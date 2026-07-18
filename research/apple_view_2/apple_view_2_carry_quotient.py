#!/usr/bin/env python3
"""Exact free-carry quotient experiment for one-block ChaCha20 inversion.

Every modular addition is written bitwise as z_i = x_i XOR y_i XOR c_i.
For the primary arm c_0 is fixed to zero and c_1..c_31 are independent
nuisance variables.  Eliminating those variables can only produce necessary
linear equations on the 256-bit key; no concrete carry or secret-key value is
given to the extraction routine.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import resource
import struct
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


MASK32 = (1 << 32) - 1
KEY_BITS = 256
OUTPUT_BITS = 512
CONSTANT_WORDS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
DEFAULT_SEED = "apple-view-2-carry-quotient-v1-20260719"
DEFAULT_TARGETS = 8
CPU_BUDGET_SECONDS = 30.0
MEMORY_BUDGET_BYTES = 128 * 1024 * 1024
APPLE_VIEW_2_DIR = Path(__file__).resolve().parent

RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)

PRIMARY_MODE = "exact_c0_fixed_free_c1_to_c31"
ALL_FREE_CONTROL = "control_all_32_sum_bits_free"
NO_CARRY_CONTROL = "control_xor_no_carries"
CARRY_MODES = (PRIMARY_MODE, ALL_FREE_CONTROL, NO_CARRY_CONTROL)


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & MASK32) | (value >> (32 - distance))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _initial_words(key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    if not 0 <= counter <= MASK32:
        raise ValueError("counter must be uint32")
    if len(nonce) != 12:
        raise ValueError("nonce must be exactly 12 bytes")
    return (
        *CONSTANT_WORDS,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    )


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Independent, standard 20-round RFC 8439 block evaluator."""

    initial = _initial_words(key, counter, nonce)
    state = list(initial)
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *((word + base) & MASK32 for word, base in zip(state, initial))
    )


@dataclass(frozen=True)
class PublicTarget:
    counter: int
    nonce: bytes
    block: bytes

    def validate(self) -> None:
        if not 0 <= self.counter <= MASK32:
            raise ValueError("counter must be uint32")
        if len(self.nonce) != 12:
            raise ValueError("nonce must be exactly 12 bytes")
        if len(self.block) != 64:
            raise ValueError("block must be exactly 64 bytes")


@dataclass(frozen=True)
class GeneratedCase:
    case_id: int
    target: PublicTarget
    measurement_key: bytes


@dataclass(frozen=True)
class ExperimentConfig:
    seed: str = DEFAULT_SEED
    targets: int = DEFAULT_TARGETS
    addition_identity_checks: int = 256

    def validate(self) -> None:
        if not self.seed:
            raise ValueError("seed must not be empty")
        if not 1 <= self.targets <= 64:
            raise ValueError("targets must be in [1, 64]")
        if not 1 <= self.addition_identity_checks <= 100_000:
            raise ValueError("addition_identity_checks must be in [1, 100000]")


@dataclass
class WorkMeter:
    symbolic_circuits_compiled: int = 0
    symbolic_additions: int = 0
    affine_carry_variables_created: int = 0
    output_equations: int = 0
    gf2_row_xors: int = 0
    gf2_rank_calls: int = 0
    concrete_lift_assignment_validations: int = 0


@dataclass(frozen=True)
class LiftedSystem:
    # Each row is B_row, A_row, rhs for B*c XOR A*k = rhs.
    rows: tuple[tuple[int, int, int], ...]
    carry_variables: int
    addition_carry_ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class ExtractionResult:
    summary: dict[str, object]
    surviving_key_equations: tuple[tuple[int, int], ...]
    recovered_key_bits: tuple[tuple[int, int], ...]
    candidate_key: bytes | None
    lifted_rows: tuple[tuple[int, int, int], ...]
    carry_rows: tuple[int, ...]
    addition_carry_ranges: tuple[tuple[int, int], ...]


def _derive(seed: str, label: str, indices: Sequence[int], length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(seed.encode("utf-8"))
    shake.update(b"\x00")
    shake.update(label.encode("ascii"))
    for index in indices:
        shake.update(index.to_bytes(8, "little", signed=False))
    return shake.digest(length)


def generate_cases(config: ExperimentConfig) -> list[GeneratedCase]:
    """Create fixed, explicitly unsealed targets for post-attack measurement."""

    config.validate()
    cases: list[GeneratedCase] = []
    for case_id in range(config.targets):
        key = _derive(config.seed, "measurement-key", (case_id,), 32)
        nonce = _derive(config.seed, "public-nonce", (case_id,), 12)
        counter = int.from_bytes(
            _derive(config.seed, "public-counter", (case_id,), 4), "little"
        )
        target = PublicTarget(counter, nonce, chacha20_block(key, counter, nonce))
        cases.append(GeneratedCase(case_id, target, key))
    return cases


AffineWord = tuple[int, ...]


class AffineChaChaBuilder:
    """Build the XOR-affine circuit after lifting every addition carry."""

    def __init__(self, carry_mode: str) -> None:
        if carry_mode not in CARRY_MODES:
            raise ValueError(f"unknown carry mode: {carry_mode}")
        self.carry_mode = carry_mode
        self.next_variable = KEY_BITS
        self.addition_carry_ranges: list[tuple[int, int]] = []

    @staticmethod
    def constant_word(value: int) -> AffineWord:
        return tuple((value >> bit) & 1 for bit in range(32))

    @staticmethod
    def key_word(first_key_bit: int) -> AffineWord:
        return tuple(1 << (1 + first_key_bit + bit) for bit in range(32))

    @staticmethod
    def xor_words(left: AffineWord, right: AffineWord) -> AffineWord:
        return tuple(a ^ b for a, b in zip(left, right, strict=True))

    @staticmethod
    def rotl_word(word: AffineWord, distance: int) -> AffineWord:
        return word[-distance:] + word[:-distance]

    def _fresh_carry(self) -> int:
        expression = 1 << (1 + self.next_variable)
        self.next_variable += 1
        return expression

    def add_words(self, left: AffineWord, right: AffineWord) -> AffineWord:
        start = self.next_variable - KEY_BITS
        output: list[int] = []
        for bit, (a, b) in enumerate(zip(left, right, strict=True)):
            if self.carry_mode == PRIMARY_MODE:
                carry = 0 if bit == 0 else self._fresh_carry()
            elif self.carry_mode == ALL_FREE_CONTROL:
                carry = self._fresh_carry()
            else:
                carry = 0
            output.append(a ^ b ^ carry)
        end = self.next_variable - KEY_BITS
        self.addition_carry_ranges.append((start, end))
        return tuple(output)

    def quarter_round(
        self, state: list[AffineWord], a: int, b: int, c: int, d: int
    ) -> None:
        state[a] = self.add_words(state[a], state[b])
        state[d] = self.rotl_word(self.xor_words(state[d], state[a]), 16)
        state[c] = self.add_words(state[c], state[d])
        state[b] = self.rotl_word(self.xor_words(state[b], state[c]), 12)
        state[a] = self.add_words(state[a], state[b])
        state[d] = self.rotl_word(self.xor_words(state[d], state[a]), 8)
        state[c] = self.add_words(state[c], state[d])
        state[b] = self.rotl_word(self.xor_words(state[b], state[c]), 7)

    def block_words(self, counter: int, nonce: bytes) -> tuple[AffineWord, ...]:
        if not 0 <= counter <= MASK32:
            raise ValueError("counter must be uint32")
        if len(nonce) != 12:
            raise ValueError("nonce must be exactly 12 bytes")
        initial: list[AffineWord] = [
            *(self.constant_word(word) for word in CONSTANT_WORDS),
            *(self.key_word(32 * word) for word in range(8)),
            self.constant_word(counter),
            *(self.constant_word(word) for word in struct.unpack("<3I", nonce)),
        ]
        state = list(initial)
        for _ in range(10):
            self.quarter_round(state, 0, 4, 8, 12)
            self.quarter_round(state, 1, 5, 9, 13)
            self.quarter_round(state, 2, 6, 10, 14)
            self.quarter_round(state, 3, 7, 11, 15)
            self.quarter_round(state, 0, 5, 10, 15)
            self.quarter_round(state, 1, 6, 11, 12)
            self.quarter_round(state, 2, 7, 8, 13)
            self.quarter_round(state, 3, 4, 9, 14)
        return tuple(
            self.add_words(word, base) for word, base in zip(state, initial)
        )


def compile_lifted_system(
    target: PublicTarget, carry_mode: str, meter: WorkMeter | None = None
) -> LiftedSystem:
    """Compile public equations; this interface has no secret-key input."""

    target.validate()
    builder = AffineChaChaBuilder(carry_mode)
    symbolic_output = builder.block_words(target.counter, target.nonce)
    observed_words = struct.unpack("<16I", target.block)
    carry_variables = builder.next_variable - KEY_BITS
    key_mask_limit = (1 << KEY_BITS) - 1
    rows: list[tuple[int, int, int]] = []
    for word_index, word in enumerate(symbolic_output):
        for bit, expression in enumerate(word):
            observed = (observed_words[word_index] >> bit) & 1
            constant = expression & 1
            variables = expression >> 1
            key_mask = variables & key_mask_limit
            carry_mask = variables >> KEY_BITS
            rows.append((carry_mask, key_mask, observed ^ constant))
    if len(rows) != OUTPUT_BITS:
        raise AssertionError("symbolic block did not emit 512 equations")
    if len(builder.addition_carry_ranges) != 336:
        raise AssertionError("full ChaCha block must contain 336 word additions")
    if meter is not None:
        meter.symbolic_circuits_compiled += 1
        meter.symbolic_additions += len(builder.addition_carry_ranges)
        meter.affine_carry_variables_created += carry_variables
        meter.output_equations += len(rows)
    return LiftedSystem(
        tuple(rows), carry_variables, tuple(builder.addition_carry_ranges)
    )


def _eliminate_carries(
    rows: Iterable[tuple[int, int, int]], meter: WorkMeter | None = None
) -> tuple[int, tuple[tuple[int, int], ...]]:
    """Return rank(B) and a basis-sized list spanning the left-null relations."""

    basis: dict[int, tuple[int, int, int]] = {}
    surviving: list[tuple[int, int]] = []
    for carry_mask, key_mask, rhs in rows:
        while carry_mask:
            pivot = carry_mask.bit_length() - 1
            prior = basis.get(pivot)
            if prior is None:
                basis[pivot] = (carry_mask, key_mask, rhs)
                break
            carry_mask ^= prior[0]
            key_mask ^= prior[1]
            rhs ^= prior[2]
            if meter is not None:
                meter.gf2_row_xors += 1
        else:
            surviving.append((key_mask, rhs))
    return len(basis), tuple(surviving)


def _rref_key_equations(
    equations: Iterable[tuple[int, int]], meter: WorkMeter | None = None
) -> tuple[dict[int, tuple[int, int]], int]:
    basis: dict[int, tuple[int, int]] = {}
    inconsistent_rows = 0
    for mask, rhs in equations:
        while mask:
            pivot = mask.bit_length() - 1
            prior = basis.get(pivot)
            if prior is None:
                basis[pivot] = (mask, rhs)
                break
            mask ^= prior[0]
            rhs ^= prior[1]
            if meter is not None:
                meter.gf2_row_xors += 1
        else:
            inconsistent_rows += rhs

    for pivot in sorted(basis):
        pivot_mask, pivot_rhs = basis[pivot]
        for other in tuple(basis):
            if other != pivot and ((basis[other][0] >> pivot) & 1):
                other_mask, other_rhs = basis[other]
                basis[other] = (other_mask ^ pivot_mask, other_rhs ^ pivot_rhs)
                if meter is not None:
                    meter.gf2_row_xors += 1
    return basis, inconsistent_rows


def _matrix_rank(rows: Iterable[int], meter: WorkMeter | None = None) -> int:
    basis: dict[int, int] = {}
    for row in rows:
        while row:
            pivot = row.bit_length() - 1
            prior = basis.get(pivot)
            if prior is None:
                basis[pivot] = row
                break
            row ^= prior
            if meter is not None:
                meter.gf2_row_xors += 1
    if meter is not None:
        meter.gf2_rank_calls += 1
    return len(basis)


def extract_key_information(
    target: PublicTarget,
    carry_mode: str = PRIMARY_MODE,
    meter: WorkMeter | None = None,
) -> ExtractionResult:
    """Eliminate carries using public data only and return key parities/bits."""

    system = compile_lifted_system(target, carry_mode, meter)
    carry_rank, key_equations = _eliminate_carries(system.rows, meter)
    key_basis, inconsistent_rows = _rref_key_equations(key_equations, meter)
    suggested_bits = tuple(
        sorted(
            (pivot, rhs)
            for pivot, (mask, rhs) in key_basis.items()
            if mask == 1 << pivot
        )
    )
    candidate: bytes | None = None
    if len(key_basis) == KEY_BITS and inconsistent_rows == 0:
        candidate_value = 0
        for bit, value in suggested_bits:
            candidate_value |= value << bit
        candidate = candidate_value.to_bytes(32, "little")
    exact_model = carry_mode != NO_CARRY_CONTROL
    exact_recovered_bits = (
        suggested_bits if exact_model and inconsistent_rows == 0 else ()
    )
    summary: dict[str, object] = {
        "carry_mode": carry_mode,
        "model_is_exact_relaxation": exact_model,
        "output_equations": len(system.rows),
        "word_additions": len(system.addition_carry_ranges),
        "nuisance_carry_variables": system.carry_variables,
        "carry_coefficient_rank": carry_rank,
        "relations_after_carry_elimination": len(key_equations),
        "key_information_rank_bits": len(key_basis),
        "key_entropy_upper_bound_after_relations_bits": KEY_BITS - len(key_basis),
        "inconsistent_key_only_rows": inconsistent_rows,
        "system_consistent": inconsistent_rows == 0,
        "unit_key_bits_suggested_by_model": len(suggested_bits),
        "exact_key_bits_recovered": len(exact_recovered_bits),
        "exact_recovered_key_bit_indices": [
            bit for bit, _ in exact_recovered_bits
        ],
        "full_rank_key_candidate_emitted": candidate is not None,
    }
    return ExtractionResult(
        summary,
        key_equations,
        suggested_bits,
        candidate,
        system.rows,
        tuple(row[0] for row in system.rows),
        system.addition_carry_ranges,
    )


def _range_mask(ranges: Sequence[tuple[int, int]], first: int, end: int) -> int:
    if not 0 <= first < end <= len(ranges):
        raise ValueError("invalid addition range")
    low = ranges[first][0]
    high = ranges[end - 1][1]
    if high == low:
        return 0
    return ((1 << (high - low)) - 1) << low


def carry_span_profile(
    extraction: ExtractionResult, meter: WorkMeter | None = None
) -> dict[str, object]:
    """Locate which full-round carry groups already span output space."""

    rows = extraction.carry_rows
    ranges = extraction.addition_carry_ranges

    def rank(first: int, end: int) -> int:
        mask = _range_mask(ranges, first, end)
        return _matrix_rank((row & mask for row in rows), meter)

    double_rounds = [
        {
            "double_round": index,
            "addition_range": [32 * index, 32 * (index + 1)],
            "carry_span_rank": rank(32 * index, 32 * (index + 1)),
        }
        for index in range(10)
    ]
    return {
        "per_double_round": double_rounds,
        "all_20_round_permutation_additions": rank(0, 320),
        "first_18_rounds_only": rank(0, 288),
        "last_double_round_only": rank(288, 320),
        "final_feed_forward_only": rank(320, 336),
        "last_double_round_plus_feed_forward": rank(288, 336),
    }


def _parity(value: int) -> int:
    return value.bit_count() & 1


def _require_int(value: object) -> int:
    if type(value) is not int:
        raise TypeError(f"expected int metric, got {type(value).__name__}")
    return value


def _concrete_add_with_lifted_carries(
    left: int, right: int, carry_mode: str, carries: list[int]
) -> int:
    carry = 0
    output = 0
    for bit in range(32):
        x_bit = (left >> bit) & 1
        y_bit = (right >> bit) & 1
        if carry_mode == ALL_FREE_CONTROL or (
            carry_mode == PRIMARY_MODE and bit > 0
        ):
            carries.append(carry)
        output |= (x_bit ^ y_bit ^ carry) << bit
        carry = (x_bit & y_bit) | (carry & (x_bit ^ y_bit))
    return output


def _quarter_round_with_lifted_carries(
    state: list[int], a: int, b: int, c: int, d: int, mode: str, carries: list[int]
) -> None:
    state[a] = _concrete_add_with_lifted_carries(state[a], state[b], mode, carries)
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = _concrete_add_with_lifted_carries(state[c], state[d], mode, carries)
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = _concrete_add_with_lifted_carries(state[a], state[b], mode, carries)
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = _concrete_add_with_lifted_carries(state[c], state[d], mode, carries)
    state[b] = _rotl32(state[b] ^ state[c], 7)


def concrete_block_and_lifted_carries(
    key: bytes, counter: int, nonce: bytes, carry_mode: str
) -> tuple[bytes, int, int]:
    """Return a standard block plus the real carry assignment for an exact arm."""

    if carry_mode not in (PRIMARY_MODE, ALL_FREE_CONTROL):
        raise ValueError("real carry assignment exists only for exact relaxation arms")
    initial = _initial_words(key, counter, nonce)
    state = list(initial)
    carries: list[int] = []
    for _ in range(10):
        _quarter_round_with_lifted_carries(state, 0, 4, 8, 12, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 1, 5, 9, 13, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 2, 6, 10, 14, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 3, 7, 11, 15, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 0, 5, 10, 15, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 1, 6, 11, 12, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 2, 7, 8, 13, carry_mode, carries)
        _quarter_round_with_lifted_carries(state, 3, 4, 9, 14, carry_mode, carries)
    output = [
        _concrete_add_with_lifted_carries(word, base, carry_mode, carries)
        for word, base in zip(state, initial)
    ]
    carry_assignment = sum(value << index for index, value in enumerate(carries))
    return struct.pack("<16I", *output), carry_assignment, len(carries)


def score_extraction(
    extraction: ExtractionResult,
    case: GeneratedCase,
    meter: WorkMeter | None = None,
) -> dict[str, object]:
    """Truth-only scoring performed after the public extraction is complete."""

    key_value = int.from_bytes(case.measurement_key, "little")
    equations_total = len(extraction.surviving_key_equations)
    equations_satisfied = sum(
        _parity(mask & key_value) == rhs
        for mask, rhs in extraction.surviving_key_equations
    )
    suggested_correct = sum(
        ((key_value >> bit) & 1) == value
        for bit, value in extraction.recovered_key_bits
    )
    candidate_matches_key = extraction.candidate_key == case.measurement_key
    candidate_matches_block = bool(
        extraction.candidate_key is not None
        and chacha20_block(
            extraction.candidate_key, case.target.counter, case.target.nonce
        )
        == case.target.block
    )
    lifted_satisfied: int | None = None
    lifted_total: int | None = None
    if bool(extraction.summary["model_is_exact_relaxation"]):
        block, concrete_carries, carry_count = concrete_block_and_lifted_carries(
            case.measurement_key,
            case.target.counter,
            case.target.nonce,
            str(extraction.summary["carry_mode"]),
        )
        if block != case.target.block:
            raise AssertionError("concrete lifted execution disagrees with standard block")
        if carry_count != _require_int(
            extraction.summary["nuisance_carry_variables"]
        ):
            raise AssertionError("concrete and symbolic carry counts differ")
        lifted_total = len(extraction.lifted_rows)
        lifted_satisfied = sum(
            (_parity(carry_mask & concrete_carries) ^ _parity(key_mask & key_value))
            == rhs
            for carry_mask, key_mask, rhs in extraction.lifted_rows
        )
        if lifted_satisfied != lifted_total:
            raise AssertionError("real key/carries do not satisfy lifted output system")
        if meter is not None:
            meter.concrete_lift_assignment_validations += 1
    return {
        "truth_key_equations_satisfied": equations_satisfied,
        "truth_key_equations_total": equations_total,
        "truth_key_equation_fraction": (
            equations_satisfied / equations_total if equations_total else None
        ),
        "all_emitted_relations_hold_for_truth": equations_satisfied == equations_total,
        "suggested_key_bits_correct": suggested_correct,
        "exact_recovered_key_bits_correct": (
            suggested_correct
            if bool(extraction.summary["model_is_exact_relaxation"])
            and bool(extraction.summary["system_consistent"])
            else 0
        ),
        "candidate_equals_measurement_key": candidate_matches_key,
        "candidate_reproduces_all_512_output_bits": candidate_matches_block,
        "exact_key_recovered_and_block_verified": (
            candidate_matches_key and candidate_matches_block
        ),
        "lifted_output_equations_satisfied_by_real_assignment": lifted_satisfied,
        "lifted_output_equations_checked_with_real_assignment": lifted_total,
        "real_assignment_satisfies_entire_lifted_system": (
            lifted_satisfied == lifted_total if lifted_total is not None else None
        ),
    }


def _evaluate_affine(expression: int, assignment: int) -> int:
    return (expression & 1) ^ _parity((expression >> 1) & assignment)


def validate_lifted_addition(seed: str, checks: int) -> int:
    """Substitute real carries into the symbolic adder for deterministic pairs."""

    builder = AffineChaChaBuilder(PRIMARY_MODE)
    left = tuple(1 << (1 + bit) for bit in range(32))
    right = tuple(1 << (1 + 32 + bit) for bit in range(32))
    output = builder.add_words(left, right)
    if builder.addition_carry_ranges != [(0, 31)]:
        raise AssertionError("primary adder must allocate c1..c31 exactly once")
    for index in range(checks):
        material = _derive(seed, "adder-check", (index,), 8)
        x, y = struct.unpack("<2I", material)
        assignment = x | (y << 32)
        carry = 0
        for bit in range(32):
            if bit:
                assignment |= carry << (KEY_BITS + bit - 1)
            carry = (((x >> bit) & 1) & ((y >> bit) & 1)) | (
                carry & (((x >> bit) & 1) ^ ((y >> bit) & 1))
            )
        evaluated = sum(
            _evaluate_affine(expression, assignment) << bit
            for bit, expression in enumerate(output)
        )
        if evaluated != (x + y) & MASK32:
            raise AssertionError(f"lifted adder mismatch at deterministic pair {index}")
    return checks


def synthetic_elimination_sanity() -> dict[str, int]:
    """A two-row toy where eliminating one carry exposes k0 XOR k1."""

    carry_rank, equations = _eliminate_carries(
        ((1, 1 << 0, 0), (1, 1 << 1, 1))
    )
    basis, inconsistent = _rref_key_equations(equations)
    expected = ((1 << 0) | (1 << 1), 1)
    if carry_rank != 1 or equations != (expected,) or len(basis) != 1 or inconsistent:
        raise AssertionError("synthetic carry elimination failed")
    return {
        "input_equations": 2,
        "carry_rank": carry_rank,
        "surviving_key_relations": len(equations),
        "key_information_rank_bits": len(basis),
    }


def _mode_metadata(mode: str) -> dict[str, object]:
    if mode == PRIMARY_MODE:
        return {
            "role": "tested_mechanism",
            "carry_rule": "c0=0 exactly; c1..c31 independent per addition",
            "exactness": "exact necessary-condition relaxation",
        }
    if mode == ALL_FREE_CONTROL:
        return {
            "role": "matched_null_control",
            "carry_rule": "c0..c31 independent per addition",
            "exactness": "strictly looser exact relaxation",
        }
    return {
        "role": "matched_optimistic_control",
        "carry_rule": "all carries forced to zero",
        "exactness": "non-exact XOR surrogate; cannot support key claims",
    }


def _aggregate_arm(rows: Sequence[dict[str, object]]) -> dict[str, object]:
    ranks = [_require_int(row["key_information_rank_bits"]) for row in rows]
    carry_ranks = [_require_int(row["carry_coefficient_rank"]) for row in rows]
    relation_total = sum(
        _require_int(row["truth_key_equations_total"]) for row in rows
    )
    relation_satisfied = sum(
        _require_int(row["truth_key_equations_satisfied"]) for row in rows
    )
    lifted_total = sum(
        _require_int(row["lifted_output_equations_checked_with_real_assignment"])
        if row["lifted_output_equations_checked_with_real_assignment"] is not None
        else 0
        for row in rows
    )
    lifted_satisfied = sum(
        _require_int(row["lifted_output_equations_satisfied_by_real_assignment"])
        if row["lifted_output_equations_satisfied_by_real_assignment"] is not None
        else 0
        for row in rows
    )
    return {
        "targets": len(rows),
        "carry_rank_values": sorted(set(carry_ranks)),
        "key_information_rank_min_bits": min(ranks),
        "key_information_rank_max_bits": max(ranks),
        "key_information_rank_mean_bits": sum(ranks) / len(ranks),
        "consistent_systems": sum(bool(row["system_consistent"]) for row in rows),
        "truth_key_equations_satisfied": relation_satisfied,
        "truth_key_equations_total": relation_total,
        "truth_key_equation_fraction": (
            relation_satisfied / relation_total if relation_total else None
        ),
        "lifted_output_equations_satisfied_by_real_assignments": lifted_satisfied,
        "lifted_output_equations_checked_with_real_assignments": lifted_total,
        "targets_with_all_emitted_relations_holding": sum(
            bool(row["all_emitted_relations_hold_for_truth"]) for row in rows
        ),
        "exact_key_bits_recovered": sum(
            _require_int(row["exact_key_bits_recovered"]) for row in rows
        ),
        "exact_recovered_key_bits_correct": sum(
            _require_int(row["exact_recovered_key_bits_correct"]) for row in rows
        ),
        "unit_key_bits_suggested_by_model": sum(
            _require_int(row["unit_key_bits_suggested_by_model"]) for row in rows
        ),
        "suggested_key_bits_correct": sum(
            _require_int(row["suggested_key_bits_correct"]) for row in rows
        ),
        "full_key_candidates_emitted": sum(
            bool(row["full_rank_key_candidate_emitted"]) for row in rows
        ),
        "exact_keys_recovered_and_block_verified": sum(
            bool(row["exact_key_recovered_and_block_verified"]) for row in rows
        ),
    }


def _max_rss_bytes(raw_value: int) -> int:
    return raw_value if sys.platform == "darwin" else raw_value * 1024


def run_experiment(config: ExperimentConfig = ExperimentConfig()) -> dict[str, object]:
    config.validate()
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    tracemalloc.start()
    meter = WorkMeter()

    if chacha20_block(RFC_KEY, 1, RFC_NONCE) != RFC_BLOCK:
        raise AssertionError("local implementation does not reproduce RFC 8439")
    adder_checks = validate_lifted_addition(
        config.seed, config.addition_identity_checks
    )
    synthetic = synthetic_elimination_sanity()
    cases = generate_cases(config)

    per_mode_rows: dict[str, list[dict[str, object]]] = {
        mode: [] for mode in CARRY_MODES
    }
    case_records: list[dict[str, object]] = []
    reference_span_profile: dict[str, object] | None = None
    for case in cases:
        arms: dict[str, object] = {}
        for mode in CARRY_MODES:
            extraction = extract_key_information(case.target, mode, meter)
            if mode == PRIMARY_MODE:
                profile = carry_span_profile(extraction, meter)
                if reference_span_profile is None:
                    reference_span_profile = profile
                elif profile != reference_span_profile:
                    raise AssertionError("carry span profile changed across public targets")
            scored = {
                **extraction.summary,
                **score_extraction(extraction, case, meter),
            }
            per_mode_rows[mode].append(scored)
            arms[mode] = scored
        case_records.append(
            {
                "case_id": case.case_id,
                "measurement_key_hex_unsealed": case.measurement_key.hex(),
                "counter": case.target.counter,
                "nonce_hex": case.target.nonce.hex(),
                "block_hex": case.target.block.hex(),
                "public_target_sha256": hashlib.sha256(
                    struct.pack("<I", case.target.counter)
                    + case.target.nonce
                    + case.target.block
                ).hexdigest(),
                "arms": arms,
            }
        )

    aggregates = {
        mode: {**_mode_metadata(mode), **_aggregate_arm(per_mode_rows[mode])}
        for mode in CARRY_MODES
    }
    primary = aggregates[PRIMARY_MODE]
    primary_relations_hold = (
        _require_int(primary["targets_with_all_emitted_relations_holding"])
        == config.targets
    )
    continuation_passed = (
        _require_int(primary["key_information_rank_min_bits"]) >= 1
        and primary_relations_hold
    )

    python_current, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    usage_after = resource.getrusage(resource.RUSAGE_SELF)
    max_rss = _max_rss_bytes(usage_after.ru_maxrss)
    budget_passed = cpu_seconds < CPU_BUDGET_SECONDS and max_rss < MEMORY_BUDGET_BYTES
    if not budget_passed:
        raise RuntimeError(
            f"resource budget exceeded: cpu={cpu_seconds:.6f}s rss={max_rss} bytes"
        )

    if _require_int(primary["exact_keys_recovered_and_block_verified"]):
        decision = "exact full-key recovery observed; independently block-verified"
    elif continuation_passed:
        decision = (
            "at least one exact linear key parity survived free-carry elimination on "
            "every target; continue with independent targets"
        )
    else:
        decision = (
            "stop the independent-free-carry quotient at full 20 rounds: the carry "
            "columns span all 512 output equations, leaving zero linear key information"
        )

    return {
        "schema": "apple-view-2-full256-carry-quotient-v1",
        "hypothesis": (
            "eliminating independently lifted addition carries leaves exact public "
            "linear parities of the unknown 256-bit key"
        ),
        "equations": {
            "addition_bit": "z_i = x_i XOR y_i XOR c_i, with c_0 = 0",
            "lifted_block": "b = A*k XOR B*c XOR d over GF(2)",
            "carry_quotient": "H*B = 0 implies (H*A)*k = H*(b XOR d)",
            "key_information_metric": "rank(H*A) exact key-parity bits",
        },
        "config": asdict(config),
        "attacker_boundary": {
            "primitive": "RFC 8439 ChaCha20 block, 20 rounds",
            "unknown_key_bits": 256,
            "blocks_per_attack": 1,
            "public_input_per_attack": "constants + counter + 96-bit nonce + one 512-bit block",
            "truth_key_input_to_extraction": False,
            "concrete_internal_carries_input_to_extraction": False,
            "key_enumeration": False,
            "target_refitting_or_training": False,
            "reduced_round_results_mixed_in": False,
            "sealed_targets_used": False,
            "gpu_mps_or_other_accelerator": False,
            "network_used": False,
            "target_generation": "fixed SHAKE-256 build data; keys are committed unsealed for audit",
        },
        "validation": {
            "rfc8439_block_vector": True,
            "lifted_word_addition_pairs_checked": adder_checks,
            "synthetic_elimination_sanity": synthetic,
            "extract_key_information_parameters": list(
                inspect.signature(extract_key_information).parameters
            ),
            "truth_used_only_after_each_extraction": True,
            "exact_recovery_definition": (
                "publicly emitted full-rank candidate equals the measurement key and "
                "reproduces all 512 block bits under standard ChaCha20"
            ),
        },
        "matched_arms": aggregates,
        "primary_carry_span_profile": reference_span_profile,
        "targets": case_records,
        "predeclared_continuation_gate": {
            "rule": (
                "continue only if primary exact relaxation has rank >= 1 on every "
                "target and all emitted equations hold under post-attack truth scoring"
            ),
            "passed": continuation_passed,
        },
        "resources": {
            "cpu_budget_seconds": CPU_BUDGET_SECONDS,
            "memory_budget_bytes": MEMORY_BUDGET_BYTES,
            "budget_passed": budget_passed,
            "wall_seconds": wall_seconds,
            "cpu_seconds": cpu_seconds,
            "python_tracemalloc_current_bytes": python_current,
            "python_tracemalloc_peak_bytes": python_peak,
            "process_max_rss_bytes": max_rss,
            "minor_page_faults_delta": usage_after.ru_minflt - usage_before.ru_minflt,
            "major_page_faults_delta": usage_after.ru_majflt - usage_before.ru_majflt,
            "symbolic_circuits_compiled": meter.symbolic_circuits_compiled,
            "symbolic_word_additions": meter.symbolic_additions,
            "affine_carry_variables_created": meter.affine_carry_variables_created,
            "output_equations_processed": meter.output_equations,
            "gf2_rank_calls": meter.gf2_rank_calls,
            "gf2_row_xors": meter.gf2_row_xors,
            "concrete_lift_assignment_validations": (
                meter.concrete_lift_assignment_validations
            ),
            "cpu_processes": 1,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "decision": decision,
        "next_discriminating_step": (
            "globally substitute the exact carry-majority recurrence at depth c1 "
            "for all 336 additions, then c2 and higher one depth at a time, measuring "
            "exact Boolean domain pruning; leaving even one whole double-round free "
            "cannot discriminate because each such carry group already has rank 512"
        ),
    }


def validated_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    resolved = candidate.resolve()
    if resolved.parent != APPLE_VIEW_2_DIR:
        raise ValueError("output must remain directly inside research/apple_view_2")
    if not resolved.name.startswith("apple_view_2_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_2_*.json")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the full-round ChaCha20 exact free-carry quotient experiment."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--targets", type=int, default=DEFAULT_TARGETS)
    parser.add_argument("--addition-checks", type=int, default=256)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    output: Path | None = None
    if args.output is not None:
        try:
            output = validated_output_path(args.output)
        except ValueError as error:
            parser.error(str(error))
    result = run_experiment(
        ExperimentConfig(args.seed, args.targets, args.addition_checks)
    )
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
