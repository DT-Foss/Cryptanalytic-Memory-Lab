#!/usr/bin/env python3
"""Exact public cross-block consequences for shared-key Full256 ChaCha CNFs.

For a final pre-feedforward word ``P`` and public output word ``Y``, ChaCha20
has ``Y = P + X`` modulo 2**32.  Public initial lanes therefore reveal ``P``
directly.  On key lanes, two blocks with one shared key satisfy

    P_b = P_0 + (Y_b - Y_0)  (mod 2**32).

This module makes only those redundant logical consequences explicit.  It does
not add a key unit, read a target key, generate entropy, or invoke a solver.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import struct
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, cast

from o1_crypto_lab.full256_cnf import (
    Full256CNFError,
    InstanceWriteReport,
    load_full256_template_map,
    verify_full256_template,
)
from o1_crypto_lab.full256_multiblock_cnf import (
    MULTIBLOCK_CNF_SCHEMA,
    MULTIBLOCK_REMAP_RULE,
    Full256MultiblockCNFReport,
    multiblock_clause_count,
    multiblock_variable_count,
    remap_full256_variable,
    verify_full256_multiblock_cnf,
)
from o1_crypto_lab.living_inverse import canonical_json_bytes, canonical_sha256


MASK32 = (1 << 32) - 1
SCHEMA = "apple-view-0008-crossblock-consequence-cnf-v1"
VERIFICATION_SCHEMA = "apple-view-0008-crossblock-consequence-verification-v1"
O1C57_PREFLIGHT_SCHEMA = "apple-view-0008-o1c57-consumed-build-preflight-v1"
PUBLIC_FINAL_LANES = (0, 1, 2, 3, 12, 13, 14, 15)
KEY_LANES = tuple(range(4, 12))
CONSTANT_WORDS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
ROUND_OPERATION_COUNT = 640
FEED_FORWARD_OPERATION_COUNT = 16
FINAL_WORD_COUNT = 16
WORD_BITS = 32
O1C57_CAPSULE_NAME = "20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1"
O1C57_MANIFEST_SHA256 = "008b985868b18160711be70cc9fa2a7697d5888c5515702caef72228ea2a742e"
O1C57_CONFIG_FILE_SHA256 = "34bc4f02ed412e3ee9e45929a22096ee73e28b0aedbca8f7f1743303b646078e"
O1C57_PUBLICATION_FILE_SHA256 = "637b2447ba03d450fd90384462bb577dcf2f32e5feac2241502c62545da8a765"
O1C57_TEMPLATE_SHA256 = "c293d36cab270b28ab2e89c073227fd50b75a6b357b9994d27c3acf7c01a0d52"
O1C57_SEMANTIC_MAP_FILE_SHA256 = "7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318"

Clause = tuple[int, ...]
SourceRow = tuple[
    str | Path,
    InstanceWriteReport | Mapping[str, object] | str | Path,
]


class AppleView8Error(Full256CNFError):
    """An input, consequence, immutable output, or report differs."""


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint(path: Path) -> tuple[int, int, int, int]:
    metadata = path.stat(follow_symlinks=False)
    if not path.is_file():
        raise AppleView8Error("input must be a regular file")
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _load_json(path: Path, *, canonical: bool, field: str) -> dict[str, object]:
    raw = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AppleView8Error(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AppleView8Error(f"{field} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise AppleView8Error(f"{field} must be a JSON object")
    if canonical and raw != canonical_json_bytes(value) + b"\n":
        raise AppleView8Error(f"{field} is not canonical JSON")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AppleView8Error(f"{field} must be an object")
    return value


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AppleView8Error(f"{field} must be an array")
    return value


def _canonical_clause(values: Sequence[int]) -> Clause:
    if any(not _is_int(value) or value == 0 for value in values):
        raise AppleView8Error("consequence clause contains an invalid literal")
    literals = set(values)
    if len(literals) != len(values) or any(-literal in literals for literal in literals):
        raise AppleView8Error("consequence clause is not simplified")
    return tuple(sorted(literals, key=lambda item: (abs(item), item < 0)))


def _clause_bytes(clause: Clause) -> bytes:
    return (" ".join(str(literal) for literal in (*clause, 0)) + "\n").encode(
        "ascii"
    )


def _clauses_sha256(clauses: Sequence[Clause]) -> str:
    digest = hashlib.sha256()
    for clause in clauses:
        digest.update(_clause_bytes(clause))
    return digest.hexdigest()


def _blocking_clauses(
    variables: Sequence[int], predicate: Callable[[tuple[bool, ...]], bool]
) -> tuple[Clause, ...]:
    rows: list[Clause] = []
    for values in itertools.product((False, True), repeat=len(variables)):
        if predicate(values):
            continue
        rows.append(
            _canonical_clause(
                tuple(-variable if value else variable for variable, value in zip(variables, values, strict=True))
            )
        )
    return tuple(rows)


@dataclass(frozen=True)
class ConstantAdditionEncoding:
    """CNF for one variable word plus one public constant modulo 2**width."""

    width: int
    constant: int
    carry_variables: tuple[int, ...]
    clauses: tuple[Clause, ...]

    @property
    def clause_count(self) -> int:
        return len(self.clauses)


def encode_constant_addition(
    left_bits: Sequence[int],
    result_bits: Sequence[int],
    constant: int,
    first_carry_variable: int,
) -> ConstantAdditionEncoding:
    """Encode ``result = left + constant`` with one fresh carry per bit.

    The last carry is constrained and retained even though the result is modulo
    ``2**width``.  Widths up to 32 are supported so tests can exhaustively prove
    a small instance of the exact encoder used by the production path.
    """

    left = tuple(left_bits)
    result = tuple(result_bits)
    width = len(left)
    if (
        not 1 <= width <= WORD_BITS
        or len(result) != width
        or any(not _is_int(variable) or variable <= 0 for variable in (*left, *result))
        or len(set((*left, *result))) != 2 * width
        or not _is_int(constant)
        or not 0 <= constant < (1 << width)
        or not _is_int(first_carry_variable)
        or first_carry_variable <= 0
    ):
        raise AppleView8Error("constant-adder inputs differ")
    carries = tuple(first_carry_variable + bit for bit in range(width))
    if set(carries) & set((*left, *result)):
        raise AppleView8Error("constant-adder carry variables are not fresh")

    clauses: list[Clause] = []
    for bit, (source, target, carry_out) in enumerate(
        zip(left, result, carries, strict=True)
    ):
        constant_bit = bool((constant >> bit) & 1)
        if bit == 0:
            # carry-in is the Boolean constant zero.  Retain a named carry-out.
            clauses.extend(
                _blocking_clauses(
                    (source, target),
                    lambda row, d=constant_bit: row[1] == (row[0] ^ d),
                )
            )
            if constant_bit:
                clauses.extend(
                    _blocking_clauses(
                        (source, carry_out), lambda row: row[1] == row[0]
                    )
                )
            else:
                clauses.append((-carry_out,))
            continue

        carry_in = carries[bit - 1]
        clauses.extend(
            _blocking_clauses(
                (source, carry_in, target),
                lambda row, d=constant_bit: row[2] == (row[0] ^ row[1] ^ d),
            )
        )
        clauses.extend(
            (
                (
                    _canonical_clause((source, carry_in, -carry_out)),
                    _canonical_clause((-source, carry_out)),
                    _canonical_clause((-carry_in, carry_out)),
                )
                if constant_bit
                else (
                    _canonical_clause((-source, -carry_in, carry_out)),
                    _canonical_clause((source, -carry_out)),
                    _canonical_clause((carry_in, -carry_out)),
                )
            )
        )
    expected = 7 * width - 4 + (constant & 1)
    if len(clauses) != expected:
        raise AssertionError("specialized constant-adder clause count differs")
    return ConstantAdditionEncoding(width, constant, carries, tuple(clauses))


def reconstruct_final_pre_feedforward_variables(
    semantic_map_path: str | Path,
) -> tuple[tuple[int, ...], ...]:
    """Recover the sixteen final ``P20`` word wires from the canonical map."""

    sidecar = Path(semantic_map_path).resolve(strict=True)
    document = load_full256_template_map(sidecar)
    raw_operations = document.get("operations")
    variable_count = document.get("variable_count")
    if (
        not isinstance(raw_operations, list)
        or len(raw_operations)
        != ROUND_OPERATION_COUNT + FEED_FORWARD_OPERATION_COUNT
        or not _is_int(variable_count)
    ):
        raise AppleView8Error("semantic operation inventory differs")

    state: list[tuple[int, ...] | None] = [None] * FINAL_WORD_COUNT
    for expected_id, raw in enumerate(raw_operations):
        operation = _mapping(raw, "semantic operation")
        if operation.get("operation_id") != expected_id:
            raise AppleView8Error("semantic operation order differs")
        phase = operation.get("phase")
        destination = operation.get("destination_lane")
        source = operation.get("source_lane")
        kind = operation.get("kind")
        bit_ranges = operation.get("bit_ranges")
        if (
            not _is_int(destination)
            or not 0 <= cast(int, destination) < FINAL_WORD_COUNT
            or not _is_int(source)
            or not 0 <= cast(int, source) < FINAL_WORD_COUNT
            or not isinstance(bit_ranges, list)
            or len(bit_ranges) != WORD_BITS
        ):
            raise AppleView8Error("semantic operation shape differs")
        lane = cast(int, destination)
        if expected_id >= ROUND_OPERATION_COUNT:
            expected_lane = expected_id - ROUND_OPERATION_COUNT
            if (
                phase != "feed_forward"
                or kind != "add32"
                or lane != expected_lane
                or source != expected_lane
                or state[expected_lane] is None
            ):
                raise AppleView8Error("feed-forward boundary differs")
            continue
        if phase != "round" or kind not in ("add32", "xor32"):
            raise AppleView8Error("round operation boundary differs")
        raw_word: list[int] = []
        field = "sum_variable" if kind == "add32" else "output_variable"
        for expected_bit, raw_range in enumerate(bit_ranges):
            bit_range = _mapping(raw_range, "semantic bit range")
            variable = bit_range.get(field)
            if bit_range.get("bit") != expected_bit or not _is_int(variable):
                raise AppleView8Error("semantic output wire differs")
            integer = cast(int, variable)
            if not 897 <= integer <= cast(int, variable_count):
                raise AppleView8Error("semantic final wire is outside internal space")
            raw_word.append(integer)
        if kind == "xor32":
            rotation = operation.get("rotation")
            if not _is_int(rotation) or not 0 < cast(int, rotation) < WORD_BITS:
                raise AppleView8Error("semantic XOR rotation differs")
            distance = cast(int, rotation)
            raw_word = raw_word[-distance:] + raw_word[:-distance]
        state[lane] = tuple(raw_word)

    if any(word is None for word in state):
        raise AppleView8Error("semantic map lacks a final word")
    words = cast(tuple[tuple[int, ...], ...], tuple(state))
    flattened = tuple(variable for word in words for variable in word)
    if len(flattened) != FINAL_WORD_COUNT * WORD_BITS or len(set(flattened)) != len(
        flattened
    ):
        raise AppleView8Error("semantic final wire inventory differs")
    return words


def _final_wire_sha256(final_wires: Sequence[Sequence[int]]) -> str:
    return hashlib.sha256(canonical_json_bytes([list(word) for word in final_wires])).hexdigest()


@dataclass(frozen=True)
class CrossblockRelation:
    block_index: int
    lane: int
    delta: int
    first_carry_variable: int
    last_carry_variable: int
    carry_variable_count: int
    clause_count: int
    clause_sha256: str

    def __post_init__(self) -> None:
        if (
            not _is_int(self.block_index)
            or self.block_index < 1
            or self.lane not in KEY_LANES
            or not _is_int(self.delta)
            or not 0 <= self.delta <= MASK32
            or self.carry_variable_count != WORD_BITS
            or self.last_carry_variable
            != self.first_carry_variable + self.carry_variable_count - 1
            or self.clause_count != 220 + (self.delta & 1)
            or not _is_sha256(self.clause_sha256)
        ):
            raise AppleView8Error("cross-block relation report differs")

    def describe(self) -> dict[str, object]:
        return {
            "block_index": self.block_index,
            "lane": self.lane,
            "delta": self.delta,
            "first_carry_variable": self.first_carry_variable,
            "last_carry_variable": self.last_carry_variable,
            "carry_variable_count": self.carry_variable_count,
            "clause_count": self.clause_count,
            "clause_sha256": self.clause_sha256,
        }


@dataclass(frozen=True)
class CrossblockConsequencePlan:
    block_count: int
    counters: tuple[int, ...]
    nonce_hex: str
    output_sha256: tuple[str, ...]
    base_variable_count: int
    final_wires: tuple[tuple[int, ...], ...]
    direct_clauses: tuple[Clause, ...]
    ripple_clauses: tuple[Clause, ...]
    relations: tuple[CrossblockRelation, ...]

    @property
    def direct_unit_clause_count(self) -> int:
        return len(self.direct_clauses)

    @property
    def ripple_clause_count(self) -> int:
        return len(self.ripple_clauses)

    @property
    def ripple_carry_variable_count(self) -> int:
        return len(self.relations) * WORD_BITS

    @property
    def variable_count(self) -> int:
        return self.base_variable_count + self.ripple_carry_variable_count

    @property
    def augmentation_clause_count(self) -> int:
        return self.direct_unit_clause_count + self.ripple_clause_count

    @property
    def clauses(self) -> tuple[Clause, ...]:
        return self.direct_clauses + self.ripple_clauses


def _validate_public_inputs(
    output_blocks: Sequence[bytes], counters: Sequence[int], nonce: bytes
) -> tuple[tuple[bytes, ...], tuple[int, ...]]:
    outputs = tuple(output_blocks)
    schedule = tuple(counters)
    if (
        not 1 <= len(outputs) <= 16
        or len(schedule) != len(outputs)
        or any(not isinstance(block, bytes) or len(block) != 64 for block in outputs)
        or any(not _is_int(counter) or not 0 <= counter <= MASK32 for counter in schedule)
        or tuple(range(schedule[0], schedule[0] + len(schedule))) != schedule
        or schedule[-1] > MASK32
        or not isinstance(nonce, bytes)
        or len(nonce) != 12
    ):
        raise AppleView8Error("public multiblock view differs")
    return outputs, schedule


def compile_crossblock_consequences(
    semantic_map_path: str | Path,
    *,
    output_blocks: Sequence[bytes],
    counters: Sequence[int],
    nonce: bytes,
    base_variable_count: int | None = None,
) -> CrossblockConsequencePlan:
    """Compile direct public-lane units and shared-key lane equations."""

    outputs, schedule = _validate_public_inputs(output_blocks, counters, nonce)
    block_count = len(outputs)
    canonical_base = multiblock_variable_count(block_count)
    if base_variable_count is None:
        base_variable_count = canonical_base
    if not _is_int(base_variable_count) or base_variable_count != canonical_base:
        raise AppleView8Error("base multiblock variable count differs")
    final_wires = reconstruct_final_pre_feedforward_variables(semantic_map_path)
    output_words = tuple(struct.unpack("<16I", block) for block in outputs)
    nonce_words = struct.unpack("<3I", nonce)

    direct: list[Clause] = []
    for block_index, (words, counter) in enumerate(zip(output_words, schedule, strict=True)):
        initial_public = {
            0: CONSTANT_WORDS[0],
            1: CONSTANT_WORDS[1],
            2: CONSTANT_WORDS[2],
            3: CONSTANT_WORDS[3],
            12: counter,
            13: nonce_words[0],
            14: nonce_words[1],
            15: nonce_words[2],
        }
        for lane in PUBLIC_FINAL_LANES:
            value = (words[lane] - initial_public[lane]) & MASK32
            for bit, single_variable in enumerate(final_wires[lane]):
                variable = remap_full256_variable(single_variable, block_index)
                direct.append((variable if (value >> bit) & 1 else -variable,))

    ripple: list[Clause] = []
    relations: list[CrossblockRelation] = []
    next_carry = base_variable_count + 1
    for block_index in range(1, block_count):
        for lane in KEY_LANES:
            delta = (output_words[block_index][lane] - output_words[0][lane]) & MASK32
            left = tuple(
                remap_full256_variable(variable, 0) for variable in final_wires[lane]
            )
            result = tuple(
                remap_full256_variable(variable, block_index)
                for variable in final_wires[lane]
            )
            encoding = encode_constant_addition(left, result, delta, next_carry)
            relation = CrossblockRelation(
                block_index=block_index,
                lane=lane,
                delta=delta,
                first_carry_variable=encoding.carry_variables[0],
                last_carry_variable=encoding.carry_variables[-1],
                carry_variable_count=len(encoding.carry_variables),
                clause_count=len(encoding.clauses),
                clause_sha256=_clauses_sha256(encoding.clauses),
            )
            relations.append(relation)
            ripple.extend(encoding.clauses)
            next_carry += WORD_BITS
    expected_relations = (block_count - 1) * len(KEY_LANES)
    if (
        len(direct) != block_count * len(PUBLIC_FINAL_LANES) * WORD_BITS
        or len(relations) != expected_relations
        or next_carry != base_variable_count + expected_relations * WORD_BITS + 1
    ):
        raise AssertionError("cross-block consequence inventory differs")
    return CrossblockConsequencePlan(
        block_count=block_count,
        counters=schedule,
        nonce_hex=nonce.hex(),
        output_sha256=tuple(hashlib.sha256(block).hexdigest() for block in outputs),
        base_variable_count=base_variable_count,
        final_wires=final_wires,
        direct_clauses=tuple(direct),
        ripple_clauses=tuple(ripple),
        relations=tuple(relations),
    )


def crossblock_auxiliary_assignment(
    plan: CrossblockConsequencePlan, final_assignment: Mapping[int, bool]
) -> dict[int, bool]:
    """Return the unique retained carry values for a final-wire assignment."""

    result: dict[int, bool] = {}
    for relation in plan.relations:
        carry = False
        for bit, carry_variable in enumerate(
            range(relation.first_carry_variable, relation.last_carry_variable + 1)
        ):
            source = remap_full256_variable(plan.final_wires[relation.lane][bit], 0)
            if source not in final_assignment:
                raise AppleView8Error("final assignment lacks a source word bit")
            source_value = bool(final_assignment[source])
            constant_value = bool((relation.delta >> bit) & 1)
            carry = (source_value and constant_value) or (source_value and carry) or (
                constant_value and carry
            )
            result[carry_variable] = carry
    return result


@dataclass(frozen=True)
class CrossblockConsequenceReport:
    schema: str
    source_schema: str
    source_instance_sha256: str
    source_report_sha256: str
    semantic_map_file_sha256: str
    semantic_map_sha256: str
    remap_rule: str
    block_count: int
    counters: tuple[int, ...]
    nonce_hex: str
    output_sha256: tuple[str, ...]
    final_wire_sha256: str
    base_variable_count: int
    base_clause_count: int
    added_variable_count: int
    variable_count: int
    direct_final_lane_count: int
    direct_unit_clause_count: int
    direct_unit_clause_sha256: str
    crossblock_relation_count: int
    constant_lsb_one_relation_count: int
    ripple_carry_variable_count: int
    ripple_clause_count: int
    ripple_clause_sha256: str
    augmentation_clause_count: int
    augmentation_sha256: str
    clause_count: int
    key_unit_clause_count: int
    assumption_unit_clause_count: int
    target_key_included: bool
    target_trace_included: bool
    body_sha256: str
    instance_sha256: str
    instance_bytes: int
    relations: tuple[CrossblockRelation, ...]

    def __post_init__(self) -> None:
        relation_count = (
            (self.block_count - 1) * len(KEY_LANES)
            if _is_int(self.block_count)
            else -1
        )
        counters_are_canonical = (
            len(self.counters) == self.block_count
            and all(_is_int(counter) and 0 <= counter <= MASK32 for counter in self.counters)
            and bool(self.counters)
            and self.counters
            == tuple(range(self.counters[0], self.counters[0] + self.block_count))
        )
        if (
            self.schema != SCHEMA
            or self.source_schema != MULTIBLOCK_CNF_SCHEMA
            or self.remap_rule != MULTIBLOCK_REMAP_RULE
            or not _is_int(self.block_count)
            or not 1 <= self.block_count <= 16
            or not counters_are_canonical
            or len(self.nonce_hex) != 24
            or any(character not in "0123456789abcdef" for character in self.nonce_hex)
            or len(self.output_sha256) != self.block_count
            or any(not _is_sha256(value) for value in self.output_sha256)
            or any(
                not _is_sha256(value)
                for value in (
                    self.source_instance_sha256,
                    self.source_report_sha256,
                    self.semantic_map_file_sha256,
                    self.semantic_map_sha256,
                    self.final_wire_sha256,
                    self.direct_unit_clause_sha256,
                    self.ripple_clause_sha256,
                    self.augmentation_sha256,
                    self.body_sha256,
                    self.instance_sha256,
                )
            )
            or self.base_variable_count != multiblock_variable_count(self.block_count)
            or self.base_clause_count != multiblock_clause_count(self.block_count)
            or self.crossblock_relation_count != relation_count
            or self.ripple_carry_variable_count != relation_count * WORD_BITS
            or self.added_variable_count != self.ripple_carry_variable_count
            or self.variable_count
            != self.base_variable_count + self.ripple_carry_variable_count
            or self.direct_final_lane_count
            != self.block_count * len(PUBLIC_FINAL_LANES)
            or self.direct_unit_clause_count
            != self.direct_final_lane_count * WORD_BITS
            or len(self.relations) != relation_count
            or tuple((row.block_index, row.lane) for row in self.relations)
            != tuple(
                (block, lane)
                for block in range(1, self.block_count)
                for lane in KEY_LANES
            )
            or tuple(row.first_carry_variable for row in self.relations)
            != tuple(
                self.base_variable_count + 1 + index * WORD_BITS
                for index in range(relation_count)
            )
            or self.constant_lsb_one_relation_count
            != sum(row.delta & 1 for row in self.relations)
            or self.ripple_clause_count
            != sum(row.clause_count for row in self.relations)
            or self.augmentation_clause_count
            != self.direct_unit_clause_count + self.ripple_clause_count
            or self.clause_count
            != self.base_clause_count + self.augmentation_clause_count
            or self.key_unit_clause_count != 0
            or self.assumption_unit_clause_count != 0
            or self.target_key_included is not False
            or self.target_trace_included is not False
            or not _is_int(self.instance_bytes)
            or self.instance_bytes <= 0
        ):
            raise AppleView8Error("cross-block aggregate report differs")

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source_schema": self.source_schema,
            "source_instance_sha256": self.source_instance_sha256,
            "source_report_sha256": self.source_report_sha256,
            "semantic_map_file_sha256": self.semantic_map_file_sha256,
            "semantic_map_sha256": self.semantic_map_sha256,
            "remap_rule": self.remap_rule,
            "block_count": self.block_count,
            "counters": list(self.counters),
            "nonce_hex": self.nonce_hex,
            "output_sha256": list(self.output_sha256),
            "final_wire_sha256": self.final_wire_sha256,
            "base_variable_count": self.base_variable_count,
            "base_clause_count": self.base_clause_count,
            "added_variable_count": self.added_variable_count,
            "variable_count": self.variable_count,
            "direct_final_lane_count": self.direct_final_lane_count,
            "direct_unit_clause_count": self.direct_unit_clause_count,
            "direct_unit_clause_sha256": self.direct_unit_clause_sha256,
            "crossblock_relation_count": self.crossblock_relation_count,
            "constant_lsb_one_relation_count": self.constant_lsb_one_relation_count,
            "ripple_carry_variable_count": self.ripple_carry_variable_count,
            "ripple_clause_count": self.ripple_clause_count,
            "ripple_clause_sha256": self.ripple_clause_sha256,
            "augmentation_clause_count": self.augmentation_clause_count,
            "augmentation_sha256": self.augmentation_sha256,
            "clause_count": self.clause_count,
            "key_unit_clause_count": self.key_unit_clause_count,
            "assumption_unit_clause_count": self.assumption_unit_clause_count,
            "target_key_included": self.target_key_included,
            "target_trace_included": self.target_trace_included,
            "body_sha256": self.body_sha256,
            "instance_sha256": self.instance_sha256,
            "instance_bytes": self.instance_bytes,
            "relations": [relation.describe() for relation in self.relations],
        }


def _source_report_mapping(
    report: Full256MultiblockCNFReport | Mapping[str, object] | str | Path,
) -> dict[str, object]:
    if isinstance(report, Full256MultiblockCNFReport):
        return report.describe()
    if isinstance(report, (str, Path)):
        return _load_json(Path(report).resolve(strict=True), canonical=True, field="source report")
    if not isinstance(report, Mapping):
        raise AppleView8Error("source multiblock report differs")
    return dict(report)


def _relation_from_mapping(value: object) -> CrossblockRelation:
    fields = {
        "block_index",
        "lane",
        "delta",
        "first_carry_variable",
        "last_carry_variable",
        "carry_variable_count",
        "clause_count",
        "clause_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AppleView8Error("cross-block relation fields differ")
    return CrossblockRelation(**dict(value))  # type: ignore[arg-type]


def _report_from_mapping(value: Mapping[str, object]) -> CrossblockConsequenceReport:
    fields = {
        "schema",
        "source_schema",
        "source_instance_sha256",
        "source_report_sha256",
        "semantic_map_file_sha256",
        "semantic_map_sha256",
        "remap_rule",
        "block_count",
        "counters",
        "nonce_hex",
        "output_sha256",
        "final_wire_sha256",
        "base_variable_count",
        "base_clause_count",
        "added_variable_count",
        "variable_count",
        "direct_final_lane_count",
        "direct_unit_clause_count",
        "direct_unit_clause_sha256",
        "crossblock_relation_count",
        "constant_lsb_one_relation_count",
        "ripple_carry_variable_count",
        "ripple_clause_count",
        "ripple_clause_sha256",
        "augmentation_clause_count",
        "augmentation_sha256",
        "clause_count",
        "key_unit_clause_count",
        "assumption_unit_clause_count",
        "target_key_included",
        "target_trace_included",
        "body_sha256",
        "instance_sha256",
        "instance_bytes",
        "relations",
    }
    if set(value) != fields:
        raise AppleView8Error("cross-block report fields differ")
    raw_relations = _sequence(value.get("relations"), "relations")
    counters = _sequence(value.get("counters"), "counters")
    outputs = _sequence(value.get("output_sha256"), "output SHA inventory")
    payload = dict(value)
    payload["relations"] = tuple(_relation_from_mapping(row) for row in raw_relations)
    payload["counters"] = tuple(counters)
    payload["output_sha256"] = tuple(outputs)
    return CrossblockConsequenceReport(**payload)  # type: ignore[arg-type]


def _report_value(
    report: CrossblockConsequenceReport | Mapping[str, object] | str | Path,
) -> CrossblockConsequenceReport:
    if isinstance(report, CrossblockConsequenceReport):
        return report
    if isinstance(report, (str, Path)):
        return _report_from_mapping(
            _load_json(Path(report).resolve(strict=True), canonical=True, field="consequence report")
        )
    if not isinstance(report, Mapping):
        raise AppleView8Error("consequence report differs")
    return _report_from_mapping(report)


def _validate_outputs_against_source(
    source_report: Mapping[str, object], plan: CrossblockConsequencePlan
) -> None:
    blocks = _sequence(source_report.get("blocks"), "source report blocks")
    if len(blocks) != plan.block_count:
        raise AppleView8Error("output block count differs from source CNF")
    for index, raw in enumerate(blocks):
        block = _mapping(raw, "source block report")
        if (
            block.get("block_index") != index
            or block.get("counter") != plan.counters[index]
            or block.get("nonce_hex") != plan.nonce_hex
            or block.get("output_sha256") != plan.output_sha256[index]
        ):
            raise AppleView8Error("public output differs from source CNF")


def _temporary_output(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(destination)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    return descriptor, Path(raw)


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _remove_if_owned(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) == identity:
        path.unlink()


def _publish_temporary(temporary: Path, destination: Path) -> tuple[int, int]:
    metadata = temporary.stat(follow_symlinks=False)
    identity = (metadata.st_dev, metadata.st_ino)
    linked = False
    try:
        os.link(temporary, destination, follow_symlinks=False)
        linked = True
        temporary.unlink()
        parent = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except Exception:
        if linked:
            _remove_if_owned(destination, identity)
        raise
    return identity


def _augmentation_sha256(plan: CrossblockConsequencePlan) -> str:
    return _clauses_sha256(plan.clauses)


def _make_report(
    *,
    source_report: Mapping[str, object],
    semantic_document: Mapping[str, object],
    semantic_map_file_sha256: str,
    plan: CrossblockConsequencePlan,
    body_sha256: str,
    instance_sha256: str,
    instance_bytes: int,
) -> CrossblockConsequenceReport:
    return CrossblockConsequenceReport(
        schema=SCHEMA,
        source_schema=str(source_report.get("schema")),
        source_instance_sha256=str(source_report.get("instance_sha256")),
        source_report_sha256=hashlib.sha256(
            canonical_json_bytes(dict(source_report)) + b"\n"
        ).hexdigest(),
        semantic_map_file_sha256=semantic_map_file_sha256,
        semantic_map_sha256=str(semantic_document.get("map_sha256")),
        remap_rule=MULTIBLOCK_REMAP_RULE,
        block_count=plan.block_count,
        counters=plan.counters,
        nonce_hex=plan.nonce_hex,
        output_sha256=plan.output_sha256,
        final_wire_sha256=_final_wire_sha256(plan.final_wires),
        base_variable_count=plan.base_variable_count,
        base_clause_count=multiblock_clause_count(plan.block_count),
        added_variable_count=plan.ripple_carry_variable_count,
        variable_count=plan.variable_count,
        direct_final_lane_count=plan.block_count * len(PUBLIC_FINAL_LANES),
        direct_unit_clause_count=plan.direct_unit_clause_count,
        direct_unit_clause_sha256=_clauses_sha256(plan.direct_clauses),
        crossblock_relation_count=len(plan.relations),
        constant_lsb_one_relation_count=sum(row.delta & 1 for row in plan.relations),
        ripple_carry_variable_count=plan.ripple_carry_variable_count,
        ripple_clause_count=plan.ripple_clause_count,
        ripple_clause_sha256=_clauses_sha256(plan.ripple_clauses),
        augmentation_clause_count=plan.augmentation_clause_count,
        augmentation_sha256=_augmentation_sha256(plan),
        clause_count=multiblock_clause_count(plan.block_count)
        + plan.augmentation_clause_count,
        key_unit_clause_count=0,
        assumption_unit_clause_count=0,
        target_key_included=False,
        target_trace_included=False,
        body_sha256=body_sha256,
        instance_sha256=instance_sha256,
        instance_bytes=instance_bytes,
        relations=plan.relations,
    )


def _validate_paths(
    *,
    source: Path,
    template: Path,
    sidecar: Path,
    instances: Sequence[SourceRow],
    destination: Path,
    report_destination: Path | None,
) -> None:
    protected = {source, template, sidecar}
    for raw in instances:
        if not isinstance(raw, tuple) or len(raw) != 2:
            raise AppleView8Error("source instance row differs")
        protected.add(Path(raw[0]).resolve(strict=True))
        if isinstance(raw[1], (str, Path)):
            protected.add(Path(raw[1]).resolve(strict=True))
    if destination in protected or report_destination in protected | {destination}:
        raise AppleView8Error("consequence output paths collide")


def write_crossblock_consequence_cnf(
    multiblock_path: str | Path,
    multiblock_report: Full256MultiblockCNFReport | Mapping[str, object] | str | Path,
    template_path: str | Path,
    semantic_map_path: str | Path,
    instances: Sequence[SourceRow],
    destination_path: str | Path,
    *,
    output_blocks: Sequence[bytes],
    counters: Sequence[int],
    nonce: bytes,
    report_path: str | Path | None = None,
) -> CrossblockConsequenceReport:
    """Verify the base, append exact consequences, and publish atomically."""

    source = Path(multiblock_path).resolve(strict=True)
    template = Path(template_path).resolve(strict=True)
    sidecar = Path(semantic_map_path).resolve(strict=True)
    destination = Path(destination_path).resolve()
    report_destination = None if report_path is None else Path(report_path).resolve()
    rows = tuple(instances)
    _validate_paths(
        source=source,
        template=template,
        sidecar=sidecar,
        instances=rows,
        destination=destination,
        report_destination=report_destination,
    )
    if destination.exists() or (
        report_destination is not None and report_destination.exists()
    ):
        raise FileExistsError("consequence outputs are immutable and must not exist")
    source_fingerprint = _fingerprint(source)
    map_fingerprint = _fingerprint(sidecar)
    verify_full256_multiblock_cnf(
        source, template, sidecar, rows, multiblock_report
    )
    source_report = _source_report_mapping(multiblock_report)
    semantic_document = load_full256_template_map(sidecar)
    plan = compile_crossblock_consequences(
        sidecar,
        output_blocks=output_blocks,
        counters=counters,
        nonce=nonce,
        base_variable_count=cast(int, source_report.get("variable_count")),
    )
    _validate_outputs_against_source(source_report, plan)
    expected_source_header = (
        f"p cnf {plan.base_variable_count} {multiblock_clause_count(plan.block_count)}\n"
    ).encode("ascii")
    header = (
        f"p cnf {plan.variable_count} "
        f"{multiblock_clause_count(plan.block_count) + plan.augmentation_clause_count}\n"
    ).encode("ascii")

    descriptor, temporary = _temporary_output(destination)
    report_temporary: Path | None = None
    published: dict[Path, tuple[int, int]] = {}
    try:
        artifact_digest = hashlib.sha256()
        body_digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as base:
            if base.readline() != expected_source_header:
                raise AppleView8Error("source multiblock header differs")
            output.write(header)
            artifact_digest.update(header)
            for chunk in iter(lambda: base.read(1 << 20), b""):
                output.write(chunk)
                artifact_digest.update(chunk)
                body_digest.update(chunk)
            for clause in plan.clauses:
                raw = _clause_bytes(clause)
                output.write(raw)
                artifact_digest.update(raw)
                body_digest.update(raw)
            output.flush()
            os.fsync(output.fileno())
        if _fingerprint(source) != source_fingerprint or _fingerprint(sidecar) != map_fingerprint:
            raise AppleView8Error("inputs changed while writing consequence CNF")
        report = _make_report(
            source_report=source_report,
            semantic_document=semantic_document,
            semantic_map_file_sha256=_sha256_file(sidecar),
            plan=plan,
            body_sha256=body_digest.hexdigest(),
            instance_sha256=artifact_digest.hexdigest(),
            instance_bytes=temporary.stat().st_size,
        )
        if report_destination is not None:
            report_descriptor, report_temporary = _temporary_output(report_destination)
            with os.fdopen(report_descriptor, "wb") as handle:
                handle.write(canonical_json_bytes(report.describe()) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        published[destination] = _publish_temporary(temporary, destination)
        if report_destination is not None and report_temporary is not None:
            published[report_destination] = _publish_temporary(
                report_temporary, report_destination
            )
            report_temporary = None
        return report
    except Exception:
        _remove_if_present(temporary)
        if report_temporary is not None:
            _remove_if_present(report_temporary)
        for path, identity in published.items():
            _remove_if_owned(path, identity)
        raise


def _read_exact(handle: IO[bytes], size: int) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        raise AppleView8Error("consequence DIMACS ended early")
    return value


def verify_crossblock_consequence_cnf(
    instance_path: str | Path,
    multiblock_path: str | Path,
    multiblock_report: Full256MultiblockCNFReport | Mapping[str, object] | str | Path,
    template_path: str | Path,
    semantic_map_path: str | Path,
    instances: Sequence[SourceRow],
    report: CrossblockConsequenceReport | Mapping[str, object] | str | Path,
    *,
    output_blocks: Sequence[bytes],
    counters: Sequence[int],
    nonce: bytes,
) -> dict[str, object]:
    """Recompute the source, wires, clauses, bytes, hashes, and strict report."""

    target = Path(instance_path).resolve(strict=True)
    source = Path(multiblock_path).resolve(strict=True)
    template = Path(template_path).resolve(strict=True)
    sidecar = Path(semantic_map_path).resolve(strict=True)
    rows = tuple(instances)
    if target in (source, template, sidecar):
        raise AppleView8Error("verification paths collide")
    source_fingerprint = _fingerprint(source)
    map_fingerprint = _fingerprint(sidecar)
    verify_full256_multiblock_cnf(source, template, sidecar, rows, multiblock_report)
    source_report = _source_report_mapping(multiblock_report)
    expected_report = _report_value(report)
    semantic_document = load_full256_template_map(sidecar)
    plan = compile_crossblock_consequences(
        sidecar,
        output_blocks=output_blocks,
        counters=counters,
        nonce=nonce,
        base_variable_count=cast(int, source_report.get("variable_count")),
    )
    _validate_outputs_against_source(source_report, plan)
    source_header = (
        f"p cnf {plan.base_variable_count} {multiblock_clause_count(plan.block_count)}\n"
    ).encode("ascii")
    target_header = (
        f"p cnf {plan.variable_count} "
        f"{multiblock_clause_count(plan.block_count) + plan.augmentation_clause_count}\n"
    ).encode("ascii")
    artifact_digest = hashlib.sha256()
    body_digest = hashlib.sha256()
    with target.open("rb") as actual, source.open("rb") as base:
        if actual.readline() != target_header or base.readline() != source_header:
            raise AppleView8Error("consequence DIMACS header differs")
        artifact_digest.update(target_header)
        for expected in iter(lambda: base.read(1 << 20), b""):
            observed = _read_exact(actual, len(expected))
            if observed != expected:
                raise AppleView8Error("base multiblock byte stream differs")
            artifact_digest.update(observed)
            body_digest.update(observed)
        for clause in plan.clauses:
            expected = _clause_bytes(clause)
            observed = _read_exact(actual, len(expected))
            if observed != expected:
                raise AppleView8Error("cross-block consequence byte stream differs")
            artifact_digest.update(observed)
            body_digest.update(observed)
        if actual.read(1):
            raise AppleView8Error("consequence DIMACS has trailing bytes")
    actual_report = _make_report(
        source_report=source_report,
        semantic_document=semantic_document,
        semantic_map_file_sha256=_sha256_file(sidecar),
        plan=plan,
        body_sha256=body_digest.hexdigest(),
        instance_sha256=artifact_digest.hexdigest(),
        instance_bytes=target.stat().st_size,
    )
    if (
        _fingerprint(source) != source_fingerprint
        or _fingerprint(sidecar) != map_fingerprint
        or actual_report != expected_report
    ):
        raise AppleView8Error("consequence report binding differs")
    return {
        "schema": VERIFICATION_SCHEMA,
        "ok": True,
        "block_count": plan.block_count,
        "variable_count": actual_report.variable_count,
        "clause_count": actual_report.clause_count,
        "augmentation_clause_count": actual_report.augmentation_clause_count,
        "key_unit_clause_count": 0,
        "assumption_unit_clause_count": 0,
        "instance_sha256": actual_report.instance_sha256,
        "augmentation_sha256": actual_report.augmentation_sha256,
    }


def _manifest_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text("ascii").splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise AppleView8Error("O1C57 manifest row differs")
        digest, relative = line[:64], line[66:]
        candidate = Path(relative)
        if (
            not _is_sha256(digest)
            or not relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or relative in rows
        ):
            raise AppleView8Error("O1C57 manifest inventory differs")
        rows[relative] = digest
    return rows


def preflight_o1c57_consumed_public_build(
    capsule_path: str | Path,
) -> dict[str, object]:
    """Pure preflight for a later O1C57 consequence build.

    Only the manifest, config, sealed public publication, and frozen template
    inputs are read.  The reveal/result are deliberately not opened.  No target,
    CNF instance, report, or solver process is created.
    """

    capsule = Path(capsule_path).resolve(strict=True)
    if not capsule.is_dir() or capsule.name != O1C57_CAPSULE_NAME:
        raise AppleView8Error("O1C57 consumed capsule differs")
    manifest = capsule / "artifacts.sha256"
    if _sha256_file(manifest) != O1C57_MANIFEST_SHA256:
        raise AppleView8Error("O1C57 manifest hash differs")
    inventory = _manifest_rows(manifest)
    required = {
        "config.json": O1C57_CONFIG_FILE_SHA256,
        "publication.json": O1C57_PUBLICATION_FILE_SHA256,
    }
    for relative, expected in required.items():
        path = capsule / relative
        if inventory.get(relative) != expected or _sha256_file(path) != expected:
            raise AppleView8Error(f"O1C57 {relative} hash differs")
    config = _load_json(capsule / "config.json", canonical=False, field="O1C57 config")
    publication = _load_json(
        capsule / "publication.json", canonical=True, field="O1C57 publication"
    )
    source = _mapping(config.get("source"), "O1C57 source")
    expected_hashes = _mapping(source.get("expected_sha256"), "O1C57 source hashes")
    target = _mapping(config.get("target"), "O1C57 target")
    public_view = _mapping(publication.get("public_view"), "O1C57 public view")
    if (
        config.get("schema") != "o1-256-multiblock-parent-criticality-rank-config-v1"
        or config.get("attempt_id") != "O1C-0057"
        or target.get("target_id") != "o1c-0057-multiblock-fresh-0000"
        or target.get("block_count") != 8
        or publication.get("schema") != "o1-256-sealed-publication-v1"
        or publication.get("target_id") != target.get("target_id")
        or public_view.get("schema") != "o1-256-public-target-view-v1"
        or public_view.get("unknown_key_bits") != 256
        or public_view.get("target_key_included") is not False
        or public_view.get("target_trace_included") is not False
        or public_view.get("rounds") != 20
        or public_view.get("feed_forward") is not True
        or canonical_sha256(dict(public_view)) != publication.get("public_view_sha256")
        or canonical_sha256(
            {key: value for key, value in publication.items() if key != "publication_sha256"}
        )
        != publication.get("publication_sha256")
    ):
        raise AppleView8Error("O1C57 public binding differs")

    lab_root = capsule.parent.parent.resolve(strict=True)
    raw_template = source.get("template")
    raw_map = source.get("semantic_map")
    if not isinstance(raw_template, str) or not isinstance(raw_map, str):
        raise AppleView8Error("O1C57 template paths differ")
    template = (lab_root / raw_template).resolve(strict=True)
    sidecar = (lab_root / raw_map).resolve(strict=True)
    if lab_root not in template.parents or lab_root not in sidecar.parents:
        raise AppleView8Error("O1C57 template path escapes the lab")
    if (
        expected_hashes.get("template") != O1C57_TEMPLATE_SHA256
        or expected_hashes.get("semantic_map") != O1C57_SEMANTIC_MAP_FILE_SHA256
        or _sha256_file(template) != O1C57_TEMPLATE_SHA256
        or _sha256_file(sidecar) != O1C57_SEMANTIC_MAP_FILE_SHA256
    ):
        raise AppleView8Error("O1C57 frozen template hash differs")
    template_verification = verify_full256_template(template, sidecar)
    if template_verification.get("ok") is not True:
        raise AppleView8Error("O1C57 template verification differs")

    raw_counters = _sequence(public_view.get("counter_schedule"), "counter schedule")
    raw_outputs = _sequence(public_view.get("output_blocks_hex"), "output blocks")
    raw_nonce = public_view.get("nonce_hex")
    if (
        len(raw_counters) != 8
        or any(not _is_int(value) for value in raw_counters)
        or len(raw_outputs) != 8
        or any(not isinstance(value, str) or len(value) != 128 for value in raw_outputs)
        or not isinstance(raw_nonce, str)
        or len(raw_nonce) != 24
    ):
        raise AppleView8Error("O1C57 public block inventory differs")
    try:
        outputs = tuple(bytes.fromhex(cast(str, value)) for value in raw_outputs)
        nonce = bytes.fromhex(raw_nonce)
    except ValueError as exc:
        raise AppleView8Error("O1C57 public hex encoding differs") from exc
    counters = tuple(cast(int, value) for value in raw_counters)
    plan = compile_crossblock_consequences(
        sidecar,
        output_blocks=outputs,
        counters=counters,
        nonce=nonce,
    )
    return {
        "schema": O1C57_PREFLIGHT_SCHEMA,
        "ok": True,
        "consumed_attempt": "O1C-0057",
        "target_id": publication["target_id"],
        "capsule_manifest_sha256": O1C57_MANIFEST_SHA256,
        "config_file_sha256": O1C57_CONFIG_FILE_SHA256,
        "publication_file_sha256": O1C57_PUBLICATION_FILE_SHA256,
        "publication_sha256": publication["publication_sha256"],
        "public_view_sha256": publication["public_view_sha256"],
        "template_path": str(template),
        "template_sha256": O1C57_TEMPLATE_SHA256,
        "semantic_map_path": str(sidecar),
        "semantic_map_file_sha256": O1C57_SEMANTIC_MAP_FILE_SHA256,
        "final_wire_sha256": _final_wire_sha256(plan.final_wires),
        "block_count": plan.block_count,
        "counters": list(plan.counters),
        "nonce_hex": plan.nonce_hex,
        "output_blocks_hex": [block.hex() for block in outputs],
        "output_sha256": list(plan.output_sha256),
        "planned_base_variable_count": plan.base_variable_count,
        "planned_base_clause_count": multiblock_clause_count(plan.block_count),
        "planned_direct_unit_clause_count": plan.direct_unit_clause_count,
        "planned_crossblock_relation_count": len(plan.relations),
        "planned_constant_lsb_one_relation_count": sum(
            relation.delta & 1 for relation in plan.relations
        ),
        "planned_ripple_carry_variable_count": plan.ripple_carry_variable_count,
        "planned_ripple_clause_count": plan.ripple_clause_count,
        "planned_augmentation_clause_count": plan.augmentation_clause_count,
        "planned_variable_count": plan.variable_count,
        "planned_clause_count": multiblock_clause_count(plan.block_count)
        + plan.augmentation_clause_count,
        "planned_direct_unit_clause_sha256": _clauses_sha256(plan.direct_clauses),
        "planned_ripple_clause_sha256": _clauses_sha256(plan.ripple_clauses),
        "planned_augmentation_sha256": _augmentation_sha256(plan),
        "fresh_target_generated": False,
        "truth_artifacts_read": False,
        "large_cnf_written": False,
        "solver_calls": 0,
    }


__all__ = [
    "AppleView8Error",
    "ConstantAdditionEncoding",
    "CrossblockConsequencePlan",
    "CrossblockConsequenceReport",
    "CrossblockRelation",
    "KEY_LANES",
    "PUBLIC_FINAL_LANES",
    "compile_crossblock_consequences",
    "crossblock_auxiliary_assignment",
    "encode_constant_addition",
    "preflight_o1c57_consumed_public_build",
    "reconstruct_final_pre_feedforward_variables",
    "verify_crossblock_consequence_cnf",
    "write_crossblock_consequence_cnf",
]
