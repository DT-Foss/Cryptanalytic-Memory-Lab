#!/usr/bin/env python3
"""Bidirectional exact constraint propagation for partial ChaCha20 carries.

The base relation is one standard 20-round ChaCha20 block with a complete
candidate key and the public output fixed.  For carry depth d, c1..c_d of all
336 additions obey the real majority recurrence; later carries remain free
Boolean variables.  XOR and majority truth tables are propagated from both
inputs and outputs until a fixed point.  A local empty domain is an exact
conflict.  A non-conflict is only UNKNOWN unless every variable was assigned.
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
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence, TypedDict


MASK32 = (1 << 32) - 1
KEY_BITS = 256
OUTPUT_BITS = 512
ADDITIONS_PER_BLOCK = 336
XOR2_PER_BLOCK = 320 * 32
XOR3_PER_BLOCK = ADDITIONS_PER_BLOCK * 32
DEFAULT_SEED = "apple-view-4-bidirectional-carry-v1-20260719"
DEFAULT_PROBES = 4
DEFAULT_DEPTHS = (24, 28, 29, 30, 31)
CPU_BUDGET_SECONDS = 30.0
MEMORY_BUDGET_BYTES = 128 * 1024 * 1024
APPLE_VIEW_4_DIR = Path(__file__).resolve().parent
UNKNOWN = 2

CONSTANT_WORDS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
RFC_KEY = bytes(range(32))
RFC_NONCE = bytes.fromhex("000000090000004a00000000")
RFC_BLOCK = bytes.fromhex(
    "10f1e7e4d13b5915500fdd1fa32071c4"
    "c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2"
    "b5129cd1de164eb9cbd083e8a2503c4e"
)

XOR2_ROWS = tuple(
    (a, b, a ^ b) for a in (0, 1) for b in (0, 1)
)
XOR3_ROWS = tuple(
    (a, b, c, a ^ b ^ c)
    for a in (0, 1)
    for b in (0, 1)
    for c in (0, 1)
)
MAJORITY_ROWS = tuple(
    (a, b, c, (a & b) | (a & c) | (b & c))
    for a in (0, 1)
    for b in (0, 1)
    for c in (0, 1)
)
TRUTH_TABLES = {
    "xor2": XOR2_ROWS,
    "xor3": XOR3_ROWS,
    "majority": MAJORITY_ROWS,
}

Word = tuple[int, ...]


@dataclass(frozen=True)
class ExperimentConfig:
    seed: str = DEFAULT_SEED
    probes: int = DEFAULT_PROBES
    depths: tuple[int, ...] = DEFAULT_DEPTHS

    def validate(self) -> None:
        if not self.seed:
            raise ValueError("seed must not be empty")
        if not 1 <= self.probes <= 128:
            raise ValueError("probes must be in [1,128]")
        if not self.depths:
            raise ValueError("at least one carry depth is required")
        if tuple(sorted(set(self.depths))) != self.depths:
            raise ValueError("carry depths must be unique and strictly increasing")
        if any(depth < 0 or depth > 31 for depth in self.depths):
            raise ValueError("carry depths must be in [0,31]")


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
class Constraint:
    kind: str
    variables: tuple[int, ...]


@dataclass(frozen=True)
class CompiledNetwork:
    carry_depth: int
    variable_count: int
    constraints: tuple[Constraint, ...]
    adjacency: tuple[tuple[int, ...], ...]
    fixed_assignments: tuple[tuple[int, int], ...]
    key_variables: tuple[int, ...]
    output_variables: tuple[int, ...]
    additions: int
    xor2_constraints: int
    xor3_constraints: int
    majority_constraints: int
    free_carry_variables: int


@dataclass
class WorkMeter:
    networks_compiled: int = 0
    variables_compiled: int = 0
    constraints_compiled: int = 0
    propagation_calls: int = 0
    constraint_visits: int = 0
    truth_table_rows_checked: int = 0
    inferred_assignments: int = 0
    exact_conflicts: int = 0
    concrete_block_evaluations: int = 0


class PropagationRow(TypedDict):
    status: str
    conflict_constraint: int | None
    conflict_kind: str | None
    assigned_variables: int
    initial_assigned_variables: int
    inferred_variables: int
    constraint_visits: int
    truth_table_rows_checked: int


class ProbeSummary(TypedDict):
    probes: int
    exact_conflicts: int
    unknown_survivors: int
    consistent_complete: int
    assigned_variables_min: int
    assigned_variables_max: int
    assigned_variables_mean: float
    inferred_variables_min: int
    inferred_variables_max: int
    inferred_variables_mean: float


class NetworkSummary(TypedDict):
    variables: int
    constraints: int
    additions: int
    xor2_constraints: int
    xor3_constraints: int
    majority_constraints: int
    free_carry_variables: int


class DepthResultRow(TypedDict):
    carry_depth: int
    network: NetworkSummary
    truth: PropagationRow
    probe_summary: ProbeSummary
    probe_rows: list[dict[str, object]]


class SyntheticSanity(TypedDict):
    forced_right_values: list[int]
    forced_right_is_zero: bool
    setting_right_one_conflicts: bool


def _derive(seed: str, label: str, index: int, length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(seed.encode("utf-8"))
    shake.update(b"\x00")
    shake.update(label.encode("ascii"))
    shake.update(index.to_bytes(8, "little", signed=False))
    return shake.digest(length)


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & MASK32) | (value >> (32 - distance))


def _quarter_round_concrete(
    state: list[int], a: int, b: int, c: int, d: int
) -> None:
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
    initial = _initial_words(key, counter, nonce)
    state = list(initial)
    for _ in range(10):
        _quarter_round_concrete(state, 0, 4, 8, 12)
        _quarter_round_concrete(state, 1, 5, 9, 13)
        _quarter_round_concrete(state, 2, 6, 10, 14)
        _quarter_round_concrete(state, 3, 7, 11, 15)
        _quarter_round_concrete(state, 0, 5, 10, 15)
        _quarter_round_concrete(state, 1, 6, 11, 12)
        _quarter_round_concrete(state, 2, 7, 8, 13)
        _quarter_round_concrete(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *((word + base) & MASK32 for word, base in zip(state, initial))
    )


def generate_target(config: ExperimentConfig) -> tuple[PublicTarget, bytes]:
    key = _derive(config.seed, "measurement-key", 0, 32)
    nonce = _derive(config.seed, "public-nonce", 0, 12)
    counter = int.from_bytes(_derive(config.seed, "public-counter", 0, 4), "little")
    return PublicTarget(counter, nonce, chacha20_block(key, counter, nonce)), key


def generate_probe_keys(config: ExperimentConfig) -> tuple[bytes, ...]:
    return tuple(
        _derive(config.seed, "output-independent-probe-key", index, 32)
        for index in range(config.probes)
    )


class NetworkBuilder:
    def __init__(self, carry_depth: int) -> None:
        if not 0 <= carry_depth <= 31:
            raise ValueError("carry_depth must be in [0,31]")
        self.carry_depth = carry_depth
        self.constraints: list[Constraint] = []
        self.adjacency: list[list[int]] = []
        self.fixed_assignments: list[tuple[int, int]] = []
        self.additions = 0
        self.xor2_constraints = 0
        self.xor3_constraints = 0
        self.majority_constraints = 0
        self.free_carry_variables = 0
        self.zero = self._new_variable()
        self.one = self._new_variable()
        self.fixed_assignments.extend(((self.zero, 0), (self.one, 1)))
        self.key_variables = tuple(self._new_variable() for _ in range(KEY_BITS))

    def _new_variable(self) -> int:
        variable = len(self.adjacency)
        self.adjacency.append([])
        return variable

    def _add_constraint(self, kind: str, variables: Iterable[int]) -> None:
        row = Constraint(kind, tuple(variables))
        if kind not in TRUTH_TABLES:
            raise ValueError(f"unknown constraint kind: {kind}")
        if len(row.variables) != len(TRUTH_TABLES[kind][0]):
            raise ValueError("constraint arity differs from truth table")
        constraint_id = len(self.constraints)
        self.constraints.append(row)
        for variable in set(row.variables):
            self.adjacency[variable].append(constraint_id)

    def _constant_word(self, value: int) -> Word:
        return tuple(self.one if (value >> bit) & 1 else self.zero for bit in range(32))

    def _key_word(self, first_bit: int) -> Word:
        return self.key_variables[first_bit : first_bit + 32]

    def _xor2(self, left: int, right: int) -> int:
        output = self._new_variable()
        self._add_constraint("xor2", (left, right, output))
        self.xor2_constraints += 1
        return output

    def _xor3(self, a: int, b: int, c: int) -> int:
        output = self._new_variable()
        self._add_constraint("xor3", (a, b, c, output))
        self.xor3_constraints += 1
        return output

    def _majority(self, a: int, b: int, c: int) -> int:
        output = self._new_variable()
        self._add_constraint("majority", (a, b, c, output))
        self.majority_constraints += 1
        return output

    def _xor_words(self, left: Word, right: Word) -> Word:
        return tuple(
            self._xor2(a, b) for a, b in zip(left, right, strict=True)
        )

    @staticmethod
    def _rotl_word(word: Word, distance: int) -> Word:
        return word[-distance:] + word[:-distance]

    def _add_words(self, left: Word, right: Word) -> Word:
        self.additions += 1
        carry = self.zero
        output: list[int] = []
        for bit, (a, b) in enumerate(zip(left, right, strict=True)):
            output.append(self._xor3(a, b, carry))
            if bit == 31:
                continue
            if bit < self.carry_depth:
                carry = self._majority(a, b, carry)
            else:
                carry = self._new_variable()
                self.free_carry_variables += 1
        return tuple(output)

    def _quarter_round(
        self, state: list[Word], a: int, b: int, c: int, d: int
    ) -> None:
        state[a] = self._add_words(state[a], state[b])
        state[d] = self._rotl_word(self._xor_words(state[d], state[a]), 16)
        state[c] = self._add_words(state[c], state[d])
        state[b] = self._rotl_word(self._xor_words(state[b], state[c]), 12)
        state[a] = self._add_words(state[a], state[b])
        state[d] = self._rotl_word(self._xor_words(state[d], state[a]), 8)
        state[c] = self._add_words(state[c], state[d])
        state[b] = self._rotl_word(self._xor_words(state[b], state[c]), 7)

    def compile(self, counter: int, nonce: bytes) -> CompiledNetwork:
        if not 0 <= counter <= MASK32 or len(nonce) != 12:
            raise ValueError("invalid public counter or nonce")
        initial: list[Word] = [
            *(self._constant_word(word) for word in CONSTANT_WORDS),
            *(self._key_word(32 * word) for word in range(8)),
            self._constant_word(counter),
            *(
                self._constant_word(word)
                for word in struct.unpack("<3I", nonce)
            ),
        ]
        state = list(initial)
        for _ in range(10):
            self._quarter_round(state, 0, 4, 8, 12)
            self._quarter_round(state, 1, 5, 9, 13)
            self._quarter_round(state, 2, 6, 10, 14)
            self._quarter_round(state, 3, 7, 11, 15)
            self._quarter_round(state, 0, 5, 10, 15)
            self._quarter_round(state, 1, 6, 11, 12)
            self._quarter_round(state, 2, 7, 8, 13)
            self._quarter_round(state, 3, 4, 9, 14)
        output_words = [
            self._add_words(word, base)
            for word, base in zip(state, initial, strict=True)
        ]
        if self.additions != ADDITIONS_PER_BLOCK:
            raise AssertionError("full block must compile exactly 336 additions")
        if self.xor2_constraints != XOR2_PER_BLOCK:
            raise AssertionError("full block XOR2 count differs")
        if self.xor3_constraints != XOR3_PER_BLOCK:
            raise AssertionError("full block XOR3 count differs")
        if self.majority_constraints != ADDITIONS_PER_BLOCK * self.carry_depth:
            raise AssertionError("majority constraint count differs")
        if self.free_carry_variables != ADDITIONS_PER_BLOCK * (31 - self.carry_depth):
            raise AssertionError("free carry count differs")
        return CompiledNetwork(
            self.carry_depth,
            len(self.adjacency),
            tuple(self.constraints),
            tuple(tuple(rows) for rows in self.adjacency),
            tuple(self.fixed_assignments),
            self.key_variables,
            tuple(variable for word in output_words for variable in word),
            self.additions,
            self.xor2_constraints,
            self.xor3_constraints,
            self.majority_constraints,
            self.free_carry_variables,
        )


def compile_network(
    target: PublicTarget, carry_depth: int, meter: WorkMeter | None = None
) -> CompiledNetwork:
    """Compile public structure only; no candidate or truth key is accepted."""

    target.validate()
    network = NetworkBuilder(carry_depth).compile(target.counter, target.nonce)
    if len(network.output_variables) != OUTPUT_BITS:
        raise AssertionError("compiled output must contain 512 variables")
    if meter is not None:
        meter.networks_compiled += 1
        meter.variables_compiled += network.variable_count
        meter.constraints_compiled += len(network.constraints)
    return network


def _assignment_pairs(variables: Sequence[int], packed: bytes) -> tuple[tuple[int, int], ...]:
    if len(variables) != 8 * len(packed):
        raise ValueError("packed assignment width differs from variable count")
    return tuple(
        (variable, (packed[index // 8] >> (index & 7)) & 1)
        for index, variable in enumerate(variables)
    )


def _viable_rows(
    constraint: Constraint, values: bytearray, meter: WorkMeter | None
) -> tuple[tuple[int, ...], ...]:
    viable: list[tuple[int, ...]] = []
    for row in TRUTH_TABLES[constraint.kind]:
        if meter is not None:
            meter.truth_table_rows_checked += 1
        by_variable: dict[int, int] = {}
        valid = True
        for variable, candidate in zip(constraint.variables, row, strict=True):
            prior = by_variable.get(variable)
            if prior is not None and prior != candidate:
                valid = False
                break
            by_variable[variable] = candidate
            assigned = values[variable]
            if assigned != UNKNOWN and assigned != candidate:
                valid = False
                break
        if valid:
            viable.append(row)
    return tuple(viable)


def propagate_candidate(
    network: CompiledNetwork,
    target: PublicTarget,
    candidate_key: bytes,
    meter: WorkMeter | None = None,
) -> PropagationRow:
    """Run deterministic bidirectional truth-table propagation to fixed point."""

    target.validate()
    if len(candidate_key) != 32:
        raise ValueError("candidate_key must be exactly 32 bytes")
    values = bytearray([UNKNOWN]) * network.variable_count
    queue: deque[int] = deque()
    queued = bytearray(len(network.constraints))
    initial_assignments = (
        *network.fixed_assignments,
        *_assignment_pairs(network.key_variables, candidate_key),
        *_assignment_pairs(network.output_variables, target.block),
    )
    initial_unique: set[int] = set()

    def enqueue_neighbors(variable: int) -> None:
        for constraint_id in network.adjacency[variable]:
            if not queued[constraint_id]:
                queued[constraint_id] = 1
                queue.append(constraint_id)

    for variable, value in initial_assignments:
        prior = values[variable]
        if prior != UNKNOWN and prior != value:
            return {
                "status": "CONFLICT",
                "conflict_constraint": None,
                "conflict_kind": "initial_assignment",
                "assigned_variables": sum(item != UNKNOWN for item in values),
                "initial_assigned_variables": len(initial_unique),
                "inferred_variables": 0,
                "constraint_visits": 0,
                "truth_table_rows_checked": 0,
            }
        if prior == UNKNOWN:
            values[variable] = value
            initial_unique.add(variable)
            enqueue_neighbors(variable)

    visits_before = meter.constraint_visits if meter is not None else 0
    rows_before = meter.truth_table_rows_checked if meter is not None else 0
    inferred = 0
    if meter is not None:
        meter.propagation_calls += 1
    while queue:
        constraint_id = queue.popleft()
        queued[constraint_id] = 0
        constraint = network.constraints[constraint_id]
        if meter is not None:
            meter.constraint_visits += 1
        viable = _viable_rows(constraint, values, meter)
        if not viable:
            if meter is not None:
                meter.exact_conflicts += 1
            return {
                "status": "CONFLICT",
                "conflict_constraint": constraint_id,
                "conflict_kind": constraint.kind,
                "assigned_variables": sum(item != UNKNOWN for item in values),
                "initial_assigned_variables": len(initial_unique),
                "inferred_variables": inferred,
                "constraint_visits": (
                    (meter.constraint_visits - visits_before) if meter is not None else 0
                ),
                "truth_table_rows_checked": (
                    (meter.truth_table_rows_checked - rows_before)
                    if meter is not None
                    else 0
                ),
            }
        possible_by_variable: dict[int, set[int]] = {}
        for position, variable in enumerate(constraint.variables):
            if values[variable] == UNKNOWN:
                possible_by_variable.setdefault(variable, set()).update(
                    row[position] for row in viable
                )
        for variable, possible in possible_by_variable.items():
            if len(possible) == 1:
                value = next(iter(possible))
                if values[variable] == UNKNOWN:
                    values[variable] = value
                    inferred += 1
                    if meter is not None:
                        meter.inferred_assignments += 1
                    enqueue_neighbors(variable)
    assigned = sum(item != UNKNOWN for item in values)
    return {
        "status": (
            "CONSISTENT_COMPLETE" if assigned == network.variable_count else "UNKNOWN"
        ),
        "conflict_constraint": None,
        "conflict_kind": None,
        "assigned_variables": assigned,
        "initial_assigned_variables": len(initial_unique),
        "inferred_variables": inferred,
        "constraint_visits": (
            (meter.constraint_visits - visits_before) if meter is not None else 0
        ),
        "truth_table_rows_checked": (
            (meter.truth_table_rows_checked - rows_before) if meter is not None else 0
        ),
    }


def synthetic_bidirectional_sanity() -> SyntheticSanity:
    """A tiny XOR where fixing both ends forces the middle, then detects conflict."""

    builder = NetworkBuilder(0)
    left = builder._new_variable()
    right = builder._new_variable()
    output = builder._xor2(left, right)
    network = CompiledNetwork(
        0,
        len(builder.adjacency),
        tuple(builder.constraints),
        tuple(tuple(rows) for rows in builder.adjacency),
        ((builder.zero, 0), (builder.one, 1)),
        (left,),
        (output,),
        0,
        1,
        0,
        0,
        0,
    )
    values = bytearray([UNKNOWN]) * network.variable_count
    values[left] = 1
    values[output] = 1
    viable = _viable_rows(network.constraints[0], values, None)
    forced_right = {row[1] for row in viable}
    conflict_if_right_one = not any(row[1] == 1 for row in viable)
    return {
        "forced_right_values": sorted(forced_right),
        "forced_right_is_zero": forced_right == {0},
        "setting_right_one_conflicts": conflict_if_right_one,
    }


def _max_rss_bytes(raw_value: int) -> int:
    return raw_value if sys.platform == "darwin" else raw_value * 1024


def _aggregate_probe_rows(rows: Sequence[PropagationRow]) -> ProbeSummary:
    conflicts = sum(row["status"] == "CONFLICT" for row in rows)
    complete = sum(row["status"] == "CONSISTENT_COMPLETE" for row in rows)
    assigned = [row["assigned_variables"] for row in rows]
    inferred = [row["inferred_variables"] for row in rows]
    return {
        "probes": len(rows),
        "exact_conflicts": conflicts,
        "unknown_survivors": len(rows) - conflicts - complete,
        "consistent_complete": complete,
        "assigned_variables_min": min(assigned),
        "assigned_variables_max": max(assigned),
        "assigned_variables_mean": sum(assigned) / len(assigned),
        "inferred_variables_min": min(inferred),
        "inferred_variables_max": max(inferred),
        "inferred_variables_mean": sum(inferred) / len(inferred),
    }


def run_experiment(config: ExperimentConfig = ExperimentConfig()) -> dict[str, object]:
    config.validate()
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    tracemalloc.start()
    meter = WorkMeter()

    if chacha20_block(RFC_KEY, 1, RFC_NONCE) != RFC_BLOCK:
        raise AssertionError("local implementation does not reproduce RFC 8439")
    meter.concrete_block_evaluations += 1
    synthetic = synthetic_bidirectional_sanity()
    if not synthetic["forced_right_is_zero"] or not synthetic["setting_right_one_conflicts"]:
        raise AssertionError("synthetic bidirectional propagation sanity failed")
    target, truth = generate_target(config)
    meter.concrete_block_evaluations += 1
    probes = generate_probe_keys(config)
    if truth in probes:
        raise AssertionError("fixed probe set unexpectedly contains truth key")

    depth_rows: list[DepthResultRow] = []
    first_conflict_depths: list[int | None] = [None] * len(probes)
    for depth in config.depths:
        network = compile_network(target, depth, meter)
        truth_row = propagate_candidate(network, target, truth, meter)
        if truth_row["status"] == "CONFLICT":
            raise AssertionError("exact relaxation rejected the true key")
        probe_rows = [
            propagate_candidate(network, target, candidate, meter)
            for candidate in probes
        ]
        for index, row in enumerate(probe_rows):
            if row["status"] == "CONFLICT" and first_conflict_depths[index] is None:
                first_conflict_depths[index] = depth
        depth_rows.append(
            {
                "carry_depth": depth,
                "network": {
                    "variables": network.variable_count,
                    "constraints": len(network.constraints),
                    "additions": network.additions,
                    "xor2_constraints": network.xor2_constraints,
                    "xor3_constraints": network.xor3_constraints,
                    "majority_constraints": network.majority_constraints,
                    "free_carry_variables": network.free_carry_variables,
                },
                "truth": truth_row,
                "probe_summary": _aggregate_probe_rows(probe_rows),
                "probe_rows": [
                    {"probe_id": index, **row}
                    for index, row in enumerate(probe_rows)
                ],
            }
        )

    sub31_conflicts = sum(
        row["probe_summary"]["exact_conflicts"]
        for row in depth_rows
        if row["carry_depth"] < 31
    )
    first_any_sub31 = next(
        (
            row["carry_depth"]
            for row in depth_rows
            if row["carry_depth"] < 31
            and row["probe_summary"]["exact_conflicts"] > 0
        ),
        None,
    )
    first_conflict_histogram = {
        str(depth): sum(value == depth for value in first_conflict_depths)
        for depth in config.depths
        if any(value == depth for value in first_conflict_depths)
    }

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

    source_path = Path(__file__).resolve()
    test_path = source_path.with_name("apple_view_4_test_bidirectional_carry.py")
    if not test_path.is_file():
        raise RuntimeError("reproduction test file is missing")
    result: dict[str, object] = {
        "schema": "apple-view-4-full256-bidirectional-carry-v1",
        "started_at": started_at,
        "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hypothesis": (
            "bidirectional local propagation between a complete candidate key and "
            "the public output exposes an exact conflict before all 31 carry layers "
            "are restored"
        ),
        "config": {
            **asdict(config),
            "depths": list(config.depths),
        },
        "attacker_boundary": {
            "primitive": "RFC 8439 ChaCha20 block, 20 rounds",
            "unknown_key_bits_in_base_problem": 256,
            "public_input": "constants + counter + 96-bit nonce + one 512-bit output",
            "complete_candidate_key_is_a_diagnostic_assumption": True,
            "probe_generation_uses_target_or_truth": False,
            "truth_key_role": "post-propagation soundness check only",
            "unbounded_cdcl_used": False,
            "search_decisions_used": False,
            "fresh_or_sealed_target": False,
            "network_used": False,
            "gpu_or_mps_used": False,
        },
        "mechanism": {
            "constraints": "exact XOR2, XOR3, and carry-majority truth tables",
            "propagation": (
                "deterministic generalized arc consistency to a fixed point from "
                "fixed public output and complete candidate input"
            ),
            "carry_depth": (
                "c1..c_d exact in every addition; c_(d+1)..c31 free Boolean variables"
            ),
            "conflict_semantics": (
                "a truth-table constraint has no row compatible with current assignments"
            ),
            "survivor_semantics": (
                "UNKNOWN means local propagation found no contradiction; it is not SAT"
            ),
        },
        "target": {
            "source": "fixed SHAKE-256 build target, committed unsealed",
            "measurement_key_hex_unsealed": truth.hex(),
            "counter": target.counter,
            "nonce_hex": target.nonce.hex(),
            "block_hex": target.block.hex(),
            "public_target_sha256": hashlib.sha256(
                struct.pack("<I", target.counter) + target.nonce + target.block
            ).hexdigest(),
        },
        "validation": {
            "rfc8439_block_vector": True,
            "synthetic_bidirectional_sanity": synthetic,
            "compile_network_parameters": list(
                inspect.signature(compile_network).parameters
            ),
            "propagate_candidate_parameters": list(
                inspect.signature(propagate_candidate).parameters
            ),
            "true_key_checked_at_every_depth": True,
            "true_key_conflicts": 0,
        },
        "depth_results": depth_rows,
        "summary": {
            "success_gate": "at least one exact false-probe conflict at depth < 31",
            "success_gate_passed": sub31_conflicts > 0,
            "first_depth_with_any_exact_conflict_below_31": first_any_sub31,
            "total_exact_conflicts_below_31_across_depth_rows": sub31_conflicts,
            "probe_first_conflict_histogram": first_conflict_histogram,
            "exact_full_key_recoveries": 0,
            "exact_key_bits_recovered": 0,
            "global_key_entropy_reduction_claimed_bits": 0,
        },
        "decision": (
            "retain bidirectional carry propagation as a candidate filter only if "
            "the frozen sub-31 conflict gate passes; otherwise close this local "
            "truth-table mechanism without extrapolating probe fractions"
        ),
        "artifact_hashes": {
            source_path.name: {
                "bytes": source_path.stat().st_size,
                "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
            },
            test_path.name: {
                "bytes": test_path.stat().st_size,
                "sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
            },
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
            **asdict(meter),
            "cpu_processes": 1,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }
    scientific_fields = {
        key: result[key]
        for key in (
            "schema",
            "hypothesis",
            "config",
            "attacker_boundary",
            "mechanism",
            "target",
            "validation",
            "depth_results",
            "summary",
            "decision",
        )
    }
    scientific_bytes = json.dumps(
        scientific_fields,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    result["reproducibility"] = {
        "scientific_payload_sha256": hashlib.sha256(scientific_bytes).hexdigest(),
        "source_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "dynamic_resource_fields_excluded_from_scientific_hash": True,
    }
    return result


def validated_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    resolved = candidate.resolve()
    if resolved.parent != APPLE_VIEW_4_DIR:
        raise ValueError("output must remain directly inside research/apple_view_4")
    if not resolved.name.startswith("apple_view_4_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_4_*.json")
    return resolved


def _parse_depths(value: str) -> tuple[int, ...]:
    try:
        depths = tuple(int(item) for item in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("depths must be comma-separated integers") from error
    if not depths:
        raise argparse.ArgumentTypeError("at least one depth is required")
    return depths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded bidirectional Full256 carry propagation."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--probes", type=int, default=DEFAULT_PROBES)
    parser.add_argument(
        "--depths",
        type=_parse_depths,
        default=DEFAULT_DEPTHS,
        help="comma-separated sorted depths",
    )
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
    result = run_experiment(ExperimentConfig(args.seed, args.probes, args.depths))
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
