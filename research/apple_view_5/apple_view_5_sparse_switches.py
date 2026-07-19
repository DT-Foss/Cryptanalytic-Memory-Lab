#!/usr/bin/env python3
"""Sparse carry-identity switches for a full-round ChaCha20 candidate filter.

APPLE-VIEW-0004 left exactly one independent c31 variable in each of the 336
32-bit additions.  This experiment compiles that depth-30 relaxation once and
turns the 336 missing majority identities on incrementally.  A conflict is an
exact rejection certificate for the complete candidate key using only the
enabled identities; a survivor is UNKNOWN unless the whole network is assigned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import resource
import struct
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence, TypedDict, cast


MASK32 = (1 << 32) - 1
KEY_BITS = 256
OUTPUT_BITS = 512
ADDITIONS_PER_BLOCK = 336
BASE_CARRY_DEPTH = 30
MATERIAL_SWITCH_LIMIT = 268  # at least 20% of the 336 identities remain absent
STRETCH_SWITCH_LIMIT = 252  # at least 25% of the identities remain absent
DEFAULT_SEED = "apple-view-4-bidirectional-carry-v1-20260719"
DEFAULT_PROBES = 4
CPU_BUDGET_SECONDS = 45.0
MEMORY_BUDGET_BYTES = 192 * 1024 * 1024
APPLE_VIEW_5_DIR = Path(__file__).resolve().parent
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

XOR2_ROWS = tuple((a, b, a ^ b) for a in (0, 1) for b in (0, 1))
XOR3_ROWS = tuple((a, b, c, a ^ b ^ c) for a in (0, 1) for b in (0, 1) for c in (0, 1))
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

    def validate(self) -> None:
        if not self.seed:
            raise ValueError("seed must not be empty")
        if not 1 <= self.probes <= 32:
            raise ValueError("probes must be in [1,32]")


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
class CarrySwitch:
    switch_id: int
    addition_index: int
    left_bit30: int
    right_bit30: int
    carry30: int
    carry31: int
    constraint_id: int


@dataclass(frozen=True)
class CompiledNetwork:
    variable_count: int
    constraints: tuple[Constraint, ...]
    adjacency: tuple[tuple[int, ...], ...]
    fixed_assignments: tuple[tuple[int, int], ...]
    key_variables: tuple[int, ...]
    output_variables: tuple[int, ...]
    base_constraint_count: int
    switches: tuple[CarrySwitch, ...]
    xor2_constraints: int
    xor3_constraints: int
    base_majority_constraints: int


@dataclass
class WorkMeter:
    networks_compiled: int = 0
    propagation_states: int = 0
    constraint_visits: int = 0
    truth_table_rows_checked: int = 0
    inferred_assignments: int = 0
    switch_activations: int = 0
    exact_conflicts: int = 0
    greedy_candidates_scored: int = 0
    concrete_block_evaluations: int = 0
    proof_slice_replays: int = 0


class RunRow(TypedDict):
    status: str
    base_status: str
    first_conflict_switch_count: int | None
    first_conflict_switch_id: int | None
    first_conflict_addition_index: int | None
    conflict_constraint: int | None
    enabled_switches: int
    omitted_switches: int
    assigned_variables: int
    initial_assigned_variables: int
    inferred_variables: int
    constraint_visits: int
    truth_table_rows_checked: int
    base_assigned_variables: int
    base_constraint_visits: int
    certificate_switch_ids: list[int]
    certificate_sha256: str | None
    proof_slice_switch_count: int | None
    proof_slice_switch_ids: list[int]
    proof_slice_sha256: str | None
    proof_slice_replay_status: str | None
    proof_slice_replay_constraint_visits: int | None


def _derive(seed: str, label: str, index: int, length: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(seed.encode("utf-8"))
    shake.update(b"\x00")
    shake.update(label.encode("ascii"))
    shake.update(index.to_bytes(8, "little", signed=False))
    return shake.digest(length)


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & MASK32) | (value >> (32 - distance))


def _quarter_round_concrete(state: list[int], a: int, b: int, c: int, d: int) -> None:
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
    """Reproduce the fixed APPLE-VIEW-0004 target exactly."""

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
    """Compile depth 30 while retaining the 336 missing c31 identities."""

    def __init__(self) -> None:
        self.constraints: list[Constraint] = []
        self.adjacency: list[list[int]] = []
        self.fixed_assignments: list[tuple[int, int]] = []
        self.pending_switch_variables: list[tuple[int, int, int, int]] = []
        self.additions = 0
        self.xor2_constraints = 0
        self.xor3_constraints = 0
        self.base_majority_constraints = 0
        self.zero = self._new_variable()
        self.one = self._new_variable()
        self.fixed_assignments.extend(((self.zero, 0), (self.one, 1)))
        self.key_variables = tuple(self._new_variable() for _ in range(KEY_BITS))

    def _new_variable(self) -> int:
        variable = len(self.adjacency)
        self.adjacency.append([])
        return variable

    def _add_constraint(self, kind: str, variables: Iterable[int]) -> int:
        row = Constraint(kind, tuple(variables))
        if kind not in TRUTH_TABLES:
            raise ValueError(f"unknown constraint kind: {kind}")
        if len(row.variables) != len(TRUTH_TABLES[kind][0]):
            raise ValueError("constraint arity differs from truth table")
        constraint_id = len(self.constraints)
        self.constraints.append(row)
        for variable in set(row.variables):
            self.adjacency[variable].append(constraint_id)
        return constraint_id

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
        self.base_majority_constraints += 1
        return output

    def _xor_words(self, left: Word, right: Word) -> Word:
        return tuple(self._xor2(a, b) for a, b in zip(left, right, strict=True))

    @staticmethod
    def _rotl_word(word: Word, distance: int) -> Word:
        return word[-distance:] + word[:-distance]

    def _add_words(self, left: Word, right: Word) -> Word:
        addition_index = self.additions
        self.additions += 1
        carry = self.zero
        output: list[int] = []
        for bit, (a, b) in enumerate(zip(left, right, strict=True)):
            output.append(self._xor3(a, b, carry))
            if bit == 31:
                continue
            if bit < BASE_CARRY_DEPTH:
                carry = self._majority(a, b, carry)
            else:
                free_carry31 = self._new_variable()
                self.pending_switch_variables.append((a, b, carry, free_carry31))
                carry = free_carry31
        if len(self.pending_switch_variables) != addition_index + 1:
            raise AssertionError("each addition must contribute one c31 switch")
        return tuple(output)

    def _quarter_round(self, state: list[Word], a: int, b: int, c: int, d: int) -> None:
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
            *(self._constant_word(word) for word in struct.unpack("<3I", nonce)),
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
        if len(self.pending_switch_variables) != ADDITIONS_PER_BLOCK:
            raise AssertionError("expected exactly one missing identity per addition")
        base_constraint_count = len(self.constraints)
        switches: list[CarrySwitch] = []
        for switch_id, variables in enumerate(self.pending_switch_variables):
            constraint_id = self._add_constraint("majority", variables)
            switches.append(
                CarrySwitch(switch_id, switch_id, *variables, constraint_id)
            )
        if any(
            switch.constraint_id != base_constraint_count + switch.switch_id
            for switch in switches
        ):
            raise AssertionError("dormant switch constraints must be contiguous")
        return CompiledNetwork(
            len(self.adjacency),
            tuple(self.constraints),
            tuple(tuple(rows) for rows in self.adjacency),
            tuple(self.fixed_assignments),
            self.key_variables,
            tuple(variable for word in output_words for variable in word),
            base_constraint_count,
            tuple(switches),
            self.xor2_constraints,
            self.xor3_constraints,
            self.base_majority_constraints,
        )


def compile_network(
    target: PublicTarget, meter: WorkMeter | None = None
) -> CompiledNetwork:
    """Compile public structure only; candidate and truth are not accepted."""

    target.validate()
    network = NetworkBuilder().compile(target.counter, target.nonce)
    if len(network.output_variables) != OUTPUT_BITS:
        raise AssertionError("compiled output must contain 512 variables")
    if network.base_majority_constraints != ADDITIONS_PER_BLOCK * BASE_CARRY_DEPTH:
        raise AssertionError("depth-30 base majority count differs")
    if meter is not None:
        meter.networks_compiled += 1
    return network


def _assignment_pairs(
    variables: Sequence[int], packed: bytes
) -> tuple[tuple[int, int], ...]:
    if len(variables) != 8 * len(packed):
        raise ValueError("packed assignment width differs from variable count")
    return tuple(
        (variable, (packed[index // 8] >> (index & 7)) & 1)
        for index, variable in enumerate(variables)
    )


def _viable_rows(
    constraint: Constraint,
    values: bytearray,
    meter: WorkMeter | None = None,
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


class IncrementalPropagator:
    """Exact monotone propagation as dormant carry identities are enabled."""

    def __init__(
        self,
        network: CompiledNetwork,
        target: PublicTarget,
        candidate_key: bytes | None,
        meter: WorkMeter | None = None,
    ) -> None:
        target.validate()
        if candidate_key is not None and len(candidate_key) != 32:
            raise ValueError("candidate_key must be exactly 32 bytes")
        self.network = network
        self.meter = meter
        self.values = bytearray([UNKNOWN]) * network.variable_count
        self.active = bytearray(len(network.constraints))
        self.active[: network.base_constraint_count] = (
            b"\x01" * network.base_constraint_count
        )
        self.queue: deque[int] = deque()
        self.queued = bytearray(len(network.constraints))
        self.enabled_switch_ids: list[int] = []
        self.conflict_constraint: int | None = None
        self.conflict_antecedents: tuple[int, ...] = ()
        self.reasons: list[tuple[int, tuple[int, ...]] | None] = [
            None
        ] * network.variable_count
        self.constraint_visits = 0
        self.truth_table_rows_checked = 0
        self.inferred_variables = 0
        initial_assignments: tuple[tuple[int, int], ...] = (
            *network.fixed_assignments,
            *_assignment_pairs(network.output_variables, target.block),
        )
        if candidate_key is not None:
            initial_assignments = (
                *initial_assignments,
                *_assignment_pairs(network.key_variables, candidate_key),
            )
        initial_unique: set[int] = set()
        for variable, value in initial_assignments:
            prior = self.values[variable]
            if prior != UNKNOWN and prior != value:
                raise AssertionError("public initial assignments conflict")
            if prior == UNKNOWN:
                self.values[variable] = value
                initial_unique.add(variable)
                self._enqueue_neighbors(variable)
        self.initial_assigned_variables = len(initial_unique)
        if meter is not None:
            meter.propagation_states += 1

    @property
    def status(self) -> str:
        if self.conflict_constraint is not None:
            return "CONFLICT"
        if self.assigned_variables == self.network.variable_count:
            return "CONSISTENT_COMPLETE"
        return "UNKNOWN"

    @property
    def assigned_variables(self) -> int:
        return sum(value != UNKNOWN for value in self.values)

    def _enqueue(self, constraint_id: int) -> None:
        if self.active[constraint_id] and not self.queued[constraint_id]:
            self.queued[constraint_id] = 1
            self.queue.append(constraint_id)

    def _enqueue_neighbors(self, variable: int) -> None:
        for constraint_id in self.network.adjacency[variable]:
            self._enqueue(constraint_id)

    def propagate(self) -> str:
        if self.conflict_constraint is not None:
            return "CONFLICT"
        while self.queue:
            constraint_id = self.queue.popleft()
            self.queued[constraint_id] = 0
            constraint = self.network.constraints[constraint_id]
            self.constraint_visits += 1
            if self.meter is not None:
                self.meter.constraint_visits += 1
            before_rows = (
                self.meter.truth_table_rows_checked if self.meter is not None else 0
            )
            viable = _viable_rows(constraint, self.values, self.meter)
            if self.meter is not None:
                checked = self.meter.truth_table_rows_checked - before_rows
            else:
                checked = len(TRUTH_TABLES[constraint.kind])
            self.truth_table_rows_checked += checked
            if not viable:
                self.conflict_constraint = constraint_id
                self.conflict_antecedents = tuple(
                    dict.fromkeys(
                        variable
                        for variable in constraint.variables
                        if self.values[variable] != UNKNOWN
                    )
                )
                if self.meter is not None:
                    self.meter.exact_conflicts += 1
                return "CONFLICT"
            antecedents = tuple(
                dict.fromkeys(
                    variable
                    for variable in constraint.variables
                    if self.values[variable] != UNKNOWN
                )
            )
            possible_by_variable: dict[int, set[int]] = {}
            for position, variable in enumerate(constraint.variables):
                if self.values[variable] == UNKNOWN:
                    possible_by_variable.setdefault(variable, set()).update(
                        row[position] for row in viable
                    )
            for variable, possible in possible_by_variable.items():
                if len(possible) == 1 and self.values[variable] == UNKNOWN:
                    self.values[variable] = next(iter(possible))
                    self.reasons[variable] = (constraint_id, antecedents)
                    self.inferred_variables += 1
                    if self.meter is not None:
                        self.meter.inferred_assignments += 1
                    self._enqueue_neighbors(variable)
        return self.status

    def activate_switch(self, switch_id: int) -> str:
        if not 0 <= switch_id < len(self.network.switches):
            raise ValueError("switch_id out of range")
        switch = self.network.switches[switch_id]
        if self.active[switch.constraint_id]:
            raise ValueError("switch already active")
        if self.conflict_constraint is not None:
            raise RuntimeError("cannot activate after conflict")
        self.active[switch.constraint_id] = 1
        self.enabled_switch_ids.append(switch_id)
        self._enqueue(switch.constraint_id)
        if self.meter is not None:
            self.meter.switch_activations += 1
        return self.propagate()

    def proof_switch_ids(self) -> tuple[int, ...]:
        """Slice the actual propagation proof back to its dormant switches."""

        if self.conflict_constraint is None:
            return ()
        required_constraints = {self.conflict_constraint}
        pending = list(self.conflict_antecedents)
        seen_variables: set[int] = set()
        while pending:
            variable = pending.pop()
            if variable in seen_variables:
                continue
            seen_variables.add(variable)
            reason = self.reasons[variable]
            if reason is None:
                continue
            constraint_id, antecedents = reason
            required_constraints.add(constraint_id)
            pending.extend(antecedents)
        required_switches = {
            constraint_id - self.network.base_constraint_count
            for constraint_id in required_constraints
            if constraint_id >= self.network.base_constraint_count
        }
        return tuple(
            switch_id
            for switch_id in self.enabled_switch_ids
            if switch_id in required_switches
        )


def _certificate_sha256(switch_ids: Sequence[int]) -> str:
    payload = b"".join(value.to_bytes(2, "little") for value in switch_ids)
    return hashlib.sha256(payload).hexdigest()


def _finalize_run_row(
    state: IncrementalPropagator,
    network: CompiledNetwork,
    base_status: str,
    base_assigned: int,
    base_visits: int,
    first_switch_id: int | None,
) -> RunRow:
    enabled = list(state.enabled_switch_ids)
    conflict_constraint = state.conflict_constraint
    conflict_switch_count = len(enabled) if conflict_constraint is not None else None
    switch = network.switches[first_switch_id] if first_switch_id is not None else None
    proof_switch_ids = list(state.proof_switch_ids())
    return {
        "status": state.status,
        "base_status": base_status,
        "first_conflict_switch_count": conflict_switch_count,
        "first_conflict_switch_id": first_switch_id,
        "first_conflict_addition_index": (
            switch.addition_index if switch is not None else None
        ),
        "conflict_constraint": conflict_constraint,
        "enabled_switches": len(enabled),
        "omitted_switches": ADDITIONS_PER_BLOCK - len(enabled),
        "assigned_variables": state.assigned_variables,
        "initial_assigned_variables": state.initial_assigned_variables,
        "inferred_variables": state.inferred_variables,
        "constraint_visits": state.constraint_visits,
        "truth_table_rows_checked": state.truth_table_rows_checked,
        "base_assigned_variables": base_assigned,
        "base_constraint_visits": base_visits,
        "certificate_switch_ids": enabled if conflict_constraint is not None else [],
        "certificate_sha256": (
            _certificate_sha256(enabled) if conflict_constraint is not None else None
        ),
        "proof_slice_switch_count": (
            len(proof_switch_ids) if conflict_constraint is not None else None
        ),
        "proof_slice_switch_ids": proof_switch_ids,
        "proof_slice_sha256": (
            _certificate_sha256(proof_switch_ids)
            if conflict_constraint is not None
            else None
        ),
        "proof_slice_replay_status": None,
        "proof_slice_replay_constraint_visits": None,
    }


def _verify_proof_slice(
    row: RunRow,
    network: CompiledNetwork,
    target: PublicTarget,
    candidate_key: bytes,
    meter: WorkMeter | None,
) -> None:
    if row["status"] != "CONFLICT":
        return
    proof_switch_ids = row["proof_slice_switch_ids"]
    if not proof_switch_ids:
        raise AssertionError("candidate conflict has an empty dormant-switch proof")
    replay = IncrementalPropagator(network, target, candidate_key, meter)
    if replay.propagate() == "CONFLICT":
        raise AssertionError("depth-30 base cannot be the sliced conflict")
    for switch_id in proof_switch_ids:
        if replay.activate_switch(switch_id) == "CONFLICT":
            break
    row["proof_slice_replay_status"] = replay.status
    row["proof_slice_replay_constraint_visits"] = replay.constraint_visits
    if meter is not None:
        meter.proof_slice_replays += 1
    if replay.status != "CONFLICT":
        raise AssertionError("propagation proof slice did not replay as a conflict")


def run_order(
    network: CompiledNetwork,
    target: PublicTarget,
    candidate_key: bytes | None,
    order: Sequence[int],
    meter: WorkMeter | None = None,
) -> RunRow:
    if tuple(sorted(order)) != tuple(range(ADDITIONS_PER_BLOCK)):
        raise ValueError("order must be a permutation of all 336 switches")
    state = IncrementalPropagator(network, target, candidate_key, meter)
    base_status = state.propagate()
    base_assigned = state.assigned_variables
    base_visits = state.constraint_visits
    if base_status == "CONFLICT":
        raise AssertionError("depth-30 base unexpectedly conflicts")
    first_switch_id: int | None = None
    for switch_id in order:
        if state.activate_switch(switch_id) == "CONFLICT":
            first_switch_id = switch_id
            break
    row = _finalize_run_row(
        state,
        network,
        base_status,
        base_assigned,
        base_visits,
        first_switch_id,
    )
    if candidate_key is not None:
        _verify_proof_slice(row, network, target, candidate_key, meter)
    return row


def _public_random_order(seed: str, target: PublicTarget) -> tuple[int, ...]:
    public_bytes = struct.pack("<I", target.counter) + target.nonce + target.block
    digest = hashlib.sha256(
        seed.encode("utf-8") + b"\x00apple-view-5-public-order\x00" + public_bytes
    ).digest()
    rng = random.Random(int.from_bytes(digest, "big"))
    order = list(range(ADDITIONS_PER_BLOCK))
    rng.shuffle(order)
    return tuple(order)


def _local_gain(constraint: Constraint, values: bytearray) -> tuple[int, int, int]:
    """Return forced unknowns, known positions, and inverse viable-row count."""

    viable = _viable_rows(constraint, values)
    if not viable:
        return (10_000, 10_000, 0)
    possible_by_variable: dict[int, set[int]] = {}
    known = 0
    for position, variable in enumerate(constraint.variables):
        if values[variable] == UNKNOWN:
            possible_by_variable.setdefault(variable, set()).update(
                row[position] for row in viable
            )
        else:
            known += 1
    forced = sum(len(possible) == 1 for possible in possible_by_variable.values())
    return forced, known, -len(viable)


def public_gain_greedy_order(
    network: CompiledNetwork,
    target: PublicTarget,
    meter: WorkMeter | None = None,
) -> tuple[tuple[int, ...], dict[str, object]]:
    """Build an order online from public assignments only, never a probe or truth."""

    state = IncrementalPropagator(network, target, None, meter)
    if state.propagate() == "CONFLICT":
        raise AssertionError("public depth-30 relaxation must be consistent")
    base_assigned_variables = state.assigned_variables
    remaining = set(range(ADDITIONS_PER_BLOCK))
    order: list[int] = []
    selected_score_histogram: dict[str, int] = {}
    assigned_trace: list[dict[str, int]] = []
    while remaining:
        scored: list[tuple[tuple[int, int, int], int]] = []
        for switch_id in remaining:
            constraint = network.constraints[network.switches[switch_id].constraint_id]
            scored.append((_local_gain(constraint, state.values), switch_id))
        if meter is not None:
            meter.greedy_candidates_scored += len(scored)
        best_score, selected = max(scored, key=lambda item: (item[0], -item[1]))
        order.append(selected)
        remaining.remove(selected)
        key = "/".join(str(value) for value in best_score)
        selected_score_histogram[key] = selected_score_histogram.get(key, 0) + 1
        before = state.assigned_variables
        if state.activate_switch(selected) == "CONFLICT":
            raise AssertionError("public-only switch ordering must retain a solution")
        after = state.assigned_variables
        if after != before or best_score[0] != 0:
            assigned_trace.append(
                {
                    "step": len(order),
                    "switch_id": selected,
                    "immediate_forced_score": best_score[0],
                    "assigned_before": before,
                    "assigned_after": after,
                }
            )
    return tuple(order), {
        "uses_probe_key": False,
        "uses_truth_key": False,
        "initial_assigned_variables": state.initial_assigned_variables,
        "base_assigned_variables": base_assigned_variables,
        "final_assigned_variables": state.assigned_variables,
        "selected_score_histogram": selected_score_histogram,
        "nonzero_assignment_trace": assigned_trace,
        "constraint_visits": state.constraint_visits,
        "truth_table_rows_checked": state.truth_table_rows_checked,
    }


def candidate_gain_greedy_run(
    network: CompiledNetwork,
    target: PublicTarget,
    candidate_key: bytes,
    meter: WorkMeter | None = None,
) -> tuple[RunRow, dict[str, object]]:
    """Pick each next switch from public output plus the candidate under test.

    This is attacker-valid candidate filtering, not hidden-truth guidance: a
    verifier necessarily knows the complete candidate it is trying to reject.
    """

    state = IncrementalPropagator(network, target, candidate_key, meter)
    base_status = state.propagate()
    if base_status == "CONFLICT":
        raise AssertionError("depth-30 base unexpectedly conflicts")
    base_assigned = state.assigned_variables
    base_visits = state.constraint_visits
    remaining = set(range(ADDITIONS_PER_BLOCK))
    selected_score_histogram: dict[str, int] = {}
    score_trace: list[dict[str, int]] = []
    candidates_scored = 0
    first_switch_id: int | None = None
    while remaining:
        scored: list[tuple[tuple[int, int, int], int]] = []
        for switch_id in remaining:
            constraint = network.constraints[network.switches[switch_id].constraint_id]
            scored.append((_local_gain(constraint, state.values), switch_id))
        candidates_scored += len(scored)
        if meter is not None:
            meter.greedy_candidates_scored += len(scored)
        best_score, selected = max(scored, key=lambda item: (item[0], -item[1]))
        remaining.remove(selected)
        key = "/".join(str(value) for value in best_score)
        selected_score_histogram[key] = selected_score_histogram.get(key, 0) + 1
        before = state.assigned_variables
        status = state.activate_switch(selected)
        after = state.assigned_variables
        score_trace.append(
            {
                "step": len(state.enabled_switch_ids),
                "switch_id": selected,
                "forced_score": best_score[0],
                "known_positions_score": best_score[1],
                "inverse_viable_rows_score": best_score[2],
                "assigned_before": before,
                "assigned_after": after,
            }
        )
        if status == "CONFLICT":
            first_switch_id = selected
            break
    row = _finalize_run_row(
        state,
        network,
        base_status,
        base_assigned,
        base_visits,
        first_switch_id,
    )
    _verify_proof_slice(row, network, target, candidate_key, meter)
    return row, {
        "uses_public_target": True,
        "uses_candidate_under_test": True,
        "candidates_scored": candidates_scored,
        "selected_score_histogram": selected_score_histogram,
        "selection_trace": score_trace,
    }


def build_orders(
    network: CompiledNetwork,
    target: PublicTarget,
    seed: str,
    meter: WorkMeter | None = None,
) -> tuple[dict[str, tuple[int, ...]], dict[str, object]]:
    greedy, greedy_ledger = public_gain_greedy_order(network, target, meter)
    orders = {
        "early_to_final": tuple(range(ADDITIONS_PER_BLOCK)),
        "final_to_early": tuple(reversed(range(ADDITIONS_PER_BLOCK))),
        "deterministic_public_random": _public_random_order(seed, target),
        "online_public_gain_greedy": greedy,
    }
    for order in orders.values():
        if tuple(sorted(order)) != tuple(range(ADDITIONS_PER_BLOCK)):
            raise AssertionError("constructed order is not a permutation")
    return orders, greedy_ledger


def _max_rss_bytes(raw_value: int) -> int:
    return raw_value if sys.platform == "darwin" else raw_value * 1024


def _order_sha256(order: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(value.to_bytes(2, "little") for value in order)
    ).hexdigest()


def _scientific_payload(result: dict[str, object]) -> dict[str, object]:
    return {
        key: result[key]
        for key in (
            "schema",
            "hypothesis",
            "config",
            "attacker_boundary",
            "mechanism",
            "target",
            "orders",
            "probe_results",
            "truth_controls",
            "summary",
            "decision",
        )
    }


def run_experiment(config: ExperimentConfig = ExperimentConfig()) -> dict[str, object]:
    config.validate()
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    meter = WorkMeter()

    if chacha20_block(RFC_KEY, 1, RFC_NONCE) != RFC_BLOCK:
        raise AssertionError("local implementation does not reproduce RFC 8439")
    meter.concrete_block_evaluations += 1
    target, truth = generate_target(config)
    meter.concrete_block_evaluations += 1
    probes = generate_probe_keys(config)
    if truth in probes:
        raise AssertionError("fixed probe set unexpectedly contains truth key")
    network = compile_network(target, meter)
    orders, greedy_ledger = build_orders(network, target, config.seed, meter)

    # Outcome-bearing wrong probes run first.  Truth is deliberately untouched
    # until every public/probe result has been measured.
    probe_results: dict[str, list[dict[str, object]]] = {}
    for order_name, order in orders.items():
        rows: list[dict[str, object]] = []
        for probe_id, probe in enumerate(probes):
            row = run_order(network, target, probe, order, meter)
            rows.append({"probe_id": probe_id, **row})
        probe_results[order_name] = rows
    adaptive_rows: list[dict[str, object]] = []
    for probe_id, probe in enumerate(probes):
        row, selection_ledger = candidate_gain_greedy_run(network, target, probe, meter)
        adaptive_rows.append(
            {
                "probe_id": probe_id,
                **row,
                "selection_ledger": selection_ledger,
            }
        )
    probe_results["online_candidate_public_gain_greedy"] = adaptive_rows

    truth_controls: dict[str, RunRow] = {}
    for order_name, order in orders.items():
        truth_row = run_order(network, target, truth, order, meter)
        if truth_row["status"] == "CONFLICT":
            raise AssertionError("an exact carry-identity subset rejected truth")
        if truth_row["status"] != "CONSISTENT_COMPLETE":
            raise AssertionError("all 336 identities must complete the true execution")
        truth_controls[order_name] = truth_row
    adaptive_truth_row, _adaptive_truth_ledger = candidate_gain_greedy_run(
        network, target, truth, meter
    )
    if adaptive_truth_row["status"] != "CONSISTENT_COMPLETE":
        raise AssertionError("adaptive exact switches must complete true execution")
    truth_controls["online_candidate_public_gain_greedy"] = adaptive_truth_row

    conflict_counts = [
        cast(int, row["first_conflict_switch_count"])
        for rows in probe_results.values()
        for row in rows
        if row["first_conflict_switch_count"] is not None
    ]
    material_rows = [
        value for value in conflict_counts if value <= MATERIAL_SWITCH_LIMIT
    ]
    proof_counts = [
        cast(int, row["proof_slice_switch_count"])
        for rows in probe_results.values()
        for row in rows
        if row["proof_slice_switch_count"] is not None
    ]
    material_proof_rows = [
        value for value in proof_counts if value <= MATERIAL_SWITCH_LIMIT
    ]
    stretch_proof_rows = [
        value for value in proof_counts if value <= STRETCH_SWITCH_LIMIT
    ]
    per_order_summary: dict[str, dict[str, object]] = {}
    for order_name, rows in probe_results.items():
        values = [
            cast(int, row["first_conflict_switch_count"])
            for row in rows
            if row["first_conflict_switch_count"] is not None
        ]
        proof_values = [
            cast(int, row["proof_slice_switch_count"])
            for row in rows
            if row["proof_slice_switch_count"] is not None
        ]
        per_order_summary[order_name] = {
            "exact_rejections": len(values),
            "minimum_first_conflict_switch_count": min(values) if values else None,
            "maximum_first_conflict_switch_count": max(values) if values else None,
            "mean_first_conflict_switch_count": (
                sum(values) / len(values) if values else None
            ),
            "minimum_proof_slice_switch_count": (
                min(proof_values) if proof_values else None
            ),
            "material_rejections_at_or_below_268": sum(
                value <= MATERIAL_SWITCH_LIMIT for value in proof_values
            ),
            "stretch_rejections_at_or_below_252": sum(
                value <= STRETCH_SWITCH_LIMIT for value in proof_values
            ),
        }

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
    test_path = APPLE_VIEW_5_DIR / "apple_view_5_test_sparse_switches.py"
    result: dict[str, object] = {
        "schema": "apple-view-5-full256-sparse-carry-switches-v1",
        "started_at": started_at,
        "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "hypothesis": (
            "wrong complete 256-bit candidates can be rejected by a sparse subset "
            "of the 336 c31 majority identities missing from the depth-30 relaxation"
        ),
        "config": {
            **asdict(config),
            "base_carry_depth": BASE_CARRY_DEPTH,
            "total_switches": ADDITIONS_PER_BLOCK,
            "material_switch_limit": MATERIAL_SWITCH_LIMIT,
            "stretch_switch_limit": STRETCH_SWITCH_LIMIT,
        },
        "attacker_boundary": {
            "primitive": "RFC 8439 ChaCha20 block, 20 rounds",
            "unknown_key_bits_in_base_problem": 256,
            "public_input": "constants + counter + 96-bit nonce + one 512-bit output",
            "complete_candidate_key_is_a_diagnostic_assumption": True,
            "probe_generation_uses_target_or_truth": False,
            "fixed_order_generation_uses_probe_or_truth": False,
            "adaptive_order_uses_complete_candidate_under_test": True,
            "adaptive_order_uses_hidden_truth_for_wrong_probes": False,
            "truth_key_role": "post-experiment consistency control only",
            "unbounded_cdcl_used": False,
            "branching_or_search_decisions_used": False,
            "fixed_unsealed_target": True,
            "network_used": False,
            "gpu_or_mps_used": False,
        },
        "mechanism": {
            "base_relation": (
                "all XOR gates and c1..c30 majority recurrences exact; one independent "
                "c31 Boolean remains in each of 336 additions"
            ),
            "switch": "c31 = majority(a30,b30,c30) for one named addition",
            "propagation": (
                "deterministic incremental generalized arc consistency with no branching"
            ),
            "adaptive_picker": (
                "online lexicographic immediate propagation gain from public output plus "
                "the complete candidate being filtered; no target key or branching"
            ),
            "certificate": (
                "an empty local truth-table domain after enabling an ordered prefix; "
                "a recorded reason-DAG slice is replayed independently as the exact "
                "wrong-candidate rejection certificate"
            ),
            "materiality_rule_frozen_before_run": (
                "proof-replayed conflict at <=268 switches, leaving at least 68/336 "
                "identities absent; <=252 is retained as a 25%-omission stretch gate"
            ),
        },
        "target": {
            "source": "exact fixed APPLE-VIEW-0004 SHAKE-256 target",
            "measurement_key_hex_unsealed": truth.hex(),
            "counter": target.counter,
            "nonce_hex": target.nonce.hex(),
            "block_hex": target.block.hex(),
            "public_target_sha256": hashlib.sha256(
                struct.pack("<I", target.counter) + target.nonce + target.block
            ).hexdigest(),
        },
        "network": {
            "variables": network.variable_count,
            "base_constraints": network.base_constraint_count,
            "all_constraints": len(network.constraints),
            "xor2_constraints": network.xor2_constraints,
            "xor3_constraints": network.xor3_constraints,
            "base_majority_constraints": network.base_majority_constraints,
            "dormant_c31_identity_switches": len(network.switches),
        },
        "orders": {
            name: {
                "sha256": _order_sha256(order),
                "first_16_switch_ids": list(order[:16]),
                "last_16_switch_ids": list(order[-16:]),
            }
            for name, order in orders.items()
        }
        | {
            "online_public_gain_greedy_ledger": greedy_ledger,
            "online_candidate_public_gain_greedy": {
                "fixed_order_sha256": None,
                "reason": (
                    "the deterministic next switch is recomputed from each candidate's "
                    "current exact propagation state"
                ),
            },
        },
        "probe_results": probe_results,
        "truth_controls": truth_controls,
        "summary": {
            "success_gate": (
                "at least one exact proof-replayed wrong-probe conflict at <=268 identities"
            ),
            "success_gate_passed": bool(material_proof_rows),
            "minimum_first_conflict_switch_count": (
                min(conflict_counts) if conflict_counts else None
            ),
            "maximum_first_conflict_switch_count": (
                max(conflict_counts) if conflict_counts else None
            ),
            "exact_rejections_across_order_probe_runs": len(conflict_counts),
            "first_prefix_rejections_at_or_below_268": len(material_rows),
            "minimum_proof_slice_switch_count": (
                min(proof_counts) if proof_counts else None
            ),
            "maximum_proof_slice_switch_count": (
                max(proof_counts) if proof_counts else None
            ),
            "material_proof_rejections_at_or_below_268": len(material_proof_rows),
            "stretch_proof_rejections_at_or_below_252": len(stretch_proof_rows),
            "per_order": per_order_summary,
            "truth_controls_retained": all(
                row["status"] == "CONSISTENT_COMPLETE"
                for row in truth_controls.values()
            ),
            "exact_full_key_recoveries": 0,
            "exact_key_bits_recovered": 0,
            "global_key_entropy_reduction_claimed_bits": 0,
        },
        "decision": (
            "retain sparse c31 identity scheduling as a candidate-filter mechanism only "
            "if the frozen <=268-switch material gate passes; the stricter <=252 stretch "
            "gate decides whether the current order itself is already efficient enough"
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
            "memory_measurement": "process peak RSS from getrusage",
            "process_max_rss_bytes": max_rss,
            "minor_page_faults_delta": usage_after.ru_minflt - usage_before.ru_minflt,
            "major_page_faults_delta": usage_after.ru_majflt - usage_before.ru_majflt,
            **asdict(meter),
            "cpu_processes": 1,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }
    scientific_bytes = json.dumps(
        _scientific_payload(result),
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
    if resolved.parent != APPLE_VIEW_5_DIR:
        raise ValueError("output must remain directly inside research/apple_view_5")
    if not resolved.name.startswith("apple_view_5_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_5_*.json")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded sparse c31 identity scheduling on Full256 probes."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--probes", type=int, default=DEFAULT_PROBES)
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
    result = run_experiment(ExperimentConfig(args.seed, args.probes))
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
