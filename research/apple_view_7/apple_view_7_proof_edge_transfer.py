#!/usr/bin/env python3
"""Transfer exact proof-DAG predecessor paths across Full20/Full256 targets.

A fixed-size addressed state consumes causal carry-switch predecessor events
from a deterministic BUILD stream.  Its reader is frozen before disjoint
held-out public targets are generated and attacked.  The circuit, propagator,
and APPLE6 comparator order are self-contained; no mutable sibling experiment
is imported at runtime.
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
DEFAULT_SEED = "apple-view-6-proof-stream-transfer-v1-20260719"
DEFAULT_BUILD_TARGETS = 3
DEFAULT_EVAL_TARGETS = 2
DEFAULT_PROBES_PER_TARGET = 2
CPU_BUDGET_SECONDS = 120.0
MEMORY_BUDGET_BYTES = 256 * 1024 * 1024
STATE_COUNTER_MAX = (1 << 8) - 1
STATE_BATCH_CLOCK_MAX = (1 << 16) - 1
STATE_HEADER_BYTES = 2
STATE_EDGE_BYTES = ADDITIONS_PER_BLOCK * ADDITIONS_PER_BLOCK
STATE_ROOT_BYTES = ADDITIONS_PER_BLOCK
STATE_TERMINAL_BYTES = ADDITIONS_PER_BLOCK
STATE_EDGE_OFFSET = STATE_HEADER_BYTES
STATE_ROOT_OFFSET = STATE_EDGE_OFFSET + STATE_EDGE_BYTES
STATE_TERMINAL_OFFSET = STATE_ROOT_OFFSET + STATE_ROOT_BYTES
STATE_BYTES = STATE_TERMINAL_OFFSET + STATE_TERMINAL_BYTES
APPLE_VIEW_7_DIR = Path(__file__).resolve().parent
UNKNOWN = 2

APPLE6_UNARY_BASELINE_TOTAL = 1_268
APPLE6_BEST_FIXED_STRUCTURAL_TOTAL = 1_031
APPLE6_FROZEN_UNARY_ORDER_SHA256 = (
    "47bcaca7e350042cfa3283fbb89978b5fb7f2a50bc8b53e765750878da73f92b"
)
APPLE6_FROZEN_UNARY_ORDER = (
    193, 195, 203, 205, 220, 222, 207, 208, 209, 217, 80, 82, 83, 84, 86,
    87, 89, 90, 91, 93, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
    106, 107, 108, 109, 110, 111, 112, 113, 114, 116, 117, 121, 124, 210,
    211, 212, 213, 214, 215, 218, 219, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 244,
    245, 246, 248, 249, 250, 251, 252, 253, 254, 255, 131, 132, 139, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 153, 154, 155, 156, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
    174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187,
    188, 189, 190, 191, 192, 194, 196, 197, 198, 200, 201, 204, 206, 78,
    85, 92, 94, 243, 256, 118, 128, 129, 130, 134, 135, 141, 142, 157,
    199, 221, 247, 257, 115, 119, 120, 122, 123, 125, 126, 127, 133, 136,
    137, 138, 140, 152, 202, 216, 260, 261, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 46, 47, 48, 49, 52, 53, 60, 259, 275, 290, 291,
    293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305,
    306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318,
    319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331,
    332, 333, 334, 335, 50, 51, 258, 264, 279, 281, 283, 285, 287, 288,
    289, 292, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68,
    69, 70, 71, 72, 73, 74, 75, 76, 77, 79, 81, 88, 262, 263, 265,
    266, 267, 268, 269, 270, 271, 272, 273, 274, 276, 277, 278, 280,
    282, 284, 286,
)

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
    build_targets: int = DEFAULT_BUILD_TARGETS
    eval_targets: int = DEFAULT_EVAL_TARGETS
    probes_per_target: int = DEFAULT_PROBES_PER_TARGET

    def validate(self) -> None:
        if not self.seed:
            raise ValueError("seed must not be empty")
        if not 1 <= self.build_targets <= 8:
            raise ValueError("build_targets must be in [1,8]")
        if not 1 <= self.eval_targets <= 4:
            raise ValueError("eval_targets must be in [1,4]")
        if not 1 <= self.probes_per_target <= 4:
            raise ValueError("probes_per_target must be in [1,4]")


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
class CaseFixture:
    split: str
    target_id: int
    target: PublicTarget
    truth_key: bytes
    probes: tuple[bytes, ...]


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


@dataclass(frozen=True)
class InferenceEvent:
    """One monotone propagation inference with causal predecessor events."""

    constraint_id: int
    predecessor_event_ids: tuple[int, ...]


class ProofEdgeMemory:
    """A fixed 113,570-byte saturating predecessor-edge state.

    Every directed address is ``predecessor * 336 + successor``.  Two bounded
    endpoint channels remember proof roots and conflict-facing terminals.  The
    reader is fixed: terminal-anchored predecessor-first DFS over the strongest
    observed predecessor per identity, followed by the same traversal from the
    remaining high-support identities.  It has no threshold, trained parameter,
    or EVAL-visible choice.
    """

    def __init__(self) -> None:
        self.state = bytearray(STATE_BYTES)

    @staticmethod
    def _validate_switch_id(switch_id: int) -> None:
        if not 0 <= switch_id < ADDITIONS_PER_BLOCK:
            raise ValueError("switch_id out of range")

    @classmethod
    def _edge_offset(cls, predecessor: int, successor: int) -> int:
        cls._validate_switch_id(predecessor)
        cls._validate_switch_id(successor)
        if predecessor == successor:
            raise ValueError("proof predecessor edge must not be a self-edge")
        return STATE_EDGE_OFFSET + predecessor * ADDITIONS_PER_BLOCK + successor

    @classmethod
    def _root_offset(cls, switch_id: int) -> int:
        cls._validate_switch_id(switch_id)
        return STATE_ROOT_OFFSET + switch_id

    @classmethod
    def _terminal_offset(cls, switch_id: int) -> int:
        cls._validate_switch_id(switch_id)
        return STATE_TERMINAL_OFFSET + switch_id

    @property
    def clock(self) -> int:
        return cast(int, struct.unpack_from("<H", self.state, 0)[0])

    def edge_count(self, predecessor: int, successor: int) -> int:
        return self.state[self._edge_offset(predecessor, successor)]

    def root_count(self, switch_id: int) -> int:
        return self.state[self._root_offset(switch_id)]

    def terminal_count(self, switch_id: int) -> int:
        return self.state[self._terminal_offset(switch_id)]

    def _saturating_increment(self, offset: int) -> bool:
        before = self.state[offset]
        self.state[offset] = min(before + 1, STATE_COUNTER_MAX)
        return before == STATE_COUNTER_MAX

    def update_proof_batch(
        self,
        predecessor_edges: Sequence[Sequence[int]],
        root_switch_events: Sequence[int],
        terminal_switch_events: Sequence[int],
    ) -> dict[str, object]:
        """Consume one exact replayed proof-DAG event batch in a single pass."""

        edges: list[tuple[int, int]] = []
        for raw_edge in predecessor_edges:
            if len(raw_edge) != 2:
                raise ValueError("predecessor edge must contain exactly two identities")
            predecessor, successor = int(raw_edge[0]), int(raw_edge[1])
            self._edge_offset(predecessor, successor)
            edges.append((predecessor, successor))
        roots = tuple(int(value) for value in root_switch_events)
        terminals = tuple(int(value) for value in terminal_switch_events)
        for switch_id in roots:
            self._root_offset(switch_id)
        for switch_id in terminals:
            self._terminal_offset(switch_id)
        if not edges and not roots and not terminals:
            raise ValueError("proof-DAG batch must contain at least one event")

        timestamp = min(self.clock + 1, STATE_BATCH_CLOCK_MAX)
        struct.pack_into("<H", self.state, 0, timestamp)
        already_saturated = 0
        for predecessor, successor in edges:
            already_saturated += self._saturating_increment(
                self._edge_offset(predecessor, successor)
            )
        for switch_id in roots:
            already_saturated += self._saturating_increment(
                self._root_offset(switch_id)
            )
        for switch_id in terminals:
            already_saturated += self._saturating_increment(
                self._terminal_offset(switch_id)
            )
        return {
            "batch_timestamp": timestamp,
            "predecessor_edge_events": len(edges),
            "root_events": len(roots),
            "terminal_events": len(terminals),
            "predecessor_edges_sha256": _edge_events_sha256(edges),
            "root_events_sha256": _certificate_sha256(roots),
            "terminal_events_sha256": _certificate_sha256(terminals),
            "already_saturated_cells": already_saturated,
        }

    def _incident_support(self, switch_id: int) -> int:
        incoming = sum(
            self.edge_count(predecessor, switch_id)
            for predecessor in range(ADDITIONS_PER_BLOCK)
            if predecessor != switch_id
        )
        outgoing = sum(
            self.edge_count(switch_id, successor)
            for successor in range(ADDITIONS_PER_BLOCK)
            if successor != switch_id
        )
        return incoming + outgoing

    def frozen_order(self) -> tuple[int, ...]:
        """Read one deterministic predecessor-first sequence from the state."""

        support = [
            self._incident_support(switch_id)
            for switch_id in range(ADDITIONS_PER_BLOCK)
        ]

        def strongest_predecessor(switch_id: int) -> int | None:
            observed = [
                predecessor
                for predecessor in range(ADDITIONS_PER_BLOCK)
                if predecessor != switch_id
                and self.edge_count(predecessor, switch_id) > 0
            ]
            if not observed:
                return None
            return min(
                observed,
                key=lambda predecessor: (
                    -self.edge_count(predecessor, switch_id),
                    -support[predecessor],
                    predecessor,
                ),
            )

        terminal_anchors = sorted(
            range(ADDITIONS_PER_BLOCK),
            key=lambda switch_id: (
                -self.terminal_count(switch_id),
                -support[switch_id],
                -self.root_count(switch_id),
                switch_id,
            ),
        )
        emitted: set[int] = set()
        visiting: set[int] = set()
        order: list[int] = []

        def emit_predecessor_first(switch_id: int) -> None:
            if switch_id in emitted or switch_id in visiting:
                return
            visiting.add(switch_id)
            predecessor = strongest_predecessor(switch_id)
            if predecessor is not None:
                emit_predecessor_first(predecessor)
            visiting.remove(switch_id)
            emitted.add(switch_id)
            order.append(switch_id)

        for switch_id in terminal_anchors:
            if self.terminal_count(switch_id) > 0:
                emit_predecessor_first(switch_id)
        for switch_id in sorted(
            range(ADDITIONS_PER_BLOCK),
            key=lambda identity: (
                -support[identity],
                -self.root_count(identity),
                identity,
            ),
        ):
            emit_predecessor_first(switch_id)
        if tuple(sorted(order)) != tuple(range(ADDITIONS_PER_BLOCK)):
            raise AssertionError("proof-edge reader did not emit a permutation")
        return tuple(order)

    def positive_edges(self) -> list[dict[str, int]]:
        return [
            {
                "predecessor": predecessor,
                "successor": successor,
                "count": self.edge_count(predecessor, successor),
            }
            for predecessor in range(ADDITIONS_PER_BLOCK)
            for successor in range(ADDITIONS_PER_BLOCK)
            if predecessor != successor
            and self.edge_count(predecessor, successor) > 0
        ]

    def endpoint_table(self) -> list[dict[str, int]]:
        return [
            {
                "switch_id": switch_id,
                "root_count": self.root_count(switch_id),
                "terminal_count": self.terminal_count(switch_id),
                "incident_edge_support": self._incident_support(switch_id),
            }
            for switch_id in range(ADDITIONS_PER_BLOCK)
        ]

    def sha256(self) -> str:
        return hashlib.sha256(self.state).hexdigest()


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
    proof_predecessor_edge_event_count: int | None
    proof_predecessor_edge_events: list[list[int]]
    proof_predecessor_edges_sha256: str | None
    proof_root_switch_events: list[int]
    proof_terminal_switch_events: list[int]
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


def generate_case(config: ExperimentConfig, split: str, target_id: int) -> CaseFixture:
    """Generate one deterministic case; BUILD and EVAL labels are disjoint."""

    if split not in {"build", "eval"}:
        raise ValueError("split must be 'build' or 'eval'")
    limit = config.build_targets if split == "build" else config.eval_targets
    if not 0 <= target_id < limit:
        raise ValueError("target_id outside configured split")
    key = _derive(config.seed, f"{split}-target-key", target_id, 32)
    nonce = _derive(config.seed, f"{split}-public-nonce", target_id, 12)
    counter = int.from_bytes(
        _derive(config.seed, f"{split}-public-counter", target_id, 4), "little"
    )
    target = PublicTarget(counter, nonce, chacha20_block(key, counter, nonce))
    probes = tuple(
        _derive(
            config.seed,
            f"{split}-output-independent-probe-key",
            target_id * config.probes_per_target + probe_id,
            32,
        )
        for probe_id in range(config.probes_per_target)
    )
    if key in probes:
        raise AssertionError("probe set unexpectedly contains its truth key")
    return CaseFixture(split, target_id, target, key, probes)


def public_target_sha256(target: PublicTarget) -> str:
    target.validate()
    return hashlib.sha256(
        struct.pack("<I", target.counter) + target.nonce + target.block
    ).hexdigest()


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
        self.reason_event_for_variable: list[int | None] = [
            None
        ] * network.variable_count
        self.inference_events: list[InferenceEvent] = []
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
                    predecessor_event_ids = tuple(
                        dict.fromkeys(
                            event_id
                            for antecedent in antecedents
                            if (
                                event_id := self.reason_event_for_variable[
                                    antecedent
                                ]
                            )
                            is not None
                        )
                    )
                    event_id = len(self.inference_events)
                    self.inference_events.append(
                        InferenceEvent(constraint_id, predecessor_event_ids)
                    )
                    self.reason_event_for_variable[variable] = event_id
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

    def _required_proof_event_ids(self) -> tuple[int, ...]:
        if self.conflict_constraint is None:
            return ()
        pending = [
            event_id
            for variable in self.conflict_antecedents
            if (event_id := self.reason_event_for_variable[variable]) is not None
        ]
        required: set[int] = set()
        while pending:
            event_id = pending.pop()
            if event_id in required:
                continue
            required.add(event_id)
            pending.extend(self.inference_events[event_id].predecessor_event_ids)
        return tuple(sorted(required))

    def proof_switch_ids(self) -> tuple[int, ...]:
        """Slice the actual inference-event DAG back to dormant identities."""

        if self.conflict_constraint is None:
            return ()
        switch_by_constraint = {
            switch.constraint_id: switch.switch_id
            for switch in self.network.switches
        }
        required_switches = {
            switch_by_constraint[event.constraint_id]
            for event_id in self._required_proof_event_ids()
            if (
                event := self.inference_events[event_id]
            ).constraint_id in switch_by_constraint
        }
        if self.conflict_constraint in switch_by_constraint:
            required_switches.add(switch_by_constraint[self.conflict_constraint])
        return tuple(
            switch_id
            for switch_id in self.enabled_switch_ids
            if switch_id in required_switches
        )

    def proof_predecessor_events(
        self,
    ) -> tuple[tuple[tuple[int, int], ...], tuple[int, ...], tuple[int, ...]]:
        """Contract the exact inference DAG to switch-to-switch path events.

        Base-constraint inference events are transparent.  Each switch event is
        linked to the latest of its nearest upstream switch events: a canonical
        exact predecessor chosen by inference time, not a learned threshold.
        The latest exact conflict-facing switch event becomes the terminal.
        Repeated identity pairs remain repeated events rather than collapsing to
        unary membership.
        """

        if self.conflict_constraint is None:
            return (), (), ()
        required = set(self._required_proof_event_ids())
        switch_by_constraint = {
            switch.constraint_id: switch.switch_id
            for switch in self.network.switches
        }

        def nearest_switch_events(start_event_ids: Sequence[int]) -> tuple[int, ...]:
            pending = list(start_event_ids)
            nearest: set[int] = set()
            seen: set[int] = set()
            while pending:
                event_id = pending.pop()
                if event_id in seen or event_id not in required:
                    continue
                seen.add(event_id)
                event = self.inference_events[event_id]
                if event.constraint_id in switch_by_constraint:
                    nearest.add(event_id)
                else:
                    pending.extend(event.predecessor_event_ids)
            return tuple(sorted(nearest))

        edges: list[tuple[int, int]] = []
        roots: list[int] = []
        for event_id in sorted(required):
            event = self.inference_events[event_id]
            successor = switch_by_constraint.get(event.constraint_id)
            if successor is None:
                continue
            predecessor_events = nearest_switch_events(event.predecessor_event_ids)
            distinct_predecessors = tuple(
                predecessor_event_id
                for predecessor_event_id in predecessor_events
                if switch_by_constraint[
                    self.inference_events[predecessor_event_id].constraint_id
                ]
                != successor
            )
            if distinct_predecessors:
                predecessor_event_id = max(distinct_predecessors)
                predecessor = switch_by_constraint[
                    self.inference_events[predecessor_event_id].constraint_id
                ]
                if predecessor_event_id >= event_id:
                    raise AssertionError("proof predecessor is not causal")
                edges.append((predecessor, successor))
            else:
                roots.append(successor)

        conflict_predecessors = tuple(
            dict.fromkeys(
                event_id
                for variable in self.conflict_antecedents
                if (event_id := self.reason_event_for_variable[variable]) is not None
            )
        )
        if self.conflict_constraint in switch_by_constraint:
            terminals = (switch_by_constraint[self.conflict_constraint],)
        else:
            terminal_events = nearest_switch_events(conflict_predecessors)
            terminals = (
                (
                    switch_by_constraint[
                        self.inference_events[max(terminal_events)].constraint_id
                    ],
                )
                if terminal_events
                else ()
            )
        proof_id_set = set(self.proof_switch_ids())
        if any(
            predecessor not in proof_id_set or successor not in proof_id_set
            for predecessor, successor in edges
        ):
            raise AssertionError("proof edge escaped exact dormant-switch slice")
        if any(value not in proof_id_set for value in (*roots, *terminals)):
            raise AssertionError("proof endpoint escaped exact dormant-switch slice")
        return tuple(edges), tuple(roots), tuple(terminals)


def _certificate_sha256(switch_ids: Sequence[int]) -> str:
    payload = b"".join(value.to_bytes(2, "little") for value in switch_ids)
    return hashlib.sha256(payload).hexdigest()


def _edge_events_sha256(edges: Sequence[Sequence[int]]) -> str:
    payload = b"".join(
        int(value).to_bytes(2, "little")
        for edge in edges
        for value in edge
    )
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
    proof_edges, proof_roots, proof_terminals = state.proof_predecessor_events()
    proof_edge_lists = [[predecessor, successor] for predecessor, successor in proof_edges]
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
        "proof_predecessor_edge_event_count": (
            len(proof_edges) if conflict_constraint is not None else None
        ),
        "proof_predecessor_edge_events": proof_edge_lists,
        "proof_predecessor_edges_sha256": (
            _edge_events_sha256(proof_edges)
            if conflict_constraint is not None
            else None
        ),
        "proof_root_switch_events": list(proof_roots),
        "proof_terminal_switch_events": list(proof_terminals),
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
        seed.encode("utf-8") + b"\x00apple-view-6-public-order\x00" + public_bytes
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


def _case_record(case: CaseFixture) -> dict[str, object]:
    return {
        "split": case.split,
        "target_id": case.target_id,
        "counter": case.target.counter,
        "nonce_hex": case.target.nonce.hex(),
        "block_hex": case.target.block.hex(),
        "truth_key_hex_unsealed_after_scoring": case.truth_key.hex(),
        "probe_key_sha256": [
            hashlib.sha256(probe).hexdigest() for probe in case.probes
        ],
        "public_target_sha256": public_target_sha256(case.target),
    }


def _build_collector_orders(
    config: ExperimentConfig, case: CaseFixture
) -> dict[str, tuple[int, ...]]:
    return {
        "early_to_final": tuple(range(ADDITIONS_PER_BLOCK)),
        "final_to_early": tuple(reversed(range(ADDITIONS_PER_BLOCK))),
        "deterministic_public_random": _public_random_order(
            f"{config.seed}-build-{case.target_id}", case.target
        ),
    }


def build_proof_stream(
    config: ExperimentConfig,
    memory: ProofEdgeMemory,
    meter: WorkMeter,
) -> tuple[list[dict[str, object]], set[bytes], dict[str, int]]:
    """Consume BUILD proof events only; no held-out fixture exists yet."""

    build_targets: list[dict[str, object]] = []
    used_keys: set[bytes] = set()
    stream_events = {
        "predecessor_edges": 0,
        "roots": 0,
        "terminals": 0,
    }
    for target_id in range(config.build_targets):
        case = generate_case(config, "build", target_id)
        meter.concrete_block_evaluations += 1
        if case.truth_key in used_keys or any(
            probe in used_keys for probe in case.probes
        ):
            raise AssertionError("BUILD keys are not disjoint")
        used_keys.add(case.truth_key)
        used_keys.update(case.probes)
        network = compile_network(case.target, meter)
        collectors = _build_collector_orders(config, case)
        batches: list[dict[str, object]] = []
        for probe_id, probe in enumerate(case.probes):
            for collector_name, order in collectors.items():
                row = run_order(network, case.target, probe, order, meter)
                if row["status"] != "CONFLICT":
                    raise AssertionError("BUILD collector did not reject wrong probe")
                if row["proof_slice_replay_status"] != "CONFLICT":
                    raise AssertionError("BUILD proof did not replay exactly")
                proof_edges = row["proof_predecessor_edge_events"]
                proof_roots = row["proof_root_switch_events"]
                proof_terminals = row["proof_terminal_switch_events"]
                event = memory.update_proof_batch(
                    proof_edges, proof_roots, proof_terminals
                )
                stream_events["predecessor_edges"] += len(proof_edges)
                stream_events["roots"] += len(proof_roots)
                stream_events["terminals"] += len(proof_terminals)
                batches.append(
                    {
                        "probe_id": probe_id,
                        "collector": collector_name,
                        "collector_order_sha256": _order_sha256(order),
                        "first_pass": row,
                        "stream_event": event,
                    }
                )
        truth_row = run_order(
            network,
            case.target,
            case.truth_key,
            tuple(range(ADDITIONS_PER_BLOCK)),
            meter,
        )
        if truth_row["status"] != "CONSISTENT_COMPLETE":
            raise AssertionError("BUILD truth control failed")
        build_targets.append(
            {
                "case": _case_record(case),
                "collector_batches": batches,
                "truth_control": truth_row,
            }
        )
    return build_targets, used_keys, stream_events


def _fixed_eval_orders(
    config: ExperimentConfig,
    case: CaseFixture,
    learned_order: tuple[int, ...],
    public_gain_order: tuple[int, ...],
) -> dict[str, tuple[int, ...]]:
    orders = {
        "learned_proof_edge_predecessor": learned_order,
        "apple6_frozen_unary_frequency_recency": APPLE6_FROZEN_UNARY_ORDER,
        "early_to_final": tuple(range(ADDITIONS_PER_BLOCK)),
        "final_to_early": tuple(reversed(range(ADDITIONS_PER_BLOCK))),
        "deterministic_public_random": _public_random_order(
            f"{config.seed}-eval-{case.target_id}", case.target
        ),
        "immediate_public_gain": public_gain_order,
    }
    for order in orders.values():
        if tuple(sorted(order)) != tuple(range(ADDITIONS_PER_BLOCK)):
            raise AssertionError("EVAL order is not a complete switch permutation")
    return orders


def evaluate_heldout_first_passes(
    config: ExperimentConfig,
    cases: Sequence[CaseFixture],
    learned_order: tuple[int, ...],
    memory: ProofEdgeMemory,
    frozen_state_sha256: str,
    meter: WorkMeter,
) -> tuple[
    list[dict[str, object]],
    dict[int, dict[str, tuple[int, ...]]],
]:
    """Score all wrong held-out probes before any held-out truth is touched."""

    evaluation_targets: list[dict[str, object]] = []
    cached_orders: dict[int, dict[str, tuple[int, ...]]] = {}
    for case in cases:
        network = compile_network(case.target, meter)
        learned_rows: list[dict[str, object]] = []
        scored_sequence: list[str] = []

        # The frozen O1-style state always receives the first scored pass.
        for probe_id, probe in enumerate(case.probes):
            row = run_order(network, case.target, probe, learned_order, meter)
            if row["status"] != "CONFLICT":
                raise AssertionError("learned held-out filter failed to reject a probe")
            learned_rows.append({"probe_id": probe_id, **row})
            scored_sequence.append(f"learned_proof_edge_predecessor:probe-{probe_id}")
            if memory.sha256() != frozen_state_sha256:
                raise AssertionError("held-out evaluation mutated frozen memory")

        public_gain_order, public_gain_ledger = public_gain_greedy_order(
            network, case.target, meter
        )
        fixed_orders = _fixed_eval_orders(
            config, case, learned_order, public_gain_order
        )
        cached_orders[case.target_id] = fixed_orders
        runs: dict[str, list[dict[str, object]]] = {
            "learned_proof_edge_predecessor": learned_rows
        }
        for strategy in (
            "apple6_frozen_unary_frequency_recency",
            "early_to_final",
            "final_to_early",
            "deterministic_public_random",
            "immediate_public_gain",
        ):
            rows: list[dict[str, object]] = []
            for probe_id, probe in enumerate(case.probes):
                row = run_order(
                    network, case.target, probe, fixed_orders[strategy], meter
                )
                rows.append({"probe_id": probe_id, **row})
                scored_sequence.append(f"{strategy}:probe-{probe_id}")
            runs[strategy] = rows

        candidate_rows: list[dict[str, object]] = []
        for probe_id, probe in enumerate(case.probes):
            row, selection_ledger = candidate_gain_greedy_run(
                network, case.target, probe, meter
            )
            candidate_rows.append(
                {
                    "probe_id": probe_id,
                    **row,
                    "selection_ledger": selection_ledger,
                }
            )
            scored_sequence.append(f"immediate_candidate_gain:probe-{probe_id}")
        runs["immediate_candidate_gain"] = candidate_rows
        if memory.sha256() != frozen_state_sha256:
            raise AssertionError("comparators mutated frozen memory")

        evaluation_targets.append(
            {
                "case": _case_record(case),
                "learned_first_for_every_probe": True,
                "scored_sequence": scored_sequence,
                "public_gain_order_ledger": public_gain_ledger,
                "runs": runs,
            }
        )
    return evaluation_targets, cached_orders


def run_heldout_truth_controls(
    cases: Sequence[CaseFixture],
    cached_orders: dict[int, dict[str, tuple[int, ...]]],
    memory: ProofEdgeMemory,
    frozen_state_sha256: str,
    meter: WorkMeter,
) -> list[dict[str, object]]:
    """Reveal truth only after every held-out wrong-candidate pass is complete."""

    truth_targets: list[dict[str, object]] = []
    for case in cases:
        network = compile_network(case.target, meter)
        rows: dict[str, RunRow] = {}
        for strategy, order in cached_orders[case.target_id].items():
            row = run_order(network, case.target, case.truth_key, order, meter)
            if row["status"] != "CONSISTENT_COMPLETE":
                raise AssertionError(f"truth control failed for {strategy}")
            rows[strategy] = row
        adaptive_row, _ledger = candidate_gain_greedy_run(
            network, case.target, case.truth_key, meter
        )
        if adaptive_row["status"] != "CONSISTENT_COMPLETE":
            raise AssertionError("adaptive truth control failed")
        rows["immediate_candidate_gain"] = adaptive_row
        if memory.sha256() != frozen_state_sha256:
            raise AssertionError("truth controls mutated frozen memory")
        truth_targets.append({"target_id": case.target_id, "strategies": rows})
    return truth_targets


def _strategy_rows(
    evaluation_targets: Sequence[dict[str, object]], strategy: str
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for target in evaluation_targets:
        runs = cast(dict[str, list[dict[str, object]]], target["runs"])
        rows.extend(runs[strategy])
    return rows


def aggregate_evaluation(
    evaluation_targets: Sequence[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    strategies = (
        "learned_proof_edge_predecessor",
        "apple6_frozen_unary_frequency_recency",
        "early_to_final",
        "final_to_early",
        "deterministic_public_random",
        "immediate_public_gain",
        "immediate_candidate_gain",
    )
    aggregates: dict[str, dict[str, object]] = {}
    for strategy in strategies:
        rows = _strategy_rows(evaluation_targets, strategy)
        first_counts = [cast(int, row["first_conflict_switch_count"]) for row in rows]
        proof_counts = [cast(int, row["proof_slice_switch_count"]) for row in rows]
        visits = [cast(int, row["constraint_visits"]) for row in rows]
        replay_visits = [
            cast(int, row["proof_slice_replay_constraint_visits"]) for row in rows
        ]
        if not all(row["status"] == "CONFLICT" for row in rows):
            raise AssertionError(f"held-out non-conflict in {strategy}")
        if not all(row["proof_slice_replay_status"] == "CONFLICT" for row in rows):
            raise AssertionError(f"held-out proof replay failed in {strategy}")
        aggregates[strategy] = {
            "cases": len(rows),
            "exact_rejections": len(rows),
            "total_first_conflict_switches": sum(first_counts),
            "mean_first_conflict_switches": sum(first_counts) / len(first_counts),
            "minimum_first_conflict_switches": min(first_counts),
            "maximum_first_conflict_switches": max(first_counts),
            "total_exact_certificate_switches": sum(proof_counts),
            "mean_exact_certificate_switches": sum(proof_counts) / len(proof_counts),
            "minimum_exact_certificate_switches": min(proof_counts),
            "maximum_exact_certificate_switches": max(proof_counts),
            "total_first_pass_constraint_visits": sum(visits),
            "mean_first_pass_constraint_visits": sum(visits) / len(visits),
            "total_proof_replay_constraint_visits": sum(replay_visits),
        }

    structural_names = (
        "early_to_final",
        "final_to_early",
        "deterministic_public_random",
    )

    def aggregate_key(name: str) -> tuple[int, int]:
        aggregate = aggregates[name]
        return (
            cast(int, aggregate["total_first_conflict_switches"]),
            cast(int, aggregate["total_first_pass_constraint_visits"]),
        )

    best_structural = min(structural_names, key=aggregate_key)
    learned_key = aggregate_key("learned_proof_edge_predecessor")
    best_key = aggregate_key(best_structural)
    learned_switches = learned_key[0]
    apple6_unary_switches = aggregate_key(
        "apple6_frozen_unary_frequency_recency"
    )[0]
    strict_below_apple6_unary = learned_switches < APPLE6_UNARY_BASELINE_TOTAL
    strict_below_apple6_best_fixed = (
        learned_switches < APPLE6_BEST_FIXED_STRUCTURAL_TOTAL
    )
    apple6_unary_reproduced = (
        apple6_unary_switches == APPLE6_UNARY_BASELINE_TOTAL
    )
    apple6_best_fixed_reproduced = (
        best_structural == "final_to_early"
        and best_key[0] == APPLE6_BEST_FIXED_STRUCTURAL_TOTAL
    )

    smaller_certificate_cases: list[dict[str, int]] = []
    for target in evaluation_targets:
        target_id = cast(dict[str, object], target["case"])["target_id"]
        runs = cast(dict[str, list[dict[str, object]]], target["runs"])
        learned_rows = runs["learned_proof_edge_predecessor"]
        for index, learned in enumerate(learned_rows):
            learned_count = cast(int, learned["proof_slice_switch_count"])
            best_structural_count = min(
                cast(int, runs[name][index]["proof_slice_switch_count"])
                for name in structural_names
            )
            if learned_count < best_structural_count:
                smaller_certificate_cases.append(
                    {
                        "target_id": cast(int, target_id),
                        "probe_id": cast(int, learned["probe_id"]),
                        "learned_certificate_switches": learned_count,
                        "best_structural_certificate_switches": best_structural_count,
                    }
                )
    gate = {
        "best_fixed_structural_comparator": best_structural,
        "learned_aggregate_key_switches_then_visits": list(learned_key),
        "best_structural_aggregate_key_switches_then_visits": list(best_key),
        "apple6_frozen_unary_observed_switches": apple6_unary_switches,
        "apple6_frozen_unary_expected_switches": APPLE6_UNARY_BASELINE_TOTAL,
        "apple6_best_fixed_expected_switches": APPLE6_BEST_FIXED_STRUCTURAL_TOTAL,
        "apple6_unary_baseline_reproduced": apple6_unary_reproduced,
        "apple6_best_fixed_baseline_reproduced": apple6_best_fixed_reproduced,
        "strictly_below_apple6_unary_1268": strict_below_apple6_unary,
        "strictly_below_apple6_best_fixed_1031": strict_below_apple6_best_fixed,
        "strictly_smaller_exact_certificate_cases": smaller_certificate_cases,
        "certificate_gain_can_pass_gate": False,
        "success_gate_passed": (
            apple6_unary_reproduced
            and apple6_best_fixed_reproduced
            and strict_below_apple6_unary
            and strict_below_apple6_best_fixed
        ),
    }
    return aggregates, gate


def _scientific_payload(result: dict[str, object]) -> dict[str, object]:
    return {
        key: result[key]
        for key in (
            "schema",
            "hypothesis",
            "config",
            "attacker_boundary",
            "mechanism",
            "build_phase",
            "frozen_state",
            "evaluation_phase",
            "heldout_truth_controls",
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

    if tuple(sorted(APPLE6_FROZEN_UNARY_ORDER)) != tuple(
        range(ADDITIONS_PER_BLOCK)
    ):
        raise AssertionError("embedded APPLE6 unary order is not a permutation")
    if _order_sha256(APPLE6_FROZEN_UNARY_ORDER) != APPLE6_FROZEN_UNARY_ORDER_SHA256:
        raise AssertionError("embedded APPLE6 unary order hash mismatch")

    memory = ProofEdgeMemory()
    build_started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    build_targets, used_keys, stream_events = build_proof_stream(config, memory, meter)
    build_completed_at = datetime.now().astimezone().isoformat(timespec="seconds")

    frozen_state = bytes(memory.state)
    if len(frozen_state) != STATE_BYTES:
        raise AssertionError("bounded state size changed")
    frozen_state_sha256 = memory.sha256()
    learned_order = memory.frozen_order()
    frozen_order_sha256 = _order_sha256(learned_order)
    freeze_completed_at = datetime.now().astimezone().isoformat(timespec="seconds")

    # Held-out fixtures are deliberately generated only after state/order freeze.
    eval_cases = [
        generate_case(config, "eval", target_id)
        for target_id in range(config.eval_targets)
    ]
    meter.concrete_block_evaluations += len(eval_cases)
    for case in eval_cases:
        if case.truth_key in used_keys or any(
            probe in used_keys for probe in case.probes
        ):
            raise AssertionError("EVAL key material overlaps BUILD")
        used_keys.add(case.truth_key)
        for probe in case.probes:
            if probe in used_keys:
                raise AssertionError("EVAL probe material overlaps another key")
            used_keys.add(probe)
    eval_generated_at = datetime.now().astimezone().isoformat(timespec="seconds")

    evaluation_targets, cached_orders = evaluate_heldout_first_passes(
        config,
        eval_cases,
        learned_order,
        memory,
        frozen_state_sha256,
        meter,
    )
    scored_passes_completed_at = (
        datetime.now().astimezone().isoformat(timespec="seconds")
    )
    if bytes(memory.state) != frozen_state:
        raise AssertionError("held-out scored passes changed frozen state")

    heldout_truth_controls = run_heldout_truth_controls(
        eval_cases,
        cached_orders,
        memory,
        frozen_state_sha256,
        meter,
    )
    if bytes(memory.state) != frozen_state:
        raise AssertionError("held-out truth controls changed frozen state")
    aggregates, transfer_gate = aggregate_evaluation(evaluation_targets)

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
    test_path = APPLE_VIEW_7_DIR / "apple_view_7_test_proof_edge_transfer.py"
    truth_retained = all(
        row["status"] == "CONSISTENT_COMPLETE"
        for target in heldout_truth_controls
        for row in cast(dict[str, RunRow], target["strategies"]).values()
    )
    result: dict[str, object] = {
        "schema": "apple-view-7-full256-proof-edge-transfer-v1",
        "started_at": started_at,
        "completed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "timeline": {
            "build_started_at": build_started_at,
            "build_completed_at": build_completed_at,
            "freeze_completed_at": freeze_completed_at,
            "eval_targets_generated_at": eval_generated_at,
            "all_wrong_candidate_passes_completed_at": scored_passes_completed_at,
            "truth_reveal_after_all_wrong_passes": True,
        },
        "hypothesis": (
            "a fixed-size target-independent stream state trained only on BUILD "
            "proof-DAG predecessor paths transfers a better carry-identity schedule "
            "than both APPLE6 unary membership and fixed structural orders to "
            "disjoint held-out Full20/Full256 candidate filters"
        ),
        "config": {
            **asdict(config),
            "build_collectors": [
                "early_to_final",
                "final_to_early",
                "deterministic_public_random",
            ],
            "state_bytes": STATE_BYTES,
            "cpu_budget_seconds": CPU_BUDGET_SECONDS,
            "memory_budget_bytes": MEMORY_BUDGET_BYTES,
        },
        "attacker_boundary": {
            "primitive": "RFC 8439 ChaCha20 block, 20 rounds",
            "unknown_key_bits_in_base_problem": 256,
            "public_input": "constants + counter + 96-bit nonce + one 512-bit output",
            "complete_wrong_candidate_is_filter_input": True,
            "build_and_eval_key_material_disjoint": True,
            "eval_targets_generated_after_state_freeze": True,
            "heldout_proof_feedback_before_or_during_scored_pass": 0,
            "heldout_state_updates": 0,
            "truth_key_role": "revealed only after all held-out wrong passes",
            "unbounded_cdcl_used": False,
            "branching_or_boolean_search_decisions_used": False,
            "network_used": False,
            "gpu_or_mps_used": False,
        },
        "mechanism": {
            "stream_event": (
                "one exact contracted predecessor-to-successor c31 proof-DAG edge "
                "from an independently replayed BUILD wrong-candidate conflict"
            ),
            "state": (
                "one addressed uint8 saturating counter per directed 336x336 edge, "
                "one uint8 root and terminal channel per identity, and one uint16 "
                "saturating batch clock"
            ),
            "update": (
                "one pass over exact predecessor, root, and terminal events; no "
                "gradient, NN, target slot, threshold, or EVAL update"
            ),
            "reader": (
                "terminal-anchored predecessor-first DFS over the strongest observed "
                "incoming edge per identity, then deterministic high-support coverage "
                "of every remaining identity"
            ),
            "matched_switch_work": (
                "all schedulers start from the identical depth-30 network and enable "
                "one exact c31 identity per step until first conflict"
            ),
            "exact_certificate": (
                "inference-event DAG switch slice independently replayed from a fresh "
                "propagator; base-event paths contracted only after exact slicing"
            ),
        },
        "build_phase": {
            "targets_generated_before_freeze": config.build_targets,
            "proof_batches": memory.clock,
            "stream_length_exact_predecessor_edge_events": stream_events[
                "predecessor_edges"
            ],
            "stream_length_exact_root_events": stream_events["roots"],
            "stream_length_exact_terminal_events": stream_events["terminals"],
            "state_updates": memory.clock,
            "targets": build_targets,
        },
        "frozen_state": {
            "logical_state_bytes": len(frozen_state),
            "size_independent_of_targets_and_stream_length": True,
            "serialization_hex": frozen_state.hex(),
            "sha256": frozen_state_sha256,
            "batch_clock": memory.clock,
            "counter_bits": 8,
            "addressed_directed_edge_cells": STATE_EDGE_BYTES,
            "root_cells": STATE_ROOT_BYTES,
            "terminal_cells": STATE_TERMINAL_BYTES,
            "positive_edges": memory.positive_edges(),
            "endpoint_cells": memory.endpoint_table(),
            "frozen_identity_order": list(learned_order),
            "frozen_identity_order_sha256": frozen_order_sha256,
            "first_32_identities": list(learned_order[:32]),
            "last_32_identities": list(learned_order[-32:]),
            "embedded_apple6_unary_order_sha256": _order_sha256(
                APPLE6_FROZEN_UNARY_ORDER
            ),
        },
        "evaluation_phase": {
            "targets_generated_after_freeze": config.eval_targets,
            "wrong_probes_per_target": config.probes_per_target,
            "learned_scheduler_always_scored_first": True,
            "frozen_state_sha256_before": frozen_state_sha256,
            "frozen_state_sha256_after": memory.sha256(),
            "state_unchanged": bytes(memory.state) == frozen_state,
            "targets": evaluation_targets,
            "strategy_aggregates": aggregates,
        },
        "heldout_truth_controls": heldout_truth_controls,
        "summary": {
            "success_gate": (
                "raw held-out total first-conflict switches must be strictly below "
                "both the exact APPLE6 unary 1268 baseline and the exact APPLE6 best "
                "fixed structural 1031 baseline; certificate gains cannot pass"
            ),
            **transfer_gate,
            "heldout_exact_wrong_rejections": sum(
                cast(int, aggregate["exact_rejections"])
                for aggregate in aggregates.values()
            ),
            "heldout_truth_controls_retained": truth_retained,
            "exact_full_key_recoveries": 0,
            "exact_key_bits_recovered": 0,
            "global_key_entropy_reduction_claimed_bits": 0,
        },
        "decision": (
            "retain proof-edge sequence transfer only if the frozen raw gate passes; "
            "on failure preserve the causal graph breadcrumb without reader sweep or "
            "held-out redesign"
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
        "dynamic_resource_and_timeline_fields_excluded_from_scientific_hash": True,
    }
    return result


def validated_output_path(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    resolved = candidate.resolve()
    if resolved.parent != APPLE_VIEW_7_DIR:
        raise ValueError("output must remain directly inside research/apple_view_7")
    if not resolved.name.startswith("apple_view_7_") or resolved.suffix != ".json":
        raise ValueError("output filename must match apple_view_7_*.json")
    return resolved


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run BUILD-to-held-out proof-DAG predecessor transfer."
    )
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--build-targets", type=int, default=DEFAULT_BUILD_TARGETS)
    parser.add_argument("--eval-targets", type=int, default=DEFAULT_EVAL_TARGETS)
    parser.add_argument(
        "--probes-per-target", type=int, default=DEFAULT_PROBES_PER_TARGET
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
    result = run_experiment(
        ExperimentConfig(
            args.seed,
            args.build_targets,
            args.eval_targets,
            args.probes_per_target,
        )
    )
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
