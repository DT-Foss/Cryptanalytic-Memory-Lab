"""Attacker-computable forward values for exact Full-256 CNF variables.

The evaluator follows the immutable semantic operation map rather than solving
the target CNF.  It can therefore expose selected internal wire phases for any
candidate key, including candidates whose output does not match the target.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .chacha_trace import UINT32_MASK, add32_with_carry_mask
from .full256_cnf import load_full256_template_map


KEY_LAST_VARIABLE = 256
COUNTER_FIRST_VARIABLE = 257
COUNTER_LAST_VARIABLE = 288
NONCE_FIRST_VARIABLE = 289
NONCE_LAST_VARIABLE = 384
OUTPUT_FIRST_VARIABLE = 385
OUTPUT_LAST_VARIABLE = 896
INTERNAL_FIRST_VARIABLE = 897


class Full256ForwardAssignmentError(ValueError):
    """A semantic map, requested variable, or candidate input differs."""


@dataclass(frozen=True)
class _WireRead:
    variable: int
    role: str
    bit: int


@dataclass(frozen=True)
class _ForwardOperation:
    phase: str
    kind: str
    destination_lane: int
    source_lane: int
    rotation: int | None
    reads: tuple[_WireRead, ...]


@dataclass(frozen=True)
class Full256ForwardReadPlan:
    """A compiled fixed-variable view over one exact ChaCha forward execution."""

    requested_variables: tuple[int, ...]
    variable_count: int
    semantic_sha256: str
    operations: tuple[_ForwardOperation, ...]

    def evaluate(self, *, key: bytes, counter: int, nonce: bytes) -> dict[int, int]:
        if not isinstance(key, bytes) or len(key) != 32:
            raise Full256ForwardAssignmentError("candidate key must contain 32 bytes")
        if (
            isinstance(counter, bool)
            or not isinstance(counter, int)
            or not 0 <= counter <= UINT32_MASK
        ):
            raise Full256ForwardAssignmentError("counter must be uint32")
        if not isinstance(nonce, bytes) or len(nonce) != 12:
            raise Full256ForwardAssignmentError("nonce must contain 12 bytes")

        initial = (
            0x61707865,
            0x3320646E,
            0x79622D32,
            0x6B206574,
            *struct.unpack("<8I", key),
            counter,
            *struct.unpack("<3I", nonce),
        )
        state = list(initial)
        values: dict[int, int] = {}

        def set_word_variables(first: int, words: Sequence[int]) -> None:
            last = first + 32 * len(words)
            for variable in self.requested_variables:
                if first <= variable < last:
                    offset = variable - first
                    word, bit = divmod(offset, 32)
                    values[variable] = 1 if (words[word] >> bit) & 1 else -1

        set_word_variables(1, struct.unpack("<8I", key))
        set_word_variables(COUNTER_FIRST_VARIABLE, (counter,))
        set_word_variables(NONCE_FIRST_VARIABLE, struct.unpack("<3I", nonce))

        output_words: list[int] = []
        for operation in self.operations:
            left = state[operation.destination_lane]
            if operation.phase == "round":
                right = state[operation.source_lane]
            elif operation.phase == "feed_forward":
                right = initial[operation.source_lane]
            else:
                raise Full256ForwardAssignmentError("operation phase differs")

            if operation.kind == "add32":
                raw, carry = add32_with_carry_mask(left, right)
                updated = raw
            elif operation.kind == "xor32":
                if operation.rotation is None:
                    raise Full256ForwardAssignmentError("XOR rotation differs")
                raw = left ^ right
                carry = 0
                updated = ((raw << operation.rotation) & UINT32_MASK) | (
                    raw >> (32 - operation.rotation)
                )
            else:
                raise Full256ForwardAssignmentError("operation kind differs")

            for read in operation.reads:
                word = carry if read.role == "carry" else raw
                values[read.variable] = 1 if (word >> read.bit) & 1 else -1
            if operation.phase == "round":
                state[operation.destination_lane] = updated
            else:
                output_words.append(updated)

        if len(output_words) != 16:
            raise Full256ForwardAssignmentError("feed-forward output count differs")
        set_word_variables(OUTPUT_FIRST_VARIABLE, output_words)
        if set(values) != set(self.requested_variables):
            raise Full256ForwardAssignmentError("forward assignment lacks variables")
        return values


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise Full256ForwardAssignmentError(f"{field} must be an object")
    return value


def compile_full256_forward_read_plan(
    semantic_map: str | Path | Mapping[str, object],
    requested_variables: Sequence[int],
) -> Full256ForwardReadPlan:
    """Compile exact semantic operations for a fixed set of CNF variables."""

    if isinstance(semantic_map, (str, Path)):
        document = load_full256_template_map(semantic_map)
        semantic_bytes = Path(semantic_map).resolve(strict=True).read_bytes()
    else:
        document = dict(semantic_map)
        semantic_bytes = json.dumps(
            document, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    variable_count = document.get("variable_count")
    raw_operations = document.get("operations")
    if (
        isinstance(variable_count, bool)
        or not isinstance(variable_count, int)
        or not isinstance(raw_operations, list)
        or len(raw_operations) != 656
    ):
        raise Full256ForwardAssignmentError("semantic map shape differs")
    requested = tuple(sorted(set(requested_variables)))
    if not requested or any(
        isinstance(variable, bool)
        or not isinstance(variable, int)
        or not 1 <= variable <= variable_count
        for variable in requested
    ):
        raise Full256ForwardAssignmentError("requested variable set differs")
    internal_requested = {
        variable for variable in requested if variable >= INTERNAL_FIRST_VARIABLE
    }
    located: set[int] = set()
    operations: list[_ForwardOperation] = []
    for expected_id, raw_operation in enumerate(raw_operations):
        operation = _mapping(raw_operation, "operation")
        if operation.get("operation_id") != expected_id:
            raise Full256ForwardAssignmentError("operation order differs")
        phase = operation.get("phase")
        kind = operation.get("kind")
        destination = operation.get("destination_lane")
        source = operation.get("source_lane")
        rotation = operation.get("rotation")
        bit_ranges = operation.get("bit_ranges")
        if (
            phase not in ("round", "feed_forward")
            or kind not in ("add32", "xor32")
            or isinstance(destination, bool)
            or not isinstance(destination, int)
            or isinstance(source, bool)
            or not isinstance(source, int)
            or not 0 <= destination < 16
            or not 0 <= source < 16
            or not isinstance(bit_ranges, list)
            or len(bit_ranges) != 32
            or (kind == "add32" and rotation is not None)
            or (
                kind == "xor32"
                and (
                    isinstance(rotation, bool)
                    or not isinstance(rotation, int)
                    or not 0 < rotation < 32
                )
            )
        ):
            raise Full256ForwardAssignmentError("operation metadata differs")
        reads: list[_WireRead] = []
        for expected_bit, raw_range in enumerate(bit_ranges):
            bit_range = _mapping(raw_range, "bit range")
            if bit_range.get("bit") != expected_bit:
                raise Full256ForwardAssignmentError("bit-range order differs")
            fields = (
                (("sum_variable", "sum"), ("carry_variable", "carry"))
                if kind == "add32"
                else (("output_variable", "xor"),)
            )
            for name, role in fields:
                variable = bit_range.get(name)
                if variable in internal_requested:
                    if not isinstance(variable, int) or variable in located:
                        raise Full256ForwardAssignmentError(
                            "internal variable mapping differs"
                        )
                    reads.append(_WireRead(variable, role, expected_bit))
                    located.add(variable)
        operations.append(
            _ForwardOperation(
                phase=str(phase),
                kind=str(kind),
                destination_lane=destination,
                source_lane=source,
                rotation=rotation if isinstance(rotation, int) else None,
                reads=tuple(reads),
            )
        )
    if located != internal_requested:
        raise Full256ForwardAssignmentError("semantic map lacks requested wires")
    return Full256ForwardReadPlan(
        requested_variables=requested,
        variable_count=variable_count,
        semantic_sha256=hashlib.sha256(semantic_bytes).hexdigest(),
        operations=tuple(operations),
    )


__all__ = [
    "Full256ForwardAssignmentError",
    "Full256ForwardReadPlan",
    "compile_full256_forward_read_plan",
]
