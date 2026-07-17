"""Exact RFC 8439 ChaCha20 with optional attacker-computable trace data.

The public block function and traced block function share the same implementation.
Trace rows are suitable for known-key teachers and for keys proposed by the
attacker.  A target trace is never part of the public target type defined by the
Living Inverse module.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


UINT32_MASK = (1 << 32) - 1
CHACHA20_ROUNDS = 20
WORDS_PER_STATE = 16
ADDITIONS_PER_ROUND = 16


class ChaChaTraceError(ValueError):
    """Raised when a key, nonce, counter or trace invariant differs."""


def _u32(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChaChaTraceError(f"{field} must be an integer")
    if not 0 <= value <= UINT32_MASK:
        raise ChaChaTraceError(f"{field} must be uint32")
    return value


def _rotl32(value: int, distance: int) -> int:
    return ((value << distance) & UINT32_MASK) | (value >> (32 - distance))


def add32_with_carry_mask(left: int, right: int) -> tuple[int, int]:
    """Return the uint32 sum and a mask of carry-outs from bit positions 0..31."""

    left = _u32(left, "left")
    right = _u32(right, "right")
    result = (left + right) & UINT32_MASK
    carry_mask = ((left & right) | ((left | right) & (~result & UINT32_MASK)))
    return result, carry_mask & UINT32_MASK


def _quarter_round(
    state: list[int],
    a: int,
    b: int,
    c: int,
    d: int,
    carry_masks: list[int],
) -> None:
    state[a], carry = add32_with_carry_mask(state[a], state[b])
    carry_masks.append(carry)
    state[d] = _rotl32(state[d] ^ state[a], 16)

    state[c], carry = add32_with_carry_mask(state[c], state[d])
    carry_masks.append(carry)
    state[b] = _rotl32(state[b] ^ state[c], 12)

    state[a], carry = add32_with_carry_mask(state[a], state[b])
    carry_masks.append(carry)
    state[d] = _rotl32(state[d] ^ state[a], 8)

    state[c], carry = add32_with_carry_mask(state[c], state[d])
    carry_masks.append(carry)
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _initial_state(key: bytes, counter: int, nonce: bytes) -> tuple[int, ...]:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ChaChaTraceError("ChaCha20 key must be exactly 32 bytes")
    counter = _u32(counter, "counter")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ChaChaTraceError("ChaCha20 nonce must be exactly 12 bytes")
    return (
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *struct.unpack("<8I", key),
        counter,
        *struct.unpack("<3I", nonce),
    )


@dataclass(frozen=True)
class ChaChaBlockTrace:
    """One exact known-key execution trace.

    ``round_states`` contains the initial state followed by the state after every
    column or diagonal round, for 21 states total.  ``round_carry_masks`` contains
    sixteen addition carry masks for each of the twenty rounds.  Feed-forward
    carries are separate because they are outside the round permutation.
    """

    initial_state: tuple[int, ...]
    round_states: tuple[tuple[int, ...], ...]
    round_carry_masks: tuple[tuple[int, ...], ...]
    feedforward_carry_masks: tuple[int, ...]
    output_words: tuple[int, ...]

    def validate(self) -> None:
        if len(self.initial_state) != WORDS_PER_STATE:
            raise ChaChaTraceError("initial trace state must contain 16 words")
        if len(self.round_states) != CHACHA20_ROUNDS + 1:
            raise ChaChaTraceError("trace must contain initial plus twenty states")
        if self.round_states[0] != self.initial_state:
            raise ChaChaTraceError("first round state must equal initial state")
        if any(len(state) != WORDS_PER_STATE for state in self.round_states):
            raise ChaChaTraceError("every trace state must contain 16 words")
        if len(self.round_carry_masks) != CHACHA20_ROUNDS or any(
            len(row) != ADDITIONS_PER_ROUND for row in self.round_carry_masks
        ):
            raise ChaChaTraceError("each of twenty rounds must contain 16 carries")
        if len(self.feedforward_carry_masks) != WORDS_PER_STATE:
            raise ChaChaTraceError("feed-forward trace must contain 16 carries")
        if len(self.output_words) != WORDS_PER_STATE:
            raise ChaChaTraceError("trace output must contain 16 words")
        words = (
            self.initial_state
            + tuple(word for row in self.round_states for word in row)
            + tuple(word for row in self.round_carry_masks for word in row)
            + self.feedforward_carry_masks
            + self.output_words
        )
        if any(
            isinstance(word, bool)
            or not isinstance(word, int)
            or not 0 <= word <= UINT32_MASK
            for word in words
        ):
            raise ChaChaTraceError("trace values must all be uint32")

    @property
    def output(self) -> bytes:
        return struct.pack("<16I", *self.output_words)

    @property
    def logical_bytes(self) -> int:
        # Initial state is also round_states[0], so count it once.
        words = (
            len(self.round_states) * WORDS_PER_STATE
            + CHACHA20_ROUNDS * ADDITIONS_PER_ROUND
            + WORDS_PER_STATE
            + WORDS_PER_STATE
        )
        return words * 4

    def digest(self) -> str:
        digest = hashlib.sha256()
        for state in self.round_states:
            digest.update(struct.pack("<16I", *state))
        for carries in self.round_carry_masks:
            digest.update(struct.pack("<16I", *carries))
        digest.update(struct.pack("<16I", *self.feedforward_carry_masks))
        digest.update(self.output)
        return digest.hexdigest()

    def compact_summary(self) -> dict[str, object]:
        return {
            "schema": "o1-256-known-key-trace-summary-v1",
            "rounds": CHACHA20_ROUNDS,
            "round_state_popcounts": [
                [word.bit_count() for word in state]
                for state in self.round_states[1:]
            ],
            "round_carry_popcounts": [
                [mask.bit_count() for mask in row]
                for row in self.round_carry_masks
            ],
            "feedforward_carry_popcounts": [
                mask.bit_count() for mask in self.feedforward_carry_masks
            ],
            "trace_sha256": self.digest(),
            "logical_bytes": self.logical_bytes,
        }


def chacha20_block_trace(key: bytes, counter: int, nonce: bytes) -> ChaChaBlockTrace:
    """Execute one standard ChaCha20 block and retain exact round/carry traces."""

    initial = _initial_state(key, counter, nonce)
    state = list(initial)
    states: list[tuple[int, ...]] = [initial]
    round_carries: list[tuple[int, ...]] = []

    for _ in range(10):
        carries: list[int] = []
        _quarter_round(state, 0, 4, 8, 12, carries)
        _quarter_round(state, 1, 5, 9, 13, carries)
        _quarter_round(state, 2, 6, 10, 14, carries)
        _quarter_round(state, 3, 7, 11, 15, carries)
        if len(carries) != ADDITIONS_PER_ROUND:
            raise AssertionError("column-round carry count differs")
        round_carries.append(tuple(carries))
        states.append(tuple(state))

        carries = []
        _quarter_round(state, 0, 5, 10, 15, carries)
        _quarter_round(state, 1, 6, 11, 12, carries)
        _quarter_round(state, 2, 7, 8, 13, carries)
        _quarter_round(state, 3, 4, 9, 14, carries)
        if len(carries) != ADDITIONS_PER_ROUND:
            raise AssertionError("diagonal-round carry count differs")
        round_carries.append(tuple(carries))
        states.append(tuple(state))

    output_words: list[int] = []
    feedforward_carries: list[int] = []
    for final_word, initial_word in zip(state, initial, strict=True):
        output, carry = add32_with_carry_mask(final_word, initial_word)
        output_words.append(output)
        feedforward_carries.append(carry)

    trace = ChaChaBlockTrace(
        initial_state=initial,
        round_states=tuple(states),
        round_carry_masks=tuple(round_carries),
        feedforward_carry_masks=tuple(feedforward_carries),
        output_words=tuple(output_words),
    )
    trace.validate()
    return trace


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Return one standard twenty-round RFC 8439 block."""

    return chacha20_block_trace(key, counter, nonce).output


def chacha20_blocks(
    key: bytes, counter: int, nonce: bytes, block_count: int
) -> tuple[bytes, ...]:
    if not isinstance(block_count, int) or isinstance(block_count, bool):
        raise ChaChaTraceError("block_count must be an integer")
    if not 1 <= block_count <= 256:
        raise ChaChaTraceError("block_count must be in [1, 256]")
    counter = _u32(counter, "counter")
    if counter + block_count - 1 > UINT32_MASK:
        raise ChaChaTraceError("counter schedule wraps uint32")
    return tuple(
        chacha20_block(key, counter + offset, nonce)
        for offset in range(block_count)
    )
