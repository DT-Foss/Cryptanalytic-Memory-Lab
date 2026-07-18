from __future__ import annotations

import copy
import math
import unittest
from collections.abc import Iterator

import numpy as np

from o1_crypto_lab.polyphase_sufficient_state import (
    BASIS_SHA256,
    GAINS,
    KEY_BITS,
    POLES,
    SLOT_SHAPE,
    STATE_BYTES,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    PolyphaseSufficientStateError,
    ReplayRequiredError,
    basis_descriptor,
    basis_sha256_from_descriptor,
    direct_polyphase_state,
    read_polyphase_reference,
    read_polyphase_state,
    reference_readout_roundoff_bound,
)


PARTITIONS = (17, 64, 5, 96, 65, 32, 105)


def fixture(groups: int = 384, switch: int = 193) -> np.ndarray:
    result = np.empty((groups, 3, KEY_BITS), dtype=np.float32)
    coordinates = np.arange(KEY_BITS, dtype=np.int64)
    signs = ((1, -1, 1), (-1, 1, 1))
    carrier_scale = (4, -8)
    for t in range(groups):
        regime = int(t >= switch)
        for horizon in range(3):
            q = 2 * ((17 * coordinates + 29 * t + 7 * horizon) & 31) - 31
            parity = np.fromiter(
                (
                    1
                    if (int(i) ^ (13 * t + 5 * horizon)).bit_count() % 2 == 0
                    else -1
                    for i in coordinates
                ),
                dtype=np.int64,
                count=KEY_BITS,
            )
            numerator = signs[regime][horizon] * q + carrier_scale[regime] * parity
            result[t, horizon] = np.asarray(numerator / 64.0, dtype=np.float32)
    return result


def specs() -> tuple[PolyphaseReadoutSpec, ...]:
    rows = (
        ("balanced_t1", [[0.25] * 4] * 3, 1.0),
        ("fast_t05", [[0.625, 0.25, 0.125, 0.0]] * 3, 0.5),
        ("slow_t2", [[0.0, 0.125, 0.25, 0.625]] * 3, 2.0),
        (
            "crosswave_t075",
            [
                [0.5, 0.0, 0.25, 0.25],
                [0.25, 0.5, 0.0, 0.25],
                [0.25, 0.25, 0.5, 0.0],
            ],
            0.75,
        ),
    )
    return tuple(
        PolyphaseReadoutSpec(
            name=name,
            basis_sha256=BASIS_SHA256,
            slot_weights=np.asarray(weights, dtype=np.float32),
            temperature=temperature,
        )
        for name, weights, temperature in rows
    )


def partition(source: np.ndarray) -> list[np.ndarray]:
    chunks: list[np.ndarray] = []
    offset = 0
    for width in PARTITIONS:
        chunks.append(source[offset : offset + width])
        offset += width
    if offset != source.shape[0]:
        raise AssertionError("fixture partition differs")
    return chunks


class PolyphaseSufficientStateTests(unittest.TestCase):
    def test_exact_state_width_basis_and_roundtrip(self) -> None:
        state = PolyphaseSufficientState.initial()
        self.assertEqual(STATE_BYTES, 25_096)
        self.assertEqual(state.persistent_bytes, 25_096)
        self.assertEqual(len(state.to_bytes()), 25_096)
        self.assertEqual(state.clock, 0)
        self.assertEqual(state.coverage.tolist(), [0] * KEY_BITS)
        self.assertEqual(basis_sha256_from_descriptor(basis_descriptor()), BASIS_SHA256)
        restored = PolyphaseSufficientState.from_bytes(state.to_bytes())
        self.assertEqual(restored.to_bytes(), state.to_bytes())
        self.assertEqual(restored.sha256(), state.sha256())

    def test_single_impulse_matches_frozen_recurrence(self) -> None:
        group = np.zeros((3, KEY_BITS), dtype=np.float32)
        group[1, 37] = np.float32(0.75)
        state = PolyphaseSufficientState.initial()
        self.assertEqual(state.consume([group]), 1)
        expected = np.zeros(SLOT_SHAPE, dtype=np.complex64)
        expected[1, :, 37] = GAINS[1] * np.float32(0.75)
        self.assertTrue(np.array_equal(state.slots, expected))
        zero = np.zeros_like(group)
        state.consume([zero])
        expected = np.asarray(POLES[:, :, None] * expected, dtype=np.complex64)
        self.assertTrue(np.array_equal(state.slots, expected))
        self.assertTrue(np.array_equal(state.coverage, np.full(KEY_BITS, 2, np.uint16)))

    def test_chunk_partitions_are_byte_identical(self) -> None:
        source = fixture()
        whole = PolyphaseSufficientState.initial()
        rechunked = PolyphaseSufficientState.initial()
        one_by_one = PolyphaseSufficientState.initial()
        self.assertEqual(whole.consume(source), 384)
        self.assertEqual(rechunked.consume(partition(source)), 384)
        self.assertEqual(one_by_one.consume((row for row in source)), 384)
        self.assertEqual(whole.to_bytes(), rechunked.to_bytes())
        self.assertEqual(whole.to_bytes(), one_by_one.to_bytes())
        self.assertEqual(whole.clock, 384)
        self.assertTrue(
            np.array_equal(whole.coverage, np.full(KEY_BITS, 384, np.uint16))
        )

    def test_hot_readouts_are_distinct_reference_bounded_and_nonmutating(self) -> None:
        source = fixture()
        state = PolyphaseSufficientState.initial()
        state.consume(source)
        reference = direct_polyphase_state(source)
        original_hash = state.sha256()
        outputs: list[np.ndarray] = []
        for spec in specs():
            before = state.sha256()
            actual = read_polyphase_state(state, spec)
            expected = read_polyphase_reference(reference, spec)
            bound = reference_readout_roundoff_bound(reference, spec)
            self.assertTrue(np.all(np.abs(actual.astype(np.float64) - expected) <= bound))
            self.assertEqual(state.sha256(), before)
            self.assertFalse(actual.flags.writeable)
            outputs.append(actual)
        self.assertEqual(state.sha256(), original_hash)
        pairwise = [
            float(np.sqrt(np.mean((left - right).astype(np.float64) ** 2)))
            for index, left in enumerate(outputs)
            for right in outputs[index + 1 :]
        ]
        self.assertGreater(min(pairwise), 1e-3)

    def test_branch_swap_is_exactly_odd_with_even_counters(self) -> None:
        source = fixture()
        factual = PolyphaseSufficientState.initial()
        swapped = PolyphaseSufficientState.initial()
        factual.consume(source)
        swapped.consume(np.negative(source, dtype=np.float32))
        self.assertTrue(np.array_equal(swapped.slots, -factual.slots))
        self.assertTrue(np.array_equal(swapped.coverage, factual.coverage))
        self.assertEqual(swapped.clock, factual.clock)
        for spec in specs():
            self.assertTrue(
                np.array_equal(
                    read_polyphase_state(swapped, spec),
                    -read_polyphase_state(factual, spec),
                )
            )

    def test_encoder_kernel_and_phase_changes_require_replay_without_mutation(self) -> None:
        state = PolyphaseSufficientState.initial()
        state.consume(fixture(groups=12, switch=7))
        descriptor = basis_descriptor()
        mutations = []
        encoder = copy.deepcopy(descriptor)
        encoder["encoder"]["coordinate_order"] = "reverse-key-bit-255-through-0"
        mutations.append(encoder)
        kernel = copy.deepcopy(descriptor)
        kernel["kernel"]["timescales"] = [1, 2, 4, 9]
        mutations.append(kernel)
        phase = copy.deepcopy(descriptor)
        phase["phase"]["wavelengths"] = [63, 96, 65]
        mutations.append(phase)
        original = state.sha256()
        for index, changed in enumerate(mutations):
            with self.subTest(index=index):
                foreign = PolyphaseReadoutSpec(
                    name=f"foreign-{index}",
                    basis_sha256=basis_sha256_from_descriptor(changed),
                    slot_weights=np.ones((3, 4), dtype=np.float32),
                    temperature=1.0,
                )
                with self.assertRaises(ReplayRequiredError):
                    read_polyphase_state(state, foreign)
                self.assertEqual(state.sha256(), original)

    def test_failed_consume_is_transactional_and_zero_counts_as_observed(self) -> None:
        state = PolyphaseSufficientState.initial()
        original = state.sha256()
        good = np.zeros((3, KEY_BITS), dtype=np.float32)
        bad = np.zeros((3, KEY_BITS), dtype=np.float64)
        with self.assertRaises(PolyphaseSufficientStateError):
            state.consume([good, bad])
        self.assertEqual(state.sha256(), original)
        self.assertEqual(state.consume([good]), 1)
        self.assertTrue(np.array_equal(state.coverage, np.ones(KEY_BITS, np.uint16)))

    def test_coverage_saturates_but_clock_and_resonator_continue(self) -> None:
        state = PolyphaseSufficientState(
            np.zeros(SLOT_SHAPE, dtype=np.complex64),
            np.full(KEY_BITS, np.iinfo(np.uint16).max, dtype=np.uint16),
            65_535,
        )
        state.consume([np.zeros((3, KEY_BITS), dtype=np.float32)])
        self.assertEqual(state.clock, 65_536)
        self.assertTrue(
            np.array_equal(
                state.coverage,
                np.full(KEY_BITS, np.iinfo(np.uint16).max, dtype=np.uint16),
            )
        )

    def test_properties_and_specs_do_not_expose_mutable_state(self) -> None:
        state = PolyphaseSufficientState.initial()
        slots = state.slots
        coverage = state.coverage
        self.assertFalse(slots.flags.writeable)
        self.assertFalse(coverage.flags.writeable)
        spec = specs()[0]
        self.assertFalse(spec.slot_weights.flags.writeable)
        with self.assertRaises(ValueError):
            slots[0, 0, 0] = 1.0
        with self.assertRaises(ValueError):
            spec.slot_weights[0, 0] = 2.0
        for frozen in (POLES, GAINS, spec.slot_weights):
            with self.assertRaises(ValueError):
                frozen.setflags(write=True)

    def test_finite_overflow_aborts_the_entire_consume_transaction(self) -> None:
        state = PolyphaseSufficientState.initial()
        before = state.sha256()
        maximum = float(np.finfo(np.float32).max)

        def resonant_groups() -> Iterator[np.ndarray]:
            for t in range(4096):
                group = np.zeros((3, KEY_BITS), dtype=np.float32)
                group[0].fill(
                    np.float32(
                        0.5 * maximum * math.cos(2.0 * math.pi * t / 64.0)
                    )
                )
                yield group

        with self.assertRaisesRegex(
            PolyphaseSufficientStateError, "overflowed the complex64 recurrence"
        ):
            state.consume(resonant_groups())
        self.assertEqual(state.clock, 0)
        self.assertEqual(state.sha256(), before)


if __name__ == "__main__":
    unittest.main()
