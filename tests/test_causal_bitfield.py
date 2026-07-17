from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.cadical_sensor import KEY_BITS, MOTIF_DIMENSIONS
from o1_crypto_lab.causal_bitfield import (
    HORIZON_COUNT,
    CausalBitfieldAccumulator,
    CausalBitfieldError,
    CausalBitfieldPlan,
    PairedCausalEvent,
    frozen_state_from_bytes,
    state_swap_control,
)


SOURCE_PAIR_SHA256 = "1" * 64
SOURCE_STREAM_SHA256 = "2" * 64


def _event(
    *,
    bit: int,
    horizon: int,
    polarity: float = 1.0,
    information_mass: float = 0.25,
) -> PairedCausalEvent:
    motif = np.zeros(MOTIF_DIMENSIONS, dtype=np.float64)
    motif[(bit + horizon) % MOTIF_DIMENSIONS] = polarity * 0.125
    key_touch = np.zeros(KEY_BITS, dtype=np.float64)
    key_touch[(bit + 1) % KEY_BITS] = polarity * 0.25
    key_touch[(bit + 32) % KEY_BITS] = polarity * -0.125
    return PairedCausalEvent(
        bit_index=bit,
        horizon=horizon,
        unary_score=polarity * ((bit % 17) - 8) / 16.0,
        information_mass=information_mass,
        motif_delta=motif,
        key_touch_delta=key_touch,
        source_pair_sha256=SOURCE_PAIR_SHA256,
    )


def _full_state(*, polarity: float = 1.0):
    plan = CausalBitfieldPlan()
    accumulator = CausalBitfieldAccumulator(plan)
    for bit in range(KEY_BITS):
        for horizon in plan.horizons:
            accumulator.update(
                _event(bit=bit, horizon=horizon, polarity=polarity)
            )
    return accumulator.freeze(source_stream_sha256=SOURCE_STREAM_SHA256)


class CausalBitfieldStateTests(unittest.TestCase):
    def test_full_3x256_coverage_has_exact_17408_byte_width(self) -> None:
        state = _full_state()
        description = state.describe()

        self.assertEqual(state.plan.serialized_state_bytes, 17_408)
        self.assertEqual(len(state.to_bytes()), 17_408)
        self.assertEqual(state.probe_counts.shape, (KEY_BITS,))
        np.testing.assert_array_equal(
            state.probe_counts,
            np.full(KEY_BITS, HORIZON_COUNT, dtype=np.uint16),
        )
        self.assertEqual(description["probe_events"], 3 * KEY_BITS)
        self.assertEqual(description["bits_covered"], KEY_BITS)

    def test_serialization_round_trip_is_byte_and_array_exact(self) -> None:
        original = _full_state()
        payload = original.to_bytes()
        restored = frozen_state_from_bytes(
            payload,
            plan=original.plan,
            source_stream_sha256=SOURCE_STREAM_SHA256,
        )

        self.assertEqual(restored.to_bytes(), payload)
        self.assertEqual(restored.state_sha256, original.state_sha256)
        for name in (
            "unary",
            "evidence_mass",
            "interactions",
            "holographic",
            "probe_counts",
            "family_stats",
        ):
            np.testing.assert_array_equal(
                getattr(restored, name), getattr(original, name)
            )
            self.assertFalse(getattr(restored, name).flags.writeable)

    def test_event_order_and_freeze_coverage_are_enforced(self) -> None:
        plan = CausalBitfieldPlan()
        accumulator = CausalBitfieldAccumulator(plan)

        with self.assertRaisesRegex(CausalBitfieldError, "frozen horizon order"):
            accumulator.update(_event(bit=7, horizon=plan.horizons[1]))
        accumulator.update(_event(bit=7, horizon=plan.horizons[0]))
        with self.assertRaisesRegex(CausalBitfieldError, "frozen horizon order"):
            accumulator.update(_event(bit=7, horizon=plan.horizons[2]))
        with self.assertRaisesRegex(CausalBitfieldError, "every bit"):
            accumulator.freeze(source_stream_sha256=SOURCE_STREAM_SHA256)

        accumulator.update(_event(bit=7, horizon=plan.horizons[1]))
        accumulator.update(_event(bit=7, horizon=plan.horizons[2]))
        with self.assertRaisesRegex(CausalBitfieldError, "frozen horizon order"):
            accumulator.update(_event(bit=7, horizon=plan.horizons[2]))

    def test_event_validation_rejects_malformed_or_nonfinite_evidence(self) -> None:
        valid = {
            "bit_index": 0,
            "horizon": 64,
            "unary_score": 0.0,
            "information_mass": 0.0,
            "motif_delta": np.zeros(MOTIF_DIMENSIONS),
            "key_touch_delta": np.zeros(KEY_BITS),
            "source_pair_sha256": SOURCE_PAIR_SHA256,
        }
        invalid_cases = (
            ({"bit_index": KEY_BITS}, "outside the key"),
            ({"horizon": 0}, "horizon must be positive"),
            ({"unary_score": float("nan")}, "finite scalar"),
            ({"information_mass": -1.0}, "non-negative"),
            ({"motif_delta": np.zeros(MOTIF_DIMENSIONS - 1)}, "shape"),
            ({"key_touch_delta": np.zeros(KEY_BITS + 1)}, "shape"),
            ({"source_pair_sha256": "A" * 64}, "lowercase SHA-256"),
        )
        for override, message in invalid_cases:
            with self.subTest(override=next(iter(override))):
                with self.assertRaisesRegex(CausalBitfieldError, message):
                    PairedCausalEvent(**(valid | override))

    def test_swap_control_is_exactly_antisymmetric(self) -> None:
        direct = _full_state(polarity=1.0)
        swapped = _full_state(polarity=-1.0)

        result = state_swap_control(direct, swapped)

        self.assertTrue(result["passed"], result)
        np.testing.assert_array_equal(direct.unary, -swapped.unary)
        np.testing.assert_array_equal(
            direct.interactions, -swapped.interactions
        )
        np.testing.assert_array_equal(
            direct.holographic, -swapped.holographic
        )
        np.testing.assert_array_equal(
            direct.evidence_mass, swapped.evidence_mass
        )
        np.testing.assert_array_equal(
            direct.family_stats, swapped.family_stats
        )
        np.testing.assert_array_equal(
            direct.probe_counts, swapped.probe_counts
        )


if __name__ == "__main__":
    unittest.main()
