from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.cadical_sensor import KEY_BITS, MOTIF_DIMENSIONS
from o1_crypto_lab.causal_bitfield import (
    HORIZON_COUNT,
    HOLOGRAPHIC_CHANNELS,
    HOLOGRAPHIC_FAMILIES,
    NEIGHBORS_PER_BIT,
    CausalBitfieldPlan,
    FrozenCausalBitfieldState,
)
from o1_crypto_lab.causal_orientation_reader import (
    ARM_CAUSAL_LOCAL,
    ARM_HORIZON_0,
    ARM_HORIZON_1,
    ARM_U3,
    ARM_U3_ARX24,
    ARM_U3_ARX24_M12,
    CausalOrientationReaderError,
    calibrate_orientation_reader,
    canonical_feature_tensor,
    deserialize_orientation_reader,
    fit_build_orientation_candidates,
    fit_causal_orientation_reader,
    orientation_metrics,
    serialize_orientation_reader,
)


def _labels(seed: int, count: int) -> np.ndarray:
    generator = np.random.default_rng(seed)
    return generator.integers(0, 2, size=(count, KEY_BITS), dtype=np.uint8)


def _canonical_features(
    labels: np.ndarray,
    *,
    seed: int,
) -> np.ndarray:
    generator = np.random.default_rng(seed)
    signed = 2.0 * labels.astype(np.float64) - 1.0
    count = labels.shape[0]
    unary = generator.normal(0.0, 0.30, size=(count, KEY_BITS, 3))
    unary[:, :, 0] += 1.25 * signed
    unary[:, :, 1] += 0.50 * signed
    unary[:, :, 2] -= 0.20 * signed
    arx = generator.normal(0.0, 0.45, size=(count, KEY_BITS, 24))
    arx[:, :, :4] += signed[:, :, None] * np.array([0.45, -0.35, 0.30, 0.20])
    motif = generator.normal(0.0, 0.55, size=(count, KEY_BITS, 12))
    motif[:, :, :2] += signed[:, :, None] * np.array([0.20, -0.15])
    return canonical_feature_tensor(unary, arx, motif)


def _frozen_state(
    signed: np.ndarray, *, source_digit: str
) -> FrozenCausalBitfieldState:
    plan = CausalBitfieldPlan()
    unary = np.stack((signed, 0.5 * signed, -0.25 * signed)).astype(np.float32)
    interactions = np.repeat(signed[:, None], NEIGHBORS_PER_BIT, axis=1)
    interactions *= np.linspace(0.125, 0.5, NEIGHBORS_PER_BIT)[None, :]
    return FrozenCausalBitfieldState(
        plan=plan,
        unary=unary,
        evidence_mass=np.ones(KEY_BITS, dtype=np.float32),
        interactions=interactions.astype(np.float32),
        holographic=np.zeros(
            (HOLOGRAPHIC_FAMILIES, HOLOGRAPHIC_CHANNELS), dtype=np.complex64
        ),
        probe_counts=np.full(KEY_BITS, HORIZON_COUNT, dtype=np.uint16),
        family_stats=np.ones(MOTIF_DIMENSIONS, dtype=np.float64),
        source_stream_sha256=source_digit * 64,
    )


class CausalOrientationReaderTests(unittest.TestCase):
    def test_frozen_state_reader_is_odd_and_swap_probabilities_complement(self) -> None:
        build_labels = _labels(1, 3)
        calibration_labels = _labels(2, 2)
        build_states = tuple(
            _frozen_state(
                2.0 * row.astype(np.float64) - 1.0,
                source_digit=str(index + 1),
            )
            for index, row in enumerate(build_labels)
        )
        calibration_states = tuple(
            _frozen_state(
                2.0 * row.astype(np.float64) - 1.0,
                source_digit=str(index + 5),
            )
            for index, row in enumerate(calibration_labels)
        )
        reader = fit_causal_orientation_reader(
            build_states,
            build_labels,
            calibration_states,
            calibration_labels,
            arms=(ARM_CAUSAL_LOCAL,),
            ridge_lambdas=(1.0,),
            temperatures=(2.0,),
        )
        direct = calibration_states[0]
        swapped = _frozen_state(
            -(2.0 * calibration_labels[0].astype(np.float64) - 1.0),
            source_digit="9",
        )

        direct_scores = reader.predict_scores(direct)
        swapped_scores = reader.predict_scores(swapped)
        direct_probability = reader.predict_probabilities(direct)
        swapped_probability = reader.predict_probabilities(swapped)

        self.assertGreater(reader.logit_scale, 0.0)
        np.testing.assert_array_equal(direct_scores, -swapped_scores)
        np.testing.assert_array_equal(
            direct_probability + swapped_probability,
            np.ones(KEY_BITS, dtype=np.float64),
        )
        self.assertEqual(reader.describe()["information_boundary"]["intercept"], 0.0)
        self.assertFalse(reader.describe()["information_boundary"]["feature_centering"])

    def test_canonical_reader_round_trip_is_byte_hash_and_prediction_exact(
        self,
    ) -> None:
        build_labels = _labels(11, 4)
        calibration_labels = _labels(12, 2)
        build = _canonical_features(build_labels, seed=13)
        calibration = _canonical_features(calibration_labels, seed=14)
        reader = fit_causal_orientation_reader(
            build,
            build_labels,
            calibration,
            calibration_labels,
            arms=(ARM_HORIZON_0, ARM_U3, ARM_U3_ARX24, ARM_U3_ARX24_M12),
            ridge_lambdas=(0.1, 1.0),
            temperatures=(0.5, 1.0, 2.0),
        )

        payload = serialize_orientation_reader(reader)
        restored = deserialize_orientation_reader(payload)

        self.assertEqual(serialize_orientation_reader(restored), payload)
        self.assertEqual(restored.reader_sha256, reader.reader_sha256)
        self.assertEqual(restored.candidate_sha256, reader.candidate_sha256)
        np.testing.assert_array_equal(
            restored.predict_probabilities(calibration),
            reader.predict_probabilities(calibration),
        )
        damaged = bytearray(payload)
        damaged[-1] ^= 1
        with self.assertRaisesRegex(CausalOrientationReaderError, "payload"):
            deserialize_orientation_reader(bytes(damaged))

    def test_calibration_selects_without_refitting_build_candidates(self) -> None:
        build_labels = _labels(21, 3)
        calibration_labels = _labels(22, 2)
        build = _canonical_features(build_labels, seed=23)
        calibration = _canonical_features(calibration_labels, seed=24)
        candidates = fit_build_orientation_candidates(
            build,
            build_labels,
            arms=(ARM_U3,),
            ridge_lambdas=(1.0,),
        )
        candidate = candidates[0]
        original_scale = candidate.feature_scale.copy()
        original_weights = candidate.weights.copy()

        direct = calibrate_orientation_reader(
            candidates,
            calibration,
            calibration_labels,
            temperatures=(1.0,),
        )
        inverted = calibrate_orientation_reader(
            candidates,
            calibration,
            1 - calibration_labels,
            temperatures=(1.0,),
        )

        np.testing.assert_array_equal(candidate.feature_scale, original_scale)
        np.testing.assert_array_equal(candidate.weights, original_weights)
        np.testing.assert_array_equal(direct.feature_scale, inverted.feature_scale)
        np.testing.assert_array_equal(direct.weights, inverted.weights)
        self.assertEqual(direct.candidate_sha256, inverted.candidate_sha256)
        self.assertEqual(direct.build_dataset_sha256, inverted.build_dataset_sha256)
        self.assertNotEqual(
            direct.calibration_dataset_sha256,
            inverted.calibration_dataset_sha256,
        )
        self.assertEqual(
            direct.describe()["information_boundary"]["parameter_fit_split"],
            "BUILD",
        )
        self.assertEqual(
            direct.describe()["information_boundary"]["hyperparameter_selection_split"],
            "CAL",
        )
        self.assertFalse(direct.describe()["information_boundary"]["calibration_refit"])

    def test_candidate_selection_is_deterministic_under_grid_reordering(self) -> None:
        build_labels = _labels(31, 4)
        calibration_labels = _labels(32, 2)
        build = _canonical_features(build_labels, seed=33)
        calibration = _canonical_features(calibration_labels, seed=34)
        arms = (
            ARM_HORIZON_1,
            ARM_U3_ARX24_M12,
            ARM_HORIZON_0,
            ARM_U3_ARX24,
            ARM_U3,
        )
        forward = fit_causal_orientation_reader(
            build,
            build_labels,
            calibration,
            calibration_labels,
            arms=arms,
            ridge_lambdas=(10.0, 0.1, 1.0),
            temperatures=(4.0, 0.5, 2.0),
        )
        reversed_grid = fit_causal_orientation_reader(
            build,
            build_labels,
            calibration,
            calibration_labels,
            arms=tuple(reversed(arms)),
            ridge_lambdas=(1.0, 10.0, 0.1),
            temperatures=(2.0, 4.0, 0.5),
        )

        self.assertEqual(
            serialize_orientation_reader(forward),
            serialize_orientation_reader(reversed_grid),
        )
        self.assertEqual(forward.reader_sha256, reversed_grid.reader_sha256)

    def test_metrics_report_exact_random_baseline_width(self) -> None:
        labels = _labels(41, 2)
        metrics = orientation_metrics(
            np.full((2, KEY_BITS), 0.5, dtype=np.float64), labels
        )

        self.assertEqual(metrics.total_bits, 512)
        self.assertEqual(metrics.total_nll_bits, 512.0)
        self.assertEqual(metrics.nll_bits_per_key, 256.0)
        self.assertEqual(metrics.nll_bits_per_bit, 1.0)
        self.assertEqual(metrics.describe()["compression_bits_per_key"], 0.0)

    def test_null_signal_calibration_selects_exact_uniform_fallback(self) -> None:
        build_labels = _labels(51, 2)
        calibration_labels = _labels(52, 2)
        build = np.zeros((2, KEY_BITS, 39), dtype=np.float64)
        calibration = np.zeros((2, KEY_BITS, 39), dtype=np.float64)

        reader = fit_causal_orientation_reader(
            build,
            build_labels,
            calibration,
            calibration_labels,
            arms=(ARM_HORIZON_0, ARM_U3),
            ridge_lambdas=(0.1, 1.0),
            temperatures=(0.5, 2.0),
            logit_scales=(0.0, 0.5, 1.0),
        )

        self.assertEqual(reader.logit_scale, 0.0)
        np.testing.assert_array_equal(
            reader.predict_probabilities(calibration),
            np.full((2, KEY_BITS), 0.5, dtype=np.float64),
        )
        self.assertEqual(
            reader.evaluate(calibration, calibration_labels).nll_bits_per_key,
            256.0,
        )


if __name__ == "__main__":
    unittest.main()
