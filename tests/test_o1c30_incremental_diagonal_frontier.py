from __future__ import annotations

import hashlib
import math
import unittest

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.o1c30_incremental_diagonal_frontier import (
    ARM_NAMES,
    ODD_ARM_NAMES,
    O1C30IncrementalDiagonalFrontierError,
    bounded_psi,
    exact_local_true_rank,
    fit_leave_one_out,
    fixed_point_free_sha_derangement,
    local_true_ranks,
    nll_bits,
    project_branch_features,
    project_pool,
    score_logits,
)


def _pool(
    features: np.ndarray, horizons: tuple[int, ...] = (64, 96, 65)
) -> Full256ActionPool:
    return Full256ActionPool(
        horizons=horizons,
        branch_features=np.asarray(features, dtype=np.float32),
        final_resources=np.zeros((256, 2, 3), dtype=np.uint64),
        pair_sha256=tuple(
            hashlib.sha256(f"pair/{bit}".encode("ascii")).hexdigest()
            for bit in range(256)
        ),
        source_stream_sha256=hashlib.sha256(b"source").hexdigest(),
    )


def _symmetric_features() -> np.ndarray:
    features = np.zeros((3, 256, 2, BRANCH_FEATURES), dtype=np.float32)
    # Storage is 64,96,65; chronological bounded odd values become .5,.75,.875.
    for storage, magnitude in enumerate((1.0, 7.0, 3.0)):
        coordinates = np.arange(256)
        features[storage, coordinates, 0, 74 + coordinates] = -magnitude
        features[storage, coordinates, 1, 74 + coordinates] = magnitude
    return features


class FixedProjectionTests(unittest.TestCase):
    def test_storage_reorders_to_chronological_innovations(self) -> None:
        features = _symmetric_features()
        projected = project_pool(_pool(features))

        np.testing.assert_array_equal(projected.q, np.zeros((3, 256), np.uint8))
        np.testing.assert_allclose(projected.odd_ancestry[:, 0], (0.5, 0.75, 0.875))
        np.testing.assert_allclose(projected.odd_innovations[:, 0], (0.5, 0.25, 0.125))
        np.testing.assert_allclose(projected.primary, 0.875)
        np.testing.assert_array_equal(projected.primary, projected.cumulative_replace)
        np.testing.assert_allclose(projected.legacy_reintegrated, 2.125)
        np.testing.assert_array_equal(projected.polarity_even_common_mode, 0.0)
        self.assertEqual(tuple(projected), ARM_NAMES)
        self.assertEqual(tuple(projected.as_mapping()), ARM_NAMES)
        self.assertTrue(all(not projected[name].flags.writeable for name in ARM_NAMES))

    def test_conflict_gate_and_deranged_control_are_exact(self) -> None:
        features = _symmetric_features()
        # Conflict disagreement sets branch-XOR-conflict agreement q=1.
        features[:, :, 1, 9] = 1.0
        projected = project_branch_features(features)

        np.testing.assert_array_equal(projected.q, np.ones((3, 256), np.uint8))
        np.testing.assert_allclose(projected.primary, 1.75)
        np.testing.assert_allclose(projected.deranged_confidence, 1.75)
        np.testing.assert_array_equal(
            projected.deranged_q, projected.q[:, projected.derangement]
        )
        self.assertEqual(len(np.unique(projected.derangement)), 256)
        self.assertFalse(np.any(projected.derangement == np.arange(256)))

    def test_actual_whole_branch_swap_negates_odd_and_preserves_gate_and_even(
        self,
    ) -> None:
        generator = np.random.Generator(np.random.PCG64(30))
        features = generator.normal(0.0, 2.0, (3, 256, 2, BRANCH_FEATURES)).astype(
            np.float32
        )
        features[..., 9] = generator.integers(0, 2, (3, 256, 2))
        direct = project_pool(_pool(features))
        swapped = project_pool(_pool(features[:, :, ::-1, :]))

        np.testing.assert_array_equal(swapped.q, direct.q)
        np.testing.assert_array_equal(swapped.deranged_q, direct.deranged_q)
        for arm in ODD_ARM_NAMES:
            np.testing.assert_allclose(swapped[arm], -direct[arm], atol=1e-15)
        np.testing.assert_allclose(
            swapped.polarity_even_common_mode,
            direct.polarity_even_common_mode,
            atol=1e-15,
        )

    def test_sha_derangement_and_psi_are_deterministic_and_bounded(self) -> None:
        first = fixed_point_free_sha_derangement()
        second = fixed_point_free_sha_derangement()
        np.testing.assert_array_equal(first, second)
        self.assertFalse(first.flags.writeable)
        values = np.asarray((-1e30, -1.0, 0.0, 1.0, 1e30), dtype=np.float64)
        transformed = bounded_psi(values)
        np.testing.assert_allclose(
            transformed, values / (1.0 + np.abs(values)), rtol=0.0, atol=0.0
        )
        self.assertTrue(np.all(np.abs(transformed) <= 1.0))

    def test_projection_rejects_contract_drift(self) -> None:
        features = _symmetric_features()
        with self.assertRaisesRegex(
            O1C30IncrementalDiagonalFrontierError, "storage order"
        ):
            project_branch_features(features, horizons=(64, 65, 96))
        with self.assertRaisesRegex(
            O1C30IncrementalDiagonalFrontierError, "branch_features"
        ):
            project_branch_features(features[:, :-1])
        invalid = features.copy()
        invalid[0, 0, 0, 9] = 0.5
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "conflict"):
            project_branch_features(invalid)
        with self.assertRaises(TypeError):
            project_pool(features)  # type: ignore[arg-type]
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "psi"):
            bounded_psi(np.asarray([math.nan]))


def _labels() -> np.ndarray:
    generator = np.random.Generator(np.random.PCG64(30030))
    return generator.integers(0, 2, (4, 256), dtype=np.uint8)


class StandardizedLeaveOneOutTests(unittest.TestCase):
    def test_tiny_features_fit_signal_after_training_rms_standardization(self) -> None:
        labels = _labels()
        signed = 2.0 * labels.astype(np.float64) - 1.0
        features = signed * np.asarray((1e-9, 2e-9, 3e-9, 4e-9))[:, None]
        result = fit_leave_one_out(features, labels, l2=1.0 / 768.0, arm_name="primary")

        self.assertEqual(result.logits.shape, (4, 256))
        self.assertTrue(np.all((result.logits > 0.0) == labels.astype(bool)))
        self.assertTrue(all(row.coefficient > 0.0 for row in result.fits))
        self.assertTrue(all(row.training_rms < 1e-8 for row in result.fits))
        self.assertTrue(all(row.absolute_gradient < 1e-11 for row in result.fits))
        self.assertLess(
            sum(nll_bits(result.logits[i], labels[i]) for i in range(4)), 64.0
        )
        self.assertFalse(result.logits.flags.writeable)

    def test_global_rescaling_leaves_standardized_logits_unchanged(self) -> None:
        labels = _labels()
        signed = 2.0 * labels.astype(np.float64) - 1.0
        features = signed * np.linspace(0.25, 1.25, 256)[None, :]
        first = fit_leave_one_out(features, labels, l2=0.1, arm_name="primary")
        second = fit_leave_one_out(features * 1e-12, labels, l2=0.1, arm_name="primary")
        np.testing.assert_allclose(first.logits, second.logits, rtol=2e-15, atol=2e-15)
        np.testing.assert_allclose(
            [row.coefficient for row in first.fits],
            [row.coefficient for row in second.fits],
            rtol=2e-15,
            atol=2e-15,
        )

    def test_own_heldout_label_and_feature_never_enter_own_fit(self) -> None:
        labels = _labels()
        features = np.where(labels == 1, 0.75, -0.75).astype(np.float64)
        baseline = fit_leave_one_out(features, labels, l2=0.1, arm_name="primary")

        changed_labels = labels.copy()
        changed_labels[0] = 1 - changed_labels[0]
        label_variant = fit_leave_one_out(
            features, changed_labels, l2=0.1, arm_name="primary"
        )
        self.assertEqual(baseline.fits[0], label_variant.fits[0])
        np.testing.assert_array_equal(baseline.logits[0], label_variant.logits[0])

        changed_features = features.copy()
        changed_features[0] *= 17.0
        feature_variant = fit_leave_one_out(
            changed_features, labels, l2=0.1, arm_name="primary"
        )
        self.assertEqual(baseline.fits[0], feature_variant.fits[0])
        np.testing.assert_allclose(feature_variant.logits[0], baseline.logits[0] * 17.0)
        self.assertEqual(baseline.fits[0].receipt_document()["training_examples"], 768)
        self.assertEqual(
            baseline.fits[0].receipt_document()["heldout_labels_used_for_fit"], 0
        )

    def test_zero_field_has_unit_floor_and_zero_logits(self) -> None:
        labels = _labels()
        result = fit_leave_one_out(
            np.zeros((4, 256), dtype=np.float64),
            labels,
            l2=0.1,
            arm_name="cumulative_replace",
        )
        np.testing.assert_array_equal(result.logits, 0.0)
        self.assertTrue(all(row.training_rms == 1.0 for row in result.fits))
        self.assertTrue(all(row.coefficient == 0.0 for row in result.fits))

    def test_fit_validation_and_replay_hashes(self) -> None:
        labels = _labels()
        features = np.ones((4, 256), dtype=np.float64)
        first = fit_leave_one_out(features, labels, l2=0.1, arm_name="primary")
        second = fit_leave_one_out(features, labels, l2=0.1, arm_name="primary")
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "features"):
            fit_leave_one_out(features[:, :-1], labels, l2=0.1, arm_name="primary")
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "labels"):
            fit_leave_one_out(
                features, labels.astype(np.float64), l2=0.1, arm_name="primary"
            )
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "l2"):
            fit_leave_one_out(features, labels, l2=0.0, arm_name="primary")
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "arm"):
            fit_leave_one_out(features, labels, l2=0.1, arm_name="invented")


class ExactMetricTests(unittest.TestCase):
    def test_zero_logit_ties_follow_little_endian_value_order(self) -> None:
        byte_labels = np.unpackbits(np.asarray([5], np.uint8), bitorder="little")
        self.assertEqual(exact_local_true_rank(np.zeros(8), byte_labels), 6)
        self.assertEqual(
            exact_local_true_rank(np.zeros(16), np.ones(16, np.uint8)), 65_536
        )

    def test_perfect_logits_have_rank_one_and_positive_compression(self) -> None:
        labels = _labels()[0]
        logits = np.where(labels == 1, 50.0, -50.0)
        metrics = score_logits(logits, labels)
        self.assertEqual(metrics.correct_bits, 256)
        self.assertGreater(metrics.compression_bits, 255.99)
        self.assertEqual(metrics.true_byte_ranks, (1,) * 32)
        self.assertEqual(metrics.true_u16_ranks, (1,) * 16)
        self.assertEqual(
            local_true_ranks(logits, labels),
            (metrics.true_byte_ranks, metrics.true_u16_ranks),
        )
        self.assertAlmostEqual(metrics.nll_bits, nll_bits(logits, labels))

    def test_metric_validation_rejects_wrong_width_and_label_dtype(self) -> None:
        labels = _labels()[0]
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "logits"):
            nll_bits(np.zeros(255), labels)
        with self.assertRaisesRegex(O1C30IncrementalDiagonalFrontierError, "labels"):
            score_logits(np.zeros(256), labels.astype(bool))


if __name__ == "__main__":
    unittest.main()
