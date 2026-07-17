from __future__ import annotations

import json
import unittest

import numpy as np

from o1_crypto_lab.living_inverse import (
    ContrastFamily,
    LivingInverseError,
    bits_to_key,
    build_known_target,
    deployment_feature_vector,
    key_bits,
    make_deployment_contrast,
    make_output_flip_control,
    make_training_contrast,
    make_wrong_nonce_control,
    posterior_metrics,
    propose_contrast_key,
    public_target_feature_vector,
)


class LivingInverseBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes((17 * index + 3) & 0xFF for index in range(32))
        self.target = build_known_target(
            self.key,
            counter=19,
            nonce=bytes(range(12)),
            block_count=1,
        )

    def test_public_target_is_full_width_and_contains_no_teacher(self) -> None:
        public = self.target.public.describe()
        encoded = json.dumps(public, sort_keys=True)
        self.assertEqual(public["unknown_key_bits"], 256)
        self.assertEqual(public["rounds"], 20)
        self.assertFalse(public["target_key_included"])
        self.assertFalse(public["target_trace_included"])
        self.assertNotIn(self.key.hex(), encoded)
        self.assertNotIn("round_states", encoded)
        self.assertEqual(public_target_feature_vector(self.target.public).shape, (640,))

    def test_key_bit_codec_is_exact_little_bit_order(self) -> None:
        bits = key_bits(bytes([1, 2]) + bytes(30))
        self.assertEqual(bits[:16].tolist(), [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        self.assertEqual(bits_to_key(bits), bytes([1, 2]) + bytes(30))
        with self.assertRaises(LivingInverseError):
            bits_to_key([0] * 255)

    def test_all_contrast_families_are_deterministic_and_full_width(self) -> None:
        outputs = {}
        for family in ContrastFamily:
            probabilities = [0.6] * 256 if family is ContrastFamily.POSTERIOR_SAMPLE else None
            first = propose_contrast_key(
                self.key,
                family,
                seed=11,
                step=5,
                posterior_probabilities=probabilities,
            )
            second = propose_contrast_key(
                self.key,
                family,
                seed=11,
                step=5,
                posterior_probabilities=probabilities,
            )
            self.assertEqual(first, second)
            self.assertEqual(len(first), 32)
            outputs[family] = first
        self.assertEqual(len(set(outputs.values())), len(ContrastFamily))

    def test_deployment_contrast_has_candidate_trace_but_no_target_trace(self) -> None:
        candidate = propose_contrast_key(
            self.key, ContrastFamily.SINGLE_BIT, seed=7, step=0
        )
        contrast = make_deployment_contrast(
            self.target.public,
            candidate,
            family=ContrastFamily.SINGLE_BIT,
            sequence=0,
        )
        description = contrast.describe()
        encoded = json.dumps(description, sort_keys=True)
        self.assertIn(candidate.hex(), encoded)
        self.assertNotIn(self.key.hex(), encoded)
        self.assertFalse(description["target_trace_included"])
        features = deployment_feature_vector(contrast)
        self.assertEqual(features.shape, (2576,))
        self.assertEqual(features.dtype, np.float32)
        self.assertTrue(np.all(np.isfinite(features)))

    def test_training_labels_are_physically_separate(self) -> None:
        training = make_training_contrast(
            self.target,
            family=ContrastFamily.GRAY_WINDOW,
            seed=13,
            sequence=2,
            anchor_key=self.target.teacher.target_key,
        )
        training.validate(self.target)
        deployment = json.dumps(training.deployment.describe(), sort_keys=True)
        labels = training.describe_labels()
        self.assertNotIn("correction_bits", deployment)
        self.assertEqual(len(labels["correction_bits"]), 256)
        self.assertFalse(labels["deployment_input"])

    def test_public_controls_change_exactly_the_declared_input(self) -> None:
        flipped = make_output_flip_control(self.target.public, 137)
        wrong_nonce = make_wrong_nonce_control(self.target.public, 23)
        output_delta = sum(
            (left ^ right).bit_count()
            for left, right in zip(
                self.target.public.output_blocks[0],
                flipped.output_blocks[0],
                strict=True,
            )
        )
        nonce_delta = sum(
            (left ^ right).bit_count()
            for left, right in zip(
                self.target.public.nonce, wrong_nonce.nonce, strict=True
            )
        )
        self.assertEqual(output_delta, 1)
        self.assertEqual(nonce_delta, 1)
        self.assertEqual(wrong_nonce.output_blocks, self.target.public.output_blocks)


class PosteriorMetricTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes((29 * index + 5) & 0xFF for index in range(32))

    def test_random_baseline_is_exactly_256_bits(self) -> None:
        metrics = posterior_metrics(
            self.key,
            np.full(256, 0.5),
            decoy_count=128,
            decoy_seed=3,
            beam_uncertain_bits=8,
            beam_size=256,
        )
        self.assertAlmostEqual(metrics["key_nll_bits"], 256.0)
        self.assertAlmostEqual(metrics["effective_compression_bits"], 0.0)
        self.assertEqual(len(metrics["byte_ranks"]), 32)
        self.assertEqual(len(metrics["word16_ranks"]), 16)
        self.assertGreaterEqual(metrics["full_key_rank_among_decoys"], 1)

    def test_high_confidence_truth_has_exact_mode_and_beam(self) -> None:
        truth = key_bits(self.key)
        probabilities = np.where(truth == 1, 0.99, 0.01)
        metrics = posterior_metrics(
            self.key,
            probabilities,
            confidence_threshold=0.9,
            decoy_count=256,
            decoy_seed=9,
            beam_uncertain_bits=8,
            beam_size=256,
        )
        self.assertEqual(metrics["hamming_distance"], 0)
        self.assertEqual(metrics["confident_bits"], 256)
        self.assertEqual(metrics["confident_correct_bits"], 256)
        self.assertTrue(metrics["beam"]["exact_key_in_beam"])
        self.assertEqual(metrics["full_key_rank_among_decoys"], 1)
        self.assertGreater(metrics["effective_compression_bits"], 250)

    def test_invalid_posterior_is_rejected(self) -> None:
        with self.assertRaises(LivingInverseError):
            posterior_metrics(self.key, [0.5] * 255)
        with self.assertRaises(LivingInverseError):
            posterior_metrics(self.key, [0.0] * 256)


if __name__ == "__main__":
    unittest.main()
