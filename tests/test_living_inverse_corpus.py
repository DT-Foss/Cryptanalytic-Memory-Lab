from __future__ import annotations

import unittest
from dataclasses import replace

import numpy as np

from o1_crypto_lab.living_inverse import (
    ContrastFamily,
    deployment_feature_vector,
    make_deployment_contrast,
)
from o1_crypto_lab.living_inverse_corpus import (
    CANDIDATE_FEATURE_DIMENSION,
    PUBLIC_FEATURE_DIMENSION,
    TEACHER_FEATURE_DIMENSION,
    attacker_candidate_keys,
    candidate_feature_vector,
    make_reader_target,
    training_candidate_key,
)


class LivingInverseCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = make_reader_target(
            seed=17,
            split="DEVELOPMENT",
            index=3,
            counter=1,
            nonce=bytes(12),
            structured=False,
        )

    def test_target_shapes_commitments_and_distributions(self) -> None:
        self.assertEqual(self.target.public_features.shape, (PUBLIC_FEATURE_DIMENSION,))
        self.assertEqual(self.target.key_labels.shape, (256,))
        self.assertEqual(
            self.target.teacher_features.shape, (TEACHER_FEATURE_DIMENSION,)
        )
        self.assertEqual(len(self.target.public_commitment()), 64)
        self.assertEqual(len(self.target.teacher_commitment()), 64)
        structured = make_reader_target(
            seed=17,
            split="TRAIN",
            index=3,
            counter=1,
            nonce=bytes(12),
            structured=True,
        )
        self.assertEqual(structured.distribution, "STRUCTURED")
        self.assertNotEqual(structured.key, self.target.key)
        with self.assertRaises(ValueError):
            make_reader_target(
                seed=17,
                split="DEVELOPMENT",
                index=3,
                counter=1,
                nonce=bytes(12),
                structured=True,
            )
        corrupt = replace(
            self.target,
            key_labels=np.roll(self.target.key_labels, 1),
        )
        with self.assertRaises(ValueError):
            corrupt.validate()

    def test_fast_candidate_features_match_strict_deployment_encoder(self) -> None:
        family = ContrastFamily.UNIFORM_RANDOM
        candidate = attacker_candidate_keys(
            self.target.public, np.full(256, 0.5), count=12, seed=9
        )[-1]
        fast = candidate_feature_vector(self.target.public, candidate)
        strict = deployment_feature_vector(
            make_deployment_contrast(
                self.target.public,
                candidate,
                family=family,
                sequence=2,
            )
        )
        self.assertEqual(fast.shape, (CANDIDATE_FEATURE_DIMENSION,))
        np.testing.assert_array_equal(fast, strict)

    def test_attacker_portfolio_depends_only_on_public_view_and_posterior(self) -> None:
        probabilities = np.linspace(0.1, 0.9, 256)
        first = attacker_candidate_keys(
            self.target.public, probabilities, count=12, seed=7
        )
        second = attacker_candidate_keys(
            self.target.public, probabilities, count=12, seed=7
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)
        self.assertEqual(len(set(first)), 12)
        self.assertTrue(all(len(key) == 32 for key in first))
        self.assertEqual(first[0], bytes(32))
        self.assertNotIn(self.target.key, first)
        with self.assertRaises(ValueError):
            attacker_candidate_keys(
                self.target.public, probabilities, count=12, seed=True
            )

    def test_training_family_cycles_without_returning_target(self) -> None:
        target = make_reader_target(
            seed=17,
            split="TRAIN",
            index=3,
            counter=1,
            nonce=bytes(12),
            structured=False,
        )
        observed = set()
        for index in range(len(ContrastFamily)):
            family, candidate = training_candidate_key(
                target, seed=31, example_index=index
            )
            observed.add(family)
            self.assertNotEqual(candidate, target.key)
        self.assertEqual(observed, set(ContrastFamily))

        with self.assertRaises(ValueError):
            training_candidate_key(self.target, seed=31, example_index=0)


if __name__ == "__main__":
    unittest.main()
