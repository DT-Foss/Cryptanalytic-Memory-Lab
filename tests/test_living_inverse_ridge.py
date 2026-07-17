from __future__ import annotations

import hashlib
import unittest

import numpy as np

from o1_crypto_lab.living_inverse_ridge import (
    FeatureSegment,
    HolographicFeatureMap,
    HolographicFeaturePlan,
    deserialize_ridge,
    fit_holographic_ridge,
    serialize_ridge,
)


class HolographicRidgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = HolographicFeaturePlan(
            input_dimension=16,
            slots=32,
            seed=17,
            segments=(
                FeatureSegment("left", 0, 8),
                FeatureSegment("right", 8, 16),
            ),
            interactions=(("left", "right"),),
        )
        rng = np.random.default_rng(5)
        self.features = rng.integers(0, 2, size=(384, 16)).astype(np.float32)
        base = np.tile(self.features[:, :8], (1, 32))[:, :256]
        self.labels = base.astype(np.float64)

    def test_feature_map_is_deterministic_and_interactive(self) -> None:
        feature_map = HolographicFeatureMap(self.plan)
        first = feature_map.transform(self.features)
        second = HolographicFeatureMap(self.plan).transform(self.features)
        np.testing.assert_array_equal(first, second)
        self.assertEqual(first.shape, (384, 96))
        self.assertEqual(
            hashlib.sha256(first.tobytes()).hexdigest(),
            hashlib.sha256(second.tobytes()).hexdigest(),
        )

    def test_reduced_rank_reader_learns_and_round_trips(self) -> None:
        mapped = HolographicFeatureMap(self.plan).transform(self.features)
        model = fit_holographic_ridge(
            self.plan,
            mapped,
            self.labels,
            ridge_lambda=1.0,
            rank=8,
            auxiliary_labels=self.features[:, :4],
            auxiliary_weight=0.25,
        )
        scores = model.predict_mapped(mapped)
        accuracy = np.mean((scores >= 0.0) == self.labels)
        self.assertGreater(accuracy, 0.9)
        frozen = serialize_ridge(model)
        restored = deserialize_ridge(frozen)
        np.testing.assert_array_equal(scores, restored.predict_mapped(mapped))
        self.assertEqual(
            model.describe()["model_sha256"], hashlib.sha256(frozen).hexdigest()
        )

    def test_plan_requires_exact_nonoverlapping_cover(self) -> None:
        bad = HolographicFeaturePlan(
            input_dimension=4,
            slots=4,
            seed=1,
            segments=(FeatureSegment("bad", 0, 3),),
            interactions=(),
        )
        with self.assertRaises(ValueError):
            bad.validate()


if __name__ == "__main__":
    unittest.main()
