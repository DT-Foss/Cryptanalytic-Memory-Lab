from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.full256_online_real_forensics import (
    _compression_bits,
    _cosine,
    _horizon_inventory,
    _pearson,
    _posthoc_scale_search,
    _rank_overlap,
    _work_prefix,
)


class Full256OnlineRealForensicsTests(unittest.TestCase):
    def test_vector_diagnostics_preserve_sign_and_overlap(self) -> None:
        left = np.asarray([1.0, 2.0, 4.0])
        self.assertAlmostEqual(_pearson(left, left), 1.0)
        self.assertAlmostEqual(_pearson(left, -left), -1.0)
        self.assertAlmostEqual(_cosine(left, left), 1.0)
        self.assertAlmostEqual(_cosine(left, -left), -1.0)

        overlap = _rank_overlap((1, 2, 3), (1, 2, 4), universe=8)
        self.assertEqual(overlap["intersection"], 2)
        self.assertAlmostEqual(overlap["action_set_jaccard"], 0.5)
        self.assertAlmostEqual(overlap["common_action_rank_pearson"], 1.0)

    def test_work_and_horizon_inventory_use_flat_action_address(self) -> None:
        horizons = (64, 65, 96)
        order = (0, 256 + 7, 512 + 9)
        np.testing.assert_array_equal(
            _work_prefix(order, horizons),
            np.asarray([0, 128, 258, 450]),
        )
        self.assertEqual(
            _horizon_inventory(order, horizons),
            {"h64": 1, "h65": 1, "h96": 1},
        )

    def test_compression_and_posthoc_scale_are_explicitly_label_conditioned(
        self,
    ) -> None:
        labels = np.tile(np.asarray([0, 1], dtype=np.uint8), 128)
        correct = (2.0 * labels.astype(np.float64) - 1.0) * 0.25
        self.assertAlmostEqual(_compression_bits(np.zeros(256), labels), 0.0)
        self.assertGreater(_compression_bits(correct, labels), 0.0)
        self.assertLess(_compression_bits(-correct, labels), 0.0)

        report = _posthoc_scale_search(
            np.stack((-correct, -correct)),
            np.stack((labels, labels)),
        )
        self.assertLess(report["best_scale"], 0.0)
        self.assertGreater(report["mean_compression_bits"], 0.0)


if __name__ == "__main__":
    unittest.main()
