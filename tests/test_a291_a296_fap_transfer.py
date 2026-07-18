from __future__ import annotations

import hashlib
import unittest

import numpy as np

from o1_crypto_lab.a291_a296_fap_transfer import (
    A291A296TransferError,
    A291_SELECTED_FEATURE_INDICES,
    A291_SELECTED_FEATURE_NAMES,
    audit_fap_compatibility,
    exact_a291_selected_channel_scores,
    load_frozen_a291_model,
    require_exact_fap_mapping,
)
from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.shape532 import FEATURE_NAMES, RAW_CHANNELS, trajectory_shape532


def _cells() -> tuple[dict[int, dict[str, float]], ...]:
    cells = []
    for candidate in range(256):
        rows = {}
        for horizon in (1, 2, 4, 8):
            rows[horizon] = {
                channel: float(1 + ((candidate * (index + 3) + horizon) % 29))
                for index, channel in enumerate(RAW_CHANNELS)
            }
        cells.append(rows)
    return tuple(cells)


class A291TransferTests(unittest.TestCase):
    def test_frozen_model_loads_from_lab_local_finalized_snapshot(self) -> None:
        model = load_frozen_a291_model()
        self.assertEqual(len(model.means), 532)
        self.assertEqual(len(model.scales), 532)
        self.assertEqual(len(model.coefficients), 532)
        self.assertTrue(all(scale > 0.0 for scale in model.scales))

    def test_frozen_eight_feature_identity_and_score(self) -> None:
        self.assertEqual(
            tuple(FEATURE_NAMES[index] for index in A291_SELECTED_FEATURE_INDICES),
            A291_SELECTED_FEATURE_NAMES,
        )
        cells = _cells()
        means = np.zeros(532)
        scales = np.ones(532)
        coefficients = np.zeros(532)
        coefficients[np.asarray(A291_SELECTED_FEATURE_INDICES)] = np.linspace(
            0.25, 2.0, 8
        )
        score = exact_a291_selected_channel_scores(
            cells, means=means, scales=scales, coefficients=coefficients
        )
        matrix = np.asarray(trajectory_shape532(cells))
        expected = (
            matrix[:, np.asarray(A291_SELECTED_FEATURE_INDICES)]
            * coefficients[np.asarray(A291_SELECTED_FEATURE_INDICES)]
        ).sum(axis=1)
        np.testing.assert_allclose(score, expected, rtol=2e-15, atol=2e-15)
        self.assertFalse(score.flags.writeable)

    def test_cached_fap_shortcut_is_rejected(self) -> None:
        pool = Full256ActionPool(
            horizons=(64, 96, 65),
            branch_features=np.zeros((3, 256, 2, BRANCH_FEATURES), np.float32),
            final_resources=np.zeros((256, 2, 3), np.uint64),
            pair_sha256=tuple(
                hashlib.sha256(str(index).encode()).hexdigest()
                for index in range(256)
            ),
            source_stream_sha256=hashlib.sha256(b"stream").hexdigest(),
        )
        report = audit_fap_compatibility(pool)
        self.assertFalse(report.exact_mapping_available)
        self.assertTrue(
            any("candidate-XOR neighborhood" in row for row in report.geometry_mismatches)
        )
        with self.assertRaisesRegex(A291A296TransferError, "unavailable"):
            require_exact_fap_mapping(pool)


if __name__ == "__main__":
    unittest.main()
