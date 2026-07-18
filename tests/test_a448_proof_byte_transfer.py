from __future__ import annotations

import hashlib
import json
import unittest

import numpy as np

from o1_crypto_lab.a448_proof_byte_transfer import (
    A448_FROZEN_MODEL_SHA256,
    A448_MODEL_ROLES,
    A448_OPERATOR,
    A448_TOP4_FEATURE_INDICES,
    A448_TOP4_FEATURE_NAMES,
    a448_rank_field_from_run,
    load_frozen_a448_model,
    revealed_byte_rank,
    target_normalize_shape532,
)
from o1_crypto_lab.shape532 import FEATURE_NAMES


class A448ProofByteTransferTests(unittest.TestCase):
    def test_frozen_sibling_model_is_exact_and_complete(self) -> None:
        model = load_frozen_a448_model()
        self.assertEqual(model.model_sha256, A448_FROZEN_MODEL_SHA256)
        self.assertEqual(tuple(model.definitions), A448_MODEL_ROLES)
        self.assertEqual(model.top4_feature_indices, A448_TOP4_FEATURE_INDICES)
        self.assertEqual(model.top4_feature_names, A448_TOP4_FEATURE_NAMES)
        self.assertEqual(
            [len(model.definitions[role].member_feature_indices) for role in A448_MODEL_ROLES],
            [64, 8, 128, 128],
        )

    def test_shape_normalization_zeroes_constant_columns(self) -> None:
        matrix = np.zeros((256, len(FEATURE_NAMES)), dtype=np.float64)
        matrix[:, 0] = np.arange(256, dtype=np.float64)
        normalized = target_normalize_shape532(matrix)
        self.assertAlmostEqual(float(normalized[:, 0].mean()), 0.0, places=12)
        self.assertAlmostEqual(float(normalized[:, 0].std()), 1.0, places=12)
        self.assertEqual(int(np.count_nonzero(normalized[:, 1:])), 0)

    def test_one_pass_reader_matches_frozen_a448_target_001_rank(self) -> None:
        try:
            import zstandard
        except ModuleNotFoundError:
            self.skipTest("zstandard is unavailable for the read-only sibling fixture")
        model = load_frozen_a448_model()
        shard = (
            model.sibling_root
            / "research/results/v1/"
            "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1/"
            "target_001.json.zst"
        )
        result_path = (
            model.sibling_root
            / "research/results/v1/"
            "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
        )
        if not shard.is_file() or not result_path.is_file():
            self.skipTest("exact A448 sibling fixture is unavailable")
        measurement = json.loads(
            zstandard.ZstdDecompressor().decompress(shard.read_bytes())
        )
        result = json.loads(result_path.read_bytes())
        field = a448_rank_field_from_run(measurement["run"], model=model)
        # A448 target 001 is the first of the frozen no-refit remaining96 panel.
        expected = result["primary_no_refit_evaluation"]["truth_ranks"][0]
        self.assertEqual(A448_OPERATOR, "hybrid_proof_top4_equal")
        self.assertEqual(
            hashlib.sha256(field.baseline_ranks.astype("<i2").tobytes()).hexdigest(),
            "d301536c6fd8512744e29bc9b0e55e78045ba7ef2c998e96a083c147637df7dd",
        )
        self.assertEqual(
            field.directional_rank_sha256,
            "073f51e1d872c6b9decbe2e82749a76c97aa396a4ee6a811a7de24d6a03ac2e1",
        )
        self.assertEqual(revealed_byte_rank(field, 92), expected)
        self.assertEqual(expected, 139)


if __name__ == "__main__":
    unittest.main()
