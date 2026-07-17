from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.full256_multikey_calibration import (
    Full256MultiKeyCalibrationError,
    load_full256_multikey_calibration_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/full256_multikey_causal_calibration_v1.json"


class Full256MultiKeyCalibrationConfigTests(unittest.TestCase):
    def test_canonical_config_declares_complete_freeze_and_resource_contract(self):
        top_level, config = load_full256_multikey_calibration_config(CONFIG)

        self.assertEqual(top_level["attempt_id"], "O1C-0013")
        self.assertEqual(config.corpus.build_targets, 4)
        self.assertEqual(config.corpus.calibration_targets, 2)
        self.assertEqual(config.corpus.sealed_targets, 2)
        self.assertEqual(
            config.reader.arms,
            (
                "horizon_0",
                "horizon_1",
                "horizon_2",
                "u3",
                "u3_arx24",
                "u3_arx24_m12",
            ),
        )
        self.assertEqual(config.reader.shrinkages, (0.0, 0.25, 0.5, 1.0))
        self.assertEqual(config.reader.decoy_count, 1_000_000)
        self.assertEqual(config.state_plan.serialized_state_bytes, 17_408)
        self.assertEqual(config.maximum_live_target_state_bytes, 58_368)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 5_632)
        self.assertTrue(config.controls.run_only_if_calibration_compression_positive)

    def test_config_rejects_unaccounted_top_level_fields(self):
        value = json.loads(CONFIG.read_text(encoding="utf-8"))
        value["unaccounted_work"] = True
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(
                Full256MultiKeyCalibrationError, "config fields differ"
            ):
                load_full256_multikey_calibration_config(path)


if __name__ == "__main__":
    unittest.main()
