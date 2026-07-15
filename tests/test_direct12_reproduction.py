import json
import os
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.direct12_reproduction import (
    Direct12ReproductionError,
    _reject_embedded_truth,
    run_direct12_reproduction,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/direct12_reproduction_v1.json"
CAPSULE = ROOT / "runs/20260715_123734_O1C-0003_direct12-source-snapshot"


class ReproductionLifecycleTests(unittest.TestCase):
    def test_config_contains_no_pre_freeze_truth_shortcut(self):
        config = json.loads(CONFIG.read_bytes())
        _reject_embedded_truth(config)
        config["a348"]["correct_prefix12"] = 2990
        with self.assertRaisesRegex(
            Direct12ReproductionError, "forbidden before order freeze"
        ):
            _reject_embedded_truth(config)

    def test_rejects_attempt_identity_before_source_access(self):
        config = json.loads(CONFIG.read_bytes())
        config["attempt_id"] = "O1C-9999"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(
                Direct12ReproductionError, "attempt ID differs"
            ):
                run_direct12_reproduction(path, lab_root=ROOT)


@unittest.skipUnless(
    os.environ.get("O1_CRYPTO_DIRECT12_REAL") == "1" and CAPSULE.is_dir(),
    "set O1_CRYPTO_DIRECT12_REAL=1 to run the immutable-snapshot reproduction",
)
class RealReproductionTests(unittest.TestCase):
    def test_orders_are_frozen_before_calibration_truth(self):
        frozen = []
        result = run_direct12_reproduction(
            CONFIG, lab_root=ROOT, on_frozen=frozen.append
        )
        self.assertTrue(result.success_gate_passed)
        self.assertEqual(len(frozen), 1)
        self.assertEqual(frozen[0]["labels_read"], {"A272": 0, "A348": 0, "A349": 0})
        self.assertEqual(
            frozen[0]["a349"]["slice_z_order_uint16be_sha256"],
            "441c6af3d9a2a32e1a61f0d50804a1ecbf2363517a7b570c408a09a15fd1bbaa",
        )
        self.assertEqual(result.report["a348"]["slice_z_rank_one_based"], 298)
        self.assertEqual(result.report["labels"]["A349_labels_read"], 0)


if __name__ == "__main__":
    unittest.main()
