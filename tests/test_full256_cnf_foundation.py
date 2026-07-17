from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.full256_cnf import verify_full256_instance
from o1_crypto_lab.full256_cnf_foundation import (
    Full256CNFFoundationError,
    load_full256_cnf_foundation_config,
    run_full256_cnf_foundation,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/full256_cnf_foundation_v1.json"


class Full256CNFFoundationTests(unittest.TestCase):
    def test_frozen_config_loads_and_rejects_extra_foundation_fields(self) -> None:
        top_level, config = load_full256_cnf_foundation_config(CONFIG)
        self.assertEqual(top_level["attempt_id"], "O1C-0011")
        self.assertEqual(config.expected_variable_count, 32_128)
        self.assertEqual(config.expected_clause_count, 187_370)
        self.assertEqual(config.paired_assumption_bit, 173)
        forged = dict(top_level["foundation"])
        forged["unregistered"] = True
        with self.assertRaisesRegex(Full256CNFFoundationError, "fields differ"):
            type(config).from_mapping(forged)

    @unittest.skipUnless(shutil.which("cadical"), "CaDiCaL is not installed")
    def test_complete_foundation_run_and_persistent_instances_verify(self) -> None:
        _, config = load_full256_cnf_foundation_config(CONFIG)
        with tempfile.TemporaryDirectory() as temporary:
            result = run_full256_cnf_foundation(config, temporary)
            self.assertTrue(result.success_gate_passed)
            metrics = result.metrics()
            self.assertEqual(metrics["unknown_target_key_bits"], 256)
            self.assertEqual(metrics["public_key_unit_clauses"], 0)
            self.assertEqual(metrics["rfc_fixed_key_status"], "SAT")
            self.assertEqual(metrics["flipped_output_status"], "UNSAT")
            self.assertEqual(metrics["second_fixed_key_status"], "SAT")
            self.assertLessEqual(
                metrics["maximum_working_bytes"], config.maximum_working_bytes
            )

            template = result.artifact_paths["cnf/full256_chacha20.cnf"]
            map_path = result.artifact_paths["cnf/full256_chacha20.map.json"]
            public_path = result.artifact_paths["cnf/public_attacker_instance.cnf"]
            public_report = result.report["instances"]["public"]["instance_report"]
            self.assertTrue(
                verify_full256_instance(
                    public_path, template, map_path, public_report
                )["ok"]
            )
            for value in (0, 1):
                relative = f"cnf/paired_keybit_173_eq_{value}.cnf"
                pair_report = result.report["instances"]["paired"][str(value)]
                self.assertTrue(
                    verify_full256_instance(
                        result.artifact_paths[relative],
                        template,
                        map_path,
                        pair_report,
                    )["ok"]
                )


if __name__ == "__main__":
    unittest.main()
