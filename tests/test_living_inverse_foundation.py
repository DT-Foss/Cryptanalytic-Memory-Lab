from __future__ import annotations

import unittest

from o1_crypto_lab.living_inverse_foundation import (
    FoundationConfig,
    run_living_inverse_foundation,
)


class LivingInverseFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = FoundationConfig(
            build_targets=2,
            development_targets=1,
            contrasts_per_family=1,
            block_count=1,
            seed=73,
            decoy_count=128,
            decoy_seed=91,
            confidence_threshold=0.75,
            beam_uncertain_bits=8,
            beam_size=256,
        )

    def test_foundation_is_deterministic_full_width_and_closed(self) -> None:
        first = run_living_inverse_foundation(self.config)
        second = run_living_inverse_foundation(self.config)
        self.assertEqual(first.report, second.report)
        self.assertTrue(first.success_gate_passed)
        self.assertEqual(
            first.report["attacker_contract"]["unknown_target_key_bits"], 256
        )
        self.assertEqual(
            first.report["attacker_contract"]["target_trace_fields_in_deployment"],
            0,
        )
        self.assertFalse(first.report["attacker_contract"]["reduced_width_target"])
        self.assertEqual(first.report["corpus"]["deployment_contrasts"], 18)
        self.assertEqual(first.report["corpus"]["deployment_feature_dimension"], 2576)
        self.assertEqual(
            first.report["metric_harness"]["random_baseline"]["key_nll_bits"],
            256.0,
        )
        self.assertTrue(
            first.report["metric_harness"]["oracle_ceiling"]["beam"][
                "exact_key_in_beam"
            ]
        )

    def test_config_validation_rejects_bad_ranges_and_fields(self) -> None:
        value = self.config.describe()
        value["build_targets"] = 0
        with self.assertRaises(ValueError):
            FoundationConfig.from_mapping(value)
        value = self.config.describe()
        value["extra"] = 1
        with self.assertRaises(ValueError):
            FoundationConfig.from_mapping(value)


if __name__ == "__main__":
    unittest.main()
