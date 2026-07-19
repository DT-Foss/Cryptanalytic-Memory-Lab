from __future__ import annotations

import inspect
import json
import unittest
from typing import Any, cast

from apple_view_4_bidirectional_carry import (
    ADDITIONS_PER_BLOCK,
    APPLE_VIEW_4_DIR,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    ExperimentConfig,
    chacha20_block,
    compile_network,
    generate_probe_keys,
    generate_target,
    propagate_candidate,
    run_experiment,
    synthetic_bidirectional_sanity,
    validated_output_path,
)


class AppleView4BidirectionalCarryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ExperimentConfig(probes=2, depths=(0, 30, 31))
        self.target, self.truth = generate_target(self.config)

    def test_rfc_8439_full_round_block_vector(self) -> None:
        self.assertEqual(chacha20_block(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_target_and_probe_generation_are_fixed_and_disjoint(self) -> None:
        self.assertEqual(generate_target(self.config), (self.target, self.truth))
        probes = generate_probe_keys(self.config)
        self.assertEqual(probes, generate_probe_keys(self.config))
        self.assertNotIn(self.truth, probes)

    def test_compile_interface_has_no_candidate_or_truth_input(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(compile_network).parameters),
            ("target", "carry_depth", "meter"),
        )
        for forbidden in ("candidate", "key", "truth"):
            self.assertNotIn(forbidden, inspect.signature(compile_network).parameters)

    def test_network_counts_match_global_carry_depth(self) -> None:
        for depth in (0, 30, 31):
            with self.subTest(depth=depth):
                network = compile_network(self.target, depth)
                self.assertEqual(network.additions, ADDITIONS_PER_BLOCK)
                self.assertEqual(
                    network.majority_constraints, ADDITIONS_PER_BLOCK * depth
                )
                self.assertEqual(
                    network.free_carry_variables,
                    ADDITIONS_PER_BLOCK * (31 - depth),
                )
                self.assertEqual(len(network.key_variables), 256)
                self.assertEqual(len(network.output_variables), 512)

    def test_synthetic_constraint_propagates_backward_and_conflicts(self) -> None:
        self.assertEqual(
            synthetic_bidirectional_sanity(),
            {
                "forced_right_values": [0],
                "forced_right_is_zero": True,
                "setting_right_one_conflicts": True,
            },
        )

    def test_true_key_never_conflicts_at_tested_depths(self) -> None:
        for depth in self.config.depths:
            with self.subTest(depth=depth):
                row = propagate_candidate(
                    compile_network(self.target, depth), self.target, self.truth
                )
                self.assertNotEqual(row["status"], "CONFLICT")

    def test_full_depth_truth_completes_and_wrong_key_conflicts(self) -> None:
        network = compile_network(self.target, 31)
        truth_row = propagate_candidate(network, self.target, self.truth)
        wrong_row = propagate_candidate(
            network, self.target, generate_probe_keys(self.config)[0]
        )
        self.assertEqual(truth_row["status"], "CONSISTENT_COMPLETE")
        self.assertEqual(truth_row["assigned_variables"], network.variable_count)
        self.assertEqual(wrong_row["status"], "CONFLICT")

    def test_small_experiment_is_json_safe_and_explicitly_one_sided(self) -> None:
        result = cast(
            dict[str, Any],
            run_experiment(ExperimentConfig(probes=1, depths=(0, 31))),
        )
        self.assertFalse(result["attacker_boundary"]["unbounded_cdcl_used"])
        self.assertFalse(result["attacker_boundary"]["search_decisions_used"])
        self.assertEqual(result["summary"]["global_key_entropy_reduction_claimed_bits"], 0)
        self.assertIn("not SAT", result["mechanism"]["survivor_semantics"])
        self.assertTrue(result["resources"]["budget_passed"])
        json.dumps(result, allow_nan=False)

    def test_scientific_hash_ignores_dynamic_resources(self) -> None:
        config = ExperimentConfig(probes=1, depths=(0,))
        first = cast(dict[str, Any], run_experiment(config))
        second = cast(dict[str, Any], run_experiment(config))
        self.assertEqual(
            first["reproducibility"]["scientific_payload_sha256"],
            second["reproducibility"]["scientific_payload_sha256"],
        )

    def test_cli_output_is_confined_to_owned_json_files(self) -> None:
        allowed = APPLE_VIEW_4_DIR / "apple_view_4_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_4_DIR.parent / "apple_view_4_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_4_DIR / "result.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_4_DIR / "apple_view_4_result.md")


if __name__ == "__main__":
    unittest.main()
