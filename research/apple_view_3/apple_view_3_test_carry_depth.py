from __future__ import annotations

import inspect
import json
import unittest
from typing import Any, cast

from apple_view_3_carry_depth import (
    APPLE_VIEW_3_DIR,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    UNKNOWN,
    ExperimentConfig,
    _derive,
    abstract_chacha20_block,
    chacha20_block,
    concrete_word,
    generate_probe_keys,
    generate_target,
    run_experiment,
    score_probe,
    tri_add_words,
    tri_majority,
    tri_xor,
    validated_output_path,
)


class AppleView3CarryDepthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ExperimentConfig(probes=2)
        self.target, self.truth = generate_target(self.config)

    def test_rfc_8439_full_round_block_vector(self) -> None:
        self.assertEqual(chacha20_block(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_target_and_probe_generation_are_fixed_and_output_independent(self) -> None:
        self.assertEqual(generate_target(self.config), (self.target, self.truth))
        probes = generate_probe_keys(self.config)
        self.assertEqual(probes, generate_probe_keys(self.config))
        self.assertEqual(
            probes[0],
            _derive(self.config.seed, "output-independent-probe-key", 0, 32),
        )
        self.assertNotIn(self.truth, probes)

    def test_three_valued_gates_are_sound_for_all_completions(self) -> None:
        values = (0, 1, UNKNOWN)
        self.assertEqual(tri_xor(UNKNOWN, 0), UNKNOWN)
        self.assertEqual(tri_xor(1, 0), 1)
        self.assertEqual(tri_majority(0, 0, UNKNOWN), 0)
        self.assertEqual(tri_majority(1, UNKNOWN, 1), 1)
        self.assertEqual(tri_majority(0, 1, UNKNOWN), UNKNOWN)
        for a in values:
            for b in values:
                for c in values:
                    abstract = tri_majority(a, b, c)
                    if abstract == UNKNOWN:
                        continue
                    completions = [
                        ((aa & bb) | (aa & cc) | (bb & cc))
                        for aa in ((0, 1) if a == UNKNOWN else (a,))
                        for bb in ((0, 1) if b == UNKNOWN else (b,))
                        for cc in ((0, 1) if c == UNKNOWN else (c,))
                    ]
                    self.assertTrue(all(value == abstract for value in completions))

    def test_abstract_addition_restores_exact_known_prefix(self) -> None:
        left = 0x89ABCDEF
        right = 0x76543210
        concrete = (left + right) & 0xFFFFFFFF
        for depth in range(32):
            with self.subTest(depth=depth):
                abstract = tri_add_words(
                    concrete_word(left), concrete_word(right), depth
                )
                expected_known = 32 if depth == 31 else depth + 1
                self.assertEqual(
                    sum(value != UNKNOWN for value in abstract), expected_known
                )
                for bit, value in enumerate(abstract):
                    if value != UNKNOWN:
                        self.assertEqual(value, (concrete >> bit) & 1)

    def test_depth_31_equals_concrete_full_round_for_fixed_keys(self) -> None:
        for index in range(3):
            key = _derive(self.config.seed, "full-depth-check", index, 32)
            abstract = abstract_chacha20_block(
                key, self.target.counter, self.target.nonce, 31
            )
            concrete = chacha20_block(
                key, self.target.counter, self.target.nonce
            )
            concrete_bits = tuple(
                (byte >> bit) & 1 for byte in concrete for bit in range(8)
            )
            self.assertEqual(abstract, concrete_bits)

    def test_fixed_reference_loses_all_forward_known_bits_below_full_depth(self) -> None:
        for depth in (0, 1, 8, 16, 24, 30):
            with self.subTest(depth=depth):
                abstract = abstract_chacha20_block(
                    self.truth, self.target.counter, self.target.nonce, depth
                )
                self.assertEqual(sum(value != UNKNOWN for value in abstract), 0)

    def test_truth_is_never_rejected_and_wrong_full_depth_key_is(self) -> None:
        wrong = generate_probe_keys(self.config)[0]
        for depth in range(32):
            with self.subTest(depth=depth):
                self.assertFalse(
                    score_probe(self.target, self.truth, depth)["rejected_exactly"]
                )
        wrong_score = score_probe(self.target, wrong, 31)
        self.assertEqual(wrong_score["determined_output_bits"], 512)
        self.assertTrue(wrong_score["rejected_exactly"])

    def test_probe_scoring_signature_has_no_truth_parameter(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(score_probe).parameters),
            ("target", "candidate_key", "carry_depth", "meter"),
        )
        self.assertNotIn("truth", inspect.signature(score_probe).parameters)

    def test_small_experiment_is_json_safe_and_explicitly_one_sided(self) -> None:
        result = cast(
            dict[str, Any], run_experiment(ExperimentConfig(probes=2, max_depth=2))
        )
        self.assertEqual(
            result["attacker_boundary"]["unknown_key_bits_in_base_problem"], 256
        )
        self.assertFalse(result["attacker_boundary"]["truth_key_input_to_probe_scoring"])
        self.assertFalse(
            result["attacker_boundary"]["truth_key_input_to_probe_generation"]
        )
        self.assertTrue(result["resources"]["budget_passed"])
        self.assertIn("does not prove SAT", result["mechanism"]["one_sided_rule"])
        json.dumps(result, allow_nan=False)

    def test_scientific_hash_ignores_dynamic_resource_measurements(self) -> None:
        config = ExperimentConfig(probes=1, max_depth=1)
        first = cast(dict[str, Any], run_experiment(config))
        second = cast(dict[str, Any], run_experiment(config))
        self.assertEqual(
            first["reproducibility"]["scientific_payload_sha256"],
            second["reproducibility"]["scientific_payload_sha256"],
        )
        self.assertTrue(
            first["reproducibility"][
                "dynamic_resource_fields_excluded_from_scientific_hash"
            ]
        )

    def test_cli_output_is_confined_to_owned_json_files(self) -> None:
        allowed = APPLE_VIEW_3_DIR / "apple_view_3_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_3_DIR.parent / "apple_view_3_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_3_DIR / "result.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_3_DIR / "apple_view_3_result.md")


if __name__ == "__main__":
    unittest.main()
