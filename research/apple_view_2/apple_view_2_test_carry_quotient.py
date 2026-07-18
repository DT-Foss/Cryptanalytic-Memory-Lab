from __future__ import annotations

import inspect
import json
import unittest
from typing import Any, cast

from apple_view_2_carry_quotient import (
    ALL_FREE_CONTROL,
    APPLE_VIEW_2_DIR,
    NO_CARRY_CONTROL,
    PRIMARY_MODE,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    ExperimentConfig,
    _eliminate_carries,
    _rref_key_equations,
    chacha20_block,
    compile_lifted_system,
    extract_key_information,
    generate_cases,
    run_experiment,
    score_extraction,
    synthetic_elimination_sanity,
    validate_lifted_addition,
    validated_output_path,
)


class AppleView2CarryQuotientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ExperimentConfig(targets=1, addition_identity_checks=8)
        self.case = generate_cases(self.config)[0]

    def test_rfc_8439_full_round_block_vector(self) -> None:
        self.assertEqual(chacha20_block(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_target_generation_is_fixed_and_unsealed(self) -> None:
        first = generate_cases(self.config)
        second = generate_cases(self.config)
        self.assertEqual(first, second)
        self.assertEqual(len(first[0].measurement_key), 32)
        self.assertEqual(len(first[0].target.block), 64)
        self.assertEqual(
            chacha20_block(
                first[0].measurement_key,
                first[0].target.counter,
                first[0].target.nonce,
            ),
            first[0].target.block,
        )

    def test_public_extraction_signature_has_no_truth_or_intermediate_input(self) -> None:
        parameters = inspect.signature(extract_key_information).parameters
        self.assertEqual(tuple(parameters), ("target", "carry_mode", "meter"))
        for forbidden in ("secret", "truth", "key", "carries", "intermediate"):
            self.assertNotIn(forbidden, parameters)

    def test_lifted_adder_accepts_real_carries_exactly(self) -> None:
        self.assertEqual(validate_lifted_addition(self.config.seed, 128), 128)

    def test_synthetic_elimination_exposes_one_key_parity(self) -> None:
        self.assertEqual(
            synthetic_elimination_sanity(),
            {
                "input_equations": 2,
                "carry_rank": 1,
                "surviving_key_relations": 1,
                "key_information_rank_bits": 1,
            },
        )
        carry_rank, equations = _eliminate_carries(
            ((1, 1 << 4, 1), (1, 1 << 9, 0))
        )
        basis, inconsistent = _rref_key_equations(equations)
        self.assertEqual(carry_rank, 1)
        self.assertEqual(equations, (((1 << 4) | (1 << 9), 1),))
        self.assertEqual(len(basis), 1)
        self.assertEqual(inconsistent, 0)

    def test_full_block_circuit_has_expected_addition_and_carry_counts(self) -> None:
        expected_carries = {
            PRIMARY_MODE: 336 * 31,
            ALL_FREE_CONTROL: 336 * 32,
            NO_CARRY_CONTROL: 0,
        }
        for mode, expected in expected_carries.items():
            with self.subTest(mode=mode):
                system = compile_lifted_system(self.case.target, mode)
                self.assertEqual(len(system.rows), 512)
                self.assertEqual(len(system.addition_carry_ranges), 336)
                self.assertEqual(system.carry_variables, expected)

    def test_primary_full_round_quotient_is_vacuous_on_reference_target(self) -> None:
        extraction = extract_key_information(self.case.target, PRIMARY_MODE)
        self.assertEqual(extraction.summary["carry_coefficient_rank"], 512)
        self.assertEqual(extraction.summary["relations_after_carry_elimination"], 0)
        self.assertEqual(extraction.summary["key_information_rank_bits"], 0)
        self.assertEqual(extraction.summary["exact_key_bits_recovered"], 0)
        self.assertIsNone(extraction.candidate_key)
        scored = score_extraction(extraction, self.case)
        self.assertTrue(scored["all_emitted_relations_hold_for_truth"])
        self.assertEqual(
            scored["lifted_output_equations_satisfied_by_real_assignment"], 512
        )
        self.assertTrue(scored["real_assignment_satisfies_entire_lifted_system"])
        self.assertFalse(scored["exact_key_recovered_and_block_verified"])

    def test_no_carry_control_cannot_masquerade_as_exact_information(self) -> None:
        extraction = extract_key_information(self.case.target, NO_CARRY_CONTROL)
        self.assertFalse(extraction.summary["model_is_exact_relaxation"])
        self.assertEqual(extraction.summary["key_information_rank_bits"], 256)
        self.assertGreater(
            cast(int, extraction.summary["inconsistent_key_only_rows"]), 0
        )
        self.assertEqual(extraction.summary["exact_key_bits_recovered"], 0)
        self.assertEqual(extraction.summary["unit_key_bits_suggested_by_model"], 256)
        scored = score_extraction(extraction, self.case)
        self.assertLess(
            cast(int, scored["truth_key_equations_satisfied"]),
            cast(int, scored["truth_key_equations_total"]),
        )

    def test_small_experiment_is_json_safe_and_within_fixed_boundary(self) -> None:
        result = cast(dict[str, Any], run_experiment(self.config))
        self.assertEqual(result["attacker_boundary"]["unknown_key_bits"], 256)
        self.assertEqual(result["attacker_boundary"]["blocks_per_attack"], 1)
        self.assertFalse(result["attacker_boundary"]["truth_key_input_to_extraction"])
        self.assertFalse(result["attacker_boundary"]["key_enumeration"])
        self.assertTrue(result["resources"]["budget_passed"])
        self.assertEqual(
            result["matched_arms"][PRIMARY_MODE]["key_information_rank_max_bits"],
            0,
        )
        self.assertEqual(
            result["matched_arms"][NO_CARRY_CONTROL]["exact_key_bits_recovered"],
            0,
        )
        self.assertIn("measurement_key_hex_unsealed", result["targets"][0])
        json.dumps(result, allow_nan=False)

    def test_cli_output_is_confined_to_owned_json_files(self) -> None:
        allowed = APPLE_VIEW_2_DIR / "apple_view_2_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_2_DIR.parent / "apple_view_2_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_2_DIR / "result.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_2_DIR / "apple_view_2_result.md")


if __name__ == "__main__":
    unittest.main()
