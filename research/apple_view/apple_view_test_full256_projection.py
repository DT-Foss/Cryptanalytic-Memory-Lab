from __future__ import annotations

import inspect
import json
import unittest

from apple_view_full256_projection import (
    APPLE_VIEW_DIR,
    MASK256,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    EvaluationMeter,
    ExperimentConfig,
    _verify_candidate,
    apply_update_mask,
    chacha20_block_raw,
    generate_cases,
    generated_start,
    project_key,
    projection_chain_search,
    run_experiment,
    validated_output_path,
)


class AppleViewFull256Tests(unittest.TestCase):
    def test_rfc_8439_block_vector(self) -> None:
        self.assertEqual(chacha20_block_raw(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_true_256_bit_key_is_projection_fixed_point(self) -> None:
        config = ExperimentConfig(
            targets=4,
            projection_starts=1,
            projection_steps=1,
            coordinate_targets=0,
            coordinate_steps=0,
        )
        meter = EvaluationMeter()
        case = generate_cases(config, meter)[0]
        self.assertEqual(project_key(case.target, case.secret_key, meter), case.secret_key)

    def test_exact_candidate_requires_both_block_implementations(self) -> None:
        config = ExperimentConfig(
            targets=4,
            projection_starts=1,
            projection_steps=1,
            coordinate_targets=0,
            coordinate_steps=0,
        )
        case = generate_cases(config, EvaluationMeter())[0]
        meter = EvaluationMeter()
        block_match, key_match = _verify_candidate(
            case, case.secret_key, 0, meter
        )
        self.assertTrue(block_match)
        self.assertTrue(key_match)
        self.assertEqual(meter.permutation_evaluations, 1)
        self.assertEqual(meter.lean_block_evaluations, 1)
        self.assertEqual(meter.lean_permutation_only_evaluations, 0)
        self.assertEqual(meter.project_helper_block_evaluations, 1)

    def test_public_search_signature_has_no_secret(self) -> None:
        parameters = inspect.signature(projection_chain_search).parameters
        self.assertNotIn("secret", parameters)
        self.assertNotIn("secret_key", parameters)
        self.assertEqual(
            tuple(parameters), ("target", "start", "steps", "meter")
        )

    def test_deterministic_build_cases_and_full_width_updates(self) -> None:
        config = ExperimentConfig(
            targets=4,
            projection_starts=1,
            projection_steps=1,
            coordinate_targets=0,
            coordinate_steps=0,
        )
        first = generate_cases(config, EvaluationMeter())
        second = generate_cases(config, EvaluationMeter())
        self.assertEqual(first, second)
        start = generated_start(config, first[0].case_id, 0)
        projected = project_key(first[0].target, start, EvaluationMeter())
        self.assertEqual(len(start), 32)
        self.assertEqual(len(projected), 32)
        self.assertEqual(apply_update_mask(start, projected, MASK256), projected)

    def test_small_end_to_end_experiment_preserves_constraints(self) -> None:
        result = run_experiment(
            ExperimentConfig(
                targets=4,
                projection_starts=1,
                projection_steps=2,
                coordinate_targets=1,
                coordinate_steps=1,
            )
        )
        self.assertEqual(result["constraints"]["rounds"], 20)
        self.assertEqual(
            result["constraints"]["unknown_key_bits_seen_by_search"], 256
        )
        self.assertFalse(result["constraints"]["sealed_targets_used"])
        self.assertFalse(result["constraints"]["gpu_or_mps_used"])
        self.assertEqual(result["validation"]["project_helper_cross_checks"], 5)
        self.assertGreater(
            result["resources"]["total_chacha20_core_permutation_evaluations"],
            256,
        )
        json.dumps(result, allow_nan=False)

    def test_cli_output_is_confined_to_apple_view_json(self) -> None:
        allowed = APPLE_VIEW_DIR / "apple_view_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_DIR.parent / "apple_view_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_DIR / "result.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_DIR / "apple_view_result.md")


if __name__ == "__main__":
    unittest.main()
