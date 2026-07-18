from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from o1_crypto_lab import posterior_frontier_run as runner
from o1_crypto_lab.run_capsule import ClaimLevel, RunCapsuleManager


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/posterior_frontier_v1.json"


def _small_burned_spec(*, top_k: int = 16, verification_limit: int = 4) -> dict:
    top, _ = runner.load_posterior_frontier_run_config(CONFIG)
    burned = copy.deepcopy(top["experiment"]["burned"])
    burned["top_k"] = top_k
    burned["public_verification_limit"] = verification_limit
    return burned


class PosteriorFrontierRunConfigTests(unittest.TestCase):
    def test_formal_identity_and_exact_work_budgets(self) -> None:
        top, budgets = runner.load_posterior_frontier_run_config(CONFIG)

        self.assertEqual(top["schema"], runner.RUN_CONFIG_SCHEMA)
        self.assertEqual(top["attempt_id"], runner.ATTEMPT_ID)
        self.assertEqual(top["attempt_id"], "O1C-0024")
        self.assertEqual(top["slug"], runner.FORMAL_SLUG)
        self.assertEqual(top["claim_level"], ClaimLevel.RETROSPECTIVE.value)
        self.assertEqual(top["experiment"]["exhaustive_active_widths"], [3, 6, 10])

        synthetic = top["experiment"]["synthetic"]
        burned = top["experiment"]["burned"]
        self.assertEqual(synthetic["expected_truth_rank"], 4)
        self.assertEqual(synthetic["top_k"], 8)
        self.assertEqual(burned["top_k"], 65_536)
        self.assertEqual(burned["public_verification_limit"], 4_096)
        self.assertEqual(
            synthetic["top_k"] + burned["top_k"],
            budgets.maximum_frontier_candidates,
        )
        self.assertEqual(budgets.maximum_frontier_candidates, 65_544)
        self.assertEqual(budgets.maximum_proof_candidate_evaluations, 2_192)
        self.assertEqual(budgets.maximum_legacy_cube_assignments, 65_540)
        self.assertEqual(budgets.maximum_burned_public_verifications, 4_096)
        self.assertEqual(budgets.maximum_synthetic_public_verifications, 24)
        self.assertEqual(budgets.maximum_source_manifest_reads, 1)
        self.assertEqual(budgets.maximum_source_payload_reads, 5)
        self.assertEqual(budgets.maximum_source_reveal_payload_reads, 1)
        self.assertEqual(budgets.maximum_source_evaluation_payload_reads, 1)
        self.assertEqual(budgets.maximum_other_outcome_payload_reads, 0)
        self.assertEqual(budgets.maximum_full_source_capsule_scans, 0)
        self.assertEqual(budgets.maximum_burned_reveal_reads, 1)
        self.assertEqual(
            budgets.maximum_proof_candidate_evaluations,
            2 * sum(1 << width for width in (3, 6, 10)),
        )
        self.assertEqual(
            budgets.maximum_legacy_cube_assignments,
            (1 << synthetic["legacy_uncertain_bits"]) + (1 << 16),
        )
        for field in (
            "maximum_scientific_entropy_calls",
            "maximum_other_outcome_payload_reads",
            "maximum_full_source_capsule_scans",
            "maximum_native_solver_branches",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        ):
            self.assertEqual(getattr(budgets, field), 0)

    def test_rejects_identity_or_zero_external_work_budget_drift(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            (None, "attempt_id", "O1C-0025"),
            (None, "slug", "changed-frontier"),
            (None, "claim_level", ClaimLevel.VALIDATION.value),
            ("budgets", "maximum_scientific_entropy_calls", 1),
            ("budgets", "maximum_burned_reveal_reads", 0),
            ("budgets", "maximum_native_solver_branches", 1),
            ("budgets", "maximum_source_manifest_reads", 0),
            ("budgets", "maximum_source_payload_reads", 4),
            ("budgets", "maximum_source_reveal_payload_reads", 0),
            ("budgets", "maximum_source_evaluation_payload_reads", 0),
            ("budgets", "maximum_other_outcome_payload_reads", 1),
            ("budgets", "maximum_full_source_capsule_scans", 1),
            ("budgets", "maximum_frontier_candidates", 65_543),
            ("budgets", "maximum_proof_candidate_evaluations", 2_191),
            ("budgets", "maximum_legacy_cube_assignments", 65_539),
            ("budgets", "maximum_burned_public_verifications", 4_095),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field, value=value):
                document = copy.deepcopy(original)
                target = document if section is None else document[section]
                target[field] = value
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "config.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises(runner.PosteriorFrontierRunError):
                        runner.load_posterior_frontier_run_config(path)


class PosteriorFrontierSyntheticTests(unittest.TestCase):
    def test_rank_four_full_round_discriminator_and_public_controls(self) -> None:
        top, _ = runner.load_posterior_frontier_run_config(CONFIG)
        result = runner._synthetic_experiment(top["experiment"]["synthetic"])

        self.assertTrue(result["all_gates_pass"])
        self.assertTrue(all(result["gates"].values()))
        self.assertEqual(result["evaluation"]["true_rank_one_based"], 4)
        self.assertTrue(result["evaluation"]["exact_key_hit"])
        self.assertEqual(
            result["factual_verification"]["first_match_rank_one_based"], 4
        )
        self.assertEqual(result["factual_verification"]["candidates_verified"], 4)
        self.assertFalse(result["legacy_restricted_cube"]["exact_key_in_beam"])
        self.assertEqual(
            result["legacy_restricted_cube"]["uncertain_coordinates"], [0, 1]
        )
        self.assertFalse(result["wrong_nonce_verification"]["exact_match_found"])
        self.assertFalse(result["output_flip_verification"]["exact_match_found"])
        self.assertEqual(result["wrong_nonce_verification"]["candidates_verified"], 8)
        self.assertEqual(result["output_flip_verification"]["candidates_verified"], 8)
        self.assertEqual(result["public_verification_count"], 20)
        self.assertEqual(len(result["candidates"]), 8)
        self.assertEqual(len(result["candidate_keys"]), 8 * 32)
        self.assertEqual(len(result["candidate_scores"]), 8 * 8)
        self.assertFalse(result["frontier_index"]["truth_used_for_generation"])
        self.assertEqual(
            [candidate.flipped_coordinates for candidate in result["candidates"][:4]],
            [(), (0,), (1,), (2,)],
        )


class PosteriorFrontierBurnedBoundaryTests(unittest.TestCase):
    def test_pre_reveal_small_frontier_never_reads_reveal_or_evaluation(self) -> None:
        burned = _small_burned_spec()
        original_read_regular = runner._read_regular_beneath
        relative_reads: list[str] = []

        def recording_no_follow_read(
            directory: Path, relative: str, field: str
        ) -> bytes:
            relative_reads.append(relative)
            if Path(relative).name in {"reveal.json", "evaluation.json"}:
                raise AssertionError(f"pre-reveal boundary read {relative}")
            return original_read_regular(directory, relative, field)

        with (
            mock.patch.object(
                runner, "_read_regular_beneath", new=recording_no_follow_read
            ),
            mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("ordinary Path.read_bytes source read"),
            ),
        ):
            pre = runner._burned_pre_reveal(ROOT, burned)

        self.assertEqual(pre["semantic_reveal_reads"], 0)
        self.assertEqual(pre["source_manifest_reads"], 1)
        self.assertEqual(pre["source_payload_reads"], 3)
        self.assertEqual(pre["source_reveal_payload_reads"], 0)
        self.assertEqual(pre["source_evaluation_payload_reads"], 0)
        self.assertEqual(pre["other_outcome_payload_reads"], 0)
        self.assertEqual(pre["full_source_capsule_scans"], 0)
        self.assertEqual(len(pre["candidates"]), 16)
        self.assertEqual(len(pre["candidate_keys"]), 16 * 32)
        self.assertEqual(len(pre["candidate_scores"]), 16 * 8)
        self.assertEqual(pre["probabilities"].shape, (256,))
        self.assertEqual(pre["frontier_index"]["candidate_count"], 16)
        self.assertFalse(pre["frontier_index"]["truth_used_for_generation"])
        self.assertEqual(
            [Path(relative).name for relative in relative_reads],
            [
                "artifacts.sha256",
                "publication.json",
                "probabilities.f64le",
                "prediction_freeze.json",
            ],
        )
        source_index = pre["source_manifest_index"]
        self.assertEqual(source_index["manifest_payload_reads"], 1)
        self.assertEqual(source_index["selected_member_count"], 5)
        self.assertEqual(source_index["full_capsule_scans"], 0)
        self.assertEqual(
            set(source_index["selected_members"]), set(pre["paths"].values())
        )

    def test_selected_source_reader_rejects_final_and_intermediate_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_directory = root / "real"
            real_directory.mkdir()
            member = real_directory / "member.bin"
            member.write_bytes(b"selected-source")
            final_link = real_directory / "final-link.bin"
            final_link.symlink_to(member)
            directory_link = root / "directory-link"
            directory_link.symlink_to(real_directory, target_is_directory=True)

            self.assertEqual(
                runner._read_regular_beneath(
                    root, "real/member.bin", "regular selected member"
                ),
                b"selected-source",
            )
            with self.assertRaisesRegex(
                runner.PosteriorFrontierRunError, "without links"
            ):
                runner._read_regular_beneath(
                    root, "real/final-link.bin", "linked selected member"
                )
            with self.assertRaisesRegex(
                runner.PosteriorFrontierRunError, "without links"
            ):
                runner._read_regular_beneath(
                    root, "directory-link/member.bin", "linked selected directory"
                )
            for unsafe in ("../member.bin", "/member.bin", "real/../member.bin"):
                with (
                    self.subTest(unsafe=unsafe),
                    self.assertRaisesRegex(runner.PosteriorFrontierRunError, "unsafe"),
                ):
                    runner._read_regular_beneath(root, unsafe, "unsafe member")

    def test_prediction_freeze_records_zero_pre_freeze_reveal_reads(self) -> None:
        burned = _small_burned_spec()
        pre = runner._burned_pre_reveal(ROOT, burned)
        freeze = runner._prediction_freeze_document(burned, pre)

        self.assertEqual(freeze["schema"], runner.PREDICTION_FREEZE_SCHEMA)
        self.assertEqual(
            freeze["phase"], "GLOBAL_TOPK_FROZEN_BEFORE_BURNED_REVEAL_READ"
        )
        self.assertEqual(freeze["semantic_reveal_reads_before_freeze"], 0)
        self.assertFalse(freeze["truth_used_for_generation"])
        self.assertEqual(freeze["candidate_count"], 16)
        self.assertEqual(
            freeze["source_manifest_sha256"],
            burned["capsule_manifest_sha256"],
        )
        self.assertEqual(
            freeze["artifact_commitments"]["burned/candidates.bin"]["sha256"],
            pre["frontier_index"]["keys_sha256"],
        )
        self.assertEqual(
            freeze["artifact_commitments"]["burned/scores.f64le"]["sha256"],
            pre["frontier_index"]["scores_sha256"],
        )
        self.assertEqual(
            freeze["artifact_commitments"]["burned/frontier_index.json"]["sha256"],
            runner._sha256(pre["frontier_index_payload"]),
        )
        self.assertEqual(
            freeze["artifact_commitments"]["burned/source_manifest_index.json"][
                "sha256"
            ],
            runner._sha256(pre["source_manifest_index_payload"]),
        )
        unsigned = {
            key: value for key, value in freeze.items() if key != "freeze_sha256"
        }
        self.assertEqual(
            freeze["freeze_sha256"], runner._sha256(runner._canonical_json(unsigned))
        )

    def test_post_reveal_uses_selected_reads_callbacks_and_exact_accounting(
        self,
    ) -> None:
        burned = _small_burned_spec()
        pre = runner._burned_pre_reveal(ROOT, burned)
        original_read_verified = runner._read_verified
        events: list[str] = []

        def recording_read(
            capsule: Path,
            relative: str,
            expected_sha256: str,
            field: str,
        ) -> bytes:
            events.append(f"read:{field}")
            return original_read_verified(capsule, relative, expected_sha256, field)

        with (
            mock.patch.object(runner, "_read_verified", new=recording_read),
            mock.patch.object(
                RunCapsuleManager,
                "verify",
                side_effect=AssertionError("full source capsule scan"),
            ) as full_scan,
        ):
            result = runner._burned_post_reveal(
                burned,
                pre,
                on_reveal_read_started=lambda: events.append("reveal:start"),
                on_reveal_read_completed=lambda: events.append("reveal:complete"),
                on_evaluation_read_started=lambda: events.append("evaluation:start"),
                on_evaluation_read_completed=lambda: events.append(
                    "evaluation:complete"
                ),
            )

        full_scan.assert_not_called()
        self.assertEqual(
            events,
            [
                "reveal:start",
                "read:burned reveal",
                "reveal:complete",
                "evaluation:start",
                "read:burned evaluation",
                "evaluation:complete",
            ],
        )
        self.assertEqual(result["semantic_reveal_reads"], 1)
        self.assertEqual(result["source_manifest_reads"], 1)
        self.assertEqual(result["source_payload_reads"], 5)
        self.assertEqual(result["source_reveal_payload_reads"], 1)
        self.assertEqual(result["source_evaluation_payload_reads"], 1)
        self.assertEqual(result["other_outcome_payload_reads"], 0)
        self.assertEqual(result["full_source_capsule_scans"], 0)
        self.assertEqual(result["source_selected_members_verified"], 5)
        self.assertEqual(
            result["source_capsule_manifest_sha256"],
            burned["capsule_manifest_sha256"],
        )
        self.assertEqual(result["global_frontier"]["candidate_count"], 16)
        self.assertFalse(result["global_frontier"]["exact_key_hit"])
        self.assertIsNone(result["global_frontier"]["true_rank_one_based"])
        self.assertEqual(result["global_frontier"]["best_hamming_distance"], 115)
        self.assertEqual(result["public_verification_prefix"]["candidates_verified"], 4)
        self.assertTrue(
            result["public_verification_prefix"]["verification_limit_reached"]
        )
        self.assertFalse(result["public_verification_prefix"]["exact_match_found"])
        self.assertEqual(result["recomputed_correct_bits"], 139)
        self.assertAlmostEqual(result["recomputed_compression_bits"], 0.506129537281879)
        self.assertTrue(result["diagnostic_only"])
        self.assertFalse(result["reader_fit_or_selection"])
        self.assertFalse(result["fresh_target_or_entropy"])

    def test_post_reveal_rejects_cross_bound_publication_and_evaluation(self) -> None:
        burned = _small_burned_spec(top_k=4, verification_limit=2)
        pre = runner._burned_pre_reveal(ROOT, burned)

        wrong_publication_pre = dict(pre)
        wrong_publication_pre["publication"] = {
            **pre["publication"],
            "target_id": "cross-bound-target",
        }
        with self.assertRaisesRegex(
            runner.PosteriorFrontierRunError,
            "reveal publication differs from the frozen public input",
        ):
            runner._burned_post_reveal(burned, wrong_publication_pre)

        original_read_verified = runner._read_verified

        def cross_bound_evaluation(
            capsule: Path,
            relative: str,
            expected_sha256: str,
            field: str,
        ) -> bytes:
            payload = original_read_verified(capsule, relative, expected_sha256, field)
            if field != "burned evaluation":
                return payload
            document = json.loads(payload.decode("utf-8"))
            document["reveal_sha256"] = "0" * 64
            return json.dumps(document).encode("utf-8")

        with (
            mock.patch.object(runner, "_read_verified", new=cross_bound_evaluation),
            self.assertRaisesRegex(
                runner.PosteriorFrontierRunError,
                "burned evaluation identity differs",
            ),
        ):
            runner._burned_post_reveal(burned, pre)


class PosteriorFrontierRecoveryAccountingTests(unittest.TestCase):
    def test_checkpoint_read_accounting_for_every_phase_and_unknown_payloads(
        self,
    ) -> None:
        cases = (
            (None, "NO_CHECKPOINT", 0, 0, True),
            (
                {"phase": runner.PHASE_FRONTIER_FROZEN},
                runner.PHASE_FRONTIER_FROZEN,
                0,
                0,
                True,
            ),
            (
                {"phase": runner.PHASE_REVEAL_READ_STARTED},
                runner.PHASE_REVEAL_READ_STARTED,
                1,
                0,
                True,
            ),
            (
                {"phase": runner.PHASE_REVEAL_READ_COMPLETED},
                runner.PHASE_REVEAL_READ_COMPLETED,
                1,
                0,
                True,
            ),
            (
                {"phase": runner.PHASE_EVALUATION_READ_STARTED},
                runner.PHASE_EVALUATION_READ_STARTED,
                1,
                1,
                True,
            ),
            (
                {"phase": runner.PHASE_EVALUATION_READ_COMPLETED},
                runner.PHASE_EVALUATION_READ_COMPLETED,
                1,
                1,
                True,
            ),
            ({"phase": "FUTURE_PHASE"}, "FUTURE_PHASE", None, None, False),
            ({}, "UNKNOWN", None, None, False),
            ([], "UNKNOWN", None, None, False),
        )
        for payload, phase, reveal_reads, evaluation_reads, known in cases:
            with self.subTest(phase=phase, payload=payload):
                accounting = runner._checkpoint_read_accounting(payload)
                self.assertEqual(accounting["checkpoint_phase"], phase)
                self.assertEqual(
                    accounting["source_reveal_payload_reads"], reveal_reads
                )
                self.assertEqual(
                    accounting["source_evaluation_payload_reads"], evaluation_reads
                )
                self.assertIs(accounting["read_accounting_known"], known)

    def test_operational_budget_failure_overrides_scientific_success(self) -> None:
        self.assertEqual(
            runner._final_classification(
                science_pass=True, burned_hit=False, failed_budgets=()
            ),
            runner.SUCCESS_NULL,
        )
        self.assertEqual(
            runner._final_classification(
                science_pass=True, burned_hit=True, failed_budgets=()
            ),
            runner.SUCCESS_RETROSPECTIVE_HIT,
        )
        self.assertEqual(
            runner._final_classification(
                science_pass=False, burned_hit=True, failed_budgets=()
            ),
            runner.FAILURE,
        )
        for science_pass, burned_hit in (
            (True, False),
            (True, True),
            (False, False),
        ):
            with self.subTest(science_pass=science_pass, burned_hit=burned_hit):
                self.assertEqual(
                    runner._final_classification(
                        science_pass=science_pass,
                        burned_hit=burned_hit,
                        failed_budgets=("cpu",),
                    ),
                    runner.OPERATIONAL_BUDGET_FAILURE,
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
