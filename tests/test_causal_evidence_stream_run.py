from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Callable
from unittest import mock

from o1_crypto_lab import causal_evidence_stream_run as runner


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/causal_evidence_stream_256_v1.json"


def _commitments(payloads: dict[str, bytes]) -> dict[str, object]:
    return {
        name: {"sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
        for name, value in sorted(payloads.items())
    }


def _freeze(
    *,
    schema: str,
    phase: str,
    freeze_path: str,
    payloads: dict[str, bytes],
    extra: dict[str, object],
) -> tuple[dict[str, bytes], dict[str, object]]:
    document = {
        "schema": schema,
        "phase": phase,
        **extra,
        "artifact_commitments": _commitments(payloads),
    }
    document["freeze_sha256"] = hashlib.sha256(
        runner._canonical_json(document)
    ).hexdigest()
    artifacts = dict(payloads)
    artifacts[freeze_path] = runner._canonical_json(document)
    return artifacts, document


class _FakeRun:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.publication_prepared = False
        self.finalize_calls: list[dict[str, object]] = []
        self.stderr: list[str] = []

    def write_artifact(self, relative: str, payload: bytes) -> Path:
        path = self.root / "artifacts" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def checkpoint(self, _payload: object) -> Path:
        return self.root / "checkpoint.json"

    def append_stdout(self, _value: object) -> None:
        return None

    def append_stderr(self, value: object) -> None:
        self.stderr.append(str(value))

    def finalize(self, **kwargs: object) -> SimpleNamespace:
        self.finalize_calls.append(dict(kwargs))
        return SimpleNamespace(
            attempt_id="O1C-0021",
            path=self.root,
            manifest_sha256="f" * 64,
            verification=SimpleNamespace(ok=True),
        )


def _result(classification: str) -> SimpleNamespace:
    success = classification == runner._SUCCESS_CLASSIFICATION
    score_gates = {
        name: True for name in runner._SCORE_INTEGRITY_GATE_NAMES
    }
    score_gates["terminal"] = success
    if classification == "TRUTH_PATH_LEAKAGE":
        score_gates["zero_prior_baseline_exact_null"] = False
    scores = {
        "schema": "o1-256-causal-evidence-recomputed-scores-v1",
        "classification": classification,
        "success_gate_passed": success,
        "gates": score_gates,
        "failed_gates": sorted(
            name for name, passed in score_gates.items() if not passed
        ),
        "metrics_sha256": "a" * 64,
    }
    execution_gates = {
        name: True for name in runner._EXECUTION_INTEGRITY_GATE_NAMES
    }
    if classification == "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE":
        execution_gates["fresh_post_learning_evaluation_material"] = False
    gates = {**score_gates, **execution_gates}
    report: dict[str, object] = {
        "schema": runner.RESULT_SCHEMA,
        "classification": classification,
        "success_gate_passed": success,
        "gates": gates,
        "failed_gates": sorted(
            name for name, passed in gates.items() if not passed
        ),
        "scores": scores,
        "state": {
            "total_live_state_bytes": 352,
            "stream_length_dependent_model_state": False,
        },
        "work": {
            "physical_public_tokens": 1,
            "gate_token_evaluations": 1,
            "coefficient_query_tokens": 1,
            "core_marker_updates": 0,
            "current_marker_control_updates": 0,
            "accepted_update_opportunities": 1,
            "public_fsm_table_lookups": 1,
            "logical_arm_updates": len(runner.ALL_ARMS),
            "calibration_physical_public_tokens": 1,
            "calibration_reader_token_evaluations": 1,
            "temperature_grid_value_evaluations": 1,
            "training_token_exposures": 1,
            "public_fsm_build_outcome_lookups": 262_144,
            "public_fsm_calibration_table_lookups": 524_288,
            "public_fsm_evaluation_table_lookups": 1_835_008,
            "scientific_entropy_calls": 1,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "native_solver_branches": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        },
    }
    report["result_sha256"] = hashlib.sha256(
        runner._canonical_json(report)
    ).hexdigest()
    return SimpleNamespace(report=report, success_gate_passed=success)


def _science(
    result: SimpleNamespace,
    events: list[str],
):
    def execute(config: object, **kwargs: object) -> SimpleNamespace:
        learning_payloads = {
            "learning/primary_slow_state.bin": b"primary",
            "learning/shuffled_confidence_slow_state.bin": b"shuffled",
            "learning/outcome_public_fsm.i8": bytes(64),
            "learning/calibration.json": b"{}\n",
        }
        learning_artifacts, learning_document = _freeze(
            schema=runner.LEARNING_FREEZE_SCHEMA,
            phase="ALL_SLOW_STATES_FROZEN_BEFORE_EVALUATION_LEDGER_GENERATION",
            freeze_path="learning/learning_freeze.json",
            payloads=learning_payloads,
            extra={
                "evaluation_ledgers_generated": 0,
                "evaluation_tokens_seen": 0,
                "evaluation_slow_updates": 0,
                "outcome_public_fsm_sha256": hashlib.sha256(bytes(64)).hexdigest(),
            },
        )
        kwargs["on_learning_frozen"](learning_artifacts, learning_document)
        events.append("learning")
        materials, entropy_calls = kwargs["evaluation_material_provider"](
            config.evaluation_seeds
        )
        events.append("entropy")
        material_commitments = {
            str(seed): hashlib.sha256(materials[seed]).hexdigest()
            for seed in config.evaluation_seeds
        }
        prediction_payloads = {
            "prediction/evaluation_predictions.f32le": b"predictions",
            "prediction/evaluation_predictions_index.json": b"{}\n",
            "prediction/evaluation_receipts.json": b"{}\n",
        }
        variants = (
            "base",
            *(f"duplicate_r{factor}" for factor in config.repeat_factors[1:]),
            "complement",
            "id_permutation",
            "coordinate_permutation",
        )
        for seed in config.evaluation_seeds:
            for variant in variants:
                prediction_payloads[
                    f"prediction/routes/{variant}_{seed}.bitpack"
                ] = b"route"
                prediction_payloads[
                    f"prediction/states/{variant}_{seed}.bin"
                ] = bytes(config.live_state_bytes)
                prediction_payloads[
                    f"prediction/fsm_states/{variant}_{seed}.bin"
                ] = bytes(config.n_bits + 17)
        prediction_artifacts, prediction_document = _freeze(
            schema=runner.PREDICTION_FREEZE_SCHEMA,
            phase="ALL_EVALUATION_PREDICTIONS_FROZEN_BEFORE_TRUTH_REVEAL",
            freeze_path="prediction/prediction_freeze.json",
            payloads=prediction_payloads,
            extra={
                "parent_learning_freeze_sha256": learning_document[
                    "freeze_sha256"
                ],
                "truth_ledger_count": 4 * len(config.evaluation_seeds),
                "truth_ledger_reveal_count": 0,
                "scorer_calls": 0,
                "evaluation_slow_updates": 0,
                "evaluation_seeds": list(config.evaluation_seeds),
                "prefixes": list(config.independent_group_prefixes),
                "arms": list(runner.ALL_ARMS),
                "repeat_factors": list(config.repeat_factors),
                "transforms": [
                    "complement",
                    "id_permutation",
                    "coordinate_permutation",
                ],
                "prediction_value_count": config.prediction_value_count,
                "secret_material_commitments": material_commitments,
                "entropy_calls": entropy_calls,
            },
        )
        kwargs["on_predictions_frozen"](
            prediction_artifacts, prediction_document
        )
        events.append("prediction")
        truth_payloads = {
            "truth/evaluation_truth.bitpack": b"truth",
            "truth/evaluation_truth_index.json": b"{}\n",
            "truth/evaluation_secret_material.bin": b"materials",
            "truth/evaluation_secret_material_index.json": b"{}\n",
        }
        truth_artifacts, truth_document = _freeze(
            schema=runner.TRUTH_REVEAL_SCHEMA,
            phase=(
                "RAW_EVALUATION_TRUTH_PERSISTED_AFTER_PREDICTION_FREEZE_BEFORE_SCORING"
            ),
            freeze_path="truth/truth_reveal.json",
            payloads=truth_payloads,
            extra={
                "parent_prediction_freeze_sha256": prediction_document[
                    "freeze_sha256"
                ],
                "truth_ledger_count": 4 * len(config.evaluation_seeds),
                "truth_ledger_reveal_count_per_ledger": 1,
                "total_truth_ledgers_revealed": 4
                * len(config.evaluation_seeds),
                "scorer_calls": 0,
                "bitorder": "little",
                "secret_material_commitments": material_commitments,
            },
        )
        kwargs["on_truth_revealed_before_scoring"](
            truth_artifacts, truth_document
        )
        events.append("truth")
        return result

    return execute


class CausalEvidenceRunConfigTests(unittest.TestCase):
    def test_formal_shape_and_exact_derived_work(self) -> None:
        top, experiment, budgets = runner.load_causal_evidence_run_config(CONFIG)
        self.assertEqual(top["schema"], runner.RUN_CONFIG_SCHEMA)
        self.assertEqual(top["attempt_id"], "O1C-0021")
        self.assertEqual(top["claim_level"], "VALIDATION")
        self.assertEqual(experiment.n_bits, 256)
        self.assertEqual(experiment.quality_reliabilities, (0.62, 0.70))
        self.assertEqual(experiment.coefficient_magnitudes, (1, 2))
        self.assertEqual(experiment.independent_group_prefixes, (1, 4, 16, 64, 256))
        self.assertEqual(experiment.repeat_factors, (1, 4, 16, 64))
        self.assertEqual(experiment.live_state_bytes, 352)
        self.assertEqual(experiment.core_config.fast_state_bytes(), 80)
        self.assertEqual(experiment.planned_public_tokens, 46_227_456)
        self.assertEqual(experiment.planned_reader_token_evaluations, 53_588_992)
        self.assertEqual(experiment.planned_calibration_public_tokens, 1_050_624)
        self.assertEqual(
            experiment.planned_calibration_reader_token_evaluations, 3_153_920
        )
        self.assertEqual(experiment.planned_training_token_exposures, 15_974_400)
        self.assertEqual(
            experiment.planned_public_fsm_build_outcome_lookups, 262_144
        )
        self.assertEqual(
            experiment.planned_public_fsm_calibration_table_lookups, 524_288
        )
        self.assertEqual(
            experiment.planned_public_fsm_evaluation_table_lookups, 1_835_008
        )
        self.assertEqual(experiment.planned_arm_token_updates, 462_274_560)
        self.assertEqual(experiment.prediction_value_count, 358_400)
        self.assertEqual(budgets.maximum_accepted_arm_updates, 18_350_080)
        self.assertEqual(budgets.maximum_temperature_grid_value_evaluations, 24_657_920)
        self.assertEqual(budgets.maximum_scientific_entropy_calls, 1)

    def test_rejects_formal_mutations_and_work_drift(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            ("experiment", "n_bits", 128),
            ("experiment", "model_dimension", 25),
            ("experiment", "independent_group_prefixes", [1, 4, 16, 64]),
            ("experiment", "training_steps", 479),
            ("experiment", "core_seed", 210022),
            ("experiment", "evaluation_seeds", [210021301, 210021302, 210021303, 9]),
            ("budgets", "maximum_live_state_bytes", 353),
            ("budgets", "maximum_cpu_seconds", 301),
            ("budgets", "maximum_physical_public_tokens", 46_227_455),
            ("budgets", "maximum_public_fsm_build_outcome_lookups", 262_143),
            ("budgets", "maximum_scientific_entropy_calls", 0),
            ("budgets", "maximum_gpu_calls", 1),
            (None, "attempt_id", "O1C-0022"),
            (None, "claim_level", "SOTA"),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                document = json.loads(json.dumps(original))
                if section is None:
                    document[field] = value
                else:
                    document[section][field] = value
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "config.json"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    with self.assertRaises((runner.CausalEvidenceRunError, ValueError)):
                        runner.load_causal_evidence_run_config(path)

    def test_rejects_overlapping_splits_and_control_inventory_change(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        overlap = json.loads(json.dumps(original))
        overlap["experiment"]["evaluation_seeds"][0] = overlap["experiment"][
            "development_seeds"
        ][0]
        controls = json.loads(json.dumps(original))
        controls["controls"].pop()
        for document in (overlap, controls):
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "config.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(ValueError):
                    runner.load_causal_evidence_run_config(path)

    def test_external_config_rejected_before_manager_or_science(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "copied.json"
            copied.write_bytes(CONFIG.read_bytes())
            with (
                mock.patch.object(runner, "RunCapsuleManager") as manager,
                mock.patch.object(runner, "run_causal_evidence_stream") as science,
            ):
                with self.assertRaisesRegex(
                    runner.CausalEvidenceRunError, "canonical tracked config"
                ):
                    runner.run_capsule_from_config(copied)
                manager.assert_not_called()
                science.assert_not_called()


class CausalEvidenceRunLifecycleTests(unittest.TestCase):
    def test_finalized_attempt_returns_without_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            (capsule / "metrics.json").write_text(
                json.dumps({"status": "completed"}), encoding="utf-8"
            )
            manager = mock.Mock()
            manager.finalized_attempt.return_value = SimpleNamespace(
                path=capsule,
                manifest_sha256="a" * 64,
                verification=SimpleNamespace(ok=True),
            )
            with (
                mock.patch.object(runner, "RunCapsuleManager", return_value=manager),
                mock.patch.object(runner, "run_causal_evidence_stream") as science,
            ):
                self.assertEqual(runner.run_capsule_from_config(CONFIG), 0)
                science.assert_not_called()
                manager.recoverable_attempt_ids.assert_not_called()

    def test_recoverable_running_attempt_is_stopped_without_replay(self) -> None:
        interrupted = mock.Mock(publication_prepared=False)
        interrupted.finalize.return_value = SimpleNamespace(path=Path("/tmp/stopped"))
        manager = mock.Mock()
        manager.finalized_attempt.return_value = None
        manager.recoverable_attempt_ids.return_value = ("O1C-0021",)
        manager.recover.return_value = interrupted
        with (
            mock.patch.object(runner, "RunCapsuleManager", return_value=manager),
            mock.patch.object(runner, "run_causal_evidence_stream") as science,
        ):
            self.assertEqual(runner.run_capsule_from_config(CONFIG), 2)
            science.assert_not_called()
            self.assertEqual(interrupted.finalize.call_args.kwargs["status"], "stopped")

    def test_prepared_failed_publication_preserves_failed_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            (capsule / "metrics.json").write_text(
                json.dumps({"status": "failed"}), encoding="utf-8"
            )
            interrupted = mock.Mock(publication_prepared=True)
            interrupted.finalize.return_value = SimpleNamespace(path=capsule)
            manager = mock.Mock()
            manager.finalized_attempt.return_value = None
            manager.recoverable_attempt_ids.return_value = ("O1C-0021",)
            manager.recover.return_value = interrupted
            with (
                mock.patch.object(runner, "RunCapsuleManager", return_value=manager),
                mock.patch.object(runner, "run_causal_evidence_stream") as science,
            ):
                self.assertEqual(runner.run_capsule_from_config(CONFIG), 2)
                science.assert_not_called()

    def _run_mocked(
        self,
        classification: str,
        *,
        mutate_result: Callable[[SimpleNamespace], None] | None = None,
    ) -> tuple[int, _FakeRun, list[str], object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        fake_run = _FakeRun(Path(temporary.name))
        manager = mock.Mock()
        manager.finalized_attempt.return_value = None
        manager.recoverable_attempt_ids.return_value = ()
        manager.start.return_value = fake_run
        events: list[str] = []
        result = _result(classification)
        if mutate_result is not None:
            mutate_result(result)
            unsigned = dict(result.report)
            unsigned.pop("result_sha256", None)
            result.report["result_sha256"] = hashlib.sha256(
                runner._canonical_json(unsigned)
            ).hexdigest()
        with (
            mock.patch.object(runner, "RunCapsuleManager", return_value=manager),
            mock.patch.object(runner, "_git_commit", return_value="c" * 40),
            mock.patch.object(runner, "_source_hashes", return_value={"x": "d" * 64}),
            mock.patch.object(runner, "_process_peak_rss_bytes", return_value=1),
            mock.patch.object(runner.secrets, "token_bytes", return_value=b"R" * 32) as entropy,
            mock.patch.object(
                runner,
                "_build_post_reveal_audit_artifacts",
                return_value={"truth/mock_audit.bin": b"audit"},
            ),
            mock.patch.object(
                runner,
                "recompute_causal_evidence_scores",
                return_value=result.report["scores"],
            ),
            mock.patch.object(
                runner,
                "run_causal_evidence_stream",
                side_effect=_science(result, events),
            ),
        ):
            exit_code = runner.run_capsule_from_config(CONFIG)
        return exit_code, fake_run, events, entropy

    def test_mocked_full_lifecycle_uses_one_post_learning_entropy_call(self) -> None:
        exit_code, fake_run, events, entropy = self._run_mocked("NOT_EXACT_256")
        self.assertEqual(exit_code, 0)
        self.assertEqual(events, ["learning", "entropy", "prediction", "truth"])
        entropy.assert_called_once_with(32)
        self.assertEqual(fake_run.finalize_calls[-1]["status"], "completed")
        self.assertTrue(
            (fake_run.root / "artifacts/truth/evaluation_truth.bitpack").is_file()
        )
        self.assertTrue(
            (fake_run.root / "artifacts/score_recomputation.json").is_file()
        )

    def test_integrity_classification_fails_capsule_but_not_replays(self) -> None:
        exit_code, fake_run, _events, _entropy = self._run_mocked(
            "TRUTH_PATH_LEAKAGE"
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(fake_run.finalize_calls[-1]["status"], "failed")
        metrics = fake_run.finalize_calls[-1]["metrics"]
        self.assertTrue(metrics["integrity_failure"])
        self.assertFalse(metrics["operationally_complete"])

    def test_missing_mandatory_integrity_gate_is_rejected(self) -> None:
        def remove_gate(result: SimpleNamespace) -> None:
            result.report["gates"].pop("fresh_post_learning_evaluation_material")

        exit_code, fake_run, _events, _entropy = self._run_mocked(
            runner._SUCCESS_CLASSIFICATION,
            mutate_result=remove_gate,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(fake_run.finalize_calls[-1]["status"], "failed")
        self.assertTrue(
            any("top-level/recomputed gates differ" in row for row in fake_run.stderr)
        )

    def test_precedence_masked_integrity_gate_still_fails_capsule(self) -> None:
        def mask_complement(result: SimpleNamespace) -> None:
            gate = "complement_logit_antisymmetry"
            result.report["scores"]["gates"][gate] = False
            result.report["scores"]["failed_gates"] = sorted(
                name
                for name, passed in result.report["scores"]["gates"].items()
                if not passed
            )
            result.report["gates"][gate] = False
            result.report["failed_gates"] = sorted(
                name
                for name, passed in result.report["gates"].items()
                if not passed
            )

        exit_code, fake_run, _events, _entropy = self._run_mocked(
            "GENERATOR_CEILING_INSUFFICIENT",
            mutate_result=mask_complement,
        )
        self.assertEqual(exit_code, 1)
        metrics = fake_run.finalize_calls[-1]["metrics"]
        self.assertTrue(metrics["integrity_failure"])
        self.assertIn(
            "complement_logit_antisymmetry",
            metrics["failed_integrity_gates"],
        )

    def test_entropy_provider_before_learning_is_rejected_without_entropy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fake_run = _FakeRun(Path(temporary))
            manager = mock.Mock()
            manager.finalized_attempt.return_value = None
            manager.recoverable_attempt_ids.return_value = ()
            manager.start.return_value = fake_run

            def invalid_science(_config: object, **kwargs: object) -> object:
                kwargs["evaluation_material_provider"](_config.evaluation_seeds)
                raise AssertionError("provider should reject before this line")

            with (
                mock.patch.object(runner, "RunCapsuleManager", return_value=manager),
                mock.patch.object(runner, "_git_commit", return_value="c" * 40),
                mock.patch.object(
                    runner, "_source_hashes", return_value={"x": "d" * 64}
                ),
                mock.patch.object(runner.secrets, "token_bytes") as entropy,
                mock.patch.object(
                    runner, "run_causal_evidence_stream", side_effect=invalid_science
                ),
            ):
                self.assertEqual(runner.run_capsule_from_config(CONFIG), 1)
                entropy.assert_not_called()
                self.assertEqual(fake_run.finalize_calls[-1]["status"], "failed")

    def test_freeze_commitment_mismatch_is_rejected(self) -> None:
        artifacts, document = _freeze(
            schema=runner.LEARNING_FREEZE_SCHEMA,
            phase="x",
            freeze_path="learning/learning_freeze.json",
            payloads={"learning/a.bin": b"a"},
            extra={},
        )
        artifacts["learning/a.bin"] = b"changed"
        with self.assertRaisesRegex(
            runner.CausalEvidenceRunError, "artifact commitment differs"
        ):
            runner._validate_artifact_commitments(
                artifacts,
                document,
                freeze_path="learning/learning_freeze.json",
            )


if __name__ == "__main__":
    unittest.main()
