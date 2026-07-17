from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from o1_crypto_lab.selective_mqar_run import (
    RUN_CONFIG_SCHEMA,
    SelectiveMQARRunError,
    load_selective_mqar_run_config,
    run_capsule_from_config,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/selective_mqar_256_v1.json"


class SelectiveMQARRunConfigTests(unittest.TestCase):
    def test_frozen_o1c0020_shape_and_work_budgets(self) -> None:
        top, experiment, budgets = load_selective_mqar_run_config(CONFIG)
        self.assertEqual(top["schema"], RUN_CONFIG_SCHEMA)
        self.assertEqual(top["attempt_id"], "O1C-0020")
        self.assertEqual(top["claim_level"], "VALIDATION")
        self.assertEqual(experiment.n_bits, 256)
        self.assertEqual(experiment.haystack_lengths, (0, 65536, 1048576))
        self.assertEqual(experiment.live_state_bytes, 352)
        self.assertEqual(budgets.maximum_live_state_bytes, 352)
        self.assertEqual(experiment.cpu_threads, 1)
        self.assertEqual(
            set(experiment.build_seeds) & set(experiment.calibration_seeds)
            | set(experiment.build_seeds) & set(experiment.evaluation_seeds)
            | set(experiment.calibration_seeds) & set(experiment.evaluation_seeds),
            set(),
        )
        planned_gate_work = (
            5
            * len(experiment.evaluation_seeds)
            * sum(experiment.n_bits + length for length in experiment.haystack_lengths)
            + experiment.no_binding_length
            + experiment.literal_audit_tokens
            + 2
            * len(experiment.calibration_seeds)
            * 2
            * experiment.calibration_examples_per_class
        )
        self.assertEqual(planned_gate_work, 23_366_656)
        self.assertLessEqual(planned_gate_work, budgets.maximum_gate_token_evaluations)
        planned_training = (
            2
            * experiment.training_steps
            * len(experiment.build_seeds)
            * 2
            * experiment.build_examples_per_class
        )
        self.assertEqual(planned_training, 10_485_760)
        self.assertLessEqual(planned_training, budgets.maximum_training_token_exposures)
        for field in (
            "maximum_scientific_entropy_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_native_solver_branches",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        ):
            self.assertEqual(getattr(budgets, field), 0)

    def test_rejects_changed_width_sweep_or_nonzero_external_work(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            ("experiment", "n_bits", 128),
            ("experiment", "haystack_lengths", [0, 65536]),
            ("budgets", "maximum_sibling_reads", 1),
            ("budgets", "maximum_live_state_bytes", 353),
            (None, "attempt_id", "O1C-0019"),
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
                    with self.assertRaises(SelectiveMQARRunError):
                        load_selective_mqar_run_config(path)

    def test_external_config_is_rejected_before_capsule_manager_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "copied.json"
            copied.write_bytes(CONFIG.read_bytes())
            with mock.patch(
                "o1_crypto_lab.selective_mqar_run.RunCapsuleManager"
            ) as manager:
                with self.assertRaisesRegex(
                    SelectiveMQARRunError, "canonical tracked config"
                ):
                    run_capsule_from_config(copied)
                manager.assert_not_called()

    def test_finalized_attempt_returns_without_science_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            (capsule / "metrics.json").write_text(
                json.dumps({"status": "completed"}), encoding="utf-8"
            )
            published = SimpleNamespace(
                path=capsule,
                manifest_sha256="a" * 64,
                verification=SimpleNamespace(ok=True),
            )
            manager = mock.Mock()
            manager.finalized_attempt.return_value = published
            with (
                mock.patch(
                    "o1_crypto_lab.selective_mqar_run.RunCapsuleManager",
                    return_value=manager,
                ),
                mock.patch(
                    "o1_crypto_lab.selective_mqar_run.run_selective_mqar"
                ) as science,
            ):
                self.assertEqual(run_capsule_from_config(CONFIG), 0)
                science.assert_not_called()
                manager.recoverable_attempt_ids.assert_not_called()

    def test_recoverable_running_attempt_is_stopped_without_replay(self) -> None:
        finalized = SimpleNamespace(path=Path("/tmp/stopped-o1c0020"))
        interrupted = mock.Mock(publication_prepared=False)
        interrupted.finalize.return_value = finalized
        manager = mock.Mock()
        manager.finalized_attempt.return_value = None
        manager.recoverable_attempt_ids.return_value = ("O1C-0020",)
        manager.recover.return_value = interrupted
        with (
            mock.patch(
                "o1_crypto_lab.selective_mqar_run.RunCapsuleManager",
                return_value=manager,
            ),
            mock.patch(
                "o1_crypto_lab.selective_mqar_run.run_selective_mqar"
            ) as science,
        ):
            self.assertEqual(run_capsule_from_config(CONFIG), 2)
            science.assert_not_called()
            interrupted.finalize.assert_called_once()
            self.assertEqual(interrupted.finalize.call_args.kwargs["status"], "stopped")

    def test_prepared_failed_publication_preserves_failed_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            (capsule / "metrics.json").write_text(
                json.dumps({"status": "failed"}), encoding="utf-8"
            )
            finalized = SimpleNamespace(
                path=capsule,
                manifest_sha256="b" * 64,
                verification=SimpleNamespace(ok=True),
            )
            interrupted = mock.Mock(publication_prepared=True)
            interrupted.finalize.return_value = finalized
            manager = mock.Mock()
            manager.finalized_attempt.return_value = None
            manager.recoverable_attempt_ids.return_value = ("O1C-0020",)
            manager.recover.return_value = interrupted
            with (
                mock.patch(
                    "o1_crypto_lab.selective_mqar_run.RunCapsuleManager",
                    return_value=manager,
                ),
                mock.patch(
                    "o1_crypto_lab.selective_mqar_run.run_selective_mqar"
                ) as science,
            ):
                self.assertEqual(run_capsule_from_config(CONFIG), 2)
                science.assert_not_called()


if __name__ == "__main__":
    unittest.main()
