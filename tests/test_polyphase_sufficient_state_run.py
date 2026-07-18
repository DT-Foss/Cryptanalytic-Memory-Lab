from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from o1_crypto_lab.polyphase_sufficient_state import BASIS_SHA256, STATE_BYTES
from o1_crypto_lab.polyphase_sufficient_state_run import (
    ATTEMPT_ID,
    RESULT_SCHEMA,
    RUN_CONFIG_SCHEMA,
    PolyphaseSufficientStateRunError,
    evaluate_polyphase_sufficient_state,
    load_polyphase_run_config,
    run_capsule_from_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/polyphase_sufficient_state_v1.json"


class PolyphaseSufficientStateRunTests(unittest.TestCase):
    def test_frozen_o1c0027_geometry_and_exact_work_budgets(self) -> None:
        top, experiment, budgets = load_polyphase_run_config(CONFIG)
        self.assertEqual(top["schema"], RUN_CONFIG_SCHEMA)
        self.assertEqual(top["attempt_id"], ATTEMPT_ID)
        self.assertEqual(top["claim_level"], "VALIDATION")
        self.assertEqual(experiment.n_bits, 256)
        self.assertEqual(experiment.stream_groups, 384)
        self.assertEqual(experiment.regime_switch, 193)
        self.assertEqual(experiment.chunk_partition, (17, 64, 5, 96, 65, 32, 105))
        self.assertEqual(experiment.basis_sha256, BASIS_SHA256)
        self.assertEqual(len(experiment.readouts), 4)
        self.assertEqual(budgets.maximum_state_bytes_per_arm, STATE_BYTES)
        self.assertEqual(budgets.maximum_deployment_live_state_bytes, 4 * STATE_BYTES)
        self.assertEqual(budgets.maximum_reference_state_bytes, 74_248)
        self.assertEqual(budgets.maximum_aggregate_algorithmic_state_bytes, 174_632)
        self.assertEqual(budgets.maximum_state_snapshot_bytes, 5 * STATE_BYTES)
        self.assertEqual(budgets.maximum_source_buffer_bytes, 1_179_648)
        self.assertEqual(budgets.maximum_control_input_chunk_bytes, 3_072)
        self.assertEqual(budgets.maximum_source_plus_control_input_bytes, 1_182_720)
        self.assertEqual(budgets.maximum_state_group_updates, 1_345)
        self.assertEqual(budgets.maximum_input_scalar_deliveries, 1_032_960)
        self.assertEqual(budgets.maximum_resonator_cell_updates, 4_131_840)
        self.assertEqual(budgets.maximum_direct_reference_group_updates, 384)
        self.assertEqual(
            budgets.maximum_direct_reference_resonator_cell_updates, 1_179_648
        )
        self.assertEqual(budgets.maximum_direct_reference_readout_calls, 4)
        self.assertEqual(
            budgets.maximum_direct_reference_readout_slot_contributions, 12_288
        )
        for field in (
            "maximum_primary_reingested_groups",
            "maximum_scientific_entropy_calls",
            "maximum_target_reads",
            "maximum_label_reads",
            "maximum_outcome_or_progress_reads",
            "maximum_solver_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_network_calls",
            "maximum_gpu_calls",
            "maximum_mps_calls",
        ):
            self.assertEqual(getattr(budgets, field), 0)

    def test_deterministic_mechanism_passes_every_gate_and_inventory(self) -> None:
        _top, experiment, _budgets = load_polyphase_run_config(CONFIG)
        result = evaluate_polyphase_sufficient_state(experiment)
        self.assertTrue(result.passed)
        self.assertEqual(result.report["schema"], RESULT_SCHEMA)
        self.assertEqual(
            result.report["classification"], "POLYPHASE_SUFFICIENT_STATE_PASS"
        )
        self.assertTrue(all(result.report["gates"].values()))
        self.assertFalse(result.report["cryptanalytic_signal_claimed"])
        self.assertFalse(result.report["full_round_key_recovery_claimed"])
        self.assertEqual(len(result.artifacts), 12)
        self.assertEqual(len(result.artifacts["readouts.f32le"]), 16_384)
        for name in (
            "state_t000.bin",
            "state_t193.bin",
            "state_primary_t384.bin",
            "state_rechunk_t384.bin",
            "state_swap_t384.bin",
        ):
            self.assertEqual(len(result.artifacts[name]), STATE_BYTES)
        work = result.report["work"]
        self.assertEqual(work["source_generation_calls"], 1)
        self.assertEqual(work["primary_consume_calls"], 1)
        self.assertEqual(work["primary_reingested_groups"], 0)
        self.assertEqual(work["total_query_attempts"], 15)
        self.assertEqual(work["successful_state_readout_calls"], 12)
        self.assertEqual(work["replay_required_probes"], 3)
        self.assertEqual(work["resonator_cell_updates"], 4_131_840)
        self.assertGreaterEqual(
            result.report["readout"]["minimum_pairwise_rms_after_normalization"],
            0.05,
        )
        self.assertLess(
            result.report["readout"][
                "collapsed_bank_maximum_pairwise_rms_after_normalization"
            ],
            0.05,
        )
        repeated = evaluate_polyphase_sufficient_state(experiment)
        self.assertEqual(
            repeated.report["result_sha256"], result.report["result_sha256"]
        )
        self.assertEqual(repeated.artifacts, result.artifacts)

    def test_rejects_width_basis_work_or_external_access_mutations(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            ("experiment", "n_bits", 128),
            ("experiment", "stream_groups", 383),
            ("experiment", "basis_sha256", "0" * 64),
            ("budgets", "maximum_state_bytes_per_arm", STATE_BYTES + 1),
            ("budgets", "maximum_sibling_reads", 1),
            (None, "attempt_id", "O1C-0028"),
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
                    with self.assertRaises(PolyphaseSufficientStateRunError):
                        load_polyphase_run_config(path)

    def test_external_config_is_rejected_before_capsule_manager_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "copied.json"
            copied.write_bytes(CONFIG.read_bytes())
            with mock.patch(
                "o1_crypto_lab.polyphase_sufficient_state_run.RunCapsuleManager"
            ) as manager:
                with self.assertRaisesRegex(
                    PolyphaseSufficientStateRunError, "canonical tracked config"
                ):
                    run_capsule_from_config(copied)
                manager.assert_not_called()

    def test_finalized_attempt_returns_without_mechanism_replay(self) -> None:
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
                    "o1_crypto_lab.polyphase_sufficient_state_run.RunCapsuleManager",
                    return_value=manager,
                ),
                mock.patch(
                    "o1_crypto_lab.polyphase_sufficient_state_run.evaluate_polyphase_sufficient_state"
                ) as science,
            ):
                self.assertEqual(run_capsule_from_config(CONFIG), 0)
                science.assert_not_called()
                manager.recoverable_attempt_ids.assert_not_called()

    def test_interrupted_attempt_is_stopped_without_replay(self) -> None:
        finalized = SimpleNamespace(path=Path("/tmp/stopped-o1c0027"))
        interrupted = mock.Mock(publication_prepared=False)
        interrupted.finalize.return_value = finalized
        manager = mock.Mock()
        manager.finalized_attempt.return_value = None
        manager.recoverable_attempt_ids.return_value = (ATTEMPT_ID,)
        manager.recover.return_value = interrupted
        with (
            mock.patch(
                "o1_crypto_lab.polyphase_sufficient_state_run.RunCapsuleManager",
                return_value=manager,
            ),
            mock.patch(
                "o1_crypto_lab.polyphase_sufficient_state_run.evaluate_polyphase_sufficient_state"
            ) as science,
        ):
            self.assertEqual(run_capsule_from_config(CONFIG), 2)
            science.assert_not_called()
            interrupted.finalize.assert_called_once()
            self.assertEqual(interrupted.finalize.call_args.kwargs["status"], "stopped")


if __name__ == "__main__":
    unittest.main()
