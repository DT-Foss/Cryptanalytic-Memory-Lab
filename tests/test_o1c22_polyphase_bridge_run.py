from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from o1_crypto_lab.o1c22_polyphase_bridge import GROUP_BYTES
from o1_crypto_lab.o1c22_polyphase_bridge_run import (
    ATTEMPT_ID,
    RESULT_SCHEMA,
    RUN_CONFIG_SCHEMA,
    O1C22PolyphaseBridgeRunError,
    _source_hashes,
    evaluate_bridge,
    load_bridge_run_config,
    run_capsule_from_config,
)
from o1_crypto_lab.polyphase_sufficient_state_v2 import STATE_BYTES


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c22_polyphase_bridge_v1.json"


class O1C22PolyphaseBridgeRunTests(unittest.TestCase):
    def test_frozen_o1c0028_geometry_and_budgets(self) -> None:
        top, experiment, budgets = load_bridge_run_config(CONFIG)
        self.assertEqual(top["schema"], RUN_CONFIG_SCHEMA)
        self.assertEqual(top["attempt_id"], ATTEMPT_ID)
        self.assertEqual(top["claim_level"], "VALIDATION")
        self.assertEqual(experiment.n_bits, 256)
        self.assertEqual(experiment.packet_horizons, (64, 65, 96))
        self.assertEqual(experiment.polyphase_wavelengths, (64, 96, 65))
        self.assertEqual(budgets.maximum_state_bytes_per_arm, STATE_BYTES)
        self.assertEqual(budgets.maximum_dense_stream_bytes_per_encoding, GROUP_BYTES)
        self.assertEqual(budgets.expected_packet_groups_per_extraction, 256)
        self.assertEqual(budgets.expected_packet_slots_per_extraction, 768)
        self.assertEqual(budgets.expected_hot_operator_bindings, 2)
        self.assertEqual(budgets.expected_cold_replay_probes, 13)

    def test_deterministic_mechanism_passes_every_gate_and_repeats(self) -> None:
        _top, experiment, _budgets = load_bridge_run_config(CONFIG)
        result = evaluate_bridge(experiment)
        self.assertTrue(result.passed)
        self.assertEqual(result.report["schema"], RESULT_SCHEMA)
        self.assertEqual(
            result.report["classification"], "HORIZON_MAJOR_HOT_ROUTING_PASS"
        )
        self.assertTrue(all(result.report["gates"].values()))
        self.assertFalse(result.report["cryptanalytic_signal_claimed"])
        self.assertFalse(result.report["full_round_key_recovery_claimed"])
        self.assertFalse(result.report["contains_chacha20_evidence"])
        self.assertEqual(len(result.artifacts), 13)
        self.assertEqual(len(result.artifacts["normalized_evidence.f32le"]), GROUP_BYTES)
        self.assertEqual(len(result.artifacts["quantized_evidence.f32le"]), GROUP_BYTES)
        self.assertEqual(len(result.artifacts["state_primary.bin"]), STATE_BYTES)
        work = result.report["work"]
        self.assertEqual(work["primary_consume_calls"], 1)
        self.assertEqual(work["primary_reingested_groups"], 0)
        self.assertEqual(work["hot_operator_bindings"], 2)
        self.assertEqual(work["cold_replay_probes"], 13)
        repeated = evaluate_bridge(experiment)
        self.assertEqual(result.report["result_sha256"], repeated.report["result_sha256"])
        self.assertEqual(result.artifacts, repeated.artifacts)

    def test_strict_parser_rejects_geometry_work_or_access_mutations(self) -> None:
        original = json.loads(CONFIG.read_text(encoding="utf-8"))
        mutations = (
            ("experiment", "n_bits", 128),
            ("experiment", "packet_horizons", [64, 96, 65]),
            ("experiment", "coordinate_permutation_offset", 18),
            ("budgets", "maximum_state_bytes_per_arm", STATE_BYTES + 1),
            ("budgets", "expected_cold_replay_probes", 12),
            ("budgets", "maximum_sibling_reads", 1),
            (None, "attempt_id", "O1C-0029"),
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
                    with self.assertRaises(O1C22PolyphaseBridgeRunError):
                        load_bridge_run_config(path)

    def test_external_config_is_rejected_before_capsule_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "copied.json"
            copied.write_bytes(CONFIG.read_bytes())
            with mock.patch(
                "o1_crypto_lab.o1c22_polyphase_bridge_run.RunCapsuleManager"
            ) as manager:
                with self.assertRaisesRegex(
                    O1C22PolyphaseBridgeRunError, "canonical tracked config"
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
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.RunCapsuleManager",
                    return_value=manager,
                ),
                mock.patch(
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.evaluate_bridge"
                ) as science,
                mock.patch(
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.load_bridge_run_config"
                ) as config_loader,
            ):
                self.assertEqual(run_capsule_from_config(CONFIG), 0)
                science.assert_not_called()
                config_loader.assert_not_called()
                manager.recoverable_attempt_ids.assert_not_called()

    def test_interrupted_attempt_is_stopped_without_replay(self) -> None:
        finalized = SimpleNamespace(path=Path("/tmp/stopped-o1c0028"))
        interrupted = mock.Mock(publication_prepared=False)
        interrupted.finalize.return_value = finalized
        manager = mock.Mock()
        manager.finalized_attempt.return_value = None
        manager.recoverable_attempt_ids.return_value = (ATTEMPT_ID,)
        manager.recover.return_value = interrupted
        with (
            mock.patch(
                "o1_crypto_lab.o1c22_polyphase_bridge_run.RunCapsuleManager",
                return_value=manager,
            ),
            mock.patch(
                "o1_crypto_lab.o1c22_polyphase_bridge_run.evaluate_bridge"
            ) as science,
            mock.patch(
                "o1_crypto_lab.o1c22_polyphase_bridge_run.load_bridge_run_config"
            ) as config_loader,
        ):
            self.assertEqual(run_capsule_from_config(CONFIG), 2)
            science.assert_not_called()
            config_loader.assert_not_called()
            interrupted.finalize.assert_called_once()
            self.assertEqual(interrupted.finalize.call_args.kwargs["status"], "stopped")

    def test_publication_prepared_attempt_recovers_without_science_or_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capsule = Path(temporary)
            (capsule / "metrics.json").write_text(
                json.dumps({"status": "completed"}), encoding="utf-8"
            )
            finalized = SimpleNamespace(path=capsule)
            interrupted = mock.Mock(publication_prepared=True)
            interrupted.finalize.return_value = finalized
            manager = mock.Mock()
            manager.finalized_attempt.return_value = None
            manager.recoverable_attempt_ids.return_value = (ATTEMPT_ID,)
            manager.recover.return_value = interrupted
            with (
                mock.patch(
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.RunCapsuleManager",
                    return_value=manager,
                ),
                mock.patch(
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.evaluate_bridge"
                ) as science,
                mock.patch(
                    "o1_crypto_lab.o1c22_polyphase_bridge_run.load_bridge_run_config"
                ) as config_loader,
            ):
                self.assertEqual(run_capsule_from_config(CONFIG), 0)
                science.assert_not_called()
                config_loader.assert_not_called()
                interrupted.finalize.assert_called_once_with(metrics={})

    def test_source_hashes_bind_both_legacy_and_v2_state_implementations(self) -> None:
        hashes = _source_hashes(ROOT, CONFIG)
        self.assertIn("module_o1c19_causal_vault_bridge", hashes)
        self.assertIn("module_polyphase_sufficient_state", hashes)
        self.assertIn("module_polyphase_sufficient_state_v2", hashes)
        self.assertIn("module_o1c22_packet_codec", hashes)
        self.assertNotEqual(
            hashes["module_polyphase_sufficient_state"],
            hashes["module_polyphase_sufficient_state_v2"],
        )


if __name__ == "__main__":
    unittest.main()
