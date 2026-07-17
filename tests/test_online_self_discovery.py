from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES
from o1_crypto_lab.living_inverse import canonical_sha256
from o1_crypto_lab.o1_streaming_core import torch
from o1_crypto_lab.online_causal_controller import KEY_BITS, OnlineCausalFastState
from o1_crypto_lab.online_self_discovery import (
    PREDICTION_ARMS,
    SELF_DISCOVERY_CONFIG_SCHEMA,
    SELF_DISCOVERY_FREEZE_SCHEMA,
    SELF_DISCOVERY_RESULT_SCHEMA,
    OnlineSelfDiscoveryBudgets,
    OnlineSelfDiscoveryConfig,
    OnlineSelfDiscoveryError,
    _build_episode,
    load_online_self_discovery_config,
    run_online_self_discovery,
)


def _tiny_config(**overrides: object) -> OnlineSelfDiscoveryConfig:
    values: dict[str, object] = {
        "train_targets": 1,
        "evaluation_targets": 1,
        "train_seed_start": 10,
        "evaluation_seed_start": 20,
        "hidden_channel": 7,
        "signal_amplitude": 8.0,
        "signed_distractor_scale": 0.05,
        "common_scale": 0.05,
        "horizon": 1,
        "nuisance_rank": 1,
        "nuisance_warmup": 1,
        "model_dimension": 1,
        "heads": 1,
        "head_dimension": 1,
        "holographic_slots": 1,
        "feedforward_dimension": 1,
        "reader_learning_rate": 0.01,
        "recall_loss_weight": 1.0,
        "gradient_chunk_actions": KEY_BITS,
        "cpu_threads": 1,
        "controller_seed": 17,
        # The tiny run is a structural regression, not the calibrated mechanism
        # benchmark. Its learned-performance gates may legitimately remain false.
        "minimum_mean_compression_bits": 1e-9,
        "minimum_control_margin_bits": 1e-9,
        "minimum_bit_accuracy": 0.01,
    }
    values.update(overrides)
    return OnlineSelfDiscoveryConfig(**values)


class OnlineSelfDiscoveryCorpusTests(unittest.TestCase):
    def test_train_and_evaluation_seed_sets_must_be_disjoint(self) -> None:
        with self.assertRaisesRegex(OnlineSelfDiscoveryError, "must be disjoint"):
            _tiny_config(
                train_targets=2,
                train_seed_start=10,
                evaluation_seed_start=11,
            )

        adjacent = _tiny_config(
            train_targets=2,
            train_seed_start=10,
            evaluation_seed_start=12,
        )
        restored = OnlineSelfDiscoveryConfig.from_mapping(dataclasses.asdict(adjacent))
        self.assertEqual(restored, adjacent)

    def test_exact_preregistered_config_and_budget_loader(self) -> None:
        config = _tiny_config()
        budgets = OnlineSelfDiscoveryBudgets(
            maximum_cpu_seconds=60,
            maximum_wall_seconds=60,
            maximum_resident_memory_mib=1_024,
            maximum_persistent_artifact_bytes=1_000_000,
            maximum_action_observations=4_096,
            maximum_fresh_entropy_calls=0,
            maximum_sibling_reads=0,
            maximum_sibling_writes=0,
            maximum_mps_calls=0,
            maximum_gpu_calls=0,
        )
        document: dict[str, object] = {
            "schema": SELF_DISCOVERY_CONFIG_SCHEMA,
            "attempt_id": "O1C-0017",
            "slug": "online-self-discovery",
            "claim_level": "synthetic-mechanism-gate",
            "hypothesis": "one anonymous oriented channel transfers",
            "prediction": "primary exceeds matched controls",
            "controls": ["channel ablation", "shuffled labels"],
            "budgets": budgets.describe(),
            "next_action": "advance only after the frozen gate",
            "experiment": dataclasses.asdict(config),
        }

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            raw, loaded_config, loaded_budgets = load_online_self_discovery_config(path)

            self.assertEqual(raw, document)
            self.assertEqual(loaded_config, config)
            self.assertEqual(loaded_budgets, budgets)
            self.assertEqual(
                OnlineSelfDiscoveryBudgets.from_mapping(budgets.describe()),
                budgets,
            )

            malformed = dict(document)
            malformed_budgets = dict(budgets.describe())
            malformed_budgets["unexpected"] = 1
            malformed["budgets"] = malformed_budgets
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaisesRegex(OnlineSelfDiscoveryError, "budget fields"):
                load_online_self_discovery_config(path)

            malformed = dict(document)
            malformed["unexpected"] = True
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaisesRegex(
                OnlineSelfDiscoveryError,
                "top-level config fields",
            ):
                load_online_self_discovery_config(path)

    def test_corpus_is_exactly_deterministic_and_ablation_changes_one_channel(
        self,
    ) -> None:
        config = _tiny_config()
        primary, labels = _build_episode(
            config,
            config.evaluation_seed_start,
            ablate_hidden_channel=False,
        )
        replay, replay_labels = _build_episode(
            config,
            config.evaluation_seed_start,
            ablate_hidden_channel=False,
        )
        ablated, ablated_labels = _build_episode(
            config,
            config.evaluation_seed_start,
            ablate_hidden_channel=True,
        )

        np.testing.assert_array_equal(replay_labels, labels)
        np.testing.assert_array_equal(ablated_labels, labels)
        np.testing.assert_array_equal(replay.branch_features, primary.branch_features)
        np.testing.assert_array_equal(replay.final_resources, primary.final_resources)
        self.assertEqual(replay.action_pool_sha256, primary.action_pool_sha256)

        retained = np.ones(BRANCH_FEATURES, dtype=np.bool_)
        retained[config.hidden_channel] = False
        np.testing.assert_array_equal(
            primary.branch_features[..., retained],
            ablated.branch_features[..., retained],
        )
        np.testing.assert_array_equal(
            primary.final_resources,
            ablated.final_resources,
        )
        self.assertEqual(primary.pair_sha256, ablated.pair_sha256)
        self.assertNotEqual(
            primary.source_stream_sha256,
            ablated.source_stream_sha256,
        )

        signed_difference = primary.signed_field() - ablated.signed_field()
        np.testing.assert_array_equal(
            signed_difference[..., retained],
            np.zeros((1, KEY_BITS, BRANCH_FEATURES - 1), dtype=np.float32),
        )
        expected_orientation = (2.0 * labels.astype(np.float32) - 1.0) * np.float32(
            config.signal_amplitude
        )
        np.testing.assert_allclose(
            signed_difference[0, :, config.hidden_channel],
            expected_orientation,
            rtol=0.0,
            atol=1e-6,
        )


@unittest.skipUnless(torch is not None, "optional torch dependency is absent")
class OnlineSelfDiscoveryRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = _tiny_config()
        cls.freeze_calls: list[tuple[dict[str, bytes], dict[str, object]]] = []

        def freeze_callback(
            artifacts: object,
            document: object,
        ) -> None:
            if not isinstance(artifacts, dict) or not isinstance(document, dict):
                raise AssertionError("freeze callback arguments differ")
            cls.freeze_calls.append((dict(artifacts), dict(document)))

        with patch(
            "o1_crypto_lab.online_self_discovery._peak_rss_bytes",
            return_value=111_111,
        ):
            cls.result = run_online_self_discovery(
                cls.config,
                on_predictions_frozen=freeze_callback,
            )
        with patch(
            "o1_crypto_lab.online_self_discovery._peak_rss_bytes",
            return_value=222_222,
        ):
            cls.replay = run_online_self_discovery(cls.config)

    def test_full256_artifacts_commitments_and_structural_gates(self) -> None:
        result = self.result
        report = result.report
        commitments = report["artifact_commitments"]

        self.assertEqual(report["schema"], SELF_DISCOVERY_RESULT_SCHEMA)
        self.assertEqual(
            result.predictions.shape,
            (len(PREDICTION_ARMS), self.config.evaluation_targets, KEY_BITS),
        )
        self.assertEqual(result.predictions.dtype, np.float32)
        self.assertEqual(
            result.labels.shape,
            (self.config.evaluation_targets, KEY_BITS),
        )
        self.assertEqual(result.labels.dtype, np.uint8)
        self.assertEqual(
            result.compressions.shape,
            (len(PREDICTION_ARMS), self.config.evaluation_targets),
        )
        self.assertEqual(result.compressions.dtype, np.float64)
        self.assertTrue(np.all(np.isfinite(result.predictions)))
        self.assertTrue(np.all(np.isfinite(result.compressions)))

        self.assertEqual(
            commitments["prediction_shape"], [len(PREDICTION_ARMS), 1, KEY_BITS]
        )
        self.assertEqual(
            commitments["prediction_bytes"], len(PREDICTION_ARMS) * KEY_BITS * 4
        )
        self.assertEqual(
            commitments["prediction_sha256"],
            hashlib.sha256(result.prediction_bytes()).hexdigest(),
        )
        self.assertEqual(commitments["label_shape"], [1, KEY_BITS])
        self.assertEqual(commitments["label_bitpack_bytes"], KEY_BITS // 8)
        self.assertEqual(
            commitments["label_sha256"],
            hashlib.sha256(result.label_bytes()).hexdigest(),
        )
        self.assertEqual(commitments["compression_shape"], [len(PREDICTION_ARMS), 1])
        self.assertEqual(commitments["compression_bytes"], len(PREDICTION_ARMS) * 8)
        self.assertEqual(
            commitments["compression_sha256"],
            hashlib.sha256(result.compression_bytes()).hexdigest(),
        )
        for artifact_name, payload in (
            ("primary_slow_state", result.primary_slow_state),
            ("shuffled_slow_state", result.shuffled_slow_state),
            ("representative_fast_state", result.representative_fast_state),
        ):
            self.assertEqual(
                commitments[f"{artifact_name}_sha256"],
                hashlib.sha256(payload).hexdigest(),
            )

        scientific_result = dict(report)
        result_sha256 = scientific_result.pop("result_sha256")
        scientific_result.pop("resources")
        self.assertEqual(result_sha256, canonical_sha256(scientific_result))
        self.assertIn("except resources", report["result_commitment_scope"])
        self.assertEqual(
            report["classification"],
            "MECHANISM_PASS" if result.success_gate_passed else "MECHANISM_FAIL",
        )

        fast_state = OnlineCausalFastState.from_bytes(
            result.representative_fast_state,
            self.config.controller_config,
        )
        self.assertEqual(fast_state.action_count, KEY_BITS)
        self.assertEqual(fast_state.steps, KEY_BITS)
        np.testing.assert_array_equal(
            fast_state.coverage,
            np.ones((1, KEY_BITS), dtype=np.uint16),
        )
        np.testing.assert_array_equal(
            fast_state.action_order,
            np.arange(KEY_BITS, dtype=np.uint16),
        )
        self.assertEqual(
            len(result.representative_fast_state),
            report["invariants"]["fast_state_serialized_bytes"],
        )
        self.assertEqual(
            report["invariants"]["fast_state_numeric_bytes"],
            self.config.controller_config.fast_state_numeric_bytes,
        )
        self.assertFalse(report["invariants"]["stream_length_dependent_fast_state"])
        self.assertEqual(report["invariants"]["bit_vault_coordinates"], KEY_BITS)
        self.assertEqual(report["invariants"]["raw_channels"], BRANCH_FEATURES)

        gates = report["gates"]
        for gate_name in (
            "all_256_coordinates_observed",
            "constant_fast_state_bytes",
            "exact_polarity_swap_antisymmetry",
            "common_only_orientation_zero",
            "zero_fresh_entropy_calls",
            "zero_mps_calls",
            "zero_gpu_calls",
            "synthetic_only_no_crypto_claim",
        ):
            with self.subTest(gate_name=gate_name):
                self.assertTrue(gates[gate_name])
        self.assertEqual(
            report["invariants"]["polarity_swap_max_absolute_logit_residual"],
            0.0,
        )
        self.assertEqual(
            report["invariants"]["common_only_max_absolute_logit"],
            0.0,
        )

        self.assertFalse(self.config.describe()["cryptographic_inverse_claim"])
        self.assertFalse(report["claim_boundary"]["standard_chacha20_target"])
        self.assertFalse(
            report["claim_boundary"]["cryptographic_inverse_signal_claimed"]
        )
        self.assertTrue(
            report["claim_boundary"]["autonomous_signal_channel_discovery_evaluated"]
        )
        self.assertFalse(report["claim_boundary"]["learned_action_picker_evaluated"])
        self.assertTrue(report["claim_boundary"]["bit_vault_retention_evaluated"])
        self.assertTrue(report["claim_boundary"]["raw_holographic_end_state_reported"])
        self.assertFalse(report["claim_boundary"]["o1_memory_necessity_evaluated"])
        self.assertEqual(report["static_accounting"]["native_solver_branches"], 0)
        self.assertEqual(
            report["static_accounting"]["train_action_observations"],
            6 * KEY_BITS,
        )
        self.assertEqual(
            report["static_accounting"]["train_replay_action_observations"],
            4 * KEY_BITS,
        )
        self.assertEqual(
            report["static_accounting"]["evaluation_action_observations"],
            self.config.evaluation_targets * KEY_BITS * 4 + 2 * KEY_BITS,
        )
        self.assertEqual(
            report["static_accounting"]["total_action_observations"],
            12 * KEY_BITS,
        )

    def test_single_evaluation_is_finite_and_reruns_bind_same_science(self) -> None:
        first = self.result
        replay = self.replay

        self.assertEqual(first.report["evaluation_targets"], 1)
        for arm in PREDICTION_ARMS:
            self.assertEqual(
                first.report["arms"][arm]["compression_stddev_bits"],
                0.0,
            )
        json.dumps(first.report, sort_keys=True, allow_nan=False)
        self.assertTrue(np.all(np.isfinite(first.predictions)))
        self.assertTrue(np.all(np.isfinite(first.compressions)))

        self.assertNotEqual(first.report["resources"], replay.report["resources"])
        self.assertEqual(
            first.report["resources"]["process_peak_rss_bytes"],
            111_111,
        )
        self.assertEqual(
            replay.report["resources"]["process_peak_rss_bytes"],
            222_222,
        )
        self.assertEqual(
            first.report["result_sha256"],
            replay.report["result_sha256"],
        )
        self.assertEqual(first.prediction_bytes(), replay.prediction_bytes())
        self.assertEqual(first.label_bytes(), replay.label_bytes())
        self.assertEqual(first.compression_bytes(), replay.compression_bytes())
        self.assertEqual(first.primary_slow_state, replay.primary_slow_state)
        self.assertEqual(first.shuffled_slow_state, replay.shuffled_slow_state)
        self.assertEqual(
            first.representative_fast_state,
            replay.representative_fast_state,
        )

    def test_prediction_freeze_callback_is_label_free_and_fully_bound(self) -> None:
        self.assertEqual(len(self.freeze_calls), 1)
        artifacts, document = self.freeze_calls[0]
        self.assertEqual(
            set(artifacts),
            {"prediction_freeze.json", "predictions.f32le"},
        )
        self.assertEqual(document["schema"], SELF_DISCOVERY_FREEZE_SCHEMA)
        self.assertEqual(
            document["phase"],
            "ALL_SYNTHETIC_PREDICTIONS_FROZEN_BEFORE_SCORING",
        )
        self.assertEqual(document["labels_exposed_to_controllers"], 0)
        label_fields = {key for key in document if "label" in key.lower()}
        self.assertEqual(label_fields, {"labels_exposed_to_controllers"})
        self.assertFalse(any("label" in name.lower() for name in artifacts))

        prediction_bytes = artifacts["predictions.f32le"]
        self.assertEqual(prediction_bytes, self.result.prediction_bytes())
        self.assertEqual(document["prediction_bytes"], len(prediction_bytes))
        self.assertEqual(
            document["prediction_sha256"],
            hashlib.sha256(prediction_bytes).hexdigest(),
        )
        self.assertEqual(
            document["prediction_sha256"],
            self.result.report["artifact_commitments"]["prediction_sha256"],
        )
        self.assertEqual(
            document["evaluation_pool_set_sha256"],
            self.result.report["artifact_commitments"]["evaluation_pool_set_sha256"],
        )
        for field in (
            "ablation_pool_set_sha256",
            "swap_control_pool_sha256",
            "common_only_pool_sha256",
            "all_control_pools_sha256",
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    document[field],
                    self.result.report["artifact_commitments"][field],
                )

        freeze_unsigned = dict(document)
        freeze_sha256 = freeze_unsigned.pop("freeze_sha256")
        self.assertEqual(freeze_sha256, canonical_sha256(freeze_unsigned))
        decoded = json.loads(artifacts["prediction_freeze.json"])
        self.assertEqual(decoded, document)


if __name__ == "__main__":
    unittest.main()
