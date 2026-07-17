from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from o1_crypto_lab.full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from o1_crypto_lab.full256_online_real_gate import (
    POLICY_ARMS,
    RAW_ARMS,
    Full256OnlineRealGateConfig,
    Full256OnlineRealGateError,
    _classify_gate_outcome,
    interleaved_latin_action_order,
    run_full256_online_real_gate,
)
from o1_crypto_lab.full256_online_real_gate_run import (
    load_full256_online_real_gate_run_config,
)
from o1_crypto_lab.full256_proof_pool import FrozenFull256ProofPool
from o1_crypto_lab.online_causal_controller import OnlineCausalControllerConfig, torch


def _controller_config() -> OnlineCausalControllerConfig:
    return OnlineCausalControllerConfig(
        horizons=(3, 5, 7),
        nuisance_rank=2,
        nuisance_warmup=2,
        model_dimension=8,
        heads=1,
        head_dimension=4,
        holographic_slots=2,
        feedforward_dimension=8,
        reader_learning_rate=1e-3,
        recall_loss_weight=0.0,
        gradient_chunk_actions=256,
        critic_shortlist_size=8,
        cpu_threads=1,
        seed=180018,
    )


class _FakePublicBuilder:
    def __init__(self, horizons: tuple[int, ...]) -> None:
        self.config = SimpleNamespace(
            state_plan=SimpleNamespace(horizons=horizons)
        )

    def probe_public(self, *, target_id: str, public: object) -> FrozenFull256ProofPool:
        public_digest = public.digest()
        seed = int(public_digest[:16], 16)
        generator = np.random.Generator(np.random.PCG64(seed))
        features = generator.normal(
            0.0,
            0.05,
            (3, 256, 2, BRANCH_FEATURES),
        ).astype(np.float32)
        resources = np.zeros((256, 2, 3), dtype=np.uint64)
        resources[:, :, 0] = np.uint64(7)
        pairs = tuple(
            hashlib.sha256(f"{target_id}-pair-{bit}".encode("ascii")).hexdigest()
            for bit in range(256)
        )
        pool = Full256ActionPool(
            horizons=tuple(self.config.state_plan.horizons),
            branch_features=features,
            final_resources=resources,
            pair_sha256=pairs,
            source_stream_sha256=hashlib.sha256(
                f"{target_id}-{public_digest}".encode("ascii")
            ).hexdigest(),
        )
        from o1_crypto_lab.full256_action_pool import serialize_action_pool

        return FrozenFull256ProofPool(
            target_id=target_id,
            public=public,
            action_pool=pool,
            action_pool_bytes=serialize_action_pool(pool),
            instance={"instance_sha256": "1" * 64},
            probe={"result_sha256": "2" * 64},
            resources={
                "total_native_solver_branches": 512,
                "conservative_process_group_peak_rss_bytes": 1,
            },
        )


@unittest.skipUnless(torch is not None, "optional torch training dependency is absent")
class Full256OnlineRealGateTests(unittest.TestCase):
    def test_structural_failure_has_distinct_operational_classification(self) -> None:
        classification, structural, raw, picker = _classify_gate_outcome(
            {"freeze_order": True, "antisymmetry": False},
            {"raw_signal": True},
            {"picker_signal": True},
        )
        self.assertEqual(classification, "OPERATIONAL_FAILURE")
        self.assertFalse(structural)
        self.assertFalse(raw)
        self.assertFalse(picker)

    def test_latin_order_is_exhaustive_and_covers_every_bit_per_pass(self) -> None:
        config = _controller_config()
        first = interleaved_latin_action_order(config, 0)
        second = interleaved_latin_action_order(config, 1)

        self.assertEqual(len(first), 768)
        self.assertEqual(len(set(first)), 768)
        self.assertNotEqual(first, second)
        for pass_index in range(3):
            rows = first[pass_index * 256 : (pass_index + 1) * 256]
            self.assertEqual({value % 256 for value in rows}, set(range(256)))
        for bit in range(256):
            horizons = {value // 256 for value in first if value % 256 == bit}
            self.assertEqual(horizons, {0, 1, 2})

    def test_gate_freezes_build_reader_and_nested_predictions_before_labels(
        self,
    ) -> None:
        controller = _controller_config()
        config = Full256OnlineRealGateConfig(
            controller=controller,
            corpus_seed=180018,
            build_targets=1,
            evaluation_targets=1,
            work_checkpoints=(12, 24, 36),
            maximum_checkpoint_slack=13,
            minimum_raw_mean_compression_bits=-256.0,
            minimum_raw_control_margin_bits=-256.0,
            minimum_picker_iauc_margin_bits=-256.0,
        )
        builder = _FakePublicBuilder(controller.horizons)
        phases: list[str] = []
        frozen_prediction_artifacts: dict[str, bytes] = {}

        def pool_callback(
            artifacts: object,
            document: object,
        ) -> None:
            self.assertTrue(artifacts)
            self.assertEqual(document["labels_materialized"], 0)
            phases.append(f"pool:{document['split']}")

        def learning_callback(
            artifacts: object,
            document: object,
        ) -> None:
            self.assertEqual(document["evaluation_targets_generated"], 0)
            self.assertIn("primary_slow_state.bin", artifacts)
            phases.append("learning")

        def build_prediction_callback(
            artifacts: object,
            document: object,
        ) -> None:
            self.assertEqual(document["labels_materialized"], 0)
            self.assertIn("build-0000.primary.fast", repr(artifacts))
            phases.append("build-prediction")

        def prediction_callback(
            artifacts: object,
            document: object,
        ) -> None:
            self.assertEqual(document["evaluation_labels_materialized"], 0)
            self.assertEqual(document["evaluation_slow_updates"], 0)
            frozen_prediction_artifacts.update(artifacts)
            phases.append("predictions")

        result = run_full256_online_real_gate(
            config,
            builder=builder,
            on_pool_frozen=pool_callback,
            on_build_prediction_frozen=build_prediction_callback,
            on_learning_frozen=learning_callback,
            on_predictions_frozen=prediction_callback,
        )

        self.assertEqual(
            phases,
            [
                "pool:BUILD",
                "build-prediction",
                "learning",
                "pool:DEVELOPMENT",
                "predictions",
            ],
        )
        self.assertEqual(result.raw_predictions.shape, (len(RAW_ARMS), 1, 256))
        self.assertEqual(
            result.policy_predictions.shape,
            (len(POLICY_ARMS), 1, 3, 256),
        )
        self.assertEqual(result.action_orders.shape, (len(POLICY_ARMS), 1, 768))
        self.assertTrue(
            np.all(np.diff(result.checkpoint_action_counts, axis=-1) >= 0)
        )
        self.assertTrue(np.all(np.diff(result.checkpoint_work, axis=-1) >= 0))
        for arm_index in range(len(POLICY_ARMS)):
            final_count = int(result.checkpoint_action_counts[arm_index, 0, -1])
            ledger = result.action_orders[arm_index, 0]
            self.assertEqual(len(set(int(value) for value in ledger[:final_count])), final_count)
            self.assertTrue(
                np.all(
                    ledger[final_count:]
                    == np.iinfo(np.uint16).max
                )
            )
        self.assertEqual(
            result.report["invariants"]["polarity_swap_max_absolute_logit_residual"],
            0.0,
        )
        self.assertEqual(
            result.report["invariants"]["common_only_max_absolute_logit"],
            0.0,
        )
        self.assertTrue(
            result.report["gates"]["shared_reader_for_true_and_shifted_critics"]
        )
        for name, payload in result.prediction_artifacts().items():
            self.assertEqual(frozen_prediction_artifacts[name], payload)
        self.assertNotIn(
            b'"key_sha256"',
            frozen_prediction_artifacts["prediction_freeze.json"],
        )

    def test_config_rejects_exhaustive_or_mismatched_contracts(self) -> None:
        controller = _controller_config()
        with self.assertRaisesRegex(Full256OnlineRealGateError, "sub-exhaustive"):
            Full256OnlineRealGateConfig(
                controller=controller,
                work_checkpoints=(100, 1000, 7680),
            )
        with self.assertRaisesRegex(
            Full256OnlineRealGateError,
            "exactly three controller horizons",
        ):
            Full256OnlineRealGateConfig(
                controller=OnlineCausalControllerConfig(horizons=(3, 5)),
            )

    def test_checked_in_development_config_has_exact_real_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        top, gate, proof, budgets = load_full256_online_real_gate_run_config(
            root / "configs/full256_online_real_gate_dev_v1.json"
        )

        self.assertEqual(top["attempt_id"], "O1C-0018")
        self.assertEqual(gate.evaluation_split, "DEVELOPMENT")
        self.assertEqual(gate.controller.horizons, (64, 96, 65))
        self.assertEqual(gate.work_checkpoints, (16384, 32768, 57600))
        self.assertEqual(proof.state_plan.horizons, gate.controller.horizons)
        self.assertEqual(
            budgets.maximum_physical_public_pools,
            gate.build_targets + gate.evaluation_targets,
        )
        self.assertEqual(budgets.maximum_scientific_entropy_calls, 0)


if __name__ == "__main__":
    unittest.main()
