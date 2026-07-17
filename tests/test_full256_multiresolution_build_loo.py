from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from typing import Mapping
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.full256_action_pool import (
    BRANCH_FEATURES,
    Full256ActionPool,
    serialize_action_pool,
)
from o1_crypto_lab.full256_multiresolution_build_loo import (
    POLICY_ARMS,
    RAW_ARMS,
    VOLATILE_RESOURCE_FIELDS,
    ArtifactBuildCorpus,
    ArtifactBuildEpisode,
    Full256BuildLooConfig,
    Full256BuildLooError,
    discover_artifact_build_corpus,
    packet_latin_action_order,
    run_full256_multiresolution_build_loo,
)
from o1_crypto_lab.full256_multiresolution_build_loo_run import (
    load_full256_build_loo_run_config,
)
from o1_crypto_lab.full256_proof_pool import make_deterministic_known_target
from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.online_causal_controller import (
    KEY_BITS,
    CausalAction,
    OnlineCausalControllerConfig,
    torch,
)
from o1_crypto_lab.online_multiresolution_controller import (
    MultiResolutionControllerConfig,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(canonical_json_bytes(value))


def _base_config() -> OnlineCausalControllerConfig:
    return OnlineCausalControllerConfig(
        horizons=(1, 3, 2),
        nuisance_rank=1,
        nuisance_learning_rate=1.0 / 16.0,
        nuisance_warmup=1,
        model_dimension=4,
        heads=1,
        head_dimension=2,
        holographic_slots=1,
        feedforward_dimension=4,
        reader_learning_rate=1e-3,
        recall_loss_weight=1.0,
        gradient_chunk_actions=2,
        cpu_threads=1,
        seed=190_119,
    )


def _controller_config() -> MultiResolutionControllerConfig:
    return MultiResolutionControllerConfig(
        base=_base_config(),
        stationarity_penalty=1.0,
        critic_exploration_scale=0.0,
        soft_coverage_weight=0.0,
        soft_age_weight=0.0,
        starvation_steps=8,
        minimum_decisions_before_stop=256,
        minimum_critic_episodes_before_stop=2,
        reader_training_passes=1,
        stop_margin=0.0,
        require_all_coordinates_before_stop=True,
    )


def _pool(config: OnlineCausalControllerConfig, ordinal: int) -> Full256ActionPool:
    features = np.zeros(
        (len(config.horizons), KEY_BITS, 2, BRANCH_FEATURES),
        dtype=np.float32,
    )
    bit = np.arange(KEY_BITS, dtype=np.float32)
    parity = np.where(np.arange(KEY_BITS) % 2, -1.0, 1.0).astype(np.float32)
    for horizon_index, _horizon in enumerate(config.horizons):
        common = np.zeros((KEY_BITS, BRANCH_FEATURES), dtype=np.float32)
        signed = np.zeros_like(common)
        common[:, 0] = np.float32(ordinal + 1) / np.float32(8.0)
        common[:, 1] = (bit + np.float32(1.0)) / np.float32(KEY_BITS)
        common[:, 4] = np.sin(
            (bit + np.float32(1.0)) * np.float32(horizon_index + 1) / np.float32(23.0)
        )
        signed[:, 2] = parity * np.float32(0.25 + 0.05 * horizon_index)
        signed[:, 3] = np.cos(
            (bit + np.float32(1.0)) / np.float32(7.0 + ordinal + horizon_index)
        )
        signed[:, 5] = parity * (bit + np.float32(1.0)) / np.float32(8 * KEY_BITS)
        features[horizon_index, :, 0] = common - np.float32(0.5) * signed
        features[horizon_index, :, 1] = common + np.float32(0.5) * signed
    resources = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
    resources[:, :, 0] = np.uint64(ordinal + 1)
    pairs = tuple(
        _sha256(f"synthetic-pair-{ordinal}-{index}".encode("ascii"))
        for index in range(KEY_BITS)
    )
    return Full256ActionPool(
        horizons=config.horizons,
        branch_features=features,
        final_resources=resources,
        pair_sha256=pairs,
        source_stream_sha256=_sha256(f"synthetic-source-{ordinal}".encode("ascii")),
    )


def _corpus() -> ArtifactBuildCorpus:
    seed = 190_119_190_119
    base = _base_config()
    episodes: list[ArtifactBuildEpisode] = []
    for ordinal in range(3):
        target = make_deterministic_known_target(
            seed=seed,
            split="BUILD",
            index=ordinal,
        )
        description = target.public_description()
        pool = _pool(base, ordinal)
        payload = serialize_action_pool(pool)
        episodes.append(
            ArtifactBuildEpisode(
                ordinal=ordinal,
                target_id=target.target_id,
                target_index=ordinal,
                public_view_sha256=target.public.digest(),
                key_sha256=target.key_sha256,
                target_description_sha256=_canonical_sha256(description),
                action_pool_sha256=pool.action_pool_sha256,
                action_pool_bytes=len(payload),
                pool=pool,
                corpus_seed=seed,
            )
        )
    return ArtifactBuildCorpus(
        capsule_path=Path("/synthetic/finalized-o1c0018"),
        capsule_manifest_sha256=_sha256(b"synthetic-manifest"),
        artifact_index_sha256=_sha256(b"synthetic-index"),
        source_result_sha256=_sha256(b"synthetic-result"),
        source_config_sha256=_sha256(b"synthetic-config"),
        source_attempt_id="SYNTHETIC-O1C-0018",
        corpus_seed=seed,
        base_controller=base,
        episodes=tuple(episodes),
        bytes_read=sum(row.action_pool_bytes for row in episodes),
    )


def _experiment() -> Full256BuildLooConfig:
    return Full256BuildLooConfig(
        controller=_controller_config(),
        work_checkpoints=(2, 4, 6),
        held_out_ordinals=(0,),
        training_actions_per_episode=3,
        raw_actions_per_episode=3,
        coordinate_rotation_stride=67,
        train_stream=True,
        train_gate=True,
    )


@unittest.skipUnless(torch is not None, "optional torch training dependency is absent")
class Full256MultiresolutionBuildLooTests(unittest.TestCase):
    def test_packet_training_schedule_is_coordinate_local_and_depth_sorted(
        self,
    ) -> None:
        config = _experiment()
        order = packet_latin_action_order(config, 1)
        decoded = [
            CausalAction.from_flat_index(value, config.controller.base)
            for value in order
        ]
        self.assertEqual(
            decoded,
            [
                CausalAction(67, 1),
                CausalAction(67, 2),
                CausalAction(67, 3),
            ],
        )
        full = packet_latin_action_order(
            Full256BuildLooConfig(
                controller=config.controller,
                work_checkpoints=config.work_checkpoints,
                held_out_ordinals=config.held_out_ordinals,
                coordinate_rotation_stride=67,
            ),
            0,
        )
        self.assertEqual(len(full), 3 * KEY_BITS)
        self.assertEqual(len(set(full)), len(full))

    def test_synthetic_fold_freezes_before_label_and_scores_all_controls(
        self,
    ) -> None:
        corpus = _corpus()
        config = _experiment()
        learning_documents: list[Mapping[str, object]] = []
        prediction_documents: list[Mapping[str, object]] = []
        held_out_prediction_frozen = False
        original = ArtifactBuildEpisode.labels_after_prediction_freeze

        def labels_with_boundary(episode: ArtifactBuildEpisode) -> np.ndarray:
            if episode.ordinal == 0:
                self.assertTrue(held_out_prediction_frozen)
            return original(episode)

        def on_learning(
            artifacts: Mapping[str, bytes],
            document: Mapping[str, object],
        ) -> None:
            self.assertEqual(document["held_out_labels_materialized"], 0)
            self.assertIn("learning_freeze.json", " ".join(artifacts))
            learning_documents.append(document)

        def on_prediction(
            artifacts: Mapping[str, bytes],
            document: Mapping[str, object],
        ) -> None:
            nonlocal held_out_prediction_frozen
            self.assertEqual(document["held_out_labels_materialized"], 0)
            freeze_payload = next(
                payload
                for name, payload in artifacts.items()
                if name.endswith("prediction_freeze.json")
            )
            self.assertNotIn(b"key_sha256", freeze_payload)
            self.assertNotIn(b'"labels":', freeze_payload)
            prediction_documents.append(document)
            held_out_prediction_frozen = True

        with patch.object(
            ArtifactBuildEpisode,
            "labels_after_prediction_freeze",
            autospec=True,
            side_effect=labels_with_boundary,
        ):
            result = run_full256_multiresolution_build_loo(
                config,
                corpus,
                on_learning_frozen=on_learning,
                on_prediction_frozen=on_prediction,
            )

        self.assertEqual(len(learning_documents), 1)
        self.assertEqual(len(prediction_documents), 1)
        self.assertEqual(
            result.predictions.shape,
            (1, len(POLICY_ARMS), 3, KEY_BITS),
        )
        self.assertEqual(
            result.raw_predictions.shape,
            (1, len(RAW_ARMS), KEY_BITS),
        )
        self.assertEqual(
            result.slot_orders.shape,
            (1, len(POLICY_ARMS), config.controller.maximum_actions),
        )
        self.assertEqual(
            result.checkpoint_slot_counts.shape,
            (1, len(POLICY_ARMS), 3),
        )
        self.assertTrue(np.all(np.isfinite(result.nll_bits)))
        self.assertTrue(np.all(np.isfinite(result.raw_nll_bits)))
        self.assertTrue(
            np.all(
                result.checkpoint_work
                <= np.asarray(config.work_checkpoints, dtype=np.uint32)[None, None]
            )
        )
        self.assertTrue(
            np.array_equal(
                result.raw_action_orders[:, 0],
                result.raw_action_orders[:, 1],
            )
        )
        self.assertEqual(
            result.report["folds"][0]["critic"]["episode_count"],
            2,
        )
        self.assertEqual(
            result.report["folds"][0]["shifted_critic"]["episode_count"],
            2,
        )
        self.assertTrue(
            result.report["folds"][0]["shifted_critic"]["contexts_identical_to_true"]
        )
        self.assertTrue(result.report["gates"]["stop_enabled_route_is_no_stop_prefix"])
        self.assertIn(
            "raw_learned_minus_untrained_mean_compression_bits",
            result.report["margins"],
        )
        self.assertEqual(result.report["resources"]["native_solver_branches"], 0)
        self.assertEqual(
            result.report["resources"]["physical_public_pools_generated"],
            0,
        )
        commitments = result.report["artifact_commitments"]
        self.assertEqual(
            commitments["slot_orders_sha256"],
            _sha256(result.slot_orders.astype("<u2", copy=False).tobytes(order="C")),
        )
        self.assertEqual(
            commitments["checkpoint_slot_counts_sha256"],
            _sha256(
                result.checkpoint_slot_counts.astype("<u2", copy=False).tobytes(
                    order="C"
                )
            ),
        )
        execution_payload = {
            key: value
            for key, value in result.report.items()
            if key not in {"execution_report_sha256", "result_sha256"}
        }
        self.assertEqual(
            result.report["execution_report_sha256"],
            _canonical_sha256(execution_payload),
        )
        scientific_payload = dict(execution_payload)
        scientific_payload["resources"] = {
            key: value
            for key, value in result.report["resources"].items()
            if key not in VOLATILE_RESOURCE_FIELDS
        }
        self.assertEqual(
            result.result_sha256,
            _canonical_sha256(scientific_payload),
        )

        repeated = run_full256_multiresolution_build_loo(config, corpus)
        self.assertEqual(repeated.result_sha256, result.result_sha256)
        self.assertEqual(
            repeated.report["artifact_commitments"],
            result.report["artifact_commitments"],
        )
        self.assertEqual(
            repeated.report["folds"][0]["learning_freeze_sha256"],
            result.report["folds"][0]["learning_freeze_sha256"],
        )
        self.assertEqual(
            repeated.report["folds"][0]["prediction_freeze_sha256"],
            result.report["folds"][0]["prediction_freeze_sha256"],
        )

    def test_finalized_real_discovery_is_key_lazy_and_config_is_exact(self) -> None:
        root = Path(__file__).resolve().parents[1]
        capsule = root / (
            "runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1"
        )
        with patch(
            "o1_crypto_lab.full256_multiresolution_build_loo."
            "make_deterministic_known_target",
            side_effect=AssertionError("key oracle used during discovery"),
        ):
            corpus = discover_artifact_build_corpus(
                capsule,
                lab_root=root,
            )
        self.assertEqual(len(corpus.episodes), 4)
        self.assertEqual(
            corpus.capsule_manifest_sha256,
            "fcbf43c99994c0debe5b39bb3e734ea1d1e23ba58e89b10ff2bb7e23886493fb",
        )
        self.assertEqual(
            [row.target_id for row in corpus.episodes],
            [f"build-{index:04d}" for index in range(4)],
        )
        with self.assertRaisesRegex(
            Full256BuildLooError,
            "artifact-index hash differs",
        ):
            discover_artifact_build_corpus(
                capsule,
                lab_root=root,
                expected_artifact_index_sha256="0" * 64,
            )

        top, experiment, loaded, budgets = load_full256_build_loo_run_config(
            root / "configs/full256_multiresolution_build_loo_v1.json",
            root=root,
        )
        self.assertEqual(top["attempt_id"], "O1C-0019")
        self.assertEqual(experiment.held_out_ordinals, (0, 1, 2, 3))
        self.assertEqual(experiment.work_checkpoints, (16_384, 32_768, 49_152))
        self.assertEqual(experiment.controller.reader_training_passes, 4)
        self.assertEqual(
            loaded.capsule_manifest_sha256,
            corpus.capsule_manifest_sha256,
        )
        self.assertGreaterEqual(
            budgets.maximum_source_artifact_bytes_read,
            loaded.bytes_read,
        )


if __name__ == "__main__":
    unittest.main()
