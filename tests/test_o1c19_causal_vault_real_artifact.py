from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.full256_multiresolution_build_loo import ArtifactBuildEpisode
from o1_crypto_lab.o1_streaming_core import StreamingSelectiveHolographicCore
from o1_crypto_lab.o1c19_causal_vault_bridge import (
    FORMAL_VAULT_BYTES,
    FrozenMedianAbsQuantizer,
    NestedActiveCoordinatePlan,
    deterministic_coordinate_permutation,
)
from o1_crypto_lab.o1c19_causal_vault_bridge_run import (
    COORDINATE_SALT,
    HORIZON_ORDER,
    KEY_BITS,
    O1C19FoldSource,
    PREDICTION_ARMS,
    _execute_extraction,
    _execution_logits,
    _fresh_extraction,
    _verify_actual_polarity_swap,
    _verify_duplicate_probe,
    load_o1c19_causal_vault_bridge_run_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c19_causal_vault_bridge_v1.json"
SOURCE_CAPSULE = ROOT / "runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1"
ACTIVE_COORDINATES = 12
EXPECTED_SLOTS = ACTIVE_COORDINATES * len(HORIZON_ORDER)
EXPECTED_WORK = 2 * max(HORIZON_ORDER) * ACTIVE_COORDINATES


class O1C19CausalVaultRealArtifactTests(unittest.TestCase):
    """Exercise the real FAP -> frozen reader -> exact vault ABI without labels."""

    @classmethod
    def setUpClass(cls) -> None:
        if not SOURCE_CAPSULE.is_dir():
            raise unittest.SkipTest(
                "the immutable O1C-0018 source capsule is not locally available"
            )

    def test_real_fap_untrained_reader_transport_is_exact_and_label_free(self) -> None:
        with patch.object(
            ArtifactBuildEpisode,
            "labels_after_prediction_freeze",
            side_effect=AssertionError("real-artifact ABI smoke must not read labels"),
        ) as label_oracle:
            config = load_o1c19_causal_vault_bridge_run_config(CONFIG, root=ROOT)
            episode = config.corpus.episodes[0]
            controller = config.upstream_controller

            # An untrained reader is intentionally used here.  The test covers the
            # production ABI and invariants; only finalized O1C-0019 may supply a
            # scientifically trained held-out fold reader.
            from o1_crypto_lab.online_multiresolution_controller import (
                MultiResolutionCausalController,
            )

            source = MultiResolutionCausalController(controller)
            reader_bytes = source.reader_state_bytes()
            slow_state_bytes = source.slow_state_bytes()
            reader_sha256 = hashlib.sha256(reader_bytes).hexdigest()
            slow_state_sha256 = hashlib.sha256(slow_state_bytes).hexdigest()
            fold = O1C19FoldSource(
                fold_index=0,
                held_out_ordinal=episode.ordinal,
                target_id=episode.target_id,
                reader_bytes=reader_bytes,
                slow_state_bytes=slow_state_bytes,
                reader_sha256=reader_sha256,
                slow_state_sha256=slow_state_sha256,
                learning_freeze_sha256="0" * 64,
                prediction_freeze_sha256="0" * 64,
                upstream_learned_raw_prediction=np.zeros(KEY_BITS, dtype=np.float32),
                source_artifact_hashes={},
            )
            plan = NestedActiveCoordinatePlan(
                episode.pool.source_stream_sha256,
                COORDINATE_SALT,
            )
            coordinates = plan.active_coordinates(ACTIVE_COORDINATES)
            extraction = _fresh_extraction(
                fold,
                controller,
                episode.pool,
                coordinates,
                group_salt=COORDINATE_SALT,
            )
            repeated = _fresh_extraction(
                fold,
                controller,
                episode.pool,
                coordinates,
                group_salt=COORDINATE_SALT,
            )
            swapped = _fresh_extraction(
                fold,
                controller,
                episode.pool.polarity_swapped(),
                coordinates,
                group_salt=COORDINATE_SALT,
            )

            quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
                extraction.groups,
                horizons=HORIZON_ORDER,
            )
            self.assertEqual(
                FrozenMedianAbsQuantizer.from_bytes(quantizer.to_bytes()).to_bytes(),
                quantizer.to_bytes(),
            )
            shuffled = deterministic_coordinate_permutation(
                episode.pool.source_stream_sha256,
                COORDINATE_SALT,
                shuffled_destination=True,
            )
            core = StreamingSelectiveHolographicCore(config.causal_config.core_config)
            execution = _execute_extraction(
                config.causal_config,
                core,
                quantizer,
                extraction,
                shuffled,
            )
            swapped_execution = _execute_extraction(
                config.causal_config,
                core,
                quantizer,
                swapped,
                shuffled,
            )
            label_oracle.assert_not_called()

        self.assertEqual(extraction.to_bytes(), repeated.to_bytes())
        self.assertEqual(
            extraction.source_stream_sha256, episode.pool.source_stream_sha256
        )
        self.assertEqual(extraction.action_pool_sha256, episode.action_pool_sha256)
        self.assertEqual(extraction.reader_state_sha256, reader_sha256)
        self.assertEqual(extraction.slow_state_sha256, slow_state_sha256)
        self.assertEqual(extraction.active_coordinates, coordinates)
        self.assertEqual(extraction.ordered_horizons, HORIZON_ORDER)
        self.assertEqual(extraction.observed_slots, EXPECTED_SLOTS)
        self.assertEqual(extraction.physical_work_units, EXPECTED_WORK)
        for replay in (repeated, swapped):
            self.assertEqual(replay.observed_slots, EXPECTED_SLOTS)
            self.assertEqual(replay.physical_work_units, EXPECTED_WORK)
        self.assertEqual(
            sum(
                replay.physical_work_units for replay in (extraction, repeated, swapped)
            ),
            3 * EXPECTED_WORK,
        )
        self.assertTrue(
            all(
                np.isfinite(
                    np.asarray(group.incremental_deltas, dtype=np.float64)
                ).all()
                for group in extraction.groups
            )
        )
        self.assertTrue(
            any(
                delta != 0.0
                for group in extraction.groups
                for delta in group.incremental_deltas
            )
        )

        logits = _execution_logits(execution)
        self.assertEqual(logits.shape, (len(PREDICTION_ARMS), KEY_BITS))
        self.assertTrue(np.isfinite(logits).all())
        self.assertEqual(
            len(execution.state.primary_bytes(config.causal_config)),
            FORMAL_VAULT_BYTES,
        )
        report = execution.describe(config.causal_config)
        self.assertEqual(report["groups_offered"], ACTIVE_COORDINATES)
        self.assertEqual(report["groups_accepted"], ACTIVE_COORDINATES)
        self.assertEqual(report["slots_offered"], EXPECTED_SLOTS)
        self.assertEqual(report["slots_accepted"], EXPECTED_SLOTS)
        self.assertEqual(report["physical_work_offered"], EXPECTED_WORK)
        self.assertEqual(report["physical_work_accepted"], EXPECTED_WORK)

        swap_ok, delta_residual, logit_residual = _verify_actual_polarity_swap(
            extraction,
            swapped,
            execution,
            swapped_execution,
        )
        self.assertTrue(swap_ok)
        self.assertLessEqual(delta_residual, 1e-6)
        self.assertLessEqual(logit_residual, 1e-6)
        self.assertTrue(
            _verify_duplicate_probe(
                config.causal_config,
                core,
                quantizer,
                extraction,
            )
        )


if __name__ == "__main__":
    unittest.main()
