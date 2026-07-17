from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import numpy as np

from o1_crypto_lab.o1c19_causal_vault_bridge import (
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
)
from o1_crypto_lab.o1c19_causal_vault_bridge_run import (
    CALIBRATION_FREEZE_SCHEMA,
    PREDICTION_ARMS,
    PREDICTION_FREEZE_SCHEMA,
    O1C19FoldSource,
    O1C19Prerequisite,
    O1C19CausalVaultBridgeRunError,
    _score_report,
    _verify_commit_bound_files,
    _verify_upstream_capsule_config,
    fit_nonnegative_calibration_scale,
    load_o1c19_causal_vault_bridge_run_config,
    preflight_o1c19_causal_vault_bridge,
    main,
    run_o1c19_causal_vault_bridge_science,
)
from o1_crypto_lab.run_capsule import CapsuleVerification, FinalizedRun


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c19_causal_vault_bridge_v1.json"


class _StaticPlan:
    def __init__(self, order: tuple[int, ...]) -> None:
        self.order = order

    def active_coordinates(self, width: int) -> tuple[int, ...]:
        return self.order[:width]


class O1C19CausalVaultBridgeRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_o1c19_causal_vault_bridge_run_config(CONFIG, root=ROOT)

    def test_exact_config_and_pending_preflight_do_not_reserve_o1c22(self) -> None:
        self.assertEqual(self.config.causal_config.live_state_bytes, 352)
        self.assertEqual(self.config.budgets.maximum_o1c19_reader_replays, 32)
        self.assertEqual(self.config.budgets.maximum_packet_slot_observations, 17_664)
        self.assertEqual(
            self.config.budgets.maximum_physical_public_work_units, 1_130_496
        )
        reservation = ROOT / "runs/.attempt_ids/O1C-0022.json"
        existed = reservation.exists()
        with (
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.finalized_attempt",
                return_value=None,
            ),
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.recoverable_attempt_ids",
                return_value=(),
            ),
        ):
            preflight = preflight_o1c19_causal_vault_bridge(CONFIG, root=ROOT)
        self.assertEqual(preflight.report["status"], "prerequisite-pending")
        self.assertFalse(preflight.report["o1c22_reserved_by_this_preflight"])
        self.assertFalse(preflight.report["o1c22_existing_finalized"])
        self.assertFalse(preflight.report["o1c22_existing_recoverable"])
        self.assertEqual(reservation.exists(), existed)
        with (
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.finalized_attempt",
                return_value=None,
            ),
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.recoverable_attempt_ids",
                return_value=(),
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(["--config", str(CONFIG), "--preflight"]), 2)

        verification = CapsuleVerification(
            schema="test",
            path=ROOT / "runs/synthetic-o1c22",
            manifest_sha256="e" * 64,
            checked=1,
            missing=(),
            mismatched=(),
            unexpected=(),
        )
        existing = FinalizedRun(
            attempt_id="O1C-0022",
            path=verification.path,
            manifest_sha256="e" * 64,
            verification=verification,
        )
        with (
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.finalized_attempt",
                side_effect=lambda attempt: existing if attempt == "O1C-0022" else None,
            ),
            patch(
                "o1_crypto_lab.o1c19_causal_vault_bridge_run."
                "RunCapsuleManager.recoverable_attempt_ids",
                return_value=("O1C-0022",),
            ),
        ):
            existing_report = preflight_o1c19_causal_vault_bridge(
                CONFIG, root=ROOT
            ).report
        self.assertFalse(existing_report["o1c22_reserved_by_this_preflight"])
        self.assertTrue(existing_report["o1c22_existing_finalized"])
        self.assertTrue(existing_report["o1c22_existing_recoverable"])

    def test_upstream_capsule_commit_is_exactly_pinned(self) -> None:
        document = {
            "attempt_id": "O1C-0019",
            "claim_level": "RETROSPECTIVE",
            "commit": self.config.o1c19_science_commit,
            "config": self.config.upstream_top,
            "source_hashes": {"config": self.config.o1c19_config_sha256},
        }
        _verify_upstream_capsule_config(self.config, document)
        document["commit"] = "0" * 40
        with self.assertRaisesRegex(
            O1C19CausalVaultBridgeRunError, "science commit differs"
        ):
            _verify_upstream_capsule_config(self.config, document)

    def test_o1c21_state_defining_files_are_normatively_commit_bound(self) -> None:
        relatives = (
            "configs/causal_evidence_stream_256_v1.json",
            "src/o1_crypto_lab/causal_evidence_stream.py",
            "src/o1_crypto_lab/o1_streaming_core.py",
        )
        commitments = _verify_commit_bound_files(
            ROOT, self.config.o1c21_source_commit, relatives
        )
        self.assertEqual(set(commitments), set(relatives))
        with patch(
            "o1_crypto_lab.o1c19_causal_vault_bridge_run._git_blob_bytes",
            return_value=b"drifted-frozen-source",
        ):
            with self.assertRaisesRegex(
                O1C19CausalVaultBridgeRunError, "commit-bound source drifted"
            ):
                _verify_commit_bound_files(
                    ROOT, self.config.o1c21_source_commit, relatives
                )

    def test_strict_parser_rejects_extra_fields_and_inexact_work(self) -> None:
        source = json.loads(CONFIG.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            altered = json.loads(json.dumps(source))
            altered["experiment"]["unexpected"] = True
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                O1C19CausalVaultBridgeRunError, "experiment fields differ"
            ):
                load_o1c19_causal_vault_bridge_run_config(path, root=ROOT)

            altered = json.loads(json.dumps(source))
            altered["budgets"]["maximum_o1c19_reader_replays"] = 31
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                O1C19CausalVaultBridgeRunError, "exact frozen work 32"
            ):
                load_o1c19_causal_vault_bridge_run_config(path, root=ROOT)

    def test_nonnegative_calibration_grid_and_smallest_tie(self) -> None:
        zero = np.zeros((3, 256), dtype=np.float64)
        labels = np.zeros((3, 256), dtype=np.uint8)
        scale, nll, evaluations = fit_nonnegative_calibration_scale(zero, labels)
        self.assertEqual(scale, 0.0)
        self.assertAlmostEqual(nll, 768.0)
        self.assertEqual(evaluations, 401 * 3 * 256)

        signed = -np.ones((3, 256), dtype=np.float64)
        scale, _, _ = fit_nonnegative_calibration_scale(signed, labels)
        self.assertEqual(scale, 2.0)
        self.assertGreaterEqual(scale, 0.0)

    def _classification_fixture(
        self,
    ) -> tuple[
        np.ndarray,
        np.ndarray,
        np.ndarray,
        list[_StaticPlan],
        np.ndarray,
        np.ndarray,
        dict[str, bool],
    ]:
        labels = np.zeros((4, 256), dtype=np.uint8)
        plans = [_StaticPlan(tuple(range(256))) for _ in range(4)]
        raw = np.zeros((4, 4, len(PREDICTION_ARMS), 256), dtype=np.float64)
        calibrated = np.zeros_like(raw)
        signs = -np.ones(256, dtype=np.float64)
        for fold in range(4):
            for width_index, width in enumerate((12, 52, 128, 256)):
                for arm in (0, 1, 2):
                    raw[fold, width_index, arm, :width] = signs[:width]
                    calibrated[fold, width_index, arm, :width] = signs[:width]
        scales = np.ones((4, len(PREDICTION_ARMS)), dtype=np.float64)
        scales[:, -1] = 0.0
        anchor = np.tile(signs.astype(np.float32), (4, 1))
        integrity = {"synthetic_integrity": True}
        return raw, calibrated, labels, plans, scales, anchor, integrity

    def test_classification_precedence_and_pass_gate(self) -> None:
        fixture = self._classification_fixture()
        report, _, _ = _score_report(*fixture)
        self.assertEqual(report["classification"], "REAL_CAUSAL_VAULT_BUILD_LOO_PASS")
        self.assertEqual(report["failed_gates"], [])

        broken_integrity = dict(fixture[-1])
        broken_integrity["synthetic_integrity"] = False
        report, _, _ = _score_report(*fixture[:-1], broken_integrity)
        self.assertEqual(report["classification"], "INTEGRITY_OR_LIFECYCLE_FAILURE")

        collapse = fixture[1].copy()
        collapse[:, -1, 2] = 0.0
        collapse_raw = fixture[0].copy()
        collapse_raw[:, -1, 2] = 0.0
        report, _, _ = _score_report(
            collapse_raw,
            collapse,
            fixture[2],
            fixture[3],
            fixture[4],
            fixture[5],
            fixture[6],
        )
        self.assertEqual(report["classification"], "CROSS_COORDINATE_DILUTION")

        for control_index, gate_name in (
            (3, "int8_minus_last_horizon_only_mean_compression_positive"),
            (4, "int8_minus_unit_sign_sum_mean_compression_positive"),
        ):
            control_dominance = fixture[1].copy()
            control_dominance[:, -1, control_index] = control_dominance[:, -1, 2]
            control_dominance_raw = fixture[0].copy()
            control_dominance_raw[:, -1, control_index] = control_dominance_raw[
                :, -1, 2
            ]
            report, _, _ = _score_report(
                control_dominance_raw,
                control_dominance,
                fixture[2],
                fixture[3],
                fixture[4],
                fixture[5],
                fixture[6],
            )
            self.assertEqual(report["classification"], "CONTROL_SPECIFICITY_FAILURE")
            self.assertIn(gate_name, report["failed_gates"])

    def test_complete_synthetic_protocol_hits_exact_work_and_freezes(self) -> None:
        original_pool_hashes = {
            episode.pool.action_pool_sha256 for episode in self.config.corpus.episodes
        }

        def public_sign(source_stream_sha256: str, coordinate: int) -> float:
            digest = hashlib.sha256(
                bytes.fromhex(source_stream_sha256)
                + coordinate.to_bytes(2, "big")
                + b"o1c22-runner-test-public-sign"
            ).digest()
            return 1.0 if digest[0] & 1 else -1.0

        reader_bytes = [f"reader-{index}".encode() for index in range(4)]
        slow_bytes = [f"slow-{index}".encode() for index in range(4)]
        folds = []
        for index, episode in enumerate(self.config.corpus.episodes):
            signs = np.asarray(
                [
                    public_sign(episode.pool.source_stream_sha256, coordinate)
                    for coordinate in range(256)
                ],
                dtype=np.float32,
            )
            folds.append(
                O1C19FoldSource(
                    fold_index=index,
                    held_out_ordinal=index,
                    target_id=episode.target_id,
                    reader_bytes=reader_bytes[index],
                    slow_state_bytes=slow_bytes[index],
                    reader_sha256=hashlib.sha256(reader_bytes[index]).hexdigest(),
                    slow_state_sha256=hashlib.sha256(slow_bytes[index]).hexdigest(),
                    learning_freeze_sha256=hashlib.sha256(
                        f"learning-{index}".encode()
                    ).hexdigest(),
                    prediction_freeze_sha256=hashlib.sha256(
                        f"prediction-{index}".encode()
                    ).hexdigest(),
                    upstream_learned_raw_prediction=signs,
                    source_artifact_hashes={},
                )
            )
        verification = CapsuleVerification(
            schema="test",
            path=ROOT / "runs/synthetic-o1c19",
            manifest_sha256="a" * 64,
            checked=1,
            missing=(),
            mismatched=(),
            unexpected=(),
        )
        prerequisite = O1C19Prerequisite(
            finalized=FinalizedRun(
                attempt_id="O1C-0019",
                path=verification.path,
                manifest_sha256="a" * 64,
                verification=verification,
            ),
            folds=tuple(folds),
            artifact_index_sha256="b" * 64,
            result_sha256="c" * 64,
            source_artifact_bytes_read=self.config.corpus.bytes_read,
        )

        def fake_extract(
            fold: O1C19FoldSource,
            _controller: object,
            pool: object,
            coordinates: tuple[int, ...],
            *,
            group_salt: int,
        ) -> PacketDeltaExtraction:
            coordinate_tuple = tuple(coordinates)
            swapped = pool.action_pool_sha256 not in original_pool_hashes
            held_out_source = self.config.corpus.episodes[
                fold.held_out_ordinal
            ].pool.source_stream_sha256
            magnitude = 4.0 if pool.source_stream_sha256 == held_out_source else 1.0
            active_hash = active_coordinate_sequence_sha256(coordinate_tuple)
            groups = []
            for coordinate in coordinate_tuple:
                sign = public_sign(pool.source_stream_sha256, coordinate)
                if swapped:
                    sign = -sign
                groups.append(
                    PacketDeltaGroup(
                        source_stream_sha256=pool.source_stream_sha256,
                        action_pool_sha256=pool.action_pool_sha256,
                        reader_state_sha256=fold.reader_sha256,
                        active_coordinates_sha256=active_hash,
                        pair_sha256=pool.pair_sha256[coordinate],
                        coordinate=coordinate,
                        horizons=(64, 65, 96),
                        incremental_deltas=(
                            0.25 * magnitude * sign,
                            0.5 * magnitude * sign,
                            magnitude * sign,
                        ),
                        incremental_work_units=(128, 2, 62),
                        group_salt=group_salt,
                    )
                )
            return PacketDeltaExtraction(
                source_stream_sha256=pool.source_stream_sha256,
                action_pool_sha256=pool.action_pool_sha256,
                active_coordinates=coordinate_tuple,
                ordered_horizons=(64, 65, 96),
                groups=tuple(groups),
                reader_state_sha256=fold.reader_sha256,
                reader_state_bytes=len(fold.reader_bytes),
                slow_state_sha256=fold.slow_state_sha256,
                slow_state_bytes=len(fold.slow_state_bytes),
                final_fast_state_sha256="d" * 64,
                final_fast_state_bytes=1,
                physical_work_units=192 * len(coordinate_tuple),
                observed_slots=3 * len(coordinate_tuple),
            )

        calibration_documents = []
        prediction_documents = []

        def calibration_callback(artifacts: object, document: object) -> None:
            self.assertTrue(artifacts)
            self.assertEqual(document["schema"], CALIBRATION_FREEZE_SCHEMA)
            self.assertEqual(
                document["labels_used_by_this_fold_before_calibration_freeze"], []
            )
            self.assertFalse(document["held_out_label_used_for_this_fold"])
            calibration_documents.append(document)

        def prediction_callback(artifacts: object, document: object) -> None:
            self.assertTrue(artifacts)
            self.assertEqual(document["schema"], PREDICTION_FREEZE_SCHEMA)
            self.assertFalse(document["held_out_label_used_for_this_fold"])
            self.assertNotIn(
                document["held_out_ordinal"],
                document["calibration_label_ordinals_used_for_this_fold"],
            )
            self.assertTrue(
                any(name.endswith("packet_deltas.json") for name in artifacts)
            )
            self.assertTrue(
                any(name.endswith("calibration_scales.f64le") for name in artifacts)
            )
            prediction_documents.append(document)

        with patch(
            "o1_crypto_lab.o1c19_causal_vault_bridge_run._fresh_extraction",
            side_effect=fake_extract,
        ):
            result = run_o1c19_causal_vault_bridge_science(
                self.config,
                prerequisite,
                on_calibration_predictions_frozen=calibration_callback,
                on_heldout_predictions_frozen=prediction_callback,
            )
        self.assertEqual(len(calibration_documents), 4)
        self.assertEqual(len(prediction_documents), 4)
        self.assertEqual(result.reader_replays, 32)
        self.assertEqual(result.packet_slots, 17_664)
        self.assertEqual(result.public_work_units, 1_130_496)
        self.assertEqual(result.calibration_value_evaluations, 7_391_232)
        self.assertNotEqual(
            result.report["classification"], "INTEGRITY_OR_LIFECYCLE_FAILURE"
        )
        self.assertTrue(result.report["gates"]["integrity_gate_passed"])
        self.assertFalse(
            calibration_documents[0]["build_labels_may_have_been_opened_in_other_folds"]
        )
        self.assertTrue(
            calibration_documents[1]["build_labels_may_have_been_opened_in_other_folds"]
        )
        self.assertIn("upstream_o1c19_anchor.f32le", result.artifacts)


if __name__ == "__main__":
    unittest.main()
