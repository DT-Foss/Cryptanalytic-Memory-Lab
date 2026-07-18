from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace
from unittest.mock import patch

import numpy as np
import o1_crypto_lab.o1c29_stacked_hot_calibration as stacked_hot

from o1_crypto_lab.o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
)
from o1_crypto_lab.o1c29_stacked_hot_calibration import (
    AllowlistedFoldLabelBroker,
    O1C29StackedHotCalibrationError,
    OwnerPacketCorpus,
    PROTOCOL,
    StackedHotCalibrationConfig,
    fit_outer_fold,
    freeze_all_owner_states,
    freeze_owner_quantizer,
    predict_outer_fold,
    run_stacked_hot_calibration,
    run_stacked_hot_calibration_from_freeze,
)


FOLDS = ("A", "B", "C", "D")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _bit(label: str) -> int:
    return hashlib.sha256(label.encode("ascii")).digest()[0] & 1


def _fixture_labels() -> dict[str, np.ndarray]:
    return {
        fold: np.asarray(
            [_bit(f"o1c29-label/{fold}/{coordinate}") for coordinate in range(256)],
            dtype=np.uint8,
        )
        for fold in FOLDS
    }


def _fixture_packet(
    *,
    owner: str,
    episode: str,
    labels: dict[str, np.ndarray],
) -> PacketDeltaExtraction:
    owner_index = FOLDS.index(owner)
    episode_index = FOLDS.index(episode)
    coordinates = tuple(range(256))
    active_sha = active_coordinate_sequence_sha256(coordinates)
    reader_sha = _digest(f"reader/{owner}")
    source_sha = _digest(f"source/{episode}")
    action_sha = _digest(f"action-pool/{episode}")
    groups = []
    for coordinate in coordinates:
        sign = 1.0 if labels[episode][coordinate] else -1.0
        nuisance64 = 1.0 if _bit(f"nuisance64/{owner}/{episode}/{coordinate}") else -1.0
        nuisance65 = 1.0 if _bit(f"nuisance65/{owner}/{episode}/{coordinate}") else -1.0
        groups.append(
            PacketDeltaGroup(
                source_stream_sha256=source_sha,
                action_pool_sha256=action_sha,
                reader_state_sha256=reader_sha,
                active_coordinates_sha256=active_sha,
                pair_sha256=_digest(f"pair/{episode}/{coordinate}"),
                coordinate=coordinate,
                horizons=(64, 65, 96),
                incremental_deltas=(
                    0.0625 * nuisance64,
                    0.125 * nuisance65,
                    (1.0 + owner_index / 16.0 + episode_index / 64.0) * sign,
                ),
                incremental_work_units=(128, 2, 62),
                group_salt=29_000 + owner_index,
            )
        )
    return PacketDeltaExtraction(
        source_stream_sha256=source_sha,
        action_pool_sha256=action_sha,
        active_coordinates=coordinates,
        ordered_horizons=(64, 65, 96),
        groups=tuple(groups),
        reader_state_sha256=reader_sha,
        reader_state_bytes=128,
        slow_state_sha256=_digest(f"slow/{owner}"),
        slow_state_bytes=64,
        final_fast_state_sha256=_digest(f"fast/{owner}/{episode}"),
        final_fast_state_bytes=512,
        physical_work_units=256 * 192,
        observed_slots=256 * 3,
    )


def _fixture() -> tuple[
    StackedHotCalibrationConfig,
    tuple[OwnerPacketCorpus, ...],
    dict[str, np.ndarray],
]:
    config = StackedHotCalibrationConfig(
        fold_ids=FOLDS,
        alpha=1.0,
        confidence_temperature_grid=(0.5, 1.0, 2.0, 4.0),
    )
    labels = _fixture_labels()
    corpora = []
    for owner in FOLDS:
        quantizer = FrozenMedianAbsQuantizer(
            horizons=(64, 65, 96),
            scales=(1.0, 1.0, 1.0),
            total_counts=(768, 768, 768),
            nonzero_counts=(768, 768, 768),
            public_replay_ledger_sha256=_digest(f"quantizer-ledger/{owner}"),
        )
        binding = freeze_owner_quantizer(
            config,
            owner_fold=owner,
            reader_state_sha256=_digest(f"reader/{owner}"),
            quantizer=quantizer,
        )
        corpora.append(
            OwnerPacketCorpus(
                owner_fold=owner,
                quantizer=binding,
                episode_packets=tuple(
                    (
                        episode,
                        _fixture_packet(
                            owner=owner,
                            episode=episode,
                            labels=labels,
                        ),
                    )
                    for episode in FOLDS
                ),
            )
        )
    return config, tuple(corpora), labels


class GlobalStateBarrierTests(unittest.TestCase):
    def test_label_broker_rejects_lossy_dtype_coercion(self) -> None:
        config, _corpora, labels = _fixture()
        fractional = {fold: row.copy() for fold, row in labels.items()}
        fractional["A"] = fractional["A"].astype(np.float64)
        fractional["A"][0] = 0.5
        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "labels must be uint8"
        ):
            AllowlistedFoldLabelBroker(config, fractional)

        wrong_width = {fold: row.copy() for fold, row in labels.items()}
        wrong_width["A"] = wrong_width["A"][:-1]
        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "exactly 256 bits"
        ):
            AllowlistedFoldLabelBroker(config, wrong_width)

    def test_all_sixteen_owner_states_freeze_before_label_access(self) -> None:
        config, corpora, labels = _fixture()
        broker = AllowlistedFoldLabelBroker(config, labels)
        with self.assertRaisesRegex(O1C29StackedHotCalibrationError, "early-label"):
            broker.grant("A")

        freeze = freeze_all_owner_states(config, corpora)
        self.assertEqual(len(freeze.states), 16)
        self.assertEqual(freeze.label_accesses_before_freeze, 0)
        self.assertTrue(
            freeze.receipt_document()["all_states_frozen_before_any_label_access"]
        )
        self.assertEqual(
            tuple((row.owner_fold, row.episode_fold) for row in freeze.states),
            tuple((owner, episode) for owner in FOLDS for episode in FOLDS),
        )
        for row in freeze.states:
            self.assertEqual(
                row.inherited_label_ancestry,
                tuple(fold for fold in FOLDS if fold != row.owner_fold),
            )
            self.assertNotIn(row.owner_fold, row.inherited_label_ancestry)
            self.assertEqual(row.receipt_document()["direct_label_accesses"], 0)

        broker.activate(freeze)
        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "heldout-excluding allowlist"
        ):
            broker.grant("A", requested_folds=("A", "B", "C"))
        grant = broker.grant("A")
        self.assertEqual(grant.granted_folds, ("B", "C", "D"))
        self.assertEqual(grant.receipt_document()["denied_fold"], "A")

    def test_wrong_owner_reader_and_quantizer_are_rejected(self) -> None:
        config, corpora, _labels = _fixture()
        wrong_quantizer = replace(corpora[0], quantizer=corpora[1].quantizer)
        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "wrong-owner or wrong-quantizer"
        ):
            freeze_all_owner_states(config, (wrong_quantizer, *corpora[1:]))

        wrong_reader = replace(corpora[0], episode_packets=corpora[1].episode_packets)
        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "wrong-owner reader"
        ):
            freeze_all_owner_states(config, (wrong_reader, *corpora[1:]))


class FoldSafeFitTests(unittest.TestCase):
    def test_wrong_owner_and_heldout_state_substitutions_are_rejected(self) -> None:
        config, corpora, labels = _fixture()
        freeze = freeze_all_owner_states(config, corpora)
        broker = AllowlistedFoldLabelBroker(config, labels)
        broker.activate(freeze)
        grant = broker.grant("A")

        with self.assertRaisesRegex(O1C29StackedHotCalibrationError, "wrong-owner"):
            fit_outer_fold(
                config,
                freeze,
                grant,
                outer_fold="A",
                training_state_refs=(("B", "B"), ("A", "C"), ("A", "D")),
            )
        with self.assertRaisesRegex(O1C29StackedHotCalibrationError, "heldout-state"):
            fit_outer_fold(
                config,
                freeze,
                grant,
                outer_fold="A",
                training_state_refs=(("A", "A"), ("A", "C"), ("A", "D")),
            )

        fit = fit_outer_fold(config, freeze, grant, outer_fold="A")
        self.assertEqual(fit.calibration_folds, ("B", "C", "D"))
        self.assertEqual(fit.inherited_label_ancestry, ("B", "C", "D"))
        self.assertNotIn("A", fit.inherited_label_ancestry)
        self.assertFalse(fit.receipt_document()["heldout_state_is_fit_input"])

        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "exact owner-fold heldout"
        ):
            predict_outer_fold(
                config,
                freeze,
                fit,
                outer_fold="A",
                heldout_state_ref=("A", "B"),
            )

    def test_heldout_label_flip_leaves_own_fit_and_logits_byte_identical(self) -> None:
        config, corpora, labels = _fixture()
        freeze = freeze_all_owner_states(config, corpora)
        flipped = {fold: row.copy() for fold, row in labels.items()}
        flipped["A"] = np.uint8(1) - flipped["A"]

        broker_first = AllowlistedFoldLabelBroker(config, labels)
        broker_second = AllowlistedFoldLabelBroker(config, flipped)
        broker_first.activate(freeze)
        broker_second.activate(freeze)
        first_grant = broker_first.grant("A")
        second_grant = broker_second.grant("A")
        self.assertEqual(first_grant.receipt_sha256, second_grant.receipt_sha256)

        first_fit = fit_outer_fold(config, freeze, first_grant, outer_fold="A")
        second_fit = fit_outer_fold(config, freeze, second_grant, outer_fold="A")
        self.assertEqual(first_fit.receipt_sha256, second_fit.receipt_sha256)
        self.assertEqual(
            first_fit.simplex_fit.fit_receipt_sha256,
            second_fit.simplex_fit.fit_receipt_sha256,
        )

        first_prediction = predict_outer_fold(config, freeze, first_fit, outer_fold="A")
        second_prediction = predict_outer_fold(
            config, freeze, second_fit, outer_fold="A"
        )
        self.assertEqual(
            first_prediction.primary_logits_bytes,
            second_prediction.primary_logits_bytes,
        )
        self.assertEqual(
            first_prediction.secondary_logits_bytes,
            second_prediction.secondary_logits_bytes,
        )
        self.assertEqual(
            first_prediction.receipt_sha256,
            second_prediction.receipt_sha256,
        )


class OutcomeIndependentPredictionTests(unittest.TestCase):
    def test_existing_freeze_is_reused_without_duplicate_state_consumption(
        self,
    ) -> None:
        config, corpora, labels = _fixture()
        selector_sha = _digest("authoritative-o1c23-context")
        original_consume = stacked_hot.consume_dense_horizon_major_stream
        with patch.object(
            stacked_hot,
            "consume_dense_horizon_major_stream",
            wraps=original_consume,
        ) as consume:
            baseline = run_stacked_hot_calibration(
                config,
                corpora,
                AllowlistedFoldLabelBroker(config, labels),
                actual_o1c23_selector_sha256=selector_sha,
            )
            self.assertEqual(consume.call_count, 16)

            consume.reset_mock()
            freeze = freeze_all_owner_states(config, corpora)
            self.assertEqual(consume.call_count, 16)
            broker = AllowlistedFoldLabelBroker(config, labels)
            broker.activate(freeze)
            reused = run_stacked_hot_calibration_from_freeze(
                config,
                freeze,
                broker,
                actual_o1c23_selector_sha256=selector_sha,
            )
            self.assertEqual(consume.call_count, 16)

        self.assertIs(reused.global_freeze, freeze)
        self.assertTrue(
            all(
                reused_state is frozen_state
                for reused_state, frozen_state in zip(
                    reused.global_freeze.states,
                    freeze.states,
                    strict=True,
                )
            )
        )
        self.assertEqual(reused.receipt_sha256, baseline.receipt_sha256)
        self.assertEqual(
            [row.receipt_sha256 for row in reused.fits],
            [row.receipt_sha256 for row in baseline.fits],
        )
        self.assertEqual(
            [row.receipt_sha256 for row in reused.predictions],
            [row.receipt_sha256 for row in baseline.predictions],
        )

    def test_o1c23_hash_is_context_only_and_cannot_select_science(self) -> None:
        config, corpora, labels = _fixture()
        freeze = freeze_all_owner_states(config, corpora)
        broker = AllowlistedFoldLabelBroker(config, labels)
        broker.activate(freeze)
        fit = fit_outer_fold(config, freeze, broker.grant("A"), outer_fold="A")

        with self.assertRaisesRegex(
            O1C29StackedHotCalibrationError, "cannot select a clean arm"
        ):
            predict_outer_fold(
                config,
                freeze,
                fit,
                outer_fold="A",
                actual_o1c23_selector_sha256=_digest("selector/one"),
                actual_o1c23_selector_used_for_scientific_selection=True,
            )

        first = predict_outer_fold(
            config,
            freeze,
            fit,
            outer_fold="A",
            actual_o1c23_selector_sha256=_digest("selector/one"),
        )
        second = predict_outer_fold(
            config,
            freeze,
            fit,
            outer_fold="A",
            actual_o1c23_selector_sha256=_digest("selector/two"),
        )
        self.assertEqual(first.primary_logits_bytes, second.primary_logits_bytes)
        self.assertEqual(first.secondary_logits_bytes, second.secondary_logits_bytes)
        self.assertNotEqual(first.receipt_sha256, second.receipt_sha256)
        self.assertFalse(
            first.receipt_document()[
                "actual_o1c23_selector_used_for_scientific_selection"
            ]
        )
        self.assertNotEqual(
            first.primary_binding_sha256, first.secondary_binding_sha256
        )
        self.assertTrue(first.state_unchanged)

    def test_complete_four_fold_protocol_is_deterministic_and_unscored(self) -> None:
        config, corpora, labels = _fixture()
        broker = AllowlistedFoldLabelBroker(config, labels)
        selector_sha = _digest("authoritative-o1c23-context")
        result = run_stacked_hot_calibration(
            config,
            corpora,
            broker,
            actual_o1c23_selector_sha256=selector_sha,
        )
        self.assertEqual(len(result.global_freeze.states), 16)
        self.assertEqual(len(result.fits), 4)
        self.assertEqual(len(result.predictions), 4)
        self.assertEqual(broker.direct_label_accesses, 12)
        self.assertEqual(result.receipt_document()["classification"], PROTOCOL)
        self.assertEqual(
            result.receipt_document()["heldout_labels_opened_for_scoring"], 0
        )
        self.assertFalse(
            result.receipt_document()[
                "actual_o1c23_selector_used_for_scientific_selection"
            ]
        )
        for prediction in result.predictions:
            expected = labels[prediction.outer_fold]
            actual = (prediction.primary_logits() > 0.0).astype(np.uint8)
            self.assertTrue(np.array_equal(actual, expected))
            self.assertNotIn(prediction.outer_fold, prediction.inherited_label_ancestry)

        second = run_stacked_hot_calibration(
            config,
            corpora,
            AllowlistedFoldLabelBroker(config, labels),
            actual_o1c23_selector_sha256=selector_sha,
        )
        self.assertEqual(result.receipt_sha256, second.receipt_sha256)
        self.assertEqual(
            [row.primary_logits_sha256 for row in result.predictions],
            [row.primary_logits_sha256 for row in second.predictions],
        )
        with self.assertRaises((TypeError, ValueError)):
            replace(  # type: ignore[call-arg]
                result.predictions[0], receipt_sha256="f" * 64
            )


if __name__ == "__main__":
    unittest.main()
