from __future__ import annotations

import hashlib
import unittest

from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
)
from o1_crypto_lab.living_inverse_reader_experiment import (
    DevelopmentReveal,
    LivingInverseReaderConfig,
    SealedDevelopmentPanel,
    _orient_correction_scores,
    run_living_inverse_reader_experiment,
)
from o1_crypto_lab.living_inverse_ridge import deserialize_ridge


class LivingInverseReaderExperimentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = LivingInverseReaderConfig(
            train_structured_targets=4,
            train_uniform_targets=4,
            calibration_targets=4,
            development_targets=6,
            candidates_per_target=4,
            corpus_seed=11,
            relation_seed=13,
            candidate_seed=17,
            feature_seed=19,
            feature_slots=8,
            ridge_lambda=1.0,
            rank=4,
            auxiliary_weight=0.25,
            shrinkage_grid=(0.0, 0.25, 0.5, 1.0),
            confidence_threshold=0.75,
            stable_accuracy=0.55,
            stable_nll_gain=0.002,
            familywise_alpha=0.05,
            maximum_selected_bits=8,
            signal_compression_bits=0.25,
            signal_control_margin_bits=0.1,
            decoy_count=32,
            decoy_seed=23,
            beam_uncertain_bits=4,
            beam_size=16,
        )

    def _development_callbacks(self, events=None):
        events = [] if events is None else events
        brokers = []
        publications = []

        def open_panel():
            self.assertFalse(brokers)
            if events:
                self.assertEqual(events[-1], "calibration_frozen")
            events.append("development_opened")
            for index in range(self.config.development_targets):
                entropy = hashlib.shake_256(
                    f"sealed-test/{index}".encode("ascii")
                ).digest(ENTROPY_BYTES)
                broker = Full256TargetBroker(
                    entropy_source=lambda size, value=entropy: (
                        value if size == ENTROPY_BYTES else b""
                    ),
                    entropy_source_id="test.deterministic-v1",
                    target_id=f"test-dev-{index:04d}",
                )
                publication = broker.publish()
                brokers.append(broker)
                publications.append(publication)
            return SealedDevelopmentPanel(
                target_ids=tuple(
                    str(publication["target_id"]) for publication in publications
                ),
                public_targets=tuple(
                    public_view_from_publication(publication)
                    for publication in publications
                ),
                publications=tuple(publications),
            )

        def freeze_and_reveal(blob, index):
            self.assertEqual(events[-1], "development_opened")
            events.append("predictions_frozen")
            frozen_sha = hashlib.sha256(blob).hexdigest()
            self.assertEqual(frozen_sha, index["sha256"])
            keys = []
            reveal_hashes = []
            for broker, publication in zip(brokers, publications, strict=True):
                receipt = make_freeze_receipt(
                    publication, frozen_artifact_sha256=frozen_sha
                )
                reveal = broker.reveal(receipt)
                keys.append(bytes.fromhex(reveal["commitment_preimage"]["key_hex"]))
                reveal_hashes.append(reveal["reveal_sha256"])
            return DevelopmentReveal(
                keys=tuple(keys),
                receipt={
                    "schema": "o1-256-development-panel-reveal-receipt-v1",
                    "predictions_frozen_before_reveal": True,
                    "frozen_prediction_sha256": frozen_sha,
                    "frozen_prediction_index_sha256": index["index_sha256"],
                    "reveal_root": hashlib.sha256(
                        "".join(reveal_hashes).encode("ascii")
                    ).hexdigest(),
                },
            )

        return open_panel, freeze_and_reveal

    def test_full_width_reader_is_deterministic_and_freezes_before_dev(self) -> None:
        freezes = []
        events = []

        def freeze(document, model_blobs):
            self.assertEqual(document["development_targets_created"], 0)
            self.assertEqual(document["development_labels_read"], 0)
            self.assertEqual(
                set(model_blobs),
                {
                    "direct",
                    "relative",
                    "distilled",
                    "shuffled_key_control",
                },
            )
            freezes.append(document["primary_arm"])
            events.append("calibration_frozen")
            return {
                "schema": "o1-256-calibration-freeze-receipt-v1",
                "persisted": True,
                "selection_sha256": hashlib.sha256(
                    document["primary_arm"].encode("ascii")
                ).hexdigest(),
            }

        first_open, first_reveal = self._development_callbacks(events)
        first = run_living_inverse_reader_experiment(
            self.config,
            open_sealed_development=first_open,
            freeze_predictions_and_reveal=first_reveal,
            on_calibration_frozen=freeze,
            require_calibration_persistence=True,
        )
        second_events = []

        def second_freeze(document, model_blobs):
            second_events.append("calibration_frozen")
            freezes.append(document["primary_arm"])
            return {
                "schema": "o1-256-calibration-freeze-receipt-v1",
                "persisted": True,
                "selection_sha256": hashlib.sha256(
                    document["primary_arm"].encode("ascii")
                ).hexdigest(),
            }

        second_open, second_reveal = self._development_callbacks(second_events)
        second = run_living_inverse_reader_experiment(
            self.config,
            open_sealed_development=second_open,
            freeze_predictions_and_reveal=second_reveal,
            on_calibration_frozen=second_freeze,
            require_calibration_persistence=True,
        )
        self.assertEqual(first.report, second.report)
        self.assertEqual(first.posterior_blob, second.posterior_blob)
        self.assertEqual(len(freezes), 2)
        self.assertEqual(
            events,
            ["calibration_frozen", "development_opened", "predictions_frozen"],
        )
        self.assertTrue(first.execution_success_gate_passed)
        self.assertEqual(
            first.report["attacker_contract"]["unknown_target_key_bits"], 256
        )
        self.assertEqual(
            first.report["attacker_contract"]["target_trace_fields_in_deployment"],
            0,
        )
        self.assertFalse(first.report["attacker_contract"]["reduced_width_target"])
        self.assertGreaterEqual(len(first.posterior_index["matrices"]), 7)
        self.assertIn(
            "factual/direct",
            {row["name"] for row in first.posterior_index["matrices"]},
        )
        self.assertTrue(first.report["protocol"]["fresh_target_generated"])
        self.assertTrue(
            first.report["protocol"]["development_predictions_frozen_before_reveal"]
        )
        self.assertTrue(
            first.report["protocol"]["development_keys_absent_from_committed_config"]
        )
        for selection in first.report["calibration"]["frozen_bit_selections"].values():
            self.assertFalse(selection["development_statistics_used_for_selection"])
        for transfer in first.report["development"]["cross_split_bits"].values():
            self.assertFalse(transfer["unselected_development_bits_used_for_claim"])
        self.assertEqual(
            first.report["bounded_live_state"][
                "maximum_persistent_bytes_per_target_arm"
            ],
            2056,
        )
        for name, blob in first.model_blobs.items():
            self.assertEqual(
                deserialize_ridge(blob).describe()["model_sha256"],
                hashlib.sha256(blob).hexdigest(),
                name,
            )

    def test_production_requires_persistence_receipt(self) -> None:
        open_panel, reveal = self._development_callbacks()
        with self.assertRaisesRegex(ValueError, "persisted calibration callback"):
            run_living_inverse_reader_experiment(
                self.config,
                open_sealed_development=open_panel,
                freeze_predictions_and_reveal=reveal,
                require_calibration_persistence=True,
            )

    def test_config_mapping_is_strict(self) -> None:
        value = self.config.describe()
        self.assertEqual(LivingInverseReaderConfig.from_mapping(value), self.config)
        value = self.config.describe()
        value["development_targets"] = 1
        with self.assertRaises(ValueError):
            LivingInverseReaderConfig.from_mapping(value)

    def test_correction_polarity_rotates_into_target_bit_space(self) -> None:
        candidate = [[0.0, 1.0] + [0.0] * 254]
        # target bits [1, 1] imply correction bits [1, 0], hence signed
        # correction evidence [+,-].  Rotating by the candidate yields [+,+].
        correction_scores = [[3.0, -2.0] + [0.0] * 254]
        oriented = _orient_correction_scores(correction_scores, candidate)
        self.assertEqual(oriented[0, :2].tolist(), [3.0, 2.0])
        value = self.config.describe()
        value["extra"] = 1
        with self.assertRaises(ValueError):
            LivingInverseReaderConfig.from_mapping(value)


if __name__ == "__main__":
    unittest.main()
