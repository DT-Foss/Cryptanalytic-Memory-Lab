from __future__ import annotations

import hashlib
import math
import unittest

import numpy as np

from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
)
from o1_crypto_lab.living_inverse_reader_experiment import (
    DevelopmentReveal,
    SealedDevelopmentPanel,
)
from o1_crypto_lab.living_inverse_ridge import (
    FeatureSegment,
    FrozenHolographicRidge,
    HolographicFeaturePlan,
    serialize_ridge,
)
from o1_crypto_lab.signed_direct_replication import (
    PREDICTION_ARMS,
    FrozenReaderSource,
    SignedDirectReplicationConfig,
    conditional_uniform_compression_null,
    conditional_uniform_paired_null,
    run_signed_direct_replication,
)


def _model_blob(*, reverse: bool = False) -> bytes:
    plan = HolographicFeaturePlan(
        input_dimension=640,
        slots=32,
        seed=137256,
        segments=(
            FeatureSegment("target_output", 0, 512),
            FeatureSegment("public_relation", 512, 640),
        ),
        interactions=(("target_output", "public_relation"),),
    )
    intercept = np.linspace(-0.2, 0.2, 256, dtype=np.float64)
    if reverse:
        intercept = intercept[::-1].copy()
    model = FrozenHolographicRidge(
        plan=plan,
        ridge_lambda=1.0,
        requested_rank=1,
        effective_rank=1,
        feature_mean=np.zeros(96, dtype=np.float64),
        feature_scale=np.ones(96, dtype=np.float64),
        key_mean=intercept,
        key_weights=np.zeros((96, 256), dtype=np.float64),
        singular_values=np.ones(1, dtype=np.float64),
        auxiliary_dimension=0,
    )
    return serialize_ridge(model)


class SignedDirectStatisticsTests(unittest.TestCase):
    def test_uniform_posterior_has_degenerate_zero_null(self) -> None:
        probabilities = np.full((2, 256), 0.5, dtype=np.float64)
        labels = np.vstack(
            [np.zeros(256, dtype=np.float64), np.ones(256, dtype=np.float64)]
        )
        report = conditional_uniform_compression_null(probabilities, labels)
        self.assertEqual(report["null_mean_bits"], 0.0)
        self.assertEqual(report["null_standard_deviation_bits"], 0.0)
        self.assertEqual(report["z_score"], 0.0)
        self.assertEqual(report["effective_weighted_terms"], 0.0)

    def test_one_active_log2_bit_matches_weighted_rademacher_fixture(self) -> None:
        probabilities = np.full((1, 256), 0.5, dtype=np.float64)
        probabilities[0, 0] = 2.0 / 3.0
        labels = np.zeros((1, 256), dtype=np.float64)
        labels[0, 0] = 1.0
        report = conditional_uniform_compression_null(probabilities, labels)
        self.assertAlmostEqual(report["null_mean_bits"], -0.08496250072115613)
        self.assertAlmostEqual(report["null_standard_deviation_bits"], 0.5)
        self.assertAlmostEqual(report["observed_minus_null_bits"], 0.5)
        self.assertAlmostEqual(report["z_score"], 1.0)
        self.assertAlmostEqual(
            report["normal_approx_one_sided_p_value"],
            0.5 * math.erfc(1.0 / math.sqrt(2.0)),
        )

    def test_paired_fixture_and_identical_degenerate_control(self) -> None:
        direct = np.full((1, 256), 0.5, dtype=np.float64)
        control = direct.copy()
        direct[0, 0] = 2.0 / 3.0
        control[0, 0] = 1.0 / 3.0
        labels = np.zeros((1, 256), dtype=np.float64)
        labels[0, 0] = 1.0
        report = conditional_uniform_paired_null(direct, control, labels)
        self.assertAlmostEqual(report["null_mean_bits"], 0.0)
        self.assertAlmostEqual(report["null_standard_deviation_bits"], 1.0)
        self.assertAlmostEqual(report["observed_minus_null_bits"], 1.0)
        self.assertAlmostEqual(report["z_score"], 1.0)
        degenerate = conditional_uniform_paired_null(direct, direct, labels)
        self.assertEqual(degenerate["null_standard_deviation_bits"], 0.0)
        self.assertEqual(degenerate["z_score"], 0.0)


class SignedDirectReplicationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.direct_blob = _model_blob()
        self.shuffled_blob = _model_blob(reverse=True)
        self.source = FrozenReaderSource(
            source_attempt_id="O1C-TEST-SOURCE",
            source_capsule="runs/test-source",
            source_manifest_sha256="a" * 64,
            source_result_sha256="b" * 64,
            direct_model_artifact="artifacts/direct.o1hrr",
            direct_model_sha256=hashlib.sha256(self.direct_blob).hexdigest(),
            shuffled_model_artifact="artifacts/shuffled.o1hrr",
            shuffled_model_sha256=hashlib.sha256(self.shuffled_blob).hexdigest(),
            direct_scale=-0.125,
            shuffled_scale=-0.0625,
            selection_origin="unit-test post-reveal hypothesis",
        )
        self.config = SignedDirectReplicationConfig(
            development_targets=4,
            minimum_direct_compression_bits=0.015,
            minimum_direct_conditional_z=3.0,
            minimum_target_lcb_z=3.0,
            minimum_shuffled_margin_bits=0.01,
            minimum_output_permutation_margin_bits=0.01,
            minimum_paired_conditional_z=3.0,
        )

    def test_no_refit_protocol_freezes_before_panel_and_predictions_before_reveal(
        self,
    ) -> None:
        events: list[str] = []
        brokers: list[Full256TargetBroker] = []
        publications: list[dict[str, object]] = []

        def freeze_protocol(document, blobs):
            self.assertEqual(events, [])
            self.assertEqual(document["development_targets_created"], 0)
            self.assertFalse(document["models_refit"])
            self.assertEqual(set(blobs), {"direct", "shuffled_key_control"})
            events.append("protocol_frozen")
            return {
                "schema": "o1-256-signed-direct-protocol-freeze-receipt-v1",
                "persisted": True,
                "protocol_sha256": hashlib.sha256(
                    repr(document).encode("utf-8")
                ).hexdigest(),
            }

        def open_panel():
            self.assertEqual(events, ["protocol_frozen"])
            events.append("panel_opened")
            for index in range(self.config.development_targets):
                entropy = hashlib.shake_256(
                    f"signed-replication-test/{index}".encode("ascii")
                ).digest(ENTROPY_BYTES)
                broker = Full256TargetBroker(
                    entropy_source=lambda size, value=entropy: (
                        value if size == ENTROPY_BYTES else b""
                    ),
                    entropy_source_id="test.deterministic-v1",
                    target_id=f"signed-test-{index:04d}",
                )
                brokers.append(broker)
                publications.append(broker.publish())
            return SealedDevelopmentPanel(
                target_ids=tuple(str(row["target_id"]) for row in publications),
                public_targets=tuple(
                    public_view_from_publication(row) for row in publications
                ),
                publications=tuple(publications),
            )

        def freeze_and_reveal(blob, index):
            self.assertEqual(events, ["protocol_frozen", "panel_opened"])
            self.assertEqual(len(blob), 6 * 4 * 256 * 8)
            self.assertEqual(
                tuple(row["name"] for row in index["matrices"]), PREDICTION_ARMS
            )
            events.append("predictions_frozen")
            keys = []
            for broker, publication in zip(brokers, publications, strict=True):
                receipt = make_freeze_receipt(
                    publication, frozen_artifact_sha256=index["sha256"]
                )
                reveal = broker.reveal(receipt)
                keys.append(bytes.fromhex(reveal["commitment_preimage"]["key_hex"]))
            return DevelopmentReveal(
                keys=tuple(keys),
                receipt={
                    "schema": "o1-256-development-panel-reveal-receipt-v1",
                    "predictions_frozen_before_reveal": True,
                    "frozen_prediction_sha256": index["sha256"],
                    "frozen_prediction_index_sha256": index["index_sha256"],
                },
            )

        result = run_signed_direct_replication(
            self.config,
            self.source,
            direct_model_blob=self.direct_blob,
            shuffled_model_blob=self.shuffled_blob,
            source_provenance={
                "source_capsule_verified": True,
                "source_manifest_sha256": "a" * 64,
                "source_result_sha256": "b" * 64,
            },
            open_sealed_development=open_panel,
            freeze_predictions_and_reveal=freeze_and_reveal,
            on_protocol_frozen=freeze_protocol,
            require_protocol_persistence=True,
        )
        self.assertEqual(
            events, ["protocol_frozen", "panel_opened", "predictions_frozen"]
        )
        self.assertTrue(result.execution_success_gate_passed)
        self.assertFalse(result.report["protocol"]["source_models_refit"])
        self.assertEqual(
            result.report["attacker_contract"]["unknown_target_key_bits"], 256
        )
        self.assertEqual(len(result.prediction_blob), 6 * 4 * 256 * 8)
        self.assertEqual(set(result.report["evaluation"]["arms"]), set(PREDICTION_ARMS))

    def test_production_requires_protocol_persistence(self) -> None:
        with self.assertRaisesRegex(ValueError, "persisted protocol callback"):
            run_signed_direct_replication(
                self.config,
                self.source,
                direct_model_blob=self.direct_blob,
                shuffled_model_blob=self.shuffled_blob,
                source_provenance={
                    "source_capsule_verified": True,
                    "source_manifest_sha256": "a" * 64,
                    "source_result_sha256": "b" * 64,
                },
                open_sealed_development=lambda: None,  # type: ignore[arg-type]
                freeze_predictions_and_reveal=lambda _blob, _index: None,  # type: ignore[arg-type]
                require_protocol_persistence=True,
            )

    def test_model_hash_mismatch_fails_before_panel_creation(self) -> None:
        opened = False

        def open_panel():
            nonlocal opened
            opened = True
            return None

        with self.assertRaisesRegex(ValueError, "source model SHA-256 differs"):
            run_signed_direct_replication(
                self.config,
                self.source,
                direct_model_blob=self.direct_blob + b"tamper",
                shuffled_model_blob=self.shuffled_blob,
                source_provenance={
                    "source_capsule_verified": True,
                    "source_manifest_sha256": "a" * 64,
                    "source_result_sha256": "b" * 64,
                },
                open_sealed_development=open_panel,  # type: ignore[arg-type]
                freeze_predictions_and_reveal=lambda _blob, _index: None,  # type: ignore[arg-type]
            )
        self.assertFalse(opened)


if __name__ == "__main__":
    unittest.main()
