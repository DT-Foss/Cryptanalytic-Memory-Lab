from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import unittest
from dataclasses import replace

import numpy as np

import o1_crypto_lab.o1c29_packet_corpus as packet_corpus
import o1_crypto_lab.o1c29_real_protocol as real_protocol
from o1_crypto_lab.o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
)
from o1_crypto_lab.o1c29_packet_corpus import (
    PACKET_CORPUS_SCHEMA,
    VerifiedO1C22OwnerFold,
    VerifiedO1C22Packet,
    VerifiedO1C22PacketCorpus,
    VerifiedO1C22Quantizer,
)
from o1_crypto_lab.o1c29_real_protocol import (
    CANONICAL_FOLD_IDS,
    GLOBAL_FRONTIER_TIE_POLICY,
    LABEL_BITPACK_BYTES,
    LOCAL_RANK_TIE_POLICY,
    FrozenArmScore,
    FrozenFoldArmScore,
    FrozenTwoArmScore,
    ManagerAuthorityCommitment,
    O1C29RealProtocolError,
    PostPredictionLabelCapability,
    RealProtocolInputs,
    _document_sha256,
    _exact_local_true_rank,
    adapt_verified_o1c22_packet_corpus,
    bind_manager_authority_commitment,
    open_authoritative_calibration_broker_after_state_freeze,
    open_authoritative_labels_after_prediction_freeze,
    score_frozen_two_arm_predictions,
)
from o1_crypto_lab.o1c29_stacked_hot_calibration import (
    AllowlistedFoldLabelBroker,
    GlobalStateFreeze,
    StackedHotCalibrationResult,
    freeze_all_owner_states,
    run_stacked_hot_calibration,
)


HORIZONS = (64, 65, 96)
WORK = (128, 2, 62)


def _digest(*parts: object) -> str:
    value = "/".join(str(part) for part in parts).encode("ascii")
    return hashlib.sha256(value).hexdigest()


def _bit(*parts: object) -> int:
    return (
        hashlib.sha256("/".join(str(part) for part in parts).encode("ascii")).digest()[
            0
        ]
        & 1
    )


def _labels() -> np.ndarray:
    return np.asarray(
        [
            [_bit("label", fold, coordinate) for coordinate in range(256)]
            for fold in CANONICAL_FOLD_IDS
        ],
        dtype=np.uint8,
    )


def _packet(owner: int, source: int, labels: np.ndarray) -> PacketDeltaExtraction:
    coordinates = tuple(range(256))
    active_sha = active_coordinate_sequence_sha256(coordinates)
    reader_sha = _digest("reader", owner)
    stream_sha = _digest("stream", source)
    pool_sha = _digest("pool", source)
    groups = []
    for coordinate in coordinates:
        sign = 1.0 if labels[source, coordinate] else -1.0
        nuisance64 = 1.0 if _bit("n64", owner, source, coordinate) else -1.0
        nuisance65 = 1.0 if _bit("n65", owner, source, coordinate) else -1.0
        groups.append(
            PacketDeltaGroup(
                source_stream_sha256=stream_sha,
                action_pool_sha256=pool_sha,
                reader_state_sha256=reader_sha,
                active_coordinates_sha256=active_sha,
                pair_sha256=_digest("pair", source, coordinate),
                coordinate=coordinate,
                horizons=HORIZONS,
                incremental_deltas=(
                    0.0625 * nuisance64,
                    0.125 * nuisance65,
                    (1.0 + owner / 16.0 + source / 64.0) * sign,
                ),
                incremental_work_units=WORK,
                group_salt=29_000 + owner,
            )
        )
    return PacketDeltaExtraction(
        source_stream_sha256=stream_sha,
        action_pool_sha256=pool_sha,
        active_coordinates=coordinates,
        ordered_horizons=HORIZONS,
        groups=tuple(groups),
        reader_state_sha256=reader_sha,
        reader_state_bytes=128,
        slow_state_sha256=_digest("slow", owner),
        slow_state_bytes=64,
        final_fast_state_sha256=_digest("fast", owner, source),
        final_fast_state_bytes=512,
        physical_work_units=256 * sum(WORK),
        observed_slots=256 * len(HORIZONS),
    )


def _verified_packet(
    extraction: PacketDeltaExtraction,
    *,
    owner: int,
    source: int,
) -> VerifiedO1C22Packet:
    payload = extraction.to_bytes()
    return VerifiedO1C22Packet(
        role="heldout" if owner == source else "calibration",
        owner_fold_index=owner,
        owner_target_id=CANONICAL_FOLD_IDS[owner],
        source_ordinal=source,
        source_target_id=CANONICAL_FOLD_IDS[source],
        packet_json=payload,
        packet_sha256=hashlib.sha256(payload).hexdigest(),
        public_packet_ledger_sha256=extraction.public_packet_ledger_sha256,
        source_stream_sha256=extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        reader_state_sha256=extraction.reader_state_sha256,
        slow_state_sha256=extraction.slow_state_sha256,
        active_coordinates_sha256=active_coordinate_sequence_sha256(
            extraction.active_coordinates
        ),
        ordered_horizons=extraction.ordered_horizons,
        observed_slots=extraction.observed_slots,
        physical_work_units=extraction.physical_work_units,
    )


def _fixture() -> tuple[VerifiedO1C22PacketCorpus, np.ndarray, bytes, bytes]:
    labels = _labels()
    extractions = {
        (owner, source): _packet(owner, source, labels)
        for owner in range(4)
        for source in range(4)
    }
    folds = []
    for owner in range(4):
        training = tuple((owner + offset) % 4 for offset in range(1, 4))
        packets = {
            source: _verified_packet(
                extractions[(owner, source)], owner=owner, source=source
            )
            for source in range(4)
        }
        quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
            tuple(
                group
                for source in training
                for group in extractions[(owner, source)].groups
            ),
            horizons=HORIZONS,
        )
        quantizer_payload = quantizer.to_bytes()
        folds.append(
            VerifiedO1C22OwnerFold(
                owner_fold_index=owner,
                owner_target_id=CANONICAL_FOLD_IDS[owner],
                training_ordinals=training,
                training_target_ids=tuple(
                    CANONICAL_FOLD_IDS[index] for index in training
                ),
                reader_state_sha256=_digest("reader", owner),
                slow_state_sha256=_digest("slow", owner),
                heldout_action_pool_sha256=_digest("pool", owner),
                upstream_prediction_freeze_sha256=_digest("prediction-freeze", owner),
                active_coordinate_plan_sha256=_digest("plan", owner),
                calibration_freeze_file_sha256=_digest("calibration-file", owner),
                calibration_freeze_sha256=_digest("calibration", owner),
                heldout_freeze_file_sha256=_digest("heldout-file", owner),
                heldout_freeze_sha256=_digest("heldout", owner),
                quantizer=VerifiedO1C22Quantizer(
                    owner_fold_index=owner,
                    owner_target_id=CANONICAL_FOLD_IDS[owner],
                    quantizer_json=quantizer_payload,
                    quantizer_sha256=quantizer.sha256,
                    public_replay_ledger_sha256=(quantizer.public_replay_ledger_sha256),
                    ordered_horizons=quantizer.horizons,
                    total_counts=quantizer.total_counts,
                    nonzero_counts=quantizer.nonzero_counts,
                ),
                calibration_packets=tuple(packets[source] for source in training),
                heldout_packet=packets[owner],
            )
        )
    payload = np.packbits(labels, axis=1, bitorder="little").tobytes(order="C")
    assert len(payload) == LABEL_BITPACK_BYTES
    artifacts = {
        "labels.bitpack": {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": LABEL_BITPACK_BYTES,
            "phase": "POST_FREEZE_SCORED_RESULT",
        }
    }
    for index in range(383):
        artifacts[f"fixture/{index:03d}.bin"] = {
            "sha256": _digest("fixture-artifact", index),
            "bytes": 0,
            "phase": "POST_FREEZE_SCORED_RESULT",
        }
    artifact_index_payload = json.dumps(
        {
            "schema": "o1-256-o1c19-causal-vault-artifact-index-v1",
            "attempt_id": "O1C-0022",
            "o1c19_manifest_sha256": _digest("upstream-manifest"),
            "o1c19_artifact_index_sha256": _digest("upstream-index"),
            "artifacts": artifacts,
            "indexed_artifact_count": len(artifacts),
            "indexed_artifact_bytes": LABEL_BITPACK_BYTES,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    manifest_sha256 = _digest("manifest")
    artifact_index_sha256 = hashlib.sha256(artifact_index_payload).hexdigest()
    authority_unsigned = {
        "schema": packet_corpus.MANAGER_AUTHORITY_SCHEMA,
        "attempt_id": "O1C-0022",
        "capsule_manifest_sha256": manifest_sha256,
        "artifact_index_sha256": artifact_index_sha256,
        "artifact_index_bytes": len(artifact_index_payload),
        "labels_relative": "labels.bitpack",
        "labels_sha256": hashlib.sha256(payload).hexdigest(),
        "labels_bytes": LABEL_BITPACK_BYTES,
        "labels_phase": "POST_FREEZE_SCORED_RESULT",
        "trusted_manager_verification_count": 1,
        "trusted_manager_verification_bytes": 1_000_000,
        "manager_checked_member_count": 400,
    }
    manager_authority = packet_corpus.O1C22ManagerAuthorityReceipt(
        **authority_unsigned,
        receipt_sha256=_document_sha256(authority_unsigned),
        _factory_token=packet_corpus._FACTORY_TOKEN,
    )
    return (
        VerifiedO1C22PacketCorpus(
            schema=PACKET_CORPUS_SCHEMA,
            attempt_id="O1C-0022",
            capsule_manifest_sha256=manifest_sha256,
            artifact_index_sha256=artifact_index_sha256,
            folds=tuple(folds),
            manager_authority=manager_authority,
            _factory_token=packet_corpus._FACTORY_TOKEN,
        ),
        labels,
        payload,
        artifact_index_payload,
    )


class O1C29RealProtocolTests(unittest.TestCase):
    corpus: VerifiedO1C22PacketCorpus
    labels: np.ndarray
    label_payload: bytes
    artifact_index_payload: bytes
    inputs: RealProtocolInputs
    manager_authority: ManagerAuthorityCommitment
    freeze: GlobalStateFreeze
    calibration_broker: AllowlistedFoldLabelBroker
    result: StackedHotCalibrationResult
    capability: PostPredictionLabelCapability

    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.corpus,
            cls.labels,
            cls.label_payload,
            cls.artifact_index_payload,
        ) = _fixture()
        cls.inputs = adapt_verified_o1c22_packet_corpus(cls.corpus)
        cls.manager_authority = bind_manager_authority_commitment(
            cls.inputs, cls.corpus
        )
        cls.freeze = freeze_all_owner_states(
            cls.inputs.config, cls.inputs.owner_corpora
        )
        cls.calibration_broker = (
            open_authoritative_calibration_broker_after_state_freeze(
                cls.inputs,
                cls.freeze,
                cls.artifact_index_payload,
                cls.label_payload,
                manager_authority=cls.manager_authority,
            )
        )
        cls.result = run_stacked_hot_calibration(
            cls.inputs.config,
            cls.inputs.owner_corpora,
            cls.calibration_broker,
        )
        cls.capability = open_authoritative_labels_after_prediction_freeze(
            cls.inputs,
            cls.result,
            cls.artifact_index_payload,
            cls.label_payload,
            manager_authority=cls.manager_authority,
        )
        if cls.result.global_freeze.receipt_sha256 != cls.freeze.receipt_sha256:
            raise AssertionError("fixture state freeze is not deterministic")

    def test_adapter_reorders_every_owner_by_source_and_binds_lineage(self) -> None:
        self.assertIsInstance(self.inputs, RealProtocolInputs)
        self.assertEqual(self.inputs.config.fold_ids, CANONICAL_FOLD_IDS)
        self.assertFalse(self.inputs.receipt_document()["labels_accepted_by_adapter"])
        for owner, corpus in enumerate(self.inputs.owner_corpora):
            self.assertEqual(corpus.owner_fold, CANONICAL_FOLD_IDS[owner])
            self.assertEqual(
                tuple(episode for episode, _packet in corpus.episode_packets),
                CANONICAL_FOLD_IDS,
            )
            self.assertEqual(
                corpus.quantizer.reader_state_sha256,
                self.corpus.folds[owner].reader_state_sha256,
            )
            self.assertEqual(
                corpus.quantizer.quantizer.sha256,
                self.corpus.folds[owner].quantizer.quantizer_sha256,
            )
            for _episode, extraction in corpus.episode_packets:
                self.assertEqual(
                    extraction.reader_state_sha256,
                    corpus.quantizer.reader_state_sha256,
                )

        fold = self.corpus.folds[0]
        wrong = replace(
            fold.calibration_packets[0],
            reader_state_sha256=_digest("foreign-reader"),
        )
        bad_fold = replace(
            fold,
            calibration_packets=(wrong, *fold.calibration_packets[1:]),
        )
        bad = replace(
            self.corpus,
            folds=(bad_fold, *self.corpus.folds[1:]),
            _factory_token=packet_corpus._FACTORY_TOKEN,
        )
        with self.assertRaisesRegex(O1C29RealProtocolError, "packet adapter lineage"):
            adapt_verified_o1c22_packet_corpus(bad)

    def test_labels_are_absent_from_adapter_and_require_state_freeze(self) -> None:
        parameters = inspect.signature(adapt_verified_o1c22_packet_corpus).parameters
        self.assertFalse(any("label" in name for name in parameters))
        self.assertFalse(
            any("label" in row.name for row in dataclasses.fields(RealProtocolInputs))
        )
        self.assertEqual(self.freeze.label_accesses_before_freeze, 0)
        with self.assertRaisesRegex(
            O1C29RealProtocolError, "before a valid global state freeze"
        ):
            open_authoritative_calibration_broker_after_state_freeze(
                self.inputs,
                object(),  # type: ignore[arg-type]
                self.artifact_index_payload,
                self.label_payload,
                manager_authority=self.manager_authority,
            )
        broker = open_authoritative_calibration_broker_after_state_freeze(
            self.inputs,
            self.freeze,
            self.artifact_index_payload,
            self.label_payload,
            manager_authority=self.manager_authority,
        )
        self.assertFalse(hasattr(broker, "label_for"))
        self.assertFalse(hasattr(broker, "labels_bitpack"))
        with self.assertRaisesRegex(Exception, "heldout-excluding allowlist"):
            broker.grant(
                CANONICAL_FOLD_IDS[0],
                requested_folds=CANONICAL_FOLD_IDS,
            )
        with self.assertRaises(TypeError):
            score_frozen_two_arm_predictions(
                self.result,
                broker,  # type: ignore[arg-type]
            )

    def test_label_bitpack_is_strict_and_little_bitorder(self) -> None:
        self.assertIsInstance(self.capability, PostPredictionLabelCapability)
        self.assertFalse(hasattr(self.capability, "labels_bitpack"))
        first = self.capability.label_for(CANONICAL_FOLD_IDS[0])
        expected_first_byte = np.unpackbits(
            np.frombuffer(self.label_payload[:1], dtype=np.uint8),
            bitorder="little",
        )
        self.assertTrue(np.array_equal(first[:8], expected_first_byte))
        self.assertFalse(first.flags.writeable)
        malformed = (
            self.label_payload[:-1],
            self.label_payload + b"\x00",
            bytearray(self.label_payload),
        )
        for payload in malformed:
            with self.subTest(payload_type=type(payload), length=len(payload)):
                with self.assertRaisesRegex(
                    O1C29RealProtocolError, "exactly 128 immutable bytes"
                ):
                    open_authoritative_labels_after_prediction_freeze(
                        self.inputs,
                        self.result,
                        self.artifact_index_payload,
                        payload,  # type: ignore[arg-type]
                        manager_authority=self.manager_authority,
                    )

    def test_arbitrary_flipped_labels_and_self_hash_index_are_rejected(self) -> None:
        flipped = bytearray(self.label_payload)
        flipped[0] ^= 1
        flipped_payload = bytes(flipped)
        with self.assertRaisesRegex(O1C29RealProtocolError, "artifact SHA-256"):
            open_authoritative_labels_after_prediction_freeze(
                self.inputs,
                self.result,
                self.artifact_index_payload,
                flipped_payload,
                manager_authority=self.manager_authority,
            )
        forged_index = json.loads(self.artifact_index_payload.decode("ascii"))
        forged_index["artifacts"]["labels.bitpack"]["sha256"] = hashlib.sha256(
            flipped_payload
        ).hexdigest()
        forged_payload = json.dumps(
            forged_index,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertNotEqual(
            hashlib.sha256(forged_payload).hexdigest(),
            self.inputs.source_artifact_index_sha256,
        )
        with self.assertRaisesRegex(O1C29RealProtocolError, "index payload SHA-256"):
            open_authoritative_labels_after_prediction_freeze(
                self.inputs,
                self.result,
                forged_payload,
                flipped_payload,
                manager_authority=self.manager_authority,
            )

    def test_forged_inputs_index_and_arbitrary_labels_cannot_open_either_gate(
        self,
    ) -> None:
        """Regression for the exact pre-authority audit bypass construction."""

        arbitrary_labels = bytes(LABEL_BITPACK_BYTES)
        forged_index = json.loads(self.artifact_index_payload.decode("ascii"))
        forged_index["artifacts"]["labels.bitpack"]["sha256"] = hashlib.sha256(
            arbitrary_labels
        ).hexdigest()
        forged_index_payload = json.dumps(
            forged_index,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        forged_index_sha256 = hashlib.sha256(forged_index_payload).hexdigest()

        with self.assertRaisesRegex(O1C29RealProtocolError, "verified packet adapter"):
            RealProtocolInputs(
                config=self.inputs.config,
                owner_corpora=self.inputs.owner_corpora,
                source_capsule_manifest_sha256=(
                    self.inputs.source_capsule_manifest_sha256
                ),
                source_artifact_index_sha256=forged_index_sha256,
                receipt_sha256="0" * 64,
                _factory_token=object(),
            )

        # Model the old public-dataclass bypass exactly without granting the new
        # factory marker. Genuine corpora/freeze/result are copied; only the index
        # and arbitrary self-hashed labels differ.
        forged_inputs = object.__new__(RealProtocolInputs)
        object.__setattr__(forged_inputs, "config", self.inputs.config)
        object.__setattr__(forged_inputs, "owner_corpora", self.inputs.owner_corpora)
        object.__setattr__(
            forged_inputs,
            "source_capsule_manifest_sha256",
            self.inputs.source_capsule_manifest_sha256,
        )
        object.__setattr__(
            forged_inputs,
            "source_artifact_index_sha256",
            forged_index_sha256,
        )
        object.__setattr__(forged_inputs, "receipt_sha256", "0" * 64)
        object.__setattr__(
            forged_inputs,
            "receipt_sha256",
            _document_sha256(forged_inputs.receipt_document()),
        )
        for opener, phase_object in (
            (open_authoritative_calibration_broker_after_state_freeze, self.freeze),
            (open_authoritative_labels_after_prediction_freeze, self.result),
        ):
            with self.subTest(opener=opener.__name__):
                with self.assertRaisesRegex(
                    O1C29RealProtocolError, "factory-created verified adapter inputs"
                ):
                    opener(
                        forged_inputs,
                        phase_object,
                        forged_index_payload,
                        arbitrary_labels,
                        manager_authority=self.manager_authority,
                    )

    def test_postprediction_capability_rejects_incomplete_or_wrong_result(self) -> None:
        with self.assertRaisesRegex(O1C29RealProtocolError, "complete stacked result"):
            open_authoritative_labels_after_prediction_freeze(
                self.inputs,
                object(),  # type: ignore[arg-type]
                self.artifact_index_payload,
                self.label_payload,
                manager_authority=self.manager_authority,
            )
        incomplete = object.__new__(type(self.result))
        for row in dataclasses.fields(self.result):
            object.__setattr__(incomplete, row.name, getattr(self.result, row.name))
        object.__setattr__(incomplete, "predictions", self.result.predictions[:-1])
        with self.assertRaisesRegex(O1C29RealProtocolError, "incomplete"):
            open_authoritative_labels_after_prediction_freeze(
                self.inputs,
                incomplete,
                self.artifact_index_payload,
                self.label_payload,
                manager_authority=self.manager_authority,
            )
        wrong = object.__new__(type(self.result))
        for row in dataclasses.fields(self.result):
            object.__setattr__(wrong, row.name, getattr(self.result, row.name))
        object.__setattr__(wrong, "config_sha256", _digest("wrong-config"))
        with self.assertRaisesRegex(O1C29RealProtocolError, "incomplete"):
            open_authoritative_labels_after_prediction_freeze(
                self.inputs,
                wrong,
                self.artifact_index_payload,
                self.label_payload,
                manager_authority=self.manager_authority,
            )

    def test_frozen_two_arm_scoring_and_frontier_are_deterministic(self) -> None:
        first = score_frozen_two_arm_predictions(
            self.result, self.capability, top_k_limit=8
        )
        replay = score_frozen_two_arm_predictions(
            self.result, self.capability, top_k_limit=8
        )
        self.assertEqual(first, replay)
        self.assertEqual(
            first.receipt_sha256,
            _document_sha256(first.receipt_document()),
        )
        self.assertEqual(tuple(row.arm for row in first.arms), ("primary", "secondary"))
        self.assertEqual(first.receipt_document()["refits_during_scoring"], 0)
        self.assertFalse(first.receipt_document()["label_dependent_arm_selection"])
        for arm in first.arms:
            self.assertEqual(
                arm.receipt_sha256,
                _document_sha256(arm.receipt_document()),
            )
            self.assertEqual(len(arm.folds), 4)
            self.assertGreaterEqual(arm.positive_fold_count, 0)
            self.assertLessEqual(arm.positive_fold_count, 4)
            self.assertGreaterEqual(arm.bit_accuracy, 0.0)
            self.assertLessEqual(arm.bit_accuracy, 1.0)
            self.assertEqual(
                arm.byte_top1_count,
                sum(row.byte_top1_count for row in arm.folds),
            )
            self.assertEqual(
                arm.block16_top16_count,
                sum(row.block16_top16_count for row in arm.folds),
            )
            for fold in arm.folds:
                self.assertEqual(
                    fold.receipt_sha256,
                    _document_sha256(fold.receipt_document()),
                )
                self.assertEqual(fold.top_k_limit, 8)
                self.assertIsNotNone(fold.frontier_sha256)
                self.assertEqual(len(fold.true_byte_ranks), 32)
                self.assertEqual(len(fold.true_block16_ranks), 16)
                self.assertTrue(all(1 <= rank <= 256 for rank in fold.true_byte_ranks))
                self.assertTrue(
                    all(1 <= rank <= 65_536 for rank in fold.true_block16_ranks)
                )
                self.assertEqual(
                    fold.receipt_document()["local_rank_tie_policy"],
                    LOCAL_RANK_TIE_POLICY,
                )
                self.assertEqual(
                    fold.receipt_document()["global_frontier_tie_policy"],
                    GLOBAL_FRONTIER_TIE_POLICY,
                )
            self.assertEqual(
                arm.receipt_document()["global_frontier_tie_policy"],
                GLOBAL_FRONTIER_TIE_POLICY,
            )
        self.assertEqual(
            first.receipt_document()["global_frontier_tie_policy"],
            GLOBAL_FRONTIER_TIE_POLICY,
        )
        without_frontier = score_frozen_two_arm_predictions(
            self.result, self.capability
        )
        self.assertTrue(
            all(
                row.frontier_sha256 is None and row.true_key_rank is None
                for arm in without_frontier.arms
                for row in arm.folds
            )
        )
        with self.assertRaisesRegex(O1C29RealProtocolError, "top_k_limit"):
            score_frozen_two_arm_predictions(
                self.result, self.capability, top_k_limit=0
            )

    def test_score_records_are_factory_only(self) -> None:
        score = score_frozen_two_arm_predictions(
            self.result,
            self.capability,
            top_k_limit=8,
        )
        fold = score.arms[0].folds[0]
        with self.assertRaisesRegex(O1C29RealProtocolError, "frozen scorer"):
            replace(
                fold,
                nll_bits=float("nan"),
                _factory_token=object(),
            )
        with self.assertRaisesRegex(O1C29RealProtocolError, "frozen scorer"):
            replace(
                score.arms[0],
                correct_bits=-1,
                _factory_token=object(),
            )
        with self.assertRaisesRegex(O1C29RealProtocolError, "frozen scorer"):
            replace(
                score,
                top_k_limit=0,
                _factory_token=object(),
            )
        with self.assertRaisesRegex(O1C29RealProtocolError, "finite float"):
            replace(
                fold,
                nll_bits=float("nan"),
                _factory_token=real_protocol._FOLD_SCORE_FACTORY,
            )
        with self.assertRaisesRegex(O1C29RealProtocolError, "correct_bits"):
            replace(
                score.arms[0],
                correct_bits=-1,
                _factory_token=real_protocol._ARM_SCORE_FACTORY,
            )
        with self.assertRaisesRegex(O1C29RealProtocolError, "top_k_limit"):
            replace(
                score,
                top_k_limit=0,
                _factory_token=real_protocol._TWO_ARM_SCORE_FACTORY,
            )
        self.assertIsInstance(fold, FrozenFoldArmScore)
        self.assertIsInstance(score.arms[0], FrozenArmScore)
        self.assertIsInstance(score, FrozenTwoArmScore)

    def test_exact_local_rank_edges_and_zero_penalty_ties(self) -> None:
        byte_labels = np.unpackbits(np.asarray([5], dtype=np.uint8), bitorder="little")
        self.assertEqual(
            _exact_local_true_rank(np.zeros(8, dtype=np.float32), byte_labels),
            6,
        )
        block_labels = np.ones(16, dtype=np.uint8)
        self.assertEqual(
            _exact_local_true_rank(np.zeros(16, dtype=np.float32), block_labels),
            65_536,
        )
        exact_mode = np.where(
            block_labels == 1, np.float32(1_000.0), np.float32(-1_000.0)
        )
        self.assertEqual(
            _exact_local_true_rank(exact_mode, block_labels),
            1,
        )
        adjacent = np.asarray(
            [
                np.nextafter(np.float32(0.7), np.float32(np.inf)),
                np.float32(0.7),
                *([np.float32(4.0)] * 6),
            ],
            dtype=np.float32,
        )
        adjacent_labels = np.ones(8, dtype=np.uint8)
        adjacent_labels[0] = 0
        first = _exact_local_true_rank(adjacent, adjacent_labels)
        replay = _exact_local_true_rank(adjacent.copy(), adjacent_labels.copy())
        self.assertEqual(first, 3)
        self.assertEqual(first, replay)


if __name__ == "__main__":
    unittest.main()
