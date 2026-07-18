from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import o1_crypto_lab.o1c29_packet_corpus as packet_corpus

from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    PacketDeltaExtraction,
    PacketDeltaGroup,
    active_coordinate_sequence_sha256,
)
from o1_crypto_lab.o1c22_postresult_composer import UPSTREAM_ATTEMPT_ID
from o1_crypto_lab.o1c22_postresult_composer_run import (
    EXPECTED_UPSTREAM_ARTIFACTS,
    UPSTREAM_ARTIFACT_INDEX_SCHEMA,
    UPSTREAM_CALIBRATION_FREEZE_SCHEMA,
    UPSTREAM_PREDICTION_FREEZE_SCHEMA,
)
from o1_crypto_lab.o1c29_packet_corpus import (
    EXPECTED_CALIBRATION_PACKETS,
    EXPECTED_HELDOUT_PACKETS,
    EXPECTED_HORIZONS,
    EXPECTED_PACKET_SLOTS,
    EXPECTED_PHYSICAL_WORK,
    EXPECTED_QUANTIZERS,
    O1C29PacketCorpusError,
    PACKET_CORPUS_SCHEMA,
    load_verified_o1c22_packet_corpus,
)
from o1_crypto_lab.run_capsule import CapsuleVerification, FinalizedRun


ROOT = Path(__file__).resolve().parents[1]
WORK_PER_GROUP = (128, 2, 62)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _token(*parts: object) -> str:
    return _sha(canonical_json_bytes(["synthetic-o1c29", *parts]))


def _target(ordinal: int) -> str:
    return f"build-{ordinal:04d}"


def _packet(owner: int, source: int) -> PacketDeltaExtraction:
    coordinates = tuple(range(256))
    active_sha = active_coordinate_sequence_sha256(coordinates)
    reader_sha = _token("reader", owner)
    stream_sha = _token("stream", source)
    pool_sha = _token("pool", source)
    groups = tuple(
        PacketDeltaGroup(
            source_stream_sha256=stream_sha,
            action_pool_sha256=pool_sha,
            reader_state_sha256=reader_sha,
            active_coordinates_sha256=active_sha,
            pair_sha256=_token("pair", source, coordinate),
            coordinate=coordinate,
            horizons=EXPECTED_HORIZONS,
            incremental_deltas=(0.0, 0.0, 0.0),
            incremental_work_units=WORK_PER_GROUP,
            group_salt=29,
        )
        for coordinate in coordinates
    )
    return PacketDeltaExtraction(
        source_stream_sha256=stream_sha,
        action_pool_sha256=pool_sha,
        active_coordinates=coordinates,
        ordered_horizons=EXPECTED_HORIZONS,
        groups=groups,
        reader_state_sha256=reader_sha,
        reader_state_bytes=96,
        slow_state_sha256=_token("slow", owner),
        slow_state_bytes=32,
        final_fast_state_sha256=_token("fast", owner, source),
        final_fast_state_bytes=512,
        physical_work_units=EXPECTED_PHYSICAL_WORK,
        observed_slots=EXPECTED_PACKET_SLOTS,
    )


def _freeze(fields: dict[str, object], artifacts: dict[str, bytes]) -> bytes:
    unsigned = {
        **fields,
        "artifacts": {
            relative: {"sha256": _sha(payload), "bytes": len(payload)}
            for relative, payload in sorted(artifacts.items())
        },
    }
    return canonical_json_bytes(
        {**unsigned, "freeze_sha256": _sha(canonical_json_bytes(unsigned))}
    )


class _Fixture:
    def __init__(self, capsule: Path) -> None:
        self.capsule = capsule
        self.artifacts_root = capsule / "artifacts"
        self.artifacts_root.mkdir(parents=True)
        self.entries: dict[str, dict[str, object]] = {}
        self.source: SimpleNamespace

    def add(self, relative: str, payload: bytes, phase: str) -> None:
        path = self.artifacts_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        self.entries[relative] = {
            "sha256": _sha(payload),
            "bytes": len(payload),
            "phase": phase,
        }

    def write_index(self) -> None:
        while len(self.entries) < EXPECTED_UPSTREAM_ARTIFACTS:
            ordinal = len(self.entries)
            self.entries[f"synthetic-authority/dummy-{ordinal:03d}.bin"] = {
                "sha256": _token("dummy", ordinal),
                "bytes": 0,
                "phase": "FULLY_VERIFIED_BY_MOCK_AUTHORITY",
            }
        index = {
            "schema": UPSTREAM_ARTIFACT_INDEX_SCHEMA,
            "attempt_id": UPSTREAM_ATTEMPT_ID,
            "o1c19_manifest_sha256": _token("o1c19-manifest"),
            "o1c19_artifact_index_sha256": _token("o1c19-index"),
            "artifacts": dict(sorted(self.entries.items())),
            "indexed_artifact_count": len(self.entries),
            "indexed_artifact_bytes": sum(
                int(entry["bytes"]) for entry in self.entries.values()
            ),
        }
        payload = canonical_json_bytes(index)
        (self.artifacts_root / "artifact_index.json").write_bytes(payload)
        if hasattr(self, "source"):
            self.source.artifact_index_sha256 = _sha(payload)

    def rebind(
        self,
        relative: str,
        payload: bytes,
        *,
        freeze_relative: str,
    ) -> None:
        """Rehash a mutation through freeze+index to reach semantic guards."""

        (self.artifacts_root / relative).write_bytes(payload)
        self.entries[relative]["sha256"] = _sha(payload)
        self.entries[relative]["bytes"] = len(payload)
        freeze_path = self.artifacts_root / freeze_relative
        document = json.loads(freeze_path.read_bytes())
        document["artifacts"][relative] = {
            "sha256": _sha(payload),
            "bytes": len(payload),
        }
        document.pop("freeze_sha256")
        document["freeze_sha256"] = _sha(canonical_json_bytes(document))
        freeze_payload = canonical_json_bytes(document)
        freeze_path.write_bytes(freeze_payload)
        self.entries[freeze_relative]["sha256"] = _sha(freeze_payload)
        self.entries[freeze_relative]["bytes"] = len(freeze_payload)
        self.write_index()


def _write_fixture(capsule: Path) -> _Fixture:
    fixture = _Fixture(capsule)
    extractions = {
        (owner, source): _packet(owner, source)
        for owner in range(4)
        for source in range(4)
    }
    for owner in range(4):
        target = _target(owner)
        training = tuple((owner + offset) % 4 for offset in range(1, 4))
        calibration_phase = f"CALIBRATION_PREDICTIONS_FROZEN_FOLD_{owner}"
        heldout_phase = f"HELDOUT_PREDICTIONS_FROZEN_FOLD_{owner}"
        calibration_prefix = f"folds/{target}/calibration"
        heldout_prefix = f"folds/{target}/heldout"
        calibration_payloads = {
            f"{calibration_prefix}/source-{_target(source)}/packet_deltas.json": (
                extractions[(owner, source)].to_bytes()
            )
            for source in training
        }
        quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
            tuple(
                group
                for source in training
                for group in extractions[(owner, source)].groups
            ),
            horizons=EXPECTED_HORIZONS,
        )
        calibration_quantizer_relative = f"{calibration_prefix}/quantizer.json"
        calibration_payloads[calibration_quantizer_relative] = quantizer.to_bytes()
        for relative, payload in calibration_payloads.items():
            fixture.add(relative, payload, calibration_phase)
        calibration_freeze_relative = f"{calibration_prefix}/prediction_freeze.json"
        fixture.add(
            calibration_freeze_relative,
            _freeze(
                {
                    "schema": UPSTREAM_CALIBRATION_FREEZE_SCHEMA,
                    "phase": (
                        "THIS_FOLD_TRAINING_PUBLIC_DELTAS_STATES_AND_"
                        "PREDICTIONS_FROZEN_BEFORE_THIS_FOLD_"
                        "CALIBRATION_LABEL_USE"
                    ),
                    "fold_index": owner,
                    "held_out_ordinal": owner,
                    "held_out_target_id": target,
                    "training_ordinals": list(training),
                    "training_target_ids": [_target(source) for source in training],
                    "reader_state_sha256": _token("reader", owner),
                    "slow_state_sha256": _token("slow", owner),
                    "quantizer_sha256": quantizer.sha256,
                    "labels_used_by_this_fold_before_calibration_freeze": [],
                    "held_out_label_used_for_this_fold": False,
                    "previously_opened_build_label_ordinals": [],
                    "build_labels_may_have_been_opened_in_other_folds": False,
                    "reader_updates": 0,
                    "solver_calls": 0,
                },
                calibration_payloads,
            ),
            calibration_phase,
        )

        heldout_quantizer_relative = f"{heldout_prefix}/quantizer.json"
        heldout_packet_relative = f"{heldout_prefix}/k256/packet_deltas.json"
        heldout_payloads = {
            heldout_quantizer_relative: quantizer.to_bytes(),
            heldout_packet_relative: extractions[(owner, owner)].to_bytes(),
        }
        for relative, payload in heldout_payloads.items():
            fixture.add(relative, payload, heldout_phase)
        heldout_freeze_relative = f"{heldout_prefix}/prediction_freeze.json"
        fixture.add(
            heldout_freeze_relative,
            _freeze(
                {
                    "schema": UPSTREAM_PREDICTION_FREEZE_SCHEMA,
                    "phase": (
                        "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_"
                        "PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE"
                    ),
                    "fold_index": owner,
                    "held_out_ordinal": owner,
                    "held_out_target_id": target,
                    "held_out_action_pool_sha256": _token("pool", owner),
                    "reader_state_sha256": _token("reader", owner),
                    "slow_state_sha256": _token("slow", owner),
                    "upstream_prediction_freeze_sha256": _token(
                        "upstream-freeze", owner
                    ),
                    "quantizer_sha256": quantizer.sha256,
                    "calibration_scales": [1.0] * 7,
                    "active_coordinate_plan_sha256": _token("plan", owner),
                    "active_coordinate_counts": [12, 52, 128, 256],
                    "prediction_arms": [
                        "raw_float_delta_sum",
                        "normalized_float_delta_sum",
                        "quantized_int8_vault",
                        "last_horizon_only",
                        "unit_sign_sum",
                        "coordinate_shuffled_vault",
                        "zero_prior",
                    ],
                    "calibration_label_ordinals_used_for_this_fold": list(training),
                    "held_out_label_used_for_this_fold": False,
                    "previously_opened_build_label_ordinals": list(training),
                    "held_out_label_may_have_been_opened_in_other_fold": False,
                    "held_out_reader_updates": 0,
                    "solver_calls": 0,
                    "scientific_entropy_calls": 0,
                },
                heldout_payloads,
            ),
            heldout_phase,
        )
    fixture.entries["labels.bitpack"] = {
        "sha256": _token("committed-labels"),
        "bytes": 128,
        "phase": "POST_FREEZE_SCORED_RESULT",
    }
    fixture.write_index()
    manifest_sha = _token("capsule-manifest")
    verification = CapsuleVerification(
        schema="o1c-capsule-verification-v1",
        path=capsule,
        manifest_sha256=manifest_sha,
        checked=EXPECTED_UPSTREAM_ARTIFACTS,
        missing=(),
        mismatched=(),
        unexpected=(),
    )
    finalized = FinalizedRun(
        attempt_id=UPSTREAM_ATTEMPT_ID,
        path=capsule,
        manifest_sha256=manifest_sha,
        verification=verification,
    )
    fixture.source = SimpleNamespace(
        finalized=finalized,
        artifact_index_sha256=_sha(
            (fixture.artifacts_root / "artifact_index.json").read_bytes()
        ),
    )
    return fixture


def _load(fixture: _Fixture):
    config = SimpleNamespace(root=fixture.capsule.parent)
    with (
        patch("o1_crypto_lab.o1c29_packet_corpus.RunCapsuleManager") as manager_type,
        patch(
            "o1_crypto_lab.o1c29_packet_corpus.load_producer_authentic_o1c22_source",
            return_value=fixture.source,
        ) as authority,
    ):
        manager_type.return_value.finalized_attempt.return_value = (
            fixture.source.finalized
        )
        result = load_verified_o1c22_packet_corpus(config)
        manager_type.assert_called_once_with(config.root)
        manager_type.return_value.finalized_attempt.assert_called_once_with(
            UPSTREAM_ATTEMPT_ID
        )
        authority.assert_called_once_with(
            config,
            manager_type.return_value,
            fixture.source.finalized,
        )
        return result


class O1C29PacketCorpusTests(unittest.TestCase):
    def test_projection_exports_exact_narrow_nested_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(Path(temporary) / "synthetic-o1c22")
            corpus = _load(fixture)
        self.assertEqual(corpus.schema, PACKET_CORPUS_SCHEMA)
        self.assertEqual(len(corpus.calibration_packets), EXPECTED_CALIBRATION_PACKETS)
        self.assertEqual(len(corpus.heldout_packets), EXPECTED_HELDOUT_PACKETS)
        self.assertEqual(len(corpus.quantizers), EXPECTED_QUANTIZERS)
        for owner, fold in enumerate(corpus.folds):
            expected_training = tuple((owner + offset) % 4 for offset in range(1, 4))
            self.assertEqual(fold.owner_fold_index, owner)
            self.assertEqual(fold.training_ordinals, expected_training)
            self.assertNotIn(owner, fold.training_ordinals)
            self.assertEqual(fold.heldout_packet.source_ordinal, owner)
            self.assertEqual(fold.quantizer.total_counts, (768, 768, 768))
            for packet in (*fold.calibration_packets, fold.heldout_packet):
                self.assertEqual(packet.owner_fold_index, owner)
                self.assertEqual(packet.ordered_horizons, (64, 65, 96))
                self.assertEqual(packet.observed_slots, 768)
                self.assertEqual(packet.physical_work_units, 49_152)
                self.assertEqual(packet.reader_state_sha256, fold.reader_state_sha256)
                self.assertEqual(packet.slow_state_sha256, fold.slow_state_sha256)
                self.assertEqual(packet.packet_sha256, _sha(packet.packet_json))
            for packet in fold.calibration_packets:
                source = corpus.fold(packet.source_ordinal).heldout_packet
                self.assertEqual(packet.action_pool_sha256, source.action_pool_sha256)
                self.assertEqual(
                    packet.source_stream_sha256, source.source_stream_sha256
                )

    def test_scientific_facade_has_no_sensitive_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = _load(_write_fixture(Path(temporary) / "synthetic-o1c22"))
        objects = [
            corpus,
            *corpus.folds,
            *corpus.calibration_packets,
            *corpus.heldout_packets,
            *corpus.quantizers,
        ]
        for value in objects:
            self.assertTrue(dataclasses.is_dataclass(value))
            self.assertNotIsInstance(value, Path)
            for field in dataclasses.fields(value):
                self.assertNotEqual(field.name, "path")
                self.assertFalse(field.name.endswith("_path"))
                self.assertNotIn("corpus_seed", field.name)
                self.assertNotIn("episode", field.name)
                self.assertNotIn("label", field.name)
                member = getattr(value, field.name)
                self.assertNotIsInstance(member, Path)

    def test_owner_fold_rejects_rehashed_own_heldout_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(Path(temporary) / "synthetic-o1c22")
            victim = "folds/build-0000/calibration/source-build-0001/packet_deltas.json"
            substituted = (
                fixture.artifacts_root
                / "folds/build-0001/heldout/k256/packet_deltas.json"
            ).read_bytes()
            fixture.rebind(
                victim,
                substituted,
                freeze_relative=("folds/build-0000/calibration/prediction_freeze.json"),
            )
            with self.assertRaisesRegex(
                O1C29PacketCorpusError,
                "owner reader commitment differs.*substitution rejected",
            ):
                _load(fixture)

    def test_packet_must_match_both_index_and_freeze_commitments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(Path(temporary) / "synthetic-o1c22")
            relative = (
                "folds/build-0000/calibration/source-build-0001/packet_deltas.json"
            )
            path = fixture.artifacts_root / relative
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(
                O1C29PacketCorpusError, "artifact index commitment differs"
            ):
                _load(fixture)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(Path(temporary) / "synthetic-o1c22")
            relative = (
                "folds/build-0000/calibration/source-build-0001/packet_deltas.json"
            )
            path = fixture.artifacts_root / relative
            payload = path.read_bytes() + b" "
            path.write_bytes(payload)
            fixture.entries[relative]["sha256"] = _sha(payload)
            fixture.entries[relative]["bytes"] = len(payload)
            fixture.write_index()
            with self.assertRaisesRegex(
                O1C29PacketCorpusError, "freeze commitment differs"
            ):
                _load(fixture)

    def test_heldout_freeze_requires_zero_producer_scientific_entropy(self) -> None:
        for replacement in (None, 1):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = _write_fixture(Path(temporary) / "synthetic-o1c22")
                    relative = "folds/build-0000/heldout/prediction_freeze.json"
                    path = fixture.artifacts_root / relative
                    document = json.loads(path.read_bytes())
                    document.pop("freeze_sha256")
                    if replacement is None:
                        document.pop("scientific_entropy_calls")
                    else:
                        document["scientific_entropy_calls"] = replacement
                    document["freeze_sha256"] = _sha(canonical_json_bytes(document))
                    payload = canonical_json_bytes(document)
                    path.write_bytes(payload)
                    fixture.entries[relative]["sha256"] = _sha(payload)
                    fixture.entries[relative]["bytes"] = len(payload)
                    fixture.write_index()
                    with self.assertRaisesRegex(
                        O1C29PacketCorpusError,
                        "producer scientific_entropy_calls must equal zero",
                    ):
                        _load(fixture)

    def test_import_is_lightweight_and_does_not_load_training_stack(self) -> None:
        script = (
            "import sys;"
            f"sys.path.insert(0,{str(ROOT / 'src')!r});"
            "import o1_crypto_lab.o1c29_packet_corpus;"
            "assert 'torch' not in sys.modules;"
            "assert 'o1_crypto_lab.o1c19_causal_vault_bridge' not in sys.modules;"
            "assert 'o1_crypto_lab.full256_multiresolution_build_loo' "
            "not in sys.modules"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_arbitrary_wire_cannot_mint_factory_authority(self) -> None:
        with self.assertRaisesRegex(
            O1C29PacketCorpusError, "trusted packet transfer capability differs"
        ):
            packet_corpus.deserialize_verified_o1c22_packet_corpus(b"{}")

    def test_trusted_wire_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = _load(_write_fixture(Path(temporary) / "synthetic-o1c22"))
        nonce = packet_corpus._new_trusted_packet_corpus_transfer_nonce()
        payload = packet_corpus.serialize_verified_o1c22_packet_corpus(
            corpus, _trusted_nonce=nonce
        )
        document = json.loads(payload)
        document["folds"][0]["owner_target_id"] = "forged"
        with self.assertRaisesRegex(O1C29PacketCorpusError, "wire identity differs"):
            packet_corpus.deserialize_verified_o1c22_packet_corpus(
                canonical_json_bytes(document), _trusted_nonce=nonce
            )


if __name__ == "__main__":
    unittest.main()
