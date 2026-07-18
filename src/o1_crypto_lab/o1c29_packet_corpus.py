"""Capability-safe O1C-0022 packet corpus for an O1C-0029 successor.

The producer-authentic successor authority is the production boundary: it
resolves the manager-authoritative finalized O1C-0022 capsule and verifies its
complete publication, including the entropy-zero field omitted by the frozen
O1C-0023 verifier, before this module reads a deliberately narrow subset.
The returned scientific facade contains no filesystem capability, labels,
corpus seed, or build-episode object.
"""

from __future__ import annotations

import hashlib
import json
import base64
import secrets
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Mapping, cast

from .living_inverse import canonical_json_bytes
from .o1c23_selection_authority import (
    O1C23SelectionAuthorityError,
    load_producer_authentic_o1c22_source,
    load_trusted_manager_verified_o1c22_source,
)
from .o1c22_packet_codec import (
    FrozenMedianAbsQuantizer,
    O1C22PacketCodecError,
    PacketDeltaExtraction,
    active_coordinate_sequence_sha256,
)
from .o1c22_postresult_composer import UPSTREAM_ATTEMPT_ID
from .o1c22_postresult_composer_run import (
    EXPECTED_UPSTREAM_ARTIFACTS,
    O1C22PostResultSource,
    O1C23RunConfig,
    UPSTREAM_ARTIFACT_INDEX_SCHEMA,
    UPSTREAM_CALIBRATION_FREEZE_SCHEMA,
    UPSTREAM_PREDICTION_FREEZE_SCHEMA,
)
from .run_capsule import RunCapsuleManager


PACKET_CORPUS_SCHEMA = "o1-256-o1c29-verified-o1c22-packet-corpus-v1"
MANAGER_AUTHORITY_SCHEMA = "o1-256-o1c29-manager-authority-receipt-v1"
PACKET_CORPUS_WIRE_SCHEMA = "o1-256-o1c29-packet-corpus-wire-v1"
EXPECTED_FOLDS = 4
EXPECTED_HORIZONS = (64, 65, 96)
EXPECTED_ACTIVE_COORDINATES = 256
EXPECTED_PACKET_SLOTS = 768
EXPECTED_PHYSICAL_WORK = 49_152
EXPECTED_CALIBRATION_PACKETS = 12
EXPECTED_HELDOUT_PACKETS = 4
EXPECTED_QUANTIZERS = 4
_HEX = frozenset("0123456789abcdef")
_CALIBRATION_PHASE = (
    "THIS_FOLD_TRAINING_PUBLIC_DELTAS_STATES_AND_PREDICTIONS_FROZEN_"
    "BEFORE_THIS_FOLD_CALIBRATION_LABEL_USE"
)
_HELDOUT_PHASE = (
    "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_"
    "FROZEN_BEFORE_LABEL_ORACLE"
)
_CALIBRATION_FREEZE_FIELDS = frozenset(
    {
        "schema",
        "phase",
        "fold_index",
        "held_out_ordinal",
        "held_out_target_id",
        "training_ordinals",
        "training_target_ids",
        "reader_state_sha256",
        "slow_state_sha256",
        "quantizer_sha256",
        "labels_used_by_this_fold_before_calibration_freeze",
        "held_out_label_used_for_this_fold",
        "previously_opened_build_label_ordinals",
        "build_labels_may_have_been_opened_in_other_folds",
        "reader_updates",
        "solver_calls",
        "artifacts",
        "freeze_sha256",
    }
)
_HELDOUT_FREEZE_FIELDS = frozenset(
    {
        "schema",
        "phase",
        "fold_index",
        "held_out_ordinal",
        "held_out_target_id",
        "held_out_action_pool_sha256",
        "reader_state_sha256",
        "slow_state_sha256",
        "upstream_prediction_freeze_sha256",
        "quantizer_sha256",
        "calibration_scales",
        "active_coordinate_plan_sha256",
        "active_coordinate_counts",
        "prediction_arms",
        "calibration_label_ordinals_used_for_this_fold",
        "held_out_label_used_for_this_fold",
        "previously_opened_build_label_ordinals",
        "held_out_label_may_have_been_opened_in_other_fold",
        "held_out_reader_updates",
        "solver_calls",
        "scientific_entropy_calls",
        "artifacts",
        "freeze_sha256",
    }
)
_PREDICTION_ARMS = (
    "raw_float_delta_sum",
    "normalized_float_delta_sum",
    "quantized_int8_vault",
    "last_horizon_only",
    "unit_sign_sum",
    "coordinate_shuffled_vault",
    "zero_prior",
)
_FACTORY_TOKEN = object()
_FACTORY_MARKER = object()
_TRUSTED_TRANSFER_NONCES: set[str] = set()


class O1C29PacketCorpusError(ValueError):
    """The authoritative O1C-0022 packet projection differs from its ABI."""


@dataclass(frozen=True, slots=True)
class O1C22ManagerAuthorityReceipt:
    """FS-free commitment minted by one trusted manager verification process."""

    schema: str
    attempt_id: str
    capsule_manifest_sha256: str
    artifact_index_sha256: str
    artifact_index_bytes: int
    labels_relative: str
    labels_sha256: str
    labels_bytes: int
    labels_phase: str
    trusted_manager_verification_count: int
    trusted_manager_verification_bytes: int
    manager_checked_member_count: int
    receipt_sha256: str
    _factory_token: InitVar[object] = None
    _factory_marker: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FACTORY_TOKEN:
            raise O1C29PacketCorpusError("manager authority is factory-only")
        object.__setattr__(self, "_factory_marker", _FACTORY_MARKER)
        unsigned = self.receipt_document(include_digest=False)
        if (
            self.schema != MANAGER_AUTHORITY_SCHEMA
            or self.attempt_id != UPSTREAM_ATTEMPT_ID
            or self.labels_relative != "labels.bitpack"
            or self.labels_bytes != 128
            or self.labels_phase != "POST_FREEZE_SCORED_RESULT"
            or self.trusted_manager_verification_count != 1
            or self.trusted_manager_verification_bytes <= 0
            or self.manager_checked_member_count < EXPECTED_UPSTREAM_ARTIFACTS
            or self.receipt_sha256 != _sha256_bytes(canonical_json_bytes(unsigned))
        ):
            raise O1C29PacketCorpusError("manager authority receipt differs")
        for value, name in (
            (self.capsule_manifest_sha256, "capsule manifest"),
            (self.artifact_index_sha256, "artifact index"),
            (self.labels_sha256, "labels"),
            (self.receipt_sha256, "authority receipt"),
        ):
            _sha256(value, name)
        _integer(self.artifact_index_bytes, "artifact index bytes", 1, 1 << 40)

    def receipt_document(self, *, include_digest: bool = True) -> dict[str, object]:
        document = {
            "schema": self.schema,
            "attempt_id": self.attempt_id,
            "capsule_manifest_sha256": self.capsule_manifest_sha256,
            "artifact_index_sha256": self.artifact_index_sha256,
            "artifact_index_bytes": self.artifact_index_bytes,
            "labels_relative": self.labels_relative,
            "labels_sha256": self.labels_sha256,
            "labels_bytes": self.labels_bytes,
            "labels_phase": self.labels_phase,
            "trusted_manager_verification_count": self.trusted_manager_verification_count,
            "trusted_manager_verification_bytes": self.trusted_manager_verification_bytes,
            "manager_checked_member_count": self.manager_checked_member_count,
        }
        if include_digest:
            document["receipt_sha256"] = self.receipt_sha256
        return document


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C29PacketCorpusError(f"{field} must be lowercase SHA-256")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C29PacketCorpusError(f"{field} differs")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C29PacketCorpusError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise O1C29PacketCorpusError(f"{field} must be non-empty text")
    return value


def _sequence_of_ints(value: object, field: str) -> tuple[int, ...]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) for item in value
    ):
        raise O1C29PacketCorpusError(f"{field} must be an integer list")
    return tuple(cast(list[int], value))


def _sequence_of_strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise O1C29PacketCorpusError(f"{field} must be a string list")
    return tuple(cast(list[str], value))


def _decode_json(value: bytes, field: str) -> Mapping[str, object]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C29PacketCorpusError(f"{field} is invalid JSON") from exc
    return _mapping(decoded, field)


def _target_id(ordinal: int) -> str:
    return f"build-{ordinal:04d}"


@dataclass(frozen=True, slots=True)
class VerifiedO1C22Packet:
    """One exact, label-free packet JSON selected from the publication."""

    role: str
    owner_fold_index: int
    owner_target_id: str
    source_ordinal: int
    source_target_id: str
    packet_json: bytes
    packet_sha256: str
    public_packet_ledger_sha256: str
    source_stream_sha256: str
    action_pool_sha256: str
    reader_state_sha256: str
    slow_state_sha256: str
    active_coordinates_sha256: str
    ordered_horizons: tuple[int, ...]
    observed_slots: int
    physical_work_units: int

    def decode(self) -> PacketDeltaExtraction:
        """Decode a fresh immutable view using the lightweight frozen codec."""

        return PacketDeltaExtraction.from_bytes(self.packet_json)


@dataclass(frozen=True, slots=True)
class VerifiedO1C22Quantizer:
    """One owner-fold quantizer, shared by calibration and heldout packets."""

    owner_fold_index: int
    owner_target_id: str
    quantizer_json: bytes
    quantizer_sha256: str
    public_replay_ledger_sha256: str
    ordered_horizons: tuple[int, ...]
    total_counts: tuple[int, ...]
    nonzero_counts: tuple[int, ...]

    def decode(self) -> FrozenMedianAbsQuantizer:
        """Decode a fresh immutable view using the lightweight frozen codec."""

        return FrozenMedianAbsQuantizer.from_bytes(self.quantizer_json)


@dataclass(frozen=True, slots=True)
class VerifiedO1C22OwnerFold:
    """The only O1C-0022 capabilities exposed for one outer owner fold."""

    owner_fold_index: int
    owner_target_id: str
    training_ordinals: tuple[int, ...]
    training_target_ids: tuple[str, ...]
    reader_state_sha256: str
    slow_state_sha256: str
    heldout_action_pool_sha256: str
    upstream_prediction_freeze_sha256: str
    active_coordinate_plan_sha256: str
    calibration_freeze_file_sha256: str
    calibration_freeze_sha256: str
    heldout_freeze_file_sha256: str
    heldout_freeze_sha256: str
    quantizer: VerifiedO1C22Quantizer
    calibration_packets: tuple[VerifiedO1C22Packet, ...]
    heldout_packet: VerifiedO1C22Packet

    def calibration_packet(self, source_ordinal: int) -> VerifiedO1C22Packet:
        if (
            isinstance(source_ordinal, bool)
            or source_ordinal not in self.training_ordinals
        ):
            raise KeyError(source_ordinal)
        for packet in self.calibration_packets:
            if packet.source_ordinal == source_ordinal:
                return packet
        raise AssertionError("verified calibration packet inventory is incomplete")


@dataclass(frozen=True, slots=True)
class VerifiedO1C22PacketCorpus:
    """Path-free and label-free projection of authoritative O1C-0022 evidence."""

    schema: str
    attempt_id: str
    capsule_manifest_sha256: str
    artifact_index_sha256: str
    folds: tuple[VerifiedO1C22OwnerFold, ...]
    manager_authority: O1C22ManagerAuthorityReceipt
    _factory_token: InitVar[object] = None
    _factory_marker: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FACTORY_TOKEN:
            raise O1C29PacketCorpusError("verified packet corpus is factory-only")
        object.__setattr__(self, "_factory_marker", _FACTORY_MARKER)
        authority = self.manager_authority
        if (
            getattr(authority, "_factory_marker", None) is not _FACTORY_MARKER
            or self.schema != PACKET_CORPUS_SCHEMA
            or self.attempt_id != UPSTREAM_ATTEMPT_ID
            or authority.attempt_id != self.attempt_id
            or authority.capsule_manifest_sha256 != self.capsule_manifest_sha256
            or authority.artifact_index_sha256 != self.artifact_index_sha256
        ):
            raise O1C29PacketCorpusError("packet corpus authority binding differs")

    def fold(self, owner_fold_index: int) -> VerifiedO1C22OwnerFold:
        if (
            isinstance(owner_fold_index, bool)
            or not isinstance(owner_fold_index, int)
            or not 0 <= owner_fold_index < len(self.folds)
        ):
            raise KeyError(owner_fold_index)
        fold = self.folds[owner_fold_index]
        if fold.owner_fold_index != owner_fold_index:
            raise AssertionError("verified owner-fold order differs")
        return fold

    @property
    def calibration_packets(self) -> tuple[VerifiedO1C22Packet, ...]:
        return tuple(
            packet for fold in self.folds for packet in fold.calibration_packets
        )

    @property
    def heldout_packets(self) -> tuple[VerifiedO1C22Packet, ...]:
        return tuple(fold.heldout_packet for fold in self.folds)

    @property
    def quantizers(self) -> tuple[VerifiedO1C22Quantizer, ...]:
        return tuple(fold.quantizer for fold in self.folds)


def require_factory_minted_o1c22_packet_corpus(
    value: object,
) -> O1C22ManagerAuthorityReceipt:
    """Fail closed unless ``value`` was minted by this module's verifier."""

    if (
        type(value) is not VerifiedO1C22PacketCorpus
        or getattr(value, "_factory_marker", None) is not _FACTORY_MARKER
    ):
        raise O1C29PacketCorpusError("verified packet corpus factory marker differs")
    corpus = cast(VerifiedO1C22PacketCorpus, value)
    authority = corpus.manager_authority
    if getattr(authority, "_factory_marker", None) is not _FACTORY_MARKER:
        raise O1C29PacketCorpusError("manager authority factory marker differs")
    if (
        corpus.capsule_manifest_sha256 != authority.capsule_manifest_sha256
        or corpus.artifact_index_sha256 != authority.artifact_index_sha256
    ):
        raise O1C29PacketCorpusError("manager authority identity differs")
    return authority


def _read_indexed_artifact(
    artifacts_root: Path,
    artifacts: Mapping[str, object],
    relative: str,
    expected_phase: str,
) -> bytes:
    entry = _mapping(artifacts.get(relative), f"artifact index entry {relative}")
    if set(entry) != {"sha256", "bytes", "phase"}:
        raise O1C29PacketCorpusError(f"artifact index entry differs: {relative}")
    digest = _sha256(entry.get("sha256"), f"artifact {relative} SHA-256")
    size = _integer(entry.get("bytes"), f"artifact {relative} bytes", 0, 1 << 40)
    if entry.get("phase") != expected_phase:
        raise O1C29PacketCorpusError(f"artifact phase differs: {relative}")
    root = artifacts_root.resolve(strict=True)
    try:
        path = (root / relative).resolve(strict=True)
    except OSError as exc:
        raise O1C29PacketCorpusError(f"artifact is unavailable: {relative}") from exc
    if not path.is_relative_to(root) or not path.is_file():
        raise O1C29PacketCorpusError(f"artifact escapes publication: {relative}")
    payload = path.read_bytes()
    if len(payload) != size or _sha256_bytes(payload) != digest:
        raise O1C29PacketCorpusError(f"artifact index commitment differs: {relative}")
    return payload


def _freeze_document(payload: bytes, field: str) -> Mapping[str, object]:
    document = dict(_decode_json(payload, field))
    supplied = _sha256(document.pop("freeze_sha256", None), f"{field} freeze SHA")
    if supplied != _sha256_bytes(canonical_json_bytes(document)):
        raise O1C29PacketCorpusError(f"{field} self-commitment differs")
    return {**document, "freeze_sha256": supplied}


def _require_freeze_commitment(
    document: Mapping[str, object],
    relative: str,
    payload: bytes,
) -> None:
    commitments = _mapping(document.get("artifacts"), "freeze artifacts")
    commitment = _mapping(commitments.get(relative), f"freeze commitment {relative}")
    if set(commitment) != {"sha256", "bytes"} or (
        _sha256(commitment.get("sha256"), f"freeze {relative} SHA-256")
        != _sha256_bytes(payload)
        or _integer(commitment.get("bytes"), f"freeze {relative} bytes", 0, 1 << 40)
        != len(payload)
    ):
        raise O1C29PacketCorpusError(f"freeze commitment differs: {relative}")


def _decode_packet(
    payload: bytes,
    *,
    role: str,
    owner_fold_index: int,
    source_ordinal: int,
    reader_state_sha256: str,
    slow_state_sha256: str,
) -> tuple[VerifiedO1C22Packet, PacketDeltaExtraction]:
    try:
        extraction = PacketDeltaExtraction.from_bytes(payload)
    except O1C22PacketCodecError as exc:
        raise O1C29PacketCorpusError(
            "packet JSON violates the frozen wire ABI"
        ) from exc
    if extraction.ordered_horizons != EXPECTED_HORIZONS:
        raise O1C29PacketCorpusError("packet horizons differ from H64/H65/H96")
    if (
        len(extraction.active_coordinates) != EXPECTED_ACTIVE_COORDINATES
        or set(extraction.active_coordinates) != set(range(EXPECTED_ACTIVE_COORDINATES))
        or len(extraction.groups) != EXPECTED_ACTIVE_COORDINATES
    ):
        raise O1C29PacketCorpusError("packet is not a complete K256 extraction")
    if extraction.observed_slots != EXPECTED_PACKET_SLOTS:
        raise O1C29PacketCorpusError("packet slot count differs from 768")
    if extraction.physical_work_units != EXPECTED_PHYSICAL_WORK:
        raise O1C29PacketCorpusError("packet work differs from 49152")
    if extraction.reader_state_sha256 != reader_state_sha256:
        raise O1C29PacketCorpusError(
            "packet owner reader commitment differs; own-heldout substitution rejected"
        )
    if extraction.slow_state_sha256 != slow_state_sha256:
        raise O1C29PacketCorpusError("packet owner slow-state commitment differs")
    return (
        VerifiedO1C22Packet(
            role=role,
            owner_fold_index=owner_fold_index,
            owner_target_id=_target_id(owner_fold_index),
            source_ordinal=source_ordinal,
            source_target_id=_target_id(source_ordinal),
            packet_json=payload,
            packet_sha256=_sha256_bytes(payload),
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
        ),
        extraction,
    )


def _critical_freeze_identity(
    document: Mapping[str, object],
    *,
    schema: str,
    owner: int,
    phase: str,
    expected_fields: frozenset[str],
) -> None:
    if (
        schema == UPSTREAM_PREDICTION_FREEZE_SCHEMA
        and document.get("scientific_entropy_calls") != 0
    ):
        raise O1C29PacketCorpusError(
            f"fold-{owner} producer scientific_entropy_calls must equal zero"
        )
    if set(document) != expected_fields:
        raise O1C29PacketCorpusError(f"fold-{owner} freeze field inventory differs")
    if (
        document.get("schema") != schema
        or document.get("phase") != phase
        or document.get("fold_index") != owner
        or document.get("held_out_ordinal") != owner
        or document.get("held_out_target_id") != _target_id(owner)
    ):
        raise O1C29PacketCorpusError(f"fold-{owner} freeze owner identity differs")


def _load_owner_fold(
    owner: int,
    artifacts_root: Path,
    artifacts: Mapping[str, object],
) -> VerifiedO1C22OwnerFold:
    target = _target_id(owner)
    calibration_phase = f"CALIBRATION_PREDICTIONS_FROZEN_FOLD_{owner}"
    heldout_phase = f"HELDOUT_PREDICTIONS_FROZEN_FOLD_{owner}"
    calibration_prefix = f"folds/{target}/calibration"
    heldout_prefix = f"folds/{target}/heldout"
    calibration_freeze_relative = f"{calibration_prefix}/prediction_freeze.json"
    heldout_freeze_relative = f"{heldout_prefix}/prediction_freeze.json"
    calibration_freeze_payload = _read_indexed_artifact(
        artifacts_root,
        artifacts,
        calibration_freeze_relative,
        calibration_phase,
    )
    heldout_freeze_payload = _read_indexed_artifact(
        artifacts_root,
        artifacts,
        heldout_freeze_relative,
        heldout_phase,
    )
    calibration_freeze = _freeze_document(
        calibration_freeze_payload, f"fold-{owner} calibration freeze"
    )
    heldout_freeze = _freeze_document(
        heldout_freeze_payload, f"fold-{owner} heldout freeze"
    )
    _critical_freeze_identity(
        calibration_freeze,
        schema=UPSTREAM_CALIBRATION_FREEZE_SCHEMA,
        owner=owner,
        phase=_CALIBRATION_PHASE,
        expected_fields=_CALIBRATION_FREEZE_FIELDS,
    )
    _critical_freeze_identity(
        heldout_freeze,
        schema=UPSTREAM_PREDICTION_FREEZE_SCHEMA,
        owner=owner,
        phase=_HELDOUT_PHASE,
        expected_fields=_HELDOUT_FREEZE_FIELDS,
    )
    expected_training = tuple(
        (owner + offset) % EXPECTED_FOLDS for offset in range(1, EXPECTED_FOLDS)
    )
    training_ordinals = _sequence_of_ints(
        calibration_freeze.get("training_ordinals"), "training ordinals"
    )
    training_targets = _sequence_of_strings(
        calibration_freeze.get("training_target_ids"), "training target IDs"
    )
    expected_targets = tuple(_target_id(ordinal) for ordinal in expected_training)
    if (
        training_ordinals != expected_training
        or training_targets != expected_targets
        or owner in training_ordinals
        or calibration_freeze.get("labels_used_by_this_fold_before_calibration_freeze")
        != []
        or calibration_freeze.get("held_out_label_used_for_this_fold") is not False
        or calibration_freeze.get("reader_updates") != 0
        or calibration_freeze.get("solver_calls") != 0
        or _sequence_of_ints(
            heldout_freeze.get("calibration_label_ordinals_used_for_this_fold"),
            "heldout calibration ordinals",
        )
        != expected_training
        or heldout_freeze.get("active_coordinate_counts") != [12, 52, 128, 256]
        or heldout_freeze.get("prediction_arms") != list(_PREDICTION_ARMS)
        or heldout_freeze.get("held_out_label_used_for_this_fold") is not False
        or heldout_freeze.get("held_out_reader_updates") != 0
        or heldout_freeze.get("solver_calls") != 0
    ):
        raise O1C29PacketCorpusError(f"fold-{owner} nested training identity differs")
    reader_sha = _sha256(
        calibration_freeze.get("reader_state_sha256"), "reader state SHA"
    )
    slow_sha = _sha256(calibration_freeze.get("slow_state_sha256"), "slow state SHA")
    if (
        heldout_freeze.get("reader_state_sha256") != reader_sha
        or heldout_freeze.get("slow_state_sha256") != slow_sha
    ):
        raise O1C29PacketCorpusError(f"fold-{owner} reader lineage differs")
    quantizer_sha = _sha256(calibration_freeze.get("quantizer_sha256"), "quantizer SHA")
    if heldout_freeze.get("quantizer_sha256") != quantizer_sha:
        raise O1C29PacketCorpusError(f"fold-{owner} quantizer lineage differs")
    heldout_pool_sha = _sha256(
        heldout_freeze.get("held_out_action_pool_sha256"),
        "heldout action-pool SHA",
    )
    upstream_freeze_sha = _sha256(
        heldout_freeze.get("upstream_prediction_freeze_sha256"),
        "upstream prediction-freeze SHA",
    )
    active_plan_sha = _sha256(
        heldout_freeze.get("active_coordinate_plan_sha256"),
        "active-coordinate plan SHA",
    )

    calibration_quantizer_relative = f"{calibration_prefix}/quantizer.json"
    heldout_quantizer_relative = f"{heldout_prefix}/quantizer.json"
    quantizer_payload = _read_indexed_artifact(
        artifacts_root,
        artifacts,
        calibration_quantizer_relative,
        calibration_phase,
    )
    heldout_quantizer_payload = _read_indexed_artifact(
        artifacts_root,
        artifacts,
        heldout_quantizer_relative,
        heldout_phase,
    )
    _require_freeze_commitment(
        calibration_freeze, calibration_quantizer_relative, quantizer_payload
    )
    _require_freeze_commitment(
        heldout_freeze, heldout_quantizer_relative, heldout_quantizer_payload
    )
    if (
        quantizer_payload != heldout_quantizer_payload
        or _sha256_bytes(quantizer_payload) != quantizer_sha
    ):
        raise O1C29PacketCorpusError(f"fold-{owner} quantizer bytes differ")
    try:
        decoded_quantizer = FrozenMedianAbsQuantizer.from_bytes(quantizer_payload)
    except O1C22PacketCodecError as exc:
        raise O1C29PacketCorpusError("quantizer violates the frozen wire ABI") from exc
    if (
        decoded_quantizer.horizons != EXPECTED_HORIZONS
        or decoded_quantizer.total_counts != (EXPECTED_PACKET_SLOTS,) * 3
    ):
        raise O1C29PacketCorpusError(f"fold-{owner} quantizer corpus shape differs")

    calibration_packets: list[VerifiedO1C22Packet] = []
    calibration_extractions: list[PacketDeltaExtraction] = []
    for source_ordinal, source_target in zip(training_ordinals, training_targets):
        relative = f"{calibration_prefix}/source-{source_target}/packet_deltas.json"
        payload = _read_indexed_artifact(
            artifacts_root, artifacts, relative, calibration_phase
        )
        _require_freeze_commitment(calibration_freeze, relative, payload)
        packet, extraction = _decode_packet(
            payload,
            role="calibration",
            owner_fold_index=owner,
            source_ordinal=source_ordinal,
            reader_state_sha256=reader_sha,
            slow_state_sha256=slow_sha,
        )
        calibration_packets.append(packet)
        calibration_extractions.append(extraction)
    recomputed_quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
        tuple(
            group
            for extraction in calibration_extractions
            for group in extraction.groups
        ),
        horizons=EXPECTED_HORIZONS,
    )
    if recomputed_quantizer.to_bytes() != quantizer_payload:
        raise O1C29PacketCorpusError(
            f"fold-{owner} quantizer is not fitted from its three frozen packets"
        )

    heldout_relative = f"{heldout_prefix}/k256/packet_deltas.json"
    heldout_payload = _read_indexed_artifact(
        artifacts_root, artifacts, heldout_relative, heldout_phase
    )
    _require_freeze_commitment(heldout_freeze, heldout_relative, heldout_payload)
    heldout_packet, heldout_extraction = _decode_packet(
        heldout_payload,
        role="heldout",
        owner_fold_index=owner,
        source_ordinal=owner,
        reader_state_sha256=reader_sha,
        slow_state_sha256=slow_sha,
    )
    if heldout_packet.action_pool_sha256 != heldout_pool_sha:
        raise O1C29PacketCorpusError(f"fold-{owner} heldout action-pool differs")
    packet_reader_widths = {
        extraction.reader_state_bytes
        for extraction in (*calibration_extractions, heldout_extraction)
    }
    packet_slow_widths = {
        extraction.slow_state_bytes
        for extraction in (*calibration_extractions, heldout_extraction)
    }
    if len(packet_reader_widths) != 1 or len(packet_slow_widths) != 1:
        raise O1C29PacketCorpusError(f"fold-{owner} reader state widths differ")

    return VerifiedO1C22OwnerFold(
        owner_fold_index=owner,
        owner_target_id=target,
        training_ordinals=training_ordinals,
        training_target_ids=training_targets,
        reader_state_sha256=reader_sha,
        slow_state_sha256=slow_sha,
        heldout_action_pool_sha256=heldout_pool_sha,
        upstream_prediction_freeze_sha256=upstream_freeze_sha,
        active_coordinate_plan_sha256=active_plan_sha,
        calibration_freeze_file_sha256=_sha256_bytes(calibration_freeze_payload),
        calibration_freeze_sha256=cast(str, calibration_freeze["freeze_sha256"]),
        heldout_freeze_file_sha256=_sha256_bytes(heldout_freeze_payload),
        heldout_freeze_sha256=cast(str, heldout_freeze["freeze_sha256"]),
        quantizer=VerifiedO1C22Quantizer(
            owner_fold_index=owner,
            owner_target_id=target,
            quantizer_json=quantizer_payload,
            quantizer_sha256=quantizer_sha,
            public_replay_ledger_sha256=(decoded_quantizer.public_replay_ledger_sha256),
            ordered_horizons=decoded_quantizer.horizons,
            total_counts=decoded_quantizer.total_counts,
            nonzero_counts=decoded_quantizer.nonzero_counts,
        ),
        calibration_packets=tuple(calibration_packets),
        heldout_packet=heldout_packet,
    )


def _mint_manager_authority(
    source: O1C22PostResultSource,
    index_payload: bytes,
    artifacts: Mapping[str, object],
) -> O1C22ManagerAuthorityReceipt:
    finalized = source.finalized
    capsule = finalized.path.resolve(strict=True)
    verification_bytes = 0
    for candidate in capsule.rglob("*"):
        if candidate.is_symlink():
            raise O1C29PacketCorpusError("manager-verified capsule contains symlink")
        if candidate.is_file():
            verification_bytes += candidate.stat().st_size
    label_entry = _mapping(artifacts.get("labels.bitpack"), "labels index entry")
    if set(label_entry) != {"sha256", "bytes", "phase"}:
        raise O1C29PacketCorpusError("labels index entry differs")
    unsigned = {
        "schema": MANAGER_AUTHORITY_SCHEMA,
        "attempt_id": UPSTREAM_ATTEMPT_ID,
        "capsule_manifest_sha256": _sha256(
            finalized.manifest_sha256, "capsule manifest SHA"
        ),
        "artifact_index_sha256": _sha256_bytes(index_payload),
        "artifact_index_bytes": len(index_payload),
        "labels_relative": "labels.bitpack",
        "labels_sha256": _sha256(label_entry.get("sha256"), "labels SHA"),
        "labels_bytes": _integer(label_entry.get("bytes"), "labels bytes", 0, 1 << 40),
        "labels_phase": label_entry.get("phase"),
        "trusted_manager_verification_count": 1,
        "trusted_manager_verification_bytes": verification_bytes,
        "manager_checked_member_count": finalized.verification.checked,
    }
    if not isinstance(unsigned["labels_phase"], str):
        raise O1C29PacketCorpusError("labels phase differs")
    return O1C22ManagerAuthorityReceipt(
        **unsigned,
        receipt_sha256=_sha256_bytes(canonical_json_bytes(unsigned)),
        _factory_token=_FACTORY_TOKEN,
    )


def _project_verified_source(
    source: O1C22PostResultSource,
) -> VerifiedO1C22PacketCorpus:
    """Project one already-authoritative source without exporting its capability."""

    finalized = source.finalized
    if finalized.attempt_id != UPSTREAM_ATTEMPT_ID or not finalized.verification.ok:
        raise O1C29PacketCorpusError("O1C-0022 authority identity differs")
    index_sha = _sha256(source.artifact_index_sha256, "artifact index SHA")
    artifacts_root = finalized.path / "artifacts"
    index_path = artifacts_root / "artifact_index.json"
    try:
        index_payload = index_path.read_bytes()
    except OSError as exc:
        raise O1C29PacketCorpusError("O1C-0022 artifact index is unavailable") from exc
    if _sha256_bytes(index_payload) != index_sha:
        raise O1C29PacketCorpusError("verified artifact-index SHA changed")
    index = _decode_json(index_payload, "O1C-0022 artifact index")
    artifacts = _mapping(index.get("artifacts"), "indexed artifacts")
    if (
        index.get("schema") != UPSTREAM_ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or len(artifacts) != EXPECTED_UPSTREAM_ARTIFACTS
        or index.get("indexed_artifact_count") != EXPECTED_UPSTREAM_ARTIFACTS
    ):
        raise O1C29PacketCorpusError("O1C-0022 artifact-index identity differs")
    folds = tuple(
        _load_owner_fold(owner, artifacts_root, artifacts)
        for owner in range(EXPECTED_FOLDS)
    )
    heldout_by_source = {fold.owner_fold_index: fold.heldout_packet for fold in folds}
    for fold in folds:
        for packet in fold.calibration_packets:
            source_anchor = heldout_by_source[packet.source_ordinal]
            if (
                packet.action_pool_sha256 != source_anchor.action_pool_sha256
                or packet.source_stream_sha256 != source_anchor.source_stream_sha256
            ):
                raise O1C29PacketCorpusError(
                    "calibration packet source pool commitment differs"
                )
    authority = _mint_manager_authority(source, index_payload, artifacts)
    corpus = VerifiedO1C22PacketCorpus(
        schema=PACKET_CORPUS_SCHEMA,
        attempt_id=UPSTREAM_ATTEMPT_ID,
        capsule_manifest_sha256=_sha256(
            finalized.manifest_sha256, "capsule manifest SHA"
        ),
        artifact_index_sha256=index_sha,
        folds=folds,
        manager_authority=authority,
        _factory_token=_FACTORY_TOKEN,
    )
    if (
        len(corpus.calibration_packets) != EXPECTED_CALIBRATION_PACKETS
        or len(corpus.heldout_packets) != EXPECTED_HELDOUT_PACKETS
        or len(corpus.quantizers) != EXPECTED_QUANTIZERS
    ):
        raise O1C29PacketCorpusError("packet facade inventory differs")
    return corpus


def _load_manager_authoritative_source(
    config: O1C23RunConfig,
) -> O1C22PostResultSource:
    """Encapsulate the producer-authentic, manager-pinned successor authority."""

    manager = RunCapsuleManager(config.root)
    candidate = manager.finalized_attempt(UPSTREAM_ATTEMPT_ID)
    if candidate is None:
        raise O1C29PacketCorpusError(
            "manager-authoritative finalized O1C-0022 is unavailable"
        )
    try:
        return load_producer_authentic_o1c22_source(config, manager, candidate)
    except O1C23SelectionAuthorityError as exc:
        raise O1C29PacketCorpusError(
            "producer-authentic successor authority rejected O1C-0022"
        ) from exc


def load_trusted_verified_o1c22_packet_corpus(
    config: O1C23RunConfig,
    authoritative: object,
) -> VerifiedO1C22PacketCorpus:
    """Project the direct result of the trusted process's sole manager pass."""

    try:
        source = load_trusted_manager_verified_o1c22_source(
            config,
            cast(object, authoritative),  # type: ignore[arg-type]
        )
    except O1C23SelectionAuthorityError as exc:
        raise O1C29PacketCorpusError(
            "trusted manager successor authority rejected O1C-0022"
        ) from exc
    return _project_verified_source(source)


def load_verified_o1c22_packet_corpus(
    config: O1C23RunConfig,
) -> VerifiedO1C22PacketCorpus:
    """Load only the capability-safe scientific packet projection.

    ``config`` must be produced by
    ``load_o1c22_postresult_composer_run_config`` so the complete frozen
    verifier and O1C-0022 static sources are source-pinned. The authoritative
    source object and its capsule path remain local to this call and are never
    returned.
    """

    return _project_verified_source(_load_manager_authoritative_source(config))


def _bytes_to_wire(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _bytes_from_wire(value: object, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise O1C29PacketCorpusError(f"{field_name} must be base64 text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise O1C29PacketCorpusError(f"{field_name} base64 differs") from exc


def _packet_to_wire(packet: VerifiedO1C22Packet) -> dict[str, object]:
    return {
        field_name: (
            _bytes_to_wire(value)
            if field_name == "packet_json"
            else list(value)
            if isinstance(value, tuple)
            else value
        )
        for field_name, value in (
            (name, getattr(packet, name))
            for name in VerifiedO1C22Packet.__dataclass_fields__
        )
    }


def _packet_from_wire(value: object) -> VerifiedO1C22Packet:
    row = _mapping(value, "packet wire")
    fields = set(VerifiedO1C22Packet.__dataclass_fields__)
    if set(row) != fields:
        raise O1C29PacketCorpusError("packet wire fields differ")
    owner = _integer(row["owner_fold_index"], "packet owner", 0, 3)
    source = _integer(row["source_ordinal"], "packet source", 0, 3)
    role = row["role"]
    if role not in {"calibration", "heldout"}:
        raise O1C29PacketCorpusError("packet role differs")
    packet, _ = _decode_packet(
        _bytes_from_wire(row["packet_json"], "packet JSON"),
        role=cast(str, role),
        owner_fold_index=owner,
        source_ordinal=source,
        reader_state_sha256=_sha256(row["reader_state_sha256"], "reader SHA"),
        slow_state_sha256=_sha256(row["slow_state_sha256"], "slow SHA"),
    )
    expected = _packet_to_wire(packet)
    if dict(row) != expected:
        raise O1C29PacketCorpusError("packet wire semantic projection differs")
    return packet


def _new_trusted_packet_corpus_transfer_nonce() -> str:
    nonce = secrets.token_hex(32)
    _TRUSTED_TRANSFER_NONCES.add(nonce)
    return nonce


def _discard_trusted_packet_corpus_transfer_nonce(nonce: str) -> None:
    _TRUSTED_TRANSFER_NONCES.discard(nonce)


def serialize_verified_o1c22_packet_corpus(
    corpus: VerifiedO1C22PacketCorpus,
    *,
    _trusted_nonce: str | None = None,
) -> bytes:
    """Serialize only the validated label-free scientific facade."""

    require_factory_minted_o1c22_packet_corpus(corpus)
    if _trusted_nonce not in _TRUSTED_TRANSFER_NONCES:
        raise O1C29PacketCorpusError("trusted packet transfer capability differs")
    folds: list[dict[str, object]] = []
    for owner in corpus.folds:
        quantizer = owner.quantizer
        folds.append(
            {
                "owner_fold_index": owner.owner_fold_index,
                "owner_target_id": owner.owner_target_id,
                "training_ordinals": list(owner.training_ordinals),
                "training_target_ids": list(owner.training_target_ids),
                "reader_state_sha256": owner.reader_state_sha256,
                "slow_state_sha256": owner.slow_state_sha256,
                "heldout_action_pool_sha256": owner.heldout_action_pool_sha256,
                "upstream_prediction_freeze_sha256": owner.upstream_prediction_freeze_sha256,
                "active_coordinate_plan_sha256": owner.active_coordinate_plan_sha256,
                "calibration_freeze_file_sha256": owner.calibration_freeze_file_sha256,
                "calibration_freeze_sha256": owner.calibration_freeze_sha256,
                "heldout_freeze_file_sha256": owner.heldout_freeze_file_sha256,
                "heldout_freeze_sha256": owner.heldout_freeze_sha256,
                "quantizer": {
                    "owner_fold_index": quantizer.owner_fold_index,
                    "owner_target_id": quantizer.owner_target_id,
                    "quantizer_json": _bytes_to_wire(quantizer.quantizer_json),
                    "quantizer_sha256": quantizer.quantizer_sha256,
                    "public_replay_ledger_sha256": quantizer.public_replay_ledger_sha256,
                    "ordered_horizons": list(quantizer.ordered_horizons),
                    "total_counts": list(quantizer.total_counts),
                    "nonzero_counts": list(quantizer.nonzero_counts),
                },
                "calibration_packets": [
                    _packet_to_wire(packet) for packet in owner.calibration_packets
                ],
                "heldout_packet": _packet_to_wire(owner.heldout_packet),
            }
        )
    unsigned = {
        "schema": PACKET_CORPUS_WIRE_SCHEMA,
        "transfer_nonce": _trusted_nonce,
        "attempt_id": corpus.attempt_id,
        "capsule_manifest_sha256": corpus.capsule_manifest_sha256,
        "artifact_index_sha256": corpus.artifact_index_sha256,
        "manager_authority": corpus.manager_authority.receipt_document(),
        "folds": folds,
    }
    return canonical_json_bytes(
        {
            **unsigned,
            "wire_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
        }
    )


def deserialize_verified_o1c22_packet_corpus(
    payload: bytes,
    *,
    _trusted_nonce: str | None = None,
) -> VerifiedO1C22PacketCorpus:
    """Strictly revalidate the trusted child wire projection before minting."""

    if _trusted_nonce not in _TRUSTED_TRANSFER_NONCES:
        raise O1C29PacketCorpusError("trusted packet transfer capability differs")
    _TRUSTED_TRANSFER_NONCES.remove(cast(str, _trusted_nonce))
    top = _decode_json(payload, "packet corpus wire")
    expected_top = {
        "schema",
        "transfer_nonce",
        "wire_sha256",
        "attempt_id",
        "capsule_manifest_sha256",
        "artifact_index_sha256",
        "manager_authority",
        "folds",
    }
    unsigned = dict(top)
    supplied_wire_sha = _sha256(unsigned.pop("wire_sha256", None), "wire SHA")
    if (
        set(top) != expected_top
        or top.get("schema") != PACKET_CORPUS_WIRE_SCHEMA
        or top.get("transfer_nonce") != _trusted_nonce
        or supplied_wire_sha != _sha256_bytes(canonical_json_bytes(unsigned))
    ):
        raise O1C29PacketCorpusError("packet corpus wire identity differs")
    authority_row = _mapping(top["manager_authority"], "manager authority wire")
    authority_fields = {
        name
        for name in O1C22ManagerAuthorityReceipt.__dataclass_fields__
        if not name.startswith("_factory_")
    }
    if set(authority_row) != authority_fields:
        raise O1C29PacketCorpusError("manager authority wire fields differ")
    authority = O1C22ManagerAuthorityReceipt(
        schema=_string(authority_row["schema"], "authority schema"),
        attempt_id=_string(authority_row["attempt_id"], "authority attempt"),
        capsule_manifest_sha256=_sha256(
            authority_row["capsule_manifest_sha256"], "authority manifest"
        ),
        artifact_index_sha256=_sha256(
            authority_row["artifact_index_sha256"], "authority index"
        ),
        artifact_index_bytes=_integer(
            authority_row["artifact_index_bytes"], "authority index bytes", 1, 1 << 40
        ),
        labels_relative=_string(
            authority_row["labels_relative"], "authority labels relative"
        ),
        labels_sha256=_sha256(authority_row["labels_sha256"], "authority labels"),
        labels_bytes=_integer(
            authority_row["labels_bytes"], "authority labels bytes", 1, 1 << 40
        ),
        labels_phase=_string(authority_row["labels_phase"], "authority labels phase"),
        trusted_manager_verification_count=_integer(
            authority_row["trusted_manager_verification_count"],
            "authority verification count",
            1,
            1,
        ),
        trusted_manager_verification_bytes=_integer(
            authority_row["trusted_manager_verification_bytes"],
            "authority verification bytes",
            1,
            1 << 50,
        ),
        manager_checked_member_count=_integer(
            authority_row["manager_checked_member_count"],
            "authority checked members",
            1,
            1 << 20,
        ),
        receipt_sha256=_sha256(authority_row["receipt_sha256"], "authority receipt"),
        _factory_token=_FACTORY_TOKEN,
    )
    raw_folds = top["folds"]
    if not isinstance(raw_folds, list) or len(raw_folds) != EXPECTED_FOLDS:
        raise O1C29PacketCorpusError("packet corpus fold wire differs")
    folds: list[VerifiedO1C22OwnerFold] = []
    owner_fields = set(VerifiedO1C22OwnerFold.__dataclass_fields__)
    quantizer_fields = set(VerifiedO1C22Quantizer.__dataclass_fields__)
    for expected_owner, raw_owner in enumerate(raw_folds):
        row = _mapping(raw_owner, f"owner-{expected_owner} wire")
        if set(row) != owner_fields:
            raise O1C29PacketCorpusError("owner wire fields differ")
        quantizer_row = _mapping(row["quantizer"], "quantizer wire")
        if set(quantizer_row) != quantizer_fields:
            raise O1C29PacketCorpusError("quantizer wire fields differ")
        quantizer_payload = _bytes_from_wire(
            quantizer_row["quantizer_json"], "quantizer JSON"
        )
        try:
            decoded_quantizer = FrozenMedianAbsQuantizer.from_bytes(quantizer_payload)
        except O1C22PacketCodecError as exc:
            raise O1C29PacketCorpusError("quantizer wire ABI differs") from exc
        quantizer = VerifiedO1C22Quantizer(
            owner_fold_index=expected_owner,
            owner_target_id=_target_id(expected_owner),
            quantizer_json=quantizer_payload,
            quantizer_sha256=decoded_quantizer.sha256,
            public_replay_ledger_sha256=decoded_quantizer.public_replay_ledger_sha256,
            ordered_horizons=decoded_quantizer.horizons,
            total_counts=decoded_quantizer.total_counts,
            nonzero_counts=decoded_quantizer.nonzero_counts,
        )
        expected_quantizer = {
            **{name: getattr(quantizer, name) for name in quantizer_fields},
            "quantizer_json": _bytes_to_wire(quantizer.quantizer_json),
            "ordered_horizons": list(quantizer.ordered_horizons),
            "total_counts": list(quantizer.total_counts),
            "nonzero_counts": list(quantizer.nonzero_counts),
        }
        if dict(quantizer_row) != expected_quantizer:
            raise O1C29PacketCorpusError("quantizer wire semantic projection differs")
        raw_calibration = row["calibration_packets"]
        if not isinstance(raw_calibration, list) or len(raw_calibration) != 3:
            raise O1C29PacketCorpusError("calibration packet wire differs")
        calibration = tuple(_packet_from_wire(item) for item in raw_calibration)
        heldout = _packet_from_wire(row["heldout_packet"])
        owner = VerifiedO1C22OwnerFold(
            owner_fold_index=_integer(
                row["owner_fold_index"], "owner fold index", 0, 3
            ),
            owner_target_id=_string(row["owner_target_id"], "owner target ID"),
            training_ordinals=tuple(
                _sequence_of_ints(row["training_ordinals"], "training ordinals")
            ),
            training_target_ids=tuple(
                _sequence_of_strings(row["training_target_ids"], "training targets")
            ),
            reader_state_sha256=_sha256(row["reader_state_sha256"], "reader state"),
            slow_state_sha256=_sha256(row["slow_state_sha256"], "slow state"),
            heldout_action_pool_sha256=_sha256(
                row["heldout_action_pool_sha256"], "heldout action pool"
            ),
            upstream_prediction_freeze_sha256=_sha256(
                row["upstream_prediction_freeze_sha256"], "upstream freeze"
            ),
            active_coordinate_plan_sha256=_sha256(
                row["active_coordinate_plan_sha256"], "active coordinate plan"
            ),
            calibration_freeze_file_sha256=_sha256(
                row["calibration_freeze_file_sha256"], "calibration freeze file"
            ),
            calibration_freeze_sha256=_sha256(
                row["calibration_freeze_sha256"], "calibration freeze"
            ),
            heldout_freeze_file_sha256=_sha256(
                row["heldout_freeze_file_sha256"], "heldout freeze file"
            ),
            heldout_freeze_sha256=_sha256(
                row["heldout_freeze_sha256"], "heldout freeze"
            ),
            quantizer=quantizer,
            calibration_packets=calibration,
            heldout_packet=heldout,
        )
        if owner.owner_fold_index != expected_owner:
            raise O1C29PacketCorpusError("owner wire order differs")
        folds.append(owner)
    corpus = VerifiedO1C22PacketCorpus(
        schema=PACKET_CORPUS_SCHEMA,
        attempt_id=cast(str, top["attempt_id"]),
        capsule_manifest_sha256=cast(str, top["capsule_manifest_sha256"]),
        artifact_index_sha256=cast(str, top["artifact_index_sha256"]),
        folds=tuple(folds),
        manager_authority=authority,
        _factory_token=_FACTORY_TOKEN,
    )
    if (
        len(corpus.calibration_packets) != EXPECTED_CALIBRATION_PACKETS
        or len(corpus.heldout_packets) != EXPECTED_HELDOUT_PACKETS
        or len(corpus.quantizers) != EXPECTED_QUANTIZERS
    ):
        raise O1C29PacketCorpusError("deserialized packet inventory differs")
    for fold in corpus.folds:
        expected_training = tuple(
            (fold.owner_fold_index + offset) % EXPECTED_FOLDS
            for offset in range(1, EXPECTED_FOLDS)
        )
        if (
            fold.training_ordinals != expected_training
            or tuple(packet.source_ordinal for packet in fold.calibration_packets)
            != expected_training
            or fold.heldout_packet.source_ordinal != fold.owner_fold_index
        ):
            raise O1C29PacketCorpusError("deserialized owner lineage differs")
    return corpus


__all__ = [
    "EXPECTED_ACTIVE_COORDINATES",
    "EXPECTED_CALIBRATION_PACKETS",
    "EXPECTED_HELDOUT_PACKETS",
    "EXPECTED_HORIZONS",
    "EXPECTED_PACKET_SLOTS",
    "EXPECTED_PHYSICAL_WORK",
    "EXPECTED_QUANTIZERS",
    "O1C29PacketCorpusError",
    "O1C22ManagerAuthorityReceipt",
    "MANAGER_AUTHORITY_SCHEMA",
    "PACKET_CORPUS_SCHEMA",
    "VerifiedO1C22OwnerFold",
    "VerifiedO1C22Packet",
    "VerifiedO1C22PacketCorpus",
    "VerifiedO1C22Quantizer",
    "load_trusted_verified_o1c22_packet_corpus",
    "load_verified_o1c22_packet_corpus",
    "require_factory_minted_o1c22_packet_corpus",
]
