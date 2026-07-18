"""Real O1C-0029 packet adapter, reveal capability, and frozen scorer.

The three surfaces in this module are intentionally separate:

* the packet adapter accepts only the label-free verified O1C-0022 facade;
* the 128-byte label artifact can open only after the exact 4x4 state barrier;
* scoring consumes already-frozen primary and secondary logits without fitting
  or selecting an arm from the revealed outcomes.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import InitVar, dataclass, field
from typing import Mapping, Sequence

import numpy as np

from .living_inverse import KEY_BITS, bits_to_key
from .o1c22_packet_codec import O1C22PacketCodecError, PacketDeltaExtraction
from .o1c29_packet_corpus import (
    PACKET_CORPUS_SCHEMA,
    O1C29PacketCorpusError,
    VerifiedO1C22Packet,
    VerifiedO1C22PacketCorpus,
    require_factory_minted_o1c22_packet_corpus,
)
from .o1c29_stacked_hot_calibration import (
    PRIMARY_OPERATOR_ID,
    SECONDARY_OPERATOR_ID,
    AllowlistedFoldLabelBroker,
    FrozenOuterPrediction,
    GlobalStateFreeze,
    OwnerPacketCorpus,
    StackedHotCalibrationConfig,
    StackedHotCalibrationResult,
    freeze_owner_quantizer,
)
from .posterior_logit_frontier import (
    LOGIT_TOPOLOGY_TIE_POLICY,
    iter_factorized_logit_topk,
)


CANONICAL_FOLD_IDS = tuple(f"build-{index:04d}" for index in range(4))
CANONICAL_ALPHA = 1.0
CANONICAL_CONFIDENCE_TEMPERATURE_GRID = (0.5, 1.0, 2.0, 4.0)
LABEL_BITPACK_BYTES = 128
MAXIMUM_TOP_K_LIMIT = 65_536
ADAPTER_SCHEMA = "o1-256-o1c29-real-packet-adapter-v1"
MANAGER_AUTHORITY_SCHEMA = "o1-256-o1c29-manager-authority-commitment-v1"
LABEL_CAPABILITY_SCHEMA = "o1-256-o1c29-post-prediction-label-capability-v1"
FOLD_SCORE_SCHEMA = "o1-256-o1c29-frozen-fold-arm-score-v1"
ARM_SCORE_SCHEMA = "o1-256-o1c29-frozen-arm-score-v1"
SCORE_SCHEMA = "o1-256-o1c29-frozen-two-arm-score-v1"
LOCAL_RANK_TIE_POLICY = (
    "ascending-exact-binary-logit-flip-penalty-then-ascending-"
    "little-endian-numeric-value"
)
GLOBAL_FRONTIER_TIE_POLICY = LOGIT_TOPOLOGY_TIE_POLICY
O1C22_ARTIFACT_INDEX_SCHEMA = "o1-256-o1c19-causal-vault-artifact-index-v1"
O1C22_ARTIFACT_COUNT = 384
O1C22_LABEL_PHASE = "POST_FREEZE_SCORED_RESULT"
_INPUTS_FACTORY = object()
_MANAGER_AUTHORITY_FACTORY = object()
_LABEL_FACTORY = object()
_FOLD_SCORE_FACTORY = object()
_ARM_SCORE_FACTORY = object()
_TWO_ARM_SCORE_FACTORY = object()
_HEX = frozenset("0123456789abcdef")
_ARM_ORDER = (
    ("primary", PRIMARY_OPERATOR_ID),
    ("secondary", SECONDARY_OPERATOR_ID),
)


class O1C29RealProtocolError(ValueError):
    """The real packet, reveal, or frozen-score protocol differs."""


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise O1C29RealProtocolError("protocol receipt is not finite JSON") from exc
    return rendered.encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _document_sha256(value: Mapping[str, object]) -> str:
    return _sha256_bytes(_canonical_json_bytes(dict(value)))


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C29RealProtocolError(f"{field_name} must be lowercase SHA-256")
    return value


def _readonly_bits(value: np.ndarray) -> np.ndarray:
    raw = np.asarray(value)
    if (
        raw.dtype != np.uint8
        or raw.shape != (KEY_BITS,)
        or bool(((raw != 0) & (raw != 1)).any())
    ):
        raise O1C29RealProtocolError("decoded label row differs")
    return np.frombuffer(raw.tobytes(order="C"), dtype=np.uint8)


def _top_k_limit(value: object) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAXIMUM_TOP_K_LIMIT
    ):
        raise O1C29RealProtocolError(
            f"top_k_limit must be in [1,{MAXIMUM_TOP_K_LIMIT}]"
        )
    return value


@dataclass(frozen=True, slots=True)
class RealProtocolInputs:
    """Canonical label-free inputs for the stacked hot-calibration protocol."""

    config: StackedHotCalibrationConfig
    owner_corpora: tuple[OwnerPacketCorpus, ...] = field(repr=False, compare=False)
    source_capsule_manifest_sha256: str
    source_artifact_index_sha256: str
    receipt_sha256: str
    _factory_token: InitVar[object]
    _factory_marker: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _INPUTS_FACTORY:
            raise O1C29RealProtocolError(
                "real protocol inputs must be created by the verified packet adapter"
            )
        if not isinstance(self.config, StackedHotCalibrationConfig):
            raise TypeError("config must be StackedHotCalibrationConfig")
        if self.config.fold_ids != CANONICAL_FOLD_IDS:
            raise O1C29RealProtocolError("real protocol fold order differs")
        if tuple(row.owner_fold for row in self.owner_corpora) != CANONICAL_FOLD_IDS:
            raise O1C29RealProtocolError("owner packet-corpus order differs")
        for field_name in (
            "source_capsule_manifest_sha256",
            "source_artifact_index_sha256",
            "receipt_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("packet adapter receipt differs")
        object.__setattr__(self, "_factory_marker", _INPUTS_FACTORY)

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": ADAPTER_SCHEMA,
            "config_sha256": self.config.sha256,
            "source_capsule_manifest_sha256": (self.source_capsule_manifest_sha256),
            "source_artifact_index_sha256": self.source_artifact_index_sha256,
            "owner_corpora": [
                {
                    "owner_fold": corpus.owner_fold,
                    "reader_state_sha256": (corpus.quantizer.reader_state_sha256),
                    "quantizer_sha256": corpus.quantizer.quantizer.sha256,
                    "episode_packet_sha256": [
                        {
                            "episode_fold": episode,
                            "packet_sha256": extraction.sha256,
                        }
                        for episode, extraction in corpus.episode_packets
                    ],
                }
                for corpus in self.owner_corpora
            ],
            "labels_accepted_by_adapter": False,
            "episode_order": list(CANONICAL_FOLD_IDS),
        }


@dataclass(frozen=True, slots=True)
class ManagerAuthorityCommitment:
    """Path- and label-free commitment inherited from trusted manager preflight.

    The capability can be minted only from factory-created ``RealProtocolInputs``.
    Those inputs, in turn, can be created only by the verified packet adapter;
    the adapter's corpus is the manager-authoritative preflight projection.
    """

    adapter_receipt_sha256: str
    source_capsule_manifest_sha256: str
    source_artifact_index_sha256: str
    source_artifact_index_bytes: int
    labels_relative: str
    labels_bitpack_sha256: str
    labels_bitpack_bytes: int
    labels_phase: str
    trusted_manager_verification_count: int
    trusted_manager_verification_bytes: int
    manager_checked_member_count: int
    upstream_manager_authority_receipt_sha256: str
    receipt_sha256: str
    _factory_token: InitVar[object]
    _factory_marker: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _MANAGER_AUTHORITY_FACTORY:
            raise O1C29RealProtocolError(
                "manager authority must be bound from verified adapter inputs"
            )
        for field_name in (
            "adapter_receipt_sha256",
            "source_capsule_manifest_sha256",
            "source_artifact_index_sha256",
            "labels_bitpack_sha256",
            "upstream_manager_authority_receipt_sha256",
            "receipt_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if (
            type(self.source_artifact_index_bytes) is not int
            or self.source_artifact_index_bytes <= 0
            or self.labels_relative != "labels.bitpack"
            or type(self.labels_bitpack_bytes) is not int
            or self.labels_bitpack_bytes != LABEL_BITPACK_BYTES
            or self.labels_phase != O1C22_LABEL_PHASE
            or type(self.trusted_manager_verification_count) is not int
            or self.trusted_manager_verification_count != 1
            or type(self.trusted_manager_verification_bytes) is not int
            or self.trusted_manager_verification_bytes <= 0
            or type(self.manager_checked_member_count) is not int
            or self.manager_checked_member_count < O1C22_ARTIFACT_COUNT
        ):
            raise O1C29RealProtocolError("manager authority metadata differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("manager authority receipt differs")
        object.__setattr__(self, "_factory_marker", _MANAGER_AUTHORITY_FACTORY)

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": MANAGER_AUTHORITY_SCHEMA,
            "source_attempt_id": "O1C-0022",
            "adapter_receipt_sha256": self.adapter_receipt_sha256,
            "source_capsule_manifest_sha256": self.source_capsule_manifest_sha256,
            "source_artifact_index_sha256": self.source_artifact_index_sha256,
            "source_artifact_index_bytes": self.source_artifact_index_bytes,
            "labels_relative": self.labels_relative,
            "labels_bitpack_sha256": self.labels_bitpack_sha256,
            "labels_bitpack_bytes": self.labels_bitpack_bytes,
            "labels_phase": self.labels_phase,
            "trusted_manager_verification_count": (
                self.trusted_manager_verification_count
            ),
            "trusted_manager_verification_bytes": (
                self.trusted_manager_verification_bytes
            ),
            "manager_checked_member_count": self.manager_checked_member_count,
            "upstream_manager_authority_receipt_sha256": (
                self.upstream_manager_authority_receipt_sha256
            ),
            "labels_payload_opened": False,
            "authority_origin": "manager-verified-packet-corpus-projection",
        }


def bind_manager_authority_commitment(
    inputs: RealProtocolInputs,
    corpus: VerifiedO1C22PacketCorpus,
) -> ManagerAuthorityCommitment:
    """Bind the trusted preflight authority without filesystem or label access."""

    if (
        not isinstance(inputs, RealProtocolInputs)
        or getattr(inputs, "_factory_marker", None) is not _INPUTS_FACTORY
        or inputs.receipt_sha256 != _document_sha256(inputs.receipt_document())
    ):
        raise O1C29RealProtocolError(
            "manager authority requires factory-created verified adapter inputs"
        )
    try:
        upstream = require_factory_minted_o1c22_packet_corpus(corpus)
    except O1C29PacketCorpusError as exc:
        raise O1C29RealProtocolError(
            "manager authority requires a factory-minted packet corpus"
        ) from exc
    if (
        upstream.attempt_id != "O1C-0022"
        or upstream.capsule_manifest_sha256 != inputs.source_capsule_manifest_sha256
        or upstream.artifact_index_sha256 != inputs.source_artifact_index_sha256
    ):
        raise O1C29RealProtocolError("manager authority packet-corpus lineage differs")
    unsigned = {
        "schema": MANAGER_AUTHORITY_SCHEMA,
        "source_attempt_id": "O1C-0022",
        "adapter_receipt_sha256": inputs.receipt_sha256,
        "source_capsule_manifest_sha256": inputs.source_capsule_manifest_sha256,
        "source_artifact_index_sha256": inputs.source_artifact_index_sha256,
        "source_artifact_index_bytes": upstream.artifact_index_bytes,
        "labels_relative": upstream.labels_relative,
        "labels_bitpack_sha256": upstream.labels_sha256,
        "labels_bitpack_bytes": upstream.labels_bytes,
        "labels_phase": upstream.labels_phase,
        "trusted_manager_verification_count": (
            upstream.trusted_manager_verification_count
        ),
        "trusted_manager_verification_bytes": (
            upstream.trusted_manager_verification_bytes
        ),
        "manager_checked_member_count": upstream.manager_checked_member_count,
        "upstream_manager_authority_receipt_sha256": upstream.receipt_sha256,
        "labels_payload_opened": False,
        "authority_origin": "manager-verified-packet-corpus-projection",
    }
    return ManagerAuthorityCommitment(
        adapter_receipt_sha256=inputs.receipt_sha256,
        source_capsule_manifest_sha256=inputs.source_capsule_manifest_sha256,
        source_artifact_index_sha256=inputs.source_artifact_index_sha256,
        source_artifact_index_bytes=upstream.artifact_index_bytes,
        labels_relative=upstream.labels_relative,
        labels_bitpack_sha256=upstream.labels_sha256,
        labels_bitpack_bytes=upstream.labels_bytes,
        labels_phase=upstream.labels_phase,
        trusted_manager_verification_count=(
            upstream.trusted_manager_verification_count
        ),
        trusted_manager_verification_bytes=(
            upstream.trusted_manager_verification_bytes
        ),
        manager_checked_member_count=upstream.manager_checked_member_count,
        upstream_manager_authority_receipt_sha256=upstream.receipt_sha256,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_MANAGER_AUTHORITY_FACTORY,
    )


def _decode_bound_packet(
    packet: VerifiedO1C22Packet,
    *,
    owner_ordinal: int,
    source_ordinal: int,
    reader_state_sha256: str,
    slow_state_sha256: str,
    expected_role: str,
) -> PacketDeltaExtraction:
    if (
        not isinstance(packet, VerifiedO1C22Packet)
        or packet.owner_fold_index != owner_ordinal
        or packet.owner_target_id != CANONICAL_FOLD_IDS[owner_ordinal]
        or packet.source_ordinal != source_ordinal
        or packet.source_target_id != CANONICAL_FOLD_IDS[source_ordinal]
        or packet.role != expected_role
        or packet.reader_state_sha256 != reader_state_sha256
        or packet.slow_state_sha256 != slow_state_sha256
        or _sha256_bytes(packet.packet_json) != packet.packet_sha256
    ):
        raise O1C29RealProtocolError("verified packet adapter lineage differs")
    try:
        extraction = packet.decode()
    except O1C22PacketCodecError as exc:
        raise O1C29RealProtocolError("verified packet cannot be decoded") from exc
    if (
        extraction.sha256 != packet.packet_sha256
        or extraction.reader_state_sha256 != reader_state_sha256
        or extraction.slow_state_sha256 != slow_state_sha256
        or extraction.source_stream_sha256 != packet.source_stream_sha256
        or extraction.action_pool_sha256 != packet.action_pool_sha256
        or extraction.public_packet_ledger_sha256 != packet.public_packet_ledger_sha256
    ):
        raise O1C29RealProtocolError("decoded packet commitment differs")
    return extraction


def adapt_verified_o1c22_packet_corpus(
    corpus: VerifiedO1C22PacketCorpus,
    *,
    alpha: float = CANONICAL_ALPHA,
    confidence_temperature_grid: Sequence[float] = (
        CANONICAL_CONFIDENCE_TEMPERATURE_GRID
    ),
) -> RealProtocolInputs:
    """Create canonical 4x4 stacked inputs without accepting a label surface."""

    if not isinstance(corpus, VerifiedO1C22PacketCorpus):
        raise TypeError("corpus must be VerifiedO1C22PacketCorpus")
    try:
        require_factory_minted_o1c22_packet_corpus(corpus)
    except O1C29PacketCorpusError as exc:
        raise O1C29RealProtocolError(
            "packet adapter requires a factory-minted verified corpus"
        ) from exc
    if (
        corpus.schema != PACKET_CORPUS_SCHEMA
        or corpus.attempt_id != "O1C-0022"
        or tuple(row.owner_target_id for row in corpus.folds) != CANONICAL_FOLD_IDS
        or tuple(row.owner_fold_index for row in corpus.folds) != tuple(range(4))
    ):
        raise O1C29RealProtocolError("verified corpus identity differs")
    config = StackedHotCalibrationConfig(
        fold_ids=CANONICAL_FOLD_IDS,
        alpha=alpha,
        confidence_temperature_grid=tuple(confidence_temperature_grid),
    )
    owner_corpora: list[OwnerPacketCorpus] = []
    for owner_ordinal, owner in enumerate(corpus.folds):
        owner_fold = CANONICAL_FOLD_IDS[owner_ordinal]
        expected_training = tuple(
            (owner_ordinal + offset) % 4 for offset in range(1, 4)
        )
        if (
            owner.training_ordinals != expected_training
            or owner.training_target_ids
            != tuple(CANONICAL_FOLD_IDS[index] for index in expected_training)
            or owner.quantizer.owner_fold_index != owner_ordinal
            or owner.quantizer.owner_target_id != owner_fold
            or owner.quantizer.quantizer_sha256
            != _sha256_bytes(owner.quantizer.quantizer_json)
        ):
            raise O1C29RealProtocolError("owner quantizer/fold lineage differs")
        quantizer = owner.quantizer.decode()
        if quantizer.sha256 != owner.quantizer.quantizer_sha256:
            raise O1C29RealProtocolError("owner quantizer commitment differs")
        binding = freeze_owner_quantizer(
            config,
            owner_fold=owner_fold,
            reader_state_sha256=owner.reader_state_sha256,
            quantizer=quantizer,
        )
        packets = (*owner.calibration_packets, owner.heldout_packet)
        by_source = {packet.source_ordinal: packet for packet in packets}
        if len(packets) != 4 or set(by_source) != set(range(4)):
            raise O1C29RealProtocolError("owner packet source inventory differs")
        episode_packets = []
        for source_ordinal, episode_fold in enumerate(CANONICAL_FOLD_IDS):
            extraction = _decode_bound_packet(
                by_source[source_ordinal],
                owner_ordinal=owner_ordinal,
                source_ordinal=source_ordinal,
                reader_state_sha256=owner.reader_state_sha256,
                slow_state_sha256=owner.slow_state_sha256,
                expected_role=(
                    "heldout" if source_ordinal == owner_ordinal else "calibration"
                ),
            )
            episode_packets.append((episode_fold, extraction))
        owner_corpora.append(
            OwnerPacketCorpus(
                owner_fold=owner_fold,
                quantizer=binding,
                episode_packets=tuple(episode_packets),
            )
        )
    unsigned = {
        "schema": ADAPTER_SCHEMA,
        "config_sha256": config.sha256,
        "source_capsule_manifest_sha256": corpus.capsule_manifest_sha256,
        "source_artifact_index_sha256": corpus.artifact_index_sha256,
        "owner_corpora": [
            {
                "owner_fold": row.owner_fold,
                "reader_state_sha256": row.quantizer.reader_state_sha256,
                "quantizer_sha256": row.quantizer.quantizer.sha256,
                "episode_packet_sha256": [
                    {
                        "episode_fold": episode,
                        "packet_sha256": extraction.sha256,
                    }
                    for episode, extraction in row.episode_packets
                ],
            }
            for row in owner_corpora
        ],
        "labels_accepted_by_adapter": False,
        "episode_order": list(CANONICAL_FOLD_IDS),
    }
    return RealProtocolInputs(
        config=config,
        owner_corpora=tuple(owner_corpora),
        source_capsule_manifest_sha256=corpus.capsule_manifest_sha256,
        source_artifact_index_sha256=corpus.artifact_index_sha256,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_INPUTS_FACTORY,
    )


def _verify_manager_authority_matches_inputs(
    inputs: RealProtocolInputs,
    authority: ManagerAuthorityCommitment,
) -> None:
    if (
        not isinstance(inputs, RealProtocolInputs)
        or getattr(inputs, "_factory_marker", None) is not _INPUTS_FACTORY
    ):
        raise O1C29RealProtocolError(
            "labels require factory-created verified adapter inputs"
        )
    if (
        not isinstance(authority, ManagerAuthorityCommitment)
        or getattr(authority, "_factory_marker", None) is not _MANAGER_AUTHORITY_FACTORY
        or authority.receipt_sha256 != _document_sha256(authority.receipt_document())
        or inputs.receipt_sha256 != _document_sha256(inputs.receipt_document())
        or authority.adapter_receipt_sha256 != inputs.receipt_sha256
        or authority.source_capsule_manifest_sha256
        != inputs.source_capsule_manifest_sha256
        or authority.source_artifact_index_sha256 != inputs.source_artifact_index_sha256
        or authority.labels_relative != "labels.bitpack"
        or authority.labels_bitpack_bytes != LABEL_BITPACK_BYTES
        or authority.labels_phase != O1C22_LABEL_PHASE
        or authority.trusted_manager_verification_count != 1
    ):
        raise O1C29RealProtocolError(
            "manager authority does not match verified adapter inputs"
        )


def _verify_freeze_matches_inputs(
    inputs: RealProtocolInputs,
    freeze: GlobalStateFreeze,
) -> None:
    if not isinstance(inputs, RealProtocolInputs):
        raise TypeError("inputs must be RealProtocolInputs")
    if not isinstance(freeze, GlobalStateFreeze):
        raise O1C29RealProtocolError(
            "labels cannot open before a valid global state freeze"
        )
    if (
        freeze.config_sha256 != inputs.config.sha256
        or freeze.fold_ids != CANONICAL_FOLD_IDS
        or freeze.label_accesses_before_freeze != 0
        or len(freeze.states) != 16
    ):
        raise O1C29RealProtocolError("global state freeze does not match adapter")
    for corpus in inputs.owner_corpora:
        for episode, extraction in corpus.episode_packets:
            state = freeze.state_for(corpus.owner_fold, episode)
            if (
                state.packet_extraction_sha256 != extraction.sha256
                or state.reader_state_sha256 != corpus.quantizer.reader_state_sha256
                or state.quantizer_sha256 != corpus.quantizer.quantizer.sha256
            ):
                raise O1C29RealProtocolError(
                    "global state freeze packet lineage differs"
                )


def _decode_index_bound_labels(
    inputs: RealProtocolInputs,
    authority: ManagerAuthorityCommitment,
    artifact_index_payload: bytes,
    labels_payload: bytes,
) -> tuple[str, tuple[np.ndarray, ...]]:
    if type(artifact_index_payload) is not bytes:
        raise O1C29RealProtocolError("artifact index payload must be immutable bytes")
    if (
        len(artifact_index_payload) != authority.source_artifact_index_bytes
        or _sha256_bytes(artifact_index_payload) != inputs.source_artifact_index_sha256
        or inputs.source_artifact_index_sha256 != authority.source_artifact_index_sha256
    ):
        raise O1C29RealProtocolError("artifact index payload SHA-256 differs")
    try:
        index = json.loads(artifact_index_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C29RealProtocolError("artifact index payload is invalid JSON") from exc
    if not isinstance(index, Mapping):
        raise O1C29RealProtocolError("artifact index payload must be an object")
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, Mapping) or any(
        not isinstance(key, str) for key in artifacts
    ):
        raise O1C29RealProtocolError("artifact index inventory differs")
    count = index.get("indexed_artifact_count")
    if (
        index.get("schema") != O1C22_ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != "O1C-0022"
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != O1C22_ARTIFACT_COUNT
        or len(artifacts) != O1C22_ARTIFACT_COUNT
    ):
        raise O1C29RealProtocolError("artifact index identity/count differs")
    entry = artifacts.get(authority.labels_relative)
    if not isinstance(entry, Mapping) or set(entry) != {
        "sha256",
        "bytes",
        "phase",
    }:
        raise O1C29RealProtocolError("labels.bitpack artifact entry differs")
    expected_sha = _sha256(entry.get("sha256"), "labels.bitpack entry SHA-256")
    entry_bytes = entry.get("bytes")
    if (
        isinstance(entry_bytes, bool)
        or not isinstance(entry_bytes, int)
        or entry_bytes != authority.labels_bitpack_bytes
        or entry.get("phase") != authority.labels_phase
        or expected_sha != authority.labels_bitpack_sha256
    ):
        raise O1C29RealProtocolError("labels.bitpack artifact metadata differs")
    if type(labels_payload) is not bytes or len(labels_payload) != LABEL_BITPACK_BYTES:
        raise O1C29RealProtocolError(
            "labels.bitpack must be exactly 128 immutable bytes"
        )
    if _sha256_bytes(labels_payload) != expected_sha:
        raise O1C29RealProtocolError("labels.bitpack artifact SHA-256 differs")
    packed = np.frombuffer(labels_payload, dtype=np.uint8).reshape(4, 32)
    rows = tuple(
        _readonly_bits(np.unpackbits(packed[index], bitorder="little"))
        for index in range(4)
    )
    return expected_sha, rows


def open_authoritative_calibration_broker_after_state_freeze(
    inputs: RealProtocolInputs,
    freeze: GlobalStateFreeze,
    artifact_index_payload: bytes,
    labels_payload: bytes,
    *,
    manager_authority: ManagerAuthorityCommitment,
) -> AllowlistedFoldLabelBroker:
    """Return only an activated broker whose grants always exclude the owner."""

    _verify_manager_authority_matches_inputs(inputs, manager_authority)
    _verify_freeze_matches_inputs(inputs, freeze)
    _labels_sha, rows = _decode_index_bound_labels(
        inputs, manager_authority, artifact_index_payload, labels_payload
    )
    broker = AllowlistedFoldLabelBroker(
        inputs.config,
        {fold: rows[index] for index, fold in enumerate(CANONICAL_FOLD_IDS)},
    )
    broker.activate(freeze)
    return broker


def _verify_complete_prediction_result(
    inputs: RealProtocolInputs,
    result: StackedHotCalibrationResult,
) -> None:
    if not isinstance(result, StackedHotCalibrationResult):
        raise O1C29RealProtocolError(
            "post-prediction labels require a complete stacked result"
        )
    _verify_freeze_matches_inputs(inputs, result.global_freeze)
    if (
        result.config_sha256 != inputs.config.sha256
        or type(result.fits) is not tuple
        or type(result.predictions) is not tuple
        or tuple(row.outer_fold for row in result.fits) != CANONICAL_FOLD_IDS
        or tuple(row.outer_fold for row in result.predictions) != CANONICAL_FOLD_IDS
        or len(result.fits) != 4
        or len(result.predictions) != 4
        or result.receipt_document().get("heldout_labels_opened_for_scoring") != 0
        or result.receipt_sha256 != _document_sha256(result.receipt_document())
    ):
        raise O1C29RealProtocolError("stacked prediction result is incomplete")
    for fold, fit, prediction in zip(
        CANONICAL_FOLD_IDS, result.fits, result.predictions, strict=True
    ):
        expected_calibration = tuple(
            candidate for candidate in CANONICAL_FOLD_IDS if candidate != fold
        )
        heldout = result.global_freeze.state_for(fold, fold)
        if (
            fit.outer_fold != fold
            or fit.config_sha256 != result.config_sha256
            or fit.global_state_freeze_sha256 != result.global_freeze.receipt_sha256
            or fit.calibration_folds != expected_calibration
            or fit.inherited_label_ancestry != expected_calibration
            or prediction.outer_fold != fold
            or prediction.config_sha256 != result.config_sha256
            or prediction.global_state_freeze_sha256
            != result.global_freeze.receipt_sha256
            or prediction.fit_receipt_sha256 != fit.receipt_sha256
            or prediction.heldout_state_sha256 != heldout.state_sha256
            or prediction.heldout_state_receipt_sha256 != heldout.receipt_sha256
            or prediction.inherited_label_ancestry != expected_calibration
            or not prediction.state_unchanged
            or _sha256_bytes(prediction.primary_logits_bytes)
            != prediction.primary_logits_sha256
            or _sha256_bytes(prediction.secondary_logits_bytes)
            != prediction.secondary_logits_sha256
            or fit.receipt_sha256 != _document_sha256(fit.receipt_document())
            or prediction.receipt_sha256
            != _document_sha256(prediction.receipt_document())
        ):
            raise O1C29RealProtocolError("stacked prediction result lineage differs")


class PostPredictionLabelCapability:
    """Reveal capability created only after all four heldout predictions freeze."""

    config_sha256: str
    adapter_receipt_sha256: str
    global_state_freeze_sha256: str
    prediction_result_receipt_sha256: str
    source_artifact_index_sha256: str
    manager_authority_receipt_sha256: str
    labels_bitpack_sha256: str
    receipt_sha256: str
    __labels_bitpack: bytes

    __slots__ = (
        "config_sha256",
        "adapter_receipt_sha256",
        "global_state_freeze_sha256",
        "prediction_result_receipt_sha256",
        "source_artifact_index_sha256",
        "manager_authority_receipt_sha256",
        "labels_bitpack_sha256",
        "receipt_sha256",
        "__labels_bitpack",
    )

    def __init__(
        self,
        *,
        config_sha256: str,
        adapter_receipt_sha256: str,
        global_state_freeze_sha256: str,
        prediction_result_receipt_sha256: str,
        source_artifact_index_sha256: str,
        manager_authority_receipt_sha256: str,
        labels_bitpack: bytes,
        labels_bitpack_sha256: str,
        receipt_sha256: str,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _LABEL_FACTORY:
            raise O1C29RealProtocolError(
                "label capability must be opened by its post-prediction API"
            )
        for field_name, value in (
            ("config_sha256", config_sha256),
            ("adapter_receipt_sha256", adapter_receipt_sha256),
            ("global_state_freeze_sha256", global_state_freeze_sha256),
            ("prediction_result_receipt_sha256", prediction_result_receipt_sha256),
            ("source_artifact_index_sha256", source_artifact_index_sha256),
            ("manager_authority_receipt_sha256", manager_authority_receipt_sha256),
            ("labels_bitpack_sha256", labels_bitpack_sha256),
            ("receipt_sha256", receipt_sha256),
        ):
            _sha256(value, field_name)
            object.__setattr__(self, field_name, value)
        if (
            type(labels_bitpack) is not bytes
            or len(labels_bitpack) != LABEL_BITPACK_BYTES
            or _sha256_bytes(labels_bitpack) != labels_bitpack_sha256
        ):
            raise O1C29RealProtocolError("labels.bitpack payload differs")
        object.__setattr__(
            self,
            "_PostPredictionLabelCapability__labels_bitpack",
            labels_bitpack,
        )
        if receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("label capability receipt differs")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("post-prediction label capability is immutable")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": LABEL_CAPABILITY_SCHEMA,
            "config_sha256": self.config_sha256,
            "adapter_receipt_sha256": self.adapter_receipt_sha256,
            "global_state_freeze_sha256": self.global_state_freeze_sha256,
            "prediction_result_receipt_sha256": (self.prediction_result_receipt_sha256),
            "source_artifact_index_sha256": self.source_artifact_index_sha256,
            "manager_authority_receipt_sha256": (self.manager_authority_receipt_sha256),
            "labels_artifact_path": "labels.bitpack",
            "labels_bitpack_sha256": self.labels_bitpack_sha256,
            "labels_bitpack_bytes": LABEL_BITPACK_BYTES,
            "labels_shape": [4, KEY_BITS],
            "bitorder": "little",
            "opened_after_complete_prediction_result": True,
        }

    def label_for(self, fold_id: str) -> np.ndarray:
        try:
            ordinal = CANONICAL_FOLD_IDS.index(fold_id)
        except ValueError as exc:
            raise O1C29RealProtocolError("label fold is not canonical") from exc
        packed = np.frombuffer(self.__labels_bitpack, dtype=np.uint8).reshape(4, 32)
        return _readonly_bits(np.unpackbits(packed[ordinal], bitorder="little"))


def open_authoritative_labels_after_prediction_freeze(
    inputs: RealProtocolInputs,
    result: StackedHotCalibrationResult,
    artifact_index_payload: bytes,
    labels_payload: bytes,
    *,
    manager_authority: ManagerAuthorityCommitment,
) -> PostPredictionLabelCapability:
    """Revalidate and expose heldout labels after every prediction is frozen."""

    _verify_manager_authority_matches_inputs(inputs, manager_authority)
    _verify_complete_prediction_result(inputs, result)
    labels_sha, _rows = _decode_index_bound_labels(
        inputs, manager_authority, artifact_index_payload, labels_payload
    )
    unsigned = {
        "schema": LABEL_CAPABILITY_SCHEMA,
        "config_sha256": inputs.config.sha256,
        "adapter_receipt_sha256": inputs.receipt_sha256,
        "global_state_freeze_sha256": result.global_freeze.receipt_sha256,
        "prediction_result_receipt_sha256": result.receipt_sha256,
        "source_artifact_index_sha256": inputs.source_artifact_index_sha256,
        "manager_authority_receipt_sha256": manager_authority.receipt_sha256,
        "labels_artifact_path": "labels.bitpack",
        "labels_bitpack_sha256": labels_sha,
        "labels_bitpack_bytes": LABEL_BITPACK_BYTES,
        "labels_shape": [4, KEY_BITS],
        "bitorder": "little",
        "opened_after_complete_prediction_result": True,
    }
    return PostPredictionLabelCapability(
        config_sha256=inputs.config.sha256,
        adapter_receipt_sha256=inputs.receipt_sha256,
        global_state_freeze_sha256=result.global_freeze.receipt_sha256,
        prediction_result_receipt_sha256=result.receipt_sha256,
        source_artifact_index_sha256=inputs.source_artifact_index_sha256,
        manager_authority_receipt_sha256=manager_authority.receipt_sha256,
        labels_bitpack=labels_payload,
        labels_bitpack_sha256=labels_sha,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_LABEL_FACTORY,
    )


def _fixed_operator(arm: object) -> str:
    for fixed_arm, fixed_operator in _ARM_ORDER:
        if arm == fixed_arm:
            return fixed_operator
    raise O1C29RealProtocolError("score arm is not precommitted")


def _finite_float(value: object, field_name: str) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise O1C29RealProtocolError(f"{field_name} must be a finite float")
    return value


def _bounded_integer(
    value: object,
    field_name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C29RealProtocolError(f"{field_name} must be in [{minimum},{maximum}]")
    return value


@dataclass(frozen=True, slots=True)
class FrozenFoldArmScore:
    outer_fold: str
    arm: str
    operator_id: str
    prediction_receipt_sha256: str
    logits_sha256: str
    fold_labels_sha256: str
    nll_bits: float
    compression_bits: float
    correct_bits: int
    bit_accuracy: float
    true_byte_ranks: tuple[int, ...]
    true_block16_ranks: tuple[int, ...]
    byte_top1_count: int
    byte_top4_count: int
    byte_top16_count: int
    block16_top1_count: int
    block16_top4_count: int
    block16_top16_count: int
    top_k_limit: int | None
    true_key_rank: int | None
    frontier_sha256: str | None
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FOLD_SCORE_FACTORY:
            raise O1C29RealProtocolError(
                "fold score must be created by the frozen scorer"
            )
        if self.outer_fold not in CANONICAL_FOLD_IDS:
            raise O1C29RealProtocolError("fold score identity differs")
        if self.operator_id != _fixed_operator(self.arm):
            raise O1C29RealProtocolError("fold score operator differs")
        for field_name in (
            "prediction_receipt_sha256",
            "logits_sha256",
            "fold_labels_sha256",
            "receipt_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        nll = _finite_float(self.nll_bits, "nll_bits")
        compression = _finite_float(self.compression_bits, "compression_bits")
        accuracy = _finite_float(self.bit_accuracy, "bit_accuracy")
        correct = _bounded_integer(
            self.correct_bits,
            "correct_bits",
            minimum=0,
            maximum=KEY_BITS,
        )
        if (
            nll < 0.0
            or compression != float(KEY_BITS - nll)
            or accuracy != float(correct / KEY_BITS)
        ):
            raise O1C29RealProtocolError("fold score metric semantics differ")
        if (
            type(self.true_byte_ranks) is not tuple
            or len(self.true_byte_ranks) != 32
            or any(
                isinstance(rank, bool)
                or not isinstance(rank, int)
                or not 1 <= rank <= 256
                for rank in self.true_byte_ranks
            )
            or type(self.true_block16_ranks) is not tuple
            or len(self.true_block16_ranks) != 16
            or any(
                isinstance(rank, bool)
                or not isinstance(rank, int)
                or not 1 <= rank <= 65_536
                for rank in self.true_block16_ranks
            )
        ):
            raise O1C29RealProtocolError("local true-rank inventory differs")
        expected_counts = (
            sum(rank <= 1 for rank in self.true_byte_ranks),
            sum(rank <= 4 for rank in self.true_byte_ranks),
            sum(rank <= 16 for rank in self.true_byte_ranks),
            sum(rank <= 1 for rank in self.true_block16_ranks),
            sum(rank <= 4 for rank in self.true_block16_ranks),
            sum(rank <= 16 for rank in self.true_block16_ranks),
        )
        supplied_counts = (
            self.byte_top1_count,
            self.byte_top4_count,
            self.byte_top16_count,
            self.block16_top1_count,
            self.block16_top4_count,
            self.block16_top16_count,
        )
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in supplied_counts
            )
            or supplied_counts != expected_counts
        ):
            raise O1C29RealProtocolError("local true-rank aggregate differs")
        limit = _top_k_limit(self.top_k_limit)
        if limit is None:
            if self.true_key_rank is not None or self.frontier_sha256 is not None:
                raise O1C29RealProtocolError("disabled global frontier has results")
        else:
            if self.frontier_sha256 is None:
                raise O1C29RealProtocolError("global frontier commitment is absent")
            _sha256(self.frontier_sha256, "frontier_sha256")
            if self.true_key_rank is not None:
                _bounded_integer(
                    self.true_key_rank,
                    "true_key_rank",
                    minimum=1,
                    maximum=limit,
                )
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("fold score receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": FOLD_SCORE_SCHEMA,
            "outer_fold": self.outer_fold,
            "arm": self.arm,
            "operator_id": self.operator_id,
            "prediction_receipt_sha256": self.prediction_receipt_sha256,
            "logits_sha256": self.logits_sha256,
            "fold_labels_sha256": self.fold_labels_sha256,
            "nll_bits_float64_hex": self.nll_bits.hex(),
            "compression_bits_float64_hex": self.compression_bits.hex(),
            "correct_bits": self.correct_bits,
            "bit_accuracy_float64_hex": self.bit_accuracy.hex(),
            "true_byte_ranks": list(self.true_byte_ranks),
            "true_block16_ranks": list(self.true_block16_ranks),
            "byte_top1_count": self.byte_top1_count,
            "byte_top4_count": self.byte_top4_count,
            "byte_top16_count": self.byte_top16_count,
            "block16_top1_count": self.block16_top1_count,
            "block16_top4_count": self.block16_top4_count,
            "block16_top16_count": self.block16_top16_count,
            "local_rank_tie_policy": LOCAL_RANK_TIE_POLICY,
            "local_value_encoding": "little-endian-contiguous-key-coordinates",
            "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
            "top_k_limit": self.top_k_limit,
            "true_key_rank": self.true_key_rank,
            "frontier_sha256": self.frontier_sha256,
        }


@dataclass(frozen=True, slots=True)
class FrozenArmScore:
    arm: str
    operator_id: str
    folds: tuple[FrozenFoldArmScore, ...]
    total_nll_bits: float
    mean_nll_bits: float
    total_compression_bits: float
    mean_compression_bits: float
    positive_fold_count: int
    correct_bits: int
    bit_accuracy: float
    byte_top1_count: int
    byte_top4_count: int
    byte_top16_count: int
    block16_top1_count: int
    block16_top4_count: int
    block16_top16_count: int
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _ARM_SCORE_FACTORY:
            raise O1C29RealProtocolError(
                "arm score must be created by the frozen scorer"
            )
        if self.operator_id != _fixed_operator(self.arm):
            raise O1C29RealProtocolError("arm score operator differs")
        _sha256(self.receipt_sha256, "receipt_sha256")
        if (
            type(self.folds) is not tuple
            or len(self.folds) != 4
            or any(not isinstance(row, FrozenFoldArmScore) for row in self.folds)
            or tuple(row.outer_fold for row in self.folds) != CANONICAL_FOLD_IDS
            or any(
                row.arm != self.arm or row.operator_id != self.operator_id
                for row in self.folds
            )
            or len({row.top_k_limit for row in self.folds}) != 1
        ):
            raise O1C29RealProtocolError("arm fold-score order differs")
        total_nll = _finite_float(self.total_nll_bits, "total_nll_bits")
        mean_nll = _finite_float(self.mean_nll_bits, "mean_nll_bits")
        total_compression = _finite_float(
            self.total_compression_bits, "total_compression_bits"
        )
        mean_compression = _finite_float(
            self.mean_compression_bits, "mean_compression_bits"
        )
        accuracy = _finite_float(self.bit_accuracy, "bit_accuracy")
        positive = _bounded_integer(
            self.positive_fold_count,
            "positive_fold_count",
            minimum=0,
            maximum=4,
        )
        correct = _bounded_integer(
            self.correct_bits,
            "correct_bits",
            minimum=0,
            maximum=4 * KEY_BITS,
        )
        expected_nll = float(sum(row.nll_bits for row in self.folds))
        expected_compression = float(sum(row.compression_bits for row in self.folds))
        if (
            total_nll != expected_nll
            or mean_nll != expected_nll / 4.0
            or total_compression != expected_compression
            or mean_compression != expected_compression / 4.0
            or positive != sum(row.compression_bits > 0.0 for row in self.folds)
            or correct != sum(row.correct_bits for row in self.folds)
            or accuracy != correct / (4 * KEY_BITS)
        ):
            raise O1C29RealProtocolError("arm score metric semantics differ")
        count_fields = (
            "byte_top1_count",
            "byte_top4_count",
            "byte_top16_count",
            "block16_top1_count",
            "block16_top4_count",
            "block16_top16_count",
        )
        if any(
            isinstance(getattr(self, name), bool)
            or not isinstance(getattr(self, name), int)
            or getattr(self, name) != sum(getattr(row, name) for row in self.folds)
            for name in count_fields
        ):
            raise O1C29RealProtocolError("arm local-rank aggregate differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("arm score receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": ARM_SCORE_SCHEMA,
            "arm": self.arm,
            "operator_id": self.operator_id,
            "fold_score_receipt_sha256": [row.receipt_sha256 for row in self.folds],
            "fold_ids": [row.outer_fold for row in self.folds],
            "true_byte_ranks_by_fold": [
                list(row.true_byte_ranks) for row in self.folds
            ],
            "true_block16_ranks_by_fold": [
                list(row.true_block16_ranks) for row in self.folds
            ],
            "total_nll_bits_float64_hex": self.total_nll_bits.hex(),
            "mean_nll_bits_float64_hex": self.mean_nll_bits.hex(),
            "total_compression_bits_float64_hex": (self.total_compression_bits.hex()),
            "mean_compression_bits_float64_hex": self.mean_compression_bits.hex(),
            "positive_fold_count": self.positive_fold_count,
            "correct_bits": self.correct_bits,
            "bit_accuracy_float64_hex": self.bit_accuracy.hex(),
            "byte_top1_count": self.byte_top1_count,
            "byte_top4_count": self.byte_top4_count,
            "byte_top16_count": self.byte_top16_count,
            "block16_top1_count": self.block16_top1_count,
            "block16_top4_count": self.block16_top4_count,
            "block16_top16_count": self.block16_top16_count,
            "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
        }


@dataclass(frozen=True, slots=True)
class FrozenTwoArmScore:
    prediction_result_receipt_sha256: str
    label_capability_receipt_sha256: str
    arms: tuple[FrozenArmScore, ...]
    top_k_limit: int | None
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _TWO_ARM_SCORE_FACTORY:
            raise O1C29RealProtocolError(
                "two-arm score must be created by the frozen scorer"
            )
        for field_name in (
            "prediction_result_receipt_sha256",
            "label_capability_receipt_sha256",
            "receipt_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        limit = _top_k_limit(self.top_k_limit)
        if (
            type(self.arms) is not tuple
            or len(self.arms) != len(_ARM_ORDER)
            or any(not isinstance(row, FrozenArmScore) for row in self.arms)
            or tuple((row.arm, row.operator_id) for row in self.arms) != _ARM_ORDER
            or any(fold.top_k_limit != limit for arm in self.arms for fold in arm.folds)
            or any(
                primary.prediction_receipt_sha256 != secondary.prediction_receipt_sha256
                or primary.fold_labels_sha256 != secondary.fold_labels_sha256
                for primary, secondary in zip(
                    self.arms[0].folds,
                    self.arms[1].folds,
                    strict=True,
                )
            )
        ):
            raise O1C29RealProtocolError("two-arm score order differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29RealProtocolError("two-arm score receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": SCORE_SCHEMA,
            "prediction_result_receipt_sha256": (self.prediction_result_receipt_sha256),
            "label_capability_receipt_sha256": (self.label_capability_receipt_sha256),
            "arm_order": [row.arm for row in self.arms],
            "arm_score_receipt_sha256": [row.receipt_sha256 for row in self.arms],
            "arm_scores": [row.receipt_document() for row in self.arms],
            "top_k_limit": self.top_k_limit,
            "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
            "refits_during_scoring": 0,
            "label_dependent_arm_selection": False,
        }


def _frontier(
    logits: np.ndarray,
    labels: np.ndarray,
    limit: int,
) -> tuple[int | None, str]:
    truth = bits_to_key(labels)
    digest = hashlib.sha256(b"O1C-0029/frozen-factorized-frontier/v1\x00")
    true_rank: int | None = None
    for candidate in iter_factorized_logit_topk(
        logits.astype(np.float64, copy=False), limit=limit
    ):
        payload = _canonical_json_bytes(candidate.describe())
        digest.update(struct.pack(">Q", len(payload)))
        digest.update(payload)
        if true_rank is None and candidate.key == truth:
            true_rank = candidate.rank
    return true_rank, digest.hexdigest()


def _exact_local_true_rank(logits: np.ndarray, labels: np.ndarray) -> int:
    """Rank one true byte/u16 under exact factorized binary-logit penalties."""

    local_logits = np.asarray(logits)
    local_labels = np.asarray(labels)
    width = int(local_logits.size)
    if (
        width not in (8, 16)
        or local_logits.shape != (width,)
        or local_labels.shape != (width,)
        or local_labels.dtype != np.uint8
        or not bool(np.isfinite(local_logits).all())
        or bool(((local_labels != 0) & (local_labels != 1)).any())
    ):
        raise O1C29RealProtocolError("local rank input differs")
    ratios = tuple(abs(float(value)).as_integer_ratio() for value in local_logits)
    common_denominator = max(denominator for _numerator, denominator in ratios)
    weights = tuple(
        numerator * (common_denominator // denominator)
        for numerator, denominator in ratios
    )
    subset_penalties = [0]
    for weight in weights:
        subset_penalties.extend(penalty + weight for penalty in tuple(subset_penalties))
    mode_value = sum(
        (1 << coordinate)
        for coordinate, value in enumerate(local_logits)
        if float(value) > 0.0
    )
    true_value = sum(
        int(value) << coordinate for coordinate, value in enumerate(local_labels)
    )
    true_penalty = subset_penalties[true_value ^ mode_value]
    return 1 + sum(
        subset_penalties[candidate ^ mode_value] < true_penalty
        or (
            subset_penalties[candidate ^ mode_value] == true_penalty
            and candidate < true_value
        )
        for candidate in range(1 << width)
    )


def _local_true_ranks(
    logits: np.ndarray, labels: np.ndarray
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    byte_ranks = tuple(
        _exact_local_true_rank(logits[offset : offset + 8], labels[offset : offset + 8])
        for offset in range(0, KEY_BITS, 8)
    )
    block16_ranks = tuple(
        _exact_local_true_rank(
            logits[offset : offset + 16], labels[offset : offset + 16]
        )
        for offset in range(0, KEY_BITS, 16)
    )
    return byte_ranks, block16_ranks


def _fold_score(
    prediction: FrozenOuterPrediction,
    labels: np.ndarray,
    *,
    arm: str,
    operator_id: str,
    top_k_limit: int | None,
) -> FrozenFoldArmScore:
    if arm == "primary":
        logits = prediction.primary_logits()
        logits_sha = prediction.primary_logits_sha256
    elif arm == "secondary":
        logits = prediction.secondary_logits()
        logits_sha = prediction.secondary_logits_sha256
    else:  # pragma: no cover - fixed private arm inventory.
        raise AssertionError("unknown fixed arm")
    if logits.shape != (KEY_BITS,) or not bool(np.isfinite(logits).all()):
        raise O1C29RealProtocolError("frozen logits are non-finite or wrong-width")
    signed = 2.0 * labels.astype(np.float64) - 1.0
    losses = np.logaddexp(0.0, -signed * logits.astype(np.float64))
    nll = float(losses.sum(dtype=np.float64) / math.log(2.0))
    compression = float(KEY_BITS - nll)
    predicted = (logits > 0.0).astype(np.uint8)
    correct = int(np.count_nonzero(predicted == labels))
    accuracy = float(correct / KEY_BITS)
    byte_ranks, block16_ranks = _local_true_ranks(logits, labels)
    byte_top1 = sum(rank <= 1 for rank in byte_ranks)
    byte_top4 = sum(rank <= 4 for rank in byte_ranks)
    byte_top16 = sum(rank <= 16 for rank in byte_ranks)
    block16_top1 = sum(rank <= 1 for rank in block16_ranks)
    block16_top4 = sum(rank <= 4 for rank in block16_ranks)
    block16_top16 = sum(rank <= 16 for rank in block16_ranks)
    true_rank: int | None = None
    frontier_sha: str | None = None
    if top_k_limit is not None:
        true_rank, frontier_sha = _frontier(logits, labels, top_k_limit)
    label_sha = _sha256_bytes(labels.tobytes(order="C"))
    unsigned = {
        "schema": FOLD_SCORE_SCHEMA,
        "outer_fold": prediction.outer_fold,
        "arm": arm,
        "operator_id": operator_id,
        "prediction_receipt_sha256": prediction.receipt_sha256,
        "logits_sha256": logits_sha,
        "fold_labels_sha256": label_sha,
        "nll_bits_float64_hex": nll.hex(),
        "compression_bits_float64_hex": compression.hex(),
        "correct_bits": correct,
        "bit_accuracy_float64_hex": accuracy.hex(),
        "true_byte_ranks": list(byte_ranks),
        "true_block16_ranks": list(block16_ranks),
        "byte_top1_count": byte_top1,
        "byte_top4_count": byte_top4,
        "byte_top16_count": byte_top16,
        "block16_top1_count": block16_top1,
        "block16_top4_count": block16_top4,
        "block16_top16_count": block16_top16,
        "local_rank_tie_policy": LOCAL_RANK_TIE_POLICY,
        "local_value_encoding": "little-endian-contiguous-key-coordinates",
        "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
        "top_k_limit": top_k_limit,
        "true_key_rank": true_rank,
        "frontier_sha256": frontier_sha,
    }
    return FrozenFoldArmScore(
        outer_fold=prediction.outer_fold,
        arm=arm,
        operator_id=operator_id,
        prediction_receipt_sha256=prediction.receipt_sha256,
        logits_sha256=logits_sha,
        fold_labels_sha256=label_sha,
        nll_bits=nll,
        compression_bits=compression,
        correct_bits=correct,
        bit_accuracy=accuracy,
        true_byte_ranks=byte_ranks,
        true_block16_ranks=block16_ranks,
        byte_top1_count=byte_top1,
        byte_top4_count=byte_top4,
        byte_top16_count=byte_top16,
        block16_top1_count=block16_top1,
        block16_top4_count=block16_top4,
        block16_top16_count=block16_top16,
        top_k_limit=top_k_limit,
        true_key_rank=true_rank,
        frontier_sha256=frontier_sha,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_FOLD_SCORE_FACTORY,
    )


def score_frozen_two_arm_predictions(
    result: StackedHotCalibrationResult,
    labels: PostPredictionLabelCapability,
    *,
    top_k_limit: int | None = None,
) -> FrozenTwoArmScore:
    """Score both precommitted arms without refit or outcome-based selection."""

    if not isinstance(result, StackedHotCalibrationResult):
        raise TypeError("result must be StackedHotCalibrationResult")
    if not isinstance(labels, PostPredictionLabelCapability):
        raise TypeError("labels must be PostPredictionLabelCapability")
    limit = _top_k_limit(top_k_limit)
    if (
        result.config_sha256 != labels.config_sha256
        or result.global_freeze.receipt_sha256 != labels.global_state_freeze_sha256
        or result.receipt_sha256 != labels.prediction_result_receipt_sha256
        or result.receipt_sha256 != _document_sha256(result.receipt_document())
        or result.global_freeze.fold_ids != CANONICAL_FOLD_IDS
        or tuple(row.outer_fold for row in result.predictions) != CANONICAL_FOLD_IDS
        or result.receipt_document().get("heldout_labels_opened_for_scoring") != 0
    ):
        raise O1C29RealProtocolError("frozen prediction/label lineage differs")
    arm_scores: list[FrozenArmScore] = []
    for arm, operator_id in _ARM_ORDER:
        fold_scores = tuple(
            _fold_score(
                prediction,
                labels.label_for(prediction.outer_fold),
                arm=arm,
                operator_id=operator_id,
                top_k_limit=limit,
            )
            for prediction in result.predictions
        )
        total_nll = float(sum(row.nll_bits for row in fold_scores))
        total_compression = float(sum(row.compression_bits for row in fold_scores))
        correct = sum(row.correct_bits for row in fold_scores)
        unsigned = {
            "schema": ARM_SCORE_SCHEMA,
            "arm": arm,
            "operator_id": operator_id,
            "fold_score_receipt_sha256": [row.receipt_sha256 for row in fold_scores],
            "fold_ids": [row.outer_fold for row in fold_scores],
            "true_byte_ranks_by_fold": [
                list(row.true_byte_ranks) for row in fold_scores
            ],
            "true_block16_ranks_by_fold": [
                list(row.true_block16_ranks) for row in fold_scores
            ],
            "total_nll_bits_float64_hex": total_nll.hex(),
            "mean_nll_bits_float64_hex": (total_nll / 4.0).hex(),
            "total_compression_bits_float64_hex": total_compression.hex(),
            "mean_compression_bits_float64_hex": (total_compression / 4.0).hex(),
            "positive_fold_count": sum(
                row.compression_bits > 0.0 for row in fold_scores
            ),
            "correct_bits": correct,
            "bit_accuracy_float64_hex": (correct / (4 * KEY_BITS)).hex(),
            "byte_top1_count": sum(row.byte_top1_count for row in fold_scores),
            "byte_top4_count": sum(row.byte_top4_count for row in fold_scores),
            "byte_top16_count": sum(row.byte_top16_count for row in fold_scores),
            "block16_top1_count": sum(row.block16_top1_count for row in fold_scores),
            "block16_top4_count": sum(row.block16_top4_count for row in fold_scores),
            "block16_top16_count": sum(row.block16_top16_count for row in fold_scores),
            "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
        }
        arm_scores.append(
            FrozenArmScore(
                arm=arm,
                operator_id=operator_id,
                folds=fold_scores,
                total_nll_bits=total_nll,
                mean_nll_bits=total_nll / 4.0,
                total_compression_bits=total_compression,
                mean_compression_bits=total_compression / 4.0,
                positive_fold_count=sum(
                    row.compression_bits > 0.0 for row in fold_scores
                ),
                correct_bits=correct,
                bit_accuracy=correct / (4 * KEY_BITS),
                byte_top1_count=sum(row.byte_top1_count for row in fold_scores),
                byte_top4_count=sum(row.byte_top4_count for row in fold_scores),
                byte_top16_count=sum(row.byte_top16_count for row in fold_scores),
                block16_top1_count=sum(row.block16_top1_count for row in fold_scores),
                block16_top4_count=sum(row.block16_top4_count for row in fold_scores),
                block16_top16_count=sum(row.block16_top16_count for row in fold_scores),
                receipt_sha256=_document_sha256(unsigned),
                _factory_token=_ARM_SCORE_FACTORY,
            )
        )
    unsigned_result = {
        "schema": SCORE_SCHEMA,
        "prediction_result_receipt_sha256": result.receipt_sha256,
        "label_capability_receipt_sha256": labels.receipt_sha256,
        "arm_order": [row.arm for row in arm_scores],
        "arm_score_receipt_sha256": [row.receipt_sha256 for row in arm_scores],
        "arm_scores": [row.receipt_document() for row in arm_scores],
        "top_k_limit": limit,
        "global_frontier_tie_policy": GLOBAL_FRONTIER_TIE_POLICY,
        "refits_during_scoring": 0,
        "label_dependent_arm_selection": False,
    }
    return FrozenTwoArmScore(
        prediction_result_receipt_sha256=result.receipt_sha256,
        label_capability_receipt_sha256=labels.receipt_sha256,
        arms=tuple(arm_scores),
        top_k_limit=limit,
        receipt_sha256=_document_sha256(unsigned_result),
        _factory_token=_TWO_ARM_SCORE_FACTORY,
    )


__all__ = [
    "ADAPTER_SCHEMA",
    "CANONICAL_ALPHA",
    "CANONICAL_CONFIDENCE_TEMPERATURE_GRID",
    "CANONICAL_FOLD_IDS",
    "FrozenArmScore",
    "FrozenFoldArmScore",
    "FrozenTwoArmScore",
    "GLOBAL_FRONTIER_TIE_POLICY",
    "LABEL_BITPACK_BYTES",
    "LOCAL_RANK_TIE_POLICY",
    "MANAGER_AUTHORITY_SCHEMA",
    "MAXIMUM_TOP_K_LIMIT",
    "ManagerAuthorityCommitment",
    "O1C29RealProtocolError",
    "PostPredictionLabelCapability",
    "RealProtocolInputs",
    "adapt_verified_o1c22_packet_corpus",
    "bind_manager_authority_commitment",
    "open_authoritative_calibration_broker_after_state_freeze",
    "open_authoritative_labels_after_prediction_freeze",
    "score_frozen_two_arm_predictions",
]
