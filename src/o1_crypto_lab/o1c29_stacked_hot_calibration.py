"""Outcome-independent outer-fold hot calibration over frozen O1C-0022 packets.

The protocol deliberately separates three capabilities:

* all four reader-owner x four episode V2 states freeze without a label surface;
* one outer-fold fit receives only that owner's three non-heldout states and an
  exactly matching label grant;
* heldout inference receives the frozen fit and heldout state, but no label.

This is an ``OUTER_FOLD_STACKED_HOT_CALIBRATION``.  The base reader has already
seen the three calibration episodes, so it is intentionally not described as an
inner cross-fit.  A later O1C-0023 selector may be hash-attested as context, but
it is never scientific selection authority for either precommitted hot arm.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import InitVar, dataclass, field
from typing import Mapping, Sequence

import numpy as np

from .o1c22_packet_codec import FrozenMedianAbsQuantizer, PacketDeltaExtraction
from .o1c22_polyphase_bridge import (
    ENCODING_NORMALIZED_FLOAT32,
    DenseHorizonMajorStream,
    FittedHorizonReadout,
    bind_o1o_hot_readout,
    build_dense_horizon_major_stream,
    consume_dense_horizon_major_stream,
    fit_nonnegative_horizon_readout,
    freeze_hot_readout_lineage,
    read_bound_hot_state,
)
from .polyphase_sufficient_state_v2 import (
    BASIS_SHA256,
    KEY_BITS,
    STATE_BYTES,
    PolyphaseReadoutSpec,
    PolyphaseSufficientState,
    read_polyphase_state,
)


PROTOCOL = "OUTER_FOLD_STACKED_HOT_CALIBRATION"
CONFIG_SCHEMA = "o1-256-o1c29-stacked-hot-calibration-config-v1"
QUANTIZER_FREEZE_SCHEMA = "o1-256-o1c29-owner-quantizer-freeze-v1"
STATE_FREEZE_SCHEMA = "o1-256-o1c29-owner-episode-state-freeze-v1"
GLOBAL_FREEZE_SCHEMA = "o1-256-o1c29-all-owner-states-freeze-v1"
LABEL_GRANT_SCHEMA = "o1-256-o1c29-fold-label-grant-v1"
FIT_FREEZE_SCHEMA = "o1-256-o1c29-outer-hot-fit-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-o1c29-heldout-prediction-freeze-v1"
RESULT_SCHEMA = "o1-256-o1c29-stacked-hot-calibration-result-v1"
PRIMARY_OPERATOR_ID = "horizon_nonnegative_simplex_v1"
SECONDARY_OPERATOR_ID = "magnitude_confidence_calibration_v1"
FOLD_COUNT = 4
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_QUANTIZER_FACTORY = object()
_STATE_FACTORY = object()
_GLOBAL_FACTORY = object()
_GRANT_FACTORY = object()
_FIT_FACTORY = object()
_PREDICTION_FACTORY = object()
_RESULT_FACTORY = object()


class O1C29StackedHotCalibrationError(ValueError):
    """A precommitment, owner lineage, oracle boundary, or receipt differs."""


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
        raise O1C29StackedHotCalibrationError(
            "receipt is not finite canonical JSON"
        ) from exc
    return rendered.encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _document_sha256(value: Mapping[str, object]) -> str:
    return _sha256_bytes(_canonical_json_bytes(dict(value)))


def _require_sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise O1C29StackedHotCalibrationError(f"{field_name} must be lowercase SHA-256")
    return value


def _require_fold(value: object, folds: Sequence[str], field_name: str) -> str:
    if not isinstance(value, str) or value not in folds:
        raise O1C29StackedHotCalibrationError(
            f"{field_name} must name one precommitted fold"
        )
    return value


def _float32(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C29StackedHotCalibrationError(f"{field_name} must be numeric")
    raw = float(value)
    if not math.isfinite(raw) or raw <= 0.0:
        raise O1C29StackedHotCalibrationError(
            f"{field_name} must be finite and positive"
        )
    with np.errstate(over="ignore", under="ignore", invalid="ignore"):
        rounded = np.float32(raw)
    if not np.isfinite(rounded) or rounded <= 0.0:
        raise O1C29StackedHotCalibrationError(
            f"{field_name} must be positive finite float32"
        )
    return float(rounded)


def _readonly_label_matrix(value: object, rows: int) -> np.ndarray:
    labels = np.asarray(value)
    if (
        labels.dtype != np.uint8
        or labels.shape != (rows, KEY_BITS)
        or bool(((labels != 0) & (labels != 1)).any())
    ):
        raise O1C29StackedHotCalibrationError(
            f"labels must be uint8[{rows},{KEY_BITS}] bits"
        )
    frozen = np.frombuffer(labels.tobytes(order="C"), dtype=np.uint8).reshape(
        rows, KEY_BITS
    )
    if frozen.flags.writeable:  # pragma: no cover - bytes-backed arrays are read-only.
        raise AssertionError("label grant is unexpectedly writable")
    return frozen


def _expected_calibration_folds(
    config: "StackedHotCalibrationConfig", owner_fold: str
) -> tuple[str, ...]:
    return tuple(fold for fold in config.fold_ids if fold != owner_fold)


@dataclass(frozen=True)
class StackedHotCalibrationConfig:
    """Outcome-independent four-fold fit and temperature precommitment."""

    fold_ids: tuple[str, ...]
    alpha: float
    confidence_temperature_grid: tuple[float, ...]

    def __post_init__(self) -> None:
        folds = tuple(self.fold_ids)
        if (
            len(folds) != FOLD_COUNT
            or len(set(folds)) != FOLD_COUNT
            or any(
                not isinstance(fold, str)
                or not fold
                or len(fold) > 64
                or not fold.isascii()
                for fold in folds
            )
        ):
            raise O1C29StackedHotCalibrationError(
                "fold_ids must contain four unique finite ASCII identifiers"
            )
        alpha = _float32(self.alpha, "alpha")
        try:
            grid = tuple(
                _float32(value, "confidence temperature")
                for value in self.confidence_temperature_grid
            )
        except TypeError as exc:
            raise O1C29StackedHotCalibrationError(
                "confidence temperature grid must be a sequence"
            ) from exc
        if not grid or tuple(sorted(set(grid))) != grid:
            raise O1C29StackedHotCalibrationError(
                "confidence temperature grid must be strictly increasing"
            )
        object.__setattr__(self, "fold_ids", folds)
        object.__setattr__(self, "alpha", alpha)
        object.__setattr__(self, "confidence_temperature_grid", grid)

    def describe(self) -> dict[str, object]:
        return {
            "schema": CONFIG_SCHEMA,
            "protocol": PROTOCOL,
            "fold_ids": list(self.fold_ids),
            "outer_folds": FOLD_COUNT,
            "states_frozen_before_label_access": FOLD_COUNT * FOLD_COUNT,
            "state_encoding": ENCODING_NORMALIZED_FLOAT32,
            "state_basis_sha256": BASIS_SHA256,
            "alpha_float32_hex": float(np.float32(self.alpha)).hex(),
            "confidence_temperature_grid_float32_hex": [
                float(np.float32(value)).hex()
                for value in self.confidence_temperature_grid
            ],
            "primary_operator_id": PRIMARY_OPERATOR_ID,
            "secondary_operator_id": SECONDARY_OPERATOR_ID,
            "operator_set_precommitted_before_outcome": True,
            "actual_o1c23_selector_used_for_scientific_selection": False,
            "base_reader_calibration_is_resubstitution": True,
            "inner_crossfit_claimed": False,
            "heldout_state_is_fit_input": False,
        }

    @property
    def sha256(self) -> str:
        return _document_sha256(self.describe())


@dataclass(frozen=True)
class FrozenOwnerQuantizer:
    """One quantizer bound to its exact outer-fold reader and label ancestry."""

    config_sha256: str
    owner_fold: str
    reader_state_sha256: str
    inherited_label_ancestry: tuple[str, ...]
    quantizer: FrozenMedianAbsQuantizer = field(repr=False, compare=False)
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _QUANTIZER_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "owner quantizer must be created by its freeze factory"
            )
        _require_sha256(self.config_sha256, "config_sha256")
        _require_sha256(self.reader_state_sha256, "reader_state_sha256")
        _require_sha256(self.receipt_sha256, "receipt_sha256")
        if not isinstance(self.quantizer, FrozenMedianAbsQuantizer):
            raise TypeError("quantizer must be FrozenMedianAbsQuantizer")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError(
                "owner quantizer freeze receipt differs"
            )

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": QUANTIZER_FREEZE_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "owner_fold": self.owner_fold,
            "reader_state_sha256": self.reader_state_sha256,
            "quantizer_sha256": self.quantizer.sha256,
            "inherited_label_ancestry": list(self.inherited_label_ancestry),
            "direct_label_accesses": 0,
        }


def freeze_owner_quantizer(
    config: StackedHotCalibrationConfig,
    *,
    owner_fold: str,
    reader_state_sha256: str,
    quantizer: FrozenMedianAbsQuantizer,
) -> FrozenOwnerQuantizer:
    """Bind one public quantizer to the exact fold-owner reader."""

    if not isinstance(config, StackedHotCalibrationConfig):
        raise TypeError("config must be StackedHotCalibrationConfig")
    owner = _require_fold(owner_fold, config.fold_ids, "owner_fold")
    reader = _require_sha256(reader_state_sha256, "reader_state_sha256")
    if not isinstance(quantizer, FrozenMedianAbsQuantizer):
        raise TypeError("quantizer must be FrozenMedianAbsQuantizer")
    ancestry = _expected_calibration_folds(config, owner)
    unsigned = {
        "schema": QUANTIZER_FREEZE_SCHEMA,
        "protocol": PROTOCOL,
        "config_sha256": config.sha256,
        "owner_fold": owner,
        "reader_state_sha256": reader,
        "quantizer_sha256": quantizer.sha256,
        "inherited_label_ancestry": list(ancestry),
        "direct_label_accesses": 0,
    }
    return FrozenOwnerQuantizer(
        config_sha256=config.sha256,
        owner_fold=owner,
        reader_state_sha256=reader,
        inherited_label_ancestry=ancestry,
        quantizer=quantizer,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_QUANTIZER_FACTORY,
    )


@dataclass(frozen=True)
class OwnerPacketCorpus:
    """Exactly four label-free packet ledgers emitted by one fold owner."""

    owner_fold: str
    quantizer: FrozenOwnerQuantizer
    episode_packets: tuple[tuple[str, PacketDeltaExtraction], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.owner_fold, str) or not self.owner_fold:
            raise O1C29StackedHotCalibrationError("owner_fold is required")
        if not isinstance(self.quantizer, FrozenOwnerQuantizer):
            raise TypeError("quantizer must be FrozenOwnerQuantizer")
        try:
            rows = tuple(self.episode_packets)
        except TypeError as exc:
            raise O1C29StackedHotCalibrationError(
                "episode_packets must be a sequence"
            ) from exc
        if any(
            not isinstance(row, tuple)
            or len(row) != 2
            or not isinstance(row[0], str)
            or not isinstance(row[1], PacketDeltaExtraction)
            for row in rows
        ):
            raise O1C29StackedHotCalibrationError(
                "episode_packets must contain (fold, extraction) pairs"
            )
        object.__setattr__(self, "episode_packets", rows)


@dataclass(frozen=True)
class FrozenOwnerEpisodeState:
    """One immutable packet -> normalized stream -> V2 state lineage."""

    config_sha256: str
    owner_fold: str
    episode_fold: str
    reader_state_sha256: str
    quantizer_sha256: str
    inherited_label_ancestry: tuple[str, ...]
    packet_extraction_sha256: str
    evidence_sha256: str
    state_sha256: str
    state_bytes: bytes = field(repr=False)
    stream: DenseHorizonMajorStream = field(repr=False, compare=False)
    quantizer: FrozenMedianAbsQuantizer = field(repr=False, compare=False)
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _STATE_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "owner episode state must be created by the global freeze"
            )
        for field_name in (
            "config_sha256",
            "reader_state_sha256",
            "quantizer_sha256",
            "packet_extraction_sha256",
            "evidence_sha256",
            "state_sha256",
            "receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if (
            not isinstance(self.state_bytes, bytes)
            or len(self.state_bytes) != STATE_BYTES
        ):
            raise O1C29StackedHotCalibrationError("frozen V2 state bytes differ")
        state = PolyphaseSufficientState.from_bytes(self.state_bytes)
        if state.sha256() != self.state_sha256:
            raise O1C29StackedHotCalibrationError("frozen V2 state hash differs")
        if (
            not isinstance(self.stream, DenseHorizonMajorStream)
            or not isinstance(self.quantizer, FrozenMedianAbsQuantizer)
            or self.stream.reader_state_sha256 != self.reader_state_sha256
            or self.stream.quantizer_sha256 != self.quantizer_sha256
            or self.stream.evidence_sha256 != self.evidence_sha256
            or self.quantizer.sha256 != self.quantizer_sha256
        ):
            raise O1C29StackedHotCalibrationError(
                "frozen stream/quantizer lineage differs"
            )
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("state freeze receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": STATE_FREEZE_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "owner_fold": self.owner_fold,
            "episode_fold": self.episode_fold,
            "reader_state_sha256": self.reader_state_sha256,
            "quantizer_sha256": self.quantizer_sha256,
            "packet_extraction_sha256": self.packet_extraction_sha256,
            "evidence_sha256": self.evidence_sha256,
            "state_basis_sha256": BASIS_SHA256,
            "state_sha256": self.state_sha256,
            "state_bytes": len(self.state_bytes),
            "inherited_label_ancestry": list(self.inherited_label_ancestry),
            "direct_label_accesses": 0,
        }

    def state(self) -> PolyphaseSufficientState:
        return PolyphaseSufficientState.from_bytes(self.state_bytes)


@dataclass(frozen=True)
class GlobalStateFreeze:
    """The mandatory all-16-states-before-any-label barrier."""

    config_sha256: str
    fold_ids: tuple[str, ...]
    states: tuple[FrozenOwnerEpisodeState, ...]
    label_accesses_before_freeze: int
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _GLOBAL_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "global state barrier must be created by its freeze factory"
            )
        _require_sha256(self.config_sha256, "config_sha256")
        _require_sha256(self.receipt_sha256, "receipt_sha256")
        expected = tuple(
            (owner, episode) for owner in self.fold_ids for episode in self.fold_ids
        )
        actual = tuple((row.owner_fold, row.episode_fold) for row in self.states)
        if actual != expected or len(self.states) != FOLD_COUNT * FOLD_COUNT:
            raise O1C29StackedHotCalibrationError(
                "global state barrier must contain the canonical 4x4 inventory"
            )
        if self.label_accesses_before_freeze != 0:
            raise O1C29StackedHotCalibrationError(
                "labels were accessed before all 16 states froze"
            )
        if any(row.config_sha256 != self.config_sha256 for row in self.states):
            raise O1C29StackedHotCalibrationError("state config lineage differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("global state receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": GLOBAL_FREEZE_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "fold_ids": list(self.fold_ids),
            "state_inventory": [
                {
                    "owner_fold": row.owner_fold,
                    "episode_fold": row.episode_fold,
                    "state_sha256": row.state_sha256,
                    "state_freeze_receipt_sha256": row.receipt_sha256,
                }
                for row in self.states
            ],
            "state_count": len(self.states),
            "label_accesses_before_freeze": self.label_accesses_before_freeze,
            "all_states_frozen_before_any_label_access": True,
        }

    def state_for(self, owner_fold: str, episode_fold: str) -> FrozenOwnerEpisodeState:
        for row in self.states:
            if row.owner_fold == owner_fold and row.episode_fold == episode_fold:
                return row
        raise O1C29StackedHotCalibrationError(
            "requested owner/episode state is absent from the global freeze"
        )


def freeze_all_owner_states(
    config: StackedHotCalibrationConfig,
    corpora: Sequence[OwnerPacketCorpus],
) -> GlobalStateFreeze:
    """Freeze the canonical 4x4 state inventory without accepting a label API."""

    if not isinstance(config, StackedHotCalibrationConfig):
        raise TypeError("config must be StackedHotCalibrationConfig")
    rows = tuple(corpora)
    by_owner = {row.owner_fold: row for row in rows}
    if len(rows) != FOLD_COUNT or set(by_owner) != set(config.fold_ids):
        raise O1C29StackedHotCalibrationError(
            "packet corpora must contain every precommitted owner exactly once"
        )
    frozen_states: list[FrozenOwnerEpisodeState] = []
    for owner in config.fold_ids:
        corpus = by_owner[owner]
        binding = corpus.quantizer
        expected_ancestry = _expected_calibration_folds(config, owner)
        if (
            binding.config_sha256 != config.sha256
            or binding.owner_fold != owner
            or binding.inherited_label_ancestry != expected_ancestry
        ):
            raise O1C29StackedHotCalibrationError(
                f"wrong-owner or wrong-quantizer binding for outer fold {owner}"
            )
        packet_ids = tuple(name for name, _packet in corpus.episode_packets)
        if packet_ids != config.fold_ids:
            raise O1C29StackedHotCalibrationError(
                f"owner {owner} packet inventory must follow canonical fold order"
            )
        for episode, extraction in corpus.episode_packets:
            if extraction.reader_state_sha256 != binding.reader_state_sha256:
                raise O1C29StackedHotCalibrationError(
                    f"wrong-owner reader entered {owner}/{episode}"
                )
            stream = build_dense_horizon_major_stream(
                extraction,
                binding.quantizer,
                encoding=ENCODING_NORMALIZED_FLOAT32,
            )
            state = consume_dense_horizon_major_stream(stream)
            state_bytes = state.to_bytes()
            unsigned = {
                "schema": STATE_FREEZE_SCHEMA,
                "protocol": PROTOCOL,
                "config_sha256": config.sha256,
                "owner_fold": owner,
                "episode_fold": episode,
                "reader_state_sha256": binding.reader_state_sha256,
                "quantizer_sha256": binding.quantizer.sha256,
                "packet_extraction_sha256": extraction.sha256,
                "evidence_sha256": stream.evidence_sha256,
                "state_basis_sha256": BASIS_SHA256,
                "state_sha256": state.sha256(),
                "state_bytes": len(state_bytes),
                "inherited_label_ancestry": list(expected_ancestry),
                "direct_label_accesses": 0,
            }
            frozen_states.append(
                FrozenOwnerEpisodeState(
                    config_sha256=config.sha256,
                    owner_fold=owner,
                    episode_fold=episode,
                    reader_state_sha256=binding.reader_state_sha256,
                    quantizer_sha256=binding.quantizer.sha256,
                    inherited_label_ancestry=expected_ancestry,
                    packet_extraction_sha256=extraction.sha256,
                    evidence_sha256=stream.evidence_sha256,
                    state_sha256=state.sha256(),
                    state_bytes=state_bytes,
                    stream=stream,
                    quantizer=binding.quantizer,
                    receipt_sha256=_document_sha256(unsigned),
                    _factory_token=_STATE_FACTORY,
                )
            )
    global_unsigned = {
        "schema": GLOBAL_FREEZE_SCHEMA,
        "protocol": PROTOCOL,
        "config_sha256": config.sha256,
        "fold_ids": list(config.fold_ids),
        "state_inventory": [
            {
                "owner_fold": row.owner_fold,
                "episode_fold": row.episode_fold,
                "state_sha256": row.state_sha256,
                "state_freeze_receipt_sha256": row.receipt_sha256,
            }
            for row in frozen_states
        ],
        "state_count": len(frozen_states),
        "label_accesses_before_freeze": 0,
        "all_states_frozen_before_any_label_access": True,
    }
    return GlobalStateFreeze(
        config_sha256=config.sha256,
        fold_ids=config.fold_ids,
        states=tuple(frozen_states),
        label_accesses_before_freeze=0,
        receipt_sha256=_document_sha256(global_unsigned),
        _factory_token=_GLOBAL_FACTORY,
    )


@dataclass(frozen=True)
class FoldLabelGrant:
    """Exactly three calibration labels released after the global state barrier."""

    config_sha256: str
    global_state_freeze_sha256: str
    outer_fold: str
    granted_folds: tuple[str, ...]
    labels_bytes: bytes = field(repr=False)
    labels_sha256: str
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _GRANT_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "label grant must be created by the allowlisted broker"
            )
        for field_name in (
            "config_sha256",
            "global_state_freeze_sha256",
            "labels_sha256",
            "receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if len(self.granted_folds) != FOLD_COUNT - 1:
            raise O1C29StackedHotCalibrationError("label grant width differs")
        labels = _readonly_label_matrix(
            np.frombuffer(self.labels_bytes, dtype=np.uint8).reshape(
                len(self.granted_folds), KEY_BITS
            ),
            len(self.granted_folds),
        )
        if _sha256_bytes(labels.tobytes(order="C")) != self.labels_sha256:
            raise O1C29StackedHotCalibrationError("label grant hash differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("label grant receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": LABEL_GRANT_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "global_state_freeze_sha256": self.global_state_freeze_sha256,
            "outer_fold": self.outer_fold,
            "granted_folds": list(self.granted_folds),
            "denied_fold": self.outer_fold,
            "labels_shape": [len(self.granted_folds), KEY_BITS],
            "labels_sha256": self.labels_sha256,
            "heldout_label_accesses": 0,
        }

    def labels(self) -> np.ndarray:
        return _readonly_label_matrix(
            np.frombuffer(self.labels_bytes, dtype=np.uint8).reshape(
                len(self.granted_folds), KEY_BITS
            ),
            len(self.granted_folds),
        )


class AllowlistedFoldLabelBroker:
    """Phase-gated one-shot broker that can never grant an owner's heldout label."""

    def __init__(
        self,
        config: StackedHotCalibrationConfig,
        labels: Mapping[str, np.ndarray],
    ) -> None:
        if not isinstance(config, StackedHotCalibrationConfig):
            raise TypeError("config must be StackedHotCalibrationConfig")
        if set(labels) != set(config.fold_ids):
            raise O1C29StackedHotCalibrationError(
                "broker labels must cover the four precommitted folds"
            )
        self._config = config
        frozen_labels: dict[str, bytes] = {}
        for fold in config.fold_ids:
            raw = np.asarray(labels[fold])
            try:
                shaped = raw.reshape(1, KEY_BITS)
            except ValueError as exc:
                raise O1C29StackedHotCalibrationError(
                    f"label {fold} must contain exactly {KEY_BITS} bits"
                ) from exc
            frozen_labels[fold] = _readonly_label_matrix(shaped, 1)[0].tobytes(
                order="C"
            )
        self._labels = frozen_labels
        self._global_freeze_sha256: str | None = None
        self._granted: set[str] = set()
        self._direct_label_accesses = 0

    @property
    def direct_label_accesses(self) -> int:
        return self._direct_label_accesses

    def activate(self, freeze: GlobalStateFreeze) -> None:
        if not isinstance(freeze, GlobalStateFreeze):
            raise O1C29StackedHotCalibrationError(
                "labels cannot open before a valid global state freeze"
            )
        if (
            freeze.config_sha256 != self._config.sha256
            or freeze.fold_ids != self._config.fold_ids
            or freeze.label_accesses_before_freeze != 0
        ):
            raise O1C29StackedHotCalibrationError(
                "global state freeze does not authorize this broker"
            )
        if self._global_freeze_sha256 not in (None, freeze.receipt_sha256):
            raise O1C29StackedHotCalibrationError(
                "broker is already bound to another state freeze"
            )
        self._global_freeze_sha256 = freeze.receipt_sha256

    def grant(
        self,
        outer_fold: str,
        requested_folds: Sequence[str] | None = None,
    ) -> FoldLabelGrant:
        owner = _require_fold(outer_fold, self._config.fold_ids, "outer_fold")
        if self._global_freeze_sha256 is None:
            raise O1C29StackedHotCalibrationError(
                "early-label access rejected before all 16 states freeze"
            )
        if owner in self._granted:
            raise O1C29StackedHotCalibrationError(
                "each outer-fold label capability is one-shot"
            )
        expected = _expected_calibration_folds(self._config, owner)
        requested = expected if requested_folds is None else tuple(requested_folds)
        if requested != expected or owner in requested:
            raise O1C29StackedHotCalibrationError(
                "label request must be the exact heldout-excluding allowlist"
            )
        matrix = np.stack(
            [np.frombuffer(self._labels[fold], dtype=np.uint8) for fold in requested]
        ).astype(np.uint8, copy=False)
        label_bytes = matrix.tobytes(order="C")
        label_sha = _sha256_bytes(label_bytes)
        unsigned = {
            "schema": LABEL_GRANT_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self._config.sha256,
            "global_state_freeze_sha256": self._global_freeze_sha256,
            "outer_fold": owner,
            "granted_folds": list(requested),
            "denied_fold": owner,
            "labels_shape": [len(requested), KEY_BITS],
            "labels_sha256": label_sha,
            "heldout_label_accesses": 0,
        }
        self._granted.add(owner)
        self._direct_label_accesses += len(requested)
        return FoldLabelGrant(
            config_sha256=self._config.sha256,
            global_state_freeze_sha256=self._global_freeze_sha256,
            outer_fold=owner,
            granted_folds=requested,
            labels_bytes=label_bytes,
            labels_sha256=label_sha,
            receipt_sha256=_document_sha256(unsigned),
            _factory_token=_GRANT_FACTORY,
        )


def _binary_nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    signed = 2.0 * labels.astype(np.float64) - 1.0
    losses = np.logaddexp(0.0, -signed * logits.astype(np.float64))
    return float(losses.sum(dtype=np.float64) / math.log(2.0))


def _read_states_at_temperature(
    states: Sequence[PolyphaseSufficientState],
    fit: FittedHorizonReadout,
    temperature: float,
) -> np.ndarray:
    if fit.abstained:
        return np.zeros((len(states), KEY_BITS), dtype=np.float32)
    spec = PolyphaseReadoutSpec(
        name="o1c29-confidence-temperature-grid",
        basis_sha256=BASIS_SHA256,
        slot_weights=fit.slot_weights,
        temperature=temperature,
    )
    return np.stack([read_polyphase_state(state, spec) for state in states])


@dataclass(frozen=True)
class FrozenOuterHotFit:
    """One three-episode fit whose heldout fold is absent from every input."""

    config_sha256: str
    global_state_freeze_sha256: str
    outer_fold: str
    calibration_folds: tuple[str, ...]
    training_state_receipt_sha256: tuple[str, ...]
    training_state_sha256: tuple[str, ...]
    label_grant_receipt_sha256: str
    inherited_label_ancestry: tuple[str, ...]
    simplex_fit: FittedHorizonReadout = field(repr=False, compare=False)
    confidence_temperature: float
    confidence_objective_bits: float
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FIT_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "outer hot fit must be created by its fold-safe factory"
            )
        for field_name in (
            "config_sha256",
            "global_state_freeze_sha256",
            "label_grant_receipt_sha256",
            "receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        for value in self.training_state_receipt_sha256 + self.training_state_sha256:
            _require_sha256(value, "training state hash")
        if not isinstance(self.simplex_fit, FittedHorizonReadout):
            raise TypeError("simplex_fit must be FittedHorizonReadout")
        _float32(self.confidence_temperature, "confidence_temperature")
        if (
            isinstance(self.confidence_objective_bits, bool)
            or not isinstance(self.confidence_objective_bits, (int, float))
            or not math.isfinite(float(self.confidence_objective_bits))
            or self.confidence_objective_bits < 0.0
        ):
            raise O1C29StackedHotCalibrationError(
                "confidence objective must be finite and nonnegative"
            )
        if self.outer_fold in self.calibration_folds or self.outer_fold in (
            self.inherited_label_ancestry
        ):
            raise O1C29StackedHotCalibrationError(
                "heldout fold entered fit inputs or transitive ancestry"
            )
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("hot fit receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": FIT_FREEZE_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "global_state_freeze_sha256": self.global_state_freeze_sha256,
            "outer_fold": self.outer_fold,
            "calibration_folds": list(self.calibration_folds),
            "training_state_receipt_sha256": list(self.training_state_receipt_sha256),
            "training_state_sha256": list(self.training_state_sha256),
            "label_grant_receipt_sha256": self.label_grant_receipt_sha256,
            "inherited_label_ancestry": list(self.inherited_label_ancestry),
            "heldout_state_is_fit_input": False,
            "heldout_label_accesses": 0,
            "simplex_fit": self.simplex_fit.describe(),
            "confidence_temperature_float32_hex": float(
                np.float32(self.confidence_temperature)
            ).hex(),
            "confidence_objective_bits_float64_hex": float(
                self.confidence_objective_bits
            ).hex(),
            "actual_o1c23_selector_used_for_scientific_selection": False,
        }


def fit_outer_fold(
    config: StackedHotCalibrationConfig,
    freeze: GlobalStateFreeze,
    grant: FoldLabelGrant,
    *,
    outer_fold: str,
    training_state_refs: Sequence[tuple[str, str]] | None = None,
) -> FrozenOuterHotFit:
    """Fit the two precommitted hot arms from exactly three owner-local states."""

    owner = _require_fold(outer_fold, config.fold_ids, "outer_fold")
    if (
        freeze.config_sha256 != config.sha256
        or grant.config_sha256 != config.sha256
        or grant.global_state_freeze_sha256 != freeze.receipt_sha256
        or grant.outer_fold != owner
    ):
        raise O1C29StackedHotCalibrationError("fit authority lineage differs")
    calibration_folds = _expected_calibration_folds(config, owner)
    expected_refs = tuple((owner, episode) for episode in calibration_folds)
    refs = expected_refs if training_state_refs is None else tuple(training_state_refs)
    if any(episode == owner for _state_owner, episode in refs):
        raise O1C29StackedHotCalibrationError(
            "heldout-state substitution rejected from fit inputs"
        )
    if refs != expected_refs:
        raise O1C29StackedHotCalibrationError(
            "wrong-owner state substitution rejected from fit inputs"
        )
    if grant.granted_folds != calibration_folds:
        raise O1C29StackedHotCalibrationError(
            "fit labels differ from the exact calibration allowlist"
        )
    frozen_states = tuple(freeze.state_for(*reference) for reference in refs)
    if any(
        row.owner_fold != owner
        or row.episode_fold not in calibration_folds
        or row.inherited_label_ancestry != calibration_folds
        or owner in row.inherited_label_ancestry
        for row in frozen_states
    ):
        raise O1C29StackedHotCalibrationError(
            "fit state owner or transitive label ancestry differs"
        )
    states = tuple(row.state() for row in frozen_states)
    labels = grant.labels()
    simplex_fit = fit_nonnegative_horizon_readout(
        states,
        labels,
        alpha=config.alpha,
    )
    objectives: list[float] = []
    for temperature in config.confidence_temperature_grid:
        logits = _read_states_at_temperature(states, simplex_fit, temperature)
        objectives.append(_binary_nll_bits(logits, labels))
    selected_index = min(
        range(len(objectives)), key=lambda index: (objectives[index], index)
    )
    confidence_temperature = config.confidence_temperature_grid[selected_index]
    confidence_objective = objectives[selected_index]
    unsigned = {
        "schema": FIT_FREEZE_SCHEMA,
        "protocol": PROTOCOL,
        "config_sha256": config.sha256,
        "global_state_freeze_sha256": freeze.receipt_sha256,
        "outer_fold": owner,
        "calibration_folds": list(calibration_folds),
        "training_state_receipt_sha256": [row.receipt_sha256 for row in frozen_states],
        "training_state_sha256": [row.state_sha256 for row in frozen_states],
        "label_grant_receipt_sha256": grant.receipt_sha256,
        "inherited_label_ancestry": list(calibration_folds),
        "heldout_state_is_fit_input": False,
        "heldout_label_accesses": 0,
        "simplex_fit": simplex_fit.describe(),
        "confidence_temperature_float32_hex": float(
            np.float32(confidence_temperature)
        ).hex(),
        "confidence_objective_bits_float64_hex": float(confidence_objective).hex(),
        "actual_o1c23_selector_used_for_scientific_selection": False,
    }
    return FrozenOuterHotFit(
        config_sha256=config.sha256,
        global_state_freeze_sha256=freeze.receipt_sha256,
        outer_fold=owner,
        calibration_folds=calibration_folds,
        training_state_receipt_sha256=tuple(
            row.receipt_sha256 for row in frozen_states
        ),
        training_state_sha256=tuple(row.state_sha256 for row in frozen_states),
        label_grant_receipt_sha256=grant.receipt_sha256,
        inherited_label_ancestry=calibration_folds,
        simplex_fit=simplex_fit,
        confidence_temperature=confidence_temperature,
        confidence_objective_bits=confidence_objective,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_FIT_FACTORY,
    )


def _precommitted_operator(
    config: StackedHotCalibrationConfig,
    *,
    operator_id: str,
    fitted_slot_weights_sha256: str,
) -> dict[str, object]:
    descriptor_core = {
        "schema": "o1-256-o1c29-outcome-independent-hot-operator-v1",
        "config_sha256": config.sha256,
        "operator_id": operator_id,
        "actual_o1c23_selector_used_for_scientific_selection": False,
    }
    common: dict[str, object] = {
        "operator_id": operator_id,
        "operator_fingerprint": _document_sha256(descriptor_core),
        "source_result_sha256": _sha256_bytes(
            b"O1C-0029/precommitted-source\x00" + bytes.fromhex(config.sha256)
        ),
        "verified_decision_sha256": _sha256_bytes(
            b"O1C-0029/outcome-independent-decision\x00" + bytes.fromhex(config.sha256)
        ),
        "policy_sha256": _sha256_bytes(
            b"O1C-0029/fixed-two-hot-arm-policy\x00" + bytes.fromhex(config.sha256)
        ),
    }
    if operator_id == PRIMARY_OPERATOR_ID:
        return {
            **common,
            "replaced_components": ["horizon_scale_weighting"],
            "weight_contract": "nonnegative_horizon_simplex_equal_poles",
        }
    if operator_id == SECONDARY_OPERATOR_ID:
        return {
            **common,
            "replaced_components": ["magnitude_confidence"],
            "calibration_scope": "global_temperature_only",
            "frozen_slot_weights_sha256": fitted_slot_weights_sha256,
        }
    raise O1C29StackedHotCalibrationError("operator is not precommitted")


@dataclass(frozen=True)
class FrozenOuterPrediction:
    """Two immutable heldout logit vectors produced without the heldout label."""

    config_sha256: str
    global_state_freeze_sha256: str
    outer_fold: str
    heldout_state_receipt_sha256: str
    heldout_state_sha256: str
    fit_receipt_sha256: str
    inherited_label_ancestry: tuple[str, ...]
    primary_logits_bytes: bytes = field(repr=False)
    secondary_logits_bytes: bytes = field(repr=False)
    primary_logits_sha256: str
    secondary_logits_sha256: str
    hot_lineage_receipt_sha256: str
    primary_binding_sha256: str
    secondary_binding_sha256: str
    actual_o1c23_selector_sha256: str | None
    state_unchanged: bool
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _PREDICTION_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "prediction must be created by the heldout-safe factory"
            )
        for field_name in (
            "config_sha256",
            "global_state_freeze_sha256",
            "heldout_state_receipt_sha256",
            "heldout_state_sha256",
            "fit_receipt_sha256",
            "primary_logits_sha256",
            "secondary_logits_sha256",
            "hot_lineage_receipt_sha256",
            "primary_binding_sha256",
            "secondary_binding_sha256",
            "receipt_sha256",
        ):
            _require_sha256(getattr(self, field_name), field_name)
        if self.actual_o1c23_selector_sha256 is not None:
            _require_sha256(
                self.actual_o1c23_selector_sha256,
                "actual_o1c23_selector_sha256",
            )
        expected_bytes = KEY_BITS * np.dtype("<f4").itemsize
        if (
            not isinstance(self.primary_logits_bytes, bytes)
            or not isinstance(self.secondary_logits_bytes, bytes)
            or len(self.primary_logits_bytes) != expected_bytes
            or len(self.secondary_logits_bytes) != expected_bytes
            or _sha256_bytes(self.primary_logits_bytes) != self.primary_logits_sha256
            or _sha256_bytes(self.secondary_logits_bytes)
            != self.secondary_logits_sha256
        ):
            raise O1C29StackedHotCalibrationError("prediction logit bytes differ")
        if not self.state_unchanged:
            raise O1C29StackedHotCalibrationError("hot readout mutated heldout state")
        if self.outer_fold in self.inherited_label_ancestry:
            raise O1C29StackedHotCalibrationError(
                "heldout label entered prediction ancestry"
            )
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("prediction freeze receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": PREDICTION_FREEZE_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "global_state_freeze_sha256": self.global_state_freeze_sha256,
            "outer_fold": self.outer_fold,
            "heldout_episode_fold": self.outer_fold,
            "heldout_state_receipt_sha256": self.heldout_state_receipt_sha256,
            "heldout_state_sha256": self.heldout_state_sha256,
            "fit_receipt_sha256": self.fit_receipt_sha256,
            "inherited_label_ancestry": list(self.inherited_label_ancestry),
            "primary_operator_id": PRIMARY_OPERATOR_ID,
            "secondary_operator_id": SECONDARY_OPERATOR_ID,
            "primary_logits_sha256": self.primary_logits_sha256,
            "secondary_logits_sha256": self.secondary_logits_sha256,
            "hot_lineage_receipt_sha256": self.hot_lineage_receipt_sha256,
            "primary_binding_sha256": self.primary_binding_sha256,
            "secondary_binding_sha256": self.secondary_binding_sha256,
            "actual_o1c23_selector_sha256": self.actual_o1c23_selector_sha256,
            "actual_o1c23_selector_used_for_scientific_selection": False,
            "heldout_label_accesses": 0,
            "state_unchanged": self.state_unchanged,
        }

    def primary_logits(self) -> np.ndarray:
        return np.frombuffer(self.primary_logits_bytes, dtype="<f4")

    def secondary_logits(self) -> np.ndarray:
        return np.frombuffer(self.secondary_logits_bytes, dtype="<f4")


def predict_outer_fold(
    config: StackedHotCalibrationConfig,
    freeze: GlobalStateFreeze,
    fit: FrozenOuterHotFit,
    *,
    outer_fold: str,
    heldout_state_ref: tuple[str, str] | None = None,
    actual_o1c23_selector_sha256: str | None = None,
    actual_o1c23_selector_used_for_scientific_selection: bool = False,
) -> FrozenOuterPrediction:
    """Read both precommitted arms; O1C-0023 may be attested but cannot select."""

    owner = _require_fold(outer_fold, config.fold_ids, "outer_fold")
    if actual_o1c23_selector_used_for_scientific_selection:
        raise O1C29StackedHotCalibrationError(
            "actual O1C-0023 selector is post-result and cannot select a clean arm"
        )
    if actual_o1c23_selector_sha256 is not None:
        _require_sha256(actual_o1c23_selector_sha256, "actual_o1c23_selector_sha256")
    if (
        freeze.config_sha256 != config.sha256
        or fit.config_sha256 != config.sha256
        or fit.global_state_freeze_sha256 != freeze.receipt_sha256
        or fit.outer_fold != owner
    ):
        raise O1C29StackedHotCalibrationError("prediction authority lineage differs")
    expected_ref = (owner, owner)
    reference = expected_ref if heldout_state_ref is None else tuple(heldout_state_ref)
    if reference != expected_ref:
        raise O1C29StackedHotCalibrationError(
            "heldout inference requires the exact owner-fold heldout state"
        )
    heldout = freeze.state_for(*expected_ref)
    expected_ancestry = _expected_calibration_folds(config, owner)
    if (
        heldout.inherited_label_ancestry != expected_ancestry
        or fit.inherited_label_ancestry != expected_ancestry
        or owner in expected_ancestry
    ):
        raise O1C29StackedHotCalibrationError(
            "heldout prediction transitive ancestry differs"
        )
    state = heldout.state()
    before = state.to_bytes()
    lineage = freeze_hot_readout_lineage(
        heldout.stream,
        heldout.quantizer,
        state,
        fit.simplex_fit,
    )
    fitted_weights_sha = _sha256_bytes(
        fit.simplex_fit.slot_weights.astype("<f4", copy=False).tobytes(order="C")
    )
    if fit.simplex_fit.abstained:
        primary_logits = np.zeros(KEY_BITS, dtype=np.float32)
        secondary_logits = np.zeros(KEY_BITS, dtype=np.float32)
        primary_binding_sha = _sha256_bytes(
            b"O1C-0029/abstained-primary\x00" + bytes.fromhex(fit.receipt_sha256)
        )
        secondary_binding_sha = _sha256_bytes(
            b"O1C-0029/abstained-secondary\x00" + bytes.fromhex(fit.receipt_sha256)
        )
    else:
        primary_binding = bind_o1o_hot_readout(
            _precommitted_operator(
                config,
                operator_id=PRIMARY_OPERATOR_ID,
                fitted_slot_weights_sha256=fitted_weights_sha,
            ),
            slot_weights=fit.simplex_fit.slot_weights,
            temperature=fit.simplex_fit.temperature,
            lineage=lineage,
        )
        secondary_binding = bind_o1o_hot_readout(
            _precommitted_operator(
                config,
                operator_id=SECONDARY_OPERATOR_ID,
                fitted_slot_weights_sha256=fitted_weights_sha,
            ),
            slot_weights=fit.simplex_fit.slot_weights,
            temperature=fit.confidence_temperature,
            lineage=lineage,
        )
        primary_logits = read_bound_hot_state(state, primary_binding)
        secondary_logits = read_bound_hot_state(state, secondary_binding)
        primary_binding_sha = primary_binding.binding_sha256
        secondary_binding_sha = secondary_binding.binding_sha256
    after = state.to_bytes()
    primary_bytes = primary_logits.astype("<f4", copy=False).tobytes(order="C")
    secondary_bytes = secondary_logits.astype("<f4", copy=False).tobytes(order="C")
    primary_sha = _sha256_bytes(primary_bytes)
    secondary_sha = _sha256_bytes(secondary_bytes)
    unsigned = {
        "schema": PREDICTION_FREEZE_SCHEMA,
        "protocol": PROTOCOL,
        "config_sha256": config.sha256,
        "global_state_freeze_sha256": freeze.receipt_sha256,
        "outer_fold": owner,
        "heldout_episode_fold": owner,
        "heldout_state_receipt_sha256": heldout.receipt_sha256,
        "heldout_state_sha256": heldout.state_sha256,
        "fit_receipt_sha256": fit.receipt_sha256,
        "inherited_label_ancestry": list(expected_ancestry),
        "primary_operator_id": PRIMARY_OPERATOR_ID,
        "secondary_operator_id": SECONDARY_OPERATOR_ID,
        "primary_logits_sha256": primary_sha,
        "secondary_logits_sha256": secondary_sha,
        "hot_lineage_receipt_sha256": lineage.lineage_receipt_sha256,
        "primary_binding_sha256": primary_binding_sha,
        "secondary_binding_sha256": secondary_binding_sha,
        "actual_o1c23_selector_sha256": actual_o1c23_selector_sha256,
        "actual_o1c23_selector_used_for_scientific_selection": False,
        "heldout_label_accesses": 0,
        "state_unchanged": before == after,
    }
    return FrozenOuterPrediction(
        config_sha256=config.sha256,
        global_state_freeze_sha256=freeze.receipt_sha256,
        outer_fold=owner,
        heldout_state_receipt_sha256=heldout.receipt_sha256,
        heldout_state_sha256=heldout.state_sha256,
        fit_receipt_sha256=fit.receipt_sha256,
        inherited_label_ancestry=expected_ancestry,
        primary_logits_bytes=primary_bytes,
        secondary_logits_bytes=secondary_bytes,
        primary_logits_sha256=primary_sha,
        secondary_logits_sha256=secondary_sha,
        hot_lineage_receipt_sha256=lineage.lineage_receipt_sha256,
        primary_binding_sha256=primary_binding_sha,
        secondary_binding_sha256=secondary_binding_sha,
        actual_o1c23_selector_sha256=actual_o1c23_selector_sha256,
        state_unchanged=before == after,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_PREDICTION_FACTORY,
    )


@dataclass(frozen=True)
class StackedHotCalibrationResult:
    """Unscored four-fold prediction result; no heldout label has been opened."""

    config_sha256: str
    global_freeze: GlobalStateFreeze = field(repr=False, compare=False)
    fits: tuple[FrozenOuterHotFit, ...] = field(repr=False, compare=False)
    predictions: tuple[FrozenOuterPrediction, ...] = field(repr=False, compare=False)
    actual_o1c23_selector_sha256: str | None
    receipt_sha256: str
    _factory_token: InitVar[object]

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _RESULT_FACTORY:
            raise O1C29StackedHotCalibrationError(
                "stacked result must be created by the protocol runner"
            )
        _require_sha256(self.config_sha256, "config_sha256")
        _require_sha256(self.receipt_sha256, "receipt_sha256")
        if self.actual_o1c23_selector_sha256 is not None:
            _require_sha256(
                self.actual_o1c23_selector_sha256,
                "actual_o1c23_selector_sha256",
            )
        folds = self.global_freeze.fold_ids
        if (
            tuple(row.outer_fold for row in self.fits) != folds
            or tuple(row.outer_fold for row in self.predictions) != folds
        ):
            raise O1C29StackedHotCalibrationError("four-fold result inventory differs")
        if self.receipt_sha256 != _document_sha256(self.receipt_document()):
            raise O1C29StackedHotCalibrationError("stacked result receipt differs")

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": RESULT_SCHEMA,
            "protocol": PROTOCOL,
            "config_sha256": self.config_sha256,
            "global_state_freeze_sha256": self.global_freeze.receipt_sha256,
            "fit_receipt_sha256": [row.receipt_sha256 for row in self.fits],
            "prediction_receipt_sha256": [
                row.receipt_sha256 for row in self.predictions
            ],
            "actual_o1c23_selector_sha256": self.actual_o1c23_selector_sha256,
            "actual_o1c23_selector_used_for_scientific_selection": False,
            "heldout_labels_opened_for_scoring": 0,
            "classification": PROTOCOL,
        }


def run_stacked_hot_calibration_from_freeze(
    config: StackedHotCalibrationConfig,
    freeze: GlobalStateFreeze,
    broker: AllowlistedFoldLabelBroker,
    *,
    actual_o1c23_selector_sha256: str | None = None,
) -> StackedHotCalibrationResult:
    """Fit and predict all folds from one already-created exact state barrier."""

    if not isinstance(config, StackedHotCalibrationConfig):
        raise TypeError("config must be StackedHotCalibrationConfig")
    if not isinstance(freeze, GlobalStateFreeze):
        raise TypeError("freeze must be GlobalStateFreeze")
    if not isinstance(broker, AllowlistedFoldLabelBroker):
        raise TypeError("broker must be AllowlistedFoldLabelBroker")
    if actual_o1c23_selector_sha256 is not None:
        _require_sha256(
            actual_o1c23_selector_sha256,
            "actual_o1c23_selector_sha256",
        )
    if (
        freeze.config_sha256 != config.sha256
        or freeze.fold_ids != config.fold_ids
        or len(freeze.states) != FOLD_COUNT * FOLD_COUNT
    ):
        raise O1C29StackedHotCalibrationError(
            "existing global state freeze does not match the protocol config"
        )
    # Activation is intentionally idempotent for the same exact freeze receipt.
    broker.activate(freeze)
    fits: list[FrozenOuterHotFit] = []
    predictions: list[FrozenOuterPrediction] = []
    for outer_fold in config.fold_ids:
        grant = broker.grant(outer_fold)
        fit = fit_outer_fold(
            config,
            freeze,
            grant,
            outer_fold=outer_fold,
        )
        prediction = predict_outer_fold(
            config,
            freeze,
            fit,
            outer_fold=outer_fold,
            actual_o1c23_selector_sha256=actual_o1c23_selector_sha256,
        )
        fits.append(fit)
        predictions.append(prediction)
    unsigned = {
        "schema": RESULT_SCHEMA,
        "protocol": PROTOCOL,
        "config_sha256": config.sha256,
        "global_state_freeze_sha256": freeze.receipt_sha256,
        "fit_receipt_sha256": [row.receipt_sha256 for row in fits],
        "prediction_receipt_sha256": [row.receipt_sha256 for row in predictions],
        "actual_o1c23_selector_sha256": actual_o1c23_selector_sha256,
        "actual_o1c23_selector_used_for_scientific_selection": False,
        "heldout_labels_opened_for_scoring": 0,
        "classification": PROTOCOL,
    }
    return StackedHotCalibrationResult(
        config_sha256=config.sha256,
        global_freeze=freeze,
        fits=tuple(fits),
        predictions=tuple(predictions),
        actual_o1c23_selector_sha256=actual_o1c23_selector_sha256,
        receipt_sha256=_document_sha256(unsigned),
        _factory_token=_RESULT_FACTORY,
    )


def run_stacked_hot_calibration(
    config: StackedHotCalibrationConfig,
    corpora: Sequence[OwnerPacketCorpus],
    broker: AllowlistedFoldLabelBroker,
    *,
    actual_o1c23_selector_sha256: str | None = None,
) -> StackedHotCalibrationResult:
    """Execute the unscored protocol with the global barrier as the first action."""

    freeze = freeze_all_owner_states(config, corpora)
    return run_stacked_hot_calibration_from_freeze(
        config,
        freeze,
        broker,
        actual_o1c23_selector_sha256=actual_o1c23_selector_sha256,
    )


__all__ = [
    "AllowlistedFoldLabelBroker",
    "FoldLabelGrant",
    "FrozenOuterHotFit",
    "FrozenOuterPrediction",
    "FrozenOwnerEpisodeState",
    "FrozenOwnerQuantizer",
    "GlobalStateFreeze",
    "O1C29StackedHotCalibrationError",
    "OwnerPacketCorpus",
    "PRIMARY_OPERATOR_ID",
    "PROTOCOL",
    "SECONDARY_OPERATOR_ID",
    "StackedHotCalibrationConfig",
    "StackedHotCalibrationResult",
    "fit_outer_fold",
    "freeze_all_owner_states",
    "freeze_owner_quantizer",
    "predict_outer_fold",
    "run_stacked_hot_calibration",
    "run_stacked_hot_calibration_from_freeze",
]
