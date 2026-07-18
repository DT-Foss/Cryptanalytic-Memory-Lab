"""Truth-free O1C-0022 logit handoff to the exact O1C-0024 frontier.

O1C-0022 freezes natural Bernoulli logits, while O1C-0024's original public
entry point accepts probabilities strictly inside ``(0, 1)``.  Converting a
large finite logit through binary64 sigmoid can round to an endpoint.  This
module therefore preserves the posterior exactly in logit space: sign selects
the MAP bit, absolute logit supplies the flip penalty, and a stable softplus
supplies the MAP probability.

No function in this module accepts a key, label, reveal, or evaluation result.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import PurePosixPath
from typing import Final

import numpy as np

from .chacha_trace import chacha20_block_trace
from .living_inverse import (
    KEY_BITS,
    KEY_BYTES,
    PublicTargetView,
    bits_to_key,
    canonical_json_bytes,
)


O1C22_WIDTHS: Final = (12, 52, 128, 256)
O1C22_ARMS: Final = (
    "raw_float_delta_sum",
    "normalized_float_delta_sum",
    "quantized_int8_vault",
    "last_horizon_only",
    "unit_sign_sum",
    "coordinate_shuffled_vault",
    "zero_prior",
)

LOGIT_DIAGNOSTICS_SCHEMA: Final = "o1-256-factorized-logit-diagnostics-v1"
LOGIT_FRONTIER_FREEZE_SCHEMA: Final = "o1-256-o1c22-logit-frontier-freeze-v1"
LOGIT_FRONTIER_CANDIDATE_SCHEMA: Final = "o1-256-factorized-logit-topk-candidate-v1"
LOGIT_FRONTIER_VERIFICATION_SCHEMA: Final = (
    "o1-256-factorized-logit-topk-public-verification-v1"
)
LOGIT_TOPOLOGY_TIE_POLICY: Final = (
    "ascending-exact-absolute-binary64-logit-then-coordinate topology; "
    "equal exact subset sums use ascending topology bitmask"
)
LOGIT_FRONTIER_FREEZE_PHASE: Final = "FACTORIZED_LOGIT_FRONTIER_INPUT_FROZEN_PRE_ORACLE"
O1C22_SOURCE_SHAPE: Final = (len(O1C22_WIDTHS), len(O1C22_ARMS), KEY_BITS)
O1C22_SOURCE_ARTIFACT_BYTES: Final = math.prod(O1C22_SOURCE_SHAPE) * 8
SELECTED_LOGIT_BYTES: Final = KEY_BITS * 8

_LN2: Final = math.log(2.0)
_HEX: Final = frozenset("0123456789abcdef")
_LOGIT_SEMANTICS: Final = "natural-log-odds ln(P(bit=1)/P(bit=0))"
_COORDINATE_ORDER: Final = "RFC-little-bit-within-byte coordinates 0..255"
_FORBIDDEN_FREEZE_KEY_FRAGMENTS: Final = (
    "true_key",
    "target_key",
    "target_trace",
    "map_key_hex",
    "map_key_sha256",
)
_FORBIDDEN_FREEZE_KEYS: Final = frozenset(
    {"labels", "label_bits", "reveal", "evaluation"}
)
_O1C22_SOURCE_PATHS: Final = frozenset(
    f"folds/build-{index:04d}/heldout/calibrated_predictions.f64le"
    for index in range(4)
)
_O1C22_ARTIFACT_INDEX_SCHEMA: Final = "o1-256-o1c19-causal-vault-artifact-index-v1"
_O1C22_PREDICTION_FREEZE_SCHEMA: Final = "o1-256-o1c22-heldout-prediction-freeze-v1"
_O1C22_PREDICTION_FREEZE_PHASE: Final = "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE"
_O1C19_PREDICTION_FREEZE_SCHEMA: Final = (
    "o1-256-fullround-multiresolution-build-loo-prediction-freeze-v1"
)
_O1C19_PREDICTION_FREEZE_PHASE: Final = (
    "ALL_HELD_OUT_TRAJECTORIES_FROZEN_BEFORE_LABEL_ACCESS"
)
_FORMAL_CANDIDATE_LIMIT: Final = 65_536


class PosteriorLogitFrontierError(ValueError):
    """An O1C-0022 tensor, logit posterior, or freeze receipt differs."""


@dataclass(frozen=True)
class FactorizedLogitFrontierCandidate:
    """One globally ranked key with an exact binary64-logit subset score."""

    rank: int
    key: bytes
    log2_probability: float
    flip_penalty_bits: float
    exact_penalty_units: int
    penalty_unit_exponent: int
    flipped_coordinates: tuple[int, ...]
    topology_code: int

    def describe(self) -> dict[str, object]:
        return {
            "schema": LOGIT_FRONTIER_CANDIDATE_SCHEMA,
            "rank": self.rank,
            "key_hex": self.key.hex(),
            "log2_probability": self.log2_probability,
            "flip_penalty_bits": self.flip_penalty_bits,
            "exact_penalty_units": self.exact_penalty_units,
            "penalty_unit_exponent": self.penalty_unit_exponent,
            "flipped_coordinates": list(self.flipped_coordinates),
            "topology_code_hex": f"{self.topology_code:064x}",
            "tie_policy": LOGIT_TOPOLOGY_TIE_POLICY,
        }


@dataclass(frozen=True)
class _LogitPlan:
    logits: np.ndarray
    mode_bits: tuple[int, ...]
    topology: tuple[int, ...]
    penalty_units: tuple[int, ...]
    coordinate_penalty_units: tuple[int, ...]
    penalty_unit_exponent: int
    map_log2_probability: float


@dataclass(frozen=True)
class _VerifiedSourceLifecycle:
    capsule_manifest_sha256: str
    artifact_index_sha256: str
    prediction_freeze_sha256: str
    upstream_prediction_freeze_sha256: str
    fold_index: int
    target_id: str
    action_pool_sha256: str
    public_view_sha256: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise PosteriorLogitFrontierError(f"{field} must be lowercase SHA-256")
    return value


def _candidate_limit(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 1 << KEY_BITS
    ):
        raise PosteriorLogitFrontierError(
            f"candidate limit must be an integer in [1, 2^{KEY_BITS}]"
        )
    return value


def _selected_width(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value not in O1C22_WIDTHS
    ):
        raise PosteriorLogitFrontierError(
            f"selected width must be one of {O1C22_WIDTHS}"
        )
    return value


def _selected_arm(value: object) -> str:
    if not isinstance(value, str) or value not in O1C22_ARMS:
        raise PosteriorLogitFrontierError(
            "selected arm must be a frozen O1C-0022 prediction arm"
        )
    return value


def _source_shape(value: object) -> tuple[int, int, int]:
    if isinstance(value, (str, bytes, bytearray)):
        raise PosteriorLogitFrontierError(
            f"source shape must equal {O1C22_SOURCE_SHAPE}"
        )
    try:
        shape: tuple[object, ...] = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise PosteriorLogitFrontierError(
            f"source shape must equal {O1C22_SOURCE_SHAPE}"
        ) from exc
    if shape != O1C22_SOURCE_SHAPE or any(
        isinstance(item, bool) or not isinstance(item, int) for item in shape
    ):
        raise PosteriorLogitFrontierError(
            f"source shape must equal {O1C22_SOURCE_SHAPE}"
        )
    return O1C22_SOURCE_SHAPE


def _source_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PosteriorLogitFrontierError("source artifact path must be relative")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PosteriorLogitFrontierError("source artifact path must be relative")
    if path.as_posix() != value:
        raise PosteriorLogitFrontierError("source artifact path must be canonical")
    if value not in _O1C22_SOURCE_PATHS:
        raise PosteriorLogitFrontierError(
            "source artifact path must name one frozen O1C-0022 held-out "
            "calibrated-prediction tensor"
        )
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise PosteriorLogitFrontierError(f"{field} must be a JSON object")
    return value


def _canonical_json_mapping(payload: object, field: str) -> Mapping[str, object]:
    if not isinstance(payload, bytes):
        raise PosteriorLogitFrontierError(f"{field} must be JSON bytes")
    try:
        decoded = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PosteriorLogitFrontierError(f"{field} must be JSON bytes") from exc
    return _mapping(decoded, field)


def _canonical_freeze(
    payload: object,
    *,
    field: str,
    schema: str,
    phase: str,
) -> tuple[Mapping[str, object], str]:
    document = _canonical_json_mapping(payload, field)
    if document.get("schema") != schema or document.get("phase") != phase:
        raise PosteriorLogitFrontierError(f"{field} lifecycle schema differs")
    unsigned = dict(document)
    supplied = _sha256(unsigned.pop("freeze_sha256", None), f"{field} freeze SHA-256")
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise PosteriorLogitFrontierError(f"{field} freeze SHA-256 differs")
    return document, supplied


def _manifest_entries(payload: object) -> tuple[bytes, Mapping[str, str]]:
    if not isinstance(payload, bytes) or not payload:
        raise PosteriorLogitFrontierError(
            "source capsule manifest must be non-empty bytes"
        )
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PosteriorLogitFrontierError(
            "source capsule manifest must be ASCII"
        ) from exc
    if not text.endswith("\n"):
        raise PosteriorLogitFrontierError(
            "source capsule manifest must end with a newline"
        )
    entries: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise PosteriorLogitFrontierError("source capsule manifest line differs")
        digest = _sha256(line[:64], "source capsule manifest member SHA-256")
        relative = line[66:]
        path = PurePosixPath(relative)
        if (
            not relative
            or path.is_absolute()
            or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in path.parts)
            or relative in entries
        ):
            raise PosteriorLogitFrontierError(
                "source capsule manifest member path differs"
            )
        entries[relative] = digest
    if not entries:
        raise PosteriorLogitFrontierError("source capsule manifest is empty")
    return payload, entries


def _artifact_entry(
    artifacts: Mapping[str, object],
    relative: str,
    *,
    expected_sha256: str,
    expected_bytes: int,
    field: str,
) -> None:
    entry = _mapping(artifacts.get(relative), f"{field} entry")
    if (
        _sha256(entry.get("sha256"), f"{field} entry SHA-256") != expected_sha256
        or entry.get("bytes") != expected_bytes
    ):
        raise PosteriorLogitFrontierError(f"{field} entry differs")


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PosteriorLogitFrontierError(f"{field} must be a non-negative integer")
    return value


def _verify_source_lifecycle(
    *,
    source_payload: bytes,
    source_artifact_path: str,
    source_artifact_sha256: str,
    source_capsule_manifest_payload: object,
    source_capsule_manifest_sha256: str,
    source_artifact_index_payload: object,
    source_artifact_index_sha256: str,
    source_prediction_freeze_payload: object,
    source_prediction_freeze_sha256: str,
    upstream_prediction_freeze_payload: object,
    public_target: PublicTargetView,
) -> _VerifiedSourceLifecycle:
    manifest_payload, manifest = _manifest_entries(source_capsule_manifest_payload)
    capsule_digest = _sha256_bytes(manifest_payload)
    if capsule_digest != source_capsule_manifest_sha256:
        raise PosteriorLogitFrontierError("source capsule-manifest SHA-256 differs")

    index_document = _canonical_json_mapping(
        source_artifact_index_payload,
        "source artifact index",
    )
    index_payload = source_artifact_index_payload
    assert isinstance(index_payload, bytes)
    index_digest = _sha256_bytes(index_payload)
    if index_digest != source_artifact_index_sha256:
        raise PosteriorLogitFrontierError("source artifact-index SHA-256 differs")
    if (
        index_document.get("schema") != _O1C22_ARTIFACT_INDEX_SCHEMA
        or index_document.get("attempt_id") != "O1C-0022"
    ):
        raise PosteriorLogitFrontierError("source artifact index identity differs")
    artifacts = _mapping(index_document.get("artifacts"), "source artifact inventory")
    if _nonnegative_int(
        index_document.get("indexed_artifact_count"),
        "indexed_artifact_count",
    ) != len(artifacts) or _nonnegative_int(
        index_document.get("indexed_artifact_bytes"),
        "indexed_artifact_bytes",
    ) != sum(
        _nonnegative_int(
            _mapping(entry, f"artifact {relative}").get("bytes"),
            f"artifact {relative} bytes",
        )
        for relative, entry in artifacts.items()
    ):
        raise PosteriorLogitFrontierError("source artifact index totals differ")

    prediction_path = str(
        PurePosixPath(source_artifact_path).parent / "prediction_freeze.json"
    )
    if manifest.get("artifacts/artifact_index.json") != index_digest:
        raise PosteriorLogitFrontierError(
            "source capsule manifest does not bind the artifact index"
        )
    if manifest.get(f"artifacts/{source_artifact_path}") != source_artifact_sha256:
        raise PosteriorLogitFrontierError(
            "source capsule manifest does not bind the prediction tensor"
        )

    source_freeze, source_freeze_digest = _canonical_freeze(
        source_prediction_freeze_payload,
        field="source prediction freeze",
        schema=_O1C22_PREDICTION_FREEZE_SCHEMA,
        phase=_O1C22_PREDICTION_FREEZE_PHASE,
    )
    source_freeze_payload = source_prediction_freeze_payload
    assert isinstance(source_freeze_payload, bytes)
    source_freeze_payload_digest = _sha256_bytes(source_freeze_payload)
    if manifest.get(f"artifacts/{prediction_path}") != source_freeze_payload_digest:
        raise PosteriorLogitFrontierError(
            "source capsule manifest does not bind the prediction freeze"
        )
    if source_freeze_digest != source_prediction_freeze_sha256:
        raise PosteriorLogitFrontierError("source prediction-freeze SHA-256 differs")
    _artifact_entry(
        artifacts,
        source_artifact_path,
        expected_sha256=source_artifact_sha256,
        expected_bytes=len(source_payload),
        field="source prediction tensor",
    )
    _artifact_entry(
        artifacts,
        prediction_path,
        expected_sha256=source_freeze_payload_digest,
        expected_bytes=len(source_freeze_payload),
        field="source prediction freeze",
    )
    freeze_artifacts = _mapping(
        source_freeze.get("artifacts"),
        "source prediction-freeze artifacts",
    )
    _artifact_entry(
        freeze_artifacts,
        source_artifact_path,
        expected_sha256=source_artifact_sha256,
        expected_bytes=len(source_payload),
        field="source freeze prediction tensor",
    )

    source_name = PurePosixPath(source_artifact_path).parts[1]
    if not source_name.startswith("build-"):
        raise AssertionError("validated O1C-0022 source path lost its fold")
    fold_index = int(source_name.removeprefix("build-"))
    target_id = f"build-{fold_index:04d}"
    source_action_pool = _sha256(
        source_freeze.get("held_out_action_pool_sha256"),
        "source held-out action-pool SHA-256",
    )
    if (
        source_freeze.get("fold_index") != fold_index
        or source_freeze.get("held_out_ordinal") != fold_index
        or source_freeze.get("held_out_target_id") != target_id
        or source_freeze.get("active_coordinate_counts") != list(O1C22_WIDTHS)
        or source_freeze.get("prediction_arms") != list(O1C22_ARMS)
        or source_freeze.get("held_out_label_used_for_this_fold") is not False
        or source_freeze.get("held_out_reader_updates") != 0
        or source_freeze.get("solver_calls") != 0
        or source_freeze.get("scientific_entropy_calls") != 0
    ):
        raise PosteriorLogitFrontierError("source prediction lifecycle differs")

    upstream_freeze, upstream_digest = _canonical_freeze(
        upstream_prediction_freeze_payload,
        field="upstream prediction freeze",
        schema=_O1C19_PREDICTION_FREEZE_SCHEMA,
        phase=_O1C19_PREDICTION_FREEZE_PHASE,
    )
    if (
        source_freeze.get("upstream_prediction_freeze_sha256") != upstream_digest
        or upstream_freeze.get("fold_index") != fold_index
        or upstream_freeze.get("held_out_ordinal") != fold_index
        or upstream_freeze.get("target_id") != target_id
        or upstream_freeze.get("action_pool_sha256") != source_action_pool
        or upstream_freeze.get("held_out_labels_materialized") != 0
        or upstream_freeze.get("held_out_reader_updates") != 0
        or upstream_freeze.get("held_out_critic_updates") != 0
    ):
        raise PosteriorLogitFrontierError("upstream prediction lifecycle differs")
    public_view_sha256 = _sha256(
        upstream_freeze.get("public_view_sha256"),
        "upstream public-view SHA-256",
    )
    if public_view_sha256 != public_target.digest():
        raise PosteriorLogitFrontierError(
            "upstream fold is not bound to the supplied public target"
        )
    return _VerifiedSourceLifecycle(
        capsule_manifest_sha256=capsule_digest,
        artifact_index_sha256=index_digest,
        prediction_freeze_sha256=source_freeze_digest,
        upstream_prediction_freeze_sha256=upstream_digest,
        fold_index=fold_index,
        target_id=target_id,
        action_pool_sha256=source_action_pool,
        public_view_sha256=public_view_sha256,
    )


def _require_key_free_freeze(value: object) -> None:
    if isinstance(value, str):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PosteriorLogitFrontierError("freeze receipt keys must be strings")
            lowered = key.lower()
            if lowered in _FORBIDDEN_FREEZE_KEYS or any(
                token in lowered for token in _FORBIDDEN_FREEZE_KEY_FRAGMENTS
            ):
                raise PosteriorLogitFrontierError(
                    "freeze receipt contains a forbidden private-outcome surface"
                )
            _require_key_free_freeze(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            _require_key_free_freeze(item)


def _checked_logits(values: Sequence[float] | np.ndarray) -> np.ndarray:
    try:
        logits = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise PosteriorLogitFrontierError(
            "posterior logits must be finite float64[256]"
        ) from exc
    if logits.shape != (KEY_BITS,) or not bool(np.isfinite(logits).all()):
        raise PosteriorLogitFrontierError(
            "posterior logits must be finite float64[256]"
        )
    result = np.ascontiguousarray(logits, dtype=np.float64).copy()
    result.setflags(write=False)
    return result


def _logit_payload(logits: np.ndarray) -> bytes:
    payload = logits.astype("<f8", copy=False).tobytes(order="C")
    if len(payload) != SELECTED_LOGIT_BYTES:
        raise AssertionError("selected O1C-0022 logit payload width differs")
    return payload


def _exact_absolute_logit_units(
    logits: np.ndarray,
) -> tuple[tuple[int, ...], int]:
    ratios = tuple(abs(float(value)).as_integer_ratio() for value in logits)
    exponents = tuple(denominator.bit_length() - 1 for _, denominator in ratios)
    common_exponent = max(exponents, default=0)
    units = tuple(
        numerator << (common_exponent - exponent)
        for (numerator, _), exponent in zip(ratios, exponents, strict=True)
    )
    return units, common_exponent


def _display_penalty_bits(exact_units: int, unit_exponent: int) -> float:
    try:
        natural_penalty = exact_units / (1 << unit_exponent)
    except OverflowError as exc:
        raise PosteriorLogitFrontierError(
            "displayed logit subset penalty must remain finite"
        ) from exc
    result = natural_penalty / _LN2
    if not math.isfinite(result):
        raise PosteriorLogitFrontierError(
            "displayed logit subset penalty must remain finite"
        )
    return result


def _make_plan(values: Sequence[float] | np.ndarray) -> _LogitPlan:
    logits = _checked_logits(values)
    absolute = np.abs(logits)
    coordinate_units, unit_exponent = _exact_absolute_logit_units(logits)
    _display_penalty_bits(sum(coordinate_units), unit_exponent)
    topology = tuple(
        sorted(
            range(KEY_BITS),
            key=lambda coordinate: (coordinate_units[coordinate], coordinate),
        )
    )
    penalty_units = tuple(coordinate_units[coordinate] for coordinate in topology)
    map_terms = -np.logaddexp(0.0, -absolute) / _LN2
    map_log2_probability = math.fsum(float(value) for value in map_terms)
    if not math.isfinite(map_log2_probability):
        raise PosteriorLogitFrontierError("MAP log2 probability must remain finite")
    return _LogitPlan(
        logits=logits,
        mode_bits=tuple(int(value >= 0.0) for value in logits),
        topology=topology,
        penalty_units=penalty_units,
        coordinate_penalty_units=coordinate_units,
        penalty_unit_exponent=unit_exponent,
        map_log2_probability=map_log2_probability,
    )


def _mask_positions(mask: int) -> Iterator[int]:
    value = mask
    while value:
        least = value & -value
        yield least.bit_length() - 1
        value ^= least


def _iter_exact_subset_states(
    penalty_units: tuple[int, ...],
    limit: int,
) -> Iterator[tuple[int, int, int]]:
    """Yield rank, exact natural-logit penalty units and topology mask."""

    width = len(penalty_units)
    heap: list[tuple[int, int, int]] = [(0, 0, -1)]
    previous: tuple[int, int] | None = None
    for rank in range(1, limit + 1):
        if not heap:
            raise AssertionError("exact logit subset frontier ended early")
        exact_units, mask, last = heapq.heappop(heap)
        order = (exact_units, mask)
        if previous is not None and order < previous:
            raise AssertionError("exact logit subset frontier is not ordered")
        previous = order
        yield rank, exact_units, mask

        next_position = last + 1
        if next_position >= width:
            continue
        add_mask = mask | (1 << next_position)
        heapq.heappush(
            heap,
            (
                exact_units + penalty_units[next_position],
                add_mask,
                next_position,
            ),
        )
        if last >= 0:
            replace_mask = (mask ^ (1 << last)) | (1 << next_position)
            heapq.heappush(
                heap,
                (
                    exact_units - penalty_units[last] + penalty_units[next_position],
                    replace_mask,
                    next_position,
                ),
            )


def select_o1c22_logits(
    payload: bytes,
    width: int = 256,
    arm: str = "quantized_int8_vault",
) -> np.ndarray:
    """Select one immutable float64[256] vector from a pre-oracle O1C-0022 tensor."""

    checked_width = _selected_width(width)
    checked_arm = _selected_arm(arm)
    if not isinstance(payload, bytes) or len(payload) != O1C22_SOURCE_ARTIFACT_BYTES:
        raise PosteriorLogitFrontierError(
            f"O1C-0022 prediction payload must contain exactly "
            f"{O1C22_SOURCE_ARTIFACT_BYTES} bytes"
        )
    tensor = np.frombuffer(payload, dtype="<f8").reshape(O1C22_SOURCE_SHAPE)
    if not bool(np.isfinite(tensor).all()):
        raise PosteriorLogitFrontierError("O1C-0022 prediction tensor is non-finite")
    selected = np.asarray(
        tensor[O1C22_WIDTHS.index(checked_width), O1C22_ARMS.index(checked_arm)],
        dtype=np.float64,
    ).copy()
    if selected.shape != (KEY_BITS,) or selected.nbytes != SELECTED_LOGIT_BYTES:
        raise AssertionError("selected O1C-0022 logit vector differs")
    selected.setflags(write=False)
    return selected


def iter_factorized_logit_topk(
    logits: Sequence[float] | np.ndarray,
    *,
    limit: int,
) -> Iterator[FactorizedLogitFrontierCandidate]:
    """Lazily emit the exact global top-K of a full-width Bernoulli logit field."""

    plan = _make_plan(logits)
    checked_limit = _candidate_limit(limit)

    def generate() -> Iterator[FactorizedLogitFrontierCandidate]:
        for rank, exact_units, mask in _iter_exact_subset_states(
            plan.penalty_units,
            checked_limit,
        ):
            bits = np.asarray(plan.mode_bits, dtype=np.uint8)
            flipped = tuple(
                plan.topology[position] for position in _mask_positions(mask)
            )
            if flipped:
                bits[np.asarray(flipped, dtype=np.int64)] ^= 1
            displayed_penalty = _display_penalty_bits(
                exact_units,
                plan.penalty_unit_exponent,
            )
            yield FactorizedLogitFrontierCandidate(
                rank=rank,
                key=bits_to_key(bits),
                log2_probability=plan.map_log2_probability - displayed_penalty,
                flip_penalty_bits=displayed_penalty,
                exact_penalty_units=exact_units,
                penalty_unit_exponent=plan.penalty_unit_exponent,
                flipped_coordinates=flipped,
                topology_code=mask,
            )

    return generate()


def _validate_logit_candidate(
    candidate: object,
    *,
    expected_rank: int,
    expected_exponent: int | None,
    previous_order: tuple[int, int] | None,
) -> tuple[
    FactorizedLogitFrontierCandidate,
    int,
    tuple[int, int],
]:
    if not isinstance(candidate, FactorizedLogitFrontierCandidate):
        raise PosteriorLogitFrontierError(
            "logit frontier stream contains a foreign candidate"
        )
    if candidate.rank != expected_rank:
        raise PosteriorLogitFrontierError(
            "logit frontier candidate ranks are not contiguous"
        )
    if not isinstance(candidate.key, bytes) or len(candidate.key) != KEY_BYTES:
        raise PosteriorLogitFrontierError("logit frontier candidate key differs")
    if (
        not math.isfinite(candidate.log2_probability)
        or candidate.log2_probability > 0.0
        or not math.isfinite(candidate.flip_penalty_bits)
        or candidate.flip_penalty_bits < 0.0
    ):
        raise PosteriorLogitFrontierError("logit frontier candidate score differs")
    if (
        isinstance(candidate.exact_penalty_units, bool)
        or not isinstance(candidate.exact_penalty_units, int)
        or candidate.exact_penalty_units < 0
        or isinstance(candidate.penalty_unit_exponent, bool)
        or not isinstance(candidate.penalty_unit_exponent, int)
        or not 0 <= candidate.penalty_unit_exponent <= 1074
    ):
        raise PosteriorLogitFrontierError(
            "logit frontier exact penalty representation differs"
        )
    if (
        expected_exponent is not None
        and candidate.penalty_unit_exponent != expected_exponent
    ):
        raise PosteriorLogitFrontierError(
            "logit frontier penalty-unit exponent changed"
        )
    expected_display = _display_penalty_bits(
        candidate.exact_penalty_units,
        candidate.penalty_unit_exponent,
    )
    if candidate.flip_penalty_bits != expected_display:
        raise PosteriorLogitFrontierError(
            "displayed penalty differs from exact logit units"
        )
    if (
        isinstance(candidate.topology_code, bool)
        or not isinstance(candidate.topology_code, int)
        or not 0 <= candidate.topology_code < 1 << KEY_BITS
    ):
        raise PosteriorLogitFrontierError("logit frontier topology code differs")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < KEY_BITS
        for value in candidate.flipped_coordinates
    ) or len(candidate.flipped_coordinates) != len(set(candidate.flipped_coordinates)):
        raise PosteriorLogitFrontierError("logit frontier flipped coordinates differ")
    if candidate.topology_code.bit_count() != len(candidate.flipped_coordinates):
        raise PosteriorLogitFrontierError("logit frontier topology population differs")
    if expected_rank == 1 and (
        candidate.exact_penalty_units != 0
        or candidate.topology_code != 0
        or candidate.flipped_coordinates
    ):
        raise PosteriorLogitFrontierError("logit frontier MAP candidate differs")
    order = (candidate.exact_penalty_units, candidate.topology_code)
    if previous_order is not None and order < previous_order:
        raise PosteriorLogitFrontierError(
            "logit frontier candidates are not exactly ordered"
        )
    return candidate, candidate.penalty_unit_exponent, order


def _candidate_matches_public_target(
    candidate_key: bytes,
    target: PublicTargetView,
) -> bool:
    return all(
        chacha20_block_trace(candidate_key, counter, target.nonce).output == expected
        for counter, expected in zip(
            target.counter_schedule,
            target.output_blocks,
            strict=True,
        )
    )


def verify_logit_frontier_against_public_target(
    target: PublicTargetView,
    candidates: Iterable[FactorizedLogitFrontierCandidate],
    *,
    stop_on_first_match: bool = True,
    maximum_candidates: int | None = None,
) -> dict[str, object]:
    """Verify an exactly ordered logit frontier using public ChaCha20 output."""

    if not isinstance(target, PublicTargetView):
        raise PosteriorLogitFrontierError("target must be a PublicTargetView")
    try:
        target.validate()
    except ValueError as exc:
        raise PosteriorLogitFrontierError("public target differs") from exc
    if not isinstance(stop_on_first_match, bool):
        raise PosteriorLogitFrontierError("stop_on_first_match must be boolean")
    if maximum_candidates is not None and (
        isinstance(maximum_candidates, bool)
        or not isinstance(maximum_candidates, int)
        or maximum_candidates < 1
    ):
        raise PosteriorLogitFrontierError("maximum_candidates must be positive")

    bounded = (
        candidates
        if maximum_candidates is None
        else islice(candidates, maximum_candidates)
    )
    digest = hashlib.sha256(b"o1-256-factorized-logit-topk-verified-stream-v1\0")
    count = 0
    match_count = 0
    first_match_rank: int | None = None
    first_match_key: bytes | None = None
    previous_order: tuple[int, int] | None = None
    exponent: int | None = None
    stopped_on_match = False
    for expected_rank, raw in enumerate(bounded, start=1):
        candidate, exponent, previous_order = _validate_logit_candidate(
            raw,
            expected_rank=expected_rank,
            expected_exponent=exponent,
            previous_order=previous_order,
        )
        count = expected_rank
        digest.update(canonical_json_bytes(candidate.describe()))
        if _candidate_matches_public_target(candidate.key, target):
            match_count += 1
            if first_match_rank is None:
                first_match_rank = candidate.rank
                first_match_key = candidate.key
            if stop_on_first_match:
                stopped_on_match = True
                break
    if count == 0 or exponent is None:
        raise PosteriorLogitFrontierError("logit frontier candidate stream is empty")
    limit_reached = (
        maximum_candidates is not None
        and count == maximum_candidates
        and not stopped_on_match
    )
    return {
        "schema": LOGIT_FRONTIER_VERIFICATION_SCHEMA,
        "public_target_sha256": target.digest(),
        "candidate_stream_sha256": digest.hexdigest(),
        "candidates_verified": count,
        "exact_match_found": first_match_rank is not None,
        "exact_match_count": match_count,
        "first_match_rank_one_based": first_match_rank,
        "first_match_key_hex": first_match_key.hex() if first_match_key else None,
        "stopped_on_first_match": stopped_on_match,
        "verification_limit_reached": limit_reached,
        "penalty_unit_exponent": exponent,
        "tie_policy": LOGIT_TOPOLOGY_TIE_POLICY,
    }


def factorized_logit_diagnostics(
    logits: Sequence[float] | np.ndarray,
) -> dict[str, object]:
    """Return entropy and MAP diagnostics without accepting or deriving truth."""

    plan = _make_plan(logits)
    absolute = np.abs(plan.logits)
    tail_exponent = np.exp(-absolute)
    tail_probability = tail_exponent / (1.0 + tail_exponent)
    entropy_terms = (np.log1p(tail_exponent) + absolute * tail_probability) / _LN2
    entropy_bits = math.fsum(float(value) for value in entropy_terms)
    domain_compression = KEY_BITS - entropy_bits
    map_key = bits_to_key(np.asarray(plan.mode_bits, dtype=np.uint8))
    payload = _logit_payload(plan.logits)
    penalties = np.asarray(
        [
            _display_penalty_bits(value, plan.penalty_unit_exponent)
            for value in plan.coordinate_penalty_units
        ],
        dtype=np.float64,
    )
    return {
        "schema": LOGIT_DIAGNOSTICS_SCHEMA,
        "key_bits": KEY_BITS,
        "posterior_logits_sha256": _sha256_bytes(payload),
        "posterior_logits_bytes": len(payload),
        "logit_semantics": _LOGIT_SEMANTICS,
        "coordinate_order": _COORDINATE_ORDER,
        "factorized_entropy_bits": entropy_bits,
        "effective_domain_compression_bits": domain_compression,
        "map_log2_probability": plan.map_log2_probability,
        "map_probability": 2.0**plan.map_log2_probability,
        "map_key_hex": map_key.hex(),
        "map_key_sha256": _sha256_bytes(map_key),
        "map_one_bits": int(sum(plan.mode_bits)),
        "map_zero_bits": KEY_BITS - int(sum(plan.mode_bits)),
        "zero_logit_coordinates": int(np.count_nonzero(plan.logits == 0.0)),
        "minimum_logit": float(plan.logits.min()),
        "maximum_logit": float(plan.logits.max()),
        "maximum_absolute_logit": float(absolute.max()),
        "minimum_flip_penalty_bits": float(penalties.min()),
        "maximum_flip_penalty_bits": float(penalties.max()),
        "mean_flip_penalty_bits": float(penalties.mean()),
        "penalty_unit_exponent": plan.penalty_unit_exponent,
        "tie_policy": LOGIT_TOPOLOGY_TIE_POLICY,
        "truth_reads": 0,
        "label_reads": 0,
        "truth_used": False,
    }


def make_logit_frontier_freeze(
    logits: Sequence[float] | np.ndarray,
    *,
    source_payload: bytes,
    source_capsule_manifest_payload: bytes,
    source_artifact_index_payload: bytes,
    source_prediction_freeze_payload: bytes,
    upstream_prediction_freeze_payload: bytes,
    source_artifact_sha256: str,
    source_prediction_freeze_sha256: str,
    source_artifact_path: str,
    source_artifact_bytes: int,
    source_capsule_manifest_sha256: str,
    source_artifact_index_sha256: str,
    public_target: PublicTargetView,
    candidate_limit: int,
    selected_width: int = 256,
    selected_arm: str = "quantized_int8_vault",
    source_shape: Sequence[int] = O1C22_SOURCE_SHAPE,
) -> dict[str, object]:
    """Create a canonical truth-free receipt for one selected O1C-0022 posterior."""

    plan = _make_plan(logits)
    checked_limit = _candidate_limit(candidate_limit)
    if checked_limit != _FORMAL_CANDIDATE_LIMIT:
        raise PosteriorLogitFrontierError(
            f"frontier freeze requires candidate_limit={_FORMAL_CANDIDATE_LIMIT}"
        )
    checked_width = _selected_width(selected_width)
    checked_arm = _selected_arm(selected_arm)
    if checked_width != KEY_BITS:
        raise PosteriorLogitFrontierError(
            "frontier freeze requires the complete 256-coordinate O1C-0022 field"
        )
    if checked_arm != "quantized_int8_vault":
        raise PosteriorLogitFrontierError(
            "frontier freeze requires the frozen quantized_int8_vault arm"
        )
    checked_shape = _source_shape(source_shape)
    checked_path = _source_path(source_artifact_path)
    if (
        not isinstance(source_payload, bytes)
        or len(source_payload) != O1C22_SOURCE_ARTIFACT_BYTES
        or isinstance(source_artifact_bytes, bool)
        or not isinstance(source_artifact_bytes, int)
        or source_artifact_bytes != O1C22_SOURCE_ARTIFACT_BYTES
        or source_artifact_bytes != len(source_payload)
    ):
        raise PosteriorLogitFrontierError(
            f"source artifact must contain exactly {O1C22_SOURCE_ARTIFACT_BYTES} bytes"
        )
    artifact_sha256 = _sha256(source_artifact_sha256, "source artifact SHA-256")
    if _sha256_bytes(source_payload) != artifact_sha256:
        raise PosteriorLogitFrontierError("source artifact SHA-256 differs")
    source_selected = select_o1c22_logits(
        source_payload,
        width=checked_width,
        arm=checked_arm,
    )
    selected_payload = _logit_payload(plan.logits)
    if selected_payload != _logit_payload(source_selected):
        raise PosteriorLogitFrontierError(
            "selected logits differ from the frozen source artifact slice"
        )
    prediction_sha256 = _sha256(
        source_prediction_freeze_sha256,
        "source prediction-freeze SHA-256",
    )
    capsule_sha256 = _sha256(
        source_capsule_manifest_sha256,
        "source capsule-manifest SHA-256",
    )
    artifact_index_sha256 = _sha256(
        source_artifact_index_sha256,
        "source artifact-index SHA-256",
    )
    if not isinstance(public_target, PublicTargetView):
        raise PosteriorLogitFrontierError("public_target must be a PublicTargetView")
    try:
        public_target.validate()
    except ValueError as exc:
        raise PosteriorLogitFrontierError("public target differs") from exc
    lifecycle = _verify_source_lifecycle(
        source_payload=source_payload,
        source_artifact_path=checked_path,
        source_artifact_sha256=artifact_sha256,
        source_capsule_manifest_payload=source_capsule_manifest_payload,
        source_capsule_manifest_sha256=capsule_sha256,
        source_artifact_index_payload=source_artifact_index_payload,
        source_artifact_index_sha256=artifact_index_sha256,
        source_prediction_freeze_payload=source_prediction_freeze_payload,
        source_prediction_freeze_sha256=prediction_sha256,
        upstream_prediction_freeze_payload=upstream_prediction_freeze_payload,
        public_target=public_target,
    )

    complete_diagnostics = factorized_logit_diagnostics(plan.logits)
    diagnostics = {
        key: complete_diagnostics[key]
        for key in (
            "schema",
            "posterior_logits_sha256",
            "posterior_logits_bytes",
            "factorized_entropy_bits",
            "effective_domain_compression_bits",
            "map_log2_probability",
            "maximum_absolute_logit",
            "penalty_unit_exponent",
            "truth_reads",
            "label_reads",
        )
    }
    unsigned: dict[str, object] = {
        "schema": LOGIT_FRONTIER_FREEZE_SCHEMA,
        "phase": LOGIT_FRONTIER_FREEZE_PHASE,
        "source_capsule_manifest_sha256": capsule_sha256,
        "source_artifact_index_sha256": artifact_index_sha256,
        "source_prediction_freeze_sha256": prediction_sha256,
        "upstream_prediction_freeze_sha256": (
            lifecycle.upstream_prediction_freeze_sha256
        ),
        "source_fold_index": lifecycle.fold_index,
        "source_target_id": lifecycle.target_id,
        "source_action_pool_sha256": lifecycle.action_pool_sha256,
        "upstream_public_view_sha256": lifecycle.public_view_sha256,
        "source_artifact_path": checked_path,
        "source_artifact_sha256": artifact_sha256,
        "source_artifact_bytes": source_artifact_bytes,
        "source_shape": list(checked_shape),
        "selected_width": checked_width,
        "selected_width_index": O1C22_WIDTHS.index(checked_width),
        "selected_arm": checked_arm,
        "selected_arm_index": O1C22_ARMS.index(checked_arm),
        "selected_shape": [KEY_BITS],
        "selected_logits_encoding": "float64 little-endian",
        "selected_logits_bytes": len(selected_payload),
        "selected_logits_sha256": _sha256_bytes(selected_payload),
        "logit_semantics": _LOGIT_SEMANTICS,
        "coordinate_order": _COORDINATE_ORDER,
        "public_target_sha256": public_target.digest(),
        "candidate_limit": checked_limit,
        "penalty_unit_exponent": plan.penalty_unit_exponent,
        "tie_policy": LOGIT_TOPOLOGY_TIE_POLICY,
        "decoder_runtime_inputs": ["posterior_logits", "candidate_limit"],
        "diagnostics": diagnostics,
        "truth_reads": 0,
        "label_reads": 0,
        "truth_used_for_generation": False,
    }
    _require_key_free_freeze(unsigned)
    return {
        **unsigned,
        "freeze_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


__all__ = [
    "FactorizedLogitFrontierCandidate",
    "LOGIT_DIAGNOSTICS_SCHEMA",
    "LOGIT_FRONTIER_CANDIDATE_SCHEMA",
    "LOGIT_FRONTIER_FREEZE_PHASE",
    "LOGIT_FRONTIER_FREEZE_SCHEMA",
    "LOGIT_FRONTIER_VERIFICATION_SCHEMA",
    "LOGIT_TOPOLOGY_TIE_POLICY",
    "O1C22_ARMS",
    "O1C22_SOURCE_ARTIFACT_BYTES",
    "O1C22_SOURCE_SHAPE",
    "O1C22_WIDTHS",
    "PosteriorLogitFrontierError",
    "SELECTED_LOGIT_BYTES",
    "factorized_logit_diagnostics",
    "iter_factorized_logit_topk",
    "make_logit_frontier_freeze",
    "select_o1c22_logits",
    "verify_logit_frontier_against_public_target",
]
