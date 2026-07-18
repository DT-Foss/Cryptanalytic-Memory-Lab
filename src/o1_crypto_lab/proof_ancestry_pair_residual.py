"""Bounded projected proof-ancestry pair reader for the O1C-0026 proxy.

The raw FAP contains public branch summaries, not raw antecedent pairs.  This
module therefore exposes one deliberately narrow bilinear proxy.  It promotes
the stored float32 values to binary64, applies a bounded odd/even decomposition,
and projects ``ancestry_touch x proof_context`` into 768 deterministic features.

No API accepts a target key, reveal, development pool, solver, or entropy
source.  Projection is row-streamable.  A deployment state retains only one
effective float64[768] weight vector and one float64[256] posterior: exactly
8 KiB, independent of stream length.
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

import numpy as np

from .full256_action_pool import (
    BRANCH_FEATURES,
    KEY_TOUCH_FEATURES,
    MOTIF_DIMENSIONS,
    SCALAR_FEATURES,
    Full256ActionPool,
)
from .living_inverse import canonical_json_bytes
from .o1c22_postresult_composer import (
    OPERATOR_GRAPH_SCHEMA,
    O1C22PostResultComposerError,
    next_operator_graph,
    verify_decision,
)


PROJECTION_SCHEMA: Final = "o1-256-proof-ancestry-pair-projection-policy-v1"
SELECTION_RECEIPT_SCHEMA: Final = "o1-256-o1c26-selection-receipt-v1"
SELECTED_OPERATOR_ID: Final = "proof_ancestry_pair_residual_v1"
PROXY_OPERATOR_ID: Final = "fap_ancestry_touch_bilinear_proxy_v2"

EXPECTED_HORIZONS: Final = (64, 96, 65)
CONTEXT_COLUMNS: Final = (6, 7, 9, *range(10, 74))
TOUCH_COLUMN_START: Final = SCALAR_FEATURES + MOTIF_DIMENSIONS
TOUCH_BUCKETS: Final = 16
OFF_DIAGONAL_TOUCH_BUCKETS: Final = TOUCH_BUCKETS - 1
CONTEXT_BUCKETS: Final = 8
FEATURE_WIDTH: Final = len(EXPECTED_HORIZONS) * 2 * TOUCH_BUCKETS * CONTEXT_BUCKETS

PRIMARY_ARM: Final = "primary"
PAIR_SHUFFLE_ARM: Final = "pair_identity_shuffled"
ADDITIVE_ARM: Final = "additive_factorized_matched"
COMMON_MODE_ARM: Final = "polarity_even_common_mode"
LEARNED_ARMS: Final = (
    PRIMARY_ARM,
    PAIR_SHUFFLE_ARM,
    ADDITIVE_ARM,
    COMMON_MODE_ARM,
)

NO_EXACT_CONFLICT_ABLATION: Final = "without_exact_conflict"
NO_MOTIF_ABLATION: Final = "without_motif"
OFF_DIAGONAL_ONLY_ABLATION: Final = "off_diagonal_only"
SELF_ONLY_ABLATION: Final = "self_only"
DIAGNOSTIC_ABLATIONS: Final = (
    NO_EXACT_CONFLICT_ABLATION,
    NO_MOTIF_ABLATION,
    OFF_DIAGONAL_ONLY_ABLATION,
    SELF_ONLY_ABLATION,
)

ALPHA_GRID: Final = tuple(index / 200.0 for index in range(401))
WEIGHT_BYTES: Final = FEATURE_WIDTH * np.dtype(np.float64).itemsize
POSTERIOR_BYTES: Final = KEY_TOUCH_FEATURES * np.dtype(np.float64).itemsize
LIVE_STATE_BYTES: Final = WEIGHT_BYTES + POSTERIOR_BYTES
NUMERIC_SCRATCH_BYTES: Final = (
    2 * WEIGHT_BYTES
    + (2 * TOUCH_BUCKETS + 2 * CONTEXT_BUCKETS) * np.dtype(np.float64).itemsize
)

_TOUCH_DOMAIN: Final = b"o1c26/touch-sketch/v2\0"
_CONTEXT_DOMAIN: Final = b"o1c26/context-sketch/v2\0"
_PAIR_SHUFFLE_DOMAIN: Final = b"o1c26/pair-shuffle/v2\0"
_SQRT_TOUCHES: Final = math.sqrt(KEY_TOUCH_FEATURES)
_SQRT_CONTEXT_COLUMNS: Final = math.sqrt(len(CONTEXT_COLUMNS))
_SQRT_ADDITIVE_TOUCH_REPETITIONS: Final = math.sqrt(CONTEXT_BUCKETS)
_SQRT_ADDITIVE_CONTEXT_REPETITIONS: Final = math.sqrt(TOUCH_BUCKETS)
_SQRT_COMMON_MODE_COPIES: Final = math.sqrt(2.0)
_HEX: Final = frozenset("0123456789abcdef")


class ProofAncestryPairResidualError(ValueError):
    """A projection, model, selection, or bounded-state invariant differs."""


@dataclass(frozen=True)
class OffsetRidgeFit:
    """One deterministic offset-aware ridge fit before alpha calibration."""

    weights: np.ndarray
    regularization: float
    training_rows: int

    def predict(self, features: np.ndarray) -> np.ndarray:
        matrix = _feature_matrix(features, "features")
        result = _finite_matmul(matrix, self.weights, "ridge prediction")
        return _frozen_float64(result)


@dataclass(frozen=True)
class FrozenOuterFoldPrediction:
    """One truth-free outer prediction with alpha folded into its weights."""

    effective_weights: np.ndarray
    alpha: float
    inner_raw_predictions: np.ndarray
    held_out_logits: np.ndarray
    regularizations: tuple[float, float, float, float]
    ridge_fits: int
    alpha_bit_evaluations: int

    @property
    def effective_weight_bytes(self) -> bytes:
        return self.effective_weights.astype("<f8", copy=False).tobytes(order="C")


@dataclass(frozen=True)
class O1C26SelectionReceipt:
    """Source-level receipt; capsule authority remains a run-layer obligation."""

    decision_sha256: str
    operator_graph_sha256: str
    source_capsule_manifest_sha256: str
    source_result_sha256: str
    operator_fingerprint: str

    def describe(self) -> dict[str, object]:
        return {
            "schema": SELECTION_RECEIPT_SCHEMA,
            "selected_operator_id": SELECTED_OPERATOR_ID,
            "proxy_operator_id": PROXY_OPERATOR_ID,
            "decision_sha256": self.decision_sha256,
            "operator_graph_sha256": self.operator_graph_sha256,
            "source_capsule_manifest_sha256": self.source_capsule_manifest_sha256,
            "source_result_sha256": self.source_result_sha256,
            "operator_fingerprint": self.operator_fingerprint,
            "authoritative_capsule_verified": False,
            "attempt_reservation_authorized": False,
        }


def _frozen_float64(
    value: object, *, shape: tuple[int, ...] | None = None
) -> np.ndarray:
    raw = np.asarray(value)
    if shape is not None and raw.shape != shape:
        raise ProofAncestryPairResidualError(f"array shape must equal {shape}")
    if not np.issubdtype(raw.dtype, np.number):
        raise ProofAncestryPairResidualError("array must be numeric")
    contiguous = np.asarray(raw, dtype=np.float64, order="C")
    if not np.all(np.isfinite(contiguous)):
        raise ProofAncestryPairResidualError("array must be finite")
    payload = contiguous.tobytes(order="C")
    return np.frombuffer(payload, dtype=np.float64).reshape(contiguous.shape)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _finite_matmul(left: np.ndarray, right: np.ndarray, field: str) -> np.ndarray:
    # Accelerate/OpenBLAS can leave benign IEEE status flags set after GEMM.
    # Suppress flag-to-warning translation, then enforce the actual invariant.
    with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
        result = np.asarray(np.matmul(left, right))
    if not np.all(np.isfinite(result)):
        raise ProofAncestryPairResidualError(f"{field} is non-finite")
    return result


def _checked_sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ProofAncestryPairResidualError(f"{field} must be lowercase SHA-256")
    return value


def _coordinate(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < KEY_TOUCH_FEATURES
    ):
        raise ProofAncestryPairResidualError("coordinate must be in [0,255]")
    return value


def _horizon_index(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < len(EXPECTED_HORIZONS)
    ):
        raise ProofAncestryPairResidualError("horizon index must be in [0,2]")
    return value


def _packed_address(horizon_index: int, coordinate: int, source: int) -> bytes:
    return struct.pack(">HHH", horizon_index, coordinate, source)


def _projection_digest(
    domain: bytes,
    horizon_index: int,
    coordinate: int,
    source: int,
) -> bytes:
    return hashlib.sha256(
        domain + _packed_address(horizon_index, coordinate, source)
    ).digest()


@lru_cache(maxsize=None)
def touch_projection_table(
    horizon_index: int,
    coordinate: int,
) -> tuple[tuple[int, int], ...]:
    """Return `(bucket, sign)` for each destination touch coordinate."""

    horizon_index = _horizon_index(horizon_index)
    coordinate = _coordinate(coordinate)
    result: list[tuple[int, int]] = []
    for destination in range(KEY_TOUCH_FEATURES):
        digest = _projection_digest(
            _TOUCH_DOMAIN,
            horizon_index,
            coordinate,
            destination,
        )
        if destination == coordinate:
            result.append((0, 1 if digest[1] % 2 == 0 else -1))
            continue
        result.append(
            (
                1 + digest[0] % OFF_DIAGONAL_TOUCH_BUCKETS,
                1 if digest[1] % 2 == 0 else -1,
            )
        )
    return tuple(result)


@lru_cache(maxsize=None)
def context_projection_table(
    horizon_index: int,
    coordinate: int,
) -> tuple[tuple[int, int], ...]:
    """Return `(bucket, sign)` in exact `CONTEXT_COLUMNS` order."""

    horizon_index = _horizon_index(horizon_index)
    coordinate = _coordinate(coordinate)
    result: list[tuple[int, int]] = []
    for source_column in CONTEXT_COLUMNS:
        digest = _projection_digest(
            _CONTEXT_DOMAIN,
            horizon_index,
            coordinate,
            source_column,
        )
        result.append((digest[0] % CONTEXT_BUCKETS, 1 if digest[1] % 2 == 0 else -1))
    return tuple(result)


@lru_cache(maxsize=None)
def pair_shuffle_sources(
    horizon_index: int,
    coordinate: int,
) -> tuple[int, ...]:
    """Return source-at-destination for the fixed-point-free pair control."""

    horizon_index = _horizon_index(horizon_index)
    coordinate = _coordinate(coordinate)
    ordered = sorted(
        range(KEY_TOUCH_FEATURES),
        key=lambda source: (
            _projection_digest(
                _PAIR_SHUFFLE_DOMAIN,
                horizon_index,
                coordinate,
                source,
            ),
            source,
        ),
    )
    source_at_destination = [-1] * KEY_TOUCH_FEATURES
    for index, source in enumerate(ordered):
        destination = ordered[(index + 1) % KEY_TOUCH_FEATURES]
        source_at_destination[destination] = source
    result = tuple(source_at_destination)
    if sorted(result) != list(range(KEY_TOUCH_FEATURES)) or any(
        source == destination for destination, source in enumerate(result)
    ):
        raise AssertionError("pair shuffle is not a fixed-point-free permutation")
    return result


def projection_policy() -> dict[str, object]:
    """Describe the complete result-independent projection ABI."""

    return {
        "schema": PROJECTION_SCHEMA,
        "proxy_operator_id": PROXY_OPERATOR_ID,
        "selected_parent_operator_id": SELECTED_OPERATOR_ID,
        "horizons_in_raw_fap_order": list(EXPECTED_HORIZONS),
        "input_shape": [3, 256, 2, BRANCH_FEATURES],
        "input_dtype": "float32le_promoted_to_binary64_before_psi",
        "context_columns": list(CONTEXT_COLUMNS),
        "touch_columns_half_open": [TOUCH_COLUMN_START, BRANCH_FEATURES],
        "touch_buckets": TOUCH_BUCKETS,
        "context_buckets": CONTEXT_BUCKETS,
        "feature_width": FEATURE_WIDTH,
        "feature_order": (
            "horizon-major; odd_touch_outer_even_context then "
            "even_touch_outer_odd_context; C-order touch-major"
        ),
        "domains_hex": {
            "touch": _TOUCH_DOMAIN.hex(),
            "context": _CONTEXT_DOMAIN.hex(),
            "pair_shuffle": _PAIR_SHUFFLE_DOMAIN.hex(),
        },
        "address_suffix": "struct.pack('>HHH', horizon_index, coordinate, source)",
        "horizon_index_origin": 0,
        "sign": "digest_byte_1_even_is_plus_one_odd_is_minus_one",
        "self_lane": {
            "bucket": 0,
            "sign": "digest_byte_1_parity",
            "semantic": "assumed_coordinate_touch_times_proof_context_only",
        },
        "off_diagonal_touch": {
            "buckets": [1, 16],
            "bucket_rule": "1 + digest_byte_0_mod_15",
        },
        "touch_normalization": "complete_16d_sketch_divided_by_sqrt(256)",
        "context_normalization": "sqrt(67)",
        "learned_arms": list(LEARNED_ARMS),
        "diagnostic_ablations": list(DIAGNOSTIC_ABLATIONS),
        "alpha_grid": {"minimum": 0.0, "maximum": 2.0, "points": 401},
        "ridge": {
            "scale_squared": "sum(X*X)/768",
            "standardized_regularization": 1.0,
            "zero_scale_prediction": 0.0,
        },
        "effective_weight_bytes": WEIGHT_BYTES,
        "posterior_bytes": POSTERIOR_BYTES,
        "live_state_bytes": LIVE_STATE_BYTES,
        "numeric_scratch_bytes": NUMERIC_SCRATCH_BYTES,
        "fresh_targets": 0,
        "solver_branches": 0,
        "entropy_calls": 0,
    }


def projection_policy_sha256() -> str:
    return _sha256(canonical_json_bytes(projection_policy()))


def _checked_pool(pool: object) -> Full256ActionPool:
    if not isinstance(pool, Full256ActionPool):
        raise ProofAncestryPairResidualError("pool must be Full256ActionPool")
    if (
        pool.horizons != EXPECTED_HORIZONS
        or pool.branch_features.shape
        != (len(EXPECTED_HORIZONS), KEY_TOUCH_FEATURES, 2, BRANCH_FEATURES)
        or pool.branch_features.dtype != np.float32
    ):
        raise ProofAncestryPairResidualError(
            "pool must use exact raw FAP ABI float32[3,256,2,330] "
            "with horizons (64,96,65)"
        )
    return pool


def _odd_even(branch_zero: np.float32, branch_one: np.float32) -> tuple[float, float]:
    zero = float(branch_zero)
    one = float(branch_one)
    bounded_zero = zero / (1.0 + abs(zero))
    bounded_one = one / (1.0 + abs(one))
    return (0.5 * (bounded_one - bounded_zero), 0.5 * (bounded_one + bounded_zero))


def _arm(value: object) -> str:
    if not isinstance(value, str) or value not in LEARNED_ARMS:
        raise ProofAncestryPairResidualError(f"arm must be one of {LEARNED_ARMS}")
    return value


def _ablation(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in DIAGNOSTIC_ABLATIONS:
        raise ProofAncestryPairResidualError(
            f"ablation must be one of {DIAGNOSTIC_ABLATIONS}"
        )
    return value


def project_coordinate(
    pool: Full256ActionPool,
    coordinate: int,
    *,
    arm: str = PRIMARY_ARM,
    ablation: str | None = None,
) -> np.ndarray:
    """Project one coordinate without retaining its FAP row or sketches."""

    checked = _checked_pool(pool)
    coordinate = _coordinate(coordinate)
    arm = _arm(arm)
    ablation = _ablation(ablation)
    if ablation is not None and arm != PRIMARY_ARM:
        raise ProofAncestryPairResidualError(
            "diagnostic ablations apply only to the frozen primary arm"
        )

    row = np.empty(FEATURE_WIDTH, dtype=np.float64)
    cursor = 0
    for horizon_index in range(len(EXPECTED_HORIZONS)):
        odd_touch = np.zeros(TOUCH_BUCKETS, dtype=np.float64)
        even_touch = np.zeros(TOUCH_BUCKETS, dtype=np.float64)
        odd_context = np.zeros(CONTEXT_BUCKETS, dtype=np.float64)
        even_context = np.zeros(CONTEXT_BUCKETS, dtype=np.float64)

        touch_table = touch_projection_table(horizon_index, coordinate)
        if arm == PAIR_SHUFFLE_ARM:
            sources = pair_shuffle_sources(horizon_index, coordinate)
        else:
            sources = tuple(range(KEY_TOUCH_FEATURES))
        for destination, source in enumerate(sources):
            column = TOUCH_COLUMN_START + source
            odd, even = _odd_even(
                checked.branch_features[horizon_index, coordinate, 0, column],
                checked.branch_features[horizon_index, coordinate, 1, column],
            )
            bucket, sign = touch_table[destination]
            odd_touch[bucket] += sign * odd
            even_touch[bucket] += sign * even

        odd_touch /= _SQRT_TOUCHES
        even_touch /= _SQRT_TOUCHES

        context_table = context_projection_table(horizon_index, coordinate)
        for context_index, column in enumerate(CONTEXT_COLUMNS):
            if (
                ablation == NO_EXACT_CONFLICT_ABLATION and column == SCALAR_FEATURES - 1
            ) or (
                ablation == NO_MOTIF_ABLATION
                and SCALAR_FEATURES <= column < TOUCH_COLUMN_START
            ):
                continue
            odd, even = _odd_even(
                checked.branch_features[horizon_index, coordinate, 0, column],
                checked.branch_features[horizon_index, coordinate, 1, column],
            )
            bucket, sign = context_table[context_index]
            odd_context[bucket] += sign * odd / _SQRT_CONTEXT_COLUMNS
            even_context[bucket] += sign * even / _SQRT_CONTEXT_COLUMNS

        if ablation == OFF_DIAGONAL_ONLY_ABLATION:
            odd_touch[0] = 0.0
            even_touch[0] = 0.0
        elif ablation == SELF_ONLY_ABLATION:
            odd_touch[1:] = 0.0
            even_touch[1:] = 0.0

        for touch_bucket in range(TOUCH_BUCKETS):
            for context_bucket in range(CONTEXT_BUCKETS):
                if arm in (PRIMARY_ARM, PAIR_SHUFFLE_ARM):
                    value = odd_touch[touch_bucket] * even_context[context_bucket]
                elif arm == ADDITIVE_ARM:
                    value = odd_touch[touch_bucket] / _SQRT_ADDITIVE_TOUCH_REPETITIONS
                else:
                    value = (
                        even_touch[touch_bucket]
                        * even_context[context_bucket]
                        / _SQRT_COMMON_MODE_COPIES
                    )
                row[cursor] = value
                cursor += 1
        for touch_bucket in range(TOUCH_BUCKETS):
            for context_bucket in range(CONTEXT_BUCKETS):
                if arm in (PRIMARY_ARM, PAIR_SHUFFLE_ARM):
                    value = even_touch[touch_bucket] * odd_context[context_bucket]
                elif arm == ADDITIVE_ARM:
                    value = (
                        odd_context[context_bucket] / _SQRT_ADDITIVE_CONTEXT_REPETITIONS
                    )
                else:
                    checkerboard = (
                        1.0 if (touch_bucket + context_bucket) % 2 == 0 else -1.0
                    )
                    value = (
                        checkerboard
                        * even_touch[touch_bucket]
                        * even_context[context_bucket]
                        / _SQRT_COMMON_MODE_COPIES
                    )
                row[cursor] = value
                cursor += 1

    if cursor != FEATURE_WIDTH or not np.all(np.isfinite(row)):
        raise ProofAncestryPairResidualError("projected row is invalid")
    row[row == 0.0] = 0.0
    return _frozen_float64(row, shape=(FEATURE_WIDTH,))


def iter_projected_rows(
    pool: Full256ActionPool,
    *,
    arm: str = PRIMARY_ARM,
    ablation: str | None = None,
) -> Iterator[tuple[int, np.ndarray]]:
    """Yield one immutable row at a time; no matrix is retained."""

    checked = _checked_pool(pool)
    arm = _arm(arm)
    ablation = _ablation(ablation)
    for coordinate in range(KEY_TOUCH_FEATURES):
        yield (
            coordinate,
            project_coordinate(
                checked,
                coordinate,
                arm=arm,
                ablation=ablation,
            ),
        )


def project_pool(
    pool: Full256ActionPool,
    *,
    arm: str = PRIMARY_ARM,
    ablation: str | None = None,
) -> np.ndarray:
    """Materialize the retrospective audit matrix, never deployment state."""

    rows = np.empty((KEY_TOUCH_FEATURES, FEATURE_WIDTH), dtype=np.float64)
    for coordinate, row in iter_projected_rows(pool, arm=arm, ablation=ablation):
        rows[coordinate] = row
    return _frozen_float64(rows, shape=(KEY_TOUCH_FEATURES, FEATURE_WIDTH))


def _feature_matrix(value: object, field: str) -> np.ndarray:
    matrix = np.asarray(value)
    if (
        matrix.ndim != 2
        or matrix.shape[1] != FEATURE_WIDTH
        or matrix.shape[0] < 1
        or matrix.dtype != np.float64
        or not np.all(np.isfinite(matrix))
    ):
        raise ProofAncestryPairResidualError(
            f"{field} must be finite float64[N,{FEATURE_WIDTH}]"
        )
    return matrix


def _vector(value: object, field: str, length: int) -> np.ndarray:
    vector = np.asarray(value)
    if (
        vector.shape != (length,)
        or vector.dtype != np.float64
        or not np.all(np.isfinite(vector))
    ):
        raise ProofAncestryPairResidualError(
            f"{field} must be finite float64[{length}]"
        )
    return vector


def _labels(value: object, length: int) -> np.ndarray:
    labels = _vector(value, "labels", length)
    if not np.all(np.logical_or(labels == -1.0, labels == 1.0)):
        raise ProofAncestryPairResidualError("labels must contain only -1 and +1")
    return labels


def fit_offset_ridge(
    features: np.ndarray,
    labels: np.ndarray,
    offsets: np.ndarray,
) -> OffsetRidgeFit:
    """Fit the frozen dual-form ridge residual in binary64."""

    matrix = _feature_matrix(features, "features")
    row_count = matrix.shape[0]
    checked_labels = _labels(labels, row_count)
    checked_offsets = _vector(offsets, "offsets", row_count)
    residual = checked_labels - np.tanh(checked_offsets / 2.0)
    regularization = float(np.sum(np.square(matrix), dtype=np.float64)) / FEATURE_WIDTH
    if regularization == 0.0:
        return OffsetRidgeFit(
            weights=_frozen_float64(np.zeros(FEATURE_WIDTH, dtype=np.float64)),
            regularization=0.0,
            training_rows=row_count,
        )
    feature_scale = math.sqrt(regularization)
    standardized = matrix / feature_scale
    gram = _finite_matmul(
        standardized,
        standardized.T,
        "standardized ridge Gram matrix",
    )
    gram = 0.5 * (gram + gram.T)
    gram.flat[:: row_count + 1] += 1.0
    try:
        dual = np.linalg.solve(gram, residual)
    except np.linalg.LinAlgError as exc:
        raise ProofAncestryPairResidualError("offset ridge solve failed") from exc
    standardized_weights = _finite_matmul(
        standardized.T,
        dual,
        "standardized ridge weights",
    )
    weights = standardized_weights / feature_scale
    if not np.all(np.isfinite(weights)):
        raise ProofAncestryPairResidualError("offset ridge weights are non-finite")
    weights[weights == 0.0] = 0.0
    return OffsetRidgeFit(
        weights=_frozen_float64(weights, shape=(FEATURE_WIDTH,)),
        regularization=regularization,
        training_rows=row_count,
    )


def select_nonnegative_alpha(
    raw_predictions: np.ndarray,
    labels: np.ndarray,
    offsets: np.ndarray,
) -> tuple[float, int]:
    """Select the first (smallest) alpha attaining minimum training NLL."""

    raw = np.asarray(raw_predictions)
    if raw.ndim != 1 or raw.dtype != np.float64 or not np.all(np.isfinite(raw)):
        raise ProofAncestryPairResidualError(
            "raw_predictions must be a finite float64 vector"
        )
    checked_labels = _labels(labels, raw.size)
    checked_offsets = _vector(offsets, "offsets", raw.size)
    best_alpha = ALPHA_GRID[0]
    best_nll = math.inf
    for alpha in ALPHA_GRID:
        signed_logits = checked_labels * (checked_offsets + alpha * raw)
        nll = float(
            np.sum(np.logaddexp(0.0, -signed_logits), dtype=np.float64) / math.log(2.0)
        )
        if nll < best_nll:
            best_nll = nll
            best_alpha = alpha
    return best_alpha, len(ALPHA_GRID) * raw.size


def fit_outer_fold(
    training_features: Sequence[np.ndarray],
    training_labels: Sequence[np.ndarray],
    training_offsets: Sequence[np.ndarray],
    held_out_features: np.ndarray,
    held_out_offsets: np.ndarray,
) -> FrozenOuterFoldPrediction:
    """Generate three inner-held-out predictions and one truth-free outer logit."""

    if not (
        len(training_features) == len(training_labels) == len(training_offsets) == 3
    ):
        raise ProofAncestryPairResidualError(
            "an outer fold requires exactly three training targets"
        )
    matrices = [
        _feature_matrix(value, f"training_features[{index}]")
        for index, value in enumerate(training_features)
    ]
    if any(matrix.shape[0] != KEY_TOUCH_FEATURES for matrix in matrices):
        raise ProofAncestryPairResidualError(
            "every training feature matrix must contain 256 coordinates"
        )
    labels = [_labels(value, KEY_TOUCH_FEATURES) for value in training_labels]
    offsets = [
        _vector(value, f"training_offsets[{index}]", KEY_TOUCH_FEATURES)
        for index, value in enumerate(training_offsets)
    ]
    held_matrix = _feature_matrix(held_out_features, "held_out_features")
    if held_matrix.shape[0] != KEY_TOUCH_FEATURES:
        raise ProofAncestryPairResidualError(
            "held_out_features must contain 256 coordinates"
        )
    held_offsets = _vector(
        held_out_offsets,
        "held_out_offsets",
        KEY_TOUCH_FEATURES,
    )

    inner_predictions = np.empty((3, KEY_TOUCH_FEATURES), dtype=np.float64)
    regularizations: list[float] = []
    for inner_held_out in range(3):
        training_indices = [index for index in range(3) if index != inner_held_out]
        fit = fit_offset_ridge(
            np.concatenate([matrices[index] for index in training_indices], axis=0),
            np.concatenate([labels[index] for index in training_indices]),
            np.concatenate([offsets[index] for index in training_indices]),
        )
        inner_predictions[inner_held_out] = _finite_matmul(
            matrices[inner_held_out],
            fit.weights,
            "inner-held-out prediction",
        )
        regularizations.append(fit.regularization)

    alpha, evaluations = select_nonnegative_alpha(
        inner_predictions.reshape(-1),
        np.concatenate(labels),
        np.concatenate(offsets),
    )
    outer_fit = fit_offset_ridge(
        np.concatenate(matrices, axis=0),
        np.concatenate(labels),
        np.concatenate(offsets),
    )
    regularizations.append(outer_fit.regularization)
    raw_effective_weights = alpha * outer_fit.weights
    raw_effective_weights[raw_effective_weights == 0.0] = 0.0
    effective_weights = _frozen_float64(
        raw_effective_weights,
        shape=(FEATURE_WIDTH,),
    )
    held_logits = _frozen_float64(
        held_offsets
        + _finite_matmul(
            held_matrix,
            effective_weights,
            "outer-held-out prediction",
        ),
        shape=(KEY_TOUCH_FEATURES,),
    )
    return FrozenOuterFoldPrediction(
        effective_weights=effective_weights,
        alpha=alpha,
        inner_raw_predictions=_frozen_float64(
            inner_predictions,
            shape=(3, KEY_TOUCH_FEATURES),
        ),
        held_out_logits=held_logits,
        regularizations=(
            regularizations[0],
            regularizations[1],
            regularizations[2],
            regularizations[3],
        ),
        ridge_fits=4,
        alpha_bit_evaluations=evaluations,
    )


class ProjectedResidualState:
    """Exactly 8 KiB of retained effective weights plus posterior logits."""

    __slots__ = ("_effective_weights", "_posterior")

    def __init__(self, effective_weights: np.ndarray) -> None:
        self._effective_weights = _frozen_float64(
            effective_weights,
            shape=(FEATURE_WIDTH,),
        )
        self._posterior = np.zeros(KEY_TOUCH_FEATURES, dtype=np.float64)

    @property
    def live_state_bytes(self) -> int:
        return int(self._effective_weights.nbytes + self._posterior.nbytes)

    @property
    def effective_weights(self) -> np.ndarray:
        return self._effective_weights

    def posterior(self) -> np.ndarray:
        return _frozen_float64(self._posterior, shape=(KEY_TOUCH_FEATURES,))

    def reset(self) -> None:
        self._posterior.fill(0.0)

    def infer_coordinate(
        self,
        pool: Full256ActionPool,
        coordinate: int,
        *,
        offset: float = 0.0,
    ) -> float:
        coordinate = _coordinate(coordinate)
        if isinstance(offset, bool) or not isinstance(offset, (int, float)):
            raise ProofAncestryPairResidualError("offset must be finite")
        checked_offset = float(offset)
        if not math.isfinite(checked_offset):
            raise ProofAncestryPairResidualError("offset must be finite")
        row = project_coordinate(pool, coordinate)
        logit = checked_offset + float(
            _finite_matmul(
                row,
                self._effective_weights,
                "streaming residual prediction",
            )
        )
        if not math.isfinite(logit):
            raise ProofAncestryPairResidualError("inferred logit is non-finite")
        self._posterior[coordinate] = logit
        return logit

    def infer_pool(
        self,
        pool: Full256ActionPool,
        offsets: np.ndarray,
    ) -> np.ndarray:
        checked_offsets = _vector(offsets, "offsets", KEY_TOUCH_FEATURES)
        for coordinate in range(KEY_TOUCH_FEATURES):
            self.infer_coordinate(
                pool,
                coordinate,
                offset=float(checked_offsets[coordinate]),
            )
        return self.posterior()


def verify_o1c23_selection(
    decision: object,
    operator_graph: object,
) -> O1C26SelectionReceipt:
    """Verify supplied O1C-0023 bytes semantically, but grant no run authority."""

    try:
        checked_decision = verify_decision(decision)
    except O1C22PostResultComposerError as exc:
        raise ProofAncestryPairResidualError("O1C-0023 decision is invalid") from exc
    operator = checked_decision["operator"]
    if (
        not isinstance(operator, Mapping)
        or operator.get("operator_id") != SELECTED_OPERATOR_ID
    ):
        raise ProofAncestryPairResidualError(
            f"O1C-0023 must select {SELECTED_OPERATOR_ID}"
        )
    if not isinstance(operator_graph, Mapping):
        raise ProofAncestryPairResidualError("operator graph must be a JSON object")
    selection = operator_graph.get("selection")
    if not isinstance(selection, Mapping):
        raise ProofAncestryPairResidualError("operator graph selection is absent")
    try:
        expected = next_operator_graph(
            checked_decision,
            causal_sha256=_checked_sha256(
                selection.get("causal_sha256"),
                "causal_sha256",
            ),
            fragment_sha256=_checked_sha256(
                selection.get("fragment_sha256"),
                "fragment_sha256",
            ),
            native_generated_sha256=_checked_sha256(
                selection.get("native_generated_sha256"),
                "native_generated_sha256",
            ),
        )
    except O1C22PostResultComposerError as exc:
        raise ProofAncestryPairResidualError(
            "operator graph source is invalid"
        ) from exc
    if (
        dict(operator_graph) != expected
        or expected.get("schema") != OPERATOR_GRAPH_SCHEMA
    ):
        raise ProofAncestryPairResidualError("operator graph differs from decision")
    source = checked_decision["source"]
    if not isinstance(source, Mapping):  # pragma: no cover - verify_decision proves it.
        raise AssertionError("verified decision source is not a mapping")
    return O1C26SelectionReceipt(
        decision_sha256=str(checked_decision["decision_sha256"]),
        operator_graph_sha256=str(expected["operator_graph_sha256"]),
        source_capsule_manifest_sha256=str(source["capsule_manifest_sha256"]),
        source_result_sha256=str(source["result_sha256"]),
        operator_fingerprint=str(operator["operator_fingerprint"]),
    )


__all__ = [
    "ADDITIVE_ARM",
    "ALPHA_GRID",
    "COMMON_MODE_ARM",
    "CONTEXT_COLUMNS",
    "DIAGNOSTIC_ABLATIONS",
    "EXPECTED_HORIZONS",
    "FEATURE_WIDTH",
    "FrozenOuterFoldPrediction",
    "LEARNED_ARMS",
    "LIVE_STATE_BYTES",
    "NUMERIC_SCRATCH_BYTES",
    "O1C26SelectionReceipt",
    "OFF_DIAGONAL_ONLY_ABLATION",
    "OffsetRidgeFit",
    "PAIR_SHUFFLE_ARM",
    "POSTERIOR_BYTES",
    "PRIMARY_ARM",
    "PROJECTION_SCHEMA",
    "PROXY_OPERATOR_ID",
    "ProjectedResidualState",
    "ProofAncestryPairResidualError",
    "SELECTED_OPERATOR_ID",
    "SELF_ONLY_ABLATION",
    "TOUCH_BUCKETS",
    "WEIGHT_BYTES",
    "context_projection_table",
    "fit_offset_ridge",
    "fit_outer_fold",
    "iter_projected_rows",
    "pair_shuffle_sources",
    "project_coordinate",
    "project_pool",
    "projection_policy",
    "projection_policy_sha256",
    "select_nonnegative_alpha",
    "touch_projection_table",
    "verify_o1c23_selection",
]
