"""Fixed incremental-diagonal frontier gate for O1C-0030.

Only the self-ancestry diagonal and exact-conflict flag of an immutable FAP are
read.  The sole learned quantity is one no-intercept L2/logit scalar fitted on
training-RMS-standardized features from exactly the other three BUILD episodes
of each outer fold.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Iterator, Mapping

import numpy as np

from .full256_action_pool import BRANCH_FEATURES, Full256ActionPool


KEY_BITS = 256
STORAGE_HORIZONS = (64, 96, 65)
CHRONOLOGICAL_HORIZONS = (64, 65, 96)
_CHRONOLOGICAL_INDICES = (0, 2, 1)
EXACT_CONFLICT_COLUMN = 9
SELF_ANCESTRY_COLUMN_OFFSET = 74
ARM_NAMES = (
    "primary",
    "cumulative_replace",
    "legacy_reintegrated",
    "deranged_confidence",
    "polarity_even_common_mode",
)
ODD_ARM_NAMES = ARM_NAMES[:4]
EVEN_ARM_NAME = ARM_NAMES[4]
DERANGEMENT_DOMAIN = b"O1C-0030/incremental-diagonal-frontier/derangement/v1"
LOCAL_RANK_TIE_POLICY = "ascending-local-value-after-exact-score"


class O1C30IncrementalDiagonalFrontierError(ValueError):
    """A fixed feature, fit boundary, or metric input differs."""


def _frozen(value: np.ndarray, dtype: np.dtype) -> np.ndarray:
    raw = np.asarray(value, dtype=dtype, order="C")
    return np.frombuffer(raw.tobytes(order="C"), dtype=dtype).reshape(raw.shape)


def _array_sha(value: np.ndarray, dtype: str) -> str:
    raw = np.asarray(value, dtype=np.dtype(dtype), order="C").tobytes(order="C")
    return hashlib.sha256(raw).hexdigest()


def _document_sha(value: Mapping[str, object]) -> str:
    raw = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def bounded_psi(value: np.ndarray) -> np.ndarray:
    """The precommitted bounded map ``x / (1 + abs(x))``."""

    raw = np.asarray(value)
    if raw.dtype.kind != "f" or not bool(np.isfinite(raw).all()):
        raise O1C30IncrementalDiagonalFrontierError(
            "psi input must be a finite floating array"
        )
    wide = raw.astype(np.float64, copy=False)
    return wide / (1.0 + np.abs(wide))


def fixed_point_free_sha_derangement(
    size: int = KEY_BITS, *, domain: bytes = DERANGEMENT_DOMAIN
) -> np.ndarray:
    """Return a reproducible SHA-derived non-zero cyclic permutation."""

    if isinstance(size, bool) or not isinstance(size, int) or size < 2:
        raise O1C30IncrementalDiagonalFrontierError("derangement size is invalid")
    if not isinstance(domain, bytes) or not domain:
        raise O1C30IncrementalDiagonalFrontierError("derangement domain is invalid")
    offset = 1 + int.from_bytes(hashlib.sha256(domain).digest()[:8], "big") % (size - 1)
    return _frozen(
        (np.arange(size, dtype=np.int64) + offset) % size, np.dtype(np.int64)
    )


@dataclass(frozen=True)
class ArmFeatureSet(Mapping[str, np.ndarray]):
    """Five fixed arms plus label-free projection diagnostics."""

    primary: np.ndarray
    cumulative_replace: np.ndarray
    legacy_reintegrated: np.ndarray
    deranged_confidence: np.ndarray
    polarity_even_common_mode: np.ndarray
    q: np.ndarray
    deranged_q: np.ndarray
    odd_ancestry: np.ndarray
    odd_innovations: np.ndarray
    even_ancestry: np.ndarray
    even_innovations: np.ndarray
    derangement: np.ndarray

    def __post_init__(self) -> None:
        for name in ARM_NAMES:
            row = np.asarray(getattr(self, name))
            if row.dtype != np.float64 or row.shape != (KEY_BITS,):
                raise O1C30IncrementalDiagonalFrontierError(
                    f"{name} must be float64[256]"
                )
            object.__setattr__(self, name, _frozen(row, np.dtype(np.float64)))
        for name, dtype in (("q", np.uint8), ("deranged_q", np.uint8)):
            row = np.asarray(getattr(self, name))
            if row.dtype != dtype or row.shape != (3, KEY_BITS):
                raise O1C30IncrementalDiagonalFrontierError(
                    f"{name} must be uint8[3,256]"
                )
            object.__setattr__(self, name, _frozen(row, np.dtype(dtype)))
        for name in (
            "odd_ancestry",
            "odd_innovations",
            "even_ancestry",
            "even_innovations",
        ):
            row = np.asarray(getattr(self, name))
            if row.dtype != np.float64 or row.shape != (3, KEY_BITS):
                raise O1C30IncrementalDiagonalFrontierError(
                    f"{name} must be float64[3,256]"
                )
            object.__setattr__(self, name, _frozen(row, np.dtype(np.float64)))
        permutation = np.asarray(self.derangement)
        if (
            permutation.dtype != np.int64
            or permutation.shape != (KEY_BITS,)
            or len(np.unique(permutation)) != KEY_BITS
            or bool(np.any(permutation == np.arange(KEY_BITS)))
        ):
            raise O1C30IncrementalDiagonalFrontierError("derangement is invalid")
        object.__setattr__(
            self, "derangement", _frozen(permutation, np.dtype(np.int64))
        )

    def __getitem__(self, name: str) -> np.ndarray:
        if name not in ARM_NAMES:
            raise KeyError(name)
        return getattr(self, name)

    def __iter__(self) -> Iterator[str]:
        return iter(ARM_NAMES)

    def __len__(self) -> int:
        return len(ARM_NAMES)

    def as_mapping(self) -> dict[str, np.ndarray]:
        return {name: self[name] for name in ARM_NAMES}


def project_branch_features(
    branch_features: np.ndarray, *, horizons: tuple[int, ...] = STORAGE_HORIZONS
) -> ArmFeatureSet:
    """Project float[3,256,2,330] storage into chronological fixed arms."""

    if tuple(horizons) != STORAGE_HORIZONS:
        raise O1C30IncrementalDiagonalFrontierError(
            "pool horizons must be exact storage order (64,96,65)"
        )
    features = np.asarray(branch_features)
    if (
        features.dtype.kind != "f"
        or features.shape != (3, KEY_BITS, 2, BRANCH_FEATURES)
        or not bool(np.isfinite(features).all())
    ):
        raise O1C30IncrementalDiagonalFrontierError(
            "branch_features must be finite float[3,256,2,330]"
        )
    conflict = features[..., EXACT_CONFLICT_COLUMN]
    if bool(((conflict != 0.0) & (conflict != 1.0)).any()):
        raise O1C30IncrementalDiagonalFrontierError(
            "exact-conflict column must contain bits"
        )
    order = np.asarray(_CHRONOLOGICAL_INDICES)
    conflict = conflict[order].astype(np.uint8, copy=False)

    columns = SELF_ANCESTRY_COLUMN_OFFSET + np.arange(KEY_BITS)
    gather = np.broadcast_to(columns[None, :, None, None], (3, KEY_BITS, 2, 1))
    diagonal = np.take_along_axis(features, gather, axis=3)[..., 0][order]
    bounded = bounded_psi(diagonal)
    odd = (bounded[:, :, 1] - bounded[:, :, 0]) / 2.0
    even = (bounded[:, :, 1] + bounded[:, :, 0]) / 2.0
    odd_delta = np.stack((odd[0], odd[1] - odd[0], odd[2] - odd[1]))
    even_delta = np.stack((even[0], even[1] - even[0], even[2] - even[1]))

    # q is agreement of branch-XOR-conflict orientations, equivalently the XOR
    # of the two conflict bits.  It is direction-free under a whole-branch swap.
    branch_polarity = np.asarray((0, 1), dtype=np.uint8)[None, None, :]
    oriented = np.bitwise_xor(conflict, branch_polarity)
    q = (oriented[:, :, 0] == oriented[:, :, 1]).astype(np.uint8)
    permutation = fixed_point_free_sha_derangement()
    deranged_q = q[:, permutation]
    primary = np.sum((1.0 + q) * odd_delta, axis=0)
    deranged = np.sum((1.0 + deranged_q) * odd_delta, axis=0)
    return ArmFeatureSet(
        primary=primary,
        cumulative_replace=odd[2],
        legacy_reintegrated=np.sum(odd, axis=0),
        deranged_confidence=deranged,
        polarity_even_common_mode=np.sum((1.0 + q) * even_delta, axis=0),
        q=q,
        deranged_q=deranged_q,
        odd_ancestry=odd,
        odd_innovations=odd_delta,
        even_ancestry=even,
        even_innovations=even_delta,
        derangement=permutation,
    )


def project_pool(pool: Full256ActionPool) -> ArmFeatureSet:
    if not isinstance(pool, Full256ActionPool):
        raise TypeError("pool must be Full256ActionPool")
    return project_branch_features(pool.branch_features, horizons=pool.horizons)


def _fit_inputs(
    features: np.ndarray, labels: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    x = np.asarray(features)
    y = np.asarray(labels)
    if x.dtype.kind != "f" or x.shape != (4, KEY_BITS) or not np.isfinite(x).all():
        raise O1C30IncrementalDiagonalFrontierError(
            "features must be finite float[4,256]"
        )
    if (
        y.dtype != np.uint8
        or y.shape != (4, KEY_BITS)
        or bool(((y != 0) & (y != 1)).any())
    ):
        raise O1C30IncrementalDiagonalFrontierError("labels must be uint8[4,256] bits")
    return x.astype(np.float64, copy=False), y


def _positive(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C30IncrementalDiagonalFrontierError(f"{name} must be positive")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise O1C30IncrementalDiagonalFrontierError(f"{name} must be positive")
    return result


def _objective_gradient(
    coefficient: float, x: np.ndarray, signed: np.ndarray, l2: float
) -> tuple[float, float]:
    margin = signed * x * coefficient
    objective = float(np.logaddexp(0.0, -margin).mean() + 0.5 * l2 * coefficient**2)
    # sigmoid(-margin), branch-stable at very large magnitudes.
    z = -margin
    p = np.empty_like(z)
    positive = z >= 0.0
    p[positive] = 1.0 / (1.0 + np.exp(-z[positive]))
    exp_z = np.exp(z[~positive])
    p[~positive] = exp_z / (1.0 + exp_z)
    return objective, float(np.mean(-signed * x * p) + l2 * coefficient)


@dataclass(frozen=True)
class ScalarLogitFit:
    arm_name: str
    heldout_episode: int
    training_episode_indices: tuple[int, ...]
    coefficient: float
    training_rms: float
    effective_raw_coefficient: float
    l2: float
    objective: float
    absolute_gradient: float
    iterations: int
    training_features_sha256: str
    training_labels_sha256: str
    receipt_sha256: str

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "o1-256-o1c30-global-scalar-logit-fit-v1",
            "arm": self.arm_name,
            "heldout_episode": self.heldout_episode,
            "training_episode_indices": list(self.training_episode_indices),
            "training_examples": 768,
            "coefficient_float64_hex": self.coefficient.hex(),
            "training_rms_float64_hex": self.training_rms.hex(),
            "effective_raw_coefficient_float64_hex": (
                self.effective_raw_coefficient.hex()
            ),
            "l2_float64_hex": self.l2.hex(),
            "objective_float64_hex": self.objective.hex(),
            "absolute_gradient_float64_hex": self.absolute_gradient.hex(),
            "iterations": self.iterations,
            "training_features_sha256": self.training_features_sha256,
            "training_labels_sha256": self.training_labels_sha256,
            "intercept": 0,
            "heldout_features_used_for_fit": 0,
            "heldout_labels_used_for_fit": 0,
        }


def _fit_scalar(
    x: np.ndarray, y: np.ndarray, l2: float
) -> tuple[float, float, float, int]:
    flat_x = x.reshape(768)
    signed = 2.0 * y.reshape(768).astype(np.float64) - 1.0
    bound = float(np.mean(np.abs(flat_x))) / l2
    if bound == 0.0:
        objective, gradient = _objective_gradient(0.0, flat_x, signed, l2)
        return 0.0, objective, abs(gradient), 0
    low, high = -bound, bound
    coefficient = 0.0
    for iteration in range(1, 257):
        coefficient = low + (high - low) / 2.0
        _, gradient = _objective_gradient(coefficient, flat_x, signed, l2)
        if gradient > 0.0:
            high = coefficient
        elif gradient < 0.0:
            low = coefficient
        else:
            break
        if high - low <= 2e-15 * max(1.0, abs(coefficient)):
            coefficient = low + (high - low) / 2.0
            break
    objective, gradient = _objective_gradient(coefficient, flat_x, signed, l2)
    if abs(gradient) > 1e-11:
        raise O1C30IncrementalDiagonalFrontierError("scalar fit did not converge")
    return coefficient, objective, abs(gradient), iteration


@dataclass(frozen=True)
class LeaveOneOutLogits:
    arm_name: str
    l2: float
    logits: np.ndarray
    fits: tuple[ScalarLogitFit, ...]

    def __post_init__(self) -> None:
        values = np.asarray(self.logits)
        if values.dtype != np.float64 or values.shape != (4, KEY_BITS):
            raise O1C30IncrementalDiagonalFrontierError(
                "LOO logits must be float64[4,256]"
            )
        object.__setattr__(self, "logits", _frozen(values, np.dtype(np.float64)))

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "o1-256-o1c30-leave-one-out-logits-v1",
            "arm": self.arm_name,
            "l2_float64_hex": self.l2.hex(),
            "fit_receipt_sha256": [row.receipt_sha256 for row in self.fits],
            "heldout_logits_sha256": [_array_sha(row, "<f8") for row in self.logits],
        }

    @property
    def receipt_sha256(self) -> str:
        return _document_sha(self.receipt_document())


def fit_leave_one_out(
    features: np.ndarray, labels: np.ndarray, *, l2: float, arm_name: str
) -> LeaveOneOutLogits:
    """Fit one global scalar on 3x256 examples for each of four outer folds."""

    x, y = _fit_inputs(features, labels)
    regularization = _positive(l2, "l2")
    if arm_name not in ARM_NAMES:
        raise O1C30IncrementalDiagonalFrontierError("arm name is not precommitted")
    logits = np.empty_like(x)
    fits = []
    for heldout in range(4):
        train = tuple(index for index in range(4) if index != heldout)
        train_x, train_y = x[list(train)], y[list(train)]
        training_rms = float(np.sqrt(np.mean(np.square(train_x))))
        if training_rms == 0.0:
            training_rms = 1.0
        standardized_train_x = train_x / training_rms
        coefficient, objective, gradient, iterations = _fit_scalar(
            standardized_train_x, train_y, regularization
        )
        effective_raw_coefficient = coefficient / training_rms
        values = {
            "schema": "o1-256-o1c30-global-scalar-logit-fit-v1",
            "arm": arm_name,
            "heldout_episode": heldout,
            "training_episode_indices": list(train),
            "training_examples": 768,
            "coefficient_float64_hex": coefficient.hex(),
            "training_rms_float64_hex": training_rms.hex(),
            "effective_raw_coefficient_float64_hex": (effective_raw_coefficient.hex()),
            "l2_float64_hex": regularization.hex(),
            "objective_float64_hex": objective.hex(),
            "absolute_gradient_float64_hex": gradient.hex(),
            "iterations": iterations,
            "training_features_sha256": _array_sha(train_x, "<f8"),
            "training_labels_sha256": _array_sha(train_y, "u1"),
            "intercept": 0,
            "heldout_features_used_for_fit": 0,
            "heldout_labels_used_for_fit": 0,
        }
        fits.append(
            ScalarLogitFit(
                arm_name=arm_name,
                heldout_episode=heldout,
                training_episode_indices=train,
                coefficient=coefficient,
                training_rms=training_rms,
                effective_raw_coefficient=effective_raw_coefficient,
                l2=regularization,
                objective=objective,
                absolute_gradient=gradient,
                iterations=iterations,
                training_features_sha256=str(values["training_features_sha256"]),
                training_labels_sha256=str(values["training_labels_sha256"]),
                receipt_sha256=_document_sha(values),
            )
        )
        logits[heldout] = coefficient * (x[heldout] / training_rms)
    return LeaveOneOutLogits(arm_name, regularization, logits, tuple(fits))


def _metric_inputs(
    logits: np.ndarray, labels: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    values, truth = np.asarray(logits), np.asarray(labels)
    if (
        values.dtype.kind != "f"
        or values.shape != (KEY_BITS,)
        or not np.isfinite(values).all()
    ):
        raise O1C30IncrementalDiagonalFrontierError("logits must be finite float[256]")
    if truth.dtype != np.uint8 or truth.shape != (KEY_BITS,) or np.any(truth > 1):
        raise O1C30IncrementalDiagonalFrontierError("labels must be uint8[256] bits")
    return values.astype(np.float64, copy=False), truth


def nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values, truth = _metric_inputs(logits, labels)
    signed = 2.0 * truth.astype(np.float64) - 1.0
    return float(np.logaddexp(0.0, -signed * values).sum() / math.log(2.0))


def exact_local_true_rank(logits: np.ndarray, labels: np.ndarray) -> int:
    """Exact factorized rank of one little-endian byte/u16, ties by value."""

    values, truth = np.asarray(logits), np.asarray(labels)
    width = values.size
    if (
        width not in (8, 16)
        or values.dtype.kind != "f"
        or values.shape != (width,)
        or truth.dtype != np.uint8
        or truth.shape != (width,)
        or not np.isfinite(values).all()
        or np.any(truth > 1)
    ):
        raise O1C30IncrementalDiagonalFrontierError("local rank input is invalid")
    ratios = tuple(abs(float(value)).as_integer_ratio() for value in values)
    denominator = max(row[1] for row in ratios)
    weights = tuple(num * (denominator // den) for num, den in ratios)
    penalties = [0]
    for weight in weights:
        penalties.extend(value + weight for value in tuple(penalties))
    mode = sum(1 << bit for bit, value in enumerate(values) if value > 0.0)
    target = sum(int(value) << bit for bit, value in enumerate(truth))
    target_penalty = penalties[target ^ mode]
    return 1 + sum(
        penalties[candidate ^ mode] < target_penalty
        or (penalties[candidate ^ mode] == target_penalty and candidate < target)
        for candidate in range(1 << width)
    )


def local_true_ranks(
    logits: np.ndarray, labels: np.ndarray
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    values, truth = _metric_inputs(logits, labels)
    return (
        tuple(
            exact_local_true_rank(values[i : i + 8], truth[i : i + 8])
            for i in range(0, KEY_BITS, 8)
        ),
        tuple(
            exact_local_true_rank(values[i : i + 16], truth[i : i + 16])
            for i in range(0, KEY_BITS, 16)
        ),
    )


@dataclass(frozen=True)
class LogitMetrics:
    nll_bits: float
    compression_bits: float
    correct_bits: int
    bit_accuracy: float
    true_byte_ranks: tuple[int, ...]
    true_u16_ranks: tuple[int, ...]

    def describe(self) -> dict[str, object]:
        return {
            "nll_bits_float64_hex": self.nll_bits.hex(),
            "compression_bits_float64_hex": self.compression_bits.hex(),
            "correct_bits": self.correct_bits,
            "bit_accuracy_float64_hex": self.bit_accuracy.hex(),
            "true_byte_ranks": list(self.true_byte_ranks),
            "true_u16_ranks": list(self.true_u16_ranks),
            "byte_top1_count": sum(rank == 1 for rank in self.true_byte_ranks),
            "u16_top1_count": sum(rank == 1 for rank in self.true_u16_ranks),
            "local_rank_tie_policy": LOCAL_RANK_TIE_POLICY,
        }


def score_logits(logits: np.ndarray, labels: np.ndarray) -> LogitMetrics:
    values, truth = _metric_inputs(logits, labels)
    loss = nll_bits(values, truth)
    correct = int(np.count_nonzero((values > 0.0).astype(np.uint8) == truth))
    byte_ranks, u16_ranks = local_true_ranks(values, truth)
    return LogitMetrics(
        loss,
        KEY_BITS - loss,
        correct,
        correct / KEY_BITS,
        byte_ranks,
        u16_ranks,
    )


__all__ = [
    "ARM_NAMES",
    "CHRONOLOGICAL_HORIZONS",
    "EVEN_ARM_NAME",
    "ODD_ARM_NAMES",
    "STORAGE_HORIZONS",
    "ArmFeatureSet",
    "LeaveOneOutLogits",
    "LogitMetrics",
    "O1C30IncrementalDiagonalFrontierError",
    "ScalarLogitFit",
    "bounded_psi",
    "exact_local_true_rank",
    "fit_leave_one_out",
    "fixed_point_free_sha_derangement",
    "local_true_ranks",
    "nll_bits",
    "project_branch_features",
    "project_pool",
    "score_logits",
]
