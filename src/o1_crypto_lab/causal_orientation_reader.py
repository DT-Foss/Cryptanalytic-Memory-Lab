"""Odd, shared bit-level readers for full-256 causal evidence fields.

The reader has one deliberately narrow job: learn a shared orientation for
signed assumption-pair evidence without introducing a coordinate-specific
dictionary or an intercept.  Candidate weights and RMS scales are fitted from
BUILD only; CAL only chooses a feature arm, ridge value, and temperature.

Two input contracts are supported:

* ``FrozenCausalBitfieldState`` contributes U3 plus its eight signed,
  bit-local aggregate ARX interactions (11 features per key bit).
* A finite ``[N, 256, 39]`` tensor contributes the canonical U3 | ARX24 | M12
  field: three unary horizons, eight ARX features per horizon, and four signed
  motif-family features per horizon.  A single ``[256, 39]`` target is also
  accepted.

Every feature used by every arm is signed.  Features are RMS-scaled but never
centered, and the ridge has no intercept.  Consequently every frozen reader
satisfies ``score(-x) == -score(x)`` up to the final floating-point reduction,
and the tanh readout makes polarity-swapped probabilities complementary.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np

from .cadical_sensor import KEY_BITS
from .causal_bitfield import (
    HORIZON_COUNT,
    NEIGHBORS_PER_BIT,
    FrozenCausalBitfieldState,
)
from .living_inverse import canonical_json_bytes, canonical_sha256


READER_SCHEMA = "o1-256-frozen-causal-orientation-reader-v1"
READER_BINARY_SCHEMA = "o1-256-causal-orientation-reader-binary-v1"
READER_MAGIC = b"O1COR1\x00"

CANONICAL_TENSOR_WIDTH = 39
FROZEN_STATE_WIDTH = HORIZON_COUNT + NEIGHBORS_PER_BIT
CANONICAL_TENSOR_CONTRACT = "signed-u3-arx24-m12-v1"
FROZEN_STATE_CONTRACT = "signed-frozen-u3-arx8-v1"

ARM_HORIZON_0 = "horizon_0"
ARM_HORIZON_1 = "horizon_1"
ARM_HORIZON_2 = "horizon_2"
ARM_U3 = "u3"
ARM_U3_ARX24 = "u3_arx24"
ARM_U3_ARX24_M12 = "u3_arx24_m12"
ARM_CAUSAL_LOCAL = "causal_local"

CANONICAL_ARMS = (
    ARM_HORIZON_0,
    ARM_HORIZON_1,
    ARM_HORIZON_2,
    ARM_U3,
    ARM_U3_ARX24,
    ARM_U3_ARX24_M12,
)
FROZEN_STATE_ARMS = (
    ARM_HORIZON_0,
    ARM_HORIZON_1,
    ARM_HORIZON_2,
    ARM_U3,
    ARM_CAUSAL_LOCAL,
)
DEFAULT_RIDGE_LAMBDAS = (0.01, 0.1, 1.0, 10.0, 100.0)
DEFAULT_TEMPERATURES = (0.5, 1.0, 2.0, 4.0, 8.0)
DEFAULT_LOGIT_SCALES = (0.0, 0.25, 0.5, 1.0)
NLL_TIE_TOLERANCE = 1e-12


class CausalOrientationReaderError(ValueError):
    """A signed feature field, split, or frozen reader is invalid."""


def _finite_positive(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CausalOrientationReaderError(f"{field} must be positive and finite")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise CausalOrientationReaderError(f"{field} must be positive and finite")
    return result


def _finite_unit_interval(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CausalOrientationReaderError(f"{field} must be finite in [0,1]")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise CausalOrientationReaderError(f"{field} must be finite in [0,1]")
    return result


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CausalOrientationReaderError(f"{field} must be a lowercase SHA-256")
    return value


def _horizons(value: object) -> tuple[int, int, int]:
    if (
        not isinstance(value, (tuple, list))
        or len(value) != HORIZON_COUNT
        or len(set(value)) != HORIZON_COUNT
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 1
            for item in value
        )
    ):
        raise CausalOrientationReaderError("horizons must be three distinct positives")
    return tuple(value)  # type: ignore[return-value]


def _labels(value: object, count: int, split: str) -> np.ndarray:
    array = np.asarray(value)
    if count == 1 and array.shape == (KEY_BITS,):
        array = array[None, :]
    if array.shape != (count, KEY_BITS) or np.any((array != 0) & (array != 1)):
        raise CausalOrientationReaderError(
            f"{split} labels must be a matched binary Nx256 matrix"
        )
    return np.ascontiguousarray(array, dtype=np.uint8)


def _canonical_float_bytes(value: np.ndarray) -> bytes:
    return np.ascontiguousarray(value, dtype="<f8").tobytes(order="C")


@dataclass(frozen=True)
class _FeatureField:
    values: np.ndarray
    contract: str
    horizons: tuple[int, int, int]

    def __post_init__(self) -> None:
        value = np.asarray(self.values)
        width = (
            CANONICAL_TENSOR_WIDTH
            if self.contract == CANONICAL_TENSOR_CONTRACT
            else FROZEN_STATE_WIDTH
            if self.contract == FROZEN_STATE_CONTRACT
            else -1
        )
        if (
            value.ndim != 3
            or value.shape[0] < 1
            or value.shape[1:] != (KEY_BITS, width)
            or value.dtype != np.float64
            or not np.all(np.isfinite(value))
        ):
            raise CausalOrientationReaderError("signed causal feature field differs")
        _horizons(self.horizons)
        value.setflags(write=False)
        object.__setattr__(self, "values", value)

    @property
    def count(self) -> int:
        return int(self.values.shape[0])

    @property
    def width(self) -> int:
        return int(self.values.shape[2])


FeatureInput = (
    np.ndarray | FrozenCausalBitfieldState | Sequence[FrozenCausalBitfieldState]
)


def _feature_field(
    value: FeatureInput,
    *,
    tensor_horizons: tuple[int, int, int] = (64, 96, 65),
) -> _FeatureField:
    if isinstance(value, FrozenCausalBitfieldState):
        states = (value,)
    elif isinstance(value, np.ndarray):
        array = np.asarray(value)
        if array.ndim == 2:
            array = array[None, :, :]
        if (
            array.ndim != 3
            or array.shape[0] < 1
            or array.shape[1:] != (KEY_BITS, CANONICAL_TENSOR_WIDTH)
            or not np.all(np.isfinite(array))
        ):
            raise CausalOrientationReaderError(
                "tensor input must be finite [N,256,39] or [256,39]"
            )
        return _FeatureField(
            values=np.array(array, dtype=np.float64, copy=True, order="C"),
            contract=CANONICAL_TENSOR_CONTRACT,
            horizons=_horizons(tensor_horizons),
        )
    else:
        states = tuple(value)
        if not states or any(
            not isinstance(state, FrozenCausalBitfieldState) for state in states
        ):
            raise CausalOrientationReaderError(
                "state input must contain FrozenCausalBitfieldState values"
            )

    horizons = states[0].plan.horizons
    if any(state.plan.horizons != horizons for state in states):
        raise CausalOrientationReaderError("frozen state horizons differ")
    values = np.empty((len(states), KEY_BITS, FROZEN_STATE_WIDTH), dtype=np.float64)
    for index, state in enumerate(states):
        values[index, :, :HORIZON_COUNT] = state.unary.T
        values[index, :, HORIZON_COUNT:] = state.interactions
    return _FeatureField(
        values=values,
        contract=FROZEN_STATE_CONTRACT,
        horizons=_horizons(horizons),
    )


def canonical_feature_tensor(
    unary3: np.ndarray,
    arx24: np.ndarray,
    motif12: np.ndarray,
) -> np.ndarray:
    """Join the canonical signed U3 | ARX24 | M12 contract without mutation."""

    unary = np.asarray(unary3)
    arx = np.asarray(arx24)
    motif = np.asarray(motif12)
    single = unary.ndim == 2
    if single:
        unary = unary[None, :, :]
        arx = arx[None, :, :]
        motif = motif[None, :, :]
    count = unary.shape[0] if unary.ndim == 3 else -1
    if (
        unary.shape != (count, KEY_BITS, 3)
        or arx.shape != (count, KEY_BITS, 24)
        or motif.shape != (count, KEY_BITS, 12)
    ):
        raise CausalOrientationReaderError(
            "canonical components must have matched [N,256,3|24|12] shapes"
        )
    result = np.concatenate((unary, arx, motif), axis=2, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise CausalOrientationReaderError("canonical signed features must be finite")
    return result[0] if single else result


def _available_arms(contract: str) -> tuple[str, ...]:
    if contract == CANONICAL_TENSOR_CONTRACT:
        return CANONICAL_ARMS
    if contract == FROZEN_STATE_CONTRACT:
        return FROZEN_STATE_ARMS
    raise CausalOrientationReaderError("unknown signed feature contract")


def _arm_indices(contract: str, arm: str) -> tuple[int, ...]:
    available = _available_arms(contract)
    if arm not in available:
        raise CausalOrientationReaderError(
            f"feature arm {arm!r} is unavailable for {contract}"
        )
    if arm == ARM_HORIZON_0:
        return (0,)
    if arm == ARM_HORIZON_1:
        return (1,)
    if arm == ARM_HORIZON_2:
        return (2,)
    if arm == ARM_U3:
        return (0, 1, 2)
    if arm == ARM_U3_ARX24:
        return tuple(range(27))
    if arm == ARM_U3_ARX24_M12:
        return tuple(range(CANONICAL_TENSOR_WIDTH))
    if arm == ARM_CAUSAL_LOCAL:
        return tuple(range(FROZEN_STATE_WIDTH))
    raise AssertionError("validated feature arm lacks an index map")


def _ordered_unique_arms(arms: Iterable[str], contract: str) -> tuple[str, ...]:
    supplied = tuple(arms)
    if not supplied or len(set(supplied)) != len(supplied):
        raise CausalOrientationReaderError("feature arms must be non-empty and unique")
    available = _available_arms(contract)
    if any(arm not in available for arm in supplied):
        raise CausalOrientationReaderError("feature arm is outside the input contract")
    return tuple(arm for arm in available if arm in supplied)


def _ordered_positive_grid(values: Iterable[float], field: str) -> tuple[float, ...]:
    result = tuple(sorted(_finite_positive(value, field) for value in values))
    if not result or len(set(result)) != len(result):
        raise CausalOrientationReaderError(f"{field} grid must be non-empty and unique")
    return result


def _ordered_logit_scale_grid(values: Iterable[float]) -> tuple[float, ...]:
    result = tuple(
        sorted(_finite_unit_interval(value, "logit_scale") for value in values)
    )
    if not result or len(set(result)) != len(result):
        raise CausalOrientationReaderError(
            "logit_scale grid must be non-empty and unique"
        )
    if 0.0 not in result:
        raise CausalOrientationReaderError(
            "logit_scale grid must include the exact uniform fallback 0.0"
        )
    return result


def _dataset_sha256(
    field: _FeatureField,
    labels: np.ndarray,
    split: str,
) -> str:
    feature_bytes = _canonical_float_bytes(field.values)
    label_bytes = np.packbits(labels, bitorder="little").tobytes()
    return canonical_sha256(
        {
            "schema": "o1-256-causal-orientation-dataset-v1",
            "split": split,
            "contract": field.contract,
            "horizons": list(field.horizons),
            "target_count": field.count,
            "feature_sha256": hashlib.sha256(feature_bytes).hexdigest(),
            "label_sha256": hashlib.sha256(label_bytes).hexdigest(),
        }
    )


@dataclass(frozen=True)
class BinaryOrientationMetrics:
    key_count: int
    total_bits: int
    correct_bits: int
    accuracy: float
    total_nll_bits: float
    nll_bits_per_key: float
    nll_bits_per_bit: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.key_count, bool)
            or not isinstance(self.key_count, int)
            or self.key_count < 1
            or self.total_bits != self.key_count * KEY_BITS
            or not 0 <= self.correct_bits <= self.total_bits
        ):
            raise CausalOrientationReaderError("orientation metric counts differ")
        for name in (
            "accuracy",
            "total_nll_bits",
            "nll_bits_per_key",
            "nll_bits_per_bit",
        ):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0.0:
                raise CausalOrientationReaderError(f"metric {name} differs")
        if (
            self.accuracy != self.correct_bits / self.total_bits
            or self.nll_bits_per_key != self.total_nll_bits / self.key_count
            or self.nll_bits_per_bit != self.total_nll_bits / self.total_bits
        ):
            raise CausalOrientationReaderError("orientation metric ratios differ")

    def describe(self) -> dict[str, object]:
        return {
            "key_count": self.key_count,
            "total_bits": self.total_bits,
            "correct_bits": self.correct_bits,
            "accuracy": self.accuracy,
            "total_nll_bits": self.total_nll_bits,
            "nll_bits_per_key": self.nll_bits_per_key,
            "nll_bits_per_bit": self.nll_bits_per_bit,
            "compression_bits_per_key": KEY_BITS - self.nll_bits_per_key,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "BinaryOrientationMetrics":
        try:
            return cls(
                key_count=int(value["key_count"]),
                total_bits=int(value["total_bits"]),
                correct_bits=int(value["correct_bits"]),
                accuracy=float(value["accuracy"]),
                total_nll_bits=float(value["total_nll_bits"]),
                nll_bits_per_key=float(value["nll_bits_per_key"]),
                nll_bits_per_bit=float(value["nll_bits_per_bit"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CausalOrientationReaderError("serialized metrics differ") from exc


def orientation_metrics(
    probabilities: np.ndarray,
    labels: np.ndarray,
) -> BinaryOrientationMetrics:
    probability = np.asarray(probabilities, dtype=np.float64)
    if probability.ndim == 1:
        probability = probability[None, :]
    truth = _labels(labels, probability.shape[0], "evaluation")
    if (
        probability.shape != truth.shape
        or not np.all(np.isfinite(probability))
        or np.any((probability < 0.0) | (probability > 1.0))
    ):
        raise CausalOrientationReaderError(
            "probabilities must be finite matched Nx256 values in [0,1]"
        )
    epsilon = np.finfo(np.float64).eps
    clipped = np.clip(probability, epsilon, 1.0 - epsilon)
    signed = truth.astype(np.float64)
    loss = -(signed * np.log2(clipped) + (1.0 - signed) * np.log2(1.0 - clipped))
    total_nll = float(loss.sum(dtype=np.float64))
    correct = int(np.count_nonzero((probability >= 0.5) == truth))
    total = int(truth.size)
    return BinaryOrientationMetrics(
        key_count=truth.shape[0],
        total_bits=total,
        correct_bits=correct,
        accuracy=correct / total,
        total_nll_bits=total_nll,
        nll_bits_per_key=total_nll / truth.shape[0],
        nll_bits_per_bit=total_nll / total,
    )


@dataclass(frozen=True)
class BuildOrientationCandidate:
    contract: str
    horizons: tuple[int, int, int]
    arm: str
    ridge_lambda: float
    feature_scale: np.ndarray
    weights: np.ndarray
    build_dataset_sha256: str
    build_target_count: int

    def __post_init__(self) -> None:
        indices = _arm_indices(self.contract, self.arm)
        _horizons(self.horizons)
        ridge = _finite_positive(self.ridge_lambda, "ridge_lambda")
        _sha256(self.build_dataset_sha256, "build_dataset_sha256")
        if (
            isinstance(self.build_target_count, bool)
            or not isinstance(self.build_target_count, int)
            or self.build_target_count < 1
        ):
            raise CausalOrientationReaderError("build_target_count must be positive")
        for name in ("feature_scale", "weights"):
            array = np.asarray(getattr(self, name))
            if (
                array.shape != (len(indices),)
                or array.dtype != np.float64
                or not np.all(np.isfinite(array))
            ):
                raise CausalOrientationReaderError(f"candidate {name} differs")
            if name == "feature_scale" and np.any(array <= 0.0):
                raise CausalOrientationReaderError("candidate scales must be positive")
            array.setflags(write=False)
            object.__setattr__(self, name, array)
        object.__setattr__(self, "ridge_lambda", ridge)

    @property
    def candidate_sha256(self) -> str:
        metadata = canonical_json_bytes(
            {
                "schema": "o1-256-causal-orientation-build-candidate-v1",
                "contract": self.contract,
                "horizons": list(self.horizons),
                "arm": self.arm,
                "ridge_lambda": self.ridge_lambda,
                "build_dataset_sha256": self.build_dataset_sha256,
                "build_target_count": self.build_target_count,
                "feature_centering": False,
                "intercept": 0.0,
            }
        )
        digest = hashlib.sha256(metadata)
        digest.update(_canonical_float_bytes(self.feature_scale))
        digest.update(_canonical_float_bytes(self.weights))
        return digest.hexdigest()

    def _scores(self, field: _FeatureField) -> np.ndarray:
        if field.contract != self.contract or field.horizons != self.horizons:
            raise CausalOrientationReaderError("candidate input contract differs")
        indices = _arm_indices(self.contract, self.arm)
        selected = field.values[:, :, indices]
        scaled = selected / self.feature_scale[None, None, :]
        with np.errstate(over="ignore", invalid="ignore"):
            scores = np.einsum(
                "nbf,f->nb",
                scaled,
                self.weights,
                dtype=np.float64,
                optimize=False,
            )
        if not np.all(np.isfinite(scores)):
            raise CausalOrientationReaderError("candidate produced non-finite scores")
        return scores


def fit_build_orientation_candidates(
    build_features: FeatureInput,
    build_labels: np.ndarray,
    *,
    arms: Iterable[str] | None = None,
    ridge_lambdas: Iterable[float] = DEFAULT_RIDGE_LAMBDAS,
    tensor_horizons: tuple[int, int, int] = (64, 96, 65),
) -> tuple[BuildOrientationCandidate, ...]:
    """Fit every candidate from BUILD only; this API has no CAL parameter."""

    field = _feature_field(build_features, tensor_horizons=tensor_horizons)
    labels = _labels(build_labels, field.count, "BUILD")
    arm_grid = _ordered_unique_arms(
        _available_arms(field.contract) if arms is None else arms,
        field.contract,
    )
    ridge_grid = _ordered_positive_grid(ridge_lambdas, "ridge_lambda")
    dataset_sha = _dataset_sha256(field, labels, "BUILD")
    targets = labels.astype(np.float64)
    targets *= 2.0
    targets -= 1.0
    flat_targets = targets.reshape(-1)

    candidates: list[BuildOrientationCandidate] = []
    for arm in arm_grid:
        indices = _arm_indices(field.contract, arm)
        raw = np.ascontiguousarray(
            field.values[:, :, indices].reshape(-1, len(indices)),
            dtype=np.float64,
        )
        # RMS-only scaling is essential: subtracting a BUILD mean would add an
        # implicit intercept and break exact assumption-swap oddness.
        scale = np.sqrt(np.mean(np.square(raw), axis=0, dtype=np.float64))
        scale = np.where(scale < 1e-12, 1.0, scale)
        scaled = raw / scale
        gram = np.einsum("nf,ng->fg", scaled, scaled, dtype=np.float64, optimize=False)
        cross = np.einsum(
            "nf,n->f", scaled, flat_targets, dtype=np.float64, optimize=False
        )
        for ridge_lambda in ridge_grid:
            regularized = gram.copy()
            regularized.flat[:: regularized.shape[0] + 1] += ridge_lambda
            weights = np.linalg.solve(regularized, cross)
            if not np.all(np.isfinite(weights)):
                raise CausalOrientationReaderError("ridge fit is non-finite")
            candidates.append(
                BuildOrientationCandidate(
                    contract=field.contract,
                    horizons=field.horizons,
                    arm=arm,
                    ridge_lambda=ridge_lambda,
                    feature_scale=scale.astype(np.float64, copy=True),
                    weights=weights.astype(np.float64, copy=True),
                    build_dataset_sha256=dataset_sha,
                    build_target_count=field.count,
                )
            )
    return tuple(candidates)


def _probabilities(
    scores: np.ndarray,
    temperature: float,
    logit_scale: float,
) -> np.ndarray:
    scale = _finite_unit_interval(logit_scale, "logit_scale")
    if scale == 0.0:
        return np.full(scores.shape, 0.5, dtype=np.float64)
    logits = np.clip(scale * scores / temperature, -60.0, 60.0)
    # tanh is explicitly odd, preserving the swap-complement contract more
    # tightly than two polarity-dependent exp code paths.
    return 0.5 + 0.5 * np.tanh(0.5 * logits)


@dataclass(frozen=True)
class CandidateCalibration:
    candidate_sha256: str
    arm: str
    ridge_lambda: float
    temperature: float
    logit_scale: float
    metrics: BinaryOrientationMetrics

    def __post_init__(self) -> None:
        _sha256(self.candidate_sha256, "candidate_sha256")
        _finite_positive(self.ridge_lambda, "ridge_lambda")
        _finite_positive(self.temperature, "temperature")
        _finite_unit_interval(self.logit_scale, "logit_scale")
        if not isinstance(self.metrics, BinaryOrientationMetrics):
            raise CausalOrientationReaderError("candidate metrics differ")

    def describe(self) -> dict[str, object]:
        return {
            "candidate_sha256": self.candidate_sha256,
            "arm": self.arm,
            "ridge_lambda": self.ridge_lambda,
            "temperature": self.temperature,
            "logit_scale": self.logit_scale,
            "metrics": self.metrics.describe(),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CandidateCalibration":
        try:
            metrics = value["metrics"]
            if not isinstance(metrics, Mapping):
                raise CausalOrientationReaderError("serialized metrics are absent")
            return cls(
                candidate_sha256=str(value["candidate_sha256"]),
                arm=str(value["arm"]),
                ridge_lambda=float(value["ridge_lambda"]),
                temperature=float(value["temperature"]),
                logit_scale=float(value["logit_scale"]),
                metrics=BinaryOrientationMetrics.from_mapping(metrics),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CausalOrientationReaderError(
                "serialized candidate calibration differs"
            ) from exc


def _calibration_sort_key(
    value: CandidateCalibration,
    contract: str,
) -> tuple[float, bool, float, int, float, float, float, str]:
    arm_order = {arm: index for index, arm in enumerate(_available_arms(contract))}
    return (
        value.metrics.nll_bits_per_key,
        value.logit_scale != 0.0,
        -value.metrics.accuracy,
        arm_order[value.arm],
        value.ridge_lambda,
        value.temperature,
        value.logit_scale,
        value.candidate_sha256,
    )


def _select_calibration(
    validation: Sequence[CandidateCalibration],
    contract: str,
) -> CandidateCalibration:
    if not validation:
        raise CausalOrientationReaderError("candidate validation is empty")
    best_nll = min(row.metrics.nll_bits_per_key for row in validation)
    tied = tuple(
        row
        for row in validation
        if row.metrics.nll_bits_per_key <= best_nll + NLL_TIE_TOLERANCE
    )
    # The uniform reader wins an NLL tie before any accuracy/tie-break metric.
    # This prevents a zero-signal CAL split from forcing a spurious orientation.
    return min(tied, key=lambda row: _calibration_sort_key(row, contract)[1:])


@dataclass(frozen=True)
class FrozenCausalOrientationReader:
    contract: str
    horizons: tuple[int, int, int]
    arm: str
    ridge_lambda: float
    temperature: float
    logit_scale: float
    feature_scale: np.ndarray
    weights: np.ndarray
    build_dataset_sha256: str
    calibration_dataset_sha256: str
    build_target_count: int
    calibration_target_count: int
    candidate_validation: tuple[CandidateCalibration, ...]
    schema: str = READER_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != READER_SCHEMA:
            raise CausalOrientationReaderError("reader schema differs")
        candidate = BuildOrientationCandidate(
            contract=self.contract,
            horizons=self.horizons,
            arm=self.arm,
            ridge_lambda=self.ridge_lambda,
            feature_scale=self.feature_scale,
            weights=self.weights,
            build_dataset_sha256=self.build_dataset_sha256,
            build_target_count=self.build_target_count,
        )
        _sha256(self.calibration_dataset_sha256, "calibration_dataset_sha256")
        _finite_positive(self.temperature, "temperature")
        _finite_unit_interval(self.logit_scale, "logit_scale")
        if (
            isinstance(self.calibration_target_count, bool)
            or not isinstance(self.calibration_target_count, int)
            or self.calibration_target_count < 1
        ):
            raise CausalOrientationReaderError(
                "calibration_target_count must be positive"
            )
        validation = tuple(self.candidate_validation)
        if not validation:
            raise CausalOrientationReaderError("candidate validation is empty")
        available_arms = _available_arms(self.contract)
        if any(row.arm not in available_arms for row in validation):
            raise CausalOrientationReaderError("candidate validation arm differs")
        if not any(row.logit_scale == 0.0 for row in validation):
            raise CausalOrientationReaderError(
                "candidate validation lacks the exact uniform fallback"
            )
        identities = [
            (row.candidate_sha256, row.temperature, row.logit_scale)
            for row in validation
        ]
        if len(identities) != len(set(identities)):
            raise CausalOrientationReaderError("candidate validation is duplicated")
        selected = _select_calibration(validation, self.contract)
        if (
            selected.candidate_sha256 != candidate.candidate_sha256
            or selected.arm != self.arm
            or selected.ridge_lambda != self.ridge_lambda
            or selected.temperature != self.temperature
            or selected.logit_scale != self.logit_scale
        ):
            raise CausalOrientationReaderError("frozen reader is not CAL-selected")
        object.__setattr__(self, "feature_scale", candidate.feature_scale)
        object.__setattr__(self, "weights", candidate.weights)
        object.__setattr__(self, "candidate_validation", validation)

    @property
    def candidate_sha256(self) -> str:
        return BuildOrientationCandidate(
            contract=self.contract,
            horizons=self.horizons,
            arm=self.arm,
            ridge_lambda=self.ridge_lambda,
            feature_scale=self.feature_scale,
            weights=self.weights,
            build_dataset_sha256=self.build_dataset_sha256,
            build_target_count=self.build_target_count,
        ).candidate_sha256

    @property
    def reader_sha256(self) -> str:
        return hashlib.sha256(serialize_orientation_reader(self)).hexdigest()

    def _field(
        self,
        features: FeatureInput,
    ) -> _FeatureField:
        field = _feature_field(features, tensor_horizons=self.horizons)
        if field.contract != self.contract or field.horizons != self.horizons:
            raise CausalOrientationReaderError("reader input contract differs")
        return field

    def predict_scores(self, features: FeatureInput) -> np.ndarray:
        field = self._field(features)
        candidate = BuildOrientationCandidate(
            contract=self.contract,
            horizons=self.horizons,
            arm=self.arm,
            ridge_lambda=self.ridge_lambda,
            feature_scale=self.feature_scale,
            weights=self.weights,
            build_dataset_sha256=self.build_dataset_sha256,
            build_target_count=self.build_target_count,
        )
        result = candidate._scores(field)
        return result[0] if field.count == 1 else result

    def predict_probabilities(self, features: FeatureInput) -> np.ndarray:
        return _probabilities(
            self.predict_scores(features),
            self.temperature,
            self.logit_scale,
        )

    def evaluate(
        self,
        features: FeatureInput,
        labels: np.ndarray,
    ) -> BinaryOrientationMetrics:
        probabilities = self.predict_probabilities(features)
        if probabilities.ndim == 1:
            probabilities = probabilities[None, :]
        return orientation_metrics(probabilities, labels)

    def describe(self) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": self.schema,
            "contract": self.contract,
            "horizons": list(self.horizons),
            "selected_arm": self.arm,
            "selected_ridge_lambda": self.ridge_lambda,
            "selected_temperature": self.temperature,
            "selected_logit_scale": self.logit_scale,
            "candidate_sha256": self.candidate_sha256,
            "reader_sha256": self.reader_sha256,
            "serialized_bytes": len(serialize_orientation_reader(self)),
            "feature_dimension": len(_arm_indices(self.contract, self.arm)),
            "build_dataset_sha256": self.build_dataset_sha256,
            "calibration_dataset_sha256": self.calibration_dataset_sha256,
            "build_target_count": self.build_target_count,
            "calibration_target_count": self.calibration_target_count,
            "candidate_validation": [
                row.describe() for row in self.candidate_validation
            ],
            "information_boundary": {
                "parameter_fit_split": "BUILD",
                "hyperparameter_selection_split": "CAL",
                "calibration_refit": False,
                "feature_centering": False,
                "intercept": 0.0,
                "coordinate_specific_parameters": 0,
                "signed_features_only": True,
                "assumption_swap_odd": True,
                "exact_uniform_fallback_available": True,
            },
        }
        return value


def calibrate_orientation_reader(
    candidates: Sequence[BuildOrientationCandidate],
    calibration_features: FeatureInput,
    calibration_labels: np.ndarray,
    *,
    temperatures: Iterable[float] = DEFAULT_TEMPERATURES,
    logit_scales: Iterable[float] = DEFAULT_LOGIT_SCALES,
    tensor_horizons: tuple[int, int, int] = (64, 96, 65),
) -> FrozenCausalOrientationReader:
    """Use CAL only to select among immutable BUILD-fitted candidates."""

    fitted = tuple(candidates)
    if not fitted:
        raise CausalOrientationReaderError("BUILD candidates are empty")
    first = fitted[0]
    if any(
        candidate.contract != first.contract
        or candidate.horizons != first.horizons
        or candidate.build_dataset_sha256 != first.build_dataset_sha256
        or candidate.build_target_count != first.build_target_count
        for candidate in fitted
    ):
        raise CausalOrientationReaderError("BUILD candidate provenance differs")
    candidate_identities = [
        (candidate.arm, candidate.ridge_lambda) for candidate in fitted
    ]
    if len(candidate_identities) != len(set(candidate_identities)):
        raise CausalOrientationReaderError("BUILD candidate grid is duplicated")
    field = _feature_field(
        calibration_features,
        tensor_horizons=tensor_horizons,
    )
    if field.contract != first.contract or field.horizons != first.horizons:
        raise CausalOrientationReaderError("BUILD and CAL feature contracts differ")
    labels = _labels(calibration_labels, field.count, "CAL")
    temperature_grid = _ordered_positive_grid(temperatures, "temperature")
    logit_scale_grid = _ordered_logit_scale_grid(logit_scales)
    validation: list[CandidateCalibration] = []
    by_hash: dict[str, BuildOrientationCandidate] = {}
    for candidate in sorted(
        fitted,
        key=lambda item: (
            _available_arms(first.contract).index(item.arm),
            item.ridge_lambda,
            item.candidate_sha256,
        ),
    ):
        by_hash[candidate.candidate_sha256] = candidate
        scores = candidate._scores(field)
        for temperature in temperature_grid:
            for logit_scale in logit_scale_grid:
                metrics = orientation_metrics(
                    _probabilities(scores, temperature, logit_scale), labels
                )
                validation.append(
                    CandidateCalibration(
                        candidate_sha256=candidate.candidate_sha256,
                        arm=candidate.arm,
                        ridge_lambda=candidate.ridge_lambda,
                        temperature=temperature,
                        logit_scale=logit_scale,
                        metrics=metrics,
                    )
                )
    selected = _select_calibration(validation, first.contract)
    candidate = by_hash[selected.candidate_sha256]
    return FrozenCausalOrientationReader(
        contract=candidate.contract,
        horizons=candidate.horizons,
        arm=candidate.arm,
        ridge_lambda=candidate.ridge_lambda,
        temperature=selected.temperature,
        logit_scale=selected.logit_scale,
        feature_scale=candidate.feature_scale.copy(),
        weights=candidate.weights.copy(),
        build_dataset_sha256=candidate.build_dataset_sha256,
        calibration_dataset_sha256=_dataset_sha256(field, labels, "CAL"),
        build_target_count=candidate.build_target_count,
        calibration_target_count=field.count,
        candidate_validation=tuple(validation),
    )


def fit_causal_orientation_reader(
    build_features: FeatureInput,
    build_labels: np.ndarray,
    calibration_features: FeatureInput,
    calibration_labels: np.ndarray,
    *,
    arms: Iterable[str] | None = None,
    ridge_lambdas: Iterable[float] = DEFAULT_RIDGE_LAMBDAS,
    temperatures: Iterable[float] = DEFAULT_TEMPERATURES,
    logit_scales: Iterable[float] = DEFAULT_LOGIT_SCALES,
    tensor_horizons: tuple[int, int, int] = (64, 96, 65),
) -> FrozenCausalOrientationReader:
    """Fit on BUILD, select on CAL, and return one immutable reader."""

    candidates = fit_build_orientation_candidates(
        build_features,
        build_labels,
        arms=arms,
        ridge_lambdas=ridge_lambdas,
        tensor_horizons=tensor_horizons,
    )
    return calibrate_orientation_reader(
        candidates,
        calibration_features,
        calibration_labels,
        temperatures=temperatures,
        logit_scales=logit_scales,
        tensor_horizons=tensor_horizons,
    )


def _array_inventory(
    reader: FrozenCausalOrientationReader,
) -> tuple[list[dict[str, object]], bytes]:
    rows: list[dict[str, object]] = []
    payloads: list[bytes] = []
    offset = 0
    for name, raw in (
        ("feature_scale", reader.feature_scale),
        ("weights", reader.weights),
    ):
        payload = _canonical_float_bytes(raw)
        rows.append(
            {
                "name": name,
                "shape": list(raw.shape),
                "offset": offset,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        payloads.append(payload)
        offset += len(payload)
    return rows, b"".join(payloads)


def serialize_orientation_reader(reader: FrozenCausalOrientationReader) -> bytes:
    if not isinstance(reader, FrozenCausalOrientationReader):
        raise CausalOrientationReaderError("reader must be frozen before serialization")
    arrays, payload = _array_inventory(reader)
    header = {
        "schema": READER_BINARY_SCHEMA,
        "reader_schema": reader.schema,
        "contract": reader.contract,
        "horizons": list(reader.horizons),
        "arm": reader.arm,
        "ridge_lambda": reader.ridge_lambda,
        "temperature": reader.temperature,
        "logit_scale": reader.logit_scale,
        "build_dataset_sha256": reader.build_dataset_sha256,
        "calibration_dataset_sha256": reader.calibration_dataset_sha256,
        "build_target_count": reader.build_target_count,
        "calibration_target_count": reader.calibration_target_count,
        "candidate_validation": [row.describe() for row in reader.candidate_validation],
        "arrays": arrays,
        "payload_bytes": len(payload),
        "information_boundary": {
            "parameter_fit_split": "BUILD",
            "hyperparameter_selection_split": "CAL",
            "calibration_refit": False,
            "feature_centering": False,
            "intercept": 0.0,
            "signed_features_only": True,
            "exact_uniform_fallback_available": True,
        },
    }
    header_bytes = canonical_json_bytes(header)
    return READER_MAGIC + struct.pack(">Q", len(header_bytes)) + header_bytes + payload


def deserialize_orientation_reader(value: bytes) -> FrozenCausalOrientationReader:
    if not isinstance(value, bytes) or not value.startswith(READER_MAGIC):
        raise CausalOrientationReaderError("reader binary magic differs")
    cursor = len(READER_MAGIC)
    if len(value) < cursor + 8:
        raise CausalOrientationReaderError("reader binary header is truncated")
    header_length = struct.unpack(">Q", value[cursor : cursor + 8])[0]
    cursor += 8
    end_header = cursor + header_length
    try:
        header = json.loads(value[cursor:end_header].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalOrientationReaderError("reader binary header is invalid") from exc
    cursor = end_header
    if (
        not isinstance(header, dict)
        or header.get("schema") != READER_BINARY_SCHEMA
        or header.get("reader_schema") != READER_SCHEMA
    ):
        raise CausalOrientationReaderError("reader binary schema differs")
    expected_boundary = {
        "parameter_fit_split": "BUILD",
        "hyperparameter_selection_split": "CAL",
        "calibration_refit": False,
        "feature_centering": False,
        "intercept": 0.0,
        "signed_features_only": True,
        "exact_uniform_fallback_available": True,
    }
    if header.get("information_boundary") != expected_boundary:
        raise CausalOrientationReaderError("reader information boundary differs")
    expected_names = {"feature_scale", "weights"}
    arrays: dict[str, np.ndarray] = {}
    rows = header.get("arrays")
    if not isinstance(rows, list):
        raise CausalOrientationReaderError("reader array inventory is absent")
    for row in rows:
        if not isinstance(row, dict) or row.get("name") not in expected_names:
            raise CausalOrientationReaderError("reader array inventory differs")
        name = str(row["name"])
        if name in arrays:
            raise CausalOrientationReaderError("reader array is duplicated")
        try:
            start = cursor + int(row["offset"])
            end = start + int(row["bytes"])
            shape = tuple(int(dimension) for dimension in row["shape"])
            expected_hash = str(row["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CausalOrientationReaderError("reader array row differs") from exc
        payload = value[start:end]
        if (
            len(payload) != int(row["bytes"])
            or hashlib.sha256(payload).hexdigest() != expected_hash
        ):
            raise CausalOrientationReaderError("reader array payload differs")
        try:
            arrays[name] = np.frombuffer(payload, dtype="<f8").reshape(shape).copy()
        except ValueError as exc:
            raise CausalOrientationReaderError("reader array shape differs") from exc
    if set(arrays) != expected_names:
        raise CausalOrientationReaderError("reader array set is incomplete")
    try:
        payload_bytes = int(header["payload_bytes"])
        raw_validation = header["candidate_validation"]
        if not isinstance(raw_validation, list):
            raise CausalOrientationReaderError("reader validation is absent")
        reader = FrozenCausalOrientationReader(
            schema=str(header["reader_schema"]),
            contract=str(header["contract"]),
            horizons=_horizons(header["horizons"]),
            arm=str(header["arm"]),
            ridge_lambda=float(header["ridge_lambda"]),
            temperature=float(header["temperature"]),
            logit_scale=float(header["logit_scale"]),
            feature_scale=arrays["feature_scale"],
            weights=arrays["weights"],
            build_dataset_sha256=str(header["build_dataset_sha256"]),
            calibration_dataset_sha256=str(header["calibration_dataset_sha256"]),
            build_target_count=int(header["build_target_count"]),
            calibration_target_count=int(header["calibration_target_count"]),
            candidate_validation=tuple(
                CandidateCalibration.from_mapping(row)
                for row in raw_validation
                if isinstance(row, Mapping)
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CausalOrientationReaderError("serialized reader fields differ") from exc
    if len(value) != cursor + payload_bytes:
        raise CausalOrientationReaderError("reader binary length differs")
    # Reject non-canonical headers and hidden/ignored validation rows.
    if len(reader.candidate_validation) != len(raw_validation):
        raise CausalOrientationReaderError("reader validation row differs")
    if serialize_orientation_reader(reader) != value:
        raise CausalOrientationReaderError("reader binary is not canonical")
    return reader


__all__ = [
    "ARM_CAUSAL_LOCAL",
    "ARM_HORIZON_0",
    "ARM_HORIZON_1",
    "ARM_HORIZON_2",
    "ARM_U3",
    "ARM_U3_ARX24",
    "ARM_U3_ARX24_M12",
    "BinaryOrientationMetrics",
    "BuildOrientationCandidate",
    "CANONICAL_ARMS",
    "CANONICAL_TENSOR_CONTRACT",
    "CANONICAL_TENSOR_WIDTH",
    "CandidateCalibration",
    "CausalOrientationReaderError",
    "DEFAULT_RIDGE_LAMBDAS",
    "DEFAULT_LOGIT_SCALES",
    "DEFAULT_TEMPERATURES",
    "FROZEN_STATE_ARMS",
    "FROZEN_STATE_CONTRACT",
    "FrozenCausalOrientationReader",
    "calibrate_orientation_reader",
    "canonical_feature_tensor",
    "deserialize_orientation_reader",
    "fit_build_orientation_candidates",
    "fit_causal_orientation_reader",
    "orientation_metrics",
    "serialize_orientation_reader",
]
