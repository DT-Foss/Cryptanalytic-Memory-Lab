"""Fixed holographic feature maps and reduced-rank ridge inverse readers."""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass

import numpy as np

RIDGE_MAGIC = b"O1HRR1\x00"
KEY_BITS = 256


class HolographicRidgeError(ValueError):
    """Raised when a feature map or frozen reduced-rank reader differs."""


def _finite_matmul(left: np.ndarray, right: np.ndarray, name: str) -> np.ndarray:
    """Multiply while rejecting real non-finite output.

    Apple's Accelerate-backed NumPy can surface stale floating-point status bits
    as divide/overflow warnings for an otherwise finite matmul.  The explicit
    finite check preserves the failure boundary without making warning-strict
    experiment runs platform-dependent.
    """

    with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
        result = np.matmul(left, right)
    if not np.all(np.isfinite(result)):
        raise HolographicRidgeError(f"{name} produced non-finite values")
    return result


@dataclass(frozen=True)
class FeatureSegment:
    name: str
    start: int
    end: int

    def validate(self, input_dimension: int) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > 64:
            raise HolographicRidgeError("feature segment name is invalid")
        if (
            not isinstance(self.start, int)
            or isinstance(self.start, bool)
            or not isinstance(self.end, int)
            or isinstance(self.end, bool)
            or not 0 <= self.start < self.end <= input_dimension
        ):
            raise HolographicRidgeError("feature segment interval is invalid")

    def describe(self) -> dict[str, object]:
        return {"name": self.name, "start": self.start, "end": self.end}


@dataclass(frozen=True)
class HolographicFeaturePlan:
    input_dimension: int
    slots: int
    seed: int
    segments: tuple[FeatureSegment, ...]
    interactions: tuple[tuple[str, str], ...]

    def validate(self) -> None:
        if (
            not isinstance(self.input_dimension, int)
            or isinstance(self.input_dimension, bool)
            or self.input_dimension < 1
        ):
            raise HolographicRidgeError("input_dimension must be positive")
        if (
            not isinstance(self.slots, int)
            or isinstance(self.slots, bool)
            or not 4 <= self.slots <= 1024
        ):
            raise HolographicRidgeError("slots must be in [4, 1024]")
        if not isinstance(self.seed, int) or isinstance(self.seed, bool):
            raise HolographicRidgeError("seed must be an integer")
        if not self.segments:
            raise HolographicRidgeError("at least one segment is required")
        for segment in self.segments:
            segment.validate(self.input_dimension)
        names = [segment.name for segment in self.segments]
        if len(set(names)) != len(names):
            raise HolographicRidgeError("segment names must be unique")
        coverage = np.zeros(self.input_dimension, dtype=np.uint8)
        for segment in self.segments:
            coverage[segment.start : segment.end] += 1
        if np.any(coverage != 1):
            raise HolographicRidgeError(
                "segments must form one exact non-overlapping input cover"
            )
        if len(set(self.interactions)) != len(self.interactions):
            raise HolographicRidgeError("interactions must be unique")
        known = set(names)
        if any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or pair[0] not in known
            or pair[1] not in known
            for pair in self.interactions
        ):
            raise HolographicRidgeError("interaction references an unknown segment")

    @property
    def output_dimension(self) -> int:
        return self.slots * (len(self.segments) + len(self.interactions))

    def describe(self) -> dict[str, object]:
        self.validate()
        value = {
            "schema": "o1-256-holographic-feature-plan-v1",
            "input_dimension": self.input_dimension,
            "slots": self.slots,
            "seed": self.seed,
            "segments": [segment.describe() for segment in self.segments],
            "interactions": [list(pair) for pair in self.interactions],
            "output_dimension": self.output_dimension,
        }
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("ascii")
        return {**value, "plan_sha256": hashlib.sha256(encoded).hexdigest()}


class HolographicFeatureMap:
    def __init__(self, plan: HolographicFeaturePlan) -> None:
        plan.validate()
        self.plan = plan
        self._projections: dict[str, np.ndarray] = {}
        for segment in plan.segments:
            width = segment.end - segment.start
            projection = np.zeros((width, plan.slots), dtype=np.float32)
            scale = 1.0 / math.sqrt(width)
            for local in range(width):
                digest = hashlib.blake2b(
                    f"{segment.name}/{local}".encode("ascii"),
                    digest_size=16,
                    person=b"o1-256-holo",
                    key=(plan.seed & ((1 << 64) - 1)).to_bytes(8, "big"),
                ).digest()
                slot = int.from_bytes(digest[:8], "big") % plan.slots
                sign = 1.0 if (digest[8] & 1) == 0 else -1.0
                projection[local, slot] = sign * scale
            self._projections[segment.name] = projection

    def transform(self, features: np.ndarray) -> np.ndarray:
        matrix = np.asarray(features, dtype=np.float32)
        if (
            matrix.ndim != 2
            or matrix.shape[1] != self.plan.input_dimension
            or not np.all(np.isfinite(matrix))
        ):
            raise HolographicRidgeError(
                "features must be a finite matrix with the planned dimension"
            )
        banks: dict[str, np.ndarray] = {}
        rows: list[np.ndarray] = []
        for segment in self.plan.segments:
            bank = _finite_matmul(
                matrix[:, segment.start : segment.end],
                self._projections[segment.name],
                f"{segment.name} projection",
            )
            bank = bank.astype(np.float32, copy=False)
            banks[segment.name] = bank
            rows.append(bank)
        for left, right in self.plan.interactions:
            rows.append((banks[left] * banks[right]).astype(np.float32, copy=False))
        result = np.concatenate(rows, axis=1).astype(np.float32, copy=False)
        if result.shape != (matrix.shape[0], self.plan.output_dimension):
            raise AssertionError("holographic feature map dimension differs")
        return result


@dataclass(frozen=True)
class FrozenHolographicRidge:
    plan: HolographicFeaturePlan
    ridge_lambda: float
    requested_rank: int
    effective_rank: int
    feature_mean: np.ndarray
    feature_scale: np.ndarray
    key_mean: np.ndarray
    key_weights: np.ndarray
    singular_values: np.ndarray
    auxiliary_dimension: int

    def validate(self) -> None:
        self.plan.validate()
        if not math.isfinite(self.ridge_lambda) or self.ridge_lambda <= 0.0:
            raise HolographicRidgeError("ridge_lambda must be positive")
        if not 1 <= self.effective_rank <= self.requested_rank:
            raise HolographicRidgeError("effective rank differs")
        dimension = self.plan.output_dimension
        shapes = {
            "feature_mean": (dimension,),
            "feature_scale": (dimension,),
            "key_mean": (KEY_BITS,),
            "key_weights": (dimension, KEY_BITS),
            "singular_values": (self.effective_rank,),
        }
        for name, shape in shapes.items():
            array = np.asarray(getattr(self, name))
            if array.shape != shape or not np.all(np.isfinite(array)):
                raise HolographicRidgeError(f"{name} shape or values differ")
        if np.any(self.feature_scale <= 0.0):
            raise HolographicRidgeError("feature scales must be positive")
        if (
            not isinstance(self.auxiliary_dimension, int)
            or isinstance(self.auxiliary_dimension, bool)
            or self.auxiliary_dimension < 0
        ):
            raise HolographicRidgeError("auxiliary_dimension must be non-negative")

    @property
    def parameter_count(self) -> int:
        return int(
            self.feature_mean.size
            + self.feature_scale.size
            + self.key_mean.size
            + self.key_weights.size
        )

    def predict_mapped(self, mapped_features: np.ndarray) -> np.ndarray:
        self.validate()
        matrix = np.asarray(mapped_features, dtype=np.float64)
        if (
            matrix.ndim != 2
            or matrix.shape[1] != self.plan.output_dimension
            or not np.all(np.isfinite(matrix))
        ):
            raise HolographicRidgeError("mapped features differ")
        standardized = (matrix - self.feature_mean) / self.feature_scale
        return (
            _finite_matmul(standardized, self.key_weights, "ridge prediction")
            + self.key_mean
        )

    def predict(self, raw_features: np.ndarray) -> np.ndarray:
        mapped = HolographicFeatureMap(self.plan).transform(raw_features)
        return self.predict_mapped(mapped)

    def describe(self) -> dict[str, object]:
        self.validate()
        frozen = serialize_ridge(self)
        return {
            "schema": "o1-256-frozen-holographic-ridge-v1",
            "plan": self.plan.describe(),
            "ridge_lambda": self.ridge_lambda,
            "requested_rank": self.requested_rank,
            "effective_rank": self.effective_rank,
            "auxiliary_dimension": self.auxiliary_dimension,
            "parameter_count": self.parameter_count,
            "serialized_bytes": len(frozen),
            "model_sha256": hashlib.sha256(frozen).hexdigest(),
            "singular_values": [float(value) for value in self.singular_values],
        }


def fit_holographic_ridge(
    plan: HolographicFeaturePlan,
    mapped_features: np.ndarray,
    key_labels: np.ndarray,
    *,
    ridge_lambda: float = 1.0,
    rank: int = 64,
    auxiliary_labels: np.ndarray | None = None,
    auxiliary_weight: float = 0.25,
) -> FrozenHolographicRidge:
    plan.validate()
    feature_input = np.asarray(mapped_features)
    labels = np.asarray(key_labels)
    if (
        feature_input.ndim != 2
        or feature_input.shape[0] < 2
        or feature_input.shape[1] != plan.output_dimension
        or not np.all(np.isfinite(feature_input))
    ):
        raise HolographicRidgeError("mapped training features differ")
    if (
        labels.shape != (feature_input.shape[0], KEY_BITS)
        or not np.all(np.isfinite(labels))
        or np.any((labels != 0.0) & (labels != 1.0))
    ):
        raise HolographicRidgeError("key labels must be a matched binary Nx256 matrix")
    if not math.isfinite(ridge_lambda) or ridge_lambda <= 0.0:
        raise HolographicRidgeError("ridge_lambda must be positive")
    if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
        raise HolographicRidgeError("rank must be positive")
    if not math.isfinite(auxiliary_weight) or auxiliary_weight < 0.0:
        raise HolographicRidgeError("auxiliary_weight must be non-negative")

    # Keep only one float64 feature matrix and standardize it in place.  The
    # full-256 distilled arm is intentionally fitted from sufficient statistics;
    # an Nx(256+aux) target matrix would exceed the experiment's CPU RAM budget.
    features = np.array(feature_input, dtype=np.float64, copy=True, order="C")
    feature_mean = features.mean(axis=0)
    feature_scale = features.std(axis=0)
    feature_scale = np.where(feature_scale < 1e-6, 1.0, feature_scale)
    features -= feature_mean
    features /= feature_scale
    standardized = features

    auxiliary_dimension = 0
    auxiliary: np.ndarray | None = None
    auxiliary_mean: np.ndarray | None = None
    auxiliary_scale: np.ndarray | None = None
    if auxiliary_labels is not None:
        auxiliary = np.asarray(auxiliary_labels)
        if (
            auxiliary.ndim != 2
            or auxiliary.shape[0] != standardized.shape[0]
            or auxiliary.shape[1] < 1
            or not np.all(np.isfinite(auxiliary))
        ):
            raise HolographicRidgeError("auxiliary labels differ")
        auxiliary_dimension = int(auxiliary.shape[1])
        auxiliary_sum = np.zeros(auxiliary_dimension, dtype=np.float64)
        auxiliary_square_sum = np.zeros(auxiliary_dimension, dtype=np.float64)
        for start in range(0, auxiliary.shape[0], 512):
            chunk = np.array(
                auxiliary[start : start + 512], dtype=np.float64, copy=True
            )
            auxiliary_sum += chunk.sum(axis=0)
            auxiliary_square_sum += np.square(chunk).sum(axis=0)
        auxiliary_mean = auxiliary_sum / auxiliary.shape[0]
        variance = auxiliary_square_sum / auxiliary.shape[0] - np.square(auxiliary_mean)
        auxiliary_scale = np.sqrt(np.maximum(variance, 0.0))
        auxiliary_scale = np.where(auxiliary_scale < 1e-6, 1.0, auxiliary_scale)

    gram = _finite_matmul(standardized.T, standardized, "ridge gram matrix")
    gram.flat[:: gram.shape[0] + 1] += ridge_lambda
    target_dimension = KEY_BITS + auxiliary_dimension
    cross = np.empty((plan.output_dimension, target_dimension), dtype=np.float64)
    key_mean = 2.0 * labels.mean(axis=0, dtype=np.float64) - 1.0
    for start in range(0, KEY_BITS, 64):
        end = min(start + 64, KEY_BITS)
        target_chunk = np.array(labels[:, start:end], dtype=np.float64, copy=True)
        target_chunk *= 2.0
        target_chunk -= 1.0
        target_chunk -= key_mean[start:end]
        cross[:, start:end] = _finite_matmul(
            standardized.T,
            target_chunk,
            "ridge key cross-covariance",
        )
    if auxiliary is not None:
        if auxiliary_mean is None or auxiliary_scale is None:
            raise AssertionError("auxiliary statistics are absent")
        for start in range(0, auxiliary_dimension, 64):
            end = min(start + 64, auxiliary_dimension)
            target_chunk = np.array(
                auxiliary[:, start:end], dtype=np.float64, copy=True
            )
            target_chunk -= auxiliary_mean[start:end]
            target_chunk /= auxiliary_scale[start:end]
            target_chunk *= auxiliary_weight
            cross[:, KEY_BITS + start : KEY_BITS + end] = _finite_matmul(
                standardized.T,
                target_chunk,
                "ridge auxiliary cross-covariance",
            )
    weights = np.linalg.solve(gram, cross)
    left, singular_values, right = np.linalg.svd(weights, full_matrices=False)
    effective_rank = min(rank, len(singular_values))
    truncated = _finite_matmul(
        left[:, :effective_rank] * singular_values[:effective_rank][None, :],
        right[:effective_rank, :],
        "rank truncation",
    )
    key_weights = truncated[:, :KEY_BITS]
    result = FrozenHolographicRidge(
        plan=plan,
        ridge_lambda=float(ridge_lambda),
        requested_rank=rank,
        effective_rank=effective_rank,
        feature_mean=feature_mean.astype(np.float64),
        feature_scale=feature_scale.astype(np.float64),
        key_mean=key_mean.astype(np.float64),
        key_weights=key_weights.astype(np.float64),
        singular_values=singular_values[:effective_rank].astype(np.float64),
        auxiliary_dimension=auxiliary_dimension,
    )
    result.validate()
    return result


def _array_rows(model: FrozenHolographicRidge) -> tuple[list[dict[str, object]], bytes]:
    arrays = (
        ("feature_mean", model.feature_mean),
        ("feature_scale", model.feature_scale),
        ("key_mean", model.key_mean),
        ("key_weights", model.key_weights),
        ("singular_values", model.singular_values),
    )
    rows: list[dict[str, object]] = []
    payloads: list[bytes] = []
    offset = 0
    for name, value in arrays:
        array = np.ascontiguousarray(value, dtype="<f8")
        payload = array.tobytes()
        rows.append(
            {
                "name": name,
                "shape": list(array.shape),
                "offset": offset,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
        payloads.append(payload)
        offset += len(payload)
    return rows, b"".join(payloads)


def serialize_ridge(model: FrozenHolographicRidge) -> bytes:
    model.validate()
    arrays, payload = _array_rows(model)
    header = {
        "schema": "o1-256-holographic-ridge-binary-v1",
        "plan": model.plan.describe(),
        "ridge_lambda": model.ridge_lambda,
        "requested_rank": model.requested_rank,
        "effective_rank": model.effective_rank,
        "auxiliary_dimension": model.auxiliary_dimension,
        "arrays": arrays,
        "payload_bytes": len(payload),
    }
    header_bytes = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return RIDGE_MAGIC + struct.pack(">Q", len(header_bytes)) + header_bytes + payload


def deserialize_ridge(value: bytes) -> FrozenHolographicRidge:
    if not isinstance(value, bytes) or not value.startswith(RIDGE_MAGIC):
        raise HolographicRidgeError("ridge binary magic differs")
    cursor = len(RIDGE_MAGIC)
    if len(value) < cursor + 8:
        raise HolographicRidgeError("ridge binary header is truncated")
    header_length = struct.unpack(">Q", value[cursor : cursor + 8])[0]
    cursor += 8
    try:
        header = json.loads(value[cursor : cursor + header_length].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HolographicRidgeError("ridge binary header is invalid") from exc
    cursor += header_length
    if (
        not isinstance(header, dict)
        or header.get("schema") != "o1-256-holographic-ridge-binary-v1"
    ):
        raise HolographicRidgeError("ridge binary schema differs")
    plan_row = header.get("plan")
    if not isinstance(plan_row, dict):
        raise HolographicRidgeError("ridge plan is absent")
    segments = tuple(
        FeatureSegment(str(row["name"]), int(row["start"]), int(row["end"]))
        for row in plan_row["segments"]
    )
    plan = HolographicFeaturePlan(
        input_dimension=int(plan_row["input_dimension"]),
        slots=int(plan_row["slots"]),
        seed=int(plan_row["seed"]),
        segments=segments,
        interactions=tuple(tuple(pair) for pair in plan_row["interactions"]),
    )
    if plan.describe() != plan_row:
        raise HolographicRidgeError("ridge plan commitment differs")
    expected_names = {
        "feature_mean",
        "feature_scale",
        "key_mean",
        "key_weights",
        "singular_values",
    }
    arrays: dict[str, np.ndarray] = {}
    for row in header.get("arrays", []):
        if not isinstance(row, dict) or row.get("name") not in expected_names:
            raise HolographicRidgeError("ridge array inventory differs")
        name = str(row["name"])
        if name in arrays:
            raise HolographicRidgeError("ridge array is duplicated")
        start = cursor + int(row["offset"])
        end = start + int(row["bytes"])
        payload = value[start:end]
        if (
            len(payload) != int(row["bytes"])
            or hashlib.sha256(payload).hexdigest() != row["sha256"]
        ):
            raise HolographicRidgeError("ridge array payload differs")
        shape = tuple(int(dimension) for dimension in row["shape"])
        arrays[name] = np.frombuffer(payload, dtype="<f8").reshape(shape).copy()
    if set(arrays) != expected_names:
        raise HolographicRidgeError("ridge array set is incomplete")
    if len(value) != cursor + int(header["payload_bytes"]):
        raise HolographicRidgeError("ridge binary length differs")
    model = FrozenHolographicRidge(
        plan=plan,
        ridge_lambda=float(header["ridge_lambda"]),
        requested_rank=int(header["requested_rank"]),
        effective_rank=int(header["effective_rank"]),
        feature_mean=arrays["feature_mean"],
        feature_scale=arrays["feature_scale"],
        key_mean=arrays["key_mean"],
        key_weights=arrays["key_weights"],
        singular_values=arrays["singular_values"],
        auxiliary_dimension=int(header["auxiliary_dimension"]),
    )
    model.validate()
    return model
