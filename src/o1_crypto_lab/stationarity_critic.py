"""Fixed-size episode-equal ridge critic with stationarity uncertainty.

Each revealed BUILD episode is first reduced to one normalized ridge solution.
That solution receives exactly one Welford vote, regardless of the episode's
row count.  Only fixed-size sufficient statistics survive: the vector mean
and full matrix M2 of episode weights, plus an inverse pooled design matrix.

The conservative lower confidence bound deliberately excludes the epistemic
exploration bonus.  A caller can therefore use ``conservative_lcb`` for an
abstain/stop decision and ``conservative_lcb + epistemic_bonus`` for ranking
actions that remain admissible.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import NamedTuple

import numpy as np


STATIONARITY_CRITIC_SCHEMA = "o1-256-episode-equal-ridge-critic-v1"
STATIONARITY_CRITIC_MAGIC = b"O1SCR1\x00"
MAX_DIMENSION = 4096
MAX_EPISODE_COUNT = (1 << 64) - 1
MAX_HEADER_BYTES = 4096


class StationarityCriticError(ValueError):
    """A stationarity critic input, state, or serialized payload differs."""


class StationarityPrediction(NamedTuple):
    """Four deterministic action-value diagnostics for one context."""

    mean: float
    across_episode_std: float
    epistemic_bonus: float
    conservative_lcb: float


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StationarityCriticError("critic header is not canonical JSON") from exc


def _dimension(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_DIMENSION
    ):
        raise StationarityCriticError(
            f"dimension must be an integer in [1,{MAX_DIMENSION}]"
        )
    return value


def _positive_finite(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0.0
    ):
        raise StationarityCriticError(f"{field} must be positive and finite")
    return float(value)


def _nonnegative_finite(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0.0
    ):
        raise StationarityCriticError(f"{field} must be non-negative and finite")
    return float(value)


def _float64_array(
    value: object,
    shape: tuple[int, ...],
    field: str,
) -> np.ndarray:
    if not isinstance(value, np.ndarray):
        raise StationarityCriticError(f"{field} must be a numpy array")
    if value.dtype != np.float64 or value.shape != shape:
        raise StationarityCriticError(
            f"{field} must be float64 with shape {list(shape)}"
        )
    if not np.all(np.isfinite(value)):
        raise StationarityCriticError(f"{field} must contain only finite values")
    return np.array(value, dtype=np.float64, order="C", copy=True)


@dataclass
class EpisodeEqualRidgeCritic:
    """Bounded ridge critic in which every episode has exactly one vote.

    ``pooled_design_inverse`` is

    ``(ridge I + sum_e X_e.T X_e / n_e) ** -1``.

    Normalizing each episode's sufficient statistics by its row count makes
    duplicated observations incapable of silently increasing that episode's
    influence.  No episode rows or fitted-weight history are retained.
    """

    dimension: int
    ridge: float
    episode_count: int
    mean_weights: np.ndarray
    m2_weights: np.ndarray
    pooled_design_inverse: np.ndarray

    def __post_init__(self) -> None:
        self.dimension = _dimension(self.dimension)
        self.ridge = _positive_finite(self.ridge, "ridge")
        if (
            isinstance(self.episode_count, bool)
            or not isinstance(self.episode_count, int)
            or not 0 <= self.episode_count <= MAX_EPISODE_COUNT
        ):
            raise StationarityCriticError("episode_count must be uint64")
        self.mean_weights = _float64_array(
            self.mean_weights,
            (self.dimension,),
            "mean_weights",
        )
        self.m2_weights = _float64_array(
            self.m2_weights,
            (self.dimension, self.dimension),
            "m2_weights",
        )
        self.pooled_design_inverse = _float64_array(
            self.pooled_design_inverse,
            (self.dimension, self.dimension),
            "pooled_design_inverse",
        )
        self.validate()

    @classmethod
    def initial(cls, dimension: int, ridge: float) -> "EpisodeEqualRidgeCritic":
        checked_dimension = _dimension(dimension)
        checked_ridge = _positive_finite(ridge, "ridge")
        return cls(
            dimension=checked_dimension,
            ridge=checked_ridge,
            episode_count=0,
            mean_weights=np.zeros(checked_dimension, dtype=np.float64),
            m2_weights=np.zeros(
                (checked_dimension, checked_dimension),
                dtype=np.float64,
            ),
            pooled_design_inverse=(
                np.eye(checked_dimension, dtype=np.float64) / checked_ridge
            ),
        )

    def validate(self) -> None:
        dimension = _dimension(self.dimension)
        ridge = _positive_finite(self.ridge, "ridge")
        if (
            isinstance(self.episode_count, bool)
            or not isinstance(self.episode_count, int)
            or not 0 <= self.episode_count <= MAX_EPISODE_COUNT
        ):
            raise StationarityCriticError("episode_count must be uint64")
        arrays = (
            (self.mean_weights, (dimension,), "mean_weights"),
            (self.m2_weights, (dimension, dimension), "m2_weights"),
            (
                self.pooled_design_inverse,
                (dimension, dimension),
                "pooled_design_inverse",
            ),
        )
        for array, shape, field in arrays:
            if (
                not isinstance(array, np.ndarray)
                or array.dtype != np.float64
                or array.shape != shape
                or not array.flags.c_contiguous
                or not np.all(np.isfinite(array))
            ):
                raise StationarityCriticError(
                    f"{field} must be finite C-contiguous float64{list(shape)}"
                )
        if not np.allclose(
            self.m2_weights,
            self.m2_weights.T,
            rtol=0.0,
            atol=1e-12,
        ):
            raise StationarityCriticError("m2_weights is not symmetric")
        try:
            m2_eigenvalues = np.linalg.eigvalsh(self.m2_weights)
        except np.linalg.LinAlgError as exc:
            raise StationarityCriticError(
                "m2_weights eigendecomposition failed"
            ) from exc
        m2_scale = max(float(np.max(np.abs(m2_eigenvalues))), 1.0)
        if float(np.min(m2_eigenvalues)) < -1e-10 * m2_scale:
            raise StationarityCriticError("m2_weights is not positive semidefinite")
        if not np.allclose(
            self.pooled_design_inverse,
            self.pooled_design_inverse.T,
            rtol=0.0,
            atol=1e-12,
        ):
            raise StationarityCriticError("pooled_design_inverse is not symmetric")
        try:
            np.linalg.cholesky(self.pooled_design_inverse)
        except np.linalg.LinAlgError as exc:
            raise StationarityCriticError(
                "pooled_design_inverse must be positive definite"
            ) from exc
        if self.episode_count == 0:
            expected_inverse = np.eye(dimension, dtype=np.float64) / ridge
            if (
                np.any(self.mean_weights != 0.0)
                or np.any(self.m2_weights != 0.0)
                or not np.array_equal(
                    self.pooled_design_inverse,
                    expected_inverse,
                )
            ):
                raise StationarityCriticError("empty critic state differs")
        elif self.episode_count == 1 and np.any(self.m2_weights != 0.0):
            raise StationarityCriticError(
                "a one-episode critic must have zero Welford M2"
            )

    def clone(self) -> "EpisodeEqualRidgeCritic":
        self.validate()
        return EpisodeEqualRidgeCritic(
            dimension=self.dimension,
            ridge=self.ridge,
            episode_count=self.episode_count,
            mean_weights=self.mean_weights.copy(),
            m2_weights=self.m2_weights.copy(),
            pooled_design_inverse=self.pooled_design_inverse.copy(),
        )

    def update_episode(self, design: np.ndarray, rewards: np.ndarray) -> np.ndarray:
        """Fit and atomically add one episode-equal ridge vote.

        The returned fitted vector is a detached, read-only copy.  Invalid or
        numerically non-finite input leaves every critic byte unchanged.
        """

        self.validate()
        if self.episode_count == MAX_EPISODE_COUNT:
            raise StationarityCriticError("episode_count would overflow uint64")
        if (
            not isinstance(design, np.ndarray)
            or design.dtype != np.float64
            or design.ndim != 2
            or design.shape[0] < 1
            or design.shape[1] != self.dimension
            or not design.flags.c_contiguous
            or not np.all(np.isfinite(design))
        ):
            raise StationarityCriticError(
                "design must be a non-empty finite C-contiguous float64 matrix"
            )
        rows = design.shape[0]
        if (
            not isinstance(rewards, np.ndarray)
            or rewards.dtype != np.float64
            or rewards.shape != (rows,)
            or not rewards.flags.c_contiguous
            or not np.all(np.isfinite(rewards))
        ):
            raise StationarityCriticError(
                "rewards must be a finite C-contiguous float64 row vector"
            )

        scale = 1.0 / float(rows)
        with np.errstate(over="ignore", invalid="ignore"):
            episode_gram = (design.T @ design) * scale
            episode_rhs = (design.T @ rewards) * scale
        if not np.all(np.isfinite(episode_gram)) or not np.all(
            np.isfinite(episode_rhs)
        ):
            raise StationarityCriticError(
                "episode sufficient statistics are not finite"
            )
        episode_precision = episode_gram + self.ridge * np.eye(
            self.dimension,
            dtype=np.float64,
        )
        identity = np.eye(self.dimension, dtype=np.float64)
        try:
            fitted_weights = np.linalg.solve(episode_precision, episode_rhs)
            pooled_precision = np.linalg.solve(
                self.pooled_design_inverse,
                identity,
            )
            new_pooled_inverse = np.linalg.solve(
                pooled_precision + episode_gram,
                identity,
            )
        except np.linalg.LinAlgError as exc:
            raise StationarityCriticError("ridge solve failed") from exc
        new_pooled_inverse = 0.5 * (new_pooled_inverse + new_pooled_inverse.T)
        if not np.all(np.isfinite(fitted_weights)) or not np.all(
            np.isfinite(new_pooled_inverse)
        ):
            raise StationarityCriticError("ridge update produced non-finite state")

        new_count = self.episode_count + 1
        delta = fitted_weights - self.mean_weights
        new_mean = self.mean_weights + delta / float(new_count)
        delta_after = fitted_weights - new_mean
        new_m2 = self.m2_weights + np.outer(delta, delta_after)
        new_m2 = 0.5 * (new_m2 + new_m2.T)
        candidate = EpisodeEqualRidgeCritic(
            dimension=self.dimension,
            ridge=self.ridge,
            episode_count=new_count,
            mean_weights=new_mean,
            m2_weights=new_m2,
            pooled_design_inverse=new_pooled_inverse,
        )

        self.episode_count = candidate.episode_count
        self.mean_weights = candidate.mean_weights
        self.m2_weights = candidate.m2_weights
        self.pooled_design_inverse = candidate.pooled_design_inverse
        result = fitted_weights.copy()
        result.setflags(write=False)
        return result

    def predict(
        self,
        context: np.ndarray,
        stationarity_penalty: float,
        exploration_scale: float,
    ) -> StationarityPrediction:
        self.validate()
        if (
            not isinstance(context, np.ndarray)
            or context.dtype != np.float64
            or context.shape != (self.dimension,)
            or not context.flags.c_contiguous
            or not np.all(np.isfinite(context))
        ):
            raise StationarityCriticError(
                "context must be a finite C-contiguous float64 vector"
            )
        penalty = _nonnegative_finite(
            stationarity_penalty,
            "stationarity_penalty",
        )
        exploration = _nonnegative_finite(
            exploration_scale,
            "exploration_scale",
        )
        mean = float(context @ self.mean_weights)
        if self.episode_count < 2:
            across_episode_std = 0.0
        else:
            weight_covariance = self.m2_weights / float(self.episode_count - 1)
            projected_variance = float(context @ weight_covariance @ context)
            across_episode_std = math.sqrt(max(projected_variance, 0.0))
        epistemic_variance = float(context @ self.pooled_design_inverse @ context)
        epistemic_bonus = exploration * math.sqrt(max(epistemic_variance, 0.0))
        conservative_lcb = mean - penalty * across_episode_std
        values = (
            mean,
            across_episode_std,
            epistemic_bonus,
            conservative_lcb,
        )
        if not all(math.isfinite(value) for value in values):
            raise StationarityCriticError("prediction produced non-finite values")
        return StationarityPrediction(*values)

    def to_bytes(self) -> bytes:
        self.validate()
        array_bytes = [
            self.dimension * 8,
            self.dimension * self.dimension * 8,
            self.dimension * self.dimension * 8,
        ]
        header = _canonical_json_bytes(
            {
                "array_bytes": array_bytes,
                "dimension": self.dimension,
                "episode_count": self.episode_count,
                "ridge": self.ridge,
                "schema": STATIONARITY_CRITIC_SCHEMA,
            }
        )
        return (
            STATIONARITY_CRITIC_MAGIC
            + struct.pack(">Q", len(header))
            + header
            + self.mean_weights.astype("<f8", copy=False).tobytes(order="C")
            + self.m2_weights.astype("<f8", copy=False).tobytes(order="C")
            + self.pooled_design_inverse.astype("<f8", copy=False).tobytes(order="C")
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> "EpisodeEqualRidgeCritic":
        prefix_bytes = len(STATIONARITY_CRITIC_MAGIC) + 8
        if (
            not isinstance(value, bytes)
            or len(value) < prefix_bytes
            or not value.startswith(STATIONARITY_CRITIC_MAGIC)
        ):
            raise StationarityCriticError("critic payload magic or length differs")
        header_length = struct.unpack(
            ">Q",
            value[len(STATIONARITY_CRITIC_MAGIC) : prefix_bytes],
        )[0]
        if not 1 <= header_length <= MAX_HEADER_BYTES:
            raise StationarityCriticError("critic header length differs")
        header_end = prefix_bytes + header_length
        if header_end > len(value):
            raise StationarityCriticError("critic header is truncated")
        try:
            header = json.loads(value[prefix_bytes:header_end].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StationarityCriticError("critic header is invalid") from exc
        expected_fields = {
            "array_bytes",
            "dimension",
            "episode_count",
            "ridge",
            "schema",
        }
        if not isinstance(header, dict) or set(header) != expected_fields:
            raise StationarityCriticError("critic header field inventory differs")
        if header.get("schema") != STATIONARITY_CRITIC_SCHEMA:
            raise StationarityCriticError("critic schema differs")
        try:
            dimension = _dimension(header["dimension"])
            ridge = _positive_finite(header["ridge"], "ridge")
        except (KeyError, TypeError, ValueError) as exc:
            raise StationarityCriticError("critic header values differ") from exc
        episode_count = header.get("episode_count")
        if (
            isinstance(episode_count, bool)
            or not isinstance(episode_count, int)
            or not 0 <= episode_count <= MAX_EPISODE_COUNT
        ):
            raise StationarityCriticError("critic episode_count differs")
        expected_array_bytes = [dimension * 8, dimension**2 * 8, dimension**2 * 8]
        if header.get("array_bytes") != expected_array_bytes:
            raise StationarityCriticError("critic array byte inventory differs")
        expected_length = header_end + sum(expected_array_bytes)
        if len(value) != expected_length:
            raise StationarityCriticError("critic payload byte inventory differs")

        mean_end = header_end + expected_array_bytes[0]
        m2_end = mean_end + expected_array_bytes[1]
        try:
            result = cls(
                dimension=dimension,
                ridge=ridge,
                episode_count=episode_count,
                mean_weights=np.frombuffer(
                    value[header_end:mean_end],
                    dtype="<f8",
                ).copy(),
                m2_weights=np.frombuffer(
                    value[mean_end:m2_end],
                    dtype="<f8",
                )
                .reshape(dimension, dimension)
                .copy(),
                pooled_design_inverse=np.frombuffer(
                    value[m2_end:],
                    dtype="<f8",
                )
                .reshape(dimension, dimension)
                .copy(),
            )
        except (TypeError, ValueError) as exc:
            raise StationarityCriticError("critic array payload differs") from exc
        if result.to_bytes() != value:
            raise StationarityCriticError("critic payload is not canonical")
        return result

    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()
