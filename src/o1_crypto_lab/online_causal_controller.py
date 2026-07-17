"""Self-learning online O1 controller for paired full-256 causal actions.

The controller deliberately does not prescribe a cryptanalytic scalar.  It
streams the complete public paired-prefix field through a stateful O1 core,
learns a shared reader on known/revealed keys, and learns action utility from
realized 256-bit log-loss reduction.  A mirrored twin stream makes orientation
antisymmetry structural instead of a hoped-for training outcome.

Unknown targets may update only bounded label-free fast state.  Reader and
utility-critic parameters change only on known BUILD episodes or after reveal,
and therefore affect the next target rather than rescore the current one.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

from .full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from .living_inverse import canonical_json_bytes
from .o1_streaming_core import (
    O1FastState,
    O1StreamingCoreConfig,
    StreamingO1KeyReader,
    require_torch,
    torch,
)
from .orchestrator import DatasetSplit, ExperimentProposal


KEY_BITS = 256
ONLINE_CONTROLLER_SCHEMA = "o1-256-online-causal-controller-v1"
ONLINE_FAST_STATE_SCHEMA = "o1-256-online-causal-fast-state-v1"
ONLINE_FAST_STATE_MAGIC = b"O1OCF1\x00"
UTILITY_CRITIC_SCHEMA = "o1-256-bounded-linucb-v1"
CRITIC_CONTEXT_DIMENSION = 8
ADDRESS_HARMONIC_PAIRS = 6


class OnlineCausalControllerError(ValueError):
    """A controller contract, action, observation, or state differs."""


def _finite_float(
    value: object,
    field: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise OnlineCausalControllerError(f"{field} must be finite")
    result = float(value)
    if minimum is not None and result < minimum:
        raise OnlineCausalControllerError(f"{field} is below its minimum")
    if maximum is not None and result > maximum:
        raise OnlineCausalControllerError(f"{field} exceeds its maximum")
    return result


def _positive_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise OnlineCausalControllerError(
            f"{field} must be an integer in [1,{maximum}]"
        )
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise OnlineCausalControllerError(f"{field} must be a lowercase SHA-256")
    return value


def _readonly_float32(
    value: np.ndarray, shape: tuple[int, ...], field: str
) -> np.ndarray:
    result = np.asarray(value)
    if (
        result.shape != shape
        or result.dtype != np.float32
        or not np.all(np.isfinite(result))
    ):
        raise OnlineCausalControllerError(
            f"{field} must be finite float32{list(shape)}"
        )
    result = np.array(result, dtype=np.float32, order="C", copy=True)
    result.setflags(write=False)
    return result


@dataclass(frozen=True)
class OnlineCausalControllerConfig:
    """Fixed architecture and update rules for one controller lineage."""

    horizons: tuple[int, ...] = (64, 96, 65)
    feature_dimension: int = BRANCH_FEATURES
    nuisance_rank: int = 4
    nuisance_learning_rate: float = 1.0 / 32.0
    nuisance_warmup: int = 8
    residual_clip: float = 6.0
    variance_floor: float = 0.25
    model_dimension: int = 64
    heads: int = 4
    head_dimension: int = 16
    holographic_slots: int = 4
    feedforward_dimension: int = 128
    phase_scale: float = math.pi
    reader_learning_rate: float = 3e-4
    recall_loss_weight: float = 1.0
    gradient_chunk_actions: int = 8
    gradient_clip: float = 5.0
    critic_ridge: float = 1.0
    critic_exploration: float = 0.25
    critic_reward_clip: float = 4.0
    critic_work_scale: float = 128.0
    coverage_weight: float = 0.25
    posterior_epsilon: float = 2.0**-20
    posterior_logit_clip: float = 16.0
    cpu_threads: int = 1
    seed: int = 170017

    def __post_init__(self) -> None:
        if (
            not isinstance(self.horizons, tuple)
            or not self.horizons
            or len(self.horizons) > 8
            or len(set(self.horizons)) != len(self.horizons)
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 1_000_000
                for value in self.horizons
            )
        ):
            raise OnlineCausalControllerError(
                "horizons must be unique positive integers"
            )
        _positive_int(self.feature_dimension, "feature_dimension", 4096)
        if self.feature_dimension != BRANCH_FEATURES:
            raise OnlineCausalControllerError(
                f"feature_dimension must preserve all {BRANCH_FEATURES} raw channels"
            )
        for field, value, maximum in (
            ("nuisance_rank", self.nuisance_rank, 32),
            ("nuisance_warmup", self.nuisance_warmup, 1_000_000),
            ("model_dimension", self.model_dimension, 4096),
            ("heads", self.heads, 64),
            ("head_dimension", self.head_dimension, 1024),
            ("holographic_slots", self.holographic_slots, 64),
            ("feedforward_dimension", self.feedforward_dimension, 16384),
            ("gradient_chunk_actions", self.gradient_chunk_actions, 4096),
            ("cpu_threads", self.cpu_threads, 8),
        ):
            _positive_int(value, field, maximum)
        for field, value, minimum, maximum in (
            ("nuisance_learning_rate", self.nuisance_learning_rate, 1e-8, 1.0),
            ("residual_clip", self.residual_clip, 0.1, 100.0),
            ("variance_floor", self.variance_floor, 1e-8, 100.0),
            ("phase_scale", self.phase_scale, 1e-8, 8.0 * math.pi),
            ("reader_learning_rate", self.reader_learning_rate, 1e-8, 1.0),
            ("recall_loss_weight", self.recall_loss_weight, 0.0, 1e8),
            ("gradient_clip", self.gradient_clip, 1e-8, 1_000.0),
            ("critic_ridge", self.critic_ridge, 1e-8, 1e8),
            ("critic_exploration", self.critic_exploration, 0.0, 1e8),
            ("critic_reward_clip", self.critic_reward_clip, 1e-8, 1e8),
            ("critic_work_scale", self.critic_work_scale, 1e-8, 1e8),
            ("coverage_weight", self.coverage_weight, 0.0, 1e8),
            ("posterior_epsilon", self.posterior_epsilon, 1e-12, 0.1),
            ("posterior_logit_clip", self.posterior_logit_clip, 1.0, 1e6),
        ):
            _finite_float(value, field, minimum=minimum, maximum=maximum)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise OnlineCausalControllerError("seed must be an integer")

    @property
    def horizon_count(self) -> int:
        return len(self.horizons)

    @property
    def event_dimension(self) -> int:
        # Signed/common is an invertible view of the two polarities.  O1 sees
        # both the normalized raw signed field and its label-free Oja residual,
        # so nuisance removal is an option it may learn to use, not a mandated
        # hand-authored bottleneck.
        return 3 * self.feature_dimension + self.horizon_count + 4

    @property
    def address_dimension(self) -> int:
        return 2 * ADDRESS_HARMONIC_PAIRS + self.horizon_count + 4

    @property
    def maximum_actions(self) -> int:
        return self.horizon_count * KEY_BITS

    @property
    def fast_state_numeric_bytes(self) -> int:
        h = self.horizon_count
        f = self.feature_dimension
        r = self.nuisance_rank
        return (
            2 * self.o1_config.fast_state_bytes()
            + 2 * 8  # action_count and steps
            + 1  # reveal-consumed flag
            + h * 8  # label-free sample counts
            + 4 * h * f * 8  # running signed/common means and M2
            + h * r * f * 8  # Oja basis
            + 2 * KEY_BITS * 4  # posterior logits and precision
            + h * KEY_BITS * 2  # coverage
            + h * KEY_BITS * 4  # last-selected step
            + self.maximum_actions * 2  # fixed action ledger
        )

    @property
    def o1_config(self) -> O1StreamingCoreConfig:
        return O1StreamingCoreConfig(
            event_dimension=self.event_dimension,
            address_dimension=self.address_dimension,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            phase_scale=self.phase_scale,
            seed=self.seed,
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": ONLINE_CONTROLLER_SCHEMA,
            "horizons": list(self.horizons),
            "feature_dimension": self.feature_dimension,
            "nuisance_rank": self.nuisance_rank,
            "nuisance_learning_rate": self.nuisance_learning_rate,
            "nuisance_warmup": self.nuisance_warmup,
            "residual_clip": self.residual_clip,
            "variance_floor": self.variance_floor,
            "reader_learning_rate": self.reader_learning_rate,
            "recall_loss_weight": self.recall_loss_weight,
            "gradient_chunk_actions": self.gradient_chunk_actions,
            "gradient_clip": self.gradient_clip,
            "critic_ridge": self.critic_ridge,
            "critic_exploration": self.critic_exploration,
            "critic_reward_clip": self.critic_reward_clip,
            "critic_work_scale": self.critic_work_scale,
            "coverage_weight": self.coverage_weight,
            "posterior_epsilon": self.posterior_epsilon,
            "posterior_logit_clip": self.posterior_logit_clip,
            "cpu_threads": self.cpu_threads,
            "seed": self.seed,
            "o1": self.o1_config.describe(),
            "fast_state_numeric_bytes": self.fast_state_numeric_bytes,
            "stream_length_dependent_fast_state": False,
            "minimum_coordinate_coverage_gate": True,
            "mirrored_streams": True,
            "current_target_supervised_updates": 0,
            "slow_updates": "known-build-or-after-reveal-only",
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.describe())).hexdigest()


@dataclass(frozen=True, order=True)
class CausalAction:
    bit_index: int
    horizon: int

    def validate(self, config: OnlineCausalControllerConfig) -> None:
        if (
            isinstance(self.bit_index, bool)
            or not isinstance(self.bit_index, int)
            or not 0 <= self.bit_index < KEY_BITS
        ):
            raise OnlineCausalControllerError("bit_index must be in [0,255]")
        if self.horizon not in config.horizons:
            raise OnlineCausalControllerError("action horizon is not configured")

    def flat_index(self, config: OnlineCausalControllerConfig) -> int:
        self.validate(config)
        return config.horizons.index(self.horizon) * KEY_BITS + self.bit_index

    @classmethod
    def from_flat_index(
        cls, value: int, config: OnlineCausalControllerConfig
    ) -> "CausalAction":
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value < config.maximum_actions
        ):
            raise OnlineCausalControllerError("flat action index is outside the field")
        horizon_index, bit_index = divmod(value, KEY_BITS)
        return cls(bit_index=bit_index, horizon=config.horizons[horizon_index])

    def stable_sha256(
        self, config: OnlineCausalControllerConfig, source_stream_sha256: str
    ) -> str:
        _sha256(source_stream_sha256, "source_stream_sha256")
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "o1-256-causal-action-v1",
                    "bit_index": self.bit_index,
                    "horizon": self.horizon,
                    "controller_sha256": config.sha256,
                    "source_stream_sha256": source_stream_sha256,
                }
            )
        ).hexdigest()

    def pool_blind_tiebreak_sha256(self, config: OnlineCausalControllerConfig) -> str:
        """Bind policy tie order to architecture/action, never pool contents."""

        self.validate(config)
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "o1-256-pool-blind-action-tiebreak-v1",
                    "bit_index": self.bit_index,
                    "horizon": self.horizon,
                    "controller_sha256": config.sha256,
                }
            )
        ).hexdigest()


@dataclass(frozen=True)
class PairedCausalObservation:
    action: CausalAction
    zero_features: np.ndarray
    one_features: np.ndarray
    work_units: int
    pair_sha256: str
    source_stream_sha256: str

    def __post_init__(self) -> None:
        zero = _readonly_float32(
            self.zero_features, (BRANCH_FEATURES,), "zero_features"
        )
        one = _readonly_float32(self.one_features, (BRANCH_FEATURES,), "one_features")
        _positive_int(self.work_units, "work_units", 2_000_000_000)
        _sha256(self.pair_sha256, "pair_sha256")
        _sha256(self.source_stream_sha256, "source_stream_sha256")
        object.__setattr__(self, "zero_features", zero)
        object.__setattr__(self, "one_features", one)

    @classmethod
    def from_pool(
        cls, pool: Full256ActionPool, action: CausalAction
    ) -> "PairedCausalObservation":
        if not isinstance(pool, Full256ActionPool):
            raise TypeError("pool must be Full256ActionPool")
        if action.horizon not in pool.horizons:
            raise OnlineCausalControllerError("action horizon is absent from pool")
        if not 0 <= action.bit_index < KEY_BITS:
            raise OnlineCausalControllerError("action bit is outside pool")
        horizon_index = pool.horizons.index(action.horizon)
        return cls(
            action=action,
            zero_features=pool.branch_features[horizon_index, action.bit_index, 0],
            one_features=pool.branch_features[horizon_index, action.bit_index, 1],
            work_units=2 * action.horizon,
            pair_sha256=pool.pair_sha256[action.bit_index],
            source_stream_sha256=pool.source_stream_sha256,
        )

    @property
    def signed(self) -> np.ndarray:
        return np.subtract(self.one_features, self.zero_features, dtype=np.float32)

    @property
    def common(self) -> np.ndarray:
        result = np.add(self.one_features, self.zero_features, dtype=np.float32)
        result *= np.float32(0.5)
        return result

    def polarity_swapped(self) -> "PairedCausalObservation":
        return PairedCausalObservation(
            action=self.action,
            zero_features=self.one_features,
            one_features=self.zero_features,
            work_units=self.work_units,
            pair_sha256=self.pair_sha256,
            source_stream_sha256=self.source_stream_sha256,
        )


@dataclass
class OnlineNuisanceState:
    """Bounded label-free centering, scaling, and rank-r Oja state."""

    counts: np.ndarray
    signed_mean: np.ndarray
    signed_m2: np.ndarray
    common_mean: np.ndarray
    common_m2: np.ndarray
    basis: np.ndarray

    @classmethod
    def initial(cls, config: OnlineCausalControllerConfig) -> "OnlineNuisanceState":
        shape = (config.horizon_count, config.feature_dimension)
        generator = np.random.Generator(np.random.PCG64(config.seed ^ 0x4F4A41))
        raw = generator.standard_normal(
            (config.horizon_count, config.nuisance_rank, config.feature_dimension)
        )
        basis = np.empty_like(raw, dtype=np.float64)
        for horizon_index in range(config.horizon_count):
            q, _r = np.linalg.qr(raw[horizon_index].T, mode="reduced")
            basis[horizon_index] = q.T
        return cls(
            counts=np.zeros(config.horizon_count, dtype=np.uint64),
            signed_mean=np.zeros(shape, dtype=np.float64),
            signed_m2=np.zeros(shape, dtype=np.float64),
            common_mean=np.zeros(shape, dtype=np.float64),
            common_m2=np.zeros(shape, dtype=np.float64),
            basis=basis,
        )

    def clone(self) -> "OnlineNuisanceState":
        return OnlineNuisanceState(
            counts=self.counts.copy(),
            signed_mean=self.signed_mean.copy(),
            signed_m2=self.signed_m2.copy(),
            common_mean=self.common_mean.copy(),
            common_m2=self.common_m2.copy(),
            basis=self.basis.copy(),
        )

    def validate(self, config: OnlineCausalControllerConfig) -> None:
        h = config.horizon_count
        f = config.feature_dimension
        r = config.nuisance_rank
        expected = (
            ("counts", self.counts, (h,), np.uint64),
            ("signed_mean", self.signed_mean, (h, f), np.float64),
            ("signed_m2", self.signed_m2, (h, f), np.float64),
            ("common_mean", self.common_mean, (h, f), np.float64),
            ("common_m2", self.common_m2, (h, f), np.float64),
            ("basis", self.basis, (h, r, f), np.float64),
        )
        for name, value, shape, dtype in expected:
            if (
                not isinstance(value, np.ndarray)
                or value.shape != shape
                or value.dtype != dtype
                or (name != "counts" and not np.all(np.isfinite(value)))
            ):
                raise OnlineCausalControllerError(f"nuisance {name} differs")
        if np.any(self.signed_m2 < -1e-10) or np.any(self.common_m2 < -1e-10):
            raise OnlineCausalControllerError(
                "nuisance variance accumulator is negative"
            )

    def transform(
        self,
        signed: np.ndarray,
        common: np.ndarray,
        horizon_index: int,
        config: OnlineCausalControllerConfig,
        *,
        update: bool,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Return raw odd, residual odd, and even views; update uses no labels."""

        self.validate(config)
        signed_value = np.asarray(signed, dtype=np.float64)
        common_value = np.asarray(common, dtype=np.float64)
        expected = (config.feature_dimension,)
        if (
            signed_value.shape != expected
            or common_value.shape != expected
            or not np.all(np.isfinite(signed_value))
            or not np.all(np.isfinite(common_value))
            or not 0 <= horizon_index < config.horizon_count
        ):
            raise OnlineCausalControllerError("nuisance input field differs")

        odd_raw = np.arcsinh(signed_value)
        even_raw = np.arcsinh(common_value)
        count = int(self.counts[horizon_index])
        if count >= 2:
            odd_scale = np.sqrt(
                np.maximum(
                    self.signed_m2[horizon_index] / (count - 1),
                    config.variance_floor**2,
                )
            )
            even_scale = np.sqrt(
                np.maximum(
                    self.common_m2[horizon_index] / (count - 1),
                    config.variance_floor**2,
                )
            )
            odd_centered = (odd_raw - self.signed_mean[horizon_index]) / odd_scale
            even_centered = (even_raw - self.common_mean[horizon_index]) / even_scale
        else:
            odd_centered = odd_raw
            even_centered = even_raw

        even_bounded = np.tanh(even_centered / config.residual_clip)
        invariant_gate = 1.0 / np.sqrt(1.0 + 0.0625 * even_bounded * even_bounded)
        odd_bounded = np.tanh(odd_centered / config.residual_clip) * invariant_gate
        if count >= config.nuisance_warmup:
            basis = self.basis[horizon_index]
            odd_residual = odd_bounded - basis.T @ (basis @ odd_bounded)
        else:
            odd_residual = odd_bounded

        if update:
            new_count = count + 1
            signed_delta = odd_raw - self.signed_mean[horizon_index]
            self.signed_mean[horizon_index] += signed_delta / new_count
            self.signed_m2[horizon_index] += signed_delta * (
                odd_raw - self.signed_mean[horizon_index]
            )
            common_delta = even_raw - self.common_mean[horizon_index]
            self.common_mean[horizon_index] += common_delta / new_count
            self.common_m2[horizon_index] += common_delta * (
                even_raw - self.common_mean[horizon_index]
            )
            self.counts[horizon_index] = np.uint64(new_count)
            x = odd_bounded
            for row_index in range(config.nuisance_rank):
                vector = self.basis[horizon_index, row_index]
                response = float(np.dot(vector, x))
                vector += config.nuisance_learning_rate * (
                    response * x - response * response * vector
                )
                for previous in range(row_index):
                    prior = self.basis[horizon_index, previous]
                    vector -= float(np.dot(vector, prior)) * prior
                norm = float(np.linalg.norm(vector))
                if norm > 1e-12:
                    vector /= norm
            self.validate(config)

        odd_primary = np.asarray(odd_bounded, dtype=np.float32)
        odd_result = np.asarray(odd_residual, dtype=np.float32)
        even_result = np.asarray(even_bounded, dtype=np.float32)
        return odd_primary, odd_result, even_result


@dataclass
class BoundedLinUCBCritic:
    """Fixed-size deterministic RLS/LinUCB action-value learner."""

    a_inverse: np.ndarray
    b: np.ndarray
    updates: int

    @classmethod
    def initial(cls, config: OnlineCausalControllerConfig) -> "BoundedLinUCBCritic":
        return cls(
            a_inverse=np.eye(CRITIC_CONTEXT_DIMENSION, dtype=np.float64)
            / config.critic_ridge,
            b=np.zeros(CRITIC_CONTEXT_DIMENSION, dtype=np.float64),
            updates=0,
        )

    def clone(self) -> "BoundedLinUCBCritic":
        return BoundedLinUCBCritic(
            a_inverse=self.a_inverse.copy(),
            b=self.b.copy(),
            updates=self.updates,
        )

    def validate(self) -> None:
        if (
            self.a_inverse.shape != (CRITIC_CONTEXT_DIMENSION, CRITIC_CONTEXT_DIMENSION)
            or self.a_inverse.dtype != np.float64
            or self.b.shape != (CRITIC_CONTEXT_DIMENSION,)
            or self.b.dtype != np.float64
            or not np.all(np.isfinite(self.a_inverse))
            or not np.all(np.isfinite(self.b))
            or isinstance(self.updates, bool)
            or not isinstance(self.updates, int)
            or self.updates < 0
        ):
            raise OnlineCausalControllerError("utility critic state differs")
        if not np.allclose(self.a_inverse, self.a_inverse.T, rtol=0.0, atol=1e-10):
            raise OnlineCausalControllerError("utility critic inverse is not symmetric")

    @property
    def weights(self) -> np.ndarray:
        self.validate()
        return self.a_inverse @ self.b

    def predict(
        self, context: np.ndarray, config: OnlineCausalControllerConfig
    ) -> tuple[float, float]:
        self.validate()
        value = np.asarray(context, dtype=np.float64)
        if value.shape != (CRITIC_CONTEXT_DIMENSION,) or not np.all(np.isfinite(value)):
            raise OnlineCausalControllerError("critic context differs")
        mean = float(np.dot(self.weights, value))
        variance = max(float(value @ self.a_inverse @ value), 0.0)
        return mean, config.critic_exploration * math.sqrt(variance)

    def update(
        self,
        context: np.ndarray,
        reward: float,
        config: OnlineCausalControllerConfig,
    ) -> None:
        value = np.asarray(context, dtype=np.float64)
        if value.shape != (CRITIC_CONTEXT_DIMENSION,) or not np.all(np.isfinite(value)):
            raise OnlineCausalControllerError("critic context differs")
        target = float(
            np.clip(
                _finite_float(reward, "reward"),
                -config.critic_reward_clip,
                config.critic_reward_clip,
            )
        )
        projected = self.a_inverse @ value
        denominator = 1.0 + float(value @ projected)
        if not math.isfinite(denominator) or denominator <= 0.0:
            raise OnlineCausalControllerError("critic RLS denominator is invalid")
        self.a_inverse -= np.outer(projected, projected) / denominator
        self.a_inverse[:] = 0.5 * (self.a_inverse + self.a_inverse.T)
        self.b += value * target
        self.updates += 1
        self.validate()

    def to_bytes(self) -> bytes:
        self.validate()
        metadata = canonical_json_bytes(
            {
                "schema": UTILITY_CRITIC_SCHEMA,
                "dimension": CRITIC_CONTEXT_DIMENSION,
                "updates": self.updates,
            }
        )
        return (
            struct.pack(">Q", len(metadata))
            + metadata
            + self.a_inverse.astype("<f8", copy=False).tobytes(order="C")
            + self.b.astype("<f8", copy=False).tobytes(order="C")
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> "BoundedLinUCBCritic":
        if not isinstance(value, bytes) or len(value) < 8:
            raise OnlineCausalControllerError("critic payload is truncated")
        header_length = struct.unpack(">Q", value[:8])[0]
        end_header = 8 + header_length
        try:
            header = json.loads(value[8:end_header].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OnlineCausalControllerError("critic header is invalid") from exc
        expected_fields = {"schema", "dimension", "updates"}
        matrix_bytes = CRITIC_CONTEXT_DIMENSION**2 * 8
        vector_bytes = CRITIC_CONTEXT_DIMENSION * 8
        if (
            not isinstance(header, dict)
            or set(header) != expected_fields
            or header.get("schema") != UTILITY_CRITIC_SCHEMA
            or header.get("dimension") != CRITIC_CONTEXT_DIMENSION
            or len(value) != end_header + matrix_bytes + vector_bytes
        ):
            raise OnlineCausalControllerError("critic schema differs")
        matrix_end = end_header + matrix_bytes
        try:
            result = cls(
                a_inverse=np.frombuffer(value[end_header:matrix_end], dtype="<f8")
                .reshape(CRITIC_CONTEXT_DIMENSION, CRITIC_CONTEXT_DIMENSION)
                .copy(),
                b=np.frombuffer(value[matrix_end:], dtype="<f8").copy(),
                updates=int(header["updates"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OnlineCausalControllerError("critic fields differ") from exc
        result.validate()
        if result.to_bytes() != value:
            raise OnlineCausalControllerError("critic payload is not canonical")
        return result


@dataclass
class OnlineCausalFastState:
    """One target's bounded state; no label or unbounded transcript is retained."""

    source_stream_sha256: str
    slow_state_sha256: str
    positive_o1: O1FastState
    negative_o1: O1FastState
    nuisance: OnlineNuisanceState
    posterior_logits: np.ndarray
    posterior_precision: np.ndarray
    coverage: np.ndarray
    last_selected: np.ndarray
    action_order: np.ndarray
    action_count: int = 0
    steps: int = 0
    reveal_consumed: bool = False

    def validate(self, config: OnlineCausalControllerConfig) -> None:
        _sha256(self.source_stream_sha256, "source_stream_sha256")
        _sha256(self.slow_state_sha256, "slow_state_sha256")
        self.positive_o1.validate(config.o1_config)
        self.negative_o1.validate(config.o1_config)
        if self.positive_o1.batch_size != 1 or self.negative_o1.batch_size != 1:
            raise OnlineCausalControllerError("online O1 state batch must be one")
        self.nuisance.validate(config)
        arrays = (
            (
                "posterior_logits",
                self.posterior_logits,
                (KEY_BITS,),
                np.float32,
                True,
            ),
            (
                "posterior_precision",
                self.posterior_precision,
                (KEY_BITS,),
                np.float32,
                True,
            ),
            (
                "coverage",
                self.coverage,
                (config.horizon_count, KEY_BITS),
                np.uint16,
                False,
            ),
            (
                "last_selected",
                self.last_selected,
                (config.horizon_count, KEY_BITS),
                np.uint32,
                False,
            ),
            (
                "action_order",
                self.action_order,
                (config.maximum_actions,),
                np.uint16,
                False,
            ),
        )
        for name, value, shape, dtype, finite in arrays:
            if (
                not isinstance(value, np.ndarray)
                or value.shape != shape
                or value.dtype != dtype
                or (finite and not np.all(np.isfinite(value)))
            ):
                raise OnlineCausalControllerError(f"fast state {name} differs")
        if np.any(self.posterior_precision < 0.0):
            raise OnlineCausalControllerError(
                "posterior precision must be non-negative"
            )
        for name, value, maximum in (
            ("action_count", self.action_count, config.maximum_actions),
            ("steps", self.steps, np.iinfo(np.uint32).max),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= maximum
            ):
                raise OnlineCausalControllerError(f"fast state {name} differs")
        if self.action_count != self.steps:
            raise OnlineCausalControllerError("one unique action is required per step")
        if not isinstance(self.reveal_consumed, bool):
            raise OnlineCausalControllerError("reveal_consumed must be boolean")
        used = self.action_order[: self.action_count]
        unused = self.action_order[self.action_count :]
        if (
            len(set(int(value) for value in used)) != self.action_count
            or np.any(used >= config.maximum_actions)
            or np.any(unused != np.iinfo(np.uint16).max)
            or int(self.coverage.sum(dtype=np.uint64)) != self.action_count
        ):
            raise OnlineCausalControllerError("fast action ledger differs")
        expected_coverage = np.zeros_like(self.coverage)
        expected_last_selected = np.zeros_like(self.last_selected)
        for step, flat_index in enumerate(used, start=1):
            action = CausalAction.from_flat_index(int(flat_index), config)
            horizon_index = config.horizons.index(action.horizon)
            expected_coverage[horizon_index, action.bit_index] = np.uint16(1)
            expected_last_selected[horizon_index, action.bit_index] = np.uint32(step)
        if not np.array_equal(self.coverage, expected_coverage) or not np.array_equal(
            self.last_selected, expected_last_selected
        ):
            raise OnlineCausalControllerError(
                "fast coverage and selection clocks differ from the action ledger"
            )
        if not np.array_equal(
            self.nuisance.counts,
            self.coverage.sum(axis=1, dtype=np.uint64),
        ):
            raise OnlineCausalControllerError(
                "nuisance counts differ from the action ledger"
            )
        uncovered = self.coverage.sum(axis=0, dtype=np.uint64) == 0
        if np.any(self.posterior_logits[uncovered] != 0.0) or np.any(
            self.posterior_precision[uncovered] != 0.0
        ):
            raise OnlineCausalControllerError(
                "uncovered posterior registers must remain exactly zero"
            )

    def clone(self) -> "OnlineCausalFastState":
        return OnlineCausalFastState(
            source_stream_sha256=self.source_stream_sha256,
            slow_state_sha256=self.slow_state_sha256,
            positive_o1=self.positive_o1.clone(),
            negative_o1=self.negative_o1.clone(),
            nuisance=self.nuisance.clone(),
            posterior_logits=self.posterior_logits.copy(),
            posterior_precision=self.posterior_precision.copy(),
            coverage=self.coverage.copy(),
            last_selected=self.last_selected.copy(),
            action_order=self.action_order.copy(),
            action_count=self.action_count,
            steps=self.steps,
            reveal_consumed=self.reveal_consumed,
        )

    def probabilities(self, config: OnlineCausalControllerConfig) -> np.ndarray:
        self.validate(config)
        logits = self.posterior_logits.astype(np.float64)
        probabilities = np.empty_like(logits)
        positive = logits >= 0.0
        probabilities[positive] = 1.0 / (1.0 + np.exp(-logits[positive]))
        exponent = np.exp(logits[~positive])
        probabilities[~positive] = exponent / (1.0 + exponent)
        return np.clip(
            probabilities,
            config.posterior_epsilon,
            1.0 - config.posterior_epsilon,
        )

    def to_bytes(self, config: OnlineCausalControllerConfig) -> bytes:
        self.validate(config)
        arrays = (
            np.asarray((self.action_count, self.steps), dtype="<u8"),
            np.asarray((int(self.reveal_consumed),), dtype=np.uint8),
            self.nuisance.counts.astype("<u8", copy=False),
            self.nuisance.signed_mean.astype("<f8", copy=False),
            self.nuisance.signed_m2.astype("<f8", copy=False),
            self.nuisance.common_mean.astype("<f8", copy=False),
            self.nuisance.common_m2.astype("<f8", copy=False),
            self.nuisance.basis.astype("<f8", copy=False),
            self.posterior_logits.astype("<f4", copy=False),
            self.posterior_precision.astype("<f4", copy=False),
            self.coverage.astype("<u2", copy=False),
            self.last_selected.astype("<u4", copy=False),
            self.action_order.astype("<u2", copy=False),
        )
        header = canonical_json_bytes(
            {
                "schema": ONLINE_FAST_STATE_SCHEMA,
                "controller_sha256": config.sha256,
                "source_stream_sha256": self.source_stream_sha256,
                "slow_state_sha256": self.slow_state_sha256,
                "array_bytes": [int(value.nbytes) for value in arrays],
                "o1_state_bytes_each": config.o1_config.fast_state_bytes(),
            }
        )
        payload = b"".join(value.tobytes(order="C") for value in arrays)
        return (
            ONLINE_FAST_STATE_MAGIC
            + struct.pack(">Q", len(header))
            + header
            + self.positive_o1.to_bytes(config.o1_config)
            + self.negative_o1.to_bytes(config.o1_config)
            + payload
        )

    def sha256(self, config: OnlineCausalControllerConfig) -> str:
        return hashlib.sha256(self.to_bytes(config)).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        value: bytes,
        config: OnlineCausalControllerConfig,
        *,
        device: object = "cpu",
    ) -> "OnlineCausalFastState":
        if not isinstance(value, bytes) or not value.startswith(
            ONLINE_FAST_STATE_MAGIC
        ):
            raise OnlineCausalControllerError("online fast-state magic differs")
        cursor = len(ONLINE_FAST_STATE_MAGIC)
        if len(value) < cursor + 8:
            raise OnlineCausalControllerError("online fast-state header is truncated")
        header_length = struct.unpack(">Q", value[cursor : cursor + 8])[0]
        cursor += 8
        end_header = cursor + header_length
        try:
            header = json.loads(value[cursor:end_header].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OnlineCausalControllerError(
                "online fast-state header is invalid"
            ) from exc
        cursor = end_header
        expected_fields = {
            "schema",
            "controller_sha256",
            "source_stream_sha256",
            "slow_state_sha256",
            "array_bytes",
            "o1_state_bytes_each",
        }
        if (
            not isinstance(header, dict)
            or set(header) != expected_fields
            or header.get("schema") != ONLINE_FAST_STATE_SCHEMA
            or header.get("controller_sha256") != config.sha256
            or header.get("o1_state_bytes_each") != config.o1_config.fast_state_bytes()
        ):
            raise OnlineCausalControllerError("online fast-state schema differs")
        o1_bytes = config.o1_config.fast_state_bytes()
        positive = O1FastState.from_bytes(
            value[cursor : cursor + o1_bytes],
            config=config.o1_config,
            batch_size=1,
            device=device,
        )
        cursor += o1_bytes
        negative = O1FastState.from_bytes(
            value[cursor : cursor + o1_bytes],
            config=config.o1_config,
            batch_size=1,
            device=device,
        )
        cursor += o1_bytes
        specifications = (
            ((2,), "<u8"),
            ((1,), "<u1"),
            ((config.horizon_count,), "<u8"),
            ((config.horizon_count, config.feature_dimension), "<f8"),
            ((config.horizon_count, config.feature_dimension), "<f8"),
            ((config.horizon_count, config.feature_dimension), "<f8"),
            ((config.horizon_count, config.feature_dimension), "<f8"),
            (
                (
                    config.horizon_count,
                    config.nuisance_rank,
                    config.feature_dimension,
                ),
                "<f8",
            ),
            ((KEY_BITS,), "<f4"),
            ((KEY_BITS,), "<f4"),
            ((config.horizon_count, KEY_BITS), "<u2"),
            ((config.horizon_count, KEY_BITS), "<u4"),
            ((config.maximum_actions,), "<u2"),
        )
        arrays: list[np.ndarray] = []
        expected_bytes: list[int] = []
        for shape, dtype in specifications:
            byte_count = math.prod(shape) * np.dtype(dtype).itemsize
            expected_bytes.append(byte_count)
            payload = value[cursor : cursor + byte_count]
            if len(payload) != byte_count:
                raise OnlineCausalControllerError(
                    "online fast-state payload is truncated"
                )
            arrays.append(np.frombuffer(payload, dtype=dtype).reshape(shape).copy())
            cursor += byte_count
        if header.get("array_bytes") != expected_bytes or cursor != len(value):
            raise OnlineCausalControllerError(
                "online fast-state byte inventory differs"
            )
        if arrays[1][0] not in (0, 1):
            raise OnlineCausalControllerError("online reveal flag differs")
        nuisance = OnlineNuisanceState(
            counts=arrays[2].astype(np.uint64, copy=False),
            signed_mean=arrays[3].astype(np.float64, copy=False),
            signed_m2=arrays[4].astype(np.float64, copy=False),
            common_mean=arrays[5].astype(np.float64, copy=False),
            common_m2=arrays[6].astype(np.float64, copy=False),
            basis=arrays[7].astype(np.float64, copy=False),
        )
        try:
            result = cls(
                source_stream_sha256=str(header["source_stream_sha256"]),
                slow_state_sha256=str(header["slow_state_sha256"]),
                positive_o1=positive,
                negative_o1=negative,
                nuisance=nuisance,
                posterior_logits=arrays[8].astype(np.float32, copy=False),
                posterior_precision=arrays[9].astype(np.float32, copy=False),
                coverage=arrays[10].astype(np.uint16, copy=False),
                last_selected=arrays[11].astype(np.uint32, copy=False),
                action_order=arrays[12].astype(np.uint16, copy=False),
                action_count=int(arrays[0][0]),
                steps=int(arrays[0][1]),
                reveal_consumed=bool(arrays[1][0]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OnlineCausalControllerError(
                "online fast-state fields differ"
            ) from exc
        result.validate(config)
        if result.to_bytes(config) != value:
            raise OnlineCausalControllerError("online fast-state is not canonical")
        return result


@dataclass(frozen=True)
class ActionChoice:
    action: CausalAction
    score: float
    predicted_reward: float
    exploration_bonus: float
    coverage_debt: float
    context: np.ndarray

    def __post_init__(self) -> None:
        context = _readonly_float32(
            self.context, (CRITIC_CONTEXT_DIMENSION,), "choice context"
        )
        for field in (
            "score",
            "predicted_reward",
            "exploration_bonus",
            "coverage_debt",
        ):
            _finite_float(getattr(self, field), field)
        object.__setattr__(self, "context", context)


@dataclass(frozen=True)
class RevealLearningReport:
    actions: int
    critic_updates: int
    reward_sum_bits: float
    critic_reward_sum: float
    reward_positive_actions: int
    prequential_nll_bits: float
    final_nll_bits: float
    training_loss_bits: tuple[float, ...]
    slow_state_sha256_before: str
    slow_state_sha256_after: str


def _module_bytes(module: object) -> bytes:
    require_torch()
    if not hasattr(module, "state_dict"):
        raise OnlineCausalControllerError("module has no state_dict")
    payload = bytearray()
    state = module.state_dict()
    for name in sorted(state):
        tensor = state[name].detach().to(device="cpu", dtype=torch.float32).contiguous()
        if not bool(torch.isfinite(tensor).all()):
            raise OnlineCausalControllerError(
                f"module parameter {name!r} is not finite"
            )
        name_bytes = name.encode("utf-8")
        payload.extend(struct.pack(">H", len(name_bytes)))
        payload.extend(name_bytes)
        payload.extend(struct.pack(">B", tensor.ndim))
        for dimension in tensor.shape:
            payload.extend(struct.pack(">I", int(dimension)))
        raw = tensor.numpy().astype("<f4", copy=False).tobytes(order="C")
        payload.extend(struct.pack(">Q", len(raw)))
        payload.extend(raw)
    return bytes(payload)


def _load_module_bytes(module: object, value: bytes) -> None:
    """Load an exact canonical float32 state into an existing module."""

    require_torch()
    if not isinstance(value, bytes) or not hasattr(module, "state_dict"):
        raise OnlineCausalControllerError("module payload differs")
    target = module.state_dict()
    parsed: dict[str, object] = {}
    cursor = 0
    while cursor < len(value):
        if cursor + 2 > len(value):
            raise OnlineCausalControllerError("module payload is truncated")
        name_length = struct.unpack(">H", value[cursor : cursor + 2])[0]
        cursor += 2
        end_name = cursor + name_length
        try:
            name = value[cursor:end_name].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OnlineCausalControllerError(
                "module parameter name is invalid"
            ) from exc
        cursor = end_name
        if cursor >= len(value):
            raise OnlineCausalControllerError("module payload is truncated")
        dimensions = value[cursor]
        cursor += 1
        shape: list[int] = []
        for _index in range(dimensions):
            if cursor + 4 > len(value):
                raise OnlineCausalControllerError("module shape is truncated")
            shape.append(struct.unpack(">I", value[cursor : cursor + 4])[0])
            cursor += 4
        if cursor + 8 > len(value):
            raise OnlineCausalControllerError("module length is truncated")
        byte_count = struct.unpack(">Q", value[cursor : cursor + 8])[0]
        cursor += 8
        payload = value[cursor : cursor + byte_count]
        cursor += byte_count
        if len(payload) != byte_count or byte_count != math.prod(shape) * 4:
            raise OnlineCausalControllerError("module tensor payload differs")
        if (
            name in parsed
            or name not in target
            or tuple(target[name].shape) != tuple(shape)
        ):
            raise OnlineCausalControllerError("module parameter inventory differs")
        array = np.frombuffer(payload, dtype="<f4").reshape(shape).copy()
        if not np.all(np.isfinite(array)):
            raise OnlineCausalControllerError(
                f"module parameter {name!r} is not finite"
            )
        parsed[name] = torch.from_numpy(array).to(
            device=target[name].device, dtype=target[name].dtype
        )
    if set(parsed) != set(target):
        raise OnlineCausalControllerError("module parameter set is incomplete")
    module.load_state_dict(parsed, strict=True)
    if _module_bytes(module) != value:
        raise OnlineCausalControllerError("module payload is not canonical")


def _binary_nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        values.shape != (KEY_BITS,)
        or truth.shape != (KEY_BITS,)
        or not np.all(np.isfinite(values))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise OnlineCausalControllerError("NLL inputs differ")
    signed = (2.0 * truth - 1.0) * values
    return float(np.logaddexp(0.0, -signed).sum() / math.log(2.0))


def mobius_contrast(vertices: Sequence[object] | np.ndarray) -> float | np.ndarray:
    """Return the canonical unary, pair, or triple alternating contrast.

    Vertices use ascending binary assignment order: ``[F0,F1]``,
    ``[F00,F01,F10,F11]``, or the analogous eight triple corners.  This
    supplies legal intervention algebra only; learned orientation remains the
    controller's job.
    """

    values = np.asarray(vertices, dtype=np.float64)
    if (
        values.ndim < 1
        or values.shape[0] not in (2, 4, 8)
        or not np.all(np.isfinite(values))
    ):
        raise OnlineCausalControllerError(
            "Möbius vertices require 2, 4, or 8 matched finite corners"
        )
    degree = int(math.log2(values.shape[0]))
    coefficients = np.asarray(
        [
            -1.0 if (degree - index.bit_count()) % 2 else 1.0
            for index in range(values.shape[0])
        ],
        dtype=np.float64,
    )
    result = np.tensordot(coefficients, values, axes=(0, 0))
    if np.ndim(result) == 0:
        return float(result)
    return np.asarray(result, dtype=np.float64)


class OnlineCausalController:
    """Stateful O1 reader plus reveal-delayed learned action picker."""

    def __init__(self, config: OnlineCausalControllerConfig) -> None:
        require_torch()
        if not isinstance(config, OnlineCausalControllerConfig):
            raise TypeError("config must be OnlineCausalControllerConfig")
        self.config = config
        torch.set_num_threads(config.cpu_threads)
        try:
            torch.set_num_interop_threads(1)
        except RuntimeError:
            pass
        torch.use_deterministic_algorithms(True)
        self.reader = StreamingO1KeyReader(config.o1_config)
        self.critic = BoundedLinUCBCritic.initial(config)
        self.episodes = 0

    def validate_pool(self, pool: Full256ActionPool) -> None:
        if not isinstance(pool, Full256ActionPool):
            raise TypeError("pool must be Full256ActionPool")
        if pool.horizons != self.config.horizons:
            raise OnlineCausalControllerError(
                "pool horizon order differs from controller"
            )
        if pool.branch_features.shape[-1] != self.config.feature_dimension:
            raise OnlineCausalControllerError("pool feature width differs")

    def initial_fast_state(self, source_stream_sha256: str) -> OnlineCausalFastState:
        _sha256(source_stream_sha256, "source_stream_sha256")
        initial = self.reader.core.initial_state(1)
        result = OnlineCausalFastState(
            source_stream_sha256=source_stream_sha256,
            slow_state_sha256=self.slow_state_sha256,
            positive_o1=initial.clone(),
            negative_o1=initial.clone(),
            nuisance=OnlineNuisanceState.initial(self.config),
            posterior_logits=np.zeros(KEY_BITS, dtype=np.float32),
            posterior_precision=np.zeros(KEY_BITS, dtype=np.float32),
            coverage=np.zeros((self.config.horizon_count, KEY_BITS), dtype=np.uint16),
            last_selected=np.zeros(
                (self.config.horizon_count, KEY_BITS), dtype=np.uint32
            ),
            action_order=np.full(
                self.config.maximum_actions,
                np.iinfo(np.uint16).max,
                dtype=np.uint16,
            ),
        )
        result.validate(self.config)
        return result

    def _validate_live_state(self, state: OnlineCausalFastState) -> None:
        state.validate(self.config)
        if state.reveal_consumed:
            raise OnlineCausalControllerError("target reveal was already consumed")
        if state.slow_state_sha256 != self.slow_state_sha256:
            raise OnlineCausalControllerError(
                "slow state changed after this target started"
            )

    def slow_state_bytes(self) -> bytes:
        model = _module_bytes(self.reader)
        critic = self.critic.to_bytes()
        metadata = canonical_json_bytes(
            {
                "schema": ONLINE_CONTROLLER_SCHEMA,
                "controller_sha256": self.config.sha256,
                "model_bytes": len(model),
                "critic_bytes": len(critic),
                "episodes": self.episodes,
            }
        )
        return struct.pack(">Q", len(metadata)) + metadata + model + critic

    @property
    def slow_state_sha256(self) -> str:
        return hashlib.sha256(self.slow_state_bytes()).hexdigest()

    def load_slow_state_bytes(self, value: bytes) -> None:
        """Restore a canonical slow checkpoint for deterministic resume."""

        if not isinstance(value, bytes) or len(value) < 8:
            raise OnlineCausalControllerError("slow-state payload is truncated")
        header_length = struct.unpack(">Q", value[:8])[0]
        end_header = 8 + header_length
        try:
            header = json.loads(value[8:end_header].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OnlineCausalControllerError("slow-state header is invalid") from exc
        expected = {
            "schema",
            "controller_sha256",
            "model_bytes",
            "critic_bytes",
            "episodes",
        }
        if (
            not isinstance(header, dict)
            or set(header) != expected
            or header.get("schema") != ONLINE_CONTROLLER_SCHEMA
            or header.get("controller_sha256") != self.config.sha256
            or any(
                isinstance(header.get(field), bool)
                or not isinstance(header.get(field), int)
                for field in ("model_bytes", "critic_bytes", "episodes")
            )
        ):
            raise OnlineCausalControllerError("slow-state schema differs")
        try:
            model_bytes = int(header["model_bytes"])
            critic_bytes = int(header["critic_bytes"])
            episodes = int(header["episodes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise OnlineCausalControllerError("slow-state fields differ") from exc
        if (
            model_bytes < 1
            or critic_bytes < 1
            or episodes < 0
            or end_header + model_bytes + critic_bytes != len(value)
        ):
            raise OnlineCausalControllerError("slow-state byte inventory differs")
        model_payload = value[end_header : end_header + model_bytes]
        critic_payload = value[end_header + model_bytes :]
        old_model = _module_bytes(self.reader)
        old_critic = self.critic
        old_episodes = self.episodes
        try:
            _load_module_bytes(self.reader, model_payload)
            self.critic = BoundedLinUCBCritic.from_bytes(critic_payload)
            self.episodes = episodes
            if self.slow_state_bytes() != value:
                raise OnlineCausalControllerError("slow-state payload is not canonical")
        except Exception:
            _load_module_bytes(self.reader, old_model)
            self.critic = old_critic
            self.episodes = old_episodes
            raise

    def _horizon_index(self, horizon: int) -> int:
        try:
            return self.config.horizons.index(horizon)
        except ValueError as exc:
            raise OnlineCausalControllerError("horizon is not configured") from exc

    def _address(
        self,
        bit_index: int,
        horizon_index: int | None,
        *,
        token_kind: int,
    ) -> np.ndarray:
        if not 0 <= bit_index < KEY_BITS or token_kind not in (0, 1, 2):
            raise OnlineCausalControllerError(
                "address coordinate or token kind differs"
            )
        value = np.zeros(self.config.address_dimension, dtype=np.float32)
        angle = 2.0 * math.pi * (bit_index + 0.5) / KEY_BITS
        cursor = 0
        for frequency in (1, 2, 4, 8, 16, 32):
            value[cursor] = np.float32(math.sin(frequency * angle))
            value[cursor + 1] = np.float32(math.cos(frequency * angle))
            cursor += 2
        if horizon_index is not None:
            if not 0 <= horizon_index < self.config.horizon_count:
                raise OnlineCausalControllerError("address horizon differs")
            value[cursor + horizon_index] = 1.0
        cursor += self.config.horizon_count
        value[cursor] = np.float32((2.0 * bit_index + 1.0) / KEY_BITS - 1.0)
        value[cursor + 1 + token_kind] = 1.0
        return value

    def _event(
        self,
        odd_primary: np.ndarray,
        odd_residual: np.ndarray,
        even: np.ndarray,
        action: CausalAction,
        work_units: int,
        *,
        mirror: bool,
    ) -> np.ndarray:
        horizon_index = self._horizon_index(action.horizon)
        value = np.zeros(self.config.event_dimension, dtype=np.float32)
        sign = np.float32(-1.0 if mirror else 1.0)
        value[: self.config.feature_dimension] = sign * odd_primary
        start = self.config.feature_dimension
        value[start : 2 * start] = sign * odd_residual
        value[2 * start : 3 * start] = even
        cursor = 3 * start
        value[cursor + horizon_index] = 1.0
        cursor += self.config.horizon_count
        value[cursor] = np.float32((2.0 * action.bit_index + 1.0) / KEY_BITS - 1.0)
        value[cursor + 1] = np.float32(math.log1p(work_units) / 16.0)
        value[cursor + 2] = 1.0
        # The final reserved channel is deliberately polarity-even zero.  The
        # mirrored streams may differ only through the odd residual field.
        return value

    def _run_stream(
        self,
        events: np.ndarray,
        addresses: np.ndarray,
        update_mask: np.ndarray,
        state: O1FastState,
    ) -> tuple[object, O1FastState]:
        event_tensor = torch.from_numpy(
            np.ascontiguousarray(events[None], dtype=np.float32)
        )
        address_tensor = torch.from_numpy(
            np.ascontiguousarray(addresses[None], dtype=np.float32)
        )
        mask_tensor = torch.from_numpy(
            np.ascontiguousarray(update_mask[None], dtype=np.bool_)
        )
        return self.reader(event_tensor, address_tensor, mask_tensor, state)

    def _query_coordinates_torch(
        self,
        positive: O1FastState,
        negative: O1FastState,
        coordinates: Sequence[int],
    ) -> object:
        bits = tuple(coordinates)
        if not bits or any(
            isinstance(bit, bool) or not isinstance(bit, int) or not 0 <= bit < KEY_BITS
            for bit in bits
        ):
            raise OnlineCausalControllerError("query coordinates differ")
        events = np.zeros((len(bits), self.config.event_dimension), dtype=np.float32)
        addresses = np.stack([self._address(bit, None, token_kind=2) for bit in bits])
        mask = np.zeros(len(bits), dtype=np.bool_)
        positive_logits, held_positive = self._run_stream(
            events, addresses, mask, positive
        )
        negative_logits, held_negative = self._run_stream(
            events, addresses, mask, negative
        )
        if held_positive.to_bytes(self.config.o1_config) != positive.to_bytes(
            self.config.o1_config
        ) or held_negative.to_bytes(self.config.o1_config) != negative.to_bytes(
            self.config.o1_config
        ):
            raise AssertionError("query mutated carried O1 state")
        return 0.5 * (positive_logits[0] - negative_logits[0])

    def _query_bits_torch(
        self,
        positive: O1FastState,
        negative: O1FastState,
    ) -> object:
        return self._query_coordinates_torch(positive, negative, tuple(range(KEY_BITS)))

    def query_posteriors(self, state: OnlineCausalFastState) -> np.ndarray:
        """Return the exact addressed Bit-Vault without mutating live state."""

        self._validate_live_state(state)
        return state.posterior_logits.copy()

    def query_o1_field(self, state: OnlineCausalFastState) -> np.ndarray:
        """Diagnostic raw holographic field; the vault is the deployed posterior."""

        self._validate_live_state(state)
        self.reader.eval()
        with torch.no_grad():
            logits = self._query_bits_torch(state.positive_o1, state.negative_o1)
        return logits.detach().cpu().numpy().astype(np.float32)

    def observe(
        self,
        state: OnlineCausalFastState,
        observation: PairedCausalObservation,
    ) -> OnlineCausalFastState:
        """Advance label-free fast state by one previously unseen paired action."""

        self._validate_live_state(state)
        observation.action.validate(self.config)
        if observation.source_stream_sha256 != state.source_stream_sha256:
            raise OnlineCausalControllerError(
                "observation source differs from fast state"
            )
        horizon_index = self._horizon_index(observation.action.horizon)
        bit = observation.action.bit_index
        if state.coverage[horizon_index, bit] != 0:
            raise OnlineCausalControllerError("an action cannot be observed twice")
        odd_primary, odd_residual, even = state.nuisance.transform(
            observation.signed,
            observation.common,
            horizon_index,
            self.config,
            update=True,
        )
        positive_event = self._event(
            odd_primary,
            odd_residual,
            even,
            observation.action,
            observation.work_units,
            mirror=False,
        )[None]
        negative_event = self._event(
            odd_primary,
            odd_residual,
            even,
            observation.action,
            observation.work_units,
            mirror=True,
        )[None]
        address = self._address(bit, horizon_index, token_kind=0)[None]
        mask = np.ones(1, dtype=np.bool_)
        self.reader.eval()
        with torch.no_grad():
            _positive_output, positive_state = self._run_stream(
                positive_event, address, mask, state.positive_o1
            )
            _negative_output, negative_state = self._run_stream(
                negative_event, address, mask, state.negative_o1
            )
            evidence = self._query_coordinates_torch(
                positive_state, negative_state, (bit,)
            )[0]
        state.positive_o1 = positive_state.detached()
        state.negative_o1 = negative_state.detached()
        evidence_value = float(evidence.detach().cpu())
        state.posterior_logits[bit] = np.float32(
            np.clip(
                float(state.posterior_logits[bit]) + evidence_value,
                -self.config.posterior_logit_clip,
                self.config.posterior_logit_clip,
            )
        )
        evidence_magnitude = abs(evidence_value)
        state.posterior_precision[bit] += np.float32(
            evidence_magnitude / (1.0 + evidence_magnitude)
        )
        state.coverage[horizon_index, bit] = np.uint16(1)
        state.steps += 1
        state.last_selected[horizon_index, bit] = np.uint32(state.steps)
        state.action_order[state.action_count] = np.uint16(
            observation.action.flat_index(self.config)
        )
        state.action_count += 1
        self._validate_live_state(state)
        return state

    def _action_query_logits(
        self,
        state: OnlineCausalFastState,
        actions: Sequence[CausalAction],
    ) -> tuple[np.ndarray, np.ndarray]:
        if not actions:
            return np.empty(0, dtype=np.float32), np.empty(0, dtype=np.float32)
        events = np.zeros((len(actions), self.config.event_dimension), dtype=np.float32)
        addresses = np.stack(
            [
                self._address(
                    action.bit_index,
                    self._horizon_index(action.horizon),
                    token_kind=1,
                )
                for action in actions
            ]
        )
        mask = np.zeros(len(actions), dtype=np.bool_)
        self.reader.eval()
        with torch.no_grad():
            positive, held_positive = self._run_stream(
                events, addresses, mask, state.positive_o1
            )
            negative, held_negative = self._run_stream(
                events, addresses, mask, state.negative_o1
            )
        if held_positive.to_bytes(self.config.o1_config) != state.positive_o1.to_bytes(
            self.config.o1_config
        ) or held_negative.to_bytes(
            self.config.o1_config
        ) != state.negative_o1.to_bytes(self.config.o1_config):
            raise AssertionError("action query mutated fast state")
        orientation = 0.5 * (positive[0] - negative[0])
        common = 0.5 * (positive[0] + negative[0])
        return (
            orientation.detach().cpu().numpy().astype(np.float32),
            common.detach().cpu().numpy().astype(np.float32),
        )

    def _critic_context(
        self,
        state: OnlineCausalFastState,
        action: CausalAction,
        orientation_query: float,
        common_query: float,
    ) -> np.ndarray:
        horizon_index = self._horizon_index(action.horizon)
        probability = float(state.probabilities(self.config)[action.bit_index])
        entropy = -(
            probability * math.log2(probability)
            + (1.0 - probability) * math.log2(1.0 - probability)
        )
        coordinate_coverage = int(state.coverage[:, action.bit_index].sum())
        coverage_debt = 1.0 / (1.0 + coordinate_coverage)
        age = (
            state.steps + 1 - int(state.last_selected[horizon_index, action.bit_index])
        ) / (state.steps + 1)
        context = np.asarray(
            (
                1.0,
                entropy,
                math.tanh(abs(float(orientation_query))),
                math.tanh(abs(float(common_query))),
                coverage_debt,
                age,
                action.horizon / max(self.config.horizons),
                1.0 / (1.0 + float(state.posterior_precision[action.bit_index])),
            ),
            dtype=np.float32,
        )
        return context

    def choose_action(
        self,
        state: OnlineCausalFastState,
        *,
        allowed_horizons: Iterable[int] | None = None,
    ) -> ActionChoice | None:
        """Pick without seeing unexecuted branch features or current labels."""

        self._validate_live_state(state)
        allowed = (
            set(self.config.horizons)
            if allowed_horizons is None
            else set(allowed_horizons)
        )
        if not allowed <= set(self.config.horizons):
            raise OnlineCausalControllerError(
                "allowed_horizons contains unknown values"
            )
        candidates = [
            CausalAction(bit_index=bit, horizon=horizon)
            for horizon_index, horizon in enumerate(self.config.horizons)
            if horizon in allowed
            for bit in range(KEY_BITS)
            if state.coverage[horizon_index, bit] == 0
        ]
        if not candidates:
            return None
        # Structural exploration floor: learned utility decides *within* the
        # least-covered coordinates, so no key bit can disappear behind an
        # initially unlucky score.  This enforces sampling, never fake signal.
        coordinate_coverage = state.coverage.sum(axis=0, dtype=np.uint64)
        minimum_coverage = min(
            int(coordinate_coverage[action.bit_index]) for action in candidates
        )
        candidates = [
            action
            for action in candidates
            if int(coordinate_coverage[action.bit_index]) == minimum_coverage
        ]
        orientation, common = self._action_query_logits(state, candidates)
        ranked: list[tuple[float, str, ActionChoice]] = []
        for index, action in enumerate(candidates):
            context = self._critic_context(
                state,
                action,
                float(orientation[index]),
                float(common[index]),
            )
            predicted, exploration = self.critic.predict(context, self.config)
            coverage_debt = float(context[4] + context[5])
            work_units = 2 * action.horizon
            score = (
                max(predicted, 0.0) + exploration
            ) / work_units + self.config.coverage_weight * coverage_debt
            choice = ActionChoice(
                action=action,
                score=score,
                predicted_reward=predicted,
                exploration_bonus=exploration,
                coverage_debt=coverage_debt,
                context=context,
            )
            ranked.append(
                (
                    -score,
                    action.pool_blind_tiebreak_sha256(self.config),
                    choice,
                )
            )
        ranked.sort(key=lambda row: (row[0], row[1]))
        return ranked[0][2]

    def proposal_for_choice(
        self, choice: ActionChoice, *, split: DatasetSplit = DatasetSplit.TRAIN
    ) -> ExperimentProposal:
        if not isinstance(choice, ActionChoice):
            raise TypeError("choice must be ActionChoice")
        return ExperimentProposal(
            name=f"bit-{choice.action.bit_index:03d}-h{choice.action.horizon}",
            family=f"paired-prefix-h{choice.action.horizon}",
            expected_information_gain=max(
                choice.predicted_reward + choice.exploration_bonus, 0.0
            ),
            work_units=2 * choice.action.horizon,
            split=split,
        )

    def run_policy(
        self,
        pool: Full256ActionPool,
        *,
        action_budget: int,
        allowed_horizons: Iterable[int] | None = None,
    ) -> OnlineCausalFastState:
        self.validate_pool(pool)
        if (
            isinstance(action_budget, bool)
            or not isinstance(action_budget, int)
            or not 0 <= action_budget <= self.config.maximum_actions
        ):
            raise OnlineCausalControllerError("action_budget is outside the field")
        state = self.initial_fast_state(pool.source_stream_sha256)
        for _step in range(action_budget):
            choice = self.choose_action(state, allowed_horizons=allowed_horizons)
            if choice is None:
                break
            self.observe(state, PairedCausalObservation.from_pool(pool, choice.action))
        return state

    def _replay_for_rewards(
        self,
        pool: Full256ActionPool,
        action_order: Sequence[int],
        labels: np.ndarray,
    ) -> tuple[list[np.ndarray], list[float], float, float]:
        state = self.initial_fast_state(pool.source_stream_sha256)
        contexts: list[np.ndarray] = []
        rewards: list[float] = []
        initial_nll = _binary_nll_bits(state.posterior_logits, labels)
        for flat_index in action_order:
            action = CausalAction.from_flat_index(int(flat_index), self.config)
            orientation, common = self._action_query_logits(state, [action])
            context = self._critic_context(
                state, action, float(orientation[0]), float(common[0])
            )
            before = _binary_nll_bits(state.posterior_logits, labels)
            self.observe(state, PairedCausalObservation.from_pool(pool, action))
            after = _binary_nll_bits(state.posterior_logits, labels)
            contexts.append(context)
            rewards.append(
                (before - after) * self.config.critic_work_scale / (2 * action.horizon)
            )
        final_nll = _binary_nll_bits(state.posterior_logits, labels)
        return contexts, rewards, initial_nll, final_nll

    def _train_reader_episode(
        self,
        pool: Full256ActionPool,
        action_order: Sequence[int],
        labels: np.ndarray,
    ) -> tuple[float, ...]:
        if not action_order:
            return ()
        nuisance = OnlineNuisanceState.initial(self.config)
        positive = self.reader.core.initial_state(1)
        negative = self.reader.core.initial_state(1)
        label_tensor = torch.from_numpy(labels.astype(np.float32, copy=False))
        optimizer = torch.optim.SGD(
            self.reader.parameters(), lr=self.config.reader_learning_rate
        )
        optimizer.zero_grad(set_to_none=True)
        self.reader.train()
        losses: list[float] = []
        chunk_loss = None
        chunk_count = 0
        seen_bits: list[int] = []
        for step, flat_index in enumerate(action_order, start=1):
            action = CausalAction.from_flat_index(int(flat_index), self.config)
            observation = PairedCausalObservation.from_pool(pool, action)
            horizon_index = self._horizon_index(action.horizon)
            odd_primary, odd_residual, even = nuisance.transform(
                observation.signed,
                observation.common,
                horizon_index,
                self.config,
                update=True,
            )
            address = self._address(action.bit_index, horizon_index, token_kind=0)[None]
            mask = np.ones(1, dtype=np.bool_)
            positive_event = self._event(
                odd_primary,
                odd_residual,
                even,
                action,
                observation.work_units,
                mirror=False,
            )[None]
            negative_event = self._event(
                odd_primary,
                odd_residual,
                even,
                action,
                observation.work_units,
                mirror=True,
            )[None]
            _ignored, positive = self._run_stream(
                positive_event, address, mask, positive
            )
            _ignored, negative = self._run_stream(
                negative_event, address, mask, negative
            )
            logits = self._query_coordinates_torch(
                positive, negative, (action.bit_index,)
            )
            loss = torch.nn.functional.binary_cross_entropy_with_logits(
                logits, label_tensor[action.bit_index : action.bit_index + 1]
            ) / math.log(2.0)
            chunk_loss = loss if chunk_loss is None else chunk_loss + loss
            chunk_count += 1
            if action.bit_index not in seen_bits:
                seen_bits.append(action.bit_index)
            boundary = chunk_count == self.config.gradient_chunk_actions or step == len(
                action_order
            )
            if boundary:
                immediate = chunk_loss / chunk_count
                if self.config.recall_loss_weight > 0.0:
                    recall_logits = self._query_coordinates_torch(
                        positive, negative, tuple(seen_bits)
                    )
                    recall_indexes = torch.tensor(seen_bits, dtype=torch.int64)
                    recall = torch.nn.functional.binary_cross_entropy_with_logits(
                        recall_logits, label_tensor[recall_indexes]
                    ) / math.log(2.0)
                    averaged = (immediate + self.config.recall_loss_weight * recall) / (
                        1.0 + self.config.recall_loss_weight
                    )
                else:
                    averaged = immediate
                averaged.backward()
                torch.nn.utils.clip_grad_norm_(
                    self.reader.parameters(), self.config.gradient_clip
                )
                optimizer.step()
                optimizer.zero_grad(set_to_none=True)
                losses.append(float(averaged.detach()))
                positive = positive.detached()
                negative = negative.detached()
                chunk_loss = None
                chunk_count = 0
        self.reader.eval()
        return tuple(losses)

    def reveal_and_learn(
        self,
        pool: Full256ActionPool,
        completed_state: OnlineCausalFastState,
        key_labels: np.ndarray | Sequence[int],
    ) -> RevealLearningReport:
        """Learn only after reveal; the completed prediction remains immutable."""

        self.validate_pool(pool)
        self._validate_live_state(completed_state)
        if completed_state.source_stream_sha256 != pool.source_stream_sha256:
            raise OnlineCausalControllerError("completed state and pool source differ")
        labels = np.asarray(key_labels, dtype=np.float32)
        if labels.shape != (KEY_BITS,) or np.any((labels != 0.0) & (labels != 1.0)):
            raise OnlineCausalControllerError("key_labels must be binary shape [256]")
        order = [
            int(value)
            for value in completed_state.action_order[: completed_state.action_count]
        ]
        slow_before = self.slow_state_sha256
        contexts, rewards, initial_nll, final_nll = self._replay_for_rewards(
            pool, order, labels
        )
        model_before = _module_bytes(self.reader)
        critic_before = self.critic.clone()
        episodes_before = self.episodes
        try:
            for context, reward in zip(contexts, rewards, strict=True):
                self.critic.update(context, reward, self.config)
            losses = self._train_reader_episode(pool, order, labels)
            self.episodes += 1
            slow_after = self.slow_state_sha256
        except Exception:
            _load_module_bytes(self.reader, model_before)
            self.critic = critic_before
            self.episodes = episodes_before
            raise
        completed_state.reveal_consumed = True
        completed_state.validate(self.config)
        return RevealLearningReport(
            actions=len(order),
            critic_updates=len(rewards),
            reward_sum_bits=initial_nll - final_nll,
            critic_reward_sum=float(sum(rewards)),
            reward_positive_actions=sum(reward > 0.0 for reward in rewards),
            prequential_nll_bits=initial_nll,
            final_nll_bits=final_nll,
            training_loss_bits=losses,
            slow_state_sha256_before=slow_before,
            slow_state_sha256_after=slow_after,
        )


__all__ = [
    "ADDRESS_HARMONIC_PAIRS",
    "CRITIC_CONTEXT_DIMENSION",
    "ActionChoice",
    "BoundedLinUCBCritic",
    "CausalAction",
    "OnlineCausalController",
    "OnlineCausalControllerConfig",
    "OnlineCausalControllerError",
    "OnlineCausalFastState",
    "OnlineNuisanceState",
    "PairedCausalObservation",
    "RevealLearningReport",
    "mobius_contrast",
]
