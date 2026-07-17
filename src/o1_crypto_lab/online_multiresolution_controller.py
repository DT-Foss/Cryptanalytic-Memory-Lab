"""Packetized incremental O1 controller for the O1C-0019 architecture.

O1C-0018 deliberately remains byte-reproducible.  This versioned successor fixes
the training/deployment mismatch discovered after that run:

* one O1 query is interpreted as cumulative state, never as a fresh increment;
* each observed horizon stores exactly ``q_after - q_before`` once;
* the deployed bit posterior is recomputed from a bounded horizon packet;
* reader-stationary episode-equal credit replaces pooled stale action credit;
* every affordable address is queried, hard breadth is only a starvation fallback;
* stopping is a first-class learned decision, distinct from budget exhaustion.

No current-target label is accepted by observation, querying or action selection.
Reader/gate learning and critic fitting are separate reveal-time operations so a
critic can be bound to the exact frozen reader bytes it evaluates.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

from .full256_action_pool import Full256ActionPool
from .living_inverse import canonical_json_bytes
from .o1_streaming_core import O1FastState, require_torch, torch
from .online_causal_controller import (
    KEY_BITS,
    CausalAction,
    OnlineCausalController,
    OnlineCausalControllerConfig,
    OnlineCausalControllerError,
    OnlineCausalFastState,
    OnlineNuisanceState,
    PairedCausalObservation,
    _binary_nll_bits,
    _finite_float,
    _load_module_bytes,
    _module_bytes,
    _sha256,
)
from .stationarity_critic import EpisodeEqualRidgeCritic


MULTIRESOLUTION_CONTROLLER_SCHEMA = "o1-256-multiresolution-controller-v1"
MULTIRESOLUTION_FAST_STATE_SCHEMA = "o1-256-multiresolution-fast-state-v1"
MULTIRESOLUTION_FAST_STATE_MAGIC = b"O1MRF1\x00"
MULTIRESOLUTION_SLOW_STATE_SCHEMA = "o1-256-multiresolution-slow-state-v1"
MULTIRESOLUTION_MODEL_SCHEMA = "o1-256-multiresolution-model-v1"
ZERO_SHA256 = "0" * 64
MAX_HEADER_BYTES = 1 << 20


class MultiResolutionControllerError(OnlineCausalControllerError):
    """A packet, decision, lifecycle boundary, or serialization differs."""


def _integer(
    value: object,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise MultiResolutionControllerError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _readonly_array(
    value: np.ndarray,
    *,
    dtype: object,
    shape: tuple[int, ...],
    field: str,
) -> np.ndarray:
    array = np.asarray(value)
    if array.dtype != dtype or array.shape != shape:
        raise MultiResolutionControllerError(f"{field} array shape or dtype differs")
    if np.issubdtype(array.dtype, np.floating) and not np.all(np.isfinite(array)):
        raise MultiResolutionControllerError(f"{field} contains non-finite values")
    result = np.array(array, dtype=dtype, order="C", copy=True)
    result.setflags(write=False)
    return result


@dataclass(frozen=True)
class MultiResolutionControllerConfig:
    """Versioned packet/readout, policy and stationarity configuration."""

    base: OnlineCausalControllerConfig
    gate_max_scale: float = 4.0
    stationarity_penalty: float = 1.0
    critic_exploration_scale: float = 0.05
    soft_coverage_weight: float = 0.002
    soft_age_weight: float = 0.002
    starvation_steps: int = 256
    minimum_decisions_before_stop: int = 256
    minimum_critic_episodes_before_stop: int = 2
    stop_margin: float = 0.0
    require_all_coordinates_before_stop: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.base, OnlineCausalControllerConfig):
            raise TypeError("base must be OnlineCausalControllerConfig")
        _finite_float(
            self.gate_max_scale,
            "gate_max_scale",
            minimum=2.000001,
            maximum=1e4,
        )
        for field, value, maximum in (
            ("stationarity_penalty", self.stationarity_penalty, 1e6),
            ("critic_exploration_scale", self.critic_exploration_scale, 1e6),
            ("soft_coverage_weight", self.soft_coverage_weight, 1e6),
            ("soft_age_weight", self.soft_age_weight, 1e6),
        ):
            _finite_float(value, field, minimum=0.0, maximum=maximum)
        _finite_float(self.stop_margin, "stop_margin", minimum=-1e6, maximum=1e6)
        _integer(self.starvation_steps, "starvation_steps", 1, 1 << 31)
        _integer(
            self.minimum_decisions_before_stop,
            "minimum_decisions_before_stop",
            0,
            self.base.maximum_actions,
        )
        _integer(
            self.minimum_critic_episodes_before_stop,
            "minimum_critic_episodes_before_stop",
            2,
            1 << 31,
        )
        if not isinstance(self.require_all_coordinates_before_stop, bool):
            raise MultiResolutionControllerError(
                "require_all_coordinates_before_stop must be boolean"
            )

    @property
    def ordered_horizons(self) -> tuple[int, ...]:
        return tuple(sorted(self.base.horizons))

    @property
    def horizon_count(self) -> int:
        return self.base.horizon_count

    @property
    def maximum_actions(self) -> int:
        return self.base.maximum_actions

    @property
    def critic_context_dimension(self) -> int:
        return self.base.critic_context_dimension

    @property
    def extra_fast_state_bytes(self) -> int:
        return (
            self.horizon_count * KEY_BITS * 4 + self.maximum_actions * 2 + 3 * 8 + 1 + 8
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": MULTIRESOLUTION_CONTROLLER_SCHEMA,
            "base": self.base.describe(),
            "gate_max_scale": self.gate_max_scale,
            "gate_initial_effective_weight": 1.0,
            "stationarity_penalty": self.stationarity_penalty,
            "critic_exploration_scale": self.critic_exploration_scale,
            "soft_coverage_weight": self.soft_coverage_weight,
            "soft_age_weight": self.soft_age_weight,
            "starvation_steps": self.starvation_steps,
            "minimum_decisions_before_stop": self.minimum_decisions_before_stop,
            "minimum_critic_episodes_before_stop": (
                self.minimum_critic_episodes_before_stop
            ),
            "stop_margin": self.stop_margin,
            "require_all_coordinates_before_stop": (
                self.require_all_coordinates_before_stop
            ),
            "candidate_query": "all-affordable-state-addresses",
            "coverage_rule": "soft-until-finite-starvation-deadline",
            "packet_rule": "all-configured-prefixes-up-to-chosen-depth",
            "posterior_update": "recompute-from-q-after-minus-q-before-packet",
            "critic_rule": "episode-equal-reader-sha-bound-stationarity-lcb",
            "stop_rule": "learned-zero-utility-action-distinct-from-exhaustion",
            "extra_fast_state_bytes": self.extra_fast_state_bytes,
            "stream_length_dependent_fast_state": False,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.describe())).hexdigest()


if torch is not None:

    class OddHorizonGate(torch.nn.Module):
        """Bias-free learned horizon gate whose packet readout is exactly odd."""

        def __init__(self, horizon_count: int, maximum_scale: float) -> None:
            super().__init__()
            self.horizon_count = _integer(
                horizon_count,
                "horizon_count",
                1,
                8,
            )
            self.maximum_scale = _finite_float(
                maximum_scale,
                "maximum_scale",
                minimum=2.000001,
                maximum=1e4,
            )
            initial_raw_scale = math.atanh(2.0 / self.maximum_scale)
            self.gate_logits = torch.nn.Parameter(torch.zeros(self.horizon_count))
            self.raw_scales = torch.nn.Parameter(
                torch.full((self.horizon_count,), initial_raw_scale)
            )

        def effective_weights(self) -> object:
            return (
                torch.sigmoid(self.gate_logits)
                * self.maximum_scale
                * torch.tanh(self.raw_scales)
            )

        def forward(
            self,
            evidence: object,
            mask: object,
            *,
            logit_clip: float,
        ) -> object:
            if (
                not isinstance(evidence, torch.Tensor)
                or not isinstance(mask, torch.Tensor)
                or evidence.ndim != 2
                or evidence.shape[-1] != self.horizon_count
                or mask.shape != evidence.shape
                or mask.dtype != torch.bool
            ):
                raise MultiResolutionControllerError(
                    "gate evidence/mask must be [N,H] tensors"
                )
            clip = _finite_float(
                logit_clip,
                "logit_clip",
                minimum=1.0,
                maximum=1e6,
            )
            weighted = evidence * mask.to(dtype=evidence.dtype)
            result = (weighted * self.effective_weights()).sum(dim=-1)
            return torch.clamp(result, min=-clip, max=clip)


else:  # pragma: no cover

    class OddHorizonGate:  # type: ignore[no-redef]
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            require_torch()


@dataclass
class MultiResolutionFastState:
    """Bounded target-local packet state layered over the O1C-0018 fast state."""

    base: OnlineCausalFastState
    packet_evidence: np.ndarray
    decision_order: np.ndarray
    decision_count: int = 0
    physical_work_units: int = 0
    stopped: bool = False
    stop_decision_count: int = 0
    stop_score: float = 0.0

    def validate(self, config: MultiResolutionControllerConfig) -> None:
        if not isinstance(config, MultiResolutionControllerConfig):
            raise TypeError("config must be MultiResolutionControllerConfig")
        self.base.validate(config.base)
        h = config.horizon_count
        if (
            not isinstance(self.packet_evidence, np.ndarray)
            or self.packet_evidence.dtype != np.float32
            or self.packet_evidence.shape != (h, KEY_BITS)
            or not np.all(np.isfinite(self.packet_evidence))
        ):
            raise MultiResolutionControllerError("packet evidence differs")
        if (
            not isinstance(self.decision_order, np.ndarray)
            or self.decision_order.dtype != np.uint16
            or self.decision_order.shape != (config.maximum_actions,)
        ):
            raise MultiResolutionControllerError("decision ledger differs")
        _integer(
            self.decision_count,
            "decision_count",
            0,
            config.maximum_actions,
        )
        _integer(
            self.physical_work_units,
            "physical_work_units",
            0,
            2 * max(config.ordered_horizons) * KEY_BITS,
        )
        _integer(
            self.stop_decision_count,
            "stop_decision_count",
            0,
            config.maximum_actions,
        )
        _finite_float(self.stop_score, "stop_score", minimum=-1e9, maximum=1e9)
        if not isinstance(self.stopped, bool):
            raise MultiResolutionControllerError("stopped must be boolean")
        used = self.decision_order[: self.decision_count]
        unused = self.decision_order[self.decision_count :]
        if (
            np.any(used >= config.maximum_actions)
            or len({int(value) for value in used}) != self.decision_count
            or np.any(unused != np.iinfo(np.uint16).max)
        ):
            raise MultiResolutionControllerError("decision order differs")

        expected_coverage = np.zeros_like(self.base.coverage)
        expected_slot_order: list[int] = []
        expected_work = 0
        for flat_index in used:
            action = CausalAction.from_flat_index(int(flat_index), config.base)
            observed_depths = [
                horizon
                for horizon in config.ordered_horizons
                if expected_coverage[
                    config.base.horizons.index(horizon), action.bit_index
                ]
            ]
            current_depth = max(observed_depths, default=0)
            if action.horizon <= current_depth:
                raise MultiResolutionControllerError(
                    "packet decisions must strictly deepen a coordinate"
                )
            new_depths = [
                horizon
                for horizon in config.ordered_horizons
                if current_depth < horizon <= action.horizon
            ]
            if not new_depths or new_depths[-1] != action.horizon:
                raise MultiResolutionControllerError("packet horizon gap differs")
            for horizon in new_depths:
                horizon_index = config.base.horizons.index(horizon)
                expected_coverage[horizon_index, action.bit_index] = np.uint16(1)
                expected_slot_order.append(horizon_index * KEY_BITS + action.bit_index)
            expected_work += 2 * (action.horizon - current_depth)
        if self.base.action_count != len(expected_slot_order) or not np.array_equal(
            self.base.action_order[: self.base.action_count],
            np.asarray(expected_slot_order, dtype=np.uint16),
        ):
            raise MultiResolutionControllerError(
                "packet decisions and base slot ledger differ"
            )
        if not np.array_equal(self.base.coverage, expected_coverage):
            raise MultiResolutionControllerError(
                "packet decisions and base coverage differ"
            )
        if self.physical_work_units != expected_work:
            raise MultiResolutionControllerError("physical work ledger differs")
        uncovered = self.base.coverage == 0
        if np.any(self.packet_evidence[uncovered] != 0.0):
            raise MultiResolutionControllerError(
                "uncovered packet slots must remain zero"
            )
        if self.stopped:
            if self.stop_decision_count != self.decision_count:
                raise MultiResolutionControllerError("stop clock differs")
            if self.decision_count < config.minimum_decisions_before_stop:
                raise MultiResolutionControllerError(
                    "stopped state predates the minimum decision clock"
                )
            coordinate_coverage = self.base.coverage.sum(axis=0, dtype=np.uint64)
            if config.require_all_coordinates_before_stop and not np.all(
                coordinate_coverage > 0
            ):
                raise MultiResolutionControllerError(
                    "stopped state predates full coordinate scouting"
                )
            if self.stop_score != 0.0:
                raise MultiResolutionControllerError("STOP score must be exactly zero")
        elif self.stop_decision_count != 0 or self.stop_score != 0.0:
            raise MultiResolutionControllerError("unstopped metadata differs")

    def clone(self) -> "MultiResolutionFastState":
        return MultiResolutionFastState(
            base=self.base.clone(),
            packet_evidence=self.packet_evidence.copy(),
            decision_order=self.decision_order.copy(),
            decision_count=self.decision_count,
            physical_work_units=self.physical_work_units,
            stopped=self.stopped,
            stop_decision_count=self.stop_decision_count,
            stop_score=self.stop_score,
        )

    def probabilities(self, config: MultiResolutionControllerConfig) -> np.ndarray:
        self.validate(config)
        return self.base.probabilities(config.base)

    def to_bytes(self, config: MultiResolutionControllerConfig) -> bytes:
        self.validate(config)
        base_bytes = self.base.to_bytes(config.base)
        arrays = (
            self.packet_evidence.astype("<f4", copy=False),
            self.decision_order.astype("<u2", copy=False),
            np.asarray(
                (
                    self.decision_count,
                    self.physical_work_units,
                    self.stop_decision_count,
                ),
                dtype="<u8",
            ),
            np.asarray((int(self.stopped),), dtype=np.uint8),
            np.asarray((self.stop_score,), dtype="<f8"),
        )
        header = canonical_json_bytes(
            {
                "schema": MULTIRESOLUTION_FAST_STATE_SCHEMA,
                "controller_sha256": config.sha256,
                "base_bytes": len(base_bytes),
                "array_bytes": [int(value.nbytes) for value in arrays],
            }
        )
        return (
            MULTIRESOLUTION_FAST_STATE_MAGIC
            + struct.pack(">Q", len(header))
            + header
            + base_bytes
            + b"".join(value.tobytes(order="C") for value in arrays)
        )

    @classmethod
    def from_bytes(
        cls,
        value: bytes,
        config: MultiResolutionControllerConfig,
        *,
        device: object = "cpu",
    ) -> "MultiResolutionFastState":
        prefix = len(MULTIRESOLUTION_FAST_STATE_MAGIC) + 8
        if (
            not isinstance(value, bytes)
            or len(value) < prefix
            or not value.startswith(MULTIRESOLUTION_FAST_STATE_MAGIC)
        ):
            raise MultiResolutionControllerError("fast-state magic differs")
        header_length = struct.unpack(
            ">Q",
            value[len(MULTIRESOLUTION_FAST_STATE_MAGIC) : prefix],
        )[0]
        if not 1 <= header_length <= MAX_HEADER_BYTES:
            raise MultiResolutionControllerError("fast-state header length differs")
        header_end = prefix + header_length
        try:
            header = json.loads(value[prefix:header_end].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MultiResolutionControllerError(
                "fast-state header is invalid"
            ) from exc
        expected_fields = {
            "schema",
            "controller_sha256",
            "base_bytes",
            "array_bytes",
        }
        expected_arrays = [
            config.horizon_count * KEY_BITS * 4,
            config.maximum_actions * 2,
            24,
            1,
            8,
        ]
        if (
            not isinstance(header, dict)
            or set(header) != expected_fields
            or header.get("schema") != MULTIRESOLUTION_FAST_STATE_SCHEMA
            or header.get("controller_sha256") != config.sha256
            or header.get("array_bytes") != expected_arrays
            or isinstance(header.get("base_bytes"), bool)
            or not isinstance(header.get("base_bytes"), int)
            or header["base_bytes"] < 1
            or len(value)
            != header_end + int(header["base_bytes"]) + sum(expected_arrays)
        ):
            raise MultiResolutionControllerError("fast-state inventory differs")
        cursor = header_end
        base_end = cursor + int(header["base_bytes"])
        base = OnlineCausalFastState.from_bytes(
            value[cursor:base_end],
            config.base,
            device=device,
        )
        cursor = base_end
        packet_end = cursor + expected_arrays[0]
        packet = (
            np.frombuffer(value[cursor:packet_end], dtype="<f4")
            .reshape(config.horizon_count, KEY_BITS)
            .copy()
        )
        cursor = packet_end
        decision_end = cursor + expected_arrays[1]
        decisions = np.frombuffer(value[cursor:decision_end], dtype="<u2").copy()
        cursor = decision_end
        counters_end = cursor + expected_arrays[2]
        counters = np.frombuffer(value[cursor:counters_end], dtype="<u8").copy()
        cursor = counters_end
        stopped = value[cursor]
        cursor += 1
        stop_score = float(np.frombuffer(value[cursor:], dtype="<f8")[0])
        if stopped not in (0, 1):
            raise MultiResolutionControllerError("fast-state stop flag differs")
        result = cls(
            base=base,
            packet_evidence=packet,
            decision_order=decisions,
            decision_count=int(counters[0]),
            physical_work_units=int(counters[1]),
            stopped=bool(stopped),
            stop_decision_count=int(counters[2]),
            stop_score=stop_score,
        )
        result.validate(config)
        if result.to_bytes(config) != value:
            raise MultiResolutionControllerError("fast-state payload is not canonical")
        return result

    def sha256(self, config: MultiResolutionControllerConfig) -> str:
        return hashlib.sha256(self.to_bytes(config)).hexdigest()


@dataclass(frozen=True)
class PacketActionDecision:
    action: CausalAction
    score: float
    predicted_reward: float
    stationarity_std: float
    epistemic_bonus: float
    coverage_bonus: float
    age_bonus: float
    physical_work_units: int
    starvation_forced: bool
    state_before_sha256: str
    context: np.ndarray
    allowed_horizons: tuple[int, ...] = ()
    maximum_work_units: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, CausalAction):
            raise TypeError("action must be CausalAction")
        for field, value in (
            ("score", self.score),
            ("predicted_reward", self.predicted_reward),
            ("stationarity_std", self.stationarity_std),
            ("epistemic_bonus", self.epistemic_bonus),
            ("coverage_bonus", self.coverage_bonus),
            ("age_bonus", self.age_bonus),
        ):
            _finite_float(value, field, minimum=-1e9, maximum=1e9)
        _integer(
            self.physical_work_units,
            "physical_work_units",
            1,
            2_000_000_000,
        )
        if not isinstance(self.starvation_forced, bool):
            raise MultiResolutionControllerError("starvation_forced must be boolean")
        _sha256(self.state_before_sha256, "state_before_sha256")
        context = np.asarray(self.context)
        if (
            context.dtype != np.float32
            or context.ndim != 1
            or not np.all(np.isfinite(context))
        ):
            raise MultiResolutionControllerError(
                "decision context must be a finite float32 vector"
            )
        frozen = np.array(context, dtype=np.float32, order="C", copy=True)
        frozen.setflags(write=False)
        object.__setattr__(self, "context", frozen)
        if (
            not isinstance(self.allowed_horizons, tuple)
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in self.allowed_horizons
            )
            or len(set(self.allowed_horizons)) != len(self.allowed_horizons)
        ):
            raise MultiResolutionControllerError("decision horizons differ")
        if self.maximum_work_units is not None:
            _integer(
                self.maximum_work_units,
                "maximum_work_units",
                0,
                2_000_000_000,
            )


@dataclass(frozen=True)
class PacketStopDecision:
    score: float
    best_candidate_score: float
    state_before_sha256: str
    allowed_horizons: tuple[int, ...]
    maximum_work_units: int | None

    def __post_init__(self) -> None:
        _finite_float(self.score, "score", minimum=-1e9, maximum=1e9)
        _finite_float(
            self.best_candidate_score,
            "best_candidate_score",
            minimum=-1e9,
            maximum=1e9,
        )
        _sha256(self.state_before_sha256, "state_before_sha256")
        if (
            not isinstance(self.allowed_horizons, tuple)
            or not self.allowed_horizons
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in self.allowed_horizons
            )
        ):
            raise MultiResolutionControllerError("stop horizons differ")
        if self.maximum_work_units is not None:
            _integer(
                self.maximum_work_units,
                "maximum_work_units",
                0,
                2_000_000_000,
            )


@dataclass(frozen=True)
class PacketExhaustedDecision:
    remaining_work_units: int | None
    state_before_sha256: str

    def __post_init__(self) -> None:
        if self.remaining_work_units is not None:
            _integer(
                self.remaining_work_units,
                "remaining_work_units",
                0,
                2_000_000_000,
            )
        _sha256(self.state_before_sha256, "state_before_sha256")


@dataclass(frozen=True)
class PacketObservationReceipt:
    requested_action: CausalAction
    observed_slots: tuple[CausalAction, ...]
    physical_work_units: int
    packet_delta_sum: float
    state_before_sha256: str
    state_after_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.requested_action, CausalAction):
            raise TypeError("requested_action must be CausalAction")
        if (
            not isinstance(self.observed_slots, tuple)
            or not self.observed_slots
            or any(
                not isinstance(action, CausalAction) for action in self.observed_slots
            )
        ):
            raise MultiResolutionControllerError(
                "observed_slots must be a non-empty action tuple"
            )
        _integer(
            self.physical_work_units,
            "physical_work_units",
            1,
            2_000_000_000,
        )
        _finite_float(
            self.packet_delta_sum,
            "packet_delta_sum",
            minimum=-1e9,
            maximum=1e9,
        )
        _sha256(self.state_before_sha256, "state_before_sha256")
        _sha256(self.state_after_sha256, "state_after_sha256")


@dataclass(frozen=True)
class PacketRewardReplay:
    action_order: np.ndarray
    contexts: np.ndarray
    physical_work_units: np.ndarray
    packet_delta_sums: np.ndarray
    delta_nll_bits: np.ndarray
    initial_nll_bits: float
    final_nll_bits: float

    def __post_init__(self) -> None:
        order = _readonly_array(
            self.action_order,
            dtype=np.uint16,
            shape=(len(self.action_order),),
            field="action_order",
        )
        rows = order.shape[0]
        contexts = np.asarray(self.contexts)
        if (
            contexts.dtype != np.float32
            or contexts.ndim != 2
            or contexts.shape[0] != rows
            or not np.all(np.isfinite(contexts))
        ):
            raise MultiResolutionControllerError("reward contexts differ")
        contexts = np.array(contexts, dtype=np.float32, order="C", copy=True)
        contexts.setflags(write=False)
        work = _readonly_array(
            self.physical_work_units,
            dtype=np.uint32,
            shape=(rows,),
            field="physical_work_units",
        )
        deltas = _readonly_array(
            self.packet_delta_sums,
            dtype=np.float32,
            shape=(rows,),
            field="packet_delta_sums",
        )
        rewards = _readonly_array(
            self.delta_nll_bits,
            dtype=np.float64,
            shape=(rows,),
            field="delta_nll_bits",
        )
        _finite_float(self.initial_nll_bits, "initial_nll_bits", minimum=0.0)
        _finite_float(self.final_nll_bits, "final_nll_bits", minimum=0.0)
        object.__setattr__(self, "action_order", order)
        object.__setattr__(self, "contexts", contexts)
        object.__setattr__(self, "physical_work_units", work)
        object.__setattr__(self, "packet_delta_sums", deltas)
        object.__setattr__(self, "delta_nll_bits", rewards)


@dataclass(frozen=True)
class PacketTrainingReport:
    decisions: int
    observed_slots: int
    training_loss_bits: tuple[float, ...]
    reader_state_sha256_before: str
    reader_state_sha256_after: str
    critic_invalidated: bool


@dataclass(frozen=True)
class PacketCriticFitReport:
    decisions: int
    reward_sum_bits: float
    positive_reward_decisions: int
    fitted_weight_sha256: str
    critic_episode_count: int
    reader_state_sha256: str


@dataclass(frozen=True)
class PacketCriticCorpusReport:
    episode_reports: tuple[PacketCriticFitReport, ...]
    total_decisions: int
    final_critic_sha256: str
    reader_state_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.episode_reports, tuple)
            or not self.episode_reports
            or any(
                not isinstance(report, PacketCriticFitReport)
                for report in self.episode_reports
            )
        ):
            raise MultiResolutionControllerError(
                "episode_reports must be a non-empty critic report tuple"
            )
        _integer(
            self.total_decisions,
            "total_decisions",
            1,
            2_000_000_000,
        )
        _sha256(self.final_critic_sha256, "final_critic_sha256")
        _sha256(self.reader_state_sha256, "reader_state_sha256")


class MultiResolutionCausalController(OnlineCausalController):
    """O1C-0019 packet reader with all-address policy and reveal-only learning."""

    def __init__(self, config: MultiResolutionControllerConfig) -> None:
        require_torch()
        if not isinstance(config, MultiResolutionControllerConfig):
            raise TypeError("config must be MultiResolutionControllerConfig")
        super().__init__(config.base)
        self.controller_config = config
        self.gate = OddHorizonGate(
            config.horizon_count,
            config.gate_max_scale,
        )
        self.critic = EpisodeEqualRidgeCritic.initial(
            config.critic_context_dimension,
            config.base.critic_ridge,
        )
        self.reader_episodes = 0
        self.critic_reader_sha256 = ZERO_SHA256

    def reader_state_bytes(self) -> bytes:
        stream = _module_bytes(self.reader)
        gate = _module_bytes(self.gate)
        header = canonical_json_bytes(
            {
                "schema": MULTIRESOLUTION_MODEL_SCHEMA,
                "controller_sha256": self.controller_config.sha256,
                "stream_bytes": len(stream),
                "gate_bytes": len(gate),
            }
        )
        return struct.pack(">Q", len(header)) + header + stream + gate

    @property
    def reader_state_sha256(self) -> str:
        return hashlib.sha256(self.reader_state_bytes()).hexdigest()

    def load_reader_state_bytes(self, value: bytes) -> None:
        if not isinstance(value, bytes) or len(value) < 8:
            raise MultiResolutionControllerError("reader-state payload is truncated")
        header_length = struct.unpack(">Q", value[:8])[0]
        if not 1 <= header_length <= MAX_HEADER_BYTES:
            raise MultiResolutionControllerError("reader-state header length differs")
        header_end = 8 + header_length
        try:
            header = json.loads(value[8:header_end].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MultiResolutionControllerError(
                "reader-state header is invalid"
            ) from exc
        expected = {
            "schema",
            "controller_sha256",
            "stream_bytes",
            "gate_bytes",
        }
        if (
            not isinstance(header, dict)
            or set(header) != expected
            or header.get("schema") != MULTIRESOLUTION_MODEL_SCHEMA
            or header.get("controller_sha256") != self.controller_config.sha256
            or any(
                isinstance(header.get(field), bool)
                or not isinstance(header.get(field), int)
                or header[field] < 1
                for field in ("stream_bytes", "gate_bytes")
            )
            or len(value)
            != header_end + int(header["stream_bytes"]) + int(header["gate_bytes"])
        ):
            raise MultiResolutionControllerError("reader-state inventory differs")
        stream_end = header_end + int(header["stream_bytes"])
        stream_payload = value[header_end:stream_end]
        gate_payload = value[stream_end:]
        old_payload = self.reader_state_bytes()
        old_stream = _module_bytes(self.reader)
        old_gate = _module_bytes(self.gate)
        try:
            _load_module_bytes(self.reader, stream_payload)
            _load_module_bytes(self.gate, gate_payload)
            if self.reader_state_bytes() != value:
                raise MultiResolutionControllerError(
                    "reader-state payload is not canonical"
                )
            if value != old_payload:
                self.critic = EpisodeEqualRidgeCritic.initial(
                    self.controller_config.critic_context_dimension,
                    self.controller_config.base.critic_ridge,
                )
                self.critic_reader_sha256 = ZERO_SHA256
                self.reader_episodes = 0
        except Exception:
            _load_module_bytes(self.reader, old_stream)
            _load_module_bytes(self.gate, old_gate)
            raise

    def load_stream_state_bytes(self, value: bytes) -> None:
        """Load only the shared O1 stream, retaining the current packet gate."""

        old = _module_bytes(self.reader)
        try:
            _load_module_bytes(self.reader, value)
        except Exception:
            _load_module_bytes(self.reader, old)
            raise
        self.critic = EpisodeEqualRidgeCritic.initial(
            self.controller_config.critic_context_dimension,
            self.controller_config.base.critic_ridge,
        )
        self.critic_reader_sha256 = ZERO_SHA256
        if value != old:
            self.reader_episodes = 0

    def slow_state_bytes(self) -> bytes:
        self._validate_critic_binding()
        _integer(
            self.reader_episodes,
            "reader_episodes",
            0,
            (1 << 63) - 1,
        )
        reader = self.reader_state_bytes()
        critic = self.critic.to_bytes()
        header = canonical_json_bytes(
            {
                "schema": MULTIRESOLUTION_SLOW_STATE_SCHEMA,
                "controller_sha256": self.controller_config.sha256,
                "reader_bytes": len(reader),
                "critic_bytes": len(critic),
                "reader_episodes": self.reader_episodes,
                "critic_reader_sha256": self.critic_reader_sha256,
            }
        )
        return struct.pack(">Q", len(header)) + header + reader + critic

    @property
    def slow_state_sha256(self) -> str:
        return hashlib.sha256(self.slow_state_bytes()).hexdigest()

    def load_slow_state_bytes(self, value: bytes) -> None:
        if not isinstance(value, bytes) or len(value) < 8:
            raise MultiResolutionControllerError("slow-state payload is truncated")
        header_length = struct.unpack(">Q", value[:8])[0]
        if not 1 <= header_length <= MAX_HEADER_BYTES:
            raise MultiResolutionControllerError("slow-state header length differs")
        header_end = 8 + header_length
        try:
            header = json.loads(value[8:header_end].decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MultiResolutionControllerError(
                "slow-state header is invalid"
            ) from exc
        expected = {
            "schema",
            "controller_sha256",
            "reader_bytes",
            "critic_bytes",
            "reader_episodes",
            "critic_reader_sha256",
        }
        if (
            not isinstance(header, dict)
            or set(header) != expected
            or header.get("schema") != MULTIRESOLUTION_SLOW_STATE_SCHEMA
            or header.get("controller_sha256") != self.controller_config.sha256
            or any(
                isinstance(header.get(field), bool)
                or not isinstance(header.get(field), int)
                or header[field] < 1
                for field in ("reader_bytes", "critic_bytes")
            )
            or isinstance(header.get("reader_episodes"), bool)
            or not isinstance(header.get("reader_episodes"), int)
            or not 0 <= header["reader_episodes"] <= (1 << 63) - 1
            or not isinstance(header.get("critic_reader_sha256"), str)
            or len(value)
            != header_end + int(header["reader_bytes"]) + int(header["critic_bytes"])
        ):
            raise MultiResolutionControllerError("slow-state inventory differs")
        _sha256(header["critic_reader_sha256"], "critic_reader_sha256")
        reader_end = header_end + int(header["reader_bytes"])
        reader_payload = value[header_end:reader_end]
        critic_payload = value[reader_end:]
        old_reader = self.reader_state_bytes()
        old_critic = self.critic
        old_reader_episodes = self.reader_episodes
        old_binding = self.critic_reader_sha256
        try:
            self.load_reader_state_bytes(reader_payload)
            critic = EpisodeEqualRidgeCritic.from_bytes(critic_payload)
            if critic.dimension != self.controller_config.critic_context_dimension:
                raise MultiResolutionControllerError("critic dimension differs")
            self.critic = critic
            self.reader_episodes = int(header["reader_episodes"])
            self.critic_reader_sha256 = str(header["critic_reader_sha256"])
            if self.critic.episode_count == 0:
                if self.critic_reader_sha256 != ZERO_SHA256:
                    raise MultiResolutionControllerError(
                        "empty critic must have an empty reader binding"
                    )
            elif self.critic_reader_sha256 != self.reader_state_sha256:
                raise MultiResolutionControllerError(
                    "critic is not bound to the restored reader"
                )
            if self.slow_state_bytes() != value:
                raise MultiResolutionControllerError(
                    "slow-state payload is not canonical"
                )
        except Exception:
            self.load_reader_state_bytes(old_reader)
            self.critic = old_critic
            self.reader_episodes = old_reader_episodes
            self.critic_reader_sha256 = old_binding
            raise

    def initial_fast_state(self, source_stream_sha256: str) -> MultiResolutionFastState:
        base = OnlineCausalController.initial_fast_state(
            self,
            source_stream_sha256,
        )
        result = MultiResolutionFastState(
            base=base,
            packet_evidence=np.zeros(
                (self.controller_config.horizon_count, KEY_BITS),
                dtype=np.float32,
            ),
            decision_order=np.full(
                self.controller_config.maximum_actions,
                np.iinfo(np.uint16).max,
                dtype=np.uint16,
            ),
        )
        self._validate_live_state(result)
        return result

    def _packet_precision(self, state: MultiResolutionFastState) -> np.ndarray:
        self.gate.eval()
        with torch.no_grad():
            weights = (
                self.gate.effective_weights().detach().cpu().numpy().astype(np.float64)
            )
        magnitude = np.abs(state.packet_evidence.astype(np.float64) * weights[:, None])
        present = state.base.coverage.astype(np.float64)
        return np.sum(
            present * magnitude / (1.0 + magnitude),
            axis=0,
        ).astype(np.float32)

    def _packet_logits(self, state: MultiResolutionFastState) -> np.ndarray:
        self.gate.eval()
        evidence = torch.from_numpy(
            np.ascontiguousarray(state.packet_evidence.T, dtype=np.float32)
        )
        mask = torch.from_numpy(
            np.ascontiguousarray(state.base.coverage.T != 0, dtype=np.bool_)
        )
        with torch.no_grad():
            logits = self.gate(
                evidence,
                mask,
                logit_clip=self.config.posterior_logit_clip,
            )
        return logits.detach().cpu().numpy().astype(np.float32)

    def _validate_attached_state(
        self,
        state: MultiResolutionFastState,
        *,
        allow_stopped: bool,
    ) -> None:
        if not isinstance(state, MultiResolutionFastState):
            raise TypeError("state must be MultiResolutionFastState")
        state.validate(self.controller_config)
        if state.base.reveal_consumed:
            raise MultiResolutionControllerError("target reveal was already consumed")
        if state.stopped and not allow_stopped:
            raise MultiResolutionControllerError("target policy already stopped")
        if state.stopped and not self._stop_is_eligible(state):
            raise MultiResolutionControllerError(
                "stopped state lacks stationary STOP eligibility"
            )
        if state.base.slow_state_sha256 != self.slow_state_sha256:
            raise MultiResolutionControllerError(
                "slow state changed after this target started"
            )
        expected_logits = self._packet_logits(state)
        expected_precision = self._packet_precision(state)
        if not np.array_equal(state.base.posterior_logits, expected_logits):
            raise MultiResolutionControllerError("packet posterior differs")
        if not np.array_equal(state.base.posterior_precision, expected_precision):
            raise MultiResolutionControllerError("packet precision differs")

    def _validate_live_state(self, state: MultiResolutionFastState) -> None:
        self._validate_attached_state(state, allow_stopped=False)

    def query_posteriors(self, state: MultiResolutionFastState) -> np.ndarray:
        self._validate_attached_state(state, allow_stopped=True)
        return state.base.posterior_logits.copy()

    def query_o1_field(self, state: MultiResolutionFastState) -> np.ndarray:
        self._validate_attached_state(state, allow_stopped=True)
        self.reader.eval()
        with torch.no_grad():
            logits = self._query_bits_torch(
                state.base.positive_o1,
                state.base.negative_o1,
            )
        return logits.detach().cpu().numpy().astype(np.float32)

    def _current_depth(self, state: MultiResolutionFastState, bit_index: int) -> int:
        return max(
            (
                horizon
                for horizon in self.controller_config.ordered_horizons
                if state.base.coverage[self.config.horizons.index(horizon), bit_index]
            ),
            default=0,
        )

    def _packet_actions(
        self,
        state: MultiResolutionFastState,
        requested: CausalAction,
    ) -> tuple[CausalAction, ...]:
        requested.validate(self.config)
        current = self._current_depth(state, requested.bit_index)
        if requested.horizon <= current:
            raise MultiResolutionControllerError(
                "packet action must strictly deepen a coordinate"
            )
        depths = tuple(
            horizon
            for horizon in self.controller_config.ordered_horizons
            if current < horizon <= requested.horizon
        )
        if not depths or depths[-1] != requested.horizon:
            raise MultiResolutionControllerError("packet action depth differs")
        return tuple(
            CausalAction(bit_index=requested.bit_index, horizon=horizon)
            for horizon in depths
        )

    def action_physical_work_units(
        self,
        state: MultiResolutionFastState,
        action: CausalAction,
    ) -> int:
        current = self._current_depth(state, action.bit_index)
        if action.horizon <= current:
            raise MultiResolutionControllerError("action is already covered")
        return 2 * (action.horizon - current)

    def requested_work_units(self, state: MultiResolutionFastState) -> int:
        state.validate(self.controller_config)
        return state.physical_work_units

    def _stream_packet_delta_torch(
        self,
        positive: O1FastState,
        negative: O1FastState,
        positive_event: np.ndarray,
        negative_event: np.ndarray,
        address: np.ndarray,
        bit_index: int,
    ) -> tuple[object, O1FastState, O1FastState]:
        before = self._query_coordinates_torch(
            positive,
            negative,
            (bit_index,),
        )[0]
        mask = np.ones(1, dtype=np.bool_)
        _positive_output, positive_after = self._run_stream(
            positive_event,
            address,
            mask,
            positive,
        )
        _negative_output, negative_after = self._run_stream(
            negative_event,
            address,
            mask,
            negative,
        )
        after = self._query_coordinates_torch(
            positive_after,
            negative_after,
            (bit_index,),
        )[0]
        return after - before, positive_after, negative_after

    def _observe_slot(
        self,
        state: MultiResolutionFastState,
        observation: PairedCausalObservation,
        *,
        incremental_work_units: int,
    ) -> float:
        action = observation.action
        horizon_index = self.config.horizons.index(action.horizon)
        bit = action.bit_index
        if state.base.coverage[horizon_index, bit] != 0:
            raise MultiResolutionControllerError("packet slot was already observed")
        _integer(
            incremental_work_units,
            "incremental_work_units",
            1,
            2_000_000_000,
        )
        odd_primary, odd_residual, even = state.base.nuisance.transform(
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
            action,
            incremental_work_units,
            mirror=False,
        )[None]
        negative_event = self._event(
            odd_primary,
            odd_residual,
            even,
            action,
            incremental_work_units,
            mirror=True,
        )[None]
        address = self._address(bit, horizon_index, token_kind=0)[None]
        self.reader.eval()
        with torch.no_grad():
            delta, positive_after, negative_after = self._stream_packet_delta_torch(
                state.base.positive_o1,
                state.base.negative_o1,
                positive_event,
                negative_event,
                address,
                bit,
            )
        delta_value = float(delta.detach().cpu())
        state.base.positive_o1 = positive_after.detached()
        state.base.negative_o1 = negative_after.detached()
        state.packet_evidence[horizon_index, bit] = np.float32(delta_value)
        state.base.coverage[horizon_index, bit] = np.uint16(1)
        state.base.steps += 1
        state.base.last_selected[horizon_index, bit] = np.uint32(state.base.steps)
        state.base.action_order[state.base.action_count] = np.uint16(
            action.flat_index(self.config)
        )
        state.base.action_count += 1
        state.base.posterior_logits[:] = self._packet_logits(state)
        state.base.posterior_precision[:] = self._packet_precision(state)
        return delta_value

    @staticmethod
    def _replace_state(
        target: MultiResolutionFastState,
        source: MultiResolutionFastState,
    ) -> None:
        target.base = source.base
        target.packet_evidence = source.packet_evidence
        target.decision_order = source.decision_order
        target.decision_count = source.decision_count
        target.physical_work_units = source.physical_work_units
        target.stopped = source.stopped
        target.stop_decision_count = source.stop_decision_count
        target.stop_score = source.stop_score

    def _observe_requested_action(
        self,
        state: MultiResolutionFastState,
        pool: Full256ActionPool,
        requested: CausalAction,
        *,
        maximum_work_units: int | None,
        expected_state_sha256: str | None,
        expected_work_units: int | None,
    ) -> PacketObservationReceipt:
        self.validate_pool(pool)
        self._validate_live_state(state)
        requested.validate(self.config)
        if pool.source_stream_sha256 != state.base.source_stream_sha256:
            raise MultiResolutionControllerError(
                "action pool source differs from fast state"
            )
        if maximum_work_units is not None:
            _integer(
                maximum_work_units,
                "maximum_work_units",
                0,
                2_000_000_000,
            )
        state_before_sha256 = state.sha256(self.controller_config)
        if (
            expected_state_sha256 is not None
            and expected_state_sha256 != state_before_sha256
        ):
            raise MultiResolutionControllerError("action decision is stale")
        slots = self._packet_actions(state, requested)
        current_depth = self._current_depth(state, requested.bit_index)
        physical_work = 2 * (requested.horizon - current_depth)
        if expected_work_units is not None and expected_work_units != physical_work:
            raise MultiResolutionControllerError("action decision work differs")
        if maximum_work_units is not None and physical_work > maximum_work_units:
            raise MultiResolutionControllerError(
                "action exceeds the remaining physical-work budget"
            )

        working = state.clone()
        deltas: list[float] = []
        previous_depth = current_depth
        for slot in slots:
            incremental_work = 2 * (slot.horizon - previous_depth)
            observation = PairedCausalObservation.from_pool(pool, slot)
            deltas.append(
                self._observe_slot(
                    working,
                    observation,
                    incremental_work_units=incremental_work,
                )
            )
            previous_depth = slot.horizon
        working.decision_order[working.decision_count] = np.uint16(
            requested.flat_index(self.config)
        )
        working.decision_count += 1
        working.physical_work_units += physical_work
        self._validate_live_state(working)
        state_after_sha256 = working.sha256(self.controller_config)
        receipt = PacketObservationReceipt(
            requested_action=requested,
            observed_slots=slots,
            physical_work_units=physical_work,
            packet_delta_sum=float(sum(deltas)),
            state_before_sha256=state_before_sha256,
            state_after_sha256=state_after_sha256,
        )
        self._replace_state(state, working)
        return receipt

    def observe_action(
        self,
        state: MultiResolutionFastState,
        pool: Full256ActionPool,
        decision: PacketActionDecision,
        *,
        maximum_work_units: int | None = None,
    ) -> PacketObservationReceipt:
        """Atomically execute one still-current label-free packet decision."""

        if not isinstance(decision, PacketActionDecision):
            raise TypeError("decision must be PacketActionDecision")
        return self._observe_requested_action(
            state,
            pool,
            decision.action,
            maximum_work_units=maximum_work_units,
            expected_state_sha256=decision.state_before_sha256,
            expected_work_units=decision.physical_work_units,
        )

    @staticmethod
    def _action_decisions_equal(
        left: PacketActionDecision,
        right: PacketActionDecision,
    ) -> bool:
        scalar_fields = (
            "action",
            "score",
            "predicted_reward",
            "stationarity_std",
            "epistemic_bonus",
            "coverage_bonus",
            "age_bonus",
            "physical_work_units",
            "starvation_forced",
            "state_before_sha256",
            "allowed_horizons",
            "maximum_work_units",
        )
        return all(
            getattr(left, field) == getattr(right, field) for field in scalar_fields
        ) and np.array_equal(
            left.context,
            right.context,
        )

    def apply_policy_action(
        self,
        state: MultiResolutionFastState,
        pool: Full256ActionPool,
        decision: PacketActionDecision,
    ) -> PacketObservationReceipt:
        """Recompute and atomically apply an exact autonomous picker winner."""

        if not isinstance(decision, PacketActionDecision):
            raise TypeError("decision must be PacketActionDecision")
        if not decision.allowed_horizons:
            raise MultiResolutionControllerError(
                "manual decisions cannot be promoted as autonomous policy actions"
            )
        recomputed = self.choose_action(
            state,
            allowed_horizons=decision.allowed_horizons,
            maximum_work_units=decision.maximum_work_units,
        )
        if not isinstance(
            recomputed, PacketActionDecision
        ) or not self._action_decisions_equal(
            recomputed,
            decision,
        ):
            raise MultiResolutionControllerError("policy action proof differs")
        return self.observe_action(
            state,
            pool,
            decision,
            maximum_work_units=decision.maximum_work_units,
        )

    def _coordinate_ages(self, state: MultiResolutionFastState) -> np.ndarray:
        last = np.zeros(KEY_BITS, dtype=np.uint64)
        for decision_step, flat_index in enumerate(
            state.decision_order[: state.decision_count],
            start=1,
        ):
            action = CausalAction.from_flat_index(int(flat_index), self.config)
            last[action.bit_index] = np.uint64(decision_step)
        return np.uint64(state.decision_count + 1) - last

    def _legal_actions(
        self,
        state: MultiResolutionFastState,
        *,
        allowed_horizons: Iterable[int] | None,
        maximum_work_units: int | None,
    ) -> tuple[list[CausalAction], bool]:
        if maximum_work_units is not None:
            _integer(
                maximum_work_units,
                "maximum_work_units",
                0,
                2_000_000_000,
            )
        allowed = (
            set(self.config.horizons)
            if allowed_horizons is None
            else set(allowed_horizons)
        )
        if not allowed <= set(self.config.horizons):
            raise MultiResolutionControllerError(
                "allowed_horizons contains unknown values"
            )
        cheapest = self.controller_config.ordered_horizons[0]
        candidates: list[CausalAction] = []
        for bit in range(KEY_BITS):
            current = self._current_depth(state, bit)
            depths = (
                (cheapest,)
                if current == 0
                else tuple(
                    horizon
                    for horizon in self.controller_config.ordered_horizons
                    if horizon > current
                )
            )
            for horizon in depths:
                if horizon not in allowed:
                    continue
                action = CausalAction(bit_index=bit, horizon=horizon)
                work = 2 * (horizon - current)
                if maximum_work_units is None or work <= maximum_work_units:
                    candidates.append(action)
        if not candidates:
            return [], False

        ages = self._coordinate_ages(state)
        coordinate_coverage = state.base.coverage.sum(axis=0, dtype=np.uint64)
        uncovered_candidates = [
            action
            for action in candidates
            if coordinate_coverage[action.bit_index] == 0
        ]
        maximum_age = max(
            (int(ages[action.bit_index]) for action in uncovered_candidates),
            default=0,
        )
        starvation_forced = (
            bool(uncovered_candidates)
            and maximum_age >= self.controller_config.starvation_steps
        )
        if starvation_forced:
            candidates = [
                action
                for action in candidates
                if coordinate_coverage[action.bit_index] == 0
                and int(ages[action.bit_index]) == maximum_age
            ]
        candidates.sort(
            key=lambda action: action.pool_blind_tiebreak_sha256(self.config)
        )
        return candidates, starvation_forced

    def _normalized_allowed_horizons(
        self,
        allowed_horizons: Iterable[int] | None,
    ) -> tuple[int, ...]:
        try:
            raw = (
                tuple(self.config.horizons)
                if allowed_horizons is None
                else tuple(allowed_horizons)
            )
        except TypeError as exc:
            raise MultiResolutionControllerError(
                "allowed_horizons must be an integer iterable"
            ) from exc
        known = set(self.config.horizons)
        if not raw or any(
            isinstance(value, bool) or not isinstance(value, int) or value not in known
            for value in raw
        ):
            raise MultiResolutionControllerError(
                "allowed_horizons contains unknown values"
            )
        normalized = tuple(sorted(set(raw)))
        if self.controller_config.ordered_horizons[0] not in normalized:
            raise MultiResolutionControllerError(
                "allowed_horizons must include the configured scout depth"
            )
        return normalized

    def _action_query_logits(
        self,
        state: MultiResolutionFastState,
        actions: Sequence[CausalAction],
    ) -> tuple[np.ndarray, np.ndarray]:
        return super()._action_query_logits(state.base, actions)

    def _critic_context(
        self,
        state: MultiResolutionFastState,
        action: CausalAction,
        orientation_query: float,
        common_query: float,
    ) -> np.ndarray:
        return super()._critic_context(
            state.base,
            action,
            orientation_query,
            common_query,
        )

    def _stop_is_eligible(self, state: MultiResolutionFastState) -> bool:
        if (
            self.critic.episode_count
            < self.controller_config.minimum_critic_episodes_before_stop
        ):
            return False
        if state.decision_count < self.controller_config.minimum_decisions_before_stop:
            return False
        if not self.controller_config.require_all_coordinates_before_stop:
            return True
        coordinate_coverage = state.base.coverage.sum(axis=0, dtype=np.uint64)
        return bool(np.all(coordinate_coverage > 0))

    def _validate_critic_binding(self) -> None:
        if self.critic.episode_count == 0:
            if self.critic_reader_sha256 != ZERO_SHA256:
                raise MultiResolutionControllerError(
                    "empty critic has a non-empty reader binding"
                )
            return
        if self.critic_reader_sha256 != self.reader_state_sha256:
            raise MultiResolutionControllerError(
                "critic is not bound to the current frozen reader"
            )

    def choose_action(
        self,
        state: MultiResolutionFastState,
        *,
        allowed_horizons: Iterable[int] | None = None,
        maximum_work_units: int | None = None,
    ) -> PacketActionDecision | PacketStopDecision | PacketExhaustedDecision:
        """Query every affordable address and return ACTION, STOP, or EXHAUSTED."""

        self._validate_live_state(state)
        self._validate_critic_binding()
        normalized_allowed = self._normalized_allowed_horizons(allowed_horizons)
        state_sha256 = state.sha256(self.controller_config)
        candidates, starvation_forced = self._legal_actions(
            state,
            allowed_horizons=normalized_allowed,
            maximum_work_units=maximum_work_units,
        )
        if not candidates:
            return PacketExhaustedDecision(
                remaining_work_units=maximum_work_units,
                state_before_sha256=state_sha256,
            )

        orientation, common = self._action_query_logits(state, candidates)
        coordinate_coverage = state.base.coverage.sum(axis=0, dtype=np.uint64)
        ages = self._coordinate_ages(state)
        ranked: list[tuple[float, str, PacketActionDecision]] = []
        for index, action in enumerate(candidates):
            context = self._critic_context(
                state,
                action,
                float(orientation[index]),
                float(common[index]),
            )
            prediction = self.critic.predict(
                np.ascontiguousarray(context, dtype=np.float64),
                self.controller_config.stationarity_penalty,
                self.controller_config.critic_exploration_scale,
            )
            coverage_bonus = self.controller_config.soft_coverage_weight / (
                1.0 + float(coordinate_coverage[action.bit_index])
            )
            age_fraction = min(
                float(ages[action.bit_index])
                / float(self.controller_config.starvation_steps),
                1.0,
            )
            age_bonus = self.controller_config.soft_age_weight * age_fraction
            work = self.action_physical_work_units(state, action)
            score = (
                prediction.conservative_lcb
                + prediction.epistemic_bonus
                + coverage_bonus
                + age_bonus
            ) / float(work)
            decision = PacketActionDecision(
                action=action,
                score=score,
                predicted_reward=prediction.mean,
                stationarity_std=prediction.across_episode_std,
                epistemic_bonus=prediction.epistemic_bonus,
                coverage_bonus=coverage_bonus,
                age_bonus=age_bonus,
                physical_work_units=work,
                starvation_forced=starvation_forced,
                state_before_sha256=state_sha256,
                context=context,
                allowed_horizons=normalized_allowed,
                maximum_work_units=maximum_work_units,
            )
            ranked.append(
                (
                    -score,
                    action.pool_blind_tiebreak_sha256(self.config),
                    decision,
                )
            )
        ranked.sort(key=lambda row: (row[0], row[1]))
        best = ranked[0][2]
        if (
            not starvation_forced
            and self._stop_is_eligible(state)
            and best.score <= self.controller_config.stop_margin
        ):
            return PacketStopDecision(
                score=0.0,
                best_candidate_score=best.score,
                state_before_sha256=state_sha256,
                allowed_horizons=normalized_allowed,
                maximum_work_units=maximum_work_units,
            )
        return best

    def apply_stop(
        self,
        state: MultiResolutionFastState,
        decision: PacketStopDecision,
    ) -> MultiResolutionFastState:
        """Commit a still-current STOP without conflating it with exhaustion."""

        if not isinstance(decision, PacketStopDecision):
            raise TypeError("decision must be PacketStopDecision")
        self._validate_live_state(state)
        if decision.state_before_sha256 != state.sha256(self.controller_config):
            raise MultiResolutionControllerError("stop decision is stale")
        recomputed = self.choose_action(
            state,
            allowed_horizons=decision.allowed_horizons,
            maximum_work_units=decision.maximum_work_units,
        )
        if recomputed != decision:
            raise MultiResolutionControllerError("stop decision proof differs")
        state.stopped = True
        state.stop_decision_count = state.decision_count
        state.stop_score = float(decision.score)
        state.validate(self.controller_config)
        return state

    def _validated_decision_order(
        self,
        flat_action_order: Sequence[int],
    ) -> list[int]:
        if not isinstance(flat_action_order, Sequence):
            raise TypeError("flat_action_order must be a sequence")
        order = list(flat_action_order)
        if (
            len(order) > self.controller_config.maximum_actions
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value < self.controller_config.maximum_actions
                for value in order
            )
            or len(set(order)) != len(order)
        ):
            raise MultiResolutionControllerError(
                "flat_action_order must contain unique configured actions"
            )
        depths = np.zeros(KEY_BITS, dtype=np.int64)
        for flat_index in order:
            action = CausalAction.from_flat_index(flat_index, self.config)
            if action.horizon <= int(depths[action.bit_index]):
                raise MultiResolutionControllerError(
                    "packet decision order must strictly deepen each coordinate"
                )
            depths[action.bit_index] = action.horizon
        return order

    def run_action_order(
        self,
        pool: Full256ActionPool,
        flat_action_order: Sequence[int],
    ) -> MultiResolutionFastState:
        """Run a predeclared pool-blind depth order with prefix auto-observation."""

        self.validate_pool(pool)
        order = self._validated_decision_order(flat_action_order)
        state = self.initial_fast_state(pool.source_stream_sha256)
        for flat_index in order:
            action = CausalAction.from_flat_index(flat_index, self.config)
            self._observe_requested_action(
                state,
                pool,
                action,
                maximum_work_units=None,
                expected_state_sha256=None,
                expected_work_units=None,
            )
        return state

    def run_policy(
        self,
        pool: Full256ActionPool,
        *,
        decision_budget: int,
        allowed_horizons: Iterable[int] | None = None,
    ) -> MultiResolutionFastState:
        self.validate_pool(pool)
        _integer(
            decision_budget,
            "decision_budget",
            0,
            self.controller_config.maximum_actions,
        )
        state = self.initial_fast_state(pool.source_stream_sha256)
        while state.decision_count < decision_budget:
            choice = self.choose_action(
                state,
                allowed_horizons=allowed_horizons,
            )
            if isinstance(choice, PacketActionDecision):
                self.apply_policy_action(state, pool, choice)
            elif isinstance(choice, PacketStopDecision):
                self.apply_stop(state, choice)
                break
            else:
                break
        return state

    def run_work_budgeted_policy(
        self,
        pool: Full256ActionPool,
        *,
        work_budget: int,
        allowed_horizons: Iterable[int] | None = None,
    ) -> MultiResolutionFastState:
        """Run ACTION/STOP under an exact incremental physical-work cap."""

        self.validate_pool(pool)
        _integer(work_budget, "work_budget", 0, 2_000_000_000)
        state = self.initial_fast_state(pool.source_stream_sha256)
        while True:
            remaining = work_budget - state.physical_work_units
            choice = self.choose_action(
                state,
                allowed_horizons=allowed_horizons,
                maximum_work_units=remaining,
            )
            if isinstance(choice, PacketActionDecision):
                self.apply_policy_action(state, pool, choice)
            elif isinstance(choice, PacketStopDecision):
                self.apply_stop(state, choice)
                break
            else:
                break
        if state.physical_work_units > work_budget:
            raise AssertionError("work-budgeted packet policy exceeded its cap")
        return state

    def _replay_packet_rewards(
        self,
        pool: Full256ActionPool,
        order: Sequence[int],
        labels: np.ndarray,
    ) -> PacketRewardReplay:
        state = self.initial_fast_state(pool.source_stream_sha256)
        contexts: list[np.ndarray] = []
        work_units: list[int] = []
        packet_delta_sums: list[float] = []
        rewards: list[float] = []
        initial_nll = _binary_nll_bits(state.base.posterior_logits, labels)
        for flat_index in order:
            action = CausalAction.from_flat_index(int(flat_index), self.config)
            orientation, common = self._action_query_logits(state, (action,))
            contexts.append(
                self._critic_context(
                    state,
                    action,
                    float(orientation[0]),
                    float(common[0]),
                )
            )
            before = _binary_nll_bits(state.base.posterior_logits, labels)
            receipt = self._observe_requested_action(
                state,
                pool,
                action,
                maximum_work_units=None,
                expected_state_sha256=None,
                expected_work_units=None,
            )
            after = _binary_nll_bits(state.base.posterior_logits, labels)
            work_units.append(receipt.physical_work_units)
            packet_delta_sums.append(receipt.packet_delta_sum)
            rewards.append(before - after)
        final_nll = _binary_nll_bits(state.base.posterior_logits, labels)
        reward_sum = float(sum(rewards))
        if not math.isclose(
            reward_sum,
            initial_nll - final_nll,
            rel_tol=0.0,
            abs_tol=1e-10,
        ):
            raise AssertionError("packet reward telescope differs")
        context_array = (
            np.asarray(contexts, dtype=np.float32)
            if contexts
            else np.empty(
                (0, self.controller_config.critic_context_dimension),
                dtype=np.float32,
            )
        )
        return PacketRewardReplay(
            action_order=np.asarray(order, dtype=np.uint16),
            contexts=context_array,
            physical_work_units=np.asarray(work_units, dtype=np.uint32),
            packet_delta_sums=np.asarray(packet_delta_sums, dtype=np.float32),
            delta_nll_bits=np.asarray(rewards, dtype=np.float64),
            initial_nll_bits=initial_nll,
            final_nll_bits=final_nll,
        )

    def replay_packet_rewards(
        self,
        pool: Full256ActionPool,
        flat_action_order: Sequence[int],
        key_labels: np.ndarray | Sequence[int],
    ) -> PacketRewardReplay:
        """Reveal-time exact credit replay that cannot mutate any slow byte."""

        self.validate_pool(pool)
        order = self._validated_decision_order(flat_action_order)
        labels = np.asarray(key_labels, dtype=np.float32)
        if labels.shape != (KEY_BITS,) or np.any((labels != 0.0) & (labels != 1.0)):
            raise MultiResolutionControllerError(
                "key_labels must be binary shape [256]"
            )
        slow_before = self.slow_state_bytes()
        replay = self._replay_packet_rewards(pool, order, labels)
        if self.slow_state_bytes() != slow_before:
            raise AssertionError("packet reward replay mutated slow state")
        return replay

    def fit_critic_episode(
        self,
        pool: Full256ActionPool,
        flat_action_order: Sequence[int],
        key_labels: np.ndarray | Sequence[int],
    ) -> PacketCriticFitReport:
        """Fit one episode-equal critic vote against the exact frozen reader."""

        self._validate_critic_binding()
        replay = self.replay_packet_rewards(pool, flat_action_order, key_labels)
        if replay.action_order.size == 0:
            raise MultiResolutionControllerError(
                "critic fitting requires at least one packet decision"
            )
        reader_sha256 = self.reader_state_sha256
        critic_before = self.critic.clone()
        binding_before = self.critic_reader_sha256
        try:
            fitted = self.critic.update_episode(
                np.ascontiguousarray(replay.contexts, dtype=np.float64),
                np.ascontiguousarray(replay.delta_nll_bits, dtype=np.float64),
            )
            self.critic_reader_sha256 = reader_sha256
            self._validate_critic_binding()
        except Exception:
            self.critic = critic_before
            self.critic_reader_sha256 = binding_before
            raise
        fitted_sha256 = hashlib.sha256(
            np.asarray(fitted, dtype="<f8").tobytes(order="C")
        ).hexdigest()
        return PacketCriticFitReport(
            decisions=int(replay.action_order.size),
            reward_sum_bits=replay.initial_nll_bits - replay.final_nll_bits,
            positive_reward_decisions=int(np.sum(replay.delta_nll_bits > 0.0)),
            fitted_weight_sha256=fitted_sha256,
            critic_episode_count=self.critic.episode_count,
            reader_state_sha256=reader_sha256,
        )

    def refit_critic_corpus(
        self,
        episodes: Sequence[
            tuple[
                Full256ActionPool,
                Sequence[int],
                np.ndarray | Sequence[int],
            ]
        ],
    ) -> PacketCriticCorpusReport:
        """Atomically refit all BUILD credit after freezing the final reader.

        Episode action pools remain external artifacts; only fixed-size critic
        sufficient statistics survive this call.
        """

        if not isinstance(episodes, Sequence) or not episodes:
            raise MultiResolutionControllerError(
                "critic corpus must contain at least one BUILD episode"
            )
        sources: set[str] = set()
        for entry in episodes:
            if not isinstance(entry, tuple) or len(entry) != 3:
                raise MultiResolutionControllerError(
                    "each critic corpus entry must be (pool, order, labels)"
                )
            pool = entry[0]
            if not isinstance(pool, Full256ActionPool):
                raise TypeError("critic corpus pools must be Full256ActionPool")
            if pool.source_stream_sha256 in sources:
                raise MultiResolutionControllerError(
                    "critic corpus source hashes must be unique"
                )
            sources.add(pool.source_stream_sha256)
        frozen_reader_sha256 = self.reader_state_sha256
        critic_before = self.critic.clone()
        binding_before = self.critic_reader_sha256
        try:
            self.critic = EpisodeEqualRidgeCritic.initial(
                self.controller_config.critic_context_dimension,
                self.config.critic_ridge,
            )
            self.critic_reader_sha256 = ZERO_SHA256
            reports: list[PacketCriticFitReport] = []
            for entry in episodes:
                pool, order, labels = entry
                reports.append(self.fit_critic_episode(pool, order, labels))
            if self.reader_state_sha256 != frozen_reader_sha256:
                raise AssertionError("critic refit changed the frozen reader")
            self._validate_critic_binding()
        except Exception:
            self.critic = critic_before
            self.critic_reader_sha256 = binding_before
            raise
        return PacketCriticCorpusReport(
            episode_reports=tuple(reports),
            total_decisions=sum(report.decisions for report in reports),
            final_critic_sha256=self.critic.sha256(),
            reader_state_sha256=frozen_reader_sha256,
        )

    def _expanded_training_slots(
        self,
        order: Sequence[int],
    ) -> list[tuple[CausalAction, int]]:
        depths = np.zeros(KEY_BITS, dtype=np.int64)
        result: list[tuple[CausalAction, int]] = []
        for flat_index in order:
            requested = CausalAction.from_flat_index(int(flat_index), self.config)
            previous = int(depths[requested.bit_index])
            for horizon in self.controller_config.ordered_horizons:
                if previous < horizon <= requested.horizon:
                    action = CausalAction(requested.bit_index, horizon)
                    result.append((action, 2 * (horizon - previous)))
                    previous = horizon
            if previous != requested.horizon:
                raise MultiResolutionControllerError(
                    "training packet expansion differs"
                )
            depths[requested.bit_index] = requested.horizon
        return result

    def _train_packet_reader_episode(
        self,
        pool: Full256ActionPool,
        order: Sequence[int],
        labels: np.ndarray,
        *,
        train_stream: bool,
        train_gate: bool,
    ) -> tuple[tuple[float, ...], int]:
        slots = self._expanded_training_slots(order)
        if not slots:
            return (), 0
        if not train_stream and not train_gate:
            raise MultiResolutionControllerError(
                "at least one reader component must be trainable"
            )

        nuisance = OnlineNuisanceState.initial(self.config)
        positive = self.reader.core.initial_state(1)
        negative = self.reader.core.initial_state(1)
        packet = torch.zeros(
            (self.controller_config.horizon_count, KEY_BITS),
            dtype=torch.float32,
        )
        packet_mask = torch.zeros_like(packet, dtype=torch.bool)
        label_tensor = torch.from_numpy(labels.astype(np.float32, copy=False))
        parameters = tuple(
            parameter
            for module, enabled in (
                (self.reader, train_stream),
                (self.gate, train_gate),
            )
            if enabled
            for parameter in module.parameters()
        )
        optimizer = torch.optim.SGD(
            parameters,
            lr=self.config.reader_learning_rate,
        )
        self.reader.zero_grad(set_to_none=True)
        self.gate.zero_grad(set_to_none=True)
        self.reader.train(mode=train_stream)
        self.gate.train(mode=train_gate)
        losses: list[float] = []
        chunk_loss = None
        chunk_count = 0
        seen_bits: list[int] = []

        for slot_step, (action, incremental_work) in enumerate(slots, start=1):
            observation = PairedCausalObservation.from_pool(pool, action)
            horizon_index = self._horizon_index(action.horizon)
            odd_primary, odd_residual, even = nuisance.transform(
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
                action,
                incremental_work,
                mirror=False,
            )[None]
            negative_event = self._event(
                odd_primary,
                odd_residual,
                even,
                action,
                incremental_work,
                mirror=True,
            )[None]
            address = self._address(
                action.bit_index,
                horizon_index,
                token_kind=0,
            )[None]
            if train_stream:
                delta, positive, negative = self._stream_packet_delta_torch(
                    positive,
                    negative,
                    positive_event,
                    negative_event,
                    address,
                    action.bit_index,
                )
            else:
                with torch.no_grad():
                    delta, positive, negative = self._stream_packet_delta_torch(
                        positive,
                        negative,
                        positive_event,
                        negative_event,
                        address,
                        action.bit_index,
                    )
                delta = delta.detach()

            updated_packet = packet.clone()
            updated_packet[horizon_index, action.bit_index] = delta
            packet = updated_packet
            updated_mask = packet_mask.clone()
            updated_mask[horizon_index, action.bit_index] = True
            packet_mask = updated_mask
            logits = self.gate(
                packet.T,
                packet_mask.T,
                logit_clip=self.config.posterior_logit_clip,
            )
            immediate = torch.nn.functional.binary_cross_entropy_with_logits(
                logits[action.bit_index : action.bit_index + 1],
                label_tensor[action.bit_index : action.bit_index + 1],
            ) / math.log(2.0)
            chunk_loss = immediate if chunk_loss is None else chunk_loss + immediate
            chunk_count += 1
            if action.bit_index not in seen_bits:
                seen_bits.append(action.bit_index)

            boundary = (
                chunk_count == self.config.gradient_chunk_actions
                or slot_step == len(slots)
            )
            if boundary:
                averaged_immediate = chunk_loss / float(chunk_count)
                if self.config.recall_loss_weight > 0.0:
                    indexes = torch.tensor(seen_bits, dtype=torch.int64)
                    recall = torch.nn.functional.binary_cross_entropy_with_logits(
                        logits[indexes],
                        label_tensor[indexes],
                    ) / math.log(2.0)
                    averaged = (
                        averaged_immediate + self.config.recall_loss_weight * recall
                    ) / (1.0 + self.config.recall_loss_weight)
                else:
                    averaged = averaged_immediate
                weighted_for_episode = averaged * (
                    float(chunk_count) / float(len(slots))
                )
                weighted_for_episode.backward()
                losses.append(float(averaged.detach()))
                positive = positive.detached()
                negative = negative.detached()
                packet = packet.detach()
                chunk_loss = None
                chunk_count = 0

        # The complete episode is forwarded by one frozen reader/gate snapshot.
        # Chunk boundaries truncate graph history and accumulate gradients only;
        # stepping inside the stream would create a mixed-parameter fast state
        # that can never occur when the final reader attacks the next target.
        torch.nn.utils.clip_grad_norm_(
            parameters,
            self.config.gradient_clip,
        )
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
        self.reader.zero_grad(set_to_none=True)
        self.gate.zero_grad(set_to_none=True)
        self.reader.eval()
        self.gate.eval()
        return tuple(losses), len(slots)

    def learn_reader_after_reveal(
        self,
        pool: Full256ActionPool,
        completed_state: MultiResolutionFastState,
        key_labels: np.ndarray | Sequence[int],
        *,
        train_stream: bool = True,
        train_gate: bool = True,
    ) -> PacketTrainingReport:
        """Train representation/readout after reveal and invalidate stale credit."""

        self.validate_pool(pool)
        self._validate_attached_state(completed_state, allow_stopped=True)
        if completed_state.base.source_stream_sha256 != pool.source_stream_sha256:
            raise MultiResolutionControllerError(
                "completed state and action pool source differ"
            )
        if not isinstance(train_stream, bool) or not isinstance(train_gate, bool):
            raise MultiResolutionControllerError("training flags must be boolean")
        labels = np.asarray(key_labels, dtype=np.float32)
        if labels.shape != (KEY_BITS,) or np.any((labels != 0.0) & (labels != 1.0)):
            raise MultiResolutionControllerError(
                "key_labels must be binary shape [256]"
            )
        order = [
            int(value)
            for value in completed_state.decision_order[
                : completed_state.decision_count
            ]
        ]
        if not order:
            raise MultiResolutionControllerError(
                "reader training requires at least one packet decision"
            )

        reader_before = self.reader_state_bytes()
        reader_sha_before = hashlib.sha256(reader_before).hexdigest()
        critic_before = self.critic.clone()
        binding_before = self.critic_reader_sha256
        episodes_before = self.reader_episodes
        try:
            losses, observed_slots = self._train_packet_reader_episode(
                pool,
                order,
                labels,
                train_stream=train_stream,
                train_gate=train_gate,
            )
            self.reader_episodes += 1
            critic_invalidated = self.critic.episode_count > 0
            self.critic = EpisodeEqualRidgeCritic.initial(
                self.controller_config.critic_context_dimension,
                self.config.critic_ridge,
            )
            self.critic_reader_sha256 = ZERO_SHA256
            reader_sha_after = self.reader_state_sha256
            self._validate_critic_binding()
        except Exception:
            self.load_reader_state_bytes(reader_before)
            self.critic = critic_before
            self.critic_reader_sha256 = binding_before
            self.reader_episodes = episodes_before
            self.reader.eval()
            self.gate.eval()
            raise

        completed_state.base.reveal_consumed = True
        completed_state.validate(self.controller_config)
        return PacketTrainingReport(
            decisions=len(order),
            observed_slots=observed_slots,
            training_loss_bits=losses,
            reader_state_sha256_before=reader_sha_before,
            reader_state_sha256_after=reader_sha_after,
            critic_invalidated=critic_invalidated,
        )


__all__ = [
    "MULTIRESOLUTION_CONTROLLER_SCHEMA",
    "MULTIRESOLUTION_FAST_STATE_SCHEMA",
    "MULTIRESOLUTION_MODEL_SCHEMA",
    "MULTIRESOLUTION_SLOW_STATE_SCHEMA",
    "MultiResolutionCausalController",
    "MultiResolutionControllerConfig",
    "MultiResolutionControllerError",
    "MultiResolutionFastState",
    "OddHorizonGate",
    "PacketActionDecision",
    "PacketCriticFitReport",
    "PacketCriticCorpusReport",
    "PacketExhaustedDecision",
    "PacketObservationReceipt",
    "PacketRewardReplay",
    "PacketStopDecision",
    "PacketTrainingReport",
]
