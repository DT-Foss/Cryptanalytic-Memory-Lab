"""Full-round ChaCha20 online-reader and learned-picker development gate.

BUILD targets expose their keys only after immutable public proof pools exist.
The learned O1 reader and three reward models are then frozen before disjoint
DEVELOPMENT or EVALUATION targets are generated.  Every evaluation trajectory
is frozen before its key labels are materialized.

The public proof pools are currently generated exhaustively.  Consequently the
picker result measures information per *logically requested* solver conflict;
it does not yet claim native wall-clock savings from lazy proof execution.
"""

from __future__ import annotations

import hashlib
import json
import math
import resource
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

import numpy as np

from .full256_action_pool import Full256ActionPool
from .full256_proof_pool import (
    DeterministicKnownTarget,
    FrozenFull256ProofPool,
    Full256ProofPoolBuilder,
    make_deterministic_known_target,
)
from .living_inverse import KEY_BITS, canonical_json_bytes
from .online_causal_controller import (
    CausalAction,
    OnlineCausalController,
    OnlineCausalControllerConfig,
    OnlineCausalFastState,
    PairedCausalObservation,
)


REAL_GATE_SCHEMA = "o1-256-fullround-online-real-gate-v1"
REAL_GATE_CONFIG_SCHEMA = "o1-256-fullround-online-real-gate-config-v1"
REAL_GATE_LEARNING_FREEZE_SCHEMA = (
    "o1-256-fullround-online-learning-freeze-v1"
)
REAL_GATE_BUILD_PREDICTION_FREEZE_SCHEMA = (
    "o1-256-fullround-online-build-prediction-freeze-v1"
)
REAL_GATE_PREDICTION_FREEZE_SCHEMA = (
    "o1-256-fullround-online-prediction-freeze-v1"
)
REAL_GATE_RESULT_SCHEMA = "o1-256-fullround-online-real-gate-result-v1"

RAW_ARMS = (
    "learned_reader_full_field",
    "untrained_reader_full_field",
    "coordinate_rotation_control",
    "raw_o1_end_state",
)
POLICY_ARMS = (
    "learned_true_reward",
    "learned_shifted_reward",
    "build_static_reward",
    "shortest_first",
    "uniform_hash",
)

ArtifactCallback = Callable[[Mapping[str, bytes], Mapping[str, object]], None]


class Full256OnlineRealGateError(ValueError):
    """A gate configuration, lifecycle boundary, or trajectory differs."""


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256OnlineRealGateError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _finite(value: object, field: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise Full256OnlineRealGateError(
            f"{field} must be finite in [{minimum},{maximum}]"
        )
    return float(value)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if value > 16 * 1024 * 1024 else value * 1024


def _classify_gate_outcome(
    structural_gates: Mapping[str, bool],
    raw_gates: Mapping[str, bool],
    picker_gates: Mapping[str, bool],
) -> tuple[str, bool, bool, bool]:
    """Keep lifecycle failures distinct from a genuine no-signal result."""

    structural_passed = all(structural_gates.values())
    raw_passed = structural_passed and all(raw_gates.values())
    picker_passed = raw_passed and all(picker_gates.values())
    if not structural_passed:
        classification = "OPERATIONAL_FAILURE"
    elif picker_passed:
        classification = "DUAL_PASS"
    elif raw_passed:
        classification = "RAW_ONLY_PASS"
    else:
        classification = "NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE"
    return classification, structural_passed, raw_passed, picker_passed


def _trajectory_paths_are_nested(
    action_orders: np.ndarray,
    checkpoint_counts: np.ndarray,
    checkpoint_work: np.ndarray,
    *,
    horizons: Sequence[int],
    work_caps: Sequence[int],
) -> bool:
    """Verify every checkpoint is an exact prefix of one final action ledger."""

    if action_orders.ndim != 3 or checkpoint_counts.ndim != 3:
        return False
    if checkpoint_work.shape != checkpoint_counts.shape:
        return False
    if action_orders.shape[:2] != checkpoint_counts.shape[:2]:
        return False
    if checkpoint_counts.shape[2] != len(work_caps):
        return False
    maximum_actions = len(horizons) * KEY_BITS
    if action_orders.shape[2] != maximum_actions:
        return False
    sentinel = np.iinfo(np.uint16).max
    caps = np.asarray(work_caps, dtype=np.int64)
    for arm_index in range(action_orders.shape[0]):
        for target_index in range(action_orders.shape[1]):
            counts = checkpoint_counts[arm_index, target_index].astype(np.int64)
            work = checkpoint_work[arm_index, target_index].astype(np.int64)
            if (
                np.any(np.diff(counts) < 0)
                or np.any(np.diff(work) < 0)
                or np.any(counts < 0)
                or np.any(counts > maximum_actions)
                or np.any(work < 0)
                or np.any(work > caps)
            ):
                return False
            final_count = int(counts[-1])
            ledger = action_orders[arm_index, target_index]
            prefix = ledger[:final_count]
            if (
                np.any(prefix == sentinel)
                or np.any(prefix >= maximum_actions)
                or len(set(int(value) for value in prefix)) != final_count
                or np.any(ledger[final_count:] != sentinel)
            ):
                return False
            for checkpoint_index, count in enumerate(counts):
                requested = sum(
                    2 * int(horizons[int(flat_index) // KEY_BITS])
                    for flat_index in ledger[: int(count)]
                )
                if requested != int(work[checkpoint_index]):
                    return False
    return True


@dataclass(frozen=True)
class Full256OnlineRealGateConfig:
    """Frozen BUILD/evaluation contract for one reader/picker lineage."""

    controller: OnlineCausalControllerConfig
    corpus_seed: int = 180_018
    build_targets: int = 4
    evaluation_targets: int = 2
    build_index_start: int = 0
    evaluation_index_start: int = 0
    evaluation_split: str = "DEVELOPMENT"
    work_checkpoints: tuple[int, ...] = (16_384, 32_768, 57_600)
    coordinate_rotation: int = 73
    maximum_checkpoint_slack: int = 191
    minimum_raw_mean_compression_bits: float = 0.0
    minimum_raw_control_margin_bits: float = 0.0
    minimum_raw_positive_targets: int = 1
    minimum_picker_iauc_margin_bits: float = 0.0
    minimum_picker_win_targets: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.controller, OnlineCausalControllerConfig):
            raise Full256OnlineRealGateError(
                "controller must be OnlineCausalControllerConfig"
            )
        if self.controller.horizon_count != 3:
            raise Full256OnlineRealGateError(
                "real gate requires exactly three controller horizons"
            )
        _integer(self.corpus_seed, "corpus_seed", 0, (1 << 63) - 1)
        _integer(self.build_targets, "build_targets", 1, 64)
        _integer(self.evaluation_targets, "evaluation_targets", 1, 64)
        _integer(self.build_index_start, "build_index_start", 0, 1_000_000)
        _integer(
            self.evaluation_index_start,
            "evaluation_index_start",
            0,
            1_000_000,
        )
        if self.evaluation_split not in {"DEVELOPMENT", "EVALUATION"}:
            raise Full256OnlineRealGateError(
                "evaluation_split must be DEVELOPMENT or EVALUATION"
            )
        if (
            not isinstance(self.work_checkpoints, tuple)
            or len(self.work_checkpoints) != 3
            or any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                for value in self.work_checkpoints
            )
            or tuple(sorted(self.work_checkpoints)) != self.work_checkpoints
            or len(set(self.work_checkpoints)) != len(self.work_checkpoints)
        ):
            raise Full256OnlineRealGateError(
                "work_checkpoints must be three strictly increasing integers"
            )
        exhaustive_work = 2 * KEY_BITS * sum(self.controller.horizons)
        if self.work_checkpoints[-1] >= exhaustive_work:
            raise Full256OnlineRealGateError(
                "final work checkpoint must remain sub-exhaustive"
            )
        _integer(self.coordinate_rotation, "coordinate_rotation", 1, KEY_BITS - 1)
        _integer(
            self.maximum_checkpoint_slack,
            "maximum_checkpoint_slack",
            0,
            2 * max(self.controller.horizons) - 1,
        )
        _finite(
            self.minimum_raw_mean_compression_bits,
            "minimum_raw_mean_compression_bits",
            -KEY_BITS,
            KEY_BITS,
        )
        _finite(
            self.minimum_raw_control_margin_bits,
            "minimum_raw_control_margin_bits",
            -KEY_BITS,
            KEY_BITS,
        )
        _integer(
            self.minimum_raw_positive_targets,
            "minimum_raw_positive_targets",
            1,
            self.evaluation_targets,
        )
        _finite(
            self.minimum_picker_iauc_margin_bits,
            "minimum_picker_iauc_margin_bits",
            -KEY_BITS,
            KEY_BITS,
        )
        _integer(
            self.minimum_picker_win_targets,
            "minimum_picker_win_targets",
            1,
            self.evaluation_targets,
        )

    @property
    def maximum_actions(self) -> int:
        return self.controller.maximum_actions

    def describe(self) -> dict[str, object]:
        return {
            "schema": REAL_GATE_CONFIG_SCHEMA,
            "controller": self.controller.describe(),
            "corpus_seed": self.corpus_seed,
            "build_targets": self.build_targets,
            "evaluation_targets": self.evaluation_targets,
            "build_index_start": self.build_index_start,
            "evaluation_index_start": self.evaluation_index_start,
            "evaluation_split": self.evaluation_split,
            "work_checkpoints": list(self.work_checkpoints),
            "coordinate_rotation": self.coordinate_rotation,
            "maximum_checkpoint_slack": self.maximum_checkpoint_slack,
            "minimum_raw_mean_compression_bits": (
                self.minimum_raw_mean_compression_bits
            ),
            "minimum_raw_control_margin_bits": (
                self.minimum_raw_control_margin_bits
            ),
            "minimum_raw_positive_targets": self.minimum_raw_positive_targets,
            "minimum_picker_iauc_margin_bits": (
                self.minimum_picker_iauc_margin_bits
            ),
            "minimum_picker_win_targets": self.minimum_picker_win_targets,
            "fullround_chacha20": True,
            "unknown_key_bits_at_probe": KEY_BITS,
            "target_key_inputs_to_probe": 0,
            "target_trace_inputs": 0,
            "native_pool_execution": "exhaustive-before-logical-policy-replay",
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.describe())


@dataclass(frozen=True)
class _Trajectory:
    logits: np.ndarray
    checkpoint_work: np.ndarray
    checkpoint_action_counts: np.ndarray
    action_order: np.ndarray
    final_state: OnlineCausalFastState


@dataclass(frozen=True)
class Full256OnlineRealGateResult:
    report: dict[str, object]
    raw_predictions: np.ndarray
    policy_predictions: np.ndarray
    labels: np.ndarray
    raw_compressions: np.ndarray
    policy_compressions: np.ndarray
    iauc: np.ndarray
    action_orders: np.ndarray
    checkpoint_action_counts: np.ndarray
    checkpoint_work: np.ndarray
    primary_slow_state: bytes
    shifted_slow_state: bytes
    static_reward_mean: np.ndarray
    build_reward_deltas: np.ndarray

    def __post_init__(self) -> None:
        evaluation_targets = int(self.report["evaluation_targets"])
        checkpoints = len(self.report["work_checkpoints"])
        maximum_actions = int(self.report["maximum_actions"])
        build_targets = int(self.report["build_targets"])
        expected_raw = (len(RAW_ARMS), evaluation_targets, KEY_BITS)
        expected_policy = (
            len(POLICY_ARMS),
            evaluation_targets,
            checkpoints,
            KEY_BITS,
        )
        if (
            self.raw_predictions.shape != expected_raw
            or self.raw_predictions.dtype != np.float32
            or not np.all(np.isfinite(self.raw_predictions))
            or self.policy_predictions.shape != expected_policy
            or self.policy_predictions.dtype != np.float32
            or not np.all(np.isfinite(self.policy_predictions))
        ):
            raise Full256OnlineRealGateError("prediction arrays differ")
        if (
            self.labels.shape != (evaluation_targets, KEY_BITS)
            or self.labels.dtype != np.uint8
            or np.any((self.labels != 0) & (self.labels != 1))
            or self.raw_compressions.shape
            != (len(RAW_ARMS), evaluation_targets)
            or self.raw_compressions.dtype != np.float64
            or self.policy_compressions.shape
            != (len(POLICY_ARMS), evaluation_targets, checkpoints)
            or self.policy_compressions.dtype != np.float64
            or self.iauc.shape != (len(POLICY_ARMS), evaluation_targets)
            or self.iauc.dtype != np.float64
            or not np.all(np.isfinite(self.raw_compressions))
            or not np.all(np.isfinite(self.policy_compressions))
            or not np.all(np.isfinite(self.iauc))
        ):
            raise Full256OnlineRealGateError("score arrays differ")
        if (
            self.action_orders.shape
            != (len(POLICY_ARMS), evaluation_targets, maximum_actions)
            or self.action_orders.dtype != np.uint16
            or self.checkpoint_action_counts.shape
            != (len(POLICY_ARMS), evaluation_targets, checkpoints)
            or self.checkpoint_action_counts.dtype != np.uint16
            or self.checkpoint_work.shape
            != (len(POLICY_ARMS), evaluation_targets, checkpoints)
            or self.checkpoint_work.dtype != np.uint32
        ):
            raise Full256OnlineRealGateError("trajectory arrays differ")
        if (
            self.static_reward_mean.shape != (maximum_actions,)
            or self.static_reward_mean.dtype != np.float64
            or self.build_reward_deltas.shape
            != (build_targets, maximum_actions)
            or self.build_reward_deltas.dtype != np.float64
            or not np.all(np.isfinite(self.static_reward_mean))
            or not np.all(np.isfinite(self.build_reward_deltas))
        ):
            raise Full256OnlineRealGateError("BUILD reward arrays differ")
        if not self.primary_slow_state or not self.shifted_slow_state:
            raise Full256OnlineRealGateError("slow-state artifacts are empty")
        horizons = tuple(self.report["config"]["controller"]["horizons"])
        caps = np.asarray(self.report["work_checkpoints"], dtype=np.int64)
        sentinel = np.iinfo(np.uint16).max
        for arm_index in range(len(POLICY_ARMS)):
            for target_index in range(evaluation_targets):
                counts = self.checkpoint_action_counts[
                    arm_index, target_index
                ].astype(np.int64)
                work = self.checkpoint_work[arm_index, target_index].astype(
                    np.int64
                )
                if np.any(np.diff(counts) < 0) or np.any(np.diff(work) < 0):
                    raise Full256OnlineRealGateError(
                        "checkpoint trajectories are not nested"
                    )
                if np.any(work < 0) or np.any(work > caps):
                    raise Full256OnlineRealGateError(
                        "checkpoint trajectory exceeds its work cap"
                    )
                final_count = int(counts[-1])
                ledger = self.action_orders[arm_index, target_index]
                if (
                    final_count > maximum_actions
                    or len(set(int(value) for value in ledger[:final_count]))
                    != final_count
                    or np.any(ledger[:final_count] == sentinel)
                    or np.any(ledger[final_count:] != sentinel)
                ):
                    raise Full256OnlineRealGateError("action ledger differs")
                for checkpoint_index, count in enumerate(counts):
                    requested = 0
                    for flat_index in ledger[: int(count)]:
                        horizon_index = int(flat_index) // KEY_BITS
                        requested += 2 * int(horizons[horizon_index])
                    if requested != int(work[checkpoint_index]):
                        raise Full256OnlineRealGateError(
                            "checkpoint work and ledger prefix differ"
                        )

    @property
    def success_gate_passed(self) -> bool:
        return bool(self.report["gates"]["success_gate_passed"])

    def prediction_artifacts(self) -> dict[str, bytes]:
        return {
            "raw_predictions.f32le": self.raw_predictions.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
            "policy_predictions.f32le": self.policy_predictions.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
            "action_orders.u16le": self.action_orders.astype(
                "<u2", copy=False
            ).tobytes(order="C"),
            "checkpoint_action_counts.u16le": (
                self.checkpoint_action_counts.astype("<u2", copy=False).tobytes(
                    order="C"
                )
            ),
            "checkpoint_work.u32le": self.checkpoint_work.astype(
                "<u4", copy=False
            ).tobytes(order="C"),
        }


def interleaved_latin_action_order(
    config: OnlineCausalControllerConfig,
    ordinal: int,
) -> tuple[int, ...]:
    """Return a pool-blind 768-action Latin schedule with early bit coverage."""

    _integer(ordinal, "ordinal", 0, 1_000_000)
    if config.horizon_count != 3:
        raise Full256OnlineRealGateError("Latin schedule requires three horizons")
    rotation = (ordinal * 67) % KEY_BITS
    order: list[int] = []
    for pass_index in range(config.horizon_count):
        for rank in range(KEY_BITS):
            bit_index = (rank + rotation) % KEY_BITS
            horizon_index = (rank + pass_index + ordinal) % config.horizon_count
            order.append(horizon_index * KEY_BITS + bit_index)
    if len(order) != config.maximum_actions or len(set(order)) != len(order):
        raise AssertionError("Latin action schedule is not exhaustive")
    return tuple(order)


def _nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    signed = (2.0 * truth - 1.0) * values
    return float(np.logaddexp(0.0, -signed).sum() / math.log(2.0))


def _conditional_z(values: np.ndarray) -> float | None:
    vector = np.asarray(values, dtype=np.float64)
    if vector.size < 2:
        return None
    deviation = float(vector.std(ddof=1))
    if deviation == 0.0:
        return None
    return float(vector.mean() / (deviation / math.sqrt(vector.size)))


def _arm_summary(
    name: str,
    logits: np.ndarray,
    labels: np.ndarray,
    compression: np.ndarray,
) -> dict[str, object]:
    predicted = logits >= 0.0
    correct = predicted == labels.astype(bool)
    per_target = correct.sum(axis=-1)
    return {
        "name": name,
        "mean_compression_bits": float(compression.mean()),
        "compression_stddev_bits": (
            float(compression.std(ddof=1)) if compression.size > 1 else 0.0
        ),
        "conditional_z_score": _conditional_z(compression),
        "positive_targets": int(np.sum(compression > 0.0)),
        "bit_accuracy": float(correct.mean()),
        "mean_correct_bits_per_target": float(per_target.mean()),
        "minimum_correct_bits": int(per_target.min()),
        "maximum_correct_bits": int(per_target.max()),
        "exact_keys": int(np.sum(per_target == KEY_BITS)),
    }


def _observe_action(
    controller: OnlineCausalController,
    state: OnlineCausalFastState,
    pool: Full256ActionPool,
    action: CausalAction,
) -> int:
    controller.observe(state, PairedCausalObservation.from_pool(pool, action))
    return 2 * action.horizon


def _freeze_trajectory(
    controller: OnlineCausalController,
    state: OnlineCausalFastState,
    checkpoint_logits: Sequence[np.ndarray],
    checkpoint_work: Sequence[int],
    checkpoint_counts: Sequence[int],
) -> _Trajectory:
    order = np.full(
        controller.config.maximum_actions,
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    order[: state.action_count] = state.action_order[: state.action_count]
    result = _Trajectory(
        logits=np.asarray(checkpoint_logits, dtype=np.float32),
        checkpoint_work=np.asarray(checkpoint_work, dtype=np.uint32),
        checkpoint_action_counts=np.asarray(checkpoint_counts, dtype=np.uint16),
        action_order=order,
        final_state=state,
    )
    return result


def _run_learned_trajectory(
    controller: OnlineCausalController,
    pool: Full256ActionPool,
    checkpoints: Sequence[int],
) -> _Trajectory:
    state = controller.initial_fast_state(pool.source_stream_sha256)
    used = 0
    logits: list[np.ndarray] = []
    work: list[int] = []
    counts: list[int] = []
    for cap in checkpoints:
        while True:
            choice = controller.choose_action(
                state,
                maximum_work_units=cap - used,
            )
            if choice is None:
                break
            used += _observe_action(controller, state, pool, choice.action)
        logits.append(state.posterior_logits.copy())
        work.append(used)
        counts.append(state.action_count)
    return _freeze_trajectory(controller, state, logits, work, counts)


def _run_control_trajectory(
    controller: OnlineCausalController,
    pool: Full256ActionPool,
    checkpoints: Sequence[int],
    *,
    arm: str,
    static_scores: np.ndarray,
) -> _Trajectory:
    state = controller.initial_fast_state(pool.source_stream_sha256)
    used_actions = np.zeros(controller.config.maximum_actions, dtype=np.bool_)
    used_work = 0
    logits: list[np.ndarray] = []
    work: list[int] = []
    counts: list[int] = []
    hashes = tuple(
        CausalAction.from_flat_index(flat, controller.config)
        .pool_blind_tiebreak_sha256(controller.config)
        for flat in range(controller.config.maximum_actions)
    )
    for cap in checkpoints:
        while True:
            remaining = cap - used_work
            candidates = [
                flat
                for flat in range(controller.config.maximum_actions)
                if not used_actions[flat]
                and 2
                * CausalAction.from_flat_index(flat, controller.config).horizon
                <= remaining
            ]
            if not candidates:
                break
            coordinate_coverage = state.coverage.sum(axis=0, dtype=np.uint64)
            minimum_coverage = min(
                int(
                    coordinate_coverage[
                        CausalAction.from_flat_index(flat, controller.config).bit_index
                    ]
                )
                for flat in candidates
            )
            candidates = [
                flat
                for flat in candidates
                if int(
                    coordinate_coverage[
                        CausalAction.from_flat_index(flat, controller.config).bit_index
                    ]
                )
                == minimum_coverage
            ]
            if arm == "build_static_reward":
                flat_index = min(
                    candidates,
                    key=lambda flat: (-float(static_scores[flat]), hashes[flat]),
                )
            elif arm == "shortest_first":
                flat_index = min(
                    candidates,
                    key=lambda flat: (
                        2
                        * CausalAction.from_flat_index(
                            flat, controller.config
                        ).horizon,
                        hashes[flat],
                    ),
                )
            elif arm == "uniform_hash":
                flat_index = min(candidates, key=lambda flat: hashes[flat])
            else:
                raise Full256OnlineRealGateError("unknown control policy arm")
            action = CausalAction.from_flat_index(flat_index, controller.config)
            used_actions[flat_index] = True
            used_work += _observe_action(controller, state, pool, action)
        logits.append(state.posterior_logits.copy())
        work.append(used_work)
        counts.append(state.action_count)
    return _freeze_trajectory(controller, state, logits, work, counts)


def _common_only_pool(pool: Full256ActionPool) -> Full256ActionPool:
    features = pool.branch_features.copy()
    even = np.float32(0.5) * (features[:, :, 0] + features[:, :, 1])
    features[:, :, 0] = even
    features[:, :, 1] = even
    source_sha256 = hashlib.sha256(
        canonical_json_bytes(
            [
                "o1c0018-common-only-control-v1",
                pool.source_stream_sha256,
                pool.action_pool_sha256,
            ]
        )
    ).hexdigest()
    return Full256ActionPool(
        horizons=pool.horizons,
        branch_features=features,
        final_resources=pool.final_resources,
        pair_sha256=pool.pair_sha256,
        source_stream_sha256=source_sha256,
    )


def _pool_freeze_artifacts(
    frozen: FrozenFull256ProofPool,
    *,
    split: str,
) -> tuple[dict[str, bytes], dict[str, object]]:
    document = {
        "schema": REAL_GATE_SCHEMA,
        "phase": "PUBLIC_PROOF_POOL_FROZEN_BEFORE_LABEL_ACCESS",
        "split": split,
        "target_id": frozen.target_id,
        "public_view_sha256": frozen.public.digest(),
        "action_pool_sha256": frozen.action_pool_sha256,
        "action_pool_bytes": len(frozen.action_pool_bytes),
        "target_key_inputs_to_probe": 0,
        "target_trace_inputs": 0,
        "labels_materialized": 0,
        "pool": frozen.describe(include_resources=False),
    }
    document["freeze_sha256"] = _canonical_sha256(document)
    return (
        {
            f"pools/{frozen.target_id}.fap": frozen.action_pool_bytes,
            f"pools/{frozen.target_id}.json": _json_bytes(document),
        },
        document,
    )


def _persist_callback(
    callback: ArtifactCallback | None,
    artifacts: Mapping[str, bytes],
    document: Mapping[str, object],
) -> None:
    if callback is not None:
        callback(artifacts, document)


def run_full256_online_real_gate(
    config: Full256OnlineRealGateConfig,
    *,
    builder: Full256ProofPoolBuilder,
    on_pool_frozen: ArtifactCallback | None = None,
    on_build_prediction_frozen: ArtifactCallback | None = None,
    on_learning_frozen: ArtifactCallback | None = None,
    on_predictions_frozen: ArtifactCallback | None = None,
) -> Full256OnlineRealGateResult:
    """Train on BUILD pools, then freeze all real-target policy trajectories."""

    if not isinstance(config, Full256OnlineRealGateConfig):
        raise TypeError("config must be Full256OnlineRealGateConfig")
    if not isinstance(builder, Full256ProofPoolBuilder):
        # Tests may supply a strict duck-typed public-only builder.
        signature = getattr(builder, "probe_public", None)
        if not callable(signature):
            raise TypeError("builder must expose probe_public")
    if tuple(builder.config.state_plan.horizons) != config.controller.horizons:
        raise Full256OnlineRealGateError(
            "proof-pool and controller horizon order differs"
        )

    wall_started = time.monotonic()
    cpu_started = time.process_time()
    primary = OnlineCausalController(config.controller)
    shifted = OnlineCausalController(config.controller)
    untrained = OnlineCausalController(config.controller)
    build_reward_deltas = np.zeros(
        (config.build_targets, config.maximum_actions),
        dtype=np.float64,
    )
    build_rows: list[dict[str, object]] = []
    pool_rows: list[dict[str, object]] = []
    pool_runtime_rows: list[dict[str, object]] = []

    for ordinal in range(config.build_targets):
        order = interleaved_latin_action_order(config.controller, ordinal)
        index = config.build_index_start + ordinal
        target = make_deterministic_known_target(
            seed=config.corpus_seed,
            split="BUILD",
            index=index,
        )
        frozen = builder.probe_public(
            target_id=target.target_id,
            public=target.public,
        )
        pool_artifacts, pool_document = _pool_freeze_artifacts(
            frozen,
            split="BUILD",
        )
        _persist_callback(on_pool_frozen, pool_artifacts, pool_document)
        primary_state = primary.run_action_order(frozen.action_pool, order)
        shifted_state = shifted.run_action_order(frozen.action_pool, order)
        primary_fast_state = primary_state.to_bytes(config.controller)
        shifted_fast_state = shifted_state.to_bytes(config.controller)
        build_prediction_unsigned = {
            "schema": REAL_GATE_BUILD_PREDICTION_FREEZE_SCHEMA,
            "phase": "BUILD_TRAJECTORY_FROZEN_BEFORE_LABEL_ACCESS",
            "ordinal": ordinal,
            "target_id": target.target_id,
            "public_view_sha256": target.public.digest(),
            "action_pool_sha256": frozen.action_pool_sha256,
            "action_order_sha256": hashlib.sha256(
                np.asarray(order, dtype="<u2").tobytes(order="C")
            ).hexdigest(),
            "primary_fast_state_sha256": hashlib.sha256(
                primary_fast_state
            ).hexdigest(),
            "shifted_fast_state_sha256": hashlib.sha256(
                shifted_fast_state
            ).hexdigest(),
            "labels_materialized": 0,
            "reader_updates_after_current_reveal": 0,
            "critic_updates_after_current_reveal": 0,
        }
        build_prediction_document = {
            **build_prediction_unsigned,
            "freeze_sha256": _canonical_sha256(build_prediction_unsigned),
        }
        _persist_callback(
            on_build_prediction_frozen,
            {
                f"build_prequential/{target.target_id}.json": _json_bytes(
                    build_prediction_document
                ),
                f"build_prequential/{target.target_id}.primary.fast": (
                    primary_fast_state
                ),
                f"build_prequential/{target.target_id}.shifted.fast": (
                    shifted_fast_state
                ),
            },
            build_prediction_document,
        )
        labels = target.labels_after_pool_freeze(frozen)
        true_replay = primary.replay_action_rewards(
            frozen.action_pool,
            order,
            labels,
        )
        shifted_labels = np.roll(labels, (ordinal % (KEY_BITS - 1)) + 1)
        shifted_replay = shifted.replay_action_rewards(
            frozen.action_pool,
            order,
            shifted_labels,
        )
        if not np.array_equal(true_replay.contexts, shifted_replay.contexts):
            raise Full256OnlineRealGateError(
                "true and shifted BUILD critic contexts differ"
            )
        for position, flat_index in enumerate(true_replay.action_order):
            build_reward_deltas[ordinal, int(flat_index)] = (
                true_replay.delta_nll_bits[position]
            )
        primary_report = primary.reveal_and_learn(
            frozen.action_pool,
            primary_state,
            labels,
        )
        shifted_report = shifted.reveal_and_learn(
            frozen.action_pool,
            shifted_state,
            labels,
            critic_reward_labels=shifted_labels,
        )
        if primary.reader_state_bytes() != shifted.reader_state_bytes():
            raise Full256OnlineRealGateError(
                "shifted-reward control changed the shared reader"
            )
        build_rows.append(
            {
                "ordinal": ordinal,
                "target": target.public_description(),
                "action_pool_sha256": frozen.action_pool_sha256,
                "action_order_sha256": hashlib.sha256(
                    np.asarray(order, dtype="<u2").tobytes(order="C")
                ).hexdigest(),
                "prequential_freeze_sha256": build_prediction_document[
                    "freeze_sha256"
                ],
                "true_reward_sum_bits": primary_report.reward_sum_bits,
                "shifted_reward_sum_bits": shifted_report.reward_sum_bits,
                "true_positive_reward_actions": (
                    primary_report.reward_positive_actions
                ),
                "shifted_positive_reward_actions": (
                    shifted_report.reward_positive_actions
                ),
                "reader_state_sha256": primary.reader_state_sha256,
                "primary_critic_updates": primary.critic.updates,
                "shifted_critic_updates": shifted.critic.updates,
            }
        )
        pool_rows.append(
            {
                "split": "BUILD",
                "target_id": target.target_id,
                "action_pool_sha256": frozen.action_pool_sha256,
                "total_native_solver_branches": int(
                    frozen.resources["total_native_solver_branches"]
                ),
            }
        )
        pool_runtime_rows.append(
            {
                "split": "BUILD",
                "target_id": target.target_id,
                "resources": dict(frozen.resources),
            }
        )

    static_reward_mean = build_reward_deltas.mean(axis=0)
    static_reward_score = np.empty(config.maximum_actions, dtype=np.float64)
    for flat_index in range(config.maximum_actions):
        action = CausalAction.from_flat_index(flat_index, config.controller)
        static_reward_score[flat_index] = static_reward_mean[flat_index] / (
            2 * action.horizon
        )
    primary_slow_state = primary.slow_state_bytes()
    shifted_slow_state = shifted.slow_state_bytes()
    untrained_slow_state = untrained.slow_state_bytes()
    if primary.reader_state_sha256 != shifted.reader_state_sha256:
        raise Full256OnlineRealGateError("learning freeze readers differ")
    learning_unsigned: dict[str, object] = {
        "schema": REAL_GATE_LEARNING_FREEZE_SCHEMA,
        "phase": "BUILD_LEARNING_FROZEN_BEFORE_EVALUATION_TARGET_GENERATION",
        "build_targets": config.build_targets,
        "primary_slow_state_sha256": hashlib.sha256(
            primary_slow_state
        ).hexdigest(),
        "shifted_slow_state_sha256": hashlib.sha256(
            shifted_slow_state
        ).hexdigest(),
        "shared_reader_state_sha256": primary.reader_state_sha256,
        "untrained_slow_state_sha256": hashlib.sha256(
            untrained_slow_state
        ).hexdigest(),
        "static_reward_mean_sha256": hashlib.sha256(
            static_reward_mean.astype("<f8", copy=False).tobytes(order="C")
        ).hexdigest(),
        "static_reward_score_sha256": hashlib.sha256(
            static_reward_score.astype("<f8", copy=False).tobytes(order="C")
        ).hexdigest(),
        "build_reward_deltas_sha256": hashlib.sha256(
            build_reward_deltas.astype("<f8", copy=False).tobytes(order="C")
        ).hexdigest(),
        "evaluation_targets_generated": 0,
        "evaluation_labels_materialized": 0,
        "scientific_entropy_calls": 0,
        "operational_path_entropy_excluded": True,
    }
    learning_document = {
        **learning_unsigned,
        "freeze_sha256": _canonical_sha256(learning_unsigned),
    }
    learning_artifacts = {
        "learning_freeze.json": _json_bytes(learning_document),
        "primary_slow_state.bin": primary_slow_state,
        "shifted_slow_state.bin": shifted_slow_state,
        "static_reward_mean.f64le": static_reward_mean.astype(
            "<f8", copy=False
        ).tobytes(order="C"),
        "static_reward_score.f64le": static_reward_score.astype(
            "<f8", copy=False
        ).tobytes(order="C"),
        "build_reward_deltas.f64le": build_reward_deltas.astype(
            "<f8", copy=False
        ).tobytes(order="C"),
    }
    _persist_callback(
        on_learning_frozen,
        learning_artifacts,
        learning_document,
    )

    raw_predictions = np.empty(
        (len(RAW_ARMS), config.evaluation_targets, KEY_BITS),
        dtype=np.float32,
    )
    policy_predictions = np.empty(
        (
            len(POLICY_ARMS),
            config.evaluation_targets,
            len(config.work_checkpoints),
            KEY_BITS,
        ),
        dtype=np.float32,
    )
    action_orders = np.full(
        (len(POLICY_ARMS), config.evaluation_targets, config.maximum_actions),
        np.iinfo(np.uint16).max,
        dtype=np.uint16,
    )
    checkpoint_counts = np.empty(
        (
            len(POLICY_ARMS),
            config.evaluation_targets,
            len(config.work_checkpoints),
        ),
        dtype=np.uint16,
    )
    checkpoint_work = np.empty_like(checkpoint_counts, dtype=np.uint32)
    evaluation_targets: list[DeterministicKnownTarget] = []
    evaluation_frozen_pools: list[FrozenFull256ProofPool] = []
    evaluation_pool_hashes: list[str] = []
    representative_fast_state_sha256: dict[str, str] = {}
    swap_max_residual = 0.0
    common_only_max_logit = 0.0

    for ordinal in range(config.evaluation_targets):
        index = config.evaluation_index_start + ordinal
        target = make_deterministic_known_target(
            seed=config.corpus_seed,
            split=config.evaluation_split,
            index=index,
        )
        frozen = builder.probe_public(
            target_id=target.target_id,
            public=target.public,
        )
        pool_artifacts, pool_document = _pool_freeze_artifacts(
            frozen,
            split=config.evaluation_split,
        )
        _persist_callback(on_pool_frozen, pool_artifacts, pool_document)
        evaluation_targets.append(target)
        evaluation_frozen_pools.append(frozen)
        evaluation_pool_hashes.append(frozen.action_pool_sha256)
        pool_rows.append(
            {
                "split": config.evaluation_split,
                "target_id": target.target_id,
                "action_pool_sha256": frozen.action_pool_sha256,
                "total_native_solver_branches": int(
                    frozen.resources["total_native_solver_branches"]
                ),
            }
        )
        pool_runtime_rows.append(
            {
                "split": config.evaluation_split,
                "target_id": target.target_id,
                "resources": dict(frozen.resources),
            }
        )

        raw_order = interleaved_latin_action_order(config.controller, ordinal)
        raw_primary_state = primary.run_action_order(frozen.action_pool, raw_order)
        raw_untrained_state = untrained.run_action_order(frozen.action_pool, raw_order)
        raw_predictions[0, ordinal] = raw_primary_state.posterior_logits
        raw_predictions[1, ordinal] = raw_untrained_state.posterior_logits
        raw_predictions[2, ordinal] = np.roll(
            raw_primary_state.posterior_logits,
            config.coordinate_rotation,
        )
        raw_predictions[3, ordinal] = primary.query_o1_field(raw_primary_state)

        trajectories = (
            _run_learned_trajectory(
                primary,
                frozen.action_pool,
                config.work_checkpoints,
            ),
            _run_learned_trajectory(
                shifted,
                frozen.action_pool,
                config.work_checkpoints,
            ),
            _run_control_trajectory(
                primary,
                frozen.action_pool,
                config.work_checkpoints,
                arm="build_static_reward",
                static_scores=static_reward_score,
            ),
            _run_control_trajectory(
                primary,
                frozen.action_pool,
                config.work_checkpoints,
                arm="shortest_first",
                static_scores=static_reward_score,
            ),
            _run_control_trajectory(
                primary,
                frozen.action_pool,
                config.work_checkpoints,
                arm="uniform_hash",
                static_scores=static_reward_score,
            ),
        )
        for arm_index, trajectory in enumerate(trajectories):
            policy_predictions[arm_index, ordinal] = trajectory.logits
            action_orders[arm_index, ordinal] = trajectory.action_order
            checkpoint_counts[arm_index, ordinal] = (
                trajectory.checkpoint_action_counts
            )
            checkpoint_work[arm_index, ordinal] = trajectory.checkpoint_work
            for checkpoint_index, cap in enumerate(config.work_checkpoints):
                slack = cap - int(trajectory.checkpoint_work[checkpoint_index])
                if not 0 <= slack <= config.maximum_checkpoint_slack:
                    raise Full256OnlineRealGateError(
                        "policy checkpoint slack exceeds its frozen bound"
                    )
            if ordinal == 0:
                representative_fast_state_sha256[POLICY_ARMS[arm_index]] = (
                    trajectory.final_state.sha256(config.controller)
                )

        if ordinal == 0:
            swapped = frozen.action_pool.polarity_swapped()
            swapped_state = primary.run_action_order(swapped, raw_order)
            swap_max_residual = float(
                np.max(
                    np.abs(
                        raw_primary_state.posterior_logits
                        + swapped_state.posterior_logits
                    )
                )
            )
            common_state = primary.run_action_order(
                _common_only_pool(frozen.action_pool),
                raw_order,
            )
            common_only_max_logit = float(
                np.max(np.abs(common_state.posterior_logits))
            )

    evaluation_slow_states_unchanged = (
        primary.slow_state_bytes() == primary_slow_state
        and shifted.slow_state_bytes() == shifted_slow_state
        and untrained.slow_state_bytes() == untrained_slow_state
    )
    nested_checkpoint_paths_verified = _trajectory_paths_are_nested(
        action_orders,
        checkpoint_counts,
        checkpoint_work,
        horizons=config.controller.horizons,
        work_caps=config.work_checkpoints,
    )

    prediction_arrays = {
        "raw_predictions.f32le": raw_predictions.astype(
            "<f4", copy=False
        ).tobytes(order="C"),
        "policy_predictions.f32le": policy_predictions.astype(
            "<f4", copy=False
        ).tobytes(order="C"),
        "action_orders.u16le": action_orders.astype("<u2", copy=False).tobytes(
            order="C"
        ),
        "checkpoint_action_counts.u16le": checkpoint_counts.astype(
            "<u2", copy=False
        ).tobytes(order="C"),
        "checkpoint_work.u32le": checkpoint_work.astype(
            "<u4", copy=False
        ).tobytes(order="C"),
    }
    prediction_unsigned: dict[str, object] = {
        "schema": REAL_GATE_PREDICTION_FREEZE_SCHEMA,
        "phase": "ALL_EVALUATION_TRAJECTORIES_FROZEN_BEFORE_LABEL_SCORING",
        "raw_arms": list(RAW_ARMS),
        "policy_arms": list(POLICY_ARMS),
        "work_checkpoints": list(config.work_checkpoints),
        "raw_prediction_shape": list(raw_predictions.shape),
        "policy_prediction_shape": list(policy_predictions.shape),
        "action_order_shape": list(action_orders.shape),
        "checkpoint_action_count_shape": list(checkpoint_counts.shape),
        "checkpoint_work_shape": list(checkpoint_work.shape),
        "artifact_sha256": {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in sorted(prediction_arrays.items())
        },
        "evaluation_pool_set_sha256": _canonical_sha256(
            evaluation_pool_hashes
        ),
        "learning_freeze_sha256": learning_document["freeze_sha256"],
        "evaluation_labels_materialized": 0,
        "evaluation_slow_updates": 0,
        "evaluation_slow_states_unchanged": evaluation_slow_states_unchanged,
        "nested_checkpoint_paths_verified": nested_checkpoint_paths_verified,
        "target_key_inputs_to_probe": 0,
        "target_trace_inputs": 0,
        "scientific_entropy_calls": 0,
        "operational_path_entropy_excluded": True,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
    }
    prediction_document = {
        **prediction_unsigned,
        "freeze_sha256": _canonical_sha256(prediction_unsigned),
    }
    _persist_callback(
        on_predictions_frozen,
        {
            "prediction_freeze.json": _json_bytes(prediction_document),
            **prediction_arrays,
        },
        prediction_document,
    )

    labels = np.empty((config.evaluation_targets, KEY_BITS), dtype=np.uint8)
    for ordinal, (target, frozen_pool) in enumerate(
        zip(evaluation_targets, evaluation_frozen_pools, strict=True)
    ):
        labels[ordinal] = target.labels_after_pool_freeze(frozen_pool)

    raw_compressions = np.empty(
        (len(RAW_ARMS), config.evaluation_targets),
        dtype=np.float64,
    )
    policy_compressions = np.empty(
        (
            len(POLICY_ARMS),
            config.evaluation_targets,
            len(config.work_checkpoints),
        ),
        dtype=np.float64,
    )
    for arm_index in range(len(RAW_ARMS)):
        for target_index in range(config.evaluation_targets):
            raw_compressions[arm_index, target_index] = KEY_BITS - _nll_bits(
                raw_predictions[arm_index, target_index],
                labels[target_index],
            )
    for arm_index in range(len(POLICY_ARMS)):
        for target_index in range(config.evaluation_targets):
            for checkpoint_index in range(len(config.work_checkpoints)):
                policy_compressions[
                    arm_index, target_index, checkpoint_index
                ] = KEY_BITS - _nll_bits(
                    policy_predictions[
                        arm_index, target_index, checkpoint_index
                    ],
                    labels[target_index],
                )

    iauc = np.empty(
        (len(POLICY_ARMS), config.evaluation_targets),
        dtype=np.float64,
    )
    for arm_index in range(len(POLICY_ARMS)):
        for target_index in range(config.evaluation_targets):
            requested_work = (
                0,
                *checkpoint_work[arm_index, target_index].astype(int).tolist(),
            )
            values = (
                0.0,
                *policy_compressions[arm_index, target_index].tolist(),
            )
            area = sum(
                0.5
                * (values[index - 1] + values[index])
                * (requested_work[index] - requested_work[index - 1])
                for index in range(1, len(requested_work))
            )
            area += values[-1] * (
                config.work_checkpoints[-1] - requested_work[-1]
            )
            iauc[arm_index, target_index] = area / config.work_checkpoints[-1]

    raw_summaries = {
        arm: _arm_summary(
            arm,
            raw_predictions[index],
            labels,
            raw_compressions[index],
        )
        for index, arm in enumerate(RAW_ARMS)
    }
    policy_summaries: dict[str, object] = {}
    for arm_index, arm in enumerate(POLICY_ARMS):
        checkpoints = []
        for checkpoint_index, cap in enumerate(config.work_checkpoints):
            checkpoints.append(
                {
                    "work_cap": cap,
                    **_arm_summary(
                        arm,
                        policy_predictions[:, :, checkpoint_index][arm_index],
                        labels,
                        policy_compressions[
                            arm_index, :, checkpoint_index
                        ],
                    ),
                    "mean_requested_work": float(
                        checkpoint_work[arm_index, :, checkpoint_index].mean()
                    ),
                    "mean_action_count": float(
                        checkpoint_counts[arm_index, :, checkpoint_index].mean()
                    ),
                }
            )
        policy_summaries[arm] = {
            "checkpoints": checkpoints,
            "mean_iauc_bits": float(iauc[arm_index].mean()),
            "iauc_conditional_z_score": _conditional_z(iauc[arm_index]),
        }

    raw_primary = raw_compressions[0]
    raw_untrained_margin = raw_primary - raw_compressions[1]
    raw_rotation_margin = raw_primary - raw_compressions[2]
    true_iauc = iauc[0]
    shifted_iauc_margin = true_iauc - iauc[1]
    static_iauc_margin = true_iauc - iauc[2]
    shortest_iauc_margin = true_iauc - iauc[3]
    hash_iauc_margin = true_iauc - iauc[4]
    picker_control_margins = np.stack(
        (
            shifted_iauc_margin,
            static_iauc_margin,
            shortest_iauc_margin,
            hash_iauc_margin,
        )
    )
    structural_gates = {
        "exact_polarity_swap_antisymmetry": swap_max_residual == 0.0,
        "common_only_orientation_zero": common_only_max_logit == 0.0,
        "shared_reader_for_true_and_shifted_critics": (
            primary.reader_state_sha256 == shifted.reader_state_sha256
        ),
        "all_prediction_trajectories_frozen_before_labels": True,
        "all_checkpoint_paths_are_nested_prefixes": (
            nested_checkpoint_paths_verified
        ),
        "all_checkpoint_slack_within_bound": bool(
            np.all(
                (
                    np.asarray(config.work_checkpoints, dtype=np.int64)[
                        None, None, :
                    ]
                    - checkpoint_work.astype(np.int64)
                )
                >= 0
            )
            and np.all(
                (
                    np.asarray(config.work_checkpoints, dtype=np.int64)[
                        None, None, :
                    ]
                    - checkpoint_work.astype(np.int64)
                )
                <= config.maximum_checkpoint_slack
            )
        ),
        "zero_evaluation_slow_updates": evaluation_slow_states_unchanged,
        "zero_target_key_inputs_to_probe": True,
        "zero_target_trace_inputs": True,
        "zero_entropy_calls_affecting_scientific_state": True,
        "zero_mps_calls": True,
        "zero_gpu_calls": True,
        "zero_sibling_writes": True,
    }
    raw_gates = {
        "raw_primary_mean_compression": (
            float(raw_primary.mean())
            >= config.minimum_raw_mean_compression_bits
        ),
        "raw_primary_positive_targets": (
            int(np.sum(raw_primary > 0.0))
            >= config.minimum_raw_positive_targets
        ),
        "raw_primary_over_untrained": (
            float(raw_untrained_margin.mean())
            >= config.minimum_raw_control_margin_bits
        ),
        "raw_primary_over_coordinate_rotation": (
            float(raw_rotation_margin.mean())
            >= config.minimum_raw_control_margin_bits
        ),
    }
    picker_gates = {
        "true_picker_over_shifted_reward_iauc": (
            float(shifted_iauc_margin.mean())
            >= config.minimum_picker_iauc_margin_bits
        ),
        "true_picker_over_static_reward_iauc": (
            float(static_iauc_margin.mean())
            >= config.minimum_picker_iauc_margin_bits
        ),
        "true_picker_over_shortest_first_iauc": (
            float(shortest_iauc_margin.mean())
            >= config.minimum_picker_iauc_margin_bits
        ),
        "true_picker_over_uniform_hash_iauc": (
            float(hash_iauc_margin.mean())
            >= config.minimum_picker_iauc_margin_bits
        ),
        "true_picker_target_wins": (
            int(np.sum(np.all(picker_control_margins > 0.0, axis=0)))
            >= config.minimum_picker_win_targets
        ),
    }
    (
        classification,
        structural_passed,
        raw_passed,
        picker_passed,
    ) = _classify_gate_outcome(
        structural_gates,
        raw_gates,
        picker_gates,
    )
    gates = {
        **structural_gates,
        **raw_gates,
        **picker_gates,
        "structural_gate_passed": structural_passed,
        "raw_signal_gate_passed": raw_passed,
        "picker_gate_passed": picker_passed,
        "success_gate_passed": picker_passed,
    }

    deterministic_report: dict[str, object] = {
        "schema": REAL_GATE_RESULT_SCHEMA,
        "classification": classification,
        "claim_boundary": {
            "standard_chacha20_rounds": 20,
            "unknown_key_bits_at_probe": KEY_BITS,
            "public_input_only_at_probe": True,
            "deterministic_known_build_targets": True,
            "deterministic_holdout_split": config.evaluation_split,
            "autonomous_raw_channel_learning_evaluated": True,
            "learned_live_picker_evaluated": True,
            "exact_key_recovery_claimed": False,
            "native_solver_wall_saving_claimed": False,
            "logical_requested_conflict_efficiency_evaluated": True,
            "reason_native_saving_not_claimed": (
                "public action pools are generated exhaustively before replay"
            ),
        },
        "config": config.describe(),
        "build_targets": config.build_targets,
        "evaluation_targets": config.evaluation_targets,
        "maximum_actions": config.maximum_actions,
        "work_checkpoints": list(config.work_checkpoints),
        "iauc_convention": (
            "trapezoids at each arm-target actual cumulative requested-work "
            "coordinate, then hold the final posterior constant through the "
            "indivisible tail to the common W3 cap; normalize by W3"
        ),
        "raw_arms": raw_summaries,
        "policy_arms": policy_summaries,
        "margins": {
            "raw_primary_minus_untrained_mean_bits": float(
                raw_untrained_margin.mean()
            ),
            "raw_primary_minus_untrained_z": _conditional_z(
                raw_untrained_margin
            ),
            "raw_primary_minus_rotation_mean_bits": float(
                raw_rotation_margin.mean()
            ),
            "raw_primary_minus_rotation_z": _conditional_z(
                raw_rotation_margin
            ),
            "picker_true_minus_shifted_mean_iauc_bits": float(
                shifted_iauc_margin.mean()
            ),
            "picker_true_minus_static_mean_iauc_bits": float(
                static_iauc_margin.mean()
            ),
            "picker_true_minus_shortest_mean_iauc_bits": float(
                shortest_iauc_margin.mean()
            ),
            "picker_true_minus_hash_mean_iauc_bits": float(
                hash_iauc_margin.mean()
            ),
            "picker_true_all_control_target_wins": int(
                np.sum(np.all(picker_control_margins > 0.0, axis=0))
            ),
        },
        "build": build_rows,
        "pools": pool_rows,
        "invariants": {
            "polarity_swap_max_absolute_logit_residual": swap_max_residual,
            "common_only_max_absolute_logit": common_only_max_logit,
            "shared_reader_state_sha256": primary.reader_state_sha256,
            "representative_fast_state_sha256": (
                representative_fast_state_sha256
            ),
            "maximum_checkpoint_slack_observed": int(
                np.max(
                    np.asarray(config.work_checkpoints, dtype=np.int64)[
                        None, None, :
                    ]
                    - checkpoint_work.astype(np.int64)
                )
            ),
            "fast_state_numeric_bytes": config.controller.fast_state_numeric_bytes,
            "stream_length_dependent_fast_state": False,
        },
        "artifact_commitments": {
            "learning_freeze_sha256": learning_document["freeze_sha256"],
            "prediction_freeze_sha256": prediction_document["freeze_sha256"],
            "evaluation_pool_set_sha256": _canonical_sha256(
                evaluation_pool_hashes
            ),
            "raw_predictions_sha256": hashlib.sha256(
                prediction_arrays["raw_predictions.f32le"]
            ).hexdigest(),
            "policy_predictions_sha256": hashlib.sha256(
                prediction_arrays["policy_predictions.f32le"]
            ).hexdigest(),
            "action_orders_sha256": hashlib.sha256(
                prediction_arrays["action_orders.u16le"]
            ).hexdigest(),
            "checkpoint_action_counts_sha256": hashlib.sha256(
                prediction_arrays["checkpoint_action_counts.u16le"]
            ).hexdigest(),
            "checkpoint_work_sha256": hashlib.sha256(
                prediction_arrays["checkpoint_work.u32le"]
            ).hexdigest(),
            "labels_sha256": hashlib.sha256(
                np.packbits(labels, axis=1, bitorder="little").tobytes(order="C")
            ).hexdigest(),
            "raw_compressions_sha256": hashlib.sha256(
                raw_compressions.astype("<f8", copy=False).tobytes(order="C")
            ).hexdigest(),
            "policy_compressions_sha256": hashlib.sha256(
                policy_compressions.astype("<f8", copy=False).tobytes(order="C")
            ).hexdigest(),
            "iauc_sha256": hashlib.sha256(
                iauc.astype("<f8", copy=False).tobytes(order="C")
            ).hexdigest(),
            "primary_slow_state_sha256": hashlib.sha256(
                primary_slow_state
            ).hexdigest(),
            "shifted_slow_state_sha256": hashlib.sha256(
                shifted_slow_state
            ).hexdigest(),
            "static_reward_mean_sha256": hashlib.sha256(
                static_reward_mean.astype("<f8", copy=False).tobytes(order="C")
            ).hexdigest(),
            "build_reward_deltas_sha256": hashlib.sha256(
                build_reward_deltas.astype("<f8", copy=False).tobytes(order="C")
            ).hexdigest(),
        },
        "gates": gates,
        "next_action": (
            "If DUAL_PASS, freeze the lineage and replace exhaustive pool replay "
            "with the one-action lazy native executor. If RAW_ONLY_PASS, retain "
            "the learned reader and change only picker credit/context. If no raw "
            "signal, use per-action BUILD deltas to select the next causal view."
        ),
    }
    resources = {
        "cpu_seconds": time.process_time() - cpu_started,
        "wall_seconds": time.monotonic() - wall_started,
        "process_peak_rss_bytes": _peak_rss_bytes(),
        "physical_public_pools_generated": len(pool_rows),
        "pools": pool_runtime_rows,
        "scientific_entropy_calls": 0,
        "operational_path_entropy_excluded": True,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
    }
    report = {
        **deterministic_report,
        "resources": resources,
        "result_sha256": _canonical_sha256(deterministic_report),
    }
    return Full256OnlineRealGateResult(
        report=report,
        raw_predictions=raw_predictions,
        policy_predictions=policy_predictions,
        labels=labels,
        raw_compressions=raw_compressions,
        policy_compressions=policy_compressions,
        iauc=iauc,
        action_orders=action_orders,
        checkpoint_action_counts=checkpoint_counts,
        checkpoint_work=checkpoint_work,
        primary_slow_state=primary_slow_state,
        shifted_slow_state=shifted_slow_state,
        static_reward_mean=static_reward_mean,
        build_reward_deltas=build_reward_deltas,
    )


__all__ = [
    "POLICY_ARMS",
    "RAW_ARMS",
    "REAL_GATE_CONFIG_SCHEMA",
    "REAL_GATE_BUILD_PREDICTION_FREEZE_SCHEMA",
    "REAL_GATE_LEARNING_FREEZE_SCHEMA",
    "REAL_GATE_PREDICTION_FREEZE_SCHEMA",
    "REAL_GATE_RESULT_SCHEMA",
    "REAL_GATE_SCHEMA",
    "Full256OnlineRealGateConfig",
    "Full256OnlineRealGateError",
    "Full256OnlineRealGateResult",
    "interleaved_latin_action_order",
    "run_full256_online_real_gate",
]
