"""Deterministic post-reveal forensics for a finalized O1C real-gate capsule.

The analysis consumes only already-opened capsule artifacts.  It never creates a
new target, changes model weights, or promotes a post-hoc diagnostic to efficacy.
Its purpose is to preserve the action-level breadcrumbs needed by the next gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from .full256_action_pool import deserialize_action_pool
from .full256_online_real_gate import (
    POLICY_ARMS,
    RAW_ARMS,
    interleaved_latin_action_order,
)
from .full256_online_real_gate_run import (
    load_full256_online_real_gate_run_config,
)
from .living_inverse import KEY_BITS
from .online_causal_controller import (
    CausalAction,
    OnlineCausalController,
    PairedCausalObservation,
)
from .run_capsule import RunCapsuleManager


FORENSICS_SCHEMA = "o1-256-fullround-online-real-forensics-v1"


class Full256OnlineRealForensicsError(ValueError):
    """A capsule, commitment, array, or deterministic replay differs."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256OnlineRealForensicsError(
            f"cannot read JSON artifact {path}"
        ) from exc
    if not isinstance(value, dict):
        raise Full256OnlineRealForensicsError(f"JSON artifact {path} is not an object")
    return value


def _read_array(
    path: Path,
    *,
    dtype: str,
    shape: tuple[int, ...],
    expected_sha256: object,
) -> np.ndarray:
    payload = path.read_bytes()
    if not isinstance(expected_sha256, str) or _sha256(payload) != expected_sha256:
        raise Full256OnlineRealForensicsError(f"array commitment differs for {path}")
    expected_bytes = math.prod(shape) * np.dtype(dtype).itemsize
    if len(payload) != expected_bytes:
        raise Full256OnlineRealForensicsError(f"array byte count differs for {path}")
    return np.frombuffer(payload, dtype=dtype).reshape(shape).copy()


def _pearson(left: np.ndarray, right: np.ndarray) -> float | None:
    x = np.asarray(left, dtype=np.float64).ravel()
    y = np.asarray(right, dtype=np.float64).ravel()
    if x.shape != y.shape or x.size < 2:
        raise Full256OnlineRealForensicsError("correlation vectors differ")
    x = x - x.mean()
    y = y - y.mean()
    denominator = float(np.linalg.norm(x) * np.linalg.norm(y))
    if denominator == 0.0:
        return None
    return float(np.dot(x, y) / denominator)


def _mean_finite(values: Sequence[float | None]) -> float | None:
    finite = [float(value) for value in values if value is not None]
    return float(np.mean(finite)) if finite else None


def _cosine(left: np.ndarray, right: np.ndarray) -> float | None:
    x = np.asarray(left, dtype=np.float64).ravel()
    y = np.asarray(right, dtype=np.float64).ravel()
    if x.shape != y.shape or x.size < 1:
        raise Full256OnlineRealForensicsError("cosine vectors differ")
    denominator = float(np.linalg.norm(x) * np.linalg.norm(y))
    if denominator == 0.0:
        return None
    return float(np.dot(x, y) / denominator)


def _jaccard(left: Sequence[int], right: Sequence[int]) -> float:
    a = set(int(value) for value in left)
    b = set(int(value) for value in right)
    union = a | b
    return float(len(a & b) / len(union)) if union else 1.0


def _rank_overlap(
    left: Sequence[int],
    right: Sequence[int],
    *,
    universe: int,
) -> dict[str, object]:
    left_rank = {int(value): rank for rank, value in enumerate(left)}
    right_rank = {int(value): rank for rank, value in enumerate(right)}
    common = sorted(set(left_rank) & set(right_rank))
    expected = len(left_rank) * len(right_rank) / universe
    return {
        "left_count": len(left_rank),
        "right_count": len(right_rank),
        "intersection": len(common),
        "expected_random_intersection": expected,
        "intersection_lift_over_random": (
            float(len(common) / expected) if expected > 0.0 else None
        ),
        "action_set_jaccard": _jaccard(left, right),
        "common_action_rank_pearson": (
            _pearson(
                np.asarray([left_rank[value] for value in common]),
                np.asarray([right_rank[value] for value in common]),
            )
            if len(common) >= 2
            else None
        ),
    }


def _compression_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        values.shape != (KEY_BITS,)
        or truth.shape != (KEY_BITS,)
        or not np.all(np.isfinite(values))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise Full256OnlineRealForensicsError("compression inputs differ")
    signed = (2.0 * truth - 1.0) * values
    nll = float(np.logaddexp(0.0, -signed).sum() / math.log(2.0))
    return float(KEY_BITS - nll)


def _posthoc_scale_search(
    predictions: np.ndarray,
    labels: np.ndarray,
) -> dict[str, object]:
    logits = np.asarray(predictions, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    if (
        logits.shape != truth.shape
        or logits.ndim != 2
        or logits.shape[1] != KEY_BITS
        or not np.all(np.isfinite(logits))
        or np.any((truth != 0.0) & (truth != 1.0))
    ):
        raise Full256OnlineRealForensicsError("scale-search inputs differ")
    scales = np.linspace(-2.0, 2.0, 4001, dtype=np.float64)
    signed = (2.0 * truth - 1.0) * logits
    nll = np.logaddexp(
        0.0,
        -scales[:, None, None] * signed[None, :, :],
    ).sum(axis=2) / math.log(2.0)
    compression = KEY_BITS - nll
    index = int(np.argmax(compression.mean(axis=1)))
    return {
        "grid_minimum_scale": float(scales[0]),
        "grid_maximum_scale": float(scales[-1]),
        "grid_step": float(scales[1] - scales[0]),
        "best_scale": float(scales[index]),
        "mean_compression_bits": float(compression[index].mean()),
        "compression_bits_by_target": compression[index].tolist(),
        "best_scale_is_grid_boundary": index in (0, scales.size - 1),
    }


def _work_prefix(order: Sequence[int], horizons: Sequence[int]) -> np.ndarray:
    result = np.zeros(len(order) + 1, dtype=np.int64)
    for index, flat_index in enumerate(order, start=1):
        horizon_index = int(flat_index) // KEY_BITS
        if not 0 <= horizon_index < len(horizons):
            raise Full256OnlineRealForensicsError("action horizon index differs")
        result[index] = result[index - 1] + 2 * int(horizons[horizon_index])
    return result


def _horizon_inventory(order: Sequence[int], horizons: Sequence[int]) -> dict[str, int]:
    counts = np.bincount(
        np.asarray(order, dtype=np.int64) // KEY_BITS,
        minlength=len(horizons),
    )
    return {
        f"h{int(horizon)}": int(counts[index])
        for index, horizon in enumerate(horizons)
    }


def _coordinate_coverage(order: Sequence[int]) -> int:
    return len({int(value) % KEY_BITS for value in order})


def _pairwise_correlations(rows: np.ndarray) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for left in range(rows.shape[0]):
        for right in range(left + 1, rows.shape[0]):
            result.append(
                {
                    "left": left,
                    "right": right,
                    "pearson": _pearson(rows[left], rows[right]),
                }
            )
    return result


def _top_inventory(
    scores: np.ndarray,
    horizons: Sequence[int],
    count: int,
) -> dict[str, object]:
    order = np.lexsort((np.arange(scores.size), -scores))[:count]
    return {
        "count": count,
        "minimum_score": float(scores[order[-1]]),
        "horizons": _horizon_inventory(order, horizons),
        "coordinate_coverage": _coordinate_coverage(order),
        "action_sha256": _sha256(order.astype("<u2").tobytes(order="C")),
    }


def _load_capsule_arrays(
    capsule: Path,
    result: Mapping[str, object],
    *,
    build_targets: int,
    evaluation_targets: int,
    checkpoints: int,
    maximum_actions: int,
) -> dict[str, np.ndarray]:
    artifacts = capsule / "artifacts"
    commitments = result.get("artifact_commitments")
    if not isinstance(commitments, Mapping):
        raise Full256OnlineRealForensicsError("result commitments are absent")
    arrays = {
        "raw_predictions": _read_array(
            artifacts / "raw_predictions.f32le",
            dtype="<f4",
            shape=(len(RAW_ARMS), evaluation_targets, KEY_BITS),
            expected_sha256=commitments.get("raw_predictions_sha256"),
        ),
        "policy_predictions": _read_array(
            artifacts / "policy_predictions.f32le",
            dtype="<f4",
            shape=(
                len(POLICY_ARMS),
                evaluation_targets,
                checkpoints,
                KEY_BITS,
            ),
            expected_sha256=commitments.get("policy_predictions_sha256"),
        ),
        "raw_compressions": _read_array(
            artifacts / "raw_compressions.f64le",
            dtype="<f8",
            shape=(len(RAW_ARMS), evaluation_targets),
            expected_sha256=commitments.get("raw_compressions_sha256"),
        ),
        "policy_compressions": _read_array(
            artifacts / "policy_compressions.f64le",
            dtype="<f8",
            shape=(len(POLICY_ARMS), evaluation_targets, checkpoints),
            expected_sha256=commitments.get("policy_compressions_sha256"),
        ),
        "iauc": _read_array(
            artifacts / "iauc.f64le",
            dtype="<f8",
            shape=(len(POLICY_ARMS), evaluation_targets),
            expected_sha256=commitments.get("iauc_sha256"),
        ),
        "action_orders": _read_array(
            artifacts / "action_orders.u16le",
            dtype="<u2",
            shape=(len(POLICY_ARMS), evaluation_targets, maximum_actions),
            expected_sha256=commitments.get("action_orders_sha256"),
        ),
        "checkpoint_counts": _read_array(
            artifacts / "checkpoint_action_counts.u16le",
            dtype="<u2",
            shape=(len(POLICY_ARMS), evaluation_targets, checkpoints),
            expected_sha256=commitments.get(
                "checkpoint_action_counts_sha256"
            ),
        ),
        "checkpoint_work": _read_array(
            artifacts / "checkpoint_work.u32le",
            dtype="<u4",
            shape=(len(POLICY_ARMS), evaluation_targets, checkpoints),
            expected_sha256=commitments.get("checkpoint_work_sha256"),
        ),
        "static_reward_mean": _read_array(
            artifacts / "static_reward_mean.f64le",
            dtype="<f8",
            shape=(maximum_actions,),
            expected_sha256=commitments.get("static_reward_mean_sha256"),
        ),
        "build_reward_deltas": _read_array(
            artifacts / "build_reward_deltas.f64le",
            dtype="<f8",
            shape=(build_targets, maximum_actions),
            expected_sha256=commitments.get("build_reward_deltas_sha256"),
        ),
    }
    labels_payload = (artifacts / "labels.bitpack").read_bytes()
    if _sha256(labels_payload) != commitments.get("labels_sha256"):
        raise Full256OnlineRealForensicsError("label commitment differs")
    labels = np.unpackbits(
        np.frombuffer(labels_payload, dtype=np.uint8), bitorder="little"
    )
    if labels.size != evaluation_targets * KEY_BITS:
        raise Full256OnlineRealForensicsError("label bit count differs")
    arrays["labels"] = labels.reshape(evaluation_targets, KEY_BITS).astype(np.uint8)
    return arrays


def _load_development_pools(
    capsule: Path,
    result: Mapping[str, object],
    *,
    evaluation_targets: int,
) -> list[object]:
    pool_rows = result.get("pools")
    if not isinstance(pool_rows, list):
        raise Full256OnlineRealForensicsError("pool inventory is absent")
    evaluation_rows = [
        row
        for row in pool_rows
        if isinstance(row, Mapping) and row.get("split") == "DEVELOPMENT"
    ]
    if len(evaluation_rows) != evaluation_targets:
        raise Full256OnlineRealForensicsError("DEVELOPMENT pool inventory differs")
    pools = []
    for row in evaluation_rows:
        target_id = row.get("target_id")
        if not isinstance(target_id, str):
            raise Full256OnlineRealForensicsError("DEVELOPMENT target ID differs")
        payload = (capsule / "artifacts" / "pools" / f"{target_id}.fap").read_bytes()
        if _sha256(payload) != row.get("action_pool_sha256"):
            raise Full256OnlineRealForensicsError("DEVELOPMENT pool hash differs")
        pools.append(deserialize_action_pool(payload))
    return pools


def _build_reward_forensics(
    rewards: np.ndarray,
    static_mean: np.ndarray,
    horizons: Sequence[int],
) -> dict[str, object]:
    work = np.repeat(
        np.asarray([2 * int(horizon) for horizon in horizons], dtype=np.float64),
        KEY_BITS,
    )
    normalized = rewards / work[None, :]
    static_score = static_mean / work
    if not np.array_equal(static_mean, rewards.mean(axis=0)):
        raise Full256OnlineRealForensicsError("static reward mean differs")
    pairwise = _pairwise_correlations(normalized)
    loo_rows: list[dict[str, object]] = []
    fold_top64: list[np.ndarray] = []
    for holdout in range(rewards.shape[0]):
        train = np.delete(normalized, holdout, axis=0).mean(axis=0)
        fold_top64.append(np.lexsort((np.arange(train.size), -train))[:64])
        loo_rows.append(
            {
                "holdout": holdout,
                "per_action_reward_pearson": _pearson(
                    train, normalized[holdout]
                ),
                "train_positive_fraction": float(np.mean(train > 0.0)),
                "holdout_positive_fraction": float(
                    np.mean(normalized[holdout] > 0.0)
                ),
            }
        )
    fold_overlaps = [
        _jaccard(fold_top64[left], fold_top64[right])
        for left in range(len(fold_top64))
        for right in range(left + 1, len(fold_top64))
    ]
    sign_count = np.sum(rewards > 0.0, axis=0)
    horizon_rows: list[dict[str, object]] = []
    for horizon_index, horizon in enumerate(horizons):
        section = slice(horizon_index * KEY_BITS, (horizon_index + 1) * KEY_BITS)
        horizon_rows.append(
            {
                "horizon": int(horizon),
                "mean_delta_nll_bits_per_action": float(rewards[:, section].mean()),
                "mean_delta_nll_per_work": float(normalized[:, section].mean()),
                "positive_action_fraction": float(
                    np.mean(rewards[:, section] > 0.0)
                ),
                "mean_total_delta_nll_bits_per_build": float(
                    rewards[:, section].sum(axis=1).mean()
                ),
            }
        )
    return {
        "per_build_total_delta_nll_bits": rewards.sum(axis=1).tolist(),
        "mean_total_delta_nll_bits": float(rewards.sum(axis=1).mean()),
        "pairwise_per_work_reward_correlations": pairwise,
        "mean_pairwise_per_work_reward_correlation": _mean_finite(
            [row["pearson"] for row in pairwise]
        ),
        "leave_one_build_out_per_action_transfer": loo_rows,
        "mean_leave_one_build_out_per_action_reward_pearson": _mean_finite(
            [row["per_action_reward_pearson"] for row in loo_rows]
        ),
        "mean_pairwise_leave_one_out_top64_jaccard": float(
            np.mean(fold_overlaps)
        ),
        "actions_positive_on_all_builds": int(np.sum(sign_count == rewards.shape[0])),
        "actions_positive_on_at_least_three_builds": int(np.sum(sign_count >= 3)),
        "actions_negative_on_all_builds": int(np.sum(sign_count == 0)),
        "horizons": horizon_rows,
        "top_static_score_inventories": [
            _top_inventory(static_score, horizons, count)
            for count in (32, 64, 128, 256)
        ],
        "static_score_sha256": _sha256(
            static_score.astype("<f8", copy=False).tobytes(order="C")
        ),
    }


def _reader_path_forensics(
    *,
    controller: OnlineCausalController,
    pools: Sequence[object],
    labels: np.ndarray,
    horizons: Sequence[int],
) -> dict[str, object]:
    target_rows: list[dict[str, object]] = []
    latin_checkpoints = tuple(KEY_BITS * index for index in range(1, len(horizons) + 1))
    for target_index, pool in enumerate(pools):
        order = interleaved_latin_action_order(controller.config, target_index)
        state = controller.initial_fast_state(pool.source_stream_sha256)
        checkpoint_rows: list[dict[str, object]] = []
        for action_count, flat_index in enumerate(order, start=1):
            action = CausalAction.from_flat_index(flat_index, controller.config)
            controller.observe(
                state,
                PairedCausalObservation.from_pool(pool, action),
            )
            if action_count in latin_checkpoints:
                deployed = controller.query_posteriors(state)
                direct = controller.query_o1_field(state)
                per_coordinate_count = state.coverage.sum(axis=0, dtype=np.float32)
                normalized = deployed / np.maximum(per_coordinate_count, 1.0)
                checkpoint_rows.append(
                    {
                        "action_count": action_count,
                        "requested_work": controller.requested_work_units(state),
                        "deployed_accumulated_compression_bits": _compression_bits(
                            deployed, labels[target_index]
                        ),
                        "direct_o1_field_compression_bits": _compression_bits(
                            direct, labels[target_index]
                        ),
                        "coverage_normalized_compression_bits": _compression_bits(
                            normalized, labels[target_index]
                        ),
                        "per_coordinate_observation_count": sorted(
                            {
                                int(value)
                                for value in per_coordinate_count.astype(np.int64)
                            }
                        ),
                    }
                )
        horizon_rows: list[dict[str, object]] = []
        for horizon_index, horizon in enumerate(horizons):
            horizon_order = tuple(
                horizon_index * KEY_BITS + bit for bit in range(KEY_BITS)
            )
            horizon_state = controller.run_action_order(pool, horizon_order)
            horizon_rows.append(
                {
                    "horizon": int(horizon),
                    "requested_work": controller.requested_work_units(horizon_state),
                    "deployed_accumulated_compression_bits": _compression_bits(
                        controller.query_posteriors(horizon_state),
                        labels[target_index],
                    ),
                    "direct_o1_field_compression_bits": _compression_bits(
                        controller.query_o1_field(horizon_state),
                        labels[target_index],
                    ),
                }
            )
        target_rows.append(
            {
                "target_index": target_index,
                "latin_path": checkpoint_rows,
                "isolated_horizons": horizon_rows,
            }
        )
    return {
        "targets": target_rows,
        "mechanism_warning": (
            "All values use revealed, consumed DEVELOPMENT labels. Direct-field, "
            "coverage-normalized and isolated-horizon reads diagnose accumulation; "
            "they are not frozen efficacy arms."
        ),
    }


def _critic_agency_forensics(
    *,
    controllers: Sequence[OnlineCausalController],
    pools: Sequence[object],
    arrays: Mapping[str, np.ndarray],
    work_caps: Sequence[int],
) -> dict[str, object]:
    if len(controllers) != 2:
        raise Full256OnlineRealForensicsError("critic controller inventory differs")
    learned_arms = POLICY_ARMS[:2]
    arm_rows: dict[str, object] = {}
    for arm_index, (arm, controller) in enumerate(zip(learned_arms, controllers)):
        targets: list[dict[str, object]] = []
        for target_index, pool in enumerate(pools):
            state = controller.initial_fast_state(pool.source_stream_sha256)
            used_work = 0
            observed_order: list[int] = []
            checkpoint_rows: list[dict[str, object]] = []
            for checkpoint_index, cap in enumerate(work_caps):
                segment: list[dict[str, float]] = []
                while True:
                    choice = controller.choose_action(
                        state,
                        maximum_work_units=int(cap) - used_work,
                    )
                    if choice is None:
                        break
                    action = choice.action
                    flat_index = action.flat_index(controller.config)
                    learned = float(choice.predicted_reward)
                    exploration = float(choice.exploration_bonus)
                    coverage = float(
                        controller.config.coverage_weight * choice.coverage_debt
                    )
                    segment.append(
                        {
                            "predicted_reward": learned,
                            "exploration_bonus": exploration,
                            "coverage_contribution": coverage,
                            "absolute_learned_fraction_of_score_numerator": (
                                abs(learned)
                                / max(abs(learned) + exploration + coverage, 1e-30)
                            ),
                        }
                    )
                    controller.observe(
                        state,
                        PairedCausalObservation.from_pool(pool, action),
                    )
                    observed_order.append(flat_index)
                    used_work += 2 * action.horizon
                expected_count = int(
                    arrays["checkpoint_counts"][
                        arm_index, target_index, checkpoint_index
                    ]
                )
                expected = arrays["action_orders"][
                    arm_index, target_index, :expected_count
                ].astype(np.int64)
                if not np.array_equal(
                    np.asarray(observed_order, dtype=np.int64), expected
                ):
                    raise Full256OnlineRealForensicsError(
                        "learned policy decision replay differs"
                    )
                checkpoint_rows.append(
                    {
                        "work_cap": int(cap),
                        "actual_work": used_work,
                        "action_count": len(observed_order),
                        "new_actions": len(segment),
                        "mean_predicted_reward": (
                            float(np.mean([row["predicted_reward"] for row in segment]))
                            if segment
                            else None
                        ),
                        "mean_exploration_bonus": (
                            float(np.mean([row["exploration_bonus"] for row in segment]))
                            if segment
                            else None
                        ),
                        "mean_coverage_contribution": (
                            float(
                                np.mean(
                                    [row["coverage_contribution"] for row in segment]
                                )
                            )
                            if segment
                            else None
                        ),
                        "mean_absolute_learned_fraction_of_score_numerator": (
                            float(
                                np.mean(
                                    [
                                        row[
                                            "absolute_learned_fraction_of_score_numerator"
                                        ]
                                        for row in segment
                                    ]
                                )
                            )
                            if segment
                            else None
                        ),
                        "predicted_negative_fraction": (
                            float(
                                np.mean(
                                    [row["predicted_reward"] < 0.0 for row in segment]
                                )
                            )
                            if segment
                            else None
                        ),
                        "first_selected_components": segment[0] if segment else None,
                    }
                )
            targets.append(
                {
                    "target_index": target_index,
                    "checkpoints": checkpoint_rows,
                }
            )
        arm_rows[arm] = {"targets": targets}
    true_weights = controllers[0].critic.weights
    shifted_weights = controllers[1].critic.weights
    return {
        "arms": arm_rows,
        "critic_weights": {
            "true_updates": controllers[0].critic.updates,
            "shifted_updates": controllers[1].critic.updates,
            "true_shifted_cosine": _cosine(true_weights, shifted_weights),
            "true_shifted_pearson": _pearson(true_weights, shifted_weights),
            "true_shifted_l2_distance": float(
                np.linalg.norm(true_weights - shifted_weights)
            ),
        },
        "all_persisted_learned_routes_replayed_exactly": True,
        "interpretation_boundary": (
            "Component magnitudes quantify policy agency only; they do not use "
            "DEVELOPMENT labels."
        ),
    }


def _policy_forensics(
    *,
    arrays: Mapping[str, np.ndarray],
    controller: OnlineCausalController,
    pools: Sequence[object],
    horizons: Sequence[int],
    work_caps: Sequence[int],
) -> dict[str, object]:
    evaluation_targets = arrays["labels"].shape[0]
    checkpoints = len(work_caps)
    if len(pools) != evaluation_targets:
        raise Full256OnlineRealForensicsError("DEVELOPMENT pool count differs")

    policy_compressions = arrays["policy_compressions"]
    action_orders = arrays["action_orders"]
    checkpoint_counts = arrays["checkpoint_counts"]
    checkpoint_work = arrays["checkpoint_work"]
    static_mean = arrays["static_reward_mean"]
    action_work = np.repeat(
        np.asarray([2 * int(horizon) for horizon in horizons], dtype=np.float64),
        KEY_BITS,
    )
    static_score = static_mean / action_work
    arm_rows: dict[str, object] = {}
    replay_max_residual = 0.0
    for arm_index, arm in enumerate(POLICY_ARMS):
        target_rows: list[dict[str, object]] = []
        for target_index in range(evaluation_targets):
            counts = checkpoint_counts[arm_index, target_index].astype(np.int64)
            final_count = int(counts[-1])
            order = [
                int(value)
                for value in action_orders[arm_index, target_index, :final_count]
            ]
            replay = controller.replay_action_rewards(
                pools[target_index], order, arrays["labels"][target_index]
            )
            cumulative = np.concatenate(
                (np.zeros(1, dtype=np.float64), np.cumsum(replay.delta_nll_bits))
            )
            for checkpoint_index in range(checkpoints):
                residual = abs(
                    float(cumulative[int(counts[checkpoint_index])])
                    - float(
                        policy_compressions[
                            arm_index, target_index, checkpoint_index
                        ]
                    )
                )
                replay_max_residual = max(replay_max_residual, residual)
            work_prefix = _work_prefix(order, horizons)
            peak_index = int(np.argmax(cumulative))
            reward_correlation = _pearson(
                static_score[np.asarray(order, dtype=np.int64)],
                replay.delta_nll_bits / action_work[np.asarray(order, dtype=np.int64)],
            )
            checkpoint_rows: list[dict[str, object]] = []
            previous_count = 0
            previous_compression = 0.0
            for checkpoint_index, cap in enumerate(work_caps):
                count = int(counts[checkpoint_index])
                compression = float(
                    policy_compressions[arm_index, target_index, checkpoint_index]
                )
                segment = replay.delta_nll_bits[previous_count:count]
                checkpoint_rows.append(
                    {
                        "work_cap": int(cap),
                        "actual_work": int(
                            checkpoint_work[
                                arm_index, target_index, checkpoint_index
                            ]
                        ),
                        "action_count": count,
                        "coordinate_coverage": _coordinate_coverage(order[:count]),
                        "horizons": _horizon_inventory(order[:count], horizons),
                        "compression_bits": compression,
                        "segment_gain_bits": compression - previous_compression,
                        "segment_positive_action_fraction": (
                            float(np.mean(segment > 0.0)) if segment.size else 0.0
                        ),
                    }
                )
                previous_count = count
                previous_compression = compression
            target_rows.append(
                {
                    "target_index": target_index,
                    "iauc_bits": float(arrays["iauc"][arm_index, target_index]),
                    "checkpoints": checkpoint_rows,
                    "posthoc_peak_compression_bits": float(cumulative[peak_index]),
                    "posthoc_peak_action_count": peak_index,
                    "posthoc_peak_work": int(work_prefix[peak_index]),
                    "posthoc_tail_loss_to_w3_bits": float(
                        cumulative[peak_index] - cumulative[-1]
                    ),
                    "selected_static_score_vs_realized_per_work_reward_pearson": (
                        reward_correlation
                    ),
                }
            )
        same_order = all(
            np.array_equal(
                action_orders[arm_index, 0], action_orders[arm_index, target]
            )
            for target in range(1, evaluation_targets)
        )
        arm_rows[arm] = {
            "same_final_order_across_targets": same_order,
            "targets": target_rows,
            "mean_posthoc_peak_compression_bits": float(
                np.mean([row["posthoc_peak_compression_bits"] for row in target_rows])
            ),
            "mean_posthoc_tail_loss_to_w3_bits": float(
                np.mean([row["posthoc_tail_loss_to_w3_bits"] for row in target_rows])
            ),
        }

    overlaps: list[dict[str, object]] = []
    for target_index in range(evaluation_targets):
        for checkpoint_index, cap in enumerate(work_caps):
            true_count = int(checkpoint_counts[0, target_index, checkpoint_index])
            true_order = action_orders[0, target_index, :true_count]
            for control_index in range(1, len(POLICY_ARMS)):
                control_count = int(
                    checkpoint_counts[
                        control_index, target_index, checkpoint_index
                    ]
                )
                control_order = action_orders[
                    control_index, target_index, :control_count
                ]
                overlaps.append(
                    {
                        "target_index": target_index,
                        "work_cap": int(cap),
                        "control": POLICY_ARMS[control_index],
                        **_rank_overlap(
                            true_order,
                            control_order,
                            universe=controller.config.maximum_actions,
                        ),
                    }
                )
    cross_target_true: list[dict[str, object]] = []
    for left in range(evaluation_targets):
        for right in range(left + 1, evaluation_targets):
            for checkpoint_index, cap in enumerate(work_caps):
                left_count = int(checkpoint_counts[0, left, checkpoint_index])
                right_count = int(checkpoint_counts[0, right, checkpoint_index])
                cross_target_true.append(
                    {
                        "left_target_index": left,
                        "right_target_index": right,
                        "work_cap": int(cap),
                        **_rank_overlap(
                            action_orders[0, left, :left_count],
                            action_orders[0, right, :right_count],
                            universe=controller.config.maximum_actions,
                        ),
                    }
                )
    if replay_max_residual > 1e-9:
        raise Full256OnlineRealForensicsError(
            f"policy replay residual {replay_max_residual} exceeds tolerance"
        )
    return {
        "arms": arm_rows,
        "learned_true_action_set_overlaps": overlaps,
        "learned_true_cross_target_route_overlaps": cross_target_true,
        "maximum_checkpoint_replay_compression_residual_bits": replay_max_residual,
        "posthoc_warning": (
            "Peak positions, tail losses, reward correlations and action overlaps "
            "use revealed DEVELOPMENT labels and are diagnostics only."
        ),
    }


def analyze_capsule(
    *,
    root: Path,
    capsule: Path,
    config_path: Path,
) -> dict[str, object]:
    root = root.resolve(strict=True)
    capsule = capsule.resolve(strict=True)
    config_path = config_path.resolve(strict=True)
    verification = RunCapsuleManager(root).verify(capsule)
    if not verification.ok:
        raise Full256OnlineRealForensicsError("capsule verification failed")
    outer_config = _read_json(capsule / "config.json")
    frozen_config = outer_config.get("config")
    source_config = _read_json(config_path)
    if frozen_config != source_config:
        raise Full256OnlineRealForensicsError("source and capsule config differ")
    _top, gate, _proof, _budgets = load_full256_online_real_gate_run_config(
        config_path
    )
    result = _read_json(capsule / "artifacts" / "full256_online_real_gate.json")
    if result.get("classification") != "NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE":
        raise Full256OnlineRealForensicsError("capsule classification differs")
    arrays = _load_capsule_arrays(
        capsule,
        result,
        build_targets=gate.build_targets,
        evaluation_targets=gate.evaluation_targets,
        checkpoints=len(gate.work_checkpoints),
        maximum_actions=gate.maximum_actions,
    )
    primary_slow_state = (capsule / "artifacts" / "primary_slow_state.bin").read_bytes()
    shifted_slow_state = (capsule / "artifacts" / "shifted_slow_state.bin").read_bytes()
    commitments = result.get("artifact_commitments")
    if not isinstance(commitments, Mapping) or _sha256(
        primary_slow_state
    ) != commitments.get("primary_slow_state_sha256"):
        raise Full256OnlineRealForensicsError("primary slow-state commitment differs")
    if _sha256(shifted_slow_state) != commitments.get("shifted_slow_state_sha256"):
        raise Full256OnlineRealForensicsError("shifted slow-state commitment differs")
    controller = OnlineCausalController(gate.controller)
    controller.load_slow_state_bytes(primary_slow_state)
    shifted_controller = OnlineCausalController(gate.controller)
    shifted_controller.load_slow_state_bytes(shifted_slow_state)
    pools = _load_development_pools(
        capsule,
        result,
        evaluation_targets=gate.evaluation_targets,
    )
    build_forensics = _build_reward_forensics(
        arrays["build_reward_deltas"],
        arrays["static_reward_mean"],
        gate.controller.horizons,
    )
    policy_forensics = _policy_forensics(
        arrays=arrays,
        controller=controller,
        pools=pools,
        horizons=gate.controller.horizons,
        work_caps=gate.work_checkpoints,
    )
    reader_path_forensics = _reader_path_forensics(
        controller=controller,
        pools=pools,
        labels=arrays["labels"],
        horizons=gate.controller.horizons,
    )
    critic_agency_forensics = _critic_agency_forensics(
        controllers=(controller, shifted_controller),
        pools=pools,
        arrays=arrays,
        work_caps=gate.work_checkpoints,
    )
    raw_rows = {
        arm: arrays["raw_compressions"][index].tolist()
        for index, arm in enumerate(RAW_ARMS)
    }
    policy_rows = {
        arm: arrays["policy_compressions"][index].tolist()
        for index, arm in enumerate(POLICY_ARMS)
    }
    metrics = _read_json(capsule / "metrics.json")
    return {
        "schema": FORENSICS_SCHEMA,
        "scope": "POST_REVEAL_CONSUMED_DEVELOPMENT_DIAGNOSTIC_ONLY",
        "capsule": str(capsule.relative_to(root)),
        "capsule_verification": verification.describe(),
        "execution_commit": outer_config.get("commit"),
        "ended_at": metrics.get("ended_at"),
        "classification": result.get("classification"),
        "result_sha256": result.get("result_sha256"),
        "raw_compression_bits_by_target": raw_rows,
        "policy_compression_bits_by_target_and_checkpoint": policy_rows,
        "build_reward_forensics": build_forensics,
        "policy_forensics": policy_forensics,
        "reader_path_forensics": reader_path_forensics,
        "critic_agency_forensics": critic_agency_forensics,
        "posthoc_scale_forensics": {
            "learned_reader_full_field": _posthoc_scale_search(
                arrays["raw_predictions"][0], arrays["labels"]
            ),
            "learned_true_reward_w1": _posthoc_scale_search(
                arrays["policy_predictions"][0, :, 0], arrays["labels"]
            ),
            "build_static_reward_w1": _posthoc_scale_search(
                arrays["policy_predictions"][2, :, 0], arrays["labels"]
            ),
            "warning": (
                "Scales are selected after DEVELOPMENT-label reveal on a fixed "
                "[-2,2] grid and are diagnostics only."
            ),
        },
        "claim_boundary": {
            "new_targets_generated": 0,
            "model_updates": 0,
            "efficacy_claimed": False,
            "development_targets_are_consumed": True,
            "may_select_only_the_next_disjoint_development_gate": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute deterministic post-reveal O1C real-gate forensics"
    )
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/full256_online_real_gate_dev_v1.json"),
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    capsule = args.capsule if args.capsule.is_absolute() else root / args.capsule
    config_path = args.config if args.config.is_absolute() else root / args.config
    report = analyze_capsule(root=root, capsule=capsule, config_path=config_path)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "FORENSICS_SCHEMA",
    "Full256OnlineRealForensicsError",
    "analyze_capsule",
    "main",
]
