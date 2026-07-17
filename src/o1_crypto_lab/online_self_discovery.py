"""Deterministic full-256 mechanism gate for autonomous O1 signal discovery.

This experiment is intentionally synthetic and makes no ChaCha20 inverse claim.
It asks the architecture-level question that must pass before solver work is
worth spending: can a bounded online O1 reader find one transferable oriented
channel among 330 anonymous raw channels, retain all 256 addressed decisions in
its Bit-Vault, and beat matched channel-ablation and shuffled-label controls?
"""

from __future__ import annotations

import hashlib
import json
import math
import resource
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from .full256_action_pool import BRANCH_FEATURES, Full256ActionPool
from .living_inverse import canonical_sha256
from .online_causal_controller import (
    KEY_BITS,
    CausalAction,
    OnlineCausalController,
    OnlineCausalControllerConfig,
    OnlineCausalFastState,
    PairedCausalObservation,
)


SELF_DISCOVERY_SCHEMA = "o1-256-online-self-discovery-v1"
SELF_DISCOVERY_RESULT_SCHEMA = "o1-256-online-self-discovery-result-v1"
SELF_DISCOVERY_CONFIG_SCHEMA = "o1-256-online-self-discovery-config-v1"
SELF_DISCOVERY_FREEZE_SCHEMA = "o1-256-online-self-discovery-freeze-v1"
PREDICTION_ARMS = (
    "primary_learned",
    "hidden_channel_ablation",
    "shuffled_label_learner",
    "untrained_reader",
    "primary_raw_end_of_stream_o1_field",
)


class OnlineSelfDiscoveryError(ValueError):
    """A synthetic mechanism config, corpus, or invariant differs."""


def _positive_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise OnlineSelfDiscoveryError(f"{field} must be an integer in [1,{maximum}]")
    return value


def _finite_positive(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise OnlineSelfDiscoveryError(f"{field} must be finite in (0,{maximum}]")
    return float(value)


def _non_negative_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise OnlineSelfDiscoveryError(f"{field} must be an integer in [0,{maximum}]")
    return value


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


@dataclass(frozen=True)
class OnlineSelfDiscoveryConfig:
    train_targets: int = 8
    evaluation_targets: int = 16
    train_seed_start: int = 1_000
    evaluation_seed_start: int = 20_000
    hidden_channel: int = 137
    signal_amplitude: float = 3.0
    signed_distractor_scale: float = 0.12
    common_scale: float = 0.15
    horizon: int = 3
    nuisance_rank: int = 2
    nuisance_warmup: int = 8
    model_dimension: int = 16
    heads: int = 2
    head_dimension: int = 4
    holographic_slots: int = 8
    feedforward_dimension: int = 24
    reader_learning_rate: float = 0.01
    recall_loss_weight: float = 2.0
    gradient_chunk_actions: int = 8
    cpu_threads: int = 1
    controller_seed: int = 170_017
    minimum_mean_compression_bits: float = 16.0
    minimum_control_margin_bits: float = 12.0
    minimum_bit_accuracy: float = 0.70

    def __post_init__(self) -> None:
        for field, value, maximum in (
            ("train_targets", self.train_targets, 1024),
            ("evaluation_targets", self.evaluation_targets, 4096),
            ("train_seed_start", self.train_seed_start, 2_000_000_000),
            (
                "evaluation_seed_start",
                self.evaluation_seed_start,
                2_000_000_000,
            ),
            ("horizon", self.horizon, 1_000_000),
            ("nuisance_rank", self.nuisance_rank, 32),
            ("nuisance_warmup", self.nuisance_warmup, KEY_BITS),
            ("model_dimension", self.model_dimension, 4096),
            ("heads", self.heads, 64),
            ("head_dimension", self.head_dimension, 1024),
            ("holographic_slots", self.holographic_slots, 64),
            ("feedforward_dimension", self.feedforward_dimension, 16384),
            ("gradient_chunk_actions", self.gradient_chunk_actions, KEY_BITS),
            ("cpu_threads", self.cpu_threads, 8),
        ):
            _positive_int(value, field, maximum)
        if (
            isinstance(self.hidden_channel, bool)
            or not isinstance(self.hidden_channel, int)
            or not 0 <= self.hidden_channel < BRANCH_FEATURES
        ):
            raise OnlineSelfDiscoveryError("hidden_channel must address a raw channel")
        if isinstance(self.controller_seed, bool) or not isinstance(
            self.controller_seed, int
        ):
            raise OnlineSelfDiscoveryError("controller_seed must be an integer")
        for field, value, maximum in (
            ("signal_amplitude", self.signal_amplitude, 1e6),
            ("signed_distractor_scale", self.signed_distractor_scale, 1e6),
            ("common_scale", self.common_scale, 1e6),
            ("reader_learning_rate", self.reader_learning_rate, 1.0),
            ("recall_loss_weight", self.recall_loss_weight, 1e6),
            (
                "minimum_mean_compression_bits",
                self.minimum_mean_compression_bits,
                KEY_BITS,
            ),
            (
                "minimum_control_margin_bits",
                self.minimum_control_margin_bits,
                KEY_BITS,
            ),
            ("minimum_bit_accuracy", self.minimum_bit_accuracy, 1.0),
        ):
            _finite_positive(value, field, maximum)
        train_seeds = set(
            range(self.train_seed_start, self.train_seed_start + self.train_targets)
        )
        evaluation_seeds = set(
            range(
                self.evaluation_seed_start,
                self.evaluation_seed_start + self.evaluation_targets,
            )
        )
        if train_seeds & evaluation_seeds:
            raise OnlineSelfDiscoveryError(
                "train and evaluation seeds must be disjoint"
            )

    @property
    def controller_config(self) -> OnlineCausalControllerConfig:
        return OnlineCausalControllerConfig(
            horizons=(self.horizon,),
            nuisance_rank=self.nuisance_rank,
            nuisance_warmup=self.nuisance_warmup,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            reader_learning_rate=self.reader_learning_rate,
            recall_loss_weight=self.recall_loss_weight,
            gradient_chunk_actions=self.gradient_chunk_actions,
            cpu_threads=self.cpu_threads,
            seed=self.controller_seed,
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": SELF_DISCOVERY_SCHEMA,
            "train_targets": self.train_targets,
            "evaluation_targets": self.evaluation_targets,
            "train_seed_start": self.train_seed_start,
            "evaluation_seed_start": self.evaluation_seed_start,
            "hidden_channel": self.hidden_channel,
            "signal_amplitude": self.signal_amplitude,
            "signed_distractor_scale": self.signed_distractor_scale,
            "common_scale": self.common_scale,
            "horizon": self.horizon,
            "controller": self.controller_config.describe(),
            "minimum_mean_compression_bits": self.minimum_mean_compression_bits,
            "minimum_control_margin_bits": self.minimum_control_margin_bits,
            "minimum_bit_accuracy": self.minimum_bit_accuracy,
            "actions_per_target": KEY_BITS,
            "action_selection_policy": "fixed-complete-coordinate-coverage",
            "learned_action_picker_evaluated": False,
            "raw_channels_per_action": BRANCH_FEATURES,
            "controller_receives_hidden_channel_index": False,
            "fresh_entropy_calls": 0,
            "cryptographic_inverse_claim": False,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "OnlineSelfDiscoveryConfig":
        if not isinstance(value, Mapping):
            raise OnlineSelfDiscoveryError("experiment config must be a mapping")
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise OnlineSelfDiscoveryError("experiment config fields differ")
        try:
            return cls(**dict(value))
        except TypeError as exc:
            raise OnlineSelfDiscoveryError("experiment config fields differ") from exc


@dataclass(frozen=True)
class OnlineSelfDiscoveryBudgets:
    maximum_cpu_seconds: int
    maximum_wall_seconds: int
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_action_observations: int
    maximum_fresh_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    def __post_init__(self) -> None:
        for field, value, maximum in (
            ("maximum_cpu_seconds", self.maximum_cpu_seconds, 86_400),
            ("maximum_wall_seconds", self.maximum_wall_seconds, 86_400),
            (
                "maximum_resident_memory_mib",
                self.maximum_resident_memory_mib,
                1_048_576,
            ),
            (
                "maximum_persistent_artifact_bytes",
                self.maximum_persistent_artifact_bytes,
                1_000_000_000,
            ),
            (
                "maximum_action_observations",
                self.maximum_action_observations,
                1_000_000_000,
            ),
        ):
            _positive_int(value, field, maximum)
        for field, value in (
            ("maximum_fresh_entropy_calls", self.maximum_fresh_entropy_calls),
            ("maximum_sibling_reads", self.maximum_sibling_reads),
            ("maximum_sibling_writes", self.maximum_sibling_writes),
            ("maximum_mps_calls", self.maximum_mps_calls),
            ("maximum_gpu_calls", self.maximum_gpu_calls),
        ):
            _non_negative_int(value, field, 1_000_000_000)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "OnlineSelfDiscoveryBudgets":
        if not isinstance(value, Mapping) or set(value) != set(
            cls.__dataclass_fields__
        ):
            raise OnlineSelfDiscoveryError("budget fields differ")
        try:
            return cls(**dict(value))
        except TypeError as exc:
            raise OnlineSelfDiscoveryError("budget fields differ") from exc

    def describe(self) -> dict[str, int]:
        return {field: int(getattr(self, field)) for field in self.__dataclass_fields__}


def load_online_self_discovery_config(
    path: str | Path,
) -> tuple[dict[str, object], OnlineSelfDiscoveryConfig, OnlineSelfDiscoveryBudgets]:
    """Load one exact preregistered mechanism-gate document."""

    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OnlineSelfDiscoveryError("could not read self-discovery config") from exc
    required = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "next_action",
        "experiment",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OnlineSelfDiscoveryError("top-level config fields differ")
    if value["schema"] != SELF_DISCOVERY_CONFIG_SCHEMA:
        raise OnlineSelfDiscoveryError("top-level config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(value[field], str) or not value[field].strip():
            raise OnlineSelfDiscoveryError(f"{field} must be non-empty text")
    controls = value["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise OnlineSelfDiscoveryError("controls must be non-empty text entries")
    experiment_value = value["experiment"]
    budget_value = value["budgets"]
    if not isinstance(experiment_value, Mapping) or not isinstance(
        budget_value, Mapping
    ):
        raise OnlineSelfDiscoveryError("experiment and budgets must be mappings")
    experiment = OnlineSelfDiscoveryConfig.from_mapping(experiment_value)
    budgets = OnlineSelfDiscoveryBudgets.from_mapping(budget_value)
    return value, experiment, budgets


@dataclass(frozen=True)
class OnlineSelfDiscoveryResult:
    report: dict[str, object]
    predictions: np.ndarray
    labels: np.ndarray
    compressions: np.ndarray
    primary_slow_state: bytes
    shuffled_slow_state: bytes
    representative_fast_state: bytes

    def __post_init__(self) -> None:
        targets = int(self.report["evaluation_targets"])
        expected_prediction = (len(PREDICTION_ARMS), targets, KEY_BITS)
        if (
            self.predictions.shape != expected_prediction
            or self.predictions.dtype != np.float32
            or not np.all(np.isfinite(self.predictions))
        ):
            raise OnlineSelfDiscoveryError("prediction artifact differs")
        if (
            self.labels.shape != (targets, KEY_BITS)
            or self.labels.dtype != np.uint8
            or np.any((self.labels != 0) & (self.labels != 1))
        ):
            raise OnlineSelfDiscoveryError("label artifact differs")
        if (
            self.compressions.shape != (len(PREDICTION_ARMS), targets)
            or self.compressions.dtype != np.float64
            or not np.all(np.isfinite(self.compressions))
        ):
            raise OnlineSelfDiscoveryError("compression artifact differs")
        for name in (
            "primary_slow_state",
            "shuffled_slow_state",
            "representative_fast_state",
        ):
            if not isinstance(getattr(self, name), bytes) or not getattr(self, name):
                raise OnlineSelfDiscoveryError(f"{name} artifact is empty")

    @property
    def success_gate_passed(self) -> bool:
        return bool(self.report["gates"]["success_gate_passed"])

    def prediction_bytes(self) -> bytes:
        return self.predictions.astype("<f4", copy=False).tobytes(order="C")

    def label_bytes(self) -> bytes:
        return np.packbits(self.labels, axis=1, bitorder="little").tobytes(order="C")

    def compression_bytes(self) -> bytes:
        return self.compressions.astype("<f8", copy=False).tobytes(order="C")


def _build_episode(
    config: OnlineSelfDiscoveryConfig,
    seed: int,
    *,
    ablate_hidden_channel: bool,
) -> tuple[Full256ActionPool, np.ndarray]:
    generator = np.random.Generator(np.random.PCG64(seed))
    labels = generator.integers(0, 2, KEY_BITS, dtype=np.uint8)
    signed = generator.normal(
        0.0,
        config.signed_distractor_scale,
        (KEY_BITS, BRANCH_FEATURES),
    ).astype(np.float32)
    common = generator.normal(
        0.0,
        config.common_scale,
        (KEY_BITS, BRANCH_FEATURES),
    ).astype(np.float32)
    signed[:, config.hidden_channel] = generator.normal(
        0.0,
        config.signed_distractor_scale,
        KEY_BITS,
    ).astype(np.float32)
    if not ablate_hidden_channel:
        signed[:, config.hidden_channel] += (
            2.0 * labels.astype(np.float32) - 1.0
        ) * np.float32(config.signal_amplitude)
    features = np.empty((1, KEY_BITS, 2, BRANCH_FEATURES), dtype=np.float32)
    features[0, :, 0] = common - np.float32(0.5) * signed
    features[0, :, 1] = common + np.float32(0.5) * signed
    resource_panel = np.zeros((KEY_BITS, 2, 3), dtype=np.uint64)
    resource_panel[:, :, 0] = np.uint64(config.horizon)
    pair_hashes = tuple(_sha(f"o1c0017-pair-{seed}-{bit}") for bit in range(KEY_BITS))
    source_stream_sha256 = canonical_sha256(
        {
            "schema": "o1c0017-synthetic-public-stream-v1",
            "seed": seed,
            "hidden_channel_signal_ablated": ablate_hidden_channel,
            "horizon": config.horizon,
            "branch_features_sha256": hashlib.sha256(
                features.astype("<f4", copy=False).tobytes(order="C")
            ).hexdigest(),
            "resource_panel_sha256": hashlib.sha256(
                resource_panel.astype("<u8", copy=False).tobytes(order="C")
            ).hexdigest(),
            "pair_sha256": list(pair_hashes),
        }
    )
    pool = Full256ActionPool(
        horizons=(config.horizon,),
        branch_features=features,
        final_resources=resource_panel,
        pair_sha256=pair_hashes,
        source_stream_sha256=source_stream_sha256,
    )
    return pool, labels


def _run_fixed_coverage(
    controller: OnlineCausalController,
    pool: Full256ActionPool,
    *,
    serialized_lengths: set[int] | None = None,
) -> OnlineCausalFastState:
    state = controller.initial_fast_state(pool.source_stream_sha256)
    if serialized_lengths is not None:
        serialized_lengths.add(len(state.to_bytes(controller.config)))
    for bit in range(KEY_BITS):
        action = CausalAction(bit_index=bit, horizon=pool.horizons[0])
        controller.observe(state, PairedCausalObservation.from_pool(pool, action))
        if serialized_lengths is not None and bit in (0, 127, KEY_BITS - 1):
            serialized_lengths.add(len(state.to_bytes(controller.config)))
    if (
        state.action_count != KEY_BITS
        or not np.all(state.coverage == 1)
        or len(set(int(value) for value in state.action_order)) != KEY_BITS
    ):
        raise OnlineSelfDiscoveryError("fixed full-256 coverage differs")
    return state


def _nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.float64)
    signed = (2.0 * truth - 1.0) * values
    return float(np.logaddexp(0.0, -signed).sum() / math.log(2.0))


def _conditional_z(values: np.ndarray) -> float | None:
    vector = np.asarray(values, dtype=np.float64)
    if vector.size < 2:
        return None
    standard_deviation = float(vector.std(ddof=1))
    if standard_deviation == 0.0:
        return None
    return float(vector.mean() / (standard_deviation / math.sqrt(vector.size)))


def _arm_summary(
    name: str,
    logits: np.ndarray,
    labels: np.ndarray,
    compression: np.ndarray,
) -> dict[str, object]:
    predictions = logits >= 0.0
    correct = int(np.sum(predictions == labels.astype(bool)))
    target_correct = np.sum(predictions == labels.astype(bool), axis=1)
    exact = int(np.sum(target_correct == KEY_BITS))
    return {
        "name": name,
        "mean_nll_bits": float(KEY_BITS - compression.mean()),
        "mean_compression_bits": float(compression.mean()),
        "compression_stddev_bits": (
            float(compression.std(ddof=1)) if compression.size > 1 else 0.0
        ),
        "conditional_z_score": _conditional_z(compression),
        "positive_targets": int(np.sum(compression > 0.0)),
        "correct_bits": correct,
        "total_bits": int(labels.size),
        "bit_accuracy": correct / labels.size,
        "mean_correct_bits_per_target": float(target_correct.mean()),
        "minimum_correct_bits": int(target_correct.min()),
        "maximum_correct_bits": int(target_correct.max()),
        "exact_keys": exact,
    }


def run_online_self_discovery(
    config: OnlineSelfDiscoveryConfig,
    *,
    on_predictions_frozen: Callable[[Mapping[str, bytes], Mapping[str, object]], None]
    | None = None,
) -> OnlineSelfDiscoveryResult:
    if not isinstance(config, OnlineSelfDiscoveryConfig):
        raise TypeError("config must be OnlineSelfDiscoveryConfig")
    wall_started = time.monotonic()
    cpu_started = time.process_time()
    primary = OnlineCausalController(config.controller_config)
    shuffled = OnlineCausalController(config.controller_config)
    untrained = OnlineCausalController(config.controller_config)
    training_rows: list[dict[str, object]] = []
    train_action_observations = 0

    for index in range(config.train_targets):
        seed = config.train_seed_start + index
        pool, labels = _build_episode(config, seed, ablate_hidden_channel=False)
        primary_state = _run_fixed_coverage(primary, pool)
        primary_report = primary.reveal_and_learn(pool, primary_state, labels)
        shuffled_state = _run_fixed_coverage(shuffled, pool)
        shuffled_labels = np.roll(labels, index + 1)
        shuffled_report = shuffled.reveal_and_learn(
            pool, shuffled_state, shuffled_labels
        )
        if primary_report.actions != KEY_BITS or shuffled_report.actions != KEY_BITS:
            raise OnlineSelfDiscoveryError("training action replay count differs")
        # Each BUILD controller observes the action once for its frozen
        # prequential state, once for reward replay, and once for the
        # differentiable reader replay.
        primary_action_passes = primary_state.action_count + 2 * primary_report.actions
        shuffled_action_passes = (
            shuffled_state.action_count + 2 * shuffled_report.actions
        )
        train_action_observations += primary_action_passes + shuffled_action_passes
        training_rows.append(
            {
                "index": index,
                "seed": seed,
                "pool_sha256": pool.action_pool_sha256,
                "label_sha256": hashlib.sha256(labels.tobytes()).hexdigest(),
                "primary_prequential_nll_bits": (primary_report.final_nll_bits),
                "primary_model_action_passes": primary_action_passes,
                "primary_training_loss_bits": list(primary_report.training_loss_bits),
                "shuffled_prequential_nll_bits": (shuffled_report.final_nll_bits),
                "shuffled_model_action_passes": shuffled_action_passes,
                "shuffled_training_loss_bits": list(shuffled_report.training_loss_bits),
            }
        )

    predictions = np.empty(
        (len(PREDICTION_ARMS), config.evaluation_targets, KEY_BITS),
        dtype=np.float32,
    )
    labels_panel = np.empty((config.evaluation_targets, KEY_BITS), dtype=np.uint8)
    representative_fast_state = b""
    constant_fast_bytes: set[int] = set()
    swap_max_residual = 0.0
    evaluation_primary_pool_hashes: list[str] = []
    evaluation_ablation_pool_hashes: list[str] = []
    swap_pool_sha256 = ""
    evaluation_action_observations = 0

    for target_index in range(config.evaluation_targets):
        seed = config.evaluation_seed_start + target_index
        pool, labels = _build_episode(config, seed, ablate_hidden_channel=False)
        ablation_pool, ablation_labels = _build_episode(
            config, seed, ablate_hidden_channel=True
        )
        if not np.array_equal(labels, ablation_labels):
            raise OnlineSelfDiscoveryError("ablation labels differ")
        states = (
            _run_fixed_coverage(
                primary,
                pool,
                serialized_lengths=(constant_fast_bytes if target_index == 0 else None),
            ),
            _run_fixed_coverage(primary, ablation_pool),
            _run_fixed_coverage(shuffled, pool),
            _run_fixed_coverage(untrained, pool),
        )
        for arm_index, state in enumerate(states):
            predictions[arm_index, target_index] = state.posterior_logits
            constant_fast_bytes.add(len(state.to_bytes(config.controller_config)))
            evaluation_action_observations += state.action_count
        predictions[4, target_index] = primary.query_o1_field(states[0])
        labels_panel[target_index] = labels
        evaluation_primary_pool_hashes.append(pool.action_pool_sha256)
        evaluation_ablation_pool_hashes.append(ablation_pool.action_pool_sha256)
        if target_index == 0:
            representative_fast_state = states[0].to_bytes(config.controller_config)
            swapped_pool = pool.polarity_swapped()
            swap_pool_sha256 = swapped_pool.action_pool_sha256
            swapped_state = _run_fixed_coverage(primary, swapped_pool)
            evaluation_action_observations += swapped_state.action_count
            swap_max_residual = float(
                np.max(
                    np.abs(states[0].posterior_logits + swapped_state.posterior_logits)
                )
            )

    common_pool, _common_labels = _build_episode(
        config, config.evaluation_seed_start, ablate_hidden_channel=False
    )
    common_features = common_pool.branch_features.copy()
    even = np.float32(0.5) * (common_features[:, :, 0] + common_features[:, :, 1])
    common_features[:, :, 0] = even
    common_features[:, :, 1] = even
    common_only_pool = Full256ActionPool(
        horizons=common_pool.horizons,
        branch_features=common_features,
        final_resources=common_pool.final_resources,
        pair_sha256=common_pool.pair_sha256,
        source_stream_sha256=_sha("o1c0017-common-only-control"),
    )
    common_state = _run_fixed_coverage(primary, common_only_pool)
    evaluation_action_observations += common_state.action_count
    common_only_max_logit = float(np.max(np.abs(common_state.posterior_logits)))

    prediction_bytes = predictions.astype("<f4", copy=False).tobytes(order="C")
    freeze_unsigned: dict[str, object] = {
        "schema": SELF_DISCOVERY_FREEZE_SCHEMA,
        "phase": "ALL_SYNTHETIC_PREDICTIONS_FROZEN_BEFORE_SCORING",
        "evaluation_targets": config.evaluation_targets,
        "prediction_arms": list(PREDICTION_ARMS),
        "prediction_shape": list(predictions.shape),
        "prediction_dtype": "float32le",
        "prediction_bytes": len(prediction_bytes),
        "prediction_sha256": hashlib.sha256(prediction_bytes).hexdigest(),
        "evaluation_pool_set_sha256": canonical_sha256(evaluation_primary_pool_hashes),
        "ablation_pool_set_sha256": canonical_sha256(evaluation_ablation_pool_hashes),
        "swap_control_pool_sha256": swap_pool_sha256,
        "common_only_pool_sha256": common_only_pool.action_pool_sha256,
        "all_control_pools_sha256": canonical_sha256(
            {
                "ablation": evaluation_ablation_pool_hashes,
                "swap": swap_pool_sha256,
                "common_only": common_only_pool.action_pool_sha256,
            }
        ),
        "labels_exposed_to_controllers": 0,
        "controller_receives_hidden_channel_index": False,
        "fresh_entropy_calls": 0,
    }
    freeze_document = {
        **freeze_unsigned,
        "freeze_sha256": canonical_sha256(freeze_unsigned),
    }
    if on_predictions_frozen is not None:
        freeze_payload = (
            json.dumps(
                freeze_document,
                indent=2,
                sort_keys=True,
                allow_nan=False,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        on_predictions_frozen(
            {
                "prediction_freeze.json": freeze_payload,
                "predictions.f32le": prediction_bytes,
            },
            freeze_document,
        )

    compressions = np.empty(
        (len(PREDICTION_ARMS), config.evaluation_targets), dtype=np.float64
    )
    summaries: dict[str, dict[str, object]] = {}
    for arm_index, arm in enumerate(PREDICTION_ARMS):
        for target_index in range(config.evaluation_targets):
            compressions[arm_index, target_index] = KEY_BITS - _nll_bits(
                predictions[arm_index, target_index],
                labels_panel[target_index],
            )
        summaries[arm] = _arm_summary(
            arm,
            predictions[arm_index],
            labels_panel,
            compressions[arm_index],
        )

    primary_compression = compressions[0]
    ablation_margin = primary_compression - compressions[1]
    shuffled_margin = primary_compression - compressions[2]
    raw_end_state_margin = primary_compression - compressions[4]
    primary_summary = summaries["primary_learned"]
    gates = {
        "all_256_coordinates_observed": True,
        "constant_fast_state_bytes": len(constant_fast_bytes) == 1,
        "exact_polarity_swap_antisymmetry": swap_max_residual == 0.0,
        "common_only_orientation_zero": common_only_max_logit == 0.0,
        "primary_mean_compression_gate": (
            float(primary_compression.mean()) >= config.minimum_mean_compression_bits
        ),
        "primary_over_channel_ablation_gate": (
            float(ablation_margin.mean()) >= config.minimum_control_margin_bits
        ),
        "primary_over_shuffled_learner_gate": (
            float(shuffled_margin.mean()) >= config.minimum_control_margin_bits
        ),
        "primary_vault_over_raw_end_state_gate": (
            float(raw_end_state_margin.mean()) >= config.minimum_control_margin_bits
        ),
        "primary_bit_accuracy_gate": (
            float(primary_summary["bit_accuracy"]) >= config.minimum_bit_accuracy
        ),
        "every_evaluation_target_positive": bool(np.all(primary_compression > 0.0)),
        "zero_fresh_entropy_calls": True,
        "zero_mps_calls": True,
        "zero_gpu_calls": True,
        "synthetic_only_no_crypto_claim": True,
    }
    gates["success_gate_passed"] = all(gates.values())
    label_bytes = np.packbits(labels_panel, axis=1, bitorder="little").tobytes(
        order="C"
    )
    compression_bytes = compressions.astype("<f8", copy=False).tobytes(order="C")
    primary_slow_state = primary.slow_state_bytes()
    shuffled_slow_state = shuffled.slow_state_bytes()
    deterministic_report: dict[str, object] = {
        "schema": SELF_DISCOVERY_RESULT_SCHEMA,
        "result_commitment_scope": (
            "all report fields except resources and result_sha256; the capsule "
            "manifest separately binds measured resources"
        ),
        "classification": (
            "MECHANISM_PASS" if gates["success_gate_passed"] else "MECHANISM_FAIL"
        ),
        "claim_boundary": {
            "synthetic_full_256_key": True,
            "standard_chacha20_target": False,
            "cryptographic_inverse_signal_claimed": False,
            "autonomous_signal_channel_discovery_evaluated": True,
            "learned_action_picker_evaluated": False,
            "fixed_full_coordinate_coverage": True,
            "bit_vault_retention_evaluated": True,
            "raw_holographic_end_state_reported": True,
            "stateless_baseline_evaluated": False,
            "o1_memory_necessity_evaluated": False,
            "holographic_or_streaming_advantage_claimed": False,
            "purpose": "online representation integration and Bit-Vault retention gate",
        },
        "config": config.describe(),
        "train_targets": config.train_targets,
        "evaluation_targets": config.evaluation_targets,
        "training": training_rows,
        "arms": summaries,
        "margins": {
            "primary_minus_channel_ablation_mean_bits": float(ablation_margin.mean()),
            "primary_minus_channel_ablation_z": _conditional_z(ablation_margin),
            "primary_minus_shuffled_mean_bits": float(shuffled_margin.mean()),
            "primary_minus_shuffled_z": _conditional_z(shuffled_margin),
            "primary_vault_minus_raw_end_state_mean_bits": float(
                raw_end_state_margin.mean()
            ),
            "primary_vault_minus_raw_end_state_z": _conditional_z(raw_end_state_margin),
        },
        "invariants": {
            "polarity_swap_max_absolute_logit_residual": swap_max_residual,
            "common_only_max_absolute_logit": common_only_max_logit,
            "fast_state_serialized_bytes": next(iter(constant_fast_bytes)),
            "fast_state_numeric_bytes": (
                config.controller_config.fast_state_numeric_bytes
            ),
            "primary_slow_state_bytes": len(primary_slow_state),
            "shuffled_slow_state_bytes": len(shuffled_slow_state),
            "stream_length_dependent_fast_state": False,
            "bit_vault_coordinates": KEY_BITS,
            "raw_channels": BRANCH_FEATURES,
        },
        "artifact_commitments": {
            "prediction_shape": list(predictions.shape),
            "prediction_dtype": "float32le",
            "prediction_bytes": len(prediction_bytes),
            "prediction_sha256": hashlib.sha256(prediction_bytes).hexdigest(),
            "label_shape": list(labels_panel.shape),
            "label_bitpack_bytes": len(label_bytes),
            "label_sha256": hashlib.sha256(label_bytes).hexdigest(),
            "compression_shape": list(compressions.shape),
            "compression_dtype": "float64le",
            "compression_bytes": len(compression_bytes),
            "compression_sha256": hashlib.sha256(compression_bytes).hexdigest(),
            "primary_slow_state_sha256": hashlib.sha256(primary_slow_state).hexdigest(),
            "shuffled_slow_state_sha256": hashlib.sha256(
                shuffled_slow_state
            ).hexdigest(),
            "representative_fast_state_sha256": hashlib.sha256(
                representative_fast_state
            ).hexdigest(),
            "evaluation_pool_set_sha256": canonical_sha256(
                evaluation_primary_pool_hashes
            ),
            "ablation_pool_set_sha256": canonical_sha256(
                evaluation_ablation_pool_hashes
            ),
            "swap_control_pool_sha256": swap_pool_sha256,
            "common_only_pool_sha256": common_only_pool.action_pool_sha256,
            "all_control_pools_sha256": canonical_sha256(
                {
                    "ablation": evaluation_ablation_pool_hashes,
                    "swap": swap_pool_sha256,
                    "common_only": common_only_pool.action_pool_sha256,
                }
            ),
        },
        "static_accounting": {
            "train_unique_frozen_action_observations": (
                config.train_targets * KEY_BITS * 2
            ),
            "train_replay_action_observations": (
                train_action_observations - config.train_targets * KEY_BITS * 2
            ),
            "train_action_observations": train_action_observations,
            "evaluation_action_observations": evaluation_action_observations,
            "total_action_observations": (
                train_action_observations + evaluation_action_observations
            ),
            "native_solver_branches": 0,
            "fresh_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        },
        "gates": gates,
        "next_action": (
            "Replace the synthetic hidden channel with deterministic known-key "
            "full-round ChaCha paired proof pools; preserve the frozen online "
            "reader, Bit-Vault, controls, and whole-key holdout boundary."
        ),
    }
    resources = {
        "cpu_seconds": time.process_time() - cpu_started,
        "wall_seconds": time.monotonic() - wall_started,
        "process_peak_rss_bytes": _peak_rss_bytes(),
        **dict(deterministic_report["static_accounting"]),
    }
    report = {
        **deterministic_report,
        "resources": resources,
        "result_sha256": canonical_sha256(deterministic_report),
    }
    return OnlineSelfDiscoveryResult(
        report=report,
        predictions=predictions,
        labels=labels_panel,
        compressions=compressions,
        primary_slow_state=primary_slow_state,
        shuffled_slow_state=shuffled_slow_state,
        representative_fast_state=representative_fast_state,
    )


__all__ = [
    "PREDICTION_ARMS",
    "SELF_DISCOVERY_CONFIG_SCHEMA",
    "SELF_DISCOVERY_FREEZE_SCHEMA",
    "SELF_DISCOVERY_RESULT_SCHEMA",
    "SELF_DISCOVERY_SCHEMA",
    "OnlineSelfDiscoveryConfig",
    "OnlineSelfDiscoveryBudgets",
    "OnlineSelfDiscoveryError",
    "OnlineSelfDiscoveryResult",
    "load_online_self_discovery_config",
    "run_online_self_discovery",
]
