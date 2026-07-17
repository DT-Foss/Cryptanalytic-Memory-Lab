"""O1C-0013 multi-key orientation freeze and sealed full-256 attack."""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .cadical_sensor import build_native_sensor, sha256_file
from .causal_bitfield import CausalBitfieldPlan, plan_from_mapping
from .causal_orientation_reader import (
    FrozenCausalOrientationReader,
    deserialize_orientation_reader,
    fit_causal_orientation_reader,
    orientation_metrics,
    serialize_orientation_reader,
)
from .chacha_trace import chacha20_block
from .full256_broker import (
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from .full256_cnf import verify_full256_template, write_full256_instance
from .full256_paired_sensor import NativeDependencyConfig, SensorBudgetConfig
from .full256_probe_core import (
    READER_FEATURES,
    Full256ProbeCoreConfig,
    Full256ProbeCoreError,
    run_full256_probe_core,
)
from .living_inverse import (
    KEY_BITS,
    PublicTargetView,
    canonical_json_bytes,
    canonical_sha256,
)


CONFIG_SCHEMA = "o1-256-multikey-causal-calibration-config-v1"
RESULT_SCHEMA = "o1-256-multikey-causal-calibration-result-v1"
KNOWN_INDEX_SCHEMA = "o1-256-multikey-known-index-v1"
READER_FREEZE_SCHEMA = "o1-256-causal-reader-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-sealed-causal-prediction-freeze-v1"
EVALUATION_SCHEMA = "o1-256-sealed-causal-evaluation-v1"
ALLOWED_CONTROLS = (
    "output_bit_flip",
    "wrong_nonce",
    "output_byte_rotate",
)


class Full256MultiKeyCalibrationError(ValueError):
    """The O1C-0013 protocol, lifecycle, or resource contract differs."""


def _strict_mapping(
    value: object,
    field: str,
    expected: set[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise Full256MultiKeyCalibrationError(f"{field} fields differ")
    return value


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
        raise Full256MultiKeyCalibrationError(
            f"{field} must be an integer in [{minimum}, {maximum}]"
        )
    return value


def _positive(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise Full256MultiKeyCalibrationError(
            f"{field} must be finite in (0, {maximum}]"
        )
    return float(value)


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256MultiKeyCalibrationError(f"{field} must be lowercase SHA-256")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise Full256MultiKeyCalibrationError(f"{field} is required")
    return value


def _float_grid(
    value: object,
    field: str,
    *,
    allow_zero: bool = False,
) -> tuple[float, ...]:
    if not isinstance(value, list) or not value:
        raise Full256MultiKeyCalibrationError(f"{field} must be a non-empty array")
    rows: list[float] = []
    for index, item in enumerate(value):
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            or (float(item) < 0.0 if allow_zero else float(item) <= 0.0)
        ):
            raise Full256MultiKeyCalibrationError(
                f"{field}[{index}] has an invalid value"
            )
        rows.append(float(item))
    if rows != sorted(set(rows)):
        raise Full256MultiKeyCalibrationError(f"{field} must be sorted and unique")
    return tuple(rows)


@dataclass(frozen=True)
class MultiKeyFoundationSource:
    capsule: str
    manifest_sha256: str
    template: str
    template_sha256: str
    semantic_map: str
    semantic_map_sha256: str
    expected_variable_count: int
    expected_template_clause_count: int
    expected_public_clause_count: int

    @classmethod
    def from_mapping(cls, value: object) -> "MultiKeyFoundationSource":
        row = _strict_mapping(
            value,
            "source",
            {
                "capsule",
                "manifest_sha256",
                "template",
                "template_sha256",
                "semantic_map",
                "semantic_map_sha256",
                "expected_variable_count",
                "expected_template_clause_count",
                "expected_public_clause_count",
            },
        )
        return cls(
            capsule=_string(row["capsule"], "source.capsule"),
            manifest_sha256=_sha(row["manifest_sha256"], "source.manifest_sha256"),
            template=_string(row["template"], "source.template"),
            template_sha256=_sha(row["template_sha256"], "source.template_sha256"),
            semantic_map=_string(row["semantic_map"], "source.semantic_map"),
            semantic_map_sha256=_sha(
                row["semantic_map_sha256"], "source.semantic_map_sha256"
            ),
            expected_variable_count=_integer(
                row["expected_variable_count"],
                "source.expected_variable_count",
                897,
                1_000_000,
            ),
            expected_template_clause_count=_integer(
                row["expected_template_clause_count"],
                "source.expected_template_clause_count",
                1,
                10_000_000,
            ),
            expected_public_clause_count=_integer(
                row["expected_public_clause_count"],
                "source.expected_public_clause_count",
                1,
                10_000_000,
            ),
        )


@dataclass(frozen=True)
class MultiKeyProbeConfig:
    seed: int
    timeout_seconds: float
    sentinel_bit: int
    sentinel_reruns_per_sweep: int

    @classmethod
    def from_mapping(cls, value: object) -> "MultiKeyProbeConfig":
        row = _strict_mapping(
            value,
            "probe",
            {
                "seed",
                "timeout_seconds",
                "sentinel_bit",
                "sentinel_reruns_per_sweep",
            },
        )
        return cls(
            seed=_integer(row["seed"], "probe.seed", 0, 2_000_000_000),
            timeout_seconds=_positive(
                row["timeout_seconds"], "probe.timeout_seconds", 3600.0
            ),
            sentinel_bit=_integer(row["sentinel_bit"], "probe.sentinel_bit", 0, 255),
            sentinel_reruns_per_sweep=_integer(
                row["sentinel_reruns_per_sweep"],
                "probe.sentinel_reruns_per_sweep",
                0,
                1,
            ),
        )


@dataclass(frozen=True)
class MultiKeyCorpusConfig:
    seed: int
    build_targets: int
    calibration_targets: int
    sealed_targets: int

    @classmethod
    def from_mapping(cls, value: object) -> "MultiKeyCorpusConfig":
        row = _strict_mapping(
            value,
            "corpus",
            {"seed", "build_targets", "calibration_targets", "sealed_targets"},
        )
        return cls(
            seed=_integer(row["seed"], "corpus.seed", 0, (1 << 63) - 1),
            build_targets=_integer(row["build_targets"], "corpus.build_targets", 2, 64),
            calibration_targets=_integer(
                row["calibration_targets"],
                "corpus.calibration_targets",
                2,
                32,
            ),
            sealed_targets=_integer(
                row["sealed_targets"], "corpus.sealed_targets", 1, 16
            ),
        )


@dataclass(frozen=True)
class MultiKeyReaderConfig:
    arms: tuple[str, ...]
    ridge_lambdas: tuple[float, ...]
    temperatures: tuple[float, ...]
    shrinkages: tuple[float, ...]
    decoy_count: int
    decoy_seed: int

    @classmethod
    def from_mapping(cls, value: object) -> "MultiKeyReaderConfig":
        row = _strict_mapping(
            value,
            "reader",
            {
                "arms",
                "ridge_lambdas",
                "temperatures",
                "shrinkages",
                "decoy_count",
                "decoy_seed",
            },
        )
        arms = row["arms"]
        if (
            not isinstance(arms, list)
            or not arms
            or any(not isinstance(item, str) or not item for item in arms)
            or len(set(arms)) != len(arms)
        ):
            raise Full256MultiKeyCalibrationError(
                "reader.arms must be a non-empty unique string array"
            )
        shrinkages = _float_grid(
            row["shrinkages"], "reader.shrinkages", allow_zero=True
        )
        if not shrinkages or shrinkages[0] != 0.0:
            raise Full256MultiKeyCalibrationError(
                "reader.shrinkages must begin with the exact uniform fallback 0"
            )
        return cls(
            arms=tuple(arms),
            ridge_lambdas=_float_grid(row["ridge_lambdas"], "reader.ridge_lambdas"),
            temperatures=_float_grid(row["temperatures"], "reader.temperatures"),
            shrinkages=shrinkages,
            decoy_count=_integer(
                row["decoy_count"], "reader.decoy_count", 1, 10_000_000
            ),
            decoy_seed=_integer(
                row["decoy_seed"], "reader.decoy_seed", 0, (1 << 63) - 1
            ),
        )


@dataclass(frozen=True)
class MultiKeyControlConfig:
    transforms: tuple[str, ...]
    run_only_if_calibration_compression_positive: bool

    @classmethod
    def from_mapping(cls, value: object) -> "MultiKeyControlConfig":
        row = _strict_mapping(
            value,
            "target_controls",
            {
                "transforms",
                "run_only_if_calibration_compression_positive",
            },
        )
        transforms = row["transforms"]
        if (
            not isinstance(transforms, list)
            or any(
                not isinstance(item, str) or item not in ALLOWED_CONTROLS
                for item in transforms
            )
            or len(set(transforms)) != len(transforms)
        ):
            raise Full256MultiKeyCalibrationError("target control transforms differ")
        gate = row["run_only_if_calibration_compression_positive"]
        if not isinstance(gate, bool):
            raise Full256MultiKeyCalibrationError(
                "target control calibration gate must be boolean"
            )
        return cls(
            transforms=tuple(transforms),
            run_only_if_calibration_compression_positive=gate,
        )


@dataclass(frozen=True)
class Full256MultiKeyCalibrationConfig:
    source: MultiKeyFoundationSource
    native: NativeDependencyConfig
    probe: MultiKeyProbeConfig
    state_plan: CausalBitfieldPlan
    corpus: MultiKeyCorpusConfig
    reader: MultiKeyReaderConfig
    controls: MultiKeyControlConfig
    budgets: SensorBudgetConfig
    maximum_state_bytes: int
    maximum_live_target_state_bytes: int


def load_full256_multikey_calibration_config(
    path: str | Path,
) -> tuple[dict[str, object], Full256MultiKeyCalibrationConfig]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Full256MultiKeyCalibrationError(
            "could not load multi-key calibration config"
        ) from exc
    row = _strict_mapping(
        value,
        "config",
        {
            "schema",
            "attempt_id",
            "slug",
            "claim_level",
            "hypothesis",
            "prediction",
            "controls",
            "budgets",
            "next_action",
            "source",
            "native",
            "probe",
            "state_plan",
            "corpus",
            "reader",
            "target_controls",
            "maximum_state_bytes",
            "maximum_live_target_state_bytes",
        },
    )
    if row["schema"] != CONFIG_SCHEMA:
        raise Full256MultiKeyCalibrationError(
            "multi-key calibration config schema differs"
        )
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        _string(row[field], f"config.{field}")
    controls = row["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item for item in controls)
    ):
        raise Full256MultiKeyCalibrationError("config.controls differs")
    if not isinstance(row["state_plan"], Mapping):
        raise Full256MultiKeyCalibrationError("config.state_plan differs")
    config = Full256MultiKeyCalibrationConfig(
        source=MultiKeyFoundationSource.from_mapping(row["source"]),
        native=NativeDependencyConfig.from_mapping(row["native"]),
        probe=MultiKeyProbeConfig.from_mapping(row["probe"]),
        state_plan=plan_from_mapping(row["state_plan"]),
        corpus=MultiKeyCorpusConfig.from_mapping(row["corpus"]),
        reader=MultiKeyReaderConfig.from_mapping(row["reader"]),
        controls=MultiKeyControlConfig.from_mapping(row["target_controls"]),
        budgets=SensorBudgetConfig.from_mapping(row["budgets"]),
        maximum_state_bytes=_integer(
            row["maximum_state_bytes"], "maximum_state_bytes", 1, 1_000_000
        ),
        maximum_live_target_state_bytes=_integer(
            row["maximum_live_target_state_bytes"],
            "maximum_live_target_state_bytes",
            1,
            1_000_000,
        ),
    )
    if config.state_plan.serialized_state_bytes > config.maximum_state_bytes:
        raise Full256MultiKeyCalibrationError(
            "causal state exceeds maximum_state_bytes"
        )
    expected_live = (
        config.state_plan.serialized_state_bytes
        + KEY_BITS * READER_FEATURES * 4
        + KEY_BITS * 4
    )
    if config.maximum_live_target_state_bytes != expected_live:
        raise Full256MultiKeyCalibrationError(
            "live target state must equal causal state, bounded float32 reader "
            "feature bank, and 256 float32 logits"
        )
    maximum_sweeps = (
        config.corpus.build_targets
        + config.corpus.calibration_targets
        + config.corpus.sealed_targets
        + len(config.controls.transforms)
    )
    maximum_branches = maximum_sweeps * (
        2 * KEY_BITS + 2 * config.probe.sentinel_reruns_per_sweep
    )
    if maximum_branches > config.budgets.maximum_native_solver_branches:
        raise Full256MultiKeyCalibrationError(
            "declared multi-key branch count exceeds budget"
        )
    if config.corpus.sealed_targets > config.budgets.maximum_fresh_random_targets:
        raise Full256MultiKeyCalibrationError(
            "sealed target count exceeds fresh-target budget"
        )
    return dict(row), config


@dataclass(frozen=True)
class _KnownTarget:
    target_id: str
    split: str
    key: bytes
    public: PublicTargetView


def _known_target(
    *,
    seed: int,
    split: str,
    index: int,
) -> _KnownTarget:
    if split not in {"BUILD", "CALIBRATION"}:
        raise Full256MultiKeyCalibrationError("known target split differs")
    material = hashlib.shake_256(
        canonical_json_bytes(["o1c0013-known-target-v1", seed, split, index])
    ).digest(48)
    key = material[:32]
    counter = int.from_bytes(material[32:36], "little")
    nonce = material[36:48]
    public = PublicTargetView(
        counter_schedule=(counter,),
        nonce=nonce,
        output_blocks=(chacha20_block(key, counter, nonce),),
    )
    public.validate()
    return _KnownTarget(
        target_id=f"{split.lower()}-{index:04d}",
        split=split,
        key=key,
        public=public,
    )


def _labels_from_key(key: bytes) -> np.ndarray:
    if not isinstance(key, bytes) or len(key) != 32:
        raise Full256MultiKeyCalibrationError("key labels require exactly 32 bytes")
    return np.unpackbits(np.frombuffer(key, dtype=np.uint8), bitorder="little").astype(
        np.uint8
    )


def _bits_to_key(bits: np.ndarray) -> bytes:
    value = np.asarray(bits, dtype=np.uint8)
    if value.shape != (KEY_BITS,) or np.any((value != 0) & (value != 1)):
        raise Full256MultiKeyCalibrationError("predicted bits differ")
    return np.packbits(value, bitorder="little").tobytes()


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if __import__("sys").platform == "darwin" else raw * 1024)


def _artifact_inventory(
    artifacts: Mapping[str, bytes],
) -> dict[str, dict[str, object]]:
    return {
        name: {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for name, payload in sorted(artifacts.items())
    }


FreezeCallback = Callable[
    [Mapping[str, bytes], Mapping[str, object]],
    None,
]


@dataclass(frozen=True)
class _ProbeSnapshot:
    target_id: str
    public: PublicTargetView
    state_bytes: bytes
    state_sha256: str
    reader_features: np.ndarray
    reader_features_sha256: str
    instance: Mapping[str, object]
    probe: Mapping[str, object]
    resources: Mapping[str, object]

    def __post_init__(self) -> None:
        features = np.asarray(self.reader_features)
        if (
            features.shape != (KEY_BITS, READER_FEATURES)
            or features.dtype != np.float32
            or not np.all(np.isfinite(features))
        ):
            raise Full256MultiKeyCalibrationError("probe snapshot features differ")
        if len(self.state_bytes) == 0 or hashlib.sha256(
            self.state_bytes
        ).hexdigest() != (self.state_sha256):
            raise Full256MultiKeyCalibrationError("probe snapshot state differs")
        features.setflags(write=False)
        object.__setattr__(self, "reader_features", features)


def _public_control(view: PublicTargetView, transform: str) -> PublicTargetView:
    view.validate()
    if view.block_count != 1 or transform not in ALLOWED_CONTROLS:
        raise Full256MultiKeyCalibrationError("public target control differs")
    nonce = view.nonce
    output = view.output_blocks[0]
    if transform == "output_bit_flip":
        changed = bytearray(output)
        changed[0] ^= 1
        output = bytes(changed)
    elif transform == "wrong_nonce":
        changed = bytearray(nonce)
        changed[0] ^= 1
        nonce = bytes(changed)
    elif transform == "output_byte_rotate":
        output = output[1:] + output[:1]
    result = PublicTargetView(
        counter_schedule=view.counter_schedule,
        nonce=nonce,
        output_blocks=(output,),
    )
    result.validate()
    return result


def _stream_decoy_rank(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    decoy_count: int,
    seed: int,
) -> dict[str, object]:
    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.uint8)
    if values.shape != (KEY_BITS,) or truth.shape != (KEY_BITS,):
        raise Full256MultiKeyCalibrationError("decoy rank vector differs")
    log_zero = np.log2(np.clip(1.0 - values, 2.0**-64, 1.0))
    log_one = np.log2(np.clip(values, 2.0**-64, 1.0))
    delta = log_one - log_zero
    base = float(log_zero.sum())
    true_score = base + float(truth @ delta)
    rng = np.random.Generator(np.random.PCG64(seed))
    better = equal = 0
    digest = hashlib.sha256(b"o1c0013-decoy-score-stream-v1\0")
    remaining = decoy_count
    while remaining:
        count = min(4096, remaining)
        bits = rng.integers(0, 2, size=(count, KEY_BITS), dtype=np.uint8)
        scores = base + np.einsum(
            "ij,j->i", bits, delta, dtype=np.float64, optimize=False
        )
        better += int(np.count_nonzero(scores > true_score))
        equal += int(np.count_nonzero(scores == true_score))
        digest.update(scores.astype("<f8", copy=False).tobytes(order="C"))
        remaining -= count
    return {
        "decoy_count": decoy_count,
        "true_log2_probability": true_score,
        "strictly_better_decoys": better,
        "equal_score_decoys": equal,
        "rank_lower_one_based": better + 1,
        "rank_upper_one_based": better + equal + 1,
        "rank_midpoint_one_based": better + 1.0 + 0.5 * equal,
        # Use the pessimistic edge of the tie interval as the headline rank.
        # An exact-uniform reader therefore ranks last, not spuriously first,
        # among one million equal-score decoys.
        "rank_one_based": better + equal + 1,
        "score_stream_float64le_sha256": digest.hexdigest(),
    }


def _factorized_group_value_ranks(
    probabilities: np.ndarray,
    labels: np.ndarray,
    *,
    width: int,
) -> dict[str, object]:
    """Rank each true byte/word among every value under the bit posterior."""

    values = np.asarray(probabilities, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.uint8)
    if (
        values.shape != (KEY_BITS,)
        or truth.shape != (KEY_BITS,)
        or width not in (8, 16)
        or KEY_BITS % width
    ):
        raise Full256MultiKeyCalibrationError("factorized group rank input differs")
    clipped = np.clip(values, np.finfo(np.float64).eps, 1.0 - np.finfo(np.float64).eps)
    candidate_values = np.arange(1 << width, dtype=np.uint32)
    candidate_bits = (
        (candidate_values[:, None] >> np.arange(width, dtype=np.uint32)) & 1
    ).astype(np.float64)
    rank_rows: list[dict[str, object]] = []
    upper_ranks: list[int] = []
    lower_ranks: list[int] = []
    for group_index, first in enumerate(range(0, KEY_BITS, width)):
        group_probability = clipped[first : first + width]
        log_zero = np.log2(1.0 - group_probability)
        delta = np.log2(group_probability) - log_zero
        scores = float(log_zero.sum()) + np.sum(
            candidate_bits * delta[None, :],
            axis=1,
            dtype=np.float64,
        )
        true_bits = truth[first : first + width]
        true_value = int(
            np.dot(true_bits.astype(np.uint32), 1 << np.arange(width, dtype=np.uint32))
        )
        true_score = float(scores[true_value])
        better = int(np.count_nonzero(scores > true_score))
        equal = int(np.count_nonzero(scores == true_score))
        lower = better + 1
        upper = better + equal
        lower_ranks.append(lower)
        upper_ranks.append(upper)
        rank_rows.append(
            {
                "group_index": group_index,
                "first_key_bit": first,
                "true_value": true_value,
                "true_log2_probability": true_score,
                "strictly_better_values": better,
                "equal_score_values_including_truth": equal,
                "rank_lower_one_based": lower,
                "rank_upper_one_based": upper,
                "rank_one_based": upper,
            }
        )
    upper_array = np.asarray(upper_ranks, dtype=np.float64)
    return {
        "posterior": "independent-bit-factorization-within-group",
        "group_width_bits": width,
        "group_count": len(rank_rows),
        "candidate_values_per_group": 1 << width,
        "rank_tie_policy": "headline-is-pessimistic-upper-bound",
        "top1_groups": sum(rank_value <= 1 for rank_value in upper_ranks),
        "top4_groups": sum(rank_value <= 4 for rank_value in upper_ranks),
        "top16_groups": sum(rank_value <= 16 for rank_value in upper_ranks),
        "best_rank_one_based": min(upper_ranks),
        "worst_rank_one_based": max(upper_ranks),
        "mean_rank_one_based": float(upper_array.mean()),
        "median_rank_one_based": float(np.median(upper_array)),
        "mean_rank_interval_width": float(
            np.mean(np.asarray(upper_ranks) - np.asarray(lower_ranks))
        ),
        "rows": rank_rows,
    }


def _aggregate_group_ranks(ranks: list[int], *, width: int) -> dict[str, object]:
    if not ranks or width not in (8, 16):
        raise Full256MultiKeyCalibrationError("group rank aggregate differs")
    values = np.asarray(ranks, dtype=np.float64)
    return {
        "posterior": "independent-bit-factorization-within-group",
        "group_width_bits": width,
        "evaluated_groups": len(ranks),
        "candidate_values_per_group": 1 << width,
        "rank_tie_policy": "headline-is-pessimistic-upper-bound",
        "top1_groups": sum(rank_value <= 1 for rank_value in ranks),
        "top4_groups": sum(rank_value <= 4 for rank_value in ranks),
        "top16_groups": sum(rank_value <= 16 for rank_value in ranks),
        "best_rank_one_based": min(ranks),
        "worst_rank_one_based": max(ranks),
        "mean_rank_one_based": float(values.mean()),
        "median_rank_one_based": float(np.median(values)),
    }


def _reader_outputs(
    reader: FrozenCausalOrientationReader,
    features: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    scores = np.asarray(reader.predict_scores(features), dtype=np.float32)
    if scores.shape != (KEY_BITS,) or not np.all(np.isfinite(scores)):
        raise Full256MultiKeyCalibrationError("reader score vector differs")
    scaled = np.clip(
        scores.astype(np.float64)
        * float(reader.logit_scale)
        / float(reader.temperature),
        -60.0,
        60.0,
    )
    probabilities = 0.5 + 0.5 * np.tanh(0.5 * scaled)
    if (
        probabilities.shape != (KEY_BITS,)
        or not np.all(np.isfinite(probabilities))
        or np.any((probabilities < 0.0) | (probabilities > 1.0))
    ):
        raise Full256MultiKeyCalibrationError("reader probability vector differs")
    return scores, probabilities


def _probe_public(
    *,
    target_id: str,
    public: PublicTargetView,
    template: Path,
    semantic_map: Path,
    semantic_map_sha256: str,
    native_executable: Path,
    state_plan: CausalBitfieldPlan,
    probe: MultiKeyProbeConfig,
    maximum_state_bytes: int,
    expected_variable_count: int,
    expected_public_clause_count: int,
    working_directory: Path,
) -> _ProbeSnapshot:
    public.validate()
    if public.block_count != 1:
        raise Full256MultiKeyCalibrationError(
            "multi-key probe requires exactly one public block"
        )
    with tempfile.TemporaryDirectory(
        prefix=f"o1c0013-{target_id}-",
        dir=working_directory,
    ) as temporary:
        instance_path = Path(temporary) / "public_attacker_instance.cnf"
        instance = write_full256_instance(
            template,
            semantic_map,
            instance_path,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
            verify_template=False,
        )
        if (
            instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.public_unit_clause_count != 640
            or instance.clause_count != expected_public_clause_count
        ):
            raise Full256MultiKeyCalibrationError(
                "generated attacker instance boundary differs"
            )
        core = run_full256_probe_core(
            Full256ProbeCoreConfig(
                public_cnf=instance_path,
                semantic_map=semantic_map,
                native_executable=native_executable,
                state_plan=state_plan,
                seed=probe.seed,
                timeout_seconds=probe.timeout_seconds,
                sentinel_bit=probe.sentinel_bit,
                sentinel_reruns=probe.sentinel_reruns_per_sweep,
                maximum_state_bytes=maximum_state_bytes,
                expected_public_cnf_sha256=instance.instance_sha256,
                expected_semantic_map_sha256=semantic_map_sha256,
                expected_variable_count=expected_variable_count,
                expected_clause_count=expected_public_clause_count,
            )
        )
        if not core.success_gate_passed:
            raise Full256MultiKeyCalibrationError(
                f"probe core gate failed for {target_id}"
            )
        state_bytes = core.state.to_bytes()
        features = core.reader_features.copy()
        snapshot = _ProbeSnapshot(
            target_id=target_id,
            public=public,
            state_bytes=state_bytes,
            state_sha256=core.state.state_sha256,
            reader_features=features,
            reader_features_sha256=core.reader_features_sha256,
            instance=instance.describe(),
            probe={
                "result_sha256": core.report["result_sha256"],
                "source_stream_sha256": core.report["probe_stream"][
                    "source_stream_sha256"
                ],
                "event_index_sha256": core.event_index["event_index_sha256"],
                "public_baseline_sha256": core.report["probe_stream"][
                    "public_baseline_sha256"
                ],
                "frontier_event_gap_max": core.report["probe_stream"][
                    "frontier_event_gap_max"
                ],
                "frontier_event_gap_mean": core.report["probe_stream"][
                    "frontier_event_gap_mean"
                ],
                "gates": core.report["gates"],
            },
            resources=core.report["resources"],
        )
    return snapshot


@dataclass(frozen=True)
class Full256MultiKeyCalibrationResult:
    report: Mapping[str, object]
    final_artifacts: Mapping[str, bytes]
    reader_freeze_artifacts: Mapping[str, bytes]
    prediction_freeze_artifacts: Mapping[str, bytes]

    @property
    def success_gate_passed(self) -> bool:
        return bool(self.report["gates"]["success_gate_passed"])

    def metrics(self) -> dict[str, object]:
        sealed = self.report["sealed_evaluation"]
        resources = self.report["resources"]
        reader = self.report["reader"]
        return {
            "schema": "o1-256-multikey-causal-calibration-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "unknown_target_key_bits": 256,
            "build_targets": self.report["corpus"]["build_targets"],
            "calibration_targets": self.report["corpus"]["calibration_targets"],
            "sealed_targets": self.report["corpus"]["sealed_targets"],
            "selected_arm": reader["selected_arm"],
            "selected_logit_scale": reader["selected_logit_scale"],
            "calibration_compression_bits_per_key": self.report[
                "calibration_evaluation"
            ]["compression_bits_per_key"],
            "sealed_compression_bits_per_key": sealed["primary"][
                "compression_bits_per_key"
            ],
            "sealed_correct_bits": sealed["primary"]["correct_bits"],
            "sealed_total_bits": sealed["primary"]["total_bits"],
            "sealed_exact_keys": sealed["exact_keys"],
            "minimum_million_decoy_rank": sealed["minimum_million_decoy_rank"],
            "factorized_byte_mean_rank": sealed["factorized_byte_value_rank_aggregate"][
                "mean_rank_one_based"
            ],
            "factorized_byte_top1_groups": sealed[
                "factorized_byte_value_rank_aggregate"
            ]["top1_groups"],
            "factorized_16bit_mean_rank": sealed[
                "factorized_16bit_value_rank_aggregate"
            ]["mean_rank_one_based"],
            "factorized_16bit_top1_groups": sealed[
                "factorized_16bit_value_rank_aggregate"
            ]["top1_groups"],
            "live_target_state_bytes": self.report["state_contract"][
                "live_target_state_bytes"
            ],
            "native_solver_branches": resources["native_solver_branches"],
            "cpu_seconds": resources["budgeted_cpu_seconds"],
            "wall_seconds": resources["wall_seconds"],
            "peak_rss_bytes": resources["peak_rss_bytes"],
            "persistent_artifact_bytes": resources["persistent_artifact_bytes"],
            "fresh_random_targets": resources["fresh_random_targets"],
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        }


def run_full256_multikey_calibration(
    config: Full256MultiKeyCalibrationConfig,
    *,
    lab_root: str | Path,
    working_directory: str | Path,
    on_reader_frozen: FreezeCallback,
    on_predictions_frozen: FreezeCallback,
    sealed_entropy_source: Callable[[int], bytes] = os.urandom,
    sealed_entropy_source_id: str = "os.urandom",
) -> Full256MultiKeyCalibrationResult:
    """Fit on known keys, persist a reader freeze, then attack fresh sealed keys."""

    if not isinstance(config, Full256MultiKeyCalibrationConfig):
        raise TypeError("config must be Full256MultiKeyCalibrationConfig")
    if not callable(on_reader_frozen) or not callable(on_predictions_frozen):
        raise TypeError("freeze callbacks must be callable")
    if not callable(sealed_entropy_source):
        raise TypeError("sealed_entropy_source must be callable")
    if not isinstance(sealed_entropy_source_id, str) or not sealed_entropy_source_id:
        raise Full256MultiKeyCalibrationError("entropy source id is required")

    fresh_target_entropy_calls = 0

    def counted_sealed_entropy(byte_count: int) -> bytes:
        nonlocal fresh_target_entropy_calls
        fresh_target_entropy_calls += 1
        return sealed_entropy_source(byte_count)

    wall_started = time.monotonic()
    parent_cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    root = Path(lab_root).resolve(strict=True)
    workspace = Path(working_directory)
    workspace.mkdir(parents=True, exist_ok=True)
    workspace = workspace.resolve(strict=True)
    allowed_workspaces = (
        root,
        Path(tempfile.gettempdir()).resolve(strict=True),
        Path("/tmp").resolve(strict=True),
    )
    if not any(workspace.is_relative_to(base) for base in allowed_workspaces):
        raise Full256MultiKeyCalibrationError(
            "working directory is outside the lab and system temporary roots"
        )
    source_capsule = (root / config.source.capsule).resolve(strict=True)
    runs_root = (root / "runs").resolve(strict=True)
    if source_capsule.parent != runs_root:
        raise Full256MultiKeyCalibrationError(
            "foundation source is outside finalized runs"
        )
    template = (source_capsule / config.source.template).resolve(strict=True)
    semantic_map = (source_capsule / config.source.semantic_map).resolve(strict=True)
    if not template.is_relative_to(source_capsule) or not semantic_map.is_relative_to(
        source_capsule
    ):
        raise Full256MultiKeyCalibrationError(
            "foundation template or semantic map escapes its source capsule"
        )
    if workspace.is_relative_to(source_capsule):
        raise Full256MultiKeyCalibrationError(
            "working directory cannot modify the immutable source capsule"
        )
    source_manifest = (source_capsule / "artifacts.sha256").resolve(strict=True)
    initial_source_hashes = {
        "manifest": sha256_file(source_manifest),
        "template": sha256_file(template),
        "semantic_map": sha256_file(semantic_map),
    }
    expected_source_hashes = {
        "manifest": config.source.manifest_sha256,
        "template": config.source.template_sha256,
        "semantic_map": config.source.semantic_map_sha256,
    }
    if initial_source_hashes != expected_source_hashes:
        raise Full256MultiKeyCalibrationError(
            "immutable foundation source hash differs"
        )
    template_verification = verify_full256_template(template, semantic_map)
    if (
        template_verification["variable_count"] != config.source.expected_variable_count
        or template_verification["clause_count"]
        != config.source.expected_template_clause_count
    ):
        raise Full256MultiKeyCalibrationError(
            "foundation template dimensions differ from the pinned contract"
        )

    native_executable = workspace / "cadical_pair_sensor"
    native_build = build_native_sensor(
        source=root / "native/cadical_pair_sensor.cpp",
        tracer_header=root / "native/cadical_tracer_3_0_0.hpp",
        cadical_include=config.native.include_directory,
        cadical_library=config.native.static_library,
        output=native_executable,
        expected_cadical_header_sha256=config.native.cadical_header_sha256,
        expected_cadical_library_sha256=config.native.cadical_library_sha256,
        compiler=config.native.compiler,
    )

    sweep_attempts = 0
    resource_rows: list[Mapping[str, object]] = []
    known_features: list[np.ndarray] = []
    known_states: list[bytes] = []
    known_labels: list[np.ndarray] = []
    known_index: list[dict[str, object]] = []

    for split, count in (
        ("BUILD", config.corpus.build_targets),
        ("CALIBRATION", config.corpus.calibration_targets),
    ):
        for index in range(count):
            target = _known_target(
                seed=config.corpus.seed,
                split=split,
                index=index,
            )
            sweep_attempts += 1
            snapshot = _probe_public(
                target_id=target.target_id,
                public=target.public,
                template=template,
                semantic_map=semantic_map,
                semantic_map_sha256=config.source.semantic_map_sha256,
                native_executable=native_executable,
                state_plan=config.state_plan,
                probe=config.probe,
                maximum_state_bytes=config.maximum_state_bytes,
                expected_variable_count=config.source.expected_variable_count,
                expected_public_clause_count=(
                    config.source.expected_public_clause_count
                ),
                working_directory=workspace,
            )
            # BUILD/CAL labels are first materialized after the public probe has
            # already frozen and serialized its bounded state.
            labels = _labels_from_key(target.key)
            known_features.append(snapshot.reader_features.copy())
            known_states.append(snapshot.state_bytes)
            known_labels.append(labels)
            resource_rows.append(snapshot.resources)
            known_index.append(
                {
                    "target_id": target.target_id,
                    "split": target.split,
                    "distribution": "DETERMINISTIC_UNIFORM",
                    "public_view": target.public.describe(),
                    "public_view_sha256": target.public.digest(),
                    "key_sha256": hashlib.sha256(target.key).hexdigest(),
                    "label_bitpack_sha256": hashlib.sha256(
                        np.packbits(labels, bitorder="little").tobytes()
                    ).hexdigest(),
                    "label_access_phase": "POST_CAUSAL_STATE_FREEZE",
                    "state_sha256": snapshot.state_sha256,
                    "reader_features_sha256": snapshot.reader_features_sha256,
                    "instance_sha256": snapshot.instance["instance_sha256"],
                    "probe_result_sha256": snapshot.probe["result_sha256"],
                    "event_index_sha256": snapshot.probe["event_index_sha256"],
                }
            )

    all_features = np.stack(known_features).astype(np.float32, copy=False)
    all_labels = np.stack(known_labels).astype(np.uint8, copy=False)
    build_count = config.corpus.build_targets
    build_features = all_features[:build_count]
    calibration_features = all_features[build_count:]
    build_labels = all_labels[:build_count]
    calibration_labels = all_labels[build_count:]
    if build_features.shape != (
        build_count,
        KEY_BITS,
        READER_FEATURES,
    ) or calibration_features.shape != (
        config.corpus.calibration_targets,
        KEY_BITS,
        READER_FEATURES,
    ):
        raise AssertionError("known feature split differs")

    reader = fit_causal_orientation_reader(
        build_features,
        build_labels,
        calibration_features,
        calibration_labels,
        arms=config.reader.arms,
        ridge_lambdas=config.reader.ridge_lambdas,
        temperatures=config.reader.temperatures,
        logit_scales=config.reader.shrinkages,
        tensor_horizons=config.state_plan.horizons,
    )
    shuffled_build_labels = np.roll(build_labels, 1, axis=0)
    shuffled_calibration_labels = np.roll(calibration_labels, 1, axis=0)
    shuffled_reader = fit_causal_orientation_reader(
        build_features,
        shuffled_build_labels,
        calibration_features,
        shuffled_calibration_labels,
        arms=config.reader.arms,
        ridge_lambdas=config.reader.ridge_lambdas,
        temperatures=config.reader.temperatures,
        logit_scales=config.reader.shrinkages,
        tensor_horizons=config.state_plan.horizons,
    )

    build_probabilities = np.stack(
        [_reader_outputs(reader, panel)[1] for panel in build_features]
    )
    calibration_probabilities = np.stack(
        [_reader_outputs(reader, panel)[1] for panel in calibration_features]
    )
    shuffled_calibration_probabilities = np.stack(
        [_reader_outputs(shuffled_reader, panel)[1] for panel in calibration_features]
    )
    build_evaluation = orientation_metrics(build_probabilities, build_labels).describe()
    calibration_evaluation = orientation_metrics(
        calibration_probabilities, calibration_labels
    ).describe()
    shuffled_calibration_evaluation = orientation_metrics(
        shuffled_calibration_probabilities,
        calibration_labels,
    ).describe()
    calibration_compression = float(calibration_evaluation["compression_bits_per_key"])

    known_document: dict[str, object] = {
        "schema": KNOWN_INDEX_SCHEMA,
        "corpus_seed": config.corpus.seed,
        "build_targets": config.corpus.build_targets,
        "calibration_targets": config.corpus.calibration_targets,
        "feature_shape": list(all_features.shape),
        "state_bytes_per_target": config.state_plan.serialized_state_bytes,
        "rows": known_index,
    }
    known_document["known_index_sha256"] = canonical_sha256(known_document)
    reader_binary = serialize_orientation_reader(reader)
    shuffled_reader_binary = serialize_orientation_reader(shuffled_reader)
    reader_freeze_artifacts: dict[str, bytes] = {
        "build_cal_features.f32le": all_features.astype("<f4", copy=False).tobytes(
            order="C"
        ),
        "build_cal_labels.bitpack": np.packbits(
            all_labels, axis=1, bitorder="little"
        ).tobytes(order="C"),
        "build_cal_states.bin": b"".join(known_states),
        "build_cal_index.json": canonical_json_bytes(known_document),
        "frozen_reader.bin": reader_binary,
        "frozen_reader.json": canonical_json_bytes(reader.describe()),
        "shuffled_key_reader.bin": shuffled_reader_binary,
        "shuffled_key_reader.json": canonical_json_bytes(shuffled_reader.describe()),
        "build_evaluation.json": canonical_json_bytes(build_evaluation),
        "calibration_evaluation.json": canonical_json_bytes(calibration_evaluation),
        "shuffled_calibration_evaluation.json": canonical_json_bytes(
            shuffled_calibration_evaluation
        ),
    }
    reader_freeze_unsigned = {
        "schema": READER_FREEZE_SCHEMA,
        "phase": "READER_FROZEN_BEFORE_SEALED_TARGET_ENTROPY",
        "unknown_target_key_bits": 256,
        "reader_sha256": reader.reader_sha256,
        "shuffled_key_reader_sha256": shuffled_reader.reader_sha256,
        "selected_arm": reader.arm,
        "selected_ridge_lambda": reader.ridge_lambda,
        "selected_temperature": reader.temperature,
        "selected_logit_scale": reader.logit_scale,
        "build_dataset_sha256": reader.build_dataset_sha256,
        "calibration_dataset_sha256": reader.calibration_dataset_sha256,
        "calibration_compression_bits_per_key": calibration_compression,
        "fresh_target_entropy_calls": fresh_target_entropy_calls,
        "artifacts": _artifact_inventory(reader_freeze_artifacts),
    }
    reader_freeze_document = {
        **reader_freeze_unsigned,
        "reader_freeze_sha256": canonical_sha256(reader_freeze_unsigned),
    }
    reader_freeze_artifacts["reader_freeze.json"] = canonical_json_bytes(
        reader_freeze_document
    )
    if fresh_target_entropy_calls != 0:
        raise Full256MultiKeyCalibrationError(
            "sealed target entropy was accessed before the reader freeze"
        )
    on_reader_frozen(reader_freeze_artifacts, reader_freeze_document)
    reader_frozen_at = time.monotonic()
    reloaded_reader = deserialize_orientation_reader(reader_binary)
    reloaded_shuffled_reader = deserialize_orientation_reader(shuffled_reader_binary)
    frozen_reader_reload_exact = (
        serialize_orientation_reader(reloaded_reader) == reader_binary
        and serialize_orientation_reader(reloaded_shuffled_reader)
        == shuffled_reader_binary
        and reloaded_reader.reader_sha256 == reader.reader_sha256
        and reloaded_shuffled_reader.reader_sha256 == shuffled_reader.reader_sha256
    )
    if not frozen_reader_reload_exact:
        raise Full256MultiKeyCalibrationError(
            "persisted reader reload differs before sealed inference"
        )
    reader = reloaded_reader
    shuffled_reader = reloaded_shuffled_reader

    control_gate_open = (
        not config.controls.run_only_if_calibration_compression_positive
        or calibration_compression > 1e-12
    )
    sealed_rows: list[dict[str, object]] = []
    prediction_freeze_artifacts: dict[str, bytes] = {}
    fresh_target_created_at: float | None = None

    for index in range(config.corpus.sealed_targets):
        if fresh_target_created_at is None:
            fresh_target_created_at = time.monotonic()
        broker = Full256TargetBroker(
            block_count=1,
            entropy_source=counted_sealed_entropy,
            entropy_source_id=sealed_entropy_source_id,
            target_id=f"o1c0013-sealed-{index:04d}",
        )
        publication = broker.publish()
        public = public_view_from_publication(publication)
        target_id = str(publication["target_id"])
        sweep_attempts += 1
        snapshot = _probe_public(
            target_id=target_id,
            public=public,
            template=template,
            semantic_map=semantic_map,
            semantic_map_sha256=config.source.semantic_map_sha256,
            native_executable=native_executable,
            state_plan=config.state_plan,
            probe=config.probe,
            maximum_state_bytes=config.maximum_state_bytes,
            expected_variable_count=config.source.expected_variable_count,
            expected_public_clause_count=config.source.expected_public_clause_count,
            working_directory=workspace,
        )
        resource_rows.append(snapshot.resources)
        scores, probabilities = _reader_outputs(reader, snapshot.reader_features)
        shuffled_scores, shuffled_probabilities = _reader_outputs(
            shuffled_reader, snapshot.reader_features
        )
        swap_scores, swap_probabilities = _reader_outputs(
            reader, -snapshot.reader_features
        )
        swap_score_gate = bool(np.array_equal(swap_scores, -scores))
        swap_probability_residual = float(
            np.max(np.abs(probabilities + swap_probabilities - 1.0))
        )
        swap_probability_gate = bool(
            np.array_equal(
                probabilities + swap_probabilities,
                np.ones(KEY_BITS, dtype=np.float64),
            )
        )
        prediction = (probabilities >= 0.5).astype(np.uint8)
        predicted_key = _bits_to_key(prediction)
        exact_public_verification = (
            chacha20_block(
                predicted_key,
                public.counter_schedule[0],
                public.nonce,
            )
            == public.output_blocks[0]
        )
        prefix = f"sealed/{target_id}"
        target_artifacts = {
            f"{prefix}/publication.json": canonical_json_bytes(publication),
            f"{prefix}/causal_state.bin": snapshot.state_bytes,
            f"{prefix}/reader_features.f32le": snapshot.reader_features.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
            f"{prefix}/scores.f32le": scores.astype("<f4", copy=False).tobytes(
                order="C"
            ),
            f"{prefix}/probabilities.f64le": probabilities.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            f"{prefix}/shuffled_scores.f32le": shuffled_scores.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
            f"{prefix}/shuffled_probabilities.f64le": (
                shuffled_probabilities.astype("<f8", copy=False).tobytes(order="C")
            ),
        }
        target_freeze_unsigned = {
            "schema": PREDICTION_FREEZE_SCHEMA,
            "phase": "SEALED_PREDICTION_FROZEN_BEFORE_REVEAL",
            "target_id": target_id,
            "publication_sha256": publication["publication_sha256"],
            "public_view_sha256": publication["public_view_sha256"],
            "reader_sha256": reader.reader_sha256,
            "shuffled_key_reader_sha256": shuffled_reader.reader_sha256,
            "state_sha256": snapshot.state_sha256,
            "reader_features_sha256": snapshot.reader_features_sha256,
            "scores_float32le_sha256": hashlib.sha256(
                target_artifacts[f"{prefix}/scores.f32le"]
            ).hexdigest(),
            "probabilities_float64le_sha256": hashlib.sha256(
                target_artifacts[f"{prefix}/probabilities.f64le"]
            ).hexdigest(),
            "predicted_key_hex": predicted_key.hex(),
            "predicted_key_sha256": hashlib.sha256(predicted_key).hexdigest(),
            "predicted_key_passes_exact_public_verification": (
                exact_public_verification
            ),
            "assumption_swap_scores_negate": swap_score_gate,
            "assumption_swap_probabilities_complement": swap_probability_gate,
            "assumption_swap_probability_max_abs_residual": (swap_probability_residual),
            "live_target_state_bytes": (
                len(snapshot.state_bytes)
                + snapshot.reader_features.astype("<f4", copy=False).nbytes
                + scores.astype("<f4", copy=False).nbytes
            ),
            "retained_target_trace_fields": 0,
            "artifacts": _artifact_inventory(target_artifacts),
        }
        target_freeze = {
            **target_freeze_unsigned,
            "prediction_freeze_sha256": canonical_sha256(target_freeze_unsigned),
        }
        target_freeze_path = f"{prefix}/prediction_freeze.json"
        target_freeze_bytes = canonical_json_bytes(target_freeze)
        target_artifacts[target_freeze_path] = target_freeze_bytes
        prediction_freeze_artifacts.update(target_artifacts)
        sealed_rows.append(
            {
                "broker": broker,
                "publication": publication,
                "public": public,
                "snapshot": snapshot,
                "scores": scores,
                "probabilities": probabilities,
                "shuffled_probabilities": shuffled_probabilities,
                "predicted_key": predicted_key,
                "exact_public_verification": exact_public_verification,
                "freeze": target_freeze,
                "freeze_sha256": hashlib.sha256(target_freeze_bytes).hexdigest(),
            }
        )
    control_rows: list[dict[str, object]] = []
    if control_gate_open and config.controls.transforms:
        anchor = sealed_rows[0]
        anchor_public = anchor["public"]
        if not isinstance(anchor_public, PublicTargetView):
            raise AssertionError("sealed anchor public view differs")
        anchor_id = str(anchor["publication"]["target_id"])
        for transform in config.controls.transforms:
            control_public = _public_control(anchor_public, transform)
            control_id = f"{anchor_id}-control-{transform}"
            prefix = f"controls/{control_id}"
            control_artifacts = {
                f"{prefix}/public_view.json": canonical_json_bytes(
                    control_public.describe()
                )
            }
            prediction_freeze_artifacts.update(control_artifacts)
            sweep_attempts += 1
            try:
                control_snapshot = _probe_public(
                    target_id=control_id,
                    public=control_public,
                    template=template,
                    semantic_map=semantic_map,
                    semantic_map_sha256=config.source.semantic_map_sha256,
                    native_executable=native_executable,
                    state_plan=config.state_plan,
                    probe=config.probe,
                    maximum_state_bytes=config.maximum_state_bytes,
                    expected_variable_count=(config.source.expected_variable_count),
                    expected_public_clause_count=(
                        config.source.expected_public_clause_count
                    ),
                    working_directory=workspace,
                )
            except Full256ProbeCoreError as exc:
                if "reached SAT/UNSAT before the frozen horizon" not in str(exc):
                    raise
                control_rows.append(
                    {
                        "transform": transform,
                        "target_id": control_id,
                        "status": "relation-resolved-before-frozen-horizon",
                        "reason": (
                            "paired branch reached SAT/UNSAT before the frozen horizon"
                        ),
                        "public_view_sha256": control_public.digest(),
                        "artifacts": _artifact_inventory(control_artifacts),
                    }
                )
                continue
            resource_rows.append(control_snapshot.resources)
            control_scores, control_probabilities = _reader_outputs(
                reader, control_snapshot.reader_features
            )
            control_artifacts.update(
                {
                    f"{prefix}/causal_state.bin": control_snapshot.state_bytes,
                    f"{prefix}/reader_features.f32le": (
                        control_snapshot.reader_features.astype(
                            "<f4", copy=False
                        ).tobytes(order="C")
                    ),
                    f"{prefix}/scores.f32le": control_scores.astype(
                        "<f4", copy=False
                    ).tobytes(order="C"),
                    f"{prefix}/probabilities.f64le": (
                        control_probabilities.astype("<f8", copy=False).tobytes(
                            order="C"
                        )
                    ),
                }
            )
            prediction_freeze_artifacts.update(control_artifacts)
            control_rows.append(
                {
                    "transform": transform,
                    "target_id": control_id,
                    "status": "prediction-frozen",
                    "public_view_sha256": control_public.digest(),
                    "state_sha256": control_snapshot.state_sha256,
                    "reader_features_sha256": (control_snapshot.reader_features_sha256),
                    "probabilities": control_probabilities,
                    "artifacts": _artifact_inventory(control_artifacts),
                }
            )

    prediction_set_rows = [
        {
            "target_id": row["publication"]["target_id"],
            "publication_sha256": row["publication"]["publication_sha256"],
            "prediction_freeze_sha256": row["freeze"]["prediction_freeze_sha256"],
            "predicted_key_sha256": row["freeze"]["predicted_key_sha256"],
        }
        for row in sealed_rows
    ]
    prediction_set_unsigned = {
        "schema": "o1-256-sealed-causal-prediction-set-v1",
        "phase": "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL",
        "reader_freeze_sha256": reader_freeze_document["reader_freeze_sha256"],
        "sealed_targets": prediction_set_rows,
        "target_controls_requested": list(config.controls.transforms),
        "target_controls_gate_open": control_gate_open,
        "target_control_statuses": [
            {
                key: value
                for key, value in row.items()
                if key not in {"probabilities", "artifacts"}
            }
            for row in control_rows
        ],
        "artifacts": _artifact_inventory(prediction_freeze_artifacts),
    }
    prediction_set_document = {
        **prediction_set_unsigned,
        "prediction_set_sha256": canonical_sha256(prediction_set_unsigned),
    }
    prediction_freeze_artifacts["prediction_set_freeze.json"] = canonical_json_bytes(
        prediction_set_document
    )
    on_predictions_frozen(
        prediction_freeze_artifacts,
        prediction_set_document,
    )
    predictions_frozen_at = time.monotonic()

    reveal_started_at = time.monotonic()
    receipts: list[dict[str, object]] = []
    reveals: list[dict[str, object]] = []
    primary_probabilities: list[np.ndarray] = []
    shuffled_probabilities: list[np.ndarray] = []
    revealed_labels: list[np.ndarray] = []
    per_target_evaluations: list[dict[str, object]] = []
    exact_keys = 0
    decoy_ranks: list[int] = []
    byte_value_ranks_all: list[int] = []
    word16_value_ranks_all: list[int] = []
    final_artifacts: dict[str, bytes] = {}

    for index, row in enumerate(sealed_rows):
        broker = row["broker"]
        publication = row["publication"]
        if not isinstance(broker, Full256TargetBroker):
            raise AssertionError("sealed broker differs")
        receipt = make_freeze_receipt(
            publication,
            frozen_artifact_sha256=str(row["freeze_sha256"]),
        )
        reveal = broker.reveal(receipt)
        checked_reveal = verify_reveal(reveal)
        key = bytes.fromhex(str(checked_reveal["commitment_preimage"]["key_hex"]))
        labels = _labels_from_key(key)
        probabilities = np.asarray(row["probabilities"], dtype=np.float64)
        shuffled = np.asarray(row["shuffled_probabilities"], dtype=np.float64)
        predicted_key = row["predicted_key"]
        if not isinstance(predicted_key, bytes):
            raise AssertionError("sealed predicted key differs")
        exact = predicted_key == key
        exact_keys += int(exact)
        primary_metric = orientation_metrics(
            probabilities[None, :], labels[None, :]
        ).describe()
        shuffled_metric = orientation_metrics(
            shuffled[None, :], labels[None, :]
        ).describe()
        decoy = _stream_decoy_rank(
            probabilities,
            labels,
            decoy_count=config.reader.decoy_count,
            seed=(config.reader.decoy_seed + index) % (1 << 63),
        )
        decoy_ranks.append(int(decoy["rank_one_based"]))
        byte_truth = np.frombuffer(key, dtype=np.uint8)
        byte_prediction = np.frombuffer(predicted_key, dtype=np.uint8)
        word_truth = np.frombuffer(key, dtype="<u2")
        word_prediction = np.frombuffer(predicted_key, dtype="<u2")
        byte_value_ranks = _factorized_group_value_ranks(
            probabilities,
            labels,
            width=8,
        )
        word16_value_ranks = _factorized_group_value_ranks(
            probabilities,
            labels,
            width=16,
        )
        byte_value_ranks_all.extend(
            int(rank_row["rank_one_based"]) for rank_row in byte_value_ranks["rows"]
        )
        word16_value_ranks_all.extend(
            int(rank_row["rank_one_based"]) for rank_row in word16_value_ranks["rows"]
        )
        target_evaluation = {
            "target_id": publication["target_id"],
            "primary": primary_metric,
            "shuffled_key_control": shuffled_metric,
            "exact_key_recovered": exact,
            "predicted_key_passes_exact_public_verification": row[
                "exact_public_verification"
            ],
            "correct_bytes": int(np.count_nonzero(byte_truth == byte_prediction)),
            "correct_16bit_blocks": int(
                np.count_nonzero(word_truth == word_prediction)
            ),
            "factorized_byte_value_ranks": byte_value_ranks,
            "factorized_16bit_value_ranks": word16_value_ranks,
            "million_decoy_rank": decoy,
            "reveal_sha256": checked_reveal["reveal_sha256"],
        }
        primary_probabilities.append(probabilities)
        shuffled_probabilities.append(shuffled)
        revealed_labels.append(labels)
        per_target_evaluations.append(target_evaluation)
        receipts.append(receipt)
        reveals.append(checked_reveal)
        prefix = f"sealed/{publication['target_id']}"
        final_artifacts[f"{prefix}/freeze_receipt.json"] = canonical_json_bytes(receipt)
        final_artifacts[f"{prefix}/reveal.json"] = canonical_json_bytes(checked_reveal)
        final_artifacts[f"{prefix}/evaluation.json"] = canonical_json_bytes(
            target_evaluation
        )

    labels_matrix = np.stack(revealed_labels)
    primary_matrix = np.stack(primary_probabilities)
    shuffled_matrix = np.stack(shuffled_probabilities)
    primary_aggregate = orientation_metrics(primary_matrix, labels_matrix).describe()
    shuffled_aggregate = orientation_metrics(shuffled_matrix, labels_matrix).describe()
    control_evaluations: list[dict[str, object]] = []
    if control_rows:
        anchor_labels = labels_matrix[0]
        for row in control_rows:
            if row["status"] != "prediction-frozen":
                control_evaluations.append(
                    {
                        key: value
                        for key, value in row.items()
                        if key not in {"probabilities", "artifacts"}
                    }
                )
                continue
            probabilities = np.asarray(row["probabilities"], dtype=np.float64)
            control_evaluations.append(
                {
                    "transform": row["transform"],
                    "target_id": row["target_id"],
                    "status": "evaluated-against-anchor-key",
                    "metrics": orientation_metrics(
                        probabilities[None, :], anchor_labels[None, :]
                    ).describe(),
                    "state_sha256": row["state_sha256"],
                    "reader_features_sha256": row["reader_features_sha256"],
                }
            )

    sealed_evaluation = {
        "schema": EVALUATION_SCHEMA,
        "uniform_random_baseline_nll_bits_per_key": 256.0,
        "primary": primary_aggregate,
        "shuffled_key_control": shuffled_aggregate,
        "per_target": per_target_evaluations,
        "target_controls": control_evaluations,
        "factorized_byte_value_rank_aggregate": _aggregate_group_ranks(
            byte_value_ranks_all,
            width=8,
        ),
        "factorized_16bit_value_rank_aggregate": _aggregate_group_ranks(
            word16_value_ranks_all,
            width=16,
        ),
        "exact_keys": exact_keys,
        "minimum_million_decoy_rank": min(decoy_ranks),
        "maximum_million_decoy_rank": max(decoy_ranks),
        "full_width": True,
        "target_internal_trace_inputs": 0,
    }
    sealed_evaluation["evaluation_sha256"] = canonical_sha256(sealed_evaluation)
    final_artifacts["sealed_evaluation.json"] = canonical_json_bytes(sealed_evaluation)
    final_artifacts["freeze_receipts.json"] = canonical_json_bytes(receipts)
    final_artifacts["sealed_reveals.json"] = canonical_json_bytes(reveals)

    final_source_hashes = {
        "manifest": sha256_file(source_manifest),
        "template": sha256_file(template),
        "semantic_map": sha256_file(semantic_map),
    }
    children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
    process_child_cpu_seconds = max(
        0.0,
        (children_finished.ru_utime + children_finished.ru_stime)
        - (children_started.ru_utime + children_started.ru_stime),
    )
    parent_cpu_seconds = time.process_time() - parent_cpu_started
    native_cpu_seconds = math.fsum(
        float(row["native_cpu_seconds"]) for row in resource_rows
    )
    budgeted_cpu_seconds = parent_cpu_seconds + max(
        native_cpu_seconds, process_child_cpu_seconds
    )
    wall_seconds = time.monotonic() - wall_started
    process_peak_rss_bytes = _peak_rss_bytes()
    native_peak_rss_bytes = max(
        (int(row["native_peak_rss_bytes"]) for row in resource_rows),
        default=0,
    )
    conservative_core_peak = max(
        (
            int(row["conservative_process_group_peak_rss_bytes"])
            for row in resource_rows
        ),
        default=process_peak_rss_bytes,
    )
    conservative_process_group_peak = max(
        conservative_core_peak,
        process_peak_rss_bytes + 2 * native_peak_rss_bytes,
    )
    branches_per_sweep = 2 * KEY_BITS + 2 * config.probe.sentinel_reruns_per_sweep
    native_solver_branches = sweep_attempts * branches_per_sweep
    artifact_names = (
        list(reader_freeze_artifacts)
        + list(prediction_freeze_artifacts)
        + list(final_artifacts)
        + ["full256_multikey_calibration.json"]
    )
    if len(artifact_names) != len(set(artifact_names)):
        raise Full256MultiKeyCalibrationError(
            "reader, prediction, and final artifact paths overlap"
        )
    persistent_artifact_bytes_without_result_report = sum(
        len(payload)
        for group in (
            reader_freeze_artifacts,
            prediction_freeze_artifacts,
            final_artifacts,
        )
        for payload in group.values()
    )
    resources = {
        "parent_cpu_seconds": parent_cpu_seconds,
        "process_child_cpu_seconds": process_child_cpu_seconds,
        "native_cpu_seconds": native_cpu_seconds,
        "budgeted_cpu_seconds": budgeted_cpu_seconds,
        "wall_seconds": wall_seconds,
        "process_peak_rss_bytes": process_peak_rss_bytes,
        "native_peak_rss_bytes": native_peak_rss_bytes,
        "conservative_process_group_peak_rss_bytes": (conservative_process_group_peak),
        "peak_rss_bytes": conservative_process_group_peak,
        "rss_accounting": (
            "maximum of sequential probe-core conservative peaks and current "
            "Python peak plus one native parent and child"
        ),
        "sweep_attempts": sweep_attempts,
        "native_solver_branches": native_solver_branches,
        "native_solver_branches_accounting": (
            "conservative billed upper bound; early-resolved controls are charged "
            "one complete 512-branch sweep"
        ),
        "fresh_random_targets": config.corpus.sealed_targets,
        "fresh_target_entropy_calls": fresh_target_entropy_calls,
        "target_controls_executed": sum(
            row["status"] == "prediction-frozen" for row in control_rows
        ),
        "target_controls_resolved_early": sum(
            row["status"] == "relation-resolved-before-frozen-horizon"
            for row in control_rows
        ),
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "persistent_artifact_bytes_without_result_report": (
            persistent_artifact_bytes_without_result_report
        ),
        "persistent_artifact_bytes": 0,
    }
    resource_gates = {
        "cpu_under_budget": budgeted_cpu_seconds <= config.budgets.maximum_cpu_seconds,
        "wall_under_budget": wall_seconds <= config.budgets.maximum_wall_seconds,
        "resident_memory_under_budget": conservative_process_group_peak
        <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
        "native_branches_under_budget": native_solver_branches
        <= config.budgets.maximum_native_solver_branches,
        "fresh_targets_under_budget": config.corpus.sealed_targets
        <= config.budgets.maximum_fresh_random_targets,
        "zero_sibling_reads": 0 <= config.budgets.maximum_sibling_reads,
        "zero_sibling_writes": 0 <= config.budgets.maximum_sibling_writes,
        "zero_mps_calls": 0 <= config.budgets.maximum_mps_calls,
        "zero_gpu_calls": 0 <= config.budgets.maximum_gpu_calls,
        "persistent_artifacts_under_budget": True,
    }
    if not all(resource_gates.values()):
        failed = sorted(name for name, passed in resource_gates.items() if not passed)
        raise Full256MultiKeyCalibrationError(
            "multi-key resource budget exceeded: " + ", ".join(failed)
        )

    unique_public_views = len(
        {str(row["public_view_sha256"]) for row in known_index}
    ) == len(known_index)
    unique_known_keys = len({str(row["key_sha256"]) for row in known_index}) == len(
        known_index
    )
    swap_gates = all(
        row["freeze"]["assumption_swap_scores_negate"]
        and row["freeze"]["assumption_swap_probabilities_complement"]
        for row in sealed_rows
    )
    controls_complete = not control_gate_open or len(control_rows) == len(
        config.controls.transforms
    )
    gates = {
        "source_capsule_unchanged": final_source_hashes == initial_source_hashes,
        "known_public_views_unique": unique_public_views,
        "known_keys_unique": unique_known_keys,
        "build_calibration_disjoint": not (
            {row["key_sha256"] for row in known_index if row["split"] == "BUILD"}
            & {
                row["key_sha256"]
                for row in known_index
                if row["split"] == "CALIBRATION"
            }
        ),
        "reader_frozen_before_fresh_target_entropy": (
            fresh_target_created_at is not None
            and reader_frozen_at < fresh_target_created_at
        ),
        "persisted_reader_reloaded_for_sealed_inference": (frozen_reader_reload_exact),
        "exactly_one_entropy_call_per_sealed_target": (
            fresh_target_entropy_calls == config.corpus.sealed_targets
        ),
        "all_predictions_frozen_before_any_reveal": (
            predictions_frozen_at < reveal_started_at
        ),
        "all_sealed_commitments_open": len(reveals) == config.corpus.sealed_targets,
        "all_sealed_public_outputs_recompute": all(
            verify_reveal(reveal)["reveal_sha256"] == reveal["reveal_sha256"]
            for reveal in reveals
        ),
        "sealed_assumption_swap_complements": swap_gates,
        "target_controls_complete_or_not_triggered": controls_complete,
        "live_target_state_exactly_bounded": all(
            row["freeze"]["live_target_state_bytes"]
            == config.maximum_live_target_state_bytes
            for row in sealed_rows
        ),
        "uniform_fallback_present": any(
            candidate["logit_scale"] == 0.0
            for candidate in reader.describe()["candidate_validation"]
        ),
        "zero_target_trace_fields": True,
        **resource_gates,
    }
    gates["success_gate_passed"] = all(gates.values())
    unsigned_report = {
        "schema": RESULT_SCHEMA,
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "unknown_target_key_bits": 256,
            "public_inputs": ["counter", "nonce", "512-bit block output"],
            "target_internal_trace_inputs": 0,
            "key_unit_clauses": 0,
            "paired_assumption_branches_per_sweep": 512,
        },
        "source": {
            "capsule": config.source.capsule,
            "hashes": initial_source_hashes,
            "template_verification": template_verification,
            "native_build": native_build.describe(),
        },
        "corpus": {
            "build_targets": config.corpus.build_targets,
            "calibration_targets": config.corpus.calibration_targets,
            "sealed_targets": config.corpus.sealed_targets,
            "known_index_sha256": known_document["known_index_sha256"],
            "fresh_entropy_source_id": sealed_entropy_source_id,
        },
        "reader": reader.describe(),
        "shuffled_key_reader": shuffled_reader.describe(),
        "build_evaluation": build_evaluation,
        "calibration_evaluation": calibration_evaluation,
        "shuffled_calibration_evaluation": (shuffled_calibration_evaluation),
        "reader_freeze": reader_freeze_document,
        "prediction_set_freeze": prediction_set_document,
        "state_contract": {
            "causal_state_bytes": config.state_plan.serialized_state_bytes,
            "bounded_reader_feature_bank_bytes": KEY_BITS * READER_FEATURES * 4,
            "bounded_reader_feature_bank_shape": [KEY_BITS, READER_FEATURES],
            "bounded_reader_feature_bank_is_live_state": True,
            "logit_state_bytes": KEY_BITS * 4,
            "live_target_state_bytes": (config.maximum_live_target_state_bytes),
            "primary_reader_static_model_bytes": len(reader_binary),
            "shuffled_control_reader_static_model_bytes": len(shuffled_reader_binary),
            "stream_length_dependent": False,
            "reader_parameters_are_static_model_bytes": True,
            "retained_probe_transcripts": 0,
            "retained_candidate_keys": 0,
        },
        "sealed_evaluation": sealed_evaluation,
        "resources": resources,
        "gates": gates,
        "claim_boundary": {
            "mechanism_and_lifecycle_validated": gates["success_gate_passed"],
            "sealed_entropy_reduction_observed": (
                float(primary_aggregate["compression_bits_per_key"]) > 0.0
            ),
            "sealed_beats_shuffled_key_control": (
                float(primary_aggregate["nll_bits_per_key"])
                < float(shuffled_aggregate["nll_bits_per_key"])
            ),
            "full_key_recovery_observed": exact_keys > 0,
            "state_of_the_art_claimed": False,
        },
    }
    report: dict[str, object] = {}
    report_payload = b""
    for _ in range(16):
        gates["success_gate_passed"] = all(
            passed for name, passed in gates.items() if name != "success_gate_passed"
        )
        unsigned_report["claim_boundary"]["mechanism_and_lifecycle_validated"] = gates[
            "success_gate_passed"
        ]
        report = {
            **unsigned_report,
            "result_sha256": canonical_sha256(unsigned_report),
        }
        report_payload = canonical_json_bytes(report)
        persistent_artifact_bytes = (
            persistent_artifact_bytes_without_result_report + len(report_payload)
        )
        persistent_gate = (
            persistent_artifact_bytes
            <= config.budgets.maximum_persistent_artifact_bytes
        )
        if (
            resources["persistent_artifact_bytes"] == persistent_artifact_bytes
            and resource_gates["persistent_artifacts_under_budget"] == persistent_gate
            and gates["persistent_artifacts_under_budget"] == persistent_gate
        ):
            break
        resources["persistent_artifact_bytes"] = persistent_artifact_bytes
        resource_gates["persistent_artifacts_under_budget"] = persistent_gate
        gates["persistent_artifacts_under_budget"] = persistent_gate
    else:
        raise Full256MultiKeyCalibrationError(
            "persistent artifact accounting did not reach a fixed point"
        )
    if not all(resource_gates.values()):
        failed = sorted(name for name, passed in resource_gates.items() if not passed)
        raise Full256MultiKeyCalibrationError(
            "multi-key resource budget exceeded: " + ", ".join(failed)
        )
    final_artifacts["full256_multikey_calibration.json"] = report_payload
    if (
        sum(
            len(payload)
            for group in (
                reader_freeze_artifacts,
                prediction_freeze_artifacts,
                final_artifacts,
            )
            for payload in group.values()
        )
        != resources["persistent_artifact_bytes"]
    ):
        raise Full256MultiKeyCalibrationError(
            "persistent artifact byte accounting differs after serialization"
        )
    return Full256MultiKeyCalibrationResult(
        report=report,
        final_artifacts=final_artifacts,
        reader_freeze_artifacts=reader_freeze_artifacts,
        prediction_freeze_artifacts=prediction_freeze_artifacts,
    )
