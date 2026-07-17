"""O1C-0014 exact-byte frozen-reader replication on fresh full-256 keys."""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .cadical_sensor import build_native_sensor, sha256_file
from .causal_bitfield import CausalBitfieldPlan, plan_from_mapping
from .causal_orientation_reader import (
    FrozenCausalOrientationReader,
    deserialize_orientation_reader,
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
from .full256_cnf import verify_full256_template
from .full256_multikey_calibration import (
    ALLOWED_CONTROLS,
    MultiKeyFoundationSource,
    MultiKeyProbeConfig,
    _aggregate_group_ranks,
    _artifact_inventory,
    _bits_to_key,
    _factorized_group_value_ranks,
    _peak_rss_bytes,
    _probe_public,
    _public_control,
    _reader_outputs,
    _stream_decoy_rank,
)
from .full256_paired_sensor import NativeDependencyConfig, SensorBudgetConfig
from .full256_probe_core import READER_FEATURES, Full256ProbeCoreError
from .living_inverse import (
    KEY_BITS,
    PublicTargetView,
    canonical_json_bytes,
    canonical_sha256,
)
from .signed_direct_replication import (
    conditional_uniform_compression_null,
    conditional_uniform_paired_null,
)


CONFIG_SCHEMA = "o1-256-frozen-reader-replication-config-v1"
RESULT_SCHEMA = "o1-256-frozen-reader-replication-result-v1"
PROTOCOL_FREEZE_SCHEMA = "o1-256-frozen-reader-protocol-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-frozen-reader-prediction-freeze-v1"
EVALUATION_SCHEMA = "o1-256-frozen-reader-sealed-evaluation-v1"
COORDINATE_SCHEMA = "o1-256-frozen-reader-coordinate-stability-v1"
DECISION_THRESHOLD = 1.6448536269514722


class Full256FrozenReaderReplicationError(ValueError):
    """The O1C-0014 frozen-reader protocol or lifecycle differs."""


def _strict_mapping(
    value: object,
    field: str,
    expected: set[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise Full256FrozenReaderReplicationError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256FrozenReaderReplicationError(
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
        raise Full256FrozenReaderReplicationError(
            f"{field} must be finite in (0, {maximum}]"
        )
    return float(value)


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256FrozenReaderReplicationError(f"{field} must be lowercase SHA-256")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise Full256FrozenReaderReplicationError(f"{field} is required")
    return value


@dataclass(frozen=True)
class FrozenReaderSource:
    capsule: str
    manifest_sha256: str
    result: str
    result_sha256: str
    result_commitment_sha256: str
    evaluation: str
    evaluation_sha256: str
    evaluation_commitment_sha256: str
    reader_freeze: str
    reader_freeze_sha256: str
    reader_freeze_commitment_sha256: str
    primary_reader: str
    primary_reader_sha256: str
    shuffled_reader: str
    shuffled_reader_sha256: str
    expected_reader_contract: str
    expected_reader_schema: str
    expected_reader_arm: str
    expected_reader_ridge_lambda: float
    expected_reader_temperature: float
    expected_reader_logit_scale: float
    expected_reader_candidate_sha256: str
    expected_reader_feature_dimension: int
    expected_reader_horizons: tuple[int, ...]
    foundation: MultiKeyFoundationSource

    @classmethod
    def from_mapping(cls, value: object) -> "FrozenReaderSource":
        row = _strict_mapping(
            value,
            "source",
            {
                "capsule",
                "manifest_sha256",
                "result",
                "result_sha256",
                "result_commitment_sha256",
                "evaluation",
                "evaluation_sha256",
                "evaluation_commitment_sha256",
                "reader_freeze",
                "reader_freeze_sha256",
                "reader_freeze_commitment_sha256",
                "primary_reader",
                "primary_reader_sha256",
                "shuffled_reader",
                "shuffled_reader_sha256",
                "expected_reader_contract",
                "expected_reader_schema",
                "expected_reader_arm",
                "expected_reader_ridge_lambda",
                "expected_reader_temperature",
                "expected_reader_logit_scale",
                "expected_reader_candidate_sha256",
                "expected_reader_feature_dimension",
                "expected_reader_horizons",
                "foundation",
            },
        )
        horizons = row["expected_reader_horizons"]
        if (
            not isinstance(horizons, list)
            or len(horizons) != 3
            or any(
                isinstance(item, bool) or not isinstance(item, int) for item in horizons
            )
        ):
            raise Full256FrozenReaderReplicationError(
                "source.expected_reader_horizons differs"
            )
        try:
            foundation = MultiKeyFoundationSource.from_mapping(row["foundation"])
        except ValueError as exc:
            raise Full256FrozenReaderReplicationError(
                "source.foundation differs"
            ) from exc
        return cls(
            capsule=_string(row["capsule"], "source.capsule"),
            manifest_sha256=_sha(row["manifest_sha256"], "source.manifest_sha256"),
            result=_string(row["result"], "source.result"),
            result_sha256=_sha(row["result_sha256"], "source.result_sha256"),
            result_commitment_sha256=_sha(
                row["result_commitment_sha256"],
                "source.result_commitment_sha256",
            ),
            evaluation=_string(row["evaluation"], "source.evaluation"),
            evaluation_sha256=_sha(
                row["evaluation_sha256"], "source.evaluation_sha256"
            ),
            evaluation_commitment_sha256=_sha(
                row["evaluation_commitment_sha256"],
                "source.evaluation_commitment_sha256",
            ),
            reader_freeze=_string(row["reader_freeze"], "source.reader_freeze"),
            reader_freeze_sha256=_sha(
                row["reader_freeze_sha256"], "source.reader_freeze_sha256"
            ),
            reader_freeze_commitment_sha256=_sha(
                row["reader_freeze_commitment_sha256"],
                "source.reader_freeze_commitment_sha256",
            ),
            primary_reader=_string(row["primary_reader"], "source.primary_reader"),
            primary_reader_sha256=_sha(
                row["primary_reader_sha256"], "source.primary_reader_sha256"
            ),
            shuffled_reader=_string(row["shuffled_reader"], "source.shuffled_reader"),
            shuffled_reader_sha256=_sha(
                row["shuffled_reader_sha256"],
                "source.shuffled_reader_sha256",
            ),
            expected_reader_contract=_string(
                row["expected_reader_contract"],
                "source.expected_reader_contract",
            ),
            expected_reader_schema=_string(
                row["expected_reader_schema"], "source.expected_reader_schema"
            ),
            expected_reader_arm=_string(
                row["expected_reader_arm"], "source.expected_reader_arm"
            ),
            expected_reader_ridge_lambda=_positive(
                row["expected_reader_ridge_lambda"],
                "source.expected_reader_ridge_lambda",
                1_000_000.0,
            ),
            expected_reader_temperature=_positive(
                row["expected_reader_temperature"],
                "source.expected_reader_temperature",
                1_000_000.0,
            ),
            expected_reader_logit_scale=_positive(
                row["expected_reader_logit_scale"],
                "source.expected_reader_logit_scale",
                1_000_000.0,
            ),
            expected_reader_candidate_sha256=_sha(
                row["expected_reader_candidate_sha256"],
                "source.expected_reader_candidate_sha256",
            ),
            expected_reader_feature_dimension=_integer(
                row["expected_reader_feature_dimension"],
                "source.expected_reader_feature_dimension",
                1,
                READER_FEATURES,
            ),
            expected_reader_horizons=tuple(horizons),
            foundation=foundation,
        )


@dataclass(frozen=True)
class ReplicationCorpusConfig:
    sealed_targets: int

    @classmethod
    def from_mapping(cls, value: object) -> "ReplicationCorpusConfig":
        row = _strict_mapping(value, "corpus", {"sealed_targets"})
        return cls(
            sealed_targets=_integer(
                row["sealed_targets"], "corpus.sealed_targets", 1, 64
            )
        )


@dataclass(frozen=True)
class ReplicationReaderConfig:
    decoy_count: int
    decoy_seed: int

    @classmethod
    def from_mapping(cls, value: object) -> "ReplicationReaderConfig":
        row = _strict_mapping(value, "reader", {"decoy_count", "decoy_seed"})
        return cls(
            decoy_count=_integer(
                row["decoy_count"], "reader.decoy_count", 1, 10_000_000
            ),
            decoy_seed=_integer(
                row["decoy_seed"], "reader.decoy_seed", 0, (1 << 63) - 1
            ),
        )


@dataclass(frozen=True)
class ReplicationControlConfig:
    transforms: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: object) -> "ReplicationControlConfig":
        row = _strict_mapping(value, "target_controls", {"transforms"})
        transforms = row["transforms"]
        if (
            not isinstance(transforms, list)
            or any(
                not isinstance(item, str) or item not in ALLOWED_CONTROLS
                for item in transforms
            )
            or len(set(transforms)) != len(transforms)
        ):
            raise Full256FrozenReaderReplicationError(
                "target control transforms differ"
            )
        return cls(transforms=tuple(transforms))


@dataclass(frozen=True)
class ReplicationDecisionConfig:
    directional_minimum_positive_targets: int
    strong_minimum_positive_targets: int
    strong_z_threshold: float
    strong_requires_positive_leave_one_out_minimum: bool

    @classmethod
    def from_mapping(cls, value: object) -> "ReplicationDecisionConfig":
        row = _strict_mapping(
            value,
            "decision",
            {
                "directional_minimum_positive_targets",
                "strong_minimum_positive_targets",
                "strong_z_threshold",
                "strong_requires_positive_leave_one_out_minimum",
            },
        )
        require_loo = row["strong_requires_positive_leave_one_out_minimum"]
        if not isinstance(require_loo, bool):
            raise Full256FrozenReaderReplicationError(
                "decision leave-one-out requirement must be boolean"
            )
        return cls(
            directional_minimum_positive_targets=_integer(
                row["directional_minimum_positive_targets"],
                "decision.directional_minimum_positive_targets",
                1,
                64,
            ),
            strong_minimum_positive_targets=_integer(
                row["strong_minimum_positive_targets"],
                "decision.strong_minimum_positive_targets",
                1,
                64,
            ),
            strong_z_threshold=_positive(
                row["strong_z_threshold"], "decision.strong_z_threshold", 10.0
            ),
            strong_requires_positive_leave_one_out_minimum=require_loo,
        )


@dataclass(frozen=True)
class Full256FrozenReaderReplicationConfig:
    source: FrozenReaderSource
    native: NativeDependencyConfig
    probe: MultiKeyProbeConfig
    state_plan: CausalBitfieldPlan
    corpus: ReplicationCorpusConfig
    reader: ReplicationReaderConfig
    controls: ReplicationControlConfig
    decision: ReplicationDecisionConfig
    budgets: SensorBudgetConfig
    maximum_state_bytes: int
    maximum_live_target_state_bytes: int


def load_full256_frozen_reader_replication_config(
    path: str | Path,
) -> tuple[dict[str, object], Full256FrozenReaderReplicationConfig]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Full256FrozenReaderReplicationError(
            "could not load frozen-reader replication config"
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
            "decision",
            "maximum_state_bytes",
            "maximum_live_target_state_bytes",
        },
    )
    if row["schema"] != CONFIG_SCHEMA:
        raise Full256FrozenReaderReplicationError("frozen-reader config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        _string(row[field], f"config.{field}")
    if row["attempt_id"] != "O1C-0014" or row["claim_level"] != "VALIDATION":
        raise Full256FrozenReaderReplicationError(
            "frozen-reader attempt identity differs"
        )
    control_descriptions = row["controls"]
    if (
        not isinstance(control_descriptions, list)
        or not control_descriptions
        or any(not isinstance(item, str) or not item for item in control_descriptions)
    ):
        raise Full256FrozenReaderReplicationError("config.controls differs")
    if not isinstance(row["state_plan"], Mapping):
        raise Full256FrozenReaderReplicationError("config.state_plan differs")
    try:
        config = Full256FrozenReaderReplicationConfig(
            source=FrozenReaderSource.from_mapping(row["source"]),
            native=NativeDependencyConfig.from_mapping(row["native"]),
            probe=MultiKeyProbeConfig.from_mapping(row["probe"]),
            state_plan=plan_from_mapping(row["state_plan"]),
            corpus=ReplicationCorpusConfig.from_mapping(row["corpus"]),
            reader=ReplicationReaderConfig.from_mapping(row["reader"]),
            controls=ReplicationControlConfig.from_mapping(row["target_controls"]),
            decision=ReplicationDecisionConfig.from_mapping(row["decision"]),
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
    except Full256FrozenReaderReplicationError:
        raise
    except ValueError as exc:
        raise Full256FrozenReaderReplicationError(
            "frozen-reader nested config differs"
        ) from exc
    if config.corpus.sealed_targets != 8:
        raise Full256FrozenReaderReplicationError(
            "O1C-0014 requires exactly eight sealed targets"
        )
    if config.controls.transforms != ALLOWED_CONTROLS:
        raise Full256FrozenReaderReplicationError(
            "O1C-0014 requires its exact three target controls"
        )
    if (
        config.decision.directional_minimum_positive_targets != 5
        or config.decision.strong_minimum_positive_targets != 7
        or config.decision.strong_z_threshold != DECISION_THRESHOLD
        or not config.decision.strong_requires_positive_leave_one_out_minimum
    ):
        raise Full256FrozenReaderReplicationError("O1C-0014 decision thresholds differ")
    if config.state_plan.serialized_state_bytes > config.maximum_state_bytes:
        raise Full256FrozenReaderReplicationError(
            "causal state exceeds maximum_state_bytes"
        )
    expected_live = (
        config.state_plan.serialized_state_bytes
        + KEY_BITS * READER_FEATURES * 4
        + KEY_BITS * 4
    )
    if config.maximum_live_target_state_bytes != expected_live:
        raise Full256FrozenReaderReplicationError(
            "live target state must equal causal state, bounded feature bank, and logits"
        )
    planned_sweeps = config.corpus.sealed_targets + len(config.controls.transforms)
    planned_branches = planned_sweeps * (
        2 * KEY_BITS + 2 * config.probe.sentinel_reruns_per_sweep
    )
    if (
        planned_sweeps != 11
        or planned_branches != 5_632
        or config.budgets.maximum_native_solver_branches != planned_branches
    ):
        raise Full256FrozenReaderReplicationError(
            "declared frozen-reader branch budget differs"
        )
    if config.budgets.maximum_fresh_random_targets != config.corpus.sealed_targets:
        raise Full256FrozenReaderReplicationError(
            "fresh-target budget must equal eight"
        )
    return dict(row), config


FreezeCallback = Callable[[Mapping[str, bytes], Mapping[str, object]], None]


@dataclass(frozen=True)
class _SourceBundle:
    reader_capsule: Path
    reader_manifest: Path
    result: Path
    evaluation: Path
    reader_freeze: Path
    primary_reader: Path
    shuffled_reader: Path
    foundation_capsule: Path
    foundation_manifest: Path
    template: Path
    semantic_map: Path

    def hashes(self) -> dict[str, str]:
        return {
            "reader_manifest": sha256_file(self.reader_manifest),
            "result": sha256_file(self.result),
            "evaluation": sha256_file(self.evaluation),
            "reader_freeze": sha256_file(self.reader_freeze),
            "primary_reader": sha256_file(self.primary_reader),
            "shuffled_reader": sha256_file(self.shuffled_reader),
            "foundation_manifest": sha256_file(self.foundation_manifest),
            "template": sha256_file(self.template),
            "semantic_map": sha256_file(self.semantic_map),
        }


def _resolve_capsule(root: Path, relative: str, field: str) -> Path:
    capsule = (root / relative).resolve(strict=True)
    runs_root = (root / "runs").resolve(strict=True)
    if (
        capsule.parent != runs_root
        or capsule.name.startswith(".")
        or not capsule.is_dir()
    ):
        raise Full256FrozenReaderReplicationError(
            f"{field} is outside finalized run capsules"
        )
    return capsule


def _resolve_member(capsule: Path, relative: str, field: str) -> Path:
    member = (capsule / relative).resolve(strict=True)
    if not member.is_relative_to(capsule) or not member.is_file():
        raise Full256FrozenReaderReplicationError(f"{field} escapes its source capsule")
    return member


def _source_bundle(root: Path, source: FrozenReaderSource) -> _SourceBundle:
    reader_capsule = _resolve_capsule(root, source.capsule, "reader source capsule")
    foundation_capsule = _resolve_capsule(
        root, source.foundation.capsule, "foundation source capsule"
    )
    return _SourceBundle(
        reader_capsule=reader_capsule,
        reader_manifest=_resolve_member(
            reader_capsule, "artifacts.sha256", "reader manifest"
        ),
        result=_resolve_member(reader_capsule, source.result, "reader result"),
        evaluation=_resolve_member(
            reader_capsule, source.evaluation, "reader evaluation"
        ),
        reader_freeze=_resolve_member(
            reader_capsule, source.reader_freeze, "reader freeze"
        ),
        primary_reader=_resolve_member(
            reader_capsule, source.primary_reader, "primary reader"
        ),
        shuffled_reader=_resolve_member(
            reader_capsule, source.shuffled_reader, "shuffled reader"
        ),
        foundation_capsule=foundation_capsule,
        foundation_manifest=_resolve_member(
            foundation_capsule, "artifacts.sha256", "foundation manifest"
        ),
        template=_resolve_member(
            foundation_capsule, source.foundation.template, "foundation template"
        ),
        semantic_map=_resolve_member(
            foundation_capsule,
            source.foundation.semantic_map,
            "foundation semantic map",
        ),
    )


def _expected_source_hashes(source: FrozenReaderSource) -> dict[str, str]:
    return {
        "reader_manifest": source.manifest_sha256,
        "result": source.result_sha256,
        "evaluation": source.evaluation_sha256,
        "reader_freeze": source.reader_freeze_sha256,
        "primary_reader": source.primary_reader_sha256,
        "shuffled_reader": source.shuffled_reader_sha256,
        "foundation_manifest": source.foundation.manifest_sha256,
        "template": source.foundation.template_sha256,
        "semantic_map": source.foundation.semantic_map_sha256,
    }


def _json_document(path: Path, field: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256FrozenReaderReplicationError(f"{field} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise Full256FrozenReaderReplicationError(f"{field} must be an object")
    return value


def _verify_internal_commitment(
    document: Mapping[str, object],
    field: str,
    expected: str,
) -> None:
    actual = document.get(field)
    unsigned = {key: value for key, value in document.items() if key != field}
    if actual != expected or canonical_sha256(unsigned) != expected:
        raise Full256FrozenReaderReplicationError(f"pinned source {field} differs")


def _validate_reader_description(
    reader: FrozenCausalOrientationReader,
    source: FrozenReaderSource,
) -> None:
    row = reader.describe()
    expected = {
        "schema": source.expected_reader_schema,
        "contract": source.expected_reader_contract,
        "feature_dimension": source.expected_reader_feature_dimension,
        "horizons": list(source.expected_reader_horizons),
        "selected_arm": source.expected_reader_arm,
        "selected_ridge_lambda": source.expected_reader_ridge_lambda,
        "selected_temperature": source.expected_reader_temperature,
        "selected_logit_scale": source.expected_reader_logit_scale,
        "candidate_sha256": source.expected_reader_candidate_sha256,
        "reader_sha256": source.primary_reader_sha256,
    }
    if any(row.get(key) != value for key, value in expected.items()):
        raise Full256FrozenReaderReplicationError(
            "primary frozen reader contract differs"
        )


def _labels_from_key(key: bytes) -> np.ndarray:
    if not isinstance(key, bytes) or len(key) != KEY_BITS // 8:
        raise Full256FrozenReaderReplicationError("revealed key length differs")
    return np.unpackbits(np.frombuffer(key, dtype=np.uint8), bitorder="little").astype(
        np.uint8, copy=False
    )


def _binomial_upper_tail(successes: int, trials: int) -> float:
    if not 0 <= successes <= trials:
        raise Full256FrozenReaderReplicationError("sign-test count differs")
    return float(
        sum(math.comb(trials, count) for count in range(successes, trials + 1))
        / (2**trials)
    )


def _replication_decision(
    *,
    primary_compressions: Sequence[float],
    shuffled_compressions: Sequence[float],
    conditional_null_z: float,
    paired_conditional_null_z: float,
) -> dict[str, object]:
    primary = np.asarray(tuple(primary_compressions), dtype=np.float64)
    shuffled = np.asarray(tuple(shuffled_compressions), dtype=np.float64)
    if (
        primary.shape != (8,)
        or shuffled.shape != (8,)
        or not np.all(np.isfinite(primary))
        or not np.all(np.isfinite(shuffled))
        or not math.isfinite(conditional_null_z)
        or not math.isfinite(paired_conditional_null_z)
    ):
        raise Full256FrozenReaderReplicationError(
            "replication decision requires two finite eight-target panels"
        )
    primary_mean = float(np.mean(primary))
    shuffled_mean = float(np.mean(shuffled))
    positive_targets = int(np.count_nonzero(primary > 0.0))
    leave_one_out = tuple(
        float((np.sum(primary) - primary[index]) / 7.0) for index in range(8)
    )
    leave_one_out_minimum = min(leave_one_out)
    directional_gates = {
        "aggregate_compression_positive": primary_mean > 0.0,
        "at_least_five_positive_targets": positive_targets >= 5,
        "primary_mean_exceeds_shuffled": primary_mean > shuffled_mean,
    }
    strong_gates = {
        "conditional_null_z_at_least_threshold": (
            conditional_null_z >= DECISION_THRESHOLD
        ),
        "at_least_seven_positive_targets": positive_targets >= 7,
        "leave_one_out_minimum_positive": leave_one_out_minimum > 0.0,
        "paired_conditional_null_z_at_least_threshold": (
            paired_conditional_null_z >= DECISION_THRESHOLD
        ),
    }
    directional = all(directional_gates.values())
    strong = directional and all(strong_gates.values())
    classification = (
        "STRONG_REPLICATION"
        if strong
        else "DIRECTIONAL_REPLICATION"
        if directional
        else "NOT_REPLICATED"
    )
    return {
        "schema": "o1-256-frozen-reader-replication-decision-v1",
        "classification": classification,
        "directional_replication": directional,
        "strong_replication": strong,
        "primary_mean_compression_bits": primary_mean,
        "shuffled_mean_compression_bits": shuffled_mean,
        "primary_minus_shuffled_mean_bits": primary_mean - shuffled_mean,
        "positive_target_count": positive_targets,
        "positive_target_sign_test_conservative_upper_bound": _binomial_upper_tail(
            positive_targets, 8
        ),
        "leave_one_target_out_mean_compressions": list(leave_one_out),
        "minimum_leave_one_target_out_mean_compression_bits": (leave_one_out_minimum),
        "conditional_uniform_key_z_score": float(conditional_null_z),
        "primary_minus_shuffled_conditional_z_score": float(paired_conditional_null_z),
        "strong_z_threshold": DECISION_THRESHOLD,
        "directional_gates": directional_gates,
        "strong_gates": strong_gates,
    }


def _coordinate_stability(
    primary: np.ndarray,
    shuffled: np.ndarray,
    labels: np.ndarray,
) -> dict[str, object]:
    factual = np.asarray(primary, dtype=np.float64)
    control = np.asarray(shuffled, dtype=np.float64)
    truth = np.asarray(labels, dtype=np.uint8)
    if (
        factual.shape != (8, KEY_BITS)
        or control.shape != factual.shape
        or truth.shape != factual.shape
    ):
        raise Full256FrozenReaderReplicationError(
            "coordinate stability panel shape differs"
        )
    epsilon = np.finfo(np.float64).eps
    factual_open = np.clip(factual, epsilon, 1.0 - epsilon)
    control_open = np.clip(control, epsilon, 1.0 - epsilon)
    selected = np.where(truth == 1, factual_open, 1.0 - factual_open)
    selected_control = np.where(truth == 1, control_open, 1.0 - control_open)
    compression = 1.0 + np.log2(selected)
    shuffled_compression = 1.0 + np.log2(selected_control)
    correctness = (factual >= 0.5).astype(np.uint8) == truth
    logit = np.log(factual_open) - np.log1p(-factual_open)
    signed_logit = np.where(truth == 1, logit, -logit)
    correct_counts = np.sum(correctness, axis=0).astype(int)
    rows = []
    for coordinate in range(KEY_BITS):
        rows.append(
            {
                "coordinate": coordinate,
                "correct_targets": int(correct_counts[coordinate]),
                "mean_compression_bits": float(np.mean(compression[:, coordinate])),
                "mean_primary_minus_shuffled_bits": float(
                    np.mean(
                        compression[:, coordinate] - shuffled_compression[:, coordinate]
                    )
                ),
                "mean_truth_signed_logit": float(np.mean(signed_logit[:, coordinate])),
            }
        )
    unsigned = {
        "schema": COORDINATE_SCHEMA,
        "phase": "POST_REVEAL_BREADCRUMB_ONLY",
        "target_count": 8,
        "rows": rows,
        "coordinates_correct_at_least_six_of_eight": int(
            np.count_nonzero(correct_counts >= 6)
        ),
        "coordinates_correct_at_least_seven_of_eight": int(
            np.count_nonzero(correct_counts >= 7)
        ),
        "coordinates_correct_eight_of_eight": int(
            np.count_nonzero(correct_counts == 8)
        ),
    }
    return {**unsigned, "coordinate_stability_sha256": canonical_sha256(unsigned)}


@dataclass(frozen=True)
class Full256FrozenReaderReplicationResult:
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
        decision = sealed["decision"]
        return {
            "schema": "o1-256-frozen-reader-replication-metrics-v1",
            "success_gate_passed": self.success_gate_passed,
            "unknown_target_key_bits": KEY_BITS,
            "sealed_targets": self.report["corpus"]["sealed_targets"],
            "sealed_compression_bits_per_key": sealed["primary"][
                "compression_bits_per_key"
            ],
            "sealed_correct_bits": sealed["primary"]["correct_bits"],
            "sealed_total_bits": sealed["primary"]["total_bits"],
            "sealed_exact_keys": sealed["exact_keys"],
            "positive_target_count": decision["positive_target_count"],
            "replication_classification": decision["classification"],
            "conditional_null_z_score": decision["conditional_uniform_key_z_score"],
            "paired_conditional_null_z_score": decision[
                "primary_minus_shuffled_conditional_z_score"
            ],
            "minimum_million_decoy_rank": sealed["minimum_million_decoy_rank"],
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


def run_full256_frozen_reader_replication(
    config: Full256FrozenReaderReplicationConfig,
    *,
    lab_root: str | Path,
    working_directory: str | Path,
    on_protocol_frozen: FreezeCallback,
    on_predictions_frozen: FreezeCallback,
    sealed_entropy_source: Callable[[int], bytes] = os.urandom,
    sealed_entropy_source_id: str = "os.urandom",
) -> Full256FrozenReaderReplicationResult:
    """Reload O1C-0013 exactly and attack eight new targets without fitting."""

    if not isinstance(config, Full256FrozenReaderReplicationConfig):
        raise TypeError("config must be Full256FrozenReaderReplicationConfig")
    if not callable(on_protocol_frozen) or not callable(on_predictions_frozen):
        raise TypeError("freeze callbacks must be callable")
    if not callable(sealed_entropy_source):
        raise TypeError("sealed_entropy_source must be callable")
    if not isinstance(sealed_entropy_source_id, str) or not sealed_entropy_source_id:
        raise Full256FrozenReaderReplicationError("entropy source id is required")

    fresh_target_entropy_calls = 0

    def counted_entropy(byte_count: int) -> bytes:
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
        raise Full256FrozenReaderReplicationError(
            "working directory is outside lab and temporary roots"
        )

    bundle = _source_bundle(root, config.source)
    if workspace.is_relative_to(bundle.reader_capsule) or workspace.is_relative_to(
        bundle.foundation_capsule
    ):
        raise Full256FrozenReaderReplicationError(
            "working directory cannot modify a source capsule"
        )
    initial_source_hashes = bundle.hashes()
    expected_source_hashes = _expected_source_hashes(config.source)
    if initial_source_hashes != expected_source_hashes:
        raise Full256FrozenReaderReplicationError(
            "immutable reader or foundation source hash differs"
        )

    result_document = _json_document(bundle.result, "O1C-0013 result")
    evaluation_document = _json_document(
        bundle.evaluation, "O1C-0013 sealed evaluation"
    )
    reader_freeze_document = _json_document(
        bundle.reader_freeze, "O1C-0013 reader freeze"
    )
    _verify_internal_commitment(
        result_document,
        "result_sha256",
        config.source.result_commitment_sha256,
    )
    _verify_internal_commitment(
        evaluation_document,
        "evaluation_sha256",
        config.source.evaluation_commitment_sha256,
    )
    _verify_internal_commitment(
        reader_freeze_document,
        "reader_freeze_sha256",
        config.source.reader_freeze_commitment_sha256,
    )
    if (
        result_document.get("sealed_evaluation") != evaluation_document
        or result_document.get("reader_freeze") != reader_freeze_document
        or reader_freeze_document.get("reader_sha256")
        != config.source.primary_reader_sha256
        or reader_freeze_document.get("shuffled_key_reader_sha256")
        != config.source.shuffled_reader_sha256
        or reader_freeze_document.get("fresh_target_entropy_calls") != 0
    ):
        raise Full256FrozenReaderReplicationError(
            "O1C-0013 result and reader freeze cross-links differ"
        )

    primary_binary = bundle.primary_reader.read_bytes()
    shuffled_binary = bundle.shuffled_reader.read_bytes()
    primary_reader = deserialize_orientation_reader(primary_binary)
    shuffled_reader = deserialize_orientation_reader(shuffled_binary)
    if (
        serialize_orientation_reader(primary_reader) != primary_binary
        or serialize_orientation_reader(shuffled_reader) != shuffled_binary
        or primary_reader.reader_sha256 != config.source.primary_reader_sha256
        or shuffled_reader.reader_sha256 != config.source.shuffled_reader_sha256
    ):
        raise Full256FrozenReaderReplicationError(
            "frozen reader canonical roundtrip differs"
        )
    _validate_reader_description(primary_reader, config.source)

    template_verification = verify_full256_template(
        bundle.template, bundle.semantic_map
    )
    if (
        template_verification["variable_count"]
        != config.source.foundation.expected_variable_count
        or template_verification["clause_count"]
        != config.source.foundation.expected_template_clause_count
    ):
        raise Full256FrozenReaderReplicationError(
            "foundation template dimensions differ"
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

    reader_freeze_artifacts: dict[str, bytes] = {
        "source/frozen_reader.bin": primary_binary,
        "source/shuffled_key_reader.bin": shuffled_binary,
        "source/o1c0013_reader_freeze.json": canonical_json_bytes(
            reader_freeze_document
        ),
        "source/o1c0013_result.json": canonical_json_bytes(result_document),
        "source/o1c0013_sealed_evaluation.json": canonical_json_bytes(
            evaluation_document
        ),
    }
    protocol_unsigned = {
        "schema": PROTOCOL_FREEZE_SCHEMA,
        "phase": "FROZEN_PROTOCOL_VERIFIED_BEFORE_FRESH_TARGET_ENTROPY",
        "attempt_id": "O1C-0014",
        "unknown_target_key_bits": KEY_BITS,
        "reader_source_capsule": config.source.capsule,
        "reader_source_manifest_sha256": config.source.manifest_sha256,
        "source_result_commitment_sha256": (config.source.result_commitment_sha256),
        "source_evaluation_commitment_sha256": (
            config.source.evaluation_commitment_sha256
        ),
        "reader_freeze_sha256": (config.source.reader_freeze_commitment_sha256),
        "reader_sha256": primary_reader.reader_sha256,
        "shuffled_key_reader_sha256": shuffled_reader.reader_sha256,
        "reader_roundtrip_byte_exact": True,
        "reader_refits": 0,
        "reader_hyperparameter_changes": 0,
        "sealed_targets": config.corpus.sealed_targets,
        "target_controls": list(config.controls.transforms),
        "decision": {
            "directional_minimum_positive_targets": (
                config.decision.directional_minimum_positive_targets
            ),
            "strong_minimum_positive_targets": (
                config.decision.strong_minimum_positive_targets
            ),
            "strong_z_threshold": config.decision.strong_z_threshold,
            "strong_requires_positive_leave_one_out_minimum": (
                config.decision.strong_requires_positive_leave_one_out_minimum
            ),
        },
        "fresh_target_entropy_calls": fresh_target_entropy_calls,
        "artifacts": _artifact_inventory(reader_freeze_artifacts),
    }
    protocol_document = {
        **protocol_unsigned,
        "protocol_freeze_sha256": canonical_sha256(protocol_unsigned),
    }
    reader_freeze_artifacts["source_reader_pin.json"] = canonical_json_bytes(
        protocol_document
    )
    if fresh_target_entropy_calls != 0:
        raise Full256FrozenReaderReplicationError(
            "fresh entropy was accessed before protocol freeze"
        )
    on_protocol_frozen(reader_freeze_artifacts, protocol_document)
    protocol_frozen_at = time.monotonic()

    sweep_attempts = 0
    resource_rows: list[Mapping[str, object]] = []
    sealed_rows: list[dict[str, object]] = []
    prediction_freeze_artifacts: dict[str, bytes] = {}
    first_target_created_at: float | None = None

    for index in range(config.corpus.sealed_targets):
        if first_target_created_at is None:
            first_target_created_at = time.monotonic()
        broker = Full256TargetBroker(
            block_count=1,
            entropy_source=counted_entropy,
            entropy_source_id=sealed_entropy_source_id,
            target_id=f"o1c0014-replication-{index:04d}",
        )
        publication = broker.publish()
        public = public_view_from_publication(publication)
        target_id = str(publication["target_id"])
        sweep_attempts += 1
        snapshot = _probe_public(
            target_id=target_id,
            public=public,
            template=bundle.template,
            semantic_map=bundle.semantic_map,
            semantic_map_sha256=config.source.foundation.semantic_map_sha256,
            native_executable=native_executable,
            state_plan=config.state_plan,
            probe=config.probe,
            maximum_state_bytes=config.maximum_state_bytes,
            expected_variable_count=(config.source.foundation.expected_variable_count),
            expected_public_clause_count=(
                config.source.foundation.expected_public_clause_count
            ),
            working_directory=workspace,
        )
        resource_rows.append(snapshot.resources)
        scores, probabilities = _reader_outputs(
            primary_reader, snapshot.reader_features
        )
        shuffled_scores, shuffled_probabilities = _reader_outputs(
            shuffled_reader, snapshot.reader_features
        )
        swap_scores, swap_probabilities = _reader_outputs(
            primary_reader, -snapshot.reader_features
        )
        swap_score_gate = bool(np.array_equal(swap_scores, -scores))
        swap_sum = probabilities + swap_probabilities
        swap_probability_gate = bool(
            np.array_equal(swap_sum, np.ones(KEY_BITS, dtype=np.float64))
        )
        swap_residual = float(np.max(np.abs(swap_sum - 1.0)))
        prediction = (probabilities >= 0.5).astype(np.uint8)
        predicted_key = _bits_to_key(prediction)
        predicted_key_verifies = (
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
            "protocol_freeze_sha256": protocol_document["protocol_freeze_sha256"],
            "reader_sha256": primary_reader.reader_sha256,
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
            "predicted_key_passes_exact_public_verification": (predicted_key_verifies),
            "assumption_swap_scores_negate": swap_score_gate,
            "assumption_swap_probabilities_complement": swap_probability_gate,
            "assumption_swap_probability_max_abs_residual": swap_residual,
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
                "probabilities": probabilities,
                "shuffled_probabilities": shuffled_probabilities,
                "predicted_key": predicted_key,
                "predicted_key_verifies": predicted_key_verifies,
                "freeze": target_freeze,
                "freeze_sha256": hashlib.sha256(target_freeze_bytes).hexdigest(),
            }
        )

    control_rows: list[dict[str, object]] = []
    anchor_public = sealed_rows[0]["public"]
    if not isinstance(anchor_public, PublicTargetView):
        raise AssertionError("sealed anchor public view differs")
    anchor_id = str(sealed_rows[0]["publication"]["target_id"])
    for transform in config.controls.transforms:
        control_public = _public_control(anchor_public, transform)
        control_id = f"{anchor_id}-control-{transform}"
        prefix = f"controls/{control_id}"
        control_artifacts = {
            f"{prefix}/public_view.json": canonical_json_bytes(
                control_public.describe()
            )
        }
        sweep_attempts += 1
        try:
            snapshot = _probe_public(
                target_id=control_id,
                public=control_public,
                template=bundle.template,
                semantic_map=bundle.semantic_map,
                semantic_map_sha256=config.source.foundation.semantic_map_sha256,
                native_executable=native_executable,
                state_plan=config.state_plan,
                probe=config.probe,
                maximum_state_bytes=config.maximum_state_bytes,
                expected_variable_count=(
                    config.source.foundation.expected_variable_count
                ),
                expected_public_clause_count=(
                    config.source.foundation.expected_public_clause_count
                ),
                working_directory=workspace,
            )
        except Full256ProbeCoreError as exc:
            if "reached SAT/UNSAT before the frozen horizon" not in str(exc):
                raise
            prediction_freeze_artifacts.update(control_artifacts)
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
        resource_rows.append(snapshot.resources)
        control_scores, control_probabilities = _reader_outputs(
            primary_reader, snapshot.reader_features
        )
        control_artifacts.update(
            {
                f"{prefix}/causal_state.bin": snapshot.state_bytes,
                f"{prefix}/reader_features.f32le": (
                    snapshot.reader_features.astype("<f4", copy=False).tobytes(
                        order="C"
                    )
                ),
                f"{prefix}/scores.f32le": control_scores.astype(
                    "<f4", copy=False
                ).tobytes(order="C"),
                f"{prefix}/probabilities.f64le": control_probabilities.astype(
                    "<f8", copy=False
                ).tobytes(order="C"),
            }
        )
        prediction_freeze_artifacts.update(control_artifacts)
        control_rows.append(
            {
                "transform": transform,
                "target_id": control_id,
                "status": "prediction-frozen",
                "public_view_sha256": control_public.digest(),
                "state_sha256": snapshot.state_sha256,
                "reader_features_sha256": snapshot.reader_features_sha256,
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
        "schema": "o1-256-frozen-reader-prediction-set-v1",
        "phase": "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL",
        "protocol_freeze_sha256": protocol_document["protocol_freeze_sha256"],
        "reader_freeze_sha256": config.source.reader_freeze_commitment_sha256,
        "sealed_targets": prediction_set_rows,
        "target_controls_requested": list(config.controls.transforms),
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
        if not isinstance(broker, Full256TargetBroker) or not isinstance(
            publication, Mapping
        ):
            raise AssertionError("sealed broker row differs")
        receipt = make_freeze_receipt(
            publication,
            frozen_artifact_sha256=str(row["freeze_sha256"]),
        )
        reveal = broker.reveal(receipt)
        checked_reveal = verify_reveal(reveal)
        preimage = checked_reveal["commitment_preimage"]
        if not isinstance(preimage, Mapping):
            raise AssertionError("sealed reveal preimage differs")
        key = bytes.fromhex(str(preimage["key_hex"]))
        labels = _labels_from_key(key)
        probabilities = np.asarray(row["probabilities"], dtype=np.float64)
        shuffled = np.asarray(row["shuffled_probabilities"], dtype=np.float64)
        predicted_key = row["predicted_key"]
        if not isinstance(predicted_key, bytes):
            raise AssertionError("predicted key differs")
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
            seed=config.reader.decoy_seed + index,
        )
        byte_ranks = _factorized_group_value_ranks(probabilities, labels, width=8)
        word16_ranks = _factorized_group_value_ranks(probabilities, labels, width=16)
        byte_value_ranks_all.extend(
            int(item["rank_one_based"]) for item in byte_ranks["rows"]
        )
        word16_value_ranks_all.extend(
            int(item["rank_one_based"]) for item in word16_ranks["rows"]
        )
        predicted_bits = (probabilities >= 0.5).astype(np.uint8)
        correct_bytes = sum(
            bool(
                np.array_equal(
                    predicted_bits[first : first + 8], labels[first : first + 8]
                )
            )
            for first in range(0, KEY_BITS, 8)
        )
        correct_words = sum(
            bool(
                np.array_equal(
                    predicted_bits[first : first + 16], labels[first : first + 16]
                )
            )
            for first in range(0, KEY_BITS, 16)
        )
        target_id = str(publication["target_id"])
        target_evaluation = {
            "target_id": target_id,
            "primary": primary_metric,
            "shuffled_key_control": shuffled_metric,
            "exact_key_recovered": exact,
            "predicted_key_passes_exact_public_verification": bool(
                row["predicted_key_verifies"]
            ),
            "correct_bytes": correct_bytes,
            "correct_16bit_blocks": correct_words,
            "million_decoy_rank": decoy,
            "factorized_byte_value_ranks": byte_ranks,
            "factorized_16bit_value_ranks": word16_ranks,
            "reveal_sha256": checked_reveal["reveal_sha256"],
        }
        primary_probabilities.append(probabilities)
        shuffled_probabilities.append(shuffled)
        revealed_labels.append(labels)
        per_target_evaluations.append(target_evaluation)
        decoy_ranks.append(int(decoy["rank_one_based"]))
        receipts.append(receipt)
        reveals.append(reveal)
        prefix = f"sealed/{target_id}"
        final_artifacts[f"{prefix}/freeze_receipt.json"] = canonical_json_bytes(receipt)
        final_artifacts[f"{prefix}/reveal.json"] = canonical_json_bytes(reveal)
        final_artifacts[f"{prefix}/evaluation.json"] = canonical_json_bytes(
            target_evaluation
        )

    labels_matrix = np.stack(revealed_labels)
    primary_matrix = np.stack(primary_probabilities)
    shuffled_matrix = np.stack(shuffled_probabilities)
    primary_aggregate = orientation_metrics(primary_matrix, labels_matrix).describe()
    shuffled_aggregate = orientation_metrics(shuffled_matrix, labels_matrix).describe()
    primary_compressions = tuple(
        float(row["primary"]["compression_bits_per_key"])
        for row in per_target_evaluations
    )
    shuffled_compressions = tuple(
        float(row["shuffled_key_control"]["compression_bits_per_key"])
        for row in per_target_evaluations
    )
    conditional_epsilon = np.finfo(np.float64).eps
    conditional_primary = np.clip(
        primary_matrix, conditional_epsilon, 1.0 - conditional_epsilon
    )
    conditional_shuffled = np.clip(
        shuffled_matrix, conditional_epsilon, 1.0 - conditional_epsilon
    )
    conditional_null = conditional_uniform_compression_null(
        conditional_primary, labels_matrix
    )
    paired_null = conditional_uniform_paired_null(
        conditional_primary, conditional_shuffled, labels_matrix
    )
    decision = _replication_decision(
        primary_compressions=primary_compressions,
        shuffled_compressions=shuffled_compressions,
        conditional_null_z=float(conditional_null["z_score"]),
        paired_conditional_null_z=float(paired_null["z_score"]),
    )

    control_evaluations: list[dict[str, object]] = []
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
        metrics = orientation_metrics(
            probabilities[None, :], anchor_labels[None, :]
        ).describe()
        control_evaluations.append(
            {
                "transform": row["transform"],
                "target_id": row["target_id"],
                "status": "evaluated-against-anchor-key",
                "metrics": metrics,
                "factual_minus_control_compression_bits": float(
                    per_target_evaluations[0]["primary"]["compression_bits_per_key"]
                )
                - float(metrics["compression_bits_per_key"]),
                "state_sha256": row["state_sha256"],
                "reader_features_sha256": row["reader_features_sha256"],
            }
        )

    compression_array = np.asarray(primary_compressions, dtype=np.float64)
    robustness = {
        "target_count": config.corpus.sealed_targets,
        "positive_target_count": int(np.count_nonzero(compression_array > 0.0)),
        "minimum_compression_bits": float(np.min(compression_array)),
        "median_compression_bits": float(np.median(compression_array)),
        "mean_compression_bits": float(np.mean(compression_array)),
        "maximum_compression_bits": float(np.max(compression_array)),
        "sample_standard_deviation_bits": float(np.std(compression_array, ddof=1)),
        "standard_error_bits": float(
            np.std(compression_array, ddof=1) / math.sqrt(config.corpus.sealed_targets)
        ),
        "positive_target_sign_test_conservative_upper_bound": decision[
            "positive_target_sign_test_conservative_upper_bound"
        ],
        "minimum_leave_one_target_out_mean_compression_bits": decision[
            "minimum_leave_one_target_out_mean_compression_bits"
        ],
    }
    coordinate_stability = _coordinate_stability(
        primary_matrix, shuffled_matrix, labels_matrix
    )
    controls_directionally_negative = all(
        row.get("status") == "evaluated-against-anchor-key"
        and float(row["metrics"]["compression_bits_per_key"]) < 0.0
        for row in control_evaluations
    )
    sealed_evaluation: dict[str, object] = {
        "schema": EVALUATION_SCHEMA,
        "uniform_random_baseline_nll_bits_per_key": 256.0,
        "uniform_random_baseline_total_nll_bits": float(
            config.corpus.sealed_targets * KEY_BITS
        ),
        "primary": primary_aggregate,
        "shuffled_key_control": shuffled_aggregate,
        "conditional_uniform_key_null": conditional_null,
        "primary_minus_shuffled_conditional_null": paired_null,
        "target_robustness": robustness,
        "decision": decision,
        "per_target": per_target_evaluations,
        "target_controls": control_evaluations,
        "controls_directionally_negative": controls_directionally_negative,
        "factorized_byte_value_rank_aggregate": _aggregate_group_ranks(
            byte_value_ranks_all, width=8
        ),
        "factorized_16bit_value_rank_aggregate": _aggregate_group_ranks(
            word16_value_ranks_all, width=16
        ),
        "exact_keys": exact_keys,
        "minimum_million_decoy_rank": min(decoy_ranks),
        "maximum_million_decoy_rank": max(decoy_ranks),
        "full_width": True,
        "target_internal_trace_inputs": 0,
    }
    sealed_evaluation["evaluation_sha256"] = canonical_sha256(sealed_evaluation)
    final_artifacts["sealed_evaluation.json"] = canonical_json_bytes(sealed_evaluation)
    final_artifacts["coordinate_stability.json"] = canonical_json_bytes(
        coordinate_stability
    )
    final_artifacts["freeze_receipts.json"] = canonical_json_bytes(receipts)
    final_artifacts["sealed_reveals.json"] = canonical_json_bytes(reveals)

    final_source_hashes = bundle.hashes()
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
        (int(row["native_peak_rss_bytes"]) for row in resource_rows), default=0
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
        + ["full256_frozen_reader_replication.json"]
    )
    if len(artifact_names) != len(set(artifact_names)):
        raise Full256FrozenReaderReplicationError(
            "protocol, prediction, and final artifact paths overlap"
        )
    persistent_without_report = sum(
        len(payload)
        for group in (
            reader_freeze_artifacts,
            prediction_freeze_artifacts,
            final_artifacts,
        )
        for payload in group.values()
    )
    resources: dict[str, object] = {
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
        "reader_refits": 0,
        "reader_hyperparameter_changes": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "persistent_artifact_bytes_without_result_report": persistent_without_report,
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
        raise Full256FrozenReaderReplicationError(
            "frozen-reader resource budget exceeded: " + ", ".join(failed)
        )

    swap_gates = all(
        row["freeze"]["assumption_swap_scores_negate"]
        and row["freeze"]["assumption_swap_probabilities_complement"]
        for row in sealed_rows
    )
    gates: dict[str, bool] = {
        "source_capsules_unchanged": final_source_hashes == initial_source_hashes,
        "protocol_frozen_before_fresh_target_entropy": (
            first_target_created_at is not None
            and protocol_frozen_at < first_target_created_at
        ),
        "frozen_reader_roundtrip_exact": True,
        "zero_reader_refits": True,
        "zero_reader_hyperparameter_changes": True,
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
        "sealed_public_views_unique": len(
            {str(row["publication"]["public_view_sha256"]) for row in sealed_rows}
        )
        == config.corpus.sealed_targets,
        "sealed_assumption_swap_complements": swap_gates,
        "target_controls_complete": len(control_rows)
        == len(config.controls.transforms),
        "live_target_state_exactly_bounded": all(
            row["freeze"]["live_target_state_bytes"]
            == config.maximum_live_target_state_bytes
            for row in sealed_rows
        ),
        "conditional_nulls_finite": math.isfinite(float(conditional_null["z_score"]))
        and math.isfinite(float(paired_null["z_score"])),
        "zero_target_trace_fields": True,
        **resource_gates,
    }
    gates["success_gate_passed"] = all(gates.values())
    unsigned_report: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attacker_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "feed_forward": True,
            "unknown_target_key_bits": KEY_BITS,
            "public_inputs": ["counter", "nonce", "512-bit block output"],
            "target_internal_trace_inputs": 0,
            "key_unit_clauses": 0,
            "paired_assumption_branches_per_sweep": 512,
        },
        "source": {
            "reader_capsule": config.source.capsule,
            "foundation_capsule": config.source.foundation.capsule,
            "hashes": initial_source_hashes,
            "template_verification": template_verification,
            "native_build": native_build.describe(),
        },
        "corpus": {
            "sealed_targets": config.corpus.sealed_targets,
            "fresh_entropy_source_id": sealed_entropy_source_id,
        },
        "reader": primary_reader.describe(),
        "shuffled_key_reader": shuffled_reader.describe(),
        "protocol_freeze": protocol_document,
        "prediction_set_freeze": prediction_set_document,
        "state_contract": {
            "causal_state_bytes": config.state_plan.serialized_state_bytes,
            "bounded_reader_feature_bank_bytes": KEY_BITS * READER_FEATURES * 4,
            "bounded_reader_feature_bank_shape": [KEY_BITS, READER_FEATURES],
            "bounded_reader_feature_bank_is_live_state": True,
            "logit_state_bytes": KEY_BITS * 4,
            "live_target_state_bytes": config.maximum_live_target_state_bytes,
            "primary_reader_static_model_bytes": len(primary_binary),
            "shuffled_control_reader_static_model_bytes": len(shuffled_binary),
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
            "aggregate_compression_positive": float(
                primary_aggregate["compression_bits_per_key"]
            )
            > 0.0,
            "primary_beats_shuffled": float(primary_aggregate["nll_bits_per_key"])
            < float(shuffled_aggregate["nll_bits_per_key"]),
            "positive_target_majority": int(decision["positive_target_count"]) >= 5,
            "controls_directionally_negative": controls_directionally_negative,
            "frozen_reader_signal_replicated": bool(decision["strong_replication"]),
            "replication_claimed": bool(decision["strong_replication"]),
            "directional_signal_observed": bool(decision["directional_replication"]),
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
        persistent_artifact_bytes = persistent_without_report + len(report_payload)
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
        raise Full256FrozenReaderReplicationError(
            "persistent artifact accounting did not reach a fixed point"
        )
    if not all(resource_gates.values()):
        failed = sorted(name for name, passed in resource_gates.items() if not passed)
        raise Full256FrozenReaderReplicationError(
            "frozen-reader resource budget exceeded: " + ", ".join(failed)
        )
    final_artifacts["full256_frozen_reader_replication.json"] = report_payload
    actual_persistent_bytes = sum(
        len(payload)
        for group in (
            reader_freeze_artifacts,
            prediction_freeze_artifacts,
            final_artifacts,
        )
        for payload in group.values()
    )
    if actual_persistent_bytes != resources["persistent_artifact_bytes"]:
        raise Full256FrozenReaderReplicationError(
            "persistent artifact byte accounting differs after serialization"
        )
    return Full256FrozenReaderReplicationResult(
        report=report,
        final_artifacts=final_artifacts,
        reader_freeze_artifacts=reader_freeze_artifacts,
        prediction_freeze_artifacts=prediction_freeze_artifacts,
    )


__all__ = [
    "Full256FrozenReaderReplicationConfig",
    "Full256FrozenReaderReplicationError",
    "Full256FrozenReaderReplicationResult",
    "load_full256_frozen_reader_replication_config",
    "run_full256_frozen_reader_replication",
]
