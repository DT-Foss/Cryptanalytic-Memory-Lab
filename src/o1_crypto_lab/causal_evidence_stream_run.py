"""Capsule-backed formal runner for O1C-0021 causal evidence accumulation."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import secrets
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from .causal_evidence_stream import (
    ALL_ARMS,
    LEARNING_FREEZE_SCHEMA,
    PREDICTION_FREEZE_SCHEMA,
    RESULT_SCHEMA,
    TRUTH_INDEX_SCHEMA,
    TRUTH_REVEAL_SCHEMA,
    CausalEvidenceConfig,
    build_public_evidence_episode,
    recompute_causal_evidence_scores,
    run_causal_evidence_stream,
)
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-causal-evidence-stream-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-causal-evidence-stream-cli-result-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-causal-evidence-artifact-index-v1"
POST_REVEAL_AUDIT_SCHEMA = "o1-256-causal-evidence-post-reveal-audit-v1"

_FORMAL_SLUG = "causal-evidence-stream-256-v1"
_FORMAL_MATRIX = (
    (1, 1, 1, -1, -1, -1, 1, -1),
    (1, -1, -1, 1, 1, -1, 1, -1),
    (-1, 1, -1, 1, -1, 1, -1, 1),
    (-1, -1, 1, -1, 1, 1, -1, 1),
)
_FORMAL_CONTROLS = (
    "zero_prior_baseline is the exact zero-logit no-evidence reference",
    "same_route_last keeps only the most recent accepted signed observation",
    "same_route_unit_sum removes learned confidence while preserving routing",
    "same_encoder_static_sum removes recurrent regime memory at matched routing",
    "same_encoder_current_marker_sum resets before every public marker and tests whether the current marker alone explains the signal",
    "outcome_table_public_fsm independently learns and executes the delayed public operator with its own bounded route and state as an O1-O-targetable reference rather than an O1-necessity claim",
    "shuffled_confidence receives identical BUILD work with shuffled confidence labels",
    "all_open consumes every offered public token without selective routing",
    "duplicate expansions at factors 4, 16 and 64 must not manufacture confidence",
    "independent replacement at 16x16 matched slots must compound materially",
    "complement, opaque-ID and coordinate permutations test antisymmetry and equivariance",
    "oracle_grouped_bayes is an evaluator-only ceiling and is never fed to a learned arm",
)
_ALLOWED_CLASSIFICATIONS = frozenset(
    {
        "GENERATOR_CEILING_INSUFFICIENT",
        "PUBLIC_FSM_REFERENCE_INSUFFICIENT",
        "TRUTH_PATH_LEAKAGE",
        "COMPLEMENT_OR_EQUIVARIANCE_FAILURE",
        "DUPLICATE_CONFIDENCE_INFLATION",
        "DUPLICATE_INSTABILITY",
        "NO_INDEPENDENT_COMPOUNDING",
        "ROUTING_OR_ONE_SHOT_SUFFICIENT",
        "DIRECT_SUM_SUFFICIENT",
        "STATIC_ENCODER_SUM_SUFFICIENT",
        "CURRENT_MARKER_STATIC_SUM_SUFFICIENT",
        "SHUFFLED_CONFIDENCE_OR_ALL_OPEN_CONTROL_FAILURE",
        "UNCALIBRATED_POSTERIOR",
        "NOT_EXACT_256",
        "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE",
        "EXACT_256_LEARNED_CAUSAL_ACCUMULATION",
    }
)
_INTEGRITY_FAILURE_CLASSIFICATIONS = frozenset(
    {
        "TRUTH_PATH_LEAKAGE",
        "COMPLEMENT_OR_EQUIVARIANCE_FAILURE",
        "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE",
    }
)
_SCORE_INTEGRITY_GATE_NAMES = frozenset(
    {
        "zero_prior_baseline_exact_null",
        "complement_logit_antisymmetry",
        "complement_probability_antisymmetry",
        "opaque_id_equality_equivariance",
        "coordinate_permutation_equivariance",
    }
)
_EXECUTION_INTEGRITY_GATE_NAMES = frozenset(
    {
        "complement_metadata_route_vote_integrity",
        "independent_replacement_offered_work_matched",
        "live_state_exact_declared_width_every_execution",
        "formal_live_state_is_exactly_352_bytes",
        "public_fsm_live_state_exactly_273_bytes_every_execution",
        "duplicate_full_live_state_exactly_invariant",
        "duplicate_public_fsm_live_state_exactly_invariant",
        "fresh_post_learning_evaluation_material",
    }
)
_INTEGRITY_GATE_NAMES = (
    _SCORE_INTEGRITY_GATE_NAMES | _EXECUTION_INTEGRITY_GATE_NAMES
)
_SUCCESS_CLASSIFICATION = "EXACT_256_LEARNED_CAUSAL_ACCUMULATION"
_SECRET_MATERIAL_INDEX_SCHEMA = (
    "o1-256-causal-evidence-secret-material-index-v1"
)
_LATENT_RECORD = struct.Struct("<BHQHBBBbbbf")
_REPEAT_RECORD = struct.Struct("<BBBHQ")
_REGIME_SLICE = slice(14, 18)


class CausalEvidenceRunError(ValueError):
    """A formal config, lifecycle boundary, artifact, or budget differs."""


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise CausalEvidenceRunError("value is not canonical finite JSON") from exc
    return (rendered + "\n").encode("ascii")


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CausalEvidenceRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise CausalEvidenceRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True)
class CausalEvidenceRunBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_physical_public_tokens: int
    maximum_reader_token_evaluations: int
    maximum_calibration_physical_public_tokens: int
    maximum_calibration_reader_token_evaluations: int
    maximum_temperature_grid_value_evaluations: int
    maximum_training_token_exposures: int
    maximum_public_fsm_build_outcome_lookups: int
    maximum_public_fsm_calibration_table_lookups: int
    maximum_public_fsm_evaluation_table_lookups: int
    maximum_logical_arm_updates: int
    maximum_accepted_arm_updates: int
    maximum_prediction_values: int
    maximum_live_state_bytes: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_native_solver_branches: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "CausalEvidenceRunBudgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        for field in ("maximum_cpu_seconds", "maximum_wall_seconds"):
            scalar = row[field]
            if (
                isinstance(scalar, bool)
                or not isinstance(scalar, (int, float))
                or not 0.0 < float(scalar) <= 86_400.0
            ):
                raise CausalEvidenceRunError(f"budgets.{field} differs")
        limits = {
            "maximum_resident_memory_mib": 65_536,
            "maximum_persistent_artifact_bytes": 1_000_000_000,
            "maximum_physical_public_tokens": 1_000_000_000,
            "maximum_reader_token_evaluations": 1_000_000_000,
            "maximum_calibration_physical_public_tokens": 1_000_000_000,
            "maximum_calibration_reader_token_evaluations": 1_000_000_000,
            "maximum_temperature_grid_value_evaluations": 4_000_000_000,
            "maximum_training_token_exposures": 1_000_000_000,
            "maximum_public_fsm_build_outcome_lookups": 1_000_000_000,
            "maximum_public_fsm_calibration_table_lookups": 1_000_000_000,
            "maximum_public_fsm_evaluation_table_lookups": 1_000_000_000,
            "maximum_logical_arm_updates": 4_000_000_000,
            "maximum_accepted_arm_updates": 1_000_000_000,
            "maximum_prediction_values": 1_000_000_000,
            "maximum_live_state_bytes": 1_000_000,
            "maximum_scientific_entropy_calls": 1_000_000,
            "maximum_sibling_reads": 1_000_000,
            "maximum_sibling_writes": 1_000_000,
            "maximum_native_solver_branches": 1_000_000,
            "maximum_mps_calls": 1_000_000,
            "maximum_gpu_calls": 1_000_000,
        }
        for field, maximum in limits.items():
            _integer(row[field], f"budgets.{field}", 0, maximum)
        result = cls(
            maximum_cpu_seconds=float(row["maximum_cpu_seconds"]),
            maximum_wall_seconds=float(row["maximum_wall_seconds"]),
            **{field: int(row[field]) for field in limits},
        )
        for field in (
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_native_solver_branches",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        ):
            if getattr(result, field) != 0:
                raise CausalEvidenceRunError(f"O1C-0021 requires zero {field}")
        if result.maximum_scientific_entropy_calls != 1:
            raise CausalEvidenceRunError(
                "O1C-0021 requires exactly one scientific entropy call"
            )
        return result


def _read_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalEvidenceRunError("run config is unreadable") from exc
    if not isinstance(value, dict):
        raise CausalEvidenceRunError("run config must be a mapping")
    return value


def load_causal_evidence_run_config(
    path: str | Path,
) -> tuple[dict[str, object], CausalEvidenceConfig, CausalEvidenceRunBudgets]:
    value = _read_document(Path(path))
    expected = {
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
    top = dict(_mapping(value, "config", expected))
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise CausalEvidenceRunError("run config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(top[field], str) or not top[field].strip():
            raise CausalEvidenceRunError(f"config.{field} is required")
    if top["attempt_id"] != "O1C-0021" or top["slug"] != _FORMAL_SLUG:
        raise CausalEvidenceRunError("O1C-0021 identity differs")
    try:
        claim = ClaimLevel(str(top["claim_level"]))
    except ValueError as exc:
        raise CausalEvidenceRunError("claim_level differs") from exc
    if claim is not ClaimLevel.VALIDATION:
        raise CausalEvidenceRunError("O1C-0021 claim_level must be VALIDATION")
    controls = top["controls"]
    if not isinstance(controls, list) or tuple(controls) != _FORMAL_CONTROLS:
        raise CausalEvidenceRunError("formal control inventory differs")

    experiment = CausalEvidenceConfig.from_mapping(top["experiment"])
    budgets = CausalEvidenceRunBudgets.from_mapping(top["budgets"])
    frozen = {
        "n_bits": 256,
        "regime_count": 4,
        "family_count": 8,
        "quality_reliabilities": (0.62, 0.70),
        "coefficient_magnitudes": (1, 2),
        "orientation_matrix": _FORMAL_MATRIX,
        "event_dimension": 21,
        "address_dimension": 8,
        "model_dimension": 24,
        "heads": 1,
        "head_dimension": 4,
        "holographic_slots": 2,
        "feedforward_dimension": 48,
        "phase_scale": float(np.pi),
        "core_seed": 210021,
        "build_seeds": (
            210021001,
            210021002,
            210021003,
            210021004,
            210021005,
            210021006,
            210021007,
            210021008,
        ),
        "calibration_seeds": (210021101, 210021102, 210021103, 210021104),
        "development_seeds": (210021201, 210021202),
        "evaluation_seeds": (210021301, 210021302, 210021303, 210021304),
        "independent_group_prefixes": (1, 4, 16, 64, 256),
        "repeat_factors": (1, 4, 16, 64),
        "independent_comparison_groups": 16,
        "independent_comparison_repeat_factor": 16,
        "training_steps": 480,
        "training_batch_size": 256,
        "learning_rate": 0.02,
        "temperature_grid_max": 1.5,
        "temperature_grid_steps": 301,
        "shuffled_label_seed": 310021,
        "cpu_threads": 1,
    }
    for field, expected_value in frozen.items():
        if getattr(experiment, field) != expected_value:
            raise CausalEvidenceRunError(f"formal experiment.{field} differs")
    if tuple(
        len(getattr(experiment, field))
        for field in (
            "build_seeds",
            "calibration_seeds",
            "development_seeds",
            "evaluation_seeds",
        )
    ) != (8, 4, 2, 4):
        raise CausalEvidenceRunError("formal BUILD/CAL/DEV/EVAL split sizes differ")
    if experiment.live_state_bytes != 352:
        raise CausalEvidenceRunError("formal live state must be exactly 352 bytes")
    frozen_caps = {
        "maximum_cpu_seconds": 300.0,
        "maximum_wall_seconds": 300.0,
        "maximum_resident_memory_mib": 768,
        "maximum_persistent_artifact_bytes": 16_777_216,
    }
    for field, expected_value in frozen_caps.items():
        if getattr(budgets, field) != expected_value:
            raise CausalEvidenceRunError(f"formal budgets.{field} differs")
    derived = {
        "maximum_physical_public_tokens": experiment.planned_public_tokens,
        "maximum_reader_token_evaluations": (
            experiment.planned_reader_token_evaluations
        ),
        "maximum_calibration_physical_public_tokens": (
            experiment.planned_calibration_public_tokens
        ),
        "maximum_calibration_reader_token_evaluations": (
            experiment.planned_calibration_reader_token_evaluations
        ),
        "maximum_temperature_grid_value_evaluations": (
            (len(ALL_ARMS) - 2)
            * experiment.temperature_grid_steps
            * 2
            * len(experiment.calibration_seeds)
            * len(experiment.independent_group_prefixes)
            * experiment.n_bits
        ),
        "maximum_training_token_exposures": (
            experiment.planned_training_token_exposures
        ),
        "maximum_public_fsm_build_outcome_lookups": (
            experiment.planned_public_fsm_build_outcome_lookups
        ),
        "maximum_public_fsm_calibration_table_lookups": (
            experiment.planned_public_fsm_calibration_table_lookups
        ),
        "maximum_public_fsm_evaluation_table_lookups": (
            experiment.planned_public_fsm_evaluation_table_lookups
        ),
        "maximum_logical_arm_updates": experiment.planned_public_tokens
        * len(ALL_ARMS),
        "maximum_accepted_arm_updates": (
            len(experiment.evaluation_seeds)
            * experiment.maximum_groups
            * experiment.n_bits
            * len(ALL_ARMS)
            * (len(experiment.repeat_factors) + 3)
        ),
        "maximum_prediction_values": experiment.prediction_value_count,
        "maximum_live_state_bytes": experiment.live_state_bytes,
    }
    for field, expected_value in derived.items():
        if getattr(budgets, field) != expected_value:
            raise CausalEvidenceRunError(
                f"budgets.{field} must equal exact derived work {expected_value}"
            )
    return top, experiment, budgets


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise CausalEvidenceRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise CausalEvidenceRunError("lab commit is unavailable")
    return commit


def _source_hashes(root: Path, config_path: Path) -> dict[str, str]:
    names = (
        "causal_evidence_stream.py",
        "causal_evidence_stream_run.py",
        "isolation.py",
        "o1_streaming_core.py",
        "run_capsule.py",
        "selective_mqar.py",
    )
    return {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(
                root / "src/o1_crypto_lab" / name
            )
            for name in names
        },
    }


def _verify_freeze_document(
    document: Mapping[str, object],
    payload: bytes,
) -> None:
    freeze_sha256 = document.get("freeze_sha256")
    if not isinstance(freeze_sha256, str) or len(freeze_sha256) != 64:
        raise CausalEvidenceRunError("freeze commitment is missing")
    without = dict(document)
    without.pop("freeze_sha256", None)
    if _sha256(_canonical_json(without)) != freeze_sha256:
        raise CausalEvidenceRunError("freeze commitment differs")
    if payload != _canonical_json(dict(document)):
        raise CausalEvidenceRunError("freeze document bytes differ")


def _validate_artifact_commitments(
    artifacts: Mapping[str, bytes],
    document: Mapping[str, object],
    *,
    freeze_path: str,
) -> None:
    if freeze_path not in artifacts:
        raise CausalEvidenceRunError("freeze artifact is missing")
    payloads = {name: value for name, value in artifacts.items() if name != freeze_path}
    if any(not isinstance(value, bytes) for value in artifacts.values()):
        raise CausalEvidenceRunError("artifact payloads must be bytes")
    commitments = document.get("artifact_commitments")
    if not isinstance(commitments, Mapping) or set(commitments) != set(payloads):
        raise CausalEvidenceRunError("freeze artifact inventory differs")
    for name, payload in payloads.items():
        row = commitments[name]
        if (
            not isinstance(row, Mapping)
            or set(row) != {"sha256", "bytes"}
            or row.get("sha256") != _sha256(payload)
            or row.get("bytes") != len(payload)
        ):
            raise CausalEvidenceRunError(f"artifact commitment differs: {name}")
    _verify_freeze_document(document, artifacts[freeze_path])


def _json_artifact(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CausalEvidenceRunError(f"{field} is unreadable") from exc
    if not isinstance(value, dict):
        raise CausalEvidenceRunError(f"{field} must be a mapping")
    return value


def _parse_secret_materials(
    blob: bytes,
    index_payload: bytes,
    seeds: tuple[int, ...],
) -> dict[int, bytes]:
    document = _json_artifact(index_payload, "secret material index")
    rows = document.get("records")
    if (
        document.get("schema") != _SECRET_MATERIAL_INDEX_SCHEMA
        or document.get("blob_sha256") != _sha256(blob)
        or document.get("bytes") != len(blob)
        or not isinstance(rows, list)
        or document.get("record_count") != len(rows)
    ):
        raise CausalEvidenceRunError("secret material index commitment differs")
    result: dict[int, bytes] = {}
    consumed = 0
    for row in rows:
        if not isinstance(row, Mapping):
            raise CausalEvidenceRunError("secret material row differs")
        seed = row.get("seed")
        offset = row.get("offset_bytes")
        width = row.get("bytes")
        if (
            isinstance(seed, bool)
            or not isinstance(seed, int)
            or seed in result
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or isinstance(width, bool)
            or not isinstance(width, int)
            or offset != consumed
            or width < 32
            or offset + width > len(blob)
        ):
            raise CausalEvidenceRunError("secret material row bounds differ")
        material = blob[offset : offset + width]
        if row.get("sha256") != _sha256(material):
            raise CausalEvidenceRunError("secret material row hash differs")
        result[seed] = material
        consumed += width
    if consumed != len(blob) or set(result) != set(seeds):
        raise CausalEvidenceRunError("secret material split inventory differs")
    return result


def _parse_truth_records(blob: bytes, index_payload: bytes) -> dict[str, np.ndarray]:
    document = _json_artifact(index_payload, "truth index")
    rows = document.get("records")
    if (
        document.get("schema") != TRUTH_INDEX_SCHEMA
        or document.get("blob_sha256") != _sha256(blob)
        or document.get("bytes") != len(blob)
        or not isinstance(rows, list)
        or document.get("record_count") != len(rows)
    ):
        raise CausalEvidenceRunError("truth index commitment differs")
    result: dict[str, np.ndarray] = {}
    consumed = 0
    for row in rows:
        if not isinstance(row, Mapping):
            raise CausalEvidenceRunError("truth index row differs")
        key = row.get("key")
        offset = row.get("offset_bytes")
        width = row.get("bytes")
        n_bits = row.get("n_bits")
        if (
            not isinstance(key, str)
            or key in result
            or not isinstance(offset, int)
            or not isinstance(width, int)
            or not isinstance(n_bits, int)
            or offset != consumed
            or width * 8 != n_bits
            or row.get("bitorder") != "little"
            or offset + width > len(blob)
        ):
            raise CausalEvidenceRunError("truth index row bounds differ")
        raw = blob[offset : offset + width]
        if row.get("sha256") != _sha256(raw):
            raise CausalEvidenceRunError("truth row hash differs")
        result[key] = np.unpackbits(
            np.frombuffer(raw, dtype=np.uint8), bitorder="little"
        ).astype(np.uint8, copy=False)
        consumed += width
    if consumed != len(blob):
        raise CausalEvidenceRunError("truth blob has trailing bytes")
    return result


def _artifact_commitments(artifacts: Mapping[str, bytes]) -> dict[str, object]:
    return {
        name: {"sha256": _sha256(payload), "bytes": len(payload)}
        for name, payload in sorted(artifacts.items())
    }


def _build_post_reveal_audit_artifacts(
    config: CausalEvidenceConfig,
    prediction_document: Mapping[str, object],
    truth_document: Mapping[str, object],
    truth_artifacts: Mapping[str, bytes],
) -> dict[str, bytes]:
    material_blob = truth_artifacts["truth/evaluation_secret_material.bin"]
    material_index = truth_artifacts[
        "truth/evaluation_secret_material_index.json"
    ]
    truth_blob = truth_artifacts["truth/evaluation_truth.bitpack"]
    truth_index = truth_artifacts["truth/evaluation_truth_index.json"]
    materials = _parse_secret_materials(
        material_blob, material_index, config.evaluation_seeds
    )
    truths = _parse_truth_records(truth_blob, truth_index)
    pre_reveal = prediction_document.get("secret_material_commitments")
    if (
        not isinstance(pre_reveal, Mapping)
        or pre_reveal != truth_document.get("secret_material_commitments")
        or set(pre_reveal) != {str(seed) for seed in config.evaluation_seeds}
        or any(
            pre_reveal[str(seed)] != _sha256(materials[seed])
            for seed in config.evaluation_seeds
        )
    ):
        raise CausalEvidenceRunError(
            "post-reveal materials do not open the pre-reveal commitments"
        )

    latent = bytearray()
    repeat_map = bytearray()
    orientation = np.asarray(config.orientation_matrix, dtype=np.int8)
    reliabilities = np.asarray(config.quality_reliabilities, dtype=np.float32)
    for seed_ordinal, seed in enumerate(config.evaluation_seeds):
        episode, _sealed = build_public_evidence_episode(
            config,
            seed,
            secret_material=materials[seed],
        )
        truth = truths.get(f"base/{seed}")
        if truth is None or truth.shape != (config.n_bits,):
            raise CausalEvidenceRunError("base truth record differs")
        previous_public_symbol = 0
        for group_index in range(config.maximum_groups):
            group = episode.group(group_index)
            marker_slice = np.asarray(group.marker_event[_REGIME_SLICE])
            if (
                marker_slice.shape != (config.regime_count,)
                or int(np.count_nonzero(marker_slice == 1.0)) != 1
            ):
                raise CausalEvidenceRunError("public marker symbol differs")
            current_public_symbol = int(np.argmax(marker_slice))
            regime = previous_public_symbol
            for offset, coordinate_value in enumerate(group.coordinates):
                coordinate = int(coordinate_value)
                family = int(group.families[offset])
                quality = int(group.qualities[offset])
                vote = int(group.evidence_votes[offset])
                oriented = int(orientation[regime, family])
                truth_sign = 2 * int(truth[coordinate]) - 1
                correctness = vote * truth_sign * oriented
                if correctness not in (-1, 1):
                    raise CausalEvidenceRunError("correctness coin is non-binary")
                latent.extend(
                    _LATENT_RECORD.pack(
                        seed_ordinal,
                        group_index,
                        int(group.group_id),
                        coordinate,
                        family,
                        quality,
                        regime,
                        oriented,
                        vote,
                        correctness,
                        float(reliabilities[quality]),
                    )
                )
            previous_public_symbol = current_public_symbol
            for factor in config.repeat_factors:
                for repeat_ordinal in range(factor):
                    repeat_map.extend(
                        _REPEAT_RECORD.pack(
                            seed_ordinal,
                            factor,
                            repeat_ordinal,
                            group_index,
                            int(group.group_id),
                        )
                    )

    latent_records = (
        len(config.evaluation_seeds) * config.maximum_groups * config.n_bits
    )
    repeat_records = (
        len(config.evaluation_seeds)
        * config.maximum_groups
        * sum(config.repeat_factors)
    )
    if len(latent) != latent_records * _LATENT_RECORD.size:
        raise AssertionError("latent audit ledger width differs")
    if len(repeat_map) != repeat_records * _REPEAT_RECORD.size:
        raise AssertionError("repeat audit ledger width differs")
    audit_payloads = {
        "truth/latent_unique_group_audit.bin": bytes(latent),
        "truth/repeat_to_group_map.bin": bytes(repeat_map),
    }
    latent_index = {
        "schema": "o1-256-causal-evidence-latent-group-index-v1",
        "record_format": "<BHQHBBBbbbf",
        "record_bytes": _LATENT_RECORD.size,
        "record_count": latent_records,
        "seed_order": list(config.evaluation_seeds),
        "fields": [
            "seed_ordinal",
            "group_index",
            "group_id",
            "coordinate",
            "family",
            "quality",
            "regime",
            "orientation",
            "realized_vote",
            "correctness_coin",
            "ex_ante_reliability",
        ],
        "blob_sha256": _sha256(audit_payloads["truth/latent_unique_group_audit.bin"]),
        "pre_reveal_secret_material_commitments": dict(pre_reveal),
    }
    repeat_index = {
        "schema": "o1-256-causal-evidence-repeat-group-index-v1",
        "record_format": "<BBBHQ",
        "record_bytes": _REPEAT_RECORD.size,
        "record_count": repeat_records,
        "seed_order": list(config.evaluation_seeds),
        "repeat_factors": list(config.repeat_factors),
        "fields": [
            "seed_ordinal",
            "repeat_factor",
            "repeat_ordinal",
            "group_index",
            "group_id",
        ],
        "blob_sha256": _sha256(audit_payloads["truth/repeat_to_group_map.bin"]),
    }
    audit_payloads["truth/latent_unique_group_audit_index.json"] = _canonical_json(
        latent_index
    )
    audit_payloads["truth/repeat_to_group_map_index.json"] = _canonical_json(
        repeat_index
    )
    receipt = {
        "schema": POST_REVEAL_AUDIT_SCHEMA,
        "phase": "DERIVED_ONLY_AFTER_RAW_TRUTH_REVEAL_BEFORE_SCORING",
        "parent_prediction_freeze_sha256": prediction_document["freeze_sha256"],
        "parent_truth_reveal_sha256": truth_document["freeze_sha256"],
        "pre_reveal_secret_material_commitments": dict(pre_reveal),
        "artifacts": _artifact_commitments(audit_payloads),
    }
    audit_payloads["truth/post_reveal_audit.json"] = _canonical_json(receipt)
    return audit_payloads


def _already_finalized(manager: RunCapsuleManager, attempt_id: str) -> int | None:
    published = manager.finalized_attempt(attempt_id)
    if published is None:
        return None
    metrics = json.loads(
        (published.path / "metrics.json").read_text(encoding="utf-8")
    )
    status = metrics.get("status")
    print(
        json.dumps(
            {
                "attempt_id": attempt_id,
                "path": str(published.path),
                "manifest_sha256": published.manifest_sha256,
                "verified": published.verification.ok,
                "status": "already-finalized-no-replay",
                "capsule_status": status,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if status == "completed" else 2


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    canonical = (root / "configs/causal_evidence_stream_256_v1.json").resolve(
        strict=True
    )
    if config_path != canonical:
        raise CausalEvidenceRunError(
            "O1C-0021 requires the canonical tracked config path"
        )
    top, experiment, budgets = load_causal_evidence_run_config(config_path)
    attempt_id = str(top["attempt_id"])
    manager = RunCapsuleManager(root)
    finalized_status = _already_finalized(manager, attempt_id)
    if finalized_status is not None:
        return finalized_status
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            status = metrics.get("status")
            print(f"publication completed without replay: {finalized.path}")
            return 0 if status == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve this interrupted O1C-0021 capsule and advance under a "
                "new attempt ID without replaying its evaluation materials."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(root)
    hashes = _source_hashes(root, config_path)
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top["slug"]),
        commit=commit,
        hypothesis=str(top["hypothesis"]),
        prediction=str(top["prediction"]),
        controls=tuple(str(item) for item in top["controls"]),
        budgets=dict(top["budgets"]),
        source_hashes=hashes,
        claim_level=ClaimLevel(str(top["claim_level"])),
        next_action=str(top["next_action"]),
        config=top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.causal_evidence_stream_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "synthetic-causal-evidence-256",
            "accelerator": "none",
            "torch_device": "cpu",
            "cpu_threads": experiment.cpu_threads,
            "scientific_entropy_contract": (
                "one 32-byte root after learning freeze; per-seed SHA-256 derivation"
            ),
            "scientific_entropy_calls": 1,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "native_solver_branches": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    learning_frozen = False
    predictions_frozen = False
    truth_persisted = False
    truth_audit_persisted = False
    entropy_calls = 0
    learning_document: dict[str, object] | None = None
    prediction_document: dict[str, object] | None = None
    truth_document: dict[str, object] | None = None
    scoring_artifacts: dict[str, bytes] = {}
    cpu_started = time.process_time()
    wall_started = time.monotonic()

    def persist_group(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
        *,
        phase: str,
    ) -> None:
        nonlocal persistent_bytes
        if not artifacts or any(not isinstance(value, bytes) for value in artifacts.values()):
            raise CausalEvidenceRunError(f"{phase} artifact inventory differs")
        group_bytes = sum(len(payload) for payload in artifacts.values())
        if persistent_bytes + group_bytes > budgets.maximum_persistent_artifact_bytes:
            raise CausalEvidenceRunError(f"{phase} exceeds the artifact budget")
        for relative, payload in sorted(artifacts.items()):
            if relative in persisted:
                raise CausalEvidenceRunError(f"duplicate artifact: {relative}")
            output = run.write_artifact(relative, payload)
            digest = _sha256(payload)
            if _sha256_file(output) != digest:
                raise CausalEvidenceRunError(f"{phase} persisted bytes differ")
            persisted[relative] = {
                "sha256": digest,
                "bytes": len(payload),
                "phase": phase,
            }
            persistent_bytes += len(payload)
        run.checkpoint(
            {
                "phase": phase,
                "freeze_sha256": document.get("freeze_sha256"),
                "persistent_artifact_bytes": persistent_bytes,
                "learning_frozen": learning_frozen,
                "predictions_frozen": predictions_frozen,
                "truth_persisted": truth_persisted,
                "truth_audit_persisted": truth_audit_persisted,
                "scientific_entropy_calls": entropy_calls,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "native_solver_branches": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def learning_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal learning_frozen, learning_document
        if (
            learning_frozen
            or document.get("schema") != LEARNING_FREEZE_SCHEMA
            or document.get("phase")
            != "ALL_SLOW_STATES_FROZEN_BEFORE_EVALUATION_LEDGER_GENERATION"
            or document.get("evaluation_ledgers_generated") != 0
            or document.get("evaluation_tokens_seen") != 0
            or document.get("evaluation_slow_updates") != 0
            or entropy_calls != 0
        ):
            raise CausalEvidenceRunError("learning freeze boundary differs")
        if set(artifacts) != {
            "learning/primary_slow_state.bin",
            "learning/shuffled_confidence_slow_state.bin",
            "learning/outcome_public_fsm.i8",
            "learning/calibration.json",
            "learning/learning_freeze.json",
        }:
            raise CausalEvidenceRunError("learning artifact inventory differs")
        if document.get("outcome_public_fsm_sha256") != _sha256(
            artifacts["learning/outcome_public_fsm.i8"]
        ) or len(artifacts["learning/outcome_public_fsm.i8"]) != 64:
            raise CausalEvidenceRunError("public FSM learning commitment differs")
        _validate_artifact_commitments(
            artifacts,
            document,
            freeze_path="learning/learning_freeze.json",
        )
        persist_group(artifacts, document, phase="LEARNING_FROZEN_BEFORE_EVALUATION")
        learning_document = dict(document)
        learning_frozen = True

    def evaluation_material_provider(
        seeds: tuple[int, ...],
    ) -> tuple[Mapping[int, bytes], int]:
        nonlocal entropy_calls
        if (
            not learning_frozen
            or predictions_frozen
            or truth_persisted
            or tuple(seeds) != experiment.evaluation_seeds
            or entropy_calls != 0
        ):
            raise CausalEvidenceRunError("evaluation material boundary differs")
        root_material = secrets.token_bytes(32)
        entropy_calls += 1
        if not isinstance(root_material, bytes) or len(root_material) != 32:
            raise CausalEvidenceRunError("scientific entropy root differs")
        materials = {
            seed: hashlib.sha256(
                b"o1c0021-evaluation-seed-v1"
                + root_material
                + struct.pack("<q", seed)
            ).digest()
            for seed in seeds
        }
        if len(set(materials.values())) != len(materials):
            raise CausalEvidenceRunError("derived evaluation materials collide")
        return materials, 1

    def prediction_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal predictions_frozen, prediction_document
        if (
            predictions_frozen
            or not learning_frozen
            or learning_document is None
            or entropy_calls != 1
            or document.get("schema") != PREDICTION_FREEZE_SCHEMA
            or document.get("phase")
            != "ALL_EVALUATION_PREDICTIONS_FROZEN_BEFORE_TRUTH_REVEAL"
            or document.get("truth_ledger_reveal_count") != 0
            or document.get("scorer_calls") != 0
            or document.get("evaluation_slow_updates") != 0
            or document.get("parent_learning_freeze_sha256")
            != learning_document.get("freeze_sha256")
            or document.get("evaluation_seeds") != list(experiment.evaluation_seeds)
            or document.get("prefixes")
            != list(experiment.independent_group_prefixes)
            or document.get("arms") != list(ALL_ARMS)
            or document.get("repeat_factors") != list(experiment.repeat_factors)
            or document.get("transforms")
            != ["complement", "id_permutation", "coordinate_permutation"]
            or document.get("prediction_value_count")
            != experiment.prediction_value_count
            or document.get("truth_ledger_count")
            != 4 * len(experiment.evaluation_seeds)
        ):
            raise CausalEvidenceRunError("prediction freeze boundary differs")
        variants = (
            "base",
            *(f"duplicate_r{factor}" for factor in experiment.repeat_factors[1:]),
            "complement",
            "id_permutation",
            "coordinate_permutation",
        )
        expected_prediction_artifacts = {
            "prediction/evaluation_predictions.f32le",
            "prediction/evaluation_predictions_index.json",
            "prediction/evaluation_receipts.json",
            "prediction/prediction_freeze.json",
            *(
                f"prediction/routes/{variant}_{seed}.bitpack"
                for seed in experiment.evaluation_seeds
                for variant in variants
            ),
            *(
                f"prediction/states/{variant}_{seed}.bin"
                for seed in experiment.evaluation_seeds
                for variant in variants
            ),
            *(
                f"prediction/fsm_states/{variant}_{seed}.bin"
                for seed in experiment.evaluation_seeds
                for variant in variants
            ),
        }
        if set(artifacts) != expected_prediction_artifacts:
            raise CausalEvidenceRunError("prediction artifact inventory differs")
        if any(
            len(artifacts[f"prediction/states/{variant}_{seed}.bin"])
            != experiment.live_state_bytes
            for seed in experiment.evaluation_seeds
            for variant in variants
        ):
            raise CausalEvidenceRunError("prediction live-state width differs")
        if any(
            len(artifacts[f"prediction/fsm_states/{variant}_{seed}.bin"])
            != experiment.n_bits + 17
            for seed in experiment.evaluation_seeds
            for variant in variants
        ):
            raise CausalEvidenceRunError("prediction public-FSM state width differs")
        _validate_artifact_commitments(
            artifacts,
            document,
            freeze_path="prediction/prediction_freeze.json",
        )
        for name in (
            "prediction/evaluation_predictions.f32le",
            "prediction/evaluation_predictions_index.json",
        ):
            scoring_artifacts[name] = artifacts[name]
        persist_group(
            artifacts,
            document,
            phase="PUBLIC_PREDICTIONS_FROZEN_BEFORE_REVEAL",
        )
        prediction_document = dict(document)
        predictions_frozen = True

    def truth_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal truth_persisted, truth_audit_persisted, truth_document
        if (
            truth_persisted
            or not predictions_frozen
            or prediction_document is None
            or document.get("schema") != TRUTH_REVEAL_SCHEMA
            or document.get("phase")
            != "RAW_EVALUATION_TRUTH_PERSISTED_AFTER_PREDICTION_FREEZE_BEFORE_SCORING"
            or document.get("parent_prediction_freeze_sha256")
            != prediction_document.get("freeze_sha256")
            or document.get("truth_ledger_reveal_count_per_ledger") != 1
            or document.get("total_truth_ledgers_revealed")
            != document.get("truth_ledger_count")
            or document.get("truth_ledger_count")
            != 4 * len(experiment.evaluation_seeds)
            or document.get("scorer_calls") != 0
            or document.get("bitorder") != "little"
        ):
            raise CausalEvidenceRunError("truth reveal boundary differs")
        if set(artifacts) != {
            "truth/evaluation_truth.bitpack",
            "truth/evaluation_truth_index.json",
            "truth/evaluation_secret_material.bin",
            "truth/evaluation_secret_material_index.json",
            "truth/truth_reveal.json",
        }:
            raise CausalEvidenceRunError("truth artifact inventory differs")
        _validate_artifact_commitments(
            artifacts,
            document,
            freeze_path="truth/truth_reveal.json",
        )
        for name in (
            "truth/evaluation_truth.bitpack",
            "truth/evaluation_truth_index.json",
        ):
            scoring_artifacts[name] = artifacts[name]
        persist_group(
            artifacts,
            document,
            phase="RAW_TRUTH_PERSISTED_BEFORE_AUDIT_AND_SCORING",
        )
        truth_persisted = True
        derived = _build_post_reveal_audit_artifacts(
            experiment,
            prediction_document,
            document,
            artifacts,
        )
        if set(artifacts) & set(derived):
            raise CausalEvidenceRunError("post-reveal audit artifact collision")
        persist_group(
            derived,
            document,
            phase="POST_REVEAL_AUDIT_PERSISTED_BEFORE_SCORING",
        )
        truth_document = dict(document)
        truth_audit_persisted = True

    try:
        run.checkpoint(
            {
                "phase": "O1C0021_RESERVED",
                "n_bits": experiment.n_bits,
                "prefixes": list(experiment.independent_group_prefixes),
                "repeat_factors": list(experiment.repeat_factors),
                "evaluation_seeds": len(experiment.evaluation_seeds),
                "learning_frozen": False,
                "predictions_frozen": False,
                "truth_persisted": False,
                "truth_audit_persisted": False,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "native_solver_branches": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0021 causal-evidence accumulation started on one CPU thread.\n"
        )
        result = run_causal_evidence_stream(
            experiment,
            on_learning_frozen=learning_callback,
            on_predictions_frozen=prediction_callback,
            on_truth_revealed_before_scoring=truth_callback,
            evaluation_material_provider=evaluation_material_provider,
        )
        if not (
            learning_frozen
            and predictions_frozen
            and truth_persisted
            and truth_audit_persisted
        ):
            raise CausalEvidenceRunError("required lifecycle callbacks did not execute")
        if entropy_calls != 1:
            raise CausalEvidenceRunError("scientific entropy call count differs")
        report = dict(result.report)
        if report.get("schema") != RESULT_SCHEMA:
            raise CausalEvidenceRunError("scientific result schema differs")
        classification = report.get("classification")
        if classification not in _ALLOWED_CLASSIFICATIONS:
            raise CausalEvidenceRunError("scientific classification differs")
        gates = report.get("gates")
        if not isinstance(gates, Mapping) or any(
            not isinstance(value, bool) for value in gates.values()
        ):
            raise CausalEvidenceRunError("scientific gate inventory differs")
        claimed_result_sha = report.get("result_sha256")
        unsigned_report = dict(report)
        unsigned_report.pop("result_sha256", None)
        if claimed_result_sha != _sha256(_canonical_json(unsigned_report)):
            raise CausalEvidenceRunError("scientific result commitment differs")

        recomputed = recompute_causal_evidence_scores(
            experiment,
            prediction_blob=scoring_artifacts[
                "prediction/evaluation_predictions.f32le"
            ],
            prediction_index=scoring_artifacts[
                "prediction/evaluation_predictions_index.json"
            ],
            truth_blob=scoring_artifacts["truth/evaluation_truth.bitpack"],
            truth_index=scoring_artifacts["truth/evaluation_truth_index.json"],
        )
        if _canonical_json(recomputed) != _canonical_json(report.get("scores")):
            raise CausalEvidenceRunError("independent score recomputation differs")
        recomputed_gates = recomputed.get("gates")
        if not isinstance(recomputed_gates, Mapping) or any(
            not isinstance(value, bool) for value in recomputed_gates.values()
        ):
            raise CausalEvidenceRunError("recomputed gate inventory differs")
        expected_gate_names = set(recomputed_gates) | set(
            _EXECUTION_INTEGRITY_GATE_NAMES
        )
        if (
            set(gates) != expected_gate_names
            or not _INTEGRITY_GATE_NAMES <= set(gates)
            or any(gates[name] != value for name, value in recomputed_gates.items())
        ):
            raise CausalEvidenceRunError("top-level/recomputed gates differ")
        failed_gates = sorted(name for name, passed in gates.items() if not passed)
        if report.get("failed_gates") != failed_gates:
            raise CausalEvidenceRunError("scientific failed-gate inventory differs")
        expected_classification = (
            "INTEGRITY_LIFECYCLE_OR_MATCHED_WORK_FAILURE"
            if any(not gates[name] for name in _EXECUTION_INTEGRITY_GATE_NAMES)
            else recomputed.get("classification")
        )
        if classification != expected_classification:
            raise CausalEvidenceRunError("top-level score classification differs")
        expected_success = (
            classification == _SUCCESS_CLASSIFICATION
            and bool(gates)
            and all(gates.values())
        )
        if (
            bool(report.get("success_gate_passed")) != expected_success
            or result.success_gate_passed != expected_success
        ):
            raise CausalEvidenceRunError("success classification/gates differ")
        recomputation_receipt = {
            "schema": "o1-256-causal-evidence-score-recomputation-v1",
            "matches_scientific_report": True,
            "metrics_sha256": recomputed["metrics_sha256"],
            "prediction_blob_sha256": _sha256(
                scoring_artifacts["prediction/evaluation_predictions.f32le"]
            ),
            "prediction_index_sha256": _sha256(
                scoring_artifacts[
                    "prediction/evaluation_predictions_index.json"
                ]
            ),
            "truth_blob_sha256": _sha256(
                scoring_artifacts["truth/evaluation_truth.bitpack"]
            ),
            "truth_index_sha256": _sha256(
                scoring_artifacts["truth/evaluation_truth_index.json"]
            ),
            "result_sha256": claimed_result_sha,
        }
        result_payload = _canonical_json(report)
        persist_group(
            {
                "causal_evidence_stream.json": result_payload,
                "score_recomputation.json": _canonical_json(
                    recomputation_receipt
                ),
            },
            {"freeze_sha256": claimed_result_sha},
            phase="POST_REVEAL_INDEPENDENTLY_RECOMPUTED_RESULT",
        )
        artifact_index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": attempt_id,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
            "self_excluded_from_index": True,
        }
        persist_group(
            {"artifact_index.json": _canonical_json(artifact_index)},
            {"freeze_sha256": claimed_result_sha},
            phase="ARTIFACT_INDEX",
        )
        if _git_commit(root) != commit or _source_hashes(root, config_path) != hashes:
            raise CausalEvidenceRunError("source changed during execution")

        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        work = report["work"]
        state = report["state"]
        reader_evaluations = (
            int(work["gate_token_evaluations"])
            + int(work["coefficient_query_tokens"])
            + int(work["core_marker_updates"])
            + int(work["current_marker_control_updates"])
        )
        accepted_arm_updates = int(work["accepted_update_opportunities"]) * len(
            ALL_ARMS
        )
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "physical_public_tokens": int(work["physical_public_tokens"])
            <= budgets.maximum_physical_public_tokens,
            "reader_token_evaluations": reader_evaluations
            <= budgets.maximum_reader_token_evaluations,
            "training_token_exposures": int(work["training_token_exposures"])
            <= budgets.maximum_training_token_exposures,
            "public_fsm_build_outcome_lookups": int(
                work["public_fsm_build_outcome_lookups"]
            )
            == budgets.maximum_public_fsm_build_outcome_lookups,
            "public_fsm_calibration_table_lookups": int(
                work["public_fsm_calibration_table_lookups"]
            )
            == budgets.maximum_public_fsm_calibration_table_lookups,
            "public_fsm_evaluation_table_lookups": int(
                work["public_fsm_evaluation_table_lookups"]
            )
            == budgets.maximum_public_fsm_evaluation_table_lookups,
            "calibration_physical_public_tokens": int(
                work["calibration_physical_public_tokens"]
            )
            <= budgets.maximum_calibration_physical_public_tokens,
            "calibration_reader_token_evaluations": int(
                work["calibration_reader_token_evaluations"]
            )
            <= budgets.maximum_calibration_reader_token_evaluations,
            "temperature_grid_value_evaluations": int(
                work["temperature_grid_value_evaluations"]
            )
            <= budgets.maximum_temperature_grid_value_evaluations,
            "logical_arm_updates": int(work["logical_arm_updates"])
            <= budgets.maximum_logical_arm_updates,
            "accepted_arm_updates": accepted_arm_updates
            <= budgets.maximum_accepted_arm_updates,
            "prediction_values": experiment.prediction_value_count
            == budgets.maximum_prediction_values,
            "live_state": int(state["total_live_state_bytes"])
            == budgets.maximum_live_state_bytes
            == 352,
            "stream_state_constant": state["stream_length_dependent_model_state"]
            is False,
            "scientific_entropy": int(work["scientific_entropy_calls"])
            == entropy_calls
            == budgets.maximum_scientific_entropy_calls,
            "sibling_reads": int(work["sibling_reads"]) == 0,
            "sibling_writes": int(work["sibling_writes"]) == 0,
            "native_solver_branches": int(work["native_solver_branches"]) == 0,
            "mps": int(work["mps_calls"]) == 0,
            "gpu": int(work["gpu_calls"]) == 0,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        failed_integrity_gates = sorted(
            name
            for name in _INTEGRITY_GATE_NAMES
            if not bool(gates[name])
        )
        integrity_failure = (
            classification in _INTEGRITY_FAILURE_CLASSIFICATIONS
            or bool(failed_integrity_gates)
        )
        operationally_complete = not failed_budgets and not integrity_failure
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": classification,
            "scientific_success_gate_passed": expected_success,
            "result_sha256": claimed_result_sha,
            "recomputed_metrics_sha256": recomputed["metrics_sha256"],
            "gates": dict(gates),
            "state": state,
            "work": work,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "reader_token_evaluations": reader_evaluations,
            "accepted_arm_updates": accepted_arm_updates,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "integrity_failure": integrity_failure,
            "failed_integrity_gates": failed_integrity_gates,
            "operationally_complete": operationally_complete,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if operationally_complete else "failed",
        )
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            status = metrics.get("status")
            print(f"published prepared capsule: {finalized.path}", file=sys.stderr)
            return 0 if status == "completed" else 2
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "learning_frozen": learning_frozen,
                "predictions_frozen": predictions_frozen,
                "truth_persisted": truth_persisted,
                "truth_audit_persisted": truth_audit_persisted,
                "scientific_entropy_calls": entropy_calls,
                "persistent_artifact_bytes": persistent_bytes,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and repair the lifecycle under "
                "a new O1C attempt ID without replaying these evaluation materials."
            ),
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "attempt_id": finalized.attempt_id,
                "path": str(finalized.path),
                "manifest_sha256": finalized.manifest_sha256,
                "verified": finalized.verification.ok,
                "classification": classification,
                "scientific_success_gate_passed": expected_success,
                "failed_budgets": failed_budgets,
                "integrity_failure": integrity_failure,
                "live_state_bytes": state["total_live_state_bytes"],
                "scientific_entropy_calls": work["scientific_entropy_calls"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run capsule-backed O1C-0021 causal evidence accumulation"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "CausalEvidenceRunBudgets",
    "CausalEvidenceRunError",
    "load_causal_evidence_run_config",
    "main",
    "run_capsule_from_config",
]
