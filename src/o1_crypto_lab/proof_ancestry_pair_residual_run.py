"""Authoritative one-shot runner for the conditional O1C-0026 proxy.

The runner reserves O1C-0026 only after a finalized, manager-verified O1C-0023
selects the exact R07 operator from the all-real-primary-null O1C-0022 surface.
It then projects the four already-consumed BUILD FAPs before parsing labels,
fits four leave-one-out models for each matched arm, freezes every prediction
before own-fold scoring, and publishes a complete retrospective capsule.

BUILD-LOO is not a blind-target claim: each BUILD label is training data in
three other folds.  The enforced boundary is that the projection is frozen
before any label parse and a fold's own label never enters its fit.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import resource
import stat
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

import numpy as np

from .full256_action_pool import Full256ActionPool
from .full256_multiresolution_build_loo import ArtifactBuildCorpus
from .living_inverse import canonical_json_bytes
from .o1c19_causal_vault_bridge_run import (
    ARTIFACT_INDEX_SCHEMA as O1C22_ARTIFACT_INDEX_SCHEMA,
    CALIBRATION_FREEZE_SCHEMA as O1C22_CALIBRATION_FREEZE_SCHEMA,
    PREDICTION_ARMS as O1C22_PREDICTION_ARMS,
    PREDICTION_FREEZE_SCHEMA as O1C22_PREDICTION_FREEZE_SCHEMA,
    RESULT_SCHEMA as O1C22_RESULT_SCHEMA,
    RUN_METRICS_SCHEMA as O1C22_METRICS_SCHEMA,
    O1C22RunConfig,
    load_o1c19_causal_vault_bridge_run_config,
)
from .o1c22_postresult_composer import (
    compose_postresult_decision,
    empty_failure_memory,
)
from .o1c22_postresult_composer_run import (
    ARTIFACT_INDEX_SCHEMA as O1C23_ARTIFACT_INDEX_SCHEMA,
    RUN_METRICS_SCHEMA as O1C23_METRICS_SCHEMA,
    O1C23RunConfig,
    load_o1c22_postresult_composer_run_config,
)
from .posterior_logit_frontier import select_o1c22_logits
from .proof_ancestry_pair_residual import (
    ACCOUNTED_NUMERIC_PAYLOAD_BYTES,
    ALPHA_GRID,
    DIAGNOSTIC_ABLATIONS,
    EXPECTED_HORIZONS,
    FEATURE_WIDTH,
    LEARNED_ARMS,
    LIVE_STATE_BYTES,
    PROCESS_LOCAL_SCRATCH_CEILING_BYTES,
    PRIMARY_ARM,
    PROXY_OPERATOR_ID,
    SELECTED_OPERATOR_ID,
    FrozenInnerOOF,
    O1C26SelectionReceipt,
    ProjectedResidualState,
    ProofAncestryPairResidualError,
    finish_outer_fold,
    fit_inner_oof,
    project_pool,
    projection_policy,
    projection_policy_sha256,
    verify_o1c23_selection,
)
from .run_capsule import ClaimLevel, FinalizedRun, RunCapsule, RunCapsuleManager


RUN_CONFIG_SCHEMA: Final = "o1-256-proof-ancestry-pair-residual-run-config-v1"
PREFLIGHT_SCHEMA: Final = "o1-256-o1c26-preflight-v1"
RUN_METRICS_SCHEMA: Final = "o1-256-o1c26-cli-result-v1"
SELECTION_RECEIPT_SCHEMA: Final = "o1-256-o1c26-authoritative-selection-receipt-v1"
SOURCE_INDEX_SCHEMA: Final = "o1-256-o1c26-source-index-v1"
PROXY_MECHANISM_SCHEMA: Final = "o1-256-o1c26-proxy-mechanism-v1"
PROXY_INSTANCE_SCHEMA: Final = "o1-256-o1c26-proxy-instance-v1"
OFFSET_FREEZE_SCHEMA: Final = "o1-256-o1c26-offset-freeze-v1"
PROJECTION_FREEZE_SCHEMA: Final = "o1-256-o1c26-projection-freeze-v1"
INNER_FREEZE_SCHEMA: Final = "o1-256-o1c26-inner-prediction-freeze-v1"
OUTER_FREEZE_SCHEMA: Final = "o1-256-o1c26-outer-prediction-freeze-v1"
PREDICTION_SET_FREEZE_SCHEMA: Final = "o1-256-o1c26-prediction-set-freeze-v1"
LABEL_ACCESS_SCHEMA: Final = "o1-256-o1c26-label-access-receipt-v1"
WORK_LEDGER_SCHEMA: Final = "o1-256-o1c26-structural-work-ledger-v1"
SCORE_REPORT_SCHEMA: Final = "o1-256-o1c26-scientific-score-report-v1"
RESULT_SCHEMA: Final = "o1-256-o1c26-result-v1"
ARTIFACT_INDEX_SCHEMA: Final = "o1-256-o1c26-artifact-index-v1"

ATTEMPT_ID: Final = "O1C-0026"
O1C23_ATTEMPT_ID: Final = "O1C-0023"
O1C22_ATTEMPT_ID: Final = "O1C-0022"
FORMAL_SLUG: Final = "proof-ancestry-pair-residual-v2"
OFFSET_ARM: Final = "normalized_float_offset_only"
SCORE_ARMS: Final = (OFFSET_ARM, *LEARNED_ARMS, *DIAGNOSTIC_ABLATIONS)
FOLD_COUNT: Final = 4
KEY_BITS: Final = 256
FEATURE_SHAPE: Final = (FOLD_COUNT, KEY_BITS, FEATURE_WIDTH)
FEATURE_BYTES: Final = math.prod(FEATURE_SHAPE) * 8
LABEL_BYTES: Final = FOLD_COUNT * KEY_BITS // 8
EXPECTED_RIDGE_FITS: Final = FOLD_COUNT * len(LEARNED_ARMS) * 4
EXPECTED_ALPHA_EVALUATIONS: Final = (
    FOLD_COUNT * len(LEARNED_ARMS) * len(ALPHA_GRID) * 3 * KEY_BITS
)
EXPECTED_DIAGNOSTIC_EVALUATIONS: Final = (
    FOLD_COUNT * len(DIAGNOSTIC_ABLATIONS) * KEY_BITS
)
EXPECTED_INNER_FREEZES: Final = FOLD_COUNT * len(LEARNED_ARMS)
EXPECTED_FAP_VALUES: Final = FOLD_COUNT * 3 * KEY_BITS * 2 * 330
ABLATION_MATERIAL_BITS: Final = 0.25
PUBLICATION_CPU_RESERVE_SECONDS: Final = 5.0
PUBLICATION_WALL_RESERVE_SECONDS: Final = 10.0
PUBLICATION_RSS_RESERVE_BYTES: Final = 64 * 1024 * 1024
PRESENT = "FAP_ANCESTRY_TOUCH_BILINEAR_PROXY_PRESENT"
NULL = "FAP_ANCESTRY_TOUCH_BILINEAR_PROXY_NULL"
FAILURE = "FAP_ANCESTRY_TOUCH_BILINEAR_PROXY_OPERATIONAL_FAILURE"
_HEX: Final = frozenset("0123456789abcdef")
_O1C23_INDEXED_ARTIFACTS: Final = frozenset(
    {
        "decision_policy.json",
        "failure_memory.json",
        "quantization_diagnostics.json",
        "decision.json",
        "bridge_intents.causal",
        "o1c22_next_operator_fragments.json",
        "native_o1o_receipt.json",
        "native_generated_source.py",
        "next_operator_graph.json",
        "structural_work_ledger.json",
        "source_index.json",
    }
)


class O1C26RunError(ValueError):
    """A config, source, lifecycle, work, score, or budget differs."""


class O1C26SelectionMismatch(O1C26RunError):
    """O1C-0023 is valid but selected another successor."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C26RunError(f"{field_name} must be lowercase SHA-256")
    return value


def _commit(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in _HEX for character in value)
    ):
        raise O1C26RunError(f"{field_name} must be a lowercase 40-hex commit")
    return value


def _mapping(
    value: object,
    field_name: str,
    expected: set[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C26RunError(f"{field_name} must be a JSON object")
    if expected is not None and set(value) != expected:
        raise O1C26RunError(f"{field_name} fields differ")
    return value


def _sequence(value: object, field_name: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C26RunError(f"{field_name} must be a sequence")
    return value


def _integer(value: object, field_name: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C26RunError(f"{field_name} must be an integer in [{minimum},{maximum}]")
    return value


def _number(value: object, field_name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C26RunError(f"{field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise O1C26RunError(f"{field_name} differs")
    return result


def _read_json(path: Path, field_name: str) -> tuple[Mapping[str, object], bytes]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C26RunError(f"{field_name} is unreadable") from exc
    return _mapping(value, field_name), payload


def _freeze(unsigned: Mapping[str, object], *, digest_field: str) -> dict[str, object]:
    if digest_field in unsigned:
        raise O1C26RunError(f"{digest_field} already exists before freeze")
    return {
        **dict(unsigned),
        digest_field: _sha256_bytes(canonical_json_bytes(dict(unsigned))),
    }


def _safe_relative(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise O1C26RunError(f"{field_name} path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C26RunError(f"{field_name} path is unsafe")
    return value


def _process_peak_rss_bytes() -> int:
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return raw if raw > 16 * 1024 * 1024 else raw * 1024


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _git_clean_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise O1C26RunError("formal O1C-0026 requires a clean lab worktree")
    commit_value = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return _commit(commit_value, "HEAD commit")


@dataclass(frozen=True)
class O1C26Budgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_source_artifact_bytes_read: int
    maximum_persistent_artifact_bytes: int
    expected_build_faps: int
    maximum_development_faps_deserialized: int
    maximum_fresh_targets: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int
    maximum_live_state_bytes: int
    maximum_projection_scratch_bytes: int
    expected_ridge_fits: int
    expected_alpha_bit_evaluations: int
    expected_diagnostic_bit_evaluations: int

    @classmethod
    def from_mapping(cls, value: object) -> "O1C26Budgets":
        row = _mapping(value, "budgets", set(cls.__dataclass_fields__))
        result = cls(
            maximum_cpu_seconds=_number(
                row["maximum_cpu_seconds"], "maximum_cpu_seconds", 0.1, 86_400.0
            ),
            maximum_wall_seconds=_number(
                row["maximum_wall_seconds"], "maximum_wall_seconds", 0.1, 86_400.0
            ),
            maximum_resident_memory_mib=_integer(
                row["maximum_resident_memory_mib"],
                "maximum_resident_memory_mib",
                1,
                65_536,
            ),
            maximum_source_artifact_bytes_read=_integer(
                row["maximum_source_artifact_bytes_read"],
                "maximum_source_artifact_bytes_read",
                1,
                1 << 40,
            ),
            maximum_persistent_artifact_bytes=_integer(
                row["maximum_persistent_artifact_bytes"],
                "maximum_persistent_artifact_bytes",
                1,
                1 << 40,
            ),
            expected_build_faps=_integer(
                row["expected_build_faps"], "expected_build_faps", 1, 64
            ),
            maximum_development_faps_deserialized=_integer(
                row["maximum_development_faps_deserialized"],
                "maximum_development_faps_deserialized",
                0,
                64,
            ),
            maximum_fresh_targets=_integer(
                row["maximum_fresh_targets"], "maximum_fresh_targets", 0, 64
            ),
            maximum_native_solver_branches=_integer(
                row["maximum_native_solver_branches"],
                "maximum_native_solver_branches",
                0,
                1 << 40,
            ),
            maximum_scientific_entropy_calls=_integer(
                row["maximum_scientific_entropy_calls"],
                "maximum_scientific_entropy_calls",
                0,
                1 << 40,
            ),
            maximum_sibling_reads=_integer(
                row["maximum_sibling_reads"], "maximum_sibling_reads", 0, 1 << 40
            ),
            maximum_sibling_writes=_integer(
                row["maximum_sibling_writes"], "maximum_sibling_writes", 0, 1 << 40
            ),
            maximum_mps_calls=_integer(
                row["maximum_mps_calls"], "maximum_mps_calls", 0, 1 << 40
            ),
            maximum_gpu_calls=_integer(
                row["maximum_gpu_calls"], "maximum_gpu_calls", 0, 1 << 40
            ),
            maximum_live_state_bytes=_integer(
                row["maximum_live_state_bytes"], "maximum_live_state_bytes", 1, 1 << 30
            ),
            maximum_projection_scratch_bytes=_integer(
                row["maximum_projection_scratch_bytes"],
                "maximum_projection_scratch_bytes",
                1,
                1 << 30,
            ),
            expected_ridge_fits=_integer(
                row["expected_ridge_fits"], "expected_ridge_fits", 1, 1 << 30
            ),
            expected_alpha_bit_evaluations=_integer(
                row["expected_alpha_bit_evaluations"],
                "expected_alpha_bit_evaluations",
                1,
                1 << 40,
            ),
            expected_diagnostic_bit_evaluations=_integer(
                row["expected_diagnostic_bit_evaluations"],
                "expected_diagnostic_bit_evaluations",
                1,
                1 << 40,
            ),
        )
        exact = {
            "expected_build_faps": FOLD_COUNT,
            "maximum_development_faps_deserialized": 0,
            "maximum_fresh_targets": 0,
            "maximum_native_solver_branches": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_live_state_bytes": LIVE_STATE_BYTES,
            "maximum_projection_scratch_bytes": 16_384,
            "expected_ridge_fits": EXPECTED_RIDGE_FITS,
            "expected_alpha_bit_evaluations": EXPECTED_ALPHA_EVALUATIONS,
            "expected_diagnostic_bit_evaluations": EXPECTED_DIAGNOSTIC_EVALUATIONS,
        }
        if any(getattr(result, key) != expected for key, expected in exact.items()):
            raise O1C26RunError("frozen exact O1C-0026 budgets differ")
        return result


@dataclass(frozen=True)
class O1C26RunConfig:
    top: Mapping[str, object]
    config_path: Path
    root: Path
    budgets: O1C26Budgets
    source_config: Mapping[str, object]
    source_config_path: Path
    o1c23_config: O1C23RunConfig
    o1c22_config_path: Path
    source_freeze_commit: str
    local_source_sha256: Mapping[str, str]
    local_source_paths: Mapping[str, Path]


def load_o1c26_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C26RunConfig:
    config_path = Path(path).resolve(strict=True)
    lab_root = (
        Path(root).resolve(strict=True) if root is not None else config_path.parents[1]
    )
    if not config_path.is_relative_to(lab_root):
        raise O1C26RunError("config escapes lab root")
    top, _ = _read_json(config_path, "O1C-0026 config")
    expected_top = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "next_action",
        "prerequisites",
        "experiment",
        "source",
    }
    if set(top) != expected_top or (
        top.get("schema") != RUN_CONFIG_SCHEMA
        or top.get("attempt_id") != ATTEMPT_ID
        or top.get("slug") != FORMAL_SLUG
        or top.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
    ):
        raise O1C26RunError("formal O1C-0026 identity differs")
    for name in ("hypothesis", "prediction", "next_action"):
        if not isinstance(top[name], str) or not str(top[name]).strip():
            raise O1C26RunError(f"{name} is required")
    controls = _sequence(top["controls"], "controls")
    if len(controls) < 6 or any(not isinstance(value, str) for value in controls):
        raise O1C26RunError("formal controls are incomplete")
    budgets = O1C26Budgets.from_mapping(top["budgets"])

    experiment = _mapping(
        top["experiment"],
        "experiment",
        {
            "schema",
            "selected_parent_operator_id",
            "proxy_operator_id",
            "projection_policy_sha256",
            "learned_arms",
            "diagnostic_ablations",
            "offset_arm",
            "ridge_fits",
            "alpha_bit_evaluations",
            "diagnostic_bit_evaluations",
            "ablation_material_bits",
            "own_fold_label_used_in_fit",
            "cross_fold_labels_are_training_data",
        },
    )
    if dict(experiment) != {
        "schema": "o1-256-proof-ancestry-pair-residual-experiment-v1",
        "selected_parent_operator_id": SELECTED_OPERATOR_ID,
        "proxy_operator_id": PROXY_OPERATOR_ID,
        "projection_policy_sha256": projection_policy_sha256(),
        "learned_arms": list(LEARNED_ARMS),
        "diagnostic_ablations": list(DIAGNOSTIC_ABLATIONS),
        "offset_arm": OFFSET_ARM,
        "ridge_fits": EXPECTED_RIDGE_FITS,
        "alpha_bit_evaluations": EXPECTED_ALPHA_EVALUATIONS,
        "diagnostic_bit_evaluations": EXPECTED_DIAGNOSTIC_EVALUATIONS,
        "ablation_material_bits": ABLATION_MATERIAL_BITS,
        "own_fold_label_used_in_fit": False,
        "cross_fold_labels_are_training_data": True,
    }:
        raise O1C26RunError("frozen experiment differs")

    prerequisites = _mapping(top["prerequisites"], "prerequisites", {"o1c23", "o1c22"})
    o1c23 = _mapping(
        prerequisites["o1c23"],
        "prerequisites.o1c23",
        {
            "attempt_id",
            "config_path",
            "config_sha256",
            "source_freeze_commit",
            "source_selection",
            "required_operator_id",
            "required_reason_field",
        },
    )
    o1c22 = _mapping(
        prerequisites["o1c22"],
        "prerequisites.o1c22",
        {"attempt_id", "config_path", "config_sha256", "source_selection"},
    )
    if (
        o1c23.get("attempt_id") != O1C23_ATTEMPT_ID
        or o1c23.get("source_selection") != "reserved-finalized-attempt-only"
        or o1c23.get("required_operator_id") != SELECTED_OPERATOR_ID
        or o1c23.get("required_reason_field")
        != "all_real_primary_k256_arms_nonpositive"
        or o1c22.get("attempt_id") != O1C22_ATTEMPT_ID
        or o1c22.get("source_selection") != "decision-bound-authoritative-finalized"
    ):
        raise O1C26RunError("prerequisite selection contract differs")

    def dependency_path(raw: object, field_name: str) -> Path:
        if not isinstance(raw, str) or not raw:
            raise O1C26RunError(f"{field_name} is required")
        candidate = (lab_root / raw).resolve(strict=True)
        if not candidate.is_relative_to(lab_root):
            raise O1C26RunError(f"{field_name} escapes lab root")
        return candidate

    o1c23_path = dependency_path(o1c23["config_path"], "O1C-0023 config")
    o1c22_path = dependency_path(o1c22["config_path"], "O1C-0022 config")
    if _sha256_file(o1c23_path) != _sha256(
        o1c23["config_sha256"], "O1C-0023 config SHA-256"
    ) or _sha256_file(o1c22_path) != _sha256(
        o1c22["config_sha256"], "O1C-0022 config SHA-256"
    ):
        raise O1C26RunError("pinned upstream config hash differs")
    o1c23_config = load_o1c22_postresult_composer_run_config(o1c23_path, root=lab_root)
    if o1c23_config.upstream_config_path != o1c22_path:
        raise O1C26RunError("O1C-0023 and O1C-0026 name different O1C-0022 configs")

    source = _mapping(
        top["source"],
        "source",
        {
            "source_config_path",
            "source_config_sha256",
            "source_freeze_commit",
            "local_source_sha256",
        },
    )
    source_config_path = dependency_path(
        source["source_config_path"], "source config path"
    )
    source_config, source_config_payload = _read_json(
        source_config_path, "O1C-0026 source config"
    )
    if _sha256_bytes(source_config_payload) != _sha256(
        source["source_config_sha256"], "source config SHA-256"
    ):
        raise O1C26RunError("source config hash differs")
    if (
        source_config.get("attempt_id") != ATTEMPT_ID
        or source_config.get("projection_policy_sha256") != projection_policy_sha256()
        or source_config.get("proxy_operator_id") != PROXY_OPERATOR_ID
    ):
        raise O1C26RunError("source config mechanism differs")
    source_freeze_commit = _commit(
        source["source_freeze_commit"], "source freeze commit"
    )
    _commit(o1c23["source_freeze_commit"], "O1C-0023 source freeze commit")
    raw_hashes = _mapping(source["local_source_sha256"], "local source hashes")
    required_sources = {
        "source_config",
        "projection_module",
        "runner_module",
        "run_capsule_module",
        "posterior_logit_module",
        "pyproject",
    }
    if set(raw_hashes) != required_sources:
        raise O1C26RunError("local source hash inventory differs")
    relative_sources = {
        "source_config": source_config_path.relative_to(lab_root).as_posix(),
        "projection_module": "src/o1_crypto_lab/proof_ancestry_pair_residual.py",
        "runner_module": "src/o1_crypto_lab/proof_ancestry_pair_residual_run.py",
        "run_capsule_module": "src/o1_crypto_lab/run_capsule.py",
        "posterior_logit_module": "src/o1_crypto_lab/posterior_logit_frontier.py",
        "pyproject": "pyproject.toml",
    }
    local_hashes: dict[str, str] = {}
    local_paths: dict[str, Path] = {}
    for label, relative in relative_sources.items():
        expected = _sha256(raw_hashes[label], f"local source {label}")
        local_path = (lab_root / relative).resolve(strict=True)
        actual = _sha256_file(local_path)
        if actual != expected:
            raise O1C26RunError(f"local source differs: {label}")
        local_hashes[label] = actual
        local_paths[label] = local_path
    return O1C26RunConfig(
        top=top,
        config_path=config_path,
        root=lab_root,
        budgets=budgets,
        source_config=source_config,
        source_config_path=source_config_path,
        o1c23_config=o1c23_config,
        o1c22_config_path=o1c22_path,
        source_freeze_commit=source_freeze_commit,
        local_source_sha256=dict(sorted(local_hashes.items())),
        local_source_paths=dict(sorted(local_paths.items())),
    )


@dataclass(frozen=True)
class O1C26PreparedSource:
    o1c23: FinalizedRun
    o1c22: "O1C22NarrowSource"
    o1c22_run_config: O1C22RunConfig
    decision: Mapping[str, object]
    decision_payload: bytes
    operator_graph: Mapping[str, object]
    operator_graph_payload: bytes
    selection_receipt: Mapping[str, object]
    proxy_mechanism: Mapping[str, object]
    proxy_instance: Mapping[str, object]
    held_out_offsets: np.ndarray
    training_offsets: np.ndarray
    training_ordinals: tuple[tuple[int, int, int], ...]
    offset_members: tuple[Mapping[str, object], ...]
    label_payload_path: Path
    label_payload_sha256: str
    source_artifact_bytes_read: int

    @property
    def pools(self) -> tuple[Full256ActionPool, ...]:
        return tuple(episode.pool for episode in self.o1c22_run_config.corpus.episodes)


@dataclass(frozen=True)
class O1C22NarrowSource:
    """Manager-bound O1C-0022 surface that never opens the label member."""

    finalized: FinalizedRun
    result: Mapping[str, object]
    metrics: Mapping[str, object]
    artifact_index: Mapping[str, object]
    artifact_index_sha256: str
    result_sha256: str
    source_artifact_bytes_read: int


@dataclass(frozen=True)
class O1C26Preflight:
    report: Mapping[str, object]
    config: O1C26RunConfig
    source: O1C26PreparedSource | None

    @property
    def ready(self) -> bool:
        return self.source is not None and self.report.get("status") == "ready"


def _indexed_payload(
    artifacts_root: Path,
    artifacts: Mapping[str, object],
    relative: str,
    field_name: str,
) -> bytes:
    safe = _safe_relative(relative, field_name)
    entry = _mapping(artifacts.get(safe), field_name, {"sha256", "bytes", "phase"})
    path = (artifacts_root / safe).resolve(strict=True)
    if not path.is_relative_to(artifacts_root.resolve()):
        raise O1C26RunError(f"{field_name} escapes artifacts")
    payload = path.read_bytes()
    if (
        entry.get("sha256") != _sha256_bytes(payload)
        or entry.get("bytes") != len(payload)
        or not isinstance(entry.get("phase"), str)
    ):
        raise O1C26RunError(f"{field_name} index entry differs")
    return payload


def _authoritative_finalized(
    manager: RunCapsuleManager,
    supplied: FinalizedRun,
    attempt_id: str,
) -> FinalizedRun:
    authoritative = manager.finalized_attempt(attempt_id)
    if authoritative is None:
        raise O1C26RunError(f"authoritative finalized {attempt_id} is unavailable")
    if (
        supplied.attempt_id != attempt_id
        or supplied.path != authoritative.path
        or supplied.manifest_sha256 != authoritative.manifest_sha256
        or not authoritative.verification.ok
    ):
        raise O1C26RunError(f"{attempt_id} is not the authoritative publication")
    verification = manager.verify(authoritative.path)
    if (
        not verification.ok
        or verification.manifest_sha256 != authoritative.manifest_sha256
    ):
        raise O1C26RunError(f"{attempt_id} fresh manifest verification differs")
    return authoritative


def _verify_freeze_document(
    document: Mapping[str, object],
    *,
    schema: str,
    field_name: str,
) -> str:
    if document.get("schema") != schema:
        raise O1C26RunError(f"{field_name} schema differs")
    unsigned = dict(document)
    supplied = _sha256(unsigned.pop("freeze_sha256", None), f"{field_name} SHA-256")
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C26RunError(f"{field_name} SHA-256 differs")
    return supplied


def _load_narrow_o1c22_source(
    manager: RunCapsuleManager,
    run_config: O1C22RunConfig,
) -> O1C22NarrowSource:
    """Verify O1C-0022 authority and scoring surface without reading labels."""

    supplied = manager.finalized_attempt(O1C22_ATTEMPT_ID)
    if supplied is None:
        raise O1C26RunError("authoritative finalized O1C-0022 is unavailable")
    finalized = _authoritative_finalized(manager, supplied, O1C22_ATTEMPT_ID)
    capsule_config, config_payload = _read_json(
        finalized.path / "config.json", "O1C-0022 capsule config"
    )
    if (
        capsule_config.get("attempt_id") != O1C22_ATTEMPT_ID
        or capsule_config.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or capsule_config.get("config") != run_config.top
    ):
        raise O1C26RunError("O1C-0022 capsule config differs")
    outer_metrics, metrics_payload = _read_json(
        finalized.path / "metrics.json", "O1C-0022 metrics"
    )
    metrics = _mapping(outer_metrics.get("values"), "O1C-0022 metric values")
    if (
        outer_metrics.get("attempt_id") != O1C22_ATTEMPT_ID
        or outer_metrics.get("status") != "completed"
        or metrics.get("schema") != O1C22_METRICS_SCHEMA
        or metrics.get("operationally_complete") is not True
    ):
        raise O1C26RunError("O1C-0022 is not operationally complete")
    artifacts_root = finalized.path / "artifacts"
    artifact_index, index_payload = _read_json(
        artifacts_root / "artifact_index.json", "O1C-0022 artifact index"
    )
    if (
        artifact_index.get("schema") != O1C22_ARTIFACT_INDEX_SCHEMA
        or artifact_index.get("attempt_id") != O1C22_ATTEMPT_ID
    ):
        raise O1C26RunError("O1C-0022 artifact index differs")
    artifacts = _mapping(artifact_index.get("artifacts"), "O1C-0022 artifact inventory")
    if artifact_index.get("indexed_artifact_count") != len(
        artifacts
    ) or artifact_index.get("indexed_artifact_bytes") != sum(
        _integer(
            _mapping(entry, f"O1C-0022 artifact {relative}").get("bytes"),
            f"O1C-0022 artifact {relative} bytes",
            0,
            1 << 40,
        )
        for relative, entry in artifacts.items()
    ):
        raise O1C26RunError("O1C-0022 artifact-index totals differ")
    required = {
        "o1c19_causal_vault_bridge.json",
        "labels.bitpack",
        *(
            f"folds/build-{fold:04d}/calibration/raw_predictions.f64le"
            for fold in range(FOLD_COUNT)
        ),
        *(
            f"folds/build-{fold:04d}/calibration/prediction_freeze.json"
            for fold in range(FOLD_COUNT)
        ),
        *(
            f"folds/build-{fold:04d}/heldout/calibration_scales.f64le"
            for fold in range(FOLD_COUNT)
        ),
        *(
            f"folds/build-{fold:04d}/heldout/calibrated_predictions.f64le"
            for fold in range(FOLD_COUNT)
        ),
        *(
            f"folds/build-{fold:04d}/heldout/prediction_freeze.json"
            for fold in range(FOLD_COUNT)
        ),
    }
    if not required.issubset(artifacts):
        raise O1C26RunError("O1C-0022 required narrow artifact inventory is absent")
    result_payload = _indexed_payload(
        artifacts_root,
        artifacts,
        "o1c19_causal_vault_bridge.json",
        "O1C-0022 result",
    )
    try:
        result = _mapping(json.loads(result_payload.decode("ascii")), "O1C-0022 result")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C26RunError("O1C-0022 result is invalid") from exc
    if result.get("schema") != O1C22_RESULT_SCHEMA or metrics.get(
        "result_sha256"
    ) != result.get("result_sha256"):
        raise O1C26RunError("O1C-0022 result/metrics binding differs")
    return O1C22NarrowSource(
        finalized=finalized,
        result=result,
        metrics=metrics,
        artifact_index=artifact_index,
        artifact_index_sha256=_sha256_bytes(index_payload),
        result_sha256=_sha256_bytes(result_payload),
        source_artifact_bytes_read=(
            len(config_payload)
            + len(metrics_payload)
            + len(index_payload)
            + len(result_payload)
        ),
    )


def _proxy_mechanism(config: O1C26RunConfig) -> dict[str, object]:
    descriptor = {
        "schema": PROXY_MECHANISM_SCHEMA,
        "proxy_operator_id": PROXY_OPERATOR_ID,
        "selected_parent_operator_id": SELECTED_OPERATOR_ID,
        "projection_policy_sha256": projection_policy_sha256(),
        "experiment_sha256": _sha256_bytes(
            canonical_json_bytes(config.top["experiment"])
        ),
        "scientific_source_sha256": {
            name: config.local_source_sha256[name]
            for name in (
                "projection_module",
                "runner_module",
                "posterior_logit_module",
                "pyproject",
            )
        },
    }
    return _freeze(descriptor, digest_field="proxy_mechanism_sha256")


def _proxy_instance(
    config: O1C26RunConfig,
    mechanism: Mapping[str, object],
    source_receipt: O1C26SelectionReceipt,
    o1c22_source: O1C22NarrowSource,
    corpus: ArtifactBuildCorpus,
    held_out_offsets: np.ndarray,
    training_offsets: np.ndarray,
    training_ordinals: Sequence[Sequence[int]],
    offset_members: Sequence[Mapping[str, object]],
    label_sha256: str,
) -> dict[str, object]:
    held_payload = _little_f8(
        held_out_offsets, (FOLD_COUNT, KEY_BITS), "proxy held-out offsets"
    )
    training_payload = _little_f8(
        training_offsets,
        (FOLD_COUNT, 3, KEY_BITS),
        "proxy training offsets",
    )
    instance = {
        "schema": PROXY_INSTANCE_SCHEMA,
        "proxy_mechanism_sha256": mechanism["proxy_mechanism_sha256"],
        "parent": {
            "operator_id": SELECTED_OPERATOR_ID,
            "operator_fingerprint": source_receipt.parent_operator_fingerprint,
            "decision_sha256": source_receipt.decision_sha256,
            "operator_graph_sha256": source_receipt.operator_graph_sha256,
        },
        "evaluation_source": {
            "source_config_sha256": _sha256_file(config.source_config_path),
            "o1c22_result_sha256": o1c22_source.result["result_sha256"],
            "o1c22_result_file_sha256": o1c22_source.result_sha256,
            "o1c18_build_corpus_sha256": corpus.sha256,
            "held_out_offsets_sha256": _sha256_bytes(held_payload),
            "training_offsets_sha256": _sha256_bytes(training_payload),
            "offset_source_members_sha256": _sha256_bytes(
                canonical_json_bytes(list(offset_members))
            ),
            "label_payload_sha256": label_sha256,
            "label_payload_bytes": LABEL_BYTES,
            "label_bit_order": "little",
            "training_ordinals_by_outer_fold": [
                list(values) for values in training_ordinals
            ],
        },
    }
    return _freeze(instance, digest_field="proxy_instance_fingerprint")


def _load_o1c23_selection(
    config: O1C26RunConfig,
    supplied: FinalizedRun,
) -> O1C26PreparedSource:
    manager = RunCapsuleManager(config.root)
    finalized = _authoritative_finalized(manager, supplied, O1C23_ATTEMPT_ID)
    capsule_config, config_payload = _read_json(
        finalized.path / "config.json", "O1C-0023 capsule config"
    )
    if (
        capsule_config.get("attempt_id") != O1C23_ATTEMPT_ID
        or capsule_config.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or capsule_config.get("config") != config.o1c23_config.top
    ):
        raise O1C26RunError("O1C-0023 capsule config differs")
    commit_value = _commit(capsule_config.get("commit"), "O1C-0023 commit")
    prerequisite = _mapping(config.top["prerequisites"], "prerequisites")
    o1c23_prerequisite = _mapping(prerequisite["o1c23"], "o1c23 prerequisite")
    o1c23_freeze = _commit(
        o1c23_prerequisite["source_freeze_commit"], "O1C-0023 freeze commit"
    )
    if not _git_is_ancestor(config.root, o1c23_freeze, commit_value):
        raise O1C26RunError("O1C-0023 commit does not descend from its source freeze")

    outer_metrics, metrics_payload = _read_json(
        finalized.path / "metrics.json", "O1C-0023 metrics"
    )
    values = _mapping(outer_metrics.get("values"), "O1C-0023 metric values")
    if (
        outer_metrics.get("attempt_id") != O1C23_ATTEMPT_ID
        or outer_metrics.get("status") != "completed"
        or values.get("schema") != O1C23_METRICS_SCHEMA
        or values.get("operationally_complete") is not True
        or values.get("operator_id") != SELECTED_OPERATOR_ID
    ):
        if (
            outer_metrics.get("status") == "completed"
            and values.get("operationally_complete") is True
            and isinstance(values.get("operator_id"), str)
        ):
            raise O1C26SelectionMismatch(
                f"O1C-0023 selected {values.get('operator_id')}"
            )
        raise O1C26RunError("O1C-0023 is not an operationally complete selection")

    artifacts_root = finalized.path / "artifacts"
    index, index_payload = _read_json(
        artifacts_root / "artifact_index.json", "O1C-0023 artifact index"
    )
    if (
        index.get("schema") != O1C23_ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != O1C23_ATTEMPT_ID
    ):
        raise O1C26RunError("O1C-0023 artifact index identity differs")
    artifacts = _mapping(index.get("artifacts"), "O1C-0023 artifact inventory")
    if set(artifacts) != _O1C23_INDEXED_ARTIFACTS:
        raise O1C26RunError("O1C-0023 exact indexed artifact inventory differs")
    actual = {
        path.relative_to(artifacts_root).as_posix()
        for path in artifacts_root.rglob("*")
        if path.is_file() and path.name != "artifact_index.json"
    }
    if actual != set(artifacts):
        raise O1C26RunError("O1C-0023 actual artifact inventory differs")
    payloads = {
        relative: _indexed_payload(
            artifacts_root, artifacts, relative, f"O1C-0023 {relative}"
        )
        for relative in sorted(artifacts)
    }
    if index.get("indexed_artifact_count") != len(artifacts) or index.get(
        "indexed_artifact_bytes"
    ) != sum(len(value) for value in payloads.values()):
        raise O1C26RunError("O1C-0023 artifact-index totals differ")
    try:
        decision = _mapping(
            json.loads(payloads["decision.json"].decode("ascii")),
            "O1C-0023 decision",
        )
        graph = _mapping(
            json.loads(payloads["next_operator_graph.json"].decode("ascii")),
            "O1C-0023 operator graph",
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C26RunError("O1C-0023 decision artifacts are invalid") from exc
    operator = _mapping(decision.get("operator"), "O1C-0023 operator")
    if operator.get("operator_id") != SELECTED_OPERATOR_ID:
        raise O1C26SelectionMismatch(f"O1C-0023 selected {operator.get('operator_id')}")
    reason = _mapping(decision.get("reason_metrics"), "O1C-0023 reason metrics")
    if reason.get("all_real_primary_k256_arms_nonpositive") is not True:
        raise O1C26SelectionMismatch("O1C-0023 did not select R07 from all-real null")
    try:
        source_receipt = verify_o1c23_selection(decision, graph)
    except ProofAncestryPairResidualError as exc:
        raise O1C26RunError("O1C-0023 decision/graph binding differs") from exc
    if (
        values.get("decision_sha256") != source_receipt.decision_sha256
        or values.get("operator_graph_sha256") != source_receipt.operator_graph_sha256
        or values.get("operator_fingerprint")
        != source_receipt.parent_operator_fingerprint
    ):
        raise O1C26RunError("O1C-0023 metrics differ from selected operator")

    o1c22_run_config = load_o1c19_causal_vault_bridge_run_config(
        config.o1c22_config_path, root=config.root
    )
    o1c22_source = _load_narrow_o1c22_source(manager, o1c22_run_config)
    try:
        diagnostics = _mapping(
            json.loads(payloads["quantization_diagnostics.json"].decode("ascii")),
            "O1C-0023 quantization diagnostics",
        )
        memory = _mapping(
            json.loads(payloads["failure_memory.json"].decode("ascii")),
            "O1C-0023 failure memory",
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C26RunError("O1C-0023 decision inputs are invalid") from exc
    if dict(memory) != empty_failure_memory():
        raise O1C26RunError("O1C-0023 R07 selection did not use empty failure memory")
    recomposed = compose_postresult_decision(
        o1c22_source.result,
        o1c22_source.metrics,
        capsule_manifest_sha256=o1c22_source.finalized.manifest_sha256,
        quantization_diagnostics=diagnostics,
        failure_memory=memory,
    )
    if dict(decision) != recomposed or (
        source_receipt.source_capsule_manifest_sha256
        != o1c22_source.finalized.manifest_sha256
        or source_receipt.source_result_sha256
        != o1c22_source.result.get("result_sha256")
    ):
        raise O1C26RunError("O1C-0023 is not the exact authoritative O1C-0022 decision")

    corpus = o1c22_run_config.corpus
    source_build_rows = _sequence(
        config.source_config.get("build_faps"), "source BUILD FAP rows"
    )
    if len(corpus.episodes) != FOLD_COUNT or len(source_build_rows) != FOLD_COUNT:
        raise O1C26RunError("BUILD FAP count differs")
    for index_value, (episode, raw_row) in enumerate(
        zip(corpus.episodes, source_build_rows)
    ):
        row = _mapping(raw_row, f"source BUILD FAP {index_value}")
        if (
            episode.ordinal != index_value
            or episode.target_id != f"build-{index_value:04d}"
            or episode.pool.horizons != EXPECTED_HORIZONS
            or row.get("target_id") != episode.target_id
            or row.get("sha256") != episode.action_pool_sha256
            or row.get("bytes") != episode.action_pool_bytes
        ):
            raise O1C26RunError("exact O1C-0018 BUILD FAP membership differs")

    o1c22_artifacts = o1c22_source.finalized.path / "artifacts"
    o1c22_artifacts_index = _mapping(
        o1c22_source.artifact_index.get("artifacts"),
        "O1C-0022 artifact inventory",
    )
    held_out_offsets = np.empty((FOLD_COUNT, KEY_BITS), dtype=np.float64)
    training_offsets = np.empty((FOLD_COUNT, 3, KEY_BITS), dtype=np.float64)
    training_ordinals: list[tuple[int, int, int]] = []
    offset_members: list[Mapping[str, object]] = []
    bytes_read = (
        len(config_payload)
        + len(metrics_payload)
        + len(index_payload)
        + sum(len(value) for value in payloads.values())
        + o1c22_source.source_artifact_bytes_read
        + corpus.bytes_read
    )
    for fold_index in range(FOLD_COUNT):
        target_id = f"build-{fold_index:04d}"
        calibration_relative = f"folds/{target_id}/calibration/raw_predictions.f64le"
        calibration_freeze_relative = (
            f"folds/{target_id}/calibration/prediction_freeze.json"
        )
        scales_relative = f"folds/{target_id}/heldout/calibration_scales.f64le"
        held_relative = (
            f"folds/build-{fold_index:04d}/heldout/calibrated_predictions.f64le"
        )
        held_freeze_relative = f"folds/{target_id}/heldout/prediction_freeze.json"
        selected_payloads = {
            relative: _indexed_payload(
                o1c22_artifacts,
                o1c22_artifacts_index,
                relative,
                f"O1C-0022 fold {fold_index} {PurePosixPath(relative).name}",
            )
            for relative in (
                calibration_relative,
                calibration_freeze_relative,
                scales_relative,
                held_relative,
                held_freeze_relative,
            )
        }
        bytes_read += sum(len(payload) for payload in selected_payloads.values())
        try:
            calibration_freeze = _mapping(
                json.loads(
                    selected_payloads[calibration_freeze_relative].decode("ascii")
                ),
                f"fold {fold_index} calibration freeze",
            )
            held_freeze = _mapping(
                json.loads(selected_payloads[held_freeze_relative].decode("ascii")),
                f"fold {fold_index} held-out freeze",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise O1C26RunError("O1C-0022 fold freeze is invalid") from exc
        _verify_freeze_document(
            calibration_freeze,
            schema=O1C22_CALIBRATION_FREEZE_SCHEMA,
            field_name=f"fold {fold_index} calibration freeze",
        )
        _verify_freeze_document(
            held_freeze,
            schema=O1C22_PREDICTION_FREEZE_SCHEMA,
            field_name=f"fold {fold_index} held-out freeze",
        )
        calibration_artifacts = _mapping(
            calibration_freeze.get("artifacts"),
            f"fold {fold_index} calibration freeze artifacts",
        )
        held_artifacts = _mapping(
            held_freeze.get("artifacts"),
            f"fold {fold_index} held-out freeze artifacts",
        )
        for relative, inventory in (
            (calibration_relative, calibration_artifacts),
            (scales_relative, held_artifacts),
            (held_relative, held_artifacts),
        ):
            entry = _mapping(
                inventory.get(relative),
                f"fold {fold_index} freeze artifact {relative}",
                {"sha256", "bytes"},
            )
            payload = selected_payloads[relative]
            if entry.get("sha256") != _sha256_bytes(payload) or entry.get(
                "bytes"
            ) != len(payload):
                raise O1C26RunError("O1C-0022 offset freeze commitment differs")
        ordinals = tuple(
            _integer(value, "training ordinal", 0, FOLD_COUNT - 1)
            for value in _sequence(
                calibration_freeze.get("training_ordinals"),
                "training ordinals",
            )
        )
        expected_ordinals = tuple(
            (fold_index + offset) % FOLD_COUNT for offset in range(1, FOLD_COUNT)
        )
        if (
            ordinals != expected_ordinals
            or calibration_freeze.get("held_out_ordinal") != fold_index
            or calibration_freeze.get("held_out_target_id") != target_id
            or calibration_freeze.get("training_target_ids")
            != [f"build-{ordinal:04d}" for ordinal in ordinals]
            or calibration_freeze.get("held_out_label_used_for_this_fold") is not False
            or held_freeze.get("held_out_ordinal") != fold_index
            or held_freeze.get("held_out_target_id") != target_id
            or held_freeze.get("calibration_label_ordinals_used_for_this_fold")
            != list(ordinals)
            or held_freeze.get("held_out_label_used_for_this_fold") is not False
        ):
            raise O1C26RunError("O1C-0022 fold offset/label lifecycle differs")
        training_ordinals.append((ordinals[0], ordinals[1], ordinals[2]))
        raw = np.frombuffer(selected_payloads[calibration_relative], dtype="<f8")
        expected_raw_shape = (3, len(O1C22_PREDICTION_ARMS), KEY_BITS)
        if raw.size != math.prod(expected_raw_shape):
            raise O1C26RunError("O1C-0022 calibration prediction shape differs")
        raw = raw.reshape(expected_raw_shape)
        scales = np.frombuffer(selected_payloads[scales_relative], dtype="<f8")
        if scales.shape != (len(O1C22_PREDICTION_ARMS),):
            raise O1C26RunError("O1C-0022 calibration scale shape differs")
        normalized_index = O1C22_PREDICTION_ARMS.index("normalized_float_delta_sum")
        if (
            not np.all(np.isfinite(raw))
            or not np.all(np.isfinite(scales))
            or scales[normalized_index] < 0.0
        ):
            raise O1C26RunError("O1C-0022 calibration offsets are invalid")
        training_offsets[fold_index] = (
            raw[:, normalized_index, :] * scales[normalized_index]
        )
        held_out_offsets[fold_index] = select_o1c22_logits(
            selected_payloads[held_relative],
            width=256,
            arm="normalized_float_delta_sum",
        )
        offset_members.extend(
            {
                "fold_index": fold_index,
                "target_id": target_id,
                "relative_path": relative,
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
            }
            for relative, payload in selected_payloads.items()
        )
    held_out_offsets = np.ascontiguousarray(held_out_offsets, dtype=np.float64)
    held_out_offsets.setflags(write=False)
    training_offsets = np.ascontiguousarray(training_offsets, dtype=np.float64)
    training_offsets.setflags(write=False)
    label_path = o1c22_artifacts / "labels.bitpack"
    label_entry = _mapping(
        o1c22_artifacts_index.get("labels.bitpack"),
        "O1C-0022 label entry",
        {"sha256", "bytes", "phase"},
    )
    if label_entry.get("bytes") != LABEL_BYTES:
        raise O1C26RunError("O1C-0022 label payload width differs")
    label_sha256 = _sha256(label_entry.get("sha256"), "O1C-0022 label SHA-256")
    mechanism = _proxy_mechanism(config)
    instance = _proxy_instance(
        config,
        mechanism,
        source_receipt,
        o1c22_source,
        corpus,
        held_out_offsets,
        training_offsets,
        training_ordinals,
        offset_members,
        label_sha256,
    )
    selection_receipt = _freeze(
        {
            "schema": SELECTION_RECEIPT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "source_attempt_id": O1C23_ATTEMPT_ID,
            "authoritative_capsule_verified": True,
            "attempt_reservation_authorized": True,
            "o1c23_capsule_manifest_sha256": finalized.manifest_sha256,
            "o1c23_artifact_index_sha256": _sha256_bytes(index_payload),
            "decision_sha256": source_receipt.decision_sha256,
            "operator_graph_sha256": source_receipt.operator_graph_sha256,
            "selected_parent_operator_id": SELECTED_OPERATOR_ID,
            "proxy_operator_id": PROXY_OPERATOR_ID,
            "parent_operator_fingerprint": (source_receipt.parent_operator_fingerprint),
            "proxy_mechanism_sha256": mechanism["proxy_mechanism_sha256"],
            "proxy_instance_fingerprint": instance["proxy_instance_fingerprint"],
            "required_reason_field": "all_real_primary_k256_arms_nonpositive",
            "required_reason_field_value": True,
            "o1c22_capsule_manifest_sha256": (o1c22_source.finalized.manifest_sha256),
            "o1c22_result_sha256": o1c22_source.result["result_sha256"],
        },
        digest_field="selection_receipt_sha256",
    )
    return O1C26PreparedSource(
        o1c23=finalized,
        o1c22=o1c22_source,
        o1c22_run_config=o1c22_run_config,
        decision=decision,
        decision_payload=payloads["decision.json"],
        operator_graph=graph,
        operator_graph_payload=payloads["next_operator_graph.json"],
        selection_receipt=selection_receipt,
        proxy_mechanism=mechanism,
        proxy_instance=instance,
        held_out_offsets=held_out_offsets,
        training_offsets=training_offsets,
        training_ordinals=tuple(training_ordinals),
        offset_members=tuple(offset_members),
        label_payload_path=label_path,
        label_payload_sha256=label_sha256,
        source_artifact_bytes_read=bytes_read,
    )


def preflight_o1c26(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C26Preflight:
    """Validate the complete selection chain without reserving O1C-0026."""

    config = load_o1c26_run_config(path, root=root)
    manager = RunCapsuleManager(config.root)
    recoverable = manager.recoverable_attempt_ids()
    existing = manager.finalized_attempt(ATTEMPT_ID)
    upstream = manager.finalized_attempt(O1C23_ATTEMPT_ID)
    mechanism = _proxy_mechanism(config)
    base = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prerequisite_attempt_id": O1C23_ATTEMPT_ID,
        "o1c26_reserved_by_this_preflight": False,
        "o1c26_existing_finalized": existing is not None,
        "o1c26_existing_recoverable": ATTEMPT_ID in recoverable,
        "o1c23_existing_recoverable": O1C23_ATTEMPT_ID in recoverable,
        "projection_policy_sha256": projection_policy_sha256(),
        "proxy_mechanism_sha256": mechanism["proxy_mechanism_sha256"],
    }
    if upstream is None:
        return O1C26Preflight(
            {
                **base,
                "status": "prerequisite-pending",
                "reason": "reserved finalized O1C-0023 capsule is not available",
            },
            config,
            None,
        )
    try:
        source = _load_o1c23_selection(config, upstream)
    except O1C26SelectionMismatch as exc:
        return O1C26Preflight(
            {
                **base,
                "status": "selection-mismatch",
                "o1c23_manifest_sha256": upstream.manifest_sha256,
                "reason": str(exc),
            },
            config,
            None,
        )
    except Exception as exc:
        return O1C26Preflight(
            {
                **base,
                "status": "prerequisite-invalid",
                "o1c23_manifest_sha256": upstream.manifest_sha256,
                "reason": f"{type(exc).__name__}: {exc}",
            },
            config,
            None,
        )
    return O1C26Preflight(
        {
            **base,
            "status": "ready",
            "o1c23_manifest_sha256": source.o1c23.manifest_sha256,
            "o1c22_manifest_sha256": source.o1c22.finalized.manifest_sha256,
            "o1c22_result_sha256": source.o1c22.result["result_sha256"],
            "selected_parent_operator_id": SELECTED_OPERATOR_ID,
            "proxy_operator_id": PROXY_OPERATOR_ID,
            "proxy_instance_fingerprint": source.proxy_instance[
                "proxy_instance_fingerprint"
            ],
            "build_faps": len(source.pools),
            "development_faps_deserialized": 0,
            "source_artifact_bytes_read": source.source_artifact_bytes_read,
        },
        config,
        source,
    )


PersistArtifact = Callable[[str, bytes, str], Path]


@dataclass
class O1C26WorkLedger:
    proxy_instance_fingerprint: str = ""
    build_faps_deserialized: int = 0
    development_faps_deserialized: int = 0
    fap_float32_values_deserialized: int = 0
    label_payload_reads: int = 0
    label_vector_parses: int = 0
    learned_projection_rows: int = 0
    branch_swap_projection_rows: int = 0
    diagnostic_projection_rows: int = 0
    ridge_fits: int = 0
    alpha_bit_evaluations: int = 0
    diagnostic_bit_evaluations: int = 0
    training_label_bit_uses: int = 0
    scored_label_bit_uses: int = 0
    fresh_targets: int = 0
    native_solver_branches: int = 0
    scientific_entropy_calls: int = 0
    sibling_reads: int = 0
    sibling_writes: int = 0
    mps_calls: int = 0
    gpu_calls: int = 0
    maximum_live_state_bytes: int = 0
    maximum_observed_projection_scratch_bytes: int = 0
    accounted_numeric_projection_payload_bytes: int = 0
    primary_state_replays: int = 0
    primary_state_replay_coordinates: int = 0
    inner_prediction_freezes_persisted_and_reloaded: int = 0
    outer_prediction_freezes_persisted: int = 0
    held_out_logit_artifacts_reloaded_for_score: int = 0
    prediction_set_freezes_persisted: int = 0
    primary_batch_vs_state_max_abs: float = 0.0
    projection_frozen_before_label_parse: bool = False
    every_inner_prediction_frozen_before_alpha_selection: bool = False
    every_outer_prediction_frozen_before_own_fold_scoring: bool = False
    own_fold_label_used_in_fit: bool = False
    cross_fold_labels_used_as_training_data: bool = True
    capsule_integrity_scan_may_hash_label_member: bool = True
    sibling_scope: str = "external_w52_tree_only"

    def validate(self) -> None:
        _sha256(self.proxy_instance_fingerprint, "work proxy instance")
        expected = {
            "build_faps_deserialized": FOLD_COUNT,
            "development_faps_deserialized": 0,
            "fap_float32_values_deserialized": EXPECTED_FAP_VALUES,
            "label_payload_reads": 1,
            "label_vector_parses": 1,
            "learned_projection_rows": FOLD_COUNT * len(LEARNED_ARMS) * KEY_BITS,
            "branch_swap_projection_rows": FOLD_COUNT * len(LEARNED_ARMS) * KEY_BITS,
            "diagnostic_projection_rows": FOLD_COUNT
            * len(DIAGNOSTIC_ABLATIONS)
            * KEY_BITS,
            "ridge_fits": EXPECTED_RIDGE_FITS,
            "alpha_bit_evaluations": EXPECTED_ALPHA_EVALUATIONS,
            "diagnostic_bit_evaluations": EXPECTED_DIAGNOSTIC_EVALUATIONS,
            "training_label_bit_uses": (FOLD_COUNT * len(LEARNED_ARMS) * 3 * KEY_BITS),
            "scored_label_bit_uses": FOLD_COUNT * len(SCORE_ARMS) * KEY_BITS,
            "fresh_targets": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "maximum_live_state_bytes": LIVE_STATE_BYTES,
            "primary_state_replays": FOLD_COUNT,
            "primary_state_replay_coordinates": FOLD_COUNT * KEY_BITS,
            "inner_prediction_freezes_persisted_and_reloaded": (EXPECTED_INNER_FREEZES),
            "outer_prediction_freezes_persisted": EXPECTED_INNER_FREEZES,
            "held_out_logit_artifacts_reloaded_for_score": (EXPECTED_INNER_FREEZES),
            "prediction_set_freezes_persisted": 1,
            "accounted_numeric_projection_payload_bytes": (
                ACCOUNTED_NUMERIC_PAYLOAD_BYTES
            ),
            "projection_frozen_before_label_parse": True,
            "every_inner_prediction_frozen_before_alpha_selection": True,
            "every_outer_prediction_frozen_before_own_fold_scoring": True,
            "own_fold_label_used_in_fit": False,
            "cross_fold_labels_used_as_training_data": True,
            "capsule_integrity_scan_may_hash_label_member": True,
            "sibling_scope": "external_w52_tree_only",
        }
        if any(getattr(self, name) != value for name, value in expected.items()):
            raise O1C26RunError("O1C-0026 structural work differs")
        if not (
            0
            < self.maximum_observed_projection_scratch_bytes
            <= PROCESS_LOCAL_SCRATCH_CEILING_BYTES
        ):
            raise O1C26RunError("O1C-0026 projection scratch differs")
        if (
            not math.isfinite(self.primary_batch_vs_state_max_abs)
            or self.primary_batch_vs_state_max_abs < 0.0
            or self.primary_batch_vs_state_max_abs > 1e-12
        ):
            raise O1C26RunError("O1C-0026 state replay residual differs")

    def document(self) -> dict[str, object]:
        unsigned = {
            "schema": WORK_LEDGER_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
        }
        return {
            **unsigned,
            "work_ledger_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
        }

    @classmethod
    def from_document(cls, value: object) -> "O1C26WorkLedger":
        document = _mapping(value, "structural work ledger")
        expected = {
            "schema",
            "attempt_id",
            "work_ledger_sha256",
            *cls.__dataclass_fields__,
        }
        if (
            set(document) != expected
            or document.get("schema") != WORK_LEDGER_SCHEMA
            or document.get("attempt_id") != ATTEMPT_ID
        ):
            raise O1C26RunError("structural work-ledger identity differs")
        defaults = cls()
        values: dict[str, object] = {}
        for name in cls.__dataclass_fields__:
            item = document[name]
            default = getattr(defaults, name)
            if isinstance(default, bool):
                if not isinstance(item, bool):
                    raise O1C26RunError(f"work field {name} must be boolean")
            elif isinstance(default, int):
                _integer(item, f"work field {name}", 0, 1 << 60)
            elif isinstance(default, float):
                _number(item, f"work field {name}", 0.0, float(1 << 60))
            elif not isinstance(item, str):
                raise O1C26RunError(f"work field {name} must be a string")
            values[name] = item
        result = cls(**values)  # type: ignore[arg-type]
        result.validate()
        if result.document() != dict(document):
            raise O1C26RunError("structural work-ledger reconstruction differs")
        return result


def _recomputed_budget_checks(
    budgets: O1C26Budgets,
    metrics: Mapping[str, object],
    work_document: Mapping[str, object],
    persistent_artifact_bytes: int,
    expected_source_artifact_bytes: int,
) -> dict[str, bool]:
    work = O1C26WorkLedger.from_document(work_document)
    cpu_seconds = _number(
        metrics.get("cpu_seconds"), "metric CPU seconds", 0.0, 1_000_000.0
    )
    wall_seconds = _number(
        metrics.get("wall_seconds"), "metric wall seconds", 0.0, 1_000_000.0
    )
    pre_capsule_wall_seconds = _number(
        metrics.get("pre_capsule_wall_seconds"),
        "pre-capsule wall seconds",
        0.0,
        1_000_000.0,
    )
    if pre_capsule_wall_seconds > wall_seconds:
        raise O1C26RunError("pre-capsule wall accounting differs")
    peak_rss_bytes = _integer(
        metrics.get("peak_rss_bytes"), "metric peak RSS", 0, 1 << 60
    )
    if (
        metrics.get("publication_cpu_reserve_seconds")
        != PUBLICATION_CPU_RESERVE_SECONDS
        or metrics.get("publication_wall_reserve_seconds")
        != PUBLICATION_WALL_RESERVE_SECONDS
        or metrics.get("publication_rss_reserve_bytes") != PUBLICATION_RSS_RESERVE_BYTES
    ):
        raise O1C26RunError("publication reserve envelope differs")
    budgeted_cpu_seconds = _number(
        metrics.get("budgeted_cpu_seconds"),
        "budgeted CPU seconds",
        0.0,
        1_000_000.0,
    )
    budgeted_wall_seconds = _number(
        metrics.get("budgeted_wall_seconds"),
        "budgeted wall seconds",
        0.0,
        1_000_000.0,
    )
    budgeted_peak_rss_bytes = _integer(
        metrics.get("budgeted_peak_rss_bytes"),
        "budgeted peak RSS",
        0,
        1 << 60,
    )
    if (
        budgeted_cpu_seconds != cpu_seconds + PUBLICATION_CPU_RESERVE_SECONDS
        or budgeted_wall_seconds != wall_seconds + PUBLICATION_WALL_RESERVE_SECONDS
        or budgeted_peak_rss_bytes != peak_rss_bytes + PUBLICATION_RSS_RESERVE_BYTES
    ):
        raise O1C26RunError("budgeted resource envelope differs")
    source_bytes = _integer(
        metrics.get("source_artifact_bytes_read"),
        "metric source artifact bytes",
        0,
        1 << 60,
    )
    if source_bytes != expected_source_artifact_bytes:
        raise O1C26RunError("source artifact accounting binding differs")
    supplied_persistent_bytes = _integer(
        metrics.get("persistent_artifact_bytes"),
        "metric persistent artifact bytes",
        0,
        1 << 60,
    )
    if supplied_persistent_bytes != persistent_artifact_bytes:
        raise O1C26RunError("persistent artifact accounting binding differs")
    work_metric_fields = (
        "build_faps_deserialized",
        "development_faps_deserialized",
        "ridge_fits",
        "alpha_bit_evaluations",
        "diagnostic_bit_evaluations",
        "fresh_targets",
        "native_solver_branches",
        "scientific_entropy_calls",
        "sibling_reads",
        "sibling_writes",
        "mps_calls",
        "gpu_calls",
        "maximum_observed_projection_scratch_bytes",
        "maximum_live_state_bytes",
        "primary_state_replays",
        "primary_state_replay_coordinates",
    )
    bound_work: dict[str, int] = {}
    for name in work_metric_fields:
        supplied = _integer(metrics.get(name), f"metric {name}", 0, 1 << 60)
        actual = getattr(work, name)
        if supplied != actual:
            raise O1C26RunError(f"metric/work binding differs: {name}")
        bound_work[name] = supplied
    if (
        metrics.get("sibling_scope") != work.sibling_scope
        or work.sibling_scope != "external_w52_tree_only"
    ):
        raise O1C26RunError("metric/work sibling scope differs")
    return {
        "cpu": budgeted_cpu_seconds <= budgets.maximum_cpu_seconds,
        "wall": budgeted_wall_seconds <= budgets.maximum_wall_seconds,
        "resident_memory": budgeted_peak_rss_bytes
        <= budgets.maximum_resident_memory_mib * 1024 * 1024,
        "source_artifact_bytes_read": source_bytes
        <= budgets.maximum_source_artifact_bytes_read,
        "persistent_artifacts": supplied_persistent_bytes
        <= budgets.maximum_persistent_artifact_bytes,
        "build_faps": bound_work["build_faps_deserialized"]
        == budgets.expected_build_faps,
        "ridge_fits": bound_work["ridge_fits"] == budgets.expected_ridge_fits,
        "alpha_bit_evaluations": bound_work["alpha_bit_evaluations"]
        == budgets.expected_alpha_bit_evaluations,
        "diagnostic_bit_evaluations": bound_work["diagnostic_bit_evaluations"]
        == budgets.expected_diagnostic_bit_evaluations,
        "development_faps": bound_work["development_faps_deserialized"]
        == budgets.maximum_development_faps_deserialized,
        "fresh_targets": bound_work["fresh_targets"] == budgets.maximum_fresh_targets,
        "native_solver_branches": bound_work["native_solver_branches"]
        == budgets.maximum_native_solver_branches,
        "scientific_entropy": bound_work["scientific_entropy_calls"]
        == budgets.maximum_scientific_entropy_calls,
        "sibling_reads": bound_work["sibling_reads"] == budgets.maximum_sibling_reads,
        "sibling_writes": bound_work["sibling_writes"]
        == budgets.maximum_sibling_writes,
        "mps": bound_work["mps_calls"] == budgets.maximum_mps_calls,
        "gpu": bound_work["gpu_calls"] == budgets.maximum_gpu_calls,
        "live_state": bound_work["maximum_live_state_bytes"]
        == budgets.maximum_live_state_bytes,
        "projection_scratch": bound_work["maximum_observed_projection_scratch_bytes"]
        <= budgets.maximum_projection_scratch_bytes,
    }


@dataclass(frozen=True)
class O1C26ScienceOutcome:
    report: Mapping[str, object]
    work: O1C26WorkLedger
    projection_freeze_sha256: str
    prediction_set_freeze_sha256: str
    label_access_receipt_sha256: str


def _little_f8(value: np.ndarray, shape: tuple[int, ...], field_name: str) -> bytes:
    array = np.asarray(value)
    if (
        array.shape != shape
        or array.dtype != np.float64
        or not np.all(np.isfinite(array))
    ):
        raise O1C26RunError(f"{field_name} must be finite float64{shape}")
    return array.astype("<f8", copy=False).tobytes(order="C")


def _load_little_f8(path: Path, shape: tuple[int, ...], field_name: str) -> np.ndarray:
    payload = path.read_bytes()
    if len(payload) != math.prod(shape) * 8:
        raise O1C26RunError(f"{field_name} byte shape differs")
    array = np.frombuffer(payload, dtype="<f8").reshape(shape).copy()
    if not np.all(np.isfinite(array)):
        raise O1C26RunError(f"{field_name} is non-finite")
    array.setflags(write=False)
    return array


def _decode_labels(payload: bytes) -> tuple[np.ndarray, np.ndarray]:
    if len(payload) != LABEL_BYTES:
        raise O1C26RunError("label payload must be exactly 128 bytes")
    bits = np.unpackbits(
        np.frombuffer(payload, dtype=np.uint8), bitorder="little"
    ).reshape(FOLD_COUNT, KEY_BITS)
    bits = np.ascontiguousarray(bits, dtype=np.uint8)
    signs = bits.astype(np.float64) * 2.0 - 1.0
    bits.setflags(write=False)
    signs.setflags(write=False)
    return bits, signs


def _binary_nll_bits(logits: np.ndarray, labels: np.ndarray) -> float:
    checked_logits = np.asarray(logits)
    checked_labels = np.asarray(labels)
    if (
        checked_logits.shape != (KEY_BITS,)
        or checked_labels.shape != (KEY_BITS,)
        or checked_logits.dtype != np.float64
        or checked_labels.dtype != np.float64
        or not np.all(np.isfinite(checked_logits))
        or not np.all(np.logical_or(checked_labels == -1.0, checked_labels == 1.0))
    ):
        raise O1C26RunError("NLL inputs differ")
    value = float(
        np.sum(
            np.logaddexp(0.0, -(checked_labels * checked_logits)),
            dtype=np.float64,
        )
        / math.log(2.0)
    )
    if not math.isfinite(value):
        raise O1C26RunError("NLL is non-finite")
    return value


def _scored_report(
    predictions: np.ndarray,
    labels_bits: np.ndarray,
    labels_signs: np.ndarray,
    alphas: np.ndarray,
    *,
    offset_freeze_sha256: str,
    projection_freeze_sha256: str,
    prediction_set_freeze_sha256: str,
    label_access_receipt_sha256: str,
    selection_receipt_sha256: str,
    work_ledger_sha256: str,
    proxy_instance_fingerprint: str,
    parent_operator_fingerprint: str,
) -> tuple[dict[str, object], np.ndarray, np.ndarray, np.ndarray]:
    expected_shape = (FOLD_COUNT, len(SCORE_ARMS), KEY_BITS)
    if (
        predictions.shape != expected_shape
        or predictions.dtype != np.float64
        or not np.all(np.isfinite(predictions))
        or labels_bits.shape != (FOLD_COUNT, KEY_BITS)
        or labels_bits.dtype != np.uint8
        or not np.all(np.logical_or(labels_bits == 0, labels_bits == 1))
        or labels_signs.shape != (FOLD_COUNT, KEY_BITS)
        or labels_signs.dtype != np.float64
        or not np.array_equal(labels_signs, labels_bits.astype(np.float64) * 2.0 - 1.0)
        or alphas.shape != (FOLD_COUNT, len(LEARNED_ARMS))
        or alphas.dtype != np.float64
        or not np.all(np.isfinite(alphas))
        or not np.all(np.isin(alphas, np.asarray(ALPHA_GRID, dtype=np.float64)))
    ):
        raise O1C26RunError("scoring inventory differs")
    for value, field_name in (
        (offset_freeze_sha256, "offset freeze"),
        (projection_freeze_sha256, "projection freeze"),
        (prediction_set_freeze_sha256, "prediction-set freeze"),
        (label_access_receipt_sha256, "label-access receipt"),
        (selection_receipt_sha256, "selection receipt"),
        (work_ledger_sha256, "work ledger"),
        (proxy_instance_fingerprint, "proxy instance"),
        (parent_operator_fingerprint, "parent operator"),
    ):
        _sha256(value, field_name)
    nll = np.empty((FOLD_COUNT, len(SCORE_ARMS)), dtype=np.float64)
    compression = np.empty_like(nll)
    correct = np.empty((FOLD_COUNT, len(SCORE_ARMS)), dtype=np.uint16)
    summaries: dict[str, object] = {}
    for arm_index, arm in enumerate(SCORE_ARMS):
        fold_rows: list[dict[str, object]] = []
        for fold_index in range(FOLD_COUNT):
            logits = predictions[fold_index, arm_index]
            nll_value = _binary_nll_bits(logits, labels_signs[fold_index])
            compression_value = KEY_BITS - nll_value
            # Exact logit zero uses the globally frozen MAP tie bit 0.
            map_bits = (logits > 0.0).astype(np.uint8)
            correct_value = int(np.sum(map_bits == labels_bits[fold_index]))
            nll[fold_index, arm_index] = nll_value
            compression[fold_index, arm_index] = compression_value
            correct[fold_index, arm_index] = correct_value
            fold_rows.append(
                {
                    "fold_index": fold_index,
                    "target_id": f"build-{fold_index:04d}",
                    "nll_bits": nll_value,
                    "compression_bits": compression_value,
                    "correct_bits": correct_value,
                }
            )
        summaries[arm] = {
            "folds": fold_rows,
            "mean_nll_bits": float(nll[:, arm_index].mean()),
            "mean_compression_bits": float(compression[:, arm_index].mean()),
            "minimum_compression_bits": float(compression[:, arm_index].min()),
            "maximum_compression_bits": float(compression[:, arm_index].max()),
            "mean_correct_bits": float(correct[:, arm_index].mean()),
            "positive_folds": int(np.sum(compression[:, arm_index] > 0.0)),
        }

    indices = {name: index for index, name in enumerate(SCORE_ARMS)}
    primary = compression[:, indices[PRIMARY_ARM]]
    offset = compression[:, indices[OFFSET_ARM]]
    improvement = primary - offset
    means = {name: float(compression[:, indices[name]].mean()) for name in SCORE_ARMS}
    control_margins = {
        f"primary_minus_{name}_mean_compression_bits": means[PRIMARY_ARM] - means[name]
        for name in (OFFSET_ARM, *LEARNED_ARMS[1:])
    }
    ablation_drops = {
        f"primary_minus_{name}_mean_compression_bits": means[PRIMARY_ARM] - means[name]
        for name in DIAGNOSTIC_ABLATIONS
    }
    gates = {
        "all_primary_folds_positive": bool(np.all(primary > 0.0)),
        "primary_mean_compression_at_least_one_bit": means[PRIMARY_ARM] >= 1.0,
        "all_primary_folds_improve_offset": bool(np.all(improvement > 0.0)),
        "primary_mean_improvement_at_least_one_bit": float(improvement.mean()) >= 1.0,
        "primary_beats_pair_identity_shuffled": means[PRIMARY_ARM]
        > means[LEARNED_ARMS[1]],
        "primary_beats_additive_factorized": means[PRIMARY_ARM]
        > means[LEARNED_ARMS[2]],
        "primary_beats_polarity_even_common_mode": means[PRIMARY_ARM]
        > means[LEARNED_ARMS[3]],
    }
    passed = all(gates.values())
    breadcrumbs = {
        "primary_absolute_signal_null": not (
            gates["all_primary_folds_positive"]
            and gates["primary_mean_compression_at_least_one_bit"]
        ),
        "outer_fold_nonportable": not (
            gates["all_primary_folds_positive"]
            and gates["all_primary_folds_improve_offset"]
        ),
        "pair_identity_not_specific": not gates["primary_beats_pair_identity_shuffled"],
        "bilinear_not_needed": not gates["primary_beats_additive_factorized"],
        "common_mode_not_rejected": not gates[
            "primary_beats_polarity_even_common_mode"
        ],
        "exact_conflict_ablation_material": ablation_drops[
            "primary_minus_without_exact_conflict_mean_compression_bits"
        ]
        >= ABLATION_MATERIAL_BITS,
        "motif_ablation_material": ablation_drops[
            "primary_minus_without_motif_mean_compression_bits"
        ]
        >= ABLATION_MATERIAL_BITS,
    }
    unsigned = {
        "schema": SCORE_REPORT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "classification": PRESENT if passed else NULL,
        "scientific_success_gate_passed": passed,
        "claim_boundary": {
            "retrospective_consumed_build_leave_one_out": True,
            "fullround_chacha20_public_fap_replay": True,
            "unknown_key_bits_at_heldout_probe": KEY_BITS,
            "fresh_target_consumed": False,
            "disjoint_evaluation_claimed": False,
            "exact_key_recovery_claimed": False,
            "native_solver_speedup_claimed": False,
            "parent_r07_closed_by_proxy_null": False,
        },
        "closure_candidate": {
            "eligible_only_after_completed_operational_capsule": True,
            "disposition_if_authoritative": "NO_LIFT" if not passed else None,
            "proxy_instance_fingerprint": proxy_instance_fingerprint,
            "parent_operator_fingerprint": parent_operator_fingerprint,
            "parent_closed": False,
        },
        "map_tie_policy": "exact_zero_logit_maps_to_bit_zero",
        "score_arm_order": list(SCORE_ARMS),
        "arms": summaries,
        "alphas_by_fold_and_learned_arm": alphas.tolist(),
        "learned_arm_order": list(LEARNED_ARMS),
        "primary_minus_offset_by_fold_bits": improvement.tolist(),
        "control_margins": control_margins,
        "diagnostic_ablation_drops": ablation_drops,
        "ablation_material_threshold_bits": ABLATION_MATERIAL_BITS,
        "gates": gates,
        "failed_gates": sorted(name for name, value in gates.items() if not value),
        "breadcrumbs": breadcrumbs,
        "projection_policy_sha256": projection_policy_sha256(),
        "proxy_instance_fingerprint": proxy_instance_fingerprint,
        "parent_operator_fingerprint": parent_operator_fingerprint,
        "offset_freeze_sha256": offset_freeze_sha256,
        "projection_freeze_sha256": projection_freeze_sha256,
        "prediction_set_freeze_sha256": prediction_set_freeze_sha256,
        "label_access_receipt_sha256": label_access_receipt_sha256,
        "selection_receipt_sha256": selection_receipt_sha256,
        "work_ledger_sha256": work_ledger_sha256,
        "state": {
            "effective_weight_bytes": FEATURE_WIDTH * 8,
            "posterior_bytes": KEY_BITS * 8,
            "live_reader_plus_posterior_bytes": LIVE_STATE_BYTES,
            "stream_length_dependent_state_bytes": 0,
            "external_index_bytes": 0,
        },
    }
    report = {
        **unsigned,
        "score_report_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }
    return report, nll, compression, correct


def run_o1c26_science(
    source: O1C26PreparedSource,
    persist: PersistArtifact,
) -> O1C26ScienceOutcome:
    """Execute one complete 4x4 BUILD-LOO residual experiment."""

    if not isinstance(source, O1C26PreparedSource):
        raise TypeError("source must be O1C26PreparedSource")
    pools = source.pools
    if len(pools) != FOLD_COUNT or any(
        pool.horizons != EXPECTED_HORIZONS for pool in pools
    ):
        raise O1C26RunError("science source FAP inventory differs")
    work = O1C26WorkLedger()
    work.proxy_instance_fingerprint = _sha256(
        source.proxy_instance.get("proxy_instance_fingerprint"),
        "science proxy instance",
    )
    work.build_faps_deserialized = len(pools)
    work.fap_float32_values_deserialized = sum(
        int(pool.branch_features.size) for pool in pools
    )
    work.accounted_numeric_projection_payload_bytes = ACCOUNTED_NUMERIC_PAYLOAD_BYTES
    if tracemalloc.is_tracing():
        raise O1C26RunError("projection scratch tracer is already active")

    held_offset_payload = _little_f8(
        source.held_out_offsets,
        (FOLD_COUNT, KEY_BITS),
        "held-out offsets",
    )
    training_offset_payload = _little_f8(
        source.training_offsets,
        (FOLD_COUNT, 3, KEY_BITS),
        "training offsets",
    )
    held_offset_path = persist(
        "offsets/held_out_normalized_float.f64le",
        held_offset_payload,
        "OFFSET_INPUT_FROZEN_PRE_LABEL",
    )
    training_offset_path = persist(
        "offsets/training_same_reader_normalized_float.f64le",
        training_offset_payload,
        "OFFSET_INPUT_FROZEN_PRE_LABEL",
    )
    offset_freeze = _freeze(
        {
            "schema": OFFSET_FREEZE_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
            "offset_arm": OFFSET_ARM,
            "held_out_shape": [FOLD_COUNT, KEY_BITS],
            "training_shape": [FOLD_COUNT, 3, KEY_BITS],
            "training_ordinals_by_outer_fold": [
                list(values) for values in source.training_ordinals
            ],
            "held_out_offsets_sha256": _sha256_bytes(held_offset_payload),
            "training_offsets_sha256": _sha256_bytes(training_offset_payload),
            "source_members": list(source.offset_members),
            "label_payload_reads": 0,
            "label_vector_parses": 0,
        },
        digest_field="offset_freeze_sha256",
    )
    persist(
        "offset_freeze.json",
        canonical_json_bytes(offset_freeze),
        "OFFSET_INPUT_FROZEN_PRE_LABEL",
    )
    if held_offset_path.read_bytes() != held_offset_payload or (
        training_offset_path.read_bytes() != training_offset_payload
    ):
        raise O1C26RunError("persisted offset bytes differ")

    feature_paths: dict[str, Path] = {}
    feature_rows: dict[str, object] = {}
    branch_residuals: dict[str, float] = {}
    for arm in LEARNED_ARMS:
        feature_tensor = np.empty(FEATURE_SHAPE, dtype=np.float64)
        maximum_residual = 0.0
        for fold_index, pool in enumerate(pools):
            primary = project_pool(pool, arm=arm)
            swapped = project_pool(pool.polarity_swapped(), arm=arm)
            residual = (
                np.abs(swapped - primary)
                if arm == LEARNED_ARMS[-1]
                else np.abs(swapped + primary)
            )
            maximum_residual = max(maximum_residual, float(np.max(residual)))
            if maximum_residual > 1e-12:
                raise O1C26RunError(f"{arm} branch-swap invariant failed")
            feature_tensor[fold_index] = primary
            work.learned_projection_rows += KEY_BITS
            work.branch_swap_projection_rows += KEY_BITS
        payload = _little_f8(feature_tensor, FEATURE_SHAPE, f"{arm} features")
        relative = f"features/{arm}.f64le"
        feature_paths[arm] = persist(relative, payload, "ALL_FEATURES_FROZEN_PRE_LABEL")
        feature_rows[arm] = {
            "relative_path": relative,
            "shape": list(FEATURE_SHAPE),
            "dtype": "float64le",
            "bytes": len(payload),
            "sha256": _sha256_bytes(payload),
        }
        branch_residuals[arm] = maximum_residual
        del feature_tensor
    projection_freeze = _freeze(
        {
            "schema": PROJECTION_FREEZE_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
            "phase": "ALL_FOUR_BUILD_X_FOUR_ARM_FEATURES_FROZEN_BEFORE_LABEL_PARSE",
            "projection_policy_sha256": projection_policy_sha256(),
            "offset_freeze_sha256": offset_freeze["offset_freeze_sha256"],
            "build_faps": [
                {
                    "ordinal": episode.ordinal,
                    "target_id": episode.target_id,
                    "sha256": episode.action_pool_sha256,
                    "bytes": episode.action_pool_bytes,
                }
                for episode in source.o1c22_run_config.corpus.episodes
            ],
            "feature_artifacts": feature_rows,
            "branch_swap_maximum_absolute_residual": branch_residuals,
            "branch_swap_tolerance": 1e-12,
            "build_faps_deserialized": FOLD_COUNT,
            "development_faps_deserialized": 0,
            "label_payload_reads": 0,
            "label_vector_parses": 0,
        },
        digest_field="projection_freeze_sha256",
    )
    projection_freeze_path = persist(
        "projection_freeze.json",
        canonical_json_bytes(projection_freeze),
        "ALL_FEATURES_FROZEN_PRE_LABEL",
    )
    if not projection_freeze_path.is_file():
        raise O1C26RunError("projection freeze was not persisted")
    work.projection_frozen_before_label_parse = True

    label_payload = source.label_payload_path.read_bytes()
    work.label_payload_reads += 1
    if _sha256_bytes(label_payload) != source.label_payload_sha256:
        raise O1C26RunError("label payload changed after projection freeze")
    labels_bits, labels_signs = _decode_labels(label_payload)
    work.label_vector_parses += 1

    predictions = np.empty((FOLD_COUNT, len(SCORE_ARMS), KEY_BITS), dtype=np.float64)
    predictions[:, SCORE_ARMS.index(OFFSET_ARM), :] = source.held_out_offsets
    weights = np.empty((FOLD_COUNT, len(LEARNED_ARMS), FEATURE_WIDTH), dtype=np.float64)
    alphas = np.empty((FOLD_COUNT, len(LEARNED_ARMS)), dtype=np.float64)
    outer_freezes: list[Mapping[str, object]] = []
    for arm_index, arm in enumerate(LEARNED_ARMS):
        feature_tensor = _load_little_f8(
            feature_paths[arm], FEATURE_SHAPE, f"persisted {arm} features"
        )
        for fold_index in range(FOLD_COUNT):
            ordinals = source.training_ordinals[fold_index]
            if fold_index in ordinals or sorted(ordinals) != [
                value for value in range(FOLD_COUNT) if value != fold_index
            ]:
                raise O1C26RunError("own-fold label entered training inventory")
            train_features = [feature_tensor[ordinal] for ordinal in ordinals]
            train_labels = [labels_signs[ordinal] for ordinal in ordinals]
            train_offsets = [
                source.training_offsets[fold_index, index] for index in range(3)
            ]
            work.training_label_bit_uses += 3 * KEY_BITS
            inner = fit_inner_oof(train_features, train_labels, train_offsets)
            work.ridge_fits += inner.ridge_fits
            prefix = f"folds/build-{fold_index:04d}/{arm}"
            inner_payload = inner.raw_prediction_bytes
            inner_path = persist(
                f"{prefix}/inner_raw_predictions.f64le",
                inner_payload,
                "INNER_PREDICTIONS_FROZEN_PRE_ALPHA",
            )
            inner_freeze = _freeze(
                {
                    "schema": INNER_FREEZE_SCHEMA,
                    "attempt_id": ATTEMPT_ID,
                    "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
                    "projection_freeze_sha256": projection_freeze[
                        "projection_freeze_sha256"
                    ],
                    "fold_index": fold_index,
                    "held_out_ordinal": fold_index,
                    "held_out_target_id": f"build-{fold_index:04d}",
                    "arm": arm,
                    "training_ordinals": list(ordinals),
                    "training_target_ids": [
                        f"build-{ordinal:04d}" for ordinal in ordinals
                    ],
                    "held_out_label_used_in_fit": False,
                    "same_label_may_be_training_data_in_other_folds": True,
                    "inner_raw_predictions_sha256": _sha256_bytes(inner_payload),
                    "inner_raw_predictions_shape": [3, KEY_BITS],
                    "regularizations": list(inner.regularizations),
                    "ridge_fits": inner.ridge_fits,
                    "alpha_selection_started": False,
                },
                digest_field="inner_freeze_sha256",
            )
            inner_freeze_path = persist(
                f"{prefix}/inner_prediction_freeze.json",
                canonical_json_bytes(inner_freeze),
                "INNER_PREDICTIONS_FROZEN_PRE_ALPHA",
            )
            if (
                inner_path.read_bytes() != inner_payload
                or inner_freeze_path.read_bytes() != canonical_json_bytes(inner_freeze)
            ):
                raise O1C26RunError("persisted inner freeze differs")
            reloaded_inner = FrozenInnerOOF(
                raw_predictions=_load_little_f8(
                    inner_path,
                    (3, KEY_BITS),
                    f"fold {fold_index} {arm} inner predictions",
                ),
                regularizations=inner.regularizations,
                ridge_fits=inner.ridge_fits,
            )
            if reloaded_inner.raw_prediction_bytes != inner_payload:
                raise O1C26RunError("reloaded inner predictions differ")
            work.inner_prediction_freezes_persisted_and_reloaded += 1
            outer = finish_outer_fold(
                train_features,
                train_labels,
                train_offsets,
                feature_tensor[fold_index],
                source.held_out_offsets[fold_index],
                reloaded_inner,
            )
            work.ridge_fits += 1
            work.alpha_bit_evaluations += outer.alpha_bit_evaluations
            weights[fold_index, arm_index] = outer.effective_weights
            alphas[fold_index, arm_index] = outer.alpha
            weight_payload = outer.effective_weight_bytes
            weight_path = persist(
                f"{prefix}/effective_weights.f64le",
                weight_payload,
                "OUTER_PREDICTION_FROZEN_PRE_OWN_FOLD_SCORE",
            )
            if weight_path.read_bytes() != weight_payload:
                raise O1C26RunError("persisted effective weights differ")
            reloaded_weights = _load_little_f8(
                weight_path,
                (FEATURE_WIDTH,),
                f"fold {fold_index} {arm} effective weights",
            )
            if (
                _little_f8(
                    reloaded_weights,
                    (FEATURE_WIDTH,),
                    f"fold {fold_index} {arm} reloaded effective weights",
                )
                != weight_payload
            ):
                raise O1C26RunError("reloaded effective weight bytes differ")
            batch_reference_payload = _little_f8(
                outer.held_out_logits,
                (KEY_BITS,),
                f"fold {fold_index} {arm} batch-reference logits",
            )
            state_replay_passed = False
            state_replay_coordinates = 0
            batch_vs_state_max_abs = 0.0
            live_state_bytes = 0
            if arm == PRIMARY_ARM:
                state = ProjectedResidualState(reloaded_weights)
                if (
                    state.live_state_bytes != LIVE_STATE_BYTES
                    or _little_f8(
                        state.effective_weights,
                        (FEATURE_WIDTH,),
                        f"fold {fold_index} state weights",
                    )
                    != weight_payload
                ):
                    raise O1C26RunError("primary streaming state differs")
                work.maximum_live_state_bytes = max(
                    work.maximum_live_state_bytes, state.live_state_bytes
                )
                for coordinate in range(KEY_BITS):
                    offset = float(source.held_out_offsets[fold_index, coordinate])
                    tracemalloc.start()
                    try:
                        state.infer_coordinate(
                            pools[fold_index], coordinate, offset=offset
                        )
                        _, scratch_peak = tracemalloc.get_traced_memory()
                    finally:
                        tracemalloc.stop()
                    work.maximum_observed_projection_scratch_bytes = max(
                        work.maximum_observed_projection_scratch_bytes,
                        scratch_peak,
                    )
                    if scratch_peak > PROCESS_LOCAL_SCRATCH_CEILING_BYTES:
                        raise O1C26RunError(
                            "primary state projection scratch exceeded ceiling"
                        )
                    state_replay_coordinates += 1
                selected_logits = state.posterior()
                absolute = np.abs(selected_logits - outer.held_out_logits)
                batch_vs_state_max_abs = float(np.max(absolute))
                if batch_vs_state_max_abs > 1e-12:
                    raise O1C26RunError(
                        "primary streaming replay differs from batch reference"
                    )
                work.primary_batch_vs_state_max_abs = max(
                    work.primary_batch_vs_state_max_abs,
                    batch_vs_state_max_abs,
                )
                work.primary_state_replays += 1
                work.primary_state_replay_coordinates += state_replay_coordinates
                state_replay_passed = True
            else:
                selected_logits = outer.held_out_logits
            prediction_payload = _little_f8(
                selected_logits,
                (KEY_BITS,),
                f"fold {fold_index} {arm} held-out logits",
            )
            prediction_path = persist(
                f"{prefix}/held_out_logits.f64le",
                prediction_payload,
                "OUTER_PREDICTION_FROZEN_PRE_OWN_FOLD_SCORE",
            )
            reloaded_prediction = _load_little_f8(
                prediction_path,
                (KEY_BITS,),
                f"fold {fold_index} {arm} held-out logits",
            )
            if (
                _little_f8(
                    reloaded_prediction,
                    (KEY_BITS,),
                    f"fold {fold_index} {arm} reloaded held-out logits",
                )
                != prediction_payload
            ):
                raise O1C26RunError("reloaded held-out logits differ")
            predictions[fold_index, SCORE_ARMS.index(arm)] = reloaded_prediction
            work.held_out_logit_artifacts_reloaded_for_score += 1
            outer_freeze = _freeze(
                {
                    "schema": OUTER_FREEZE_SCHEMA,
                    "attempt_id": ATTEMPT_ID,
                    "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
                    "fold_index": fold_index,
                    "held_out_ordinal": fold_index,
                    "held_out_target_id": f"build-{fold_index:04d}",
                    "arm": arm,
                    "training_ordinals": list(ordinals),
                    "held_out_label_used_in_fit": False,
                    "held_out_label_scored": False,
                    "inner_freeze_sha256": inner_freeze["inner_freeze_sha256"],
                    "alpha": outer.alpha,
                    "regularizations": list(outer.regularizations),
                    "ridge_fits": outer.ridge_fits,
                    "alpha_bit_evaluations": outer.alpha_bit_evaluations,
                    "effective_weights_sha256": _sha256_bytes(weight_payload),
                    "effective_weight_bytes": len(weight_payload),
                    "held_out_logits_sha256": _sha256_bytes(prediction_payload),
                    "held_out_logit_bytes": len(prediction_payload),
                    "prediction_path": (
                        "projected_residual_state_replay"
                        if arm == PRIMARY_ARM
                        else "frozen_batch_control"
                    ),
                    "state_replay_passed": state_replay_passed,
                    "state_replay_coordinates": state_replay_coordinates,
                    "batch_reference_sha256": _sha256_bytes(batch_reference_payload),
                    "batch_vs_state_maximum_absolute_residual": (
                        batch_vs_state_max_abs
                    ),
                    "batch_vs_state_absolute_tolerance": 1e-12,
                    "live_state_bytes": live_state_bytes
                    if arm != PRIMARY_ARM
                    else LIVE_STATE_BYTES,
                },
                digest_field="outer_freeze_sha256",
            )
            outer_freeze_path = persist(
                f"{prefix}/outer_prediction_freeze.json",
                canonical_json_bytes(outer_freeze),
                "OUTER_PREDICTION_FROZEN_PRE_OWN_FOLD_SCORE",
            )
            if outer_freeze_path.read_bytes() != canonical_json_bytes(outer_freeze):
                raise O1C26RunError("persisted outer freeze differs")
            work.outer_prediction_freezes_persisted += 1
            outer_freezes.append(outer_freeze)
        del feature_tensor

    work.every_inner_prediction_frozen_before_alpha_selection = (
        work.inner_prediction_freezes_persisted_and_reloaded == EXPECTED_INNER_FREEZES
    )
    model_artifacts: list[Mapping[str, object]] = []
    for fold_index in range(FOLD_COUNT):
        model_payload = _little_f8(
            weights[fold_index],
            (len(LEARNED_ARMS), FEATURE_WIDTH),
            f"fold {fold_index} canonical models",
        )
        relative = f"folds/build-{fold_index:04d}/models.f64le"
        model_path = persist(
            relative,
            model_payload,
            "ALL_MODELS_FROZEN_PRE_OWN_FOLD_SCORE",
        )
        if model_path.read_bytes() != model_payload:
            raise O1C26RunError("canonical model artifact differs")
        model_artifacts.append(
            {
                "fold_index": fold_index,
                "relative_path": relative,
                "sha256": _sha256_bytes(model_payload),
                "bytes": len(model_payload),
                "shape": [len(LEARNED_ARMS), FEATURE_WIDTH],
                "learned_arm_order": list(LEARNED_ARMS),
            }
        )

    diagnostic_artifacts: list[Mapping[str, object]] = []
    for fold_index, pool in enumerate(pools):
        diagnostic = np.empty((len(DIAGNOSTIC_ABLATIONS), KEY_BITS), dtype=np.float64)
        primary_weights = weights[fold_index, LEARNED_ARMS.index(PRIMARY_ARM)]
        for ablation_index, ablation in enumerate(DIAGNOSTIC_ABLATIONS):
            features = project_pool(pool, ablation=ablation)
            # Accelerate can translate stale benign IEEE flags into warnings;
            # the explicit finite invariant below remains authoritative.
            with np.errstate(divide="ignore", over="ignore", invalid="ignore"):
                logits = (
                    source.held_out_offsets[fold_index] + features @ primary_weights
                )
            if not np.all(np.isfinite(logits)):
                raise O1C26RunError("diagnostic prediction is non-finite")
            diagnostic[ablation_index] = logits
            predictions[fold_index, SCORE_ARMS.index(ablation)] = logits
            work.diagnostic_projection_rows += KEY_BITS
            work.diagnostic_bit_evaluations += KEY_BITS
        payload = _little_f8(
            diagnostic,
            (len(DIAGNOSTIC_ABLATIONS), KEY_BITS),
            f"fold {fold_index} diagnostic predictions",
        )
        relative = f"folds/build-{fold_index:04d}/diagnostic_predictions.f64le"
        persist(
            relative,
            payload,
            "DIAGNOSTIC_PREDICTIONS_FROZEN_PRE_OWN_FOLD_SCORE",
        )
        diagnostic_artifacts.append(
            {
                "fold_index": fold_index,
                "relative_path": relative,
                "sha256": _sha256_bytes(payload),
                "shape": [len(DIAGNOSTIC_ABLATIONS), KEY_BITS],
                "ablation_order": list(DIAGNOSTIC_ABLATIONS),
            }
        )

    aggregate_prediction_artifacts: list[Mapping[str, object]] = []
    aggregate_prediction_freezes: list[Mapping[str, object]] = []
    for fold_index in range(FOLD_COUNT):
        prediction_payload = _little_f8(
            predictions[fold_index],
            (len(SCORE_ARMS), KEY_BITS),
            f"fold {fold_index} canonical outer predictions",
        )
        relative = f"folds/build-{fold_index:04d}/outer_prediction.f64le"
        prediction_path = persist(
            relative,
            prediction_payload,
            "ALL_PREDICTIONS_FROZEN_PRE_OWN_FOLD_SCORE",
        )
        if prediction_path.read_bytes() != prediction_payload:
            raise O1C26RunError("canonical outer-prediction artifact differs")
        fold_outer = [
            row for row in outer_freezes if row.get("fold_index") == fold_index
        ]
        if len(fold_outer) != len(LEARNED_ARMS):
            raise O1C26RunError("fold outer-freeze inventory differs")
        fold_freeze = _freeze(
            {
                "schema": OUTER_FREEZE_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
                "aggregate": True,
                "fold_index": fold_index,
                "held_out_ordinal": fold_index,
                "held_out_target_id": f"build-{fold_index:04d}",
                "score_arm_order": list(SCORE_ARMS),
                "outer_prediction_relative_path": relative,
                "outer_prediction_sha256": _sha256_bytes(prediction_payload),
                "outer_prediction_bytes": len(prediction_payload),
                "learned_outer_freeze_sha256": [
                    row["outer_freeze_sha256"] for row in fold_outer
                ],
                "model_artifact": model_artifacts[fold_index],
                "diagnostic_artifact": diagnostic_artifacts[fold_index],
                "held_out_label_scored": False,
            },
            digest_field="outer_freeze_sha256",
        )
        freeze_relative = f"folds/build-{fold_index:04d}/prediction_freeze.json"
        freeze_path = persist(
            freeze_relative,
            canonical_json_bytes(fold_freeze),
            "ALL_PREDICTIONS_FROZEN_PRE_OWN_FOLD_SCORE",
        )
        if freeze_path.read_bytes() != canonical_json_bytes(fold_freeze):
            raise O1C26RunError("aggregate prediction freeze differs")
        aggregate_prediction_artifacts.append(
            {
                "fold_index": fold_index,
                "relative_path": relative,
                "sha256": _sha256_bytes(prediction_payload),
                "bytes": len(prediction_payload),
                "shape": [len(SCORE_ARMS), KEY_BITS],
            }
        )
        aggregate_prediction_freezes.append(fold_freeze)

    prediction_set_freeze = _freeze(
        {
            "schema": PREDICTION_SET_FREEZE_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
            "phase": "ALL_OUTER_AND_DIAGNOSTIC_PREDICTIONS_FROZEN_BEFORE_OWN_FOLD_SCORING",
            "projection_freeze_sha256": projection_freeze["projection_freeze_sha256"],
            "outer_prediction_freeze_sha256": [
                row["outer_freeze_sha256"] for row in outer_freezes
            ],
            "outer_prediction_freeze_count": len(outer_freezes),
            "model_artifacts": model_artifacts,
            "diagnostic_artifacts": diagnostic_artifacts,
            "aggregate_prediction_artifacts": aggregate_prediction_artifacts,
            "aggregate_prediction_freeze_sha256": [
                row["outer_freeze_sha256"] for row in aggregate_prediction_freezes
            ],
            "score_arm_order": list(SCORE_ARMS),
            "held_out_labels_scored": False,
            "own_fold_label_used_in_fit": False,
            "cross_fold_labels_were_training_data": True,
        },
        digest_field="prediction_set_freeze_sha256",
    )
    prediction_set_path = persist(
        "prediction_set_freeze.json",
        canonical_json_bytes(prediction_set_freeze),
        "ALL_PREDICTIONS_FROZEN_PRE_OWN_FOLD_SCORE",
    )
    if not prediction_set_path.is_file():
        raise O1C26RunError("prediction-set freeze was not persisted")
    if prediction_set_path.read_bytes() != canonical_json_bytes(prediction_set_freeze):
        raise O1C26RunError("persisted prediction-set freeze differs")
    work.prediction_set_freezes_persisted += 1
    work.every_outer_prediction_frozen_before_own_fold_scoring = (
        work.outer_prediction_freezes_persisted == EXPECTED_INNER_FREEZES
        and work.prediction_set_freezes_persisted == 1
        and len(aggregate_prediction_freezes) == FOLD_COUNT
    )

    persisted_label_path = persist(
        "post_freeze_labels.bitpack",
        label_payload,
        "POST_PREDICTION_SCORING_COPY",
    )
    if persisted_label_path.read_bytes() != label_payload:
        raise O1C26RunError("post-freeze label copy differs")
    label_access = _freeze(
        {
            "schema": LABEL_ACCESS_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "proxy_instance_fingerprint": work.proxy_instance_fingerprint,
            "prediction_set_freeze_sha256": prediction_set_freeze[
                "prediction_set_freeze_sha256"
            ],
            "label_payload_sha256": _sha256_bytes(label_payload),
            "label_payload_bytes": len(label_payload),
            "shape": [FOLD_COUNT, KEY_BITS],
            "bit_order": "little",
            "this_is_post_prediction_scoring_copy_not_first_global_materialization": True,
            "global_label_vector_available_during_crossvalidation": True,
            "held_out_label_used_in_own_fit": False,
            "same_label_used_as_training_in_other_folds": True,
        },
        digest_field="label_access_receipt_sha256",
    )
    persist(
        "label_access_receipt.json",
        canonical_json_bytes(label_access),
        "POST_PREDICTION_SCORING_COPY",
    )

    work.scored_label_bit_uses = FOLD_COUNT * len(SCORE_ARMS) * KEY_BITS
    work.validate()
    work_document = work.document()
    report, nll, compression, correct = _scored_report(
        predictions,
        labels_bits,
        labels_signs,
        alphas,
        offset_freeze_sha256=str(offset_freeze["offset_freeze_sha256"]),
        projection_freeze_sha256=str(projection_freeze["projection_freeze_sha256"]),
        prediction_set_freeze_sha256=str(
            prediction_set_freeze["prediction_set_freeze_sha256"]
        ),
        label_access_receipt_sha256=str(label_access["label_access_receipt_sha256"]),
        selection_receipt_sha256=str(
            source.selection_receipt["selection_receipt_sha256"]
        ),
        work_ledger_sha256=str(work_document["work_ledger_sha256"]),
        proxy_instance_fingerprint=str(
            source.proxy_instance["proxy_instance_fingerprint"]
        ),
        parent_operator_fingerprint=str(
            source.selection_receipt["parent_operator_fingerprint"]
        ),
    )
    persist(
        "scores/nll_bits.f64le",
        _little_f8(nll, (FOLD_COUNT, len(SCORE_ARMS)), "NLL scores"),
        "POST_FREEZE_SCORED_RESULT",
    )
    persist(
        "scores/compression_bits.f64le",
        _little_f8(
            compression,
            (FOLD_COUNT, len(SCORE_ARMS)),
            "compression scores",
        ),
        "POST_FREEZE_SCORED_RESULT",
    )
    persist(
        "scores/correct_bits.u16le",
        correct.astype("<u2", copy=False).tobytes(order="C"),
        "POST_FREEZE_SCORED_RESULT",
    )
    persist(
        "structural_work_ledger.json",
        canonical_json_bytes(work_document),
        "POST_FREEZE_SCORED_RESULT",
    )
    persist(
        "scientific_score_report.json",
        canonical_json_bytes(report),
        "POST_FREEZE_UNCLAIMED_SCIENTIFIC_SCORE",
    )
    return O1C26ScienceOutcome(
        report=report,
        work=work,
        projection_freeze_sha256=str(projection_freeze["projection_freeze_sha256"]),
        prediction_set_freeze_sha256=str(
            prediction_set_freeze["prediction_set_freeze_sha256"]
        ),
        label_access_receipt_sha256=str(label_access["label_access_receipt_sha256"]),
    )


def _source_index(
    config: O1C26RunConfig,
    source: O1C26PreparedSource,
) -> dict[str, object]:
    unsigned = {
        "schema": SOURCE_INDEX_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "run_config_sha256": _sha256_file(config.config_path),
        "local_source_sha256": dict(config.local_source_sha256),
        "projection_policy_sha256": projection_policy_sha256(),
        "proxy_mechanism": dict(source.proxy_mechanism),
        "proxy_instance": dict(source.proxy_instance),
        "source_config": {
            "relative_path": config.source_config_path.relative_to(
                config.root
            ).as_posix(),
            "sha256": _sha256_file(config.source_config_path),
        },
        "o1c23": {
            "attempt_id": O1C23_ATTEMPT_ID,
            "capsule_relative_path": source.o1c23.path.relative_to(
                config.root
            ).as_posix(),
            "capsule_manifest_sha256": source.o1c23.manifest_sha256,
            "decision_sha256": source.selection_receipt["decision_sha256"],
            "operator_graph_sha256": source.selection_receipt["operator_graph_sha256"],
            "selected_parent_operator_id": SELECTED_OPERATOR_ID,
            "parent_operator_fingerprint": source.selection_receipt[
                "parent_operator_fingerprint"
            ],
        },
        "o1c22": {
            "attempt_id": O1C22_ATTEMPT_ID,
            "capsule_relative_path": source.o1c22.finalized.path.relative_to(
                config.root
            ).as_posix(),
            "capsule_manifest_sha256": source.o1c22.finalized.manifest_sha256,
            "artifact_index_sha256": source.o1c22.artifact_index_sha256,
            "result_sha256": source.o1c22.result["result_sha256"],
            "result_file_sha256": source.o1c22.result_sha256,
            "offset_members": list(source.offset_members),
            "label_member": {
                "relative_path": "labels.bitpack",
                "sha256": source.label_payload_sha256,
                "bytes": LABEL_BYTES,
                "opened_before_projection_freeze": False,
            },
        },
        "o1c18": {
            "capsule_relative_path": source.o1c22_run_config.corpus.capsule_path.relative_to(
                config.root
            ).as_posix(),
            "capsule_manifest_sha256": (
                source.o1c22_run_config.corpus.capsule_manifest_sha256
            ),
            "artifact_index_sha256": (
                source.o1c22_run_config.corpus.artifact_index_sha256
            ),
            "artifact_corpus_sha256": source.o1c22_run_config.corpus.sha256,
            "build_faps": [
                {
                    "ordinal": episode.ordinal,
                    "target_id": episode.target_id,
                    "relative_path": f"artifacts/pools/{episode.target_id}.fap",
                    "sha256": episode.action_pool_sha256,
                    "bytes": episode.action_pool_bytes,
                }
                for episode in source.o1c22_run_config.corpus.episodes
            ],
            "development_faps_deserialized": 0,
        },
        "source_artifact_bytes_read_before_science": (
            source.source_artifact_bytes_read
        ),
    }
    return {
        **unsigned,
        "source_index_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _source_hashes(
    config: O1C26RunConfig,
    source: O1C26PreparedSource,
) -> dict[str, str]:
    local_hashes = _fresh_local_source_sha256(config)
    o1c18_hashes = _fresh_o1c18_source_hashes(config, source)
    return {
        "config": _sha256_file(config.config_path),
        "projection_policy": projection_policy_sha256(),
        "proxy_mechanism": str(source.proxy_mechanism["proxy_mechanism_sha256"]),
        "proxy_instance": str(source.proxy_instance["proxy_instance_fingerprint"]),
        "parent_operator": str(source.selection_receipt["parent_operator_fingerprint"]),
        "source_config": _sha256_file(config.source_config_path),
        **local_hashes,
        "o1c23_capsule_manifest": source.o1c23.manifest_sha256,
        "o1c23_decision": str(source.selection_receipt["decision_sha256"]),
        "o1c23_operator_graph": str(source.selection_receipt["operator_graph_sha256"]),
        "o1c22_capsule_manifest": source.o1c22.finalized.manifest_sha256,
        "o1c22_artifact_index": source.o1c22.artifact_index_sha256,
        "o1c22_result": str(source.o1c22.result["result_sha256"]),
        "o1c22_result_file": source.o1c22.result_sha256,
        **o1c18_hashes,
    }


def _fresh_local_source_sha256(config: O1C26RunConfig) -> dict[str, str]:
    if set(config.local_source_paths) != set(config.local_source_sha256):
        raise O1C26RunError("local source path inventory differs")
    fresh: dict[str, str] = {}
    for label, path in config.local_source_paths.items():
        if not path.is_relative_to(config.root):
            raise O1C26RunError(f"local source escapes lab: {label}")
        digest = _sha256_file(path)
        if digest != config.local_source_sha256[label]:
            raise O1C26RunError(f"local source differs: {label}")
        fresh[label] = digest
    return dict(sorted(fresh.items()))


def _fresh_o1c18_source_hashes(
    config: O1C26RunConfig,
    source: O1C26PreparedSource,
) -> dict[str, str]:
    corpus = source.o1c22_run_config.corpus
    verification = RunCapsuleManager(config.root).verify(corpus.capsule_path)
    if (
        not verification.ok
        or verification.manifest_sha256 != corpus.capsule_manifest_sha256
    ):
        raise O1C26RunError("O1C-0018 fresh manifest verification differs")
    artifacts = corpus.capsule_path / "artifacts"
    if (
        _sha256_file(artifacts / "artifact_index.json") != corpus.artifact_index_sha256
        or _sha256_file(artifacts / "full256_online_real_gate.json")
        != corpus.source_result_sha256
        or _sha256_file(corpus.capsule_path / "config.json")
        != corpus.source_config_sha256
    ):
        raise O1C26RunError("O1C-0018 source commitments changed")
    if len(corpus.episodes) != FOLD_COUNT:
        raise O1C26RunError("O1C-0018 BUILD inventory changed")
    for episode in corpus.episodes:
        path = artifacts / "pools" / f"{episode.target_id}.fap"
        if (
            path.stat().st_size != episode.action_pool_bytes
            or _sha256_file(path) != episode.action_pool_sha256
        ):
            raise O1C26RunError("O1C-0018 BUILD FAP changed")
    return {
        "o1c18_capsule_manifest": corpus.capsule_manifest_sha256,
        "o1c18_artifact_index": corpus.artifact_index_sha256,
        "o1c18_build_corpus": corpus.sha256,
    }


def _recheck_sources(
    config: O1C26RunConfig,
    source: O1C26PreparedSource,
    expected: Mapping[str, str],
) -> None:
    if _source_hashes(config, source) != dict(expected):
        raise O1C26RunError("source hash set changed during O1C-0026")
    manager = RunCapsuleManager(config.root)
    if (
        _authoritative_finalized(
            manager, source.o1c23, O1C23_ATTEMPT_ID
        ).manifest_sha256
        != source.o1c23.manifest_sha256
        or _authoritative_finalized(
            manager, source.o1c22.finalized, O1C22_ATTEMPT_ID
        ).manifest_sha256
        != source.o1c22.finalized.manifest_sha256
    ):
        raise O1C26RunError("authoritative upstream changed during O1C-0026")


def _resolve_root(
    path: str | Path,
    root: str | Path | None,
) -> tuple[Path, Path]:
    config_path = Path(path).resolve(strict=False)
    lab_root = (
        Path(root).resolve(strict=True) if root is not None else config_path.parents[1]
    )
    if not config_path.is_relative_to(lab_root):
        raise O1C26RunError("config escapes lab root")
    return config_path, lab_root


def _operational_failure_disposition(
    proxy_instance_fingerprint: str,
    parent_operator_fingerprint: str,
) -> dict[str, object]:
    return {
        "schema": RUN_METRICS_SCHEMA,
        "classification": FAILURE,
        "proxy_instance_fingerprint": _sha256(
            proxy_instance_fingerprint, "failure proxy instance"
        ),
        "parent_operator_fingerprint": _sha256(
            parent_operator_fingerprint, "failure parent operator"
        ),
        "closure_disposition": "NONE_OPERATIONAL_FAILURE",
        "closed_operator_fingerprint": None,
        "parent_closed": False,
        "operationally_complete": False,
        "scientific_result_claimed": False,
    }


def _failure_metrics(
    exc: Exception,
    *,
    cpu_started: float,
    wall_started: float,
    source_bytes: int,
    persistent_bytes: int,
    proxy_instance_fingerprint: str,
    parent_operator_fingerprint: str,
) -> dict[str, object]:
    return {
        **_operational_failure_disposition(
            proxy_instance_fingerprint,
            parent_operator_fingerprint,
        ),
        "error_type": type(exc).__name__,
        "error": str(exc),
        "cpu_seconds": time.process_time() - cpu_started,
        "wall_seconds": time.monotonic() - wall_started,
        "peak_rss_bytes": _process_peak_rss_bytes(),
        "source_artifact_bytes_read": source_bytes,
        "persistent_artifact_bytes": persistent_bytes,
    }


def _final_result(
    score_report: Mapping[str, object],
) -> dict[str, object]:
    if score_report.get("schema") != SCORE_REPORT_SCHEMA:
        raise O1C26RunError("scientific score-report schema differs")
    unsigned_score = dict(score_report)
    score_sha256 = _sha256(
        unsigned_score.pop("score_report_sha256", None),
        "scientific score report",
    )
    if score_sha256 != _sha256_bytes(canonical_json_bytes(unsigned_score)):
        raise O1C26RunError("scientific score-report digest differs")
    score_classification = score_report.get("classification")
    if score_classification not in {PRESENT, NULL}:
        raise O1C26RunError("scientific score classification differs")
    proxy_fingerprint = _sha256(
        score_report.get("proxy_instance_fingerprint"),
        "final proxy instance",
    )
    parent_fingerprint = _sha256(
        score_report.get("parent_operator_fingerprint"),
        "final parent operator",
    )
    unsigned = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "result_authority": "CANDIDATE_ONLY_UNTIL_COMPLETED_OPERATIONAL_METRICS",
        "classification": score_classification,
        "scientific_success_gate_passed": bool(
            score_report.get("scientific_success_gate_passed") is True
        ),
        "scientific_score_classification": score_classification,
        "scientific_score_report_sha256": score_sha256,
        "proxy_operator_id": PROXY_OPERATOR_ID,
        "proxy_instance_fingerprint": proxy_fingerprint,
        "parent_operator_fingerprint": parent_fingerprint,
        "closure_candidate": (
            "EXACT_PROXY_INSTANCE_NO_LIFT" if score_classification == NULL else None
        ),
        "closed_operator_fingerprint": None,
        "parent_closed": False,
        "selection_receipt_sha256": score_report["selection_receipt_sha256"],
        "offset_freeze_sha256": score_report["offset_freeze_sha256"],
        "projection_freeze_sha256": score_report["projection_freeze_sha256"],
        "prediction_set_freeze_sha256": score_report["prediction_set_freeze_sha256"],
        "label_access_receipt_sha256": score_report["label_access_receipt_sha256"],
        "work_ledger_sha256": score_report["work_ledger_sha256"],
        "claim_boundary": dict(
            _mapping(score_report["claim_boundary"], "score claim boundary")
        ),
    }
    return {
        **unsigned,
        "result_sha256": _sha256_bytes(canonical_json_bytes(unsigned)),
    }


def _authoritative_disposition(
    scientific_classification: object,
    operationally_complete: bool,
    proxy_instance_fingerprint: str,
) -> dict[str, object]:
    if scientific_classification not in {PRESENT, NULL}:
        raise O1C26RunError("authoritative scientific classification differs")
    proxy = _sha256(proxy_instance_fingerprint, "authoritative proxy instance")
    if not operationally_complete:
        return {
            "classification": FAILURE,
            "closure_disposition": "NONE_OPERATIONAL_FAILURE",
            "closed_operator_fingerprint": None,
            "parent_closed": False,
        }
    if scientific_classification == NULL:
        return {
            "classification": NULL,
            "closure_disposition": "AUTHORIZE_EXACT_PROXY_INSTANCE_NO_LIFT",
            "closed_operator_fingerprint": proxy,
            "parent_closed": False,
        }
    return {
        "classification": PRESENT,
        "closure_disposition": "NONE_PRESENT_SUPPORTS_INSTANCE",
        "closed_operator_fingerprint": None,
        "parent_closed": False,
    }


def _expected_o1c26_indexed_artifacts() -> frozenset[str]:
    expected = {
        "o1c0023_decision.json",
        "o1c0023_next_operator_graph.json",
        "selection_receipt.json",
        "projection_policy.json",
        "proxy_mechanism.json",
        "proxy_instance.json",
        "source_index.json",
        "offsets/held_out_normalized_float.f64le",
        "offsets/training_same_reader_normalized_float.f64le",
        "offset_freeze.json",
        "projection_freeze.json",
        "prediction_set_freeze.json",
        "post_freeze_labels.bitpack",
        "label_access_receipt.json",
        "scores/nll_bits.f64le",
        "scores/compression_bits.f64le",
        "scores/correct_bits.u16le",
        "structural_work_ledger.json",
        "scientific_score_report.json",
        "proof_ancestry_pair_residual_result.json",
    }
    expected.update(f"features/{arm}.f64le" for arm in LEARNED_ARMS)
    for fold_index in range(FOLD_COUNT):
        prefix = f"folds/build-{fold_index:04d}"
        expected.update(
            {
                f"{prefix}/models.f64le",
                f"{prefix}/diagnostic_predictions.f64le",
                f"{prefix}/outer_prediction.f64le",
                f"{prefix}/prediction_freeze.json",
            }
        )
        for arm in LEARNED_ARMS:
            arm_prefix = f"{prefix}/{arm}"
            expected.update(
                {
                    f"{arm_prefix}/inner_raw_predictions.f64le",
                    f"{arm_prefix}/inner_prediction_freeze.json",
                    f"{arm_prefix}/effective_weights.f64le",
                    f"{arm_prefix}/held_out_logits.f64le",
                    f"{arm_prefix}/outer_prediction_freeze.json",
                }
            )
    return frozenset(expected)


def _verified_self_digest(
    artifacts_root: Path,
    relative: str,
    digest_field: str,
) -> tuple[Mapping[str, object], str]:
    document, payload = _read_json(artifacts_root / relative, relative)
    if payload != canonical_json_bytes(document):
        raise O1C26RunError(f"noncanonical JSON artifact: {relative}")
    unsigned = dict(document)
    supplied = _sha256(unsigned.pop(digest_field, None), f"{relative} digest")
    if supplied != _sha256_bytes(canonical_json_bytes(unsigned)):
        raise O1C26RunError(f"self digest differs: {relative}")
    return document, supplied


def _verify_scientific_evidence(
    artifacts_root: Path,
    *,
    prediction: Mapping[str, object],
    label_payload: bytes,
    score: Mapping[str, object],
    offset_sha256: str,
    projection_sha256: str,
    prediction_sha256: str,
    label_sha256: str,
    selection_sha256: str,
    work_sha256: str,
    proxy_instance_fingerprint: str,
    parent_operator_fingerprint: str,
) -> None:
    predictions = np.empty((FOLD_COUNT, len(SCORE_ARMS), KEY_BITS), dtype=np.float64)
    held_out_offsets = _load_little_f8(
        artifacts_root / "offsets/held_out_normalized_float.f64le",
        (FOLD_COUNT, KEY_BITS),
        "held-out normalized-float offsets",
    )
    aggregate_rows = _sequence(
        prediction.get("aggregate_prediction_artifacts"),
        "aggregate prediction artifacts",
    )
    if len(aggregate_rows) != FOLD_COUNT:
        raise O1C26RunError("aggregate prediction inventory differs")
    learned_outer_digests: dict[tuple[int, str], str] = {}
    alphas = np.empty((FOLD_COUNT, len(LEARNED_ARMS)), dtype=np.float64)
    for fold_index in range(FOLD_COUNT):
        relative = f"folds/build-{fold_index:04d}/outer_prediction.f64le"
        payload = (artifacts_root / relative).read_bytes()
        predictions[fold_index] = _load_little_f8(
            artifacts_root / relative,
            (len(SCORE_ARMS), KEY_BITS),
            f"fold {fold_index} aggregate predictions",
        )
        if not np.array_equal(
            predictions[fold_index, SCORE_ARMS.index(OFFSET_ARM)],
            held_out_offsets[fold_index],
        ):
            raise O1C26RunError("aggregate offset prediction differs")
        aggregate = _mapping(
            aggregate_rows[fold_index],
            f"fold {fold_index} aggregate prediction artifact",
            {"fold_index", "relative_path", "sha256", "bytes", "shape"},
        )
        if (
            aggregate.get("fold_index") != fold_index
            or aggregate.get("relative_path") != relative
            or aggregate.get("sha256") != _sha256_bytes(payload)
            or aggregate.get("bytes") != len(payload)
            or aggregate.get("shape") != [len(SCORE_ARMS), KEY_BITS]
        ):
            raise O1C26RunError("aggregate prediction binding differs")
        for arm_index, arm in enumerate(LEARNED_ARMS):
            freeze_relative = (
                f"folds/build-{fold_index:04d}/{arm}/outer_prediction_freeze.json"
            )
            freeze, freeze_sha256 = _verified_self_digest(
                artifacts_root, freeze_relative, "outer_freeze_sha256"
            )
            held_relative = f"folds/build-{fold_index:04d}/{arm}/held_out_logits.f64le"
            held_payload = (artifacts_root / held_relative).read_bytes()
            held_logits = _load_little_f8(
                artifacts_root / held_relative,
                (KEY_BITS,),
                f"fold {fold_index} {arm} held-out logits",
            )
            alpha = _number(
                freeze.get("alpha"),
                f"fold {fold_index} {arm} alpha",
                min(ALPHA_GRID),
                max(ALPHA_GRID),
            )
            if (
                freeze.get("schema") != OUTER_FREEZE_SCHEMA
                or freeze.get("attempt_id") != ATTEMPT_ID
                or freeze.get("proxy_instance_fingerprint")
                != proxy_instance_fingerprint
                or freeze.get("fold_index") != fold_index
                or freeze.get("held_out_ordinal") != fold_index
                or freeze.get("arm") != arm
                or freeze.get("held_out_label_used_in_fit") is not False
                or freeze.get("held_out_logits_sha256") != _sha256_bytes(held_payload)
                or freeze.get("held_out_logit_bytes") != len(held_payload)
                or alpha not in ALPHA_GRID
            ):
                raise O1C26RunError("learned outer-freeze binding differs")
            if not np.array_equal(
                predictions[fold_index, SCORE_ARMS.index(arm)], held_logits
            ):
                raise O1C26RunError("aggregate learned prediction differs")
            learned_outer_digests[(fold_index, arm)] = freeze_sha256
            alphas[fold_index, arm_index] = alpha
        diagnostic = _load_little_f8(
            artifacts_root
            / f"folds/build-{fold_index:04d}/diagnostic_predictions.f64le",
            (len(DIAGNOSTIC_ABLATIONS), KEY_BITS),
            f"fold {fold_index} diagnostic predictions",
        )
        for ablation_index, ablation in enumerate(DIAGNOSTIC_ABLATIONS):
            if not np.array_equal(
                predictions[fold_index, SCORE_ARMS.index(ablation)],
                diagnostic[ablation_index],
            ):
                raise O1C26RunError("aggregate diagnostic prediction differs")
    prediction_set_checks = {
        "count": prediction.get("outer_prediction_freeze_count")
        == FOLD_COUNT * len(LEARNED_ARMS),
        "digests": prediction.get("outer_prediction_freeze_sha256")
        == [
            learned_outer_digests[(fold_index, arm)]
            for arm in LEARNED_ARMS
            for fold_index in range(FOLD_COUNT)
        ],
        "arm_order": prediction.get("score_arm_order") == list(SCORE_ARMS),
    }
    failed_prediction_checks = sorted(
        name for name, passed in prediction_set_checks.items() if not passed
    )
    if failed_prediction_checks:
        raise O1C26RunError(
            "prediction-set learned-freeze binding differs: "
            + ", ".join(failed_prediction_checks)
        )
    labels_bits, labels_signs = _decode_labels(label_payload)
    recomputed, nll, compression, correct = _scored_report(
        predictions,
        labels_bits,
        labels_signs,
        alphas,
        offset_freeze_sha256=offset_sha256,
        projection_freeze_sha256=projection_sha256,
        prediction_set_freeze_sha256=prediction_sha256,
        label_access_receipt_sha256=label_sha256,
        selection_receipt_sha256=selection_sha256,
        work_ledger_sha256=work_sha256,
        proxy_instance_fingerprint=proxy_instance_fingerprint,
        parent_operator_fingerprint=parent_operator_fingerprint,
    )
    expected_score_payloads = {
        "scores/nll_bits.f64le": _little_f8(
            nll, (FOLD_COUNT, len(SCORE_ARMS)), "recomputed NLL scores"
        ),
        "scores/compression_bits.f64le": _little_f8(
            compression,
            (FOLD_COUNT, len(SCORE_ARMS)),
            "recomputed compression scores",
        ),
        "scores/correct_bits.u16le": correct.astype("<u2", copy=False).tobytes(
            order="C"
        ),
    }
    if dict(score) != recomputed or any(
        (artifacts_root / relative).read_bytes() != payload
        for relative, payload in expected_score_payloads.items()
    ):
        raise O1C26RunError("O1C-0026 scientific evidence reconstruction differs")


def _verify_o1c26_artifact_index(
    artifacts_root: Path,
    *,
    expected_index: Mapping[str, object] | None = None,
) -> tuple[
    Mapping[str, object],
    str,
    int,
    Mapping[str, Mapping[str, object]],
]:
    index, index_payload = _read_json(
        artifacts_root / "artifact_index.json", "O1C-0026 artifact index"
    )
    if index_payload != canonical_json_bytes(index):
        raise O1C26RunError("O1C-0026 artifact index is not canonical JSON")
    expected_fields = {
        "schema",
        "attempt_id",
        "o1c23_capsule_manifest_sha256",
        "o1c22_capsule_manifest_sha256",
        "proxy_instance_fingerprint",
        "selection_receipt_sha256",
        "projection_freeze_sha256",
        "prediction_set_freeze_sha256",
        "label_access_receipt_sha256",
        "work_ledger_sha256",
        "result_sha256",
        "artifacts",
        "indexed_artifact_count",
        "indexed_artifact_bytes",
    }
    if (
        set(index) != expected_fields
        or index.get("schema") != ARTIFACT_INDEX_SCHEMA
        or index.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C26RunError("O1C-0026 artifact-index identity differs")
    if expected_index is not None and dict(index) != dict(expected_index):
        raise O1C26RunError("persisted O1C-0026 artifact index differs")
    artifacts = _mapping(index.get("artifacts"), "O1C-0026 artifact inventory")
    expected_artifacts = _expected_o1c26_indexed_artifacts()
    if set(artifacts) != expected_artifacts:
        raise O1C26RunError("O1C-0026 indexed artifact inventory differs")
    actual: set[str] = set()
    for path in artifacts_root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or (
            not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode)
        ):
            raise O1C26RunError("O1C-0026 artifact tree contains unsafe members")
        if stat.S_ISREG(metadata.st_mode):
            actual.add(path.relative_to(artifacts_root).as_posix())
    if actual != expected_artifacts | {"artifact_index.json"}:
        raise O1C26RunError("O1C-0026 actual artifact inventory differs")
    total = 0
    for relative in sorted(expected_artifacts):
        entry = _mapping(
            artifacts.get(relative),
            f"O1C-0026 artifact {relative}",
            {"sha256", "bytes", "phase"},
        )
        payload = (artifacts_root / relative).read_bytes()
        if (
            entry.get("sha256") != _sha256_bytes(payload)
            or entry.get("bytes") != len(payload)
            or not isinstance(entry.get("phase"), str)
            or not str(entry.get("phase"))
        ):
            raise O1C26RunError(f"O1C-0026 artifact entry differs: {relative}")
        total += len(payload)
    if (
        index.get("indexed_artifact_count") != len(expected_artifacts)
        or index.get("indexed_artifact_bytes") != total
    ):
        raise O1C26RunError("O1C-0026 artifact-index totals differ")

    mechanism, mechanism_sha = _verified_self_digest(
        artifacts_root, "proxy_mechanism.json", "proxy_mechanism_sha256"
    )
    selection, selection_sha = _verified_self_digest(
        artifacts_root, "selection_receipt.json", "selection_receipt_sha256"
    )
    instance, instance_sha = _verified_self_digest(
        artifacts_root, "proxy_instance.json", "proxy_instance_fingerprint"
    )
    offset, offset_sha = _verified_self_digest(
        artifacts_root, "offset_freeze.json", "offset_freeze_sha256"
    )
    projection, projection_sha = _verified_self_digest(
        artifacts_root, "projection_freeze.json", "projection_freeze_sha256"
    )
    prediction, prediction_sha = _verified_self_digest(
        artifacts_root,
        "prediction_set_freeze.json",
        "prediction_set_freeze_sha256",
    )
    label, label_sha = _verified_self_digest(
        artifacts_root,
        "label_access_receipt.json",
        "label_access_receipt_sha256",
    )
    work, work_sha = _verified_self_digest(
        artifacts_root, "structural_work_ledger.json", "work_ledger_sha256"
    )
    O1C26WorkLedger.from_document(work)
    score, score_sha = _verified_self_digest(
        artifacts_root, "scientific_score_report.json", "score_report_sha256"
    )
    result, result_sha = _verified_self_digest(
        artifacts_root,
        "proof_ancestry_pair_residual_result.json",
        "result_sha256",
    )
    source_index, _ = _verified_self_digest(
        artifacts_root, "source_index.json", "source_index_sha256"
    )
    if set(source_index) != {
        "schema",
        "attempt_id",
        "run_config_sha256",
        "local_source_sha256",
        "projection_policy_sha256",
        "proxy_mechanism",
        "proxy_instance",
        "source_config",
        "o1c23",
        "o1c22",
        "o1c18",
        "source_artifact_bytes_read_before_science",
        "source_index_sha256",
    }:
        raise O1C26RunError("O1C-0026 source-index inventory differs")
    policy, policy_payload = _read_json(
        artifacts_root / "projection_policy.json", "projection policy"
    )
    if (
        policy_payload != canonical_json_bytes(policy)
        or dict(policy) != projection_policy()
    ):
        raise O1C26RunError("O1C-0026 projection policy differs")
    decision_payload = (artifacts_root / "o1c0023_decision.json").read_bytes()
    graph_payload = (artifacts_root / "o1c0023_next_operator_graph.json").read_bytes()
    label_payload = (artifacts_root / "post_freeze_labels.bitpack").read_bytes()
    held_offset_payload = (
        artifacts_root / "offsets/held_out_normalized_float.f64le"
    ).read_bytes()
    training_offset_payload = (
        artifacts_root / "offsets/training_same_reader_normalized_float.f64le"
    ).read_bytes()
    proxy = _sha256(index.get("proxy_instance_fingerprint"), "index proxy")
    parent = _sha256(selection.get("parent_operator_fingerprint"), "selection parent")
    instance_parent = _mapping(instance.get("parent"), "proxy-instance parent")
    instance_evaluation = _mapping(
        instance.get("evaluation_source"), "proxy-instance evaluation source"
    )
    source_local = _mapping(
        source_index.get("local_source_sha256"),
        "source-index local sources",
        {
            "source_config",
            "projection_module",
            "runner_module",
            "run_capsule_module",
            "posterior_logit_module",
            "pyproject",
        },
    )
    for name, digest in source_local.items():
        _sha256(digest, f"source-index local source {name}")
    mechanism_sources = _mapping(
        mechanism.get("scientific_source_sha256"),
        "proxy-mechanism scientific sources",
        {
            "projection_module",
            "runner_module",
            "posterior_logit_module",
            "pyproject",
        },
    )
    source_config = _mapping(
        source_index.get("source_config"),
        "source-index source config",
        {"relative_path", "sha256"},
    )
    _safe_relative(source_config.get("relative_path"), "source-index source config")
    _sha256(source_config.get("sha256"), "source-index source config")
    _sha256(source_index.get("run_config_sha256"), "source-index run config")
    _integer(
        source_index.get("source_artifact_bytes_read_before_science"),
        "source-index pre-science bytes",
        0,
        1 << 60,
    )
    source_o1c23 = _mapping(
        source_index.get("o1c23"),
        "source-index O1C-0023",
        {
            "attempt_id",
            "capsule_relative_path",
            "capsule_manifest_sha256",
            "decision_sha256",
            "operator_graph_sha256",
            "selected_parent_operator_id",
            "parent_operator_fingerprint",
        },
    )
    _safe_relative(source_o1c23.get("capsule_relative_path"), "O1C-0023 capsule")
    source_o1c22 = _mapping(
        source_index.get("o1c22"),
        "source-index O1C-0022",
        {
            "attempt_id",
            "capsule_relative_path",
            "capsule_manifest_sha256",
            "artifact_index_sha256",
            "result_sha256",
            "result_file_sha256",
            "offset_members",
            "label_member",
        },
    )
    _safe_relative(source_o1c22.get("capsule_relative_path"), "O1C-0022 capsule")
    source_o1c22_label = _mapping(
        source_o1c22.get("label_member"),
        "source-index O1C-0022 label",
        {"relative_path", "sha256", "bytes", "opened_before_projection_freeze"},
    )
    source_offset_members = _sequence(
        source_o1c22.get("offset_members"), "source-index O1C-0022 offset members"
    )
    source_o1c18 = _mapping(
        source_index.get("o1c18"),
        "source-index O1C-0018",
        {
            "capsule_relative_path",
            "capsule_manifest_sha256",
            "artifact_index_sha256",
            "artifact_corpus_sha256",
            "build_faps",
            "development_faps_deserialized",
        },
    )
    _safe_relative(source_o1c18.get("capsule_relative_path"), "O1C-0018 capsule")
    source_build_faps = _sequence(
        source_o1c18.get("build_faps"), "source-index O1C-0018 BUILD FAPs"
    )
    if len(source_build_faps) != FOLD_COUNT:
        raise O1C26RunError("source-index O1C-0018 BUILD count differs")
    for ordinal, item in enumerate(source_build_faps):
        build = _mapping(
            item,
            f"source-index O1C-0018 BUILD {ordinal}",
            {"ordinal", "target_id", "relative_path", "sha256", "bytes"},
        )
        _safe_relative(build.get("relative_path"), f"O1C-0018 BUILD {ordinal}")
        _sha256(build.get("sha256"), f"O1C-0018 BUILD {ordinal}")
        _integer(build.get("bytes"), f"O1C-0018 BUILD {ordinal} bytes", 1, 1 << 40)
        if (
            build.get("ordinal") != ordinal
            or build.get("target_id") != f"build-{ordinal:04d}"
            or build.get("relative_path") != f"artifacts/pools/build-{ordinal:04d}.fap"
        ):
            raise O1C26RunError("source-index O1C-0018 BUILD identity differs")
    semantic_checks = {
        "mechanism_schema": mechanism.get("schema") == PROXY_MECHANISM_SCHEMA,
        "mechanism_operator": mechanism.get("proxy_operator_id") == PROXY_OPERATOR_ID,
        "mechanism_parent": mechanism.get("selected_parent_operator_id")
        == SELECTED_OPERATOR_ID,
        "mechanism_projection_policy": mechanism.get("projection_policy_sha256")
        == projection_policy_sha256(),
        "mechanism_source_binding": dict(mechanism_sources)
        == {
            name: source_local[name]
            for name in (
                "projection_module",
                "runner_module",
                "posterior_logit_module",
                "pyproject",
            )
        },
        "instance_schema": instance.get("schema") == PROXY_INSTANCE_SCHEMA,
        "selection_schema": selection.get("schema") == SELECTION_RECEIPT_SCHEMA,
        "selection_source_attempt": selection.get("source_attempt_id")
        == O1C23_ATTEMPT_ID,
        "selection_authority": selection.get("authoritative_capsule_verified") is True,
        "selection_reservation": selection.get("attempt_reservation_authorized")
        is True,
        "selection_parent_operator": selection.get("selected_parent_operator_id")
        == SELECTED_OPERATOR_ID,
        "selection_proxy_operator": selection.get("proxy_operator_id")
        == PROXY_OPERATOR_ID,
        "selection_reason_name": selection.get("required_reason_field")
        == "all_real_primary_k256_arms_nonpositive",
        "selection_reason_value": selection.get("required_reason_field_value") is True,
        "offset_schema": offset.get("schema") == OFFSET_FREEZE_SCHEMA,
        "projection_schema": projection.get("schema") == PROJECTION_FREEZE_SCHEMA,
        "prediction_schema": prediction.get("schema") == PREDICTION_SET_FREEZE_SCHEMA,
        "label_schema": label.get("schema") == LABEL_ACCESS_SCHEMA,
        "work_schema": work.get("schema") == WORK_LEDGER_SCHEMA,
        "score_schema": score.get("schema") == SCORE_REPORT_SCHEMA,
        "result_schema": result.get("schema") == RESULT_SCHEMA,
        "source_index_schema": source_index.get("schema") == SOURCE_INDEX_SCHEMA,
        **{
            f"{name}_attempt": document.get("attempt_id") == ATTEMPT_ID
            for name, document in (
                ("selection", selection),
                ("offset", offset),
                ("projection", projection),
                ("prediction", prediction),
                ("label", label),
                ("work", work),
                ("score", score),
                ("result", result),
                ("source_index", source_index),
            )
        },
        "index_selection": index.get("selection_receipt_sha256") == selection_sha,
        "index_projection": index.get("projection_freeze_sha256") == projection_sha,
        "index_prediction": index.get("prediction_set_freeze_sha256") == prediction_sha,
        "index_label": index.get("label_access_receipt_sha256") == label_sha,
        "index_work": index.get("work_ledger_sha256") == work_sha,
        "index_result": index.get("result_sha256") == result_sha,
        "index_proxy": instance_sha == proxy,
        "instance_mechanism": instance.get("proxy_mechanism_sha256") == mechanism_sha,
        "instance_parent_operator": instance_parent.get("operator_id")
        == SELECTED_OPERATOR_ID,
        "instance_parent_fingerprint": instance_parent.get("operator_fingerprint")
        == parent,
        "instance_parent_decision": instance_parent.get("decision_sha256")
        == selection.get("decision_sha256"),
        "instance_parent_graph": instance_parent.get("operator_graph_sha256")
        == selection.get("operator_graph_sha256"),
        "instance_held_offsets": instance_evaluation.get("held_out_offsets_sha256")
        == _sha256_bytes(held_offset_payload),
        "instance_training_offsets": instance_evaluation.get("training_offsets_sha256")
        == _sha256_bytes(training_offset_payload),
        "instance_label_digest": instance_evaluation.get("label_payload_sha256")
        == _sha256_bytes(label_payload),
        "instance_label_size": instance_evaluation.get("label_payload_bytes")
        == len(label_payload)
        == LABEL_BYTES,
        "instance_label_order": instance_evaluation.get("label_bit_order") == "little",
        "instance_training_ordinals": instance_evaluation.get(
            "training_ordinals_by_outer_fold"
        )
        == offset.get("training_ordinals_by_outer_fold"),
        "instance_offset_members": instance_evaluation.get(
            "offset_source_members_sha256"
        )
        == _sha256_bytes(canonical_json_bytes(list(source_offset_members))),
        "instance_build_corpus": instance_evaluation.get("o1c18_build_corpus_sha256")
        == source_o1c18.get("artifact_corpus_sha256"),
        "selection_mechanism": selection.get("proxy_mechanism_sha256") == mechanism_sha,
        "selection_proxy": selection.get("proxy_instance_fingerprint") == proxy,
        "offset_proxy": offset.get("proxy_instance_fingerprint") == proxy,
        "projection_proxy": projection.get("proxy_instance_fingerprint") == proxy,
        "prediction_proxy": prediction.get("proxy_instance_fingerprint") == proxy,
        "label_proxy": label.get("proxy_instance_fingerprint") == proxy,
        "work_proxy": work.get("proxy_instance_fingerprint") == proxy,
        "score_proxy": score.get("proxy_instance_fingerprint") == proxy,
        "result_proxy": result.get("proxy_instance_fingerprint") == proxy,
        "projection_offset": projection.get("offset_freeze_sha256") == offset_sha,
        "offset_arm": offset.get("offset_arm") == OFFSET_ARM,
        "offset_held_shape": offset.get("held_out_shape") == [FOLD_COUNT, KEY_BITS],
        "offset_training_shape": offset.get("training_shape")
        == [FOLD_COUNT, 3, KEY_BITS],
        "offset_held_digest": offset.get("held_out_offsets_sha256")
        == _sha256_bytes(held_offset_payload),
        "offset_training_digest": offset.get("training_offsets_sha256")
        == _sha256_bytes(training_offset_payload),
        "offset_pre_label": offset.get("label_payload_reads") == 0
        and offset.get("label_vector_parses") == 0,
        "prediction_projection": prediction.get("projection_freeze_sha256")
        == projection_sha,
        "label_prediction": label.get("prediction_set_freeze_sha256") == prediction_sha,
        "result_selection": result.get("selection_receipt_sha256") == selection_sha,
        "result_offset": result.get("offset_freeze_sha256") == offset_sha,
        "result_projection": result.get("projection_freeze_sha256") == projection_sha,
        "result_prediction": result.get("prediction_set_freeze_sha256")
        == prediction_sha,
        "result_label": result.get("label_access_receipt_sha256") == label_sha,
        "result_work": result.get("work_ledger_sha256") == work_sha,
        "result_score": result.get("scientific_score_report_sha256") == score_sha,
        "selection_o1c23": selection.get("o1c23_capsule_manifest_sha256")
        == index.get("o1c23_capsule_manifest_sha256"),
        "selection_o1c22": selection.get("o1c22_capsule_manifest_sha256")
        == index.get("o1c22_capsule_manifest_sha256"),
        "selection_decision": selection.get("decision_sha256")
        == _sha256_bytes(decision_payload),
        "selection_graph": selection.get("operator_graph_sha256")
        == _sha256_bytes(graph_payload),
        "label_payload_digest": label.get("label_payload_sha256")
        == _sha256_bytes(label_payload),
        "label_payload_size": label.get("label_payload_bytes")
        == len(label_payload)
        == LABEL_BYTES,
        "score_selection": score.get("selection_receipt_sha256") == selection_sha,
        "score_offset": score.get("offset_freeze_sha256") == offset_sha,
        "score_projection": score.get("projection_freeze_sha256") == projection_sha,
        "score_prediction": score.get("prediction_set_freeze_sha256") == prediction_sha,
        "score_label": score.get("label_access_receipt_sha256") == label_sha,
        "score_work": score.get("work_ledger_sha256") == work_sha,
        "score_parent": score.get("parent_operator_fingerprint") == parent,
        "result_parent": result.get("parent_operator_fingerprint") == parent,
        "source_mechanism": source_index.get("proxy_mechanism") == mechanism,
        "source_instance": source_index.get("proxy_instance") == instance,
        "source_projection_policy": source_index.get("projection_policy_sha256")
        == projection_policy_sha256(),
        "source_config_local": source_config.get("sha256")
        == source_local.get("source_config"),
        "source_o1c23_attempt": source_o1c23.get("attempt_id") == O1C23_ATTEMPT_ID,
        "source_o1c23": source_o1c23.get("capsule_manifest_sha256")
        == index.get("o1c23_capsule_manifest_sha256"),
        "source_o1c23_decision": source_o1c23.get("decision_sha256")
        == selection.get("decision_sha256"),
        "source_o1c23_graph": source_o1c23.get("operator_graph_sha256")
        == selection.get("operator_graph_sha256"),
        "source_o1c23_operator": source_o1c23.get("selected_parent_operator_id")
        == SELECTED_OPERATOR_ID,
        "source_o1c23_parent": source_o1c23.get("parent_operator_fingerprint")
        == parent,
        "source_o1c22_attempt": source_o1c22.get("attempt_id") == O1C22_ATTEMPT_ID,
        "source_o1c22": source_o1c22.get("capsule_manifest_sha256")
        == index.get("o1c22_capsule_manifest_sha256"),
        "source_o1c22_result": source_o1c22.get("result_sha256")
        == selection.get("o1c22_result_sha256"),
        "source_o1c22_label": source_o1c22_label.get("relative_path")
        == "labels.bitpack"
        and source_o1c22_label.get("sha256") == _sha256_bytes(label_payload)
        and source_o1c22_label.get("bytes") == LABEL_BYTES
        and source_o1c22_label.get("opened_before_projection_freeze") is False,
        "source_o1c18_development": source_o1c18.get("development_faps_deserialized")
        == 0,
        "result_reconstruction": dict(result) == _final_result(score),
    }
    failed_checks = sorted(
        name for name, passed in semantic_checks.items() if not passed
    )
    if failed_checks:
        raise O1C26RunError(
            "O1C-0026 artifact semantic chain differs: " + ", ".join(failed_checks)
        )
    _verify_scientific_evidence(
        artifacts_root,
        prediction=prediction,
        label_payload=label_payload,
        score=score,
        offset_sha256=offset_sha,
        projection_sha256=projection_sha,
        prediction_sha256=prediction_sha,
        label_sha256=label_sha,
        selection_sha256=selection_sha,
        work_sha256=work_sha,
        proxy_instance_fingerprint=proxy,
        parent_operator_fingerprint=parent,
    )
    documents = {
        "mechanism": mechanism,
        "instance": instance,
        "selection": selection,
        "offset": offset,
        "projection": projection,
        "prediction": prediction,
        "label": label,
        "work": work,
        "score": score,
        "result": result,
        "source_index": source_index,
    }
    return (
        index,
        _sha256_bytes(index_payload),
        total + len(index_payload),
        documents,
    )


def _finalize_with_prepared_recovery(
    run: RunCapsule,
    *,
    metrics: Mapping[str, object],
    status: str,
    next_action: str | None = None,
) -> FinalizedRun:
    """Retry only the immutable publication step after a prepared-stage fault."""

    try:
        return run.finalize(
            metrics=metrics,
            status=status,
            next_action=next_action,
        )
    except Exception:
        if not run.publication_prepared:
            raise
        return run.finalize(metrics={})


def _verify_published_source_bindings(
    source_hashes: Mapping[str, object],
    frozen_config: Mapping[str, object],
    documents: Mapping[str, Mapping[str, object]],
) -> None:
    frozen_source = _mapping(
        frozen_config.get("source"),
        "published formal source config",
        {
            "local_source_sha256",
            "source_config_path",
            "source_config_sha256",
            "source_freeze_commit",
        },
    )
    _commit(frozen_source.get("source_freeze_commit"), "published source freeze")
    formal_local = _mapping(
        frozen_source.get("local_source_sha256"),
        "published formal local source hashes",
        {
            "source_config",
            "projection_module",
            "runner_module",
            "run_capsule_module",
            "posterior_logit_module",
            "pyproject",
        },
    )
    expected_source_hashes = {
        "config",
        "projection_policy",
        "proxy_mechanism",
        "proxy_instance",
        "parent_operator",
        *formal_local,
        "o1c23_capsule_manifest",
        "o1c23_decision",
        "o1c23_operator_graph",
        "o1c22_capsule_manifest",
        "o1c22_artifact_index",
        "o1c22_result",
        "o1c22_result_file",
        "o1c18_capsule_manifest",
        "o1c18_artifact_index",
        "o1c18_build_corpus",
    }
    if set(source_hashes) != expected_source_hashes:
        raise O1C26RunError("published source-hash inventory differs")
    for name, digest in source_hashes.items():
        _sha256(digest, f"published source hash {name}")
    source_index = documents["source_index"]
    mechanism = documents["mechanism"]
    instance = documents["instance"]
    selection = documents["selection"]
    source_local = _mapping(
        source_index.get("local_source_sha256"), "published source-index local hashes"
    )
    source_config = _mapping(
        source_index.get("source_config"), "published source-index source config"
    )
    source_o1c23 = _mapping(
        source_index.get("o1c23"), "published source-index O1C-0023"
    )
    source_o1c22 = _mapping(
        source_index.get("o1c22"), "published source-index O1C-0022"
    )
    source_o1c18 = _mapping(
        source_index.get("o1c18"), "published source-index O1C-0018"
    )
    experiment = _mapping(frozen_config.get("experiment"), "published experiment")
    bindings = {
        "run_config": source_index.get("run_config_sha256")
        == source_hashes.get("config"),
        "projection_policy": source_index.get("projection_policy_sha256")
        == source_hashes.get("projection_policy")
        == projection_policy_sha256(),
        "mechanism": mechanism.get("proxy_mechanism_sha256")
        == source_hashes.get("proxy_mechanism"),
        "instance": instance.get("proxy_instance_fingerprint")
        == source_hashes.get("proxy_instance"),
        "parent": selection.get("parent_operator_fingerprint")
        == source_hashes.get("parent_operator"),
        "experiment": mechanism.get("experiment_sha256")
        == _sha256_bytes(canonical_json_bytes(dict(experiment))),
        "formal_local": dict(source_local) == dict(formal_local),
        "source_config_path": source_config.get("relative_path")
        == frozen_source.get("source_config_path"),
        "source_config_digest": source_config.get("sha256")
        == frozen_source.get("source_config_sha256")
        == source_hashes.get("source_config"),
        "source_local_hashes": all(
            source_hashes.get(name) == digest for name, digest in formal_local.items()
        ),
        "o1c23_manifest": source_o1c23.get("capsule_manifest_sha256")
        == source_hashes.get("o1c23_capsule_manifest"),
        "o1c23_decision": source_o1c23.get("decision_sha256")
        == source_hashes.get("o1c23_decision"),
        "o1c23_graph": source_o1c23.get("operator_graph_sha256")
        == source_hashes.get("o1c23_operator_graph"),
        "o1c22_manifest": source_o1c22.get("capsule_manifest_sha256")
        == source_hashes.get("o1c22_capsule_manifest"),
        "o1c22_index": source_o1c22.get("artifact_index_sha256")
        == source_hashes.get("o1c22_artifact_index"),
        "o1c22_result": source_o1c22.get("result_sha256")
        == source_hashes.get("o1c22_result"),
        "o1c22_result_file": source_o1c22.get("result_file_sha256")
        == source_hashes.get("o1c22_result_file"),
        "o1c18_manifest": source_o1c18.get("capsule_manifest_sha256")
        == source_hashes.get("o1c18_capsule_manifest"),
        "o1c18_index": source_o1c18.get("artifact_index_sha256")
        == source_hashes.get("o1c18_artifact_index"),
        "o1c18_corpus": source_o1c18.get("artifact_corpus_sha256")
        == source_hashes.get("o1c18_build_corpus"),
    }
    failed = sorted(name for name, passed in bindings.items() if not passed)
    if failed:
        raise O1C26RunError("published source provenance differs: " + ", ".join(failed))


def _verified_published_summary(
    manager: RunCapsuleManager,
    finalized: FinalizedRun,
    lifecycle_status: str,
) -> tuple[dict[str, object], int]:
    if finalized.attempt_id != ATTEMPT_ID:
        raise O1C26RunError("published attempt identity differs")
    verification = manager.verify(finalized.path)
    if (
        not finalized.verification.ok
        or not verification.ok
        or verification.manifest_sha256 != finalized.manifest_sha256
    ):
        raise O1C26RunError("final O1C-0026 capsule verification differs")
    outer_metrics, _ = _read_json(
        finalized.path / "metrics.json", "published O1C-0026 metrics"
    )
    values = _mapping(outer_metrics.get("values"), "published metric values")
    capsule_config, _ = _read_json(
        finalized.path / "config.json", "published O1C-0026 config"
    )
    source_hashes = _mapping(
        capsule_config.get("source_hashes"), "published source hashes"
    )
    frozen_config = _mapping(capsule_config.get("config"), "published formal config")
    frozen_budgets = _mapping(frozen_config.get("budgets"), "published formal budgets")
    capsule_status = outer_metrics.get("status")
    if (
        outer_metrics.get("schema") != "o1c-run-metrics-v1"
        or outer_metrics.get("attempt_id") != ATTEMPT_ID
        or values.get("schema") != RUN_METRICS_SCHEMA
        or capsule_config.get("attempt_id") != ATTEMPT_ID
        or capsule_status not in {"completed", "failed", "stopped"}
    ):
        raise O1C26RunError("published O1C-0026 capsule status differs")
    proxy = _sha256(source_hashes.get("proxy_instance"), "published source proxy")
    parent = _sha256(source_hashes.get("parent_operator"), "published source parent")
    if (
        values.get("proxy_instance_fingerprint") != proxy
        or values.get("parent_operator_fingerprint") != parent
    ):
        raise O1C26RunError("published failure disposition source differs")
    artifact_index_sha256 = values.get("artifact_index_sha256")
    artifact_index_exists = (
        finalized.path / "artifacts" / "artifact_index.json"
    ).is_file()
    result_bearing = artifact_index_sha256 is not None
    if result_bearing and not artifact_index_exists:
        raise O1C26RunError("published result-bearing inventory differs")
    if result_bearing:
        verified_index, verified_index_sha256, persistent_bytes, documents = (
            _verify_o1c26_artifact_index(finalized.path / "artifacts")
        )
        result = documents["result"]
        score = documents["score"]
        if (
            verified_index.get("proxy_instance_fingerprint") != proxy
            or result.get("proxy_instance_fingerprint") != proxy
            or result.get("parent_operator_fingerprint") != parent
        ):
            raise O1C26RunError("published artifact source binding differs")
        _verify_published_source_bindings(source_hashes, frozen_config, documents)
        operationally_complete = values.get("operationally_complete") is True
        disposition = _authoritative_disposition(
            result.get("classification"), operationally_complete, proxy
        )
        budget_checks = _mapping(values.get("budget_checks"), "published budget checks")
        if any(not isinstance(value, bool) for value in budget_checks.values()):
            raise O1C26RunError("published budget checks must be boolean")
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if passed is not True
        )
        supplied_failed = _sequence(
            values.get("failed_budgets"), "published failed budgets"
        )
        if (
            _sha256(artifact_index_sha256, "published artifact index")
            != verified_index_sha256
            or values.get("persistent_artifact_bytes") != persistent_bytes
            or values.get("result_sha256") != result.get("result_sha256")
            or values.get("scientific_score_report_sha256")
            != score.get("score_report_sha256")
            or values.get("classification") != disposition["classification"]
            or values.get("closure_disposition") != disposition["closure_disposition"]
            or values.get("closed_operator_fingerprint")
            != disposition["closed_operator_fingerprint"]
            or values.get("parent_closed") is not False
            or values.get("selection_receipt_sha256")
            != result.get("selection_receipt_sha256")
            or values.get("projection_freeze_sha256")
            != result.get("projection_freeze_sha256")
            or values.get("prediction_set_freeze_sha256")
            != result.get("prediction_set_freeze_sha256")
            or values.get("label_access_receipt_sha256")
            != result.get("label_access_receipt_sha256")
            or values.get("work_ledger_sha256") != result.get("work_ledger_sha256")
            or list(supplied_failed) != failed_budgets
            or not isinstance(values.get("scientific_result_claimed"), bool)
            or values.get("scientific_result_claimed") != operationally_complete
            or not isinstance(values.get("scientific_success_gate_passed"), bool)
            or values.get("scientific_success_gate_passed")
            != bool(
                operationally_complete
                and result.get("scientific_success_gate_passed") is True
            )
        ):
            raise O1C26RunError("published artifact-index metric binding differs")
        lifecycle_failure = set(budget_checks) == {"lifecycle"}
        if lifecycle_failure:
            if budget_checks.get("lifecycle") is not False or operationally_complete:
                raise O1C26RunError("published lifecycle-failure budget differs")
        else:
            budgets = O1C26Budgets.from_mapping(frozen_budgets)
            source_index = documents["source_index"]
            expected_source_bytes = (
                _integer(
                    source_index.get("source_artifact_bytes_read_before_science"),
                    "published source-index pre-science bytes",
                    0,
                    1 << 60,
                )
                + LABEL_BYTES
            )
            recomputed_checks = _recomputed_budget_checks(
                budgets,
                values,
                documents["work"],
                persistent_bytes,
                expected_source_bytes,
            )
            if dict(budget_checks) != recomputed_checks:
                raise O1C26RunError("published recomputed budget checks differ")
        if operationally_complete != all(
            value is True for value in budget_checks.values()
        ):
            raise O1C26RunError("published operational budget disposition differs")
    else:
        early_failure = _operational_failure_disposition(proxy, parent)
        if any(values.get(key) != expected for key, expected in early_failure.items()):
            raise O1C26RunError("published early-failure disposition differs")
        if values.get("result_sha256") is not None:
            raise O1C26RunError("indexless failure cannot claim a result")
    if capsule_status == "completed":
        if (
            not result_bearing
            or values.get("operationally_complete") is not True
            or values.get("scientific_result_claimed") is not True
            or values.get("classification") not in {PRESENT, NULL}
        ):
            raise O1C26RunError("completed O1C-0026 metric disposition differs")
        maximum_wall = _number(
            frozen_budgets.get("maximum_wall_seconds"),
            "published maximum wall seconds",
            0.001,
            86_400.0,
        )
        elapsed_seconds = _number(
            outer_metrics.get("elapsed_seconds"),
            "published capsule elapsed seconds",
            0.0,
            1_000_000.0,
        )
        budgeted_wall_seconds = _number(
            values.get("budgeted_wall_seconds"),
            "published budgeted wall seconds",
            0.0,
            1_000_000.0,
        )
        pre_capsule_wall_seconds = _number(
            values.get("pre_capsule_wall_seconds"),
            "published pre-capsule wall seconds",
            0.0,
            1_000_000.0,
        )
        if (
            pre_capsule_wall_seconds + elapsed_seconds > budgeted_wall_seconds
            or budgeted_wall_seconds > maximum_wall
        ):
            raise O1C26RunError("completed O1C-0026 metric disposition differs")
    elif values.get("classification") != FAILURE:
        raise O1C26RunError("non-completed O1C-0026 must be operational failure")
    summary = {
        "attempt_id": ATTEMPT_ID,
        "path": str(finalized.path),
        "manifest_sha256": finalized.manifest_sha256,
        "verified": True,
        "status": lifecycle_status,
        "capsule_status": capsule_status,
        "classification": values.get("classification"),
        "result_sha256": values.get("result_sha256"),
    }
    return summary, 0 if capsule_status == "completed" else 2


def run_capsule_from_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> int:
    """Run or report the exact one-shot O1C-0026 lifecycle."""

    cpu_started = time.process_time()
    wall_started = time.monotonic()
    config_path, lab_root = _resolve_root(path, root)
    manager = RunCapsuleManager(lab_root)
    lease_path = manager.output_root / ".attempt_ids" / f"{ATTEMPT_ID}.execution.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    lease_fd = os.open(lease_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lease_fd).st_mode):
            raise O1C26RunError("O1C-0026 execution lease is not a regular file")
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                json.dumps(
                    {
                        "schema": PREFLIGHT_SCHEMA,
                        "attempt_id": ATTEMPT_ID,
                        "status": "active-execution-lease-held",
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        published = manager.finalized_attempt(ATTEMPT_ID)
        if published is not None:
            summary, exit_code = _verified_published_summary(
                manager, published, "already-finalized-no-replay"
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return exit_code

        if ATTEMPT_ID in manager.recoverable_attempt_ids():
            interrupted = manager.recover(ATTEMPT_ID)
            if interrupted.publication_prepared:
                finalized = _finalize_with_prepared_recovery(
                    interrupted,
                    metrics={},
                    status="completed",
                )
                summary, exit_code = _verified_published_summary(
                    manager, finalized, "publication-completed-no-replay"
                )
                print(json.dumps(summary, indent=2, sort_keys=True))
                return exit_code
            interrupted_config, _ = _read_json(
                interrupted.staging_path / "config.json",
                "interrupted O1C-0026 config",
            )
            interrupted_sources = _mapping(
                interrupted_config.get("source_hashes"),
                "interrupted O1C-0026 source hashes",
            )
            stopped_metrics = {
                **_operational_failure_disposition(
                    _sha256(
                        interrupted_sources.get("proxy_instance"),
                        "interrupted proxy instance",
                    ),
                    _sha256(
                        interrupted_sources.get("parent_operator"),
                        "interrupted parent operator",
                    ),
                ),
                "reason": "interrupted running capsule is preserved without replay",
            }
            stopped = _finalize_with_prepared_recovery(
                interrupted,
                metrics=stopped_metrics,
                status="stopped",
                next_action=(
                    "Preserve this interrupted proxy capsule and advance under a new "
                    "O1C identity after diagnosing the last checkpoint."
                ),
            )
            print(f"stopped capsule: {stopped.path}", file=sys.stderr)
            return 2

        config = load_o1c26_run_config(config_path, root=lab_root)
        preflight = preflight_o1c26(config.config_path, root=config.root)
        if not preflight.ready or preflight.source is None:
            print(
                json.dumps(preflight.report, indent=2, sort_keys=True), file=sys.stderr
            )
            return 2
        source = preflight.source
        if (
            source.source_artifact_bytes_read
            > config.budgets.maximum_source_artifact_bytes_read
        ):
            report = {
                **dict(preflight.report),
                "status": "resource-interlock-pending",
                "reason": "pre-reservation source-read budget would be exceeded",
            }
            print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
            return 2
        commit_value = _git_clean_commit(config.root)
        if not _git_is_ancestor(config.root, config.source_freeze_commit, commit_value):
            raise O1C26RunError("HEAD does not descend from O1C-0026 source freeze")
        hashes = _source_hashes(config, source)
        run = manager.start(
            attempt_id=ATTEMPT_ID,
            slug=FORMAL_SLUG,
            commit=commit_value,
            hypothesis=str(config.top["hypothesis"]),
            prediction=str(config.top["prediction"]),
            controls=tuple(
                str(value) for value in _sequence(config.top["controls"], "controls")
            ),
            budgets=dict(_mapping(config.top["budgets"], "budgets")),
            source_hashes=hashes,
            claim_level=ClaimLevel.RETROSPECTIVE,
            next_action=str(config.top["next_action"]),
            config=config.top,
            command=(
                sys.executable,
                "-m",
                "o1_crypto_lab.proof_ancestry_pair_residual_run",
                "--config",
                str(config.config_path),
            ),
            environment={
                "information_boundary": "CONSUMED_BUILD_LOO_NO_FRESH_TARGET",
                "o1c23_capsule_manifest_sha256": source.o1c23.manifest_sha256,
                "o1c22_capsule_manifest_sha256": (
                    source.o1c22.finalized.manifest_sha256
                ),
                "proxy_instance_fingerprint": source.proxy_instance[
                    "proxy_instance_fingerprint"
                ],
                "sibling_scope": "external_w52_tree_only",
                "build_faps": FOLD_COUNT,
                "development_faps": 0,
                "mps": False,
                "gpu": False,
            },
        )
        pre_capsule_wall_seconds = time.monotonic() - wall_started
        persisted: dict[str, dict[str, object]] = {}
        persistent_bytes = 0

        def persist(relative: str, payload: bytes, phase: str) -> Path:
            nonlocal persistent_bytes
            safe = _safe_relative(relative, "artifact")
            if safe in persisted:
                raise O1C26RunError(f"duplicate artifact: {safe}")
            if (
                not isinstance(payload, bytes)
                or not isinstance(phase, str)
                or not phase
            ):
                raise O1C26RunError("artifact payload or phase differs")
            if (
                persistent_bytes + len(payload)
                > config.budgets.maximum_persistent_artifact_bytes
            ):
                raise O1C26RunError("persistent artifact budget would be exceeded")
            path_value = run.write_artifact(safe, payload)
            if path_value.read_bytes() != payload:
                raise O1C26RunError(f"persisted artifact differs: {safe}")
            persisted[safe] = {
                "sha256": _sha256_bytes(payload),
                "bytes": len(payload),
                "phase": phase,
            }
            persistent_bytes += len(payload)
            return path_value

        source_bytes = source.source_artifact_bytes_read
        try:
            run.checkpoint(
                {
                    "phase": "AUTHORITATIVE_SELECTION_VALIDATED_PRE_SCIENCE",
                    "o1c23_manifest_sha256": source.o1c23.manifest_sha256,
                    "o1c22_manifest_sha256": source.o1c22.finalized.manifest_sha256,
                    "selection_receipt_sha256": source.selection_receipt[
                        "selection_receipt_sha256"
                    ],
                }
            )
            persist(
                "o1c0023_decision.json",
                source.decision_payload,
                "AUTHORITATIVE_SOURCE",
            )
            persist(
                "o1c0023_next_operator_graph.json",
                source.operator_graph_payload,
                "AUTHORITATIVE_SOURCE",
            )
            persist(
                "selection_receipt.json",
                canonical_json_bytes(source.selection_receipt),
                "AUTHORITATIVE_SOURCE",
            )
            persist(
                "projection_policy.json",
                canonical_json_bytes(projection_policy()),
                "SOURCE_POLICY",
            )
            persist(
                "proxy_mechanism.json",
                canonical_json_bytes(source.proxy_mechanism),
                "SOURCE_POLICY",
            )
            persist(
                "proxy_instance.json",
                canonical_json_bytes(source.proxy_instance),
                "AUTHORITATIVE_SOURCE",
            )
            source_index = _source_index(config, source)
            persist(
                "source_index.json",
                canonical_json_bytes(source_index),
                "AUTHORITATIVE_SOURCE",
            )
            source_bytes += LABEL_BYTES
            outcome = run_o1c26_science(source, persist)
            run.checkpoint(
                {
                    "phase": "SCIENTIFIC_SCORE_AND_WORK_FROZEN_PRE_OPERATIONAL_DISPOSITION",
                    "classification": outcome.report["classification"],
                    "score_report_sha256": outcome.report["score_report_sha256"],
                    "projection_freeze_sha256": outcome.projection_freeze_sha256,
                    "prediction_set_freeze_sha256": (
                        outcome.prediction_set_freeze_sha256
                    ),
                    "artifact_count_before_final_result": len(persisted),
                    "persistent_bytes_before_final_result": persistent_bytes,
                }
            )
            final_result = _final_result(outcome.report)

            def candidate_index(
                result_document: Mapping[str, object],
            ) -> tuple[dict[str, object], bytes, int]:
                result_payload = canonical_json_bytes(result_document)
                candidate_artifacts = {
                    **persisted,
                    "proof_ancestry_pair_residual_result.json": {
                        "sha256": _sha256_bytes(result_payload),
                        "bytes": len(result_payload),
                        "phase": "SCIENTIFIC_RESULT_CANDIDATE",
                    },
                }
                if set(candidate_artifacts) != _expected_o1c26_indexed_artifacts():
                    raise O1C26RunError("pre-index O1C-0026 artifact inventory differs")
                document = {
                    "schema": ARTIFACT_INDEX_SCHEMA,
                    "attempt_id": ATTEMPT_ID,
                    "o1c23_capsule_manifest_sha256": source.o1c23.manifest_sha256,
                    "o1c22_capsule_manifest_sha256": (
                        source.o1c22.finalized.manifest_sha256
                    ),
                    "proxy_instance_fingerprint": source.proxy_instance[
                        "proxy_instance_fingerprint"
                    ],
                    "selection_receipt_sha256": source.selection_receipt[
                        "selection_receipt_sha256"
                    ],
                    "projection_freeze_sha256": outcome.projection_freeze_sha256,
                    "prediction_set_freeze_sha256": (
                        outcome.prediction_set_freeze_sha256
                    ),
                    "label_access_receipt_sha256": (
                        outcome.label_access_receipt_sha256
                    ),
                    "work_ledger_sha256": outcome.work.document()["work_ledger_sha256"],
                    "result_sha256": result_document["result_sha256"],
                    "artifacts": dict(sorted(candidate_artifacts.items())),
                    "indexed_artifact_count": len(candidate_artifacts),
                    "indexed_artifact_bytes": (persistent_bytes + len(result_payload)),
                }
                index_payload = canonical_json_bytes(document)
                return (
                    document,
                    result_payload,
                    persistent_bytes + len(result_payload) + len(index_payload),
                )

            artifact_index, result_payload, predicted_persistent_bytes = (
                candidate_index(final_result)
            )
            persist(
                "proof_ancestry_pair_residual_result.json",
                result_payload,
                "SCIENTIFIC_RESULT_CANDIDATE",
            )
            index_payload = canonical_json_bytes(artifact_index)
            persist("artifact_index.json", index_payload, "ARTIFACT_INDEX")
            _, artifact_index_sha256, verified_persistent_bytes, _ = (
                _verify_o1c26_artifact_index(
                    run.staging_path / "artifacts",
                    expected_index=artifact_index,
                )
            )
            if (
                verified_persistent_bytes != persistent_bytes
                or verified_persistent_bytes != predicted_persistent_bytes
            ):
                raise O1C26RunError("verified persistent-byte accounting differs")
            _recheck_sources(config, source, hashes)
            if _git_clean_commit(config.root) != commit_value:
                raise O1C26RunError("lab commit changed during O1C-0026")
            cpu_seconds = time.process_time() - cpu_started
            wall_seconds = time.monotonic() - wall_started
            peak_rss_bytes = _process_peak_rss_bytes()
            budgeted_cpu_seconds = cpu_seconds + PUBLICATION_CPU_RESERVE_SECONDS
            budgeted_wall_seconds = wall_seconds + PUBLICATION_WALL_RESERVE_SECONDS
            budgeted_peak_rss_bytes = peak_rss_bytes + PUBLICATION_RSS_RESERVE_BYTES
            work_document = outcome.work.document()
            measurement_metrics = {
                "cpu_seconds": cpu_seconds,
                "wall_seconds": wall_seconds,
                "pre_capsule_wall_seconds": pre_capsule_wall_seconds,
                "peak_rss_bytes": peak_rss_bytes,
                "publication_cpu_reserve_seconds": (PUBLICATION_CPU_RESERVE_SECONDS),
                "publication_wall_reserve_seconds": (PUBLICATION_WALL_RESERVE_SECONDS),
                "publication_rss_reserve_bytes": PUBLICATION_RSS_RESERVE_BYTES,
                "budgeted_cpu_seconds": budgeted_cpu_seconds,
                "budgeted_wall_seconds": budgeted_wall_seconds,
                "budgeted_peak_rss_bytes": budgeted_peak_rss_bytes,
                "source_artifact_bytes_read": source_bytes,
                "persistent_artifact_bytes": verified_persistent_bytes,
                "build_faps_deserialized": outcome.work.build_faps_deserialized,
                "development_faps_deserialized": (
                    outcome.work.development_faps_deserialized
                ),
                "ridge_fits": outcome.work.ridge_fits,
                "alpha_bit_evaluations": outcome.work.alpha_bit_evaluations,
                "diagnostic_bit_evaluations": (outcome.work.diagnostic_bit_evaluations),
                "fresh_targets": outcome.work.fresh_targets,
                "native_solver_branches": outcome.work.native_solver_branches,
                "scientific_entropy_calls": outcome.work.scientific_entropy_calls,
                "sibling_reads": outcome.work.sibling_reads,
                "sibling_writes": outcome.work.sibling_writes,
                "mps_calls": outcome.work.mps_calls,
                "gpu_calls": outcome.work.gpu_calls,
                "maximum_observed_projection_scratch_bytes": (
                    outcome.work.maximum_observed_projection_scratch_bytes
                ),
                "maximum_live_state_bytes": outcome.work.maximum_live_state_bytes,
                "primary_state_replays": outcome.work.primary_state_replays,
                "primary_state_replay_coordinates": (
                    outcome.work.primary_state_replay_coordinates
                ),
                "sibling_scope": outcome.work.sibling_scope,
            }
            expected_source_bytes = (
                _integer(
                    source_index.get("source_artifact_bytes_read_before_science"),
                    "source-index pre-science bytes",
                    0,
                    1 << 60,
                )
                + LABEL_BYTES
            )
            budget_checks = _recomputed_budget_checks(
                config.budgets,
                measurement_metrics,
                work_document,
                verified_persistent_bytes,
                expected_source_bytes,
            )
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            operationally_complete = not failed_budgets
            disposition = _authoritative_disposition(
                final_result["classification"],
                operationally_complete,
                str(source.proxy_instance["proxy_instance_fingerprint"]),
            )
            metrics = {
                "schema": RUN_METRICS_SCHEMA,
                "classification": disposition["classification"],
                "scientific_success_gate_passed": bool(
                    operationally_complete
                    and final_result["scientific_success_gate_passed"] is True
                ),
                "result_sha256": final_result["result_sha256"],
                "scientific_score_report_sha256": outcome.report["score_report_sha256"],
                "artifact_index_sha256": artifact_index_sha256,
                "proxy_instance_fingerprint": source.proxy_instance[
                    "proxy_instance_fingerprint"
                ],
                "parent_operator_fingerprint": source.selection_receipt[
                    "parent_operator_fingerprint"
                ],
                "closure_disposition": disposition["closure_disposition"],
                "closed_operator_fingerprint": disposition[
                    "closed_operator_fingerprint"
                ],
                "parent_closed": disposition["parent_closed"],
                "selection_receipt_sha256": source.selection_receipt[
                    "selection_receipt_sha256"
                ],
                "projection_freeze_sha256": outcome.projection_freeze_sha256,
                "prediction_set_freeze_sha256": (outcome.prediction_set_freeze_sha256),
                "label_access_receipt_sha256": (outcome.label_access_receipt_sha256),
                "work_ledger_sha256": work_document["work_ledger_sha256"],
                **measurement_metrics,
                "source_artifact_accounting_scope": (
                    "selected_scientific_payloads_and_label; full capsule scans "
                    "are integrity verification"
                ),
                "budget_checks": budget_checks,
                "failed_budgets": failed_budgets,
                "operationally_complete": operationally_complete,
                "scientific_result_claimed": operationally_complete,
            }
            run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
            finalized = _finalize_with_prepared_recovery(
                run,
                metrics=metrics,
                status="completed" if operationally_complete else "failed",
            )
        except Exception as exc:
            if run.publication_prepared:
                raise
            run.append_stderr(f"{type(exc).__name__}: {exc}\n")
            failure_metrics = _failure_metrics(
                exc,
                cpu_started=cpu_started,
                wall_started=wall_started,
                source_bytes=source_bytes,
                persistent_bytes=persistent_bytes,
                proxy_instance_fingerprint=str(
                    source.proxy_instance["proxy_instance_fingerprint"]
                ),
                parent_operator_fingerprint=str(
                    source.selection_receipt["parent_operator_fingerprint"]
                ),
            )
            index_path = run.staging_path / "artifacts" / "artifact_index.json"
            if index_path.is_file():
                try:
                    (
                        _,
                        failure_index_sha256,
                        failure_persistent_bytes,
                        failure_documents,
                    ) = _verify_o1c26_artifact_index(run.staging_path / "artifacts")
                except Exception:
                    pass
                else:
                    failure_result = failure_documents["result"]
                    failure_score = failure_documents["score"]
                    failure_metrics.update(
                        {
                            "artifact_index_sha256": failure_index_sha256,
                            "persistent_artifact_bytes": failure_persistent_bytes,
                            "result_sha256": failure_result["result_sha256"],
                            "scientific_score_report_sha256": failure_score[
                                "score_report_sha256"
                            ],
                            "selection_receipt_sha256": failure_result[
                                "selection_receipt_sha256"
                            ],
                            "projection_freeze_sha256": failure_result[
                                "projection_freeze_sha256"
                            ],
                            "prediction_set_freeze_sha256": failure_result[
                                "prediction_set_freeze_sha256"
                            ],
                            "label_access_receipt_sha256": failure_result[
                                "label_access_receipt_sha256"
                            ],
                            "work_ledger_sha256": failure_result["work_ledger_sha256"],
                            "scientific_success_gate_passed": False,
                            "budget_checks": {"lifecycle": False},
                            "failed_budgets": ["lifecycle"],
                        }
                    )
            finalized = _finalize_with_prepared_recovery(
                run,
                metrics=failure_metrics,
                status="failed",
                next_action=(
                    "Preserve the operational failure. Repair only the failing "
                    "lifecycle or resource surface under a new O1C identity."
                ),
            )
            print(f"failed capsule: {finalized.path}", file=sys.stderr)
            return 2
        summary, exit_code = _verified_published_summary(
            manager, finalized, "publication-finalized"
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return exit_code
    finally:
        os.close(lease_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--root")
    parser.add_argument("--preflight", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.preflight:
        report = preflight_o1c26(args.config, root=args.root).report
        destination = sys.stdout if report.get("status") == "ready" else sys.stderr
        print(json.dumps(report, indent=2, sort_keys=True), file=destination)
        return 0 if report.get("status") == "ready" else 2
    return run_capsule_from_config(args.config, root=args.root)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "ATTEMPT_ID",
    "FAILURE",
    "NULL",
    "O1C22NarrowSource",
    "O1C26Budgets",
    "O1C26Preflight",
    "O1C26PreparedSource",
    "O1C26RunConfig",
    "O1C26RunError",
    "O1C26ScienceOutcome",
    "O1C26SelectionMismatch",
    "O1C26WorkLedger",
    "PREFLIGHT_SCHEMA",
    "PRESENT",
    "RESULT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SCORE_ARMS",
    "build_parser",
    "load_o1c26_run_config",
    "main",
    "preflight_o1c26",
    "run_capsule_from_config",
    "run_o1c26_science",
]
