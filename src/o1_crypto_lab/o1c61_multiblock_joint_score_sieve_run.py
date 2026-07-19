"""O1C-0061 one-shot fix-forward for CaDiCaL's soft conflict stop."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, cast

import numpy as np

from . import o1c60_multiblock_joint_score_sieve_run as _mechanism
from .chacha_trace import chacha20_blocks
from .criticality_potential import score_potential_assignment
from .joint_score_sieve import JointScoreSieveResult
from .joint_score_sieve_v3 import (
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS,
    build_native_joint_score_sieve,
    run_joint_score_sieve,
    validate_soft_conflict_ledger,
)
from .o1_relational_search import O1RelationalSearchError, sha256_file
from .o1c37_relational_guided_search_run import (
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)


_scientific = _mechanism._mechanism
ATTEMPT_ID = "O1C-0061"
CONFIG_SCHEMA = "o1-256-multiblock-joint-score-sieve-soft-stop-config-v1"
RESULT_SCHEMA = "o1-256-multiblock-joint-score-sieve-soft-stop-result-v1"
PREFLIGHT_SCHEMA = "o1-256-multiblock-joint-score-sieve-soft-stop-preflight-v1"
INTENT_SCHEMA = "o1-256-multiblock-joint-score-sieve-soft-stop-native-call-intent-v1"
RESULT_RELATIVE = Path(
    "research/O1C0061_MULTIBLOCK_JOINT_SCORE_SIEVE_SOFT_STOP_RESULT_20260719.json"
)
CAPSULE_SUFFIX = "O1C-0061_multiblock-joint-score-sieve-soft-stop-v1"
CONSUMED_CAPSULE_RELATIVE = _mechanism.CONSUMED_CAPSULE_RELATIVE
BLOCK_COUNT = _mechanism.BLOCK_COUNT
DECOY_COUNT = _mechanism.DECOY_COUNT
EXPECTED_VARIABLES = _mechanism.EXPECTED_VARIABLES
EXPECTED_CLAUSES = _mechanism.EXPECTED_CLAUSES
EXPECTED_FACTORS = _mechanism.EXPECTED_FACTORS
EXPECTED_ENERGY_ENTRIES = _mechanism.EXPECTED_ENERGY_ENTRIES
EXPECTED_OBSERVED_VARIABLES = _mechanism.EXPECTED_OBSERVED_VARIABLES
EXPECTED_TRUTH_SCORE = _mechanism.EXPECTED_TRUTH_SCORE
EXPECTED_DECOY_MAX = _mechanism.EXPECTED_DECOY_MAX
MEMORY_LIMIT_BYTES = _mechanism.MEMORY_LIMIT_BYTES
CONFLICT_LIMIT = _mechanism.CONFLICT_LIMIT
NATIVE_TIMEOUT_SECONDS = _mechanism.NATIVE_TIMEOUT_SECONDS
SCORE_TOLERANCE = _mechanism.SCORE_TOLERANCE
TRUTH_SCORE_TOLERANCE = _mechanism.TRUTH_SCORE_TOLERANCE
SOURCE_NAMES = (
    "template",
    "semantic_map",
    "native_source",
    "native_base_source",
    "joint_score_sieve",
    "joint_score_sieve_v2",
    "joint_score_sieve_base",
    "full256_multiblock_cnf",
    "multiblock_criticality_potential",
    "criticality_potential",
    "full256_cnf",
    "full256_forward_assignment",
    "proof_parent_criticality",
    "broker_source",
    "mechanism_base_runner",
    "mechanism_transitive_base_runner",
    "runner",
    "consumed_result",
)
COMMIT_BOUND_NAMES = tuple(
    name
    for name in SOURCE_NAMES
    if name not in {"template", "semantic_map", "consumed_result"}
)
CONSUMED_HASH_NAMES = _mechanism.CONSUMED_HASH_NAMES


class O1C61RunError(RuntimeError):
    """The soft-stop ledger, immutable inputs, or one-shot lifecycle differs."""


def prospective_threshold(decoy_max: float, safety_margin: float) -> float:
    if (
        isinstance(decoy_max, bool)
        or not isinstance(decoy_max, (int, float))
        or not math.isfinite(float(decoy_max))
        or isinstance(safety_margin, bool)
        or not isinstance(safety_margin, (int, float))
        or not math.isfinite(float(safety_margin))
        or float(safety_margin) <= 0.0
    ):
        raise O1C61RunError("prospective threshold input differs")
    return math.nextafter(float(decoy_max) - float(safety_margin), -math.inf)


def classify_sieve(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    minimum_material_bound_drop: float,
) -> tuple[str, dict[str, object]]:
    return _mechanism.classify_sieve(
        native,
        public_model_verified=public_model_verified,
        minimum_material_bound_drop=minimum_material_bound_drop,
    )


def _invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    threshold: float,
    conflict_limit: int,
    timeout_seconds: float,
    memory_limit_bytes: int,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> JointScoreSieveResult:
    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=threshold,
        conflict_limit=conflict_limit,
        seed=0,
        timeout_seconds=timeout_seconds,
        memory_limit_bytes=memory_limit_bytes,
    )


def _invoke_native_once_terminal(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    threshold: float,
    conflict_limit: int,
    timeout_seconds: float,
    memory_limit_bytes: int,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    try:
        result = _invoke_native_once(
            executable=executable,
            cnf=cnf,
            potential=potential,
            threshold=threshold,
            conflict_limit=conflict_limit,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
            runner=runner,
        )
    except Exception as exc:
        return None, {
            "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
        }
    return result, None


def validate_native_resource_ledger(
    native: JointScoreSieveResult,
    *,
    solver_calls: int,
    maximum_native_solver_calls: int = 1,
) -> dict[str, int]:
    try:
        ledger = validate_soft_conflict_ledger(native.stats)
    except O1RelationalSearchError as exc:
        raise O1C61RunError("O1C-0061 soft conflict ledger differs") from exc
    native_peak = int(native.resources["peak_rss_bytes"])
    native_wall_microseconds = int(native.resources["wall_microseconds"])
    if (
        native.conflict_limit != CONFLICT_LIMIT
        or ledger["requested_conflicts"] != CONFLICT_LIMIT
        or ledger["billed_conflicts"] > JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or ledger["conflict_limit_overshoot"]
        > JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or native_wall_microseconds > int(NATIVE_TIMEOUT_SECONDS * 1_000_000)
        or native_peak > MEMORY_LIMIT_BYTES
        or native.sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
        or solver_calls != maximum_native_solver_calls
    ):
        raise O1C61RunError("O1C-0061 native resource ledger differs")
    return ledger


def _exact_config_rows() -> dict[str, object]:
    return {
        "lineage": {
            "fix_forward_from": "O1C-0060",
            "mechanism_source_attempt": "O1C-0059",
            "new_attempt_not_retry": True,
            "o1c59_capsule_reads": 0,
            "o1c59_result_reads": 0,
            "o1c59_writes": 0,
            "o1c60_capsule_reads": 0,
            "o1c60_result_reads": 0,
            "o1c60_writes": 0,
            "only_change": "cadical-soft-conflict-stop-ledger-v3",
        },
        "consumed_target": {
            "source_attempt": "O1C-0057",
            "target_id": "o1c-0057-multiblock-fresh-0000",
            "block_count": 8,
            "counter_schedule": "eight-contiguous-without-wrap",
            "rounds": 20,
            "feed_forward": True,
            "unknown_key_bits": 256,
            "fresh_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "fresh_forward_scoring_calls": 0,
            "refits": 0,
            "primary_arm_only": True,
            "post_reveal_result_container_read_pre_native_for_provenance_and_pre_reveal_scorer_metadata": True,
            "truth_labelled_result_fields_used_as_native_or_decision_input": False,
            "reveal_and_truth_key_bytes_read_after_native_and_public_model_diagnostic_only": True,
        },
        "composition": {
            "shared_key_variables": 256,
            "block_count": 8,
            "expected_variable_count": EXPECTED_VARIABLES,
            "expected_clause_count": EXPECTED_CLAUSES,
            "expected_public_unit_clause_count": 5120,
            "expected_key_unit_clause_count": 0,
            "expected_assumption_unit_clause_count": 0,
            "expected_factor_count": EXPECTED_FACTORS,
            "expected_energy_entries": EXPECTED_ENERGY_ENTRIES,
            "expected_observed_variables": EXPECTED_OBSERVED_VARIABLES,
            "maximum_observed_variable": EXPECTED_VARIABLES,
            "expected_truth_compiled_score": EXPECTED_TRUTH_SCORE,
            "complete_score_absolute_tolerance": SCORE_TOLERANCE,
            "truth_score_absolute_tolerance": TRUTH_SCORE_TOLERANCE,
            "verification_only_forward_assignments": DECOY_COUNT * BLOCK_COUNT
            + BLOCK_COUNT,
        },
        "threshold": {
            "source": "consumed O1C-0057 scores/prefix-08-primary.f64le",
            "decoy_count": DECOY_COUNT,
            "expected_decoy_max": EXPECTED_DECOY_MAX,
            "safety_margin": SCORE_TOLERANCE,
            "rule": "nextafter(decoy_max-safety_margin,-infinity)",
            "minimum_material_bound_drop": 1.0,
        },
        "native": {
            "conflict_limit": CONFLICT_LIMIT,
            "requested_conflicts": CONFLICT_LIMIT,
            "conflict_limit_semantics": "cadical-soft-stop-with-at-most-one-conflict-overshoot",
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "ledger_equation": "solve_conflicts=requested_conflicts-unused_requested_conflicts+conflict_limit_overshoot",
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "non_darwin_memory_enforcement": "child-RLIMIT_AS-before-exec",
            "darwin_memory_enforcement": "proc_pid_rusage-physical-footprint-process-group-watchdog",
            "darwin_watchdog_poll_interval_seconds": JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
            "darwin_watchdog_guard_bytes": JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
            "darwin_watchdog_temporal_blindspot": "nominally-at-most-one-10ms-poll-interval;OS-scheduling-delay-is-not-hard-bounded;32MiB-guard-reserved-below-formal-ceiling",
            "decision_rule": "solver-owned-no-external-decisions",
            "calls": 1,
        },
        "classification": {
            "exact": "EXACT_CONSUMED_FULL256_RECOVERY",
            "active": "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY",
            "no_useful_prune": "EXACT_JOINT_SCORE_SIEVE_NO_USEFUL_PRUNE",
            "active_rule": "trail_threshold_prunes>0 or (complete_model_score_checks==0 and (root_upper_bound-minimum_upper_bound)>=minimum_material_bound_drop); complete-model-only prunes and bound minima not separable from a visited complete model are conservatively late-only",
        },
        "budgets": {
            "maximum_native_solver_calls": 1,
            "maximum_requested_conflicts": CONFLICT_LIMIT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "maximum_native_wall_seconds": NATIVE_TIMEOUT_SECONDS,
            "maximum_peak_rss_bytes": MEMORY_LIMIT_BYTES,
            "minimum_memory_pressure_free_percent": 15,
            "maximum_fresh_targets": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_fresh_reveal_calls": 0,
            "maximum_refits": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_persistent_artifact_bytes": 134_217_728,
        },
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C61RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    required = _mapping(source.get("required_commits"), "required_commits")
    rows = _exact_config_rows()
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "multiblock-joint-score-sieve-soft-stop-v1"
        or config.get("claim_level") != "TEST"
        or source.get("consumed_capsule") != CONSUMED_CAPSULE_RELATIVE.as_posix()
        or set(expected) != {*SOURCE_NAMES, *CONSUMED_HASH_NAMES}
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in expected.values()
        )
        or required
        != {"joint_score_sieve": "3ca85ff", "multiblock_adapters": "8c28958"}
        or any(config.get(name) != value for name, value in rows.items())
    ):
        raise O1C61RunError("frozen O1C-0061 config differs")
    if (
        CONFLICT_LIMIT > JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
        or JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS != CONFLICT_LIMIT + 1
    ):
        raise O1C61RunError("frozen soft conflict budget differs")
    for name in SOURCE_NAMES:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if sha256_file(resolved) != expected[name]:
            raise O1C61RunError(f"source hash differs for {name}")
    capsule = _relative_path(root, source.get("consumed_capsule"), "consumed_capsule")
    consumed_artifacts = {
        "consumed_manifest": capsule / "artifacts.sha256",
        "consumed_config": capsule / "config.json",
        "consumed_publication": capsule / "publication.json",
        "consumed_score_freeze": capsule / "score_freeze.json",
        "consumed_freeze_receipt": capsule / "freeze_receipt.json",
        "consumed_reveal": capsule / "reveal.json",
        "consumed_candidate_keys": capsule / "candidate_keys.bin",
        "consumed_prefix8_primary": capsule / "scores/prefix-08-primary.f64le",
    }
    for name, artifact in consumed_artifacts.items():
        if sha256_file(artifact.resolve(strict=True)) != expected[name]:
            raise O1C61RunError(f"consumed source hash differs for {name}")
    _scientific._required_commit_is_ancestor(
        root, str(required["joint_score_sieve"]), "core"
    )
    _scientific._required_commit_is_ancestor(
        root, str(required["multiblock_adapters"]), "adapter"
    )
    return config


def _markdown(result: Mapping[str, object]) -> str:
    classification = str(result["classification"])
    if classification.startswith("OPERATIONAL_"):
        failure = _mapping(result["operational_failure"], "operational_failure")
        return (
            "# O1C Run O1C-0061\n\n"
            f"- Classification: `{classification}`\n"
            f"- Error type: `{failure['error_type']}`\n"
            f"- Native calls consumed: `{failure['native_calls_consumed']}`\n"
            "- Retry authorized: `False`\n\n"
            "The O1C-0061 intent was consumed without a validated science claim; "
            "no prior attempt is retryable.\n"
        )
    ledger = _mapping(result["conflict_ledger"], "conflict_ledger")
    return (
        "# O1C Run O1C-0061\n\n"
        f"- Classification: `{classification}`\n"
        f"- Requested conflicts: `{ledger['requested_conflicts']}`\n"
        f"- Billed conflicts: `{ledger['billed_conflicts']}`\n"
        f"- Soft-stop overshoot: `{ledger['conflict_limit_overshoot']}`\n\n"
        "One new solver call used the unchanged scientific search and a validated "
        "CaDiCaL soft-stop ledger.\n"
    )


def _finalize_capsule(
    *,
    root: Path,
    capsule: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
) -> None:
    if (capsule / "artifacts.sha256").exists():
        raise O1C61RunError("O1C-0061 capsule is already terminal")
    run_path = capsule / "RUN.md"
    if not run_path.exists():
        _scientific._atomic_bytes(run_path, _markdown(result).encode("utf-8"))
    resources_row = cast(dict[str, object], result["resources"])
    result_path = capsule / "result.json"
    for _ in range(8):
        _scientific._replace_owned_json(result_path, result)
        manifest, persistent = _scientific._capsule_manifest(
            capsule, exclude={"artifacts.sha256"}
        )
        if resources_row["persistent_artifact_bytes"] == persistent:
            break
        resources_row["persistent_artifact_bytes"] = persistent
    else:
        raise O1C61RunError("persistent artifact ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C61RunError("persistent artifact budget differs")
    _scientific._atomic_bytes(capsule / "artifacts.sha256", manifest)
    for artifact in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        artifact.chmod(0o444 if artifact.is_file() else 0o555)
    capsule.chmod(0o555)
    _scientific._atomic_json(root / RESULT_RELATIVE, result)


def _make_capsule_writable(capsule: Path) -> None:
    capsule.chmod(0o755)
    for artifact in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        if artifact.is_symlink():
            raise O1C61RunError("post-native capsule contains a symbolic link")
        artifact.chmod(0o755 if artifact.is_dir() else 0o644)


def _optional_mapping(path: Path) -> Mapping[str, object]:
    if not path.is_file():
        return {}
    try:
        return _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _terminalize_post_native_failure(
    *, root: Path, capsule: Path, error: Exception
) -> dict[str, object]:
    native_path = capsule / "native_result.json"
    intent_path = capsule / "native_call_intent.json"
    if not native_path.is_file() or not intent_path.is_file():
        raise O1C61RunError("post-native terminalization lacks persisted evidence")
    native_payload = native_path.read_bytes()
    native_raw = _read_json(native_path)
    intent = _optional_mapping(intent_path)
    preflight = _optional_mapping(capsule / "preflight.json")
    ledger_persisted = (capsule / "conflict_ledger.json").is_file()
    public_complete = (capsule / "public_model_diagnostic.json").is_file()
    truth_intent = (capsule / "truth_access_intent.json").is_file()
    truth_receipt = (capsule / "truth_access_receipt.json").is_file()
    truth_stage = (
        "COMPLETED_RECEIPT_PERSISTED"
        if truth_receipt
        else "STARTED_RECEIPT_ABSENT_READ_STATE_UNKNOWN"
        if truth_intent
        else "NOT_STARTED"
    )
    truth_read: bool | None = True if truth_receipt else None if truth_intent else False
    calls = int(cast(int, intent.get("calls_authorized", 1)))
    recorded_at = datetime.now().astimezone().isoformat(timespec="seconds")
    failure = {
        "classification": "OPERATIONAL_POST_NATIVE_VALIDATION_FAILURE_NO_SCIENCE_CLAIM",
        "error_type": type(error).__name__,
        "error_message": str(error),
        "occurred_after_persisted_intent": True,
        "occurred_after_persisted_native_result": True,
        "native_calls_consumed": calls,
        "native_result_preserved": True,
        "native_result_sha256": hashlib.sha256(native_payload).hexdigest(),
        "conflict_ledger_persisted": ledger_persisted,
        "public_model_diagnostic_complete": public_complete,
        "truth_access_stage": truth_stage,
        "truth_key_bytes_read": truth_read,
        "retry_authorized": False,
        "o1c59_retry_authorized": False,
        "o1c60_retry_authorized": False,
    }
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": intent.get("recorded_at", recorded_at),
        "recorded_at": recorded_at,
        "source_commit": preflight.get("source_commit"),
        "classification": failure["classification"],
        "capsule": capsule.relative_to(root).as_posix(),
        "claim_boundary": {
            "consumed_attempt": "O1C-0057",
            "new_attempt_not_prior_retry": True,
            "native_solver_calls": calls,
            "validated_conflict_ledger": ledger_persisted,
            "validated_native_science_result": False,
            "truth_access_stage": truth_stage,
            "retry_authorized": False,
        },
        "operational_failure": failure,
        "native": native_raw,
        "metrics": {
            "native_status": "UNVALIDATED_POST_NATIVE_RESULT",
            "exact_consumed_recovery": False,
        },
        "resources": {
            "native_solver_calls": calls,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight),
        "next_action": (
            "Do not retry O1C-0059, O1C-0060, or O1C-0061. Diagnose this "
            "immutable O1C-0061 failure before assigning a new attempt ID."
        ),
    }
    _make_capsule_writable(capsule)
    for stale in (
        "artifacts.sha256",
        "result.json",
        "RUN.md",
        "post_native_validation_failure.json",
    ):
        path = capsule / stale
        if path.exists():
            path.unlink()
    _scientific._atomic_json(capsule / "post_native_validation_failure.json", failure)
    if native_path.read_bytes() != native_payload:
        raise O1C61RunError("persisted native result changed during terminalization")
    _finalize_capsule(
        root=root,
        capsule=capsule,
        result=result,
        maximum_persistent_bytes=sys.maxsize,
    )
    return result


def _run_impl(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    if (root / RESULT_RELATIVE).exists():
        raise O1C61RunError("authoritative O1C-0061 output already exists")
    if tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise O1C61RunError("O1C-0061 capsule already exists; refusing another call")
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    threshold_config = _mapping(config["threshold"], "threshold")
    budgets = _mapping(config["budgets"], "budgets")
    source_paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in SOURCE_NAMES
    }
    source_commit = _git_commit(root)
    for name in COMMIT_BOUND_NAMES:
        _scientific._commit_bound_bytes(root, source_commit, source_paths[name], name)
    _scientific._commit_bound_bytes(root, source_commit, config_file, "config")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    memory_free = _scientific._memory_free_percent()
    if memory_free is not None and memory_free < int(
        cast(int, budgets["minimum_memory_pressure_free_percent"])
    ):
        raise O1C61RunError("memory-pressure preflight is below frozen gate")
    memory_enforcement = (
        "proc_pid_rusage-physical-footprint-process-group-watchdog"
        if sys.platform == "darwin"
        else "child-RLIMIT_AS-before-exec"
    )
    preflight = {
        "schema": PREFLIGHT_SCHEMA,
        "observed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "memory_pressure_free_percent": memory_free,
        "minimum_memory_pressure_free_percent": budgets[
            "minimum_memory_pressure_free_percent"
        ],
        "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "native_memory_enforcement": memory_enforcement,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "solver_calls_before_intent": 0,
        "o1c59_capsule_reads": 0,
        "o1c59_result_reads": 0,
        "o1c60_capsule_reads": 0,
        "o1c60_result_reads": 0,
    }
    consumed = _scientific._verify_consumed_o1c57(root, config, source_paths)
    threshold = prospective_threshold(
        float(np.max(consumed.frozen_joint_scores)),
        float(cast(float, threshold_config["safety_margin"])),
    )
    solver_calls = 0
    with tempfile.TemporaryDirectory(prefix="o1c61-") as temporary:
        workspace = Path(temporary)
        (
            block_reports,
            multiblock_report,
            potential,
            multiblock_cnf,
            potential_path,
        ) = _scientific._build_exact_composition(
            consumed,
            template=source_paths["template"],
            semantic_map=source_paths["semantic_map"],
            workspace=workspace,
        )
        equivalence = _scientific._verify_complete_score_equivalence(
            consumed,
            potential,
            semantic_map=source_paths["semantic_map"],
            tolerance=SCORE_TOLERANCE,
        )
        native_build = build_native_joint_score_sieve(
            source=source_paths["native_source"],
            output=workspace / "cadical-o1-joint-score-sieve-v2",
        )
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _scientific._copy_exclusive(
            multiblock_cnf, capsule / "artifacts/cnf/full256-eight-block.cnf"
        )
        _scientific._copy_exclusive(
            potential_path,
            capsule / "artifacts/potential/primary-eight-block.potential",
        )
        _scientific._atomic_json(
            capsule / "artifacts/cnf/full256-eight-block.report.json",
            multiblock_report.describe(),
        )
        _scientific._atomic_json(
            capsule / "artifacts/cnf/source-block-reports.json",
            [report.describe() for report in block_reports],
        )
        _scientific._atomic_json(
            capsule / "artifacts/potential/primary-eight-block.report.json",
            potential.describe(),
        )
        _scientific._atomic_json(
            capsule / "complete_score_equivalence.json", equivalence.report
        )
        _scientific._atomic_json(capsule / "preflight.json", preflight)
        _scientific._atomic_json(capsule / "native_build.json", native_build.describe())
        _scientific._atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _scientific._atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c61_multiblock_joint_score_sieve_run "
                f"--config {config_file}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "calls_before": solver_calls,
            "calls_authorized": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "threshold": threshold,
            "cnf_sha256": sha256_file(
                capsule / "artifacts/cnf/full256-eight-block.cnf"
            ),
            "potential_sha256": sha256_file(
                capsule / "artifacts/potential/primary-eight-block.potential"
            ),
            "native_executable_sha256": native_build.executable_sha256,
            "truth_key_reads": 0,
            "fresh_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "o1c59_retry": False,
            "o1c60_retry": False,
        }
        _scientific._atomic_json(capsule / "native_call_intent.json", intent)
        solver_calls += 1
        native, native_failure = _invoke_native_once_terminal(
            executable=native_build.executable,
            cnf=capsule / "artifacts/cnf/full256-eight-block.cnf",
            potential=capsule / "artifacts/potential/primary-eight-block.potential",
            threshold=threshold,
            conflict_limit=CONFLICT_LIMIT,
            timeout_seconds=NATIVE_TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
        )
        if native_failure is not None:
            _scientific._atomic_json(capsule / "native_failure.json", native_failure)
            failure_result: dict[str, object] = {
                "schema": RESULT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "started_at": started_at,
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "source_commit": source_commit,
                "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
                "capsule": capsule_relative.as_posix(),
                "claim_boundary": {
                    "consumed_attempt": "O1C-0057",
                    "new_attempt_not_prior_retry": True,
                    "native_solver_calls": solver_calls,
                    "validated_conflict_ledger": False,
                    "validated_native_science_result": False,
                    "retry_authorized": False,
                },
                "operational_failure": native_failure,
                "native": None,
                "metrics": {
                    "native_status": "OPERATIONAL_FAILURE",
                    "exact_consumed_recovery": False,
                },
                "resources": {
                    "native_solver_calls": solver_calls,
                    "requested_conflicts": CONFLICT_LIMIT,
                    "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "sibling_reads": 0,
                    "sibling_writes": 0,
                    "MPS_or_GPU": False,
                    "persistent_artifact_bytes": 0,
                },
                "preflight": preflight,
                "next_action": (
                    "Do not retry O1C-0059, O1C-0060, or O1C-0061; diagnose "
                    "this immutable new-attempt failure first."
                ),
            }
            _finalize_capsule(
                root=root,
                capsule=capsule,
                result=failure_result,
                maximum_persistent_bytes=int(
                    cast(int, budgets["maximum_persistent_artifact_bytes"])
                ),
            )
            return failure_result
        if native is None or solver_calls != 1:
            raise O1C61RunError("native one-shot ledger differs")
        _scientific._atomic_json(capsule / "native_result.json", native.raw)

        # The tested soft-stop ledger is the first post-native gate. Nothing
        # scientific is classified and no truth bytes are read before it passes.
        ledger = validate_native_resource_ledger(
            native,
            solver_calls=solver_calls,
            maximum_native_solver_calls=int(
                cast(int, budgets["maximum_native_solver_calls"])
            ),
        )
        persisted_ledger = {
            "schema": JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
            **ledger,
        }
        _scientific._atomic_json(capsule / "conflict_ledger.json", persisted_ledger)

        public_model_verified = False
        model_score: float | None = None
        if native.key_model is not None:
            public_model_verified = (
                chacha20_blocks(
                    native.key_model,
                    consumed.public.counter_schedule[0],
                    consumed.public.nonce,
                    BLOCK_COUNT,
                )
                == consumed.public.output_blocks
            )
            if not public_model_verified:
                raise O1C61RunError("SAT model fails independent eight-block ChaCha")
            model_assignment, _ = _scientific._global_assignment(
                equivalence, key=native.key_model, public=consumed.public
            )
            model_score = score_potential_assignment(potential, model_assignment)
            if model_score < threshold:
                raise O1C61RunError("SAT model score is below frozen threshold")
        _scientific._atomic_json(
            capsule / "public_model_diagnostic.json",
            {
                "complete": True,
                "conflict_ledger_validated": True,
                "native_status": native.status_name,
                "native_key_model_present": native.key_model is not None,
                "public_model_verified": public_model_verified,
                "model_score": model_score,
            },
        )
        _scientific._atomic_json(
            capsule / "truth_access_intent.json",
            {
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "conflict_ledger_validated": True,
                "public_model_diagnostic_complete": True,
            },
        )
        truth_key, truth_score, reveal = _scientific._verify_truth_after_native(
            consumed,
            equivalence,
            potential,
            native=native,
            public_model_diagnostic_complete=True,
        )
        _scientific._atomic_json(
            capsule / "truth_access_receipt.json",
            {
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                "truth_compiled_score": truth_score,
                "reveal_sha256": reveal["reveal_sha256"],
            },
        )
        classification, gates = classify_sieve(
            native,
            public_model_verified=public_model_verified,
            minimum_material_bound_drop=float(
                cast(float, threshold_config["minimum_material_bound_drop"])
            ),
        )
        child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
        native_peak = int(native.resources["peak_rss_bytes"])
        native_wall = int(native.resources["wall_microseconds"]) / 1_000_000.0
        result = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "started_at": started_at,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "classification": classification,
            "capsule": capsule_relative.as_posix(),
            "claim_boundary": {
                "consumed_attempt": "O1C-0057",
                "new_attempt_not_prior_retry": True,
                "o1c59_capsule_reads": 0,
                "o1c59_result_reads": 0,
                "o1c60_capsule_reads": 0,
                "o1c60_result_reads": 0,
                "fresh_targets": 0,
                "scientific_entropy_calls": 0,
                "fresh_reveal_calls": 0,
                "refits": 0,
                "new_score_arms": 0,
                "primary_only": True,
                "native_solver_calls": solver_calls,
                "validated_conflict_ledger_before_classification": True,
                "exact_key_recovery": classification
                == "EXACT_CONSUMED_FULL256_RECOVERY",
            },
            "conflict_ledger": persisted_ledger,
            "consumed_provenance": {
                "capsule": CONSUMED_CAPSULE_RELATIVE.as_posix(),
                "manifest_sha256": consumed.manifest_sha256,
                "result_sha256": sha256_file(source_paths["consumed_result"]),
                "publication_sha256": consumed.publication["publication_sha256"],
                "public_view_sha256": consumed.public.digest(),
                "reveal_sha256": reveal["reveal_sha256"],
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
            },
            "threshold": {
                "rule": threshold_config["rule"],
                "decoy_count": DECOY_COUNT,
                "decoy_max": float(np.max(consumed.frozen_joint_scores)),
                "safety_margin": SCORE_TOLERANCE,
                "value": threshold,
                "truth_compiled_score": truth_score,
            },
            "composition": {
                "cnf": multiblock_report.describe(),
                "potential": potential.describe(),
                "complete_score_equivalence": equivalence.report,
            },
            "native": native.raw,
            "native_build": native_build.describe(),
            "metrics": {
                "native_status": native.status_name,
                "exact_consumed_recovery": classification
                == "EXACT_CONSUMED_FULL256_RECOVERY",
                "model_score": model_score,
                "threshold_prunes": native.threshold_prunes,
                "conflict_ledger_valid": True,
                **gates,
            },
            "resources": {
                "elapsed_seconds": time.perf_counter() - started,
                "parent_cpu_seconds": time.process_time() - cpu_started,
                "child_cpu_seconds": (
                    child_end.ru_utime
                    + child_end.ru_stime
                    - child_started.ru_utime
                    - child_started.ru_stime
                ),
                "native_wall_seconds": native_wall,
                "native_cpu_seconds": int(native.resources["cpu_microseconds"])
                / 1_000_000.0,
                "native_peak_rss_bytes": native_peak,
                "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
                "native_memory_enforcement": memory_enforcement,
                "native_solver_calls": solver_calls,
                "requested_conflicts": ledger["requested_conflicts"],
                "unused_requested_conflicts": ledger["unused_requested_conflicts"],
                "cumulative_conflicts": ledger["conflicts"],
                "conflicts_before_solve": ledger["conflicts_before_solve"],
                "solve_conflicts": ledger["solve_conflicts"],
                "conflict_limit_overshoot": ledger["conflict_limit_overshoot"],
                "billed_conflicts": ledger["billed_conflicts"],
                "maximum_billed_conflicts": JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
                "fresh_targets": 0,
                "scientific_entropy_calls": 0,
                "fresh_reveal_calls": 0,
                "refits": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "MPS_or_GPU": False,
                "persistent_artifact_bytes": 0,
            },
            "preflight": preflight,
            "source_sha256": {
                name: sha256_file(path) for name, path in source_paths.items()
            },
            "next_action": config["next_action"],
        }
        _scientific._atomic_json(
            capsule / "truth_diagnostic.json",
            {
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                "truth_compiled_score": truth_score,
                "read_after_validated_conflict_ledger": True,
                "read_after_native": True,
                "public_model_diagnostic_complete_before_read": True,
            },
        )
        _finalize_capsule(
            root=root,
            capsule=capsule,
            result=result,
            maximum_persistent_bytes=int(
                cast(int, budgets["maximum_persistent_artifact_bytes"])
            ),
        )
        return result


def run(config_path: str | Path) -> dict[str, object]:
    try:
        return _run_impl(config_path)
    except Exception as error:
        root = lab_root().resolve(strict=True)
        if (root / RESULT_RELATIVE).exists():
            raise
        capsules = tuple(
            capsule
            for capsule in root.glob(f"runs/*_{CAPSULE_SUFFIX}")
            if (capsule / "native_call_intent.json").is_file()
            and (capsule / "native_result.json").is_file()
        )
        if len(capsules) != 1:
            raise
        return _terminalize_post_native_failure(
            root=root, capsule=capsules[0], error=error
        )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    result = run(arguments.config)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "CONFLICT_LIMIT",
    "MEMORY_LIMIT_BYTES",
    "NATIVE_TIMEOUT_SECONDS",
    "O1C61RunError",
    "RESULT_RELATIVE",
    "classify_sieve",
    "load_config",
    "main",
    "prospective_threshold",
    "run",
    "validate_native_resource_ledger",
]
