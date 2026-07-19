"""Strict sealed vault-phase-field adapter for native joint sieve v9.

The adapter independently derives the phase field from the exact input vault,
validates every native reader field and JSON scalar type before inherited
normalization, and then delegates the unchanged payload contract to v11/v9.
The observed-work conflict ledger and successful-process failure evidence are
preserved exactly.
"""

from __future__ import annotations

import json
import math
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v11 as _v11
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)
from .vault_phase_field_v1 import (
    PRODUCTION_UNPHASED_VARIABLES,
    PRODUCTION_VAULT_PHASE_READER,
    VAULT_PHASE_FIELD_OPERATOR,
    VAULT_PHASE_FIELD_SCHEMA,
    VAULT_PHASE_READER_SPEC_SHA256,
    VaultPhaseFieldError,
    validate_production_vault_phase_field,
    vault_phase_field_reader_spec_bytes,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v12-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v9"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
VAULT_PHASE_FIELD_READER_SCHEMA = "o1-256-cadical-vault-phase-field-reader-v1"
VAULT_PHASE_FIELD_READER_OPERATOR = VAULT_PHASE_FIELD_OPERATOR
VAULT_PHASE_FIELD_READER_SPEC_SHA256 = VAULT_PHASE_READER_SPEC_SHA256

_READER_FIELD_ORDER = tuple(PRODUCTION_VAULT_PHASE_READER)
_READER_FIELDS = frozenset(_READER_FIELD_ORDER)
_READER_INTEGER_FIELDS = (
    "phase_before_override",
    "phase",
    "rephase",
    "seed",
    "quiet",
    "factor",
    "source_clause_count",
    "base_prefix_clause_count",
    "suffix_start_clause_index",
    "suffix_stop_clause_index_exclusive",
    "suffix_clause_count",
    "suffix_literal_count",
    "key_variable_count",
    "field_bytes",
    "positive_count",
    "negative_count",
    "unphased_count",
    "applied_phase_calls",
    "fallback_phase",
)
_READER_BOOLEAN_FIELDS = ("forcephase", "lucky", "walk")
_TOP_LEVEL_FIELDS = _v11._v9._TOP_LEVEL_FIELDS | {"reader"}

# Public inherited mechanism surface.
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = _v11.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = (
    _v11.JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = _v11.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v11.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v11.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)
APPLE_VIEW_0009_GROUPING_SHA256 = _v11.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v11.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v11.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v11.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v11.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v11.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v11.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v11.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v11.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v11.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v11.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v11.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v11.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v11.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v11.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v11.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v11.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v11.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v11.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v11.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v11.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v11.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v11.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v11.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v11.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v11.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v11.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v11.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v11.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v11.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = _v11.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
JointScoreCompatibilityGroup = _v11.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v11.JointScoreSieveExecutionError
JointScoreSieveResult = _v11.JointScoreSieveResult
JointScoreSieveV7Result = _v11.JointScoreSieveV7Result
JointScoreSieveV8Result = _v11.JointScoreSieveV8Result
JointScoreSieveV9Result = _v11.JointScoreSieveV9Result
JointScoreSieveV10Result = _v11.JointScoreSieveV10Result
JointScoreSieveV11Result = _v11.JointScoreSieveV11Result
build_compatibility_grouping = _v11.build_compatibility_grouping
build_native_joint_score_sieve = _v11.build_native_joint_score_sieve
derive_vault_soft_conflict_ledger = _v11.derive_vault_soft_conflict_ledger
derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
grouped_joint_score_cache = _v11.grouped_joint_score_cache
grouped_upper_bound_prunes = _v11.grouped_upper_bound_prunes
joint_score_complete = _v11.joint_score_complete
joint_score_upper_bound = _v11.joint_score_upper_bound
validate_incremental_conflict_ledger = _v11.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v11.validate_joint_score_sieve_grouping
validate_vault_soft_conflict_ledger = _v11.validate_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger
write_joint_score_sieve_grouping = _v11.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v11.write_joint_score_sieve_potential


@dataclass(frozen=True)
class JointScoreSieveV12Result(_v11.JointScoreSieveV11Result):
    """A fully inherited result plus the normalized sealed phase-field reader."""

    reader: Mapping[str, object]


def _expected_reader() -> dict[str, object]:
    vault_phase_field_reader_spec_bytes()
    expected = dict(PRODUCTION_VAULT_PHASE_READER)
    expected["unphased_variables"] = list(PRODUCTION_UNPHASED_VARIABLES)
    return expected


def validate_vault_phase_field_reader(raw: object) -> dict[str, object]:
    """Validate every native-v9 reader field before parent normalization."""

    reader = _v11._v9._v8._v1._mapping(raw, "reader")
    if set(reader) != _READER_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v12 reader fields differ")
    if any(
        isinstance(reader[name], bool) or not isinstance(reader[name], int)
        for name in _READER_INTEGER_FIELDS
    ) or any(not isinstance(reader[name], bool) for name in _READER_BOOLEAN_FIELDS):
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 reader scalar types differ"
        )
    unphased = reader["unphased_variables"]
    if not isinstance(unphased, list) or any(
        isinstance(value, bool) or not isinstance(value, int) for value in unphased
    ):
        raise O1RelationalSearchError("joint-score-sieve-v12 reader array types differ")
    expected = _expected_reader()
    if any(reader[name] != expected[name] for name in _READER_FIELD_ORDER):
        raise O1RelationalSearchError("joint-score-sieve-v12 reader contract differs")
    return {name: reader[name] for name in _READER_FIELD_ORDER}


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v9 lifecycle provenance through the unchanged v11 rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 lifecycle contract differs"
        )
    return _v11.validate_native_lifecycle(payload)


def _promote_result(
    result: _v11.JointScoreSieveV11Result,
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
) -> JointScoreSieveV12Result:
    return JointScoreSieveV12Result(
        status=result.status,
        conflict_limit=result.conflict_limit,
        threshold=result.threshold,
        key_model=result.key_model,
        stats=result.stats,
        sieve=result.sieve,
        resources=result.resources,
        raw=dict(raw),
        adapter_memory=result.adapter_memory,
        input_vault=result.input_vault,
        eligible_emitted_clauses=result.eligible_emitted_clauses,
        next_vault=result.next_vault,
        vault_telemetry=result.vault_telemetry,
        reader=dict(reader),
    )


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    vault_caps: VaultCaps,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    grouping_sha256: str,
    cnf_sha256: str,
    potential_sha256: str,
    threshold: float,
    requested_conflicts: int,
    seed: int,
    memory_limit_bytes: int | None,
    memory_samples: tuple[dict[str, int | float], ...],
) -> JointScoreSieveV12Result:
    """Validate native-v9 reader identity before any inherited normalization."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v12 result fields differ")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["implementation_parent_schema"]
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed != 0
        or isinstance(payload["seed"], bool)
        or not isinstance(payload["seed"], int)
        or payload["seed"] != 0
    ):
        raise O1RelationalSearchError("joint-score-sieve-v12 result contract differs")
    reader = validate_vault_phase_field_reader(payload["reader"])

    parent_payload = dict(payload)
    parent_payload["schema"] = _v11.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v11.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    parent_payload["reader"] = _v11._expected_reader()
    try:
        parent = _v11._parse_native_payload(
            parent_payload,
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha256,
            cnf_sha256=cnf_sha256,
            potential_sha256=potential_sha256,
            threshold=threshold,
            requested_conflicts=requested_conflicts,
            seed=seed,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=memory_samples,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 native payload validation failed"
        ) from exc
    return _promote_result(parent, raw=payload, reader=reader)


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV12Result:
    """Run sealed native v9 through the strict v12 process boundary."""

    requested = _v11._v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v12 native vault caps differ")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed != 0
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or (
            memory_limit_bytes is not None
            and (
                isinstance(memory_limit_bytes, bool)
                or not isinstance(memory_limit_bytes, int)
                or memory_limit_bytes <= 0
            )
        )
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v11._v9._v8._v1._read_input(
        executable, "executable"
    )
    cnf, cnf_bytes, cnf_sha = _v11._v9._v8._v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v11._v9._v8._v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = _v11._v9._v8._v1._read_input(
        grouping_path, "grouping"
    )
    vault_file, vault_bytes = _v11._v9._v8._read_bounded_vault_input(
        vault_path, caps=vault_caps
    )
    try:
        validate_production_vault_phase_field(vault_bytes)
    except VaultPhaseFieldError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 sealed vault phase field differs"
        ) from exc
    field = _v11._v9._v8._v1._potential(potential_bytes)
    grouping = _v11._v9._v8._v7.validate_joint_score_sieve_grouping(
        field, grouping_bytes
    )
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 grouping potential identity differs"
        )
    try:
        input_vault = parse_threshold_no_good_vault(
            vault_bytes,
            observed_variables=field.observed_variables,
            caps=vault_caps,
        )
        expected_identity = vault_identity_from_sources(
            cnf_sha256=cnf_sha,
            potential_sha256=potential_sha,
            grouping_sha256=grouping_sha,
            observed_variables=field.observed_variables,
            bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
            threshold=requested_threshold,
        )
        validate_threshold_no_good_vault_identity(
            input_vault, expected=expected_identity
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 input vault differs"
        ) from exc
    try:
        _v11._v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 input vault certification differs"
        ) from exc

    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential_file),
        "--grouping",
        str(grouping_file),
        "--vault-in",
        str(vault_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: _v11._v9._v8._v7._NativeExecution | None
    try:
        execution = _v11._v9._v8._v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        execution = None

    try:
        _v11._v9._v8._v1._verify_stable_input(
            executable, executable_file, executable_bytes, field="executable"
        )
        _v11._v9._v8._v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
        _v11._v9._v8._v1._verify_stable_input(
            potential_path, potential_file, potential_bytes, field="potential"
        )
        _v11._v9._v8._v1._verify_stable_input(
            grouping_path, grouping_file, grouping_bytes, field="grouping"
        )
        _v11._v9._v8._verify_stable_vault_input(
            vault_path, vault_file, vault_bytes, caps=vault_caps
        )
    except Exception as exc:
        if execution is not None:
            _v11._v9._attach_native_process_evidence(
                exc,
                command=command,
                completed=execution.completed,
                memory_samples=execution.memory_samples,
            )
        raise
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v12 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v12 execution failed: {detail}"
        ) from failure

    try:
        payload = json.loads(completed.stdout)
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha,
            cnf_sha256=cnf_sha,
            potential_sha256=potential_sha,
            threshold=requested_threshold,
            requested_conflicts=requested,
            seed=0,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=execution.memory_samples,
        )
        return replace(
            result,
            stats=derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v12 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV12Result:
    """Run native v9 while retaining v11's bounded failure evidence."""

    started = time.perf_counter()
    try:
        return _run_joint_score_sieve_native_contract(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
            vault_path=vault_path,
            vault_caps=vault_caps,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v12"):
            message = f"joint-score-sieve-v12 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [
    "APPLE_VIEW_0009_GROUPING_SHA256",
    "APPLE_VIEW_0009_POTENTIAL_SHA256",
    "COMPATIBILITY_GROUPING_BOUND_RULE",
    "COMPATIBILITY_GROUPING_MAGIC",
    "COMPATIBILITY_GROUPING_MEMORY_RULE",
    "COMPATIBILITY_GROUPING_RULE",
    "COMPATIBILITY_GROUPING_SCHEMA",
    "EmittedThresholdNoGoodClause",
    "IncrementalJointScoreGroupMaxima",
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA",
    "JOINT_SCORE_SIEVE_GROUPING_MAGIC",
    "JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE",
    "JOINT_SCORE_SIEVE_GROUPING_RULE",
    "JOINT_SCORE_SIEVE_GROUPING_SCHEMA",
    "JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA",
    "JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_STATE_SCHEMA",
    "JOINT_SCORE_SIEVE_TEARDOWN_RULE",
    "JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION",
    "JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE",
    "JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION",
    "JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreSieveExecutionError",
    "JointScoreSieveResult",
    "JointScoreSieveV10Result",
    "JointScoreSieveV11Result",
    "JointScoreSieveV12Result",
    "JointScoreSieveV7Result",
    "JointScoreSieveV8Result",
    "JointScoreSieveV9Result",
    "O1C66_VAULT_CAPS",
    "O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA",
    "PRODUCTION_VAULT_PHASE_READER",
    "ThresholdNoGoodClause",
    "ThresholdNoGoodVault",
    "VAULT_PHASE_FIELD_READER_OPERATOR",
    "VAULT_PHASE_FIELD_READER_SCHEMA",
    "VAULT_PHASE_FIELD_READER_SPEC_SHA256",
    "VAULT_PHASE_FIELD_SCHEMA",
    "VaultCaps",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "derive_vault_soft_conflict_ledger",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "validate_vault_phase_field_reader",
    "validate_vault_soft_conflict_ledger",
    "vault_phase_field_reader_spec_bytes",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
