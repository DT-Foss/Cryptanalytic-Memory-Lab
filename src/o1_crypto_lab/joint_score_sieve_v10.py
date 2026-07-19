"""Strict forced-initial-phase reader adapter for native sieve v7.

Native v7 changes only the result identity and CaDiCaL's initial phase.  This
adapter independently reconstructs the frozen reader specification, validates
the exact top-level reader object, projects the remaining payload to native-v6
for v9/v8 validation, and preserves v9's observed-work conflict ledger and
successful-process failure evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v9 as _v9
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v10-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v7"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
FORCED_INITIAL_PHASE_READER_SCHEMA = "o1-256-cadical-forced-initial-phase-reader-v1"
FORCED_INITIAL_PHASE_READER_OPERATOR = "forced-initial-phase"
FORCED_INITIAL_PHASE_COMPLEMENT_PAIR_ID = "forced-initial-phase-v1"
FORCED_INITIAL_PHASE_READER_SPEC_SHA256 = (
    "a68b3c3b1721b756314dac11ce725adf0709e9f358125cb1f8d388737d1ddddc"
)
_FORCED_INITIAL_PHASE_READER_SPEC_BYTES = (
    b"forced-initial-phase-v1\n"
    b"cadical_configuration=plain\n"
    b"phase_before_override=1\n"
    b"seed=0\n"
    b"quiet=1\n"
    b"factor=0\n"
    b"lucky=0\n"
    b"walk=0\n"
    b"rephase=0\n"
    b"forcephase=1\n"
    b"phase=0\n"
)
_READER_FIELD_ORDER = (
    "schema",
    "operator",
    "complement_pair_id",
    "cadical_configuration",
    "phase_before_override",
    "phase",
    "forcephase",
    "rephase",
    "lucky",
    "walk",
    "seed",
    "quiet",
    "factor",
    "reader_spec_sha256",
)
_READER_FIELDS = frozenset(_READER_FIELD_ORDER)

# The observed-work ledger is inherited without a new interpretation.
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = _v9.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = (
    _v9.JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = _v9.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v9.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v9.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)

APPLE_VIEW_0009_GROUPING_SHA256 = _v9.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v9.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v9.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v9.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v9.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v9.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v9.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v9.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v9.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v9.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v9.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v9.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v9.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v9.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v9.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v9.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v9.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v9.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v9.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v9.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v9.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v9.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v9.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v9.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v9.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v9.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v9.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v9.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v9.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v9.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = _v9.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
JointScoreCompatibilityGroup = _v9.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v9.JointScoreSieveExecutionError
JointScoreSieveResult = _v9.JointScoreSieveResult
JointScoreSieveV7Result = _v9.JointScoreSieveV7Result
JointScoreSieveV8Result = _v9.JointScoreSieveV8Result
JointScoreSieveV9Result = _v9.JointScoreSieveV9Result
build_compatibility_grouping = _v9.build_compatibility_grouping
build_native_joint_score_sieve = _v9.build_native_joint_score_sieve
derive_vault_soft_conflict_ledger = _v9.derive_vault_soft_conflict_ledger
derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
grouped_joint_score_cache = _v9.grouped_joint_score_cache
grouped_upper_bound_prunes = _v9.grouped_upper_bound_prunes
joint_score_complete = _v9.joint_score_complete
joint_score_upper_bound = _v9.joint_score_upper_bound
validate_incremental_conflict_ledger = _v9.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v9.validate_joint_score_sieve_grouping
validate_vault_soft_conflict_ledger = _v9.validate_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger
write_joint_score_sieve_grouping = _v9.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v9.write_joint_score_sieve_potential

_TOP_LEVEL_FIELDS = _v9._TOP_LEVEL_FIELDS | {"reader"}


@dataclass(frozen=True)
class JointScoreSieveV10Result(_v9.JointScoreSieveV9Result):
    """A v9-validated result plus the normalized forced-phase reader."""

    reader: Mapping[str, object]


def forced_initial_phase_reader_spec_bytes() -> bytes:
    """Return the independently reconstructed reader-spec preimage."""

    return _FORCED_INITIAL_PHASE_READER_SPEC_BYTES


def _expected_reader() -> dict[str, object]:
    digest = hashlib.sha256(forced_initial_phase_reader_spec_bytes()).hexdigest()
    if digest != FORCED_INITIAL_PHASE_READER_SPEC_SHA256:
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 frozen reader preimage differs"
        )
    return {
        "schema": FORCED_INITIAL_PHASE_READER_SCHEMA,
        "operator": FORCED_INITIAL_PHASE_READER_OPERATOR,
        "complement_pair_id": FORCED_INITIAL_PHASE_COMPLEMENT_PAIR_ID,
        "cadical_configuration": "plain",
        "phase_before_override": 1,
        "phase": 0,
        "forcephase": True,
        "rephase": 0,
        "lucky": False,
        "walk": False,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "reader_spec_sha256": digest,
    }


def validate_forced_initial_phase_reader(raw: object) -> dict[str, object]:
    """Validate every reader field with exact JSON scalar types and values."""

    reader = _v9._v8._v1._mapping(raw, "reader")
    if set(reader) != _READER_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v10 reader fields differ")
    expected = _expected_reader()
    integer_fields = (
        "phase_before_override",
        "phase",
        "rephase",
        "seed",
        "quiet",
        "factor",
    )
    boolean_fields = ("forcephase", "lucky", "walk")
    if (
        any(
            isinstance(reader[name], bool) or not isinstance(reader[name], int)
            for name in integer_fields
        )
        or any(not isinstance(reader[name], bool) for name in boolean_fields)
        or any(reader[name] != expected[name] for name in _READER_FIELD_ORDER)
    ):
        raise O1RelationalSearchError("joint-score-sieve-v10 reader contract differs")
    return {name: reader[name] for name in _READER_FIELD_ORDER}


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v7 lifecycle provenance through the v9 parent rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 lifecycle contract differs"
        )
    parent_payload = dict(payload)
    parent_payload["implementation_parent_schema"] = (
        _v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    normalized = _v9.validate_native_lifecycle(parent_payload)
    normalized["implementation_parent_schema"] = (
        JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    return normalized


def _promote_result(
    result: _v9.JointScoreSieveV9Result,
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
) -> JointScoreSieveV10Result:
    return JointScoreSieveV10Result(
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
) -> JointScoreSieveV10Result:
    """Validate native-v7 reader identity before inherited payload parsing."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v10 result fields differ")
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
        raise O1RelationalSearchError("joint-score-sieve-v10 result contract differs")
    reader = validate_forced_initial_phase_reader(payload["reader"])
    parent_payload = dict(payload)
    parent_payload.pop("reader")
    parent_payload["schema"] = _v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    try:
        parent = _v9._parse_native_payload(
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
            "joint-score-sieve-v10 native payload validation failed"
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
) -> JointScoreSieveV10Result:
    """Run hard-coded-phase native v7 through the strict v10 boundary."""

    requested = _v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v10 native vault caps differ")
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
            "joint-score-sieve-v10 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v9._v8._v1._read_input(
        executable, "executable"
    )
    cnf, cnf_bytes, cnf_sha = _v9._v8._v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v9._v8._v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = _v9._v8._v1._read_input(
        grouping_path, "grouping"
    )
    vault_file, vault_bytes = _v9._v8._read_bounded_vault_input(
        vault_path, caps=vault_caps
    )
    field = _v9._v8._v1._potential(potential_bytes)
    grouping = _v9._v8._v7.validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 grouping potential identity differs"
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
            "joint-score-sieve-v10 input vault differs"
        ) from exc
    try:
        _v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 input vault certification differs"
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
    execution: _v9._v8._v7._NativeExecution | None
    try:
        execution = _v9._v8._v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        execution = None

    try:
        _v9._v8._v1._verify_stable_input(
            executable, executable_file, executable_bytes, field="executable"
        )
        _v9._v8._v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
        _v9._v8._v1._verify_stable_input(
            potential_path, potential_file, potential_bytes, field="potential"
        )
        _v9._v8._v1._verify_stable_input(
            grouping_path, grouping_file, grouping_bytes, field="grouping"
        )
        _v9._v8._verify_stable_vault_input(
            vault_path, vault_file, vault_bytes, caps=vault_caps
        )
    except Exception as exc:
        if execution is not None:
            _v9._attach_native_process_evidence(
                exc,
                command=command,
                completed=execution.completed,
                memory_samples=execution.memory_samples,
            )
        raise
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v10 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v10 execution failed: {detail}"
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
        _v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v10 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v9._attach_native_process_evidence(
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
) -> JointScoreSieveV10Result:
    """Run native v7 and retain v9's bounded failure/process evidence."""

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
        telemetry = _v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v10"):
            message = f"joint-score-sieve-v10 adapter failed: {message}"
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
    "FORCED_INITIAL_PHASE_COMPLEMENT_PAIR_ID",
    "FORCED_INITIAL_PHASE_READER_OPERATOR",
    "FORCED_INITIAL_PHASE_READER_SCHEMA",
    "FORCED_INITIAL_PHASE_READER_SPEC_SHA256",
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
    "JointScoreSieveV7Result",
    "JointScoreSieveV8Result",
    "JointScoreSieveV9Result",
    "O1C66_VAULT_CAPS",
    "O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA",
    "ThresholdNoGoodClause",
    "ThresholdNoGoodVault",
    "VaultCaps",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "derive_vault_soft_conflict_ledger",
    "forced_initial_phase_reader_spec_bytes",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_forced_initial_phase_reader",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "validate_vault_soft_conflict_ledger",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
