"""O1C-0067 adapter for honest vault soft-horizon work accounting.

The native-v6 payload and O1C-0066 vault contract remain byte-for-byte
unchanged.  Adapter v9 gives that frozen native process a new, explicitly
versioned conflict ledger: the requested conflict count is a soft stopping
horizon, while billed work is the exact observed solve-conflict delta.  No
empirical overshoot ceiling is asserted.

Every error after a native process has returned retains its command, return
code, stdout, stderr, and bounded memory series, including stable-input,
JSON, payload-validation, and ledger-derivation failures.
"""

from __future__ import annotations

import json
import math
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v8 as _v8
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v9-o1c67-adapter-v1"
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = (
    "o1-256-joint-score-sieve-v9-o1c67-vault-soft-conflict-ledger-v1"
)
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = (
    JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)

# The native result is still v6.  Renaming this frozen payload would falsely
# claim a native-code change; v9 is identified by the adapter and ledger
# schemas above.
JOINT_SCORE_SIEVE_RESULT_SCHEMA = _v8.JOINT_SCORE_SIEVE_RESULT_SCHEMA
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v8.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v8.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)

APPLE_VIEW_0009_GROUPING_SHA256 = _v8.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v8.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v8.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v8.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v8.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v8.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v8.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v8.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v8.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v8.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v8.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v8.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v8.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v8.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v8.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v8.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v8.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v8.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v8.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v8.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v8.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v8.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v8.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v8.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v8.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v8.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v8.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v8.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v8.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = _v8.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
JointScoreCompatibilityGroup = _v8.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v8.JointScoreSieveExecutionError
JointScoreSieveResult = _v8.JointScoreSieveResult
JointScoreSieveV7Result = _v8.JointScoreSieveV7Result
JointScoreSieveV8Result = _v8.JointScoreSieveV8Result
build_compatibility_grouping = _v8.build_compatibility_grouping
build_native_joint_score_sieve = _v8.build_native_joint_score_sieve
grouped_joint_score_cache = _v8.grouped_joint_score_cache
grouped_upper_bound_prunes = _v8.grouped_upper_bound_prunes
joint_score_complete = _v8.joint_score_complete
joint_score_upper_bound = _v8.joint_score_upper_bound
validate_joint_score_sieve_grouping = _v8.validate_joint_score_sieve_grouping
validate_native_lifecycle = _v8.validate_native_lifecycle
write_joint_score_sieve_grouping = _v8.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v8.write_joint_score_sieve_potential

_TOP_LEVEL_FIELDS = _v8._TOP_LEVEL_FIELDS
_VAULT_FIELDS = _v8._VAULT_FIELDS
_VAULT_NATIVE_STATS_FIELDS = {
    "conflicts",
    "conflicts_before_solve",
    "solve_conflicts",
    "decisions",
    "propagations",
}
_VAULT_VALIDATED_STATS_FIELDS = {
    *_VAULT_NATIVE_STATS_FIELDS,
    "requested_conflicts",
    "unused_requested_conflicts",
    "conflict_limit_overshoot",
    "billed_conflicts",
}


@dataclass(frozen=True)
class JointScoreSieveV9Result(_v8.JointScoreSieveV8Result):
    """O1C-0067 result with v9's observed-work conflict ledger."""


def _requested_conflicts(value: object) -> int:
    try:
        return _v8._v7._requested_conflicts(value)
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 requested soft conflict horizon differs"
        ) from exc


def validate_vault_soft_conflict_ledger(
    stats: Mapping[str, object],
) -> dict[str, int]:
    """Validate O1C-0067 exact work under an unbounded soft overshoot."""

    if not isinstance(stats, Mapping) or set(stats) != _VAULT_VALIDATED_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 vault soft conflict ledger fields differ"
        )
    normalized: dict[str, int] = {}
    for name in _VAULT_VALIDATED_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-v9 vault soft conflict ledger {name} differs"
            )
        normalized[name] = value

    requested = _requested_conflicts(normalized["requested_conflicts"])
    cumulative = normalized["conflicts"]
    before = normalized["conflicts_before_solve"]
    solve = normalized["solve_conflicts"]
    unused = normalized["unused_requested_conflicts"]
    overshoot = normalized["conflict_limit_overshoot"]
    billed = normalized["billed_conflicts"]
    if (
        before > cumulative
        or solve != cumulative - before
        or unused != max(requested - solve, 0)
        or overshoot != max(solve - requested, 0)
        or solve != requested - unused + overshoot
        or (unused > 0 and overshoot > 0)
        or billed != solve
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 vault soft conflict ledger differs"
        )
    return normalized


def derive_vault_soft_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Derive O1C-0067's versioned vault ledger from raw native counters."""

    requested = _requested_conflicts(requested_conflicts)
    if not isinstance(stats, Mapping) or set(stats) != _VAULT_NATIVE_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 vault native conflict fields differ"
        )
    native: dict[str, int] = {}
    for name in _VAULT_NATIVE_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-v9 vault native conflict {name} differs"
            )
        native[name] = value
    solve = native["solve_conflicts"]
    return validate_vault_soft_conflict_ledger(
        {
            **native,
            "requested_conflicts": requested,
            "unused_requested_conflicts": max(requested - solve, 0),
            "conflict_limit_overshoot": max(solve - requested, 0),
            "billed_conflicts": solve,
        }
    )


derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger


def validate_incremental_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Derive the O1C-0067 vault ledger through the compatibility API."""

    return derive_vault_soft_conflict_ledger(
        stats, requested_conflicts=requested_conflicts
    )


def _promote_result(result: _v8.JointScoreSieveV8Result) -> JointScoreSieveV9Result:
    return JointScoreSieveV9Result(
        status=result.status,
        conflict_limit=result.conflict_limit,
        threshold=result.threshold,
        key_model=result.key_model,
        stats=result.stats,
        sieve=result.sieve,
        resources=result.resources,
        raw=result.raw,
        adapter_memory=result.adapter_memory,
        input_vault=result.input_vault,
        eligible_emitted_clauses=result.eligible_emitted_clauses,
        next_vault=result.next_vault,
        vault_telemetry=result.vault_telemetry,
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
) -> JointScoreSieveV9Result:
    """Validate frozen native-v6 bytes through the O1C-0067 v9 boundary."""

    try:
        result = _v8._parse_native_payload(
            payload,
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
            "joint-score-sieve-v9 native payload validation failed"
        ) from exc
    return _promote_result(result)


def _attach_native_process_evidence(
    exc: BaseException,
    *,
    command: list[str],
    completed: subprocess.CompletedProcess[str],
    memory_samples: tuple[dict[str, int | float], ...],
) -> None:
    """Attach O1C-0067 process evidence without replacing existing details."""

    evidence: tuple[tuple[str, object], ...] = (
        ("cmd", list(command)),
        ("returncode", completed.returncode),
        ("stdout", completed.stdout),
        ("stderr", completed.stderr),
        ("memory_samples", memory_samples),
    )
    for name, value in evidence:
        if not hasattr(exc, name):
            setattr(exc, name, value)


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
) -> JointScoreSieveV9Result:
    """Run frozen native-v6 through the O1C-0067 v9 adapter contract."""

    requested = _requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v9 native vault caps differ")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
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
            "joint-score-sieve-v9 threshold, seed, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v8._v1._read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = _v8._v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v8._v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = _v8._v1._read_input(
        grouping_path, "grouping"
    )
    vault_file, vault_bytes = _v8._read_bounded_vault_input(vault_path, caps=vault_caps)
    field = _v8._v1._potential(potential_bytes)
    grouping = _v8._v7.validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 grouping potential identity differs"
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
            "joint-score-sieve-v9 input vault differs"
        ) from exc
    try:
        _v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 input vault certification differs"
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
        str(seed),
    ]
    execution_error: Exception | None = None
    execution: _v8._v7._NativeExecution | None
    try:
        execution = _v8._v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        execution = None

    try:
        _v8._v1._verify_stable_input(
            executable, executable_file, executable_bytes, field="executable"
        )
        _v8._v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
        _v8._v1._verify_stable_input(
            potential_path, potential_file, potential_bytes, field="potential"
        )
        _v8._v1._verify_stable_input(
            grouping_path, grouping_file, grouping_bytes, field="grouping"
        )
        _v8._verify_stable_vault_input(
            vault_path, vault_file, vault_bytes, caps=vault_caps
        )
    except Exception as exc:
        if execution is not None:
            _attach_native_process_evidence(
                exc,
                command=command,
                completed=execution.completed,
                memory_samples=execution.memory_samples,
            )
        raise
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v9 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v9 execution failed: {detail}"
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
            seed=seed,
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
        _attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v9 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _attach_native_process_evidence(
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
) -> JointScoreSieveV9Result:
    """Run O1C-0067 adapter v9 and retain all bounded failure evidence."""

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
        telemetry = _v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v9"):
            message = f"joint-score-sieve-v9 adapter failed: {message}"
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
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "validate_vault_soft_conflict_ledger",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
