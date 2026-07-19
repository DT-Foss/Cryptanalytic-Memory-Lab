"""Exact joint-potential threshold pruning without external SAT decisions."""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import signal
import struct
import subprocess
import sys
import time
from ctypes import CDLL, POINTER, Structure, byref, c_int, c_uint8, c_uint64
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable, Mapping, cast

from .criticality_potential import (
    CriticalityPotentialError,
    CriticalityPotentialField,
    score_potential_assignment,
)
from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    build_native_guided_search,
)


JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v1"
JOINT_SCORE_SIEVE_DECISION_RULE = "solver_owned_no_external_decisions"
JOINT_SCORE_SIEVE_BOUND_RULE = (
    "nextafter-positive-infinity-after-each-factor-maximum-addition"
)
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = "exact-binary-superaccumulator-comparison"
JOINT_SCORE_SIEVE_STATE_ENCODING = (
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-cache-factor-order-f64le-max"
)
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = (
    "solver-functional-persistent-logical-state;excludes-immutable-potential-"
    "index,telemetry,allocator-capacity,transient-callback-scratch"
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = 32 * 1024 * 1024
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = 0.01

_TOP_LEVEL_FIELDS = {
    "schema",
    "cadical_version",
    "variables",
    "conflict_limit",
    "seed",
    "threshold",
    "status",
    "key_model_hex",
    "cnf_sha256",
    "potential_sha256",
    "stats",
    "sieve",
    "resources",
}
_STATS_FIELDS = {"conflicts", "decisions", "propagations"}
_RESOURCE_FIELDS = {"wall_microseconds", "cpu_microseconds", "peak_rss_bytes"}
_SIEVE_FIELDS = {
    "factor_count",
    "observed_variables",
    "observed_variables_sha256",
    "source_sha256",
    "offset",
    "threshold",
    "root_upper_bound",
    "bound_rule",
    "complete_threshold_rule",
    "decision_rule",
    "external_implications",
    "cb_decide_calls",
    "cb_decide_nonzero",
    "cb_propagate_calls",
    "assignment_callbacks",
    "assignment_literals",
    "new_decision_levels",
    "backtracks",
    "backtracked_assignments",
    "maximum_assigned_variables",
    "maximum_decision_level",
    "bound_checks",
    "bound_additions",
    "incident_edges",
    "incremental_factor_recomputations",
    "maximum_incremental_factors_recomputed",
    "factor_maximum_evaluations",
    "factor_row_evaluations",
    "minimum_upper_bound",
    "maximum_upper_bound",
    "threshold_prunes",
    "trail_threshold_prunes",
    "model_threshold_prunes",
    "external_clauses_queued",
    "external_clauses_emitted",
    "external_clause_literals",
    "minimum_clause_length",
    "maximum_clause_length",
    "maximum_pending_clause_length",
    "pending_clause_count",
    "cb_has_external_clause_calls",
    "model_checks",
    "complete_model_score_checks",
    "models_below_threshold",
    "models_at_or_above_threshold",
    "minimum_complete_score",
    "maximum_complete_score",
    "trace_sha256",
    "state",
}
_SIEVE_INTEGER_FIELDS = {
    "factor_count",
    "observed_variables",
    "external_implications",
    "cb_decide_calls",
    "cb_decide_nonzero",
    "cb_propagate_calls",
    "assignment_callbacks",
    "assignment_literals",
    "new_decision_levels",
    "backtracks",
    "backtracked_assignments",
    "maximum_assigned_variables",
    "maximum_decision_level",
    "bound_checks",
    "bound_additions",
    "incident_edges",
    "incremental_factor_recomputations",
    "maximum_incremental_factors_recomputed",
    "factor_maximum_evaluations",
    "factor_row_evaluations",
    "threshold_prunes",
    "trail_threshold_prunes",
    "model_threshold_prunes",
    "external_clauses_queued",
    "external_clauses_emitted",
    "external_clause_literals",
    "minimum_clause_length",
    "maximum_clause_length",
    "maximum_pending_clause_length",
    "pending_clause_count",
    "cb_has_external_clause_calls",
    "model_checks",
    "complete_model_score_checks",
    "models_below_threshold",
    "models_at_or_above_threshold",
}
_STATE_FIELDS = {
    "encoding",
    "persistent_state_scope",
    "assignment_bytes",
    "bounded_trail_bytes",
    "bounded_pending_bytes",
    "bounded_state_bytes",
    "derived_factor_cache_bytes",
    "bounded_persistent_state_bytes",
    "live_trail_bytes",
    "live_pending_bytes",
    "live_state_bytes",
    "live_persistent_state_bytes",
    "maximum_live_trail_bytes",
    "maximum_live_state_bytes",
    "maximum_live_persistent_state_bytes",
    "current_assigned_variables",
    "current_decision_level",
    "trail_entries",
    "pending_clause_length",
    "assignment_hex",
    "trail_hex",
    "pending_hex",
    "factor_cache_hex",
    "assignment_sha256",
    "trail_sha256",
    "pending_sha256",
    "factor_cache_sha256",
    "sha256",
    "persistent_sha256",
}
_STATE_INTEGER_FIELDS = {
    "assignment_bytes",
    "bounded_trail_bytes",
    "bounded_pending_bytes",
    "bounded_state_bytes",
    "derived_factor_cache_bytes",
    "bounded_persistent_state_bytes",
    "live_trail_bytes",
    "live_pending_bytes",
    "live_state_bytes",
    "live_persistent_state_bytes",
    "maximum_live_trail_bytes",
    "maximum_live_state_bytes",
    "maximum_live_persistent_state_bytes",
    "current_assigned_variables",
    "current_decision_level",
    "trail_entries",
    "pending_clause_length",
}


@dataclass(frozen=True)
class JointScoreSieveResult:
    status: int
    conflict_limit: int
    threshold: float
    key_model: bytes | None
    stats: Mapping[str, int]
    sieve: Mapping[str, object]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]

    @property
    def threshold_prunes(self) -> int:
        return cast(int, self.sieve["threshold_prunes"])

    @property
    def state_sha256(self) -> str:
        state = _mapping(self.sieve["state"], "sieve.state")
        return str(state["sha256"])


class _DarwinRUsageInfoV2(Structure):
    _fields_ = [
        ("ri_uuid", c_uint8 * 16),
        ("ri_user_time", c_uint64),
        ("ri_system_time", c_uint64),
        ("ri_pkg_idle_wkups", c_uint64),
        ("ri_interrupt_wkups", c_uint64),
        ("ri_pageins", c_uint64),
        ("ri_wired_size", c_uint64),
        ("ri_resident_size", c_uint64),
        ("ri_phys_footprint", c_uint64),
        ("ri_proc_start_abstime", c_uint64),
        ("ri_proc_exit_abstime", c_uint64),
        ("ri_child_user_time", c_uint64),
        ("ri_child_system_time", c_uint64),
        ("ri_child_pkg_idle_wkups", c_uint64),
        ("ri_child_interrupt_wkups", c_uint64),
        ("ri_child_pageins", c_uint64),
        ("ri_child_elapsed_abstime", c_uint64),
        ("ri_diskio_bytesread", c_uint64),
        ("ri_diskio_byteswritten", c_uint64),
    ]


class _JointScoreSieveMemoryLimitExceeded(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _darwin_proc_pid_rusage() -> Callable[[int, int, object], int]:
    try:
        library = CDLL("/usr/lib/libproc.dylib")
        function = library.proc_pid_rusage
        function.argtypes = (c_int, c_int, POINTER(_DarwinRUsageInfoV2))
        function.restype = c_int
    except (OSError, AttributeError) as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve Darwin memory watchdog is unavailable"
        ) from exc
    return cast(Callable[[int, int, object], int], function)


def _darwin_physical_footprint_bytes(pid: int) -> int:
    usage = _DarwinRUsageInfoV2()
    status = _darwin_proc_pid_rusage()(pid, 2, byref(usage))
    if status:
        raise O1RelationalSearchError(
            "joint-score-sieve Darwin memory watchdog query failed"
        )
    return max(int(usage.ri_resident_size), int(usage.ri_phys_footprint))


def _run_with_darwin_memory_watchdog(
    command: list[str],
    *,
    timeout_seconds: float,
    memory_limit_bytes: int,
) -> subprocess.CompletedProcess[str]:
    guard = min(
        JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
        max(0, memory_limit_bytes // 8),
    )
    kill_threshold = memory_limit_bytes - guard
    if kill_threshold <= 0:
        raise O1RelationalSearchError(
            "joint-score-sieve Darwin memory limit is too small"
        )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout_seconds
    maximum_observed = 0

    def kill_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                kill_process_group()
                process.communicate()
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            try:
                stdout, stderr = process.communicate(
                    timeout=min(
                        JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
                        remaining,
                    )
                )
                break
            except subprocess.TimeoutExpired:
                pass
            try:
                footprint = _darwin_physical_footprint_bytes(process.pid)
            except O1RelationalSearchError:
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    break
                raise
            maximum_observed = max(maximum_observed, footprint)
            if footprint >= kill_threshold:
                kill_process_group()
                process.communicate()
                raise _JointScoreSieveMemoryLimitExceeded(
                    "Darwin physical-footprint watchdog reached its guarded ceiling "
                    f"({maximum_observed} >= {kill_threshold} < {memory_limit_bytes})"
                )
            if time.monotonic() >= deadline:
                kill_process_group()
                process.communicate()
                raise subprocess.TimeoutExpired(command, timeout_seconds)
    except Exception:
        if process.poll() is None:
            kill_process_group()
            process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1RelationalSearchError(f"joint-score-sieve {field} differs")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1RelationalSearchError(f"joint-score-sieve {field} differs")
    return float(value)


def _nonnegative_integers(
    value: object, *, field: str, names: set[str]
) -> dict[str, int]:
    payload = _mapping(value, field)
    if set(payload) != names:
        raise O1RelationalSearchError(f"joint-score-sieve {field} fields differ")
    result: dict[str, int] = {}
    for name, raw in payload.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise O1RelationalSearchError(f"joint-score-sieve {field}.{name} differs")
        result[str(name)] = raw
    return result


def _read_input(path: str | Path, field: str) -> tuple[Path, bytes, str]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"joint-score-sieve {field} input differs"
        ) from exc
    if not payload:
        raise O1RelationalSearchError(f"joint-score-sieve {field} input differs")
    return resolved, payload, hashlib.sha256(payload).hexdigest()


def _verify_stable_input(
    original: str | Path, resolved: Path, before: bytes, *, field: str
) -> None:
    try:
        after_path = Path(original).resolve(strict=True)
        after = after_path.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"joint-score-sieve {field} changed during execution"
        ) from exc
    if after_path != resolved or after != before:
        raise O1RelationalSearchError(
            f"joint-score-sieve {field} changed during execution"
        )


def _potential(payload: bytes) -> CriticalityPotentialField:
    try:
        return CriticalityPotentialField.from_bytes(payload)
    except (CriticalityPotentialError, OverflowError) as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve potential input differs"
        ) from exc


def _observed_bytes(field: CriticalityPotentialField) -> bytes:
    return b"".join(
        struct.pack("<I", variable) for variable in field.observed_variables
    )


def joint_score_upper_bound(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> float:
    """Outward-rounded sum of factor maxima under a partial spin assignment."""

    if not isinstance(field, CriticalityPotentialField) or not isinstance(
        assignments, Mapping
    ):
        raise O1RelationalSearchError("joint-score-sieve bound input differs")
    normalized: dict[int, int] = {}
    for raw_variable, raw_spin in assignments.items():
        if (
            isinstance(raw_variable, bool)
            or not isinstance(raw_variable, int)
            or raw_variable not in field.observed_variables
            or isinstance(raw_spin, bool)
            or not isinstance(raw_spin, int)
            or raw_spin not in (-1, 1)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve partial assignment differs"
            )
        normalized[raw_variable] = raw_spin
    result = float(field.offset)
    for factor in field.factors:
        best = -math.inf
        for mask, energy in enumerate(factor.energies):
            if all(
                variable not in normalized
                or bool(mask & (1 << local)) == (normalized[variable] > 0)
                for local, variable in enumerate(factor.variables)
            ):
                best = max(best, energy)
        if not math.isfinite(best):
            raise O1RelationalSearchError(
                "joint-score-sieve factor has no consistent row"
            )
        raw = result + best
        if not math.isfinite(raw):
            raise O1RelationalSearchError("joint-score-sieve upper bound is not finite")
        result = math.nextafter(raw, math.inf)
        if not math.isfinite(result):
            raise O1RelationalSearchError(
                "joint-score-sieve upper bound is not representable"
            )
    return result


def joint_score_complete(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> float:
    """Exact complete score using the canonical potential scorer."""

    if set(assignments) != set(field.observed_variables):
        raise O1RelationalSearchError("joint-score-sieve complete assignment differs")
    try:
        return score_potential_assignment(field, assignments)
    except CriticalityPotentialError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve complete assignment differs"
        ) from exc


def build_native_joint_score_sieve(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    resolved, source_bytes, _ = _read_input(source, "native source")
    failure: Exception | None = None
    result: NativeGuidedSearchBuild | None = None
    try:
        result = build_native_guided_search(source=resolved, output=output)
    except Exception as exc:
        failure = exc
    _verify_stable_input(source, resolved, source_bytes, field="native source")
    if failure is not None:
        raise failure
    if result is None:
        raise O1RelationalSearchError("joint-score-sieve native build failed")
    return result


def write_joint_score_sieve_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    if not isinstance(field, CriticalityPotentialField):
        raise O1RelationalSearchError("joint-score-sieve potential differs")
    payload = field.to_bytes()
    try:
        Path(path).write_bytes(payload)
    except OSError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve potential write failed"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _decode_state(
    raw: object,
    *,
    field: CriticalityPotentialField,
    pending_clause_count: int,
) -> dict[str, object]:
    observed = field.observed_variables
    state = _mapping(raw, "sieve.state")
    if set(state) != _STATE_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve state fields differ")
    integers: dict[str, int] = {}
    for name in _STATE_INTEGER_FIELDS:
        value = state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"joint-score-sieve state.{name} differs")
        integers[name] = value
    if state["encoding"] != JOINT_SCORE_SIEVE_STATE_ENCODING:
        raise O1RelationalSearchError("joint-score-sieve state encoding differs")
    if state["persistent_state_scope"] != JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE:
        raise O1RelationalSearchError("joint-score-sieve state scope differs")
    try:
        assignments = bytes.fromhex(str(state["assignment_hex"]))
        trail = bytes.fromhex(str(state["trail_hex"]))
        pending = bytes.fromhex(str(state["pending_hex"]))
        factor_cache = bytes.fromhex(str(state["factor_cache_hex"]))
    except ValueError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve state encoding differs"
        ) from exc
    observed_count = len(observed)
    bounded_trail = 8 + 8 * observed_count
    bounded_pending = 10 + 4 * observed_count
    derived_cache_bytes = 8 * len(field.factors)
    if (
        len(assignments) != observed_count
        or any(value not in (0, 1, 255) for value in assignments)
        or len(trail) < 8
        or (len(trail) - 8) % 8
        or len(pending) < 10
        or (len(pending) - 10) % 4
        or integers["assignment_bytes"] != observed_count
        or integers["bounded_trail_bytes"] != bounded_trail
        or integers["bounded_pending_bytes"] != bounded_pending
        or integers["bounded_state_bytes"]
        != observed_count + bounded_trail + bounded_pending
        or len(factor_cache) != derived_cache_bytes
        or integers["derived_factor_cache_bytes"] != derived_cache_bytes
        or integers["bounded_persistent_state_bytes"]
        != integers["bounded_state_bytes"] + derived_cache_bytes
        or integers["live_trail_bytes"] != len(trail)
        or integers["live_pending_bytes"] != len(pending)
        or integers["live_state_bytes"] != len(assignments) + len(trail) + len(pending)
        or integers["live_persistent_state_bytes"]
        != integers["live_state_bytes"] + derived_cache_bytes
        or integers["current_assigned_variables"]
        != sum(value != 0 for value in assignments)
        or integers["maximum_live_trail_bytes"] < len(trail)
        or integers["maximum_live_trail_bytes"] > bounded_trail
        or (integers["maximum_live_trail_bytes"] - 8) % 8
        or integers["maximum_live_state_bytes"] < integers["live_state_bytes"]
        or integers["maximum_live_state_bytes"] > integers["bounded_state_bytes"]
        or integers["maximum_live_persistent_state_bytes"]
        != integers["maximum_live_state_bytes"] + derived_cache_bytes
    ):
        raise O1RelationalSearchError("joint-score-sieve state size differs")
    current_level, trail_count = struct.unpack_from("<II", trail)
    if trail_count > observed_count or len(trail) != 8 + 8 * trail_count:
        raise O1RelationalSearchError("joint-score-sieve trail differs")
    trail_entries = tuple(
        struct.unpack_from("<II", trail, 8 + 8 * index) for index in range(trail_count)
    )
    if (
        integers["current_decision_level"] != current_level
        or integers["trail_entries"] != trail_count
        or integers["current_assigned_variables"] != trail_count
        or len({local for local, _ in trail_entries}) != trail_count
        or any(local >= observed_count for local, _ in trail_entries)
        or any(level > current_level for _, level in trail_entries)
        or any(
            trail_entries[index - 1][1] > trail_entries[index][1]
            for index in range(1, trail_count)
        )
        or any(assignments[local] == 0 for local, _ in trail_entries)
    ):
        raise O1RelationalSearchError("joint-score-sieve trail differs")
    spins = {
        variable: (1 if assignments[local] == 1 else -1)
        for local, variable in enumerate(observed)
        if assignments[local]
    }
    expected_cache = bytearray()
    for factor in field.factors:
        best = -math.inf
        for mask, energy in enumerate(factor.energies):
            if (
                all(
                    variable not in spins
                    or bool(mask & (1 << local)) == (spins[variable] > 0)
                    for local, variable in enumerate(factor.variables)
                )
                and best < energy
            ):
                best = energy
        if not math.isfinite(best):
            raise O1RelationalSearchError("joint-score-sieve factor cache differs")
        expected_cache.extend(struct.pack("<d", best))
    if factor_cache != bytes(expected_cache):
        raise O1RelationalSearchError("joint-score-sieve factor cache differs")
    length, cursor, ready, blocking = struct.unpack_from("<IIBB", pending)
    if length > observed_count or len(pending) != 10 + 4 * length:
        raise O1RelationalSearchError("joint-score-sieve pending clause differs")
    literals = tuple(
        struct.unpack_from("<i", pending, 10 + 4 * index)[0] for index in range(length)
    )
    if (
        cursor > length
        or ready not in (0, 1)
        or blocking not in (0, 1)
        or ready != blocking
        or (ready == 0 and (length != 0 or cursor != 0))
        or (ready == 1 and pending_clause_count != 1)
        or ready != pending_clause_count
        or integers["pending_clause_length"] != length
        or len(set(map(abs, literals))) != len(literals)
        or any(abs(literal) not in observed for literal in literals)
    ):
        raise O1RelationalSearchError("joint-score-sieve pending clause differs")
    canonical = assignments + trail + pending
    working = canonical + factor_cache
    hashes = {
        "assignment_sha256": hashlib.sha256(assignments).hexdigest(),
        "trail_sha256": hashlib.sha256(trail).hexdigest(),
        "pending_sha256": hashlib.sha256(pending).hexdigest(),
        "factor_cache_sha256": hashlib.sha256(factor_cache).hexdigest(),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "persistent_sha256": hashlib.sha256(working).hexdigest(),
    }
    if any(
        not _is_sha256(state[name]) or state[name] != value
        for name, value in hashes.items()
    ):
        raise O1RelationalSearchError("joint-score-sieve state hash differs")
    return dict(state)


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveResult:
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or not 1 <= conflict_limit <= 1_000_000_000
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
            "joint-score-sieve threshold, limit, seed, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = _read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _read_input(
        potential_path, "potential"
    )
    field = _potential(potential_bytes)
    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(conflict_limit),
        "--seed",
        str(seed),
    ]
    execution_error: OSError | RuntimeError | subprocess.SubprocessError | None = None
    completed: subprocess.CompletedProcess[str] | None

    def apply_memory_limit() -> None:
        if memory_limit_bytes is None:
            return
        resource.setrlimit(
            resource.RLIMIT_AS,
            (memory_limit_bytes, memory_limit_bytes),
        )

    try:
        if memory_limit_bytes is not None and sys.platform == "darwin":
            completed = _run_with_darwin_memory_watchdog(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        else:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=float(timeout_seconds),
                check=False,
                preexec_fn=(
                    apply_memory_limit if memory_limit_bytes is not None else None
                ),
            )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        completed = None
    _verify_stable_input(
        executable, executable_file, executable_bytes, field="executable"
    )
    _verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
    _verify_stable_input(
        potential_path, potential_file, potential_bytes, field="potential"
    )
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve execution failed"
        ) from execution_error
    if completed is None:
        raise O1RelationalSearchError("joint-score-sieve execution failed")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(f"joint-score-sieve execution failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve result JSON is invalid"
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve result fields differ")
    variables = payload["variables"]
    reported_limit = payload["conflict_limit"]
    reported_seed = payload["seed"]
    status = payload["status"]
    reported_threshold = _finite_float(payload["threshold"], "threshold")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["cadical_version"] != "3.0.0"
        or isinstance(variables, bool)
        or not isinstance(variables, int)
        or variables < max(256, max(field.observed_variables))
        or isinstance(reported_limit, bool)
        or not isinstance(reported_limit, int)
        or reported_limit != conflict_limit
        or isinstance(reported_seed, bool)
        or not isinstance(reported_seed, int)
        or reported_seed != seed
        or reported_threshold != requested_threshold
        or isinstance(status, bool)
        or status not in (0, 10, 20)
        or payload["cnf_sha256"] != cnf_sha
        or payload["potential_sha256"] != potential_sha
    ):
        raise O1RelationalSearchError("joint-score-sieve result contract differs")
    raw_model = payload["key_model_hex"]
    if status == 10:
        if not isinstance(raw_model, str) or len(raw_model) != 64:
            raise O1RelationalSearchError("joint-score-sieve SAT result lacks key")
        try:
            key_model = bytes.fromhex(raw_model)
        except ValueError as exc:
            raise O1RelationalSearchError(
                "joint-score-sieve key encoding differs"
            ) from exc
    elif raw_model is not None:
        raise O1RelationalSearchError("joint-score-sieve non-SAT result contains key")
    else:
        key_model = None
    stats = _nonnegative_integers(payload["stats"], field="stats", names=_STATS_FIELDS)
    resources = _nonnegative_integers(
        payload["resources"], field="resources", names=_RESOURCE_FIELDS
    )
    if (
        memory_limit_bytes is not None
        and resources["peak_rss_bytes"] > memory_limit_bytes
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve child exceeded its memory limit"
        )
    sieve = _mapping(payload["sieve"], "sieve")
    if set(sieve) != _SIEVE_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve telemetry fields differ")
    integers: dict[str, int] = {}
    for name in _SIEVE_INTEGER_FIELDS:
        value = sieve[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"joint-score-sieve telemetry.{name} differs")
        integers[name] = value
    observed = field.observed_variables
    observed_sha = hashlib.sha256(_observed_bytes(field)).hexdigest()
    root_upper = joint_score_upper_bound(field, {})
    offset = _finite_float(sieve["offset"], "sieve.offset")
    sieve_threshold = _finite_float(sieve["threshold"], "sieve.threshold")
    reported_root = _finite_float(sieve["root_upper_bound"], "sieve.root_upper_bound")
    minimum_upper = _finite_float(
        sieve["minimum_upper_bound"], "sieve.minimum_upper_bound"
    )
    maximum_upper = _finite_float(
        sieve["maximum_upper_bound"], "sieve.maximum_upper_bound"
    )
    factor_count = len(field.factors)
    root_factor_rows = sum(len(factor.energies) for factor in field.factors)
    incident_edges = sum(len(factor.variables) for factor in field.factors)
    incremental_recomputations = integers["incremental_factor_recomputations"]
    if (
        integers["factor_count"] != factor_count
        or integers["observed_variables"] != len(observed)
        or sieve["observed_variables_sha256"] != observed_sha
        or sieve["source_sha256"] != field.source_sha256
        or offset != field.offset
        or sieve_threshold != requested_threshold
        or reported_root != root_upper
        or sieve["bound_rule"] != JOINT_SCORE_SIEVE_BOUND_RULE
        or sieve["complete_threshold_rule"] != JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
        or sieve["decision_rule"] != JOINT_SCORE_SIEVE_DECISION_RULE
        or integers["external_implications"] != 0
        or integers["cb_decide_nonzero"] != 0
        or not _is_sha256(sieve["trace_sha256"])
        or not minimum_upper <= reported_root <= maximum_upper
        or integers["bound_checks"] < 1
        or integers["bound_additions"] != integers["bound_checks"] * factor_count
        or integers["incident_edges"] != incident_edges
        or integers["factor_maximum_evaluations"]
        != factor_count + incremental_recomputations
        or integers["factor_row_evaluations"]
        < root_factor_rows + 2 * incremental_recomputations
        or integers["factor_row_evaluations"]
        > root_factor_rows + 256 * incremental_recomputations
        or incremental_recomputations < integers["bound_checks"] - 1
        or integers["maximum_incremental_factors_recomputed"] > factor_count
        or (
            incremental_recomputations == 0
            and integers["maximum_incremental_factors_recomputed"] != 0
        )
        or (
            incremental_recomputations > 0
            and not 1
            <= integers["maximum_incremental_factors_recomputed"]
            <= incremental_recomputations
        )
        or integers["maximum_assigned_variables"] > len(observed)
        or integers["maximum_decision_level"] > integers["new_decision_levels"]
        or integers["backtracked_assignments"] > integers["assignment_literals"]
        or integers["threshold_prunes"]
        != integers["trail_threshold_prunes"] + integers["model_threshold_prunes"]
        or integers["threshold_prunes"] != integers["external_clauses_queued"]
        or integers["models_below_threshold"] != integers["model_threshold_prunes"]
        or integers["external_clauses_emitted"] + integers["pending_clause_count"]
        != integers["external_clauses_queued"]
        or integers["pending_clause_count"] > 1
        or integers["maximum_clause_length"] > len(observed)
        or integers["maximum_pending_clause_length"] > integers["maximum_clause_length"]
        or integers["minimum_clause_length"] > integers["maximum_clause_length"]
        or integers["external_clause_literals"]
        < integers["external_clauses_queued"] * integers["minimum_clause_length"]
        or integers["external_clause_literals"]
        > integers["external_clauses_queued"] * integers["maximum_clause_length"]
        or integers["model_checks"]
        != integers["models_below_threshold"] + integers["models_at_or_above_threshold"]
        or integers["complete_model_score_checks"] != integers["model_checks"]
        or integers["models_at_or_above_threshold"] != (1 if status == 10 else 0)
    ):
        raise O1RelationalSearchError("joint-score-sieve telemetry contract differs")
    minimum_complete = sieve["minimum_complete_score"]
    maximum_complete = sieve["maximum_complete_score"]
    if integers["complete_model_score_checks"]:
        low = _finite_float(minimum_complete, "sieve.minimum_complete_score")
        high = _finite_float(maximum_complete, "sieve.maximum_complete_score")
        if low > high:
            raise O1RelationalSearchError(
                "joint-score-sieve complete score range differs"
            )
    elif minimum_complete is not None or maximum_complete is not None:
        raise O1RelationalSearchError("joint-score-sieve absent complete score differs")
    decoded_state = _decode_state(
        sieve["state"],
        field=field,
        pending_clause_count=integers["pending_clause_count"],
    )
    if (
        integers["assignment_literals"] - integers["backtracked_assignments"]
        != cast(int, decoded_state["current_assigned_variables"])
        or cast(int, decoded_state["current_decision_level"])
        > integers["maximum_decision_level"]
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve live assignment ledger differs"
        )
    state_maximum_trail = cast(int, decoded_state["maximum_live_trail_bytes"])
    state_maximum = cast(int, decoded_state["maximum_live_state_bytes"])
    if (
        state_maximum_trail != 8 + 8 * integers["maximum_assigned_variables"]
        or state_maximum < len(observed) + state_maximum_trail + 10
        or state_maximum
        < len(observed) + 8 + 10 + 4 * integers["maximum_pending_clause_length"]
        or state_maximum
        > len(observed)
        + state_maximum_trail
        + 10
        + 4 * integers["maximum_pending_clause_length"]
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve maximum live-state ledger differs"
        )
    normalized_sieve = dict(sieve)
    normalized_sieve["state"] = decoded_state
    return JointScoreSieveResult(
        status=status,
        conflict_limit=conflict_limit,
        threshold=requested_threshold,
        key_model=key_model,
        stats=stats,
        sieve=normalized_sieve,
        resources=resources,
        raw=dict(payload),
    )


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JointScoreSieveResult",
    "build_native_joint_score_sieve",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "write_joint_score_sieve_potential",
]
