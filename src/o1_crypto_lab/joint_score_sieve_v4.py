"""Compatibility-aware grouped upper bounds for the joint-score sieve.

This module is deliberately versioned beside the frozen v1-v3 contracts.  It
keeps complete-model scoring on the original potential factors while pairing
compatible factors only for partial-assignment upper bounds.
"""

from __future__ import annotations

import hashlib
import json
import math
import resource
import struct
import subprocess
import sys
from dataclasses import dataclass, replace
from functools import lru_cache
from itertools import chain
from pathlib import Path
from typing import Mapping, cast

from . import joint_score_sieve as _v1
from .criticality_potential import CriticalityPotentialFactor, CriticalityPotentialField
from .joint_score_sieve import (
    JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
    JointScoreSieveResult,
    build_native_joint_score_sieve,
    joint_score_complete,
    write_joint_score_sieve_potential,
)
from .joint_score_sieve_v3 import (
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS,
    derive_soft_conflict_ledger,
)
from .o1_relational_search import O1RelationalSearchError

JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v3"
JOINT_SCORE_SIEVE_STATE_SCHEMA = "o1-256-cadical-joint-score-sieve-grouped-state-v1"
JOINT_SCORE_SIEVE_GROUPING_MAGIC = b"O1-GROUPED-BOUND-V1\0"
JOINT_SCORE_SIEVE_GROUPING_RULE = (
    "ascending-factor-greedy-smallest-unmatched-earlier-overlap-"
    "union-width-at-most-8;groups-ascending-min-factor-index"
)
JOINT_SCORE_SIEVE_BOUND_RULE = (
    "pair-cell-twosum-directed-positive-infinity;partial-group-maximum;"
    "nextafter-positive-infinity-after-each-group-maximum-addition"
)
JOINT_SCORE_SIEVE_STATE_ENCODING = (
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-group-cache-group-order-"
    "f64le-max"
)

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
_NATIVE_STATS_FIELDS = {
    "conflicts",
    "conflicts_before_solve",
    "solve_conflicts",
    "decisions",
    "propagations",
}
_RESOURCE_FIELDS = {"wall_microseconds", "cpu_microseconds", "peak_rss_bytes"}
_SIEVE_FIELDS = {
    "factor_count",
    "group_count",
    "pair_group_count",
    "singleton_group_count",
    "group_table_rows",
    "group_incident_edges",
    "grouping_rule",
    "grouping_sha256",
    "observed_variables",
    "observed_variables_sha256",
    "source_sha256",
    "offset",
    "threshold",
    "root_upper_bound",
    "root_upper_bound_f64le_hex",
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
    "incremental_group_recomputations",
    "maximum_incremental_groups_recomputed",
    "group_maximum_evaluations",
    "group_row_evaluations",
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
    "group_count",
    "pair_group_count",
    "singleton_group_count",
    "group_table_rows",
    "group_incident_edges",
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
    "incremental_group_recomputations",
    "maximum_incremental_groups_recomputed",
    "group_maximum_evaluations",
    "group_row_evaluations",
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
    "schema",
    "encoding",
    "persistent_state_scope",
    "assignment_bytes",
    "bounded_trail_bytes",
    "bounded_pending_bytes",
    "bounded_state_bytes",
    "derived_group_cache_bytes",
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
    "group_cache_hex",
    "assignment_sha256",
    "trail_sha256",
    "pending_sha256",
    "group_cache_sha256",
    "sha256",
    "persistent_sha256",
}
_STATE_INTEGER_FIELDS = {
    "assignment_bytes",
    "bounded_trail_bytes",
    "bounded_pending_bytes",
    "bounded_state_bytes",
    "derived_group_cache_bytes",
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
class JointScoreCompatibilityGroup:
    """One singleton or compatibility-aware pair in canonical group order."""

    factor_indices: tuple[int, ...]
    variables: tuple[int, ...]
    energies: tuple[float, ...]

    def __post_init__(self) -> None:
        if (
            len(self.factor_indices) not in (1, 2)
            or tuple(sorted(set(self.factor_indices))) != self.factor_indices
            or not self.variables
            or len(self.variables) > 8
            or tuple(sorted(set(self.variables))) != self.variables
            or len(self.energies) != 1 << len(self.variables)
            or any(not math.isfinite(energy) for energy in self.energies)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve compatibility group differs"
            )


@dataclass(frozen=True)
class JointScoreCompatibilityGrouping:
    """The immutable grouping and all deterministic structural ledgers."""

    factor_count: int
    groups: tuple[JointScoreCompatibilityGroup, ...]
    serialized: bytes
    sha256: str

    def __post_init__(self) -> None:
        members = tuple(
            factor_index
            for group in self.groups
            for factor_index in group.factor_indices
        )
        minimum_factor_indices = tuple(group.factor_indices[0] for group in self.groups)
        if (
            self.factor_count < 1
            or sorted(members) != list(range(self.factor_count))
            or len(members) != len(set(members))
            or minimum_factor_indices != tuple(sorted(minimum_factor_indices))
            or self.serialized != serialize_compatibility_grouping(self.groups)
            or self.sha256 != hashlib.sha256(self.serialized).hexdigest()
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve compatibility grouping differs"
            )

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def pair_group_count(self) -> int:
        return sum(len(group.factor_indices) == 2 for group in self.groups)

    @property
    def singleton_group_count(self) -> int:
        return sum(len(group.factor_indices) == 1 for group in self.groups)

    @property
    def table_rows(self) -> int:
        return sum(len(group.energies) for group in self.groups)

    @property
    def incident_edges(self) -> int:
        return sum(len(group.variables) for group in self.groups)


def _project_union_mask(
    union_mask: int,
    union_variables: tuple[int, ...],
    factor_variables: tuple[int, ...],
) -> int:
    positions = {
        variable: position for position, variable in enumerate(union_variables)
    }
    result = 0
    for local, variable in enumerate(factor_variables):
        if union_mask & (1 << positions[variable]):
            result |= 1 << local
    return result


def _upward_pair_energy(left: float, right: float) -> float:
    raw = left + right
    if raw == -math.inf:
        return -sys.float_info.max
    if not math.isfinite(raw):
        raise O1RelationalSearchError(
            "joint-score-sieve grouped pair energy is not representable"
        )
    # Knuth TwoSum recovers the exact residual of the round-to-nearest add.
    # A positive residual means ``raw`` rounded below the real sum and needs
    # one ULP toward +infinity; zero or negative is already an upper result.
    right_virtual = raw - left
    left_virtual = raw - right_virtual
    residual = (left - left_virtual) + (right - right_virtual)
    bounded = math.nextafter(raw, math.inf) if residual > 0.0 else raw
    if not math.isfinite(bounded):
        raise O1RelationalSearchError(
            "joint-score-sieve grouped pair energy is not representable"
        )
    return bounded


def _pair_group(
    first_index: int,
    second_index: int,
    factors: tuple[CriticalityPotentialFactor, ...],
) -> JointScoreCompatibilityGroup:
    first = factors[first_index]
    second = factors[second_index]
    variables = tuple(sorted(set(first.variables) | set(second.variables)))
    energies = tuple(
        _upward_pair_energy(
            first.energies[_project_union_mask(mask, variables, first.variables)],
            second.energies[_project_union_mask(mask, variables, second.variables)],
        )
        for mask in range(1 << len(variables))
    )
    return JointScoreCompatibilityGroup(
        (first_index, second_index), variables, energies
    )


def serialize_compatibility_grouping(
    groups: tuple[JointScoreCompatibilityGroup, ...],
) -> bytes:
    """Serialize only structural grouping data in the frozen v1 byte format."""

    if not isinstance(groups, tuple) or len(groups) > 0xFFFFFFFF:
        raise O1RelationalSearchError(
            "joint-score-sieve compatibility grouping serialization differs"
        )
    payload = bytearray(JOINT_SCORE_SIEVE_GROUPING_MAGIC)
    payload.extend(struct.pack("<I", len(groups)))
    for group in groups:
        if not isinstance(group, JointScoreCompatibilityGroup):
            raise O1RelationalSearchError(
                "joint-score-sieve compatibility grouping serialization differs"
            )
        payload.extend(struct.pack("<B", len(group.factor_indices)))
        for factor_index in group.factor_indices:
            if not 0 <= factor_index <= 0xFFFFFFFF:
                raise O1RelationalSearchError(
                    "joint-score-sieve compatibility factor index differs"
                )
            payload.extend(struct.pack("<I", factor_index))
        payload.extend(struct.pack("<B", len(group.variables)))
        for variable in group.variables:
            if not 1 <= variable <= 0xFFFFFFFF:
                raise O1RelationalSearchError(
                    "joint-score-sieve compatibility variable differs"
                )
            payload.extend(struct.pack("<I", variable))
    return bytes(payload)


@lru_cache(maxsize=8)
def build_compatibility_grouping(
    field: CriticalityPotentialField,
) -> JointScoreCompatibilityGrouping:
    """Build the deterministic smallest-earlier greedy overlap partition."""

    if not isinstance(field, CriticalityPotentialField):
        raise O1RelationalSearchError(
            "joint-score-sieve compatibility potential differs"
        )
    factors = field.factors
    unmatched = [True] * len(factors)
    earlier_by_variable: dict[int, list[int]] = {}
    pairs: list[tuple[int, int]] = []
    for second_index, second in enumerate(factors):
        candidates = sorted(
            set(
                chain.from_iterable(
                    earlier_by_variable.get(variable, ())
                    for variable in second.variables
                )
            )
        )
        for first_index in candidates:
            if not unmatched[first_index]:
                continue
            union_width = len(
                set(factors[first_index].variables) | set(second.variables)
            )
            if union_width <= 8:
                unmatched[first_index] = False
                unmatched[second_index] = False
                pairs.append((first_index, second_index))
                break
        for variable in second.variables:
            earlier_by_variable.setdefault(variable, []).append(second_index)
    groups = [
        _pair_group(first_index, second_index, factors)
        for first_index, second_index in pairs
    ]
    groups.extend(
        JointScoreCompatibilityGroup((factor_index,), factor.variables, factor.energies)
        for factor_index, factor in enumerate(factors)
        if unmatched[factor_index]
    )
    ordered = tuple(sorted(groups, key=lambda group: group.factor_indices[0]))
    serialized = serialize_compatibility_grouping(ordered)
    return JointScoreCompatibilityGrouping(
        factor_count=len(factors),
        groups=ordered,
        serialized=serialized,
        sha256=hashlib.sha256(serialized).hexdigest(),
    )


def _normalize_partial_assignment(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> dict[int, int]:
    if not isinstance(field, CriticalityPotentialField) or not isinstance(
        assignments, Mapping
    ):
        raise O1RelationalSearchError("joint-score-sieve bound input differs")
    observed = set(field.observed_variables)
    normalized: dict[int, int] = {}
    for variable, spin in assignments.items():
        if (
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or variable not in observed
            or isinstance(spin, bool)
            or not isinstance(spin, int)
            or spin not in (-1, 1)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve partial assignment differs"
            )
        normalized[variable] = spin
    return normalized


def _group_maximum(
    group: JointScoreCompatibilityGroup, assignments: Mapping[int, int]
) -> float:
    best = -math.inf
    for mask, energy in enumerate(group.energies):
        if all(
            variable not in assignments
            or bool(mask & (1 << local)) == (assignments[variable] > 0)
            for local, variable in enumerate(group.variables)
        ):
            best = max(best, energy)
    if not math.isfinite(best):
        raise O1RelationalSearchError("joint-score-sieve group has no consistent row")
    return best


def grouped_joint_score_cache(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> bytes:
    """Serialize current group maxima as canonical group-order f64le values."""

    normalized = _normalize_partial_assignment(field, assignments)
    grouping = build_compatibility_grouping(field)
    return b"".join(
        struct.pack("<d", _group_maximum(group, normalized))
        for group in grouping.groups
    )


def joint_score_upper_bound(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> float:
    """Return the outward-rounded compatibility-aware grouped upper bound."""

    normalized = _normalize_partial_assignment(field, assignments)
    result = float(field.offset)
    for group in build_compatibility_grouping(field).groups:
        raw = result + _group_maximum(group, normalized)
        if not math.isfinite(raw):
            raise O1RelationalSearchError(
                "joint-score-sieve grouped upper bound is not finite"
            )
        result = math.nextafter(raw, math.inf)
        if not math.isfinite(result):
            raise O1RelationalSearchError(
                "joint-score-sieve grouped upper bound is not representable"
            )
    return result


def grouped_upper_bound_prunes(upper: float, threshold: float) -> bool:
    """The frozen threshold policy: equality survives; only strict less prunes."""

    if (
        isinstance(upper, bool)
        or not isinstance(upper, (int, float))
        or not math.isfinite(upper)
        or isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve grouped threshold comparison differs"
        )
    return float(upper) < float(threshold)


def _decode_state(
    raw: object,
    *,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    pending_clause_count: int,
) -> dict[str, object]:
    observed = field.observed_variables
    state = _v1._mapping(raw, "sieve.state")
    if set(state) != _STATE_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve grouped state fields differ")
    integers: dict[str, int] = {}
    for name in _STATE_INTEGER_FIELDS:
        value = state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve grouped state.{name} differs"
            )
        integers[name] = value
    if state["schema"] != JOINT_SCORE_SIEVE_STATE_SCHEMA:
        raise O1RelationalSearchError("joint-score-sieve grouped state schema differs")
    if state["encoding"] != JOINT_SCORE_SIEVE_STATE_ENCODING:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped state encoding differs"
        )
    if state["persistent_state_scope"] != JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE:
        raise O1RelationalSearchError("joint-score-sieve grouped state scope differs")
    try:
        assignments = bytes.fromhex(str(state["assignment_hex"]))
        trail = bytes.fromhex(str(state["trail_hex"]))
        pending = bytes.fromhex(str(state["pending_hex"]))
        group_cache = bytes.fromhex(str(state["group_cache_hex"]))
    except ValueError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped state encoding differs"
        ) from exc
    observed_count = len(observed)
    bounded_trail = 8 + 8 * observed_count
    bounded_pending = 10 + 4 * observed_count
    derived_cache_bytes = 8 * grouping.group_count
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
        or len(group_cache) != derived_cache_bytes
        or integers["derived_group_cache_bytes"] != derived_cache_bytes
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
        raise O1RelationalSearchError("joint-score-sieve grouped state size differs")
    current_level, trail_count = struct.unpack_from("<II", trail)
    if trail_count > observed_count or len(trail) != 8 + 8 * trail_count:
        raise O1RelationalSearchError("joint-score-sieve grouped trail differs")
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
        raise O1RelationalSearchError("joint-score-sieve grouped trail differs")
    spins = {
        variable: (1 if assignments[local] == 1 else -1)
        for local, variable in enumerate(observed)
        if assignments[local]
    }
    expected_cache = grouped_joint_score_cache(field, spins)
    if group_cache != expected_cache:
        raise O1RelationalSearchError("joint-score-sieve grouped cache differs")
    length, cursor, ready, blocking = struct.unpack_from("<IIBB", pending)
    if length > observed_count or len(pending) != 10 + 4 * length:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped pending clause differs"
        )
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
        raise O1RelationalSearchError(
            "joint-score-sieve grouped pending clause differs"
        )
    canonical = assignments + trail + pending
    persistent = canonical + group_cache
    hashes = {
        "assignment_sha256": hashlib.sha256(assignments).hexdigest(),
        "trail_sha256": hashlib.sha256(trail).hexdigest(),
        "pending_sha256": hashlib.sha256(pending).hexdigest(),
        "group_cache_sha256": hashlib.sha256(group_cache).hexdigest(),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "persistent_sha256": hashlib.sha256(persistent).hexdigest(),
    }
    if any(
        not _v1._is_sha256(state[name]) or state[name] != value
        for name, value in hashes.items()
    ):
        raise O1RelationalSearchError("joint-score-sieve grouped state hash differs")
    return dict(state)


def _requested_conflicts(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve requested conflict budget differs"
        )
    return value


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
    """Execute native-v3 and validate every grouped-bound byte ledger."""

    requested = _requested_conflicts(conflict_limit)
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
            "joint-score-sieve threshold, seed, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v1._read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = _v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v1._read_input(
        potential_path, "potential"
    )
    field = _v1._potential(potential_bytes)
    grouping = build_compatibility_grouping(field)
    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        str(seed),
    ]

    def apply_memory_limit() -> None:
        if memory_limit_bytes is not None:
            resource.setrlimit(
                resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes)
            )

    execution_error: OSError | RuntimeError | subprocess.SubprocessError | None = None
    completed: subprocess.CompletedProcess[str] | None
    try:
        if memory_limit_bytes is not None and sys.platform == "darwin":
            completed = _v1._run_with_darwin_memory_watchdog(
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
    _v1._verify_stable_input(
        executable, executable_file, executable_bytes, field="executable"
    )
    _v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
    _v1._verify_stable_input(
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
    reported_threshold = _v1._finite_float(payload["threshold"], "threshold")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["cadical_version"] != "3.0.0"
        or isinstance(variables, bool)
        or not isinstance(variables, int)
        or variables < max(256, max(field.observed_variables))
        or isinstance(reported_limit, bool)
        or not isinstance(reported_limit, int)
        or reported_limit != requested
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
    native_stats = _v1._nonnegative_integers(
        payload["stats"], field="stats", names=_NATIVE_STATS_FIELDS
    )
    resources = _v1._nonnegative_integers(
        payload["resources"], field="resources", names=_RESOURCE_FIELDS
    )
    if (
        memory_limit_bytes is not None
        and resources["peak_rss_bytes"] > memory_limit_bytes
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve child exceeded its memory limit"
        )
    sieve = _v1._mapping(payload["sieve"], "sieve")
    if set(sieve) != _SIEVE_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped telemetry fields differ"
        )
    integers: dict[str, int] = {}
    for name in _SIEVE_INTEGER_FIELDS:
        value = sieve[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve grouped telemetry.{name} differs"
            )
        integers[name] = value
    observed = field.observed_variables
    observed_sha = hashlib.sha256(_v1._observed_bytes(field)).hexdigest()
    root_upper = joint_score_upper_bound(field, {})
    offset = _v1._finite_float(sieve["offset"], "sieve.offset")
    sieve_threshold = _v1._finite_float(sieve["threshold"], "sieve.threshold")
    reported_root = _v1._finite_float(
        sieve["root_upper_bound"], "sieve.root_upper_bound"
    )
    minimum_upper = _v1._finite_float(
        sieve["minimum_upper_bound"], "sieve.minimum_upper_bound"
    )
    maximum_upper = _v1._finite_float(
        sieve["maximum_upper_bound"], "sieve.maximum_upper_bound"
    )
    recomputations = integers["incremental_group_recomputations"]
    if (
        integers["factor_count"] != len(field.factors)
        or integers["group_count"] != grouping.group_count
        or integers["pair_group_count"] != grouping.pair_group_count
        or integers["singleton_group_count"] != grouping.singleton_group_count
        or integers["pair_group_count"] * 2 + integers["singleton_group_count"]
        != integers["factor_count"]
        or integers["group_table_rows"] != grouping.table_rows
        or integers["group_incident_edges"] != grouping.incident_edges
        or sieve["grouping_rule"] != JOINT_SCORE_SIEVE_GROUPING_RULE
        or sieve["grouping_sha256"] != grouping.sha256
        or integers["observed_variables"] != len(observed)
        or sieve["observed_variables_sha256"] != observed_sha
        or sieve["source_sha256"] != field.source_sha256
        or offset != field.offset
        or sieve_threshold != requested_threshold
        or reported_root != root_upper
        or sieve["root_upper_bound_f64le_hex"] != struct.pack("<d", root_upper).hex()
        or sieve["bound_rule"] != JOINT_SCORE_SIEVE_BOUND_RULE
        or sieve["complete_threshold_rule"] != JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
        or sieve["decision_rule"] != JOINT_SCORE_SIEVE_DECISION_RULE
        or integers["external_implications"] != 0
        or integers["cb_decide_nonzero"] != 0
        or not _v1._is_sha256(sieve["trace_sha256"])
        or not minimum_upper <= reported_root <= maximum_upper
        or integers["bound_checks"] < 1
        or integers["bound_additions"]
        != integers["bound_checks"] * grouping.group_count
        or integers["group_maximum_evaluations"]
        != grouping.group_count + recomputations
        or integers["group_row_evaluations"] < grouping.table_rows + 2 * recomputations
        or integers["group_row_evaluations"]
        > grouping.table_rows + 256 * recomputations
        or recomputations < integers["bound_checks"] - 1
        or integers["maximum_incremental_groups_recomputed"] > grouping.group_count
        or (
            recomputations == 0
            and integers["maximum_incremental_groups_recomputed"] != 0
        )
        or (
            recomputations > 0
            and not 1
            <= integers["maximum_incremental_groups_recomputed"]
            <= recomputations
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
        raise O1RelationalSearchError(
            "joint-score-sieve grouped telemetry contract differs"
        )
    minimum_complete = sieve["minimum_complete_score"]
    maximum_complete = sieve["maximum_complete_score"]
    if integers["complete_model_score_checks"]:
        low = _v1._finite_float(minimum_complete, "sieve.minimum_complete_score")
        high = _v1._finite_float(maximum_complete, "sieve.maximum_complete_score")
        if low > high:
            raise O1RelationalSearchError(
                "joint-score-sieve complete score range differs"
            )
    elif minimum_complete is not None or maximum_complete is not None:
        raise O1RelationalSearchError("joint-score-sieve absent complete score differs")
    decoded_state = _decode_state(
        sieve["state"],
        field=field,
        grouping=grouping,
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
    native_result = JointScoreSieveResult(
        status=cast(int, status),
        conflict_limit=requested,
        threshold=requested_threshold,
        key_model=key_model,
        stats=native_stats,
        sieve=normalized_sieve,
        resources=resources,
        raw=dict(payload),
    )
    return replace(
        native_result,
        stats=derive_soft_conflict_ledger(native_stats, requested_conflicts=requested),
    )


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_GROUPING_MAGIC",
    "JOINT_SCORE_SIEVE_GROUPING_RULE",
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_STATE_SCHEMA",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreSieveResult",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "serialize_compatibility_grouping",
    "write_joint_score_sieve_potential",
]
