"""Exact width-6 grouped bounds for the lifecycle-safe native sieve.

This module is the Python contract for native v5.  It consumes the frozen
APPLE-VIEW-0009 grouping bytes, validates native incremental group maxima and
their persistent cache, preserves native-v4 lifecycle rules, and retains the
cause-preserving v6 failure boundary.  Complete-model scoring remains on the
original potential factors; grouping is used only for admissible partial-score
upper bounds.
"""

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
from collections import deque
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Mapping, cast

from . import joint_score_sieve as _v1
from . import joint_score_sieve_v6 as _v6
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import (
    COMPATIBILITY_GROUPING_BOUND_RULE,
    COMPATIBILITY_GROUPING_MAGIC,
    COMPATIBILITY_GROUPING_MEMORY_RULE,
    COMPATIBILITY_GROUPING_RULE,
    COMPATIBILITY_GROUPING_SCHEMA,
    JointScoreCompatibilityGroup,
    JointScoreCompatibilityGrouping,
    JointScoreGroupingError,
    build_compatibility_grouping as _build_compatibility_grouping,
    outward_binary64_sum,
)
from .joint_score_sieve_v5 import (
    JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE,
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS,
    JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
    JOINT_SCORE_SIEVE_TEARDOWN_RULE,
    JointScoreSieveResult as _BaseJointScoreSieveResult,
    build_native_joint_score_sieve,
    derive_soft_conflict_ledger,
    joint_score_complete,
    validate_incremental_conflict_ledger,
    validate_soft_conflict_ledger,
    write_joint_score_sieve_potential,
)
from .o1_relational_search import O1RelationalSearchError


JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v5"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v3"
)
JOINT_SCORE_SIEVE_STATE_SCHEMA = "o1-256-cadical-joint-score-sieve-grouped-state-v2"
JOINT_SCORE_SIEVE_STATE_ENCODING = (
    "observed-ascending-i8-sign;trail-u32le-level,u32le-count,"
    "u32le-local-index,u32le-level;pending-u32le-length,u32le-cursor,"
    "u8-ready,u8-blocking,i32le-literals;derived-group-cache-group-order-"
    "f64le-max"
)
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = (
    "retain-valid-pending-no-good;unwind-trail-and-refresh-group-cache;defer-new-bound"
)
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = 6
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = COMPATIBILITY_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_MAGIC = COMPATIBILITY_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_RULE = COMPATIBILITY_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = COMPATIBILITY_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_BOUND_RULE = COMPATIBILITY_GROUPING_BOUND_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v6.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = (
    "o1-256-joint-score-sieve-bounded-rss-series-v1"
)
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = 256

APPLE_VIEW_0009_POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)
APPLE_VIEW_0009_GROUPING_SHA256 = (
    "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
)

JointScoreSieveExecutionError = _v6.JointScoreSieveExecutionError
JointScoreSieveResult = _BaseJointScoreSieveResult


@dataclass(frozen=True)
class JointScoreSieveV7Result(JointScoreSieveResult):
    """A native result plus explicitly typed adapter-side memory evidence."""

    adapter_memory: Mapping[str, object]


_TOP_LEVEL_FIELDS = {
    "schema",
    "implementation_parent_schema",
    "cadical_version",
    "variables",
    "conflict_limit",
    "seed",
    "threshold",
    "status",
    "post_solve_state",
    "post_solve_state_name",
    "teardown_rule",
    "pending_backtrack_rule",
    "key_model_hex",
    "cnf_sha256",
    "potential_sha256",
    "stats",
    "sieve",
    "resources",
}
_LIFECYCLE_FIELDS = {
    "implementation_parent_schema",
    "post_solve_state",
    "post_solve_state_name",
    "teardown_rule",
    "pending_backtrack_rule",
}
_STATE_NAMES = {
    1: "INITIALIZING",
    2: "CONFIGURING",
    4: "STEADY",
    8: "ADDING",
    16: "SOLVING",
    32: "SATISFIED",
    64: "UNSATISFIED",
    128: "DELETING",
    256: "INCONCLUSIVE",
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
    "higher_order_group_count",
    "maximum_group_size",
    "grouping_width_cap",
    "grouping_serialized_bytes",
    "group_table_rows",
    "group_incident_edges",
    "grouping_rule",
    "grouping_sha256",
    "grouping_input_sha256",
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
    "higher_order_group_count",
    "maximum_group_size",
    "grouping_width_cap",
    "grouping_serialized_bytes",
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


@lru_cache(maxsize=8)
def build_compatibility_grouping(
    field: CriticalityPotentialField,
) -> JointScoreCompatibilityGrouping:
    """Build the frozen APPLE-VIEW-0009 width-6 grouping."""

    return _build_compatibility_grouping(
        field, width_cap=JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
    )


def _validated_grouping(
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping | None,
) -> JointScoreCompatibilityGrouping:
    if not isinstance(field, CriticalityPotentialField):
        raise O1RelationalSearchError("joint-score-sieve grouped potential differs")
    try:
        expected = build_compatibility_grouping(field)
    except JointScoreGroupingError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve width-6 grouping differs"
        ) from exc
    if grouping is not None and grouping != expected:
        raise O1RelationalSearchError("joint-score-sieve width-6 grouping differs")
    return expected


def validate_joint_score_sieve_grouping(
    field: CriticalityPotentialField, payload: bytes
) -> JointScoreCompatibilityGrouping:
    """Validate frozen grouping bytes against one canonical potential."""

    grouping = _validated_grouping(field, None)
    if not isinstance(payload, bytes) or payload != grouping.serialized:
        raise O1RelationalSearchError("joint-score-sieve grouping input differs")
    return grouping


def write_joint_score_sieve_grouping(
    path: str | Path,
    field: CriticalityPotentialField,
    *,
    grouping: JointScoreCompatibilityGrouping | None = None,
) -> str:
    """Write the exact deterministic width-6 membership artifact."""

    validated = _validated_grouping(field, grouping)
    try:
        Path(path).write_bytes(validated.serialized)
    except OSError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve grouping write failed"
        ) from exc
    return validated.sha256


def _normalize_partial_assignment(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> dict[int, int]:
    if not isinstance(assignments, Mapping):
        raise O1RelationalSearchError(
            "joint-score-sieve grouped partial assignment differs"
        )
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
                "joint-score-sieve grouped partial assignment differs"
            )
        normalized[variable] = spin
    return normalized


def _group_maximum(
    group: JointScoreCompatibilityGroup, assignments: Mapping[int, int]
) -> float:
    best = -math.inf
    for row, energy in enumerate(group.energies):
        if all(
            variable not in assignments
            or bool(row & (1 << local)) == (assignments[variable] > 0)
            for local, variable in enumerate(group.variables)
        ):
            best = max(best, energy)
    if best == -math.inf:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped maximum has no consistent row"
        )
    return best


def grouped_joint_score_cache(
    field: CriticalityPotentialField,
    assignments: Mapping[int, int],
    *,
    grouping: JointScoreCompatibilityGrouping | None = None,
) -> bytes:
    """Serialize exact-safe current group maxima in canonical group order."""

    validated = _validated_grouping(field, grouping)
    normalized = _normalize_partial_assignment(field, assignments)
    return b"".join(
        struct.pack("<d", _group_maximum(group, normalized))
        for group in validated.groups
    )


def joint_score_upper_bound(
    field: CriticalityPotentialField,
    assignments: Mapping[int, int],
    *,
    grouping: JointScoreCompatibilityGrouping | None = None,
) -> float:
    """Return the exact-lattice, round-once-upward width-6 bound."""

    validated = _validated_grouping(field, grouping)
    normalized = _normalize_partial_assignment(field, assignments)
    maxima = tuple(_group_maximum(group, normalized) for group in validated.groups)
    if any(maximum == math.inf for maximum in maxima):
        return math.inf
    try:
        return outward_binary64_sum((field.offset, *maxima))
    except JointScoreGroupingError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve grouped upper bound differs"
        ) from exc


def grouped_upper_bound_prunes(upper: float, threshold: float) -> bool:
    """Preserve APPLE-VIEW-0008's strict-only threshold rule."""

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


class IncrementalJointScoreGroupMaxima:
    """Reference state machine for native incident-group cache updates."""

    def __init__(
        self,
        field: CriticalityPotentialField,
        *,
        grouping: JointScoreCompatibilityGrouping | None = None,
    ) -> None:
        self.field = field
        self.grouping = _validated_grouping(field, grouping)
        incidents: dict[int, list[int]] = {
            variable: [] for variable in field.observed_variables
        }
        for group_index, group in enumerate(self.grouping.groups):
            for variable in group.variables:
                incidents[variable].append(group_index)
        if any(not indices for indices in incidents.values()):
            raise O1RelationalSearchError(
                "joint-score-sieve grouped incident index differs"
            )
        self._incident_groups = {
            variable: tuple(indices) for variable, indices in incidents.items()
        }
        self._assignments: dict[int, int] = {}
        self._maxima = [
            _group_maximum(group, self._assignments) for group in self.grouping.groups
        ]
        self.group_maximum_evaluations = self.grouping.group_count
        self.group_row_evaluations = self.grouping.table_rows
        self.incremental_group_recomputations = 0
        self.maximum_incremental_groups_recomputed = 0

    @property
    def assignments(self) -> dict[int, int]:
        return dict(self._assignments)

    @property
    def maxima(self) -> tuple[float, ...]:
        return tuple(self._maxima)

    @property
    def cache_bytes(self) -> bytes:
        return b"".join(struct.pack("<d", value) for value in self._maxima)

    @property
    def upper_bound(self) -> float:
        if any(maximum == math.inf for maximum in self._maxima):
            return math.inf
        try:
            return outward_binary64_sum((self.field.offset, *self._maxima))
        except JointScoreGroupingError as exc:
            raise O1RelationalSearchError(
                "joint-score-sieve incremental upper bound differs"
            ) from exc

    def update(self, changes: Mapping[int, int | None]) -> tuple[int, ...]:
        """Apply assignment/backtrack changes and refresh incident groups only."""

        if not isinstance(changes, Mapping):
            raise O1RelationalSearchError(
                "joint-score-sieve incremental assignment differs"
            )
        observed = set(self.field.observed_variables)
        candidate = dict(self._assignments)
        changed: list[int] = []
        for variable, spin in changes.items():
            if (
                isinstance(variable, bool)
                or not isinstance(variable, int)
                or variable not in observed
                or (
                    spin is not None
                    and (
                        isinstance(spin, bool)
                        or not isinstance(spin, int)
                        or spin not in (-1, 1)
                    )
                )
            ):
                raise O1RelationalSearchError(
                    "joint-score-sieve incremental assignment differs"
                )
            old = candidate.get(variable)
            if spin is None:
                candidate.pop(variable, None)
            else:
                candidate[variable] = spin
            if old != spin and not (old is None and spin is None):
                changed.append(variable)
        if not changed:
            return ()
        affected = tuple(
            sorted(
                {
                    group_index
                    for variable in changed
                    for group_index in self._incident_groups[variable]
                }
            )
        )
        maxima = list(self._maxima)
        row_evaluations = 0
        for group_index in affected:
            group = self.grouping.groups[group_index]
            maxima[group_index] = _group_maximum(group, candidate)
            row_evaluations += len(group.energies)
        self._assignments = candidate
        self._maxima = maxima
        self.incremental_group_recomputations += len(affected)
        self.maximum_incremental_groups_recomputed = max(
            self.maximum_incremental_groups_recomputed, len(affected)
        )
        self.group_maximum_evaluations += len(affected)
        self.group_row_evaluations += row_evaluations
        return affected


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate grouped-v5 state identity and lifecycle provenance."""

    if not isinstance(payload, Mapping) or not _LIFECYCLE_FIELDS <= set(payload):
        raise O1RelationalSearchError("joint-score-sieve-v7 lifecycle fields differ")
    status = payload.get("status")
    state = payload["post_solve_state"]
    state_name = payload["post_solve_state_name"]
    if (
        isinstance(status, bool)
        or status not in (0, 10, 20)
        or isinstance(state, bool)
        or not isinstance(state, int)
        or state not in _STATE_NAMES
        or state_name != _STATE_NAMES[state]
        or payload["implementation_parent_schema"]
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload["teardown_rule"] != JOINT_SCORE_SIEVE_TEARDOWN_RULE
        or payload["pending_backtrack_rule"] != JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
        or (status == 10 and state != 32)
        or (status == 20 and state != 64)
        or (status == 0 and state != 256)
    ):
        raise O1RelationalSearchError("joint-score-sieve-v7 lifecycle contract differs")
    return {name: cast(int | str, payload[name]) for name in sorted(_LIFECYCLE_FIELDS)}


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
    expected_cache = grouped_joint_score_cache(field, spins, grouping=grouping)
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
            "joint-score-sieve-v7 requested conflict budget differs"
        )
    return value


class _JointScoreSieveMemoryLimitExceeded(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        memory_samples: tuple[dict[str, int | float], ...],
        command: list[str],
        stdout: str,
        stderr: str,
        returncode: int | None,
    ) -> None:
        super().__init__(message)
        self.memory_samples = memory_samples
        self.cmd = list(command)
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@dataclass(frozen=True)
class _NativeExecution:
    completed: subprocess.CompletedProcess[str]
    memory_samples: tuple[dict[str, int | float], ...] = ()


def _bounded_memory_samples(
    tail: deque[dict[str, int | float]],
    peak: dict[str, int | float] | None,
) -> tuple[dict[str, int | float], ...]:
    rows = list(tail)
    if peak is not None and peak not in rows:
        rows.append(peak)
    rows.sort(key=lambda row: float(row["elapsed_seconds"]))
    if len(rows) > JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES:
        rows = rows[-JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES:]
    return tuple(dict(row) for row in rows)


def _run_with_darwin_memory_watchdog(
    command: list[str],
    *,
    timeout_seconds: float,
    memory_limit_bytes: int,
) -> _NativeExecution:
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
    started = time.monotonic()
    deadline = started + timeout_seconds
    samples: deque[dict[str, int | float]] = deque(
        maxlen=JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES - 1
    )
    peak: dict[str, int | float] | None = None

    def kill_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def record_sample() -> int | None:
        nonlocal peak
        try:
            footprint = _v1._darwin_physical_footprint_bytes(process.pid)
        except O1RelationalSearchError as exc:
            if process.poll() is None:
                setattr(exc, "memory_samples", _bounded_memory_samples(samples, peak))
                raise
            if not samples:
                samples.append(
                    {
                        "elapsed_seconds": max(time.monotonic() - started, 0.0),
                        "rss_bytes": 0,
                    }
                )
            return None
        row: dict[str, int | float] = {
            "elapsed_seconds": max(time.monotonic() - started, 0.0),
            "rss_bytes": footprint,
        }
        samples.append(row)
        if peak is None or footprint > cast(int, peak["rss_bytes"]):
            peak = row
        return footprint

    def timeout_error(stdout: str, stderr: str) -> subprocess.TimeoutExpired:
        error = subprocess.TimeoutExpired(
            command,
            timeout_seconds,
            output=stdout,
            stderr=stderr,
        )
        setattr(error, "memory_samples", _bounded_memory_samples(samples, peak))
        return error

    def raise_memory_limit() -> None:
        kill_process_group()
        stdout, stderr = process.communicate()
        bounded = _bounded_memory_samples(samples, peak)
        maximum_observed = max(cast(int, sample["rss_bytes"]) for sample in bounded)
        raise _JointScoreSieveMemoryLimitExceeded(
            "Darwin physical-footprint watchdog reached its guarded ceiling "
            f"({maximum_observed} >= {kill_threshold} < {memory_limit_bytes})",
            memory_samples=bounded,
            command=command,
            stdout=stdout,
            stderr=stderr,
            returncode=process.returncode,
        )

    try:
        initial = record_sample()
        if initial is not None and initial >= kill_threshold:
            raise_memory_limit()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                kill_process_group()
                stdout, stderr = process.communicate()
                raise timeout_error(stdout, stderr)
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
            footprint = record_sample()
            if footprint is None:
                stdout, stderr = process.communicate()
                break
            if footprint >= kill_threshold:
                raise_memory_limit()
            if time.monotonic() >= deadline:
                kill_process_group()
                stdout, stderr = process.communicate()
                raise timeout_error(stdout, stderr)
    except Exception:
        if process.poll() is None:
            kill_process_group()
            process.communicate()
        raise
    if not samples:
        samples.append(
            {
                "elapsed_seconds": max(time.monotonic() - started, 0.0),
                "rss_bytes": 0,
            }
        )
    return _NativeExecution(
        completed=subprocess.CompletedProcess(
            command, cast(int, process.returncode), stdout, stderr
        ),
        memory_samples=_bounded_memory_samples(samples, peak),
    )


def _memory_series_from_chain(exc: BaseException) -> list[dict[str, int | float]]:
    for node in _v6._exception_chain(exc):
        raw = getattr(node, "memory_samples", None)
        if not isinstance(raw, (list, tuple)):
            continue
        normalized: list[dict[str, int | float]] = []
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            elapsed = item.get("elapsed_seconds")
            rss = item.get("rss_bytes")
            if (
                isinstance(elapsed, bool)
                or not isinstance(elapsed, (int, float))
                or not math.isfinite(elapsed)
                or elapsed < 0.0
                or isinstance(rss, bool)
                or not isinstance(rss, int)
                or rss < 0
            ):
                continue
            normalized.append({"elapsed_seconds": float(elapsed), "rss_bytes": rss})
        normalized.sort(key=lambda row: cast(float, row["elapsed_seconds"]))
        return normalized[-JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES:]
    return []


def _memory_series_telemetry(series: list[dict[str, int | float]]) -> dict[str, object]:
    if series:
        rss_values = [cast(int, row["rss_bytes"]) for row in series]
        peak: int | None = max(rss_values)
        last: int | None = rss_values[-1]
        last_elapsed: float | None = cast(float, series[-1]["elapsed_seconds"])
    else:
        peak = None
        last = None
        last_elapsed = None
    return {
        "memory_series_schema": JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA,
        "memory_sample_limit": JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES,
        "memory_sample_count": len(series),
        "memory_samples": [dict(row) for row in series],
        "memory_peak_bytes": peak,
        "memory_last_bytes": last,
        "memory_last_elapsed_seconds": last_elapsed,
    }


def _failure_telemetry(
    exc: BaseException,
    *,
    elapsed_seconds: float,
    timeout_seconds: float,
    memory_limit_bytes: int | None,
) -> dict[str, object]:
    telemetry = _v6._failure_telemetry(
        exc,
        elapsed_seconds=elapsed_seconds,
        timeout_seconds=timeout_seconds,
        memory_limit_bytes=memory_limit_bytes,
    )
    if memory_limit_bytes is not None:
        guard = min(
            JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
            max(0, memory_limit_bytes // 8),
        )
        telemetry["darwin_watchdog_guard_bytes"] = guard
        telemetry["darwin_watchdog_kill_threshold_bytes"] = memory_limit_bytes - guard
    series = _memory_series_from_chain(exc)
    if series:
        telemetry.update(_memory_series_telemetry(series))
    else:
        legacy = telemetry["memory_samples"]
        observed = [
            cast(int, row["observed_bytes"])
            for row in cast(list[dict[str, object]], legacy)
            if isinstance(row.get("observed_bytes"), int)
            and not isinstance(row.get("observed_bytes"), bool)
        ]
        peak = max(observed) if observed else None
        last = observed[-1] if observed else None
        last_elapsed = elapsed_seconds if observed else None
        telemetry.update(
            {
                "memory_series_schema": JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA,
                "memory_sample_limit": JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES,
                "memory_sample_count": len(cast(list[object], legacy)),
                "memory_peak_bytes": peak,
                "memory_last_bytes": last,
                "memory_last_elapsed_seconds": last_elapsed,
            }
        )
    return telemetry


def _execute_native(
    command: list[str],
    *,
    timeout_seconds: float,
    memory_limit_bytes: int | None,
) -> _NativeExecution:
    def apply_memory_limit() -> None:
        if memory_limit_bytes is not None:
            resource.setrlimit(
                resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes)
            )

    if memory_limit_bytes is not None and sys.platform == "darwin":
        return _run_with_darwin_memory_watchdog(
            command,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
    return _NativeExecution(
        completed=subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            preexec_fn=apply_memory_limit if memory_limit_bytes is not None else None,
        )
    )


def _parse_native_payload(
    payload: object,
    *,
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
) -> JointScoreSieveV7Result:
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v7 result fields differ")
    validate_native_lifecycle(payload)
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
        or reported_limit != requested_conflicts
        or isinstance(reported_seed, bool)
        or not isinstance(reported_seed, int)
        or reported_seed != seed
        or reported_threshold != threshold
        or isinstance(status, bool)
        or status not in (0, 10, 20)
        or payload["cnf_sha256"] != cnf_sha256
        or payload["potential_sha256"] != potential_sha256
    ):
        raise O1RelationalSearchError("joint-score-sieve-v7 result contract differs")
    raw_model = payload["key_model_hex"]
    if status == 10:
        if not isinstance(raw_model, str) or len(raw_model) != 64:
            raise O1RelationalSearchError("joint-score-sieve-v7 SAT result lacks key")
        try:
            key_model = bytes.fromhex(raw_model)
        except ValueError as exc:
            raise O1RelationalSearchError(
                "joint-score-sieve-v7 key encoding differs"
            ) from exc
    elif raw_model is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v7 non-SAT result contains key"
        )
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
            "joint-score-sieve-v7 child exceeded its memory limit"
        )
    adapter_memory = _memory_series_telemetry([dict(row) for row in memory_samples])
    sieve = _v1._mapping(payload["sieve"], "sieve")
    if set(sieve) != _SIEVE_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v7 grouped telemetry fields differ"
        )
    integers: dict[str, int] = {}
    for name in _SIEVE_INTEGER_FIELDS:
        value = sieve[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-v7 grouped telemetry.{name} differs"
            )
        integers[name] = value
    observed = field.observed_variables
    observed_sha = hashlib.sha256(_v1._observed_bytes(field)).hexdigest()
    root_upper = joint_score_upper_bound(field, {}, grouping=grouping)
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
    maximum_group_size = max(len(group.factor_indices) for group in grouping.groups)
    if (
        integers["factor_count"] != len(field.factors)
        or integers["group_count"] != grouping.group_count
        or integers["pair_group_count"] != grouping.pair_group_count
        or integers["singleton_group_count"] != grouping.singleton_group_count
        or integers["higher_order_group_count"] != grouping.higher_order_group_count
        or integers["singleton_group_count"]
        + integers["pair_group_count"]
        + integers["higher_order_group_count"]
        != integers["group_count"]
        or integers["maximum_group_size"] != maximum_group_size
        or integers["grouping_width_cap"] != JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
        or integers["grouping_serialized_bytes"] != len(grouping.serialized)
        or integers["group_table_rows"] != grouping.table_rows
        or integers["group_incident_edges"] != grouping.variable_group_incidences
        or sieve["grouping_rule"] != JOINT_SCORE_SIEVE_GROUPING_RULE
        or sieve["grouping_sha256"] != grouping.sha256
        or sieve["grouping_input_sha256"] != grouping_sha256
        or grouping_sha256 != grouping.sha256
        or integers["observed_variables"] != len(observed)
        or sieve["observed_variables_sha256"] != observed_sha
        or sieve["source_sha256"] != field.source_sha256
        or offset != field.offset
        or sieve_threshold != threshold
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
        > grouping.table_rows
        + (1 << JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP) * recomputations
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
            "joint-score-sieve-v7 grouped telemetry contract differs"
        )
    minimum_complete = sieve["minimum_complete_score"]
    maximum_complete = sieve["maximum_complete_score"]
    if integers["complete_model_score_checks"]:
        low = _v1._finite_float(minimum_complete, "sieve.minimum_complete_score")
        high = _v1._finite_float(maximum_complete, "sieve.maximum_complete_score")
        if low > high:
            raise O1RelationalSearchError(
                "joint-score-sieve-v7 complete score range differs"
            )
    elif minimum_complete is not None or maximum_complete is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v7 absent complete score differs"
        )
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
            "joint-score-sieve-v7 live assignment ledger differs"
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
            "joint-score-sieve-v7 maximum live-state ledger differs"
        )
    normalized_sieve = dict(sieve)
    normalized_sieve["state"] = decoded_state
    return JointScoreSieveV7Result(
        status=cast(int, status),
        conflict_limit=requested_conflicts,
        threshold=threshold,
        key_model=key_model,
        stats=native_stats,
        sieve=normalized_sieve,
        resources=resources,
        raw=dict(payload),
        adapter_memory=adapter_memory,
    )


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV7Result:
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
            "joint-score-sieve-v7 threshold, seed, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v1._read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = _v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = _v1._read_input(
        grouping_path, "grouping"
    )
    field = _v1._potential(potential_bytes)
    grouping = validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve grouping potential identity differs"
        )
    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential_file),
        "--grouping",
        str(grouping_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        str(seed),
    ]
    execution_error: Exception | None = None
    execution: _NativeExecution | None
    try:
        execution = _execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        execution = None
    try:
        _v1._verify_stable_input(
            executable, executable_file, executable_bytes, field="executable"
        )
        _v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
        _v1._verify_stable_input(
            potential_path, potential_file, potential_bytes, field="potential"
        )
        _v1._verify_stable_input(
            grouping_path, grouping_file, grouping_bytes, field="grouping"
        )
    except Exception as exc:
        if execution is not None:
            setattr(exc, "memory_samples", execution.memory_samples)
        raise
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve execution failed")
    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        setattr(failure, "memory_samples", execution.memory_samples)
        raise O1RelationalSearchError(
            f"joint-score-sieve execution failed: {detail}"
        ) from failure
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        setattr(exc, "memory_samples", execution.memory_samples)
        raise O1RelationalSearchError(
            "joint-score-sieve-v7 result JSON is invalid"
        ) from exc
    try:
        native_result = _parse_native_payload(
            payload,
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
    except Exception as exc:
        setattr(exc, "memory_samples", execution.memory_samples)
        raise
    return replace(
        native_result,
        stats=derive_soft_conflict_ledger(
            native_result.stats, requested_conflicts=requested
        ),
    )


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV7Result:
    """Run native v5 with lifecycle, grouping, and cause validation."""

    started = time.perf_counter()
    try:
        return _run_joint_score_sieve_native_contract(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
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
        telemetry = _failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        raise JointScoreSieveExecutionError(
            str(exc), failure_telemetry=telemetry
        ) from exc


__all__ = [
    "APPLE_VIEW_0009_GROUPING_SHA256",
    "APPLE_VIEW_0009_POTENTIAL_SHA256",
    "COMPATIBILITY_GROUPING_BOUND_RULE",
    "COMPATIBILITY_GROUPING_MAGIC",
    "COMPATIBILITY_GROUPING_MEMORY_RULE",
    "COMPATIBILITY_GROUPING_RULE",
    "COMPATIBILITY_GROUPING_SCHEMA",
    "IncrementalJointScoreGroupMaxima",
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
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA",
    "JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_STATE_SCHEMA",
    "JOINT_SCORE_SIEVE_TEARDOWN_RULE",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreSieveExecutionError",
    "JointScoreSieveResult",
    "JointScoreSieveV7Result",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
