"""Lifecycle-safe native-v4 adapter with a bounded 4K conflict ledger.

Native v4 preserves native-v2 scoring and telemetry while repairing two API
boundaries: a valid pending threshold no-good survives solver backtracking,
and CaDiCaL is destroyed while its connected propagator remains alive.  This
adapter fail-closes the added lifecycle metadata and makes requested, unused,
overshoot, and billed conflict work explicit.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import FunctionType
from typing import Callable, Mapping, cast

from . import joint_score_sieve as _v1
from .joint_score_sieve import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
    JOINT_SCORE_SIEVE_STATE_ENCODING,
    JointScoreSieveResult,
    build_native_joint_score_sieve,
    joint_score_complete,
    joint_score_upper_bound,
    write_joint_score_sieve_potential,
)
from .o1_relational_search import O1RelationalSearchError

JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v4"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v2"
)
JOINT_SCORE_SIEVE_TEARDOWN_RULE = (
    "connected-solver-destroyed-before-external-propagator;no-explicit-disconnect"
)
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = (
    "retain-valid-pending-no-good;unwind-trail-and-refresh-factor-cache;defer-new-bound"
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-soft-conflict-ledger-4k-v2"
)
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = 4_096
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS = 4_097

_NATIVE_STATS_FIELDS = {
    "conflicts",
    "conflicts_before_solve",
    "solve_conflicts",
    "decisions",
    "propagations",
}
_VALIDATED_STATS_FIELDS = {
    *_NATIVE_STATS_FIELDS,
    "requested_conflicts",
    "unused_requested_conflicts",
    "conflict_limit_overshoot",
    "billed_conflicts",
}
_LIFECYCLE_FIELDS = {
    "implementation_parent_schema",
    "post_solve_state",
    "post_solve_state_name",
    "teardown_rule",
    "pending_backtrack_rule",
}
_TOP_LEVEL_FIELDS = set(_v1._TOP_LEVEL_FIELDS) | _LIFECYCLE_FIELDS
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


def _versioned_native_parser() -> Callable[..., JointScoreSieveResult]:
    """Reuse the proven v1 parser under the additive native-v4 contract."""

    parser_globals = dict(_v1.run_joint_score_sieve.__globals__)
    parser_globals.update(
        {
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA": JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "_TOP_LEVEL_FIELDS": _TOP_LEVEL_FIELDS,
            "_STATS_FIELDS": _NATIVE_STATS_FIELDS,
        }
    )
    parser = FunctionType(
        _v1.run_joint_score_sieve.__code__,
        parser_globals,
        name="_run_joint_score_sieve_v5_native_contract",
        argdefs=_v1.run_joint_score_sieve.__defaults__,
        closure=_v1.run_joint_score_sieve.__closure__,
    )
    parser.__kwdefaults__ = _v1.run_joint_score_sieve.__kwdefaults__
    return cast(Callable[..., JointScoreSieveResult], parser)


_RUN_NATIVE_CONTRACT = _versioned_native_parser()


def _requested_conflicts(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v5 requested conflict budget differs"
        )
    return value


def validate_native_lifecycle(
    payload: Mapping[str, object],
) -> dict[str, int | str]:
    """Validate state identity, implementation provenance, and teardown rules."""

    if not isinstance(payload, Mapping) or not _LIFECYCLE_FIELDS <= set(payload):
        raise O1RelationalSearchError("joint-score-sieve-v5 lifecycle fields differ")
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
        raise O1RelationalSearchError("joint-score-sieve-v5 lifecycle contract differs")
    return {name: cast(int | str, payload[name]) for name in sorted(_LIFECYCLE_FIELDS)}


def validate_soft_conflict_ledger(
    stats: Mapping[str, object],
) -> dict[str, int]:
    """Validate requested, observed, overshoot, and billed 4K work."""

    if set(stats) != _VALIDATED_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v5 soft conflict ledger fields differ"
        )
    normalized: dict[str, int] = {}
    for name in _VALIDATED_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-v5 soft conflict ledger {name} differs"
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
        or not 0 <= overshoot <= JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or billed != solve
        or billed > JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
        or billed > requested + JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v5 soft conflict ledger differs"
        )
    return normalized


def derive_soft_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Derive the persisted 4K ledger from native-v2-equivalent counters."""

    requested = _requested_conflicts(requested_conflicts)
    if set(stats) != _NATIVE_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v5 native conflict fields differ"
        )
    native: dict[str, int] = {}
    for name in _NATIVE_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-v5 native conflict {name} differs"
            )
        native[name] = value
    solve = native["solve_conflicts"]
    return validate_soft_conflict_ledger(
        {
            **native,
            "requested_conflicts": requested,
            "unused_requested_conflicts": max(requested - solve, 0),
            "conflict_limit_overshoot": max(solve - requested, 0),
            "billed_conflicts": solve,
        }
    )


def validate_incremental_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Compatibility alias that derives the explicit bounded work ledger."""

    return derive_soft_conflict_ledger(stats, requested_conflicts=requested_conflicts)


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
    """Run native v4 once and return only lifecycle- and budget-valid output."""

    requested = _requested_conflicts(conflict_limit)
    result = _RUN_NATIVE_CONTRACT(
        executable=executable,
        cnf_path=cnf_path,
        potential_path=potential_path,
        threshold=threshold,
        conflict_limit=requested,
        seed=seed,
        timeout_seconds=timeout_seconds,
        memory_limit_bytes=memory_limit_bytes,
    )
    validate_native_lifecycle(result.raw)
    ledger = derive_soft_conflict_ledger(result.stats, requested_conflicts=requested)
    return replace(result, stats=ledger)


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_TEARDOWN_RULE",
    "JointScoreSieveResult",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "write_joint_score_sieve_potential",
]
