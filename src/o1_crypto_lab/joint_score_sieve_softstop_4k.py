"""Native-v2 joint-score adapter for one 4K soft-stop request.

CaDiCaL may report one conflict beyond a requested limit because the stop is
observed at conflict boundaries.  This adapter preserves the frozen native-v2
parser while making requested, unused, overshoot, and billed work explicit for
the bounded 4,096-conflict O1C-0062 call.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Mapping

from .joint_score_sieve import JointScoreSieveResult
from .joint_score_sieve_v3 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JOINT_SCORE_SIEVE_STATE_ENCODING,
    _RUN_NATIVE_CONTRACT,
    build_native_joint_score_sieve,
    joint_score_complete,
    joint_score_upper_bound,
    write_joint_score_sieve_potential,
)
from .o1_relational_search import O1RelationalSearchError


JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-soft-conflict-ledger-4k-v1"
)
JOINT_SCORE_SIEVE_4K_MAXIMUM_REQUESTED_CONFLICTS = 4_096
JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS = 4_097
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


def _requested_conflicts(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= JOINT_SCORE_SIEVE_4K_MAXIMUM_REQUESTED_CONFLICTS
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-4k requested conflict budget differs"
        )
    return value


def validate_soft_conflict_ledger_4k(
    stats: Mapping[str, object],
) -> dict[str, int]:
    """Validate the exact 4K soft-stop work and billing equations."""

    if set(stats) != _VALIDATED_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-4k soft conflict ledger fields differ"
        )
    normalized: dict[str, int] = {}
    for name in _VALIDATED_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-4k soft conflict ledger {name} differs"
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
        or not 0 <= overshoot <= JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or billed != solve
        or billed > JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS
        or billed > requested + JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-4k soft conflict ledger differs"
        )
    return normalized


def derive_soft_conflict_ledger_4k(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Derive the 4K persisted ledger from frozen native-v2 counters."""

    requested = _requested_conflicts(requested_conflicts)
    if set(stats) != _NATIVE_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-4k native conflict fields differ"
        )
    native: dict[str, int] = {}
    for name in _NATIVE_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve-4k native conflict {name} differs"
            )
        native[name] = value
    solve = native["solve_conflicts"]
    return validate_soft_conflict_ledger_4k(
        {
            **native,
            "requested_conflicts": requested,
            "unused_requested_conflicts": max(requested - solve, 0),
            "conflict_limit_overshoot": max(solve - requested, 0),
            "billed_conflicts": solve,
        }
    )


def run_joint_score_sieve_4k(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 30.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveResult:
    """Make one native-v2 call and attach its validated 4K work ledger."""

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
    ledger = derive_soft_conflict_ledger_4k(result.stats, requested_conflicts=requested)
    return replace(result, stats=ledger)


__all__ = [
    "JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_4K_MAXIMUM_REQUESTED_CONFLICTS",
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
    "derive_soft_conflict_ledger_4k",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve_4k",
    "validate_soft_conflict_ledger_4k",
    "write_joint_score_sieve_potential",
]
