"""Versioned joint-score sieve adapter with an incremental conflict ledger."""

from __future__ import annotations

from pathlib import Path
from types import FunctionType
from typing import Mapping, cast

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


JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v2"
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = 512
_STATS_FIELDS = {
    "conflicts",
    "conflicts_before_solve",
    "solve_conflicts",
    "decisions",
    "propagations",
}


def _versioned_v1_parser() -> object:
    """Clone the proven v1 execution/parser code with isolated v2 constants."""

    parser_globals = dict(_v1.run_joint_score_sieve.__globals__)
    parser_globals.update(
        {
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA": JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "_STATS_FIELDS": _STATS_FIELDS,
        }
    )
    parser = FunctionType(
        _v1.run_joint_score_sieve.__code__,
        parser_globals,
        name="_run_joint_score_sieve_v2_contract",
        argdefs=_v1.run_joint_score_sieve.__defaults__,
        closure=_v1.run_joint_score_sieve.__closure__,
    )
    parser.__kwdefaults__ = _v1.run_joint_score_sieve.__kwdefaults__
    return parser


_RUN_V2_CONTRACT = _versioned_v1_parser()


def validate_incremental_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Validate CaDiCaL's cumulative counter against its per-solve budget."""

    if (
        isinstance(requested_conflicts, bool)
        or not isinstance(requested_conflicts, int)
        or not 1 <= requested_conflicts <= JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve incremental conflict budget differs"
        )
    if set(stats) != _STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve incremental conflict fields differ"
        )
    normalized: dict[str, int] = {}
    for name in _STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve incremental conflict {name} differs"
            )
        normalized[name] = value
    cumulative = normalized["conflicts"]
    before = normalized["conflicts_before_solve"]
    solve = normalized["solve_conflicts"]
    if (
        before > cumulative
        or solve != cumulative - before
        or solve > requested_conflicts
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve incremental conflict ledger differs"
        )
    return normalized


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
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or not 1 <= conflict_limit <= JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve incremental conflict budget differs"
        )
    parser = cast(object, _RUN_V2_CONTRACT)
    result = cast(
        JointScoreSieveResult,
        parser(  # type: ignore[operator]
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        ),
    )
    validate_incremental_conflict_ledger(
        result.stats, requested_conflicts=conflict_limit
    )
    return result


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JointScoreSieveResult",
    "build_native_joint_score_sieve",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "write_joint_score_sieve_potential",
]
