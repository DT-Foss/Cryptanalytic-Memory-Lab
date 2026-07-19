"""Joint-score sieve adapter for CaDiCaL's one-conflict soft-stop overshoot."""

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
from .joint_score_sieve_v2 import JOINT_SCORE_SIEVE_RESULT_SCHEMA
from .o1_relational_search import O1RelationalSearchError


JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-soft-conflict-ledger-v3"
)
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = 512
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS = 513
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


def _versioned_native_parser() -> Callable[..., JointScoreSieveResult]:
    """Reuse the frozen v1 parser with the immutable native-v2 JSON contract."""

    parser_globals = dict(_v1.run_joint_score_sieve.__globals__)
    parser_globals.update(
        {
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA": JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "_STATS_FIELDS": _NATIVE_STATS_FIELDS,
        }
    )
    parser = FunctionType(
        _v1.run_joint_score_sieve.__code__,
        parser_globals,
        name="_run_joint_score_sieve_v3_native_contract",
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
            "joint-score-sieve requested conflict budget differs"
        )
    return value


def validate_soft_conflict_ledger(stats: Mapping[str, object]) -> dict[str, int]:
    """Validate an explicit requested, observed, overshoot, and billing ledger."""

    if set(stats) != _VALIDATED_STATS_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve soft conflict ledger fields differ"
        )
    normalized: dict[str, int] = {}
    for name in _VALIDATED_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve soft conflict ledger {name} differs"
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
        raise O1RelationalSearchError("joint-score-sieve soft conflict ledger differs")
    return normalized


def derive_soft_conflict_ledger(
    stats: Mapping[str, object], *, requested_conflicts: int
) -> dict[str, int]:
    """Derive and then validate the persisted ledger from native-v2 counters."""

    requested = _requested_conflicts(requested_conflicts)
    if set(stats) != _NATIVE_STATS_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve native conflict fields differ")
    native: dict[str, int] = {}
    for name in _NATIVE_STATS_FIELDS:
        value = stats[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"joint-score-sieve native conflict {name} differs"
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
    ledger = derive_soft_conflict_ledger(result.stats, requested_conflicts=requested)
    return replace(result, stats=ledger)


__all__ = [
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JointScoreSieveResult",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_soft_conflict_ledger",
    "write_joint_score_sieve_potential",
]
