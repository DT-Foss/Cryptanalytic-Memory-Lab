from __future__ import annotations

import pytest

from o1_crypto_lab.joint_score_sieve_softstop_4k import (
    JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
    derive_soft_conflict_ledger_4k,
    validate_soft_conflict_ledger_4k,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


def _native_stats(*, requested: int, overshoot: int, before: int = 0) -> dict[str, int]:
    solve = requested + overshoot
    return {
        "conflicts": before + solve,
        "conflicts_before_solve": before,
        "solve_conflicts": solve,
        "decisions": 20_000,
        "propagations": 2_000_000,
    }


def test_request_4096_bills_4097_with_one_soft_stop_overshoot() -> None:
    ledger = derive_soft_conflict_ledger_4k(
        _native_stats(requested=4_096, overshoot=1),
        requested_conflicts=4_096,
    )
    assert ledger["requested_conflicts"] == 4_096
    assert ledger["solve_conflicts"] == 4_097
    assert ledger["unused_requested_conflicts"] == 0
    assert ledger["conflict_limit_overshoot"] == 1
    assert ledger["billed_conflicts"] == JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS


def test_early_finish_preserves_unused_4k_budget() -> None:
    ledger = derive_soft_conflict_ledger_4k(
        {
            "conflicts": 11,
            "conflicts_before_solve": 4,
            "solve_conflicts": 7,
            "decisions": 100,
            "propagations": 1_000,
        },
        requested_conflicts=4_096,
    )
    assert ledger["unused_requested_conflicts"] == 4_089
    assert ledger["conflict_limit_overshoot"] == 0
    assert ledger["billed_conflicts"] == 7


def test_4k_soft_stop_rejects_overshoot_two() -> None:
    with pytest.raises(O1RelationalSearchError, match="soft conflict ledger"):
        derive_soft_conflict_ledger_4k(
            _native_stats(requested=4_096, overshoot=2),
            requested_conflicts=4_096,
        )


def test_4k_soft_stop_rejects_equation_or_field_mismatch() -> None:
    ledger = derive_soft_conflict_ledger_4k(
        _native_stats(requested=4_096, overshoot=1),
        requested_conflicts=4_096,
    )
    ledger["conflicts"] -= 1
    with pytest.raises(O1RelationalSearchError, match="soft conflict ledger"):
        validate_soft_conflict_ledger_4k(ledger)
    del ledger["billed_conflicts"]
    with pytest.raises(O1RelationalSearchError, match="fields"):
        validate_soft_conflict_ledger_4k(ledger)
