from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

import o1_crypto_lab.o1c52_pattern_credit_screen as run_module
from o1_crypto_lab.o1c52_pattern_credit_screen import (
    O1C52ScreenError,
    call_ledger,
    evaluate_gate,
    evaluate_promotion,
)


ROOT = Path(__file__).resolve().parents[1]
STATIC_FULL256 = {
    "primary": False,
    "key_rotated": False,
    "clause_rotated": False,
}


def test_o1c51_result_is_bound_to_the_frozen_digest() -> None:
    payload = (ROOT / run_module.O1C51_RESULT).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == run_module.O1C51_RESULT_SHA256
    assert run_module.O1C51_RESULT_SHA256 == (
        "aa8fec70d1f97d7a127791699c5340db28168389beeeab32c70d2b1b3121c058"
    )


def _exact_gate() -> dict[str, object]:
    return evaluate_gate(
        status="SAT",
        publicly_verified=True,
        truth_exact=True,
        matches_truth_prefix=True,
    )


def _promotion(
    *,
    w11_exact: dict[str, bool] | None = None,
    w11_conflicts: dict[str, int] | None = None,
    pattern_full256: dict[str, bool] | None = None,
    static_full256: dict[str, bool] | None = None,
) -> dict[str, object]:
    return evaluate_promotion(
        w11_exact_by_arm=w11_exact
        or {
            "pattern_primary": True,
            "static_primary": False,
            "pattern_key_rotated": False,
            "pattern_clause_rotated": False,
        },
        w11_conflicts_by_arm=w11_conflicts
        or {
            "pattern_primary": 100,
            "static_primary": 200,
            "pattern_key_rotated": 300,
            "pattern_clause_rotated": 400,
        },
        pattern_full256_exact_by_arm=pattern_full256 or dict(STATIC_FULL256),
        static_full256_exact_by_arm=static_full256 or dict(STATIC_FULL256),
    )


def test_failed_w11_ledger_executes_only_the_unconditional_first_call() -> None:
    ledger = call_ledger(False)
    assert ledger["native_solver_calls"] == 1
    assert ledger["requested_conflicts"] == 512
    assert ledger["executed_call_ordinals"] == [1]
    assert ledger["skipped_call_ordinals"] == [2, 3, 4, 5, 6, 7]
    assert ledger["executed_calls"] == [
        {
            "ordinal": 1,
            "stage": "qualification",
            "mechanism": "pattern",
            "arm": "primary",
            "search_space": "post-reveal-w11",
            "residual_bits": 11,
            "conflict_limit": 512,
            "seed": 0,
            "timeout_seconds": 120.0,
            "authorization": "unconditional-first-call",
        }
    ]
    assert ledger["parameter_tuning_calls"] == 0
    assert ledger["cap_tuning_calls"] == 0
    assert ledger["group_tuning_calls"] == 0


def test_exact_w11_ledger_has_the_frozen_seven_call_order() -> None:
    ledger = call_ledger(True)
    executed = cast(list[dict[str, object]], ledger["executed_calls"])
    planned = cast(list[dict[str, object]], ledger["planned_calls"])
    assert ledger["native_solver_calls"] == 7
    assert ledger["requested_conflicts"] == 7 * 512 == 3584
    assert ledger["executed_call_ordinals"] == list(range(1, 8))
    assert ledger["skipped_calls"] == []
    assert [
        (row["mechanism"], row["arm"], row["search_space"]) for row in executed
    ] == [
        ("pattern", "primary", "post-reveal-w11"),
        ("static", "primary", "post-reveal-w11"),
        ("pattern", "key_rotated", "post-reveal-w11"),
        ("pattern", "clause_rotated", "post-reveal-w11"),
        ("pattern", "primary", "full256"),
        ("pattern", "key_rotated", "full256"),
        ("pattern", "clause_rotated", "full256"),
    ]
    assert all(row["conflict_limit"] == 512 for row in planned)


def test_failed_w11_gate_closes_without_followup_outcomes() -> None:
    gate = evaluate_gate(
        status="UNKNOWN",
        publicly_verified=False,
        truth_exact=False,
        matches_truth_prefix=False,
    )
    assert gate["passed"] is False
    assert gate["selected_tier"] == "no-exact-pattern-primary-w11"
    assert gate["followup_calls_authorized"] is False
    assert gate["expected_native_solver_calls"] == 1
    assert gate["expected_requested_conflicts"] == 512
    assert gate["telemetry_cannot_satisfy_gate"] is True
    assert gate["wall_time_cannot_satisfy_gate"] is True


def test_w11_gate_requires_every_exactness_condition() -> None:
    cases = (
        ("UNKNOWN", True, True, True),
        ("SAT", False, True, True),
        ("SAT", True, False, True),
        ("SAT", True, True, False),
    )
    for status, public, truth, prefix in cases:
        gate = evaluate_gate(
            status=status,
            publicly_verified=public,
            truth_exact=truth,
            matches_truth_prefix=prefix,
        )
        assert gate["passed"] is False
        assert gate["followup_calls_authorized"] is False


def test_exact_primary_w11_passes_only_the_exact_gate_not_telemetry() -> None:
    gate = _exact_gate()
    assert gate["passed"] is True
    assert gate["selected_tier"] == "exact-pattern-primary-w11"
    assert gate["followup_calls_authorized"] is True
    assert gate["expected_native_solver_calls"] == 7
    assert gate["expected_requested_conflicts"] == 3584
    assert gate["exact_key_and_public_verification_required"] is True


def test_w11_specificity_uses_exactness_then_strict_conflicts() -> None:
    summary = _promotion()
    assert summary["primary_specific_w11"] is True
    assert summary["selected_tier"] == "primary-specific-w11"

    tied_exact = {
        "pattern_primary": True,
        "static_primary": True,
        "pattern_key_rotated": True,
        "pattern_clause_rotated": True,
    }
    summary = _promotion(w11_exact=tied_exact)
    assert summary["primary_specific_w11"] is True

    tied_work = {
        "pattern_primary": 100,
        "static_primary": 100,
        "pattern_key_rotated": 300,
        "pattern_clause_rotated": 400,
    }
    summary = _promotion(w11_exact=tied_exact, w11_conflicts=tied_work)
    assert summary["primary_specific_w11"] is False
    assert summary["selected_tier"] == "exact-w11-without-primary-specificity"
    assert _exact_gate()["passed"] is True


def test_strict_primary_full256_is_the_highest_classification() -> None:
    pattern_full = dict(STATIC_FULL256)
    pattern_full["primary"] = True
    summary = _promotion(pattern_full256=pattern_full)
    assert summary["selected_tier"] == "strict-pattern-primary-full256"
    assert summary["strict_primary_full256_recovery"] is True
    assert summary["any_pattern_full256_recovery"] is True
    assert run_module._classification(_exact_gate(), summary) == (
        "PUBLIC_INPUT_CONSUMED_PATTERN_ACTION_CREDIT_PRIMARY_STRICT_FULL256_RECOVERY"
    )


def test_every_outcome_classification_names_pattern_action_credit() -> None:
    failed = evaluate_gate(
        status="UNKNOWN",
        publicly_verified=False,
        truth_exact=False,
        matches_truth_prefix=False,
    )
    outcomes = [run_module._classification(failed, None)]

    pattern_primary = dict(STATIC_FULL256)
    pattern_primary["primary"] = True
    static_primary = dict(STATIC_FULL256)
    static_primary["primary"] = True
    outcomes.append(
        run_module._classification(
            _exact_gate(),
            _promotion(
                pattern_full256=pattern_primary,
                static_full256=static_primary,
            ),
        )
    )

    pattern_control = dict(STATIC_FULL256)
    pattern_control["key_rotated"] = True
    outcomes.append(
        run_module._classification(
            _exact_gate(), _promotion(pattern_full256=pattern_control)
        )
    )
    outcomes.append(run_module._classification(_exact_gate(), _promotion()))

    all_exact = {name: True for name in run_module.W11_ARMS}
    tied_conflicts = {name: 100 for name in run_module.W11_ARMS}
    outcomes.append(
        run_module._classification(
            _exact_gate(),
            _promotion(w11_exact=all_exact, w11_conflicts=tied_conflicts),
        )
    )
    assert all("PATTERN_ACTION_CREDIT" in outcome for outcome in outcomes)


def test_full256_control_or_static_recovery_blocks_strict_primary_tier() -> None:
    pattern_full = dict(STATIC_FULL256)
    pattern_full["primary"] = True
    pattern_full["key_rotated"] = True
    control_summary = _promotion(pattern_full256=pattern_full)
    assert control_summary["strict_primary_full256_recovery"] is False
    assert control_summary["selected_tier"] == (
        "pattern-primary-full256-without-strict-margin"
    )

    values = dict(STATIC_FULL256)
    values["key_rotated"] = True
    static_summary = _promotion(
        pattern_full256={
            "primary": True,
            "key_rotated": False,
            "clause_rotated": False,
        },
        static_full256=values,
    )
    assert static_summary["strict_primary_full256_recovery"] is False
    assert static_summary["selected_tier"] == (
        "pattern-primary-full256-without-strict-margin"
    )


def test_exact_row_requires_status_public_truth_and_w11_prefix() -> None:
    row: dict[str, object] = {
        "status": "SAT",
        "model_publicly_verified": True,
        "model_truth_exact": True,
        "model_matches_truth_fixed_prefix": True,
    }
    assert run_module._row_exact(row, residual=True) is True
    assert run_module._row_exact(row, residual=False) is True
    for field in ("model_publicly_verified", "model_truth_exact"):
        changed = dict(row)
        changed[field] = False
        assert run_module._row_exact(changed, residual=False) is False
    changed = dict(row)
    changed["status"] = "UNKNOWN"
    assert run_module._row_exact(changed, residual=False) is False
    changed = dict(row)
    changed["model_matches_truth_fixed_prefix"] = False
    assert run_module._row_exact(changed, residual=True) is False


def test_frozen_static_full256_baselines_are_reused_without_solver_calls() -> None:
    o1c48 = json.loads((ROOT / run_module.O1C48_RESULT).read_bytes())
    o1c49 = json.loads((ROOT / run_module.O1C49_RESULT).read_bytes())
    rows, exact = run_module._frozen_static_full256_rows(
        o1c48=o1c48,
        o1c49=o1c49,
        public_view_sha256=(
            "3f7841b5080200307564c9cb1956db6a48b2129afd21e85c3e76806735f464a0"
        ),
    )
    assert [row["name"] for row in rows] == [
        "primary",
        "key_rotated",
        "clause_rotated",
    ]
    assert exact == STATIC_FULL256
    assert o1c49["static_full256_baseline"] == rows[0]
    assert call_ledger(True)["native_solver_calls"] == 7


def test_gate_and_ledger_reject_integer_truth_values() -> None:
    with pytest.raises(O1C52ScreenError, match="differs"):
        call_ledger(1)  # type: ignore[arg-type]
    with pytest.raises(O1C52ScreenError, match="differs"):
        evaluate_gate(
            status="SAT",
            publicly_verified=1,  # type: ignore[arg-type]
            truth_exact=True,
            matches_truth_prefix=True,
        )
