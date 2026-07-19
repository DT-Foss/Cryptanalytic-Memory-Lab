from __future__ import annotations

from o1_crypto_lab.o1c50_delayed_pair_credit_screen import evaluate_gate


def test_strict_exact_w10_gain_passes() -> None:
    gate = evaluate_gate(
        status="SAT",
        publicly_verified=True,
        truth_exact=True,
        matches_truth_prefix=True,
        conflicts=309,
    )
    assert gate["passed"] is True
    assert gate["selected_tier"] == "strict-w10-conflict-gain"
    assert gate["strict_conflict_delta"] == 1


def test_equal_static_work_fails() -> None:
    gate = evaluate_gate(
        status="SAT",
        publicly_verified=True,
        truth_exact=True,
        matches_truth_prefix=True,
        conflicts=310,
    )
    assert gate["passed"] is False
    assert gate["selected_tier"] == "equal-w10-conflicts"


def test_worse_static_work_fails() -> None:
    gate = evaluate_gate(
        status="SAT",
        publicly_verified=True,
        truth_exact=True,
        matches_truth_prefix=True,
        conflicts=311,
    )
    assert gate["passed"] is False
    assert gate["selected_tier"] == "worse-w10-conflicts"


def test_nonexact_or_nonpublic_row_fails() -> None:
    for kwargs in (
        {"status": "UNKNOWN", "publicly_verified": False, "truth_exact": False},
        {"status": "SAT", "publicly_verified": False, "truth_exact": True},
        {"status": "SAT", "publicly_verified": True, "truth_exact": False},
    ):
        gate = evaluate_gate(
            matches_truth_prefix=True,
            conflicts=1,
            **kwargs,
        )
        assert gate["passed"] is False
        assert gate["selected_tier"] == "no-exact-w10-recovery"


def test_prefix_violation_fails() -> None:
    gate = evaluate_gate(
        status="SAT",
        publicly_verified=True,
        truth_exact=True,
        matches_truth_prefix=False,
        conflicts=1,
    )
    assert gate["passed"] is False
