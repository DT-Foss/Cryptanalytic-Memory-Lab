from __future__ import annotations

import hashlib
import json

from o1_crypto_lab.o1c49_online_pair_credit_screen import (
    _canonical_json_bytes,
    evaluate_absolute_gate,
)


def _row(width: int, conflicts: int, exact: bool = True) -> dict[str, object]:
    return {
        "residual_bits": width,
        "model_publicly_verified": exact,
        "model_truth_exact": exact,
        "model_matches_truth_fixed_prefix": exact,
        "stats": {"conflicts": conflicts},
    }


def test_full256_gain_is_highest_tier() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=True,
        static_full_exact=False,
        online_rows=[],
        static_rows=[],
    )
    assert gate["passed"] is True
    assert gate["selected_tier"] == "strict-full256"


def test_static_full256_blocks_lower_tiers() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=True,
        static_full_exact=True,
        online_rows=[_row(10, 1)],
        static_rows=[_row(8, 500)],
    )
    assert gate["passed"] is False
    assert gate["selected_tier"] == "static-full256-blocks-lower-tiers"


def test_strict_frontier_gain_passes() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=False,
        static_full_exact=False,
        online_rows=[_row(10, 400)],
        static_rows=[_row(9, 20)],
    )
    assert gate["passed"] is True
    assert gate["selected_tier"] == "strict-residual-frontier"


def test_strict_conflict_gain_at_tied_frontier_passes() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=False,
        static_full_exact=False,
        online_rows=[_row(9, 154)],
        static_rows=[_row(9, 155)],
    )
    assert gate["passed"] is True
    assert gate["online_conflicts_at_own_frontier"] == 154


def test_equal_or_worse_conflicts_fail() -> None:
    for conflicts in (155, 156):
        gate = evaluate_absolute_gate(
            online_full_exact=False,
            static_full_exact=False,
            online_rows=[_row(9, conflicts)],
            static_rows=[_row(9, 155)],
        )
        assert gate["passed"] is False
        assert gate["selected_tier"] == "no-strict-conflict-gain"


def test_regressed_frontier_fails_even_with_fewer_conflicts() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=False,
        static_full_exact=False,
        online_rows=[_row(8, 1)],
        static_rows=[_row(9, 500)],
    )
    assert gate["passed"] is False
    assert gate["selected_tier"] == "residual-frontier-regression"


def test_nonexact_rows_do_not_enter_frontier() -> None:
    gate = evaluate_absolute_gate(
        online_full_exact=False,
        static_full_exact=False,
        online_rows=[_row(10, 1, exact=False)],
        static_rows=[_row(9, 155)],
    )
    assert gate["online_maximum_exact_residual_width"] == 0
    assert gate["passed"] is False


def test_attacker_freeze_is_an_immutable_canonical_copy() -> None:
    live_row: dict[str, object] = {"status": "UNKNOWN"}
    freeze: dict[str, object] = {"online_full256_search": live_row}
    payload = _canonical_json_bytes(freeze)
    digest = hashlib.sha256(payload).hexdigest()
    frozen = json.loads(payload)
    live_row["model_truth_hamming"] = 127
    assert "model_truth_hamming" not in frozen["online_full256_search"]
    assert hashlib.sha256(_canonical_json_bytes(frozen)).hexdigest() == digest
