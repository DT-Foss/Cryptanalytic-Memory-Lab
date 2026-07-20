from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

import o1_crypto_lab.o1c56_clause_role_credit_screen as run_module
from o1_crypto_lab.full256_broker import public_view_from_publication, verify_reveal
from o1_crypto_lab.clause_role_credit_search import (
    CLAUSE_ROLE_CREDIT_ACTION_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_CALLBACK_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_DECISION_RULE,
    CLAUSE_ROLE_CREDIT_OWNER_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_UPDATE_FORMULA,
    ClauseRoleCreditSearchResult,
)
from o1_crypto_lab.living_inverse import key_bits


ROOT = Path(__file__).resolve().parents[1]
CONFIG: dict[str, Any] = json.loads(
    (ROOT / run_module.DEFAULT_CONFIG).read_text(encoding="utf-8")
)


def _truth_and_public() -> tuple[bytes, object]:
    source = CONFIG["source"]
    publication = json.loads((ROOT / source["publication"]).read_text(encoding="utf-8"))
    reveal = verify_reveal(
        json.loads((ROOT / source["reveal"]).read_text(encoding="utf-8"))
    )
    truth = bytes.fromhex(reveal["commitment_preimage"]["key_hex"])
    return truth, public_view_from_publication(publication)


def _minimal_learned_contract(decision_sha256: str = "a" * 64) -> dict[str, Any]:
    return {
        "decision_rule": CLAUSE_ROLE_CREDIT_DECISION_RULE,
        "update_formula": CLAUSE_ROLE_CREDIT_UPDATE_FORMULA,
        "decision_scope": "explicit_ordered_key_pairs",
        "decision_variables_sha256": decision_sha256,
        "pair_count": 63,
        "group_width": 2,
        "external_implications": 0,
        "hard_clauses_added": 0,
        "clause_role_credit": {
            "clause_callbacks": 4,
            "clauses_with_membership": 3,
            "unmatched_clauses": 1,
            "matched_owner_members": 7,
            "distinct_action_cells": 3,
            "penalty_updates": 3,
            "penalty_units": 96,
            "multi_member_clauses": 2,
            "selected_deepest_members": 3,
            "selected_at_current_level": 2,
            "selected_below_current_level": 1,
            "discarded_matched_members": 4,
            "deepest_level_ties": 1,
            "callback_open": 0,
            "callback_bitmap_nonzero_members": 0,
            "same_sign_owner_literal_violations": 0,
        },
        "selection": {"credit_reordered_actions": 5},
        "state": {
            "bounded_action_state_bytes": CLAUSE_ROLE_CREDIT_ACTION_STATE_BYTES,
            "bounded_owner_state_bytes": CLAUSE_ROLE_CREDIT_OWNER_STATE_BYTES,
            "bounded_callback_state_bytes": CLAUSE_ROLE_CREDIT_CALLBACK_STATE_BYTES,
            "bounded_state_bytes": CLAUSE_ROLE_CREDIT_STATE_BYTES,
            "sha256": "c" * 64,
        },
    }


def test_identity_budget_and_one_call_ledger_are_frozen() -> None:
    assert run_module.ATTEMPT_ID == "O1C-0056"
    assert run_module.RESULT_SCHEMA == ("o1-256-clause-role-credit-screen-result-v1")
    assert run_module.RESULT_RELATIVE == Path(
        "research/O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.json"
    )
    assert run_module.RESIDUAL_WIDTH == 11
    assert run_module.CONFLICT_LIMIT == 512
    assert run_module.SEED == 0
    assert run_module.TIMEOUT_SECONDS == 120.0
    assert run_module.MAXIMUM_WALL_SECONDS == 130.0
    assert run_module.MAXIMUM_NATIVE_SOLVER_CALLS == 1
    assert run_module.MAXIMUM_REQUESTED_CONFLICTS == 512
    assert run_module.MAXIMUM_PEAK_RSS_BYTES == 512 * 1024 * 1024
    assert run_module.EXACT_RECOVERY_CLASSIFICATION == (
        "CLAUSE_ROLE_CREDIT_EXACT_W11_CLOSE"
    )
    assert run_module.MEMBERSHIP_NO_CLOSE_CLASSIFICATION == (
        "CLAUSE_ROLE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE"
    )
    assert run_module.NO_MEMBERSHIP_CLASSIFICATION == (
        "CLAUSE_ROLE_CREDIT_NO_MEMBERSHIP_NO_EXACT_W11_CLOSE"
    )
    assert CLAUSE_ROLE_CREDIT_DECISION_RULE == (
        "deepest_learned_clause_owner_pattern_credit"
    )
    assert CLAUSE_ROLE_CREDIT_STATE_BYTES == 2662
    ledger = run_module.call_ledger()
    assert ledger["native_solver_calls"] == 1
    assert ledger["requested_conflicts"] == 512
    assert ledger["full256_calls"] == 0
    assert ledger["rotation_calls"] == 0
    assert ledger["sweep_calls"] == 0
    assert ledger["fresh_target_calls"] == 0
    assert ledger["sibling_reads"] == 0
    assert ledger["sibling_writes"] == 0
    assert ledger["MPS_or_GPU"] is False
    executed = cast(list[dict[str, object]], ledger["executed_calls"])
    assert len(executed) == 1
    assert executed[0]["search_space"] == "post-reveal-w11"
    assert executed[0]["residual_bits"] == 11
    assert executed[0]["truth_fixed_bits"] == 245
    assert executed[0]["conflict_limit"] == 512
    assert executed[0]["seed"] == 0
    assert executed[0]["timeout_seconds"] == 120.0


def test_runner_contains_one_search_call_and_no_full256_promotion() -> None:
    tree = ast.parse((ROOT / run_module.RUNNER_SOURCE).read_text(encoding="utf-8"))
    search_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_clause_role_credit_search"
    ]
    assert len(search_calls) == 1
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not any(name.startswith("run_full256") for name in called_names)


def test_frozen_source_and_baseline_hashes_are_exact() -> None:
    source = CONFIG["source"]
    reveal = (ROOT / source["reveal"]).read_bytes()
    potential = (ROOT / source["primary_potential"]).read_bytes()
    baseline = (ROOT / run_module.O1C55_RESULT).read_bytes()
    assert hashlib.sha256(reveal).hexdigest() == run_module.EXPECTED_REVEAL_SHA256
    assert hashlib.sha256(potential).hexdigest() == (
        run_module.EXPECTED_PRIMARY_POTENTIAL_SHA256
    )
    assert hashlib.sha256(baseline).hexdigest() == run_module.O1C55_RESULT_SHA256
    assert run_module.CLAUSE_ROLE_CORE_COMMIT == "fc25a80"


def test_o1c55_boundary_requires_exact_matched_work() -> None:
    result = json.loads((ROOT / run_module.O1C55_RESULT).read_bytes())
    summary = run_module._validate_o1c55_boundary(
        result,
        public_view_sha256=run_module.EXPECTED_PUBLIC_VIEW_SHA256,
        truth_key_sha256=run_module.EXPECTED_TRUTH_KEY_SHA256,
    )
    assert summary["native_solver_calls"] == 1
    assert summary["conflicts"] == 512
    assert summary["decisions"] == 513
    assert summary["propagations"] == 12_083_477
    assert summary["credit_reordered_actions"] == 167
    assert summary["matched_owner_members"] == 2684
    assert summary["selected_matched_members"] == 2684
    assert summary["selected_credit_updates"] == 2057
    assert summary["discarded_matched_members"] == 0
    assert summary["multi_member_clauses"] is None
    assert summary["deepest_level_ties"] is None
    assert summary["state_sha256"] == (
        "295d27d5943267dcc0b839bea4ab5a125207824901347a04e730416b193a8ca7"
    )
    result["w11_search"]["stats"]["conflicts"] = 511
    with pytest.raises(run_module.O1C56ScreenError, match="matched-work"):
        run_module._validate_o1c55_boundary(
            result,
            public_view_sha256=run_module.EXPECTED_PUBLIC_VIEW_SHA256,
            truth_key_sha256=run_module.EXPECTED_TRUTH_KEY_SHA256,
        )


@pytest.mark.parametrize(
    ("exact", "penalties", "expected"),
    (
        (True, 0, run_module.EXACT_RECOVERY_CLASSIFICATION),
        (True, 9, run_module.EXACT_RECOVERY_CLASSIFICATION),
        (False, 1, run_module.MEMBERSHIP_NO_CLOSE_CLASSIFICATION),
        (False, 0, run_module.NO_MEMBERSHIP_CLASSIFICATION),
    ),
)
def test_classifications_are_distinct(
    exact: bool, penalties: int, expected: str
) -> None:
    assert (
        run_module.classify_result(exact_recovery=exact, penalty_updates=penalties)
        == expected
    )


def test_search_row_accepts_only_exact_public_sat_model() -> None:
    truth, public = _truth_and_public()
    residual = set(run_module.EXPECTED_W11_RESIDUAL_VARIABLES)
    spins = {index + 1: (1 if bit else -1) for index, bit in enumerate(key_bits(truth))}
    fixed = {
        variable: spin for variable, spin in spins.items() if variable not in residual
    }
    result = ClauseRoleCreditSearchResult(
        status=10,
        conflict_limit=512,
        key_model=truth,
        stats={"conflicts": 1, "decisions": 2, "propagations": 3},
        learned_clause=_minimal_learned_contract(),
        resources={"wall_microseconds": 1, "cpu_microseconds": 1, "peak_rss_bytes": 1},
        raw={},
    )
    row = run_module._search_row(
        result,
        public=public,
        truth_key=truth,
        residual=residual,
        fixed=fixed,
        prefix=run_module.EXPECTED_W11_PREFIX,
    )
    assert row["model_publicly_verified"] is True
    assert row["model_matches_truth_fixed_prefix"] is True
    assert row["model_truth_hamming"] == 0
    assert row["model_truth_exact"] is True

    wrong = ClauseRoleCreditSearchResult(
        status=10,
        conflict_limit=512,
        key_model=bytes(32),
        stats=result.stats,
        learned_clause=result.learned_clause,
        resources=result.resources,
        raw={},
    )
    with pytest.raises(run_module.O1C56ScreenError, match="public/prefix"):
        run_module._search_row(
            wrong,
            public=public,
            truth_key=truth,
            residual=residual,
            fixed=fixed,
            prefix=run_module.EXPECTED_W11_PREFIX,
        )


def test_native_contract_requires_exact_bounded_state_and_closed_callback() -> None:
    decision_sha = "b" * 64
    row = {"learned_clause": _minimal_learned_contract(decision_sha)}
    run_module._validate_native_contract(row, decision_sha256=decision_sha)
    row["learned_clause"]["state"]["bounded_state_bytes"] = 2661
    with pytest.raises(run_module.O1C56ScreenError, match="native contract"):
        run_module._validate_native_contract(row, decision_sha256=decision_sha)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("selected_deepest_members", 2),
        ("discarded_matched_members", 3),
        ("selected_at_current_level", 1),
        ("same_sign_owner_literal_violations", 1),
    ),
)
def test_native_contract_enforces_one_deepest_owner_ledger(
    field: str, value: int
) -> None:
    decision_sha = "d" * 64
    row = {"learned_clause": _minimal_learned_contract(decision_sha)}
    telemetry = row["learned_clause"]["clause_role_credit"]
    telemetry[field] = value
    with pytest.raises(run_module.O1C56ScreenError, match="native contract"):
        run_module._validate_native_contract(row, decision_sha256=decision_sha)


def test_negative_requires_full_cap_but_exact_sat_may_finish_early() -> None:
    negative = {
        "status": "UNKNOWN",
        "model_truth_exact": False,
        "stats": {"conflicts": 512},
    }
    assert run_module._validate_executed_work(negative) == 512
    with pytest.raises(run_module.O1C56ScreenError, match="frozen conflict budget"):
        run_module._validate_executed_work({**negative, "stats": {"conflicts": 511}})
    with pytest.raises(run_module.O1C56ScreenError, match="frozen conflict budget"):
        run_module._validate_executed_work(
            {**negative, "status": "UNSAT", "stats": {"conflicts": 3}}
        )
    exact = {
        "status": "SAT",
        "model_truth_exact": True,
        "model_publicly_verified": True,
        "model_matches_truth_fixed_prefix": True,
        "stats": {"conflicts": 7},
    }
    assert run_module._validate_executed_work(exact) == 7
    with pytest.raises(run_module.O1C56ScreenError, match="public recovery"):
        run_module._validate_executed_work(
            {**exact, "model_publicly_verified": False}
        )


def test_comparison_exposes_all_member_and_one_role_breadcrumbs() -> None:
    baseline_result = json.loads((ROOT / run_module.O1C55_RESULT).read_bytes())
    baseline = run_module._validate_o1c55_boundary(
        baseline_result,
        public_view_sha256=run_module.EXPECTED_PUBLIC_VIEW_SHA256,
        truth_key_sha256=run_module.EXPECTED_TRUTH_KEY_SHA256,
    )
    row = {
        "status": "UNKNOWN",
        "stats": {"conflicts": 512, "decisions": 500, "propagations": 1_000},
        "learned_clause": _minimal_learned_contract(),
    }
    comparison = cast(
        dict[str, Any],
        run_module._mechanism_comparison(
            baseline,
            row,
            classification=run_module.MEMBERSHIP_NO_CLOSE_CLASSIFICATION,
        ),
    )
    arms = comparison["arms"]
    all_member = arms["O1C-0055_all_member"]
    one_role = arms["O1C-0056_one_role"]
    assert all_member["selected_matched_members"] == 2684
    assert all_member["selected_credit_updates"] == 2057
    assert all_member["discarded_matched_members"] == 0
    assert one_role["matched_owner_members"] == 7
    assert one_role["selected_matched_members"] == 3
    assert one_role["selected_credit_updates"] == 3
    assert one_role["discarded_matched_members"] == 4
    assert one_role["multi_member_clauses"] == 2
    assert one_role["deepest_level_ties"] == 1
    assert comparison["delta_O1C56_minus_O1C55"]["decisions"] == -13
    assert comparison["state_hash_changed"] is True


def test_authoritative_output_refuses_wrong_or_existing_path(tmp_path: Path) -> None:
    with pytest.raises(run_module.O1C56ScreenError, match="result path"):
        run_module._authoritative_output(tmp_path, tmp_path / "wrong.json")
    authoritative = tmp_path / run_module.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    authoritative.write_text("occupied\n", encoding="utf-8")
    with pytest.raises(run_module.O1C56ScreenError, match="authoritative"):
        run_module._authoritative_output(tmp_path, authoritative)
