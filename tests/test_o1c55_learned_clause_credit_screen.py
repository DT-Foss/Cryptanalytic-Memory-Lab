from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

import o1_crypto_lab.o1c55_learned_clause_credit_screen as run_module
from o1_crypto_lab.full256_broker import public_view_from_publication, verify_reveal
from o1_crypto_lab.learned_clause_credit_search import (
    LEARNED_CLAUSE_CREDIT_ACTION_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_DECISION_RULE,
    LEARNED_CLAUSE_CREDIT_OWNER_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_STATE_BYTES,
    LearnedClauseCreditSearchResult,
)
from o1_crypto_lab.living_inverse import key_bits


ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / run_module.DEFAULT_CONFIG).read_text(encoding="utf-8"))


def _truth_and_public() -> tuple[bytes, object]:
    source = CONFIG["source"]
    publication = json.loads((ROOT / source["publication"]).read_text(encoding="utf-8"))
    reveal = verify_reveal(
        json.loads((ROOT / source["reveal"]).read_text(encoding="utf-8"))
    )
    truth = bytes.fromhex(reveal["commitment_preimage"]["key_hex"])
    return truth, public_view_from_publication(publication)


def _minimal_learned_contract(decision_sha256: str = "a" * 64) -> dict[str, object]:
    return {
        "decision_rule": LEARNED_CLAUSE_CREDIT_DECISION_RULE,
        "decision_scope": "explicit_ordered_key_pairs",
        "decision_variables_sha256": decision_sha256,
        "pair_count": 63,
        "group_width": 2,
        "external_implications": 0,
        "hard_clauses_added": 0,
        "learned_clause_credit": {
            "callback_open": 0,
            "callback_bitmap_nonzero_members": 0,
            "same_sign_owner_literal_violations": 0,
        },
        "state": {
            "bounded_action_state_bytes": LEARNED_CLAUSE_CREDIT_ACTION_STATE_BYTES,
            "bounded_owner_state_bytes": LEARNED_CLAUSE_CREDIT_OWNER_STATE_BYTES,
            "bounded_callback_state_bytes": LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_BYTES,
            "bounded_state_bytes": LEARNED_CLAUSE_CREDIT_STATE_BYTES,
        },
    }


def test_identity_budget_and_one_call_ledger_are_frozen() -> None:
    assert run_module.ATTEMPT_ID == "O1C-0055"
    assert run_module.RESULT_SCHEMA == ("o1-256-learned-clause-credit-screen-result-v1")
    assert run_module.RESULT_RELATIVE == Path(
        "research/O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.json"
    )
    assert run_module.RESIDUAL_WIDTH == 11
    assert run_module.CONFLICT_LIMIT == 512
    assert run_module.MAXIMUM_NATIVE_SOLVER_CALLS == 1
    assert run_module.MAXIMUM_REQUESTED_CONFLICTS == 512
    assert run_module.MAXIMUM_PEAK_RSS_BYTES == 512 * 1024 * 1024
    ledger = run_module.call_ledger()
    assert ledger["native_solver_calls"] == 1
    assert ledger["requested_conflicts"] == 512
    assert ledger["full256_calls"] == 0
    assert ledger["rotation_calls"] == 0
    assert len(ledger["executed_calls"]) == 1
    assert ledger["executed_calls"][0]["search_space"] == "post-reveal-w11"


def test_runner_contains_one_search_call_and_no_full256_promotion() -> None:
    tree = ast.parse((ROOT / run_module.RUNNER_SOURCE).read_text(encoding="utf-8"))
    search_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "run_learned_clause_credit_search"
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
    baseline = (ROOT / run_module.O1C53_RESULT).read_bytes()
    assert hashlib.sha256(reveal).hexdigest() == run_module.EXPECTED_REVEAL_SHA256
    assert hashlib.sha256(potential).hexdigest() == (
        run_module.EXPECTED_PRIMARY_POTENTIAL_SHA256
    )
    assert hashlib.sha256(baseline).hexdigest() == run_module.O1C53_RESULT_SHA256


def test_o1c53_boundary_requires_exact_matched_work() -> None:
    result = json.loads((ROOT / run_module.O1C53_RESULT).read_bytes())
    summary = run_module._validate_o1c53_boundary(
        result,
        public_view_sha256=run_module.EXPECTED_PUBLIC_VIEW_SHA256,
        truth_key_sha256=run_module.EXPECTED_TRUTH_KEY_SHA256,
    )
    assert summary["native_solver_calls"] == 1
    assert summary["conflicts"] == 512
    result["w11_search"]["survivor_primary"]["stats"]["conflicts"] = 511
    with pytest.raises(run_module.O1C55ScreenError, match="matched-work"):
        run_module._validate_o1c53_boundary(
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
    result = LearnedClauseCreditSearchResult(
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

    wrong = LearnedClauseCreditSearchResult(
        status=10,
        conflict_limit=512,
        key_model=bytes(32),
        stats=result.stats,
        learned_clause=result.learned_clause,
        resources=result.resources,
        raw={},
    )
    with pytest.raises(run_module.O1C55ScreenError, match="public/prefix"):
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
    with pytest.raises(run_module.O1C55ScreenError, match="native contract"):
        run_module._validate_native_contract(row, decision_sha256=decision_sha)


def test_negative_requires_full_cap_but_exact_sat_may_finish_early() -> None:
    negative = {
        "status": "UNKNOWN",
        "model_truth_exact": False,
        "stats": {"conflicts": 512},
    }
    assert run_module._validate_executed_work(negative) == 512
    with pytest.raises(run_module.O1C55ScreenError, match="frozen conflict budget"):
        run_module._validate_executed_work({**negative, "stats": {"conflicts": 511}})
    with pytest.raises(run_module.O1C55ScreenError, match="frozen conflict budget"):
        run_module._validate_executed_work(
            {**negative, "status": "UNSAT", "stats": {"conflicts": 3}}
        )
    exact = {
        "status": "SAT",
        "model_truth_exact": True,
        "stats": {"conflicts": 7},
    }
    assert run_module._validate_executed_work(exact) == 7


def test_authoritative_output_refuses_wrong_or_existing_path(tmp_path: Path) -> None:
    with pytest.raises(run_module.O1C55ScreenError, match="result path"):
        run_module._authoritative_output(tmp_path, tmp_path / "wrong.json")
    authoritative = tmp_path / run_module.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    authoritative.write_text("occupied\n", encoding="utf-8")
    with pytest.raises(run_module.O1C55ScreenError, match="authoritative"):
        run_module._authoritative_output(tmp_path, authoritative)
