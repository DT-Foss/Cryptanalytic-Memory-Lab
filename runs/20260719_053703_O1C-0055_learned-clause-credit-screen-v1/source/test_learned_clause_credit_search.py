from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.learned_clause_credit_search as learned_clause_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.learned_clause_credit_search import (
    LEARNED_CLAUSE_CREDIT_ACTION_BYTES_PER_CELL,
    LEARNED_CLAUSE_CREDIT_ACTION_BYTES_PER_GROUP,
    LEARNED_CLAUSE_CREDIT_ACTION_CELLS_PER_GROUP,
    LEARNED_CLAUSE_CREDIT_ACTION_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_ACTION_STATE_ENCODING,
    LEARNED_CLAUSE_CREDIT_BYTES_PER_GROUP,
    LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_ENCODING,
    LEARNED_CLAUSE_CREDIT_COUNTER_MAX,
    LEARNED_CLAUSE_CREDIT_COUNTER_SEMANTICS,
    LEARNED_CLAUSE_CREDIT_DECISION_RULE,
    LEARNED_CLAUSE_CREDIT_GROUPS,
    LEARNED_CLAUSE_CREDIT_MAX,
    LEARNED_CLAUSE_CREDIT_MIN,
    LEARNED_CLAUSE_CREDIT_OWNER_BYTES_PER_GROUP,
    LEARNED_CLAUSE_CREDIT_OWNER_BYTES_PER_MEMBER,
    LEARNED_CLAUSE_CREDIT_OWNER_MEMBERS_PER_GROUP,
    LEARNED_CLAUSE_CREDIT_OWNER_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_OWNER_STATE_ENCODING,
    LEARNED_CLAUSE_CREDIT_RESULT_SCHEMA,
    LEARNED_CLAUSE_CREDIT_SELECTION_FORMULA,
    LEARNED_CLAUSE_CREDIT_STATE_BYTES,
    LEARNED_CLAUSE_CREDIT_STATE_ENCODING,
    LEARNED_CLAUSE_CREDIT_UPDATE_FORMULA,
    build_native_learned_clause_credit_search,
    learned_clause_credit_update,
    run_learned_clause_credit_search,
    write_learned_clause_credit_decision_variables,
    write_learned_clause_credit_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_learned_clause_credit_search.cpp"
STATIC_NATIVE_SOURCE = ROOT / "native/cadical_o1_pair_envelope_search.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _decisions() -> tuple[int, ...]:
    return (2, 1, *range(3, 127))


def _field(*, two_groups: bool = False) -> CriticalityPotentialField:
    factors = [CriticalityPotentialFactor((1, 2), (0.0, 10.0, 1.0, 2.0))]
    start = 3
    if two_groups:
        factors.append(CriticalityPotentialFactor((3, 4), (0.0, 9.0, 1.0, 2.0)))
        start = 5
    factors.extend(
        CriticalityPotentialFactor((variable,), (0.0, 0.0))
        for variable in range(start, 127)
    )
    return CriticalityPotentialField(
        offset=0.25,
        source_sha256="31" * 32,
        factors=tuple(factors),
    )


def _inputs(
    tmp_path: Path, *, two_groups: bool = False
) -> tuple[Path, Path, Path, str]:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 2 0\n", encoding="ascii")
    potential = tmp_path / "potential.pot"
    decisions = tmp_path / "decisions.txt"
    write_learned_clause_credit_potential(potential, _field(two_groups=two_groups))
    decision_sha = write_learned_clause_credit_decision_variables(
        decisions, _decisions()
    )
    return cnf, potential, decisions, decision_sha


def _groups() -> list[dict[str, object]]:
    decisions = _decisions()
    return [
        {
            "index": index,
            "first_variable": decisions[2 * index],
            "second_variable": decisions[2 * index + 1],
            "actions": [
                {
                    "mask": mask,
                    "credit": 0,
                    "visits": 0,
                    "conflict_hits": 0,
                    "backtrack_hits": 0,
                }
                for mask in range(4)
            ],
            "first_owner_level": 0,
            "first_owner_mask": 0,
            "second_owner_level": 0,
            "second_owner_mask": 0,
        }
        for index in range(LEARNED_CLAUSE_CREDIT_GROUPS)
    ]


def _fake_payload(cnf: Path, decision_sha: str) -> dict[str, object]:
    action_bytes = bytes(LEARNED_CLAUSE_CREDIT_ACTION_STATE_BYTES)
    owner_bytes = bytes(LEARNED_CLAUSE_CREDIT_OWNER_STATE_BYTES)
    callback_bytes = bytes(LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_BYTES)
    combined = action_bytes + owner_bytes + callback_bytes
    field = _field()
    return {
        "schema": LEARNED_CLAUSE_CREDIT_RESULT_SCHEMA,
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "cnf_sha256": hashlib.sha256(cnf.read_bytes()).hexdigest(),
        "stats": {"conflicts": 0, "decisions": 0, "propagations": 0},
        "learned_clause": {
            "factor_count": len(field.factors),
            "pair_count": LEARNED_CLAUSE_CREDIT_GROUPS,
            "group_width": 2,
            "decision_rule": LEARNED_CLAUSE_CREDIT_DECISION_RULE,
            "cold_decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "source_sha256": field.source_sha256,
            "decision_variables_sha256": decision_sha,
            "offset": field.offset,
            "observed_variables": len(field.observed_variables),
            "eligible_decision_variables": len(_decisions()),
            "external_implications": 0,
            "hard_clauses_added": 0,
            "update_formula": LEARNED_CLAUSE_CREDIT_UPDATE_FORMULA,
            "selection_formula": LEARNED_CLAUSE_CREDIT_SELECTION_FORMULA,
            "queue": {
                "requested_decisions": 0,
                "repeated_decisions": 0,
                "queued_decisions": 0,
                "same_sign_queue_skips": 0,
                "opposite_sign_queue_invalidations": 0,
                "assignment_notifications": 0,
                "backtracks": 0,
                "maximum_assigned_variables": 0,
                "maximum_decision_level": 0,
            },
            "selection": {
                "cold_group_selections": 0,
                "credit_modulated_group_selections": 0,
                "zero_gap_fallbacks": 0,
                "envelope_evaluations": 0,
                "first_group_index": None,
                "first_pattern_mask": None,
                "maximum_raw_gap": 0.0,
                "maximum_adjusted_gap": 0.0,
                "credit_reordered_actions": 0,
                "distinct_action_cells_selected": 0,
                "differentiated_groups": 0,
                "penalized_action_cells": 0,
                "trace_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "tickets": {
                "opened": 0,
                "closed": 0,
                "closed_on_advance": 0,
                "closed_on_backtrack": 0,
                "closed_on_invalidation": 0,
                "closed_on_solve_end": 0,
                "assignment_hits": 0,
                "maximum_open": 0,
                "current_open": 0,
            },
            "pending": {
                "marked": 0,
                "bound": 0,
                "first_owner_bindings": 0,
                "second_owner_bindings": 0,
                "owner_assignment_hits": 0,
                "maximum_open": 0,
                "current_open": 0,
            },
            "learned_clause_credit": {
                "clause_callbacks": 0,
                "empty_clauses": 0,
                "unit_clauses": 0,
                "large_clauses": 0,
                "streamed_literals": 0,
                "matched_owner_members": 0,
                "distinct_action_cells": 0,
                "duplicate_owner_member_literals": 0,
                "clauses_with_membership": 0,
                "unmatched_clauses": 0,
                "penalty_updates": 0,
                "penalty_units": 0,
                "same_sign_owner_literal_violations": 0,
                "owner_clear_callbacks": 0,
                "undone_owner_clears": 0,
                "callback_open": 0,
                "callback_bitmap_nonzero_members": 0,
                "trace_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "solver_counter_deltas": {
                "conflicts": 0,
                "decisions": 0,
                "propagations": 0,
            },
            "state": {
                "encoding": LEARNED_CLAUSE_CREDIT_STATE_ENCODING,
                "action_encoding": LEARNED_CLAUSE_CREDIT_ACTION_STATE_ENCODING,
                "owner_encoding": LEARNED_CLAUSE_CREDIT_OWNER_STATE_ENCODING,
                "callback_encoding": LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_ENCODING,
                "bytes_per_group": LEARNED_CLAUSE_CREDIT_BYTES_PER_GROUP,
                "action_bytes_per_cell": LEARNED_CLAUSE_CREDIT_ACTION_BYTES_PER_CELL,
                "action_cells_per_group": LEARNED_CLAUSE_CREDIT_ACTION_CELLS_PER_GROUP,
                "action_bytes_per_group": LEARNED_CLAUSE_CREDIT_ACTION_BYTES_PER_GROUP,
                "owner_bytes_per_member": LEARNED_CLAUSE_CREDIT_OWNER_BYTES_PER_MEMBER,
                "owner_members_per_group": LEARNED_CLAUSE_CREDIT_OWNER_MEMBERS_PER_GROUP,
                "owner_bytes_per_group": LEARNED_CLAUSE_CREDIT_OWNER_BYTES_PER_GROUP,
                "bounded_action_state_bytes": LEARNED_CLAUSE_CREDIT_ACTION_STATE_BYTES,
                "bounded_owner_state_bytes": LEARNED_CLAUSE_CREDIT_OWNER_STATE_BYTES,
                "bounded_callback_state_bytes": LEARNED_CLAUSE_CREDIT_CALLBACK_STATE_BYTES,
                "bounded_state_bytes": LEARNED_CLAUSE_CREDIT_STATE_BYTES,
                "sha256": hashlib.sha256(combined).hexdigest(),
                "action_sha256": hashlib.sha256(action_bytes).hexdigest(),
                "owner_sha256": hashlib.sha256(owner_bytes).hexdigest(),
                "callback_sha256": hashlib.sha256(callback_bytes).hexdigest(),
                "credit_min": LEARNED_CLAUSE_CREDIT_MIN,
                "credit_max": LEARNED_CLAUSE_CREDIT_MAX,
                "counter_max": LEARNED_CLAUSE_CREDIT_COUNTER_MAX,
                "owner_level_max": (1 << 32) - 1,
                "owner_mask_max": 3,
                "counter_semantics": LEARNED_CLAUSE_CREDIT_COUNTER_SEMANTICS,
                "live_owners": 0,
                "maximum_live_owners": 0,
                "saturated_credit_updates": 0,
                "saturated_counter_updates": 0,
                "groups": _groups(),
            },
        },
        "resources": {
            "wall_microseconds": 1,
            "cpu_microseconds": 1,
            "peak_rss_bytes": 1,
        },
    }


def test_reference_deduplicates_members_and_saturates_signed_credit() -> None:
    owners = ((3, 2), (4, 1))
    updated, remaining, undone, cells = learned_clause_credit_update(
        (0,) * 4,
        owners,
        matched_members=(0, 0),
    )
    assert updated == (0, 0, -32, 0)
    assert remaining == owners
    assert undone == 0
    assert cells == ((0, 2),)

    saturated, _, _, _ = learned_clause_credit_update(
        (0, LEARNED_CLAUSE_CREDIT_MIN + 1, 0, 0),
        ((2, 1), (0, 0)),
        matched_members=(0,),
    )
    assert saturated[1] == LEARNED_CLAUSE_CREDIT_MIN
    assert LEARNED_CLAUSE_CREDIT_MAX == 32767


def test_reference_same_mask_deduplicates_and_different_masks_split() -> None:
    owners = ((3, 3), (4, 3), (5, 1), (6, 2))
    updated, _, _, cells = learned_clause_credit_update(
        (0,) * 8,
        owners,
        matched_members=(0, 1, 1, 2, 3),
    )
    assert cells == ((0, 3), (1, 1), (1, 2))
    assert updated == (0, 0, 0, -32, 0, -32, -32, 0)


def test_reference_empty_unit_and_backtrack_have_exact_scope() -> None:
    credits = (0,) * 8
    owners = ((3, 2), (5, 1), (7, 3), (5, 0))
    unchanged, remaining, undone, cells = learned_clause_credit_update(
        credits,
        owners,
        new_level=5,
    )
    assert unchanged == credits
    assert remaining == ((3, 2), (5, 1), (0, 0), (5, 0))
    assert undone == 1
    assert cells == ()

    unit, _, _, unit_cells = learned_clause_credit_update(
        credits,
        owners,
        matched_members=(3,),
    )
    assert unit[4] == -32
    assert sum(unit) == -32
    assert unit_cells == ((1, 0),)

    with pytest.raises(O1RelationalSearchError, match="inactive owner"):
        learned_clause_credit_update(
            (0,) * 4,
            ((0, 0), (2, 1)),
            matched_members=(0,),
        )


def test_strict_wrapper_rejects_state_and_credit_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, decisions, decision_sha = _inputs(tmp_path)
    executable = tmp_path / "fake"
    executable.write_text("x", encoding="ascii")
    payload = _fake_payload(cnf, decision_sha)
    monkeypatch.setattr(
        learned_clause_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    result = run_learned_clause_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert result.learned_clause["state"]["bounded_state_bytes"] == 2662
    cases = (
        (("learned_clause", "state", "callback_sha256"), "42" * 32, "bounded state"),
        (("learned_clause", "state", "credit_min"), 0, "bounded state"),
        (
            ("learned_clause", "learned_clause_credit", "penalty_units"),
            32,
            "update ledger",
        ),
        (
            ("learned_clause", "learned_clause_credit", "callback_open"),
            1,
            "update ledger",
        ),
    )
    for path, invalid, message in cases:
        target: object = payload
        for key in path[:-1]:
            target = target[key]  # type: ignore[index]
        original = target[path[-1]]  # type: ignore[index]
        target[path[-1]] = invalid  # type: ignore[index]
        with pytest.raises(O1RelationalSearchError, match=message):
            run_learned_clause_credit_search(
                executable=executable,
                cnf_path=cnf,
                potential_path=potential,
                decision_variables_path=decisions,
                conflict_limit=32,
            )
        target[path[-1]] = original  # type: ignore[index]


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_cold_equivalence_zero_credit_and_replay(tmp_path: Path) -> None:
    cnf, potential, decisions, _ = _inputs(tmp_path)
    static_executable = tmp_path / "static"
    learned_executable = tmp_path / "learned"
    build_native_pair_envelope_search(
        source=STATIC_NATIVE_SOURCE, output=static_executable
    )
    build_native_learned_clause_credit_search(
        source=NATIVE_SOURCE, output=learned_executable
    )
    static = run_pair_envelope_search(
        executable=static_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    first = run_learned_clause_credit_search(
        executable=learned_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    replay = run_learned_clause_credit_search(
        executable=learned_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    telemetry = first.learned_clause["learned_clause_credit"]
    assert first.status_name == static.status_name == "SAT"
    assert first.key_model == static.key_model
    assert first.learned_clause["selection"]["first_group_index"] == 0
    assert first.learned_clause["selection"]["first_pattern_mask"] == 2
    assert first.learned_clause["state"]["bounded_state_bytes"] == 2662
    assert telemetry["penalty_updates"] == 0
    assert telemetry["callback_open"] == 0
    assert telemetry["callback_bitmap_nonzero_members"] == 0
    assert all(
        action["credit"] == 0
        for group in first.learned_clause["state"]["groups"]
        for action in group["actions"]
    )
    assert first.stats == replay.stats
    assert first.learned_clause == replay.learned_clause


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_learned_clause_penalizes_only_matching_owner_cells(
    tmp_path: Path,
) -> None:
    _, potential, decisions, _ = _inputs(tmp_path, two_groups=True)
    cnf = tmp_path / "learned.cnf"
    cnf.write_text(
        "p cnf 256 4\n1 3 0\n1 -3 0\n-1 3 0\n-1 -3 0\n",
        encoding="ascii",
    )
    executable = tmp_path / "learned"
    build_native_learned_clause_credit_search(source=NATIVE_SOURCE, output=executable)
    result = run_learned_clause_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    replay = run_learned_clause_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    telemetry = result.learned_clause["learned_clause_credit"]
    groups = result.learned_clause["state"]["groups"]
    assert result.status_name == "UNSAT"
    assert telemetry["clause_callbacks"] >= 1
    assert telemetry["empty_clauses"] == 1
    assert telemetry["unit_clauses"] == 1
    assert telemetry["large_clauses"] == 0
    assert telemetry["streamed_literals"] == 1
    assert telemetry["matched_owner_members"] == 1
    assert telemetry["distinct_action_cells"] == 1
    assert telemetry["penalty_updates"] == 1
    assert telemetry["penalty_units"] == 32
    assert telemetry["same_sign_owner_literal_violations"] == 0
    assert telemetry["owner_clear_callbacks"] >= 1
    assert result.learned_clause["selection"]["penalized_action_cells"] == 1
    for group in groups:
        for action in group["actions"]:
            expected_credit = -32 if (group["index"], action["mask"]) == (0, 2) else 0
            assert action["credit"] == expected_credit
    assert result.stats == replay.stats
    assert result.learned_clause == replay.learned_clause
