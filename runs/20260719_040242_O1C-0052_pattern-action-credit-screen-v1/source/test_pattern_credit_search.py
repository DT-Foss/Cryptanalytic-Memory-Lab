from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.pattern_credit_search as pattern_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
)
from o1_crypto_lab.pattern_credit_search import (
    PATTERN_CREDIT_ACTION_BYTES_PER_CELL,
    PATTERN_CREDIT_ACTION_BYTES_PER_GROUP,
    PATTERN_CREDIT_ACTION_CELLS_PER_GROUP,
    PATTERN_CREDIT_ACTION_STATE_BYTES,
    PATTERN_CREDIT_ACTION_STATE_ENCODING,
    PATTERN_CREDIT_BYTES_PER_GROUP,
    PATTERN_CREDIT_COUNTER_MAX,
    PATTERN_CREDIT_COUNTER_SEMANTICS,
    PATTERN_CREDIT_DECISION_RULE,
    PATTERN_CREDIT_GROUPS,
    PATTERN_CREDIT_MAX,
    PATTERN_CREDIT_MIN,
    PATTERN_CREDIT_OWNER_BYTES_PER_GROUP,
    PATTERN_CREDIT_OWNER_BYTES_PER_MEMBER,
    PATTERN_CREDIT_OWNER_MEMBERS_PER_GROUP,
    PATTERN_CREDIT_OWNER_STATE_BYTES,
    PATTERN_CREDIT_OWNER_STATE_ENCODING,
    PATTERN_CREDIT_RESULT_SCHEMA,
    PATTERN_CREDIT_SELECTION_FORMULA,
    PATTERN_CREDIT_STATE_BYTES,
    PATTERN_CREDIT_STATE_ENCODING,
    PATTERN_CREDIT_UPDATE_FORMULA,
    build_native_pattern_credit_search,
    pattern_action_credit_update,
    pattern_owner_weight,
    run_pattern_credit_search,
    write_pattern_credit_decision_variables,
    write_pattern_credit_potential,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_pattern_credit_search.cpp"
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


def _field(*, tiny_gap: bool = False) -> CriticalityPotentialField:
    energies = (0.0, 0.05, 0.04, 0.03) if tiny_gap else (0.0, 10.0, 1.0, 2.0)
    factors = [CriticalityPotentialFactor((1, 2), energies)]
    factors.extend(
        CriticalityPotentialFactor((variable,), (0.0, 0.0))
        for variable in range(3, 127)
    )
    return CriticalityPotentialField(
        offset=0.25,
        source_sha256="31" * 32,
        factors=tuple(factors),
    )


def _inputs(tmp_path: Path, *, tiny_gap: bool = False) -> tuple[Path, Path, Path, str]:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 2 0\n", encoding="ascii")
    potential = tmp_path / "potential.pot"
    decisions = tmp_path / "decisions.txt"
    write_pattern_credit_potential(potential, _field(tiny_gap=tiny_gap))
    decision_sha = write_pattern_credit_decision_variables(decisions, _decisions())
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
        for index in range(PATTERN_CREDIT_GROUPS)
    ]


def _fake_payload(cnf: Path, decision_sha: str) -> dict[str, object]:
    action_bytes = bytes(PATTERN_CREDIT_ACTION_STATE_BYTES)
    owner_bytes = bytes(PATTERN_CREDIT_OWNER_STATE_BYTES)
    combined = action_bytes + owner_bytes
    zero_queue = {
        "requested_decisions": 0,
        "repeated_decisions": 0,
        "queued_decisions": 0,
        "same_sign_queue_skips": 0,
        "opposite_sign_queue_invalidations": 0,
        "assignment_notifications": 0,
        "backtracks": 0,
        "maximum_assigned_variables": 0,
        "maximum_decision_level": 0,
    }
    return {
        "schema": PATTERN_CREDIT_RESULT_SCHEMA,
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "cnf_sha256": hashlib.sha256(cnf.read_bytes()).hexdigest(),
        "stats": {"conflicts": 0, "decisions": 0, "propagations": 0},
        "pattern": {
            "factor_count": len(_field().factors),
            "pair_count": 63,
            "group_width": 2,
            "decision_rule": PATTERN_CREDIT_DECISION_RULE,
            "cold_decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "source_sha256": _field().source_sha256,
            "decision_variables_sha256": decision_sha,
            "offset": _field().offset,
            "observed_variables": len(_field().observed_variables),
            "eligible_decision_variables": 126,
            "external_implications": 0,
            "hard_clauses_added": 0,
            "update_formula": PATTERN_CREDIT_UPDATE_FORMULA,
            "selection_formula": PATTERN_CREDIT_SELECTION_FORMULA,
            "queue": zero_queue,
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
            "backtrack_credit": {
                "callbacks": 0,
                "conflict_callbacks": 0,
                "nonconflict_callbacks": 0,
                "eligible_undo_groups": 0,
                "eligible_undo_action_cells": 0,
                "eligible_undo_members": 0,
                "conflict_undo_members": 0,
                "nonconflict_undo_members": 0,
                "weighted_undo_units": 0,
                "conflict_weighted_undo_units": 0,
                "nonconflict_weighted_undo_units": 0,
                "conflict_penalty_units": 0,
                "nonconflict_penalty_units": 0,
                "credit_updates": 0,
                "assignment_credit_units": 0,
                "propagation_credit_units": 0,
            },
            "solver_counter_deltas": {
                "conflicts": 0,
                "decisions": 0,
                "propagations": 0,
            },
            "state": {
                "encoding": PATTERN_CREDIT_STATE_ENCODING,
                "action_encoding": PATTERN_CREDIT_ACTION_STATE_ENCODING,
                "owner_encoding": PATTERN_CREDIT_OWNER_STATE_ENCODING,
                "bytes_per_group": PATTERN_CREDIT_BYTES_PER_GROUP,
                "action_bytes_per_cell": PATTERN_CREDIT_ACTION_BYTES_PER_CELL,
                "action_cells_per_group": PATTERN_CREDIT_ACTION_CELLS_PER_GROUP,
                "action_bytes_per_group": PATTERN_CREDIT_ACTION_BYTES_PER_GROUP,
                "owner_bytes_per_member": PATTERN_CREDIT_OWNER_BYTES_PER_MEMBER,
                "owner_members_per_group": PATTERN_CREDIT_OWNER_MEMBERS_PER_GROUP,
                "owner_bytes_per_group": PATTERN_CREDIT_OWNER_BYTES_PER_GROUP,
                "bounded_action_state_bytes": PATTERN_CREDIT_ACTION_STATE_BYTES,
                "bounded_owner_state_bytes": PATTERN_CREDIT_OWNER_STATE_BYTES,
                "bounded_state_bytes": PATTERN_CREDIT_STATE_BYTES,
                "sha256": hashlib.sha256(combined).hexdigest(),
                "action_sha256": hashlib.sha256(action_bytes).hexdigest(),
                "owner_sha256": hashlib.sha256(owner_bytes).hexdigest(),
                "credit_min": PATTERN_CREDIT_MIN,
                "credit_max": PATTERN_CREDIT_MAX,
                "counter_max": PATTERN_CREDIT_COUNTER_MAX,
                "owner_level_max": (1 << 32) - 1,
                "owner_mask_max": 3,
                "counter_semantics": PATTERN_CREDIT_COUNTER_SEMANTICS,
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


def test_reference_exact_mask_update_and_saturation() -> None:
    assert [
        pattern_owner_weight(current_level=10, owner_level=10 - depth)
        for depth in range(6)
    ] == [32, 16, 8, 4, 2, 2]
    updated = pattern_action_credit_update(
        (0, 0, PATTERN_CREDIT_MIN + 1, 0),
        ((10, 2), (7, 1)),
        current_level=10,
        new_level=8,
        conflict_since_previous_backtrack=True,
    )
    assert updated == (
        (0, 0, PATTERN_CREDIT_MIN, 0),
        ((0, 0), (7, 1)),
        1,
        (0, 0, 64, 0),
    )


def test_strict_wrapper_rejects_state_pending_and_penalty_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, decisions, decision_sha = _inputs(tmp_path)
    executable = tmp_path / "fake"
    executable.write_text("x", encoding="ascii")
    payload = _fake_payload(cnf, decision_sha)

    monkeypatch.setattr(
        pattern_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    result = run_pattern_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert result.pattern["state"]["bounded_state_bytes"] == 2646
    cases = (
        (("pattern", "state", "owner_sha256"), "42" * 32, "bounded state"),
        (("pattern", "state", "bounded_state_bytes"), 1134, "bounded state"),
        (("pattern", "pending", "marked"), 1, "telemetry ledger"),
        (
            ("pattern", "backtrack_credit", "conflict_penalty_units"),
            1,
            "backtrack-credit ledger",
        ),
    )
    for path, invalid, message in cases:
        target: object = payload
        for key in path[:-1]:
            target = target[key]  # type: ignore[index]
        original = target[path[-1]]  # type: ignore[index]
        target[path[-1]] = invalid  # type: ignore[index]
        with pytest.raises(O1RelationalSearchError, match=message):
            run_pattern_credit_search(
                executable=executable,
                cnf_path=cnf,
                potential_path=potential,
                decision_variables_path=decisions,
                conflict_limit=32,
            )
        target[path[-1]] = original  # type: ignore[index]


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_cold_equivalence_and_replay(tmp_path: Path) -> None:
    cnf, potential, decisions, _ = _inputs(tmp_path)
    static_executable = tmp_path / "static"
    pattern_executable = tmp_path / "pattern"
    build_native_pair_envelope_search(
        source=STATIC_NATIVE_SOURCE, output=static_executable
    )
    build_native_pattern_credit_search(source=NATIVE_SOURCE, output=pattern_executable)
    static = run_pair_envelope_search(
        executable=static_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    first = run_pattern_credit_search(
        executable=pattern_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    replay = run_pattern_credit_search(
        executable=pattern_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert first.status_name == static.status_name == "SAT"
    assert first.key_model == static.key_model
    assert first.pattern["selection"]["first_group_index"] == 0
    assert first.pattern["selection"]["first_pattern_mask"] == 2
    assert first.pattern["state"]["bounded_action_state_bytes"] == 2016
    assert first.pattern["state"]["bounded_owner_state_bytes"] == 630
    assert first.pattern["state"]["bounded_state_bytes"] == 2646
    assert first.stats == replay.stats
    assert first.pattern == replay.pattern


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_repeated_failure_changes_selected_mask(tmp_path: Path) -> None:
    _, potential, decisions, _ = _inputs(tmp_path, tiny_gap=True)
    cnf = tmp_path / "failure.cnf"
    cnf.write_text(
        "p cnf 256 4\n2 127 128 0\n2 127 -128 0\n2 -127 128 0\n2 -127 -128 0\n",
        encoding="ascii",
    )
    executable = tmp_path / "pattern"
    build_native_pattern_credit_search(source=NATIVE_SOURCE, output=executable)
    result = run_pattern_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    selection = result.pattern["selection"]
    actions = result.pattern["state"]["groups"][0]["actions"]
    assert selection["first_pattern_mask"] == 2
    assert selection["credit_reordered_actions"] >= 1
    assert selection["differentiated_groups"] >= 1
    assert sum(action["visits"] > 0 for action in actions) >= 2
    assert actions[2]["credit"] < 0
    assert result.pattern["backtrack_credit"]["eligible_undo_action_cells"] >= 1
