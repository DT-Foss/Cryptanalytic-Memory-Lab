from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.survivor_support_search as survivor_module
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
from o1_crypto_lab.survivor_support_search import (
    SURVIVOR_SUPPORT_ACTION_BYTES_PER_CELL,
    SURVIVOR_SUPPORT_ACTION_BYTES_PER_GROUP,
    SURVIVOR_SUPPORT_ACTION_CELLS_PER_GROUP,
    SURVIVOR_SUPPORT_ACTION_STATE_BYTES,
    SURVIVOR_SUPPORT_ACTION_STATE_ENCODING,
    SURVIVOR_SUPPORT_BYTES_PER_GROUP,
    SURVIVOR_SUPPORT_COUNTER_MAX,
    SURVIVOR_SUPPORT_COUNTER_SEMANTICS,
    SURVIVOR_SUPPORT_DECISION_RULE,
    SURVIVOR_SUPPORT_GROUPS,
    SURVIVOR_SUPPORT_MAX,
    SURVIVOR_SUPPORT_MIN,
    SURVIVOR_SUPPORT_OWNER_BYTES_PER_GROUP,
    SURVIVOR_SUPPORT_OWNER_BYTES_PER_MEMBER,
    SURVIVOR_SUPPORT_OWNER_MEMBERS_PER_GROUP,
    SURVIVOR_SUPPORT_OWNER_STATE_BYTES,
    SURVIVOR_SUPPORT_OWNER_STATE_ENCODING,
    SURVIVOR_SUPPORT_RESULT_SCHEMA,
    SURVIVOR_SUPPORT_SELECTION_FORMULA,
    SURVIVOR_SUPPORT_STATE_BYTES,
    SURVIVOR_SUPPORT_STATE_ENCODING,
    SURVIVOR_SUPPORT_UPDATE_FORMULA,
    build_native_survivor_support_search,
    run_survivor_support_search,
    survivor_support_update,
    write_survivor_support_decision_variables,
    write_survivor_support_potential,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_survivor_support_search.cpp"
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
    write_survivor_support_potential(potential, _field(two_groups=two_groups))
    decision_sha = write_survivor_support_decision_variables(decisions, _decisions())
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
        for index in range(SURVIVOR_SUPPORT_GROUPS)
    ]


def _fake_payload(cnf: Path, decision_sha: str) -> dict[str, object]:
    action_bytes = bytes(SURVIVOR_SUPPORT_ACTION_STATE_BYTES)
    owner_bytes = bytes(SURVIVOR_SUPPORT_OWNER_STATE_BYTES)
    combined = action_bytes + owner_bytes
    return {
        "schema": SURVIVOR_SUPPORT_RESULT_SCHEMA,
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "cnf_sha256": hashlib.sha256(cnf.read_bytes()).hexdigest(),
        "stats": {"conflicts": 0, "decisions": 0, "propagations": 0},
        "survivor": {
            "factor_count": len(_field().factors),
            "pair_count": 63,
            "group_width": 2,
            "decision_rule": SURVIVOR_SUPPORT_DECISION_RULE,
            "cold_decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "source_sha256": _field().source_sha256,
            "decision_variables_sha256": decision_sha,
            "offset": _field().offset,
            "observed_variables": len(_field().observed_variables),
            "eligible_decision_variables": 126,
            "external_implications": 0,
            "hard_clauses_added": 0,
            "update_formula": SURVIVOR_SUPPORT_UPDATE_FORMULA,
            "selection_formula": SURVIVOR_SUPPORT_SELECTION_FORMULA,
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
                "supported_action_cells": 0,
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
            "survivor_support": {
                "callbacks": 0,
                "conflict_callbacks": 0,
                "nonconflict_callbacks": 0,
                "undone_owner_clears": 0,
                "conflict_undone_owner_clears": 0,
                "nonconflict_undone_owner_clears": 0,
                "conflict_callbacks_with_survivor": 0,
                "conflict_callbacks_without_survivor": 0,
                "survivor_candidates_examined": 0,
                "deepest_level_tie_callbacks": 0,
                "support_updates": 0,
                "support_units": 0,
                "assignment_support_units": 0,
                "propagation_support_units": 0,
                "undone_owner_support_units": 0,
                "all_survivor_support_units": 0,
                "maximum_supported_owner_level": 0,
                "last_survivor_group": None,
                "last_survivor_member": None,
                "last_survivor_level": None,
                "last_survivor_mask": None,
                "trace_sha256": hashlib.sha256(b"").hexdigest(),
            },
            "solver_counter_deltas": {
                "conflicts": 0,
                "decisions": 0,
                "propagations": 0,
            },
            "state": {
                "encoding": SURVIVOR_SUPPORT_STATE_ENCODING,
                "action_encoding": SURVIVOR_SUPPORT_ACTION_STATE_ENCODING,
                "owner_encoding": SURVIVOR_SUPPORT_OWNER_STATE_ENCODING,
                "bytes_per_group": SURVIVOR_SUPPORT_BYTES_PER_GROUP,
                "action_bytes_per_cell": SURVIVOR_SUPPORT_ACTION_BYTES_PER_CELL,
                "action_cells_per_group": SURVIVOR_SUPPORT_ACTION_CELLS_PER_GROUP,
                "action_bytes_per_group": SURVIVOR_SUPPORT_ACTION_BYTES_PER_GROUP,
                "owner_bytes_per_member": SURVIVOR_SUPPORT_OWNER_BYTES_PER_MEMBER,
                "owner_members_per_group": SURVIVOR_SUPPORT_OWNER_MEMBERS_PER_GROUP,
                "owner_bytes_per_group": SURVIVOR_SUPPORT_OWNER_BYTES_PER_GROUP,
                "bounded_action_state_bytes": SURVIVOR_SUPPORT_ACTION_STATE_BYTES,
                "bounded_owner_state_bytes": SURVIVOR_SUPPORT_OWNER_STATE_BYTES,
                "bounded_state_bytes": SURVIVOR_SUPPORT_STATE_BYTES,
                "sha256": hashlib.sha256(combined).hexdigest(),
                "action_sha256": hashlib.sha256(action_bytes).hexdigest(),
                "owner_sha256": hashlib.sha256(owner_bytes).hexdigest(),
                "credit_min": SURVIVOR_SUPPORT_MIN,
                "credit_max": SURVIVOR_SUPPORT_MAX,
                "counter_max": SURVIVOR_SUPPORT_COUNTER_MAX,
                "owner_level_max": (1 << 32) - 1,
                "owner_mask_max": 3,
                "counter_semantics": SURVIVOR_SUPPORT_COUNTER_SEMANTICS,
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


def test_reference_clears_then_supports_one_deepest_survivor() -> None:
    credits = (0,) * 8
    owners = ((3, 2), (5, 1), (7, 3), (5, 0))
    updated, remaining, undone, selected = survivor_support_update(
        credits, owners, new_level=5, conflict_backtrack=True
    )
    assert undone == 1
    assert remaining == ((3, 2), (5, 1), (0, 0), (5, 0))
    assert selected == (0, 1, 5, 1)
    assert updated == (0, 32, 0, 0, 0, 0, 0, 0)
    saturated, _, _, _ = survivor_support_update(
        (0, SURVIVOR_SUPPORT_MAX - 1, 0, 0),
        ((2, 1), (0, 0)),
        new_level=2,
        conflict_backtrack=True,
    )
    assert saturated[1] == SURVIVOR_SUPPORT_MAX
    unchanged, _, _, no_selection = survivor_support_update(
        credits, owners, new_level=5, conflict_backtrack=False
    )
    assert unchanged == credits
    assert no_selection is None


def test_strict_wrapper_rejects_state_and_support_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, decisions, decision_sha = _inputs(tmp_path)
    executable = tmp_path / "fake"
    executable.write_text("x", encoding="ascii")
    payload = _fake_payload(cnf, decision_sha)
    monkeypatch.setattr(
        survivor_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    result = run_survivor_support_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert result.survivor["state"]["bounded_state_bytes"] == 2646
    cases = (
        (("survivor", "state", "owner_sha256"), "42" * 32, "bounded state"),
        (("survivor", "state", "credit_min"), -32768, "bounded state"),
        (
            ("survivor", "survivor_support", "support_units"),
            32,
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
            run_survivor_support_search(
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
    survivor_executable = tmp_path / "survivor"
    build_native_pair_envelope_search(
        source=STATIC_NATIVE_SOURCE, output=static_executable
    )
    build_native_survivor_support_search(
        source=NATIVE_SOURCE, output=survivor_executable
    )
    static = run_pair_envelope_search(
        executable=static_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    first = run_survivor_support_search(
        executable=survivor_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    replay = run_survivor_support_search(
        executable=survivor_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert first.status_name == static.status_name == "SAT"
    assert first.key_model == static.key_model
    assert first.survivor["selection"]["first_group_index"] == 0
    assert first.survivor["selection"]["first_pattern_mask"] == 2
    assert first.survivor["state"]["bounded_state_bytes"] == 2646
    assert first.stats == replay.stats
    assert first.survivor == replay.survivor


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_conflict_supports_deepest_survivor(tmp_path: Path) -> None:
    _, potential, decisions, _ = _inputs(tmp_path, two_groups=True)
    cnf = tmp_path / "survivor.cnf"
    cnf.write_text(
        "p cnf 256 4\n"
        "-1 -3 127 128 0\n-1 -3 127 -128 0\n"
        "-1 -3 -127 128 0\n-1 -3 -127 -128 0\n",
        encoding="ascii",
    )
    executable = tmp_path / "survivor"
    build_native_survivor_support_search(source=NATIVE_SOURCE, output=executable)
    result = run_survivor_support_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    replay = run_survivor_support_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    telemetry = result.survivor["survivor_support"]
    assert telemetry["support_updates"] >= 1
    assert telemetry["support_units"] == 32 * telemetry["support_updates"]
    assert telemetry["last_survivor_group"] == 0
    assert telemetry["last_survivor_member"] in (0, 1)
    assert telemetry["undone_owner_support_units"] == 0
    assert telemetry["all_survivor_support_units"] == 0
    actions = result.survivor["state"]["groups"][0]["actions"]
    assert any(action["credit"] > 0 for action in actions)
    assert all(
        action["credit"] >= 0
        for group in result.survivor["state"]["groups"]
        for action in group["actions"]
    )
    assert result.stats == replay.stats
    assert result.survivor == replay.survivor
