from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.online_pair_credit_search as online_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.online_pair_credit_search import (
    ONLINE_PAIR_COUNTER_MAX,
    ONLINE_PAIR_CREDIT_BYTES_PER_GROUP,
    ONLINE_PAIR_CREDIT_DECISION_RULE,
    ONLINE_PAIR_CREDIT_GROUPS,
    ONLINE_PAIR_CREDIT_MAX,
    ONLINE_PAIR_CREDIT_MIN,
    ONLINE_PAIR_CREDIT_RESULT_SCHEMA,
    ONLINE_PAIR_CREDIT_SELECTION_FORMULA,
    ONLINE_PAIR_CREDIT_STATE_BYTES,
    ONLINE_PAIR_CREDIT_STATE_ENCODING,
    ONLINE_PAIR_CREDIT_UPDATE_FORMULA,
    bounded_group_credit_update,
    build_native_online_pair_credit_search,
    run_online_pair_credit_search,
    write_online_pair_credit_decision_variables,
    write_online_pair_credit_potential,
)
from o1_crypto_lab.pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_online_pair_search.cpp"
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


def _field() -> CriticalityPotentialField:
    factors = [CriticalityPotentialFactor((1, 2), (0.0, 10.0, 1.0, 2.0))]
    factors.extend(
        CriticalityPotentialFactor((variable,), (0.0, 0.0))
        for variable in range(3, 127)
    )
    return CriticalityPotentialField(
        offset=0.25,
        source_sha256="31" * 32,
        factors=tuple(factors),
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 2 0\n", encoding="ascii")
    potential = tmp_path / "potential.pot"
    decisions = tmp_path / "decisions.txt"
    write_online_pair_credit_potential(potential, _field())
    decision_sha = write_online_pair_credit_decision_variables(decisions, _decisions())
    return cnf, potential, decisions, decision_sha


def _group_states() -> list[dict[str, int]]:
    decisions = _decisions()
    return [
        {
            "index": index,
            "first_variable": decisions[2 * index],
            "second_variable": decisions[2 * index + 1],
            "credit": 0,
            "visits": 0,
            "conflict_hits": 0,
            "propagation_units": 0,
            "backtrack_hits": 0,
        }
        for index in range(ONLINE_PAIR_CREDIT_GROUPS)
    ]


def _fake_payload(cnf: Path, decision_sha: str) -> dict[str, object]:
    groups = _group_states()
    state_bytes = bytes(ONLINE_PAIR_CREDIT_STATE_BYTES)
    return {
        "schema": ONLINE_PAIR_CREDIT_RESULT_SCHEMA,
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "cnf_sha256": hashlib.sha256(cnf.read_bytes()).hexdigest(),
        "stats": {"conflicts": 0, "decisions": 0, "propagations": 0},
        "online": {
            "factor_count": len(_field().factors),
            "pair_count": ONLINE_PAIR_CREDIT_GROUPS,
            "group_width": 2,
            "decision_rule": ONLINE_PAIR_CREDIT_DECISION_RULE,
            "cold_decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "source_sha256": _field().source_sha256,
            "decision_variables_sha256": decision_sha,
            "offset": _field().offset,
            "observed_variables": len(_field().observed_variables),
            "eligible_decision_variables": len(_decisions()),
            "update_formula": ONLINE_PAIR_CREDIT_UPDATE_FORMULA,
            "selection_formula": ONLINE_PAIR_CREDIT_SELECTION_FORMULA,
            "external_implications": 0,
            "hard_clauses_added": 0,
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
                "maximum_score_gap": 0.0,
                "maximum_modulated_priority": 0.0,
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
            "solver_counter_deltas": {
                "conflicts": 0,
                "decisions": 0,
                "propagations": 0,
            },
            "state": {
                "encoding": ONLINE_PAIR_CREDIT_STATE_ENCODING,
                "bytes_per_group": ONLINE_PAIR_CREDIT_BYTES_PER_GROUP,
                "bounded_state_bytes": ONLINE_PAIR_CREDIT_STATE_BYTES,
                "sha256": hashlib.sha256(state_bytes).hexdigest(),
                "credit_min": ONLINE_PAIR_CREDIT_MIN,
                "credit_max": ONLINE_PAIR_CREDIT_MAX,
                "counter_max": ONLINE_PAIR_COUNTER_MAX,
                "saturated_credit_updates": 0,
                "saturated_counter_updates": 0,
                "groups": groups,
            },
        },
        "resources": {
            "wall_microseconds": 1,
            "cpu_microseconds": 1,
            "peak_rss_bytes": 1,
        },
    }


def test_formats_are_reused_and_bounded_update_saturates(tmp_path: Path) -> None:
    _, potential, decisions, decision_sha = _inputs(tmp_path)
    assert potential.read_bytes() == _field().to_bytes()
    expected_decisions = "".join(f"{value}\n" for value in _decisions()).encode("ascii")
    assert decisions.read_bytes() == expected_decisions
    assert decision_sha == hashlib.sha256(expected_decisions).hexdigest()

    high = bounded_group_credit_update(
        (ONLINE_PAIR_CREDIT_MAX - 1, ONLINE_PAIR_COUNTER_MAX, 65530, 65530, 65535),
        assigned=2,
        delta_conflicts=0,
        delta_propagations=10_000,
        backtracked=False,
    )
    assert high == (
        ONLINE_PAIR_CREDIT_MAX,
        ONLINE_PAIR_COUNTER_MAX,
        65530,
        ONLINE_PAIR_COUNTER_MAX,
        ONLINE_PAIR_COUNTER_MAX,
    )
    low = bounded_group_credit_update(
        (ONLINE_PAIR_CREDIT_MIN + 1, 0, 0, 0, 0),
        assigned=0,
        delta_conflicts=100,
        delta_propagations=0,
        backtracked=True,
    )
    assert low[0] == ONLINE_PAIR_CREDIT_MIN
    assert low[1:] == (1, 100, 0, 1)


def test_strict_contract_rejects_malformed_state_and_ticket_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, decisions, decision_sha = _inputs(tmp_path)
    executable = tmp_path / "fake-search"
    executable.write_text("placeholder\n", encoding="ascii")
    payload = _fake_payload(cnf, decision_sha)

    def run_payload(*args: object, **kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(online_module.subprocess, "run", run_payload)
    result = run_online_pair_credit_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert result.state_sha256 == payload["online"]["state"]["sha256"]

    cases = (
        ("state_sha", ("online", "state", "sha256"), "42" * 32, "bounded state"),
        ("ticket", ("online", "tickets", "maximum_open"), 2, "telemetry ledger"),
        (
            "metric",
            ("online", "selection", "maximum_score_gap"),
            -1.0,
            "metric ledger",
        ),
        (
            "implication",
            ("online", "external_implications"),
            False,
            "identity differs",
        ),
        ("rule", ("online", "decision_rule"), "static", "identity differs"),
    )
    for _, path, invalid, message in cases:
        target = payload
        for key in path[:-1]:
            target = target[key]
        original = target[path[-1]]
        target[path[-1]] = invalid
        with pytest.raises(O1RelationalSearchError, match=message):
            run_online_pair_credit_search(
                executable=executable,
                cnf_path=cnf,
                potential_path=potential,
                decision_variables_path=decisions,
                conflict_limit=32,
            )
        target[path[-1]] = original


@pytest.mark.parametrize(
    ("field", "index"),
    (("CNF", 0), ("potential", 1), ("decision-variable", 2)),
)
def test_wrapper_rejects_each_input_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    index: int,
) -> None:
    cnf, potential, decisions, decision_sha = _inputs(tmp_path)
    paths = (cnf, potential, decisions)
    executable = tmp_path / "fake-search"
    executable.write_text("placeholder\n", encoding="ascii")
    payload = _fake_payload(cnf, decision_sha)

    def mutate(*args: object, **kwargs: object) -> SimpleNamespace:
        paths[index].write_bytes(paths[index].read_bytes() + b"\n")
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(online_module.subprocess, "run", mutate)
    with pytest.raises(O1RelationalSearchError, match=f"{field} changed"):
        run_online_pair_credit_search(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            decision_variables_path=decisions,
            conflict_limit=32,
        )


def test_build_rejects_native_source_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int main() { return 0; }\n", encoding="ascii")

    def mutate_source(*, source: Path, output: Path) -> object:
        source.write_text("int main() { return 1; }\n", encoding="ascii")
        return object()

    monkeypatch.setattr(online_module, "build_native_guided_search", mutate_source)
    with pytest.raises(O1RelationalSearchError, match="native source changed"):
        build_native_online_pair_credit_search(
            source=source, output=tmp_path / "search"
        )


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_cold_equivalence_bounded_state_and_deterministic_replay(
    tmp_path: Path,
) -> None:
    cnf, potential, decisions, _ = _inputs(tmp_path)
    static_executable = tmp_path / "static-search"
    online_executable = tmp_path / "online-search"
    build_native_pair_envelope_search(
        source=STATIC_NATIVE_SOURCE, output=static_executable
    )
    build_native_online_pair_credit_search(
        source=NATIVE_SOURCE, output=online_executable
    )
    static = run_pair_envelope_search(
        executable=static_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    first = run_online_pair_credit_search(
        executable=online_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    second = run_online_pair_credit_search(
        executable=online_executable,
        cnf_path=cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    assert first.status_name == static.status_name == "SAT"
    assert first.key_model == static.key_model
    assert first.key_model is not None
    assert first.key_model[0] & 0b11 == 0b01
    selection = first.online["selection"]
    assert selection["first_group_index"] == 0
    assert selection["first_pattern_mask"] == 2
    assert selection["cold_group_selections"] == 1
    assert selection["maximum_modulated_priority"] == 0
    assert first.online["tickets"]["maximum_open"] == 1
    assert first.online["tickets"]["current_open"] == 0
    assert first.online["state"]["bounded_state_bytes"] == 630
    assert (
        sum(group["visits"] for group in first.online["state"]["groups"])
        == first.online["tickets"]["closed"]
    )
    assert first.stats == second.stats
    assert first.key_model == second.key_model
    assert first.online == second.online

    invalidating_cnf = tmp_path / "opposite.cnf"
    invalidating_cnf.write_text("p cnf 256 1\n2 -1 0\n", encoding="ascii")
    invalidated = run_online_pair_credit_search(
        executable=online_executable,
        cnf_path=invalidating_cnf,
        potential_path=potential,
        decision_variables_path=decisions,
        conflict_limit=32,
    )
    invalidation_tickets = invalidated.online["tickets"]
    assert invalidated.online["queue"]["opposite_sign_queue_invalidations"] >= 1
    assert invalidation_tickets["closed_on_invalidation"] >= 1
    assert invalidation_tickets["closed"] == sum(
        invalidation_tickets[name]
        for name in (
            "closed_on_advance",
            "closed_on_backtrack",
            "closed_on_invalidation",
            "closed_on_solve_end",
        )
    )
