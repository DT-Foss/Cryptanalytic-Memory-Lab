from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.pair_envelope_search as pair_search_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    PAIR_ENVELOPE_RESULT_SCHEMA,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
    write_pair_envelope_decision_variables,
    write_pair_envelope_potential,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_pair_envelope_search.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.5,
        source_sha256="31" * 32,
        factors=(
            CriticalityPotentialFactor(
                (1, 2, 257),
                (0.0, 1.0, 10.0, 2.0, 0.0, 1.0, 9.0, 2.0),
            ),
            CriticalityPotentialFactor((257,), (100.0, -100.0)),
        ),
    )


def test_writers_preserve_o1crit_serialization_and_ordered_pairs(
    tmp_path: Path,
) -> None:
    field = _field()
    potential_path = tmp_path / "potential.txt"
    decision_path = tmp_path / "decisions.txt"
    potential_sha = write_pair_envelope_potential(potential_path, field)
    decision_sha = write_pair_envelope_decision_variables(decision_path, (2, 1))
    assert potential_path.read_bytes() == field.to_bytes()
    assert potential_sha == hashlib.sha256(field.to_bytes()).hexdigest()
    assert decision_path.read_bytes() == b"2\n1\n"
    assert decision_sha == hashlib.sha256(b"2\n1\n").hexdigest()

    with pytest.raises(O1RelationalSearchError, match="even unique ordered"):
        write_pair_envelope_decision_variables(tmp_path / "odd.txt", (1,))
    with pytest.raises(O1RelationalSearchError, match="even unique ordered"):
        write_pair_envelope_decision_variables(tmp_path / "duplicate.txt", (1, 1))


def _fake_payload(decision_sha256: str) -> dict[str, object]:
    return {
        "schema": PAIR_ENVELOPE_RESULT_SCHEMA,
        "cadical_version": "3.0.0",
        "variables": 257,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "stats": {"conflicts": 32, "decisions": 4, "propagations": 9},
        "envelope": {
            "factor_count": 2,
            "pair_count": 1,
            "group_width": 2,
            "decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "source_sha256": "31" * 32,
            "decision_variables_sha256": decision_sha256,
            "offset": 0.5,
            "observed_variables": 3,
            "eligible_decision_variables": 2,
            "requested_decisions": 2,
            "repeated_decisions": 0,
            "queued_decisions": 2,
            "same_sign_queue_skips": 0,
            "opposite_sign_queue_invalidations": 0,
            "zero_gap_fallbacks": 1,
            "assignment_notifications": 3,
            "backtracks": 0,
            "maximum_assigned_variables": 3,
            "maximum_decision_level": 2,
            "maximum_score_gap": 8.0,
            "envelope_evaluations": 8,
        },
        "resources": {
            "wall_microseconds": 1,
            "cpu_microseconds": 1,
            "peak_rss_bytes": 1,
        },
    }


def test_runner_rejects_wrong_explicit_subset_count_and_order_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "fake-search"
    executable.write_text("placeholder\n", encoding="ascii")
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 257 0\n", encoding="ascii")
    potential = tmp_path / "potential.txt"
    write_pair_envelope_potential(potential, _field())
    decisions = tmp_path / "decisions.txt"
    decision_sha = write_pair_envelope_decision_variables(decisions, (2, 1))
    payload = _fake_payload(decision_sha)

    monkeypatch.setattr(
        pair_search_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    payload["envelope"]["eligible_decision_variables"] = 4
    with pytest.raises(
        O1RelationalSearchError,
        match="eligible decision-variable count differs",
    ):
        run_pair_envelope_search(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            decision_variables_path=decisions,
            conflict_limit=32,
        )

    payload["envelope"]["eligible_decision_variables"] = 2
    payload["envelope"]["decision_variables_sha256"] = hashlib.sha256(
        b"1\n2\n"
    ).hexdigest()
    with pytest.raises(O1RelationalSearchError, match="order hash differs"):
        run_pair_envelope_search(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            decision_variables_path=decisions,
            conflict_limit=32,
        )

    payload["envelope"]["decision_variables_sha256"] = decision_sha
    contract_cases = (
        ("decision_rule", "local_mean", "rule, scope, or width differs"),
        ("decision_scope", "sorted_pairs", "rule, scope, or width differs"),
        ("group_width", 3, "rule, scope, or width differs"),
        ("source_sha256", "42" * 32, "potential identity differs"),
        ("factor_count", 3, "potential identity differs"),
        ("offset", 1.5, "potential identity differs"),
        ("observed_variables", 2, "potential identity differs"),
    )
    for field, invalid, message in contract_cases:
        original = payload["envelope"][field]
        payload["envelope"][field] = invalid
        with pytest.raises(O1RelationalSearchError, match=message):
            run_pair_envelope_search(
                executable=executable,
                cnf_path=cnf,
                potential_path=potential,
                decision_variables_path=decisions,
                conflict_limit=32,
            )
        payload["envelope"][field] = original


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_native_global_envelope_makes_joint_pair_choice_without_internal_decision(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "pair-envelope-search"
    build_native_pair_envelope_search(source=NATIVE_SOURCE, output=executable)
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 257 1\n1 2 0\n", encoding="ascii")
    potential_path = tmp_path / "potential.txt"
    decision_path = tmp_path / "decisions.txt"
    write_pair_envelope_potential(potential_path, _field())
    decision_sha = write_pair_envelope_decision_variables(decision_path, (2, 1))

    result = run_pair_envelope_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential_path,
        decision_variables_path=decision_path,
        conflict_limit=32,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 0b11 == 0b10
    assert result.envelope["factor_count"] == 2
    assert result.envelope["pair_count"] == 1
    assert result.envelope["group_width"] == 2
    assert result.envelope["decision_rule"] == PAIR_ENVELOPE_DECISION_RULE
    assert result.envelope["decision_scope"] == PAIR_ENVELOPE_DECISION_SCOPE
    assert result.envelope["observed_variables"] == 3
    assert result.envelope["eligible_decision_variables"] == 2
    assert result.envelope["decision_variables_sha256"] == decision_sha
    assert result.envelope["requested_decisions"] >= 1
    assert result.envelope["queued_decisions"] >= result.envelope["requested_decisions"]
    assert result.envelope["repeated_decisions"] == 0
    assert result.envelope["same_sign_queue_skips"] == 0
    assert result.envelope["opposite_sign_queue_invalidations"] == 0
    assert result.envelope["backtracks"] == 0
    assert result.envelope["maximum_score_gap"] == pytest.approx(8.0)
    assert result.envelope["envelope_evaluations"] >= 6
