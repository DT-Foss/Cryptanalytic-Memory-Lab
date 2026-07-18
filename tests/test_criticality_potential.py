from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

import o1_crypto_lab.criticality_factor_search as criticality_search_module
from o1_crypto_lab.criticality_factor_search import (
    build_native_criticality_search,
    run_criticality_search,
    write_criticality_potential,
    write_decision_variables,
)
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
    add_unary_hints,
    compile_criticality_potential,
    score_potential_assignment,
    unary_hint_potential,
)
from o1_crypto_lab.proof_parent_criticality import (
    FEATURE_NAMES,
    ParentCriticalityFactor,
    ParentCriticalityField,
    parent_criticality_features,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]


def test_compiled_potential_is_exact_reader_score_for_every_assignment() -> None:
    field = ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=8,
        source_sha256="11" * 32,
        factors=(
            ParentCriticalityFactor(1, 1, 5, 300, -2, (299, 300)),
            ParentCriticalityFactor(2, 2, 6, -301, 3, (299, -301, 302)),
        ),
        metrics={"factor_count": 2},
    )
    mean = np.linspace(-0.2, 0.2, len(FEATURE_NAMES))
    std = np.linspace(0.5, 1.5, len(FEATURE_NAMES))
    reader = np.linspace(-1.0, 1.0, len(FEATURE_NAMES))
    potential = compile_criticality_potential(
        field, feature_mean=mean, feature_std=std, reader=reader
    )
    variables = (1, 2, 299, 300, 301, 302)
    for mask in range(1 << len(variables)):
        assignment = {
            variable: (1 if mask & (1 << index) else -1)
            for index, variable in enumerate(variables)
        }
        expected = float(
            np.dot((parent_criticality_features(field, assignment) - mean) / std, reader)
        )
        actual = score_potential_assignment(potential, assignment)
        assert np.isclose(actual, expected, rtol=0.0, atol=2e-15)
    restored = CriticalityPotentialField.from_bytes(potential.to_bytes())
    assert restored == potential
    assert restored.state_sha256 == potential.state_sha256


def test_unary_hints_add_reversible_local_energy() -> None:
    base = CriticalityPotentialField(
        offset=0.0,
        source_sha256="22" * 32,
        factors=(CriticalityPotentialFactor((2,), (0.0, 1.0)),),
    )
    hinted = add_unary_hints(base, [(1, -1, 8.0)])
    assert score_potential_assignment(hinted, {1: -1, 2: 1}) > score_potential_assignment(
        hinted, {1: 1, 2: 1}
    )


def test_unary_hint_only_field_is_canonical_and_prefers_truth() -> None:
    forward = unary_hint_potential([(2, 1, 8.0), (1, -1, 4.0)])
    reverse = unary_hint_potential([(1, -1, 4.0), (2, 1, 8.0)])
    assert forward == reverse
    assert score_potential_assignment(forward, {1: -1, 2: 1}) == 12.0
    assert score_potential_assignment(forward, {1: 1, 2: -1}) == -12.0


def test_native_criticality_adapter_makes_reversible_decisions(tmp_path: Path) -> None:
    executable = tmp_path / "criticality-search"
    build_native_criticality_search(
        source=ROOT / "native/cadical_o1_criticality_search.cpp",
        output=executable,
    )
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 1\n1 2 0\n", encoding="ascii")
    potential = CriticalityPotentialField(
        offset=0.0,
        source_sha256="33" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 2.0)),),
    )
    potential_path = tmp_path / "potential.txt"
    write_criticality_potential(potential_path, potential)
    result = run_criticality_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential_path,
        conflict_limit=32,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 1
    assert int(result.potential["requested_decisions"]) >= 1
    assert result.potential["decision_scope"] == "all_observed"


def test_native_criticality_adapter_can_decide_explicit_key_set(tmp_path: Path) -> None:
    executable = tmp_path / "criticality-search"
    build_native_criticality_search(
        source=ROOT / "native/cadical_o1_criticality_search.cpp",
        output=executable,
    )
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 257 1\n1 257 0\n", encoding="ascii")
    potential = CriticalityPotentialField(
        offset=0.0,
        source_sha256="44" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 2.0)),
            CriticalityPotentialFactor((257,), (0.0, 100.0)),
        ),
    )
    potential_path = tmp_path / "potential.txt"
    decision_path = tmp_path / "decisions.txt"
    write_criticality_potential(potential_path, potential)
    write_decision_variables(decision_path, (1,))
    result = run_criticality_search(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential_path,
        decision_variables_path=decision_path,
        conflict_limit=32,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 1
    assert result.potential["decision_scope"] == "explicit"
    assert result.potential["eligible_decision_variables"] == 1


def test_explicit_adapter_rejects_wrong_native_eligible_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "fake-search"
    executable.write_text("placeholder\n", encoding="ascii")
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "potential.txt"
    potential.write_text("placeholder\n", encoding="ascii")
    decisions = tmp_path / "decisions.txt"
    write_decision_variables(decisions, (1,))
    payload = {
        "schema": "o1-256-cadical-criticality-search-result-v1",
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 32,
        "seed": 0,
        "status": 0,
        "key_model_hex": None,
        "stats": {"conflicts": 32, "decisions": 32, "propagations": 32},
        "potential": {
            "factor_count": 1,
            "source_sha256": "55" * 32,
            "offset": 0.0,
            "observed_variables": 2,
            "decision_scope": "explicit",
            "eligible_decision_variables": 2,
            "requested_decisions": 1,
            "repeated_decisions": 0,
            "assignment_notifications": 1,
            "backtracks": 0,
            "maximum_assigned_variables": 1,
            "maximum_decision_level": 1,
            "maximum_abs_support": 1.0,
            "conditional_factor_evaluations": 1,
        },
        "resources": {
            "wall_microseconds": 1,
            "cpu_microseconds": 1,
            "peak_rss_bytes": 1,
        },
    }
    monkeypatch.setattr(
        criticality_search_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    with pytest.raises(
        O1RelationalSearchError,
        match="eligible decision-variable count differs",
    ):
        run_criticality_search(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            decision_variables_path=decisions,
            conflict_limit=32,
        )
