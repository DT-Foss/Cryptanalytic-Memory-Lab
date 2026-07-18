from __future__ import annotations

from pathlib import Path

import numpy as np

from o1_crypto_lab.cadical_sensor import ProbeRecord, ProofEvent, SolverSnapshot
from o1_crypto_lab.proof_antecedent_relations import OriginalClauseTable
from o1_crypto_lab.proof_parent_criticality import (
    ParentCriticalityFactor,
    ParentCriticalityField,
    _rup_pivots,
    extract_parent_criticality_field,
    parent_criticality_features,
    transform_parent_criticality_field,
)


def _event(clause_id: int, clause: tuple[int, ...], antecedents: tuple[int, ...]):
    return ProofEvent(
        clause_id=clause_id,
        redundant=False,
        witness=0,
        conclusion_phase=False,
        snapshot=SolverSnapshot(1, 1, 1, 1),
        clause=clause,
        antecedents=antecedents,
    )


def _record(
    event: ProofEvent | None, *, bit: int, assumed: int, original_count: int
) -> ProbeRecord:
    return ProbeRecord(
        bit_index=bit,
        assumed_value=assumed,
        assumption_literal=(bit + 1) * (1 if assumed else -1),
        requested_conflict_horizon=16,
        status=0,
        reported_status=0,
        original_clause_count=original_count,
        last_original_id=original_count,
        reserved_original_ids=original_count,
        stats={"conflicts": 16},
        proof_counters={},
        conclusion={},
        assumption_clauses=(),
        resources={},
        final_overshoot_conflicts=0,
        events=() if event is None else (event,),
        deterministic_sha256=f"{2 * bit + assumed + 1:064x}",
    )


def test_rup_replay_returns_ordered_pivots_and_terminal_conflict() -> None:
    assert _rup_pivots(
        (299,),
        ((299, 300), (299, -300)),
    ) == (300, 0)


def test_extractor_keeps_direct_original_role_and_excludes_conflict(
    tmp_path: Path,
) -> None:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text(
        "p cnf 300 2\n299 300 0\n299 -300 0\n", encoding="ascii"
    )
    originals = OriginalClauseTable.load(cnf)
    pairs = []
    for bit in range(256):
        exclusive = _event(3, (299,), (1, 2))
        pairs.append(
            (
                _record(exclusive, bit=bit, assumed=0, original_count=2),
                _record(None, bit=bit, assumed=1, original_count=2),
            )
        )
    field = extract_parent_criticality_field(
        pairs,
        baseline_events=(),
        originals=originals,
        conflict_horizon=16,
        capacity=512,
    )
    assert len(field.factors) == 256
    assert all(factor.parent_role == 0 for factor in field.factors)
    assert all(factor.clause_id == 1 for factor in field.factors)
    assert all(factor.expected_pivot == 300 for factor in field.factors)
    assert all(factor.score_units == -1 for factor in field.factors)
    assert field.metrics["exclusive_chain_count"] == 256
    restored = ParentCriticalityField.from_bytes(field.to_bytes())
    assert restored.factors == field.factors
    assert restored.state_sha256 == field.state_sha256


def test_candidate_features_distinguish_critical_pivot_and_literal_polarity() -> None:
    factor = ParentCriticalityFactor(1, 0, 9, 300, 2, (299, 300))
    field = ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=4,
        source_sha256="11" * 32,
        factors=(factor,),
        metrics={"factor_count": 1},
    )
    expected = np.zeros(15)
    expected[:3] = (1.0, 1.0, 1.0)
    assert np.array_equal(
        parent_criticality_features(field, {1: 1, 299: -1, 300: 1}),
        expected,
    )
    expected[:3] = (-1.0, 0.0, 0.0)
    assert np.array_equal(
        parent_criticality_features(field, {1: 1, 299: 1, 300: 1}),
        expected,
    )
    expected[:3] = (1.0, -1.0, 1.0)
    assert np.array_equal(
        parent_criticality_features(field, {1: 1, 299: 1, 300: -1}),
        expected,
    )


def test_endpoint_controls_are_deterministic_derangements() -> None:
    field = ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=4,
        source_sha256="22" * 32,
        factors=(
            ParentCriticalityFactor(1, 1, 8, 299, -2, (299, -300)),
            ParentCriticalityFactor(2, 2, 9, 300, 3, (-299, 300)),
        ),
        metrics={"factor_count": 2},
    )
    key = transform_parent_criticality_field(field, rotate="key")
    clause = transform_parent_criticality_field(field, rotate="clause")
    reverse = transform_parent_criticality_field(field, orientation=-1)
    assert [factor.key_variable for factor in key.factors] == [2, 3]
    assert clause.factors[0].clause != field.factors[0].clause
    assert [factor.score_units for factor in reverse.factors] == [2, -3]
