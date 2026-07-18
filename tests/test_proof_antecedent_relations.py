from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.cadical_sensor import ProbeRecord, ProofEvent, SolverSnapshot
from o1_crypto_lab.proof_antecedent_relations import (
    AntecedentRelationField,
    OriginalClauseTable,
    _branch_chain_nodes,
    extract_antecedent_relation_field,
    transform_antecedent_relation_field,
)


def _event(clause_id: int, clause: tuple[int, ...], antecedents: tuple[int, ...]):
    return ProofEvent(
        clause_id=clause_id,
        redundant=True,
        witness=0,
        conclusion_phase=False,
        snapshot=SolverSnapshot(1, 1, 1, 1),
        clause=clause,
        antecedents=antecedents,
    )


def _record(
    event: ProofEvent | None,
    *,
    bit_index: int = 0,
    assumed_value: int = 0,
    original_clause_count: int = 2,
) -> ProbeRecord:
    return ProbeRecord(
        bit_index=bit_index,
        assumed_value=assumed_value,
        assumption_literal=(bit_index + 1) * (1 if assumed_value else -1),
        requested_conflict_horizon=16,
        status=0,
        reported_status=0,
        original_clause_count=original_clause_count,
        last_original_id=original_clause_count,
        reserved_original_ids=original_clause_count,
        stats={"conflicts": 16, "decisions": 1, "propagations": 1, "ticks": 1},
        proof_counters={},
        conclusion={},
        assumption_clauses=(),
        resources={},
        final_overshoot_conflicts=0,
        events=() if event is None else (event,),
        deterministic_sha256=(f"{2 * bit_index + assumed_value + 1:064x}"),
    )


def test_chain_identity_changes_when_antecedent_changes(tmp_path: Path) -> None:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 4 2\n1 -3 0\n2 4 0\n", encoding="ascii")
    originals = OriginalClauseTable.load(cnf)
    left = _branch_chain_nodes(
        _record(_event(3, (4,), (1,))),
        originals=originals,
        baseline_nodes={},
    )[0]
    right = _branch_chain_nodes(
        _record(_event(3, (4,), (2,))),
        originals=originals,
        baseline_nodes={},
    )[0]
    assert left.digest != right.digest
    assert left.leaf_literals == (1, -3)
    assert right.leaf_literals == (2, 4)


def test_extractor_subtracts_common_chains_and_keeps_signed_leaf_phase(
    tmp_path: Path,
) -> None:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 300 2\n299 0\n300 0\n", encoding="ascii")
    originals = OriginalClauseTable.load(cnf)
    pairs = []
    for bit in range(256):
        common = _event(3, (299,), (1,))
        exclusive = _event(4, (300,), (2,))
        zero = _record(
            common,
            bit_index=bit,
            assumed_value=0,
            original_clause_count=2,
        )
        zero = ProbeRecord(**{**zero.__dict__, "events": (common, exclusive)})
        one = _record(
            common,
            bit_index=bit,
            assumed_value=1,
            original_clause_count=2,
        )
        pairs.append((zero, one))
    field = extract_antecedent_relation_field(
        pairs,
        baseline_events=(),
        originals=originals,
        conflict_horizon=16,
        capacity=512,
    )
    assert len(field.edges) == 256
    assert all(edge.factor_variable == 300 for edge in field.edges)
    assert all(edge.score_units == -1 for edge in field.edges)
    assert field.metrics["common_chain_count"] == 256
    assert field.metrics["exclusive_chain_count"] == 256
    restored = AntecedentRelationField.from_bytes(field.to_bytes())
    assert restored.edges == field.edges
    assert restored.state_sha256 == field.state_sha256


def test_field_transform_freezes_orientation_and_endpoint_controls(
    tmp_path: Path,
) -> None:
    cnf = tmp_path / "tiny.cnf"
    cnf.write_text("p cnf 300 2\n299 0\n300 0\n", encoding="ascii")
    originals = OriginalClauseTable.load(cnf)
    pairs = []
    for bit in range(256):
        factor = 299 if bit % 2 == 0 else 300
        antecedent = 1 if bit % 2 == 0 else 2
        event = _event(3, (factor,), (antecedent,))
        pairs.append(
            (
                _record(
                    event,
                    bit_index=bit,
                    assumed_value=0,
                    original_clause_count=2,
                ),
                _record(
                    None,
                    bit_index=bit,
                    assumed_value=1,
                    original_clause_count=2,
                ),
            )
        )
    field = extract_antecedent_relation_field(
        pairs,
        baseline_events=(),
        originals=originals,
        conflict_horizon=16,
        capacity=1024,
    )
    reversed_field = transform_antecedent_relation_field(field, orientation=-1)
    key_control = transform_antecedent_relation_field(
        field, orientation=-1, rotate="key"
    )
    factor_control = transform_antecedent_relation_field(
        field, orientation=-1, rotate="factor"
    )
    assert [edge.score_units for edge in reversed_field.edges] == [
        -edge.score_units for edge in field.edges
    ]
    assert key_control.edges[0].key_variable == 1
    assert key_control.edges[-1].key_variable == 256
    assert {edge.key_variable for edge in key_control.edges} == set(range(1, 257))
    assert factor_control.edges[0].factor_variable != field.edges[0].factor_variable
