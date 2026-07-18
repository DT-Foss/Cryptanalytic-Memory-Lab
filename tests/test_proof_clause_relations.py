from __future__ import annotations

import hashlib

from o1_crypto_lab.proof_clause_relations import (
    ClauseRelationEdge,
    ClauseRelationField,
    clause_contrast_units,
    coordinate_control_field,
    highest_degree_key_residual,
    score_relation_field,
)


def test_clause_contrast_uses_exact_sixth_units_and_removes_self() -> None:
    scores = clause_contrast_units(
        key_variable=7,
        zero_clauses=[(7,), (100, -200), (300, 400, -500)],
        one_clauses=[(-7,), (-100, -200), (-300, 400, -500)],
    )
    assert 7 not in scores
    assert scores[100] == -6
    assert 200 not in scores
    assert scores[300] == -4
    assert 400 not in scores
    assert 500 not in scores


def test_relation_field_binary_state_and_controls() -> None:
    edges = (
        ClauseRelationEdge(1, 900, 3),
        ClauseRelationEdge(2, 901, -3),
    )
    field = ClauseRelationField(
        conflict_horizon=16,
        selected_abs_units=3,
        capacity=8,
        source_sha256=hashlib.sha256(b"source").hexdigest(),
        edges=edges,
        metrics={"edge_count": 2},
    )
    assert field.serialized_bytes == 72
    assert len(field.to_bytes()) == 72
    assert field.factor_file_bytes() == b"1 900 3\n2 901 -3\n"
    scored = score_relation_field(
        field,
        {1: 1, 2: 1, 3: -1, 900: 1, 901: -1},
    )
    assert scored["primary_correct"] == 2
    assert scored["primary_accuracy"] == 1.0
    assert coordinate_control_field(field, rotate="key").edges[0].key_variable == 2
    assert (
        coordinate_control_field(field, rotate="factor").edges[0].factor_variable == 901
    )
    assert highest_degree_key_residual(field, residual_bits=1) == (1,)
