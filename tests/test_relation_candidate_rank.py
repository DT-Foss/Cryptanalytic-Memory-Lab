from __future__ import annotations

import hashlib

import numpy as np

from o1_crypto_lab.proof_clause_relations import (
    ClauseRelationEdge,
    ClauseRelationField,
)
from o1_crypto_lab.relation_candidate_rank import (
    exact_candidate_rank,
    relation_match_vector,
    surprise_log_odds_weights,
    weighted_relation_scores,
)


def _field() -> ClauseRelationField:
    return ClauseRelationField(
        conflict_horizon=16,
        selected_abs_units=3,
        capacity=4,
        source_sha256=hashlib.sha256(b"source").hexdigest(),
        edges=(
            ClauseRelationEdge(1, 900, 3),
            ClauseRelationEdge(2, 901, -3),
        ),
        metrics={"edge_count": 2},
    )


def test_relation_candidate_score_and_exact_tie_rank() -> None:
    matches = relation_match_vector(_field(), {1: 1, 2: 1, 900: 1, 901: -1})
    assert matches.tolist() == [1, 1]
    panel = np.asarray([[1, 1], [1, -1], [-1, 1], [-1, -1]], dtype=np.int8)
    weights = surprise_log_odds_weights(
        panel,
        build_correct=6,
        build_total=10,
    )
    assert weights.shape == (2,)
    scores = weighted_relation_scores(panel, np.asarray([3.0, 3.0]))
    ranked = exact_candidate_rank(
        truth_score=0.0,
        decoy_scores=scores,
        truth_key=b"\x80" + bytes(31),
        decoy_keys=[bytes([item]) + bytes(31) for item in range(4)],
    )
    assert ranked["rank_min"] == 2
    assert ranked["rank_max"] == 4
    assert ranked["rank"] == 4
