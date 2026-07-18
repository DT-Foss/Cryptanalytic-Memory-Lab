"""Candidate-level scoring for bounded signed proof-relation fields."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Mapping, Sequence

import numpy as np

from .proof_clause_relations import ClauseRelationField


class RelationCandidateRankError(ValueError):
    """A relation field, candidate panel, or score vector differs."""


def relation_match_vector(
    field: ClauseRelationField,
    assignment: Mapping[int, int],
) -> np.ndarray:
    """Return +1 when a candidate matches an edge phase and -1 otherwise."""

    if not field.edges:
        raise RelationCandidateRankError("relation field is empty")
    values = np.empty(len(field.edges), dtype=np.int8)
    for index, edge in enumerate(field.edges):
        key_spin = assignment.get(edge.key_variable)
        factor_spin = assignment.get(edge.factor_variable)
        if key_spin not in (-1, 1) or factor_spin not in (-1, 1):
            raise RelationCandidateRankError("candidate assignment lacks edge wires")
        orientation = 1 if edge.score_units > 0 else -1
        values[index] = orientation * key_spin * factor_spin
    return values


def raw_relation_weights(field: ClauseRelationField) -> np.ndarray:
    return np.asarray([abs(edge.score_units) for edge in field.edges], dtype=np.int64)


def surprise_log_odds_weights(
    decoy_matches: np.ndarray,
    *,
    build_correct: int,
    build_total: int,
    prior: float = 0.5,
) -> np.ndarray:
    """Subtract attacker-generated structural match odds from BUILD reliability."""

    matrix = np.asarray(decoy_matches)
    if (
        matrix.ndim != 2
        or matrix.shape[0] < 2
        or matrix.shape[1] < 1
        or not np.all((matrix == -1) | (matrix == 1))
        or isinstance(build_correct, bool)
        or isinstance(build_total, bool)
        or not isinstance(build_correct, int)
        or not isinstance(build_total, int)
        or not build_total // 2 < build_correct < build_total
        or not math.isfinite(prior)
        or prior <= 0.0
    ):
        raise RelationCandidateRankError("surprise calibration differs")
    reliability = build_correct / build_total
    positive = np.count_nonzero(matrix > 0, axis=0).astype(np.float64)
    background = (positive + prior) / (matrix.shape[0] + 2.0 * prior)
    return (
        math.log(reliability / (1.0 - reliability))
        - np.log(background / (1.0 - background))
    ).astype(np.float64, copy=False)


def weighted_relation_scores(
    matches: np.ndarray,
    weights: np.ndarray,
) -> np.ndarray:
    matrix = np.asarray(matches)
    vector = np.asarray(weights)
    if (
        matrix.ndim not in (1, 2)
        or vector.ndim != 1
        or matrix.shape[-1] != vector.shape[0]
        or not np.all(np.isfinite(vector))
    ):
        raise RelationCandidateRankError("weighted score shape differs")
    # Explicit float64 conversion avoids platform BLAS integer-matmul quirks.
    return np.asarray(matrix, dtype=np.float64) @ np.asarray(vector, dtype=np.float64)


def exact_candidate_rank(
    *,
    truth_score: float,
    decoy_scores: np.ndarray,
    truth_key: bytes,
    decoy_keys: Sequence[bytes],
) -> dict[str, object]:
    scores = np.asarray(decoy_scores, dtype=np.float64)
    if (
        scores.ndim != 1
        or scores.shape[0] != len(decoy_keys)
        or scores.shape[0] < 2
        or not math.isfinite(truth_score)
        or not np.all(np.isfinite(scores))
        or not isinstance(truth_key, bytes)
        or len(truth_key) != 32
        or any(not isinstance(key, bytes) or len(key) != 32 for key in decoy_keys)
        or len(set(decoy_keys)) != len(decoy_keys)
    ):
        raise RelationCandidateRankError("candidate rank panel differs")
    greater = int(np.count_nonzero(scores > truth_score))
    equal_mask = scores == truth_score
    equal = int(np.count_nonzero(equal_mask))
    lexical = sum(
        key < truth_key
        for key, tied in zip(decoy_keys, equal_mask, strict=True)
        if bool(tied)
    )
    rank = 1 + greater + lexical
    mean = float(np.mean(scores))
    std = float(np.std(scores, ddof=1))
    return {
        "truth_score": truth_score,
        "rank": rank,
        "rank_min": 1 + greater,
        "rank_max": 1 + greater + equal,
        "rank_fraction": rank / (scores.shape[0] + 1),
        "strictly_better_decoys": greater,
        "tied_decoys": equal,
        "decoy_mean": mean,
        "decoy_std": std,
        "truth_z": (truth_score - mean) / std if std else 0.0,
        "decoy_min": float(np.min(scores)),
        "decoy_max": float(np.max(scores)),
    }


def integer_score_histogram(scores: np.ndarray) -> list[dict[str, int]]:
    values = np.asarray(scores)
    if values.ndim != 1 or not np.all(values == np.rint(values)):
        raise RelationCandidateRankError("integer score vector differs")
    return [
        {"score": int(score), "count": int(count)}
        for score, count in sorted(Counter(int(item) for item in values).items())
    ]


def array_sha256(values: np.ndarray, dtype: str) -> str:
    canonical = np.ascontiguousarray(np.asarray(values, dtype=np.dtype(dtype)))
    return hashlib.sha256(canonical.tobytes(order="C")).hexdigest()


__all__ = [
    "RelationCandidateRankError",
    "array_sha256",
    "exact_candidate_rank",
    "integer_score_histogram",
    "raw_relation_weights",
    "relation_match_vector",
    "surprise_log_odds_weights",
    "weighted_relation_scores",
]
