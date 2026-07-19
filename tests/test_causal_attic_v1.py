from __future__ import annotations

import hashlib
import json
import struct

import pytest

from o1_crypto_lab.causal_attic_v1 import (
    ACTIVE_PROJECTION_SCHEMA,
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CAUSAL_ATTIC_RELATION_SCHEMA,
    CausalAtticError,
    ClauseOccurrence,
    build_causal_attic,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    reproject_causal_attic,
    strict_subsumption_relations,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
)


OBSERVED = (1, 2, 3, 4, 5, 6)
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="causal-attic-test-bound-v1",
    threshold=7.5,
)


def _vault(clauses: tuple[ThresholdNoGoodClause, ...]) -> ThresholdNoGoodVault:
    return ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses)


def _occurrence(
    stream: str,
    index: int,
    classification: str,
    clause: ThresholdNoGoodClause,
    *,
    score: float,
) -> ClauseOccurrence:
    witness_bytes = struct.pack("<d", score)
    return ClauseOccurrence(
        stream_id=stream,
        source_index=index,
        classification=classification,
        source="trail_upper_bound",
        witness_score_f64le_hex=witness_bytes.hex(),
        clause=clause,
        clause_sha256=clause.sha256,
        witness_sha256=hashlib.sha256(
            b"\x01" + witness_bytes + clause.serialized
        ).hexdigest(),
    )


def _telemetry_payload(
    input_vault: ThresholdNoGoodVault,
    occurrences: tuple[ClauseOccurrence, ...],
) -> bytes:
    class_counts = {
        classification: sum(
            occurrence.classification == classification for occurrence in occurrences
        )
        for classification in ("new", "input_duplicate", "current_duplicate")
    }
    literal_counts = {
        classification: sum(
            occurrence.clause.literal_count
            for occurrence in occurrences
            if occurrence.classification == classification
        )
        for classification in ("new", "input_duplicate", "current_duplicate")
    }
    rows = [
        {
            "classification": occurrence.classification,
            "clause_sha256": occurrence.clause_sha256,
            "index": occurrence.source_index,
            "literal_count": occurrence.clause.literal_count,
            "literals": list(occurrence.clause.literals),
            "source": occurrence.source,
            "witness_score": occurrence.witness_score,
            "witness_score_f64le_hex": occurrence.witness_score_f64le_hex,
            "witness_sha256": occurrence.witness_sha256,
        }
        for occurrence in occurrences
    ]
    aggregate = b"".join(occurrence.clause.serialized for occurrence in occurrences)
    return canonical_json_bytes(
        {
            "schema": "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1",
            "binary_magic_hex": THRESHOLD_NO_GOOD_VAULT_MAGIC.hex(),
            "input_cnf_sha256": input_vault.identity.cnf_sha256,
            "input_potential_sha256": input_vault.identity.potential_sha256,
            "input_grouping_sha256": input_vault.identity.grouping_sha256,
            "input_observed_variables_sha256": (
                input_vault.identity.observed_variables_sha256
            ),
            "input_bound_rule_sha256": input_vault.identity.bound_rule_sha256,
            "input_threshold_f64le_hex": (input_vault.identity.threshold_f64le_hex),
            "input_sha256": input_vault.sha256,
            "input_clause_count": input_vault.clause_count,
            "input_literal_count": input_vault.literal_count,
            "input_serialized_bytes": input_vault.serialized_bytes,
            "input_clause_aggregate_sha256": (input_vault.clause_aggregate_sha256),
            "fully_emitted_clauses": rows,
            "fully_emitted_clause_count": len(rows),
            "fully_emitted_literal_count": sum(
                occurrence.clause.literal_count for occurrence in occurrences
            ),
            "fully_emitted_aggregate_sha256": hashlib.sha256(aggregate).hexdigest(),
            "emitted_new_clause_count": class_counts["new"],
            "emitted_new_literal_count": literal_counts["new"],
            "emitted_input_duplicate_clause_count": class_counts["input_duplicate"],
            "emitted_input_duplicate_literal_count": literal_counts["input_duplicate"],
            "emitted_current_duplicate_clause_count": class_counts["current_duplicate"],
            "emitted_current_duplicate_literal_count": literal_counts[
                "current_duplicate"
            ],
            "terminal_empty_clause_count": 0,
        }
    )


def test_telemetry_parser_preserves_exact_bits_hashes_and_ledgers() -> None:
    input_vault = _vault((ThresholdNoGoodClause((1, -4)),))
    clause = ThresholdNoGoodClause((-1, 2))
    occurrences = (
        _occurrence("ignored", 0, "new", clause, score=3.25),
        _occurrence("ignored", 1, "current_duplicate", clause, score=3.25),
    )
    payload = _telemetry_payload(input_vault, occurrences)
    parsed = parse_vault_telemetry(
        payload,
        stream_id="test-stream",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
    )

    assert parsed.input_identity == input_vault.identity
    assert parsed.input_vault_sha256 == input_vault.sha256
    assert len(parsed.occurrences) == 2
    assert len(parsed.new_occurrences) == 1
    assert parsed.occurrences[0].stream_id == "test-stream"
    assert parsed.occurrences[0].witness_score == 3.25


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    (
        ("witness", "digest"),
        ("ledger", "ledger"),
        ("classification", "classification"),
    ),
)
def test_telemetry_parser_rejects_tampered_semantics(
    mutation: str, pattern: str
) -> None:
    input_vault = _vault((ThresholdNoGoodClause((1, -4)),))
    occurrence = _occurrence(
        "ignored", 0, "new", ThresholdNoGoodClause((-1, 2)), score=3.25
    )
    raw = json.loads(_telemetry_payload(input_vault, (occurrence,)))
    if mutation == "witness":
        raw["fully_emitted_clauses"][0]["witness_sha256"] = "00" * 32
    elif mutation == "ledger":
        raw["emitted_new_clause_count"] = 2
    else:
        raw["fully_emitted_clauses"][0]["classification"] = "invented"
    payload = canonical_json_bytes(raw)

    with pytest.raises(CausalAtticError, match=pattern):
        parse_vault_telemetry(
            payload,
            stream_id="test-stream",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
        )


def test_telemetry_parser_rejects_artifact_digest_before_json() -> None:
    with pytest.raises(CausalAtticError, match="artifact"):
        parse_vault_telemetry(
            b"not JSON\n", stream_id="test-stream", expected_sha256="00" * 32
        )


def test_subsumption_and_greedy_projection_are_exact_and_target_free() -> None:
    retained_clauses = (
        ThresholdNoGoodClause((-1, 2, 3)),
        ThresholdNoGoodClause((-1, 2)),
        ThresholdNoGoodClause((1, -4)),
    )
    retained = _vault(retained_clauses)
    retained_occurrences = tuple(
        _occurrence("retained", index, "new", clause, score=2.0 + index)
        for index, clause in enumerate(retained_clauses)
    )
    strongest = ThresholdNoGoodClause((-1,))
    other = ThresholdNoGoodClause((5,))
    current_occurrences = (
        _occurrence("current", 0, "new", strongest, score=4.0),
        _occurrence("current", 1, "current_duplicate", strongest, score=4.0),
        _occurrence("current", 2, "new", other, score=5.0),
    )

    attic = build_causal_attic(
        retained,
        retained_occurrences=retained_occurrences,
        current_occurrences=current_occurrences,
        active_limit=2,
    )

    assert attic.novel_chunk.clauses == (strongest, other)
    assert attic.union_vault.clauses == retained_clauses + (strongest, other)
    assert attic.occurrence_union_indices == (0, 1, 2, 3, 3, 4)
    assert [(row.subsumer_index, row.subsumed_index) for row in attic.relations] == [
        (1, 0),
        (3, 0),
        (3, 1),
    ]
    assert attic.undominated_indices == (2, 3, 4)
    assert attic.selection_order == (3, 4)
    assert attic.selected_union_indices == (3, 4)
    assert attic.active_projection.clauses == (strongest, other)
    assert attic.unique_coverage_count == 4
    assert attic.occurrence_coverage_count == 5
    assert attic.duplicate_occurrence_count == 1
    projection = attic.describe()["active_projection"]
    assert isinstance(projection, dict)
    assert projection["schema"] == ACTIVE_PROJECTION_SCHEMA
    assert projection["is_cumulative_vault_v1"] is False
    assert attic.occurrence_document()["schema"] == CAUSAL_ATTIC_OCCURRENCE_SCHEMA
    assert attic.relation_document()["schema"] == CAUSAL_ATTIC_RELATION_SCHEMA


def test_builder_rejects_lineage_and_native_classification_drift() -> None:
    retained_clause = ThresholdNoGoodClause((-1, 2))
    retained = _vault((retained_clause,))
    retained_occurrence = _occurrence("retained", 0, "new", retained_clause, score=2.0)
    current_clause = ThresholdNoGoodClause((5,))
    wrongly_duplicate = _occurrence(
        "current", 0, "current_duplicate", current_clause, score=3.0
    )

    with pytest.raises(CausalAtticError, match="classification"):
        build_causal_attic(
            retained,
            retained_occurrences=(retained_occurrence,),
            current_occurrences=(wrongly_duplicate,),
            active_limit=1,
        )
    with pytest.raises(CausalAtticError, match="retained witness lineage"):
        build_causal_attic(
            retained,
            retained_occurrences=(),
            current_occurrences=(
                _occurrence("current", 0, "new", current_clause, score=3.0),
            ),
            active_limit=1,
        )


def test_stream_reprojection_accepts_zero_novel_chunk_and_all_occurrences() -> None:
    retained_clause = ThresholdNoGoodClause((-1, 2))
    retained = _vault((retained_clause,))
    retained_occurrence = _occurrence("retained", 0, "new", retained_clause, score=2.0)
    novel_clause = ThresholdNoGoodClause((5,))
    novel_occurrence = _occurrence("episode-00", 0, "new", novel_clause, score=3.0)
    initial = build_causal_attic(
        retained,
        retained_occurrences=(retained_occurrence,),
        current_occurrences=(novel_occurrence,),
        active_limit=2,
    )
    repeated_rollover = _vault((novel_clause,))
    empty_rollover = _vault(())
    duplicate_occurrence = _occurrence(
        "episode-01", 0, "input_duplicate", novel_clause, score=3.0
    )

    reprojected = reproject_causal_attic(
        initial.chunks + (repeated_rollover, empty_rollover),
        initial.occurrences + (duplicate_occurrence,),
        active_limit=2,
    )

    assert len(reprojected.chunks) == 4
    assert reprojected.chunk_clause_union_indices == ((0,), (1,), (1,), ())
    assert reprojected.union_vault == initial.union_vault
    assert reprojected.active_projection == initial.active_projection
    assert reprojected.occurrence_union_indices == (0, 1, 1)
    assert reprojected.unique_coverage_count == 2
    assert reprojected.occurrence_coverage_count == 3
    assert reprojected.duplicate_occurrence_count == 1


def test_self_scoping_parser_reuses_vault_v1_and_rejects_hidden_scope() -> None:
    full_scope = _vault((ThresholdNoGoodClause((1, 2, 3, 4, 5, 6)),))
    assert parse_self_scoping_vault(full_scope.serialized) == full_scope

    hidden_scope = _vault((ThresholdNoGoodClause((1, 2)),))
    with pytest.raises(CausalAtticError, match="complete observed scope"):
        parse_self_scoping_vault(hidden_scope.serialized)


def test_relation_function_rejects_duplicates() -> None:
    clause = ThresholdNoGoodClause((-1, 2))
    with pytest.raises(CausalAtticError, match="not unique"):
        strict_subsumption_relations((clause, clause))
