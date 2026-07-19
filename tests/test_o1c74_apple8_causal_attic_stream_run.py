from __future__ import annotations

import hashlib
import gzip
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, Sequence, cast

import pytest

import o1_crypto_lab.o1c74_apple8_causal_attic_stream_run as stream_run
from o1_crypto_lab.causal_attic_v1 import (
    ClauseOccurrence,
    canonical_json_bytes,
    reproject_causal_attic,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultIdentity,
    append_new_deduplicated,
    parse_threshold_no_good_vault,
    vault_identity_from_sources,
)


OBSERVED = tuple(range(1, 9))
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="o1c74-stream-runner-test-bound-v1",
    threshold=stream_run.THRESHOLD,
)


def _vault(
    clauses: Sequence[ThresholdNoGoodClause],
    *,
    observed: tuple[int, ...] = OBSERVED,
    identity: ThresholdNoGoodVaultIdentity = IDENTITY,
) -> ThresholdNoGoodVault:
    return ThresholdNoGoodVault(identity, observed, tuple(clauses))


def _occurrence(
    stream_id: str,
    source_index: int,
    classification: str,
    clause: ThresholdNoGoodClause,
    *,
    score: float,
) -> ClauseOccurrence:
    witness = struct.pack("<d", score)
    return ClauseOccurrence(
        stream_id=stream_id,
        source_index=source_index,
        classification=classification,
        source="trail_upper_bound",
        witness_score_f64le_hex=witness.hex(),
        clause=clause,
        clause_sha256=clause.sha256,
        witness_sha256=hashlib.sha256(
            b"\x01" + witness + clause.serialized
        ).hexdigest(),
    )


def _initial_prepared() -> stream_run.PreparedStream:
    retained_clauses = (
        ThresholdNoGoodClause((1, 2, 3, 4, 5, 6, 7, 8)),
        ThresholdNoGoodClause((-1, 2, -3, 4, -5, 6, -7, 8)),
    )
    prepared_clause = ThresholdNoGoodClause((1, -2, 3, -4, 5, -6, 7, -8))
    retained = _vault(retained_clauses)
    prepared_chunk = _vault((prepared_clause,))
    occurrences = tuple(
        _occurrence("o1c73-retained", index, "new", clause, score=2.0 + index)
        for index, clause in enumerate(retained_clauses)
    ) + (_occurrence("o1c73-rollover", 0, "new", prepared_clause, score=4.0),)
    state = reproject_causal_attic(
        (retained, prepared_chunk), occurrences, active_limit=256
    )
    return stream_run.prepared_stream_from_state(state)


def _dominated_prepared() -> stream_run.PreparedStream:
    dominated = ThresholdNoGoodClause((1, 2, 3, 4, 5, 6, 7, 8))
    strongest = ThresholdNoGoodClause((1,))
    retained = _vault((dominated,))
    rollover = _vault((strongest,))
    occurrences = (
        _occurrence("o1c73-retained", 0, "new", dominated, score=2.0),
        _occurrence("o1c73-rollover", 0, "new", strongest, score=3.0),
    )
    state = reproject_causal_attic(
        (retained, rollover), occurrences, active_limit=256
    )
    assert state.active_projection.clauses == (strongest,)
    return stream_run.prepared_stream_from_state(state)


def _read_vault(path: Path, prepared: stream_run.PreparedStream) -> ThresholdNoGoodVault:
    return parse_threshold_no_good_vault(
        path.read_bytes(),
        observed_variables=prepared.rank_source.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )


def _execute(
    capsule: Path,
    prepared: stream_run.PreparedStream,
    invoke: stream_run.EpisodeInvoker,
    *,
    verifier: Callable[[bytes], bool] | None = None,
) -> stream_run.StreamOutcome:
    capsule.mkdir(parents=True)
    return stream_run.execute_stream(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=verifier or (lambda _model: False),
        bindings={"test_fixture": "synthetic-target-free"},
    )


def _replace_canonical(path: Path, value: object) -> None:
    path.chmod(0o644)
    path.write_bytes(canonical_json_bytes(value))


def _replace_publication_source(
    capsule: Path, result: Mapping[str, object]
) -> None:
    _replace_canonical(capsule / stream_run.PUBLICATION_SOURCE_NAME, result)


def _coherently_replace_episode_evidence(
    capsule: Path,
    result: Mapping[str, object],
    *,
    local_ordinal: int,
    evidence_key: str,
    value: Mapping[str, object],
) -> dict[str, object]:
    rewritten = dict(result)
    episodes = [
        dict(cast(Mapping[str, object], episode))
        for episode in cast(Sequence[object], rewritten["episodes"])
    ]
    episode = episodes[local_ordinal]
    previous = cast(Mapping[str, object], episode[evidence_key])
    name = cast(str, previous["path"])
    payload = canonical_json_bytes(value)
    compressed = stream_run._canonical_gzip(payload)
    artifact = capsule / "episodes" / f"{local_ordinal:02d}" / name
    artifact.chmod(0o644)
    artifact.write_bytes(compressed)
    episode[evidence_key] = {
        "schema": stream_run.NATIVE_EVIDENCE_SCHEMA,
        "path": name,
        "compression": "gzip-9;mtime=0;empty-filename",
        "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
        "compressed_bytes": len(compressed),
        "uncompressed_sha256": hashlib.sha256(payload).hexdigest(),
        "uncompressed_bytes": len(payload),
    }
    episodes[local_ordinal] = episode
    rewritten["episodes"] = episodes
    _replace_canonical(
        capsule / "episodes" / f"{local_ordinal:02d}" / "episode.json",
        episode,
    )
    _replace_publication_source(capsule, rewritten)
    return rewritten


def _read_episode_evidence(
    capsule: Path,
    result: Mapping[str, object],
    *,
    local_ordinal: int,
    evidence_key: str,
) -> dict[str, object]:
    episodes = cast(Sequence[object], result["episodes"])
    episode = cast(Mapping[str, object], episodes[local_ordinal])
    metadata = cast(Mapping[str, object], episode[evidence_key])
    artifact = (
        capsule
        / "episodes"
        / f"{local_ordinal:02d}"
        / cast(str, metadata["path"])
    )
    return cast(dict[str, object], json.loads(gzip.decompress(artifact.read_bytes())))


def _native_occurrences(
    specifications: Sequence[tuple[str, ThresholdNoGoodClause]],
) -> tuple[ClauseOccurrence, ...]:
    return tuple(
        _occurrence("native", index, classification, clause, score=5.0 + index)
        for index, (classification, clause) in enumerate(specifications)
    )


def _telemetry(
    active: ThresholdNoGoodVault,
    occurrences: tuple[ClauseOccurrence, ...],
    *,
    next_vault: ThresholdNoGoodVault | None,
    terminal_reason: str | None,
) -> dict[str, object]:
    clause_counts = {
        classification: sum(
            occurrence.classification == classification
            for occurrence in occurrences
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
    aggregate = b"".join(
        occurrence.clause.serialized for occurrence in occurrences
    )
    identity = active.identity
    value: dict[str, object] = {
        "schema": "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1",
        "binary_magic_hex": THRESHOLD_NO_GOOD_VAULT_MAGIC.hex(),
        "input_cnf_sha256": identity.cnf_sha256,
        "input_potential_sha256": identity.potential_sha256,
        "input_grouping_sha256": identity.grouping_sha256,
        "input_observed_variables_sha256": identity.observed_variables_sha256,
        "input_bound_rule_sha256": identity.bound_rule_sha256,
        "input_threshold_f64le_hex": identity.threshold_f64le_hex,
        "input_sha256": active.sha256,
        "input_clause_count": active.clause_count,
        "input_literal_count": active.literal_count,
        "input_serialized_bytes": active.serialized_bytes,
        "input_clause_aggregate_sha256": active.clause_aggregate_sha256,
        "validated_input_clause_count": active.clause_count,
        "validated_input_literal_count": active.literal_count,
        "validated_input_clause_aggregate_sha256": (
            active.clause_aggregate_sha256
        ),
        "preloaded_clause_count": active.clause_count,
        "preloaded_literal_count": active.literal_count,
        "fully_emitted_clauses": rows,
        "fully_emitted_clause_count": len(rows),
        "fully_emitted_literal_count": sum(
            occurrence.clause.literal_count for occurrence in occurrences
        ),
        "fully_emitted_aggregate_sha256": hashlib.sha256(aggregate).hexdigest(),
        "emitted_new_clause_count": clause_counts["new"],
        "emitted_new_literal_count": literal_counts["new"],
        "emitted_input_duplicate_clause_count": clause_counts["input_duplicate"],
        "emitted_input_duplicate_literal_count": literal_counts[
            "input_duplicate"
        ],
        "emitted_current_duplicate_clause_count": clause_counts[
            "current_duplicate"
        ],
        "emitted_current_duplicate_literal_count": literal_counts[
            "current_duplicate"
        ],
        "terminal_empty_clause_count": 0,
        "pending_clause_exported": False,
        "next_vault_available": next_vault is not None,
        "next_vault_terminal_reason": terminal_reason,
        "next_vault_sha256": next_vault.sha256 if next_vault is not None else None,
        "next_serialized_bytes": (
            next_vault.serialized_bytes if next_vault is not None else None
        ),
        "next_clause_count": (
            next_vault.clause_count if next_vault is not None else None
        ),
        "next_literal_count": (
            next_vault.literal_count if next_vault is not None else None
        ),
    }
    return value


def _fake_result(
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    specifications: Sequence[tuple[str, ThresholdNoGoodClause]] = (),
    *,
    status: int = 0,
    terminal_reason: str | None = None,
    key_model: bytes | None = None,
) -> SimpleNamespace:
    occurrences = _native_occurrences(specifications)
    native_new = tuple(
        occurrence.clause
        for occurrence in occurrences
        if occurrence.classification == "new"
    )
    if terminal_reason is None:
        next_vault = append_new_deduplicated(
            active, native_new, caps=O1C66_VAULT_CAPS
        ).vault
    else:
        next_vault = None
    telemetry = _telemetry(
        active,
        occurrences,
        next_vault=next_vault,
        terminal_reason=terminal_reason,
    )
    reader = {
        "schema": stream_run._native_v16.VAULT_RANKED_DECISION_READER_SCHEMA,
        "source_vault_sha256": rank_source.sha256,
    }
    stats = {
        "conflicts": stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        "conflicts_before_solve": 0,
        "solve_conflicts": stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        "requested_conflicts": stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 0,
        "billed_conflicts": stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        "decisions": 256,
        "propagations": 4096,
    }
    resources = {
        "wall_microseconds": 1_000,
        "cpu_microseconds": 900,
        "peak_rss_bytes": 1_000_000,
    }
    sieve = {
        "external_clauses_emitted": len(occurrences),
        "pending_clause_count": 0,
        "grouping_sha256": active.identity.grouping_sha256,
    }
    raw = {
        "schema": stream_run._native_v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
        "implementation_parent_schema": (
            stream_run._native_v16.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        ),
        "implementation_release_parent_schema": (
            stream_run._native_v16.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        ),
        "rank_source_vault_sha256": rank_source.sha256,
        "reader": dict(reader),
        "vault": telemetry,
        "cnf_sha256": active.identity.cnf_sha256,
        "potential_sha256": active.identity.potential_sha256,
        "conflict_limit": stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        "seed": stream_run.SEED,
        "threshold": stream_run.THRESHOLD,
        "status": status,
        "key_model_hex": key_model.hex() if key_model is not None else None,
        "stats": {
            name: stats[name]
            for name in (
                "conflicts",
                "conflicts_before_solve",
                "solve_conflicts",
                "decisions",
                "propagations",
            )
        },
        "resources": dict(resources),
        "sieve": dict(sieve),
    }
    typed_eligible = tuple(
        SimpleNamespace(
            index=occurrence.source_index,
            source=occurrence.source,
            witness_score=occurrence.witness_score,
            clause=occurrence.clause,
            classification=occurrence.classification,
            clause_sha256=occurrence.clause_sha256,
            witness_sha256=occurrence.witness_sha256,
        )
        for occurrence in occurrences
    )
    return SimpleNamespace(
        status=status,
        conflict_limit=stream_run.REQUESTED_CONFLICTS_PER_EPISODE,
        threshold=stream_run.THRESHOLD,
        key_model=key_model,
        reader=reader,
        stats=stats,
        resources=resources,
        sieve=sieve,
        raw=raw,
        input_vault=active,
        rank_source_vault=rank_source,
        eligible_emitted_clauses=typed_eligible,
        next_vault=next_vault,
        vault_telemetry=telemetry,
    )


@pytest.fixture(scope="module")
def exact_513_state() -> stream_run.CausalAttic:
    observed = tuple(range(1, 12))
    identity = vault_identity_from_sources(
        cnf_sha256="67" * 32,
        potential_sha256="89" * 32,
        grouping_sha256="ab" * 32,
        observed_variables=observed,
        bound_rule="o1c74-exact-513-fixture-v1",
        threshold=stream_run.THRESHOLD,
    )
    clauses = tuple(
        ThresholdNoGoodClause(
            tuple(
                variable if mask & (1 << (variable - 1)) else -variable
                for variable in observed
            )
        )
        for mask in range(513)
    )
    retained = ThresholdNoGoodVault(identity, observed, clauses[:202])
    rollover = ThresholdNoGoodVault(identity, observed, clauses[202:])
    occurrences = tuple(
        _occurrence(
            "o1c73-retained" if index < 202 else "o1c73-rollover",
            index if index < 202 else index - 202,
            "new",
            clause,
            score=2.0 + index / 1024.0,
        )
        for index, clause in enumerate(clauses)
    )
    return reproject_causal_attic(
        (retained, rollover), occurrences, active_limit=256
    )


def test_exact_513_clause_attic_reconstructs_with_a_k256_projection(
    exact_513_state: stream_run.CausalAttic,
) -> None:
    state = exact_513_state
    reconstructed_chunks = tuple(
        parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        for chunk in state.chunks
    )
    reconstructed = reproject_causal_attic(
        reconstructed_chunks, state.occurrences, active_limit=256
    )

    assert tuple(chunk.clause_count for chunk in state.chunks) == (202, 311)
    assert state.union_vault.clause_count == 513
    assert state.union_vault.literal_count == 513 * 11
    assert state.occurrence_document()["occurrence_count"] == 513
    assert len(state.undominated_indices) == 513
    assert state.active_projection.clause_count == 256
    assert len(state.selected_union_indices) == 256
    assert reconstructed.describe() == state.describe()
    assert reconstructed.active_projection.serialized == (
        state.active_projection.serialized
    )
    assert tuple(chunk.sha256 for chunk in reconstructed.chunks) == tuple(
        chunk.sha256 for chunk in state.chunks
    )


def test_exact_four_ordinals_budgets_and_durable_intent_before_every_call(
    tmp_path: Path,
) -> None:
    prepared = _initial_prepared()
    calls: list[tuple[int, int, str, str]] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        intent_path = active_path.parent / "intent.json"
        assert intent_path.is_file()
        assert intent_path.stat().st_mode & 0o222 == 0
        assert active_path.stat().st_mode & 0o222 == 0
        assert rank_path.stat().st_mode & 0o222 == 0
        intent = json.loads(intent_path.read_text(encoding="ascii"))
        assert intent["local_episode_ordinal"] == local
        assert intent["lineage_call_ordinal"] == lineage
        assert intent["requested_conflicts"] == 128
        assert hashlib.sha256(active_path.read_bytes()).hexdigest() == cast(
            Mapping[str, object], intent["active_input_vault"]
        )["sha256"]
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        calls.append((local, lineage, rank.sha256, active.sha256))
        return _fake_result(rank, active)

    capsule = tmp_path / "four-calls"
    outcome = _execute(capsule, prepared, invoke)

    assert [(local, lineage) for local, lineage, _rank, _active in calls] == [
        (0, 10),
        (1, 11),
        (2, 12),
        (3, 13),
    ]
    assert {rank for _local, _lineage, rank, _active in calls} == {
        prepared.rank_source.sha256
    }
    assert outcome.classification == stream_run.NO_GAIN
    assert outcome.native_calls == 4
    assert outcome.requested_conflicts == 512
    assert outcome.billed_conflicts == 512
    assert len(outcome.episodes) == 4
    assert [episode["requested_conflicts"] for episode in outcome.episodes] == [
        128,
        128,
        128,
        128,
    ]
    assert all(
        (capsule / f"episodes/{ordinal:02d}/intent.json").is_file()
        for ordinal in range(4)
    )


def test_capacity_crossing_is_a_durable_rollover_and_keeps_streaming(
    tmp_path: Path,
) -> None:
    prepared = _initial_prepared()
    globally_novel = ThresholdNoGoodClause(
        (-1, -2, -3, -4, -5, -6, -7, -8)
    )
    calls: list[tuple[int, int]] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        calls.append((local, lineage))
        if local == 0:
            return _fake_result(
                rank,
                active,
                (("new", globally_novel),),
                terminal_reason="capacity_clause_count",
            )
        assert globally_novel in active.clauses
        return _fake_result(rank, active)

    capsule = tmp_path / "capacity-rollover"
    outcome = _execute(capsule, prepared, invoke)

    assert calls == [(0, 10), (1, 11), (2, 12), (3, 13)]
    assert outcome.classification == stream_run.NOVEL_CLAUSE_GAIN
    assert outcome.globally_novel_clauses == 1
    assert outcome.final_state.union_vault.clause_count == (
        prepared.state.union_vault.clause_count + 1
    )
    assert outcome.final_state.chunks[2].clauses == (globally_novel,)
    first = outcome.episodes[0]
    assert first["native_next_vault_available"] is False
    assert first["native_next_vault_terminal_reason"] == "capacity_clause_count"
    assert first["capacity_is_rollover_not_terminal"] is True
    assert first["globally_novel_clause_count"] == 1
    assert first["rollover_chunk_clause_count"] == 1
    assert (capsule / "episodes/00/projection-boundary.json").is_file()
    assert (capsule / "episodes/01/intent.json").is_file()


def test_globally_duplicate_native_new_occurrence_is_preserved_in_empty_chunk(
    tmp_path: Path,
) -> None:
    prepared = _dominated_prepared()
    dominated = prepared.state.union_vault.clauses[0]
    initial_active = prepared.state.active_projection.serialized

    def invoke(
        local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        if local == 0:
            assert dominated not in active.clauses
            return _fake_result(rank, active, (("new", dominated),))
        return _fake_result(rank, active)

    capsule = tmp_path / "duplicate-only"
    outcome = _execute(capsule, prepared, invoke)

    assert outcome.classification == stream_run.NO_GAIN
    assert outcome.globally_novel_clauses == 0
    assert outcome.final_state.union_vault == prepared.state.union_vault
    assert outcome.final_state.active_projection.serialized == initial_active
    assert outcome.final_state.chunks[2].clause_count == 0
    assert len(outcome.final_state.occurrences) == len(prepared.state.occurrences) + 1
    assert outcome.final_state.occurrences[-1].clause == dominated
    assert outcome.final_state.occurrences[-1].classification == "new"
    first = outcome.episodes[0]
    assert first["fully_emitted_occurrence_count"] == 1
    assert first["globally_novel_clause_count"] == 0
    assert first["rollover_chunk_clause_count"] == 0
    empty_chunk = _read_vault(
        capsule / "episodes/00/attic-rollover.vault", prepared
    )
    assert empty_chunk.clause_count == 0


@pytest.mark.parametrize(
    ("status", "key_model", "expected"),
    (
        (10, b"public-eight-block-model" + b"!" * 8, stream_run.PUBLIC_EXACT_RECOVERY),
        (20, None, stream_run.THRESHOLD_REGION_EXHAUSTED),
    ),
)
def test_status10_and_status20_precede_novel_gain_and_capacity_rollover(
    tmp_path: Path,
    status: int,
    key_model: bytes | None,
    expected: str,
) -> None:
    prepared = _initial_prepared()
    novel = ThresholdNoGoodClause((-1, -2, 3, 4, -5, -6, 7, 8))
    calls: list[tuple[int, int]] = []
    verifications: list[bytes] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
            (("new", novel),),
            status=status,
            terminal_reason="capacity_payload_bytes",
            key_model=key_model,
        )

    def verify(model: bytes) -> bool:
        verifications.append(model)
        return True

    outcome = _execute(
        tmp_path / f"status-{status}", prepared, invoke, verifier=verify
    )

    assert calls == [(0, 10)]
    assert outcome.classification == expected
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.globally_novel_clauses == 1
    assert outcome.final_state.union_vault.clauses[-1] == novel
    assert outcome.episodes[0]["capacity_is_rollover_not_terminal"] is True
    assert verifications == ([cast(bytes, key_model)] if status == 10 else [])


def test_operational_failure_consumes_the_ordinal_and_is_never_retried(
    tmp_path: Path,
) -> None:
    prepared = _initial_prepared()
    calls: list[tuple[int, int]] = []

    def fail(
        local: int, lineage: int, _rank_path: Path, active_path: Path
    ) -> object:
        assert (active_path.parent / "intent.json").is_file()
        calls.append((local, lineage))
        raise RuntimeError("synthetic native failure")

    capsule = tmp_path / "failure"
    outcome = _execute(capsule, prepared, fail)

    assert calls == [(0, 10)]
    assert outcome.classification == stream_run.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.billed_conflicts is None
    assert outcome.final_state.describe() == prepared.state.describe()
    assert len(outcome.episodes) == 1
    failure = cast(Mapping[str, object], outcome.operational_failure)
    assert failure["occurred_after_persisted_intent"] is True
    assert failure["native_calls_consumed"] == 1
    assert failure["retry_authorized"] is False
    assert (capsule / "episodes/00/terminal-failure.json").is_file()
    assert not (capsule / "episodes/01").exists()


def test_returned_but_incomplete_native_ledger_consumes_one_call_without_retry(
    tmp_path: Path,
) -> None:
    prepared = _initial_prepared()
    calls: list[tuple[int, int]] = []

    def invalid(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        result = _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )
        result.sieve["pending_clause_count"] = 1
        return result

    capsule = tmp_path / "invalid-return"
    outcome = _execute(capsule, prepared, invalid)

    assert calls == [(0, 10)]
    assert outcome.classification == stream_run.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.billed_conflicts is None
    failure = cast(Mapping[str, object], outcome.operational_failure)
    assert failure["native_result_returned"] is True
    assert failure["retry_authorized"] is False
    assert "incomplete clause" in cast(str, failure["error_message"])
    assert not (capsule / "episodes/01").exists()


def test_publication_recovery_is_deterministic_and_issues_zero_callbacks(
    tmp_path: Path,
) -> None:
    prepared = _initial_prepared()
    calls: list[tuple[int, int]] = []
    verifications: list[bytes] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )

    def verify(model: bytes) -> bool:
        verifications.append(model)
        return False

    capsule = tmp_path / "recovery"
    outcome = _execute(capsule, prepared, invoke, verifier=verify)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative="runs/test-o1c74",
        source_commit="ab" * 20,
        started_at="2026-07-19T22:00:00+02:00",
        runtime={"elapsed_seconds": 1.0},
    )
    source_path = stream_run.write_publication_source(capsule, result)
    calls_before = list(calls)
    verifications_before = list(verifications)

    recovered_from_file = stream_run.recover_publication(capsule)
    recovered_from_mapping = stream_run.recover_publication(capsule, result)
    recovered_from_path = stream_run.recover_publication(capsule, source_path)

    assert calls == calls_before == [(0, 10), (1, 11), (2, 12), (3, 13)]
    assert verifications == verifications_before == []
    assert recovered_from_file == recovered_from_mapping == recovered_from_path
    recovery = cast(
        Mapping[str, object], recovered_from_file["publication_recovery"]
    )
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert recovery["public_verification_calls_issued_during_recovery"] == 0
    assert recovery["recovered_episode_count"] == 4
    assert recovered_from_file["final_attic"] == outcome.final_state.describe()
    assert recovered_from_file["final_active_vault"] == (
        outcome.final_state.active_projection.describe()
    )


@pytest.mark.parametrize("tamper", ("occurrence-delta", "invocation"))
def test_publication_recovery_rejects_sealed_sidecar_tampering_without_callbacks(
    tmp_path: Path,
    tamper: str,
) -> None:
    prepared = _initial_prepared()
    calls: list[tuple[int, int]] = []
    verifications: list[bytes] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )

    def verify(model: bytes) -> bool:
        verifications.append(model)
        return False

    capsule = tmp_path / tamper
    outcome = _execute(capsule, prepared, invoke, verifier=verify)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative=f"runs/test-{tamper}",
        source_commit="cd" * 20,
        started_at="2026-07-19T22:00:00+02:00",
    )
    stream_run.write_publication_source(capsule, result)
    if tamper == "occurrence-delta":
        target = capsule / "episodes/00/occurrence-delta.json"
        raw = dict(json.loads(target.read_bytes()))
        raw["stream_id"] = "tampered-stream"
    else:
        target = capsule / "invocation.json"
        raw = dict(json.loads(target.read_bytes()))
        raw["bindings"] = {"tampered": True}
    target.chmod(0o644)
    target.write_bytes(canonical_json_bytes(raw))
    callbacks_before = (list(calls), list(verifications))

    with pytest.raises(stream_run.O1C74RunError, match="recovery|artifact"):
        stream_run.recover_publication(capsule)

    assert (calls, verifications) == callbacks_before


@pytest.mark.parametrize(
    "tamper", ("native-reader-equality", "coherent-reader-provenance")
)
def test_recovery_rejects_coherently_rejournaled_native_reader_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    prepared = _initial_prepared()

    def invoke(
        _local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )

    capsule = tmp_path / tamper
    outcome = _execute(capsule, prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative=f"runs/{tamper}",
        source_commit="de" * 20,
        started_at="2026-07-19T22:00:00+02:00",
    )
    stream_run.write_publication_source(capsule, result)
    native = _read_episode_evidence(
        capsule, result, local_ordinal=0, evidence_key="native_evidence"
    )
    wrong_rank = "fe" * 32
    native_reader = dict(cast(Mapping[str, object], native["reader"]))
    native_reader["source_vault_sha256"] = wrong_rank
    native["reader"] = native_reader
    if tamper == "coherent-reader-provenance":
        native["rank_source_vault_sha256"] = wrong_rank
    rewritten = _coherently_replace_episode_evidence(
        capsule,
        result,
        local_ordinal=0,
        evidence_key="native_evidence",
        value=native,
    )
    if tamper == "coherent-reader-provenance":
        reader = _read_episode_evidence(
            capsule,
            rewritten,
            local_ordinal=0,
            evidence_key="reader_evidence",
        )
        reader["source_vault_sha256"] = wrong_rank
        rewritten = _coherently_replace_episode_evidence(
            capsule,
            rewritten,
            local_ordinal=0,
            evidence_key="reader_evidence",
            value=reader,
        )

    with pytest.raises(stream_run.O1C74RunError, match="recovery|native|reader"):
        stream_run.recover_publication(capsule, rewritten)


@pytest.mark.parametrize(
    ("ledger", "replacement"),
    (
        ("classification", stream_run.NOVEL_CLAUSE_GAIN),
        ("stop_reason", "tampered-stop-reason"),
        ("native_solver_calls", 3),
        ("billed_conflicts", 511),
        ("globally_novel_clauses", 1),
    ),
)
def test_recovery_derives_and_rejects_tampered_terminal_ledgers(
    tmp_path: Path,
    ledger: str,
    replacement: object,
) -> None:
    prepared = _initial_prepared()

    def invoke(
        _local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )

    capsule = tmp_path / ledger
    outcome = _execute(capsule, prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative=f"runs/{ledger}",
        source_commit="ef" * 20,
        started_at="2026-07-19T22:00:00+02:00",
    )
    if ledger in {"classification", "stop_reason"}:
        result[ledger] = replacement
    else:
        resources = dict(cast(Mapping[str, object], result["resources"]))
        resources[ledger] = replacement
        result["resources"] = resources
    stream_run.write_publication_source(capsule, result)

    with pytest.raises(stream_run.O1C74RunError, match="recovery|conclusion|ledger"):
        stream_run.recover_publication(capsule)


def test_post_native_archival_failure_is_operational_and_claims_no_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _initial_prepared()
    novel = ThresholdNoGoodClause((-1, -2, -3, 4, 5, 6, 7, 8))
    calls: list[tuple[int, int]] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
            (("new", novel),),
        )

    def fail_archive(_path: Path, _value: object) -> dict[str, object]:
        raise stream_run.O1C74RunError("synthetic post-native archival failure")

    monkeypatch.setattr(stream_run, "_write_compressed_json", fail_archive)
    capsule = tmp_path / "post-native-archive-failure"
    outcome = _execute(capsule, prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative="runs/post-native-archive-failure",
        source_commit="fa" * 20,
        started_at="2026-07-19T22:00:00+02:00",
    )
    claims = cast(Mapping[str, object], result["claim_boundary"])
    resources = cast(Mapping[str, object], result["resources"])

    assert calls == [(0, 10)]
    assert outcome.classification == stream_run.OPERATIONAL_TERMINAL
    assert outcome.globally_novel_clauses == 0
    assert outcome.final_state.describe() == prepared.state.describe()
    assert cast(Mapping[str, object], outcome.operational_failure)[
        "native_result_returned"
    ] is True
    assert result["classification"] != stream_run.NOVEL_CLAUSE_GAIN
    assert claims["immutable_complete_causal_attic"] is False
    assert claims["every_fully_emitted_occurrence_retained"] is False
    assert claims["duplicate_witness_occurrences_retained"] is False
    assert resources["globally_novel_clauses"] == 0


def test_preflight_native_executable_binding_rejects_stale_bytes_and_symlinks(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "native-joint-score-sieve"
    payload = b"synthetic-native-v13-executable\n"
    executable.write_bytes(payload)
    executable.chmod(0o755)
    digest = hashlib.sha256(payload).hexdigest()

    binding = stream_run.validate_native_executable(
        executable, expected_sha256=digest
    )
    assert binding["sha256"] == digest
    assert binding["serialized_bytes"] == len(payload)
    assert binding["regular_file"] is True
    assert binding["symlink"] is False

    executable.write_bytes(payload + b"stale\n")
    with pytest.raises(stream_run.O1C74RunError, match="executable identity"):
        stream_run.validate_native_executable(executable, expected_sha256=digest)

    executable.write_bytes(payload)
    executable.chmod(0o644)
    with pytest.raises(stream_run.O1C74RunError, match="executable mode"):
        stream_run.validate_native_executable(executable, expected_sha256=digest)

    replacement = tmp_path / "replacement-native"
    replacement.write_bytes(payload)
    replacement.chmod(0o755)
    alias = tmp_path / "native-alias"
    alias.symlink_to(replacement)
    with pytest.raises(stream_run.O1C74RunError, match="regular|symlink|executable"):
        stream_run.validate_native_executable(alias, expected_sha256=digest)


def test_preflight_preserves_configured_executable_path_for_no_follow_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _initial_prepared()
    config_path = tmp_path / "config.json"
    config_path.write_bytes(b"{}\n")
    parent_result = tmp_path / "parent-result.json"
    parent_result.write_bytes(b"parent-result\n")
    parent_capsule = tmp_path / "parent-capsule"
    parent_capsule.mkdir()
    parent_manifest = parent_capsule / "artifacts.sha256"
    parent_manifest.write_bytes(b"parent-manifest\n")
    preparation = tmp_path / "prepared"
    preparation.mkdir()
    inputs: dict[str, object] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        path = tmp_path / f"{name}.bin"
        payload = f"{name}\n".encode("ascii")
        path.write_bytes(payload)
        inputs[name] = path.relative_to(tmp_path).as_posix()
        inputs[f"{name}_sha256"] = hashlib.sha256(payload).hexdigest()
    source_path = tmp_path / "runner-source.py"
    source_payload = b"# synthetic source\n"
    source_path.write_bytes(source_payload)
    source_digest = hashlib.sha256(source_payload).hexdigest()
    target = tmp_path / "actual-native"
    native_payload = b"synthetic executable\n"
    target.write_bytes(native_payload)
    target.chmod(0o755)
    configured = tmp_path / "build/o1c74/native-joint-score-sieve"
    configured.parent.mkdir(parents=True)
    configured.symlink_to(target)
    native_digest = hashlib.sha256(native_payload).hexdigest()
    config: dict[str, object] = {
        "parent": {
            "result": parent_result.relative_to(tmp_path).as_posix(),
            "capsule": parent_capsule.relative_to(tmp_path).as_posix(),
        },
        "preparation": {
            "directory": preparation.relative_to(tmp_path).as_posix(),
            "manifest_sha256": prepared.manifest_sha256,
        },
        "inputs": inputs,
        "source": {
            "paths": {"runner": source_path.relative_to(tmp_path).as_posix()},
            "expected_sha256": {"runner": source_digest},
            "expected_commit": "ab" * 20,
        },
        "native": {
            "source": source_path.relative_to(tmp_path).as_posix(),
            "executable": configured.relative_to(tmp_path).as_posix(),
            "expected_source_sha256": source_digest,
            "expected_executable_sha256": native_digest,
        },
        "target_free_preflight": {
            "path": "gate.json",
            "sha256": "cd" * 32,
        },
    }
    monkeypatch.setattr(stream_run, "load_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(
        stream_run,
        "load_prepared_stream",
        lambda *_args, **_kwargs: prepared,
    )
    monkeypatch.setattr(
        stream_run,
        "PARENT_RESULT_SHA256",
        hashlib.sha256(parent_result.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(
        stream_run,
        "PARENT_MANIFEST_SHA256",
        hashlib.sha256(parent_manifest.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr(stream_run, "RANK_SOURCE_SHA256", prepared.rank_source.sha256)
    monkeypatch.setattr(
        stream_run,
        "INITIAL_UNION_CLAUSES",
        prepared.state.union_vault.clause_count,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_UNION_LITERALS",
        prepared.state.union_vault.literal_count,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_UNION_SERIALIZED_BYTES",
        prepared.state.union_vault.serialized_bytes,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_ACTIVE_SHA256",
        prepared.state.active_projection.sha256,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_ACTIVE_CLAUSES",
        prepared.state.active_projection.clause_count,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_ACTIVE_LITERALS",
        prepared.state.active_projection.literal_count,
    )
    monkeypatch.setattr(
        stream_run,
        "INITIAL_ACTIVE_SERIALIZED_BYTES",
        prepared.state.active_projection.serialized_bytes,
    )

    with pytest.raises(stream_run.O1C74RunError, match="native executable mode"):
        stream_run.preflight(
            config_path, require_commit_binding=False, root=tmp_path
        )


@pytest.mark.parametrize("partial", ("intent-only", "completed-journal"))
def test_run_blocks_replay_of_partial_capsule_without_publication_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    partial: str,
) -> None:
    runs = tmp_path / "runs"
    capsule = runs / f"20260719_230000_{stream_run.CAPSULE_SUFFIX}"
    episode = capsule / "episodes/00"
    episode.mkdir(parents=True)
    (episode / "intent.json").write_bytes(
        canonical_json_bytes({"schema": stream_run.INTENT_SCHEMA})
    )
    if partial == "completed-journal":
        (episode / "episode.json").write_bytes(
            canonical_json_bytes(
                {"schema": stream_run.EPISODE_SCHEMA, "completed": True}
            )
        )
    callbacks: list[str] = []
    monkeypatch.setattr(stream_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(
        stream_run,
        "preflight",
        lambda *_args, **_kwargs: callbacks.append("preflight"),
    )
    monkeypatch.setattr(
        stream_run,
        "execute_stream",
        lambda **_kwargs: callbacks.append("execute"),
    )
    monkeypatch.setattr(
        stream_run._native_v16,
        "run_joint_score_sieve",
        lambda **_kwargs: callbacks.append("native"),
    )

    with pytest.raises(
        stream_run.O1C74RunError,
        match="partial O1C74 capsule without publication source blocks replay",
    ):
        stream_run.run(tmp_path / "missing-config.json")

    assert callbacks == []
    assert not (tmp_path / stream_run.RESULT_RELATIVE).exists()


def test_run_republishes_one_sealed_capsule_without_any_callbacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _initial_prepared()
    capsule_relative = Path("runs") / (
        f"20260719_230100_{stream_run.CAPSULE_SUFFIX}"
    )
    capsule = tmp_path / capsule_relative
    calls: list[tuple[int, int]] = []
    verifications: list[bytes] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append((local, lineage))
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
        )

    def verify(model: bytes) -> bool:
        verifications.append(model)
        return False

    outcome = _execute(capsule, prepared, invoke, verifier=verify)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit="bc" * 20,
        started_at="2026-07-19T23:01:00+02:00",
    )
    stream_run.write_publication_source(capsule, result)
    authoritative = tmp_path / stream_run.RESULT_RELATIVE
    stream_run.finalize_capsule(capsule, authoritative, result)
    authoritative.unlink()
    calls_before = list(calls)
    verifications_before = list(verifications)
    forbidden: list[str] = []
    monkeypatch.setattr(stream_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(
        stream_run,
        "preflight",
        lambda *_args, **_kwargs: forbidden.append("preflight"),
    )
    monkeypatch.setattr(
        stream_run,
        "execute_stream",
        lambda **_kwargs: forbidden.append("execute"),
    )
    monkeypatch.setattr(
        stream_run._native_v16,
        "run_joint_score_sieve",
        lambda **_kwargs: forbidden.append("native"),
    )

    republished = stream_run.run(tmp_path / "missing-config.json")

    assert forbidden == []
    assert calls == calls_before == [(0, 10), (1, 11), (2, 12), (3, 13)]
    assert verifications == verifications_before == []
    assert republished == result
    assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
    assert json.loads(authoritative.read_bytes()) == result


@pytest.mark.parametrize(
    ("platform", "expected_peak"),
    (("darwin", 123), ("linux", 123 * 1024)),
)
def test_runtime_peak_rss_uses_platform_native_units(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    expected_peak: int,
) -> None:
    usage = SimpleNamespace(ru_utime=3.5, ru_stime=4.5, ru_maxrss=123)
    started_usage = SimpleNamespace(ru_utime=1.0, ru_stime=1.5)
    monkeypatch.setattr(stream_run.resource, "getrusage", lambda _kind: usage)
    monkeypatch.setattr(stream_run.time, "perf_counter", lambda: 11.0)
    monkeypatch.setattr(stream_run.time, "process_time", lambda: 7.0)
    monkeypatch.setattr(stream_run.sys, "platform", platform)

    resources = stream_run._runtime_resources(
        started=10.0,
        cpu_started=5.0,
        child_started=cast(stream_run.resource.struct_rusage, started_usage),
    )

    assert resources == {
        "elapsed_seconds": 1.0,
        "runner_cpu_seconds": 2.0,
        "child_user_seconds": 2.5,
        "child_system_seconds": 3.0,
        "runner_peak_rss_bytes": expected_peak,
    }
