from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, Sequence, cast

import pytest

import o1_crypto_lab.o1c75_apple8_causal_residency_stream_run as stream_run
from o1_crypto_lab.causal_attic_v1 import (
    ClauseOccurrence,
    reproject_causal_attic,
)
from o1_crypto_lab.causal_residency_v1 import initialize_causal_residency
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    append_new_deduplicated,
    parse_threshold_no_good_vault,
    vault_identity_from_sources,
)


OBSERVED = tuple(range(1, 11))
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="o1c75-residency-runner-test-bound-v1",
    threshold=stream_run.THRESHOLD,
)


def _clause(mask: int) -> ThresholdNoGoodClause:
    return ThresholdNoGoodClause(
        tuple(
            variable if mask & (1 << (variable - 1)) else -variable
            for variable in OBSERVED
        )
    )


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


@pytest.fixture(scope="module")
def prepared() -> stream_run.PreparedStream:
    clauses = tuple(_clause(mask) for mask in range(600))
    rank = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses[:300])
    rollover = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses[300:])
    occurrences = tuple(
        _occurrence("genesis", index, "new", clause, score=2.0 + index / 1024)
        for index, clause in enumerate(clauses)
    )
    attic = reproject_causal_attic(
        (rank, rollover), occurrences, active_limit=256
    )
    state = initialize_causal_residency(
        attic,
        parent_active_indices=tuple(range(256)),
        inherited_event_indices=tuple(range(6)),
        parent_lineage_ordinal=13,
        first_lineage_ordinal=14,
        active_limit=256,
    )
    assert len(state.never_resident_undominated_indices) == 94
    return stream_run.prepared_stream_from_state(state)


def _read_vault(
    path: Path, prepared: stream_run.PreparedStream
) -> ThresholdNoGoodVault:
    return parse_threshold_no_good_vault(
        path.read_bytes(),
        observed_variables=prepared.rank_source.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )


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
    classifications = ("new", "input_duplicate", "current_duplicate")
    clause_counts = {
        name: sum(item.classification == name for item in occurrences)
        for name in classifications
    }
    literal_counts = {
        name: sum(
            item.clause.literal_count
            for item in occurrences
            if item.classification == name
        )
        for name in classifications
    }
    rows = [
        {
            "classification": item.classification,
            "clause_sha256": item.clause_sha256,
            "index": item.source_index,
            "literal_count": item.clause.literal_count,
            "literals": list(item.clause.literals),
            "source": item.source,
            "witness_score": item.witness_score,
            "witness_score_f64le_hex": item.witness_score_f64le_hex,
            "witness_sha256": item.witness_sha256,
        }
        for item in occurrences
    ]
    aggregate = b"".join(item.clause.serialized for item in occurrences)
    identity = active.identity
    return {
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
        "validated_input_clause_aggregate_sha256": active.clause_aggregate_sha256,
        "preloaded_clause_count": active.clause_count,
        "preloaded_literal_count": active.literal_count,
        "fully_emitted_clauses": rows,
        "fully_emitted_clause_count": len(rows),
        "fully_emitted_literal_count": sum(
            item.clause.literal_count for item in occurrences
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
        "next_vault_sha256": next_vault.sha256 if next_vault else None,
        "next_serialized_bytes": next_vault.serialized_bytes if next_vault else None,
        "next_clause_count": next_vault.clause_count if next_vault else None,
        "next_literal_count": next_vault.literal_count if next_vault else None,
    }


def _fake_result(
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    specifications: Sequence[tuple[str, ThresholdNoGoodClause]] = (),
    *,
    status: int = 0,
    key_model: bytes | None = None,
    terminal_reason: str | None = None,
) -> SimpleNamespace:
    occurrences = _native_occurrences(specifications)
    new = tuple(
        item.clause for item in occurrences if item.classification == "new"
    )
    next_vault = (
        None
        if terminal_reason is not None
        else append_new_deduplicated(active, new, caps=O1C66_VAULT_CAPS).vault
    )
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
        "conflicts": 128,
        "conflicts_before_solve": 0,
        "solve_conflicts": 128,
        "requested_conflicts": 128,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 0,
        "billed_conflicts": 128,
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
        "conflict_limit": 128,
        "seed": 0,
        "threshold": stream_run.THRESHOLD,
        "status": status,
        "key_model_hex": key_model.hex() if key_model is not None else None,
        "stats": {
            key: stats[key]
            for key in (
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
    typed = tuple(
        SimpleNamespace(
            index=item.source_index,
            source=item.source,
            witness_score=item.witness_score,
            clause=item.clause,
            classification=item.classification,
            clause_sha256=item.clause_sha256,
            witness_sha256=item.witness_sha256,
        )
        for item in occurrences
    )
    return SimpleNamespace(
        status=status,
        conflict_limit=128,
        threshold=stream_run.THRESHOLD,
        key_model=key_model,
        reader=reader,
        stats=stats,
        resources=resources,
        sieve=sieve,
        raw=raw,
        input_vault=active,
        rank_source_vault=rank_source,
        eligible_emitted_clauses=typed,
        next_vault=next_vault,
        vault_telemetry=telemetry,
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


def test_two_fresh_pages_cover_debt_without_repeat_and_keep_exact_call_ledger(
    tmp_path: Path, prepared: stream_run.PreparedStream
) -> None:
    calls: list[tuple[int, int, str]] = []

    def invoke(
        local: int, lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        intent = active_path.parent / "intent.json"
        assert intent.is_file() and intent.stat().st_mode & 0o222 == 0
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        calls.append((local, lineage, active.sha256))
        return _fake_result(rank, active)

    capsule = tmp_path / "two-pages"
    outcome = _execute(capsule, prepared, invoke)

    assert [(local, lineage) for local, lineage, _sha in calls] == [
        (0, 14),
        (1, 15),
    ]
    assert len({sha for _local, _lineage, sha in calls}) == 2
    assert not set(sha for _local, _lineage, sha in calls) & set(
        stream_run.INHERITED_SCIENCE_INPUT_SHA256
    )
    assert outcome.classification == stream_run.NO_GAIN
    assert outcome.native_calls == 2
    assert outcome.requested_conflicts == 256
    assert outcome.billed_conflicts == 256
    assert outcome.final_state.never_resident_undominated_indices == ()
    assert len(outcome.final_state.used_active_sha256) == 4
    assert len(set(outcome.final_state.used_active_sha256)) == 4
    assert all(
        (capsule / f"episodes/{ordinal:02d}/residency-boundary.json").is_file()
        for ordinal in range(2)
    )


def test_page2_puts_inherited_debt_before_dynamic_hot_and_retains_duplicate(
    tmp_path: Path, prepared: stream_run.PreparedStream
) -> None:
    inactive_parent_index = next(
        index
        for index in range(256)
        if index not in prepared.state.current_projection.selected_union_indices
    )
    duplicate = prepared.state.attic.union_vault.clauses[inactive_parent_index]

    def invoke(
        local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        return _fake_result(
            rank,
            active,
            (("new", duplicate),) if local == 0 else (),
        )

    outcome = _execute(tmp_path / "hot", prepared, invoke)
    page2 = cast(Mapping[str, object], outcome.episodes[0]["residency_after"])
    projection = cast(Mapping[str, object], page2["current_projection"])
    categories = cast(Mapping[str, object], projection["categories"])
    order = cast(Sequence[int], projection["selection_order"])
    debt = cast(Sequence[int], categories["inherited_debt"])
    hot = cast(Sequence[int], categories["hot_event"])

    assert len(debt) == 94
    assert inactive_parent_index in hot
    assert max(order.index(index) for index in debt) < order.index(
        inactive_parent_index
    )
    assert outcome.classification == stream_run.NO_GAIN
    assert outcome.globally_novel_clauses == 0
    assert outcome.final_state.attic.chunks[2].clause_count == 0
    assert outcome.final_state.attic.occurrences[-1].clause == duplicate


@pytest.mark.parametrize("mode", ("duplicate", "novel"))
def test_duplicate_only_and_global_novel_gain_are_classified_from_archive_delta(
    tmp_path: Path,
    prepared: stream_run.PreparedStream,
    mode: str,
) -> None:
    duplicate = prepared.state.attic.union_vault.clauses[0]
    emitted = duplicate if mode == "duplicate" else _clause(700)

    def invoke(
        local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
            (("new", emitted),) if local == 0 else (),
        )

    outcome = _execute(tmp_path / mode, prepared, invoke)

    if mode == "duplicate":
        assert outcome.classification == stream_run.NO_GAIN
        assert outcome.globally_novel_clauses == 0
        assert outcome.final_state.attic.chunks[2].clause_count == 0
    else:
        assert outcome.classification == stream_run.NOVEL_CLAUSE_GAIN
        assert outcome.globally_novel_clauses == 1
        assert outcome.final_state.attic.chunks[2].clauses == (emitted,)
        first_state = cast(Mapping[str, object], outcome.episodes[0]["residency_after"])
        projection = cast(Mapping[str, object], first_state["current_projection"])
        categories = cast(Mapping[str, object], projection["categories"])
        new_index = prepared.state.attic.union_vault.clause_count
        assert new_index in cast(Sequence[int], categories["new_debt"])


def test_failures_consume_one_call_without_retry_and_suppress_gain_claims(
    tmp_path: Path,
    prepared: stream_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    novel = _clause(700)

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
        raise stream_run.O1C75RunError("synthetic post-native archival failure")

    monkeypatch.setattr(stream_run, "_write_compressed_json", fail_archive)
    outcome = _execute(tmp_path / "archive-failure", prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative="runs/archive-failure",
        source_commit="ab" * 20,
        started_at="2026-07-20T00:00:00+02:00",
    )

    assert calls == [(0, 14)]
    assert outcome.classification == stream_run.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.billed_conflicts is None
    assert outcome.globally_novel_clauses == 0
    assert outcome.final_state.describe() == prepared.state.describe()
    claims = cast(Mapping[str, object], result["claim_boundary"])
    assert claims["immutable_complete_causal_attic"] is False
    assert claims["every_fully_emitted_occurrence_retained"] is False
    assert not (tmp_path / "archive-failure/episodes/01").exists()


@pytest.mark.parametrize(
    ("status", "model", "classification"),
    (
        (10, b"!" * 32, stream_run.PUBLIC_EXACT_RECOVERY),
        (20, None, stream_run.THRESHOLD_REGION_EXHAUSTED),
    ),
)
def test_verified_recovery_and_exhaustion_stop_naturally_after_one_call(
    tmp_path: Path,
    prepared: stream_run.PreparedStream,
    status: int,
    model: bytes | None,
    classification: str,
) -> None:
    calls: list[int] = []

    def invoke(
        local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append(local)
        return _fake_result(
            _read_vault(rank_path, prepared),
            _read_vault(active_path, prepared),
            status=status,
            key_model=model,
        )

    outcome = _execute(
        tmp_path / f"status-{status}",
        prepared,
        invoke,
        verifier=lambda candidate: candidate == model,
    )

    assert calls == [0]
    assert outcome.classification == classification
    assert outcome.native_calls == 1


def test_recovery_source_replays_without_callbacks_and_rejects_tampering(
    tmp_path: Path, prepared: stream_run.PreparedStream
) -> None:
    calls: list[int] = []

    def invoke(
        local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        calls.append(local)
        return _fake_result(
            _read_vault(rank_path, prepared), _read_vault(active_path, prepared)
        )

    capsule = tmp_path / "recovery"
    outcome = _execute(capsule, prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative="runs/recovery",
        source_commit="bc" * 20,
        started_at="2026-07-20T00:01:00+02:00",
    )
    source_path = stream_run.write_recovery_source(capsule, result)
    source = cast(dict[str, object], json.loads(source_path.read_bytes()))
    calls_before = list(calls)

    recovered = stream_run.recover_publication(capsule, source)

    assert calls == calls_before == [0, 1]
    recovery = cast(Mapping[str, object], recovered["publication_recovery"])
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert recovery["public_verification_calls_issued_during_recovery"] == 0
    assert recovered["final_residency"] == outcome.final_state.describe()

    target = capsule / "episodes/00/residency-ledger.json"
    target.chmod(0o644)
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(stream_run.O1C75RunError, match="recovery|artifact|ledger"):
        stream_run.recover_publication(capsule)


def test_partial_capsule_blocks_replay_and_sealed_capsule_republishes(
    tmp_path: Path,
    prepared: stream_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runs = tmp_path / "runs"
    partial = runs / f"20260720_000200_{stream_run.CAPSULE_SUFFIX}"
    (partial / "episodes/00").mkdir(parents=True)
    (partial / "episodes/00/intent.json").write_bytes(b"{}\n")
    monkeypatch.setattr(stream_run, "lab_root", lambda: tmp_path)
    with pytest.raises(stream_run.O1C75RunError, match="partial O1C75 capsule"):
        stream_run.run(tmp_path / "missing.json")
    for path in sorted(partial.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        else:
            path.rmdir()
    partial.rmdir()

    capsule_relative = Path("runs") / (
        f"20260720_000300_{stream_run.CAPSULE_SUFFIX}"
    )
    capsule = tmp_path / capsule_relative

    def invoke(
        _local: int, _lineage: int, rank_path: Path, active_path: Path
    ) -> object:
        return _fake_result(
            _read_vault(rank_path, prepared), _read_vault(active_path, prepared)
        )

    outcome = _execute(capsule, prepared, invoke)
    result = stream_run.build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit="cd" * 20,
        started_at="2026-07-20T00:03:00+02:00",
    )
    stream_run.write_recovery_source(capsule, result)
    authoritative = tmp_path / stream_run.RESULT_RELATIVE
    stream_run.finalize_capsule(capsule, authoritative, result)
    authoritative.unlink()
    forbidden: list[str] = []
    monkeypatch.setattr(
        stream_run, "preflight", lambda *_args, **_kwargs: forbidden.append("preflight")
    )
    monkeypatch.setattr(
        stream_run,
        "execute_stream",
        lambda **_kwargs: forbidden.append("execute"),
    )

    republished = stream_run.run(tmp_path / "missing.json")

    assert forbidden == []
    assert republished == result
    assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()


@pytest.mark.parametrize(
    ("platform", "expected_peak"), (("darwin", 123), ("linux", 123 * 1024))
)
def test_runtime_peak_rss_uses_platform_native_units(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected_peak: int
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

    assert resources["runner_peak_rss_bytes"] == expected_peak
