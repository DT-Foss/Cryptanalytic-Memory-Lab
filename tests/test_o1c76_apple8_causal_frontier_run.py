from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, Sequence, cast

import pytest

import o1_crypto_lab.o1c76_apple8_causal_frontier_run as frontier_run
from o1_crypto_lab.causal_attic_v1 import (
    ClauseOccurrence,
    canonical_json_bytes,
    reproject_causal_attic,
)
from o1_crypto_lab.causal_frontier_v1 import (
    CAUSAL_FRONTIER_SOURCE_STATE_SCHEMA,
    derive_causal_frontier_plan,
    parse_causal_frontier_plan,
)
from o1_crypto_lab.causal_residency_v1 import initialize_causal_residency
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    parse_threshold_no_good_vault,
    vault_identity_from_sources,
)


OBSERVED = tuple(range(1, 11))
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="o1c76-frontier-runner-test-bound-v1",
    threshold=frontier_run.THRESHOLD,
)


def _clause(mask: int) -> ThresholdNoGoodClause:
    return ThresholdNoGoodClause(
        tuple(
            variable if mask & (1 << (variable - 1)) else -variable
            for variable in OBSERVED
        )
    )


def _occurrence(
    source_index: int,
    classification: str,
    clause: ThresholdNoGoodClause,
) -> ClauseOccurrence:
    score = 5.0 + source_index
    witness = struct.pack("<d", score)
    return ClauseOccurrence(
        stream_id="synthetic-o1c76",
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
def prepared() -> frontier_run.PreparedStream:
    clauses = tuple(_clause(mask) for mask in range(600))
    rank = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses[:300])
    rollover = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses[300:])
    occurrences = tuple(
        _occurrence(index, "new", clause)
        for index, clause in enumerate(clauses)
    )
    attic = reproject_causal_attic(
        (rank, rollover), occurrences, active_limit=256
    )
    state = initialize_causal_residency(
        attic,
        parent_active_indices=tuple(range(256)),
        inherited_event_indices=tuple(range(6)),
        parent_lineage_ordinal=15,
        first_lineage_ordinal=16,
        active_limit=256,
    )
    assignment = bytes(len(OBSERVED))
    source = canonical_json_bytes(
        {
            "sieve": {
                "state": {
                    "schema": CAUSAL_FRONTIER_SOURCE_STATE_SCHEMA,
                    "encoding": "observed-ascending-i8-sign;synthetic",
                    "assignment_hex": assignment.hex(),
                    "assignment_bytes": len(assignment),
                    "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                    "current_assigned_variables": 0,
                }
            }
        }
    )
    plan = derive_causal_frontier_plan(
        source_result=source,
        active_vault=state.active_projection,
        selected_union_indices=state.current_projection.selected_union_indices,
    )
    return frontier_run.prepared_stream_from_state(
        state,
        frontier_plan=plan,
        frontier_plan_document={"plan": plan.describe()},
    )


def _read_vault(
    path: Path, prepared: frontier_run.PreparedStream
) -> ThresholdNoGoodVault:
    return parse_threshold_no_good_vault(
        path.read_bytes(),
        observed_variables=prepared.rank_source.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )


def _fake_return(
    specifications: Sequence[tuple[str, ThresholdNoGoodClause]] = (),
    *,
    activated: bool = True,
    trace_sha256: str = "ab" * 32,
    safe_prunes: int = 0,
    status: int = 0,
    key_model: bytes | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        specifications=tuple(specifications),
        activated=activated,
        trace_sha256=trace_sha256,
        safe_prunes=safe_prunes,
        status=status,
        key_model=key_model,
    )


def _install_fake_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    def validate(
        result: object,
        *,
        active: ThresholdNoGoodVault,
        **_kwargs: object,
    ) -> dict[str, object]:
        fake = cast(SimpleNamespace, result)
        occurrences = tuple(
            _occurrence(index, classification, clause)
            for index, (classification, clause) in enumerate(
                cast(
                    Sequence[tuple[str, ThresholdNoGoodClause]],
                    fake.specifications,
                )
            )
        )
        aggregate = b"".join(
            occurrence.clause.serialized for occurrence in occurrences
        )
        activated = cast(bool, fake.activated)
        trace = cast(str, fake.trace_sha256)
        safe = cast(int, fake.safe_prunes)
        telemetry = {
            "fully_emitted_aggregate_sha256": hashlib.sha256(aggregate).hexdigest(),
        }
        frontier = {
            "initial_once_returns": 1 if activated else 0,
            "contrast_returns": 0,
        }
        return {
            "raw": {"schema": "synthetic-v14"},
            "reader": {"schema": "synthetic-parent-reader"},
            "frontier": frontier,
            "telemetry": telemetry,
            "telemetry_payload": canonical_json_bytes(telemetry),
            "occurrences": occurrences,
            "stats": {
                "requested_conflicts": 128,
                "solve_conflicts": 128,
                "billed_conflicts": 128,
            },
            "status": cast(int, fake.status),
            "key_model": cast(bytes | None, fake.key_model),
            "next_vault_available": True,
            "next_vault_terminal_reason": None,
            "frontier_substitution_count": 1 if activated else 0,
            "frontier_mechanism_activated": activated,
            "trace_sha256": trace,
            "baseline_trace_sha256": frontier_run.FROZEN_BASELINE_TRACE_SHA256,
            "baseline_trace_changed": trace
            != frontier_run.FROZEN_BASELINE_TRACE_SHA256,
            "safe_threshold_prunes": safe,
            "resources": {
                "peak_rss_bytes": 1_000_000,
                "wall_microseconds": 1_000,
                "cpu_microseconds": 900,
            },
        }

    monkeypatch.setattr(frontier_run, "_validated_episode_result", validate)


def _execute(
    capsule: Path,
    prepared: frontier_run.PreparedStream,
    invoke: frontier_run.EpisodeInvoker,
    *,
    verifier: Callable[[bytes], bool] | None = None,
) -> frontier_run.StreamOutcome:
    capsule.mkdir(parents=True)
    return frontier_run.execute_stream(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=verifier or (lambda _model: False),
        bindings={"test_fixture": "synthetic-target-free"},
    )


def test_single_call_schedule_persists_intent_and_binds_frontier_plan(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_validator(monkeypatch)
    calls: list[tuple[int, int, str, str]] = []

    def invoke(
        local: int,
        lineage: int,
        rank_path: Path,
        active_path: Path,
        plan_path: Path,
    ) -> object:
        intent_path = active_path.parent / "intent.json"
        assert intent_path.is_file() and intent_path.stat().st_mode & 0o222 == 0
        intent = json.loads(intent_path.read_bytes())
        rank = _read_vault(rank_path, prepared)
        active = _read_vault(active_path, prepared)
        plan = parse_causal_frontier_plan(plan_path.read_bytes(), active_vault=active)
        assert intent["frontier_plan"] == plan.describe()
        calls.append((local, lineage, rank.sha256, active.sha256))
        return _fake_return()

    capsule = tmp_path / "single-call"
    outcome = _execute(capsule, prepared, invoke)

    assert calls == [
        (
            0,
            16,
            prepared.rank_source.sha256,
            prepared.state.active_projection.sha256,
        )
    ]
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.billed_conflicts == 128
    assert outcome.classification == frontier_run.MECHANISM_ONLY
    assert outcome.mechanism_activated is True
    assert outcome.baseline_trace_changed is True
    assert (capsule / "episodes/00/residency-boundary.json").is_file()
    assert not (capsule / "episodes/01").exists()


def test_globally_novel_clause_is_merged_once_into_complete_attic(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_validator(monkeypatch)
    novel = _clause(900)

    def invoke(
        _local: int,
        _lineage: int,
        _rank_path: Path,
        _active_path: Path,
        _plan_path: Path,
    ) -> object:
        return _fake_return((("new", novel),))

    outcome = _execute(tmp_path / "novel", prepared, invoke)

    assert outcome.classification == frontier_run.NOVEL_CLAUSE_GAIN
    assert outcome.globally_novel_clauses == 1
    assert outcome.final_state.attic.chunks[-1].clauses == (novel,)
    assert len(outcome.final_state.attic.occurrences) == (
        len(prepared.state.attic.occurrences) + 1
    )


@pytest.mark.parametrize(
    ("activated", "trace", "safe_prunes", "classification"),
    (
        (
            True,
            frontier_run.FROZEN_BASELINE_TRACE_SHA256,
            0,
            frontier_run.NO_ACTIVATION,
        ),
        (False, "cd" * 32, 0, frontier_run.NO_ACTIVATION),
        (True, "ef" * 32, 0, frontier_run.MECHANISM_ONLY),
        (True, "12" * 32, 2, frontier_run.SAFE_PRUNE_GAIN),
    ),
)
def test_fixed_baseline_and_safe_prune_classification_are_not_conflated(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
    activated: bool,
    trace: str,
    safe_prunes: int,
    classification: str,
) -> None:
    _install_fake_validator(monkeypatch)

    def invoke(
        _local: int,
        _lineage: int,
        _rank_path: Path,
        _active_path: Path,
        _plan_path: Path,
    ) -> object:
        return _fake_return(
            activated=activated,
            trace_sha256=trace,
            safe_prunes=safe_prunes,
        )

    outcome = _execute(tmp_path / classification, prepared, invoke)
    assert outcome.classification == classification
    assert outcome.mechanism_activated is activated
    assert outcome.baseline_trace_changed is (
        trace != frontier_run.FROZEN_BASELINE_TRACE_SHA256
    )
    assert outcome.safe_threshold_prunes == safe_prunes


def test_invalid_return_consumes_lineage_without_retry(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []

    def invalid(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise frontier_run.O1C76RunError("synthetic invalid native return")

    monkeypatch.setattr(frontier_run, "_validated_episode_result", invalid)

    def invoke(
        local: int,
        lineage: int,
        _rank_path: Path,
        _active_path: Path,
        _plan_path: Path,
    ) -> object:
        calls.append((local, lineage))
        return object()

    outcome = _execute(tmp_path / "invalid", prepared, invoke)

    assert calls == [(0, 16)]
    assert outcome.classification == frontier_run.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.billed_conflicts is None
    assert not (tmp_path / "invalid/episodes/01").exists()


def test_failed_call_publication_recovery_uses_zero_callbacks(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
) -> None:
    calls: list[tuple[int, int]] = []

    def invoke(
        local: int,
        lineage: int,
        _rank_path: Path,
        _active_path: Path,
        _plan_path: Path,
    ) -> object:
        calls.append((local, lineage))
        raise RuntimeError("synthetic terminal call")

    capsule = tmp_path / "failure-recovery"
    outcome = _execute(capsule, prepared, invoke)
    result = frontier_run.build_result(
        outcome=outcome,
        capsule_relative="runs/failure-recovery",
        source_commit="ab" * 20,
        started_at="2026-07-20T00:00:00+02:00",
    )
    frontier_run.write_recovery_source(capsule, result)
    calls_before = tuple(calls)

    recovered = frontier_run.recover_publication(capsule)

    assert tuple(calls) == calls_before == ((0, 16),)
    recovery = cast(Mapping[str, object], recovered["publication_recovery"])
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert recovery["public_verification_calls_issued_during_recovery"] == 0
    assert recovered["classification"] == frontier_run.OPERATIONAL_TERMINAL


def test_sealed_capsule_republishes_result_without_preflight_or_execution(
    tmp_path: Path,
    prepared: frontier_run.PreparedStream,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_validator(monkeypatch)
    capsule_relative = Path("runs") / (
        f"20260720_010000_{frontier_run.CAPSULE_SUFFIX}"
    )
    capsule = tmp_path / capsule_relative

    def invoke(
        _local: int,
        _lineage: int,
        _rank_path: Path,
        _active_path: Path,
        _plan_path: Path,
    ) -> object:
        return _fake_return()

    outcome = _execute(capsule, prepared, invoke)
    result = frontier_run.build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit="bc" * 20,
        started_at="2026-07-20T01:00:00+02:00",
    )
    frontier_run.write_recovery_source(capsule, result)
    authoritative = tmp_path / frontier_run.RESULT_RELATIVE
    frontier_run.finalize_capsule(capsule, authoritative, result)
    authoritative.unlink()
    forbidden: list[str] = []
    monkeypatch.setattr(frontier_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(
        frontier_run,
        "preflight",
        lambda *_args, **_kwargs: forbidden.append("preflight"),
    )
    monkeypatch.setattr(
        frontier_run,
        "execute_stream",
        lambda **_kwargs: forbidden.append("execute"),
    )

    republished = frontier_run.run(tmp_path / "missing.json")

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
    monkeypatch.setattr(frontier_run.resource, "getrusage", lambda _kind: usage)
    monkeypatch.setattr(frontier_run.time, "perf_counter", lambda: 11.0)
    monkeypatch.setattr(frontier_run.time, "process_time", lambda: 7.0)
    monkeypatch.setattr(frontier_run.sys, "platform", platform)

    resources = frontier_run._runtime_resources(
        started=10.0,
        cpu_started=5.0,
        child_started=cast(frontier_run.resource.struct_rusage, started_usage),
    )
    assert resources["runner_peak_rss_bytes"] == expected_peak
