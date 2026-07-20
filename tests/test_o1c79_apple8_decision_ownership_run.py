from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from pathlib import Path
from typing import Callable, Mapping, cast

import pytest

import o1_crypto_lab.o1c79_apple8_decision_ownership_run as ownership_run
from o1_crypto_lab.causal_attic_v1 import (
    ClauseOccurrence,
    canonical_json_bytes,
    reproject_causal_attic,
)
from o1_crypto_lab.causal_frontier_v1 import (
    CAUSAL_FRONTIER_SOURCE_STATE_SCHEMA,
    derive_causal_frontier_plan,
)
from o1_crypto_lab.causal_residency_v1 import initialize_causal_residency
from o1_crypto_lab.o1c79_apple8_decision_ownership_prepare import (
    PreparedDecisionOwnership,
)
from o1_crypto_lab.rescue_prefix_preemption_v1 import RescuePrefixPreemptionPlan
from o1_crypto_lab.residual_polarity_staging_v1 import (
    ResidualPolarityIntersection,
    ResidualPolarityOverlay,
    ResidualPolarityStagingPlan,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
)
from o1_crypto_lab.vault_ranked_decision_v1 import VaultRankedDecision


OBSERVED = tuple(
    sorted(
        set(range(1, 9))
        | {abs(literal) for literal in ownership_run.O1C78_PREFIX_LITERALS}
    )
)
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="o1c79-runner-synthetic-bound-v1",
    threshold=ownership_run.THRESHOLD,
)


def _clause(mask: int) -> ThresholdNoGoodClause:
    return ThresholdNoGoodClause(
        tuple(
            variable if mask & (1 << index) else -variable
            for index, variable in enumerate(OBSERVED)
        )
    )


def _occurrence(index: int, clause: ThresholdNoGoodClause) -> ClauseOccurrence:
    witness = struct.pack("<d", float(index + 1))
    return ClauseOccurrence(
        stream_id="synthetic-o1c79",
        source_index=index,
        classification="new",
        source="trail_upper_bound",
        witness_score_f64le_hex=witness.hex(),
        clause=clause,
        clause_sha256=clause.sha256,
        witness_sha256=hashlib.sha256(
            b"\x01" + witness + clause.serialized
        ).hexdigest(),
    )


@pytest.fixture(scope="module")
def prepared(tmp_path_factory: pytest.TempPathFactory) -> PreparedDecisionOwnership:
    clauses = tuple(_clause(mask) for mask in range(300))
    rank = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses)
    occurrences = tuple(
        _occurrence(index, clause) for index, clause in enumerate(clauses)
    )
    attic = reproject_causal_attic((rank,), occurrences, active_limit=256)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=tuple(range(256)),
        inherited_event_indices=(),
        parent_lineage_ordinal=18,
        first_lineage_ordinal=19,
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
    frontier = derive_causal_frontier_plan(
        source_result=source,
        active_vault=state.active_projection,
        selected_union_indices=state.current_projection.selected_union_indices,
    )
    rank_literals = (1, -2, 3, -4, 5, -6, 7, -8)
    effective_rank_literals = (1, 2, 3, 4, 5, -6, 7, -8)
    rank_payload = struct.pack("<8i", *rank_literals)
    effective_rank_payload = struct.pack("<8i", *effective_rank_literals)
    staging = ResidualPolarityStagingPlan(
        source_result_sha256=hashlib.sha256(source).hexdigest(),
        source_assignment_sha256=hashlib.sha256(assignment).hexdigest(),
        active_vault_sha256=state.active_projection.sha256,
        parent_frontier_plan_sha256=frontier.sha256,
        selected_active_index=frontier.selected_active_index,
        selected_union_index=frontier.selected_union_index,
        selected_clause_sha256=frontier.selected_clause_sha256,
        selected_clause_literal_count=frontier.selected_clause_literal_count,
        source_rank_payload_sha256=hashlib.sha256(rank_payload).hexdigest(),
        source_rank_order_sha256=hashlib.sha256(rank_payload).hexdigest(),
        effective_rank_order_sha256=hashlib.sha256(effective_rank_payload).hexdigest(),
        source_assignment=(0,) * len(OBSERVED),
        source_rank_literals=rank_literals,
        intersections=(
            ResidualPolarityIntersection(0, 1, 1, 1),
            ResidualPolarityIntersection(1, -2, -2, 2),
            ResidualPolarityIntersection(2, 3, 3, 3),
            ResidualPolarityIntersection(3, -4, -4, 4),
            ResidualPolarityIntersection(4, 5, 5, 5),
        ),
        overlays=(
            ResidualPolarityOverlay(1, -2, 2),
            ResidualPolarityOverlay(3, -4, 4),
        ),
    )
    prefix = RescuePrefixPreemptionPlan(ownership_run.O1C78_PREFIX_LITERALS)
    manifest_bytes = canonical_json_bytes({"synthetic": "o1c79-runner"})
    return PreparedDecisionOwnership(
        directory=tmp_path_factory.mktemp("prepared-o1c79"),
        manifest={"synthetic": "o1c79-runner"},
        manifest_bytes=manifest_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        state=state,
        terminal_receipt={"synthetic": True},
        science_input_history={"active_vault_sha256": ["aa" * 32]},
        science_input={
            "lineage_call_ordinal": 19,
            "active_vault_sha256": state.active_projection.sha256,
        },
        frontier_plan=frontier,
        frontier_plan_document={"plan": frontier.describe()},
        frontier_plan_binary=frontier.serialized,
        staging_plan=staging,
        staging_plan_document={"plan": staging.describe()},
        staging_plan_binary=staging.serialized,
        prefix_plan=prefix,
        prefix_plan_document={"plan": prefix.describe()},
        prefix_plan_binary=prefix.serialized,
        rank_decision=cast(VaultRankedDecision, object()),
    )


def _validated(
    *,
    operational: bool = True,
    prefix: bool = True,
    science: bool = False,
    safe_prunes: int = 0,
    novel: int = 0,
    status: int = 0,
    key_model: bytes | None = None,
) -> dict[str, object]:
    central = {"schema": "synthetic-central"}
    ownership = {"schema": "synthetic-ownership"}
    telemetry = {"schema": "synthetic-telemetry"}
    raw = {
        "schema": "synthetic-v17",
        "central_reader": central,
        "decision_ownership": ownership,
        "vault": telemetry,
    }
    return {
        "raw": raw,
        "central_reader": central,
        "decision_ownership": ownership,
        "telemetry": telemetry,
        "occurrences": (),
        "stats": {
            "conflicts": 128,
            "conflicts_before_solve": 0,
            "solve_conflicts": 128,
            "decisions": 64,
            "propagations": 1024,
            "requested_conflicts": 128,
            "unused_requested_conflicts": 0,
            "conflict_limit_overshoot": 0,
            "billed_conflicts": 128,
        },
        "resources": {
            "peak_rss_bytes": 1_000_000,
            "wall_microseconds": 1_000,
            "cpu_microseconds": 900,
        },
        "status": status,
        "key_model": key_model,
        "trace_sha256": "ab" * 32,
        "safe_threshold_prunes": safe_prunes,
        "globally_novel_clause_sha256": [f"{index + 1:064x}" for index in range(novel)],
        "operational_ownership": {
            "operational_ownership_success": operational,
            "proposal_count_alone_is_activation": False,
        },
        "prefix_activation": {
            "qualified_prefix_activation": prefix,
            "proposal_count_alone_is_activation": False,
        },
        "science": {
            "science_gain": science,
            "trace_change_is_science_gain": False,
            "ownership_accounting_is_science_gain": False,
        },
    }


def _execute(
    capsule: Path,
    prepared: PreparedDecisionOwnership,
    invoke: ownership_run.EpisodeInvoker,
) -> ownership_run.DecisionOwnershipOutcome:
    capsule.mkdir()
    return ownership_run.execute_episode(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=lambda model: model == b"k" * 32,
        bindings={"test_fixture": "synthetic-target-free"},
    )


def test_straight_call_persists_intent_and_keeps_three_axes_separate(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(
            operational=True, prefix=False, science=False
        ),
    )
    calls: list[tuple[int, int]] = []

    def invoke(
        local: int,
        lineage: int,
        _rank: Path,
        active: Path,
        _frontier: Path,
        _staging: Path,
        _prefix: Path,
    ) -> object:
        intent = active.parent / "intent.json"
        assert intent.is_file()
        assert intent.stat().st_mode & 0o222 == 0
        document = json.loads(intent.read_bytes())
        assert document["requested_conflicts"] == 128
        assert document["requested_is_not_actual_or_billed"] is True
        calls.append((local, lineage))
        return object()

    outcome = _execute(tmp_path / "straight", prepared, invoke)

    assert calls == [(0, 19)]
    assert outcome.classification == ownership_run.OWNERSHIP_ONLY
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.actual_conflicts == 128
    assert outcome.billed_conflicts == 128
    assert outcome.operational_ownership_success is True
    assert outcome.qualified_prefix_activation is False
    assert outcome.science_gain is False
    assert not (tmp_path / "straight/episodes/01").exists()


@pytest.mark.parametrize(
    ("operational", "prefix", "science", "safe", "novel", "classification"),
    (
        (False, False, False, 0, 0, ownership_run.NO_ACTIVATION),
        (True, False, False, 0, 0, ownership_run.OWNERSHIP_ONLY),
        (True, True, False, 0, 0, ownership_run.MECHANISM_ONLY),
        (False, False, True, 2, 0, ownership_run.SAFE_PRUNE_GAIN),
        (False, False, True, 0, 1, ownership_run.NOVEL_CLAUSE_GAIN),
    ),
)
def test_three_axes_are_not_conflated(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
    operational: bool,
    prefix: bool,
    science: bool,
    safe: int,
    novel: int,
    classification: str,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(
            operational=operational,
            prefix=prefix,
            science=science,
            safe_prunes=safe,
            novel=novel,
        ),
    )
    outcome = _execute(
        tmp_path / classification,
        prepared,
        cast(ownership_run.EpisodeInvoker, lambda *_args: object()),
    )
    assert outcome.classification == classification
    assert outcome.operational_ownership_success is operational
    assert outcome.qualified_prefix_activation is prefix
    assert outcome.science_gain is science


def test_pre_call_failure_burns_page_and_lineage_without_call_or_work_claim(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []

    def reject(_binding: Mapping[str, object] | None, *, when: str) -> None:
        assert when == "before"
        raise ownership_run.O1C79RunError("synthetic pre-call guard")

    monkeypatch.setattr(ownership_run, "_validate_call_window_executable", reject)
    outcome = _execute(
        tmp_path / "pre-call",
        prepared,
        cast(
            ownership_run.EpisodeInvoker,
            lambda local, lineage, *_args: calls.append((local, lineage)),
        ),
    )

    assert calls == []
    assert outcome.classification == ownership_run.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 0
    assert outcome.requested_conflicts == 0
    assert outcome.actual_conflicts is None
    assert outcome.billed_conflicts is None
    episode = outcome.episodes[0]
    failure = cast(Mapping[str, object], episode["terminal_failure"])
    assert failure["phase"] == "PRE_CALL"
    assert failure["lineage_burned"] is True
    assert failure["page6_burned"] is True
    assert failure["requested_conflicts_consumed"] == 0


def test_call_failure_consumes_one_requested_horizon_but_not_actual_or_billed(
    tmp_path: Path, prepared: PreparedDecisionOwnership
) -> None:
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, *_args: object) -> object:
        calls.append((local, lineage))
        raise RuntimeError("synthetic native terminal")

    outcome = _execute(
        tmp_path / "call-failure",
        prepared,
        cast(ownership_run.EpisodeInvoker, invoke),
    )
    assert calls == [(0, 19)]
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.actual_conflicts is None
    assert outcome.billed_conflicts is None
    failure = cast(Mapping[str, object], outcome.episodes[0]["terminal_failure"])
    assert failure["phase"] == "CALL"
    assert failure["native_result_returned"] is False


def test_invalid_post_call_result_suppresses_all_three_axes_and_work_claims(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ownership_run.O1C79RunError("synthetic invalid return")
        ),
    )
    outcome = _execute(
        tmp_path / "post-call",
        prepared,
        cast(ownership_run.EpisodeInvoker, lambda *_args: object()),
    )
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 128
    assert outcome.actual_conflicts is None
    assert outcome.billed_conflicts is None
    assert outcome.operational_ownership_success is False
    assert outcome.qualified_prefix_activation is False
    assert outcome.science_gain is False
    failure = cast(Mapping[str, object], outcome.episodes[0]["terminal_failure"])
    assert failure["phase"] == "POST_CALL"
    assert failure["native_result_returned"] is True


def test_post_call_sidecar_publication_failure_is_terminal_and_not_retried(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(),
    )
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, *_args: object) -> object:
        calls.append((local, lineage))
        return object()

    monkeypatch.setattr(
        ownership_run,
        "_write_evidence",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ownership_run.O1C79RunError("synthetic evidence publication")
        ),
    )
    outcome = _execute(
        tmp_path / "sidecar-failure",
        prepared,
        cast(ownership_run.EpisodeInvoker, invoke),
    )
    assert calls == [(0, 19)]
    assert outcome.native_calls == 1
    assert outcome.actual_conflicts is None
    assert outcome.billed_conflicts is None
    assert not (tmp_path / "sidecar-failure/episodes/01").exists()


@pytest.mark.parametrize("crash_after_markers", (1, 2))
def test_partial_publication_recovery_and_republication_issue_zero_calls(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
    crash_after_markers: int,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(),
    )
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, *_args: object) -> object:
        calls.append((local, lineage))
        return object()

    runs = tmp_path / "runs"
    runs.mkdir()
    capsule_relative = Path("runs") / (
        f"20260720_12000{crash_after_markers}_{ownership_run.CAPSULE_SUFFIX}"
    )
    capsule = tmp_path / capsule_relative
    outcome = _execute(capsule, prepared, cast(ownership_run.EpisodeInvoker, invoke))
    result = ownership_run.build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit="ab" * 20,
        started_at="2026-07-20T12:00:00+02:00",
    )
    ownership_run.write_recovery_source(capsule, result)
    original_publish = ownership_run._publish_exact
    published = 0

    def fail_after_markers(
        path: Path, payload: bytes, *, immutable: bool = True
    ) -> None:
        nonlocal published
        if published == crash_after_markers:
            raise ownership_run.O1C79RunError("synthetic final publication failure")
        original_publish(path, payload, immutable=immutable)
        published += 1

    monkeypatch.setattr(ownership_run, "_publish_exact", fail_after_markers)
    with pytest.raises(ownership_run.O1C79RunError, match="synthetic final"):
        ownership_run.finalize_capsule(
            capsule, tmp_path / ownership_run.RESULT_RELATIVE, result
        )
    assert published == crash_after_markers
    assert (capsule / "RUN.md").is_file()
    assert (capsule / "result.json").is_file() is (crash_after_markers == 2)
    assert not (capsule / "artifacts.sha256").exists()
    monkeypatch.setattr(ownership_run, "_publish_exact", original_publish)
    monkeypatch.setattr(ownership_run, "lab_root", lambda: tmp_path)

    recovered = ownership_run.run(tmp_path / "missing-config.json")
    recovery = cast(Mapping[str, object], recovered["publication_recovery"])
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert recovery["public_verification_calls_issued_during_recovery"] == 0
    assert calls == [(0, 19)]

    authoritative = tmp_path / ownership_run.RESULT_RELATIVE
    authoritative.unlink()
    republished = ownership_run.run(tmp_path / "still-missing-config.json")
    assert republished == recovered
    assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
    assert calls == [(0, 19)]


def test_foreign_partial_publication_bytes_fail_closed_without_deletion(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(),
    )
    capsule = tmp_path / "foreign-partial"
    outcome = _execute(
        capsule,
        prepared,
        cast(ownership_run.EpisodeInvoker, lambda *_args: object()),
    )
    result = ownership_run.build_result(
        outcome=outcome,
        capsule_relative="runs/foreign-partial",
        source_commit="cd" * 20,
    )
    ownership_run.write_recovery_source(capsule, result)
    _, _, run_payload, _, _ = ownership_run._publication_payloads(capsule, result)
    ownership_run._publish_exact(capsule / "RUN.md", run_payload)
    ownership_run._atomic_create(capsule / "result.json", b"{}", immutable=True)

    with pytest.raises(
        ownership_run.O1C79RunError, match="partial publication result.json differs"
    ):
        ownership_run._remove_partial_publication(capsule, result)
    assert (capsule / "RUN.md").is_file()
    assert (capsule / "result.json").read_bytes() == b"{}"


def test_two_successive_interrupted_finalizations_resume_without_a_call(
    tmp_path: Path,
    prepared: PreparedDecisionOwnership,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        ownership_run,
        "_validated_episode_result",
        lambda *_args, **_kwargs: _validated(),
    )
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, *_args: object) -> object:
        calls.append((local, lineage))
        return object()

    runs = tmp_path / "runs"
    runs.mkdir()
    capsule_relative = Path("runs") / (
        f"20260720_130000_{ownership_run.CAPSULE_SUFFIX}"
    )
    capsule = tmp_path / capsule_relative
    outcome = _execute(capsule, prepared, cast(ownership_run.EpisodeInvoker, invoke))
    result = ownership_run.build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit="ef" * 20,
    )
    ownership_run.write_recovery_source(capsule, result)
    original_publish = ownership_run._publish_exact

    def interrupted_after_two() -> Callable[..., None]:
        published = 0

        def publish(path: Path, payload: bytes, *, immutable: bool = True) -> None:
            nonlocal published
            if published == 2:
                raise ownership_run.O1C79RunError("synthetic second interruption")
            original_publish(path, payload, immutable=immutable)
            published += 1

        return publish

    monkeypatch.setattr(ownership_run, "_publish_exact", interrupted_after_two())
    with pytest.raises(ownership_run.O1C79RunError, match="second interruption"):
        ownership_run.finalize_capsule(
            capsule, tmp_path / ownership_run.RESULT_RELATIVE, result
        )
    assert (capsule / "RUN.md").is_file()
    assert (capsule / "result.json").is_file()
    assert not (capsule / ownership_run.PUBLICATION_RECOVERY_NAME).exists()

    monkeypatch.setattr(ownership_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(ownership_run, "_publish_exact", interrupted_after_two())
    with pytest.raises(ownership_run.O1C79RunError, match="second interruption"):
        ownership_run.run(tmp_path / "missing-config.json")
    assert (capsule / ownership_run.PUBLICATION_RECOVERY_NAME).is_file()
    assert (capsule / "RUN.md").is_file()
    assert (capsule / "result.json").is_file()
    assert calls == [(0, 19)]

    monkeypatch.setattr(ownership_run, "_publish_exact", original_publish)
    completed = ownership_run.run(tmp_path / "still-missing-config.json")
    recovery = cast(Mapping[str, object], completed["publication_recovery"])
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert recovery["public_verification_calls_issued_during_recovery"] == 0
    assert (tmp_path / ownership_run.RESULT_RELATIVE).is_file()
    assert calls == [(0, 19)]


def test_frozen_new_identities_are_present_and_old_inputs_are_rejected() -> None:
    assert ownership_run.PAGE6_SHA256 == (
        "69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846"
    )
    assert ownership_run.EXPECTED_PREPARED_MANIFEST_SHA256 == (
        "17ce7568ca16fb6af01d842b9f875176ca3df11ff1ec7496d2d76ab5d2d57b4b"
    )
    assert ownership_run.FRONTIER_PLAN_BINARY_SHA256 == (
        "785cae9e32912e1d45858d046b36a7c7b9e4cf51799f233a7b3246aa6756ad65"
    )
    assert ownership_run.STAGING_PLAN_BINARY_SHA256 == (
        "c536a94483467ee1197d52e0e3f81ad2f728a36ad3982124e1b9966e0011f927"
    )
    assert ownership_run.PREFIX_PLAN_BINARY_SHA256 == (
        "b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c"
    )
    assert ownership_run.EXPECTED_SCIENCE_INPUT_SHA256 == (
        "2c9cb3879d50d104e9c6e8d2ad64f78631f8bc1a69728b8eec93849f9ccefa2a"
    )
    for value in (
        ownership_run.PAGE5_SHA256,
        ownership_run.OLD_FRONTIER_PLAN_SHA256,
        ownership_run.OLD_STAGING_PLAN_SHA256,
    ):
        with pytest.raises(ownership_run.O1C79RunError, match="consumed"):
            ownership_run._reject_consumed_identity(value, "fixture")


def test_page6_is_next_but_not_a_consumed_science_input() -> None:
    history = {
        "science_input_count": 8,
        "science_input_sha256": list(ownership_run.SCIENCE_INPUT_SHA256_HISTORY),
        "o1c78_consumed_sha256": ownership_run.PAGE5_SHA256,
        "o1c78_consumed_lineage_ordinal": 18,
        "next_active_sha256": ownership_run.PAGE6_SHA256,
        "next_lineage_ordinal": 19,
        "next_active_absent_from_history": True,
        "all_history_entries_unique": True,
        "page5_replay_authorized": False,
        "retry_authorized": False,
    }
    ownership_run._validate_science_input_history(history)

    reused = dict(history)
    reused["science_input_sha256"] = [
        *ownership_run.SCIENCE_INPUT_SHA256_HISTORY[:-1],
        ownership_run.PAGE6_SHA256,
    ]
    with pytest.raises(ownership_run.O1C79RunError, match="history"):
        ownership_run._validate_science_input_history(reused)


def test_native_include_closure_binds_header_and_every_transitive_source() -> None:
    assert ownership_run.NATIVE_INCLUDE_CLOSURE == (
        "native_v17",
        "decision_ownership_header",
        "native_v16",
        "native_v15",
        "native_v14",
        "native_v12",
        "native_v11",
        "native_v6",
        "native_base",
    )
    digests = {
        name: hashlib.sha256(name.encode()).hexdigest()
        for name in ownership_run.NATIVE_INCLUDE_CLOSURE
    }
    frozen = ownership_run._native_source_closure_sha256(digests)
    changed = dict(digests)
    changed["decision_ownership_header"] = "ff" * 32
    assert ownership_run._native_source_closure_sha256(changed) != frozen
    assert (
        ownership_run._native_source_closure_sha256(
            {**digests, "native_v17": "PENDING"}, pending=True
        )
        == "PENDING"
    )


def test_commit_guard_rejects_unenumerated_transitive_runtime_mutation(
    tmp_path: Path,
) -> None:
    package = tmp_path / "src/o1_crypto_lab"
    native = tmp_path / "native"
    package.mkdir(parents=True)
    native.mkdir()
    (package / "bound.py").write_text("BOUND = 1\n")
    (package / "transitive.py").write_text("VALUE = 1\n")
    (native / "solver.cpp").write_text("int main() { return 0; }\n")

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-q")
    git("config", "user.email", "o1c79@example.invalid")
    git("config", "user.name", "O1C79 Fixture")
    git("add", ".")
    git("commit", "-qm", "source freeze")
    frozen = git("rev-parse", "HEAD")
    (tmp_path / "config.json").write_text("{}\n")
    git("add", "config.json")
    git("commit", "-qm", "configuration only")
    configuration_commit = git("rev-parse", "HEAD")
    ownership_run._validate_runtime_source_freeze(
        tmp_path,
        expected_commit=frozen,
        execution_commit=configuration_commit,
    )

    (package / "transitive.py").write_text("VALUE = 2\n")
    git("add", "src/o1_crypto_lab/transitive.py")
    git("commit", "-qm", "mutate unenumerated runtime dependency")
    changed = git("rev-parse", "HEAD")
    with pytest.raises(ownership_run.O1C79RunError, match="changed after"):
        ownership_run._validate_runtime_source_freeze(
            tmp_path,
            expected_commit=frozen,
            execution_commit=changed,
        )
