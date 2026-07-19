from __future__ import annotations

import hashlib
import json
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, cast

import pytest

import o1_crypto_lab.o1c73_apple8_vault_release_contrast_run as release_run


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c73_apple8_vault_release_contrast_v1.json"

ParentState = tuple[
    dict[str, object],
    release_run._o1c65.FrozenGrouping,
    release_run.ImportedParentVault,
    dict[str, object],
]


@pytest.fixture(scope="module")
def sealed_parent() -> ParentState:
    config = release_run.load_config(CONFIG)
    potential = release_run._o1c66._geometry_smoke_potential_path(ROOT)
    frozen = release_run._o1c65.build_frozen_grouping(potential, config)
    imported = release_run.validate_parent_and_import_vault(ROOT, config, frozen)
    reader = release_run._release_reader_binding(
        imported.ranked_decision, "test reader"
    )
    return config, frozen, imported, reader


def _bytes_fields(prefix: str, payload: bytes) -> dict[str, object]:
    return {
        f"{prefix}_hex": payload.hex(),
        f"{prefix}_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _rank_state(indices: range | tuple[int, ...]) -> bytes:
    state = bytearray(32)
    for index in indices:
        state[index // 8] |= 1 << (index % 8)
    return bytes(state)


def _sequence_fields(prefix: str, literals: tuple[int, ...]) -> dict[str, object]:
    payload = b"".join(struct.pack("<i", literal) for literal in literals)
    return {
        f"{prefix}_encoding": (
            release_run._native_v15.VAULT_RANKED_DECISION_SEQUENCE_ENCODING
        ),
        f"{prefix}_count": len(literals),
        f"{prefix}_bytes": len(payload),
        **_bytes_fields(prefix, payload),
    }


def _state_fields(prefix: str, state: bytes) -> dict[str, object]:
    return {
        f"{prefix}_bits": 256,
        f"{prefix}_bytes": 32,
        f"{prefix}_encoding": (
            release_run._native_v15.VAULT_RANKED_DECISION_STATE_ENCODING
        ),
        **_bytes_fields(prefix, state),
    }


def _native_reader(
    reader: Mapping[str, object], *, active: bool = True
) -> dict[str, object]:
    ranked = tuple(cast(list[int], reader["ranked_literals"]))
    if active:
        original = ranked
        released = ranked
        contrasts = tuple(-literal for literal in ranked)
        cursor = len(ranked)
        calls = 2 * len(ranked) + 1
        all_state = _rank_state(range(len(ranked)))
        events = [
            {
                "call": index + 1,
                "kind": "original",
                "rank_index": index,
                "literal": literal,
                "next_callback_observed": True,
                "assignment_burst_to_next_callback": 1,
            }
            for index, literal in enumerate(ranked)
        ] + [
            {
                "call": len(ranked) + index + 1,
                "kind": "contrast",
                "rank_index": index,
                "literal": -literal,
                "next_callback_observed": True,
                "assignment_burst_to_next_callback": 1,
            }
            for index, literal in enumerate(ranked)
        ]
        pairs = [
            {
                "rank_index": index,
                "variable": abs(literal),
                "original_literal": literal,
                "contrast_literal": -literal,
                "original_return_call": index + 1,
                "original_release_after_call": len(ranked),
                "original_release_level": 0,
                "contrast_return_call": len(ranked) + index + 1,
                "contrast_release_after_call": None,
                "contrast_release_level": None,
            }
            for index, literal in enumerate(ranked)
        ]
        callback = original + contrasts + (0,)
        returned = b"".join(struct.pack("<i", literal) for literal in callback)
        original_count = len(original)
        contrast_count = len(contrasts)
        release_count = len(released)
        zero_count = 1
        first_parent = original_count + 1
        first_final = calls
        live_guidance = 4 + 6 * 32 + 2 * release_count
    else:
        original = released = contrasts = ()
        cursor = calls = original_count = contrast_count = release_count = 0
        zero_count = 0
        first_parent = first_final = None
        all_state = bytes(32)
        events = []
        pairs = []
        returned = b""
        live_guidance = 4 + 6 * 32
    empty_state = bytes(32)
    deferred_runtime: dict[str, object] = {}
    if (
        "contrast_deferred_assigned"
        in release_run._native_v15._RUNTIME_READER_FIELDS
    ):
        deferred_runtime = {
            "contrast_deferred_assigned": 0,
            **_state_fields("contrast_deferred_assigned_state", empty_state),
        }
    return {
        **dict(reader),
        "decision_rule": release_run._native_v15.VAULT_RANKED_DECISION_DECISION_RULE,
        "callback_rule": release_run._native_v15.VAULT_RANKED_DECISION_CALLBACK_RULE,
        "cursor": cursor,
        "rows_consumed": cursor,
        "original_once_returns": original_count,
        "skipped_preassigned": 0,
        "released_original": release_count,
        "contrast_enqueued": release_count,
        "contrast_returns": contrast_count,
        "contrast_releases": 0,
        "paired_variables": contrast_count,
        "variable_second_decisions": contrast_count,
        "same_signed_redecisions": 0,
        "solver_phase_calls": 0,
        "cb_decide_calls": calls,
        "cb_decide_nonzero": original_count + contrast_count,
        "cb_decide_zero": zero_count,
        "first_parent_fallback_call": first_parent,
        "first_final_fallback_call": first_final,
        "queue_size": 0,
        "maximum_queue_size": release_count,
        "assignment_literals_observed": len(events),
        **deferred_runtime,
        **_state_fields("consumed_state", all_state),
        **_state_fields("original_returned_state", all_state),
        **_state_fields("original_released_state", all_state),
        **_state_fields("contrast_enqueued_state", all_state),
        **_state_fields("contrast_returned_state", all_state),
        **_state_fields("contrast_released_state", empty_state),
        **_sequence_fields("original_return_sequence", original),
        **_sequence_fields("original_release_sequence", released),
        **_sequence_fields("contrast_return_sequence", contrasts),
        **_sequence_fields("contrast_release_sequence", ()),
        "returned_sequence_encoding": (
            release_run._native_v15.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        ),
        "returned_sequence_count": calls,
        "returned_sequence_bytes": len(returned),
        "returned_sequence_sha256": hashlib.sha256(returned).hexdigest(),
        "nonzero_event_rule": (
            release_run._native_v15.VAULT_RANKED_DECISION_NONZERO_EVENT_RULE
        ),
        "nonzero_return_events": events,
        "pair_record_rule": (
            release_run._native_v15.VAULT_RANKED_DECISION_PAIR_RECORD_RULE
        ),
        "pair_records": pairs,
        "bounded_state_rule": (
            release_run._native_v15.VAULT_RANKED_DECISION_BOUNDED_STATE_RULE
        ),
        "bounded_guidance_state_bytes": 706,
        "live_guidance_state_bytes": live_guidance,
        "bounded_telemetry_state_bytes": (
            33_490 if deferred_runtime else 33_458
        ),
    }

def _fake_v15_result(
    vault: release_run._o1c66.ClauseVault,
    reader: Mapping[str, object],
    *,
    status: int = 0,
    active: bool = True,
    eligible_clauses: tuple[tuple[int, ...], ...] = (),
    key_model: bytes | None = None,
    propagations: int = 60_000_000,
) -> SimpleNamespace:
    native_reader = _native_reader(reader, active=active)
    identity = vault.identity.describe()
    next_vault, novel, duplicates = vault.append_emitted(eligible_clauses)
    assert duplicates == 0
    assert len(novel) == len(eligible_clauses)
    eligible_literals = sum(len(clause) for clause in eligible_clauses)
    telemetry = {
        "schema": release_run.NATIVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": release_run._o1c66.VAULT_MAGIC.hex(),
        "semantic_rule": release_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
        "identity_rule": release_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
        "clause_encoding": (
            release_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        ),
        "input_certification_rule": (
            release_run._native_v15.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        ),
        "maximum_payload_bytes": release_run._o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
        "maximum_clause_count": release_run._o1c66.VAULT_MAXIMUM_CLAUSES,
        "maximum_literal_count": release_run._o1c66.VAULT_MAXIMUM_LITERALS,
        "input_sha256": vault.sha256,
        "input_serialized_bytes": vault.serialized_bytes,
        "input_clause_count": len(vault.clauses),
        "input_literal_count": vault.literal_count,
        "input_clause_aggregate_sha256": vault.aggregate_clause_sha256,
        "validated_input_clause_count": len(vault.clauses),
        "validated_input_literal_count": vault.literal_count,
        "validated_input_clause_aggregate_sha256": vault.aggregate_clause_sha256,
        "input_cnf_sha256": identity["cnf_sha256"],
        "input_potential_sha256": identity["potential_sha256"],
        "input_grouping_sha256": identity["grouping_sha256"],
        "input_observed_variables_sha256": identity["observed_variables_sha256"],
        "input_bound_rule_sha256": identity["bound_rule_sha256"],
        "input_threshold_f64le_hex": identity["threshold_f64le_hex"],
        "preloaded_clause_count": len(vault.clauses),
        "preloaded_literal_count": vault.literal_count,
        "fully_emitted_clause_count": len(eligible_clauses),
        "fully_emitted_literal_count": eligible_literals,
        "emitted_new_clause_count": len(eligible_clauses),
        "emitted_new_literal_count": eligible_literals,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "terminal_empty_clause_count": 0,
        "pending_clause_exported": False,
        "next_vault_available": True,
        "next_vault_terminal_reason": None,
        "next_vault_sha256": next_vault.sha256,
        "next_serialized_bytes": next_vault.serialized_bytes,
        "next_clause_count": len(next_vault.clauses),
        "next_literal_count": next_vault.literal_count,
    }
    stats = {
        "conflicts": 514,
        "conflicts_before_solve": 0,
        "solve_conflicts": 514,
        "decisions": 2_500,
        "propagations": propagations,
        "requested_conflicts": 512,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 2,
        "billed_conflicts": 514,
    }
    return SimpleNamespace(
        status=status,
        conflict_limit=release_run.REQUESTED_CONFLICTS,
        threshold=release_run.THRESHOLD,
        key_model=key_model,
        reader=native_reader,
        stats=stats,
        resources={
            "wall_microseconds": 200_000,
            "cpu_microseconds": 180_000,
            "peak_rss_bytes": 300_000_000,
        },
        sieve={
            "minimum_upper_bound": 8.5,
            "root_upper_bound": 262.68644197084643,
            "external_clauses_emitted": len(eligible_clauses),
            "pending_clause_count": 0,
            "cb_decide_calls": 1 if active else 0,
            "cb_decide_nonzero": 0,
        },
        raw={
            "schema": release_run.NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                release_run.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "reader": dict(native_reader),
        },
        input_vault=vault,
        eligible_emitted_clauses=eligible_clauses,
        next_vault=next_vault,
        vault_telemetry=telemetry,
    )


def _write_test_freeze(
    capsule: Path, reader: Mapping[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    expected = cast(
        dict[str, object], cast(dict[str, object], config["source"])["expected_sha256"]
    )
    source_paths = cast(dict[str, object], config["source"])
    for name in release_run.SOURCE_NAMES:
        expected[name] = release_run.sha256_file(ROOT / cast(str, source_paths[name]))
    native = cast(dict[str, object], config["native"])
    native["expected_source_sha256"] = expected["native_source"]
    native["expected_executable_sha256"] = "55" * 32
    gates = cast(dict[str, object], config["target_free_gates"])
    gates.update(
        {
            "final_preflight_sha256": "11" * 32,
            "reader_spec_sha256": release_run.READER_SPEC_SHA256,
            "public_fixture_sha256": "22" * 32,
            "deterministic_native_repeat_sha256": "33" * 32,
            "deterministic_adapter_repeat_sha256": "44" * 32,
        }
    )
    release_run._atomic_json(capsule / "config.json", config)
    config_sha256 = release_run.sha256_file(capsule / "config.json")
    source_commit = "ab" * 20
    preflight: dict[str, object] = {
        "schema": release_run.PREFLIGHT_SCHEMA,
        "attempt_id": release_run.ATTEMPT_ID,
        "ok": True,
        "ready_for_science": True,
        "source_commit": source_commit,
        "source_commit_bound": True,
        "source_tree_clean": True,
        "config_sha256": config_sha256,
        "source_sha256": dict(expected),
        "unresolved_source_hashes": [],
        "unresolved_gate_hashes": [],
        "adapter_source_sha256": expected["joint_score_sieve_v15"],
        "native_source_sha256": expected["native_source"],
        "native_adapter_schema": release_run.NATIVE_ADAPTER_SCHEMA,
        "native_result_schema": release_run.NATIVE_RESULT_SCHEMA,
        "native_implementation_parent_schema": (
            release_run.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        ),
        "native_decision_telemetry_schema": (
            release_run.NATIVE_DECISION_TELEMETRY_SCHEMA
        ),
        "reader": dict(reader),
        "rank_source": dict(release_run.RANK_SOURCE_BINDING),
        "final_target_free_preflight": {
            "path": release_run.TARGET_FREE_PREFLIGHT_RELATIVE.as_posix(),
            "expected_sha256": gates["final_preflight_sha256"],
            "observed_sha256": gates["final_preflight_sha256"],
            "present": True,
            "validated": True,
            "frozen": True,
        },
        "local_episode_ordinal": release_run.LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": release_run.LINEAGE_CALL_ORDINAL,
        "native_solver_calls": 0,
        "files_written": 0,
        "truth_key_bytes_read": False,
    }
    release_run._atomic_json(capsule / "preflight.json", preflight)
    native_build = {
        "source_sha256": native["expected_source_sha256"],
        "executable_sha256": native["expected_executable_sha256"],
    }
    release_run._atomic_json(capsule / "native_build.json", native_build)
    bindings: dict[str, object] = {
        "source_commit": source_commit,
        "config_sha256": config_sha256,
        "source_sha256": dict(expected),
        "adapter_source_sha256": expected["joint_score_sieve_v15"],
        "native_source_sha256": expected["native_source"],
        "native_executable_sha256": native["expected_executable_sha256"],
        "final_target_free_preflight_sha256": gates["final_preflight_sha256"],
        "reader": dict(reader),
    }
    return preflight, bindings


def _execute(
    capsule: Path,
    imported: release_run.ImportedParentVault,
    reader: Mapping[str, object],
    invoke: release_run.EpisodeInvoker,
    *,
    verifier: Callable[[bytes], bool] | None = None,
) -> release_run.SingleContinuationOutcome:
    capsule.mkdir(parents=True)
    _preflight, bindings = _write_test_freeze(capsule, reader)
    return release_run.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        ranked_decision=imported.ranked_decision,
        invoke_episode=invoke,
        verify_public_model=verifier or (lambda _model: False),
        bindings=bindings,
    )


def test_config_renames_baseline_alias_and_seals_parent_rank(
    sealed_parent: ParentState,
) -> None:
    config, frozen, imported, reader = sealed_parent
    original = json.loads(json.dumps(config))
    compatibility = release_run._baseline_compat_config(config)

    assert "frozen_sha256" not in config
    assert config["apple8_baseline_attempt_id"] == "APPLE-VIEW-0008-MATCHED"
    assert compatibility["frozen_sha256"] == config["apple8_baseline_sha256"]
    assert config == original
    assert frozen.grouping.sha256 == release_run.GROUPING_SHA256
    assert imported.independent.sha256 == release_run.PARENT_RETAINED_VAULT_SHA256
    assert imported.ranked_decision.order_sha256 == release_run.RANKED_ORDER_SHA256
    assert imported.ranked_decision.rank_table_sha256 == (
        release_run.RANKED_TABLE_SHA256
    )
    assert imported.ranked_decision.zero_delta_variables == (241,)
    assert len(cast(list[object], reader["ranked_literals"])) == 255
    assert 241 not in {
        abs(value) for value in cast(list[int], reader["ranked_literals"])
    }


def test_target_free_gate_is_frozen_and_required_for_science() -> None:
    config = release_run.load_config(CONFIG)
    gate, digest, frozen = release_run.validate_final_target_free_preflight(
        ROOT, config, required=False
    )
    assert gate is not None
    assert digest == config["target_free_gates"]["final_preflight_sha256"]
    assert frozen is True
    assert (ROOT / release_run.TARGET_FREE_PREFLIGHT_RELATIVE).is_file()
    assert release_run.validate_final_target_free_preflight(
        ROOT, config, required=True
    ) == (gate, digest, True)


def test_pair_count_and_low_work_are_no_gain_but_novel_and_recovery_classify(
    tmp_path: Path, sealed_parent: ParentState
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    calls: list[tuple[int, int]] = []

    def normal(local: int, lineage: int, _vault: Path) -> object:
        calls.append((local, lineage))
        return _fake_v15_result(imported.independent, reader)

    no_gain = _execute(tmp_path / "normal", imported, reader, normal)
    assert calls == [(0, 9)]
    assert no_gain.classification == release_run.VAULT_RELEASE_CONTRAST_NO_GAIN
    assert no_gain.episode["release_contrast_active"] is True
    assert (tmp_path / "normal/episodes/00/decision_telemetry.json").is_file()

    low_work = _execute(
        tmp_path / "low-work",
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v15_result(
            imported.independent,
            reader,
            propagations=1,
        ),
    )
    telemetry = cast(Mapping[str, object], low_work.episode["decision_telemetry"])
    assert low_work.classification == release_run.VAULT_RELEASE_CONTRAST_NO_GAIN
    assert low_work.stop_reason == (
        "no-verified-recovery-novel-exclusion-or-status20-frontier-proof"
    )
    assert telemetry["paired_variables"] == 255
    assert telemetry["pair_count_alone_is_cryptanalytic_gain"] is False
    assert telemetry["low_work_alone_is_cryptanalytic_gain"] is False

    existing = set(imported.independent.clauses)
    novel = next(
        (literal,)
        for variable in sorted(imported.independent.observed_variables)
        for literal in (variable, -variable)
        if (literal,) not in existing
    )
    gain = _execute(
        tmp_path / "gain",
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v15_result(
            imported.independent, reader, eligible_clauses=(novel,)
        ),
    )
    assert gain.classification == (
        release_run.VAULT_RELEASE_CONTRAST_NOVEL_CLAUSE_GAIN
    )

    model = bytes(range(32))
    recovery = _execute(
        tmp_path / "public",
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v15_result(
            imported.independent, reader, status=10, key_model=model
        ),
        verifier=lambda candidate: candidate == model,
    )
    assert recovery.classification == release_run.PUBLIC_EXACT_RECOVERY
    assert (
        cast(Mapping[str, object], recovery.episode["public_model"])["verified_8_of_8"]
        is True
    )


def test_inactive_returned_result_is_invalid_and_never_retried(
    tmp_path: Path, sealed_parent: ParentState
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    calls: list[tuple[int, int]] = []

    def inactive(local: int, lineage: int, _vault: Path) -> object:
        calls.append((local, lineage))
        return _fake_v15_result(imported.independent, reader, active=False)

    outcome = _execute(tmp_path / "invalid", imported, reader, inactive)
    assert calls == [(0, 9)]
    assert outcome.classification == release_run.INVALID_RESULT_TERMINAL
    assert outcome.billed_conflicts is None
    assert not (tmp_path / "invalid/episodes/01").exists()


def test_status20_retains_imported_vault_and_archives_no_derived_output(
    tmp_path: Path, sealed_parent: ParentState
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    outcome = _execute(
        tmp_path / "status20",
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v15_result(
            imported.independent, reader, status=20, active=False
        ),
    )

    assert outcome.classification == release_run.THRESHOLD_REGION_EXHAUSTED
    assert outcome.stop_reason == "frozen-score-region-exhausted"
    assert outcome.final_vault == imported.independent
    assert outcome.episode["output_vault"] is None
    assert outcome.episode["output_vault_archived"] is False
    assert outcome.episode["status20_exceptional_no_retry_audit"] is True
    assert not (tmp_path / "status20/episodes/00/vault-output.bin").exists()


@pytest.mark.parametrize("mode", ("normal", "status20", "invalid", "operational"))
def test_publication_recovery_revalidates_every_terminal_without_a_call(
    tmp_path: Path,
    sealed_parent: ParentState,
    mode: str,
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    root = tmp_path / mode
    capsule = root / "runs" / f"20260719_190000_{release_run.CAPSULE_SUFFIX}"
    authoritative = root / release_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, _vault: Path) -> object:
        calls.append((local, lineage))
        if mode == "operational":
            raise RuntimeError("native-failure-sentinel")
        return _fake_v15_result(
            imported.independent,
            reader,
            status=20 if mode == "status20" else 0,
            active=mode not in {"status20", "invalid"},
        )

    outcome = _execute(capsule, imported, reader, invoke)
    preflight = release_run._read_json(
        capsule / "preflight.json", "test preflight"
    )
    result = release_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row=preflight,
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T19:00:00+02:00",
    )
    release_run._atomic_json(capsule / release_run.PUBLICATION_SOURCE_NAME, result)

    recovered = release_run.recover_publication(
        root=root,
        capsule=capsule,
        authoritative=authoritative,
        cause=RuntimeError("publication-failure-sentinel"),
    )
    recovery = cast(Mapping[str, object], recovered["publication_recovery"])
    assert calls == [(0, 9)]
    assert recovered["classification"] == outcome.classification
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert authoritative.is_file()
    assert (capsule / "artifacts.sha256").is_file()


def test_publication_recovery_rejects_a_draft_gate_capsule(
    tmp_path: Path, sealed_parent: ParentState
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    root = tmp_path / "draft"
    capsule = root / "runs" / f"20260719_190000_{release_run.CAPSULE_SUFFIX}"
    authoritative = root / release_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    outcome = _execute(
        capsule,
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v15_result(
            imported.independent, reader
        ),
    )
    preflight = release_run._read_json(
        capsule / "preflight.json", "test preflight"
    )
    result = release_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row=preflight,
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T19:00:00+02:00",
    )
    release_run._atomic_json(capsule / release_run.PUBLICATION_SOURCE_NAME, result)
    config = dict(
        release_run._read_json(capsule / "config.json", "test frozen config")
    )
    gates = dict(cast(Mapping[str, object], config["target_free_gates"]))
    gates["final_preflight_sha256"] = "PENDING"
    config["target_free_gates"] = gates
    (capsule / "config.json").write_bytes(
        release_run._canonical_json_bytes(config)
    )

    with pytest.raises(release_run.O1C73RunError, match="target-free freeze"):
        release_run.recover_publication(
            root=root,
            capsule=capsule,
            authoritative=authoritative,
            cause=None,
        )
    assert not authoritative.exists()


def test_baseline_tamper_immediately_before_invoker_never_enters_adapter(
    tmp_path: Path,
    sealed_parent: ParentState,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _config, frozen, imported, reader = sealed_parent
    cnf = tmp_path / "input.cnf"
    potential = tmp_path / "input.potential"
    grouping = tmp_path / "input.grouping"
    vault = tmp_path / "vault.bin"
    executable = tmp_path / "native-joint-score-sieve"
    shutil.copyfile(
        ROOT
        / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
        / "artifacts/cnf/full256-eight-block-apple-view-0008.cnf",
        cnf,
    )
    shutil.copyfile(release_run._o1c66._geometry_smoke_potential_path(ROOT), potential)
    grouping.write_bytes(frozen.grouping.serialized)
    vault.write_bytes(imported.payload)
    executable.write_bytes(b"not-entered")
    payload = potential.read_bytes()
    potential.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))
    adapter_calls: list[object] = []
    monkeypatch.setattr(
        release_run._native_v15,
        "run_joint_score_sieve",
        lambda **kwargs: adapter_calls.append(kwargs),
    )

    with pytest.raises(Exception, match="frozen native-call input identity"):
        release_run.invoke_native_episode(
            executable=executable,
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            vault=vault,
            expected_reader=reader,
        )
    assert adapter_calls == []
