from __future__ import annotations

import hashlib
import json
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Mapping, cast

import pytest

import o1_crypto_lab.o1c71_apple8_vault_ranked_decision_run as ranked_run


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c71_apple8_vault_ranked_decision_v1.json"

ParentState = tuple[
    dict[str, object],
    ranked_run._o1c65.FrozenGrouping,
    ranked_run.ImportedParentVault,
    dict[str, object],
]


@pytest.fixture(scope="module")
def sealed_parent() -> ParentState:
    config = ranked_run.load_config(CONFIG)
    potential = ranked_run._o1c66._geometry_smoke_potential_path(ROOT)
    frozen = ranked_run._o1c65.build_frozen_grouping(potential, config)
    imported = ranked_run.validate_parent_and_import_vault(ROOT, config, frozen)
    reader = ranked_run._validate_reader(
        imported.ranked_decision.reader_binding(), "test reader"
    )
    return config, frozen, imported, reader


def _native_reader(
    reader: Mapping[str, object], *, active: bool = True
) -> dict[str, object]:
    literals = cast(list[int], reader["ranked_literals"])
    sequence = struct.pack("<i", literals[0]) if active else b""
    return {
        **dict(reader),
        "decision_rule": ranked_run._native_v13.VAULT_RANKED_DECISION_DECISION_RULE,
        "callback_rule": ranked_run._native_v13.VAULT_RANKED_DECISION_CALLBACK_RULE,
        "cb_decide_calls": 1 if active else 0,
        "cb_decide_nonzero": 1 if active else 0,
        "cb_decide_zero": 0,
        "returned_sequence_encoding": (
            ranked_run._native_v13.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        ),
        "returned_sequence_count": 1 if active else 0,
        "returned_sequence_bytes": len(sequence),
        "returned_sequence_hex": sequence.hex(),
        "returned_sequence_sha256": hashlib.sha256(sequence).hexdigest(),
        "unique_returned_variables": 1 if active else 0,
        "redecisions": 0,
        "first_fallback_call": None,
        "solver_phase_calls": 0,
    }


def _fake_v13_result(
    vault: ranked_run._o1c66.ClauseVault,
    reader: Mapping[str, object],
    *,
    status: int = 0,
    active: bool = True,
    eligible_clauses: tuple[tuple[int, ...], ...] = (),
    key_model: bytes | None = None,
) -> SimpleNamespace:
    native_reader = _native_reader(reader, active=active)
    identity = vault.identity.describe()
    next_vault, novel, duplicates = vault.append_emitted(eligible_clauses)
    assert duplicates == 0
    assert len(novel) == len(eligible_clauses)
    eligible_literals = sum(len(clause) for clause in eligible_clauses)
    telemetry = {
        "schema": ranked_run.NATIVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": ranked_run._o1c66.VAULT_MAGIC.hex(),
        "semantic_rule": ranked_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
        "identity_rule": ranked_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
        "clause_encoding": (
            ranked_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        ),
        "input_certification_rule": (
            ranked_run._native_v13.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        ),
        "maximum_payload_bytes": ranked_run._o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
        "maximum_clause_count": ranked_run._o1c66.VAULT_MAXIMUM_CLAUSES,
        "maximum_literal_count": ranked_run._o1c66.VAULT_MAXIMUM_LITERALS,
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
        "propagations": 1_180_000,
        "requested_conflicts": 512,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 2,
        "billed_conflicts": 514,
    }
    return SimpleNamespace(
        status=status,
        conflict_limit=ranked_run.REQUESTED_CONFLICTS,
        threshold=ranked_run.THRESHOLD,
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
        },
        raw={
            "schema": ranked_run.NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                ranked_run.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "reader": dict(native_reader),
        },
        input_vault=vault,
        eligible_emitted_clauses=eligible_clauses,
        next_vault=next_vault,
        vault_telemetry=telemetry,
    )


def _execute(
    capsule: Path,
    imported: ranked_run.ImportedParentVault,
    reader: Mapping[str, object],
    invoke: ranked_run.EpisodeInvoker,
    *,
    verifier: Callable[[bytes], bool] | None = None,
) -> ranked_run.SingleContinuationOutcome:
    capsule.mkdir(parents=True)
    return ranked_run.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=verifier or (lambda _model: False),
        bindings={"reader": dict(reader)},
    )


def test_config_renames_baseline_alias_and_seals_parent_rank(
    sealed_parent: ParentState,
) -> None:
    config, frozen, imported, reader = sealed_parent
    original = json.loads(json.dumps(config))
    compatibility = ranked_run._baseline_compat_config(config)

    assert "frozen_sha256" not in config
    assert config["apple8_baseline_attempt_id"] == "APPLE-VIEW-0008-MATCHED"
    assert compatibility["frozen_sha256"] == config["apple8_baseline_sha256"]
    assert config == original
    assert frozen.grouping.sha256 == ranked_run.GROUPING_SHA256
    assert imported.independent.sha256 == ranked_run.PARENT_RETAINED_VAULT_SHA256
    assert imported.ranked_decision.order_sha256 == ranked_run.RANKED_ORDER_SHA256
    assert imported.ranked_decision.rank_table_sha256 == (
        ranked_run.RANKED_TABLE_SHA256
    )
    assert imported.ranked_decision.zero_delta_variables == (241,)
    assert len(cast(list[object], reader["ranked_literals"])) == 255
    assert 241 not in {
        abs(value) for value in cast(list[int], reader["ranked_literals"])
    }


def test_active_normal_gain_and_public_model_classification(
    tmp_path: Path, sealed_parent: ParentState
) -> None:
    _config, _frozen, imported, reader = sealed_parent
    calls: list[tuple[int, int]] = []

    def normal(local: int, lineage: int, _vault: Path) -> object:
        calls.append((local, lineage))
        return _fake_v13_result(imported.independent, reader)

    no_gain = _execute(tmp_path / "normal", imported, reader, normal)
    assert calls == [(0, 7)]
    assert no_gain.classification == ranked_run.VAULT_RANKED_DECISION_NO_GAIN
    assert no_gain.episode["ranked_decision_active"] is True
    assert (tmp_path / "normal/episodes/00/decision_telemetry.json").is_file()

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
        lambda _local, _lineage, _vault: _fake_v13_result(
            imported.independent, reader, eligible_clauses=(novel,)
        ),
    )
    assert gain.classification == ranked_run.VAULT_RANKED_DECISION_GAIN

    model = bytes(range(32))
    recovery = _execute(
        tmp_path / "public",
        imported,
        reader,
        lambda _local, _lineage, _vault: _fake_v13_result(
            imported.independent, reader, status=10, key_model=model
        ),
        verifier=lambda candidate: candidate == model,
    )
    assert recovery.classification == ranked_run.PUBLIC_EXACT_RECOVERY
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
        return _fake_v13_result(imported.independent, reader, active=False)

    outcome = _execute(tmp_path / "invalid", imported, reader, inactive)
    assert calls == [(0, 7)]
    assert outcome.classification == ranked_run.INVALID_RESULT_TERMINAL
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
        lambda _local, _lineage, _vault: _fake_v13_result(
            imported.independent, reader, status=20, active=False
        ),
    )

    assert outcome.classification == ranked_run.THRESHOLD_REGION_EXHAUSTED
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
    capsule = root / "runs" / f"20260719_190000_{ranked_run.CAPSULE_SUFFIX}"
    authoritative = root / ranked_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local: int, lineage: int, _vault: Path) -> object:
        calls.append((local, lineage))
        if mode == "operational":
            raise RuntimeError("native-failure-sentinel")
        return _fake_v13_result(
            imported.independent,
            reader,
            status=20 if mode == "status20" else 0,
            active=mode not in {"status20", "invalid"},
        )

    outcome = _execute(capsule, imported, reader, invoke)
    result = ranked_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row={"reader": dict(reader)},
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T19:00:00+02:00",
    )
    ranked_run._atomic_json(capsule / ranked_run.PUBLICATION_SOURCE_NAME, result)

    recovered = ranked_run.recover_publication(
        root=root,
        capsule=capsule,
        authoritative=authoritative,
        cause=RuntimeError("publication-failure-sentinel"),
    )
    recovery = cast(Mapping[str, object], recovered["publication_recovery"])
    assert calls == [(0, 7)]
    assert recovered["classification"] == outcome.classification
    assert recovery["native_calls_issued_during_recovery"] == 0
    assert authoritative.is_file()
    assert (capsule / "artifacts.sha256").is_file()


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
    shutil.copyfile(ranked_run._o1c66._geometry_smoke_potential_path(ROOT), potential)
    grouping.write_bytes(frozen.grouping.serialized)
    vault.write_bytes(imported.payload)
    executable.write_bytes(b"not-entered")
    payload = potential.read_bytes()
    potential.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))
    adapter_calls: list[object] = []
    monkeypatch.setattr(
        ranked_run._native_v13,
        "run_joint_score_sieve",
        lambda **kwargs: adapter_calls.append(kwargs),
    )

    with pytest.raises(Exception, match="frozen native-call input identity"):
        ranked_run.invoke_native_episode(
            executable=executable,
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            vault=vault,
            expected_reader=reader,
        )
    assert adapter_calls == []
