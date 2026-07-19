from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, cast

import pytest

import o1_crypto_lab.o1c68_apple8_complementary_phase_run as phase_run


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c68_apple8_complementary_phase_v1.json"

ParentState = tuple[
    dict[str, object],
    phase_run._o1c65.FrozenGrouping,
    phase_run.ImportedParentVault,
]


@pytest.fixture(scope="module")
def sealed_parent() -> ParentState:
    config = phase_run.load_config(CONFIG)
    potential = phase_run._o1c66._geometry_smoke_potential_path(ROOT)
    frozen = phase_run._o1c65.build_frozen_grouping(potential, config)
    imported = phase_run.validate_parent_and_import_vault(ROOT, config, frozen)
    return config, frozen, imported


def _fake_v10_result(
    vault: phase_run._o1c66.ClauseVault,
    *,
    reader: Mapping[str, object] | None = None,
) -> SimpleNamespace:
    selected_reader = dict(reader or phase_run.READER_BINDING)
    identity = vault.identity.describe()
    telemetry = {
        "schema": phase_run.NATIVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": phase_run._o1c66.VAULT_MAGIC.hex(),
        "semantic_rule": phase_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
        "identity_rule": phase_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
        "clause_encoding": (
            phase_run._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        ),
        "input_certification_rule": (
            phase_run._native_v10.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        ),
        "maximum_payload_bytes": phase_run._o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
        "maximum_clause_count": phase_run._o1c66.VAULT_MAXIMUM_CLAUSES,
        "maximum_literal_count": phase_run._o1c66.VAULT_MAXIMUM_LITERALS,
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
        "fully_emitted_clause_count": 0,
        "fully_emitted_literal_count": 0,
        "emitted_new_clause_count": 0,
        "emitted_new_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "terminal_empty_clause_count": 0,
        "pending_clause_exported": False,
        "next_vault_available": True,
        "next_vault_terminal_reason": None,
        "next_vault_sha256": vault.sha256,
        "next_serialized_bytes": vault.serialized_bytes,
        "next_clause_count": len(vault.clauses),
        "next_literal_count": vault.literal_count,
    }
    stats = {
        "conflicts": 514,
        "conflicts_before_solve": 0,
        "solve_conflicts": 514,
        "decisions": 4_200,
        "propagations": 1_100_000,
        "requested_conflicts": 512,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 2,
        "billed_conflicts": 514,
    }
    return SimpleNamespace(
        status=0,
        conflict_limit=phase_run.REQUESTED_CONFLICTS,
        threshold=phase_run.THRESHOLD,
        key_model=None,
        reader=selected_reader,
        stats=stats,
        resources={
            "wall_microseconds": 200_000,
            "cpu_microseconds": 180_000,
            "peak_rss_bytes": 300_000_000,
        },
        sieve={
            "minimum_upper_bound": 8.5,
            "root_upper_bound": 262.68644197084643,
            "external_clauses_emitted": 0,
            "pending_clause_count": 0,
        },
        raw={
            "schema": phase_run.NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                phase_run.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "reader": dict(selected_reader),
        },
        input_vault=vault,
        eligible_emitted_clauses=(),
        next_vault=vault,
        vault_telemetry=telemetry,
    )


def _copy_sealed_parent(tmp_path: Path) -> Path:
    result_destination = tmp_path / phase_run.PARENT_RESULT_RELATIVE
    result_destination.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / phase_run.PARENT_RESULT_RELATIVE, result_destination)
    for relative in (
        Path("artifacts.sha256"),
        phase_run.PARENT_RETAINED_VAULT_RELATIVE,
        Path("result.json"),
    ):
        source = ROOT / phase_run.PARENT_CAPSULE_RELATIVE / relative
        destination = tmp_path / phase_run.PARENT_CAPSULE_RELATIVE / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return tmp_path


def _execute(
    tmp_path: Path,
    imported: phase_run.ImportedParentVault,
    invoke: phase_run.EpisodeInvoker,
) -> phase_run.SingleContinuationOutcome:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("public verification is valid only for SAT")

    return phase_run.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"reader": dict(phase_run.READER_BINDING)},
    )


def test_config_and_real_parent_bind_exact_reader_and_vault(
    sealed_parent: ParentState,
) -> None:
    config, frozen, imported = sealed_parent
    reader = cast(Mapping[str, object], config["reader"])
    parent = cast(Mapping[str, object], config["parent"])

    assert frozen.grouping.sha256 == phase_run.GROUPING_SHA256
    assert reader == phase_run.READER_BINDING
    assert type(reader["phase"]) is int
    assert reader["phase"] == 0
    assert reader["forcephase"] is True
    assert reader["reader_spec_sha256"] == phase_run.READER_SPEC_SHA256
    assert parent["known_completed_billed_conflicts"] == 1539
    assert parent["failed_call_billed_conflicts"] is None
    assert parent["lineage_actual_billed_conflicts"] is None
    assert imported.payload == imported.independent.to_bytes()
    assert imported.payload == imported.adapter.serialized
    assert imported.independent.sha256 == phase_run.PARENT_RETAINED_VAULT_SHA256
    assert len(imported.independent.clauses) == 12
    assert imported.independent.literal_count == 35_061


@pytest.mark.parametrize("tampered", ("result", "manifest", "vault"))
def test_parent_result_manifest_and_vault_tamper_fail_closed(
    tmp_path: Path,
    sealed_parent: ParentState,
    tampered: str,
) -> None:
    config, frozen, _imported = sealed_parent
    root = _copy_sealed_parent(tmp_path)
    if tampered == "result":
        path = root / phase_run.PARENT_RESULT_RELATIVE
    else:
        path = root / phase_run.PARENT_CAPSULE_RELATIVE
        path /= (
            "artifacts.sha256"
            if tampered == "manifest"
            else phase_run.PARENT_RETAINED_VAULT_RELATIVE
        )
    payload = path.read_bytes()
    path.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))

    with pytest.raises(phase_run.O1C68ParentError):
        phase_run.validate_parent_and_import_vault(root, config, frozen)


def test_ordinal_four_is_persisted_once_and_observed_514_is_accepted(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        invocation_path = capsule / "invocation.json"
        intent_path = capsule / "episodes/00/intent.json"
        invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        assert invocation["lineage_call_ordinal"] == 4
        assert intent["lineage_call_ordinal"] == 4
        assert invocation["reader"] == phase_run.READER_BINDING
        assert intent["reader"] == phase_run.READER_BINDING
        assert intent["invocation_sha256"] == phase_run.sha256_file(invocation_path)
        assert vault.is_file()
        calls.append((local_ordinal, lineage_ordinal))
        return _fake_v10_result(imported.independent)

    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("UNKNOWN must not invoke public verification")

    outcome = phase_run.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"reader": dict(phase_run.READER_BINDING)},
    )

    assert calls == [(0, 4)]
    assert all(lineage != 3 for _local, lineage in calls)
    assert outcome.classification == phase_run.COMPLEMENTARY_PHASE_NO_GAIN
    assert outcome.native_calls == 1
    assert outcome.billed_conflicts == 514
    work = cast(Mapping[str, object], outcome.episode["work_and_resources"])
    assert work["solve_conflicts"] == 514
    assert work["billed_conflicts"] == 514
    assert work["conflict_limit_overshoot"] == 2
    assert not (capsule / "episodes/01").exists()


@pytest.mark.parametrize("location", ("result", "raw"))
def test_wrong_v10_reader_is_terminal_and_never_retried(
    tmp_path: Path,
    sealed_parent: ParentState,
    location: str,
) -> None:
    _config, _frozen, imported = sealed_parent
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        result = _fake_v10_result(imported.independent)
        forged = dict(phase_run.READER_BINDING)
        forged["phase"] = 1
        if location == "result":
            result.reader = forged
        else:
            cast(dict[str, object], result.raw)["reader"] = forged
        return result

    outcome = _execute(tmp_path, imported, invoke)

    assert calls == [(0, 4)]
    assert outcome.classification == phase_run.INVALID_RESULT_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.billed_conflicts is None
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["retry_authorized"] is False
    assert not (tmp_path / "capsule" / "episodes/01").exists()


def test_completed_publication_recovers_without_a_second_call(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    root = tmp_path
    capsule = root / "runs" / f"20260719_160000_{phase_run.CAPSULE_SUFFIX}"
    capsule.mkdir(parents=True)
    authoritative = root / phase_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        return _fake_v10_result(imported.independent)

    outcome = _execute_in_existing_capsule(capsule, imported, invoke)
    result = phase_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row={"reader": dict(phase_run.READER_BINDING)},
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T16:00:00+02:00",
    )
    phase_run._atomic_json(capsule / phase_run.PUBLICATION_SOURCE_NAME, result)

    def fail_after_seal() -> None:
        raise RuntimeError("publication-failure-sentinel")

    with pytest.raises(RuntimeError, match="publication-failure-sentinel"):
        phase_run.finalize_capsule(
            capsule,
            authoritative,
            result,
            _after_capsule_seal=fail_after_seal,
        )

    recovered = phase_run.recover_publication(
        root=root,
        capsule=capsule,
        authoritative=authoritative,
        cause=RuntimeError("publication-failure-sentinel"),
    )
    failure = cast(Mapping[str, object], recovered["operational_failure"])
    resources = cast(Mapping[str, object], recovered["resources"])
    assert calls == [(0, 4)]
    assert recovered["classification"] == phase_run.OPERATIONAL_TERMINAL
    assert failure["native_calls_issued_during_recovery"] == 0
    assert resources["native_solver_calls"] == 1
    assert resources["publication_recovery_native_solver_calls"] == 0
    assert authoritative.is_file()
    assert (capsule / "artifacts.sha256").is_file()


@pytest.mark.parametrize(
    "relative",
    (
        "invocation.json",
        "vault-imported.bin",
        "episodes/00/intent.json",
        "episodes/00/native_result.json",
        "episodes/00/vault_telemetry.json",
        "episodes/00/vault-output.bin",
    ),
)
def test_publication_recovery_rejects_drifted_completed_sidecars(
    tmp_path: Path,
    sealed_parent: ParentState,
    relative: str,
) -> None:
    _config, _frozen, imported = sealed_parent
    root = tmp_path
    capsule = root / "runs" / f"20260719_160100_{phase_run.CAPSULE_SUFFIX}"
    capsule.mkdir(parents=True)
    authoritative = root / phase_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        return _fake_v10_result(imported.independent)

    outcome = _execute_in_existing_capsule(capsule, imported, invoke)
    result = phase_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row={"reader": dict(phase_run.READER_BINDING)},
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T16:01:00+02:00",
    )
    phase_run._atomic_json(capsule / phase_run.PUBLICATION_SOURCE_NAME, result)
    path = capsule / relative
    payload = path.read_bytes()
    path.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))

    with pytest.raises(phase_run.O1C68RunError, match="recovery"):
        phase_run.recover_publication(
            root=root,
            capsule=capsule,
            authoritative=authoritative,
            cause=RuntimeError("publication-failure-sentinel"),
        )

    assert calls == [(0, 4)]
    assert not authoritative.exists()


def test_publication_recovery_rejects_drifted_native_failure_evidence(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    root = tmp_path
    capsule = root / "runs" / f"20260719_160200_{phase_run.CAPSULE_SUFFIX}"
    capsule.mkdir(parents=True)
    authoritative = root / phase_run.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        raise RuntimeError("native-failure-sentinel")

    outcome = _execute_in_existing_capsule(capsule, imported, invoke)
    result = phase_run._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row={"reader": dict(phase_run.READER_BINDING)},
        outcome=outcome,
        runtime={"elapsed_seconds": 1.0},
        started_at="2026-07-19T16:02:00+02:00",
    )
    phase_run._atomic_json(capsule / phase_run.PUBLICATION_SOURCE_NAME, result)
    evidence = capsule / "episodes/00/native_execution_failure.json"
    payload = evidence.read_bytes()
    evidence.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))

    with pytest.raises(phase_run.O1C68RunError, match="recovery"):
        phase_run.recover_publication(
            root=root,
            capsule=capsule,
            authoritative=authoritative,
            cause=RuntimeError("publication-failure-sentinel"),
        )

    assert calls == [(0, 4)]
    assert not authoritative.exists()


def _execute_in_existing_capsule(
    capsule: Path,
    imported: phase_run.ImportedParentVault,
    invoke: phase_run.EpisodeInvoker,
) -> phase_run.SingleContinuationOutcome:
    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("UNKNOWN must not invoke public verification")

    return phase_run.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"reader": dict(phase_run.READER_BINDING)},
    )
