from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, cast

import pytest

import o1_crypto_lab.o1c67_apple8_episodic_vault_continuation_run as continuation


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c67_apple8_episodic_vault_continuation_v1.json"

ParentState = tuple[
    dict[str, object],
    continuation._o1c65.FrozenGrouping,
    continuation.ImportedParentVault,
]


@pytest.fixture(scope="module")
def sealed_parent() -> ParentState:
    """Use only the public potential and already sealed O1C-0066 evidence."""

    config = continuation.load_config(CONFIG)
    potential = continuation._o1c66._geometry_smoke_potential_path(ROOT)
    frozen = continuation._o1c65.build_frozen_grouping(potential, config)
    imported = continuation.validate_parent_and_import_vault(ROOT, config, frozen)
    return config, frozen, imported


def _fake_v9_result(
    vault: continuation._o1c66.ClauseVault,
) -> SimpleNamespace:
    identity = vault.identity.describe()
    stats = {
        "conflicts": 514,
        "conflicts_before_solve": 0,
        "solve_conflicts": 514,
        "decisions": 4_000,
        "propagations": 1_000_000,
        "requested_conflicts": 512,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 2,
        "billed_conflicts": 514,
    }
    telemetry = {
        "schema": continuation.NATIVE_VAULT_TELEMETRY_SCHEMA,
        "binary_magic_hex": continuation._o1c66.VAULT_MAGIC.hex(),
        "semantic_rule": (continuation._vault_v1.THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE),
        "identity_rule": (continuation._vault_v1.THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE),
        "clause_encoding": (
            continuation._vault_v1.THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        ),
        "input_certification_rule": (
            continuation._native_v9.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        ),
        "maximum_payload_bytes": continuation._o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
        "maximum_clause_count": continuation._o1c66.VAULT_MAXIMUM_CLAUSES,
        "maximum_literal_count": continuation._o1c66.VAULT_MAXIMUM_LITERALS,
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
    return SimpleNamespace(
        status=0,
        conflict_limit=continuation.REQUESTED_CONFLICTS,
        threshold=continuation.THRESHOLD,
        key_model=None,
        stats=stats,
        resources={
            "wall_microseconds": 200_000,
            "cpu_microseconds": 180_000,
            "peak_rss_bytes": 300_000_000,
        },
        sieve={
            "minimum_upper_bound": 12.5,
            "root_upper_bound": 262.68644197084643,
            "external_clauses_emitted": 0,
            "pending_clause_count": 0,
        },
        raw={
            "schema": continuation.NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                continuation.NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
        },
        input_vault=vault,
        eligible_emitted_clauses=(),
        next_vault=vault,
        vault_telemetry=telemetry,
    )


def _execute(
    tmp_path: Path,
    imported: continuation.ImportedParentVault,
    invoke: continuation.EpisodeInvoker,
) -> continuation.SingleContinuationOutcome:
    capsule = tmp_path / "capsule"
    capsule.mkdir()

    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("a target verifier must not run in target-free tests")

    return continuation.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"target_free_test": True},
    )


def _copy_sealed_parent(tmp_path: Path) -> Path:
    capsule_files = (
        Path("artifacts.sha256"),
        continuation.PARENT_RETAINED_VAULT_RELATIVE,
        continuation.PARENT_FAILED_INTENT_RELATIVE,
        continuation.PARENT_TERMINAL_FAILURE_RELATIVE,
        Path("result.json"),
    )
    result_destination = tmp_path / continuation.PARENT_RESULT_RELATIVE
    result_destination.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / continuation.PARENT_RESULT_RELATIVE, result_destination)
    for relative in capsule_files:
        source = ROOT / continuation.PARENT_CAPSULE_RELATIVE / relative
        destination = tmp_path / continuation.PARENT_CAPSULE_RELATIVE / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    return tmp_path


def test_frozen_config_loads_without_calls_or_writes() -> None:
    config = continuation.load_config(CONFIG)
    invocation = cast(Mapping[str, object], config["invocation"])
    native = cast(Mapping[str, object], config["native"])

    assert config["schema"] == continuation.CONFIG_SCHEMA
    assert invocation["local_episode_ordinal"] == 0
    assert invocation["lineage_call_ordinal"] == 3
    assert invocation["parent_ordinal_replay_authorized"] is False
    assert native["requested_conflicts"] == 512
    assert native["billing_rule"] == "actual-nonnegative-solve-conflicts"
    assert "maximum_billed_conflicts" not in native


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("native", "seed", 1),
        ("input", "truth_reveal", "runs/forged/reveal.json"),
        ("frozen_sha256", "truth_reveal", "00" * 32),
    ),
)
def test_claim_bearing_config_rows_are_frozen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    section: str,
    field: str,
    value: object,
) -> None:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    cast(dict[str, object], config[section])[field] = value
    path = tmp_path / CONFIG.name
    path.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setattr(continuation, "lab_root", lambda: tmp_path)

    with pytest.raises(continuation.O1C67RunError, match="frozen O1C-0067"):
        continuation.load_config(path)


def test_real_sealed_parent_is_dual_parsed_from_public_grouping(
    sealed_parent: ParentState,
) -> None:
    _config, frozen, imported = sealed_parent

    assert frozen.grouping.sha256 == continuation.GROUPING_SHA256
    assert imported.source_path == (
        ROOT
        / continuation.PARENT_CAPSULE_RELATIVE
        / continuation.PARENT_RETAINED_VAULT_RELATIVE
    )
    assert imported.payload == imported.independent.to_bytes()
    assert imported.payload == imported.adapter.serialized
    assert imported.independent.sha256 == continuation.PARENT_RETAINED_VAULT_SHA256
    assert (
        len(imported.independent.clauses) == continuation.PARENT_RETAINED_VAULT_CLAUSES
    )
    assert (
        imported.independent.literal_count
        == continuation.PARENT_RETAINED_VAULT_LITERALS
    )


@pytest.mark.parametrize("tampered", ("vault", "manifest"))
def test_tampered_parent_sidecar_or_manifest_is_rejected_from_a_copy(
    tmp_path: Path,
    sealed_parent: ParentState,
    tampered: str,
) -> None:
    config, frozen, _imported = sealed_parent
    root = _copy_sealed_parent(tmp_path)
    capsule = root / continuation.PARENT_CAPSULE_RELATIVE
    if tampered == "vault":
        path = capsule / continuation.PARENT_RETAINED_VAULT_RELATIVE
        payload = path.read_bytes()
        path.write_bytes(payload[:-1] + bytes((payload[-1] ^ 1,)))
    else:
        path = capsule / "artifacts.sha256"
        path.write_bytes(path.read_bytes() + b"#")

    with pytest.raises(continuation.O1C67ParentError):
        continuation.validate_parent_and_import_vault(root, config, frozen)


def test_execute_persists_new_ordinals_once_and_bills_observed_514(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    capsule = tmp_path / "capsule"
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        invocation_path = capsule / "invocation.json"
        intent_path = capsule / "episodes/00/intent.json"
        assert invocation_path.is_file()
        assert intent_path.is_file()
        invocation = json.loads(invocation_path.read_text(encoding="utf-8"))
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        assert invocation["local_episode_ordinal"] == 0
        assert invocation["lineage_call_ordinal"] == 3
        assert intent["local_episode_ordinal"] == 0
        assert intent["lineage_call_ordinal"] == 3
        assert intent["invocation_sha256"] == continuation.sha256_file(invocation_path)
        assert vault.is_file()
        calls.append((local_ordinal, lineage_ordinal))
        return _fake_v9_result(imported.independent)

    capsule.mkdir()

    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("public verification is not valid for UNKNOWN")

    outcome = continuation.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"target_free_test": True},
    )

    assert calls == [(0, 3)]
    assert all(lineage != 2 for _local, lineage in calls)
    assert outcome.classification == continuation.SATURATED_NO_GAIN
    assert outcome.native_calls == 1
    assert outcome.requested_conflicts == 512
    assert outcome.billed_conflicts == 514
    work = cast(Mapping[str, object], outcome.episode["work_and_resources"])
    assert work["solve_conflicts"] == 514
    assert work["billed_conflicts"] == 514
    assert work["conflict_limit_overshoot"] == 2
    assert not (capsule / "episodes/01").exists()


def test_completed_call_publication_recovers_without_a_second_native_call(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    root = tmp_path
    capsule = root / "runs" / f"20260719_150000_{continuation.CAPSULE_SUFFIX}"
    capsule.mkdir(parents=True)
    authoritative = root / continuation.RESULT_RELATIVE
    authoritative.parent.mkdir(parents=True)
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        return _fake_v9_result(imported.independent)

    def forbidden_verifier(_key: bytes) -> bool:
        raise AssertionError("public verifier must not run for UNKNOWN")

    outcome = continuation.execute_single_continuation(
        capsule=capsule,
        imported_vault=imported.independent,
        adapter_vault=imported.adapter,
        invoke_episode=invoke,
        verify_public_model=forbidden_verifier,
        bindings={"target_free_test": True},
    )
    result = continuation._result(
        capsule_relative=capsule.relative_to(root),
        source_commit="ab" * 20,
        preflight_row={"target_free_test": True},
        outcome=outcome,
        runtime={"wall_seconds": 1.0},
        started_at="2026-07-19T15:00:00+02:00",
    )
    continuation._atomic_json(capsule / continuation.PUBLICATION_SOURCE_NAME, result)

    def fail_after_seal() -> None:
        raise RuntimeError("publication-failure-sentinel")

    with pytest.raises(RuntimeError, match="publication-failure-sentinel"):
        continuation.finalize_capsule(
            capsule,
            authoritative,
            result,
            _after_capsule_seal=fail_after_seal,
        )

    assert not authoritative.exists()
    assert not (capsule / "artifacts.sha256").exists()
    recovered = continuation.recover_publication(
        root=root,
        capsule=capsule,
        authoritative=authoritative,
        cause=RuntimeError("publication-failure-sentinel"),
    )

    failure = cast(Mapping[str, object], recovered["operational_failure"])
    resources = cast(Mapping[str, object], recovered["resources"])
    assert calls == [(0, 3)]
    assert recovered["classification"] == continuation.OPERATIONAL_TERMINAL
    assert recovered["stop_reason"] == "publication-recovery"
    assert failure["original_science_classification"] == (
        continuation.SATURATED_NO_GAIN
    )
    assert failure["native_calls_issued_during_recovery"] == 0
    assert resources["native_solver_calls"] == 1
    assert resources["publication_recovery_native_solver_calls"] == 0
    assert authoritative.is_file()
    assert (capsule / "artifacts.sha256").is_file()


def test_invoke_exception_is_terminal_and_bounds_full_stdout_evidence(
    tmp_path: Path,
    sealed_parent: ParentState,
) -> None:
    _config, _frozen, imported = sealed_parent
    full_stdout = b"x" * (continuation.MAXIMUM_FAILURE_STREAM_BYTES + 257)
    calls: list[tuple[int, int]] = []

    class FakeNativeFailure(RuntimeError):
        stdout: bytes
        stderr: bytes
        returncode: int
        command: list[str]

        def __init__(self, message: str, stdout: bytes) -> None:
            super().__init__(message)
            self.stdout = stdout
            self.stderr = b"bounded stderr"
            self.returncode = -9
            self.command = ["fake-native", "--target-free"]

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        raise FakeNativeFailure("fake native stopped", full_stdout)

    outcome = _execute(tmp_path, imported, invoke)
    capsule = tmp_path / "capsule"
    evidence = json.loads(
        (capsule / "episodes/00/native_execution_failure.json").read_text(
            encoding="utf-8"
        )
    )
    stdout = cast(Mapping[str, object], evidence["stdout"])
    sidecar = capsule / "episodes/00" / cast(str, stdout["artifact"])

    assert calls == [(0, 3)]
    assert outcome.classification == continuation.OPERATIONAL_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.billed_conflicts is None
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["retry_authorized"] is False
    assert stdout["bytes"] == len(full_stdout)
    assert stdout["sha256"] == hashlib.sha256(full_stdout).hexdigest()
    assert stdout["persisted_bytes"] == continuation.MAXIMUM_FAILURE_STREAM_BYTES
    assert stdout["truncated"] is True
    assert (
        sidecar.read_bytes() == full_stdout[: continuation.MAXIMUM_FAILURE_STREAM_BYTES]
    )
    assert not (capsule / "episodes/01").exists()


@pytest.mark.parametrize("malformed", ("native_ledger", "resource_ledger"))
def test_malformed_native_or_resource_ledger_is_invalid_and_never_retried(
    tmp_path: Path,
    sealed_parent: ParentState,
    malformed: str,
) -> None:
    _config, _frozen, imported = sealed_parent
    calls: list[tuple[int, int]] = []

    def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        del vault
        calls.append((local_ordinal, lineage_ordinal))
        result = _fake_v9_result(imported.independent)
        if malformed == "native_ledger":
            cast(dict[str, object], result.stats)["billed_conflicts"] = 513
        else:
            cast(dict[str, object], result.resources)["peak_rss_bytes"] = True
        return result

    outcome = _execute(tmp_path, imported, invoke)
    capsule = tmp_path / "capsule"

    assert calls == [(0, 3)]
    assert outcome.classification == continuation.INVALID_RESULT_TERMINAL
    assert outcome.native_calls == 1
    assert outcome.billed_conflicts is None
    assert outcome.operational_failure is not None
    assert outcome.operational_failure["native_result_returned"] is True
    assert outcome.operational_failure["retry_authorized"] is False
    assert not (capsule / "episodes/01").exists()
