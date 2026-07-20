from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c78_apple8_rescue_prefix_preemption_prepare as prepare
from o1_crypto_lab.causal_frontier_v1 import (
    parse_causal_frontier_plan,
    validate_causal_frontier_plan,
)
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay
from o1_crypto_lab.rescue_prefix_preemption_v1 import (
    parse_rescue_prefix_preemption_plan,
    rescue_prefix_order_bytes,
    validate_o1c78_production_plan,
)
from o1_crypto_lab.residual_polarity_staging_v1 import (
    parse_residual_polarity_staging_plan,
    validate_residual_polarity_staging_plan,
)


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class LoadedPreparation:
    directory: Path
    prepared: prepare.PreparedRescuePrefixPreemption


@pytest.fixture(scope="module")
def loaded_preparation(
    tmp_path_factory: pytest.TempPathFactory,
) -> LoadedPreparation:
    directory = tmp_path_factory.mktemp("o1c78-real-parent") / "seed"
    with pytest.MonkeyPatch.context() as monkeypatch:
        def forbid_process(*args: object, **kwargs: object) -> object:
            raise AssertionError("zero-call preparation launched a process")

        monkeypatch.setattr(subprocess, "run", forbid_process)
        manifest = prepare.prepare_o1c78_rescue_prefix_preemption(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=directory,
        )
    payload = (directory / prepare.MANIFEST_NAME).read_bytes()
    assert manifest == json.loads(payload)
    assert hashlib.sha256(payload).hexdigest() == (
        prepare.EXPECTED_PREPARED_MANIFEST_SHA256
    )
    prepared = prepare.load_prepared_rescue_prefix_preemption(
        directory,
        expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
    )
    return LoadedPreparation(directory, prepared)


def test_real_parent_replay_is_exact_and_zero_call(
    loaded_preparation: LoadedPreparation,
) -> None:
    prepared = loaded_preparation.prepared
    state = prepared.state
    validate_activation_replay(state)

    assert [chunk.clause_count for chunk in state.attic.chunks] == [
        202,
        311,
        0,
        37,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    assert state.attic.union_vault.clause_count == 550
    assert state.attic.union_vault.literal_count == 1_488_224
    assert len(state.attic.occurrences) == 558
    assert state.attic.duplicate_occurrence_count == 8
    assert prepared.rank_source.sha256 == prepare.RANK_SOURCE_SHA256
    assert prepared.active_projection.sha256 == prepare.PAGE5_SHA256
    assert prepared.active_projection.clause_count == 256
    assert prepared.active_projection.literal_count == 654_465
    assert prepared.active_projection.serialized_bytes == 2_619_075
    assert state.current_projection.lineage_ordinal == 18
    assert state.never_resident_undominated_indices == ()
    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
    }


def test_frontier_is_exact_o1c76_control_rebound_to_page5(
    loaded_preparation: LoadedPreparation,
) -> None:
    prepared = loaded_preparation.prepared
    plan = prepared.frontier_plan
    validate_causal_frontier_plan(plan, active_vault=prepared.active_projection)

    assert plan.sha256 == prepare.FRONTIER_PLAN_BINARY_SHA256
    assert plan.serialized_bytes == 4_479
    assert plan.source_result_sha256 == prepare.CONTROL_SOURCE_RESULT_SHA256
    assert plan.source_assignment_sha256 == prepare.SOURCE_ASSIGNMENT_SHA256
    assert plan.source_assignment_sha256 != (
        prepare.PARENT_TERMINAL_ASSIGNMENT_SHA256
    )
    assert prepared.control_source_assignment == prepared.source_assignment
    assert hashlib.sha256(prepared.source_assignment).hexdigest() == (
        prepare.SOURCE_ASSIGNMENT_SHA256
    )
    assert plan.active_vault_sha256 == prepare.PAGE5_SHA256
    assert plan.selected_active_index == 232
    assert plan.selected_union_index == 526
    assert plan.selected_clause_sha256 == prepare.SELECTED_CLAUSE_SHA256
    assert (
        plan.false_literal_count,
        plan.true_literal_count,
        plan.unassigned_literal_count,
    ) == (2_409, 0, 29)
    assert plan.selected_clause_literal_count == 2_438
    assert plan.residual_clause_literals == (
        105,
        -106,
        -129,
        -130,
        131,
        -31873,
        -31874,
        63009,
        63745,
        -63746,
        -190563,
        -190565,
        -190566,
        -190568,
        -190569,
        -191209,
        -191210,
        -191211,
        -191212,
        -191213,
        -191214,
        -191215,
        -191216,
        -191233,
        -191234,
        222434,
        223063,
        223081,
        -223106,
    )
    assert plan.falsifying_decision_literals == tuple(
        -literal for literal in plan.residual_clause_literals
    )
    parsed = parse_causal_frontier_plan(
        prepared.frontier_plan_binary,
        active_vault=prepared.active_projection,
    )
    assert parsed == plan


def test_staging_plan_is_exact_page5_control_overlay(
    loaded_preparation: LoadedPreparation,
) -> None:
    prepared = loaded_preparation.prepared
    plan = prepared.staging_plan
    validate_residual_polarity_staging_plan(
        plan,
        active_vault=prepared.active_projection,
        rank_decision=prepared.rank_decision,
    )

    assert plan.sha256 == prepare.STAGING_PLAN_BINARY_SHA256
    assert plan.serialized_bytes == prepare.STAGING_PLAN_BINARY_BYTES
    assert plan.parent_frontier_plan_sha256 == prepare.FRONTIER_PLAN_BINARY_SHA256
    assert plan.source_result_sha256 == prepare.CONTROL_SOURCE_RESULT_SHA256
    assert plan.source_assignment_sha256 == prepare.SOURCE_ASSIGNMENT_SHA256
    assert plan.active_vault_sha256 == prepare.PAGE5_SHA256
    assert plan.effective_rank_order_sha256 == (
        prepare.EFFECTIVE_RANK_ORDER_SHA256
    )
    assert tuple(row.rank_index for row in plan.intersections) == (
        prepare.INTERSECTION_RANK_INDICES
    )
    assert tuple(row.rank_index for row in plan.overlays) == (
        prepare.OVERLAY_RANK_INDICES
    )
    assert tuple(
        (row.source_literal, row.effective_literal) for row in plan.overlays
    ) == ((131, -131), (-130, 130))
    parsed = parse_residual_polarity_staging_plan(
        prepared.staging_plan_binary,
        active_vault=prepared.active_projection,
        rank_decision=prepared.rank_decision,
    )
    assert parsed == plan


def test_prefix_plan_is_exact_raw_signed_i32le_order(
    loaded_preparation: LoadedPreparation,
) -> None:
    prepared = loaded_preparation.prepared
    plan = prepared.prefix_plan
    validate_o1c78_production_plan(plan)

    assert plan.prefix_literals == prepare.PREFIX_LITERALS
    assert plan.sha256 == prepare.PREFIX_PLAN_BINARY_SHA256
    assert plan.serialized_bytes == prepare.PREFIX_PLAN_BINARY_BYTES == 44
    assert prepared.prefix_plan_binary == struct.pack(
        "<11i", *prepare.PREFIX_LITERALS
    )
    assert prepared.prefix_plan_binary == rescue_prefix_order_bytes(
        prepare.PREFIX_LITERALS
    )
    assert hashlib.sha256(prepared.prefix_plan_binary).hexdigest() == (
        prepare.PREFIX_ORDER_I32LE_SHA256
    )
    parsed = parse_rescue_prefix_preemption_plan(
        prepared.prefix_plan_binary,
        active_vault=prepared.active_projection,
    )
    assert parsed == plan
    document = prepared.prefix_plan_document
    assert document["source_result_sha256"] == prepare.PARENT_NATIVE_RAW_SHA256
    assert document["source_assignment_sha256"] == (
        prepare.PARENT_TERMINAL_ASSIGNMENT_SHA256
    )
    assert document["parent_staging_plan_sha256"] == (
        prepare.STAGING_PLAN_BINARY_SHA256
    )


def test_parent_provenance_keeps_terminal_and_control_sources_distinct(
    loaded_preparation: LoadedPreparation,
) -> None:
    parent = loaded_preparation.prepared.manifest["parent"]
    assert isinstance(parent, dict)
    assert parent["parent_result_sha256"] == prepare.PARENT_RESULT_SHA256
    assert parent["parent_manifest_sha256"] == prepare.PARENT_MANIFEST_SHA256
    assert parent["terminal_native_raw_sha256"] == prepare.PARENT_NATIVE_RAW_SHA256
    assert parent["terminal_source_assignment_sha256"] == (
        prepare.PARENT_TERMINAL_ASSIGNMENT_SHA256
    )
    assert parent["terminal_assignment_used_for_frontier_derivation"] is False
    assert parent["control_source_result_sha256"] == (
        prepare.CONTROL_SOURCE_RESULT_SHA256
    )
    assert parent["control_source_assignment_sha256"] == (
        prepare.SOURCE_ASSIGNMENT_SHA256
    )
    assert parent["parent_last_consumed_lineage_ordinal"] == 17
    assert parent["prepared_lineage_ordinal"] == 18


def test_manifest_seals_exact_regular_file_inventory(
    loaded_preparation: LoadedPreparation,
) -> None:
    directory = loaded_preparation.directory
    manifest = loaded_preparation.prepared.manifest
    artifact_set = manifest["artifact_set"]
    assert isinstance(artifact_set, dict)
    rows = artifact_set["artifacts"]
    assert isinstance(rows, dict)
    assert artifact_set["artifact_count"] == len(rows) == 22
    assert {path.name for path in directory.iterdir()} == set(rows) | {
        prepare.MANIFEST_NAME
    }
    for name, row in rows.items():
        assert isinstance(name, str) and isinstance(row, dict)
        path = directory / name
        assert path.is_file() and not path.is_symlink()
        payload = path.read_bytes()
        assert row["serialized_bytes"] == len(payload)
        assert row["sha256"] == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize("mutation", ["extra", "symlink", "tamper"])
def test_loader_rejects_inventory_and_byte_mutations(
    loaded_preparation: LoadedPreparation,
    tmp_path: Path,
    mutation: str,
) -> None:
    polluted = tmp_path / mutation
    shutil.copytree(loaded_preparation.directory, polluted)
    if mutation == "extra":
        (polluted / "unmanifested-extra.bin").write_bytes(b"not sealed")
        match = "directory inventory"
    elif mutation == "symlink":
        target = polluted / prepare.PREFIX_PLAN_BINARY_NAME
        target.unlink()
        target.symlink_to(polluted / prepare.SOURCE_ASSIGNMENT_NAME)
        match = "directory inventory"
    else:
        target = polluted / prepare.PREFIX_PLAN_BINARY_NAME
        target.write_bytes(target.read_bytes() + b"\0\0\0\0")
        match = "artifact"
    with pytest.raises(prepare.O1C78PreparationError, match=match):
        prepare.load_prepared_rescue_prefix_preemption(
            polluted,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )


def test_loader_rejects_manifest_digest_before_artifact_replay(
    loaded_preparation: LoadedPreparation,
) -> None:
    with pytest.raises(prepare.O1C78PreparationError, match="manifest"):
        prepare.load_prepared_rescue_prefix_preemption(
            loaded_preparation.directory,
            expected_manifest_sha256="00" * 32,
        )


def test_frozen_manifest_is_enforced_before_publication(
    loaded_preparation: LoadedPreparation,
) -> None:
    payload = (loaded_preparation.directory / prepare.MANIFEST_NAME).read_bytes()
    prepare._validate_frozen_manifest_payload(payload)
    with pytest.raises(prepare.O1C78PreparationError, match="manifest identity"):
        prepare._validate_frozen_manifest_payload(payload + b"\n")


def test_release_contract_cannot_be_disabled(tmp_path: Path) -> None:
    with pytest.raises(prepare.O1C78PreparationError, match="must remain true"):
        prepare.prepare_o1c78_rescue_prefix_preemption(
            capsule_dir=ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            output_dir=tmp_path / "disabled",
            enforce_release_contract=False,
        )


def test_loader_rejects_root_directory_symlink(
    loaded_preparation: LoadedPreparation, tmp_path: Path
) -> None:
    alias = tmp_path / "prepared-link"
    alias.symlink_to(loaded_preparation.directory, target_is_directory=True)
    with pytest.raises(prepare.O1C78PreparationError, match="sealed directory"):
        prepare.load_prepared_rescue_prefix_preemption(
            alias,
            expected_manifest_sha256=prepare.EXPECTED_PREPARED_MANIFEST_SHA256,
        )


@pytest.mark.parametrize("root_name", ["capsule", "result"])
def test_preparation_rejects_root_input_symlink(
    tmp_path: Path, root_name: str
) -> None:
    capsule: Path = ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE
    result: Path = ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE
    alias = tmp_path / f"{root_name}-link"
    if root_name == "capsule":
        alias.symlink_to(capsule, target_is_directory=True)
        capsule = alias
    else:
        alias.symlink_to(result)
        result = alias
    with pytest.raises(
        prepare.O1C78PreparationError,
        match="sealed directory|sealed regular file",
    ):
        prepare.prepare_o1c78_rescue_prefix_preemption(
            capsule_dir=capsule,
            parent_result_path=result,
            output_dir=tmp_path / "rejected",
        )


def test_publication_fsync_failure_rolls_back_final_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "seed"
    real_open = prepare.os.open

    def fail_parent_open(
        path: Any,
        flags: int,
        *args: Any,
        **kwargs: Any,
    ) -> int:
        if not kwargs and Path(path) == tmp_path:
            raise OSError("forced parent fsync open failure")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(prepare.os, "open", fail_parent_open)
    with pytest.raises(prepare.O1C78PreparationError, match="publication failed"):
        prepare._publish_directory(destination, {"artifact.bin": b"sealed"})
    assert not destination.exists()


def test_atomic_publisher_refuses_existing_destination(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"sealed")
    with pytest.raises(prepare.O1C78PreparationError, match="already exists"):
        prepare._publish_directory(output, {"new": b"data"})
    assert sentinel.read_bytes() == b"sealed"
    assert tuple(output.iterdir()) == (sentinel,)


def test_cli_reports_bounded_preparation_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    def fail(**_kwargs: object) -> dict[str, object]:
        raise prepare.O1C78PreparationError("sealed parent differs")

    monkeypatch.setattr(prepare, "prepare_o1c78_rescue_prefix_preemption", fail)
    assert prepare.main(["--output-dir", (tmp_path / "bad").as_posix()]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "O1C-0078: sealed parent differs\n"
