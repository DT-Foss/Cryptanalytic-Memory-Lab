from __future__ import annotations

import ast
import copy
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c104_page20_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _copy_capsule(tmp_path: Path) -> Path:
    copied = tmp_path / "capsule"
    shutil.copytree(CAPSULE, copied)
    copied.chmod(copied.stat().st_mode | 0o700)
    for path in copied.rglob("*"):
        if path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
        elif path.is_file():
            path.chmod(path.stat().st_mode | 0o600)
    return copied.resolve()


def _replace_manifest(
    prepared: prepare.PreparedCausalRolloverArtifacts,
    manifest: dict[str, Any],
) -> prepare.PreparedCausalRolloverArtifacts:
    artifacts = dict(prepared.artifacts)
    artifacts[prepare.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(manifest)
    return prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=artifacts,
        manifest=manifest,
    )


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c104_page20_causal_rollover()


def test_exact_o1c103_parent_boundary_is_sealed() -> None:
    entries = prepare._validate_capsule_inventory(CAPSULE)
    result = prepare._validate_parent_result(CAPSULE, PARENT_RESULT)
    result_any: Any = result
    manifest = (CAPSULE / "artifacts.sha256").read_bytes()
    assert len(entries) == prepare.PARENT_CAPSULE_ENTRY_COUNT == 46
    assert len(manifest) == prepare.PARENT_CAPSULE_MANIFEST_BYTES == 4_808
    assert _sha256(manifest) == prepare.PARENT_CAPSULE_MANIFEST_SHA256
    assert _sha256(PARENT_RESULT.read_bytes()) == prepare.PARENT_RESULT_SHA256
    assert result["attempt_id"] == "O1C-0103"
    assert result["classification"] == prepare.PARENT_CLASSIFICATION
    assert result["science_gain"] is True
    episode: Any = result_any["episodes"][0]
    assert episode["page19_burned"] is True
    assert episode["lineage32_burned"] is True
    assert episode["native_calls_consumed"] == 1
    assert episode["actual_conflicts"] == episode["billed_conflicts"] == 18
    assert episode["retry_authorized"] is False
    assert episode["replay_authorized"] is False


def test_zero_call_and_exact_parent_regeneration(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    assert prepared.manifest["authorization"] == {
        "science_call_authorized": False,
        "intent_created": False,
        "page20_burned": False,
        "lineage33_burned": False,
        "page19_retry_or_replay_authorized": False,
        "lineage32_retry_or_replay_authorized": False,
        "historical_page_retry_or_replay_authorized": False,
    }
    parent: Any = prepared.manifest["parent"]
    assert parent["initial_artifact_count"] == 13
    assert parent["initial_artifacts_byte_equal_to_fresh_o1c102_regeneration"]
    assert parent["page19_burned"] is True
    assert parent["lineage32_burned"] is True


def test_266_occurrences_become_one_265_clause_lineage32_chunk(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 21
    assert attic.chunks[-1].sha256 == prepare.NEW_CHUNK_SHA256
    assert attic.chunks[-1].clause_count == 265
    assert attic.chunks[-1].literal_count == 755_792
    assert attic.chunks[-1].serialized_bytes == 3_024_419
    assert attic.chunk_clause_union_indices[-1] == tuple(range(2_338, 2_603))
    assert attic.union_vault.clause_count == 2_603
    assert attic.union_vault.literal_count == 7_358_158
    assert attic.union_vault.serialized_bytes == 29_443_235
    assert len(attic.occurrences) == 2_613
    assert attic.duplicate_occurrence_count == 10
    assert len(attic.relations) == 14
    assert len(attic.undominated_indices) == 2_592

    tail = attic.occurrences[-266:]
    assert all(row.stream_id == "o1c103-episode-00" for row in tail)
    assert sum(row.classification == "new" for row in tail) == 265
    assert sum(row.classification == "current_duplicate" for row in tail) == 1
    assert tail[15].clause == tail[16].clause
    assert tail[15].clause_sha256 == prepare.CURRENT_DUPLICATE_SHA256
    assert (
        attic.occurrence_union_indices[-266:][15]
        == (attic.occurrence_union_indices[-266:][16])
    )


def test_new_84_clause_fixed_point_is_replayed_exactly(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    closure = parse_threshold_no_good_vault(
        prepared.artifacts[prepare.DERIVED_CLOSURE_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    overlay = parse_threshold_no_good_vault(
        prepared.artifacts[prepare.DERIVED_OVERLAY_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert closure.sha256 == prepare.NEW_DERIVED_CLOSURE_SHA256
    assert closure.clause_count == 84
    assert closure.literal_count == 239_208
    assert closure.serialized_bytes == 957_359
    assert closure.describe()["clause_aggregate_sha256"] == (
        prepare.NEW_DERIVED_CLOSURE_AGGREGATE_SHA256
    )
    assert overlay.sha256 == prepare.NEW_DERIVED_OVERLAY_SHA256
    assert overlay.clauses == closure.clauses[:52]
    assert overlay.literal_count == 147_752
    assert overlay.serialized_bytes == 591_407

    payload = prepared.artifacts[prepare.DERIVED_RECEIPT_NAME]
    receipt: Any = json.loads(payload)
    assert canonical_json_bytes(receipt) == payload
    assert receipt["schema"] == prepare.DERIVED_RECEIPT_SCHEMA
    assert len(receipt["edges"]) == 84
    assert all(row["byte_exact_replay"] is True for row in receipt["edges"])
    audit = receipt["fixed_point_audit"]
    assert audit["generation_1"] == {
        "pair_count": 34_980,
        "zero": 0,
        "multi": 34_928,
        "single": 52,
        "novel": 52,
    }
    assert audit["generation_2"] == {
        "pair_count": 136_942,
        "zero": 138,
        "multi": 136_736,
        "single": 68,
        "known_duplicates": 36,
        "novel": 32,
    }
    assert audit["generation_3"] == {
        "pair_count": 85_616,
        "zero": 128,
        "multi": 85_456,
        "single": 32,
        "known_duplicates": 32,
        "novel": 0,
        "fixed_point_reached": True,
    }


def test_old_and_new_derived_namespaces_stay_separate(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    assert (
        prepared.artifacts[prepare.INHERITED_DERIVED_RECEIPT_NAME]
        == (CAPSULE / "initial" / prepare.INHERITED_DERIVED_RECEIPT_NAME).read_bytes()
    )
    assert (
        prepared.artifacts[prepare.INHERITED_DERIVED_CLOSURE_NAME]
        == (CAPSULE / "initial" / prepare.INHERITED_DERIVED_CLOSURE_NAME).read_bytes()
    )
    assert (
        prepared.artifacts[prepare.INHERITED_DERIVED_OVERLAY_NAME]
        == (CAPSULE / "initial" / prepare.INHERITED_DERIVED_OVERLAY_NAME).read_bytes()
    )
    namespaces: Any = prepared.manifest["derived_resolution_namespaces"]
    assert namespaces["inherited"]["closure_clause_count"] == 5
    assert namespaces["new"]["closure_clause_count"] == 84
    assert namespaces["combined_overlay_materialized"] is False
    assert namespaces["causal_attic_occurrence_rows_added"] == 0
    assert "combined-derived-resolution-overlay.vault" not in prepared.artifacts


def test_combined_registry_is_2692_with_119_relations(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    registry: Any = prepared.manifest["logical_known_registry"]
    assert registry["emitted_clause_count"] == 2_603
    assert registry["inherited_derived_clause_count"] == 5
    assert registry["new_derived_clause_count"] == 84
    assert registry["combined_clause_count"] == 2_692
    assert registry["strict_subsumption_pair_count"] == 119
    assert registry["undominated_clause_count"] == 2_579
    receipt: Any = json.loads(prepared.artifacts[prepare.DERIVED_RECEIPT_NAME])
    relation_audit = receipt["logical_relation_audit"]
    assert relation_audit["pure_native_relation_count"] == 14
    assert relation_audit["inherited_derived_relation_count"] == 7
    assert relation_audit["new_derived_to_native_relation_count"] == 66
    assert relation_audit["new_derived_internal_relation_count"] == 32
    assert relation_audit["full_relation_count"] == 119
    assert len(relation_audit["full_relations"]) == 119


def test_chronological_registry_to_emitted_union_boundary_mapping() -> None:
    assert prepare._logical_to_emitted_union_index(2_337) == 2_337
    assert prepare._logical_to_emitted_union_index(2_338) is None
    assert prepare._logical_to_emitted_union_index(2_342) is None
    assert prepare._logical_to_emitted_union_index(2_343) == 2_338
    assert prepare._logical_to_emitted_union_index(2_607) == 2_602
    assert prepare._logical_to_emitted_union_index(2_608) is None
    assert prepare._emitted_union_to_logical_index(2_337) == 2_337
    assert prepare._emitted_union_to_logical_index(2_338) == 2_343
    assert prepare._emitted_union_to_logical_index(2_602) == 2_607


def test_page20_is_247_clauses_with_exact_265_clause_headroom(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    page = parse_threshold_no_good_vault(
        prepared.artifacts[prepare.ACTIVE_PROJECTION_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    row: Any = prepared.manifest["page20"]
    assert page.sha256 == prepare.PAGE20_SHA256
    assert page.clause_count == row["active_limit"] == 247
    assert row["headroom"]["clauses"] == 265
    assert row["selected_emitted_clause_count"] == 192
    assert row["selected_inherited_derived_clause_count"] == 3
    assert row["selected_new_derived_clause_count"] == 52
    assert len(row["displaced_emitted_union_indices"]) == 55
    assert row["pure_emitted_candidate_activated"] is False
    proof = row["native_capacity_proof"]
    assert proof["observed_parent_unique_burst_fits_exactly"] is True
    assert proof["literal_future_emission_safety_claimed"] is False
    assert proof["serialized_byte_future_emission_safety_claimed"] is False

    residency: Any = json.loads(prepared.artifacts[prepare.RESIDENCY_NAME])
    assert residency["namespace_contract"]["derived_enters_emitted_attic"] is False
    assert residency["namespace_contract"]["derived_occurrence_rows"] == 0
    projection = residency["current_projection"]
    assert len(projection["selected_emitted_union_indices"]) == 192
    assert len(projection["selected_inherited_derived_clauses"]) == 3
    assert len(projection["selected_new_derived_clauses"]) == 52


def test_returned_state_authoritatively_exposes_composed_page20(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    active_payload = prepared.artifacts[prepare.ACTIVE_PROJECTION_NAME]
    assert isinstance(prepared, prepare.ParentPreparedCausalRolloverArtifacts)
    assert state.active_projection.serialized == active_payload
    assert state.active_projection == state.current_projection.vault
    assert state.active_projection.sha256 == prepare.PAGE20_SHA256
    assert state.current_projection.lineage_ordinal == prepare.PAGE20_LINEAGE_ORDINAL
    assert state.current_projection.vault.clause_count == prepare.PAGE20_ACTIVE_LIMIT
    assert state.emitted_state is state.causal_base_state
    assert state.emitted_state.active_projection.sha256 == prepare.PAGE20_BASE_SHA256
    assert state.emitted_state.active_projection != state.active_projection
    assert state.base_selection_metadata["activated"] is False
    assert prepare.PAGE20_BASE_SHA256 not in state.used_active_sha256
    assert state.used_active_sha256[-1] == prepare.PAGE20_SHA256
    assert (
        canonical_json_bytes(state.describe())
        == prepared.artifacts[prepare.RESIDENCY_NAME]
    )
    assert (
        canonical_json_bytes(state.activation_ledger_document())
        == (prepared.artifacts[prepare.ACTIVATION_LEDGER_NAME])
    )
    validate_activation_replay(state.emitted_state)


def test_continuation_bank_and_receipt_are_carried_byte_exactly(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    bank = prepared.artifacts[prepare.FINAL_BANK_NAME]
    receipt_payload = prepared.artifacts[prepare.PRIORITY_RECEIPT_NAME]
    assert len(bank) == 24_576
    assert _sha256(bank) == prepare.FINAL_BANK_SHA256
    assert len(receipt_payload) == 52_015
    assert _sha256(receipt_payload) == prepare.PRIORITY_RECEIPT_SHA256
    receipt: Any = json.loads(receipt_payload)
    assert bytes.fromhex(receipt["bank_hex"]) == bank
    assert receipt["candidate_population"] == 255
    assert receipt["consumed_coordinate_count"] == 255
    assert receipt["assignment_literals_observed"] == 24_704


def test_bundle_has_15_rows_plus_self_manifest(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    rows: Any = prepared.manifest["artifacts"]
    assert len(prepared.artifacts) == 16
    assert len(rows) == 15
    assert prepare.PREPARATION_MANIFEST_NAME not in rows
    assert prepared.artifacts[prepare.PREPARATION_MANIFEST_NAME] == (
        canonical_json_bytes(prepared.manifest)
    )
    prepare._validate_prepared_bundle_for_publication(prepared)
    for name, row in rows.items():
        payload = prepared.artifacts[name]
        assert row["serialized_bytes"] == len(payload)
        assert row["sha256"] == _sha256(payload)


@pytest.mark.parametrize(
    ("field", "stale_value"),
    (
        ("active_sha256", "0" * 64),
        ("clause_count", prepare.PAGE20_ACTIVE_LIMIT - 1),
        ("literal_count", prepare.PAGE20_LITERAL_COUNT - 1),
        ("serialized_bytes", prepare.PAGE20_SERIALIZED_BYTES - 1),
    ),
)
def test_publication_rejects_stale_manifest_page20_identity(
    prepared: prepare.PreparedCausalRolloverArtifacts,
    field: str,
    stale_value: object,
) -> None:
    manifest: dict[str, Any] = copy.deepcopy(dict(prepared.manifest))
    page20: dict[str, Any] = manifest["page20"]
    page20[field] = stale_value
    tampered = _replace_manifest(prepared, manifest)
    with pytest.raises(prepare.O1C104PreparationError, match="publication bundle"):
        prepare._validate_prepared_bundle_for_publication(tampered)


def test_publication_rejects_stale_active_artifact_row(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    manifest: dict[str, Any] = copy.deepcopy(dict(prepared.manifest))
    rows: dict[str, Any] = manifest["artifacts"]
    active_row: dict[str, Any] = rows[prepare.ACTIVE_PROJECTION_NAME]
    active_row["sha256"] = "0" * 64
    tampered = _replace_manifest(prepared, manifest)
    with pytest.raises(prepare.O1C104PreparationError, match="publication bundle"):
        prepare._validate_prepared_bundle_for_publication(tampered)


def test_parent_tamper_is_rejected_before_regeneration(tmp_path: Path) -> None:
    capsule = _copy_capsule(tmp_path)
    path = capsule / "episodes/00/vault.json"
    payload = bytearray(path.read_bytes())
    payload[-2] ^= 1
    path.write_bytes(payload)
    with pytest.raises(prepare.O1C104PreparationError, match="inventory or digest"):
        prepare.prepare_o1c104_page20_causal_rollover(
            capsule_dir=capsule,
            parent_result_path=PARENT_RESULT,
        )


def test_module_has_no_solver_target_model_or_fit_surface() -> None:
    source_path = ROOT / "src/o1_crypto_lab/o1c104_page20_causal_rollover_prepare.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not imported.intersection(
        {"subprocess", "socket", "requests", "torch", "mlx", "numpy"}
    )
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not calls.intersection({"open", "exec", "eval", "compile", "__import__"})
    assert 'native_solver_calls": 0' in source
    assert 'science_calls": 0' in source
    assert 'target_bytes_read": False' in source
    assert 'truth_key_bytes_read": False' in source
