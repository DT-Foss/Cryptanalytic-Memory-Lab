from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator, cast

import pytest

from o1_crypto_lab import o1c110_page23_type_safe_causal_rollover_prepare as o1c110
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


@pytest.fixture(scope="module")
def prepared() -> Iterator[o1c110.PreparedCausalRolloverArtifacts]:
    yield o1c110.prepare_o1c110_page23_type_safe_causal_rollover()


def _document(prepared: o1c110.PreparedCausalRolloverArtifacts, name: str) -> Any:
    return json.loads(prepared.artifacts[name])


def test_page23_exact_composition_and_267_clause_headroom(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    page = prepared.state.active_projection
    projection = prepared.state.current_projection
    assert page.sha256 == o1c110.PAGE23_SHA256
    assert page.clause_aggregate_sha256 == o1c110.PAGE23_CLAUSE_AGGREGATE_SHA256
    assert page.clause_count == 245
    assert page.literal_count == 699_680
    assert page.serialized_bytes == 2_799_891
    assert len(projection.selected_emitted_union_indices) == 4
    assert len(projection.selected_inherited_derived_clauses) == 3
    assert len(projection.selected_o1c104_derived_clauses) == 41
    assert len(projection.selected_o1c108_derived_clauses) == 149
    assert len(projection.selected_o1c110_derived_clauses) == 48
    assert projection.category_counts == {
        "emitted_structural_root": 4,
        "inherited_o1c102_derived_structural_root": 3,
        "o1c104_derived_structural_root": 41,
        "o1c108_derived_structural_root": 149,
        "o1c110_derived_structural_root": 48,
        "emitted_pinned_core": 0,
        "emitted_inherited_debt": 0,
        "emitted_new_debt": 0,
        "emitted_hot_event": 0,
        "emitted_recycled": 0,
    }
    capacity = cast(Any, prepared.manifest)["page23"]["native_capacity_proof"]
    assert capacity["maximum_additional_unique_clauses_before_capacity_terminal"] == 267
    assert capacity["required_clause_headroom"] == 267
    assert capacity["proved_sufficient"] is True
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False


def test_selector_is_recomputed_and_only_exact_four_clause_prefix_is_used(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    projection = prepared.state.current_projection
    pure = projection.pure_emitted_candidate
    assert pure.vault.sha256 == o1c110.PAGE23_PURE_EMITTED_SHA256
    assert pure.vault.clause_count == 245
    assert pure.vault.literal_count == 670_095
    assert pure.vault.serialized_bytes == 2_681_551
    assert (
        projection.priority_selected_emitted_union_indices == pure.selection_order[:4]
    )
    assert projection.selected_emitted_union_indices == tuple(
        sorted(pure.selection_order[:4])
    )
    assert projection.selected_emitted_union_indices == (9, 123, 144, 551)
    assert (
        o1c110._index_list_sha256(projection.selected_emitted_union_indices)
        == o1c110.SELECTED_EMITTED_INDICES_SHA256
    )
    residency = cast(Any, prepared.state.describe())
    assert residency["emitted_selector_candidate"]["activated"] is False
    assert residency["current_projection"]["selector_confirmation"] == (
        "exact-prefix-of-causally-advanced-pure-emitted-selection-order"
    )


def test_native_attic_append_is_complete_unique_and_append_only(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    attic = prepared.state.attic
    assert len(attic.chunks) == 23
    assert attic.chunks[-1].sha256 == o1c110.NEW_CHUNK_SHA256
    assert attic.chunks[-1].clause_count == 267
    assert attic.chunks[-1].literal_count == 749_811
    assert attic.chunks[-1].serialized_bytes == 3_000_503
    assert attic.union_vault.clause_count == 3_136
    assert attic.union_vault.sha256 == o1c110.ATTIC_UNION_SHA256
    assert attic.union_vault.clause_aggregate_sha256 == (
        o1c110.ATTIC_UNION_CLAUSE_AGGREGATE_SHA256
    )
    assert len(attic.occurrences) == 3_146
    assert attic.duplicate_occurrence_count == 10
    assert len(attic.relations) == 14
    assert len(attic.undominated_indices) == 3_125
    assert attic.occurrence_union_indices[-267:] == tuple(range(2_869, 3_136))
    occurrences = _document(prepared, o1c110.OCCURRENCES_NAME)
    assert occurrences["occurrence_count"] == 3_146
    assert occurrences["unique_clause_count"] == 3_136
    assert occurrences["duplicate_occurrence_count"] == 10


def test_dynamic_resolution_reaches_exact_fixed_point_and_replays_edges(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    observed = prepared.state.attic.union_vault.observed_variables
    closure = parse_threshold_no_good_vault(
        prepared.artifacts[o1c110.DERIVED_CLOSURE_NAME],
        observed_variables=observed,
        caps=O1C66_VAULT_CAPS,
    )
    overlay = parse_threshold_no_good_vault(
        prepared.artifacts[o1c110.DERIVED_OVERLAY_NAME],
        observed_variables=observed,
        caps=O1C66_VAULT_CAPS,
    )
    receipt = _document(prepared, o1c110.DERIVED_RECEIPT_NAME)
    generations = receipt["fixed_point_audit"]["generations"]
    assert closure == overlay
    assert closure.sha256 == o1c110.DERIVED_CLOSURE_SHA256
    assert closure.clause_count == 48
    assert closure.literal_count == 135_888
    assert closure.serialized_bytes == 543_935
    assert generations == [
        {
            "generation": 1,
            "frontier_clause_count": 267,
            "prior_clause_count": 0,
            "frontier_to_prior_pair_count": 0,
            "frontier_internal_pair_count": 35_511,
            "pair_count": 35_511,
            "zero": 0,
            "multi": 35_463,
            "single": 48,
            "unique_novel": 48,
            "pivot_variables": [194],
            "fixed_point_reached": False,
        },
        {
            "generation": 2,
            "frontier_clause_count": 48,
            "prior_clause_count": 267,
            "frontier_to_prior_pair_count": 12_816,
            "frontier_internal_pair_count": 1_128,
            "pair_count": 13_944,
            "zero": 96,
            "multi": 13_848,
            "single": 0,
            "unique_novel": 0,
            "pivot_variables": [],
            "fixed_point_reached": True,
        },
    ]
    assert receipt["claim_boundary"]["pivot_or_generation_preselected"] is False
    assert receipt["resolution_rule"]["required_pivot_variable"] is None
    assert receipt["resolution_rule"]["required_generation_count"] is None
    assert len(receipt["edges"]) == 48
    assert all(edge["byte_exact_replay"] is True for edge in receipt["edges"])
    assert (
        receipt["edge_inventory_sha256"]
        == hashlib.sha256(canonical_json_bytes(receipt["edge_inventory"])).hexdigest()
    )


def test_real_v8_certifies_all_48_new_and_all_245_active_clauses(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    audit = _document(prepared, o1c110.CERTIFICATION_AUDIT_NAME)
    candidates = audit["new_o1c110_resolution_candidates"]
    assert audit["passed"] is True
    assert candidates["candidate_count"] == 48
    assert candidates["certified_count"] == 48
    assert candidates["pass_count"] == 48
    assert candidates["fail_count"] == 0
    assert tuple(candidates["passing_closure_indices"]) == tuple(range(48))
    assert candidates["failing_closure_indices"] == []
    assert candidates["maximum_passing_upper_bound"] == 14.561642594796334
    assert len(candidates["rows_in_closure_order"]) == 48
    assert all(row["passed"] is True for row in candidates["rows_in_closure_order"])
    assert audit["page23"]["active_pass_count"] == 245
    assert audit["page23"]["active_fail_count"] == 0
    assert audit["execution"] == {"offline_only": True, **o1c110._zero_call()}


def test_logical_registry_preserves_exact_3111_prefix_then_appends_267_and_48(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    receipt = _document(prepared, o1c110.DERIVED_RECEIPT_NAME)
    combined = receipt["logical_known_registry"]["combined"]
    parent = _document(prepared, o1c110.O1C108_DERIVED_RECEIPT_NAME)
    parent_inventory = parent["logical_known_registry"]["combined"]["clause_sha256"]
    inventory = combined["clause_sha256"]
    registry = cast(Any, prepared.manifest)["logical_known_registry"]
    assert len(inventory) == len(set(inventory)) == 3_426
    assert inventory[:3_111] == parent_inventory
    assert combined["inventory_sha256"] == o1c110.LOGICAL_KNOWN_INVENTORY_SHA256
    assert combined["encoding_only"]["sha256"] == o1c110.LOGICAL_KNOWN_SHA256
    assert combined["encoding_only"]["literal_count"] == 9_687_641
    assert combined["encoding_only"]["serialized_bytes"] == 38_764_459
    assert registry["prior_prefix_clause_count"] == 3_111
    assert registry["new_native_clause_count"] == 267
    assert registry["new_derived_clause_count"] == 48
    assert registry["combined_clause_count"] == 3_426
    assert registry["strict_subsumption_pair_count"] == 333
    assert registry["undominated_clause_count"] == 3_099


def test_parent_page_is_burned_and_bank_is_carried_byte_exact(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = cast(Any, prepared.manifest)
    bank = prepared.artifacts[o1c110.FINAL_BANK_NAME]
    receipt_payload = prepared.artifacts[o1c110.PRIORITY_RECEIPT_NAME]
    receipt = json.loads(receipt_payload)
    assert manifest["parent_success"]["page22_burned"] is True
    assert manifest["parent_success"]["lineage35_burned"] is True
    assert manifest["parent_success"]["retry_or_replay_authorized"] is False
    assert manifest["parent_success"]["capsule_manifest_sha256"] == (
        o1c110.PARENT_CAPSULE_MANIFEST_SHA256
    )
    assert manifest["parent_success"]["result_sha256"] == o1c110.PARENT_RESULT_SHA256
    assert bytes.fromhex(receipt["bank_hex"]) == bank
    assert receipt["bank_bytes"] == len(bank)
    assert receipt["current_bank_sha256"] == hashlib.sha256(bank).hexdigest()
    assert hashlib.sha256(bank).hexdigest() == o1c110.FINAL_BANK_SHA256
    assert hashlib.sha256(receipt_payload).hexdigest() == o1c110.PRIORITY_RECEIPT_SHA256


def test_exact_23_artifact_inventory_and_self_validator(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
) -> None:
    assert len(prepared.artifacts) == 23
    rows = cast(Any, prepared.manifest)["artifacts"]
    assert set(rows) == set(prepared.artifacts) - {o1c110.PREPARATION_MANIFEST_NAME}
    assert prepared.artifacts[o1c110.PREPARATION_MANIFEST_NAME] == canonical_json_bytes(
        prepared.manifest
    )
    assert (
        hashlib.sha256(prepared.artifacts[o1c110.PREPARATION_MANIFEST_NAME]).hexdigest()
        == o1c110.PREPARATION_MANIFEST_SHA256
    )
    for name, row in rows.items():
        payload = prepared.artifacts[name]
        assert row["serialized_bytes"] == len(payload)
        assert row["sha256"] == hashlib.sha256(payload).hexdigest()
    o1c110._validate_prepared_bundle(prepared)


@pytest.mark.parametrize(
    "artifact",
    (
        o1c110.CERTIFICATION_AUDIT_NAME,
        o1c110.DERIVED_CLOSURE_NAME,
        o1c110.DERIVED_RECEIPT_NAME,
        o1c110.ACTIVE_PROJECTION_NAME,
        o1c110.PRIORITY_RECEIPT_NAME,
        o1c110.PREPARATION_MANIFEST_NAME,
    ),
)
def test_validator_rejects_artifact_tamper(
    prepared: o1c110.PreparedCausalRolloverArtifacts, artifact: str
) -> None:
    artifacts = dict(prepared.artifacts)
    artifacts[artifact] += b"\x00"
    with pytest.raises(o1c110.O1C110PreparationError):
        o1c110._validate_prepared_bundle(replace(prepared, artifacts=artifacts))


def test_atomic_publication_materializes_exact_bytes_and_refuses_replacement(
    prepared: o1c110.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page23"
    assert (
        o1c110.write_prepared_o1c110_page23_type_safe_causal_rollover(prepared, output)
        == output
    )
    assert {path.name for path in output.iterdir()} == set(prepared.artifacts)
    for name, payload in prepared.artifacts.items():
        path = output / name
        assert path.read_bytes() == payload
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    with pytest.raises(o1c110.O1C110PreparationError, match="already exists"):
        o1c110.write_prepared_o1c110_page23_type_safe_causal_rollover(prepared, output)


def test_atomic_publication_loses_race_without_clobbering_or_leaking_stage(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "race-target"

    def collide(_source: Path, target: Path) -> None:
        target.mkdir()
        (target / "other-owner").write_bytes(b"preserved")
        raise FileExistsError(target)

    monkeypatch.setattr(o1c110, "_atomic_rename_noreplace", collide)
    with pytest.raises(o1c110.O1C110PreparationError, match="already exists"):
        o1c110.write_prepared_o1c110_page23_type_safe_causal_rollover(prepared, output)
    assert (output / "other-owner").read_bytes() == b"preserved"
    assert not tuple(tmp_path.glob(".race-target.*.tmp"))


@pytest.mark.parametrize("command", ("preflight", "prepare"))
def test_cli_dispatches_preflight_and_atomic_prepare(
    prepared: o1c110.PreparedCausalRolloverArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    written: list[Path] = []
    monkeypatch.setattr(
        o1c110,
        "prepare_o1c110_page23_type_safe_causal_rollover",
        lambda **_kwargs: prepared,
    )
    monkeypatch.setattr(
        o1c110,
        "write_prepared_o1c110_page23_type_safe_causal_rollover",
        lambda _prepared, output: written.append(Path(output)),
    )
    argv = [command]
    if command == "prepare":
        argv += ["--output-dir", (tmp_path / "cli-page23").as_posix()]
    assert o1c110.main(argv) == 0
    assert bool(written) is (command == "prepare")
    output = json.loads(capsys.readouterr().out)
    assert output["schema"] == o1c110.PREPARATION_SCHEMA
    assert output["zero_call"] == o1c110._zero_call()
