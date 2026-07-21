from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator, cast

import pytest

from o1_crypto_lab import o1c108_page22_type_safe_causal_rollover_prepare as o1c108
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


@pytest.fixture(scope="module")
def prepared() -> Iterator[o1c108.PreparedCausalRolloverArtifacts]:
    yield o1c108.prepare_o1c108_page22_type_safe_causal_rollover()


def _state(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> o1c108.ComposedPage22State:
    return cast(o1c108.ComposedPage22State, prepared.state)


def _document(prepared: o1c108.PreparedCausalRolloverArtifacts, name: str) -> Any:
    return json.loads(prepared.artifacts[name])


def _with_manifest(
    prepared: o1c108.PreparedCausalRolloverArtifacts, manifest: Any
) -> o1c108.PreparedCausalRolloverArtifacts:
    artifacts = dict(prepared.artifacts)
    artifacts[o1c108.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(manifest)
    return replace(prepared, manifest=manifest, artifacts=artifacts)


def test_page22_frozen_encoding_and_exact_composition(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    state = _state(prepared)
    page = state.active_projection
    projection = state.current_projection
    assert page.sha256 == (
        "183878040210ffb542b199148c7151bd2656b6019755a978142f3fbf87ac162f"
    )
    assert page.clause_aggregate_sha256 == (
        "683e3f5510843679edb0e5d8dc450c3abb6b366fc49291557a0d68aaff774fd7"
    )
    assert page.clause_count == 246
    assert page.literal_count == 688_833
    assert page.serialized_bytes == 2_756_507
    assert len(projection.selected_emitted_union_indices) == 53
    assert len(projection.selected_inherited_derived_clauses) == 3
    assert len(projection.selected_o1c104_derived_clauses) == 41
    assert len(projection.selected_o1c108_derived_clauses) == 149
    assert projection.category_counts == {
        "emitted_structural_root": 9,
        "inherited_o1c102_derived_structural_root": 3,
        "o1c104_derived_structural_root": 41,
        "o1c108_derived_structural_root": 149,
        "emitted_pinned_core": 43,
        "emitted_inherited_debt": 0,
        "emitted_new_debt": 1,
        "emitted_hot_event": 0,
        "emitted_recycled": 0,
    }


def test_selector_is_confirmed_from_causal_advancement_not_assumed(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    projection = _state(prepared).current_projection
    pure = projection.pure_emitted_candidate
    assert pure.vault.sha256 == (
        "97623323579d56de5034caf107627c939a991be0e00e6aee192d60a0bcf56f88"
    )
    assert pure.vault.clause_count == 246
    assert pure.vault.literal_count == 674_160
    assert pure.vault.serialized_bytes == 2_697_815
    assert (
        projection.priority_selected_emitted_union_indices == pure.selection_order[:53]
    )
    assert projection.selected_emitted_union_indices == tuple(
        sorted(pure.selection_order[:53])
    )
    assert (
        projection.selected_emitted_union_indices
        == o1c108.SELECTED_EMITTED_UNION_INDICES
    )
    assert (
        o1c108._index_list_sha256(projection.selected_emitted_union_indices)
        == "4288c99f66b918e5f30e8cde3fc246accc477691611288e984f5b764502af0ae"
    )
    residency = cast(Any, state_description := _state(prepared).describe())
    assert state_description == residency
    assert residency["emitted_selector_candidate"]["activated"] is False
    assert residency["current_projection"]["selector_confirmation"] == (
        "exact-prefix-of-causally-advanced-pure-emitted-selection-order"
    )


def test_native_attic_append_is_unique_complete_and_append_only(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    attic = _state(prepared).attic
    assert len(attic.chunks) == 22
    assert attic.chunks[-1].sha256 == o1c108.NEW_CHUNK_SHA256
    assert attic.chunks[-1].clause_count == 266
    assert attic.chunks[-1].literal_count == 752_466
    assert attic.chunks[-1].serialized_bytes == 3_011_119
    assert attic.union_vault.clause_count == 2_869
    assert attic.union_vault.sha256 == (
        "e010b4f23efb2a672be18a151b0950d312fbe232156142e5a6f68d93eb3bc7d5"
    )
    assert len(attic.occurrences) == 2_879
    assert attic.duplicate_occurrence_count == 10
    assert len(attic.relations) == 14
    assert len(attic.undominated_indices) == 2_858
    assert attic.occurrence_union_indices[-266:] == tuple(range(2_603, 2_869))
    occurrences = _document(prepared, o1c108.OCCURRENCES_NAME)
    assert occurrences["occurrence_count"] == 2_879
    assert occurrences["unique_clause_count"] == 2_869
    assert occurrences["duplicate_occurrence_count"] == 10


def test_exact_153_clause_g1_fixed_point_and_proof_edges(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    state = _state(prepared)
    closure = parse_threshold_no_good_vault(
        prepared.artifacts[o1c108.DERIVED_CLOSURE_NAME],
        observed_variables=state.attic.union_vault.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    overlay = parse_threshold_no_good_vault(
        prepared.artifacts[o1c108.DERIVED_OVERLAY_NAME],
        observed_variables=state.attic.union_vault.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    receipt = _document(prepared, o1c108.DERIVED_RECEIPT_NAME)
    fixed = receipt["fixed_point_audit"]
    assert closure == overlay
    assert closure.sha256 == (
        "6c77595387df7a84121056fa1c09036ddae91c58ad05c6b769245cf23ee6f935"
    )
    assert closure.clause_count == 153
    assert closure.literal_count == 437_591
    assert closure.serialized_bytes == 1_751_167
    assert fixed["generation_1"] == {
        "pair_count": 35_245,
        "zero": 0,
        "multi": 35_092,
        "single": 153,
        "unique_novel": 153,
        "pivot_variables": [32],
    }
    assert fixed["generation_2"] == {
        "native_to_generation_1_pair_count": 40_698,
        "generation_1_internal_pair_count": 11_628,
        "pair_count": 52_326,
        "zero": 306,
        "multi": 52_020,
        "single": 0,
        "unique_novel": 0,
        "fixed_point_reached": True,
    }
    assert len(receipt["edges"]) == 153
    assert all(edge["pivot_variable"] == 32 for edge in receipt["edges"])
    assert receipt["edge_inventory_sha256"] == (
        "23500f3b5a7a30c8e1b08d3bdc00135a4e6cd75d1a64ab3e61fe3101f460ea79"
    )
    assert receipt["proof_overlay"]["all_153_clauses_preserved"] is True


def test_all_153_are_v8_certified_with_exact_four_failures(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    audit = _document(prepared, o1c108.CERTIFICATION_AUDIT_NAME)
    candidates = audit["new_o1c108_resolution_candidates"]
    assert audit["passed"] is True
    assert candidates["candidate_count"] == 153
    assert candidates["certified_count"] == 153
    assert candidates["pass_count"] == 149
    assert candidates["fail_count"] == 4
    assert tuple(candidates["failing_closure_indices"]) == (1, 2, 32, 55)
    assert tuple(candidates["passing_closure_indices"]) == (
        o1c108.PASSING_NEW_DERIVED_INDICES
    )
    assert candidates["maximum_passing_upper_bound"] == 14.50523425946539
    rows = candidates["rows_in_closure_order"]
    assert len(rows) == 153
    assert [index for index, row in enumerate(rows) if not row["passed"]] == [
        1,
        2,
        32,
        55,
    ]
    assert all(
        rows[index]["failure"]
        == "joint-score-sieve-v8 grouped no-good certification differs"
        for index in o1c108.FAILED_NEW_DERIVED_INDICES
    )
    assert audit["page22"]["active_pass_count"] == 246
    assert audit["page22"]["active_fail_count"] == 0
    assert audit["execution"] == {
        "offline_only": True,
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }


def test_failed_types_remain_in_proof_and_never_enter_active(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    state = _state(prepared)
    closure = parse_threshold_no_good_vault(
        prepared.artifacts[o1c108.DERIVED_CLOSURE_NAME],
        observed_variables=state.attic.union_vault.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    active = {clause.serialized for clause in state.active_projection.clauses}
    residency = cast(Any, state.describe())
    counts = residency["o1c108_derived_activation_counts"]
    lineages = residency["o1c108_derived_last_active_lineages"]
    selected = {
        row["closure_index"]
        for row in residency["current_projection"]["selected_o1c108_derived_clauses"]
    }
    assert selected == set(o1c108.PASSING_NEW_DERIVED_INDICES)
    for index in o1c108.PASSING_NEW_DERIVED_INDICES:
        assert closure.clauses[index].serialized in active
        assert counts[index] == 1
        assert lineages[index] == 35
    for index in o1c108.FAILED_NEW_DERIVED_INDICES:
        assert closure.clauses[index].serialized not in active
        assert counts[index] == 0
        assert lineages[index] is None
        assert index not in selected


def test_logical_registry_is_3111_unique_in_stable_chronological_order(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = cast(Any, prepared.manifest)
    registry = manifest["logical_known_registry"]
    receipt_registry = _document(prepared, o1c108.DERIVED_RECEIPT_NAME)[
        "logical_known_registry"
    ]["combined"]
    assert registry["combined_clause_count"] == 3_111
    assert registry["combined_encoding_sha256"] == (
        "20cd02d895ef7024a827b2bf128111e1f0b8afb1db1d11f16f3ad6baa577de57"
    )
    assert registry["combined_clause_aggregate_sha256"] == (
        "45f7ac33a37eab1699c94064de94e19a7a976c5ad855587a8430700fa6beb2cc"
    )
    assert registry["combined_inventory_sha256"] == (
        "88a28c05da2f685ccc8a24193b05771c7ee02c7ba5fe1d8e987ef3662301576d"
    )
    assert registry["combined_literal_count"] == 8_801_942
    assert registry["combined_serialized_bytes"] == 35_220_403
    inventory = receipt_registry["clause_sha256"]
    assert len(inventory) == len(set(inventory)) == 3_111
    assert receipt_registry["next_global_novelty_baseline_clause_count"] == 3_111


def test_parent_bank_and_priority_receipt_are_carried_byte_exact(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    bank = prepared.artifacts[o1c108.FINAL_BANK_NAME]
    receipt = prepared.artifacts[o1c108.PRIORITY_RECEIPT_NAME]
    receipt_document = json.loads(receipt)
    assert bytes.fromhex(receipt_document["bank_hex"]) == bank
    assert receipt_document["bank_bytes"] == len(bank)
    assert receipt_document["current_bank_sha256"] == hashlib.sha256(bank).hexdigest()
    assert hashlib.sha256(bank).hexdigest() == (
        "62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f"
    )
    assert hashlib.sha256(receipt).hexdigest() == (
        "a3578ea3fb591b9227ca11034ac34aba8c170f47a65e05e092d108106f33129e"
    )


def test_manifest_binds_zero_call_parent_seals_and_exact_266_capacity(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = cast(Any, prepared.manifest)
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    assert manifest["parent_success"]["capsule_manifest_sha256"] == (
        "ffafafaac6c90d4d2092546629f0a2bee1f3067765cf6998aca30654a6118732"
    )
    assert manifest["parent_success"]["result_sha256"] == (
        "3d16db8abfa22531d1d18407c28b2c6e435b197d03e7297f2c837c6b50b48202"
    )
    assert manifest["canonical_o1c106"]["bundle_manifest_sha256"] == (
        "91044c235473c1a24fdeeb283454babc5ebc800ea19236840dd7193d6f3c96c2"
    )
    capacity = manifest["page22"]["native_capacity_proof"]
    assert capacity["page22_input_clauses"] == 246
    assert capacity["maximum_additional_unique_clauses_before_capacity_terminal"] == 266
    assert capacity["required_clause_headroom"] == 266
    assert capacity["proved_sufficient"] is True


def test_bundle_has_exact_20_file_inventory_and_self_validating_seals(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
) -> None:
    assert len(prepared.artifacts) == 20
    rows = cast(Any, prepared.manifest)["artifacts"]
    assert set(rows) == set(prepared.artifacts) - {o1c108.PREPARATION_MANIFEST_NAME}
    assert prepared.artifacts[o1c108.PREPARATION_MANIFEST_NAME] == (
        canonical_json_bytes(prepared.manifest)
    )
    assert (
        hashlib.sha256(prepared.artifacts[o1c108.PREPARATION_MANIFEST_NAME]).hexdigest()
        == o1c108.PREPARATION_MANIFEST_SHA256
    )
    for name, row in rows.items():
        payload = prepared.artifacts[name]
        assert row["serialized_bytes"] == len(payload)
        assert row["sha256"] == hashlib.sha256(payload).hexdigest()
    o1c108._validate_prepared_bundle_for_publication(prepared)


@pytest.mark.parametrize(
    "artifact",
    (
        o1c108.CERTIFICATION_AUDIT_NAME,
        o1c108.DERIVED_CLOSURE_NAME,
        o1c108.DERIVED_RECEIPT_NAME,
        o1c108.ACTIVE_PROJECTION_NAME,
        o1c108.PRIORITY_RECEIPT_NAME,
    ),
)
def test_publication_validator_rejects_artifact_tamper(
    prepared: o1c108.PreparedCausalRolloverArtifacts, artifact: str
) -> None:
    artifacts = dict(prepared.artifacts)
    artifacts[artifact] += b"\x00"
    with pytest.raises(o1c108.O1C108PreparationError):
        o1c108._validate_prepared_bundle_for_publication(
            replace(prepared, artifacts=artifacts)
        )


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("page22", "clause_count", 245),
        ("page22", "selected_new_o1c108_derived_clause_count", 150),
        ("logical_known_registry", "combined_clause_count", 3_110),
        ("certification", "new_candidate_fail_count", 3),
        ("derived_resolution_namespaces", "combined_overlay_materialized", True),
    ),
)
def test_publication_validator_rejects_self_consistent_manifest_tamper(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
    section: str,
    field: str,
    value: object,
) -> None:
    manifest = json.loads(canonical_json_bytes(prepared.manifest))
    manifest[section][field] = value
    with pytest.raises(o1c108.O1C108PreparationError):
        o1c108._validate_prepared_bundle_for_publication(
            _with_manifest(prepared, manifest)
        )


def test_parent_capsule_manifest_tamper_is_rejected_before_use(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "artifacts.sha256").write_bytes(b"0" * 5_267)
    with pytest.raises(o1c108.O1C108PreparationError):
        o1c108._validate_capsule_inventory(capsule)


def test_atomic_publication_refuses_an_existing_destination(
    prepared: o1c108.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page22"
    o1c108.write_prepared_o1c108_page22_type_safe_causal_rollover(prepared, output)
    assert {path.name for path in output.iterdir()} == set(prepared.artifacts)
    for name, payload in prepared.artifacts.items():
        assert (output / name).read_bytes() == payload
    with pytest.raises(o1c108.O1C108PreparationError):
        o1c108.write_prepared_o1c108_page22_type_safe_causal_rollover(prepared, output)


@pytest.mark.parametrize("command", ("preflight", "prepare"))
def test_cli_preflight_and_prepare_dispatch_without_native_calls(
    prepared: o1c108.PreparedCausalRolloverArtifacts,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    observed: list[Path] = []
    monkeypatch.setattr(
        o1c108,
        "prepare_o1c108_page22_type_safe_causal_rollover",
        lambda **_kwargs: prepared,
    )
    monkeypatch.setattr(
        o1c108,
        "write_prepared_o1c108_page22_type_safe_causal_rollover",
        lambda _prepared, output: observed.append(Path(output)),
    )
    argv = [command]
    if command == "prepare":
        argv += ["--output-dir", (tmp_path / "cli-output").as_posix()]
    assert o1c108.main(argv) == 0
    assert (bool(observed)) is (command == "prepare")
    output = json.loads(capsys.readouterr().out)
    assert output["schema"] == o1c108.PREPARATION_SCHEMA
    assert output["zero_call"]["native_solver_calls"] == 0
