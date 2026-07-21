from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator, cast

import pytest

from o1_crypto_lab import o1c106_page21_type_safe_rollover_prepare as o1c106
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


@pytest.fixture(scope="module")
def prepared() -> Iterator[o1c106.PreparedCausalRolloverArtifacts]:
    yield o1c106.prepare_o1c106_page21_type_safe_rollover()


def _audit(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> Any:
    return json.loads(prepared.artifacts[o1c106.CERTIFICATION_AUDIT_NAME])


def _with_manifest(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
    manifest: Any,
) -> o1c106.PreparedCausalRolloverArtifacts:
    artifacts = dict(prepared.artifacts)
    artifacts[o1c106.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(manifest)
    return replace(prepared, manifest=manifest, artifacts=artifacts)


def test_page21_frozen_encoding_and_replacement_selector(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    state = cast(o1c106.ComposedPage21State, prepared.state)
    page = state.active_projection
    projection = state.current_projection
    assert page.sha256 == o1c106.PAGE21_SHA256
    assert page.clause_count == 247
    assert page.literal_count == 690_330
    assert page.serialized_bytes == 2_762_499
    assert (
        page.clause_aggregate_sha256
        == "72740ed87b246f17a24de10529d86f37aa6878f467d92bbcfdae197f001b1bab"
    )
    assert projection.replacement_emitted_union_indices == (
        2387,
        2395,
        2461,
        2349,
        2459,
        2429,
        2379,
        2355,
        2437,
        2451,
        2445,
    )
    assert (
        o1c106._canonical_index_list_sha256(
            projection.replacement_emitted_union_indices
        )
        == "76fb8a6e30e3c1241d79975a8f6d1e8691c65c326802fc27e490dc7d5b142c8e"
    )
    assert len(projection.selected_emitted_union_indices) == 203
    assert len(projection.selected_inherited_derived_clauses) == 3
    assert len(projection.selected_new_derived_clauses) == 41


def test_page21_is_fresh_and_forbidden_pure_candidate_was_not_activated(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    state = cast(o1c106.ComposedPage21State, prepared.state)
    assert o1c106.PAGE20_SHA256 in state.used_active_sha256
    assert o1c106.PAGE20_PURE_EMITTED_SHA256 not in state.used_active_sha256
    assert state.active_projection.sha256 not in {
        o1c106.PAGE20_SHA256,
        o1c106.PAGE20_PURE_EMITTED_SHA256,
    }
    activation = cast(Any, state.activation_ledger_document())
    assert activation["pure_emitted_candidate_activated"] is False
    assert (
        activation["forbidden_nonactivated_candidate_sha256"]
        == o1c106.PAGE20_PURE_EMITTED_SHA256
    )
    assert activation["burned_parent"]["lineage_ordinal"] == 33
    assert activation["burned_parent"]["retry_or_replay_authorized"] is False


def test_real_v8_audit_certifies_all_active_and_excludes_exact_failures(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    audit = _audit(prepared)
    page = audit["page21"]
    categories = audit["categories"]
    execution = audit["execution"]
    assert audit["passed"] is True
    assert audit["publication_gate"] == (
        "all-247-active-v8-certifications-finished-before-publication"
    )
    assert page["active_pass_count"] == 247
    assert page["active_fail_count"] == 0
    assert page["maximum_active_upper_bound"] == 14.605986705470585
    assert page["maximum_strictly_below_threshold"] is True
    assert categories["emitted"] == {"active": 203, "pass": 203, "fail": 0}
    assert categories["inherited_derived"] == {
        "active": 3,
        "pass": 3,
        "fail": 0,
    }
    assert tuple(categories["new_derived"]["passing_closure_indices"]) == (
        0,
        2,
        12,
        13,
        *range(15, 52),
    )
    assert tuple(categories["new_derived"]["excluded_failing_closure_indices"]) == (
        1,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        14,
    )
    assert len(audit["active_rows_in_serialization_order"]) == 247
    assert all(
        row["passed"] is True for row in audit["active_rows_in_serialization_order"]
    )
    assert len(audit["excluded_new_overlay_failure_rows"]) == 11
    assert all(
        row["failure"] == "joint-score-sieve-v8 grouped no-good certification differs"
        for row in audit["excluded_new_overlay_failure_rows"]
    )
    assert execution == {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
        "offline_only": True,
    }


def test_logical_registry_order_and_sidecars_are_preserved_byte_exact(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = cast(Any, prepared.manifest)
    registry = manifest["logical_known_registry"]
    assert registry["registry_segment_order"] == [
        "historical-emitted-causal-attic",
        "inherited-o1c102-derived-resolution",
        "new-o1c103-native-emission",
        "new-o1c104-derived-resolution",
    ]
    assert registry["combined_clause_count"] == 2692
    assert registry["combined_encoding_sha256"] == (
        "ed53e022239f84f3bc9bbb2a822170405e362ba1a0a98a1d887e9c38d79f0220"
    )
    assert registry["combined_inventory_sha256"] == (
        "9b61b7e9dc9c299c311f46a6f3dce683798b589fb1994b96987fc69768a6379f"
    )
    root = o1c106.lab_root() / o1c106.DEFAULT_O1C104_BUNDLE_RELATIVE
    sidecars = (
        o1c106.INHERITED_DERIVED_RECEIPT_NAME,
        o1c106.INHERITED_DERIVED_CLOSURE_NAME,
        o1c106.INHERITED_DERIVED_OVERLAY_NAME,
        o1c106.DERIVED_RECEIPT_NAME,
        o1c106.DERIVED_CLOSURE_NAME,
        o1c106.DERIVED_OVERLAY_NAME,
        o1c106.FINAL_BANK_NAME,
        o1c106.PRIORITY_RECEIPT_NAME,
    )
    for name in sidecars:
        assert prepared.artifacts[name] == (root / name).read_bytes()


def test_failed_clauses_remain_in_sidecars_and_historical_activation_only(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    state = cast(o1c106.ComposedPage21State, prepared.state)
    residency = cast(Any, state.describe())
    counts = residency["new_derived_activation_counts"]
    lineages = residency["new_derived_last_active_lineages"]
    selected = {
        row["closure_index"]
        for row in residency["current_projection"]["selected_new_derived_clauses"]
    }
    assert selected == set(o1c106.PASSING_NEW_OVERLAY_INDICES)
    for index in o1c106.PASSING_NEW_OVERLAY_INDICES:
        assert counts[index] == 2
        assert lineages[index] == 34
    for index in o1c106.FAILED_NEW_OVERLAY_INDICES:
        assert counts[index] == 1
        assert lineages[index] == 33
        assert index not in selected
    overlay = parse_threshold_no_good_vault(
        prepared.artifacts[o1c106.DERIVED_OVERLAY_NAME],
        observed_variables=state.attic.union_vault.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert overlay.clause_count == 52


def test_manifest_binds_parent_terminal_audit_and_capacity(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = cast(Any, prepared.manifest)
    parent = manifest["parent_terminal"]
    certification = manifest["certification"]
    page = manifest["page21"]
    assert parent["result_sha256"] == (
        "f4e4e2ef4fcec6817b3fa6cf445448cae9aa693460c14cd2a8f7a7a3a295d66b"
    )
    assert parent["intent_sha256"] == (
        "013ad6009c770b1370a935584ccd0f85acbc737b4895ab3ee09c6e6d58a558f9"
    )
    assert parent["capsule_manifest_sha256"] == (
        "5185f293b51a1185cca1d06f18f6c4ca85172bd1245bb08867df293a995f8d97"
    )
    assert parent["page20_burned"] is True
    assert parent["lineage33_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    audit_payload = prepared.artifacts[o1c106.CERTIFICATION_AUDIT_NAME]
    assert certification["sha256"] == hashlib.sha256(audit_payload).hexdigest()
    assert certification["all_active_clauses_certified_before_publication"] is True
    assert page["headroom"]["clauses"] == 265
    assert page["native_capacity_proof"]["proved_sufficient"] is True
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }


def test_bundle_has_exact_17_file_inventory_and_all_artifact_seals(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    assert len(prepared.artifacts) == 17
    rows = cast(Any, prepared.manifest)["artifacts"]
    assert set(rows) == set(prepared.artifacts) - {o1c106.PREPARATION_MANIFEST_NAME}
    assert prepared.artifacts[o1c106.PREPARATION_MANIFEST_NAME] == canonical_json_bytes(
        prepared.manifest
    )
    for name, row in rows.items():
        payload = prepared.artifacts[name]
        assert row["serialized_bytes"] == len(payload)
        assert row["sha256"] == hashlib.sha256(payload).hexdigest()


def test_publication_validator_rejects_tampered_audit(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    artifacts = dict(prepared.artifacts)
    artifacts[o1c106.CERTIFICATION_AUDIT_NAME] += b"\n"
    tampered = replace(prepared, artifacts=artifacts)
    with pytest.raises(o1c106.O1C106PreparationError):
        o1c106._validate_prepared_bundle_for_publication(tampered)


def test_publication_is_atomic_and_refuses_existing_destination(
    prepared: o1c106.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page21"
    o1c106.write_prepared_o1c106_page21_type_safe_rollover(prepared, output)
    assert {path.name for path in output.iterdir()} == set(prepared.artifacts)
    for name, payload in prepared.artifacts.items():
        assert (output / name).read_bytes() == payload
    with pytest.raises(o1c106.O1C106PreparationError):
        o1c106.write_prepared_o1c106_page21_type_safe_rollover(prepared, output)


def test_publication_validator_rejects_manifest_active_identity_tamper(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
) -> None:
    manifest = json.loads(canonical_json_bytes(prepared.manifest))
    manifest["page21"]["active_sha256"] = "0" * 64
    tampered = _with_manifest(prepared, manifest)
    with pytest.raises(o1c106.O1C106PreparationError):
        o1c106._validate_prepared_bundle_for_publication(tampered)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("page21", "clause_count", 246),
        ("page21", "selected_new_derived_clause_count", 42),
        ("page21", "replacement_emitted_union_indices_sha256", "0" * 64),
        ("logical_known_registry", "combined_clause_count", 2_691),
        ("derived_resolution_namespaces", "combined_overlay_materialized", True),
        ("certification", "active_pass_count", 246),
    ),
)
def test_publication_validator_rejects_self_consistent_manifest_contract_tamper(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
    section: str,
    field: str,
    value: object,
) -> None:
    manifest = json.loads(canonical_json_bytes(prepared.manifest))
    manifest[section][field] = value
    tampered = _with_manifest(prepared, manifest)
    with pytest.raises(o1c106.O1C106PreparationError):
        o1c106._validate_prepared_bundle_for_publication(tampered)


@pytest.mark.parametrize(
    "field",
    (
        "excluded_new_derived_closure_indices",
        "displaced_emitted_union_indices",
        "category_counts",
        "category_priority_order",
    ),
)
def test_projection_rejects_residency_provenance_tamper(
    prepared: o1c106.PreparedCausalRolloverArtifacts,
    field: str,
) -> None:
    state = cast(o1c106.ComposedPage21State, prepared.state)
    projection = state.current_projection
    document = json.loads(canonical_json_bytes(projection.document))
    value = document[field]
    if isinstance(value, list):
        value.pop()
    else:
        first = next(iter(value))
        value[first] += 1
    with pytest.raises(o1c106.O1C106PreparationError):
        replace(projection, document=document)
