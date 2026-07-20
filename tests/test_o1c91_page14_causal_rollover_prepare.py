from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c91_page14_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c91_page14_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_o1c90_parent_boundary_and_only_new_science_are_imported(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["attempt_id"] == "O1C-0090"
    assert parent["capsule_manifest_sha256"] == (
        "d4088eddb3cf671b908ebbc2d19e6e0159eac149b4b882bb21cca62635df1df0"
    )
    assert parent["capsule_entry_count"] == 29
    assert parent["result_sha256"] == (
        "7089f78809de90007a4914f0cdaebeef7491d04a46871d05e8a2598e30676886"
    )
    assert parent["preparation_manifest_sha256"] == (
        "467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec"
    )
    assert parent["source_lineage_ordinal"] == 26
    assert parent["source_active_sha256"] == prepare.PAGE13_SHA256
    assert parent["page13_burned"] is True
    assert parent["lineage26_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    assert parent["global_novelty_baseline_clause_count"] == 1_291
    assert parent["initial_artifacts_byte_equal_to_fresh_page13_regeneration"]

    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    assert prepared.manifest["authorization"] == {
        "science_call_authorized": False,
        "intent_created": False,
        "page14_burned": False,
        "lineage27_burned": False,
        "page13_replay_authorized": False,
        "lineage26_replay_authorized": False,
        "page9_retry_or_replay_authorized": False,
    }
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_fully_emitted_clause_count"] == 260
    assert science["imported_globally_novel_clause_count"] == 260
    assert science["imported_literal_count"] == 743_794
    assert science["all_sources"] == ["trail_upper_bound"]
    assert science["all_classifications"] == ["new"]
    assert science["page9_retry_imported"] is False
    assert science["o1c84_terminal_failure_imported_as_science"] is False
    assert science["priority_magnitude_imported_as_science"] is False
    assert "o1c84-terminal-failure-receipt.json" not in prepared.artifacts

    tail = prepared.state.attic.occurrences[-260:]
    assert len(tail) == 260
    assert all(row.stream_id == "o1c90-episode-00" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert all(row.classification == "new" for row in tail)
    assert len({row.clause_sha256 for row in tail}) == 260
    known = {
        clause.sha256
        for clause in prepared.state.attic.union_vault.clauses[:1_291]
    }
    assert not known.intersection(row.clause_sha256 for row in tail)


def test_exact_chunk_and_immutable_attic_extension(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    chunk = attic.chunks[-1]
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 17
    assert chunk.sha256 == prepare.NEW_CHUNK_SHA256
    assert chunk.clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT == 260
    assert chunk.literal_count == prepare.NEW_CHUNK_LITERAL_COUNT == 743_794
    assert chunk.serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES == 2_976_407
    assert _sha256(prepared.artifacts[prepare.NEW_CHUNK_NAME]) == (
        prepare.NEW_CHUNK_SHA256
    )

    union = attic.union_vault
    assert union.sha256 == prepare.ATTIC_UNION_SHA256
    assert union.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT == 1_551
    assert union.literal_count == prepare.ATTIC_UNION_LITERAL_COUNT == 4_334_114
    assert union.serialized_bytes == prepare.ATTIC_UNION_SERIALIZED_BYTES == 17_342_851
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT == 1_559
    assert attic.duplicate_occurrence_count == 8
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT == 13
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT == 1_541
    assert attic.chunk_clause_union_indices[-1] == tuple(range(1_291, 1_551))
    assert attic.occurrence_union_indices[-260:] == tuple(range(1_291, 1_551))
    attic_manifest: Any = prepared.manifest["attic"]
    assert attic_manifest["prior_1291_clause_union_is_exact_prefix"] is True
    assert attic_manifest["prior_relation_set_preserved_exactly"] is True
    assert attic_manifest["new_strict_subsumption_pair_count"] == 3
    relations = attic_manifest["new_strict_subsumption_relations"]
    assert [
        (row["subsumer_index"], row["subsumed_index"]) for row in relations
    ] == list(prepare.NEW_STRICT_SUBSUMPTION_RELATIONS)
    assert [row["literal_delta"] for row in relations] == [2, 15, 17]


def test_page14_is_fresh_exact_and_mechanically_cap_safe(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 27
    assert state.active_limit == prepare.PAGE14_ACTIVE_LIMIT == 252
    assert page.sha256 == prepare.PAGE14_SHA256
    assert page.clause_count == prepare.PAGE14_CLAUSE_COUNT == 252
    assert page.literal_count == prepare.PAGE14_LITERAL_COUNT == 704_145
    assert page.serialized_bytes == prepare.PAGE14_SERIALIZED_BYTES == 2_817_779
    assert state.current_projection.category_counts == {
        "structural_root": 8,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 201,
        "hot_event": 0,
        "recycled": 0,
    }
    assert state.never_resident_undominated_indices == (
        prepare.NEVER_RESIDENT_UNDOMINATED_INDICES
    )
    assert len(state.never_resident_undominated_indices) == 107
    assert len(state.activation_ledger) == 15
    validate_activation_replay(state)

    page14: Any = prepared.manifest["page14"]
    assert page14["fresh_identity"] is True
    assert page14["headroom"] == {
        "clauses": 260,
        "literals": 895_855,
        "serialized_bytes": 5_570_829,
    }
    capacity = page14["native_capacity_proof"]
    assert capacity["caps"] == {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    clause_proof = capacity["clause_headroom_guarantee"]
    assert clause_proof["maximum_additional_clauses_before_capacity_terminal"] == 260
    assert clause_proof["parent_centered_action_capacity"] == 256
    assert clause_proof["spare_clause_slots_beyond_action_capacity"] == 4
    assert clause_proof["proved_sufficient"] is True
    assert capacity["recorded_residual_headroom"] == {
        "literals": 895_855,
        "serialized_bytes": 5_570_829,
    }
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False

    sacrifice = page14["one_slot_residency_sacrifice"]
    assert sacrifice == {
        "source_input_clause_count": 253,
        "fully_emitted_clause_count": 260,
        "unsacrificed_terminal_clause_count": 513,
        "native_vault_maximum_clauses": 512,
        "terminal_overflow_clause_count": 1,
        "prior_active_limit": 253,
        "next_active_limit": 252,
        "residency_slots_sacrificed": 1,
        "measured_clause_headroom": 260,
        "prior_structural_root_count": 5,
        "new_structural_root_count": 3,
        "next_structural_root_count": 8,
        "pinned_core_count_preserved": 43,
    }
    residency = page14["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 260
    assert residency["resident_clause_count"] == 190
    assert tuple(residency["resident_union_indices"]) == (
        prepare.NEW_RESIDENT_UNION_INDICES
    )
    assert residency["missing_clause_count"] == 70
    assert tuple(residency["missing_union_indices"]) == (
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert [row["union_index"] for row in residency["missing_clauses"]] == list(
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert all(len(row["clause_sha256"]) == 64 for row in residency["missing_clauses"])
    assert residency["dominated_missing_clause_count"] == 3
    assert tuple(residency["dominated_missing_union_indices"]) == (
        prepare.NEW_DOMINATED_MISSING_UNION_INDICES
    )
    assert residency["undominated_missing_clause_count"] == 67
    assert tuple(residency["undominated_missing_union_indices"]) == (
        prepare.NEW_UNDOMINATED_MISSING_UNION_INDICES
    )

    prior = page14["prior_clause_residency"]
    assert prior["prior_missing_clause_count"] == 54
    assert prior["newly_resident_clause_count"] == 14
    assert tuple(prior["newly_resident_union_indices"]) == (
        prepare.PRIOR_NEWLY_RESIDENT_UNION_INDICES
    )
    assert prior["remaining_missing_clause_count"] == 40
    assert tuple(prior["remaining_missing_union_indices"]) == (
        prepare.PRIOR_REMAINING_MISSING_UNION_INDICES
    )
    never = page14["never_resident_undominated"]
    assert never["clause_count"] == 107
    assert tuple(never["union_indices"]) == (
        prepare.NEVER_RESIDENT_UNDOMINATED_INDICES
    )


def test_page13_activation_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior: Any = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current: Any = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 27
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE14_SHA256
    assert prepare.PAGE14_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == 15


def test_evolved_bank_and_exact_receipt_are_carried_together(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    episode = CAPSULE / "episodes/00"
    bank = prepared.artifacts[prepare.FINAL_BANK_NAME]
    receipt = prepared.artifacts[prepare.PRIORITY_RECEIPT_NAME]
    assert bank == (episode / "final-parent-centered-priority-bank.bin").read_bytes()
    assert receipt == (episode / "priority-state.json").read_bytes()
    assert len(bank) == prepare.FINAL_BANK_BYTES == 24_576
    assert _sha256(bank) == prepare.FINAL_BANK_SHA256
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 52_016
    assert _sha256(receipt) == prepare.PRIORITY_RECEIPT_SHA256
    assert canonical_json_bytes(json.loads(receipt)) == receipt

    continuation: Any = prepared.manifest["final_priority_bank"]
    assert continuation["semantic_role"] == ("sealed-evolved-live-continuation-bytes")
    assert continuation["receipt_artifact"] == prepare.PRIORITY_RECEIPT_NAME
    assert continuation["receipt_bank_hex_byte_equal"] is True
    assert continuation["coordinate_record_count"] == 256
    assert continuation["record_bytes"] == 96
    assert continuation["eligible_coordinate_count"] == 255
    assert continuation["zero_coordinate_variables"] == [241]
    assert continuation["minimum_nonzero_evolved_count"] == 224
    assert continuation["maximum_evolved_count"] == 2_180
    assert continuation["maximum_evolved_count_variables"] == [15]
    assert continuation["aggregate_evolved_count"] == 249_671
    assert continuation["fresh_seed_parser_compatible"] is False


def test_artifact_bundle_is_complete_canonical_and_byte_sealed(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    artifacts = prepared.artifacts
    assert set(artifacts) == {
        prepare.NEW_CHUNK_NAME,
        prepare.ACTIVE_PROJECTION_NAME,
        prepare.RESIDENCY_NAME,
        prepare.ACTIVATION_LEDGER_NAME,
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.COMMON_CORE_AUDIT_NAME,
        prepare.FINAL_BANK_NAME,
        prepare.PRIORITY_RECEIPT_NAME,
        prepare.PREPARATION_MANIFEST_NAME,
    }
    assert artifacts[prepare.ACTIVE_PROJECTION_NAME] == (
        prepared.state.active_projection.serialized
    )
    assert artifacts[prepare.RESIDENCY_NAME] == canonical_json_bytes(
        prepared.state.describe()
    )
    assert artifacts[prepare.ACTIVATION_LEDGER_NAME] == canonical_json_bytes(
        prepared.state.activation_ledger_document()
    )
    assert artifacts[prepare.OCCURRENCES_NAME] == canonical_json_bytes(
        prepared.state.attic.occurrence_document()
    )
    assert artifacts[prepare.RELATIONS_NAME] == canonical_json_bytes(
        prepared.state.attic.relation_document()
    )
    manifest_payload = artifacts[prepare.PREPARATION_MANIFEST_NAME]
    assert manifest_payload == canonical_json_bytes(prepared.manifest)
    assert len(manifest_payload) == prepare.PREPARATION_MANIFEST_BYTES
    assert _sha256(manifest_payload) == prepare.PREPARATION_MANIFEST_SHA256
    rows: Any = prepared.manifest["artifacts"]
    assert set(rows) == set(artifacts) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(artifacts[name])
        assert row["sha256"] == _sha256(artifacts[name])
        assert isinstance(row["role"], str) and row["role"]


def test_atomic_writer_refuses_republication_and_tampered_bundle(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page14"
    prepare.write_prepared_o1c91_page14_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C91PreparationError, match="publication failed"):
        prepare.write_prepared_o1c91_page14_causal_rollover(prepared, output)

    tampered_artifacts = dict(prepared.artifacts)
    tampered_artifacts[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_artifacts,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C91PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c91_page14_causal_rollover(
            tampered, tmp_path / "tampered"
        )

    false_manifest = json.loads(canonical_json_bytes(prepared.manifest))
    false_manifest["page14"]["headroom"]["clauses"] = 257
    false_artifacts = dict(prepared.artifacts)
    false_artifacts[prepare.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(
        false_manifest
    )
    falsified = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=false_artifacts,
        manifest=false_manifest,
    )
    with pytest.raises(prepare.O1C91PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c91_page14_causal_rollover(
            falsified, tmp_path / "falsified"
        )


def test_source_tampering_and_bank_receipt_mismatch_are_rejected(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C91PreparationError, match="result binding"):
        prepare.prepare_o1c91_page14_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C91PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(CAPSULE, bytes(tampered_bank))

    with pytest.raises(prepare.O1C91PreparationError, match="not canonical"):
        prepare.prepare_o1c91_page14_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c91-page14"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c91-page14"


def test_source_has_no_native_solver_target_truth_or_reveal_interface() -> None:
    source = Path(prepare.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {"subprocess", "o1c90_apple8_parent_centered_continuation_run"} & imports
    assert "native_solver_calls\": 0" in source
    assert "target_bytes_read\": False" in source
    assert "truth_key_bytes_read\": False" in source
    assert "reveal_calls\": 0" in source
