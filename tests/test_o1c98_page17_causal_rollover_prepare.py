from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c98_page17_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c98_page17_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_o1c97_parent_boundary_and_zero_call_contract(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["attempt_id"] == "O1C-0097"
    assert parent["capsule_manifest_sha256"] == (
        "b7d8712b2ade9e5b75ff0d2f76c11907fbcafb3f01cf6e260e82303c08ff0f42"
    )
    assert parent["capsule_entry_count"] == 29
    assert parent["result_sha256"] == (
        "19b47ac6512c073d8f2b646d864d81cedfa8f1c2b2a9999f974c119779ae79e3"
    )
    assert parent["preparation_manifest_sha256"] == (
        "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
    )
    assert parent["source_lineage_ordinal"] == 29
    assert parent["source_active_sha256"] == prepare.PAGE16_SHA256
    assert parent["page16_burned"] is True
    assert parent["lineage29_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    assert parent["global_novelty_baseline_clause_count"] == 1_812
    assert parent["initial_artifacts_byte_equal_to_fresh_page16_regeneration"]

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
        "page17_burned": False,
        "lineage30_burned": False,
        "page16_replay_authorized": False,
        "lineage29_replay_authorized": False,
        "historical_page_retry_or_replay_authorized": False,
    }


def test_263_occurrences_preserve_one_current_duplicate_and_262_unique_clauses(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_fully_emitted_clause_count"] == 263
    assert science["imported_fully_emitted_literal_count"] == 748_011
    assert science["imported_globally_novel_clause_count"] == 262
    assert science["imported_globally_novel_literal_count"] == 745_152
    assert science["imported_current_duplicate_clause_count"] == 1
    assert science["imported_current_duplicate_literal_count"] == 2_859
    assert science["all_classifications"] == ["current_duplicate", "new"]
    assert science["historical_failed_or_retry_evidence_imported"] is False
    assert science["priority_state_magnitude_alone_imported_as_science"] is False
    assert "page9_retry_imported" not in science
    assert "o1c84_terminal_failure_imported_as_science" not in science

    rollover: Any = prepared.manifest["rollover"]
    duplicate = rollover["current_duplicate"]
    assert duplicate["emission_index"] == 7
    assert duplicate["duplicate_source_emission_index"] == 6
    assert "duplicates_emission_index" not in duplicate

    tail = prepared.state.attic.occurrences[-263:]
    assert len(tail) == 263
    assert all(row.stream_id == "o1c97-episode-00" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert sum(row.classification == "new" for row in tail) == 262
    assert sum(row.classification == "current_duplicate" for row in tail) == 1
    assert tail[6].classification == "new"
    assert tail[7].classification == "current_duplicate"
    assert tail[6].clause == tail[7].clause
    assert tail[6].clause_sha256 == tail[7].clause_sha256 == (
        "d479f1335c455aa61873154205c94b1a98cb050a0851fc8df65a5ed536baee2f"
    )
    assert tail[6].witness_sha256 == tail[7].witness_sha256 == (
        "a460a6832f4ab0afd09498956cedeb6a8ecd6d3bf9b18ef5677064d6faa4c0b1"
    )
    assert tail[7].witness_score == 13.293490727958314
    assert len({row.clause_sha256 for row in tail}) == 262
    known = {
        clause.sha256 for clause in prepared.state.attic.union_vault.clauses[:1_812]
    }
    assert not known.intersection(row.clause_sha256 for row in tail)

    occurrence_indices = prepared.state.attic.occurrence_union_indices[-263:]
    assert occurrence_indices[6] == occurrence_indices[7]
    assert len(set(occurrence_indices)) == 262
    assert set(occurrence_indices) == set(range(1_812, 2_074))


def test_unique_chunk_extends_union_and_occurrence_ledger_without_relation_gain(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    attic = prepared.state.attic
    chunk = attic.chunks[-1]
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 19
    assert chunk.sha256 == prepare.NEW_CHUNK_SHA256
    assert chunk.clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT == 262
    assert chunk.literal_count == prepare.NEW_CHUNK_LITERAL_COUNT == 745_152
    assert chunk.serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES == 2_981_847
    assert attic.chunk_clause_union_indices[-1] == tuple(range(1_812, 2_074))
    assert _sha256(prepared.artifacts[prepare.NEW_CHUNK_NAME]) == (
        prepare.NEW_CHUNK_SHA256
    )

    union = attic.union_vault
    assert union.sha256 == prepare.ATTIC_UNION_SHA256
    assert union.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT == 2_074
    assert union.literal_count == prepare.ATTIC_UNION_LITERAL_COUNT == 5_835_680
    assert union.serialized_bytes == prepare.ATTIC_UNION_SERIALIZED_BYTES == 23_351_207
    assert union.clauses[-262:] == chunk.clauses
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT == 2_083
    assert attic.duplicate_occurrence_count == 9
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT == 14
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT == 2_063

    prior_occurrences: Any = json.loads(
        (CAPSULE / "initial/occurrence-ledger.json").read_bytes()
    )
    current_occurrences: Any = prepared.state.attic.occurrence_document()
    assert current_occurrences["records"][:1_820] == prior_occurrences["records"]
    prior_relations: Any = json.loads(
        (CAPSULE / "initial/subsumption-relations.json").read_bytes()
    )
    current_relations: Any = prepared.state.attic.relation_document()
    assert current_relations["relations"] == prior_relations["relations"]
    attic_manifest: Any = prepared.manifest["attic"]
    assert attic_manifest["prior_1812_clause_union_is_exact_prefix"] is True
    assert attic_manifest["prior_relation_set_preserved_exactly"] is True
    assert attic_manifest["new_strict_subsumption_pair_count"] == 0
    assert attic_manifest["new_strict_subsumption_relations"] == []


def test_page17_is_fresh_exact_and_equal_burst_clause_safe(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 30
    assert state.active_limit == prepare.PAGE17_ACTIVE_LIMIT == 249
    assert page.sha256 == prepare.PAGE17_SHA256
    assert page.clause_count == prepare.PAGE17_CLAUSE_COUNT == 249
    assert page.literal_count == prepare.PAGE17_LITERAL_COUNT == 693_183
    assert page.serialized_bytes == prepare.PAGE17_SERIALIZED_BYTES == 2_773_919
    assert state.current_projection.category_counts == {
        "structural_root": 9,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 197,
        "hot_event": 0,
        "recycled": 0,
    }
    assert state.never_resident_undominated_indices == (
        prepare.NEVER_RESIDENT_UNDOMINATED_INDICES
    )
    assert len(state.never_resident_undominated_indices) == 65
    assert len(state.activation_ledger) == 18
    validate_activation_replay(state)

    page17: Any = prepared.manifest["page17"]
    assert page17["fresh_identity"] is True
    assert page17["headroom"] == {
        "clauses": 263,
        "literals": 906_817,
        "serialized_bytes": 5_614_689,
    }
    capacity = page17["native_capacity_proof"]
    clause_proof = capacity["clause_headroom_guarantee"]
    assert clause_proof["maximum_additional_clauses_before_capacity_terminal"] == 263
    assert clause_proof["equal_parent_burst_clause_count"] == 263
    assert clause_proof["equal_parent_burst_fits_exactly"] is True
    assert 249 + 263 == 512
    assert clause_proof["parent_centered_action_capacity"] == 256
    assert clause_proof["spare_clause_slots_beyond_action_capacity"] == 7
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False

    sacrifice = page17["two_slot_residency_sacrifice"]
    assert sacrifice["source_input_clause_count"] == 251
    assert sacrifice["fully_emitted_clause_count"] == 263
    assert sacrifice["unsacrificed_terminal_clause_count"] == 514
    assert sacrifice["terminal_overflow_clause_count"] == 2
    assert sacrifice["prior_active_limit"] == 251
    assert sacrifice["next_active_limit"] == 249
    assert sacrifice["residency_slots_sacrificed"] == 2
    assert sacrifice["new_structural_root_count"] == 0

    residency = page17["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 262
    assert residency["resident_clause_count"] == 197
    assert tuple(residency["resident_union_indices"]) == (
        prepare.NEW_RESIDENT_UNION_INDICES
    )
    assert residency["missing_clause_count"] == 65
    assert tuple(residency["missing_union_indices"]) == (
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert residency["dominated_missing_clause_count"] == 0
    assert residency["undominated_missing_clause_count"] == 65
    assert 1_960 in residency["missing_union_indices"]
    assert state.attic.union_vault.clauses[1_960].sha256 == (
        "93b78aba548d831615283bb517a6a10e1cf6a296b0cdd2802b085fcb7ec8d805"
    )


def test_activation_prefix_and_evolved_bank_receipt_are_exact(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior: Any = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current: Any = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 30
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE17_SHA256
    assert prepare.PAGE17_SHA256 not in prior["used_active_sha256"]

    episode = CAPSULE / "episodes/00"
    bank = prepared.artifacts[prepare.FINAL_BANK_NAME]
    receipt = prepared.artifacts[prepare.PRIORITY_RECEIPT_NAME]
    assert bank == (episode / "final-parent-centered-priority-bank.bin").read_bytes()
    assert receipt == (episode / "priority-state.json").read_bytes()
    assert len(bank) == prepare.FINAL_BANK_BYTES == 24_576
    assert _sha256(bank) == prepare.FINAL_BANK_SHA256 == (
        "8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc"
    )
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 52_011
    assert _sha256(receipt) == prepare.PRIORITY_RECEIPT_SHA256 == (
        "050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad"
    )
    assert canonical_json_bytes(json.loads(receipt)) == receipt
    continuation: Any = prepared.manifest["final_priority_bank"]
    assert continuation["validation_contract"] == (
        "o1c97-live-continuation-bank-with-state-receipt"
    )
    assert continuation["receipt_bank_hex_byte_equal"] is True
    assert continuation["minimum_nonzero_evolved_count"] == 230
    assert continuation["maximum_evolved_count"] == 2_921
    assert continuation["maximum_evolved_count_variables"] == [15]
    assert continuation["aggregate_evolved_count"] == 316_312
    assert continuation["fresh_seed_parser_compatible"] is False


def test_artifact_bundle_is_canonical_byte_sealed_and_published_atomically(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
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

    output = tmp_path / "page17"
    prepare.write_prepared_o1c98_page17_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C98PreparationError, match="publication failed"):
        prepare.write_prepared_o1c98_page17_causal_rollover(prepared, output)

    tampered_artifacts = dict(prepared.artifacts)
    tampered_artifacts[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_artifacts,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C98PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c98_page17_causal_rollover(
            tampered, tmp_path / "tampered"
        )


def test_source_tampering_canonical_paths_cli_and_forbidden_interfaces(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C98PreparationError, match="result binding"):
        prepare.prepare_o1c98_page17_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C98PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(CAPSULE, bytes(tampered_bank))
    with pytest.raises(prepare.O1C98PreparationError, match="not canonical"):
        prepare.prepare_o1c98_page17_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )

    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c98-page17"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c98-page17"

    source = Path(prepare.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "subprocess" not in imports
    assert not any("continuation_run" in imported for imported in imports)
    assert "native_solver_calls\": 0" in source
    assert "native_preflight_calls\": 0" in source
    assert "target_bytes_read\": False" in source
    assert "truth_key_bytes_read\": False" in source
    assert "reveal_calls\": 0" in source
