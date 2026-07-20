from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c93_page15_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c93_page15_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_o1c92_parent_boundary_and_only_new_science_are_imported(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["attempt_id"] == "O1C-0092"
    assert parent["capsule_manifest_sha256"] == (
        "b91e23706c1a019c30f4de016f4f78e8da3494416e9a5fc69043b5c2fb890eae"
    )
    assert parent["capsule_entry_count"] == 29
    assert parent["result_sha256"] == (
        "04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c"
    )
    assert parent["preparation_manifest_sha256"] == (
        "e46ca7373bc3a94efc30dcd309728005e3bee8b93983dc2c396f45bd487dd458"
    )
    assert parent["source_lineage_ordinal"] == 27
    assert parent["source_active_sha256"] == prepare.PAGE14_SHA256
    assert parent["page14_burned"] is True
    assert parent["lineage27_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    assert parent["global_novelty_baseline_clause_count"] == 1_551
    assert parent["initial_artifacts_byte_equal_to_fresh_page14_regeneration"]

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
        "page15_burned": False,
        "lineage28_burned": False,
        "page14_replay_authorized": False,
        "lineage27_replay_authorized": False,
        "page13_replay_authorized": False,
        "page9_retry_or_replay_authorized": False,
    }
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_fully_emitted_clause_count"] == 261
    assert science["imported_globally_novel_clause_count"] == 261
    assert science["imported_literal_count"] == 756_414
    assert science["all_sources"] == ["trail_upper_bound"]
    assert science["all_classifications"] == ["new"]
    assert science["page9_retry_imported"] is False
    assert science["o1c84_terminal_failure_imported_as_science"] is False
    assert science["priority_magnitude_imported_as_science"] is False
    assert "o1c84-terminal-failure-receipt.json" not in prepared.artifacts

    tail = prepared.state.attic.occurrences[-261:]
    assert len(tail) == 261
    assert all(row.stream_id == "o1c92-episode-00" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert all(row.classification == "new" for row in tail)
    assert len({row.clause_sha256 for row in tail}) == 261
    known = {
        clause.sha256
        for clause in prepared.state.attic.union_vault.clauses[:1_551]
    }
    assert not known.intersection(row.clause_sha256 for row in tail)


def test_exact_chunk_and_immutable_attic_extension(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    chunk = attic.chunks[-1]
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 18
    assert chunk.sha256 == prepare.NEW_CHUNK_SHA256
    assert chunk.clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT == 261
    assert chunk.literal_count == prepare.NEW_CHUNK_LITERAL_COUNT == 756_414
    assert chunk.serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES == 3_026_891
    assert _sha256(prepared.artifacts[prepare.NEW_CHUNK_NAME]) == (
        prepare.NEW_CHUNK_SHA256
    )

    union = attic.union_vault
    assert union.sha256 == prepare.ATTIC_UNION_SHA256
    assert union.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT == 1_812
    assert union.literal_count == prepare.ATTIC_UNION_LITERAL_COUNT == 5_090_528
    assert union.serialized_bytes == prepare.ATTIC_UNION_SERIALIZED_BYTES == 20_369_551
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT == 1_820
    assert attic.duplicate_occurrence_count == 8
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT == 14
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT == 1_801
    assert attic.chunk_clause_union_indices[-1] == tuple(range(1_551, 1_812))
    assert attic.occurrence_union_indices[-261:] == tuple(range(1_551, 1_812))
    attic_manifest: Any = prepared.manifest["attic"]
    assert attic_manifest["prior_1551_clause_union_is_exact_prefix"] is True
    assert attic_manifest["prior_relation_set_preserved_exactly"] is True
    assert attic_manifest["new_strict_subsumption_pair_count"] == 1
    relations = attic_manifest["new_strict_subsumption_relations"]
    assert [
        (row["subsumer_index"], row["subsumed_index"]) for row in relations
    ] == list(prepare.NEW_STRICT_SUBSUMPTION_RELATIONS)
    assert [row["literal_delta"] for row in relations] == [17]


def test_page15_is_fresh_exact_and_mechanically_cap_safe(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 28
    assert state.active_limit == prepare.PAGE15_ACTIVE_LIMIT == 251
    assert page.sha256 == prepare.PAGE15_SHA256
    assert page.clause_count == prepare.PAGE15_CLAUSE_COUNT == 251
    assert page.literal_count == prepare.PAGE15_LITERAL_COUNT == 710_463
    assert page.serialized_bytes == prepare.PAGE15_SERIALIZED_BYTES == 2_843_047
    assert state.current_projection.category_counts == {
        "structural_root": 9,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 199,
        "hot_event": 0,
        "recycled": 0,
    }
    assert state.never_resident_undominated_indices == (
        prepare.NEVER_RESIDENT_UNDOMINATED_INDICES
    )
    assert len(state.never_resident_undominated_indices) == 167
    assert len(state.activation_ledger) == 16
    validate_activation_replay(state)

    page15: Any = prepared.manifest["page15"]
    assert page15["fresh_identity"] is True
    assert page15["headroom"] == {
        "clauses": 261,
        "literals": 889_537,
        "serialized_bytes": 5_545_561,
    }
    capacity = page15["native_capacity_proof"]
    assert capacity["caps"] == {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    clause_proof = capacity["clause_headroom_guarantee"]
    assert clause_proof["maximum_additional_clauses_before_capacity_terminal"] == 261
    assert clause_proof["parent_centered_action_capacity"] == 256
    assert clause_proof["spare_clause_slots_beyond_action_capacity"] == 5
    assert clause_proof["proved_sufficient"] is True
    assert capacity["recorded_residual_headroom"] == {
        "literals": 889_537,
        "serialized_bytes": 5_545_561,
    }
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False

    sacrifice = page15["one_slot_residency_sacrifice"]
    assert sacrifice == {
        "source_input_clause_count": 252,
        "fully_emitted_clause_count": 261,
        "unsacrificed_terminal_clause_count": 513,
        "native_vault_maximum_clauses": 512,
        "terminal_overflow_clause_count": 1,
        "prior_active_limit": 252,
        "next_active_limit": 251,
        "residency_slots_sacrificed": 1,
        "measured_clause_headroom": 261,
        "prior_structural_root_count": 8,
        "new_structural_root_count": 1,
        "next_structural_root_count": 9,
        "pinned_core_count_preserved": 43,
    }
    residency = page15["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 261
    assert residency["resident_clause_count"] == 160
    assert tuple(residency["resident_union_indices"]) == (
        prepare.NEW_RESIDENT_UNION_INDICES
    )
    assert residency["missing_clause_count"] == 101
    assert tuple(residency["missing_union_indices"]) == (
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert [row["union_index"] for row in residency["missing_clauses"]] == list(
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert all(len(row["clause_sha256"]) == 64 for row in residency["missing_clauses"])
    assert residency["dominated_missing_clause_count"] == 1
    assert tuple(residency["dominated_missing_union_indices"]) == (
        prepare.NEW_DOMINATED_MISSING_UNION_INDICES
    )
    assert residency["undominated_missing_clause_count"] == 100
    assert tuple(residency["undominated_missing_union_indices"]) == (
        prepare.NEW_UNDOMINATED_MISSING_UNION_INDICES
    )

    selected = frozenset(state.current_projection.selected_union_indices)
    new_indices = tuple(range(1_551, 1_812))
    derived_missing = tuple(index for index in new_indices if index not in selected)
    dominated = frozenset(row.subsumed_index for row in state.attic.relations)
    derived_dominated_missing = tuple(
        index for index in derived_missing if index in dominated
    )
    derived_undominated_missing = tuple(
        index for index in derived_missing if index not in dominated
    )
    assert derived_missing == prepare.NEW_MISSING_UNION_INDICES
    assert derived_dominated_missing == prepare.NEW_DOMINATED_MISSING_UNION_INDICES
    assert derived_undominated_missing == prepare.NEW_UNDOMINATED_MISSING_UNION_INDICES

    historical = page15["historical_never_resident_undominated"]
    assert historical["prior_clause_count"] == 107
    assert historical["newly_resident_clause_count"] == 40
    assert tuple(historical["newly_resident_union_indices"]) == (
        prepare.HISTORICAL_NEWLY_RESIDENT_UNION_INDICES
    )
    assert historical["remaining_clause_count"] == 67
    assert tuple(historical["remaining_union_indices"]) == (
        prepare.HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
    )
    parent_residency: Any = json.loads(
        (CAPSULE / "initial/residency.json").read_bytes()
    )
    prior_never = tuple(parent_residency["never_resident_undominated_indices"])
    assert tuple(index for index in prior_never if index in selected) == (
        prepare.HISTORICAL_NEWLY_RESIDENT_UNION_INDICES
    )
    assert tuple(index for index in prior_never if index not in selected) == (
        prepare.HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
    )
    never = page15["never_resident_undominated"]
    assert never["clause_count"] == 167
    assert never["historical_clause_count"] == 67
    assert never["new_undominated_missing_clause_count"] == 100
    assert tuple(never["union_indices"]) == (
        prepare.NEVER_RESIDENT_UNDOMINATED_INDICES
    )


def test_page14_activation_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior: Any = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current: Any = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 28
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE15_SHA256
    assert prepare.PAGE15_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == 16


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
    assert prepare.FINAL_BANK_SHA256 == (
        "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
    )
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 52_014
    assert _sha256(receipt) == prepare.PRIORITY_RECEIPT_SHA256
    assert prepare.PRIORITY_RECEIPT_SHA256 == (
        "1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6"
    )
    assert canonical_json_bytes(json.loads(receipt)) == receipt

    continuation: Any = prepared.manifest["final_priority_bank"]
    assert continuation["semantic_role"] == ("sealed-evolved-live-continuation-bytes")
    assert continuation["receipt_artifact"] == prepare.PRIORITY_RECEIPT_NAME
    assert continuation["receipt_bank_hex_byte_equal"] is True
    assert continuation["coordinate_record_count"] == 256
    assert continuation["record_bytes"] == 96
    assert continuation["eligible_coordinate_count"] == 255
    assert continuation["zero_coordinate_variables"] == [241]
    assert continuation["minimum_nonzero_evolved_count"] == 227
    assert continuation["maximum_evolved_count"] == 2_675
    assert continuation["maximum_evolved_count_variables"] == [15]
    assert continuation["aggregate_evolved_count"] == 283_069
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
    output = tmp_path / "page15"
    prepare.write_prepared_o1c93_page15_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C93PreparationError, match="publication failed"):
        prepare.write_prepared_o1c93_page15_causal_rollover(prepared, output)

    tampered_artifacts = dict(prepared.artifacts)
    tampered_artifacts[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_artifacts,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C93PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c93_page15_causal_rollover(
            tampered, tmp_path / "tampered"
        )

    false_manifest = json.loads(canonical_json_bytes(prepared.manifest))
    false_manifest["page15"]["headroom"]["clauses"] = 257
    false_artifacts = dict(prepared.artifacts)
    false_artifacts[prepare.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(
        false_manifest
    )
    falsified = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=false_artifacts,
        manifest=false_manifest,
    )
    with pytest.raises(prepare.O1C93PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c93_page15_causal_rollover(
            falsified, tmp_path / "falsified"
        )


def test_source_tampering_and_bank_receipt_mismatch_are_rejected(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C93PreparationError, match="result binding"):
        prepare.prepare_o1c93_page15_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C93PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(CAPSULE, bytes(tampered_bank))

    with pytest.raises(prepare.O1C93PreparationError, match="not canonical"):
        prepare.prepare_o1c93_page15_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c93-page15"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c93-page15"


def test_source_has_no_native_solver_target_truth_or_reveal_interface() -> None:
    source = Path(prepare.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {"subprocess", "o1c92_apple8_parent_centered_continuation_run"} & imports
    assert "native_solver_calls\": 0" in source
    assert "native_preflight_calls\": 0" in source
    assert "target_bytes_read\": False" in source
    assert "truth_key_bytes_read\": False" in source
    assert "reveal_calls\": 0" in source
