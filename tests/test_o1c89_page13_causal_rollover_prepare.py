from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c89_page13_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c89_page13_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_o1c88_parent_boundary_and_only_new_science_are_imported(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["attempt_id"] == "O1C-0088"
    assert parent["capsule_manifest_sha256"] == (
        "8ae16f758ee4c5e1f489c7f9c5d40d2dc001037a9b215ca60f973432af953f84"
    )
    assert parent["capsule_entry_count"] == 29
    assert parent["result_sha256"] == (
        "f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0"
    )
    assert parent["preparation_manifest_sha256"] == (
        "64427e4861507e373cc02b52b9c0f2d25d62f26cf9362af681b9bc90ef4a57b6"
    )
    assert parent["source_lineage_ordinal"] == 25
    assert parent["source_active_sha256"] == prepare.PAGE12_SHA256
    assert parent["page12_burned"] is True
    assert parent["lineage25_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    assert parent["global_novelty_baseline_clause_count"] == 1_032
    assert parent["initial_artifacts_byte_equal_to_fresh_page12_regeneration"]

    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_fully_emitted_clause_count"] == 259
    assert science["imported_globally_novel_clause_count"] == 259
    assert science["imported_literal_count"] == 744_973
    assert science["all_sources"] == ["trail_upper_bound"]
    assert science["all_classifications"] == ["new"]
    assert science["page9_retry_imported"] is False
    assert science["o1c84_terminal_failure_imported_as_science"] is False
    assert science["priority_magnitude_imported_as_science"] is False
    assert "o1c84-terminal-failure-receipt.json" not in prepared.artifacts

    tail = prepared.state.attic.occurrences[-259:]
    assert len(tail) == 259
    assert all(row.stream_id == "o1c88-episode-00" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert all(row.classification == "new" for row in tail)
    assert len({row.clause_sha256 for row in tail}) == 259
    known = {
        clause.sha256
        for clause in prepared.state.attic.union_vault.clauses[:1_032]
    }
    assert not known.intersection(row.clause_sha256 for row in tail)


def test_exact_chunk_and_immutable_attic_extension(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    chunk = attic.chunks[-1]
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 16
    assert chunk.sha256 == prepare.NEW_CHUNK_SHA256
    assert chunk.clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT == 259
    assert chunk.literal_count == prepare.NEW_CHUNK_LITERAL_COUNT == 744_973
    assert chunk.serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES == 2_981_119
    assert _sha256(prepared.artifacts[prepare.NEW_CHUNK_NAME]) == (
        prepare.NEW_CHUNK_SHA256
    )

    union = attic.union_vault
    assert union.sha256 == prepare.ATTIC_UNION_SHA256
    assert union.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT == 1_291
    assert union.literal_count == prepare.ATTIC_UNION_LITERAL_COUNT == 3_590_320
    assert union.serialized_bytes == prepare.ATTIC_UNION_SERIALIZED_BYTES == 14_366_635
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT == 1_299
    assert attic.duplicate_occurrence_count == 8
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT == 10
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT == 1_284
    assert attic.chunk_clause_union_indices[-1] == tuple(range(1_032, 1_291))
    assert attic.occurrence_union_indices[-259:] == tuple(range(1_032, 1_291))
    attic_manifest: Any = prepared.manifest["attic"]
    assert attic_manifest["prior_1032_clause_union_is_exact_prefix"] is True
    assert attic_manifest["prior_relation_set_preserved_exactly"] is True
    assert attic_manifest["new_strict_subsumption_pair_count"] == 0
    assert attic_manifest["new_strict_subsumption_relations"] == []


def test_page13_is_fresh_exact_and_mechanically_cap_safe(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 26
    assert state.active_limit == prepare.PAGE13_ACTIVE_LIMIT == 253
    assert page.sha256 == prepare.PAGE13_SHA256
    assert page.clause_count == prepare.PAGE13_CLAUSE_COUNT == 253
    assert page.literal_count == prepare.PAGE13_LITERAL_COUNT == 711_355
    assert page.serialized_bytes == prepare.PAGE13_SERIALIZED_BYTES == 2_846_623
    assert state.current_projection.category_counts == {
        "structural_root": 5,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 205,
        "hot_event": 0,
        "recycled": 0,
    }
    assert state.never_resident_undominated_indices == (
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert len(state.activation_ledger) == 14
    validate_activation_replay(state)

    page13: Any = prepared.manifest["page13"]
    assert page13["fresh_identity"] is True
    assert page13["headroom"] == {
        "clauses": 259,
        "literals": 888_645,
        "serialized_bytes": 5_541_985,
    }
    capacity = page13["native_capacity_proof"]
    assert capacity["caps"] == {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    clause_proof = capacity["clause_headroom_guarantee"]
    assert clause_proof["maximum_additional_clauses_before_capacity_terminal"] == 259
    assert clause_proof["parent_centered_action_capacity"] == 256
    assert clause_proof["spare_clause_slots_beyond_action_capacity"] == 3
    assert clause_proof["proved_sufficient"] is True
    assert capacity["recorded_residual_headroom"] == {
        "literals": 888_645,
        "serialized_bytes": 5_541_985,
    }
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False

    sacrifice = page13["one_slot_residency_sacrifice"]
    assert sacrifice == {
        "source_input_clause_count": 254,
        "fully_emitted_clause_count": 259,
        "unsacrificed_terminal_clause_count": 513,
        "native_vault_maximum_clauses": 512,
        "terminal_overflow_clause_count": 1,
        "prior_active_limit": 254,
        "next_active_limit": 253,
        "residency_slots_sacrificed": 1,
        "measured_clause_headroom": 259,
        "structural_root_count_preserved": 5,
        "pinned_core_count_preserved": 43,
    }
    residency = page13["new_clause_residency"]
    assert residency["attic_retained_clause_count"] == 259
    assert residency["resident_clause_count"] == 205
    assert tuple(residency["resident_union_indices"]) == (
        prepare.NEW_RESIDENT_UNION_INDICES
    )
    assert residency["missing_clause_count"] == 54
    assert tuple(residency["missing_union_indices"]) == (
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert [row["union_index"] for row in residency["missing_clauses"]] == list(
        prepare.NEW_MISSING_UNION_INDICES
    )
    assert all(len(row["clause_sha256"]) == 64 for row in residency["missing_clauses"])


def test_page12_activation_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior: Any = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current: Any = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 26
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE13_SHA256
    assert prepare.PAGE13_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == 14


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
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 52_009
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
    assert continuation["minimum_nonzero_evolved_count"] == 200
    assert continuation["maximum_evolved_count"] == 1_752
    assert continuation["maximum_evolved_count_variables"] == [21]
    assert continuation["aggregate_evolved_count"] == 215_781
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
    output = tmp_path / "page13"
    prepare.write_prepared_o1c89_page13_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C89PreparationError, match="publication failed"):
        prepare.write_prepared_o1c89_page13_causal_rollover(prepared, output)

    tampered_artifacts = dict(prepared.artifacts)
    tampered_artifacts[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_artifacts,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C89PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c89_page13_causal_rollover(
            tampered, tmp_path / "tampered"
        )

    false_manifest = json.loads(canonical_json_bytes(prepared.manifest))
    false_manifest["page13"]["headroom"]["clauses"] = 257
    false_artifacts = dict(prepared.artifacts)
    false_artifacts[prepare.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(
        false_manifest
    )
    falsified = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=false_artifacts,
        manifest=false_manifest,
    )
    with pytest.raises(prepare.O1C89PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c89_page13_causal_rollover(
            falsified, tmp_path / "falsified"
        )


def test_source_tampering_and_bank_receipt_mismatch_are_rejected(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C89PreparationError, match="result binding"):
        prepare.prepare_o1c89_page13_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C89PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(CAPSULE, bytes(tampered_bank))

    with pytest.raises(prepare.O1C89PreparationError, match="not canonical"):
        prepare.prepare_o1c89_page13_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c89-page13"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c89-page13"


def test_source_has_no_native_solver_target_truth_or_reveal_interface() -> None:
    source = Path(prepare.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert not {"subprocess", "o1c88_apple8_parent_centered_continuation_run"} & imports
    assert "native_solver_calls\": 0" in source
    assert "target_bytes_read\": False" in source
    assert "truth_key_bytes_read\": False" in source
    assert "reveal_calls\": 0" in source
