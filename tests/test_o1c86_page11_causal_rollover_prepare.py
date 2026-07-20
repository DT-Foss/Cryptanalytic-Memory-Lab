from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c86_page11_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c86_page11_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_o1c85_parent_boundary_and_only_new_science_are_imported(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["attempt_id"] == "O1C-0085"
    assert parent["capsule_manifest_sha256"] == (
        "c6f4cb50ab5e7b0e57afbe5bbaccf53106008094be824c35bb7f849a8d4be492"
    )
    assert parent["capsule_entry_count"] == 29
    assert parent["result_sha256"] == (
        "d65fcaa76caa50905b5061b99cdf3ea10841449bdec6e9d20344e17bbe1e2ca4"
    )
    assert parent["preparation_manifest_sha256"] == (
        "d512f675d7076ecc650ce93052d60b8db1d1ed206d5b8d119118bdcec310c42c"
    )
    assert parent["source_lineage_ordinal"] == 23
    assert parent["source_active_sha256"] == prepare.PAGE10_SHA256
    assert parent["page10_burned"] is True
    assert parent["lineage23_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    assert parent["global_novelty_baseline_clause_count"] == 807
    assert parent["initial_artifacts_byte_equal_to_fresh_page10_regeneration"]

    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_fully_emitted_clause_count"] == 23
    assert science["imported_globally_novel_clause_count"] == 23
    assert science["imported_literal_count"] == 67_130
    assert science["all_sources"] == ["trail_upper_bound"]
    assert science["all_classifications"] == ["new"]
    assert science["page9_retry_imported"] is False
    assert science["o1c84_terminal_failure_imported_as_science"] is False
    assert science["priority_magnitude_imported_as_science"] is False
    assert "o1c84-terminal-failure-receipt.json" not in prepared.artifacts

    tail = prepared.state.attic.occurrences[-23:]
    assert len(tail) == 23
    assert all(row.stream_id == "o1c85-episode-00" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert all(row.classification == "new" for row in tail)
    assert len({row.clause_sha256 for row in tail}) == 23
    known = {clause.sha256 for clause in prepared.state.attic.union_vault.clauses[:807]}
    assert not known.intersection(row.clause_sha256 for row in tail)


def test_exact_chunk_and_immutable_attic_extension(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    chunk = attic.chunks[-1]
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 14
    assert chunk.sha256 == prepare.NEW_CHUNK_SHA256
    assert chunk.clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT == 23
    assert chunk.literal_count == prepare.NEW_CHUNK_LITERAL_COUNT == 67_130
    assert chunk.serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES == 268_803
    assert _sha256(prepared.artifacts[prepare.NEW_CHUNK_NAME]) == (
        prepare.NEW_CHUNK_SHA256
    )

    union = attic.union_vault
    assert union.sha256 == prepare.ATTIC_UNION_SHA256
    assert union.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT == 830
    assert union.literal_count == prepare.ATTIC_UNION_LITERAL_COUNT == 2_298_483
    assert union.serialized_bytes == prepare.ATTIC_UNION_SERIALIZED_BYTES == 9_197_443
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT == 838
    assert attic.duplicate_occurrence_count == 8
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT == 10
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT == 823
    assert attic.chunk_clause_union_indices[-1] == tuple(range(807, 830))
    assert attic.occurrence_union_indices[-23:] == tuple(range(807, 830))
    attic_manifest: Any = prepared.manifest["attic"]
    assert attic_manifest["prior_807_clause_union_is_exact_prefix"] is True


def test_page11_is_fresh_exact_and_mechanically_cap_safe(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 24
    assert state.active_limit == prepare.PAGE11_ACTIVE_LIMIT == 254
    assert page.sha256 == prepare.PAGE11_SHA256
    assert page.clause_count == prepare.PAGE11_CLAUSE_COUNT == 254
    assert page.literal_count == prepare.PAGE11_LITERAL_COUNT == 718_881
    assert page.serialized_bytes == prepare.PAGE11_SERIALIZED_BYTES == 2_876_731
    assert state.current_projection.category_counts == {
        "structural_root": 5,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 21,
        "hot_event": 0,
        "recycled": 185,
    }
    assert not state.never_resident_undominated_indices
    assert len(state.activation_ledger) == 12
    validate_activation_replay(state)

    page11: Any = prepared.manifest["page11"]
    assert page11["fresh_identity"] is True
    assert page11["headroom"] == {
        "clauses": 258,
        "literals": 881_119,
        "serialized_bytes": 5_511_877,
    }
    capacity = page11["native_capacity_proof"]
    assert capacity["caps"] == {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    clause_proof = capacity["clause_headroom_guarantee"]
    assert clause_proof["maximum_additional_clauses_before_capacity_terminal"] == 258
    assert clause_proof["parent_centered_action_capacity"] == 256
    assert clause_proof["spare_clause_slots_beyond_action_capacity"] == 2
    assert clause_proof["proved_sufficient"] is True
    assert capacity["recorded_residual_headroom"] == {
        "literals": 881_119,
        "serialized_bytes": 5_511_877,
    }
    assert capacity["literal_future_emission_safety_claimed"] is False
    assert capacity["serialized_byte_future_emission_safety_claimed"] is False


def test_page10_activation_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 24
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE11_SHA256
    assert prepare.PAGE11_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == 12


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
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 51_273
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
    assert continuation["minimum_nonzero_evolved_count"] == 38
    assert continuation["maximum_evolved_count"] == 829
    assert continuation["maximum_evolved_count_variables"] == [21]
    assert continuation["aggregate_evolved_count"] == 82_330
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
    assert len(manifest_payload) == 6_893
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
    output = tmp_path / "page11"
    prepare.write_prepared_o1c86_page11_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C86PreparationError, match="publication failed"):
        prepare.write_prepared_o1c86_page11_causal_rollover(prepared, output)

    tampered_artifacts = dict(prepared.artifacts)
    tampered_artifacts[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_artifacts,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C86PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c86_page11_causal_rollover(
            tampered, tmp_path / "tampered"
        )

    false_manifest = json.loads(canonical_json_bytes(prepared.manifest))
    false_manifest["page11"]["headroom"]["clauses"] = 257
    false_artifacts = dict(prepared.artifacts)
    false_artifacts[prepare.PREPARATION_MANIFEST_NAME] = canonical_json_bytes(
        false_manifest
    )
    falsified = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=false_artifacts,
        manifest=false_manifest,
    )
    with pytest.raises(prepare.O1C86PreparationError, match="publication bundle"):
        prepare.write_prepared_o1c86_page11_causal_rollover(
            falsified, tmp_path / "falsified"
        )


def test_source_tampering_and_bank_receipt_mismatch_are_rejected(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C86PreparationError, match="result binding"):
        prepare.prepare_o1c86_page11_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C86PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(CAPSULE, bytes(tampered_bank))

    with pytest.raises(prepare.O1C86PreparationError, match="not canonical"):
        prepare.prepare_o1c86_page11_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c86-page11"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c86-page11"
