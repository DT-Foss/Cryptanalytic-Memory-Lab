from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c83_apple8_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c83_causal_rollover(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_zero_call_integration_reconstructs_and_advances_exactly(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    assert state.current_projection.lineage_ordinal == 22
    assert state.active_limit == prepare.PAGE9_ACTIVE_LIMIT == 255
    assert state.active_projection.sha256 == prepare.PAGE9_SHA256
    assert state.active_projection.clause_count == prepare.PAGE9_CLAUSE_COUNT == 255
    assert state.active_projection.literal_count == prepare.PAGE9_LITERAL_COUNT
    assert state.active_projection.serialized_bytes == prepare.PAGE9_SERIALIZED_BYTES
    assert state.current_projection.category_counts == prepare.PAGE9_CATEGORY_COUNTS
    assert state.used_active_sha256[-2:] == (prepare.PAGE8_SHA256, prepare.PAGE9_SHA256)
    assert len(state.used_active_sha256) == len(set(state.used_active_sha256)) == 10
    assert len(state.activation_ledger) == 10
    validate_activation_replay(state)

    attic = state.attic
    assert len(attic.chunks) == 13
    assert attic.chunks[-1].sha256 == prepare.NEW_CHUNK_SHA256
    assert attic.chunks[-1].clause_count == prepare.NEW_CHUNK_CLAUSE_COUNT
    assert attic.chunks[-1].literal_count == prepare.NEW_CHUNK_LITERAL_COUNT
    assert attic.chunks[-1].serialized_bytes == prepare.NEW_CHUNK_SERIALIZED_BYTES
    assert attic.union_vault.clause_count == prepare.ATTIC_UNION_CLAUSE_COUNT
    assert len(attic.occurrences) == prepare.ATTIC_OCCURRENCE_COUNT
    assert len(attic.relations) == prepare.ATTIC_SUBSUMPTION_RELATION_COUNT
    assert len(attic.undominated_indices) == prepare.ATTIC_UNDOMINATED_CLAUSE_COUNT
    assert _sha256(canonical_json_bytes(attic.relation_document())) == (
        prepare.PAGE9_RELATION_DOCUMENT_SHA256
    )
    assert len(attic.occurrences[-257:]) == 257
    assert all(row.stream_id == "o1c82-episode-00" for row in attic.occurrences[-257:])
    assert all(row.classification == "new" for row in attic.occurrences[-257:])
    assert len({row.clause_sha256 for row in attic.occurrences[-257:]}) == 257

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
        "page9_burned": False,
        "lineage22_burned": False,
        "page8_replay_authorized": False,
    }
    parent = prepared.manifest["parent"]
    assert isinstance(parent, dict)
    assert parent["initial_artifacts_byte_equal_to_fresh_reconstruction"] is True
    assert parent["activation_ledger_prefix_preserved"] is True
    assert parent["capsule_entry_count"] == 26


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
        prepare.PREPARATION_MANIFEST_NAME,
    }
    assert _sha256(artifacts[prepare.NEW_CHUNK_NAME]) == prepare.NEW_CHUNK_SHA256
    assert len(artifacts[prepare.NEW_CHUNK_NAME]) == prepare.NEW_CHUNK_SERIALIZED_BYTES
    assert _sha256(artifacts[prepare.ACTIVE_PROJECTION_NAME]) == prepare.PAGE9_SHA256
    assert len(artifacts[prepare.ACTIVE_PROJECTION_NAME]) == (
        prepare.PAGE9_SERIALIZED_BYTES
    )
    assert _sha256(artifacts[prepare.FINAL_BANK_NAME]) == (
        prepare.PARENT_FINAL_BANK_SHA256
    )
    assert len(artifacts[prepare.FINAL_BANK_NAME]) == prepare.PARENT_FINAL_BANK_BYTES
    continuation = prepared.manifest["final_priority_bank"]
    assert isinstance(continuation, dict)
    assert continuation["semantic_role"] == "sealed-live-continuation-bytes"
    assert continuation["receipt_bank_hex_byte_equal"] is True
    assert continuation["coordinate_record_count"] == 256
    assert continuation["record_bytes"] == 96
    assert continuation["eligible_coordinate_count"] == 255
    assert continuation["zero_coordinate_variables"] == [241]
    assert continuation["fresh_seed_parser_compatible"] is False
    assert continuation["next_action_parser_gate"] == (
        "require-live-continuation-parser;do-not-use-fresh-seed-parser"
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
    assert artifacts[prepare.PREPARATION_MANIFEST_NAME] == canonical_json_bytes(
        prepared.manifest
    )
    manifest = json.loads(artifacts[prepare.PREPARATION_MANIFEST_NAME])
    rows: dict[str, Any] = manifest["artifacts"]
    assert set(rows) == set(artifacts) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(artifacts[name])
        assert row["sha256"] == _sha256(artifacts[name])
        assert isinstance(row["role"], str) and row["role"]


def test_common_signed_intersection_and_public_bound_audit_are_exact(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payload = prepared.artifacts[prepare.COMMON_CORE_AUDIT_NAME]
    audit = json.loads(payload)
    assert canonical_json_bytes(audit) == payload
    intersection = audit["signed_intersection"]
    assert intersection["literal_count"] == 2764
    assert intersection["key_literal_count"] == 247
    assert intersection["internal_literal_count"] == 2517
    assert intersection["canonical_clause_sha256"] == (
        prepare.COMMON_CORE_CLAUSE_SHA256
    )
    assert len(intersection["signed_literals"]) == 2764
    cube = audit["key_cube"]
    assert cube["common_tail_key_variables"] == [21, 24, 49, 55, 66, 90, 100, 153]
    assert cube["publicly_unobserved_key_variables"] == [241]
    assert cube["missing_common_key_variables"] == [
        21,
        24,
        49,
        55,
        66,
        90,
        100,
        153,
        241,
    ]
    assert cube["unique_key_projection_count"] == 256
    assert cube["simple_non_tautological_resolvent_count"] == 0
    public_bound = audit["public_bound"]
    assert public_bound["upper_bound"] == prepare.COMMON_CORE_UPPER_BOUND
    assert public_bound["threshold"] == pytest.approx(14.606178797892962, abs=0)
    assert public_bound["margin"] == prepare.COMMON_CORE_MARGIN
    assert public_bound["prunable"] is False


def test_prior_activation_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current = prepared.state.activation_ledger_document()
    current_entries: Any = current["entries"]
    current_identities: Any = current["used_active_sha256"]
    assert current_entries[:-1] == prior["entries"]
    assert current_identities[:-1] == prior["used_active_sha256"]
    assert current_entries[-1]["lineage_ordinal"] == 22
    assert current_entries[-1]["active_sha256"] == prepare.PAGE9_SHA256


def test_atomic_writer_publishes_once_and_refuses_existing_or_symlink_outputs(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page9"
    prepare.write_prepared_o1c83_causal_rollover(prepared, output)
    assert output.is_dir()
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C83PreparationError, match="already exists"):
        prepare.write_prepared_o1c83_causal_rollover(prepared, output)

    alias = tmp_path / "alias"
    alias.symlink_to(output, target_is_directory=True)
    with pytest.raises(prepare.O1C83PreparationError, match="symlink"):
        prepare.write_prepared_o1c83_causal_rollover(prepared, alias)


def test_source_path_result_and_capsule_inventory_tampering_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(prepare.O1C83PreparationError, match="not canonical"):
        prepare.prepare_o1c83_causal_rollover(
            capsule_dir=prepare.DEFAULT_PARENT_CAPSULE_RELATIVE,
            parent_result_path=PARENT_RESULT,
        )

    alias = tmp_path / "capsule-alias"
    alias.symlink_to(CAPSULE, target_is_directory=True)
    with pytest.raises(prepare.O1C83PreparationError, match="not canonical"):
        prepare.prepare_o1c83_causal_rollover(
            capsule_dir=alias,
            parent_result_path=PARENT_RESULT,
        )

    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C83PreparationError, match="result binding"):
        prepare.prepare_o1c83_causal_rollover(
            capsule_dir=CAPSULE,
            parent_result_path=bad_result,
        )

    incomplete_capsule = (tmp_path / "incomplete-capsule").resolve()
    incomplete_capsule.mkdir()
    (incomplete_capsule / "artifacts.sha256").write_bytes(
        (CAPSULE / "artifacts.sha256").read_bytes()
    )
    (incomplete_capsule / "unexpected").write_bytes(b"x")
    with pytest.raises(prepare.O1C83PreparationError, match="inventory"):
        prepare._validate_capsule_inventory(incomplete_capsule)


def test_replay_and_mutated_chunk_are_rejected(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    telemetry = prepare.parse_vault_telemetry(
        (CAPSULE / "episodes/00/vault.json").read_bytes(),
        stream_id="o1c82-episode-00",
        expected_sha256=prepare.PARENT_VAULT_TELEMETRY_SHA256,
    )
    with pytest.raises(prepare.O1C83PreparationError, match="causal rollover"):
        prepare._advance_page9(
            prepared.state,
            prepared.state.attic.chunks[-1],
            telemetry,
        )

    tampered_bank = bytearray(prepared.artifacts[prepare.FINAL_BANK_NAME])
    tampered_bank[0] ^= 1
    with pytest.raises(prepare.O1C83PreparationError, match="receipt"):
        prepare._validate_live_continuation_bank(CAPSULE, bytes(tampered_bank))


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c83-page9"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c83-page9"
