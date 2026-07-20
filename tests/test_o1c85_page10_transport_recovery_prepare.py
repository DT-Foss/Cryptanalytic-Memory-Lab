from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c85_page10_transport_recovery_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.causal_residency_v1 import validate_activation_replay


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c85_page10_transport_recovery(
        capsule_dir=CAPSULE,
        parent_result_path=PARENT_RESULT,
    )


def test_exact_page10_identity_and_zero_call_boundary(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    page = state.active_projection
    assert state.current_projection.lineage_ordinal == 23
    assert state.active_limit == prepare.PAGE10_ACTIVE_LIMIT == 254
    assert page.sha256 == prepare.PAGE10_SHA256
    assert page.clause_count == prepare.PAGE10_CLAUSE_COUNT == 254
    assert page.literal_count == prepare.PAGE10_LITERAL_COUNT == 718_295
    assert page.serialized_bytes == prepare.PAGE10_SERIALIZED_BYTES == 2_874_387
    assert state.current_projection.category_counts == {
        "structural_root": 4,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 47,
        "hot_event": 0,
        "recycled": 160,
    }
    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    page10: Any = prepared.manifest["page10"]
    assert page10["headroom"] == {
        "clauses": 258,
        "literals": 881_705,
        "serialized_bytes": 5_514_221,
    }
    assert page10["fresh_identity"] is True
    validate_activation_replay(state)


def test_same_attic_and_unchanged_transport_artifacts(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    assert len(attic.chunks) == 13
    assert attic.union_vault.clause_count == 807
    assert len(attic.occurrences) == 815
    assert len(attic.relations) == 9
    assert len(attic.undominated_indices) == 801

    initial = CAPSULE / "initial"
    pairs = {
        prepare.OCCURRENCES_NAME: "occurrence-ledger.json",
        prepare.RELATIONS_NAME: "subsumption-relations.json",
        prepare.COMMON_CORE_AUDIT_NAME: "common-signed-intersection-audit.json",
        prepare.FINAL_BANK_NAME: "final-parent-centered-priority-bank.bin",
    }
    for output_name, initial_name in pairs.items():
        assert prepared.artifacts[output_name] == (initial / initial_name).read_bytes()
    assert prepared.artifacts[prepare.OCCURRENCES_NAME] == canonical_json_bytes(
        attic.occurrence_document()
    )
    assert prepared.artifacts[prepare.RELATIONS_NAME] == canonical_json_bytes(
        attic.relation_document()
    )
    transport: Any = prepared.manifest["transport_recovery"]
    assert transport["fully_emitted_event_count"] == 0
    assert transport["new_chunk_count"] == 0
    assert transport["attic_evidence_unchanged"] is True
    assert transport["continuation_bank_unchanged"] is True


def test_parent_failure_seals_and_unchanged_bank_receipt_are_preserved(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    parent: Any = prepared.manifest["parent"]
    assert parent["capsule_manifest_sha256"] == (
        "811ad89955b383c4ac1303fc3f510c4169278e19cec73d465adf7a76e65cc2bf"
    )
    assert parent["result_sha256"] == (
        "4ae1238203ef10c03a1dd325242ccb59bd0f8f67c0b93fa5debd95259c7f7b96"
    )
    assert parent["intent_sha256"] == (
        "89483dda835275adba37a3cbb9099c12590cf26f439913eb4d91bbd6c912d20c"
    )
    assert parent["terminal_failure_sha256"] == prepare.PARENT_FAILURE_SHA256
    assert parent["classification"] == (
        "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
    )
    assert parent["page9_burned"] is True
    assert parent["lineage22_burned"] is True
    assert parent["native_result_returned"] is False
    assert parent["actual_conflicts"] is None
    assert parent["billed_conflicts"] is None
    assert parent["science_gain"] is False
    assert parent["state_update_available"] is False
    assert parent["initial_o1c83_artifact_count"] == 9
    assert parent["initial_artifacts_byte_equal_to_fresh_regeneration"] is True

    failure = prepared.artifacts[prepare.FAILURE_RECEIPT_NAME]
    assert failure == (CAPSULE / "episodes/00/terminal-failure.json").read_bytes()
    assert _sha256(failure) == prepare.PARENT_FAILURE_SHA256
    failure_document = json.loads(failure)
    assert canonical_json_bytes(failure_document) == failure
    assert failure_document["message"].count("missing LC_UUID load command") == 2

    bank = prepared.artifacts[prepare.FINAL_BANK_NAME]
    assert len(bank) == prepare.CONTINUATION_BANK_BYTES == 24_576
    assert _sha256(bank) == prepare.CONTINUATION_BANK_SHA256
    continuation: Any = prepared.manifest["final_priority_bank"]
    assert continuation["receipt_sha256"] == prepare.PRIORITY_RECEIPT_SHA256
    assert continuation["receipt_bank_hex_byte_equal"] is True
    assert continuation["semantic_role"] == ("unchanged-sealed-live-continuation-bytes")


def test_page10_activation_is_fresh_and_parent_ledger_is_an_exact_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prior_payload = (CAPSULE / "initial/activation-ledger.json").read_bytes()
    prior = json.loads(prior_payload)
    assert canonical_json_bytes(prior) == prior_payload
    current = prepared.state.activation_ledger_document()
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 23
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE10_SHA256
    assert prepare.PAGE10_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == 11


def test_artifact_bundle_is_complete_canonical_and_byte_sealed(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    artifacts = prepared.artifacts
    assert set(artifacts) == {
        prepare.ACTIVE_PROJECTION_NAME,
        prepare.RESIDENCY_NAME,
        prepare.ACTIVATION_LEDGER_NAME,
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.COMMON_CORE_AUDIT_NAME,
        prepare.FINAL_BANK_NAME,
        prepare.FAILURE_RECEIPT_NAME,
        prepare.PREPARATION_MANIFEST_NAME,
    }
    assert artifacts[prepare.RESIDENCY_NAME] == canonical_json_bytes(
        prepared.state.describe()
    )
    assert artifacts[prepare.ACTIVATION_LEDGER_NAME] == canonical_json_bytes(
        prepared.state.activation_ledger_document()
    )
    assert artifacts[prepare.PREPARATION_MANIFEST_NAME] == canonical_json_bytes(
        prepared.manifest
    )
    rows: Any = prepared.manifest["artifacts"]
    assert set(rows) == set(artifacts) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(artifacts[name])
        assert row["sha256"] == _sha256(artifacts[name])
        assert isinstance(row["role"], str) and row["role"]


def test_o1c83_atomic_writer_is_reused_for_page10(
    prepared: prepare.PreparedCausalRolloverArtifacts, tmp_path: Path
) -> None:
    output = tmp_path / "page10"
    prepare.write_prepared_o1c85_page10_transport_recovery(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        prepared.artifacts
    )
    with pytest.raises(prepare.O1C85PreparationError, match="publication failed"):
        prepare.write_prepared_o1c85_page10_transport_recovery(prepared, output)


def test_cli_parser_exposes_preflight_and_atomic_prepare_modes() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c85-page10"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c85-page10"
