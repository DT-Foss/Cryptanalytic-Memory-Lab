from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c96_page16_transport_recovery_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes, parse_self_scoping_vault


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()
PUBLISHED = ROOT / "research/o1c96_page16_transport_recovery_seed_20260720"
O1C93 = ROOT / "research/o1c93_page15_causal_rollover_seed_20260720"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _published_payloads() -> dict[str, bytes]:
    assert PUBLISHED.is_dir() and not PUBLISHED.is_symlink()
    return {path.name: path.read_bytes() for path in PUBLISHED.iterdir()}


def test_exact_o1c95_terminal_boundary_is_validated_without_science_call() -> None:
    entries = prepare._validate_capsule_inventory(CAPSULE)
    parent, failure = prepare._validate_parent_result(CAPSULE, PARENT_RESULT)
    assert len(entries) == 20
    assert _sha256((CAPSULE / "artifacts.sha256").read_bytes()) == (
        "10c2b0f2f2745bb2a101c116d1ecf9af5c090cf627bf334d96f01e46998d26a6"
    )
    assert _sha256(PARENT_RESULT.read_bytes()) == prepare.PARENT_RESULT_SHA256
    assert _sha256(failure) == prepare.PARENT_FAILURE_SHA256
    assert parent["classification"] == (
        "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
    )
    assert parent["science_gain"] is False
    episodes: Any = parent["episodes"]
    episode: Any = episodes[0]
    assert episode["page15_burned"] is True
    assert episode["lineage28_burned"] is True
    assert episode["native_call_issued"] is True
    assert episode["native_calls_consumed"] == 1
    assert episode["native_result_returned"] is False
    assert episode["actual_conflicts"] is None
    assert episode["billed_conflicts"] is None
    terminal = json.loads(failure)
    assert terminal["message"] == (
        "joint-score-sieve-v29 priority seed fields differs"
    )
    assert terminal["native_process_evidence"] is None
    assert canonical_json_bytes(terminal) == failure


def test_tampered_parent_result_and_noncanonical_paths_fail_before_regeneration(
    tmp_path: Path,
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C96PreparationError, match="result binding"):
        prepare._validate_parent_result(CAPSULE, bad_result)
    with pytest.raises(prepare.O1C96PreparationError, match="not canonical"):
        prepare._canonical_path(
            prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            "parent result",
            directory=False,
        )


def test_module_has_zero_native_solver_target_truth_or_reveal_surface() -> None:
    source_path = ROOT / "src/o1_crypto_lab/o1c96_page16_transport_recovery_prepare.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert "subprocess" not in imported_roots
    assert "torch" not in imported_roots
    assert "cryptography" not in imported_roots
    assert "socket" not in imported_roots
    assert prepare.PAGE16_ACTIVE_LIMIT == 251
    assert prepare.PAGE16_LINEAGE_ORDINAL == 29


def test_cli_parser_exposes_only_zero_call_preflight_and_atomic_prepare() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c96-page16"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c96-page16"


def test_published_bundle_is_complete_canonical_and_byte_sealed() -> None:
    payloads = _published_payloads()
    assert set(payloads) == {
        prepare.ACTIVE_PROJECTION_NAME,
        prepare.RESIDENCY_NAME,
        prepare.ACTIVATION_LEDGER_NAME,
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.COMMON_CORE_AUDIT_NAME,
        prepare.FINAL_BANK_NAME,
        prepare.PRIORITY_RECEIPT_NAME,
        prepare.FAILURE_RECEIPT_NAME,
        prepare.PREPARATION_MANIFEST_NAME,
    }
    manifest_payload = payloads[prepare.PREPARATION_MANIFEST_NAME]
    manifest: Any = json.loads(manifest_payload)
    assert canonical_json_bytes(manifest) == manifest_payload
    assert len(manifest_payload) == prepare.PREPARATION_MANIFEST_BYTES == 6_414
    assert _sha256(manifest_payload) == prepare.PREPARATION_MANIFEST_SHA256
    assert prepare.PREPARATION_MANIFEST_SHA256 == (
        "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
    )
    rows: Any = manifest["artifacts"]
    assert set(rows) == set(payloads) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(payloads[name])
        assert row["sha256"] == _sha256(payloads[name])
        assert isinstance(row["role"], str) and row["role"]
    assert not any("chunk" in name for name in payloads)


def test_page16_is_fresh_exact_and_keeps_active_limit_251() -> None:
    payloads = _published_payloads()
    page_payload = payloads[prepare.ACTIVE_PROJECTION_NAME]
    page = parse_self_scoping_vault(page_payload)
    assert page.sha256 == prepare.PAGE16_SHA256
    assert page.clause_count == prepare.PAGE16_CLAUSE_COUNT == 251
    assert page.literal_count == prepare.PAGE16_LITERAL_COUNT == 707_566
    assert page.serialized_bytes == prepare.PAGE16_SERIALIZED_BYTES == 2_831_459

    residency_payload = payloads[prepare.RESIDENCY_NAME]
    residency: Any = json.loads(residency_payload)
    assert canonical_json_bytes(residency) == residency_payload
    assert len(residency_payload) == prepare.PAGE16_RESIDENCY_DOCUMENT_BYTES
    assert _sha256(residency_payload) == prepare.PAGE16_RESIDENCY_DOCUMENT_SHA256
    assert residency["active_limit"] == prepare.PAGE16_ACTIVE_LIMIT == 251
    current = residency["current_projection"]
    assert current["lineage_ordinal"] == prepare.PAGE16_LINEAGE_ORDINAL == 29
    assert current["encoding_only"]["sha256"] == prepare.PAGE16_SHA256
    assert current["category_counts"] == {
        "structural_root": 9,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 167,
        "hot_event": 0,
        "recycled": 32,
    }
    assert residency["never_resident_undominated_indices"] == []

    manifest: Any = json.loads(payloads[prepare.PREPARATION_MANIFEST_NAME])
    page16 = manifest["page16"]
    assert page16["headroom"] == {
        "clauses": 261,
        "literals": 892_434,
        "serialized_bytes": 5_557_149,
    }
    assert page16["fresh_identity"] is True
    assert page16["debt_completion"] == {
        "prior_never_resident_undominated_clause_count": 167,
        "admitted_as_new_debt_clause_count": 167,
        "remaining_never_resident_undominated_clause_count": 0,
        "recycled_clause_count": 32,
        "all_prior_debt_admitted": True,
    }


def test_activation_adds_exactly_one_entry_and_preserves_o1c93_prefix() -> None:
    payloads = _published_payloads()
    prior_payload = (O1C93 / prepare.ACTIVATION_LEDGER_NAME).read_bytes()
    current_payload = payloads[prepare.ACTIVATION_LEDGER_NAME]
    prior: Any = json.loads(prior_payload)
    current: Any = json.loads(current_payload)
    assert canonical_json_bytes(current) == current_payload
    assert len(current_payload) == prepare.PAGE16_ACTIVATION_DOCUMENT_BYTES
    assert _sha256(current_payload) == prepare.PAGE16_ACTIVATION_DOCUMENT_SHA256
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 29
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE16_SHA256
    assert prepare.PAGE16_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == prepare.PAGE16_ACTIVATION_COUNT == 17


def test_attic_bank_receipt_and_failure_are_exact_unchanged_transports() -> None:
    payloads = _published_payloads()
    unchanged = (
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.COMMON_CORE_AUDIT_NAME,
        prepare.FINAL_BANK_NAME,
        prepare.PRIORITY_RECEIPT_NAME,
    )
    for name in unchanged:
        assert payloads[name] == (O1C93 / name).read_bytes()
    assert len(payloads[prepare.FINAL_BANK_NAME]) == 24_576
    assert _sha256(payloads[prepare.FINAL_BANK_NAME]) == (
        "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
    )
    assert len(payloads[prepare.PRIORITY_RECEIPT_NAME]) == 52_014
    assert _sha256(payloads[prepare.PRIORITY_RECEIPT_NAME]) == (
        "1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6"
    )
    failure = payloads[prepare.FAILURE_RECEIPT_NAME]
    assert failure == (CAPSULE / "episodes/00/terminal-failure.json").read_bytes()
    assert len(failure) == 831
    assert _sha256(failure) == prepare.PARENT_FAILURE_SHA256

    manifest: Any = json.loads(payloads[prepare.PREPARATION_MANIFEST_NAME])
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }
    assert manifest["science_boundary"]["imported_clause_count"] == 0
    assert manifest["science_boundary"]["imported_priority_state_update"] is False
    assert manifest["science_boundary"]["o1c95_native_json_imported"] is False
    assert manifest["transport_recovery"]["new_chunk_count"] == 0
    assert manifest["transport_recovery"]["attic_evidence_unchanged"] is True
    assert manifest["attic"] == {
        "chunk_count": 18,
        "union_sha256": prepare.ATTIC_UNION_SHA256,
        "union_clause_count": 1_812,
        "union_literal_count": 5_090_528,
        "union_serialized_bytes": 20_369_551,
        "occurrence_count": 1_820,
        "duplicate_occurrence_count": 8,
        "strict_subsumption_pair_count": 14,
        "undominated_clause_count": 1_801,
        "byte_and_relation_equal_to_o1c93": True,
    }
