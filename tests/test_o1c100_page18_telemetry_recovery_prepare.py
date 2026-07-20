from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any, cast

import pytest

import o1_crypto_lab.o1c100_page18_telemetry_recovery_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes, parse_self_scoping_vault


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()
O1C98 = ROOT / "research/o1c98_page17_causal_rollover_seed_20260720"


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _copy_capsule(tmp_path: Path) -> Path:
    copied = tmp_path / "copied-capsule"
    shutil.copytree(CAPSULE, copied)
    copied.chmod(copied.stat().st_mode | 0o700)
    for path in copied.rglob("*"):
        if path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
        elif path.is_file():
            path.chmod(path.stat().st_mode | 0o600)
    return copied.resolve()


def _reseal_capsule_manifest(capsule: Path, replacements: dict[str, bytes]) -> bytes:
    manifest_path = capsule / "artifacts.sha256"
    rows: list[str] = []
    for row in manifest_path.read_text(encoding="ascii").splitlines():
        digest, relative = row.split("  ", maxsplit=1)
        payload = replacements.get(relative)
        rows.append(
            f"{_sha256(payload) if payload is not None else digest}  {relative}"
        )
    manifest_payload = ("\n".join(rows) + "\n").encode("ascii")
    manifest_path.write_bytes(manifest_payload)
    return manifest_payload


@pytest.fixture(scope="session")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c100_page18_telemetry_recovery()


def test_exact_o1c99_post_call_terminal_boundary_is_validated() -> None:
    entries = prepare._validate_capsule_inventory(CAPSULE)
    parent, failure_payload = prepare._validate_parent_result(CAPSULE, PARENT_RESULT)
    assert len(entries) == prepare.PARENT_CAPSULE_ENTRY_COUNT == 33
    assert len((CAPSULE / "artifacts.sha256").read_bytes()) == 3_440
    assert _sha256((CAPSULE / "artifacts.sha256").read_bytes()) == (
        "93fdb7eb7ce828fd6c41a327a5ab1c7c58305e6a6be752dc0812b214b1fbbf9e"
    )
    assert _sha256(PARENT_RESULT.read_bytes()) == prepare.PARENT_RESULT_SHA256
    assert _sha256(failure_payload) == prepare.PARENT_FAILURE_SHA256
    assert parent["classification"] == (
        "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
    )
    assert parent["science_gain"] is False
    episodes: Any = parent["episodes"]
    episode: Any = episodes[0]
    assert episode["page17_burned"] is True
    assert episode["lineage30_burned"] is True
    assert episode["native_call_issued"] is True
    assert episode["native_calls_consumed"] == 1
    assert episode["native_result_returned"] is False
    assert episode["actual_conflicts"] is None
    assert episode["billed_conflicts"] is None

    failure: Any = json.loads(failure_payload)
    process: Any = failure["native_process_evidence"]
    telemetry: Any = process["failure_telemetry"]
    assert failure["phase"] == "POST_CALL"
    assert failure["message"] == prepare.PARENT_FAILURE_MESSAGE
    assert process["returncode"] == 1
    assert process["stdout_bytes"] == 0
    assert process["stdout_sha256"] == prepare.PARENT_NATIVE_STDOUT_SHA256
    assert process["stderr_bytes"] == 72
    assert process["stderr_sha256"] == prepare.PARENT_NATIVE_STDERR_SHA256
    assert process["stderr_tail"] == prepare.PARENT_NATIVE_STDERR
    assert telemetry["phase"] == "adapter_validation"
    assert telemetry["returncode"] == 1
    assert telemetry["stdout"] == ""
    assert telemetry["stderr"] == prepare.PARENT_NATIVE_STDERR
    assert canonical_json_bytes(failure) == failure_payload


def test_tampered_parent_result_and_noncanonical_paths_fail_before_regeneration(
    tmp_path: Path,
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C100PreparationError, match="result binding"):
        prepare._validate_parent_result(CAPSULE, bad_result)
    with pytest.raises(prepare.O1C100PreparationError, match="not canonical"):
        prepare._canonical_path(
            prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            "parent result",
            directory=False,
        )


@pytest.mark.parametrize("kind", ["symlink", "special"])
def test_copied_capsule_rejects_symlink_or_special_file_before_regeneration(
    kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capsule = _copy_capsule(tmp_path)
    unexpected = capsule / f"unexpected-{kind}"
    if kind == "symlink":
        unexpected.symlink_to("config.json")
        expected = "contains a symlink"
    else:
        os.mkfifo(unexpected)
        expected = "contains a special file"

    def regeneration_must_not_run(_capsule: Path) -> Any:
        raise AssertionError("regeneration reached after capsule type rejection")

    monkeypatch.setattr(
        prepare,
        "_regenerate_o1c98_and_validate_initial",
        regeneration_must_not_run,
    )
    with pytest.raises(prepare.O1C100PreparationError, match=expected):
        prepare.prepare_o1c100_page18_telemetry_recovery(
            capsule_dir=capsule,
            parent_result_path=PARENT_RESULT,
        )


@pytest.mark.parametrize(
    "tamper",
    ["science_gain", "native_result_returned", "failure_phase"],
)
def test_canonical_resealed_semantic_tamper_fails_before_regeneration(
    tamper: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capsule = _copy_capsule(tmp_path)
    episode_path = capsule / "episodes/00/episode.json"
    failure_path = capsule / "episodes/00/terminal-failure.json"
    result_path = capsule / "result.json"
    episode: Any = json.loads(episode_path.read_bytes())
    failure: Any = json.loads(failure_path.read_bytes())
    result: Any = json.loads(result_path.read_bytes())

    if tamper == "science_gain":
        failure["science_gain"] = True
        episode["science"]["science_gain"] = True
        result["science_gain"] = True
    elif tamper == "native_result_returned":
        failure["native_result_returned"] = True
        episode["native_result_returned"] = True
    else:
        failure["phase"] = "CALL"
    episode["terminal_failure"] = failure
    result["episodes"] = [episode]

    failure_payload = canonical_json_bytes(failure)
    episode_payload = canonical_json_bytes(episode)
    result_payload = canonical_json_bytes(result)
    failure_path.write_bytes(failure_payload)
    episode_path.write_bytes(episode_payload)
    result_path.write_bytes(result_payload)
    external_result = (tmp_path / "resealed-result.json").resolve()
    external_result.write_bytes(result_payload)
    manifest_payload = _reseal_capsule_manifest(
        capsule,
        {
            "episodes/00/episode.json": episode_payload,
            "episodes/00/terminal-failure.json": failure_payload,
            "result.json": result_payload,
        },
    )

    monkeypatch.setattr(
        prepare, "PARENT_CAPSULE_MANIFEST_SHA256", _sha256(manifest_payload)
    )
    monkeypatch.setattr(prepare, "PARENT_CAPSULE_MANIFEST_BYTES", len(manifest_payload))
    monkeypatch.setattr(prepare, "PARENT_RESULT_SHA256", _sha256(result_payload))
    monkeypatch.setattr(prepare, "PARENT_RESULT_BYTES", len(result_payload))
    monkeypatch.setattr(prepare, "PARENT_EPISODE_SHA256", _sha256(episode_payload))
    monkeypatch.setattr(prepare, "PARENT_EPISODE_BYTES", len(episode_payload))
    monkeypatch.setattr(prepare, "PARENT_FAILURE_SHA256", _sha256(failure_payload))
    monkeypatch.setattr(prepare, "PARENT_FAILURE_BYTES", len(failure_payload))

    def regeneration_must_not_run(_capsule: Path) -> Any:
        raise AssertionError("regeneration reached after semantic rejection")

    monkeypatch.setattr(
        prepare,
        "_regenerate_o1c98_and_validate_initial",
        regeneration_must_not_run,
    )
    with pytest.raises(
        prepare.O1C100PreparationError, match="parent terminal contract differs"
    ):
        prepare.prepare_o1c100_page18_telemetry_recovery(
            capsule_dir=capsule,
            parent_result_path=external_result,
        )


def test_capsule_has_no_native_result_or_science_state_output() -> None:
    entries = prepare._validate_capsule_inventory(CAPSULE)
    assert "episodes/00/native-result.json" not in entries
    assert "episodes/00/vault.json" not in entries
    assert "episodes/00/priority-state.json" not in entries
    assert "episodes/00/final-parent-centered-priority-bank.bin" not in entries
    assert entries["episodes/00/native-stdout.json"] == (
        prepare.PARENT_NATIVE_STDOUT_SHA256
    )
    assert (CAPSULE / "episodes/00/native-stdout.json").read_bytes() == b""


def test_module_has_zero_native_solver_target_truth_or_reveal_surface() -> None:
    source_path = ROOT / (
        "src/o1_crypto_lab/o1c100_page18_telemetry_recovery_prepare.py"
    )
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
    assert prepare.PAGE18_ACTIVE_LIMIT == 249
    assert prepare.PAGE18_LINEAGE_ORDINAL == 31


def test_cli_parser_exposes_only_zero_call_preflight_and_atomic_prepare() -> None:
    preflight = prepare._parser().parse_args(["preflight"])
    assert preflight.command == "preflight"
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c100-page18"]
    )
    assert publication.command == "prepare"
    assert publication.output_dir == "/tmp/o1c100-page18"


def test_prepared_bundle_is_complete_canonical_and_byte_sealed(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payloads = prepared.artifacts
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
    assert len(manifest_payload) == prepare.PREPARATION_MANIFEST_BYTES == 6_865
    assert _sha256(manifest_payload) == prepare.PREPARATION_MANIFEST_SHA256
    assert prepare.PREPARATION_MANIFEST_SHA256 == (
        "c0050ae08738f424505a92278759702bee4fcab23139a31137e715087ae437d9"
    )
    rows: Any = manifest["artifacts"]
    assert set(rows) == set(payloads) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(payloads[name])
        assert row["sha256"] == _sha256(payloads[name])
        assert isinstance(row["role"], str) and row["role"]
    assert not any("chunk" in name for name in payloads)


def test_page18_is_fresh_exact_and_keeps_active_limit_249(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payloads = prepared.artifacts
    page_payload = payloads[prepare.ACTIVE_PROJECTION_NAME]
    page = parse_self_scoping_vault(page_payload)
    assert page.sha256 == prepare.PAGE18_SHA256
    assert page.clause_count == prepare.PAGE18_CLAUSE_COUNT == 249
    assert page.literal_count == prepare.PAGE18_LITERAL_COUNT == 669_910
    assert page.serialized_bytes == prepare.PAGE18_SERIALIZED_BYTES == 2_680_827

    residency_payload = payloads[prepare.RESIDENCY_NAME]
    residency: Any = json.loads(residency_payload)
    assert canonical_json_bytes(residency) == residency_payload
    assert len(residency_payload) == prepare.PAGE18_RESIDENCY_DOCUMENT_BYTES == 60_284
    assert _sha256(residency_payload) == prepare.PAGE18_RESIDENCY_DOCUMENT_SHA256
    assert residency["active_limit"] == prepare.PAGE18_ACTIVE_LIMIT == 249
    current = residency["current_projection"]
    assert current["lineage_ordinal"] == prepare.PAGE18_LINEAGE_ORDINAL == 31
    assert current["encoding_only"]["sha256"] == prepare.PAGE18_SHA256
    assert current["category_counts"] == {
        "structural_root": 9,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 65,
        "hot_event": 0,
        "recycled": 132,
    }
    assert residency["never_resident_undominated_indices"] == []

    manifest: Any = json.loads(payloads[prepare.PREPARATION_MANIFEST_NAME])
    page18 = manifest["page18"]
    assert page18["headroom"] == {
        "clauses": 263,
        "literals": 930_090,
        "serialized_bytes": 5_707_781,
    }
    assert page18["fresh_identity"] is True
    assert page18["selected_union_indices_sha256"] == (
        "05c007e53843c89b87c109fb1b2b52f484fe358469de91336dcdaa420c49aa4b"
    )
    assert page18["selection_order_sha256"] == (
        "4951ae5c6a10658a71a0f74c7ae63ef0ca8c3ddf5387d260b38192b6827c08b6"
    )
    assert page18["debt_completion"] == {
        "prior_never_resident_undominated_clause_count": 65,
        "admitted_as_new_debt_clause_count": 65,
        "remaining_never_resident_undominated_clause_count": 0,
        "recycled_clause_count": 132,
        "all_prior_debt_admitted": True,
    }


def test_activation_adds_one_entry_and_preserves_o1c98_prefix(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payloads = prepared.artifacts
    prior_payload = (O1C98 / prepare.ACTIVATION_LEDGER_NAME).read_bytes()
    current_payload = payloads[prepare.ACTIVATION_LEDGER_NAME]
    prior: Any = json.loads(prior_payload)
    current: Any = json.loads(current_payload)
    assert canonical_json_bytes(current) == current_payload
    assert len(current_payload) == prepare.PAGE18_ACTIVATION_DOCUMENT_BYTES == 37_446
    assert _sha256(current_payload) == prepare.PAGE18_ACTIVATION_DOCUMENT_SHA256
    assert current["entries"][:-1] == prior["entries"]
    assert current["used_active_sha256"][:-1] == prior["used_active_sha256"]
    assert current["entries"][-1]["lineage_ordinal"] == 31
    assert current["entries"][-1]["active_sha256"] == prepare.PAGE18_SHA256
    assert prepare.PAGE18_SHA256 not in prior["used_active_sha256"]
    assert len(current["entries"]) == prepare.PAGE18_ACTIVATION_COUNT == 19


def test_attic_bank_receipt_and_failure_are_exact_transports(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payloads = prepared.artifacts
    unchanged = (
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.COMMON_CORE_AUDIT_NAME,
        prepare.FINAL_BANK_NAME,
        prepare.PRIORITY_RECEIPT_NAME,
    )
    for name in unchanged:
        assert payloads[name] == (O1C98 / name).read_bytes()
    assert len(payloads[prepare.FINAL_BANK_NAME]) == 24_576
    assert _sha256(payloads[prepare.FINAL_BANK_NAME]) == (
        "8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc"
    )
    assert len(payloads[prepare.PRIORITY_RECEIPT_NAME]) == 52_011
    assert _sha256(payloads[prepare.PRIORITY_RECEIPT_NAME]) == (
        "050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad"
    )
    failure = payloads[prepare.FAILURE_RECEIPT_NAME]
    assert failure == (CAPSULE / "episodes/00/terminal-failure.json").read_bytes()
    assert len(failure) == 22_520
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
    assert (
        manifest["science_boundary"]["o1c99_terminal_failure_imported_as_science"]
        is False
    )
    assert manifest["telemetry_recovery"]["new_chunk_count"] == 0
    assert manifest["telemetry_recovery"]["attic_evidence_unchanged"] is True
    assert manifest["attic"] == {
        "chunk_count": 19,
        "union_sha256": prepare.ATTIC_UNION_SHA256,
        "union_clause_count": 2_074,
        "union_literal_count": 5_835_680,
        "union_serialized_bytes": 23_351_207,
        "occurrence_count": 2_083,
        "duplicate_occurrence_count": 9,
        "strict_subsumption_pair_count": 14,
        "undominated_clause_count": 2_063,
        "byte_and_relation_equal_to_o1c98": True,
    }


def test_publication_validator_rejects_any_payload_mutation(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    prepare._validate_prepared_bundle_for_publication(prepared)
    artifacts = cast(dict[str, bytes], prepared.artifacts)
    original = artifacts[prepare.ACTIVE_PROJECTION_NAME]
    artifacts[prepare.ACTIVE_PROJECTION_NAME] = original + b"x"
    try:
        with pytest.raises(prepare.O1C100PreparationError, match="bundle differs"):
            prepare._validate_prepared_bundle_for_publication(prepared)
    finally:
        artifacts[prepare.ACTIVE_PROJECTION_NAME] = original
    prepare._validate_prepared_bundle_for_publication(prepared)


def test_atomic_writer_publishes_exact_ten_file_bundle(
    prepared: prepare.PreparedCausalRolloverArtifacts,
    tmp_path: Path,
) -> None:
    output = (tmp_path / "o1c100-page18").resolve()
    prepare.write_prepared_o1c100_page18_telemetry_recovery(prepared, output)
    assert output.is_dir() and not output.is_symlink()
    observed = {path.name: path.read_bytes() for path in output.iterdir()}
    assert observed == prepared.artifacts
    assert len(observed) == 10
    with pytest.raises(prepare.O1C100PreparationError, match="publication failed"):
        prepare.write_prepared_o1c100_page18_telemetry_recovery(prepared, output)
