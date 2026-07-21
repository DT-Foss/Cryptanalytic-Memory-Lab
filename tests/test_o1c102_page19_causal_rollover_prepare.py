from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c102_page19_causal_rollover_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
CAPSULE = (ROOT / prepare.DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
PARENT_RESULT = (ROOT / prepare.DEFAULT_PARENT_RESULT_RELATIVE).resolve()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _copy_capsule(tmp_path: Path, name: str = "capsule") -> Path:
    copied = tmp_path / name
    shutil.copytree(CAPSULE, copied)
    copied.chmod(copied.stat().st_mode | 0o700)
    for path in copied.rglob("*"):
        if path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
        elif path.is_file():
            path.chmod(path.stat().st_mode | 0o600)
    return copied.resolve()


def _reseal_manifest(capsule: Path, replacements: dict[str, bytes]) -> bytes:
    rows: list[str] = []
    for row in (capsule / "artifacts.sha256").read_text(encoding="ascii").splitlines():
        digest, relative = row.split("  ", maxsplit=1)
        replacement = replacements.get(relative)
        rows.append(
            f"{_sha256(replacement) if replacement is not None else digest}  {relative}"
        )
    payload = ("\n".join(rows) + "\n").encode("ascii")
    (capsule / "artifacts.sha256").write_bytes(payload)
    return payload


@pytest.fixture(scope="module")
def prepared() -> prepare.PreparedCausalRolloverArtifacts:
    return prepare.prepare_o1c102_page19_causal_rollover()


def test_exact_o1c101_parent_boundary_is_sealed_before_regeneration() -> None:
    entries = prepare._validate_capsule_inventory(CAPSULE)
    result = prepare._validate_parent_result(CAPSULE, PARENT_RESULT)
    assert len(entries) == prepare.PARENT_CAPSULE_ENTRY_COUNT == 43
    manifest = (CAPSULE / "artifacts.sha256").read_bytes()
    assert len(manifest) == prepare.PARENT_CAPSULE_MANIFEST_BYTES == 4_463
    assert _sha256(manifest) == prepare.PARENT_CAPSULE_MANIFEST_SHA256
    assert _sha256(PARENT_RESULT.read_bytes()) == prepare.PARENT_RESULT_SHA256
    assert result["attempt_id"] == "O1C-0101"
    assert result["classification"] == (
        "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
    )
    assert result["science_gain"] is True
    episodes: Any = result["episodes"]
    episode: Any = episodes[0]
    assert episode["page18_burned"] is True
    assert episode["lineage31_burned"] is True
    assert episode["native_calls_consumed"] == 1
    assert episode["actual_conflicts"] == episode["billed_conflicts"] == 36
    assert episode["retry_authorized"] is False
    assert episode["replay_authorized"] is False


def test_zero_call_parent_and_science_contract(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
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
        "page19_burned": False,
        "lineage32_burned": False,
        "page18_retry_or_replay_authorized": False,
        "lineage31_retry_or_replay_authorized": False,
        "historical_page_retry_or_replay_authorized": False,
    }
    parent: Any = prepared.manifest["parent"]
    assert parent["initial_artifacts_byte_equal_to_fresh_o1c100_regeneration"]
    assert parent["page18_burned"] is True
    assert parent["lineage31_burned"] is True
    assert parent["retry_or_replay_authorized"] is False
    science: Any = prepared.manifest["science_boundary"]
    assert science["imported_native_fully_emitted_clause_count"] == 264
    assert science["certified_derived_resolution_clause_count"] == 5
    assert science["resident_derived_resolution_clause_count"] == 3
    assert science["derived_occurrence_count"] == 0
    assert science["derived_clauses_are_native_emissions"] is False
    assert science["certified_logical_consequence"] is True
    assert science["attacker_valid_domain_reduction"] == 0
    assert science["attacker_valid_entropy_gain_bits"] == 0.0


def test_native_264_rollover_keeps_the_causal_attic_pure(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    state = prepared.state
    attic = state.attic
    assert len(attic.chunks) == prepare.ATTIC_CHUNK_COUNT == 20
    assert attic.chunks[-1].sha256 == prepare.NEW_CHUNK_SHA256
    assert attic.chunks[-1].clause_count == 264
    assert attic.chunks[-1].literal_count == 766_686
    assert attic.chunks[-1].serialized_bytes == 3_067_991
    assert attic.chunk_clause_union_indices[-1] == tuple(range(2_074, 2_338))
    assert attic.union_vault.sha256 == prepare.ATTIC_UNION_SHA256
    assert attic.union_vault.clause_count == 2_338
    assert attic.union_vault.literal_count == 6_602_366
    assert attic.union_vault.serialized_bytes == 26_419_007
    assert len(attic.occurrences) == 2_347
    assert attic.duplicate_occurrence_count == 9
    assert len(attic.relations) == 14
    assert len(attic.undominated_indices) == 2_327

    tail = attic.occurrences[-264:]
    assert all(row.stream_id == "o1c101-episode-00" for row in tail)
    assert all(row.classification == "new" for row in tail)
    assert all(row.source == "trail_upper_bound" for row in tail)
    assert len({row.clause_sha256 for row in tail}) == 264
    assert attic.occurrence_union_indices[-264:] == tuple(range(2_074, 2_338))
    emitted: Any = prepared.manifest["emitted_causal_attic"]
    assert emitted["derived_occurrence_count"] == 0
    assert emitted["derived_sidecars_excluded"] is True


def test_five_node_resolution_proof_and_three_node_antichain_are_exact(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    artifacts = prepared.artifacts
    closure = parse_threshold_no_good_vault(
        artifacts[prepare.DERIVED_CLOSURE_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    overlay = parse_threshold_no_good_vault(
        artifacts[prepare.DERIVED_OVERLAY_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert closure.sha256 == prepare.DERIVED_CLOSURE_SHA256
    assert closure.clause_count == 5
    assert closure.literal_count == 14_519
    assert closure.serialized_bytes == 58_287
    assert tuple(clause.sha256 for clause in closure.clauses) == (
        prepare.DERIVED_CLAUSE_SHA256
    )
    assert overlay.sha256 == prepare.DERIVED_OVERLAY_SHA256
    assert overlay.clauses == tuple(
        closure.clauses[index] for index in prepare.DERIVED_OVERLAY_ORDER
    )
    assert tuple(clause.literal_count for clause in overlay.clauses) == (
        2_860,
        2_914,
        2_915,
    )

    receipt_payload = artifacts[prepare.DERIVED_RECEIPT_NAME]
    receipt: Any = json.loads(receipt_payload)
    assert canonical_json_bytes(receipt) == receipt_payload
    assert receipt["schema"] == prepare.DERIVED_RECEIPT_SCHEMA
    assert receipt["claim_boundary"]["derived_clauses_are_native_occurrences"] is False
    assert receipt["claim_boundary"]["derived_clauses_enter_causal_attic"] is False
    assert receipt["claim_boundary"]["observed"] is False
    assert receipt["claim_boundary"]["emitted"] is False
    assert receipt["claim_boundary"]["certified_logical_consequence"] is True
    assert receipt["claim_boundary"]["attacker_valid_domain_reduction"] == 0
    assert receipt["claim_boundary"]["attacker_valid_entropy_gain_bits"] == 0.0
    assert receipt["claim_boundary"]["certified_model_or_key"] is False
    assert len(receipt["edges"]) == 5
    assert receipt["edges"][-1]["alternative_derivation"]["byte_equal"] is True
    audit = receipt["exhaustive_audit"]
    assert audit["historical_vs_native_pair_count"] == 547_536
    assert audit["native_vs_native_pair_count"] == 34_716
    assert audit["derived_incremental_pair_count"] == 11_700
    assert audit["derived_duplicate_count"] == 0
    assert audit["derived_vs_historical_native_strict_subsumption_count"] == 5
    assert audit["within_derived_strict_subsumption_count"] == 2
    assert len(audit["all_incremental_relations"]) == 7


def test_future_known_registry_includes_all_five_derived_clauses(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    receipt: Any = json.loads(prepared.artifacts[prepare.DERIVED_RECEIPT_NAME])
    registry = receipt["logical_known_registry"]
    emitted = registry["emitted"]
    derived = registry["derived"]
    combined = registry["combined"]
    assert emitted["clause_count"] == 2_338
    assert emitted["clause_sha256"] == [
        clause.sha256 for clause in prepared.state.attic.union_vault.clauses
    ]
    assert derived["clause_count"] == 5
    assert tuple(derived["clause_sha256"]) == prepare.DERIVED_CLAUSE_SHA256
    assert combined["clause_count"] == 2_343
    assert combined["clause_sha256"] == [
        *emitted["clause_sha256"],
        *derived["clause_sha256"],
    ]
    assert combined["next_global_novelty_baseline_clause_count"] == 2_343
    manifest_registry: Any = prepared.manifest["logical_known_registry"]
    assert manifest_registry["emitted_clause_count"] == 2_338
    assert manifest_registry["derived_clause_count"] == 5
    assert manifest_registry["combined_clause_count"] == 2_343
    assert manifest_registry["next_global_novelty_baseline_clause_count"] == 2_343
    assert (
        manifest_registry["combined_inventory_sha256"] == combined["inventory_sha256"]
    )


def test_composed_page19_is_exact_and_replays_from_two_namespaces(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    artifacts = prepared.artifacts
    page = parse_threshold_no_good_vault(
        artifacts[prepare.ACTIVE_PROJECTION_NAME],
        observed_variables=prepared.state.active_projection.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert page.sha256 == prepare.PAGE19_SHA256
    assert page.clause_count == 248
    assert page.literal_count == 702_343
    assert page.serialized_bytes == 2_810_555
    assert page.sha256 != prepare.PAGE19_BASE_SHA256

    residency_payload = artifacts[prepare.RESIDENCY_NAME]
    residency: Any = json.loads(residency_payload)
    assert canonical_json_bytes(residency) == residency_payload
    assert residency["schema"] == prepare.COMPOSED_RESIDENCY_SCHEMA
    assert residency["namespace_contract"]["derived_occurrence_rows"] == 0
    current = residency["current_projection"]
    assert current["encoding_only"]["sha256"] == prepare.PAGE19_SHA256
    assert current["category_counts"] == {
        "structural_root": 12,
        "pinned_core": 43,
        "inherited_debt": 0,
        "new_debt": 193,
        "hot_event": 0,
        "recycled": 0,
    }
    assert current["displaced_emitted_union_indices"] == [2_079, 2_081, 2_302]
    selected_emitted = tuple(current["selected_emitted_union_indices"])
    assert len(selected_emitted) == 245
    assert not set(prepare.DISPLACED_EMITTED_UNION_INDICES).intersection(
        selected_emitted
    )
    overlay = parse_threshold_no_good_vault(
        artifacts[prepare.DERIVED_OVERLAY_NAME],
        observed_variables=page.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    replay = type(page)(
        page.identity,
        page.observed_variables,
        (
            *(
                prepared.state.attic.union_vault.clauses[index]
                for index in selected_emitted
            ),
            *overlay.clauses,
        ),
    )
    assert replay == page


def test_composed_activation_uses_final_page_and_never_activates_base_candidate(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    payload = prepared.artifacts[prepare.ACTIVATION_LEDGER_NAME]
    document: Any = json.loads(payload)
    assert canonical_json_bytes(document) == payload
    assert document["schema"] == prepare.COMPOSED_ACTIVATION_SCHEMA
    prefix = document["causal_v1_prefix"]
    assert prefix["schema"] == ("o1-score-threshold-residency-activation-ledger-v1")
    assert prefix["document"]["schema"] == prefix["schema"]
    prefix_payload = canonical_json_bytes(prefix["document"])
    assert len(prefix_payload) == prefix["serialized_bytes"]
    assert _sha256(prefix_payload) == prefix["sha256"]
    assert prefix["entry_count"] == 19
    assert prefix["byte_exact_and_unmodified"] is True
    assert len(document["composed_entries"]) == 1
    entry = document["composed_entries"][0]
    assert entry["lineage_ordinal"] == 32
    assert entry["active_sha256"] == prepare.PAGE19_SHA256
    assert len(entry["selected_emitted_union_indices"]) == 245
    assert len(entry["selected_derived_clauses"]) == 3
    assert document["pure_emitted_candidate_activated"] is False
    assert document["forbidden_nonactivated_candidate_sha256"] == (
        prepare.PAGE19_BASE_SHA256
    )
    assert prepare.PAGE19_BASE_SHA256 not in document["used_active_sha256"]
    assert document["used_active_sha256"][-1] == prepare.PAGE19_SHA256


def test_evolved_bank_and_receipt_are_carried_byte_exact(
    prepared: prepare.PreparedCausalRolloverArtifacts,
) -> None:
    episode = CAPSULE / "episodes/00"
    bank = prepared.artifacts[prepare.FINAL_BANK_NAME]
    receipt = prepared.artifacts[prepare.PRIORITY_RECEIPT_NAME]
    assert bank == (episode / "final-parent-centered-priority-bank.bin").read_bytes()
    assert receipt == (episode / "priority-state.json").read_bytes()
    assert len(bank) == prepare.FINAL_BANK_BYTES == 24_576
    assert _sha256(bank) == prepare.FINAL_BANK_SHA256
    assert len(receipt) == prepare.PRIORITY_RECEIPT_BYTES == 52_013
    assert _sha256(receipt) == prepare.PRIORITY_RECEIPT_SHA256
    assert json.loads(receipt)["bank_hex"] == bank.hex()


def test_artifact_bundle_is_canonical_sealed_and_published_atomically(
    prepared: prepare.PreparedCausalRolloverArtifacts,
    tmp_path: Path,
) -> None:
    artifacts = prepared.artifacts
    assert len(artifacts) == 13
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
        prepare.DERIVED_RECEIPT_NAME,
        prepare.DERIVED_CLOSURE_NAME,
        prepare.DERIVED_OVERLAY_NAME,
        prepare.PREPARATION_MANIFEST_NAME,
    }
    manifest_payload = artifacts[prepare.PREPARATION_MANIFEST_NAME]
    assert canonical_json_bytes(prepared.manifest) == manifest_payload
    assert len(manifest_payload) == prepare.PREPARATION_MANIFEST_BYTES
    assert _sha256(manifest_payload) == prepare.PREPARATION_MANIFEST_SHA256
    rows: Any = prepared.manifest["artifacts"]
    assert set(rows) == set(artifacts) - {prepare.PREPARATION_MANIFEST_NAME}
    for name, row in rows.items():
        assert row["serialized_bytes"] == len(artifacts[name])
        assert row["sha256"] == _sha256(artifacts[name])
        assert row["role"]

    output = tmp_path / "page19"
    prepare.write_prepared_o1c102_page19_causal_rollover(prepared, output)
    assert {path.name: path.read_bytes() for path in output.iterdir()} == dict(
        artifacts
    )
    with pytest.raises(prepare.O1C102PreparationError, match="publication failed"):
        prepare.write_prepared_o1c102_page19_causal_rollover(prepared, output)

    tampered_payloads = dict(artifacts)
    tampered_payloads[prepare.ACTIVE_PROJECTION_NAME] += b"\x00"
    tampered = prepare.PreparedCausalRolloverArtifacts(
        state=prepared.state,
        artifacts=tampered_payloads,
        manifest=prepared.manifest,
    )
    with pytest.raises(prepare.O1C102PreparationError, match="exact artifact seal"):
        prepare.write_prepared_o1c102_page19_causal_rollover(
            tampered, tmp_path / "tampered"
        )


def test_tampered_result_and_noncanonical_paths_fail_before_regeneration(
    tmp_path: Path,
) -> None:
    bad_result = (tmp_path / "result.json").resolve()
    bad_result.write_bytes(b"{}\n")
    with pytest.raises(prepare.O1C102PreparationError, match="result binding"):
        prepare._validate_parent_result(CAPSULE, bad_result)
    with pytest.raises(prepare.O1C102PreparationError, match="not canonical"):
        prepare._canonical_path(
            prepare.DEFAULT_PARENT_RESULT_RELATIVE,
            "parent result",
            directory=False,
        )


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_capsule_rejects_symlink_or_fifo_before_regeneration(
    kind: str,
    tmp_path: Path,
) -> None:
    capsule = _copy_capsule(tmp_path, f"capsule-{kind}")
    unexpected = capsule / f"unexpected-{kind}"
    if kind == "symlink":
        unexpected.symlink_to("config.json")
        expected = "contains a symlink"
    else:
        os.mkfifo(unexpected)
        expected = "contains a special file"
    with pytest.raises(prepare.O1C102PreparationError, match=expected):
        prepare._validate_capsule_inventory(capsule)


def test_resealed_burn_tamper_fails_semantics_before_regeneration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capsule = _copy_capsule(tmp_path, "burn-tamper")
    result_path = capsule / "result.json"
    episode_path = capsule / "episodes/00/episode.json"
    result: Any = json.loads(result_path.read_bytes())
    episode: Any = json.loads(episode_path.read_bytes())
    result["claim_boundary"]["page18_burned"] = False
    episode["page18_burned"] = False
    result["episodes"] = [episode]
    result_payload = canonical_json_bytes(result)
    episode_payload = canonical_json_bytes(episode)
    result_path.write_bytes(result_payload)
    episode_path.write_bytes(episode_payload)
    external = (tmp_path / "resealed-result.json").resolve()
    external.write_bytes(result_payload)
    manifest_payload = _reseal_manifest(
        capsule,
        {
            "result.json": result_payload,
            "episodes/00/episode.json": episode_payload,
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
    with pytest.raises(prepare.O1C102PreparationError, match="completed-call contract"):
        prepare.prepare_o1c102_page19_causal_rollover(
            capsule_dir=capsule,
            parent_result_path=external,
        )


def test_parent_artifact_bank_and_receipt_tampering_are_rejected(
    tmp_path: Path,
) -> None:
    capsule = _copy_capsule(tmp_path, "parent-tamper")
    initial_page = capsule / "initial/page-18-active.bin"
    initial_page.write_bytes(initial_page.read_bytes() + b"\x00")
    with pytest.raises(prepare.O1C102PreparationError, match="inventory or digest"):
        prepare._validate_capsule_inventory(capsule)

    minimal = tmp_path / "minimal"
    episode = minimal / "episodes/00"
    episode.mkdir(parents=True)
    source_episode = CAPSULE / "episodes/00"
    for name in ("final-parent-centered-priority-bank.bin", "priority-state.json"):
        shutil.copy2(source_episode / name, episode / name)
        (episode / name).chmod((episode / name).stat().st_mode | 0o600)
    bank_path = episode / "final-parent-centered-priority-bank.bin"
    tampered_bank = bytearray(bank_path.read_bytes())
    tampered_bank[0] ^= 1
    bank_path.write_bytes(tampered_bank)
    with pytest.raises(prepare.O1C102PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(minimal)

    shutil.copy2(source_episode / "final-parent-centered-priority-bank.bin", bank_path)
    receipt_path = episode / "priority-state.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(prepare.O1C102PreparationError, match="continuation state"):
        prepare._validate_evolved_continuation_bank(minimal)


def test_module_exposes_only_zero_call_preparation_surfaces() -> None:
    source = Path(prepare.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
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
    assert '"native_solver_calls": 0' in source
    assert '"native_preflight_calls": 0' in source
    assert '"target_bytes_read": False' in source
    assert '"truth_key_bytes_read": False' in source
    preflight = prepare._parser().parse_args(["preflight"])
    publication = prepare._parser().parse_args(
        ["prepare", "--output-dir", "/tmp/o1c102-page19"]
    )
    assert preflight.command == "preflight"
    assert publication.command == "prepare"
