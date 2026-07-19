from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

import o1_crypto_lab.o1c74_apple8_causal_attic_prepare as prepare
from o1_crypto_lab.causal_attic_v1 import parse_self_scoping_vault
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class PreparedRealAttic:
    output: Path
    manifest: dict[str, object]
    source_hashes_before: dict[Path, str]
    source_hashes_after: dict[Path, str]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def prepared_real_attic(
    tmp_path_factory: pytest.TempPathFactory,
) -> PreparedRealAttic:
    capsule = ROOT / prepare.DEFAULT_CAPSULE_RELATIVE
    retained_telemetry = tuple(
        ROOT / relative for relative in prepare.DEFAULT_RETAINED_TELEMETRY_RELATIVES
    )
    sources = (
        capsule / prepare.RETAINED_VAULT_RELATIVE,
        capsule / prepare.CURRENT_TELEMETRY_RELATIVE,
        *retained_telemetry,
    )
    before = {path: _sha(path) for path in sources}
    output = tmp_path_factory.mktemp("o1c74-attic") / "prepared"
    manifest = prepare.prepare_o1c74_causal_attic(
        capsule_dir=capsule,
        retained_telemetry_paths=retained_telemetry,
        output_dir=output,
    )
    after = {path: _sha(path) for path in sources}
    return PreparedRealAttic(output, manifest, before, after)


def test_real_sealed_preparation_matches_frozen_chunks_and_k256(
    prepared_real_attic: PreparedRealAttic,
) -> None:
    prepared = prepared_real_attic
    assert prepared.source_hashes_after == prepared.source_hashes_before
    assert sorted(path.name for path in prepared.output.iterdir()) == sorted(
        (
            prepare.ACTIVE_PROJECTION_NAME,
            prepare.MANIFEST_NAME,
            prepare.NOVEL_CHUNK_NAME,
            prepare.OCCURRENCES_NAME,
            prepare.RELATIONS_NAME,
            prepare.RETAINED_CHUNK_NAME,
        )
    )

    retained_payload = (prepared.output / prepare.RETAINED_CHUNK_NAME).read_bytes()
    retained = parse_self_scoping_vault(retained_payload)
    novel = parse_threshold_no_good_vault(
        (prepared.output / prepare.NOVEL_CHUNK_NAME).read_bytes(),
        observed_variables=retained.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    active = parse_threshold_no_good_vault(
        (prepared.output / prepare.ACTIVE_PROJECTION_NAME).read_bytes(),
        observed_variables=retained.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )

    assert retained.sha256 == prepare.EXPECTED_RETAINED_VAULT_SHA256
    assert (retained.clause_count, retained.literal_count) == (202, 599_728)
    assert novel.sha256 == prepare.EXPECTED_NOVEL_VAULT_SHA256
    assert novel.clause_aggregate_sha256 == (prepare.EXPECTED_NOVEL_AGGREGATE_SHA256)
    assert (novel.clause_count, novel.literal_count, novel.serialized_bytes) == (
        311,
        798_046,
        3_193_619,
    )
    assert active.sha256 == prepare.EXPECTED_ACTIVE_VAULT_SHA256
    assert active.clause_aggregate_sha256 == (prepare.EXPECTED_ACTIVE_AGGREGATE_SHA256)
    assert (active.clause_count, active.literal_count, active.serialized_bytes) == (
        256,
        654_753,
        2_620_227,
    )

    attic = prepared.manifest["attic"]
    assert isinstance(attic, dict)
    projection = attic["active_projection"]
    assert isinstance(projection, dict)
    assert projection["is_cumulative_vault_v1"] is False
    assert projection["unique_coverage_count"] == 261
    assert projection["occurrence_coverage_count"] == 263
    selected = projection["selected_union_indices"]
    assert isinstance(selected, list)
    assert [index for index in selected if index < 202] == [9, 123, 144]
    assert prepared.manifest["rank_source_vault_sha256"] == retained.sha256
    assert prepared.manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
    }


def test_compact_ledgers_preserve_all_occurrences_duplicates_and_relations(
    prepared_real_attic: PreparedRealAttic,
) -> None:
    occurrence_document = json.loads(
        (prepared_real_attic.output / prepare.OCCURRENCES_NAME).read_bytes()
    )
    records = occurrence_document["records"]
    assert occurrence_document["occurrence_count"] == 515
    assert occurrence_document["unique_clause_count"] == 513
    assert occurrence_document["duplicate_occurrence_count"] == 2
    assert len(records) == 515
    assert all("literals" not in record for record in records)
    duplicates = [record for record in records if record["classification"] != "new"]
    assert [record["source_index"] for record in duplicates] == [77, 135]
    by_current_index = {
        record["source_index"]: record
        for record in records
        if record["stream_id"] == "o1c73-current"
    }
    assert (
        by_current_index[77]["union_clause_index"]
        == by_current_index[76]["union_clause_index"]
    )
    assert (
        by_current_index[135]["union_clause_index"]
        == by_current_index[134]["union_clause_index"]
    )

    relation_document = json.loads(
        (prepared_real_attic.output / prepare.RELATIONS_NAME).read_bytes()
    )
    relation_pairs = [
        (row["subsumer_index"], row["subsumed_index"])
        for row in relation_document["relations"]
    ]
    assert relation_document["strict_subsumption_pair_count"] == 8
    assert relation_document["undominated_clause_count"] == 508
    assert relation_document["dominated_clause_count"] == 5
    assert relation_pairs == [
        (7, 6),
        (8, 6),
        (8, 7),
        (9, 6),
        (9, 7),
        (9, 8),
        (123, 120),
        (144, 143),
    ]


def test_manifest_hashes_every_nonmanifest_output(
    prepared_real_attic: PreparedRealAttic,
) -> None:
    artifact_set = prepared_real_attic.manifest["artifact_set"]
    assert isinstance(artifact_set, dict)
    artifacts = artifact_set["artifacts"]
    assert isinstance(artifacts, dict)
    assert set(artifacts) == {
        prepare.ACTIVE_PROJECTION_NAME,
        prepare.NOVEL_CHUNK_NAME,
        prepare.OCCURRENCES_NAME,
        prepare.RELATIONS_NAME,
        prepare.RETAINED_CHUNK_NAME,
    }
    for name, value in artifacts.items():
        assert isinstance(name, str) and isinstance(value, dict)
        payload = (prepared_real_attic.output / name).read_bytes()
        assert value["serialized_bytes"] == len(payload)
        assert value["sha256"] == hashlib.sha256(payload).hexdigest()
    manifest_payload = (prepared_real_attic.output / prepare.MANIFEST_NAME).read_bytes()
    assert json.loads(manifest_payload) == prepared_real_attic.manifest


def test_atomic_publisher_rejects_existing_output_without_mutation(
    tmp_path: Path,
) -> None:
    output = tmp_path / "already-present"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"sealed")

    with pytest.raises(prepare.O1C74PreparationError, match="already exists"):
        prepare._publish_directory(output, {"new": b"data"})

    assert sentinel.read_bytes() == b"sealed"
    assert tuple(output.iterdir()) == (sentinel,)


def test_manifested_reader_rejects_tamper(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    artifact = capsule / "source.bin"
    artifact.write_bytes(b"original")
    (capsule / "artifacts.sha256").write_text(
        f"{hashlib.sha256(b'original').hexdigest()}  source.bin\n",
        encoding="ascii",
    )
    artifact.write_bytes(b"tampered")

    with pytest.raises(prepare.O1C74PreparationError, match="digest"):
        prepare._read_manifested(artifact)


def test_cli_has_zero_call_success_and_bounded_failure_surface(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    expected = {"schema": "test-zero-call-manifest"}
    monkeypatch.setattr(
        prepare,
        "prepare_o1c74_causal_attic",
        lambda **_kwargs: expected,
    )
    assert prepare.main(["--output-dir", (tmp_path / "ok").as_posix()]) == 0
    assert json.loads(capsys.readouterr().out) == expected

    def fail(**_kwargs: object) -> dict[str, object]:
        raise prepare.O1C74PreparationError("sealed source differs")

    monkeypatch.setattr(prepare, "prepare_o1c74_causal_attic", fail)
    assert prepare.main(["--output-dir", (tmp_path / "bad").as_posix()]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "O1C-0074: sealed source differs\n"
