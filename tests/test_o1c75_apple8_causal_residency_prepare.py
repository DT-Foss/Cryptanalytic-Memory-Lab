from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

import o1_crypto_lab.o1c75_apple8_causal_residency_prepare as prepare
from o1_crypto_lab.causal_residency_v1 import (
    reproject_causal_residency,
    validate_activation_replay,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    parse_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "research/o1c75_causal_residency_seed_20260719"
MANIFEST_SHA256 = prepare.EXPECTED_PREPARED_MANIFEST_SHA256


@dataclass(frozen=True)
class LoadedSeed:
    prepared: prepare.PreparedResidency
    manifest: dict[str, object]


@pytest.fixture(scope="module")
def loaded_seed() -> LoadedSeed:
    prepared = prepare.load_prepared_residency(
        SEED, expected_manifest_sha256=MANIFEST_SHA256
    )
    return LoadedSeed(prepared, dict(prepared.manifest))


def test_checked_in_seed_replays_complete_parent_and_exact_page1(
    loaded_seed: LoadedSeed,
) -> None:
    state = loaded_seed.prepared.state
    validate_activation_replay(state)

    assert [chunk.clause_count for chunk in state.attic.chunks] == [
        202,
        311,
        0,
        37,
        0,
        0,
    ]
    assert state.attic.chunks[0].sha256 == prepare.EXPECTED_RANK_SOURCE_SHA256
    assert state.attic.union_vault.clause_count == 550
    assert state.attic.union_vault.literal_count == 1_488_224
    assert (
        state.attic.union_vault.clause_aggregate_sha256
        == prepare.EXPECTED_PARENT_UNION_AGGREGATE_SHA256
    )
    assert len(state.attic.occurrences) == 558
    assert state.attic.duplicate_occurrence_count == 8
    assert len(state.attic.undominated_indices) == 545
    assert len(state.pinned_core_indices) == 46
    assert state.structural_root_indices == (9, 123, 144)

    page1 = state.active_projection
    assert page1.sha256 == prepare.EXPECTED_PAGE1_SHA256
    assert page1.clause_aggregate_sha256 == prepare.EXPECTED_PAGE1_AGGREGATE_SHA256
    assert (page1.clause_count, page1.literal_count, page1.serialized_bytes) == (
        256,
        703_070,
        2_813_495,
    )
    assert state.current_projection.category_counts == {
        "structural_root": 3,
        "pinned_core": 43,
        "inherited_debt": 210,
        "new_debt": 0,
        "hot_event": 0,
        "recycled": 0,
    }
    assert len(state.never_resident_undominated_indices) == 79
    assert state.used_active_sha256 == (
        prepare.EXPECTED_PARENT_ACTIVE_SHA256,
        prepare.EXPECTED_PAGE1_SHA256,
    )


def test_zero_event_page2_closes_all_inherited_residency_debt(
    loaded_seed: LoadedSeed,
) -> None:
    page1_state = loaded_seed.prepared.state
    page2_state = reproject_causal_residency(
        page1_state.attic,
        previous_state=page1_state,
        fully_emitted_union_indices=(),
        next_lineage_ordinal=prepare.SECOND_LINEAGE_ORDINAL,
    )
    page2 = page2_state.active_projection

    assert page2.sha256 == prepare.EXPECTED_PAGE2_SHA256
    assert page2.clause_aggregate_sha256 == prepare.EXPECTED_PAGE2_AGGREGATE_SHA256
    assert (page2.clause_count, page2.literal_count, page2.serialized_bytes) == (
        256,
        684_922,
        2_740_903,
    )
    assert page2_state.current_projection.category_counts == {
        "structural_root": 3,
        "pinned_core": 43,
        "inherited_debt": 79,
        "new_debt": 0,
        "hot_event": 0,
        "recycled": 131,
    }
    parent = set(page1_state.activation_ledger[0].selected_union_indices)
    page1 = set(page1_state.current_projection.selected_union_indices)
    second = set(page2_state.current_projection.selected_union_indices)
    assert len(page1 & second) == 46
    assert len(parent & second) == 177
    assert len(parent | page1 | second) == 545
    assert page2_state.never_resident_undominated_indices == ()
    assert len(set(page2_state.used_active_sha256)) == 3


def test_manifest_hashes_complete_inventory_and_keeps_breadcrumbs_later_only(
    loaded_seed: LoadedSeed,
) -> None:
    manifest = loaded_seed.manifest
    artifact_set = manifest["artifact_set"]
    assert isinstance(artifact_set, dict)
    artifacts = artifact_set["artifacts"]
    assert isinstance(artifacts, dict)
    assert artifact_set["artifact_count"] == len(artifacts) == 21
    assert sorted(path.name for path in SEED.iterdir()) == sorted(
        (*artifacts, prepare.MANIFEST_NAME)
    )
    for name, raw in artifacts.items():
        assert isinstance(name, str) and isinstance(raw, dict)
        payload = (SEED / name).read_bytes()
        assert raw["serialized_bytes"] == len(payload)
        assert raw["sha256"] == hashlib.sha256(payload).hexdigest()
    assert manifest["zero_call"] == {
        "native_solver_calls": 0,
        "science_calls": 0,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
    }
    breadcrumb = manifest["later_only_breadcrumbs"]
    assert isinstance(breadcrumb, dict)
    assert breadcrumb["selection_input"] is False
    assert "semantic-match-schema-reconstructed-not-byte-identity" in {
        row["status"] for row in breadcrumb["reference_vs_published"].values()
    }


def test_later_only_pair_geometry_and_soft_orientation_are_exactly_described() -> None:
    reciprocal = json.loads((SEED / prepare.RECIPROCAL_PAIRS_NAME).read_bytes())
    assert reciprocal["pair_count"] == 223
    assert reciprocal["clause_coverage_count"] == 446
    assert (
        reciprocal["distance_min"],
        reciprocal["distance_median"],
        reciprocal["distance_max"],
    ) == (2, 16, 44)
    assert reciprocal["distance_at_most_32_count"] == 219
    distance_two = [
        row for row in reciprocal["pairs"] if row["signed_symmetric_distance"] == 2
    ]
    assert [(row["left_union_index"], row["right_union_index"]) for row in distance_two] == [
        (109, 110)
    ]

    clean = json.loads((SEED / prepare.KEY_FLIP_PAIRS_NAME).read_bytes())
    assert clean["pair_count"] == 93
    assert clean["key_variables"] == [
        32,
        59,
        73,
        106,
        115,
        133,
        193,
        201,
        210,
        244,
        246,
        249,
        251,
        255,
    ]
    summary = json.loads((SEED / prepare.ORIENTATION_SUMMARY_NAME).read_bytes())
    assert summary["unanimous_key_variable_count"] == 13
    assert summary["mixed_key_variables"] == [251]
    oriented = json.loads((SEED / prepare.ORIENTED_PAIRS_NAME).read_bytes())
    assert oriented["selection_input"] is False
    assert "soft local orientation only" in oriented["claim_boundary"]


def test_exact_focus_and_ten_clause_resolution_vaults_match_binary_contract(
    loaded_seed: LoadedSeed,
) -> None:
    rank = loaded_seed.prepared.rank_source
    focus = json.loads((SEED / prepare.RESOLVENT_RECORD_NAME).read_bytes())
    assert focus["left_union_index"] == 109
    assert focus["left_clause_sha256"] == (
        "85cc003852858447eac3630235b1e56e7612d5042abd5d8b33e328a0f0e0171d"
    )
    assert focus["left_first_witness_score"] == 14.044979902836593
    assert focus["right_union_index"] == 110
    assert focus["right_clause_sha256"] == (
        "35058f118d9da7673eea00a28324d8154fceac8bde8695ddde709654b2c3f864"
    )
    assert focus["right_first_witness_score"] == 14.293096759046755
    assert set(focus["signed_symmetric_difference"]) == {-201, 201}
    assert focus["resolvent_clause_sha256"] == prepare.EXPECTED_RESOLVENT_SHA256
    assert focus["resolvent_literal_count"] == 2_972

    one = parse_threshold_no_good_vault(
        (SEED / prepare.RESOLVENT_VAULT_NAME).read_bytes(),
        observed_variables=rank.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert (one.clause_count, one.literal_count, one.serialized_bytes) == (
        1,
        2_972,
        12_083,
    )
    assert one.clauses[0].sha256 == prepare.EXPECTED_RESOLVENT_SHA256
    assert one.sha256 == prepare.EXPECTED_RESOLVENT_VAULT_SHA256

    ten_record = json.loads((SEED / prepare.RESOLVENT_SET_NAME).read_bytes())
    ten = parse_threshold_no_good_vault(
        (SEED / prepare.RESOLVENT_SET_VAULT_NAME).read_bytes(),
        observed_variables=rank.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    assert ten_record["non_tautological_resolvent_count"] == 10
    assert (ten.clause_count, ten.literal_count, ten.serialized_bytes) == (
        10,
        29_702,
        119_039,
    )
    assert (
        ten.clause_aggregate_sha256
        == prepare.EXPECTED_RESOLVENT_SET_AGGREGATE_SHA256
    )
    assert ten.sha256 == prepare.EXPECTED_RESOLVENT_SET_VAULT_SHA256


def test_loader_rejects_manifest_digest_before_artifact_reads() -> None:
    with pytest.raises(prepare.O1C75PreparationError, match="manifest"):
        prepare.load_prepared_residency(
            SEED, expected_manifest_sha256="00" * 32
        )


def test_loader_rejects_unmanifested_directory_entries(tmp_path: Path) -> None:
    polluted = tmp_path / "polluted-seed"
    shutil.copytree(SEED, polluted)
    (polluted / "unmanifested-extra.bin").write_bytes(b"not sealed")

    with pytest.raises(
        prepare.O1C75PreparationError, match="directory inventory"
    ):
        prepare.load_prepared_residency(
            polluted, expected_manifest_sha256=MANIFEST_SHA256
        )


def test_atomic_publisher_rejects_existing_output_without_mutation(
    tmp_path: Path,
) -> None:
    output = tmp_path / "already-present"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"sealed")
    with pytest.raises(prepare.O1C75PreparationError, match="already exists"):
        prepare._publish_directory(output, {"new": b"data"})
    assert sentinel.read_bytes() == b"sealed"
    assert tuple(output.iterdir()) == (sentinel,)


def test_cli_has_zero_call_success_and_bounded_failure_surface(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    expected = {"schema": "test-zero-call-manifest"}
    monkeypatch.setattr(
        prepare, "prepare_o1c75_causal_residency", lambda **_kwargs: expected
    )
    assert prepare.main(["--output-dir", (tmp_path / "ok").as_posix()]) == 0
    assert json.loads(capsys.readouterr().out) == expected

    def fail(**_kwargs: object) -> dict[str, object]:
        raise prepare.O1C75PreparationError("sealed source differs")

    monkeypatch.setattr(prepare, "prepare_o1c75_causal_residency", fail)
    assert prepare.main(["--output-dir", (tmp_path / "bad").as_posix()]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "O1C-0075: sealed source differs\n"
