from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from o1_crypto_lab import o1c111_breadcrumb_sign_alignment as alignment
from o1_crypto_lab.causal_attic_v1 import canonical_json_bytes
from o1_crypto_lab.living_inverse import bits_to_key


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c111_breadcrumb_sign_alignment_v1.json"


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    return cast(Mapping[str, object], value)


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


def _integer(value: object) -> int:
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def _number(value: object) -> float:
    assert isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value)


@pytest.fixture(scope="module")
def prepared() -> alignment.PreparedBreadcrumbAnalysis:
    return alignment.prepare_breadcrumb_sign_alignment(CONFIG, root=ROOT)


def _truth_reader(
    key: bytes,
    calls: list[tuple[Path, str, str]],
) -> alignment.TruthReader:
    def read(
        path: Path, source_sha256: str, freeze_sha256: str
    ) -> alignment.HistoricalTruth:
        calls.append((path, source_sha256, freeze_sha256))
        assert len(freeze_sha256) == 64
        return alignment.HistoricalTruth(
            key=key,
            source_file_sha256=source_sha256,
            reveal_sha256="a" * 64,
        )

    return read


def test_pretruth_authenticates_exact_parent_and_census(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    freeze = _mapping(prepared.score_freeze)
    assert freeze["schema"] == alignment.SCORE_FREEZE_SCHEMA
    assert hashlib.sha256(prepared.score_freeze_bytes).hexdigest() == (
        prepared.score_freeze_sha256
    )
    assert freeze["design_sha256"] == (
        "a17ba0c73ba37f6c11e5a99e3112ef26738ceb09c3cffb7ec61f146051dde3a1"
    )
    assert freeze["authenticated_input_sha256"] == {
        "breadcrumbs": (
            "da472d3a8d60deb95227e36cb7264734169db4da369fa9006835930dee401014"
        ),
        "capsule_manifest": (
            "050a073b24fb2866b87e8353c1c8357c6598fa2eb9cf54119ee2991d7a99f2d0"
        ),
        "parent_result": (
            "22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28"
        ),
        "vault": ("9994058a39003697fae7322c7e50d7e7888f63322489cb328de301ac7e7b7705"),
    }

    census = _mapping(freeze["parent_census"])
    breadcrumbs = _mapping(census["breadcrumbs"])
    clauses = _mapping(census["clauses"])
    assert census["parent_classification"] == (
        "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
    )
    assert census["parent_science_gain"] is True
    assert census["parent_truth_key_bytes_read"] is False
    assert breadcrumbs["total_match_count"] == 100
    assert breadcrumbs["retained_count"] == 100
    assert breadcrumbs["overflow_count"] == 0
    assert breadcrumbs["complete"] is True
    assert breadcrumbs["class_counts"] == {
        "BOTH_PRUNABLE": 63,
        "ONE_PRUNABLE": 37,
    }
    assert breadcrumbs["consumed_before_count"] == 100
    assert breadcrumbs["crossing_eligible_count"] == 0
    assert breadcrumbs["unique_coordinate_count"] == 2
    assert breadcrumbs["unique_parent_count"] == 57
    assert clauses["fully_emitted_clause_count"] == 267
    assert clauses["fully_emitted_literal_count"] == 749_811
    assert clauses["globally_novel_clauses"] == 267
    assert clauses["unique_clause_count"] == 267
    assert clauses["clause_inventory_sha256"] == (
        "29ad476be015cbd787460377e1431db0bbd933e58115e9f33237c9c190430dac"
    )


def test_primary_and_secondary_are_frozen_separately(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    primary = _mapping(prepared.score_freeze["primary_score_freeze"])
    secondary = _mapping(prepared.score_freeze["secondary_score_freeze"])
    assert primary["classification_filter"] == "ONE_PRUNABLE"
    assert primary["row_count"] == 37
    assert primary["unique_coordinate_count"] == 2
    assert primary["repeated_row_count"] == 35
    assert primary["nonzero_unique_coordinate_count"] == 2
    assert secondary["classification_filter"] == "BOTH_PRUNABLE"
    assert secondary["row_count"] == 63
    assert secondary["unique_coordinate_count"] == 2
    assert secondary["repeated_row_count"] == 61

    primary_rows = [
        _mapping(row) for row in _sequence(primary["coordinate_aggregates"])
    ]
    secondary_rows = [
        _mapping(row) for row in _sequence(secondary["coordinate_aggregates"])
    ]
    assert [row["coordinate_index"] for row in primary_rows] == [193, 196]
    assert [row["row_count"] for row in primary_rows] == [8, 29]
    assert [row["prediction_bit"] for row in primary_rows] == [0, 0]
    assert all(_number(row["score_sum"]) < 0.0 for row in primary_rows)
    assert [row["row_count"] for row in secondary_rows] == [49, 14]

    pretruth = _mapping(prepared.score_freeze["pretruth_broad_gate"])
    assert pretruth == {
        "broad_posterior_promotion_possible": False,
        "minimum_unique_nonzero_coordinates": 32,
        "observed_unique_nonzero_coordinates": 2,
        "status": "FAILED_INSUFFICIENT_UNIQUE_COORDINATES",
    }
    lifecycle = _mapping(prepared.score_freeze["truth_lifecycle"])
    assert lifecycle["historical_reveal_file_reads_before_freeze"] == 0
    assert lifecycle["truth_key_bytes_read_before_freeze"] == 0


def test_two_of_two_is_only_retrospective_directional_breadcrumb(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    calls: list[tuple[Path, str, str]] = []
    result = alignment.finalize_breadcrumb_sign_alignment(
        prepared,
        truth_reader=_truth_reader(bytes(32), calls),
    )
    assert len(calls) == 1
    assert calls[0][2] == prepared.score_freeze_sha256
    assert result["classification"] == (
        "RETROSPECTIVE_TWO_COORDINATE_DIRECTIONAL_BREADCRUMB"
    )
    primary = _mapping(result["primary"])
    assert primary["evaluated_coordinate_count"] == 2
    assert primary["correct_count"] == 2
    assert primary["abstention_count"] == 0
    assert primary["binomial_tail"] == {
        "decimal": 0.25,
        "denominator": 4,
        "numerator": 1,
    }
    assert result["secondary_can_change_primary_classification"] is False
    broad = _mapping(result["broad_posterior_gate"])
    assert broad["coverage_pass"] is False
    assert broad["passed"] is False
    claim = _mapping(result["claim_boundary"])
    assert claim["posterior_bits_authorized"] == 0
    assert claim["attacker_valid_entropy_gain_bits"] == 0.0
    assert claim["fresh_attacker_valid_claim"] is False
    assert claim["result_is_retrospective"] is True
    assert claim["fresh_replication_required"] is True


def test_one_miss_cannot_be_repaired_by_secondary_or_sign_flip(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    primary_freeze = _mapping(prepared.score_freeze["primary_score_freeze"])
    aggregates = [
        _mapping(row) for row in _sequence(primary_freeze["coordinate_aggregates"])
    ]
    bits = [0] * 256
    first = aggregates[0]
    coordinate = _integer(first["coordinate_index"])
    prediction = _integer(first["prediction_bit"])
    bits[coordinate] = 1 - prediction
    key = bits_to_key(bits)
    result = alignment.finalize_breadcrumb_sign_alignment(
        prepared,
        truth_reader=_truth_reader(key, []),
    )
    assert result["classification"] == ("RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG")
    primary = _mapping(result["primary"])
    assert primary["correct_count"] == 1
    assert primary["binomial_tail"] == {
        "decimal": 0.75,
        "denominator": 4,
        "numerator": 3,
    }
    assert _mapping(result["broad_posterior_gate"])["passed"] is False


def test_controls_are_all_rotations_with_conservative_ties(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    result = alignment.finalize_breadcrumb_sign_alignment(
        prepared,
        truth_reader=_truth_reader(bytes(32), []),
    )
    primary = _mapping(result["primary"])
    controls = [_mapping(row) for row in _sequence(primary["cyclic_controls"])]
    assert len(controls) == 256
    assert [row["offset"] for row in controls] == list(range(256))
    identity = _number(primary["identity_alignment"])
    assert _number(controls[0]["alignment"]) == identity
    conservative_rank = sum(_number(row["alignment"]) >= identity for row in controls)
    assert primary["cyclic_rank_count_conservative"] == conservative_rank
    assert primary["cyclic_rank_fraction"] == conservative_rank / 256
    assert primary["global_sign_flip_alignment"] == -identity
    assert (
        primary["control_ledger_sha256"]
        == hashlib.sha256(canonical_json_bytes(controls)).hexdigest()
    )


def test_result_sha_and_serialization_reject_mutation(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    result = alignment.finalize_breadcrumb_sign_alignment(
        prepared,
        truth_reader=_truth_reader(bytes(32), []),
    )
    payload = alignment.serialize_result(result)
    assert payload == alignment.serialize_result(result)
    unsigned = dict(result)
    observed = unsigned.pop("result_sha256")
    assert observed == hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()

    changed = dict(result)
    changed["classification"] = "RETROSPECTIVE_TWO_COORDINATE_MIXED_OR_WRONG"
    with pytest.raises(
        alignment.O1C111BreadcrumbSignAlignmentError,
        match="result SHA-256 differs",
    ):
        alignment.serialize_result(changed)


def test_default_truth_reader_requires_existing_score_freeze_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_path = tmp_path / "historical-reveal.json"
    payload = canonical_json_bytes({"fixture": "not-production-truth"})
    fake_path.write_bytes(payload)
    key = bytes(range(32))

    def verify(_: object) -> dict[str, object]:
        return {
            "commitment_preimage": {"key_hex": key.hex()},
            "reveal_sha256": "b" * 64,
        }

    monkeypatch.setattr(alignment, "verify_reveal", verify)
    truth = alignment._read_historical_truth(
        fake_path,
        hashlib.sha256(payload).hexdigest(),
        "c" * 64,
    )
    assert truth.key == key
    assert truth.reveal_sha256 == "b" * 64
    with pytest.raises(
        alignment.O1C111BreadcrumbSignAlignmentError,
        match="score freeze SHA-256 differs",
    ):
        alignment._read_historical_truth(
            fake_path,
            hashlib.sha256(payload).hexdigest(),
            "not-a-freeze",
        )


def test_score_freeze_envelope_is_canonical_and_truth_free(
    prepared: alignment.PreparedBreadcrumbAnalysis,
) -> None:
    payload = alignment.serialize_score_freeze(prepared)
    assert b"key_hex" not in payload
    assert b"truth_bit" not in payload
    assert prepared.score_freeze_sha256.encode("ascii") in payload
    decoded = _mapping(__import__("json").loads(payload))
    assert decoded["schema"] == alignment.SCORE_FREEZE_ENVELOPE_SCHEMA
    assert decoded["score_freeze_sha256"] == prepared.score_freeze_sha256
    assert _mapping(decoded["score_freeze"])["config_sha256"] == (
        prepared.config_sha256
    )
