from __future__ import annotations

import hashlib
import json
import math
import struct
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from o1_crypto_lab import o1c112_full_bank_sign_alignment as alignment
from o1_crypto_lab.living_inverse import bits_to_key, canonical_json_bytes


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c112_full_bank_sign_alignment_v1.json"


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
def prepared() -> alignment.PreparedFullBankAnalysis:
    return alignment.prepare_full_bank_sign_alignment(CONFIG, root=ROOT)


def _truth_reader(
    key: bytes,
    calls: list[tuple[Path, int, str, str]] | None = None,
) -> alignment.TruthReader:
    ledger = calls if calls is not None else []

    def read(
        path: Path,
        source_bytes: int,
        source_sha256: str,
        freeze_sha256: str,
    ) -> alignment.HistoricalTruth:
        ledger.append((path, source_bytes, source_sha256, freeze_sha256))
        assert source_bytes == 2_714
        assert len(freeze_sha256) == 64
        return alignment.HistoricalTruth(
            key=key,
            source_file_sha256=source_sha256,
            reveal_sha256="a" * 64,
        )

    return read


def _frozen_arm(
    prepared: alignment.PreparedFullBankAnalysis, arm_name: str
) -> Mapping[str, object]:
    rows = [
        _mapping(value)
        for value in _sequence(prepared.score_freeze["arms"])
        if _mapping(value)["arm"] == arm_name
    ]
    assert len(rows) == 1
    return rows[0]


def _primary_prediction_key(
    prepared: alignment.PreparedFullBankAnalysis,
) -> bytes:
    bits = [0] * 256
    primary = _frozen_arm(prepared, alignment.PRIMARY_ARM)
    for value in _sequence(primary["coordinate_scores"]):
        row = _mapping(value)
        prediction = row["prediction_bit"]
        if prediction is not None:
            bits[_integer(row["coordinate_index"])] = _integer(prediction)
    return bits_to_key(bits)


def test_pretruth_freeze_authenticates_parent_banks_and_census(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    freeze = _mapping(prepared.score_freeze)
    assert freeze["schema"] == alignment.SCORE_FREEZE_SCHEMA
    assert hashlib.sha256(prepared.score_freeze_bytes).hexdigest() == (
        prepared.score_freeze_sha256
    )
    assert freeze["design_sha256"] == (
        "5a5e2a9923d3620381a988fa66246c82f0a95c6e33adb73b95c7fe0883a314a7"
    )
    assert freeze["authenticated_input_sha256"] == {
        "authoritative_result": (
            "22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28"
        ),
        "capsule_manifest": (
            "050a073b24fb2866b87e8353c1c8357c6598fa2eb9cf54119ee2991d7a99f2d0"
        ),
        "final_bank": (
            "efffdc2021d3c62bd92e4557a8515f1728bd3350582010b0b4a90a0d2fc65951"
        ),
        "parent_initial_prior_bank": (
            "62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f"
        ),
        "parent_result": (
            "22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28"
        ),
        "prior_bank": (
            "62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f"
        ),
    }
    census = _mapping(freeze["bank_census"])
    assert census == alignment.EXPECTED_CENSUS
    assert _mapping(census["final"])["count_sum"] == 449_663
    assert _mapping(census["prior"])["count_sum"] == 416_094
    increment = _mapping(census["increment"])
    assert increment == {
        "all_coordinate_counts_monotone": True,
        "count_sum": 33_569,
        "maximum_count": 534,
        "minimum_nonzero_count": 1,
        "nonzero_coordinate_count": 255,
        "zero_variables": [241],
    }

    lifecycle = _mapping(freeze["truth_lifecycle"])
    assert lifecycle["historical_reveal_file_reads_before_freeze"] == 0
    assert lifecycle["truth_key_bytes_read_before_freeze"] == 0
    assert b"key_hex" not in prepared.score_freeze_bytes
    assert b"truth_bit" not in prepared.score_freeze_bytes


def test_seven_frozen_arms_have_exact_orientation_and_population(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    arms = [_mapping(value) for value in _sequence(prepared.score_freeze["arms"])]
    assert [arm["arm"] for arm in arms] == [
        alignment.PRIMARY_ARM,
        *alignment.SECONDARY_ARMS,
    ]
    assert arms[0]["role"] == "primary"
    assert all(arm["role"] == "secondary_diagnostic" for arm in arms[1:])
    assert all(arm["evaluated_coordinate_count"] == 255 for arm in arms)
    assert all(arm["abstention_count"] == 1 for arm in arms)
    assert all(arm["secondary_can_change_primary"] is False for arm in arms)
    assert {
        cast(str, arm["arm"]): arm["prediction_census"] for arm in arms
    } == _mapping(alignment.EXPECTED_CENSUS["arm_predictions"])

    for arm in arms:
        rows = [_mapping(value) for value in _sequence(arm["coordinate_scores"])]
        assert len(rows) == 256
        assert [row["coordinate_index"] for row in rows] == list(range(256))
        missing = rows[240]
        assert missing["variable"] == 241
        assert missing["final_count"] == 0
        assert missing["prior_count"] == 0
        assert missing["increment_count"] == 0
        assert missing["prediction_bit"] is None
        assert missing["score"] == 0.0


def test_increment_means_use_the_frozen_binary64_fsum_formula(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    prior_payload = (ROOT / alignment.PRIOR_BANK_RELATIVE).read_bytes()
    final_payload = (ROOT / alignment.FINAL_BANK_RELATIVE).read_bytes()
    prior = alignment.decode_priority_bank(
        prior_payload, expected_sha256=alignment.PRIOR_BANK_SHA256
    )
    final = alignment.decode_priority_bank(
        final_payload, expected_sha256=alignment.FINAL_BANK_SHA256
    )
    fields = {
        alignment.SECONDARY_ARMS[3]: "robust_z_mean",
        alignment.SECONDARY_ARMS[4]: "centered_mean",
        alignment.SECONDARY_ARMS[5]: "raw_mean",
    }
    for arm_name, field in fields.items():
        arm = _frozen_arm(prepared, arm_name)
        rows = [_mapping(value) for value in _sequence(arm["coordinate_scores"])]
        for coordinate in (0, 96, 193, 255):
            old = prior[coordinate]
            new = final[coordinate]
            delta = new.count - old.count
            expected = -math.fsum(
                [
                    new.count * cast(float, getattr(new, field)),
                    -(old.count * cast(float, getattr(old, field))),
                ]
            ) / delta
            observed = _number(rows[coordinate]["score"])
            assert struct.pack("<d", observed) == struct.pack("<d", expected)


def test_perfect_frozen_primary_reaches_only_the_strong_retrospective_tier(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    calls: list[tuple[Path, int, str, str]] = []
    result = alignment.finalize_full_bank_sign_alignment(
        prepared,
        truth_reader=_truth_reader(_primary_prediction_key(prepared), calls),
    )
    assert len(calls) == 1
    assert calls[0][3] == prepared.score_freeze_sha256
    assert result["classification"] == alignment.STRONG_CLASSIFICATION
    assert result["secondary_arm_count"] == 6
    assert result["secondary_can_change_primary_classification"] is False
    primary = _mapping(result["primary"])
    assert primary["evaluated_coordinate_count"] == 255
    assert primary["abstention_count"] == 1
    assert primary["correct_count"] == 255
    assert primary["binomial_tail"] == {
        "decimal": float(1 / 2**255),
        "denominator": 2**255,
        "numerator": 1,
    }
    assert primary["strict_positive_sign_flip_margin"] is True
    assert _number(primary["identity_over_sign_flip_margin"]) > 0.0
    assert _mapping(primary["byte_accuracy"]) == {
        "exact_count": 31,
        "exact_indices": [*range(30), 31],
        "excluded_indices": [30],
        "fully_predicted_count": 31,
        "group_width_bits": 8,
    }
    assert _mapping(primary["word16_accuracy"]) == {
        "exact_count": 15,
        "exact_indices": list(range(15)),
        "excluded_indices": [15],
        "fully_predicted_count": 15,
        "group_width_bits": 16,
    }
    gates = _mapping(result["classification_gates"])
    assert _mapping(gates["strong"])["passed"] is True
    assert _mapping(gates["breadcrumb"])["passed"] is False
    claim = _mapping(result["claim_boundary"])
    assert claim["attacker_valid_entropy_gain_bits"] == 0.0
    assert claim["posterior_authorized"] is False
    assert claim["fresh_replication_required"] is True
    assert claim["sota_recovery_claim"] is False


def test_exact_142_of_255_with_positive_margin_reaches_breadcrumb_tier(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    primary = _frozen_arm(prepared, alignment.PRIMARY_ARM)
    rows = [_mapping(value) for value in _sequence(primary["coordinate_scores"])]
    bits = [0] * 256
    evaluated: list[tuple[float, int, int]] = []
    for row in rows:
        prediction = row["prediction_bit"]
        coordinate = _integer(row["coordinate_index"])
        if prediction is not None:
            bit = _integer(prediction)
            bits[coordinate] = bit
            evaluated.append((abs(_number(row["score"])), coordinate, bit))
    for _, coordinate, prediction in sorted(evaluated)[:113]:
        bits[coordinate] = 1 - prediction
    result = alignment.finalize_full_bank_sign_alignment(
        prepared, truth_reader=_truth_reader(bits_to_key(bits))
    )
    assert result["classification"] == alignment.BREADCRUMB_CLASSIFICATION
    measured = _mapping(result["primary"])
    assert measured["correct_count"] == 142
    assert measured["strict_positive_sign_flip_margin"] is True
    gates = _mapping(result["classification_gates"])
    assert _mapping(gates["strong"])["binomial_tail_pass"] is False
    assert _mapping(gates["strong"])["passed"] is False
    assert _mapping(gates["breadcrumb"])["passed"] is True


def test_no_directional_alignment_cannot_be_rescued_by_secondary_arms(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    result = alignment.finalize_full_bank_sign_alignment(
        prepared, truth_reader=_truth_reader(bytes(32))
    )
    assert result["classification"] == alignment.NULL_CLASSIFICATION
    assert _mapping(result["primary"])["correct_count"] == 113
    assert len(_sequence(result["secondary"])) == 6
    assert result["secondary_can_change_primary_classification"] is False
    assert _mapping(_mapping(result["classification_gates"])["strong"])[
        "passed"
    ] is False
    assert _mapping(_mapping(result["classification_gates"])["breadcrumb"])[
        "passed"
    ] is False


def test_controls_cover_identity_and_all_nonidentity_rotations(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    result = alignment.finalize_full_bank_sign_alignment(
        prepared, truth_reader=_truth_reader(_primary_prediction_key(prepared))
    )
    primary = _mapping(result["primary"])
    controls = [_mapping(row) for row in _sequence(primary["cyclic_controls"])]
    assert len(controls) == 256
    assert [row["offset"] for row in controls] == list(range(256))
    identity = _number(primary["identity_alignment"])
    assert _number(controls[0]["alignment"]) == identity
    rank = sum(_number(row["alignment"]) >= identity for row in controls)
    assert primary["cyclic_rank_count_conservative"] == rank
    assert primary["cyclic_rank_fraction"] == rank / 256
    assert primary["global_sign_flip_alignment"] == -identity
    assert primary["control_ledger_sha256"] == hashlib.sha256(
        canonical_json_bytes(controls)
    ).hexdigest()


def test_score_freeze_seal_prevents_truth_reader_invocation(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    calls: list[tuple[Path, int, str, str]] = []
    changed = replace(prepared, score_freeze_bytes=prepared.score_freeze_bytes + b"x")
    with pytest.raises(
        alignment.O1C112FullBankSignAlignmentError,
        match="score freeze seal differs",
    ):
        alignment.finalize_full_bank_sign_alignment(
            changed, truth_reader=_truth_reader(bytes(32), calls)
        )
    assert calls == []


def test_bank_decoder_rejects_digest_and_semantic_corruption() -> None:
    payload = (ROOT / alignment.PRIOR_BANK_RELATIVE).read_bytes()
    changed = bytearray(payload)
    changed[8:16] = struct.pack("<d", math.nan)
    changed_payload = bytes(changed)
    with pytest.raises(
        alignment.O1C112FullBankSignAlignmentError,
        match="priority bank SHA-256 differs",
    ):
        alignment.decode_priority_bank(
            changed_payload, expected_sha256=alignment.PRIOR_BANK_SHA256
        )
    with pytest.raises(
        alignment.O1C112FullBankSignAlignmentError,
        match="priority bank finite record differs",
    ):
        alignment.decode_priority_bank(
            changed_payload,
            expected_sha256=hashlib.sha256(changed_payload).hexdigest(),
        )


def test_truth_reader_accepts_hash_sealed_noncanonical_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "historical-reveal.json"
    payload = json.dumps({"fixture": "sealed-but-pretty"}, indent=2).encode("ascii")
    path.write_bytes(payload)
    key = bytes(range(32))

    def verify(value: object) -> dict[str, object]:
        assert value == {"fixture": "sealed-but-pretty"}
        return {
            "commitment_preimage": {"key_hex": key.hex()},
            "reveal_sha256": alignment.HISTORICAL_REVEAL_INNER_SHA256,
        }

    monkeypatch.setattr(alignment, "verify_reveal", verify)
    truth = alignment._read_historical_truth(
        path,
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        "c" * 64,
    )
    assert truth.key == key
    assert truth.source_file_sha256 == hashlib.sha256(payload).hexdigest()
    assert truth.reveal_sha256 == alignment.HISTORICAL_REVEAL_INNER_SHA256


def test_result_and_freeze_serialization_are_canonical_and_truth_minimal(
    prepared: alignment.PreparedFullBankAnalysis,
) -> None:
    freeze_payload = alignment.serialize_score_freeze(prepared)
    assert b"key_hex" not in freeze_payload
    assert b"truth_bit" not in freeze_payload
    assert prepared.score_freeze_sha256.encode("ascii") in freeze_payload

    result = alignment.finalize_full_bank_sign_alignment(
        prepared, truth_reader=_truth_reader(bytes(32))
    )
    payload = alignment.serialize_result(result)
    assert b"key_hex" not in payload
    assert b'"truth_bit"' not in payload
    unsigned = dict(result)
    observed = unsigned.pop("result_sha256")
    assert observed == hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    changed = dict(result)
    changed["classification"] = alignment.STRONG_CLASSIFICATION
    with pytest.raises(
        alignment.O1C112FullBankSignAlignmentError,
        match="result SHA-256 differs",
    ):
        alignment.serialize_result(changed)
