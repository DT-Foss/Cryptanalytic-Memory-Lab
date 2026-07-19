from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import numpy as np
import pytest

from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256BrokerError,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from o1_crypto_lab.o1c58_multiblock_bit_vault_gradient_run import (
    ALL_ARMS_LIVE_STATE_BYTES,
    ARMS,
    BLOCK_COUNT,
    COMMIT_BOUND_SOURCE_NAMES,
    CONFIDENCE_DEPTHS,
    DECOY_COUNT,
    GRADIENT_PANEL_SIZE,
    KEY_BITS,
    O1C58RunError,
    PIPELINE,
    PREFIXES,
    PRIMARY_LIVE_STATE_BYTES,
    _apply_scalar_calibration,
    _attended_base_index,
    _base_truth_metrics,
    _classify_vault,
    _confidence_order,
    _delta_from_panel_z,
    _gradient_panel,
    _key_bit,
    _public_verify_key,
    _synthesize_key,
    _truth_metrics,
    _validate_freeze_rows,
    _vault_prefixes,
    _xor_key_bit,
    load_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c58_multiblock_bit_vault_gradient_v1.json"


class _Entropy:
    def __init__(self) -> None:
        self.payload = bytes((37 * index + 19) & 0xFF for index in range(ENTROPY_BYTES))
        self.requests: list[int] = []

    def __call__(self, count: int) -> bytes:
        self.requests.append(count)
        return self.payload


def _published() -> tuple[_Entropy, Full256TargetBroker, dict[str, object]]:
    entropy = _Entropy()
    broker = Full256TargetBroker(
        block_count=BLOCK_COUNT,
        entropy_source=entropy,
        entropy_source_id="test.o1c58",
        target_id="test-o1c58-eight-block",
    )
    return entropy, broker, broker.publish()


def _metric(
    *, correct: int, longest: int, top8_correct: int, exact: bool = False
) -> dict[str, object]:
    rows = []
    for depth in CONFIDENCE_DEPTHS:
        count = top8_correct if depth == 8 else min(correct, depth)
        rows.append(
            {
                "depth": depth,
                "correct": count,
                "accuracy": count / depth,
                "all_correct": count == depth,
            }
        )
    return {
        "correct_bits": correct,
        "longest_fully_correct_confidence_prefix": longest,
        "candidate_equals_truth": exact,
        "confidence_depths": rows,
    }


def _classification_maps() -> tuple[
    dict[tuple[str, int], dict[str, object]],
    dict[tuple[str, int], dict[str, object]],
]:
    metrics = {
        (arm, prefix): _metric(correct=128, longest=0, top8_correct=4)
        for arm in ARMS
        for prefix in PREFIXES
    }
    verification: dict[tuple[str, int], dict[str, object]] = {
        (arm, prefix): {"exact_all_blocks": False}
        for arm in ARMS
        for prefix in PREFIXES
    }
    return metrics, verification


def _freeze_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    block_rows: list[dict[str, object]] = []
    for block_index in range(BLOCK_COUNT):
        for arm in ARMS:
            block_rows.append(
                {
                    "block_index": block_index,
                    "counter": 100 + block_index,
                    "arm": arm,
                    "pipeline": PIPELINE,
                    "field_sha256": "01" * 32,
                    "field_description": {"arm": arm},
                    "feature_mean": [0.0] * 15,
                    "feature_std": [1.0] * 15,
                    "decoy_raw_score_sha256": "02" * 32,
                    "scalar_decoy_mean": 0.0,
                    "scalar_decoy_std_ddof1": 1.0,
                    "decoy_scalar_z_sha256": "03" * 32,
                    "calibration_keys_sha256": "04" * 32,
                    "gradient_raw_score_sha256": "05" * 32,
                    "gradient_scalar_z_sha256": "06" * 32,
                    "delta_sha256": "07" * 32,
                    "gradient_keys_sha256": "08" * 32,
                }
            )
    prefix_rows: list[dict[str, object]] = []
    for prefix in PREFIXES:
        for arm in ARMS:
            prefix_rows.append(
                {
                    "prefix": prefix,
                    "selection_scope": (
                        "primary-all-eight-block-attack"
                        if prefix == 8
                        else "post-selection-evidence-ablation"
                    ),
                    "arm": arm,
                    "pipeline": PIPELINE,
                    "vault_sha256": "09" * 32,
                    "live_state_bytes": PRIMARY_LIVE_STATE_BYTES,
                    "confidence_order_sha256": "0a" * 32,
                    "synthesized_key_sha256": "0b" * 32,
                    "gradient_keys_sha256": "08" * 32,
                    "public_verification": {
                        "candidate_output_sha256": "0c" * 32,
                        "block_matches": [False] * BLOCK_COUNT,
                        "matched_blocks": 0,
                        "exact_all_blocks": False,
                    },
                }
            )
    return block_rows, prefix_rows


def test_gradient_panel_uses_exact_little_endian_in_byte_bit_convention() -> None:
    base = bytes(range(32))
    panel = _gradient_panel(base)
    assert len(panel) == len(set(panel)) == GRADIENT_PANEL_SIZE
    assert panel[0] == base
    assert panel[1] == bytes([base[0] ^ 0x01]) + base[1:]
    assert panel[8] == bytes([base[0] ^ 0x80]) + base[1:]
    assert panel[9] == base[:1] + bytes([base[1] ^ 0x01]) + base[2:]
    assert panel[256] == base[:-1] + bytes([base[-1] ^ 0x80])
    for bit_index, neighbor in enumerate(panel[1:]):
        assert neighbor == _xor_key_bit(base, bit_index)
        assert _key_bit(neighbor, bit_index) == 1 - _key_bit(base, bit_index)
        assert (
            sum((left ^ right).bit_count() for left, right in zip(base, neighbor)) == 1
        )


def test_attended_base_is_ordered_streaming_prefix8_argmax_with_index_tie() -> None:
    matrix = np.zeros((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64)
    matrix[0, 9] = 1e16
    matrix[1, 9] = -1e16
    matrix[2, 9] = 3.0
    matrix[:, 4] = 0.25
    matrix[:, 5] = 0.25
    index, aggregate = _attended_base_index(matrix)
    expected = np.zeros(DECOY_COUNT, dtype=np.float64)
    for row in matrix:
        expected = np.add(expected, row, dtype=np.float64)
    assert aggregate.tobytes() == expected.tobytes()
    assert index == 9

    matrix[:, 9] = 0.0
    index, _ = _attended_base_index(matrix)
    assert index == 4


def test_decoy_scalar_calibration_delta_and_vault_prefix_math_are_exact() -> None:
    panel = np.linspace(-7.0, 11.0, GRADIENT_PANEL_SIZE, dtype=np.float64)
    z_values = _apply_scalar_calibration(panel, mean=2.0, std=3.0)
    delta = _delta_from_panel_z(z_values)
    assert np.array_equal(delta, z_values[1:] - z_values[0])

    blocks = np.vstack([delta + index for index in range(BLOCK_COUNT)])
    snapshots = _vault_prefixes(blocks)
    assert tuple(snapshots) == PREFIXES
    for prefix in PREFIXES:
        expected = np.zeros(KEY_BITS, dtype=np.float64)
        for row in blocks[:prefix]:
            expected = np.add(expected, row, dtype=np.float64)
        assert snapshots[prefix].tobytes() == expected.tobytes()
        assert snapshots[prefix].nbytes == PRIMARY_LIVE_STATE_BYTES
    assert ALL_ARMS_LIVE_STATE_BYTES == 6144


def test_synthesis_strict_positive_flip_tie_retains_and_confidence_ties_by_index() -> (
    None
):
    base = b"\x00" * 32
    evidence = np.zeros(KEY_BITS, dtype=np.float64)
    evidence[0] = 2.0
    evidence[1] = -2.0
    evidence[7] = 1.0
    evidence[8] = -0.0
    candidate = _synthesize_key(base, evidence)
    assert candidate[:2] == b"\x81\x00"
    assert candidate[2:] == b"\x00" * 30
    order = _confidence_order(evidence)
    assert order[:4] == (0, 1, 7, 2)


def test_public_verification_is_complete_and_needs_no_truth_read() -> None:
    entropy, broker, publication = _published()
    public = public_view_from_publication(publication)
    assert broker.phase == "PUBLISHED"
    base = hashlib.sha256(bytes.fromhex(public.digest())).digest()
    panel = _gradient_panel(base)
    verification = _public_verify_key(panel[0], public)
    assert set(verification) == {
        "candidate_output_sha256",
        "block_matches",
        "matched_blocks",
        "exact_all_blocks",
    }
    assert len(cast(list[bool], verification["block_matches"])) == BLOCK_COUNT
    assert broker.phase == "PUBLISHED"
    assert entropy.requests == [ENTROPY_BYTES]

    frozen = hashlib.sha256(
        json.dumps(verification, sort_keys=True).encode()
    ).hexdigest()
    receipt = make_freeze_receipt(publication, frozen_artifact_sha256=frozen)
    revealed = verify_reveal(broker.reveal(receipt))
    assert revealed["commitment_preimage"]
    with pytest.raises(Full256BrokerError, match="already"):
        broker.reveal(receipt)


def test_truth_metrics_freeze_confidence_depths_and_residual_width() -> None:
    base = b"\x00" * 32
    evidence = np.linspace(256.0, 1.0, KEY_BITS, dtype=np.float64)
    candidate = _synthesize_key(base, evidence)
    truth = bytearray(candidate)
    truth[2] ^= 1 << 4  # Confidence-order bit 20 is the first wrong polarity.
    order = _confidence_order(evidence)
    metrics = _truth_metrics(
        base_key=base,
        candidate=candidate,
        truth_key=bytes(truth),
        evidence=evidence,
        confidence_order=order,
    )
    assert metrics["correct_bits"] == 255
    assert metrics["hamming_distance"] == 1
    assert metrics["longest_fully_correct_confidence_prefix"] == 20
    assert metrics["residual_width_after_correct_confidence_prefix"] == 236
    depths = cast(list[dict[str, object]], metrics["confidence_depths"])
    assert [row["depth"] for row in depths] == list(CONFIDENCE_DEPTHS)
    assert cast(dict[str, object], depths[3])["all_correct"] is True


def test_classification_exact_base_exact_synth_partial_and_no_transfer() -> None:
    metrics, verification = _classification_maps()
    base_metrics = _base_truth_metrics(b"\x00" * 32, b"\x00" * 32)
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metrics,
        verification_lookup=verification,
        base_verification={"exact_all_blocks": True},
        guidance_depth=8,
        minimum_correct_bits=144,
        minimum_base_improvement=8,
    )
    assert classification == "MULTIBLOCK_BIT_VAULT_EXACT_FULL256_RECOVERY"
    assert gates["base_exact_recovery"] is True

    base_metrics = {"correct_bits": 128, "candidate_equals_truth": False}
    metrics[("clause_rotated", 4)] = _metric(
        correct=256, longest=256, top8_correct=8, exact=True
    )
    verification[("clause_rotated", 4)] = {"exact_all_blocks": True}
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metrics,
        verification_lookup=verification,
        base_verification={"exact_all_blocks": False},
        guidance_depth=8,
        minimum_correct_bits=144,
        minimum_base_improvement=8,
    )
    assert classification.endswith("EXACT_FULL256_RECOVERY")
    assert gates["exact_synthesized_candidates"] == [
        {"arm": "clause_rotated", "prefix": 4}
    ]

    metrics, verification = _classification_maps()
    metrics[("primary", 8)] = _metric(correct=136, longest=9, top8_correct=8)
    metrics[("key_rotated", 8)] = _metric(correct=140, longest=1, top8_correct=5)
    metrics[("clause_rotated", 8)] = _metric(correct=141, longest=2, top8_correct=5)
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metrics,
        verification_lookup=verification,
        base_verification={"exact_all_blocks": False},
        guidance_depth=8,
        minimum_correct_bits=144,
        minimum_base_improvement=8,
    )
    assert classification == "MULTIBLOCK_BIT_VAULT_PARTIAL_DIRECTIONAL_RECOVERY"
    assert gates["primary_partial_guidance_gate"] is True
    assert gates["secondary_strong_bit_advantage_gate"] is False

    metrics[("primary", 8)] = _metric(correct=150, longest=0, top8_correct=4)
    metrics[("key_rotated", 8)] = _metric(correct=140, longest=0, top8_correct=4)
    metrics[("clause_rotated", 8)] = _metric(correct=141, longest=0, top8_correct=4)
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metrics,
        verification_lookup=verification,
        base_verification={"exact_all_blocks": False},
        guidance_depth=8,
        minimum_correct_bits=144,
        minimum_base_improvement=8,
    )
    assert classification == "MULTIBLOCK_BIT_VAULT_PARTIAL_DIRECTIONAL_RECOVERY"
    assert gates["primary_partial_guidance_gate"] is False
    assert gates["secondary_strong_bit_advantage_gate"] is True

    metrics[("primary", 8)] = _metric(correct=128, longest=0, top8_correct=4)
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metrics,
        verification_lookup=verification,
        base_verification={"exact_all_blocks": False},
        guidance_depth=8,
        minimum_correct_bits=144,
        minimum_base_improvement=8,
    )
    assert classification == "MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER"
    assert gates["partial_recovery_gate"] is False


def test_freeze_requires_all_fields_vaults_verifications_and_ablation_labels() -> None:
    block_rows, prefix_rows = _freeze_rows()
    _validate_freeze_rows(block_rows, prefix_rows)
    assert len(block_rows) == 24
    assert len(prefix_rows) == 12
    assert {row["selection_scope"] for row in prefix_rows if row["prefix"] != 8} == {
        "post-selection-evidence-ablation"
    }
    with pytest.raises(O1C58RunError, match="freeze rows"):
        _validate_freeze_rows(block_rows[:-1], prefix_rows)
    tampered = [dict(row) for row in prefix_rows]
    tampered[0]["selection_scope"] = "future-blind-online-attack"
    with pytest.raises(O1C58RunError, match="verification row"):
        _validate_freeze_rows(block_rows, tampered)


def test_real_config_freezes_attention_blindness_state_and_exact_ledgers() -> None:
    config = load_config(CONFIG)
    gradient = cast(dict[str, object], config["gradient_panel"])
    vault = cast(dict[str, object], config["vault"])
    verification = cast(dict[str, object], config["verification"])
    budgets = cast(dict[str, object], config["budgets"])
    assert gradient["base_selection"] == (
        "argmax-unweighted-eight-block-primary-decoy-scalar-z-with-smallest-index-tiebreak"
    )
    assert gradient["truth_key_used_in_generation"] is False
    assert str(gradient["truth_collision_policy"]).startswith("allowed-and-counted")
    assert vault["primary_live_state_bytes"] == PRIMARY_LIVE_STATE_BYTES == 2048
    assert vault["all_three_live_state_bytes"] == ALL_ARMS_LIVE_STATE_BYTES == 6144
    assert str(vault["prefix_interpretation"]).startswith("prefix-8-is-the-primary")
    assert verification["candidate_count"] == 13
    assert budgets["maximum_candidate_forward_evaluations"] == 34824
    assert budgets["maximum_direct_chacha_block_evaluations"] == 112
    assert budgets["maximum_all_arms_live_state_bytes"] == 6144
    assert json.loads(CONFIG.read_text(encoding="utf-8"))["claim_level"] == "TEST"


def test_commit_binding_covers_every_imported_scientific_source() -> None:
    assert set(COMMIT_BOUND_SOURCE_NAMES) == {
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "o1c57_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    }
