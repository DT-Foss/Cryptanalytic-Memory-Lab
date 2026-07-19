from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import numpy as np
import pytest

from o1_crypto_lab.chacha_trace import chacha20_blocks
from o1_crypto_lab.full256_broker import (
    ENTROPY_BYTES,
    Full256BrokerError,
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from o1_crypto_lab.living_inverse import PublicTargetView
from o1_crypto_lab.o1c57_multiblock_parent_criticality_rank_run import (
    ARMS,
    BLOCK_COUNT,
    COMMIT_BOUND_SOURCE_NAMES,
    DECOY_COUNT,
    PIPELINE,
    PREFIXES,
    O1C57RunError,
    _assert_no_truth_collision,
    _classify_prefix_ranks,
    _prefix_sums,
    _shared_decoy_panel,
    _slice_public_blocks,
    _slice_public_view,
    _standardize_scalar_decoys,
    _standardize_scalar_truth,
    _validate_freeze_rows,
    load_config,
)
from o1_crypto_lab.relation_candidate_rank import array_sha256, exact_candidate_rank


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c57_multiblock_parent_criticality_rank_v1.json"


class _Entropy:
    def __init__(self) -> None:
        self.payload = bytes((29 * index + 11) & 0xFF for index in range(ENTROPY_BYTES))
        self.requests: list[int] = []

    def __call__(self, count: int) -> bytes:
        self.requests.append(count)
        return self.payload


def _published_view() -> tuple[_Entropy, Full256TargetBroker, dict[str, object], PublicTargetView]:
    entropy = _Entropy()
    broker = Full256TargetBroker(
        block_count=BLOCK_COUNT,
        entropy_source=entropy,
        entropy_source_id="test.o1c57",
        target_id="test-o1c57-eight-block",
    )
    publication = broker.publish()
    return entropy, broker, publication, public_view_from_publication(publication)


def _freeze_rows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    candidate_hash = "ab" * 32
    block_rows = []
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
                    "raw_score_sha256": "02" * 32,
                    "scalar_decoy_mean": 0.0,
                    "scalar_decoy_std_ddof1": 1.0,
                    "scalar_z_sha256": "03" * 32,
                    "candidate_keys_sha256": candidate_hash,
                }
            )
    prefix_rows = []
    for prefix in PREFIXES:
        for arm in ARMS:
            prefix_rows.append(
                {
                    "prefix": prefix,
                    "arm": arm,
                    "pipeline": PIPELINE,
                    "aggregate_score_sha256": "04" * 32,
                    "candidate_keys_sha256": candidate_hash,
                }
            )
    return block_rows, prefix_rows


def test_eight_contiguous_blocks_publish_slice_and_reveal_once() -> None:
    entropy, broker, publication, public = _published_view()
    assert entropy.requests == [ENTROPY_BYTES]
    assert public.block_count == BLOCK_COUNT
    assert public.counter_schedule == tuple(
        range(public.counter_schedule[0], public.counter_schedule[0] + BLOCK_COUNT)
    )

    slices = _slice_public_blocks(public)
    assert len(slices) == BLOCK_COUNT
    assert tuple(item.counter_schedule[0] for item in slices) == public.counter_schedule
    assert tuple(item.output_blocks[0] for item in slices) == public.output_blocks
    assert all(item.nonce == public.nonce and item.block_count == 1 for item in slices)

    receipt = make_freeze_receipt(publication, frozen_artifact_sha256="57" * 32)
    reveal = broker.reveal(receipt)
    verified = verify_reveal(reveal)
    truth = bytes.fromhex(verified["commitment_preimage"]["key_hex"])
    assert chacha20_blocks(
        truth, public.counter_schedule[0], public.nonce, BLOCK_COUNT
    ) == public.output_blocks
    assert entropy.requests == [ENTROPY_BYTES]
    with pytest.raises(Full256BrokerError, match="already"):
        broker.reveal(receipt)


def test_public_slicing_rejects_wrong_count_and_invalid_index() -> None:
    _, _, _, public = _published_view()
    assert _slice_public_view(public, 7).counter_schedule == (
        public.counter_schedule[7],
    )
    with pytest.raises(O1C57RunError, match="slice"):
        _slice_public_view(public, 8)
    seven = PublicTargetView(
        counter_schedule=public.counter_schedule[:7],
        nonce=public.nonce,
        output_blocks=public.output_blocks[:7],
    )
    seven.validate()
    with pytest.raises(O1C57RunError, match="slice"):
        _slice_public_blocks(seven)


def test_shared_panel_uses_full_public_digest_and_is_byte_identical() -> None:
    _, _, _, public = _published_view()
    first = _shared_decoy_panel(
        public,
        domain="O1C57-multiblock-parent-criticality-decoy-v1",
        count=DECOY_COUNT,
    )
    second = _shared_decoy_panel(
        public,
        domain="O1C57-multiblock-parent-criticality-decoy-v1",
        count=DECOY_COUNT,
    )
    assert first == second
    assert len(first) == len(set(first)) == DECOY_COUNT
    assert b"".join(first) == b"".join(second)
    seed = hashlib.sha256(
        b"O1C57-multiblock-parent-criticality-decoy-v1\0"
        + bytes.fromhex(public.digest())
    ).digest()
    assert first[:4] == tuple(
        hashlib.sha256(seed + index.to_bytes(8, "little")).digest()
        for index in range(4)
    )

    changed_block = bytes([public.output_blocks[-1][0] ^ 1]) + public.output_blocks[-1][1:]
    changed = PublicTargetView(
        counter_schedule=public.counter_schedule,
        nonce=public.nonce,
        output_blocks=(*public.output_blocks[:-1], changed_block),
    )
    changed.validate()
    changed_panel = _shared_decoy_panel(
        changed,
        domain="O1C57-multiblock-parent-criticality-decoy-v1",
        count=DECOY_COUNT,
    )
    assert changed_panel != first


def test_scalar_standardization_is_decoy_only_ddof1_and_zero_variance_fatal() -> None:
    decoys = np.asarray([-2.0, -0.5, 1.0, 5.0], dtype=np.float64)
    z_values, mean, std = _standardize_scalar_decoys(decoys)
    assert mean == pytest.approx(float(np.mean(decoys)))
    assert std == pytest.approx(float(np.std(decoys, ddof=1)))
    assert float(np.mean(z_values)) == pytest.approx(0.0, abs=1e-15)
    assert float(np.std(z_values, ddof=1)) == pytest.approx(1.0)

    truth_z = _standardize_scalar_truth(1000.0, mean=mean, std=std)
    assert truth_z == pytest.approx((1000.0 - mean) / std)
    # The truth is transformed after, and therefore cannot alter calibration.
    _, repeated_mean, repeated_std = _standardize_scalar_decoys(decoys)
    assert (repeated_mean, repeated_std) == (mean, std)
    with pytest.raises(O1C57RunError, match="variance is zero"):
        _standardize_scalar_decoys(np.ones(8, dtype=np.float64))


def test_prefixes_are_exact_unweighted_positive_sums() -> None:
    matrix = np.arange(BLOCK_COUNT * 5, dtype=np.float64).reshape(BLOCK_COUNT, 5)
    prefixes = _prefix_sums(matrix)
    assert tuple(prefixes) == PREFIXES
    for prefix in PREFIXES:
        assert np.array_equal(prefixes[prefix], np.sum(matrix[:prefix], axis=0))
    assert array_sha256(prefixes[8], "<f8") == array_sha256(
        np.sum(matrix, axis=0), "<f8"
    )


def test_freeze_requires_all_24_block_and_12_prefix_rows_on_identical_path() -> None:
    block_rows, prefix_rows = _freeze_rows()
    _validate_freeze_rows(block_rows, prefix_rows)
    assert len(block_rows) == 24
    assert len(prefix_rows) == 12
    assert {row["pipeline"] for row in (*block_rows, *prefix_rows)} == {PIPELINE}
    assert len({row["candidate_keys_sha256"] for row in block_rows}) == 1

    missing = block_rows[:-1]
    with pytest.raises(O1C57RunError, match="freeze rows"):
        _validate_freeze_rows(missing, prefix_rows)
    tampered = [dict(row) for row in prefix_rows]
    tampered[0]["pipeline"] = "control-shortcut"
    with pytest.raises(O1C57RunError, match="freeze rows"):
        _validate_freeze_rows(block_rows, tampered)


def test_synthetic_prefix_ranks_hashes_and_classification_are_deterministic() -> None:
    keys = tuple(index.to_bytes(32, "little") for index in range(DECOY_COUNT))
    blocks = np.vstack(
        [np.linspace(-1.0 + index, 1.0 + index, DECOY_COUNT) for index in range(8)]
    )
    aggregate = _prefix_sums(blocks)
    first_hash = array_sha256(aggregate[8], "<f8")
    assert first_hash == "31c51995e621c804e93cedc4396245c64dc0829778c7b395364f716ce6817f5d"
    assert first_hash == array_sha256(_prefix_sums(blocks)[8], "<f8")
    rank = exact_candidate_rank(
        truth_score=float(np.max(aggregate[8]) + 1.0),
        decoy_scores=aggregate[8],
        truth_key=b"\xff" * 32,
        decoy_keys=keys,
    )
    assert rank["rank"] == 1

    ranks = {
        (arm, prefix): 100 for arm in ARMS for prefix in PREFIXES
    }
    ranks[("primary", 1)] = 40
    ranks[("primary", 8)] = 12
    ranks[("key_rotated", 8)] = 30
    ranks[("clause_rotated", 8)] = 31
    classification, gates = _classify_prefix_ranks(
        ranks, maximum_prefix8_rank=16
    )
    assert classification == "MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER"
    assert gates["prediction_pass"] is True
    ranks[("key_rotated", 8)] = 8
    classification, gates = _classify_prefix_ranks(
        ranks, maximum_prefix8_rank=16
    )
    assert classification.endswith("RANK_IMPROVEMENT_WITHOUT_FULL_GATE")
    assert gates["prediction_pass"] is False


def test_truth_collision_is_fatal_without_panel_regeneration() -> None:
    keys = tuple(index.to_bytes(32, "little") for index in range(DECOY_COUNT))
    with pytest.raises(O1C57RunError, match="collides"):
        _assert_no_truth_collision(keys[57], keys)
    _assert_no_truth_collision(b"\xff" * 32, keys)


def test_real_config_forbids_refit_reweight_signs_and_subsets() -> None:
    config = load_config(CONFIG)
    target = cast(dict[str, object], config["target"])
    reader = cast(dict[str, object], config["reader"])
    aggregation = cast(dict[str, object], config["aggregation"])
    field = cast(dict[str, object], config["field"])
    panel = cast(dict[str, object], config["candidate_panel"])
    controls = cast(dict[str, object], config["controls"])
    budgets = cast(dict[str, object], config["budgets"])
    assert config["attempt_id"] == "O1C-0057"
    assert target["block_count"] == BLOCK_COUNT
    assert str(reader["weights_sha256"]).startswith("c4149a46")
    assert reader["no_refit"] is True
    assert reader["no_reweight"] is True
    assert reader["no_sign_selection"] is True
    assert reader["no_block_subset_selection"] is True
    assert field["score_unit"] == "exclusive-chain-direct-original-parent-occurrence"
    assert str(reader["feature_standardization"]).startswith("unchanged-o1c43")
    assert str(panel["generator"]).startswith("sha256(sha256(domain")
    assert aggregation["block_signs"] == [1] * BLOCK_COUNT
    assert aggregation["prefixes"] == list(PREFIXES)
    assert controls["arms"] == list(ARMS)
    assert str(controls["rotation"]).startswith("one-step cyclic derangement")
    assert budgets["maximum_candidate_forward_evaluations"] == 32776
    assert json.loads(CONFIG.read_text(encoding="utf-8"))["claim_level"] == "TEST"


def test_commit_binding_separates_tracked_code_from_hashed_capsule_artifacts() -> None:
    bound = set(COMMIT_BOUND_SOURCE_NAMES)
    assert bound == {
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    }
    assert bound.isdisjoint({"template", "semantic_map", "o1c43_manifest"})
