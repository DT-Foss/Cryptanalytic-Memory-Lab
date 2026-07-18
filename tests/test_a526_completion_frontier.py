from __future__ import annotations

import numpy as np

from o1_crypto_lab.a526_completion_frontier import (
    A526_FIXED_WIDTH,
    evaluate_a526_complement_topk,
    iter_a526_complement_topk,
)
from o1_crypto_lab.chacha_trace import chacha20_block
from o1_crypto_lab.living_inverse import PublicTargetView, key_bits


def _public(key: bytes) -> PublicTargetView:
    nonce = bytes.fromhex("000000090000004a00000000")
    return PublicTargetView(
        counter_schedule=(1,),
        nonce=nonce,
        output_blocks=(chacha20_block(key, 1, nonce),),
    )


def test_map_complement_binds_to_unchanged_a526_codec() -> None:
    key = bytes(range(32))
    truth = key_bits(key)
    logits = np.where(truth == 1, 3.0, -3.0)
    candidate = next(iter_a526_complement_topk(logits, limit=1))
    assignment = sum(int(truth[index]) << index for index in range(52))
    handoff = candidate.handoff(_public(key))
    assert len(candidate.fixed_bits) == A526_FIXED_WIDTH
    assert handoff.candidate_key(assignment) == key
    assert handoff.verify(assignment)


def test_frontier_never_flips_a526_residual_coordinates() -> None:
    logits = np.full(256, -10.0)
    logits[:52] = 0.0
    logits[52] = -0.01
    first, second = iter_a526_complement_topk(logits, limit=2)
    assert first.flipped_coordinates == ()
    assert second.flipped_coordinates == (52,)


def test_post_reveal_evaluation_finds_one_error_at_rank_two() -> None:
    truth_key = bytes(32)
    logits = np.full(256, -5.0)
    logits[52] = 0.01
    result = evaluate_a526_complement_topk(
        logits,
        truth_key=truth_key,
        limit=2,
    )
    assert result["map_correct_fixed_bits"] == 203
    assert result["best_beam_correct_fixed_bits"] == 204
    assert result["exact_complement_in_beam"] is True
    assert result["exact_complement_rank_one_based"] == 2
    assert result["beam_worst_case_candidate_work_log2"] == 53.0


def test_absent_exact_complement_reports_a_strict_rank_floor() -> None:
    truth_key = bytes(32)
    logits = np.full(256, 5.0)
    result = evaluate_a526_complement_topk(
        logits,
        truth_key=truth_key,
        limit=16,
    )
    assert result["exact_complement_in_beam"] is False
    assert result["exact_complement_rank_lower_bound"] == 17
    assert result["backend_launched"] is False
