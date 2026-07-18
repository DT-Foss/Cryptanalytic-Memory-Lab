from __future__ import annotations

import numpy as np

from o1_crypto_lab.o1c47_global_criticality_residual_beam_run import (
    _candidate_key,
    _nested_masks,
    _rank_row,
)


def test_candidate_codec_and_nested_rank_are_exact() -> None:
    truth = bytes(32)
    variables = (1, 8, 9, 256)
    key = _candidate_key(truth, variables, 0b1101)
    assert key[0] == 0b00000001
    assert key[1] == 0b00000001
    assert key[31] == 0b10000000

    masks = _nested_masks(truth_mask=0b1011, width=2, maximum_width=4)
    assert masks.tolist() == [8, 9, 10, 11]
    scores = np.asarray([float(value) for value in range(16)])
    row = _rank_row(scores=scores, masks=masks, truth_mask=0b1011)
    assert row["candidate_count"] == 4
    assert row["strict_rank"] == 1
    assert row["deterministic_rank"] == 1
    assert row["search_compression_bits"] == 2.0
