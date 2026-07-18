from __future__ import annotations

from pathlib import Path

import numpy as np

from o1_crypto_lab.o1_relational_search import repair_radius_scores
from o1_crypto_lab.o1c38_exact_residual_completion_run import (
    ATTEMPT_ID,
    _confidence_order,
    load_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c38_exact_residual_completion_v1.json"


def test_frozen_o1c38_config_has_exact_conflict_ledger() -> None:
    config = load_config(CONFIG)
    assert config["attempt_id"] == ATTEMPT_ID
    assert config["sweep"]["residual_bits_at_base"] == [0, 1, 2, 4, 8, 9, 16]
    assert config["budgets"]["maximum_native_solver_calls"] == 10
    assert config["budgets"]["maximum_conflicts"] == 46592


def test_exact_truth_prefix_stays_correct_under_tied_o1_magnitudes() -> None:
    scores = np.zeros(256, dtype=np.float64)
    scores[::3] = 2.0
    truth = np.arange(256) & 1
    exact = repair_radius_scores(scores, truth, wrong_count=0)
    order = _confidence_order(exact)
    signs = exact >= 0.0
    for guided_bits in (256, 255, 254, 252, 248, 247, 240):
        assert (
            int(
                np.count_nonzero(
                    signs[order[:guided_bits]] == truth[order[:guided_bits]]
                )
            )
            == guided_bits
        )
