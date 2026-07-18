from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c40_relation_candidate_rank_run import ATTEMPT_ID, load_config


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c40_relation_candidate_rank_v1.json"


def test_o1c40_freezes_one_raw_and_one_surprise_candidate_score() -> None:
    config = load_config(CONFIG)
    assert config["attempt_id"] == ATTEMPT_ID
    assert config["candidate_panel"]["count_per_target"] == 4096
    assert config["scorers"]["methods"] == [
        "raw_abs_units",
        "surprise_log_odds_v1",
    ]
    assert config["scorers"]["no_other_score_or_calibration_arm"] is True
