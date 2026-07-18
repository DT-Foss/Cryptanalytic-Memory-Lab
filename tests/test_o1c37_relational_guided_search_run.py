from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c37_relational_guided_search_run import ATTEMPT_ID, load_config


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c37_relational_guided_search_v1.json"


def test_frozen_o1c37_config_selects_one_consumed_full256_target() -> None:
    config = load_config(CONFIG)
    assert config["attempt_id"] == ATTEMPT_ID
    assert config["target"]["target_id"] == "build-0000"
    assert config["exact_relation"]["o1_guided_widths"] == [52, 128, 256]
    assert config["budgets"]["maximum_fresh_targets"] == 0
    assert config["budgets"]["maximum_sibling_writes"] == 0
