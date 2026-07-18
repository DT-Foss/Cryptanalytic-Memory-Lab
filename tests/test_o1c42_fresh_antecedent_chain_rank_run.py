from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c42_fresh_antecedent_chain_rank_run import (
    _classify_ranks,
    load_config,
)


def test_real_fresh_config_is_frozen() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_config(
        root / "configs/o1c42_fresh_antecedent_chain_rank_v1.json"
    )
    assert config["attempt_id"] == "O1C-0042"
    assert config["field"]["global_orientation"] == -1
    assert config["candidate_panel"]["count"] == 4096
    assert config["budgets"]["maximum_scientific_entropy_calls"] == 1


def test_rank_classification_requires_threshold_and_both_controls() -> None:
    passed = {
        "primary": {"rank_fraction": 0.20},
        "key_rotated": {"rank_fraction": 0.40},
        "factor_rotated": {"rank_fraction": 0.30},
    }
    assert _classify_ranks(passed, maximum_fraction=0.25) == (
        "FRESH_CHAIN_RANK_TRANSFER",
        True,
        True,
    )
    no_margin = {
        **passed,
        "factor_rotated": {"rank_fraction": 0.10},
    }
    assert _classify_ranks(no_margin, maximum_fraction=0.25) == (
        "FRESH_CHAIN_RANK_WITHOUT_CONTROL_MARGIN",
        True,
        False,
    )
    null = {
        **passed,
        "primary": {"rank_fraction": 0.50},
    }
    assert _classify_ranks(null, maximum_fraction=0.25) == (
        "FRESH_CHAIN_RANK_NOT_REPLICATED",
        False,
        False,
    )
