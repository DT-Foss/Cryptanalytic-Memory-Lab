from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c44_fresh_parent_criticality_rank_run import (
    _classify_ranks,
    load_config,
)


def test_real_config_locks_the_o1c43_reader_without_refit() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_config(
        root / "configs/o1c44_fresh_parent_criticality_rank_v1.json"
    )
    assert config["attempt_id"] == "O1C-0044"
    assert config["reader"]["no_refit"] is True
    assert config["reader"]["weights_sha256"].startswith("c4149a46")
    assert config["target"]["unknown_key_bits"] == 256


def test_fresh_classification_requires_threshold_and_both_controls() -> None:
    ranks = {
        "primary": {"rank_fraction": 0.04},
        "key_rotated": {"rank_fraction": 0.31},
        "clause_rotated": {"rank_fraction": 0.72},
    }
    classification, threshold, controls = _classify_ranks(
        ranks, maximum_fraction=0.25
    )
    assert classification == "FRESH_PARENT_CRITICALITY_RANK_TRANSFER"
    assert threshold and controls
    ranks["key_rotated"]["rank_fraction"] = 0.02
    classification, threshold, controls = _classify_ranks(
        ranks, maximum_fraction=0.25
    )
    assert classification == "FRESH_PARENT_CRITICALITY_RANK_WITHOUT_CONTROL_MARGIN"
    assert threshold and not controls
