from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c41_antecedent_chain_rank_run import (
    _candidate_keys,
    _select_orientations,
    load_config,
)


def test_real_config_and_candidate_panel_are_frozen() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_config(root / "configs/o1c41_antecedent_chain_rank_v1.json")
    assert config["attempt_id"] == "O1C-0041"
    keys = _candidate_keys("O1C41-antecedent-chain-decoy-v1", "11" * 32, 32)
    assert keys == _candidate_keys(
        "O1C41-antecedent-chain-decoy-v1", "11" * 32, 32
    )
    assert len(keys) == len(set(keys)) == 32
    assert all(len(key) == 32 for key in keys)


def test_strict_and_rank_product_orientation_are_separate() -> None:
    natural = (0.9492311447400537, 0.5835977544544789, 0.9938979741274103, 0.45594337319990236)
    reversed_rank = (0.05565047595801806, 0.38735660239199415, 0.006346106907493288, 0.5528435440566268)
    signs = (-1, -1, -1, 1)
    rows = [
        {
            "natural_center_sign": sign,
            "natural": {"rank_fraction": forward},
            "reversed": {"rank_fraction": reverse},
        }
        for sign, forward, reverse in zip(
            signs, natural, reversed_rank, strict=True
        )
    ]
    selected = _select_orientations(rows)
    assert selected["strict_center_signs"] == list(signs)
    assert selected["strict_selection"] == 0
    assert selected["pooled_rank_product_selection"] == -1
    assert selected["reversed_geometric_rank_fraction"] < 0.10
    assert (
        selected["reversed_geometric_rank_fraction"]
        < selected["natural_geometric_rank_fraction"]
    )
