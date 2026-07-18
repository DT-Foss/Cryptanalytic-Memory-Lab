from __future__ import annotations

from pathlib import Path

from o1_crypto_lab.o1c39_proof_clause_relation_transfer_run import (
    ATTEMPT_ID,
    _write_factor_rows,
    load_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c39_proof_clause_relation_transfer_v1.json"


def test_frozen_o1c39_config_selects_one_relation_class_and_two_targets() -> None:
    config = load_config(CONFIG)
    assert config["attempt_id"] == ATTEMPT_ID
    assert config["selection_freeze"]["selected_absolute_weight"] == 0.5
    assert config["selection_freeze"]["no_other_horizon_or_weight_arm"] is True
    assert [row["target_id"] for row in config["targets"]] == [
        "development-0000",
        "development-0001",
    ]
    assert config["search"]["residual_bits"] == 9


def test_combined_factor_rows_coalesce_anchor_and_relation_edge(tmp_path: Path) -> None:
    destination = tmp_path / "factors.txt"
    digest = _write_factor_rows(
        destination,
        [(1, 257, 4096), (1, 257, -3), (2, 257, -4095)],
    )
    payload = b"1 257 4093\n2 257 -4095\n"
    assert destination.read_bytes() == payload
    assert len(digest) == 64
