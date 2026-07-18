from __future__ import annotations

from pathlib import Path

import numpy as np

from o1_crypto_lab.o1c43_parent_criticality_rank_run import (
    _classify_development,
    _fit_reader,
    _standardize_panel,
    load_config,
)
from o1_crypto_lab.proof_parent_criticality import FEATURE_NAMES


def test_real_config_freezes_the_direct_original_reader() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_config(root / "configs/o1c43_parent_criticality_rank_v1.json")
    assert config["attempt_id"] == "O1C-0043"
    assert config["field"]["direct_original_only"] is True
    assert config["reader"]["feature_names"] == list(FEATURE_NAMES)
    assert config["corpus"]["fresh_targets"] == 0


def test_reader_is_exact_normalized_mean_build_truth_z() -> None:
    rows = []
    for index in range(4):
        row = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
        row[3] = -2.0 - index
        row[6] = -1.0
        rows.append(row)
    raw, reader = _fit_reader(rows)
    assert raw[3] == -3.5
    assert raw[6] == -1.0
    assert np.isclose(np.linalg.norm(reader), 1.0)
    assert reader[3] < reader[6] < 0.0


def test_panel_standardization_leaves_inactive_channels_zero() -> None:
    panel = np.zeros((8, len(FEATURE_NAMES)), dtype=np.float64)
    panel[:, 4] = np.arange(8)
    standardized, mean, std = _standardize_panel(panel)
    assert np.all(standardized[:, 0] == 0.0)
    assert std[0] == 0.0
    assert np.isclose(np.mean(standardized[:, 4]), 0.0)
    assert np.isclose(np.std(standardized[:, 4], ddof=1), 1.0)
    assert mean[4] == 3.5


def test_development_gate_requires_threshold_and_control_margin() -> None:
    prediction, control = _classify_development(
        {"primary": 0.12, "key_rotated": 0.31, "clause_rotated": 0.27},
        [0.08, 0.18],
        maximum_geometric=0.25,
        maximum_each=0.5,
    )
    assert prediction and control
    prediction, control = _classify_development(
        {"primary": 0.12, "key_rotated": 0.08, "clause_rotated": 0.27},
        [0.08, 0.18],
        maximum_geometric=0.25,
        maximum_each=0.5,
    )
    assert prediction and not control
