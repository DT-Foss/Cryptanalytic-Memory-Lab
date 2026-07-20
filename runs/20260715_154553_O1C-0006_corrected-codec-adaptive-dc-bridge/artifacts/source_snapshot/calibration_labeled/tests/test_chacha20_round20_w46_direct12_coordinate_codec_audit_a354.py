from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w46_direct12_coordinate_codec_audit_a354.py"
)
SPEC = importlib.util.spec_from_file_location("a354_coordinate_codec", RUNNER)
assert SPEC is not None and SPEC.loader is not None
A354 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A354
SPEC.loader.exec_module(A354)


def test_confirmed_candidate_separates_measured_and_metal_cells() -> None:
    candidate = 0x1DF3BAE9E3A6
    assert A354.a348_measured_cell(candidate) == 0x77C
    assert A354.metal_group_cell(candidate) == 0xBAE
    assert A354.a348_measured_cell(candidate) != A354.metal_group_cell(candidate)


def test_corrected_reader_mapping_targets_coordinates_24_through_31() -> None:
    source = list(range(1, 47))
    corrected = A354.corrected_synthetic_mapping(source)
    assert corrected == [*source[:12], *source[24:32]]
    assert corrected != [*source[:12], *source[38:46]]


def test_A348_source_coordinates_are_derived_from_frozen_runner() -> None:
    assert A354._literal_coordinates_from_function(  # noqa: SLF001
        A354.A348_RUNNER, "low4_unit_literals"
    ) == (37, 36, 35, 34)


def test_A348_orders_reproduce_both_rank_interpretations() -> None:
    result = json.loads(A354.A348_RESULT.read_bytes())
    expected_actual = {
        "A340_selected8_global_raw": 1475,
        "A340_selected8_slice_z": 1589,
        "A341_selected_single_global_raw": 1673,
        "A341_selected_single_slice_z": 1652,
        "A342_selected_pair_global_raw": 561,
        "A342_selected_pair_slice_z": 567,
        "A342_selected_triple_global_raw": 758,
        "A342_selected_triple_slice_z": 808,
    }
    for name, order in result["orders"].items():
        assert A354.rank_metrics(order, 0xBAE)["rank_one_based"] == result["rank_panel"][name][
            "rank_one_based"
        ]
        assert A354.rank_metrics(order, 0x77C)["rank_one_based"] == expected_actual[name]


def test_result_and_authentic_causal_if_present() -> None:
    if not A354.RESULT.exists():
        return
    verified = A354.verify()
    assert verified["explicit_triplets"] == 3
    assert verified["all_triplets"] == 4
    assert verified["next_gap"]["expected_object_type"] == (
        "complete_corrected_W46_direct12_measurement"
    )
