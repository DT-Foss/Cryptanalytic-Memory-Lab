from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT / "research/experiments/chacha20_round20_w46_corrected_group_a345_transfer_a356.py"
)
SPEC = importlib.util.spec_from_file_location("a356_corrected_transfer", RUNNER)
assert SPEC is not None and SPEC.loader is not None
A356 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A356
SPEC.loader.exec_module(A356)


def test_design_was_frozen_before_A355_and_A345_results() -> None:
    design = A356.load_design()
    boundary = design["information_boundary"]
    assert boundary["A355_result_available_at_design_freeze"] is False
    assert boundary["A345_result_available_at_design_freeze"] is False
    assert boundary["target_labels_from_A345_used"] == 0
    assert boundary["reader_refits_on_A345"] == 0


def test_A356_uses_the_corrected_word0_prefix_coordinates() -> None:
    design = A356.load_design()["measurement_contract"]
    assert design["low4_fixed_unit_coordinates"] == [23, 22, 21, 20]
    assert design["high8_assumption_coordinates"] == [31, 30, 29, 28, 27, 26, 25, 24]
    assert design["synthetic_reader_mapping_source_indices"] == [
        *range(12),
        *range(24, 32),
    ]


def test_A349_source_mapping_is_reused_with_the_corrected_projection() -> None:
    preflight = json.loads(A356.A349_PREFLIGHT.read_bytes())
    source = preflight["source_one_literals_bit0_upward"]
    corrected = A356.A355.corrected_synthetic_mapping(source)
    assert corrected == [*source[:12], *source[24:32]]
    assert corrected != preflight["synthetic_reader_mapping"]


def test_A356_slice_renderer_fixes_bits20_through23() -> None:
    source = list(range(1, A356.WIDTH + 1))
    rendered = A356.A355.render_slice_cnf(
        b"p cnf 100 1\n1 -2 0\n", low4=0b1010, source_mapping=source
    )
    assert rendered.splitlines()[0] == b"p cnf 100 5"
    assert rendered.splitlines()[-4:] == [b"24 0", b"-23 0", b"22 0", b"-21 0"]


def test_measurement_and_order_contracts_if_present() -> None:
    if A356.MEASUREMENT.exists():
        measurement = json.loads(A356.MEASUREMENT.read_bytes())
        summary = measurement["measurement_summary"]
        assert summary["complete_direct12_cells"] == 4096
        assert summary["A355_selected_view_read"] is False
        assert summary["target_labels_used"] == 0
    if A356.ORDER.exists():
        order = json.loads(A356.ORDER.read_bytes())
        assert len(order["selected_order"]) == 4096
        assert set(order["selected_order"]) == set(range(4096))
        assert order["A345_result_available_at_order_freeze"] is False
        assert order["target_labels_used"] == 0
        assert order["reader_refits"] == 0
        assert order["causal"]["explicit_triplets"] == 3
