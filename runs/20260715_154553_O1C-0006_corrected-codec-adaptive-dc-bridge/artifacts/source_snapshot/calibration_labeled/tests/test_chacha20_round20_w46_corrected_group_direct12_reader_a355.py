from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w46_corrected_group_direct12_reader_a355.py"
)
SPEC = importlib.util.spec_from_file_location("a355_corrected_group", RUNNER)
assert SPEC is not None and SPEC.loader is not None
A355 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = A355
SPEC.loader.exec_module(A355)


def test_design_binds_exact_metal_group_coordinates() -> None:
    design = A355.load_design()
    measurement = design["measurement_contract"]
    assert measurement["low4_fixed_unit_coordinates"] == [23, 22, 21, 20]
    assert measurement["high8_assumption_coordinates"] == [31, 30, 29, 28, 27, 26, 25, 24]
    assert measurement["synthetic_reader_mapping_source_indices"] == [
        *range(12),
        *range(24, 32),
    ]


def test_low4_units_encode_assignment_bits20_through23() -> None:
    source = list(range(1, A355.WIDTH + 1))
    assert A355.low4_unit_literals(0b0000, source) == [-24, -23, -22, -21]
    assert A355.low4_unit_literals(0b1010, source) == [24, -23, 22, -21]
    assert A355.low4_unit_literals(0b1111, source) == [24, 23, 22, 21]


def test_synthetic_mapping_encodes_assignment_bits24_through31() -> None:
    source = list(range(1, A355.WIDTH + 1))
    assert A355.corrected_synthetic_mapping(source) == [*source[:12], *source[24:32]]


def test_rendered_slice_adds_only_the_four_correct_units() -> None:
    source = list(range(1, A355.WIDTH + 1))
    base = b"p cnf 100 1\n1 -2 0\n"
    rendered = A355.render_slice_cnf(base, low4=0b0101, source_mapping=source)
    assert rendered.splitlines()[0] == b"p cnf 100 5"
    assert rendered.splitlines()[-4:] == [b"-24 0", b"23 0", b"-22 0", b"21 0"]


def test_A354_mapping_commitment_matches_A355_preflight_mapping() -> None:
    preflight = json.loads(A355.A340_PREFLIGHT.read_bytes())
    correction = json.loads(A355.A354_RESULT.read_bytes())["corrected_successor_contract"]
    mapping = A355.corrected_synthetic_mapping(preflight["source_one_literals_bit0_upward"])
    assert A355.canonical_sha256(mapping) == correction["synthetic_reader_mapping_sha256"]


def test_result_contract_if_complete() -> None:
    if not A355.RESULT.exists():
        return
    result = json.loads(A355.RESULT.read_bytes())
    assert result["coordinate_contract"]["low4_fixed_unit_coordinates_high_to_low"] == [
        23,
        22,
        21,
        20,
    ]
    assert result["measurement_summary"]["complete_direct12_cells"] == 4096
    assert result["measurement_summary"]["target_labels_used_during_measurement"] == 0
    assert result["confirmed_prefix12_hex"] == "bae"
    assert result["causal"]["explicit_triplets"] == 3
    assert result["causal"]["materialized_inferred_triplets"] == 1
