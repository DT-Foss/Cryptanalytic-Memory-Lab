from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c81_bound_differential_analysis as differential


ROOT = Path(__file__).resolve().parents[1]
PERSISTED_JSON = ROOT / "research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.json"
PERSISTED_MARKDOWN = ROOT / "research/O1C0081_BOUND_DIFFERENTIAL_CENSUS_20260720.md"


@pytest.fixture(scope="module")
def evidence() -> differential.ReaderEvidence:
    return differential.load_sealed_o1c80_reader(ROOT)


@pytest.fixture(scope="module")
def report() -> dict[str, object]:
    return differential.generate_bound_differential_census(ROOT)


def _mapping(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


def _synthetic_event(
    call: int, coordinate_index: int, variable: int, value: float
) -> differential.ProbeObservation:
    return differential.ProbeObservation(
        call=call,
        coordinate_index=coordinate_index,
        parent_assignment_sha256=f"{call:064x}",
        parent_level=call - 1,
        probe=(call - 1) * 4 + coordinate_index + 1,
        upper_zero=value,
        upper_one=0.0,
        variable=variable,
    )


def test_synthetic_parent_centering_removes_common_mode() -> None:
    events = tuple(
        _synthetic_event(call, index, index + 1, common + residual)
        for call, common in ((1, 10.0), (2, 20.0))
        for index, residual in enumerate((-2.0, -1.0, 1.0, 2.0))
    )
    result = differential.analyze_probe_events(events)
    diagnostics = _mapping(result["common_mode_diagnostics"])
    raw = _mapping(diagnostics["raw_differential"])
    centered = _mapping(diagnostics["centered_differential"])
    medians = _mapping(diagnostics["parent_median_common_mode"])
    assert raw["mean"] == 15.0
    assert raw["positive_fraction"] == 1.0
    assert centered["mean"] == 0.0
    assert centered["positive_fraction"] == 0.5
    assert medians["minimum"] == 10.0
    assert medians["maximum"] == 20.0

    coordinates = result["coordinate_accumulators"]
    assert isinstance(coordinates, list)
    first = _mapping(coordinates[0])
    fourth = _mapping(coordinates[3])
    unseen = _mapping(coordinates[4])
    assert first["centered_mean"] == -2.0
    assert fourth["centered_mean"] == 2.0
    assert first["centered_directional_stability"] == 1.0
    assert unseen["count"] == 0
    assert unseen["query_priority_score"] is None


def test_sealed_reader_rejects_digest_tamper_and_symlink(tmp_path: Path) -> None:
    source = ROOT / differential.SEALED_READER.relative
    payload = bytearray(source.read_bytes())
    payload[len(payload) // 2] ^= 1
    tampered = tmp_path / "tampered.json.gz"
    tampered.write_bytes(payload)
    tampered_spec = dataclasses.replace(
        differential.SEALED_READER, relative=Path(tampered.name)
    )
    with pytest.raises(
        differential.O1C81BoundDifferentialError, match="gzip digest differs"
    ):
        differential._read_sealed_reader_bytes(tmp_path, tampered_spec)

    linked = tmp_path / "linked.json.gz"
    try:
        linked.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable")
    linked_spec = dataclasses.replace(
        differential.SEALED_READER, relative=Path(linked.name)
    )
    with pytest.raises(
        differential.O1C81BoundDifferentialError,
        match="not a sealed regular file",
    ):
        differential._read_sealed_reader_bytes(tmp_path, linked_spec)


def test_recorded_prefix_is_exact_and_full_trace_is_metadata_only(
    evidence: differential.ReaderEvidence, report: dict[str, object]
) -> None:
    assert len(evidence.events) == 16_384
    assert evidence.events[0].probe == 1
    assert evidence.events[-1].probe == 16_384
    assert evidence.events[0].call == 1
    assert evidence.events[-1].call == 74

    boundary = _mapping(report["population_boundary"])
    recorded = _mapping(boundary["recorded_prefix"])
    omitted = _mapping(boundary["omitted_suffix"])
    full_trace = _mapping(boundary["full_trace"])
    witness = _mapping(boundary["separate_global_minimum_witness"])
    assert recorded["event_count"] == 16_384
    assert recorded["probe_range"] == [1, 16_384]
    assert recorded["missing_key_variables"] == [241]
    assert omitted == {
        "event_count": 269_341,
        "first_probe": 16_385,
        "values_inferred": False,
    }
    assert full_trace["event_count"] == 285_725
    assert full_trace["per_event_values_available"] is False
    assert full_trace["sha256"] == differential.FULL_TRACE_SHA256
    assert witness["probe"] == 37_567
    assert witness["excluded_from_accumulators"] is True


def test_actual_common_mode_is_large_and_centering_is_balanced(
    report: dict[str, object],
) -> None:
    summary = _mapping(report["summary"])
    assert summary["raw_minimum"] == -3.721211809959186
    assert summary["raw_maximum"] == 1.8624800468152216
    assert summary["raw_mean"] == pytest.approx(0.435558404488658)
    assert summary["raw_positive_count"] == 15_601
    assert summary["raw_positive_fraction"] == 0.95220947265625
    assert summary["centered_mean"] == pytest.approx(-0.006465018506553668)
    assert summary["centered_positive_fraction"] == 0.498779296875

    analysis = _mapping(report["recorded_prefix_analysis"])
    diagnostics = _mapping(analysis["common_mode_diagnostics"])
    parent_mode = _mapping(diagnostics["parent_median_common_mode"])
    centered = _mapping(diagnostics["centered_differential"])
    assert parent_mode["positive_count"] == 74
    assert parent_mode["negative_count"] == 0
    assert centered["positive_count"] == 8_172
    assert centered["negative_count"] == 8_172
    assert centered["zero_count"] == 40
    assert diagnostics["median_centered_energy_reduction_fraction"] == (
        pytest.approx(0.5507450368488783)
    )


def test_priority_is_not_belief_and_has_target_free_structure(
    report: dict[str, object],
) -> None:
    analysis = _mapping(report["recorded_prefix_analysis"])
    priority = _mapping(analysis["query_priority"])
    assert priority["belief_orientation_authorized"] is False
    assert priority["priority_only_not_bit_polarity"] is True
    assert priority["minimum_parent_observations"] == 37
    top = priority["top_coordinates"]
    assert isinstance(top, list)
    first = _mapping(top[0])
    assert first["variable"] == 185
    assert first["count"] == 73
    assert first["centered_directional_stability"] == 1.0
    assert first["query_priority_score"] == pytest.approx(91.75281760473375)

    coordinates = analysis["coordinate_accumulators"]
    assert isinstance(coordinates, list)
    sparse = _mapping(coordinates[157])
    assert sparse["variable"] == 158
    assert sparse["count"] == 10
    assert sparse["query_priority_score"] == pytest.approx(48.780649516472025)
    assert all(_mapping(row)["variable"] != 158 for row in top)

    conclusion = _mapping(report["conclusion"])
    assert conclusion["key_bit_claims"] == 0
    assert conclusion["full_key_recovery"] is False
    assert conclusion["belief_orientation"] == (
        "WITHHELD_NO_TARGET_FREE_POLARITY_CALIBRATION"
    )


def test_deterministic_controls_preserve_values_and_break_label_peak(
    report: dict[str, object],
) -> None:
    analysis = _mapping(report["recorded_prefix_analysis"])
    controls = _mapping(analysis["target_free_controls"])
    permutation = _mapping(controls["within_parent_coordinate_permutation"])
    temporal = _mapping(controls["temporal_parent_split"])
    assert permutation["global_value_multiset_preserved"] is True
    assert permutation["coordinate_association_only_is_permuted"] is True
    assert permutation["permutation_count"] == 1
    assert permutation["single_control_has_no_p_value"] is True
    assert permutation["observed_max_priority"] == pytest.approx(91.75281760473375)
    assert permutation["permuted_max_priority"] == pytest.approx(3.0906512561469452)
    assert permutation["priority_correlation"] == pytest.approx(-0.028412595664496245)
    assert permutation["top16_overlap_variables"] == [83, 196, 212]

    assert temporal["mean_correlation"] == pytest.approx(0.8538130771826461)
    assert temporal["sign_agreement_fraction"] == pytest.approx(0.8110599078341014)
    assert temporal["top16_overlap_variables"] == [33, 129, 170, 185]


def test_state_accounting_is_fixed_o256(report: dict[str, object]) -> None:
    accounting = _mapping(report["state_accounting"])
    assert accounting["asymptotic_state"] == "O(256)"
    assert accounting["coordinate_capacity"] == 256
    assert accounting["packed_bytes_per_coordinate"] == 96
    assert accounting["coordinate_state_bytes"] == 24_576
    assert accounting["parent_scratch_bytes"] == 4_096
    assert accounting["live_packed_state_bytes"] == 28_672
    assert accounting["input_artifact_materialization_excluded"] is True


def test_report_is_target_free_and_persisted_outputs_are_fresh(
    report: dict[str, object],
) -> None:
    scope = _mapping(report["scope"])
    assert scope == {
        "fresh_targets": 0,
        "mps_or_gpu_calls": 0,
        "native_solver_calls": 0,
        "public_verification_calls": 0,
        "refits": 0,
        "reveal_calls": 0,
        "science_calls": 0,
        "truth_key_bytes_read": False,
        "unrecorded_event_values_inferred": False,
    }
    json_payload = differential.serialize_bound_differential_census(report)
    markdown_payload = differential.render_bound_differential_markdown(report)
    assert json_payload == differential.serialize_bound_differential_census(report)
    assert PERSISTED_JSON.read_bytes() == json_payload
    assert PERSISTED_MARKDOWN.read_bytes() == markdown_payload
    markdown = markdown_payload.decode("utf-8")
    assert "query-priority mechanism candidate" in markdown
    assert "at least `37` retained-parent observations" in markdown
    assert "not inferred" in markdown
    assert "28,672" not in markdown
    assert "`28672` bytes" in markdown
