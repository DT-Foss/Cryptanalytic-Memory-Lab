from __future__ import annotations

import copy
import dataclasses
import itertools
import os
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.o1c80_archived_bound_census as census
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v7 import (
    build_compatibility_grouping,
    grouped_joint_score_cache,
)


ROOT = Path(__file__).resolve().parents[1]
PERSISTED = ROOT / "research/O1C0080_ARCHIVED_BOUND_CENSUS_20260720.json"


@pytest.fixture(scope="module")
def public_inputs() -> census.PublicBoundInputs:
    return census.load_public_bound_inputs(ROOT)


@pytest.fixture(scope="module")
def report() -> dict[str, object]:
    return census.generate_archived_bound_census(ROOT)


def _mapping(value: object) -> dict[str, Any]:
    assert isinstance(value, dict)
    return value


def _synthetic_inputs() -> census.PublicBoundInputs:
    field = CriticalityPotentialField(
        offset=0.125,
        source_sha256="45" * 32,
        factors=tuple(
            sorted(
                (
                    CriticalityPotentialFactor(
                        (1, 2), (0.0, 1.25, -0.5, 2.0)
                    ),
                    CriticalityPotentialFactor(
                        (2, 3), (0.75, -0.25, 1.5, 0.5)
                    ),
                    CriticalityPotentialFactor((4,), (-1.0, 0.25)),
                )
            )
        ),
    )
    grouping = build_compatibility_grouping(field)
    incidents: dict[int, list[int]] = {
        variable: [] for variable in field.observed_variables
    }
    for group_index, group in enumerate(grouping.groups):
        for variable in group.variables:
            incidents[variable].append(group_index)
    return census.PublicBoundInputs(
        field=field,
        grouping=grouping,
        incidents={
            variable: tuple(indices) for variable, indices in incidents.items()
        },
    )


def test_incident_cache_matches_full_scan_exhaustively_on_finite_fixture() -> None:
    inputs = _synthetic_inputs()
    variables = inputs.field.observed_variables
    checked = 0
    for spins in itertools.product((None, -1, 1), repeat=len(variables)):
        assignments = {
            variable: spin
            for variable, spin in zip(variables, spins, strict=True)
            if spin is not None
        }
        cache = grouped_joint_score_cache(
            inputs.field, assignments, grouping=inputs.grouping
        )
        for variable in variables:
            if variable in assignments:
                continue
            result = census.exact_one_bit_child_bounds(
                inputs,
                assignments,
                cache,
                variable,
                verify_full_scan=True,
            )
            assert result.incident_group_count >= 1
            assert result.incident_row_evaluations >= 2
            checked += 2
    assert checked == 216


def test_one_bit_reader_rejects_tampered_parent_cache() -> None:
    inputs = _synthetic_inputs()
    assignments = {2: 1}
    cache = bytearray(
        grouped_joint_score_cache(
            inputs.field, assignments, grouping=inputs.grouping
        )
    )
    cache[-1] ^= 1
    with pytest.raises(census.O1C80ArchivedBoundCensusError, match="cache differs"):
        census.exact_one_bit_child_bounds(
            inputs, assignments, bytes(cache), 1, verify_full_scan=True
        )


def test_all_sealed_snapshot_specs_construct_and_are_distinct() -> None:
    assert len(census.ARCHIVED_SNAPSHOT_SPECS) == 19
    assert len({spec.label for spec in census.ARCHIVED_SNAPSHOT_SPECS}) == 19
    assert len({spec.relative for spec in census.ARCHIVED_SNAPSHOT_SPECS}) == 19
    assert sum(spec.compressed for spec in census.ARCHIVED_SNAPSHOT_SPECS) == 9


def test_sealed_reader_rejects_byte_tamper_and_symlink(tmp_path: Path) -> None:
    source_spec = census.ARCHIVED_SNAPSHOT_SPECS[0]
    source_payload = (ROOT / source_spec.relative).read_bytes()
    tampered = bytearray(source_payload)
    tampered[-1] ^= 1
    relative = Path("tampered.json")
    (tmp_path / relative).write_bytes(tampered)
    spec = dataclasses.replace(source_spec, relative=relative)
    with pytest.raises(census.O1C80ArchivedBoundCensusError, match="digest differs"):
        census._read_json_payload(tmp_path, spec)

    target = tmp_path / "target.json"
    target.write_bytes(source_payload)
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    linked_spec = dataclasses.replace(source_spec, relative=Path("linked.json"))
    with pytest.raises(
        census.O1C80ArchivedBoundCensusError, match="sealed regular file"
    ):
        census._read_json_payload(tmp_path, linked_spec)

    gzip_spec = next(
        spec for spec in census.ARCHIVED_SNAPSHOT_SPECS if spec.compressed
    )
    gzip_payload = bytearray((ROOT / gzip_spec.relative).read_bytes())
    gzip_payload[len(gzip_payload) // 2] ^= 1
    gzip_relative = Path("tampered.json.gz")
    (tmp_path / gzip_relative).write_bytes(gzip_payload)
    tampered_gzip_spec = dataclasses.replace(gzip_spec, relative=gzip_relative)
    with pytest.raises(census.O1C80ArchivedBoundCensusError, match="digest differs"):
        census._read_json_payload(tmp_path, tampered_gzip_spec)

def test_terminal_state_rejects_cache_and_hash_tamper(
    public_inputs: census.PublicBoundInputs,
) -> None:
    spec = census.ARCHIVED_SNAPSHOT_SPECS[0]
    original = census._read_json_payload(ROOT, spec)

    cache_tamper = copy.deepcopy(original)
    cache_state = _mapping(_mapping(cache_tamper["sieve"])["state"])
    cache_hex = cache_state["group_cache_hex"]
    assert isinstance(cache_hex, str)
    cache_state["group_cache_hex"] = cache_hex[:-2] + (
        "00" if cache_hex[-2:] != "00" else "01"
    )
    with pytest.raises(
        census.O1C80ArchivedBoundCensusError, match="terminal state differs"
    ):
        census._validate_snapshot_document(cache_tamper, spec, public_inputs)

    hash_tamper = copy.deepcopy(original)
    hash_state = _mapping(_mapping(hash_tamper["sieve"])["state"])
    hash_state["assignment_sha256"] = "00" * 32
    with pytest.raises(
        census.O1C80ArchivedBoundCensusError, match="terminal state differs"
    ):
        census._validate_snapshot_document(hash_tamper, spec, public_inputs)


def test_terminal_census_is_exact_deduplicated_and_near_margin(
    report: dict[str, object],
) -> None:
    terminal = _mapping(report["terminal_exact_census"])
    assert terminal["snapshot_count"] == 19
    assert terminal["parent_count"] == 13
    assert terminal["pair_count"] == 1_580
    assert terminal["child_bound_count"] == 3_160
    assert terminal["crossing_pair_count"] == 0
    assert terminal["both_children_strict_prunable_pair_count"] == 0
    equivalence = _mapping(terminal["incident_cache_full_scan_equivalence"])
    assert equivalence == {
        "checked_child_bound_count": 24,
        "checked_parent_bound_count": 13,
        "f64le_mismatch_count": 0,
        "scope": (
            "every-deduplicated terminal parent and both children of each "
            "parent's deterministic minimum-child pair; exhaustive child "
            "equivalence is covered by the finite fixture test"
        ),
    }
    closest = _mapping(terminal["closest_child"])
    assert closest["parent_identity"] == (
        "013c0b079127aead78625330b4932e71c0efa4fdc8cf1758f1fd8605f29239d2"
    )
    assert closest["variable"] == 105
    assert closest["parent_upper_bound"] == 15.531057646608152
    assert closest["u0"] == 15.224559961355952
    assert closest["u1"] == 14.842606678748025
    assert closest["minimum_child_margin_above_threshold"] == (
        0.2364278808550626
    )


def test_visible_events_are_separate_inexact_lower_envelope(
    report: dict[str, object],
) -> None:
    visible = _mapping(report["visible_event_lower_envelope"])
    assert visible["marker_count"] == 549
    assert visible["pair_count"] == 81_632
    assert visible["crossing_pair_count"] == 0
    assert visible["exact_parent_population"] == 0
    assert visible["callback_parent_state_exact"] is False
    zero = _mapping(visible["zero_return_reconstruction"])
    assert zero == {
        "assignment_callback_count": 1_227,
        "callback_count": 1_587,
        "decision_levels_without_assignment_callback_at_least": 360,
        "exact_zero_return_parent_count": 0,
        "nonzero_marker_count": 549,
        "zero_return_count": 1_038,
    }
    release = _mapping(visible["release_evidence"])
    assert release["native_backtrack_count"] == 138
    assert release["serialized_release_batch_count"] == 8
    assert release["missing_backtrack_target_count_at_least"] == 130
    minimum = _mapping(visible["closest_lower_envelope_child"])
    assert minimum["callback"] == 667
    assert minimum["reported_level"] == 253
    assert minimum["variable"] == 158
    assert minimum["parent_upper_bound"] == 32.808564326869394
    assert minimum["u0"] == 29.42639570750978
    assert minimum["u1"] == 31.359697343608754
    breadcrumb = _mapping(visible["maximum_drop_breadcrumb"])
    assert breadcrumb["certifies_crossing"] is False
    drop_row = _mapping(breadcrumb["row"])
    assert drop_row["callback"] == 541
    assert drop_row["variable"] == 188
    assert drop_row["parent_to_minimum_child_drop"] == 4.335772097681144
    monotonic = _mapping(visible["monotonic_no_crossing_scope"])
    assert monotonic["certificate"] is True
    assert monotonic["lower_envelope_minimum_exceeds_threshold"] is True


def test_persisted_report_is_fresh_canonical_and_zero_call(
    report: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_: object, **__: object) -> int:
        raise AssertionError("archived census attempted an external call")

    monkeypatch.setattr(os, "system", forbidden)
    payload = census.serialize_archived_bound_census(report)
    assert payload == census.serialize_archived_bound_census(report)
    assert PERSISTED.read_bytes() == payload
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
    }
    resource_reporting = _mapping(report["resource_reporting"])
    assert resource_reporting["live_runtime_or_rss_in_deterministic_json"] is False
