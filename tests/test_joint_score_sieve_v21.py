from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v21 as sieve_v21
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError

import test_joint_score_sieve_v20 as v20_fixtures


TAU = 2.0
CANDIDATES = (11, 22)
ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v18.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


@pytest.fixture(scope="module")
def native_v18(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not (
        shutil.which("c++")
        and NATIVE_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    ):
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    executable = tmp_path_factory.mktemp("o1c80-v21-native") / "native-v18"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C80_PUBLIC_FIXTURE",
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _sha(byte: int) -> str:
    return f"{byte:02x}" * 32


def _f64(value: float) -> str:
    return struct.pack("<d", value).hex()


def _clause_sha(literals: tuple[int, ...]) -> str:
    payload = struct.pack("<I", len(literals)) + b"".join(
        struct.pack("<i", literal) for literal in literals
    )
    return hashlib.sha256(payload).hexdigest()


def _state() -> dict[str, str]:
    return {
        "assignment_sha256": _sha(1),
        "trail_sha256": _sha(2),
        "pending_sha256": _sha(3),
        "group_cache_sha256": _sha(4),
        "trace_sha256": _sha(5),
        "counters_sha256": _sha(6),
    }


def _ownership_event(
    sequence: int,
    kind: str,
    *,
    observed: int = 0,
    level: int,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "kind": kind,
        "token": 1,
        "callback": 7,
        "origin": "BOUND_LOSING_CHILD",
        "row": 0,
        "literal": -11,
        "level": level,
        "observed_literal": observed,
    }


def _payload() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    state = _state()
    probe = {
        "call": 7,
        "probe": 1,
        "coordinate_index": 0,
        "variable": 11,
        "parent_level": 0,
        "parent_assignment_sha256": state["assignment_sha256"],
        "upper_zero": 1.0,
        "upper_zero_f64le_hex": _f64(1.0),
        "upper_one": 3.0,
        "upper_one_f64le_hex": _f64(3.0),
        "threshold": TAU,
        "threshold_f64le_hex": _f64(TAU),
        "selection_class": "ZERO_PRUNABLE",
        "losing_bit": 0,
        "losing_spin": -1,
        "losing_literal": -11,
        "proposal_token": 1,
        "state_before": copy.deepcopy(state),
        "state_after": copy.deepcopy(state),
        "state_unchanged": True,
    }
    no_good = (11,)
    intervention = {
        "token": 1,
        "call": 7,
        "probe": 1,
        "coordinate_index": 0,
        "variable": 11,
        "parent_level": 0,
        "origin": "BOUND_LOSING_CHILD",
        "selection_class": "ZERO_PRUNABLE",
        "upper_zero": 1.0,
        "upper_zero_f64le_hex": _f64(1.0),
        "upper_one": 3.0,
        "upper_one_f64le_hex": _f64(3.0),
        "threshold": TAU,
        "threshold_f64le_hex": _f64(TAU),
        "losing_bit": 0,
        "losing_spin": -1,
        "losing_literal": -11,
        "parent_assignment_sha256": state["assignment_sha256"],
        "state_before": copy.deepcopy(state),
        "state_after": copy.deepcopy(state),
        "state_unchanged": True,
        "level_bound": 1,
        "matching_assignment_observed": True,
        "observed_literal": -11,
        "v6_threshold_prunes_before": 4,
        "v6_threshold_prunes_after": 5,
        "v6_trail_threshold_prunes_before": 4,
        "v6_trail_threshold_prunes_after": 5,
        "v6_external_clauses_queued_before": 4,
        "v6_external_clauses_queued_after": 5,
        "v6_pending_clause_count_before": 0,
        "v6_pending_clause_count_after": 1,
        "v6_pending_clause_sha256_before": None,
        "v6_pending_clause_sha256_after": _clause_sha(no_good),
        "v6_trace_sha256_before": _sha(9),
        "v6_trace_sha256_after": _sha(10),
        "no_good_literals": list(no_good),
        "no_good_clause_sha256": _clause_sha(no_good),
        "fully_emitted": True,
        "fully_emitted_index": 0,
        "realized_prune": True,
        "released": True,
        "unobserved_release": False,
    }
    candidate_payload = b"".join(struct.pack("<i", item) for item in CANDIDATES)
    trace_payload = b"".join(
        (
            struct.pack("<Q", 7),
            struct.pack("<Q", 1),
            struct.pack("<I", 0),
            struct.pack("<I", 0),
            struct.pack("<i", 11),
            struct.pack("<d", 1.0),
            struct.pack("<d", 3.0),
            struct.pack("<d", TAU),
            bytes((1,)),
            struct.pack("<i", -11),
        )
    )
    witness = {
        name: copy.deepcopy(value)
        for name, value in probe.items()
        if name != "proposal_token"
    }
    reader = {
        "schema": "o1-256-exact-one-bit-child-bound-reader-v1",
        "operator": sieve_v21.ONE_BIT_BOUND_OPERATOR,
        "runtime_parent_schema": sieve_v21.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
        "candidate_order_rule": sieve_v21.ONE_BIT_CANDIDATE_ORDER_RULE,
        "bound_rule": sieve_v21.ONE_BIT_BOUND_RULE,
        "decision_rule": sieve_v21.ONE_BIT_DECISION_RULE,
        "realized_prune_rule": sieve_v21.ONE_BIT_REALIZED_PRUNE_RULE,
        "key_variable_count": 256,
        "threshold": TAU,
        "threshold_f64le_hex": _f64(TAU),
        "candidate_count": 2,
        "ranked_candidate_count": 2,
        "omitted_candidate_count": 0,
        "parent_scans": 7,
        "probe_count": 1,
        "child_bound_evaluations": 2,
        "recorded_probe_event_count": 1,
        "omitted_probe_event_count": 0,
        "probe_trace_encoding": sieve_v21.PROBE_TRACE_ENCODING,
        "probe_trace_count": 1,
        "probe_trace_bytes": len(trace_payload),
        "probe_trace_sha256": hashlib.sha256(trace_payload).hexdigest(),
        "proposals": 1,
        "level_bindings": 1,
        "matching_assignments_observed": 1,
        "realized_prunes": 1,
        "fully_emitted_prunes": 1,
        "releases": 1,
        "live_tokens": 0,
        "unobserved_releases": 0,
        "class_counts": {
            "NEITHER_PRUNABLE": 0,
            "ZERO_PRUNABLE": 1,
            "ONE_PRUNABLE": 0,
            "BOTH_PRUNABLE": 0,
        },
        "minimum_child_upper": 1.0,
        "minimum_child_upper_f64le_hex": _f64(1.0),
        "minimum_child_margin": -1.0,
        "minimum_child_variable": 11,
        "minimum_upper_zero": 1.0,
        "minimum_upper_zero_f64le_hex": _f64(1.0),
        "minimum_upper_one": 3.0,
        "minimum_upper_one_f64le_hex": _f64(3.0),
        "minimum_witness_tie_rule": sieve_v21.MINIMUM_WITNESS_TIE_RULE,
        "minimum_witness": witness,
        "candidate_order_encoding": sieve_v21.SIGNED_I32_SEQUENCE_ENCODING,
        "candidate_order_count": 2,
        "candidate_order_bytes": len(candidate_payload),
        "candidate_order_hex": candidate_payload.hex(),
        "candidate_order_sha256": hashlib.sha256(candidate_payload).hexdigest(),
        "probe_events": [probe],
        "interventions": [intervention],
    }
    events = [
        _ownership_event(1, "PROPOSED", level=0),
        _ownership_event(2, "LEVEL_BOUND", level=1),
        _ownership_event(3, "CONFIRMED", observed=-11, level=1),
        _ownership_event(4, "RELEASED", level=0),
    ]
    ownership = {
        "schema": "o1-256-central-decision-ownership-v2",
        "lifecycle": sieve_v21.OWNERSHIP_LIFECYCLE,
        "eligibility_rule": sieve_v21.OWNERSHIP_ELIGIBILITY_RULE,
        "assignment_notification_rule": sieve_v21.OWNERSHIP_ASSIGNMENT_RULE,
        "current_level": 0,
        "proposals": 1,
        "level_bound_interventions": 1,
        "confirmed_interventions": 1,
        "releases": 1,
        "confirmed_releases": 1,
        "level_bound_unobserved_releases": 0,
        "opposite_assignments": 0,
        "foreign_assignments": 0,
        "renotifications": 0,
        "live_tokens": 0,
        "maximum_live_tokens": 1,
        "event_count": len(events),
        "recorded_event_count": len(events),
        "omitted_event_count": 0,
        "proposal_activated": True,
        "level_bound_activated": True,
        "confirmed_activated": True,
        "events": events,
        "origin_counts": {
            origin: {
                "proposals": int(origin == sieve_v21.BOUND_ORIGIN),
                "level_bound": int(origin == sieve_v21.BOUND_ORIGIN),
                "confirmed": int(origin == sieve_v21.BOUND_ORIGIN),
                "releases": int(origin == sieve_v21.BOUND_ORIGIN),
            }
            for origin in sieve_v21.ORIGINS
        },
    }
    sieve = {
        "threshold_prunes": 5,
        "trail_threshold_prunes": 5,
        "external_clauses_queued": 5,
    }
    vault = {
        "fully_emitted_clause_count": 1,
        "fully_emitted_clauses": [
            {
                "index": 0,
                "literals": list(no_good),
                "clause_sha256": _clause_sha(no_good),
            }
        ],
    }
    return reader, ownership, sieve, vault


def _validate(
    reader: object, ownership: object, sieve: object, vault: object
) -> sieve_v21.OneBitBoundValidation:
    return sieve_v21.validate_one_bit_bound_reader(
        reader,
        decision_ownership=ownership,
        sieve=sieve,
        vault=vault,
        threshold=TAU,
        candidate_order=CANDIDATES,
        ranked_candidate_count=2,
    )


def _refresh_probe_aggregates(reader: dict[str, Any]) -> None:
    probe = reader["probe_events"][0]
    reader["minimum_witness"] = {
        name: copy.deepcopy(value)
        for name, value in probe.items()
        if name != "proposal_token"
    }
    zero = float(probe["upper_zero"])
    one = float(probe["upper_one"])
    reader["minimum_child_upper"] = min(zero, one)
    reader["minimum_child_upper_f64le_hex"] = _f64(min(zero, one))
    reader["minimum_child_margin"] = min(zero, one) - TAU
    reader["minimum_child_variable"] = probe["variable"]
    reader["minimum_upper_zero"] = zero
    reader["minimum_upper_zero_f64le_hex"] = _f64(zero)
    reader["minimum_upper_one"] = one
    reader["minimum_upper_one_f64le_hex"] = _f64(one)
    reader["class_counts"] = {name: 0 for name in sieve_v21.SELECTION_CLASSES}
    reader["class_counts"][probe["selection_class"]] = 1
    class_code = {
        "NEITHER_PRUNABLE": 0,
        "ZERO_PRUNABLE": 1,
        "ONE_PRUNABLE": 2,
        "BOTH_PRUNABLE": 3,
    }[probe["selection_class"]]
    trace = b"".join(
        (
            struct.pack("<Q", probe["call"]),
            struct.pack("<Q", probe["probe"]),
            struct.pack("<I", probe["coordinate_index"]),
            struct.pack("<I", probe["parent_level"]),
            struct.pack("<i", probe["variable"]),
            struct.pack("<d", zero),
            struct.pack("<d", one),
            struct.pack("<d", probe["threshold"]),
            bytes((class_code,)),
            struct.pack("<i", probe["losing_literal"] or 0),
        )
    )
    reader["probe_trace_bytes"] = len(trace)
    reader["probe_trace_sha256"] = hashlib.sha256(trace).hexdigest()


def test_realized_losing_child_is_linked_end_to_end() -> None:
    reader, ownership, sieve, vault = _payload()
    result = _validate(reader, ownership, sieve, vault)
    assert result.probe_count == 1
    assert result.crossing_count == 1
    assert result.realized_prune_count == 1
    assert result.fully_emitted_count == 1


def test_genuine_native_v18_fixture_validates_full_crossing_lifecycle(
    native_v18: Path, tmp_path: Path
) -> None:
    artifacts = v20_fixtures._artifacts(tmp_path)
    completed = subprocess.run(
        v20_fixtures._command(native_v18, artifacts),
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    payload = sieve_v21.load_native_json(completed.stdout)
    assert payload["schema"] == sieve_v21.JOINT_SCORE_SIEVE_RESULT_SCHEMA

    observed = set(artifacts.field.observed_variables)
    effective = sieve_v21._v20._effective_rank_literals(
        artifacts.decision, artifacts.staging_plan
    )
    candidates: list[int] = []
    seen: set[int] = set()
    for literal in effective:
        variable = abs(literal)
        if variable <= 256 and variable in observed and variable not in seen:
            candidates.append(variable)
            seen.add(variable)
    ranked_count = len(candidates)
    candidates.extend(
        variable
        for variable in range(1, 257)
        if variable in observed and variable not in seen
    )
    assert 241 not in observed and 241 not in candidates

    result = sieve_v21.validate_one_bit_bound_reader(
        payload["one_bit_bound_reader"],
        decision_ownership=payload["decision_ownership"],
        sieve=payload["sieve"],
        vault=payload["vault"],
        threshold=12.0,
        candidate_order=tuple(candidates),
        ranked_candidate_count=ranked_count,
    )
    assert result.probe_count == 56
    assert result.crossing_count == 1
    assert result.realized_prune_count == 1
    assert result.fully_emitted_count == 1

    parsed = sieve_v21._parse_native_payload(
        payload,
        input_vault=artifacts.active_vault,
        rank_source_vault=artifacts.rank_vault,
        frontier_plan=artifacts.frontier_plan,
        staging_plan=artifacts.staging_plan,
        prefix_preemption_plan=artifacts.prefix_plan,
        vault_caps=v20_fixtures.O1C66_VAULT_CAPS,
        field=artifacts.field,
        grouping=artifacts.grouping,
        grouping_sha256=artifacts.active_vault.identity.grouping_sha256,
        cnf_sha256=artifacts.active_vault.identity.cnf_sha256,
        potential_sha256=artifacts.active_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=artifacts.decision,
    )
    assert isinstance(parsed, sieve_v21.JointScoreSieveV21Result)
    assert parsed.one_bit_bound_validation == result
    lifecycle = sieve_v21.validate_native_lifecycle(payload)
    assert lifecycle["bound_proposals"] == 1
    assert lifecycle["bound_live_tokens"] == 0


def test_public_runner_preserves_exact_native_stdout(
    native_v18: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = v20_fixtures._artifacts(tmp_path)
    monkeypatch.setattr(
        sieve_v21,
        "derive_production_vault_ranked_decision",
        lambda *_args: artifacts.decision,
    )
    result = sieve_v21.run_joint_score_sieve(
        executable=native_v18,
        cnf_path=artifacts.cnf,
        potential_path=artifacts.potential,
        grouping_path=artifacts.grouping_path,
        rank_vault_path=artifacts.rank_vault_path,
        vault_path=artifacts.active_vault_path,
        frontier_plan_path=artifacts.frontier_plan_path,
        staging_plan_path=artifacts.staging_plan_path,
        prefix_plan_path=artifacts.prefix_plan_path,
        vault_caps=v20_fixtures.O1C66_VAULT_CAPS,
        threshold=12.0,
        conflict_limit=64,
        timeout_seconds=30.0,
    )
    assert isinstance(result, sieve_v21.JointScoreSieveV21Result)
    assert result.native_stdout is not None
    assert (
        result.native_stdout_sha256
        == hashlib.sha256(result.native_stdout.encode()).hexdigest()
    )
    assert sieve_v21.load_native_json(result.native_stdout) == result.raw


def test_json_roundtrip_preserves_exact_f64_and_clause_identity() -> None:
    values = _payload()
    roundtripped = tuple(json.loads(json.dumps(value)) for value in values)
    result = _validate(*roundtripped)
    assert result.intervention_count == 1


def test_native_json_loader_rejects_duplicate_and_nonfinite_fields() -> None:
    assert sieve_v21.load_native_json('{"schema":"x","nested":{"value":1}}') == {
        "schema": "x",
        "nested": {"value": 1},
    }
    with pytest.raises(O1RelationalSearchError, match="duplicate JSON field value"):
        sieve_v21.load_native_json('{"nested":{"value":1,"value":2}}')
    with pytest.raises(O1RelationalSearchError, match="non-finite JSON"):
        sieve_v21.load_native_json('{"value":NaN}')


def test_equality_is_live_and_both_dead_tie_selects_zero() -> None:
    reader, ownership, sieve, vault = _payload()
    probe = reader["probe_events"][0]
    intervention = reader["interventions"][0]
    probe["upper_one"] = TAU
    probe["upper_one_f64le_hex"] = _f64(TAU)
    intervention["upper_one"] = TAU
    intervention["upper_one_f64le_hex"] = _f64(TAU)
    _refresh_probe_aggregates(reader)
    _validate(reader, ownership, sieve, vault)

    probe["upper_one"] = 1.0
    probe["upper_one_f64le_hex"] = _f64(1.0)
    probe["selection_class"] = "BOTH_PRUNABLE"
    intervention["upper_one"] = 1.0
    intervention["upper_one_f64le_hex"] = _f64(1.0)
    intervention["selection_class"] = "BOTH_PRUNABLE"
    _refresh_probe_aggregates(reader)
    _validate(reader, ownership, sieve, vault)


def test_one_prunable_requires_positive_spin_and_literal() -> None:
    reader, ownership, sieve, vault = _payload()
    probe = reader["probe_events"][0]
    intervention = reader["interventions"][0]
    for row in (probe, intervention):
        row["upper_zero"] = 3.0
        row["upper_zero_f64le_hex"] = _f64(3.0)
        row["upper_one"] = 1.0
        row["upper_one_f64le_hex"] = _f64(1.0)
        row["selection_class"] = "ONE_PRUNABLE"
        row["losing_bit"] = 1
        row["losing_spin"] = 1
        row["losing_literal"] = 11
    intervention["observed_literal"] = 11
    intervention["no_good_literals"] = [-11]
    intervention["no_good_clause_sha256"] = _clause_sha((-11,))
    intervention["v6_pending_clause_sha256_after"] = _clause_sha((-11,))
    vault["fully_emitted_clauses"][0]["literals"] = [-11]
    vault["fully_emitted_clauses"][0]["clause_sha256"] = _clause_sha((-11,))
    for event in ownership["events"]:
        event["literal"] = 11
        if event["kind"] == "CONFIRMED":
            event["observed_literal"] = 11
    _refresh_probe_aggregates(reader)
    _validate(reader, ownership, sieve, vault)


def test_unobserved_release_is_not_a_realized_prune() -> None:
    reader, ownership, sieve, vault = _payload()
    intervention = reader["interventions"][0]
    intervention.update(
        matching_assignment_observed=False,
        observed_literal=None,
        v6_threshold_prunes_after=4,
        v6_trail_threshold_prunes_after=4,
        v6_external_clauses_queued_after=4,
        v6_pending_clause_count_after=0,
        v6_pending_clause_sha256_after=None,
        v6_trace_sha256_after=_sha(9),
        no_good_literals=[],
        no_good_clause_sha256=None,
        fully_emitted=False,
        fully_emitted_index=None,
        realized_prune=False,
        unobserved_release=True,
    )
    reader["matching_assignments_observed"] = 0
    reader["realized_prunes"] = 0
    reader["fully_emitted_prunes"] = 0
    reader["unobserved_releases"] = 1
    ownership["events"] = [
        ownership["events"][0],
        ownership["events"][1],
        {
            **ownership["events"][3],
            "sequence": 3,
            "kind": "LEVEL_BOUND_UNOBSERVED_RELEASE",
        },
    ]
    ownership["recorded_event_count"] = 3
    ownership["event_count"] = 3
    ownership["confirmed_interventions"] = 0
    ownership["confirmed_releases"] = 0
    ownership["level_bound_unobserved_releases"] = 1
    ownership["confirmed_activated"] = False
    ownership["origin_counts"][sieve_v21.BOUND_ORIGIN]["confirmed"] = 0
    vault["fully_emitted_clause_count"] = 0
    vault["fully_emitted_clauses"] = []
    result = _validate(reader, ownership, sieve, vault)
    assert result.realized_prune_count == 0


def test_confirmed_bound_token_may_remain_live_at_solve_end() -> None:
    reader, ownership, sieve, vault = _payload()
    reader["interventions"][0]["released"] = False
    reader["releases"] = 0
    reader["live_tokens"] = 1
    ownership["events"] = ownership["events"][:-1]
    ownership["current_level"] = 1
    ownership["releases"] = 0
    ownership["confirmed_releases"] = 0
    ownership["live_tokens"] = 1
    ownership["event_count"] = 3
    ownership["recorded_event_count"] = 3
    ownership["origin_counts"][sieve_v21.BOUND_ORIGIN]["releases"] = 0

    result = _validate(reader, ownership, sieve, vault)
    assert result.realized_prune_count == 1
    assert result.released_count == 0
    assert result.live_count == 1


def test_live_unmatched_token_is_not_an_unobserved_release() -> None:
    reader, ownership, sieve, vault = _payload()
    intervention = reader["interventions"][0]
    intervention.update(
        matching_assignment_observed=False,
        observed_literal=None,
        v6_threshold_prunes_after=4,
        v6_trail_threshold_prunes_after=4,
        v6_external_clauses_queued_after=4,
        v6_pending_clause_count_after=0,
        v6_pending_clause_sha256_after=None,
        v6_trace_sha256_after=_sha(9),
        no_good_literals=[],
        no_good_clause_sha256=None,
        fully_emitted=False,
        fully_emitted_index=None,
        realized_prune=False,
        released=False,
        unobserved_release=False,
    )
    reader.update(
        matching_assignments_observed=0,
        realized_prunes=0,
        fully_emitted_prunes=0,
        releases=0,
        live_tokens=1,
        unobserved_releases=0,
    )
    ownership["events"] = ownership["events"][:2]
    ownership.update(
        current_level=1,
        confirmed_interventions=0,
        releases=0,
        confirmed_releases=0,
        live_tokens=1,
        event_count=2,
        recorded_event_count=2,
        confirmed_activated=False,
    )
    ownership["origin_counts"][sieve_v21.BOUND_ORIGIN].update(
        confirmed=0,
        releases=0,
    )
    vault["fully_emitted_clause_count"] = 0
    vault["fully_emitted_clauses"] = []

    result = _validate(reader, ownership, sieve, vault)
    assert result.realized_prune_count == 0
    assert result.live_count == 1
    assert result.unobserved_release_count == 0


@pytest.mark.parametrize(
    ("location", "field", "value"),
    [
        ("probe", "upper_zero_f64le_hex", _f64(9.0)),
        ("probe", "upper_one", float("nan")),
        ("probe", "threshold", float("inf")),
        ("probe", "coordinate_index", 1),
        ("probe", "variable", 22),
        ("probe", "selection_class", "ONE_PRUNABLE"),
        ("probe", "losing_bit", 1),
        ("probe", "losing_spin", 1),
        ("probe", "losing_literal", 11),
        ("probe", "proposal_token", 2),
        ("probe", "state_unchanged", False),
        ("intervention", "parent_level", 1),
        ("intervention", "observed_literal", 11),
        ("intervention", "v6_threshold_prunes_after", 4),
        ("intervention", "v6_trail_threshold_prunes_after", 6),
        ("intervention", "v6_external_clauses_queued_after", 4),
        ("intervention", "v6_pending_clause_count_after", 0),
        ("intervention", "v6_pending_clause_sha256_after", _sha(7)),
        ("intervention", "v6_trace_sha256_after", _sha(9)),
        ("intervention", "no_good_clause_sha256", _sha(31)),
        ("intervention", "fully_emitted_index", 1),
        ("ownership", "origin", "PREFIX"),
        ("ownership", "literal", 11),
        ("ownership", "callback", 8),
        ("ownership", "row", 1),
        ("sieve", "threshold_prunes", 4),
        ("vault", "clause_sha256", _sha(30)),
    ],
)
def test_tamper_is_rejected(location: str, field: str, value: object) -> None:
    reader, ownership, sieve, vault = _payload()
    if location == "probe":
        reader["probe_events"][0][field] = value
    elif location == "intervention":
        reader["interventions"][0][field] = value
    elif location == "ownership":
        ownership["events"][0][field] = value
    elif location == "sieve":
        sieve[field] = value
    elif location == "vault":
        vault["fully_emitted_clauses"][0][field] = value
    else:  # pragma: no cover - parametrization is static
        raise AssertionError(location)
    with pytest.raises(O1RelationalSearchError):
        _validate(reader, ownership, sieve, vault)


def test_rejects_state_digest_and_probe_intervention_disagreement() -> None:
    reader, ownership, sieve, vault = _payload()
    reader["probe_events"][0]["state_after"]["trace_sha256"] = _sha(99)
    with pytest.raises(O1RelationalSearchError, match="non-mutation"):
        _validate(reader, ownership, sieve, vault)

    reader, ownership, sieve, vault = _payload()
    reader["interventions"][0]["upper_zero_f64le_hex"] = _f64(3.0)
    with pytest.raises(O1RelationalSearchError, match="probe binding"):
        _validate(reader, ownership, sieve, vault)


def test_rejects_unknown_or_missing_row_fields() -> None:
    reader, ownership, sieve, vault = _payload()
    reader["probe_events"][0]["surprise"] = 1
    with pytest.raises(O1RelationalSearchError, match="probe event fields"):
        _validate(reader, ownership, sieve, vault)

    reader, ownership, sieve, vault = _payload()
    del reader["interventions"][0]["level_bound"]
    with pytest.raises(O1RelationalSearchError, match="intervention fields"):
        _validate(reader, ownership, sieve, vault)


def test_rejects_omitted_crossing_and_duplicate_token_or_emission() -> None:
    reader, ownership, sieve, vault = _payload()
    reader["probe_count"] = 2
    reader["child_bound_evaluations"] = 4
    reader["omitted_probe_event_count"] = 1
    reader["probe_trace_count"] = 2
    reader["probe_trace_bytes"] = 114
    reader["proposals"] = 2
    reader["class_counts"]["ZERO_PRUNABLE"] = 2
    with pytest.raises(O1RelationalSearchError, match="crossing intervention"):
        _validate(reader, ownership, sieve, vault)

    reader, ownership, sieve, vault = _payload()
    reader["probe_events"].append(copy.deepcopy(reader["probe_events"][0]))
    reader["probe_events"][1]["probe"] = 2
    reader["probe_events"][1]["call"] = 8
    reader["probe_count"] = 2
    reader["recorded_probe_event_count"] = 2
    reader["parent_scans"] = 8
    with pytest.raises(O1RelationalSearchError, match="duplicate proposal token"):
        _validate(reader, ownership, sieve, vault)
