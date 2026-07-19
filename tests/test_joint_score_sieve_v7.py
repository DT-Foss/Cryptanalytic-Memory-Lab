from __future__ import annotations

import hashlib
import inspect
import itertools
import json
import math
import struct
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, cast

import pytest

import o1_crypto_lab.joint_score_sieve_v7 as sieve_v7
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v7 import (
    APPLE_VIEW_0009_GROUPING_SHA256,
    APPLE_VIEW_0009_POTENTIAL_SHA256,
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA,
    JOINT_SCORE_SIEVE_GROUPING_RULE,
    JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP,
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES,
    JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA,
    JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JOINT_SCORE_SIEVE_STATE_ENCODING,
    JOINT_SCORE_SIEVE_STATE_SCHEMA,
    JOINT_SCORE_SIEVE_TEARDOWN_RULE,
    IncrementalJointScoreGroupMaxima,
    JointScoreSieveExecutionError,
    build_compatibility_grouping,
    grouped_joint_score_cache,
    joint_score_upper_bound,
    run_joint_score_sieve,
    write_joint_score_sieve_grouping,
    write_joint_score_sieve_potential,
)

ROOT = Path(__file__).resolve().parents[1]
APPLE_VIEW_0009_POTENTIAL = (
    ROOT
    / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
    / "artifacts/potential/primary-eight-block.potential"
)


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 3.0)),
            CriticalityPotentialFactor((1, 2), (4.0, 0.0, 0.0, 0.0)),
            CriticalityPotentialFactor((2,), (2.0, -1.0)),
            CriticalityPotentialFactor((9,), (1.0, -2.0)),
        ),
    )


def _exact_score(
    field: CriticalityPotentialField, assignments: dict[int, int]
) -> Fraction:
    total = Fraction.from_float(field.offset)
    for factor in field.factors:
        row = sum(
            (assignments[variable] > 0) << local
            for local, variable in enumerate(factor.variables)
        )
        total += Fraction.from_float(factor.energies[row])
    return total


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    executable = tmp_path / "native-v5"
    executable.write_bytes(b"synthetic-native-v5")
    cnf = tmp_path / "case.cnf"
    cnf.write_text("p cnf 256 1\n1 0\n", encoding="ascii")
    potential = tmp_path / "case.potential"
    write_joint_score_sieve_potential(potential, _field())
    grouping = tmp_path / "case.grouping"
    write_joint_score_sieve_grouping(grouping, _field())
    return executable, cnf, potential, grouping


def _state(field: CriticalityPotentialField) -> dict[str, object]:
    grouping = build_compatibility_grouping(field)
    assignments = bytes(len(field.observed_variables))
    trail = struct.pack("<II", 0, 0)
    pending = struct.pack("<IIBB", 0, 0, 0, 0)
    cache = grouped_joint_score_cache(field, {}, grouping=grouping)
    canonical = assignments + trail + pending
    persistent = canonical + cache
    live_state = len(canonical)
    bounded_trail = 8 + 8 * len(assignments)
    bounded_pending = 10 + 4 * len(assignments)
    bounded_state = len(assignments) + bounded_trail + bounded_pending
    return {
        "schema": JOINT_SCORE_SIEVE_STATE_SCHEMA,
        "encoding": JOINT_SCORE_SIEVE_STATE_ENCODING,
        "persistent_state_scope": sieve_v7.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE,
        "assignment_bytes": len(assignments),
        "bounded_trail_bytes": bounded_trail,
        "bounded_pending_bytes": bounded_pending,
        "bounded_state_bytes": bounded_state,
        "derived_group_cache_bytes": len(cache),
        "bounded_persistent_state_bytes": bounded_state + len(cache),
        "live_trail_bytes": len(trail),
        "live_pending_bytes": len(pending),
        "live_state_bytes": live_state,
        "live_persistent_state_bytes": live_state + len(cache),
        "maximum_live_trail_bytes": len(trail),
        "maximum_live_state_bytes": live_state,
        "maximum_live_persistent_state_bytes": live_state + len(cache),
        "current_assigned_variables": 0,
        "current_decision_level": 0,
        "trail_entries": 0,
        "pending_clause_length": 0,
        "assignment_hex": assignments.hex(),
        "trail_hex": trail.hex(),
        "pending_hex": pending.hex(),
        "group_cache_hex": cache.hex(),
        "assignment_sha256": hashlib.sha256(assignments).hexdigest(),
        "trail_sha256": hashlib.sha256(trail).hexdigest(),
        "pending_sha256": hashlib.sha256(pending).hexdigest(),
        "group_cache_sha256": hashlib.sha256(cache).hexdigest(),
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "persistent_sha256": hashlib.sha256(persistent).hexdigest(),
    }


def _payload(cnf: Path, potential: Path, grouping_path: Path) -> dict[str, object]:
    field = _field()
    grouping = build_compatibility_grouping(field)
    root = joint_score_upper_bound(field, {}, grouping=grouping)
    group_count = grouping.group_count
    sieve: dict[str, object] = {
        "factor_count": len(field.factors),
        "group_count": group_count,
        "pair_group_count": grouping.pair_group_count,
        "singleton_group_count": grouping.singleton_group_count,
        "higher_order_group_count": grouping.higher_order_group_count,
        "maximum_group_size": max(
            len(group.factor_indices) for group in grouping.groups
        ),
        "grouping_width_cap": JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP,
        "grouping_serialized_bytes": len(grouping.serialized),
        "group_table_rows": grouping.table_rows,
        "group_incident_edges": grouping.variable_group_incidences,
        "grouping_rule": JOINT_SCORE_SIEVE_GROUPING_RULE,
        "grouping_sha256": grouping.sha256,
        "grouping_input_sha256": hashlib.sha256(grouping_path.read_bytes()).hexdigest(),
        "observed_variables": len(field.observed_variables),
        "observed_variables_sha256": hashlib.sha256(
            b"".join(
                struct.pack("<I", variable) for variable in field.observed_variables
            )
        ).hexdigest(),
        "source_sha256": field.source_sha256,
        "offset": field.offset,
        "threshold": -1.0,
        "root_upper_bound": root,
        "root_upper_bound_f64le_hex": struct.pack("<d", root).hex(),
        "bound_rule": JOINT_SCORE_SIEVE_BOUND_RULE,
        "complete_threshold_rule": (sieve_v7.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE),
        "decision_rule": sieve_v7.JOINT_SCORE_SIEVE_DECISION_RULE,
        "external_implications": 0,
        "cb_decide_calls": 0,
        "cb_decide_nonzero": 0,
        "cb_propagate_calls": 0,
        "assignment_callbacks": 0,
        "assignment_literals": 0,
        "new_decision_levels": 0,
        "backtracks": 0,
        "backtracked_assignments": 0,
        "maximum_assigned_variables": 0,
        "maximum_decision_level": 0,
        "bound_checks": 1,
        "bound_additions": group_count,
        "incremental_group_recomputations": 0,
        "maximum_incremental_groups_recomputed": 0,
        "group_maximum_evaluations": group_count,
        "group_row_evaluations": grouping.table_rows,
        "minimum_upper_bound": root,
        "maximum_upper_bound": root,
        "threshold_prunes": 0,
        "trail_threshold_prunes": 0,
        "model_threshold_prunes": 0,
        "external_clauses_queued": 0,
        "external_clauses_emitted": 0,
        "external_clause_literals": 0,
        "minimum_clause_length": 0,
        "maximum_clause_length": 0,
        "maximum_pending_clause_length": 0,
        "pending_clause_count": 0,
        "cb_has_external_clause_calls": 0,
        "model_checks": 0,
        "complete_model_score_checks": 0,
        "models_below_threshold": 0,
        "models_at_or_above_threshold": 0,
        "minimum_complete_score": None,
        "maximum_complete_score": None,
        "trace_sha256": "ab" * 32,
        "state": _state(field),
    }
    return {
        "schema": JOINT_SCORE_SIEVE_RESULT_SCHEMA,
        "implementation_parent_schema": (
            JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        ),
        "cadical_version": "3.0.0",
        "variables": 256,
        "conflict_limit": 1,
        "seed": 7,
        "threshold": -1.0,
        "status": 0,
        "post_solve_state": 256,
        "post_solve_state_name": "INCONCLUSIVE",
        "teardown_rule": JOINT_SCORE_SIEVE_TEARDOWN_RULE,
        "pending_backtrack_rule": JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
        "key_model_hex": None,
        "cnf_sha256": hashlib.sha256(cnf.read_bytes()).hexdigest(),
        "potential_sha256": hashlib.sha256(potential.read_bytes()).hexdigest(),
        "stats": {
            "conflicts": 0,
            "conflicts_before_solve": 0,
            "solve_conflicts": 0,
            "decisions": 0,
            "propagations": 0,
        },
        "sieve": sieve,
        "resources": {
            "wall_microseconds": 0,
            "cpu_microseconds": 0,
            "peak_rss_bytes": 0,
        },
    }


def _call(inputs: tuple[Path, Path, Path, Path], **overrides: object):
    executable, cnf, potential, grouping = inputs
    kwargs: dict[str, object] = {
        "executable": executable,
        "cnf_path": cnf,
        "potential_path": potential,
        "grouping_path": grouping,
        "threshold": -1.0,
        "conflict_limit": 1,
        "seed": 7,
        "timeout_seconds": 45.0,
        "memory_limit_bytes": None,
    }
    kwargs.update(overrides)
    return run_joint_score_sieve(**kwargs)  # type: ignore[arg-type]


def test_fixed_width_grouping_is_higher_order_and_replay_stable(
    tmp_path: Path,
) -> None:
    field = _field()
    first = build_compatibility_grouping(field)
    second = build_compatibility_grouping(field)
    assert first == second
    assert first.width_cap == 6
    assert tuple(group.factor_indices for group in first.groups) == (
        (0, 1, 2),
        (3,),
    )
    assert first.higher_order_group_count == 1
    assert first.table_rows == 6
    path = tmp_path / "grouping.bin"
    assert write_joint_score_sieve_grouping(path, field) == first.sha256
    assert path.read_bytes() == first.serialized


def test_frozen_apple_view_0009_width6_shape_hash_and_root_without_solver() -> None:
    if not APPLE_VIEW_0009_POTENTIAL.is_file():
        pytest.skip("frozen APPLE-VIEW-0009 potential is absent")
    payload = APPLE_VIEW_0009_POTENTIAL.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == APPLE_VIEW_0009_POTENTIAL_SHA256
    field = CriticalityPotentialField.from_bytes(payload)
    grouping = build_compatibility_grouping(field)
    assert grouping.width_cap == 6
    assert grouping.factor_count == 7_557
    assert grouping.group_count == 2_885
    assert grouping.singleton_group_count == 28
    assert grouping.pair_group_count == 1_641
    assert grouping.higher_order_group_count == 1_216
    assert max(len(group.factor_indices) for group in grouping.groups) == 8
    assert grouping.table_rows == 176_912
    assert grouping.variable_group_incidences == 17_025
    assert len(grouping.serialized) == 115_700
    assert grouping.sha256 == APPLE_VIEW_0009_GROUPING_SHA256
    root = joint_score_upper_bound(field, {}, grouping=grouping)
    assert root == 262.68644197084643
    assert struct.pack("<d", root).hex() == "327693aafb6a7040"


def test_incremental_cache_touches_only_incident_groups_and_stays_exact_safe() -> None:
    field = _field()
    state = IncrementalJointScoreGroupMaxima(field)
    assert state.cache_bytes == grouped_joint_score_cache(field, {})
    assert state.update({1: 1}) == (0,)
    assert state.upper_bound == joint_score_upper_bound(field, {1: 1}) == 6.0
    assert state.update({9: 1}) == (1,)
    assert state.upper_bound == joint_score_upper_bound(field, {1: 1, 9: 1})
    assert state.update({1: None, 9: None}) == (0, 1)
    assert state.cache_bytes == grouped_joint_score_cache(field, {})

    variables = field.observed_variables
    for spins in itertools.product((None, -1, 1), repeat=len(variables)):
        changes = dict(zip(variables, spins, strict=True))
        state.update(changes)
        partial = {
            variable: spin for variable, spin in changes.items() if spin is not None
        }
        assert state.cache_bytes == grouped_joint_score_cache(field, partial)
        assert state.upper_bound == joint_score_upper_bound(field, partial)
        missing = tuple(variable for variable in variables if variable not in partial)
        for completion_spins in itertools.product((-1, 1), repeat=len(missing)):
            complete = dict(partial)
            complete.update(zip(missing, completion_spins, strict=True))
            assert Fraction.from_float(state.upper_bound) >= _exact_score(
                field, complete
            )


def test_root_sum_rounds_once_to_the_least_safe_binary64() -> None:
    tiny = 2.0**-53
    field = CriticalityPotentialField(
        offset=1.0,
        source_sha256="44" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (tiny, tiny)),
            CriticalityPotentialFactor((2,), (0.0, 0.0)),
        ),
    )
    upper = joint_score_upper_bound(field, {})
    exact = Fraction.from_float(1.0) + Fraction.from_float(tiny)
    assert upper == math.nextafter(1.0, math.inf)
    assert Fraction.from_float(upper) >= exact
    assert Fraction.from_float(math.nextafter(upper, -math.inf)) < exact


def test_success_contract_validates_grouping_lifecycle_cache_and_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    payload = _payload(inputs[1], inputs[2], inputs[3])
    commands: list[list[str]] = []

    def succeed(command: list[str], **_: object):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(sieve_v7.subprocess, "run", succeed)
    result = _call(inputs)
    assert result.status == 0
    assert result.stats["requested_conflicts"] == 1
    assert result.stats["unused_requested_conflicts"] == 1
    assert result.adapter_memory["memory_sample_count"] == 0
    assert result.adapter_memory["memory_samples"] == []
    assert set(result.resources) == {
        "wall_microseconds",
        "cpu_microseconds",
        "peak_rss_bytes",
    }
    assert set(cast(Mapping[str, object], result.raw["resources"])) == {
        "wall_microseconds",
        "cpu_microseconds",
        "peak_rss_bytes",
    }
    assert result.raw["implementation_parent_schema"] == (
        JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    assert commands and commands[0][5:7] == ["--grouping", str(inputs[3].resolve())]
    assert "grouping_path" in inspect.signature(run_joint_score_sieve).parameters


def test_success_preserves_external_memory_series_outside_strict_raw_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    payload = _payload(inputs[1], inputs[2], inputs[3])
    samples = (
        {"elapsed_seconds": 0.01, "rss_bytes": 100},
        {"elapsed_seconds": 0.02, "rss_bytes": 125},
    )

    def succeed(command: list[str], **_: object):
        return sieve_v7._NativeExecution(
            completed=sieve_v7.subprocess.CompletedProcess(
                command, 0, json.dumps(payload), ""
            ),
            memory_samples=samples,
        )

    monkeypatch.setattr(sieve_v7, "_execute_native", succeed)
    result = _call(inputs, memory_limit_bytes=1_000)
    assert result.adapter_memory["memory_series_schema"] == (
        JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
    )
    assert result.adapter_memory["memory_sample_count"] == 2
    assert result.adapter_memory["memory_samples"] == list(samples)
    assert result.adapter_memory["memory_peak_bytes"] == 125
    assert result.adapter_memory["memory_last_bytes"] == 125
    assert result.adapter_memory["memory_last_elapsed_seconds"] == 0.02
    assert set(result.resources) == {
        "wall_microseconds",
        "cpu_microseconds",
        "peak_rss_bytes",
    }
    assert set(cast(Mapping[str, object], result.raw["resources"])) == {
        "wall_microseconds",
        "cpu_microseconds",
        "peak_rss_bytes",
    }


def test_darwin_watchdog_samples_immediately_even_for_fast_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 123
        returncode = 0

        def communicate(self, timeout: float | None = None):
            return "native-json", ""

        def poll(self):
            return self.returncode

    monkeypatch.setattr(sieve_v7.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        sieve_v7._v1, "_darwin_physical_footprint_bytes", lambda pid: 123
    )
    execution = sieve_v7._run_with_darwin_memory_watchdog(
        ["native"], timeout_seconds=1.0, memory_limit_bytes=1_000
    )
    assert execution.completed.returncode == 0
    assert execution.memory_samples
    assert execution.memory_samples[0]["rss_bytes"] == 123


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload.update(post_solve_state=16),
            "lifecycle contract",
        ),
        (
            lambda payload: payload["sieve"].update(  # type: ignore[union-attr]
                grouping_input_sha256="00" * 32
            ),
            "telemetry contract",
        ),
    ],
)
def test_parser_fail_closes_lifecycle_and_group_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate,
    message: str,
) -> None:
    inputs = _inputs(tmp_path)
    payload = _payload(inputs[1], inputs[2], inputs[3])
    mutate(payload)
    monkeypatch.setattr(
        sieve_v7.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    with pytest.raises(JointScoreSieveExecutionError, match=message) as caught:
        _call(inputs)
    assert caught.value.failure_telemetry["classification_kind"] == (
        "adapter_or_parser"
    )


def test_parser_rejects_self_consistent_forged_group_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    payload = _payload(inputs[1], inputs[2], inputs[3])
    state = payload["sieve"]["state"]  # type: ignore[index]
    cache = bytearray.fromhex(state["group_cache_hex"])
    cache[0] ^= 1
    state["group_cache_hex"] = cache.hex()
    state["group_cache_sha256"] = hashlib.sha256(cache).hexdigest()
    canonical = (
        bytes.fromhex(state["assignment_hex"])
        + bytes.fromhex(state["trail_hex"])
        + bytes.fromhex(state["pending_hex"])
    )
    state["persistent_sha256"] = hashlib.sha256(canonical + cache).hexdigest()
    monkeypatch.setattr(
        sieve_v7.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    with pytest.raises(JointScoreSieveExecutionError, match="grouped cache"):
        _call(inputs)


def test_wrong_grouping_bytes_fail_before_any_process_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    inputs[3].write_bytes(inputs[3].read_bytes() + b"forged")
    entered = False

    def forbidden(*args: object, **kwargs: object):
        nonlocal entered
        entered = True
        raise AssertionError("process boundary entered")

    monkeypatch.setattr(sieve_v7.subprocess, "run", forbidden)
    with pytest.raises(JointScoreSieveExecutionError, match="grouping input"):
        _call(inputs)
    assert not entered


def test_child_exit_preserves_returncode_command_and_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    monkeypatch.setattr(
        sieve_v7.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=7, stdout="partial-output", stderr="native-sentinel"
        ),
    )
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call(inputs)
    telemetry = caught.value.failure_telemetry
    assert telemetry["schema"] == JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
    assert telemetry["classification_kind"] == "child_exit"
    assert telemetry["returncode"] == 7
    assert telemetry["stdout"] == "partial-output"
    assert telemetry["stderr"] == "native-sentinel"
    assert telemetry["command"][5:7] == [  # type: ignore[index]
        "--grouping",
        str(inputs[3].resolve()),
    ]


def test_failure_telemetry_keeps_bounded_time_indexed_memory_series(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    samples = (
        {"elapsed_seconds": 0.25, "rss_bytes": 100},
        {"elapsed_seconds": 0.50, "rss_bytes": 360},
        {"elapsed_seconds": 0.75, "rss_bytes": 350},
    )

    def fail(*args: object, **kwargs: object):
        raise sieve_v7._JointScoreSieveMemoryLimitExceeded(
            "Darwin physical-footprint watchdog reached its guarded ceiling "
            "(360 >= 350 < 400)",
            memory_samples=samples,
            command=["native", "--grouping", "case.grouping"],
            stdout="partial",
            stderr="killed",
            returncode=-9,
        )

    monkeypatch.setattr(sieve_v7.sys, "platform", "linux")
    monkeypatch.setattr(sieve_v7.subprocess, "run", fail)
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call(inputs, memory_limit_bytes=400)
    telemetry = caught.value.failure_telemetry
    assert telemetry["classification_kind"] == "watchdog_memory"
    assert telemetry["memory_series_schema"] == JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
    assert telemetry["memory_sample_limit"] == JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
    assert telemetry["memory_sample_count"] == 3
    assert telemetry["memory_samples"] == list(samples)
    assert telemetry["memory_peak_bytes"] == 360
    assert telemetry["memory_last_bytes"] == 350
    assert telemetry["memory_last_elapsed_seconds"] == 0.75
    assert telemetry["darwin_watchdog_guard_bytes"] == 50
    assert telemetry["darwin_watchdog_kill_threshold_bytes"] == 350
    assert telemetry["returncode"] == -9
    assert telemetry["signal_number"] == 9
    assert telemetry["stdout"] == "partial"
    assert telemetry["stderr"] == "killed"


def test_memory_series_extractor_is_hard_bounded() -> None:
    samples = tuple(
        {"elapsed_seconds": float(index), "rss_bytes": index}
        for index in range(JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES + 20)
    )
    error = sieve_v7._JointScoreSieveMemoryLimitExceeded(
        "watchdog",
        memory_samples=samples,
        command=["native"],
        stdout="",
        stderr="",
        returncode=-9,
    )
    extracted = sieve_v7._memory_series_from_chain(error)
    assert len(extracted) == JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
    assert extracted[0]["rss_bytes"] == 20
    assert extracted[-1]["rss_bytes"] == 275
