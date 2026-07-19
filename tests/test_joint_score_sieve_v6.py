from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import o1_crypto_lab.joint_score_sieve_v6 as sieve_v6
from o1_crypto_lab.joint_score_sieve_v6 import (
    JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA,
    JointScoreSieveExecutionError,
    run_joint_score_sieve,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


def _call(**overrides: object):
    kwargs: dict[str, object] = {
        "executable": Path("native"),
        "cnf_path": Path("case.cnf"),
        "potential_path": Path("case.potential"),
        "threshold": 1.25,
        "conflict_limit": 4_096,
        "seed": 7,
        "timeout_seconds": 45.0,
        "memory_limit_bytes": 1_073_741_824,
    }
    kwargs.update(overrides)
    return run_joint_score_sieve(**kwargs)  # type: ignore[arg-type]


def test_success_is_the_identical_v5_result_and_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()
    observed: list[dict[str, object]] = []

    def succeed(**kwargs: object):
        observed.append(dict(kwargs))
        return sentinel

    monkeypatch.setattr(sieve_v6._v5, "run_joint_score_sieve", succeed)
    assert _call() is sentinel
    assert observed == [
        {
            "executable": Path("native"),
            "cnf_path": Path("case.cnf"),
            "potential_path": Path("case.potential"),
            "threshold": 1.25,
            "conflict_limit": 4_096,
            "seed": 7,
            "timeout_seconds": 45.0,
            "memory_limit_bytes": 1_073_741_824,
        }
    ]


def test_nested_memory_watchdog_cause_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _JointScoreSieveMemoryLimitExceeded(RuntimeError):
        pass

    def fail(**_: object):
        cause = _JointScoreSieveMemoryLimitExceeded(
            "Darwin physical-footprint watchdog reached its guarded ceiling "
            "(1040187392 >= 1040187392 < 1073741824)"
        )
        raise O1RelationalSearchError("joint-score-sieve execution failed") from cause

    monkeypatch.setattr(sieve_v6._v5, "run_joint_score_sieve", fail)
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call()
    error = caught.value
    telemetry = error.failure_telemetry
    assert telemetry == error.describe()
    assert telemetry["schema"] == JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
    assert telemetry["classification_kind"] == "watchdog_memory"
    assert telemetry["phase"] == "native_process"
    assert telemetry["configured_timeout_seconds"] == 45.0
    assert telemetry["configured_memory_limit_bytes"] == 1_073_741_824
    assert telemetry["darwin_watchdog_kill_threshold_bytes"] == 1_040_187_392
    assert telemetry["memory_samples"] == [
        {
            "observed_bytes": 1_040_187_392,
            "kill_threshold_bytes": 1_040_187_392,
            "configured_limit_bytes": 1_073_741_824,
        }
    ]
    chain = telemetry["exception_chain"]
    assert isinstance(chain, list)
    assert chain[0]["type"] == "O1RelationalSearchError"
    assert str(chain[1]["type"]).endswith("._JointScoreSieveMemoryLimitExceeded")
    assert isinstance(error.__cause__, O1RelationalSearchError)


def test_timeout_keeps_command_and_raw_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_: object):
        cause = subprocess.TimeoutExpired(
            ["native", "--cnf", "case.cnf"], 45.0, output=b"partial", stderr=b"late"
        )
        raise O1RelationalSearchError("joint-score-sieve execution failed") from cause

    monkeypatch.setattr(sieve_v6._v5, "run_joint_score_sieve", fail)
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call()
    telemetry = caught.value.failure_telemetry
    assert telemetry["classification_kind"] == "timeout"
    assert telemetry["command"] == ["native", "--cnf", "case.cnf"]
    assert telemetry["stdout"] == b"partial"
    assert telemetry["stderr"] == b"late"


@pytest.mark.parametrize(
    ("failure", "kind"),
    [
        (OSError("permission denied"), "launch_or_os"),
        (RuntimeError("parser differs"), "adapter_or_parser"),
    ],
)
def test_os_and_parser_failures_are_distinguished(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, kind: str
) -> None:
    def fail(**_: object):
        if isinstance(failure, OSError):
            raise O1RelationalSearchError(
                "joint-score-sieve execution failed"
            ) from failure
        raise failure

    monkeypatch.setattr(sieve_v6._v5, "run_joint_score_sieve", fail)
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call()
    assert caught.value.failure_telemetry["classification_kind"] == kind


def test_native_nonzero_message_is_classified_as_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_: object):
        raise O1RelationalSearchError(
            "joint-score-sieve execution failed: native callback failed"
        )

    monkeypatch.setattr(sieve_v6._v5, "run_joint_score_sieve", fail)
    with pytest.raises(JointScoreSieveExecutionError) as caught:
        _call(memory_limit_bytes=None)
    telemetry = caught.value.failure_telemetry
    assert telemetry["classification_kind"] == "child_exit"
    assert telemetry["configured_memory_limit_bytes"] is None
    assert telemetry["darwin_watchdog_kill_threshold_bytes"] is None
    assert isinstance(telemetry["elapsed_seconds"], float)
    assert telemetry["elapsed_seconds"] >= 0.0
