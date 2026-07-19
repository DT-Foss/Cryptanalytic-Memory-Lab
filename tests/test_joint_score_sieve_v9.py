from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping

import pytest

import o1_crypto_lab.joint_score_sieve_v9 as sieve_v9
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v9 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JointScoreSieveExecutionError,
    JointScoreSieveV9Result,
    derive_vault_soft_conflict_ledger,
    run_joint_score_sieve,
    validate_vault_soft_conflict_ledger,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


def _native_stats(*, solve: int, conflicts_before_solve: int = 0) -> dict[str, int]:
    return {
        "conflicts": conflicts_before_solve + solve,
        "conflicts_before_solve": conflicts_before_solve,
        "solve_conflicts": solve,
        "decisions": 9,
        "propagations": 99,
    }


def test_o1c67_bills_observed_514_at_requested_soft_horizon_512() -> None:
    ledger = derive_vault_soft_conflict_ledger(
        _native_stats(solve=514, conflicts_before_solve=17),
        requested_conflicts=512,
    )

    assert "v9-o1c67" in JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
    assert ledger == {
        "conflicts": 531,
        "conflicts_before_solve": 17,
        "solve_conflicts": 514,
        "decisions": 9,
        "propagations": 99,
        "requested_conflicts": 512,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 2,
        "billed_conflicts": 514,
    }


def test_o1c67_rejects_forged_native_conflict_delta() -> None:
    forged = _native_stats(solve=514)
    forged["solve_conflicts"] = 513

    with pytest.raises(O1RelationalSearchError, match="v9 vault soft conflict"):
        derive_vault_soft_conflict_ledger(forged, requested_conflicts=512)


@pytest.mark.parametrize(
    ("field", "value"),
    (("solve_conflicts", True), ("conflicts", -1), ("decisions", 1.5)),
)
def test_o1c67_native_ledger_retains_strict_types_and_nonnegativity(
    field: str, value: object
) -> None:
    forged: dict[str, object] = {**_native_stats(solve=7)}
    forged[field] = value

    with pytest.raises(O1RelationalSearchError, match="v9 vault native conflict"):
        derive_vault_soft_conflict_ledger(forged, requested_conflicts=512)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("billed_conflicts", 513),
        ("conflict_limit_overshoot", 1),
        ("unused_requested_conflicts", 1),
    ),
)
def test_o1c67_validated_ledger_retains_all_algebraic_equalities(
    field: str, value: int
) -> None:
    ledger = derive_vault_soft_conflict_ledger(
        _native_stats(solve=514), requested_conflicts=512
    )
    ledger[field] = value

    with pytest.raises(O1RelationalSearchError, match="v9 vault soft conflict"):
        validate_vault_soft_conflict_ledger(ledger)


@pytest.mark.parametrize(
    "case",
    (
        "invalid_requested",
        "before_exceeds_conflicts",
        "validated_boolean",
        "validated_negative",
        "unused_and_overshoot",
    ),
)
def test_o1c67_validated_ledger_rejects_remaining_contract_gates(case: str) -> None:
    ledger = derive_vault_soft_conflict_ledger(
        _native_stats(solve=7), requested_conflicts=512
    )
    if case == "invalid_requested":
        ledger["requested_conflicts"] = 0
    elif case == "before_exceeds_conflicts":
        ledger["conflicts_before_solve"] = ledger["conflicts"] + 1
    elif case == "validated_boolean":
        ledger["decisions"] = True
    elif case == "validated_negative":
        ledger["propagations"] = -1
    else:
        ledger = derive_vault_soft_conflict_ledger(
            _native_stats(solve=514), requested_conflicts=512
        )
        ledger["unused_requested_conflicts"] = 1

    with pytest.raises(O1RelationalSearchError, match="joint-score-sieve-v9"):
        validate_vault_soft_conflict_ledger(ledger)


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 3.0)),
            CriticalityPotentialFactor((2,), (-2.0, 2.0)),
        ),
    )


def _inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault]:
    field = _field()
    executable = tmp_path / "synthetic-native-v6"
    executable.write_bytes(b"synthetic-native-v6")
    cnf = tmp_path / "target-free.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "target-free.potential"
    sieve_v9.write_joint_score_sieve_potential(potential, field)
    grouping = tmp_path / "target-free.grouping"
    sieve_v9.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=0.0,
    )
    input_vault = ThresholdNoGoodVault(identity, field.observed_variables, ())
    vault = tmp_path / "target-free.vault"
    write_threshold_no_good_vault(vault, input_vault, caps=O1C66_VAULT_CAPS)
    return executable, cnf, potential, grouping, vault, input_vault


def _result(
    input_vault: ThresholdNoGoodVault, stats: Mapping[str, int]
) -> JointScoreSieveV9Result:
    return JointScoreSieveV9Result(
        status=0,
        conflict_limit=512,
        threshold=0.0,
        key_model=None,
        stats=stats,
        sieve={},
        resources={},
        raw={},
        adapter_memory={},
        input_vault=input_vault,
        eligible_emitted_clauses=(),
        next_vault=input_vault,
        vault_telemetry={},
    )


def _mock_execution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str,
    stderr: str = "stderr-sentinel",
) -> tuple[list[str], tuple[dict[str, int | float], ...]]:
    command_seen: list[str] = []
    samples: tuple[dict[str, int | float], ...] = (
        {"elapsed_seconds": 0.25, "rss_bytes": 12_345},
    )

    def fake_execute(
        command: list[str], *, timeout_seconds: float, memory_limit_bytes: int | None
    ) -> Any:
        assert timeout_seconds == 60.0
        assert memory_limit_bytes is None
        command_seen.extend(command)
        return sieve_v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(sieve_v9._v8._v7, "_execute_native", fake_execute)
    return command_seen, samples


def _run_inputs(
    inputs: tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault],
) -> JointScoreSieveV9Result:
    executable, cnf, potential, grouping, vault, _ = inputs
    return run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=0.0,
        conflict_limit=512,
    )


def _assert_process_evidence(
    error: JointScoreSieveExecutionError,
    *,
    command: list[str],
    stdout: str,
    stderr: str,
    samples: tuple[dict[str, int | float], ...],
) -> None:
    telemetry = error.failure_telemetry
    assert telemetry["classification_kind"] == "adapter_or_parser"
    assert telemetry["phase"] == "adapter_validation"
    assert telemetry["command"] == command
    assert telemetry["returncode"] == 0
    assert telemetry["stdout"] == stdout
    assert telemetry["stderr"] == stderr
    assert telemetry["memory_samples"] == list(samples)


def test_o1c67_full_adapter_accepts_soft_overshoot_without_a_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps({"process": "success-sentinel"})
    _mock_execution(monkeypatch, stdout=stdout)
    input_vault = inputs[-1]
    monkeypatch.setattr(
        sieve_v9,
        "_parse_native_payload",
        lambda *_args, **_kwargs: _result(input_vault, _native_stats(solve=514)),
    )

    result = _run_inputs(inputs)

    assert isinstance(result, JointScoreSieveV9Result)
    assert result.stats["requested_conflicts"] == 512
    assert result.stats["conflict_limit_overshoot"] == 2
    assert result.stats["billed_conflicts"] == 514


def test_o1c67_postprocess_failure_preserves_successful_process_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps({"process": "ledger-failure-sentinel"})
    stderr = "successful-process-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)
    input_vault = inputs[-1]
    forged = _native_stats(solve=514)
    forged["solve_conflicts"] = 513
    monkeypatch.setattr(
        sieve_v9,
        "_parse_native_payload",
        lambda *_args, **_kwargs: _result(input_vault, forged),
    )

    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)

    _assert_process_evidence(
        raised.value,
        command=command,
        stdout=stdout,
        stderr=stderr,
        samples=samples,
    )
    assert "joint-score-sieve-v9" in str(raised.value)


def test_o1c67_payload_parser_failure_preserves_successful_process_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps({"process": "payload-parser-failure-sentinel"})
    stderr = "payload-parser-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)

    def fail_parser(*_args: object, **_kwargs: object) -> JointScoreSieveV9Result:
        raise O1RelationalSearchError("joint-score-sieve-v9 payload-parser-sentinel")

    monkeypatch.setattr(sieve_v9, "_parse_native_payload", fail_parser)

    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)

    _assert_process_evidence(
        raised.value,
        command=command,
        stdout=stdout,
        stderr=stderr,
        samples=samples,
    )
    assert "payload-parser-sentinel" in str(raised.value)


def test_o1c67_invalid_json_preserves_successful_process_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = "invalid-json-sentinel"
    stderr = "json-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)

    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)

    _assert_process_evidence(
        raised.value,
        command=command,
        stdout=stdout,
        stderr=stderr,
        samples=samples,
    )
    assert "joint-score-sieve-v9 result JSON is invalid" in str(raised.value)


def test_o1c67_stable_input_failure_preserves_successful_process_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps({"process": "stable-input-failure-sentinel"})
    stderr = "stable-input-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)

    def fail_stability(*_args: object, **_kwargs: object) -> None:
        raise O1RelationalSearchError("stable-input-sentinel")

    monkeypatch.setattr(sieve_v9._v8._v1, "_verify_stable_input", fail_stability)

    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)

    _assert_process_evidence(
        raised.value,
        command=command,
        stdout=stdout,
        stderr=stderr,
        samples=samples,
    )
    assert "joint-score-sieve-v9 adapter failed" in str(raised.value)


def test_o1c67_evidence_helper_never_overwrites_specific_attributes() -> None:
    error = O1RelationalSearchError("specific-evidence")
    setattr(error, "cmd", ["specific-command"])
    setattr(error, "returncode", 7)
    setattr(error, "stdout", "specific-stdout")
    setattr(error, "stderr", "specific-stderr")
    setattr(
        error,
        "memory_samples",
        ({"elapsed_seconds": 1.0, "rss_bytes": 77},),
    )
    completed = subprocess.CompletedProcess(
        ["replacement-command"], 0, "replacement-stdout", "replacement-stderr"
    )

    sieve_v9._attach_native_process_evidence(
        error,
        command=["replacement-command"],
        completed=completed,
        memory_samples=({"elapsed_seconds": 2.0, "rss_bytes": 88},),
    )

    assert getattr(error, "cmd") == ["specific-command"]
    assert getattr(error, "returncode") == 7
    assert getattr(error, "stdout") == "specific-stdout"
    assert getattr(error, "stderr") == "specific-stderr"
    assert getattr(error, "memory_samples") == (
        {"elapsed_seconds": 1.0, "rss_bytes": 77},
    )
