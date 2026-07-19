from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import o1_crypto_lab.o1c60_multiblock_joint_score_sieve_run as run_module
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.joint_score_sieve_v2 import JOINT_SCORE_SIEVE_DECISION_RULE
from o1_crypto_lab.o1c60_multiblock_joint_score_sieve_run import (
    CONFLICT_LIMIT,
    MEMORY_LIMIT_BYTES,
    NATIVE_TIMEOUT_SECONDS,
    O1C60RunError,
    RESULT_RELATIVE,
    _finalize_capsule,
    _invoke_native_once,
    _invoke_native_once_terminal,
    classify_sieve,
    load_config,
    prospective_threshold,
    validate_native_resource_ledger,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c60_multiblock_joint_score_sieve_conflict_ledger_v1.json"


def _native(
    *,
    status: int = 0,
    key_model: bytes | None = None,
    root_upper: float = 100.0,
    minimum_upper: float = 100.0,
    trail_prunes: int = 0,
    model_prunes: int = 0,
    cumulative_conflicts: int = 513,
    conflicts_before_solve: int = 1,
    solve_conflicts: int = 512,
) -> JointScoreSieveResult:
    return JointScoreSieveResult(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=1.0,
        key_model=key_model,
        stats={
            "conflicts": cumulative_conflicts,
            "conflicts_before_solve": conflicts_before_solve,
            "solve_conflicts": solve_conflicts,
            "decisions": 9_166,
            "propagations": 1_227_877,
        },
        sieve={
            "decision_rule": JOINT_SCORE_SIEVE_DECISION_RULE,
            "root_upper_bound": root_upper,
            "minimum_upper_bound": minimum_upper,
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": model_prunes,
            "threshold_prunes": trail_prunes + model_prunes,
            "complete_model_score_checks": model_prunes,
        },
        resources={
            "wall_microseconds": 438_847,
            "cpu_microseconds": 1_003_479,
            "peak_rss_bytes": 383_451_136,
        },
        raw={},
    )


def test_o1c59_cumulative_513_is_valid_under_incremental_ledger() -> None:
    ledger = validate_native_resource_ledger(
        _native(), solver_calls=1, maximum_native_solver_calls=1
    )
    assert ledger == {
        "conflicts": 513,
        "conflicts_before_solve": 1,
        "solve_conflicts": 512,
        "decisions": 9_166,
        "propagations": 1_227_877,
    }


@pytest.mark.parametrize(
    "native",
    [
        _native(solve_conflicts=511),
        _native(conflicts_before_solve=2),
        _native(cumulative_conflicts=514, solve_conflicts=513),
    ],
)
def test_o1c60_resource_ledger_rejects_conflict_mismatch(
    native: JointScoreSieveResult,
) -> None:
    with pytest.raises(O1C60RunError, match="conflict ledger"):
        validate_native_resource_ledger(
            native, solver_calls=1, maximum_native_solver_calls=1
        )


def test_prospective_threshold_and_classification_are_unchanged() -> None:
    decoy_max = 14.606178797992964
    expected = __import__("math").nextafter(decoy_max - 1e-10, -__import__("math").inf)
    assert prospective_threshold(decoy_max, 1e-10) == expected
    classification, metrics = classify_sieve(
        _native(trail_prunes=1),
        public_model_verified=False,
        minimum_material_bound_drop=1.0,
    )
    assert classification == "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY"
    assert metrics["safe_trail_threshold_prunes"] == 1


def test_native_adapter_is_called_once_with_frozen_limits(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    expected = _native()

    def fake_runner(**kwargs: object) -> JointScoreSieveResult:
        calls.append(dict(kwargs))
        return expected

    result = _invoke_native_once(
        executable=tmp_path / "native",
        cnf=tmp_path / "eight.cnf",
        potential=tmp_path / "primary.potential",
        threshold=2.5,
        conflict_limit=CONFLICT_LIMIT,
        timeout_seconds=NATIVE_TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
        runner=fake_runner,
    )
    assert result is expected
    assert len(calls) == 1
    assert calls[0]["conflict_limit"] == 512
    assert calls[0]["timeout_seconds"] == 180.0
    assert calls[0]["memory_limit_bytes"] == 805_306_368
    assert calls[0]["seed"] == 0


def test_exception_after_intent_is_terminal_and_never_retries(tmp_path: Path) -> None:
    calls = 0

    def exploding_runner(**kwargs: object) -> JointScoreSieveResult:
        nonlocal calls
        calls += 1
        raise TimeoutError("synthetic native timeout")

    result, failure = _invoke_native_once_terminal(
        executable=tmp_path / "native",
        cnf=tmp_path / "eight.cnf",
        potential=tmp_path / "primary.potential",
        threshold=2.5,
        conflict_limit=CONFLICT_LIMIT,
        timeout_seconds=NATIVE_TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
        runner=exploding_runner,
    )
    assert calls == 1
    assert result is None
    assert failure is not None
    assert failure["native_calls_consumed"] == 1
    assert failure["retry_authorized"] is False
    assert failure["truth_key_bytes_read"] is False


def test_operational_failure_capsule_terminalizes_immutably(tmp_path: Path) -> None:
    capsule = tmp_path / "runs/failure"
    capsule.mkdir(parents=True)
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    result: dict[str, object] = {
        "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
        "operational_failure": {
            "error_type": "TimeoutError",
            "native_calls_consumed": 1,
        },
        "metrics": {"native_status": "OPERATIONAL_FAILURE"},
        "resources": {"persistent_artifact_bytes": 0},
    }
    _finalize_capsule(
        root=tmp_path,
        capsule=capsule,
        result=result,
        maximum_persistent_bytes=1_000_000,
    )
    assert (capsule / "artifacts.sha256").is_file()
    assert (tmp_path / RESULT_RELATIVE).is_file()
    assert capsule.stat().st_mode & 0o777 == 0o555
    for path in capsule.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    capsule.chmod(0o755)


def test_post_native_failure_does_not_touch_o1c59(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule = (
        tmp_path
        / "runs/20260719_120000_O1C-0060_multiblock-joint-score-sieve-conflict-ledger-v1"
    )
    capsule.mkdir(parents=True)
    (capsule / "native_call_intent.json").write_text(
        '{"calls_authorized":1,"recorded_at":"2026-07-19T12:00:00+02:00"}\n',
        encoding="ascii",
    )
    native_payload = b'{"status":0,"stats":{"conflicts":513}}\n'
    (capsule / "native_result.json").write_bytes(native_payload)
    old_capsule = tmp_path / "runs/immutable_O1C-0059_multiblock-joint-score-sieve-v1"
    old_capsule.mkdir()
    old_sentinel = old_capsule / "sentinel.bin"
    old_sentinel.write_bytes(b"immutable-o1c59")
    old_result = tmp_path / "research/O1C0059_RESULT.json"
    old_result.parent.mkdir()
    old_result.write_bytes(b"immutable-o1c59-result")
    old_hashes = (
        hashlib.sha256(old_sentinel.read_bytes()).hexdigest(),
        hashlib.sha256(old_result.read_bytes()).hexdigest(),
    )
    calls = 0

    def fail_after_native(_config_path: str | Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise O1C60RunError("synthetic public replay failure")

    monkeypatch.setattr(run_module, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(run_module, "_run_impl", fail_after_native)
    result = run_module.run(tmp_path / "unused-config.json")
    assert calls == 1
    assert result["classification"] == (
        "OPERATIONAL_POST_NATIVE_VALIDATION_FAILURE_NO_SCIENCE_CLAIM"
    )
    assert result["operational_failure"]["retry_authorized"] is False  # type: ignore[index]
    assert result["operational_failure"]["o1c59_retry_authorized"] is False  # type: ignore[index]
    assert (capsule / "native_result.json").read_bytes() == native_payload
    assert old_hashes == (
        hashlib.sha256(old_sentinel.read_bytes()).hexdigest(),
        hashlib.sha256(old_result.read_bytes()).hexdigest(),
    )
    for path in capsule.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    capsule.chmod(0o755)


def test_frozen_config_hashes_all_executing_sources() -> None:
    config = load_config(CONFIG)
    source = config["source"]
    assert source["native_source"].endswith("_v2.cpp")  # type: ignore[index,union-attr]
    assert source["joint_score_sieve"].endswith("_v2.py")  # type: ignore[index,union-attr]
    assert source["mechanism_base_runner"].endswith(  # type: ignore[index,union-attr]
        "o1c59_multiblock_joint_score_sieve_run.py"
    )
    assert config["lineage"] == {  # type: ignore[comparison-overlap]
        "mechanism_source_attempt": "O1C-0059",
        "new_attempt_not_retry": True,
        "o1c59_capsule_reads": 0,
        "o1c59_result_reads": 0,
        "o1c59_writes": 0,
        "only_change": "incremental-conflict-ledger-v2",
    }
