from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from pathlib import Path

import pytest

import o1_crypto_lab.o1c61_multiblock_joint_score_sieve_run as run_module
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.joint_score_sieve_v3 import JOINT_SCORE_SIEVE_DECISION_RULE
from o1_crypto_lab.o1c61_multiblock_joint_score_sieve_run import (
    CONFLICT_LIMIT,
    MEMORY_LIMIT_BYTES,
    NATIVE_TIMEOUT_SECONDS,
    O1C61RunError,
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
CONFIG = ROOT / "configs/o1c61_multiblock_joint_score_sieve_soft_stop_v1.json"


def _native(
    *,
    status: int = 0,
    key_model: bytes | None = None,
    requested: int = 512,
    before: int = 0,
    solve: int = 513,
    cumulative: int = 513,
    unused: int = 0,
    overshoot: int = 1,
    billed: int = 513,
    trail_prunes: int = 0,
) -> JointScoreSieveResult:
    return JointScoreSieveResult(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=1.0,
        key_model=key_model,
        stats={
            "conflicts": cumulative,
            "conflicts_before_solve": before,
            "solve_conflicts": solve,
            "decisions": 9_166,
            "propagations": 1_227_877,
            "requested_conflicts": requested,
            "unused_requested_conflicts": unused,
            "conflict_limit_overshoot": overshoot,
            "billed_conflicts": billed,
        },
        sieve={
            "decision_rule": JOINT_SCORE_SIEVE_DECISION_RULE,
            "root_upper_bound": 100.0,
            "minimum_upper_bound": 100.0,
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": 0,
            "threshold_prunes": trail_prunes,
            "complete_model_score_checks": 0,
        },
        resources={
            "wall_microseconds": 438_847,
            "cpu_microseconds": 1_003_479,
            "peak_rss_bytes": 383_451_136,
        },
        raw={},
    )


def test_request_512_total_513_is_valid_and_billed_513() -> None:
    ledger = validate_native_resource_ledger(
        _native(), solver_calls=1, maximum_native_solver_calls=1
    )
    assert ledger["requested_conflicts"] == 512
    assert ledger["conflicts"] == 513
    assert ledger["conflicts_before_solve"] == 0
    assert ledger["solve_conflicts"] == 513
    assert ledger["conflict_limit_overshoot"] == 1
    assert ledger["billed_conflicts"] == 513


def test_early_recovery_is_valid_without_overshoot() -> None:
    ledger = validate_native_resource_ledger(
        _native(
            solve=7,
            cumulative=11,
            before=4,
            unused=505,
            overshoot=0,
            billed=7,
        ),
        solver_calls=1,
    )
    assert ledger["unused_requested_conflicts"] == 505
    assert ledger["billed_conflicts"] == 7


@pytest.mark.parametrize(
    "stats_change",
    [
        {
            "conflicts": 514,
            "solve_conflicts": 514,
            "conflict_limit_overshoot": 2,
            "billed_conflicts": 514,
        },
        {"conflicts": 512},
        {"conflict_limit_overshoot": 0},
    ],
)
def test_formal_resource_ledger_rejects_mismatch(
    stats_change: dict[str, int],
) -> None:
    native = _native()
    stats = dict(native.stats)
    stats.update(stats_change)
    with pytest.raises(O1C61RunError, match="soft conflict ledger"):
        validate_native_resource_ledger(replace(native, stats=stats), solver_calls=1)


def test_formal_resource_ledger_rejects_missing_field() -> None:
    native = _native()
    stats = dict(native.stats)
    del stats["conflict_limit_overshoot"]
    with pytest.raises(O1C61RunError, match="soft conflict ledger"):
        validate_native_resource_ledger(replace(native, stats=stats), solver_calls=1)


def test_formal_path_gates_science_on_tested_ledger_helper() -> None:
    source = inspect.getsource(run_module._run_impl)
    ledger_gate = source.index("ledger = validate_native_resource_ledger(")
    persisted_gate = source.index('capsule / "conflict_ledger.json"')
    public_diagnostic = source.index('capsule / "public_model_diagnostic.json"')
    truth_access = source.index('capsule / "truth_access_intent.json"')
    classification = source.index("classification, gates = classify_sieve(")
    assert (
        ledger_gate < persisted_gate < public_diagnostic < truth_access < classification
    )


def test_threshold_and_classification_mechanism_are_unchanged() -> None:
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


def test_native_adapter_is_called_once_with_frozen_request(tmp_path: Path) -> None:
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


def test_invalid_post_native_ledger_terminalizes_before_truth_and_preserves_prior_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule = (
        tmp_path
        / "runs/20260719_120000_O1C-0061_multiblock-joint-score-sieve-soft-stop-v1"
    )
    capsule.mkdir(parents=True)
    (capsule / "native_call_intent.json").write_text(
        '{"calls_authorized":1,"recorded_at":"2026-07-19T12:00:00+02:00"}\n',
        encoding="ascii",
    )
    native_payload = b'{"status":0,"stats":{"conflicts":514}}\n'
    (capsule / "native_result.json").write_bytes(native_payload)
    prior_hashes: list[tuple[Path, str]] = []
    for attempt in ("O1C-0059", "O1C-0060"):
        prior = tmp_path / f"runs/immutable_{attempt}_sentinel.bin"
        prior.parent.mkdir(exist_ok=True)
        prior.write_bytes(attempt.encode("ascii"))
        prior_hashes.append((prior, hashlib.sha256(prior.read_bytes()).hexdigest()))
    calls = 0

    def fail_after_native(_config_path: str | Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise O1C61RunError("synthetic invalid soft-stop ledger")

    monkeypatch.setattr(run_module, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(run_module, "_run_impl", fail_after_native)
    result = run_module.run(tmp_path / "unused-config.json")
    assert calls == 1
    failure = result["operational_failure"]
    assert failure["conflict_ledger_persisted"] is False  # type: ignore[index]
    assert failure["truth_key_bytes_read"] is False  # type: ignore[index]
    assert failure["retry_authorized"] is False  # type: ignore[index]
    assert not (capsule / "truth_access_intent.json").exists()
    assert (capsule / "native_result.json").read_bytes() == native_payload
    for prior, digest in prior_hashes:
        assert hashlib.sha256(prior.read_bytes()).hexdigest() == digest
    for path in capsule.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    capsule.chmod(0o755)


def test_frozen_config_binds_all_imported_mechanism_sources() -> None:
    config = load_config(CONFIG)
    source = config["source"]
    assert source["joint_score_sieve"].endswith("_v3.py")  # type: ignore[index,union-attr]
    assert source["joint_score_sieve_v2"].endswith("_v2.py")  # type: ignore[index,union-attr]
    assert source["mechanism_base_runner"].endswith(  # type: ignore[index,union-attr]
        "o1c60_multiblock_joint_score_sieve_run.py"
    )
    assert source["mechanism_transitive_base_runner"].endswith(  # type: ignore[index,union-attr]
        "o1c59_multiblock_joint_score_sieve_run.py"
    )
    native = config["native"]
    assert native["requested_conflicts"] == 512  # type: ignore[index]
    assert native["maximum_billed_conflicts"] == 513  # type: ignore[index]
