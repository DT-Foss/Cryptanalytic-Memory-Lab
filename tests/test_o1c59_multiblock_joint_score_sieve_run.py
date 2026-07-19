from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

import pytest

import o1_crypto_lab.o1c59_multiblock_joint_score_sieve_run as run_module
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.o1c59_multiblock_joint_score_sieve_run import (
    CONFLICT_LIMIT,
    MEMORY_LIMIT_BYTES,
    NATIVE_TIMEOUT_SECONDS,
    O1C59RunError,
    RESULT_RELATIVE,
    _finalize_capsule,
    _invoke_native_once,
    _invoke_native_once_terminal,
    _manifest_inventory,
    _verify_truth_after_native,
    classify_sieve,
    load_config,
    prospective_threshold,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c59_multiblock_joint_score_sieve_v1.json"


def _native(
    *,
    status: int = 0,
    key_model: bytes | None = None,
    root_upper: float = 100.0,
    minimum_upper: float = 100.0,
    trail_prunes: int = 0,
    model_prunes: int = 0,
) -> JointScoreSieveResult:
    sieve = {
        "root_upper_bound": root_upper,
        "minimum_upper_bound": minimum_upper,
        "trail_threshold_prunes": trail_prunes,
        "model_threshold_prunes": model_prunes,
        "threshold_prunes": trail_prunes + model_prunes,
        "complete_model_score_checks": model_prunes,
    }
    return JointScoreSieveResult(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=1.0,
        key_model=key_model,
        stats={},
        sieve=sieve,
        resources={},
        raw={},
    )


def test_prospective_threshold_is_strict_and_exactly_outward() -> None:
    decoy_max = 14.606178797992964
    expected = __import__("math").nextafter(decoy_max - 1e-10, -__import__("math").inf)
    assert prospective_threshold(decoy_max, 1e-10) == expected
    assert expected < decoy_max
    with pytest.raises(O1C59RunError, match="threshold input"):
        prospective_threshold(decoy_max, 0.0)


def test_classification_ladder_distinguishes_safe_early_and_late_only() -> None:
    exact, exact_metrics = classify_sieve(
        _native(status=10, key_model=b"x" * 32),
        public_model_verified=True,
        minimum_material_bound_drop=1.0,
    )
    assert exact == "EXACT_CONSUMED_FULL256_RECOVERY"
    assert exact_metrics["public_model_verified"] is True

    pruned, pruned_metrics = classify_sieve(
        _native(trail_prunes=1),
        public_model_verified=False,
        minimum_material_bound_drop=1.0,
    )
    assert pruned == "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY"
    assert pruned_metrics["safe_trail_threshold_prunes"] == 1

    bounded, bounded_metrics = classify_sieve(
        _native(root_upper=100.0, minimum_upper=98.75),
        public_model_verified=False,
        minimum_material_bound_drop=1.0,
    )
    assert bounded == "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY"
    assert bounded_metrics["material_bound_drop"] is True

    late, late_metrics = classify_sieve(
        _native(model_prunes=1, root_upper=100.0, minimum_upper=99.5),
        public_model_verified=False,
        minimum_material_bound_drop=1.0,
    )
    assert late == "EXACT_JOINT_SCORE_SIEVE_NO_USEFUL_PRUNE"
    assert late_metrics["late_only_prune"] is True


def test_native_adapter_is_called_once_with_formal_memory_ceiling(
    tmp_path: Path,
) -> None:
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
    assert calls[0]["memory_limit_bytes"] == MEMORY_LIMIT_BYTES
    assert calls[0]["conflict_limit"] == CONFLICT_LIMIT
    assert calls[0]["timeout_seconds"] == NATIVE_TIMEOUT_SECONDS
    assert calls[0]["seed"] == 0


def test_exception_after_persisted_intent_becomes_terminal_without_retry(
    tmp_path: Path,
) -> None:
    intent = tmp_path / "native_call_intent.json"
    intent.write_text('{"calls_authorized":1}\n', encoding="ascii")
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
    assert intent.is_file()
    assert calls == 1
    assert result is None
    assert failure is not None
    assert failure["classification"] == "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT"
    assert failure["native_calls_consumed"] == 1
    assert failure["retry_authorized"] is False
    assert failure["truth_key_bytes_read"] is False


def test_operational_failure_capsule_terminalizes_immutably(tmp_path: Path) -> None:
    capsule = tmp_path / "runs/failure"
    capsule.mkdir(parents=True)
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    result: dict[str, object] = {
        "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
        "metrics": {"native_status": "OPERATIONAL_FAILURE"},
        "operational_failure": {
            "error_type": "TimeoutError",
            "native_calls_consumed": 1,
        },
        "resources": {"persistent_artifact_bytes": 0},
    }
    _finalize_capsule(
        root=tmp_path,
        capsule=capsule,
        result=result,
        maximum_persistent_bytes=1_000_000,
    )
    assert (capsule / "artifacts.sha256").is_file()
    assert (capsule / "result.json").is_file()
    assert (tmp_path / RESULT_RELATIVE).is_file()
    assert capsule.stat().st_mode & 0o777 == 0o555
    assert (capsule / "result.json").stat().st_mode & 0o777 == 0o444
    for path in capsule.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    capsule.chmod(0o755)


def test_post_native_validation_failure_terminalizes_without_second_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capsule = (
        tmp_path
        / "runs/20260719_120000_O1C-0059_multiblock-joint-score-sieve-v1"
    )
    capsule.mkdir(parents=True)
    (capsule / "native_call_intent.json").write_text(
        '{"calls_authorized":1,"recorded_at":"2026-07-19T12:00:00+02:00"}\n',
        encoding="ascii",
    )
    native_payload = b'{"status":0,"stats":{"conflicts":1}}\n'
    (capsule / "native_result.json").write_bytes(native_payload)
    calls = 0

    def fail_after_native(_config_path: str | Path) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise O1C59RunError("synthetic public replay failure")

    monkeypatch.setattr(run_module, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(run_module, "_run_impl", fail_after_native)
    result = run_module.run(tmp_path / "unused-config.json")

    assert calls == 1
    assert result["classification"] == (
        "OPERATIONAL_POST_NATIVE_VALIDATION_FAILURE_NO_SCIENCE_CLAIM"
    )
    failure = result["operational_failure"]
    assert failure["native_calls_consumed"] == 1  # type: ignore[index]
    assert failure["retry_authorized"] is False  # type: ignore[index]
    assert failure["truth_key_bytes_read"] is False  # type: ignore[index]
    assert (capsule / "native_result.json").read_bytes() == native_payload
    assert (capsule / "artifacts.sha256").is_file()
    assert (capsule / "result.json").is_file()
    assert (tmp_path / RESULT_RELATIVE).is_file()
    assert capsule.stat().st_mode & 0o777 == 0o555
    assert (capsule / "native_result.json").stat().st_mode & 0o777 == 0o444
    for path in capsule.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    capsule.chmod(0o755)


def test_consumed_manifest_requires_exact_hashes_and_inventory(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    rows = []
    for index in range(80):
        relative = f"member-{index:02d}.bin"
        payload = bytes([index])
        (capsule / relative).write_bytes(payload)
        rows.append(f"{hashlib.sha256(payload).hexdigest()}  {relative}\n")
    manifest = "".join(rows).encode("ascii")
    (capsule / "artifacts.sha256").write_bytes(manifest)
    digest = hashlib.sha256(manifest).hexdigest()
    inventory = _manifest_inventory(capsule, expected_manifest_sha256=digest)
    assert len(inventory) == 80
    (capsule / "member-17.bin").write_bytes(b"tampered")
    with pytest.raises(O1C59RunError, match="artifact differs"):
        _manifest_inventory(capsule, expected_manifest_sha256=digest)


def test_truth_helper_refuses_access_before_native_public_diagnostic() -> None:
    with pytest.raises(O1C59RunError, match="preceded"):
        _verify_truth_after_native(
            cast(object, None),  # type: ignore[arg-type]
            cast(object, None),  # type: ignore[arg-type]
            cast(object, None),  # type: ignore[arg-type]
            native=_native(),
            public_model_diagnostic_complete=False,
        )


def test_frozen_config_and_all_hash_bindings_load() -> None:
    config = load_config(CONFIG)
    assert config["attempt_id"] == "O1C-0059"
    assert config["native"]["calls"] == 1  # type: ignore[index]
    assert config["budgets"]["maximum_peak_rss_bytes"] == MEMORY_LIMIT_BYTES  # type: ignore[index]
