from __future__ import annotations

from pathlib import Path

import pytest

from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.joint_score_sieve_softstop_4k import (
    JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DECISION_RULE,
)
from o1_crypto_lab.o1_relational_search import sha256_file
from o1_crypto_lab.o1c62_apple8_4k_run import (
    CONFLICT_LIMIT,
    MEMORY_LIMIT_BYTES,
    NATIVE_TIMEOUT_SECONDS,
    O1C62RunError,
    SUSTAINED_SCALING_MINIMUM_PRUNES,
    _finalize_consumed_call_terminally,
    classify_scaling,
    finalize_capsule,
    invoke_native_once,
    load_config,
    preflight,
    public_model_then_truth_diagnostic,
    validate_native_resource_ledger,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c62_apple8_4k_v1.json"
APPLE_CAPSULE = (
    ROOT
    / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
)
APPLE_RESULT = ROOT / "research/apple_view_8/apple_view_8_matched_result.json"


def _native(
    *,
    status: int = 0,
    key_model: bytes | None = None,
    requested: int = 4_096,
    before: int = 0,
    solve: int = 4_097,
    cumulative: int = 4_097,
    unused: int = 0,
    overshoot: int = 1,
    billed: int = 4_097,
    trail_prunes: int = 24,
) -> JointScoreSieveResult:
    return JointScoreSieveResult(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=14.606178797892962,
        key_model=key_model,
        stats={
            "conflicts": cumulative,
            "conflicts_before_solve": before,
            "solve_conflicts": solve,
            "decisions": 20_000,
            "propagations": 2_000_000,
            "requested_conflicts": requested,
            "unused_requested_conflicts": unused,
            "conflict_limit_overshoot": overshoot,
            "billed_conflicts": billed,
        },
        sieve={
            "decision_rule": JOINT_SCORE_SIEVE_DECISION_RULE,
            "root_upper_bound": 292.30611344510277,
            "minimum_upper_bound": 12.0,
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": 0,
            "threshold_prunes": trail_prunes,
            "complete_model_score_checks": 0,
        },
        resources={
            "wall_microseconds": 5_000_000,
            "cpu_microseconds": 5_000_000,
            "peak_rss_bytes": 400_000_000,
        },
        raw={"schema": "o1-256-cadical-joint-score-sieve-result-v2"},
    )


def _make_writable(capsule: Path) -> None:
    if not capsule.exists():
        return
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _terminal_result() -> dict[str, object]:
    return {
        "classification": "O1C62_APPLE8_4K_SUSTAINED_SCALING",
        "claim_boundary": {
            "truth_key_bytes_read_after_public_diagnostic": False,
            "different_budget_work_is_matched": False,
        },
        "resources": {
            "native_solver_calls": 1,
            "requested_conflicts": 4_096,
            "billed_conflicts": 4_097,
            "persistent_artifact_bytes": 0,
        },
    }


def test_actual_positive_apple8_preflight_is_read_only_and_zero_science() -> None:
    before = {
        "manifest": sha256_file(APPLE_CAPSULE / "artifacts.sha256"),
        "capsule_result": sha256_file(APPLE_CAPSULE / "result.json"),
        "authoritative_result": sha256_file(APPLE_RESULT),
    }
    result = preflight(CONFIG)
    after = {
        "manifest": sha256_file(APPLE_CAPSULE / "artifacts.sha256"),
        "capsule_result": sha256_file(APPLE_CAPSULE / "result.json"),
        "authoritative_result": sha256_file(APPLE_RESULT),
    }
    assert before == after
    assert result["ok"] is True
    assert result["ready_for_science"] is False
    assert result["native_solver_calls"] == 0
    assert result["files_written"] == 0
    assert result["truth_key_bytes_read"] is False
    assert result["cnf_sha256"] == (
        "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432"
    )


def test_native_adapter_is_one_frozen_4k_call(tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    expected = _native()

    def fake_runner(**kwargs: object) -> JointScoreSieveResult:
        calls.append(dict(kwargs))
        return expected

    observed = invoke_native_once(
        executable=tmp_path / "native",
        cnf=tmp_path / "apple.cnf",
        potential=tmp_path / "apple.potential",
        runner=fake_runner,
    )
    assert observed is expected
    assert len(calls) == 1
    assert calls[0]["conflict_limit"] == 4_096
    assert calls[0]["timeout_seconds"] == 30.0
    assert calls[0]["memory_limit_bytes"] == 805_306_368
    assert calls[0]["seed"] == 0


def test_4k_resource_ledger_accepts_4097_and_early_finish() -> None:
    ledger = validate_native_resource_ledger(_native(), solver_calls=1)
    assert ledger["requested_conflicts"] == 4_096
    assert ledger["billed_conflicts"] == 4_097
    early = validate_native_resource_ledger(
        _native(
            before=4,
            solve=7,
            cumulative=11,
            unused=4_089,
            overshoot=0,
            billed=7,
        ),
        solver_calls=1,
    )
    assert early["unused_requested_conflicts"] == 4_089
    assert early["billed_conflicts"] == 7


def test_no_model_unknown_or_unsat_reads_truth_zero() -> None:
    for status in (0, 20):
        callbacks: list[str] = []
        public_ledger = [False]
        result = public_model_then_truth_diagnostic(
            _native(status=status, trail_prunes=0),
            verify_public_model=lambda _: callbacks.append("public") is None,
            read_truth_key=lambda: callbacks.append("truth") or bytes(32),
            public_diagnostic_ledger=public_ledger,
        )
        assert result == (False, None, None)
        assert callbacks == []
        assert public_ledger == [True]


def test_unsat_fails_closed_before_scaling_classification() -> None:
    with pytest.raises(
        O1C62RunError, match="contradicts the frozen satisfiable public target"
    ):
        classify_scaling(
            _native(status=20, trail_prunes=100),
            public_model_verified=False,
            billed_conflicts=4_097,
        )


@pytest.mark.parametrize(
    ("prunes", "classification"),
    [
        (24, "O1C62_APPLE8_4K_SUSTAINED_SCALING"),
        (23, "O1C62_APPLE8_4K_ACTIVE_SUBLINEAR"),
        (1, "O1C62_APPLE8_4K_ACTIVE_SUBLINEAR"),
        (0, "O1C62_APPLE8_4K_SCALING_REGRESSION"),
    ],
)
def test_scaling_gate_is_exact(prunes: int, classification: str) -> None:
    observed, metrics = classify_scaling(
        _native(trail_prunes=prunes),
        public_model_verified=False,
        billed_conflicts=4_097,
    )
    assert SUSTAINED_SCALING_MINIMUM_PRUNES == 24
    assert observed == classification
    assert metrics["different_budget_work_is_matched"] is False


def test_terminal_capsule_is_immutable_and_no_overwrite(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    authoritative = tmp_path / "result.json"
    result = _terminal_result()
    try:
        finalize_capsule(
            capsule=capsule,
            authoritative_result=authoritative,
            result=result,
            maximum_persistent_bytes=1_000_000,
        )
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
        assert capsule.stat().st_mode & 0o777 == 0o555
        assert (capsule / "artifacts.sha256").is_file()
        with pytest.raises(O1C62RunError, match="already exists"):
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=1_000_000,
            )
    finally:
        _make_writable(capsule)


def test_post_seal_failure_recovers_to_one_terminal_authoritative_result(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    (capsule / "native_result.json").write_text("{}\n", encoding="ascii")
    authoritative = tmp_path / "result.json"

    def fail_after_seal() -> None:
        raise OSError("injected post-seal failure")

    try:
        terminal = _finalize_consumed_call_terminally(
            capsule=capsule,
            authoritative_result=authoritative,
            result=_terminal_result(),
            maximum_persistent_bytes=1_000_000,
            capsule_relative=Path("runs/O1C62-test"),
            source_commit="a" * 40,
            preflight_row={"native_solver_calls": 0},
            _after_capsule_seal=fail_after_seal,
        )
        assert terminal["classification"] == (
            "O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        )
        resources = terminal["resources"]
        assert isinstance(resources, dict)
        assert resources["native_solver_calls"] == 1
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
        assert capsule.stat().st_mode & 0o777 == 0o555
        assert (capsule / "publication_failure.json").is_file()
        with pytest.raises(O1C62RunError, match="already exists"):
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=_terminal_result(),
                maximum_persistent_bytes=1_000_000,
            )
    finally:
        _make_writable(capsule)


def test_config_freezes_new_ledger_and_limits() -> None:
    config = load_config(CONFIG)
    assert config["native"] == {
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_conflict_limit_overshoot": 1,
        "maximum_billed_conflicts": 4_097,
        "soft_conflict_ledger_schema": JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
        "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "calls": 1,
    }
