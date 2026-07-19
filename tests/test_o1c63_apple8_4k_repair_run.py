from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import o1_crypto_lab.o1c63_apple8_4k_repair_run as repair_run
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.o1_relational_search import NativeGuidedSearchBuild, sha256_file
from o1_crypto_lab.o1c63_apple8_4k_repair_run import (
    CONFLICT_LIMIT,
    MAXIMUM_BILLED_CONFLICTS,
    MAXIMUM_NATIVE_FAILURE_STREAM_BYTES,
    MEMORY_LIMIT_BYTES,
    NATIVE_TIMEOUT_SECONDS,
    O1C62_MANIFEST_SHA256,
    O1C62_RESULT_SHA256,
    O1C63RunError,
    PENDING_BACKTRACK_RULE,
    SOFT_CONFLICT_LEDGER_SCHEMA,
    SUSTAINED_SCALING_MINIMUM_PRUNES,
    TEARDOWN_RULE,
    _finalize_consumed_call_terminally,
    classify_scaling,
    finalize_capsule,
    invoke_native_once,
    invoke_native_once_terminal,
    load_config,
    preflight,
    public_model_then_truth_diagnostic,
    validate_native_resource_ledger,
    validate_native_build_identity,
    validate_o1c62_repair_provenance,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c63_apple8_4k_repair_v1.json"
O1C62_RESULT = ROOT / "research/O1C0062_APPLE8_CROSSBLOCK_SIEVE_4K_RESULT_20260719.json"
O1C62_CAPSULE = (
    ROOT / "runs/20260719_102136_O1C-0062_apple8-crossblock-consequence-sieve-4k-v1"
)


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
    model_prunes: int = 0,
    emitted: int | None = None,
) -> JointScoreSieveResult:
    state = {0: (256, "INCONCLUSIVE"), 10: (32, "SATISFIED"), 20: (64, "UNSATISFIED")}[
        status
    ]
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
            "decision_rule": repair_run.JOINT_SCORE_SIEVE_DECISION_RULE,
            "root_upper_bound": 292.30611344510277,
            "minimum_upper_bound": 12.0,
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": model_prunes,
            "threshold_prunes": trail_prunes + model_prunes,
            "external_clauses_queued": trail_prunes + model_prunes,
            "external_clauses_emitted": (
                trail_prunes + model_prunes if emitted is None else emitted
            ),
            "complete_model_score_checks": 0,
        },
        resources={
            "wall_microseconds": 5_000_000,
            "cpu_microseconds": 5_000_000,
            "peak_rss_bytes": 400_000_000,
        },
        raw={
            "schema": "o1-256-cadical-joint-score-sieve-result-v4",
            "status": status,
            "implementation_parent_schema": (
                "o1-256-cadical-joint-score-sieve-result-v2"
            ),
            "post_solve_state": state[0],
            "post_solve_state_name": state[1],
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
        },
    )


def test_native_build_identity_rejects_wrong_executable_before_call(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "cadical-o1-joint-score-sieve-v4"
    command = ("c++", "-o", str(executable))
    valid = NativeGuidedSearchBuild(
        executable=executable,
        command=command,
        source_sha256=repair_run.NATIVE_SOURCE_SHA256,
        cadical_header_sha256="11" * 32,
        cadical_library_sha256="22" * 32,
        executable_sha256=repair_run.NATIVE_EXECUTABLE_SHA256,
    )
    validate_native_build_identity(valid)
    invalid = NativeGuidedSearchBuild(
        executable=executable,
        command=command,
        source_sha256=valid.source_sha256,
        cadical_header_sha256=valid.cadical_header_sha256,
        cadical_library_sha256=valid.cadical_library_sha256,
        executable_sha256="00" * 32,
    )
    with pytest.raises(O1C63RunError, match="build identity"):
        validate_native_build_identity(invalid)


def _make_writable(capsule: Path) -> None:
    if not capsule.exists():
        return
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _terminal_result() -> dict[str, object]:
    return {
        "classification": "O1C63_APPLE8_4K_REPAIR_SUSTAINED_SCALING",
        "claim_boundary": {
            "new_attempt_not_o1c62_retry": True,
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


def test_source_hashes_and_native_lifecycle_contract_are_frozen() -> None:
    config = load_config(CONFIG)
    source = config["source"]
    assert isinstance(source, dict)
    expected = source["expected_sha256"]
    assert isinstance(expected, dict)
    for name, relative in source.items():
        if name == "expected_sha256":
            continue
        assert isinstance(relative, str)
        assert sha256_file(ROOT / relative) == expected[name]
    native = config["native"]
    assert native == {
        "requested_conflicts": 4_096,
        "maximum_conflict_limit_overshoot": 1,
        "maximum_billed_conflicts": 4_097,
        "timeout_seconds": 30.0,
        "memory_limit_bytes": 805_306_368,
        "seed": 0,
        "calls": 1,
        "result_schema": "o1-256-cadical-joint-score-sieve-result-v4",
        "executable_sha256": repair_run.NATIVE_EXECUTABLE_SHA256,
        "implementation_parent_schema": ("o1-256-cadical-joint-score-sieve-result-v2"),
        "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
        "teardown_rule": TEARDOWN_RULE,
        "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
        "repair_scope": (
            "connected-propagator-destruction-and-pending-no-good-backtrack-lifecycle"
        ),
    }


def test_source_hash_drift_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    real_sha256 = repair_run.sha256_file

    def drift(path: Path) -> str:
        if Path(path).name == "joint_score_sieve_v5.py":
            return "0" * 64
        return real_sha256(path)

    monkeypatch.setattr(repair_run, "sha256_file", drift)
    with pytest.raises(O1C63RunError, match="source hash differs"):
        load_config(CONFIG)


def test_o1c62_terminal_failure_is_bound_as_read_only_repair_provenance() -> None:
    before = {
        "result": sha256_file(O1C62_RESULT),
        "manifest": sha256_file(O1C62_CAPSULE / "artifacts.sha256"),
        "native_failure": sha256_file(O1C62_CAPSULE / "native_failure.json"),
    }
    config = load_config(CONFIG)
    observed = validate_o1c62_repair_provenance(ROOT, config)
    after = {
        "result": sha256_file(O1C62_RESULT),
        "manifest": sha256_file(O1C62_CAPSULE / "artifacts.sha256"),
        "native_failure": sha256_file(O1C62_CAPSULE / "native_failure.json"),
    }
    assert before == after
    assert after["result"] == O1C62_RESULT_SHA256
    assert after["manifest"] == O1C62_MANIFEST_SHA256
    assert observed.result["classification"] == (
        "O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
    )
    assert observed.native_failure["native_calls_consumed"] == 1
    assert observed.native_failure["retry_authorized"] is False
    assert observed.native_failure["truth_key_bytes_read"] is False
    assert O1C62_CAPSULE.stat().st_mode & 0o222 == 0


def test_preflight_is_zero_science_and_commit_binding_covers_all_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit_bound: list[str] = []
    monkeypatch.setattr(repair_run, "_git_commit", lambda _: "a" * 40)
    monkeypatch.setattr(
        repair_run,
        "_commit_bound_bytes",
        lambda _root, _commit, _path, name: commit_bound.append(name),
    )
    result = preflight(CONFIG, require_commit_binding=True)
    assert result["ready_for_science"] is True
    assert result["source_commit_bound"] is True
    assert result["native_solver_calls"] == 0
    assert result["files_written"] == 0
    assert result["truth_key_bytes_read"] is False
    assert result["new_attempt_not_o1c62_retry"] is True
    assert result["o1c62_native_calls_consumed"] == 1
    assert result["o1c62_retry_authorized"] is False
    assert commit_bound == [*repair_run.SOURCE_NAMES, "config"]


def test_native_adapter_is_exactly_one_frozen_4k_call(tmp_path: Path) -> None:
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


def test_native_v5_lifecycle_and_4k_ledger_are_required() -> None:
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
    wrong = _native()
    wrong.raw["teardown_rule"] = "explicit-disconnect"
    with pytest.raises(O1C63RunError, match="lifecycle or ledger differs"):
        validate_native_resource_ledger(wrong, solver_calls=1)


def test_structured_native_failure_telemetry_and_bounded_raw_files_are_published(
    tmp_path: Path,
) -> None:
    class NativeProcessFailure(RuntimeError):
        returncode = -9
        stdout = b"A" * (MAXIMUM_NATIVE_FAILURE_STREAM_BYTES + 17)
        stderr = b"original native error\n"
        telemetry = {"phase": "solve", "watchdog_fired": True}

    def fail(**_: object) -> JointScoreSieveResult:
        raise NativeProcessFailure("native failed")

    native, failure = invoke_native_once_terminal(
        executable=tmp_path / "native",
        cnf=tmp_path / "apple.cnf",
        potential=tmp_path / "apple.potential",
        runner=fail,
        failure_directory=tmp_path,
    )
    assert native is None
    assert failure is not None
    telemetry = failure["native_failure_telemetry"]
    assert isinstance(telemetry, dict)
    assert telemetry["returncode"] == -9
    assert telemetry["signal_number"] == 9
    assert telemetry["signal_name"] == "SIGKILL"
    stdout = telemetry["stdout"]
    stderr = telemetry["stderr"]
    assert isinstance(stdout, dict) and isinstance(stderr, dict)
    assert stdout["bytes"] == MAXIMUM_NATIVE_FAILURE_STREAM_BYTES + 17
    assert stdout["truncated"] is True
    assert stdout["sha256"] == hashlib.sha256(NativeProcessFailure.stdout).hexdigest()
    assert (tmp_path / "native_failure.stdout").stat().st_size == (
        MAXIMUM_NATIVE_FAILURE_STREAM_BYTES
    )
    assert (tmp_path / "native_failure.stderr").read_bytes() == (
        NativeProcessFailure.stderr
    )
    assert stderr["sha256"] == hashlib.sha256(NativeProcessFailure.stderr).hexdigest()
    structured = telemetry["structured"]
    assert isinstance(structured, dict)
    assert structured["telemetry"] == {
        "phase": "solve",
        "watchdog_fired": True,
    }


def test_truth_isolated_until_present_model_publicly_verifies_8_of_8() -> None:
    for status in (0, 20):
        callbacks: list[str] = []
        ledger = [False]
        observed = public_model_then_truth_diagnostic(
            _native(status=status, trail_prunes=0),
            verify_public_model=lambda _: callbacks.append("public") is None,
            read_truth_key=lambda: callbacks.append("truth") or bytes(32),
            public_diagnostic_ledger=ledger,
        )
        assert observed == (False, None, None)
        assert callbacks == []
        assert ledger == [True]

    callbacks = []
    with pytest.raises(O1C63RunError, match="fails eight public blocks"):
        public_model_then_truth_diagnostic(
            _native(status=10, key_model=b"m" * 32),
            verify_public_model=lambda _: callbacks.append("public") and False,
            read_truth_key=lambda: callbacks.append("truth") or bytes(32),
            public_diagnostic_ledger=[False],
        )
    assert callbacks == ["public"]

    callbacks = []
    observed = public_model_then_truth_diagnostic(
        _native(status=10, key_model=b"m" * 32),
        verify_public_model=lambda _: callbacks.append("public") is None,
        read_truth_key=lambda: callbacks.append("truth") or b"m" * 32,
        public_diagnostic_ledger=[False],
    )
    assert observed == (True, b"m" * 32, True)
    assert callbacks == ["public", "truth"]


def test_status20_fails_closed_before_any_valid_classification() -> None:
    with pytest.raises(
        O1C63RunError, match="contradicts the frozen satisfiable public target"
    ):
        classify_scaling(
            _native(status=20, trail_prunes=100),
            public_model_verified=False,
            billed_conflicts=4_097,
        )


@pytest.mark.parametrize(
    ("prunes", "classification"),
    [
        (24, "O1C63_APPLE8_4K_REPAIR_SUSTAINED_SCALING"),
        (23, "O1C63_APPLE8_4K_REPAIR_ACTIVE_SUBLINEAR"),
        (1, "O1C63_APPLE8_4K_REPAIR_ACTIVE_SUBLINEAR"),
        (0, "O1C63_APPLE8_4K_REPAIR_SCALING_REGRESSION"),
    ],
)
def test_scaling_classification_boundaries_are_exact(
    prunes: int, classification: str
) -> None:
    observed, metrics = classify_scaling(
        _native(trail_prunes=prunes),
        public_model_verified=False,
        billed_conflicts=4_097,
    )
    assert SUSTAINED_SCALING_MINIMUM_PRUNES == 24
    assert observed == classification
    assert metrics["different_budget_work_is_matched"] is False


@pytest.mark.parametrize(
    ("queued", "emitted", "classification", "lower_bound"),
    [
        (25, 24, "O1C63_APPLE8_4K_REPAIR_SUSTAINED_SCALING", 24),
        (24, 23, "O1C63_APPLE8_4K_REPAIR_ACTIVE_SUBLINEAR", 23),
        (1, 0, "O1C63_APPLE8_4K_REPAIR_SCALING_REGRESSION", 0),
    ],
)
def test_pending_no_good_is_retained_but_not_counted_as_emitted_search_effect(
    queued: int, emitted: int, classification: str, lower_bound: int
) -> None:
    observed, metrics = classify_scaling(
        _native(trail_prunes=queued, emitted=emitted),
        public_model_verified=False,
        billed_conflicts=4_097,
    )
    assert observed == classification
    assert metrics["queued_certified_trail_no_goods"] == queued
    assert metrics["external_clauses_emitted"] == emitted
    assert metrics["pending_exact_no_good_count"] == 1
    assert metrics["emitted_certified_trail_prune_lower_bound"] == lower_bound


def test_more_than_one_pending_no_good_fails_closed() -> None:
    with pytest.raises(O1C63RunError, match="prune emission ledger differs"):
        classify_scaling(
            _native(trail_prunes=24, emitted=22),
            public_model_verified=False,
            billed_conflicts=4_097,
        )


def test_exact_recovery_requires_sat_present_publicly_verified_model() -> None:
    observed, metrics = classify_scaling(
        _native(status=10, key_model=b"m" * 32, trail_prunes=0),
        public_model_verified=True,
        billed_conflicts=7,
    )
    assert observed == "O1C63_EXACT_PUBLIC_FULL256_RECOVERY"
    promotion = metrics["promotion"]
    assert isinstance(promotion, dict)
    assert promotion["exact_recovery"] is True
    with pytest.raises(O1C63RunError, match="publicly verified"):
        classify_scaling(
            _native(status=10, key_model=b"m" * 32),
            public_model_verified=False,
            billed_conflicts=4_097,
        )


def test_terminal_capsule_is_immutable_mirrored_and_never_overwritten(
    tmp_path: Path,
) -> None:
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
        with pytest.raises(O1C63RunError, match="already exists"):
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
            capsule_relative=Path("runs/O1C63-test"),
            source_commit="a" * 40,
            preflight_row={"native_solver_calls": 0},
            _after_capsule_seal=fail_after_seal,
        )
        assert terminal["classification"] == (
            "O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        )
        resources = terminal["resources"]
        assert isinstance(resources, dict)
        assert resources["native_solver_calls"] == 1
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
        assert capsule.stat().st_mode & 0o777 == 0o555
        failure = json.loads((capsule / "publication_failure.json").read_bytes())
        assert failure["publication_recovered"] is True
        assert failure["retry_authorized"] is False
        with pytest.raises(O1C63RunError, match="already exists"):
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=_terminal_result(),
                maximum_persistent_bytes=1_000_000,
            )
    finally:
        _make_writable(capsule)


def test_frozen_limits_are_unchanged() -> None:
    assert CONFLICT_LIMIT == 4_096
    assert MAXIMUM_BILLED_CONFLICTS == 4_097
    assert NATIVE_TIMEOUT_SECONDS == 30.0
    assert MEMORY_LIMIT_BYTES == 805_306_368
