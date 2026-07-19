from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import pytest

import o1_crypto_lab.o1c64_apple8_4k_resource_fix_run as resource_run
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.o1_relational_search import NativeGuidedSearchBuild, sha256_file
from o1_crypto_lab.o1c64_apple8_4k_resource_fix_run import (
    CONFLICT_LIMIT,
    DARWIN_WATCHDOG_GUARD_BYTES,
    DARWIN_WATCHDOG_INTERVAL_SECONDS,
    DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES,
    EXPECTED_NATIVE_EXECUTABLE_SHA256,
    MEMORY_LIMIT_BYTES,
    NATIVE_EXECUTION_FAILURE_SCHEMA,
    NATIVE_TIMEOUT_SECONDS,
    O1C63_MANIFEST_SHA256,
    O1C63_RESULT_SHA256,
    O1C64RunError,
    PENDING_BACKTRACK_RULE,
    SOFT_CONFLICT_LEDGER_SCHEMA,
    TEARDOWN_RULE,
    _finalize_consumed_call_terminally,
    classify_scaling,
    finalize_capsule,
    invoke_native_once,
    invoke_native_once_terminal,
    load_config,
    native_failure_telemetry,
    preflight,
    public_model_then_truth_diagnostic,
    run,
    validate_native_resource_ledger,
    validate_o1c63_resource_fix_provenance,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c64_apple8_4k_resource_fix_v1.json"
O1C63_RESULT = (
    ROOT / "research/O1C0063_APPLE8_CROSSBLOCK_SIEVE_4K_REPAIR_RESULT_20260719.json"
)
O1C63_CAPSULE = (
    ROOT
    / "runs/20260719_110348_O1C-0063_apple8-crossblock-consequence-sieve-4k-repair-v1"
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
    wall_microseconds: int = 5_000_000,
    peak_rss_bytes: int = 400_000_000,
) -> JointScoreSieveResult:
    state = {
        0: (256, "INCONCLUSIVE"),
        10: (32, "SATISFIED"),
        20: (64, "UNSATISFIED"),
    }[status]
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
            "decision_rule": resource_run.JOINT_SCORE_SIEVE_DECISION_RULE,
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
            "wall_microseconds": wall_microseconds,
            "cpu_microseconds": wall_microseconds,
            "peak_rss_bytes": peak_rss_bytes,
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


def _make_writable(capsule: Path) -> None:
    if not capsule.exists():
        return
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _terminal_result() -> dict[str, object]:
    return {
        "classification": "O1C64_APPLE8_4K_RESOURCE_FIX_SUSTAINED_SCALING",
        "claim_boundary": {
            "new_attempt_not_o1c63_retry": True,
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


def test_source_hashes_resources_and_terminal_o1c63_provenance_are_frozen() -> None:
    before = {
        "result": sha256_file(O1C63_RESULT),
        "manifest": sha256_file(O1C63_CAPSULE / "artifacts.sha256"),
        "native_failure": sha256_file(O1C63_CAPSULE / "native_failure.json"),
    }
    config = load_config(CONFIG)
    source = config["source"]
    assert isinstance(source, dict)
    expected = source["expected_sha256"]
    assert isinstance(expected, dict)
    for name, relative in source.items():
        if name != "expected_sha256":
            assert isinstance(relative, str)
            assert sha256_file(ROOT / relative) == expected[name]
    assert config["native"] == {
        "requested_conflicts": 4_096,
        "maximum_conflict_limit_overshoot": 1,
        "maximum_billed_conflicts": 4_097,
        "timeout_seconds": 45.0,
        "memory_limit_bytes": 1_073_741_824,
        "seed": 0,
        "calls": 1,
        "result_schema": "o1-256-cadical-joint-score-sieve-result-v4",
        "implementation_parent_schema": ("o1-256-cadical-joint-score-sieve-result-v2"),
        "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
        "teardown_rule": TEARDOWN_RULE,
        "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
        "execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
        "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
        "darwin_watchdog_kill_threshold_bytes": (DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES),
        "darwin_watchdog_poll_interval_seconds": (DARWIN_WATCHDOG_INTERVAL_SECONDS),
        "expected_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "same_native_science_as_o1c63": True,
    }
    observed = validate_o1c63_resource_fix_provenance(ROOT, config)
    binding = resource_run._resource_fix_binding_row(
        root=ROOT, predecessor=observed, config=config
    )
    ready = preflight(CONFIG)
    after = {
        "result": sha256_file(O1C63_RESULT),
        "manifest": sha256_file(O1C63_CAPSULE / "artifacts.sha256"),
        "native_failure": sha256_file(O1C63_CAPSULE / "native_failure.json"),
    }
    assert before == after
    assert before["result"] == O1C63_RESULT_SHA256
    assert before["manifest"] == O1C63_MANIFEST_SHA256
    assert observed.result["classification"] == (
        "O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
    )
    assert binding["schema"] == ("o1-256-o1c64-terminal-resource-fix-provenance-v1")
    assert ready["ready_for_science"] is False
    assert ready["new_attempt_not_o1c63_retry"] is True
    assert ready["native_solver_calls"] == 0
    assert ready["truth_key_bytes_read"] is False
    assert ready["timeout_seconds"] == 45.0
    assert ready["memory_limit_bytes"] == 1_073_741_824


def test_one_call_wrapper_has_exact_science_and_new_resource_ceiling() -> None:
    calls: list[dict[str, object]] = []
    expected = _native()

    def fake(**kwargs: object) -> JointScoreSieveResult:
        calls.append(kwargs)
        return expected

    observed = invoke_native_once(
        executable=Path("solver"),
        cnf=Path("target.cnf"),
        potential=Path("target.potential"),
        runner=fake,
    )
    assert observed is expected
    assert calls == [
        {
            "executable": Path("solver"),
            "cnf_path": Path("target.cnf"),
            "potential_path": Path("target.potential"),
            "threshold": 14.606178797892962,
            "conflict_limit": 4_096,
            "seed": 0,
            "timeout_seconds": 45.0,
            "memory_limit_bytes": 1_073_741_824,
        }
    ]


def test_native_build_mismatch_fails_before_capsule_intent_or_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="ascii")
    native_source = tmp_path / "native.cpp"
    native_source.write_text("// frozen\n", encoding="ascii")
    executable = tmp_path / "solver"
    executable.write_bytes(b"wrong binary")
    build = NativeGuidedSearchBuild(
        executable=executable,
        command=("c++", "-o", str(executable)),
        source_sha256=resource_run.EXPECTED_NATIVE_SOURCE_SHA256,
        cadical_header_sha256="11" * 32,
        cadical_library_sha256="22" * 32,
        executable_sha256="00" * 32,
    )
    config = {
        "source": {
            "native_source": native_source.name,
            "expected_sha256": {},
        },
        "budgets": {"maximum_persistent_artifact_bytes": 1_000_000},
    }
    marker: list[str] = []
    monkeypatch.setattr(resource_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(resource_run, "load_config", lambda _path: config)
    monkeypatch.setattr(
        resource_run,
        "preflight",
        lambda _path, require_commit_binding: {"source_commit": "f" * 40},
    )
    monkeypatch.setattr(resource_run, "validate_apple8_baseline", lambda *_: object())
    monkeypatch.setattr(
        resource_run,
        "validate_o1c63_resource_fix_provenance",
        lambda *_: object(),
    )
    monkeypatch.setattr(
        resource_run._native_v6,
        "build_native_joint_score_sieve",
        lambda **_: build,
    )
    monkeypatch.setattr(
        resource_run,
        "invoke_native_once_terminal",
        lambda **_: marker.append("called"),
    )
    with pytest.raises(O1C64RunError, match="build identity"):
        run(config_path)
    assert marker == []
    assert not (tmp_path / resource_run.RESULT_RELATIVE).exists()
    assert not (tmp_path / "runs").exists()


class _RichFailure(RuntimeError):
    def __init__(self, telemetry: dict[str, object]) -> None:
        super().__init__("rich execution failure")
        self.failure_telemetry = telemetry

    def describe(self) -> dict[str, object]:
        return self.failure_telemetry


def _rich_failure() -> _RichFailure:
    return _RichFailure(
        {
            "schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "classification_kind": "DARWIN_MEMORY_WATCHDOG",
            "phase": "wait_for_process",
            "elapsed_seconds": 17.763,
            "configured_timeout_seconds": 45.0,
            "configured_memory_limit_bytes": 1_073_741_824,
            "darwin_watchdog_guard_bytes": 33_554_432,
            "darwin_watchdog_kill_threshold_bytes": 1_040_187_392,
            "darwin_watchdog_poll_interval_seconds": 0.01,
            "memory_samples": [{"elapsed_seconds": 17.75, "rss_bytes": 1_040_200_000}],
            "returncode": -9,
            "signal_number": 9,
            "stdout": "progress\n",
            "stderr": "watchdog kill\n",
            "exception_chain": [
                {"type": "RuntimeError", "message": "watchdog fired"},
                {"type": "ProcessLookupError", "message": "gone"},
            ],
        }
    )


def test_rich_failure_preserves_adapter_evidence_raw_streams_and_cause_chain(
    tmp_path: Path,
) -> None:
    inner = ProcessLookupError("process vanished")
    exc = _rich_failure()
    exc.__cause__ = inner
    telemetry = native_failure_telemetry(exc, directory=tmp_path)
    assert telemetry["adapter_contract_valid"] is True
    assert telemetry["classification_kind"] == "DARWIN_MEMORY_WATCHDOG"
    assert telemetry["phase"] == "wait_for_process"
    assert telemetry["elapsed_seconds"] == 17.763
    assert telemetry["configured_timeout_seconds"] == 45.0
    assert telemetry["configured_memory_limit_bytes"] == 1_073_741_824
    assert telemetry["darwin_watchdog_kill_threshold_bytes"] == 1_040_187_392
    assert telemetry["memory_samples"] == [
        {"elapsed_seconds": 17.75, "rss_bytes": 1_040_200_000}
    ]
    assert telemetry["returncode"] == -9
    assert telemetry["signal_number"] == 9
    assert telemetry["signal_name"] == "SIGKILL"
    assert (tmp_path / "native_failure.stdout").read_bytes() == b"progress\n"
    assert (tmp_path / "native_failure.stderr").read_bytes() == b"watchdog kill\n"
    chain = telemetry["exception_chain_outer_to_cause_or_context"]
    assert isinstance(chain, list)
    assert [row["type"] for row in chain] == ["_RichFailure", "ProcessLookupError"]
    adapter = telemetry["adapter_failure_telemetry"]
    assert isinstance(adapter, dict)
    assert adapter["stdout"] == "progress\n"
    assert adapter["stderr"] == "watchdog kill\n"
    assert adapter["exception_chain"][-1]["message"] == "gone"


def test_terminal_wrapper_consumes_one_call_and_publishes_rich_evidence(
    tmp_path: Path,
) -> None:
    calls = 0

    def fail(**_: object) -> JointScoreSieveResult:
        nonlocal calls
        calls += 1
        try:
            raise OSError("watchdog query failed")
        except OSError as cause:
            raise _rich_failure() from cause

    native, failure = invoke_native_once_terminal(
        executable=Path("solver"),
        cnf=Path("target.cnf"),
        potential=Path("target.potential"),
        runner=fail,
        failure_directory=tmp_path,
    )
    assert calls == 1
    assert native is None
    assert failure is not None
    assert failure["classification"] == (
        "O1C64_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT"
    )
    assert failure["native_calls_consumed"] == 1
    assert failure["retry_authorized"] is False
    assert failure["truth_key_bytes_read"] is False
    evidence_path = tmp_path / "native_execution_failure.json"
    assert evidence_path.is_file()
    assert failure["native_execution_failure_sha256"] == sha256_file(evidence_path)
    evidence = json.loads(evidence_path.read_bytes())
    chain = evidence["exception_chain_outer_to_cause_or_context"]
    assert [row["type"] for row in chain] == ["_RichFailure", "OSError"]


def test_failure_evidence_sidecar_error_does_not_escape_consumed_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_sidecar(path: Path, _value: object) -> None:
        assert path.name == "native_execution_failure.json"
        raise OSError("injected evidence write failure")

    def fail(**_: object) -> JointScoreSieveResult:
        raise _rich_failure()

    monkeypatch.setattr(resource_run, "_atomic_json", reject_sidecar)
    native, failure = invoke_native_once_terminal(
        executable=Path("solver"),
        cnf=Path("target.cnf"),
        potential=Path("target.potential"),
        runner=fail,
        failure_directory=tmp_path,
    )
    assert native is None
    assert failure is not None
    assert failure["native_calls_consumed"] == 1
    assert failure["native_execution_failure_artifact"] is None
    assert failure["native_execution_failure_sha256"] is None
    telemetry = failure["native_failure_telemetry"]
    assert isinstance(telemetry, dict)
    assert telemetry["evidence_artifact_write_failure"]["type"] == "OSError"


def test_post_call_native_result_write_failure_still_publishes_terminally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "research").mkdir()
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="ascii")
    native_source = tmp_path / "native.cpp"
    native_source.write_text("// frozen\n", encoding="ascii")
    executable = tmp_path / "solver"
    executable.write_bytes(b"frozen")
    apple_capsule = tmp_path / "apple8"
    apple_capsule.mkdir()
    (apple_capsule / "artifacts.sha256").write_text("", encoding="ascii")
    apple_result = tmp_path / "apple8.json"
    apple_result.write_text("{}\n", encoding="ascii")
    cnf = tmp_path / "target.cnf"
    cnf.write_text("p cnf 0 0\n", encoding="ascii")
    potential = tmp_path / "target.potential"
    potential.write_text("{}\n", encoding="ascii")
    baseline = SimpleNamespace(
        authoritative_result=apple_result,
        capsule=apple_capsule,
        cnf=cnf,
        potential=potential,
    )
    build = NativeGuidedSearchBuild(
        executable=executable,
        command=("c++", "-o", str(executable)),
        source_sha256=resource_run.EXPECTED_NATIVE_SOURCE_SHA256,
        cadical_header_sha256="11" * 32,
        cadical_library_sha256="22" * 32,
        executable_sha256=EXPECTED_NATIVE_EXECUTABLE_SHA256,
    )
    config = {
        "source": {
            "native_source": native_source.name,
            "expected_sha256": {},
        },
        "budgets": {"maximum_persistent_artifact_bytes": 1_000_000},
    }
    calls: list[str] = []
    real_atomic_json = resource_run._atomic_json

    def fail_native_result(path: Path, value: object) -> None:
        if path.name == "native_result.json":
            raise OSError("injected native-result write failure")
        real_atomic_json(path, value)

    monkeypatch.setattr(resource_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(resource_run, "load_config", lambda _path: config)
    monkeypatch.setattr(
        resource_run,
        "preflight",
        lambda _path, require_commit_binding: {
            "schema": resource_run.PREFLIGHT_SCHEMA,
            "source_commit": "f" * 40,
            "source_commit_bound": require_commit_binding,
        },
    )
    monkeypatch.setattr(resource_run, "validate_apple8_baseline", lambda *_: baseline)
    monkeypatch.setattr(
        resource_run,
        "validate_o1c63_resource_fix_provenance",
        lambda *_: object(),
    )
    monkeypatch.setattr(
        resource_run,
        "_resource_fix_binding_row",
        lambda **_: {"schema": "o1-256-o1c64-test-provenance-v1"},
    )
    monkeypatch.setattr(
        resource_run._native_v6,
        "build_native_joint_score_sieve",
        lambda **_: build,
    )
    monkeypatch.setattr(resource_run, "validate_native_build_identity", lambda _: None)
    monkeypatch.setattr(resource_run, "_source_hashes", lambda *_: {})
    monkeypatch.setattr(
        resource_run,
        "invoke_native_once_terminal",
        lambda **_: (calls.append("called") or _native(), None),
    )
    monkeypatch.setattr(resource_run, "_atomic_json", fail_native_result)

    terminal = run(config_path)
    assert calls == ["called"]
    assert terminal["classification"] == ("O1C64_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT")
    failure = terminal["operational_failure"]
    assert isinstance(failure, dict)
    assert failure["classification"] == (
        "O1C64_OPERATIONAL_POST_NATIVE_FAILURE_NO_SCIENCE_RESULT"
    )
    assert failure["native_calls_consumed"] == 1
    assert failure["native_result_preserved"] is False
    assert isinstance(failure["native_result_inline_if_sidecar_missing"], dict)
    claim = terminal["claim_boundary"]
    assert isinstance(claim, dict)
    assert claim["truth_key_bytes_read_after_public_diagnostic"] is False
    authoritative = tmp_path / resource_run.RESULT_RELATIVE
    assert authoritative.is_file()
    capsule = tmp_path / str(terminal["capsule"])
    try:
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
        assert capsule.stat().st_mode & 0o777 == 0o555
        assert (capsule / "native_call_intent.json").is_file()
        assert not (capsule / "truth_access_intent.json").exists()
    finally:
        _make_writable(capsule)


def test_truth_isolated_until_present_model_publicly_verifies_8_of_8() -> None:
    callbacks: list[str] = []
    no_model = public_model_then_truth_diagnostic(
        _native(),
        verify_public_model=lambda _key: callbacks.append("public") or True,
        read_truth_key=lambda: callbacks.append("truth") or bytes(32),
        public_diagnostic_ledger=[False],
    )
    assert no_model == (False, None, None)
    assert callbacks == []

    with pytest.raises(O1C64RunError, match="fails eight public blocks"):
        public_model_then_truth_diagnostic(
            _native(status=10, key_model=b"m" * 32),
            verify_public_model=lambda _key: callbacks.append("public") or False,
            read_truth_key=lambda: callbacks.append("truth") or bytes(32),
            public_diagnostic_ledger=[False],
        )
    assert callbacks == ["public"]

    observed = public_model_then_truth_diagnostic(
        _native(status=10, key_model=b"m" * 32),
        verify_public_model=lambda _key: callbacks.append("public") or True,
        read_truth_key=lambda: callbacks.append("truth") or b"m" * 32,
        public_diagnostic_ledger=[False],
    )
    assert observed == (True, b"m" * 32, True)
    assert callbacks == ["public", "public", "truth"]


@pytest.mark.parametrize(
    ("trail_prunes", "emitted", "expected"),
    [
        (25, 24, "O1C64_APPLE8_4K_RESOURCE_FIX_SUSTAINED_SCALING"),
        (24, 24, "O1C64_APPLE8_4K_RESOURCE_FIX_SUSTAINED_SCALING"),
        (24, 23, "O1C64_APPLE8_4K_RESOURCE_FIX_ACTIVE_SUBLINEAR"),
        (1, 1, "O1C64_APPLE8_4K_RESOURCE_FIX_ACTIVE_SUBLINEAR"),
        (1, 0, "O1C64_APPLE8_4K_RESOURCE_FIX_SCALING_REGRESSION"),
        (0, 0, "O1C64_APPLE8_4K_RESOURCE_FIX_SCALING_REGRESSION"),
    ],
)
def test_emitted_trail_lower_bound_classification_boundaries(
    trail_prunes: int, emitted: int, expected: str
) -> None:
    observed, metrics = classify_scaling(
        _native(trail_prunes=trail_prunes, emitted=emitted),
        public_model_verified=False,
        billed_conflicts=4_097,
    )
    assert observed == expected
    assert metrics["emitted_certified_trail_prune_lower_bound"] == max(
        0, trail_prunes - (trail_prunes - emitted)
    )
    assert metrics["different_budget_work_is_matched"] is False


def test_status_20_fails_closed_without_truth_access() -> None:
    callbacks: list[str] = []
    native = _native(status=20)
    assert public_model_then_truth_diagnostic(
        native,
        verify_public_model=lambda _key: callbacks.append("public") or True,
        read_truth_key=lambda: callbacks.append("truth") or bytes(32),
        public_diagnostic_ledger=[False],
    ) == (False, None, None)
    with pytest.raises(O1C64RunError, match="UNSAT contradicts"):
        classify_scaling(
            native,
            public_model_verified=False,
            billed_conflicts=4_097,
        )
    assert callbacks == []


def test_resource_ledger_accepts_exact_ceiling_and_rejects_excess() -> None:
    observed = validate_native_resource_ledger(_native(), solver_calls=1)
    assert observed == {
        "conflicts": 4_097,
        "conflicts_before_solve": 0,
        "solve_conflicts": 4_097,
        "decisions": 20_000,
        "propagations": 2_000_000,
        "requested_conflicts": 4_096,
        "unused_requested_conflicts": 0,
        "conflict_limit_overshoot": 1,
        "billed_conflicts": 4_097,
    }
    validate_native_resource_ledger(
        _native(
            wall_microseconds=int(NATIVE_TIMEOUT_SECONDS * 1_000_000),
            peak_rss_bytes=MEMORY_LIMIT_BYTES,
        ),
        solver_calls=1,
    )
    with pytest.raises(O1C64RunError, match="resource ledger"):
        validate_native_resource_ledger(
            _native(wall_microseconds=int(NATIVE_TIMEOUT_SECONDS * 1_000_000) + 1),
            solver_calls=1,
        )
    with pytest.raises(O1C64RunError, match="resource ledger"):
        validate_native_resource_ledger(
            _native(peak_rss_bytes=MEMORY_LIMIT_BYTES + 1), solver_calls=1
        )


def test_terminal_capsule_is_immutable_mirrored_and_never_overwritten(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    authoritative = tmp_path / "authoritative.json"
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
        with pytest.raises(O1C64RunError, match="already exists"):
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=1_000_000,
            )
    finally:
        _make_writable(capsule)


def test_post_seal_failure_recovers_one_o1c64_terminal_result(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    (capsule / "native_result.json").write_text("{}\n", encoding="ascii")
    authoritative = tmp_path / "authoritative.json"

    def fail_after_seal() -> None:
        raise OSError("injected post-seal failure")

    try:
        terminal = _finalize_consumed_call_terminally(
            capsule=capsule,
            authoritative_result=authoritative,
            result=_terminal_result(),
            maximum_persistent_bytes=1_000_000,
            capsule_relative=Path("runs/O1C64-test"),
            source_commit="f" * 40,
            preflight_row={"schema": resource_run.PREFLIGHT_SCHEMA},
            runtime_resources={"elapsed_seconds": 1.0},
            _after_capsule_seal=fail_after_seal,
        )
        assert terminal["classification"] == (
            "O1C64_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        )
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
        assert capsule.stat().st_mode & 0o777 == 0o555
        failure = json.loads((capsule / "publication_failure.json").read_bytes())
        assert failure["classification"] == (
            "O1C64_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT"
        )
        assert failure["publication_recovered"] is True
        assert failure["retry_authorized"] is False
    finally:
        _make_writable(capsule)


def test_source_hash_drift_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    real_sha256: Callable[[Path], str] = resource_run.sha256_file

    def drift(path: Path) -> str:
        if Path(path).name == "joint_score_sieve_v6.py":
            return "0" * 64
        return real_sha256(path)

    monkeypatch.setattr(resource_run, "sha256_file", drift)
    with pytest.raises(O1C64RunError, match="source hash differs"):
        load_config(CONFIG)
