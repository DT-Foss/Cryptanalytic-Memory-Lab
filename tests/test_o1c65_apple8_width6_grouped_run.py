from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.o1c65_apple8_width6_grouped_run as grouped_run
from o1_crypto_lab.joint_score_sieve import JointScoreSieveResult
from o1_crypto_lab.o1_relational_search import NativeGuidedSearchBuild, sha256_file
from o1_crypto_lab.o1c65_apple8_width6_grouped_run import (
    CONFLICT_LIMIT,
    EXPECTED_GROUPING_SHA256,
    GROUPING_WIDTH_CAP,
    MEMORY_LIMIT_BYTES,
    O1C65RunError,
    _finalize_consumed_call_terminally,
    build_frozen_grouping,
    classify_efficacy,
    finalize_capsule,
    invoke_native_once,
    invoke_native_once_terminal,
    load_config,
    materialize_grouping,
    native_failure_telemetry,
    preflight,
    public_model_then_truth_diagnostic,
    validate_native_resource_ledger,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c65_apple8_width6_grouped_v1.json"
APPLE8_CAPSULE = (
    ROOT / "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_"
    "crossblock-consequence-sieve-v1"
)
APPLE8_RESULT = ROOT / "research/apple_view_8/apple_view_8_matched_result.json"
APPLE9_RESULT = (
    ROOT / "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json"
)


def _native(
    *,
    status: int = 0,
    key_model: bytes | None = None,
    trail_prunes: int = 7,
    queued: int | None = None,
    emitted: int | None = None,
    requested: int = 512,
    before: int = 0,
    solve: int = 513,
    cumulative: int = 513,
    unused: int = 0,
    overshoot: int = 1,
    billed: int = 513,
    wall_microseconds: int = 1_000_000,
    peak_rss_bytes: int = 450_000_000,
) -> JointScoreSieveResult:
    state = {0: (256, "INCONCLUSIVE"), 10: (32, "SATISFIED"), 20: (64, "UNSATISFIED")}[
        status
    ]
    queued_value = trail_prunes if queued is None else queued
    emitted_value = queued_value if emitted is None else emitted
    raw = {
        "schema": grouped_run.NATIVE_RESULT_SCHEMA,
        "implementation_parent_schema": grouped_run.IMPLEMENTATION_PARENT_SCHEMA,
        "status": status,
        "post_solve_state": state[0],
        "post_solve_state_name": state[1],
        "teardown_rule": grouped_run.TEARDOWN_RULE,
        "pending_backtrack_rule": grouped_run.PENDING_BACKTRACK_RULE,
    }
    return grouped_run._native_v7.JointScoreSieveV7Result(
        status=status,
        conflict_limit=CONFLICT_LIMIT,
        threshold=grouped_run.THRESHOLD,
        key_model=key_model,
        stats={
            "conflicts": cumulative,
            "conflicts_before_solve": before,
            "solve_conflicts": solve,
            "decisions": 4_000,
            "propagations": 1_000_000,
            "requested_conflicts": requested,
            "unused_requested_conflicts": unused,
            "conflict_limit_overshoot": overshoot,
            "billed_conflicts": billed,
        },
        sieve={
            "decision_rule": grouped_run.JOINT_SCORE_SIEVE_DECISION_RULE,
            "bound_rule": grouped_run.COMPATIBILITY_GROUPING_BOUND_RULE,
            "grouping_rule": grouped_run.COMPATIBILITY_GROUPING_RULE,
            "grouping_sha256": EXPECTED_GROUPING_SHA256,
            "grouping_input_sha256": EXPECTED_GROUPING_SHA256,
            "grouping_width_cap": 6,
            "grouping_serialized_bytes": 115_700,
            "factor_count": 7_557,
            "group_count": 2_885,
            "singleton_group_count": 28,
            "pair_group_count": 1_641,
            "higher_order_group_count": 1_216,
            "maximum_group_size": 8,
            "group_table_rows": 176_912,
            "group_incident_edges": 17_025,
            "root_upper_bound": 262.68644197084643,
            "root_upper_bound_f64le_hex": "327693aafb6a7040",
            "minimum_upper_bound": 12.0,
            "trail_threshold_prunes": trail_prunes,
            "model_threshold_prunes": 0,
            "threshold_prunes": queued_value,
            "external_clauses_queued": queued_value,
            "external_clauses_emitted": emitted_value,
            "state": {"schema": grouped_run.NATIVE_STATE_SCHEMA},
        },
        resources={
            "wall_microseconds": wall_microseconds,
            "cpu_microseconds": wall_microseconds,
            "peak_rss_bytes": peak_rss_bytes,
        },
        raw=raw,
        adapter_memory={
            "memory_series_schema": grouped_run.NATIVE_MEMORY_SERIES_SCHEMA,
            "memory_sample_limit": grouped_run.MAXIMUM_NATIVE_MEMORY_SAMPLES,
            "memory_sample_count": 2,
            "memory_samples": [
                {"elapsed_seconds": 0.1, "rss_bytes": 300_000_000},
                {"elapsed_seconds": 0.9, "rss_bytes": peak_rss_bytes},
            ],
            "memory_peak_bytes": max(300_000_000, peak_rss_bytes),
            "memory_last_bytes": peak_rss_bytes,
            "memory_last_elapsed_seconds": 0.9,
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
        "classification": "O1C65_GROUPED_WIDTH6_STRICT_EFFICACY_GAIN",
        "claim_boundary": {
            "truth_key_bytes_read_after_public_diagnostic": False,
            "matched_requested_work": True,
        },
        "resources": {
            "native_solver_calls": 1,
            "requested_conflicts": 512,
            "billed_conflicts": 513,
            "persistent_artifact_bytes": 0,
        },
    }


@pytest.fixture(scope="module")
def frozen_grouping() -> grouped_run.FrozenGrouping:
    config = load_config(CONFIG)
    potential = APPLE8_CAPSULE / grouped_run.APPLE8_POTENTIAL_RELATIVE
    return build_frozen_grouping(potential, config)


def test_preflight_is_read_only_zero_call_and_freezes_width6() -> None:
    before = {
        "apple8_result": sha256_file(APPLE8_RESULT),
        "apple8_manifest": sha256_file(APPLE8_CAPSULE / "artifacts.sha256"),
        "apple9_result": sha256_file(APPLE9_RESULT),
    }
    observed = preflight(CONFIG)
    after = {
        "apple8_result": sha256_file(APPLE8_RESULT),
        "apple8_manifest": sha256_file(APPLE8_CAPSULE / "artifacts.sha256"),
        "apple9_result": sha256_file(APPLE9_RESULT),
    }
    assert before == after
    assert observed["ok"] is True
    assert observed["ready_for_science"] is False
    assert observed["native_solver_calls"] == 0
    assert observed["files_written"] == 0
    assert observed["truth_key_bytes_read"] is False
    assert observed["grouping_materialized"] is False
    assert observed["grouping_width_cap"] == GROUPING_WIDTH_CAP == 6
    assert observed["grouping_sha256"] == EXPECTED_GROUPING_SHA256
    assert observed["grouping_serialized_bytes"] == 115_700
    assert observed["requested_conflicts"] == 512
    assert observed["maximum_billed_conflicts"] == 513


def test_sources_and_matched_work_resource_contract_are_frozen() -> None:
    config = load_config(CONFIG)
    source = config["source"]
    assert isinstance(source, dict)
    expected = source["expected_sha256"]
    assert isinstance(expected, dict)
    for name, relative in source.items():
        if name != "expected_sha256":
            assert sha256_file(ROOT / str(relative)) == expected[name]
    assert config["native"] == {
        "requested_conflicts": 512,
        "maximum_conflict_limit_overshoot": 1,
        "maximum_billed_conflicts": 513,
        "timeout_seconds": 45.0,
        "memory_limit_bytes": 1_073_741_824,
        "seed": 0,
        "calls": 1,
        "result_schema": grouped_run.NATIVE_RESULT_SCHEMA,
        "implementation_parent_schema": grouped_run.IMPLEMENTATION_PARENT_SCHEMA,
        "state_schema": grouped_run.NATIVE_STATE_SCHEMA,
        "soft_conflict_ledger_schema": grouped_run.SOFT_CONFLICT_LEDGER_SCHEMA,
        "teardown_rule": grouped_run.TEARDOWN_RULE,
        "pending_backtrack_rule": grouped_run.PENDING_BACKTRACK_RULE,
        "execution_failure_schema": grouped_run.NATIVE_EXECUTION_FAILURE_SCHEMA,
        "memory_series_schema": grouped_run.NATIVE_MEMORY_SERIES_SCHEMA,
        "maximum_memory_samples": grouped_run.MAXIMUM_NATIVE_MEMORY_SAMPLES,
        "darwin_watchdog_guard_bytes": 33_554_432,
        "darwin_watchdog_kill_threshold_bytes": 1_040_187_392,
        "darwin_watchdog_poll_interval_seconds": 0.01,
        "expected_source_sha256": grouped_run.EXPECTED_NATIVE_SOURCE_SHA256,
        "expected_executable_sha256": grouped_run.EXPECTED_NATIVE_EXECUTABLE_SHA256,
    }


def test_grouping_is_materialized_and_reread_before_any_intent(
    tmp_path: Path, frozen_grouping: grouped_run.FrozenGrouping
) -> None:
    path = tmp_path / "width6.grouping"
    report = materialize_grouping(path, frozen_grouping)
    assert not (tmp_path / "native_call_intent.json").exists()
    assert path.read_bytes() == frozen_grouping.grouping.serialized
    assert sha256_file(path) == EXPECTED_GROUPING_SHA256
    assert report["materialized_before_intent"] is True
    assert report["serialized_bytes"] == 115_700
    assert report["group_count"] == 2_885
    assert report["grouped_root_upper_bound_f64le_hex"] == "327693aafb6a7040"


def test_one_call_wrapper_has_exact_grouped_matched_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    expected = _native()

    def fake(**kwargs: object) -> JointScoreSieveResult:
        calls.append(dict(kwargs))
        return expected

    monkeypatch.setattr(grouped_run, "validate_frozen_call_inputs", lambda **_: None)
    observed = invoke_native_once(
        executable=Path("solver"),
        cnf=Path("target.cnf"),
        potential=Path("target.potential"),
        grouping=Path("width6.grouping"),
        runner=fake,
    )
    assert observed is expected
    assert calls == [
        {
            "executable": Path("solver"),
            "cnf_path": Path("target.cnf"),
            "potential_path": Path("target.potential"),
            "grouping_path": Path("width6.grouping"),
            "threshold": 14.606178797892962,
            "conflict_limit": 512,
            "seed": 0,
            "timeout_seconds": 45.0,
            "memory_limit_bytes": 1_073_741_824,
        }
    ]


def test_hash_mismatch_fails_before_entering_native_runner(
    tmp_path: Path,
) -> None:
    cnf = tmp_path / "target.cnf"
    potential = tmp_path / "target.potential"
    grouping = tmp_path / "width6.grouping"
    cnf.write_bytes(b"wrong cnf")
    potential.write_bytes(b"wrong potential")
    grouping.write_bytes(b"wrong grouping")
    calls: list[int] = []

    def fake(**_: object) -> JointScoreSieveResult:
        calls.append(1)
        return _native()

    with pytest.raises(O1C65RunError, match="input identity"):
        invoke_native_once(
            executable=tmp_path / "solver",
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            runner=fake,
        )
    assert calls == []


def test_native_grouping_and_resource_ledger_fail_closed() -> None:
    ledger = validate_native_resource_ledger(_native(), solver_calls=1)
    assert ledger["requested_conflicts"] == 512
    assert ledger["billed_conflicts"] == 513
    mismatched = _native()
    mismatched = replace(
        mismatched, sieve={**mismatched.sieve, "grouping_sha256": "00" * 32}
    )
    with pytest.raises(O1C65RunError, match="grouped resource ledger"):
        validate_native_resource_ledger(mismatched, solver_calls=1)
    with pytest.raises(O1C65RunError, match="grouped resource ledger"):
        validate_native_resource_ledger(
            _native(peak_rss_bytes=MEMORY_LIMIT_BYTES + 1), solver_calls=1
        )


def test_success_adapter_memory_series_is_bounded_and_detached() -> None:
    native = _native()
    observed = grouped_run.validate_native_adapter_memory(native)
    assert observed["memory_sample_count"] == 2
    assert observed["memory_peak_bytes"] == 450_000_000
    assert observed["memory_last_bytes"] == 450_000_000
    assert observed["memory_last_elapsed_seconds"] == 0.9
    assert observed["memory_samples"] == [
        {"elapsed_seconds": 0.1, "rss_bytes": 300_000_000},
        {"elapsed_seconds": 0.9, "rss_bytes": 450_000_000},
    ]
    assert set(native.resources) == {
        "wall_microseconds",
        "cpu_microseconds",
        "peak_rss_bytes",
    }


class _RichFailure(RuntimeError):
    def __init__(self, telemetry: dict[str, object]) -> None:
        super().__init__("rich grouped failure")
        self.failure_telemetry = telemetry

    def describe(self) -> dict[str, object]:
        return dict(self.failure_telemetry)


def _rich_failure() -> _RichFailure:
    return _RichFailure(
        {
            "schema": grouped_run.NATIVE_EXECUTION_FAILURE_SCHEMA,
            "classification_kind": "watchdog_memory",
            "phase": "native_process",
            "elapsed_seconds": 3.0,
            "configured_timeout_seconds": 45.0,
            "configured_memory_limit_bytes": 1_073_741_824,
            "darwin_watchdog_guard_bytes": 33_554_432,
            "darwin_watchdog_kill_threshold_bytes": 1_040_187_392,
            "darwin_watchdog_poll_interval_seconds": 0.01,
            "memory_series_schema": grouped_run._native_v7.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA,
            "memory_sample_limit": 256,
            "memory_sample_count": 2,
            "memory_peak_bytes": 800_000_000,
            "memory_last_bytes": 800_000_000,
            "memory_last_elapsed_seconds": 2.9,
            "memory_samples": [
                {"elapsed_seconds": 0.1, "rss_bytes": 300_000_000},
                {"elapsed_seconds": 2.9, "rss_bytes": 800_000_000},
            ],
            "returncode": -9,
            "signal_number": 9,
            "signal_name": "SIGKILL",
            "command": ["solver"],
            "stdout": "progress\n",
            "stderr": "watchdog\n",
            "exception_chain": [],
        }
    )


def test_v7_failure_preserves_cause_and_time_indexed_rss(tmp_path: Path) -> None:
    evidence = native_failure_telemetry(_rich_failure(), directory=tmp_path)
    assert evidence["schema"] == "o1-256-o1c65-native-failure-evidence-v1"
    assert evidence["adapter_contract_valid"] is True
    adapter = evidence["adapter_failure_telemetry"]
    assert isinstance(adapter, dict)
    assert adapter["memory_sample_count"] == 2
    assert adapter["memory_samples"] == [
        {"elapsed_seconds": 0.1, "rss_bytes": 300_000_000},
        {"elapsed_seconds": 2.9, "rss_bytes": 800_000_000},
    ]
    chain = evidence["exception_chain_outer_to_cause_or_context"]
    assert isinstance(chain, list)
    assert isinstance(chain[0], dict)
    assert chain[0]["type"] == "_RichFailure"
    contract = evidence["o1c65_resource_contract"]
    assert isinstance(contract, dict)
    assert contract["memory_limit_bytes"] == MEMORY_LIMIT_BYTES


def test_terminal_native_wrapper_consumes_exactly_one_call_without_truth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    def fail(**_: object) -> JointScoreSieveResult:
        calls.append(1)
        raise _rich_failure()

    monkeypatch.setattr(grouped_run, "validate_frozen_call_inputs", lambda **_: None)
    native, failure = invoke_native_once_terminal(
        executable=tmp_path / "solver",
        cnf=tmp_path / "target.cnf",
        potential=tmp_path / "target.potential",
        grouping=tmp_path / "width6.grouping",
        runner=fail,
        failure_directory=tmp_path,
    )
    assert native is None
    assert calls == [1]
    assert failure is not None
    assert failure["native_calls_consumed"] == 1
    assert failure["retry_authorized"] is False
    assert failure["truth_key_bytes_read"] is False
    assert (tmp_path / "native_execution_failure.json").is_file()


def test_truth_is_never_read_even_for_publicly_verified_model() -> None:
    callbacks: list[str] = []
    no_model = public_model_then_truth_diagnostic(
        _native(trail_prunes=0),
        verify_public_model=lambda _: callbacks.append("public") is None,
        read_truth_key=lambda: callbacks.append("truth") or bytes(32),
        public_diagnostic_ledger=[False],
    )
    assert no_model == (False, None, None)
    assert callbacks == []

    public_ledger = [False]
    verified = public_model_then_truth_diagnostic(
        _native(
            status=10,
            key_model=bytes(32),
            solve=100,
            cumulative=100,
            unused=412,
            overshoot=0,
            billed=100,
        ),
        verify_public_model=lambda _: callbacks.append("public") or True,
        read_truth_key=lambda: callbacks.append("truth") or bytes(32),
        public_diagnostic_ledger=public_ledger,
    )
    assert verified == (True, None, None)
    assert callbacks == ["public"]
    assert public_ledger == [True]


@pytest.mark.parametrize(
    ("prunes", "queued", "emitted", "classification"),
    [
        (7, 7, 7, "O1C65_GROUPED_WIDTH6_STRICT_EFFICACY_GAIN"),
        (7, 7, 6, "O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED"),
        (6, 6, 6, "O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED"),
        (6, 6, 5, "O1C65_GROUPED_WIDTH6_EFFICACY_REGRESSION"),
        (0, 0, 0, "O1C65_GROUPED_WIDTH6_EFFICACY_REGRESSION"),
    ],
)
def test_matched_efficacy_classification_uses_emitted_trail_lower_bound(
    prunes: int, queued: int, emitted: int, classification: str
) -> None:
    observed, metrics = classify_efficacy(
        _native(trail_prunes=prunes, queued=queued, emitted=emitted),
        public_model_verified=False,
        billed_conflicts=513,
    )
    assert observed == classification
    assert metrics["emitted_trail_prune_lower_bound"] == prunes - (queued - emitted)
    assert metrics["requested_work_matched"] is True
    assert metrics["billed_work_matched"] is True


def test_unsat_and_unmatched_unknown_fail_closed_without_truth() -> None:
    with pytest.raises(O1C65RunError, match="UNSAT contradicts"):
        classify_efficacy(
            _native(status=20),
            public_model_verified=False,
            billed_conflicts=513,
        )
    with pytest.raises(O1C65RunError, match="not matched billed work"):
        classify_efficacy(
            _native(
                solve=100,
                cumulative=100,
                unused=412,
                overshoot=0,
                billed=100,
            ),
            public_model_verified=False,
            billed_conflicts=100,
        )


def test_native_build_mismatch_fails_before_capsule_intent_or_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}\n", encoding="ascii")
    native_source = tmp_path / "native.cpp"
    native_source.write_text("// frozen\n", encoding="ascii")
    executable = tmp_path / "solver"
    executable.write_bytes(b"wrong")
    build = NativeGuidedSearchBuild(
        executable=executable,
        command=("c++", "-o", str(executable)),
        source_sha256=grouped_run.EXPECTED_NATIVE_SOURCE_SHA256,
        cadical_header_sha256="11" * 32,
        cadical_library_sha256="22" * 32,
        executable_sha256="00" * 32,
    )
    baseline = SimpleNamespace(potential=tmp_path / "potential")
    marker: list[str] = []
    monkeypatch.setattr(grouped_run, "lab_root", lambda: tmp_path)
    monkeypatch.setattr(
        grouped_run,
        "load_config",
        lambda _path: {
            "source": {"native_source": native_source.name, "expected_sha256": {}},
            "budgets": {"maximum_persistent_artifact_bytes": 1_000_000},
        },
    )
    monkeypatch.setattr(
        grouped_run,
        "preflight",
        lambda _path, require_commit_binding: {"source_commit": "f" * 40},
    )
    monkeypatch.setattr(grouped_run, "validate_apple8_baseline", lambda *_: baseline)
    monkeypatch.setattr(grouped_run, "validate_grouping_provenance", lambda *_: {})
    monkeypatch.setattr(grouped_run, "build_frozen_grouping", lambda *_: object())
    monkeypatch.setattr(
        grouped_run._native_v7, "build_native_joint_score_sieve", lambda **_: build
    )
    monkeypatch.setattr(
        grouped_run, "invoke_native_once_terminal", lambda **_: marker.append("called")
    )
    with pytest.raises(O1C65RunError, match="build identity"):
        grouped_run.run(config_path)
    assert marker == []
    assert not (tmp_path / grouped_run.RESULT_RELATIVE).exists()
    assert not (tmp_path / "runs").exists()


def test_terminal_capsule_is_immutable_mirrored_and_never_overwritten(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    (capsule / "apple9-width6.grouping").write_bytes(b"grouping")
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
        with pytest.raises(O1C65RunError, match="already exists"):
            finalize_capsule(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=1_000_000,
            )
    finally:
        _make_writable(capsule)


def test_post_seal_failure_recovers_one_terminal_result(tmp_path: Path) -> None:
    capsule = tmp_path / "capsule"
    capsule.mkdir()
    (capsule / "native_call_intent.json").write_text("{}\n", encoding="ascii")
    authoritative = tmp_path / "result.json"

    def fail_after_seal() -> None:
        raise OSError("injected post-seal failure")

    try:
        terminal = _finalize_consumed_call_terminally(
            capsule=capsule,
            authoritative_result=authoritative,
            result=_terminal_result(),
            maximum_persistent_bytes=1_000_000,
            capsule_relative=Path("runs/capsule"),
            source_commit="f" * 40,
            preflight_row={"native_solver_calls": 0},
            _after_capsule_seal=fail_after_seal,
        )
        assert terminal["classification"] == (
            "O1C65_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        )
        failure = terminal["operational_failure"]
        assert isinstance(failure, dict)
        assert failure["classification"] == (
            "O1C65_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT"
        )
        assert failure["native_calls_consumed"] == 1
        assert failure["retry_authorized"] is False
        assert failure["truth_key_bytes_read"] is False
        assert authoritative.read_bytes() == (capsule / "result.json").read_bytes()
    finally:
        _make_writable(capsule)


def test_grouping_file_digest_is_the_frozen_expected_value(
    tmp_path: Path, frozen_grouping: grouped_run.FrozenGrouping
) -> None:
    path = tmp_path / "grouping"
    materialize_grouping(path, frozen_grouping)
    payload = path.read_bytes()
    assert len(payload) == 115_700
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_GROUPING_SHA256


def test_source_hash_drift_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = grouped_run.sha256_file

    def drift(path: Path) -> str:
        observed = original(path)
        if path.name == "joint_score_grouping_v1.py":
            return "00" * 32
        return observed

    monkeypatch.setattr(grouped_run, "sha256_file", drift)
    with pytest.raises(O1C65RunError, match="source hash differs"):
        load_config(CONFIG)


def test_config_json_has_no_duplicate_keys() -> None:
    pairs_seen: list[list[tuple[str, object]]] = []

    def hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        pairs_seen.append(pairs)
        keys = [key for key, _ in pairs]
        assert len(keys) == len(set(keys))
        return dict(pairs)

    parsed = json.loads(CONFIG.read_bytes(), object_pairs_hook=hook)
    assert parsed["attempt_id"] == "O1C-0065"
    assert pairs_seen
