from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v10 as sieve_v10
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v10 import (
    FORCED_INITIAL_PHASE_READER_SCHEMA,
    FORCED_INITIAL_PHASE_READER_SPEC_SHA256,
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JointScoreSieveExecutionError,
    JointScoreSieveV10Result,
    forced_initial_phase_reader_spec_bytes,
    run_joint_score_sieve,
    validate_forced_initial_phase_reader,
)
from o1_crypto_lab.joint_score_sieve_v9 import JointScoreSieveV9Result
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_V6_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v6.cpp"
NATIVE_V7_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v7.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
STRICT_NATIVE_FLAGS = (
    "-std=c++17",
    "-O3",
    "-DNDEBUG",
    "-Wall",
    "-Wextra",
    "-Werror",
)


def _reader() -> dict[str, object]:
    return {
        "schema": "o1-256-cadical-forced-initial-phase-reader-v1",
        "operator": "forced-initial-phase",
        "complement_pair_id": "forced-initial-phase-v1",
        "cadical_configuration": "plain",
        "phase_before_override": 1,
        "phase": 0,
        "forcephase": True,
        "rephase": 0,
        "lucky": False,
        "walk": False,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "reader_spec_sha256": (
            "a68b3c3b1721b756314dac11ce725adf0709e9f358125cb1f8d388737d1ddddc"
        ),
    }


def _payload(*, reader: object | None = None) -> dict[str, object]:
    payload: dict[str, object] = {name: None for name in sieve_v10._TOP_LEVEL_FIELDS}
    payload.update(
        {
            "schema": "o1-256-cadical-joint-score-sieve-result-v7",
            "implementation_parent_schema": (
                "o1-256-cadical-joint-score-sieve-result-v6"
            ),
            "seed": 0,
            "reader": _reader() if reader is None else reader,
        }
    )
    return payload


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 3.0)),
            CriticalityPotentialFactor((2,), (-2.0, 2.0)),
        ),
    )


def _vault() -> ThresholdNoGoodVault:
    field = _field()
    identity = vault_identity_from_sources(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=0.0,
    )
    return ThresholdNoGoodVault(identity, field.observed_variables, ())


def _native_stats(*, solve: int, conflicts_before_solve: int = 0) -> dict[str, int]:
    return {
        "conflicts": conflicts_before_solve + solve,
        "conflicts_before_solve": conflicts_before_solve,
        "solve_conflicts": solve,
        "decisions": 9,
        "propagations": 99,
    }


def _parent_result(
    input_vault: ThresholdNoGoodVault, *, solve: int = 514
) -> JointScoreSieveV9Result:
    return JointScoreSieveV9Result(
        status=0,
        conflict_limit=512,
        threshold=0.0,
        key_model=None,
        stats=_native_stats(solve=solve, conflicts_before_solve=17),
        sieve={},
        resources={},
        raw={},
        adapter_memory={},
        input_vault=input_vault,
        eligible_emitted_clauses=(),
        next_vault=input_vault,
        vault_telemetry={},
    )


def _parse(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
) -> JointScoreSieveV10Result:
    field = _field()
    return sieve_v10._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=field,
        grouping=sieve_v10.build_compatibility_grouping(field),
        grouping_sha256="45" * 32,
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        threshold=0.0,
        requested_conflicts=512,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
    )


def test_reader_preimage_and_digest_are_independently_exact() -> None:
    expected = (
        b"forced-initial-phase-v1\n"
        b"cadical_configuration=plain\n"
        b"phase_before_override=1\n"
        b"seed=0\n"
        b"quiet=1\n"
        b"factor=0\n"
        b"lucky=0\n"
        b"walk=0\n"
        b"rephase=0\n"
        b"forcephase=1\n"
        b"phase=0\n"
    )
    assert forced_initial_phase_reader_spec_bytes() == expected
    assert len(expected) == 146
    assert hashlib.sha256(expected).hexdigest() == (
        FORCED_INITIAL_PHASE_READER_SPEC_SHA256
    )


def test_exact_reader_is_normalized_and_v7_payload_projects_to_v9(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_vault = _vault()
    original = _payload()
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **_: object) -> JointScoreSieveV9Result:
        assert isinstance(payload, dict)
        seen.update(payload)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v10._v9, "_parse_native_payload", fake_parent)
    result = _parse(original, input_vault=input_vault)

    assert isinstance(result, JointScoreSieveV10Result)
    assert result.reader == _reader()
    assert result.raw == original
    assert "reader" not in seen
    assert seen["schema"] == sieve_v10._v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert (
        seen["implementation_parent_schema"]
        == sieve_v10._v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    assert set(seen) == sieve_v10._v9._TOP_LEVEL_FIELDS


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    (
        (lambda reader: reader.pop("phase"), "reader fields"),
        (lambda reader: reader.__setitem__("extra", 0), "reader fields"),
        (lambda reader: reader.__setitem__("phase", False), "reader contract"),
        (lambda reader: reader.__setitem__("phase", 1), "reader contract"),
        (
            lambda reader: reader.__setitem__("reader_spec_sha256", "00" * 32),
            "reader contract",
        ),
        (lambda reader: reader.__setitem__("schema", "wrong"), "reader contract"),
        (lambda reader: reader.__setitem__("operator", "wrong"), "reader contract"),
        (lambda reader: reader.__setitem__("forcephase", 1), "reader contract"),
        (lambda reader: reader.__setitem__("seed", False), "reader contract"),
    ),
)
def test_missing_extra_wrong_phase_hash_schema_and_types_are_rejected(
    mutation: Any, pattern: str
) -> None:
    reader = _reader()
    mutation(reader)
    with pytest.raises(O1RelationalSearchError, match=pattern):
        validate_forced_initial_phase_reader(reader)


@pytest.mark.parametrize("case", ("missing", "extra", "schema", "parent"))
def test_top_level_v7_fields_and_identity_are_exact(case: str) -> None:
    payload = _payload()
    if case == "missing":
        payload.pop("reader")
        pattern = "result fields"
    elif case == "extra":
        payload["extra"] = None
        pattern = "result fields"
    elif case == "schema":
        payload["schema"] = sieve_v10._v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        pattern = "result contract"
    else:
        payload["implementation_parent_schema"] = "wrong"
        pattern = "result contract"
    with pytest.raises(O1RelationalSearchError, match=pattern):
        _parse(payload, input_vault=_vault())


def test_parent_validation_failure_preserves_its_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_: object, **__: object) -> JointScoreSieveV9Result:
        raise O1RelationalSearchError("v9-parent-sentinel")

    monkeypatch.setattr(sieve_v10._v9, "_parse_native_payload", fail)
    with pytest.raises(
        O1RelationalSearchError, match="v10 native payload validation"
    ) as raised:
        _parse(_payload(), input_vault=_vault())
    assert isinstance(raised.value.__cause__, O1RelationalSearchError)
    assert "v9-parent-sentinel" in str(raised.value.__cause__)


def _inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault]:
    field = _field()
    executable = tmp_path / "synthetic-native-v7"
    executable.write_bytes(b"synthetic-native-v7")
    cnf = tmp_path / "target-free.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "target-free.potential"
    sieve_v10.write_joint_score_sieve_potential(potential, field)
    grouping = tmp_path / "target-free.grouping"
    sieve_v10.write_joint_score_sieve_grouping(grouping, field)
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
        return sieve_v10._v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(sieve_v10._v9._v8._v7, "_execute_native", fake_execute)
    return command_seen, samples


def _run_inputs(
    inputs: tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault],
    *,
    seed: int = 0,
) -> JointScoreSieveV10Result:
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
        seed=seed,
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


def test_full_mocked_process_accepts_solve514_at_requested512_and_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps(_payload())
    command, _ = _mock_execution(monkeypatch, stdout=stdout)
    input_vault = inputs[-1]
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **kwargs: object) -> JointScoreSieveV9Result:
        assert isinstance(payload, dict)
        seen.update(kwargs)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v10._v9, "_parse_native_payload", fake_parent)
    result = _run_inputs(inputs)

    assert result.stats["requested_conflicts"] == 512
    assert result.stats["conflict_limit_overshoot"] == 2
    assert result.stats["billed_conflicts"] == 514
    assert result.reader == _reader()
    assert command[command.index("--seed") + 1] == "0"
    assert "--phase" not in command
    assert "--forcephase" not in command
    assert seen["seed"] == 0


def test_reader_rejection_after_successful_process_retains_all_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    forged = _payload()
    reader = copy.deepcopy(forged["reader"])
    assert isinstance(reader, dict)
    reader["reader_spec_sha256"] = "00" * 32
    forged["reader"] = reader
    stdout = json.dumps(forged)
    stderr = "reader-parser-stderr-sentinel"
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
    assert "reader contract" in str(raised.value)


def test_postprocess_ledger_failure_retains_successful_process_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    stdout = json.dumps({"process": "ledger-failure-sentinel"})
    stderr = "ledger-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)
    input_vault = inputs[-1]
    forged = _parent_result(input_vault)
    assert isinstance(forged.stats, dict)
    forged.stats["solve_conflicts"] = 513

    def fake_parser(*_: object, **__: object) -> JointScoreSieveV10Result:
        return JointScoreSieveV10Result(
            **forged.__dict__,
            reader=_reader(),
        )

    monkeypatch.setattr(sieve_v10, "_parse_native_payload", fake_parser)
    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)

    _assert_process_evidence(
        raised.value,
        command=command,
        stdout=stdout,
        stderr=stderr,
        samples=samples,
    )


def test_nonzero_seed_is_rejected_before_native_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("native launch should not occur")

    monkeypatch.setattr(sieve_v10._v9._v8._v7, "_execute_native", forbidden)
    with pytest.raises(JointScoreSieveExecutionError, match="reader"):
        _run_inputs(inputs, seed=1)


def test_public_constants_match_the_frozen_native_identity() -> None:
    assert JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v7")
    assert JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA.endswith("result-v6")
    assert FORCED_INITIAL_PHASE_READER_SCHEMA == _reader()["schema"]


def _native_phase_gate_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
        and NATIVE_V6_SOURCE.is_file()
        and NATIVE_V7_SOURCE.is_file()
    )


def _strict_compile_native(source: Path, output: Path) -> None:
    completed = subprocess.run(
        [
            "c++",
            *STRICT_NATIVE_FLAGS,
            f"-I{CADICAL_INCLUDE}",
            str(source),
            str(CADICAL_LIBRARY),
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


@pytest.fixture(scope="module")
def strict_phase_native_pair(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    if not _native_phase_gate_available():
        pytest.skip("CaDiCaL development files absent")
    build = tmp_path_factory.mktemp("joint-score-sieve-v10-phase-gate")
    native_v6 = build / "native-v6-default-phase"
    native_v7 = build / "native-v7-forced-phase-zero"
    _strict_compile_native(NATIVE_V6_SOURCE, native_v6)
    _strict_compile_native(NATIVE_V7_SOURCE, native_v7)
    return native_v6, native_v7


def _run_phase_native(
    executable: Path,
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            str(executable),
            "--cnf",
            str(cnf),
            "--potential",
            str(potential),
            "--grouping",
            str(grouping),
            "--vault-in",
            str(vault),
            "--threshold",
            "5",
            "--conflict-limit",
            "64",
            "--seed",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def _emitted_literal_rows(payload: dict[str, Any]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(row["literals"]) for row in payload["vault"]["fully_emitted_clauses"]
    )


def test_real_target_free_phase_zero_reader_changes_asymmetric_branch_trace(
    tmp_path: Path,
    strict_phase_native_pair: tuple[Path, Path],
) -> None:
    """Compare only public synthetic phase behavior; no target or truth is read."""

    native_v6, native_v7 = strict_phase_native_pair
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="52" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 10.0)),),
    )
    cnf = tmp_path / "empty-branch-sensitive.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "asymmetric-unary.potential"
    grouping = tmp_path / "asymmetric-unary.grouping"
    sieve_v10.write_joint_score_sieve_potential(potential, field)
    sieve_v10.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=5.0,
    )
    empty_vault = ThresholdNoGoodVault(identity, field.observed_variables, ())
    vault = tmp_path / "empty.vault"
    write_threshold_no_good_vault(vault, empty_vault, caps=O1C66_VAULT_CAPS)

    default_phase = _run_phase_native(
        native_v6,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    forced_phase_first = _run_phase_native(
        native_v7,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    forced_phase_second = _run_phase_native(
        native_v7,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )

    assert default_phase["schema"].endswith("result-v6")
    assert "reader" not in default_phase
    assert forced_phase_first["schema"] == JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert (
        forced_phase_first["implementation_parent_schema"]
        == JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    assert (
        validate_forced_initial_phase_reader(forced_phase_first["reader"]) == _reader()
    )
    assert type(forced_phase_first["reader"]["phase"]) is int

    stable_first = dict(forced_phase_first)
    stable_second = dict(forced_phase_second)
    stable_first.pop("resources")
    stable_second.pop("resources")
    assert stable_first == stable_second

    default_emitted = _emitted_literal_rows(default_phase)
    forced_emitted = _emitted_literal_rows(forced_phase_first)
    assert default_phase["status"] == forced_phase_first["status"] == 10
    assert default_emitted == ()
    assert forced_emitted == ((1,),)
    assert default_phase["sieve"]["minimum_upper_bound"] == 10.0
    assert forced_phase_first["sieve"]["minimum_upper_bound"] == 0.0
    assert (
        default_phase["sieve"]["trace_sha256"]
        != forced_phase_first["sieve"]["trace_sha256"]
        or default_emitted != forced_emitted
    )
