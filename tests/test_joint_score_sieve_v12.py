from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v12 as sieve_v12
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v12 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JointScoreSieveExecutionError,
    JointScoreSieveV12Result,
    run_joint_score_sieve,
    validate_vault_phase_field_reader,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)
from o1_crypto_lab.vault_phase_field_v1 import (
    PRODUCTION_UNPHASED_VARIABLES,
    PRODUCTION_VAULT_PHASE_READER,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_V6_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v6.cpp"
NATIVE_V8_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v8.cpp"
NATIVE_V9_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v9.cpp"
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
    reader = dict(PRODUCTION_VAULT_PHASE_READER)
    reader["unphased_variables"] = list(PRODUCTION_UNPHASED_VARIABLES)
    return reader


def _payload(*, reader: object | None = None) -> dict[str, object]:
    payload: dict[str, object] = {name: None for name in sieve_v12._TOP_LEVEL_FIELDS}
    payload.update(
        {
            "schema": sieve_v12.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                sieve_v12.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
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


def _parent_result(input_vault: ThresholdNoGoodVault) -> Any:
    return sieve_v12._v11.JointScoreSieveV11Result(
        status=0,
        conflict_limit=512,
        threshold=0.0,
        key_model=None,
        stats={
            "conflicts": 531,
            "conflicts_before_solve": 17,
            "solve_conflicts": 514,
            "decisions": 9,
            "propagations": 99,
        },
        sieve={},
        resources={},
        raw={},
        adapter_memory={},
        input_vault=input_vault,
        eligible_emitted_clauses=(),
        next_vault=input_vault,
        vault_telemetry={},
        reader=sieve_v12._v11._expected_reader(),
    )


def _parse(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
) -> JointScoreSieveV12Result:
    field = _field()
    return sieve_v12._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=field,
        grouping=sieve_v12.build_compatibility_grouping(field),
        grouping_sha256="45" * 32,
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        threshold=0.0,
        requested_conflicts=512,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
    )


def test_exact_reader_mapping_and_json_scalar_types_are_validated() -> None:
    assert validate_vault_phase_field_reader(_reader()) == _reader()
    assert len(_reader()) == 36

    for name, forged in (
        ("field_bytes", True),
        ("forcephase", 1),
        ("field_sha256", "00" * 32),
        ("unphased_variables", (241,)),
    ):
        reader = _reader()
        reader[name] = forged
        with pytest.raises(O1RelationalSearchError, match="reader"):
            validate_vault_phase_field_reader(reader)

    missing = _reader()
    missing.pop("field_sha256")
    with pytest.raises(O1RelationalSearchError, match="reader fields"):
        validate_vault_phase_field_reader(missing)


def test_reader_is_checked_before_v11_parent_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader()
    reader["applied_phase_calls"] = 254
    called = False

    def forbidden(*_: object, **__: object) -> Any:
        nonlocal called
        called = True
        raise AssertionError("parent validation must not run")

    monkeypatch.setattr(sieve_v12._v11, "_parse_native_payload", forbidden)
    with pytest.raises(O1RelationalSearchError, match="reader contract"):
        _parse(_payload(reader=reader), input_vault=_vault())
    assert not called


def test_v9_payload_projects_to_v11_without_weakening_parent_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_vault = _vault()
    original = _payload()
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **_: object) -> Any:
        assert isinstance(payload, dict)
        seen.update(payload)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v12._v11, "_parse_native_payload", fake_parent)
    result = _parse(original, input_vault=input_vault)

    assert isinstance(result, JointScoreSieveV12Result)
    assert result.reader == _reader()
    assert result.raw == original
    assert seen["schema"] == sieve_v12._v11.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert seen["reader"] == sieve_v12._v11._expected_reader()
    assert set(seen) == sieve_v12._v11._TOP_LEVEL_FIELDS


def _inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault]:
    field = _field()
    executable = tmp_path / "synthetic-native-v9"
    executable.write_bytes(b"synthetic-native-v9")
    cnf = tmp_path / "target-free.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "target-free.potential"
    grouping = tmp_path / "target-free.grouping"
    sieve_v12.write_joint_score_sieve_potential(potential, field)
    sieve_v12.write_joint_score_sieve_grouping(grouping, field)
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
        return sieve_v12._v11._v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(sieve_v12._v11._v9._v8._v7, "_execute_native", fake_execute)
    return command_seen, samples


def _run_inputs(
    inputs: tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault],
) -> JointScoreSieveV12Result:
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
        seed=0,
    )


def test_full_mock_preserves_conflict_ledger_and_has_no_phase_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    input_vault = inputs[-1]
    command, _ = _mock_execution(monkeypatch, stdout=json.dumps(_payload()))
    monkeypatch.setattr(
        sieve_v12, "validate_production_vault_phase_field", lambda _: object()
    )
    monkeypatch.setattr(
        sieve_v12._v11,
        "_parse_native_payload",
        lambda *_, **__: _parent_result(input_vault),
    )

    result = _run_inputs(inputs)
    assert result.stats["requested_conflicts"] == 512
    assert result.stats["conflict_limit_overshoot"] == 2
    assert result.stats["billed_conflicts"] == 514
    assert command[command.index("--seed") + 1] == "0"
    assert "--phase" not in command
    assert "--forcephase" not in command


def test_reader_rejection_after_successful_process_retains_failure_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    forged = _payload()
    reader = copy.deepcopy(forged["reader"])
    assert isinstance(reader, dict)
    reader["field_sha256"] = "00" * 32
    forged["reader"] = reader
    stdout = json.dumps(forged)
    stderr = "phase-field-parser-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(
        sieve_v12, "validate_production_vault_phase_field", lambda _: object()
    )

    with pytest.raises(JointScoreSieveExecutionError) as raised:
        _run_inputs(inputs)
    telemetry = raised.value.failure_telemetry
    assert telemetry["classification_kind"] == "adapter_or_parser"
    assert telemetry["phase"] == "adapter_validation"
    assert telemetry["command"] == command
    assert telemetry["returncode"] == 0
    assert telemetry["stdout"] == stdout
    assert telemetry["stderr"] == stderr
    assert telemetry["memory_samples"] == list(samples)


def test_nonproduction_vault_is_rejected_before_native_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)

    def forbidden(*_: object, **__: object) -> Any:
        raise AssertionError("native launch should not occur")

    monkeypatch.setattr(sieve_v12._v11._v9._v8._v7, "_execute_native", forbidden)
    with pytest.raises(JointScoreSieveExecutionError, match="sealed vault"):
        _run_inputs(inputs)


def _native_phase_gate_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
        and NATIVE_V6_SOURCE.is_file()
        and NATIVE_V8_SOURCE.is_file()
        and NATIVE_V9_SOURCE.is_file()
    )


def _strict_compile_native(
    source: Path, output: Path, *, fixture_mode: bool = False
) -> None:
    command = ["c++", *STRICT_NATIVE_FLAGS]
    if fixture_mode:
        command.append("-DO1_CRYPTO_LAB_O1C70_PUBLIC_FIXTURE")
    command.extend(
        [
            f"-I{CADICAL_INCLUDE}",
            str(source),
            str(CADICAL_LIBRARY),
            "-o",
            str(output),
        ]
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr


@pytest.fixture(scope="module")
def public_consequence_natives(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    if not _native_phase_gate_available():
        pytest.skip("CaDiCaL development files absent")
    build = tmp_path_factory.mktemp("joint-score-sieve-v12-public-consequence")
    passive = build / "native-v8-passive-phase-one"
    active = build / "native-v9-public-fixture"
    _strict_compile_native(NATIVE_V8_SOURCE, passive)
    _strict_compile_native(NATIVE_V9_SOURCE, active, fixture_mode=True)
    return passive, active


def _write_consequence_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path]:
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="73" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 10.0)),
            CriticalityPotentialFactor((2,), (0.0, 10.0)),
        ),
    )
    cnf = tmp_path / "public-consequence.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "public-consequence.potential"
    grouping = tmp_path / "public-consequence.grouping"
    sieve_v12.write_joint_score_sieve_potential(potential, field)
    sieve_v12.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=15.0,
    )
    vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (ThresholdNoGoodClause((-1, 2)),),
    )
    vault_path = tmp_path / "public-consequence.vault"
    write_threshold_no_good_vault(vault_path, vault, caps=O1C66_VAULT_CAPS)
    return cnf, potential, grouping, vault_path


def _run_native(
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
            "15",
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


def _stable(payload: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop("resources")
    return result


def _emitted_rows(payload: dict[str, Any]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(row["literals"]) for row in payload["vault"]["fully_emitted_clauses"]
    )


def test_public_synthetic_phase_field_has_deterministic_native_consequence(
    tmp_path: Path,
    public_consequence_natives: tuple[Path, Path],
) -> None:
    """The certified (-1,+2) vault changes trace and emits (+1,-2)."""

    passive_native, active_native = public_consequence_natives
    cnf, potential, grouping, vault = _write_consequence_fixture(tmp_path)
    passive = _run_native(
        passive_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    passive_repeat = _run_native(
        passive_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    active = _run_native(
        active_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    active_repeat = _run_native(
        active_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )

    assert _stable(passive) == _stable(passive_repeat)
    assert _stable(active) == _stable(active_repeat)
    assert _emitted_rows(passive) == ()
    assert _emitted_rows(active) == ((1, -2),)
    assert passive["sieve"]["minimum_upper_bound"] == 20.0
    assert active["sieve"]["minimum_upper_bound"] == 10.0
    assert active["sieve"]["trace_sha256"] != passive["sieve"]["trace_sha256"]
    assert active["reader"]["positive_count"] == 1
    assert active["reader"]["negative_count"] == 1
    assert active["reader"]["unphased_count"] == 254
    assert active["reader"]["applied_phase_calls"] == 2
