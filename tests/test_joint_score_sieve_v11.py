from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v11 as sieve_v11
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v11 import (
    FORCED_INITIAL_PHASE_READER_SCHEMA,
    FORCED_INITIAL_PHASE_READER_SPEC_SHA256,
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA,
    JointScoreSieveExecutionError,
    JointScoreSieveV11Result,
    forced_initial_phase_reader_spec_bytes,
    run_joint_score_sieve,
    validate_forced_initial_phase_reader,
)
from o1_crypto_lab.joint_score_sieve_v9 import JointScoreSieveV9Result
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_V6_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v6.cpp"
NATIVE_V7_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v7.cpp"
NATIVE_V8_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v8.cpp"
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
        "phase": 1,
        "forcephase": True,
        "rephase": 0,
        "lucky": False,
        "walk": False,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "reader_spec_sha256": (
            "ce039b56a647cbc67deea1fa70db7e755ea00a6dd183015a43e94c032b5706cc"
        ),
    }


def _payload(*, reader: object | None = None) -> dict[str, object]:
    payload: dict[str, object] = {name: None for name in sieve_v11._TOP_LEVEL_FIELDS}
    payload.update(
        {
            "schema": "o1-256-cadical-joint-score-sieve-result-v8",
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
) -> JointScoreSieveV11Result:
    field = _field()
    return sieve_v11._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=field,
        grouping=sieve_v11.build_compatibility_grouping(field),
        grouping_sha256="45" * 32,
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        threshold=0.0,
        requested_conflicts=512,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
    )


def test_phase_one_reader_preimage_digest_and_identity_are_exact() -> None:
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
        b"phase=1\n"
    )
    assert forced_initial_phase_reader_spec_bytes() == expected
    assert len(expected) == 146
    assert hashlib.sha256(expected).hexdigest() == (
        FORCED_INITIAL_PHASE_READER_SPEC_SHA256
    )
    assert validate_forced_initial_phase_reader(_reader()) == _reader()


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    (
        (lambda reader: reader.pop("phase"), "reader fields"),
        (lambda reader: reader.__setitem__("extra", 0), "reader fields"),
        (lambda reader: reader.__setitem__("phase", False), "reader contract"),
        (lambda reader: reader.__setitem__("phase", 0), "reader contract"),
        (
            lambda reader: reader.__setitem__("reader_spec_sha256", "00" * 32),
            "reader contract",
        ),
        (lambda reader: reader.__setitem__("forcephase", 1), "reader contract"),
        (lambda reader: reader.__setitem__("seed", False), "reader contract"),
    ),
)
def test_wrong_phase_one_reader_identity_and_types_are_rejected(
    mutation: Any, pattern: str
) -> None:
    reader = _reader()
    mutation(reader)
    with pytest.raises(O1RelationalSearchError, match=pattern):
        validate_forced_initial_phase_reader(reader)


def test_v8_payload_projects_to_v9_without_weakening_parent_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_vault = _vault()
    original = _payload()
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **_: object) -> JointScoreSieveV9Result:
        assert isinstance(payload, dict)
        seen.update(payload)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v11._v9, "_parse_native_payload", fake_parent)
    result = _parse(original, input_vault=input_vault)

    assert isinstance(result, JointScoreSieveV11Result)
    assert result.reader == _reader()
    assert result.raw == original
    assert "reader" not in seen
    assert seen["schema"] == sieve_v11._v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert (
        seen["implementation_parent_schema"]
        == sieve_v11._v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    assert set(seen) == sieve_v11._v9._TOP_LEVEL_FIELDS


def _inputs(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault]:
    field = _field()
    executable = tmp_path / "synthetic-native-v8"
    executable.write_bytes(b"synthetic-native-v8")
    cnf = tmp_path / "target-free.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "target-free.potential"
    sieve_v11.write_joint_score_sieve_potential(potential, field)
    grouping = tmp_path / "target-free.grouping"
    sieve_v11.write_joint_score_sieve_grouping(grouping, field)
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
        return sieve_v11._v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(sieve_v11._v9._v8._v7, "_execute_native", fake_execute)
    return command_seen, samples


def _run_inputs(
    inputs: tuple[Path, Path, Path, Path, Path, ThresholdNoGoodVault],
    *,
    seed: int = 0,
) -> JointScoreSieveV11Result:
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


def test_full_mocked_process_preserves_actual_conflict_ledger_and_no_phase_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)
    command, _ = _mock_execution(monkeypatch, stdout=json.dumps(_payload()))
    input_vault = inputs[-1]

    def fake_parent(payload: object, **_: object) -> JointScoreSieveV9Result:
        assert isinstance(payload, dict)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v11._v9, "_parse_native_payload", fake_parent)
    result = _run_inputs(inputs)

    assert result.stats["requested_conflicts"] == 512
    assert result.stats["conflict_limit_overshoot"] == 2
    assert result.stats["billed_conflicts"] == 514
    assert result.reader == _reader()
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
    reader["phase"] = 0
    forged["reader"] = reader
    stdout = json.dumps(forged)
    stderr = "phase-one-parser-stderr-sentinel"
    command, samples = _mock_execution(monkeypatch, stdout=stdout, stderr=stderr)

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


def test_nonzero_seed_is_rejected_before_native_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_path)

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("native launch should not occur")

    monkeypatch.setattr(sieve_v11._v9._v8._v7, "_execute_native", forbidden)
    with pytest.raises(JointScoreSieveExecutionError, match="reader"):
        _run_inputs(inputs, seed=1)


def test_public_constants_bind_v11_to_native_v8_and_frozen_v6() -> None:
    assert sieve_v11.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA.endswith("v11-adapter-v1")
    assert JOINT_SCORE_SIEVE_RESULT_SCHEMA.endswith("result-v8")
    assert JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA.endswith("result-v6")
    assert FORCED_INITIAL_PHASE_READER_SCHEMA == _reader()["schema"]


def _native_phase_gate_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
        and NATIVE_V6_SOURCE.is_file()
        and NATIVE_V7_SOURCE.is_file()
        and NATIVE_V8_SOURCE.is_file()
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
def strict_phase_natives(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path, Path]:
    if not _native_phase_gate_available():
        pytest.skip("CaDiCaL development files absent")
    build = tmp_path_factory.mktemp("joint-score-sieve-v11-phase-gate")
    native_v6 = build / "native-v6-default-phase-one"
    native_v7 = build / "native-v7-forced-phase-zero"
    native_v8 = build / "native-v8-explicit-phase-one"
    _strict_compile_native(NATIVE_V6_SOURCE, native_v6)
    _strict_compile_native(NATIVE_V7_SOURCE, native_v7)
    _strict_compile_native(NATIVE_V8_SOURCE, native_v8)
    return native_v6, native_v7, native_v8


def _run_phase_native(
    executable: Path,
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
    threshold: float,
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
            format(threshold, ".17g"),
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


def _write_fixture(
    tmp_path: Path,
    *,
    cnf_text: str,
    field: CriticalityPotentialField,
    threshold: float,
    name: str,
    clauses: tuple[ThresholdNoGoodClause, ...] = (),
) -> tuple[Path, Path, Path, Path, ThresholdNoGoodVault]:
    cnf = tmp_path / f"{name}.cnf"
    cnf.write_text(cnf_text, encoding="ascii")
    potential = tmp_path / f"{name}.potential"
    grouping = tmp_path / f"{name}.grouping"
    sieve_v11.write_joint_score_sieve_potential(potential, field)
    sieve_v11.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=threshold,
    )
    archive = ThresholdNoGoodVault(identity, field.observed_variables, clauses)
    vault = tmp_path / f"{name}.vault"
    write_threshold_no_good_vault(vault, archive, caps=O1C66_VAULT_CAPS)
    return cnf, potential, grouping, vault, archive


def _normalized_v6_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(payload)
    normalized.pop("resources")
    normalized.pop("reader", None)
    normalized["schema"] = sieve_v11._v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    normalized["implementation_parent_schema"] = (
        sieve_v11._v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    return normalized


def _emitted_literal_rows(payload: dict[str, Any]) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(row["literals"]) for row in payload["vault"]["fully_emitted_clauses"]
    )


def test_real_target_free_v8_is_normalized_exactly_equivalent_to_v6_default(
    tmp_path: Path,
    strict_phase_natives: tuple[Path, Path, Path],
) -> None:
    """The explicit phase-one reader changes identity, not v6 behavior."""

    native_v6, _, native_v8 = strict_phase_natives
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="52" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 10.0)),),
    )
    cnf, potential, grouping, vault, _ = _write_fixture(
        tmp_path,
        cnf_text="p cnf 256 0\n",
        field=field,
        threshold=5.0,
        name="phase-one-equivalence",
    )
    default = _run_phase_native(
        native_v6,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=5.0,
    )
    explicit_first = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=5.0,
    )
    explicit_second = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=5.0,
    )

    assert validate_forced_initial_phase_reader(explicit_first["reader"]) == _reader()
    assert _normalized_v6_payload(explicit_first) == _normalized_v6_payload(default)
    assert _normalized_v6_payload(explicit_second) == _normalized_v6_payload(default)


def test_real_target_free_phase_zero_and_phase_one_readers_diverge(
    tmp_path: Path,
    strict_phase_natives: tuple[Path, Path, Path],
) -> None:
    """The paired immutable readers expose distinct deterministic trajectories."""

    _, native_v7, native_v8 = strict_phase_natives
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="53" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 10.0)),),
    )
    cnf, potential, grouping, vault, _ = _write_fixture(
        tmp_path,
        cnf_text="p cnf 256 0\n",
        field=field,
        threshold=5.0,
        name="phase-reader-divergence",
    )
    phase_zero = _run_phase_native(
        native_v7,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=5.0,
    )
    phase_one = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=5.0,
    )

    assert phase_zero["reader"]["phase"] == 0
    assert phase_one["reader"]["phase"] == 1
    assert (
        phase_zero["reader"]["complement_pair_id"]
        == (phase_one["reader"]["complement_pair_id"])
    )
    assert _emitted_literal_rows(phase_zero) == ((1,),)
    assert _emitted_literal_rows(phase_one) == ()
    assert phase_zero["sieve"]["minimum_upper_bound"] == 0.0
    assert phase_one["sieve"]["minimum_upper_bound"] == 10.0
    assert phase_zero["sieve"]["trace_sha256"] != phase_one["sieve"]["trace_sha256"]


def test_real_target_free_phase_zero_vault_perturbs_phase_one_sequence(
    tmp_path: Path,
    strict_phase_natives: tuple[Path, Path, Path],
) -> None:
    """A phase-zero exclusion changes the complementary phase-one trajectory."""

    _, native_v7, native_v8 = strict_phase_natives
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="54" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 10.0)),
            CriticalityPotentialFactor((2,), (0.0, 10.0)),
        ),
    )
    cnf, potential, grouping, empty_vault_path, empty_vault = _write_fixture(
        tmp_path,
        cnf_text="p cnf 256 1\n-1 -2 0\n",
        field=field,
        threshold=15.0,
        name="alternating-reader-empty",
    )
    phase_zero = _run_phase_native(
        native_v7,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=empty_vault_path,
        threshold=15.0,
    )
    new_rows = tuple(
        ThresholdNoGoodClause(tuple(row["literals"]))
        for row in phase_zero["vault"]["fully_emitted_clauses"]
        if row["classification"] == "new"
    )
    assert new_rows
    phase_zero_vault = ThresholdNoGoodVault(
        empty_vault.identity,
        empty_vault.observed_variables,
        new_rows,
    )
    assert phase_zero["vault"]["next_vault_sha256"] == phase_zero_vault.sha256
    assert (
        phase_zero["vault"]["next_serialized_bytes"]
        == phase_zero_vault.serialized_bytes
    )
    imported_vault_path = tmp_path / "alternating-reader-imported.vault"
    write_threshold_no_good_vault(
        imported_vault_path, phase_zero_vault, caps=O1C66_VAULT_CAPS
    )

    phase_one_empty = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=empty_vault_path,
        threshold=15.0,
    )
    phase_one_imported = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=imported_vault_path,
        threshold=15.0,
    )
    phase_one_empty_repeat = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=empty_vault_path,
        threshold=15.0,
    )
    phase_one_imported_repeat = _run_phase_native(
        native_v8,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=imported_vault_path,
        threshold=15.0,
    )

    stable_empty = copy.deepcopy(phase_one_empty)
    stable_empty_repeat = copy.deepcopy(phase_one_empty_repeat)
    stable_imported = copy.deepcopy(phase_one_imported)
    stable_imported_repeat = copy.deepcopy(phase_one_imported_repeat)
    for payload in (
        stable_empty,
        stable_empty_repeat,
        stable_imported,
        stable_imported_repeat,
    ):
        payload.pop("resources")
    assert stable_empty == stable_empty_repeat
    assert stable_imported == stable_imported_repeat

    assert phase_one_imported["status"] == 20
    assert phase_one_imported["vault"]["preloaded_clause_count"] == len(new_rows)
    assert phase_one_imported["vault"]["fully_emitted_clause_count"] == 0
    assert (
        phase_one_imported["sieve"]["trace_sha256"]
        != phase_one_empty["sieve"]["trace_sha256"]
        or phase_one_imported["stats"] != phase_one_empty["stats"]
    )
