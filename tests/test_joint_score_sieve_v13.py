from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v13 as sieve_v13
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import build_compatibility_grouping
from o1_crypto_lab.joint_score_sieve_v13 import (
    JointScoreSieveExecutionError,
    JointScoreSieveV13Result,
    run_joint_score_sieve,
    validate_vault_ranked_decision_reader,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)
from o1_crypto_lab.vault_phase_field_v1 import derive_vault_phase_field
from o1_crypto_lab.vault_ranked_decision_v1 import (
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_vault_ranked_decision,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_V9_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v9.cpp"
NATIVE_V10_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v10.cpp"
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


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="73" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (8.0, 0.0)),
            CriticalityPotentialFactor((2,), (6.0, 0.0)),
            CriticalityPotentialFactor((3,), (0.0, 10.0)),
        ),
    )


def _fixture_artifacts(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, ThresholdNoGoodVault, VaultRankedDecision]:
    field = _field()
    cnf = tmp_path / "ranked-target-free.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    potential = tmp_path / "ranked-target-free.potential"
    grouping = tmp_path / "ranked-target-free.grouping"
    sieve_v13.write_joint_score_sieve_potential(potential, field)
    sieve_v13.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v13.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    input_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
        ),
    )
    vault = tmp_path / "ranked-target-free.vault"
    write_threshold_no_good_vault(vault, input_vault, caps=O1C66_VAULT_CAPS)
    phase = derive_vault_phase_field(
        vault.read_bytes(), key_variable_count=256, clause_start=0
    )
    decision = derive_vault_ranked_decision(
        phase,
        field,
        build_compatibility_grouping(field, width_cap=6),
    )
    return cnf, potential, grouping, vault, input_vault, decision


def _reader(
    decision: VaultRankedDecision,
    returns: tuple[int, ...] = (3, -1, -2, 0),
) -> dict[str, object]:
    sequence = b"".join(struct.pack("<i", literal) for literal in returns)
    nonzero = sum(literal != 0 for literal in returns)
    zero = len(returns) - nonzero
    first_fallback = next(
        (index for index, literal in enumerate(returns, start=1) if not literal),
        None,
    )
    return {
        **decision.reader_binding(),
        "decision_rule": sieve_v13.VAULT_RANKED_DECISION_DECISION_RULE,
        "callback_rule": sieve_v13.VAULT_RANKED_DECISION_CALLBACK_RULE,
        "cb_decide_calls": len(returns),
        "cb_decide_nonzero": nonzero,
        "cb_decide_zero": zero,
        "returned_sequence_encoding": (
            sieve_v13.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        ),
        "returned_sequence_count": len(returns),
        "returned_sequence_bytes": len(sequence),
        "returned_sequence_hex": sequence.hex(),
        "returned_sequence_sha256": hashlib.sha256(sequence).hexdigest(),
        "unique_returned_variables": len(
            {abs(literal) for literal in returns if literal}
        ),
        "redecisions": nonzero
        - len({abs(literal) for literal in returns if literal}),
        "first_fallback_call": first_fallback,
        "solver_phase_calls": 0,
    }


def _payload(
    decision: VaultRankedDecision,
    *,
    reader: object | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {name: None for name in sieve_v13._TOP_LEVEL_FIELDS}
    actual_reader = _reader(decision) if reader is None else reader
    calls = actual_reader.get("cb_decide_calls", 0) if isinstance(actual_reader, dict) else 0
    result.update(
        {
            "schema": sieve_v13.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                sieve_v13.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "seed": 0,
            "reader": actual_reader,
            "sieve": {"cb_decide_calls": calls, "cb_decide_nonzero": 0},
        }
    )
    return result


def _parent_result(input_vault: ThresholdNoGoodVault) -> Any:
    return sieve_v13._v12.JointScoreSieveV12Result(
        status=0,
        conflict_limit=512,
        threshold=12.0,
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
        reader=sieve_v13._v12._expected_reader(),
    )


def _parse(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    decision: VaultRankedDecision,
) -> JointScoreSieveV13Result:
    field = _field()
    return sieve_v13._parse_native_payload(
        payload,
        input_vault=input_vault,
        vault_caps=O1C66_VAULT_CAPS,
        field=field,
        grouping=build_compatibility_grouping(field, width_cap=6),
        grouping_sha256=input_vault.identity.grouping_sha256,
        cnf_sha256=input_vault.identity.cnf_sha256,
        potential_sha256=input_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=512,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=decision,
    )


def test_reader_validates_rank_and_complete_return_sequence(tmp_path: Path) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    returns = (3, -1, -2, 0, 3)
    reader = _reader(decision, returns)
    assert validate_vault_ranked_decision_reader(
        reader, expected_decision=decision
    ) == {name: reader[name] for name in sorted(reader)}
    assert decision.ranked_literals == (3, -1, -2)
    assert tuple(abs(row.delta) for row in decision.rows) == (2, 1, 1)
    assert tuple(row.gap for row in decision.rows) == (10.0, 8.0, 6.0)
    assert reader["redecisions"] == 1
    assert reader["first_fallback_call"] == 4


@pytest.mark.parametrize(
    ("field", "forged", "message"),
    (
        ("order_sha256", "00" * 32, "rank contract"),
        ("cb_decide_calls", True, "runtime scalar"),
        ("returned_sequence_sha256", "00" * 32, "callback telemetry"),
        ("first_fallback_call", 2, "callback telemetry"),
        ("solver_phase_calls", 1, "callback telemetry"),
    ),
)
def test_reader_rejects_static_and_runtime_tampering(
    tmp_path: Path, field: str, forged: object, message: str
) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    reader[field] = forged
    with pytest.raises(O1RelationalSearchError, match=message):
        validate_vault_ranked_decision_reader(reader, expected_decision=decision)


def test_reader_rejects_wrong_literal_sign_and_noncanonical_hex(tmp_path: Path) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    wrong_sign = _reader(decision, (3, 1))
    with pytest.raises(O1RelationalSearchError, match="callback telemetry"):
        validate_vault_ranked_decision_reader(
            wrong_sign, expected_decision=decision
        )

    noncanonical = _reader(decision)
    noncanonical["returned_sequence_hex"] = str(
        noncanonical["returned_sequence_hex"]
    ).upper()
    with pytest.raises(O1RelationalSearchError, match="sequence encoding"):
        validate_vault_ranked_decision_reader(
            noncanonical, expected_decision=decision
        )


def test_rank_reader_is_checked_before_v12_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    *_, input_vault, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    reader["rank_table_sha256"] = "00" * 32
    called = False

    def forbidden(*_: object, **__: object) -> Any:
        nonlocal called
        called = True
        raise AssertionError("v12 projection must not run")

    monkeypatch.setattr(sieve_v13._v12, "_parse_native_payload", forbidden)
    with pytest.raises(O1RelationalSearchError, match="rank contract"):
        _parse(
            _payload(decision, reader=reader),
            input_vault=input_vault,
            decision=decision,
        )
    assert not called


def test_v10_payload_projects_every_inherited_field_through_v12(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    *_, input_vault, decision = _fixture_artifacts(tmp_path)
    original = _payload(decision)
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **_: object) -> Any:
        assert isinstance(payload, dict)
        seen.update(payload)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v13._v12, "_parse_native_payload", fake_parent)
    result = _parse(original, input_vault=input_vault, decision=decision)
    assert isinstance(result, JointScoreSieveV13Result)
    assert result.raw == original
    assert result.reader == _reader(decision)
    assert seen["schema"] == sieve_v13._v12.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert seen["reader"] == sieve_v13._v12._expected_reader()
    assert set(seen) == sieve_v13._v12._TOP_LEVEL_FIELDS


def _mock_execution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str,
    expected_rank: bytes,
    stderr: str = "ranked-reader-stderr",
) -> tuple[list[str], list[Path], tuple[dict[str, int | float], ...]]:
    command_seen: list[str] = []
    rank_paths: list[Path] = []
    samples: tuple[dict[str, int | float], ...] = (
        {"elapsed_seconds": 0.25, "rss_bytes": 12_345},
    )

    def fake_execute(
        command: list[str], *, timeout_seconds: float, memory_limit_bytes: int | None
    ) -> Any:
        assert timeout_seconds == 60.0
        assert memory_limit_bytes is None
        command_seen.extend(command)
        rank_path = Path(command[command.index("--rank-table") + 1])
        rank_paths.append(rank_path)
        assert rank_path.read_bytes() == expected_rank
        assert rank_path.stat().st_mode & 0o777 == 0o600
        return sieve_v13._v12._v11._v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(
        sieve_v13._v12._v11._v9._v8._v7, "_execute_native", fake_execute
    )
    return command_seen, rank_paths, samples


def test_full_mock_writes_bounded_rank_table_and_preserves_billing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, grouping, vault, input_vault, decision = _fixture_artifacts(
        tmp_path
    )
    executable = tmp_path / "synthetic-native-v10"
    executable.write_bytes(b"synthetic-native-v10")
    command, rank_paths, _ = _mock_execution(
        monkeypatch,
        stdout=json.dumps(_payload(decision)),
        expected_rank=decision.rank_table_bytes,
    )
    monkeypatch.setattr(
        sieve_v13,
        "derive_production_vault_ranked_decision",
        lambda *_: decision,
    )
    monkeypatch.setattr(
        sieve_v13._v12,
        "_parse_native_payload",
        lambda *_, **__: _parent_result(input_vault),
    )
    result = run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=12.0,
        conflict_limit=512,
        seed=0,
    )
    assert result.stats["requested_conflicts"] == 512
    assert result.stats["conflict_limit_overshoot"] == 2
    assert result.stats["billed_conflicts"] == 514
    assert command[command.index("--rank-table") + 1] == str(rank_paths[0])
    assert not rank_paths[0].exists()
    assert "--phase" not in command
    assert "--forcephase" not in command


def test_reader_rejection_after_process_retains_failure_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, grouping, vault, _, decision = _fixture_artifacts(tmp_path)
    executable = tmp_path / "synthetic-native-v10"
    executable.write_bytes(b"synthetic-native-v10")
    forged = _payload(decision)
    reader = copy.deepcopy(forged["reader"])
    assert isinstance(reader, dict)
    reader["returned_sequence_sha256"] = "00" * 32
    forged["reader"] = reader
    stdout = json.dumps(forged)
    command, rank_paths, samples = _mock_execution(
        monkeypatch,
        stdout=stdout,
        expected_rank=decision.rank_table_bytes,
    )
    monkeypatch.setattr(
        sieve_v13,
        "derive_production_vault_ranked_decision",
        lambda *_: decision,
    )
    with pytest.raises(JointScoreSieveExecutionError) as raised:
        run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            vault_path=vault,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=12.0,
            conflict_limit=512,
            seed=0,
        )
    telemetry = raised.value.failure_telemetry
    assert telemetry["classification_kind"] == "adapter_or_parser"
    assert telemetry["phase"] == "adapter_validation"
    assert telemetry["command"] == command
    assert telemetry["returncode"] == 0
    assert telemetry["stdout"] == stdout
    assert telemetry["memory_samples"] == list(samples)
    assert not rank_paths[0].exists()


def test_nonproduction_rank_is_rejected_before_native_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, grouping, vault, _, _ = _fixture_artifacts(tmp_path)
    executable = tmp_path / "synthetic-native-v10"
    executable.write_bytes(b"synthetic-native-v10")

    def reject(*_: object, **__: object) -> Any:
        raise VaultRankedDecisionError("production rank differs")

    def forbidden(*_: object, **__: object) -> Any:
        raise AssertionError("native launch should not occur")

    monkeypatch.setattr(sieve_v13, "derive_production_vault_ranked_decision", reject)
    monkeypatch.setattr(
        sieve_v13._v12._v11._v9._v8._v7, "_execute_native", forbidden
    )
    with pytest.raises(JointScoreSieveExecutionError, match="sealed ranked"):
        run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            vault_path=vault,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=12.0,
            conflict_limit=64,
            seed=0,
        )


def _native_gate_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
        and NATIVE_V9_SOURCE.is_file()
        and NATIVE_V10_SOURCE.is_file()
    )


def _strict_compile_native(source: Path, output: Path, *, macro: str) -> None:
    completed = subprocess.run(
        [
            "c++",
            *STRICT_NATIVE_FLAGS,
            f"-D{macro}",
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
def public_rank_natives(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path, Path]:
    if not _native_gate_available():
        pytest.skip("CaDiCaL development files or native v10 absent")
    build = tmp_path_factory.mktemp("joint-score-sieve-v13-public-rank")
    first = build / "native-v10-first"
    second = build / "native-v10-second"
    passive = build / "native-v9-passive"
    _strict_compile_native(
        NATIVE_V10_SOURCE,
        first,
        macro="O1_CRYPTO_LAB_O1C71_PUBLIC_FIXTURE",
    )
    _strict_compile_native(
        NATIVE_V10_SOURCE,
        second,
        macro="O1_CRYPTO_LAB_O1C71_PUBLIC_FIXTURE",
    )
    _strict_compile_native(
        NATIVE_V9_SOURCE,
        passive,
        macro="O1_CRYPTO_LAB_O1C70_PUBLIC_FIXTURE",
    )
    return first, second, passive


def _run_native(
    executable: Path,
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
    rank_table: Path | None,
) -> dict[str, Any]:
    command = [
        str(executable),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential),
        "--grouping",
        str(grouping),
        "--vault-in",
        str(vault),
    ]
    if rank_table is not None:
        command.extend(("--rank-table", str(rank_table)))
    command.extend(
        (
            "--threshold",
            "12",
            "--conflict-limit",
            "64",
            "--seed",
            "0",
        )
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr
    parsed = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return parsed


def _stable(payload: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop("resources")
    return result


def _returned(reader: dict[str, Any]) -> tuple[int, ...]:
    payload = bytes.fromhex(reader["returned_sequence_hex"])
    return struct.unpack(f"<{len(payload) // 4}i", payload)


def test_public_rank_callback_prefix_is_nonascending_and_deterministic(
    tmp_path: Path,
    public_rank_natives: tuple[Path, Path, Path],
) -> None:
    first_native, second_native, passive_native = public_rank_natives
    cnf, potential, grouping, vault, _, decision = _fixture_artifacts(tmp_path)
    rank_table = tmp_path / "target-free.rank-table"
    rank_table.write_bytes(decision.rank_table_bytes)

    first = _run_native(
        first_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )
    repeat = _run_native(
        first_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )
    second_build = _run_native(
        second_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )
    passive = _run_native(
        passive_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=None,
    )

    assert _stable(first) == _stable(repeat) == _stable(second_build)
    binding = decision.reader_binding()
    assert {name: first["reader"][name] for name in binding} == binding
    assert validate_vault_ranked_decision_reader(
        first["reader"], expected_decision=decision
    )
    assert _returned(first["reader"])[:3] == (3, -1, -2)
    assert first["reader"]["ranked_literals"] == [3, -1, -2]
    assert first["reader"]["solver_phase_calls"] == 0
    assert first["reader"]["cb_decide_nonzero"] >= 3
    assert first["sieve"]["cb_decide_calls"] == first["reader"]["cb_decide_calls"]
    assert passive["schema"] == sieve_v13._v12.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert passive["reader"]["applied_phase_calls"] == 3
    assert passive["sieve"]["cb_decide_nonzero"] == 0


def test_native_source_has_one_connection_and_no_phase_call() -> None:
    if not NATIVE_V10_SOURCE.is_file():
        pytest.skip("native v10 is owned by a concurrent worker")
    source = NATIVE_V10_SOURCE.read_text(encoding="utf-8")
    assert len(re.findall(r"connect_external_propagator\s*\(", source)) == 1
    assert not re.search(r"\bsolver\s*\.\s*phase\s*\(", source)


def test_native_rejects_tampered_rank_table(
    tmp_path: Path,
    public_rank_natives: tuple[Path, Path, Path],
) -> None:
    native, _, _ = public_rank_natives
    cnf, potential, grouping, vault, _, decision = _fixture_artifacts(tmp_path)
    tampered = bytearray(decision.rank_table_bytes)
    tampered[-1] ^= 1
    rank_table = tmp_path / "tampered.rank-table"
    rank_table.write_bytes(tampered)
    completed = subprocess.run(
        [
            str(native),
            "--cnf",
            str(cnf),
            "--potential",
            str(potential),
            "--grouping",
            str(grouping),
            "--vault-in",
            str(vault),
            "--rank-table",
            str(rank_table),
            "--threshold",
            "12",
            "--conflict-limit",
            "64",
            "--seed",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode != 0
    assert "rank" in completed.stderr.lower()
