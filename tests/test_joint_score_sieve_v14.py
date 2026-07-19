from __future__ import annotations

import copy
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v14 as sieve_v14
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import build_compatibility_grouping
from o1_crypto_lab.joint_score_sieve_v14 import (
    JointScoreSieveExecutionError,
    JointScoreSieveV14Result,
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
NATIVE_V10_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v10.cpp"
NATIVE_V11_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v11.cpp"
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
        source_sha256="74" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (8.0, 0.0)),
            CriticalityPotentialFactor((2,), (6.0, 0.0)),
            CriticalityPotentialFactor((3,), (0.0, 10.0)),
            CriticalityPotentialFactor((6,), (1.0, 0.0)),
        ),
    )


def _fixture_artifacts(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, ThresholdNoGoodVault, VaultRankedDecision]:
    field = _field()
    cnf = tmp_path / "backtrack-release.cnf"
    cnf.write_text(
        "p cnf 256 5\n6 0\n2 4 5 0\n2 4 -5 0\n2 -4 5 0\n2 -4 -5 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "backtrack-release.potential"
    grouping = tmp_path / "backtrack-release.grouping"
    sieve_v14.write_joint_score_sieve_potential(potential, field)
    sieve_v14.write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v14.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    input_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
            ThresholdNoGoodClause((-1, 3, -6)),
        ),
    )
    vault = tmp_path / "backtrack-release.vault"
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


def _mask(indices: tuple[int, ...]) -> bytes:
    result = bytearray(32)
    for index in indices:
        result[index // 8] |= 1 << (index % 8)
    return bytes(result)


def _byte_fields(prefix: str, payload: bytes) -> dict[str, object]:
    return {
        f"{prefix}_hex": payload.hex(),
        f"{prefix}_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _sequence(literals: tuple[int, ...]) -> bytes:
    return b"".join(struct.pack("<i", literal) for literal in literals)


def _reader(
    decision: VaultRankedDecision,
    *,
    zero_returns: int = 2,
    released_literals: tuple[int, ...] = (-2,),
) -> dict[str, object]:
    once = (3, -1, -2)
    callbacks = once + (0,) * zero_returns
    once_payload = _sequence(once)
    guided_payload = _sequence(released_literals)
    returned_payload = _sequence(callbacks)
    rank_index = {
        literal: index for index, literal in enumerate(decision.ranked_literals)
    }
    returned_indices = tuple(rank_index[literal] for literal in once)
    released_indices = tuple(rank_index[literal] for literal in released_literals)
    reader = decision.reader_binding()
    reader.update(
        {
            "schema": sieve_v14.VAULT_RANKED_DECISION_READER_SCHEMA,
            "release_policy_spec_bytes": (
                sieve_v14.VAULT_BACKTRACK_RELEASE_POLICY_SPEC_BYTES
            ),
            "release_policy_spec_sha256": (
                sieve_v14.VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256
            ),
            "decision_rule": sieve_v14.VAULT_RANKED_DECISION_DECISION_RULE,
            "callback_rule": sieve_v14.VAULT_RANKED_DECISION_CALLBACK_RULE,
            "cursor": 4,
            "rows_consumed": 4,
            "once_returns": 3,
            "skipped_preassigned": 1,
            "consumed_state_bits": 256,
            "consumed_state_bytes": 32,
            "consumed_state_encoding": (sieve_v14.VAULT_RANKED_DECISION_STATE_ENCODING),
            **_byte_fields("consumed_state", _mask((0, 1, 2, 3))),
            "returned_state_bits": 256,
            "returned_state_bytes": 32,
            "returned_state_encoding": (sieve_v14.VAULT_RANKED_DECISION_STATE_ENCODING),
            **_byte_fields("returned_state", _mask(returned_indices)),
            "released_state_bits": 256,
            "released_state_bytes": 32,
            "released_state_encoding": (sieve_v14.VAULT_RANKED_DECISION_STATE_ENCODING),
            **_byte_fields("released_state", _mask(released_indices)),
            "once_return_sequence_encoding": (
                sieve_v14.VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING
            ),
            "once_return_sequence_count": len(once),
            "once_return_sequence_bytes": len(once_payload),
            **_byte_fields("once_return_sequence", once_payload),
            "released_guided": len(released_literals),
            "guided_release_sequence_encoding": (
                sieve_v14.VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING
            ),
            "guided_release_sequence_count": len(released_literals),
            "guided_release_sequence_bytes": len(guided_payload),
            **_byte_fields("guided_release_sequence", guided_payload),
            "cb_decide_calls": len(callbacks),
            "cb_decide_nonzero": len(once),
            "cb_decide_zero": zero_returns,
            "returned_sequence_encoding": (
                sieve_v14.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
            ),
            "returned_sequence_count": len(callbacks),
            "returned_sequence_bytes": len(returned_payload),
            **_byte_fields("returned_sequence", returned_payload),
            "unique_returned_variables": len(once),
            "redecisions": 0,
            "first_fallback_call": 4 if zero_returns else None,
            "solver_phase_calls": 0,
            "bounded_state_rule": (sieve_v14.VAULT_RANKED_DECISION_BOUNDED_STATE_RULE),
            "bounded_guidance_state_bytes": 4 + 3 * 32 + 8 * 4,
            "live_guidance_state_bytes": (
                4 + 3 * 32 + len(once_payload) + len(guided_payload)
            ),
        }
    )
    return reader


def _payload(
    decision: VaultRankedDecision, *, reader: object | None = None
) -> dict[str, object]:
    result: dict[str, object] = {name: None for name in sieve_v14._TOP_LEVEL_FIELDS}
    actual_reader = _reader(decision) if reader is None else reader
    calls = (
        actual_reader.get("cb_decide_calls", 0)
        if isinstance(actual_reader, dict)
        else 0
    )
    result.update(
        {
            "schema": sieve_v14.JOINT_SCORE_SIEVE_RESULT_SCHEMA,
            "implementation_parent_schema": (
                sieve_v14.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "seed": 0,
            "reader": actual_reader,
            "sieve": {"cb_decide_calls": calls, "cb_decide_nonzero": 0},
        }
    )
    return result


def _parent_result(input_vault: ThresholdNoGoodVault) -> Any:
    return sieve_v14._v13.JointScoreSieveV13Result(
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
        reader={},
    )


def _parse(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    decision: VaultRankedDecision,
) -> JointScoreSieveV14Result:
    field = _field()
    return sieve_v14._parse_native_payload(
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


def _replace_bytes(reader: dict[str, object], prefix: str, payload: bytes) -> None:
    reader[f"{prefix}_bytes"] = len(payload)
    reader.update(_byte_fields(prefix, payload))


def test_release_policy_and_stronger_rank_are_exact(tmp_path: Path) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    policy = sieve_v14.vault_backtrack_release_policy_spec_bytes()
    assert len(policy) == 540
    assert hashlib.sha256(policy).hexdigest() == (
        "bfa752664e19d5899d114ee8cf75dd15a52a8306ff2399fde046a5bb6ebdc132"
    )
    assert decision.ranked_literals == (3, -1, -2, -6)
    assert tuple(abs(row.delta) for row in decision.rows) == (3, 2, 1, 1)
    assert tuple(row.gap for row in decision.rows) == (10.0, 8.0, 6.0, 1.0)


def test_reader_validates_complete_one_shot_state(tmp_path: Path) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    assert validate_vault_ranked_decision_reader(
        reader, expected_decision=decision
    ) == {name: reader[name] for name in sorted(reader)}
    assert bytes.fromhex(str(reader["consumed_state_hex"])) == _mask((0, 1, 2, 3))
    assert bytes.fromhex(str(reader["returned_state_hex"])) == _mask((0, 1, 2))
    assert bytes.fromhex(str(reader["released_state_hex"])) == _mask((2,))


@pytest.mark.parametrize(
    ("field", "forged", "message"),
    (
        ("order_sha256", "00" * 32, "rank or release-policy"),
        ("release_policy_spec_sha256", "00" * 32, "rank or release-policy"),
        ("zero_delta_count", True, "static scalar"),
        ("cursor", True, "runtime scalar"),
        ("rows_consumed", 3, "one-shot telemetry"),
        ("cb_decide_nonzero", 2, "one-shot telemetry"),
        ("redecisions", 1, "one-shot telemetry"),
        ("first_fallback_call", 5, "one-shot telemetry"),
        ("solver_phase_calls", 1, "one-shot telemetry"),
        ("bounded_guidance_state_bytes", 131, "one-shot telemetry"),
    ),
)
def test_reader_rejects_static_policy_and_runtime_tampering(
    tmp_path: Path, field: str, forged: object, message: str
) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    reader[field] = forged
    with pytest.raises(O1RelationalSearchError, match=message):
        validate_vault_ranked_decision_reader(reader, expected_decision=decision)


@pytest.mark.parametrize(
    "prefix",
    (
        "consumed_state",
        "returned_state",
        "released_state",
    ),
)
def test_reader_rejects_rank_mask_tampering(tmp_path: Path, prefix: str) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    mask = bytearray(bytes.fromhex(str(reader[f"{prefix}_hex"])))
    mask[31] |= 0x80
    reader.update(_byte_fields(prefix, bytes(mask)))
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(reader, expected_decision=decision)


def test_reader_rejects_out_of_order_duplicate_and_post_zero_returns(
    tmp_path: Path,
) -> None:
    *_, decision = _fixture_artifacts(tmp_path)

    out_of_order = _reader(decision)
    _replace_bytes(out_of_order, "once_return_sequence", _sequence((3, -2, -1)))
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(out_of_order, expected_decision=decision)

    duplicate = _reader(decision)
    _replace_bytes(duplicate, "once_return_sequence", _sequence((3, -1, -1)))
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(duplicate, expected_decision=decision)

    post_zero = _reader(decision, zero_returns=1)
    _replace_bytes(post_zero, "returned_sequence", _sequence((3, 0, -1, -2)))
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(post_zero, expected_decision=decision)


def test_reader_rejects_returned_rank_outside_consumed_prefix(
    tmp_path: Path,
) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    reader["cursor"] = 3
    reader["rows_consumed"] = 3
    reader["skipped_preassigned"] = 0
    reader.update(_byte_fields("consumed_state", _mask((0, 1, 2))))
    reader["once_return_sequence_count"] = 3
    _replace_bytes(reader, "once_return_sequence", _sequence((3, -1, -6)))
    reader.update(_byte_fields("returned_state", _mask((0, 1, 3))))
    reader["released_guided"] = 0
    reader["guided_release_sequence_count"] = 0
    _replace_bytes(reader, "guided_release_sequence", b"")
    reader.update(_byte_fields("released_state", _mask(())))
    reader["first_fallback_call"] = None
    reader["cb_decide_zero"] = 0
    reader["cb_decide_calls"] = 3
    reader["returned_sequence_count"] = 3
    _replace_bytes(reader, "returned_sequence", _sequence((3, -1, -6)))
    reader["bounded_guidance_state_bytes"] = 132
    reader["live_guidance_state_bytes"] = 112
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(reader, expected_decision=decision)


def test_reader_rejects_noncanonical_hex_and_release_outside_returned_subset(
    tmp_path: Path,
) -> None:
    *_, decision = _fixture_artifacts(tmp_path)
    noncanonical = _reader(decision)
    noncanonical["returned_sequence_hex"] = str(
        noncanonical["returned_sequence_hex"]
    ).upper()
    with pytest.raises(O1RelationalSearchError, match="returned sequence"):
        validate_vault_ranked_decision_reader(noncanonical, expected_decision=decision)

    outside = _reader(decision, released_literals=(-6,))
    with pytest.raises(O1RelationalSearchError, match="one-shot telemetry"):
        validate_vault_ranked_decision_reader(outside, expected_decision=decision)


def test_release_reader_is_checked_before_v13_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    *_, input_vault, decision = _fixture_artifacts(tmp_path)
    reader = _reader(decision)
    reader["consumed_state_sha256"] = "00" * 32
    called = False

    def forbidden(*_: object, **__: object) -> Any:
        nonlocal called
        called = True
        raise AssertionError("v13 projection must not run")

    monkeypatch.setattr(sieve_v14._v13, "_parse_native_payload", forbidden)
    with pytest.raises(O1RelationalSearchError, match="consumed state"):
        _parse(
            _payload(decision, reader=reader),
            input_vault=input_vault,
            decision=decision,
        )
    assert not called


def test_v11_payload_projects_inherited_fields_through_v13(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    *_, input_vault, decision = _fixture_artifacts(tmp_path)
    original = _payload(decision)
    seen: dict[str, object] = {}

    def fake_parent(payload: object, **_: object) -> Any:
        assert isinstance(payload, dict)
        seen.update(payload)
        return _parent_result(input_vault)

    monkeypatch.setattr(sieve_v14._v13, "_parse_native_payload", fake_parent)
    result = _parse(original, input_vault=input_vault, decision=decision)
    assert isinstance(result, JointScoreSieveV14Result)
    assert result.raw == original
    assert result.reader == _reader(decision)
    assert seen["schema"] == sieve_v14._v13.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert isinstance(seen["reader"], dict)
    assert seen["reader"]["schema"] == (
        sieve_v14._v13.VAULT_RANKED_DECISION_READER_SCHEMA
    )
    assert seen["reader"]["cb_decide_nonzero"] == 3
    assert set(seen) == sieve_v14._v13._TOP_LEVEL_FIELDS


def test_payload_rejects_base_outer_callback_disagreement(
    tmp_path: Path,
) -> None:
    *_, input_vault, decision = _fixture_artifacts(tmp_path)
    payload = _payload(decision)
    payload["sieve"] = {"cb_decide_calls": 4, "cb_decide_nonzero": 0}
    with pytest.raises(O1RelationalSearchError, match="base and outer"):
        _parse(payload, input_vault=input_vault, decision=decision)


def _mock_execution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    stdout: str,
    expected_rank: bytes,
    stderr: str = "release-reader-stderr",
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
        return sieve_v14._v13._v12._v11._v9._v8._v7._NativeExecution(
            subprocess.CompletedProcess(command, 0, stdout, stderr), samples
        )

    monkeypatch.setattr(
        sieve_v14._v13._v12._v11._v9._v8._v7,
        "_execute_native",
        fake_execute,
    )
    return command_seen, rank_paths, samples


def test_full_mock_reuses_private_rank_boundary_and_preserves_billing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf, potential, grouping, vault, input_vault, decision = _fixture_artifacts(
        tmp_path
    )
    executable = tmp_path / "synthetic-native-v11"
    executable.write_bytes(b"synthetic-native-v11")
    command, rank_paths, _ = _mock_execution(
        monkeypatch,
        stdout=json.dumps(_payload(decision)),
        expected_rank=decision.rank_table_bytes,
    )
    monkeypatch.setattr(
        sieve_v14,
        "derive_production_vault_ranked_decision",
        lambda *_: decision,
    )
    monkeypatch.setattr(
        sieve_v14._v13,
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
    executable = tmp_path / "synthetic-native-v11"
    executable.write_bytes(b"synthetic-native-v11")
    forged = _payload(decision)
    reader = copy.deepcopy(forged["reader"])
    assert isinstance(reader, dict)
    reader["release_policy_spec_sha256"] = "00" * 32
    forged["reader"] = reader
    stdout = json.dumps(forged)
    command, rank_paths, samples = _mock_execution(
        monkeypatch,
        stdout=stdout,
        expected_rank=decision.rank_table_bytes,
    )
    monkeypatch.setattr(
        sieve_v14,
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
    executable = tmp_path / "synthetic-native-v11"
    executable.write_bytes(b"synthetic-native-v11")

    def reject(*_: object, **__: object) -> Any:
        raise VaultRankedDecisionError("production rank differs")

    def forbidden(*_: object, **__: object) -> Any:
        raise AssertionError("native launch should not occur")

    monkeypatch.setattr(sieve_v14, "derive_production_vault_ranked_decision", reject)
    monkeypatch.setattr(
        sieve_v14._v13._v12._v11._v9._v8._v7,
        "_execute_native",
        forbidden,
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
        and NATIVE_V10_SOURCE.is_file()
        and NATIVE_V11_SOURCE.is_file()
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
def public_release_natives(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    if not _native_gate_available():
        pytest.skip("CaDiCaL development files or native v11 absent")
    build = tmp_path_factory.mktemp("joint-score-sieve-v14-public-release")
    control = build / "native-v10-control"
    release = build / "native-v11-release"
    _strict_compile_native(
        NATIVE_V10_SOURCE,
        control,
        macro="O1_CRYPTO_LAB_O1C71_PUBLIC_FIXTURE",
    )
    _strict_compile_native(
        NATIVE_V11_SOURCE,
        release,
        macro="O1_CRYPTO_LAB_O1C72_PUBLIC_FIXTURE",
    )
    return control, release


def _run_native(
    executable: Path,
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
    rank_table: Path,
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
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def _stable(payload: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop("resources")
    return result


def _i32_hex(encoded: object) -> tuple[int, ...]:
    assert isinstance(encoded, str)
    payload = bytes.fromhex(encoded)
    return struct.unpack(f"<{len(payload) // 4}i", payload) if payload else ()


def test_public_release_reader_is_one_shot_and_deterministic(
    tmp_path: Path,
    public_release_natives: tuple[Path, Path],
) -> None:
    control_native, release_native = public_release_natives
    cnf, potential, grouping, vault, _, decision = _fixture_artifacts(tmp_path)
    rank_table = tmp_path / "backtrack-release.rank-table"
    rank_table.write_bytes(decision.rank_table_bytes)

    control = _run_native(
        control_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )
    release = _run_native(
        release_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )
    repeat = _run_native(
        release_native,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        rank_table=rank_table,
    )

    assert _stable(release) == _stable(repeat)
    assert validate_vault_ranked_decision_reader(
        release["reader"], expected_decision=decision
    )
    assert release["reader"]["ranked_literals"] == [3, -1, -2, -6]
    control_nonzero = tuple(
        literal
        for literal in _i32_hex(control["reader"]["returned_sequence_hex"])
        if literal
    )
    assert control_nonzero[:4] == (
        3,
        -1,
        -2,
        -1,
    )
    assert _i32_hex(release["reader"]["once_return_sequence_hex"]) == (
        3,
        -1,
        -2,
    )
    assert release["reader"]["rows_consumed"] == 4
    assert release["reader"]["once_returns"] == 3
    assert release["reader"]["skipped_preassigned"] == 1
    assert release["reader"]["first_fallback_call"] == 4
    assert release["reader"]["redecisions"] == 0
    assert release["reader"]["solver_phase_calls"] == 0
    assert -2 in _i32_hex(release["reader"]["guided_release_sequence_hex"])
    callbacks = _i32_hex(release["reader"]["returned_sequence_hex"])
    assert callbacks[:3] == (3, -1, -2)
    assert callbacks[3:]
    assert set(callbacks[3:]) == {0}
    assert release["sieve"]["backtracks"] > 0
    assert release["sieve"]["cb_decide_calls"] == (release["reader"]["cb_decide_calls"])
    assert release["sieve"]["cb_decide_nonzero"] == 0


def test_native_rejects_tampered_rank_table(
    tmp_path: Path,
    public_release_natives: tuple[Path, Path],
) -> None:
    _, release_native = public_release_natives
    cnf, potential, grouping, vault, _, decision = _fixture_artifacts(tmp_path)
    tampered = bytearray(decision.rank_table_bytes)
    tampered[-1] ^= 1
    rank_table = tmp_path / "tampered.rank-table"
    rank_table.write_bytes(tampered)
    completed = subprocess.run(
        [
            str(release_native),
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
