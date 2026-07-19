from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v7 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_STATE_SCHEMA,
    write_joint_score_sieve_grouping,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.joint_score_sieve_v8 import (
    run_joint_score_sieve as run_joint_score_sieve_v8,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import O1C66_VAULT_CAPS

ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v6.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")
STRICT_FLAGS = ("-std=c++17", "-O3", "-DNDEBUG", "-Wall", "-Wextra", "-Werror")
VAULT_MAGIC = b"O1-NOGOOD-VAULT-V1\0"
RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
VAULT_SCHEMA = "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1"


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _compile(source: Path, output: Path) -> None:
    completed = subprocess.run(
        [
            "c++",
            *STRICT_FLAGS,
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
def native_executable(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _native_available():
        pytest.skip("CaDiCaL development files absent")
    output = tmp_path_factory.mktemp("o1c66-native") / "o1c66-native"
    _compile(NATIVE_SOURCE, output)
    return output


def _field(*, positive_score: bool = True) -> CriticalityPotentialField:
    first = (0.0, 10.0) if positive_score else (10.0, 0.0)
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), first),
            CriticalityPotentialFactor((2,), (0.0, 0.0)),
        ),
    )


def _write_inputs(
    tmp_path: Path, *, positive_unit: bool = False, positive_score: bool = True
) -> tuple[Path, Path, Path, CriticalityPotentialField]:
    cnf = tmp_path / "case.cnf"
    literal = 1 if positive_unit else -1
    cnf.write_text(f"p cnf 256 1\n{literal} 0\n", encoding="ascii")
    field = _field(positive_score=positive_score)
    potential = tmp_path / "case.potential"
    grouping = tmp_path / "case.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    return cnf, potential, grouping, field


def _vault_bytes(
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    field: CriticalityPotentialField,
    threshold: float,
    clauses: tuple[tuple[int, ...], ...] = (),
) -> bytes:
    observed = b"".join(
        struct.pack("<I", variable) for variable in field.observed_variables
    )
    payload = bytearray(VAULT_MAGIC)
    payload.extend(hashlib.sha256(cnf.read_bytes()).digest())
    payload.extend(hashlib.sha256(potential.read_bytes()).digest())
    payload.extend(hashlib.sha256(grouping.read_bytes()).digest())
    payload.extend(hashlib.sha256(observed).digest())
    payload.extend(hashlib.sha256(JOINT_SCORE_SIEVE_BOUND_RULE.encode()).digest())
    payload.extend(struct.pack("<dI", threshold, len(clauses)))
    for clause in clauses:
        payload.extend(struct.pack("<I", len(clause)))
        payload.extend(struct.pack(f"<{len(clause)}i", *clause))
    return bytes(payload)


def _run(
    executable: Path,
    *,
    cnf: Path,
    potential: Path,
    grouping: Path,
    vault: Path,
    threshold: float = 5.0,
    conflicts: int = 64,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
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
            repr(threshold),
            "--conflict-limit",
            str(conflicts),
            "--seed",
            "7",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_empty_vault_round_trip_emits_exact_safe_clause_and_preloads_it(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf, potential, grouping, field = _write_inputs(tmp_path)
    empty = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
    )
    vault = tmp_path / "empty.vault"
    vault.write_bytes(empty)
    first = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert first.returncode == 0, first.stderr
    payload = json.loads(first.stdout)
    assert payload["schema"] == RESULT_SCHEMA
    assert payload["implementation_parent_schema"].endswith("result-v5")
    telemetry = payload["vault"]
    assert telemetry["schema"] == VAULT_SCHEMA
    assert telemetry["input_sha256"] == hashlib.sha256(empty).hexdigest()
    assert telemetry["preloaded_clause_count"] == 0
    assert telemetry["fully_emitted_clause_count"] == 1
    assert telemetry["emitted_new_clause_count"] == 1
    assert telemetry["pending_clause_exported"] is False
    (emitted,) = telemetry["fully_emitted_clauses"]
    assert emitted["source"] == "trail_upper_bound"
    assert emitted["literals"] == [1]
    assert emitted["classification"] == "new"
    canonical = struct.pack("<Ii", 1, 1)
    assert emitted["clause_sha256"] == hashlib.sha256(canonical).hexdigest()

    cumulative = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
        clauses=((1,),),
    )
    assert telemetry["next_vault_available"] is True
    assert telemetry["next_vault_sha256"] == hashlib.sha256(cumulative).hexdigest()
    assert telemetry["next_serialized_bytes"] == len(cumulative)
    assert telemetry["next_clause_count"] == 1
    assert telemetry["next_literal_count"] == 1

    second_vault = tmp_path / "second.vault"
    second_vault.write_bytes(cumulative)
    second = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=second_vault,
    )
    assert second.returncode == 0, second.stderr
    second_payload = json.loads(second.stdout)
    assert second_payload["status"] == 20
    assert second_payload["vault"]["preloaded_clause_count"] == 1
    assert (
        second_payload["vault"]["next_vault_sha256"]
        == hashlib.sha256(cumulative).hexdigest()
    )

    augmented_cnf = tmp_path / "explicitly-augmented.cnf"
    augmented_cnf.write_text("p cnf 256 2\n-1 0\n1 0\n", encoding="ascii")
    augmented_vault = tmp_path / "augmented-empty.vault"
    augmented_vault.write_bytes(
        _vault_bytes(
            cnf=augmented_cnf,
            potential=potential,
            grouping=grouping,
            field=field,
            threshold=5.0,
        )
    )
    augmented = _run(
        native_executable,
        cnf=augmented_cnf,
        potential=potential,
        grouping=grouping,
        vault=augmented_vault,
    )
    assert augmented.returncode == 0, augmented.stderr
    augmented_payload = json.loads(augmented.stdout)
    assert second_payload["status"] == augmented_payload["status"] == 20
    assert second_payload["key_model_hex"] is None
    assert augmented_payload["key_model_hex"] is None
    for field_name in (
        "root_upper_bound",
        "group_maximum_evaluations",
        "group_row_evaluations",
        "bound_checks",
    ):
        assert (
            second_payload["sieve"][field_name]
            == augmented_payload["sieve"][field_name]
        )


def test_emitted_clause_preserves_opposite_polarity(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf, potential, grouping, field = _write_inputs(
        tmp_path, positive_unit=True, positive_score=False
    )
    vault = tmp_path / "empty.vault"
    vault.write_bytes(
        _vault_bytes(
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            field=field,
            threshold=5.0,
        )
    )
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 0, completed.stderr
    emitted = json.loads(completed.stdout)["vault"]["fully_emitted_clauses"]
    assert len(emitted) == 1
    assert emitted[0]["literals"] == [-1]


def test_real_native_result_passes_the_independent_v8_adapter(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf, potential, grouping, field = _write_inputs(tmp_path)
    empty = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
    )
    vault = tmp_path / "adapter-empty.vault"
    vault.write_bytes(empty)
    result = run_joint_score_sieve_v8(
        executable=native_executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=5.0,
        conflict_limit=64,
        seed=7,
        timeout_seconds=45.0,
        memory_limit_bytes=None,
    )
    assert result.status == 20
    assert len(result.eligible_emitted_clauses) == 1
    assert result.eligible_emitted_clauses[0].literals == (1,)
    assert result.next_vault is not None
    assert result.next_vault.clauses[0].literals == (1,)
    assert result.vault_telemetry["validated_input_clause_count"] == 0

    episode_two_vault = tmp_path / "adapter-episode-two.vault"
    episode_two_vault.write_bytes(result.next_vault.serialized)
    episode_two = run_joint_score_sieve_v8(
        executable=native_executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=episode_two_vault,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=5.0,
        conflict_limit=64,
        seed=7,
        timeout_seconds=45.0,
        memory_limit_bytes=None,
    )
    assert episode_two.status == 20
    assert episode_two.input_vault == result.next_vault
    assert episode_two.input_vault.clauses[0].literals == (1,)
    assert episode_two.vault_telemetry["validated_input_clause_count"] == 1
    assert episode_two.vault_telemetry["validated_input_literal_count"] == 1
    assert episode_two.sieve["external_clauses_emitted"] == 0
    state = episode_two.sieve["state"]
    assert isinstance(state, dict)
    assert state["schema"] == JOINT_SCORE_SIEVE_STATE_SCHEMA
    assert state["pending_clause_length"] == 1
    assert episode_two.sieve["external_clauses_queued"] == 1


def test_root_empty_clause_is_typed_terminal_and_never_archived(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf, potential, grouping, field = _write_inputs(tmp_path)
    vault = tmp_path / "root-terminal-empty.vault"
    vault.write_bytes(
        _vault_bytes(
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            field=field,
            threshold=11.0,
        )
    )
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=11.0,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == 20
    telemetry = payload["vault"]
    (emitted,) = telemetry["fully_emitted_clauses"]
    assert emitted["literals"] == []
    assert emitted["classification"] == "terminal_empty"
    assert telemetry["terminal_empty_clause_count"] == 1
    assert telemetry["emitted_new_clause_count"] == 0
    assert telemetry["next_vault_available"] is False
    assert telemetry["next_vault_terminal_reason"] == "terminal_empty_clause"
    assert telemetry["next_vault_sha256"] is None


@pytest.mark.parametrize(
    "mutation",
    (
        "magic",
        "cnf_identity",
        "potential_identity",
        "grouping_identity",
        "observed_identity",
        "bound_rule_identity",
        "threshold_identity",
        "trailing",
        "empty_clause",
        "zero_literal",
        "int_min_literal",
        "non_observed_literal",
        "out_of_range_literal",
        "out_of_order",
        "tautology",
        "duplicate_clause",
        "uncertified_clause",
        "clause_cap",
        "literal_cap",
    ),
)
def test_vault_tampering_and_noncanonical_clauses_fail_closed(
    tmp_path: Path, native_executable: Path, mutation: str
) -> None:
    case = tmp_path / mutation
    case.mkdir()
    cnf, potential, grouping, field = _write_inputs(case)
    base = bytearray(
        _vault_bytes(
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            field=field,
            threshold=5.0,
        )
    )
    if mutation == "magic":
        base[0] ^= 1
    elif mutation == "cnf_identity":
        base[len(VAULT_MAGIC)] ^= 1
    elif mutation == "potential_identity":
        base[len(VAULT_MAGIC) + 32] ^= 1
    elif mutation == "grouping_identity":
        base[len(VAULT_MAGIC) + 64] ^= 1
    elif mutation == "observed_identity":
        base[len(VAULT_MAGIC) + 96] ^= 1
    elif mutation == "bound_rule_identity":
        base[len(VAULT_MAGIC) + 128] ^= 1
    elif mutation == "threshold_identity":
        base[19 + 5 * 32] ^= 1
    elif mutation == "trailing":
        base += b"x"
    elif mutation == "clause_cap":
        struct.pack_into("<I", base, 19 + 5 * 32 + 8, 513)
    elif mutation == "literal_cap":
        struct.pack_into("<I", base, 19 + 5 * 32 + 8, 1)
        base += struct.pack("<I", 1_600_001)
    else:
        clauses: tuple[tuple[int, ...], ...]
        clauses = {
            "empty_clause": ((),),
            "zero_literal": ((0,),),
            "int_min_literal": ((-(2**31),),),
            "non_observed_literal": ((3,),),
            "out_of_range_literal": ((1_000_001,),),
            "out_of_order": ((2, 1),),
            "tautology": ((1, -1),),
            "duplicate_clause": ((1,), (1,)),
            "uncertified_clause": ((2,),),
        }[mutation]
        base = bytearray(
            _vault_bytes(
                cnf=cnf,
                potential=potential,
                grouping=grouping,
                field=field,
                threshold=5.0,
                clauses=clauses,
            )
        )
    vault = case / "tampered.vault"
    vault.write_bytes(base)
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 1
    assert "score-threshold vault" in completed.stderr
    assert not completed.stdout


def test_complete_model_cut_exports_exact_score_source_and_reimports(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf = tmp_path / "complete.cnf"
    cnf.write_text("p cnf 256 2\n1 0\n2 0\n", encoding="ascii")
    tiny = 2.0**-53
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="43" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (1.0, 1.0)),
            CriticalityPotentialFactor((1, 2), (tiny, tiny, tiny, tiny)),
        ),
    )
    potential = tmp_path / "complete.potential"
    grouping = tmp_path / "complete.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    threshold = struct.unpack("<d", struct.pack("<Q", 0x3FF0000000000001))[0]
    empty = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=threshold,
    )
    vault = tmp_path / "complete-empty.vault"
    vault.write_bytes(empty)
    first = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
        threshold=threshold,
    )
    assert first.returncode == 0, first.stderr
    first_payload = json.loads(first.stdout)
    (emitted,) = first_payload["vault"]["fully_emitted_clauses"]
    assert emitted["source"] == "complete_model_score"
    assert emitted["witness_score_f64le_hex"] == struct.pack("<d", 1.0).hex()
    assert emitted["literals"] == [-1, -2]

    cumulative = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=threshold,
        clauses=((-1, -2),),
    )
    assert (
        first_payload["vault"]["next_vault_sha256"]
        == hashlib.sha256(cumulative).hexdigest()
    )
    next_path = tmp_path / "complete-next.vault"
    next_path.write_bytes(cumulative)
    second = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=next_path,
        threshold=threshold,
    )
    assert second.returncode == 0, second.stderr
    certified = json.loads(second.stdout)["vault"]
    assert certified["validated_input_clause_count"] == 1
    assert certified["validated_input_literal_count"] == 2


@pytest.mark.parametrize("clause", ((2,), (1, 2)))
def test_import_certification_rejects_partial_and_complete_threshold_equality(
    tmp_path: Path, native_executable: Path, clause: tuple[int, ...]
) -> None:
    cnf = tmp_path / "strict-equality.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="47" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (5.0, 5.0)),
            CriticalityPotentialFactor((2,), (0.0, 0.0)),
        ),
    )
    potential = tmp_path / "strict-equality.potential"
    grouping = tmp_path / "strict-equality.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    vault = tmp_path / f"strict-equality-{len(clause)}.vault"
    vault.write_bytes(
        _vault_bytes(
            cnf=cnf,
            potential=potential,
            grouping=grouping,
            field=field,
            threshold=5.0,
            clauses=(clause,),
        )
    )
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 1
    assert "clause certification differs" in completed.stderr
    assert not completed.stdout


def test_archive_capacity_crossing_is_typed_not_a_callback_failure(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf = tmp_path / "capacity.cnf"
    cnf.write_text("p cnf 256 1\n-1 0\n", encoding="ascii")
    energies = [0.0] * 64
    energies[-1] = 10.0
    factors = [CriticalityPotentialFactor(tuple(range(1, 7)), tuple(energies))]
    factors.extend(
        CriticalityPotentialFactor((variable,), (0.0, 0.0)) for variable in range(7, 13)
    )
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="44" * 32,
        factors=tuple(factors),
    )
    potential = tmp_path / "capacity.potential"
    grouping = tmp_path / "capacity.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)

    clauses: list[tuple[int, ...]] = []
    for code in range(1, 513):
        literals = [1, 2]
        value = code
        for variable in range(3, 13):
            trit = value % 3
            value //= 3
            if trit == 1:
                literals.append(variable)
            elif trit == 2:
                literals.append(-variable)
        clauses.append(tuple(literals))
    assert len(set(clauses)) == 512 and (1,) not in clauses
    archive = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
        clauses=tuple(clauses),
    )
    vault = tmp_path / "capacity.vault"
    vault.write_bytes(archive)
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    telemetry = payload["vault"]
    assert payload["status"] == 20
    assert telemetry["validated_input_clause_count"] == 512
    assert telemetry["fully_emitted_clause_count"] == 1
    assert telemetry["emitted_new_clause_count"] == 1
    assert telemetry["next_vault_available"] is False
    assert telemetry["next_vault_terminal_reason"] == "capacity_clause_count"
    assert telemetry["next_vault_sha256"] is None
    assert telemetry["next_serialized_bytes"] is None
    assert telemetry["next_clause_count"] is None
    assert telemetry["next_literal_count"] is None


def test_cumulative_vault_preserves_input_then_first_emission_order(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf = tmp_path / "ordered.cnf"
    cnf.write_text("p cnf 256 2\n1 0\n-2 0\n", encoding="ascii")
    energies = [0.0, 0.0, 0.0, 10.0]
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="45" * 32,
        factors=(CriticalityPotentialFactor((1, 2), tuple(energies)),),
    )
    potential = tmp_path / "ordered.potential"
    grouping = tmp_path / "ordered.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    input_bytes = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
        clauses=((1,),),
    )
    vault = tmp_path / "ordered-input.vault"
    vault.write_bytes(input_bytes)
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 0, completed.stderr
    telemetry = json.loads(completed.stdout)["vault"]
    assert telemetry["fully_emitted_clauses"][0]["literals"] == [-1, 2]
    expected = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
        clauses=((1,), (-1, 2)),
    )
    assert telemetry["next_vault_sha256"] == hashlib.sha256(expected).hexdigest()
    assert telemetry["next_clause_count"] == 2
    assert telemetry["next_literal_count"] == 3


def test_first_capacity_crossing_terminates_before_any_later_clause(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf = tmp_path / "capacity-terminator.cnf"
    cnf.write_text("p cnf 256 0\n", encoding="ascii")
    factors = [CriticalityPotentialFactor((1, 2), (10.0, 0.0, 0.0, 0.0))]
    factors.extend(
        CriticalityPotentialFactor((variable,), (0.0, 0.0)) for variable in range(3, 13)
    )
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="46" * 32,
        factors=tuple(factors),
    )
    potential = tmp_path / "capacity-terminator.potential"
    grouping = tmp_path / "capacity-terminator.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    clauses: list[tuple[int, ...]] = []
    for code in range(1, 513):
        literals = [-1, 3]
        value = code
        for variable in range(4, 13):
            trit = value % 3
            value //= 3
            if trit == 1:
                literals.append(variable)
            elif trit == 2:
                literals.append(-variable)
        clauses.append(tuple(literals))
    assert len(set(clauses)) == 512 and (-1,) not in clauses
    archive = _vault_bytes(
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        field=field,
        threshold=5.0,
        clauses=tuple(clauses),
    )
    vault = tmp_path / "capacity-terminator.vault"
    vault.write_bytes(archive)
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    telemetry = payload["vault"]
    assert payload["status"] == 0
    assert payload["post_solve_state_name"] == "INCONCLUSIVE"
    assert telemetry["validated_input_clause_count"] == 512
    assert telemetry["fully_emitted_clause_count"] == 1
    assert telemetry["emitted_new_clause_count"] == 1
    assert telemetry["next_vault_available"] is False
    assert telemetry["next_vault_terminal_reason"] == "capacity_clause_count"
    assert payload["sieve"]["pending_clause_count"] == 0


def test_payload_cap_is_checked_before_vault_body_allocation(
    tmp_path: Path, native_executable: Path
) -> None:
    cnf, potential, grouping, _ = _write_inputs(tmp_path)
    vault = tmp_path / "oversized.vault"
    with vault.open("wb") as output:
        output.seek(8_388_608)
        output.write(b"x")
    completed = _run(
        native_executable,
        cnf=cnf,
        potential=potential,
        grouping=grouping,
        vault=vault,
    )
    assert completed.returncode == 1
    assert "payload exceeds hard cap" in completed.stderr


@pytest.mark.skipif(not _native_available(), reason="CaDiCaL development files absent")
def test_partial_callback_is_never_exported_before_terminating_zero(
    tmp_path: Path,
) -> None:
    harness = tmp_path / "emission_boundary.cpp"
    executable = tmp_path / "emission_boundary"
    harness.write_text(
        f'''#define O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN
#include "{NATIVE_SOURCE.as_posix()}"
#undef O1_CRYPTO_LAB_JOINT_SCORE_SIEVE_V6_NO_MAIN

std::string raw_digest(const std::string &hex) {{
  std::string result;
  result.reserve(32U);
  for (size_t index = 0; index < hex.size(); index += 2U) {{
    const auto nibble = [](char value) -> unsigned {{
      return value <= '9' ? static_cast<unsigned>(value - '0')
                          : static_cast<unsigned>(value - 'a' + 10);
    }};
    result.push_back(static_cast<char>((nibble(hex[index]) << 4U) |
                                       nibble(hex[index + 1U])));
  }}
  return result;
}}

void append_u16_test(std::string &output, uint16_t value) {{
  output.push_back(static_cast<char>(value));
  output.push_back(static_cast<char>(value >> 8U));
}}

int main() {{
  PotentialField field;
  field.offset = 0.0;
  field.source_sha256 = std::string(64U, '4');
  PotentialFactor factor;
  factor.variables = {{1}};
  factor.energies = {{0.0, 10.0}};
  field.factors.push_back(std::move(factor));

  const std::string potential_sha(64U, '4');
  const std::string cnf_sha(64U, '5');
  std::string grouping(kGroupingMagic);
  grouping += raw_digest(potential_sha);
  append_u16_test(grouping, 6U);
  append_u32_le(grouping, 1U);
  append_u32_le(grouping, 1U);
  append_u32_le(grouping, 1U);
  append_u32_le(grouping, 0U);
  append_u16_test(grouping, 1U);
  append_u32_le(grouping, 1U);
  std::string observed;
  append_u32_le(observed, 1U);
  const double threshold = 5.0;
  std::string vault(kVaultMagic);
  vault += raw_digest(cnf_sha);
  vault += raw_digest(potential_sha);
  vault += raw_digest(sha256(grouping));
  vault += raw_digest(sha256(observed));
  vault += raw_digest(sha256(kGroupedBoundRule));
  append_u64_le(vault, f64_bits(threshold));
  append_u32_le(vault, 0U);

  GroupedJointScoreSieveV6 sieve(std::move(field), grouping, vault, cnf_sha,
                                 potential_sha, threshold);
  sieve.notify_new_decision_level();
  sieve.notify_assignment({{-1}});
  std::ostringstream queued;
  sieve.write_vault_json(queued);
  if (queued.str().find("\\\"fully_emitted_clause_count\\\":0") ==
      std::string::npos)
    return 10;
  const std::string pending_before_backtrack = sieve.pending_state();
  sieve.notify_backtrack(0U);
  if (sieve.pending_state() != pending_before_backtrack ||
      sieve.assignment_state() != std::string(1U, '\\0'))
    return 11;
  bool forgettable = true;
  if (!sieve.cb_has_external_clause(forgettable) || forgettable)
    return 12;
  if (sieve.cb_add_external_clause_lit() != 1)
    return 13;
  std::ostringstream partial;
  sieve.write_vault_json(partial);
  if (partial.str().find("\\\"fully_emitted_clause_count\\\":0") ==
      std::string::npos)
    return 14;
  if (sieve.cb_add_external_clause_lit() != 0)
    return 15;
  std::ostringstream complete;
  sieve.write_vault_json(complete);
  if (complete.str().find("\\\"fully_emitted_clause_count\\\":1") ==
          std::string::npos ||
      complete.str().find("\\\"classification\\\":\\\"new\\\"") ==
          std::string::npos)
    return 16;
  return 0;
}}
''',
        encoding="utf-8",
    )
    _compile(harness, executable)
    completed = subprocess.run(
        [str(executable)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
