from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any

import pytest

from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v12 import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    write_joint_score_sieve_grouping,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
    write_threshold_no_good_vault,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v12.cpp"
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
RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v12"
IMPLEMENTATION_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
RELEASE_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v11"
READER_SCHEMA = (
    "o1-256-cadical-vault-release-contrast-ranked-decision-reader-v1"
)
RANK_SPEC_SHA256 = (
    "974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543"
)
CONTRAST_POLICY_SHA256 = (
    "96e040917b6566671683598a09c6d03f6ebec3809c6c63354f09ffca93c246b5"
)
THRESHOLD = 50.0


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and NATIVE_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _compile(output: Path, *, fixture: bool) -> None:
    command = ["c++", *STRICT_NATIVE_FLAGS]
    if fixture:
        command.append("-DO1_CRYPTO_LAB_O1C73_PUBLIC_FIXTURE")
    command.extend(
        [
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(output),
        ]
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stderr


@pytest.fixture(scope="module")
def native_binaries(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[tuple[Path, Path], Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    first = tmp_path_factory.mktemp("o1c73-native-contrast-first")
    second = tmp_path_factory.mktemp("o1c73-native-contrast-second")
    fixture_a = first / "cadical-o1c73-public-fixture"
    fixture_b = second / "cadical-o1c73-public-fixture"
    production = first / "cadical-o1c73-production"
    _compile(fixture_a, fixture=True)
    _compile(fixture_b, fixture=True)
    _compile(production, fixture=False)
    return (fixture_a, fixture_b), production


@dataclass(frozen=True)
class ContrastFixture:
    cnf: Path
    potential: Path
    grouping: Path
    vault: Path
    rank_table: Path


def _write_fixture(tmp_path: Path) -> ContrastFixture:
    cnf = tmp_path / "release-contrast.cnf"
    cnf.write_text(
        "p cnf 256 5\n"
        "2 4 5 0\n"
        "2 4 -5 0\n"
        "2 -4 5 0\n"
        "2 -4 -5 0\n"
        "6 0\n",
        encoding="ascii",
    )
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="73" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 0.0)),
            CriticalityPotentialFactor((2,), (0.0, 10.0)),
            CriticalityPotentialFactor((3,), (0.0, 100.0)),
            CriticalityPotentialFactor((6,), (1.0, 0.0)),
        ),
    )
    potential = tmp_path / "release-contrast.potential"
    grouping = tmp_path / "release-contrast.grouping"
    write_joint_score_sieve_potential(potential, field)
    write_joint_score_sieve_grouping(grouping, field)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=THRESHOLD,
    )
    vault = tmp_path / "release-contrast.vault"
    write_threshold_no_good_vault(
        vault,
        ThresholdNoGoodVault(
            identity,
            field.observed_variables,
            (
                ThresholdNoGoodClause((-1, 3)),
                ThresholdNoGoodClause((-2, 3)),
                ThresholdNoGoodClause((-1, 3, -6)),
            ),
        ),
        caps=O1C66_VAULT_CAPS,
    )
    rows = (
        (3, 3, 111.0, 11.0, 100.0),
        (1, -2, 111.0, 111.0, 0.0),
        (2, -1, 111.0, 101.0, 10.0),
        (6, -1, 110.0, 111.0, 1.0),
    )
    rank_table = tmp_path / "release-contrast.rank-table"
    rank_table.write_bytes(b"".join(struct.pack("<Iqddd", *row) for row in rows))
    return ContrastFixture(cnf, potential, grouping, vault, rank_table)


def _command(executable: Path, fixture: ContrastFixture) -> list[str]:
    return [
        str(executable),
        "--cnf",
        str(fixture.cnf),
        "--potential",
        str(fixture.potential),
        "--grouping",
        str(fixture.grouping),
        "--vault-in",
        str(fixture.vault),
        "--rank-table",
        str(fixture.rank_table),
        "--threshold",
        str(THRESHOLD),
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _run(executable: Path, fixture: ContrastFixture) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(executable, fixture), capture_output=True, text=True, check=False
    )


def _i32(hex_value: object) -> tuple[int, ...]:
    assert isinstance(hex_value, str)
    payload = bytes.fromhex(hex_value)
    return tuple(row[0] for row in struct.iter_unpack("<i", payload))


def _bits(hex_value: object) -> set[int]:
    assert isinstance(hex_value, str)
    payload = bytes.fromhex(hex_value)
    assert len(payload) == 32
    return {
        index
        for index in range(256)
        if payload[index // 8] & (1 << (index % 8))
    }


def _stable(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        {key: value for key, value in payload.items() if key != "resources"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_public_opposite_release_is_paired_bounded_and_repeatable(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    fixture_binaries, _ = native_binaries
    fixture = _write_fixture(tmp_path)
    payloads: list[dict[str, Any]] = []
    for executable in fixture_binaries:
        for _ in range(3):
            completed = _run(executable, fixture)
            assert completed.returncode == 0, completed.stderr
            payloads.append(json.loads(completed.stdout))
    stable = [_stable(payload) for payload in payloads]
    assert len(set(stable)) == 1

    payload = payloads[0]
    reader = payload["reader"]
    assert payload["schema"] == RESULT_SCHEMA
    assert payload["implementation_parent_schema"] == IMPLEMENTATION_PARENT_SCHEMA
    assert payload["implementation_release_parent_schema"] == RELEASE_PARENT_SCHEMA
    assert payload["status"] == 10
    assert reader["schema"] == READER_SCHEMA
    assert reader["reader_spec_sha256"] == RANK_SPEC_SHA256
    assert reader["contrast_policy_spec_bytes"] == 674
    assert reader["contrast_policy_spec_sha256"] == CONTRAST_POLICY_SHA256
    assert reader["ranked_literals"] == [3, -1, -2, -6]
    assert reader["cursor"] == reader["rows_consumed"] == 4
    assert reader["original_once_returns"] == 3
    assert reader["skipped_preassigned"] == 1
    assert _i32(reader["original_return_sequence_hex"]) == (3, -1, -2)
    assert _i32(reader["original_release_sequence_hex"]) == (-2, 3, -1)
    assert _i32(reader["contrast_return_sequence_hex"]) == (1,)
    assert reader["released_original"] == reader["contrast_enqueued"] == 3
    assert reader["contrast_returns"] == reader["paired_variables"] == 1
    assert reader["variable_second_decisions"] == 1
    assert reader["same_signed_redecisions"] == 0
    assert reader["solver_phase_calls"] == 0
    assert reader["cb_decide_nonzero"] == 4
    assert reader["cb_decide_calls"] == (
        reader["cb_decide_nonzero"] + reader["cb_decide_zero"]
    )
    assert reader["first_parent_fallback_call"] == 4
    assert reader["maximum_queue_size"] == 3
    assert reader["queue_size"] == 2
    assert reader["contrast_deferred_assigned"] == 2
    assert reader["bounded_guidance_state_bytes"] == 706
    assert reader["live_guidance_state_bytes"] <= 706
    assert reader["bounded_telemetry_state_bytes"] == 33_490

    assert _bits(reader["consumed_state_hex"]) == {0, 1, 2, 3}
    original = _bits(reader["original_returned_state_hex"])
    released = _bits(reader["original_released_state_hex"])
    enqueued = _bits(reader["contrast_enqueued_state_hex"])
    contrasted = _bits(reader["contrast_returned_state_hex"])
    deferred = _bits(reader["contrast_deferred_assigned_state_hex"])
    assert original == {0, 1, 2}
    assert released == enqueued == {0, 1, 2}
    assert contrasted == {1}
    assert deferred == {0, 2}

    events = reader["nonzero_return_events"]
    assert [(row["call"], row["kind"], row["literal"]) for row in events] == [
        (1, "original", 3),
        (2, "original", -1),
        (3, "original", -2),
        (255, "contrast", 1),
    ]
    event_by_call = {row["call"]: row["literal"] for row in events}
    callback_bytes = b"".join(
        struct.pack("<i", event_by_call.get(call, 0))
        for call in range(1, reader["cb_decide_calls"] + 1)
    )
    assert hashlib.sha256(callback_bytes).hexdigest() == reader[
        "returned_sequence_sha256"
    ]
    pair = next(row for row in reader["pair_records"] if row["rank_index"] == 1)
    assert pair["original_literal"] == -1
    assert pair["contrast_literal"] == 1
    assert pair["contrast_return_call"] == 255
    assert payload["sieve"]["cb_decide_calls"] == reader["cb_decide_calls"]
    assert payload["sieve"]["backtracks"] > 0


def test_production_binary_rejects_public_fixture(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    _, production = native_binaries
    fixture = _write_fixture(tmp_path)
    completed = _run(production, fixture)
    assert completed.returncode == 1
    assert "rank vote-field source vault differs" in completed.stderr
