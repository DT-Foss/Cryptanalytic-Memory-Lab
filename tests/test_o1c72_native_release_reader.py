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
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v11.cpp"
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
RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v11"
IMPLEMENTATION_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
READER_SCHEMA = (
    "o1-256-cadical-vault-backtrack-release-ranked-decision-reader-v1"
)
RANK_SPEC_SHA256 = (
    "974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543"
)
RELEASE_POLICY_SPEC_SHA256 = (
    "bfa752664e19d5899d114ee8cf75dd15a52a8306ff2399fde046a5bb6ebdc132"
)
THRESHOLD = 50.0


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and NATIVE_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _compile(source: Path, output: Path, *, fixture: bool) -> None:
    command = ["c++", *STRICT_NATIVE_FLAGS]
    if fixture:
        command.append("-DO1_CRYPTO_LAB_O1C72_PUBLIC_FIXTURE")
    command.extend(
        [
            f"-I{CADICAL_INCLUDE}",
            str(source),
            str(CADICAL_LIBRARY),
            "-o",
            str(output),
        ]
    )
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


@pytest.fixture(scope="module")
def native_binaries(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    if not _native_available():
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    build = tmp_path_factory.mktemp("o1c72-native-release-reader")
    fixture = build / "cadical-o1c72-public-fixture"
    production = build / "cadical-o1c72-production"
    _compile(NATIVE_SOURCE, fixture, fixture=True)
    _compile(NATIVE_SOURCE, production, fixture=False)
    return fixture, production


@dataclass(frozen=True)
class ReleaseFixture:
    cnf: Path
    potential: Path
    grouping: Path
    vault: Path
    rank_table: Path


def _write_release_fixture(tmp_path: Path) -> ReleaseFixture:
    # The four-clause gadget makes the -2 decision subtree inconsistent.  The
    # unit +6 makes the final ranked row -6 preassigned, so the same run proves
    # both permanent release and assigned-before-opportunity retirement.
    cnf = tmp_path / "release.cnf"
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
    potential = tmp_path / "release.potential"
    grouping = tmp_path / "release.grouping"
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
    vault_value = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
            ThresholdNoGoodClause((-1, 3, -6)),
        ),
    )
    vault = tmp_path / "release.vault"
    write_threshold_no_good_vault(vault, vault_value, caps=O1C66_VAULT_CAPS)

    # Deltas are exact vault occurrence counts: +3, -2, -1, -1.  Singleton
    # gaps break the final magnitude tie in variable-2/variable-6 order.
    rows = (
        (3, 3, 111.0, 11.0, 100.0),
        (1, -2, 111.0, 111.0, 0.0),
        (2, -1, 111.0, 101.0, 10.0),
        (6, -1, 110.0, 111.0, 1.0),
    )
    rank_table = tmp_path / "release.rank-table"
    rank_table.write_bytes(
        b"".join(struct.pack("<Iqddd", *row) for row in rows)
    )
    return ReleaseFixture(cnf, potential, grouping, vault, rank_table)


def _command(executable: Path, fixture: ReleaseFixture, rank_table: Path) -> list[str]:
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
        str(rank_table),
        "--threshold",
        str(THRESHOLD),
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _run(
    executable: Path, fixture: ReleaseFixture, rank_table: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(executable, fixture, rank_table or fixture.rank_table),
        capture_output=True,
        text=True,
        check=False,
    )


def _i32_sequence(hex_value: object) -> tuple[int, ...]:
    assert isinstance(hex_value, str)
    payload = bytes.fromhex(hex_value)
    assert len(payload) % 4 == 0
    return tuple(row[0] for row in struct.iter_unpack("<i", payload))


def _bits(hex_value: object) -> tuple[int, ...]:
    assert isinstance(hex_value, str)
    payload = bytes.fromhex(hex_value)
    assert len(payload) == 32
    return tuple(
        index
        for index in range(256)
        if payload[index // 8] & (1 << (index % 8))
    )


def test_public_backtrack_release_is_once_only_and_bounded(
    native_binaries: tuple[Path, Path], tmp_path: Path
) -> None:
    fixture_binary, _ = native_binaries
    fixture = _write_release_fixture(tmp_path)
    completed = _run(fixture_binary, fixture)
    assert completed.returncode == 0, completed.stderr
    payload: dict[str, Any] = json.loads(completed.stdout)
    reader = payload["reader"]
    sieve = payload["sieve"]

    assert payload["schema"] == RESULT_SCHEMA
    assert payload["implementation_parent_schema"] == IMPLEMENTATION_PARENT_SCHEMA
    assert payload["status"] == 10
    assert reader["schema"] == READER_SCHEMA
    assert reader["reader_spec_sha256"] == RANK_SPEC_SHA256
    assert reader["release_policy_spec_bytes"] == 540
    assert reader["release_policy_spec_sha256"] == RELEASE_POLICY_SPEC_SHA256
    assert reader["ranked_literals"] == [3, -1, -2, -6]
    assert reader["cursor"] == reader["rows_consumed"] == 4
    assert reader["once_returns"] == reader["cb_decide_nonzero"] == 3
    assert reader["skipped_preassigned"] == 1
    assert reader["rows_consumed"] == (
        reader["once_returns"] + reader["skipped_preassigned"]
    )
    assert reader["unique_returned_variables"] == 3
    assert reader["redecisions"] == 0
    assert reader["solver_phase_calls"] == 0
    assert reader["first_fallback_call"] == 4
    assert _i32_sequence(reader["once_return_sequence_hex"]) == (3, -1, -2)
    callback_returns = _i32_sequence(reader["returned_sequence_hex"])
    assert callback_returns[:3] == (3, -1, -2)
    assert callback_returns[3:]
    assert set(callback_returns[3:]) == {0}
    assert reader["returned_sequence_count"] == len(callback_returns)
    assert reader["cb_decide_calls"] == len(callback_returns)
    assert sieve["cb_decide_calls"] == reader["cb_decide_calls"]
    assert sieve["backtracks"] > 0
    assert sieve["backtracked_assignments"] > 0

    consumed = _bits(reader["consumed_state_hex"])
    returned = _bits(reader["returned_state_hex"])
    released = _bits(reader["released_state_hex"])
    assert consumed == (0, 1, 2, 3)
    assert returned == (0, 1, 2)
    assert set(released) <= set(returned)
    releases = _i32_sequence(reader["guided_release_sequence_hex"])
    assert len(releases) == reader["released_guided"]
    assert len(set(map(abs, releases))) == len(releases)
    assert set(releases) <= {3, -1, -2}
    assert -2 in releases
    assert reader["bounded_guidance_state_bytes"] == 132
    assert reader["live_guidance_state_bytes"] <= 132


@pytest.mark.parametrize("tamper", ["gap", "order"])
def test_public_reader_rejects_structural_rank_tampering(
    native_binaries: tuple[Path, Path], tmp_path: Path, tamper: str
) -> None:
    fixture_binary, _ = native_binaries
    fixture = _write_release_fixture(tmp_path)
    payload = bytearray(fixture.rank_table.read_bytes())
    if tamper == "gap":
        struct.pack_into("<d", payload, 3 * 36 + 28, 2.0)
    else:
        third = bytes(payload[2 * 36 : 3 * 36])
        fourth = bytes(payload[3 * 36 : 4 * 36])
        payload[2 * 36 : 3 * 36] = fourth
        payload[3 * 36 : 4 * 36] = third
    rank_table = tmp_path / f"tampered-{tamper}.rank-table"
    rank_table.write_bytes(payload)
    completed = _run(fixture_binary, fixture, rank_table)
    assert completed.returncode == 1
    assert "rank-table" in completed.stderr


def test_production_binary_rejects_unsealed_public_fixture(
    native_binaries: tuple[Path, Path], tmp_path: Path
) -> None:
    _, production_binary = native_binaries
    fixture = _write_release_fixture(tmp_path)
    completed = _run(production_binary, fixture)
    assert completed.returncode == 1
    assert "rank vote-field source vault differs" in completed.stderr
