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
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v13.cpp"
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
RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v13"
IMPLEMENTATION_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
RELEASE_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v12"
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
        command.append("-DO1_CRYPTO_LAB_O1C74_PUBLIC_FIXTURE")
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
    first = tmp_path_factory.mktemp("o1c74-native-split-first")
    second = tmp_path_factory.mktemp("o1c74-native-split-second")
    fixture_a = first / "cadical-o1c74-public-fixture"
    fixture_b = second / "cadical-o1c74-public-fixture"
    production = first / "cadical-o1c74-production"
    _compile(fixture_a, fixture=True)
    _compile(fixture_b, fixture=True)
    _compile(production, fixture=False)
    return (fixture_a, fixture_b), production


@dataclass(frozen=True)
class SplitFixture:
    cnf: Path
    potential: Path
    grouping: Path
    rank_vault: Path
    active_empty: Path
    active_one: Path
    rank_table: Path


def _write_fixture(tmp_path: Path) -> SplitFixture:
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
        source_sha256="74" * 32,
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
    clauses = (
        ThresholdNoGoodClause((-1, 3)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-1, 3, -6)),
    )
    rank_vault = tmp_path / "rank-source.vault"
    active_empty = tmp_path / "active-empty.vault"
    active_one = tmp_path / "active-one.vault"
    write_threshold_no_good_vault(
        rank_vault,
        ThresholdNoGoodVault(identity, field.observed_variables, clauses),
        caps=O1C66_VAULT_CAPS,
    )
    write_threshold_no_good_vault(
        active_empty,
        ThresholdNoGoodVault(identity, field.observed_variables, ()),
        caps=O1C66_VAULT_CAPS,
    )
    write_threshold_no_good_vault(
        active_one,
        ThresholdNoGoodVault(identity, field.observed_variables, clauses[:1]),
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
    return SplitFixture(
        cnf,
        potential,
        grouping,
        rank_vault,
        active_empty,
        active_one,
        rank_table,
    )


def _command(
    executable: Path,
    fixture: SplitFixture,
    *,
    rank_vault: Path | None = None,
    active_vault: Path | None = None,
) -> list[str]:
    return [
        str(executable),
        "--cnf",
        str(fixture.cnf),
        "--potential",
        str(fixture.potential),
        "--grouping",
        str(fixture.grouping),
        "--rank-vault",
        str(rank_vault or fixture.rank_vault),
        "--vault-in",
        str(active_vault or fixture.active_empty),
        "--rank-table",
        str(fixture.rank_table),
        "--threshold",
        str(THRESHOLD),
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _run(
    executable: Path,
    fixture: SplitFixture,
    *,
    rank_vault: Path | None = None,
    active_vault: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _command(
            executable,
            fixture,
            rank_vault=rank_vault,
            active_vault=active_vault,
        ),
        capture_output=True,
        text=True,
        check=False,
    )


def _stable(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        {key: value for key, value in payload.items() if key != "resources"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_v13_help_and_rank_vault_argument_are_strict(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    fixture_binary = native_binaries[0][0]
    help_result = subprocess.run(
        [str(fixture_binary), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "--rank-vault PATH" in help_result.stdout

    fixture = _write_fixture(tmp_path)
    command = _command(fixture_binary, fixture)
    rank_index = command.index("--rank-vault")
    missing = subprocess.run(
        command[:rank_index] + command[rank_index + 2 :],
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode == 1
    assert "rank-vault argument is missing" in missing.stderr

    duplicate = subprocess.run(
        command + ["--rank-vault", str(fixture.rank_vault)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert duplicate.returncode == 1
    assert "rank-vault argument differs" in duplicate.stderr


def test_active_projection_changes_preload_but_not_rank_source(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    fixture_binaries, _ = native_binaries
    fixture = _write_fixture(tmp_path)
    by_active: list[list[dict[str, Any]]] = []
    for active in (fixture.active_empty, fixture.active_one):
        payloads: list[dict[str, Any]] = []
        for executable in fixture_binaries:
            completed = _run(executable, fixture, active_vault=active)
            assert completed.returncode == 0, completed.stderr
            payloads.append(json.loads(completed.stdout))
        assert len({_stable(payload) for payload in payloads}) == 1
        by_active.append(payloads)

    empty = by_active[0][0]
    one = by_active[1][0]
    rank_sha256 = hashlib.sha256(fixture.rank_vault.read_bytes()).hexdigest()
    empty_sha256 = hashlib.sha256(fixture.active_empty.read_bytes()).hexdigest()
    one_sha256 = hashlib.sha256(fixture.active_one.read_bytes()).hexdigest()
    stable_empty = _stable(empty)
    stable_one = _stable(one)
    assert (len(stable_empty), hashlib.sha256(stable_empty).hexdigest()) == (
        16_582,
        "cffbf3d49cf484697e1e20480caf5dfef50290b86b13944224b47addc463e0a3",
    )
    assert (len(stable_one), hashlib.sha256(stable_one).hexdigest()) == (
        16_587,
        "b4c1f637eecd1fe25ab5617db5f92a225b86aea7a7b2eea793fc5d02c4e460eb",
    )
    for payload in (empty, one):
        assert payload["schema"] == RESULT_SCHEMA
        assert payload["implementation_parent_schema"] == (
            IMPLEMENTATION_PARENT_SCHEMA
        )
        assert payload["implementation_release_parent_schema"] == (
            RELEASE_PARENT_SCHEMA
        )
        assert payload["rank_source_vault_sha256"] == rank_sha256
        assert payload["reader"]["source_vault_sha256"] == rank_sha256
        assert payload["reader"]["ranked_literals"] == [3, -1, -2, -6]

    assert empty["reader"]["order_sha256"] == one["reader"]["order_sha256"]
    assert empty["reader"]["rank_table_sha256"] == one["reader"][
        "rank_table_sha256"
    ]
    assert empty["vault"]["input_sha256"] == empty_sha256
    assert one["vault"]["input_sha256"] == one_sha256
    assert empty["vault"]["input_clause_count"] == 0
    assert one["vault"]["input_clause_count"] == 1
    assert empty["vault"]["preloaded_clause_count"] == 0
    assert one["vault"]["preloaded_clause_count"] == 1
    assert rank_sha256 not in {empty_sha256, one_sha256}


def test_swapped_or_tampered_split_inputs_fail_closed(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    fixture_binary = native_binaries[0][0]
    fixture = _write_fixture(tmp_path)
    swapped = _run(
        fixture_binary,
        fixture,
        rank_vault=fixture.active_one,
        active_vault=fixture.rank_vault,
    )
    assert swapped.returncode == 1
    assert "cadical_o1_joint_score_sieve_v13:" in swapped.stderr

    tampered_rank = tmp_path / "tampered-rank.vault"
    tampered_rank.write_bytes(fixture.rank_vault.read_bytes() + b"x")
    bad_rank = _run(fixture_binary, fixture, rank_vault=tampered_rank)
    assert bad_rank.returncode == 1
    assert "cadical_o1_joint_score_sieve_v13:" in bad_rank.stderr

    tampered_active = tmp_path / "tampered-active.vault"
    tampered_active.write_bytes(fixture.active_empty.read_bytes() + b"x")
    bad_active = _run(fixture_binary, fixture, active_vault=tampered_active)
    assert bad_active.returncode == 1
    assert "cadical_o1_joint_score_sieve_v13:" in bad_active.stderr


def test_production_binary_rejects_public_rank_source(
    native_binaries: tuple[tuple[Path, Path], Path], tmp_path: Path
) -> None:
    _, production = native_binaries
    fixture = _write_fixture(tmp_path)
    completed = _run(production, fixture)
    assert completed.returncode == 1
    assert "rank vote-field source vault differs" in completed.stderr
