from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.joint_score_sieve_v2 as sieve_v2
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v2 import (
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET,
    build_native_joint_score_sieve,
    run_joint_score_sieve,
    validate_incremental_conflict_ledger,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v2.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 0.0)),
            CriticalityPotentialFactor((1, 257), (0.0, 0.0, 2.0, 10.0)),
            CriticalityPotentialFactor((257,), (0.0, 0.0)),
        ),
    )


@pytest.fixture(scope="module")
def native_build(tmp_path_factory: pytest.TempPathFactory):
    if not _native_available():
        pytest.skip("CaDiCaL development files absent")
    output = tmp_path_factory.mktemp("joint-score-v2-native") / "joint-score-v2"
    return build_native_joint_score_sieve(source=NATIVE_SOURCE, output=output)


def _run_native(tmp_path: Path, executable: Path):
    cnf = tmp_path / "case.cnf"
    cnf.write_text("p cnf 257 1\n257 0\n", encoding="ascii")
    potential = tmp_path / "case.potential"
    write_joint_score_sieve_potential(potential, _field())
    return (
        run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            threshold=9.0,
            conflict_limit=128,
        ),
        cnf,
        potential,
    )


def test_cumulative_513_before_1_solve_512_is_valid() -> None:
    ledger = validate_incremental_conflict_ledger(
        {
            "conflicts": 513,
            "conflicts_before_solve": 1,
            "solve_conflicts": 512,
            "decisions": 9_166,
            "propagations": 1_227_877,
        },
        requested_conflicts=512,
    )
    assert ledger["conflicts"] == 513
    assert ledger["conflicts_before_solve"] == 1
    assert ledger["solve_conflicts"] == 512


@pytest.mark.parametrize(
    ("changes", "requested"),
    [
        ({"solve_conflicts": 511}, 512),
        ({"conflicts_before_solve": 514}, 512),
        ({"conflicts": 514, "solve_conflicts": 513}, 512),
        ({}, 513),
    ],
)
def test_incremental_conflict_ledger_rejects_mismatch(
    changes: dict[str, int], requested: int
) -> None:
    stats = {
        "conflicts": 513,
        "conflicts_before_solve": 1,
        "solve_conflicts": 512,
        "decisions": 9_166,
        "propagations": 1_227_877,
    }
    stats.update(changes)
    with pytest.raises(O1RelationalSearchError, match="conflict"):
        validate_incremental_conflict_ledger(stats, requested_conflicts=requested)


def test_v2_native_reports_exact_incremental_ledger(
    tmp_path: Path, native_build
) -> None:
    result, _, _ = _run_native(tmp_path, native_build.executable)
    stats = result.stats
    assert stats["solve_conflicts"] == (
        stats["conflicts"] - stats["conflicts_before_solve"]
    )
    assert stats["solve_conflicts"] <= result.conflict_limit
    assert result.conflict_limit <= JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET


def test_full_v2_parser_accepts_513_1_512_and_rejects_mismatch(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid, cnf, potential = _run_native(tmp_path, native_build.executable)
    historical = copy.deepcopy(valid.raw)
    historical["conflict_limit"] = 512
    historical["stats"].update(  # type: ignore[union-attr]
        {
            "conflicts": 513,
            "conflicts_before_solve": 1,
            "solve_conflicts": 512,
        }
    )

    def install(payload: object) -> None:
        monkeypatch.setattr(
            sieve_v2._v1.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout=json.dumps(payload), stderr=""
            ),
        )

    install(historical)
    parsed = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=9.0,
        conflict_limit=512,
    )
    assert parsed.stats["solve_conflicts"] == 512

    mismatch = copy.deepcopy(historical)
    mismatch["stats"]["solve_conflicts"] = 511  # type: ignore[index]
    install(mismatch)
    with pytest.raises(O1RelationalSearchError, match="conflict ledger"):
        run_joint_score_sieve(
            executable=native_build.executable,
            cnf_path=cnf,
            potential_path=potential,
            threshold=9.0,
            conflict_limit=512,
        )


def test_v2_rejects_oversized_budget_before_reading_inputs() -> None:
    with pytest.raises(O1RelationalSearchError, match="conflict budget"):
        run_joint_score_sieve(
            executable="not-read",
            cnf_path="not-read",
            potential_path="not-read",
            threshold=0.0,
            conflict_limit=513,
        )
