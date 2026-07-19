from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.joint_score_sieve_v3 as sieve_v3
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve_v3 import (
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    build_native_joint_score_sieve,
    derive_soft_conflict_ledger,
    run_joint_score_sieve,
    validate_soft_conflict_ledger,
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
    output = tmp_path_factory.mktemp("joint-score-v3-native") / "joint-score-v3"
    return build_native_joint_score_sieve(source=NATIVE_SOURCE, output=output)


def _native_stats(*, requested: int, overshoot: int) -> dict[str, int]:
    solve = requested + overshoot
    return {
        "conflicts": solve,
        "conflicts_before_solve": 0,
        "solve_conflicts": solve,
        "decisions": 9_166,
        "propagations": 1_227_877,
    }


def _validated(*, requested: int, overshoot: int) -> dict[str, int]:
    return derive_soft_conflict_ledger(
        _native_stats(requested=requested, overshoot=overshoot),
        requested_conflicts=requested,
    )


def test_request_512_bills_513_with_one_soft_stop_overshoot() -> None:
    ledger = _validated(requested=512, overshoot=1)
    assert ledger["requested_conflicts"] == 512
    assert ledger["conflicts"] == 513
    assert ledger["conflicts_before_solve"] == 0
    assert ledger["solve_conflicts"] == 513
    assert ledger["conflict_limit_overshoot"] == 1
    assert ledger["billed_conflicts"] == JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS


def test_request_one_exact_stop_is_valid() -> None:
    ledger = _validated(requested=1, overshoot=0)
    assert ledger["requested_conflicts"] == 1
    assert ledger["solve_conflicts"] == 1
    assert ledger["conflict_limit_overshoot"] == 0
    assert ledger["billed_conflicts"] == 1


def test_early_finish_preserves_unused_requested_budget() -> None:
    ledger = derive_soft_conflict_ledger(
        {
            "conflicts": 11,
            "conflicts_before_solve": 4,
            "solve_conflicts": 7,
            "decisions": 100,
            "propagations": 1_000,
        },
        requested_conflicts=512,
    )
    assert ledger["unused_requested_conflicts"] == 505
    assert ledger["conflict_limit_overshoot"] == 0
    assert ledger["billed_conflicts"] == 7


def test_soft_conflict_ledger_rejects_overshoot_two() -> None:
    with pytest.raises(O1RelationalSearchError, match="soft conflict ledger"):
        derive_soft_conflict_ledger(
            _native_stats(requested=512, overshoot=2),
            requested_conflicts=512,
        )


def test_soft_conflict_ledger_rejects_equation_mismatch() -> None:
    ledger = _validated(requested=512, overshoot=1)
    ledger["conflicts"] = 512
    with pytest.raises(O1RelationalSearchError, match="soft conflict ledger"):
        validate_soft_conflict_ledger(ledger)


def test_soft_conflict_ledger_rejects_missing_field() -> None:
    ledger = _validated(requested=512, overshoot=1)
    del ledger["conflict_limit_overshoot"]
    with pytest.raises(O1RelationalSearchError, match="fields"):
        validate_soft_conflict_ledger(ledger)


def test_v3_parser_persists_validated_soft_ledger(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf = tmp_path / "case.cnf"
    cnf.write_text("p cnf 257 1\n257 0\n", encoding="ascii")
    potential = tmp_path / "case.potential"
    write_joint_score_sieve_potential(potential, _field())
    native = sieve_v3._RUN_NATIVE_CONTRACT(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=9.0,
        conflict_limit=1,
    )
    payload = copy.deepcopy(native.raw)
    payload["conflict_limit"] = 512
    payload["stats"].update(_native_stats(requested=512, overshoot=1))  # type: ignore[union-attr]
    monkeypatch.setattr(
        sieve_v3._v1.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr=""
        ),
    )
    parsed = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=9.0,
        conflict_limit=512,
    )
    assert parsed.stats["requested_conflicts"] == 512
    assert parsed.stats["unused_requested_conflicts"] == 0
    assert parsed.stats["solve_conflicts"] == 513
    assert parsed.stats["conflict_limit_overshoot"] == 1
    assert parsed.stats["billed_conflicts"] == 513


def test_v3_rejects_oversized_request_before_reading_inputs() -> None:
    with pytest.raises(O1RelationalSearchError, match="requested conflict"):
        run_joint_score_sieve(
            executable="not-read",
            cnf_path="not-read",
            potential_path="not-read",
            threshold=0.0,
            conflict_limit=513,
        )
