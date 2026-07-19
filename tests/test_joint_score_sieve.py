from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math
import shutil
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

import o1_crypto_lab.joint_score_sieve as sieve_module
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_sieve import (
    JOINT_SCORE_SIEVE_BOUND_RULE,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    build_native_joint_score_sieve,
    joint_score_complete,
    joint_score_upper_bound,
    run_joint_score_sieve,
    write_joint_score_sieve_potential,
)
from o1_crypto_lab.o1_relational_search import O1RelationalSearchError


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _native_available() -> bool:
    return bool(
        shutil.which("c++")
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    )


def _exhaustive_field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.25,
        source_sha256="31" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (-3.0, 5.0)),
            CriticalityPotentialFactor((1, 2), (0.0, 7.0, -2.0, 4.0)),
            CriticalityPotentialFactor(
                (2, 3),
                (-11.0, 2.0, 13.0, -5.0),
            ),
        ),
    )


def _joint_field() -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="42" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (0.0, 0.0)),
            CriticalityPotentialFactor(
                (1, 257),
                (0.0, 0.0, 2.0, 10.0),
            ),
            CriticalityPotentialFactor((257,), (0.0, 0.0)),
        ),
    )


@pytest.fixture(scope="module")
def native_build(tmp_path_factory: pytest.TempPathFactory):
    if not _native_available():
        pytest.skip("CaDiCaL development files absent")
    output = tmp_path_factory.mktemp("joint-score-native") / "joint-score-sieve"
    build = build_native_joint_score_sieve(source=NATIVE_SOURCE, output=output)
    assert {"-Wall", "-Wextra", "-Werror"}.issubset(build.command)
    return build


def _run_case(
    tmp_path: Path,
    executable: Path,
    *,
    name: str,
    cnf: str,
    field: CriticalityPotentialField,
    threshold: float,
):
    cnf_path = tmp_path / f"{name}.cnf"
    cnf_path.write_text(cnf, encoding="ascii")
    potential_path = tmp_path / f"{name}.potential"
    write_joint_score_sieve_potential(potential_path, field)
    return run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf_path,
        potential_path=potential_path,
        threshold=threshold,
        conflict_limit=128,
    )


def test_partial_bound_is_sound_for_every_synthetic_assignment() -> None:
    field = _exhaustive_field()
    variables = field.observed_variables
    complete = []
    for spins in itertools.product((-1, 1), repeat=len(variables)):
        assignment = dict(zip(variables, spins, strict=True))
        complete.append((assignment, joint_score_complete(field, assignment)))

    for partial_spins in itertools.product((-1, 0, 1), repeat=len(variables)):
        partial = {
            variable: spin
            for variable, spin in zip(variables, partial_spins, strict=True)
            if spin
        }
        consistent_scores = [
            score
            for assignment, score in complete
            if all(assignment[variable] == spin for variable, spin in partial.items())
        ]
        upper = joint_score_upper_bound(field, partial)
        assert upper >= max(consistent_scores)

    with pytest.raises(O1RelationalSearchError, match="partial assignment"):
        joint_score_upper_bound(field, {1: 0})

    unrepresentable = CriticalityPotentialField(
        offset=0.0,
        source_sha256="ff" * 32,
        factors=(
            CriticalityPotentialFactor(
                (1,), (float.fromhex("0x1.fffffffffffffp1023"),) * 2
            ),
        ),
    )
    with pytest.raises(O1RelationalSearchError, match="not representable"):
        joint_score_upper_bound(unrepresentable, {})


def test_potential_writer_is_exact_and_hashed(tmp_path: Path) -> None:
    field = _joint_field()
    destination = tmp_path / "joint.potential"
    reported = write_joint_score_sieve_potential(destination, field)
    assert destination.read_bytes() == field.to_bytes()
    assert reported == hashlib.sha256(field.to_bytes()).hexdigest()


def test_native_prunes_below_joint_branch_and_accepts_above_solution(
    tmp_path: Path, native_build
) -> None:
    result = _run_case(
        tmp_path,
        native_build.executable,
        name="joint-above",
        cnf="p cnf 257 1\n257 0\n",
        field=_joint_field(),
        threshold=9.0,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert result.key_model[0] & 1
    assert result.sieve["decision_rule"] == JOINT_SCORE_SIEVE_DECISION_RULE
    assert result.sieve["bound_rule"] == JOINT_SCORE_SIEVE_BOUND_RULE
    assert result.sieve["observed_variables"] == 2
    assert result.sieve["cb_decide_calls"] > 0
    assert result.sieve["cb_decide_nonzero"] == 0
    assert result.sieve["models_at_or_above_threshold"] >= 1
    assert result.sieve["minimum_complete_score"] >= 9.0
    assert result.sieve["factor_maximum_evaluations"] < (
        result.sieve["bound_checks"] * result.sieve["factor_count"]
    )


def test_native_matches_every_synthetic_model_around_exact_threshold(
    tmp_path: Path, native_build
) -> None:
    field = _exhaustive_field()
    variables = field.observed_variables
    for mask, spins in enumerate(itertools.product((-1, 1), repeat=len(variables))):
        assignment = dict(zip(variables, spins, strict=True))
        score = joint_score_complete(field, assignment)
        units = "".join(
            f"{variable if spin > 0 else -variable} 0\n"
            for variable, spin in assignment.items()
        )
        cnf = f"p cnf 256 {len(variables)}\n{units}"
        for relation, threshold in (
            ("below", score - 0.125),
            ("equal", score),
            ("above", score + 0.125),
        ):
            result = _run_case(
                tmp_path,
                native_build.executable,
                name=f"exhaustive-{mask}-{relation}",
                cnf=cnf,
                field=field,
                threshold=threshold,
            )
            assert (result.status_name == "SAT") is (score >= threshold)


def test_native_bad_first_branch_backtracks_into_survivor(
    tmp_path: Path, native_build
) -> None:
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="47" * 32,
        factors=(CriticalityPotentialFactor((1,), (10.0, 0.0)),),
    )
    result = _run_case(
        tmp_path,
        native_build.executable,
        name="backtrack-survivor",
        cnf="p cnf 256 0\n",
        field=field,
        threshold=9.0,
    )
    assert result.status_name == "SAT"
    assert result.key_model is not None
    assert not result.key_model[0] & 1
    assert result.sieve["threshold_prunes"] >= 1
    assert result.sieve["backtracks"] >= 1
    assert result.sieve["backtracked_assignments"] >= 1
    assert result.sieve["pending_clause_count"] == 0


def test_native_blocks_forced_below_threshold_branch(
    tmp_path: Path, native_build
) -> None:
    result = _run_case(
        tmp_path,
        native_build.executable,
        name="joint-below",
        cnf="p cnf 257 2\n257 0\n-1 0\n",
        field=_joint_field(),
        threshold=9.0,
    )
    assert result.status_name == "UNSAT"
    assert result.key_model is None
    assert result.sieve["trail_threshold_prunes"] >= 1
    assert result.sieve["external_clauses_queued"] >= 1
    assert result.sieve["external_clauses_emitted"] >= 1
    assert result.sieve["maximum_clause_length"] == 1
    assert result.sieve["cb_decide_nonzero"] == 0


def test_native_complete_model_check_rejects_score_below_threshold(
    tmp_path: Path, native_build
) -> None:
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="53" * 32,
        factors=(CriticalityPotentialFactor((1,), (0.0, 10.0)),),
    )
    result = _run_case(
        tmp_path,
        native_build.executable,
        name="model-reject",
        cnf="p cnf 256 1\n-1 0\n",
        field=field,
        threshold=math.nextafter(0.0, math.inf),
    )
    assert result.status_name == "UNSAT"
    assert result.sieve["trail_threshold_prunes"] == 0
    assert result.sieve["model_threshold_prunes"] == 1
    assert result.sieve["models_below_threshold"] == 1
    assert result.sieve["minimum_complete_score"] == 0.0


def test_native_threshold_comparison_is_exact_under_cancellation(
    tmp_path: Path, native_build
) -> None:
    field = CriticalityPotentialField(
        offset=1.0e16,
        source_sha256="64" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (1.0, 1.0)),
            CriticalityPotentialFactor((2,), (-1.0e16, -1.0e16)),
        ),
    )
    cnf = "p cnf 256 2\n-1 0\n-2 0\n"
    accepted = _run_case(
        tmp_path,
        native_build.executable,
        name="exact-cancellation-accepted",
        cnf=cnf,
        field=field,
        threshold=0.5,
    )
    rejected = _run_case(
        tmp_path,
        native_build.executable,
        name="exact-cancellation-rejected",
        cnf=cnf,
        field=field,
        threshold=1.5,
    )
    assert accepted.status_name == "SAT"
    assert accepted.sieve["models_at_or_above_threshold"] == 1
    assert accepted.sieve["minimum_complete_score"] == 1.0
    assert rejected.status_name == "UNSAT"
    assert rejected.sieve["trail_threshold_prunes"] == 0
    assert rejected.sieve["model_threshold_prunes"] == 1
    assert rejected.sieve["minimum_complete_score"] == 1.0


def test_native_replay_has_identical_scientific_state(
    tmp_path: Path, native_build
) -> None:
    first = _run_case(
        tmp_path,
        native_build.executable,
        name="replay",
        cnf="p cnf 257 1\n257 0\n",
        field=_joint_field(),
        threshold=9.0,
    )
    second = _run_case(
        tmp_path,
        native_build.executable,
        name="replay",
        cnf="p cnf 257 1\n257 0\n",
        field=_joint_field(),
        threshold=9.0,
    )
    assert first.status == second.status
    assert first.key_model == second.key_model
    assert first.stats == second.stats
    assert first.sieve == second.sieve
    state = first.sieve["state"]
    combined = (
        bytes.fromhex(str(state["assignment_hex"]))
        + bytes.fromhex(str(state["trail_hex"]))
        + bytes.fromhex(str(state["pending_hex"]))
    )
    assert hashlib.sha256(combined).hexdigest() == state["sha256"]
    assert state["live_state_bytes"] <= state["bounded_state_bytes"]
    cache = bytes.fromhex(str(state["factor_cache_hex"]))
    assert state["derived_factor_cache_bytes"] == len(cache)
    assert state["live_persistent_state_bytes"] == len(combined) + len(cache)
    assert hashlib.sha256(combined + cache).hexdigest() == state["persistent_sha256"]


def test_adapter_rejects_tampered_native_contract(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    field = _joint_field()
    cnf = tmp_path / "tamper.cnf"
    cnf.write_text("p cnf 257 1\n257 0\n", encoding="ascii")
    potential = tmp_path / "tamper.potential"
    write_joint_score_sieve_potential(potential, field)
    valid = run_joint_score_sieve(
        executable=native_build.executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=9.0,
        conflict_limit=128,
    ).raw

    def reject(payload: object, message: str) -> None:
        monkeypatch.setattr(
            sieve_module.subprocess,
            "run",
            lambda *args, **kwargs: SimpleNamespace(
                returncode=0,
                stdout=json.dumps(payload),
                stderr="",
            ),
        )
        with pytest.raises(O1RelationalSearchError, match=message):
            run_joint_score_sieve(
                executable=native_build.executable,
                cnf_path=cnf,
                potential_path=potential,
                threshold=9.0,
                conflict_limit=128,
            )

    wrong_input = copy.deepcopy(valid)
    wrong_input["cnf_sha256"] = "00" * 32
    reject(wrong_input, "result contract")

    external_decision = copy.deepcopy(valid)
    external_decision["sieve"]["cb_decide_nonzero"] = 1
    reject(external_decision, "telemetry contract")

    wrong_state = copy.deepcopy(valid)
    wrong_state["sieve"]["state"]["sha256"] = "00" * 32
    reject(wrong_state, "state hash")

    wrong_cache = copy.deepcopy(valid)
    cache_state = wrong_cache["sieve"]["state"]
    cache = bytearray.fromhex(cache_state["factor_cache_hex"])
    cache[0] ^= 1
    cache_state["factor_cache_hex"] = cache.hex()
    cache_state["factor_cache_sha256"] = hashlib.sha256(cache).hexdigest()
    canonical = (
        bytes.fromhex(cache_state["assignment_hex"])
        + bytes.fromhex(cache_state["trail_hex"])
        + bytes.fromhex(cache_state["pending_hex"])
    )
    cache_state["persistent_sha256"] = hashlib.sha256(canonical + cache).hexdigest()
    reject(wrong_cache, "factor cache")

    malformed_trail = copy.deepcopy(valid)
    trail_state = malformed_trail["sieve"]["state"]
    trail = bytearray.fromhex(trail_state["trail_hex"])
    struct.pack_into("<I", trail, 4, 2**32 - 1)
    trail_state["trail_hex"] = trail.hex()
    reject(malformed_trail, "trail differs")

    malformed_pending = copy.deepcopy(valid)
    pending_state = malformed_pending["sieve"]["state"]
    pending = bytearray.fromhex(pending_state["pending_hex"])
    struct.pack_into("<I", pending, 0, 2**32 - 1)
    pending_state["pending_hex"] = pending.hex()
    reject(malformed_pending, "pending clause differs")

    missing_field = copy.deepcopy(valid)
    del missing_field["sieve"]["trace_sha256"]
    reject(missing_field, "telemetry fields")

    reject("not-json", "result fields")


def test_adapter_rejects_malformed_json(
    tmp_path: Path, native_build, monkeypatch: pytest.MonkeyPatch
) -> None:
    cnf = tmp_path / "malformed.cnf"
    cnf.write_text("p cnf 257 0\n", encoding="ascii")
    potential = tmp_path / "malformed.potential"
    write_joint_score_sieve_potential(potential, _joint_field())
    monkeypatch.setattr(
        sieve_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="{",
            stderr="",
        ),
    )
    with pytest.raises(O1RelationalSearchError, match="JSON is invalid"):
        run_joint_score_sieve(
            executable=native_build.executable,
            cnf_path=cnf,
            potential_path=potential,
            threshold=9.0,
            conflict_limit=128,
        )
