from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
from typing import Any, Callable

import pytest

import o1_crypto_lab.joint_score_sieve_v17 as sieve_v17
from o1_crypto_lab.causal_frontier_v1 import (
    CausalFrontierPlan,
    derive_causal_frontier_plan,
    write_causal_frontier_plan,
)
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import (
    JointScoreCompatibilityGrouping,
    build_compatibility_grouping,
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
    derive_vault_ranked_decision,
)


ROOT = Path(__file__).resolve().parents[1]
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v14.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _field() -> CriticalityPotentialField:
    # Variables 7 and 8 are observed but absent from the rank-source vault.
    # They therefore provide a deterministic parent-fallback-only frontier.
    return CriticalityPotentialField(
        offset=0.0,
        source_sha256="74" * 32,
        factors=(
            CriticalityPotentialFactor((1,), (8.0, 0.0)),
            CriticalityPotentialFactor((2,), (6.0, 0.0)),
            CriticalityPotentialFactor((3,), (0.0, 10.0)),
            CriticalityPotentialFactor((6,), (1.0, 0.0)),
            CriticalityPotentialFactor((7,), (0.5, 0.0)),
            CriticalityPotentialFactor((8,), (0.25, 0.0)),
        ),
    )


@dataclass(frozen=True)
class FrontierArtifacts:
    cnf: Path
    potential: Path
    grouping_path: Path
    rank_vault_path: Path
    active_vault_path: Path
    rank_table_path: Path
    frontier_plan_path: Path
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    rank_vault: ThresholdNoGoodVault
    active_vault: ThresholdNoGoodVault
    decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan


def _source_result(signs: tuple[int, ...]) -> tuple[dict[str, object], str]:
    assignment = bytes(255 if sign == -1 else sign for sign in signs)
    source: dict[str, object] = {
        "schema": "public-frontier-source-v1",
        "sieve": {
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": "observed-ascending-i8-sign;public-fixture",
                "assignment_bytes": len(assignment),
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": sum(sign != 0 for sign in signs),
            }
        },
    }
    payload = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    return source, hashlib.sha256(payload).hexdigest()


def _artifacts(tmp_path: Path) -> FrontierArtifacts:
    field = _field()
    cnf = tmp_path / "frontier.cnf"
    cnf.write_text(
        "p cnf 256 5\n6 0\n2 4 5 0\n2 4 -5 0\n2 -4 5 0\n2 -4 -5 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "frontier.potential"
    grouping_path = tmp_path / "frontier.grouping"
    sieve_v17.write_joint_score_sieve_potential(potential, field)
    sieve_v17.write_joint_score_sieve_grouping(grouping_path, field)
    grouping = build_compatibility_grouping(field, width_cap=6)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping_path.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v17.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    rank_clauses = (
        ThresholdNoGoodClause((-1, 3)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-1, 3, -6)),
    )
    rank_vault = ThresholdNoGoodVault(identity, field.observed_variables, rank_clauses)
    # This remains certified because (-1,3) is certified; appending 7,8
    # restricts its falsifying assignment further.  At runtime 7 and 8 are
    # absent from the parent rank and remain available at parent fallback.
    active_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (ThresholdNoGoodClause((-1, 3, 7, 8)),),
    )
    rank_vault_path = tmp_path / "rank-source.vault"
    active_vault_path = tmp_path / "active.vault"
    write_threshold_no_good_vault(rank_vault_path, rank_vault, caps=O1C66_VAULT_CAPS)
    write_threshold_no_good_vault(
        active_vault_path, active_vault, caps=O1C66_VAULT_CAPS
    )
    phase = derive_vault_phase_field(
        rank_vault.serialized, key_variable_count=256, clause_start=0
    )
    decision = derive_vault_ranked_decision(phase, field, grouping)
    assert decision.ranked_literals == (3, -1, -2, -6)
    rank_table_path = tmp_path / "frontier.rank-table"
    rank_table_path.write_bytes(decision.rank_table_bytes)

    source, source_sha256 = _source_result((1, 0, -1, 0, 0, 0))
    frontier_plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=active_vault,
        selected_union_indices=(91,),
    )
    assert frontier_plan.residual_clause_literals == (7, 8)
    frontier_plan_path = tmp_path / "frontier.plan"
    write_causal_frontier_plan(frontier_plan_path, frontier_plan)
    return FrontierArtifacts(
        cnf,
        potential,
        grouping_path,
        rank_vault_path,
        active_vault_path,
        rank_table_path,
        frontier_plan_path,
        field,
        grouping,
        rank_vault,
        active_vault,
        decision,
        frontier_plan,
    )


@pytest.fixture(scope="module")
def native_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not (
        shutil.which("c++")
        and NATIVE_SOURCE.is_file()
        and (CADICAL_INCLUDE / "cadical.hpp").is_file()
        and CADICAL_LIBRARY.is_file()
    ):
        pytest.skip("CaDiCaL 3.0.0 development files absent")
    executable = tmp_path_factory.mktemp("o1c76-v17-native") / "native-v14"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C76_PUBLIC_FIXTURE",
            f"-I{CADICAL_INCLUDE}",
            str(NATIVE_SOURCE),
            str(CADICAL_LIBRARY),
            "-o",
            str(executable),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return executable


def _command(executable: Path, artifacts: FrontierArtifacts) -> list[str]:
    return [
        str(executable),
        "--cnf",
        str(artifacts.cnf),
        "--potential",
        str(artifacts.potential),
        "--grouping",
        str(artifacts.grouping_path),
        "--rank-vault",
        str(artifacts.rank_vault_path),
        "--vault-in",
        str(artifacts.active_vault_path),
        "--rank-table",
        str(artifacts.rank_table_path),
        "--frontier-plan",
        str(artifacts.frontier_plan_path),
        "--threshold",
        "12",
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _native_payload(executable: Path, artifacts: FrontierArtifacts) -> dict[str, Any]:
    completed = subprocess.run(
        _command(executable, artifacts),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _parse(
    payload: object, artifacts: FrontierArtifacts
) -> sieve_v17.JointScoreSieveV17Result:
    return sieve_v17._parse_native_payload(
        payload,
        input_vault=artifacts.active_vault,
        rank_source_vault=artifacts.rank_vault,
        frontier_plan=artifacts.frontier_plan,
        vault_caps=O1C66_VAULT_CAPS,
        field=artifacts.field,
        grouping=artifacts.grouping,
        grouping_sha256=artifacts.rank_vault.identity.grouping_sha256,
        cnf_sha256=artifacts.rank_vault.identity.cnf_sha256,
        potential_sha256=artifacts.rank_vault.identity.potential_sha256,
        threshold=12.0,
        requested_conflicts=64,
        seed=0,
        memory_limit_bytes=None,
        memory_samples=(),
        expected_decision=artifacts.decision,
        require_active_contrast=False,
    )


def test_native_frontier_intervenes_only_at_parent_fallback_and_contrasts(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    result = _parse(payload, artifacts)
    frontier = payload["frontier"]
    parent = payload["reader"]

    assert payload["schema"] == sieve_v17.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert payload["implementation_release_parent_schema"] == (
        sieve_v17.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    )
    assert payload["frontier_plan_sha256"] == artifacts.frontier_plan.sha256
    assert frontier["initial_once_returns"] == 2
    assert frontier["initial_releases"] == 2
    assert frontier["contrast_returns"] == 2
    assert frontier["initial_return_sequence_hex"] == (struct_i32_hex((-7, -8)))
    assert frontier["contrast_return_sequence_hex"] == struct_i32_hex((7, 8))
    parent_nonzero_calls = {event["call"] for event in parent["nonzero_return_events"]}
    substitutions = frontier["substitution_events"]
    assert [event["literal"] for event in substitutions] == [-7, -8, 7, 8]
    assert all(event["call"] not in parent_nonzero_calls for event in substitutions)
    assert frontier["cb_decide_calls"] == parent["cb_decide_calls"]
    assert result.frontier_plan == artifacts.frontier_plan
    assert result.frontier_reader == frontier
    assert result.frontier == frontier
    assert result.reader == parent


def struct_i32_hex(values: tuple[int, ...]) -> str:
    return b"".join(
        int(value).to_bytes(4, "little", signed=True) for value in values
    ).hex()


def test_native_is_deterministic_and_rejects_plan_mismatch(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    left = _native_payload(native_fixture, artifacts)
    right = _native_payload(native_fixture, artifacts)
    left.pop("resources")
    right.pop("resources")
    assert left == right

    wrong_active = ThresholdNoGoodVault(
        artifacts.active_vault.identity,
        artifacts.field.observed_variables,
        (ThresholdNoGoodClause((-1, 3)),),
    )
    source, source_sha256 = _source_result((0, 0, 0, 0, 0, 0))
    wrong_plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=wrong_active,
        selected_union_indices=(3,),
    )
    write_causal_frontier_plan(artifacts.frontier_plan_path, wrong_plan)
    completed = subprocess.run(
        _command(native_fixture, artifacts),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "active vault digest differs" in completed.stderr


Mutation = Callable[[dict[str, Any]], None]


def _top(field: str, value: object) -> Mutation:
    return lambda payload: payload.__setitem__(field, value)


def _frontier(field: str, value: object) -> Mutation:
    def mutate(payload: dict[str, Any]) -> None:
        payload["frontier"][field] = value

    return mutate


def _event_literal(payload: dict[str, Any]) -> None:
    payload["frontier"]["substitution_events"][0]["literal"] *= -1


@pytest.mark.parametrize(
    "mutation",
    (
        _top("schema", "legacy"),
        _top("frontier_plan_sha256", "00" * 32),
        _top("frontier_source_result_sha256", "00" * 32),
        _frontier("source_assignment_sha256", "00" * 32),
        _frontier("cb_decide_calls", 1),
        _frontier("returned_sequence_sha256", "00" * 32),
        _frontier("bounded_guidance_state_bytes", 1),
        _event_literal,
    ),
)
def test_adapter_rejects_field_hash_count_sequence_and_state_tamper(
    native_fixture: Path,
    tmp_path: Path,
    mutation: Mutation,
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = copy.deepcopy(_native_payload(native_fixture, artifacts))
    mutation(payload)
    with pytest.raises(O1RelationalSearchError, match="joint-score-sieve-v17"):
        _parse(payload, artifacts)


def test_lifecycle_validator_rejects_corrupt_outer_sequence(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    assert sieve_v17.validate_native_lifecycle(payload)
    payload["frontier"]["returned_sequence_sha256"] = "00" * 32
    with pytest.raises(O1RelationalSearchError, match="joint-score-sieve-v17"):
        sieve_v17.validate_native_lifecycle(payload)


def test_process_adapter_returns_v17_and_stability_checks_plan(
    native_fixture: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    monkeypatch.setattr(
        sieve_v17,
        "derive_production_vault_ranked_decision",
        lambda *_args: artifacts.decision,
    )
    result = sieve_v17.run_joint_score_sieve(
        executable=native_fixture,
        cnf_path=artifacts.cnf,
        potential_path=artifacts.potential,
        grouping_path=artifacts.grouping_path,
        rank_vault_path=artifacts.rank_vault_path,
        vault_path=artifacts.active_vault_path,
        frontier_plan_path=artifacts.frontier_plan_path,
        vault_caps=O1C66_VAULT_CAPS,
        threshold=12.0,
        conflict_limit=64,
        seed=0,
        timeout_seconds=10.0,
        require_active_contrast=False,
    )
    assert isinstance(result, sieve_v17.JointScoreSieveV17Result)
    assert result.raw["schema"] == sieve_v17.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    assert result.frontier_plan_sha256 == artifacts.frontier_plan.sha256

    executor = sieve_v17._v16._v15._v14._v13._v12._v11._v9._v8._v7
    original_execute = executor._execute_native

    def execute_then_drift(
        command: list[str],
        *,
        timeout_seconds: float,
        memory_limit_bytes: int | None,
    ) -> object:
        execution = original_execute(
            command,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        artifacts.frontier_plan_path.write_bytes(
            artifacts.frontier_plan_path.read_bytes() + b"x"
        )
        return execution

    monkeypatch.setattr(executor, "_execute_native", execute_then_drift)
    with pytest.raises(
        sieve_v17.JointScoreSieveExecutionError,
        match="joint-score-sieve-v17",
    ):
        sieve_v17.run_joint_score_sieve(
            executable=native_fixture,
            cnf_path=artifacts.cnf,
            potential_path=artifacts.potential,
            grouping_path=artifacts.grouping_path,
            rank_vault_path=artifacts.rank_vault_path,
            vault_path=artifacts.active_vault_path,
            frontier_plan_path=artifacts.frontier_plan_path,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=12.0,
            conflict_limit=64,
            seed=0,
            timeout_seconds=10.0,
            require_active_contrast=False,
        )


def test_native_cli_requires_frontier_plan(native_fixture: Path) -> None:
    help_result = subprocess.run(
        [str(native_fixture), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "--frontier-plan PATH" in help_result.stdout
    missing = subprocess.run(
        [str(native_fixture), "--seed", "0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode == 1
    assert "frontier-plan argument is missing" in missing.stderr
