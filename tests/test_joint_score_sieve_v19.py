from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

import o1_crypto_lab.joint_score_sieve_v19 as sieve_v19
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
from o1_crypto_lab.rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
    O1C78_PREFIX_ORDER_SHA256,
    RescuePrefixPreemptionPlan,
    write_rescue_prefix_preemption_plan,
)
from o1_crypto_lab.residual_polarity_staging_v1 import (
    ResidualPolarityStagingPlan,
    derive_residual_polarity_staging_plan,
    write_residual_polarity_staging_plan,
)
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
NATIVE_SOURCE = ROOT / "native/cadical_o1_joint_score_sieve_v16.cpp"
CADICAL_INCLUDE = Path("/opt/homebrew/opt/cadical/include")
CADICAL_LIBRARY = Path("/opt/homebrew/opt/cadical/lib/libcadical.a")


def _field() -> CriticalityPotentialField:
    factors = [
        CriticalityPotentialFactor((1,), (8.0, 0.0)),
        CriticalityPotentialFactor((2,), (6.0, 0.0)),
        CriticalityPotentialFactor((3,), (0.0, 10.0)),
        CriticalityPotentialFactor((6,), (1.0, 0.0)),
        CriticalityPotentialFactor((7,), (0.5, 0.0)),
    ]
    factors.extend(
        CriticalityPotentialFactor((abs(literal),), (0.0, 0.0))
        for literal in O1C78_PREFIX_LITERALS
        if abs(literal) not in {1, 2, 3, 6, 7}
    )
    return CriticalityPotentialField(
        offset=0.0, source_sha256="74" * 32, factors=tuple(factors)
    )


@dataclass(frozen=True)
class PrefixArtifacts:
    cnf: Path
    potential: Path
    grouping_path: Path
    rank_vault_path: Path
    active_vault_path: Path
    rank_table_path: Path
    frontier_plan_path: Path
    staging_plan_path: Path
    prefix_plan_path: Path
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    rank_vault: ThresholdNoGoodVault
    active_vault: ThresholdNoGoodVault
    decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan
    staging_plan: ResidualPolarityStagingPlan
    prefix_plan: RescuePrefixPreemptionPlan


def _source_result(count: int) -> tuple[dict[str, object], str]:
    assignment = b"\0" * count
    source: dict[str, object] = {
        "schema": "public-prefix-source-v1",
        "sieve": {
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": "observed-ascending-i8-sign;fixture",
                "assignment_bytes": count,
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": 0,
            }
        },
    }
    payload = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    return source, hashlib.sha256(payload).hexdigest()


def _artifacts(tmp_path: Path) -> PrefixArtifacts:
    field = _field()
    cnf = tmp_path / "prefix.cnf"
    cnf.write_text(
        "p cnf 191234 5\n6 0\n2 4 5 0\n2 4 -5 0\n"
        "2 -4 5 0\n2 -4 -5 0\n",
        encoding="ascii",
    )
    potential = tmp_path / "prefix.potential"
    grouping_path = tmp_path / "prefix.grouping"
    sieve_v19.write_joint_score_sieve_potential(potential, field)
    sieve_v19.write_joint_score_sieve_grouping(grouping_path, field)
    grouping = build_compatibility_grouping(field, width_cap=6)
    identity = vault_identity_from_sources(
        cnf_sha256=hashlib.sha256(cnf.read_bytes()).hexdigest(),
        potential_sha256=hashlib.sha256(potential.read_bytes()).hexdigest(),
        grouping_sha256=hashlib.sha256(grouping_path.read_bytes()).hexdigest(),
        observed_variables=field.observed_variables,
        bound_rule=sieve_v19.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=12.0,
    )
    rank_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (
            ThresholdNoGoodClause((-1, 3)),
            ThresholdNoGoodClause((-2, 3)),
            ThresholdNoGoodClause((-1, 3, -6)),
            ThresholdNoGoodClause((-1, 3, 7)),
        ),
    )
    active_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (ThresholdNoGoodClause((-1, -2, 3, -6, 7)),),
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
    assert decision.candidate_count == 5
    rank_table_path = tmp_path / "prefix.rank-table"
    rank_table_path.write_bytes(decision.rank_table_bytes)

    source, source_sha = _source_result(len(field.observed_variables))
    frontier_plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active_vault,
        selected_union_indices=(91,),
    )
    frontier_plan_path = tmp_path / "frontier.plan"
    write_causal_frontier_plan(frontier_plan_path, frontier_plan)
    overlay_indices = tuple(
        sorted(
            index
            for index, literal in enumerate(decision.ranked_literals)
            if abs(literal) in (1, 2)
        )
    )
    staging_plan = derive_residual_polarity_staging_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active_vault,
        rank_decision=decision,
        parent_frontier_plan_sha256=frontier_plan.sha256,
        selected_active_index=0,
        selected_union_index=91,
        overlay_rank_indices=overlay_indices,
    )
    staging_plan_path = tmp_path / "staging.plan"
    write_residual_polarity_staging_plan(staging_plan_path, staging_plan)
    prefix_plan = RescuePrefixPreemptionPlan(O1C78_PREFIX_LITERALS)
    prefix_plan_path = tmp_path / "prefix.plan"
    write_rescue_prefix_preemption_plan(prefix_plan_path, prefix_plan)
    return PrefixArtifacts(
        cnf,
        potential,
        grouping_path,
        rank_vault_path,
        active_vault_path,
        rank_table_path,
        frontier_plan_path,
        staging_plan_path,
        prefix_plan_path,
        field,
        grouping,
        rank_vault,
        active_vault,
        decision,
        frontier_plan,
        staging_plan,
        prefix_plan,
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
    executable = tmp_path_factory.mktemp("o1c78-v19-native") / "native-v16"
    completed = subprocess.run(
        [
            "c++",
            "-std=c++17",
            "-O3",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C78_PUBLIC_FIXTURE",
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


def _command(executable: Path, artifacts: PrefixArtifacts) -> list[str]:
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
        "--staging-plan",
        str(artifacts.staging_plan_path),
        "--prefix-plan",
        str(artifacts.prefix_plan_path),
        "--threshold",
        "12",
        "--conflict-limit",
        "64",
        "--seed",
        "0",
    ]


def _native_payload(executable: Path, artifacts: PrefixArtifacts) -> dict[str, Any]:
    completed = subprocess.run(
        _command(executable, artifacts), capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _parse(
    payload: object,
    artifacts: PrefixArtifacts,
    *,
    require_activation: bool = True,
) -> sieve_v19.JointScoreSieveV19Result:
    return sieve_v19._parse_native_payload(
        payload,
        input_vault=artifacts.active_vault,
        rank_source_vault=artifacts.rank_vault,
        frontier_plan=artifacts.frontier_plan,
        staging_plan=artifacts.staging_plan,
        prefix_preemption_plan=artifacts.prefix_plan,
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
        require_frontier_intervention=False,
        require_staging_activation=False,
        require_prefix_preemption_activation=require_activation,
    )


def test_native_consumes_exact_prefix_before_parent_and_preserves_parent(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    result = _parse(payload, artifacts)
    prefix = payload["prefix_preemption"]
    staging = payload["staging"]

    assert prefix["plan_sha256"] == O1C78_PREFIX_ORDER_SHA256
    assert prefix["prefix_literals"] == list(O1C78_PREFIX_LITERALS)
    assert prefix["rows_consumed"] == 11
    assert prefix["once_returns"] + prefix["skipped_preassigned_falsifying"] == 11
    assert prefix["skipped_preassigned_rescue"] == 0
    assert prefix["once_returns"] >= 1
    assert prefix["all_rows_consumed_before_first_parent_call"] is True
    assert prefix["parent_cb_decide_calls"] == staging["cb_decide_calls"]
    assert prefix["parent_returned_sequence_hex"] == staging["returned_sequence_hex"]
    assert payload["sieve"]["trace_sha256"] != O1C78_BASELINE_TRACE_SHA256
    assert result.prefix_preemption_plan == artifacts.prefix_plan
    assert result.prefix_preemption == prefix
    assert sieve_v19.validate_native_lifecycle(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("skipped_preassigned_rescue", 1),
        ("all_rows_consumed_before_first_parent_call", False),
        ("parent_cb_decide_calls", 0),
        ("plan_sha256", "00" * 32),
    ],
)
def test_adapter_rejects_prefix_telemetry_mutation(
    native_fixture: Path,
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    artifacts = _artifacts(tmp_path)
    payload = _native_payload(native_fixture, artifacts)
    mutated = copy.deepcopy(payload)
    mutated["prefix_preemption"][field] = value
    with pytest.raises(O1RelationalSearchError):
        _parse(mutated, artifacts, require_activation=False)


def test_native_rejects_reordered_prefix_plan(
    native_fixture: Path, tmp_path: Path
) -> None:
    artifacts = _artifacts(tmp_path)
    artifacts.prefix_plan_path.write_bytes(
        RescuePrefixPreemptionPlan(tuple(reversed(O1C78_PREFIX_LITERALS))).serialized
    )
    completed = subprocess.run(
        _command(native_fixture, artifacts),
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 1
    assert "sealed O1C78 rescue-prefix preemption plan differs" in completed.stderr
