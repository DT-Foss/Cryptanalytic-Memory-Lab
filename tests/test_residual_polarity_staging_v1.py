from __future__ import annotations

import hashlib
import json

import pytest

from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import build_compatibility_grouping
from o1_crypto_lab.residual_polarity_staging_v1 import (
    RESIDUAL_POLARITY_STAGING_PLAN_MAGIC,
    ResidualPolarityStagingError,
    derive_residual_polarity_staging_plan,
    parse_residual_polarity_staging_plan,
    validate_residual_polarity_staging_plan,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
)
from o1_crypto_lab.vault_phase_field_v1 import derive_vault_phase_field
from o1_crypto_lab.vault_ranked_decision_v1 import derive_vault_ranked_decision


def _artifacts() -> tuple[
    ThresholdNoGoodVault,
    object,
    dict[str, object],
    str,
]:
    field = CriticalityPotentialField(
        offset=0.0,
        source_sha256="74" * 32,
        factors=tuple(
            CriticalityPotentialFactor((variable,), (float(variable), 0.0))
            for variable in (1, 2, 3, 4, 5)
        ),
    )
    grouping = build_compatibility_grouping(field, width_cap=6)
    identity = vault_identity_from_sources(
        cnf_sha256="01" * 32,
        potential_sha256="02" * 32,
        grouping_sha256="03" * 32,
        observed_variables=field.observed_variables,
        bound_rule="fixture-bound-v1",
        threshold=1.0,
    )
    rank_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        tuple(ThresholdNoGoodClause((variable,)) for variable in range(1, 6)),
    )
    active_vault = ThresholdNoGoodVault(
        identity,
        field.observed_variables,
        (ThresholdNoGoodClause((-1, -2, -3, -4, 5)),),
    )
    phase = derive_vault_phase_field(
        rank_vault.serialized, key_variable_count=5, clause_start=0
    )
    decision = derive_vault_ranked_decision(phase, field, grouping)
    assert decision.candidate_count == 5
    assignment = b"\0" * 5
    source: dict[str, object] = {
        "schema": "fixture-source-v1",
        "sieve": {
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": "observed-ascending-i8-sign;fixture",
                "assignment_bytes": len(assignment),
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": 0,
            }
        },
    }
    source_sha = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return active_vault, decision, source, source_sha


def test_plan_round_trip_binds_five_residual_intersections_and_two_overlays() -> None:
    active, decision, source, source_sha = _artifacts()
    plan = derive_residual_polarity_staging_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active,
        rank_decision=decision,  # type: ignore[arg-type]
        parent_frontier_plan_sha256="ab" * 32,
        selected_active_index=0,
        selected_union_index=17,
        overlay_rank_indices=(1, 3),
    )
    assert plan.serialized.startswith(RESIDUAL_POLARITY_STAGING_PLAN_MAGIC)
    assert len(plan.intersections) == 5
    assert len(plan.overlays) == 2
    assert plan.effective_rank_literals[1] == -plan.source_rank_literals[1]
    assert plan.effective_rank_literals[3] == -plan.source_rank_literals[3]
    assert (
        parse_residual_polarity_staging_plan(
            plan.serialized,
            active_vault=active,
            rank_decision=decision,  # type: ignore[arg-type]
        )
        == plan
    )


def test_only_prior_unassigned_clause_rows_form_the_intersection() -> None:
    active, decision, source, source_sha = _artifacts()
    state = source["sieve"]["state"]  # type: ignore[index]
    assert isinstance(state, dict)
    assignment = bytes((1, 0, 0, 0, 0))
    state["assignment_hex"] = assignment.hex()
    state["assignment_sha256"] = hashlib.sha256(assignment).hexdigest()
    state["current_assigned_variables"] = 1
    source_sha = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ResidualPolarityStagingError, match="intersection"):
        derive_residual_polarity_staging_plan(
            source_result=source,
            source_result_sha256=source_sha,
            active_vault=active,
            rank_decision=decision,  # type: ignore[arg-type]
            parent_frontier_plan_sha256="ab" * 32,
            selected_active_index=0,
            selected_union_index=17,
            overlay_rank_indices=(1, 3),
        )


def test_checksum_and_active_binding_tamper_are_rejected() -> None:
    active, decision, source, source_sha = _artifacts()
    plan = derive_residual_polarity_staging_plan(
        source_result=source,
        source_result_sha256=source_sha,
        active_vault=active,
        rank_decision=decision,  # type: ignore[arg-type]
        parent_frontier_plan_sha256="ab" * 32,
        selected_active_index=0,
        selected_union_index=17,
        overlay_rank_indices=(1, 3),
    )
    payload = bytearray(plan.serialized)
    payload[-33] ^= 1
    with pytest.raises(ResidualPolarityStagingError, match="checksum"):
        parse_residual_polarity_staging_plan(bytes(payload))

    other = ThresholdNoGoodVault(
        active.identity,
        active.observed_variables,
        (ThresholdNoGoodClause((-1, -2, -3, 4, 5)),),
    )
    with pytest.raises(ResidualPolarityStagingError, match="source binding"):
        validate_residual_polarity_staging_plan(
            plan,
            active_vault=other,
            rank_decision=decision,  # type: ignore[arg-type]
        )
