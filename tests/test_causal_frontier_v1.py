from __future__ import annotations

import hashlib
import json

import pytest

from o1_crypto_lab.causal_frontier_v1 import (
    CAUSAL_FRONTIER_PLAN_MAGIC,
    CAUSAL_FRONTIER_PLAN_SCHEMA,
    CausalFrontierError,
    derive_causal_frontier_plan,
    parse_causal_frontier_plan,
    serialize_causal_frontier_plan,
    validate_causal_frontier_plan,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    observed_variables_sha256,
    vault_identity_from_sources,
)


def _vault(
    clauses: tuple[ThresholdNoGoodClause, ...],
    observed: tuple[int, ...] = (1, 2, 3, 4, 5, 6),
) -> ThresholdNoGoodVault:
    identity = vault_identity_from_sources(
        cnf_sha256="01" * 32,
        potential_sha256="23" * 32,
        grouping_sha256="45" * 32,
        observed_variables=observed,
        bound_rule="fixture-bound-v1",
        threshold=1.25,
    )
    assert identity.observed_variables_sha256 == observed_variables_sha256(observed)
    return ThresholdNoGoodVault(identity, observed, clauses)


def _source(signs: tuple[int, ...]) -> tuple[dict[str, object], str]:
    assignment = bytes(255 if sign == -1 else sign for sign in signs)
    source: dict[str, object] = {
        "schema": "fixture-result-v1",
        "sieve": {
            "state": {
                "schema": "o1-256-cadical-joint-score-sieve-grouped-state-v2",
                "encoding": ("observed-ascending-i8-sign;fixture-remaining-state"),
                "assignment_bytes": len(assignment),
                "assignment_hex": assignment.hex(),
                "assignment_sha256": hashlib.sha256(assignment).hexdigest(),
                "current_assigned_variables": sum(sign != 0 for sign in signs),
            }
        },
    }
    payload = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    return source, hashlib.sha256(payload).hexdigest()


def test_generic_derivation_round_trip_binds_exact_frontier() -> None:
    # Under +1, -2, and three unassigned values, the first clause is rescued,
    # the second is false/false with two residuals, and the third has three.
    vault = _vault(
        (
            ThresholdNoGoodClause((1, 2, -3)),
            ThresholdNoGoodClause((-1, 2, -4, 5)),
            ThresholdNoGoodClause((-1, 2, 3, -4, 6)),
        )
    )
    source, source_sha256 = _source((1, -1, 0, 0, 0, 0))
    plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=vault,
        selected_union_indices=(11, 17, 29),
    )

    assert plan.describe()["schema"] == CAUSAL_FRONTIER_PLAN_SCHEMA
    assert plan.selected_active_index == 1
    assert plan.selected_union_index == 17
    assert plan.false_literal_count == 2
    assert plan.true_literal_count == 0
    assert plan.unassigned_literal_count == 2
    assert plan.residual_clause_literals == (-4, 5)
    assert plan.falsifying_decision_literals == (4, -5)
    payload = serialize_causal_frontier_plan(plan)
    assert payload.startswith(CAUSAL_FRONTIER_PLAN_MAGIC)
    assert parse_causal_frontier_plan(payload, active_vault=vault) == plan
    assert plan.sha256 == hashlib.sha256(payload).hexdigest()


def test_tie_breaks_by_clause_sha_then_active_index_deterministically() -> None:
    clauses = (
        ThresholdNoGoodClause((-1, 3)),
        ThresholdNoGoodClause((-1, -4)),
        ThresholdNoGoodClause((-1, 5)),
    )
    vault = _vault(clauses)
    source, source_sha256 = _source((1, 0, 0, 0, 0, 0))
    expected = min(
        range(len(clauses)), key=lambda index: (1, clauses[index].sha256, index)
    )
    first = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=vault,
        selected_union_indices=(100, 101, 102),
    )
    second = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=vault,
        selected_union_indices=(100, 101, 102),
    )
    assert first.selected_active_index == expected
    assert first.serialized == second.serialized


def test_source_assignment_and_count_tampering_are_rejected() -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 3)),))
    source, source_sha256 = _source((1, 0, 0, 0, 0, 0))
    state = source["sieve"]["state"]  # type: ignore[index]
    assert isinstance(state, dict)
    state["assignment_hex"] = "00" + str(state["assignment_hex"])[2:]
    source_sha256 = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(CausalFrontierError, match="source assignment"):
        derive_causal_frontier_plan(
            source_result=source,
            source_result_sha256=source_sha256,
            active_vault=vault,
            selected_union_indices=(9,),
        )

    source, source_sha256 = _source((1, 0, 0, 0, 0, 0))
    state = source["sieve"]["state"]  # type: ignore[index]
    assert isinstance(state, dict)
    state["current_assigned_variables"] = 0
    source_sha256 = hashlib.sha256(
        json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(CausalFrontierError, match="assigned-variable"):
        derive_causal_frontier_plan(
            source_result=source,
            source_result_sha256=source_sha256,
            active_vault=vault,
            selected_union_indices=(9,),
        )


def test_binary_checksum_structure_and_active_binding_tamper_are_rejected() -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 3)),))
    source, source_sha256 = _source((1, 0, 0, 0, 0, 0))
    plan = derive_causal_frontier_plan(
        source_result=source,
        source_result_sha256=source_sha256,
        active_vault=vault,
        selected_union_indices=(9,),
    )
    payload = bytearray(plan.serialized)
    payload[-33] ^= 1
    with pytest.raises(CausalFrontierError, match="checksum"):
        parse_causal_frontier_plan(bytes(payload))
    with pytest.raises(CausalFrontierError, match="checksum|size"):
        parse_causal_frontier_plan(plan.serialized[:-1])

    other = _vault((ThresholdNoGoodClause((-1, -3)),))
    with pytest.raises(CausalFrontierError, match="active vault binding"):
        validate_causal_frontier_plan(plan, active_vault=other)


def test_source_bytes_bind_their_own_digest() -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 3)),))
    source, _ = _source((1, 0, 0, 0, 0, 0))
    payload = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    plan = derive_causal_frontier_plan(
        source_result=payload,
        active_vault=vault,
        selected_union_indices=(9,),
    )
    assert plan.source_result_sha256 == hashlib.sha256(payload).hexdigest()
    with pytest.raises(CausalFrontierError, match="source result hash"):
        derive_causal_frontier_plan(
            source_result=payload,
            source_result_sha256="00" * 32,
            active_vault=vault,
            selected_union_indices=(9,),
        )


def test_mapping_source_rejects_a_digest_not_of_the_used_content() -> None:
    vault = _vault((ThresholdNoGoodClause((-1, 3)),))
    source, _ = _source((1, 0, 0, 0, 0, 0))
    with pytest.raises(CausalFrontierError, match="source result hash"):
        derive_causal_frontier_plan(
            source_result=source,
            source_result_sha256="ab" * 32,
            active_vault=vault,
            selected_union_indices=(9,),
        )
