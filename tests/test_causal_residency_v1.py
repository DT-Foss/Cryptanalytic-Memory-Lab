from __future__ import annotations

import copy
import hashlib
import struct
from typing import cast

import pytest

from o1_crypto_lab.causal_attic_v1 import (
    ClauseOccurrence,
    reproject_causal_attic,
)
from o1_crypto_lab.causal_residency_v1 import (
    ACTIVATION_LEDGER_SCHEMA,
    CAUSAL_RESIDENCY_SCHEMA,
    RESIDENCY_PROJECTION_SCHEMA,
    CausalResidencyError,
    advance_causal_residency,
    initialize_causal_residency,
    replay_causal_residency,
    reproject_causal_residency,
    validate_activation_replay,
)
from o1_crypto_lab.threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    vault_identity_from_sources,
)


OBSERVED = tuple(range(1, 17))
IDENTITY = vault_identity_from_sources(
    cnf_sha256="01" * 32,
    potential_sha256="23" * 32,
    grouping_sha256="45" * 32,
    observed_variables=OBSERVED,
    bound_rule="causal-residency-test-bound-v1",
    threshold=7.5,
)


def _occurrence(
    stream: str,
    index: int,
    clause: ThresholdNoGoodClause,
    *,
    classification: str = "new",
    score: float | None = None,
) -> ClauseOccurrence:
    witness = struct.pack("<d", score if score is not None else 2.0 + index)
    return ClauseOccurrence(
        stream_id=stream,
        source_index=index,
        classification=classification,
        source="trail_upper_bound",
        witness_score_f64le_hex=witness.hex(),
        clause=clause,
        clause_sha256=clause.sha256,
        witness_sha256=hashlib.sha256(
            b"\x01" + witness + clause.serialized
        ).hexdigest(),
    )


def _attic(
    clauses: tuple[ThresholdNoGoodClause, ...], *, active_limit: int
):
    vault = ThresholdNoGoodVault(IDENTITY, OBSERVED, clauses)
    occurrences = tuple(
        _occurrence("genesis", index, clause)
        for index, clause in enumerate(clauses)
    )
    return reproject_causal_attic(
        (vault,), occurrences, active_limit=active_limit
    )


def test_initial_page_pins_core_then_serves_debt_and_serializes_union_order() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),  # dominated by index 0
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
        ThresholdNoGoodClause((-6, 7)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )

    assert state.pinned_core_indices == (0, 2)
    assert state.inherited_debt_indices == (5, 6)
    assert state.current_projection.structural_root_indices == (0,)
    assert state.current_projection.pinned_core_indices == (2,)
    assert set(state.current_projection.inherited_debt_indices) == {5, 6}
    assert state.current_projection.new_debt_indices == ()
    assert state.current_projection.hot_event_indices == ()
    assert state.current_projection.recycled_indices == ()
    assert state.current_projection.selected_union_indices == (0, 2, 5, 6)
    assert state.active_projection.clauses == tuple(
        clauses[index] for index in (0, 2, 5, 6)
    )
    assert state.activation_counts == (2, 0, 2, 1, 1, 1, 1)
    assert state.last_active_lineages == (14, None, 14, 13, 13, 14, 14)
    assert len(set(state.used_active_sha256)) == 2
    assert state.describe()["schema"] == CAUSAL_RESIDENCY_SCHEMA
    assert (
        state.current_projection.describe()["schema"]
        == RESIDENCY_PROJECTION_SCHEMA
    )
    assert (
        state.activation_ledger_document()["schema"]
        == ACTIVATION_LEDGER_SCHEMA
    )
    validate_activation_replay(state)


def test_zero_event_page_recycles_least_used_oldest_before_newer() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
        ThresholdNoGoodClause((-6, 7)),
    )
    attic = _attic(clauses, active_limit=4)
    page1 = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )
    page2 = reproject_causal_residency(
        attic,
        previous_state=page1,
        fully_emitted_union_indices=(),
        next_lineage_ordinal=15,
    )

    assert page2.never_resident_undominated_indices == ()
    assert page2.current_projection.structural_root_indices == (0,)
    assert page2.current_projection.pinned_core_indices == (2,)
    # The strict oldest page would repeat the inherited parent SHA, so the
    # deterministic collision escape exchanges its lowest-priority tail.
    assert page2.current_projection.recycled_indices == (4, 5)
    assert page2.current_projection.selected_union_indices == (0, 2, 4, 5)
    assert len(set(page2.used_active_sha256)) == 3


def test_inherited_debt_precedes_duplicate_hot_attention() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
        ThresholdNoGoodClause((-6, 7)),
        ThresholdNoGoodClause((-7, 8)),
        ThresholdNoGoodClause((-8, 9)),
        ThresholdNoGoodClause((-9, 10)),
        ThresholdNoGoodClause((-10, 11)),
    )
    attic = _attic(clauses, active_limit=5)
    page1 = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4, 5),
        inherited_event_indices=(2,),
        active_limit=5,
    )
    assert len(page1.never_resident_undominated_indices) == 2

    page2 = reproject_causal_residency(
        attic,
        previous_state=page1,
        fully_emitted_union_indices=(3,),
        next_lineage_ordinal=15,
    )
    assert len(page2.current_projection.inherited_debt_indices) == 2
    assert page2.current_projection.hot_event_indices == (3,)
    assert page2.never_resident_undominated_indices == ()


def test_append_preserves_all_evidence_and_promotes_new_structural_root() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )
    new_clause = ThresholdNoGoodClause((-5,))
    chunk = ThresholdNoGoodVault(IDENTITY, OBSERVED, (new_clause,))
    occurrence = _occurrence("episode-00", 0, new_clause, score=9.0)

    advanced = advance_causal_residency(
        state,
        chunk=chunk,
        occurrences=(occurrence,),
        next_lineage_ordinal=15,
    )

    assert advanced.attic.chunks == (*attic.chunks, chunk)
    assert advanced.attic.occurrences == (*attic.occurrences, occurrence)
    assert advanced.attic.union_vault.clauses[: len(clauses)] == clauses
    assert advanced.structural_root_indices == (0, 6)
    assert 6 in advanced.current_projection.structural_root_indices
    assert 5 not in advanced.attic.undominated_indices
    assert len(advanced.activation_counts) == len(clauses) + 1
    validate_activation_replay(advanced)


def test_advance_can_lower_only_the_next_active_limit() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )
    new_clause = ThresholdNoGoodClause((-6, 7))
    chunk = ThresholdNoGoodVault(IDENTITY, OBSERVED, (new_clause,))
    occurrence = _occurrence("episode-00", 0, new_clause, score=9.0)

    advanced = advance_causal_residency(
        state,
        chunk=chunk,
        occurrences=(occurrence,),
        next_lineage_ordinal=15,
        next_active_limit=3,
    )

    assert advanced.active_limit == 3
    assert advanced.attic.active_limit == 3
    assert advanced.active_projection.clause_count == 3
    assert advanced.activation_ledger[:-1] == state.activation_ledger
    assert advanced.used_active_sha256[:-1] == state.used_active_sha256
    assert advanced.attic.chunks == (*attic.chunks, chunk)
    assert advanced.attic.occurrences == (*attic.occurrences, occurrence)
    assert advanced.attic.union_vault.clauses[: len(clauses)] == clauses
    validate_activation_replay(advanced)
    assert replay_causal_residency(advanced.attic, advanced.describe()) == advanced


def test_direct_reprojection_can_lower_only_the_next_active_limit() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )

    projected = reproject_causal_residency(
        attic,
        previous_state=state,
        fully_emitted_union_indices=(),
        next_lineage_ordinal=15,
        next_active_limit=3,
    )

    assert projected.active_limit == 3
    assert projected.attic.active_limit == 3
    assert projected.active_projection.clause_count == 3
    assert projected.activation_ledger[:-1] == state.activation_ledger
    assert projected.used_active_sha256[:-1] == state.used_active_sha256
    assert projected.attic.chunks == attic.chunks
    assert projected.attic.occurrences == attic.occurrences
    assert projected.attic.union_vault == attic.union_vault
    validate_activation_replay(projected)


@pytest.mark.parametrize("bad_limit", (True, 0, 513))
def test_next_active_limit_rejects_invalid_values(bad_limit: object) -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )
    chunk = ThresholdNoGoodVault(
        IDENTITY,
        OBSERVED,
        (ThresholdNoGoodClause((-6, 7)),),
    )
    occurrence = _occurrence("episode-00", 0, chunk.clauses[0], score=9.0)

    with pytest.raises(CausalResidencyError, match="active limit"):
        advance_causal_residency(
            state,
            chunk=chunk,
            occurrences=(occurrence,),
            next_lineage_ordinal=15,
            next_active_limit=cast(int, bad_limit),
        )
    with pytest.raises(CausalResidencyError, match="active limit"):
        reproject_causal_residency(
            attic,
            previous_state=state,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=15,
            next_active_limit=cast(int, bad_limit),
        )


def test_omitted_next_active_limit_preserves_legacy_projection() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
        ThresholdNoGoodClause((-5, 6)),
        ThresholdNoGoodClause((-6, 7)),
    )
    attic = _attic(clauses, active_limit=4)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3, 4),
        inherited_event_indices=(2,),
        active_limit=4,
    )

    legacy = reproject_causal_residency(
        attic,
        previous_state=state,
        fully_emitted_union_indices=(),
        next_lineage_ordinal=15,
    )
    explicit = reproject_causal_residency(
        attic,
        previous_state=state,
        fully_emitted_union_indices=(),
        next_lineage_ordinal=15,
        next_active_limit=state.active_limit,
    )

    assert legacy == explicit


def test_complete_description_round_trips_and_tamper_is_rejected() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
    )
    attic = _attic(clauses, active_limit=3)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3),
        inherited_event_indices=(2,),
        active_limit=3,
    )
    document = state.describe()
    replayed = replay_causal_residency(attic, document)
    assert replayed == state
    assert replayed.describe() == document

    tampered = copy.deepcopy(document)
    ledger = cast(dict[str, object], tampered["activation_ledger"])
    entries = cast(list[dict[str, object]], ledger["entries"])
    entries[-1]["active_sha256"] = "00" * 32
    with pytest.raises(CausalResidencyError, match="ledger entry|identit"):
        replay_causal_residency(attic, tampered)


def test_fail_closed_when_mandatory_core_cannot_fit_or_page_would_repeat() -> None:
    two_roots = _attic(
        (
            ThresholdNoGoodClause((1,)),
            ThresholdNoGoodClause((1, 2)),
            ThresholdNoGoodClause((-3,)),
            ThresholdNoGoodClause((-3, 4)),
        ),
        active_limit=2,
    )
    with pytest.raises(CausalResidencyError, match="core exceeds"):
        initialize_causal_residency(
            two_roots,
            parent_active_indices=(0,),
            inherited_event_indices=(),
            active_limit=1,
        )

    exact_page = _attic(
        (
            ThresholdNoGoodClause((1,)),
            ThresholdNoGoodClause((1, 2)),
            ThresholdNoGoodClause((-2, 3)),
        ),
        active_limit=2,
    )
    with pytest.raises(CausalResidencyError, match="no unused"):
        initialize_causal_residency(
            exact_page,
            parent_active_indices=(0, 2),
            inherited_event_indices=(2,),
            active_limit=2,
        )


def test_reprojection_rejects_evidence_rewrite_and_bad_lineage() -> None:
    clauses = (
        ThresholdNoGoodClause((1,)),
        ThresholdNoGoodClause((1, 2)),
        ThresholdNoGoodClause((-2, 3)),
        ThresholdNoGoodClause((-3, 4)),
        ThresholdNoGoodClause((-4, 5)),
    )
    attic = _attic(clauses, active_limit=3)
    state = initialize_causal_residency(
        attic,
        parent_active_indices=(0, 2, 3),
        inherited_event_indices=(2,),
        active_limit=3,
    )
    with pytest.raises(CausalResidencyError, match="next lineage"):
        reproject_causal_residency(
            attic,
            previous_state=state,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=14,
        )

    rewritten = _attic(tuple(reversed(clauses)), active_limit=3)
    with pytest.raises(CausalResidencyError, match="rewrites evidence"):
        reproject_causal_residency(
            rewritten,
            previous_state=state,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=15,
        )
