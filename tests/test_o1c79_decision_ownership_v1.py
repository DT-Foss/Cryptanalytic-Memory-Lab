from __future__ import annotations

import hashlib

import pytest

from o1_crypto_lab.decision_ownership_v1 import (
    DECISION_OWNERSHIP_SCHEMA,
    FOREIGN_NO_PROPOSAL,
    FOREIGN_NO_PROPOSAL_RELEASE,
    FOREIGN_OPPOSITE_SIGN,
    FOREIGN_OPPOSITE_SIGN_RELEASE,
    OWNED_SAME_SIGN_EAGER,
    OWNED_SAME_SIGN_NON_EAGER,
    OWNED_SAME_SIGN_RELEASE,
    OWNED_UNOBSERVED_RELEASE,
    DecisionOwnershipError,
    DecisionOwnershipLedger,
    DecisionOwnershipLimits,
    serialize_decision_ownership_snapshot,
)


def _legacy_unobserved_then_foreign_trace() -> DecisionOwnershipLedger:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(
        owner="v11-ranked-reader", literal=173, callback=1
    )
    level = ledger.notify_new_decision_level(
        callback=1, proposal_ordinal=proposal.ordinal
    )
    assert level.proposal_ordinal == proposal.ordinal

    # CaDiCaL may skip the +173 assignment notification before conflict.  The
    # proposal is nevertheless owned by level 1 through the decision
    # handshake, so backtracking releases that proposal without inventing an
    # assignment observation.
    first_backtrack = ledger.notify_backtrack(0, callback=1)
    assert first_backtrack.release_ordinals == (1,)

    # A later -173 assignment has no relationship to the retired +173
    # proposal.  The legacy returned-state/sign test would have conflated the
    # two; the typed ledger records and releases it as foreign.
    ledger.notify_new_decision_level(callback=2)
    observation = ledger.observe_assignment(-173, callback=2)
    assert observation.classification == FOREIGN_NO_PROPOSAL
    ledger.notify_backtrack(0, callback=2)
    return ledger


def _mandatory_end_to_end_reproducer() -> DecisionOwnershipLedger:
    ledger = DecisionOwnershipLedger()

    prefix = ledger.record_proposal(owner="PREFIX", literal=130, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=prefix.ordinal)
    ledger.notify_backtrack(0, callback=1)

    ledger.notify_new_decision_level(callback=2)
    foreign = ledger.observe_assignment(-130, callback=2)
    assert foreign.classification == FOREIGN_NO_PROPOSAL
    ledger.notify_backtrack(0, callback=2)

    rank = ledger.record_proposal(owner="RANK_ORIGINAL", literal=130, callback=3)
    ledger.notify_new_decision_level(callback=3, proposal_ordinal=rank.ordinal)
    confirmed = ledger.observe_assignment(
        130, callback=3, proposal_ordinal=rank.ordinal
    )
    assert confirmed.classification == OWNED_SAME_SIGN_EAGER
    ledger.notify_backtrack(0, callback=3)
    return ledger


def test_skipped_notification_releases_bound_proposal_before_foreign_opposite() -> None:
    ledger = _legacy_unobserved_then_foreign_trace()
    snapshot = ledger.snapshot()

    assert [release.classification for release in snapshot.releases] == [
        OWNED_UNOBSERVED_RELEASE,
        FOREIGN_NO_PROPOSAL_RELEASE,
    ]
    assert snapshot.releases[0].proposal_ordinal == 1
    assert snapshot.releases[0].assignment_observation_ordinal is None
    assert snapshot.releases[1].proposal_ordinal is None
    assert snapshot.releases[1].literal == -173
    proposal = snapshot.document()["proposals"][0]  # type: ignore[index]
    assert proposal["status"] == "released"  # type: ignore[index]
    assert proposal["release_ordinal"] == 1  # type: ignore[index]


def test_opposite_assignment_at_bound_level_is_foreign_not_a_silent_release() -> None:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(owner="v11-ranked-reader", literal=41, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=proposal.ordinal)

    with pytest.raises(DecisionOwnershipError, match="selected proposal"):
        ledger.observe_assignment(-41, callback=1, proposal_ordinal=proposal.ordinal)

    observation = ledger.observe_assignment(-41, callback=1)
    assert observation.classification == FOREIGN_OPPOSITE_SIGN
    assert observation.proposal_ordinal is None
    assert observation.opposite_sign_proposal_ordinals == (proposal.ordinal,)

    backtrack = ledger.notify_backtrack(0, callback=1)
    snapshot = ledger.snapshot()
    assert backtrack.release_ordinals == (1, 2)
    assert snapshot.releases[0].classification == FOREIGN_OPPOSITE_SIGN_RELEASE
    assert snapshot.releases[0].proposal_ordinal is None
    assert snapshot.releases[0].nonowning_proposal_ordinals == (proposal.ordinal,)
    assert snapshot.releases[1].classification == OWNED_UNOBSERVED_RELEASE
    assert snapshot.releases[1].proposal_ordinal == proposal.ordinal


def test_delayed_same_sign_notification_retains_exact_owned_level() -> None:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(owner="prefix-arbiter", literal=-97, callback=4)
    ledger.notify_new_decision_level(callback=4, proposal_ordinal=proposal.ordinal)

    observation = ledger.observe_assignment(
        -97, callback=7, proposal_ordinal=proposal.ordinal
    )
    assert observation.classification == OWNED_SAME_SIGN_NON_EAGER
    assert observation.callback_delay == 3
    assert observation.decision_level == 1

    ledger.notify_backtrack(0, callback=7)
    release = ledger.snapshot().releases[0]
    assert release.classification == OWNED_SAME_SIGN_RELEASE
    assert release.proposal_ordinal == proposal.ordinal
    assert release.literal == -97


def test_eager_same_sign_and_duplicate_notification_do_not_duplicate_trail() -> None:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(owner="frontier-reader", literal=23, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=proposal.ordinal)
    first = ledger.observe_assignment(23, callback=1)
    duplicate = ledger.observe_assignment(23, callback=1)

    assert first.classification == OWNED_SAME_SIGN_EAGER
    assert duplicate.origin_observation_ordinal == first.ordinal
    backtrack = ledger.notify_backtrack(0, callback=1)
    assert backtrack.release_ordinals == (1,)
    assert ledger.snapshot().releases[0].assignment_observation_ordinal == first.ordinal


def test_active_opposite_sign_and_live_bound_reproposal_are_rejected() -> None:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(owner="reader-a", literal=5, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=proposal.ordinal)

    with pytest.raises(DecisionOwnershipError, match="live bound decision"):
        ledger.record_proposal(owner="reader-b", literal=-5, callback=2)

    ledger.observe_assignment(5, callback=2)
    with pytest.raises(DecisionOwnershipError, match="without backtrack"):
        ledger.observe_assignment(-5, callback=2)


def test_canonical_snapshot_and_event_trace_are_byte_exact_and_bounded() -> None:
    left = _legacy_unobserved_then_foreign_trace().snapshot()
    right = _legacy_unobserved_then_foreign_trace().snapshot()
    payload = serialize_decision_ownership_snapshot(left)

    assert payload == right.serialized
    assert left.sha256 == right.sha256 == hashlib.sha256(payload).hexdigest()
    assert left.serialized_bytes == 3_841
    assert (
        left.sha256
        == "34a0c50e61e2e0be03da9c9a40f01ebaae0a3d48146c2f34dcbd45b658cd96a1"
    )
    assert left.document()["schema"] == DECISION_OWNERSHIP_SCHEMA
    telemetry = left.document()["telemetry"]
    assert isinstance(telemetry, dict)
    assert telemetry["event_trace_count"] == 8
    assert telemetry["event_trace_bytes"] == len(left.event_trace) == 362
    assert (
        telemetry["event_trace_sha256"] == hashlib.sha256(left.event_trace).hexdigest()
    )
    assert (
        telemetry["event_trace_sha256"]
        == "7f209c58845503d0bf593b7c34202f0c52509a282d4a217a65969934bf0087ac"
    )
    assert telemetry["bounded_event_trace_bytes"] >= len(left.event_trace)


def test_caps_fail_before_mutating_the_ledger() -> None:
    ledger = DecisionOwnershipLedger(
        DecisionOwnershipLimits(maximum_events=2, maximum_proposals=1)
    )
    proposal = ledger.record_proposal(owner="reader", literal=11, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=proposal.ordinal)
    before = ledger.snapshot().serialized

    with pytest.raises(DecisionOwnershipError, match="event cap"):
        ledger.observe_assignment(11, callback=1)
    assert ledger.snapshot().serialized == before


def test_proposal_must_bind_immediately_and_snapshot_fails_closed() -> None:
    ledger = DecisionOwnershipLedger()
    proposal = ledger.record_proposal(owner="PREFIX", literal=130, callback=1)

    with pytest.raises(DecisionOwnershipError, match="previous proposal"):
        ledger.record_proposal(owner="RANK_ORIGINAL", literal=131, callback=1)
    with pytest.raises(DecisionOwnershipError, match="pending proposal binding"):
        ledger.notify_new_decision_level(callback=1)
    with pytest.raises(DecisionOwnershipError, match="snapshot overlaps pending"):
        ledger.snapshot()

    transition = ledger.notify_new_decision_level(
        callback=1, proposal_ordinal=proposal.ordinal
    )
    assert transition.proposal_ordinal == proposal.ordinal
    ledger.notify_backtrack(0, callback=1)
    assert ledger.snapshot().document()["telemetry"]["proposal_count"] == 1  # type: ignore[index]


def test_mixed_backtrack_releases_deep_unobserved_before_shallow_observed() -> None:
    ledger = DecisionOwnershipLedger()
    shallow = ledger.record_proposal(owner="PREFIX", literal=11, callback=1)
    ledger.notify_new_decision_level(callback=1, proposal_ordinal=shallow.ordinal)
    ledger.observe_assignment(11, callback=1)
    deep = ledger.record_proposal(owner="RANK_ORIGINAL", literal=22, callback=2)
    ledger.notify_new_decision_level(callback=2, proposal_ordinal=deep.ordinal)

    backtrack = ledger.notify_backtrack(0, callback=2)
    releases = ledger.snapshot().releases
    assert backtrack.release_ordinals == (1, 2)
    assert [release.from_level for release in releases] == [2, 1]
    assert [release.classification for release in releases] == [
        OWNED_UNOBSERVED_RELEASE,
        OWNED_SAME_SIGN_RELEASE,
    ]
    assert [release.proposal_ordinal for release in releases] == [
        deep.ordinal,
        shallow.ordinal,
    ]


def test_mandatory_end_to_end_reproducer_is_terminal_and_deterministic() -> None:
    left = _mandatory_end_to_end_reproducer().snapshot()
    right = _mandatory_end_to_end_reproducer().snapshot()

    assert left.serialized == right.serialized
    assert left.event_trace == right.event_trace
    assert left.serialized_bytes == 5_157
    assert (
        left.sha256
        == "ba32ace4d839bf00daa35250dcc97ae9098a5dc5a1e1eaedbc54efdb99a118f9"
    )
    assert len(left.event_trace) == 591
    assert (
        hashlib.sha256(left.event_trace).hexdigest()
        == "de1396b25195a345dc7e9c7f3ffb35ab102a25ba514c9dd9e08cfdde9af94bc3"
    )
    assert left.current_level == 0
    assert left.active_assignments == ()
    assert [release.classification for release in left.releases] == [
        OWNED_UNOBSERVED_RELEASE,
        FOREIGN_NO_PROPOSAL_RELEASE,
        OWNED_SAME_SIGN_RELEASE,
    ]
    assert [release.proposal_ordinal for release in left.releases] == [1, None, 2]
    assert all(
        proposal["status"] == "released"
        for proposal in left.document()["proposals"]  # type: ignore[union-attr]
    )
