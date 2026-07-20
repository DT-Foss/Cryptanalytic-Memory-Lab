"""Bounded typed ownership for delayed external-decision notifications.

CaDiCaL assignment notifications are explicitly not necessarily eager.  A
historical callback return therefore cannot, by itself, prove ownership of a
later assignment on the same variable.  This module keeps proposals,
observed assignments, and releases as separate typed events and binds them
only through an exact same-sign proposal identity.

The implementation is intentionally solver-independent.  It is the compact
reference state machine for the equivalent native arbiter, with canonical
portable telemetry rather than Python object-size claims.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import struct
from typing import Sequence


DECISION_OWNERSHIP_SCHEMA = "o1-decision-ownership-ledger-v1"
DECISION_OWNERSHIP_VERSION = 1
DECISION_OWNERSHIP_EVENT_TRACE_ENCODING = (
    "typed-little-endian-v1;proposal-owner-length-prefixed-ascii;"
    "proposal-to-new-level-binding;"
    "assignment-exact-same-and-opposite-proposal-ordinals;"
    "backtrack-followed-by-release-records"
)
DECISION_OWNERSHIP_BOUNDED_STATE_RULE = (
    "portable-state-only;positive-explicit-caps-on-proposals-observations-"
    "releases-levels-backtracks-events-active-assignments-related-proposals-"
    "and-owner-bytes;no-host-object-size-claim"
)

OWNED_SAME_SIGN_EAGER = "owned-same-sign-eager"
OWNED_SAME_SIGN_NON_EAGER = "owned-same-sign-non-eager"
FOREIGN_AMBIGUOUS_SAME_SIGN = "foreign-ambiguous-same-sign"
FOREIGN_OPPOSITE_SIGN = "foreign-opposite-sign"
FOREIGN_NO_PROPOSAL = "foreign-no-proposal"
DUPLICATE_SAME_SIGN = "duplicate-same-sign"

OWNED_SAME_SIGN_RELEASE = "owned-same-sign-release"
OWNED_UNOBSERVED_RELEASE = "owned-unobserved-release"
FOREIGN_AMBIGUOUS_SAME_SIGN_RELEASE = "foreign-ambiguous-same-sign-release"
FOREIGN_OPPOSITE_SIGN_RELEASE = "foreign-opposite-sign-release"
FOREIGN_NO_PROPOSAL_RELEASE = "foreign-no-proposal-release"

_ASSIGNMENT_CLASSIFICATIONS = (
    OWNED_SAME_SIGN_EAGER,
    OWNED_SAME_SIGN_NON_EAGER,
    FOREIGN_AMBIGUOUS_SAME_SIGN,
    FOREIGN_OPPOSITE_SIGN,
    FOREIGN_NO_PROPOSAL,
    DUPLICATE_SAME_SIGN,
)
_RELEASE_CLASSIFICATIONS = (
    OWNED_SAME_SIGN_RELEASE,
    OWNED_UNOBSERVED_RELEASE,
    FOREIGN_AMBIGUOUS_SAME_SIGN_RELEASE,
    FOREIGN_OPPOSITE_SIGN_RELEASE,
    FOREIGN_NO_PROPOSAL_RELEASE,
)
_ASSIGNMENT_CLASSIFICATION_CODE = {
    name: index + 1 for index, name in enumerate(_ASSIGNMENT_CLASSIFICATIONS)
}
_RELEASE_CLASSIFICATION_CODE = {
    name: index + 1 for index, name in enumerate(_RELEASE_CLASSIFICATIONS)
}

_EVENT_PROPOSAL = 1
_EVENT_ASSIGNMENT = 2
_EVENT_NEW_LEVEL = 3
_EVENT_BACKTRACK = 4
_EVENT_RELEASE = 5

_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_UINT16_MAX = (1 << 16) - 1
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1

_HARD_MAXIMUM_OWNER_BYTES = 256
_HARD_MAXIMUM_RECORDS = 16_777_216
_HARD_MAXIMUM_ACTIVE_ASSIGNMENTS = 1_600_000
_HARD_MAXIMUM_RELATED_PROPOSALS = 4_096


class DecisionOwnershipError(ValueError):
    """A ledger input, transition, bound, or internal relation differs."""


def _positive_bounded_int(value: object, maximum: int, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise DecisionOwnershipError(f"decision ownership {field} differs")
    return value


def _callback(value: object, *, allow_zero: bool) -> int:
    minimum = 0 if allow_zero else 1
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= _UINT64_MAX
    ):
        raise DecisionOwnershipError("decision ownership callback differs")
    return value


def _literal(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value in (0, _INT32_MIN)
        or not _INT32_MIN < value <= _INT32_MAX
    ):
        raise DecisionOwnershipError("decision ownership literal differs")
    return value


def _owner(value: object, maximum_bytes: int) -> str:
    if not isinstance(value, str):
        raise DecisionOwnershipError("decision ownership owner differs")
    try:
        payload = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DecisionOwnershipError("decision ownership owner differs") from exc
    if (
        not payload
        or len(payload) > maximum_bytes
        or any(
            not (
                48 <= byte <= 57
                or 65 <= byte <= 90
                or 97 <= byte <= 122
                or byte in b"._:-"
            )
            for byte in payload
        )
    ):
        raise DecisionOwnershipError("decision ownership owner differs")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DecisionOwnershipError(
            "decision ownership canonical serialization differs"
        ) from exc


def _ordinal_bytes(values: Sequence[int]) -> bytes:
    return b"".join(struct.pack("<Q", value) for value in values)


@dataclass(frozen=True, slots=True)
class DecisionOwnershipLimits:
    """Explicit portable caps for one ownership ledger."""

    maximum_proposals: int = 4_096
    maximum_observations: int = 4_096
    maximum_releases: int = 4_096
    maximum_level_transitions: int = 4_096
    maximum_backtracks: int = 4_096
    maximum_events: int = 24_576
    maximum_active_assignments: int = 4_096
    maximum_related_proposals: int = 64
    maximum_owner_bytes: int = 64

    def __post_init__(self) -> None:
        for value, maximum, field in (
            (self.maximum_proposals, _HARD_MAXIMUM_RECORDS, "proposal cap"),
            (
                self.maximum_observations,
                _HARD_MAXIMUM_RECORDS,
                "observation cap",
            ),
            (self.maximum_releases, _HARD_MAXIMUM_RECORDS, "release cap"),
            (
                self.maximum_level_transitions,
                _HARD_MAXIMUM_RECORDS,
                "level-transition cap",
            ),
            (self.maximum_backtracks, _HARD_MAXIMUM_RECORDS, "backtrack cap"),
            (self.maximum_events, _HARD_MAXIMUM_RECORDS, "event cap"),
            (
                self.maximum_active_assignments,
                _HARD_MAXIMUM_ACTIVE_ASSIGNMENTS,
                "active-assignment cap",
            ),
            (
                self.maximum_related_proposals,
                min(_UINT16_MAX, _HARD_MAXIMUM_RELATED_PROPOSALS),
                "related-proposal cap",
            ),
            (
                self.maximum_owner_bytes,
                min(_UINT16_MAX, _HARD_MAXIMUM_OWNER_BYTES),
                "owner-byte cap",
            ),
        ):
            _positive_bounded_int(value, maximum, field)

    def describe(self) -> dict[str, int]:
        return {
            "maximum_proposals": self.maximum_proposals,
            "maximum_observations": self.maximum_observations,
            "maximum_releases": self.maximum_releases,
            "maximum_level_transitions": self.maximum_level_transitions,
            "maximum_backtracks": self.maximum_backtracks,
            "maximum_events": self.maximum_events,
            "maximum_active_assignments": self.maximum_active_assignments,
            "maximum_related_proposals": self.maximum_related_proposals,
            "maximum_owner_bytes": self.maximum_owner_bytes,
        }

    @property
    def maximum_event_record_bytes(self) -> int:
        proposal = 31 + self.maximum_owner_bytes
        assignment = 62 + 8 * self.maximum_related_proposals
        release = 64 + 8 * self.maximum_related_proposals
        return max(proposal, assignment, release)

    @property
    def bounded_event_trace_bytes(self) -> int:
        return self.maximum_events * self.maximum_event_record_bytes


@dataclass(frozen=True, slots=True)
class DecisionProposal:
    """One typed literal proposal returned by one named reader callback."""

    ordinal: int
    event_ordinal: int
    owner: str
    literal: int
    callback: int


@dataclass(frozen=True, slots=True)
class AssignmentObservation:
    """One assignment notification and its exact proposal relationship."""

    ordinal: int
    event_ordinal: int
    literal: int
    callback: int
    decision_level: int
    classification: str
    proposal_ordinal: int | None
    callback_delay: int | None
    same_sign_proposal_ordinals: tuple[int, ...]
    opposite_sign_proposal_ordinals: tuple[int, ...]
    origin_observation_ordinal: int | None = None


@dataclass(frozen=True, slots=True)
class DecisionLevelTransition:
    """One solver notification that opens the next decision level."""

    ordinal: int
    event_ordinal: int
    callback: int
    new_level: int
    proposal_ordinal: int | None


@dataclass(frozen=True, slots=True)
class DecisionRelease:
    """One assignment removed by a typed backtrack transition."""

    ordinal: int
    event_ordinal: int
    backtrack_ordinal: int
    assignment_observation_ordinal: int | None
    literal: int
    callback: int
    from_level: int
    to_level: int
    classification: str
    proposal_ordinal: int | None
    nonowning_proposal_ordinals: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class BacktrackTransition:
    """One backtrack request plus the exact releases it produced."""

    ordinal: int
    event_ordinal: int
    callback: int
    from_level: int
    to_level: int
    release_ordinals: tuple[int, ...]


def _proposal_record(proposal: DecisionProposal) -> bytes:
    owner = proposal.owner.encode("ascii")
    return b"".join(
        (
            struct.pack(
                "<BQQQiH",
                _EVENT_PROPOSAL,
                proposal.event_ordinal,
                proposal.ordinal,
                proposal.callback,
                proposal.literal,
                len(owner),
            ),
            owner,
        )
    )


def _observation_record(observation: AssignmentObservation) -> bytes:
    proposal = observation.proposal_ordinal or 0
    delay = (
        observation.callback_delay
        if observation.callback_delay is not None
        else _UINT64_MAX
    )
    origin = observation.origin_observation_ordinal or 0
    same = observation.same_sign_proposal_ordinals
    opposite = observation.opposite_sign_proposal_ordinals
    return b"".join(
        (
            struct.pack(
                "<BQQQIiQBQQHH",
                _EVENT_ASSIGNMENT,
                observation.event_ordinal,
                observation.ordinal,
                observation.callback,
                observation.decision_level,
                observation.literal,
                proposal,
                _ASSIGNMENT_CLASSIFICATION_CODE[observation.classification],
                delay,
                origin,
                len(same),
                len(opposite),
            ),
            _ordinal_bytes(same),
            _ordinal_bytes(opposite),
        )
    )


def _level_record(transition: DecisionLevelTransition) -> bytes:
    return struct.pack(
        "<BQQIQ",
        _EVENT_NEW_LEVEL,
        transition.event_ordinal,
        transition.callback,
        transition.new_level,
        transition.proposal_ordinal or 0,
    )


def _backtrack_record(backtrack: BacktrackTransition) -> bytes:
    return struct.pack(
        "<BQQIIQ",
        _EVENT_BACKTRACK,
        backtrack.event_ordinal,
        backtrack.callback,
        backtrack.from_level,
        backtrack.to_level,
        len(backtrack.release_ordinals),
    )


def _release_record(release: DecisionRelease) -> bytes:
    nonowning = release.nonowning_proposal_ordinals
    return b"".join(
        (
            struct.pack(
                "<BQQQQiQIIQBH",
                _EVENT_RELEASE,
                release.event_ordinal,
                release.ordinal,
                release.backtrack_ordinal,
                release.assignment_observation_ordinal or 0,
                release.literal,
                release.callback,
                release.from_level,
                release.to_level,
                release.proposal_ordinal or 0,
                _RELEASE_CLASSIFICATION_CODE[release.classification],
                len(nonowning),
            ),
            _ordinal_bytes(nonowning),
        )
    )


@dataclass(frozen=True, slots=True)
class DecisionOwnershipSnapshot:
    """Immutable canonical projection of one complete live ledger state."""

    limits: DecisionOwnershipLimits
    current_level: int
    last_callback: int
    proposals: tuple[DecisionProposal, ...]
    observations: tuple[AssignmentObservation, ...]
    level_transitions: tuple[DecisionLevelTransition, ...]
    backtracks: tuple[BacktrackTransition, ...]
    releases: tuple[DecisionRelease, ...]
    active_assignments: tuple[tuple[int, int], ...]
    event_trace: bytes

    def __post_init__(self) -> None:
        _validate_snapshot(self)

    @property
    def serialized(self) -> bytes:
        return _canonical_json_bytes(self.document())

    @property
    def serialized_bytes(self) -> int:
        return len(self.serialized)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()

    def document(self) -> dict[str, object]:
        proposal_observations = {
            observation.proposal_ordinal: observation.ordinal
            for observation in self.observations
            if observation.proposal_ordinal is not None
            and observation.classification
            in (OWNED_SAME_SIGN_EAGER, OWNED_SAME_SIGN_NON_EAGER)
        }
        proposal_releases = {
            release.proposal_ordinal: release.ordinal
            for release in self.releases
            if release.proposal_ordinal is not None
        }
        proposal_levels = {
            transition.proposal_ordinal: transition.new_level
            for transition in self.level_transitions
            if transition.proposal_ordinal is not None
        }
        proposals: list[dict[str, object]] = []
        for proposal in self.proposals:
            observation_ordinal = proposal_observations.get(proposal.ordinal)
            release_ordinal = proposal_releases.get(proposal.ordinal)
            status = (
                "released"
                if release_ordinal is not None
                else "assignment-observed"
                if observation_ordinal is not None
                else "level-bound-unobserved"
                if proposal.ordinal in proposal_levels
                else "offered"
            )
            proposals.append(
                {
                    "ordinal": proposal.ordinal,
                    "event_ordinal": proposal.event_ordinal,
                    "owner": proposal.owner,
                    "literal": proposal.literal,
                    "callback": proposal.callback,
                    "status": status,
                    "assignment_observation_ordinal": observation_ordinal,
                    "bound_decision_level": proposal_levels.get(proposal.ordinal),
                    "release_ordinal": release_ordinal,
                }
            )
        observations = [
            {
                "ordinal": value.ordinal,
                "event_ordinal": value.event_ordinal,
                "literal": value.literal,
                "callback": value.callback,
                "decision_level": value.decision_level,
                "classification": value.classification,
                "proposal_ordinal": value.proposal_ordinal,
                "callback_delay": value.callback_delay,
                "same_sign_proposal_ordinals": list(value.same_sign_proposal_ordinals),
                "opposite_sign_proposal_ordinals": list(
                    value.opposite_sign_proposal_ordinals
                ),
                "origin_observation_ordinal": value.origin_observation_ordinal,
            }
            for value in self.observations
        ]
        levels = [
            {
                "ordinal": value.ordinal,
                "event_ordinal": value.event_ordinal,
                "callback": value.callback,
                "new_level": value.new_level,
                "proposal_ordinal": value.proposal_ordinal,
            }
            for value in self.level_transitions
        ]
        backtracks = [
            {
                "ordinal": value.ordinal,
                "event_ordinal": value.event_ordinal,
                "callback": value.callback,
                "from_level": value.from_level,
                "to_level": value.to_level,
                "release_ordinals": list(value.release_ordinals),
            }
            for value in self.backtracks
        ]
        releases = [
            {
                "ordinal": value.ordinal,
                "event_ordinal": value.event_ordinal,
                "backtrack_ordinal": value.backtrack_ordinal,
                "assignment_observation_ordinal": (
                    value.assignment_observation_ordinal
                ),
                "literal": value.literal,
                "callback": value.callback,
                "from_level": value.from_level,
                "to_level": value.to_level,
                "classification": value.classification,
                "proposal_ordinal": value.proposal_ordinal,
                "nonowning_proposal_ordinals": list(value.nonowning_proposal_ordinals),
            }
            for value in self.releases
        ]
        assignment_counts = Counter(
            observation.classification for observation in self.observations
        )
        release_counts = Counter(release.classification for release in self.releases)
        status_counts = Counter(value["status"] for value in proposals)
        event_count = (
            len(self.proposals)
            + len(self.observations)
            + len(self.level_transitions)
            + len(self.backtracks)
            + len(self.releases)
        )
        return {
            "schema": DECISION_OWNERSHIP_SCHEMA,
            "version": DECISION_OWNERSHIP_VERSION,
            "current_level": self.current_level,
            "last_callback": self.last_callback,
            "limits": self.limits.describe(),
            "proposals": proposals,
            "observations": observations,
            "level_transitions": levels,
            "backtracks": backtracks,
            "releases": releases,
            "active_assignments": [
                {
                    "variable": variable,
                    "origin_observation_ordinal": observation,
                }
                for variable, observation in self.active_assignments
            ],
            "telemetry": {
                "proposal_count": len(self.proposals),
                "proposal_status_counts": {
                    status: status_counts.get(status, 0)
                    for status in (
                        "offered",
                        "level-bound-unobserved",
                        "assignment-observed",
                        "released",
                    )
                },
                "observation_count": len(self.observations),
                "assignment_classification_counts": {
                    classification: assignment_counts.get(classification, 0)
                    for classification in _ASSIGNMENT_CLASSIFICATIONS
                },
                "non_eager_owned_assignment_count": assignment_counts.get(
                    OWNED_SAME_SIGN_NON_EAGER, 0
                ),
                "release_count": len(self.releases),
                "release_classification_counts": {
                    classification: release_counts.get(classification, 0)
                    for classification in _RELEASE_CLASSIFICATIONS
                },
                "level_transition_count": len(self.level_transitions),
                "proposal_level_binding_count": sum(
                    value.proposal_ordinal is not None
                    for value in self.level_transitions
                ),
                "backtrack_count": len(self.backtracks),
                "active_assignment_count": len(self.active_assignments),
                "event_trace_encoding": DECISION_OWNERSHIP_EVENT_TRACE_ENCODING,
                "event_trace_count": event_count,
                "event_trace_bytes": len(self.event_trace),
                "event_trace_hex": self.event_trace.hex(),
                "event_trace_sha256": hashlib.sha256(self.event_trace).hexdigest(),
                "bounded_state_rule": DECISION_OWNERSHIP_BOUNDED_STATE_RULE,
                "maximum_event_record_bytes": (self.limits.maximum_event_record_bytes),
                "bounded_event_trace_bytes": (self.limits.bounded_event_trace_bytes),
            },
        }

    def describe(self) -> dict[str, object]:
        return {
            **self.document(),
            "serialized_bytes": self.serialized_bytes,
            "sha256": self.sha256,
        }


def _event_trace(
    *,
    proposals: Sequence[DecisionProposal],
    observations: Sequence[AssignmentObservation],
    level_transitions: Sequence[DecisionLevelTransition],
    backtracks: Sequence[BacktrackTransition],
    releases: Sequence[DecisionRelease],
) -> bytes:
    records: list[tuple[int, bytes]] = []
    records.extend(
        (proposal.event_ordinal, _proposal_record(proposal)) for proposal in proposals
    )
    records.extend(
        (observation.event_ordinal, _observation_record(observation))
        for observation in observations
    )
    records.extend(
        (transition.event_ordinal, _level_record(transition))
        for transition in level_transitions
    )
    records.extend(
        (backtrack.event_ordinal, _backtrack_record(backtrack))
        for backtrack in backtracks
    )
    records.extend(
        (release.event_ordinal, _release_record(release)) for release in releases
    )
    records.sort(key=lambda item: item[0])
    return b"".join(record for _, record in records)


def _validate_snapshot(snapshot: DecisionOwnershipSnapshot) -> None:
    limits = snapshot.limits
    if (
        isinstance(snapshot.current_level, bool)
        or not isinstance(snapshot.current_level, int)
        or not 0 <= snapshot.current_level <= _UINT32_MAX
        or _callback(snapshot.last_callback, allow_zero=True) != snapshot.last_callback
        or len(snapshot.proposals) > limits.maximum_proposals
        or len(snapshot.observations) > limits.maximum_observations
        or len(snapshot.releases) > limits.maximum_releases
        or len(snapshot.level_transitions) > limits.maximum_level_transitions
        or len(snapshot.backtracks) > limits.maximum_backtracks
        or len(snapshot.active_assignments) > limits.maximum_active_assignments
    ):
        raise DecisionOwnershipError("decision ownership snapshot bound differs")
    typed_events: list[tuple[int, str]] = []
    event_callbacks: list[tuple[int, int]] = []
    for expected, proposal in enumerate(snapshot.proposals, 1):
        if (
            proposal.ordinal != expected
            or _owner(proposal.owner, limits.maximum_owner_bytes) != proposal.owner
            or _literal(proposal.literal) != proposal.literal
            or _callback(proposal.callback, allow_zero=False) != proposal.callback
        ):
            raise DecisionOwnershipError("decision ownership proposal differs")
        typed_events.append((proposal.event_ordinal, "proposal"))
        event_callbacks.append((proposal.event_ordinal, proposal.callback))
    proposal_count = len(snapshot.proposals)
    observations_by_ordinal: dict[int, AssignmentObservation] = {}
    for expected, observation in enumerate(snapshot.observations, 1):
        related = (
            observation.same_sign_proposal_ordinals
            + observation.opposite_sign_proposal_ordinals
        )
        if (
            observation.ordinal != expected
            or _literal(observation.literal) != observation.literal
            or _callback(observation.callback, allow_zero=True) != observation.callback
            or isinstance(observation.decision_level, bool)
            or not 0 <= observation.decision_level <= _UINT32_MAX
            or observation.classification not in _ASSIGNMENT_CLASSIFICATIONS
            or len(related) > limits.maximum_related_proposals
            or len(set(related)) != len(related)
            or any(not 1 <= value <= proposal_count for value in related)
            or (
                observation.proposal_ordinal is not None
                and not 1 <= observation.proposal_ordinal <= proposal_count
            )
            or (
                observation.callback_delay is not None
                and (
                    isinstance(observation.callback_delay, bool)
                    or not 0 <= observation.callback_delay <= _UINT64_MAX
                )
            )
            or (
                observation.origin_observation_ordinal is not None
                and not 1
                <= observation.origin_observation_ordinal
                < observation.ordinal
            )
        ):
            raise DecisionOwnershipError(
                "decision ownership assignment observation differs"
            )
        observations_by_ordinal[observation.ordinal] = observation
        typed_events.append((observation.event_ordinal, "observation"))
        event_callbacks.append((observation.event_ordinal, observation.callback))
    proposal_levels: dict[int, DecisionLevelTransition] = {}
    for expected, transition in enumerate(snapshot.level_transitions, 1):
        if (
            transition.ordinal != expected
            or _callback(transition.callback, allow_zero=True) != transition.callback
            or not 1 <= transition.new_level <= _UINT32_MAX
            or (
                transition.proposal_ordinal is not None
                and not 1 <= transition.proposal_ordinal <= proposal_count
            )
        ):
            raise DecisionOwnershipError("decision ownership level transition differs")
        if transition.proposal_ordinal is not None:
            proposal = snapshot.proposals[transition.proposal_ordinal - 1]
            if (
                transition.proposal_ordinal in proposal_levels
                or proposal.callback != transition.callback
                or proposal.event_ordinal >= transition.event_ordinal
            ):
                raise DecisionOwnershipError(
                    "decision ownership proposal-level binding differs"
                )
            proposal_levels[transition.proposal_ordinal] = transition
        typed_events.append((transition.event_ordinal, "level"))
        event_callbacks.append((transition.event_ordinal, transition.callback))
    if len(proposal_levels) != proposal_count:
        raise DecisionOwnershipError("decision ownership proposal is not level-bound")
    releases_by_ordinal: dict[int, DecisionRelease] = {}
    for expected, release in enumerate(snapshot.releases, 1):
        if (
            release.ordinal != expected
            or _literal(release.literal) != release.literal
            or _callback(release.callback, allow_zero=True) != release.callback
            or release.classification not in _RELEASE_CLASSIFICATIONS
            or not 0 <= release.to_level < release.from_level <= _UINT32_MAX
            or (
                release.assignment_observation_ordinal is not None
                and release.assignment_observation_ordinal
                not in observations_by_ordinal
            )
            or (
                release.proposal_ordinal is not None
                and not 1 <= release.proposal_ordinal <= proposal_count
            )
            or len(release.nonowning_proposal_ordinals)
            > limits.maximum_related_proposals
            or len(set(release.nonowning_proposal_ordinals))
            != len(release.nonowning_proposal_ordinals)
            or any(
                not 1 <= value <= proposal_count
                for value in release.nonowning_proposal_ordinals
            )
        ):
            raise DecisionOwnershipError("decision ownership release differs")
        releases_by_ordinal[release.ordinal] = release
        typed_events.append((release.event_ordinal, "release"))
        event_callbacks.append((release.event_ordinal, release.callback))
    for expected, backtrack in enumerate(snapshot.backtracks, 1):
        if (
            backtrack.ordinal != expected
            or _callback(backtrack.callback, allow_zero=True) != backtrack.callback
            or not 0 <= backtrack.to_level <= backtrack.from_level <= _UINT32_MAX
            or len(set(backtrack.release_ordinals)) != len(backtrack.release_ordinals)
            or any(
                value not in releases_by_ordinal for value in backtrack.release_ordinals
            )
            or any(
                releases_by_ordinal[value].backtrack_ordinal != backtrack.ordinal
                for value in backtrack.release_ordinals
            )
        ):
            raise DecisionOwnershipError("decision ownership backtrack differs")
        if (
            tuple(
                release.ordinal
                for release in snapshot.releases
                if release.backtrack_ordinal == backtrack.ordinal
            )
            != backtrack.release_ordinals
        ):
            raise DecisionOwnershipError(
                "decision ownership backtrack release sequence differs"
            )
        ordered_releases = tuple(
            releases_by_ordinal[value] for value in backtrack.release_ordinals
        )
        expected_releases = tuple(
            sorted(
                ordered_releases,
                key=lambda release: (
                    -release.from_level,
                    release.assignment_observation_ordinal is None,
                    -(
                        observations_by_ordinal[
                            release.assignment_observation_ordinal
                        ].event_ordinal
                        if release.assignment_observation_ordinal is not None
                        else release.proposal_ordinal or 0
                    ),
                ),
            )
        )
        if ordered_releases != expected_releases:
            raise DecisionOwnershipError(
                "decision ownership backtrack stack order differs"
            )
        typed_events.append((backtrack.event_ordinal, "backtrack"))
        event_callbacks.append((backtrack.event_ordinal, backtrack.callback))

    proposal_observations: dict[int, int] = {}
    for observation in snapshot.observations:
        same = observation.same_sign_proposal_ordinals
        opposite = observation.opposite_sign_proposal_ordinals
        if (
            same != tuple(sorted(same))
            or opposite != tuple(sorted(opposite))
            or any(
                snapshot.proposals[value - 1].literal != observation.literal
                or value not in proposal_levels
                for value in same
            )
            or any(
                snapshot.proposals[value - 1].literal != -observation.literal
                or value not in proposal_levels
                for value in opposite
            )
        ):
            raise DecisionOwnershipError(
                "decision ownership assignment candidate relation differs"
            )
        if observation.classification in (
            OWNED_SAME_SIGN_EAGER,
            OWNED_SAME_SIGN_NON_EAGER,
        ):
            proposal_ordinal = observation.proposal_ordinal
            if proposal_ordinal is None:
                raise DecisionOwnershipError(
                    "decision ownership owned observation differs"
                )
            proposal = snapshot.proposals[proposal_ordinal - 1]
            level = proposal_levels.get(proposal_ordinal)
            delay = observation.callback - proposal.callback
            if (
                proposal_ordinal not in same
                or proposal_ordinal in proposal_observations
                or level is None
                or observation.decision_level != level.new_level
                or observation.callback_delay != delay
                or delay < 0
                or (observation.classification == OWNED_SAME_SIGN_EAGER and delay != 0)
                or (
                    observation.classification == OWNED_SAME_SIGN_NON_EAGER
                    and delay == 0
                )
                or level.event_ordinal >= observation.event_ordinal
                or observation.origin_observation_ordinal is not None
            ):
                raise DecisionOwnershipError(
                    "decision ownership owned observation differs"
                )
            proposal_observations[proposal_ordinal] = observation.ordinal
        elif observation.classification == DUPLICATE_SAME_SIGN:
            origin = observations_by_ordinal.get(
                observation.origin_observation_ordinal or 0
            )
            if (
                origin is None
                or origin.literal != observation.literal
                or origin.event_ordinal >= observation.event_ordinal
                or observation.proposal_ordinal != origin.proposal_ordinal
                or observation.callback_delay is not None
                or same
                or opposite
            ):
                raise DecisionOwnershipError(
                    "decision ownership duplicate observation differs"
                )
        elif (
            observation.proposal_ordinal is not None
            or observation.callback_delay is not None
            or observation.origin_observation_ordinal is not None
            or (
                observation.classification == FOREIGN_AMBIGUOUS_SAME_SIGN
                and len(same) <= 1
            )
            or (
                observation.classification == FOREIGN_OPPOSITE_SIGN
                and (same or not opposite)
            )
            or (
                observation.classification == FOREIGN_NO_PROPOSAL and (same or opposite)
            )
        ):
            raise DecisionOwnershipError(
                "decision ownership foreign observation differs"
            )

    proposal_releases: dict[int, int] = {}
    released_observations: set[int] = set()
    release_mapping = {
        OWNED_SAME_SIGN_EAGER: OWNED_SAME_SIGN_RELEASE,
        OWNED_SAME_SIGN_NON_EAGER: OWNED_SAME_SIGN_RELEASE,
        FOREIGN_AMBIGUOUS_SAME_SIGN: FOREIGN_AMBIGUOUS_SAME_SIGN_RELEASE,
        FOREIGN_OPPOSITE_SIGN: FOREIGN_OPPOSITE_SIGN_RELEASE,
        FOREIGN_NO_PROPOSAL: FOREIGN_NO_PROPOSAL_RELEASE,
    }
    for release in snapshot.releases:
        backtrack = snapshot.backtracks[release.backtrack_ordinal - 1]
        if (
            backtrack.event_ordinal >= release.event_ordinal
            or release.callback != backtrack.callback
            or release.to_level != backtrack.to_level
        ):
            raise DecisionOwnershipError(
                "decision ownership release backtrack relation differs"
            )
        if release.classification == OWNED_UNOBSERVED_RELEASE:
            proposal_ordinal = release.proposal_ordinal
            if proposal_ordinal is None:
                raise DecisionOwnershipError(
                    "decision ownership unobserved release differs"
                )
            proposal = snapshot.proposals[proposal_ordinal - 1]
            level = proposal_levels.get(proposal_ordinal)
            if (
                release.assignment_observation_ordinal is not None
                or proposal_ordinal in proposal_observations
                or proposal_ordinal in proposal_releases
                or level is None
                or release.literal != proposal.literal
                or release.from_level != level.new_level
                or release.nonowning_proposal_ordinals
            ):
                raise DecisionOwnershipError(
                    "decision ownership unobserved release differs"
                )
            proposal_releases[proposal_ordinal] = release.ordinal
            continue
        observation_ordinal = release.assignment_observation_ordinal
        if observation_ordinal is None:
            raise DecisionOwnershipError("decision ownership observed release differs")
        observation = observations_by_ordinal[observation_ordinal]
        expected_nonowning = tuple(
            value
            for value in (
                observation.same_sign_proposal_ordinals
                + observation.opposite_sign_proposal_ordinals
            )
            if value != observation.proposal_ordinal
        )
        if (
            observation_ordinal in released_observations
            or release.classification != release_mapping.get(observation.classification)
            or release.literal != observation.literal
            or release.from_level != observation.decision_level
            or release.proposal_ordinal != observation.proposal_ordinal
            or release.nonowning_proposal_ordinals != expected_nonowning
        ):
            raise DecisionOwnershipError("decision ownership observed release differs")
        released_observations.add(observation_ordinal)
        if release.proposal_ordinal is not None:
            if release.proposal_ordinal in proposal_releases:
                raise DecisionOwnershipError(
                    "decision ownership proposal release is not unique"
                )
            proposal_releases[release.proposal_ordinal] = release.ordinal

    event_count = len(typed_events)
    ordered_callbacks = [
        callback for _, callback in sorted(event_callbacks, key=lambda item: item[0])
    ]
    if (
        event_count > limits.maximum_events
        or sorted(ordinal for ordinal, _ in typed_events)
        != list(range(1, event_count + 1))
        or ordered_callbacks != sorted(ordered_callbacks)
        or (ordered_callbacks[-1] if ordered_callbacks else 0) != snapshot.last_callback
        or snapshot.event_trace
        != _event_trace(
            proposals=snapshot.proposals,
            observations=snapshot.observations,
            level_transitions=snapshot.level_transitions,
            backtracks=snapshot.backtracks,
            releases=snapshot.releases,
        )
    ):
        raise DecisionOwnershipError("decision ownership event trace differs")

    ordered_events: list[tuple[int, str, object]] = []
    ordered_events.extend(
        (value.event_ordinal, "proposal", value) for value in snapshot.proposals
    )
    ordered_events.extend(
        (value.event_ordinal, "observation", value) for value in snapshot.observations
    )
    ordered_events.extend(
        (value.event_ordinal, "level", value) for value in snapshot.level_transitions
    )
    ordered_events.extend(
        (value.event_ordinal, "backtrack", value) for value in snapshot.backtracks
    )
    ordered_events.extend(
        (value.event_ordinal, "release", value) for value in snapshot.releases
    )
    ordered_events.sort(key=lambda item: item[0])
    replay_level = 0
    replay_active: dict[int, int] = {}
    replay_live_proposals: set[int] = set()
    for _, kind, value in ordered_events:
        if kind == "proposal":
            continue
        if kind == "level":
            if not isinstance(value, DecisionLevelTransition):
                raise DecisionOwnershipError(
                    "decision ownership lifecycle type differs"
                )
            if value.new_level != replay_level + 1:
                raise DecisionOwnershipError(
                    "decision ownership lifecycle level differs"
                )
            if value.proposal_ordinal is not None:
                proposal = snapshot.proposals[value.proposal_ordinal - 1]
                if value.proposal_ordinal in replay_live_proposals or any(
                    abs(snapshot.proposals[ordinal - 1].literal)
                    == abs(proposal.literal)
                    for ordinal in replay_live_proposals
                ):
                    raise DecisionOwnershipError(
                        "decision ownership live proposal differs"
                    )
                replay_live_proposals.add(value.proposal_ordinal)
            replay_level = value.new_level
            continue
        if kind == "observation":
            if not isinstance(value, AssignmentObservation):
                raise DecisionOwnershipError(
                    "decision ownership lifecycle type differs"
                )
            variable = abs(value.literal)
            if value.classification == DUPLICATE_SAME_SIGN:
                if replay_active.get(variable) != value.origin_observation_ordinal:
                    raise DecisionOwnershipError(
                        "decision ownership duplicate lifecycle differs"
                    )
            elif variable in replay_active or value.decision_level > replay_level:
                raise DecisionOwnershipError(
                    "decision ownership assignment lifecycle differs"
                )
            else:
                replay_active[variable] = value.ordinal
            continue
        if kind == "backtrack":
            if not isinstance(value, BacktrackTransition):
                raise DecisionOwnershipError(
                    "decision ownership lifecycle type differs"
                )
            if value.from_level != replay_level or value.to_level > replay_level:
                raise DecisionOwnershipError(
                    "decision ownership backtrack lifecycle differs"
                )
            replay_level = value.to_level
            continue
        if not isinstance(value, DecisionRelease):
            raise DecisionOwnershipError("decision ownership lifecycle type differs")
        if value.assignment_observation_ordinal is not None:
            variable = abs(value.literal)
            if replay_active.get(variable) != value.assignment_observation_ordinal:
                raise DecisionOwnershipError(
                    "decision ownership release lifecycle differs"
                )
            del replay_active[variable]
        if value.proposal_ordinal is not None:
            if value.proposal_ordinal not in replay_live_proposals:
                raise DecisionOwnershipError(
                    "decision ownership proposal lifecycle differs"
                )
            replay_live_proposals.remove(value.proposal_ordinal)
    if (
        replay_level != snapshot.current_level
        or tuple(sorted(replay_active.items())) != snapshot.active_assignments
        or any(
            proposal_levels[ordinal].new_level > snapshot.current_level
            for ordinal in replay_live_proposals
        )
    ):
        raise DecisionOwnershipError("decision ownership final lifecycle differs")

    active_variables: set[int] = set()
    active_observations: set[int] = set()
    for variable, observation_ordinal in snapshot.active_assignments:
        observation = observations_by_ordinal.get(observation_ordinal)
        if (
            isinstance(variable, bool)
            or not 1 <= variable <= _INT32_MAX
            or variable in active_variables
            or observation_ordinal in active_observations
            or observation is None
            or abs(observation.literal) != variable
            or observation.classification == DUPLICATE_SAME_SIGN
            or observation_ordinal in released_observations
        ):
            raise DecisionOwnershipError("decision ownership active assignment differs")
        active_variables.add(variable)
        active_observations.add(observation_ordinal)


class DecisionOwnershipLedger:
    """Mutable transition engine with immutable typed event outputs."""

    def __init__(self, limits: DecisionOwnershipLimits | None = None) -> None:
        self.limits = limits or DecisionOwnershipLimits()
        if not isinstance(self.limits, DecisionOwnershipLimits):
            raise DecisionOwnershipError("decision ownership limits differ")
        self._current_level = 0
        self._last_callback = 0
        self._event_count = 0
        self._proposals: list[DecisionProposal] = []
        self._observations: list[AssignmentObservation] = []
        self._level_transitions: list[DecisionLevelTransition] = []
        self._backtracks: list[BacktrackTransition] = []
        self._releases: list[DecisionRelease] = []
        self._active: dict[int, int] = {}
        self._trail: list[int] = []
        self._proposal_observation: dict[int, int] = {}
        self._proposal_release: dict[int, int] = {}
        self._proposal_level: dict[int, int] = {}
        self._level_proposal: dict[int, int] = {}
        self._owner_callbacks: set[tuple[str, int]] = set()
        self._pending_proposal: int | None = None

    @property
    def current_level(self) -> int:
        return self._current_level

    @property
    def last_callback(self) -> int:
        return self._last_callback

    def _accept_callback(self, value: object, *, allow_zero: bool) -> int:
        result = _callback(value, allow_zero=allow_zero)
        if result < self._last_callback:
            raise DecisionOwnershipError(
                "decision ownership callback chronology differs"
            )
        return result

    def _reserve_events(self, count: int) -> None:
        if self._event_count + count > self.limits.maximum_events:
            raise DecisionOwnershipError("decision ownership event cap exceeded")

    def _next_event(self) -> int:
        self._event_count += 1
        return self._event_count

    def _assignment_candidate_proposals(
        self, variable: int
    ) -> tuple[DecisionProposal, ...]:
        return tuple(
            proposal
            for proposal in self._proposals
            if abs(proposal.literal) == variable
            and proposal.ordinal in self._proposal_level
            and proposal.ordinal not in self._proposal_observation
            and proposal.ordinal not in self._proposal_release
        )

    def record_proposal(
        self, *, owner: str, literal: int, callback: int
    ) -> DecisionProposal:
        """Record one actually offered decision with its originating reader."""

        owner = _owner(owner, self.limits.maximum_owner_bytes)
        literal = _literal(literal)
        callback = self._accept_callback(callback, allow_zero=False)
        if len(self._proposals) >= self.limits.maximum_proposals:
            raise DecisionOwnershipError("decision ownership proposal cap exceeded")
        if self._pending_proposal is not None:
            raise DecisionOwnershipError(
                "decision ownership previous proposal is not level-bound"
            )
        if abs(literal) in self._active:
            raise DecisionOwnershipError(
                "decision ownership proposal targets an observed assignment"
            )
        if any(
            abs(proposal.literal) == abs(literal)
            and proposal.ordinal in self._proposal_level
            and proposal.ordinal not in self._proposal_release
            for proposal in self._proposals
        ):
            raise DecisionOwnershipError(
                "decision ownership proposal targets a live bound decision"
            )
        if (owner, callback) in self._owner_callbacks:
            raise DecisionOwnershipError(
                "decision ownership owner callback is not unique"
            )
        self._reserve_events(1)
        proposal = DecisionProposal(
            ordinal=len(self._proposals) + 1,
            event_ordinal=self._next_event(),
            owner=owner,
            literal=literal,
            callback=callback,
        )
        self._proposals.append(proposal)
        self._owner_callbacks.add((owner, callback))
        self._pending_proposal = proposal.ordinal
        self._last_callback = callback
        return proposal

    def notify_new_decision_level(
        self, *, callback: int, proposal_ordinal: int | None = None
    ) -> DecisionLevelTransition:
        """Advance one level and optionally bind its exact offered proposal.

        The explicit binding models CaDiCaL's
        ``ask_decision -> assume_decision -> notify_new_decision_level``
        handshake.  It survives a skipped assignment notification and can
        therefore be released as owned-but-unobserved without inspecting a
        later assignment's sign.
        """

        callback = self._accept_callback(callback, allow_zero=True)
        if self._current_level >= _UINT32_MAX:
            raise DecisionOwnershipError(
                "decision ownership decision level exceeds bound"
            )
        if len(self._level_transitions) >= self.limits.maximum_level_transitions:
            raise DecisionOwnershipError(
                "decision ownership level-transition cap exceeded"
            )
        if self._pending_proposal is not None:
            if proposal_ordinal != self._pending_proposal:
                raise DecisionOwnershipError(
                    "decision ownership pending proposal binding differs"
                )
        elif proposal_ordinal is not None:
            raise DecisionOwnershipError(
                "decision ownership level binding has no pending proposal"
            )
        if proposal_ordinal is not None:
            if (
                isinstance(proposal_ordinal, bool)
                or not isinstance(proposal_ordinal, int)
                or not 1 <= proposal_ordinal <= len(self._proposals)
            ):
                raise DecisionOwnershipError(
                    "decision ownership level proposal differs"
                )
            proposal = self._proposals[proposal_ordinal - 1]
            if (
                proposal.callback != callback
                or proposal.ordinal in self._proposal_level
                or proposal.ordinal in self._proposal_observation
                or proposal.ordinal in self._proposal_release
            ):
                raise DecisionOwnershipError(
                    "decision ownership level proposal binding differs"
                )
        self._reserve_events(1)
        transition = DecisionLevelTransition(
            ordinal=len(self._level_transitions) + 1,
            event_ordinal=self._next_event(),
            callback=callback,
            new_level=self._current_level + 1,
            proposal_ordinal=proposal_ordinal,
        )
        self._level_transitions.append(transition)
        if proposal_ordinal is not None:
            self._proposal_level[proposal_ordinal] = transition.new_level
            self._level_proposal[transition.new_level] = proposal_ordinal
            self._pending_proposal = None
        self._current_level = transition.new_level
        self._last_callback = callback
        return transition

    def observe_assignment(
        self,
        literal: int,
        *,
        callback: int,
        proposal_ordinal: int | None = None,
    ) -> AssignmentObservation:
        """Bind one notification only to an exact, available same-sign proposal.

        Passing ``proposal_ordinal`` is the strongest arbiter path.  Without
        it, exactly one same-sign outstanding proposal may be inferred; two
        or more are deliberately classified as foreign/ambiguous rather than
        guessed.
        """

        literal = _literal(literal)
        callback = self._accept_callback(callback, allow_zero=True)
        if len(self._observations) >= self.limits.maximum_observations:
            raise DecisionOwnershipError("decision ownership observation cap exceeded")
        variable = abs(literal)
        active_ordinal = self._active.get(variable)
        if active_ordinal is not None:
            origin = self._observations[active_ordinal - 1]
            if origin.literal != literal:
                raise DecisionOwnershipError(
                    "decision ownership assignment changed without backtrack"
                )
            if proposal_ordinal is not None:
                raise DecisionOwnershipError(
                    "decision ownership duplicate assignment selects a proposal"
                )
            self._reserve_events(1)
            duplicate = AssignmentObservation(
                ordinal=len(self._observations) + 1,
                event_ordinal=self._next_event(),
                literal=literal,
                callback=callback,
                decision_level=self._current_level,
                classification=DUPLICATE_SAME_SIGN,
                proposal_ordinal=origin.proposal_ordinal,
                callback_delay=None,
                same_sign_proposal_ordinals=(),
                opposite_sign_proposal_ordinals=(),
                origin_observation_ordinal=origin.ordinal,
            )
            self._observations.append(duplicate)
            self._last_callback = callback
            return duplicate

        outstanding = self._assignment_candidate_proposals(variable)
        same = tuple(
            proposal.ordinal for proposal in outstanding if proposal.literal == literal
        )
        opposite = tuple(
            proposal.ordinal for proposal in outstanding if proposal.literal == -literal
        )
        if len(same) + len(opposite) > self.limits.maximum_related_proposals:
            raise DecisionOwnershipError(
                "decision ownership related-proposal cap exceeded"
            )
        selected: DecisionProposal | None = None
        if proposal_ordinal is not None:
            if (
                isinstance(proposal_ordinal, bool)
                or not isinstance(proposal_ordinal, int)
                or proposal_ordinal not in same
            ):
                raise DecisionOwnershipError(
                    "decision ownership selected proposal differs"
                )
            selected = self._proposals[proposal_ordinal - 1]
        elif len(same) == 1:
            selected = self._proposals[same[0] - 1]

        delay: int | None = None
        if selected is not None:
            delay = callback - selected.callback
            classification = (
                OWNED_SAME_SIGN_EAGER if delay == 0 else OWNED_SAME_SIGN_NON_EAGER
            )
        elif len(same) > 1:
            classification = FOREIGN_AMBIGUOUS_SAME_SIGN
        elif opposite:
            classification = FOREIGN_OPPOSITE_SIGN
        else:
            classification = FOREIGN_NO_PROPOSAL
        if len(self._active) >= self.limits.maximum_active_assignments:
            raise DecisionOwnershipError(
                "decision ownership active-assignment cap exceeded"
            )
        self._reserve_events(1)
        observation = AssignmentObservation(
            ordinal=len(self._observations) + 1,
            event_ordinal=self._next_event(),
            literal=literal,
            callback=callback,
            decision_level=(
                self._proposal_level[selected.ordinal]
                if selected is not None
                else self._current_level
            ),
            classification=classification,
            proposal_ordinal=selected.ordinal if selected is not None else None,
            callback_delay=delay,
            same_sign_proposal_ordinals=same,
            opposite_sign_proposal_ordinals=opposite,
        )
        self._observations.append(observation)
        self._active[variable] = observation.ordinal
        self._trail.append(observation.ordinal)
        if selected is not None:
            self._proposal_observation[selected.ordinal] = observation.ordinal
        self._last_callback = callback
        return observation

    def notify_backtrack(self, new_level: int, *, callback: int) -> BacktrackTransition:
        """Remove the trail suffix and classify every release by provenance."""

        callback = self._accept_callback(callback, allow_zero=True)
        if (
            isinstance(new_level, bool)
            or not isinstance(new_level, int)
            or not 0 <= new_level <= self._current_level
        ):
            raise DecisionOwnershipError("decision ownership backtrack level differs")
        if len(self._backtracks) >= self.limits.maximum_backtracks:
            raise DecisionOwnershipError("decision ownership backtrack cap exceeded")
        if self._pending_proposal is not None:
            raise DecisionOwnershipError(
                "decision ownership backtrack overlaps pending proposal"
            )
        release_observations: list[AssignmentObservation] = []
        for ordinal in reversed(self._trail):
            observation = self._observations[ordinal - 1]
            if observation.decision_level <= new_level:
                break
            release_observations.append(observation)
        release_unobserved = sorted(
            (
                proposal
                for proposal in self._proposals
                if self._proposal_level.get(proposal.ordinal, 0) > new_level
                and proposal.ordinal not in self._proposal_observation
                and proposal.ordinal not in self._proposal_release
            ),
            key=lambda proposal: (
                -self._proposal_level[proposal.ordinal],
                -proposal.ordinal,
            ),
        )
        release_sequence: list[
            tuple[str, AssignmentObservation | DecisionProposal]
        ] = []
        release_order: list[
            tuple[int, int, int, str, AssignmentObservation | DecisionProposal]
        ] = []
        release_order.extend(
            (
                observation.decision_level,
                0,
                position,
                "observed",
                observation,
            )
            for position, observation in enumerate(release_observations)
        )
        release_order.extend(
            (
                self._proposal_level[proposal.ordinal],
                1,
                position,
                "unobserved",
                proposal,
            )
            for position, proposal in enumerate(release_unobserved)
        )
        release_order.sort(key=lambda value: (-value[0], value[1], value[2]))
        release_sequence.extend((kind, value) for _, _, _, kind, value in release_order)
        release_count = len(release_sequence)
        if len(self._releases) + release_count > self.limits.maximum_releases:
            raise DecisionOwnershipError("decision ownership release cap exceeded")
        self._reserve_events(1 + release_count)

        backtrack_ordinal = len(self._backtracks) + 1
        first_release_ordinal = len(self._releases) + 1
        release_ordinals = tuple(
            range(
                first_release_ordinal,
                first_release_ordinal + release_count,
            )
        )
        backtrack = BacktrackTransition(
            ordinal=backtrack_ordinal,
            event_ordinal=self._next_event(),
            callback=callback,
            from_level=self._current_level,
            to_level=new_level,
            release_ordinals=release_ordinals,
        )
        self._backtracks.append(backtrack)

        for (kind, value), release_ordinal in zip(
            release_sequence, release_ordinals, strict=True
        ):
            if kind == "observed":
                if not isinstance(value, AssignmentObservation):
                    raise DecisionOwnershipError(
                        "decision ownership observed release type differs"
                    )
                observation = value
                proposal_ordinal = observation.proposal_ordinal
                if observation.classification in (
                    OWNED_SAME_SIGN_EAGER,
                    OWNED_SAME_SIGN_NON_EAGER,
                ):
                    if proposal_ordinal is None:
                        raise DecisionOwnershipError(
                            "decision ownership owned proposal binding differs"
                        )
                    proposal = self._proposals[proposal_ordinal - 1]
                    if proposal.literal != observation.literal:
                        raise DecisionOwnershipError(
                            "decision ownership owned release sign differs"
                        )
                    classification = OWNED_SAME_SIGN_RELEASE
                elif observation.classification == FOREIGN_AMBIGUOUS_SAME_SIGN:
                    classification = FOREIGN_AMBIGUOUS_SAME_SIGN_RELEASE
                elif observation.classification == FOREIGN_OPPOSITE_SIGN:
                    classification = FOREIGN_OPPOSITE_SIGN_RELEASE
                elif observation.classification == FOREIGN_NO_PROPOSAL:
                    classification = FOREIGN_NO_PROPOSAL_RELEASE
                else:
                    raise DecisionOwnershipError(
                        "decision ownership release origin differs"
                    )
                nonowning = tuple(
                    ordinal
                    for ordinal in (
                        observation.same_sign_proposal_ordinals
                        + observation.opposite_sign_proposal_ordinals
                    )
                    if ordinal != proposal_ordinal
                )
                release = DecisionRelease(
                    ordinal=release_ordinal,
                    event_ordinal=self._next_event(),
                    backtrack_ordinal=backtrack.ordinal,
                    assignment_observation_ordinal=observation.ordinal,
                    literal=observation.literal,
                    callback=callback,
                    from_level=observation.decision_level,
                    to_level=new_level,
                    classification=classification,
                    proposal_ordinal=proposal_ordinal,
                    nonowning_proposal_ordinals=nonowning,
                )
                self._releases.append(release)
                del self._active[abs(observation.literal)]
                if proposal_ordinal is not None:
                    self._proposal_release[proposal_ordinal] = release.ordinal
                continue

            if kind != "unobserved" or not isinstance(value, DecisionProposal):
                raise DecisionOwnershipError(
                    "decision ownership unobserved release type differs"
                )
            proposal = value
            bound_level = self._proposal_level[proposal.ordinal]
            release = DecisionRelease(
                ordinal=release_ordinal,
                event_ordinal=self._next_event(),
                backtrack_ordinal=backtrack.ordinal,
                assignment_observation_ordinal=None,
                literal=proposal.literal,
                callback=callback,
                from_level=bound_level,
                to_level=new_level,
                classification=OWNED_UNOBSERVED_RELEASE,
                proposal_ordinal=proposal.ordinal,
                nonowning_proposal_ordinals=(),
            )
            self._releases.append(release)
            self._proposal_release[proposal.ordinal] = release.ordinal

        if release_observations:
            del self._trail[-len(release_observations) :]
        for level in tuple(self._level_proposal):
            if level > new_level:
                del self._level_proposal[level]
        self._current_level = new_level
        self._last_callback = callback
        return backtrack

    def snapshot(self) -> DecisionOwnershipSnapshot:
        """Freeze, validate, and return the canonical current ledger."""

        if self._pending_proposal is not None:
            raise DecisionOwnershipError(
                "decision ownership snapshot overlaps pending proposal"
            )
        trace = _event_trace(
            proposals=self._proposals,
            observations=self._observations,
            level_transitions=self._level_transitions,
            backtracks=self._backtracks,
            releases=self._releases,
        )
        return DecisionOwnershipSnapshot(
            limits=self.limits,
            current_level=self._current_level,
            last_callback=self._last_callback,
            proposals=tuple(self._proposals),
            observations=tuple(self._observations),
            level_transitions=tuple(self._level_transitions),
            backtracks=tuple(self._backtracks),
            releases=tuple(self._releases),
            active_assignments=tuple(sorted(self._active.items())),
            event_trace=trace,
        )


def serialize_decision_ownership_snapshot(
    snapshot: DecisionOwnershipSnapshot,
) -> bytes:
    """Return canonical ASCII JSON for one already-validated snapshot."""

    if not isinstance(snapshot, DecisionOwnershipSnapshot):
        raise DecisionOwnershipError("decision ownership snapshot differs")
    _validate_snapshot(snapshot)
    return snapshot.serialized


__all__ = [
    "AssignmentObservation",
    "BacktrackTransition",
    "DECISION_OWNERSHIP_BOUNDED_STATE_RULE",
    "DECISION_OWNERSHIP_EVENT_TRACE_ENCODING",
    "DECISION_OWNERSHIP_SCHEMA",
    "DECISION_OWNERSHIP_VERSION",
    "DUPLICATE_SAME_SIGN",
    "DecisionLevelTransition",
    "DecisionOwnershipError",
    "DecisionOwnershipLedger",
    "DecisionOwnershipLimits",
    "DecisionOwnershipSnapshot",
    "DecisionProposal",
    "DecisionRelease",
    "FOREIGN_AMBIGUOUS_SAME_SIGN",
    "FOREIGN_AMBIGUOUS_SAME_SIGN_RELEASE",
    "FOREIGN_NO_PROPOSAL",
    "FOREIGN_NO_PROPOSAL_RELEASE",
    "FOREIGN_OPPOSITE_SIGN",
    "FOREIGN_OPPOSITE_SIGN_RELEASE",
    "OWNED_SAME_SIGN_EAGER",
    "OWNED_SAME_SIGN_NON_EAGER",
    "OWNED_SAME_SIGN_RELEASE",
    "serialize_decision_ownership_snapshot",
]
