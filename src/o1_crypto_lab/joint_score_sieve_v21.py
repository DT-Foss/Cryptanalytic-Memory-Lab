"""Fail-closed O1C-0080 exact one-bit child-bound telemetry adapter.

The native reader is proof producing only when a selected losing child is
observed by CaDiCaL and the unchanged v6 propagator independently records the
matching strict-threshold prune and canonical no-good lifecycle.  This module
validates that chain without treating a probe or a proposal as science gain.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import joint_score_sieve_v20 as _v20
from .o1_relational_search import O1RelationalSearchError


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v21-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v18"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v20.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
ONE_BIT_BOUND_READER_SCHEMA = "o1-256-exact-one-bit-child-bound-reader-v1"
DECISION_OWNERSHIP_SCHEMA = "o1-256-central-decision-ownership-v2"
CENTRAL_READER_SCHEMA = "o1-256-central-composed-reader-v2"
BOUND_ORIGIN = "BOUND_LOSING_CHILD"

CENTRAL_OPERATOR = (
    "single-owner-bound-losing-child-prefix-rank-original-rank-contrast-"
    "frontier-initial-frontier-contrast-over-unchanged-v6"
)
CENTRAL_SELECTION_RULE = (
    "BOUND_LOSING_CHILD-reconsider-every-parent;PREFIX-until-consumed;"
    "RANK_ORIGINAL-until-consumed;released-RANK_CONTRAST;FRONTIER_INITIAL-"
    "until-consumed;released-FRONTIER_CONTRAST;base-zero"
)
CENTRAL_RELEASE_RULE = _v20.CENTRAL_RELEASE_RULE

ONE_BIT_BOUND_OPERATOR = "same-parent-exact-one-bit-U0-U1-losing-child-selector"
ONE_BIT_CANDIDATE_ORDER_RULE = (
    "effective-rank-order-then-omitted-key-variables-ascending;unassigned-"
    "coordinates-reconsidered-at-every-parent"
)
ONE_BIT_BOUND_RULE = (
    "copied-parent-assignment;same-v6-compatibility-groups;bit0-spin-minus1-"
    "literal-minus-v;bit1-spin-plus1-literal-plus-v;upward-exact-sum"
)
ONE_BIT_DECISION_RULE = (
    "strict-U-less-than-tau;equality-live;one-dead-propose-losing-child;both-"
    "dead-propose-lower-U;exact-tie-bit0"
)
ONE_BIT_REALIZED_PRUNE_RULE = (
    "matching-bound-token-and-losing-assignment-plus-v6-threshold-prune-"
    "trail-prune-queued-canonical-no-good-lifecycle"
)
SIGNED_I32_SEQUENCE_ENCODING = "concatenated-signed-i32le-literals"
PROBE_TRACE_ENCODING = (
    "u64le-call;u64le-probe;u32le-coordinate;u32le-parent-level;i32le-variable;"
    "f64le-U0;f64le-U1;f64le-tau;u8-selection;i32le-losing-literal"
)
MINIMUM_WITNESS_TIE_RULE = (
    "smaller-min-U0-U1;then-smaller-call;then-smaller-coordinate-index;then-"
    "smaller-variable"
)
_PROBE_TRACE_RECORD_BYTES = 57

SELECTION_CLASSES = {
    "NEITHER_PRUNABLE",
    "ZERO_PRUNABLE",
    "ONE_PRUNABLE",
    "BOTH_PRUNABLE",
}

ORIGINS = (*_v20.ORIGINS, BOUND_ORIGIN)
EVENT_KINDS = _v20.EVENT_KINDS
OWNERSHIP_LIFECYCLE = _v20.OWNERSHIP_LIFECYCLE
OWNERSHIP_ELIGIBILITY_RULE = _v20.OWNERSHIP_ELIGIBILITY_RULE
OWNERSHIP_ASSIGNMENT_RULE = _v20.OWNERSHIP_ASSIGNMENT_RULE

_OWNERSHIP_FIELDS = _v20._OWNERSHIP_FIELDS
_TOP_LEVEL_FIELDS = _v20._TOP_LEVEL_FIELDS | {"one_bit_bound_reader"}
_CENTRAL_FIELDS = _v20._CENTRAL_FIELDS | {"bound"}
_CENTRAL_BOUND_FIELDS = {
    "candidate_count",
    "parent_scans",
    "probes",
    "returns",
    "level_bindings",
    "matching_assignments",
    "realized_prunes",
    "releases",
    "live_tokens",
    "unobserved_releases",
}

_DIGEST_FIELDS = {
    "assignment_sha256",
    "trail_sha256",
    "pending_sha256",
    "group_cache_sha256",
    "trace_sha256",
    "counters_sha256",
}

_ONE_BIT_BOUND_FIELDS = {
    "schema",
    "operator",
    "runtime_parent_schema",
    "candidate_order_rule",
    "bound_rule",
    "decision_rule",
    "realized_prune_rule",
    "key_variable_count",
    "threshold",
    "threshold_f64le_hex",
    "candidate_count",
    "ranked_candidate_count",
    "omitted_candidate_count",
    "parent_scans",
    "probe_count",
    "child_bound_evaluations",
    "recorded_probe_event_count",
    "omitted_probe_event_count",
    "probe_trace_encoding",
    "probe_trace_count",
    "probe_trace_bytes",
    "probe_trace_sha256",
    "proposals",
    "level_bindings",
    "matching_assignments_observed",
    "realized_prunes",
    "fully_emitted_prunes",
    "releases",
    "live_tokens",
    "unobserved_releases",
    "class_counts",
    "minimum_child_upper",
    "minimum_child_upper_f64le_hex",
    "minimum_child_margin",
    "minimum_child_variable",
    "minimum_upper_zero",
    "minimum_upper_zero_f64le_hex",
    "minimum_upper_one",
    "minimum_upper_one_f64le_hex",
    "minimum_witness_tie_rule",
    "minimum_witness",
    "candidate_order_encoding",
    "candidate_order_count",
    "candidate_order_bytes",
    "candidate_order_hex",
    "candidate_order_sha256",
    "probe_events",
    "interventions",
}

_PROBE_FIELDS = {
    "call",
    "probe",
    "coordinate_index",
    "variable",
    "parent_level",
    "parent_assignment_sha256",
    "upper_zero",
    "upper_zero_f64le_hex",
    "upper_one",
    "upper_one_f64le_hex",
    "threshold",
    "threshold_f64le_hex",
    "selection_class",
    "losing_bit",
    "losing_spin",
    "losing_literal",
    "proposal_token",
    "state_before",
    "state_after",
    "state_unchanged",
}

_WITNESS_FIELDS = _PROBE_FIELDS - {"proposal_token"}

# The native worker intentionally keeps every intervention.  These rows are
# consequently authoritative linkage evidence, unlike the bounded probe log.
_INTERVENTION_FIELDS = {
    "token",
    "call",
    "probe",
    "coordinate_index",
    "variable",
    "parent_level",
    "origin",
    "selection_class",
    "upper_zero",
    "upper_zero_f64le_hex",
    "upper_one",
    "upper_one_f64le_hex",
    "threshold",
    "threshold_f64le_hex",
    "losing_bit",
    "losing_spin",
    "losing_literal",
    "parent_assignment_sha256",
    "state_before",
    "state_after",
    "state_unchanged",
    "level_bound",
    "matching_assignment_observed",
    "observed_literal",
    "v6_threshold_prunes_before",
    "v6_threshold_prunes_after",
    "v6_trail_threshold_prunes_before",
    "v6_trail_threshold_prunes_after",
    "v6_external_clauses_queued_before",
    "v6_external_clauses_queued_after",
    "v6_pending_clause_count_before",
    "v6_pending_clause_count_after",
    "v6_pending_clause_sha256_before",
    "v6_pending_clause_sha256_after",
    "v6_trace_sha256_before",
    "v6_trace_sha256_after",
    "no_good_literals",
    "no_good_clause_sha256",
    "fully_emitted",
    "fully_emitted_index",
    "realized_prune",
    "released",
    "unobserved_release",
}


@dataclass(frozen=True)
class OneBitBoundValidation:
    """Certified normalized O1C-0080 bound-reader evidence."""

    reader: Mapping[str, object]
    probe_count: int
    recorded_probe_count: int
    crossing_count: int
    intervention_count: int
    realized_prune_count: int
    fully_emitted_count: int
    released_count: int
    live_count: int
    unobserved_release_count: int


@dataclass(frozen=True)
class JointScoreSieveV21Result(_v20.JointScoreSieveV20Result):
    """Unchanged v6 result plus central-v2 and exact child-bound evidence."""

    one_bit_bound_reader: Mapping[str, object]
    one_bit_bound_validation: OneBitBoundValidation
    native_stdout: str | None = None
    native_stdout_sha256: str | None = None


@dataclass(frozen=True)
class _OwnershipReplay:
    ownership: Mapping[str, object]
    events: tuple[Mapping[str, object], ...]
    terminal_phases: Mapping[int, str]


def _error(field: str) -> O1RelationalSearchError:
    return O1RelationalSearchError(f"joint-score-sieve-v21 {field} differs")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _error(field)
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _error(field)
    return cast(Sequence[object], value)


def _nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(field)
    return value


def _positive(value: object, field: str) -> int:
    result = _nonnegative(value, field)
    if not result:
        raise _error(field)
    return result


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _error(field)
    return value


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _error(field)
    return value


def _literal(value: object, field: str, *, zero: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < -(1 << 31) + 1
        or value > (1 << 31) - 1
        or (not zero and value == 0)
    ):
        raise _error(field)
    return value


def _nullable_positive(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _positive(value, field)


def _nullable_nonnegative(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _nonnegative(value, field)


def load_native_json(payload: str | bytes | bytearray) -> Mapping[str, object]:
    """Decode native JSON while rejecting duplicate names and non-finite constants."""

    if not isinstance(payload, (str, bytes, bytearray)):
        raise _error("result JSON input")

    def object_pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in rows:
            if name in result:
                raise _error(f"duplicate JSON field {name}")
            result[name] = value
        return result

    def reject_constant(value: str) -> object:
        raise _error(f"non-finite JSON constant {value}")

    try:
        value = json.loads(
            payload,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("result JSON") from exc
    return _mapping(value, "result JSON root")


def _finite_f64(value: object, hexadecimal: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise _error(field)
    result = float(value)
    expected = struct.pack("<d", result).hex()
    if hexadecimal != expected:
        raise _error(f"{field} f64 identity")
    return result


def _state(value: object, field: str) -> Mapping[str, object]:
    result = _mapping(value, field)
    if set(result) != _DIGEST_FIELDS:
        raise _error(f"{field} fields")
    for name in _DIGEST_FIELDS:
        _sha(result.get(name), f"{field} {name}")
    return result


def _selection(
    *, upper_zero: float, upper_one: float, threshold: float
) -> tuple[str, int | None, int, int]:
    zero_dead = upper_zero < threshold
    one_dead = upper_one < threshold
    if not zero_dead and not one_dead:
        return "NEITHER_PRUNABLE", None, 0, 0
    if zero_dead and not one_dead:
        return "ZERO_PRUNABLE", 0, -1, 0
    if one_dead and not zero_dead:
        return "ONE_PRUNABLE", 1, 1, 0
    losing_bit = 0 if upper_zero <= upper_one else 1
    return "BOTH_PRUNABLE", losing_bit, -1 if losing_bit == 0 else 1, 0


def _canonical_clause(literals: Sequence[object], field: str) -> tuple[int, ...]:
    result = tuple(_literal(item, f"{field} literal") for item in literals)
    if not result:
        raise _error(field)
    if any(abs(left) >= abs(right) for left, right in zip(result, result[1:])):
        raise _error(f"{field} ordering")
    return result


def _clause_sha256(literals: tuple[int, ...]) -> str:
    payload = struct.pack("<I", len(literals)) + b"".join(
        struct.pack("<i", literal) for literal in literals
    )
    return hashlib.sha256(payload).hexdigest()


def _i32_sequence(
    value: Mapping[str, object], prefix: str, expected_count: int
) -> tuple[int, ...]:
    raw = value.get(f"{prefix}_hex")
    if not isinstance(raw, str) or len(raw) % 8:
        raise _error(f"{prefix} hex")
    try:
        payload = bytes.fromhex(raw)
    except ValueError as exc:
        raise _error(f"{prefix} hex") from exc
    if (
        value.get(f"{prefix}_encoding") != SIGNED_I32_SEQUENCE_ENCODING
        or value.get(f"{prefix}_count") != expected_count
        or value.get(f"{prefix}_bytes") != len(payload)
        or len(payload) != 4 * expected_count
        or value.get(f"{prefix}_sha256") != hashlib.sha256(payload).hexdigest()
    ):
        raise _error(f"{prefix} projection")
    return tuple(item[0] for item in struct.iter_unpack("<i", payload))


def _candidate_sequence(
    reader: Mapping[str, object], expected: tuple[int, ...]
) -> None:
    if reader.get("candidate_order_encoding") != SIGNED_I32_SEQUENCE_ENCODING:
        raise _error("candidate order encoding")
    count = _nonnegative(reader.get("candidate_order_count"), "candidate order count")
    size = _nonnegative(reader.get("candidate_order_bytes"), "candidate order bytes")
    hexadecimal = reader.get("candidate_order_hex")
    if not isinstance(hexadecimal, str):
        raise _error("candidate order hex")
    try:
        payload = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise _error("candidate order hex") from exc
    if (
        count != len(expected)
        or size != 4 * count
        or len(payload) != size
        or hashlib.sha256(payload).hexdigest()
        != _sha(reader.get("candidate_order_sha256"), "candidate order hash")
    ):
        raise _error("candidate order envelope")
    decoded = tuple(
        struct.unpack_from("<i", payload, offset)[0] for offset in range(0, size, 4)
    )
    if decoded != expected:
        raise _error("candidate order identity")


def _probe_trace_record(probe: Mapping[str, object]) -> bytes:
    class_code = {
        "NEITHER_PRUNABLE": 0,
        "ZERO_PRUNABLE": 1,
        "ONE_PRUNABLE": 2,
        "BOTH_PRUNABLE": 3,
    }[cast(str, probe["selection_class"])]
    return b"".join(
        (
            struct.pack("<Q", cast(int, probe["call"])),
            struct.pack("<Q", cast(int, probe["probe"])),
            struct.pack("<I", cast(int, probe["coordinate_index"])),
            struct.pack("<I", cast(int, probe["parent_level"])),
            struct.pack("<i", cast(int, probe["variable"])),
            struct.pack("<d", cast(float, probe["upper_zero"])),
            struct.pack("<d", cast(float, probe["upper_one"])),
            struct.pack("<d", cast(float, probe["threshold"])),
            bytes((class_code,)),
            struct.pack("<i", cast(int, probe["losing_literal"])),
        )
    )


def _replay_ownership(value: object) -> _OwnershipReplay:
    """Replay every v2 ownership event, including terminal live tokens."""

    ownership = _mapping(value, "decision ownership")
    if set(ownership) != _OWNERSHIP_FIELDS:
        raise _error("decision ownership fields")
    if (
        ownership.get("schema") != DECISION_OWNERSHIP_SCHEMA
        or ownership.get("lifecycle") != OWNERSHIP_LIFECYCLE
        or ownership.get("eligibility_rule") != OWNERSHIP_ELIGIBILITY_RULE
        or ownership.get("assignment_notification_rule") != OWNERSHIP_ASSIGNMENT_RULE
    ):
        raise _error("decision ownership identity")

    count_names = (
        "current_level",
        "proposals",
        "level_bound_interventions",
        "confirmed_interventions",
        "releases",
        "confirmed_releases",
        "level_bound_unobserved_releases",
        "opposite_assignments",
        "foreign_assignments",
        "renotifications",
        "live_tokens",
        "maximum_live_tokens",
        "event_count",
        "recorded_event_count",
        "omitted_event_count",
    )
    counts = {
        name: _nonnegative(ownership.get(name), f"ownership {name}")
        for name in count_names
    }
    if (
        counts["level_bound_interventions"] > counts["proposals"]
        or counts["confirmed_interventions"] > counts["level_bound_interventions"]
        or counts["releases"] > counts["level_bound_interventions"]
        or counts["releases"]
        != counts["confirmed_releases"] + counts["level_bound_unobserved_releases"]
        or counts["live_tokens"] + counts["releases"]
        != counts["level_bound_interventions"]
        or counts["live_tokens"] > counts["maximum_live_tokens"]
        or counts["event_count"]
        != counts["recorded_event_count"] + counts["omitted_event_count"]
        or counts["omitted_event_count"]
        or counts["event_count"]
        != counts["proposals"]
        + counts["level_bound_interventions"]
        + counts["confirmed_interventions"]
        + counts["releases"]
        + counts["opposite_assignments"]
        + counts["foreign_assignments"]
        + counts["renotifications"]
        or _boolean(ownership.get("proposal_activated"), "proposal activated")
        != bool(counts["proposals"])
        or _boolean(ownership.get("level_bound_activated"), "level-bound activated")
        != bool(counts["level_bound_interventions"])
        or _boolean(ownership.get("confirmed_activated"), "confirmed activated")
        != bool(counts["confirmed_interventions"])
    ):
        raise _error("decision ownership arithmetic")

    raw_origins = _mapping(ownership.get("origin_counts"), "origin counts")
    if set(raw_origins) != set(ORIGINS):
        raise _error("origin count fields")
    origin_fields = {"proposals", "level_bound", "confirmed", "releases"}
    origin_counts: dict[str, dict[str, int]] = {}
    for origin in ORIGINS:
        raw_row = _mapping(raw_origins.get(origin), f"origin {origin}")
        if set(raw_row) != origin_fields:
            raise _error(f"origin {origin} counters")
        origin_counts[origin] = {
            name: _nonnegative(raw_row.get(name), f"origin {origin} {name}")
            for name in origin_fields
        }
    if (
        sum(row["proposals"] for row in origin_counts.values()) != counts["proposals"]
        or sum(row["level_bound"] for row in origin_counts.values())
        != counts["level_bound_interventions"]
        or sum(row["confirmed"] for row in origin_counts.values())
        != counts["confirmed_interventions"]
        or sum(row["releases"] for row in origin_counts.values()) != counts["releases"]
    ):
        raise _error("origin count total")

    events = tuple(
        _mapping(item, "ownership event")
        for item in _sequence(ownership.get("events"), "ownership events")
    )
    if len(events) != counts["recorded_event_count"]:
        raise _error("recorded ownership event count")

    tokens: dict[int, dict[str, object]] = {}
    kind_counts = {kind: 0 for kind in EVENT_KINDS}
    replay_origins = {origin: {name: 0 for name in origin_fields} for origin in ORIGINS}
    pending_token: int | None = None
    release_tokens: list[int] = []
    release_target: int | None = None
    replay_maximum_live = 0
    release_kinds = {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    live_phases = {"LEVEL_BOUND", "CONFIRMED"}
    event_fields = {
        "sequence",
        "kind",
        "token",
        "callback",
        "origin",
        "row",
        "literal",
        "level",
        "observed_literal",
    }
    for index, event in enumerate(events, start=1):
        if set(event) != event_fields:
            raise _error("ownership event fields")
        kind = event.get("kind")
        origin = event.get("origin")
        if event.get("sequence") != index or kind not in EVENT_KINDS:
            raise _error("ownership event chronology")
        kind = cast(str, kind)
        kind_counts[kind] += 1
        token = _nonnegative(event.get("token"), "ownership event token")
        callback = _nonnegative(event.get("callback"), "ownership event callback")
        row = _nonnegative(event.get("row"), "ownership event row")
        literal = _literal(event.get("literal"), "ownership event literal", zero=True)
        level = _nonnegative(event.get("level"), "ownership event level")
        observed = _literal(
            event.get("observed_literal"),
            "ownership event observed literal",
            zero=True,
        )
        is_release = kind in release_kinds
        if pending_token is not None and not (
            kind == "LEVEL_BOUND" and token == pending_token
        ):
            raise _error("pending ownership proposal binding")
        if release_tokens and not is_release:
            raise _error("incomplete ownership release batch")
        if not is_release and any(
            cast(int, state["level"]) > level
            for state in tokens.values()
            if state["phase"] in live_phases
        ):
            raise _error("global ownership level")

        if kind == "FOREIGN_ASSIGNMENT":
            if (
                token
                or callback
                or origin != "NONE"
                or row
                or not observed
                or literal != observed
                or any(
                    state["phase"] in live_phases
                    and abs(cast(int, state["literal"])) == abs(literal)
                    for state in tokens.values()
                )
            ):
                raise _error("foreign ownership assignment")
            continue
        if origin not in ORIGINS or not token or not callback or not literal:
            raise _error("owned event identity")

        if kind == "PROPOSED":
            if (
                pending_token is not None
                or token in tokens
                or token != len(tokens) + 1
                or observed
                or any(
                    state["phase"] in live_phases
                    and abs(cast(int, state["literal"])) == abs(literal)
                    for state in tokens.values()
                )
            ):
                raise _error("ownership proposal transition")
            tokens[token] = {
                "origin": origin,
                "row": row,
                "literal": literal,
                "callback": callback,
                "phase": "PROPOSED",
                "proposal_level": level,
                "level": 0,
            }
            pending_token = token
            replay_origins[cast(str, origin)]["proposals"] += 1
            continue

        state = tokens.get(token)
        if state is None or any(
            state[name] != expected
            for name, expected in (
                ("origin", origin),
                ("row", row),
                ("literal", literal),
                ("callback", callback),
            )
        ):
            raise _error("owned event token binding")
        phase = state["phase"]
        if kind == "LEVEL_BOUND":
            if (
                pending_token != token
                or phase != "PROPOSED"
                or level != cast(int, state["proposal_level"]) + 1
                or observed
                or any(
                    other is not state
                    and other["phase"] in live_phases
                    and (
                        abs(cast(int, other["literal"])) == abs(literal)
                        or other["level"] == level
                    )
                    for other in tokens.values()
                )
            ):
                raise _error("ownership level-bound transition")
            state["phase"] = "LEVEL_BOUND"
            state["level"] = level
            pending_token = None
            replay_origins[cast(str, origin)]["level_bound"] += 1
            replay_maximum_live = max(
                replay_maximum_live,
                sum(item["phase"] in live_phases for item in tokens.values()),
            )
        elif kind == "CONFIRMED":
            if (
                phase != "LEVEL_BOUND"
                or observed != literal
                or level < cast(int, state["level"])
            ):
                raise _error("ownership confirmation transition")
            state["phase"] = "CONFIRMED"
            replay_origins[cast(str, origin)]["confirmed"] += 1
        elif kind == "RENOTIFIED":
            if (
                phase != "CONFIRMED"
                or observed != literal
                or level < cast(int, state["level"])
            ):
                raise _error("ownership renotification transition")
        elif kind == "OPPOSITE_ASSIGNMENT":
            if (
                phase not in live_phases
                or observed != -literal
                or level < cast(int, state["level"])
            ):
                raise _error("ownership opposite transition")
        elif is_release:
            if not release_tokens:
                release_target = level
                release_tokens = [
                    candidate_token
                    for candidate_token, candidate in sorted(
                        tokens.items(),
                        key=lambda item: (-cast(int, item[1]["level"]), -item[0]),
                    )
                    if candidate["phase"] in live_phases
                    and cast(int, candidate["level"]) > level
                ]
                if not release_tokens:
                    raise _error("ownership release without live token")
            expected_phase = "CONFIRMED" if kind == "RELEASED" else "LEVEL_BOUND"
            if (
                release_target != level
                or release_tokens[0] != token
                or phase != expected_phase
                or observed
                or level >= cast(int, state["level"])
            ):
                raise _error("ownership release transition")
            state["phase"] = "RELEASED"
            replay_origins[cast(str, origin)]["releases"] += 1
            del release_tokens[0]
            if not release_tokens:
                release_target = None
        else:
            raise _error("ownership event kind")

    live_states = [state for state in tokens.values() if state["phase"] in live_phases]
    if (
        pending_token is not None
        or release_tokens
        or any(state["phase"] == "PROPOSED" for state in tokens.values())
        or len(tokens) != counts["proposals"]
        or counts["level_bound_interventions"] != counts["proposals"]
        or len(live_states) != counts["live_tokens"]
        or replay_maximum_live != counts["maximum_live_tokens"]
        or any(
            cast(int, state["level"]) > counts["current_level"] for state in live_states
        )
        or kind_counts["PROPOSED"] != counts["proposals"]
        or kind_counts["LEVEL_BOUND"] != counts["level_bound_interventions"]
        or kind_counts["CONFIRMED"] != counts["confirmed_interventions"]
        or kind_counts["RELEASED"] != counts["confirmed_releases"]
        or kind_counts["LEVEL_BOUND_UNOBSERVED_RELEASE"]
        != counts["level_bound_unobserved_releases"]
        or kind_counts["OPPOSITE_ASSIGNMENT"] != counts["opposite_assignments"]
        or kind_counts["FOREIGN_ASSIGNMENT"] != counts["foreign_assignments"]
        or kind_counts["RENOTIFIED"] != counts["renotifications"]
        or replay_origins != origin_counts
    ):
        raise _error("complete ownership event projection")
    return _OwnershipReplay(
        ownership=ownership,
        events=events,
        terminal_phases={
            token: cast(str, state["phase"]) for token, state in tokens.items()
        },
    )


def _owned_token_events(
    events: tuple[Mapping[str, object], ...], token: int
) -> tuple[Mapping[str, object], ...]:
    return tuple(event for event in events if event.get("token") == token)


def _probe_event(
    value: object,
    *,
    threshold: float,
    candidate_order: tuple[int, ...],
) -> dict[str, object]:
    probe = _mapping(value, "probe event")
    if set(probe) != _PROBE_FIELDS:
        raise _error("probe event fields")
    call = _positive(probe.get("call"), "probe call")
    sequence = _positive(probe.get("probe"), "probe sequence")
    parent_level = _nonnegative(probe.get("parent_level"), "probe parent level")
    coordinate = _nonnegative(probe.get("coordinate_index"), "probe coordinate")
    if coordinate >= len(candidate_order):
        raise _error("probe coordinate range")
    variable = _positive(probe.get("variable"), "probe variable")
    if variable != candidate_order[coordinate]:
        raise _error("probe coordinate identity")
    parent_assignment = _sha(
        probe.get("parent_assignment_sha256"), "probe parent assignment"
    )
    upper_zero = _finite_f64(
        probe.get("upper_zero"), probe.get("upper_zero_f64le_hex"), "probe U0"
    )
    upper_one = _finite_f64(
        probe.get("upper_one"), probe.get("upper_one_f64le_hex"), "probe U1"
    )
    reported_threshold = _finite_f64(
        probe.get("threshold"),
        probe.get("threshold_f64le_hex"),
        "probe threshold",
    )
    if (
        reported_threshold != threshold
        or probe.get("threshold_f64le_hex") != struct.pack("<d", threshold).hex()
    ):
        raise _error("probe requested threshold")
    expected_class, bit, spin, _ = _selection(
        upper_zero=upper_zero, upper_one=upper_one, threshold=threshold
    )
    losing_literal = 0 if bit is None else spin * variable
    losing_fields = (
        probe.get("losing_bit"),
        probe.get("losing_spin"),
        probe.get("losing_literal"),
    )
    expected_losing_fields = (
        (None, None, None) if bit is None else (bit, spin, losing_literal)
    )
    if (
        probe.get("selection_class") != expected_class
        or losing_fields != expected_losing_fields
    ):
        raise _error("probe selection semantics")
    token = _nullable_positive(probe.get("proposal_token"), "probe proposal token")
    if (bit is None) != (token is None):
        raise _error("probe proposal presence")
    before = _state(probe.get("state_before"), "probe state before")
    after = _state(probe.get("state_after"), "probe state after")
    if (
        before != after
        or not _boolean(probe.get("state_unchanged"), "probe state unchanged")
        or parent_assignment != before.get("assignment_sha256")
    ):
        raise _error("probe non-mutation")
    return {
        "raw": probe,
        "call": call,
        "probe": sequence,
        "parent_level": parent_level,
        "coordinate_index": coordinate,
        "variable": variable,
        "upper_zero": upper_zero,
        "upper_one": upper_one,
        "threshold": reported_threshold,
        "selection_class": expected_class,
        "losing_bit": bit,
        "losing_spin": spin,
        "losing_literal": losing_literal,
        "proposal_token": token,
        "parent_assignment_sha256": parent_assignment,
        "state_before": before,
        "state_after": after,
    }


def _emitted_rows(vault: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    rows = tuple(
        _mapping(item, "emitted clause")
        for item in _sequence(
            vault.get("fully_emitted_clauses"), "fully emitted clauses"
        )
    )
    if _nonnegative(
        vault.get("fully_emitted_clause_count"), "fully emitted clause count"
    ) != len(rows):
        raise _error("fully emitted clause count")
    return rows


def _validate_intervention(
    value: object,
    *,
    probe: Mapping[str, object],
    ownership_events: tuple[Mapping[str, object], ...],
    terminal_phases: Mapping[int, str],
    sieve: Mapping[str, object],
    emitted: tuple[Mapping[str, object], ...],
) -> tuple[bool, bool, bool, bool]:
    row = _mapping(value, "bound intervention")
    if set(row) != _INTERVENTION_FIELDS:
        raise _error("bound intervention fields")
    token = _positive(row.get("token"), "intervention token")
    if token != probe["proposal_token"]:
        raise _error("intervention probe token")
    exact_probe_fields = {
        "call",
        "probe",
        "coordinate_index",
        "variable",
        "parent_level",
        "selection_class",
        "upper_zero",
        "upper_zero_f64le_hex",
        "upper_one",
        "upper_one_f64le_hex",
        "threshold",
        "threshold_f64le_hex",
        "losing_bit",
        "losing_spin",
        "losing_literal",
        "parent_assignment_sha256",
        "state_before",
        "state_after",
        "state_unchanged",
    }
    probe_raw = _mapping(probe["raw"], "normalized probe")
    if any(row.get(name) != probe_raw.get(name) for name in exact_probe_fields):
        raise _error("intervention probe binding")
    if row.get("origin") != BOUND_ORIGIN:
        raise _error("intervention origin")
    parent_level = _nonnegative(row.get("parent_level"), "intervention parent level")
    level_bound = _positive(row.get("level_bound"), "intervention bound level")
    if level_bound != parent_level + 1:
        raise _error("intervention level binding")

    token_events = _owned_token_events(ownership_events, token)
    proposals = [event for event in token_events if event.get("kind") == "PROPOSED"]
    bounds = [event for event in token_events if event.get("kind") == "LEVEL_BOUND"]
    confirms = [event for event in token_events if event.get("kind") == "CONFIRMED"]
    releases = [
        event
        for event in token_events
        if event.get("kind") in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    ]
    expected_identity = (
        token,
        probe["call"],
        BOUND_ORIGIN,
        probe["coordinate_index"],
        probe["losing_literal"],
    )
    for event in token_events:
        if event.get("kind") == "FOREIGN_ASSIGNMENT":
            raise _error("bound token foreign event")
        identity = (
            event.get("token"),
            event.get("callback"),
            event.get("origin"),
            event.get("row"),
            event.get("literal"),
        )
        if identity != expected_identity:
            raise _error("bound token ownership identity")
    if len(proposals) != 1 or len(bounds) != 1 or len(releases) > 1:
        raise _error("bound token ownership lifecycle")
    if (
        proposals[0].get("level") != parent_level
        or bounds[0].get("level") != level_bound
    ):
        raise _error("bound token ownership level")

    observed = _boolean(
        row.get("matching_assignment_observed"), "matching assignment observed"
    )
    raw_observed_literal = row.get("observed_literal")
    observed_literal = (
        _literal(raw_observed_literal, "intervention observed literal")
        if raw_observed_literal is not None
        else None
    )
    if observed:
        if (
            len(confirms) != 1
            or confirms[0].get("observed_literal") != probe["losing_literal"]
            or observed_literal != probe["losing_literal"]
        ):
            raise _error("matching assignment ownership linkage")
    elif confirms or observed_literal is not None:
        raise _error("unobserved assignment ownership linkage")

    released = _boolean(row.get("released"), "intervention released")
    unobserved_release = _boolean(
        row.get("unobserved_release"), "intervention unobserved release"
    )
    if released != bool(releases):
        raise _error("intervention released projection")
    if released:
        release_kind = releases[0].get("kind")
        if (
            unobserved_release != (release_kind == "LEVEL_BOUND_UNOBSERVED_RELEASE")
            or observed == unobserved_release
            or terminal_phases.get(token) != "RELEASED"
        ):
            raise _error("intervention release linkage")
    elif unobserved_release or terminal_phases.get(token) != (
        "CONFIRMED" if observed else "LEVEL_BOUND"
    ):
        raise _error("intervention terminal-live linkage")

    counter_names = (
        "threshold_prunes",
        "trail_threshold_prunes",
        "external_clauses_queued",
    )
    deltas: list[int] = []
    for name in counter_names:
        before = _nonnegative(row.get(f"v6_{name}_before"), f"v6 {name} before")
        after = _nonnegative(row.get(f"v6_{name}_after"), f"v6 {name} after")
        if after < before:
            raise _error(f"v6 {name} monotonicity")
        if after > _nonnegative(sieve.get(name), f"sieve {name}"):
            raise _error(f"v6 {name} final counter")
        deltas.append(after - before)
    pending_before = _nonnegative(
        row.get("v6_pending_clause_count_before"), "v6 pending before"
    )
    pending_after = _nonnegative(
        row.get("v6_pending_clause_count_after"), "v6 pending after"
    )
    if pending_before > 1 or pending_after > 1:
        raise _error("v6 pending clause count")
    pending_hash_before = row.get("v6_pending_clause_sha256_before")
    pending_hash_after = row.get("v6_pending_clause_sha256_after")
    if pending_hash_before is not None:
        pending_hash_before = _sha(pending_hash_before, "v6 pending hash before")
    if pending_hash_after is not None:
        pending_hash_after = _sha(pending_hash_after, "v6 pending hash after")
    trace_before = _sha(row.get("v6_trace_sha256_before"), "v6 trace before")
    trace_after = _sha(row.get("v6_trace_sha256_after"), "v6 trace after")
    realized = _boolean(row.get("realized_prune"), "realized prune")
    if realized != observed:
        raise _error("realized prune assignment linkage")

    fully_emitted = _boolean(row.get("fully_emitted"), "fully emitted")
    fully_emitted_index = _nullable_nonnegative(
        row.get("fully_emitted_index"), "fully emitted index"
    )

    raw_literals = _sequence(row.get("no_good_literals"), "no-good literals")
    no_good_hash = row.get("no_good_clause_sha256")
    if realized:
        if (
            deltas != [1, 1, 1]
            or pending_before != 0
            or pending_after != 1
            or pending_hash_before is not None
            or pending_hash_after is None
            or trace_before == trace_after
            or not fully_emitted
        ):
            raise _error("realized v6 prune transition")
        literals = _canonical_clause(raw_literals, "no-good clause")
        expected_hash = _clause_sha256(literals)
        if _sha(no_good_hash, "no-good clause hash") != expected_hash:
            raise _error("canonical no-good identity")
        if pending_hash_after != expected_hash:
            raise _error("pending canonical no-good linkage")
        if -cast(int, probe["losing_literal"]) not in literals:
            raise _error("no-good losing-child literal")
        if fully_emitted:
            if fully_emitted_index is None or fully_emitted_index >= len(emitted):
                raise _error("emitted no-good index")
            emitted_row = emitted[fully_emitted_index]
            if (
                emitted_row.get("clause_sha256") != expected_hash
                or tuple(
                    _literal(item, "emitted no-good literal")
                    for item in _sequence(
                        emitted_row.get("literals"), "emitted literals"
                    )
                )
                != literals
            ):
                raise _error("emitted no-good linkage")
        elif fully_emitted_index is not None:
            raise _error("absent emitted no-good index")
    else:
        if (
            deltas != [0, 0, 0]
            or pending_before != 0
            or pending_after != 0
            or pending_hash_before is not None
            or pending_hash_after is not None
            or trace_before != trace_after
            or raw_literals
            or no_good_hash is not None
            or fully_emitted
            or fully_emitted_index is not None
        ):
            raise _error("unobserved intervention v6 neutrality")
    return realized, fully_emitted, released, unobserved_release


def validate_one_bit_bound_reader(
    value: object,
    *,
    decision_ownership: object,
    sieve: object,
    vault: object,
    threshold: float,
    candidate_order: tuple[int, ...],
    ranked_candidate_count: int,
    key_variable_count: int = 256,
) -> OneBitBoundValidation:
    """Validate exact probes through ownership, v6 prune and clause export."""

    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or not isinstance(candidate_order, tuple)
        or not candidate_order
        or isinstance(ranked_candidate_count, bool)
        or not isinstance(ranked_candidate_count, int)
        or not 0 <= ranked_candidate_count <= len(candidate_order)
        or isinstance(key_variable_count, bool)
        or not isinstance(key_variable_count, int)
        or key_variable_count <= 0
        or len(set(candidate_order)) != len(candidate_order)
        or any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= key_variable_count
            for variable in candidate_order
        )
    ):
        raise _error("bound reader validation inputs")
    reader = _mapping(value, "one-bit bound reader")
    if set(reader) != _ONE_BIT_BOUND_FIELDS:
        raise _error("one-bit bound reader fields")
    reported_threshold = _finite_f64(
        reader.get("threshold"),
        reader.get("threshold_f64le_hex"),
        "bound reader threshold",
    )
    if (
        reader.get("schema") != ONE_BIT_BOUND_READER_SCHEMA
        or reader.get("operator") != ONE_BIT_BOUND_OPERATOR
        or reader.get("runtime_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or reader.get("candidate_order_rule") != ONE_BIT_CANDIDATE_ORDER_RULE
        or reader.get("bound_rule") != ONE_BIT_BOUND_RULE
        or reader.get("decision_rule") != ONE_BIT_DECISION_RULE
        or reader.get("realized_prune_rule") != ONE_BIT_REALIZED_PRUNE_RULE
        or reader.get("minimum_witness_tie_rule") != MINIMUM_WITNESS_TIE_RULE
        or reader.get("key_variable_count") != key_variable_count
        or reported_threshold != float(threshold)
        or reader.get("threshold_f64le_hex")
        != struct.pack("<d", float(threshold)).hex()
        or reader.get("candidate_count") != len(candidate_order)
        or reader.get("ranked_candidate_count") != ranked_candidate_count
        or reader.get("omitted_candidate_count")
        != len(candidate_order) - ranked_candidate_count
    ):
        raise _error("one-bit bound reader identity")
    _candidate_sequence(reader, candidate_order)

    probe_values = _sequence(reader.get("probe_events"), "probe events")
    interventions_values = _sequence(reader.get("interventions"), "interventions")
    probe_count = _nonnegative(reader.get("probe_count"), "probe count")
    recorded_count = _nonnegative(
        reader.get("recorded_probe_event_count"), "recorded probe count"
    )
    omitted_count = _nonnegative(
        reader.get("omitted_probe_event_count"), "omitted probe count"
    )
    if (
        recorded_count != len(probe_values)
        or probe_count != recorded_count + omitted_count
    ):
        raise _error("probe count arithmetic")
    probes = [
        _probe_event(item, threshold=float(threshold), candidate_order=candidate_order)
        for item in probe_values
    ]
    parent_scans = _nonnegative(reader.get("parent_scans"), "bound parent scans")
    prior_probe = 0
    prior_call = 0
    prior_coordinate = -1
    prior_parent: tuple[int, str, Mapping[str, object]] | None = None
    token_to_probe: dict[int, Mapping[str, object]] = {}
    for probe in probes:
        sequence = cast(int, probe["probe"])
        call = cast(int, probe["call"])
        coordinate = cast(int, probe["coordinate_index"])
        if (
            sequence <= prior_probe
            or sequence > probe_count
            or call < prior_call
            or call > parent_scans
        ):
            raise _error("probe chronology")
        if call == prior_call and coordinate <= prior_coordinate:
            raise _error("same-parent probe order")
        if call != prior_call:
            prior_coordinate = -1
            prior_parent = None
        parent_identity = (
            cast(int, probe["parent_level"]),
            cast(str, probe["parent_assignment_sha256"]),
            cast(Mapping[str, object], probe["state_before"]),
        )
        if prior_parent is not None and parent_identity != prior_parent:
            raise _error("same-call parent census")
        token = probe["proposal_token"]
        if token is not None:
            if cast(int, token) in token_to_probe:
                raise _error("duplicate proposal token")
            token_to_probe[cast(int, token)] = probe
        prior_probe = sequence
        prior_call = call
        prior_coordinate = coordinate
        prior_parent = parent_identity
    if not omitted_count and tuple(
        cast(int, probe["probe"]) for probe in probes
    ) != tuple(range(1, probe_count + 1)):
        raise _error("complete probe sequence")

    crossing_count = len(token_to_probe)
    proposals = _nonnegative(reader.get("proposals"), "bound proposals")
    if proposals != crossing_count or len(interventions_values) != crossing_count:
        raise _error("crossing intervention completeness")

    class_counts = _mapping(reader.get("class_counts"), "bound class counts")
    if set(class_counts) != SELECTION_CLASSES:
        raise _error("bound class count fields")
    normalized_class_counts = {
        name: _nonnegative(class_counts.get(name), f"bound class {name}")
        for name in SELECTION_CLASSES
    }
    if sum(normalized_class_counts.values()) != probe_count:
        raise _error("bound class count total")
    recorded_class_counts = {name: 0 for name in SELECTION_CLASSES}
    for probe in probes:
        recorded_class_counts[cast(str, probe["selection_class"])] += 1
    for name in SELECTION_CLASSES - {"NEITHER_PRUNABLE"}:
        if recorded_class_counts[name] != normalized_class_counts[name]:
            raise _error("crossing probes must be recorded")

    if (
        _nonnegative(reader.get("child_bound_evaluations"), "child evaluations")
        != 2 * probe_count
        or _nonnegative(reader.get("probe_trace_count"), "probe trace count")
        != probe_count
        or _nonnegative(reader.get("probe_trace_bytes"), "probe trace bytes")
        != _PROBE_TRACE_RECORD_BYTES * probe_count
        or reader.get("probe_trace_encoding") != PROBE_TRACE_ENCODING
    ):
        raise _error("probe trace envelope")
    trace_sha = _sha(reader.get("probe_trace_sha256"), "probe trace hash")
    if not omitted_count:
        expected_trace = hashlib.sha256(
            b"".join(_probe_trace_record(probe) for probe in probes)
        ).hexdigest()
        if trace_sha != expected_trace:
            raise _error("probe trace identity")

    witness_value = reader.get("minimum_witness")
    if probe_count:
        witness = _mapping(witness_value, "minimum witness")
        if set(witness) != _WITNESS_FIELDS:
            raise _error("minimum witness fields")
        fake_probe = dict(witness)
        fake_probe["proposal_token"] = (
            1 if witness.get("losing_literal") is not None else None
        )
        normalized_witness = _probe_event(
            fake_probe,
            threshold=float(threshold),
            candidate_order=candidate_order,
        )
        minimum_upper = _finite_f64(
            reader.get("minimum_child_upper"),
            reader.get("minimum_child_upper_f64le_hex"),
            "minimum child upper",
        )
        minimum_zero = _finite_f64(
            reader.get("minimum_upper_zero"),
            reader.get("minimum_upper_zero_f64le_hex"),
            "minimum U0",
        )
        minimum_one = _finite_f64(
            reader.get("minimum_upper_one"),
            reader.get("minimum_upper_one_f64le_hex"),
            "minimum U1",
        )
        margin = reader.get("minimum_child_margin")
        minimum_variable = _positive(
            reader.get("minimum_child_variable"), "minimum child variable"
        )
        if (
            isinstance(margin, bool)
            or not isinstance(margin, (int, float))
            or not math.isfinite(margin)
            or minimum_upper != min(minimum_zero, minimum_one)
            or float(margin) != minimum_upper - float(threshold)
            or minimum_variable != normalized_witness["variable"]
            or minimum_zero != normalized_witness["upper_zero"]
            or minimum_one != normalized_witness["upper_one"]
        ):
            raise _error("minimum witness summary")
        recorded_witnesses = [
            probe for probe in probes if probe["probe"] == normalized_witness["probe"]
        ]
        if recorded_witnesses and any(
            witness.get(name)
            != cast(Mapping[str, object], recorded_witnesses[0]["raw"]).get(name)
            for name in _WITNESS_FIELDS
        ):
            raise _error("minimum witness recorded identity")
        if not omitted_count:
            expected_witness = min(
                probes,
                key=lambda probe: (
                    min(
                        cast(float, probe["upper_zero"]),
                        cast(float, probe["upper_one"]),
                    ),
                    cast(int, probe["call"]),
                    cast(int, probe["coordinate_index"]),
                    cast(int, probe["variable"]),
                ),
            )
            if any(
                witness.get(name)
                != cast(Mapping[str, object], expected_witness["raw"]).get(name)
                for name in _WITNESS_FIELDS
            ):
                raise _error("minimum witness tie selection")
    elif witness_value is not None or any(
        reader.get(name) is not None
        for name in (
            "minimum_child_upper",
            "minimum_child_upper_f64le_hex",
            "minimum_child_margin",
            "minimum_child_variable",
            "minimum_upper_zero",
            "minimum_upper_zero_f64le_hex",
            "minimum_upper_one",
            "minimum_upper_one_f64le_hex",
        )
    ):
        raise _error("absent minimum witness")

    ownership_replay = _replay_ownership(decision_ownership)
    ownership_events = ownership_replay.events
    normalized_sieve = _mapping(sieve, "sieve")
    normalized_vault = _mapping(vault, "vault")
    emitted = _emitted_rows(normalized_vault)
    realized_count = 0
    fully_emitted_count = 0
    released_count = 0
    unobserved_release_count = 0
    seen_tokens: set[int] = set()
    seen_emitted: set[int] = set()
    for item in interventions_values:
        intervention = _mapping(item, "bound intervention")
        token = _positive(intervention.get("token"), "intervention token")
        if token in seen_tokens or token not in token_to_probe:
            raise _error("intervention token completeness")
        realized, fully_emitted, released, unobserved_release = _validate_intervention(
            intervention,
            probe=token_to_probe[token],
            ownership_events=ownership_events,
            terminal_phases=ownership_replay.terminal_phases,
            sieve=normalized_sieve,
            emitted=emitted,
        )
        if realized:
            realized_count += 1
        if fully_emitted:
            index = _nonnegative(
                intervention.get("fully_emitted_index"), "fully emitted index"
            )
            if index in seen_emitted:
                raise _error("duplicate emitted no-good linkage")
            seen_emitted.add(index)
            fully_emitted_count += 1
        if released:
            released_count += 1
        if unobserved_release:
            unobserved_release_count += 1
        seen_tokens.add(token)
    if seen_tokens != set(token_to_probe):
        raise _error("intervention set completeness")
    if tuple(
        _positive(
            _mapping(item, "bound intervention").get("token"),
            "intervention order token",
        )
        for item in interventions_values
    ) != tuple(token_to_probe):
        raise _error("intervention chronology")
    if (
        _nonnegative(reader.get("realized_prunes"), "realized prune count")
        != realized_count
    ):
        raise _error("realized prune count")
    if (
        _nonnegative(reader.get("fully_emitted_prunes"), "fully emitted count")
        != fully_emitted_count
    ):
        raise _error("fully emitted count")
    if (
        _nonnegative(reader.get("level_bindings"), "bound level bindings") != proposals
        or _nonnegative(
            reader.get("matching_assignments_observed"), "bound matching assignments"
        )
        != realized_count
        or _nonnegative(reader.get("releases"), "bound releases") != released_count
        or _nonnegative(reader.get("live_tokens"), "bound live tokens")
        != proposals - released_count
        or _nonnegative(reader.get("unobserved_releases"), "bound unobserved releases")
        != unobserved_release_count
    ):
        raise _error("bound lifecycle aggregate")
    bound_origin = _mapping(
        _mapping(
            ownership_replay.ownership.get("origin_counts"), "ownership origin counts"
        ).get(BOUND_ORIGIN),
        "ownership bound origin",
    )
    if (
        bound_origin.get("proposals") != proposals
        or bound_origin.get("level_bound") != proposals
        or bound_origin.get("confirmed") != realized_count
        or bound_origin.get("releases") != released_count
    ):
        raise _error("bound ownership origin projection")
    return OneBitBoundValidation(
        reader=reader,
        probe_count=probe_count,
        recorded_probe_count=recorded_count,
        crossing_count=crossing_count,
        intervention_count=len(interventions_values),
        realized_prune_count=realized_count,
        fully_emitted_count=fully_emitted_count,
        released_count=released_count,
        live_count=proposals - released_count,
        unobserved_release_count=unobserved_release_count,
    )


def _candidate_order_from_inputs(
    *,
    expected_decision: _v20.VaultRankedDecision,
    staging_plan: _v20.ResidualPolarityStagingPlan,
    field: _v20.CriticalityPotentialField,
    key_variable_count: int = 256,
) -> tuple[tuple[int, ...], int]:
    effective = _v20._effective_rank_literals(expected_decision, staging_plan)
    observed = set(field.observed_variables)
    result: list[int] = []
    seen: set[int] = set()
    for literal in effective:
        variable = abs(literal)
        if (
            variable <= key_variable_count
            and variable in observed
            and variable not in seen
        ):
            result.append(variable)
            seen.add(variable)
    ranked_count = len(result)
    result.extend(
        variable
        for variable in range(1, key_variable_count + 1)
        if variable in observed and variable not in seen
    )
    if not result:
        raise _error("empty observed key candidate order")
    return tuple(result), ranked_count


def _bound_token_identities(
    bound: Mapping[str, object],
) -> dict[int, tuple[int, int, int]]:
    result: dict[int, tuple[int, int, int]] = {}
    for raw in _sequence(bound.get("interventions"), "bound interventions"):
        row = _mapping(raw, "bound intervention")
        token = _positive(row.get("token"), "bound intervention token")
        identity = (
            _positive(row.get("call"), "bound intervention call"),
            _nonnegative(row.get("coordinate_index"), "bound intervention coordinate"),
            _literal(row.get("losing_literal"), "bound intervention literal"),
        )
        if token in result:
            raise _error("duplicate bound intervention token")
        result[token] = identity
    return result


def _validate_owned_literals(
    replay: _OwnershipReplay,
    *,
    prefix: _v20.RescuePrefixPreemptionPlan,
    effective_rank: tuple[int, ...],
    frontier: _v20.CausalFrontierPlan,
    bound_reader: Mapping[str, object],
) -> None:
    bound_tokens = _bound_token_identities(bound_reader)
    for event in replay.events:
        if event.get("kind") == "FOREIGN_ASSIGNMENT":
            continue
        origin = cast(str, event.get("origin"))
        row = _nonnegative(event.get("row"), "owned event row")
        literal = _literal(event.get("literal"), "owned event literal")
        token = _positive(event.get("token"), "owned event token")
        if origin == BOUND_ORIGIN:
            identity = bound_tokens.get(token)
            if identity is None or identity != (
                _positive(event.get("callback"), "bound ownership callback"),
                row,
                literal,
            ):
                raise _error("bound owned event identity")
        elif literal != _v20._expected_literal(
            origin,
            row,
            prefix=prefix,
            effective_rank=effective_rank,
            frontier=frontier,
        ):
            raise _error("owned event literal")


def _validate_central_nested(
    central: Mapping[str, object],
    *,
    ownership: Mapping[str, object],
    effective_rank: tuple[int, ...],
    frontier_plan: _v20.CausalFrontierPlan,
    staging_plan: _v20.ResidualPolarityStagingPlan,
    prefix_plan: _v20.RescuePrefixPreemptionPlan,
    return_events: Sequence[object],
) -> None:
    prefix = _mapping(central.get("prefix"), "central prefix")
    rank = _mapping(central.get("rank"), "central rank")
    frontier = _mapping(central.get("frontier"), "central frontier")
    staging = _mapping(central.get("staging"), "central staging")
    if (
        set(prefix)
        != {
            "rows",
            "cursor",
            "returns",
            "releases",
            "skipped_preassigned_falsifying",
            "skipped_preassigned_rescue",
        }
        or set(rank)
        != {
            "rows",
            "cursor",
            "original_returns",
            "original_releases",
            "contrast_enqueued",
            "contrast_returns",
            "contrast_releases",
            "skipped_preassigned",
        }
        or set(frontier)
        != {
            "rows",
            "cursor",
            "initial_returns",
            "initial_releases",
            "contrast_enqueued",
            "contrast_returns",
            "contrast_releases",
            "skipped_preassigned_falsifying",
            "skipped_preassigned_rescue",
            "live_false_literal_count",
            "live_true_literal_count",
            "live_unassigned_literal_count",
        }
        or set(staging)
        != {
            "overlay_rows",
            "effective_original_returns",
            "source_contrast_returns",
            "proposal_activated",
            "level_bound_activated",
            "confirmed_activated",
        }
    ):
        raise _error("central nested fields")
    prefix_counts = {
        name: _nonnegative(prefix.get(name), f"prefix {name}") for name in prefix
    }
    rank_counts = {name: _nonnegative(rank.get(name), f"rank {name}") for name in rank}
    frontier_counts = {
        name: _nonnegative(frontier.get(name), f"frontier {name}") for name in frontier
    }
    staging_counts = {
        name: _nonnegative(staging.get(name), f"staging {name}")
        for name in (
            "overlay_rows",
            "effective_original_returns",
            "source_contrast_returns",
        )
    }
    raw_origin_counts = _mapping(ownership.get("origin_counts"), "origin counts")
    origins = {
        origin: _mapping(raw_origin_counts.get(origin), f"origin {origin}")
        for origin in ORIGINS
    }
    if (
        prefix.get("rows") != len(prefix_plan.prefix_literals)
        or rank.get("rows") != len(effective_rank)
        or frontier.get("rows") != len(frontier_plan.residual_clause_literals)
        or staging.get("overlay_rows") != len(staging_plan.overlays)
        or prefix.get("returns") != origins["PREFIX"].get("proposals")
        or rank.get("original_returns") != origins["RANK_ORIGINAL"].get("proposals")
        or rank.get("contrast_returns") != origins["RANK_CONTRAST"].get("proposals")
        or frontier.get("initial_returns")
        != origins["FRONTIER_INITIAL"].get("proposals")
        or frontier.get("contrast_returns")
        != origins["FRONTIER_CONTRAST"].get("proposals")
        or prefix_counts["cursor"]
        != prefix_counts["returns"]
        + prefix_counts["skipped_preassigned_falsifying"]
        + prefix_counts["skipped_preassigned_rescue"]
        or prefix_counts["cursor"] != prefix_counts["rows"]
        or prefix_counts["releases"] > prefix_counts["returns"]
        or prefix_counts["releases"] != origins["PREFIX"].get("releases")
        or rank_counts["cursor"]
        != rank_counts["original_returns"] + rank_counts["skipped_preassigned"]
        or rank_counts["cursor"] > rank_counts["rows"]
        or rank_counts["original_releases"] > rank_counts["original_returns"]
        or rank_counts["contrast_enqueued"] != rank_counts["original_releases"]
        or rank_counts["contrast_returns"] > rank_counts["contrast_enqueued"]
        or rank_counts["contrast_releases"] > rank_counts["contrast_returns"]
        or rank_counts["original_releases"] != origins["RANK_ORIGINAL"].get("releases")
        or rank_counts["contrast_releases"] != origins["RANK_CONTRAST"].get("releases")
        or frontier_counts["cursor"]
        != frontier_counts["initial_returns"]
        + frontier_counts["skipped_preassigned_falsifying"]
        + frontier_counts["skipped_preassigned_rescue"]
        or frontier_counts["cursor"] > frontier_counts["rows"]
        or frontier_counts["initial_releases"] > frontier_counts["initial_returns"]
        or frontier_counts["contrast_enqueued"] != frontier_counts["initial_releases"]
        or frontier_counts["contrast_returns"] > frontier_counts["contrast_enqueued"]
        or frontier_counts["contrast_releases"] > frontier_counts["contrast_returns"]
        or frontier_counts["initial_releases"]
        != origins["FRONTIER_INITIAL"].get("releases")
        or frontier_counts["contrast_releases"]
        != origins["FRONTIER_CONTRAST"].get("releases")
        or frontier_counts["live_false_literal_count"]
        + frontier_counts["live_true_literal_count"]
        + frontier_counts["live_unassigned_literal_count"]
        != frontier_plan.selected_clause_literal_count
        or staging_counts["effective_original_returns"]
        > rank_counts["original_returns"]
        or staging_counts["source_contrast_returns"] > rank_counts["contrast_returns"]
        or _boolean(staging.get("proposal_activated"), "staging proposal activation")
        != bool(staging_counts["effective_original_returns"])
    ):
        raise _error("central stage projection")

    ownership_events = tuple(
        _mapping(item, "ownership event")
        for item in _sequence(ownership.get("events"), "ownership events")
    )
    overlay_rows = {overlay.rank_index for overlay in staging_plan.overlays}
    staged_bound = any(
        event.get("kind") == "LEVEL_BOUND"
        and event.get("origin") == "RANK_ORIGINAL"
        and event.get("row") in overlay_rows
        for event in ownership_events
    )
    staged_confirmed = any(
        event.get("kind") == "CONFIRMED"
        and event.get("origin") == "RANK_ORIGINAL"
        and event.get("row") in overlay_rows
        for event in ownership_events
    )
    if (
        _boolean(staging.get("level_bound_activated"), "staging level activation")
        != staged_bound
        or _boolean(staging.get("confirmed_activated"), "staging confirmation")
        != staged_confirmed
    ):
        raise _error("staging activation semantics")

    legacy_events = [
        _mapping(item, "return event")
        for item in return_events
        if _mapping(item, "return event").get("origin") != BOUND_ORIGIN
    ]
    origin_rows = {
        origin: [
            _nonnegative(event.get("row"), f"{origin} return row")
            for event in legacy_events
            if event.get("origin") == origin
        ]
        for origin in _v20.ORIGINS
    }
    non_prefix = [
        index
        for index, event in enumerate(legacy_events)
        if event.get("origin") != "PREFIX"
    ]
    if non_prefix and any(
        event.get("origin") == "PREFIX" for event in legacy_events[non_prefix[0] :]
    ):
        raise _error("prefix scheduling")
    lower = [
        index
        for index, event in enumerate(legacy_events)
        if event.get("origin")
        in {"RANK_CONTRAST", "FRONTIER_INITIAL", "FRONTIER_CONTRAST"}
    ]
    if lower and any(
        event.get("origin") == "RANK_ORIGINAL" for event in legacy_events[lower[0] :]
    ):
        raise _error("rank-original scheduling")
    for origin in ("PREFIX", "RANK_ORIGINAL", "FRONTIER_INITIAL"):
        if origin_rows[origin] != sorted(origin_rows[origin]) or len(
            origin_rows[origin]
        ) != len(set(origin_rows[origin])):
            raise _error(f"{origin} row chronology")
    if origin_rows["RANK_CONTRAST"] and rank_counts["cursor"] != rank_counts["rows"]:
        raise _error("rank contrast before original exhaustion")
    if (
        origin_rows["FRONTIER_CONTRAST"]
        and frontier_counts["cursor"] != frontier_counts["rows"]
    ):
        raise _error("frontier contrast before initial exhaustion")


def _validate_central(
    value: object,
    *,
    replay: _OwnershipReplay,
    input_vault: _v20.ThresholdNoGoodVault,
    rank_source_vault: _v20.ThresholdNoGoodVault,
    expected_decision: _v20.VaultRankedDecision,
    effective_rank: tuple[int, ...],
    frontier_plan: _v20.CausalFrontierPlan,
    staging_plan: _v20.ResidualPolarityStagingPlan,
    prefix_plan: _v20.RescuePrefixPreemptionPlan,
    potential_sha256: str,
    potential_source_sha256: str,
    grouping_sha256: str,
    bound_validation: OneBitBoundValidation,
    candidate_order: tuple[int, ...],
) -> Mapping[str, object]:
    central = _mapping(value, "central reader")
    if set(central) != _CENTRAL_FIELDS:
        raise _error("central reader fields")
    effective_bytes = b"".join(struct.pack("<i", item) for item in effective_rank)
    if (
        central.get("schema") != CENTRAL_READER_SCHEMA
        or central.get("operator") != CENTRAL_OPERATOR
        or central.get("selection_rule") != CENTRAL_SELECTION_RULE
        or central.get("release_rule") != CENTRAL_RELEASE_RULE
        or central.get("runtime_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or central.get("rank_source_vault_sha256") != rank_source_vault.sha256
        or central.get("active_vault_sha256") != input_vault.sha256
        or central.get("potential_sha256") != potential_sha256
        or central.get("potential_source_sha256") != potential_source_sha256
        or expected_decision.potential_source_sha256 != potential_source_sha256
        or central.get("grouping_sha256") != grouping_sha256
        or central.get("rank_table_sha256") != expected_decision.rank_table_sha256
        or central.get("effective_rank_order_sha256")
        != hashlib.sha256(effective_bytes).hexdigest()
        or central.get("frontier_plan_sha256") != frontier_plan.sha256
        or central.get("staging_plan_sha256") != staging_plan.sha256
        or central.get("prefix_plan_sha256") != prefix_plan.sha256
    ):
        raise _error("central reader binding")
    calls = _nonnegative(central.get("callback_calls"), "central callback calls")
    nonzero = _nonnegative(central.get("nonzero_returns"), "central returns")
    zero = _nonnegative(central.get("zero_returns"), "central zero returns")
    _nonnegative(
        central.get("assignment_literals_observed"), "assignment literals observed"
    )
    ownership = replay.ownership
    proposals = _nonnegative(ownership.get("proposals"), "ownership proposals")
    releases = _nonnegative(ownership.get("releases"), "ownership releases")
    if calls != nonzero + zero or nonzero != proposals:
        raise _error("central callback arithmetic")
    returned = _i32_sequence(central, "returned_sequence", calls)
    proposed = _i32_sequence(central, "proposal_sequence", proposals)
    released = _i32_sequence(central, "release_sequence", releases)
    if tuple(item for item in returned if item) != proposed:
        raise _error("central returned sequence composition")

    return_events = _sequence(central.get("return_events"), "central return events")
    if len(return_events) != proposals:
        raise _error("central return event count")
    central_proposals: list[tuple[int, int, object, int, int]] = []
    prior_call = 0
    for token, raw_event in enumerate(return_events, start=1):
        event = _mapping(raw_event, "central return event")
        if set(event) != {"call", "origin", "row", "literal", "token"}:
            raise _error("central return event fields")
        call = _positive(event.get("call"), "central return call")
        origin = event.get("origin")
        row = _nonnegative(event.get("row"), "central return row")
        literal = _literal(event.get("literal"), "central return literal")
        if (
            event.get("token") != token
            or origin not in ORIGINS
            or call <= prior_call
            or call > calls
            or returned[call - 1] != literal
        ):
            raise _error("central return event chronology")
        central_proposals.append((token, call, origin, row, literal))
        prior_call = call
    if tuple(row[4] for row in central_proposals) != proposed:
        raise _error("central proposal sequence")
    nonzero_calls = {row[1] for row in central_proposals}
    if any(
        bool(literal) != (call in nonzero_calls)
        for call, literal in enumerate(returned, start=1)
    ):
        raise _error("central zero-return projection")
    ownership_proposals = tuple(
        (
            _positive(event.get("token"), "ownership proposal token"),
            _positive(event.get("callback"), "ownership proposal callback"),
            event.get("origin"),
            _nonnegative(event.get("row"), "ownership proposal row"),
            _literal(event.get("literal"), "ownership proposal literal"),
        )
        for event in replay.events
        if event.get("kind") == "PROPOSED"
    )
    ownership_releases = tuple(
        _literal(event.get("literal"), "ownership release literal")
        for event in replay.events
        if event.get("kind") in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    )
    if (
        ownership_proposals != tuple(central_proposals)
        or ownership_releases != released
    ):
        raise _error("central ownership sequence binding")

    bound = _mapping(central.get("bound"), "central bound")
    if set(bound) != _CENTRAL_BOUND_FIELDS:
        raise _error("central bound fields")
    expected_bound = {
        "candidate_count": len(candidate_order),
        "parent_scans": calls,
        "probes": bound_validation.probe_count,
        "returns": bound_validation.crossing_count,
        "level_bindings": bound_validation.crossing_count,
        "matching_assignments": bound_validation.realized_prune_count,
        "realized_prunes": bound_validation.realized_prune_count,
        "releases": bound_validation.released_count,
        "live_tokens": bound_validation.live_count,
        "unobserved_releases": bound_validation.unobserved_release_count,
    }
    if (
        any(
            _nonnegative(bound.get(name), f"central bound {name}") != expected
            for name, expected in expected_bound.items()
        )
        or bound_validation.reader.get("parent_scans") != calls
    ):
        raise _error("central bound projection")
    if any(
        _positive(probe.get("call"), "bound probe call") > calls
        for probe in (
            _mapping(item, "bound probe")
            for item in _sequence(
                bound_validation.reader.get("probe_events"), "bound probe events"
            )
        )
    ):
        raise _error("bound probe callback range")
    _validate_central_nested(
        central,
        ownership=ownership,
        effective_rank=effective_rank,
        frontier_plan=frontier_plan,
        staging_plan=staging_plan,
        prefix_plan=prefix_plan,
        return_events=return_events,
    )
    return central


def _base_v6_payload(payload: Mapping[str, object]) -> dict[str, object]:
    return _v20._base_v6_payload(payload)


def _parse_native_payload(
    payload: object,
    *,
    input_vault: _v20.ThresholdNoGoodVault,
    rank_source_vault: _v20.ThresholdNoGoodVault,
    frontier_plan: _v20.CausalFrontierPlan,
    staging_plan: _v20.ResidualPolarityStagingPlan,
    prefix_preemption_plan: _v20.RescuePrefixPreemptionPlan,
    vault_caps: _v20.VaultCaps,
    field: _v20.CriticalityPotentialField,
    grouping: _v20.JointScoreCompatibilityGrouping,
    grouping_sha256: str,
    cnf_sha256: str,
    potential_sha256: str,
    threshold: float,
    requested_conflicts: int,
    seed: int,
    memory_limit_bytes: int | None,
    memory_samples: tuple[dict[str, int | float], ...],
    expected_decision: _v20.VaultRankedDecision,
) -> JointScoreSieveV21Result:
    """Fail closed over native v18, including its unchanged v6 parent."""

    root = _mapping(payload, "result")
    if set(root) != _TOP_LEVEL_FIELDS:
        raise _error("result fields")
    if (
        root.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or root.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or root.get("rank_source_vault_sha256") != rank_source_vault.sha256
        or root.get("active_vault_sha256") != input_vault.sha256
        or root.get("frontier_plan_sha256") != frontier_plan.sha256
        or root.get("staging_plan_sha256") != staging_plan.sha256
        or root.get("prefix_preemption_plan_sha256") != prefix_preemption_plan.sha256
    ):
        raise _error("result identity")
    effective_rank = _v20._effective_rank_literals(expected_decision, staging_plan)
    candidate_order, ranked_count = _candidate_order_from_inputs(
        expected_decision=expected_decision,
        staging_plan=staging_plan,
        field=field,
    )
    replay = _replay_ownership(root.get("decision_ownership"))
    bound_validation = validate_one_bit_bound_reader(
        root.get("one_bit_bound_reader"),
        decision_ownership=replay.ownership,
        sieve=root.get("sieve"),
        vault=root.get("vault"),
        threshold=threshold,
        candidate_order=candidate_order,
        ranked_candidate_count=ranked_count,
    )
    _validate_owned_literals(
        replay,
        prefix=prefix_preemption_plan,
        effective_rank=effective_rank,
        frontier=frontier_plan,
        bound_reader=bound_validation.reader,
    )
    central = _validate_central(
        root.get("central_reader"),
        replay=replay,
        input_vault=input_vault,
        rank_source_vault=rank_source_vault,
        expected_decision=expected_decision,
        effective_rank=effective_rank,
        frontier_plan=frontier_plan,
        staging_plan=staging_plan,
        prefix_plan=prefix_preemption_plan,
        potential_sha256=potential_sha256,
        potential_source_sha256=field.source_sha256,
        grouping_sha256=grouping_sha256,
        bound_validation=bound_validation,
        candidate_order=candidate_order,
    )
    try:
        parent = _v20._v9._parse_native_payload(
            _base_v6_payload(root),
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha256,
            cnf_sha256=cnf_sha256,
            potential_sha256=potential_sha256,
            threshold=threshold,
            requested_conflicts=requested_conflicts,
            seed=seed,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=memory_samples,
        )
    except O1RelationalSearchError as exc:
        raise _error("unchanged v6 parent") from exc
    if parent.sieve.get("cb_decide_calls") != central.get("callback_calls"):
        raise _error("one-v6-call-per-central-callback")
    values = dict(parent.__dict__)
    values.update(
        raw=dict(root),
        rank_source_vault=rank_source_vault,
        expected_decision=expected_decision,
        frontier_plan=frontier_plan,
        staging_plan=staging_plan,
        prefix_preemption_plan=prefix_preemption_plan,
        central_reader=central,
        decision_ownership=replay.ownership,
        one_bit_bound_reader=bound_validation.reader,
        one_bit_bound_validation=bound_validation,
    )
    return JointScoreSieveV21Result(**values)  # pyright: ignore[reportArgumentType]


derive_production_vault_ranked_decision = _v20.derive_production_vault_ranked_decision


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    rank_vault_path: str | Path,
    vault_path: str | Path,
    frontier_plan_path: str | Path,
    staging_plan_path: str | Path,
    prefix_plan_path: str | Path,
    vault_caps: _v20.VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV21Result:
    requested = _v20._v9._requested_conflicts(conflict_limit)
    if (
        not isinstance(vault_caps, _v20.VaultCaps)
        or vault_caps != _v20.O1C66_VAULT_CAPS
    ):
        raise _error("native vault caps")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed != 0
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or (
            memory_limit_bytes is not None
            and (
                isinstance(memory_limit_bytes, bool)
                or not isinstance(memory_limit_bytes, int)
                or memory_limit_bytes <= 0
            )
        )
    ):
        raise _error("threshold, seed, timeout, or memory limit")
    requested_threshold = float(threshold)
    io_v1 = _v20._v9._v8._v1
    io_v8 = _v20._v9._v8
    executable_file, executable_bytes, _ = io_v1._read_input(executable, "executable")
    cnf_file, cnf_bytes, cnf_sha = io_v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = io_v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = io_v1._read_input(
        grouping_path, "grouping"
    )
    rank_vault_file, rank_vault_bytes = io_v8._read_bounded_vault_input(
        rank_vault_path, caps=vault_caps
    )
    active_vault_file, active_vault_bytes = io_v8._read_bounded_vault_input(
        vault_path, caps=vault_caps
    )
    try:
        frontier_file, frontier_bytes = (
            _v20._v19._v18._v17._frontier._read_regular_file(frontier_plan_path)
        )
        staging_file, staging_bytes = _v20._v19._v18._staging._read_regular_file(
            staging_plan_path
        )
        prefix_file, prefix_bytes = _v20._v19._prefix._read_regular_file(
            prefix_plan_path
        )
    except (
        _v20.CausalFrontierError,
        _v20.ResidualPolarityStagingError,
        _v20.RescuePrefixPreemptionError,
    ) as exc:
        raise _error("plan input") from exc

    field = io_v1._potential(potential_bytes)
    grouping = io_v8._v7.validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise _error("grouping potential identity")
    try:
        expected_decision = derive_production_vault_ranked_decision(
            rank_vault_bytes, potential_bytes, grouping_bytes
        )
    except _v20.VaultRankedDecisionError as exc:
        raise _error("sealed rank-source decision") from exc
    identity = _v20.vault_identity_from_sources(
        cnf_sha256=cnf_sha,
        potential_sha256=potential_sha,
        grouping_sha256=grouping_sha,
        observed_variables=field.observed_variables,
        bound_rule=_v20.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=requested_threshold,
    )
    rank_source_vault = _v20._v19._parse_and_certify_vault(
        rank_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="rank-source",
    )
    input_vault = _v20._v19._parse_and_certify_vault(
        active_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="active",
    )
    try:
        frontier_plan = _v20.parse_causal_frontier_plan(
            frontier_bytes, active_vault=input_vault
        )
        staging_plan = _v20.parse_residual_polarity_staging_plan(
            staging_bytes,
            active_vault=input_vault,
            rank_decision=expected_decision,
        )
        prefix_plan = _v20.parse_rescue_prefix_preemption_plan(
            prefix_bytes, active_vault=input_vault
        )
        _v20.validate_rescue_prefix_preemption_plan(
            prefix_plan,
            active_vault=input_vault,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=_v20.O1C78_BASELINE_TRACE_SHA256,
            required_prefix_literals=_v20.O1C78_PREFIX_LITERALS,
        )
        _v20.validate_o1c78_production_plan(prefix_plan)
    except (
        _v20.CausalFrontierError,
        _v20.ResidualPolarityStagingError,
        _v20.RescuePrefixPreemptionError,
    ) as exc:
        raise _error("plan certification") from exc
    if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
        raise _error("parent frontier plan binding")

    rank_path, rank_bytes = _v20._v19._v18._v17._v16._v15._v14._v13._rank_table_temp(
        expected_decision
    )
    command = [
        str(executable_file),
        "--cnf",
        str(cnf_file),
        "--potential",
        str(potential_file),
        "--grouping",
        str(grouping_file),
        "--rank-vault",
        str(rank_vault_file),
        "--vault-in",
        str(active_vault_file),
        "--rank-table",
        str(rank_path),
        "--frontier-plan",
        str(frontier_file),
        "--staging-plan",
        str(staging_file),
        "--prefix-plan",
        str(prefix_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: object | None = None
    try:
        try:
            execution = io_v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
        try:
            io_v1._verify_stable_input(
                executable, executable_file, executable_bytes, field="executable"
            )
            io_v1._verify_stable_input(cnf_path, cnf_file, cnf_bytes, field="CNF")
            io_v1._verify_stable_input(
                potential_path, potential_file, potential_bytes, field="potential"
            )
            io_v1._verify_stable_input(
                grouping_path, grouping_file, grouping_bytes, field="grouping"
            )
            io_v8._verify_stable_vault_input(
                rank_vault_path, rank_vault_file, rank_vault_bytes, caps=vault_caps
            )
            io_v8._verify_stable_vault_input(
                vault_path, active_vault_file, active_vault_bytes, caps=vault_caps
            )
            io_v1._verify_stable_input(
                frontier_plan_path,
                frontier_file,
                frontier_bytes,
                field="frontier plan",
            )
            io_v1._verify_stable_input(
                staging_plan_path,
                staging_file,
                staging_bytes,
                field="staging plan",
            )
            io_v1._verify_stable_input(
                prefix_plan_path, prefix_file, prefix_bytes, field="prefix plan"
            )
            if rank_path.read_bytes() != rank_bytes:
                raise _error("rank table changed during execution")
        except Exception as exc:
            if execution is not None:
                _v20._v9._attach_native_process_evidence(
                    exc,
                    command=command,
                    completed=execution.completed,  # type: ignore[attr-defined]
                    memory_samples=execution.memory_samples,  # type: ignore[attr-defined]
                )
            raise
    finally:
        try:
            rank_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise _error("rank table cleanup") from exc
    if execution_error is not None:
        raise _error("execution") from execution_error
    if execution is None:
        raise _error("execution")
    completed = execution.completed  # type: ignore[attr-defined]
    memory_samples = execution.memory_samples  # type: ignore[attr-defined]
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v20._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v21 execution failed: {detail}"
        ) from failure
    try:
        result = _parse_native_payload(
            load_native_json(completed.stdout),
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
            frontier_plan=frontier_plan,
            staging_plan=staging_plan,
            prefix_preemption_plan=prefix_plan,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha,
            cnf_sha256=cnf_sha,
            potential_sha256=potential_sha,
            threshold=requested_threshold,
            requested_conflicts=requested,
            seed=0,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=memory_samples,
            expected_decision=expected_decision,
        )
        return replace(
            result,
            stats=_v20._v9.derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
            native_stdout=completed.stdout,
            native_stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest(),
        )
    except Exception as exc:
        _v20._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    rank_vault_path: str | Path,
    vault_path: str | Path,
    frontier_plan_path: str | Path,
    staging_plan_path: str | Path,
    prefix_plan_path: str | Path,
    vault_caps: _v20.VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV21Result:
    """Run native v18 once with stable inputs and complete proof replay."""

    started = time.perf_counter()
    try:
        return _run_joint_score_sieve_native_contract(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
            rank_vault_path=rank_vault_path,
            vault_path=vault_path,
            frontier_plan_path=frontier_plan_path,
            staging_plan_path=staging_plan_path,
            prefix_plan_path=prefix_plan_path,
            vault_caps=vault_caps,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v20._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v21"):
            message = f"joint-score-sieve-v21 adapter failed: {message}"
        raise _v20.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


def _candidate_order_from_reader(reader: Mapping[str, object]) -> tuple[int, ...]:
    count = _positive(reader.get("candidate_order_count"), "candidate order count")
    hexadecimal = reader.get("candidate_order_hex")
    if not isinstance(hexadecimal, str):
        raise _error("candidate order hex")
    try:
        payload = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise _error("candidate order hex") from exc
    if len(payload) != 4 * count:
        raise _error("candidate order bytes")
    result = tuple(item[0] for item in struct.iter_unpack("<i", payload))
    _candidate_sequence(reader, result)
    return result


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v18 teardown, ownership, bounds and central sequence linkage."""

    root = _mapping(payload, "lifecycle payload")
    if (
        set(root) != _TOP_LEVEL_FIELDS
        or root.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or root.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise _error("lifecycle identity")
    normalized = _v20._v9.validate_native_lifecycle(_base_v6_payload(root))
    replay = _replay_ownership(root.get("decision_ownership"))
    reader = _mapping(root.get("one_bit_bound_reader"), "one-bit bound reader")
    candidate_order = _candidate_order_from_reader(reader)
    ranked_count = _nonnegative(
        reader.get("ranked_candidate_count"), "ranked candidate count"
    )
    threshold = reader.get("threshold")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
    ):
        raise _error("lifecycle threshold")
    bound_validation = validate_one_bit_bound_reader(
        reader,
        decision_ownership=replay.ownership,
        sieve=root.get("sieve"),
        vault=root.get("vault"),
        threshold=float(threshold),
        candidate_order=candidate_order,
        ranked_candidate_count=ranked_count,
    )
    central = _mapping(root.get("central_reader"), "central reader")
    if (
        set(central) != _CENTRAL_FIELDS
        or central.get("schema") != CENTRAL_READER_SCHEMA
        or central.get("operator") != CENTRAL_OPERATOR
        or central.get("selection_rule") != CENTRAL_SELECTION_RULE
        or central.get("release_rule") != CENTRAL_RELEASE_RULE
        or central.get("runtime_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise _error("lifecycle central identity")
    calls = _nonnegative(central.get("callback_calls"), "central callback calls")
    proposals = _nonnegative(replay.ownership.get("proposals"), "ownership proposals")
    releases = _nonnegative(replay.ownership.get("releases"), "ownership releases")
    if (
        calls
        != _nonnegative(central.get("nonzero_returns"), "central nonzero returns")
        + _nonnegative(central.get("zero_returns"), "central zero returns")
        or central.get("nonzero_returns") != proposals
        or _mapping(root.get("sieve"), "sieve").get("cb_decide_calls") != calls
    ):
        raise _error("lifecycle callback composition")
    returned = _i32_sequence(central, "returned_sequence", calls)
    proposed = _i32_sequence(central, "proposal_sequence", proposals)
    released = _i32_sequence(central, "release_sequence", releases)
    events = tuple(
        _mapping(item, "central return event")
        for item in _sequence(central.get("return_events"), "central return events")
    )
    central_proposals: list[tuple[int, int, object, int, int]] = []
    prior_call = 0
    for token, event in enumerate(events, start=1):
        if set(event) != {"call", "origin", "row", "literal", "token"}:
            raise _error("lifecycle return event fields")
        call = _positive(event.get("call"), "lifecycle return call")
        literal = _literal(event.get("literal"), "lifecycle return literal")
        origin = event.get("origin")
        row = _nonnegative(event.get("row"), "lifecycle return row")
        if (
            event.get("token") != token
            or origin not in ORIGINS
            or call <= prior_call
            or call > calls
            or returned[call - 1] != literal
        ):
            raise _error("lifecycle return chronology")
        central_proposals.append((token, call, origin, row, literal))
        prior_call = call
    ownership_proposals = tuple(
        (
            _positive(event.get("token"), "lifecycle proposal token"),
            _positive(event.get("callback"), "lifecycle proposal callback"),
            event.get("origin"),
            _nonnegative(event.get("row"), "lifecycle proposal row"),
            _literal(event.get("literal"), "lifecycle proposal literal"),
        )
        for event in replay.events
        if event.get("kind") == "PROPOSED"
    )
    ownership_releases = tuple(
        _literal(event.get("literal"), "lifecycle release literal")
        for event in replay.events
        if event.get("kind") in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    )
    if (
        len(events) != proposals
        or tuple(item for item in returned if item) != proposed
        or tuple(row[4] for row in central_proposals) != proposed
        or ownership_proposals != tuple(central_proposals)
        or ownership_releases != released
    ):
        raise _error("lifecycle sequence composition")
    bound = _mapping(central.get("bound"), "central bound")
    expected_bound = {
        "candidate_count": len(candidate_order),
        "parent_scans": calls,
        "probes": bound_validation.probe_count,
        "returns": bound_validation.crossing_count,
        "level_bindings": bound_validation.crossing_count,
        "matching_assignments": bound_validation.realized_prune_count,
        "realized_prunes": bound_validation.realized_prune_count,
        "releases": bound_validation.released_count,
        "live_tokens": bound_validation.live_count,
        "unobserved_releases": bound_validation.unobserved_release_count,
    }
    if set(bound) != _CENTRAL_BOUND_FIELDS or any(
        _nonnegative(bound.get(name), f"lifecycle bound {name}") != expected
        for name, expected in expected_bound.items()
    ):
        raise _error("lifecycle bound composition")
    normalized["central_callback_calls"] = calls
    normalized["ownership_proposals"] = proposals
    normalized["bound_proposals"] = bound_validation.crossing_count
    normalized["bound_live_tokens"] = bound_validation.live_count
    return normalized


JOINT_SCORE_SIEVE_BOUND_RULE = _v20.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v20.JointScoreSieveExecutionError
build_native_joint_score_sieve = _v20.build_native_joint_score_sieve
write_joint_score_sieve_grouping = _v20.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v20.write_joint_score_sieve_potential


__all__ = [
    "BOUND_ORIGIN",
    "CENTRAL_OPERATOR",
    "CENTRAL_READER_SCHEMA",
    "CENTRAL_RELEASE_RULE",
    "CENTRAL_SELECTION_RULE",
    "DECISION_OWNERSHIP_SCHEMA",
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JointScoreSieveExecutionError",
    "JointScoreSieveV21Result",
    "ONE_BIT_BOUND_READER_SCHEMA",
    "OneBitBoundValidation",
    "build_native_joint_score_sieve",
    "load_native_json",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
    "validate_one_bit_bound_reader",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
