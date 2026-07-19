"""Strict causal-frontier adapter for native joint sieve v14.

The native envelope preserves the complete v13 parent reader unchanged and
adds a separate ``frontier`` telemetry object.  This adapter validates the
outer callback sequence and plan causality, projects the parent-shaped payload
back to v13, and then delegates all frozen sieve/vault validation to v16.
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

from . import causal_frontier_v1 as _frontier
from . import joint_score_sieve_v16 as _v16
from .causal_frontier_v1 import CausalFrontierError, CausalFrontierPlan
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultIdentity,
    VaultCaps,
    vault_identity_from_sources,
)
from .vault_ranked_decision_v1 import (
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_production_vault_ranked_decision,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v17-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v14"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v16.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA = _v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
JOINT_SCORE_SIEVE_V16_RELEASE_PARENT_SCHEMA = (
    _v16.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_BOUND_RULE = _v16.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v16.JointScoreSieveExecutionError
write_joint_score_sieve_grouping = _v16.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v16.write_joint_score_sieve_potential

CAUSAL_FRONTIER_READER_SCHEMA = "o1-256-cadical-causal-frontier-reader-v1"
CAUSAL_FRONTIER_OPERATOR = "parent-first-causal-frontier-falsify-then-released-rescue"
CAUSAL_FRONTIER_STATE_ENCODING = "residual-plan-index-lsb-first"
CAUSAL_FRONTIER_SEQUENCE_ENCODING = (
    "concatenated-signed-i32le-literals-in-observation-order"
)
CAUSAL_FRONTIER_RETURNED_SEQUENCE_ENCODING = (
    "one-signed-i32le-literal-per-cb-decide-including-zero"
)
CAUSAL_FRONTIER_DECISION_RULE = (
    "parent-nonzero-unchanged;parent-zero-consume-initial-residual-to-"
    "exhaustion;then-earliest-released-currently-unassigned-satisfying-"
    "opposite-once;zero-delegates"
)
CAUSAL_FRONTIER_CALLBACK_RULE = (
    "call-parent-every-callback;initial-assigned-rows-consumed-and-"
    "classified-once;enqueue-genuine-initial-release;defer-assigned-"
    "contrast;never-repeat-frontier-row-kind"
)
CAUSAL_FRONTIER_BOUNDED_STATE_RULE = (
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "nine-residual-bitsets;bounded-u32-release-order;bounded-two-events-"
    "and-one-pair-record-per-residual;incremental-all-callback-sha256"
)

_TOP_LEVEL_FIELDS = _v16._TOP_LEVEL_FIELDS | {
    "frontier_plan_sha256",
    "frontier_source_result_sha256",
    "frontier",
}

_STATE_PREFIXES = (
    "consumed_state",
    "initial_returned_state",
    "initial_released_state",
    "contrast_enqueued_state",
    "contrast_returned_state",
    "contrast_released_state",
    "skipped_falsifying_state",
    "skipped_rescue_state",
    "contrast_deferred_assigned_state",
)
_SEQUENCE_PREFIXES = (
    "initial_return_sequence",
    "initial_release_sequence",
    "contrast_return_sequence",
    "contrast_release_sequence",
)
_FRONTIER_BASE_FIELDS = {
    "schema",
    "operator",
    "plan_sha256",
    "source_result_sha256",
    "source_assignment_sha256",
    "active_vault_sha256",
    "selected_active_index",
    "selected_union_index",
    "selected_clause_sha256",
    "selected_clause_literal_count",
    "prior_false_literal_count",
    "prior_true_literal_count",
    "prior_unassigned_literal_count",
    "residual_clause_literals",
    "falsifying_decision_literals",
    "decision_rule",
    "callback_rule",
    "cursor",
    "rows_consumed",
    "initial_once_returns",
    "initial_skipped_preassigned_falsifying",
    "initial_skipped_preassigned_rescue",
    "initial_releases",
    "contrast_enqueued",
    "contrast_returns",
    "contrast_releases",
    "contrast_deferred_assigned",
    "queue_size",
    "maximum_queue_size",
    "cb_decide_calls",
    "parent_nonzero_returns",
    "parent_zero_returns",
    "outer_nonzero_returns",
    "outer_zero_returns",
    "first_parent_zero_call",
    "first_frontier_return_call",
    "first_outer_zero_call",
    "assignment_literals_observed",
    "live_false_literal_count",
    "live_true_literal_count",
    "live_unassigned_literal_count",
    "minimum_live_false_literal_count",
    "minimum_live_true_literal_count",
    "minimum_live_unassigned_literal_count",
    "prior_distance_reached",
    "unit_distance_reached",
    "returned_sequence_encoding",
    "returned_sequence_count",
    "returned_sequence_bytes",
    "returned_sequence_sha256",
    "substitution_events",
    "pair_records",
    "bounded_state_rule",
    "bounded_guidance_state_bytes",
    "live_guidance_state_bytes",
    "bounded_telemetry_state_bytes",
}
_FRONTIER_FIELDS = set(_FRONTIER_BASE_FIELDS)
for _prefix in _STATE_PREFIXES:
    _FRONTIER_FIELDS.update(
        {
            f"{_prefix}_bits",
            f"{_prefix}_bytes",
            f"{_prefix}_encoding",
            f"{_prefix}_hex",
            f"{_prefix}_sha256",
        }
    )
for _prefix in _SEQUENCE_PREFIXES:
    _FRONTIER_FIELDS.update(
        {
            f"{_prefix}_encoding",
            f"{_prefix}_count",
            f"{_prefix}_bytes",
            f"{_prefix}_hex",
            f"{_prefix}_sha256",
        }
    )


@dataclass(frozen=True)
class JointScoreSieveV17Result(_v16.JointScoreSieveV16Result):
    """A v16-validated result retaining its plan and outer reader."""

    frontier_plan: CausalFrontierPlan
    frontier_reader: Mapping[str, object]

    @property
    def frontier_plan_sha256(self) -> str:
        return self.frontier_plan.sha256

    @property
    def frontier(self) -> Mapping[str, object]:
        return self.frontier_reader


@dataclass(frozen=True)
class _LifecycleFrontierPlanView:
    """Telemetry-only plan view; it never substitutes for binary parsing."""

    sha256: str
    source_result_sha256: str
    source_assignment_sha256: str
    active_vault_sha256: str
    selected_active_index: int
    selected_union_index: int
    selected_clause_sha256: str
    selected_clause_literal_count: int
    false_literal_count: int
    true_literal_count: int
    unassigned_literal_count: int
    prior_assignment: Sequence[int]
    residual_clause_literals: tuple[int, ...]
    falsifying_decision_literals: tuple[int, ...]


def __getattr__(name: str) -> object:
    """Expose the unchanged v16 public surface without copying it."""

    try:
        return getattr(_v16, name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc


def _error(field: str) -> O1RelationalSearchError:
    return O1RelationalSearchError(f"joint-score-sieve-v17 {field} differs")


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _error(field)
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _error(field)
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(field)
    return value


def _positive_int(value: object, field: str) -> int:
    result = _nonnegative_int(value, field)
    if not result:
        raise _error(field)
    return result


def _nullable_positive(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _positive_int(value, field)


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _error(field)
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _error(field)
    return value


def _literal_list(value: object, field: str) -> tuple[int, ...]:
    rows = _sequence(value, field)
    result: list[int] = []
    previous = 0
    for value in rows:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value == 0
            or not -(1 << 31) < value < (1 << 31)
            or abs(value) <= previous
        ):
            raise _error(field)
        previous = abs(value)
        result.append(value)
    return tuple(result)


def _hex_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise _error(field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise _error(field) from exc


def _state_bits(
    frontier: Mapping[str, object], prefix: str, *, plan_rows: int
) -> tuple[bool, ...]:
    expected_bytes = (plan_rows + 7) // 8
    payload = _hex_bytes(frontier.get(f"{prefix}_hex"), f"{prefix} hex")
    if (
        frontier.get(f"{prefix}_encoding") != CAUSAL_FRONTIER_STATE_ENCODING
        or frontier.get(f"{prefix}_bits") != plan_rows
        or frontier.get(f"{prefix}_bytes") != expected_bytes
        or len(payload) != expected_bytes
        or _sha256(frontier.get(f"{prefix}_sha256"), f"{prefix} hash")
        != hashlib.sha256(payload).hexdigest()
        or (plan_rows % 8 and payload and payload[-1] & ~((1 << (plan_rows % 8)) - 1))
    ):
        raise _error(f"{prefix} state")
    return tuple(
        bool(payload[index // 8] & (1 << (index % 8))) for index in range(plan_rows)
    )


def _literal_sequence(
    frontier: Mapping[str, object],
    prefix: str,
    *,
    expected_count: int,
) -> tuple[int, ...]:
    payload = _hex_bytes(frontier.get(f"{prefix}_hex"), f"{prefix} hex")
    if (
        frontier.get(f"{prefix}_encoding") != CAUSAL_FRONTIER_SEQUENCE_ENCODING
        or frontier.get(f"{prefix}_count") != expected_count
        or frontier.get(f"{prefix}_bytes") != 4 * expected_count
        or len(payload) != 4 * expected_count
        or _sha256(frontier.get(f"{prefix}_sha256"), f"{prefix} hash")
        != hashlib.sha256(payload).hexdigest()
    ):
        raise _error(f"{prefix} sequence")
    return tuple(
        struct.unpack_from("<i", payload, 4 * index)[0]
        for index in range(expected_count)
    )


def _parent_nonzero_events(reader: Mapping[str, object], calls: int) -> dict[int, int]:
    events = _sequence(reader.get("nonzero_return_events"), "parent events")
    result: dict[int, int] = {}
    previous_call = 0
    for raw_event in events:
        event = _mapping(raw_event, "parent event")
        call = _positive_int(event.get("call"), "parent event call")
        literal = event.get("literal")
        if (
            call <= previous_call
            or call > calls
            or isinstance(literal, bool)
            or not isinstance(literal, int)
            or not literal
            or not -(1 << 31) < literal < (1 << 31)
        ):
            raise _error("parent event causality")
        previous_call = call
        result[call] = literal
    return result


def _first_missing_call(calls: int, nonzero_calls: set[int]) -> int | None:
    candidate = 1
    while candidate <= calls and candidate in nonzero_calls:
        candidate += 1
    return candidate if candidate <= calls else None


def _hash_sparse_returns(calls: int, events: Mapping[int, int]) -> str:
    digest = hashlib.sha256()
    cursor = 1
    zero_chunk = b"\0" * 65_536
    for call, literal in sorted(events.items()):
        missing_bytes = 4 * (call - cursor)
        while missing_bytes:
            take = min(missing_bytes, len(zero_chunk))
            digest.update(zero_chunk[:take])
            missing_bytes -= take
        digest.update(struct.pack("<i", literal))
        cursor = call + 1
    missing_bytes = 4 * (calls + 1 - cursor)
    while missing_bytes:
        take = min(missing_bytes, len(zero_chunk))
        digest.update(zero_chunk[:take])
        missing_bytes -= take
    return digest.hexdigest()


def _validate_frontier_reader(
    value: object,
    *,
    plan: CausalFrontierPlan | _LifecycleFrontierPlanView,
    parent_reader: Mapping[str, object],
    require_frontier_intervention: bool,
) -> dict[str, object]:
    frontier = _mapping(value, "frontier reader")
    if set(frontier) != _FRONTIER_FIELDS:
        raise _error("frontier reader fields")
    if (
        frontier.get("schema") != CAUSAL_FRONTIER_READER_SCHEMA
        or frontier.get("operator") != CAUSAL_FRONTIER_OPERATOR
        or frontier.get("decision_rule") != CAUSAL_FRONTIER_DECISION_RULE
        or frontier.get("callback_rule") != CAUSAL_FRONTIER_CALLBACK_RULE
        or frontier.get("bounded_state_rule") != CAUSAL_FRONTIER_BOUNDED_STATE_RULE
        or _sha256(frontier.get("plan_sha256"), "frontier plan hash") != plan.sha256
        or _sha256(frontier.get("source_result_sha256"), "source result hash")
        != plan.source_result_sha256
        or _sha256(frontier.get("source_assignment_sha256"), "source assignment hash")
        != plan.source_assignment_sha256
        or _sha256(frontier.get("active_vault_sha256"), "active vault hash")
        != plan.active_vault_sha256
        or frontier.get("selected_active_index") != plan.selected_active_index
        or frontier.get("selected_union_index") != plan.selected_union_index
        or frontier.get("selected_clause_sha256") != plan.selected_clause_sha256
        or frontier.get("selected_clause_literal_count")
        != plan.selected_clause_literal_count
        or frontier.get("prior_false_literal_count") != plan.false_literal_count
        or frontier.get("prior_true_literal_count") != plan.true_literal_count
        or frontier.get("prior_unassigned_literal_count")
        != plan.unassigned_literal_count
        or _literal_list(frontier.get("residual_clause_literals"), "residual literals")
        != plan.residual_clause_literals
        or _literal_list(
            frontier.get("falsifying_decision_literals"), "decision literals"
        )
        != plan.falsifying_decision_literals
    ):
        raise _error("frontier plan binding")

    row_count = len(plan.residual_clause_literals)
    cursor = _nonnegative_int(frontier.get("cursor"), "frontier cursor")
    rows_consumed = _nonnegative_int(frontier.get("rows_consumed"), "rows consumed")
    initial_returns = _nonnegative_int(
        frontier.get("initial_once_returns"), "initial returns"
    )
    skipped_falsifying = _nonnegative_int(
        frontier.get("initial_skipped_preassigned_falsifying"),
        "falsifying skips",
    )
    skipped_rescue = _nonnegative_int(
        frontier.get("initial_skipped_preassigned_rescue"), "rescue skips"
    )
    initial_releases = _nonnegative_int(
        frontier.get("initial_releases"), "initial releases"
    )
    contrast_enqueued = _nonnegative_int(
        frontier.get("contrast_enqueued"), "contrast enqueued"
    )
    contrast_returns = _nonnegative_int(
        frontier.get("contrast_returns"), "contrast returns"
    )
    contrast_releases = _nonnegative_int(
        frontier.get("contrast_releases"), "contrast releases"
    )
    contrast_deferred = _nonnegative_int(
        frontier.get("contrast_deferred_assigned"), "contrast deferred"
    )
    queue_size = _nonnegative_int(frontier.get("queue_size"), "queue size")
    maximum_queue_size = _nonnegative_int(
        frontier.get("maximum_queue_size"), "maximum queue size"
    )
    calls = _nonnegative_int(frontier.get("cb_decide_calls"), "callback count")
    parent_nonzero = _nonnegative_int(
        frontier.get("parent_nonzero_returns"), "parent nonzero returns"
    )
    parent_zero = _nonnegative_int(
        frontier.get("parent_zero_returns"), "parent zero returns"
    )
    outer_nonzero = _nonnegative_int(
        frontier.get("outer_nonzero_returns"), "outer nonzero returns"
    )
    outer_zero = _nonnegative_int(
        frontier.get("outer_zero_returns"), "outer zero returns"
    )

    states = {
        prefix: _state_bits(frontier, prefix, plan_rows=row_count)
        for prefix in _STATE_PREFIXES
    }
    consumed = states["consumed_state"]
    initial_returned = states["initial_returned_state"]
    initial_released = states["initial_released_state"]
    enqueued = states["contrast_enqueued_state"]
    contrast_returned = states["contrast_returned_state"]
    contrast_released_state = states["contrast_released_state"]
    falsifying_skips = states["skipped_falsifying_state"]
    rescue_skips = states["skipped_rescue_state"]
    deferred = states["contrast_deferred_assigned_state"]

    if (
        cursor > row_count
        or rows_consumed != cursor
        or tuple(index < cursor for index in range(row_count)) != consumed
        or rows_consumed != initial_returns + skipped_falsifying + skipped_rescue
        or sum(initial_returned) != initial_returns
        or sum(falsifying_skips) != skipped_falsifying
        or sum(rescue_skips) != skipped_rescue
        or any(
            sum((initial_returned[index], falsifying_skips[index], rescue_skips[index]))
            > 1
            for index in range(row_count)
        )
        or any(
            initial_returned[index] and not consumed[index]
            for index in range(row_count)
        )
        or sum(initial_released) != initial_releases
        or any(
            initial_released[index] and not initial_returned[index]
            for index in range(row_count)
        )
        or initial_releases != contrast_enqueued
        or enqueued != initial_released
        or sum(contrast_returned) != contrast_returns
        or any(
            contrast_returned[index] and not enqueued[index]
            for index in range(row_count)
        )
        or sum(contrast_released_state) != contrast_releases
        or any(
            contrast_released_state[index] and not contrast_returned[index]
            for index in range(row_count)
        )
        or sum(deferred) != contrast_deferred
        or any(deferred[index] and not enqueued[index] for index in range(row_count))
        or contrast_returns > contrast_enqueued
        or contrast_releases > contrast_returns
        or queue_size != contrast_enqueued - contrast_returns
        or not queue_size <= maximum_queue_size <= row_count
        or (contrast_returns and cursor != row_count)
    ):
        raise _error("frontier plan state")

    initial_return_sequence = _literal_sequence(
        frontier,
        "initial_return_sequence",
        expected_count=initial_returns,
    )
    initial_release_sequence = _literal_sequence(
        frontier,
        "initial_release_sequence",
        expected_count=initial_releases,
    )
    contrast_return_sequence = _literal_sequence(
        frontier,
        "contrast_return_sequence",
        expected_count=contrast_returns,
    )
    contrast_release_sequence = _literal_sequence(
        frontier,
        "contrast_release_sequence",
        expected_count=contrast_releases,
    )
    if initial_return_sequence != tuple(
        plan.falsifying_decision_literals[index]
        for index, returned in enumerate(initial_returned)
        if returned
    ):
        raise _error("initial return order")

    parent_calls = _nonnegative_int(
        parent_reader.get("cb_decide_calls"), "parent callback count"
    )
    parent_reported_nonzero = _nonnegative_int(
        parent_reader.get("cb_decide_nonzero"), "parent nonzero count"
    )
    parent_reported_zero = _nonnegative_int(
        parent_reader.get("cb_decide_zero"), "parent zero count"
    )
    parent_events = _parent_nonzero_events(parent_reader, calls)
    if (
        calls != parent_calls
        or parent_nonzero != parent_reported_nonzero
        or parent_zero != parent_reported_zero
        or len(parent_events) != parent_nonzero
        or calls != parent_nonzero + parent_zero
    ):
        raise _error("parent callback counts")

    raw_events = _sequence(frontier.get("substitution_events"), "substitution events")
    substitutions: dict[int, int] = {}
    initial_event_indices: list[int] = []
    contrast_event_indices: list[int] = []
    previous_call = 0
    for raw_event in raw_events:
        event = _mapping(raw_event, "substitution event")
        if set(event) != {"call", "kind", "plan_index", "literal"}:
            raise _error("substitution event fields")
        call = _positive_int(event.get("call"), "substitution call")
        index = _nonnegative_int(event.get("plan_index"), "substitution index")
        literal = event.get("literal")
        kind = event.get("kind")
        if (
            call <= previous_call
            or call > calls
            or call in parent_events
            or call in substitutions
            or index >= row_count
            or isinstance(literal, bool)
            or not isinstance(literal, int)
        ):
            raise _error("substitution event causality")
        if kind == "initial":
            if (
                not initial_returned[index]
                or literal != plan.falsifying_decision_literals[index]
            ):
                raise _error("initial substitution event")
            initial_event_indices.append(index)
        elif kind == "contrast":
            if (
                not contrast_returned[index]
                or literal != plan.residual_clause_literals[index]
            ):
                raise _error("contrast substitution event")
            contrast_event_indices.append(index)
        else:
            raise _error("substitution event kind")
        substitutions[call] = literal
        previous_call = call
    if (
        len(raw_events) != initial_returns + contrast_returns
        or initial_event_indices != sorted(initial_event_indices)
        or len(set(initial_event_indices)) != len(initial_event_indices)
        or len(set(contrast_event_indices)) != len(contrast_event_indices)
    ):
        raise _error("substitution event order")

    raw_pairs = _sequence(frontier.get("pair_records"), "pair records")
    if len(raw_pairs) != initial_returns:
        raise _error("pair record count")
    pairs: dict[int, dict[str, int | None]] = {}
    expected_pair_fields = {
        "plan_index",
        "clause_literal",
        "initial_literal",
        "initial_return_call",
        "initial_release_after_call",
        "initial_release_level",
        "contrast_return_call",
        "contrast_release_after_call",
        "contrast_release_level",
    }
    previous_index = -1
    for raw_pair in raw_pairs:
        pair = _mapping(raw_pair, "pair record")
        if set(pair) != expected_pair_fields:
            raise _error("pair record fields")
        index = _nonnegative_int(pair.get("plan_index"), "pair index")
        initial_call = _positive_int(
            pair.get("initial_return_call"), "pair initial call"
        )
        initial_release_call = _nullable_positive(
            pair.get("initial_release_after_call"), "pair initial release call"
        )
        initial_release_level = (
            None
            if pair.get("initial_release_level") is None
            else _nonnegative_int(
                pair.get("initial_release_level"), "pair initial release level"
            )
        )
        contrast_call = _nullable_positive(
            pair.get("contrast_return_call"), "pair contrast call"
        )
        contrast_release_call = _nullable_positive(
            pair.get("contrast_release_after_call"), "pair contrast release call"
        )
        contrast_release_level = (
            None
            if pair.get("contrast_release_level") is None
            else _nonnegative_int(
                pair.get("contrast_release_level"), "pair contrast release level"
            )
        )
        if (
            index <= previous_index
            or index >= row_count
            or not initial_returned[index]
            or pair.get("clause_literal") != plan.residual_clause_literals[index]
            or pair.get("initial_literal") != plan.falsifying_decision_literals[index]
            or substitutions.get(initial_call)
            != plan.falsifying_decision_literals[index]
            or (initial_release_call is None) != (not initial_released[index])
            or (initial_release_level is None) != (initial_release_call is None)
            or (contrast_call is None) != (not contrast_returned[index])
            or (contrast_release_call is None) != (not contrast_released_state[index])
            or (contrast_release_level is None) != (contrast_release_call is None)
            or (
                initial_release_call is not None and initial_release_call < initial_call
            )
            or (
                contrast_call is not None
                and (
                    initial_release_call is None
                    or contrast_call <= initial_release_call
                    or substitutions.get(contrast_call)
                    != plan.residual_clause_literals[index]
                )
            )
            or (
                contrast_release_call is not None
                and (contrast_call is None or contrast_release_call < contrast_call)
            )
        ):
            raise _error("pair record causality")
        previous_index = index
        pairs[index] = {
            "initial_call": initial_call,
            "initial_release_call": initial_release_call,
            "contrast_call": contrast_call,
            "contrast_release_call": contrast_release_call,
        }
    if set(pairs) != {
        index for index, returned in enumerate(initial_returned) if returned
    }:
        raise _error("pair record coverage")

    release_order = sorted(
        (
            cast(int, pair["initial_release_call"]),
            index,
        )
        for index, pair in pairs.items()
        if pair["initial_release_call"] is not None
    )
    if initial_release_sequence != tuple(
        plan.falsifying_decision_literals[index] for _, index in release_order
    ):
        raise _error("initial release order")
    release_positions = {
        index: position for position, (_, index) in enumerate(release_order)
    }
    if any(index not in release_positions for index in contrast_event_indices):
        raise _error("contrast release-order priority")
    if contrast_return_sequence != tuple(
        plan.residual_clause_literals[index] for index in contrast_event_indices
    ):
        raise _error("contrast return order")
    contrast_release_order = sorted(
        (cast(int, pair["contrast_release_call"]), index)
        for index, pair in pairs.items()
        if pair["contrast_release_call"] is not None
    )
    if contrast_release_sequence != tuple(
        plan.residual_clause_literals[index] for _, index in contrast_release_order
    ):
        raise _error("contrast release order")

    actual_events = dict(parent_events)
    actual_events.update(substitutions)
    expected_outer_nonzero = len(actual_events)
    expected_parent_zero_first = _first_missing_call(calls, set(parent_events))
    expected_outer_zero_first = _first_missing_call(calls, set(actual_events))
    expected_frontier_first = min(substitutions) if substitutions else None
    if (
        outer_nonzero != expected_outer_nonzero
        or outer_zero != calls - expected_outer_nonzero
        or outer_nonzero != parent_nonzero + initial_returns + contrast_returns
        or frontier.get("returned_sequence_encoding")
        != CAUSAL_FRONTIER_RETURNED_SEQUENCE_ENCODING
        or frontier.get("returned_sequence_count") != calls
        or frontier.get("returned_sequence_bytes") != 4 * calls
        or _sha256(frontier.get("returned_sequence_sha256"), "outer return hash")
        != _hash_sparse_returns(calls, actual_events)
        or _nullable_positive(
            frontier.get("first_parent_zero_call"), "first parent zero call"
        )
        != expected_parent_zero_first
        or _nullable_positive(
            frontier.get("first_frontier_return_call"),
            "first frontier return call",
        )
        != expected_frontier_first
        or _nullable_positive(
            frontier.get("first_outer_zero_call"), "first outer zero call"
        )
        != expected_outer_zero_first
    ):
        raise _error("outer returned sequence")
    if require_frontier_intervention and not substitutions:
        raise _error("required frontier intervention")

    live_false = _nonnegative_int(
        frontier.get("live_false_literal_count"), "live false count"
    )
    live_true = _nonnegative_int(
        frontier.get("live_true_literal_count"), "live true count"
    )
    live_unassigned = _nonnegative_int(
        frontier.get("live_unassigned_literal_count"), "live unassigned count"
    )
    minimum_false = _nonnegative_int(
        frontier.get("minimum_live_false_literal_count"), "minimum false count"
    )
    minimum_true = _nonnegative_int(
        frontier.get("minimum_live_true_literal_count"), "minimum true count"
    )
    minimum_unassigned = _nonnegative_int(
        frontier.get("minimum_live_unassigned_literal_count"),
        "minimum unassigned count",
    )
    prior_distance = _boolean(
        frontier.get("prior_distance_reached"), "prior distance reached"
    )
    unit_distance = _boolean(
        frontier.get("unit_distance_reached"), "unit distance reached"
    )
    if (
        live_false + live_true + live_unassigned != plan.selected_clause_literal_count
        or minimum_false > live_false
        or minimum_true > live_true
        or minimum_unassigned > live_unassigned
        or minimum_false != 0
        or minimum_true != 0
        or (
            not live_true
            and live_unassigned <= plan.unassigned_literal_count
            and not prior_distance
        )
        or (not live_true and live_unassigned <= 1 and not unit_distance)
        or (unit_distance and not prior_distance and plan.unassigned_literal_count >= 1)
    ):
        raise _error("selected clause live minima")

    state_bytes = (row_count + 7) // 8
    assignment_count = len(plan.prior_assignment)
    bounded_guidance = (
        4 + assignment_count + 8 * assignment_count + 9 * state_bytes + 4 * row_count
    )
    live_guidance = _nonnegative_int(
        frontier.get("live_guidance_state_bytes"), "live guidance bytes"
    )
    live_base = 4 + assignment_count + 9 * state_bytes + 4 * initial_releases
    live_remainder = live_guidance - live_base
    bounded_telemetry = bounded_guidance + 34 * row_count + 56 * row_count + 112
    if (
        frontier.get("bounded_guidance_state_bytes") != bounded_guidance
        or live_remainder < 0
        or live_remainder % 8
        or live_remainder // 8 > assignment_count
        or live_guidance > bounded_guidance
        or frontier.get("bounded_telemetry_state_bytes") != bounded_telemetry
    ):
        raise _error("bounded frontier state")
    # Validate the field's type independently; the prior assignment and live
    # solver assignment are intentionally different populations.
    _nonnegative_int(
        frontier.get("assignment_literals_observed"),
        "assignment literals observed",
    )
    return dict(frontier)


def _validate_frontier_lifecycle(payload: Mapping[str, object]) -> None:
    """Validate self-contained outer telemetry without claiming plan proof."""

    frontier = _mapping(payload.get("frontier"), "frontier reader")
    reader = _mapping(payload.get("reader"), "parent reader")
    vault = _mapping(payload.get("vault"), "vault telemetry")
    if set(frontier) != _FRONTIER_FIELDS:
        raise _error("frontier reader fields")
    residual = _literal_list(
        frontier.get("residual_clause_literals"), "residual literals"
    )
    decisions = _literal_list(
        frontier.get("falsifying_decision_literals"), "decision literals"
    )
    selected_literal_count = _nonnegative_int(
        frontier.get("selected_clause_literal_count"),
        "selected clause literal count",
    )
    false_count = _nonnegative_int(
        frontier.get("prior_false_literal_count"), "prior false count"
    )
    true_count = _nonnegative_int(
        frontier.get("prior_true_literal_count"), "prior true count"
    )
    unassigned_count = _nonnegative_int(
        frontier.get("prior_unassigned_literal_count"),
        "prior unassigned count",
    )
    if (
        true_count != 0
        or false_count + true_count + unassigned_count != selected_literal_count
        or unassigned_count != len(residual)
        or decisions != tuple(-literal for literal in residual)
    ):
        raise _error("frontier prior counts")
    observed_count = _nonnegative_int(
        reader.get("observed_variable_count"), "observed variable count"
    )
    view = _LifecycleFrontierPlanView(
        sha256=_sha256(payload.get("frontier_plan_sha256"), "frontier plan hash"),
        source_result_sha256=_sha256(
            payload.get("frontier_source_result_sha256"), "source result hash"
        ),
        source_assignment_sha256=_sha256(
            frontier.get("source_assignment_sha256"), "source assignment hash"
        ),
        active_vault_sha256=_sha256(vault.get("input_sha256"), "active vault hash"),
        selected_active_index=_nonnegative_int(
            frontier.get("selected_active_index"), "selected active index"
        ),
        selected_union_index=_nonnegative_int(
            frontier.get("selected_union_index"), "selected union index"
        ),
        selected_clause_sha256=_sha256(
            frontier.get("selected_clause_sha256"), "selected clause hash"
        ),
        selected_clause_literal_count=selected_literal_count,
        false_literal_count=false_count,
        true_literal_count=true_count,
        unassigned_literal_count=unassigned_count,
        prior_assignment=range(observed_count),
        residual_clause_literals=residual,
        falsifying_decision_literals=decisions,
    )
    _validate_frontier_reader(
        frontier,
        plan=view,
        parent_reader=reader,
        require_frontier_intervention=False,
    )


def _promote_result(
    result: _v16.JointScoreSieveV16Result,
    *,
    raw: Mapping[str, object],
    frontier_plan: CausalFrontierPlan,
    frontier_reader: Mapping[str, object],
) -> JointScoreSieveV17Result:
    return JointScoreSieveV17Result(
        status=result.status,
        conflict_limit=result.conflict_limit,
        threshold=result.threshold,
        key_model=result.key_model,
        stats=result.stats,
        sieve=result.sieve,
        resources=result.resources,
        raw=dict(raw),
        adapter_memory=result.adapter_memory,
        input_vault=result.input_vault,
        eligible_emitted_clauses=result.eligible_emitted_clauses,
        next_vault=result.next_vault,
        vault_telemetry=result.vault_telemetry,
        reader=result.reader,
        rank_source_vault=result.rank_source_vault,
        frontier_plan=frontier_plan,
        frontier_reader=dict(frontier_reader),
    )


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v14 provenance and delegate the projected lifecycle to v16."""

    if (
        not isinstance(payload, Mapping)
        or set(payload) != _TOP_LEVEL_FIELDS
        or payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    ):
        raise _error("lifecycle contract")
    _sha256(payload.get("frontier_plan_sha256"), "frontier plan hash")
    _sha256(payload.get("frontier_source_result_sha256"), "source result hash")
    _validate_frontier_lifecycle(payload)
    projected = dict(payload)
    projected.pop("frontier")
    projected.pop("frontier_plan_sha256")
    projected.pop("frontier_source_result_sha256")
    projected["schema"] = _v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_V16_RELEASE_PARENT_SCHEMA
    )
    return _v16.validate_native_lifecycle(projected)


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    rank_source_vault: ThresholdNoGoodVault,
    frontier_plan: CausalFrontierPlan,
    vault_caps: VaultCaps,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    grouping_sha256: str,
    cnf_sha256: str,
    potential_sha256: str,
    threshold: float,
    requested_conflicts: int,
    seed: int,
    memory_limit_bytes: int | None,
    memory_samples: tuple[dict[str, int | float], ...],
    expected_decision: VaultRankedDecision,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = True,
) -> JointScoreSieveV17Result:
    """Validate outer causality, then apply the frozen v16 parser."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise _error("result fields")
    if (
        payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or _sha256(payload.get("frontier_plan_sha256"), "frontier plan hash")
        != frontier_plan.sha256
        or _sha256(payload.get("frontier_source_result_sha256"), "source result hash")
        != frontier_plan.source_result_sha256
    ):
        raise _error("result provenance")
    projected = dict(payload)
    frontier_value = projected.pop("frontier")
    projected.pop("frontier_plan_sha256")
    projected.pop("frontier_source_result_sha256")
    projected["schema"] = _v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_V16_RELEASE_PARENT_SCHEMA
    )
    try:
        parent = _v16._parse_native_payload(
            projected,
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
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
            expected_decision=expected_decision,
            require_active_contrast=require_active_contrast,
        )
        frontier_reader = _validate_frontier_reader(
            frontier_value,
            plan=frontier_plan,
            parent_reader=parent.reader,
            require_frontier_intervention=require_frontier_intervention,
        )
    except O1RelationalSearchError as exc:
        raise _error("native payload validation") from exc
    return _promote_result(
        parent,
        raw=payload,
        frontier_plan=frontier_plan,
        frontier_reader=frontier_reader,
    )


def _parse_and_certify_vault(
    payload: bytes,
    *,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    expected_identity: ThresholdNoGoodVaultIdentity,
    threshold: float,
    caps: VaultCaps,
    role: str,
) -> ThresholdNoGoodVault:
    return _v16._parse_and_certify_vault(
        payload,
        field=field,
        grouping=grouping,
        expected_identity=expected_identity,
        threshold=threshold,
        caps=caps,
        role=role,
    )


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    rank_vault_path: str | Path,
    vault_path: str | Path,
    frontier_plan_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = True,
) -> JointScoreSieveV17Result:
    """Run native v14 with a stable, certified frontier plan."""

    requested = _v16._v15._v14._v13._v12._v11._v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
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
        or not isinstance(require_active_contrast, bool)
        or not isinstance(require_frontier_intervention, bool)
        or (
            memory_limit_bytes is not None
            and (
                isinstance(memory_limit_bytes, bool)
                or not isinstance(memory_limit_bytes, int)
                or memory_limit_bytes <= 0
            )
        )
    ):
        raise _error("reader, threshold, timeout, or memory limit")
    requested_threshold = float(threshold)
    io_v1 = _v16._v15._v14._v13._v12._v11._v9._v8._v1
    io_v8 = _v16._v15._v14._v13._v12._v11._v9._v8
    executable_file, executable_bytes, _ = io_v1._read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = io_v1._read_input(cnf_path, "CNF")
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
        plan_file, plan_bytes = _frontier._read_regular_file(frontier_plan_path)
    except CausalFrontierError as exc:
        raise _error("frontier plan input") from exc
    field = io_v1._potential(potential_bytes)
    grouping = io_v8._v7.validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise _error("grouping potential identity")
    try:
        expected_decision = derive_production_vault_ranked_decision(
            rank_vault_bytes, potential_bytes, grouping_bytes
        )
    except VaultRankedDecisionError as exc:
        raise _error("sealed rank-source decision") from exc

    expected_identity = vault_identity_from_sources(
        cnf_sha256=cnf_sha,
        potential_sha256=potential_sha,
        grouping_sha256=grouping_sha,
        observed_variables=field.observed_variables,
        bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=requested_threshold,
    )
    rank_source_vault = _parse_and_certify_vault(
        rank_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=expected_identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="rank-source",
    )
    input_vault = _parse_and_certify_vault(
        active_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=expected_identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="active",
    )
    try:
        frontier_plan = _frontier.parse_causal_frontier_plan(
            plan_bytes, active_vault=input_vault
        )
    except CausalFrontierError as exc:
        raise _error("frontier plan certification") from exc

    rank_path, rank_bytes = _v16._v15._v14._v13._rank_table_temp(expected_decision)
    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
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
        str(plan_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: _v16._v15._v14._v13._v12._v11._v9._v8._v7._NativeExecution | None
    try:
        try:
            execution = io_v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
            execution = None
        try:
            io_v1._verify_stable_input(
                executable, executable_file, executable_bytes, field="executable"
            )
            io_v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
            io_v1._verify_stable_input(
                potential_path,
                potential_file,
                potential_bytes,
                field="potential",
            )
            io_v1._verify_stable_input(
                grouping_path,
                grouping_file,
                grouping_bytes,
                field="grouping",
            )
            io_v8._verify_stable_vault_input(
                rank_vault_path,
                rank_vault_file,
                rank_vault_bytes,
                caps=vault_caps,
            )
            io_v8._verify_stable_vault_input(
                vault_path,
                active_vault_file,
                active_vault_bytes,
                caps=vault_caps,
            )
            io_v1._verify_stable_input(
                frontier_plan_path,
                plan_file,
                plan_bytes,
                field="frontier plan",
            )
            if rank_path.read_bytes() != rank_bytes:
                raise _error("rank table changed during execution")
        except Exception as exc:
            if execution is not None:
                _v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
                    exc,
                    command=command,
                    completed=execution.completed,
                    memory_samples=execution.memory_samples,
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

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v17 execution failed: {detail}"
        ) from failure
    try:
        payload = json.loads(completed.stdout)
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
            frontier_plan=frontier_plan,
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
            memory_samples=execution.memory_samples,
            expected_decision=expected_decision,
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
        )
        return replace(
            result,
            stats=_v16._v15.derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise _error("result JSON") from exc
    except Exception as exc:
        _v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
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
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = True,
) -> JointScoreSieveV17Result:
    """Run v14 with independently stable rank, active, and plan inputs."""

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
            vault_caps=vault_caps,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v16._v15._v14._v13._v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v17"):
            message = f"joint-score-sieve-v17 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [  # pyright: ignore[reportUnsupportedDunderAll]
    *(
        name
        for name in _v16.__all__
        if name
        not in {
            "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
            "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
            "JointScoreSieveV16Result",
            "run_joint_score_sieve",
            "validate_native_lifecycle",
        }
    ),
    "CAUSAL_FRONTIER_READER_SCHEMA",
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_V16_RELEASE_PARENT_SCHEMA",
    "JointScoreSieveV17Result",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
]
