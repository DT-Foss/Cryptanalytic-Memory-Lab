"""Strict residual-polarity staging adapter for native joint sieve v15.

Native v15 embeds the complete v14 frontier reader.  Its only science change
is a canonical two-row sign overlay applied after source-rank validation and
before the embedded v14/v12 objects are constructed.  This adapter validates
the effective reader and outer callback chronology, then uses a reversible
source-sign projection to reuse every frozen v17 sieve/vault check.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import struct
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import joint_score_sieve_v17 as _v17
from . import residual_polarity_staging_v1 as _staging
from .causal_frontier_v1 import CausalFrontierError, CausalFrontierPlan
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .residual_polarity_staging_v1 import (
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
)
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v18-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v15"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v17.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA = _v17.JOINT_SCORE_SIEVE_RESULT_SCHEMA
JOINT_SCORE_SIEVE_V17_RELEASE_PARENT_SCHEMA = (
    _v17.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_BOUND_RULE = _v17.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v17.JointScoreSieveExecutionError
write_joint_score_sieve_grouping = _v17.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v17.write_joint_score_sieve_potential

RESIDUAL_POLARITY_STAGING_READER_SCHEMA = (
    "o1-256-cadical-residual-polarity-staging-reader-v1"
)
RESIDUAL_POLARITY_STAGING_OPERATOR = (
    "parse-source-rank-then-two-row-polarity-overlay-before-v14"
)
RESIDUAL_POLARITY_STAGING_READER_RANK_ROLE = "effective-derived-order"
RESIDUAL_POLARITY_STAGING_DECISION_RULE = (
    "embedded-v14-return-unchanged;effective-original-sign-first;embedded-"
    "v12-release-contrast-opposite-of-effective-original"
)
RESIDUAL_POLARITY_STAGING_CALLBACK_RULE = (
    "one-v14-call-per-callback;never-override-or-discard-parent-return;"
    "finalize-assignment-burst-at-next-callback-or-solve-end"
)
RESIDUAL_POLARITY_STAGING_STATE_ENCODING = "two-overlay-bits-lsb-first-by-overlay-index"
RESIDUAL_POLARITY_STAGING_SEQUENCE_ENCODING = (
    "one-signed-i32le-literal-per-cb-decide-including-zero"
)
RESIDUAL_POLARITY_STAGING_TRACE_ENCODING = (
    "records:u64le-call;i32le-return;u64le-assignment-burst;u8-completion-"
    "one-next-callback-two-solve-end"
)
RESIDUAL_POLARITY_STAGING_BOUNDED_STATE_RULE = (
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "two-overlay-bitsets;bounded-4194304-callback-records;bounded-four-"
    "overlay-events;exact-return-and-callback-trace-bytes"
)

_TOP_LEVEL_FIELDS = _v17._TOP_LEVEL_FIELDS | {
    "staging_plan_sha256",
    "staging_source_result_sha256",
    "reader_rank_role",
    "staging",
}
_STAGING_FIELDS = {
    "schema",
    "operator",
    "plan_sha256",
    "source_result_sha256",
    "source_assignment_sha256",
    "active_vault_sha256",
    "parent_frontier_plan_sha256",
    "selected_active_index",
    "selected_union_index",
    "selected_clause_sha256",
    "selected_clause_literal_count",
    "source_rank_payload_sha256",
    "source_rank_order_sha256",
    "effective_rank_order_sha256",
    "reader_rank_role",
    "decision_rule",
    "callback_rule",
    "intersections",
    "overlays",
    "mechanism_activated",
    "first_activation_call",
    "overlay_effective_returns",
    "overlay_contrast_returns",
    "unit_activation",
    "source_rank_cursor",
    "cb_decide_calls",
    "nonzero_returns",
    "zero_returns",
    "assignments_before_first_callback",
    "assignment_literals_observed",
    "live_false_literal_count",
    "live_true_literal_count",
    "live_unassigned_literal_count",
    "post_activation_minimum_false_literal_count",
    "post_activation_minimum_true_literal_count",
    "post_activation_minimum_unassigned_literal_count",
    "effective_returned_state_bits",
    "effective_returned_state_bytes",
    "effective_returned_state_encoding",
    "effective_returned_state_hex",
    "effective_returned_state_sha256",
    "contrast_observed_state_bits",
    "contrast_observed_state_bytes",
    "contrast_observed_state_encoding",
    "contrast_observed_state_hex",
    "contrast_observed_state_sha256",
    "returned_sequence_encoding",
    "returned_sequence_count",
    "returned_sequence_bytes",
    "returned_sequence_hex",
    "returned_sequence_sha256",
    "callback_trace_encoding",
    "callback_trace_count",
    "callback_trace_bytes",
    "callback_trace_hex",
    "callback_trace_sha256",
    "callback_records",
    "overlay_return_events",
    "bounded_state_rule",
    "bounded_guidance_state_bytes",
    "live_guidance_state_bytes",
    "bounded_telemetry_state_bytes",
}

_STAGING_MAXIMUM_CALLBACK_RECORDS = 4_194_304
_STAGING_CALLBACK_RECORD_STATE_BYTES = 32
_STAGING_MAXIMUM_OVERLAY_EVENTS = 4
_STAGING_OVERLAY_EVENT_STATE_BYTES = 40
_STAGING_RETURN_AND_TRACE_BYTES_PER_CALLBACK = 25


@dataclass(frozen=True)
class JointScoreSieveV18Result(_v17.JointScoreSieveV17Result):
    """A fully v17-validated result retaining effective staging telemetry."""

    staging_plan: ResidualPolarityStagingPlan
    staging_reader: Mapping[str, object]

    @property
    def staging_plan_sha256(self) -> str:
        return self.staging_plan.sha256

    @property
    def staging(self) -> Mapping[str, object]:
        return self.staging_reader


@dataclass(frozen=True)
class _LifecycleStagingPlanView:
    sha256: str
    source_result_sha256: str
    source_assignment_sha256: str
    active_vault_sha256: str
    parent_frontier_plan_sha256: str
    selected_active_index: int
    selected_union_index: int
    selected_clause_sha256: str
    selected_clause_literal_count: int
    source_rank_payload_sha256: str
    source_rank_order_sha256: str
    effective_rank_order_sha256: str
    source_assignment_count: int
    source_rank_literals: tuple[int, ...]
    effective_rank_literals: tuple[int, ...]
    intersections: tuple[object, ...]
    overlays: tuple[object, ...]


def __getattr__(name: str) -> object:
    try:
        return getattr(_v17, name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc


def _error(field: str) -> O1RelationalSearchError:
    return O1RelationalSearchError(f"joint-score-sieve-v18 {field} differs")


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


def _nullable_positive(value: object, field: str) -> int | None:
    if value is None:
        return None
    return _positive(value, field)


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


def _hex(value: object, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise _error(field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise _error(field) from exc


def _literal(value: object, field: str, *, allow_zero: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or (not allow_zero and value == 0)
        or not -(1 << 31) < value < (1 << 31)
    ):
        raise _error(field)
    return value


def _rank_literals(reader: Mapping[str, object]) -> tuple[int, ...]:
    values = _sequence(reader.get("ranked_literals"), "reader ranked literals")
    result = tuple(_literal(value, "reader ranked literal") for value in values)
    if len({abs(value) for value in result}) != len(result):
        raise _error("reader ranked variables")
    return result


def _plan_intersections(
    plan: ResidualPolarityStagingPlan | _LifecycleStagingPlanView,
) -> tuple[tuple[int, int, int, int], ...]:
    result: list[tuple[int, int, int, int]] = []
    for row in plan.intersections:
        result.append(
            (
                cast(int, getattr(row, "rank_index")),
                cast(int, getattr(row, "clause_literal")),
                cast(int, getattr(row, "source_literal")),
                cast(int, getattr(row, "effective_literal")),
            )
        )
    return tuple(result)


def _plan_overlays(
    plan: ResidualPolarityStagingPlan | _LifecycleStagingPlanView,
) -> tuple[tuple[int, int, int], ...]:
    result: list[tuple[int, int, int]] = []
    for row in plan.overlays:
        result.append(
            (
                cast(int, getattr(row, "rank_index")),
                cast(int, getattr(row, "source_literal")),
                cast(int, getattr(row, "effective_literal")),
            )
        )
    return tuple(result)


def _telemetry_rows(
    value: object, *, field: str, width: int
) -> tuple[tuple[int, ...], ...]:
    rows = _sequence(value, field)
    result: list[tuple[int, ...]] = []
    expected_fields = (
        {"rank_index", "clause_literal", "source_literal", "effective_literal"}
        if width == 4
        else {"rank_index", "source_literal", "effective_literal"}
    )
    prior = -1
    for raw in rows:
        row = _mapping(raw, field)
        if set(row) != expected_fields:
            raise _error(field)
        rank_index = _nonnegative(row.get("rank_index"), field)
        values = [rank_index]
        if width == 4:
            values.append(_literal(row.get("clause_literal"), field))
        values.extend(
            (
                _literal(row.get("source_literal"), field),
                _literal(row.get("effective_literal"), field),
            )
        )
        if rank_index <= prior:
            raise _error(field)
        prior = rank_index
        result.append(tuple(values))
    return tuple(result)


def _state_bits(staging: Mapping[str, object], prefix: str) -> tuple[bool, bool]:
    payload = _hex(staging.get(f"{prefix}_hex"), f"{prefix} hex")
    if (
        staging.get(f"{prefix}_bits") != 2
        or staging.get(f"{prefix}_bytes") != 1
        or staging.get(f"{prefix}_encoding") != RESIDUAL_POLARITY_STAGING_STATE_ENCODING
        or len(payload) != 1
        or payload[0] & 0xFC
        or _sha(staging.get(f"{prefix}_sha256"), f"{prefix} hash")
        != hashlib.sha256(payload).hexdigest()
    ):
        raise _error(f"{prefix} state")
    return bool(payload[0] & 1), bool(payload[0] & 2)


def _reader_events(reader: Mapping[str, object]) -> dict[int, tuple[int, str, int]]:
    result: dict[int, tuple[int, str, int]] = {}
    prior = 0
    for raw in _sequence(reader.get("nonzero_return_events"), "reader events"):
        event = _mapping(raw, "reader event")
        call = _positive(event.get("call"), "reader event call")
        rank_index = _nonnegative(event.get("rank_index"), "reader event rank")
        literal = _literal(event.get("literal"), "reader event literal")
        kind = event.get("kind")
        if call <= prior or kind not in ("original", "contrast"):
            raise _error("reader event chronology")
        prior = call
        result[call] = (literal, cast(str, kind), rank_index)
    return result


def _frontier_events(frontier: Mapping[str, object]) -> dict[int, int]:
    result: dict[int, int] = {}
    prior = 0
    for raw in _sequence(frontier.get("substitution_events"), "frontier events"):
        event = _mapping(raw, "frontier event")
        call = _positive(event.get("call"), "frontier event call")
        literal = _literal(event.get("literal"), "frontier event literal")
        if call <= prior:
            raise _error("frontier event chronology")
        prior = call
        result[call] = literal
    return result


def _sparse_hash(calls: int, events: Mapping[int, int]) -> str:
    digest = hashlib.sha256()
    for call in range(1, calls + 1):
        digest.update(struct.pack("<i", events.get(call, 0)))
    return digest.hexdigest()


def _validate_staging_reader(
    value: object,
    *,
    plan: ResidualPolarityStagingPlan | _LifecycleStagingPlanView,
    parent_reader: Mapping[str, object],
    frontier_reader: Mapping[str, object],
    sieve_state: Mapping[str, object],
    require_staging_activation: bool,
) -> dict[str, object]:
    staging = _mapping(value, "staging reader")
    if set(staging) != _STAGING_FIELDS:
        raise _error("staging reader fields")
    if (
        staging.get("schema") != RESIDUAL_POLARITY_STAGING_READER_SCHEMA
        or staging.get("operator") != RESIDUAL_POLARITY_STAGING_OPERATOR
        or staging.get("reader_rank_role") != RESIDUAL_POLARITY_STAGING_READER_RANK_ROLE
        or staging.get("decision_rule") != RESIDUAL_POLARITY_STAGING_DECISION_RULE
        or staging.get("callback_rule") != RESIDUAL_POLARITY_STAGING_CALLBACK_RULE
        or staging.get("bounded_state_rule")
        != RESIDUAL_POLARITY_STAGING_BOUNDED_STATE_RULE
        or _sha(staging.get("plan_sha256"), "staging plan hash") != plan.sha256
        or _sha(staging.get("source_result_sha256"), "source result hash")
        != plan.source_result_sha256
        or _sha(staging.get("source_assignment_sha256"), "assignment hash")
        != plan.source_assignment_sha256
        or _sha(staging.get("active_vault_sha256"), "active vault hash")
        != plan.active_vault_sha256
        or _sha(staging.get("parent_frontier_plan_sha256"), "frontier plan hash")
        != plan.parent_frontier_plan_sha256
        or staging.get("selected_active_index") != plan.selected_active_index
        or staging.get("selected_union_index") != plan.selected_union_index
        or staging.get("selected_clause_sha256") != plan.selected_clause_sha256
        or staging.get("selected_clause_literal_count")
        != plan.selected_clause_literal_count
        or staging.get("source_rank_payload_sha256") != plan.source_rank_payload_sha256
        or staging.get("source_rank_order_sha256") != plan.source_rank_order_sha256
        or staging.get("effective_rank_order_sha256")
        != plan.effective_rank_order_sha256
        or _telemetry_rows(staging.get("intersections"), field="intersections", width=4)
        != _plan_intersections(plan)
        or _telemetry_rows(staging.get("overlays"), field="overlays", width=3)
        != _plan_overlays(plan)
    ):
        raise _error("staging plan binding")

    effective_rank = _rank_literals(parent_reader)
    assignment_count = (
        len(plan.source_assignment)
        if isinstance(plan, ResidualPolarityStagingPlan)
        else plan.source_assignment_count
    )
    observed_count = _nonnegative(
        parent_reader.get("observed_variable_count"), "observed variable count"
    )
    current_assigned = _nonnegative(
        sieve_state.get("current_assigned_variables"),
        "current assigned variables",
    )
    if (
        effective_rank != plan.effective_rank_literals
        or observed_count != assignment_count
        or current_assigned > assignment_count
        or parent_reader.get("rank_table_sha256") != plan.source_rank_payload_sha256
        or parent_reader.get("order_sha256") != plan.effective_rank_order_sha256
        or parent_reader.get("order_bytes") != 4 * len(effective_rank)
        or frontier_reader.get("plan_sha256") != plan.parent_frontier_plan_sha256
        or frontier_reader.get("source_result_sha256") != plan.source_result_sha256
        or frontier_reader.get("source_assignment_sha256")
        != plan.source_assignment_sha256
        or frontier_reader.get("active_vault_sha256") != plan.active_vault_sha256
    ):
        raise _error("effective parent binding")

    calls = _nonnegative(staging.get("cb_decide_calls"), "callback count")
    nonzero = _nonnegative(staging.get("nonzero_returns"), "nonzero returns")
    zero = _nonnegative(staging.get("zero_returns"), "zero returns")
    if (
        calls != nonzero + zero
        or parent_reader.get("cb_decide_calls") != calls
        or frontier_reader.get("cb_decide_calls") != calls
        or frontier_reader.get("outer_nonzero_returns") != nonzero
        or frontier_reader.get("outer_zero_returns") != zero
        or staging.get("source_rank_cursor") != parent_reader.get("cursor")
    ):
        raise _error("parent/outer callback accounting")

    returned = _hex(staging.get("returned_sequence_hex"), "returned sequence")
    if (
        staging.get("returned_sequence_encoding")
        != RESIDUAL_POLARITY_STAGING_SEQUENCE_ENCODING
        or staging.get("returned_sequence_count") != calls
        or staging.get("returned_sequence_bytes") != 4 * calls
        or len(returned) != 4 * calls
        or _sha(staging.get("returned_sequence_sha256"), "returned hash")
        != hashlib.sha256(returned).hexdigest()
    ):
        raise _error("returned sequence")
    returned_literals = struct.unpack(f"<{calls}i", returned) if calls else ()
    parent_events = _reader_events(parent_reader)
    frontier_events = _frontier_events(frontier_reader)
    if set(parent_events) & set(frontier_events):
        raise _error("parent/frontier event collision")
    expected_outer = {call: event[0] for call, event in parent_events.items()}
    expected_outer.update(frontier_events)
    if (
        sum(value != 0 for value in returned_literals) != nonzero
        or any(
            returned_literals[call - 1] != literal
            for call, literal in expected_outer.items()
        )
        or any(
            literal != expected_outer.get(call, 0)
            for call, literal in enumerate(returned_literals, start=1)
        )
        or frontier_reader.get("returned_sequence_sha256")
        != hashlib.sha256(returned).hexdigest()
    ):
        raise _error("actual outer return causality")

    records = _sequence(staging.get("callback_records"), "callback records")
    trace = bytearray()
    burst_sum = _nonnegative(
        staging.get("assignments_before_first_callback"), "pre-first assignments"
    )
    if len(records) != calls:
        raise _error("callback record count")
    for index, raw in enumerate(records):
        record = _mapping(raw, "callback record")
        if set(record) != {
            "call",
            "returned_literal",
            "assignment_burst_after_callback",
            "completion",
        }:
            raise _error("callback record fields")
        call = _positive(record.get("call"), "callback record call")
        literal = _literal(
            record.get("returned_literal"), "callback return", allow_zero=True
        )
        burst = _nonnegative(
            record.get("assignment_burst_after_callback"), "assignment burst"
        )
        completion = record.get("completion")
        expected_completion = "solve-end" if index + 1 == calls else "next-callback"
        if (
            call != index + 1
            or literal != returned_literals[index]
            or completion != expected_completion
        ):
            raise _error("callback record chronology")
        burst_sum += burst
        trace.extend(struct.pack("<QiQ", call, literal, burst))
        trace.append(2 if completion == "solve-end" else 1)
    trace_payload = _hex(staging.get("callback_trace_hex"), "callback trace")
    if (
        staging.get("callback_trace_encoding")
        != RESIDUAL_POLARITY_STAGING_TRACE_ENCODING
        or staging.get("callback_trace_count") != calls
        or staging.get("callback_trace_bytes") != 21 * calls
        or trace_payload != bytes(trace)
        or _sha(staging.get("callback_trace_sha256"), "callback trace hash")
        != hashlib.sha256(trace_payload).hexdigest()
        or burst_sum != staging.get("assignment_literals_observed")
    ):
        raise _error("callback assignment trace")

    effective_state = _state_bits(staging, "effective_returned_state")
    contrast_state = _state_bits(staging, "contrast_observed_state")
    effective_returns = _nonnegative(
        staging.get("overlay_effective_returns"), "effective returns"
    )
    contrast_returns = _nonnegative(
        staging.get("overlay_contrast_returns"), "contrast returns"
    )
    mechanism = _boolean(staging.get("mechanism_activated"), "activation")
    first_activation = _nullable_positive(
        staging.get("first_activation_call"), "first activation"
    )
    if (
        effective_returns != sum(effective_state)
        or contrast_returns != sum(contrast_state)
        or mechanism != bool(effective_returns)
        or mechanism != (first_activation is not None)
        or (first_activation is not None and first_activation > calls)
        or (require_staging_activation and not mechanism)
    ):
        raise _error("staging activation state")

    overlay_by_rank = {
        rank_index: (ordinal, source, effective)
        for ordinal, (rank_index, source, effective) in enumerate(_plan_overlays(plan))
    }
    expected_overlay_events: list[tuple[int, int, int, int, str]] = []
    for call, (literal, kind, rank_index) in parent_events.items():
        overlay = overlay_by_rank.get(rank_index)
        if overlay is None:
            continue
        ordinal, source, effective = overlay
        expected_kind = (
            "effective-original" if kind == "original" else "source-contrast"
        )
        expected_literal = effective if kind == "original" else source
        if literal != expected_literal:
            raise _error("embedded contrast polarity")
        expected_overlay_events.append(
            (call, rank_index, source, effective, expected_kind)
        )
        if not (effective_state if kind == "original" else contrast_state)[ordinal]:
            raise _error("overlay state/event projection")
    actual_overlay_events: list[tuple[int, int, int, int, str]] = []
    prior_call = 0
    for raw in _sequence(staging.get("overlay_return_events"), "overlay events"):
        event = _mapping(raw, "overlay event")
        if set(event) != {
            "call",
            "rank_index",
            "source_literal",
            "effective_literal",
            "returned_literal",
            "kind",
        }:
            raise _error("overlay event fields")
        call = _positive(event.get("call"), "overlay event call")
        rank_index = _nonnegative(event.get("rank_index"), "overlay event rank")
        source = _literal(event.get("source_literal"), "overlay source")
        effective = _literal(event.get("effective_literal"), "overlay effective")
        returned_literal = _literal(event.get("returned_literal"), "overlay return")
        kind = event.get("kind")
        if (
            call <= prior_call
            or kind not in ("effective-original", "source-contrast")
            or returned_literal
            != (effective if kind == "effective-original" else source)
            or returned_literals[call - 1] != returned_literal
        ):
            raise _error("overlay event chronology")
        prior_call = call
        actual_overlay_events.append(
            (call, rank_index, source, effective, cast(str, kind))
        )
    if tuple(actual_overlay_events) != tuple(expected_overlay_events):
        raise _error("actual overlay return identity")
    expected_first = next(
        (row[0] for row in expected_overlay_events if row[4] == "effective-original"),
        None,
    )
    if first_activation != expected_first:
        raise _error("first activation causality")

    clause_count = plan.selected_clause_literal_count
    live_counts = tuple(
        _nonnegative(staging.get(name), name)
        for name in (
            "live_false_literal_count",
            "live_true_literal_count",
            "live_unassigned_literal_count",
        )
    )
    minima_values = tuple(
        staging.get(name)
        for name in (
            "post_activation_minimum_false_literal_count",
            "post_activation_minimum_true_literal_count",
            "post_activation_minimum_unassigned_literal_count",
        )
    )
    if sum(live_counts) != clause_count:
        raise _error("live selected-clause counts")
    if mechanism:
        minima = tuple(
            _nonnegative(value, "post-activation minimum") for value in minima_values
        )
        if any(value > clause_count for value in minima) or any(
            minima[index] > live_counts[index] for index in range(3)
        ):
            raise _error("post-activation minima")
        unit = _boolean(staging.get("unit_activation"), "unit activation")
        if unit and not (minima[1] == 0 and minima[2] <= 1):
            raise _error("unit activation witness")
    elif (
        minima_values != (None, None, None)
        or staging.get("unit_activation") is not False
    ):
        raise _error("inactive minima")
    rank_count = len(effective_rank)
    bounded_guidance = 4 + assignment_count + 8 * assignment_count + 4 * rank_count + 2
    live_guidance = 4 + assignment_count + 8 * current_assigned + 4 * rank_count + 2
    bounded_telemetry = (
        bounded_guidance
        + _STAGING_MAXIMUM_CALLBACK_RECORDS
        * _STAGING_CALLBACK_RECORD_STATE_BYTES
        + _STAGING_MAXIMUM_OVERLAY_EVENTS * _STAGING_OVERLAY_EVENT_STATE_BYTES
        + _STAGING_RETURN_AND_TRACE_BYTES_PER_CALLBACK
        * _STAGING_MAXIMUM_CALLBACK_RECORDS
    )
    if (
        _positive(
            staging.get("bounded_guidance_state_bytes"),
            "bounded guidance state bytes",
        )
        != bounded_guidance
        or _positive(
            staging.get("live_guidance_state_bytes"),
            "live guidance state bytes",
        )
        != live_guidance
        or _positive(
            staging.get("bounded_telemetry_state_bytes"),
            "bounded telemetry state bytes",
        )
        != bounded_telemetry
    ):
        raise _error("bounded staging state")
    return dict(staging)


def _rewrite_i32_sequence(
    reader: dict[str, object], prefix: str, overlay_variables: set[int]
) -> None:
    payload = _hex(reader.get(f"{prefix}_hex"), prefix)
    values = list(struct.unpack(f"<{len(payload) // 4}i", payload)) if payload else []
    values = [-value if abs(value) in overlay_variables else value for value in values]
    rewritten = b"".join(struct.pack("<i", value) for value in values)
    reader[f"{prefix}_hex"] = rewritten.hex()
    reader[f"{prefix}_sha256"] = hashlib.sha256(rewritten).hexdigest()


def _project_to_source_rank(
    payload: Mapping[str, object],
    plan: ResidualPolarityStagingPlan | _LifecycleStagingPlanView,
) -> dict[str, object]:
    """Return a reversible compatibility projection for frozen v17 checks."""

    projected = copy.deepcopy(dict(payload))
    projected.pop("staging")
    projected.pop("staging_plan_sha256")
    projected.pop("staging_source_result_sha256")
    projected.pop("reader_rank_role")
    projected["schema"] = _v17.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_V17_RELEASE_PARENT_SCHEMA
    )
    reader = cast(dict[str, object], projected["reader"])
    overlay_indices = {row[0] for row in _plan_overlays(plan)}
    overlay_variables = {abs(row[1]) for row in _plan_overlays(plan)}
    reader["ranked_literals"] = list(plan.source_rank_literals)
    reader["order_sha256"] = plan.source_rank_order_sha256
    for prefix in (
        "original_return_sequence",
        "original_release_sequence",
        "contrast_return_sequence",
        "contrast_release_sequence",
    ):
        _rewrite_i32_sequence(reader, prefix, overlay_variables)
    events = cast(list[dict[str, object]], reader["nonzero_return_events"])
    for event in events:
        if cast(int, event["rank_index"]) in overlay_indices:
            event["literal"] = -cast(int, event["literal"])
    pairs = cast(list[dict[str, object]], reader["pair_records"])
    for pair in pairs:
        if cast(int, pair["rank_index"]) in overlay_indices:
            pair["original_literal"] = -cast(int, pair["original_literal"])
            pair["contrast_literal"] = -cast(int, pair["contrast_literal"])
    calls = cast(int, reader["cb_decide_calls"])
    projected_parent_events = {
        cast(int, event["call"]): cast(int, event["literal"]) for event in events
    }
    reader["returned_sequence_sha256"] = _sparse_hash(calls, projected_parent_events)

    frontier = cast(dict[str, object], projected["frontier"])
    outer_events = dict(projected_parent_events)
    for event in cast(list[dict[str, object]], frontier["substitution_events"]):
        call = cast(int, event["call"])
        if call in outer_events:
            raise _error("projected outer event collision")
        outer_events[call] = cast(int, event["literal"])
    frontier["returned_sequence_sha256"] = _sparse_hash(calls, outer_events)
    return projected


def _lifecycle_plan(payload: Mapping[str, object]) -> _LifecycleStagingPlanView:
    staging = _mapping(payload.get("staging"), "staging reader")
    reader = _mapping(payload.get("reader"), "reader")
    effective = _rank_literals(reader)
    observed_count = _nonnegative(
        reader.get("observed_variable_count"), "observed variable count"
    )
    intersections = _telemetry_rows(
        staging.get("intersections"), field="intersections", width=4
    )
    overlays = _telemetry_rows(staging.get("overlays"), field="overlays", width=3)
    source = list(effective)
    for rank_index, source_literal, effective_literal in overlays:
        if rank_index >= len(source) or source[rank_index] != effective_literal:
            raise _error("lifecycle overlay rank")
        source[rank_index] = source_literal

    @dataclass(frozen=True)
    class _Intersection:
        rank_index: int
        clause_literal: int
        source_literal: int
        effective_literal: int

    @dataclass(frozen=True)
    class _Overlay:
        rank_index: int
        source_literal: int
        effective_literal: int

    return _LifecycleStagingPlanView(
        sha256=_sha(payload.get("staging_plan_sha256"), "staging plan hash"),
        source_result_sha256=_sha(
            payload.get("staging_source_result_sha256"), "source result hash"
        ),
        source_assignment_sha256=_sha(
            staging.get("source_assignment_sha256"), "assignment hash"
        ),
        active_vault_sha256=_sha(staging.get("active_vault_sha256"), "vault hash"),
        parent_frontier_plan_sha256=_sha(
            staging.get("parent_frontier_plan_sha256"), "frontier plan hash"
        ),
        selected_active_index=_nonnegative(
            staging.get("selected_active_index"), "selected active index"
        ),
        selected_union_index=_nonnegative(
            staging.get("selected_union_index"), "selected union index"
        ),
        selected_clause_sha256=_sha(
            staging.get("selected_clause_sha256"), "clause hash"
        ),
        selected_clause_literal_count=_positive(
            staging.get("selected_clause_literal_count"), "clause count"
        ),
        source_rank_payload_sha256=_sha(
            staging.get("source_rank_payload_sha256"), "rank payload hash"
        ),
        source_rank_order_sha256=_sha(
            staging.get("source_rank_order_sha256"), "source order hash"
        ),
        effective_rank_order_sha256=_sha(
            staging.get("effective_rank_order_sha256"), "effective order hash"
        ),
        source_assignment_count=observed_count,
        source_rank_literals=tuple(source),
        effective_rank_literals=effective,
        intersections=tuple(_Intersection(*row) for row in intersections),
        overlays=tuple(_Overlay(*row) for row in overlays),
    )


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v15 staging and project the unchanged lifecycle to v17."""

    if (
        not isinstance(payload, Mapping)
        or set(payload) != _TOP_LEVEL_FIELDS
        or payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or payload.get("reader_rank_role") != RESIDUAL_POLARITY_STAGING_READER_RANK_ROLE
    ):
        raise _error("lifecycle contract")
    plan = _lifecycle_plan(payload)
    sieve = _mapping(payload.get("sieve"), "sieve")
    _validate_staging_reader(
        payload.get("staging"),
        plan=plan,
        parent_reader=_mapping(payload.get("reader"), "reader"),
        frontier_reader=_mapping(payload.get("frontier"), "frontier"),
        sieve_state=_mapping(sieve.get("state"), "sieve state"),
        require_staging_activation=False,
    )
    return _v17.validate_native_lifecycle(_project_to_source_rank(payload, plan))


def _promote_result(
    result: _v17.JointScoreSieveV17Result,
    *,
    raw: Mapping[str, object],
    staging_plan: ResidualPolarityStagingPlan,
    staging_reader: Mapping[str, object],
) -> JointScoreSieveV18Result:
    return JointScoreSieveV18Result(
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
        reader=dict(_mapping(raw.get("reader"), "reader")),
        rank_source_vault=result.rank_source_vault,
        frontier_plan=result.frontier_plan,
        frontier_reader=dict(_mapping(raw.get("frontier"), "frontier")),
        staging_plan=staging_plan,
        staging_reader=dict(staging_reader),
    )


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    rank_source_vault: ThresholdNoGoodVault,
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
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
    require_frontier_intervention: bool = False,
    require_staging_activation: bool = True,
) -> JointScoreSieveV18Result:
    """Validate effective staging, then reuse frozen v17 certification."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise _error("result fields")
    if (
        payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or payload.get("reader_rank_role") != RESIDUAL_POLARITY_STAGING_READER_RANK_ROLE
        or _sha(payload.get("staging_plan_sha256"), "staging plan hash")
        != staging_plan.sha256
        or _sha(payload.get("staging_source_result_sha256"), "source result hash")
        != staging_plan.source_result_sha256
        or staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256
    ):
        raise _error("result provenance")
    reader = _mapping(payload.get("reader"), "reader")
    frontier = _mapping(payload.get("frontier"), "frontier")
    sieve = _mapping(payload.get("sieve"), "sieve")
    staging_reader = _validate_staging_reader(
        payload.get("staging"),
        plan=staging_plan,
        parent_reader=reader,
        frontier_reader=frontier,
        sieve_state=_mapping(sieve.get("state"), "sieve state"),
        require_staging_activation=require_staging_activation,
    )
    projected = _project_to_source_rank(payload, staging_plan)
    try:
        parent = _v17._parse_native_payload(
            projected,
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
            frontier_plan=frontier_plan,
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
            require_frontier_intervention=require_frontier_intervention,
        )
    except O1RelationalSearchError as exc:
        raise _error("native payload validation") from exc
    return _promote_result(
        parent,
        raw=payload,
        staging_plan=staging_plan,
        staging_reader=staging_reader,
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
    return _v17._parse_and_certify_vault(
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
    staging_plan_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = False,
    require_staging_activation: bool = True,
) -> JointScoreSieveV18Result:
    requested = _v17._v16._v15._v14._v13._v12._v11._v9._requested_conflicts(
        conflict_limit
    )
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
        or not all(
            isinstance(value, bool)
            for value in (
                require_active_contrast,
                require_frontier_intervention,
                require_staging_activation,
            )
        )
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
    io_v1 = _v17._v16._v15._v14._v13._v12._v11._v9._v8._v1
    io_v8 = _v17._v16._v15._v14._v13._v12._v11._v9._v8
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
        frontier_file, frontier_bytes = _v17._frontier._read_regular_file(
            frontier_plan_path
        )
        staging_file, staging_bytes = _staging._read_regular_file(staging_plan_path)
    except (CausalFrontierError, ResidualPolarityStagingError) as exc:
        raise _error("plan input") from exc
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
    identity = vault_identity_from_sources(
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
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="rank-source",
    )
    input_vault = _parse_and_certify_vault(
        active_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="active",
    )
    try:
        frontier_plan = _v17._frontier.parse_causal_frontier_plan(
            frontier_bytes, active_vault=input_vault
        )
        staging_plan = _staging.parse_residual_polarity_staging_plan(
            staging_bytes,
            active_vault=input_vault,
            rank_decision=expected_decision,
        )
    except (CausalFrontierError, ResidualPolarityStagingError) as exc:
        raise _error("plan certification") from exc
    if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
        raise _error("parent frontier plan binding")

    rank_path, rank_bytes = _v17._v16._v15._v14._v13._rank_table_temp(expected_decision)
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
        str(frontier_file),
        "--staging-plan",
        str(staging_file),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: object | None = None
    executor = io_v8._v7
    try:
        try:
            execution = executor._execute_native(
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
            io_v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
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
                frontier_plan_path, frontier_file, frontier_bytes, field="frontier plan"
            )
            io_v1._verify_stable_input(
                staging_plan_path, staging_file, staging_bytes, field="staging plan"
            )
            if rank_path.read_bytes() != rank_bytes:
                raise _error("rank table changed during execution")
        except Exception as exc:
            if execution is not None:
                _v17._v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
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
        _v17._v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v18 execution failed: {detail}"
        ) from failure
    try:
        payload = json.loads(completed.stdout)
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
            frontier_plan=frontier_plan,
            staging_plan=staging_plan,
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
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
            require_staging_activation=require_staging_activation,
        )
        return replace(
            result,
            stats=_v17._v16._v15.derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        raise _error("result JSON") from exc


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
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = False,
    require_staging_activation: bool = True,
) -> JointScoreSieveV18Result:
    """Run native v15 with stable source rank, frontier, and staging plans."""

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
            vault_caps=vault_caps,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
            require_staging_activation=require_staging_activation,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v17._v16._v15._v14._v13._v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v18"):
            message = f"joint-score-sieve-v18 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [  # pyright: ignore[reportUnsupportedDunderAll]
    *(
        name
        for name in _v17.__all__
        if name
        not in {
            "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
            "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
            "JointScoreSieveV17Result",
            "run_joint_score_sieve",
            "validate_native_lifecycle",
        }
    ),
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_V17_RELEASE_PARENT_SCHEMA",
    "RESIDUAL_POLARITY_STAGING_READER_SCHEMA",
    "JointScoreSieveV18Result",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
]
