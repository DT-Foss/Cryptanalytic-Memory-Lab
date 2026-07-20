"""Strict rescue-prefix preemption adapter for native joint sieve v16.

Native v16 places one immutable once-only prefix in front of the complete v15
staging/v14 frontier/v12 release-contrast stack.  This adapter proves the
outer chronology and exact parent suffix, then projects the untouched parent
envelope to v18 for all frozen sieve, vault, frontier, and staging checks.
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

from . import joint_score_sieve_v18 as _v18
from . import rescue_prefix_preemption_v1 as _prefix
from .causal_frontier_v1 import CausalFrontierError, CausalFrontierPlan
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .rescue_prefix_preemption_v1 import (
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
)
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v19-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v16"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v18.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA = _v18.JOINT_SCORE_SIEVE_RESULT_SCHEMA
JOINT_SCORE_SIEVE_V18_RELEASE_PARENT_SCHEMA = (
    _v18.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_BOUND_RULE = _v18.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v18.JointScoreSieveExecutionError
write_joint_score_sieve_grouping = _v18.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v18.write_joint_score_sieve_potential

RESCUE_PREFIX_PREEMPTION_READER_SCHEMA = (
    "o1-256-cadical-rescue-prefix-preemption-reader-v1"
)
RESCUE_PREFIX_PREEMPTION_OPERATOR = (
    "once-only-ordered-prefix-before-inherited-v15"
)
RESCUE_PREFIX_PREEMPTION_DECISION_RULE = (
    "scan-exact-order;consume-assigned;return-first-unassigned-once;after-"
    "all-consumed-return-one-parent-result-unchanged"
)
RESCUE_PREFIX_PREEMPTION_CALLBACK_RULE = (
    "no-parent-before-complete-prefix;then-one-parent-call-per-callback;"
    "never-override-or-discard-parent-return"
)
RESCUE_PREFIX_PREEMPTION_ONCE_SEQUENCE_ENCODING = (
    "concatenated-signed-i32le-literals-in-return-order"
)
RESCUE_PREFIX_PREEMPTION_RETURNED_SEQUENCE_ENCODING = (
    "one-signed-i32le-literal-per-cb-decide-including-zero"
)
RESCUE_PREFIX_PREEMPTION_BOUNDED_STATE_RULE = (
    "observed-i8-assignment;bounded-observed-u32-local,u32-level-trail;"
    "immutable-prefix-u32-local;bounded-4194304-outer-and-parent-return-"
    "bytes;bounded-once-u32-and-one-event-per-prefix-row"
)

_TOP_LEVEL_FIELDS = _v18._TOP_LEVEL_FIELDS | {
    "prefix_preemption_plan_sha256",
    "prefix_preemption_source_result_sha256",
    "prefix_preemption",
}
_PREFIX_FIELDS = {
    "schema",
    "operator",
    "plan_sha256",
    "source_result_sha256",
    "source_assignment_sha256",
    "active_vault_sha256",
    "parent_staging_plan_sha256",
    "baseline_trace_sha256",
    "prefix_order_encoding",
    "prefix_order_bytes",
    "prefix_order_sha256",
    "prefix_literals",
    "decision_rule",
    "callback_rule",
    "cursor",
    "rows_consumed",
    "once_returns",
    "skipped_preassigned_falsifying",
    "skipped_preassigned_rescue",
    "cb_decide_calls",
    "parent_cb_decide_calls",
    "outer_nonzero_returns",
    "outer_zero_returns",
    "parent_nonzero_returns",
    "parent_zero_returns",
    "first_once_return_call",
    "first_parent_call",
    "all_rows_consumed_before_first_parent_call",
    "mechanism_activated",
    "assignment_literals_observed",
    "once_return_sequence_encoding",
    "once_return_sequence_count",
    "once_return_sequence_bytes",
    "once_return_sequence_hex",
    "once_return_sequence_sha256",
    "outer_returned_sequence_encoding",
    "outer_returned_sequence_count",
    "outer_returned_sequence_bytes",
    "outer_returned_sequence_hex",
    "outer_returned_sequence_sha256",
    "parent_returned_sequence_encoding",
    "parent_returned_sequence_count",
    "parent_returned_sequence_bytes",
    "parent_returned_sequence_hex",
    "parent_returned_sequence_sha256",
    "once_return_events",
    "bounded_state_rule",
    "bounded_guidance_state_bytes",
    "live_guidance_state_bytes",
    "bounded_telemetry_state_bytes",
}
_MAXIMUM_CALLBACK_RECORDS = 4_194_304
_MAXIMUM_PREFIX_ROWS = 4_096
_PREFIX_EVENT_STATE_BYTES = 16


@dataclass(frozen=True)
class JointScoreSieveV19Result(_v18.JointScoreSieveV18Result):
    """A fully v18-validated result retaining prefix plan and telemetry."""

    prefix_preemption_plan: RescuePrefixPreemptionPlan
    prefix_preemption_reader: Mapping[str, object]

    @property
    def prefix_preemption_plan_sha256(self) -> str:
        return self.prefix_preemption_plan.sha256

    @property
    def prefix_preemption(self) -> Mapping[str, object]:
        return self.prefix_preemption_reader


def __getattr__(name: str) -> object:
    try:
        return getattr(_v18, name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc


def _error(field: str) -> O1RelationalSearchError:
    return O1RelationalSearchError(f"joint-score-sieve-v19 {field} differs")


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


def _literal(value: object, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value == 0
        or not -(1 << 31) < value < (1 << 31)
    ):
        raise _error(field)
    return value


def _i32_sequence(
    reader: Mapping[str, object],
    prefix: str,
    *,
    encoding: str,
    expected_count: int,
) -> tuple[tuple[int, ...], bytes]:
    payload = _hex(reader.get(f"{prefix}_hex"), f"{prefix} hex")
    if (
        reader.get(f"{prefix}_encoding") != encoding
        or reader.get(f"{prefix}_count") != expected_count
        or reader.get(f"{prefix}_bytes") != 4 * expected_count
        or len(payload) != 4 * expected_count
        or _sha(reader.get(f"{prefix}_sha256"), f"{prefix} hash")
        != hashlib.sha256(payload).hexdigest()
    ):
        raise _error(prefix)
    values = struct.unpack(f"<{expected_count}i", payload) if expected_count else ()
    return tuple(values), payload


def _validate_prefix_preemption(
    value: object,
    *,
    plan: RescuePrefixPreemptionPlan,
    staging_plan_sha256: str,
    active_vault_sha256: str,
    parent_reader: Mapping[str, object],
    parent_staging: Mapping[str, object],
    sieve_state: Mapping[str, object],
    sieve_trace_sha256: str,
    require_prefix_preemption_activation: bool,
) -> dict[str, object]:
    reader = _mapping(value, "prefix preemption reader")
    if set(reader) != _PREFIX_FIELDS:
        raise _error("prefix preemption reader fields")
    try:
        _prefix.validate_o1c78_production_plan(plan)
    except RescuePrefixPreemptionError as exc:
        raise _error("prefix plan identity") from exc
    literals = tuple(
        _literal(raw, "prefix literal")
        for raw in _sequence(reader.get("prefix_literals"), "prefix literals")
    )
    if (
        reader.get("schema") != RESCUE_PREFIX_PREEMPTION_READER_SCHEMA
        or reader.get("operator") != RESCUE_PREFIX_PREEMPTION_OPERATOR
        or reader.get("decision_rule") != RESCUE_PREFIX_PREEMPTION_DECISION_RULE
        or reader.get("callback_rule") != RESCUE_PREFIX_PREEMPTION_CALLBACK_RULE
        or reader.get("bounded_state_rule")
        != RESCUE_PREFIX_PREEMPTION_BOUNDED_STATE_RULE
        or _sha(reader.get("plan_sha256"), "prefix plan hash") != plan.sha256
        or _sha(reader.get("source_result_sha256"), "prefix source result hash")
        != _prefix.O1C78_SOURCE_RESULT_SHA256
        or _sha(
            reader.get("source_assignment_sha256"),
            "prefix source assignment hash",
        )
        != _prefix.O1C78_SOURCE_ASSIGNMENT_SHA256
        or _sha(reader.get("active_vault_sha256"), "prefix active vault hash")
        != active_vault_sha256
        or _sha(
            reader.get("parent_staging_plan_sha256"),
            "prefix parent staging hash",
        )
        != staging_plan_sha256
        or _sha(reader.get("baseline_trace_sha256"), "prefix baseline trace")
        != _prefix.O1C78_BASELINE_TRACE_SHA256
        or reader.get("prefix_order_encoding")
        != _prefix.RESCUE_PREFIX_PREEMPTION_PREFIX_ENCODING
        or reader.get("prefix_order_bytes") != plan.serialized_bytes
        or _sha(reader.get("prefix_order_sha256"), "prefix order hash")
        != plan.prefix_order_sha256
        or literals != plan.prefix_literals
    ):
        raise _error("prefix preemption binding")

    cursor = _nonnegative(reader.get("cursor"), "prefix cursor")
    rows = _nonnegative(reader.get("rows_consumed"), "prefix rows consumed")
    once = _nonnegative(reader.get("once_returns"), "prefix once returns")
    skipped_false = _nonnegative(
        reader.get("skipped_preassigned_falsifying"),
        "prefix falsifying skips",
    )
    skipped_rescue = _nonnegative(
        reader.get("skipped_preassigned_rescue"), "prefix rescue skips"
    )
    calls = _nonnegative(reader.get("cb_decide_calls"), "outer callback count")
    parent_calls = _nonnegative(
        reader.get("parent_cb_decide_calls"), "parent callback count"
    )
    outer_nonzero = _nonnegative(
        reader.get("outer_nonzero_returns"), "outer nonzero returns"
    )
    outer_zero = _nonnegative(
        reader.get("outer_zero_returns"), "outer zero returns"
    )
    parent_nonzero = _nonnegative(
        reader.get("parent_nonzero_returns"), "parent nonzero returns"
    )
    parent_zero = _nonnegative(
        reader.get("parent_zero_returns"), "parent zero returns"
    )
    mechanism = _boolean(reader.get("mechanism_activated"), "prefix activation")
    first_once = _nullable_positive(
        reader.get("first_once_return_call"), "first prefix return call"
    )
    first_parent = _nullable_positive(
        reader.get("first_parent_call"), "first parent call"
    )
    consumed_before_parent = _boolean(
        reader.get("all_rows_consumed_before_first_parent_call"),
        "prefix parent handoff",
    )
    if (
        cursor != rows
        or rows > len(literals)
        or rows != once + skipped_false + skipped_rescue
        or calls > _MAXIMUM_CALLBACK_RECORDS
        or calls != once + parent_calls
        or calls != outer_nonzero + outer_zero
        or parent_calls != parent_nonzero + parent_zero
        or parent_staging.get("cb_decide_calls") != parent_calls
        or parent_staging.get("nonzero_returns") != parent_nonzero
        or parent_staging.get("zero_returns") != parent_zero
        or mechanism != bool(once)
        or first_once != (1 if once else None)
        or first_parent != (once + 1 if parent_calls else None)
        or (parent_calls > 0) != consumed_before_parent
        or (parent_calls and rows != len(literals))
    ):
        raise _error("prefix callback accounting")

    once_values, once_payload = _i32_sequence(
        reader,
        "once_return_sequence",
        encoding=RESCUE_PREFIX_PREEMPTION_ONCE_SEQUENCE_ENCODING,
        expected_count=once,
    )
    outer_values, outer_payload = _i32_sequence(
        reader,
        "outer_returned_sequence",
        encoding=RESCUE_PREFIX_PREEMPTION_RETURNED_SEQUENCE_ENCODING,
        expected_count=calls,
    )
    parent_values, parent_payload = _i32_sequence(
        reader,
        "parent_returned_sequence",
        encoding=RESCUE_PREFIX_PREEMPTION_RETURNED_SEQUENCE_ENCODING,
        expected_count=parent_calls,
    )
    inherited_parent_payload = _hex(
        parent_staging.get("returned_sequence_hex"),
        "inherited parent returned sequence",
    )
    if (
        sum(value != 0 for value in outer_values) != outer_nonzero
        or sum(value != 0 for value in parent_values) != parent_nonzero
        or outer_payload != once_payload + parent_payload
        or parent_payload != inherited_parent_payload
        or parent_staging.get("returned_sequence_bytes") != len(parent_payload)
        or parent_staging.get("returned_sequence_sha256")
        != hashlib.sha256(parent_payload).hexdigest()
    ):
        raise _error("prefix parent pass-through")

    events = _sequence(reader.get("once_return_events"), "prefix return events")
    expected_values: list[int] = []
    prior_index = -1
    if len(events) != once:
        raise _error("prefix return event count")
    for ordinal, raw in enumerate(events, start=1):
        event = _mapping(raw, "prefix return event")
        if set(event) != {"call", "prefix_index", "literal"}:
            raise _error("prefix return event fields")
        call = _positive(event.get("call"), "prefix return event call")
        index = _nonnegative(event.get("prefix_index"), "prefix return event index")
        literal = _literal(event.get("literal"), "prefix return event literal")
        if (
            call != ordinal
            or index <= prior_index
            or index >= len(literals)
            or literal != literals[index]
        ):
            raise _error("prefix return event chronology")
        prior_index = index
        expected_values.append(literal)
    if tuple(expected_values) != once_values:
        raise _error("prefix returned subsequence")

    observed_assignments = _nonnegative(
        parent_staging.get("assignment_literals_observed"),
        "parent observed assignments",
    )
    assignment_observed = _nonnegative(
        reader.get("assignment_literals_observed"), "prefix observed assignments"
    )
    observed_count = _positive(
        parent_reader.get("observed_variable_count"), "observed variable count"
    )
    state_assigned = _nonnegative(
        sieve_state.get("current_assigned_variables"), "current assigned variables"
    )
    # The prefix and inherited staging receive identical assignment callbacks.
    if assignment_observed != observed_assignments:
        raise _error("prefix assignment observation")

    bounded_guidance = _positive(
        reader.get("bounded_guidance_state_bytes"), "prefix bounded guidance"
    )
    live_guidance = _positive(
        reader.get("live_guidance_state_bytes"), "prefix live guidance"
    )
    bounded_telemetry = _positive(
        reader.get("bounded_telemetry_state_bytes"), "prefix bounded telemetry"
    )
    if (
        bounded_guidance != 4 + 9 * observed_count + 4 * len(literals)
        or live_guidance
        != 4 + observed_count + 8 * state_assigned + 4 * len(literals)
        or state_assigned > observed_count
        or bounded_telemetry
        != bounded_guidance
        + 8 * _MAXIMUM_CALLBACK_RECORDS
        + 4 * _MAXIMUM_PREFIX_ROWS
        + _MAXIMUM_PREFIX_ROWS * _PREFIX_EVENT_STATE_BYTES
    ):
        raise _error("bounded prefix state")

    trace = _sha(sieve_trace_sha256, "native trace hash")
    if require_prefix_preemption_activation and (
        rows != len(literals)
        or once + skipped_false != len(literals)
        or skipped_rescue != 0
        or once < 1
        or not mechanism
        or parent_calls < 1
        or not consumed_before_parent
        or trace == _prefix.O1C78_BASELINE_TRACE_SHA256
    ):
        raise _error("qualified prefix activation")
    return dict(reader)


def _project_to_v18(payload: Mapping[str, object]) -> dict[str, object]:
    projected = copy.deepcopy(dict(payload))
    projected.pop("prefix_preemption_plan_sha256")
    projected.pop("prefix_preemption_source_result_sha256")
    projected.pop("prefix_preemption")
    projected["schema"] = _v18.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        _v18.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    )
    return projected


def _promote_result(
    result: _v18.JointScoreSieveV18Result,
    *,
    raw: Mapping[str, object],
    prefix_plan: RescuePrefixPreemptionPlan,
    prefix_reader: Mapping[str, object],
) -> JointScoreSieveV19Result:
    return JointScoreSieveV19Result(
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
        frontier_plan=result.frontier_plan,
        frontier_reader=result.frontier_reader,
        staging_plan=result.staging_plan,
        staging_reader=result.staging_reader,
        prefix_preemption_plan=prefix_plan,
        prefix_preemption_reader=dict(prefix_reader),
    )


def _plan_from_reader(value: object) -> RescuePrefixPreemptionPlan:
    reader = _mapping(value, "prefix preemption reader")
    literals = tuple(
        _literal(raw, "prefix literal")
        for raw in _sequence(reader.get("prefix_literals"), "prefix literals")
    )
    try:
        return RescuePrefixPreemptionPlan(literals)
    except RescuePrefixPreemptionError as exc:
        raise _error("prefix plan") from exc


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v16 prefix chronology and reuse the complete v18 lifecycle."""

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
    prefix_value = payload.get("prefix_preemption")
    plan = _plan_from_reader(prefix_value)
    if (
        _sha(payload.get("prefix_preemption_plan_sha256"), "prefix plan hash")
        != plan.sha256
        or _sha(
            payload.get("prefix_preemption_source_result_sha256"),
            "prefix source result hash",
        )
        != _prefix.O1C78_SOURCE_RESULT_SHA256
    ):
        raise _error("lifecycle prefix provenance")
    sieve = _mapping(payload.get("sieve"), "sieve")
    vault = _mapping(payload.get("vault"), "vault")
    _validate_prefix_preemption(
        prefix_value,
        plan=plan,
        staging_plan_sha256=_sha(
            payload.get("staging_plan_sha256"), "staging plan hash"
        ),
        active_vault_sha256=_sha(vault.get("input_sha256"), "active vault hash"),
        parent_reader=_mapping(payload.get("reader"), "reader"),
        parent_staging=_mapping(payload.get("staging"), "staging"),
        sieve_state=_mapping(sieve.get("state"), "sieve state"),
        sieve_trace_sha256=_sha(sieve.get("trace_sha256"), "sieve trace hash"),
        require_prefix_preemption_activation=False,
    )
    return _v18.validate_native_lifecycle(_project_to_v18(payload))


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    rank_source_vault: ThresholdNoGoodVault,
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
    prefix_preemption_plan: RescuePrefixPreemptionPlan,
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
    require_prefix_preemption_activation: bool = True,
) -> JointScoreSieveV19Result:
    """Validate outer prefix preemption, then reuse frozen v18 certification."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise _error("result fields")
    try:
        _prefix.validate_o1c78_production_plan(prefix_preemption_plan)
    except RescuePrefixPreemptionError as exc:
        raise _error("prefix plan identity") from exc
    if (
        payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or _sha(payload.get("prefix_preemption_plan_sha256"), "prefix plan hash")
        != prefix_preemption_plan.sha256
        or _sha(
            payload.get("prefix_preemption_source_result_sha256"),
            "prefix source result hash",
        )
        != _prefix.O1C78_SOURCE_RESULT_SHA256
        or _sha(payload.get("staging_plan_sha256"), "staging plan hash")
        != staging_plan.sha256
    ):
        raise _error("result provenance")
    parent_reader = _mapping(payload.get("reader"), "reader")
    parent_staging = _mapping(payload.get("staging"), "staging")
    sieve = _mapping(payload.get("sieve"), "sieve")
    prefix_reader = _validate_prefix_preemption(
        payload.get("prefix_preemption"),
        plan=prefix_preemption_plan,
        staging_plan_sha256=staging_plan.sha256,
        active_vault_sha256=input_vault.sha256,
        parent_reader=parent_reader,
        parent_staging=parent_staging,
        sieve_state=_mapping(sieve.get("state"), "sieve state"),
        sieve_trace_sha256=_sha(sieve.get("trace_sha256"), "sieve trace hash"),
        require_prefix_preemption_activation=require_prefix_preemption_activation,
    )
    try:
        parent = _v18._parse_native_payload(
            _project_to_v18(payload),
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
            frontier_plan=frontier_plan,
            staging_plan=staging_plan,
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
            require_staging_activation=require_staging_activation,
        )
    except O1RelationalSearchError as exc:
        raise _error("native payload validation") from exc
    return _promote_result(
        parent,
        raw=payload,
        prefix_plan=prefix_preemption_plan,
        prefix_reader=prefix_reader,
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
    return _v18._parse_and_certify_vault(
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
    prefix_plan_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = False,
    require_staging_activation: bool = True,
    require_prefix_preemption_activation: bool = True,
) -> JointScoreSieveV19Result:
    requested = _v18._v17._v16._v15._v14._v13._v12._v11._v9._requested_conflicts(
        conflict_limit
    )
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise _error("native vault caps")
    flags = (
        require_active_contrast,
        require_frontier_intervention,
        require_staging_activation,
        require_prefix_preemption_activation,
    )
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
        or not all(isinstance(value, bool) for value in flags)
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
    io_v1 = _v18._v17._v16._v15._v14._v13._v12._v11._v9._v8._v1
    io_v8 = _v18._v17._v16._v15._v14._v13._v12._v11._v9._v8
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
        frontier_file, frontier_bytes = _v18._v17._frontier._read_regular_file(
            frontier_plan_path
        )
        staging_file, staging_bytes = _v18._staging._read_regular_file(
            staging_plan_path
        )
        prefix_file, prefix_bytes = _prefix._read_regular_file(prefix_plan_path)
    except (
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
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
        frontier_plan = _v18._v17._frontier.parse_causal_frontier_plan(
            frontier_bytes, active_vault=input_vault
        )
        staging_plan = _v18._staging.parse_residual_polarity_staging_plan(
            staging_bytes,
            active_vault=input_vault,
            rank_decision=expected_decision,
        )
        prefix_plan = _prefix.parse_rescue_prefix_preemption_plan(
            prefix_bytes, active_vault=input_vault
        )
        _prefix.validate_rescue_prefix_preemption_plan(
            prefix_plan,
            active_vault=input_vault,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=_prefix.O1C78_BASELINE_TRACE_SHA256,
            required_prefix_literals=_prefix.O1C78_PREFIX_LITERALS,
        )
        _prefix.validate_o1c78_production_plan(prefix_plan)
    except (
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise _error("plan certification") from exc
    if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
        raise _error("parent frontier plan binding")

    rank_path, rank_bytes = (
        _v18._v17._v16._v15._v14._v13._rank_table_temp(expected_decision)
    )
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
                prefix_plan_path,
                prefix_file,
                prefix_bytes,
                field="prefix plan",
            )
            if rank_path.read_bytes() != rank_bytes:
                raise _error("rank table changed during execution")
        except Exception as exc:
            if execution is not None:
                _v18._v17._v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
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
        _v18._v17._v16._v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v19 execution failed: {detail}"
        ) from failure
    try:
        payload = json.loads(completed.stdout)
        result = _parse_native_payload(
            payload,
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
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
            require_staging_activation=require_staging_activation,
            require_prefix_preemption_activation=(
                require_prefix_preemption_activation
            ),
        )
        return replace(
            result,
            stats=_v18._v17._v16._v15.derive_vault_soft_conflict_ledger(
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
    prefix_plan_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
    require_frontier_intervention: bool = False,
    require_staging_activation: bool = True,
    require_prefix_preemption_activation: bool = True,
) -> JointScoreSieveV19Result:
    """Run native v16 with stable parent plans and exact prefix preemption."""

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
            require_active_contrast=require_active_contrast,
            require_frontier_intervention=require_frontier_intervention,
            require_staging_activation=require_staging_activation,
            require_prefix_preemption_activation=(
                require_prefix_preemption_activation
            ),
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = (
            _v18._v17._v16._v15._v14._v13._v12._v11._v9._v8._v7._failure_telemetry(
                exc,
                elapsed_seconds=elapsed,
                timeout_seconds=timeout_seconds,
                memory_limit_bytes=memory_limit_bytes,
            )
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v19"):
            message = f"joint-score-sieve-v19 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [  # pyright: ignore[reportUnsupportedDunderAll]
    *(
        name
        for name in _v18.__all__
        if name
        not in {
            "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
            "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
            "JointScoreSieveV18Result",
            "run_joint_score_sieve",
            "validate_native_lifecycle",
        }
    ),
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_V18_RELEASE_PARENT_SCHEMA",
    "RESCUE_PREFIX_PREEMPTION_READER_SCHEMA",
    "RescuePrefixPreemptionPlan",
    "JointScoreSieveV19Result",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
]
