"""Fail-closed adapter for O1C-0082's native-v19 live priority operator.

The adapter validates the native process as a proof-mining mechanism.  A
failure-first action is never promoted to a prune or key-bit belief, while a
certified crossing must use the strict ``min(U0, U1) < tau`` boundary.  The
24,576-byte final bank is validated as a continuation seed, not as a key.
"""

from __future__ import annotations

import hashlib
import json
import math
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import joint_score_sieve_v9 as _v9
from . import joint_score_sieve_v21 as _v21
from .criticality_potential import CriticalityPotentialField
from .o1_relational_search import O1RelationalSearchError
from .o1c82_parent_centered_seed import (
    BANK_BYTES,
    ELIGIBILITY_MINIMUM_COUNT,
    EXPECTED_BANK_SHA256,
    RECORD_BYTES,
    RECORD_STRUCT,
    parse_seed_bank,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v22-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v19"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
PRIORITY_STATE_SCHEMA = "o1-256-o1c82-live-parent-centered-priority-state-v1"
PRIORITY_ACTION_SCHEMA = "o1-256-o1c82-failure-first-proof-mining-actions-v1"
PRIORITY_OPERATOR_SCHEMA = "o1-256-o1c82-parent-centered-priority-telemetry-v1"
PRIORITY_SEED_SCHEMA = "o1-256-o1c82-parent-centered-priority-seed-v1"
PRIORITY_SEED_MAGIC = "O1C82-PCP-SEED1"

OPERATOR_SEMANTICS = "failure-first-proof-mining-with-certified-crossing-precedence"
CANDIDATE_ORDER_RULE = (
    "observed-key-variables-ascending;currently-unassigned-and-no-live-token"
)
ACTION_ORDER_RULE = (
    "certified-strict-U-less-than-tau-crossing-first;otherwise-highest-"
    "persistent-priority-unconsumed-current-coordinate"
)
ONE_SHOT_RULE = "coordinate-consumed-on-first-return;release-does-not-rearm"
PROOF_MINING_SEMANTIC = "FAILURE_FIRST_PROOF_MINING"
CERTIFIED_CROSSING_SEMANTIC = "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE"
TRANSPORT_ORIGIN = "BOUND_LOSING_CHILD"
PRODUCTION_PAGE8_SHA256 = (
    "89e085e7323ea9aaaa31ad1430c3f20ac03f9c21a49c6404374b75ddf59330f4"
)
PRODUCTION_PAGE8_BYTES = 2_769_351
PRODUCTION_CANDIDATES = tuple(variable for variable in range(1, 257) if variable != 241)
PROBE_TRACE_ENCODING = (
    "u64le-call;u64le-probe;u32le-candidate-index;u32le-parent-level;"
    "i32le-variable;f64le-U0;f64le-U1;f64le-tau;u8-selection;"
    "i32le-certified-literal"
)
PROBE_TRACE_RECORD_BYTES = 57
ACTION_TRACE_RECORD_BYTES = 45
NATIVE_SOURCE_RELATIVE = Path("native/cadical_o1_joint_score_sieve_v19.cpp")

_TOP_LEVEL_FIELDS = {
    "schema",
    "implementation_parent_schema",
    "operator_semantics",
    "priority_seed",
    "priority_state",
    "priority_actions",
    "decision_ownership",
    "cadical_version",
    "variables",
    "conflict_limit",
    "seed",
    "threshold",
    "status",
    "post_solve_state",
    "post_solve_state_name",
    "teardown_rule",
    "pending_backtrack_rule",
    "key_model_hex",
    "cnf_sha256",
    "potential_sha256",
    "active_vault_sha256",
    "stats",
    "base_sieve",
    "vault",
    "resources",
}
_SEED_FIELDS = {
    "magic",
    "schema",
    "payload_bytes",
    "payload_sha256",
    "production_seal_enforced",
    "expected_production_sha256",
    "import_roundtrip_exact",
    "initial_eligible_coordinate_count",
}
_STATE_FIELDS = {
    "schema",
    "operator",
    "candidate_population",
    "candidate_order_rule",
    "candidate_order_sha256",
    "parent_scans",
    "last_parent_candidate_count",
    "callback_calls",
    "nonzero_returns",
    "zero_returns",
    "assignment_literals_observed",
    "consumed_coordinate_count",
    "one_shot_rule",
    "bank_encoding",
    "bank_bytes",
    "bank_hex",
    "current_bank_sha256",
    "probe_trace",
    "probe_counters",
    "state_accounting",
}
_PROBE_TRACE_FIELDS = {"encoding", "record_bytes", "count", "bytes", "sha256"}
_PROBE_COUNTER_FIELDS = {
    "child_bound_evaluations",
    "NEITHER_PRUNABLE",
    "ZERO_PRUNABLE",
    "ONE_PRUNABLE",
    "BOTH_PRUNABLE",
}
_STATE_ACCOUNTING_FIELDS = {
    "priority_bank_bytes",
    "parent_scratch_bytes",
    "priority_live_state_bytes",
    "consumed_mask_bytes",
    "action_capacity",
    "action_record_bytes",
    "action_state_bytes",
    "growing_parent_history_bytes",
}
_ACTION_FIELDS = {
    "schema",
    "transport_origin",
    "transport_is_semantic_name",
    "action_order_rule",
    "one_shot_rule",
    "proof_mining_semantic",
    "certified_crossing_semantic",
    "belief_orientation_authorized",
    "posterior_emitted",
    "prune_claim_for_failure_first",
    "action_count",
    "failure_first_count",
    "certified_crossing_count",
    "level_bindings",
    "confirmed_actions",
    "coincident_v6_pending_actions",
    "releases",
    "unobserved_releases",
    "action_trace_bytes",
    "action_trace_sha256",
    "actions",
}
_ACTION_ROW_FIELDS = {
    "sequence",
    "token",
    "call",
    "first_probe",
    "parent_probe_count",
    "coordinate_index",
    "variable",
    "literal",
    "transport_origin",
    "semantic",
    "machine_action",
    "certified_threshold_action",
    "proof_mining_action",
    "belief_orientation_authorized",
    "parent_level",
    "bound_level",
    "parent_assignment_sha256",
    "upper_zero",
    "upper_one",
    "current_lower_upper_bound",
    "current_differential",
    "persistent_priority",
    "accumulated_count",
    "confirmed",
    "coincident_v6_pending",
    "released",
    "unobserved_release",
}
_OPERATOR_FIELDS = {
    "schema",
    "coordinate_capacity",
    "minimum_eligible_count",
    "eligible_coordinate_count",
    "current_parent_candidate_count",
    "priority_order",
    "action_semantics",
    "proof_mining_action_only",
    "belief_orientation_authorized",
    "selection",
    "state_accounting",
}
_OPERATOR_ACCOUNTING_FIELDS = {
    "packed_bytes_per_coordinate",
    "coordinate_state_bytes",
    "parent_scratch_bytes",
    "live_packed_state_bytes",
}
_SELECTION_FIELDS = {
    "available",
    "proof_mining_action",
    "belief_orientation_authorized",
    "variable",
    "action_literal",
    "current_differential",
    "coordinate",
}
_COORDINATE_FIELDS = {
    "variable",
    "count",
    "eligible",
    "raw_mean",
    "raw_variance",
    "raw_positive_fraction",
    "raw_negative_fraction",
    "raw_zero_fraction",
    "raw_directional_stability",
    "centered_mean",
    "centered_variance",
    "centered_positive_fraction",
    "centered_negative_fraction",
    "centered_zero_fraction",
    "centered_directional_stability",
    "centered_signed_consistency",
    "robust_z_mean",
    "robust_abs_z_mean",
    "robust_abs_z_max",
    "priority",
}


class JointScoreSieveV22Error(O1RelationalSearchError):
    """Native-v19 build, execution, or proof-boundary validation failed."""


@dataclass(frozen=True)
class JointScoreSieveV22Result:
    """Typed native-v19 result and its validated continuation seed."""

    status: int
    conflict_limit: int
    threshold: float
    key_model: bytes | None
    stats: Mapping[str, int]
    resources: Mapping[str, int]
    base_result: _v9.JointScoreSieveV9Result
    priority_seed: Mapping[str, object]
    priority_state: Mapping[str, object]
    priority_actions: Mapping[str, object]
    decision_ownership: Mapping[str, object]
    next_priority_seed: bytes
    normalized_summary: Mapping[str, object]
    raw: Mapping[str, object]
    native_stdout: str | None = None
    native_stdout_sha256: str | None = None
    command: tuple[str, ...] = ()

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _error(field: str) -> JointScoreSieveV22Error:
    return JointScoreSieveV22Error(f"joint-score-sieve-v22 {field} differs")


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
    if result == 0:
        raise _error(field)
    return result


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise _error(field)
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error(field)
    result = float(value)
    if not math.isfinite(result):
        raise _error(field)
    return result


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _error(field)
    return value


def _same_f64(left: object, right: float, field: str) -> float:
    value = _finite(left, field)
    if struct.pack("<d", value) != struct.pack("<d", right):
        raise _error(field)
    return value


def _base_v6_payload(root: Mapping[str, object]) -> dict[str, object]:
    result = {name: root[name] for name in _v9._TOP_LEVEL_FIELDS if name != "sieve"}
    result["schema"] = _v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    result["implementation_parent_schema"] = (
        _v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    result["sieve"] = root["base_sieve"]
    return result


def _candidate_order(field: CriticalityPotentialField) -> tuple[int, ...]:
    return tuple(
        variable for variable in field.observed_variables if 1 <= variable <= 256
    )


def _candidate_order_sha256(candidates: Sequence[int]) -> str:
    payload = b"".join(struct.pack("<I", variable) for variable in candidates)
    return hashlib.sha256(payload).hexdigest()


def _parse_continuation_bank(payload: bytes) -> tuple[tuple[object, ...], ...]:
    if len(payload) != BANK_BYTES:
        raise _error("continuation seed bytes")
    records: list[tuple[object, ...]] = []
    for variable in range(1, 257):
        offset = (variable - 1) * RECORD_BYTES
        values = RECORD_STRUCT.unpack_from(payload, offset)
        count = values[0]
        raw_positive, raw_zero = values[3], values[4]
        centered_positive, centered_zero = values[7], values[8]
        floats = (values[1], values[2], values[5], values[6], *values[9:12])
        if (
            any(not math.isfinite(value) for value in floats)
            or values[2] < 0.0
            or values[6] < 0.0
            or raw_positive + raw_zero > count
            or centered_positive + centered_zero > count
            or values[10] < abs(values[9])
            or values[11] < values[10]
        ):
            raise _error("continuation seed record")
        records.append(values)
    return tuple(records)


def _validate_seed_report(
    value: object, *, seed_sha256: str, production_seal: bool
) -> Mapping[str, object]:
    report = _mapping(value, "priority seed")
    if set(report) != _SEED_FIELDS:
        raise _error("priority seed fields")
    if (
        report.get("magic") != PRIORITY_SEED_MAGIC
        or report.get("schema") != PRIORITY_SEED_SCHEMA
        or report.get("payload_bytes") != BANK_BYTES
        or report.get("payload_sha256") != seed_sha256
        or report.get("expected_production_sha256") != EXPECTED_BANK_SHA256
        or report.get("production_seal_enforced") is not production_seal
        or report.get("import_roundtrip_exact") is not True
        or _nonnegative(
            report.get("initial_eligible_coordinate_count"),
            "initial eligible coordinate count",
        )
        != 225
    ):
        raise _error("priority seed contract")
    return dict(report)


def _coordinate_values(
    variable: int, record: Sequence[object]
) -> dict[str, int | float | bool]:
    count = _positive(record[0], "selected coordinate count")
    raw_positive = _nonnegative(record[3], "selected raw positive count")
    raw_zero = _nonnegative(record[4], "selected raw zero count")
    centered_positive = _nonnegative(record[7], "selected centered positive count")
    centered_zero = _nonnegative(record[8], "selected centered zero count")
    raw_negative = count - raw_positive - raw_zero
    centered_negative = count - centered_positive - centered_zero
    raw_positive_fraction = raw_positive / count
    raw_negative_fraction = raw_negative / count
    centered_positive_fraction = centered_positive / count
    centered_negative_fraction = centered_negative / count
    centered_stability = max(centered_positive_fraction, centered_negative_fraction)
    robust_z_mean = _finite(record[9], "selected robust-z mean")
    return {
        "variable": variable,
        "count": count,
        "eligible": count >= ELIGIBILITY_MINIMUM_COUNT,
        "raw_mean": _finite(record[1], "selected raw mean"),
        "raw_variance": _finite(record[2], "selected raw M2") / count,
        "raw_positive_fraction": raw_positive_fraction,
        "raw_negative_fraction": raw_negative_fraction,
        "raw_zero_fraction": raw_zero / count,
        "raw_directional_stability": max(raw_positive_fraction, raw_negative_fraction),
        "centered_mean": _finite(record[5], "selected centered mean"),
        "centered_variance": _finite(record[6], "selected centered M2") / count,
        "centered_positive_fraction": centered_positive_fraction,
        "centered_negative_fraction": centered_negative_fraction,
        "centered_zero_fraction": centered_zero / count,
        "centered_directional_stability": centered_stability,
        "centered_signed_consistency": (centered_positive - centered_negative) / count,
        "robust_z_mean": robust_z_mean,
        "robust_abs_z_mean": _finite(record[10], "selected robust absolute-z mean"),
        "robust_abs_z_max": _finite(record[11], "selected robust absolute-z maximum"),
        "priority": abs(robust_z_mean) * math.sqrt(count) * centered_stability,
    }


def _validate_operator(
    value: object,
    records: Sequence[Sequence[object]],
    *,
    candidates: tuple[int, ...],
    last_parent_candidate_count: int,
) -> None:
    operator = _mapping(value, "priority operator")
    accounting = _mapping(operator.get("state_accounting"), "operator accounting")
    selection = _mapping(operator.get("selection"), "operator selection")
    current_parent_candidate_count = _nonnegative(
        operator.get("current_parent_candidate_count"),
        "operator current parent candidate count",
    )
    eligible_count = sum(
        _nonnegative(record[0], "continuation record count")
        >= ELIGIBILITY_MINIMUM_COUNT
        for record in records
    )
    if (
        set(operator) != _OPERATOR_FIELDS
        or set(accounting) != _OPERATOR_ACCOUNTING_FIELDS
        or set(selection) != _SELECTION_FIELDS
        or operator.get("schema") != PRIORITY_OPERATOR_SCHEMA
        or operator.get("coordinate_capacity") != 256
        or operator.get("minimum_eligible_count") != ELIGIBILITY_MINIMUM_COUNT
        or operator.get("eligible_coordinate_count") != eligible_count
        or current_parent_candidate_count != last_parent_candidate_count
        or operator.get("priority_order") != "score-desc,count-desc,variable-asc"
        or operator.get("action_semantics") != "current-lower-upper-bound-proof-mining"
        or operator.get("proof_mining_action_only") is not True
        or operator.get("belief_orientation_authorized") is not False
        or accounting
        != {
            "packed_bytes_per_coordinate": 96,
            "coordinate_state_bytes": 24_576,
            "parent_scratch_bytes": 4_096,
            "live_packed_state_bytes": 28_672,
        }
        or selection.get("proof_mining_action") is not True
        or selection.get("belief_orientation_authorized") is not False
    ):
        raise _error("priority operator contract")
    available = _boolean(selection.get("available"), "operator selection available")
    if not available:
        if any(
            selection.get(name) is not None
            for name in (
                "variable",
                "action_literal",
                "current_differential",
                "coordinate",
            )
        ):
            raise _error("unavailable operator selection")
        return
    variable = _positive(selection.get("variable"), "operator selection variable")
    literal = selection.get("action_literal")
    differential = _finite(
        selection.get("current_differential"), "operator selection differential"
    )
    coordinate = _mapping(selection.get("coordinate"), "selection coordinate")
    expected_coordinate = _coordinate_values(variable, records[variable - 1])
    if (
        variable not in candidates
        or current_parent_candidate_count == 0
        or isinstance(literal, bool)
        or not isinstance(literal, int)
        or literal != (-variable if differential <= 0.0 else variable)
        or set(coordinate) != _COORDINATE_FIELDS
        or any(
            coordinate.get(name) != expected
            for name, expected in expected_coordinate.items()
        )
    ):
        raise _error("operator selection mapping")


def _validate_priority_state(
    value: object,
    *,
    candidates: tuple[int, ...],
) -> tuple[Mapping[str, object], bytes, dict[str, int]]:
    state = _mapping(value, "priority state")
    if set(state) != _STATE_FIELDS or state.get("schema") != PRIORITY_STATE_SCHEMA:
        raise _error("priority state fields")
    if (
        state.get("candidate_population") != len(candidates)
        or state.get("candidate_order_rule") != CANDIDATE_ORDER_RULE
        or state.get("candidate_order_sha256") != _candidate_order_sha256(candidates)
        or state.get("one_shot_rule") != ONE_SHOT_RULE
        or state.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
    ):
        raise _error("priority state identity")
    parent_scans = _nonnegative(state.get("parent_scans"), "parent scans")
    callback_calls = _nonnegative(state.get("callback_calls"), "callback calls")
    nonzero = _nonnegative(state.get("nonzero_returns"), "nonzero returns")
    zero = _nonnegative(state.get("zero_returns"), "zero returns")
    last_candidates = _nonnegative(
        state.get("last_parent_candidate_count"), "last parent candidate count"
    )
    consumed = _nonnegative(
        state.get("consumed_coordinate_count"), "consumed coordinate count"
    )
    if (
        parent_scans != callback_calls
        or callback_calls != nonzero + zero
        or last_candidates > len(candidates)
        or consumed > len(candidates)
    ):
        raise _error("priority callback ledger")
    hexadecimal = state.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise _error("priority bank hex")
    try:
        bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise _error("priority bank hex") from exc
    digest = hashlib.sha256(bank).hexdigest()
    if (
        state.get("bank_bytes") != BANK_BYTES
        or len(bank) != BANK_BYTES
        or state.get("current_bank_sha256") != digest
        or bank[240 * RECORD_BYTES : 241 * RECORD_BYTES] != bytes(RECORD_BYTES)
    ):
        raise _error("priority bank seal")
    records = _parse_continuation_bank(bank)
    _validate_operator(
        state.get("operator"),
        records,
        candidates=candidates,
        last_parent_candidate_count=last_candidates,
    )

    trace = _mapping(state.get("probe_trace"), "probe trace")
    counters = _mapping(state.get("probe_counters"), "probe counters")
    accounting = _mapping(state.get("state_accounting"), "state accounting")
    if (
        set(trace) != _PROBE_TRACE_FIELDS
        or set(counters) != _PROBE_COUNTER_FIELDS
        or set(accounting) != _STATE_ACCOUNTING_FIELDS
        or trace.get("encoding") != PROBE_TRACE_ENCODING
        or trace.get("record_bytes") != PROBE_TRACE_RECORD_BYTES
        or accounting.get("priority_bank_bytes") != 24_576
        or accounting.get("parent_scratch_bytes") != 4_096
        or accounting.get("priority_live_state_bytes") != 28_672
        or accounting.get("consumed_mask_bytes") != 256
        or accounting.get("action_capacity") != 256
        or accounting.get("action_state_bytes")
        != _positive(accounting.get("action_record_bytes"), "action record bytes") * 256
        or accounting.get("growing_parent_history_bytes") != 0
    ):
        raise _error("bounded state accounting")
    probe_count = _nonnegative(trace.get("count"), "probe trace count")
    if (
        trace.get("bytes") != probe_count * PROBE_TRACE_RECORD_BYTES
        or _sha(trace.get("sha256"), "probe trace SHA-256") == ""
    ):
        raise _error("probe trace envelope")
    class_counts = {
        name: _nonnegative(counters.get(name), f"probe counter {name}")
        for name in (
            "NEITHER_PRUNABLE",
            "ZERO_PRUNABLE",
            "ONE_PRUNABLE",
            "BOTH_PRUNABLE",
        )
    }
    if (
        sum(class_counts.values()) != probe_count
        or counters.get("child_bound_evaluations") != 2 * probe_count
        or probe_count > parent_scans * len(candidates)
    ):
        raise _error("probe counter ledger")
    summary = {
        "parent_scans": parent_scans,
        "callback_calls": callback_calls,
        "nonzero_returns": nonzero,
        "zero_returns": zero,
        "consumed_coordinate_count": consumed,
        "probe_count": probe_count,
        "child_bound_evaluations": 2 * probe_count,
    }
    return dict(state), bank, summary


def _validate_actions(
    value: object,
    *,
    threshold: float,
    candidates: tuple[int, ...],
    probe_count: int,
    parent_scans: int,
) -> tuple[Mapping[str, object], tuple[Mapping[str, object], ...], dict[str, int]]:
    report = _mapping(value, "priority actions")
    if set(report) != _ACTION_FIELDS:
        raise _error("priority action fields")
    fixed = {
        "schema": PRIORITY_ACTION_SCHEMA,
        "transport_origin": TRANSPORT_ORIGIN,
        "transport_is_semantic_name": False,
        "action_order_rule": ACTION_ORDER_RULE,
        "one_shot_rule": ONE_SHOT_RULE,
        "proof_mining_semantic": PROOF_MINING_SEMANTIC,
        "certified_crossing_semantic": CERTIFIED_CROSSING_SEMANTIC,
        "belief_orientation_authorized": False,
        "posterior_emitted": False,
        "prune_claim_for_failure_first": False,
    }
    if any(report.get(name) != expected for name, expected in fixed.items()):
        raise _error("priority action contract")
    rows_raw = _sequence(report.get("actions"), "priority action rows")
    rows: list[Mapping[str, object]] = []
    trace = bytearray()
    variables: set[int] = set()
    failure_count = 0
    crossing_count = 0
    level_bindings = 0
    confirmed = 0
    coincident = 0
    releases = 0
    unobserved = 0
    candidate_set = set(candidates)
    for index, raw in enumerate(rows_raw, start=1):
        row = _mapping(raw, "priority action row")
        if set(row) != _ACTION_ROW_FIELDS:
            raise _error("priority action row fields")
        token = _positive(row.get("token"), "action token")
        call = _positive(row.get("call"), "action call")
        first_probe = _positive(row.get("first_probe"), "action first probe")
        parent_probes = _positive(
            row.get("parent_probe_count"), "action parent probe count"
        )
        coordinate = _nonnegative(row.get("coordinate_index"), "action coordinate")
        variable = _positive(row.get("variable"), "action variable")
        literal = row.get("literal")
        upper_zero = _finite(row.get("upper_zero"), "action upper zero")
        upper_one = _finite(row.get("upper_one"), "action upper one")
        lower = _finite(row.get("current_lower_upper_bound"), "action lower upper")
        differential = _finite(row.get("current_differential"), "action differential")
        priority = _finite(row.get("persistent_priority"), "action priority")
        accumulated = _nonnegative(row.get("accumulated_count"), "action count")
        semantic = row.get("semantic")
        if (
            row.get("sequence") != index
            or token != index
            or variable not in candidate_set
            or variable in variables
            or coordinate != variable - 1
            or isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal != (-variable if upper_zero <= upper_one else variable)
            or lower != min(upper_zero, upper_one)
            or differential != upper_zero - upper_one
            or priority < 0.0
            or accumulated < ELIGIBILITY_MINIMUM_COUNT
            or row.get("transport_origin") != TRANSPORT_ORIGIN
            or row.get("belief_orientation_authorized") is not False
            or first_probe + parent_probes - 1 > probe_count
            or parent_probes > len(candidates)
            or call > parent_scans
            or len(_sha(row.get("parent_assignment_sha256"), "parent assignment")) != 64
        ):
            raise _error("priority action semantics")
        variables.add(variable)
        if semantic == PROOF_MINING_SEMANTIC:
            failure_count += 1
            code = 1
            if (
                lower < threshold
                or row.get("machine_action") != PROOF_MINING_SEMANTIC
                or row.get("proof_mining_action") is not True
                or row.get("certified_threshold_action") is not False
            ):
                raise _error("failure-first nonclaim")
        elif semantic == CERTIFIED_CROSSING_SEMANTIC:
            crossing_count += 1
            code = 2
            if (
                not lower < threshold
                or row.get("machine_action") != "CERTIFIED_STRICT_BOUND_CROSSING"
                or row.get("proof_mining_action") is not False
                or row.get("certified_threshold_action") is not True
                or row.get("coincident_v6_pending") is not False
            ):
                raise _error("certified crossing boundary")
        else:
            raise _error("action semantic class")
        bound_level = row.get("bound_level")
        if bound_level is not None:
            _positive(bound_level, "action bound level")
            if (
                bound_level
                != _nonnegative(row.get("parent_level"), "action parent level") + 1
            ):
                raise _error("action bound level")
            level_bindings += 1
        is_confirmed = _boolean(row.get("confirmed"), "action confirmed")
        is_coincident = _boolean(row.get("coincident_v6_pending"), "coincident")
        is_released = _boolean(row.get("released"), "action released")
        is_unobserved = _boolean(row.get("unobserved_release"), "unobserved release")
        if (
            (is_confirmed and bound_level is None)
            or (
                is_coincident
                and (semantic != PROOF_MINING_SEMANTIC or not is_confirmed)
            )
            or is_unobserved != (is_released and not is_confirmed)
        ):
            raise _error("action ownership state")
        confirmed += is_confirmed
        coincident += is_coincident
        releases += is_released
        unobserved += is_unobserved
        trace.extend(
            struct.pack(
                "<QQIii",
                token,
                call,
                coordinate,
                variable,
                literal,
            )
        )
        trace.extend(struct.pack("<ddB", upper_zero, upper_one, code))
        rows.append(dict(row))
    action_count = len(rows)
    expected_counts = {
        "action_count": action_count,
        "failure_first_count": failure_count,
        "certified_crossing_count": crossing_count,
        "level_bindings": level_bindings,
        "confirmed_actions": confirmed,
        "coincident_v6_pending_actions": coincident,
        "releases": releases,
        "unobserved_releases": unobserved,
    }
    if (
        any(report.get(name) != expected for name, expected in expected_counts.items())
        or report.get("action_trace_bytes") != action_count * ACTION_TRACE_RECORD_BYTES
        or report.get("action_trace_sha256") != hashlib.sha256(trace).hexdigest()
    ):
        raise _error("action aggregate ledger")
    return dict(report), tuple(rows), expected_counts


def _validate_ownership_linkage(
    value: object,
    *,
    actions: Sequence[Mapping[str, object]],
    counts: Mapping[str, int],
) -> Mapping[str, object]:
    try:
        replay = _v21._replay_ownership(value)
    except O1RelationalSearchError as exc:
        raise _error("decision ownership replay") from exc
    ownership = replay.ownership
    origin_counts = _mapping(ownership.get("origin_counts"), "ownership origins")
    bound = _mapping(origin_counts.get(TRANSPORT_ORIGIN), "bound origin")
    if (
        ownership.get("proposals") != counts["action_count"]
        or ownership.get("level_bound_interventions") != counts["level_bindings"]
        or ownership.get("confirmed_interventions") != counts["confirmed_actions"]
        or ownership.get("releases") != counts["releases"]
        or ownership.get("level_bound_unobserved_releases")
        != counts["unobserved_releases"]
        or bound.get("proposals") != counts["action_count"]
        or bound.get("level_bound") != counts["level_bindings"]
        or bound.get("confirmed") != counts["confirmed_actions"]
        or bound.get("releases") != counts["releases"]
        or ownership.get("live_tokens")
        != sum(not bool(action["released"]) for action in actions)
    ):
        raise _error("ownership aggregate linkage")
    proposed = {
        _positive(event.get("token"), "proposed ownership token"): event
        for event in replay.events
        if event.get("kind") == "PROPOSED"
    }
    for action in actions:
        event = proposed.get(_positive(action.get("token"), "action ownership token"))
        if (
            event is None
            or any(
                event.get(name) != action[action_name]
                for name, action_name in (
                    ("callback", "call"),
                    ("row", "coordinate_index"),
                    ("literal", "literal"),
                )
            )
            or event.get("origin") != TRANSPORT_ORIGIN
        ):
            raise _error("ownership action event linkage")
    return dict(ownership)


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    vault_caps: VaultCaps,
    field: CriticalityPotentialField,
    grouping: object,
    grouping_sha256: str,
    cnf_sha256: str,
    potential_sha256: str,
    threshold: float,
    requested_conflicts: int,
    seed: int,
    priority_seed_sha256: str,
    production_seal: bool,
    memory_limit_bytes: int | None = None,
    memory_samples: tuple[dict[str, int | float], ...] = (),
) -> JointScoreSieveV22Result:
    """Validate one native-v19 document and its unchanged v6 lifecycle."""

    root = _mapping(payload, "result")
    if set(root) != _TOP_LEVEL_FIELDS:
        raise _error("result fields")
    candidates = _candidate_order(field)
    if production_seal and candidates != PRODUCTION_CANDIDATES:
        raise _error("production candidate population including missing 241")
    if (
        root.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or root.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or root.get("operator_semantics") != OPERATOR_SEMANTICS
        or root.get("cnf_sha256") != cnf_sha256
        or root.get("potential_sha256") != potential_sha256
        or root.get("active_vault_sha256") != input_vault.sha256
        or root.get("seed") != seed
        or root.get("conflict_limit") != requested_conflicts
    ):
        raise _error("result identity")
    _same_f64(root.get("threshold"), threshold, "result threshold")
    priority_seed = _validate_seed_report(
        root.get("priority_seed"),
        seed_sha256=priority_seed_sha256,
        production_seal=production_seal,
    )
    priority_state, next_seed, state_counts = _validate_priority_state(
        root.get("priority_state"), candidates=candidates
    )
    priority_actions, action_rows, action_counts = _validate_actions(
        root.get("priority_actions"),
        threshold=threshold,
        candidates=candidates,
        probe_count=state_counts["probe_count"],
        parent_scans=state_counts["parent_scans"],
    )
    if (
        action_counts["action_count"] != state_counts["nonzero_returns"]
        or action_counts["action_count"] != state_counts["consumed_coordinate_count"]
    ):
        raise _error("action and one-shot state linkage")
    ownership = _validate_ownership_linkage(
        root.get("decision_ownership"), actions=action_rows, counts=action_counts
    )
    try:
        base = _v9._parse_native_payload(
            _base_v6_payload(root),
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,  # type: ignore[arg-type]
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
        raise _error("unchanged v6 base and vault lifecycle") from exc
    if (
        base.sieve.get("cb_decide_calls") != state_counts["callback_calls"]
        or base.sieve.get("cb_decide_nonzero") != 0
    ):
        raise _error("one unchanged-v6 call per priority callback")
    realized_actions = sum(
        bool(action["confirmed"])
        and (
            action["semantic"] == CERTIFIED_CROSSING_SEMANTIC
            or bool(action["coincident_v6_pending"])
        )
        for action in action_rows
    )
    for name in (
        "threshold_prunes",
        "trail_threshold_prunes",
        "external_clauses_queued",
    ):
        if _nonnegative(base.sieve.get(name), f"base {name}") < realized_actions:
            raise _error("certified/coincident v6 prune linkage")
    soft_stats = _v9.derive_vault_soft_conflict_ledger(
        base.stats, requested_conflicts=requested_conflicts
    )
    summary: dict[str, object] = {
        "schema": JOINT_SCORE_SIEVE_ADAPTER_SCHEMA,
        "status": base.status,
        "candidate_population": len(candidates),
        "missing_key_coordinate": 241 if production_seal else None,
        "parent_scans": state_counts["parent_scans"],
        "probe_count": state_counts["probe_count"],
        "child_bound_evaluations": state_counts["child_bound_evaluations"],
        "action_count": action_counts["action_count"],
        "failure_first_count": action_counts["failure_first_count"],
        "certified_crossing_count": action_counts["certified_crossing_count"],
        "coincident_v6_pending_nonclaims": action_counts[
            "coincident_v6_pending_actions"
        ],
        "threshold_prunes": base.threshold_prunes,
        "next_priority_seed_sha256": hashlib.sha256(next_seed).hexdigest(),
        "next_priority_seed_bytes": len(next_seed),
        "belief_orientation_authorized": False,
        "key_bits_emitted": 0,
    }
    return JointScoreSieveV22Result(
        status=base.status,
        conflict_limit=base.conflict_limit,
        threshold=base.threshold,
        key_model=base.key_model,
        stats=soft_stats,
        resources=base.resources,
        base_result=base,
        priority_seed=priority_seed,
        priority_state=priority_state,
        priority_actions=priority_actions,
        decision_ownership=ownership,
        next_priority_seed=next_seed,
        normalized_summary=summary,
        raw=dict(root),
    )


def _build_native(*, source: Path, output: Path, public_fixture: bool) -> None:
    source_resolved = source.resolve(strict=True)
    before = source_resolved.read_bytes()
    if public_fixture:
        include = Path("/opt/homebrew/opt/cadical/include").resolve(strict=True)
        library = Path("/opt/homebrew/opt/cadical/lib/libcadical.a").resolve(
            strict=True
        )
        if shutil.which("c++") is None:
            raise _error("C++ compiler")
        output.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "c++",
            "-std=c++17",
            "-O2",
            "-DNDEBUG",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DO1_CRYPTO_LAB_O1C82_PUBLIC_FIXTURE",
            f"-I{include}",
            str(source_resolved),
            str(library),
            "-o",
            str(output),
        ]
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=120
        )
        if completed.returncode or not output.is_file():
            raise JointScoreSieveV22Error(
                "joint-score-sieve-v22 native build failed: "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
    else:
        _v9.build_native_joint_score_sieve(source=source_resolved, output=output)
    if source_resolved.read_bytes() != before:
        raise _error("native source changed during build")


def run_joint_score_sieve(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    vault_path: str | Path,
    priority_seed_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    source_path: str | Path | None = None,
    public_fixture: bool = False,
) -> JointScoreSieveV22Result:
    """Build native-v19 if absent, execute once, and validate every boundary."""

    started = time.perf_counter()
    try:
        requested = _v9._requested_conflicts(conflict_limit)
        if (
            not isinstance(vault_caps, VaultCaps)
            or vault_caps != O1C66_VAULT_CAPS
            or isinstance(seed, bool)
            or not isinstance(seed, int)
            or seed != 0
            or isinstance(public_fixture, bool) is False
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0.0
            or (
                memory_limit_bytes is not None
                and (
                    isinstance(memory_limit_bytes, bool)
                    or not isinstance(memory_limit_bytes, int)
                    or memory_limit_bytes <= 0
                )
            )
        ):
            raise _error("run configuration")
        requested_threshold = _finite(threshold, "requested threshold")
        executable_path = Path(executable).resolve()
        source = (
            Path(source_path)
            if source_path is not None
            else lab_root() / NATIVE_SOURCE_RELATIVE
        )
        if not executable_path.exists():
            _build_native(
                source=source, output=executable_path, public_fixture=public_fixture
            )
        io_v1 = _v9._v8._v7._v1
        executable_file, executable_bytes, _ = io_v1._read_input(
            executable_path, "executable"
        )
        cnf_file, cnf_bytes, cnf_sha = io_v1._read_input(cnf_path, "CNF")
        potential_file, potential_bytes, potential_sha = io_v1._read_input(
            potential_path, "potential"
        )
        grouping_file, grouping_bytes, grouping_sha = io_v1._read_input(
            grouping_path, "grouping"
        )
        vault_file, vault_bytes = _v9._v8._read_bounded_vault_input(
            vault_path, caps=vault_caps
        )
        seed_file, priority_seed_bytes, priority_seed_sha = io_v1._read_input(
            priority_seed_path, "priority seed"
        )
        if (
            len(priority_seed_bytes) != BANK_BYTES
            or priority_seed_sha != EXPECTED_BANK_SHA256
        ):
            raise _error("priority seed production seal")
        parse_seed_bank(priority_seed_bytes, expected_sha256=EXPECTED_BANK_SHA256)
        field = io_v1._potential(potential_bytes)
        grouping = _v9.validate_joint_score_sieve_grouping(field, grouping_bytes)
        if grouping.potential_sha256 != potential_sha:
            raise _error("grouping potential identity")
        try:
            input_vault = parse_threshold_no_good_vault(
                vault_bytes,
                observed_variables=field.observed_variables,
                caps=vault_caps,
            )
            expected_identity = vault_identity_from_sources(
                cnf_sha256=cnf_sha,
                potential_sha256=potential_sha,
                grouping_sha256=grouping_sha,
                observed_variables=field.observed_variables,
                bound_rule=_v9.JOINT_SCORE_SIEVE_BOUND_RULE,
                threshold=requested_threshold,
            )
            validate_threshold_no_good_vault_identity(
                input_vault, expected=expected_identity
            )
            _v9._v8._certify_input_vault(
                input_vault,
                field=field,
                grouping=grouping,
                threshold=requested_threshold,
            )
        except ThresholdNoGoodVaultError as exc:
            raise _error("input vault") from exc
        if not public_fixture and (
            input_vault.sha256 != PRODUCTION_PAGE8_SHA256
            or len(vault_bytes) != PRODUCTION_PAGE8_BYTES
            or _candidate_order(field) != PRODUCTION_CANDIDATES
        ):
            raise _error("Page-8 production seal")
        command = [
            str(executable_file),
            "--cnf",
            str(cnf_file),
            "--potential",
            str(potential_file),
            "--grouping",
            str(grouping_file),
            "--vault-in",
            str(vault_file),
            "--priority-seed",
            str(seed_file),
            "--threshold",
            format(requested_threshold, ".17g"),
            "--conflict-limit",
            str(requested),
            "--seed",
            "0",
        ]
        execution = _v9._v8._v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
        completed = execution.completed
        for original, resolved, before, name in (
            (executable_path, executable_file, executable_bytes, "executable"),
            (cnf_path, cnf_file, cnf_bytes, "CNF"),
            (potential_path, potential_file, potential_bytes, "potential"),
            (grouping_path, grouping_file, grouping_bytes, "grouping"),
            (priority_seed_path, seed_file, priority_seed_bytes, "priority seed"),
        ):
            io_v1._verify_stable_input(original, resolved, before, field=name)
        _v9._v8._verify_stable_vault_input(
            vault_path, vault_file, vault_bytes, caps=vault_caps
        )
        if completed.returncode:
            failure = subprocess.CalledProcessError(
                completed.returncode,
                command,
                output=completed.stdout,
                stderr=completed.stderr,
            )
            _v9._attach_native_process_evidence(
                failure,
                command=command,
                completed=completed,
                memory_samples=execution.memory_samples,
            )
            raise JointScoreSieveV22Error(
                "joint-score-sieve-v22 execution failed: "
                + (completed.stderr.strip() or completed.stdout.strip())
            ) from failure
        try:
            payload = _v21.load_native_json(completed.stdout)
        except (json.JSONDecodeError, O1RelationalSearchError) as exc:
            raise _error("native JSON") from exc
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            vault_caps=vault_caps,
            field=field,
            grouping=grouping,
            grouping_sha256=grouping_sha,
            cnf_sha256=cnf_sha,
            potential_sha256=potential_sha,
            threshold=requested_threshold,
            requested_conflicts=requested,
            seed=0,
            priority_seed_sha256=priority_seed_sha,
            production_seal=not public_fixture,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=execution.memory_samples,
        )
        return replace(
            result,
            native_stdout=completed.stdout,
            native_stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest(),
            command=tuple(command),
        )
    except Exception as exc:
        elapsed = max(0.0, time.perf_counter() - started)
        telemetry = _v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v22"):
            message = f"joint-score-sieve-v22 adapter failed: {message}"
        raise _v9.JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


def build_native_joint_score_sieve(
    *,
    source: str | Path,
    output: str | Path,
    public_fixture: bool = False,
) -> Path:
    """Build native-v19 with its production seal unless explicitly a fixture."""

    destination = Path(output).resolve()
    _build_native(
        source=Path(source), output=destination, public_fixture=public_fixture
    )
    return destination


__all__ = [
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JointScoreSieveV22Error",
    "JointScoreSieveV22Result",
    "build_native_joint_score_sieve",
    "run_joint_score_sieve",
]
