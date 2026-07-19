"""Bounded online group-credit decisions for the frozen O1C-0048 pairs."""

from __future__ import annotations

import hashlib
import json
import math
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence, cast

from .criticality_potential import (
    CriticalityPotentialError,
    CriticalityPotentialField,
)
from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    build_native_guided_search,
)
from .pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    write_pair_envelope_decision_variables,
    write_pair_envelope_potential,
)


ONLINE_PAIR_CREDIT_RESULT_SCHEMA = "o1-256-cadical-online-pair-credit-search-result-v1"
ONLINE_PAIR_CREDIT_DECISION_RULE = "online_saturating_pair_group_credit"
ONLINE_PAIR_CREDIT_GROUPS = 63
ONLINE_PAIR_CREDIT_VARIABLES = 126
ONLINE_PAIR_CREDIT_STATE_ENCODING = (
    "i16le-credit,u16le-visits,u16le-conflict-hits,"
    "u16le-propagation-units,u16le-backtrack-hits"
)
ONLINE_PAIR_CREDIT_UPDATE_FORMULA = (
    "sat_i16(credit+4*assigned+min(dprop/64,31)-8*min(dconf,31)-12*backtrack)"
)
ONLINE_PAIR_CREDIT_SELECTION_FORMULA = (
    "cold:max-gap-then-group-order;"
    "online:max-gap-plus-credit-over-1024-then-gap-then-group-order"
)
ONLINE_PAIR_CREDIT_BYTES_PER_GROUP = 10
ONLINE_PAIR_CREDIT_STATE_BYTES = (
    ONLINE_PAIR_CREDIT_GROUPS * ONLINE_PAIR_CREDIT_BYTES_PER_GROUP
)
ONLINE_PAIR_CREDIT_MIN = -(1 << 15)
ONLINE_PAIR_CREDIT_MAX = (1 << 15) - 1
ONLINE_PAIR_COUNTER_MAX = (1 << 16) - 1

_TOP_LEVEL_FIELDS = {
    "schema",
    "cadical_version",
    "variables",
    "conflict_limit",
    "seed",
    "status",
    "key_model_hex",
    "cnf_sha256",
    "stats",
    "online",
    "resources",
}
_STATS_FIELDS = {"conflicts", "decisions", "propagations"}
_RESOURCE_FIELDS = {"wall_microseconds", "cpu_microseconds", "peak_rss_bytes"}
_ONLINE_FIELDS = {
    "factor_count",
    "pair_count",
    "group_width",
    "decision_rule",
    "cold_decision_rule",
    "decision_scope",
    "source_sha256",
    "decision_variables_sha256",
    "offset",
    "observed_variables",
    "eligible_decision_variables",
    "update_formula",
    "selection_formula",
    "external_implications",
    "hard_clauses_added",
    "queue",
    "selection",
    "tickets",
    "solver_counter_deltas",
    "state",
}
_QUEUE_FIELDS = {
    "requested_decisions",
    "repeated_decisions",
    "queued_decisions",
    "same_sign_queue_skips",
    "opposite_sign_queue_invalidations",
    "assignment_notifications",
    "backtracks",
    "maximum_assigned_variables",
    "maximum_decision_level",
}
_SELECTION_FIELDS = {
    "cold_group_selections",
    "credit_modulated_group_selections",
    "zero_gap_fallbacks",
    "envelope_evaluations",
    "first_group_index",
    "first_pattern_mask",
    "maximum_score_gap",
    "maximum_modulated_priority",
    "trace_sha256",
}
_TICKET_FIELDS = {
    "opened",
    "closed",
    "closed_on_advance",
    "closed_on_backtrack",
    "closed_on_invalidation",
    "closed_on_solve_end",
    "assignment_hits",
    "maximum_open",
    "current_open",
}
_DELTA_FIELDS = {"conflicts", "decisions", "propagations"}
_STATE_FIELDS = {
    "encoding",
    "bytes_per_group",
    "bounded_state_bytes",
    "sha256",
    "credit_min",
    "credit_max",
    "counter_max",
    "saturated_credit_updates",
    "saturated_counter_updates",
    "groups",
}
_GROUP_FIELDS = {
    "index",
    "first_variable",
    "second_variable",
    "credit",
    "visits",
    "conflict_hits",
    "propagation_units",
    "backtrack_hits",
}


@dataclass(frozen=True)
class OnlinePairCreditSearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    online: Mapping[str, object]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]

    @property
    def state_sha256(self) -> str:
        state = _mapping(self.online["state"], "online.state")
        return str(state["sha256"])


def build_native_online_pair_credit_search(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    resolved, source_bytes, _ = _read_input(source, "native source")
    build_error: Exception | None = None
    result: NativeGuidedSearchBuild | None = None
    try:
        result = build_native_guided_search(source=resolved, output=output)
    except Exception as exc:
        build_error = exc
    _verify_stable_input(source, resolved, source_bytes, field="native source")
    if build_error is not None:
        raise build_error
    if result is None:
        raise O1RelationalSearchError("online pair-credit native build failed")
    return result


def write_online_pair_credit_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    return write_pair_envelope_potential(path, field)


def write_online_pair_credit_decision_variables(
    path: str | Path, variables: Iterable[int]
) -> str:
    return write_pair_envelope_decision_variables(path, variables)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1RelationalSearchError(f"online pair-credit {field} differs")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonnegative_integer_group(
    value: object, *, field: str, names: set[str]
) -> dict[str, int]:
    payload = _mapping(value, field)
    if set(payload) != names:
        raise O1RelationalSearchError(f"online pair-credit {field} fields differ")
    result: dict[str, int] = {}
    for name, raw in payload.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise O1RelationalSearchError(f"online pair-credit {field}.{name} differs")
        result[str(name)] = raw
    return result


def _read_input(path: str | Path, field: str) -> tuple[Path, bytes, str]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"online pair-credit {field} input differs"
        ) from exc
    if not payload:
        raise O1RelationalSearchError(f"online pair-credit {field} input differs")
    return resolved, payload, hashlib.sha256(payload).hexdigest()


def _decision_values(payload: bytes) -> tuple[int, ...]:
    try:
        tokens = payload.decode("ascii").split()
        values = tuple(int(token) for token in tokens)
    except (UnicodeError, ValueError) as exc:
        raise O1RelationalSearchError(
            "online pair-credit decision-variable input differs"
        ) from exc
    if (
        len(values) != ONLINE_PAIR_CREDIT_VARIABLES
        or len(set(values)) != len(values)
        or any(not 1 <= value <= 256 for value in values)
    ):
        raise O1RelationalSearchError(
            "online pair-credit requires exactly 63 unique ordered key pairs"
        )
    return values


def _potential_field(payload: bytes) -> CriticalityPotentialField:
    try:
        return CriticalityPotentialField.from_bytes(payload)
    except CriticalityPotentialError as exc:
        raise O1RelationalSearchError(
            "online pair-credit potential input differs"
        ) from exc


def _verify_stable_input(
    original_path: str | Path, resolved_path: Path, before: bytes, *, field: str
) -> None:
    try:
        after_path = Path(original_path).resolve(strict=True)
        after = after_path.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"online pair-credit {field} changed during execution"
        ) from exc
    if after_path != resolved_path or after != before:
        raise O1RelationalSearchError(
            f"online pair-credit {field} changed during execution"
        )


def _sat_signed(value: int) -> int:
    return min(ONLINE_PAIR_CREDIT_MAX, max(ONLINE_PAIR_CREDIT_MIN, value))


def _sat_counter(value: int) -> int:
    return min(ONLINE_PAIR_COUNTER_MAX, max(0, value))


def bounded_group_credit_update(
    state: tuple[int, int, int, int, int],
    *,
    assigned: int,
    delta_conflicts: int,
    delta_propagations: int,
    backtracked: bool,
) -> tuple[int, int, int, int, int]:
    """Reference one-ticket update; it is not used in the solver hot loop."""

    if (
        len(state) != 5
        or not ONLINE_PAIR_CREDIT_MIN <= state[0] <= ONLINE_PAIR_CREDIT_MAX
        or any(not 0 <= value <= ONLINE_PAIR_COUNTER_MAX for value in state[1:])
        or isinstance(assigned, bool)
        or not isinstance(assigned, int)
        or not 0 <= assigned <= 2
        or isinstance(delta_conflicts, bool)
        or not isinstance(delta_conflicts, int)
        or delta_conflicts < 0
        or isinstance(delta_propagations, bool)
        or not isinstance(delta_propagations, int)
        or delta_propagations < 0
        or not isinstance(backtracked, bool)
    ):
        raise O1RelationalSearchError("online pair-credit bounded update differs")
    credit, visits, conflicts, propagations, backtracks = state
    delta = (
        4 * assigned
        + min(delta_propagations // 64, 31)
        - 8 * min(delta_conflicts, 31)
        - 12 * int(backtracked)
    )
    return (
        _sat_signed(credit + delta),
        _sat_counter(visits + 1),
        _sat_counter(conflicts + delta_conflicts),
        _sat_counter(propagations + delta_propagations),
        _sat_counter(backtracks + int(backtracked)),
    )


def _state_bytes(
    groups: Sequence[Mapping[str, object]], decisions: tuple[int, ...]
) -> bytes:
    if len(groups) != ONLINE_PAIR_CREDIT_GROUPS:
        raise O1RelationalSearchError("online pair-credit group-state count differs")
    output = bytearray()
    for index, group in enumerate(groups):
        if set(group) != _GROUP_FIELDS:
            raise O1RelationalSearchError(
                f"online pair-credit state group {index} fields differ"
            )
        expected_pair = decisions[2 * index : 2 * index + 2]
        raw_values = tuple(
            group[name]
            for name in (
                "index",
                "first_variable",
                "second_variable",
                "credit",
                "visits",
                "conflict_hits",
                "propagation_units",
                "backtrack_hits",
            )
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in raw_values
        ):
            raise O1RelationalSearchError(
                f"online pair-credit state group {index} value differs"
            )
        values = tuple(cast(int, value) for value in raw_values)
        (
            reported_index,
            first,
            second,
            credit,
            visits,
            conflicts,
            propagations,
            backtracks,
        ) = values
        if (
            reported_index != index
            or (first, second) != expected_pair
            or not ONLINE_PAIR_CREDIT_MIN <= credit <= ONLINE_PAIR_CREDIT_MAX
            or any(
                not 0 <= counter <= ONLINE_PAIR_COUNTER_MAX
                for counter in (visits, conflicts, propagations, backtracks)
            )
        ):
            raise O1RelationalSearchError(
                f"online pair-credit state group {index} contract differs"
            )
        output.extend(
            struct.pack("<hHHHH", credit, visits, conflicts, propagations, backtracks)
        )
    return bytes(output)


def run_online_pair_credit_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    decision_variables_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> OnlinePairCreditSearchResult:
    if (
        isinstance(conflict_limit, bool)
        or not isinstance(conflict_limit, int)
        or not 1 <= conflict_limit <= 1_000_000_000
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0.0
    ):
        raise O1RelationalSearchError(
            "online pair-credit search limit, seed, or timeout differs"
        )
    cnf, cnf_bytes, cnf_sha256 = _read_input(cnf_path, "CNF")
    potential, potential_bytes, _ = _read_input(potential_path, "potential")
    decisions_path, decision_bytes, decision_sha256 = _read_input(
        decision_variables_path, "decision-variable"
    )
    field = _potential_field(potential_bytes)
    decisions = _decision_values(decision_bytes)
    if not set(decisions).issubset(field.observed_variables):
        raise O1RelationalSearchError(
            "online pair-credit decision variables are absent from potential"
        )
    command = [
        str(Path(executable).resolve(strict=True)),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential),
        "--decision-variables",
        str(decisions_path),
        "--conflict-limit",
        str(conflict_limit),
        "--seed",
        str(seed),
    ]
    execution_error: OSError | subprocess.TimeoutExpired | None = None
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        execution_error = exc
        completed = None
    _verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
    _verify_stable_input(potential_path, potential, potential_bytes, field="potential")
    _verify_stable_input(
        decision_variables_path,
        decisions_path,
        decision_bytes,
        field="decision-variable",
    )
    if execution_error is not None:
        raise O1RelationalSearchError(
            "online pair-credit search execution failed"
        ) from execution_error
    if completed is None:
        raise O1RelationalSearchError("online pair-credit search execution failed")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(
            f"online pair-credit search execution failed: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError(
            "online pair-credit search JSON is invalid"
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("online pair-credit result fields differ")
    variables = payload["variables"]
    reported_limit = payload["conflict_limit"]
    reported_seed = payload["seed"]
    status = payload["status"]
    if (
        payload["schema"] != ONLINE_PAIR_CREDIT_RESULT_SCHEMA
        or payload["cadical_version"] != "3.0.0"
        or isinstance(variables, bool)
        or not isinstance(variables, int)
        or variables < 256
        or isinstance(reported_limit, bool)
        or not isinstance(reported_limit, int)
        or reported_limit != conflict_limit
        or isinstance(reported_seed, bool)
        or not isinstance(reported_seed, int)
        or reported_seed != seed
        or isinstance(status, bool)
        or status not in (0, 10, 20)
        or payload["cnf_sha256"] != cnf_sha256
    ):
        raise O1RelationalSearchError("online pair-credit result contract differs")
    model_hex = payload["key_model_hex"]
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT online pair-credit result lacks key")
        try:
            key_model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError(
                "online pair-credit key encoding differs"
            ) from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT online pair-credit result contains key")
    else:
        key_model = None

    stats = _nonnegative_integer_group(
        payload["stats"], field="stats", names=_STATS_FIELDS
    )
    resources = _nonnegative_integer_group(
        payload["resources"], field="resources", names=_RESOURCE_FIELDS
    )
    online = _mapping(payload["online"], "online")
    if set(online) != _ONLINE_FIELDS:
        raise O1RelationalSearchError("online pair-credit online fields differ")
    external_implications = online["external_implications"]
    hard_clauses_added = online["hard_clauses_added"]
    identity_integers = (
        (online["factor_count"], len(field.factors)),
        (online["pair_count"], ONLINE_PAIR_CREDIT_GROUPS),
        (online["group_width"], 2),
        (online["observed_variables"], len(field.observed_variables)),
        (online["eligible_decision_variables"], len(decisions)),
        (external_implications, 0),
        (hard_clauses_added, 0),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value != expected
        for value, expected in identity_integers
    ):
        raise O1RelationalSearchError("online pair-credit identity differs")
    reported_offset = online["offset"]
    if (
        online["decision_rule"] != ONLINE_PAIR_CREDIT_DECISION_RULE
        or online["cold_decision_rule"] != PAIR_ENVELOPE_DECISION_RULE
        or online["decision_scope"] != PAIR_ENVELOPE_DECISION_SCOPE
        or online["source_sha256"] != field.source_sha256
        or online["decision_variables_sha256"] != decision_sha256
        or isinstance(reported_offset, bool)
        or not isinstance(reported_offset, (int, float))
        or not math.isfinite(reported_offset)
        or reported_offset != field.offset
        or online["update_formula"] != ONLINE_PAIR_CREDIT_UPDATE_FORMULA
        or online["selection_formula"] != ONLINE_PAIR_CREDIT_SELECTION_FORMULA
    ):
        raise O1RelationalSearchError("online pair-credit identity differs")

    queue = _nonnegative_integer_group(
        online["queue"], field="online.queue", names=_QUEUE_FIELDS
    )
    tickets = _nonnegative_integer_group(
        online["tickets"], field="online.tickets", names=_TICKET_FIELDS
    )
    deltas = _nonnegative_integer_group(
        online["solver_counter_deltas"],
        field="online.solver_counter_deltas",
        names=_DELTA_FIELDS,
    )
    selection = _mapping(online["selection"], "online.selection")
    if set(selection) != _SELECTION_FIELDS:
        raise O1RelationalSearchError("online pair-credit selection fields differ")
    for name in (
        "cold_group_selections",
        "credit_modulated_group_selections",
        "zero_gap_fallbacks",
        "envelope_evaluations",
    ):
        value = selection[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"online pair-credit selection.{name} differs"
            )
    cold_selections = cast(int, selection["cold_group_selections"])
    modulated_selections = cast(int, selection["credit_modulated_group_selections"])
    for name in ("maximum_score_gap", "maximum_modulated_priority"):
        value = selection[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise O1RelationalSearchError(
                f"online pair-credit selection.{name} differs"
            )
    maximum_gap = float(cast(int | float, selection["maximum_score_gap"]))
    maximum_modulated_priority = float(
        cast(int | float, selection["maximum_modulated_priority"])
    )
    priority_upper_bound = maximum_gap + ONLINE_PAIR_CREDIT_MAX / 1024.0
    priority_tolerance = 1e-12 * max(1.0, abs(priority_upper_bound))
    if (
        maximum_gap < 0
        or (tickets["opened"] == 0 and maximum_gap != 0)
        or (tickets["opened"] > 0 and maximum_gap <= 0)
        or (modulated_selections == 0 and maximum_modulated_priority != 0)
        or (
            modulated_selections > 0
            and (
                maximum_modulated_priority < -32.0
                or maximum_modulated_priority
                > priority_upper_bound + priority_tolerance
            )
        )
    ):
        raise O1RelationalSearchError(
            "online pair-credit selection metric ledger differs"
        )
    if not _is_sha256(selection["trace_sha256"]):
        raise O1RelationalSearchError("online pair-credit selection trace differs")
    first_group = selection["first_group_index"]
    first_mask = selection["first_pattern_mask"]
    if tickets["opened"]:
        if (
            isinstance(first_group, bool)
            or not isinstance(first_group, int)
            or not 0 <= first_group < ONLINE_PAIR_CREDIT_GROUPS
            or isinstance(first_mask, bool)
            or not isinstance(first_mask, int)
            or not 0 <= first_mask < 4
        ):
            raise O1RelationalSearchError(
                "online pair-credit first cold selection differs"
            )
    elif first_group is not None or first_mask is not None:
        raise O1RelationalSearchError(
            "online pair-credit empty selection contains first action"
        )
    if (
        tickets["opened"] != tickets["closed"]
        or tickets["closed"]
        != tickets["closed_on_advance"]
        + tickets["closed_on_backtrack"]
        + tickets["closed_on_invalidation"]
        + tickets["closed_on_solve_end"]
        or tickets["maximum_open"] != int(tickets["opened"] > 0)
        or tickets["current_open"] != 0
        or tickets["assignment_hits"] > 2 * tickets["closed"]
        or cold_selections != min(tickets["opened"], 1)
        or modulated_selections != tickets["opened"] - cold_selections
        or queue["requested_decisions"] > queue["queued_decisions"]
    ):
        raise O1RelationalSearchError("online pair-credit telemetry ledger differs")

    state = _mapping(online["state"], "online.state")
    if set(state) != _STATE_FIELDS:
        raise O1RelationalSearchError("online pair-credit state fields differ")
    groups_raw = state["groups"]
    if not isinstance(groups_raw, list) or any(
        not isinstance(group, Mapping) for group in groups_raw
    ):
        raise O1RelationalSearchError("online pair-credit group states differ")
    groups = [dict(cast(Mapping[str, object], group)) for group in groups_raw]
    encoded = _state_bytes(groups, decisions)
    if (
        state["encoding"] != ONLINE_PAIR_CREDIT_STATE_ENCODING
        or state["bytes_per_group"] != ONLINE_PAIR_CREDIT_BYTES_PER_GROUP
        or state["bounded_state_bytes"] != ONLINE_PAIR_CREDIT_STATE_BYTES
        or state["credit_min"] != ONLINE_PAIR_CREDIT_MIN
        or state["credit_max"] != ONLINE_PAIR_CREDIT_MAX
        or state["counter_max"] != ONLINE_PAIR_COUNTER_MAX
        or not _is_sha256(state["sha256"])
        or state["sha256"] != hashlib.sha256(encoded).hexdigest()
    ):
        raise O1RelationalSearchError("online pair-credit bounded state differs")
    for name in ("saturated_credit_updates", "saturated_counter_updates"):
        value = state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"online pair-credit state.{name} differs")
    if sum(cast(int, group["visits"]) for group in groups) > tickets["closed"]:
        raise O1RelationalSearchError("online pair-credit state visit ledger differs")
    if any(delta > stats[name] for name, delta in deltas.items()):
        raise O1RelationalSearchError(
            "online pair-credit solver counter delta ledger differs"
        )

    normalized_online = dict(online)
    normalized_online["queue"] = queue
    normalized_online["tickets"] = tickets
    normalized_online["solver_counter_deltas"] = deltas
    normalized_online["selection"] = dict(selection)
    normalized_state = dict(state)
    normalized_state["groups"] = groups
    normalized_online["state"] = normalized_state
    return OnlinePairCreditSearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=key_model,
        stats=stats,
        online=normalized_online,
        resources=resources,
        raw=dict(payload),
    )


# Compatibility names mirror the frozen pair-envelope adapter.
write_criticality_potential = write_online_pair_credit_potential
write_decision_variables = write_online_pair_credit_decision_variables


__all__ = [
    "ONLINE_PAIR_COUNTER_MAX",
    "ONLINE_PAIR_CREDIT_BYTES_PER_GROUP",
    "ONLINE_PAIR_CREDIT_DECISION_RULE",
    "ONLINE_PAIR_CREDIT_GROUPS",
    "ONLINE_PAIR_CREDIT_MAX",
    "ONLINE_PAIR_CREDIT_MIN",
    "ONLINE_PAIR_CREDIT_RESULT_SCHEMA",
    "ONLINE_PAIR_CREDIT_SELECTION_FORMULA",
    "ONLINE_PAIR_CREDIT_STATE_BYTES",
    "ONLINE_PAIR_CREDIT_STATE_ENCODING",
    "ONLINE_PAIR_CREDIT_UPDATE_FORMULA",
    "OnlinePairCreditSearchResult",
    "bounded_group_credit_update",
    "build_native_online_pair_credit_search",
    "run_online_pair_credit_search",
    "write_criticality_potential",
    "write_decision_variables",
    "write_online_pair_credit_decision_variables",
    "write_online_pair_credit_potential",
]
