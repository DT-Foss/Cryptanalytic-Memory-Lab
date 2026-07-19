"""Bounded delayed group-credit decisions for the frozen O1C-0048 pairs."""

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


DELAYED_PAIR_CREDIT_RESULT_SCHEMA = (
    "o1-256-cadical-delayed-pair-credit-search-result-v1"
)
DELAYED_PAIR_CREDIT_DECISION_RULE = "delayed_trail_owner_pair_group_credit"
DELAYED_PAIR_CREDIT_GROUPS = 63
DELAYED_PAIR_CREDIT_VARIABLES = 126
DELAYED_PAIR_CREDIT_GROUP_STATE_ENCODING = (
    "i16le-credit,u16le-visits,u16le-conflict-hits,"
    "u16le-propagation-units,u16le-backtrack-hits"
)
DELAYED_PAIR_CREDIT_OWNER_STATE_ENCODING = (
    "u32le-first-owner-level,u32le-second-owner-level"
)
DELAYED_PAIR_CREDIT_STATE_ENCODING = (
    f"group-block:{DELAYED_PAIR_CREDIT_GROUP_STATE_ENCODING};"
    f"owner-block:{DELAYED_PAIR_CREDIT_OWNER_STATE_ENCODING}"
)
DELAYED_PAIR_CREDIT_COUNTER_SEMANTICS = (
    "visits=closed-action-tickets;"
    "conflict-hits=conflict-bearing-owner-undos;"
    "propagation-units=reserved-zero;backtrack-hits=all-owner-undos"
)
DELAYED_PAIR_CREDIT_UPDATE_FORMULA = (
    "on-backtrack:c=I(conflicts>previous-backtrack-conflicts);"
    "for-owner-level>new-level:w=32>>min(current-level-owner-level,4);"
    "credit=sat_i16(credit-(1+c)*sum(w));clear-undone-owners"
)
DELAYED_PAIR_CREDIT_SELECTION_FORMULA = (
    "cold:max-gap-then-group-order;"
    "delayed:max-gap-plus-credit-over-1024-then-gap-then-group-order"
)
DELAYED_PAIR_CREDIT_GROUP_BYTES_PER_GROUP = 10
DELAYED_PAIR_CREDIT_OWNER_BYTES_PER_GROUP = 8
DELAYED_PAIR_CREDIT_BYTES_PER_GROUP = 18
DELAYED_PAIR_CREDIT_GROUP_STATE_BYTES = 630
DELAYED_PAIR_CREDIT_OWNER_STATE_BYTES = 504
DELAYED_PAIR_CREDIT_STATE_BYTES = 1134
DELAYED_PAIR_CREDIT_MIN = -(1 << 15)
DELAYED_PAIR_CREDIT_MAX = (1 << 15) - 1
DELAYED_PAIR_COUNTER_MAX = (1 << 16) - 1

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
    "delayed",
    "resources",
}
_STATS_FIELDS = {"conflicts", "decisions", "propagations"}
_RESOURCE_FIELDS = {"wall_microseconds", "cpu_microseconds", "peak_rss_bytes"}
_DELAYED_FIELDS = {
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
    "pending",
    "backtrack_credit",
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
_PENDING_FIELDS = {
    "marked",
    "bound",
    "first_owner_bindings",
    "second_owner_bindings",
    "owner_assignment_hits",
    "maximum_open",
    "current_open",
}
_BACKTRACK_CREDIT_FIELDS = {
    "callbacks",
    "conflict_callbacks",
    "nonconflict_callbacks",
    "eligible_undo_groups",
    "eligible_undo_members",
    "conflict_undo_members",
    "nonconflict_undo_members",
    "weighted_undo_units",
    "conflict_weighted_undo_units",
    "nonconflict_weighted_undo_units",
    "conflict_penalty_units",
    "nonconflict_penalty_units",
    "credit_updates",
    "assignment_credit_units",
    "propagation_credit_units",
}
_DELTA_FIELDS = {"conflicts", "decisions", "propagations"}
_STATE_FIELDS = {
    "encoding",
    "group_encoding",
    "owner_encoding",
    "bytes_per_group",
    "group_bytes_per_group",
    "owner_bytes_per_group",
    "bounded_group_state_bytes",
    "bounded_owner_state_bytes",
    "bounded_state_bytes",
    "sha256",
    "group_sha256",
    "owner_sha256",
    "credit_min",
    "credit_max",
    "counter_max",
    "owner_level_max",
    "counter_semantics",
    "live_owners",
    "maximum_live_owners",
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
    "first_owner_level",
    "second_owner_level",
}


@dataclass(frozen=True)
class DelayedPairCreditSearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    delayed: Mapping[str, object]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]

    @property
    def state_sha256(self) -> str:
        state = _mapping(self.delayed["state"], "delayed.state")
        return str(state["sha256"])

    @property
    def owner_state_sha256(self) -> str:
        state = _mapping(self.delayed["state"], "delayed.state")
        return str(state["owner_sha256"])


def build_native_delayed_pair_credit_search(
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
        raise O1RelationalSearchError("delayed pair-credit native build failed")
    return result


def write_delayed_pair_credit_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    return write_pair_envelope_potential(path, field)


def write_delayed_pair_credit_decision_variables(
    path: str | Path, variables: Iterable[int]
) -> str:
    return write_pair_envelope_decision_variables(path, variables)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1RelationalSearchError(f"delayed pair-credit {field} differs")
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
        raise O1RelationalSearchError(f"delayed pair-credit {field} fields differ")
    result: dict[str, int] = {}
    for name, raw in payload.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise O1RelationalSearchError(f"delayed pair-credit {field}.{name} differs")
        result[str(name)] = raw
    return result


def _read_input(path: str | Path, field: str) -> tuple[Path, bytes, str]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"delayed pair-credit {field} input differs"
        ) from exc
    if not payload:
        raise O1RelationalSearchError(f"delayed pair-credit {field} input differs")
    return resolved, payload, hashlib.sha256(payload).hexdigest()


def _decision_values(payload: bytes) -> tuple[int, ...]:
    try:
        tokens = payload.decode("ascii").split()
        values = tuple(int(token) for token in tokens)
    except (UnicodeError, ValueError) as exc:
        raise O1RelationalSearchError(
            "delayed pair-credit decision-variable input differs"
        ) from exc
    if (
        len(values) != DELAYED_PAIR_CREDIT_VARIABLES
        or len(set(values)) != len(values)
        or any(not 1 <= value <= 256 for value in values)
    ):
        raise O1RelationalSearchError(
            "delayed pair-credit requires exactly 63 unique ordered key pairs"
        )
    return values


def _potential_field(payload: bytes) -> CriticalityPotentialField:
    try:
        return CriticalityPotentialField.from_bytes(payload)
    except CriticalityPotentialError as exc:
        raise O1RelationalSearchError(
            "delayed pair-credit potential input differs"
        ) from exc


def _verify_stable_input(
    original_path: str | Path, resolved_path: Path, before: bytes, *, field: str
) -> None:
    try:
        after_path = Path(original_path).resolve(strict=True)
        after = after_path.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"delayed pair-credit {field} changed during execution"
        ) from exc
    if after_path != resolved_path or after != before:
        raise O1RelationalSearchError(
            f"delayed pair-credit {field} changed during execution"
        )


def _sat_signed(value: int) -> int:
    return min(DELAYED_PAIR_CREDIT_MAX, max(DELAYED_PAIR_CREDIT_MIN, value))


def delayed_owner_weight(*, current_level: int, owner_level: int) -> int:
    """Reference age-decay weight; it is not used in the solver hot loop."""

    if (
        isinstance(current_level, bool)
        or not isinstance(current_level, int)
        or current_level < 1
        or isinstance(owner_level, bool)
        or not isinstance(owner_level, int)
        or not 1 <= owner_level <= min(current_level, (1 << 32) - 1)
    ):
        raise O1RelationalSearchError("delayed pair-credit owner weight differs")
    return 32 >> min(current_level - owner_level, 4)


def delayed_group_credit_update(
    credit: int,
    owner_levels: tuple[int, int],
    *,
    current_level: int,
    new_level: int,
    conflict_since_previous_backtrack: bool,
) -> tuple[int, tuple[int, int], int, int]:
    """Reference delayed owner-undo update: credit, owners, count, penalty."""

    if (
        isinstance(credit, bool)
        or not isinstance(credit, int)
        or not DELAYED_PAIR_CREDIT_MIN <= credit <= DELAYED_PAIR_CREDIT_MAX
        or not isinstance(owner_levels, tuple)
        or len(owner_levels) != 2
        or any(
            isinstance(level, bool)
            or not isinstance(level, int)
            or not 0 <= level <= (1 << 32) - 1
            for level in owner_levels
        )
        or isinstance(current_level, bool)
        or not isinstance(current_level, int)
        or current_level < 0
        or isinstance(new_level, bool)
        or not isinstance(new_level, int)
        or not 0 <= new_level <= current_level
        or any(level > current_level for level in owner_levels)
        or not isinstance(conflict_since_previous_backtrack, bool)
    ):
        raise O1RelationalSearchError("delayed pair-credit bounded update differs")
    undone = tuple(level for level in owner_levels if level > new_level)
    weight = sum(
        delayed_owner_weight(current_level=current_level, owner_level=level)
        for level in undone
    )
    penalty = (1 + int(conflict_since_previous_backtrack)) * weight
    remaining = tuple(level if level <= new_level else 0 for level in owner_levels)
    return (
        _sat_signed(credit - penalty),
        cast(tuple[int, int], remaining),
        len(undone),
        penalty,
    )


def _state_blocks(
    groups: Sequence[Mapping[str, object]], decisions: tuple[int, ...]
) -> tuple[bytes, bytes]:
    if len(groups) != DELAYED_PAIR_CREDIT_GROUPS:
        raise O1RelationalSearchError("delayed pair-credit group-state count differs")
    group_output = bytearray()
    owner_output = bytearray()
    for index, group in enumerate(groups):
        if set(group) != _GROUP_FIELDS:
            raise O1RelationalSearchError(
                f"delayed pair-credit state group {index} fields differ"
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
                "first_owner_level",
                "second_owner_level",
            )
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in raw_values
        ):
            raise O1RelationalSearchError(
                f"delayed pair-credit state group {index} value differs"
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
            first_owner_level,
            second_owner_level,
        ) = values
        if (
            reported_index != index
            or (first, second) != expected_pair
            or not DELAYED_PAIR_CREDIT_MIN <= credit <= DELAYED_PAIR_CREDIT_MAX
            or any(
                not 0 <= counter <= DELAYED_PAIR_COUNTER_MAX
                for counter in (visits, conflicts, propagations, backtracks)
            )
            or not 0 <= first_owner_level <= (1 << 32) - 1
            or not 0 <= second_owner_level <= (1 << 32) - 1
        ):
            raise O1RelationalSearchError(
                f"delayed pair-credit state group {index} contract differs"
            )
        group_output.extend(
            struct.pack("<hHHHH", credit, visits, conflicts, propagations, backtracks)
        )
        owner_output.extend(struct.pack("<II", first_owner_level, second_owner_level))
    return bytes(group_output), bytes(owner_output)


def run_delayed_pair_credit_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    decision_variables_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> DelayedPairCreditSearchResult:
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
            "delayed pair-credit search limit, seed, or timeout differs"
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
            "delayed pair-credit decision variables are absent from potential"
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
            "delayed pair-credit search execution failed"
        ) from execution_error
    if completed is None:
        raise O1RelationalSearchError("delayed pair-credit search execution failed")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(
            f"delayed pair-credit search execution failed: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError(
            "delayed pair-credit search JSON is invalid"
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("delayed pair-credit result fields differ")
    variables = payload["variables"]
    reported_limit = payload["conflict_limit"]
    reported_seed = payload["seed"]
    status = payload["status"]
    if (
        payload["schema"] != DELAYED_PAIR_CREDIT_RESULT_SCHEMA
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
        raise O1RelationalSearchError("delayed pair-credit result contract differs")
    model_hex = payload["key_model_hex"]
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT delayed pair-credit result lacks key")
        try:
            key_model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError(
                "delayed pair-credit key encoding differs"
            ) from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT delayed pair-credit result contains key")
    else:
        key_model = None

    stats = _nonnegative_integer_group(
        payload["stats"], field="stats", names=_STATS_FIELDS
    )
    resources = _nonnegative_integer_group(
        payload["resources"], field="resources", names=_RESOURCE_FIELDS
    )
    delayed = _mapping(payload["delayed"], "delayed")
    if set(delayed) != _DELAYED_FIELDS:
        raise O1RelationalSearchError("delayed pair-credit delayed fields differ")
    external_implications = delayed["external_implications"]
    hard_clauses_added = delayed["hard_clauses_added"]
    identity_integers = (
        (delayed["factor_count"], len(field.factors)),
        (delayed["pair_count"], DELAYED_PAIR_CREDIT_GROUPS),
        (delayed["group_width"], 2),
        (delayed["observed_variables"], len(field.observed_variables)),
        (delayed["eligible_decision_variables"], len(decisions)),
        (external_implications, 0),
        (hard_clauses_added, 0),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value != expected
        for value, expected in identity_integers
    ):
        raise O1RelationalSearchError("delayed pair-credit identity differs")
    reported_offset = delayed["offset"]
    if (
        delayed["decision_rule"] != DELAYED_PAIR_CREDIT_DECISION_RULE
        or delayed["cold_decision_rule"] != PAIR_ENVELOPE_DECISION_RULE
        or delayed["decision_scope"] != PAIR_ENVELOPE_DECISION_SCOPE
        or delayed["source_sha256"] != field.source_sha256
        or delayed["decision_variables_sha256"] != decision_sha256
        or isinstance(reported_offset, bool)
        or not isinstance(reported_offset, (int, float))
        or not math.isfinite(reported_offset)
        or reported_offset != field.offset
        or delayed["update_formula"] != DELAYED_PAIR_CREDIT_UPDATE_FORMULA
        or delayed["selection_formula"] != DELAYED_PAIR_CREDIT_SELECTION_FORMULA
    ):
        raise O1RelationalSearchError("delayed pair-credit identity differs")

    queue = _nonnegative_integer_group(
        delayed["queue"], field="delayed.queue", names=_QUEUE_FIELDS
    )
    tickets = _nonnegative_integer_group(
        delayed["tickets"], field="delayed.tickets", names=_TICKET_FIELDS
    )
    pending = _nonnegative_integer_group(
        delayed["pending"], field="delayed.pending", names=_PENDING_FIELDS
    )
    backtrack_credit = _nonnegative_integer_group(
        delayed["backtrack_credit"],
        field="delayed.backtrack_credit",
        names=_BACKTRACK_CREDIT_FIELDS,
    )
    deltas = _nonnegative_integer_group(
        delayed["solver_counter_deltas"],
        field="delayed.solver_counter_deltas",
        names=_DELTA_FIELDS,
    )
    selection = _mapping(delayed["selection"], "delayed.selection")
    if set(selection) != _SELECTION_FIELDS:
        raise O1RelationalSearchError("delayed pair-credit selection fields differ")
    for name in (
        "cold_group_selections",
        "credit_modulated_group_selections",
        "zero_gap_fallbacks",
        "envelope_evaluations",
    ):
        value = selection[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                f"delayed pair-credit selection.{name} differs"
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
                f"delayed pair-credit selection.{name} differs"
            )
    maximum_gap = float(cast(int | float, selection["maximum_score_gap"]))
    maximum_modulated_priority = float(
        cast(int | float, selection["maximum_modulated_priority"])
    )
    priority_upper_bound = maximum_gap
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
            "delayed pair-credit selection metric ledger differs"
        )
    if not _is_sha256(selection["trace_sha256"]):
        raise O1RelationalSearchError("delayed pair-credit selection trace differs")
    first_group = selection["first_group_index"]
    first_mask = selection["first_pattern_mask"]
    if tickets["opened"]:
        if (
            isinstance(first_group, bool)
            or not isinstance(first_group, int)
            or not 0 <= first_group < DELAYED_PAIR_CREDIT_GROUPS
            or isinstance(first_mask, bool)
            or not isinstance(first_mask, int)
            or not 0 <= first_mask < 4
        ):
            raise O1RelationalSearchError(
                "delayed pair-credit first cold selection differs"
            )
    elif first_group is not None or first_mask is not None:
        raise O1RelationalSearchError(
            "delayed pair-credit empty selection contains first action"
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
        or queue["requested_decisions"] != pending["marked"]
        or pending["marked"] != pending["bound"]
        or pending["bound"]
        != pending["first_owner_bindings"] + pending["second_owner_bindings"]
        or pending["owner_assignment_hits"] > pending["bound"]
        or pending["maximum_open"] != int(pending["marked"] > 0)
        or pending["current_open"] != 0
    ):
        raise O1RelationalSearchError("delayed pair-credit telemetry ledger differs")
    if (
        backtrack_credit["callbacks"] != queue["backtracks"]
        or backtrack_credit["callbacks"]
        != backtrack_credit["conflict_callbacks"]
        + backtrack_credit["nonconflict_callbacks"]
        or backtrack_credit["eligible_undo_groups"]
        != backtrack_credit["credit_updates"]
        or backtrack_credit["eligible_undo_members"]
        != backtrack_credit["conflict_undo_members"]
        + backtrack_credit["nonconflict_undo_members"]
        or backtrack_credit["weighted_undo_units"]
        != backtrack_credit["conflict_weighted_undo_units"]
        + backtrack_credit["nonconflict_weighted_undo_units"]
        or backtrack_credit["conflict_penalty_units"]
        != 2 * backtrack_credit["conflict_weighted_undo_units"]
        or backtrack_credit["nonconflict_penalty_units"]
        != backtrack_credit["nonconflict_weighted_undo_units"]
        or backtrack_credit["eligible_undo_groups"]
        > backtrack_credit["eligible_undo_members"]
        or backtrack_credit["eligible_undo_members"] > pending["bound"]
        or backtrack_credit["assignment_credit_units"] != 0
        or backtrack_credit["propagation_credit_units"] != 0
        or backtrack_credit["conflict_callbacks"] > stats["conflicts"]
        or not 2 * backtrack_credit["eligible_undo_members"]
        <= backtrack_credit["weighted_undo_units"]
        <= 32 * backtrack_credit["eligible_undo_members"]
    ):
        raise O1RelationalSearchError(
            "delayed pair-credit backtrack-credit ledger differs"
        )

    state = _mapping(delayed["state"], "delayed.state")
    if set(state) != _STATE_FIELDS:
        raise O1RelationalSearchError("delayed pair-credit state fields differ")
    groups_raw = state["groups"]
    if not isinstance(groups_raw, list) or any(
        not isinstance(group, Mapping) for group in groups_raw
    ):
        raise O1RelationalSearchError("delayed pair-credit group states differ")
    groups = [dict(cast(Mapping[str, object], group)) for group in groups_raw]
    group_encoded, owner_encoded = _state_blocks(groups, decisions)
    encoded = group_encoded + owner_encoded
    state_integers = (
        (state["bytes_per_group"], DELAYED_PAIR_CREDIT_BYTES_PER_GROUP),
        (
            state["group_bytes_per_group"],
            DELAYED_PAIR_CREDIT_GROUP_BYTES_PER_GROUP,
        ),
        (
            state["owner_bytes_per_group"],
            DELAYED_PAIR_CREDIT_OWNER_BYTES_PER_GROUP,
        ),
        (
            state["bounded_group_state_bytes"],
            DELAYED_PAIR_CREDIT_GROUP_STATE_BYTES,
        ),
        (
            state["bounded_owner_state_bytes"],
            DELAYED_PAIR_CREDIT_OWNER_STATE_BYTES,
        ),
        (state["bounded_state_bytes"], DELAYED_PAIR_CREDIT_STATE_BYTES),
        (state["credit_min"], DELAYED_PAIR_CREDIT_MIN),
        (state["credit_max"], DELAYED_PAIR_CREDIT_MAX),
        (state["counter_max"], DELAYED_PAIR_COUNTER_MAX),
        (state["owner_level_max"], (1 << 32) - 1),
    )
    if (
        state["encoding"] != DELAYED_PAIR_CREDIT_STATE_ENCODING
        or state["group_encoding"] != DELAYED_PAIR_CREDIT_GROUP_STATE_ENCODING
        or state["owner_encoding"] != DELAYED_PAIR_CREDIT_OWNER_STATE_ENCODING
        or state["counter_semantics"] != DELAYED_PAIR_CREDIT_COUNTER_SEMANTICS
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value != expected
            for value, expected in state_integers
        )
        or not _is_sha256(state["sha256"])
        or state["sha256"] != hashlib.sha256(encoded).hexdigest()
        or not _is_sha256(state["group_sha256"])
        or state["group_sha256"] != hashlib.sha256(group_encoded).hexdigest()
        or not _is_sha256(state["owner_sha256"])
        or state["owner_sha256"] != hashlib.sha256(owner_encoded).hexdigest()
    ):
        raise O1RelationalSearchError("delayed pair-credit bounded state differs")
    for name in ("saturated_credit_updates", "saturated_counter_updates"):
        value = state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"delayed pair-credit state.{name} differs")
    live_owners_raw = state["live_owners"]
    maximum_live_owners_raw = state["maximum_live_owners"]
    if (
        isinstance(live_owners_raw, bool)
        or not isinstance(live_owners_raw, int)
        or live_owners_raw < 0
        or isinstance(maximum_live_owners_raw, bool)
        or not isinstance(maximum_live_owners_raw, int)
        or maximum_live_owners_raw < live_owners_raw
    ):
        raise O1RelationalSearchError("delayed pair-credit owner state differs")
    live_owners = cast(int, live_owners_raw)
    maximum_live_owners = cast(int, maximum_live_owners_raw)
    observed_live_owners = sum(
        int(cast(int, group[name]) > 0)
        for group in groups
        for name in ("first_owner_level", "second_owner_level")
    )
    maximum_level = queue["maximum_decision_level"]
    if (
        live_owners != observed_live_owners
        or live_owners != pending["bound"] - backtrack_credit["eligible_undo_members"]
        or maximum_live_owners < live_owners
        or maximum_live_owners > pending["bound"]
        or any(
            cast(int, group[name]) > maximum_level
            for group in groups
            for name in ("first_owner_level", "second_owner_level")
        )
    ):
        raise O1RelationalSearchError("delayed pair-credit owner ledger differs")
    if sum(cast(int, group["visits"]) for group in groups) > tickets["closed"]:
        raise O1RelationalSearchError("delayed pair-credit state visit ledger differs")
    if any(
        cast(int, group["credit"]) > 0
        or cast(int, group["propagation_units"]) != 0
        or cast(int, group["conflict_hits"]) > cast(int, group["backtrack_hits"])
        for group in groups
    ):
        raise O1RelationalSearchError("delayed pair-credit group state differs")
    conflict_hits = sum(cast(int, group["conflict_hits"]) for group in groups)
    backtrack_hits = sum(cast(int, group["backtrack_hits"]) for group in groups)
    total_penalty = (
        backtrack_credit["conflict_penalty_units"]
        + backtrack_credit["nonconflict_penalty_units"]
    )
    observed_credit_penalty = -sum(cast(int, group["credit"]) for group in groups)
    if (
        conflict_hits > backtrack_credit["conflict_undo_members"]
        or backtrack_hits > backtrack_credit["eligible_undo_members"]
        or observed_credit_penalty > total_penalty
        or (
            state["saturated_credit_updates"] == 0
            and observed_credit_penalty != total_penalty
        )
    ):
        raise O1RelationalSearchError("delayed pair-credit penalty state differs")
    if any(delta > stats[name] for name, delta in deltas.items()):
        raise O1RelationalSearchError(
            "delayed pair-credit solver counter delta ledger differs"
        )

    normalized_delayed = dict(delayed)
    normalized_delayed["queue"] = queue
    normalized_delayed["tickets"] = tickets
    normalized_delayed["pending"] = pending
    normalized_delayed["backtrack_credit"] = backtrack_credit
    normalized_delayed["solver_counter_deltas"] = deltas
    normalized_delayed["selection"] = dict(selection)
    normalized_state = dict(state)
    normalized_state["groups"] = groups
    normalized_delayed["state"] = normalized_state
    return DelayedPairCreditSearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=key_model,
        stats=stats,
        delayed=normalized_delayed,
        resources=resources,
        raw=dict(payload),
    )


# Compatibility names mirror the frozen pair-envelope adapter.
write_criticality_potential = write_delayed_pair_credit_potential
write_decision_variables = write_delayed_pair_credit_decision_variables


__all__ = [
    "DELAYED_PAIR_COUNTER_MAX",
    "DELAYED_PAIR_CREDIT_BYTES_PER_GROUP",
    "DELAYED_PAIR_CREDIT_COUNTER_SEMANTICS",
    "DELAYED_PAIR_CREDIT_DECISION_RULE",
    "DELAYED_PAIR_CREDIT_GROUP_BYTES_PER_GROUP",
    "DELAYED_PAIR_CREDIT_GROUPS",
    "DELAYED_PAIR_CREDIT_GROUP_STATE_BYTES",
    "DELAYED_PAIR_CREDIT_GROUP_STATE_ENCODING",
    "DELAYED_PAIR_CREDIT_MAX",
    "DELAYED_PAIR_CREDIT_MIN",
    "DELAYED_PAIR_CREDIT_OWNER_BYTES_PER_GROUP",
    "DELAYED_PAIR_CREDIT_OWNER_STATE_BYTES",
    "DELAYED_PAIR_CREDIT_OWNER_STATE_ENCODING",
    "DELAYED_PAIR_CREDIT_RESULT_SCHEMA",
    "DELAYED_PAIR_CREDIT_SELECTION_FORMULA",
    "DELAYED_PAIR_CREDIT_STATE_BYTES",
    "DELAYED_PAIR_CREDIT_STATE_ENCODING",
    "DELAYED_PAIR_CREDIT_UPDATE_FORMULA",
    "DelayedPairCreditSearchResult",
    "build_native_delayed_pair_credit_search",
    "delayed_group_credit_update",
    "delayed_owner_weight",
    "run_delayed_pair_credit_search",
    "write_criticality_potential",
    "write_decision_variables",
    "write_delayed_pair_credit_decision_variables",
    "write_delayed_pair_credit_potential",
]
