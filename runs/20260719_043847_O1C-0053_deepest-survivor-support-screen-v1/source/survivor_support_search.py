"""Bounded survivor support decisions for the frozen O1C-0048 pairs."""

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


SURVIVOR_SUPPORT_RESULT_SCHEMA = "o1-256-cadical-survivor-support-search-result-v1"
SURVIVOR_SUPPORT_DECISION_RULE = "deepest_surviving_owner_pattern_support"
SURVIVOR_SUPPORT_GROUPS = 63
SURVIVOR_SUPPORT_VARIABLES = 126
SURVIVOR_SUPPORT_ACTION_STATE_ENCODING = (
    "i16le-credit,u16le-visits,u16le-conflict-hits,u16le-backtrack-hits"
)
SURVIVOR_SUPPORT_OWNER_STATE_ENCODING = (
    "u32le-first-owner-level,u8-first-owner-mask,"
    "u32le-second-owner-level,u8-second-owner-mask"
)
SURVIVOR_SUPPORT_STATE_ENCODING = (
    "action-block[group,mask]:i16le-credit,u16le-visits,"
    "u16le-conflict-hits,u16le-backtrack-hits;"
    "owner-block[group,member]:u32le-level,u8-mask"
)
SURVIVOR_SUPPORT_COUNTER_SEMANTICS = (
    "visits=closed-exact-pattern-tickets;"
    "conflict-hits=deepest-survivor-support-updates;"
    "backtrack-hits=exact-pattern-undone-owner-clears"
)
SURVIVOR_SUPPORT_UPDATE_FORMULA = (
    "on-backtrack:c=I(conflicts>previous-backtrack-conflicts);"
    "clear-all-owner-level>new-level-with-zero-support;"
    "if-c:choose-one-remaining-max-owner-level-tie-group-member;"
    "action-credit[group,owner-mask]=sat_i16(action-credit+32);"
    "else-no-support"
)
SURVIVOR_SUPPORT_SELECTION_FORMULA = (
    "cold:max-raw-top-vs-second-gap-then-group-order;"
    "active:pattern-adjusted=raw+action-credit[group,mask]/1024;"
    "sort-adjusted-desc-raw-desc-mask-asc;"
    "max-adjusted-top-vs-second-gap-then-group-order"
)
SURVIVOR_SUPPORT_ACTION_BYTES_PER_CELL = 8
SURVIVOR_SUPPORT_ACTION_CELLS_PER_GROUP = 4
SURVIVOR_SUPPORT_ACTION_BYTES_PER_GROUP = 32
SURVIVOR_SUPPORT_OWNER_BYTES_PER_MEMBER = 5
SURVIVOR_SUPPORT_OWNER_MEMBERS_PER_GROUP = 2
SURVIVOR_SUPPORT_OWNER_BYTES_PER_GROUP = 10
SURVIVOR_SUPPORT_BYTES_PER_GROUP = 42
SURVIVOR_SUPPORT_ACTION_STATE_BYTES = 2016
SURVIVOR_SUPPORT_OWNER_STATE_BYTES = 630
SURVIVOR_SUPPORT_STATE_BYTES = 2646
SURVIVOR_SUPPORT_MIN = 0
SURVIVOR_SUPPORT_MAX = (1 << 15) - 1
SURVIVOR_SUPPORT_COUNTER_MAX = (1 << 16) - 1

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
    "survivor",
    "resources",
}
_STATS_FIELDS = {"conflicts", "decisions", "propagations"}
_RESOURCE_FIELDS = {"wall_microseconds", "cpu_microseconds", "peak_rss_bytes"}
_SURVIVOR_FIELDS = {
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
    "survivor_support",
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
    "maximum_raw_gap",
    "maximum_adjusted_gap",
    "credit_reordered_actions",
    "distinct_action_cells_selected",
    "differentiated_groups",
    "supported_action_cells",
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
_SURVIVOR_INTEGER_FIELDS = {
    "callbacks",
    "conflict_callbacks",
    "nonconflict_callbacks",
    "undone_owner_clears",
    "conflict_undone_owner_clears",
    "nonconflict_undone_owner_clears",
    "conflict_callbacks_with_survivor",
    "conflict_callbacks_without_survivor",
    "survivor_candidates_examined",
    "deepest_level_tie_callbacks",
    "support_updates",
    "support_units",
    "assignment_support_units",
    "propagation_support_units",
    "undone_owner_support_units",
    "all_survivor_support_units",
    "maximum_supported_owner_level",
}
_SURVIVOR_NULLABLE_FIELDS = {
    "last_survivor_group",
    "last_survivor_member",
    "last_survivor_level",
    "last_survivor_mask",
}
_SURVIVOR_SUPPORT_FIELDS = (
    _SURVIVOR_INTEGER_FIELDS | _SURVIVOR_NULLABLE_FIELDS | {"trace_sha256"}
)
_DELTA_FIELDS = {"conflicts", "decisions", "propagations"}
_STATE_FIELDS = {
    "encoding",
    "action_encoding",
    "owner_encoding",
    "bytes_per_group",
    "action_bytes_per_cell",
    "action_cells_per_group",
    "action_bytes_per_group",
    "owner_bytes_per_member",
    "owner_members_per_group",
    "owner_bytes_per_group",
    "bounded_action_state_bytes",
    "bounded_owner_state_bytes",
    "bounded_state_bytes",
    "sha256",
    "action_sha256",
    "owner_sha256",
    "credit_min",
    "credit_max",
    "counter_max",
    "owner_level_max",
    "owner_mask_max",
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
    "actions",
    "first_owner_level",
    "first_owner_mask",
    "second_owner_level",
    "second_owner_mask",
}
_ACTION_FIELDS = {"mask", "credit", "visits", "conflict_hits", "backtrack_hits"}


@dataclass(frozen=True)
class SurvivorSupportSearchResult:
    status: int
    conflict_limit: int
    key_model: bytes | None
    stats: Mapping[str, int]
    survivor: Mapping[str, object]
    resources: Mapping[str, int]
    raw: Mapping[str, object]

    @property
    def status_name(self) -> str:
        return {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[self.status]

    @property
    def state_sha256(self) -> str:
        state = _mapping(self.survivor["state"], "survivor.state")
        return str(state["sha256"])

    @property
    def owner_state_sha256(self) -> str:
        state = _mapping(self.survivor["state"], "survivor.state")
        return str(state["owner_sha256"])


def build_native_survivor_support_search(
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
        raise O1RelationalSearchError("survivor-support native build failed")
    return result


def write_survivor_support_potential(
    path: str | Path, field: CriticalityPotentialField
) -> str:
    return write_pair_envelope_potential(path, field)


def write_survivor_support_decision_variables(
    path: str | Path, variables: Iterable[int]
) -> str:
    return write_pair_envelope_decision_variables(path, variables)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1RelationalSearchError(f"survivor-support {field} differs")
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
        raise O1RelationalSearchError(f"survivor-support {field} fields differ")
    result: dict[str, int] = {}
    for name, raw in payload.items():
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise O1RelationalSearchError(f"survivor-support {field}.{name} differs")
        result[str(name)] = raw
    return result


def _read_input(path: str | Path, field: str) -> tuple[Path, bytes, str]:
    try:
        resolved = Path(path).resolve(strict=True)
        payload = resolved.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"survivor-support {field} input differs"
        ) from exc
    if not payload:
        raise O1RelationalSearchError(f"survivor-support {field} input differs")
    return resolved, payload, hashlib.sha256(payload).hexdigest()


def _decision_values(payload: bytes) -> tuple[int, ...]:
    try:
        tokens = payload.decode("ascii").split()
        values = tuple(int(token) for token in tokens)
    except (UnicodeError, ValueError) as exc:
        raise O1RelationalSearchError(
            "survivor-support decision-variable input differs"
        ) from exc
    if (
        len(values) != SURVIVOR_SUPPORT_VARIABLES
        or len(set(values)) != len(values)
        or any(not 1 <= value <= 256 for value in values)
    ):
        raise O1RelationalSearchError(
            "survivor-support requires exactly 63 unique ordered key pairs"
        )
    return values


def _potential_field(payload: bytes) -> CriticalityPotentialField:
    try:
        return CriticalityPotentialField.from_bytes(payload)
    except CriticalityPotentialError as exc:
        raise O1RelationalSearchError(
            "survivor-support potential input differs"
        ) from exc


def _verify_stable_input(
    original_path: str | Path, resolved_path: Path, before: bytes, *, field: str
) -> None:
    try:
        after_path = Path(original_path).resolve(strict=True)
        after = after_path.read_bytes()
    except OSError as exc:
        raise O1RelationalSearchError(
            f"survivor-support {field} changed during execution"
        ) from exc
    if after_path != resolved_path or after != before:
        raise O1RelationalSearchError(
            f"survivor-support {field} changed during execution"
        )


def _sat_signed(value: int) -> int:
    return min(SURVIVOR_SUPPORT_MAX, max(SURVIVOR_SUPPORT_MIN, value))


def survivor_support_update(
    credits: tuple[int, ...],
    owners: tuple[tuple[int, int], ...],
    *,
    new_level: int,
    conflict_backtrack: bool,
) -> tuple[
    tuple[int, ...],
    tuple[tuple[int, int], ...],
    int,
    tuple[int, int, int, int] | None,
]:
    """Reference clear-then-deepest-survivor update; not used natively."""

    if (
        not isinstance(credits, tuple)
        or not isinstance(owners, tuple)
        or not owners
        or len(owners) % 2
        or len(credits) != 2 * len(owners)
        or any(
            isinstance(credit, bool)
            or not isinstance(credit, int)
            or not SURVIVOR_SUPPORT_MIN <= credit <= SURVIVOR_SUPPORT_MAX
            for credit in credits
        )
        or any(
            not isinstance(owner, tuple)
            or len(owner) != 2
            or isinstance(owner[0], bool)
            or not isinstance(owner[0], int)
            or not 0 <= owner[0] <= (1 << 32) - 1
            or isinstance(owner[1], bool)
            or not isinstance(owner[1], int)
            or not 0 <= owner[1] <= 3
            or (owner[0] == 0 and owner[1] != 0)
            for owner in owners
        )
        or isinstance(new_level, bool)
        or not isinstance(new_level, int)
        or not 0 <= new_level <= (1 << 32) - 1
        or not isinstance(conflict_backtrack, bool)
    ):
        raise O1RelationalSearchError("survivor-support bounded update differs")
    remaining: list[tuple[int, int]] = []
    undone = 0
    for level, mask in owners:
        if level > new_level:
            remaining.append((0, 0))
            undone += 1
        else:
            remaining.append((level, mask))
    selected: tuple[int, int, int, int] | None = None
    if conflict_backtrack:
        for owner_index, (level, mask) in enumerate(remaining):
            if not level:
                continue
            group, member = divmod(owner_index, 2)
            candidate = (group, member, level, mask)
            if selected is None or level > selected[2]:
                selected = candidate
    updated = list(credits)
    if selected is not None:
        group, _, _, mask = selected
        cell = 4 * group + mask
        updated[cell] = _sat_signed(updated[cell] + 32)
    return tuple(updated), tuple(remaining), undone, selected


def _state_blocks(
    groups: Sequence[Mapping[str, object]], decisions: tuple[int, ...]
) -> tuple[bytes, bytes]:
    if len(groups) != SURVIVOR_SUPPORT_GROUPS:
        raise O1RelationalSearchError("survivor-support group-state count differs")
    action_output = bytearray()
    owner_output = bytearray()
    for index, group in enumerate(groups):
        if set(group) != _GROUP_FIELDS:
            raise O1RelationalSearchError(
                f"survivor-support state group {index} fields differ"
            )
        expected_pair = decisions[2 * index : 2 * index + 2]
        raw_values = tuple(
            group[name]
            for name in (
                "index",
                "first_variable",
                "second_variable",
                "first_owner_level",
                "first_owner_mask",
                "second_owner_level",
                "second_owner_mask",
            )
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in raw_values
        ):
            raise O1RelationalSearchError(
                f"survivor-support state group {index} value differs"
            )
        values = tuple(cast(int, value) for value in raw_values)
        (
            reported_index,
            first,
            second,
            first_owner_level,
            first_owner_mask,
            second_owner_level,
            second_owner_mask,
        ) = values
        if (
            reported_index != index
            or (first, second) != expected_pair
            or not 0 <= first_owner_level <= (1 << 32) - 1
            or not 0 <= second_owner_level <= (1 << 32) - 1
            or not 0 <= first_owner_mask <= 3
            or not 0 <= second_owner_mask <= 3
            or (first_owner_level == 0 and first_owner_mask != 0)
            or (second_owner_level == 0 and second_owner_mask != 0)
        ):
            raise O1RelationalSearchError(
                f"survivor-support state group {index} contract differs"
            )
        actions_raw = group["actions"]
        if not isinstance(actions_raw, list) or len(actions_raw) != 4:
            raise O1RelationalSearchError(
                f"survivor-support state group {index} actions differ"
            )
        for mask, raw_action in enumerate(actions_raw):
            action = _mapping(raw_action, f"state group {index} action {mask}")
            if set(action) != _ACTION_FIELDS:
                raise O1RelationalSearchError(
                    f"survivor-support state group {index} action fields differ"
                )
            action_values = tuple(
                action[name]
                for name in (
                    "mask",
                    "credit",
                    "visits",
                    "conflict_hits",
                    "backtrack_hits",
                )
            )
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in action_values
            ):
                raise O1RelationalSearchError(
                    f"survivor-support state group {index} action value differs"
                )
            reported_mask, credit, visits, conflicts, backtracks = cast(
                tuple[int, int, int, int, int], action_values
            )
            if (
                reported_mask != mask
                or not SURVIVOR_SUPPORT_MIN <= credit <= SURVIVOR_SUPPORT_MAX
                or any(
                    not 0 <= counter <= SURVIVOR_SUPPORT_COUNTER_MAX
                    for counter in (visits, conflicts, backtracks)
                )
            ):
                raise O1RelationalSearchError(
                    f"survivor-support state group {index} action contract differs"
                )
            action_output.extend(
                struct.pack("<hHHH", credit, visits, conflicts, backtracks)
            )
        owner_output.extend(
            struct.pack(
                "<IBIB",
                first_owner_level,
                first_owner_mask,
                second_owner_level,
                second_owner_mask,
            )
        )
    return bytes(action_output), bytes(owner_output)


def run_survivor_support_search(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    decision_variables_path: str | Path,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
) -> SurvivorSupportSearchResult:
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
            "survivor-support search limit, seed, or timeout differs"
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
            "survivor-support decision variables are absent from potential"
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
            "survivor-support search execution failed"
        ) from execution_error
    if completed is None:
        raise O1RelationalSearchError("survivor-support search execution failed")
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise O1RelationalSearchError(
            f"survivor-support search execution failed: {detail}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise O1RelationalSearchError(
            "survivor-support search JSON is invalid"
        ) from exc
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("survivor-support result fields differ")
    variables = payload["variables"]
    reported_limit = payload["conflict_limit"]
    reported_seed = payload["seed"]
    status = payload["status"]
    if (
        payload["schema"] != SURVIVOR_SUPPORT_RESULT_SCHEMA
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
        raise O1RelationalSearchError("survivor-support result contract differs")
    model_hex = payload["key_model_hex"]
    if status == 10:
        if not isinstance(model_hex, str) or len(model_hex) != 64:
            raise O1RelationalSearchError("SAT survivor-support result lacks key")
        try:
            key_model = bytes.fromhex(model_hex)
        except ValueError as exc:
            raise O1RelationalSearchError(
                "survivor-support key encoding differs"
            ) from exc
    elif model_hex is not None:
        raise O1RelationalSearchError("non-SAT survivor-support result contains key")
    else:
        key_model = None

    stats = _nonnegative_integer_group(
        payload["stats"], field="stats", names=_STATS_FIELDS
    )
    resources = _nonnegative_integer_group(
        payload["resources"], field="resources", names=_RESOURCE_FIELDS
    )
    pattern = _mapping(payload["survivor"], "survivor")
    if set(pattern) != _SURVIVOR_FIELDS:
        raise O1RelationalSearchError("survivor-support pattern fields differ")
    external_implications = pattern["external_implications"]
    hard_clauses_added = pattern["hard_clauses_added"]
    identity_integers = (
        (pattern["factor_count"], len(field.factors)),
        (pattern["pair_count"], SURVIVOR_SUPPORT_GROUPS),
        (pattern["group_width"], 2),
        (pattern["observed_variables"], len(field.observed_variables)),
        (pattern["eligible_decision_variables"], len(decisions)),
        (external_implications, 0),
        (hard_clauses_added, 0),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value != expected
        for value, expected in identity_integers
    ):
        raise O1RelationalSearchError("survivor-support identity differs")
    reported_offset = pattern["offset"]
    if (
        pattern["decision_rule"] != SURVIVOR_SUPPORT_DECISION_RULE
        or pattern["cold_decision_rule"] != PAIR_ENVELOPE_DECISION_RULE
        or pattern["decision_scope"] != PAIR_ENVELOPE_DECISION_SCOPE
        or pattern["source_sha256"] != field.source_sha256
        or pattern["decision_variables_sha256"] != decision_sha256
        or isinstance(reported_offset, bool)
        or not isinstance(reported_offset, (int, float))
        or not math.isfinite(reported_offset)
        or reported_offset != field.offset
        or pattern["update_formula"] != SURVIVOR_SUPPORT_UPDATE_FORMULA
        or pattern["selection_formula"] != SURVIVOR_SUPPORT_SELECTION_FORMULA
    ):
        raise O1RelationalSearchError("survivor-support identity differs")

    queue = _nonnegative_integer_group(
        pattern["queue"], field="pattern.queue", names=_QUEUE_FIELDS
    )
    tickets = _nonnegative_integer_group(
        pattern["tickets"], field="pattern.tickets", names=_TICKET_FIELDS
    )
    pending = _nonnegative_integer_group(
        pattern["pending"], field="pattern.pending", names=_PENDING_FIELDS
    )
    support_payload = _mapping(pattern["survivor_support"], "survivor.support")
    if set(support_payload) != _SURVIVOR_SUPPORT_FIELDS:
        raise O1RelationalSearchError("survivor-support telemetry fields differ")
    support: dict[str, int] = {}
    for name in _SURVIVOR_INTEGER_FIELDS:
        value = support_payload[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"survivor-support telemetry.{name} differs")
        support[name] = value
    deltas = _nonnegative_integer_group(
        pattern["solver_counter_deltas"],
        field="pattern.solver_counter_deltas",
        names=_DELTA_FIELDS,
    )
    selection = _mapping(pattern["selection"], "pattern.selection")
    if set(selection) != _SELECTION_FIELDS:
        raise O1RelationalSearchError("survivor-support selection fields differ")
    for name in (
        "cold_group_selections",
        "credit_modulated_group_selections",
        "zero_gap_fallbacks",
        "envelope_evaluations",
        "credit_reordered_actions",
        "distinct_action_cells_selected",
        "differentiated_groups",
        "supported_action_cells",
    ):
        value = selection[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"survivor-support selection.{name} differs")
    cold_selections = cast(int, selection["cold_group_selections"])
    modulated_selections = cast(int, selection["credit_modulated_group_selections"])
    for name in ("maximum_raw_gap", "maximum_adjusted_gap"):
        value = selection[name]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise O1RelationalSearchError(f"survivor-support selection.{name} differs")
    maximum_raw_gap = float(cast(int | float, selection["maximum_raw_gap"]))
    maximum_adjusted_gap = float(cast(int | float, selection["maximum_adjusted_gap"]))
    reordered_actions = cast(int, selection["credit_reordered_actions"])
    distinct_selected = cast(int, selection["distinct_action_cells_selected"])
    differentiated = cast(int, selection["differentiated_groups"])
    supported = cast(int, selection["supported_action_cells"])
    if (
        maximum_raw_gap < 0
        or maximum_adjusted_gap < 0
        or (tickets["opened"] == 0 and maximum_raw_gap != 0)
        or (tickets["opened"] > 0 and maximum_raw_gap <= 0)
        or (modulated_selections == 0 and maximum_adjusted_gap != 0)
        or reordered_actions > modulated_selections
        or distinct_selected > 4 * SURVIVOR_SUPPORT_GROUPS
        or differentiated > SURVIVOR_SUPPORT_GROUPS
        or supported > 4 * SURVIVOR_SUPPORT_GROUPS
    ):
        raise O1RelationalSearchError(
            "survivor-support selection metric ledger differs"
        )
    if not _is_sha256(selection["trace_sha256"]):
        raise O1RelationalSearchError("survivor-support selection trace differs")
    first_group = selection["first_group_index"]
    first_mask = selection["first_pattern_mask"]
    if tickets["opened"]:
        if (
            isinstance(first_group, bool)
            or not isinstance(first_group, int)
            or not 0 <= first_group < SURVIVOR_SUPPORT_GROUPS
            or isinstance(first_mask, bool)
            or not isinstance(first_mask, int)
            or not 0 <= first_mask < 4
        ):
            raise O1RelationalSearchError(
                "survivor-support first cold selection differs"
            )
    elif first_group is not None or first_mask is not None:
        raise O1RelationalSearchError(
            "survivor-support empty selection contains first action"
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
        raise O1RelationalSearchError("survivor-support telemetry ledger differs")
    last_values = tuple(support_payload[name] for name in _SURVIVOR_NULLABLE_FIELDS)
    if (
        support["callbacks"] != queue["backtracks"]
        or support["callbacks"]
        != support["conflict_callbacks"] + support["nonconflict_callbacks"]
        or support["undone_owner_clears"]
        != support["conflict_undone_owner_clears"]
        + support["nonconflict_undone_owner_clears"]
        or support["undone_owner_clears"] > pending["bound"]
        or support["conflict_callbacks"]
        != support["conflict_callbacks_with_survivor"]
        + support["conflict_callbacks_without_survivor"]
        or support["support_updates"] != support["conflict_callbacks_with_survivor"]
        or support["support_units"] != 32 * support["support_updates"]
        or support["deepest_level_tie_callbacks"] > support["support_updates"]
        or support["survivor_candidates_examined"] < support["support_updates"]
        or support["conflict_callbacks"] > stats["conflicts"]
        or support["maximum_supported_owner_level"] > queue["maximum_decision_level"]
        or any(
            support[name] != 0
            for name in (
                "assignment_support_units",
                "propagation_support_units",
                "undone_owner_support_units",
                "all_survivor_support_units",
            )
        )
        or not _is_sha256(support_payload["trace_sha256"])
    ):
        raise O1RelationalSearchError("survivor-support update ledger differs")
    if support["support_updates"] == 0:
        if (
            any(value is not None for value in last_values)
            or support["maximum_supported_owner_level"] != 0
        ):
            raise O1RelationalSearchError("survivor-support empty selection differs")
    else:
        group = support_payload["last_survivor_group"]
        member = support_payload["last_survivor_member"]
        level = support_payload["last_survivor_level"]
        mask = support_payload["last_survivor_mask"]
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in last_values
            )
            or not 0 <= cast(int, group) < SURVIVOR_SUPPORT_GROUPS
            or not 0 <= cast(int, member) < 2
            or not 1 <= cast(int, level) <= queue["maximum_decision_level"]
            or not 0 <= cast(int, mask) < 4
            or cast(int, level) > support["maximum_supported_owner_level"]
        ):
            raise O1RelationalSearchError("survivor-support selection differs")

    state = _mapping(pattern["state"], "survivor.state")
    if set(state) != _STATE_FIELDS:
        raise O1RelationalSearchError("survivor-support state fields differ")
    groups_raw = state["groups"]
    if not isinstance(groups_raw, list) or any(
        not isinstance(group, Mapping) for group in groups_raw
    ):
        raise O1RelationalSearchError("survivor-support group states differ")
    groups = [dict(cast(Mapping[str, object], group)) for group in groups_raw]
    action_encoded, owner_encoded = _state_blocks(groups, decisions)
    encoded = action_encoded + owner_encoded
    state_integers = (
        (state["bytes_per_group"], SURVIVOR_SUPPORT_BYTES_PER_GROUP),
        (
            state["action_bytes_per_cell"],
            SURVIVOR_SUPPORT_ACTION_BYTES_PER_CELL,
        ),
        (
            state["action_cells_per_group"],
            SURVIVOR_SUPPORT_ACTION_CELLS_PER_GROUP,
        ),
        (
            state["action_bytes_per_group"],
            SURVIVOR_SUPPORT_ACTION_BYTES_PER_GROUP,
        ),
        (
            state["owner_bytes_per_member"],
            SURVIVOR_SUPPORT_OWNER_BYTES_PER_MEMBER,
        ),
        (
            state["owner_members_per_group"],
            SURVIVOR_SUPPORT_OWNER_MEMBERS_PER_GROUP,
        ),
        (
            state["owner_bytes_per_group"],
            SURVIVOR_SUPPORT_OWNER_BYTES_PER_GROUP,
        ),
        (
            state["bounded_action_state_bytes"],
            SURVIVOR_SUPPORT_ACTION_STATE_BYTES,
        ),
        (
            state["bounded_owner_state_bytes"],
            SURVIVOR_SUPPORT_OWNER_STATE_BYTES,
        ),
        (state["bounded_state_bytes"], SURVIVOR_SUPPORT_STATE_BYTES),
        (state["credit_min"], SURVIVOR_SUPPORT_MIN),
        (state["credit_max"], SURVIVOR_SUPPORT_MAX),
        (state["counter_max"], SURVIVOR_SUPPORT_COUNTER_MAX),
        (state["owner_level_max"], (1 << 32) - 1),
        (state["owner_mask_max"], 3),
    )
    if (
        state["encoding"] != SURVIVOR_SUPPORT_STATE_ENCODING
        or state["action_encoding"] != SURVIVOR_SUPPORT_ACTION_STATE_ENCODING
        or state["owner_encoding"] != SURVIVOR_SUPPORT_OWNER_STATE_ENCODING
        or state["counter_semantics"] != SURVIVOR_SUPPORT_COUNTER_SEMANTICS
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value != expected
            for value, expected in state_integers
        )
        or not _is_sha256(state["sha256"])
        or state["sha256"] != hashlib.sha256(encoded).hexdigest()
        or not _is_sha256(state["action_sha256"])
        or state["action_sha256"] != hashlib.sha256(action_encoded).hexdigest()
        or not _is_sha256(state["owner_sha256"])
        or state["owner_sha256"] != hashlib.sha256(owner_encoded).hexdigest()
    ):
        raise O1RelationalSearchError("survivor-support bounded state differs")
    for name in ("saturated_credit_updates", "saturated_counter_updates"):
        value = state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(f"survivor-support state.{name} differs")
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
        raise O1RelationalSearchError("survivor-support owner state differs")
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
        or live_owners != pending["bound"] - support["undone_owner_clears"]
        or maximum_live_owners < live_owners
        or maximum_live_owners > pending["bound"]
        or any(
            cast(int, group[name]) > maximum_level
            for group in groups
            for name in ("first_owner_level", "second_owner_level")
        )
    ):
        raise O1RelationalSearchError("survivor-support owner ledger differs")
    actions = [
        cast(Mapping[str, object], action)
        for group in groups
        for action in cast(list[object], group["actions"])
    ]
    if sum(cast(int, action["visits"]) for action in actions) > tickets["closed"]:
        raise O1RelationalSearchError("survivor-support state visit ledger differs")
    if any(cast(int, action["credit"]) < 0 for action in actions):
        raise O1RelationalSearchError("survivor-support action state differs")
    distinct_actions = sum(cast(int, action["visits"]) > 0 for action in actions)
    differentiated_groups = sum(
        sum(
            cast(int, cast(Mapping[str, object], action)["visits"]) > 0
            for action in cast(list[object], group["actions"])
        )
        > 1
        for group in groups
    )
    supported_actions = sum(cast(int, action["credit"]) > 0 for action in actions)
    if (
        selection["distinct_action_cells_selected"] != distinct_actions
        or selection["differentiated_groups"] != differentiated_groups
        or selection["supported_action_cells"] != supported_actions
    ):
        raise O1RelationalSearchError("survivor-support differentiation ledger differs")
    conflict_hits = sum(cast(int, action["conflict_hits"]) for action in actions)
    backtrack_hits = sum(cast(int, action["backtrack_hits"]) for action in actions)
    observed_support = sum(cast(int, action["credit"]) for action in actions)
    if (
        conflict_hits > support["support_updates"]
        or backtrack_hits > support["undone_owner_clears"]
        or observed_support > support["support_units"]
        or (
            state["saturated_credit_updates"] == 0
            and observed_support != support["support_units"]
        )
        or (
            state["saturated_counter_updates"] == 0
            and (
                conflict_hits != support["support_updates"]
                or backtrack_hits != support["undone_owner_clears"]
            )
        )
    ):
        raise O1RelationalSearchError("survivor-support state ledger differs")
    if any(delta > stats[name] for name, delta in deltas.items()):
        raise O1RelationalSearchError(
            "survivor-support solver counter delta ledger differs"
        )

    normalized_pattern = dict(pattern)
    normalized_pattern["queue"] = queue
    normalized_pattern["tickets"] = tickets
    normalized_pattern["pending"] = pending
    normalized_support = dict(support_payload)
    normalized_support.update(support)
    normalized_pattern["survivor_support"] = normalized_support
    normalized_pattern["solver_counter_deltas"] = deltas
    normalized_pattern["selection"] = dict(selection)
    normalized_state = dict(state)
    normalized_state["groups"] = groups
    normalized_pattern["state"] = normalized_state
    return SurvivorSupportSearchResult(
        status=status,
        conflict_limit=conflict_limit,
        key_model=key_model,
        stats=stats,
        survivor=normalized_pattern,
        resources=resources,
        raw=dict(payload),
    )


# Compatibility names mirror the frozen pair-envelope adapter.
write_criticality_potential = write_survivor_support_potential
write_decision_variables = write_survivor_support_decision_variables


__all__ = [
    "SURVIVOR_SUPPORT_ACTION_BYTES_PER_CELL",
    "SURVIVOR_SUPPORT_ACTION_BYTES_PER_GROUP",
    "SURVIVOR_SUPPORT_ACTION_CELLS_PER_GROUP",
    "SURVIVOR_SUPPORT_ACTION_STATE_BYTES",
    "SURVIVOR_SUPPORT_ACTION_STATE_ENCODING",
    "SURVIVOR_SUPPORT_BYTES_PER_GROUP",
    "SURVIVOR_SUPPORT_COUNTER_MAX",
    "SURVIVOR_SUPPORT_COUNTER_SEMANTICS",
    "SURVIVOR_SUPPORT_DECISION_RULE",
    "SURVIVOR_SUPPORT_GROUPS",
    "SURVIVOR_SUPPORT_MAX",
    "SURVIVOR_SUPPORT_MIN",
    "SURVIVOR_SUPPORT_OWNER_BYTES_PER_MEMBER",
    "SURVIVOR_SUPPORT_OWNER_BYTES_PER_GROUP",
    "SURVIVOR_SUPPORT_OWNER_MEMBERS_PER_GROUP",
    "SURVIVOR_SUPPORT_OWNER_STATE_BYTES",
    "SURVIVOR_SUPPORT_OWNER_STATE_ENCODING",
    "SURVIVOR_SUPPORT_RESULT_SCHEMA",
    "SURVIVOR_SUPPORT_SELECTION_FORMULA",
    "SURVIVOR_SUPPORT_STATE_BYTES",
    "SURVIVOR_SUPPORT_STATE_ENCODING",
    "SURVIVOR_SUPPORT_UPDATE_FORMULA",
    "SurvivorSupportSearchResult",
    "build_native_survivor_support_search",
    "survivor_support_update",
    "run_survivor_support_search",
    "write_criticality_potential",
    "write_decision_variables",
    "write_survivor_support_decision_variables",
    "write_survivor_support_potential",
]
