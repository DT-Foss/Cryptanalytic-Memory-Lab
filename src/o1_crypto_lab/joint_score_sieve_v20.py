"""O1C-0079 adapter for the central ownership-aware native v17 reader.

Native v17 preserves the frozen grouped score/vault core from native v6 but
replaces the nested v11-v16 decision wrappers with one typed ownership ledger.
This module independently validates that ledger, its five-origin composition,
and the exact immutable prefix/rank/frontier/staging bindings.
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

from . import joint_score_sieve_v19 as _v19
from . import joint_score_sieve_v9 as _v9
from .causal_frontier_v1 import (
    CausalFrontierError,
    CausalFrontierPlan,
    parse_causal_frontier_plan,
)
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import NativeGuidedSearchBuild, O1RelationalSearchError
from .rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
    parse_rescue_prefix_preemption_plan,
    validate_o1c78_production_plan,
    validate_rescue_prefix_preemption_plan,
)
from .residual_polarity_staging_v1 import (
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
    parse_residual_polarity_staging_plan,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    VaultCaps,
    vault_identity_from_sources,
)
from .vault_ranked_decision_v1 import (
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_production_vault_ranked_decision,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v20-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v17"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
CENTRAL_READER_SCHEMA = "o1-256-central-composed-reader-v1"
DECISION_OWNERSHIP_SCHEMA = "o1-256-central-decision-ownership-v1"
CENTRAL_OPERATOR = (
    "single-owner-prefix-rank-original-rank-contrast-frontier-initial-"
    "frontier-contrast-over-unchanged-v6"
)
CENTRAL_SELECTION_RULE = (
    "PREFIX-until-consumed;RANK_ORIGINAL-until-consumed;released-"
    "RANK_CONTRAST;FRONTIER_INITIAL-until-consumed;released-"
    "FRONTIER_CONTRAST;base-zero"
)
CENTRAL_RELEASE_RULE = (
    "retire-every-token-bound-above-backtrack-level-atomically;enqueue-"
    "contrast-only-from-token-origin-and-row;confirmation-not-required"
)
OWNERSHIP_LIFECYCLE = (
    "PROPOSED->LEVEL_BOUND->optional-CONFIRMED->RELEASED-or-"
    "LEVEL_BOUND_UNOBSERVED_RELEASE"
)
OWNERSHIP_ELIGIBILITY_RULE = (
    "origin-row-level-token;never-returned-ever-plus-variable-sign"
)
OWNERSHIP_ASSIGNMENT_RULE = (
    "confirmation-is-evidence-not-release-precondition;opposite-and-foreign-"
    "never-claim-token"
)
SIGNED_I32_SEQUENCE_ENCODING = "concatenated-signed-i32le-literals"

ORIGINS = (
    "PREFIX",
    "RANK_ORIGINAL",
    "RANK_CONTRAST",
    "FRONTIER_INITIAL",
    "FRONTIER_CONTRAST",
)
EVENT_KINDS = {
    "PROPOSED",
    "LEVEL_BOUND",
    "CONFIRMED",
    "OPPOSITE_ASSIGNMENT",
    "FOREIGN_ASSIGNMENT",
    "RENOTIFIED",
    "RELEASED",
    "LEVEL_BOUND_UNOBSERVED_RELEASE",
}

_TOP_LEVEL_FIELDS = {
    "schema",
    "implementation_parent_schema",
    "rank_source_vault_sha256",
    "active_vault_sha256",
    "frontier_plan_sha256",
    "staging_plan_sha256",
    "prefix_preemption_plan_sha256",
    "central_reader",
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
    "stats",
    "sieve",
    "vault",
    "resources",
}

_OWNERSHIP_FIELDS = {
    "schema",
    "lifecycle",
    "eligibility_rule",
    "assignment_notification_rule",
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
    "proposal_activated",
    "level_bound_activated",
    "confirmed_activated",
    "events",
    "origin_counts",
}

_CENTRAL_FIELDS = {
    "schema",
    "operator",
    "selection_rule",
    "release_rule",
    "runtime_parent_schema",
    "rank_source_vault_sha256",
    "active_vault_sha256",
    "potential_sha256",
    "potential_source_sha256",
    "grouping_sha256",
    "rank_table_sha256",
    "effective_rank_order_sha256",
    "frontier_plan_sha256",
    "staging_plan_sha256",
    "prefix_plan_sha256",
    "callback_calls",
    "nonzero_returns",
    "zero_returns",
    "assignment_literals_observed",
    "prefix",
    "rank",
    "frontier",
    "staging",
    "returned_sequence_encoding",
    "returned_sequence_count",
    "returned_sequence_bytes",
    "returned_sequence_hex",
    "returned_sequence_sha256",
    "proposal_sequence_encoding",
    "proposal_sequence_count",
    "proposal_sequence_bytes",
    "proposal_sequence_hex",
    "proposal_sequence_sha256",
    "release_sequence_encoding",
    "release_sequence_count",
    "release_sequence_bytes",
    "release_sequence_hex",
    "release_sequence_sha256",
    "return_events",
}


@dataclass(frozen=True)
class JointScoreSieveV20Result(_v9.JointScoreSieveV9Result):
    """A native-v6 validated result plus central composition evidence."""

    rank_source_vault: ThresholdNoGoodVault
    expected_decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan
    staging_plan: ResidualPolarityStagingPlan
    prefix_preemption_plan: RescuePrefixPreemptionPlan
    central_reader: Mapping[str, object]
    decision_ownership: Mapping[str, object]


def _error(field: str) -> O1RelationalSearchError:
    return O1RelationalSearchError(f"joint-score-sieve-v20 {field} differs")


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
        or (not zero and not value)
        or not -(1 << 31) < value < (1 << 31)
    ):
        raise _error(field)
    return value


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


def _effective_rank_literals(
    decision: VaultRankedDecision, staging: ResidualPolarityStagingPlan
) -> tuple[int, ...]:
    result = list(decision.ranked_literals)
    for overlay in staging.overlays:
        if result[overlay.rank_index] != overlay.source_literal:
            raise _error("staging source rank")
        result[overlay.rank_index] = overlay.effective_literal
    return tuple(result)


def _expected_literal(
    origin: str,
    row: int,
    *,
    prefix: RescuePrefixPreemptionPlan,
    effective_rank: tuple[int, ...],
    frontier: CausalFrontierPlan,
) -> int:
    populations: dict[str, tuple[int, ...]] = {
        "PREFIX": prefix.prefix_literals,
        "RANK_ORIGINAL": effective_rank,
        "RANK_CONTRAST": tuple(-literal for literal in effective_rank),
        "FRONTIER_INITIAL": frontier.falsifying_decision_literals,
        "FRONTIER_CONTRAST": frontier.residual_clause_literals,
    }
    try:
        return populations[origin][row]
    except (KeyError, IndexError) as exc:
        raise _error("origin row") from exc


def _replay_ownership(value: object) -> Mapping[str, object]:
    """Replay the complete plan-independent native ownership state machine."""

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
    counts = {
        name: _nonnegative(ownership.get(name), f"ownership {name}")
        for name in (
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
        or counts["omitted_event_count"] != 0
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
        or _boolean(ownership.get("level_bound_activated"), "level activated")
        != bool(counts["level_bound_interventions"])
        or _boolean(ownership.get("confirmed_activated"), "confirmed activated")
        != bool(counts["confirmed_interventions"])
    ):
        raise _error("decision ownership arithmetic")

    origins = _mapping(ownership.get("origin_counts"), "origin counts")
    if set(origins) != set(ORIGINS):
        raise _error("origin count fields")
    origin_totals = {
        name: 0 for name in ("proposals", "level_bound", "confirmed", "releases")
    }
    for origin in ORIGINS:
        row = _mapping(origins[origin], f"origin {origin}")
        if set(row) != set(origin_totals):
            raise _error("origin counters")
        for name in origin_totals:
            origin_totals[name] += _nonnegative(row[name], f"origin {origin} {name}")
    if (
        origin_totals["proposals"] != counts["proposals"]
        or origin_totals["level_bound"] != counts["level_bound_interventions"]
        or origin_totals["confirmed"] != counts["confirmed_interventions"]
        or origin_totals["releases"] != counts["releases"]
    ):
        raise _error("origin total")

    events = _sequence(ownership.get("events"), "ownership events")
    if len(events) != counts["recorded_event_count"]:
        raise _error("recorded event count")
    tokens: dict[int, dict[str, object]] = {}
    event_kind_counts = {kind: 0 for kind in EVENT_KINDS}
    event_origin_counts = {
        origin: {
            name: 0 for name in ("proposals", "level_bound", "confirmed", "releases")
        }
        for origin in ORIGINS
    }
    pending_token: int | None = None
    release_tokens: list[int] = []
    release_target: int | None = None
    replay_maximum_live = 0
    release_kinds = {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    live_phases = {"LEVEL_BOUND", "CONFIRMED"}
    for index, raw_event in enumerate(events, start=1):
        event = _mapping(raw_event, "ownership event")
        if set(event) != {
            "sequence",
            "kind",
            "token",
            "callback",
            "origin",
            "row",
            "literal",
            "level",
            "observed_literal",
        }:
            raise _error("ownership event fields")
        kind = event.get("kind")
        origin = event.get("origin")
        if event.get("sequence") != index or kind not in EVENT_KINDS:
            raise _error("ownership event chronology")
        event_kind_counts[cast(str, kind)] += 1
        token = _nonnegative(event.get("token"), "event token")
        callback = _nonnegative(event.get("callback"), "event callback")
        row_index = _nonnegative(event.get("row"), "event row")
        literal = _literal(event.get("literal"), "event literal", zero=True)
        level = _nonnegative(event.get("level"), "event level")
        observed = _literal(
            event.get("observed_literal"), "event observed literal", zero=True
        )
        is_release = kind in release_kinds
        if pending_token is not None and not (
            kind == "LEVEL_BOUND" and token == pending_token
        ):
            raise _error("pending proposal binding")
        if release_tokens and not is_release:
            raise _error("incomplete release batch")
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
                or row_index
                or not observed
                or literal != observed
                or any(
                    state["phase"] in live_phases
                    and abs(cast(int, state["literal"])) == abs(literal)
                    for state in tokens.values()
                )
            ):
                raise _error("foreign assignment")
            continue
        if origin not in ORIGINS or not token or not callback:
            raise _error("owned event identity")
        if not literal:
            raise _error("owned event literal")
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
                raise _error("proposal transition")
            tokens[token] = {
                "origin": origin,
                "row": row_index,
                "literal": literal,
                "callback": callback,
                "phase": "PROPOSED",
                "proposal_level": level,
                "level": 0,
            }
            pending_token = token
            event_origin_counts[cast(str, origin)]["proposals"] += 1
            continue
        state = tokens.get(token)
        if state is None or any(
            state[name] != value
            for name, value in (
                ("origin", origin),
                ("row", row_index),
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
            ):
                raise _error("level-bound transition")
            if any(
                other is not state
                and other["phase"] in {"LEVEL_BOUND", "CONFIRMED"}
                and abs(cast(int, other["literal"])) == abs(literal)
                for other in tokens.values()
            ):
                raise _error("simultaneous live-variable ownership")
            if any(
                other is not state
                and other["phase"] in {"LEVEL_BOUND", "CONFIRMED"}
                and other["level"] == level
                for other in tokens.values()
            ):
                raise _error("simultaneous live-level ownership")
            state["phase"] = "LEVEL_BOUND"
            state["level"] = level
            pending_token = None
            event_origin_counts[cast(str, origin)]["level_bound"] += 1
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
                raise _error("confirmation transition")
            state["phase"] = "CONFIRMED"
            event_origin_counts[cast(str, origin)]["confirmed"] += 1
        elif kind == "RENOTIFIED":
            if (
                phase != "CONFIRMED"
                or observed != literal
                or level < cast(int, state["level"])
            ):
                raise _error("renotification transition")
        elif kind == "OPPOSITE_ASSIGNMENT":
            if (
                phase not in live_phases
                or observed != -literal
                or level < cast(int, state["level"])
            ):
                raise _error("opposite assignment transition")
        elif is_release:
            if not release_tokens:
                release_target = level
                release_tokens = [
                    cast(int, item[0])
                    for item in sorted(
                        (
                            (candidate_token, candidate)
                            for candidate_token, candidate in tokens.items()
                            if candidate["phase"] in live_phases
                            and cast(int, candidate["level"]) > level
                        ),
                        key=lambda item: (
                            -cast(int, item[1]["level"]),
                            -item[0],
                        ),
                    )
                ]
                if not release_tokens:
                    raise _error("release batch without live token")
            if release_target != level or release_tokens[0] != token:
                raise _error("release batch projection")
            expected_phase = "CONFIRMED" if kind == "RELEASED" else "LEVEL_BOUND"
            if (
                phase != expected_phase
                or observed
                or level >= cast(int, state["level"])
            ):
                raise _error("release transition")
            state["phase"] = "RELEASED"
            event_origin_counts[cast(str, origin)]["releases"] += 1
            del release_tokens[0]
            if not release_tokens:
                release_target = None

    # O1C79 fails closed before telemetry truncation, so replay is complete.
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
        or event_kind_counts["PROPOSED"] != counts["proposals"]
        or event_kind_counts["LEVEL_BOUND"] != counts["level_bound_interventions"]
        or event_kind_counts["CONFIRMED"] != counts["confirmed_interventions"]
        or event_kind_counts["RELEASED"] != counts["confirmed_releases"]
        or event_kind_counts["LEVEL_BOUND_UNOBSERVED_RELEASE"]
        != counts["level_bound_unobserved_releases"]
        or event_kind_counts["OPPOSITE_ASSIGNMENT"] != counts["opposite_assignments"]
        or event_kind_counts["FOREIGN_ASSIGNMENT"] != counts["foreign_assignments"]
        or event_kind_counts["RENOTIFIED"] != counts["renotifications"]
        or event_origin_counts
        != {
            origin: {
                name: _nonnegative(
                    _mapping(origins[origin], f"origin {origin}")[name],
                    f"origin {origin} {name}",
                )
                for name in ("proposals", "level_bound", "confirmed", "releases")
            }
            for origin in ORIGINS
        }
    ):
        raise _error("complete ownership event projection")
    return ownership


def _validate_ownership(
    value: object,
    *,
    prefix: RescuePrefixPreemptionPlan,
    effective_rank: tuple[int, ...],
    frontier: CausalFrontierPlan,
) -> Mapping[str, object]:
    ownership = _replay_ownership(value)
    for raw_event in _sequence(ownership.get("events"), "ownership events"):
        event = _mapping(raw_event, "ownership event")
        if event.get("kind") == "FOREIGN_ASSIGNMENT":
            continue
        origin = cast(str, event.get("origin"))
        row = _nonnegative(event.get("row"), "event row")
        literal = _literal(event.get("literal"), "event literal")
        if literal != _expected_literal(
            origin,
            row,
            prefix=prefix,
            effective_rank=effective_rank,
            frontier=frontier,
        ):
            raise _error("owned event literal")
    return ownership


def _validate_central(
    value: object,
    *,
    ownership: Mapping[str, object],
    input_vault: ThresholdNoGoodVault,
    rank_source_vault: ThresholdNoGoodVault,
    expected_decision: VaultRankedDecision,
    effective_rank: tuple[int, ...],
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
    prefix_plan: RescuePrefixPreemptionPlan,
    potential_sha256: str,
    potential_source_sha256: str,
    grouping_sha256: str,
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
    calls = _nonnegative(central.get("callback_calls"), "callback calls")
    nonzero = _nonnegative(central.get("nonzero_returns"), "nonzero returns")
    zero = _nonnegative(central.get("zero_returns"), "zero returns")
    if calls != nonzero + zero or nonzero != ownership.get("proposals"):
        raise _error("central callback arithmetic")
    returned = _i32_sequence(central, "returned_sequence", calls)
    proposed = _i32_sequence(central, "proposal_sequence", nonzero)
    released = _i32_sequence(
        central,
        "release_sequence",
        _nonnegative(ownership.get("releases"), "ownership releases"),
    )
    if tuple(item for item in returned if item) != proposed or len(
        released
    ) != ownership.get("releases"):
        raise _error("central sequence composition")

    events = _sequence(central.get("return_events"), "return events")
    if len(events) != nonzero:
        raise _error("return event count")
    prior_call = 0
    proposal_event_literals: list[int] = []
    origin_rows: dict[str, list[int]] = {origin: [] for origin in ORIGINS}
    for token, raw_event in enumerate(events, start=1):
        event = _mapping(raw_event, "return event")
        if set(event) != {"call", "origin", "row", "literal", "token"}:
            raise _error("return event fields")
        call = _positive(event.get("call"), "return call")
        origin = event.get("origin")
        row = _nonnegative(event.get("row"), "return row")
        literal = _literal(event.get("literal"), "return literal")
        if (
            call <= prior_call
            or call > calls
            or event.get("token") != token
            or origin not in ORIGINS
            or literal
            != _expected_literal(
                cast(str, origin),
                row,
                prefix=prefix_plan,
                effective_rank=effective_rank,
                frontier=frontier_plan,
            )
        ):
            raise _error("return event chronology")
        if returned[call - 1] != literal:
            raise _error("returned sequence call position")
        proposal_event_literals.append(literal)
        origin_rows[cast(str, origin)].append(row)
        prior_call = call
    if tuple(proposal_event_literals) != proposed:
        raise _error("proposal event sequence")
    nonzero_calls = {
        cast(int, _mapping(event, "return event")["call"]) for event in events
    }
    if any(
        bool(literal) != (index in nonzero_calls)
        for index, literal in enumerate(returned, start=1)
    ):
        raise _error("returned zero pass-through sequence")

    ownership_events = _sequence(ownership.get("events"), "ownership events")
    if not ownership.get("omitted_event_count"):
        ownership_proposals = tuple(
            (
                _positive(
                    _mapping(event, "ownership event")["token"], "proposal token"
                ),
                _positive(
                    _mapping(event, "ownership event")["callback"], "proposal callback"
                ),
                _mapping(event, "ownership event")["origin"],
                _nonnegative(_mapping(event, "ownership event")["row"], "proposal row"),
                _literal(
                    _mapping(event, "ownership event")["literal"],
                    "proposal event literal",
                ),
            )
            for event in ownership_events
            if _mapping(event, "ownership event").get("kind") == "PROPOSED"
        )
        central_proposals = tuple(
            (
                _positive(_mapping(event, "return event")["token"], "return token"),
                _positive(_mapping(event, "return event")["call"], "return call"),
                _mapping(event, "return event")["origin"],
                _nonnegative(_mapping(event, "return event")["row"], "return row"),
                _literal(_mapping(event, "return event")["literal"], "return literal"),
            )
            for event in events
        )
        proposed_from_ownership = tuple(
            _literal(
                _mapping(event, "ownership event")["literal"], "proposal event literal"
            )
            for event in ownership_events
            if _mapping(event, "ownership event").get("kind") == "PROPOSED"
        )
        released_from_ownership = tuple(
            _literal(
                _mapping(event, "ownership event")["literal"], "release event literal"
            )
            for event in ownership_events
            if _mapping(event, "ownership event").get("kind")
            in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
        )
        if (
            ownership_proposals != central_proposals
            or proposed_from_ownership != proposed
            or released_from_ownership != released
        ):
            raise _error("ownership sequence binding")
        proposed_tokens = tuple(
            _positive(_mapping(event, "ownership event")["token"], "proposal token")
            for event in ownership_events
            if _mapping(event, "ownership event").get("kind") == "PROPOSED"
        )
        if proposed_tokens != tuple(range(1, nonzero + 1)):
            raise _error("proposal token continuity")

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
    origin_counts = _mapping(ownership["origin_counts"], "origin counts")
    origin_row = {
        origin: _mapping(origin_counts[origin], f"origin {origin}")
        for origin in ORIGINS
    }
    if (
        prefix.get("rows") != len(prefix_plan.prefix_literals)
        or rank.get("rows") != len(effective_rank)
        or frontier.get("rows") != len(frontier_plan.residual_clause_literals)
        or staging.get("overlay_rows") != len(staging_plan.overlays)
        or prefix.get("returns") != origin_row["PREFIX"]["proposals"]
        or rank.get("original_returns") != origin_row["RANK_ORIGINAL"]["proposals"]
        or rank.get("contrast_returns") != origin_row["RANK_CONTRAST"]["proposals"]
        or frontier.get("initial_returns")
        != origin_row["FRONTIER_INITIAL"]["proposals"]
        or frontier.get("contrast_returns")
        != origin_row["FRONTIER_CONTRAST"]["proposals"]
        or prefix_counts["cursor"]
        != prefix_counts["returns"]
        + prefix_counts["skipped_preassigned_falsifying"]
        + prefix_counts["skipped_preassigned_rescue"]
        or prefix_counts["cursor"] > prefix_counts["rows"]
        or prefix_counts["cursor"] != prefix_counts["rows"]
        or prefix_counts["releases"] > prefix_counts["returns"]
        or prefix_counts["releases"] != origin_row["PREFIX"]["releases"]
        or rank_counts["cursor"]
        != rank_counts["original_returns"] + rank_counts["skipped_preassigned"]
        or rank_counts["cursor"] > rank_counts["rows"]
        or rank_counts["original_releases"] > rank_counts["original_returns"]
        or rank_counts["contrast_enqueued"] != rank_counts["original_releases"]
        or rank_counts["contrast_returns"] > rank_counts["contrast_enqueued"]
        or rank_counts["contrast_releases"] > rank_counts["contrast_returns"]
        or rank_counts["original_releases"] != origin_row["RANK_ORIGINAL"]["releases"]
        or rank_counts["contrast_releases"] != origin_row["RANK_CONTRAST"]["releases"]
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
        != origin_row["FRONTIER_INITIAL"]["releases"]
        or frontier_counts["contrast_releases"]
        != origin_row["FRONTIER_CONTRAST"]["releases"]
        or frontier_counts["live_false_literal_count"]
        + frontier_counts["live_true_literal_count"]
        + frontier_counts["live_unassigned_literal_count"]
        != frontier_plan.selected_clause_literal_count
        or staging_counts["overlay_rows"] != len(staging_plan.overlays)
        or staging_counts["effective_original_returns"]
        > rank_counts["original_returns"]
        or staging_counts["source_contrast_returns"] > rank_counts["contrast_returns"]
        or _boolean(staging.get("proposal_activated"), "staging proposal activation")
        != bool(staging_counts["effective_original_returns"])
    ):
        raise _error("central stage projection")

    overlay_rows = {overlay.rank_index for overlay in staging_plan.overlays}
    ownership_event_maps = [
        _mapping(event, "ownership event") for event in ownership_events
    ]
    staged_bound = any(
        event.get("kind") == "LEVEL_BOUND"
        and event.get("origin") == "RANK_ORIGINAL"
        and event.get("row") in overlay_rows
        for event in ownership_event_maps
    )
    staged_confirmed = any(
        event.get("kind") == "CONFIRMED"
        and event.get("origin") == "RANK_ORIGINAL"
        and event.get("row") in overlay_rows
        for event in ownership_event_maps
    )
    if (
        _boolean(staging.get("level_bound_activated"), "staging level activation")
        != staged_bound
        or _boolean(staging.get("confirmed_activated"), "staging confirmed activation")
        != staged_confirmed
    ):
        raise _error("staging activation semantics")

    # Immutable stage chronology: prefix preempts everything; rank-original is
    # exhausted before contrast/frontier; per-stage row cursors are monotone.
    non_prefix_positions = [
        index
        for index, event in enumerate(events)
        if _mapping(event, "return event")["origin"] != "PREFIX"
    ]
    if non_prefix_positions and any(
        _mapping(event, "return event")["origin"] == "PREFIX"
        for event in events[non_prefix_positions[0] :]
    ):
        raise _error("prefix scheduling")
    lower_positions = [
        index
        for index, event in enumerate(events)
        if _mapping(event, "return event")["origin"]
        in {"RANK_CONTRAST", "FRONTIER_INITIAL", "FRONTIER_CONTRAST"}
    ]
    if lower_positions and any(
        _mapping(event, "return event")["origin"] == "RANK_ORIGINAL"
        for event in events[lower_positions[0] :]
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
    return central


def _base_v6_payload(payload: Mapping[str, object]) -> dict[str, object]:
    names = _v9._TOP_LEVEL_FIELDS
    result = {name: payload[name] for name in names}
    result["schema"] = _v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    result["implementation_parent_schema"] = (
        _v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    return result


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
) -> JointScoreSieveV20Result:
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
    effective_rank = _effective_rank_literals(expected_decision, staging_plan)
    ownership = _validate_ownership(
        root.get("decision_ownership"),
        prefix=prefix_preemption_plan,
        effective_rank=effective_rank,
        frontier=frontier_plan,
    )
    central = _validate_central(
        root.get("central_reader"),
        ownership=ownership,
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
    )
    try:
        parent = _v9._parse_native_payload(
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
        decision_ownership=ownership,
    )
    return JointScoreSieveV20Result(**values)  # pyright: ignore[reportArgumentType]


def _validate_lifecycle_composition(
    central: Mapping[str, object], ownership: Mapping[str, object]
) -> int:
    """Cross-bind the plan-independent central and ownership projections."""

    calls = _nonnegative(central.get("callback_calls"), "central callback calls")
    nonzero = _nonnegative(central.get("nonzero_returns"), "central nonzero returns")
    zero = _nonnegative(central.get("zero_returns"), "central zero returns")
    proposals = _nonnegative(ownership.get("proposals"), "ownership proposals")
    releases = _nonnegative(ownership.get("releases"), "ownership releases")
    if (
        set(central) != _CENTRAL_FIELDS
        or central.get("schema") != CENTRAL_READER_SCHEMA
        or central.get("runtime_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or calls != nonzero + zero
        or nonzero != proposals
    ):
        raise _error("lifecycle composition")

    returned = _i32_sequence(central, "returned_sequence", calls)
    proposed = _i32_sequence(central, "proposal_sequence", proposals)
    released = _i32_sequence(central, "release_sequence", releases)
    return_events = _sequence(central.get("return_events"), "central return events")
    if (
        len(return_events) != proposals
        or tuple(literal for literal in returned if literal) != proposed
    ):
        raise _error("lifecycle sequence composition")

    prior_call = 0
    central_proposals: list[tuple[int, int, object, int, int]] = []
    for token, raw_event in enumerate(return_events, start=1):
        event = _mapping(raw_event, "central return event")
        if set(event) != {"call", "origin", "row", "literal", "token"}:
            raise _error("lifecycle return event fields")
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
            raise _error("lifecycle return event chronology")
        central_proposals.append((token, call, origin, row, literal))
        prior_call = call
    nonzero_calls = {row[1] for row in central_proposals}
    if any(
        bool(literal) != (call in nonzero_calls)
        for call, literal in enumerate(returned, start=1)
    ):
        raise _error("lifecycle returned zero composition")

    ownership_events = _sequence(ownership.get("events"), "ownership events")
    ownership_proposals = tuple(
        (
            _positive(event.get("token"), "ownership proposal token"),
            _positive(event.get("callback"), "ownership proposal callback"),
            event.get("origin"),
            _nonnegative(event.get("row"), "ownership proposal row"),
            _literal(event.get("literal"), "ownership proposal literal"),
        )
        for event in (
            _mapping(raw_event, "ownership event") for raw_event in ownership_events
        )
        if event.get("kind") == "PROPOSED"
    )
    ownership_releases = tuple(
        _literal(event.get("literal"), "ownership release literal")
        for event in (
            _mapping(raw_event, "ownership event") for raw_event in ownership_events
        )
        if event.get("kind") in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}
    )
    if (
        ownership_proposals != tuple(central_proposals)
        or tuple(row[4] for row in central_proposals) != proposed
        or ownership_releases != released
    ):
        raise _error("lifecycle ownership sequence binding")
    return calls


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v17 teardown plus its exact unchanged-v6 lifecycle parent."""

    root = _mapping(payload, "lifecycle payload")
    if (
        set(root) != _TOP_LEVEL_FIELDS
        or root.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or root.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise _error("lifecycle identity")
    normalized = _v9.validate_native_lifecycle(_base_v6_payload(root))
    central = _mapping(root.get("central_reader"), "central reader")
    ownership = _replay_ownership(root.get("decision_ownership"))
    calls = _validate_lifecycle_composition(central, ownership)
    if _mapping(root.get("sieve"), "sieve").get("cb_decide_calls") != calls:
        raise _error("lifecycle callback composition")
    normalized["central_callback_calls"] = calls
    normalized["ownership_proposals"] = _nonnegative(
        ownership.get("proposals"), "ownership proposals"
    )
    return normalized


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
) -> JointScoreSieveV20Result:
    requested = _v9._requested_conflicts(conflict_limit)
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
    io_v1 = _v9._v8._v1
    io_v8 = _v9._v8
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
        frontier_file, frontier_bytes = _v19._v18._v17._frontier._read_regular_file(
            frontier_plan_path
        )
        staging_file, staging_bytes = _v19._v18._staging._read_regular_file(
            staging_plan_path
        )
        prefix_file, prefix_bytes = _v19._prefix._read_regular_file(prefix_plan_path)
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
    rank_source_vault = _v19._parse_and_certify_vault(
        rank_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="rank-source",
    )
    input_vault = _v19._parse_and_certify_vault(
        active_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="active",
    )
    try:
        frontier_plan = parse_causal_frontier_plan(
            frontier_bytes, active_vault=input_vault
        )
        staging_plan = parse_residual_polarity_staging_plan(
            staging_bytes,
            active_vault=input_vault,
            rank_decision=expected_decision,
        )
        prefix_plan = parse_rescue_prefix_preemption_plan(
            prefix_bytes, active_vault=input_vault
        )
        validate_rescue_prefix_preemption_plan(
            prefix_plan,
            active_vault=input_vault,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=O1C78_BASELINE_TRACE_SHA256,
            required_prefix_literals=O1C78_PREFIX_LITERALS,
        )
        validate_o1c78_production_plan(prefix_plan)
    except (
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise _error("plan certification") from exc
    if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
        raise _error("parent frontier plan binding")

    rank_path, rank_bytes = _v19._v18._v17._v16._v15._v14._v13._rank_table_temp(
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
                _v9._attach_native_process_evidence(
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
        _v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v20 execution failed: {detail}"
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
        )
        return replace(
            result,
            stats=_v9.derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=memory_samples,
        )
        raise _error("result JSON") from exc
    except Exception as exc:
        _v9._attach_native_process_evidence(
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
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
) -> JointScoreSieveV20Result:
    """Run native v17 once with stable inputs and a complete ownership replay."""

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
        telemetry = _v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v20"):
            message = f"joint-score-sieve-v20 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


def build_native_joint_score_sieve(
    *, source: str | Path, output: str | Path
) -> NativeGuidedSearchBuild:
    """Build native v17 with the same strict compiler path as the v6 adapter."""

    return _v9.build_native_joint_score_sieve(source=source, output=output)


JOINT_SCORE_SIEVE_BOUND_RULE = _v9.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v9.JointScoreSieveExecutionError
write_joint_score_sieve_grouping = _v9.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v9.write_joint_score_sieve_potential


__all__ = [
    "CENTRAL_OPERATOR",
    "CENTRAL_READER_SCHEMA",
    "DECISION_OWNERSHIP_SCHEMA",
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JointScoreSieveExecutionError",
    "JointScoreSieveV20Result",
    "build_native_joint_score_sieve",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
