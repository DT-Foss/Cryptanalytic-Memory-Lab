"""Strict release-contrast adapter for native joint sieve v12.

The adapter validates the O1C73 opposite-on-release causal trace before
projecting a synthetic, original-only lineage view through the frozen v14
parser.  The projection exists only to retain the inherited lifecycle, vault,
resource, and result contracts; it is never exposed as native telemetry.
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
from typing import Mapping, cast

from . import joint_score_sieve_v14 as _v14
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)
from .vault_ranked_decision_v1 import (
    PRODUCTION_CANDIDATE_COUNT,
    PRODUCTION_ORDER_BYTES,
    PRODUCTION_ORDER_SHA256,
    PRODUCTION_RANK_TABLE_BYTES,
    PRODUCTION_RANK_TABLE_SHA256,
    VAULT_RANKED_DECISION_BOUND_RULE,
    VAULT_RANKED_DECISION_GAP_RULE,
    VAULT_RANKED_DECISION_LITERAL_RULE,
    VAULT_RANKED_DECISION_OPERATOR,
    VAULT_RANKED_DECISION_ORDER_ENCODING,
    VAULT_RANKED_DECISION_SORT_RULE,
    VAULT_RANKED_DECISION_SPEC_SHA256,
    VAULT_RANKED_DECISION_TABLE_ENCODING,
    VAULT_RANKED_DECISION_VOTE_RULE,
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_production_vault_ranked_decision,
    validate_vault_ranked_decision,
    vault_ranked_decision_spec_bytes,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v15-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v12"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)
JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v11"
)
VAULT_RANKED_DECISION_READER_SCHEMA = (
    "o1-256-cadical-vault-release-contrast-ranked-decision-reader-v1"
)
VAULT_RELEASE_CONTRAST_OPERATOR = (
    "vault-ranked-once-then-released-opposite-once"
)
VAULT_RELEASE_CONTRAST_POLICY_SCHEMA = "o1-vault-release-contrast-v1"
VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES = 674
VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256 = (
    "96e040917b6566671683598a09c6d03f6ebec3809c6c63354f09ffca93c246b5"
)
VAULT_BACKTRACK_RELEASE_POLICY_SCHEMA = VAULT_RELEASE_CONTRAST_POLICY_SCHEMA
VAULT_BACKTRACK_RELEASE_POLICY_SPEC_BYTES = (
    VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES
)
VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256 = (
    VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256
)
VAULT_RANKED_DECISION_DECISION_RULE = (
    "v11-original-first;after-rank-exhaustion-earliest-released-currently-"
    "unassigned-opposite-once;zero-delegates"
)
VAULT_RANKED_DECISION_CALLBACK_RULE = (
    "preserve-v11-monotone-consume-once;enqueue-first-real-original-release;"
    "bounded-scan-defer-assigned;never-repeat-signed-literal"
)
VAULT_RANKED_DECISION_STATE_ENCODING = "256-bits-lsb-first-by-rank-index"
VAULT_RANKED_DECISION_SEQUENCE_ENCODING = (
    "concatenated-signed-i32le-literals-in-observation-order"
)
VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING = (
    VAULT_RANKED_DECISION_SEQUENCE_ENCODING
)
VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING = (
    VAULT_RANKED_DECISION_SEQUENCE_ENCODING
)
VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING = (
    _v14.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
)
VAULT_RANKED_DECISION_NONZERO_EVENT_RULE = (
    "bounded-at-most-510-events;one-record-per-nonzero-callback;"
    "assignment-burst-finalized-at-next-cb-decide"
)
VAULT_RANKED_DECISION_PAIR_RECORD_RULE = (
    "bounded-at-most-255-original-returned-rank-records;callback-ordinals-"
    "one-based;release-after-call-and-new-level"
)
VAULT_RANKED_DECISION_BOUNDED_STATE_RULE = (
    "six-256-bit-rank-bitsets;bounded-u16-release-order;bounded-510-nonzero-"
    "events;bounded-255-pair-records;one-256-bit-deferred-assignment-telemetry;"
    "incremental-all-callback-sha256"
)

_RELEASE_CONTRAST_POLICY_SPEC = (
    b"o1-vault-release-contrast-v1\n"
    b"parent=o1-vault-backtrack-release-ranked-decision-v1\n"
    b"original=monotone-rank-consume-once;assigned-rows-consumed-and-skipped\n"
    b"enqueue=on-first-real-release-of-original-returned-signed-literal\n"
    b"contrast=after-original-rank-exhaustion;earliest-release-order-currently-"
    b"unassigned;return-exact-opposite-once\n"
    b"defer=assigned-enqueued-row-remains-pending;bounded-full-queue-scan\n"
    b"limits=at-most-255-original;at-most-255-contrast;at-most-two-decisions-"
    b"per-variable;no-signed-literal-repeat\n"
    b"fallback=zero-delegates-to-native-solver\n"
    b"phase=none\n"
    b"state=six-256-bit-rank-bitsets;u16-release-order;bounded-nonzero-events-"
    b"and-pair-records;incremental-callback-hash\n"
)

_RANK_STATE_BITS = 256
_RANK_STATE_BYTES = 32
_MAXIMUM_CANDIDATES = 255
_MAXIMUM_NONZERO_EVENTS = 2 * _MAXIMUM_CANDIDATES
_BOUNDED_GUIDANCE_STATE_BYTES = 4 + 6 * _RANK_STATE_BYTES + 2 * _MAXIMUM_CANDIDATES
_BOUNDED_TELEMETRY_STATE_BYTES = (
    _BOUNDED_GUIDANCE_STATE_BYTES
    + _MAXIMUM_NONZERO_EVENTS * 32
    + _MAXIMUM_CANDIDATES * 64
    + 112
    + _RANK_STATE_BYTES
)
_TOP_LEVEL_FIELDS = _v14._TOP_LEVEL_FIELDS | {"implementation_release_parent_schema"}
_STATIC_RANK_FIELDS = (
    _v14._STATIC_RANK_FIELDS - {"zero_delta_count", "unobserved_nonzero_count"}
) | {"implementation_release_parent_schema"}
_POLICY_FIELDS = frozenset(
    {"contrast_policy_spec_bytes", "contrast_policy_spec_sha256"}
)
_GUIDANCE_STATE_PREFIXES = (
    "consumed_state",
    "original_returned_state",
    "original_released_state",
    "contrast_enqueued_state",
    "contrast_returned_state",
    "contrast_released_state",
)
_STATE_PREFIXES = _GUIDANCE_STATE_PREFIXES + (
    "contrast_deferred_assigned_state",
)
_SEQUENCE_PREFIXES = (
    "original_return_sequence",
    "original_release_sequence",
    "contrast_return_sequence",
    "contrast_release_sequence",
)
_RUNTIME_READER_FIELDS = frozenset(
    {
        "decision_rule",
        "callback_rule",
        "cursor",
        "rows_consumed",
        "original_once_returns",
        "skipped_preassigned",
        "released_original",
        "contrast_enqueued",
        "contrast_returns",
        "contrast_releases",
        "contrast_deferred_assigned",
        "paired_variables",
        "cb_decide_calls",
        "cb_decide_nonzero",
        "cb_decide_zero",
        "first_parent_fallback_call",
        "first_final_fallback_call",
        "same_signed_redecisions",
        "variable_second_decisions",
        "solver_phase_calls",
        "queue_size",
        "maximum_queue_size",
        "assignment_literals_observed",
        "returned_sequence_encoding",
        "returned_sequence_count",
        "returned_sequence_bytes",
        "returned_sequence_sha256",
        "nonzero_event_rule",
        "nonzero_return_events",
        "pair_record_rule",
        "pair_records",
        "bounded_state_rule",
        "bounded_guidance_state_bytes",
        "live_guidance_state_bytes",
        "bounded_telemetry_state_bytes",
        *(
            field
            for prefix in _STATE_PREFIXES
            for field in (
                f"{prefix}_bits",
                f"{prefix}_bytes",
                f"{prefix}_encoding",
                f"{prefix}_hex",
                f"{prefix}_sha256",
            )
        ),
        *(
            field
            for prefix in _SEQUENCE_PREFIXES
            for field in (
                f"{prefix}_encoding",
                f"{prefix}_count",
                f"{prefix}_bytes",
                f"{prefix}_hex",
                f"{prefix}_sha256",
            )
        ),
    }
)
_READER_FIELDS = _STATIC_RANK_FIELDS | _POLICY_FIELDS | _RUNTIME_READER_FIELDS

# Public inherited mechanism surface.
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = (
    _v14.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = (
    _v14.JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = (
    _v14.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v14.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v14.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)
APPLE_VIEW_0009_GROUPING_SHA256 = _v14.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v14.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v14.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v14.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v14.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v14.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v14.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v14.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v14.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v14.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v14.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v14.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v14.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v14.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v14.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v14.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = (
    _v14.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
)
JOINT_SCORE_SIEVE_GROUPING_RULE = _v14.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v14.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v14.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = (
    _v14.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
)
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v14.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = (
    _v14.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
)
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = (
    _v14.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
)
JOINT_SCORE_SIEVE_STATE_ENCODING = _v14.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v14.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v14.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v14.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v14.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v14.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = (
    _v14.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
)
JointScoreCompatibilityGroup = _v14.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v14.JointScoreSieveExecutionError
JointScoreSieveResult = _v14.JointScoreSieveResult
JointScoreSieveV7Result = _v14.JointScoreSieveV7Result
JointScoreSieveV8Result = _v14.JointScoreSieveV8Result
JointScoreSieveV9Result = _v14.JointScoreSieveV9Result
JointScoreSieveV10Result = _v14.JointScoreSieveV10Result
JointScoreSieveV11Result = _v14.JointScoreSieveV11Result
JointScoreSieveV12Result = _v14.JointScoreSieveV12Result
JointScoreSieveV13Result = _v14.JointScoreSieveV13Result
JointScoreSieveV14Result = _v14.JointScoreSieveV14Result
build_compatibility_grouping = _v14.build_compatibility_grouping
build_native_joint_score_sieve = _v14.build_native_joint_score_sieve
derive_vault_soft_conflict_ledger = _v14.derive_vault_soft_conflict_ledger
derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
grouped_joint_score_cache = _v14.grouped_joint_score_cache
grouped_upper_bound_prunes = _v14.grouped_upper_bound_prunes
joint_score_complete = _v14.joint_score_complete
joint_score_upper_bound = _v14.joint_score_upper_bound
validate_incremental_conflict_ledger = _v14.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v14.validate_joint_score_sieve_grouping
validate_vault_soft_conflict_ledger = _v14.validate_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger
write_joint_score_sieve_grouping = _v14.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v14.write_joint_score_sieve_potential


@dataclass(frozen=True)
class JointScoreSieveV15Result(_v14.JointScoreSieveV14Result):
    """A v14-validated result with strict release-contrast telemetry."""

    @property
    def nonzero_events(self) -> tuple[VaultReleaseContrastReturnEvent, ...]:
        """Return the validated callback events as immutable typed records."""

        return _return_events(self.reader["nonzero_return_events"])

    @property
    def contrast_pairs(self) -> tuple[VaultReleaseContrastPairRecord, ...]:
        """Return the validated original/opposite causal pair records."""

        return _pair_records(self.reader["pair_records"])


def vault_release_contrast_policy_spec_bytes() -> bytes:
    """Return and self-check the canonical O1C73 contrast policy."""

    if (
        len(_RELEASE_CONTRAST_POLICY_SPEC)
        != VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES
        or hashlib.sha256(_RELEASE_CONTRAST_POLICY_SPEC).hexdigest()
        != VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 contrast policy specification differs"
        )
    return _RELEASE_CONTRAST_POLICY_SPEC


# Compatibility spelling used by the one-shot lineage runner.
vault_backtrack_release_policy_spec_bytes = vault_release_contrast_policy_spec_bytes


@dataclass(frozen=True)
class VaultReleaseContrastReturnEvent:
    """One bounded nonzero return in the actual callback timeline."""

    call: int
    kind: str
    rank_index: int
    literal: int
    next_callback_observed: bool
    assignment_burst_to_next_callback: int


@dataclass(frozen=True)
class VaultReleaseContrastPairRecord:
    """Causal lifecycle of one original literal and its opposite contrast."""

    rank_index: int
    variable: int
    original_literal: int
    contrast_literal: int
    original_return_call: int
    original_release_after_call: int | None
    original_release_level: int | None
    contrast_return_call: int | None
    contrast_release_after_call: int | None
    contrast_release_level: int | None


_NONZERO_RETURN_EVENT_FIELDS = frozenset(
    {
        "call",
        "kind",
        "rank_index",
        "literal",
        "next_callback_observed",
        "assignment_burst_to_next_callback",
    }
)
_PAIR_RECORD_FIELDS = frozenset(
    {
        "rank_index",
        "variable",
        "original_literal",
        "contrast_literal",
        "original_return_call",
        "original_release_after_call",
        "original_release_level",
        "contrast_return_call",
        "contrast_release_after_call",
        "contrast_release_level",
    }
)


def _integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {field.replace('_', ' ')} differs"
        )
    return value


def _positive_integer(value: object, *, field: str) -> int:
    result = _integer(value, field=field)
    if result < 1:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {field.replace('_', ' ')} differs"
        )
    return result


def _optional_integer(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return _integer(value, field=field)


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {field.replace('_', ' ')} differs"
        )
    return value


def _return_events(value: object) -> tuple[VaultReleaseContrastReturnEvent, ...]:
    if not isinstance(value, list):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 nonzero return events differ"
        )
    result: list[VaultReleaseContrastReturnEvent] = []
    for raw in value:
        event = _mapping(raw, field="nonzero_return_event")
        if set(event) != _NONZERO_RETURN_EVENT_FIELDS or event["kind"] not in {
            "original",
            "contrast",
        }:
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 nonzero return event fields differ"
            )
        next_callback_observed = event["next_callback_observed"]
        if not isinstance(next_callback_observed, bool):
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 return-event finalization differs"
            )
        literal = event["literal"]
        if (
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or not literal
            or literal == -(1 << 31)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 return-event literal differs"
            )
        result.append(
            VaultReleaseContrastReturnEvent(
                call=_positive_integer(
                    event["call"], field="return_event_call"
                ),
                kind=str(event["kind"]),
                rank_index=_integer(
                    event["rank_index"], field="return_event_rank_index"
                ),
                literal=literal,
                next_callback_observed=next_callback_observed,
                assignment_burst_to_next_callback=_integer(
                    event["assignment_burst_to_next_callback"],
                    field="assignment_burst_to_next_callback",
                ),
            )
        )
    return tuple(result)


def _pair_records(value: object) -> tuple[VaultReleaseContrastPairRecord, ...]:
    if not isinstance(value, list):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 pair records differ"
        )
    result: list[VaultReleaseContrastPairRecord] = []
    optional_names = (
        "original_release_after_call",
        "original_release_level",
        "contrast_return_call",
        "contrast_release_after_call",
        "contrast_release_level",
    )
    for raw in value:
        pair = _mapping(raw, field="pair_record")
        if set(pair) != _PAIR_RECORD_FIELDS:
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 pair-record fields differ"
            )
        original_literal = pair["original_literal"]
        contrast_literal = pair["contrast_literal"]
        if any(
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or not literal
            or literal == -(1 << 31)
            for literal in (original_literal, contrast_literal)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 pair-record literal differs"
            )
        original_literal = cast(int, original_literal)
        contrast_literal = cast(int, contrast_literal)
        optional = {
            name: _optional_integer(pair[name], field=f"pair_record_{name}")
            for name in optional_names
        }
        result.append(
            VaultReleaseContrastPairRecord(
                rank_index=_integer(pair["rank_index"], field="pair_rank_index"),
                variable=_positive_integer(pair["variable"], field="pair_variable"),
                original_literal=original_literal,
                contrast_literal=contrast_literal,
                original_return_call=_positive_integer(
                    pair["original_return_call"], field="pair_original_return_call"
                ),
                original_release_after_call=optional[
                    "original_release_after_call"
                ],
                original_release_level=optional["original_release_level"],
                contrast_return_call=optional["contrast_return_call"],
                contrast_release_after_call=optional[
                    "contrast_release_after_call"
                ],
                contrast_release_level=optional["contrast_release_level"],
            )
        )
    return tuple(result)


def _canonical_bytes(
    reader: Mapping[str, object], *, prefix: str, expected_length: int
) -> bytes:
    encoded = reader[f"{prefix}_hex"]
    digest = reader[f"{prefix}_sha256"]
    if not isinstance(encoded, str) or not isinstance(digest, str):
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {prefix.replace('_', ' ')} types differ"
        )
    try:
        payload = bytes.fromhex(encoded)
    except ValueError as exc:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {prefix.replace('_', ' ')} differs"
        ) from exc
    if (
        payload.hex() != encoded
        or len(payload) != expected_length
        or hashlib.sha256(payload).hexdigest() != digest
    ):
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 {prefix.replace('_', ' ')} differs"
        )
    return payload


def _i32_sequence(payload: bytes, *, field: str) -> tuple[int, ...]:
    if len(payload) % 4:
        raise O1RelationalSearchError(f"joint-score-sieve-v15 {field} length differs")
    return struct.unpack(f"<{len(payload) // 4}i", payload) if payload else ()


def _rank_mask(indices: tuple[int, ...]) -> bytes:
    mask = bytearray(_RANK_STATE_BYTES)
    for index in indices:
        if not 0 <= index < _RANK_STATE_BITS:
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 rank-state index differs"
            )
        mask[index // 8] |= 1 << (index % 8)
    return bytes(mask)


def _state_indices(payload: bytes) -> tuple[int, ...]:
    if len(payload) != _RANK_STATE_BYTES:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 rank-state length differs"
        )
    return tuple(
        index
        for index in range(_RANK_STATE_BITS)
        if payload[index // 8] & (1 << (index % 8))
    )


def _is_subsequence(values: tuple[int, ...], source: tuple[int, ...]) -> bool:
    cursor = iter(source)
    return all(any(candidate == value for candidate in cursor) for value in values)


def _reader_expected(decision: VaultRankedDecision) -> dict[str, object]:
    try:
        validated = validate_vault_ranked_decision(decision)
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 expected rank differs"
        ) from exc
    expected = validated.reader_binding()
    expected.pop("zero_delta_count")
    expected.pop("unobserved_nonzero_count")
    expected["schema"] = VAULT_RANKED_DECISION_READER_SCHEMA
    expected["operator"] = VAULT_RELEASE_CONTRAST_OPERATOR
    expected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    )
    expected["contrast_policy_spec_bytes"] = len(
        vault_release_contrast_policy_spec_bytes()
    )
    expected["contrast_policy_spec_sha256"] = (
        VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256
    )
    if set(expected) != _STATIC_RANK_FIELDS | _POLICY_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 rank binding fields differ"
        )
    return expected


def validate_vault_ranked_decision_reader(
    raw: object,
    *,
    expected_decision: VaultRankedDecision,
    require_active_contrast: bool = True,
) -> dict[str, object]:
    """Validate native-v12 rank identity and complete contrast causality."""

    if not isinstance(require_active_contrast, bool):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 active-contrast requirement differs"
        )
    reader = _mapping(raw, field="reader")
    if set(reader) != _READER_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v15 reader fields differ")
    expected = _reader_expected(expected_decision)
    static_integer_fields: set[str] = set(_v14._v13._STATIC_INTEGER_FIELDS)
    static_integer_fields.difference_update(
        {"zero_delta_count", "unobserved_nonzero_count"}
    )
    static_integer_fields.add("contrast_policy_spec_bytes")
    if any(
        isinstance(reader[name], bool) or not isinstance(reader[name], int)
        for name in static_integer_fields
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 reader static scalar types differ"
        )
    if any(reader[name] != value for name, value in expected.items()):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 reader rank, identity, or policy differs"
        )
    ranked_literals = reader["ranked_literals"]
    if (
        not isinstance(ranked_literals, list)
        or any(
            isinstance(literal, bool) or not isinstance(literal, int)
            for literal in ranked_literals
        )
        or expected_decision.key_variable_count != _RANK_STATE_BITS
        or not 0 < expected_decision.candidate_count <= _MAXIMUM_CANDIDATES
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 reader rank population differs"
        )
    if (
        reader["decision_rule"] != VAULT_RANKED_DECISION_DECISION_RULE
        or reader["callback_rule"] != VAULT_RANKED_DECISION_CALLBACK_RULE
        or reader["returned_sequence_encoding"]
        != VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        or reader["nonzero_event_rule"]
        != VAULT_RANKED_DECISION_NONZERO_EVENT_RULE
        or reader["pair_record_rule"] != VAULT_RANKED_DECISION_PAIR_RECORD_RULE
        or reader["bounded_state_rule"]
        != VAULT_RANKED_DECISION_BOUNDED_STATE_RULE
        or any(
            reader[f"{prefix}_encoding"]
            != VAULT_RANKED_DECISION_STATE_ENCODING
            for prefix in _STATE_PREFIXES
        )
        or any(
            reader[f"{prefix}_encoding"]
            != VAULT_RANKED_DECISION_SEQUENCE_ENCODING
            for prefix in _SEQUENCE_PREFIXES
        )
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 reader runtime contract differs"
        )
    _validate_runtime_causality(
        reader,
        expected_decision=expected_decision,
        require_active_contrast=require_active_contrast,
    )
    return {name: reader[name] for name in sorted(_READER_FIELDS)}


validate_vault_release_contrast_ranked_decision_reader = (
    validate_vault_ranked_decision_reader
)
validate_vault_backtrack_release_ranked_decision_reader = (
    validate_vault_ranked_decision_reader
)


def _validate_runtime_causality(
    reader: Mapping[str, object],
    *,
    expected_decision: VaultRankedDecision,
    require_active_contrast: bool,
) -> None:
    """Validate the bounded two-stage state and its real callback chronology."""

    integer_names = (
        "cursor",
        "rows_consumed",
        "original_once_returns",
        "skipped_preassigned",
        "released_original",
        "contrast_enqueued",
        "contrast_returns",
        "contrast_releases",
        "contrast_deferred_assigned",
        "paired_variables",
        "cb_decide_calls",
        "cb_decide_nonzero",
        "cb_decide_zero",
        "same_signed_redecisions",
        "variable_second_decisions",
        "solver_phase_calls",
        "queue_size",
        "maximum_queue_size",
        "assignment_literals_observed",
        "bounded_guidance_state_bytes",
        "live_guidance_state_bytes",
        "bounded_telemetry_state_bytes",
    )
    state_prefixes = _STATE_PREFIXES
    sequence_prefixes = _SEQUENCE_PREFIXES
    integers = {name: _integer(reader[name], field=name) for name in integer_names}
    for prefix in state_prefixes:
        integers[f"{prefix}_bits"] = _integer(
            reader[f"{prefix}_bits"], field=f"{prefix}_bits"
        )
        integers[f"{prefix}_bytes"] = _integer(
            reader[f"{prefix}_bytes"], field=f"{prefix}_bytes"
        )
    for prefix in sequence_prefixes:
        integers[f"{prefix}_count"] = _integer(
            reader[f"{prefix}_count"], field=f"{prefix}_count"
        )
        integers[f"{prefix}_bytes"] = _integer(
            reader[f"{prefix}_bytes"], field=f"{prefix}_bytes"
        )
    for name in ("returned_sequence_count", "returned_sequence_bytes"):
        integers[name] = _integer(reader[name], field=name)

    states = {
        prefix: _canonical_bytes(
            reader,
            prefix=prefix,
            expected_length=integers[f"{prefix}_bytes"],
        )
        for prefix in state_prefixes
    }
    sequence_payloads = {
        prefix: _canonical_bytes(
            reader,
            prefix=prefix,
            expected_length=integers[f"{prefix}_bytes"],
        )
        for prefix in sequence_prefixes
    }
    sequences = {
        prefix: _i32_sequence(payload, field=prefix.replace("_", " "))
        for prefix, payload in sequence_payloads.items()
    }
    events = _return_events(reader["nonzero_return_events"])
    pairs = _pair_records(reader["pair_records"])

    candidate_count = expected_decision.candidate_count
    ranked_literals = expected_decision.ranked_literals
    rank_by_original = {
        literal: index for index, literal in enumerate(ranked_literals)
    }
    rank_by_contrast = {
        -literal: index for index, literal in enumerate(ranked_literals)
    }
    try:
        original_return_indices = tuple(
            rank_by_original[literal]
            for literal in sequences["original_return_sequence"]
        )
        original_release_indices = tuple(
            rank_by_original[literal]
            for literal in sequences["original_release_sequence"]
        )
        contrast_return_indices = tuple(
            rank_by_contrast[literal]
            for literal in sequences["contrast_return_sequence"]
        )
        contrast_release_indices = tuple(
            rank_by_contrast[literal]
            for literal in sequences["contrast_release_sequence"]
        )
    except KeyError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 sequence literal is outside immutable rank"
        ) from exc

    cursor = integers["cursor"]
    original_returns = integers["original_once_returns"]
    released_original = integers["released_original"]
    contrast_enqueued = integers["contrast_enqueued"]
    contrast_returns = integers["contrast_returns"]
    contrast_releases = integers["contrast_releases"]
    calls = integers["cb_decide_calls"]
    nonzero = integers["cb_decide_nonzero"]
    zero = integers["cb_decide_zero"]
    queue_size = integers["queue_size"]
    maximum_queue_size = integers["maximum_queue_size"]

    if any(
        integers[f"{prefix}_bits"] != _RANK_STATE_BITS
        or integers[f"{prefix}_bytes"] != _RANK_STATE_BYTES
        for prefix in state_prefixes
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 rank-state scalar contract differs"
        )
    expected_counts = {
        "original_return_sequence": original_returns,
        "original_release_sequence": released_original,
        "contrast_return_sequence": contrast_returns,
        "contrast_release_sequence": contrast_releases,
    }
    if any(
        integers[f"{prefix}_count"] != expected_counts[prefix]
        or integers[f"{prefix}_bytes"] != 4 * expected_counts[prefix]
        or len(sequences[prefix]) != expected_counts[prefix]
        for prefix in sequence_prefixes
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 sequence scalar contract differs"
        )

    original_return_set = set(original_return_indices)
    original_release_set = set(original_release_indices)
    contrast_return_set = set(contrast_return_indices)
    contrast_release_set = set(contrast_release_indices)
    original_state_indices = _state_indices(states["original_returned_state"])
    original_released_state_indices = _state_indices(
        states["original_released_state"]
    )
    contrast_enqueued_state_indices = _state_indices(
        states["contrast_enqueued_state"]
    )
    contrast_returned_state_indices = _state_indices(
        states["contrast_returned_state"]
    )
    contrast_released_state_indices = _state_indices(
        states["contrast_released_state"]
    )
    contrast_deferred_state_indices = _state_indices(
        states["contrast_deferred_assigned_state"]
    )
    state_and_subset_valid = (
        cursor == integers["rows_consumed"]
        and cursor == original_returns + integers["skipped_preassigned"]
        and cursor <= candidate_count <= _MAXIMUM_CANDIDATES
        and _state_indices(states["consumed_state"]) == tuple(range(cursor))
        and len(original_return_indices) == len(original_return_set)
        and all(index < cursor for index in original_return_indices)
        and all(
            left < right
            for left, right in zip(
                original_return_indices, original_return_indices[1:]
            )
        )
        and len(original_release_indices) == len(original_release_set)
        and original_release_set.issubset(original_return_set)
        and len(contrast_return_indices) == len(contrast_return_set)
        and contrast_return_set.issubset(original_release_set)
        and len(contrast_release_indices) == len(contrast_release_set)
        and contrast_release_set.issubset(contrast_return_set)
        and original_state_indices == tuple(sorted(original_return_set))
        and original_released_state_indices
        == tuple(sorted(original_release_set))
        and contrast_enqueued_state_indices
        == tuple(sorted(original_release_set))
        and contrast_returned_state_indices == tuple(sorted(contrast_return_set))
        and contrast_released_state_indices
        == tuple(sorted(contrast_release_set))
        and len(contrast_deferred_state_indices)
        == integers["contrast_deferred_assigned"]
        and set(contrast_deferred_state_indices).issubset(original_release_set)
        and contrast_enqueued == released_original
    )
    if not state_and_subset_valid:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 release-contrast state subset differs"
        )

    first_parent = _optional_integer(
        reader["first_parent_fallback_call"], field="first_parent_fallback_call"
    )
    first_final = _optional_integer(
        reader["first_final_fallback_call"], field="first_final_fallback_call"
    )
    if first_parent == 0 or first_final == 0:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 fallback chronology differs"
        )
    callback_counts_valid = (
        calls == nonzero + zero
        and nonzero == original_returns + contrast_returns
        and integers["paired_variables"] == contrast_returns
        and integers["same_signed_redecisions"] == 0
        and integers["variable_second_decisions"] == contrast_returns
        and integers["solver_phase_calls"] == 0
        and contrast_returns <= contrast_enqueued <= _MAXIMUM_CANDIDATES
        and contrast_releases <= contrast_returns
        and queue_size == contrast_enqueued - contrast_returns
        and queue_size <= maximum_queue_size <= _MAXIMUM_CANDIDATES
    )
    if not callback_counts_valid:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 callback or queue counts differ"
        )
    parent_fallback_expected = cursor == candidate_count and calls > original_returns
    if (first_parent is not None) != parent_fallback_expected or (
        first_parent is not None and first_parent != original_returns + 1
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 parent fallback chronology differs"
        )
    if require_active_contrast and contrast_returns == 0:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 active contrast is required"
        )

    if (
        len(events) != nonzero
        or any(event.call > calls for event in events)
        or any(left.call >= right.call for left, right in zip(events, events[1:]))
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 nonzero return event chronology differs"
        )
    original_events = tuple(event for event in events if event.kind == "original")
    contrast_events = tuple(event for event in events if event.kind == "contrast")
    if (
        tuple(event.literal for event in original_events)
        != sequences["original_return_sequence"]
        or tuple(event.rank_index for event in original_events)
        != original_return_indices
        or tuple(event.literal for event in contrast_events)
        != sequences["contrast_return_sequence"]
        or tuple(event.rank_index for event in contrast_events)
        != contrast_return_indices
        or tuple(event.call for event in original_events)
        != tuple(range(1, original_returns + 1))
        or any(event.kind != "original" for event in events[:original_returns])
        or any(event.kind != "contrast" for event in events[original_returns:])
        or (
            contrast_events
            and (
                first_parent is None
                or cursor != candidate_count
                or contrast_events[0].call < first_parent
            )
        )
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 original/contrast event projection differs"
        )
    for event in events:
        finalized = event.call < calls
        if event.next_callback_observed != finalized or (
            finalized and event.assignment_burst_to_next_callback < 1
        ) or (
            not finalized and event.assignment_burst_to_next_callback != 0
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 return-event notification telemetry differs"
            )

    signed_literals = tuple(event.literal for event in events)
    variable_counts: dict[int, int] = {}
    for literal in signed_literals:
        variable_counts[abs(literal)] = variable_counts.get(abs(literal), 0) + 1
    if len(signed_literals) != len(set(signed_literals)) or any(
        count > 2 for count in variable_counts.values()
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 signed or variable decision multiplicity differs"
        )
    actual_encoding = reader["returned_sequence_encoding"]
    actual_digest = reader["returned_sequence_sha256"]
    actual_sequence = [0] * calls
    for event in events:
        actual_sequence[event.call - 1] = event.literal
    actual_payload = b"".join(struct.pack("<i", literal) for literal in actual_sequence)
    expected_first_final = next(
        (
            ordinal
            for ordinal, literal in enumerate(actual_sequence, start=1)
            if literal == 0
        ),
        None,
    )
    if (
        actual_encoding != VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        or integers["returned_sequence_count"] != calls
        or integers["returned_sequence_bytes"] != len(actual_payload)
        or not isinstance(actual_digest, str)
        or hashlib.sha256(actual_payload).hexdigest() != actual_digest
        or first_final != expected_first_final
        or integers["assignment_literals_observed"]
        < sum(event.assignment_burst_to_next_callback for event in events)
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 actual callback-return hash differs"
        )

    pair_by_index = {pair.rank_index: pair for pair in pairs}
    event_by_call = {event.call: event for event in events}
    if (
        len(pairs) != original_returns
        or len(pair_by_index) != len(pairs)
        or tuple(pair.rank_index for pair in pairs) != original_return_indices
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 pair-record population differs"
        )
    for pair in pairs:
        expected_original = ranked_literals[pair.rank_index]
        expected_contrast = -expected_original
        original_event = event_by_call.get(pair.original_return_call)
        release_values = (
            pair.original_release_after_call,
            pair.original_release_level,
        )
        contrast_release_values = (
            pair.contrast_release_after_call,
            pair.contrast_release_level,
        )
        is_released = pair.rank_index in original_release_set
        is_contrast_returned = pair.rank_index in contrast_return_set
        is_contrast_released = pair.rank_index in contrast_release_set
        if (
            pair.variable != abs(expected_original)
            or pair.original_literal != expected_original
            or pair.contrast_literal != expected_contrast
            or original_event is None
            or original_event.kind != "original"
            or original_event.rank_index != pair.rank_index
            or (all(value is not None for value in release_values) != is_released)
            or (any(value is not None for value in release_values) != is_released)
            or ((pair.contrast_return_call is not None) != is_contrast_returned)
            or (
                all(value is not None for value in contrast_release_values)
                != is_contrast_released
            )
            or (
                any(value is not None for value in contrast_release_values)
                != is_contrast_released
            )
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 pair-record identity or state differs"
            )
        if is_released:
            assert pair.original_release_after_call is not None
            if (
                pair.original_release_after_call < pair.original_return_call
                or pair.original_release_after_call > calls
            ):
                raise O1RelationalSearchError(
                    "joint-score-sieve-v15 original pair causality differs"
                )
        if is_contrast_returned:
            assert pair.contrast_return_call is not None
            contrast_event = event_by_call.get(pair.contrast_return_call)
            if (
                not is_released
                or pair.original_release_after_call is None
                or pair.contrast_return_call <= pair.original_release_after_call
                or contrast_event is None
                or contrast_event.kind != "contrast"
                or contrast_event.rank_index != pair.rank_index
                or contrast_event.literal != expected_contrast
            ):
                raise O1RelationalSearchError(
                    "joint-score-sieve-v15 contrast pair causality differs"
                )
        if is_contrast_released:
            assert pair.contrast_return_call is not None
            assert pair.contrast_release_after_call is not None
            if (
                pair.contrast_release_after_call < pair.contrast_return_call
                or pair.contrast_release_after_call > calls
            ):
                raise O1RelationalSearchError(
                    "joint-score-sieve-v15 contrast-release pair causality differs"
                )

    released_pairs = tuple(pair_by_index[index] for index in original_release_indices)
    contrast_released_pairs = tuple(
        pair_by_index[index] for index in contrast_release_indices
    )
    release_after_calls = tuple(
        pair.original_release_after_call for pair in released_pairs
    )
    contrast_release_after_calls = tuple(
        pair.contrast_release_after_call for pair in contrast_released_pairs
    )
    if (
        any(
            left is None or right is None or left > right
            for left, right in zip(release_after_calls, release_after_calls[1:])
        )
        or any(
            left is None or right is None or left > right
            for left, right in zip(
                contrast_release_after_calls, contrast_release_after_calls[1:]
            )
        )
        or not _is_subsequence(contrast_return_indices, original_release_indices)
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 release queue or pair chronology differs"
        )

    releases_after_call: dict[int, int] = {}
    for pair in released_pairs:
        assert pair.original_release_after_call is not None
        releases_after_call[pair.original_release_after_call] = (
            releases_after_call.get(pair.original_release_after_call, 0) + 1
        )
    contrast_calls = {event.call for event in contrast_events}
    simulated_queue = 0
    simulated_maximum = 0
    for call in range(1, calls + 1):
        if call in contrast_calls:
            if simulated_queue == 0:
                raise O1RelationalSearchError(
                    "joint-score-sieve-v15 contrast returned before enqueue"
                )
            simulated_queue -= 1
        simulated_queue += releases_after_call.get(call, 0)
        simulated_maximum = max(simulated_maximum, simulated_queue)
    expected_live = 4 + 6 * _RANK_STATE_BYTES + 2 * released_original
    if (
        simulated_queue != queue_size
        or simulated_maximum != maximum_queue_size
        or integers["bounded_guidance_state_bytes"]
        != _BOUNDED_GUIDANCE_STATE_BYTES
        or integers["live_guidance_state_bytes"] != expected_live
        or integers["live_guidance_state_bytes"]
        > integers["bounded_guidance_state_bytes"]
        or integers["bounded_telemetry_state_bytes"]
        != _BOUNDED_TELEMETRY_STATE_BYTES
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 bounded guidance state differs"
        )


def _v14_reader(
    reader: Mapping[str, object], decision: VaultRankedDecision
) -> dict[str, object]:
    """Build the frozen original-only lineage view consumed by v14."""

    expected = _v14._reader_expected(decision)
    original_payload = bytes.fromhex(str(reader["original_return_sequence_hex"]))
    release_payload = bytes.fromhex(str(reader["original_release_sequence_hex"]))
    original_returns = _integer(
        reader["original_once_returns"], field="original_once_returns"
    )
    calls = _integer(reader["cb_decide_calls"], field="cb_decide_calls")
    synthetic_zero = calls - original_returns
    returned_payload = original_payload + b"\0\0\0\0" * synthetic_zero
    return {
        **expected,
        "decision_rule": _v14.VAULT_RANKED_DECISION_DECISION_RULE,
        "callback_rule": _v14.VAULT_RANKED_DECISION_CALLBACK_RULE,
        "cursor": reader["cursor"],
        "rows_consumed": reader["rows_consumed"],
        "once_returns": original_returns,
        "skipped_preassigned": reader["skipped_preassigned"],
        "consumed_state_bits": reader["consumed_state_bits"],
        "consumed_state_bytes": reader["consumed_state_bytes"],
        "consumed_state_encoding": _v14.VAULT_RANKED_DECISION_STATE_ENCODING,
        "consumed_state_hex": reader["consumed_state_hex"],
        "consumed_state_sha256": reader["consumed_state_sha256"],
        "returned_state_bits": reader["original_returned_state_bits"],
        "returned_state_bytes": reader["original_returned_state_bytes"],
        "returned_state_encoding": _v14.VAULT_RANKED_DECISION_STATE_ENCODING,
        "returned_state_hex": reader["original_returned_state_hex"],
        "returned_state_sha256": reader["original_returned_state_sha256"],
        "released_state_bits": reader["original_released_state_bits"],
        "released_state_bytes": reader["original_released_state_bytes"],
        "released_state_encoding": _v14.VAULT_RANKED_DECISION_STATE_ENCODING,
        "released_state_hex": reader["original_released_state_hex"],
        "released_state_sha256": reader["original_released_state_sha256"],
        "once_return_sequence_encoding": (
            _v14.VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING
        ),
        "once_return_sequence_count": original_returns,
        "once_return_sequence_bytes": len(original_payload),
        "once_return_sequence_hex": original_payload.hex(),
        "once_return_sequence_sha256": hashlib.sha256(original_payload).hexdigest(),
        "released_guided": reader["released_original"],
        "guided_release_sequence_encoding": (
            _v14.VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING
        ),
        "guided_release_sequence_count": reader["released_original"],
        "guided_release_sequence_bytes": len(release_payload),
        "guided_release_sequence_hex": release_payload.hex(),
        "guided_release_sequence_sha256": hashlib.sha256(release_payload).hexdigest(),
        "cb_decide_calls": calls,
        "cb_decide_nonzero": original_returns,
        "cb_decide_zero": synthetic_zero,
        "returned_sequence_encoding": (
            _v14.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        ),
        "returned_sequence_count": calls,
        "returned_sequence_bytes": len(returned_payload),
        "returned_sequence_hex": returned_payload.hex(),
        "returned_sequence_sha256": hashlib.sha256(returned_payload).hexdigest(),
        "unique_returned_variables": original_returns,
        "redecisions": 0,
        "first_fallback_call": original_returns + 1 if synthetic_zero else None,
        "solver_phase_calls": 0,
        "bounded_state_rule": _v14.VAULT_RANKED_DECISION_BOUNDED_STATE_RULE,
        "bounded_guidance_state_bytes": (
            4 + 3 * _RANK_STATE_BYTES + 8 * decision.candidate_count
        ),
        "live_guidance_state_bytes": (
            4 + 3 * _RANK_STATE_BYTES + len(original_payload) + len(release_payload)
        ),
    }


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v12 lifecycle provenance through frozen v14 rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 lifecycle contract differs"
        )
    return _v14.validate_native_lifecycle(payload)


def _promote_result(
    result: _v14.JointScoreSieveV14Result,
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
) -> JointScoreSieveV15Result:
    return JointScoreSieveV15Result(
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
        reader=dict(reader),
    )


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
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
) -> JointScoreSieveV15Result:
    """Validate native-v12 telemetry before frozen v14 normalization."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v15 result fields differ")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["implementation_parent_schema"]
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload["implementation_release_parent_schema"]
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed != 0
        or isinstance(payload["seed"], bool)
        or not isinstance(payload["seed"], int)
        or payload["seed"] != 0
    ):
        raise O1RelationalSearchError("joint-score-sieve-v15 result contract differs")
    reader = validate_vault_ranked_decision_reader(
        payload["reader"],
        expected_decision=expected_decision,
        require_active_contrast=require_active_contrast,
    )
    sieve = payload["sieve"]
    if (
        not isinstance(sieve, Mapping)
        or sieve.get("cb_decide_calls") != reader["cb_decide_calls"]
        or sieve.get("cb_decide_nonzero") != 0
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 base and outer callback accounting differs"
        )

    parent_payload = dict(payload)
    parent_payload.pop("implementation_release_parent_schema")
    parent_payload["schema"] = _v14.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v14.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    parent_payload["reader"] = _v14_reader(reader, expected_decision)
    try:
        parent = _v14._parse_native_payload(
            parent_payload,
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
            expected_decision=expected_decision,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 native payload validation failed"
        ) from exc
    return _promote_result(parent, raw=payload, reader=reader)


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
) -> JointScoreSieveV15Result:
    """Run sealed native v12 through the strict v15 process boundary."""

    requested = _v14._v13._v12._v11._v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v15 native vault caps differ")
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
        or (
            memory_limit_bytes is not None
            and (
                isinstance(memory_limit_bytes, bool)
                or not isinstance(memory_limit_bytes, int)
                or memory_limit_bytes <= 0
            )
        )
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = (
        _v14._v13._v12._v11._v9._v8._v1._read_input(executable, "executable")
    )
    cnf, cnf_bytes, cnf_sha = _v14._v13._v12._v11._v9._v8._v1._read_input(
        cnf_path, "CNF"
    )
    potential_file, potential_bytes, potential_sha = (
        _v14._v13._v12._v11._v9._v8._v1._read_input(
            potential_path, "potential"
        )
    )
    grouping_file, grouping_bytes, grouping_sha = (
        _v14._v13._v12._v11._v9._v8._v1._read_input(grouping_path, "grouping")
    )
    vault_file, vault_bytes = (
        _v14._v13._v12._v11._v9._v8._read_bounded_vault_input(
            vault_path, caps=vault_caps
        )
    )
    field = _v14._v13._v12._v11._v9._v8._v1._potential(potential_bytes)
    grouping = _v14._v13._v12._v11._v9._v8._v7.validate_joint_score_sieve_grouping(
        field, grouping_bytes
    )
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 grouping potential identity differs"
        )
    try:
        expected_decision = derive_production_vault_ranked_decision(
            vault_bytes, potential_bytes, grouping_bytes
        )
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 sealed ranked decision differs"
        ) from exc
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
            bound_rule=JOINT_SCORE_SIEVE_BOUND_RULE,
            threshold=requested_threshold,
        )
        validate_threshold_no_good_vault_identity(
            input_vault, expected=expected_identity
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 input vault differs"
        ) from exc
    try:
        _v14._v13._v12._v11._v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 input vault certification differs"
        ) from exc

    rank_path, rank_bytes = _v14._v13._rank_table_temp(expected_decision)
    command = [
        str(executable_file),
        "--cnf",
        str(cnf),
        "--potential",
        str(potential_file),
        "--grouping",
        str(grouping_file),
        "--vault-in",
        str(vault_file),
        "--rank-table",
        str(rank_path),
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: _v14._v13._v12._v11._v9._v8._v7._NativeExecution | None
    try:
        try:
            execution = _v14._v13._v12._v11._v9._v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
            execution = None
        try:
            _v14._v13._v12._v11._v9._v8._v1._verify_stable_input(
                executable, executable_file, executable_bytes, field="executable"
            )
            _v14._v13._v12._v11._v9._v8._v1._verify_stable_input(
                cnf_path, cnf, cnf_bytes, field="CNF"
            )
            _v14._v13._v12._v11._v9._v8._v1._verify_stable_input(
                potential_path,
                potential_file,
                potential_bytes,
                field="potential",
            )
            _v14._v13._v12._v11._v9._v8._v1._verify_stable_input(
                grouping_path,
                grouping_file,
                grouping_bytes,
                field="grouping",
            )
            _v14._v13._v12._v11._v9._v8._verify_stable_vault_input(
                vault_path, vault_file, vault_bytes, caps=vault_caps
            )
            if rank_path.read_bytes() != rank_bytes:
                raise O1RelationalSearchError(
                    "joint-score-sieve-v15 rank table changed during execution"
                )
        except Exception as exc:
            if execution is not None:
                _v14._v13._v12._v11._v9._attach_native_process_evidence(
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
            raise O1RelationalSearchError(
                "joint-score-sieve-v15 rank table cleanup failed"
            ) from exc
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v15 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v14._v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v15 execution failed: {detail}"
        ) from failure

    try:
        payload = json.loads(completed.stdout)
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
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=execution.memory_samples,
            expected_decision=expected_decision,
            require_active_contrast=require_active_contrast,
        )
        return replace(
            result,
            stats=derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v14._v13._v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v15 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v14._v13._v12._v11._v9._attach_native_process_evidence(
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
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
) -> JointScoreSieveV15Result:
    """Run native v12 while retaining v14's bounded failure evidence."""

    started = time.perf_counter()
    try:
        return _run_joint_score_sieve_native_contract(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
            vault_path=vault_path,
            vault_caps=vault_caps,
            threshold=threshold,
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
            require_active_contrast=require_active_contrast,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v14._v13._v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v15"):
            message = f"joint-score-sieve-v15 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [  # pyright: ignore[reportUnsupportedDunderAll]
    *_v14.__all__,
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JointScoreSieveV15Result",
    "O1C66_VAULT_CAPS",
    "PRODUCTION_CANDIDATE_COUNT",
    "PRODUCTION_ORDER_BYTES",
    "PRODUCTION_ORDER_SHA256",
    "PRODUCTION_RANK_TABLE_BYTES",
    "PRODUCTION_RANK_TABLE_SHA256",
    "ThresholdNoGoodClause",
    "ThresholdNoGoodVault",
    "VAULT_BACKTRACK_RELEASE_POLICY_SCHEMA",
    "VAULT_BACKTRACK_RELEASE_POLICY_SPEC_BYTES",
    "VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256",
    "VAULT_RANKED_DECISION_BOUND_RULE",
    "VAULT_RANKED_DECISION_BOUNDED_STATE_RULE",
    "VAULT_RANKED_DECISION_CALLBACK_RULE",
    "VAULT_RANKED_DECISION_DECISION_RULE",
    "VAULT_RANKED_DECISION_GAP_RULE",
    "VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_LITERAL_RULE",
    "VAULT_RANKED_DECISION_NONZERO_EVENT_RULE",
    "VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_OPERATOR",
    "VAULT_RANKED_DECISION_ORDER_ENCODING",
    "VAULT_RANKED_DECISION_PAIR_RECORD_RULE",
    "VAULT_RANKED_DECISION_READER_SCHEMA",
    "VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_SORT_RULE",
    "VAULT_RANKED_DECISION_SPEC_SHA256",
    "VAULT_RANKED_DECISION_STATE_ENCODING",
    "VAULT_RANKED_DECISION_TABLE_ENCODING",
    "VAULT_RANKED_DECISION_VOTE_RULE",
    "VAULT_RELEASE_CONTRAST_OPERATOR",
    "VAULT_RELEASE_CONTRAST_POLICY_SCHEMA",
    "VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES",
    "VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256",
    "VaultCaps",
    "VaultRankedDecision",
    "VaultReleaseContrastPairRecord",
    "VaultReleaseContrastReturnEvent",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
    "validate_vault_backtrack_release_ranked_decision_reader",
    "validate_vault_ranked_decision_reader",
    "validate_vault_release_contrast_ranked_decision_reader",
    "vault_backtrack_release_policy_spec_bytes",
    "vault_ranked_decision_spec_bytes",
    "vault_release_contrast_policy_spec_bytes",
]
