"""Strict one-shot backtrack-release adapter for native joint sieve v11.

The adapter independently rebuilds the sealed O1C71 rank through v13, binds a
separate immutable release-policy specification, and validates the complete
monotone-cursor state machine before projecting the remaining payload through
the unchanged v13/v12 validation stack.
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
from typing import Mapping

from . import joint_score_sieve_v13 as _v13
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v14-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v11"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)

VAULT_RANKED_DECISION_READER_SCHEMA = (
    "o1-256-cadical-vault-backtrack-release-ranked-decision-reader-v1"
)
VAULT_BACKTRACK_RELEASE_POLICY_SCHEMA = (
    "o1-vault-backtrack-release-ranked-decision-reader-v1"
)
VAULT_BACKTRACK_RELEASE_POLICY_SPEC_BYTES = 540
VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256 = (
    "bfa752664e19d5899d114ee8cf75dd15a52a8306ff2399fde046a5bb6ebdc132"
)
VAULT_RANKED_DECISION_DECISION_RULE = (
    "immutable-rank-monotone-consume;return-each-ranked-literal-at-most-once;"
    "assigned-before-opportunity-consumed;zero-after-none"
)
VAULT_RANKED_DECISION_CALLBACK_RULE = (
    "reuse-v6-assignment-backtrack-state;scan-from-monotone-rank-cursor;"
    "consume-assigned-ranked-rows;consume-before-nonzero-return;"
    "never-unconsume-on-backtrack;zero-delegates-to-solver"
)
VAULT_RANKED_DECISION_STATE_ENCODING = "rank-index-bitset-lsb-first-32-bytes"
VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING = (
    "callback-nonzero-return-order-concatenated-signed-i32le"
)
VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING = (
    "backtrack-callback-order;within-callback-immutable-rank-order;"
    "concatenated-signed-i32le"
)
VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING = (
    "cb-decide-return-order-concatenated-signed-i32le-including-zero"
)
VAULT_RANKED_DECISION_BOUNDED_STATE_RULE = (
    "u32le-monotone-cursor;three-256-bit-rank-index-bitsets;"
    "at-most-rank-rows-once-return-and-guided-release-i32le-sequences;"
    "independent-of-callback-count"
)

_RELEASE_POLICY_SPEC = (
    b"o1-vault-backtrack-release-ranked-decision-reader-v1\n"
    b"rank-spec-sha256="
    b"974d0f915ef827ecaa453f795a649f78b72bd38be7f413c8eb2c104de58e4543\n"
    b"rank-order=immutable\n"
    b"cursor=monotone-rank-index;consume-before-return-or-skip\n"
    b"assigned-row=consume-and-skip-permanently\n"
    b"unassigned-row=consume-and-return-signed-rank-literal-at-most-once\n"
    b"backtrack=never-decrement-cursor;released-guided-literal-never-reasserted\n"
    b"fallback=zero-after-rank-exhaustion\n"
    b"phase-calls=0\n"
    b"state=u32le-cursor;three-256-bit-rank-index-bitsets;"
    b"bounded-once-return-and-release-sequences\n"
)

_STATIC_RANK_FIELDS = _v13._STATIC_READER_FIELDS
_POLICY_FIELDS = frozenset({"release_policy_spec_bytes", "release_policy_spec_sha256"})
_RUNTIME_READER_FIELDS = frozenset(
    {
        "decision_rule",
        "callback_rule",
        "cursor",
        "rows_consumed",
        "once_returns",
        "skipped_preassigned",
        "consumed_state_bits",
        "consumed_state_bytes",
        "consumed_state_encoding",
        "consumed_state_hex",
        "consumed_state_sha256",
        "returned_state_bits",
        "returned_state_bytes",
        "returned_state_encoding",
        "returned_state_hex",
        "returned_state_sha256",
        "released_state_bits",
        "released_state_bytes",
        "released_state_encoding",
        "released_state_hex",
        "released_state_sha256",
        "once_return_sequence_encoding",
        "once_return_sequence_count",
        "once_return_sequence_bytes",
        "once_return_sequence_hex",
        "once_return_sequence_sha256",
        "released_guided",
        "guided_release_sequence_encoding",
        "guided_release_sequence_count",
        "guided_release_sequence_bytes",
        "guided_release_sequence_hex",
        "guided_release_sequence_sha256",
        "cb_decide_calls",
        "cb_decide_nonzero",
        "cb_decide_zero",
        "returned_sequence_encoding",
        "returned_sequence_count",
        "returned_sequence_bytes",
        "returned_sequence_hex",
        "returned_sequence_sha256",
        "unique_returned_variables",
        "redecisions",
        "first_fallback_call",
        "solver_phase_calls",
        "bounded_state_rule",
        "bounded_guidance_state_bytes",
        "live_guidance_state_bytes",
    }
)
_READER_FIELDS = _STATIC_RANK_FIELDS | _POLICY_FIELDS | _RUNTIME_READER_FIELDS
_RUNTIME_INTEGER_FIELDS = (
    "cursor",
    "rows_consumed",
    "once_returns",
    "skipped_preassigned",
    "consumed_state_bits",
    "consumed_state_bytes",
    "returned_state_bits",
    "returned_state_bytes",
    "released_state_bits",
    "released_state_bytes",
    "once_return_sequence_count",
    "once_return_sequence_bytes",
    "released_guided",
    "guided_release_sequence_count",
    "guided_release_sequence_bytes",
    "cb_decide_calls",
    "cb_decide_nonzero",
    "cb_decide_zero",
    "returned_sequence_count",
    "returned_sequence_bytes",
    "unique_returned_variables",
    "redecisions",
    "solver_phase_calls",
    "bounded_guidance_state_bytes",
    "live_guidance_state_bytes",
)
_TOP_LEVEL_FIELDS = _v13._TOP_LEVEL_FIELDS
_RANK_STATE_BITS = 256
_RANK_STATE_BYTES = 32
_MAXIMUM_CANDIDATES = 255

# Public inherited mechanism surface.
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = _v13.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = (
    _v13.JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = _v13.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v13.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v13.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)
APPLE_VIEW_0009_GROUPING_SHA256 = _v13.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v13.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v13.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v13.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v13.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v13.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v13.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v13.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v13.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v13.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v13.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v13.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v13.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v13.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v13.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v13.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v13.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v13.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v13.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v13.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v13.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v13.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v13.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v13.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v13.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v13.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v13.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v13.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v13.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v13.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = _v13.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
JointScoreCompatibilityGroup = _v13.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v13.JointScoreSieveExecutionError
JointScoreSieveResult = _v13.JointScoreSieveResult
JointScoreSieveV7Result = _v13.JointScoreSieveV7Result
JointScoreSieveV8Result = _v13.JointScoreSieveV8Result
JointScoreSieveV9Result = _v13.JointScoreSieveV9Result
JointScoreSieveV10Result = _v13.JointScoreSieveV10Result
JointScoreSieveV11Result = _v13.JointScoreSieveV11Result
JointScoreSieveV12Result = _v13.JointScoreSieveV12Result
JointScoreSieveV13Result = _v13.JointScoreSieveV13Result
build_compatibility_grouping = _v13.build_compatibility_grouping
build_native_joint_score_sieve = _v13.build_native_joint_score_sieve
derive_vault_soft_conflict_ledger = _v13.derive_vault_soft_conflict_ledger
derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
grouped_joint_score_cache = _v13.grouped_joint_score_cache
grouped_upper_bound_prunes = _v13.grouped_upper_bound_prunes
joint_score_complete = _v13.joint_score_complete
joint_score_upper_bound = _v13.joint_score_upper_bound
validate_incremental_conflict_ledger = _v13.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v13.validate_joint_score_sieve_grouping
validate_vault_soft_conflict_ledger = _v13.validate_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger
write_joint_score_sieve_grouping = _v13.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v13.write_joint_score_sieve_potential


@dataclass(frozen=True)
class JointScoreSieveV14Result(_v13.JointScoreSieveV13Result):
    """A v13-validated result plus one-shot release telemetry."""


def vault_backtrack_release_policy_spec_bytes() -> bytes:
    """Return and self-check the canonical release-policy specification."""

    if (
        len(_RELEASE_POLICY_SPEC) != VAULT_BACKTRACK_RELEASE_POLICY_SPEC_BYTES
        or hashlib.sha256(_RELEASE_POLICY_SPEC).hexdigest()
        != VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 release policy specification differs"
        )
    return _RELEASE_POLICY_SPEC


def _reader_expected(decision: VaultRankedDecision) -> dict[str, object]:
    try:
        validated = validate_vault_ranked_decision(decision)
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 expected rank differs"
        ) from exc
    expected = validated.reader_binding()
    if set(expected) != _STATIC_RANK_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 rank binding fields differ"
        )
    expected["schema"] = VAULT_RANKED_DECISION_READER_SCHEMA
    expected["release_policy_spec_bytes"] = len(
        vault_backtrack_release_policy_spec_bytes()
    )
    expected["release_policy_spec_sha256"] = VAULT_BACKTRACK_RELEASE_POLICY_SPEC_SHA256
    return expected


def _runtime_integers(reader: Mapping[str, object]) -> dict[str, int]:
    result: dict[str, int] = {}
    for name in _RUNTIME_INTEGER_FIELDS:
        value = reader[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                "joint-score-sieve-v14 reader runtime scalar types differ"
            )
        result[name] = value
    return result


def _canonical_bytes(
    reader: Mapping[str, object], *, prefix: str, expected_length: int
) -> bytes:
    encoded = reader[f"{prefix}_hex"]
    digest = reader[f"{prefix}_sha256"]
    if not isinstance(encoded, str) or not isinstance(digest, str):
        raise O1RelationalSearchError(
            f"joint-score-sieve-v14 {prefix.replace('_', ' ')} types differ"
        )
    try:
        payload = bytes.fromhex(encoded)
    except ValueError as exc:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v14 {prefix.replace('_', ' ')} differs"
        ) from exc
    if (
        payload.hex() != encoded
        or len(payload) != expected_length
        or hashlib.sha256(payload).hexdigest() != digest
    ):
        raise O1RelationalSearchError(
            f"joint-score-sieve-v14 {prefix.replace('_', ' ')} differs"
        )
    return payload


def _i32_sequence(payload: bytes, *, field: str) -> tuple[int, ...]:
    if len(payload) % 4:
        raise O1RelationalSearchError(f"joint-score-sieve-v14 {field} length differs")
    return struct.unpack(f"<{len(payload) // 4}i", payload) if payload else ()


def _rank_mask(indices: tuple[int, ...]) -> bytes:
    mask = bytearray(_RANK_STATE_BYTES)
    for index in indices:
        if not 0 <= index < _RANK_STATE_BITS:
            raise O1RelationalSearchError(
                "joint-score-sieve-v14 rank-state index differs"
            )
        mask[index // 8] |= 1 << (index % 8)
    return bytes(mask)


def validate_vault_ranked_decision_reader(
    raw: object, *, expected_decision: VaultRankedDecision
) -> dict[str, object]:
    """Validate the immutable rank and complete one-shot release state machine."""

    reader = _v13._v12._v11._v9._v8._v1._mapping(raw, "reader")
    if set(reader) != _READER_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v14 reader fields differ")
    expected = _reader_expected(expected_decision)
    if any(
        isinstance(reader[name], bool) or not isinstance(reader[name], int)
        for name in (*_v13._STATIC_INTEGER_FIELDS, "release_policy_spec_bytes")
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader static scalar types differ"
        )
    if any(reader[name] != value for name, value in expected.items()):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader rank or release-policy contract differs"
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
            "joint-score-sieve-v14 reader rank population differs"
        )
    integers = _runtime_integers(reader)
    if (
        reader["decision_rule"] != VAULT_RANKED_DECISION_DECISION_RULE
        or reader["callback_rule"] != VAULT_RANKED_DECISION_CALLBACK_RULE
        or reader["consumed_state_encoding"] != VAULT_RANKED_DECISION_STATE_ENCODING
        or reader["returned_state_encoding"] != VAULT_RANKED_DECISION_STATE_ENCODING
        or reader["released_state_encoding"] != VAULT_RANKED_DECISION_STATE_ENCODING
        or reader["once_return_sequence_encoding"]
        != VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING
        or reader["guided_release_sequence_encoding"]
        != VAULT_RANKED_DECISION_GUIDED_RELEASE_SEQUENCE_ENCODING
        or reader["returned_sequence_encoding"]
        != VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        or reader["bounded_state_rule"] != VAULT_RANKED_DECISION_BOUNDED_STATE_RULE
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader release-policy runtime contract differs"
        )

    first_fallback = reader["first_fallback_call"]
    if first_fallback is not None and (
        isinstance(first_fallback, bool)
        or not isinstance(first_fallback, int)
        or first_fallback < 1
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader first fallback differs"
        )

    cursor = integers["cursor"]
    consumed = integers["rows_consumed"]
    returned_once = integers["once_returns"]
    skipped = integers["skipped_preassigned"]
    calls = integers["cb_decide_calls"]
    nonzero = integers["cb_decide_nonzero"]
    zero = integers["cb_decide_zero"]
    released = integers["released_guided"]
    candidate_count = expected_decision.candidate_count

    consumed_state = _canonical_bytes(
        reader, prefix="consumed_state", expected_length=_RANK_STATE_BYTES
    )
    returned_state = _canonical_bytes(
        reader, prefix="returned_state", expected_length=_RANK_STATE_BYTES
    )
    released_state = _canonical_bytes(
        reader, prefix="released_state", expected_length=_RANK_STATE_BYTES
    )
    once_payload = _canonical_bytes(
        reader,
        prefix="once_return_sequence",
        expected_length=integers["once_return_sequence_bytes"],
    )
    guided_payload = _canonical_bytes(
        reader,
        prefix="guided_release_sequence",
        expected_length=integers["guided_release_sequence_bytes"],
    )
    returned_payload = _canonical_bytes(
        reader,
        prefix="returned_sequence",
        expected_length=integers["returned_sequence_bytes"],
    )
    once_returns = _i32_sequence(once_payload, field="once-return sequence")
    guided_releases = _i32_sequence(guided_payload, field="guided-release sequence")
    callback_returns = _i32_sequence(returned_payload, field="callback-return sequence")

    rank_index = {
        literal: index
        for index, literal in enumerate(expected_decision.ranked_literals)
    }
    try:
        returned_indices = tuple(rank_index[literal] for literal in once_returns)
        released_indices = tuple(rank_index[literal] for literal in guided_releases)
    except KeyError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 returned literal is outside immutable rank"
        ) from exc
    expected_consumed_state = _rank_mask(tuple(range(cursor)))
    expected_returned_state = _rank_mask(returned_indices)
    expected_released_state = _rank_mask(tuple(sorted(released_indices)))

    state_scalars_valid = (
        integers["consumed_state_bits"] == _RANK_STATE_BITS
        and integers["consumed_state_bytes"] == _RANK_STATE_BYTES
        and integers["returned_state_bits"] == _RANK_STATE_BITS
        and integers["returned_state_bytes"] == _RANK_STATE_BYTES
        and integers["released_state_bits"] == _RANK_STATE_BITS
        and integers["released_state_bytes"] == _RANK_STATE_BYTES
    )
    sequence_scalars_valid = (
        integers["once_return_sequence_count"] == returned_once
        and integers["once_return_sequence_bytes"] == 4 * returned_once
        and integers["guided_release_sequence_count"] == released
        and integers["guided_release_sequence_bytes"] == 4 * released
        and integers["returned_sequence_count"] == calls
        and integers["returned_sequence_bytes"] == 4 * calls
    )
    strictly_in_order = (
        len(returned_indices) == len(set(returned_indices))
        and all(index < cursor for index in returned_indices)
        and all(
            left < right for left, right in zip(returned_indices, returned_indices[1:])
        )
    )
    released_subset = len(released_indices) == len(set(released_indices)) and set(
        released_indices
    ).issubset(returned_indices)
    fallback_valid = (zero == 0 and first_fallback is None) or (
        zero > 0 and first_fallback == returned_once + 1 and cursor == candidate_count
    )
    callback_sequence_valid = (
        len(callback_returns) == returned_once + zero
        and callback_returns[:returned_once] == once_returns
        and all(literal == 0 for literal in callback_returns[returned_once:])
    )
    expected_bounded_bytes = 4 + 3 * _RANK_STATE_BYTES + 8 * candidate_count
    expected_live_bytes = (
        4 + 3 * _RANK_STATE_BYTES + len(once_payload) + len(guided_payload)
    )

    if not (
        state_scalars_valid
        and sequence_scalars_valid
        and cursor == consumed
        and consumed == returned_once + skipped
        and consumed <= candidate_count <= _MAXIMUM_CANDIDATES
        and calls == nonzero + zero
        and nonzero == returned_once == len(once_returns)
        and integers["unique_returned_variables"] == returned_once
        and integers["redecisions"] == 0
        and integers["solver_phase_calls"] == 0
        and strictly_in_order
        and released == len(guided_releases)
        and released_subset
        and fallback_valid
        and callback_sequence_valid
        and consumed_state == expected_consumed_state
        and returned_state == expected_returned_state
        and released_state == expected_released_state
        and integers["bounded_guidance_state_bytes"] == expected_bounded_bytes
        and integers["live_guidance_state_bytes"] == expected_live_bytes
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader one-shot telemetry differs"
        )
    return {name: reader[name] for name in sorted(_READER_FIELDS)}


validate_vault_backtrack_release_ranked_decision_reader = (
    validate_vault_ranked_decision_reader
)


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v11 lifecycle provenance through unchanged v13 rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 lifecycle contract differs"
        )
    return _v13.validate_native_lifecycle(payload)


def _v13_reader(
    reader: Mapping[str, object], decision: VaultRankedDecision
) -> dict[str, object]:
    """Project validated v14 telemetry onto v13's frozen parent reader."""

    expected = _v13._reader_expected(decision)
    return {
        **expected,
        "decision_rule": _v13.VAULT_RANKED_DECISION_DECISION_RULE,
        "callback_rule": _v13.VAULT_RANKED_DECISION_CALLBACK_RULE,
        "cb_decide_calls": reader["cb_decide_calls"],
        "cb_decide_nonzero": reader["cb_decide_nonzero"],
        "cb_decide_zero": reader["cb_decide_zero"],
        "returned_sequence_encoding": (
            _v13.VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        ),
        "returned_sequence_count": reader["returned_sequence_count"],
        "returned_sequence_bytes": reader["returned_sequence_bytes"],
        "returned_sequence_hex": reader["returned_sequence_hex"],
        "returned_sequence_sha256": reader["returned_sequence_sha256"],
        "unique_returned_variables": reader["unique_returned_variables"],
        "redecisions": reader["redecisions"],
        "first_fallback_call": reader["first_fallback_call"],
        "solver_phase_calls": reader["solver_phase_calls"],
    }


def _promote_result(
    result: _v13.JointScoreSieveV13Result,
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
) -> JointScoreSieveV14Result:
    return JointScoreSieveV14Result(
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
) -> JointScoreSieveV14Result:
    """Validate native-v11 release telemetry before inherited normalization."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v14 result fields differ")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["implementation_parent_schema"]
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed != 0
        or isinstance(payload["seed"], bool)
        or not isinstance(payload["seed"], int)
        or payload["seed"] != 0
    ):
        raise O1RelationalSearchError("joint-score-sieve-v14 result contract differs")
    reader = validate_vault_ranked_decision_reader(
        payload["reader"], expected_decision=expected_decision
    )
    sieve = payload["sieve"]
    if (
        not isinstance(sieve, Mapping)
        or sieve.get("cb_decide_calls") != reader["cb_decide_calls"]
        or sieve.get("cb_decide_nonzero") != 0
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 base and outer callback accounting differs"
        )

    parent_payload = dict(payload)
    parent_payload["schema"] = _v13.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v13.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    parent_payload["reader"] = _v13_reader(reader, expected_decision)
    try:
        parent = _v13._parse_native_payload(
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
            "joint-score-sieve-v14 native payload validation failed"
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
) -> JointScoreSieveV14Result:
    """Run sealed native v11 through the strict v14 process boundary."""

    requested = _v13._v12._v11._v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v14 native vault caps differ")
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
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v13._v12._v11._v9._v8._v1._read_input(
        executable, "executable"
    )
    cnf, cnf_bytes, cnf_sha = _v13._v12._v11._v9._v8._v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = (
        _v13._v12._v11._v9._v8._v1._read_input(potential_path, "potential")
    )
    grouping_file, grouping_bytes, grouping_sha = (
        _v13._v12._v11._v9._v8._v1._read_input(grouping_path, "grouping")
    )
    vault_file, vault_bytes = _v13._v12._v11._v9._v8._read_bounded_vault_input(
        vault_path, caps=vault_caps
    )
    field = _v13._v12._v11._v9._v8._v1._potential(potential_bytes)
    grouping = _v13._v12._v11._v9._v8._v7.validate_joint_score_sieve_grouping(
        field, grouping_bytes
    )
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 grouping potential identity differs"
        )
    try:
        expected_decision = derive_production_vault_ranked_decision(
            vault_bytes, potential_bytes, grouping_bytes
        )
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 sealed ranked decision differs"
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
            "joint-score-sieve-v14 input vault differs"
        ) from exc
    try:
        _v13._v12._v11._v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 input vault certification differs"
        ) from exc

    rank_path, rank_bytes = _v13._rank_table_temp(expected_decision)
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
    execution: _v13._v12._v11._v9._v8._v7._NativeExecution | None
    try:
        try:
            execution = _v13._v12._v11._v9._v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
            execution = None
        try:
            _v13._v12._v11._v9._v8._v1._verify_stable_input(
                executable, executable_file, executable_bytes, field="executable"
            )
            _v13._v12._v11._v9._v8._v1._verify_stable_input(
                cnf_path, cnf, cnf_bytes, field="CNF"
            )
            _v13._v12._v11._v9._v8._v1._verify_stable_input(
                potential_path,
                potential_file,
                potential_bytes,
                field="potential",
            )
            _v13._v12._v11._v9._v8._v1._verify_stable_input(
                grouping_path,
                grouping_file,
                grouping_bytes,
                field="grouping",
            )
            _v13._v12._v11._v9._v8._verify_stable_vault_input(
                vault_path, vault_file, vault_bytes, caps=vault_caps
            )
            if rank_path.read_bytes() != rank_bytes:
                raise O1RelationalSearchError(
                    "joint-score-sieve-v14 rank table changed during execution"
                )
        except Exception as exc:
            if execution is not None:
                _v13._v12._v11._v9._attach_native_process_evidence(
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
                "joint-score-sieve-v14 rank table cleanup failed"
            ) from exc
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v14 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v14 execution failed: {detail}"
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
        )
        return replace(
            result,
            stats=derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v13._v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v14 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v13._v12._v11._v9._attach_native_process_evidence(
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
) -> JointScoreSieveV14Result:
    """Run native v11 while retaining v13's bounded failure evidence."""

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
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        if not math.isfinite(elapsed) or elapsed < 0.0:
            elapsed = 0.0
        telemetry = _v13._v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v14"):
            message = f"joint-score-sieve-v14 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


__all__ = [
    "APPLE_VIEW_0009_GROUPING_SHA256",
    "APPLE_VIEW_0009_POTENTIAL_SHA256",
    "COMPATIBILITY_GROUPING_BOUND_RULE",
    "COMPATIBILITY_GROUPING_MAGIC",
    "COMPATIBILITY_GROUPING_MEMORY_RULE",
    "COMPATIBILITY_GROUPING_RULE",
    "COMPATIBILITY_GROUPING_SCHEMA",
    "EmittedThresholdNoGoodClause",
    "IncrementalJointScoreGroupMaxima",
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_BOUND_RULE",
    "JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE",
    "JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES",
    "JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "JOINT_SCORE_SIEVE_DECISION_RULE",
    "JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA",
    "JOINT_SCORE_SIEVE_GROUPING_MAGIC",
    "JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE",
    "JOINT_SCORE_SIEVE_GROUPING_RULE",
    "JOINT_SCORE_SIEVE_GROUPING_SCHEMA",
    "JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP",
    "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES",
    "JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA",
    "JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE",
    "JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_STATE_ENCODING",
    "JOINT_SCORE_SIEVE_STATE_SCHEMA",
    "JOINT_SCORE_SIEVE_TEARDOWN_RULE",
    "JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION",
    "JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA",
    "JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE",
    "JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION",
    "JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreSieveExecutionError",
    "JointScoreSieveResult",
    "JointScoreSieveV10Result",
    "JointScoreSieveV11Result",
    "JointScoreSieveV12Result",
    "JointScoreSieveV13Result",
    "JointScoreSieveV14Result",
    "JointScoreSieveV7Result",
    "JointScoreSieveV8Result",
    "JointScoreSieveV9Result",
    "O1C66_VAULT_CAPS",
    "O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA",
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
    "VAULT_RANKED_DECISION_ONCE_RETURN_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_OPERATOR",
    "VAULT_RANKED_DECISION_ORDER_ENCODING",
    "VAULT_RANKED_DECISION_READER_SCHEMA",
    "VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_SORT_RULE",
    "VAULT_RANKED_DECISION_SPEC_SHA256",
    "VAULT_RANKED_DECISION_STATE_ENCODING",
    "VAULT_RANKED_DECISION_TABLE_ENCODING",
    "VAULT_RANKED_DECISION_VOTE_RULE",
    "VaultCaps",
    "VaultRankedDecision",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "derive_vault_soft_conflict_ledger",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "validate_vault_backtrack_release_ranked_decision_reader",
    "validate_vault_ranked_decision_reader",
    "validate_vault_soft_conflict_ledger",
    "vault_backtrack_release_policy_spec_bytes",
    "vault_ranked_decision_spec_bytes",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
