"""Typed adapter for the bounded score-threshold no-good vault.

Native v6 extends the lifecycle-safe width-6 sieve with one identity-bound
input vault and complete-callback emission telemetry.  This adapter validates
the input archive before launch, independently certifies every imported and
fully emitted no-good, reconstructs the cumulative archive without trusting
native byte claims, and preserves v7's cause- and RSS-rich failure boundary.
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

from . import joint_score_sieve as _v1
from . import joint_score_sieve_v7 as _v7
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING,
    THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE,
    THRESHOLD_NO_GOOD_VAULT_MAGIC,
    THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE,
    THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    VaultCaps,
    append_new_deduplicated,
    parse_threshold_no_good_vault,
    partial_assignment_from_vault_clause,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)


JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v5"
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = (
    "o1-256-cadical-score-threshold-no-good-vault-telemetry-v1"
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    "partial-excluded-assignment-grouped-upper-bound-strictly-below-threshold;"
    "full-excluded-assignment-original-factor-exact-score-strictly-below-threshold"
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = "grouped_upper_bound"
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = "original_factor_exact_score"

JointScoreSieveExecutionError = _v7.JointScoreSieveExecutionError
JointScoreSieveResult = _v7.JointScoreSieveResult
APPLE_VIEW_0009_GROUPING_SHA256 = _v7.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v7.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v7.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v7.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v7.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v7.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v7.COMPATIBILITY_GROUPING_SCHEMA
IncrementalJointScoreGroupMaxima = _v7.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v7.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v7.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = _v7.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v7.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v7.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v7.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v7.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v7.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v7.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v7.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v7.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v7.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS = (
    _v7.JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v7.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = (
    _v7.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
)
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v7.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v7.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v7.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v7.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v7.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v7.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v7.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v7.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JointScoreCompatibilityGroup = _v7.JointScoreCompatibilityGroup
JointScoreSieveV7Result = _v7.JointScoreSieveV7Result
build_compatibility_grouping = _v7.build_compatibility_grouping
build_native_joint_score_sieve = _v7.build_native_joint_score_sieve
derive_soft_conflict_ledger = _v7.derive_soft_conflict_ledger
grouped_joint_score_cache = _v7.grouped_joint_score_cache
grouped_upper_bound_prunes = _v7.grouped_upper_bound_prunes
joint_score_complete = _v7.joint_score_complete
joint_score_upper_bound = _v7.joint_score_upper_bound
validate_incremental_conflict_ledger = _v7.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v7.validate_joint_score_sieve_grouping
validate_soft_conflict_ledger = _v7.validate_soft_conflict_ledger
write_joint_score_sieve_grouping = _v7.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v7.write_joint_score_sieve_potential

_TOP_LEVEL_FIELDS = _v7._TOP_LEVEL_FIELDS | {"vault"}
_EMITTED_FIELDS = {
    "index",
    "source",
    "witness_score",
    "witness_score_f64le_hex",
    "literal_count",
    "literals",
    "clause_sha256",
    "witness_sha256",
    "classification",
}
_VAULT_FIELDS = {
    "schema",
    "binary_magic_hex",
    "semantic_rule",
    "identity_rule",
    "clause_encoding",
    "witness_encoding",
    "maximum_payload_bytes",
    "maximum_clause_count",
    "maximum_literal_count",
    "input_sha256",
    "input_serialized_bytes",
    "input_clause_count",
    "input_literal_count",
    "input_clause_aggregate_sha256",
    "input_certification_rule",
    "validated_input_clause_count",
    "validated_input_literal_count",
    "validated_input_clause_aggregate_sha256",
    "input_cnf_sha256",
    "input_potential_sha256",
    "input_grouping_sha256",
    "input_observed_variables_sha256",
    "input_bound_rule_sha256",
    "input_threshold_f64le_hex",
    "preloaded_clause_count",
    "preloaded_literal_count",
    "fully_emitted_clause_count",
    "fully_emitted_literal_count",
    "emitted_new_clause_count",
    "emitted_new_literal_count",
    "emitted_input_duplicate_clause_count",
    "emitted_input_duplicate_literal_count",
    "emitted_current_duplicate_clause_count",
    "emitted_current_duplicate_literal_count",
    "terminal_empty_clause_count",
    "pending_clause_exported",
    "fully_emitted_aggregate_sha256",
    "fully_emitted_clauses",
    "next_vault_available",
    "next_vault_terminal_reason",
    "next_vault_sha256",
    "next_serialized_bytes",
    "next_clause_count",
    "next_literal_count",
}
_VAULT_INTEGER_FIELDS = {
    "maximum_payload_bytes",
    "maximum_clause_count",
    "maximum_literal_count",
    "input_serialized_bytes",
    "input_clause_count",
    "input_literal_count",
    "validated_input_clause_count",
    "validated_input_literal_count",
    "preloaded_clause_count",
    "preloaded_literal_count",
    "fully_emitted_clause_count",
    "fully_emitted_literal_count",
    "emitted_new_clause_count",
    "emitted_new_literal_count",
    "emitted_input_duplicate_clause_count",
    "emitted_input_duplicate_literal_count",
    "emitted_current_duplicate_clause_count",
    "emitted_current_duplicate_literal_count",
    "terminal_empty_clause_count",
}
_NEXT_INTEGER_FIELDS = {
    "next_serialized_bytes",
    "next_clause_count",
    "next_literal_count",
}
_SOURCE_CODES = {"trail_upper_bound": 1, "complete_model_score": 2}
_CAPACITY_REASONS = {
    "capacity_clause_count",
    "capacity_literal_count",
    "capacity_payload_bytes",
}


@dataclass(frozen=True)
class EmittedThresholdNoGoodClause:
    """One fully emitted, independently certified, nonempty native no-good."""

    index: int
    source: str
    witness_score: float
    clause: ThresholdNoGoodClause
    excluded_assignment: tuple[tuple[int, int], ...]
    classification: str
    certification: str
    clause_sha256: str
    witness_sha256: str

    @property
    def literals(self) -> tuple[int, ...]:
        return self.clause.literals


@dataclass(frozen=True)
class JointScoreSieveV8Result(_v7.JointScoreSieveV7Result):
    """Native-v6 result with typed input, emitted, and cumulative vaults."""

    input_vault: ThresholdNoGoodVault
    eligible_emitted_clauses: tuple[EmittedThresholdNoGoodClause, ...]
    next_vault: ThresholdNoGoodVault | None
    vault_telemetry: Mapping[str, object]


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v6 lifecycle provenance while reusing v7 state rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError("joint-score-sieve-v8 lifecycle contract differs")
    parent_payload = dict(payload)
    parent_payload["implementation_parent_schema"] = (
        _v7.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    normalized = _v7.validate_native_lifecycle(parent_payload)
    normalized["implementation_parent_schema"] = (
        JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    return normalized


def _nonnegative_integer(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v8 vault {field_name} differs"
        )
    return value


def _exact_scaled_integer(value: float) -> int:
    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
    negative = bool(bits >> 63)
    exponent = (bits >> 52) & 0x7FF
    fraction = bits & ((1 << 52) - 1)
    magnitude = fraction if exponent == 0 else ((1 << 52) | fraction) << (exponent - 1)
    return -magnitude if negative else magnitude


def _complete_score_scaled_integer(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> int:
    if set(assignments) != set(field.observed_variables):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 complete no-good assignment differs"
        )
    total = _exact_scaled_integer(field.offset)
    for factor in field.factors:
        row = 0
        for local, variable in enumerate(factor.variables):
            if assignments[variable] > 0:
                row |= 1 << local
        total += _exact_scaled_integer(factor.energies[row])
    return total


def _certify_no_good(
    clause: ThresholdNoGoodClause,
    *,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    threshold: float,
    source: str | None,
    witness_score: float | None,
) -> tuple[tuple[tuple[int, int], ...], str]:
    assignments = partial_assignment_from_vault_clause(clause)
    complete = len(assignments) == len(field.observed_variables)
    if source == "complete_model_score" and not complete:
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 complete witness is partial"
        )
    if source == "trail_upper_bound" or (source is None and not complete):
        upper = _v7.joint_score_upper_bound(field, assignments, grouping=grouping)
        if upper >= threshold or (
            witness_score is not None
            and struct.pack("<d", witness_score) != struct.pack("<d", upper)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 grouped no-good certification differs"
            )
        if complete and _complete_score_scaled_integer(
            field, assignments
        ) >= _exact_scaled_integer(threshold):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 complete no-good exact score differs"
            )
        certification = JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
    else:
        if not complete:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 input no-good certification differs"
            )
        exact_score = _complete_score_scaled_integer(field, assignments)
        if exact_score >= _exact_scaled_integer(threshold):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 complete no-good exact score differs"
            )
        rounded = _v7.joint_score_complete(field, assignments)
        if witness_score is not None and struct.pack(
            "<d", witness_score
        ) != struct.pack("<d", rounded):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 complete no-good witness differs"
            )
        certification = JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
    return tuple(sorted(assignments.items())), certification


def _certify_input_vault(
    vault: ThresholdNoGoodVault,
    *,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    threshold: float,
) -> None:
    for clause in vault.clauses:
        _certify_no_good(
            clause,
            field=field,
            grouping=grouping,
            threshold=threshold,
            source=None,
            witness_score=None,
        )


def _canonical_clause_bytes(literals: tuple[int, ...]) -> bytes:
    payload = bytearray(struct.pack("<I", len(literals)))
    for literal in literals:
        payload.extend(struct.pack("<i", literal))
    return bytes(payload)


def _expected_terminal_reason(
    *,
    input_vault: ThresholdNoGoodVault,
    new_clauses: tuple[ThresholdNoGoodClause, ...],
    terminal_empty_count: int,
    caps: VaultCaps,
) -> str | None:
    if terminal_empty_count:
        return "terminal_empty_clause"
    new_clause_count = len(new_clauses)
    new_literal_count = sum(clause.literal_count for clause in new_clauses)
    new_serialized_bytes = sum(4 + 4 * clause.literal_count for clause in new_clauses)
    if new_clause_count > caps.maximum_clauses - input_vault.clause_count:
        return "capacity_clause_count"
    if new_literal_count > caps.maximum_literals - input_vault.literal_count:
        return "capacity_literal_count"
    if (
        new_serialized_bytes
        > caps.maximum_serialized_bytes - input_vault.serialized_bytes
    ):
        return "capacity_payload_bytes"
    return None


def _parse_vault_telemetry(
    raw: object,
    *,
    input_vault: ThresholdNoGoodVault,
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    threshold: float,
    caps: VaultCaps,
) -> tuple[
    tuple[EmittedThresholdNoGoodClause, ...],
    ThresholdNoGoodVault | None,
    dict[str, object],
]:
    if input_vault.observed_variables != field.observed_variables or struct.pack(
        "<d", input_vault.identity.threshold
    ) != struct.pack("<d", threshold):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 input vault certification identity differs"
        )
    telemetry = _v1._mapping(raw, "vault")
    if set(telemetry) != _VAULT_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 vault telemetry fields differ"
        )
    integers = {
        name: _nonnegative_integer(telemetry[name], name)
        for name in _VAULT_INTEGER_FIELDS
    }
    if (
        telemetry["schema"] != JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
        or telemetry["binary_magic_hex"] != THRESHOLD_NO_GOOD_VAULT_MAGIC.hex()
        or telemetry["semantic_rule"] != THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE
        or telemetry["identity_rule"] != THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE
        or telemetry["clause_encoding"] != THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING
        or telemetry["witness_encoding"] != THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING
        or telemetry["input_certification_rule"]
        != JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
        or integers["maximum_payload_bytes"] != caps.maximum_serialized_bytes
        or integers["maximum_clause_count"] != caps.maximum_clauses
        or integers["maximum_literal_count"] != caps.maximum_literals
        or telemetry["input_sha256"] != input_vault.sha256
        or integers["input_serialized_bytes"] != input_vault.serialized_bytes
        or integers["input_clause_count"] != input_vault.clause_count
        or integers["input_literal_count"] != input_vault.literal_count
        or telemetry["input_clause_aggregate_sha256"]
        != input_vault.clause_aggregate_sha256
        or integers["validated_input_clause_count"] != input_vault.clause_count
        or integers["validated_input_literal_count"] != input_vault.literal_count
        or telemetry["validated_input_clause_aggregate_sha256"]
        != input_vault.clause_aggregate_sha256
        or telemetry["input_cnf_sha256"] != input_vault.identity.cnf_sha256
        or telemetry["input_potential_sha256"] != input_vault.identity.potential_sha256
        or telemetry["input_grouping_sha256"] != input_vault.identity.grouping_sha256
        or telemetry["input_observed_variables_sha256"]
        != input_vault.identity.observed_variables_sha256
        or telemetry["input_bound_rule_sha256"]
        != input_vault.identity.bound_rule_sha256
        or telemetry["input_threshold_f64le_hex"]
        != input_vault.identity.threshold_f64le_hex
        or integers["preloaded_clause_count"] != input_vault.clause_count
        or integers["preloaded_literal_count"] != input_vault.literal_count
        or telemetry["pending_clause_exported"] is not False
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 input vault telemetry differs"
        )
    emitted_raw = telemetry["fully_emitted_clauses"]
    if not isinstance(emitted_raw, list):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 emitted clause list differs"
        )

    input_keys = {clause.serialized for clause in input_vault.clauses}
    observed = set(field.observed_variables)
    current_new_keys: set[bytes] = set()
    new_clauses: list[ThresholdNoGoodClause] = []
    eligible: list[EmittedThresholdNoGoodClause] = []
    emitted_aggregate = bytearray()
    fully_emitted_literals = 0
    class_clause_counts = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    class_literal_counts = {"new": 0, "input_duplicate": 0, "current_duplicate": 0}
    terminal_empty_count = 0

    for expected_index, raw_emitted in enumerate(emitted_raw):
        emitted = _v1._mapping(raw_emitted, "vault.fully_emitted_clauses")
        if set(emitted) != _EMITTED_FIELDS:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause fields differ"
            )
        index = _nonnegative_integer(emitted["index"], "emitted.index")
        literal_count = _nonnegative_integer(
            emitted["literal_count"], "emitted.literal_count"
        )
        source = emitted["source"]
        classification = emitted["classification"]
        literals_raw = emitted["literals"]
        witness = _v1._finite_float(
            emitted["witness_score"], "vault.emitted.witness_score"
        )
        if (
            index != expected_index
            or not isinstance(source, str)
            or source not in _SOURCE_CODES
            or not isinstance(literals_raw, list)
            or len(literals_raw) != literal_count
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in literals_raw
            )
            or emitted["witness_score_f64le_hex"] != struct.pack("<d", witness).hex()
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause encoding differs"
            )
        literals = tuple(cast(list[int], literals_raw))
        try:
            canonical = _canonical_clause_bytes(literals)
        except struct.error as exc:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause encoding differs"
            ) from exc
        expected_clause_sha = hashlib.sha256(canonical).hexdigest()
        witness_preimage = (
            bytes((_SOURCE_CODES[source],)) + struct.pack("<d", witness) + canonical
        )
        expected_witness_sha = hashlib.sha256(witness_preimage).hexdigest()
        if (
            emitted["clause_sha256"] != expected_clause_sha
            or emitted["witness_sha256"] != expected_witness_sha
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause digest differs"
            )
        emitted_aggregate.extend(canonical)
        fully_emitted_literals += literal_count

        if not literals:
            if classification != "terminal_empty" or source != "trail_upper_bound":
                raise O1RelationalSearchError(
                    "joint-score-sieve-v8 terminal empty clause differs"
                )
            root_upper = _v7.joint_score_upper_bound(field, {}, grouping=grouping)
            if root_upper >= threshold or struct.pack("<d", root_upper) != struct.pack(
                "<d", witness
            ):
                raise O1RelationalSearchError(
                    "joint-score-sieve-v8 terminal empty witness differs"
                )
            terminal_empty_count += 1
            continue

        try:
            clause = ThresholdNoGoodClause(literals)
        except ThresholdNoGoodVaultError as exc:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause is not canonical"
            ) from exc
        if any(abs(literal) not in observed for literal in literals):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause scope differs"
            )
        clause_key = clause.serialized
        if clause_key in input_keys:
            expected_classification = "input_duplicate"
        elif clause_key in current_new_keys:
            expected_classification = "current_duplicate"
        else:
            expected_classification = "new"
            current_new_keys.add(clause_key)
            new_clauses.append(clause)
        if classification != expected_classification:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 emitted clause classification differs"
            )
        assignment, certification = _certify_no_good(
            clause,
            field=field,
            grouping=grouping,
            threshold=threshold,
            source=source,
            witness_score=witness,
        )
        class_clause_counts[expected_classification] += 1
        class_literal_counts[expected_classification] += literal_count
        eligible.append(
            EmittedThresholdNoGoodClause(
                index=index,
                source=source,
                witness_score=witness,
                clause=clause,
                excluded_assignment=assignment,
                classification=expected_classification,
                certification=certification,
                clause_sha256=expected_clause_sha,
                witness_sha256=expected_witness_sha,
            )
        )

    expected_ledgers = {
        "fully_emitted_clause_count": len(emitted_raw),
        "fully_emitted_literal_count": fully_emitted_literals,
        "emitted_new_clause_count": class_clause_counts["new"],
        "emitted_new_literal_count": class_literal_counts["new"],
        "emitted_input_duplicate_clause_count": class_clause_counts["input_duplicate"],
        "emitted_input_duplicate_literal_count": class_literal_counts[
            "input_duplicate"
        ],
        "emitted_current_duplicate_clause_count": class_clause_counts[
            "current_duplicate"
        ],
        "emitted_current_duplicate_literal_count": class_literal_counts[
            "current_duplicate"
        ],
        "terminal_empty_clause_count": terminal_empty_count,
    }
    if (
        any(integers[name] != value for name, value in expected_ledgers.items())
        or telemetry["fully_emitted_aggregate_sha256"]
        != hashlib.sha256(emitted_aggregate).hexdigest()
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 emitted clause ledger differs"
        )

    expected_reason = _expected_terminal_reason(
        input_vault=input_vault,
        new_clauses=tuple(new_clauses),
        terminal_empty_count=terminal_empty_count,
        caps=caps,
    )
    available = telemetry["next_vault_available"]
    if not isinstance(available, bool):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 next vault availability differs"
        )
    if expected_reason is None:
        appended = append_new_deduplicated(input_vault, tuple(new_clauses), caps=caps)
        next_vault: ThresholdNoGoodVault | None = appended.vault
        next_integers = {
            name: _nonnegative_integer(telemetry[name], name)
            for name in _NEXT_INTEGER_FIELDS
        }
        if (
            not available
            or telemetry["next_vault_terminal_reason"] is not None
            or telemetry["next_vault_sha256"] != next_vault.sha256
            or next_integers["next_serialized_bytes"] != next_vault.serialized_bytes
            or next_integers["next_clause_count"] != next_vault.clause_count
            or next_integers["next_literal_count"] != next_vault.literal_count
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 cumulative vault differs"
            )
    else:
        if expected_reason not in _CAPACITY_REASONS | {"terminal_empty_clause"}:
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 next vault terminal reason differs"
            )
        if (
            available
            or telemetry["next_vault_terminal_reason"] != expected_reason
            or telemetry["next_vault_sha256"] is not None
            or any(telemetry[name] is not None for name in _NEXT_INTEGER_FIELDS)
        ):
            raise O1RelationalSearchError(
                "joint-score-sieve-v8 unavailable cumulative vault differs"
            )
        next_vault = None
    return tuple(eligible), next_vault, dict(telemetry)


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
) -> JointScoreSieveV8Result:
    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v8 result fields differ")
    if (
        payload["schema"] != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload["implementation_parent_schema"]
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError("joint-score-sieve-v8 result contract differs")
    validate_native_lifecycle(payload)
    parent_payload = dict(payload)
    vault_raw = parent_payload.pop("vault")
    parent_payload["schema"] = _v7.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v7.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    parent = _v7._parse_native_payload(
        parent_payload,
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
    eligible, next_vault, telemetry = _parse_vault_telemetry(
        vault_raw,
        input_vault=input_vault,
        field=field,
        grouping=grouping,
        threshold=threshold,
        caps=vault_caps,
    )
    state = _v1._mapping(parent.sieve["state"], "sieve.state")
    emitted_count = cast(int, parent.sieve["external_clauses_emitted"])
    queued_literals = cast(int, parent.sieve["external_clause_literals"])
    pending_literals = cast(int, state["pending_clause_length"])
    vault_emitted_count = cast(int, telemetry["fully_emitted_clause_count"])
    vault_emitted_literals = cast(int, telemetry["fully_emitted_literal_count"])
    if (
        vault_emitted_count != emitted_count
        or vault_emitted_literals + pending_literals != queued_literals
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 sieve and vault emission ledgers differ"
        )
    return JointScoreSieveV8Result(
        status=parent.status,
        conflict_limit=parent.conflict_limit,
        threshold=parent.threshold,
        key_model=parent.key_model,
        stats=parent.stats,
        sieve=parent.sieve,
        resources=parent.resources,
        raw=dict(payload),
        adapter_memory=parent.adapter_memory,
        input_vault=input_vault,
        eligible_emitted_clauses=eligible,
        next_vault=next_vault,
        vault_telemetry=telemetry,
    )


def _read_bounded_vault_input(
    path: str | Path, *, caps: VaultCaps
) -> tuple[Path, bytes]:
    try:
        resolved = Path(path).resolve(strict=True)
        with resolved.open("rb") as handle:
            payload = handle.read(caps.maximum_serialized_bytes + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise O1RelationalSearchError("joint-score-sieve vault input differs") from exc
    if not payload or len(payload) > caps.maximum_serialized_bytes:
        raise O1RelationalSearchError("joint-score-sieve vault input differs")
    return resolved, payload


def _verify_stable_vault_input(
    original: str | Path,
    resolved: Path,
    before: bytes,
    *,
    caps: VaultCaps,
) -> None:
    try:
        after_path, after = _read_bounded_vault_input(original, caps=caps)
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve vault changed during execution"
        ) from exc
    if after_path != resolved or after != before:
        raise O1RelationalSearchError(
            "joint-score-sieve vault changed during execution"
        )


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
) -> JointScoreSieveV8Result:
    requested = _v7._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v8 native vault caps differ")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or not 0 <= seed <= 2_000_000_000
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
            "joint-score-sieve-v8 threshold, seed, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v1._read_input(executable, "executable")
    cnf, cnf_bytes, cnf_sha = _v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = _v1._read_input(
        potential_path, "potential"
    )
    grouping_file, grouping_bytes, grouping_sha = _v1._read_input(
        grouping_path, "grouping"
    )
    vault_file, vault_bytes = _read_bounded_vault_input(vault_path, caps=vault_caps)
    field = _v1._potential(potential_bytes)
    grouping = _v7.validate_joint_score_sieve_grouping(field, grouping_bytes)
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 grouping potential identity differs"
        )
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
            bound_rule=_v7.JOINT_SCORE_SIEVE_BOUND_RULE,
            threshold=requested_threshold,
        )
        validate_threshold_no_good_vault_identity(
            input_vault, expected=expected_identity
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 input vault differs"
        ) from exc
    _certify_input_vault(
        input_vault,
        field=field,
        grouping=grouping,
        threshold=requested_threshold,
    )
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
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        str(seed),
    ]
    execution_error: Exception | None = None
    execution: _v7._NativeExecution | None
    try:
        execution = _v7._execute_native(
            command,
            timeout_seconds=float(timeout_seconds),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        execution_error = exc
        execution = None
    try:
        _v1._verify_stable_input(
            executable, executable_file, executable_bytes, field="executable"
        )
        _v1._verify_stable_input(cnf_path, cnf, cnf_bytes, field="CNF")
        _v1._verify_stable_input(
            potential_path, potential_file, potential_bytes, field="potential"
        )
        _v1._verify_stable_input(
            grouping_path, grouping_file, grouping_bytes, field="grouping"
        )
        _verify_stable_vault_input(vault_path, vault_file, vault_bytes, caps=vault_caps)
    except Exception as exc:
        if execution is not None:
            setattr(exc, "memory_samples", execution.memory_samples)
        raise
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve execution failed")
    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        setattr(failure, "memory_samples", execution.memory_samples)
        raise O1RelationalSearchError(
            f"joint-score-sieve execution failed: {detail}"
        ) from failure
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        setattr(exc, "memory_samples", execution.memory_samples)
        raise O1RelationalSearchError(
            "joint-score-sieve-v8 result JSON is invalid"
        ) from exc
    try:
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
            seed=seed,
            memory_limit_bytes=memory_limit_bytes,
            memory_samples=execution.memory_samples,
        )
    except Exception as exc:
        setattr(exc, "memory_samples", execution.memory_samples)
        raise
    return replace(
        result,
        stats=_v7.derive_soft_conflict_ledger(
            result.stats, requested_conflicts=requested
        ),
    )


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
) -> JointScoreSieveV8Result:
    """Run native v6 and return only independently vault-valid output."""

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
        telemetry = _v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        raise JointScoreSieveExecutionError(
            str(exc), failure_telemetry=telemetry
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
    "JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET",
    "JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
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
    "JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE",
    "JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION",
    "JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreSieveExecutionError",
    "JointScoreSieveResult",
    "JointScoreSieveV7Result",
    "JointScoreSieveV8Result",
    "O1C66_VAULT_CAPS",
    "ThresholdNoGoodClause",
    "ThresholdNoGoodVault",
    "VaultCaps",
    "build_compatibility_grouping",
    "build_native_joint_score_sieve",
    "derive_soft_conflict_ledger",
    "grouped_joint_score_cache",
    "grouped_upper_bound_prunes",
    "joint_score_complete",
    "joint_score_upper_bound",
    "run_joint_score_sieve",
    "validate_incremental_conflict_ledger",
    "validate_joint_score_sieve_grouping",
    "validate_native_lifecycle",
    "validate_soft_conflict_ledger",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
