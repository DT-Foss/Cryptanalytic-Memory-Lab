"""Strict ranked-decision adapter for native joint sieve v10.

The adapter independently rebuilds the sealed O1C71 rank from the vault,
potential, and grouping, writes only its bounded canonical table to a private
temporary file, and validates every static and runtime reader field before
projecting the otherwise unchanged payload through v12.  The inherited vault,
lifecycle, state, resource, and observed-work billing contracts are therefore
retained without reinterpretation.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v12 as _v12
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
    VAULT_RANKED_DECISION_READER_SCHEMA,
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


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v13-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v10"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-result-v6"
)

VAULT_RANKED_DECISION_DECISION_RULE = (
    "immutable-rank-first-currently-unassigned;zero-delegates-to-solver"
)
VAULT_RANKED_DECISION_CALLBACK_RULE = (
    "scan-immutable-rank-from-start-every-call;reuse-v6-assignment-backtrack-state;"
    "return-first-unassigned-ranked-literal;zero-after-none"
)
VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING = (
    "cb-decide-return-order-concatenated-signed-i32le-including-zero"
)

_STATIC_READER_FIELDS = frozenset(
    {
        "schema",
        "operator",
        "source_vault_sha256",
        "suffix_canonical_records_sha256",
        "vote_field_sha256",
        "potential_sha256",
        "potential_source_sha256",
        "grouping_sha256",
        "grouping_width_cap",
        "key_variable_count",
        "observed_variable_count",
        "candidate_count",
        "zero_delta_count",
        "unobserved_nonzero_count",
        "vote_rule",
        "bound_rule",
        "gap_rule",
        "sort_rule",
        "literal_rule",
        "reader_spec_bytes",
        "reader_spec_sha256",
        "order_encoding",
        "ranked_literals",
        "order_bytes",
        "order_sha256",
        "rank_table_encoding",
        "rank_table_rows",
        "rank_table_bytes",
        "rank_table_sha256",
    }
)
_RUNTIME_READER_FIELDS = frozenset(
    {
        "decision_rule",
        "callback_rule",
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
    }
)
_READER_FIELDS = _STATIC_READER_FIELDS | _RUNTIME_READER_FIELDS
_STATIC_INTEGER_FIELDS = (
    "grouping_width_cap",
    "key_variable_count",
    "observed_variable_count",
    "candidate_count",
    "zero_delta_count",
    "unobserved_nonzero_count",
    "reader_spec_bytes",
    "order_bytes",
    "rank_table_rows",
    "rank_table_bytes",
)
_RUNTIME_INTEGER_FIELDS = (
    "cb_decide_calls",
    "cb_decide_nonzero",
    "cb_decide_zero",
    "returned_sequence_count",
    "returned_sequence_bytes",
    "unique_returned_variables",
    "redecisions",
    "solver_phase_calls",
)
_TOP_LEVEL_FIELDS = _v12._TOP_LEVEL_FIELDS
_MAXIMUM_RANK_TABLE_BYTES = 36 * 256

# Public inherited mechanism surface.
O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA = (
    _v12.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA = (
    _v12.JOINT_SCORE_SIEVE_VAULT_CONFLICT_LEDGER_SCHEMA
)
JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA = _v12.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS = (
    _v12.JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
)
JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET = (
    _v12.JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_BUDGET
)
APPLE_VIEW_0009_GROUPING_SHA256 = _v12.APPLE_VIEW_0009_GROUPING_SHA256
APPLE_VIEW_0009_POTENTIAL_SHA256 = _v12.APPLE_VIEW_0009_POTENTIAL_SHA256
COMPATIBILITY_GROUPING_BOUND_RULE = _v12.COMPATIBILITY_GROUPING_BOUND_RULE
COMPATIBILITY_GROUPING_MAGIC = _v12.COMPATIBILITY_GROUPING_MAGIC
COMPATIBILITY_GROUPING_MEMORY_RULE = _v12.COMPATIBILITY_GROUPING_MEMORY_RULE
COMPATIBILITY_GROUPING_RULE = _v12.COMPATIBILITY_GROUPING_RULE
COMPATIBILITY_GROUPING_SCHEMA = _v12.COMPATIBILITY_GROUPING_SCHEMA
EmittedThresholdNoGoodClause = _v12.EmittedThresholdNoGoodClause
IncrementalJointScoreGroupMaxima = _v12.IncrementalJointScoreGroupMaxima
JOINT_SCORE_SIEVE_BOUND_RULE = _v12.JOINT_SCORE_SIEVE_BOUND_RULE
JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE = (
    _v12.JOINT_SCORE_SIEVE_COMPLETE_THRESHOLD_RULE
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES = (
    _v12.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
)
JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _v12.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
JOINT_SCORE_SIEVE_DECISION_RULE = _v12.JOINT_SCORE_SIEVE_DECISION_RULE
JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA = (
    _v12.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
)
JOINT_SCORE_SIEVE_GROUPING_MAGIC = _v12.JOINT_SCORE_SIEVE_GROUPING_MAGIC
JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE = _v12.JOINT_SCORE_SIEVE_GROUPING_MEMORY_RULE
JOINT_SCORE_SIEVE_GROUPING_RULE = _v12.JOINT_SCORE_SIEVE_GROUPING_RULE
JOINT_SCORE_SIEVE_GROUPING_SCHEMA = _v12.JOINT_SCORE_SIEVE_GROUPING_SCHEMA
JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP = _v12.JOINT_SCORE_SIEVE_GROUPING_WIDTH_CAP
JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES = _v12.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA = _v12.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE = _v12.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE = _v12.JOINT_SCORE_SIEVE_PERSISTENT_STATE_SCOPE
JOINT_SCORE_SIEVE_STATE_ENCODING = _v12.JOINT_SCORE_SIEVE_STATE_ENCODING
JOINT_SCORE_SIEVE_STATE_SCHEMA = _v12.JOINT_SCORE_SIEVE_STATE_SCHEMA
JOINT_SCORE_SIEVE_TEARDOWN_RULE = _v12.JOINT_SCORE_SIEVE_TEARDOWN_RULE
JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION = (
    _v12.JOINT_SCORE_SIEVE_VAULT_COMPLETE_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE = (
    _v12.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE
)
JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION = (
    _v12.JOINT_SCORE_SIEVE_VAULT_PARTIAL_CERTIFICATION
)
JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA = _v12.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA
JointScoreCompatibilityGroup = _v12.JointScoreCompatibilityGroup
JointScoreSieveExecutionError = _v12.JointScoreSieveExecutionError
JointScoreSieveResult = _v12.JointScoreSieveResult
JointScoreSieveV7Result = _v12.JointScoreSieveV7Result
JointScoreSieveV8Result = _v12.JointScoreSieveV8Result
JointScoreSieveV9Result = _v12.JointScoreSieveV9Result
JointScoreSieveV10Result = _v12.JointScoreSieveV10Result
JointScoreSieveV11Result = _v12.JointScoreSieveV11Result
JointScoreSieveV12Result = _v12.JointScoreSieveV12Result
build_compatibility_grouping = _v12.build_compatibility_grouping
build_native_joint_score_sieve = _v12.build_native_joint_score_sieve
derive_vault_soft_conflict_ledger = _v12.derive_vault_soft_conflict_ledger
derive_soft_conflict_ledger = derive_vault_soft_conflict_ledger
grouped_joint_score_cache = _v12.grouped_joint_score_cache
grouped_upper_bound_prunes = _v12.grouped_upper_bound_prunes
joint_score_complete = _v12.joint_score_complete
joint_score_upper_bound = _v12.joint_score_upper_bound
validate_incremental_conflict_ledger = _v12.validate_incremental_conflict_ledger
validate_joint_score_sieve_grouping = _v12.validate_joint_score_sieve_grouping
validate_vault_soft_conflict_ledger = _v12.validate_vault_soft_conflict_ledger
validate_soft_conflict_ledger = validate_vault_soft_conflict_ledger
write_joint_score_sieve_grouping = _v12.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v12.write_joint_score_sieve_potential


@dataclass(frozen=True)
class JointScoreSieveV13Result(_v12.JointScoreSieveV12Result):
    """A v12-validated result plus authoritative ranked-decision telemetry."""


def _reader_expected(decision: VaultRankedDecision) -> dict[str, object]:
    try:
        validated = validate_vault_ranked_decision(decision)
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 expected rank differs"
        ) from exc
    expected = validated.reader_binding()
    if set(expected) != _STATIC_READER_FIELDS:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 rank binding fields differ"
        )
    return expected


def validate_vault_ranked_decision_reader(
    raw: object, *, expected_decision: VaultRankedDecision
) -> dict[str, object]:
    """Validate exact static rank identities and coherent callback telemetry."""

    reader = _v12._v11._v9._v8._v1._mapping(raw, "reader")
    if set(reader) != _READER_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v13 reader fields differ")
    expected = _reader_expected(expected_decision)
    if any(
        isinstance(reader[name], bool) or not isinstance(reader[name], int)
        for name in _STATIC_INTEGER_FIELDS
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader static scalar types differ"
        )
    ranked_literals = reader["ranked_literals"]
    if not isinstance(ranked_literals, list) or any(
        isinstance(literal, bool) or not isinstance(literal, int)
        for literal in ranked_literals
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader rank array types differ"
        )
    if any(reader[name] != value for name, value in expected.items()):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader rank contract differs"
        )

    runtime_integers: dict[str, int] = {}
    for name in _RUNTIME_INTEGER_FIELDS:
        value = reader[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise O1RelationalSearchError(
                "joint-score-sieve-v13 reader runtime scalar types differ"
            )
        runtime_integers[name] = value
    returned_hex = reader["returned_sequence_hex"]
    returned_sha256 = reader["returned_sequence_sha256"]
    if (
        reader["decision_rule"] != VAULT_RANKED_DECISION_DECISION_RULE
        or reader["callback_rule"] != VAULT_RANKED_DECISION_CALLBACK_RULE
        or reader["returned_sequence_encoding"]
        != VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING
        or not isinstance(returned_hex, str)
        or not isinstance(returned_sha256, str)
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader callback contract differs"
        )
    first_fallback = reader["first_fallback_call"]
    if first_fallback is not None and (
        isinstance(first_fallback, bool)
        or not isinstance(first_fallback, int)
        or first_fallback < 1
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader first fallback differs"
        )
    try:
        sequence = bytes.fromhex(returned_hex)
    except ValueError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 returned sequence differs"
        ) from exc
    if sequence.hex() != returned_hex:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 returned sequence encoding differs"
        )
    calls = runtime_integers["cb_decide_calls"]
    nonzero = runtime_integers["cb_decide_nonzero"]
    zero = runtime_integers["cb_decide_zero"]
    if len(sequence) % 4:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 returned sequence length differs"
        )
    returns = (
        struct.unpack(f"<{len(sequence) // 4}i", sequence) if sequence else ()
    )
    allowed = set(expected_decision.ranked_literals)
    actual_first_fallback = next(
        (index for index, literal in enumerate(returns, start=1) if literal == 0),
        None,
    )
    unique = len({abs(literal) for literal in returns if literal})
    if (
        calls != nonzero + zero
        or calls != len(returns)
        or nonzero != sum(literal != 0 for literal in returns)
        or zero != sum(literal == 0 for literal in returns)
        or runtime_integers["returned_sequence_count"] != calls
        or runtime_integers["returned_sequence_bytes"] != len(sequence)
        or runtime_integers["returned_sequence_bytes"] != 4 * calls
        or hashlib.sha256(sequence).hexdigest() != returned_sha256
        or any(literal not in allowed for literal in returns if literal)
        or runtime_integers["unique_returned_variables"] != unique
        or runtime_integers["redecisions"] != nonzero - unique
        or first_fallback != actual_first_fallback
        or runtime_integers["solver_phase_calls"] != 0
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 reader callback telemetry differs"
        )
    return {name: reader[name] for name in sorted(_READER_FIELDS)}


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate native-v10 lifecycle provenance through unchanged v12 rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 lifecycle contract differs"
        )
    return _v12.validate_native_lifecycle(payload)


def _promote_result(
    result: _v12.JointScoreSieveV12Result,
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
) -> JointScoreSieveV13Result:
    return JointScoreSieveV13Result(
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
) -> JointScoreSieveV13Result:
    """Validate native-v10 rank telemetry before inherited normalization."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v13 result fields differ")
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
        raise O1RelationalSearchError("joint-score-sieve-v13 result contract differs")
    reader = validate_vault_ranked_decision_reader(
        payload["reader"], expected_decision=expected_decision
    )

    parent_payload = dict(payload)
    parent_payload["schema"] = _v12.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    parent_payload["implementation_parent_schema"] = (
        _v12.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
    )
    parent_payload["reader"] = _v12._expected_reader()
    try:
        parent = _v12._parse_native_payload(
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
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 native payload validation failed"
        ) from exc
    if (
        not isinstance(payload["sieve"], Mapping)
        or payload["sieve"].get("cb_decide_calls") != reader["cb_decide_calls"]
        or payload["sieve"].get("cb_decide_nonzero") != 0
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 inherited callback accounting differs"
        )
    return _promote_result(parent, raw=payload, reader=reader)


def _rank_table_temp(decision: VaultRankedDecision) -> tuple[Path, bytes]:
    payload = decision.rank_table_bytes
    if (
        not payload
        or len(payload) != 36 * decision.candidate_count
        or len(payload) > _MAXIMUM_RANK_TABLE_BYTES
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 bounded rank table differs"
        )
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix="o1c71-rank-table-", suffix=".bin"
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        path = Path(raw_path)
        os.chmod(path, 0o600)
    except OSError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 rank table write failed"
        ) from exc
    return path, payload


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
) -> JointScoreSieveV13Result:
    """Run sealed native v10 through the strict v13 process boundary."""

    requested = _v12._v11._v9._requested_conflicts(conflict_limit)
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v13 native vault caps differ")
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
            "joint-score-sieve-v13 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    executable_file, executable_bytes, _ = _v12._v11._v9._v8._v1._read_input(
        executable, "executable"
    )
    cnf, cnf_bytes, cnf_sha = _v12._v11._v9._v8._v1._read_input(cnf_path, "CNF")
    potential_file, potential_bytes, potential_sha = (
        _v12._v11._v9._v8._v1._read_input(potential_path, "potential")
    )
    grouping_file, grouping_bytes, grouping_sha = (
        _v12._v11._v9._v8._v1._read_input(grouping_path, "grouping")
    )
    vault_file, vault_bytes = _v12._v11._v9._v8._read_bounded_vault_input(
        vault_path, caps=vault_caps
    )
    field = _v12._v11._v9._v8._v1._potential(potential_bytes)
    grouping = _v12._v11._v9._v8._v7.validate_joint_score_sieve_grouping(
        field, grouping_bytes
    )
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 grouping potential identity differs"
        )
    try:
        expected_decision = derive_production_vault_ranked_decision(
            vault_bytes, potential_bytes, grouping_bytes
        )
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 sealed ranked decision differs"
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
            "joint-score-sieve-v13 input vault differs"
        ) from exc
    try:
        _v12._v11._v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=requested_threshold,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 input vault certification differs"
        ) from exc

    rank_path, rank_bytes = _rank_table_temp(expected_decision)
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
    execution: _v12._v11._v9._v8._v7._NativeExecution | None
    try:
        try:
            execution = _v12._v11._v9._v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
            execution = None
        try:
            _v12._v11._v9._v8._v1._verify_stable_input(
                executable, executable_file, executable_bytes, field="executable"
            )
            _v12._v11._v9._v8._v1._verify_stable_input(
                cnf_path, cnf, cnf_bytes, field="CNF"
            )
            _v12._v11._v9._v8._v1._verify_stable_input(
                potential_path, potential_file, potential_bytes, field="potential"
            )
            _v12._v11._v9._v8._v1._verify_stable_input(
                grouping_path, grouping_file, grouping_bytes, field="grouping"
            )
            _v12._v11._v9._v8._verify_stable_vault_input(
                vault_path, vault_file, vault_bytes, caps=vault_caps
            )
            if rank_path.read_bytes() != rank_bytes:
                raise O1RelationalSearchError(
                    "joint-score-sieve-v13 rank table changed during execution"
                )
        except Exception as exc:
            if execution is not None:
                _v12._v11._v9._attach_native_process_evidence(
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
                "joint-score-sieve-v13 rank table cleanup failed"
            ) from exc
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v13 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v13 execution failed: {detail}"
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
        _v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v13 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v12._v11._v9._attach_native_process_evidence(
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
) -> JointScoreSieveV13Result:
    """Run native v10 while retaining v12's bounded failure evidence."""

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
        telemetry = _v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v13"):
            message = f"joint-score-sieve-v13 adapter failed: {message}"
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
    "VAULT_RANKED_DECISION_BOUND_RULE",
    "VAULT_RANKED_DECISION_CALLBACK_RULE",
    "VAULT_RANKED_DECISION_DECISION_RULE",
    "VAULT_RANKED_DECISION_GAP_RULE",
    "VAULT_RANKED_DECISION_LITERAL_RULE",
    "VAULT_RANKED_DECISION_OPERATOR",
    "VAULT_RANKED_DECISION_ORDER_ENCODING",
    "VAULT_RANKED_DECISION_READER_SCHEMA",
    "VAULT_RANKED_DECISION_RETURNED_SEQUENCE_ENCODING",
    "VAULT_RANKED_DECISION_SORT_RULE",
    "VAULT_RANKED_DECISION_SPEC_SHA256",
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
    "validate_vault_ranked_decision_reader",
    "validate_vault_soft_conflict_ledger",
    "vault_ranked_decision_spec_bytes",
    "write_joint_score_sieve_grouping",
    "write_joint_score_sieve_potential",
]
