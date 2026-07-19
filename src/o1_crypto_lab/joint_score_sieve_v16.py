"""Strict dual-vault adapter for native joint sieve v13.

O1C74 freezes rank derivation to the sealed O1C73 202-clause vault while
allowing a separately bounded active projection to be preloaded into CaDiCaL.
The two inputs are parsed, certified, and stability-checked independently.
"""

from __future__ import annotations

import json
import math
import subprocess
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from . import joint_score_sieve_v15 as _v15
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    ThresholdNoGoodVaultIdentity,
    VaultCaps,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)
from .vault_ranked_decision_v1 import (
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_production_vault_ranked_decision,
)


JOINT_SCORE_SIEVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v16-adapter-v1"
JOINT_SCORE_SIEVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v13"
JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _v15.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA = _v15.JOINT_SCORE_SIEVE_RESULT_SCHEMA
JOINT_SCORE_SIEVE_V15_RELEASE_PARENT_SCHEMA = (
    _v15.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
)
JOINT_SCORE_SIEVE_BOUND_RULE = _v15.JOINT_SCORE_SIEVE_BOUND_RULE
JointScoreSieveExecutionError = _v15.JointScoreSieveExecutionError
write_joint_score_sieve_grouping = _v15.write_joint_score_sieve_grouping
write_joint_score_sieve_potential = _v15.write_joint_score_sieve_potential

VAULT_RANKED_DECISION_READER_SCHEMA = _v15.VAULT_RANKED_DECISION_READER_SCHEMA
VAULT_RELEASE_CONTRAST_OPERATOR = _v15.VAULT_RELEASE_CONTRAST_OPERATOR
VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES = (
    _v15.VAULT_RELEASE_CONTRAST_POLICY_SPEC_BYTES
)
VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256 = (
    _v15.VAULT_RELEASE_CONTRAST_POLICY_SPEC_SHA256
)

_TOP_LEVEL_FIELDS = _v15._TOP_LEVEL_FIELDS | {"rank_source_vault_sha256"}


@dataclass(frozen=True)
class JointScoreSieveV16Result(_v15.JointScoreSieveV15Result):
    """A v15-validated result retaining the independent rank-source vault."""

    rank_source_vault: ThresholdNoGoodVault

    @property
    def rank_source_vault_sha256(self) -> str:
        return self.rank_source_vault.sha256


def __getattr__(name: str) -> object:
    """Expose the unchanged v15 public surface without copying implementation."""

    try:
        return getattr(_v15, name)
    except AttributeError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc


def _sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1RelationalSearchError(f"joint-score-sieve-v16 {field} differs")
    return value


def validate_native_lifecycle(payload: Mapping[str, object]) -> dict[str, int | str]:
    """Validate v13 provenance, then apply the frozen v15 lifecycle rules."""

    if (
        not isinstance(payload, Mapping)
        or payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 lifecycle contract differs"
        )
    _sha256(payload.get("rank_source_vault_sha256"), field="rank source hash")
    projected = dict(payload)
    projected.pop("rank_source_vault_sha256")
    projected["schema"] = _v15.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_V15_RELEASE_PARENT_SCHEMA
    )
    return _v15.validate_native_lifecycle(projected)


def _promote_result(
    result: _v15.JointScoreSieveV15Result,
    *,
    raw: Mapping[str, object],
    rank_source_vault: ThresholdNoGoodVault,
) -> JointScoreSieveV16Result:
    return JointScoreSieveV16Result(
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
        rank_source_vault=rank_source_vault,
    )


def _parse_native_payload(
    payload: object,
    *,
    input_vault: ThresholdNoGoodVault,
    rank_source_vault: ThresholdNoGoodVault,
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
) -> JointScoreSieveV16Result:
    """Validate v13's split provenance before frozen v15 normalization."""

    if not isinstance(payload, Mapping) or set(payload) != _TOP_LEVEL_FIELDS:
        raise O1RelationalSearchError("joint-score-sieve-v16 result fields differ")
    rank_source_sha256 = _sha256(
        payload.get("rank_source_vault_sha256"), field="rank source hash"
    )
    reader = payload.get("reader")
    vault = payload.get("vault")
    if (
        payload.get("schema") != JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or payload.get("implementation_parent_schema")
        != JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or payload.get("implementation_release_parent_schema")
        != JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or rank_source_sha256 != rank_source_vault.sha256
        or rank_source_vault.identity != input_vault.identity
        or not isinstance(reader, Mapping)
        or reader.get("source_vault_sha256") != rank_source_sha256
        or not isinstance(vault, Mapping)
        or vault.get("input_sha256") != input_vault.sha256
    ):
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 rank-source or active-vault identity differs"
        )

    projected = dict(payload)
    projected.pop("rank_source_vault_sha256")
    projected["schema"] = _v15.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    projected["implementation_release_parent_schema"] = (
        JOINT_SCORE_SIEVE_V15_RELEASE_PARENT_SCHEMA
    )
    try:
        parent = _v15._parse_native_payload(
            projected,
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
            require_active_contrast=require_active_contrast,
        )
    except O1RelationalSearchError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 native payload validation failed"
        ) from exc
    return _promote_result(
        parent, raw=payload, rank_source_vault=rank_source_vault
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
    try:
        vault = parse_threshold_no_good_vault(
            payload,
            observed_variables=field.observed_variables,
            caps=caps,
        )
        validate_threshold_no_good_vault_identity(vault, expected=expected_identity)
        _v15._v14._v13._v12._v11._v9._v8._certify_input_vault(
            vault,
            field=field,
            grouping=grouping,
            threshold=threshold,
        )
        return vault
    except (ThresholdNoGoodVaultError, O1RelationalSearchError) as exc:
        raise O1RelationalSearchError(
            f"joint-score-sieve-v16 {role} vault certification differs"
        ) from exc


def _run_joint_score_sieve_native_contract(
    *,
    executable: str | Path,
    cnf_path: str | Path,
    potential_path: str | Path,
    grouping_path: str | Path,
    rank_vault_path: str | Path,
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
) -> JointScoreSieveV16Result:
    """Run native v13 across independently frozen rank and active vaults."""

    requested = _v15._v14._v13._v12._v11._v9._requested_conflicts(
        conflict_limit
    )
    if not isinstance(vault_caps, VaultCaps) or vault_caps != O1C66_VAULT_CAPS:
        raise O1RelationalSearchError("joint-score-sieve-v16 native vault caps differ")
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
            "joint-score-sieve-v16 reader, threshold, timeout, or memory limit differs"
        )
    requested_threshold = float(threshold)
    io_v1 = _v15._v14._v13._v12._v11._v9._v8._v1
    io_v8 = _v15._v14._v13._v12._v11._v9._v8
    executable_file, executable_bytes, _ = io_v1._read_input(
        executable, "executable"
    )
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
    field = io_v1._potential(potential_bytes)
    grouping = io_v8._v7.validate_joint_score_sieve_grouping(
        field, grouping_bytes
    )
    if grouping.potential_sha256 != potential_sha:
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 grouping potential identity differs"
        )
    try:
        expected_decision = derive_production_vault_ranked_decision(
            rank_vault_bytes, potential_bytes, grouping_bytes
        )
    except VaultRankedDecisionError as exc:
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 sealed rank-source decision differs"
        ) from exc

    expected_identity = vault_identity_from_sources(
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
        expected_identity=expected_identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="rank-source",
    )
    input_vault = _parse_and_certify_vault(
        active_vault_bytes,
        field=field,
        grouping=grouping,
        expected_identity=expected_identity,
        threshold=requested_threshold,
        caps=vault_caps,
        role="active",
    )

    rank_path, rank_bytes = _v15._v14._v13._rank_table_temp(expected_decision)
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
        "--threshold",
        format(requested_threshold, ".17g"),
        "--conflict-limit",
        str(requested),
        "--seed",
        "0",
    ]
    execution_error: Exception | None = None
    execution: _v15._v14._v13._v12._v11._v9._v8._v7._NativeExecution | None
    try:
        try:
            execution = io_v8._v7._execute_native(
                command,
                timeout_seconds=float(timeout_seconds),
                memory_limit_bytes=memory_limit_bytes,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            execution_error = exc
            execution = None
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
                rank_vault_path,
                rank_vault_file,
                rank_vault_bytes,
                caps=vault_caps,
            )
            io_v8._verify_stable_vault_input(
                vault_path,
                active_vault_file,
                active_vault_bytes,
                caps=vault_caps,
            )
            if rank_path.read_bytes() != rank_bytes:
                raise O1RelationalSearchError(
                    "joint-score-sieve-v16 rank table changed during execution"
                )
        except Exception as exc:
            if execution is not None:
                _v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
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
                "joint-score-sieve-v16 rank table cleanup failed"
            ) from exc
    if execution_error is not None:
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 execution failed"
        ) from execution_error
    if execution is None:
        raise O1RelationalSearchError("joint-score-sieve-v16 execution failed")

    completed = execution.completed
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        failure = subprocess.CalledProcessError(
            completed.returncode,
            command,
            output=completed.stdout,
            stderr=completed.stderr,
        )
        _v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            failure,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            f"joint-score-sieve-v16 execution failed: {detail}"
        ) from failure

    try:
        payload = json.loads(completed.stdout)
        result = _parse_native_payload(
            payload,
            input_vault=input_vault,
            rank_source_vault=rank_source_vault,
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
            stats=_v15.derive_vault_soft_conflict_ledger(
                result.stats, requested_conflicts=requested
            ),
        )
    except json.JSONDecodeError as exc:
        _v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
            exc,
            command=command,
            completed=completed,
            memory_samples=execution.memory_samples,
        )
        raise O1RelationalSearchError(
            "joint-score-sieve-v16 result JSON is invalid"
        ) from exc
    except Exception as exc:
        _v15._v14._v13._v12._v11._v9._attach_native_process_evidence(
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
    rank_vault_path: str | Path,
    vault_path: str | Path,
    vault_caps: VaultCaps,
    threshold: float,
    conflict_limit: int,
    seed: int = 0,
    timeout_seconds: float = 60.0,
    memory_limit_bytes: int | None = None,
    require_active_contrast: bool = True,
) -> JointScoreSieveV16Result:
    """Run v13 with a sealed rank source and independent active projection."""

    started = time.perf_counter()
    try:
        return _run_joint_score_sieve_native_contract(
            executable=executable,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
            rank_vault_path=rank_vault_path,
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
        telemetry = _v15._v14._v13._v12._v11._v9._v8._v7._failure_telemetry(
            exc,
            elapsed_seconds=elapsed,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
        )
        message = str(exc)
        if not message.startswith("joint-score-sieve-v16"):
            message = f"joint-score-sieve-v16 adapter failed: {message}"
        raise JointScoreSieveExecutionError(
            message, failure_telemetry=telemetry
        ) from exc


validate_vault_ranked_decision_reader = (
    _v15.validate_vault_ranked_decision_reader
)
validate_vault_release_contrast_ranked_decision_reader = (
    _v15.validate_vault_release_contrast_ranked_decision_reader
)
vault_release_contrast_policy_spec_bytes = (
    _v15.vault_release_contrast_policy_spec_bytes
)

__all__ = [  # pyright: ignore[reportUnsupportedDunderAll]
    *(
        name
        for name in _v15.__all__
        if name
        not in {
            "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
            "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
            "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
            "JointScoreSieveV15Result",
            "run_joint_score_sieve",
            "validate_native_lifecycle",
        }
    ),
    "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA",
    "JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA",
    "JOINT_SCORE_SIEVE_RESULT_SCHEMA",
    "JOINT_SCORE_SIEVE_V15_RELEASE_PARENT_SCHEMA",
    "JointScoreSieveV16Result",
    "run_joint_score_sieve",
    "validate_native_lifecycle",
]
