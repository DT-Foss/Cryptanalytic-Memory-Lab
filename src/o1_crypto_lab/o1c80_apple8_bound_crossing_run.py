"""Burn-on-intent O1C-0080 exact one-bit bound-crossing runner.

The runner consumes only the prepared Page 7 / local 0 / lineage 20 input and
permits one 128-conflict native call.  Exact probe operation, threshold-crossing
activation, and attacker-valid science gain are reported as independent axes.
Raw native stdout is archived byte-for-byte; promoted JSON views never replace
that primary evidence.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import resource
import shlex
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v21 as _native_v21
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from . import o1c79_apple8_decision_ownership_run as _publication_base
from .causal_attic_v1 import canonical_json_bytes, parse_vault_telemetry, sha256_bytes
from .causal_residency_v1 import CausalResidencyError, validate_activation_replay
from .joint_score_sieve_v9 import validate_vault_soft_conflict_ledger
from .o1c80_apple8_bound_crossing_prepare import (
    ACTIVATION_LEDGER_NAME,
    ACTIVE_PROJECTION_NAME,
    CHUNK_NAMES,
    DEFAULT_PARENT_CAPSULE_RELATIVE,
    DEFAULT_PARENT_ERRATUM_RELATIVE,
    DEFAULT_PARENT_RESULT_RELATIVE,
    EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256,
    EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256,
    EXPECTED_PREPARED_MANIFEST_SHA256,
    EXPECTED_SCIENCE_INPUT_SHA256,
    EXPECTED_STAGING_PLAN_DOCUMENT_SHA256,
    FRONTIER_PLAN_BINARY_BYTES,
    FRONTIER_PLAN_BINARY_NAME,
    FRONTIER_PLAN_BINARY_SHA256,
    FRONTIER_PLAN_NAME,
    MANIFEST_NAME as PREPARED_MANIFEST_NAME,
    OCCURRENCES_NAME,
    PAGE6_SHA256,
    PAGE7_CLAUSE_COUNT,
    PAGE7_LITERAL_COUNT,
    PAGE7_SELECTION_ORDER_SHA256,
    PAGE7_SERIALIZED_BYTES,
    PAGE7_SHA256,
    PARENT_CAPSULE_MANIFEST_SHA256,
    PARENT_CORRECTED_CLASSIFICATION,
    PARENT_ERRATUM_SHA256,
    PARENT_RECEIPT_NAME,
    PARENT_RESULT_SHA256,
    PARENT_SOURCE_COMMIT,
    PREFIX_PLAN_BINARY_BYTES,
    PREFIX_PLAN_BINARY_NAME,
    PREFIX_PLAN_BINARY_SHA256,
    PREFIX_PLAN_NAME,
    PreparedBoundCrossing,
    RELATIONS_NAME,
    RESIDENCY_NAME,
    SCIENCE_HISTORY_NAME,
    SCIENCE_INPUT_NAME,
    SCIENCE_INPUT_SHA256_HISTORY,
    STAGING_PLAN_BINARY_BYTES,
    STAGING_PLAN_BINARY_NAME,
    STAGING_PLAN_BINARY_SHA256,
    STAGING_PLAN_NAME,
    load_prepared_bound_crossing,
)
from .threshold_no_good_vault_v1 import O1C66_VAULT_CAPS, ThresholdNoGoodVault


ATTEMPT_ID = "O1C-0080"
CONFIG_SCHEMA = "o1-256-apple8-bound-crossing-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-bound-crossing-preflight-v1"
TARGET_FREE_GATE_SCHEMA = "o1-256-o1c80-target-free-bound-crossing-preflight-v1"
TARGET_FREE_GATE_PENDING = (
    "O1C80_TARGET_FREE_BOUND_CROSSING_PREFLIGHT_PENDING_NATIVE_FREEZE"
)
TARGET_FREE_GATE_PASS = "O1C80_TARGET_FREE_BOUND_CROSSING_PREFLIGHT_PASS"
INVOCATION_SCHEMA = "o1-256-apple8-bound-crossing-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-bound-crossing-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-bound-crossing-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-bound-crossing-result-v1"
RECOVERY_SOURCE_SCHEMA = "o1-256-apple8-bound-crossing-pre-finalization-source-v1"
PUBLICATION_RECOVERY_SCHEMA = "o1-256-apple8-bound-crossing-publication-recovery-v1"
RECOVERED_PUBLICATION_SOURCE_SCHEMA = (
    "o1-256-apple8-bound-crossing-recovered-finalization-source-v1"
)
NATIVE_SOURCE_CLOSURE_SCHEMA = "o1-256-native-source-include-closure-v1"
RAW_STDOUT_EVIDENCE_SCHEMA = "o1-256-byte-exact-native-stdout-evidence-v1"
PROMOTED_JSON_EVIDENCE_SCHEMA = "o1-256-promoted-canonical-json-evidence-v1"

CONFIG_RELATIVE = Path("configs/o1c80_apple8_bound_crossing_v1.json")
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0080_TARGET_FREE_BOUND_CROSSING_PREFLIGHT_20260720.json"
)
RESULT_RELATIVE = Path("research/O1C0080_APPLE8_BOUND_CROSSING_RESULT_20260720.json")
CAPSULE_SUFFIX = "O1C-0080_apple8-bound-crossing-v1"
RECOVERY_SOURCE_NAME = "pre-finalization-recovery-source.json"
PUBLICATION_RECOVERY_NAME = "publication-recovery.json"
PREPARATION_DIRECTORY_RELATIVE = Path("research/o1c80_bound_crossing_seed_20260720")

PARENT_RESULT_RELATIVE = DEFAULT_PARENT_RESULT_RELATIVE
PARENT_CAPSULE_RELATIVE = DEFAULT_PARENT_CAPSULE_RELATIVE
PARENT_ERRATUM_RELATIVE = DEFAULT_PARENT_ERRATUM_RELATIVE
PARENT_LAST_LINEAGE_ORDINAL = 19
PARENT_CLASSIFICATION = PARENT_CORRECTED_CLASSIFICATION

RANK_SOURCE_SHA256 = "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
ACTIVE_CLAUSE_LIMIT = 256
LOCAL_EPISODES = (0,)
LINEAGE_ORDINALS = (20,)
REQUESTED_CONFLICTS_PER_EPISODE = 128
MAXIMUM_NATIVE_SOLVER_CALLS = 1
MAXIMUM_TOTAL_REQUESTED_CONFLICTS = 128
SEED = 0
THRESHOLD = 14.606178797892962
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 134_217_728
MINIMUM_DISK_FREE_BYTES = 1_073_741_824

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
THRESHOLD_REGION_EXHAUSTED = "THRESHOLD_REGION_EXHAUSTED"
BOTH_CHILD_CLOSURE_GAIN = "BOUND_CROSSING_BOTH_CHILD_CLOSURE_GAIN"
REALIZED_PRUNE_GAIN = "BOUND_CROSSING_REALIZED_PRUNE_GAIN"
NOVEL_CLAUSE_GAIN = "BOUND_CROSSING_NOVEL_CLAUSE_GAIN"
CROSSING_MECHANISM_ONLY = "BOUND_CROSSING_MECHANISM_ONLY"
PROBE_OPERATION_ONLY = "BOUND_PROBE_OPERATION_ONLY"
NO_OPERATION = "BOUND_CROSSING_NO_OPERATION_NO_GAIN"
OPERATIONAL_TERMINAL = "BOUND_CROSSING_OPERATIONAL_TERMINAL"

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c80_apple8_bound_crossing_run.py",
    "adapter_v21": "src/o1_crypto_lab/joint_score_sieve_v21.py",
    "adapter_v21_fixture_tests": "tests/test_joint_score_sieve_v21.py",
    "preparation": "src/o1_crypto_lab/o1c80_apple8_bound_crossing_prepare.py",
    "preparation_fixture_tests": "tests/test_o1c80_apple8_bound_crossing_prepare.py",
    "runner_fixture_tests": "tests/test_o1c80_apple8_bound_crossing_run.py",
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency_v1": "src/o1_crypto_lab/causal_residency_v1.py",
    "causal_frontier_v1": "src/o1_crypto_lab/causal_frontier_v1.py",
    "residual_polarity_staging_v1": "src/o1_crypto_lab/residual_polarity_staging_v1.py",
    "rescue_prefix_preemption_v1": "src/o1_crypto_lab/rescue_prefix_preemption_v1.py",
    "threshold_no_good_vault_v1": "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
    "native_v18": "native/cadical_o1_joint_score_sieve_v18.cpp",
    "one_bit_bound_header": "native/o1c80_one_bit_bound.hpp",
    "decision_ownership_header": "native/o1c80_decision_ownership.hpp",
    "native_v16": "native/cadical_o1_joint_score_sieve_v16.cpp",
    "native_v15": "native/cadical_o1_joint_score_sieve_v15.cpp",
    "native_v14": "native/cadical_o1_joint_score_sieve_v14.cpp",
    "native_v12": "native/cadical_o1_joint_score_sieve_v12.cpp",
    "native_v11": "native/cadical_o1_joint_score_sieve_v11.cpp",
    "native_v6": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "native_base": "native/cadical_o1_joint_score_sieve.cpp",
    "native_fixture_tests": "tests/test_o1c80_native_one_bit_bound.py",
}
NATIVE_INCLUDE_CLOSURE = (
    "native_v18",
    "one_bit_bound_header",
    "decision_ownership_header",
    "native_v16",
    "native_v15",
    "native_v14",
    "native_v12",
    "native_v11",
    "native_v6",
    "native_base",
)
SOURCE_FREEZE_GUARD_PATHS = ("src/o1_crypto_lab", "native")


class O1C80RunError(RuntimeError):
    """A frozen Page-7 input, one-call ledger, or evidence seal differs."""


class EpisodeInvoker(Protocol):
    def __call__(
        self,
        local_ordinal: int,
        lineage_ordinal: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
        prefix_plan: Path,
        /,
    ) -> object:
        """Consume the sole predeclared native subprocess call."""


@dataclass(frozen=True)
class BoundCrossingOutcome:
    classification: str
    stop_reason: str
    episodes: tuple[Mapping[str, object], ...]
    native_calls: int
    requested_conflicts: int
    actual_conflicts: int | None
    billed_conflicts: int | None
    exact_probe_operation: bool
    crossing_activation: bool
    science_gain: bool
    globally_novel_clauses: int
    realized_prunes: int
    fully_emitted_prunes: int
    both_child_closures: int
    operational_failure: Mapping[str, object] | None


EpisodeOutcome = BoundCrossingOutcome
StreamOutcome = BoundCrossingOutcome


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C80RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C80RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C80RunError(f"{field} differs")
    return value


def _sha256(value: object, field: str, *, pending: bool = False) -> str:
    if pending and value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C80RunError(f"{field} differs")
    return value


def _commit(value: object, field: str, *, pending: bool = False) -> str:
    if pending and value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C80RunError(f"{field} differs")
    return value


def _relative_contract(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C80RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C80RunError(f"{field} escapes the lab")
    return path.as_posix()


def _relative(root: Path, value: object, field: str) -> Path:
    relative = Path(_relative_contract(value, field))
    try:
        path = (root / relative).resolve(strict=True)
    except OSError as exc:
        raise O1C80RunError(f"{field} cannot be resolved") from exc
    if not path.is_relative_to(root):
        raise O1C80RunError(f"{field} escapes the lab")
    return path


def _regular(path: Path, field: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise O1C80RunError(f"{field} cannot be read") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise O1C80RunError(f"{field} is not a regular file")
    return path


def _base_call(function: Callable[[], object]) -> object:
    try:
        return function()
    except Exception as exc:
        if isinstance(exc, O1C80RunError):
            raise
        raise O1C80RunError(str(exc)) from exc


def _atomic_create(path: Path, payload: bytes, *, immutable: bool = False) -> None:
    _base_call(
        lambda: _publication_base._atomic_create(path, payload, immutable=immutable)
    )


def _atomic_json(path: Path, value: object, *, immutable: bool = False) -> None:
    _atomic_create(path, canonical_json_bytes(value), immutable=immutable)


def _sha256_file(path: Path) -> str:
    return cast(str, _base_call(lambda: _publication_base._sha256_file(path)))


def _artifact_row(path: Path, *, relative_to: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        _base_call(
            lambda: _publication_base._artifact_row(path, relative_to=relative_to)
        ),
    )


def _validate_artifact_row(root: Path, value: object, field: str) -> Path:
    return cast(
        Path,
        _base_call(
            lambda: _publication_base._validate_artifact_row(root, value, field)
        ),
    )


def _validate_capsule_tree(capsule: Path) -> None:
    _base_call(lambda: _publication_base._validate_capsule_tree(capsule))


def validate_native_executable(
    path: str | Path, *, expected_sha256: str
) -> dict[str, object]:
    return cast(
        dict[str, object],
        _base_call(
            lambda: _publication_base.validate_native_executable(
                path, expected_sha256=expected_sha256
            )
        ),
    )


def _copy_immutable(path: Path, payload: bytes) -> dict[str, object]:
    _atomic_create(path, payload, immutable=True)
    return _artifact_row(path, relative_to=path.parent)


def _prepared_rank_source(prepared: PreparedBoundCrossing) -> ThresholdNoGoodVault:
    try:
        rank = prepared.state.attic.chunks[0]
    except (AttributeError, IndexError) as exc:
        raise O1C80RunError("prepared rank source differs") from exc
    if not isinstance(rank, ThresholdNoGoodVault):
        raise O1C80RunError("prepared rank source differs")
    return rank


def _validate_prepared_contract(
    prepared: PreparedBoundCrossing, *, require_frozen: bool = True
) -> None:
    if not isinstance(prepared, PreparedBoundCrossing):
        raise O1C80RunError("prepared bound-crossing input differs")
    state = prepared.state
    active = state.active_projection
    rank = _prepared_rank_source(prepared)
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C80RunError("prepared residency replay differs") from exc
    if (
        state.current_projection.lineage_ordinal != LINEAGE_ORDINALS[0]
        or active.clause_count > ACTIVE_CLAUSE_LIMIT
        or rank.identity != active.identity
        or prepared.frontier_plan.active_vault_sha256 != active.sha256
        or prepared.staging_plan.active_vault_sha256 != active.sha256
        or prepared.staging_plan.parent_frontier_plan_sha256
        != prepared.frontier_plan.sha256
    ):
        raise O1C80RunError("prepared Page-7 plan composition differs")
    history = prepared.science_input_history
    entries = tuple(
        _sha256(item, "science-input history entry")
        for item in _sequence(history.get("science_input_sha256"), "science history")
    )
    if (
        entries != SCIENCE_INPUT_SHA256_HISTORY
        or entries[-1] != PAGE6_SHA256
        or PAGE7_SHA256 in entries
        or history.get("next_active_sha256") != active.sha256
        or history.get("next_lineage_ordinal") != 20
        or history.get("page6_replay_authorized") is not False
        or history.get("retry_authorized") is not False
        or prepared.science_input.get("active_vault_sha256") != active.sha256
        or prepared.science_input.get("lineage_call_ordinal") != 20
        or prepared.science_input.get("science_call_authorized") is not False
        or prepared.science_input.get("intent_created") is not False
        or prepared.science_input.get("page_burned") is not False
    ):
        raise O1C80RunError("prepared Page-7 science-input history differs")
    if not require_frozen:
        return
    directory = prepared.directory
    checks = {
        FRONTIER_PLAN_BINARY_NAME: (
            FRONTIER_PLAN_BINARY_SHA256,
            FRONTIER_PLAN_BINARY_BYTES,
        ),
        STAGING_PLAN_BINARY_NAME: (
            STAGING_PLAN_BINARY_SHA256,
            STAGING_PLAN_BINARY_BYTES,
        ),
        PREFIX_PLAN_BINARY_NAME: (PREFIX_PLAN_BINARY_SHA256, PREFIX_PLAN_BINARY_BYTES),
        FRONTIER_PLAN_NAME: (EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256, None),
        STAGING_PLAN_NAME: (EXPECTED_STAGING_PLAN_DOCUMENT_SHA256, None),
        PREFIX_PLAN_NAME: (EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256, None),
        SCIENCE_INPUT_NAME: (EXPECTED_SCIENCE_INPUT_SHA256, None),
    }
    for name, (digest, size) in checks.items():
        path = _regular(directory / name, f"prepared {name}")
        if _sha256_file(path) != digest or (
            size is not None and path.stat().st_size != size
        ):
            raise O1C80RunError(f"prepared {name} seal differs")
    if (
        prepared.manifest_sha256 != EXPECTED_PREPARED_MANIFEST_SHA256
        or sha256_bytes(prepared.manifest_bytes) != EXPECTED_PREPARED_MANIFEST_SHA256
        or active.sha256 != PAGE7_SHA256
        or active.clause_count != PAGE7_CLAUSE_COUNT
        or active.literal_count != PAGE7_LITERAL_COUNT
        or active.serialized_bytes != PAGE7_SERIALIZED_BYTES
        or state.current_projection.describe().get("selection_order_sha256")
        != PAGE7_SELECTION_ORDER_SHA256
        or rank.sha256 != RANK_SOURCE_SHA256
        or prepared.frontier_plan.sha256 != FRONTIER_PLAN_BINARY_SHA256
        or prepared.staging_plan.sha256 != STAGING_PLAN_BINARY_SHA256
        or prepared.prefix_plan.sha256 != PREFIX_PLAN_BINARY_SHA256
    ):
        raise O1C80RunError("frozen prepared Page-7 identities differ")


def _candidate_order(prepared: PreparedBoundCrossing) -> tuple[tuple[int, ...], int]:
    observed = set(prepared.state.active_projection.observed_variables)
    candidates: list[int] = []
    seen: set[int] = set()
    for literal in prepared.staging_plan.effective_rank_literals:
        variable = abs(literal)
        if 1 <= variable <= 256 and variable in observed and variable not in seen:
            candidates.append(variable)
            seen.add(variable)
    ranked = len(candidates)
    candidates.extend(
        variable
        for variable in range(1, 257)
        if variable in observed and variable not in seen
    )
    if not candidates or len(set(candidates)) != len(candidates):
        raise O1C80RunError("Page-7 one-bit candidate order differs")
    return tuple(candidates), ranked


def _raw_stdout_bytes(result: object) -> bytes:
    value = getattr(result, "native_stdout", None)
    if isinstance(value, str):
        try:
            payload = value.encode("utf-8")
        except UnicodeError as exc:
            raise O1C80RunError("native raw stdout encoding differs") from exc
    elif isinstance(value, bytes):
        payload = value
    else:
        raise O1C80RunError("adapter did not preserve native stdout bytes")
    reported = getattr(result, "native_stdout_sha256", None)
    if _sha256(reported, "adapter native stdout digest") != sha256_bytes(payload):
        raise O1C80RunError("adapter native stdout digest differs")
    return payload


def _science_gain_evidence(
    *,
    status: int,
    public_model_verified: bool,
    realized_prunes: int,
    fully_emitted_prunes: int,
    both_child_closures: int,
    globally_novel_clauses: int,
    minimum_child_upper: object,
) -> dict[str, object]:
    formal_exhaustion = status == 20
    gain = (
        public_model_verified
        or formal_exhaustion
        or realized_prunes > 0
        or fully_emitted_prunes > 0
        or both_child_closures > 0
        or globally_novel_clauses > 0
    )
    return {
        "science_gain": gain,
        "public_complete_model_verified": public_model_verified,
        "formal_threshold_region_exhaustion": formal_exhaustion,
        "realized_v6_losing_child_prunes": realized_prunes,
        "fully_emitted_exact_no_goods": fully_emitted_prunes,
        "rigorously_validated_both_child_closures": both_child_closures,
        "globally_novel_exact_threshold_no_goods": globally_novel_clauses,
        "minimum_child_upper": minimum_child_upper,
        "lower_minimum_alone_is_science_gain": False,
        "probe_operation_alone_is_science_gain": False,
        "crossing_proposal_alone_is_science_gain": False,
        "decision_or_trace_change_alone_is_science_gain": False,
    }


def _validated_episode_result(
    result: object,
    *,
    prepared: PreparedBoundCrossing,
    active: ThresholdNoGoodVault,
    stream_id: str,
    verify_public_model: Callable[[bytes], bool],
    require_concrete_result: bool,
) -> dict[str, object]:
    """Bind one adapter-v21 return to Page 7 and validate all three axes."""

    try:
        if require_concrete_result and not isinstance(
            result, _native_v21.JointScoreSieveV21Result
        ):
            raise O1C80RunError("native v21 result type differs")
        raw = _mapping(getattr(result, "raw"), "native raw result")
        raw_stdout = _raw_stdout_bytes(result)
        decoded = _native_v21.load_native_json(raw_stdout)
        if decoded != raw:
            raise O1C80RunError("native raw stdout/result projection differs")
        central = _mapping(getattr(result, "central_reader"), "central reader")
        ownership = _mapping(
            getattr(result, "decision_ownership"), "decision ownership"
        )
        reader = _mapping(
            getattr(result, "one_bit_bound_reader"), "one-bit bound reader"
        )
        telemetry = _mapping(getattr(result, "vault_telemetry"), "vault telemetry")
        stats = validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native conflict ledger")
        )
        resources = _mapping(getattr(result, "resources"), "native resources")
        sieve = _mapping(getattr(result, "sieve"), "native sieve")
        status = getattr(result, "status")
        key_model = getattr(result, "key_model")
        rank = _prepared_rank_source(prepared)
        if (
            isinstance(status, bool)
            or status not in (0, 10, 20)
            or getattr(result, "conflict_limit") != REQUESTED_CONFLICTS_PER_EPISODE
            or getattr(result, "threshold") != THRESHOLD
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS_PER_EPISODE
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or getattr(result, "rank_source_vault") != rank
            or getattr(result, "input_vault") != active
            or getattr(result, "frontier_plan") != prepared.frontier_plan
            or getattr(result, "staging_plan") != prepared.staging_plan
            or getattr(result, "prefix_preemption_plan") != prepared.prefix_plan
            or raw.get("central_reader") != central
            or raw.get("decision_ownership") != ownership
            or raw.get("one_bit_bound_reader") != reader
            or raw.get("vault") != telemetry
            or raw.get("sieve") != sieve
            or central.get("schema") != _native_v21.CENTRAL_READER_SCHEMA
            or ownership.get("schema") != _native_v21.DECISION_OWNERSHIP_SCHEMA
            or reader.get("schema") != _native_v21.ONE_BIT_BOUND_READER_SCHEMA
        ):
            raise O1C80RunError("native v21 Page-7 binding differs")
        if (
            require_concrete_result
            and raw.get("schema") != _native_v21.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        ):
            raise O1C80RunError("native v18 result schema differs")
        if raw.get("schema") == _native_v21.JOINT_SCORE_SIEVE_RESULT_SCHEMA:
            _native_v21.validate_native_lifecycle(raw)
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        if peak > MEMORY_LIMIT_BYTES or wall > int(TIMEOUT_SECONDS * 1_000_000):
            raise O1C80RunError("native resource boundary differs")
        if _nonnegative_int(sieve.get("pending_clause_count"), "pending clause count"):
            raise O1C80RunError("native result retained an incomplete clause")

        candidates, ranked_count = _candidate_order(prepared)
        bound = _native_v21.validate_one_bit_bound_reader(
            reader,
            decision_ownership=ownership,
            sieve=sieve,
            vault=telemetry,
            threshold=THRESHOLD,
            candidate_order=candidates,
            ranked_candidate_count=ranked_count,
        )
        attached = getattr(result, "one_bit_bound_validation", None)
        if require_concrete_result and attached != bound:
            raise O1C80RunError("adapter/runner bound validation differs")

        telemetry_payload = canonical_json_bytes(telemetry)
        parsed = parse_vault_telemetry(
            telemetry_payload,
            stream_id=stream_id,
            expected_sha256=sha256_bytes(telemetry_payload),
        )
        if (
            parsed.input_identity != active.identity
            or parsed.input_vault_sha256 != active.sha256
            or parsed.input_clause_count != active.clause_count
            or parsed.input_literal_count != active.literal_count
            or parsed.input_serialized_bytes != active.serialized_bytes
            or parsed.input_clause_aggregate_sha256 != active.clause_aggregate_sha256
        ):
            raise O1C80RunError("native emission ledger Page-7 input differs")
        globally_known = {
            clause.serialized for clause in prepared.state.attic.union_vault.clauses
        }
        globally_novel: list[str] = []
        for occurrence in parsed.occurrences:
            serialized = occurrence.clause.serialized
            if serialized not in globally_known:
                if occurrence.classification != "new":
                    raise O1C80RunError(
                        "globally novel no-good lacks new classification"
                    )
                globally_known.add(serialized)
                globally_novel.append(occurrence.clause_sha256)
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C80RunError("public candidate failed exact public verification")
            public_verified = True
        else:
            if key_model is not None:
                raise O1C80RunError("non-SAT result returned a candidate")
            public_verified = False
        class_counts = _mapping(reader.get("class_counts"), "bound class counts")
        both_closures = _nonnegative_int(
            class_counts.get("BOTH_PRUNABLE"), "both-child closures"
        )
        minimum = reader.get("minimum_child_upper")
        exact_probe = {
            "exact_probe_operation": bound.probe_count > 0,
            "probe_count": bound.probe_count,
            "recorded_probe_count": bound.recorded_probe_count,
            "child_bound_evaluations": 2 * bound.probe_count,
            "same_parent_exact_U0_U1_validated": True,
            "minimum_child_upper": minimum,
            "minimum_child_upper_alone_is_activation": False,
            "minimum_child_upper_alone_is_science_gain": False,
        }
        crossing = {
            "crossing_activation": bound.crossing_count > 0,
            "crossing_count": bound.crossing_count,
            "intervention_count": bound.intervention_count,
            "selection_classes": dict(class_counts),
            "strict_U_less_than_tau": True,
            "equality_is_live": True,
            "probe_count_alone_is_crossing_activation": False,
        }
        science = _science_gain_evidence(
            status=cast(int, status),
            public_model_verified=public_verified,
            realized_prunes=bound.realized_prune_count,
            fully_emitted_prunes=bound.fully_emitted_count,
            both_child_closures=both_closures,
            globally_novel_clauses=len(globally_novel),
            minimum_child_upper=minimum,
        )
        return {
            "raw": dict(raw),
            "raw_stdout": raw_stdout,
            "central_reader": dict(central),
            "decision_ownership": dict(ownership),
            "one_bit_bound_reader": dict(reader),
            "telemetry": dict(telemetry),
            "occurrences": parsed.occurrences,
            "stats": stats,
            "resources": {
                "peak_rss_bytes": peak,
                "wall_microseconds": wall,
                "cpu_microseconds": cpu,
            },
            "status": status,
            "key_model": key_model,
            "globally_novel_clause_sha256": globally_novel,
            "realized_prunes": bound.realized_prune_count,
            "fully_emitted_prunes": bound.fully_emitted_count,
            "both_child_closures": both_closures,
            "exact_probe": exact_probe,
            "crossing": crossing,
            "science": science,
        }
    except O1C80RunError:
        raise
    except Exception as exc:
        raise O1C80RunError("native O1C-0080 result differs") from exc


def _write_bytes_evidence(
    path: Path, payload: bytes, *, schema: str
) -> dict[str, object]:
    if not isinstance(payload, bytes):
        raise O1C80RunError("evidence payload differs")
    compressed = gzip.compress(payload, compresslevel=9, mtime=0)
    _atomic_create(path, compressed, immutable=True)
    return {
        "schema": schema,
        "path": path.name,
        "compression": "gzip-9;mtime=0",
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256_bytes(compressed),
        "uncompressed_bytes": len(payload),
        "uncompressed_sha256": sha256_bytes(payload),
    }


def _write_raw_evidence(path: Path, payload: bytes) -> dict[str, object]:
    return _write_bytes_evidence(path, payload, schema=RAW_STDOUT_EVIDENCE_SCHEMA)


def _write_json_evidence(path: Path, value: object) -> dict[str, object]:
    return _write_bytes_evidence(
        path, canonical_json_bytes(value), schema=PROMOTED_JSON_EVIDENCE_SCHEMA
    )


def _read_bytes_evidence(
    base: Path, row_value: object, field: str, *, schema: str
) -> bytes:
    row = _mapping(row_value, field)
    if (
        set(row)
        != {
            "schema",
            "path",
            "compression",
            "compressed_bytes",
            "compressed_sha256",
            "uncompressed_bytes",
            "uncompressed_sha256",
        }
        or row.get("schema") != schema
        or row.get("compression") != "gzip-9;mtime=0"
    ):
        raise O1C80RunError(f"{field} envelope differs")
    name = row.get("path")
    if not isinstance(name, str) or Path(name).name != name:
        raise O1C80RunError(f"{field} path differs")
    path = _regular(base / name, field)
    compressed = path.read_bytes()
    if len(compressed) != _nonnegative_int(
        row.get("compressed_bytes"), field
    ) or sha256_bytes(compressed) != _sha256(row.get("compressed_sha256"), field):
        raise O1C80RunError(f"{field} compressed seal differs")
    try:
        payload = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C80RunError(f"{field} gzip differs") from exc
    if len(payload) != _nonnegative_int(
        row.get("uncompressed_bytes"), field
    ) or sha256_bytes(payload) != _sha256(row.get("uncompressed_sha256"), field):
        raise O1C80RunError(f"{field} raw seal differs")
    return payload


def _read_json_evidence(base: Path, row: object, field: str) -> Mapping[str, object]:
    payload = _read_bytes_evidence(
        base, row, field, schema=PROMOTED_JSON_EVIDENCE_SCHEMA
    )
    try:
        value = _mapping(json.loads(payload), field)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C80RunError(f"{field} JSON differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C80RunError(f"{field} promoted JSON is not canonical")
    return value


def _initial_artifacts(
    capsule: Path, prepared: PreparedBoundCrossing
) -> dict[str, object]:
    initial = capsule / "initial"
    if initial.exists() or initial.is_symlink():
        raise O1C80RunError("initial bound-crossing directory already exists")
    initial.mkdir(parents=True)
    source_names = sorted(path.name for path in prepared.directory.iterdir())
    expected_names = {
        *CHUNK_NAMES,
        ACTIVE_PROJECTION_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        ACTIVATION_LEDGER_NAME,
        RESIDENCY_NAME,
        PARENT_RECEIPT_NAME,
        SCIENCE_HISTORY_NAME,
        SCIENCE_INPUT_NAME,
        FRONTIER_PLAN_NAME,
        FRONTIER_PLAN_BINARY_NAME,
        STAGING_PLAN_NAME,
        STAGING_PLAN_BINARY_NAME,
        PREFIX_PLAN_NAME,
        PREFIX_PLAN_BINARY_NAME,
        PREPARED_MANIFEST_NAME,
    }
    if set(source_names) != expected_names:
        raise O1C80RunError("prepared Page-7 inventory differs")
    rows: dict[str, object] = {}
    for name in source_names:
        source = _regular(prepared.directory / name, f"prepared artifact {name}")
        rows[name] = _copy_immutable(initial / name, source.read_bytes())
    rows["residency_document"] = prepared.state.describe()
    return rows


def _invocation_document(
    prepared: PreparedBoundCrossing,
    initial_rows: Mapping[str, object],
    bindings: Mapping[str, object],
) -> dict[str, object]:
    candidates, ranked = _candidate_order(prepared)
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "rank_source_vault": _prepared_rank_source(prepared).describe(),
        "active_page7_vault": prepared.state.active_projection.describe(),
        "residency": prepared.state.describe(),
        "frontier_plan": prepared.frontier_plan.describe(),
        "staging_plan": prepared.staging_plan.describe(),
        "prefix_plan": prepared.prefix_plan.describe(),
        "one_bit_candidate_order": list(candidates),
        "ranked_candidate_count": ranked,
        "science_input": dict(prepared.science_input),
        "initial_artifacts": dict(initial_rows),
        "local_episode_ordinals": list(LOCAL_EPISODES),
        "lineage_call_ordinals": list(LINEAGE_ORDINALS),
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
        "bindings": dict(bindings),
        "retry_authorized": False,
        "sweep_authorized": False,
        "replay_authorized": False,
        "truth_key_bytes_read": False,
    }


def _executable_binding(bindings: Mapping[str, object]) -> Mapping[str, object] | None:
    value = bindings.get("native_executable")
    if value is None:
        return None
    binding = _mapping(value, "native executable binding")
    if not isinstance(binding.get("path"), str):
        raise O1C80RunError("native executable binding path differs")
    _sha256(binding.get("sha256"), "native executable binding digest")
    return binding


def _validate_call_window_executable(
    binding: Mapping[str, object] | None, *, when: str
) -> None:
    if binding is None:
        return
    observed = validate_native_executable(
        cast(str, binding["path"]), expected_sha256=cast(str, binding["sha256"])
    )
    if observed != binding:
        raise O1C80RunError(f"native executable changed {when} call")


def _native_failure(exc: BaseException) -> dict[str, object]:
    try:
        return cast(dict[str, object], _publication_base._o1c78_native_failure(exc))
    except Exception:
        return {
            "exception_type": type(exc).__name__,
            "message": str(exc),
            "native_process_evidence": None,
        }


def _failure_episode(
    *,
    episode_dir: Path,
    invocation_sha256: str,
    intent_sha256: str,
    active: ThresholdNoGoodVault,
    prepared: PreparedBoundCrossing,
    exc: BaseException,
    phase: str,
    native_call_issued: bool,
    native_result_returned: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    if phase not in {"PRE_CALL", "CALL", "POST_CALL"}:
        raise O1C80RunError("failure phase differs")
    calls = int(native_call_issued)
    requested = calls * REQUESTED_CONFLICTS_PER_EPISODE
    failure = {
        "classification": OPERATIONAL_TERMINAL,
        "phase": phase,
        "local_episode_ordinal": 0,
        "lineage_call_ordinal": 20,
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "occurred_after_persisted_intent": True,
        "lineage_burned": True,
        "page7_burned": True,
        "native_call_issued": native_call_issued,
        "native_result_returned": native_result_returned,
        "native_calls_consumed": calls,
        "requested_conflicts_consumed": requested,
        "actual_conflicts": None,
        "billed_conflicts": None,
        "exact_probe_operation": False,
        "crossing_activation": False,
        "science_gain": False,
        "retry_authorized": False,
        "sweep_authorized": False,
        "replay_authorized": False,
        "truth_key_bytes_read": False,
        **_native_failure(exc),
    }
    _atomic_json(episode_dir / "terminal-failure.json", failure, immutable=True)
    episode = {
        "schema": EPISODE_SCHEMA,
        "completed": False,
        "local_episode_ordinal": 0,
        "lineage_call_ordinal": 20,
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "input_active_vault": active.describe(),
        "residency": prepared.state.describe(),
        "native_call_issued": native_call_issued,
        "native_result_returned": native_result_returned,
        "native_calls_consumed": calls,
        "requested_conflicts": requested,
        "actual_conflicts": None,
        "billed_conflicts": None,
        "exact_probe_operation": False,
        "crossing_activation": False,
        "science_gain": False,
        "retry_authorized": False,
        "sweep_authorized": False,
        "replay_authorized": False,
        "terminal_failure": failure,
    }
    _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    return episode, failure


def _terminal_outcome(
    *, episode: Mapping[str, object], failure: Mapping[str, object]
) -> BoundCrossingOutcome:
    calls = _nonnegative_int(episode.get("native_calls_consumed"), "failed calls")
    requested = _nonnegative_int(episode.get("requested_conflicts"), "failed work")
    return BoundCrossingOutcome(
        OPERATIONAL_TERMINAL,
        "pre-call-intent-burned-without-native-call"
        if calls == 0
        else "native-call-or-invalid-unarchivable-result-terminal",
        (dict(episode),),
        calls,
        requested,
        None,
        None,
        False,
        False,
        False,
        0,
        0,
        0,
        0,
        dict(failure),
    )


def _classify_completed_episode(
    *,
    status: int,
    both_child_closures: int,
    realized_prunes: int,
    fully_emitted_prunes: int,
    globally_novel_clauses: int,
    crossing_activation: bool,
    exact_probe_operation: bool,
) -> tuple[str, str]:
    """Apply the frozen precedence without conflating any conclusion axis."""

    for value, field in (
        (both_child_closures, "both-child closures"),
        (realized_prunes, "realized prunes"),
        (fully_emitted_prunes, "fully emitted prunes"),
        (globally_novel_clauses, "globally novel clauses"),
    ):
        _nonnegative_int(value, field)
    if (
        status not in (0, 10, 20)
        or not isinstance(crossing_activation, bool)
        or not isinstance(exact_probe_operation, bool)
    ):
        raise O1C80RunError("completed classification input differs")
    if status == 10:
        return PUBLIC_EXACT_RECOVERY, "public-complete-model-exactly-verified"
    if status == 20:
        return THRESHOLD_REGION_EXHAUSTED, "certified-frozen-threshold-region-exhausted"
    if both_child_closures:
        return BOTH_CHILD_CLOSURE_GAIN, "rigorously-validated-both-child-closure"
    if realized_prunes or fully_emitted_prunes:
        return REALIZED_PRUNE_GAIN, "realized-v6-prune-and-exact-no-good"
    if globally_novel_clauses:
        return NOVEL_CLAUSE_GAIN, "globally-novel-exact-threshold-no-good"
    if crossing_activation:
        return (
            CROSSING_MECHANISM_ONLY,
            "threshold-crossing-activated-without-science-gain",
        )
    if exact_probe_operation:
        return PROBE_OPERATION_ONLY, "exact-probes-operated-without-crossing-or-science"
    return NO_OPERATION, "no-exact-probe-crossing-or-science-gain"


def execute_episode(
    *,
    capsule: Path,
    prepared: PreparedBoundCrossing,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object] | None = None,
) -> BoundCrossingOutcome:
    """Consume Page 7 / local 0 / lineage 20 once after durable intent."""

    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or not callable(invoke_episode)
        or not callable(verify_public_model)
    ):
        raise O1C80RunError("episode execution input differs")
    normalized_bindings = dict(bindings or {})
    synthetic = normalized_bindings.get("test_fixture") == "synthetic-target-free"
    _validate_prepared_contract(prepared, require_frozen=not synthetic)
    executable_binding = _executable_binding(normalized_bindings)
    initial_rows = _initial_artifacts(capsule, prepared)
    invocation = _invocation_document(prepared, initial_rows, normalized_bindings)
    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, invocation, immutable=True)
    invocation_sha = _sha256_file(invocation_path)

    initial = capsule / "initial"
    rank_path = initial / CHUNK_NAMES[0]
    frontier_path = initial / FRONTIER_PLAN_BINARY_NAME
    staging_path = initial / STAGING_PLAN_BINARY_NAME
    prefix_path = initial / PREFIX_PLAN_BINARY_NAME
    episode_dir = capsule / "episodes/00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    active = prepared.state.active_projection
    active_path = episode_dir / "active-input.bin"
    active_row = _copy_immutable(active_path, active.serialized)
    intent = {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "local_episode_ordinal": 0,
        "lineage_call_ordinal": 20,
        "invocation_sha256": invocation_sha,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "rank_source_vault": _prepared_rank_source(prepared).describe(),
        "active_input_vault": active.describe(),
        "active_input_artifact": active_row,
        "frontier_plan": prepared.frontier_plan.describe(),
        "frontier_plan_artifact": _artifact_row(frontier_path, relative_to=initial),
        "staging_plan": prepared.staging_plan.describe(),
        "staging_plan_artifact": _artifact_row(staging_path, relative_to=initial),
        "prefix_plan": prepared.prefix_plan.describe(),
        "prefix_plan_artifact": _artifact_row(prefix_path, relative_to=initial),
        "science_input": dict(prepared.science_input),
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "page7_and_lineage20_burn_on_persisted_intent": True,
        "requested_is_not_actual_or_billed": True,
        "retry_authorized": False,
        "sweep_authorized": False,
        "replay_authorized": False,
        "truth_key_bytes_read": False,
    }
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, intent, immutable=True)
    intent_sha = _sha256_file(intent_path)

    native_call_issued = False
    try:
        _validate_call_window_executable(executable_binding, when="before")
        native_call_issued = True
        result = invoke_episode(
            0, 20, rank_path, active_path, frontier_path, staging_path, prefix_path
        )
    except BaseException as exc:
        episode, failure = _failure_episode(
            episode_dir=episode_dir,
            invocation_sha256=invocation_sha,
            intent_sha256=intent_sha,
            active=active,
            prepared=prepared,
            exc=exc,
            phase="CALL" if native_call_issued else "PRE_CALL",
            native_call_issued=native_call_issued,
            native_result_returned=False,
        )
        return _terminal_outcome(episode=episode, failure=failure)

    try:
        _validate_call_window_executable(executable_binding, when="after")
        validated = _validated_episode_result(
            result,
            prepared=prepared,
            active=active,
            stream_id="o1c80-episode-00",
            verify_public_model=verify_public_model,
            require_concrete_result=not synthetic,
        )
        raw = _mapping(validated.get("raw"), "validated raw result")
        raw_stdout = validated.get("raw_stdout")
        if not isinstance(raw_stdout, bytes):
            raise O1C80RunError("validated raw stdout differs")
        central = _mapping(validated.get("central_reader"), "validated central")
        ownership = _mapping(validated.get("decision_ownership"), "validated ownership")
        reader = _mapping(
            validated.get("one_bit_bound_reader"), "validated bound reader"
        )
        telemetry = _mapping(validated.get("telemetry"), "validated telemetry")
        stats = validate_vault_soft_conflict_ledger(
            _mapping(validated.get("stats"), "validated work ledger")
        )
        resources = _mapping(validated.get("resources"), "validated resources")
        exact_probe = _mapping(validated.get("exact_probe"), "probe conclusion")
        crossing = _mapping(validated.get("crossing"), "crossing conclusion")
        science = _mapping(validated.get("science"), "science conclusion")
        probe_success = exact_probe.get("exact_probe_operation")
        crossing_success = crossing.get("crossing_activation")
        science_gain = science.get("science_gain")
        if not all(
            isinstance(v, bool) for v in (probe_success, crossing_success, science_gain)
        ):
            raise O1C80RunError("three-axis conclusion differs")
        realized = _nonnegative_int(validated.get("realized_prunes"), "realized prunes")
        emitted = _nonnegative_int(
            validated.get("fully_emitted_prunes"), "fully emitted prunes"
        )
        both = _nonnegative_int(
            validated.get("both_child_closures"), "both-child closures"
        )
        novel_sha = tuple(
            _sha256(item, "novel clause digest")
            for item in _sequence(
                validated.get("globally_novel_clause_sha256"), "novel clauses"
            )
        )
        status = _nonnegative_int(validated.get("status"), "native status")
        key_model = validated.get("key_model")

        native_evidence = _write_raw_evidence(
            episode_dir / "native-stdout.json.gz", raw_stdout
        )
        raw_projection_evidence = _write_json_evidence(
            episode_dir / "native-result-projection.json.gz", raw
        )
        telemetry_evidence = _write_json_evidence(
            episode_dir / "vault-telemetry.json.gz", telemetry
        )
        central_evidence = _write_json_evidence(
            episode_dir / "central-reader.json.gz", central
        )
        ownership_evidence = _write_json_evidence(
            episode_dir / "decision-ownership.json.gz", ownership
        )
        bound_evidence = _write_json_evidence(
            episode_dir / "one-bit-bound-reader.json.gz", reader
        )
        conclusion = {
            "exact_probe_operation": dict(exact_probe),
            "crossing_activation": dict(crossing),
            "science": dict(science),
        }
        conclusion_path = episode_dir / "three-axis-conclusion.json"
        _atomic_json(conclusion_path, conclusion, immutable=True)
        actual = stats["solve_conflicts"]
        billed = stats["billed_conflicts"]
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": 0,
            "lineage_call_ordinal": 20,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "input_active_vault": active.describe(),
            "residency": prepared.state.describe(),
            "native_call_issued": True,
            "native_result_returned": True,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
            "actual_conflicts": actual,
            "billed_conflicts": billed,
            "status": status,
            "native_stdout_evidence": native_evidence,
            "native_result_projection_evidence": raw_projection_evidence,
            "vault_telemetry_evidence": telemetry_evidence,
            "central_reader_evidence": central_evidence,
            "decision_ownership_evidence": ownership_evidence,
            "one_bit_bound_reader_evidence": bound_evidence,
            "three_axis_conclusion_artifact": _artifact_row(
                conclusion_path, relative_to=episode_dir
            ),
            "exact_probe": dict(exact_probe),
            "crossing": dict(crossing),
            "science": dict(science),
            "exact_probe_operation": probe_success,
            "crossing_activation": crossing_success,
            "science_gain": science_gain,
            "globally_novel_clause_count": len(novel_sha),
            "globally_novel_clause_sha256": list(novel_sha),
            "realized_prunes": realized,
            "fully_emitted_prunes": emitted,
            "both_child_closures": both,
            "work": dict(stats),
            "resources": dict(resources),
            "public_model": {
                "present": key_model is not None,
                "verified_public_model": status == 10,
                "model_sha256": sha256_bytes(cast(bytes, key_model))
                if status == 10
                else None,
                "truth_key_bytes_read": False,
            },
            "page7_burned": True,
            "lineage20_burned": True,
            "retry_authorized": False,
            "sweep_authorized": False,
            "replay_authorized": False,
            "terminal_failure": None,
        }
        _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    except BaseException as exc:
        episode, failure = _failure_episode(
            episode_dir=episode_dir,
            invocation_sha256=invocation_sha,
            intent_sha256=intent_sha,
            active=active,
            prepared=prepared,
            exc=exc,
            phase="POST_CALL",
            native_call_issued=True,
            native_result_returned=True,
        )
        return _terminal_outcome(episode=episode, failure=failure)

    classification, stop = _classify_completed_episode(
        status=status,
        both_child_closures=both,
        realized_prunes=realized,
        fully_emitted_prunes=emitted,
        globally_novel_clauses=len(novel_sha),
        crossing_activation=cast(bool, crossing_success),
        exact_probe_operation=cast(bool, probe_success),
    )
    return BoundCrossingOutcome(
        classification,
        stop,
        (episode,),
        1,
        REQUESTED_CONFLICTS_PER_EPISODE,
        actual,
        billed,
        cast(bool, probe_success),
        cast(bool, crossing_success),
        cast(bool, science_gain),
        len(novel_sha),
        realized,
        emitted,
        both,
        None,
    )


execute_stream = execute_episode


def build_result(
    *,
    outcome: BoundCrossingOutcome,
    capsule_relative: str,
    source_commit: str,
    preflight: Mapping[str, object] | None = None,
    started_at: str | None = None,
    runtime: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if (
        not isinstance(outcome, BoundCrossingOutcome)
        or not isinstance(capsule_relative, str)
        or not capsule_relative
        or not isinstance(source_commit, str)
        or outcome.native_calls not in (0, 1)
        or outcome.requested_conflicts
        != outcome.native_calls * REQUESTED_CONFLICTS_PER_EPISODE
        or (
            outcome.operational_failure is not None
            and (
                outcome.actual_conflicts is not None
                or outcome.billed_conflicts is not None
            )
        )
    ):
        raise O1C80RunError("terminal result/work ledger differs")
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at
        or datetime.now().astimezone().isoformat(timespec="seconds"),
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "capsule": capsule_relative,
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "episodes": [dict(episode) for episode in outcome.episodes],
        "operational_failure": dict(outcome.operational_failure)
        if outcome.operational_failure is not None
        else None,
        "claim_boundary": {
            "exact_probe_operation": outcome.exact_probe_operation,
            "crossing_activation": outcome.crossing_activation,
            "science_gain": outcome.science_gain,
            "probe_operation_alone_is_science_gain": False,
            "crossing_proposal_alone_is_science_gain": False,
            "lower_minimum_alone_is_science_gain": False,
            "science_requires": [
                "verified-public-model",
                "formal-threshold-region-exhaustion",
                "realized-v6-losing-child-prune-and-emitted-exact-no-good",
                "rigorously-validated-both-child-closure",
                "globally-novel-exact-threshold-no-good",
            ],
            "requested_conflicts_are_actual_or_billed": False,
            "page7_sha256": PAGE7_SHA256,
            "page6_replayed": False,
            "lineage20_only": True,
            "retry_sweep_or_replay": False,
            "truth_key_bytes_read": False,
            "fresh_targets": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "resources": {
            "native_solver_calls": outcome.native_calls,
            "requested_conflicts": outcome.requested_conflicts,
            "actual_conflicts": outcome.actual_conflicts,
            "billed_conflicts": outcome.billed_conflicts,
            "globally_novel_clauses": outcome.globally_novel_clauses,
            "realized_prunes": outcome.realized_prunes,
            "fully_emitted_prunes": outcome.fully_emitted_prunes,
            "both_child_closures": outcome.both_child_closures,
            "persistent_artifact_bytes": None,
            **dict(runtime or {}),
        },
        "preflight": dict(preflight) if preflight is not None else None,
        "publication_recovery": None,
        "next_action": (
            "Never retry Page 7 or lineage 20. Preserve probe operation, crossing "
            "activation, and attacker-valid science as independent axes."
        ),
    }


def write_recovery_source(capsule: Path, result: Mapping[str, object]) -> Path:
    """Persist the complete pre-finalization state before terminal markers."""

    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C80RunError("pre-finalization recovery result differs")
    payload = canonical_json_bytes(result)
    source = {
        "schema": RECOVERY_SOURCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "PRE_FINALIZATION",
        "result_schema": RESULT_SCHEMA,
        "result_sha256": sha256_bytes(payload),
        "result_serialized_bytes": len(payload),
        "pre_finalization_result": dict(result),
        "native_calls_authorized_during_recovery": 0,
        "public_verification_calls_authorized_during_recovery": 0,
        "retry_or_replay_authorized": False,
        "truth_key_bytes_read": False,
    }
    path = capsule / RECOVERY_SOURCE_NAME
    _atomic_json(path, source, immutable=True)
    return path


write_publication_source = write_recovery_source
PUBLICATION_SOURCE_NAME = RECOVERY_SOURCE_NAME


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        payload = _regular(path, field).read_bytes()
        value = _mapping(json.loads(payload), field)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C80RunError(f"{field} JSON differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C80RunError(f"{field} is not canonical")
    return value


def _validate_recovery_episode(
    capsule: Path, result: Mapping[str, object]
) -> tuple[int, int, int | None, int | None, bool, bool, bool]:
    episodes = _sequence(result.get("episodes"), "recovery episodes")
    if len(episodes) != 1:
        raise O1C80RunError("recovery straight episode count differs")
    expected = _mapping(episodes[0], "recovery expected episode")
    episode_dir = capsule / "episodes/00"
    journal = _read_json(episode_dir / "episode.json", "episode journal")
    intent_path = _regular(episode_dir / "intent.json", "recovery intent")
    intent = _read_json(intent_path, "recovery intent")
    invocation_path = _regular(capsule / "invocation.json", "recovery invocation")
    if (
        journal != expected
        or journal.get("schema") != EPISODE_SCHEMA
        or intent.get("schema") != INTENT_SCHEMA
        or intent.get("local_episode_ordinal") != 0
        or intent.get("lineage_call_ordinal") != 20
        or intent.get("invocation_sha256") != _sha256_file(invocation_path)
        or expected.get("intent_sha256") != _sha256_file(intent_path)
        or intent.get("page7_and_lineage20_burn_on_persisted_intent") is not True
    ):
        raise O1C80RunError("recovery persisted intent differs")
    calls = _nonnegative_int(expected.get("native_calls_consumed"), "recovery calls")
    requested = _nonnegative_int(
        expected.get("requested_conflicts"), "recovery requested conflicts"
    )
    if calls not in (0, 1) or requested != calls * REQUESTED_CONFLICTS_PER_EPISODE:
        raise O1C80RunError("recovery call ledger differs")
    completed = expected.get("completed")
    if completed is False:
        failure = _mapping(expected.get("terminal_failure"), "recovery failure")
        observed = _read_json(
            episode_dir / "terminal-failure.json", "recovery failure journal"
        )
        if (
            observed != failure
            or failure.get("occurred_after_persisted_intent") is not True
            or failure.get("lineage_burned") is not True
            or failure.get("page7_burned") is not True
            or failure.get("native_calls_consumed") != calls
            or failure.get("requested_conflicts_consumed") != requested
            or expected.get("actual_conflicts") is not None
            or expected.get("billed_conflicts") is not None
        ):
            raise O1C80RunError("recovery terminal failure differs")
        return calls, requested, None, None, False, False, False
    if completed is not True or calls != 1:
        raise O1C80RunError("recovery completion differs")
    stats = validate_vault_soft_conflict_ledger(
        _mapping(expected.get("work"), "recovery work ledger")
    )
    actual = _nonnegative_int(expected.get("actual_conflicts"), "actual conflicts")
    billed = _nonnegative_int(expected.get("billed_conflicts"), "billed conflicts")
    if actual != stats["solve_conflicts"] or billed != stats["billed_conflicts"]:
        raise O1C80RunError("recovery conflict ledger differs")

    raw_stdout = _read_bytes_evidence(
        episode_dir,
        expected.get("native_stdout_evidence"),
        "recovery native stdout",
        schema=RAW_STDOUT_EVIDENCE_SCHEMA,
    )
    raw = _read_json_evidence(
        episode_dir,
        expected.get("native_result_projection_evidence"),
        "recovery native projection",
    )
    try:
        decoded = _native_v21.load_native_json(raw_stdout)
    except Exception as exc:
        raise O1C80RunError("recovery native stdout JSON differs") from exc
    central = _read_json_evidence(
        episode_dir,
        expected.get("central_reader_evidence"),
        "recovery central reader",
    )
    ownership = _read_json_evidence(
        episode_dir,
        expected.get("decision_ownership_evidence"),
        "recovery ownership",
    )
    bound = _read_json_evidence(
        episode_dir,
        expected.get("one_bit_bound_reader_evidence"),
        "recovery bound reader",
    )
    telemetry = _read_json_evidence(
        episode_dir,
        expected.get("vault_telemetry_evidence"),
        "recovery vault telemetry",
    )
    if (
        decoded != raw
        or raw.get("central_reader") != central
        or raw.get("decision_ownership") != ownership
        or raw.get("one_bit_bound_reader") != bound
        or raw.get("vault") != telemetry
    ):
        raise O1C80RunError("recovery native/promoted evidence differs")
    if raw.get("schema") == _native_v21.JOINT_SCORE_SIEVE_RESULT_SCHEMA:
        try:
            _native_v21.validate_native_lifecycle(raw)
        except Exception as exc:
            raise O1C80RunError("recovery native lifecycle differs") from exc
    conclusion_path = _validate_artifact_row(
        episode_dir,
        expected.get("three_axis_conclusion_artifact"),
        "recovery three-axis conclusion",
    )
    conclusion = _read_json(conclusion_path, "recovery conclusion")
    probe = expected.get("exact_probe_operation")
    crossing = expected.get("crossing_activation")
    science = expected.get("science_gain")
    if (
        not all(isinstance(value, bool) for value in (probe, crossing, science))
        or _mapping(conclusion.get("exact_probe_operation"), "recovery probe axis").get(
            "exact_probe_operation"
        )
        is not probe
        or _mapping(
            conclusion.get("crossing_activation"), "recovery crossing axis"
        ).get("crossing_activation")
        is not crossing
        or _mapping(conclusion.get("science"), "recovery science axis").get(
            "science_gain"
        )
        is not science
    ):
        raise O1C80RunError("recovery three-axis conclusion differs")
    return (
        calls,
        requested,
        actual,
        billed,
        cast(bool, probe),
        cast(bool, crossing),
        cast(bool, science),
    )


def recover_publication(capsule: Path) -> dict[str, object]:
    """Recover publication only from sealed sidecars, issuing zero callbacks."""

    _validate_capsule_tree(capsule)
    source_path = _regular(capsule / RECOVERY_SOURCE_NAME, "recovery source")
    source = _read_json(source_path, "recovery source")
    result = dict(_mapping(source.get("pre_finalization_result"), "recovery result"))
    payload = canonical_json_bytes(result)
    if (
        source.get("schema") != RECOVERY_SOURCE_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("state") != "PRE_FINALIZATION"
        or source.get("result_schema") != RESULT_SCHEMA
        or source.get("result_sha256") != sha256_bytes(payload)
        or source.get("result_serialized_bytes") != len(payload)
        or source.get("native_calls_authorized_during_recovery") != 0
        or source.get("public_verification_calls_authorized_during_recovery") != 0
        or source.get("retry_or_replay_authorized") is not False
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C80RunError("pre-finalization recovery source differs")
    calls, requested, actual, billed, probe, crossing, science = (
        _validate_recovery_episode(capsule, result)
    )
    resources = _mapping(result.get("resources"), "recovery resources")
    boundary = _mapping(result.get("claim_boundary"), "recovery boundary")
    if (
        resources.get("native_solver_calls") != calls
        or resources.get("requested_conflicts") != requested
        or resources.get("actual_conflicts") != actual
        or resources.get("billed_conflicts") != billed
        or boundary.get("exact_probe_operation") is not probe
        or boundary.get("crossing_activation") is not crossing
        or boundary.get("science_gain") is not science
    ):
        raise O1C80RunError("recovery result conclusion differs")
    result["publication_recovery"] = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "pre_finalization_source_sha256": sha256_bytes(source_path.read_bytes()),
        "publication_recovered_from_episode_sidecars": True,
        "raw_native_stdout_revalidated_byte_exact": calls == 1,
        "native_calls_issued_during_recovery": 0,
        "public_verification_calls_issued_during_recovery": 0,
        "retry_or_replay_calls_issued_during_recovery": 0,
        "truth_key_bytes_read": False,
        "recovered_episode_count": 1,
        "recovered_native_calls_consumed": calls,
    }
    return result


def _recovered_publication_source_document(
    capsule: Path, recovered: Mapping[str, object]
) -> dict[str, object]:
    recovery = _mapping(
        recovered.get("publication_recovery"), "recovered publication proof"
    )
    if (
        recovered.get("schema") != RESULT_SCHEMA
        or recovered.get("attempt_id") != ATTEMPT_ID
        or recovery.get("schema") != PUBLICATION_RECOVERY_SCHEMA
        or recovery.get("native_calls_issued_during_recovery") != 0
        or recovery.get("public_verification_calls_issued_during_recovery") != 0
    ):
        raise O1C80RunError("recovered finalization result differs")
    payload = canonical_json_bytes(recovered)
    return {
        "schema": RECOVERED_PUBLICATION_SOURCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "RECOVERED_PRE_FINALIZATION",
        "original_recovery_source_sha256": sha256_bytes(
            _regular(capsule / RECOVERY_SOURCE_NAME, "recovery source").read_bytes()
        ),
        "result_schema": RESULT_SCHEMA,
        "result_sha256": sha256_bytes(payload),
        "result_serialized_bytes": len(payload),
        "recovered_result": dict(recovered),
        "native_calls_authorized_during_resume": 0,
        "public_verification_calls_authorized_during_resume": 0,
        "retry_or_replay_authorized": False,
        "truth_key_bytes_read": False,
    }


def write_recovered_publication_source(
    capsule: Path, recovered: Mapping[str, object]
) -> Path:
    document = _recovered_publication_source_document(capsule, recovered)
    payload = canonical_json_bytes(document)
    path = capsule / PUBLICATION_RECOVERY_NAME
    if path.exists() or path.is_symlink():
        if _regular(path, "recovered publication source").read_bytes() != payload:
            raise O1C80RunError("recovered publication source differs")
        return path
    _atomic_create(path, payload, immutable=True)
    return path


def _read_recovered_publication_source(capsule: Path) -> dict[str, object]:
    document = _read_json(
        capsule / PUBLICATION_RECOVERY_NAME, "recovered publication source"
    )
    recovered = dict(
        _mapping(document.get("recovered_result"), "recovered finalization result")
    )
    expected = recover_publication(capsule)
    payload = canonical_json_bytes(recovered)
    if (
        document.get("schema") != RECOVERED_PUBLICATION_SOURCE_SCHEMA
        or document.get("attempt_id") != ATTEMPT_ID
        or document.get("state") != "RECOVERED_PRE_FINALIZATION"
        or document.get("original_recovery_source_sha256")
        != sha256_bytes((capsule / RECOVERY_SOURCE_NAME).read_bytes())
        or document.get("result_schema") != RESULT_SCHEMA
        or document.get("result_sha256") != sha256_bytes(payload)
        or document.get("result_serialized_bytes") != len(payload)
        or document.get("native_calls_authorized_during_resume") != 0
        or document.get("public_verification_calls_authorized_during_resume") != 0
        or document.get("retry_or_replay_authorized") is not False
        or recovered != expected
    ):
        raise O1C80RunError("recovered publication resume source differs")
    return recovered


def _markdown(result: Mapping[str, object]) -> bytes:
    resources = _mapping(result.get("resources"), "result resources")
    boundary = _mapping(result.get("claim_boundary"), "result claim boundary")
    return (
        "# O1C-0080 — APPLE8 exact one-bit bound crossing\n\n"
        f"- Classification: `{result.get('classification')}`\n"
        f"- Stop reason: `{result.get('stop_reason')}`\n"
        f"- Native calls: `{resources.get('native_solver_calls')}`\n"
        f"- Requested conflicts: `{resources.get('requested_conflicts')}`\n"
        f"- Actual conflicts: `{resources.get('actual_conflicts')}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n"
        "- Input: fresh Page 7 / local 0 / lineage 20\n"
        f"- Exact probe operation: `{str(boundary.get('exact_probe_operation')).lower()}`\n"
        f"- Crossing activation: `{str(boundary.get('crossing_activation')).lower()}`\n"
        f"- Science gain: `{str(boundary.get('science_gain')).lower()}`\n"
        "- Raw native stdout preserved byte-for-byte\n"
        "- No retry, sweep, replay, truth, reveal, refit, MPS, or GPU work\n"
    ).encode("utf-8")


def _manifest_payload(capsule: Path, virtual: Mapping[str, bytes]) -> tuple[bytes, int]:
    return cast(
        tuple[bytes, int],
        _base_call(lambda: _publication_base._manifest_payload(capsule, virtual)),
    )


def _publish_exact(path: Path, payload: bytes, *, immutable: bool = True) -> None:
    if path.exists() or path.is_symlink():
        if _regular(path, "publication artifact").read_bytes() != payload:
            raise O1C80RunError(f"partial publication artifact differs: {path.name}")
        return
    _atomic_create(path, payload, immutable=immutable)


def _publication_payloads(
    capsule: Path, result: Mapping[str, object]
) -> tuple[dict[str, object], bytes, bytes, bytes, int]:
    finalized = cast(dict[str, object], json.loads(canonical_json_bytes(result)))
    resources = finalized.get("resources")
    if not isinstance(resources, dict):
        raise O1C80RunError("publication resource ledger differs")
    for _ in range(16):
        result_payload = canonical_json_bytes(finalized)
        run_payload = _markdown(finalized)
        manifest, persistent = _manifest_payload(
            capsule, {"RUN.md": run_payload, "result.json": result_payload}
        )
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C80RunError("persistent artifact ledger did not converge")
    result_payload = canonical_json_bytes(finalized)
    run_payload = _markdown(finalized)
    manifest, persistent = _manifest_payload(
        capsule, {"RUN.md": run_payload, "result.json": result_payload}
    )
    if (
        resources.get("persistent_artifact_bytes") != persistent
        or persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES
    ):
        raise O1C80RunError("persistent artifact byte budget differs")
    return finalized, result_payload, run_payload, manifest, persistent


def finalize_capsule(
    capsule: Path, authoritative: Path, result: dict[str, object]
) -> None:
    if result.get("schema") != RESULT_SCHEMA or result.get("attempt_id") != ATTEMPT_ID:
        raise O1C80RunError("terminal O1C80 publication differs")
    if result.get("publication_recovery") is not None:
        write_recovered_publication_source(capsule, result)
    finalized, result_payload, run_payload, manifest, _ = _publication_payloads(
        capsule, result
    )
    result.clear()
    result.update(finalized)
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    _publish_exact(capsule / "RUN.md", run_payload)
    _publish_exact(capsule / "result.json", result_payload)
    _publish_exact(capsule / "artifacts.sha256", manifest)
    _publish_exact(authoritative, result_payload)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        path.chmod(0o444 if path.is_file() else 0o555)
    capsule.chmod(0o555)


def _existing_authoritative(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    value = dict(_read_json(path, "authoritative O1C80 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C80RunError("authoritative O1C80 result differs")
    return value


def _republish_sealed_capsule(capsule: Path, authoritative: Path) -> dict[str, object]:
    _validate_capsule_tree(capsule)
    result_path = _regular(capsule / "result.json", "sealed capsule result")
    result = dict(_read_json(result_path, "sealed capsule result"))
    expected_manifest, persistent = _manifest_payload(capsule, {})
    resources = _mapping(result.get("resources"), "sealed capsule resources")
    if (
        _regular(capsule / "artifacts.sha256", "sealed manifest").read_bytes()
        != expected_manifest
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or resources.get("persistent_artifact_bytes") != persistent
    ):
        raise O1C80RunError("sealed O1C80 capsule differs")
    _publish_exact(authoritative, result_path.read_bytes())
    return result


def _native_source_closure_sha256(
    digests: Mapping[str, object], *, pending: bool = False
) -> str:
    rows: list[dict[str, str]] = []
    for name in NATIVE_INCLUDE_CLOSURE:
        digest = _sha256(
            digests.get(name), f"native closure digest {name}", pending=pending
        )
        if digest == "PENDING":
            return "PENDING"
        rows.append({"path": SOURCE_PATHS[name], "sha256": digest})
    return sha256_bytes(
        canonical_json_bytes({"schema": NATIVE_SOURCE_CLOSURE_SCHEMA, "files": rows})
    )


def load_config(path: str | Path, *, root: Path | None = None) -> dict[str, object]:
    """Load the complete contract; PENDING seals are syntactically accepted."""

    lab = (root or lab_root()).resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(lab):
        raise O1C80RunError("O1C80 config escapes the lab")
    config = dict(_read_json(config_path, "O1C80 config"))
    if (
        set(config)
        != {
            "schema",
            "attempt_id",
            "parent",
            "preparation",
            "inputs",
            "native",
            "source",
            "target_free_preflight",
            "budgets",
            "next_action",
        }
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or not isinstance(config.get("next_action"), str)
        or not config.get("next_action")
    ):
        raise O1C80RunError("frozen O1C80 config fields differ")
    parent = _mapping(config["parent"], "config parent")
    if (
        set(parent)
        != {
            "result",
            "capsule",
            "erratum",
            "result_sha256",
            "manifest_sha256",
            "erratum_sha256",
            "source_commit",
            "last_lineage_ordinal",
            "classification",
        }
        or _relative_contract(parent.get("result"), "parent result")
        != PARENT_RESULT_RELATIVE.as_posix()
        or _relative_contract(parent.get("capsule"), "parent capsule")
        != PARENT_CAPSULE_RELATIVE.as_posix()
        or _relative_contract(parent.get("erratum"), "parent erratum")
        != PARENT_ERRATUM_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("manifest_sha256") != PARENT_CAPSULE_MANIFEST_SHA256
        or parent.get("erratum_sha256") != PARENT_ERRATUM_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("last_lineage_ordinal") != PARENT_LAST_LINEAGE_ORDINAL
        or parent.get("classification") != PARENT_CLASSIFICATION
    ):
        raise O1C80RunError("frozen O1C79 terminal parent differs")
    preparation = _mapping(config["preparation"], "config preparation")
    if (
        set(preparation) != {"directory", "manifest_sha256"}
        or _relative_contract(preparation.get("directory"), "preparation directory")
        != PREPARATION_DIRECTORY_RELATIVE.as_posix()
        or preparation.get("manifest_sha256") != EXPECTED_PREPARED_MANIFEST_SHA256
    ):
        raise O1C80RunError("prepared Page-7 config differs")
    inputs = _mapping(config["inputs"], "config inputs")
    if set(inputs) != {
        "cnf",
        "cnf_sha256",
        "potential",
        "potential_sha256",
        "grouping",
        "grouping_sha256",
        "o1c73_config",
        "o1c73_config_sha256",
    }:
        raise O1C80RunError("frozen O1C80 public inputs differ")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        _relative_contract(inputs.get(name), f"input {name}")
        _sha256(inputs.get(f"{name}_sha256"), f"input {name} digest", pending=True)
    native = _mapping(config["native"], "config native")
    required_native = {
        "source",
        "executable",
        "expected_source_sha256",
        "expected_executable_sha256",
        "expected_executable_bytes",
        "adapter_schema",
        "result_schema",
        "one_bit_bound_reader_schema",
        "rank_source_sha256",
        "active_vault_sha256",
        "frontier_plan_sha256",
        "frontier_plan_document_sha256",
        "staging_plan_sha256",
        "staging_plan_document_sha256",
        "prefix_plan_sha256",
        "prefix_plan_document_sha256",
        "science_input_sha256",
        "one_bit_bound_header_sha256",
        "decision_ownership_header_sha256",
        "source_closure_sha256",
    }
    if (
        set(native) != required_native
        or _relative_contract(native.get("source"), "native source")
        != SOURCE_PATHS["native_v18"]
        or _relative_contract(native.get("executable"), "native executable")
        != "build/o1c80/native-joint-score-sieve"
        or native.get("adapter_schema") != _native_v21.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema") != _native_v21.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("one_bit_bound_reader_schema")
        != _native_v21.ONE_BIT_BOUND_READER_SCHEMA
        or native.get("rank_source_sha256") != RANK_SOURCE_SHA256
        or native.get("active_vault_sha256") != PAGE7_SHA256
        or native.get("frontier_plan_sha256") != FRONTIER_PLAN_BINARY_SHA256
        or native.get("frontier_plan_document_sha256")
        != EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256
        or native.get("staging_plan_sha256") != STAGING_PLAN_BINARY_SHA256
        or native.get("staging_plan_document_sha256")
        != EXPECTED_STAGING_PLAN_DOCUMENT_SHA256
        or native.get("prefix_plan_sha256") != PREFIX_PLAN_BINARY_SHA256
        or native.get("prefix_plan_document_sha256")
        != EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256
        or native.get("science_input_sha256") != EXPECTED_SCIENCE_INPUT_SHA256
        or native.get("expected_executable_bytes") != 1_740_376
    ):
        raise O1C80RunError("native bound-crossing config differs")
    _sha256(native.get("expected_source_sha256"), "native source digest", pending=True)
    _sha256(
        native.get("expected_executable_sha256"),
        "native executable digest",
        pending=True,
    )
    _sha256(
        native.get("one_bit_bound_header_sha256"), "one-bit header digest", pending=True
    )
    _sha256(
        native.get("decision_ownership_header_sha256"),
        "ownership header digest",
        pending=True,
    )
    source = _mapping(config["source"], "config source")
    paths = _mapping(source.get("paths"), "config source paths")
    expected_sources = _mapping(source.get("expected_sha256"), "source digests")
    if (
        set(source) != {"paths", "expected_sha256", "expected_commit"}
        or dict(paths) != SOURCE_PATHS
        or set(expected_sources) != set(SOURCE_PATHS)
    ):
        raise O1C80RunError("source freeze config differs")
    _commit(source.get("expected_commit"), "expected source commit", pending=True)
    for name in SOURCE_PATHS:
        _sha256(expected_sources.get(name), f"source digest {name}", pending=True)
    closure = _native_source_closure_sha256(expected_sources, pending=True)
    if (
        native.get("expected_source_sha256") != expected_sources.get("native_v18")
        or native.get("one_bit_bound_header_sha256")
        != expected_sources.get("one_bit_bound_header")
        or native.get("decision_ownership_header_sha256")
        != expected_sources.get("decision_ownership_header")
        or _sha256(
            native.get("source_closure_sha256"), "native source closure", pending=True
        )
        != closure
    ):
        raise O1C80RunError("native/source closure binding differs")
    gate = _mapping(config["target_free_preflight"], "config target-free gate")
    if (
        set(gate) != {"path", "sha256", "schema", "classification"}
        or _relative_contract(gate.get("path"), "target-free path")
        != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or gate.get("schema") != TARGET_FREE_GATE_SCHEMA
        or gate.get("classification")
        not in {TARGET_FREE_GATE_PENDING, TARGET_FREE_GATE_PASS}
    ):
        raise O1C80RunError("target-free bound-crossing gate config differs")
    gate_sha = _sha256(gate.get("sha256"), "target-free gate digest", pending=True)
    if (gate_sha == "PENDING") != (
        gate.get("classification") == TARGET_FREE_GATE_PENDING
    ):
        raise O1C80RunError("target-free gate freeze state differs")
    budgets = _mapping(config["budgets"], "config budgets")
    expected_budgets: dict[str, object] = {
        "active_clause_limit": ACTIVE_CLAUSE_LIMIT,
        "local_episode_ordinals": [0],
        "lineage_call_ordinals": [20],
        "requested_conflicts_per_episode": 128,
        "maximum_native_solver_calls": 1,
        "maximum_total_requested_conflicts": 128,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "maximum_persistent_artifact_bytes": MAXIMUM_PERSISTENT_ARTIFACT_BYTES,
        "minimum_disk_free_bytes": MINIMUM_DISK_FREE_BYTES,
        "maximum_fresh_targets": 0,
        "maximum_scientific_entropy_calls": 0,
        "maximum_fresh_reveal_calls": 0,
        "maximum_refits": 0,
        "maximum_mps_calls": 0,
        "maximum_gpu_calls": 0,
        "retry_authorized": False,
        "sweep_authorized": False,
        "replay_authorized": False,
    }
    if dict(budgets) != expected_budgets:
        raise O1C80RunError("frozen O1C80 budgets differ")
    return config


_REQUIRED_GATE_TRUE = (
    "exact_child_bound_reference_fixture_passed",
    "selection_class_fixture_passed",
    "equality_live_fixture_passed",
    "same_parent_nonmutation_fixture_passed",
    "candidate_order_fixture_passed",
    "ownership_lifecycle_fixture_passed",
    "realized_v6_prune_linkage_fixture_passed",
    "emitted_exact_no_good_fixture_passed",
    "both_child_closure_fixture_passed",
    "minimum_not_science_fixture_passed",
    "raw_stdout_preservation_fixture_passed",
    "preparation_determinism_fixture_passed",
    "single_call_schedule_fixture_passed",
    "durable_intent_fixture_passed",
    "no_retry_sweep_replay_fixture_passed",
    "recovery_zero_call_fixture_passed",
    "publication_republish_zero_call_fixture_passed",
)


def _validate_target_free_gate(
    path: Path,
    *,
    expected_sha256: str,
    prepared: PreparedBoundCrossing,
    source_sha256: Mapping[str, str],
) -> Mapping[str, object]:
    payload = _regular(path, "target-free preflight").read_bytes()
    if sha256_bytes(payload) != expected_sha256:
        raise O1C80RunError("target-free preflight digest differs")
    try:
        row = _mapping(json.loads(payload), "target-free preflight")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C80RunError("target-free preflight JSON differs") from exc
    if (
        canonical_json_bytes(row) != payload
        or row.get("schema") != TARGET_FREE_GATE_SCHEMA
        or row.get("attempt_id") != ATTEMPT_ID
        or row.get("classification") != TARGET_FREE_GATE_PASS
        or row.get("status") != "PASS"
        or row.get("native_solver_calls") != 0
        or row.get("truth_key_bytes_read") is not False
        or row.get("fresh_targets") != 0
        or row.get("fresh_reveal_calls") != 0
        or row.get("refits") != 0
        or row.get("MPS_or_GPU") is not False
        or row.get("prepared_manifest_sha256") != prepared.manifest_sha256
        or row.get("page7_sha256") != PAGE7_SHA256
        or row.get("frontier_plan_sha256") != FRONTIER_PLAN_BINARY_SHA256
        or row.get("staging_plan_sha256") != STAGING_PLAN_BINARY_SHA256
        or row.get("prefix_plan_sha256") != PREFIX_PLAN_BINARY_SHA256
        or row.get("science_input_sha256") != EXPECTED_SCIENCE_INPUT_SHA256
        or row.get("one_bit_bound_header_sha256")
        != source_sha256.get("one_bit_bound_header")
        or row.get("decision_ownership_header_sha256")
        != source_sha256.get("decision_ownership_header")
        or row.get("adapter_v21_fixture_sha256")
        != source_sha256.get("adapter_v21_fixture_tests")
        or row.get("native_fixture_sha256") != source_sha256.get("native_fixture_tests")
        or row.get("preparation_fixture_sha256")
        != source_sha256.get("preparation_fixture_tests")
        or row.get("runner_fixture_sha256") != source_sha256.get("runner_fixture_tests")
        or row.get("native_source_closure_sha256")
        != _native_source_closure_sha256(source_sha256)
        or row.get("local_episode_ordinals") != [0]
        or row.get("lineage_call_ordinals") != [20]
        or row.get("requested_conflicts_per_episode") != 128
        or row.get("maximum_native_solver_calls") != 1
        or any(row.get(field) is not True for field in _REQUIRED_GATE_TRUE)
    ):
        raise O1C80RunError("target-free bound-crossing gate differs")
    return dict(row)


def _pending_fields(value: object, prefix: str = "config") -> tuple[str, ...]:
    found: list[str] = []
    if value == "PENDING":
        found.append(prefix)
    elif isinstance(value, Mapping):
        for name, nested in value.items():
            found.extend(_pending_fields(nested, f"{prefix}.{name}"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            found.extend(_pending_fields(nested, f"{prefix}[{index}]"))
    return tuple(found)


def _available_memory_bytes() -> int | None:
    try:
        if sys.platform == "darwin":
            output = subprocess.run(
                ["vm_stat"], check=True, capture_output=True, text=True
            ).stdout
            page_size = 4096
            first = output.splitlines()[0]
            if "page size of" in first:
                page_size = int(first.split("page size of", 1)[1].split("bytes", 1)[0])
            free_pages = sum(
                int(line.rsplit(":", 1)[1].strip().rstrip("."))
                for line in output.splitlines()[1:]
                if line.startswith(
                    ("Pages free", "Pages inactive", "Pages speculative")
                )
            )
            return free_pages * page_size
        pages = os.sysconf("SC_AVPHYS_PAGES")
        size = os.sysconf("SC_PAGE_SIZE")
        if isinstance(pages, int) and isinstance(size, int):
            return pages * size
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def _sibling_solver_pids() -> tuple[int, ...]:
    try:
        output = subprocess.run(
            ["ps", "-axo", "pid=,args="],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C80RunError("solver process preflight cannot be established") from exc
    current = os.getpid()
    pids: list[int] = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        try:
            argv = shlex.split(parts[1])
        except ValueError:
            continue
        if not argv:
            continue
        executable_name = Path(argv[0]).name
        solver_executable = (
            executable_name == "native-joint-score-sieve"
            or executable_name.startswith("cadical_o1_joint_score_sieve")
        )
        if pid != current and solver_executable:
            pids.append(pid)
    return tuple(sorted(pids))


def _validate_runtime_source_freeze(
    root: Path, *, expected_commit: str, execution_commit: str
) -> None:
    comparison = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            expected_commit,
            execution_commit,
            "--",
            *SOURCE_FREEZE_GUARD_PATHS,
        ],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if comparison.returncode == 1:
        raise O1C80RunError("Python/native runtime changed after frozen commit")
    if comparison.returncode != 0:
        raise O1C80RunError("runtime source freeze comparison failed")


def preflight(
    config_path: str | Path,
    *,
    require_commit_binding: bool = True,
    root: Path | None = None,
) -> dict[str, object]:
    """Reject PENDING before creating a capsule, then verify every seal/gate."""

    lab = (root or lab_root()).resolve(strict=True)
    config = load_config(config_path, root=lab)
    pending = _pending_fields(config)
    if pending:
        raise O1C80RunError(
            "production preflight contains PENDING: " + ", ".join(pending)
        )
    parent = _mapping(config["parent"], "preflight parent")
    if (
        _sha256_file(_relative(lab, parent["result"], "parent result"))
        != PARENT_RESULT_SHA256
        or _sha256_file(
            _regular(
                _relative(lab, parent["capsule"], "parent capsule")
                / "artifacts.sha256",
                "parent manifest",
            )
        )
        != PARENT_CAPSULE_MANIFEST_SHA256
        or _sha256_file(_relative(lab, parent["erratum"], "parent erratum"))
        != PARENT_ERRATUM_SHA256
    ):
        raise O1C80RunError("O1C79 terminal identity differs")
    preparation = _mapping(config["preparation"], "preflight preparation")
    prepared = load_prepared_bound_crossing(
        _relative(lab, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
    _validate_prepared_contract(prepared)
    inputs = _mapping(config["inputs"], "preflight inputs")
    observed_inputs: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        path = _relative(lab, inputs[name], f"input {name}")
        observed = _sha256_file(path)
        if observed != inputs[f"{name}_sha256"]:
            raise O1C80RunError(f"frozen input {name} differs")
        observed_inputs[name] = observed
    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "preflight source paths")
    expected_sources = _mapping(source["expected_sha256"], "source digests")
    observed_sources: dict[str, str] = {}
    for name, relative in paths.items():
        observed = _sha256_file(_relative(lab, relative, f"source {name}"))
        if observed != expected_sources[name]:
            raise O1C80RunError(f"source {name} differs")
        observed_sources[name] = observed
    native = _mapping(config["native"], "preflight native")
    executable = lab / _relative_contract(native["executable"], "native executable")
    executable_binding = validate_native_executable(
        executable,
        expected_sha256=cast(str, native["expected_executable_sha256"]),
    )
    if (
        executable_binding.get("serialized_bytes")
        != native["expected_executable_bytes"]
    ):
        raise O1C80RunError("native executable byte size differs")
    gate_config = _mapping(config["target_free_preflight"], "target-free gate")
    gate = _validate_target_free_gate(
        _relative(lab, gate_config["path"], "target-free gate"),
        expected_sha256=cast(str, gate_config["sha256"]),
        prepared=prepared,
        source_sha256=observed_sources,
    )
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=lab,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=lab,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C80RunError("source commit binding cannot be established") from exc
    expected_commit = cast(str, source["expected_commit"])
    if require_commit_binding:
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", expected_commit, commit],
            cwd=lab,
            check=False,
            capture_output=True,
        )
        if ancestor.returncode != 0 or dirty:
            raise O1C80RunError("clean source freeze is not an execution ancestor")
        _validate_runtime_source_freeze(
            lab, expected_commit=expected_commit, execution_commit=commit
        )
        for name, relative in paths.items():
            try:
                blob = subprocess.run(
                    ["git", "show", f"{expected_commit}:{relative}"],
                    cwd=lab,
                    check=True,
                    capture_output=True,
                ).stdout
            except (OSError, subprocess.SubprocessError) as exc:
                raise O1C80RunError("source commit blob binding differs") from exc
            if sha256_bytes(blob) != observed_sources[name]:
                raise O1C80RunError(f"source {name} differs from frozen commit")
    disk_free = shutil.disk_usage(lab).free
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C80RunError("disk resource preflight differs")
    siblings = _sibling_solver_pids()
    if siblings:
        raise O1C80RunError("a sibling solver process is live")
    available_memory = _available_memory_bytes()
    if available_memory is not None and available_memory < MEMORY_LIMIT_BYTES:
        raise O1C80RunError("native memory headroom differs")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "passed": True,
        "source_freeze_commit": expected_commit,
        "execution_commit": commit,
        "source_clean": not bool(dirty),
        "runtime_source_freeze_guard_paths": list(SOURCE_FREEZE_GUARD_PATHS),
        "runtime_source_bytes_changed_after_freeze": False,
        "source_sha256": observed_sources,
        "native_source_closure_sha256": _native_source_closure_sha256(observed_sources),
        "input_sha256": observed_inputs,
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
        "parent_erratum_sha256": PARENT_ERRATUM_SHA256,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "page7_sha256": prepared.state.active_projection.sha256,
        "frontier_plan_sha256": prepared.frontier_plan.sha256,
        "staging_plan_sha256": prepared.staging_plan.sha256,
        "prefix_plan_sha256": prepared.prefix_plan.sha256,
        "science_input_sha256": sha256_bytes(
            canonical_json_bytes(prepared.science_input)
        ),
        "target_free_preflight_sha256": gate_config["sha256"],
        "target_free_preflight": gate,
        "native_executable": executable_binding,
        "disk_free_bytes": disk_free,
        "available_memory_bytes": available_memory,
        "sibling_solver_pids": [],
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _remove_partial_publication(
    capsule: Path, source_result: Mapping[str, object]
) -> None:
    markers = (
        capsule / "RUN.md",
        capsule / "result.json",
        capsule / "artifacts.sha256",
    )
    if not any(path.exists() for path in markers) or all(
        path.exists() for path in markers
    ):
        return
    _, result_payload, run_payload, manifest_payload, _ = _publication_payloads(
        capsule, source_result
    )
    expected = {
        "RUN.md": run_payload,
        "result.json": result_payload,
        "artifacts.sha256": manifest_payload,
    }
    for path in markers:
        if (
            path.exists()
            and _regular(path, "partial publication").read_bytes()
            != expected[path.name]
        ):
            raise O1C80RunError(f"partial publication {path.name} differs")
    capsule.chmod(0o755)
    for path in markers:
        if path.exists():
            path.chmod(0o644)
            path.unlink()


def run(config_path: str | Path = CONFIG_RELATIVE) -> dict[str, object]:
    """Execute once, or recover/republish without issuing another native call."""

    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    existing = _existing_authoritative(authoritative)
    if existing is not None:
        return existing
    capsules = sorted(
        path for path in (root / "runs").glob(f"*_{CAPSULE_SUFFIX}") if path.is_dir()
    )
    if capsules:
        if len(capsules) != 1:
            raise O1C80RunError("multiple O1C80 capsules block replay")
        capsule = capsules[0]
        if all(
            (capsule / name).is_file()
            for name in ("RUN.md", "result.json", "artifacts.sha256")
        ):
            return _republish_sealed_capsule(capsule, authoritative)
        if (capsule / PUBLICATION_RECOVERY_NAME).is_file():
            recovered = _read_recovered_publication_source(capsule)
            _remove_partial_publication(capsule, recovered)
            finalize_capsule(capsule, authoritative, recovered)
            return recovered
        source = _read_json(capsule / RECOVERY_SOURCE_NAME, "recovery source")
        source_result = _mapping(
            source.get("pre_finalization_result"), "partial publication result"
        )
        _remove_partial_publication(capsule, source_result)
        recovered = recover_publication(capsule)
        write_recovered_publication_source(capsule, recovered)
        finalize_capsule(capsule, authoritative, recovered)
        return recovered

    config_file = Path(config_path).resolve(strict=True)
    preflight_row = preflight(config_file, require_commit_binding=True, root=root)
    config = load_config(config_file, root=root)
    preparation = _mapping(config["preparation"], "run preparation")
    prepared = load_prepared_bound_crossing(
        _relative(root, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
    _validate_prepared_contract(prepared)
    inputs = _mapping(config["inputs"], "run inputs")
    cnf = _relative(root, inputs["cnf"], "run CNF")
    potential = _relative(root, inputs["potential"], "run potential")
    grouping = _relative(root, inputs["grouping"], "run grouping")
    baseline_config = _o1c73.load_config(
        _relative(root, inputs["o1c73_config"], "run O1C73 config")
    )
    baseline = _o1c73.validate_apple8_baseline(root, baseline_config)
    public_target = _o1c73._o1c66._public_target(baseline)
    native = _mapping(config["native"], "run native")
    executable = root / _relative_contract(native["executable"], "native executable")
    executable_binding = validate_native_executable(
        executable, expected_sha256=cast(str, native["expected_executable_sha256"])
    )
    if executable_binding != preflight_row.get("native_executable"):
        raise O1C80RunError("post-preflight native executable differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
    capsule = root / capsule_relative
    capsule.mkdir(parents=True, exist_ok=False)
    _atomic_create(capsule / "config.json", config_file.read_bytes(), immutable=True)
    _atomic_json(capsule / "preflight.json", preflight_row, immutable=True)
    _atomic_json(
        capsule / "native-build.json",
        {
            "source": native["source"],
            "source_sha256": native["expected_source_sha256"],
            "source_closure_schema": NATIVE_SOURCE_CLOSURE_SCHEMA,
            "source_closure_names": list(NATIVE_INCLUDE_CLOSURE),
            "source_closure_sha256": native["source_closure_sha256"],
            "executable": executable_binding,
            "adapter_schema": native["adapter_schema"],
            "result_schema": native["result_schema"],
            "one_bit_bound_reader_schema": native["one_bit_bound_reader_schema"],
            "active_vault_sha256": PAGE7_SHA256,
            "frontier_plan_sha256": FRONTIER_PLAN_BINARY_SHA256,
            "staging_plan_sha256": STAGING_PLAN_BINARY_SHA256,
            "prefix_plan_sha256": PREFIX_PLAN_BINARY_SHA256,
            "fixed_output_basename_reproducibility_required": True,
        },
        immutable=True,
    )
    bindings = {
        "source_freeze_commit": preflight_row["source_freeze_commit"],
        "execution_commit": preflight_row["execution_commit"],
        "config_sha256": _sha256_file(config_file),
        "native_executable": executable_binding,
        "native_adapter_schema": native["adapter_schema"],
        "native_result_schema": native["result_schema"],
        "native_source_closure_sha256": preflight_row["native_source_closure_sha256"],
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "page7_sha256": PAGE7_SHA256,
        "frontier_plan_sha256": prepared.frontier_plan.sha256,
        "staging_plan_sha256": prepared.staging_plan.sha256,
        "prefix_plan_sha256": prepared.prefix_plan.sha256,
        "science_input_sha256": EXPECTED_SCIENCE_INPUT_SHA256,
        "target_free_preflight_sha256": preflight_row["target_free_preflight_sha256"],
        "truth_key_bytes_read": False,
    }

    def invoke(
        local: int,
        lineage: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
        prefix_plan: Path,
    ) -> object:
        if (
            (local, lineage) != (0, 20)
            or _sha256_file(rank_vault) != RANK_SOURCE_SHA256
            or _sha256_file(active_vault) != PAGE7_SHA256
            or _sha256_file(frontier_plan) != FRONTIER_PLAN_BINARY_SHA256
            or _sha256_file(staging_plan) != STAGING_PLAN_BINARY_SHA256
            or _sha256_file(prefix_plan) != PREFIX_PLAN_BINARY_SHA256
        ):
            raise O1C80RunError("native Page-7 invocation identity differs")
        return _native_v21.run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            rank_vault_path=rank_vault,
            vault_path=active_vault,
            frontier_plan_path=frontier_plan,
            staging_plan_path=staging_plan,
            prefix_plan_path=prefix_plan,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
        )

    outcome = execute_episode(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=public_target.verify,
        bindings=bindings,
    )
    runtime = cast(
        Mapping[str, object],
        _base_call(
            lambda: _publication_base._o1c78_runtime_resources(
                started=started,
                cpu_started=cpu_started,
                child_started=child_started,
            )
        ),
    )
    result = build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit=cast(str, preflight_row["execution_commit"]),
        preflight=preflight_row,
        started_at=started_at,
        runtime=runtime,
    )
    write_recovery_source(capsule, result)
    finalize_capsule(capsule, authoritative, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight, run, or recover O1C80's one Page-7 bound call"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", default=str(CONFIG_RELATIVE))
    recovery = subparsers.add_parser("recover")
    recovery.add_argument("--capsule", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            value = preflight(args.config)
        elif args.command == "run":
            value = run(args.config)
        else:
            root = lab_root().resolve(strict=True)
            capsule = Path(args.capsule).resolve(strict=True)
            if not capsule.is_relative_to(root / "runs"):
                raise O1C80RunError("recovery capsule escapes run root")
            value = recover_publication(capsule)
            finalize_capsule(capsule, root / RESULT_RELATIVE, value)
        sys.stdout.buffer.write(canonical_json_bytes(value))
        return 0
    except O1C80RunError as exc:
        print(f"O1C80: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
