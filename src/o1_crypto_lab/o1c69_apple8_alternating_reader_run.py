"""O1C-0069: one explicit phase-1 reader call from O1C-0068's vault.

O1C-0068 consumed lineage ordinal 4 and sealed a 202-clause phase-0 gain.
O1C-0069 imports that exact vault, persists a new local intent for lineage
ordinal 5, and authorizes exactly one native-v8 process whose scientific change
is the alternating phase-1 reader applied to the enlarged state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v11 as _native_v11
from . import o1c68_apple8_complementary_phase_run as _o1c68
from .joint_score_grouping_v1 import COMPATIBILITY_GROUPING_BOUND_RULE
from .o1_relational_search import NativeGuidedSearchBuild, sha256_file
from .o1c37_relational_guided_search_run import _git_commit, lab_root
from .o1c59_multiblock_joint_score_sieve_run import (
    _atomic_bytes,
    _atomic_json,
    _canonical_json_bytes,
    _commit_bound_bytes,
    _memory_free_percent,
    _replace_owned_json,
)


_o1c67 = _o1c68._o1c67
_o1c65 = _o1c68._o1c65
_o1c66 = _o1c68._o1c66
_vault_v1 = _o1c68._vault_v1

ATTEMPT_ID = "O1C-0069"
CONFIG_SCHEMA = "o1-256-apple8-alternating-reader-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-alternating-reader-preflight-v1"
INVOCATION_SCHEMA = "o1-256-apple8-alternating-reader-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-alternating-reader-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-alternating-reader-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-alternating-reader-result-v1"
FAILURE_EVIDENCE_SCHEMA = "o1-256-o1c69-native-failure-evidence-v1"
PUBLICATION_RECOVERY_SCHEMA = "o1-256-o1c69-publication-recovery-v1"

INVOCATION_ID = "O1C-0069-apple8-alternating-reader-v1-call-0005"
CAPSULE_SUFFIX = "O1C-0069_apple8-alternating-reader-v1"
PUBLICATION_SOURCE_NAME = "publication_source.json"
RESULT_RELATIVE = Path(
    "research/O1C0069_APPLE8_ALTERNATING_READER_RESULT_20260719.json"
)
DESIGN_RELATIVE = Path("research/O1C0069_APPLE8_ALTERNATING_READER_DESIGN_20260719.md")
CONFIG_RELATIVE = Path("configs/o1c69_apple8_alternating_reader_v1.json")

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0068_APPLE8_COMPLEMENTARY_PHASE_RESULT_20260719.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_161838_O1C-0068_apple8-complementary-phase-v1"
)
PARENT_RESULT_SHA256 = (
    "d494887d2be96516211acf09ff8852a88a44576044723223b9057942fd7aea80"
)
PARENT_MANIFEST_SHA256 = (
    "dd0236774c1352238cce86458a8f01380aa32dc538dbe80a3c1744b0f126a745"
)
PARENT_SOURCE_COMMIT = "8446414d73e871de829c182ca4cd5b500e4d9d14"
PARENT_RETAINED_VAULT_RELATIVE = Path("episodes/00/vault-output.bin")
PARENT_RETAINED_VAULT_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PARENT_RETAINED_VAULT_BYTES = 2_399_911
PARENT_RETAINED_VAULT_CLAUSES = 202
PARENT_RETAINED_VAULT_LITERALS = 599_728
PARENT_RETAINED_VAULT_AGGREGATE_SHA256 = (
    "72d788d52064f4d67ea4355069df0420ecfb100656a985691ff82000794dd0e9"
)
PARENT_ATTEMPT_NATIVE_CALLS = 1
PARENT_LINEAGE_CALLS = 5
PARENT_COMPLETED_EPISODES = 1
PARENT_LAST_CONSUMED_ORDINAL = 4
PARENT_LAST_COMPLETED_ORDINAL = 4
PARENT_FAILED_ORDINAL = 2
PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS = 2_051
PARENT_FAILED_CALL_BILLED_CONFLICTS: None = None
PARENT_LINEAGE_ACTUAL_BILLED_CONFLICTS: None = None
PARENT_LAST_DECISIONS = 1_330
PARENT_LAST_PROPAGATIONS = 31_944_523
PARENT_LAST_MINIMUM_UPPER_BOUND = 12.8607806294803

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 5
MAXIMUM_NATIVE_SOLVER_CALLS = 1
REQUESTED_CONFLICTS = 512
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_FAILURE_STREAM_BYTES = 1_048_576
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 67_108_864
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MINIMUM_MEMORY_FREE_PERCENT = 25
MAXIMUM_NORMALIZED_LOAD_1M = 0.75
PLANNING_RESERVED_CLAUSES = 397
PLANNING_RESERVED_LITERALS = 1_179_254
PLANNING_RESERVED_BYTES = 4_718_795
THRESHOLD = _o1c66.THRESHOLD
SEED = 0

APPLE8_CNF_SHA256 = _o1c66.APPLE8_CNF_SHA256
APPLE8_POTENTIAL_SHA256 = _o1c66.APPLE8_POTENTIAL_SHA256
GROUPING_SHA256 = _o1c66.GROUPING_SHA256

CAPACITY_RESERVATION: dict[str, object] = {
    "schema": "o1-256-o1c69-observed-envelope-capacity-reservation-v1",
    "basis_attempt": "O1C-0068",
    "basis": "matched-observed-fully-emitted-envelope-not-formal-maximum",
    "planning_only": True,
    "formal_maximum": False,
    "input_clause_count": PARENT_RETAINED_VAULT_CLAUSES,
    "input_literal_count": PARENT_RETAINED_VAULT_LITERALS,
    "input_serialized_bytes": PARENT_RETAINED_VAULT_BYTES,
    "observed_envelope_clause_count": 195,
    "observed_envelope_literal_count": 579_526,
    "observed_envelope_serialized_bytes": 2_318_884,
    "projected_clause_count": PLANNING_RESERVED_CLAUSES,
    "projected_literal_count": PLANNING_RESERVED_LITERALS,
    "projected_serialized_bytes": PLANNING_RESERVED_BYTES,
    "maximum_clause_count": _o1c66.VAULT_MAXIMUM_CLAUSES,
    "maximum_literal_count": _o1c66.VAULT_MAXIMUM_LITERALS,
    "maximum_serialized_bytes": _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES,
    "hard_caps_fail_closed": True,
}

READER_SCHEMA = "o1-256-cadical-forced-initial-phase-reader-v1"
READER_OPERATOR = "forced-initial-phase"
READER_COMPLEMENT_PAIR_ID = "forced-initial-phase-v1"
READER_SPEC_SHA256 = "ce039b56a647cbc67deea1fa70db7e755ea00a6dd183015a43e94c032b5706cc"
READER_BINDING: dict[str, object] = {
    "schema": READER_SCHEMA,
    "operator": READER_OPERATOR,
    "cadical_configuration": "plain",
    "phase_before_override": 1,
    "seed": 0,
    "quiet": 1,
    "factor": 0,
    "phase": 1,
    "forcephase": True,
    "rephase": 0,
    "lucky": False,
    "walk": False,
    "complement_pair_id": READER_COMPLEMENT_PAIR_ID,
    "reader_spec_sha256": READER_SPEC_SHA256,
}

NATIVE_RESULT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v8"
NATIVE_IMPLEMENTATION_PARENT_SCHEMA = "o1-256-cadical-joint-score-sieve-result-v6"
NATIVE_ADAPTER_SCHEMA = "o1-256-joint-score-sieve-v11-adapter-v1"
NATIVE_LEDGER_SCHEMA = _native_v11.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
NATIVE_VAULT_TELEMETRY_SCHEMA = _o1c67.NATIVE_VAULT_TELEMETRY_SCHEMA

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
ALTERNATING_READER_GAIN = "EPISODIC_VAULT_ALTERNATING_READER_GAIN"
ALTERNATING_READER_NO_GAIN = "EPISODIC_VAULT_ALTERNATING_READER_NO_GAIN"
THRESHOLD_REGION_EXHAUSTED = "EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED"
CAPACITY_TERMINAL = "EPISODIC_VAULT_CAPACITY_TERMINAL"
OPERATIONAL_TERMINAL = "EPISODIC_VAULT_ALTERNATING_READER_OPERATIONAL_TERMINAL"
INVALID_RESULT_TERMINAL = "EPISODIC_VAULT_ALTERNATING_READER_INVALID_RESULT"

SOURCE_RELATIVES = {
    "runner": "src/o1_crypto_lab/o1c69_apple8_alternating_reader_run.py",
    "joint_score_sieve_v11": "src/o1_crypto_lab/joint_score_sieve_v11.py",
    "joint_score_sieve_v10": "src/o1_crypto_lab/joint_score_sieve_v10.py",
    "joint_score_sieve_v9": "src/o1_crypto_lab/joint_score_sieve_v9.py",
    "native_source": "native/cadical_o1_joint_score_sieve_v8.cpp",
    "native_parent_source": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "o1c68_runner": "src/o1_crypto_lab/o1c68_apple8_complementary_phase_run.py",
    "o1c67_runner": (
        "src/o1_crypto_lab/o1c67_apple8_episodic_vault_continuation_run.py"
    ),
    "o1c66_runner": "src/o1_crypto_lab/o1c66_apple8_episodic_vault_run.py",
    "o1c65_runner": "src/o1_crypto_lab/o1c65_apple8_width6_grouped_run.py",
    "joint_score_grouping_v1": "src/o1_crypto_lab/joint_score_grouping_v1.py",
    "threshold_no_good_vault_v1": ("src/o1_crypto_lab/threshold_no_good_vault_v1.py"),
    "lifecycle_helpers": "src/o1_crypto_lab/o1c59_multiblock_joint_score_sieve_run.py",
    "chacha_trace": "src/o1_crypto_lab/chacha_trace.py",
    "full256_broker": "src/o1_crypto_lab/full256_broker.py",
    "design": DESIGN_RELATIVE.as_posix(),
}
SOURCE_NAMES = tuple(SOURCE_RELATIVES)
CONFIG_FIELDS = {
    "schema",
    "attempt_id",
    "slug",
    "claim_level",
    "hypothesis",
    "prediction",
    "source",
    "frozen_sha256",
    "grouping_provenance",
    "input",
    "parent",
    "retained_vault",
    "reader",
    "invocation",
    "native",
    "budgets",
    "capacity_reservation",
    "next_action",
}


class O1C69RunError(RuntimeError):
    """O1C-0069 provenance, protocol, reader, or result differs."""


class O1C69ParentError(O1C69RunError):
    """The sealed O1C-0068 parent or retained vault differs."""


class EpisodeInvoker(Protocol):
    def __call__(self, local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        """Make the one authorized fresh native-v8 process call."""


@dataclass(frozen=True)
class ImportedParentVault:
    source_path: Path
    payload: bytes
    independent: _o1c66.ClauseVault
    adapter: _vault_v1.ThresholdNoGoodVault


@dataclass(frozen=True)
class SingleContinuationOutcome:
    classification: str
    stop_reason: str
    episode: Mapping[str, object]
    final_vault: _o1c66.ClauseVault
    native_calls: int
    requested_conflicts: int
    billed_conflicts: int | None
    operational_failure: Mapping[str, object] | None


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C69RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C69RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C69RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1C69RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C69RunError(f"{field} differs")
    return value


def _digest_or_pending(value: object, field: str) -> str:
    if value == "PENDING":
        return "PENDING"
    return _sha256(value, field)


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C69RunError(f"{field} differs")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise O1C69RunError(f"{field} escapes the lab")
    try:
        path = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise O1C69RunError(f"{field} cannot be resolved") from exc
    if not path.is_relative_to(root):
        raise O1C69RunError(f"{field} escapes the lab")
    return path


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C69RunError(f"{field} cannot be read") from exc
    return _mapping(value, field)


def _validate_reader(value: object, field: str = "reader") -> dict[str, object]:
    reader = _mapping(value, field)
    if set(reader) != set(READER_BINDING):
        raise O1C69RunError(f"{field} fields differ")
    integer_fields = {
        "phase_before_override": 1,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "phase": 1,
        "rephase": 0,
    }
    boolean_fields = {
        "forcephase": True,
        "lucky": False,
        "walk": False,
    }
    if any(
        isinstance(reader.get(name), bool)
        or not isinstance(reader.get(name), int)
        or reader.get(name) != expected
        for name, expected in integer_fields.items()
    ) or any(
        not isinstance(reader.get(name), bool) or reader.get(name) is not expected
        for name, expected in boolean_fields.items()
    ):
        raise O1C69RunError(f"{field} phase binding differs")
    for name in set(READER_BINDING) - set(integer_fields) - set(boolean_fields):
        if reader.get(name) != READER_BINDING[name]:
            raise O1C69RunError(f"{field} identity differs")
    return dict(reader)


FROZEN_APPLE8_SHA256 = {
    "authoritative_result": (
        "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be"
    ),
    "manifest": "751b89019d1f65b8180b15eafbb4bdf45c6080b0894c50567ee63eff15405a69",
    "capsule_result": (
        "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be"
    ),
    "native_result": (
        "2cbd354b2d39d7c80206c6f3fb06ed4583d4b7c8436334f76ccaa1feaac5ab20"
    ),
    "preflight": "c0456e495d340fe8f08569ffc511608db976c0702988101ceaf946b668cc5880",
    "native_build": (
        "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a"
    ),
    "truth_reveal": (
        "63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd"
    ),
}


def load_config(path: str | Path) -> dict[str, object]:
    """Load the exact O1C-0069 protocol without a call or filesystem write."""

    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C69RunError("config escapes the lab")
    config = dict(_read_json(config_path, "O1C69 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    grouping = _mapping(config.get("grouping_provenance"), "grouping_provenance")
    input_row = _mapping(config.get("input"), "input")
    parent = _mapping(config.get("parent"), "parent")
    retained = _mapping(config.get("retained_vault"), "retained_vault")
    invocation = _mapping(config.get("invocation"), "invocation")
    native = _mapping(config.get("native"), "native")
    budgets = _mapping(config.get("budgets"), "budgets")
    capacity = validate_capacity_reservation(config.get("capacity_reservation"))
    reader = _validate_reader(config.get("reader"), "config.reader")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-alternating-reader-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or any(source.get(name) != path for name, path in SOURCE_RELATIVES.items())
        or dict(frozen) != FROZEN_APPLE8_SHA256
        or grouping.get("source_attempt") != "APPLE-VIEW-0009"
        or grouping.get("result")
        != "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json"
        or grouping.get("result_sha256")
        != "ebbe9e308f3e3dfa00685a9c10eba6554c85e453459178a26a03b9fc6b2b3728"
        or grouping.get("classification")
        != "PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM"
        or grouping.get("native_solver_calls") != 0
        or grouping.get("truth_bytes_read") is not False
        or input_row.get("apple8_result")
        != "research/apple_view_8/apple_view_8_matched_result.json"
        or input_row.get("apple8_capsule")
        != "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
        or input_row.get("cnf_relative")
        != "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
        or input_row.get("potential_relative")
        != "artifacts/potential/primary-eight-block.potential"
        or input_row.get("truth_reveal")
        != "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/reveal.json"
        or input_row.get("cnf_sha256") != APPLE8_CNF_SHA256
        or input_row.get("potential_sha256") != APPLE8_POTENTIAL_SHA256
        or input_row.get("threshold") != THRESHOLD
        or input_row.get("seed") != SEED
        or input_row.get("fresh_targets") != 0
        or input_row.get("scientific_entropy_calls") != 0
        or input_row.get("fresh_reveal_calls") != 0
        or input_row.get("refits") != 0
        or parent.get("attempt_id") != "O1C-0068"
        or parent.get("result") != PARENT_RESULT_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("classification") != _o1c68.COMPLEMENTARY_PHASE_GAIN
        or parent.get("native_calls_consumed") != PARENT_ATTEMPT_NATIVE_CALLS
        or parent.get("lineage_calls_consumed") != PARENT_LINEAGE_CALLS
        or parent.get("completed_episodes") != PARENT_COMPLETED_EPISODES
        or parent.get("last_consumed_ordinal") != PARENT_LAST_CONSUMED_ORDINAL
        or parent.get("last_completed_ordinal") != PARENT_LAST_COMPLETED_ORDINAL
        or parent.get("failed_ordinal") != PARENT_FAILED_ORDINAL
        or parent.get("known_completed_billed_conflicts")
        != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or parent.get("failed_call_billed_conflicts") is not None
        or parent.get("lineage_actual_billed_conflicts") is not None
        or parent.get("retry_authorized") is not False
        or parent.get("truth_key_bytes_read") is not False
        or retained.get("path") != PARENT_RETAINED_VAULT_RELATIVE.as_posix()
        or retained.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or retained.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or retained.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or retained.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or retained.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
        or retained.get("copy_into_capsule_as") != "vault-imported.bin"
        or retained.get("dual_parse_required") is not True
        or invocation.get("invocation_id") != INVOCATION_ID
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("continuation_calls_before") != 0
        or invocation.get("lineage_calls_before") != PARENT_LINEAGE_CALLS
        or invocation.get("parent_last_consumed_ordinal")
        != PARENT_LAST_CONSUMED_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
        or native.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_SOLVER_CALLS
        or native.get("requested_conflicts") != REQUESTED_CONFLICTS
        or native.get("billing_rule") != "actual-nonnegative-solve-conflicts"
        or native.get("timeout_seconds") != TIMEOUT_SECONDS
        or native.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or native.get("seed") != SEED
        or native.get("result_schema") != NATIVE_RESULT_SCHEMA
        or native.get("implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or native.get("adapter_schema") != NATIVE_ADAPTER_SCHEMA
        or native.get("ledger_schema") != NATIVE_LEDGER_SCHEMA
        or native.get("vault_telemetry_schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
        or native.get("reader_spec_sha256") != READER_SPEC_SHA256
        or native.get("fresh_process") is not True
        or "maximum_billed_conflicts" in native
        or "maximum_conflict_limit_overshoot" in native
        or budgets.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_SOLVER_CALLS
        or budgets.get("maximum_requested_conflicts") != REQUESTED_CONFLICTS
        or budgets.get("maximum_failure_stream_bytes") != MAXIMUM_FAILURE_STREAM_BYTES
        or budgets.get("maximum_persistent_artifact_bytes")
        != MAXIMUM_PERSISTENT_ARTIFACT_BYTES
        or budgets.get("minimum_disk_free_bytes") != MINIMUM_DISK_FREE_BYTES
        or budgets.get("minimum_memory_free_percent") != MINIMUM_MEMORY_FREE_PERCENT
        or budgets.get("maximum_normalized_load_1m") != MAXIMUM_NORMALIZED_LOAD_1M
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_scientific_entropy_calls") != 0
        or budgets.get("maximum_fresh_reveal_calls") != 0
        or budgets.get("maximum_refits") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or capacity["projected_clause_count"] != PLANNING_RESERVED_CLAUSES
        or capacity["projected_literal_count"] != PLANNING_RESERVED_LITERALS
        or capacity["projected_serialized_bytes"] != PLANNING_RESERVED_BYTES
        or reader != READER_BINDING
    ):
        raise O1C69RunError("frozen O1C-0069 config differs")
    for name in SOURCE_NAMES:
        _digest_or_pending(expected[name], f"source.expected_sha256.{name}")
    source_native = _digest_or_pending(
        native.get("expected_source_sha256"), "native.expected_source_sha256"
    )
    executable = _digest_or_pending(
        native.get("expected_executable_sha256"),
        "native.expected_executable_sha256",
    )
    if source_native != expected["native_source"] or executable == "":
        raise O1C69RunError("native source/executable binding differs")
    return config


def validate_capacity_reservation(value: object) -> dict[str, object]:
    """Validate the conservative observed-envelope reservation before a call."""

    capacity = _mapping(value, "capacity_reservation")
    if dict(capacity) != CAPACITY_RESERVATION:
        raise O1C69RunError("capacity reservation differs")
    projected_clauses = _nonnegative_int(
        capacity["projected_clause_count"], "projected clause count"
    )
    projected_literals = _nonnegative_int(
        capacity["projected_literal_count"], "projected literal count"
    )
    projected_bytes = _nonnegative_int(
        capacity["projected_serialized_bytes"], "projected serialized bytes"
    )
    maximum_clauses = _nonnegative_int(
        capacity["maximum_clause_count"], "maximum clause count"
    )
    maximum_literals = _nonnegative_int(
        capacity["maximum_literal_count"], "maximum literal count"
    )
    maximum_bytes = _nonnegative_int(
        capacity["maximum_serialized_bytes"], "maximum serialized bytes"
    )
    if (
        projected_clauses > maximum_clauses
        or projected_literals > maximum_literals
        or projected_bytes > maximum_bytes
    ):
        raise O1C69RunError("capacity reservation exceeds a hard vault cap")
    return dict(capacity)


def _manifest_inventory(capsule: Path) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != PARENT_MANIFEST_SHA256:
        raise O1C69ParentError("O1C-0068 manifest identity differs")
    inventory: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            if separator != "  " or relative in inventory:
                raise O1C69ParentError("O1C-0068 manifest syntax differs")
            _sha256(digest, "O1C-0068 manifest digest")
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise O1C69ParentError("O1C-0068 manifest path escapes")
            inventory[relative] = digest
    except (OSError, UnicodeError, ValueError) as exc:
        raise O1C69ParentError("O1C-0068 manifest cannot be read") from exc
    return inventory


def validate_parent_and_import_vault(
    root: Path, config: Mapping[str, object], frozen: object
) -> ImportedParentVault:
    """Verify and dual-parse O1C-0068's exact sealed output vault."""

    del config
    result_path = root / PARENT_RESULT_RELATIVE
    capsule = root / PARENT_CAPSULE_RELATIVE
    if (
        sha256_file(result_path) != PARENT_RESULT_SHA256
        or not capsule.is_dir()
        or capsule.is_symlink()
    ):
        raise O1C69ParentError("O1C-0068 parent identity differs")
    result = _read_json(result_path, "O1C-0068 result")
    episode = _mapping(result.get("episode"), "O1C-0068 episode")
    final_vault = _mapping(result.get("final_vault"), "O1C-0068 final vault")
    resources = _mapping(result.get("resources"), "O1C-0068 resources")
    parent = _mapping(result.get("parent"), "O1C-0068 lineage parent")
    claim = _mapping(result.get("claim_boundary"), "O1C-0068 claim boundary")
    if (
        result.get("attempt_id") != "O1C-0068"
        or result.get("classification") != _o1c68.COMPLEMENTARY_PHASE_GAIN
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("local_episode_ordinal") != 0
        or result.get("lineage_call_ordinal") != 4
        or episode.get("completed") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("billed_conflicts") != 512
        or episode.get("retry_authorized") is not False
        or resources.get("native_solver_calls") != 1
        or resources.get("billed_conflicts") != 512
        or resources.get("lineage_actual_billed_conflicts") is not None
        or parent.get("known_completed_billed_conflicts") != 1_539
        or parent.get("failed_call_billed_conflicts") is not None
        or claim.get("truth_key_bytes_read") is not False
        or final_vault.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or final_vault.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or final_vault.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or final_vault.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or final_vault.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C69ParentError("O1C-0068 terminal evidence differs")
    inventory = _manifest_inventory(capsule)
    required = {
        PARENT_RETAINED_VAULT_RELATIVE.as_posix(): PARENT_RETAINED_VAULT_SHA256,
        "result.json": PARENT_RESULT_SHA256,
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C69ParentError("O1C-0068 manifest inventory differs")
    for relative, digest in required.items():
        if sha256_file(capsule / relative) != digest:
            raise O1C69ParentError("O1C-0068 capsule artifact differs")

    source = capsule / PARENT_RETAINED_VAULT_RELATIVE
    try:
        status = source.stat(follow_symlinks=False)
        if (
            source.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_size != PARENT_RETAINED_VAULT_BYTES
        ):
            raise O1C69ParentError("retained vault file identity differs")
        payload = source.read_bytes()
    except O1C69ParentError:
        raise
    except OSError as exc:
        raise O1C69ParentError("retained vault cannot be read") from exc
    if hashlib.sha256(payload).hexdigest() != PARENT_RETAINED_VAULT_SHA256:
        raise O1C69ParentError("retained vault hash differs")

    field = cast(object, getattr(frozen, "field"))
    observed_tuple = tuple(cast(Sequence[int], getattr(field, "observed_variables")))
    observed = frozenset(observed_tuple)
    try:
        independent = _o1c66.ClauseVault.from_bytes(
            payload,
            expected_identity=_o1c66.frozen_vault_identity(field),  # type: ignore[arg-type]
            observed_variables=observed,
        )
        adapter = _vault_v1.parse_threshold_no_good_vault(
            payload,
            observed_variables=observed_tuple,
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
        expected_identity = _vault_v1.vault_identity_from_sources(
            cnf_sha256=APPLE8_CNF_SHA256,
            potential_sha256=APPLE8_POTENTIAL_SHA256,
            grouping_sha256=GROUPING_SHA256,
            observed_variables=observed_tuple,
            bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
            threshold=THRESHOLD,
        )
        _vault_v1.validate_threshold_no_good_vault_identity(
            adapter, expected=expected_identity
        )
    except Exception as exc:
        raise O1C69ParentError("retained vault dual parse differs") from exc
    if (
        independent.to_bytes() != payload
        or adapter.serialized != payload
        or independent.sha256 != adapter.sha256
        or independent.sha256 != PARENT_RETAINED_VAULT_SHA256
        or len(independent.clauses) != PARENT_RETAINED_VAULT_CLAUSES
        or independent.literal_count != PARENT_RETAINED_VAULT_LITERALS
        or independent.aggregate_clause_sha256 != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C69ParentError("retained vault parsers disagree")
    return ImportedParentVault(source, payload, independent, adapter)


def _source_hashes(root: Path, config: Mapping[str, object]) -> dict[str, str]:
    source = _mapping(config["source"], "source")
    return {
        name: sha256_file(_relative(root, source[name], f"source.{name}"))
        for name in SOURCE_NAMES
    }


def _selected_sources_clean(
    root: Path, config_path: Path, config: Mapping[str, object]
) -> bool:
    source = _mapping(config["source"], "source")
    paths = [
        config_path,
        *(_relative(root, source[name], name) for name in SOURCE_NAMES),
    ]
    relatives = [path.relative_to(root).as_posix() for path in paths]
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--", *relatives],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0 and not completed.stdout.strip()


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    """Read-only authorization with zero writes, calls, targets, or truth reads."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "source.expected_sha256")
    observed = _source_hashes(root, config)
    unresolved = tuple(name for name in SOURCE_NAMES if expected[name] == "PENDING")
    for name in SOURCE_NAMES:
        if expected[name] != "PENDING" and observed[name] != expected[name]:
            raise O1C69RunError(f"source hash differs for {name}")
    if require_commit_binding and unresolved:
        raise O1C69RunError("science source hashes remain PENDING")
    if (
        getattr(_native_v11, "JOINT_SCORE_SIEVE_ADAPTER_SCHEMA", None)
        != NATIVE_ADAPTER_SCHEMA
        or getattr(_native_v11, "JOINT_SCORE_SIEVE_RESULT_SCHEMA", None)
        != NATIVE_RESULT_SCHEMA
        or getattr(_native_v11, "JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA", None)
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
    ):
        raise O1C69RunError("adapter-v11 schema binding differs")

    baseline = _o1c65.validate_apple8_baseline(root, config)
    _o1c65.validate_grouping_provenance(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    capacity = validate_capacity_reservation(config["capacity_reservation"])
    source_commit = _git_commit(root)
    clean = _selected_sources_clean(root, config_file, config)
    if require_commit_binding:
        if not clean:
            raise O1C69RunError("science sources/config are not clean")
        for name in SOURCE_NAMES:
            _commit_bound_bytes(
                root, source_commit, _relative(root, source[name], name), name
            )
        _commit_bound_bytes(root, source_commit, config_file, "config")

    memory_free = _memory_free_percent()
    disk_free = shutil.disk_usage(root).free
    cpu_count = max(os.cpu_count() or 1, 1)
    load_1m = os.getloadavg()[0]
    normalized_load = load_1m / cpu_count
    active = _o1c67._active_conflicting_processes()
    if memory_free is not None and memory_free < MINIMUM_MEMORY_FREE_PERCENT:
        raise O1C69RunError("memory-pressure preflight is below gate")
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C69RunError("disk-free preflight is below gate")
    if normalized_load > MAXIMUM_NORMALIZED_LOAD_1M:
        raise O1C69RunError("normalized system load is above gate")
    if active:
        raise O1C69RunError("conflicting science process is active")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "source_tree_clean": clean,
        "config_sha256": sha256_file(config_file),
        "source_sha256": observed,
        "unresolved_source_hashes": list(unresolved),
        "adapter_source_sha256": observed["joint_score_sieve_v11"],
        "native_source_sha256": observed["native_source"],
        "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "native_implementation_parent_schema": NATIVE_IMPLEMENTATION_PARENT_SCHEMA,
        "reader": dict(READER_BINDING),
        "reader_spec_sha256": READER_SPEC_SHA256,
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_lineage_calls_consumed": PARENT_LINEAGE_CALLS,
        "parent_last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
        "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
        "parent_known_completed_billed_conflicts": (
            PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        ),
        "parent_failed_call_billed_conflicts": None,
        "parent_lineage_actual_billed_conflicts": None,
        "retained_vault_sha256": imported.independent.sha256,
        "retained_vault_clause_count": len(imported.independent.clauses),
        "retained_vault_literal_count": imported.independent.literal_count,
        "retained_vault_serialized_bytes": imported.independent.serialized_bytes,
        "capacity_reservation": capacity,
        "cnf_sha256": sha256_file(cnf),
        "potential_sha256": sha256_file(potential),
        "grouping_sha256": frozen.grouping.sha256,
        "invocation_id": INVOCATION_ID,
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "maximum_billed_conflicts": None,
        "maximum_conflict_limit_overshoot": None,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "memory_pressure_free_percent": memory_free,
        "disk_free_bytes": disk_free,
        "load_1m": load_1m,
        "cpu_count": cpu_count,
        "normalized_load_1m": normalized_load,
        "active_conflicting_processes": active,
        "native_solver_calls": 0,
        "files_written": 0,
        "public_target_artifacts_validated": True,
        "fresh_target_bytes_generated": 0,
        "truth_key_bytes_read": False,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def native_failure_evidence(exc: BaseException, directory: Path) -> dict[str, object]:
    """Persist bounded process streams while retaining full lengths and hashes."""

    raw_returncode = _o1c67._first_evidence(exc, "returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    command = _o1c67._first_evidence(exc, "command") or _o1c67._first_evidence(
        exc, "cmd"
    )
    stdout = _o1c67._stream_bytes(_o1c67._first_evidence(exc, "stdout"))
    stderr = _o1c67._stream_bytes(_o1c67._first_evidence(exc, "stderr"))
    raw_telemetry = getattr(exc, "failure_telemetry", None)
    adapter_telemetry: dict[str, object] | None
    if isinstance(raw_telemetry, Mapping):
        adapter_telemetry = dict(raw_telemetry)
        adapter_telemetry["stdout"] = None
        adapter_telemetry["stderr"] = None
        adapter_telemetry["raw_streams_externalized"] = True
    else:
        adapter_telemetry = None
    return {
        "schema": FAILURE_EVIDENCE_SCHEMA,
        "returncode": returncode,
        "command": (
            [str(part) for part in command]
            if isinstance(command, (list, tuple))
            else str(command)
            if command is not None
            else None
        ),
        "stdout": _o1c67._failure_stream(directory, "stdout", stdout),
        "stderr": _o1c67._failure_stream(directory, "stderr", stderr),
        "exception_chain_outer_to_cause_or_context": _o1c67._exception_chain(exc),
        "adapter_failure_telemetry": adapter_telemetry,
    }


def _invocation(
    bindings: Mapping[str, object], vault: _o1c66.ClauseVault
) -> dict[str, object]:
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "invocation_id": INVOCATION_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "continuation_calls_before": 0,
        "lineage_calls_before": PARENT_LINEAGE_CALLS,
        "parent_last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
        "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
        "parent_ordinal_replay_authorized": False,
        "episode_is_retry": False,
        "calls_authorized": 1,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "maximum_billed_conflicts": None,
        "maximum_conflict_limit_overshoot": None,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "parent_known_completed_billed_conflicts": (
            PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        ),
        "parent_failed_call_billed_conflicts": None,
        "lineage_actual_billed_conflicts": None,
        "reader": dict(READER_BINDING),
        "capacity_reservation": dict(CAPACITY_RESERVATION),
        "retained_vault": vault.describe(),
        "bindings": dict(bindings),
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _intent(
    invocation_sha256: str,
    vault: _o1c66.ClauseVault,
    bindings: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "invocation_id": INVOCATION_ID,
        "invocation_sha256": invocation_sha256,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "episode_is_retry": False,
        "parent_ordinal_replay_authorized": False,
        "calls_before": 0,
        "calls_authorized_by_this_intent": 1,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "billing_rule": "actual-nonnegative-solve-conflicts",
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "reader": dict(READER_BINDING),
        "reader_spec_sha256": READER_SPEC_SHA256,
        "capacity_reservation": dict(CAPACITY_RESERVATION),
        "adapter_source_sha256": bindings.get("adapter_source_sha256"),
        "native_source_sha256": bindings.get("native_source_sha256"),
        "native_adapter_schema": bindings.get("native_adapter_schema"),
        "native_result_schema": bindings.get("native_result_schema"),
        "bindings": dict(bindings),
        "input_vault": vault.describe(),
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _validated_native(
    result: object,
) -> tuple[
    dict[str, object], dict[str, int | float], Mapping[str, object], dict[str, object]
]:
    try:
        raw = _mapping(getattr(result, "raw"), "native.raw")
        result_reader = _validate_reader(getattr(result, "reader"), "native.reader")
        raw_reader = _validate_reader(raw.get("reader"), "native.raw.reader")
        stats = _native_v11.validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native.stats")
        )
        resources = _mapping(getattr(result, "resources"), "native.resources")
        sieve = _mapping(getattr(result, "sieve"), "native.sieve")
        telemetry = _mapping(
            getattr(result, "vault_telemetry"), "native.vault_telemetry"
        )
        status = getattr(result, "status")
        conflict_limit = getattr(result, "conflict_limit")
        threshold = getattr(result, "threshold")
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        minimum_upper_bound = _finite_float(
            sieve.get("minimum_upper_bound"), "minimum upper bound"
        )
        root_upper_bound = _finite_float(
            sieve.get("root_upper_bound"), "root upper bound"
        )
        fully_emitted = _nonnegative_int(
            sieve.get("external_clauses_emitted"), "fully emitted clauses"
        )
        pending_clauses = _nonnegative_int(
            sieve.get("pending_clause_count"), "pending clauses"
        )
        if (
            result_reader != READER_BINDING
            or raw_reader != READER_BINDING
            or isinstance(status, bool)
            or status not in (0, 10, 20)
            or conflict_limit != REQUESTED_CONFLICTS
            or threshold != THRESHOLD
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or raw.get("schema") != NATIVE_RESULT_SCHEMA
            or raw.get("implementation_parent_schema")
            != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            or telemetry.get("schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
            or peak > MEMORY_LIMIT_BYTES
            or wall > int(TIMEOUT_SECONDS * 1_000_000)
        ):
            raise O1C69RunError("native O1C-0069 contract differs")
        ledger: dict[str, int | float] = {
            **stats,
            "status": cast(int, status),
            "peak_rss_bytes": peak,
            "wall_microseconds": wall,
            "cpu_microseconds": cpu,
            "minimum_upper_bound": minimum_upper_bound,
            "root_upper_bound": root_upper_bound,
            "fully_emitted_clauses": fully_emitted,
            "pending_clause_count": pending_clauses,
        }
        return dict(raw), ledger, telemetry, result_reader
    except O1C69RunError:
        raise
    except Exception as exc:
        raise O1C69RunError("native O1C-0069 result differs") from exc


def execute_single_continuation(
    *,
    capsule: Path,
    imported_vault: _o1c66.ClauseVault,
    adapter_vault: _vault_v1.ThresholdNoGoodVault,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object],
) -> SingleContinuationOutcome:
    """Persist ordinal 5, consume exactly one call, and never retry it."""

    if not capsule.is_dir() or imported_vault.sha256 != PARENT_RETAINED_VAULT_SHA256:
        raise O1C69RunError("single-continuation capsule or vault differs")
    if (
        len(imported_vault.clauses) != PARENT_RETAINED_VAULT_CLAUSES
        or imported_vault.literal_count != PARENT_RETAINED_VAULT_LITERALS
        or imported_vault.serialized_bytes != PARENT_RETAINED_VAULT_BYTES
        or PLANNING_RESERVED_CLAUSES > _o1c66.VAULT_MAXIMUM_CLAUSES
        or PLANNING_RESERVED_LITERALS > _o1c66.VAULT_MAXIMUM_LITERALS
        or PLANNING_RESERVED_BYTES > _o1c66.VAULT_MAXIMUM_SERIALIZED_BYTES
    ):
        raise O1C69RunError("capacity reservation is not call-safe")
    imported_path = capsule / "vault-imported.bin"
    _o1c66.write_vault(imported_path, imported_vault)
    if imported_path.read_bytes() != adapter_vault.serialized:
        raise O1C69RunError("dual-parsed imported vault bytes differ")
    reread = _o1c66.read_vault(
        imported_path,
        identity=imported_vault.identity,
        observed_variables=imported_vault.observed_variables,
    )
    if reread != imported_vault:
        raise O1C69RunError("capsule imported vault reread differs")

    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, _invocation(bindings, imported_vault))
    invocation_sha = sha256_file(invocation_path)
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, _intent(invocation_sha, imported_vault, bindings))
    intent_sha = sha256_file(intent_path)
    if not invocation_path.is_file() or not intent_path.is_file():
        raise O1C69RunError("invocation/intent not durable before call")

    try:
        result = invoke_episode(
            LOCAL_EPISODE_ORDINAL, LINEAGE_CALL_ORDINAL, imported_path
        )
    except BaseException as exc:
        evidence = native_failure_evidence(exc, episode_dir)
        evidence_path = episode_dir / "native_execution_failure.json"
        _atomic_json(evidence_path, evidence)
        failure = {
            "classification": OPERATIONAL_TERMINAL,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "reader": dict(READER_BINDING),
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "native_execution_failure_sha256": sha256_file(evidence_path),
            "truth_key_bytes_read": False,
        }
        _atomic_json(episode_dir / "terminal_failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "intent_sha256": intent_sha,
            "reader": dict(READER_BINDING),
            "input_vault": imported_vault.describe(),
            "output_vault": None,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": None,
            "retry_authorized": False,
            "terminal_failure": failure,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            OPERATIONAL_TERMINAL,
            "native-call-or-resource-terminal",
            episode,
            imported_vault,
            1,
            REQUESTED_CONFLICTS,
            None,
            failure,
        )

    try:
        raw, ledger, vault_telemetry, reader = _validated_native(result)
        eligible_raw = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible_raw, Sequence):
            raise O1C69RunError("eligible emitted clause sequence differs")
        eligible = tuple(_o1c66._clause_literals(item) for item in eligible_raw)
        if (
            _o1c66._adapter_vault_payload(getattr(result, "input_vault"))
            != imported_vault.to_bytes()
        ):
            raise O1C69RunError("native input vault differs")
        status = cast(int, ledger["status"])
        key_model = getattr(result, "key_model", None)
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C69RunError("SAT model failed public eight-block verification")
        elif key_model is not None:
            raise O1C69RunError("non-SAT continuation returned a key")

        next_available = vault_telemetry.get("next_vault_available")
        terminal_reason = vault_telemetry.get("next_vault_terminal_reason")
        adapter_next = getattr(result, "next_vault")
        if not isinstance(next_available, bool):
            raise O1C69RunError("next-vault availability differs")
        if next_available:
            if terminal_reason is not None or adapter_next is None:
                raise O1C69RunError("available next vault differs")
            next_payload = _o1c66._adapter_vault_payload(adapter_next)
            parsed_next = _o1c66.ClauseVault.from_bytes(
                next_payload,
                expected_identity=imported_vault.identity,
                observed_variables=imported_vault.observed_variables,
            )
            expected_next, novel, duplicates = imported_vault.append_emitted(eligible)
            if parsed_next != expected_next:
                raise O1C69RunError("cumulative continuation vault differs")
        else:
            if (
                terminal_reason
                not in {
                    "terminal_empty_clause",
                    "capacity_clause_count",
                    "capacity_literal_count",
                    "capacity_payload_bytes",
                }
                or adapter_next is not None
            ):
                raise O1C69RunError("terminal next vault differs")
            parsed_next = imported_vault
            if terminal_reason == "terminal_empty_clause":
                novel, duplicates = (), 0
            else:
                novel, duplicates = _o1c66._deduplicate_without_capacity(
                    imported_vault, eligible
                )
        _o1c66._validate_vault_telemetry(
            vault_telemetry,
            current=imported_vault,
            eligible_raw=cast(Sequence[object], eligible_raw),
            eligible=eligible,
            parsed_next=parsed_next,
            next_available=next_available,
            terminal_reason=cast(str | None, terminal_reason),
        )
        native_path = episode_dir / "native_result.json"
        _atomic_json(native_path, raw)
        telemetry_path = episode_dir / "vault_telemetry.json"
        _atomic_json(telemetry_path, dict(vault_telemetry))
        final_vault = imported_vault if status == 20 else parsed_next
        archive_output = next_available and status != 20
        output_path = episode_dir / "vault-output.bin"
        if archive_output:
            assert adapter_next is not None
            _o1c66._write_adapter_vault(output_path, adapter_next)
            if (
                _o1c66.read_vault(
                    output_path,
                    identity=imported_vault.identity,
                    observed_variables=imported_vault.observed_variables,
                )
                != parsed_next
            ):
                raise O1C69RunError("continuation output vault reread differs")

        novel_count = len(novel)
        if status == 10:
            classification, stop_reason = (
                PUBLIC_EXACT_RECOVERY,
                "public-verified-candidate",
            )
        elif status == 20:
            classification, stop_reason = (
                THRESHOLD_REGION_EXHAUSTED,
                "threshold-region-exhausted",
            )
        elif not next_available:
            classification, stop_reason = CAPACITY_TERMINAL, cast(str, terminal_reason)
        elif novel_count:
            classification, stop_reason = (
                ALTERNATING_READER_GAIN,
                "novel-exact-clauses",
            )
        else:
            classification, stop_reason = (
                ALTERNATING_READER_NO_GAIN,
                "zero-novel-eligible-clauses",
            )
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "reader": reader,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": cast(int, ledger["billed_conflicts"]),
            "input_vault": imported_vault.describe(),
            "output_vault": None if status == 20 else parsed_next.describe(),
            "output_vault_archived": archive_output,
            "output_vault_sidecar": (
                "episodes/00/vault-output.bin" if archive_output else None
            ),
            "status20_retained_input_vault": (
                imported_vault.describe() if status == 20 else None
            ),
            "status20_unarchived_derived_vault": (
                parsed_next.describe() if status == 20 and next_available else None
            ),
            "status20_native_next_vault_available": (
                next_available if status == 20 else None
            ),
            "status20_native_terminal_reason": (
                terminal_reason if status == 20 else None
            ),
            "status20_exceptional_no_retry_audit": status == 20,
            "eligible_emitted": {
                "clause_count": len(eligible),
                "literal_count": sum(len(clause) for clause in eligible),
                "novel_clause_count": novel_count,
                "novel_literal_count": sum(len(clause) for clause in novel),
                "duplicate_clause_count": duplicates,
            },
            "work_and_resources": ledger,
            "search_delta_from_parent": {
                "decisions_delta": cast(int, ledger["decisions"])
                - PARENT_LAST_DECISIONS,
                "propagations_delta": cast(int, ledger["propagations"])
                - PARENT_LAST_PROPAGATIONS,
                "minimum_upper_bound_delta": (
                    cast(float, ledger["minimum_upper_bound"])
                    - PARENT_LAST_MINIMUM_UPPER_BOUND
                ),
            },
            "native_result_sha256": sha256_file(native_path),
            "vault_telemetry_sha256": sha256_file(telemetry_path),
            "public_model": {
                "present": key_model is not None,
                "verified_8_of_8": status == 10,
                "model_sha256": (
                    hashlib.sha256(key_model).hexdigest()
                    if isinstance(key_model, bytes)
                    else None
                ),
                "truth_key_bytes_read": False,
            },
            "retry_authorized": False,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            classification,
            stop_reason,
            episode,
            final_vault,
            1,
            REQUESTED_CONFLICTS,
            cast(int, ledger["billed_conflicts"]),
            None,
        )
    except BaseException as exc:
        failure = {
            "classification": INVALID_RESULT_TERMINAL,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "retry_authorized": False,
            "expected_reader": dict(READER_BINDING),
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "truth_key_bytes_read": False,
        }
        _atomic_json(episode_dir / "terminal_failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "intent_sha256": intent_sha,
            "reader": dict(READER_BINDING),
            "input_vault": imported_vault.describe(),
            "output_vault": None,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": None,
            "retry_authorized": False,
            "terminal_failure": failure,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            INVALID_RESULT_TERMINAL,
            "invalid-post-native-result",
            episode,
            imported_vault,
            1,
            REQUESTED_CONFLICTS,
            None,
            failure,
        )


def validate_native_build_identity(
    native_build: NativeGuidedSearchBuild,
    *,
    expected_source_sha256: str,
    expected_executable_sha256: str,
) -> None:
    try:
        executable_sha = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C69RunError("native-v8 build identity differs") from exc
    if (
        expected_source_sha256 == "PENDING"
        or expected_executable_sha256 == "PENDING"
        or not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.executable.name != "native-joint-score-sieve"
        or native_build.source_sha256 != expected_source_sha256
        or native_build.executable_sha256 != expected_executable_sha256
        or executable_sha != expected_executable_sha256
    ):
        raise O1C69RunError("native-v8 build identity differs")


def invoke_native_episode(
    *, executable: Path, cnf: Path, potential: Path, grouping: Path, vault: Path
) -> object:
    _o1c65.validate_frozen_call_inputs(cnf=cnf, potential=potential, grouping=grouping)
    if vault.is_symlink() or sha256_file(vault) != PARENT_RETAINED_VAULT_SHA256:
        raise O1C69RunError("alternating-reader input vault differs before call")
    return _native_v11.run_joint_score_sieve(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        vault_path=vault,
        vault_caps=_vault_v1.O1C66_VAULT_CAPS,
        threshold=THRESHOLD,
        conflict_limit=REQUESTED_CONFLICTS,
        seed=SEED,
        timeout_seconds=TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
    )


def _runtime_resources(
    started: float, cpu_started: float, child_started: resource.struct_rusage
) -> dict[str, object]:
    return _o1c67._runtime_resources(started, cpu_started, child_started)


def _result(
    *,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    outcome: SingleContinuationOutcome,
    runtime: Mapping[str, object],
    started_at: str,
) -> dict[str, object]:
    billed = outcome.billed_conflicts
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "source_sha256": preflight_row.get("source_sha256"),
        "adapter_source_sha256": preflight_row.get("adapter_source_sha256"),
        "native_source_sha256": preflight_row.get("native_source_sha256"),
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "capsule": capsule_relative.as_posix(),
        "invocation_id": INVOCATION_ID,
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "reader": dict(READER_BINDING),
        "parent": {
            "attempt_id": "O1C-0068",
            "result_sha256": PARENT_RESULT_SHA256,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "source_commit": PARENT_SOURCE_COMMIT,
            "native_calls_consumed": PARENT_ATTEMPT_NATIVE_CALLS,
            "lineage_calls_consumed": PARENT_LINEAGE_CALLS,
            "last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
            "failed_ordinal": PARENT_FAILED_ORDINAL,
            "known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "failed_call_billed_conflicts": None,
            "lineage_actual_billed_conflicts": None,
        },
        "claim_boundary": {
            "new_attempt_not_parent_retry": True,
            "parent_ordinal_replay_authorized": False,
            "exactly_one_new_native_call": outcome.native_calls == 1,
            "only_science_change": (
                "forced-phase1-alternating-reader-on-sealed-phase0-vault"
            ),
            "reader_spec_sha256": READER_SPEC_SHA256,
            "requested_conflicts_is_soft_horizon": True,
            "actual_solve_conflicts_billed": billed is not None,
            "numeric_overshoot_ceiling_asserted": False,
            "hard_process_time_rss_caps_retained": True,
            "capacity_reservation_is_planning_not_formal_maximum": True,
            "status20_is_exceptional_no_retry_consistency_audit": True,
            "vault_clauses_valid_for": (
                "CNF-and-potential-score-greater-than-or-equal-threshold"
            ),
            "vault_clauses_are_cnf_only_entailed": False,
            "truth_key_bytes_read": False,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "episode": dict(outcome.episode),
        "final_vault": outcome.final_vault.describe(),
        "resources": {
            **dict(runtime),
            "native_solver_calls": outcome.native_calls,
            "requested_conflicts": outcome.requested_conflicts,
            "billed_conflicts": billed,
            "maximum_billed_conflicts": None,
            "parent_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "parent_failed_call_billed_conflicts": None,
            "lineage_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS + billed
                if billed is not None
                else PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "lineage_actual_billed_conflicts": None,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "persistent_artifact_bytes": 0,
        },
        "operational_failure": (
            None
            if outcome.operational_failure is None
            else dict(outcome.operational_failure)
        ),
        "publication_recovery": None,
        "preflight": dict(preflight_row),
        "next_action": (
            "Do not replay lineage ordinal 5 or sweep phase/horizon; choose the "
            "next explicit operator from this one-call terminal."
        ),
    }


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# O1C-0069 — APPLE8 alternating reader\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Stop reason: `{result['stop_reason']}`\n"
        "- New native calls: `1`\n"
        "- Local / lineage ordinal: `0 / 5`\n"
        "- Reader: `forcephase=true`, `phase=1` (true polarity), seed `0`\n"
        "- Billing: actual observed solve conflicts\n"
        "- Truth key bytes read: `false`\n"
    )


def finalize_capsule(
    capsule: Path,
    authoritative: Path,
    result: dict[str, object],
    *,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    if authoritative.exists() or (capsule / "artifacts.sha256").exists():
        raise O1C69RunError("O1C-0069 terminal publication already exists")
    _o1c65._replace_owned_bytes(capsule / "RUN.md", _markdown(result).encode())
    result_path = capsule / "result.json"
    resources = cast(dict[str, object], result["resources"])
    for _ in range(12):
        _replace_owned_json(result_path, result)
        manifest, persistent = _o1c65._capsule_manifest(capsule)
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C69RunError("persistent artifact ledger did not converge")
    if persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES:
        raise O1C69RunError("persistent artifact byte budget exceeded")
    payload = _canonical_json_bytes(result)
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative, payload)
        authoritative_published = True
        _atomic_bytes(manifest_path, manifest)
        manifest_published = True
        for path in sorted(
            capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
        ):
            path.chmod(0o444 if path.is_file() else 0o555)
        capsule.chmod(0o555)
        if _after_capsule_seal is not None:
            _after_capsule_seal()
        if authoritative.read_bytes() != payload or result_path.read_bytes() != payload:
            raise O1C69RunError("terminal publication bytes differ")
        _o1c65._assert_immutable_tree(capsule)
    except Exception:
        _o1c65._restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _o1c65._unlink_owned_exact(
                manifest_path, manifest, "O1C69 capsule manifest"
            )
        if authoritative_published:
            _o1c65._unlink_owned_exact(
                authoritative, payload, "O1C69 authoritative result"
            )
        raise


def _validate_recovery_file(
    path: Path,
    *,
    expected_sha256: object,
    field: str,
    expected_bytes: object | None = None,
) -> None:
    """Bind a recovery input to its journaled hash and optional byte count."""

    expected_sha = _sha256(expected_sha256, f"{field} sha256")
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise O1C69RunError(f"{field} cannot be read during recovery") from exc
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise O1C69RunError(f"{field} differs during recovery")
    if expected_bytes is not None:
        size = _nonnegative_int(expected_bytes, f"{field} bytes")
        if status.st_size != size:
            raise O1C69RunError(f"{field} size differs during recovery")
    if sha256_file(path) != expected_sha:
        raise O1C69RunError(f"{field} hash differs during recovery")


def _validate_recovery_sidecars(
    capsule: Path,
    source: Mapping[str, object],
    episode: Mapping[str, object],
) -> None:
    """Revalidate every completed-call sidecar before zero-call publication."""

    episode_dir = capsule / "episodes" / "00"
    terminal = (
        None
        if episode.get("completed") is True
        else _mapping(episode.get("terminal_failure"), "recovery terminal failure")
    )
    invocation_sha = (
        episode.get("invocation_sha256")
        if terminal is None
        else terminal.get("invocation_sha256")
    )
    _validate_recovery_file(
        capsule / "invocation.json",
        expected_sha256=invocation_sha,
        field="recovery invocation",
    )
    _validate_recovery_file(
        episode_dir / "intent.json",
        expected_sha256=episode.get("intent_sha256"),
        field="recovery intent",
    )
    invocation = _read_json(capsule / "invocation.json", "recovery invocation")
    intent = _read_json(episode_dir / "intent.json", "recovery intent")
    if (
        invocation.get("invocation_id") != INVOCATION_ID
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
        or _validate_reader(invocation.get("reader"), "recovery invocation reader")
        != READER_BINDING
        or invocation.get("capacity_reservation") != CAPACITY_RESERVATION
        or intent.get("invocation_id") != INVOCATION_ID
        or intent.get("invocation_sha256")
        != _sha256(invocation_sha, "recovery invocation sha256")
        or intent.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or intent.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or intent.get("parent_ordinal_replay_authorized") is not False
        or intent.get("episode_is_retry") is not False
        or _validate_reader(intent.get("reader"), "recovery intent reader")
        != READER_BINDING
        or intent.get("capacity_reservation") != CAPACITY_RESERVATION
    ):
        raise O1C69RunError("recovery invocation/intent journal differs")

    input_vault = _mapping(episode.get("input_vault"), "recovery input vault")
    _validate_recovery_file(
        capsule / "vault-imported.bin",
        expected_sha256=input_vault.get("sha256"),
        expected_bytes=input_vault.get("serialized_bytes"),
        field="recovery imported vault",
    )

    native_result = episode_dir / "native_result.json"
    vault_telemetry = episode_dir / "vault_telemetry.json"
    vault_output = episode_dir / "vault-output.bin"
    native_failure = episode_dir / "native_execution_failure.json"
    terminal_failure = episode_dir / "terminal_failure.json"
    if terminal is None:
        _validate_recovery_file(
            native_result,
            expected_sha256=episode.get("native_result_sha256"),
            field="recovery native result",
        )
        _validate_recovery_file(
            vault_telemetry,
            expected_sha256=episode.get("vault_telemetry_sha256"),
            field="recovery vault telemetry",
        )
        if native_failure.exists() or terminal_failure.exists():
            raise O1C69RunError("completed recovery has failure sidecars")
        final_vault = _mapping(source.get("final_vault"), "recovery final vault")
        archived = episode.get("output_vault_archived")
        work = _mapping(episode.get("work_and_resources"), "recovery work")
        if work.get("status") == 20:
            retained = _mapping(
                episode.get("status20_retained_input_vault"),
                "recovery status20 retained input vault",
            )
            telemetry_row = _read_json(
                vault_telemetry, "recovery status20 vault telemetry"
            )
            available = telemetry_row.get("next_vault_available")
            derived_raw = episode.get("status20_unarchived_derived_vault")
            derived = (
                _mapping(derived_raw, "recovery status20 derived vault")
                if available is True
                else None
            )
            if (
                source.get("classification") != THRESHOLD_REGION_EXHAUSTED
                or source.get("stop_reason") != "threshold-region-exhausted"
                or source.get("operational_failure") is not None
                or episode.get("output_vault") is not None
                or episode.get("status20_exceptional_no_retry_audit") is not True
                or retained != input_vault
                or final_vault != input_vault
                or not isinstance(available, bool)
                or episode.get("status20_native_next_vault_available") is not available
                or episode.get("status20_native_terminal_reason")
                != telemetry_row.get("next_vault_terminal_reason")
                or (
                    available
                    and (
                        derived is None
                        or derived.get("sha256")
                        != telemetry_row.get("next_vault_sha256")
                        or derived.get("serialized_bytes")
                        != telemetry_row.get("next_serialized_bytes")
                        or derived.get("clause_count")
                        != telemetry_row.get("next_clause_count")
                        or derived.get("literal_count")
                        != telemetry_row.get("next_literal_count")
                    )
                )
                or (not available and derived_raw is not None)
                or archived is not False
                or episode.get("output_vault_sidecar") is not None
                or vault_output.exists()
            ):
                raise O1C69RunError("status-20 recovery vault/result differs")
            return

        output_vault = _mapping(episode.get("output_vault"), "recovery output vault")
        if (
            source.get("operational_failure") is not None
            or final_vault != output_vault
            or not isinstance(archived, bool)
            or episode.get("status20_retained_input_vault") is not None
            or episode.get("status20_unarchived_derived_vault") is not None
            or episode.get("status20_native_next_vault_available") is not None
            or episode.get("status20_native_terminal_reason") is not None
            or episode.get("status20_exceptional_no_retry_audit") is not False
        ):
            raise O1C69RunError("completed recovery vault/result differs")
        if archived:
            if episode.get("output_vault_sidecar") != "episodes/00/vault-output.bin":
                raise O1C69RunError("recovery output vault path differs")
            _validate_recovery_file(
                vault_output,
                expected_sha256=output_vault.get("sha256"),
                expected_bytes=output_vault.get("serialized_bytes"),
                field="recovery output vault",
            )
        elif episode.get("output_vault_sidecar") is not None or vault_output.exists():
            raise O1C69RunError("unarchived recovery output vault differs")
        return

    persisted_failure = _read_json(terminal_failure, "recovery terminal failure")
    operational_failure = _mapping(
        source.get("operational_failure"), "recovery operational failure"
    )
    if (
        persisted_failure != terminal
        or operational_failure != terminal
        or source.get("final_vault") != input_vault
        or episode.get("output_vault") is not None
        or native_result.exists()
        or vault_telemetry.exists()
        or vault_output.exists()
    ):
        raise O1C69RunError("failed recovery journal differs")
    failure_sha = terminal.get("native_execution_failure_sha256")
    if failure_sha is None:
        if native_failure.exists():
            raise O1C69RunError("invalid-result recovery failure sidecar differs")
    else:
        _validate_recovery_file(
            native_failure,
            expected_sha256=failure_sha,
            field="recovery native execution failure",
        )


def _validate_publication_source(root: Path, capsule: Path) -> dict[str, object]:
    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or capsule.parent != root / "runs"
        or not capsule.name.endswith(f"_{CAPSULE_SUFFIX}")
        or (capsule / "artifacts.sha256").exists()
    ):
        raise O1C69RunError("O1C-0069 recovery capsule differs")
    source = dict(
        _read_json(capsule / PUBLICATION_SOURCE_NAME, "O1C-0069 publication source")
    )
    episode = _mapping(source.get("episode"), "publication source episode")
    resources = _mapping(source.get("resources"), "publication source resources")
    persisted = _read_json(
        capsule / "episodes" / "00" / "episode.json", "persisted O1C-0069 episode"
    )
    if (
        source.get("schema") != RESULT_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("capsule") != capsule.relative_to(root).as_posix()
        or source.get("invocation_id") != INVOCATION_ID
        or source.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or source.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or _validate_reader(source.get("reader"), "publication reader")
        != READER_BINDING
        or episode != persisted
        or episode.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or episode.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or episode.get("native_calls_consumed") != 1
        or episode.get("retry_authorized") is not False
        or resources.get("native_solver_calls") != 1
        or source.get("publication_recovery") is not None
        or not (capsule / "invocation.json").is_file()
        or not (capsule / "episodes" / "00" / "intent.json").is_file()
    ):
        raise O1C69RunError("O1C-0069 publication source differs")
    _validate_recovery_sidecars(capsule, source, episode)
    return source


def recover_publication(
    *,
    root: Path,
    capsule: Path,
    authoritative: Path,
    cause: BaseException | None,
) -> dict[str, object]:
    """Seal completed sidecars with zero native calls."""

    if authoritative.exists():
        raise O1C69RunError("O1C-0069 authoritative publication already exists")
    source = _validate_publication_source(root, capsule)
    recovery = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_consumed": 1,
        "native_calls_issued_during_recovery": 0,
        "completed_sidecars_revalidated": True,
        "retry_authorized": False,
        "science_classification_preserved": source.get("classification"),
        "science_stop_reason_preserved": source.get("stop_reason"),
        "reader": dict(READER_BINDING),
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "error_type": type(cause).__qualname__ if cause is not None else None,
        "error_message": str(cause) if cause is not None else None,
        "exception_chain_outer_to_cause_or_context": (
            _o1c67._exception_chain(cause) if cause is not None else []
        ),
        "truth_key_bytes_read": False,
    }
    recovered = dict(source)
    recovered["publication_recovery"] = recovery
    resources = dict(_mapping(recovered["resources"], "recovered resources"))
    resources["publication_recovery_native_solver_calls"] = 0
    recovered["resources"] = resources
    finalize_capsule(capsule, authoritative, recovered)
    return recovered


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    partial_capsules = tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}"))
    if authoritative.exists():
        raise O1C69RunError("O1C-0069 already exists")
    if partial_capsules:
        if len(partial_capsules) != 1:
            raise O1C69RunError("multiple O1C-0069 recovery capsules exist")
        return recover_publication(
            root=root,
            capsule=partial_capsules[0],
            authoritative=authoritative,
            cause=None,
        )
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = _o1c65.validate_apple8_baseline(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    public_target = _o1c66._public_target(baseline)
    source_commit = cast(str, preflight_row["source_commit"])
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "source.expected_sha256")
    native = _mapping(config["native"], "native")
    expected_native_source = _sha256(
        native["expected_source_sha256"], "native expected source"
    )
    expected_executable = _sha256(
        native["expected_executable_sha256"], "native expected executable"
    )
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c69-apple8-alternating-reader-") as raw:
        workspace = Path(raw)
        native_build = _native_v11.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "native-joint-score-sieve",
        )
        validate_native_build_identity(
            native_build,
            expected_source_sha256=expected_native_source,
            expected_executable_sha256=expected_executable,
        )
        observed_sources = _source_hashes(root, config)
        if observed_sources != {
            name: _sha256(expected[name], f"source expected {name}")
            for name in SOURCE_NAMES
        }:
            raise O1C69RunError("source identity changed after preflight")
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        grouping_path = capsule / "apple8-width6.grouping"
        _atomic_json(
            capsule / "grouping.json",
            _o1c65.materialize_grouping(grouping_path, frozen),
        )
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c69_apple8_alternating_reader_run run "
                f"--config {config_file.relative_to(root).as_posix()}\n"
            ).encode(),
        )
        bindings = {
            "source_commit": source_commit,
            "config_sha256": sha256_file(config_file),
            "source_sha256": observed_sources,
            "adapter_source_sha256": observed_sources["joint_score_sieve_v11"],
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_implementation_parent_schema": (
                NATIVE_IMPLEMENTATION_PARENT_SCHEMA
            ),
            "native_ledger_schema": NATIVE_LEDGER_SCHEMA,
            "reader": dict(READER_BINDING),
            "reader_spec_sha256": READER_SPEC_SHA256,
            "parent_result_sha256": PARENT_RESULT_SHA256,
            "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
            "retained_vault_sha256": PARENT_RETAINED_VAULT_SHA256,
            "parent_failed_ordinal": PARENT_FAILED_ORDINAL,
            "parent_failed_call_billed_conflicts": None,
            "parent_known_completed_billed_conflicts": (
                PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
            ),
            "lineage_actual_billed_conflicts": None,
            "cnf_sha256": sha256_file(cnf),
            "potential_sha256": sha256_file(potential),
            "grouping_sha256": sha256_file(grouping_path),
            "threshold_f64le_hex": struct.pack("<d", THRESHOLD).hex(),
            "seed": SEED,
        }

        def invoke(local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
            if (
                local_ordinal != LOCAL_EPISODE_ORDINAL
                or lineage_ordinal != LINEAGE_CALL_ORDINAL
            ):
                raise O1C69RunError("alternating-reader ordinal differs")
            return invoke_native_episode(
                executable=native_build.executable,
                cnf=cnf,
                potential=potential,
                grouping=grouping_path,
                vault=vault,
            )

        outcome = execute_single_continuation(
            capsule=capsule,
            imported_vault=imported.independent,
            adapter_vault=imported.adapter,
            invoke_episode=invoke,
            verify_public_model=public_target.verify,
            bindings=bindings,
        )
        result = _result(
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            outcome=outcome,
            runtime=_runtime_resources(started, cpu_started, child_started),
            started_at=started_at,
        )
        _atomic_json(capsule / PUBLICATION_SOURCE_NAME, result)
        try:
            finalize_capsule(capsule, authoritative, result)
            return result
        except Exception as exc:
            return recover_publication(
                root=root,
                capsule=capsule,
                authoritative=authoritative,
                cause=exc,
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run O1C-0069's one alternating reader call"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", default=CONFIG_RELATIVE.as_posix())
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = (
            preflight(args.config) if args.command == "preflight" else run(args.config)
        )
    except O1C69RunError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
