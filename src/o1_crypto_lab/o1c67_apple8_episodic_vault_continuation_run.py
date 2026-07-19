"""O1C-0067: one honest continuation call from O1C-0066's sealed vault.

This attempt does not replay O1C-0066 episode 2.  O1C-0066 consumed lineage
ordinals 0, 1, and 2; O1C-0067 persists a new invocation and local intent for
lineage ordinal 3, imports the last completed 12-clause vault, and makes exactly
one fresh native-v6 call through adapter v9.

The 512-conflict value is a requested soft horizon.  Actual nonnegative solve
conflicts are billed without an empirical overshoot ceiling.  Process count,
wall time, and RSS remain hard limits.
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

from . import joint_score_sieve_v9 as _native_v9
from . import o1c65_apple8_width6_grouped_run as _o1c65
from . import o1c66_apple8_episodic_vault_run as _o1c66
from . import threshold_no_good_vault_v1 as _vault_v1
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


ATTEMPT_ID = "O1C-0067"
CONFIG_SCHEMA = "o1-256-apple8-vault-continuation-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-vault-continuation-preflight-v1"
INVOCATION_SCHEMA = "o1-256-apple8-vault-continuation-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-vault-continuation-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-vault-continuation-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-vault-continuation-result-v1"
FAILURE_EVIDENCE_SCHEMA = "o1-256-o1c67-native-failure-evidence-v1"
ADAPTER_PREFLIGHT_SCHEMA = "o1-256-o1c67-target-free-adapter-preflight-v1"
ADAPTER_PREFLIGHT_CLASSIFICATION = "O1C67_TARGET_FREE_ADAPTER_PREFLIGHT_PASS"

INVOCATION_ID = "O1C-0067-apple8-vault-continuation-v1-call-0003"
CAPSULE_SUFFIX = "O1C-0067_apple8-vault-continuation-v1"
PUBLICATION_SOURCE_NAME = "publication_source.json"
RESULT_RELATIVE = Path(
    "research/O1C0067_APPLE8_EPISODIC_VAULT_CONTINUATION_RESULT_20260719.json"
)
DESIGN_RELATIVE = Path("research/O1C0067_APPLE8_VAULT_CONTINUATION_DESIGN_20260719.md")
ADAPTER_PREFLIGHT_RELATIVE = Path(
    "research/O1C0067_TARGET_FREE_ADAPTER_PREFLIGHT_20260719.json"
)
CONFIG_RELATIVE = Path("configs/o1c67_apple8_episodic_vault_continuation_v1.json")

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0066_APPLE8_EPISODIC_VAULT_RESULT_20260719.json"
)
PARENT_CAPSULE_RELATIVE = Path("runs/20260719_135856_O1C-0066_apple8-episodic-vault-v1")
PARENT_RESULT_SHA256 = (
    "b8b61d0f2feaa9c544c1fef30cba4c7cead90c390a577a444405d45ad85000e3"
)
PARENT_MANIFEST_SHA256 = (
    "b0022997a1c316e71131268b3e3e5524aee4de8167013463f845646c8982d562"
)
PARENT_SOURCE_COMMIT = "881c461c79dc1fd9aa51aed89d3f2a8b298c2284"
PARENT_FAILED_INTENT_RELATIVE = Path("episodes/02/intent.json")
PARENT_FAILED_INTENT_SHA256 = (
    "7a2fb83611fbc6108e2e3503f406141c13b1087a951a075147cdb679fedd62ed"
)
PARENT_TERMINAL_FAILURE_RELATIVE = Path("episodes/02/terminal_failure.json")
PARENT_TERMINAL_FAILURE_SHA256 = (
    "0915eb4220000bf80a3326b6533976220e4f08eba1ee98fd69296e856ea64834"
)
PARENT_RETAINED_VAULT_RELATIVE = Path("episodes/01/vault-output.bin")
PARENT_RETAINED_VAULT_SHA256 = (
    "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a"
)
PARENT_RETAINED_VAULT_BYTES = 140_483
PARENT_RETAINED_VAULT_CLAUSES = 12
PARENT_RETAINED_VAULT_LITERALS = 35_061
PARENT_RETAINED_VAULT_AGGREGATE_SHA256 = (
    "76d5bab1665fdfafa6ff7d8d7de6a830f3fa94f8742105f6ee41bcc192d05ff0"
)
PARENT_NATIVE_CALLS = 3
PARENT_COMPLETED_EPISODES = 2
PARENT_LAST_CONSUMED_ORDINAL = 2
PARENT_LAST_COMPLETED_ORDINAL = 1
PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS = 1_025
PARENT_FAILED_CALL_BILLED_CONFLICTS: None = None
PARENT_LAST_DECISIONS = 4_666
PARENT_LAST_PROPAGATIONS = 1_230_568
PARENT_LAST_MINIMUM_UPPER_BOUND = 7.973483108047071

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 3
MAXIMUM_NATIVE_SOLVER_CALLS = 1
REQUESTED_CONFLICTS = 512
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_FAILURE_STREAM_BYTES = 1_048_576
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 67_108_864
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MINIMUM_MEMORY_FREE_PERCENT = 25
MAXIMUM_NORMALIZED_LOAD_1M = 0.75
THRESHOLD = _o1c66.THRESHOLD
SEED = 0

APPLE8_CNF_SHA256 = _o1c66.APPLE8_CNF_SHA256
APPLE8_POTENTIAL_SHA256 = _o1c66.APPLE8_POTENTIAL_SHA256
GROUPING_SHA256 = _o1c66.GROUPING_SHA256
GROUPING_SERIALIZED_BYTES = _o1c66.GROUPING_SERIALIZED_BYTES
GROUPING_WIDTH_CAP = _o1c66.GROUPING_WIDTH_CAP
EXPECTED_NATIVE_SOURCE_SHA256 = _o1c66.EXPECTED_NATIVE_SOURCE_SHA256
EXPECTED_NATIVE_EXECUTABLE_SHA256 = _o1c66.EXPECTED_NATIVE_EXECUTABLE_SHA256
NATIVE_RESULT_SCHEMA = _native_v9.JOINT_SCORE_SIEVE_RESULT_SCHEMA
NATIVE_IMPLEMENTATION_PARENT_SCHEMA = (
    _native_v9.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
)
NATIVE_ADAPTER_SCHEMA = _native_v9.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
NATIVE_LEDGER_SCHEMA = _native_v9.O1C67_VAULT_SOFT_CONFLICT_LEDGER_SCHEMA
NATIVE_VAULT_TELEMETRY_SCHEMA = _native_v9.JOINT_SCORE_SIEVE_VAULT_TELEMETRY_SCHEMA

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
CONTINUATION_GAIN = "EPISODIC_VAULT_CONTINUATION_GAIN"
SATURATED_NO_GAIN = "EPISODIC_VAULT_SATURATED_NO_GAIN"
THRESHOLD_REGION_EXHAUSTED = "EPISODIC_VAULT_THRESHOLD_REGION_EXHAUSTED"
CAPACITY_TERMINAL = "EPISODIC_VAULT_CAPACITY_TERMINAL"
OPERATIONAL_TERMINAL = "EPISODIC_VAULT_CONTINUATION_OPERATIONAL_TERMINAL"
INVALID_RESULT_TERMINAL = "EPISODIC_VAULT_CONTINUATION_INVALID_RESULT"

SOURCE_NAMES = (
    "runner",
    "joint_score_sieve_v9",
    "joint_score_sieve_v8",
    "joint_score_sieve_v7",
    "joint_score_grouping_v1",
    "threshold_no_good_vault_v1",
    "native_source",
    "native_base_source",
    "o1c66_runner",
    "o1c65_runner",
    "lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
    "design",
    "adapter_preflight",
)
SOURCE_RELATIVES = {
    "runner": "src/o1_crypto_lab/o1c67_apple8_episodic_vault_continuation_run.py",
    "joint_score_sieve_v9": "src/o1_crypto_lab/joint_score_sieve_v9.py",
    "joint_score_sieve_v8": "src/o1_crypto_lab/joint_score_sieve_v8.py",
    "joint_score_sieve_v7": "src/o1_crypto_lab/joint_score_sieve_v7.py",
    "joint_score_grouping_v1": "src/o1_crypto_lab/joint_score_grouping_v1.py",
    "threshold_no_good_vault_v1": "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
    "native_source": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "native_base_source": "native/cadical_o1_joint_score_sieve.cpp",
    "o1c66_runner": "src/o1_crypto_lab/o1c66_apple8_episodic_vault_run.py",
    "o1c65_runner": "src/o1_crypto_lab/o1c65_apple8_width6_grouped_run.py",
    "lifecycle_helpers": "src/o1_crypto_lab/o1c59_multiblock_joint_score_sieve_run.py",
    "chacha_trace": "src/o1_crypto_lab/chacha_trace.py",
    "full256_broker": "src/o1_crypto_lab/full256_broker.py",
    "design": DESIGN_RELATIVE.as_posix(),
    "adapter_preflight": ADAPTER_PREFLIGHT_RELATIVE.as_posix(),
}
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
    "invocation",
    "native",
    "budgets",
    "adapter_preflight",
    "next_action",
}


class O1C67RunError(RuntimeError):
    """O1C-0067 provenance, protocol, or result differs."""


class O1C67ParentError(O1C67RunError):
    """The sealed O1C-0066 parent or retained vault differs."""


class EpisodeInvoker(Protocol):
    def __call__(self, local_ordinal: int, lineage_ordinal: int, vault: Path) -> object:
        """Make the one authorized fresh subprocess call."""


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
        raise O1C67RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C67RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C67RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise O1C67RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C67RunError(f"{field} differs")
    return value


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C67RunError(f"{field} differs")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise O1C67RunError(f"{field} escapes the lab")
    try:
        path = (root / candidate).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise O1C67RunError(f"{field} cannot be resolved") from exc
    if not path.is_relative_to(root):
        raise O1C67RunError(f"{field} escapes the lab")
    return path


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C67RunError(f"{field} cannot be read") from exc
    return _mapping(value, field)


def load_config(path: str | Path) -> dict[str, object]:
    """Load the exact O1C-0067 protocol without performing a call or write."""

    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C67RunError("config escapes the lab")
    config = dict(_read_json(config_path, "O1C67 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen_sha = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    grouping_provenance = _mapping(
        config.get("grouping_provenance"), "grouping_provenance"
    )
    input_row = _mapping(config.get("input"), "input")
    parent = _mapping(config.get("parent"), "parent")
    retained = _mapping(config.get("retained_vault"), "retained_vault")
    invocation = _mapping(config.get("invocation"), "invocation")
    native = _mapping(config.get("native"), "native")
    budgets = _mapping(config.get("budgets"), "budgets")
    adapter_gate = _mapping(config.get("adapter_preflight"), "adapter_preflight")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-vault-continuation-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or any(
            source.get(name) != relative for name, relative in SOURCE_RELATIVES.items()
        )
        or dict(frozen_sha)
        != {
            "authoritative_result": "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be",
            "manifest": "751b89019d1f65b8180b15eafbb4bdf45c6080b0894c50567ee63eff15405a69",
            "capsule_result": "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be",
            "native_result": "2cbd354b2d39d7c80206c6f3fb06ed4583d4b7c8436334f76ccaa1feaac5ab20",
            "preflight": "c0456e495d340fe8f08569ffc511608db976c0702988101ceaf946b668cc5880",
            "native_build": "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a",
            "truth_reveal": "63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd",
        }
        or dict(grouping_provenance)
        != {
            "source_attempt": "APPLE-VIEW-0009",
            "result": "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json",
            "result_sha256": "ebbe9e308f3e3dfa00685a9c10eba6554c85e453459178a26a03b9fc6b2b3728",
            "classification": "PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_NO_SEARCH_CLAIM",
            "native_solver_calls": 0,
            "truth_bytes_read": False,
            "native_integration_validated": False,
        }
        or dict(input_row)
        != {
            "apple8_result": "research/apple_view_8/apple_view_8_matched_result.json",
            "apple8_capsule": "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1",
            "cnf_relative": "artifacts/cnf/full256-eight-block-apple-view-0008.cnf",
            "potential_relative": "artifacts/potential/primary-eight-block.potential",
            "truth_reveal": "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/reveal.json",
            "cnf_sha256": APPLE8_CNF_SHA256,
            "potential_sha256": APPLE8_POTENTIAL_SHA256,
            "threshold": THRESHOLD,
            "seed": SEED,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
        }
        or parent.get("attempt_id") != "O1C-0066"
        or parent.get("result") != PARENT_RESULT_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("capsule") != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("classification") != "EPISODIC_VAULT_OPERATIONAL_TERMINAL"
        or parent.get("native_calls_consumed") != PARENT_NATIVE_CALLS
        or parent.get("completed_episodes") != PARENT_COMPLETED_EPISODES
        or parent.get("last_consumed_ordinal") != PARENT_LAST_CONSUMED_ORDINAL
        or parent.get("last_completed_ordinal") != PARENT_LAST_COMPLETED_ORDINAL
        or parent.get("known_completed_billed_conflicts")
        != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or parent.get("failed_call_billed_conflicts") is not None
        or parent.get("retry_authorized") is not False
        or parent.get("truth_key_bytes_read") is not False
        or parent.get("failed_intent") != PARENT_FAILED_INTENT_RELATIVE.as_posix()
        or parent.get("terminal_failure") != PARENT_TERMINAL_FAILURE_RELATIVE.as_posix()
        or parent.get("failed_intent_sha256") != PARENT_FAILED_INTENT_SHA256
        or parent.get("terminal_failure_sha256") != PARENT_TERMINAL_FAILURE_SHA256
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
        or invocation.get("lineage_calls_before") != PARENT_NATIVE_CALLS
        or invocation.get("parent_last_consumed_ordinal")
        != PARENT_LAST_CONSUMED_ORDINAL
        or invocation.get("parent_ordinal_replay_authorized") is not False
        or invocation.get("episode_is_retry") is not False
        or native.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_SOLVER_CALLS
        or native.get("requested_conflicts") != REQUESTED_CONFLICTS
        or native.get("timeout_seconds") != TIMEOUT_SECONDS
        or native.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or native.get("seed") != SEED
        or native.get("billing_rule") != "actual-nonnegative-solve-conflicts"
        or "maximum_billed_conflicts" in native
        or "maximum_conflict_limit_overshoot" in native
        or native.get("adapter_schema") != NATIVE_ADAPTER_SCHEMA
        or native.get("ledger_schema") != NATIVE_LEDGER_SCHEMA
        or native.get("result_schema") != NATIVE_RESULT_SCHEMA
        or native.get("implementation_parent_schema")
        != NATIVE_IMPLEMENTATION_PARENT_SCHEMA
        or native.get("vault_telemetry_schema") != NATIVE_VAULT_TELEMETRY_SCHEMA
        or native.get("expected_source_sha256") != EXPECTED_NATIVE_SOURCE_SHA256
        or native.get("expected_executable_sha256") != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or native.get("fresh_process") is not True
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
        or adapter_gate.get("artifact") != ADAPTER_PREFLIGHT_RELATIVE.as_posix()
        or adapter_gate.get("schema") != ADAPTER_PREFLIGHT_SCHEMA
        or adapter_gate.get("classification") != ADAPTER_PREFLIGHT_CLASSIFICATION
        or adapter_gate.get("target_free") is not True
        or adapter_gate.get("native_solver_calls") != 0
        or adapter_gate.get("truth_key_bytes_read") is not False
    ):
        raise O1C67RunError("frozen O1C-0067 config differs")
    for name in SOURCE_NAMES:
        _sha256(expected[name], f"source.expected_sha256.{name}")
    adapter_sha = _sha256(adapter_gate.get("sha256"), "adapter_preflight.sha256")
    if adapter_sha != expected["adapter_preflight"]:
        raise O1C67RunError("adapter-preflight config binding differs")
    return config


def _manifest_inventory(capsule: Path) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != PARENT_MANIFEST_SHA256:
        raise O1C67ParentError("O1C-0066 manifest identity differs")
    inventory: dict[str, str] = {}
    try:
        for line in manifest.read_text(encoding="ascii").splitlines():
            digest, separator, relative = line.partition("  ")
            if separator != "  " or relative in inventory:
                raise O1C67ParentError("O1C-0066 manifest syntax differs")
            _sha256(digest, "O1C-0066 manifest digest")
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise O1C67ParentError("O1C-0066 manifest path escapes")
            inventory[relative] = digest
    except (OSError, UnicodeError, ValueError) as exc:
        raise O1C67ParentError("O1C-0066 manifest cannot be read") from exc
    return inventory


def validate_parent_and_import_vault(
    root: Path, config: Mapping[str, object], frozen: object
) -> ImportedParentVault:
    """Dual-parse the exact sealed parent sidecar without writing anything."""

    del config
    result_path = root / PARENT_RESULT_RELATIVE
    capsule = root / PARENT_CAPSULE_RELATIVE
    if (
        sha256_file(result_path) != PARENT_RESULT_SHA256
        or not capsule.is_dir()
        or capsule.is_symlink()
    ):
        raise O1C67ParentError("O1C-0066 parent identity differs")
    result = _read_json(result_path, "O1C-0066 result")
    totals = _mapping(result.get("totals"), "O1C-0066 totals")
    final_vault = _mapping(result.get("final_vault"), "O1C-0066 final vault")
    failure = _mapping(result.get("operational_failure"), "O1C-0066 failure")
    if (
        result.get("attempt_id") != "O1C-0066"
        or result.get("classification") != "EPISODIC_VAULT_OPERATIONAL_TERMINAL"
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or totals.get("native_solver_calls") != PARENT_NATIVE_CALLS
        or totals.get("completed_episodes") != PARENT_COMPLETED_EPISODES
        or totals.get("billed_conflicts") != PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS
        or failure.get("episode_ordinal") != PARENT_LAST_CONSUMED_ORDINAL
        or failure.get("retry_authorized") is not False
        or final_vault.get("sha256") != PARENT_RETAINED_VAULT_SHA256
        or final_vault.get("serialized_bytes") != PARENT_RETAINED_VAULT_BYTES
        or final_vault.get("clause_count") != PARENT_RETAINED_VAULT_CLAUSES
        or final_vault.get("literal_count") != PARENT_RETAINED_VAULT_LITERALS
        or final_vault.get("aggregate_clause_sha256")
        != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C67ParentError("O1C-0066 terminal evidence differs")
    inventory = _manifest_inventory(capsule)
    expected_inventory = {
        PARENT_RETAINED_VAULT_RELATIVE.as_posix(): PARENT_RETAINED_VAULT_SHA256,
        PARENT_FAILED_INTENT_RELATIVE.as_posix(): PARENT_FAILED_INTENT_SHA256,
        PARENT_TERMINAL_FAILURE_RELATIVE.as_posix(): (PARENT_TERMINAL_FAILURE_SHA256),
        "result.json": PARENT_RESULT_SHA256,
    }
    if any(
        inventory.get(path) != digest for path, digest in expected_inventory.items()
    ):
        raise O1C67ParentError("O1C-0066 manifest inventory differs")
    for relative, digest in expected_inventory.items():
        if sha256_file(capsule / relative) != digest:
            raise O1C67ParentError("O1C-0066 capsule artifact differs")

    source = capsule / PARENT_RETAINED_VAULT_RELATIVE
    try:
        mode = source.stat(follow_symlinks=False).st_mode
        if (
            source.is_symlink()
            or not stat.S_ISREG(mode)
            or source.stat(follow_symlinks=False).st_size != PARENT_RETAINED_VAULT_BYTES
        ):
            raise O1C67ParentError("retained vault file identity differs")
        payload = source.read_bytes()
    except O1C67ParentError:
        raise
    except OSError as exc:
        raise O1C67ParentError("retained vault cannot be read") from exc
    if hashlib.sha256(payload).hexdigest() != PARENT_RETAINED_VAULT_SHA256:
        raise O1C67ParentError("retained vault hash differs")

    field = cast(object, getattr(frozen, "field"))
    observed_tuple = tuple(cast(Sequence[int], getattr(field, "observed_variables")))
    observed = frozenset(observed_tuple)
    independent_identity = _o1c66.frozen_vault_identity(field)  # type: ignore[arg-type]
    try:
        independent = _o1c66.ClauseVault.from_bytes(
            payload,
            expected_identity=independent_identity,
            observed_variables=observed,
        )
        adapter = _vault_v1.parse_threshold_no_good_vault(
            payload,
            observed_variables=observed_tuple,
            caps=_vault_v1.O1C66_VAULT_CAPS,
        )
        adapter_identity = _vault_v1.vault_identity_from_sources(
            cnf_sha256=APPLE8_CNF_SHA256,
            potential_sha256=APPLE8_POTENTIAL_SHA256,
            grouping_sha256=GROUPING_SHA256,
            observed_variables=observed_tuple,
            bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
            threshold=THRESHOLD,
        )
        _vault_v1.validate_threshold_no_good_vault_identity(
            adapter, expected=adapter_identity
        )
    except Exception as exc:
        raise O1C67ParentError("retained vault dual parse differs") from exc
    if (
        independent.to_bytes() != payload
        or adapter.serialized != payload
        or independent.sha256 != adapter.sha256
        or independent.sha256 != PARENT_RETAINED_VAULT_SHA256
        or len(independent.clauses) != PARENT_RETAINED_VAULT_CLAUSES
        or independent.literal_count != PARENT_RETAINED_VAULT_LITERALS
        or independent.aggregate_clause_sha256 != PARENT_RETAINED_VAULT_AGGREGATE_SHA256
    ):
        raise O1C67ParentError("retained vault parsers disagree")
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


def _active_conflicting_processes() -> list[dict[str, object]]:
    patterns = (
        "w52",
        "arx-carry-leak",
        "metal-recovery",
        "native-joint-score-sieve",
        "cadical_o1_joint_score_sieve",
    )
    completed = subprocess.run(
        ["ps", "-axo", "pid=,command="],
        capture_output=True,
        text=True,
        check=False,
    )
    rows: list[dict[str, object]] = []
    if completed.returncode:
        return rows
    own = os.getpid()
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        pid_text, separator, command = stripped.partition(" ")
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        lowered = command.lower()
        if separator and pid != own and any(pattern in lowered for pattern in patterns):
            rows.append(
                {
                    "pid": pid,
                    "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
                }
            )
    return rows


def _validate_adapter_preflight(
    root: Path, config: Mapping[str, object]
) -> Mapping[str, object]:
    row = _mapping(config["adapter_preflight"], "adapter_preflight")
    artifact = _relative(root, row["artifact"], "adapter preflight artifact")
    expected = _sha256(row["sha256"], "adapter preflight sha256")
    if sha256_file(artifact) != expected:
        raise O1C67RunError("target-free adapter preflight identity differs")
    report = _read_json(artifact, "target-free adapter preflight")
    if (
        report.get("schema") != ADAPTER_PREFLIGHT_SCHEMA
        or report.get("attempt_id") != ATTEMPT_ID
        or report.get("classification") != ADAPTER_PREFLIGHT_CLASSIFICATION
        or report.get("target_free") is not True
        or report.get("native_solver_calls") != 0
        or report.get("truth_key_bytes_read") is not False
        or report.get("all_gates_passed") is not True
    ):
        raise O1C67RunError("target-free adapter preflight differs")
    return report


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    """Read-only authorization with zero calls, writes, target, or truth reads."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    expected = _mapping(
        _mapping(config["source"], "source")["expected_sha256"],
        "source.expected_sha256",
    )
    observed = _source_hashes(root, config)
    if any(observed[name] != _sha256(expected[name], name) for name in SOURCE_NAMES):
        raise O1C67RunError("source hash differs")
    baseline = _o1c65.validate_apple8_baseline(root, config)
    _o1c65.validate_grouping_provenance(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    frozen = _o1c65.build_frozen_grouping(potential, config)
    imported = validate_parent_and_import_vault(root, config, frozen)
    gate = _validate_adapter_preflight(root, config)
    source_commit = _git_commit(root)
    clean = _selected_sources_clean(root, config_file, config)
    if require_commit_binding:
        if not clean:
            raise O1C67RunError("science sources/config are not clean")
        source = _mapping(config["source"], "source")
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
    active = _active_conflicting_processes()
    if memory_free is not None and memory_free < MINIMUM_MEMORY_FREE_PERCENT:
        raise O1C67RunError("memory-pressure preflight is below gate")
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C67RunError("disk-free preflight is below gate")
    if normalized_load > MAXIMUM_NORMALIZED_LOAD_1M:
        raise O1C67RunError("normalized system load is above gate")
    if active:
        raise O1C67RunError("conflicting science process is active")
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
        "adapter_preflight_sha256": sha256_file(root / ADAPTER_PREFLIGHT_RELATIVE),
        "adapter_preflight_classification": gate["classification"],
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_native_calls_consumed": PARENT_NATIVE_CALLS,
        "parent_failed_call_billed_conflicts": None,
        "retained_vault_sha256": imported.independent.sha256,
        "retained_vault_clause_count": len(imported.independent.clauses),
        "retained_vault_literal_count": imported.independent.literal_count,
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


def _stream_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogatepass")
    return None


def _failure_stream(
    directory: Path, name: str, payload: bytes | None
) -> dict[str, object]:
    if payload is None:
        return {
            "present": False,
            "bytes": None,
            "sha256": None,
            "artifact": None,
            "persisted_bytes": 0,
            "persisted_sha256": None,
            "truncated": False,
        }
    bounded = payload[:MAXIMUM_FAILURE_STREAM_BYTES]
    artifact = f"native_failure.{name}"
    _atomic_bytes(directory / artifact, bounded)
    return {
        "present": True,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "artifact": artifact,
        "persisted_bytes": len(bounded),
        "persisted_sha256": hashlib.sha256(bounded).hexdigest(),
        "truncated": len(bounded) != len(payload),
    }


def _exception_chain(exc: BaseException) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        rows.append({"type": type(current).__qualname__, "message": str(current)})
        current = current.__cause__ or current.__context__
    return rows


def _first_evidence(exc: BaseException, name: str) -> object | None:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, name, None)
        if value is not None:
            return value
        telemetry = getattr(current, "failure_telemetry", None)
        if isinstance(telemetry, Mapping) and telemetry.get(name) is not None:
            return telemetry[name]
        current = current.__cause__ or current.__context__
    return None


def native_failure_evidence(exc: BaseException, directory: Path) -> dict[str, object]:
    """Persist bounded streams while retaining full byte lengths and hashes."""

    raw_returncode = _first_evidence(exc, "returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    command = _first_evidence(exc, "command") or _first_evidence(exc, "cmd")
    stdout = _stream_bytes(_first_evidence(exc, "stdout"))
    stderr = _stream_bytes(_first_evidence(exc, "stderr"))
    raw_telemetry = getattr(exc, "failure_telemetry", None)
    if isinstance(raw_telemetry, Mapping):
        adapter_telemetry: dict[str, object] | None = dict(raw_telemetry)
        # Streams are externalized below. Duplicating raw strings inside JSON
        # would silently defeat the 1-MiB persisted-evidence boundary.
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
        "stdout": _failure_stream(directory, "stdout", stdout),
        "stderr": _failure_stream(directory, "stderr", stderr),
        "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
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
        "lineage_calls_before": PARENT_NATIVE_CALLS,
        "parent_last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
        "parent_last_completed_ordinal": PARENT_LAST_COMPLETED_ORDINAL,
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
        "retained_vault": vault.describe(),
        "bindings": dict(bindings),
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _intent(invocation_sha256: str, vault: _o1c66.ClauseVault) -> dict[str, object]:
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
        "input_vault": vault.describe(),
        "truth_key_reads": 0,
        "fresh_reveal_calls": 0,
        "entropy_calls": 0,
        "refits": 0,
        "MPS_or_GPU": False,
    }


def _validated_native(
    result: object,
) -> tuple[dict[str, object], dict[str, int | float], Mapping[str, object]]:
    try:
        raw = _mapping(getattr(result, "raw"), "native.raw")
        stats = _native_v9.validate_vault_soft_conflict_ledger(
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
            isinstance(status, bool)
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
            raise O1C67RunError("native O1C-0067 contract differs")
        ledger = {
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
        return dict(raw), ledger, telemetry
    except O1C67RunError:
        raise
    except Exception as exc:
        raise O1C67RunError("native O1C-0067 result differs") from exc


def execute_single_continuation(
    *,
    capsule: Path,
    imported_vault: _o1c66.ClauseVault,
    adapter_vault: _vault_v1.ThresholdNoGoodVault,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object],
) -> SingleContinuationOutcome:
    """Persist intent, consume exactly one new call, and never retry."""

    if not capsule.is_dir() or imported_vault.sha256 != PARENT_RETAINED_VAULT_SHA256:
        raise O1C67RunError("single-continuation capsule or vault differs")
    imported_path = capsule / "vault-imported.bin"
    _o1c66.write_vault(imported_path, imported_vault)
    if imported_path.read_bytes() != adapter_vault.serialized:
        raise O1C67RunError("dual-parsed imported vault bytes differ")
    reread = _o1c66.read_vault(
        imported_path,
        identity=imported_vault.identity,
        observed_variables=imported_vault.observed_variables,
    )
    if reread != imported_vault:
        raise O1C67RunError("capsule imported vault reread differs")

    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, _invocation(bindings, imported_vault))
    invocation_sha = sha256_file(invocation_path)
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, _intent(invocation_sha, imported_vault))
    intent_sha = sha256_file(intent_path)
    if not invocation_path.exists() or not intent_path.exists():
        raise O1C67RunError("invocation/intent not durable before call")

    try:
        result = invoke_episode(
            LOCAL_EPISODE_ORDINAL, LINEAGE_CALL_ORDINAL, imported_path
        )
    except BaseException as exc:
        evidence = native_failure_evidence(exc, episode_dir)
        _atomic_json(episode_dir / "native_execution_failure.json", evidence)
        failure = {
            "classification": OPERATIONAL_TERMINAL,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "native_execution_failure_sha256": sha256_file(
                episode_dir / "native_execution_failure.json"
            ),
            "truth_key_bytes_read": False,
        }
        _atomic_json(episode_dir / "terminal_failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "intent_sha256": intent_sha,
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
        raw, ledger, vault_telemetry = _validated_native(result)
        eligible_raw = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible_raw, Sequence):
            raise O1C67RunError("eligible emitted clause sequence differs")
        eligible = tuple(_o1c66._clause_literals(item) for item in eligible_raw)
        if (
            _o1c66._adapter_vault_payload(getattr(result, "input_vault"))
            != imported_vault.to_bytes()
        ):
            raise O1C67RunError("native input vault differs")
        status = ledger["status"]
        key_model = getattr(result, "key_model", None)
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C67RunError("SAT model failed public eight-block verification")
        elif key_model is not None:
            raise O1C67RunError("non-SAT continuation returned a key")

        next_available = vault_telemetry.get("next_vault_available")
        terminal_reason = vault_telemetry.get("next_vault_terminal_reason")
        adapter_next = getattr(result, "next_vault")
        if not isinstance(next_available, bool):
            raise O1C67RunError("next-vault availability differs")
        if next_available:
            if terminal_reason is not None or adapter_next is None:
                raise O1C67RunError("available next vault differs")
            next_payload = _o1c66._adapter_vault_payload(adapter_next)
            parsed_next = _o1c66.ClauseVault.from_bytes(
                next_payload,
                expected_identity=imported_vault.identity,
                observed_variables=imported_vault.observed_variables,
            )
            expected_next, novel, duplicates = imported_vault.append_emitted(eligible)
            if parsed_next != expected_next:
                raise O1C67RunError("cumulative continuation vault differs")
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
                raise O1C67RunError("terminal next vault differs")
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
                raise O1C67RunError("continuation output vault reread differs")

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
            classification, stop_reason = CONTINUATION_GAIN, "novel-exact-clauses"
        else:
            classification, stop_reason = (
                SATURATED_NO_GAIN,
                "zero-novel-eligible-clauses",
            )
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "billed_conflicts": cast(int, ledger["billed_conflicts"]),
            "input_vault": imported_vault.describe(),
            "output_vault": parsed_next.describe(),
            "output_vault_archived": archive_output,
            "output_vault_sidecar": "episodes/00/vault-output.bin"
            if archive_output
            else None,
            "eligible_emitted": {
                "clause_count": len(eligible),
                "literal_count": sum(len(clause) for clause in eligible),
                "novel_clause_count": novel_count,
                "novel_literal_count": sum(len(clause) for clause in novel),
                "duplicate_clause_count": duplicates,
            },
            "work_and_resources": ledger,
            "search_delta_from_parent_last_completed": {
                "decisions_delta": (
                    cast(int, ledger["decisions"]) - PARENT_LAST_DECISIONS
                ),
                "propagations_delta": (
                    cast(int, ledger["propagations"]) - PARENT_LAST_PROPAGATIONS
                ),
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
                "model_sha256": hashlib.sha256(key_model).hexdigest()
                if isinstance(key_model, bytes)
                else None,
                "truth_key_bytes_read": False,
            },
            "retry_authorized": False,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return SingleContinuationOutcome(
            classification,
            stop_reason,
            episode,
            parsed_next,
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


def validate_native_build_identity(native_build: NativeGuidedSearchBuild) -> None:
    try:
        executable_sha = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C67RunError("native-v6 build identity differs") from exc
    if (
        not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.executable.name != "native-joint-score-sieve"
        or native_build.source_sha256 != EXPECTED_NATIVE_SOURCE_SHA256
        or native_build.executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or executable_sha != EXPECTED_NATIVE_EXECUTABLE_SHA256
    ):
        raise O1C67RunError("native-v6 build identity differs")


def invoke_native_episode(
    *, executable: Path, cnf: Path, potential: Path, grouping: Path, vault: Path
) -> object:
    _o1c65.validate_frozen_call_inputs(cnf=cnf, potential=potential, grouping=grouping)
    if vault.is_symlink() or sha256_file(vault) != PARENT_RETAINED_VAULT_SHA256:
        raise O1C67RunError("continuation input vault differs before call")
    return _native_v9.run_joint_score_sieve(
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
    return _o1c66._runtime_resources(
        started=started, cpu_started=cpu_started, child_started=child_started
    )


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
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "capsule": capsule_relative.as_posix(),
        "invocation_id": INVOCATION_ID,
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "parent": {
            "attempt_id": "O1C-0066",
            "result_sha256": PARENT_RESULT_SHA256,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "native_calls_consumed": PARENT_NATIVE_CALLS,
            "last_consumed_ordinal": PARENT_LAST_CONSUMED_ORDINAL,
            "known_completed_billed_conflicts": PARENT_KNOWN_COMPLETED_BILLED_CONFLICTS,
            "failed_call_billed_conflicts": None,
        },
        "claim_boundary": {
            "new_attempt_not_parent_retry": True,
            "parent_ordinal_replay_authorized": False,
            "exactly_one_new_native_call": outcome.native_calls == 1,
            "requested_conflicts_is_soft_horizon": True,
            "actual_solve_conflicts_billed": billed is not None,
            "numeric_overshoot_ceiling_asserted": False,
            "hard_process_time_rss_caps_retained": True,
            "vault_clauses_valid_for": "CNF-and-potential-score-greater-than-or-equal-threshold",
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
            "parent_failed_call_billed_conflicts": None,
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
        "preflight": dict(preflight_row),
        "next_action": "Do not replay this invocation; choose the next mechanism from its exact one-call terminal.",
    }


def _markdown(result: Mapping[str, object]) -> str:
    return (
        "# O1C-0067 — APPLE8 sealed-vault continuation\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Stop reason: `{result['stop_reason']}`\n"
        "- New native calls: `1`\n"
        "- Local / lineage ordinal: `0 / 3`\n"
        "- Billing: actual observed solve conflicts; no numeric overshoot ceiling\n"
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
        raise O1C67RunError("O1C-0067 terminal publication already exists")
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
        raise O1C67RunError("persistent artifact ledger did not converge")
    if persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES:
        raise O1C67RunError("persistent artifact byte budget exceeded")
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
            raise O1C67RunError("terminal publication bytes differ")
        _o1c65._assert_immutable_tree(capsule)
    except Exception:
        _o1c65._restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _o1c65._unlink_owned_exact(
                manifest_path, manifest, "O1C67 capsule manifest"
            )
        if authoritative_published:
            _o1c65._unlink_owned_exact(
                authoritative, payload, "O1C67 authoritative result"
            )
        raise


def _validate_publication_source(root: Path, capsule: Path) -> dict[str, object]:
    """Recover only a completed one-call outcome; never infer or replay a call."""

    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or capsule.parent != root / "runs"
        or not capsule.name.endswith(f"_{CAPSULE_SUFFIX}")
        or (capsule / "artifacts.sha256").exists()
    ):
        raise O1C67RunError("O1C-0067 recovery capsule differs")
    source_path = capsule / PUBLICATION_SOURCE_NAME
    source = dict(_read_json(source_path, "O1C-0067 publication source"))
    episode = _mapping(source.get("episode"), "publication source episode")
    resources = _mapping(source.get("resources"), "publication source resources")
    episode_path = capsule / "episodes" / "00" / "episode.json"
    persisted_episode = _read_json(episode_path, "persisted O1C-0067 episode")
    relative = capsule.relative_to(root).as_posix()
    if (
        source.get("schema") != RESULT_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("capsule") != relative
        or source.get("invocation_id") != INVOCATION_ID
        or source.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or source.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or episode != persisted_episode
        or episode.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or episode.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or episode.get("native_calls_consumed") != 1
        or episode.get("retry_authorized") is not False
        or resources.get("native_solver_calls") != 1
        or not (capsule / "invocation.json").is_file()
        or not (capsule / "episodes" / "00" / "intent.json").is_file()
    ):
        raise O1C67RunError("O1C-0067 publication source differs")
    return source


def recover_publication(
    *,
    root: Path,
    capsule: Path,
    authoritative: Path,
    cause: BaseException | None,
) -> dict[str, object]:
    """Seal completed sidecars without issuing a native process call."""

    if authoritative.exists():
        raise O1C67RunError("O1C-0067 authoritative publication already exists")
    source = _validate_publication_source(root, capsule)
    original_classification = source.get("classification")
    original_stop_reason = source.get("stop_reason")
    failure = {
        "classification": OPERATIONAL_TERMINAL,
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_consumed": 1,
        "native_calls_issued_during_recovery": 0,
        "retry_authorized": False,
        "original_science_classification": original_classification,
        "original_science_stop_reason": original_stop_reason,
        "error_type": type(cause).__qualname__ if cause is not None else None,
        "error_message": str(cause) if cause is not None else None,
        "exception_chain_outer_to_cause_or_context": (
            _exception_chain(cause) if cause is not None else []
        ),
        "truth_key_bytes_read": False,
    }
    recovered = dict(source)
    recovered["classification"] = OPERATIONAL_TERMINAL
    recovered["stop_reason"] = "publication-recovery"
    recovered["operational_failure"] = failure
    recovered["recorded_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
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
        raise O1C67RunError("O1C-0067 already exists")
    if partial_capsules:
        if len(partial_capsules) != 1:
            raise O1C67RunError("multiple O1C-0067 recovery capsules exist")
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
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c67-apple8-vault-continuation-") as raw:
        workspace = Path(raw)
        native_build = _native_v9.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "native-joint-score-sieve",
        )
        validate_native_build_identity(native_build)
        observed_sources = _source_hashes(root, config)
        if observed_sources != dict(
            _mapping(source["expected_sha256"], "source.expected_sha256")
        ):
            raise O1C67RunError("source identity changed after preflight")
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
                "o1_crypto_lab.o1c67_apple8_episodic_vault_continuation_run run "
                f"--config {config_file.relative_to(root).as_posix()}\n"
            ).encode(),
        )
        bindings = {
            "source_commit": source_commit,
            "config_sha256": sha256_file(config_file),
            "source_sha256": observed_sources,
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_adapter_schema": NATIVE_ADAPTER_SCHEMA,
            "native_ledger_schema": NATIVE_LEDGER_SCHEMA,
            "parent_result_sha256": PARENT_RESULT_SHA256,
            "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
            "parent_failed_intent_sha256": PARENT_FAILED_INTENT_SHA256,
            "parent_terminal_failure_sha256": PARENT_TERMINAL_FAILURE_SHA256,
            "retained_vault_sha256": PARENT_RETAINED_VAULT_SHA256,
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
                raise O1C67RunError("continuation ordinal differs")
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
        description="Preflight or run the frozen O1C-0067 one-call continuation"
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
    except O1C67RunError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
