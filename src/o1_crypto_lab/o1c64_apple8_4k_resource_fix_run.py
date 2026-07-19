"""O1C-0064: one resource-capped, evidence-complete APPLE8 4K call."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import signal
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence, cast

from . import joint_score_sieve_v6 as _native_v6
from . import o1c63_apple8_4k_repair_run as _o1c63
from .chacha_trace import chacha20_blocks
from .full256_broker import verify_reveal
from .joint_score_sieve import JointScoreSieveResult
from .o1_relational_search import (
    NativeGuidedSearchBuild,
    O1RelationalSearchError,
    sha256_file,
)
from .o1c37_relational_guided_search_run import _git_commit, lab_root
from .o1c59_multiblock_joint_score_sieve_run import (
    _atomic_bytes,
    _atomic_json,
    _canonical_json_bytes,
    _capsule_manifest as _shared_capsule_manifest,
    _commit_bound_bytes,
    _memory_free_percent,
    _replace_owned_json,
)


ATTEMPT_ID = "O1C-0064"
CONFIG_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-resource-fix-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-resource-fix-preflight-v1"
INTENT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-resource-fix-native-call-intent-v1"
RESULT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-resource-fix-result-v1"
CAPSULE_SUFFIX = "O1C-0064_apple8-crossblock-consequence-sieve-4k-resource-fix-v1"
RESULT_RELATIVE = Path(
    "research/O1C0064_APPLE8_CROSSBLOCK_SIEVE_4K_RESOURCE_FIX_RESULT_20260719.json"
)

APPLE8_RESULT_RELATIVE = _o1c63.APPLE8_RESULT_RELATIVE
APPLE8_CAPSULE_RELATIVE = _o1c63.APPLE8_CAPSULE_RELATIVE
APPLE8_CNF_RELATIVE = _o1c63.APPLE8_CNF_RELATIVE
APPLE8_POTENTIAL_RELATIVE = _o1c63.APPLE8_POTENTIAL_RELATIVE
O1C57_REVEAL_RELATIVE = _o1c63.O1C57_REVEAL_RELATIVE
O1C63_RESULT_RELATIVE = Path(
    "research/O1C0063_APPLE8_CROSSBLOCK_SIEVE_4K_REPAIR_RESULT_20260719.json"
)
O1C63_CAPSULE_RELATIVE = Path(
    "runs/20260719_110348_O1C-0063_apple8-crossblock-consequence-sieve-4k-repair-v1"
)

CONFLICT_LIMIT = 4_096
MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
MAXIMUM_BILLED_CONFLICTS = 4_097
NATIVE_TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 1_073_741_824
THRESHOLD = 14.606178797892962
SUSTAINED_SCALING_MINIMUM_PRUNES = 24
MAXIMUM_NATIVE_FAILURE_STREAM_BYTES = 1_048_576
NATIVE_EXECUTION_FAILURE_SCHEMA = _native_v6.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA

NATIVE_RESULT_SCHEMA = _native_v6.JOINT_SCORE_SIEVE_RESULT_SCHEMA
IMPLEMENTATION_PARENT_SCHEMA = _native_v6.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
SOFT_CONFLICT_LEDGER_SCHEMA = _native_v6.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
JOINT_SCORE_SIEVE_DECISION_RULE = _native_v6.JOINT_SCORE_SIEVE_DECISION_RULE
TEARDOWN_RULE = _native_v6.JOINT_SCORE_SIEVE_TEARDOWN_RULE
PENDING_BACKTRACK_RULE = _native_v6.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
DARWIN_WATCHDOG_GUARD_BYTES = _native_v6.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _native_v6.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES = MEMORY_LIMIT_BYTES - DARWIN_WATCHDOG_GUARD_BYTES
EXPECTED_NATIVE_EXECUTABLE_SHA256 = (
    "a87044336c3ad137d42405ea3db20795c4b8a2fc65d977a59235cb2ab47ae467"
)
EXPECTED_NATIVE_SOURCE_SHA256 = (
    "8b479aa421b93fce4376ceb291fea175528f9ab6ab4f2ccc9377563357e9cf04"
)

O1C63_RESULT_SHA256 = "fdf46885ff0c268057a8118743d127d39203a219b323729cc05ff6e1f48c23a2"
O1C63_MANIFEST_SHA256 = (
    "d652b9d6d1dc1fcc7c83594d236223a958cef427e6263cb964dd479b110d7b1a"
)
O1C63_NATIVE_FAILURE_SHA256 = (
    "cb0e42774f5d1326ff79081e96768b9aec870d72f5c008caea67d5a2e9e8d0b5"
)

SOURCE_NAMES = (
    "runner",
    "resource_parent_runner",
    "joint_score_sieve_v6",
    "joint_score_sieve_v5",
    "joint_score_sieve_base",
    "native_source",
    "native_base_source",
    "native_v2_conceptual_parent",
    "o1c59_lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
)
FROZEN_APPLE8_SHA256 = dict(_o1c63.FROZEN_APPLE8_SHA256)
CONFIG_FIELDS = {
    "schema",
    "attempt_id",
    "slug",
    "claim_level",
    "hypothesis",
    "prediction",
    "source",
    "frozen_sha256",
    "resource_fix_provenance",
    "input",
    "native",
    "apple512",
    "promotion",
    "budgets",
    "next_action",
}


class O1C64RunError(RuntimeError):
    """The O1C63 provenance, resource fix, telemetry, or one-call ledger differs."""


@dataclass(frozen=True)
class FrozenO1C63Provenance:
    capsule: Path
    authoritative_result: Path
    result: Mapping[str, object]
    native_failure: Mapping[str, object]
    inventory: Mapping[str, str]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C64RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C64RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise O1C64RunError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return _mapping(
            json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates), field
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C64RunError(f"{field} is not valid JSON") from exc


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C64RunError(f"{field} path differs")
    path = (root / value).resolve(strict=True)
    if not path.is_relative_to(root):
        raise O1C64RunError(f"{field} escapes the lab")
    return path


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C64RunError(f"{field} hash differs")
    return value


def _assert_immutable_tree(capsule: Path, field: str) -> None:
    if not capsule.is_dir() or capsule.is_symlink():
        raise O1C64RunError(f"{field} capsule differs")
    for path in (capsule, *capsule.rglob("*")):
        if path.is_symlink() or path.stat(follow_symlinks=False).st_mode & (
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        ):
            raise O1C64RunError(f"{field} capsule is not immutable")


def _manifest_inventory(capsule: Path, expected_sha256: str) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != expected_sha256:
        raise O1C64RunError("O1C-0063 terminal manifest hash differs")
    inventory: dict[str, str] = {}
    try:
        rows = manifest.read_text("ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise O1C64RunError("O1C-0063 terminal manifest encoding differs") from exc
    for row in rows:
        digest, separator, relative = row.partition("  ")
        relative_path = Path(relative)
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative in inventory
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative == "artifacts.sha256"
        ):
            raise O1C64RunError("O1C-0063 terminal manifest row differs")
        target = (capsule / relative_path).resolve(strict=True)
        if (
            not target.is_relative_to(capsule)
            or not target.is_file()
            or target.is_symlink()
            or sha256_file(target) != digest
        ):
            raise O1C64RunError(f"O1C-0063 terminal artifact differs: {relative}")
        inventory[relative] = digest
    observed = {
        path.relative_to(capsule).as_posix()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if observed != {*inventory, "artifacts.sha256"}:
        raise O1C64RunError("O1C-0063 terminal manifest inventory differs")
    return inventory


def _exact_config_rows() -> dict[str, object]:
    baseline_density = 6 * 1_000.0 / 513
    derived_gate = math.ceil(0.5 * baseline_density * 4_097 / 1_000.0)
    if derived_gate != SUSTAINED_SCALING_MINIMUM_PRUNES:
        raise O1C64RunError("sustained scaling gate derivation differs")
    return {
        "resource_fix_provenance": {
            "source_attempt": "O1C-0063",
            "terminal_result": O1C63_RESULT_RELATIVE.as_posix(),
            "terminal_capsule": O1C63_CAPSULE_RELATIVE.as_posix(),
            "authoritative_result_sha256": O1C63_RESULT_SHA256,
            "manifest_sha256": O1C63_MANIFEST_SHA256,
            "capsule_result_sha256": O1C63_RESULT_SHA256,
            "native_failure_sha256": O1C63_NATIVE_FAILURE_SHA256,
            "native_call_intent_sha256": "15c8d93dd2e76c5f61da16c8849000e416797191bd8abb44afe9d06c6282ec47",
            "preflight_sha256": "6152953aa411b9017561db719c4dc1bbbdde5f0b8941e53191ce5c72513afb8d",
            "native_build_sha256": "ec8d8a0a8381f0e079a6f9beceb4f4f08c1e38f40274277b1ef06c5c4f0d6007",
            "config_sha256": "c67569e27f627243cdfd2f8eb4d53e69ed7065d2cbc3a6b83e82af78d4389923",
            "repair_provenance_sha256": "8a554646b47ff59d23d8fc4e19a5612e301c4e2bddcdef75ad68897a9c6aca4d",
            "apple8_binding_sha256": "f92f2307b1b2e1ce9ca4d634e63fc33972036481ec5ee33b3d38fd06974d8e3f",
            "terminal_classification": "O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
            "native_failure_classification": "O1C63_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "source_commit": "45b03a90daeb2daac1c1cf74fdb2513a53876eaf",
            "native_calls_consumed": 1,
            "validated_science_result": False,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
            "new_attempt_not_retry": True,
            "predecessor_reads_for_provenance_only": True,
            "predecessor_writes": 0,
            "audit_classification": "DARWIN_MEMORY_WATCHDOG_MOST_LIKELY",
            "audit_confidence": "HIGH_NOT_CONCLUSIVE",
            "audit_basis": "17.7s launched execution is below the 30s timeout; launch was OS-observed and allowed; the generic no-colon wrapper error excludes a detailed native nonzero exit; watchdog query failure remains a lower-probability alternative",
            "only_science_change": "none",
            "resource_change": "peak cap 805306368->1073741824 bytes; timeout 30->45 seconds",
            "operational_change": "rich chained execution-failure telemetry",
        },
        "input": {
            "apple8_result": APPLE8_RESULT_RELATIVE.as_posix(),
            "apple8_capsule": APPLE8_CAPSULE_RELATIVE.as_posix(),
            "cnf_relative": APPLE8_CNF_RELATIVE.as_posix(),
            "potential_relative": APPLE8_POTENTIAL_RELATIVE.as_posix(),
            "truth_reveal": O1C57_REVEAL_RELATIVE.as_posix(),
            "cnf_sha256": "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432",
            "potential_sha256": "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390",
            "threshold": THRESHOLD,
            "seed": 0,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
        },
        "native": {
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "seed": 0,
            "calls": 1,
            "result_schema": NATIVE_RESULT_SCHEMA,
            "implementation_parent_schema": IMPLEMENTATION_PARENT_SCHEMA,
            "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
            "execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
            "darwin_watchdog_kill_threshold_bytes": (
                DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES
            ),
            "darwin_watchdog_poll_interval_seconds": (DARWIN_WATCHDOG_INTERVAL_SECONDS),
            "expected_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
            "same_native_science_as_o1c63": True,
        },
        "apple512": {
            "trail_threshold_prunes": 6,
            "billed_conflicts": 513,
            "decisions": 4_471,
            "minimum_upper_bound": 13.197930778790159,
            "prune_density_per_1000_billed": baseline_density,
        },
        "promotion": {
            "exact_recovery": "SAT with a present model publicly verified on 8/8 blocks",
            "sustained_scaling_minimum_emitted_trail_prune_lower_bound": 24,
            "derivation": "ceil(0.5*(6/513)*4097)=24",
            "sustained": ">=24 emitted certified trail-prune lower bound without exact recovery",
            "active_sublinear": "1..23 emitted certified trail-prune lower bound without recovery",
            "regression": "0 emitted certified trail-prune lower bound without recovery",
            "pending_rule": "pending=external_clauses_queued-external_clauses_emitted in 0..1; emitted_trail_lower_bound=max(0,trail_threshold_prunes-pending)",
            "different_budget_work_is_matched": False,
        },
        "budgets": {
            "maximum_native_solver_calls": 1,
            "maximum_requested_conflicts": CONFLICT_LIMIT,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "maximum_native_wall_seconds": NATIVE_TIMEOUT_SECONDS,
            "maximum_peak_rss_bytes": MEMORY_LIMIT_BYTES,
            "minimum_memory_pressure_free_percent": 15,
            "maximum_fresh_targets": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_fresh_reveal_calls": 0,
            "maximum_refits": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_native_failure_stream_bytes": MAXIMUM_NATIVE_FAILURE_STREAM_BYTES,
            "maximum_persistent_artifact_bytes": 134_217_728,
        },
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C64RunError("config escapes the lab")
    config = dict(_read_mapping(config_path, "O1C64 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug")
        != "apple8-crossblock-consequence-sieve-4k-resource-fix-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or dict(frozen) != FROZEN_APPLE8_SHA256
        or any(
            config.get(name) != value for name, value in _exact_config_rows().items()
        )
    ):
        raise O1C64RunError("frozen O1C-0064 config differs")
    for name in SOURCE_NAMES:
        source_path = _relative(root, source[name], f"source.{name}")
        if sha256_file(source_path) != _sha256(expected[name], f"source.{name}"):
            raise O1C64RunError(f"source hash differs for {name}")
    return config


def validate_apple8_baseline(
    root: Path, config: Mapping[str, object]
) -> _o1c63._o1c62.FrozenApple8:
    try:
        return _o1c63.validate_apple8_baseline(root, config)
    except Exception as exc:
        raise O1C64RunError("frozen positive APPLE8 input differs") from exc


def validate_o1c63_resource_fix_provenance(
    root: Path, config: Mapping[str, object]
) -> FrozenO1C63Provenance:
    provenance = _mapping(
        config.get("resource_fix_provenance"), "resource_fix_provenance"
    )
    authoritative = _relative(
        root, provenance.get("terminal_result"), "O1C63 terminal result"
    )
    capsule = _relative(
        root, provenance.get("terminal_capsule"), "O1C63 terminal capsule"
    )
    if (
        authoritative != root / O1C63_RESULT_RELATIVE
        or capsule != root / O1C63_CAPSULE_RELATIVE
    ):
        raise O1C64RunError("O1C-0063 resource-fix provenance path differs")
    _assert_immutable_tree(capsule, "O1C-0063 terminal")
    inventory = _manifest_inventory(
        capsule, _sha256(provenance.get("manifest_sha256"), "O1C63 manifest")
    )
    required = {
        "result.json": provenance.get("capsule_result_sha256"),
        "native_failure.json": provenance.get("native_failure_sha256"),
        "native_call_intent.json": provenance.get("native_call_intent_sha256"),
        "preflight.json": provenance.get("preflight_sha256"),
        "native_build.json": provenance.get("native_build_sha256"),
        "config.json": provenance.get("config_sha256"),
        "repair_provenance.json": provenance.get("repair_provenance_sha256"),
        "apple8_binding.json": provenance.get("apple8_binding_sha256"),
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C64RunError("O1C-0063 resource-fix manifest binding differs")
    expected_result = _sha256(
        provenance.get("authoritative_result_sha256"), "O1C63 result"
    )
    capsule_result = capsule / "result.json"
    if (
        expected_result != O1C63_RESULT_SHA256
        or provenance.get("capsule_result_sha256") != expected_result
        or sha256_file(authoritative) != expected_result
        or sha256_file(capsule_result) != expected_result
        or authoritative.read_bytes() != capsule_result.read_bytes()
    ):
        raise O1C64RunError("O1C-0063 terminal result mirror differs")
    result = _read_mapping(authoritative, "O1C63 terminal result")
    claim = _mapping(result.get("claim_boundary"), "O1C63 claim boundary")
    failure = _mapping(result.get("operational_failure"), "O1C63 failure")
    resources = _mapping(result.get("resources"), "O1C63 resources")
    native_failure = _read_mapping(
        capsule / "native_failure.json", "O1C63 native failure"
    )
    opaque = _mapping(
        failure.get("native_failure_telemetry"), "O1C63 native failure telemetry"
    )
    if (
        result.get("schema") != _o1c63.RESULT_SCHEMA
        or result.get("attempt_id") != "O1C-0063"
        or result.get("classification") != "O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        or result.get("capsule") != O1C63_CAPSULE_RELATIVE.as_posix()
        or result.get("source_commit") != provenance.get("source_commit")
        or claim.get("native_solver_calls") != 1
        or claim.get("retry_authorized") is not False
        or claim.get("validated_science_result") is not False
        or claim.get("truth_key_bytes_read_after_public_diagnostic") is not False
        or failure.get("classification")
        != "O1C63_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT"
        or failure.get("error_type") != "O1RelationalSearchError"
        or failure.get("error_message") != "joint-score-sieve execution failed"
        or failure.get("occurred_after_persisted_intent") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("retry_authorized") is not False
        or failure.get("truth_key_bytes_read") is not False
        or opaque.get("returncode") is not None
        or opaque.get("signal_number") is not None
        or opaque.get("signal_name") is not None
        or opaque.get("structured") != {}
        or dict(native_failure) != dict(failure)
        or resources.get("native_solver_calls") != 1
        or resources.get("requested_conflicts") != CONFLICT_LIMIT
        or resources.get("maximum_billed_conflicts") != MAXIMUM_BILLED_CONFLICTS
        or resources.get("billed_conflicts") is not None
    ):
        raise O1C64RunError("O1C-0063 terminal operational semantics differ")
    preflight_row = _read_mapping(capsule / "preflight.json", "O1C63 preflight")
    intent = _read_mapping(capsule / "native_call_intent.json", "O1C63 intent")
    native_build = _read_mapping(capsule / "native_build.json", "O1C63 build")
    predecessor_config = _read_mapping(capsule / "config.json", "O1C63 config")
    if (
        preflight_row.get("ready_for_science") is not True
        or preflight_row.get("source_commit_bound") is not True
        or preflight_row.get("native_solver_calls") != 0
        or preflight_row.get("truth_key_bytes_read") is not False
        or preflight_row.get("timeout_seconds") not in (None, 30.0)
        or intent.get("attempt_id") != "O1C-0063"
        or intent.get("calls_before") != 0
        or intent.get("calls_authorized") != 1
        or intent.get("requested_conflicts") != CONFLICT_LIMIT
        or intent.get("maximum_billed_conflicts") != MAXIMUM_BILLED_CONFLICTS
        or intent.get("seed") != 0
        or intent.get("timeout_seconds") != 30.0
        or intent.get("memory_limit_bytes") != 805_306_368
        or intent.get("threshold") != THRESHOLD
        or intent.get("truth_key_reads") != 0
        or intent.get("native_executable_sha256") != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or native_build.get("source_sha256")
        != "8b479aa421b93fce4376ceb291fea175528f9ab6ab4f2ccc9377563357e9cf04"
        or native_build.get("executable_sha256") != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or predecessor_config.get("attempt_id") != "O1C-0063"
    ):
        raise O1C64RunError("O1C-0063 persisted resource-fix evidence differs")
    return FrozenO1C63Provenance(
        capsule=capsule,
        authoritative_result=authoritative,
        result=result,
        native_failure=native_failure,
        inventory=inventory,
    )


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    baseline = validate_apple8_baseline(root, config)
    predecessor = validate_o1c63_resource_fix_provenance(root, config)
    source_commit = _git_commit(root)
    if require_commit_binding:
        for name in SOURCE_NAMES:
            _commit_bound_bytes(
                root, source_commit, _relative(root, source[name], name), name
            )
        _commit_bound_bytes(root, source_commit, config_file, "config")
    memory_free = _memory_free_percent()
    budgets = _mapping(config["budgets"], "budgets")
    if memory_free is not None and memory_free < cast(
        int, budgets["minimum_memory_pressure_free_percent"]
    ):
        raise O1C64RunError("memory-pressure preflight is below frozen gate")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "config_sha256": sha256_file(config_file),
        "new_attempt_not_o1c63_retry": True,
        "o1c63_terminal_result_sha256": sha256_file(predecessor.authoritative_result),
        "o1c63_terminal_manifest_sha256": sha256_file(
            predecessor.capsule / "artifacts.sha256"
        ),
        "o1c63_native_calls_consumed": 1,
        "o1c63_validated_science_result": False,
        "o1c63_retry_authorized": False,
        "o1c63_writes": 0,
        "apple8_capsule": baseline.capsule.relative_to(root).as_posix(),
        "apple8_result_sha256": sha256_file(baseline.authoritative_result),
        "apple8_manifest_sha256": sha256_file(baseline.capsule / "artifacts.sha256"),
        "cnf_sha256": sha256_file(baseline.cnf),
        "potential_sha256": sha256_file(baseline.potential),
        "threshold": THRESHOLD,
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
        "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
        "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "expected_native_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
        "native_solver_calls": 0,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "truth_key_bytes_read": False,
        "files_written": 0,
        "memory_pressure_free_percent": memory_free,
    }


def validate_native_build_identity(native_build: NativeGuidedSearchBuild) -> None:
    """Authorize the exact native-v4 bytes before an O1C64 intent can exist."""

    try:
        executable_sha256 = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C64RunError("native-v4 build identity differs") from exc
    if (
        not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.source_sha256 != EXPECTED_NATIVE_SOURCE_SHA256
        or native_build.executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
    ):
        raise O1C64RunError("native-v4 build identity differs")


def invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    runner: Callable[..., JointScoreSieveResult] = _native_v6.run_joint_score_sieve,
) -> JointScoreSieveResult:
    """Make the sole O1C64 call with the frozen science and resource ceiling."""

    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=THRESHOLD,
        conflict_limit=CONFLICT_LIMIT,
        seed=0,
        timeout_seconds=NATIVE_TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
    )


def _json_lossless(value: object) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"non_finite_float": repr(value)}
    if isinstance(value, bytes):
        return {
            "encoding": "hex",
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "value": value.hex(),
        }
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_lossless(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_lossless(item) for item in value]
    return {
        "python_type": f"{type(value).__module__}.{type(value).__qualname__}",
        "repr": repr(value),
    }


def _stream_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogatepass")
    if isinstance(value, Mapping):
        for key in ("value", "text", "raw", "data"):
            if key in value:
                return _stream_bytes(value[key])
    return None


def _find_nested(value: object, *names: str) -> object:
    pending = [value]
    visited: set[int] = set()
    while pending:
        current = pending.pop(0)
        identity = id(current)
        if identity in visited:
            continue
        visited.add(identity)
        if isinstance(current, Mapping):
            for name in names:
                if name in current:
                    return current[name]
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return None


def _exception_chain(exc: Exception) -> list[dict[str, object]]:
    """Return every outer-to-cause/context node without discarding messages."""

    chain: list[dict[str, object]] = []
    current: BaseException | None = exc
    relationship = "outer"
    visited: set[int] = set()
    while current is not None:
        identity = id(current)
        if identity in visited:
            chain.append(
                {
                    "depth": len(chain),
                    "relationship": relationship,
                    "cycle_detected": True,
                }
            )
            break
        visited.add(identity)
        chain.append(
            {
                "depth": len(chain),
                "relationship": relationship,
                "module": type(current).__module__,
                "type": type(current).__qualname__,
                "message": str(current),
                "args": _json_lossless(current.args),
            }
        )
        if current.__cause__ is not None:
            current = current.__cause__
            relationship = "cause"
        elif current.__context__ is not None and not current.__suppress_context__:
            current = current.__context__
            relationship = "context"
        else:
            current = None
    return chain


def _first_exception_attribute(exc: Exception, *names: str) -> object:
    """Recover process fields even if an unexpected adapter omits telemetry."""

    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        for name in names:
            value = getattr(current, name, None)
            if value is not None:
                return value
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__context__ is not None and not current.__suppress_context__:
            current = current.__context__
        else:
            current = None
    return None


def _failure_stream(
    *, directory: Path | None, name: str, payload: bytes | None
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
    bounded = payload[:MAXIMUM_NATIVE_FAILURE_STREAM_BYTES]
    artifact = f"native_failure.{name}"
    artifact_persisted = False
    artifact_write_failure: dict[str, object] | None = None
    if directory is not None:
        try:
            _atomic_bytes(directory / artifact, bounded)
            artifact_persisted = True
        except Exception as exc:
            artifact_write_failure = {
                "type": type(exc).__qualname__,
                "message": str(exc),
                "chain": _exception_chain(exc),
            }
    return {
        "present": True,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "artifact": artifact if artifact_persisted else None,
        "persisted_bytes": len(bounded) if artifact_persisted else 0,
        "persisted_sha256": (
            hashlib.sha256(bounded).hexdigest() if artifact_persisted else None
        ),
        "truncated": len(bounded) != len(payload),
        "exact_value_preserved_in_adapter_telemetry": True,
        "artifact_write_failure": artifact_write_failure,
    }


def native_failure_telemetry(
    exc: Exception, *, directory: Path | None = None
) -> dict[str, object]:
    """Preserve v6 telemetry verbatim plus an independent Python cause chain."""

    declared = getattr(exc, "failure_telemetry", None)
    described_method = getattr(exc, "describe", None)
    described: object = None
    describe_error: dict[str, object] | None = None
    if callable(described_method):
        try:
            described = described_method()
        except Exception as capture_exc:
            describe_error = {
                "type": type(capture_exc).__qualname__,
                "message": str(capture_exc),
                "chain": _exception_chain(capture_exc),
            }
    adapter = declared if isinstance(declared, Mapping) else described
    adapter_mapping = adapter if isinstance(adapter, Mapping) else {}
    adapter_safe = cast(dict[str, object], _json_lossless(adapter_mapping))
    described_safe = (
        cast(dict[str, object], _json_lossless(described))
        if isinstance(described, Mapping)
        else None
    )
    declared_safe = (
        cast(dict[str, object], _json_lossless(declared))
        if isinstance(declared, Mapping)
        else None
    )
    adapter_schema = _find_nested(adapter_mapping, "schema")
    raw_stdout = _find_nested(adapter_mapping, "stdout")
    if raw_stdout is None:
        raw_stdout = _first_exception_attribute(exc, "stdout", "output")
    raw_stderr = _find_nested(adapter_mapping, "stderr")
    if raw_stderr is None:
        raw_stderr = _first_exception_attribute(exc, "stderr")
    stdout_payload = _stream_bytes(raw_stdout)
    stderr_payload = _stream_bytes(raw_stderr)
    raw_returncode = _find_nested(adapter_mapping, "returncode")
    if raw_returncode is None:
        raw_returncode = _first_exception_attribute(exc, "returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    raw_signal = _find_nested(adapter_mapping, "signal_number", "signal")
    if raw_signal is None:
        raw_signal = _first_exception_attribute(exc, "signal_number", "signal")
    signal_number = (
        raw_signal
        if isinstance(raw_signal, int) and not isinstance(raw_signal, bool)
        else -returncode
        if returncode is not None and returncode < 0
        else None
    )
    try:
        signal_name = signal.Signals(signal_number).name if signal_number else None
    except ValueError:
        signal_name = None
    adapter_contract_valid = (
        isinstance(declared, Mapping)
        and isinstance(described, Mapping)
        and declared_safe == described_safe
        and adapter_schema == NATIVE_EXECUTION_FAILURE_SCHEMA
    )
    return {
        "schema": "o1-256-o1c64-native-failure-evidence-v1",
        "adapter_failure_schema": adapter_schema,
        "adapter_contract_valid": adapter_contract_valid,
        "adapter_declared_and_described_equal": declared_safe == described_safe,
        "adapter_failure_telemetry": adapter_safe,
        "adapter_describe_error": describe_error,
        "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
        "classification_kind": _find_nested(
            adapter_mapping, "classification_kind", "kind", "classification"
        ),
        "phase": _find_nested(adapter_mapping, "phase"),
        "elapsed_seconds": _find_nested(adapter_mapping, "elapsed_seconds", "elapsed"),
        "configured_timeout_seconds": _find_nested(
            adapter_mapping, "configured_timeout_seconds", "timeout_seconds"
        ),
        "configured_memory_limit_bytes": _find_nested(
            adapter_mapping, "configured_memory_limit_bytes", "memory_limit_bytes"
        ),
        "darwin_watchdog_guard_bytes": _find_nested(
            adapter_mapping, "darwin_watchdog_guard_bytes", "guard_bytes"
        ),
        "darwin_watchdog_kill_threshold_bytes": _find_nested(
            adapter_mapping,
            "darwin_watchdog_kill_threshold_bytes",
            "kill_threshold_bytes",
        ),
        "darwin_watchdog_poll_interval_seconds": _find_nested(
            adapter_mapping,
            "darwin_watchdog_poll_interval_seconds",
            "poll_interval_seconds",
        ),
        "memory_samples": _json_lossless(
            _find_nested(adapter_mapping, "memory_samples", "rss_samples")
        ),
        "returncode": returncode,
        "signal_number": signal_number,
        "signal_name": signal_name,
        "stdout": _failure_stream(
            directory=directory, name="stdout", payload=stdout_payload
        ),
        "stderr": _failure_stream(
            directory=directory, name="stderr", payload=stderr_payload
        ),
        "o1c64_resource_contract": {
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
            "darwin_watchdog_kill_threshold_bytes": (
                DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES
            ),
            "darwin_watchdog_poll_interval_seconds": (DARWIN_WATCHDOG_INTERVAL_SECONDS),
        },
    }


def invoke_native_once_terminal(
    *, failure_directory: Path | None = None, **kwargs: object
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    try:
        return invoke_native_once(**kwargs), None  # type: ignore[arg-type]
    except Exception as exc:
        try:
            telemetry = native_failure_telemetry(exc, directory=failure_directory)
        except Exception as capture_exc:
            telemetry = {
                "schema": "o1-256-o1c64-native-failure-evidence-v1",
                "adapter_contract_valid": False,
                "telemetry_capture_failure": {
                    "type": type(capture_exc).__qualname__,
                    "message": str(capture_exc),
                    "chain": _exception_chain(capture_exc),
                },
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "o1c64_resource_contract": {
                    "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
                    "memory_limit_bytes": MEMORY_LIMIT_BYTES,
                    "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
                    "darwin_watchdog_kill_threshold_bytes": (
                        DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES
                    ),
                    "darwin_watchdog_poll_interval_seconds": (
                        DARWIN_WATCHDOG_INTERVAL_SECONDS
                    ),
                },
            }
        telemetry_artifact_sha256: str | None = None
        if failure_directory is not None:
            try:
                _atomic_json(
                    failure_directory / "native_execution_failure.json", telemetry
                )
                telemetry_artifact_sha256 = sha256_file(
                    failure_directory / "native_execution_failure.json"
                )
            except Exception as artifact_exc:
                telemetry["evidence_artifact_write_failure"] = {
                    "type": type(artifact_exc).__qualname__,
                    "message": str(artifact_exc),
                    "chain": _exception_chain(artifact_exc),
                }
        return None, {
            "classification": "O1C64_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
            "native_execution_failure_artifact": (
                "native_execution_failure.json"
                if telemetry_artifact_sha256 is not None
                else None
            ),
            "native_execution_failure_sha256": telemetry_artifact_sha256,
            "native_failure_telemetry": telemetry,
        }


def validate_native_resource_ledger(
    native: JointScoreSieveResult, *, solver_calls: int
) -> dict[str, int]:
    try:
        _native_v6.validate_native_lifecycle(native.raw)
        ledger = _native_v6.validate_soft_conflict_ledger(native.stats)
        if (
            native.raw.get("schema") != NATIVE_RESULT_SCHEMA
            or native.raw.get("implementation_parent_schema")
            != IMPLEMENTATION_PARENT_SCHEMA
            or native.raw.get("teardown_rule") != TEARDOWN_RULE
            or native.raw.get("pending_backtrack_rule") != PENDING_BACKTRACK_RULE
            or native.conflict_limit != CONFLICT_LIMIT
            or ledger["requested_conflicts"] != CONFLICT_LIMIT
            or ledger["billed_conflicts"] > MAXIMUM_BILLED_CONFLICTS
            or ledger["conflict_limit_overshoot"] > MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
            or int(native.resources["wall_microseconds"])
            > int(NATIVE_TIMEOUT_SECONDS * 1_000_000)
            or int(native.resources["peak_rss_bytes"]) > MEMORY_LIMIT_BYTES
            or native.sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
            or solver_calls != 1
        ):
            raise O1C64RunError("O1C-0064 native resource ledger differs")
    except O1C64RunError:
        raise
    except (
        O1RelationalSearchError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise O1C64RunError("O1C-0064 native lifecycle or ledger differs") from exc
    return ledger


def public_model_then_truth_diagnostic(
    native: JointScoreSieveResult,
    *,
    verify_public_model: Callable[[bytes], bool],
    read_truth_key: Callable[[], bytes],
    public_diagnostic_ledger: list[bool],
) -> tuple[bool, bytes | None, bool | None]:
    """Read truth only after a present native model publicly verifies 8/8."""

    if public_diagnostic_ledger != [False]:
        raise O1C64RunError("public diagnostic ledger differs")
    if native.key_model is None:
        public_diagnostic_ledger[0] = True
        if native.status == 10:
            raise O1C64RunError("SAT result lacks a native key model")
        return False, None, None
    try:
        public_verified = bool(verify_public_model(native.key_model))
    finally:
        public_diagnostic_ledger[0] = True
    if not public_verified:
        raise O1C64RunError("native model fails eight public blocks")
    truth = read_truth_key()
    if not isinstance(truth, bytes) or len(truth) != 32:
        raise O1C64RunError("post-native truth key differs")
    return True, truth, native.key_model == truth


def classify_scaling(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    billed_conflicts: int,
) -> tuple[str, dict[str, object]]:
    """Apply the unchanged O1C63 science under O1C64-owned labels."""

    try:
        classification, metrics = _o1c63.classify_scaling(
            native,
            public_model_verified=public_model_verified,
            billed_conflicts=billed_conflicts,
        )
    except Exception as exc:
        raise O1C64RunError(str(exc)) from exc
    translated = {
        "O1C63_EXACT_PUBLIC_FULL256_RECOVERY": ("O1C64_EXACT_PUBLIC_FULL256_RECOVERY"),
        "O1C63_APPLE8_4K_REPAIR_SUSTAINED_SCALING": (
            "O1C64_APPLE8_4K_RESOURCE_FIX_SUSTAINED_SCALING"
        ),
        "O1C63_APPLE8_4K_REPAIR_ACTIVE_SUBLINEAR": (
            "O1C64_APPLE8_4K_RESOURCE_FIX_ACTIVE_SUBLINEAR"
        ),
        "O1C63_APPLE8_4K_REPAIR_SCALING_REGRESSION": (
            "O1C64_APPLE8_4K_RESOURCE_FIX_SCALING_REGRESSION"
        ),
    }
    if classification not in translated:
        raise O1C64RunError("O1C-0064 scaling classification differs")
    return translated[classification], metrics


def _pretty_json_bytes(value: object) -> bytes:
    return _canonical_json_bytes(value)


def _capsule_manifest(capsule: Path) -> tuple[bytes, int]:
    return _shared_capsule_manifest(capsule, exclude={"artifacts.sha256"})


def _replace_owned_bytes(path: Path, payload: bytes) -> None:
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _restore_owned_capsule_for_recovery(capsule: Path) -> None:
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _unlink_owned_exact(path: Path, payload: bytes, field: str) -> None:
    if not path.exists():
        return
    if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
        raise O1C64RunError(f"{field} recovery ownership differs")
    path.chmod(0o644)
    path.unlink()
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _markdown(result: Mapping[str, object]) -> str:
    resources = _mapping(result["resources"], "resources")
    return (
        "# O1C Run O1C-0064\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native calls: `{resources['native_solver_calls']}`\n"
        f"- Requested conflicts: `{resources['requested_conflicts']}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n"
        f"- Peak cap: `{MEMORY_LIMIT_BYTES}` bytes\n"
        f"- Timeout: `{NATIVE_TIMEOUT_SECONDS}` seconds\n\n"
        "This is a new resource-fix attempt after O1C-0063's immutable terminal "
        "operational failure, not an O1C-0063 retry. It freezes the same Full256 "
        "target, CNF, potential, threshold, 4K conflict request, and native-v4 "
        "science. Only the peak cap, timeout, and execution-failure evidence "
        "adapter change. Apple512 comparison remains contextual, never "
        "matched-work.\n"
    )


def finalize_capsule(
    *,
    capsule: Path,
    authoritative_result: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    """Publish one immutable O1C64 capsule and byte-identical result mirror."""

    if (capsule / "artifacts.sha256").exists() or authoritative_result.exists():
        raise O1C64RunError("O1C-0064 terminal output already exists")
    _replace_owned_bytes(capsule / "RUN.md", _markdown(result).encode("utf-8"))
    resources = cast(dict[str, object], result["resources"])
    result_path = capsule / "result.json"
    for _ in range(8):
        _replace_owned_json(result_path, result)
        manifest, persistent = _capsule_manifest(capsule)
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C64RunError("O1C-0064 persistent byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C64RunError("O1C-0064 persistent byte budget exceeded")
    result_payload = _pretty_json_bytes(result)
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative_result, result_payload)
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
        if (
            authoritative_result.read_bytes() != result_payload
            or result_path.read_bytes() != result_payload
        ):
            raise O1C64RunError("O1C-0064 publication bytes differ")
        _assert_immutable_tree(capsule, "O1C-0064 terminal")
    except Exception:
        _restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _unlink_owned_exact(manifest_path, manifest, "O1C64 manifest")
        if authoritative_published:
            _unlink_owned_exact(
                authoritative_result,
                result_payload,
                "O1C64 authoritative result",
            )
        raise


def _truth_diagnostic(
    *,
    root: Path,
    capsule: Path,
    config: Mapping[str, object],
    baseline: object,
    native: JointScoreSieveResult,
) -> tuple[bool, bytes | None, bool | None, bool, bool]:
    """Own O1C64 truth-access artifacts; never call an O1C63 finalizer/path."""

    public_ledger = [False]
    truth_ledger = [False]
    baseline_mapping = cast(object, baseline)
    try:
        public_preflight = cast(
            Mapping[str, object], getattr(baseline_mapping, "public_preflight")
        )
    except AttributeError as exc:
        raise O1C64RunError("APPLE8 public preflight differs") from exc
    counters = tuple(
        cast(int, value)
        for value in _sequence(public_preflight["counters"], "counters")
    )
    outputs = tuple(
        bytes.fromhex(str(value))
        for value in _sequence(public_preflight["output_blocks_hex"], "outputs")
    )
    nonce = bytes.fromhex(str(public_preflight["nonce_hex"]))

    def verify_public(key: bytes) -> bool:
        verified = (
            len(key) == 32
            and tuple(
                chacha20_blocks(key, counter, nonce, 1)[0] for counter in counters
            )
            == outputs
        )
        _atomic_json(
            capsule / "public_model_diagnostic.json",
            {
                "schema": "o1-256-o1c64-public-model-diagnostic-v1",
                "present": True,
                "public_verified_8_of_8": verified,
                "truth_key_bytes_read": False,
            },
        )
        return verified

    def read_truth() -> bytes:
        _atomic_json(
            capsule / "truth_access_intent.json",
            {
                "schema": "o1-256-o1c64-truth-access-intent-v1",
                "reason": "diagnose-present-publicly-verified-8-of-8-model-only",
                "public_verified_8_of_8": True,
                "fresh_reveal_calls": 0,
            },
        )
        truth_ledger[0] = True
        input_row = _mapping(config["input"], "input")
        reveal_path = _relative(root, input_row["truth_reveal"], "truth reveal")
        expected = _sha256(
            _mapping(config["frozen_sha256"], "frozen_sha256")["truth_reveal"],
            "truth reveal",
        )
        if sha256_file(reveal_path) != expected:
            raise O1C64RunError("truth reveal hash differs")
        reveal = verify_reveal(_read_mapping(reveal_path, "truth reveal"))
        preimage = _mapping(reveal["commitment_preimage"], "commitment preimage")
        truth = bytes.fromhex(str(preimage["key_hex"]))
        _atomic_json(
            capsule / "truth_access_receipt.json",
            {
                "schema": "o1-256-o1c64-truth-access-receipt-v1",
                "truth_key_sha256": hashlib.sha256(truth).hexdigest(),
            },
        )
        return truth

    try:
        public, truth, equals = public_model_then_truth_diagnostic(
            native,
            verify_public_model=verify_public,
            read_truth_key=read_truth,
            public_diagnostic_ledger=public_ledger,
        )
    except Exception:
        if public_ledger[0] and not (capsule / "public_model_diagnostic.json").exists():
            _atomic_json(
                capsule / "public_model_diagnostic.json",
                {
                    "schema": "o1-256-o1c64-public-model-diagnostic-v1",
                    "present": native.key_model is not None,
                    "public_verified_8_of_8": False,
                    "truth_key_bytes_read": False,
                },
            )
        raise
    diagnostic_path = capsule / "public_model_diagnostic.json"
    if not diagnostic_path.exists():
        _atomic_json(
            diagnostic_path,
            {
                "schema": "o1-256-o1c64-public-model-diagnostic-v1",
                "present": False,
                "public_verified_8_of_8": False,
                "truth_key_bytes_read": False,
            },
        )
    return public, truth, equals, public_ledger[0], truth_ledger[0]


def _resource_fix_binding_row(
    *, root: Path, predecessor: FrozenO1C63Provenance, config: Mapping[str, object]
) -> dict[str, object]:
    provenance = _mapping(config["resource_fix_provenance"], "resource provenance")
    return {
        "schema": "o1-256-o1c64-terminal-resource-fix-provenance-v1",
        "source_attempt": "O1C-0063",
        "terminal_result": predecessor.authoritative_result.relative_to(
            root
        ).as_posix(),
        "terminal_capsule": predecessor.capsule.relative_to(root).as_posix(),
        "terminal_result_sha256": sha256_file(predecessor.authoritative_result),
        "terminal_manifest_sha256": sha256_file(
            predecessor.capsule / "artifacts.sha256"
        ),
        "native_failure_sha256": sha256_file(
            predecessor.capsule / "native_failure.json"
        ),
        "terminal_classification": predecessor.result["classification"],
        "native_failure_classification": predecessor.native_failure["classification"],
        "native_calls_consumed": 1,
        "validated_science_result": False,
        "truth_key_bytes_read": False,
        "retry_authorized": False,
        "new_attempt_not_retry": True,
        "predecessor_writes": 0,
        "audit_classification": provenance["audit_classification"],
        "audit_confidence": provenance["audit_confidence"],
        "audit_basis": provenance["audit_basis"],
        "only_science_change": provenance["only_science_change"],
        "resource_change": provenance["resource_change"],
        "operational_change": provenance["operational_change"],
        "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "native_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "native_source_sha256": EXPECTED_NATIVE_SOURCE_SHA256,
        "teardown_rule": TEARDOWN_RULE,
        "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
    }


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def _runtime_resources(
    *,
    started: float,
    cpu_started: float,
    child_started: resource.struct_rusage,
) -> dict[str, object]:
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "elapsed_seconds": time.perf_counter() - started,
        "parent_cpu_seconds": time.process_time() - cpu_started,
        "child_cpu_seconds": child.ru_utime
        + child.ru_stime
        - child_started.ru_utime
        - child_started.ru_stime,
        "peak_rss_bytes": _peak_rss_bytes(),
    }


def _terminal_runtime_resources(
    *,
    started: float,
    cpu_started: float,
    child_started: resource.struct_rusage,
) -> dict[str, object]:
    """Keep post-call terminalization alive if usage collection itself fails."""

    try:
        return _runtime_resources(
            started=started,
            cpu_started=cpu_started,
            child_started=child_started,
        )
    except Exception as exc:
        return {
            "elapsed_seconds": max(0.0, time.perf_counter() - started),
            "parent_cpu_seconds": None,
            "child_cpu_seconds": None,
            "peak_rss_bytes": None,
            "resource_capture_failure": {
                "type": type(exc).__qualname__,
                "message": str(exc),
                "chain": _exception_chain(exc),
            },
        }


def _persist_failure_evidence(path: Path, failure: dict[str, object]) -> None:
    """Record a sidecar when possible and retain any write failure in result.json."""

    try:
        _atomic_json(path, failure)
    except Exception as exc:
        failure["sidecar_write_failure"] = {
            "artifact": path.name,
            "type": type(exc).__qualname__,
            "message": str(exc),
            "chain": _exception_chain(exc),
        }


def _failure_result(
    *,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    failure: Mapping[str, object],
    solver_calls: int,
    runtime_resources: Mapping[str, object] | None = None,
    truth_read: bool = False,
) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": "O1C64_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
        "capsule": capsule_relative.as_posix(),
        "resource_fix_provenance": {
            "source_attempt": "O1C-0063",
            "terminal_result_sha256": O1C63_RESULT_SHA256,
            "terminal_manifest_sha256": O1C63_MANIFEST_SHA256,
            "native_failure_sha256": O1C63_NATIVE_FAILURE_SHA256,
            "new_attempt_not_retry": True,
            "o1c63_retry_authorized": False,
            "o1c63_native_calls_consumed": 1,
        },
        "claim_boundary": {
            "native_solver_calls": solver_calls,
            "retry_authorized": False,
            "validated_science_result": False,
            "new_attempt_not_o1c63_retry": True,
            "o1c63_terminal_provenance_bound": True,
            "o1c63_writes": 0,
            "same_full256_science_as_o1c63": True,
            "different_budget_work_is_matched": False,
            "truth_key_bytes_read_after_public_diagnostic": truth_read,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
        },
        "operational_failure": dict(failure),
        "metrics": {"native_status": "OPERATIONAL_FAILURE"},
        "resources": {
            **dict(runtime_resources or {}),
            "native_solver_calls": solver_calls,
            "requested_conflicts": CONFLICT_LIMIT,
            "billed_conflicts": None,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "native_timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight_row),
        "next_action": (
            "Do not retry O1C-0063 or O1C-0064; diagnose this immutable "
            "O1C-0064 terminal capsule under a new attempt ID."
        ),
    }


def _finalize_consumed_call_terminally(
    *,
    capsule: Path,
    authoritative_result: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    runtime_resources: Mapping[str, object] | None = None,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Publish once, or recover that publication into one O1C64 terminal."""

    try:
        finalize_capsule(
            capsule=capsule,
            authoritative_result=authoritative_result,
            result=result,
            maximum_persistent_bytes=maximum_persistent_bytes,
            _after_capsule_seal=_after_capsule_seal,
        )
        return result
    except Exception as exc:
        claim = _mapping(result.get("claim_boundary"), "claim_boundary")
        truth_read = claim.get("truth_key_bytes_read_after_public_diagnostic") is True
        failure = {
            "classification": (
                "O1C64_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT"
            ),
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
            "native_calls_consumed": 1,
            "publication_recovered": True,
            "retry_authorized": False,
            "truth_key_bytes_read": truth_read,
        }
        _persist_failure_evidence(capsule / "publication_failure.json", failure)
        terminal = _failure_result(
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            failure=failure,
            solver_calls=1,
            runtime_resources=runtime_resources,
            truth_read=truth_read,
        )
        finalize_capsule(
            capsule=capsule,
            authoritative_result=authoritative_result,
            result=terminal,
            maximum_persistent_bytes=maximum_persistent_bytes,
        )
        return terminal


def _source_hashes(root: Path, config: Mapping[str, object]) -> dict[str, str]:
    source = _mapping(config["source"], "source")
    return {
        name: sha256_file(_relative(root, source[name], f"source.{name}"))
        for name in SOURCE_NAMES
    }


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    if authoritative.exists() or tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise O1C64RunError("O1C-0064 already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = validate_apple8_baseline(root, config)
    predecessor = validate_o1c63_resource_fix_provenance(root, config)
    source_commit = str(preflight_row["source_commit"])
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c64-apple8-4k-resource-fix-") as raw:
        workspace = Path(raw)
        source = _mapping(config["source"], "source")
        native_build = _native_v6.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "cadical-o1-joint-score-sieve-v4",
        )
        # This check intentionally precedes capsule creation, intent, and invocation.
        validate_native_build_identity(native_build)
        observed_source_hashes = _source_hashes(root, config)
        expected_source_hashes = dict(
            _mapping(source["expected_sha256"], "source.expected_sha256")
        )
        if observed_source_hashes != expected_source_hashes:
            raise O1C64RunError("source identity changed after preflight")

        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        _atomic_json(
            capsule / "resource_fix_provenance.json",
            _resource_fix_binding_row(
                root=root, predecessor=predecessor, config=config
            ),
        )
        _atomic_json(
            capsule / "apple8_binding.json",
            {
                "schema": "o1-256-o1c64-frozen-apple8-binding-v1",
                "capsule": APPLE8_CAPSULE_RELATIVE.as_posix(),
                "result_sha256": sha256_file(baseline.authoritative_result),
                "manifest_sha256": sha256_file(baseline.capsule / "artifacts.sha256"),
                "cnf_sha256": sha256_file(baseline.cnf),
                "potential_sha256": sha256_file(baseline.potential),
                "threshold": THRESHOLD,
                "different_budget_work_is_matched": False,
            },
        )
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c64_apple8_4k_resource_fix_run run --config "
                f"{config_file.relative_to(root).as_posix()}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "config_sha256": sha256_file(config_file),
            "source_sha256": observed_source_hashes,
            "calls_before": 0,
            "calls_authorized": 1,
            "new_attempt_not_o1c63_retry": True,
            "o1c63_retry": False,
            "o1c63_native_calls_consumed": 1,
            "o1c63_terminal_result_sha256": O1C63_RESULT_SHA256,
            "o1c63_terminal_manifest_sha256": O1C63_MANIFEST_SHA256,
            "o1c63_native_failure_sha256": O1C63_NATIVE_FAILURE_SHA256,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
            "darwin_watchdog_kill_threshold_bytes": (
                DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES
            ),
            "darwin_watchdog_poll_interval_seconds": (DARWIN_WATCHDOG_INTERVAL_SECONDS),
            "threshold": THRESHOLD,
            "cnf_sha256": sha256_file(baseline.cnf),
            "potential_sha256": sha256_file(baseline.potential),
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
            "truth_key_reads": 0,
            "fresh_entropy_calls": 0,
            "fresh_reveal_calls": 0,
        }
        _atomic_json(capsule / "native_call_intent.json", intent)

        solver_calls = 1
        native, native_failure = invoke_native_once_terminal(
            executable=native_build.executable,
            cnf=baseline.cnf,
            potential=baseline.potential,
            failure_directory=capsule,
        )
        if native_failure is not None:
            native_failure = dict(native_failure)
            _persist_failure_evidence(capsule / "native_failure.json", native_failure)
            runtime = _terminal_runtime_resources(
                started=started,
                cpu_started=cpu_started,
                child_started=child_started,
            )
            result = _failure_result(
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                failure=native_failure,
                solver_calls=solver_calls,
                runtime_resources=runtime,
            )
            return _finalize_consumed_call_terminally(
                capsule=capsule,
                authoritative_result=authoritative,
                result=result,
                maximum_persistent_bytes=cast(
                    int, budgets["maximum_persistent_artifact_bytes"]
                ),
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                runtime_resources=runtime,
            )

        assert native is not None
        public_diagnostic_complete = False
        truth_read = False
        try:
            _atomic_json(capsule / "native_result.json", native.raw)
            ledger = validate_native_resource_ledger(native, solver_calls=solver_calls)
            _atomic_json(
                capsule / "conflict_ledger.json",
                {"schema": SOFT_CONFLICT_LEDGER_SCHEMA, **ledger},
            )
            public, truth, equals, public_diagnostic_complete, truth_read = (
                _truth_diagnostic(
                    root=root,
                    capsule=capsule,
                    config=config,
                    baseline=baseline,
                    native=native,
                )
            )
            classification, metrics = classify_scaling(
                native,
                public_model_verified=public,
                billed_conflicts=ledger["billed_conflicts"],
            )
            runtime = _terminal_runtime_resources(
                started=started,
                cpu_started=cpu_started,
                child_started=child_started,
            )
            result = {
                "schema": RESULT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "started_at": started_at,
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "source_commit": source_commit,
                "classification": classification,
                "capsule": capsule_relative.as_posix(),
                "resource_fix_provenance": {
                    "source_attempt": "O1C-0063",
                    "terminal_result_sha256": O1C63_RESULT_SHA256,
                    "terminal_manifest_sha256": O1C63_MANIFEST_SHA256,
                    "native_failure_sha256": O1C63_NATIVE_FAILURE_SHA256,
                    "new_attempt_not_retry": True,
                    "o1c63_retry_authorized": False,
                    "o1c63_native_calls_consumed": 1,
                    "resource_fix_binding_sha256": sha256_file(
                        capsule / "resource_fix_provenance.json"
                    ),
                },
                "claim_boundary": {
                    "consumed_positive_apple8": True,
                    "new_attempt_not_o1c63_retry": True,
                    "o1c63_terminal_provenance_bound": True,
                    "o1c63_writes": 0,
                    "same_full256_science_as_o1c63": True,
                    "native_solver_calls": 1,
                    "new_score_arms": 0,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "public_model_diagnostic_complete": (public_diagnostic_complete),
                    "truth_key_bytes_read_after_public_diagnostic": truth_read,
                    "public_collision_counts_as_exact_recovery": True,
                    "different_budget_work_is_matched": False,
                    "comparison_is_contextual_scaling_only": True,
                    "classification_uses_emitted_trail_prune_lower_bound": True,
                },
                "native": {
                    "schema": native.raw.get("schema"),
                    "implementation_parent_schema": native.raw.get(
                        "implementation_parent_schema"
                    ),
                    "status": native.status,
                    "post_solve_state": native.raw.get("post_solve_state"),
                    "post_solve_state_name": native.raw.get("post_solve_state_name"),
                    "teardown_rule": native.raw.get("teardown_rule"),
                    "pending_backtrack_rule": native.raw.get("pending_backtrack_rule"),
                    "native_result_sha256": sha256_file(capsule / "native_result.json"),
                },
                "conflict_ledger": {
                    "schema": SOFT_CONFLICT_LEDGER_SCHEMA,
                    **ledger,
                },
                "metrics": {
                    **metrics,
                    "native_status": {0: "UNKNOWN", 10: "SAT"}[native.status],
                    "native_model_sha256": None
                    if native.key_model is None
                    else hashlib.sha256(native.key_model).hexdigest(),
                    "public_model_verified_8_of_8": public,
                    "native_model_equals_committed_truth": equals,
                    "truth_key_sha256": None
                    if truth is None
                    else hashlib.sha256(truth).hexdigest(),
                },
                "resources": {
                    **runtime,
                    "native_solver_calls": 1,
                    "requested_conflicts": ledger["requested_conflicts"],
                    "billed_conflicts": ledger["billed_conflicts"],
                    "conflict_limit_overshoot": ledger["conflict_limit_overshoot"],
                    "native_wall_seconds": int(native.resources["wall_microseconds"])
                    / 1_000_000.0,
                    "native_peak_rss_bytes": native.resources["peak_rss_bytes"],
                    "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
                    "native_timeout_seconds": NATIVE_TIMEOUT_SECONDS,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "MPS_or_GPU": False,
                    "persistent_artifact_bytes": 0,
                },
                "preflight": preflight_row,
                "next_action": (
                    "Promote only exact public recovery or sustained scaling; "
                    "retain active-sublinear and regression as contextual "
                    "breadcrumbs without calling unequal-budget work matched."
                ),
            }
        except Exception as exc:
            public_diagnostic_complete = (
                capsule / "public_model_diagnostic.json"
            ).is_file()
            truth_read = (capsule / "truth_access_intent.json").is_file()
            native_result_path = capsule / "native_result.json"
            native_result_preserved = native_result_path.is_file()
            try:
                native_result_sha256 = (
                    sha256_file(native_result_path) if native_result_preserved else None
                )
            except Exception as hash_exc:
                native_result_sha256 = None
                native_result_hash_failure: dict[str, object] | None = {
                    "type": type(hash_exc).__qualname__,
                    "message": str(hash_exc),
                    "chain": _exception_chain(hash_exc),
                }
            else:
                native_result_hash_failure = None
            failure = {
                "classification": (
                    "O1C64_OPERATIONAL_POST_NATIVE_FAILURE_NO_SCIENCE_RESULT"
                ),
                "error_type": type(exc).__qualname__,
                "error_message": str(exc),
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "native_calls_consumed": 1,
                "native_result_preserved": native_result_preserved,
                "native_result_sha256": native_result_sha256,
                "native_result_hash_failure": native_result_hash_failure,
                "native_result_inline_if_sidecar_missing": (
                    None if native_result_preserved else _json_lossless(native.raw)
                ),
                "retry_authorized": False,
                "public_model_diagnostic_complete": public_diagnostic_complete,
                "truth_key_bytes_read": truth_read,
            }
            _persist_failure_evidence(capsule / "post_native_failure.json", failure)
            runtime = _terminal_runtime_resources(
                started=started,
                cpu_started=cpu_started,
                child_started=child_started,
            )
            result = _failure_result(
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                failure=failure,
                solver_calls=1,
                runtime_resources=runtime,
                truth_read=truth_read,
            )
        return _finalize_consumed_call_terminally(
            capsule=capsule,
            authoritative_result=authoritative,
            result=result,
            maximum_persistent_bytes=cast(
                int, budgets["maximum_persistent_artifact_bytes"]
            ),
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            runtime_resources=runtime,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = preflight(args.config) if args.command == "preflight" else run(args.config)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "APPLE8_CAPSULE_RELATIVE",
    "APPLE8_RESULT_RELATIVE",
    "ATTEMPT_ID",
    "CAPSULE_SUFFIX",
    "CONFLICT_LIMIT",
    "DARWIN_WATCHDOG_GUARD_BYTES",
    "DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES",
    "EXPECTED_NATIVE_EXECUTABLE_SHA256",
    "EXPECTED_NATIVE_SOURCE_SHA256",
    "MAXIMUM_BILLED_CONFLICTS",
    "MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "MEMORY_LIMIT_BYTES",
    "NATIVE_EXECUTION_FAILURE_SCHEMA",
    "NATIVE_TIMEOUT_SECONDS",
    "O1C63_CAPSULE_RELATIVE",
    "O1C63_MANIFEST_SHA256",
    "O1C63_NATIVE_FAILURE_SHA256",
    "O1C63_RESULT_RELATIVE",
    "O1C63_RESULT_SHA256",
    "O1C64RunError",
    "RESULT_RELATIVE",
    "SOFT_CONFLICT_LEDGER_SCHEMA",
    "SUSTAINED_SCALING_MINIMUM_PRUNES",
    "THRESHOLD",
    "_finalize_consumed_call_terminally",
    "classify_scaling",
    "finalize_capsule",
    "invoke_native_once",
    "invoke_native_once_terminal",
    "load_config",
    "native_failure_telemetry",
    "preflight",
    "public_model_then_truth_diagnostic",
    "run",
    "validate_apple8_baseline",
    "validate_native_build_identity",
    "validate_native_resource_ledger",
    "validate_o1c63_resource_fix_provenance",
]
