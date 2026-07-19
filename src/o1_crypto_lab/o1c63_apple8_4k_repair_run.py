"""O1C-0063: one fix-forward APPLE8 4K call after O1C-0062 teardown failure."""

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

from . import o1c62_apple8_4k_run as _o1c62
from .chacha_trace import chacha20_blocks
from .full256_broker import verify_reveal
from .joint_score_sieve import JointScoreSieveResult
from .joint_score_sieve_v5 import (
    JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA,
    JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS,
    JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE,
    JOINT_SCORE_SIEVE_RESULT_SCHEMA as NATIVE_RESULT_SCHEMA,
    JOINT_SCORE_SIEVE_TEARDOWN_RULE,
    build_native_joint_score_sieve,
    run_joint_score_sieve,
    validate_native_lifecycle,
    validate_soft_conflict_ledger,
)
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


ATTEMPT_ID = "O1C-0063"
CONFIG_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-repair-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-repair-preflight-v1"
INTENT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-repair-native-call-intent-v1"
RESULT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-repair-result-v1"
CAPSULE_SUFFIX = "O1C-0063_apple8-crossblock-consequence-sieve-4k-repair-v1"
RESULT_RELATIVE = Path(
    "research/O1C0063_APPLE8_CROSSBLOCK_SIEVE_4K_REPAIR_RESULT_20260719.json"
)

APPLE8_RESULT_RELATIVE = _o1c62.APPLE8_RESULT_RELATIVE
APPLE8_CAPSULE_RELATIVE = _o1c62.APPLE8_CAPSULE_RELATIVE
APPLE8_CNF_RELATIVE = _o1c62.APPLE8_CNF_RELATIVE
APPLE8_POTENTIAL_RELATIVE = _o1c62.APPLE8_POTENTIAL_RELATIVE
O1C57_REVEAL_RELATIVE = _o1c62.O1C57_REVEAL_RELATIVE
O1C62_RESULT_RELATIVE = Path(
    "research/O1C0062_APPLE8_CROSSBLOCK_SIEVE_4K_RESULT_20260719.json"
)
O1C62_CAPSULE_RELATIVE = Path(
    "runs/20260719_102136_O1C-0062_apple8-crossblock-consequence-sieve-4k-v1"
)

CONFLICT_LIMIT = JOINT_SCORE_SIEVE_MAXIMUM_REQUESTED_CONFLICTS
MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = JOINT_SCORE_SIEVE_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
MAXIMUM_BILLED_CONFLICTS = JOINT_SCORE_SIEVE_MAXIMUM_BILLED_CONFLICTS
NATIVE_TIMEOUT_SECONDS = 30.0
MEMORY_LIMIT_BYTES = 805_306_368
NATIVE_EXECUTABLE_SHA256 = (
    "a87044336c3ad137d42405ea3db20795c4b8a2fc65d977a59235cb2ab47ae467"
)
NATIVE_SOURCE_SHA256 = (
    "8b479aa421b93fce4376ceb291fea175528f9ab6ab4f2ccc9377563357e9cf04"
)
THRESHOLD = 14.606178797892962
APPLE512_TRAIL_PRUNES = 6
APPLE512_BILLED_CONFLICTS = 513
APPLE512_DECISIONS = 4_471
APPLE512_MINIMUM_UPPER_BOUND = 13.197930778790159
SUSTAINED_SCALING_MINIMUM_PRUNES = 24
MAXIMUM_NATIVE_FAILURE_STREAM_BYTES = 1_048_576
SOFT_CONFLICT_LEDGER_SCHEMA = JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
IMPLEMENTATION_PARENT_SCHEMA = JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
TEARDOWN_RULE = JOINT_SCORE_SIEVE_TEARDOWN_RULE
PENDING_BACKTRACK_RULE = JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE

O1C62_RESULT_SHA256 = "918d585878e667e94f31f042366b5f2d779bf4689a6a024160a5cc5997a27726"
O1C62_MANIFEST_SHA256 = (
    "2f5acb7852a14c30854da4eed8512eec101a9e4871a6ef1834088b4fb1297f0a"
)
O1C62_NATIVE_FAILURE_SHA256 = (
    "273503c9aeff43c6959649610e25c7fc3dd9862c0d8f22cb882e438f422e0ef8"
)

SOURCE_NAMES = (
    "runner",
    "repair_parent_runner",
    "repair_parent_adapter_4k",
    "joint_score_sieve_v5",
    "joint_score_sieve_v3",
    "joint_score_sieve_v2",
    "joint_score_sieve_base",
    "native_source",
    "native_base_source",
    "native_v2_conceptual_parent",
    "o1c59_lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
)
FROZEN_APPLE8_SHA256 = {
    "authoritative_result": "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be",
    "manifest": "751b89019d1f65b8180b15eafbb4bdf45c6080b0894c50567ee63eff15405a69",
    "capsule_result": "21c2170225a814bf715b6a4332bd88210fca7cbb4c6db21237becbfdd85795be",
    "native_result": "2cbd354b2d39d7c80206c6f3fb06ed4583d4b7c8436334f76ccaa1feaac5ab20",
    "preflight": "c0456e495d340fe8f08569ffc511608db976c0702988101ceaf946b668cc5880",
    "native_build": "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a",
    "truth_reveal": "63706f65c9e355711621e2188494514d1c201306d2b6a5c6928833aedfd77efd",
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
    "repair_provenance",
    "input",
    "native",
    "apple512",
    "promotion",
    "budgets",
    "next_action",
}


class O1C63RunError(RuntimeError):
    """The frozen repair provenance, inputs, or one-call lifecycle differs."""


@dataclass(frozen=True)
class FrozenRepairProvenance:
    capsule: Path
    authoritative_result: Path
    result: Mapping[str, object]
    native_failure: Mapping[str, object]
    inventory: Mapping[str, str]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C63RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C63RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise O1C63RunError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return _mapping(
            json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates), field
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C63RunError(f"{field} is not valid JSON") from exc


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C63RunError(f"{field} path differs")
    path = (root / value).resolve(strict=True)
    if not path.is_relative_to(root):
        raise O1C63RunError(f"{field} escapes the lab")
    return path


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C63RunError(f"{field} hash differs")
    return value


def _assert_immutable_tree(capsule: Path, field: str) -> None:
    if not capsule.is_dir() or capsule.is_symlink():
        raise O1C63RunError(f"{field} capsule differs")
    for path in (capsule, *capsule.rglob("*")):
        if path.is_symlink() or path.stat(follow_symlinks=False).st_mode & (
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        ):
            raise O1C63RunError(f"{field} capsule is not immutable")


def _manifest_inventory(capsule: Path, expected_sha256: str) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != expected_sha256:
        raise O1C63RunError("O1C-0062 terminal manifest hash differs")
    inventory: dict[str, str] = {}
    try:
        rows = manifest.read_text("ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise O1C63RunError("O1C-0062 terminal manifest encoding differs") from exc
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
            raise O1C63RunError("O1C-0062 terminal manifest row differs")
        target = (capsule / relative_path).resolve(strict=True)
        if (
            not target.is_relative_to(capsule)
            or not target.is_file()
            or target.is_symlink()
            or sha256_file(target) != digest
        ):
            raise O1C63RunError(f"O1C-0062 terminal artifact differs: {relative}")
        inventory[relative] = digest
    observed = {
        path.relative_to(capsule).as_posix()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if observed != {*inventory, "artifacts.sha256"}:
        raise O1C63RunError("O1C-0062 terminal manifest inventory differs")
    return inventory


def _exact_config_rows() -> dict[str, object]:
    baseline_density = APPLE512_TRAIL_PRUNES * 1_000.0 / APPLE512_BILLED_CONFLICTS
    derived_gate = math.ceil(
        0.5 * baseline_density * MAXIMUM_BILLED_CONFLICTS / 1_000.0
    )
    if derived_gate != SUSTAINED_SCALING_MINIMUM_PRUNES:
        raise O1C63RunError("sustained scaling gate derivation differs")
    return {
        "repair_provenance": {
            "source_attempt": "O1C-0062",
            "terminal_result": O1C62_RESULT_RELATIVE.as_posix(),
            "terminal_capsule": O1C62_CAPSULE_RELATIVE.as_posix(),
            "authoritative_result_sha256": O1C62_RESULT_SHA256,
            "manifest_sha256": O1C62_MANIFEST_SHA256,
            "capsule_result_sha256": O1C62_RESULT_SHA256,
            "native_failure_sha256": O1C62_NATIVE_FAILURE_SHA256,
            "native_call_intent_sha256": "56da9ce9b4d1c352e7daedb783767ad0648ae87c72660c35442c52933a6ff367",
            "preflight_sha256": "76da402fe7ae1e55e7cb555a8ff172677e8762023f3b3417cffb24703eb7718f",
            "native_build_sha256": "03eecfdb8fb61322db90b5fa80046e255b5c325ff5b9877d63e37b05a9bc0b3a",
            "config_sha256": "58645558076a72cbec42e6c51afef28709f8fdf5d1de8d95fba7a1ca4d8d74ad",
            "terminal_classification": "O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
            "native_failure_classification": "O1C62_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "source_commit": "dd5e1395d3c1ef04f2118d9123fd4ae4a93d3c48",
            "native_calls_consumed": 1,
            "validated_science_result": False,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
            "new_attempt_not_retry": True,
            "predecessor_reads_for_provenance_only": True,
            "predecessor_writes": 0,
            "diagnosis": "a solve exception was masked by invalid external-propagator disconnect during unwinding",
            "repair": "destroy the connected solver before its external propagator without explicit disconnect, and retain valid pending no-goods while backtrack unwinds the trail and refreshes the factor cache before deferring a new bound",
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
            "executable_sha256": NATIVE_EXECUTABLE_SHA256,
            "implementation_parent_schema": IMPLEMENTATION_PARENT_SCHEMA,
            "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
            "repair_scope": "connected-propagator-destruction-and-pending-no-good-backtrack-lifecycle",
        },
        "apple512": {
            "trail_threshold_prunes": APPLE512_TRAIL_PRUNES,
            "billed_conflicts": APPLE512_BILLED_CONFLICTS,
            "decisions": APPLE512_DECISIONS,
            "minimum_upper_bound": APPLE512_MINIMUM_UPPER_BOUND,
            "prune_density_per_1000_billed": baseline_density,
        },
        "promotion": {
            "exact_recovery": "SAT with a present model publicly verified on 8/8 blocks",
            "sustained_scaling_minimum_emitted_trail_prune_lower_bound": SUSTAINED_SCALING_MINIMUM_PRUNES,
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
        raise O1C63RunError("config escapes the lab")
    config = dict(_read_mapping(config_path, "O1C63 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-crossblock-consequence-sieve-4k-repair-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or dict(frozen) != FROZEN_APPLE8_SHA256
        or any(
            config.get(name) != value for name, value in _exact_config_rows().items()
        )
    ):
        raise O1C63RunError("frozen O1C-0063 config differs")
    for name in SOURCE_NAMES:
        source_path = _relative(root, source[name], f"source.{name}")
        if sha256_file(source_path) != _sha256(expected[name], f"source.{name}"):
            raise O1C63RunError(f"source hash differs for {name}")
    return config


def validate_apple8_baseline(
    root: Path, config: Mapping[str, object]
) -> _o1c62.FrozenApple8:
    """Validate the exact positive APPLE8 input inherited by O1C-0062."""

    try:
        return _o1c62.validate_apple8_baseline(root, config)
    except Exception as exc:
        raise O1C63RunError("frozen positive APPLE8 input differs") from exc


def validate_o1c62_repair_provenance(
    root: Path, config: Mapping[str, object]
) -> FrozenRepairProvenance:
    """Bind the immutable failed O1C-0062 call without treating it as retriable."""

    provenance = _mapping(config.get("repair_provenance"), "repair_provenance")
    authoritative = _relative(
        root, provenance.get("terminal_result"), "O1C62 terminal result"
    )
    capsule = _relative(
        root, provenance.get("terminal_capsule"), "O1C62 terminal capsule"
    )
    if (
        authoritative != root / O1C62_RESULT_RELATIVE
        or capsule != root / O1C62_CAPSULE_RELATIVE
    ):
        raise O1C63RunError("O1C-0062 repair provenance path differs")
    _assert_immutable_tree(capsule, "O1C-0062 terminal")
    inventory = _manifest_inventory(
        capsule, _sha256(provenance.get("manifest_sha256"), "O1C62 manifest")
    )
    required = {
        "result.json": provenance.get("capsule_result_sha256"),
        "native_failure.json": provenance.get("native_failure_sha256"),
        "native_call_intent.json": provenance.get("native_call_intent_sha256"),
        "preflight.json": provenance.get("preflight_sha256"),
        "native_build.json": provenance.get("native_build_sha256"),
        "config.json": provenance.get("config_sha256"),
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C63RunError("O1C-0062 repair provenance manifest binding differs")
    expected_result = _sha256(
        provenance.get("authoritative_result_sha256"), "O1C62 result"
    )
    capsule_result = capsule / "result.json"
    if (
        expected_result != O1C62_RESULT_SHA256
        or provenance.get("capsule_result_sha256") != expected_result
        or sha256_file(authoritative) != expected_result
        or sha256_file(capsule_result) != expected_result
        or authoritative.read_bytes() != capsule_result.read_bytes()
    ):
        raise O1C63RunError("O1C-0062 terminal result mirror differs")
    result = _read_mapping(authoritative, "O1C62 terminal result")
    claim = _mapping(result.get("claim_boundary"), "O1C62 claim boundary")
    failure = _mapping(result.get("operational_failure"), "O1C62 failure")
    resources = _mapping(result.get("resources"), "O1C62 resources")
    native_failure = _read_mapping(
        capsule / "native_failure.json", "O1C62 native failure"
    )
    if (
        result.get("schema") != _o1c62.RESULT_SCHEMA
        or result.get("attempt_id") != "O1C-0062"
        or result.get("classification") != "O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT"
        or result.get("capsule") != O1C62_CAPSULE_RELATIVE.as_posix()
        or result.get("source_commit") != provenance.get("source_commit")
        or claim.get("native_solver_calls") != 1
        or claim.get("retry_authorized") is not False
        or claim.get("validated_science_result") is not False
        or claim.get("truth_key_bytes_read_after_public_diagnostic") is not False
        or failure.get("classification")
        != "O1C62_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT"
        or failure.get("error_type") != "O1RelationalSearchError"
        or "disconnect_external_propagator" not in str(failure.get("error_message"))
        or failure.get("occurred_after_persisted_intent") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("retry_authorized") is not False
        or failure.get("truth_key_bytes_read") is not False
        or dict(native_failure) != dict(failure)
        or resources.get("native_solver_calls") != 1
        or resources.get("requested_conflicts") != CONFLICT_LIMIT
        or resources.get("maximum_billed_conflicts") != MAXIMUM_BILLED_CONFLICTS
        or resources.get("billed_conflicts") is not None
    ):
        raise O1C63RunError("O1C-0062 terminal operational semantics differ")
    preflight_row = _read_mapping(capsule / "preflight.json", "O1C62 preflight")
    intent = _read_mapping(capsule / "native_call_intent.json", "O1C62 intent")
    native_build = _read_mapping(capsule / "native_build.json", "O1C62 build")
    predecessor_config = _read_mapping(capsule / "config.json", "O1C62 config")
    if (
        preflight_row.get("ready_for_science") is not True
        or preflight_row.get("source_commit_bound") is not True
        or preflight_row.get("native_solver_calls") != 0
        or preflight_row.get("truth_key_bytes_read") is not False
        or intent.get("attempt_id") != "O1C-0062"
        or intent.get("calls_before") != 0
        or intent.get("calls_authorized") != 1
        or intent.get("requested_conflicts") != CONFLICT_LIMIT
        or intent.get("maximum_billed_conflicts") != MAXIMUM_BILLED_CONFLICTS
        or intent.get("seed") != 0
        or intent.get("timeout_seconds") != NATIVE_TIMEOUT_SECONDS
        or intent.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or intent.get("threshold") != THRESHOLD
        or intent.get("truth_key_reads") != 0
        or native_build.get("source_sha256")
        != "c9ddc07d8d5ae22852ad7302ba9f8888cc86d3c04cf5fabf8c79a9eb8b28e91b"
        or predecessor_config.get("attempt_id") != "O1C-0062"
    ):
        raise O1C63RunError("O1C-0062 persisted repair evidence differs")
    return FrozenRepairProvenance(
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
    repair = validate_o1c62_repair_provenance(root, config)
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
        raise O1C63RunError("memory-pressure preflight is below frozen gate")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "new_attempt_not_o1c62_retry": True,
        "o1c62_terminal_result_sha256": sha256_file(repair.authoritative_result),
        "o1c62_terminal_manifest_sha256": sha256_file(
            repair.capsule / "artifacts.sha256"
        ),
        "o1c62_native_calls_consumed": 1,
        "o1c62_validated_science_result": False,
        "o1c62_retry_authorized": False,
        "o1c62_writes": 0,
        "apple8_capsule": baseline.capsule.relative_to(root).as_posix(),
        "apple8_result_sha256": sha256_file(baseline.authoritative_result),
        "apple8_manifest_sha256": sha256_file(baseline.capsule / "artifacts.sha256"),
        "cnf_sha256": sha256_file(baseline.cnf),
        "potential_sha256": sha256_file(baseline.potential),
        "threshold": THRESHOLD,
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
        "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
        "teardown_rule": TEARDOWN_RULE,
        "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
        "native_solver_calls": 0,
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "truth_key_bytes_read": False,
        "files_written": 0,
        "memory_pressure_free_percent": memory_free,
    }


def invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> JointScoreSieveResult:
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


def _stream_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogatepass")
    return None


def _json_safe(value: object) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, bytes):
        return {
            "encoding": "hex",
            "bytes": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return repr(value)


def _structured_exception_telemetry(exc: Exception) -> dict[str, object]:
    structured: dict[str, object] = {}
    for name in ("telemetry", "failure_telemetry", "native_failure"):
        value = getattr(exc, name, None)
        if isinstance(value, Mapping):
            structured[name] = cast(dict[str, object], _json_safe(value))
    describe = getattr(exc, "describe", None)
    if callable(describe):
        try:
            described = describe()
        except Exception as describe_error:
            structured["describe_error"] = type(describe_error).__name__
        else:
            if isinstance(described, Mapping):
                structured["describe"] = cast(dict[str, object], _json_safe(described))
    for name in (
        "phase",
        "timed_out",
        "watchdog_fired",
        "memory_limit_exceeded",
        "command",
    ):
        value = getattr(exc, name, None)
        if value is not None:
            structured[name] = _json_safe(value)
    return structured


def _failure_stream(
    *,
    directory: Path | None,
    name: str,
    payload: bytes | None,
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
    if directory is not None:
        _atomic_bytes(directory / artifact, bounded)
    return {
        "present": True,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "artifact": artifact if directory is not None else None,
        "persisted_bytes": len(bounded),
        "persisted_sha256": hashlib.sha256(bounded).hexdigest(),
        "truncated": len(bounded) != len(payload),
    }


def native_failure_telemetry(
    exc: Exception, *, directory: Path | None = None
) -> dict[str, object]:
    """Preserve structured v5 process evidence and bounded raw streams."""

    structured = _structured_exception_telemetry(exc)
    telemetry_candidates = [
        value
        for value in (
            getattr(exc, "telemetry", None),
            getattr(exc, "failure_telemetry", None),
            getattr(exc, "native_failure", None),
        )
        if isinstance(value, Mapping)
    ]

    def candidate(name: str) -> object:
        direct = getattr(exc, name, None)
        if direct is not None:
            return direct
        for row in telemetry_candidates:
            if name in row:
                return row[name]
        return None

    raw_returncode = candidate("returncode")
    returncode = (
        raw_returncode
        if isinstance(raw_returncode, int) and not isinstance(raw_returncode, bool)
        else None
    )
    raw_signal = candidate("signal")
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
    stdout = _stream_bytes(candidate("stdout"))
    stderr = _stream_bytes(candidate("stderr"))
    return {
        "schema": "o1-256-native-failure-telemetry-v1",
        "returncode": returncode,
        "signal_number": signal_number,
        "signal_name": signal_name,
        "stdout": _failure_stream(directory=directory, name="stdout", payload=stdout),
        "stderr": _failure_stream(directory=directory, name="stderr", payload=stderr),
        "structured": structured,
    }


def invoke_native_once_terminal(
    *, failure_directory: Path | None = None, **kwargs: object
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    try:
        return invoke_native_once(**kwargs), None  # type: ignore[arg-type]
    except Exception as exc:
        try:
            telemetry = native_failure_telemetry(exc, directory=failure_directory)
        except Exception as telemetry_error:
            telemetry = {
                "schema": "o1-256-native-failure-telemetry-v1",
                "capture_error_type": type(telemetry_error).__name__,
                "capture_error_message": str(telemetry_error),
                "returncode": None,
                "signal_number": None,
                "signal_name": None,
                "stdout": None,
                "stderr": None,
                "structured": {},
            }
        return None, {
            "classification": "O1C63_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
            "native_failure_telemetry": telemetry,
        }


def validate_native_resource_ledger(
    native: JointScoreSieveResult, *, solver_calls: int
) -> dict[str, int]:
    try:
        validate_native_lifecycle(native.raw)
        ledger = validate_soft_conflict_ledger(native.stats)
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
            raise O1C63RunError("O1C-0063 native resource ledger differs")
    except O1C63RunError:
        raise
    except (
        O1RelationalSearchError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
    ) as exc:
        raise O1C63RunError("O1C-0063 native lifecycle or ledger differs") from exc
    return ledger


def validate_native_build_identity(native_build: NativeGuidedSearchBuild) -> None:
    """Authorize the exact compiled bytes before the one-call intent exists."""

    if (
        not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.source_sha256 != NATIVE_SOURCE_SHA256
        or native_build.executable_sha256 != NATIVE_EXECUTABLE_SHA256
    ):
        raise O1C63RunError("native-v4 build identity differs")


def public_model_then_truth_diagnostic(
    native: JointScoreSieveResult,
    *,
    verify_public_model: Callable[[bytes], bool],
    read_truth_key: Callable[[], bytes],
    public_diagnostic_ledger: list[bool],
) -> tuple[bool, bytes | None, bool | None]:
    """Read truth only after a present native model verifies on all public blocks."""

    if public_diagnostic_ledger != [False]:
        raise O1C63RunError("public diagnostic ledger differs")
    if native.key_model is None:
        public_diagnostic_ledger[0] = True
        if native.status == 10:
            raise O1C63RunError("SAT result lacks a native key model")
        return False, None, None
    try:
        public_verified = bool(verify_public_model(native.key_model))
    finally:
        public_diagnostic_ledger[0] = True
    if not public_verified:
        raise O1C63RunError("native model fails eight public blocks")
    truth = read_truth_key()
    if not isinstance(truth, bytes) or len(truth) != 32:
        raise O1C63RunError("post-native truth key differs")
    return True, truth, native.key_model == truth


def classify_scaling(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    billed_conflicts: int,
) -> tuple[str, dict[str, object]]:
    if native.status == 20:
        raise O1C63RunError("UNSAT contradicts the frozen satisfiable public target")
    if native.status not in (0, 10):
        raise O1C63RunError("native status differs")
    try:
        queued_trail_prunes = int(cast(int, native.sieve["trail_threshold_prunes"]))
        queued_total = int(cast(int, native.sieve["external_clauses_queued"]))
        emitted_total = int(cast(int, native.sieve["external_clauses_emitted"]))
        model_prunes = int(cast(int, native.sieve["model_threshold_prunes"]))
        threshold_prunes = int(cast(int, native.sieve["threshold_prunes"]))
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise O1C63RunError("native prune emission ledger differs") from exc
    pending = queued_total - emitted_total
    if (
        min(
            queued_trail_prunes,
            queued_total,
            emitted_total,
            model_prunes,
            threshold_prunes,
        )
        < 0
        or pending not in (0, 1)
        or threshold_prunes != queued_trail_prunes + model_prunes
        or queued_total != threshold_prunes
    ):
        raise O1C63RunError("native prune emission ledger differs")
    emitted_trail_lower_bound = max(0, queued_trail_prunes - pending)
    if native.status == 10:
        if native.key_model is None or not public_model_verified:
            raise O1C63RunError("SAT result lacks a publicly verified key model")
        classification = "O1C63_EXACT_PUBLIC_FULL256_RECOVERY"
    elif public_model_verified or native.key_model is not None:
        raise O1C63RunError("non-SAT result contains a key model")
    elif emitted_trail_lower_bound >= SUSTAINED_SCALING_MINIMUM_PRUNES:
        classification = "O1C63_APPLE8_4K_REPAIR_SUSTAINED_SCALING"
    elif emitted_trail_lower_bound > 0:
        classification = "O1C63_APPLE8_4K_REPAIR_ACTIVE_SUBLINEAR"
    else:
        classification = "O1C63_APPLE8_4K_REPAIR_SCALING_REGRESSION"
    decisions = int(cast(int, native.stats["decisions"]))
    minimum_upper = float(cast(float, native.sieve["minimum_upper_bound"]))
    if billed_conflicts <= 0 or not math.isfinite(minimum_upper):
        raise O1C63RunError("O1C-0063 contextual metric differs")
    baseline_density = APPLE512_TRAIL_PRUNES * 1_000.0 / APPLE512_BILLED_CONFLICTS
    density = emitted_trail_lower_bound * 1_000.0 / billed_conflicts
    decisions_density = decisions * 1_000.0 / billed_conflicts
    return classification, {
        "public_model_verified": public_model_verified,
        "safe_trail_threshold_prunes": emitted_trail_lower_bound,
        "queued_certified_trail_no_goods": queued_trail_prunes,
        "external_clauses_queued": queued_total,
        "external_clauses_emitted": emitted_total,
        "pending_exact_no_good_count": pending,
        "emitted_certified_trail_prune_lower_bound": emitted_trail_lower_bound,
        "emitted_prune_lower_bound_density_per_1000_billed": density,
        "prune_density_per_1000_billed": density,
        "decisions": decisions,
        "decisions_per_1000_billed": decisions_density,
        "minimum_upper_bound": minimum_upper,
        "apple512": {
            "safe_trail_threshold_prunes": APPLE512_TRAIL_PRUNES,
            "emitted_certified_trail_prune_lower_bound": APPLE512_TRAIL_PRUNES,
            "pending_exact_no_good_count": 0,
            "billed_conflicts": APPLE512_BILLED_CONFLICTS,
            "prune_density_per_1000_billed": baseline_density,
            "decisions": APPLE512_DECISIONS,
            "decisions_per_1000_billed": APPLE512_DECISIONS
            * 1_000.0
            / APPLE512_BILLED_CONFLICTS,
            "minimum_upper_bound": APPLE512_MINIMUM_UPPER_BOUND,
        },
        "contextual_deltas": {
            "prune_density_per_1000_billed": density - baseline_density,
            "decisions_per_1000_billed": decisions_density
            - APPLE512_DECISIONS * 1_000.0 / APPLE512_BILLED_CONFLICTS,
            "minimum_upper_bound": minimum_upper - APPLE512_MINIMUM_UPPER_BOUND,
        },
        "promotion": {
            "exact_recovery": public_model_verified and native.status == 10,
            "minimum_safe_trail_prunes": SUSTAINED_SCALING_MINIMUM_PRUNES,
            "sustained_scaling": not public_model_verified
            and emitted_trail_lower_bound >= SUSTAINED_SCALING_MINIMUM_PRUNES,
            "active_sublinear": not public_model_verified
            and 1 <= emitted_trail_lower_bound <= 23,
            "regression": not public_model_verified and emitted_trail_lower_bound == 0,
        },
        "different_budget_work_is_matched": False,
    }


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
        raise O1C63RunError(f"{field} recovery ownership differs")
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
        "# O1C Run O1C-0063\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native calls: `{resources['native_solver_calls']}`\n"
        f"- Requested conflicts: `{resources['requested_conflicts']}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n\n"
        "This is a new fix-forward attempt after O1C-0062's immutable terminal "
        "operational failure, not a retry of O1C-0062. It freezes the same "
        "positive APPLE-VIEW-0008 input and changes two native correctness "
        "boundaries: exception-safe teardown and pending-no-good backtrack "
        "handling. All scientific inputs remain unchanged. Apple512 comparison "
        "remains contextual, never matched-work.\n"
    )


def finalize_capsule(
    *,
    capsule: Path,
    authoritative_result: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
    _after_capsule_seal: Callable[[], None] | None = None,
) -> None:
    if (capsule / "artifacts.sha256").exists() or authoritative_result.exists():
        raise O1C63RunError("O1C-0063 terminal output already exists")
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
        raise O1C63RunError("O1C-0063 persistent byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C63RunError("O1C-0063 persistent byte budget exceeded")
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
            raise O1C63RunError("O1C-0063 publication bytes differ")
        _assert_immutable_tree(capsule, "O1C-0063 terminal")
    except Exception:
        _restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _unlink_owned_exact(manifest_path, manifest, "O1C63 manifest")
        if authoritative_published:
            _unlink_owned_exact(
                authoritative_result, result_payload, "O1C63 authoritative result"
            )
        raise


def _truth_diagnostic(
    *,
    root: Path,
    capsule: Path,
    config: Mapping[str, object],
    baseline: _o1c62.FrozenApple8,
    native: JointScoreSieveResult,
) -> tuple[bool, bytes | None, bool | None, bool, bool]:
    public_ledger = [False]
    truth_ledger = [False]
    counters = tuple(
        cast(int, value)
        for value in _sequence(baseline.public_preflight["counters"], "counters")
    )
    outputs = tuple(
        bytes.fromhex(str(value))
        for value in _sequence(
            baseline.public_preflight["output_blocks_hex"], "outputs"
        )
    )
    nonce = bytes.fromhex(str(baseline.public_preflight["nonce_hex"]))

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
                "reason": "diagnose-present-publicly-verified-8-of-8-model-only",
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
            raise O1C63RunError("truth reveal hash differs")
        reveal = verify_reveal(_read_mapping(reveal_path, "truth reveal"))
        preimage = _mapping(reveal["commitment_preimage"], "commitment preimage")
        truth = bytes.fromhex(str(preimage["key_hex"]))
        _atomic_json(
            capsule / "truth_access_receipt.json",
            {"truth_key_sha256": hashlib.sha256(truth).hexdigest()},
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
                "present": False,
                "public_verified_8_of_8": False,
                "truth_key_bytes_read": False,
            },
        )
    return public, truth, equals, public_ledger[0], truth_ledger[0]


def _repair_binding_row(
    *, root: Path, repair: FrozenRepairProvenance, config: Mapping[str, object]
) -> dict[str, object]:
    provenance = _mapping(config["repair_provenance"], "repair_provenance")
    return {
        "schema": "o1-256-o1c62-terminal-repair-provenance-v1",
        "source_attempt": "O1C-0062",
        "terminal_result": repair.authoritative_result.relative_to(root).as_posix(),
        "terminal_capsule": repair.capsule.relative_to(root).as_posix(),
        "terminal_result_sha256": sha256_file(repair.authoritative_result),
        "terminal_manifest_sha256": sha256_file(repair.capsule / "artifacts.sha256"),
        "native_failure_sha256": sha256_file(repair.capsule / "native_failure.json"),
        "terminal_classification": repair.result["classification"],
        "native_failure_classification": repair.native_failure["classification"],
        "native_calls_consumed": 1,
        "validated_science_result": False,
        "truth_key_bytes_read": False,
        "retry_authorized": False,
        "new_attempt_not_retry": True,
        "predecessor_writes": 0,
        "diagnosis": provenance["diagnosis"],
        "repair": provenance["repair"],
        "teardown_rule": TEARDOWN_RULE,
        "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
    }


def _failure_result(
    *,
    capsule_relative: Path,
    source_commit: str,
    preflight_row: Mapping[str, object],
    failure: Mapping[str, object],
    solver_calls: int,
    truth_read: bool = False,
) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": "O1C63_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
        "capsule": capsule_relative.as_posix(),
        "repair_provenance": {
            "source_attempt": "O1C-0062",
            "terminal_result_sha256": O1C62_RESULT_SHA256,
            "terminal_manifest_sha256": O1C62_MANIFEST_SHA256,
            "new_attempt_not_retry": True,
            "o1c62_retry_authorized": False,
            "o1c62_native_calls_consumed": 1,
        },
        "claim_boundary": {
            "native_solver_calls": solver_calls,
            "retry_authorized": False,
            "validated_science_result": False,
            "new_attempt_not_o1c62_retry": True,
            "o1c62_terminal_provenance_bound": True,
            "o1c62_writes": 0,
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
            "native_solver_calls": solver_calls,
            "requested_conflicts": CONFLICT_LIMIT,
            "billed_conflicts": None,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight_row),
        "next_action": (
            "Do not retry O1C-0062 or O1C-0063; diagnose this immutable "
            "O1C-0063 terminal capsule under a new attempt ID."
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
    _after_capsule_seal: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Publish once, or recover that publication into one terminal failure."""

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
            "classification": "O1C63_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "native_calls_consumed": 1,
            "publication_recovered": True,
            "retry_authorized": False,
            "truth_key_bytes_read": truth_read,
        }
        _atomic_json(capsule / "publication_failure.json", failure)
        terminal = _failure_result(
            capsule_relative=capsule_relative,
            source_commit=source_commit,
            preflight_row=preflight_row,
            failure=failure,
            solver_calls=1,
            truth_read=truth_read,
        )
        finalize_capsule(
            capsule=capsule,
            authoritative_result=authoritative_result,
            result=terminal,
            maximum_persistent_bytes=maximum_persistent_bytes,
        )
        return terminal


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    if authoritative.exists() or tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise O1C63RunError("O1C-0063 already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = validate_apple8_baseline(root, config)
    repair = validate_o1c62_repair_provenance(root, config)
    source_commit = str(preflight_row["source_commit"])
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c63-apple8-4k-repair-") as raw:
        workspace = Path(raw)
        source = _mapping(config["source"], "source")
        native_build = build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "cadical-o1-joint-score-sieve-v4",
        )
        validate_native_build_identity(native_build)
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        _atomic_json(
            capsule / "repair_provenance.json",
            _repair_binding_row(root=root, repair=repair, config=config),
        )
        _atomic_json(
            capsule / "apple8_binding.json",
            {
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
                "o1_crypto_lab.o1c63_apple8_4k_repair_run run --config "
                f"{config_file.relative_to(root).as_posix()}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "calls_before": 0,
            "calls_authorized": 1,
            "new_attempt_not_o1c62_retry": True,
            "o1c62_retry": False,
            "o1c62_native_calls_consumed": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "threshold": THRESHOLD,
            "cnf_sha256": sha256_file(baseline.cnf),
            "potential_sha256": sha256_file(baseline.potential),
            "native_executable_sha256": native_build.executable_sha256,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
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
            _atomic_json(capsule / "native_failure.json", native_failure)
            result = _failure_result(
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                failure=native_failure,
                solver_calls=solver_calls,
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
            )
        assert native is not None
        _atomic_json(capsule / "native_result.json", native.raw)
        public_diagnostic_complete = False
        truth_read = False
        try:
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
            child = resource.getrusage(resource.RUSAGE_CHILDREN)
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
                "repair_provenance": {
                    "source_attempt": "O1C-0062",
                    "terminal_result_sha256": O1C62_RESULT_SHA256,
                    "terminal_manifest_sha256": O1C62_MANIFEST_SHA256,
                    "new_attempt_not_retry": True,
                    "o1c62_retry_authorized": False,
                    "o1c62_native_calls_consumed": 1,
                    "repair_binding_sha256": sha256_file(
                        capsule / "repair_provenance.json"
                    ),
                },
                "claim_boundary": {
                    "consumed_positive_apple8": True,
                    "new_attempt_not_o1c62_retry": True,
                    "o1c62_terminal_provenance_bound": True,
                    "o1c62_writes": 0,
                    "native_solver_calls": 1,
                    "new_score_arms": 0,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "public_model_diagnostic_complete": public_diagnostic_complete,
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
                    "elapsed_seconds": time.perf_counter() - started,
                    "parent_cpu_seconds": time.process_time() - cpu_started,
                    "child_cpu_seconds": child.ru_utime
                    + child.ru_stime
                    - child_started.ru_utime
                    - child_started.ru_stime,
                    "peak_rss_bytes": _peak_rss_bytes(),
                    "native_solver_calls": 1,
                    "requested_conflicts": ledger["requested_conflicts"],
                    "billed_conflicts": ledger["billed_conflicts"],
                    "conflict_limit_overshoot": ledger["conflict_limit_overshoot"],
                    "native_wall_seconds": int(native.resources["wall_microseconds"])
                    / 1_000_000.0,
                    "native_peak_rss_bytes": native.resources["peak_rss_bytes"],
                    "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
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
            failure = {
                "classification": "O1C63_OPERATIONAL_POST_NATIVE_FAILURE_NO_SCIENCE_RESULT",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "native_calls_consumed": 1,
                "native_result_preserved": True,
                "native_result_sha256": sha256_file(capsule / "native_result.json"),
                "retry_authorized": False,
                "public_model_diagnostic_complete": public_diagnostic_complete,
                "truth_key_bytes_read": truth_read,
            }
            _atomic_json(capsule / "post_native_failure.json", failure)
            result = _failure_result(
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                failure=failure,
                solver_calls=1,
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
    "MAXIMUM_BILLED_CONFLICTS",
    "MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "MEMORY_LIMIT_BYTES",
    "NATIVE_TIMEOUT_SECONDS",
    "O1C62_CAPSULE_RELATIVE",
    "O1C62_RESULT_RELATIVE",
    "O1C62_RESULT_SHA256",
    "O1C63RunError",
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
    "validate_native_resource_ledger",
    "validate_native_build_identity",
    "validate_o1c62_repair_provenance",
]
