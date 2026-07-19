"""O1C-0065: one matched-work APPLE8 width-6 grouped-bound call."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import stat
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence, cast

from . import joint_score_sieve_v7 as _native_v7
from . import o1c64_apple8_4k_resource_fix_run as _o1c64
from .chacha_trace import chacha20_blocks
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import (
    COMPATIBILITY_GROUPING_BOUND_RULE,
    COMPATIBILITY_GROUPING_MEMORY_RULE,
    COMPATIBILITY_GROUPING_RULE,
    JointScoreCompatibilityGrouping,
    build_compatibility_grouping,
    compatibility_grouping_diagnostics,
)
from .joint_score_sieve import JointScoreSieveResult
from .o1_relational_search import NativeGuidedSearchBuild, sha256_file
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


ATTEMPT_ID = "O1C-0065"
CONFIG_SCHEMA = "o1-256-apple8-width6-grouped-run-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-width6-grouped-run-preflight-v1"
INTENT_SCHEMA = "o1-256-apple8-width6-grouped-native-call-intent-v1"
RESULT_SCHEMA = "o1-256-apple8-width6-grouped-run-result-v1"
CAPSULE_SUFFIX = "O1C-0065_apple8-width6-grouped-sieve-v1"
RESULT_RELATIVE = Path(
    "research/O1C0065_APPLE8_WIDTH6_GROUPED_SIEVE_RESULT_20260719.json"
)

APPLE8_RESULT_RELATIVE = _o1c64.APPLE8_RESULT_RELATIVE
APPLE8_CAPSULE_RELATIVE = _o1c64.APPLE8_CAPSULE_RELATIVE
APPLE8_CNF_RELATIVE = _o1c64.APPLE8_CNF_RELATIVE
APPLE8_POTENTIAL_RELATIVE = _o1c64.APPLE8_POTENTIAL_RELATIVE
O1C57_REVEAL_RELATIVE = _o1c64.O1C57_REVEAL_RELATIVE
APPLE9_RESULT_RELATIVE = Path(
    "research/APPLE_VIEW_0009_EXACT_GROUPED_BOUND_RESULT_20260719.json"
)

# The requested work is intentionally the matched APPLE-VIEW-0008 efficacy call,
# not the later 4K resource-bound experiment.
CONFLICT_LIMIT = 512
MAXIMUM_CONFLICT_LIMIT_OVERSHOOT = 1
MAXIMUM_BILLED_CONFLICTS = 513
NATIVE_TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 1_073_741_824
THRESHOLD = 14.606178797892962
GROUPING_WIDTH_CAP = 6
EXPECTED_GROUPING_SHA256 = (
    "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
)
EXPECTED_GROUPING_SERIALIZED_BYTES = 115_700
APPLE8_TRAIL_PRUNES = 6
APPLE8_BILLED_CONFLICTS = 513
MAXIMUM_NATIVE_FAILURE_STREAM_BYTES = 1_048_576

NATIVE_RESULT_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_RESULT_SCHEMA
IMPLEMENTATION_PARENT_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
NATIVE_STATE_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_STATE_SCHEMA
SOFT_CONFLICT_LEDGER_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_CONFLICT_LEDGER_SCHEMA
NATIVE_EXECUTION_FAILURE_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_EXECUTION_FAILURE_SCHEMA
NATIVE_MEMORY_SERIES_SCHEMA = _native_v7.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
MAXIMUM_NATIVE_MEMORY_SAMPLES = _native_v7.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
JOINT_SCORE_SIEVE_DECISION_RULE = _native_v7.JOINT_SCORE_SIEVE_DECISION_RULE
TEARDOWN_RULE = _native_v7.JOINT_SCORE_SIEVE_TEARDOWN_RULE
PENDING_BACKTRACK_RULE = _native_v7.JOINT_SCORE_SIEVE_PENDING_BACKTRACK_RULE
DARWIN_WATCHDOG_GUARD_BYTES = _native_v7.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
DARWIN_WATCHDOG_INTERVAL_SECONDS = (
    _native_v7.JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
)
DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES = MEMORY_LIMIT_BYTES - DARWIN_WATCHDOG_GUARD_BYTES

# Filled from the committed source/build identity before the paid run.  These
# constants are fail-closed and are mirrored by the config.
EXPECTED_NATIVE_SOURCE_SHA256 = (
    "36d4498724c7f0c465fb1177aaa24b5cbb73cd3703cd8ad0d23a2aa1a51e4e81"
)
EXPECTED_NATIVE_EXECUTABLE_SHA256 = (
    "847a51457680ffa13472558f6bd690dede3a4e7a2b346fae6a206683e32779e7"
)

APPLE9_RESULT_SHA256 = (
    "ebbe9e308f3e3dfa00685a9c10eba6554c85e453459178a26a03b9fc6b2b3728"
)
FROZEN_APPLE8_SHA256 = dict(_o1c64.FROZEN_APPLE8_SHA256)

SOURCE_NAMES = (
    "runner",
    "joint_score_sieve_v7",
    "joint_score_grouping_v1",
    "joint_score_sieve_v6",
    "joint_score_sieve_v5",
    "joint_score_sieve_v4",
    "joint_score_sieve_base",
    "native_source",
    "native_base_source",
    "capsule_parent_runner",
    "o1c59_lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
)
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
    "grouping",
    "native",
    "apple512",
    "promotion",
    "budgets",
    "next_action",
}


class O1C65RunError(RuntimeError):
    """The frozen input, grouping, native identity, or one-call ledger differs."""


@dataclass(frozen=True)
class FrozenGrouping:
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    diagnostics: Mapping[str, object]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C65RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C65RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise O1C65RunError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return _mapping(
            json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates), field
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C65RunError(f"{field} is not valid JSON") from exc


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C65RunError(f"{field} path differs")
    try:
        path = (root / value).resolve(strict=True)
    except OSError as exc:
        raise O1C65RunError(f"{field} path differs") from exc
    if not path.is_relative_to(root):
        raise O1C65RunError(f"{field} escapes the lab")
    return path


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C65RunError(f"{field} hash differs")
    return value


def _exact_grouping_row() -> dict[str, object]:
    return {
        "width_cap": GROUPING_WIDTH_CAP,
        "expected_sha256": EXPECTED_GROUPING_SHA256,
        "serialized_bytes": EXPECTED_GROUPING_SERIALIZED_BYTES,
        "factor_count": 7_557,
        "observed_variable_count": 2_981,
        "group_count": 2_885,
        "singleton_group_count": 28,
        "pair_group_count": 1_641,
        "higher_order_group_count": 1_216,
        "maximum_group_size": 8,
        "table_rows": 176_912,
        "variable_group_incidences": 17_025,
        "raw_table_bytes": 1_415_296,
        "estimated_indexed_bytes": 1_710_776,
        "group_size_distribution": [
            [1, 28],
            [2, 1_641],
            [3, 695],
            [4, 473],
            [5, 30],
            [6, 9],
            [7, 6],
            [8, 3],
        ],
        "group_width_distribution": [[3, 24], [4, 27], [5, 159], [6, 2_675]],
        "independent_root_upper_bound": 292.30611344487517,
        "grouped_root_upper_bound": 262.68644197084643,
        "grouped_root_upper_bound_f64le_hex": "327693aafb6a7040",
        "grouping_rule": COMPATIBILITY_GROUPING_RULE,
        "bound_rule": COMPATIBILITY_GROUPING_BOUND_RULE,
        "memory_rule": COMPATIBILITY_GROUPING_MEMORY_RULE,
    }


def _exact_config_rows() -> dict[str, object]:
    return {
        "grouping_provenance": {
            "source_attempt": "APPLE-VIEW-0009",
            "result": APPLE9_RESULT_RELATIVE.as_posix(),
            "result_sha256": APPLE9_RESULT_SHA256,
            "classification": (
                "PUBLIC_EXACT_GROUPED_BOUND_STRICTLY_DOMINATES_PAIR_RELAXATION_"
                "NO_SEARCH_CLAIM"
            ),
            "native_solver_calls": 0,
            "truth_bytes_read": False,
            "native_integration_validated": False,
        },
        "input": {
            "apple8_result": APPLE8_RESULT_RELATIVE.as_posix(),
            "apple8_capsule": APPLE8_CAPSULE_RELATIVE.as_posix(),
            "cnf_relative": APPLE8_CNF_RELATIVE.as_posix(),
            "potential_relative": APPLE8_POTENTIAL_RELATIVE.as_posix(),
            "truth_reveal": O1C57_REVEAL_RELATIVE.as_posix(),
            "cnf_sha256": (
                "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432"
            ),
            "potential_sha256": (
                "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
            ),
            "threshold": THRESHOLD,
            "seed": 0,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
        },
        "grouping": _exact_grouping_row(),
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
            "state_schema": NATIVE_STATE_SCHEMA,
            "soft_conflict_ledger_schema": SOFT_CONFLICT_LEDGER_SCHEMA,
            "teardown_rule": TEARDOWN_RULE,
            "pending_backtrack_rule": PENDING_BACKTRACK_RULE,
            "execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "memory_series_schema": NATIVE_MEMORY_SERIES_SCHEMA,
            "maximum_memory_samples": MAXIMUM_NATIVE_MEMORY_SAMPLES,
            "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
            "darwin_watchdog_kill_threshold_bytes": (
                DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES
            ),
            "darwin_watchdog_poll_interval_seconds": (DARWIN_WATCHDOG_INTERVAL_SECONDS),
            "expected_source_sha256": EXPECTED_NATIVE_SOURCE_SHA256,
            "expected_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        },
        "apple512": {
            "requested_conflicts": 512,
            "billed_conflicts": APPLE8_BILLED_CONFLICTS,
            "trail_threshold_prunes": APPLE8_TRAIL_PRUNES,
            "decisions": 4_471,
            "propagations": 1_178_185,
            "minimum_upper_bound": 13.197930778790159,
            "native_wall_seconds": 0.451725,
            "native_peak_rss_bytes": 388_644_864,
        },
        "promotion": {
            "exact_recovery": "SAT with a present model publicly verified on 8/8 blocks",
            "strict_efficacy_gain": (
                ">6 emitted certified trail-prune lower bound at requested 512/"
                "billed 513 conflicts"
            ),
            "efficacy_retained": (
                "6 emitted certified trail-prune lower bound at requested 512/"
                "billed 513 conflicts"
            ),
            "efficacy_regression": (
                "0..5 emitted certified trail-prune lower bound at requested 512/"
                "billed 513 conflicts"
            ),
            "pending_rule": (
                "pending=external_clauses_queued-external_clauses_emitted in 0..1;"
                "emitted_trail_lower_bound=max(0,trail_threshold_prunes-pending)"
            ),
            "matched_requested_work": True,
            "matched_maximum_billed_work": True,
            "time_and_rss_are_contextual": True,
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
            "maximum_native_failure_stream_bytes": (
                MAXIMUM_NATIVE_FAILURE_STREAM_BYTES
            ),
            "maximum_persistent_artifact_bytes": 16_777_216,
        },
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C65RunError("config escapes the lab")
    config = dict(_read_mapping(config_path, "O1C65 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    frozen = _mapping(config.get("frozen_sha256"), "frozen_sha256")
    if (
        set(config) != CONFIG_FIELDS
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-width6-grouped-sieve-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or dict(frozen) != FROZEN_APPLE8_SHA256
        or any(
            config.get(name) != value for name, value in _exact_config_rows().items()
        )
    ):
        raise O1C65RunError("frozen O1C-0065 config differs")
    for name in SOURCE_NAMES:
        source_path = _relative(root, source[name], f"source.{name}")
        if sha256_file(source_path) != _sha256(expected[name], f"source.{name}"):
            raise O1C65RunError(f"source hash differs for {name}")
    return config


def validate_apple8_baseline(root: Path, config: Mapping[str, object]) -> object:
    try:
        return _o1c64.validate_apple8_baseline(root, config)
    except Exception as exc:
        raise O1C65RunError("frozen positive APPLE8 input differs") from exc


def validate_grouping_provenance(
    root: Path, config: Mapping[str, object]
) -> Mapping[str, object]:
    row = _mapping(config.get("grouping_provenance"), "grouping_provenance")
    result_path = _relative(root, row.get("result"), "APPLE9 result")
    if (
        result_path != root / APPLE9_RESULT_RELATIVE
        or sha256_file(result_path) != APPLE9_RESULT_SHA256
    ):
        raise O1C65RunError("APPLE-VIEW-0009 result identity differs")
    result = _read_mapping(result_path, "APPLE9 result")
    selected = _mapping(result.get("selected_width6"), "APPLE9 selected_width6")
    verification = _mapping(result.get("verification"), "APPLE9 verification")
    claim = _mapping(result.get("claim_boundary"), "APPLE9 claim boundary")
    expected = _exact_grouping_row()
    if (
        result.get("attempt_id") != "APPLE-VIEW-0009"
        or result.get("classification") != row.get("classification")
        or selected.get("width_cap") != expected["width_cap"]
        or selected.get("grouping_sha256") != expected["expected_sha256"]
        or selected.get("serialized_bytes") != expected["serialized_bytes"]
        or selected.get("group_count") != expected["group_count"]
        or selected.get("table_rows") != expected["table_rows"]
        or selected.get("grouped_root_upper_bound_f64le_hex")
        != expected["grouped_root_upper_bound_f64le_hex"]
        or verification.get("solver_calls") != 0
        or verification.get("truth_reads") != 0
        or claim.get("native_solver_integration_validated") is not False
        or claim.get("search_pruning_claim") is not False
    ):
        raise O1C65RunError("APPLE-VIEW-0009 frozen grouping evidence differs")
    return result


def build_frozen_grouping(
    potential_path: Path, config: Mapping[str, object]
) -> FrozenGrouping:
    input_row = _mapping(config.get("input"), "input")
    expected_potential = _sha256(input_row.get("potential_sha256"), "potential_sha256")
    try:
        payload = potential_path.read_bytes()
        field = CriticalityPotentialField.from_bytes(payload)
        grouping = build_compatibility_grouping(field, width_cap=GROUPING_WIDTH_CAP)
        diagnostics = compatibility_grouping_diagnostics(field, grouping).describe()
    except Exception as exc:
        raise O1C65RunError("frozen width-6 grouping construction failed") from exc
    expected = _exact_grouping_row()
    comparable = {
        name: diagnostics[name] for name in expected if name not in {"expected_sha256"}
    }
    comparable["expected_sha256"] = diagnostics["grouping_sha256"]
    # JSON freezes distributions as arrays; normalize the diagnostic tuples.
    comparable["group_size_distribution"] = [
        list(row)
        for row in cast(Sequence[Sequence[int]], diagnostics["group_size_distribution"])
    ]
    comparable["group_width_distribution"] = [
        list(row)
        for row in cast(
            Sequence[Sequence[int]], diagnostics["group_width_distribution"]
        )
    ]
    if (
        hashlib.sha256(payload).hexdigest() != expected_potential
        or field.state_sha256 != expected_potential
        or grouping.sha256 != EXPECTED_GROUPING_SHA256
        or len(grouping.serialized) != EXPECTED_GROUPING_SERIALIZED_BYTES
        or comparable != expected
    ):
        raise O1C65RunError("frozen width-6 grouping identity differs")
    return FrozenGrouping(field=field, grouping=grouping, diagnostics=diagnostics)


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    """Perform a read-only, zero-native-call authorization check."""

    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    baseline = validate_apple8_baseline(root, config)
    validate_grouping_provenance(root, config)
    potential = cast(Path, getattr(baseline, "potential"))
    frozen_grouping = build_frozen_grouping(potential, config)
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
        raise O1C65RunError("memory-pressure preflight is below frozen gate")
    capsule = cast(Path, getattr(baseline, "capsule"))
    authoritative = cast(Path, getattr(baseline, "authoritative_result"))
    cnf = cast(Path, getattr(baseline, "cnf"))
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "config_sha256": sha256_file(config_file),
        "apple8_capsule": capsule.relative_to(root).as_posix(),
        "apple8_result_sha256": sha256_file(authoritative),
        "apple8_manifest_sha256": sha256_file(capsule / "artifacts.sha256"),
        "apple9_result_sha256": APPLE9_RESULT_SHA256,
        "cnf_sha256": sha256_file(cnf),
        "potential_sha256": sha256_file(potential),
        "threshold": THRESHOLD,
        "grouping_width_cap": GROUPING_WIDTH_CAP,
        "grouping_sha256": frozen_grouping.grouping.sha256,
        "grouping_serialized_bytes": len(frozen_grouping.grouping.serialized),
        "group_count": frozen_grouping.grouping.group_count,
        "group_table_rows": frozen_grouping.grouping.table_rows,
        "grouping_materialized": False,
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
        "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
        "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "expected_native_executable_sha256": EXPECTED_NATIVE_EXECUTABLE_SHA256,
        "native_result_schema": NATIVE_RESULT_SCHEMA,
        "native_memory_series_schema": NATIVE_MEMORY_SERIES_SCHEMA,
        "maximum_native_memory_samples": MAXIMUM_NATIVE_MEMORY_SAMPLES,
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
    """Authorize exact native-v5 source and executable bytes before intent."""

    try:
        actual_executable = sha256_file(native_build.executable)
    except (AttributeError, OSError) as exc:
        raise O1C65RunError("native-v5 build identity differs") from exc
    if (
        not isinstance(native_build, NativeGuidedSearchBuild)
        or native_build.executable.is_symlink()
        or native_build.source_sha256 != EXPECTED_NATIVE_SOURCE_SHA256
        or native_build.executable_sha256 != EXPECTED_NATIVE_EXECUTABLE_SHA256
        or actual_executable != EXPECTED_NATIVE_EXECUTABLE_SHA256
    ):
        raise O1C65RunError("native-v5 build identity differs")


def materialize_grouping(path: Path, frozen: FrozenGrouping) -> dict[str, object]:
    """Persist and reread the exact grouped input before call intent exists."""

    if path.exists() or path.is_symlink():
        raise O1C65RunError("grouping artifact already exists")
    try:
        written_sha256 = _native_v7.write_joint_score_sieve_grouping(
            path, frozen.field, grouping=frozen.grouping
        )
    except Exception as exc:
        raise O1C65RunError("grouping artifact materialization failed") from exc
    try:
        observed = path.read_bytes()
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise O1C65RunError("grouping artifact verification failed") from exc
    digest = hashlib.sha256(observed).hexdigest()
    if (
        path.is_symlink()
        or not stat.S_ISREG(mode)
        or written_sha256 != EXPECTED_GROUPING_SHA256
        or observed != frozen.grouping.serialized
        or digest != EXPECTED_GROUPING_SHA256
        or len(observed) != EXPECTED_GROUPING_SERIALIZED_BYTES
    ):
        raise O1C65RunError("grouping artifact identity differs")
    return {
        "schema": "o1-256-o1c65-materialized-width6-grouping-v1",
        "artifact": path.name,
        "materialized_before_intent": True,
        "sha256": digest,
        "serialized_bytes": len(observed),
        **dict(frozen.diagnostics),
    }


def validate_frozen_call_inputs(*, cnf: Path, potential: Path, grouping: Path) -> None:
    """Fail closed on every science byte before entering the native runner."""

    expected = {
        cnf: "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432",
        potential: ("8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"),
        grouping: EXPECTED_GROUPING_SHA256,
    }
    try:
        for path, digest in expected.items():
            mode = path.stat(follow_symlinks=False).st_mode
            if (
                path.is_symlink()
                or not stat.S_ISREG(mode)
                or sha256_file(path) != digest
            ):
                raise O1C65RunError("frozen native-call input identity differs")
        if grouping.stat().st_size != EXPECTED_GROUPING_SERIALIZED_BYTES:
            raise O1C65RunError("frozen native-call grouping size differs")
    except O1C65RunError:
        raise
    except OSError as exc:
        raise O1C65RunError("frozen native-call input identity differs") from exc
    if (
        CONFLICT_LIMIT != 512
        or THRESHOLD != 14.606178797892962
        or GROUPING_WIDTH_CAP != 6
    ):
        raise O1C65RunError("frozen native-call scalar identity differs")


def invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    grouping: Path,
    runner: Callable[..., JointScoreSieveResult] = _native_v7.run_joint_score_sieve,
) -> JointScoreSieveResult:
    """Make the sole O1C65 native call with the frozen matched-work inputs."""

    validate_frozen_call_inputs(cnf=cnf, potential=potential, grouping=grouping)
    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        grouping_path=grouping,
        threshold=THRESHOLD,
        conflict_limit=CONFLICT_LIMIT,
        seed=0,
        timeout_seconds=NATIVE_TIMEOUT_SECONDS,
        memory_limit_bytes=MEMORY_LIMIT_BYTES,
    )


def _json_lossless(value: object) -> object:
    return _o1c64._json_lossless(value)


def _exception_chain(exc: BaseException) -> list[dict[str, object]]:
    return _o1c64._exception_chain(cast(Exception, exc))


def native_failure_telemetry(
    exc: Exception, *, directory: Path | None = None
) -> dict[str, object]:
    """Preserve v7 cause/RSS telemetry and bounded raw streams verbatim."""

    try:
        evidence = dict(_o1c64.native_failure_telemetry(exc, directory=directory))
    except Exception as capture_exc:
        return {
            "schema": "o1-256-o1c65-native-failure-evidence-v1",
            "adapter_contract_valid": False,
            "telemetry_capture_failure": {
                "type": type(capture_exc).__qualname__,
                "message": str(capture_exc),
                "chain": _exception_chain(capture_exc),
            },
            "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
            "o1c65_resource_contract": _resource_contract(),
        }
    evidence["schema"] = "o1-256-o1c65-native-failure-evidence-v1"
    evidence.pop("o1c64_resource_contract", None)
    evidence["o1c65_resource_contract"] = _resource_contract()
    return evidence


def _resource_contract() -> dict[str, object]:
    return {
        "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "darwin_watchdog_guard_bytes": DARWIN_WATCHDOG_GUARD_BYTES,
        "darwin_watchdog_kill_threshold_bytes": DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES,
        "darwin_watchdog_poll_interval_seconds": DARWIN_WATCHDOG_INTERVAL_SECONDS,
    }


def invoke_native_once_terminal(
    *, failure_directory: Path | None = None, **kwargs: object
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    """Consume at most one call and convert every call failure to evidence."""

    try:
        return invoke_native_once(**kwargs), None  # type: ignore[arg-type]
    except Exception as exc:
        telemetry = native_failure_telemetry(exc, directory=failure_directory)
        telemetry_sha: str | None = None
        if failure_directory is not None:
            try:
                _atomic_json(
                    failure_directory / "native_execution_failure.json", telemetry
                )
                telemetry_sha = sha256_file(
                    failure_directory / "native_execution_failure.json"
                )
            except Exception as artifact_exc:
                telemetry["evidence_artifact_write_failure"] = {
                    "type": type(artifact_exc).__qualname__,
                    "message": str(artifact_exc),
                    "chain": _exception_chain(artifact_exc),
                }
        return None, {
            "classification": "O1C65_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__qualname__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
            "native_execution_failure_artifact": (
                "native_execution_failure.json" if telemetry_sha else None
            ),
            "native_execution_failure_sha256": telemetry_sha,
            "native_failure_telemetry": telemetry,
        }


def validate_native_resource_ledger(
    native: JointScoreSieveResult, *, solver_calls: int
) -> dict[str, int]:
    try:
        validate_native_adapter_memory(native)
        ledger = _native_v7.validate_soft_conflict_ledger(native.stats)
        sieve = _mapping(native.sieve, "native.sieve")
        state = _mapping(sieve.get("state"), "native.sieve.state")
        pending = cast(int, sieve["external_clauses_queued"]) - cast(
            int, sieve["external_clauses_emitted"]
        )
        expected = _exact_grouping_row()
        expected_state_by_status = {
            0: (256, "INCONCLUSIVE"),
            10: (32, "SATISFIED"),
            20: (64, "UNSATISFIED"),
        }
        if (
            native.raw.get("schema") != NATIVE_RESULT_SCHEMA
            or native.raw.get("implementation_parent_schema")
            != IMPLEMENTATION_PARENT_SCHEMA
            or (
                native.raw.get("post_solve_state"),
                native.raw.get("post_solve_state_name"),
            )
            != expected_state_by_status.get(native.status)
            or native.raw.get("teardown_rule") != TEARDOWN_RULE
            or native.raw.get("pending_backtrack_rule") != PENDING_BACKTRACK_RULE
            or state.get("schema") != NATIVE_STATE_SCHEMA
            or native.conflict_limit != CONFLICT_LIMIT
            or ledger["requested_conflicts"] != CONFLICT_LIMIT
            or ledger["billed_conflicts"] > MAXIMUM_BILLED_CONFLICTS
            or ledger["conflict_limit_overshoot"] > MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
            or (native.status == 0 and ledger["billed_conflicts"] != 513)
            or int(native.resources["wall_microseconds"])
            > int(NATIVE_TIMEOUT_SECONDS * 1_000_000)
            or int(native.resources["peak_rss_bytes"]) > MEMORY_LIMIT_BYTES
            or sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
            or sieve.get("grouping_rule") != COMPATIBILITY_GROUPING_RULE
            or sieve.get("bound_rule") != COMPATIBILITY_GROUPING_BOUND_RULE
            or sieve.get("grouping_sha256") != EXPECTED_GROUPING_SHA256
            or sieve.get("grouping_input_sha256") != EXPECTED_GROUPING_SHA256
            or sieve.get("grouping_width_cap") != GROUPING_WIDTH_CAP
            or sieve.get("grouping_serialized_bytes")
            != EXPECTED_GROUPING_SERIALIZED_BYTES
            or sieve.get("factor_count") != expected["factor_count"]
            or sieve.get("group_count") != expected["group_count"]
            or sieve.get("singleton_group_count") != expected["singleton_group_count"]
            or sieve.get("pair_group_count") != expected["pair_group_count"]
            or sieve.get("higher_order_group_count")
            != expected["higher_order_group_count"]
            or sieve.get("maximum_group_size") != expected["maximum_group_size"]
            or sieve.get("group_table_rows") != expected["table_rows"]
            or sieve.get("group_incident_edges")
            != expected["variable_group_incidences"]
            or sieve.get("root_upper_bound_f64le_hex")
            != expected["grouped_root_upper_bound_f64le_hex"]
            or not 0 <= pending <= 1
            or solver_calls != 1
        ):
            raise O1C65RunError("O1C-0065 native grouped resource ledger differs")
    except O1C65RunError as exc:
        raise O1C65RunError("O1C-0065 native grouped resource ledger differs") from exc
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise O1C65RunError(
            "O1C-0065 native grouped lifecycle or ledger differs"
        ) from exc
    return dict(ledger)


def validate_native_adapter_memory(
    native: JointScoreSieveResult,
) -> dict[str, object]:
    """Validate and detach v7's bounded success-side RSS time series."""

    raw = getattr(native, "adapter_memory", None)
    row = _mapping(raw, "native.adapter_memory")
    fields = {
        "memory_series_schema",
        "memory_sample_limit",
        "memory_sample_count",
        "memory_samples",
        "memory_peak_bytes",
        "memory_last_bytes",
        "memory_last_elapsed_seconds",
    }
    if set(row) != fields:
        raise O1C65RunError("native adapter memory fields differ")
    samples = row["memory_samples"]
    if not isinstance(samples, list):
        raise O1C65RunError("native adapter memory samples differ")
    normalized: list[dict[str, int | float]] = []
    for sample in samples:
        if not isinstance(sample, Mapping):
            raise O1C65RunError("native adapter memory sample differs")
        elapsed = sample.get("elapsed_seconds")
        rss = sample.get("rss_bytes")
        if (
            set(sample) != {"elapsed_seconds", "rss_bytes"}
            or isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
            or not 0.0 <= float(elapsed) <= NATIVE_TIMEOUT_SECONDS
            or isinstance(rss, bool)
            or not isinstance(rss, int)
            or not 0 <= rss <= MEMORY_LIMIT_BYTES
        ):
            raise O1C65RunError("native adapter memory sample differs")
        normalized.append({"elapsed_seconds": float(elapsed), "rss_bytes": rss})
    count = row["memory_sample_count"]
    if (
        row["memory_series_schema"] != NATIVE_MEMORY_SERIES_SCHEMA
        or row["memory_sample_limit"] != MAXIMUM_NATIVE_MEMORY_SAMPLES
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != len(normalized)
        or count > MAXIMUM_NATIVE_MEMORY_SAMPLES
        or normalized
        != sorted(normalized, key=lambda sample: float(sample["elapsed_seconds"]))
    ):
        raise O1C65RunError("native adapter memory ledger differs")
    if normalized:
        expected_peak: int | None = max(
            cast(int, sample["rss_bytes"]) for sample in normalized
        )
        expected_last: int | None = cast(int, normalized[-1]["rss_bytes"])
        expected_elapsed: float | None = cast(float, normalized[-1]["elapsed_seconds"])
    else:
        expected_peak = None
        expected_last = None
        expected_elapsed = None
    if (
        row["memory_peak_bytes"] != expected_peak
        or row["memory_last_bytes"] != expected_last
        or row["memory_last_elapsed_seconds"] != expected_elapsed
    ):
        raise O1C65RunError("native adapter memory summary differs")
    return {
        **dict(row),
        "memory_samples": [dict(sample) for sample in normalized],
    }


def public_model_then_truth_diagnostic(
    native: JointScoreSieveResult,
    *,
    verify_public_model: Callable[[bytes], bool],
    read_truth_key: Callable[[], bytes],
    public_diagnostic_ledger: list[bool],
) -> tuple[bool, bytes | None, bool | None]:
    """Publicly verify a model without ever invoking the truth callback."""

    if public_diagnostic_ledger != [False]:
        raise O1C65RunError("public diagnostic ledger differs")
    if native.key_model is None:
        public_diagnostic_ledger[0] = True
        if native.status == 10:
            raise O1C65RunError("SAT result lacks a native key model")
        return False, None, None
    try:
        public_verified = bool(verify_public_model(native.key_model))
    finally:
        public_diagnostic_ledger[0] = True
    if not public_verified:
        raise O1C65RunError("native model fails eight public blocks")
    # The callback remains in this compatibility-shaped API solely so tests can
    # prove it is never called.  Public 8/8 verification is sufficient.
    del read_truth_key
    return True, None, None


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C65RunError(f"{field} differs")
    return value


def classify_efficacy(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    billed_conflicts: int,
) -> tuple[str, dict[str, object]]:
    """Compare the grouped call to APPLE-VIEW-0008 at exactly matched work."""

    trail = _nonnegative_int(
        native.sieve.get("trail_threshold_prunes"), "grouped trail prune ledger"
    )
    queued = _nonnegative_int(
        native.sieve.get("external_clauses_queued"), "grouped queued clause ledger"
    )
    emitted = _nonnegative_int(
        native.sieve.get("external_clauses_emitted"), "grouped emitted clause ledger"
    )
    pending = queued - emitted
    if not 0 <= pending <= 1:
        raise O1C65RunError("grouped pending clause ledger differs")
    emitted_lower = max(0, trail - pending)
    if native.status == 20:
        raise O1C65RunError("UNSAT contradicts the frozen satisfiable public target")
    if native.status == 10:
        if not public_model_verified or native.key_model is None:
            raise O1C65RunError("SAT lacks an 8/8 publicly verified model")
        classification = "O1C65_EXACT_PUBLIC_FULL256_RECOVERY"
    else:
        if billed_conflicts != APPLE8_BILLED_CONFLICTS:
            raise O1C65RunError("UNKNOWN grouped result is not matched billed work")
        if emitted_lower > APPLE8_TRAIL_PRUNES:
            classification = "O1C65_GROUPED_WIDTH6_STRICT_EFFICACY_GAIN"
        elif emitted_lower == APPLE8_TRAIL_PRUNES:
            classification = "O1C65_GROUPED_WIDTH6_EFFICACY_RETAINED"
        else:
            classification = "O1C65_GROUPED_WIDTH6_EFFICACY_REGRESSION"
    return classification, {
        "trail_threshold_prunes": trail,
        "external_clauses_queued": queued,
        "external_clauses_emitted": emitted,
        "pending_clause_count": pending,
        "emitted_trail_prune_lower_bound": emitted_lower,
        "apple8_emitted_trail_prune_lower_bound": APPLE8_TRAIL_PRUNES,
        "emitted_trail_prune_delta": emitted_lower - APPLE8_TRAIL_PRUNES,
        "minimum_upper_bound": native.sieve["minimum_upper_bound"],
        "decisions": native.stats["decisions"],
        "propagations": native.stats["propagations"],
        "requested_work_matched": native.stats["requested_conflicts"] == 512,
        "billed_work_matched": billed_conflicts == 513,
        "time_and_rss_are_contextual": True,
    }


def _truth_diagnostic(
    *,
    root: Path,
    capsule: Path,
    config: Mapping[str, object],
    baseline: object,
    native: JointScoreSieveResult,
) -> tuple[bool, bytes | None, bool | None, bool, bool]:
    public_ledger = [False]
    public_preflight = cast(Mapping[str, object], getattr(baseline, "public_preflight"))
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
                "schema": "o1-256-o1c65-public-model-diagnostic-v1",
                "present": True,
                "public_verified_8_of_8": verified,
                "truth_key_bytes_read": False,
            },
        )
        return verified

    public, truth, equals = public_model_then_truth_diagnostic(
        native,
        verify_public_model=verify_public,
        read_truth_key=lambda: (_ for _ in ()).throw(
            O1C65RunError("O1C-0065 truth access is forbidden")
        ),
        public_diagnostic_ledger=public_ledger,
    )
    diagnostic = capsule / "public_model_diagnostic.json"
    if not diagnostic.exists():
        _atomic_json(
            diagnostic,
            {
                "schema": "o1-256-o1c65-public-model-diagnostic-v1",
                "present": False,
                "public_verified_8_of_8": False,
                "truth_key_bytes_read": False,
            },
        )
    return public, truth, equals, public_ledger[0], False


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def _runtime_resources(
    *, started: float, cpu_started: float, child_started: resource.struct_rusage
) -> dict[str, object]:
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "elapsed_seconds": time.perf_counter() - started,
        "parent_cpu_seconds": time.process_time() - cpu_started,
        "child_cpu_seconds": (
            child.ru_utime
            + child.ru_stime
            - child_started.ru_utime
            - child_started.ru_stime
        ),
        "peak_rss_bytes": _peak_rss_bytes(),
    }


def _terminal_runtime_resources(
    *, started: float, cpu_started: float, child_started: resource.struct_rusage
) -> dict[str, object]:
    try:
        return _runtime_resources(
            started=started, cpu_started=cpu_started, child_started=child_started
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
        "classification": "O1C65_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
        "capsule": capsule_relative.as_posix(),
        "claim_boundary": {
            "native_solver_calls": solver_calls,
            "retry_authorized": False,
            "validated_science_result": False,
            "same_full256_target_cnf_potential_threshold_seed_as_apple8": True,
            "grouping_is_only_science_change": True,
            "matched_requested_work": True,
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
            "Do not retry O1C-0065 or read truth; diagnose this immutable terminal "
            "capsule under a new attempt ID."
        ),
    }


def _pretty_json_bytes(value: object) -> bytes:
    return _canonical_json_bytes(value)


def _capsule_manifest(capsule: Path) -> tuple[bytes, int]:
    return _shared_capsule_manifest(capsule, exclude={"artifacts.sha256"})


def _assert_immutable_tree(capsule: Path) -> None:
    if not capsule.is_dir() or capsule.is_symlink():
        raise O1C65RunError("O1C-0065 terminal capsule differs")
    for path in (capsule, *capsule.rglob("*")):
        if path.is_symlink() or path.stat(follow_symlinks=False).st_mode & (
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        ):
            raise O1C65RunError("O1C-0065 terminal capsule is not immutable")


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
        raise O1C65RunError(f"{field} recovery ownership differs")
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
        "# O1C Run O1C-0065\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native calls: `{resources['native_solver_calls']}`\n"
        f"- Requested conflicts: `{resources['requested_conflicts']}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n"
        f"- Width/grouping: `6/{EXPECTED_GROUPING_SHA256}`\n\n"
        "This one-call capsule keeps APPLE-VIEW-0008's Full-256 target, CNF, "
        "potential, threshold, seed, and 512-conflict efficacy budget unchanged. "
        "The frozen APPLE-VIEW-0009 exact width-6 grouped bound is the sole "
        "science change; time and RSS remain contextual.\n"
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
        raise O1C65RunError("O1C-0065 terminal output already exists")
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
        raise O1C65RunError("O1C-0065 persistent byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C65RunError("O1C-0065 persistent byte budget exceeded")
    payload = _pretty_json_bytes(result)
    manifest_path = capsule / "artifacts.sha256"
    authoritative_published = False
    manifest_published = False
    try:
        _atomic_bytes(authoritative_result, payload)
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
            authoritative_result.read_bytes() != payload
            or result_path.read_bytes() != payload
        ):
            raise O1C65RunError("O1C-0065 publication bytes differ")
        _assert_immutable_tree(capsule)
    except Exception:
        _restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _unlink_owned_exact(manifest_path, manifest, "O1C65 manifest")
        if authoritative_published:
            _unlink_owned_exact(
                authoritative_result, payload, "O1C65 authoritative result"
            )
        raise


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
            "classification": "O1C65_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT",
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
        raise O1C65RunError("O1C-0065 already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = validate_apple8_baseline(root, config)
    validate_grouping_provenance(root, config)
    frozen = build_frozen_grouping(cast(Path, getattr(baseline, "potential")), config)
    source_commit = str(preflight_row["source_commit"])
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c65-apple8-width6-grouped-") as raw:
        workspace = Path(raw)
        source = _mapping(config["source"], "source")
        native_build = _native_v7.build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "cadical-o1-joint-score-sieve-v5",
        )
        validate_native_build_identity(native_build)
        observed_sources = _source_hashes(root, config)
        expected_sources = dict(
            _mapping(source["expected_sha256"], "source.expected_sha256")
        )
        if observed_sources != expected_sources:
            raise O1C65RunError("source identity changed after preflight")

        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        _atomic_json(capsule / "preflight.json", preflight_row)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        _atomic_json(
            capsule / "apple8_binding.json",
            {
                "schema": "o1-256-o1c65-frozen-apple8-binding-v1",
                "capsule": APPLE8_CAPSULE_RELATIVE.as_posix(),
                "result_sha256": sha256_file(
                    cast(Path, getattr(baseline, "authoritative_result"))
                ),
                "manifest_sha256": sha256_file(
                    cast(Path, getattr(baseline, "capsule")) / "artifacts.sha256"
                ),
                "cnf_sha256": sha256_file(cast(Path, getattr(baseline, "cnf"))),
                "potential_sha256": sha256_file(
                    cast(Path, getattr(baseline, "potential"))
                ),
                "threshold": THRESHOLD,
                "seed": 0,
                "requested_conflicts": CONFLICT_LIMIT,
                "matched_requested_work": True,
            },
        )
        grouping_path = capsule / "apple9-width6.grouping"
        grouping_report = materialize_grouping(grouping_path, frozen)
        _atomic_json(capsule / "grouping.json", grouping_report)
        # The grouping bytes and report are fully reread and verified above.  The
        # call authorization is deliberately the next persistent write.
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c65_apple8_width6_grouped_run run --config "
                f"{config_file.relative_to(root).as_posix()}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "config_sha256": sha256_file(config_file),
            "source_sha256": observed_sources,
            "calls_before": 0,
            "calls_authorized": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": MAXIMUM_BILLED_CONFLICTS,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            **_resource_contract(),
            "threshold": THRESHOLD,
            "cnf_sha256": sha256_file(cast(Path, getattr(baseline, "cnf"))),
            "potential_sha256": sha256_file(cast(Path, getattr(baseline, "potential"))),
            "grouping_artifact": grouping_path.name,
            "grouping_width_cap": GROUPING_WIDTH_CAP,
            "grouping_sha256": sha256_file(grouping_path),
            "grouping_serialized_bytes": grouping_path.stat().st_size,
            "grouping_materialized_and_verified_before_intent": True,
            "native_source_sha256": native_build.source_sha256,
            "native_executable_sha256": native_build.executable_sha256,
            "native_result_schema": NATIVE_RESULT_SCHEMA,
            "native_execution_failure_schema": NATIVE_EXECUTION_FAILURE_SCHEMA,
            "native_memory_series_schema": NATIVE_MEMORY_SERIES_SCHEMA,
            "maximum_native_memory_samples": MAXIMUM_NATIVE_MEMORY_SAMPLES,
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
            cnf=cast(Path, getattr(baseline, "cnf")),
            potential=cast(Path, getattr(baseline, "potential")),
            grouping=grouping_path,
            failure_directory=capsule,
        )
        if native_failure is not None:
            failure = dict(native_failure)
            _persist_failure_evidence(capsule / "native_failure.json", failure)
            runtime = _terminal_runtime_resources(
                started=started, cpu_started=cpu_started, child_started=child_started
            )
            result = _failure_result(
                capsule_relative=capsule_relative,
                source_commit=source_commit,
                preflight_row=preflight_row,
                failure=failure,
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
        public_complete = False
        truth_read = False
        try:
            _atomic_json(capsule / "native_result.json", native.raw)
            adapter_memory = validate_native_adapter_memory(native)
            _atomic_json(
                capsule / "native_adapter_memory.json",
                {
                    "schema": "o1-256-o1c65-native-adapter-memory-v1",
                    "adapter_memory": adapter_memory,
                },
            )
            ledger = validate_native_resource_ledger(native, solver_calls=solver_calls)
            _atomic_json(
                capsule / "conflict_ledger.json",
                {"schema": SOFT_CONFLICT_LEDGER_SCHEMA, **ledger},
            )
            public, truth, equals, public_complete, truth_read = _truth_diagnostic(
                root=root,
                capsule=capsule,
                config=config,
                baseline=baseline,
                native=native,
            )
            classification, metrics = classify_efficacy(
                native,
                public_model_verified=public,
                billed_conflicts=ledger["billed_conflicts"],
            )
            runtime = _terminal_runtime_resources(
                started=started, cpu_started=cpu_started, child_started=child_started
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
                "claim_boundary": {
                    "consumed_positive_apple8": True,
                    "consumed_public_apple9_grouping": True,
                    "same_full256_target_cnf_potential_threshold_seed_as_apple8": True,
                    "grouping_is_only_science_change": True,
                    "native_solver_calls": 1,
                    "new_score_arms": 0,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "refits": 0,
                    "public_model_diagnostic_complete": public_complete,
                    "truth_key_bytes_read_after_public_diagnostic": truth_read,
                    "public_collision_counts_as_exact_recovery": True,
                    "matched_requested_work": True,
                    "matched_maximum_billed_work": True,
                    "time_and_rss_are_contextual": True,
                    "classification_uses_emitted_trail_prune_lower_bound": True,
                },
                "grouping": {
                    "width_cap": GROUPING_WIDTH_CAP,
                    "sha256": sha256_file(grouping_path),
                    "serialized_bytes": grouping_path.stat().st_size,
                    "artifact": grouping_path.name,
                    "report_sha256": sha256_file(capsule / "grouping.json"),
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
                    "native_adapter_memory_sha256": sha256_file(
                        capsule / "native_adapter_memory.json"
                    ),
                },
                "adapter_memory": {
                    "artifact": "native_adapter_memory.json",
                    **adapter_memory,
                },
                "conflict_ledger": {
                    "schema": SOFT_CONFLICT_LEDGER_SCHEMA,
                    **ledger,
                },
                "metrics": {
                    **metrics,
                    "native_status": {0: "UNKNOWN", 10: "SAT"}[native.status],
                    "native_model_sha256": (
                        None
                        if native.key_model is None
                        else hashlib.sha256(native.key_model).hexdigest()
                    ),
                    "public_model_verified_8_of_8": public,
                    "native_model_equals_committed_truth": equals,
                    "truth_key_sha256": (
                        None if truth is None else hashlib.sha256(truth).hexdigest()
                    ),
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
                    "Promote only exact public recovery or a strict matched-work "
                    "emitted-prune gain; retain equal efficacy and regression as "
                    "terminal evidence without retry."
                ),
            }
        except Exception as exc:
            public_complete = (capsule / "public_model_diagnostic.json").is_file()
            truth_read = (capsule / "truth_access_intent.json").is_file()
            native_path = capsule / "native_result.json"
            preserved = native_path.is_file()
            try:
                native_sha = sha256_file(native_path) if preserved else None
            except Exception:
                native_sha = None
            failure = {
                "classification": "O1C65_OPERATIONAL_POST_NATIVE_FAILURE_NO_SCIENCE_RESULT",
                "error_type": type(exc).__qualname__,
                "error_message": str(exc),
                "exception_chain_outer_to_cause_or_context": _exception_chain(exc),
                "native_calls_consumed": 1,
                "native_result_preserved": preserved,
                "native_result_sha256": native_sha,
                "native_result_inline_if_sidecar_missing": (
                    None if preserved else _json_lossless(native.raw)
                ),
                "native_adapter_memory_inline": _json_lossless(
                    getattr(native, "adapter_memory", None)
                ),
                "retry_authorized": False,
                "public_model_diagnostic_complete": public_complete,
                "truth_key_bytes_read": truth_read,
            }
            _persist_failure_evidence(capsule / "post_native_failure.json", failure)
            runtime = _terminal_runtime_resources(
                started=started, cpu_started=cpu_started, child_started=child_started
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
    "APPLE9_RESULT_RELATIVE",
    "ATTEMPT_ID",
    "CAPSULE_SUFFIX",
    "CONFLICT_LIMIT",
    "DARWIN_WATCHDOG_GUARD_BYTES",
    "DARWIN_WATCHDOG_INTERVAL_SECONDS",
    "DARWIN_WATCHDOG_KILL_THRESHOLD_BYTES",
    "EXPECTED_GROUPING_SHA256",
    "EXPECTED_NATIVE_EXECUTABLE_SHA256",
    "EXPECTED_NATIVE_SOURCE_SHA256",
    "GROUPING_WIDTH_CAP",
    "MAXIMUM_BILLED_CONFLICTS",
    "MAXIMUM_CONFLICT_LIMIT_OVERSHOOT",
    "MEMORY_LIMIT_BYTES",
    "NATIVE_EXECUTION_FAILURE_SCHEMA",
    "NATIVE_TIMEOUT_SECONDS",
    "O1C65RunError",
    "RESULT_RELATIVE",
    "SOFT_CONFLICT_LEDGER_SCHEMA",
    "THRESHOLD",
    "_finalize_consumed_call_terminally",
    "build_frozen_grouping",
    "classify_efficacy",
    "finalize_capsule",
    "invoke_native_once",
    "invoke_native_once_terminal",
    "load_config",
    "materialize_grouping",
    "native_failure_telemetry",
    "preflight",
    "public_model_then_truth_diagnostic",
    "run",
    "validate_apple8_baseline",
    "validate_grouping_provenance",
    "validate_native_build_identity",
    "validate_native_resource_ledger",
    "validate_frozen_call_inputs",
]
