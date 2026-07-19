"""O1C-0062: one frozen 4K continuation of the positive APPLE-0008 sieve."""

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

from .chacha_trace import chacha20_blocks
from .full256_broker import verify_reveal
from .joint_score_sieve import JointScoreSieveResult
from .joint_score_sieve_softstop_4k import (
    JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
    JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
    JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
    JOINT_SCORE_SIEVE_DECISION_RULE,
    build_native_joint_score_sieve,
    run_joint_score_sieve_4k,
    validate_soft_conflict_ledger_4k,
)
from .o1_relational_search import O1RelationalSearchError, sha256_file
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


ATTEMPT_ID = "O1C-0062"
CONFIG_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-preflight-v1"
INTENT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-native-call-intent-v1"
RESULT_SCHEMA = "o1-256-apple8-crossblock-sieve-4k-result-v1"
CAPSULE_SUFFIX = "O1C-0062_apple8-crossblock-consequence-sieve-4k-v1"
RESULT_RELATIVE = Path(
    "research/O1C0062_APPLE8_CROSSBLOCK_SIEVE_4K_RESULT_20260719.json"
)
APPLE8_RESULT_RELATIVE = Path("research/apple_view_8/apple_view_8_matched_result.json")
APPLE8_CAPSULE_RELATIVE = Path(
    "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1"
)
APPLE8_CNF_RELATIVE = Path("artifacts/cnf/full256-eight-block-apple-view-0008.cnf")
APPLE8_POTENTIAL_RELATIVE = Path("artifacts/potential/primary-eight-block.potential")
O1C57_REVEAL_RELATIVE = Path(
    "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1/reveal.json"
)
CONFLICT_LIMIT = 4_096
NATIVE_TIMEOUT_SECONDS = 30.0
MEMORY_LIMIT_BYTES = 805_306_368
THRESHOLD = 14.606178797892962
APPLE512_TRAIL_PRUNES = 6
APPLE512_BILLED_CONFLICTS = 513
APPLE512_DECISIONS = 4_471
APPLE512_MINIMUM_UPPER_BOUND = 13.197930778790159
SUSTAINED_SCALING_MINIMUM_PRUNES = 24
SOURCE_NAMES = (
    "runner",
    "adapter_4k",
    "joint_score_sieve_v3",
    "joint_score_sieve_v2",
    "joint_score_sieve_base",
    "native_source",
    "o1c59_lifecycle_helpers",
    "chacha_trace",
    "full256_broker",
)


class O1C62RunError(RuntimeError):
    """The frozen APPLE8 input, 4K ledger, or one-shot lifecycle differs."""


@dataclass(frozen=True)
class FrozenApple8:
    capsule: Path
    authoritative_result: Path
    cnf: Path
    potential: Path
    result: Mapping[str, object]
    public_preflight: Mapping[str, object]
    native_build: Mapping[str, object]


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
        raise O1C62RunError(f"{field} recovery ownership differs")
    path.chmod(0o644)
    path.unlink()
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _assert_immutable_capsule(capsule: Path) -> None:
    for path in (capsule, *capsule.rglob("*")):
        if path.stat(follow_symlinks=False).st_mode & (
            stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
        ):
            raise O1C62RunError("positive APPLE8 capsule is writable")


def _manifest_inventory(capsule: Path, expected_sha256: str) -> dict[str, str]:
    manifest = capsule / "artifacts.sha256"
    if sha256_file(manifest) != expected_sha256:
        raise O1C62RunError("positive APPLE8 manifest hash differs")
    inventory: dict[str, str] = {}
    try:
        rows = manifest.read_text("ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise O1C62RunError("positive APPLE8 manifest encoding differs") from exc
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
            raise O1C62RunError("positive APPLE8 manifest row differs")
        target = (capsule / relative_path).resolve(strict=True)
        if (
            not target.is_relative_to(capsule)
            or not target.is_file()
            or target.is_symlink()
            or sha256_file(target) != digest
        ):
            raise O1C62RunError(f"positive APPLE8 artifact differs: {relative}")
        inventory[relative] = digest
    observed = {
        path.relative_to(capsule).as_posix()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if observed != {*inventory, "artifacts.sha256"}:
        raise O1C62RunError("positive APPLE8 manifest inventory differs")
    return inventory


def _peak_rss_bytes() -> int:
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(raw if sys.platform == "darwin" else raw * 1024)


def public_model_then_truth_diagnostic(
    native: JointScoreSieveResult,
    *,
    verify_public_model: Callable[[bytes], bool],
    read_truth_key: Callable[[], bytes],
    public_diagnostic_ledger: list[bool],
) -> tuple[bool, bytes | None, bool | None]:
    if public_diagnostic_ledger != [False]:
        raise O1C62RunError("public diagnostic ledger differs")
    if native.key_model is None:
        public_diagnostic_ledger[0] = True
        if native.status == 10:
            raise O1C62RunError("SAT result lacks a native key model")
        return False, None, None
    try:
        public_verified = bool(verify_public_model(native.key_model))
    finally:
        public_diagnostic_ledger[0] = True
    if not public_verified:
        raise O1C62RunError("native model fails eight public blocks")
    truth = read_truth_key()
    if not isinstance(truth, bytes) or len(truth) != 32:
        raise O1C62RunError("post-native truth key differs")
    return True, truth, native.key_model == truth


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise O1C62RunError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise O1C62RunError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _read_mapping(path: Path, field: str) -> Mapping[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise O1C62RunError(f"duplicate {field} JSON key")
            result[key] = value
        return result

    try:
        return _mapping(
            json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates), field
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C62RunError(f"{field} is not valid JSON") from exc


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C62RunError(f"{field} path differs")
    path = (root / value).resolve(strict=True)
    if not path.is_relative_to(root):
        raise O1C62RunError(f"{field} escapes the lab")
    return path


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C62RunError(f"{field} hash differs")
    return value


def _exact_config_rows() -> dict[str, object]:
    baseline_density = APPLE512_TRAIL_PRUNES * 1_000.0 / APPLE512_BILLED_CONFLICTS
    derived_gate = math.ceil(
        0.5 * baseline_density * JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS / 1_000.0
    )
    if derived_gate != SUSTAINED_SCALING_MINIMUM_PRUNES:
        raise O1C62RunError("sustained scaling gate derivation differs")
    return {
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
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
            "soft_conflict_ledger_schema": JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "calls": 1,
        },
        "apple512": {
            "trail_threshold_prunes": APPLE512_TRAIL_PRUNES,
            "billed_conflicts": APPLE512_BILLED_CONFLICTS,
            "decisions": APPLE512_DECISIONS,
            "minimum_upper_bound": APPLE512_MINIMUM_UPPER_BOUND,
            "prune_density_per_1000_billed": baseline_density,
        },
        "promotion": {
            "sustained_scaling_minimum_safe_trail_prunes": SUSTAINED_SCALING_MINIMUM_PRUNES,
            "derivation": "ceil(0.5*(6/513)*4097)=24",
            "sustained": ">=24 safe trail prunes or SAT/public recovery",
            "active_sublinear": "1..23 safe trail prunes without recovery",
            "regression": "0 safe trail prunes without recovery",
            "different_budget_work_is_matched": False,
        },
        "budgets": {
            "maximum_native_solver_calls": 1,
            "maximum_requested_conflicts": CONFLICT_LIMIT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
            "maximum_native_wall_seconds": NATIVE_TIMEOUT_SECONDS,
            "maximum_peak_rss_bytes": MEMORY_LIMIT_BYTES,
            "minimum_memory_pressure_free_percent": 15,
            "maximum_fresh_targets": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_fresh_reveal_calls": 0,
            "maximum_refits": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_persistent_artifact_bytes": 134_217_728,
        },
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C62RunError("config escapes the lab")
    config = dict(_read_mapping(config_path, "O1C62 config"))
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "apple8-crossblock-consequence-sieve-4k-v1"
        or config.get("claim_level") != "TEST"
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
        or any(
            config.get(name) != value for name, value in _exact_config_rows().items()
        )
    ):
        raise O1C62RunError("frozen O1C-0062 config differs")
    for name in SOURCE_NAMES:
        path_value = _relative(root, source[name], f"source.{name}")
        if sha256_file(path_value) != _sha256(expected[name], f"source.{name}"):
            raise O1C62RunError(f"source hash differs for {name}")
    return config


def validate_apple8_baseline(root: Path, config: Mapping[str, object]) -> FrozenApple8:
    frozen = _mapping(config["frozen_sha256"], "frozen_sha256")
    if set(frozen) != {
        "authoritative_result",
        "manifest",
        "capsule_result",
        "native_result",
        "preflight",
        "native_build",
        "truth_reveal",
    }:
        raise O1C62RunError("frozen APPLE8 hashes differ")
    rows = _exact_config_rows()
    input_row = _mapping(rows["input"], "input")
    capsule = _relative(root, input_row["apple8_capsule"], "APPLE8 capsule")
    authoritative = _relative(
        root, input_row["apple8_result"], "APPLE8 authoritative result"
    )
    manifest_sha = _sha256(frozen["manifest"], "APPLE8 manifest")
    try:
        inventory = _manifest_inventory(capsule, manifest_sha)
        _assert_immutable_capsule(capsule)
    except Exception as exc:
        raise O1C62RunError("immutable APPLE8 capsule differs") from exc
    required = {
        "result.json": frozen["capsule_result"],
        "native_result.json": frozen["native_result"],
        "preflight.json": frozen["preflight"],
        "native_build.json": frozen["native_build"],
        APPLE8_CNF_RELATIVE.as_posix(): input_row["cnf_sha256"],
        APPLE8_POTENTIAL_RELATIVE.as_posix(): input_row["potential_sha256"],
    }
    if any(inventory.get(name) != digest for name, digest in required.items()):
        raise O1C62RunError("APPLE8 manifest binding differs")
    capsule_result = capsule / "result.json"
    result_sha = _sha256(frozen["authoritative_result"], "APPLE8 result")
    if (
        result_sha != frozen["capsule_result"]
        or sha256_file(authoritative) != result_sha
        or sha256_file(capsule_result) != result_sha
        or authoritative.read_bytes() != capsule_result.read_bytes()
    ):
        raise O1C62RunError("APPLE8 authoritative mirror differs")
    result = _read_mapping(authoritative, "APPLE8 result")
    comparison = _mapping(result.get("comparison"), "APPLE8 comparison")
    augmented = _mapping(comparison.get("augmented"), "APPLE8 augmented metrics")
    work = _mapping(
        _mapping(comparison.get("work"), "APPLE8 work").get("augmented"),
        "APPLE8 augmented work",
    )
    claim = _mapping(result.get("claim_boundary"), "APPLE8 claim boundary")
    expected_augmented = {
        "trail_threshold_prunes": APPLE512_TRAIL_PRUNES,
        "minimum_upper_bound": APPLE512_MINIMUM_UPPER_BOUND,
    }
    if (
        result.get("schema") != "apple-view-0008-matched-joint-score-sieve-result-v1"
        or result.get("attempt_id") != "APPLE-VIEW-0008-MATCHED"
        or result.get("classification")
        != "APPLE_VIEW_0008_STRICT_INCREMENTAL_EFFECT_NO_RECOVERY"
        or result.get("capsule") != APPLE8_CAPSULE_RELATIVE.as_posix()
        or any(
            augmented.get(name) != value for name, value in expected_augmented.items()
        )
        or work.get("billed_conflicts") != APPLE512_BILLED_CONFLICTS
        or work.get("decisions") != APPLE512_DECISIONS
        or claim.get("native_solver_calls") != 1
        or claim.get("truth_key_bytes_read_after_public_diagnostic") is not False
    ):
        raise O1C62RunError("positive APPLE8 baseline semantics differ")
    preflight = _read_mapping(capsule / "preflight.json", "APPLE8 preflight")
    public = _mapping(
        preflight.get("public_o1c57_preflight"), "APPLE8 public preflight"
    )
    if (
        preflight.get("threshold") != THRESHOLD
        or preflight.get("potential_sha256") != input_row["potential_sha256"]
        or public.get("truth_artifacts_read") is not False
        or len(_sequence(public.get("counters"), "public counters")) != 8
        or len(_sequence(public.get("output_blocks_hex"), "public outputs")) != 8
    ):
        raise O1C62RunError("APPLE8 public preflight differs")
    native_build = _read_mapping(capsule / "native_build.json", "APPLE8 native build")
    if (
        native_build.get("source_sha256")
        != "c9ddc07d8d5ae22852ad7302ba9f8888cc86d3c04cf5fabf8c79a9eb8b28e91b"
        or native_build.get("executable_sha256")
        != "07b132949ec11737b6de8004acb1ee48874812b975604f030865aad6a13b7024"
    ):
        raise O1C62RunError("APPLE8 native-v2 build binding differs")
    return FrozenApple8(
        capsule=capsule,
        authoritative_result=authoritative,
        cnf=capsule / APPLE8_CNF_RELATIVE,
        potential=capsule / APPLE8_POTENTIAL_RELATIVE,
        result=result,
        public_preflight=public,
        native_build=native_build,
    )


def preflight(
    config_path: str | Path, *, require_commit_binding: bool = False
) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    baseline = validate_apple8_baseline(root, config)
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
        raise O1C62RunError("memory-pressure preflight is below frozen gate")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ok": True,
        "ready_for_science": require_commit_binding,
        "source_commit": source_commit,
        "source_commit_bound": require_commit_binding,
        "apple8_capsule": baseline.capsule.relative_to(root).as_posix(),
        "apple8_result_sha256": sha256_file(baseline.authoritative_result),
        "apple8_manifest_sha256": sha256_file(baseline.capsule / "artifacts.sha256"),
        "cnf_sha256": sha256_file(baseline.cnf),
        "potential_sha256": sha256_file(baseline.potential),
        "threshold": THRESHOLD,
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_billed_conflicts": JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
        "soft_conflict_ledger_schema": JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
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
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve_4k,
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


def invoke_native_once_terminal(
    **kwargs: object,
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    try:
        return invoke_native_once(**kwargs), None  # type: ignore[arg-type]
    except Exception as exc:
        return None, {
            "classification": "O1C62_OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
        }


def validate_native_resource_ledger(
    native: JointScoreSieveResult, *, solver_calls: int
) -> dict[str, int]:
    try:
        ledger = validate_soft_conflict_ledger_4k(native.stats)
    except O1RelationalSearchError as exc:
        raise O1C62RunError("O1C-0062 soft conflict ledger differs") from exc
    if (
        native.conflict_limit != CONFLICT_LIMIT
        or ledger["requested_conflicts"] != CONFLICT_LIMIT
        or ledger["billed_conflicts"] > JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS
        or ledger["conflict_limit_overshoot"]
        > JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT
        or int(native.resources["wall_microseconds"])
        > int(NATIVE_TIMEOUT_SECONDS * 1_000_000)
        or int(native.resources["peak_rss_bytes"]) > MEMORY_LIMIT_BYTES
        or native.sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
        or solver_calls != 1
    ):
        raise O1C62RunError("O1C-0062 native resource ledger differs")
    return ledger


def classify_scaling(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    billed_conflicts: int,
) -> tuple[str, dict[str, object]]:
    if native.status == 20:
        raise O1C62RunError("UNSAT contradicts the frozen satisfiable public target")
    if native.status not in (0, 10):
        raise O1C62RunError("native status differs")
    if native.status == 10:
        if native.key_model is None or not public_model_verified:
            raise O1C62RunError("SAT result lacks a publicly verified key model")
        classification = "O1C62_EXACT_PUBLIC_FULL256_RECOVERY"
    elif public_model_verified or native.key_model is not None:
        raise O1C62RunError("non-SAT result contains a key model")
    else:
        trail_prunes = int(cast(int, native.sieve["trail_threshold_prunes"]))
        if trail_prunes >= SUSTAINED_SCALING_MINIMUM_PRUNES:
            classification = "O1C62_APPLE8_4K_SUSTAINED_SCALING"
        elif trail_prunes > 0:
            classification = "O1C62_APPLE8_4K_ACTIVE_SUBLINEAR"
        else:
            classification = "O1C62_APPLE8_4K_SCALING_REGRESSION"
    prunes = int(cast(int, native.sieve["trail_threshold_prunes"]))
    decisions = int(cast(int, native.stats["decisions"]))
    minimum_upper = float(cast(float, native.sieve["minimum_upper_bound"]))
    if billed_conflicts <= 0 or not math.isfinite(minimum_upper):
        raise O1C62RunError("O1C-0062 contextual metric differs")
    baseline_density = APPLE512_TRAIL_PRUNES * 1_000.0 / APPLE512_BILLED_CONFLICTS
    density = prunes * 1_000.0 / billed_conflicts
    decisions_density = decisions * 1_000.0 / billed_conflicts
    return classification, {
        "public_model_verified": public_model_verified,
        "safe_trail_threshold_prunes": prunes,
        "prune_density_per_1000_billed": density,
        "decisions": decisions,
        "decisions_per_1000_billed": decisions_density,
        "minimum_upper_bound": minimum_upper,
        "apple512": {
            "safe_trail_threshold_prunes": APPLE512_TRAIL_PRUNES,
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
            "minimum_safe_trail_prunes": SUSTAINED_SCALING_MINIMUM_PRUNES,
            "sustained_scaling": public_model_verified
            or prunes >= SUSTAINED_SCALING_MINIMUM_PRUNES,
            "active_sublinear": not public_model_verified and 1 <= prunes <= 23,
            "regression": not public_model_verified and prunes == 0,
        },
        "different_budget_work_is_matched": False,
    }


def _markdown(result: Mapping[str, object]) -> str:
    resources = _mapping(result["resources"], "resources")
    return (
        "# O1C Run O1C-0062\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native calls: `{resources['native_solver_calls']}`\n"
        f"- Requested conflicts: `{resources['requested_conflicts']}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n\n"
        "This is one frozen 4K continuation of the positive APPLE-VIEW-0008 "
        "input. Its comparison with Apple512 is contextual, never matched-work.\n"
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
        raise O1C62RunError("O1C-0062 terminal output already exists")
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
        raise O1C62RunError("O1C-0062 persistent byte ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C62RunError("O1C-0062 persistent byte budget exceeded")
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
            raise O1C62RunError("O1C-0062 publication bytes differ")
    except Exception:
        _restore_owned_capsule_for_recovery(capsule)
        if manifest_published:
            _unlink_owned_exact(manifest_path, manifest, "O1C62 manifest")
        if authoritative_published:
            _unlink_owned_exact(
                authoritative_result, result_payload, "O1C62 authoritative result"
            )
        raise


def _truth_diagnostic(
    *,
    root: Path,
    capsule: Path,
    config: Mapping[str, object],
    baseline: FrozenApple8,
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
                "reason": "diagnose-present-publicly-verified-model-only",
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
            raise O1C62RunError("truth reveal hash differs")
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
        "classification": "O1C62_OPERATIONAL_FAILURE_NO_SCIENCE_RESULT",
        "capsule": capsule_relative.as_posix(),
        "claim_boundary": {
            "native_solver_calls": solver_calls,
            "retry_authorized": False,
            "validated_science_result": False,
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
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight_row),
        "next_action": "Do not retry O1C-0062; diagnose its immutable terminal capsule.",
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
            "classification": "O1C62_OPERATIONAL_PUBLICATION_FAILURE_NO_SCIENCE_RESULT",
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


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    if authoritative.exists() or tuple(root.glob(f"runs/*_{CAPSULE_SUFFIX}")):
        raise O1C62RunError("O1C-0062 already exists")
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    preflight_row = preflight(config_file, require_commit_binding=True)
    baseline = validate_apple8_baseline(root, config)
    source_commit = str(preflight_row["source_commit"])
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c62-apple8-4k-") as raw:
        workspace = Path(raw)
        source = _mapping(config["source"], "source")
        native_build = build_native_joint_score_sieve(
            source=_relative(root, source["native_source"], "native source"),
            output=workspace / "cadical-o1-joint-score-sieve-v2",
        )
        if native_build.describe() != dict(baseline.native_build):
            raise O1C62RunError("native-v2 executable differs from APPLE8")
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
                "capsule": APPLE8_CAPSULE_RELATIVE.as_posix(),
                "result_sha256": sha256_file(baseline.authoritative_result),
                "manifest_sha256": sha256_file(baseline.capsule / "artifacts.sha256"),
                "cnf_sha256": sha256_file(baseline.cnf),
                "potential_sha256": sha256_file(baseline.potential),
                "different_budget_work_is_matched": False,
            },
        )
        _atomic_bytes(
            capsule / "command.txt",
            (
                "nice -n 10 env PYTHONPATH=src python3 -m "
                "o1_crypto_lab.o1c62_apple8_4k_run run --config "
                f"{config_file.relative_to(root).as_posix()}\n"
            ).encode("utf-8"),
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "calls_before": 0,
            "calls_authorized": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "maximum_conflict_limit_overshoot": JOINT_SCORE_SIEVE_4K_MAXIMUM_CONFLICT_LIMIT_OVERSHOOT,
            "maximum_billed_conflicts": JOINT_SCORE_SIEVE_4K_MAXIMUM_BILLED_CONFLICTS,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "threshold": THRESHOLD,
            "cnf_sha256": sha256_file(baseline.cnf),
            "potential_sha256": sha256_file(baseline.potential),
            "native_executable_sha256": native_build.executable_sha256,
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
                {
                    "schema": JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
                    **ledger,
                },
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
                "claim_boundary": {
                    "consumed_positive_apple8": True,
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
                },
                "native": {
                    "schema": native.raw.get("schema"),
                    "status": native.status,
                    "native_result_sha256": sha256_file(capsule / "native_result.json"),
                },
                "conflict_ledger": {
                    "schema": JOINT_SCORE_SIEVE_4K_CONFLICT_LEDGER_SCHEMA,
                    **ledger,
                },
                "metrics": {
                    **metrics,
                    "native_status": {0: "UNKNOWN", 10: "SAT", 20: "UNSAT"}[
                        native.status
                    ],
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
                    "Promote only sustained scaling or exact public recovery; "
                    "otherwise retain the contextual breadcrumbs without calling "
                    "different-budget work matched."
                ),
            }
        except Exception as exc:
            public_diagnostic_complete = (
                capsule / "public_model_diagnostic.json"
            ).is_file()
            truth_read = (capsule / "truth_access_intent.json").is_file()
            failure = {
                "classification": "O1C62_OPERATIONAL_POST_NATIVE_FAILURE_NO_SCIENCE_RESULT",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "native_calls_consumed": 1,
                "native_result_preserved": True,
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
    "MEMORY_LIMIT_BYTES",
    "NATIVE_TIMEOUT_SECONDS",
    "O1C62RunError",
    "RESULT_RELATIVE",
    "SUSTAINED_SCALING_MINIMUM_PRUNES",
    "THRESHOLD",
    "_finalize_consumed_call_terminally",
    "classify_scaling",
    "finalize_capsule",
    "invoke_native_once",
    "invoke_native_once_terminal",
    "load_config",
    "preflight",
    "run",
    "validate_apple8_baseline",
    "validate_native_resource_ledger",
]
