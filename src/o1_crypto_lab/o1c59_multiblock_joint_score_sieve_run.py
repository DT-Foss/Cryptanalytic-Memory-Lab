"""O1C-0059 exact eight-block joint-score sieve over consumed O1C-0057."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, cast

import numpy as np

from .chacha_trace import chacha20_blocks
from .criticality_potential import (
    CriticalityPotentialField,
    compile_criticality_potential,
    score_potential_assignment,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import InstanceWriteReport, verify_full256_instance, write_full256_instance
from .full256_forward_assignment import (
    Full256ForwardReadPlan,
    compile_full256_forward_read_plan,
)
from .full256_multiblock_cnf import (
    Full256MultiblockCNFReport,
    remap_full256_variable,
    verify_full256_multiblock_cnf,
    write_full256_multiblock_cnf,
)
from .joint_score_sieve import (
    JOINT_SCORE_SIEVE_DECISION_RULE,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES,
    JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS,
    JointScoreSieveResult,
    build_native_joint_score_sieve,
    run_joint_score_sieve,
    write_joint_score_sieve_potential,
)
from .living_inverse import PublicTargetView
from .multiblock_criticality_potential import (
    compile_multiblock_criticality_potential,
    verify_multiblock_complete_score_equivalence,
)
from .o1_relational_search import sha256_file
from .o1c37_relational_guided_search_run import (
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c41_antecedent_chain_rank_run import _peak_rss_bytes
from .proof_parent_criticality import FEATURE_NAMES, ParentCriticalityField
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0059"
CONFIG_SCHEMA = "o1-256-multiblock-joint-score-sieve-config-v1"
RESULT_SCHEMA = "o1-256-multiblock-joint-score-sieve-result-v1"
PREFLIGHT_SCHEMA = "o1-256-multiblock-joint-score-sieve-preflight-v1"
INTENT_SCHEMA = "o1-256-multiblock-joint-score-sieve-native-call-intent-v1"
EQUIVALENCE_SCHEMA = "o1-256-multiblock-complete-score-equivalence-v1"
RESULT_RELATIVE = Path(
    "research/O1C0059_MULTIBLOCK_JOINT_SCORE_SIEVE_RESULT_20260719.json"
)
CONSUMED_CAPSULE_RELATIVE = Path(
    "runs/20260719_062932_O1C-0057_multiblock-parent-criticality-rank-v1"
)
BLOCK_COUNT = 8
DECOY_COUNT = 4096
EXPECTED_VARIABLES = 255_232
EXPECTED_CLAUSES = 1_504_080
EXPECTED_FACTORS = 7_557
EXPECTED_ENERGY_ENTRIES = 104_432
EXPECTED_OBSERVED_VARIABLES = 2_981
EXPECTED_TRUTH_SCORE = 21.330305438256453
EXPECTED_DECOY_MAX = 14.606178797992964
MEMORY_LIMIT_BYTES = 805_306_368
CONFLICT_LIMIT = 512
NATIVE_TIMEOUT_SECONDS = 180.0
SCORE_TOLERANCE = 1e-10
TRUTH_SCORE_TOLERANCE = 1e-12
SOURCE_NAMES = (
    "template",
    "semantic_map",
    "native_source",
    "joint_score_sieve",
    "full256_multiblock_cnf",
    "multiblock_criticality_potential",
    "criticality_potential",
    "full256_cnf",
    "full256_forward_assignment",
    "proof_parent_criticality",
    "broker_source",
    "runner",
    "consumed_result",
)
COMMIT_BOUND_NAMES = (
    "config",
    "native_source",
    "joint_score_sieve",
    "full256_multiblock_cnf",
    "multiblock_criticality_potential",
    "criticality_potential",
    "full256_cnf",
    "full256_forward_assignment",
    "proof_parent_criticality",
    "broker_source",
    "runner",
)
EXPECTED_MANIFEST_MEMBERS = 80
_MANIFEST_ROW = re.compile(r"^([0-9a-f]{64})  ([^\n]+)$")


class O1C59RunError(RuntimeError):
    """The consumed evidence, exact composition, or one-shot ledger differs."""


@dataclass(frozen=True)
class ConsumedO1C57:
    capsule: Path
    result: Mapping[str, object]
    score_freeze: Mapping[str, object]
    publication: Mapping[str, object]
    public: PublicTargetView
    candidate_keys: tuple[bytes, ...]
    fields: tuple[ParentCriticalityField, ...]
    reader: np.ndarray
    feature_means: tuple[np.ndarray, ...]
    feature_stds: tuple[np.ndarray, ...]
    scalar_means: tuple[float, ...]
    scalar_stds: tuple[float, ...]
    raw_scores: tuple[np.ndarray, ...]
    frozen_joint_scores: np.ndarray
    instance_sha256: tuple[str, ...]
    manifest_sha256: str


@dataclass(frozen=True)
class EquivalenceRuntime:
    local_potentials: tuple[CriticalityPotentialField, ...]
    forward_plans: tuple[Full256ForwardReadPlan, ...]
    report: Mapping[str, object]


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            allow_nan=False,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _atomic_bytes(path: Path, payload: bytes) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise O1C59RunError(f"refusing to overwrite artifact: {path}")
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        linked = True
        temporary.unlink()
        parent = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if linked:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return payload


def _atomic_json(path: Path, value: object) -> bytes:
    return _atomic_bytes(path, _canonical_json_bytes(value))


def _copy_exclusive(source: Path, destination: Path) -> None:
    if destination.exists():
        raise O1C59RunError(f"refusing to overwrite artifact: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(raw)
    os.close(descriptor)
    try:
        shutil.copyfile(source, temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    if sha256_file(source) != sha256_file(destination):
        raise O1C59RunError("exclusive artifact copy differs")


def _commit_bound_bytes(root: Path, commit: str, path: Path, field: str) -> None:
    try:
        relative = path.resolve(strict=True).relative_to(root).as_posix()
        completed = subprocess.run(
            ("git", "show", f"{commit}:{relative}"),
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise O1C59RunError(f"{field} is not bound to source commit") from exc
    if completed.stdout != path.read_bytes():
        raise O1C59RunError(f"{field} differs from source commit")


def _required_commit_is_ancestor(root: Path, revision: str, field: str) -> None:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", revision, "HEAD"),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise O1C59RunError(f"required {field} commit is not an ancestor")


def _manifest_inventory(
    capsule: Path, *, expected_manifest_sha256: str
) -> dict[str, str]:
    manifest = (capsule / "artifacts.sha256").resolve(strict=True)
    if not manifest.is_relative_to(capsule) or sha256_file(manifest) != expected_manifest_sha256:
        raise O1C59RunError("consumed O1C-0057 manifest hash differs")
    try:
        rows = manifest.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise O1C59RunError("consumed O1C-0057 manifest encoding differs") from exc
    inventory: dict[str, str] = {}
    for row in rows:
        matched = _MANIFEST_ROW.fullmatch(row)
        if matched is None:
            raise O1C59RunError("consumed O1C-0057 manifest row differs")
        digest, relative = matched.groups()
        relative_path = Path(relative)
        if (
            relative in inventory
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative == "artifacts.sha256"
        ):
            raise O1C59RunError("consumed O1C-0057 manifest inventory differs")
        target = (capsule / relative_path).resolve(strict=True)
        if (
            not target.is_relative_to(capsule)
            or not target.is_file()
            or target.is_symlink()
            or sha256_file(target) != digest
        ):
            raise O1C59RunError(f"consumed artifact differs: {relative}")
        inventory[relative] = digest
    observed = {
        path.relative_to(capsule).as_posix()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if (
        len(inventory) != EXPECTED_MANIFEST_MEMBERS
        or observed != {*inventory, "artifacts.sha256"}
    ):
        raise O1C59RunError("consumed O1C-0057 manifest inventory differs")
    return inventory


def _float_vector(path: Path, *, count: int, digest: str) -> np.ndarray:
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != digest or len(payload) != count * 8:
        raise O1C59RunError(f"frozen float vector differs: {path}")
    result = np.frombuffer(payload, dtype="<f8").astype(np.float64, copy=True)
    if result.shape != (count,) or not bool(np.all(np.isfinite(result))):
        raise O1C59RunError(f"frozen float vector shape differs: {path}")
    result.setflags(write=False)
    return result


def _reader_vector(value: object) -> np.ndarray:
    try:
        reader = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise O1C59RunError("consumed O1C-0057 reader differs") from exc
    if (
        reader.shape != (len(FEATURE_NAMES),)
        or not bool(np.all(np.isfinite(reader)))
        or array_sha256(reader, "<f8")
        != "c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30"
    ):
        raise O1C59RunError("consumed O1C-0057 reader differs")
    result = np.array(reader, dtype=np.float64, copy=True)
    result.setflags(write=False)
    return result


def _feature_vector(value: object, field: str, *, nonnegative: bool = False) -> np.ndarray:
    try:
        result = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise O1C59RunError(f"{field} differs") from exc
    if (
        result.shape != (len(FEATURE_NAMES),)
        or not bool(np.all(np.isfinite(result)))
        or (nonnegative and bool(np.any(result < 0.0)))
    ):
        raise O1C59RunError(f"{field} differs")
    copied = np.array(result, dtype=np.float64, copy=True)
    copied.setflags(write=False)
    return copied


def _memory_free_percent() -> int | None:
    executable = Path("/usr/bin/memory_pressure")
    if not executable.is_file():
        return None
    completed = subprocess.run(
        (str(executable), "-Q"),
        check=False,
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    matched = re.search(
        r"System-wide memory free percentage:\s*([0-9]{1,3})%",
        completed.stdout,
    )
    if completed.returncode or matched is None:
        raise O1C59RunError("memory-pressure preflight differs")
    value = int(matched.group(1))
    if not 0 <= value <= 100:
        raise O1C59RunError("memory-pressure preflight differs")
    return value


def prospective_threshold(decoy_max: float, safety_margin: float) -> float:
    if (
        isinstance(decoy_max, bool)
        or not isinstance(decoy_max, (int, float))
        or not math.isfinite(float(decoy_max))
        or isinstance(safety_margin, bool)
        or not isinstance(safety_margin, (int, float))
        or not math.isfinite(float(safety_margin))
        or float(safety_margin) <= 0.0
    ):
        raise O1C59RunError("prospective threshold input differs")
    result = math.nextafter(float(decoy_max) - float(safety_margin), -math.inf)
    if not math.isfinite(result) or not result < float(decoy_max):
        raise O1C59RunError("prospective threshold differs")
    return result


def classify_sieve(
    native: JointScoreSieveResult,
    *,
    public_model_verified: bool,
    minimum_material_bound_drop: float,
) -> tuple[str, dict[str, object]]:
    if not isinstance(native, JointScoreSieveResult):
        raise O1C59RunError("native classification input differs")
    if native.status == 10:
        if not public_model_verified or native.key_model is None:
            raise O1C59RunError("SAT model failed independent public verification")
        classification = "EXACT_CONSUMED_FULL256_RECOVERY"
    elif public_model_verified or native.key_model is not None:
        raise O1C59RunError("non-SAT native result contains a verified model")
    else:
        root_upper = float(cast(float, native.sieve["root_upper_bound"]))
        minimum_upper = float(cast(float, native.sieve["minimum_upper_bound"]))
        bound_drop = root_upper - minimum_upper
        trail_prunes = int(cast(int, native.sieve["trail_threshold_prunes"]))
        complete_checks = int(
            cast(int, native.sieve.get("complete_model_score_checks", 0))
        )
        partial_bound_progress = (
            complete_checks == 0 and bound_drop >= minimum_material_bound_drop
        )
        if trail_prunes > 0 or partial_bound_progress:
            classification = "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY"
        else:
            classification = "EXACT_JOINT_SCORE_SIEVE_NO_USEFUL_PRUNE"
    root_upper = float(cast(float, native.sieve["root_upper_bound"]))
    minimum_upper = float(cast(float, native.sieve["minimum_upper_bound"]))
    trail_prunes = int(cast(int, native.sieve["trail_threshold_prunes"]))
    model_prunes = int(cast(int, native.sieve["model_threshold_prunes"]))
    complete_checks = int(
        cast(int, native.sieve.get("complete_model_score_checks", 0))
    )
    partial_bound_progress = (
        complete_checks == 0
        and root_upper - minimum_upper >= minimum_material_bound_drop
    )
    return classification, {
        "public_model_verified": public_model_verified,
        "root_to_minimum_bound_drop": root_upper - minimum_upper,
        "material_bound_drop": root_upper
        - minimum_upper
        >= minimum_material_bound_drop,
        "material_bound_drop_observed_before_any_complete_model": partial_bound_progress,
        "complete_model_score_checks": complete_checks,
        "safe_trail_threshold_prunes": trail_prunes,
        "complete_model_only_prunes": model_prunes,
        "late_only_prune": trail_prunes == 0 and model_prunes > 0,
        "useful_prune_or_bound_progress": classification
        in (
            "EXACT_CONSUMED_FULL256_RECOVERY",
            "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY",
        ),
    }


def _invoke_native_once(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    threshold: float,
    conflict_limit: int,
    timeout_seconds: float,
    memory_limit_bytes: int,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> JointScoreSieveResult:
    return runner(
        executable=executable,
        cnf_path=cnf,
        potential_path=potential,
        threshold=threshold,
        conflict_limit=conflict_limit,
        seed=0,
        timeout_seconds=timeout_seconds,
        memory_limit_bytes=memory_limit_bytes,
    )


def _invoke_native_once_terminal(
    *,
    executable: Path,
    cnf: Path,
    potential: Path,
    threshold: float,
    conflict_limit: int,
    timeout_seconds: float,
    memory_limit_bytes: int,
    runner: Callable[..., JointScoreSieveResult] = run_joint_score_sieve,
) -> tuple[JointScoreSieveResult | None, dict[str, object] | None]:
    """Convert every post-intent execution failure into terminalizable data."""

    try:
        result = _invoke_native_once(
            executable=executable,
            cnf=cnf,
            potential=potential,
            threshold=threshold,
            conflict_limit=conflict_limit,
            timeout_seconds=timeout_seconds,
            memory_limit_bytes=memory_limit_bytes,
            runner=runner,
        )
    except Exception as exc:
        return None, {
            "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "occurred_after_persisted_intent": True,
            "native_calls_consumed": 1,
            "retry_authorized": False,
            "truth_key_bytes_read": False,
        }
    return result, None


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C59RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    required = _mapping(source.get("required_commits"), "required_commits")
    target = _mapping(config.get("consumed_target"), "consumed_target")
    composition = _mapping(config.get("composition"), "composition")
    threshold = _mapping(config.get("threshold"), "threshold")
    native = _mapping(config.get("native"), "native")
    classification = _mapping(config.get("classification"), "classification")
    budgets = _mapping(config.get("budgets"), "budgets")
    expected_hash_names = {
        *SOURCE_NAMES,
        "consumed_manifest",
        "consumed_config",
        "consumed_publication",
        "consumed_score_freeze",
        "consumed_freeze_receipt",
        "consumed_reveal",
        "consumed_candidate_keys",
        "consumed_prefix8_primary",
    }
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "multiblock-joint-score-sieve-v1"
        or config.get("claim_level") != "TEST"
        or source.get("consumed_capsule") != CONSUMED_CAPSULE_RELATIVE.as_posix()
        or set(expected) != expected_hash_names
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in expected.values()
        )
        or required
        != {"joint_score_sieve": "3ca85ff", "multiblock_adapters": "8c28958"}
        or target.get("source_attempt") != "O1C-0057"
        or target.get("target_id") != "o1c-0057-multiblock-fresh-0000"
        or target.get("block_count") != BLOCK_COUNT
        or target.get("counter_schedule") != "eight-contiguous-without-wrap"
        or target.get("rounds") != 20
        or target.get("feed_forward") is not True
        or target.get("unknown_key_bits") != 256
        or target.get("fresh_entropy_calls") != 0
        or target.get("fresh_reveal_calls") != 0
        or target.get("fresh_forward_scoring_calls") != 0
        or target.get("refits") != 0
        or target.get("primary_arm_only") is not True
        or target.get(
            "post_reveal_result_container_read_pre_native_for_provenance_and_pre_reveal_scorer_metadata"
        )
        is not True
        or target.get("truth_labelled_result_fields_used_as_native_or_decision_input")
        is not False
        or target.get(
            "reveal_and_truth_key_bytes_read_after_native_and_public_model_diagnostic_only"
        )
        is not True
        or composition.get("shared_key_variables") != 256
        or composition.get("block_count") != BLOCK_COUNT
        or composition.get("expected_variable_count") != EXPECTED_VARIABLES
        or composition.get("expected_clause_count") != EXPECTED_CLAUSES
        or composition.get("expected_public_unit_clause_count") != 5120
        or composition.get("expected_key_unit_clause_count") != 0
        or composition.get("expected_assumption_unit_clause_count") != 0
        or composition.get("expected_factor_count") != EXPECTED_FACTORS
        or composition.get("expected_energy_entries") != EXPECTED_ENERGY_ENTRIES
        or composition.get("expected_observed_variables")
        != EXPECTED_OBSERVED_VARIABLES
        or composition.get("maximum_observed_variable") != EXPECTED_VARIABLES
        or composition.get("expected_truth_compiled_score") != EXPECTED_TRUTH_SCORE
        or composition.get("complete_score_absolute_tolerance") != SCORE_TOLERANCE
        or composition.get("truth_score_absolute_tolerance")
        != TRUTH_SCORE_TOLERANCE
        or composition.get("verification_only_forward_assignments")
        != DECOY_COUNT * BLOCK_COUNT + BLOCK_COUNT
        or threshold.get("decoy_count") != DECOY_COUNT
        or threshold.get("expected_decoy_max") != EXPECTED_DECOY_MAX
        or threshold.get("safety_margin") != SCORE_TOLERANCE
        or threshold.get("rule")
        != "nextafter(decoy_max-safety_margin,-infinity)"
        or threshold.get("minimum_material_bound_drop") != 1.0
        or native.get("conflict_limit") != CONFLICT_LIMIT
        or native.get("seed") != 0
        or native.get("timeout_seconds") != NATIVE_TIMEOUT_SECONDS
        or native.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or native.get("non_darwin_memory_enforcement")
        != "child-RLIMIT_AS-before-exec"
        or native.get("darwin_memory_enforcement")
        != "proc_pid_rusage-physical-footprint-process-group-watchdog"
        or native.get("darwin_watchdog_poll_interval_seconds")
        != JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
        or native.get("darwin_watchdog_guard_bytes")
        != JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
        or native.get("darwin_watchdog_temporal_blindspot")
        != "nominally-at-most-one-10ms-poll-interval;OS-scheduling-delay-is-not-hard-bounded;32MiB-guard-reserved-below-formal-ceiling"
        or native.get("decision_rule") != "solver-owned-no-external-decisions"
        or native.get("calls") != 1
        or classification.get("exact") != "EXACT_CONSUMED_FULL256_RECOVERY"
        or classification.get("active")
        != "EXACT_JOINT_SCORE_SIEVE_ACTIVE_NO_RECOVERY"
        or classification.get("no_useful_prune")
        != "EXACT_JOINT_SCORE_SIEVE_NO_USEFUL_PRUNE"
        or classification.get("active_rule")
        != "trail_threshold_prunes>0 or (complete_model_score_checks==0 and (root_upper_bound-minimum_upper_bound)>=minimum_material_bound_drop); complete-model-only prunes and bound minima not separable from a visited complete model are conservatively late-only"
        or budgets.get("maximum_native_solver_calls") != 1
        or budgets.get("maximum_conflicts") != CONFLICT_LIMIT
        or budgets.get("maximum_native_wall_seconds") != NATIVE_TIMEOUT_SECONDS
        or budgets.get("maximum_peak_rss_bytes") != MEMORY_LIMIT_BYTES
        or budgets.get("minimum_memory_pressure_free_percent") != 15
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_scientific_entropy_calls") != 0
        or budgets.get("maximum_fresh_reveal_calls") != 0
        or budgets.get("maximum_refits") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 134_217_728
    ):
        raise O1C59RunError("frozen O1C-0059 config differs")
    for name in SOURCE_NAMES:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if sha256_file(resolved) != expected[name]:
            raise O1C59RunError(f"source hash differs for {name}")
    capsule = _relative_path(root, source.get("consumed_capsule"), "consumed_capsule")
    consumed_artifacts = {
        "consumed_manifest": capsule / "artifacts.sha256",
        "consumed_config": capsule / "config.json",
        "consumed_publication": capsule / "publication.json",
        "consumed_score_freeze": capsule / "score_freeze.json",
        "consumed_freeze_receipt": capsule / "freeze_receipt.json",
        "consumed_reveal": capsule / "reveal.json",
        "consumed_candidate_keys": capsule / "candidate_keys.bin",
        "consumed_prefix8_primary": capsule
        / "scores/prefix-08-primary.f64le",
    }
    for name, artifact in consumed_artifacts.items():
        if sha256_file(artifact.resolve(strict=True)) != expected[name]:
            raise O1C59RunError(f"consumed source hash differs for {name}")
    _required_commit_is_ancestor(root, str(required["joint_score_sieve"]), "core")
    _required_commit_is_ancestor(
        root, str(required["multiblock_adapters"]), "adapter"
    )
    return config


def _verify_consumed_o1c57(
    root: Path,
    config: Mapping[str, object],
    source_paths: Mapping[str, Path],
) -> ConsumedO1C57:
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "expected_sha256")
    capsule = (root / CONSUMED_CAPSULE_RELATIVE).resolve(strict=True)
    inventory = _manifest_inventory(
        capsule, expected_manifest_sha256=str(expected["consumed_manifest"])
    )
    authoritative_bytes = source_paths["consumed_result"].read_bytes()
    if (
        capsule.joinpath("result.json").read_bytes() != authoritative_bytes
        or hashlib.sha256(authoritative_bytes).hexdigest()
        != expected["consumed_result"]
        or inventory.get("result.json") != expected["consumed_result"]
    ):
        raise O1C59RunError("consumed O1C-0057 authoritative result differs")
    result = _read_json(source_paths["consumed_result"])
    publication = _read_json(capsule / "publication.json")
    score_freeze = _read_json(capsule / "score_freeze.json")
    receipt = _read_json(capsule / "freeze_receipt.json")
    public = public_view_from_publication(publication)
    if (
        result.get("schema") != "o1-256-multiblock-parent-criticality-rank-result-v1"
        or result.get("attempt_id") != "O1C-0057"
        or result.get("capsule") != CONSUMED_CAPSULE_RELATIVE.as_posix()
        or result.get("publication_sha256") != publication.get("publication_sha256")
        or result.get("public_view_sha256") != public.digest()
        or result.get("score_freeze_sha256")
        != hashlib.sha256((capsule / "score_freeze.json").read_bytes()).hexdigest()
        or result.get("freeze_receipt_sha256") != receipt.get("receipt_sha256")
        or score_freeze.get("schema")
        != "o1-256-multiblock-parent-criticality-score-freeze-v1"
        or score_freeze.get("attempt_id") != "O1C-0057"
        or score_freeze.get("block_count") != BLOCK_COUNT
        or score_freeze.get("target_key_reads") != 0
        or score_freeze.get("reveal_calls") != 0
        or score_freeze.get("publication_sha256")
        != publication.get("publication_sha256")
        or score_freeze.get("full_public_view_sha256") != public.digest()
        or receipt.get("frozen_artifact_sha256")
        != result.get("score_freeze_sha256")
        or public.block_count != BLOCK_COUNT
        or public.counter_schedule
        != tuple(range(public.counter_schedule[0], public.counter_schedule[0] + 8))
    ):
        raise O1C59RunError("consumed O1C-0057 lifecycle differs")
    candidate_payload = (capsule / "candidate_keys.bin").read_bytes()
    if (
        len(candidate_payload) != DECOY_COUNT * 32
        or hashlib.sha256(candidate_payload).hexdigest()
        != score_freeze.get("candidate_keys_sha256")
    ):
        raise O1C59RunError("consumed O1C-0057 candidate panel differs")
    candidate_keys = tuple(
        candidate_payload[index : index + 32]
        for index in range(0, len(candidate_payload), 32)
    )
    if len(candidate_keys) != DECOY_COUNT or len(set(candidate_keys)) != DECOY_COUNT:
        raise O1C59RunError("consumed O1C-0057 candidate panel is not unique")
    reader_row = _mapping(result.get("reader"), "O1C-0057 reader")
    if reader_row.get("feature_names") != list(FEATURE_NAMES):
        raise O1C59RunError("consumed O1C-0057 feature order differs")
    reader = _reader_vector(reader_row.get("weights_l2"))
    raw_block_rows = result.get("pre_reveal_block_rows")
    freeze_block_rows = score_freeze.get("block_rows")
    natural_descriptions = result.get("natural_fields")
    freeze_descriptions = score_freeze.get("natural_fields")
    instance_hashes = result.get("instance_sha256")
    if (
        not isinstance(raw_block_rows, list)
        or not isinstance(freeze_block_rows, list)
        or raw_block_rows != freeze_block_rows
        or not isinstance(natural_descriptions, list)
        or not isinstance(freeze_descriptions, list)
        or natural_descriptions != freeze_descriptions
        or not isinstance(instance_hashes, list)
        or instance_hashes != score_freeze.get("instance_sha256")
        or len(natural_descriptions) != BLOCK_COUNT
        or len(instance_hashes) != BLOCK_COUNT
    ):
        raise O1C59RunError("consumed O1C-0057 frozen field inventory differs")
    primary_rows = {
        int(cast(int, row["block_index"])): row
        for row in raw_block_rows
        if isinstance(row, Mapping) and row.get("arm") == "primary"
    }
    if set(primary_rows) != set(range(BLOCK_COUNT)):
        raise O1C59RunError("consumed O1C-0057 primary rows differ")
    fields: list[ParentCriticalityField] = []
    means: list[np.ndarray] = []
    stds: list[np.ndarray] = []
    scalar_means: list[float] = []
    scalar_stds: list[float] = []
    raw_scores: list[np.ndarray] = []
    z_scores: list[np.ndarray] = []
    natural_hashes = score_freeze.get("natural_field_sha256")
    if not isinstance(natural_hashes, list) or len(natural_hashes) != BLOCK_COUNT:
        raise O1C59RunError("consumed O1C-0057 natural field hashes differ")
    for block_index in range(BLOCK_COUNT):
        row = _mapping(primary_rows[block_index], "primary block row")
        field_path = capsule / f"fields/block-{block_index:02d}.bin"
        payload = field_path.read_bytes()
        field = ParentCriticalityField.from_bytes(payload)
        description = _mapping(
            natural_descriptions[block_index], "natural field description"
        )
        if (
            hashlib.sha256(payload).hexdigest() != natural_hashes[block_index]
            or field.state_sha256 != natural_hashes[block_index]
            or row.get("field_sha256") != natural_hashes[block_index]
            or row.get("field_description") != description
            or field.source_sha256 != description.get("source_sha256")
            or len(field.factors) != description.get("factor_count")
            or field.serialized_bytes != description.get("serialized_bytes")
            or field.conflict_horizon != description.get("conflict_horizon")
            or hashlib.sha256(field.factor_file_bytes()).hexdigest()
            != description.get("factor_file_sha256")
            or row.get("counter") != public.counter_schedule[block_index]
            or row.get("candidate_keys_sha256")
            != hashlib.sha256(candidate_payload).hexdigest()
        ):
            raise O1C59RunError("consumed O1C-0057 field binding differs")
        mean = _feature_vector(row.get("feature_mean"), "feature mean")
        std = _feature_vector(
            row.get("feature_std"), "feature standard deviation", nonnegative=True
        )
        scalar_mean = row.get("scalar_decoy_mean")
        scalar_std = row.get("scalar_decoy_std_ddof1")
        if (
            isinstance(scalar_mean, bool)
            or not isinstance(scalar_mean, (int, float))
            or not math.isfinite(float(scalar_mean))
            or isinstance(scalar_std, bool)
            or not isinstance(scalar_std, (int, float))
            or not math.isfinite(float(scalar_std))
            or float(scalar_std) <= 0.0
        ):
            raise O1C59RunError("consumed O1C-0057 scalar calibration differs")
        raw = _float_vector(
            capsule / f"scores/raw/block-{block_index:02d}-primary.f64le",
            count=DECOY_COUNT,
            digest=str(row["raw_score_sha256"]),
        )
        z = _float_vector(
            capsule / f"scores/scalar-z/block-{block_index:02d}-primary.f64le",
            count=DECOY_COUNT,
            digest=str(row["scalar_z_sha256"]),
        )
        recomputed_z = (raw - float(scalar_mean)) / float(scalar_std)
        if not np.array_equal(recomputed_z, z):
            raise O1C59RunError("consumed O1C-0057 scalar z scores differ")
        fields.append(field)
        means.append(mean)
        stds.append(std)
        scalar_means.append(float(scalar_mean))
        scalar_stds.append(float(scalar_std))
        raw_scores.append(raw)
        z_scores.append(z)
    running = np.zeros(DECOY_COUNT, dtype=np.float64)
    for z in z_scores:
        running = np.add(running, z, dtype=np.float64)
    frozen_joint = _float_vector(
        capsule / "scores/prefix-08-primary.f64le",
        count=DECOY_COUNT,
        digest=str(expected["consumed_prefix8_primary"]),
    )
    if not np.array_equal(running, frozen_joint):
        raise O1C59RunError("consumed O1C-0057 prefix-8 scores differ")
    decoy_max = float(np.max(frozen_joint))
    if decoy_max != EXPECTED_DECOY_MAX:
        raise O1C59RunError("consumed O1C-0057 decoy maximum differs")
    return ConsumedO1C57(
        capsule=capsule,
        result=result,
        score_freeze=score_freeze,
        publication=publication,
        public=public,
        candidate_keys=candidate_keys,
        fields=tuple(fields),
        reader=reader,
        feature_means=tuple(means),
        feature_stds=tuple(stds),
        scalar_means=tuple(scalar_means),
        scalar_stds=tuple(scalar_stds),
        raw_scores=tuple(raw_scores),
        frozen_joint_scores=frozen_joint,
        instance_sha256=tuple(str(value) for value in instance_hashes),
        manifest_sha256=str(expected["consumed_manifest"]),
    )


def _build_exact_composition(
    consumed: ConsumedO1C57,
    *,
    template: Path,
    semantic_map: Path,
    workspace: Path,
) -> tuple[
    tuple[InstanceWriteReport, ...],
    Full256MultiblockCNFReport,
    CriticalityPotentialField,
    Path,
    Path,
]:
    reports: list[InstanceWriteReport] = []
    instances: list[tuple[Path, InstanceWriteReport]] = []
    for block_index in range(BLOCK_COUNT):
        block_path = workspace / f"block-{block_index:02d}.cnf"
        report = write_full256_instance(
            template,
            semantic_map,
            block_path,
            counter=consumed.public.counter_schedule[block_index],
            nonce=consumed.public.nonce,
            output=consumed.public.output_blocks[block_index],
        )
        verification = verify_full256_instance(
            block_path, template, semantic_map, report
        )
        if (
            verification.get("ok") is not True
            or report.instance_sha256 != consumed.instance_sha256[block_index]
            or report.public_unit_clause_count != 640
            or report.key_unit_clause_count != 0
            or report.assumption_unit_clause_count != 0
            or report.key_fixed_for_self_test
        ):
            raise O1C59RunError("consumed one-block public CNF differs")
        reports.append(report)
        instances.append((block_path, report))
    multiblock_cnf = workspace / "full256-eight-block-shared-key.cnf"
    multiblock_report_path = workspace / "full256-eight-block-shared-key.report.json"
    multiblock_report = write_full256_multiblock_cnf(
        template,
        semantic_map,
        instances,
        multiblock_cnf,
        report_path=multiblock_report_path,
    )
    verification = verify_full256_multiblock_cnf(
        multiblock_cnf,
        template,
        semantic_map,
        instances,
        multiblock_report,
    )
    if (
        verification.get("ok") is not True
        or multiblock_report.variable_count != EXPECTED_VARIABLES
        or multiblock_report.clause_count != EXPECTED_CLAUSES
        or multiblock_report.public_unit_clause_count != 5120
        or multiblock_report.key_unit_clause_count != 0
        or multiblock_report.assumption_unit_clause_count != 0
    ):
        raise O1C59RunError("exact eight-block CNF composition differs")
    potential = compile_multiblock_criticality_potential(
        consumed.fields,
        counters=consumed.public.counter_schedule,
        feature_means=consumed.feature_means,
        feature_stds=consumed.feature_stds,
        reader=consumed.reader,
        scalar_score_means=consumed.scalar_means,
        scalar_score_stds=consumed.scalar_stds,
    )
    potential_path = workspace / "primary-eight-block.potential"
    potential_sha = write_joint_score_sieve_potential(potential_path, potential)
    reparsed = CriticalityPotentialField.from_bytes(potential_path.read_bytes())
    description = potential.describe()
    if (
        reparsed != potential
        or potential_sha != potential.state_sha256
        or description["factor_count"] != EXPECTED_FACTORS
        or description["truth_table_entries"] != EXPECTED_ENERGY_ENTRIES
        or description["observed_variable_count"] != EXPECTED_OBSERVED_VARIABLES
        or max(potential.observed_variables) > EXPECTED_VARIABLES
    ):
        raise O1C59RunError("exact eight-block potential composition differs")
    return (
        tuple(reports),
        multiblock_report,
        potential,
        multiblock_cnf,
        potential_path,
    )


def _global_assignment(
    runtime: EquivalenceRuntime,
    *,
    key: bytes,
    public: PublicTargetView,
) -> tuple[dict[int, int], tuple[float, ...]]:
    global_assignment: dict[int, int] = {}
    raw_scores: list[float] = []
    for block_index, (local_potential, plan) in enumerate(
        zip(runtime.local_potentials, runtime.forward_plans, strict=True)
    ):
        local = plan.evaluate(
            key=key,
            counter=public.counter_schedule[block_index],
            nonce=public.nonce,
        )
        raw_scores.append(score_potential_assignment(local_potential, local))
        for variable, spin in local.items():
            remapped = remap_full256_variable(variable, block_index)
            previous = global_assignment.setdefault(remapped, spin)
            if previous != spin:
                raise O1C59RunError("shared-key forward assignment differs")
    return global_assignment, tuple(raw_scores)


def _verify_complete_score_equivalence(
    consumed: ConsumedO1C57,
    potential: CriticalityPotentialField,
    *,
    semantic_map: Path,
    tolerance: float,
) -> EquivalenceRuntime:
    local_potentials = tuple(
        compile_criticality_potential(
            consumed.fields[block_index],
            feature_mean=consumed.feature_means[block_index],
            feature_std=consumed.feature_stds[block_index],
            reader=consumed.reader,
        )
        for block_index in range(BLOCK_COUNT)
    )
    plans = tuple(
        compile_full256_forward_read_plan(
            semantic_map, local_potential.observed_variables
        )
        for local_potential in local_potentials
    )
    provisional = EquivalenceRuntime(local_potentials, plans, {})
    maximum_local_error = 0.0
    maximum_merged_error = 0.0
    maximum_component_error = 0.0
    compiled_scores = np.empty(DECOY_COUNT, dtype=np.float64)
    for candidate_index, key in enumerate(consumed.candidate_keys):
        assignment, local_scores = _global_assignment(
            provisional, key=key, public=consumed.public
        )
        for block_index, actual in enumerate(local_scores):
            maximum_local_error = max(
                maximum_local_error,
                float(
                    abs(actual - consumed.raw_scores[block_index][candidate_index])
                ),
            )
        component_score = math.fsum(
            (local_scores[block_index] - consumed.scalar_means[block_index])
            / consumed.scalar_stds[block_index]
            for block_index in range(BLOCK_COUNT)
        )
        merged_score = score_potential_assignment(potential, assignment)
        expected = float(consumed.frozen_joint_scores[candidate_index])
        maximum_component_error = max(
            maximum_component_error, abs(component_score - expected)
        )
        maximum_merged_error = max(maximum_merged_error, abs(merged_score - expected))
        compiled_scores[candidate_index] = merged_score
    if (
        maximum_local_error > tolerance
        or maximum_component_error > tolerance
        or maximum_merged_error > tolerance
    ):
        raise O1C59RunError("complete decoy score equivalence differs")
    report = {
        "schema": EQUIVALENCE_SCHEMA,
        "decoy_count": DECOY_COUNT,
        "block_count": BLOCK_COUNT,
        "primary_only": True,
        "complete_assignments": DECOY_COUNT,
        "forward_plan_evaluations": DECOY_COUNT * BLOCK_COUNT,
        "scientific_forward_scoring_calls": 0,
        "purpose": "deterministic-complete-assignment-adapter-equivalence-only",
        "absolute_tolerance": tolerance,
        "maximum_local_raw_score_absolute_error": maximum_local_error,
        "maximum_component_sum_absolute_error": maximum_component_error,
        "maximum_merged_score_absolute_error": maximum_merged_error,
        "frozen_scores_sha256": array_sha256(consumed.frozen_joint_scores, "<f8"),
        "compiled_scores_sha256": array_sha256(compiled_scores, "<f8"),
        "semantic_map_sha256": plans[0].semantic_sha256,
        "forward_plan_requested_variables": [
            len(plan.requested_variables) for plan in plans
        ],
    }
    return EquivalenceRuntime(local_potentials, plans, report)


def _verify_truth_after_native(
    consumed: ConsumedO1C57,
    runtime: EquivalenceRuntime,
    potential: CriticalityPotentialField,
    *,
    native: JointScoreSieveResult,
    public_model_diagnostic_complete: bool,
) -> tuple[bytes, float, Mapping[str, object]]:
    if not public_model_diagnostic_complete:
        raise O1C59RunError("truth access preceded native model diagnostic")
    reveal = verify_reveal(_read_json(consumed.capsule / "reveal.json"))
    publication = _mapping(reveal.get("publication"), "consumed reveal publication")
    receipt = _mapping(reveal.get("freeze_receipt"), "consumed reveal receipt")
    preimage = _mapping(reveal.get("commitment_preimage"), "consumed reveal preimage")
    frozen_receipt = _read_json(consumed.capsule / "freeze_receipt.json")
    if (
        publication != consumed.publication
        or receipt != frozen_receipt
        or receipt.get("frozen_artifact_sha256")
        != hashlib.sha256(
            (consumed.capsule / "score_freeze.json").read_bytes()
        ).hexdigest()
    ):
        raise O1C59RunError("consumed reveal lifecycle differs")
    try:
        truth_key = bytes.fromhex(str(preimage["key_hex"]))
    except (KeyError, ValueError) as exc:
        raise O1C59RunError("consumed truth key encoding differs") from exc
    if (
        len(truth_key) != 32
        or hashlib.sha256(truth_key).hexdigest()
        != consumed.result.get("truth_key_sha256")
        or chacha20_blocks(
            truth_key,
            consumed.public.counter_schedule[0],
            consumed.public.nonce,
            BLOCK_COUNT,
        )
        != consumed.public.output_blocks
    ):
        raise O1C59RunError("consumed truth fails exact eight-block verification")
    assignment, _ = _global_assignment(runtime, key=truth_key, public=consumed.public)
    truth_score = verify_multiblock_complete_score_equivalence(
        potential,
        consumed.fields,
        assignment,
        counters=consumed.public.counter_schedule,
        feature_means=consumed.feature_means,
        feature_stds=consumed.feature_stds,
        reader=consumed.reader,
        scalar_score_means=consumed.scalar_means,
        scalar_score_stds=consumed.scalar_stds,
        absolute_tolerance=TRUTH_SCORE_TOLERANCE,
    )
    if not math.isclose(
        truth_score,
        EXPECTED_TRUTH_SCORE,
        rel_tol=0.0,
        abs_tol=TRUTH_SCORE_TOLERANCE,
    ):
        raise O1C59RunError("consumed truth compiled score differs")
    if native.status == 20:
        raise O1C59RunError("native UNSAT contradicts consumed above-threshold truth")
    return truth_key, truth_score, reveal


def _capsule_manifest(capsule: Path, *, exclude: set[str]) -> tuple[bytes, int]:
    rows: list[str] = []
    total = 0
    for path in sorted(capsule.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(capsule).as_posix()
        if relative in exclude:
            continue
        rows.append(f"{sha256_file(path)}  {relative}\n")
        total += path.stat().st_size
    payload = "".join(rows).encode("ascii")
    return payload, total + len(payload)


def _markdown(result: Mapping[str, object]) -> str:
    classification = str(result["classification"])
    if classification.startswith("OPERATIONAL_"):
        failure = _mapping(result["operational_failure"], "operational_failure")
        return (
            f"# O1C Run {ATTEMPT_ID}\n\n"
            f"- Classification: `{classification}`\n"
            f"- Error type: `{failure['error_type']}`\n"
            f"- Native calls consumed: `{failure['native_calls_consumed']}`\n"
            "- Retry authorized: `False`\n\n"
            "The persisted one-shot intent was consumed, but the run did not "
            "produce a validated scientific claim. The capsule is terminal and "
            "immutable; the persisted lifecycle fields record whether truth access "
            "had begun or completed.\n"
        )
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Native status: `{metrics['native_status']}`\n"
        f"- Safe trail prunes: `{metrics['safe_trail_threshold_prunes']}`\n"
        f"- Root-to-minimum bound drop: `{metrics['root_to_minimum_bound_drop']}`\n"
        f"- Exact consumed recovery: `{metrics['exact_consumed_recovery']}`\n"
        f"- Native wall seconds: `{resources['native_wall_seconds']}`\n"
        f"- Native peak RSS bytes: `{resources['native_peak_rss_bytes']}`\n\n"
        "One exact solver-owned joint-score-sieve call consumed the immutable "
        "O1C-0057 eight-block target. No fresh target, entropy, reveal, reader "
        "fit, score arm, external SAT decision, MPS, or GPU was used.\n"
    )


def _replace_owned_json(path: Path, value: object) -> bytes:
    payload = _canonical_json_bytes(value)
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
    return payload


def _finalize_capsule(
    *,
    root: Path,
    capsule: Path,
    result: dict[str, object],
    maximum_persistent_bytes: int,
) -> None:
    if (capsule / "artifacts.sha256").exists():
        raise O1C59RunError("O1C-0059 capsule is already terminal")
    run_path = capsule / "RUN.md"
    if not run_path.exists():
        _atomic_bytes(run_path, _markdown(result).encode("utf-8"))
    resources_row = cast(dict[str, object], result["resources"])
    result_path = capsule / "result.json"
    for _ in range(8):
        _replace_owned_json(result_path, result)
        manifest, persistent = _capsule_manifest(
            capsule, exclude={"artifacts.sha256"}
        )
        if resources_row["persistent_artifact_bytes"] == persistent:
            break
        resources_row["persistent_artifact_bytes"] = persistent
    else:
        raise O1C59RunError("persistent artifact ledger did not converge")
    if persistent > maximum_persistent_bytes:
        raise O1C59RunError("persistent artifact budget differs")
    _atomic_bytes(capsule / "artifacts.sha256", manifest)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        if path.is_file():
            path.chmod(0o444)
        elif path.is_dir():
            path.chmod(0o555)
    capsule.chmod(0o555)
    _atomic_json(root / RESULT_RELATIVE, result)


def _make_capsule_writable(capsule: Path) -> None:
    capsule.chmod(0o755)
    for path in sorted(capsule.rglob("*"), key=lambda item: len(item.parts)):
        if path.is_symlink():
            raise O1C59RunError("post-native capsule contains a symbolic link")
        path.chmod(0o755 if path.is_dir() else 0o644)


def _optional_mapping(path: Path) -> Mapping[str, object]:
    if not path.is_file():
        return {}
    try:
        return _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _terminalize_post_native_failure(
    *,
    root: Path,
    capsule: Path,
    error: Exception,
) -> dict[str, object]:
    native_path = capsule / "native_result.json"
    intent_path = capsule / "native_call_intent.json"
    if not native_path.is_file() or not intent_path.is_file():
        raise O1C59RunError("post-native terminalization lacks persisted evidence")
    native_payload = native_path.read_bytes()
    native_raw = _read_json(native_path)
    intent = _optional_mapping(intent_path)
    preflight = _optional_mapping(capsule / "preflight.json")
    public_diagnostic_complete = (
        capsule / "public_model_diagnostic.json"
    ).is_file()
    truth_intent = (capsule / "truth_access_intent.json").is_file()
    truth_receipt = (capsule / "truth_access_receipt.json").is_file()
    if truth_receipt:
        truth_access_stage = "COMPLETED_RECEIPT_PERSISTED"
        truth_key_bytes_read: bool | None = True
    elif truth_intent:
        truth_access_stage = "STARTED_RECEIPT_ABSENT_READ_STATE_UNKNOWN"
        truth_key_bytes_read = None
    else:
        truth_access_stage = "NOT_STARTED"
        truth_key_bytes_read = False
    native_calls_consumed = int(cast(int, intent.get("calls_authorized", 1)))
    recorded_at = datetime.now().astimezone().isoformat(timespec="seconds")
    failure = {
        "classification": (
            "OPERATIONAL_POST_NATIVE_VALIDATION_FAILURE_NO_SCIENCE_CLAIM"
        ),
        "error_type": type(error).__name__,
        "error_message": str(error),
        "occurred_after_persisted_intent": True,
        "occurred_after_persisted_native_result": True,
        "native_calls_consumed": native_calls_consumed,
        "native_result_preserved": True,
        "native_result_sha256": hashlib.sha256(native_payload).hexdigest(),
        "public_model_diagnostic_complete": public_diagnostic_complete,
        "truth_access_intent_persisted": truth_intent,
        "truth_access_receipt_persisted": truth_receipt,
        "truth_access_stage": truth_access_stage,
        "truth_key_bytes_read": truth_key_bytes_read,
        "retry_authorized": False,
    }
    try:
        capsule_relative = capsule.relative_to(root).as_posix()
    except ValueError as exc:
        raise O1C59RunError("post-native capsule escapes lab") from exc
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": intent.get("recorded_at", recorded_at),
        "recorded_at": recorded_at,
        "source_commit": preflight.get("source_commit"),
        "classification": (
            "OPERATIONAL_POST_NATIVE_VALIDATION_FAILURE_NO_SCIENCE_CLAIM"
        ),
        "capsule": capsule_relative,
        "claim_boundary": {
            "consumed_attempt": "O1C-0057",
            "consumed_target": True,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "native_solver_calls": native_calls_consumed,
            "persisted_intent_consumed": True,
            "persisted_native_result": True,
            "validated_native_science_result": False,
            "public_model_diagnostic_complete": public_diagnostic_complete,
            "truth_access_stage": truth_access_stage,
            "reveal_and_truth_key_bytes_read": truth_key_bytes_read,
            "retry_authorized": False,
            "exact_key_recovery": False,
        },
        "operational_failure": failure,
        "native": native_raw,
        "metrics": {
            "native_status": "UNVALIDATED_POST_NATIVE_RESULT",
            "exact_consumed_recovery": False,
        },
        "resources": {
            "native_solver_calls": native_calls_consumed,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "preflight": dict(preflight),
        "next_action": (
            "Do not retry O1C-0059. Diagnose the immutable post-native "
            "validation failure and use a new attempt ID after repair."
        ),
    }
    _make_capsule_writable(capsule)
    for stale_name in (
        "artifacts.sha256",
        "result.json",
        "RUN.md",
        "post_native_validation_failure.json",
    ):
        stale_path = capsule / stale_name
        if stale_path.exists():
            stale_path.unlink()
    _atomic_json(capsule / "post_native_validation_failure.json", failure)
    if native_path.read_bytes() != native_payload:
        raise O1C59RunError("persisted native result changed during terminalization")
    _finalize_capsule(
        root=root,
        capsule=capsule,
        result=result,
        maximum_persistent_bytes=sys.maxsize,
    )
    return result


def _run_impl(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    if (root / RESULT_RELATIVE).exists():
        raise O1C59RunError("authoritative O1C-0059 output already exists")
    prior_capsules = tuple(root.glob("runs/*_O1C-0059_multiblock-joint-score-sieve-v1"))
    if prior_capsules:
        raise O1C59RunError("O1C-0059 capsule already exists; refusing another call")
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    threshold_config = _mapping(config["threshold"], "threshold")
    budgets = _mapping(config["budgets"], "budgets")
    source_paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in SOURCE_NAMES
    }
    source_commit = _git_commit(root)
    commit_paths = {"config": config_file, **source_paths}
    for name in COMMIT_BOUND_NAMES:
        _commit_bound_bytes(root, source_commit, commit_paths[name], name)
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    memory_free = _memory_free_percent()
    if (
        memory_free is not None
        and memory_free
        < int(cast(int, budgets["minimum_memory_pressure_free_percent"]))
    ):
        raise O1C59RunError("memory-pressure preflight is below frozen gate")
    memory_enforcement = (
        "proc_pid_rusage-physical-footprint-process-group-watchdog"
        if sys.platform == "darwin"
        else "child-RLIMIT_AS-before-exec"
    )
    preflight = {
        "schema": PREFLIGHT_SCHEMA,
        "observed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "memory_pressure_free_percent": memory_free,
        "minimum_memory_pressure_free_percent": budgets[
            "minimum_memory_pressure_free_percent"
        ],
        "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "native_memory_enforcement": memory_enforcement,
        "darwin_watchdog_poll_interval_seconds": (
            JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_INTERVAL_SECONDS
            if sys.platform == "darwin"
            else None
        ),
        "darwin_watchdog_guard_bytes": (
            JOINT_SCORE_SIEVE_DARWIN_WATCHDOG_GUARD_BYTES
            if sys.platform == "darwin"
            else None
        ),
        "darwin_watchdog_temporal_blindspot": (
            "nominally-at-most-one-10ms-poll-interval;OS-scheduling-delay-is-not-hard-bounded;32MiB-guard-reserved-below-formal-ceiling"
            if sys.platform == "darwin"
            else None
        ),
        "load_average": list(os.getloadavg()),
        "cpu_count": os.cpu_count(),
        "fresh_targets": 0,
        "scientific_entropy_calls": 0,
        "fresh_reveal_calls": 0,
        "solver_calls_before_intent": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "MPS_or_GPU": False,
    }
    consumed = _verify_consumed_o1c57(root, config, source_paths)
    threshold = prospective_threshold(
        float(np.max(consumed.frozen_joint_scores)),
        float(cast(float, threshold_config["safety_margin"])),
    )
    solver_calls = 0
    capsule: Path | None = None
    with tempfile.TemporaryDirectory(prefix="o1c59-") as temporary:
        workspace = Path(temporary)
        (
            block_reports,
            multiblock_report,
            potential,
            multiblock_cnf,
            potential_path,
        ) = _build_exact_composition(
            consumed,
            template=source_paths["template"],
            semantic_map=source_paths["semantic_map"],
            workspace=workspace,
        )
        equivalence = _verify_complete_score_equivalence(
            consumed,
            potential,
            semantic_map=source_paths["semantic_map"],
            tolerance=SCORE_TOLERANCE,
        )
        native_build = build_native_joint_score_sieve(
            source=source_paths["native_source"],
            output=workspace / "cadical-o1-joint-score-sieve",
        )
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capsule_relative = (
            Path("runs")
            / f"{stamp}_{ATTEMPT_ID}_multiblock-joint-score-sieve-v1"
        )
        capsule = root / capsule_relative
        capsule.mkdir(parents=True, exist_ok=False)
        _copy_exclusive(
            multiblock_cnf, capsule / "artifacts/cnf/full256-eight-block.cnf"
        )
        _copy_exclusive(
            potential_path,
            capsule / "artifacts/potential/primary-eight-block.potential",
        )
        _atomic_json(
            capsule / "artifacts/cnf/full256-eight-block.report.json",
            multiblock_report.describe(),
        )
        _atomic_json(
            capsule / "artifacts/cnf/source-block-reports.json",
            [report.describe() for report in block_reports],
        )
        _atomic_json(
            capsule / "artifacts/potential/primary-eight-block.report.json",
            potential.describe(),
        )
        _atomic_json(
            capsule / "complete_score_equivalence.json", equivalence.report
        )
        _atomic_json(capsule / "preflight.json", preflight)
        _atomic_json(capsule / "native_build.json", native_build.describe())
        _atomic_bytes(capsule / "config.json", config_file.read_bytes())
        command = (
            "nice -n 10 env PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c59_multiblock_joint_score_sieve_run "
            f"--config {config_file}\n"
        ).encode("utf-8")
        _atomic_bytes(capsule / "command.txt", command)
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "calls_before": solver_calls,
            "calls_authorized": 1,
            "conflict_limit": CONFLICT_LIMIT,
            "seed": 0,
            "timeout_seconds": NATIVE_TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "memory_limit_mechanism": memory_enforcement,
            "darwin_watchdog_poll_interval_seconds": preflight[
                "darwin_watchdog_poll_interval_seconds"
            ],
            "darwin_watchdog_guard_bytes": preflight[
                "darwin_watchdog_guard_bytes"
            ],
            "darwin_watchdog_temporal_blindspot": preflight[
                "darwin_watchdog_temporal_blindspot"
            ],
            "threshold": threshold,
            "cnf_sha256": sha256_file(
                capsule / "artifacts/cnf/full256-eight-block.cnf"
            ),
            "potential_sha256": sha256_file(
                capsule / "artifacts/potential/primary-eight-block.potential"
            ),
            "native_executable_sha256": native_build.executable_sha256,
            "truth_key_reads": 0,
            "fresh_entropy_calls": 0,
            "fresh_reveal_calls": 0,
        }
        _atomic_json(capsule / "native_call_intent.json", intent)
        solver_calls += 1
        if solver_calls != 1:
            raise O1C59RunError("native solver call ledger differs")
        native, native_failure = _invoke_native_once_terminal(
            executable=native_build.executable,
            cnf=capsule / "artifacts/cnf/full256-eight-block.cnf",
            potential=capsule
            / "artifacts/potential/primary-eight-block.potential",
            threshold=threshold,
            conflict_limit=CONFLICT_LIMIT,
            timeout_seconds=NATIVE_TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
        )
        if native_failure is not None:
            if native is not None:
                raise O1C59RunError("terminal native failure contains a result")
            _atomic_json(capsule / "native_failure.json", native_failure)
            child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
            failure_result: dict[str, object] = {
                "schema": RESULT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "started_at": started_at,
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "source_commit": source_commit,
                "classification": "OPERATIONAL_NATIVE_FAILURE_NO_SCIENCE_RESULT",
                "capsule": capsule_relative.as_posix(),
                "claim_boundary": {
                    "consumed_attempt": "O1C-0057",
                    "consumed_target": True,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "native_solver_calls": solver_calls,
                    "persisted_intent_consumed": True,
                    "validated_native_science_result": False,
                    "reveal_and_truth_key_bytes_read": False,
                    "retry_authorized": False,
                    "exact_key_recovery": False,
                },
                "operational_failure": native_failure,
                "consumed_provenance": {
                    "capsule": CONSUMED_CAPSULE_RELATIVE.as_posix(),
                    "manifest_sha256": consumed.manifest_sha256,
                    "result_sha256": sha256_file(source_paths["consumed_result"]),
                    "publication_sha256": consumed.publication[
                        "publication_sha256"
                    ],
                    "public_view_sha256": consumed.public.digest(),
                },
                "threshold": {
                    "rule": threshold_config["rule"],
                    "decoy_count": DECOY_COUNT,
                    "decoy_max": float(np.max(consumed.frozen_joint_scores)),
                    "safety_margin": SCORE_TOLERANCE,
                    "value": threshold,
                },
                "composition": {
                    "cnf": multiblock_report.describe(),
                    "potential": potential.describe(),
                    "complete_score_equivalence": equivalence.report,
                },
                "native": None,
                "native_build": native_build.describe(),
                "metrics": {
                    "native_status": "OPERATIONAL_FAILURE",
                    "exact_consumed_recovery": False,
                },
                "resources": {
                    "elapsed_seconds": time.perf_counter() - started,
                    "parent_cpu_seconds": time.process_time() - cpu_started,
                    "child_cpu_seconds": (
                        child_end.ru_utime
                        + child_end.ru_stime
                        - child_started.ru_utime
                        - child_started.ru_stime
                    ),
                    "peak_rss_bytes": _peak_rss_bytes(),
                    "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
                    "native_memory_enforcement": memory_enforcement,
                    "native_solver_calls": solver_calls,
                    "conflict_limit": CONFLICT_LIMIT,
                    "fresh_targets": 0,
                    "scientific_entropy_calls": 0,
                    "fresh_reveal_calls": 0,
                    "sibling_reads": 0,
                    "sibling_writes": 0,
                    "MPS_or_GPU": False,
                    "persistent_artifact_bytes": 0,
                },
                "preflight": preflight,
                "source_sha256": {
                    name: sha256_file(path) for name, path in source_paths.items()
                },
                "next_action": (
                    "Do not retry O1C-0059. Diagnose the immutable operational "
                    "failure capsule and assign a new attempt ID only after the "
                    "execution defect is fixed."
                ),
            }
            _finalize_capsule(
                root=root,
                capsule=capsule,
                result=failure_result,
                maximum_persistent_bytes=int(
                    cast(int, budgets["maximum_persistent_artifact_bytes"])
                ),
            )
            return failure_result
        if native is None:
            raise O1C59RunError("native execution returned neither result nor failure")
        _atomic_json(capsule / "native_result.json", native.raw)
        if solver_calls != 1:
            raise O1C59RunError("native solver was invoked more than once")
        public_model_verified = False
        model_score: float | None = None
        if native.key_model is not None:
            public_model_verified = (
                chacha20_blocks(
                    native.key_model,
                    consumed.public.counter_schedule[0],
                    consumed.public.nonce,
                    BLOCK_COUNT,
                )
                == consumed.public.output_blocks
            )
            if not public_model_verified:
                raise O1C59RunError("SAT model fails independent eight-block ChaCha")
            model_assignment, _ = _global_assignment(
                equivalence, key=native.key_model, public=consumed.public
            )
            model_score = score_potential_assignment(potential, model_assignment)
            if model_score < threshold:
                raise O1C59RunError("SAT model score is below frozen threshold")
        public_model_diagnostic_complete = True
        _atomic_json(
            capsule / "public_model_diagnostic.json",
            {
                "complete": True,
                "native_status": native.status_name,
                "native_key_model_present": native.key_model is not None,
                "public_model_verified": public_model_verified,
                "model_score": model_score,
            },
        )
        _atomic_json(
            capsule / "truth_access_intent.json",
            {
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "public_model_diagnostic_complete": True,
            },
        )
        truth_key, truth_score, reveal = _verify_truth_after_native(
            consumed,
            equivalence,
            potential,
            native=native,
            public_model_diagnostic_complete=public_model_diagnostic_complete,
        )
        _atomic_json(
            capsule / "truth_access_receipt.json",
            {
                "recorded_at": datetime.now()
                .astimezone()
                .isoformat(timespec="seconds"),
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                "truth_compiled_score": truth_score,
                "reveal_sha256": reveal["reveal_sha256"],
            },
        )
        classification, gates = classify_sieve(
            native,
            public_model_verified=public_model_verified,
            minimum_material_bound_drop=float(
                cast(float, threshold_config["minimum_material_bound_drop"])
            ),
        )
        child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
        elapsed = time.perf_counter() - started
        native_peak = int(native.resources["peak_rss_bytes"])
        native_wall = int(native.resources["wall_microseconds"]) / 1_000_000.0
        if (
            native.conflict_limit != CONFLICT_LIMIT
            or int(native.stats["conflicts"]) > CONFLICT_LIMIT
            or native_wall > NATIVE_TIMEOUT_SECONDS
            or native_peak > MEMORY_LIMIT_BYTES
            or native.sieve.get("decision_rule") != JOINT_SCORE_SIEVE_DECISION_RULE
            or solver_calls
            != int(cast(int, budgets["maximum_native_solver_calls"]))
        ):
            raise O1C59RunError("O1C-0059 native resource ledger differs")
        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "started_at": started_at,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "classification": classification,
            "capsule": capsule_relative.as_posix(),
            "claim_boundary": {
                "consumed_attempt": "O1C-0057",
                "consumed_target": True,
                "fresh_targets": 0,
                "scientific_entropy_calls": 0,
                "fresh_reveal_calls": 0,
                "refits": 0,
                "new_score_arms": 0,
                "primary_only": True,
                "public_blocks": BLOCK_COUNT,
                "unknown_key_bits": 256,
                "exact_shared_key_cnf": True,
                "safe_outward_rounded_score_bound": True,
                "solver_owned_decisions": True,
                "native_solver_calls": solver_calls,
                "post_reveal_result_container_read_pre_native_for_provenance_and_pre_reveal_scorer_metadata": True,
                "truth_labelled_result_fields_used_as_native_or_decision_input": False,
                "reveal_and_truth_key_bytes_read_after_native_and_public_model_diagnostic": True,
                "exact_key_recovery": classification
                == "EXACT_CONSUMED_FULL256_RECOVERY",
            },
            "consumed_provenance": {
                "capsule": CONSUMED_CAPSULE_RELATIVE.as_posix(),
                "manifest_sha256": consumed.manifest_sha256,
                "result_sha256": sha256_file(source_paths["consumed_result"]),
                "publication_sha256": consumed.publication["publication_sha256"],
                "public_view_sha256": consumed.public.digest(),
                "score_freeze_sha256": hashlib.sha256(
                    (consumed.capsule / "score_freeze.json").read_bytes()
                ).hexdigest(),
                "reveal_sha256": reveal["reveal_sha256"],
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
            },
            "threshold": {
                "rule": threshold_config["rule"],
                "decoy_count": DECOY_COUNT,
                "decoy_max": float(np.max(consumed.frozen_joint_scores)),
                "safety_margin": SCORE_TOLERANCE,
                "value": threshold,
                "truth_compiled_score": truth_score,
                "truth_margin": truth_score - threshold,
            },
            "composition": {
                "cnf": multiblock_report.describe(),
                "potential": potential.describe(),
                "complete_score_equivalence": equivalence.report,
            },
            "native": native.raw,
            "native_build": native_build.describe(),
            "metrics": {
                "native_status": native.status_name,
                "exact_consumed_recovery": classification
                == "EXACT_CONSUMED_FULL256_RECOVERY",
                "model_score": model_score,
                "native_model_sha256": (
                    None
                    if native.key_model is None
                    else hashlib.sha256(native.key_model).hexdigest()
                ),
                "native_model_equals_committed_truth": (
                    None if native.key_model is None else native.key_model == truth_key
                ),
                "threshold_prunes": native.threshold_prunes,
                "maximum_assigned_variables": native.sieve[
                    "maximum_assigned_variables"
                ],
                "maximum_decision_level": native.sieve["maximum_decision_level"],
                "bound_checks": native.sieve["bound_checks"],
                "bounded_state_bytes": _mapping(
                    native.sieve["state"], "native state"
                )["bounded_state_bytes"],
                "derived_factor_cache_bytes": _mapping(
                    native.sieve["state"], "native state"
                )["derived_factor_cache_bytes"],
                "bounded_persistent_state_bytes": _mapping(
                    native.sieve["state"], "native state"
                )["bounded_persistent_state_bytes"],
                **gates,
            },
            "resources": {
                "elapsed_seconds": elapsed,
                "parent_cpu_seconds": time.process_time() - cpu_started,
                "child_cpu_seconds": (
                    child_end.ru_utime
                    + child_end.ru_stime
                    - child_started.ru_utime
                    - child_started.ru_stime
                ),
                "peak_rss_bytes": _peak_rss_bytes(),
                "native_wall_seconds": native_wall,
                "native_cpu_seconds": int(native.resources["cpu_microseconds"])
                / 1_000_000.0,
                "native_peak_rss_bytes": native_peak,
                "native_memory_limit_bytes": MEMORY_LIMIT_BYTES,
                "native_memory_enforcement": memory_enforcement,
                "darwin_watchdog_poll_interval_seconds": preflight[
                    "darwin_watchdog_poll_interval_seconds"
                ],
                "darwin_watchdog_guard_bytes": preflight[
                    "darwin_watchdog_guard_bytes"
                ],
                "darwin_watchdog_temporal_blindspot": preflight[
                    "darwin_watchdog_temporal_blindspot"
                ],
                "native_solver_calls": solver_calls,
                "conflict_limit": CONFLICT_LIMIT,
                "complete_equivalence_forward_plan_evaluations": DECOY_COUNT
                * BLOCK_COUNT,
                "post_native_truth_forward_plan_evaluations": BLOCK_COUNT,
                "fresh_targets": 0,
                "scientific_entropy_calls": 0,
                "fresh_reveal_calls": 0,
                "refits": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "MPS_or_GPU": False,
                "persistent_artifact_bytes": 0,
            },
            "preflight": preflight,
            "source_sha256": {
                name: sha256_file(path) for name, path in source_paths.items()
            },
            "next_action": config["next_action"],
        }
        _atomic_json(capsule / "truth_diagnostic.json", {
            "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
            "truth_compiled_score": truth_score,
            "read_after_native": True,
            "public_model_diagnostic_complete_before_read": True,
            "native_model_equals_committed_truth": (
                None if native.key_model is None else native.key_model == truth_key
            ),
        })
        _finalize_capsule(
            root=root,
            capsule=capsule,
            result=result,
            maximum_persistent_bytes=int(
                cast(int, budgets["maximum_persistent_artifact_bytes"])
            ),
        )
        return result


def run(config_path: str | Path) -> dict[str, object]:
    try:
        return _run_impl(config_path)
    except Exception as error:
        root = lab_root().resolve(strict=True)
        if (root / RESULT_RELATIVE).exists():
            raise
        capsules = tuple(
            capsule
            for capsule in root.glob(
                "runs/*_O1C-0059_multiblock-joint-score-sieve-v1"
            )
            if (capsule / "native_call_intent.json").is_file()
            and (capsule / "native_result.json").is_file()
        )
        if len(capsules) != 1:
            raise
        return _terminalize_post_native_failure(
            root=root,
            capsule=capsules[0],
            error=error,
        )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    result = run(arguments.config)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "O1C59RunError",
    "classify_sieve",
    "load_config",
    "main",
    "prospective_threshold",
    "run",
]
