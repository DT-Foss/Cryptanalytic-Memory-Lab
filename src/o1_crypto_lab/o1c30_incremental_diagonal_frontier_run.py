"""Formal light-weight runner for the O1C-0030 retrospective frontier probe.

Only the four immutable O1C-0018 BUILD action pools are consumed.  The source
loader deliberately depends on the NumPy action-pool codec instead of the
Torch-backed multiresolution loader.  Public features are persisted before the
deterministic BUILD oracle is opened; all leave-one-out logits are persisted
before any score or frontier diagnostic is computed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import resource
import stat
import struct
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence, cast

import numpy as np

from .chacha_trace import chacha20_block
from .full256_action_pool import Full256ActionPool, deserialize_action_pool
from .living_inverse import canonical_json_bytes
from .o1c30_incremental_diagonal_frontier import (
    ARM_NAMES,
    fit_leave_one_out,
    local_true_ranks,
    project_pool,
    score_logits,
)
from .posterior_logit_frontier import iter_factorized_logit_topk
from .run_capsule import ClaimLevel, RunCapsuleManager


ATTEMPT_ID = "O1C-0030"
FORMAL_SLUG = "incremental-diagonal-frontier-v1"
FORMAL_CONFIG_RELATIVE = "configs/o1c30_incremental_diagonal_frontier_v1.json"
RUN_CONFIG_SCHEMA = "o1-256-o1c30-incremental-diagonal-frontier-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-o1c30-incremental-diagonal-frontier-metrics-v1"
RESULT_SCHEMA = "o1-256-o1c30-incremental-diagonal-frontier-result-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-o1c30-incremental-diagonal-frontier-artifact-index-v1"
FEATURE_FREEZE_SCHEMA = "o1-256-o1c30-public-feature-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-o1c30-loo-prediction-freeze-v1"
KNOWN_TARGET_SCHEMA = "o1-256-deterministic-known-fullround-target-v1"
SOURCE_ATTEMPT_ID = "O1C-0018"
SOURCE_RESULT_SCHEMA = "o1-256-fullround-online-real-gate-result-v1"
SOURCE_INDEX_SCHEMA = "o1-256-fullround-online-real-gate-artifact-index-v1"
SOURCE_CORPUS_SEED = 180_018_180_018
KEY_BITS = 256
FOLD_COUNT = 4
TOP_K_LIMIT = 65_536
RIDGE_L2 = 1.0 / 768.0
_HEX = frozenset("0123456789abcdef")


class O1C30RunError(ValueError):
    """The formal config, pinned source, lifecycle, or resource contract differs."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise O1C30RunError(f"{field} must be lowercase SHA-256")
    return value


def _mapping(
    value: object,
    field: str,
    expected: set[str] | frozenset[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C30RunError(f"{field} must be an object")
    row = cast(Mapping[str, object], value)
    if expected is not None and set(row) != set(expected):
        raise O1C30RunError(f"{field} fields differ")
    return row


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C30RunError(f"{field} must be an integer in [{minimum},{maximum}]")
    return value


def _finite(value: object, field: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise O1C30RunError(f"{field} must be finite in [{minimum},{maximum}]")
    return float(value)


def _safe_relative(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise O1C30RunError(f"{field} must be a relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C30RunError(f"{field} must be a safe canonical relative path")
    return value


def _decode_json(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C30RunError(f"{field} is invalid JSON") from exc
    return _mapping(value, field)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _freeze_document(unsigned: Mapping[str, object]) -> dict[str, object]:
    return {**unsigned, "freeze_sha256": _sha256_bytes(canonical_json_bytes(unsigned))}


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True, slots=True)
class O1C30Budgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_source_artifact_bytes_read: int
    expected_existing_build_pools: int
    maximum_physical_public_pools_generated: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "O1C30Budgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        cpu = _finite(
            row["maximum_cpu_seconds"], "budgets.maximum_cpu_seconds", 0.01, 600.0
        )
        wall = _finite(
            row["maximum_wall_seconds"], "budgets.maximum_wall_seconds", 0.01, 900.0
        )
        integers = {
            name: _integer(row[name], f"budgets.{name}", 0, 1_000_000_000)
            for name in fields - {"maximum_cpu_seconds", "maximum_wall_seconds"}
        }
        exact = {
            "expected_existing_build_pools": FOLD_COUNT,
            "maximum_physical_public_pools_generated": 0,
            "maximum_native_solver_branches": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
        }
        if any(integers[name] != expected for name, expected in exact.items()):
            raise O1C30RunError("formal zero-work or BUILD-pool budget differs")
        if (
            integers["maximum_resident_memory_mib"] > 512
            or integers["maximum_persistent_artifact_bytes"] > 4 * 1024 * 1024
            or integers["maximum_source_artifact_bytes_read"] > 32 * 1024 * 1024
        ):
            raise O1C30RunError("formal light-resource budget differs")
        return cls(
            maximum_cpu_seconds=cpu,
            maximum_wall_seconds=wall,
            **integers,
        )


@dataclass(frozen=True, slots=True)
class BuildPin:
    ordinal: int
    target_id: str
    target_index: int
    key_sha256: str
    public_view_sha256: str
    fap: str
    fap_sha256: str
    fap_bytes: int
    sidecar: str
    sidecar_sha256: str

    @classmethod
    def from_mapping(cls, value: object, ordinal: int) -> "BuildPin":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, f"source.build[{ordinal}]", fields)
        parsed = cls(
            ordinal=_integer(row["ordinal"], "source.build.ordinal", 0, FOLD_COUNT - 1),
            target_id=str(row["target_id"]),
            target_index=_integer(
                row["target_index"], "source.build.target_index", 0, 1_000_000
            ),
            key_sha256=_sha256(row["key_sha256"], "source.build.key_sha256"),
            public_view_sha256=_sha256(
                row["public_view_sha256"], "source.build.public_view_sha256"
            ),
            fap=_safe_relative(row["fap"], "source.build.fap"),
            fap_sha256=_sha256(row["fap_sha256"], "source.build.fap_sha256"),
            fap_bytes=_integer(
                row["fap_bytes"], "source.build.fap_bytes", 1, 8_000_000
            ),
            sidecar=_safe_relative(row["sidecar"], "source.build.sidecar"),
            sidecar_sha256=_sha256(
                row["sidecar_sha256"], "source.build.sidecar_sha256"
            ),
        )
        if (
            parsed.ordinal != ordinal
            or parsed.target_id != f"build-{parsed.target_index:04d}"
            or parsed.target_index != ordinal
            or parsed.fap != f"artifacts/pools/{parsed.target_id}.fap"
            or parsed.sidecar != f"artifacts/pools/{parsed.target_id}.json"
        ):
            raise O1C30RunError("source BUILD identity/path inventory differs")
        return parsed


@dataclass(frozen=True, slots=True)
class O1C30Config:
    top: Mapping[str, object]
    path: Path
    root: Path
    source: Mapping[str, object]
    builds: tuple[BuildPin, ...]
    budgets: O1C30Budgets
    ridge_l2: float
    strong_gate: Mapping[str, object]
    source_freeze_commit: str


@dataclass(frozen=True, slots=True)
class VerifiedBuild:
    pin: BuildPin
    pool: Full256ActionPool
    public_view: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class VerifiedSource:
    capsule: Path
    manifest_sha256: str
    artifact_index_sha256: str
    result_sha256: str
    config_sha256: str
    metrics_sha256: str
    builds: tuple[VerifiedBuild, ...]
    bytes_read: int


def load_o1c30_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C30Config:
    config_path = Path(path).resolve(strict=True)
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C30RunError("run config is unreadable") from exc
    fields = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "source",
        "experiment",
        "budgets",
        "next_action",
        "source_freeze_commit",
    }
    top = dict(_mapping(value, "config", fields))
    if (
        top["schema"] != RUN_CONFIG_SCHEMA
        or top["attempt_id"] != ATTEMPT_ID
        or top["slug"] != FORMAL_SLUG
        or top["claim_level"] != ClaimLevel.RETROSPECTIVE.value
    ):
        raise O1C30RunError("formal identity/schema/claim level differs")
    for name in ("hypothesis", "prediction", "next_action"):
        if not isinstance(top[name], str) or not str(top[name]).strip():
            raise O1C30RunError(f"config.{name} is required")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise O1C30RunError("config.controls differ")

    source_fields = {
        "capsule",
        "manifest_sha256",
        "artifact_index_sha256",
        "result_sha256",
        "config_sha256",
        "metrics_sha256",
        "corpus_seed",
        "build",
    }
    source = _mapping(top["source"], "source", source_fields)
    if source["corpus_seed"] != SOURCE_CORPUS_SEED:
        raise O1C30RunError("source corpus seed differs")
    build_rows = source["build"]
    if not isinstance(build_rows, list) or len(build_rows) != FOLD_COUNT:
        raise O1C30RunError("source BUILD inventory differs")
    builds = tuple(
        BuildPin.from_mapping(row, index) for index, row in enumerate(build_rows)
    )
    for name in (
        "manifest_sha256",
        "artifact_index_sha256",
        "result_sha256",
        "config_sha256",
        "metrics_sha256",
    ):
        _sha256(source[name], f"source.{name}")
    _safe_relative(source["capsule"], "source.capsule")

    experiment = _mapping(
        top["experiment"],
        "experiment",
        {
            "horizons_storage",
            "horizons_chronological",
            "feature_arms",
            "ridge_l2",
            "candidate_limit",
            "strong_gate",
        },
    )
    if (
        experiment["horizons_storage"] != [64, 96, 65]
        or experiment["horizons_chronological"] != [64, 65, 96]
        or experiment["feature_arms"] != list(ARM_NAMES)
        or experiment["candidate_limit"] != TOP_K_LIMIT
    ):
        raise O1C30RunError("formal experiment inventory differs")
    ridge_l2 = _finite(experiment["ridge_l2"], "experiment.ridge_l2", 1e-12, 1_000.0)
    if ridge_l2.hex() != RIDGE_L2.hex():
        raise O1C30RunError("formal ridge_l2 must equal exactly 1/768")
    strong_gate = _mapping(
        experiment["strong_gate"],
        "experiment.strong_gate",
        {
            "positive_folds",
            "minimum_mean_compression_bits",
            "minimum_mean_primary_minus_cumulative_bits",
            "primary_beats_cumulative_all_folds",
            "required_mean_control_wins",
        },
    )
    if (
        strong_gate["positive_folds"] != FOLD_COUNT
        or strong_gate["minimum_mean_compression_bits"] != 0.25
        or strong_gate["minimum_mean_primary_minus_cumulative_bits"] != 0.10
        or strong_gate["primary_beats_cumulative_all_folds"] is not True
        or strong_gate["required_mean_control_wins"]
        != [
            "deranged_confidence",
            "legacy_reintegrated",
            "polarity_even_common_mode",
        ]
    ):
        raise O1C30RunError("formal strong gate differs")
    freeze = top["source_freeze_commit"]
    if (
        not isinstance(freeze, str)
        or len(freeze) != 40
        or any(character not in _HEX for character in freeze)
    ):
        raise O1C30RunError("source_freeze_commit must be a lowercase Git object ID")
    lab_root = (
        Path(root).resolve(strict=True)
        if root is not None
        else Path(__file__).resolve().parents[2]
    )
    return O1C30Config(
        top=top,
        path=config_path,
        root=lab_root,
        source=source,
        builds=builds,
        budgets=O1C30Budgets.from_mapping(top["budgets"]),
        ridge_l2=ridge_l2,
        strong_gate=strong_gate,
        source_freeze_commit=freeze,
    )


def _read_source_member(capsule: Path, relative: str) -> bytes:
    candidate = (capsule / relative).resolve(strict=True)
    if not candidate.is_relative_to(capsule) or not candidate.is_file():
        raise O1C30RunError(f"source member escapes or is not regular: {relative}")
    metadata = candidate.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C30RunError(f"source member is not a regular file: {relative}")
    return candidate.read_bytes()


def _indexed_entry(
    artifacts: Mapping[str, object], relative: str, payload: bytes
) -> None:
    row = _mapping(artifacts.get(relative), f"source index {relative}")
    if row.get("sha256") != _sha256_bytes(payload) or row.get("bytes") != len(payload):
        raise O1C30RunError(f"source index commitment differs: {relative}")


def _derived_target(seed: int, index: int) -> tuple[bytes, dict[str, object]]:
    material = hashlib.shake_256(
        canonical_json_bytes([KNOWN_TARGET_SCHEMA, seed, "BUILD", index])
    ).digest(48)
    key, counter_bytes, nonce = material[:32], material[32:36], material[36:48]
    counter = int.from_bytes(counter_bytes, "little")
    public = {
        "schema": "o1-256-public-target-view-v1",
        "cipher": "ChaCha20",
        "rounds": 20,
        "feed_forward": True,
        "counter_schedule": [counter],
        "nonce_hex": nonce.hex(),
        "output_blocks_hex": [chacha20_block(key, counter, nonce).hex()],
        "unknown_key_bits": KEY_BITS,
        "target_key_included": False,
        "target_trace_included": False,
    }
    return key, public


def load_verified_source(config: O1C30Config) -> VerifiedSource:
    capsule_relative = _safe_relative(config.source["capsule"], "source.capsule")
    capsule = (config.root / capsule_relative).resolve(strict=True)
    runs = (config.root / "runs").resolve(strict=True)
    if capsule.parent != runs or not capsule.is_dir():
        raise O1C30RunError("source capsule must be one finalized run")
    verification = RunCapsuleManager(config.root).verify(capsule)
    if (
        not verification.ok
        or verification.manifest_sha256 != config.source["manifest_sha256"]
    ):
        raise O1C30RunError("source capsule manifest verification differs")

    global_paths = {
        "artifact_index": "artifacts/artifact_index.json",
        "result": "artifacts/full256_online_real_gate.json",
        "config": "config.json",
        "metrics": "metrics.json",
    }
    payloads = {
        name: _read_source_member(capsule, relative)
        for name, relative in global_paths.items()
    }
    for name in global_paths:
        if _sha256_bytes(payloads[name]) != config.source[f"{name}_sha256"]:
            raise O1C30RunError(f"pinned source {name} differs")
    index = _decode_json(payloads["artifact_index"], "source artifact index")
    result = _decode_json(payloads["result"], "source result")
    source_config = _decode_json(payloads["config"], "source capsule config")
    metrics = _decode_json(payloads["metrics"], "source metrics")
    if (
        index.get("schema") != SOURCE_INDEX_SCHEMA
        or index.get("attempt_id") != SOURCE_ATTEMPT_ID
        or result.get("schema") != SOURCE_RESULT_SCHEMA
        or source_config.get("attempt_id") != SOURCE_ATTEMPT_ID
        or metrics.get("attempt_id") != SOURCE_ATTEMPT_ID
        or metrics.get("status") != "completed"
    ):
        raise O1C30RunError("source lifecycle/schema differs")
    artifacts = _mapping(index.get("artifacts"), "source index artifacts")
    _indexed_entry(artifacts, "full256_online_real_gate.json", payloads["result"])
    result_config = _mapping(result.get("config"), "source result config")
    if (
        result_config.get("corpus_seed") != SOURCE_CORPUS_SEED
        or result.get("build_targets") != FOLD_COUNT
    ):
        raise O1C30RunError("source BUILD corpus contract differs")
    result_builds = result.get("build")
    if not isinstance(result_builds, list) or len(result_builds) != FOLD_COUNT:
        raise O1C30RunError("source result BUILD inventory differs")

    bytes_read = sum(len(value) for value in payloads.values())
    verified: list[VerifiedBuild] = []
    for pin, raw_result in zip(config.builds, result_builds, strict=True):
        result_row = _mapping(raw_result, f"source result build[{pin.ordinal}]")
        target = _mapping(result_row.get("target"), "source BUILD target")
        if (
            result_row.get("ordinal") != pin.ordinal
            or result_row.get("action_pool_sha256") != pin.fap_sha256
            or target.get("target_id") != pin.target_id
            or target.get("index") != pin.target_index
            or target.get("split") != "BUILD"
            or target.get("key_sha256") != pin.key_sha256
            or target.get("public_view_sha256") != pin.public_view_sha256
            or target.get("unknown_key_bits_at_probe") != KEY_BITS
            or target.get("target_key_enters_probe") is not False
        ):
            raise O1C30RunError("pinned source BUILD/result binding differs")
        fap_payload = _read_source_member(capsule, pin.fap)
        sidecar_payload = _read_source_member(capsule, pin.sidecar)
        bytes_read += len(fap_payload) + len(sidecar_payload)
        if (
            len(fap_payload) != pin.fap_bytes
            or _sha256_bytes(fap_payload) != pin.fap_sha256
            or _sha256_bytes(sidecar_payload) != pin.sidecar_sha256
        ):
            raise O1C30RunError("pinned BUILD pool bytes differ")
        _indexed_entry(artifacts, pin.fap.removeprefix("artifacts/"), fap_payload)
        _indexed_entry(
            artifacts, pin.sidecar.removeprefix("artifacts/"), sidecar_payload
        )
        sidecar = _decode_json(sidecar_payload, f"source sidecar {pin.target_id}")
        sidecar_pool = _mapping(sidecar.get("pool"), "source sidecar pool")
        public = dict(_mapping(target.get("public_view"), "source BUILD public view"))
        if (
            _sha256_bytes(canonical_json_bytes(public)) != pin.public_view_sha256
            or sidecar.get("phase") != "PUBLIC_PROOF_POOL_FROZEN_BEFORE_LABEL_ACCESS"
            or sidecar.get("labels_materialized") != 0
            or sidecar.get("target_id") != pin.target_id
            or sidecar.get("public_view_sha256") != pin.public_view_sha256
            or sidecar.get("action_pool_sha256") != pin.fap_sha256
            or sidecar.get("target_key_inputs_to_probe") != 0
            or sidecar.get("target_trace_inputs") != 0
            or sidecar_pool.get("public_view") != public
            or sidecar_pool.get("target_key_inputs") != 0
            or sidecar_pool.get("target_trace_inputs") != 0
        ):
            raise O1C30RunError("BUILD public/secret freeze commitment differs")
        try:
            pool = deserialize_action_pool(fap_payload)
        except (TypeError, ValueError) as exc:
            raise O1C30RunError("BUILD FAP is invalid") from exc
        if pool.action_pool_sha256 != pin.fap_sha256 or pool.horizons != (64, 96, 65):
            raise O1C30RunError("BUILD FAP semantic binding differs")
        verified.append(VerifiedBuild(pin=pin, pool=pool, public_view=public))
    if bytes_read > config.budgets.maximum_source_artifact_bytes_read:
        raise O1C30RunError("source reads exceed formal budget")
    return VerifiedSource(
        capsule=capsule,
        manifest_sha256=verification.manifest_sha256,
        artifact_index_sha256=_sha256_bytes(payloads["artifact_index"]),
        result_sha256=_sha256_bytes(payloads["result"]),
        config_sha256=_sha256_bytes(payloads["config"]),
        metrics_sha256=_sha256_bytes(payloads["metrics"]),
        builds=tuple(verified),
        bytes_read=bytes_read,
    )


def _derive_labels(source: VerifiedSource) -> np.ndarray:
    labels = np.empty((FOLD_COUNT, KEY_BITS), dtype=np.uint8)
    for fold, episode in enumerate(source.builds):
        key, public = _derived_target(SOURCE_CORPUS_SEED, episode.pin.target_index)
        if (
            _sha256_bytes(key) != episode.pin.key_sha256
            or _sha256_bytes(canonical_json_bytes(public))
            != episode.pin.public_view_sha256
            or public != episode.public_view
        ):
            raise O1C30RunError("deterministic BUILD label oracle differs")
        labels[fold] = np.unpackbits(
            np.frombuffer(key, dtype=np.uint8), bitorder="little"
        )
    labels.setflags(write=False)
    return labels


def _git_commit_and_freeze(config: O1C30Config) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=config.root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise O1C30RunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=config.root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestor = subprocess.run(
        ("git", "merge-base", "--is-ancestor", config.source_freeze_commit, commit),
        cwd=config.root,
    )
    if ancestor.returncode != 0:
        raise O1C30RunError("source freeze is not an ancestor of the clean run commit")
    frozen_paths = (
        "src/o1_crypto_lab/o1c30_incremental_diagonal_frontier.py",
        "src/o1_crypto_lab/o1c30_incremental_diagonal_frontier_run.py",
        "src/o1_crypto_lab/full256_action_pool.py",
        "src/o1_crypto_lab/chacha_trace.py",
        "src/o1_crypto_lab/living_inverse.py",
        "src/o1_crypto_lab/posterior_logit_frontier.py",
        "src/o1_crypto_lab/run_capsule.py",
        "pyproject.toml",
    )
    for relative in frozen_paths:
        payload = subprocess.run(
            ("git", "show", f"{config.source_freeze_commit}:{relative}"),
            cwd=config.root,
            check=True,
            capture_output=True,
        ).stdout
        if _sha256_bytes(payload) != _sha256_file(config.root / relative):
            raise O1C30RunError(f"source differs from freeze commit: {relative}")
    return commit


def _source_hashes(config: O1C30Config, source: VerifiedSource) -> dict[str, str]:
    paths = {
        "core": "src/o1_crypto_lab/o1c30_incremental_diagonal_frontier.py",
        "runner": "src/o1_crypto_lab/o1c30_incremental_diagonal_frontier_run.py",
        "action_pool": "src/o1_crypto_lab/full256_action_pool.py",
        "chacha_trace": "src/o1_crypto_lab/chacha_trace.py",
        "living_inverse": "src/o1_crypto_lab/living_inverse.py",
        "frontier": "src/o1_crypto_lab/posterior_logit_frontier.py",
        "run_capsule": "src/o1_crypto_lab/run_capsule.py",
        "pyproject": "pyproject.toml",
    }
    return {
        "config": _sha256_file(config.path),
        "source_capsule_manifest": source.manifest_sha256,
        "source_artifact_index": source.artifact_index_sha256,
        "source_result": source.result_sha256,
        "source_config": source.config_sha256,
        "source_metrics": source.metrics_sha256,
        **{
            name: _sha256_file(config.root / relative)
            for name, relative in paths.items()
        },
        **{
            f"source_pool_{row.pin.ordinal:04d}": row.pin.fap_sha256
            for row in source.builds
        },
    }


def _describe(value: object) -> object:
    describe = getattr(value, "describe", None)
    if callable(describe):
        return describe()
    receipt = getattr(value, "receipt_document", None)
    if callable(receipt):
        return receipt()
    if is_dataclass(value):
        return asdict(cast(Any, value))
    if isinstance(value, Mapping):
        return dict(value)
    raise O1C30RunError(
        f"result receipt lacks a serializable description: {type(value).__name__}"
    )


def _frontier_diagnostic(
    logits: np.ndarray, labels: np.ndarray, limit: int
) -> dict[str, object]:
    truth = np.packbits(labels, bitorder="little").tobytes()
    digest = hashlib.sha256(b"O1C-0030/exact-native-logit-topk/v1\x00")
    true_rank: int | None = None
    best_hamming_distance = KEY_BITS + 1
    best_hamming_rank: int | None = None
    count = 0
    for candidate in iter_factorized_logit_topk(logits, limit=limit):
        count += 1
        digest.update(struct.pack(">Q", candidate.rank))
        digest.update(candidate.key)
        exact = candidate.exact_penalty_units.to_bytes(
            max(1, (candidate.exact_penalty_units.bit_length() + 7) // 8), "big"
        )
        digest.update(struct.pack(">I", len(exact)))
        digest.update(exact)
        digest.update(struct.pack(">H", candidate.penalty_unit_exponent))
        digest.update(candidate.topology_code.to_bytes(32, "big"))
        if true_rank is None and candidate.key == truth:
            true_rank = candidate.rank
        hamming = sum(
            (left ^ right).bit_count()
            for left, right in zip(candidate.key, truth, strict=True)
        )
        if hamming < best_hamming_distance:
            best_hamming_distance = hamming
            best_hamming_rank = candidate.rank
    if count != limit:
        raise O1C30RunError("exact frontier emitted the wrong candidate count")
    return {
        "candidate_limit": limit,
        "candidates_evaluated": count,
        "true_key_rank_if_within_limit": true_rank,
        "true_key_within_limit": true_rank is not None,
        "best_hamming_distance": best_hamming_distance,
        "best_hamming_rank": best_hamming_rank,
        "frontier_sha256": digest.hexdigest(),
        "ranking": "exact-binary64-logit-subset-penalty",
    }


def run_capsule_from_config(path: str | Path) -> int:
    config = load_o1c30_run_config(path)
    formal_path = (config.root / FORMAL_CONFIG_RELATIVE).resolve(strict=True)
    if config.path != formal_path or Path(path).resolve(strict=True) != formal_path:
        raise O1C30RunError(
            "formal execution requires the canonical O1C-0030 config path"
        )
    manager = RunCapsuleManager(config.root)
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is not None:
        metrics = _decode_json(
            (published.path / "metrics.json").read_bytes(), "published metrics"
        )
        status = metrics.get("status")
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": status,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if status == "completed" else 2
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            print(f"publication completed: {finalized.path}")
            return 0
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action="Preserve the stopped capsule and advance only under a new attempt ID.",
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    source = load_verified_source(config)
    commit = _git_commit_and_freeze(config)
    hashes = _source_hashes(config, source)
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=FORMAL_SLUG,
        commit=commit,
        hypothesis=str(config.top["hypothesis"]),
        prediction=str(config.top["prediction"]),
        controls=tuple(
            str(item) for item in cast(Sequence[object], config.top["controls"])
        ),
        budgets=dict(cast(Mapping[str, object], config.top["budgets"])),
        source_hashes=hashes,
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action=str(config.top["next_action"]),
        config=config.top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.o1c30_incremental_diagonal_frontier_run",
            "--config",
            str(config.path),
        ),
        environment={
            "experiment_boundary": "retrospective-existing-build-pools-only",
            "source_attempt_id": SOURCE_ATTEMPT_ID,
            "source_freeze_commit": config.source_freeze_commit,
            "physical_public_pools_generated": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "accelerator": "none",
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    labels_derived = False
    features_frozen_before_labels = False
    predictions_frozen = False
    score_started = False
    cpu_started = time.process_time()
    wall_started = time.monotonic()

    def persist(relative: str, payload: bytes, phase: str) -> str:
        nonlocal persistent_bytes
        if relative in persisted:
            raise O1C30RunError(f"duplicate artifact: {relative}")
        if (
            persistent_bytes + len(payload)
            > config.budgets.maximum_persistent_artifact_bytes
        ):
            raise O1C30RunError("persistent artifact budget exceeded")
        output = run.write_artifact(relative, payload)
        digest = _sha256_bytes(payload)
        if _sha256_file(output) != digest:
            raise O1C30RunError(f"persisted artifact differs: {relative}")
        persisted[relative] = {"sha256": digest, "bytes": len(payload), "phase": phase}
        persistent_bytes += len(payload)
        return digest

    try:
        run.append_stdout(
            "O1C-0030 light retrospective BUILD-pool probe started on CPU.\n"
        )
        run.checkpoint(
            {
                "phase": "SOURCE_VERIFIED",
                "source_artifact_bytes_read": source.bytes_read,
                "existing_build_pools": FOLD_COUNT,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

        feature_tensor = np.empty(
            (FOLD_COUNT, len(ARM_NAMES), KEY_BITS), dtype=np.float64
        )
        feature_rows: list[dict[str, object]] = []
        diagnostic_rows: list[dict[str, object]] = []
        for fold, episode in enumerate(source.builds):
            projected = project_pool(episode.pool)
            mapping = projected.as_mapping()
            if tuple(mapping) != ARM_NAMES:
                raise O1C30RunError("core arm order differs")
            for arm_index, arm in enumerate(ARM_NAMES):
                values = np.asarray(mapping[arm], dtype=np.float64)
                if values.shape != (KEY_BITS,) or not bool(np.isfinite(values).all()):
                    raise O1C30RunError("projected feature vector differs")
                feature_tensor[fold, arm_index] = values
                feature_rows.append(
                    {
                        "fold": fold,
                        "target_id": episode.pin.target_id,
                        "arm": arm,
                        "sha256": _sha256_bytes(
                            values.astype("<f8", copy=False).tobytes()
                        ),
                    }
                )
            diagnostic_rows.append(
                {
                    "fold": fold,
                    "target_id": episode.pin.target_id,
                    "q_sha256": _sha256_bytes(
                        np.asarray(projected.q, dtype="u1").tobytes()
                    ),
                    "deranged_q_sha256": _sha256_bytes(
                        np.asarray(projected.deranged_q, dtype="u1").tobytes()
                    ),
                    "odd_innovations_sha256": _sha256_bytes(
                        np.asarray(projected.odd_innovations, dtype="<f8").tobytes()
                    ),
                    "even_innovations_sha256": _sha256_bytes(
                        np.asarray(projected.even_innovations, dtype="<f8").tobytes()
                    ),
                }
            )
        feature_payload = feature_tensor.astype("<f8", copy=False).tobytes(order="C")
        feature_sha = persist(
            "features/arm_features.f64le",
            feature_payload,
            "PUBLIC_FEATURES_FROZEN_PRE_LABEL",
        )
        feature_freeze = _freeze_document(
            {
                "schema": FEATURE_FREEZE_SCHEMA,
                "phase": "ALL_FOUR_PUBLIC_BUILD_FEATURE_SETS_PERSISTED_BEFORE_LABEL_DERIVATION",
                "shape": [FOLD_COUNT, len(ARM_NAMES), KEY_BITS],
                "arms": list(ARM_NAMES),
                "tensor_sha256": feature_sha,
                "features": feature_rows,
                "diagnostics": diagnostic_rows,
                "labels_derived": 0,
                "source_pool_sha256": [row.pin.fap_sha256 for row in source.builds],
            }
        )
        persist(
            "features/feature_freeze.json",
            _json_bytes(feature_freeze),
            "PUBLIC_FEATURES_FROZEN_PRE_LABEL",
        )
        features_frozen_before_labels = True
        run.checkpoint(
            {
                "phase": "PUBLIC_FEATURES_FROZEN_PRE_LABEL",
                "freeze_sha256": feature_freeze["freeze_sha256"],
                "persistent_artifact_bytes": persistent_bytes,
            }
        )

        labels = _derive_labels(source)
        labels_derived = True
        fits: dict[str, object] = {}
        logits = np.empty((len(ARM_NAMES), FOLD_COUNT, KEY_BITS), dtype=np.float64)
        for arm_index, arm in enumerate(ARM_NAMES):
            fitted = fit_leave_one_out(
                feature_tensor[:, arm_index, :],
                labels,
                l2=config.ridge_l2,
                arm_name=arm,
            )
            values = np.asarray(fitted.logits, dtype=np.float64)
            if values.shape != (FOLD_COUNT, KEY_BITS) or not bool(
                np.isfinite(values).all()
            ):
                raise O1C30RunError("LOO logit tensor differs")
            for fold, receipt in enumerate(fitted.fits):
                expected_training = tuple(
                    index for index in range(FOLD_COUNT) if index != fold
                )
                if (
                    receipt.heldout_episode != fold
                    or tuple(receipt.training_episode_indices) != expected_training
                    or receipt.l2.hex() != RIDGE_L2.hex()
                ):
                    raise O1C30RunError(
                        "LOO fit receipt violates the exact 3x256 boundary"
                    )
            logits[arm_index] = values
            fits[arm] = {
                "logits_sha256": _sha256_bytes(
                    values.astype("<f8", copy=False).tobytes()
                ),
                "loo_receipt": _describe(fitted),
                "folds": [_describe(row) for row in fitted.fits],
            }
        logits_payload = logits.astype("<f8", copy=False).tobytes(order="C")
        logits_sha = persist(
            "predictions/loo_logits.f64le",
            logits_payload,
            "ALL_LOO_LOGITS_FROZEN_PRE_SCORE",
        )
        prediction_freeze = _freeze_document(
            {
                "schema": PREDICTION_FREEZE_SCHEMA,
                "phase": "ALL_ARM_ALL_FOLD_LOO_LOGITS_PERSISTED_BEFORE_SCORING",
                "shape": [len(ARM_NAMES), FOLD_COUNT, KEY_BITS],
                "arms": list(ARM_NAMES),
                "logits_sha256": logits_sha,
                "fits": fits,
                "ridge_l2": config.ridge_l2,
                "heldout_rows_per_fit": KEY_BITS,
                "training_rows_per_fit": 3 * KEY_BITS,
                "score_calls_before_freeze": 0,
            }
        )
        persist(
            "predictions/prediction_freeze.json",
            _json_bytes(prediction_freeze),
            "ALL_LOO_LOGITS_FROZEN_PRE_SCORE",
        )
        predictions_frozen = True
        run.checkpoint(
            {
                "phase": "ALL_LOO_LOGITS_FROZEN_PRE_SCORE",
                "freeze_sha256": prediction_freeze["freeze_sha256"],
                "persistent_artifact_bytes": persistent_bytes,
            }
        )

        score_started = True
        labels_payload = np.packbits(labels, axis=1, bitorder="little").tobytes(
            order="C"
        )
        labels_sha = persist(
            "scores/build_labels.bitpack", labels_payload, "POST_FREEZE_SCORED_RESULT"
        )
        arm_reports: dict[str, object] = {}
        compression = np.empty((len(ARM_NAMES), FOLD_COUNT), dtype=np.float64)
        correct = np.empty((len(ARM_NAMES), FOLD_COUNT), dtype=np.uint16)
        nll = np.empty((len(ARM_NAMES), FOLD_COUNT), dtype=np.float64)
        rank_rows: dict[str, object] = {}
        for arm_index, arm in enumerate(ARM_NAMES):
            folds: list[dict[str, object]] = []
            for fold in range(FOLD_COUNT):
                metric = score_logits(logits[arm_index, fold], labels[fold])
                described = cast(Mapping[str, object], _describe(metric))
                nll[arm_index, fold] = float(metric.nll_bits)
                compression[arm_index, fold] = float(metric.compression_bits)
                correct[arm_index, fold] = int(metric.correct_bits)
                byte_ranks, u16_ranks = local_true_ranks(
                    logits[arm_index, fold], labels[fold]
                )
                rank_rows[f"{arm}/fold-{fold}"] = {
                    "byte_ranks": list(byte_ranks),
                    "u16_ranks": list(u16_ranks),
                }
                folds.append(
                    {
                        "fold": fold,
                        "nll_bits": float(metric.nll_bits),
                        "compression_bits": float(metric.compression_bits),
                        "correct_bits": int(metric.correct_bits),
                        "metric_receipt": dict(described),
                    }
                )
            arm_reports[arm] = {
                "folds": folds,
                "mean_nll_bits": float(nll[arm_index].mean()),
                "mean_compression_bits": float(compression[arm_index].mean()),
                "mean_correct_bits": float(correct[arm_index].mean()),
                "positive_folds": int(np.count_nonzero(compression[arm_index] > 0.0)),
            }
        frontier = [
            {
                "fold": fold,
                **_frontier_diagnostic(logits[0, fold], labels[fold], TOP_K_LIMIT),
            }
            for fold in range(FOLD_COUNT)
        ]
        persist(
            "scores/local_ranks.json",
            _json_bytes(rank_rows),
            "POST_FREEZE_SCORED_RESULT",
        )
        persist(
            "scores/primary_top65536.json",
            _json_bytes(frontier),
            "POST_FREEZE_SCORED_RESULT",
        )
        persist(
            "scores/nll_bits.f64le",
            nll.astype("<f8", copy=False).tobytes(),
            "POST_FREEZE_SCORED_RESULT",
        )
        persist(
            "scores/compression_bits.f64le",
            compression.astype("<f8", copy=False).tobytes(),
            "POST_FREEZE_SCORED_RESULT",
        )
        persist(
            "scores/correct_bits.u16le",
            correct.astype("<u2", copy=False).tobytes(),
            "POST_FREEZE_SCORED_RESULT",
        )

        primary = compression[0]
        cumulative = compression[1]
        margins = {
            "primary_mean_compression_bits": float(primary.mean()),
            "cumulative_replace_mean_compression_bits": float(cumulative.mean()),
            "primary_minus_cumulative_mean_compression_bits": float(
                (primary - cumulative).mean()
            ),
            "primary_positive_folds": int(np.count_nonzero(primary > 0.0)),
            "primary_beats_cumulative_folds": int(
                np.count_nonzero(primary > cumulative)
            ),
            "primary_minus_deranged_confidence_mean_compression_bits": float(
                primary.mean()
                - compression[ARM_NAMES.index("deranged_confidence")].mean()
            ),
            "primary_minus_legacy_reintegrated_mean_compression_bits": float(
                primary.mean()
                - compression[ARM_NAMES.index("legacy_reintegrated")].mean()
            ),
            "primary_minus_polarity_even_common_mode_mean_compression_bits": float(
                primary.mean()
                - compression[ARM_NAMES.index("polarity_even_common_mode")].mean()
            ),
        }
        gates = {
            "source_manifest_and_exact_pins_verified": True,
            "all_public_features_persisted_before_label_derivation": (
                features_frozen_before_labels and labels_derived
            ),
            "all_loo_logits_persisted_before_score": predictions_frozen
            and score_started,
            "all_logits_finite": bool(np.isfinite(logits).all()),
            "all_fits_use_exactly_three_training_episodes": True,
            "zero_solver_entropy_sibling_mps_gpu_work": True,
            "primary_positive_on_all_four_folds": margins["primary_positive_folds"]
            == FOLD_COUNT,
            "primary_mean_compression_at_least_0_25_bits": margins[
                "primary_mean_compression_bits"
            ]
            >= 0.25,
            "primary_minus_cumulative_mean_at_least_0_10_bits": margins[
                "primary_minus_cumulative_mean_compression_bits"
            ]
            >= 0.10,
            "primary_beats_cumulative_all_four_folds": margins[
                "primary_beats_cumulative_folds"
            ]
            == FOLD_COUNT,
            "primary_mean_beats_deranged_confidence": (
                margins["primary_minus_deranged_confidence_mean_compression_bits"] > 0.0
            ),
            "primary_mean_beats_legacy_reintegrated": (
                margins["primary_minus_legacy_reintegrated_mean_compression_bits"] > 0.0
            ),
            "primary_mean_beats_polarity_even_common_mode": (
                margins["primary_minus_polarity_even_common_mode_mean_compression_bits"]
                > 0.0
            ),
        }
        strong_gate_passed = all(list(gates.values())[-7:])
        classification = (
            "STRONG_INCREMENTAL_DIAGONAL_SIGNAL"
            if strong_gate_passed
            else "RETROSPECTIVE_BREADCRUMB_NO_STRONG_GATE"
        )
        work_ledger = {
            "existing_build_pools_loaded": FOLD_COUNT,
            "feature_projection_episodes": FOLD_COUNT,
            "feature_values": int(feature_tensor.size),
            "ridge_fits": len(ARM_NAMES) * FOLD_COUNT,
            "ridge_training_rows": len(ARM_NAMES) * FOLD_COUNT * 3 * KEY_BITS,
            "loo_logit_values": int(logits.size),
            "score_bit_evaluations": len(ARM_NAMES) * FOLD_COUNT * KEY_BITS,
            "exact_frontier_candidates": FOLD_COUNT * TOP_K_LIMIT,
            "physical_public_pools_generated": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        }
        result = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "claim_level": ClaimLevel.RETROSPECTIVE.value,
            "classification": classification,
            "strong_gate_passed": strong_gate_passed,
            "source": {
                "attempt_id": SOURCE_ATTEMPT_ID,
                "manifest_sha256": source.manifest_sha256,
                "artifact_index_sha256": source.artifact_index_sha256,
                "result_sha256": source.result_sha256,
                "source_artifact_bytes_read": source.bytes_read,
            },
            "feature_freeze_sha256": feature_freeze["freeze_sha256"],
            "prediction_freeze_sha256": prediction_freeze["freeze_sha256"],
            "labels_sha256": labels_sha,
            "arms": arm_reports,
            "margins": margins,
            "gates": gates,
            "primary_top65536": frontier,
            "work_ledger": work_ledger,
        }
        result_payload = _json_bytes(result)
        result_sha = persist(
            "o1c30_incremental_diagonal_frontier.json",
            result_payload,
            "POST_FREEZE_SCORED_RESULT",
        )
        artifact_index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "source_manifest_sha256": source.manifest_sha256,
            "source_artifact_index_sha256": source.artifact_index_sha256,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
        }
        index_payload = _json_bytes(artifact_index)
        index_sha = persist("artifact_index.json", index_payload, "ARTIFACT_INDEX")

        if (
            _git_commit_and_freeze(config) != commit
            or _source_hashes(config, source) != hashes
        ):
            raise O1C30RunError("clean source freeze changed during execution")
        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        budget_checks = {
            "cpu": cpu_seconds <= config.budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= config.budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= config.budgets.maximum_persistent_artifact_bytes,
            "source_artifact_bytes_read": source.bytes_read
            <= config.budgets.maximum_source_artifact_bytes_read,
            "existing_build_pools": len(source.builds) == FOLD_COUNT,
            "zero_external_work": all(
                work_ledger[name] == 0
                for name in (
                    "physical_public_pools_generated",
                    "native_solver_branches",
                    "scientific_entropy_calls",
                    "sibling_reads",
                    "sibling_writes",
                    "mps_calls",
                    "gpu_calls",
                )
            ),
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operationally_complete = not failed_budgets and all(list(gates.values())[:6])
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": classification,
            "scientific_success_gate_passed": strong_gate_passed,
            "operationally_complete": operationally_complete,
            "operational_failure": not operationally_complete,
            "result_sha256": result_sha,
            "artifact_index_sha256": index_sha,
            "margins": margins,
            "gates": gates,
            "work_ledger": work_ledger,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "source_artifact_bytes_read": source.bytes_read,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics, status="completed" if operationally_complete else "failed"
        )
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "labels_derived": labels_derived,
                "predictions_frozen": predictions_frozen,
                "score_started": score_started,
                "persistent_artifact_bytes": persistent_bytes,
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action="Preserve the operational failure and repair under a new attempt ID.",
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "attempt_id": finalized.attempt_id,
                "path": str(finalized.path),
                "manifest_sha256": finalized.manifest_sha256,
                "verified": finalized.verification.ok,
                "classification": classification,
                "scientific_success_gate_passed": strong_gate_passed,
                "primary_mean_compression_bits": margins[
                    "primary_mean_compression_bits"
                ],
                "primary_minus_cumulative_mean_compression_bits": margins[
                    "primary_minus_cumulative_mean_compression_bits"
                ],
                "failed_budgets": failed_budgets,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run O1C-0030 incremental diagonal frontier"
    )
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args(argv)
    return run_capsule_from_config(arguments.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "ATTEMPT_ID",
    "FORMAL_SLUG",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "O1C30Budgets",
    "O1C30Config",
    "O1C30RunError",
    "VerifiedSource",
    "load_o1c30_run_config",
    "load_verified_source",
    "main",
    "run_capsule_from_config",
]
