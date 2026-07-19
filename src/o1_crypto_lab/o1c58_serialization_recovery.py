"""One-shot terminal-serialization recovery for the consumed O1C-0058 run.

This module never runs the native sensor or creates a target.  It accepts only the
known, already-revealed O1C-0058 partial capsule, verifies every surviving byte,
reconstructs the post-reveal result from those bytes, and seals the capsule.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Mapping, cast

import numpy as np

from .chacha_trace import chacha20_blocks
from .full256_broker import (
    make_freeze_receipt,
    public_view_from_publication,
    verify_publication,
    verify_reveal,
)
from .o1c43_parent_criticality_rank_run import _standardize_vector
from .o1c57_multiblock_parent_criticality_rank_run import (
    _shared_decoy_panel,
    _standardize_scalar_decoys,
)
from .o1c58_multiblock_bit_vault_gradient_run import (
    ALL_ARMS_LIVE_STATE_BYTES,
    ARMS,
    ATTEMPT_ID,
    BLOCK_COUNT,
    DECOY_COUNT,
    FREEZE_SCHEMA,
    GRADIENT_PANEL_SIZE,
    KEY_BITS,
    PREFIXES,
    PRIMARY_LIVE_STATE_BYTES,
    READER_SHA256,
    RESULT_RELATIVE,
    RESULT_SCHEMA,
    _apply_scalar_calibration,
    _attended_base_index,
    _base_truth_metrics,
    _classify_vault,
    _confidence_order,
    _delta_from_panel_z,
    _gradient_panel,
    _public_verify_key,
    _synthesize_key,
    _truth_metrics,
    _validate_freeze_rows,
    _vault_prefixes,
)
from .living_inverse import PublicTargetView
from .proof_parent_criticality import FEATURE_NAMES, ParentCriticalityField
from .relation_candidate_rank import array_sha256


SCIENCE_SOURCE_COMMIT = "09cc48b9d61b4cccbeaa7cf038404ac4f2a3b15a"
EXPECTED_CAPSULE_RELATIVE = Path(
    "runs/20260719_070833_O1C-0058_multiblock-bit-vault-gradient-v1"
)
EXPECTED_CONFIG_RELATIVE = Path("configs/o1c58_multiblock_bit_vault_gradient_v1.json")
RECOVERY_SOURCE_RELATIVE = Path("src/o1_crypto_lab/o1c58_serialization_recovery.py")
O1C57_RESULT_RELATIVE = Path(
    "research/O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.json"
)
O1C43_MANIFEST_RELATIVE = Path(
    "runs/20260718_233458_O1C-0043_parent-criticality-rank-v1/artifacts.sha256"
)
EXPECTED_CONFIG_SHA256 = (
    "c659c9b502377bc2d2c28991399b4b193ed68c51fc933679c0bf98fa057de693"
)
EXPECTED_RUN_SHA256 = "05eadbcaef8db7003be3bd5a7144969a659cc2be52ffbc1c32e90d7dc1ed97f0"
EXPECTED_COMMAND_SHA256 = (
    "acc0eeb1187546ebd9a2dd405c7124df47a8c7eea77b9798bbbd35dd15942619"
)
EXPECTED_SCORE_FREEZE_SHA256 = (
    "df6e02577c96c8a2286189e5af98afb2dd02ae53604ba592977a9c8da83d3277"
)
EXPECTED_O1C57_RESULT_SHA256 = (
    "bae7899503ec0d349dd7da51ebaca3cef2982c4e53d1ca560adcffe7bff47971"
)
SCIENCE_STARTED_AT = "2026-07-19T07:06:54+02:00"
SCIENCE_RECORDED_AT = "2026-07-19T07:08:33+02:00"
ORIGINAL_ERROR = "TypeError: Object of type int64 is not JSON serializable"
RECOVERY_SCHEMA = "o1-256-terminal-serialization-recovery-v1"
MANIFEST_NAME = "artifacts.sha256"
RESULT_NAME = "result.json"
RECOVERY_COMMAND_NAME = "recovery_command.txt"
RECOVERY_NOTE_NAME = "RECOVERY.md"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_BOUND_SCIENCE_NAMES = {
    "sensor_source",
    "tracer_header",
    "parent_criticality_source",
    "o1c43_runner",
    "o1c57_runner",
    "broker_source",
    "runner",
    "o1c43_result",
}
EXECUTED_SCIENCE_MODULES = (
    Path("src/o1_crypto_lab/chacha_trace.py"),
    Path("src/o1_crypto_lab/full256_broker.py"),
    Path("src/o1_crypto_lab/living_inverse.py"),
    Path("src/o1_crypto_lab/o1c43_parent_criticality_rank_run.py"),
    Path("src/o1_crypto_lab/o1c57_multiblock_parent_criticality_rank_run.py"),
    Path("src/o1_crypto_lab/o1c58_multiblock_bit_vault_gradient_run.py"),
    Path("src/o1_crypto_lab/proof_parent_criticality.py"),
    Path("src/o1_crypto_lab/relation_candidate_rank.py"),
)
RECOVERY_INSTALL_ORDER = (
    RECOVERY_NOTE_NAME,
    RECOVERY_COMMAND_NAME,
    RESULT_NAME,
    MANIFEST_NAME,
)


class O1C58RecoveryError(RuntimeError):
    """The partial capsule or deterministic recovery contract differs."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise O1C58RecoveryError(f"{field} differs")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C58RecoveryError(f"{field} differs")
    return value


def _normalize_json(value: object) -> object:
    """Recursively convert NumPy values into strict JSON-native values."""

    if isinstance(value, np.ndarray):
        return _normalize_json(value.tolist())
    if isinstance(value, np.generic):
        return _normalize_json(value.item())
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise O1C58RecoveryError("non-string JSON key differs")
            normalized[key] = _normalize_json(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize_json(item) for item in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise O1C58RecoveryError("non-finite JSON scalar differs")
        return value
    raise O1C58RecoveryError(f"unsupported JSON value {type(value).__name__}")


def _compact_json_bytes(value: object) -> bytes:
    normalized = _normalize_json(value)
    return (
        json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _result_json_bytes(value: object) -> bytes:
    normalized = _normalize_json(value)
    return (
        json.dumps(
            normalized,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _read_json_bytes(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C58RecoveryError(f"{field} JSON differs") from exc
    if not isinstance(value, dict):
        raise O1C58RecoveryError(f"{field} JSON differs")
    return cast(dict[str, object], value)


def _read_canonical_json(path: Path, field: str) -> tuple[dict[str, object], bytes]:
    payload = path.read_bytes()
    value = _read_json_bytes(payload, field)
    if payload != _compact_json_bytes(value):
        raise O1C58RecoveryError(f"{field} is not canonical")
    return value, payload


def _git_blob(root: Path, commit: str, relative: Path, field: str) -> bytes:
    if relative.is_absolute() or ".." in relative.parts:
        raise O1C58RecoveryError(f"{field} path differs")
    try:
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative.as_posix()}"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise O1C58RecoveryError(f"{field} is absent from source commit") from exc
    return completed.stdout


def _git_head(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise O1C58RecoveryError("recovery source commit differs") from exc
    commit = completed.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise O1C58RecoveryError("recovery source commit differs")
    return commit


def _validate_source_commits(
    root: Path, config: Mapping[str, object]
) -> tuple[str, dict[str, str], dict[str, object]]:
    config_blob = _git_blob(
        root, SCIENCE_SOURCE_COMMIT, EXPECTED_CONFIG_RELATIVE, "science config"
    )
    if _sha256(config_blob) != EXPECTED_CONFIG_SHA256:
        raise O1C58RecoveryError("science config hash differs")
    source = _mapping(config.get("source"), "config source")
    expected = _mapping(source.get("expected_sha256"), "source expected hashes")
    names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "o1c57_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    )
    source_hashes: dict[str, str] = {}
    for name in names:
        path_value = source.get(name)
        expected_hash = expected.get(name)
        if (
            not isinstance(path_value, str)
            or not isinstance(expected_hash, str)
            or SHA256_RE.fullmatch(expected_hash) is None
        ):
            raise O1C58RecoveryError(f"science source declaration differs for {name}")
        path = Path(path_value)
        if path.is_absolute() or ".." in path.parts:
            raise O1C58RecoveryError(f"science source path differs for {name}")
        if name in COMMIT_BOUND_SCIENCE_NAMES:
            blob = _git_blob(
                root, SCIENCE_SOURCE_COMMIT, path, f"science source {name}"
            )
        else:
            source_path = root / path
            resolved = source_path.resolve(strict=True)
            if (
                not resolved.is_relative_to(root)
                or source_path.is_symlink()
                or not resolved.is_file()
            ):
                raise O1C58RecoveryError(f"science artifact differs for {name}")
            blob = resolved.read_bytes()
        if _sha256(blob) != expected_hash:
            raise O1C58RecoveryError(f"science source hash differs for {name}")
        source_hashes[name] = expected_hash
    manifest_hash = expected.get("o1c43_manifest")
    if not isinstance(manifest_hash, str) or SHA256_RE.fullmatch(manifest_hash) is None:
        raise O1C58RecoveryError("O1C-0043 manifest declaration differs")
    raw_manifest_path = root / O1C43_MANIFEST_RELATIVE
    manifest_path = raw_manifest_path.resolve(strict=True)
    if (
        not manifest_path.is_relative_to(root)
        or raw_manifest_path.is_symlink()
        or not manifest_path.is_file()
        or _sha256(manifest_path.read_bytes()) != manifest_hash
    ):
        raise O1C58RecoveryError("O1C-0043 manifest hash differs")
    source_hashes["o1c43_manifest"] = manifest_hash

    # Every imported helper that participates in reconstruction must be the exact
    # implementation present at the consumed science commit.  Merely checking a
    # Git blob while executing a dirty worktree copy would not bind the recovery.
    for relative in EXECUTED_SCIENCE_MODULES:
        current = (root / relative).resolve(strict=True)
        if (
            not current.is_relative_to(root)
            or (root / relative).is_symlink()
            or current.read_bytes()
            != _git_blob(
                root,
                SCIENCE_SOURCE_COMMIT,
                relative,
                f"executed science helper {relative.name}",
            )
        ):
            raise O1C58RecoveryError(
                f"executed science helper is not commit-bound: {relative.name}"
            )

    recovery_commit = _git_head(root)
    recovery_blob = _git_blob(
        root, recovery_commit, RECOVERY_SOURCE_RELATIVE, "recovery source"
    )
    recovery_path = root / RECOVERY_SOURCE_RELATIVE
    if not recovery_path.is_file() or recovery_path.read_bytes() != recovery_blob:
        raise O1C58RecoveryError("recovery source is not commit-bound")
    try:
        subprocess.run(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                SCIENCE_SOURCE_COMMIT,
                recovery_commit,
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise O1C58RecoveryError(
            "science commit is not an ancestor of recovery"
        ) from exc

    o1c43_blob = _git_blob(
        root,
        SCIENCE_SOURCE_COMMIT,
        Path(str(source["o1c43_result"])),
        "O1C-0043 result",
    )
    o1c43 = _read_json_bytes(o1c43_blob, "O1C-0043 result")
    reader = _mapping(o1c43.get("reader"), "O1C-0043 reader")
    if (
        reader.get("feature_names") != list(FEATURE_NAMES)
        or reader.get("weights_sha256") != READER_SHA256
    ):
        raise O1C58RecoveryError("frozen reader differs")

    o1c57_blob = _git_blob(
        root, SCIENCE_SOURCE_COMMIT, O1C57_RESULT_RELATIVE, "O1C-0057 result"
    )
    if _sha256(o1c57_blob) != EXPECTED_O1C57_RESULT_SHA256:
        raise O1C58RecoveryError("O1C-0057 result hash differs")
    o1c57 = _read_json_bytes(o1c57_blob, "O1C-0057 result")
    native = _mapping(o1c57.get("native_build"), "O1C-0057 native build")
    if (
        native.get("source_sha256") != source_hashes["sensor_source"]
        or native.get("tracer_header_sha256") != source_hashes["tracer_header"]
        or native.get("cadical_header_sha256")
        != "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
        or native.get("cadical_library_sha256")
        != "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
    ):
        raise O1C58RecoveryError("reused native build identity differs")
    return (
        recovery_commit,
        source_hashes,
        {
            "reader": dict(reader),
            "native_build": dict(native),
        },
    )


_RUN_RE = re.compile(
    rb"\A# O1C Run O1C-0058\n\n"
    rb"- Classification: `([^`]+)`\n"
    rb"- Base / primary prefix-8 correct bits: `([0-9]+)` / `([0-9]+)`\n"
    rb"- Primary prefix-8 longest correct confidence prefix: `([0-9]+)`\n"
    rb"- Exact recovery: `(True|False)`\n"
    rb"- Elapsed seconds: `([^`]+)`\n"
    rb"- Peak RSS bytes: `([0-9]+)`\n"
    rb"- Live efficacy/control vault bytes: `([0-9]+)`\n\n"
    rb"The attended base, all finite differences, 256-cell vault snapshots, "
    rb"confidence orders, synthesized keys, and public output checks were frozen "
    rb"before the one-shot reveal\. Prefixes 1/2/4 are post-selection evidence "
    rb"ablations; prefix 8 is the primary all-public-block attack\.\n\Z"
)


def _parse_run_markdown(payload: bytes) -> dict[str, object]:
    match = _RUN_RE.fullmatch(payload)
    if match is None:
        raise O1C58RecoveryError("original RUN.md differs")
    try:
        elapsed = float(match.group(6).decode("ascii"))
    except ValueError as exc:
        raise O1C58RecoveryError("original RUN elapsed differs") from exc
    result: dict[str, object] = {
        "classification": match.group(1).decode("ascii"),
        "base_correct_bits": int(match.group(2)),
        "primary_prefix8_correct_bits": int(match.group(3)),
        "primary_prefix8_longest_correct_confidence_prefix": int(match.group(4)),
        "exact_recovery": match.group(5) == b"True",
        "elapsed_seconds": elapsed,
        "peak_rss_bytes": int(match.group(7)),
        "all_arms_live_state_bytes": int(match.group(8)),
    }
    if not math.isfinite(elapsed) or elapsed < 0.0:
        raise O1C58RecoveryError("original RUN elapsed differs")
    return result


def _safe_artifact_path(capsule: Path, name: str) -> Path:
    pure = PurePosixPath(name)
    if (
        not name
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != name
        or name
        in {RESULT_NAME, MANIFEST_NAME, RECOVERY_COMMAND_NAME, RECOVERY_NOTE_NAME}
    ):
        raise O1C58RecoveryError("pre-reveal artifact path differs")
    path = capsule.joinpath(*pure.parts)
    if path.is_symlink() or not path.is_file():
        raise O1C58RecoveryError(f"pre-reveal artifact is absent: {name}")
    return path


def _f64(path: Path, count: int, field: str) -> np.ndarray:
    payload = path.read_bytes()
    if len(payload) != count * 8:
        raise O1C58RecoveryError(f"{field} byte length differs")
    values = np.frombuffer(payload, dtype="<f8")
    if values.shape != (count,) or not np.all(np.isfinite(values)):
        raise O1C58RecoveryError(f"{field} values differ")
    return np.asarray(values, dtype=np.float64)


def _u16_order(path: Path, field: str) -> tuple[int, ...]:
    payload = path.read_bytes()
    if len(payload) != KEY_BITS * 2:
        raise O1C58RecoveryError(f"{field} byte length differs")
    values = tuple(int(item) for item in np.frombuffer(payload, dtype="<u2"))
    if len(values) != KEY_BITS or set(values) != set(range(KEY_BITS)):
        raise O1C58RecoveryError(f"{field} values differ")
    return values


def _validate_capsule_inventory(
    capsule: Path,
    artifact_hashes: Mapping[str, object],
    *,
    allow_recovery_prefix: bool = False,
) -> dict[str, bytes]:
    metadata = {
        "RUN.md",
        "command.txt",
        "config.json",
        "freeze_receipt.json",
        "publication.json",
        "reveal.json",
        "score_freeze.json",
    }
    expected = metadata | set(artifact_hashes)
    actual: set[str] = set()
    for path in capsule.rglob("*"):
        if path.is_symlink():
            raise O1C58RecoveryError("capsule contains a symlink")
        if path.is_file():
            actual.add(path.relative_to(capsule).as_posix())
    recovery_present = tuple(name for name in RECOVERY_INSTALL_ORDER if name in actual)
    if allow_recovery_prefix:
        prefix = RECOVERY_INSTALL_ORDER[: len(recovery_present)]
        if recovery_present != prefix or actual - set(recovery_present) != expected:
            raise O1C58RecoveryError("partial recovery inventory differs")
    elif actual != expected:
        raise O1C58RecoveryError("partial capsule inventory differs")
    members: dict[str, bytes] = {}
    for name in sorted(expected):
        path = (
            _safe_artifact_path(capsule, name)
            if name in artifact_hashes
            else capsule / name
        )
        payload = path.read_bytes()
        members[name] = payload
        if name in artifact_hashes:
            expected_hash = artifact_hashes[name]
            if (
                not isinstance(expected_hash, str)
                or SHA256_RE.fullmatch(expected_hash) is None
                or _sha256(payload) != expected_hash
            ):
                raise O1C58RecoveryError(f"pre-reveal artifact hash differs: {name}")
    return members


def _validate_freeze_artifacts(
    *,
    capsule: Path,
    config: Mapping[str, object],
    freeze: Mapping[str, object],
    public: PublicTargetView,
    allow_recovery_prefix: bool = False,
) -> dict[str, object]:
    artifact_hashes = _mapping(
        freeze.get("pre_reveal_artifact_sha256"), "pre-reveal artifact hashes"
    )
    members = _validate_capsule_inventory(
        capsule,
        artifact_hashes,
        allow_recovery_prefix=allow_recovery_prefix,
    )
    block_rows_raw = freeze.get("block_rows")
    prefix_rows_raw = freeze.get("prefix_rows")
    if not isinstance(block_rows_raw, list) or not isinstance(prefix_rows_raw, list):
        raise O1C58RecoveryError("freeze rows differ")
    block_rows = [dict(_mapping(row, "block row")) for row in block_rows_raw]
    prefix_rows = [dict(_mapping(row, "prefix row")) for row in prefix_rows_raw]
    _validate_freeze_rows(block_rows, prefix_rows)

    calibration_bytes = members["calibration_keys.bin"]
    calibration_keys = tuple(
        calibration_bytes[offset : offset + 32]
        for offset in range(0, len(calibration_bytes), 32)
    )
    calibration_config = _mapping(config.get("calibration_panel"), "calibration panel")
    expected_calibration = _shared_decoy_panel(
        public,
        domain=str(calibration_config["domain"]),
        count=DECOY_COUNT,
    )
    if (
        len(calibration_bytes) != DECOY_COUNT * 32
        or calibration_keys != expected_calibration
        or _sha256(calibration_bytes) != freeze.get("calibration_keys_sha256")
    ):
        raise O1C58RecoveryError("calibration panel differs")

    decoy_z_primary = np.empty((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64)
    block_lookup: dict[tuple[int, str], dict[str, object]] = {}
    for row in block_rows:
        block_index = _integer(row["block_index"], "block index")
        arm = str(row["arm"])
        block_lookup[(block_index, arm)] = row
        raw_name = f"scores/decoy-raw/block-{block_index:02d}-{arm}.f64le"
        z_name = f"scores/decoy-z/block-{block_index:02d}-{arm}.f64le"
        gradient_raw_name = f"scores/gradient-raw/block-{block_index:02d}-{arm}.f64le"
        gradient_z_name = f"scores/gradient-z/block-{block_index:02d}-{arm}.f64le"
        delta_name = f"deltas/block-{block_index:02d}-{arm}.f64le"
        raw = _f64(capsule / raw_name, DECOY_COUNT, raw_name)
        z_values = _f64(capsule / z_name, DECOY_COUNT, z_name)
        expected_z, mean, std = _standardize_scalar_decoys(raw)
        if (
            expected_z.tobytes() != z_values.tobytes()
            or mean != row.get("scalar_decoy_mean")
            or std != row.get("scalar_decoy_std_ddof1")
            or _sha256(members[raw_name]) != row.get("decoy_raw_score_sha256")
            or _sha256(members[z_name]) != row.get("decoy_scalar_z_sha256")
            or row.get("calibration_keys_sha256")
            != freeze.get("calibration_keys_sha256")
        ):
            raise O1C58RecoveryError(
                f"decoy calibration differs for {block_index}/{arm}"
            )
        if arm == "primary":
            decoy_z_primary[block_index] = z_values

        gradient_raw = _f64(
            capsule / gradient_raw_name, GRADIENT_PANEL_SIZE, gradient_raw_name
        )
        gradient_z = _f64(
            capsule / gradient_z_name, GRADIENT_PANEL_SIZE, gradient_z_name
        )
        expected_gradient_z = _apply_scalar_calibration(
            gradient_raw, mean=mean, std=std
        )
        delta = _f64(capsule / delta_name, KEY_BITS, delta_name)
        if (
            expected_gradient_z.tobytes() != gradient_z.tobytes()
            or _delta_from_panel_z(gradient_z).tobytes() != delta.tobytes()
            or _sha256(members[gradient_raw_name])
            != row.get("gradient_raw_score_sha256")
            or _sha256(members[gradient_z_name]) != row.get("gradient_scalar_z_sha256")
            or _sha256(members[delta_name]) != row.get("delta_sha256")
        ):
            raise O1C58RecoveryError(f"gradient row differs for {block_index}/{arm}")

        means = row.get("feature_mean")
        stds = row.get("feature_std")
        if (
            not isinstance(means, list)
            or not isinstance(stds, list)
            or len(means) != len(FEATURE_NAMES)
            or len(stds) != len(FEATURE_NAMES)
        ):
            raise O1C58RecoveryError("feature calibration shape differs")
        # Exercise the committed validation path without rescoring any candidate.
        _standardize_vector(
            np.asarray(means, dtype=np.float64),
            np.asarray(means, dtype=np.float64),
            np.asarray(stds, dtype=np.float64),
        )
        description = _mapping(row.get("field_description"), "field description")
        if description.get("state_sha256") != row.get("field_sha256"):
            raise O1C58RecoveryError("field description hash differs")

    base_index, aggregate = _attended_base_index(decoy_z_primary)
    selection = _mapping(freeze.get("attended_base_selection"), "attended base")
    aggregate_name = "selection/primary-eight-block-decoy-sum.f64le"
    base_name = "selection/attended-base-key.bin"
    base_key = members[base_name]
    if (
        aggregate.astype("<f8", copy=False).tobytes() != members[aggregate_name]
        or base_index != selection.get("selected_index")
        or float(aggregate[base_index]) != selection.get("selected_score")
        or base_key != calibration_keys[base_index]
        or len(base_key) != 32
        or _sha256(base_key) != selection.get("base_key_sha256")
    ):
        raise O1C58RecoveryError("attended base reconstruction differs")

    gradient_bytes = members["gradient_keys.bin"]
    gradient_keys = _gradient_panel(base_key)
    if gradient_bytes != b"".join(gradient_keys) or _sha256(
        gradient_bytes
    ) != freeze.get("gradient_keys_sha256"):
        raise O1C58RecoveryError("gradient key layout differs")

    field_descriptions = freeze.get("natural_fields")
    field_hashes = freeze.get("natural_field_sha256")
    if (
        not isinstance(field_descriptions, list)
        or not isinstance(field_hashes, list)
        or len(field_descriptions) != BLOCK_COUNT
        or len(field_hashes) != BLOCK_COUNT
    ):
        raise O1C58RecoveryError("natural fields differ")
    for block_index in range(BLOCK_COUNT):
        payload = members[f"fields/block-{block_index:02d}.bin"]
        parsed = ParentCriticalityField.from_bytes(payload)
        description = _mapping(field_descriptions[block_index], "natural field")
        if (
            _sha256(payload) != field_hashes[block_index]
            or parsed.to_bytes() != payload
            or description.get("state_sha256") != field_hashes[block_index]
            or block_lookup[(block_index, "primary")]["field_sha256"]
            != field_hashes[block_index]
        ):
            raise O1C58RecoveryError("natural field serialization differs")

    base_verification = _public_verify_key(base_key, public)
    if base_verification != selection.get("public_verification"):
        raise O1C58RecoveryError("base public verification differs")

    vault_lookup: dict[tuple[str, int], np.ndarray] = {}
    confidence_lookup: dict[tuple[str, int], tuple[int, ...]] = {}
    candidate_lookup: dict[tuple[str, int], bytes] = {}
    verification_lookup: dict[tuple[str, int], dict[str, object]] = {}
    prefix_lookup = {
        (_integer(row["prefix"], "prefix"), str(row["arm"])): row for row in prefix_rows
    }
    for arm in ARMS:
        deltas = np.vstack(
            [
                _f64(
                    capsule / f"deltas/block-{index:02d}-{arm}.f64le", KEY_BITS, "delta"
                )
                for index in range(BLOCK_COUNT)
            ]
        )
        snapshots = _vault_prefixes(deltas)
        for prefix in PREFIXES:
            row = prefix_lookup[(prefix, arm)]
            vault_name = f"vaults/prefix-{prefix:02d}-{arm}.f64le"
            confidence_name = f"confidence/prefix-{prefix:02d}-{arm}.u16le"
            candidate_name = f"synthesized/prefix-{prefix:02d}-{arm}.key"
            vault = _f64(capsule / vault_name, KEY_BITS, vault_name)
            order = _u16_order(capsule / confidence_name, confidence_name)
            candidate = members[candidate_name]
            verification = _public_verify_key(candidate, public)
            if (
                snapshots[prefix].tobytes() != vault.tobytes()
                or _confidence_order(vault) != order
                or _synthesize_key(base_key, vault) != candidate
                or _sha256(members[vault_name]) != row.get("vault_sha256")
                or _sha256(members[confidence_name])
                != row.get("confidence_order_sha256")
                or _sha256(candidate) != row.get("synthesized_key_sha256")
                or verification != row.get("public_verification")
                or row.get("gradient_keys_sha256") != freeze.get("gradient_keys_sha256")
            ):
                raise O1C58RecoveryError(f"vault freeze differs for {arm}/{prefix}")
            vault_lookup[(arm, prefix)] = vault
            confidence_lookup[(arm, prefix)] = order
            candidate_lookup[(arm, prefix)] = candidate
            verification_lookup[(arm, prefix)] = verification

    bounded = _mapping(freeze.get("bounded_state"), "bounded state")
    prefix8 = b"".join(members[f"vaults/prefix-08-{arm}.f64le"] for arm in ARMS)
    if (
        bounded.get("primary_live_state_bytes") != PRIMARY_LIVE_STATE_BYTES
        or bounded.get("all_arms_live_state_bytes") != ALL_ARMS_LIVE_STATE_BYTES
        or len(prefix8) != ALL_ARMS_LIVE_STATE_BYTES
        or _sha256(prefix8) != bounded.get("all_arms_prefix8_state_sha256")
    ):
        raise O1C58RecoveryError("bounded state differs")
    return {
        "members": members,
        "block_rows": block_rows,
        "prefix_rows": prefix_rows,
        "base_key": base_key,
        "base_index": base_index,
        "base_score": float(aggregate[base_index]),
        "base_verification": base_verification,
        "vault_lookup": vault_lookup,
        "confidence_lookup": confidence_lookup,
        "candidate_lookup": candidate_lookup,
        "verification_lookup": verification_lookup,
    }


def _reconstruct_truth(
    *,
    config: Mapping[str, object],
    reveal: Mapping[str, object],
    frozen: Mapping[str, object],
) -> dict[str, object]:
    verified = verify_reveal(dict(reveal))
    preimage = _mapping(verified.get("commitment_preimage"), "reveal preimage")
    try:
        truth_key = bytes.fromhex(str(preimage.get("key_hex")))
    except ValueError as exc:
        raise O1C58RecoveryError("truth key encoding differs") from exc
    base_key = cast(bytes, frozen["base_key"])
    vault_lookup = cast(dict[tuple[str, int], np.ndarray], frozen["vault_lookup"])
    confidence_lookup = cast(
        dict[tuple[str, int], tuple[int, ...]], frozen["confidence_lookup"]
    )
    candidate_lookup = cast(dict[tuple[str, int], bytes], frozen["candidate_lookup"])
    verification_lookup = cast(
        dict[tuple[str, int], dict[str, object]], frozen["verification_lookup"]
    )
    base_metrics = _base_truth_metrics(base_key, truth_key)
    truth_rows: list[dict[str, object]] = []
    metric_lookup: dict[tuple[str, int], Mapping[str, object]] = {}
    for arm in ARMS:
        for prefix in PREFIXES:
            metrics = _truth_metrics(
                base_key=base_key,
                candidate=candidate_lookup[(arm, prefix)],
                truth_key=truth_key,
                evidence=vault_lookup[(arm, prefix)],
                confidence_order=confidence_lookup[(arm, prefix)],
            )
            metric_lookup[(arm, prefix)] = metrics
            truth_rows.append(
                {
                    "arm": arm,
                    "prefix": prefix,
                    "selection_scope": (
                        "primary-all-eight-block-attack"
                        if prefix == 8
                        else "post-selection-evidence-ablation"
                    ),
                    "metrics": metrics,
                    "public_verification": verification_lookup[(arm, prefix)],
                }
            )
    success = _mapping(config.get("success"), "success config")
    classification, gates = _classify_vault(
        base_metrics=base_metrics,
        metric_lookup=metric_lookup,
        verification_lookup=verification_lookup,
        base_verification=cast(Mapping[str, object], frozen["base_verification"]),
        guidance_depth=_integer(success["confidence_guidance_depth"], "guidance depth"),
        minimum_correct_bits=_integer(
            success["secondary_minimum_primary_prefix8_correct_bits"],
            "minimum correct bits",
        ),
        minimum_base_improvement=_integer(
            success["secondary_minimum_improvement_over_base_correct_bits"],
            "minimum base improvement",
        ),
    )
    return {
        "verified_reveal": verified,
        "truth_key": truth_key,
        "base_metrics": base_metrics,
        "truth_rows": truth_rows,
        "classification": classification,
        "gates": gates,
    }


def _validate_run_summary(
    summary: Mapping[str, object], truth: Mapping[str, object]
) -> None:
    gates = _mapping(truth["gates"], "reconstructed gates")
    base = _mapping(truth["base_metrics"], "reconstructed base metrics")
    expected = {
        "classification": truth["classification"],
        "base_correct_bits": base["correct_bits"],
        "primary_prefix8_correct_bits": gates["primary_prefix8_correct_bits"],
        "primary_prefix8_longest_correct_confidence_prefix": gates[
            "primary_prefix8_longest_correct_confidence_prefix"
        ],
        "exact_recovery": gates["exact_recovery"],
        "elapsed_seconds": 99.07695375000185,
        "peak_rss_bytes": 211124224,
        "all_arms_live_state_bytes": ALL_ARMS_LIVE_STATE_BYTES,
    }
    if dict(summary) != expected:
        raise O1C58RecoveryError("RUN.md does not match reconstructed result")


def _manifest_bytes(members: Mapping[str, bytes]) -> bytes:
    if MANIFEST_NAME in members:
        raise O1C58RecoveryError("manifest cannot hash itself")
    return "".join(
        f"{_sha256(payload)}  {name}\n" for name, payload in sorted(members.items())
    ).encode("ascii")


def _converge_result_manifest(
    result: dict[str, object], members: Mapping[str, bytes]
) -> tuple[dict[str, object], bytes, bytes]:
    working = cast(dict[str, object], _normalize_json(result))
    resources = cast(dict[str, object], working["resources"])
    stable_members = dict(members)
    for _ in range(16):
        result_bytes = _result_json_bytes(working)
        current = {**stable_members, RESULT_NAME: result_bytes}
        manifest = _manifest_bytes(current)
        persistent = sum(len(payload) for payload in current.values()) + len(manifest)
        if resources.get("persistent_artifact_bytes") == persistent:
            if _result_json_bytes(working) != result_bytes:
                raise O1C58RecoveryError("result serialization is unstable")
            return working, result_bytes, manifest
        resources["persistent_artifact_bytes"] = persistent
    raise O1C58RecoveryError("persistent artifact ledger did not converge")


def _atomic_write(path: Path, payload: bytes, *, refuse_existing: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if refuse_existing and path.exists():
        raise O1C58RecoveryError(f"refusing to replace {path.name}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if refuse_existing and path.exists():
            raise O1C58RecoveryError(f"refusing to replace {path.name}")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _install_exact(path: Path, payload: bytes) -> None:
    """Install one member once, or accept an identical crash-recovery member."""

    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise O1C58RecoveryError(f"existing recovery member differs: {path.name}")
        return
    _atomic_write(path, payload)


def _install_recovery_outputs(
    *,
    capsule: Path,
    authoritative: Path,
    original_members: Mapping[str, bytes],
    command: bytes,
    note: bytes,
    result_bytes: bytes,
    manifest: bytes,
) -> None:
    """Resumably install, verify, seal, then mirror a fully computed recovery."""

    payloads = {
        RECOVERY_NOTE_NAME: note,
        RECOVERY_COMMAND_NAME: command,
        RESULT_NAME: result_bytes,
        MANIFEST_NAME: manifest,
    }
    expected_non_manifest = {
        **dict(original_members),
        RECOVERY_NOTE_NAME: note,
        RECOVERY_COMMAND_NAME: command,
        RESULT_NAME: result_bytes,
    }
    if _manifest_bytes(expected_non_manifest) != manifest:
        raise O1C58RecoveryError("recovery manifest input differs")
    for name in RECOVERY_INSTALL_ORDER:
        _install_exact(capsule / name, payloads[name])

    actual_files = {
        path.relative_to(capsule).as_posix(): path.read_bytes()
        for path in capsule.rglob("*")
        if path.is_file()
    }
    if (
        set(actual_files) != set(expected_non_manifest) | {MANIFEST_NAME}
        or actual_files[MANIFEST_NAME] != manifest
        or _manifest_bytes(
            {
                name: payload
                for name, payload in actual_files.items()
                if name != MANIFEST_NAME
            }
        )
        != manifest
    ):
        raise O1C58RecoveryError("installed recovery ledger differs")

    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        if path.is_file():
            path.chmod(0o444)
        elif path.is_dir():
            path.chmod(0o555)
    capsule.chmod(0o555)
    _install_exact(authoritative, result_bytes)
    if authoritative.read_bytes() != (capsule / RESULT_NAME).read_bytes():
        raise O1C58RecoveryError("authoritative mirror differs")


def _recovery_note(recovery_commit: str, recovered_at: str) -> bytes:
    return (
        "# O1C-0058 terminal serialization recovery\n\n"
        f"- Original science commit: `{SCIENCE_SOURCE_COMMIT}`\n"
        f"- Recovery source commit: `{recovery_commit}`\n"
        f"- Recovered at: `{recovered_at}`\n"
        f"- Original terminal error: `{ORIGINAL_ERROR}`\n"
        f"- Original RUN.md SHA-256: `{EXPECTED_RUN_SHA256}`\n"
        "- Added entropy, reveal calls, native probes, scoring, or scientific trials: `0`\n\n"
        "The already-frozen artifacts and already-opened commitment were validated and "
        "serialized. The original RUN.md and science command remain byte-identical.\n"
    ).encode("utf-8")


def _recovered_at(capsule: Path, recovery_commit: str) -> str:
    note_path = capsule / RECOVERY_NOTE_NAME
    if not note_path.exists():
        return datetime.now().astimezone().isoformat(timespec="seconds")
    if not note_path.is_file() or note_path.is_symlink():
        raise O1C58RecoveryError("existing recovery note differs")
    payload = note_path.read_bytes()
    match = re.search(rb"^- Recovered at: `([^`]+)`$", payload, re.MULTILINE)
    if match is None:
        raise O1C58RecoveryError("existing recovery timestamp differs")
    try:
        value = match.group(1).decode("ascii")
        parsed = datetime.fromisoformat(value)
    except (UnicodeDecodeError, ValueError) as exc:
        raise O1C58RecoveryError("existing recovery timestamp differs") from exc
    if parsed.tzinfo is None or _recovery_note(recovery_commit, value) != payload:
        raise O1C58RecoveryError("existing recovery note differs")
    return value


def recover(capsule_path: str | Path) -> dict[str, object]:
    """Recover and seal the one known consumed O1C-0058 partial capsule."""

    root = Path(__file__).resolve(strict=True).parents[2]
    capsule = Path(capsule_path).resolve(strict=True)
    expected_capsule = (root / EXPECTED_CAPSULE_RELATIVE).resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    if capsule != expected_capsule or not capsule.is_dir() or capsule.is_symlink():
        raise O1C58RecoveryError("capsule is not the expected O1C-0058 partial state")
    if authoritative.exists():
        raise O1C58RecoveryError("O1C-0058 recovery has already completed")

    config_bytes = (capsule / "config.json").read_bytes()
    config = _read_json_bytes(config_bytes, "config")
    if (
        _sha256(config_bytes) != EXPECTED_CONFIG_SHA256
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("schema") != "o1-256-multiblock-bit-vault-gradient-config-v1"
    ):
        raise O1C58RecoveryError("capsule config differs")
    run_bytes = (capsule / "RUN.md").read_bytes()
    if _sha256(run_bytes) != EXPECTED_RUN_SHA256:
        raise O1C58RecoveryError("original RUN.md hash differs")
    if _sha256((capsule / "command.txt").read_bytes()) != EXPECTED_COMMAND_SHA256:
        raise O1C58RecoveryError("original science command differs")
    run_summary = _parse_run_markdown(run_bytes)
    recovery_commit, source_hashes, provenance = _validate_source_commits(root, config)

    freeze, freeze_bytes = _read_canonical_json(
        capsule / "score_freeze.json", "score freeze"
    )
    publication, publication_bytes = _read_canonical_json(
        capsule / "publication.json", "publication"
    )
    receipt, receipt_bytes = _read_canonical_json(
        capsule / "freeze_receipt.json", "freeze receipt"
    )
    reveal, reveal_bytes = _read_canonical_json(capsule / "reveal.json", "reveal")
    checked_publication = verify_publication(publication)
    public = public_view_from_publication(checked_publication)
    if (
        _sha256(freeze_bytes) != EXPECTED_SCORE_FREEZE_SHA256
        or freeze.get("schema") != FREEZE_SCHEMA
        or freeze.get("attempt_id") != ATTEMPT_ID
        or freeze.get("target_id") != "o1c-0058-bit-vault-fresh-0000"
        or freeze.get("publication_sha256") != checked_publication["publication_sha256"]
        or freeze.get("full_public_view_sha256") != public.digest()
        or freeze.get("block_count") != BLOCK_COUNT
        or freeze.get("target_key_reads") != 0
        or freeze.get("reveal_calls") != 0
        or freeze.get("reader_weights_sha256") != READER_SHA256
        or freeze.get("pre_reveal_verified_candidates") != 13
        or freeze.get("pre_reveal_direct_chacha_blocks") != 104
    ):
        raise O1C58RecoveryError("score freeze identity differs")
    expected_receipt = make_freeze_receipt(
        checked_publication, frozen_artifact_sha256=_sha256(freeze_bytes)
    )
    if receipt != expected_receipt or receipt_bytes != _compact_json_bytes(
        expected_receipt
    ):
        raise O1C58RecoveryError("freeze receipt differs")
    checked_reveal = verify_reveal(reveal)
    if (
        reveal_bytes != _compact_json_bytes(checked_reveal)
        or checked_reveal.get("publication") != checked_publication
        or checked_reveal.get("freeze_receipt") != expected_receipt
    ):
        raise O1C58RecoveryError("reveal lifecycle differs")

    frozen = _validate_freeze_artifacts(
        capsule=capsule,
        config=config,
        freeze=freeze,
        public=public,
        allow_recovery_prefix=True,
    )
    truth = _reconstruct_truth(config=config, reveal=checked_reveal, frozen=frozen)
    _validate_run_summary(run_summary, truth)

    truth_key = cast(bytes, truth["truth_key"])
    reproduced = chacha20_blocks(
        truth_key, public.counter_schedule[0], public.nonce, BLOCK_COUNT
    )
    if reproduced != public.output_blocks:
        raise O1C58RecoveryError("revealed truth fails all-block verification")
    reader_row = _mapping(provenance["reader"], "reader")
    reader = np.asarray(reader_row.get("weights_l2"), dtype=np.float64)
    if (
        reader.shape != (len(FEATURE_NAMES),)
        or not np.all(np.isfinite(reader))
        or array_sha256(reader, "<f8") != READER_SHA256
    ):
        raise O1C58RecoveryError("reader vector differs")

    recovered_at = _recovered_at(capsule, recovery_commit)
    base_metrics = _mapping(truth["base_metrics"], "base metrics")
    gates = _mapping(truth["gates"], "gates")
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": SCIENCE_STARTED_AT,
        "recorded_at": SCIENCE_RECORDED_AT,
        "source_commit": SCIENCE_SOURCE_COMMIT,
        "classification": truth["classification"],
        "claim_boundary": {
            "fresh_targets": 1,
            "scientific_entropy_calls": 1,
            "public_blocks": BLOCK_COUNT,
            "same_key_and_nonce_across_blocks": True,
            "contiguous_counter_schedule": True,
            "reader_loaded_without_refit_reweight_or_sign_selection": True,
            "attended_base_selected_only_from_primary_public_decoy_scores": True,
            "same_primary_conditioned_base_used_for_all_controls": True,
            "control_base_selection_is_not_arm_symmetric": True,
            "truth_key_not_used_in_gradient_generation": True,
            "all_vault_state_keys_and_public_verifications_frozen_before_reveal": True,
            "prefix8_is_primary_all_public_block_attack": True,
            "prefixes1_2_4_are_post_selection_evidence_ablations": True,
            "revealed_key_directly_reproduces_all_eight_outputs": True,
            "exact_key_recovery": gates["exact_recovery"],
        },
        "publication_sha256": checked_publication["publication_sha256"],
        "public_view_sha256": public.digest(),
        "score_freeze_sha256": _sha256(freeze_bytes),
        "freeze_receipt_sha256": receipt["receipt_sha256"],
        "reveal_sha256": checked_reveal["reveal_sha256"],
        "truth_key_sha256": _sha256(truth_key),
        "reader": {
            "feature_names": list(FEATURE_NAMES),
            "weights_l2": reader.tolist(),
            "weights_sha256": array_sha256(reader, "<f8"),
            "source_attempt": "O1C-0043",
        },
        "instance_sha256": freeze["instance_sha256"],
        "natural_fields": freeze["natural_fields"],
        "calibration_keys_sha256": freeze["calibration_keys_sha256"],
        "gradient_keys_sha256": freeze["gradient_keys_sha256"],
        "attended_base": {
            "selected_decoy_index": frozen["base_index"],
            "selected_primary_eight_block_score": frozen["base_score"],
            "base_key_sha256": _sha256(cast(bytes, frozen["base_key"])),
            "public_verification": frozen["base_verification"],
            "post_reveal_metrics": base_metrics,
        },
        "pre_reveal_block_rows": frozen["block_rows"],
        "pre_reveal_prefix_rows": frozen["prefix_rows"],
        "post_reveal_truth_rows": truth["truth_rows"],
        "bounded_state": freeze["bounded_state"],
        "metrics": {
            **dict(gates),
            "base_correct_bits": base_metrics["correct_bits"],
            "base_hamming_distance": base_metrics["hamming_distance"],
        },
        "resources": {
            "elapsed_seconds": run_summary["elapsed_seconds"],
            "parent_cpu_seconds": None,
            "child_cpu_seconds": None,
            "peak_rss_bytes": run_summary["peak_rss_bytes"],
            "native_probe_branches": 4096,
            "candidate_forward_evaluations": 34824,
            "decoy_calibration_forward_evaluations": 32768,
            "gradient_forward_evaluations": 2056,
            "synthesized_candidates": 12,
            "pre_reveal_verified_candidates": 13,
            "direct_chacha_block_evaluations": 112,
            "decoy_keys": 4096,
            "gradient_keys": 257,
            "primary_live_state_bytes": 2048,
            "all_arms_live_state_bytes": 6144,
            "prefix_snapshots_counted_as_live_state": False,
            "fresh_targets": 1,
            "scientific_entropy_calls": 1,
            "sensor_builds": 1,
            "reveal_calls": 1,
            "solver_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "native_build": provenance["native_build"],
        "source_sha256": source_hashes,
        "next_action": config["next_action"],
        "capsule": EXPECTED_CAPSULE_RELATIVE.as_posix(),
        "terminal_serialization_recovery": {
            "schema": RECOVERY_SCHEMA,
            "no_added_entropy": True,
            "no_added_reveal": True,
            "no_added_science": True,
            "original_error": ORIGINAL_ERROR,
            "original_run_sha256": EXPECTED_RUN_SHA256,
            "science_source_commit": SCIENCE_SOURCE_COMMIT,
            "recovery_source_commit": recovery_commit,
            "recovered_at": recovered_at,
            "unavailable_original_fields": [
                "resources.parent_cpu_seconds",
                "resources.child_cpu_seconds",
            ],
        },
    }

    command = (
        "PYTHONPATH=src python3 -m o1_crypto_lab.o1c58_serialization_recovery "
        f"--capsule {EXPECTED_CAPSULE_RELATIVE.as_posix()}\n"
    ).encode("utf-8")
    note = _recovery_note(recovery_commit, recovered_at)
    original_members = cast(dict[str, bytes], frozen["members"])
    ledger_members = {
        **original_members,
        RECOVERY_COMMAND_NAME: command,
        RECOVERY_NOTE_NAME: note,
    }
    normalized, result_bytes, manifest = _converge_result_manifest(
        result, ledger_members
    )
    budget = _mapping(config.get("budgets"), "budgets")
    persistent = _integer(
        _mapping(normalized["resources"], "resources")["persistent_artifact_bytes"],
        "persistent artifact bytes",
    )
    if persistent > _integer(
        budget["maximum_persistent_artifact_bytes"], "persistent artifact budget"
    ):
        raise O1C58RecoveryError("recovered capsule exceeds persistent budget")

    if (
        sum(len(payload) for payload in ledger_members.values())
        + len(result_bytes)
        + len(manifest)
        != persistent
    ):
        raise O1C58RecoveryError("recovered persistent byte ledger differs")
    _install_recovery_outputs(
        capsule=capsule,
        authoritative=authoritative,
        original_members=original_members,
        command=command,
        note=note,
        result_bytes=result_bytes,
        manifest=manifest,
    )
    return normalized


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Seal the already-consumed O1C-0058 partial capsule"
    )
    parser.add_argument("--capsule", required=True)
    arguments = parser.parse_args()
    result = recover(arguments.capsule)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "O1C58RecoveryError",
    "_converge_result_manifest",
    "_manifest_bytes",
    "_normalize_json",
    "_parse_run_markdown",
    "_reconstruct_truth",
    "main",
    "recover",
]
