"""O1C-0077 bounded residual-polarity staging science call.

The immutable causal attic and the native rank source are never rewritten.  A
separate target-free residency state chooses one K=256 solver input for each
fresh lineage ordinal.  Every native call is preceded by a durable intent, and
every complete emission ledger is archived before the next residency page is
eligible to become a science input.

This module owns its execution and recovery state machine.  The science call
consumes only the frozen O1C-0077 seed; it never replays the mutable parent
layout or calls a target/reveal surface.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import math
import os
import resource
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v18 as _native_v18
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .causal_attic_v1 import (
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    reproject_causal_attic,
    sha256_bytes,
)
from .causal_frontier_v1 import (
    CausalFrontierError,
    CausalFrontierPlan,
    parse_causal_frontier_plan,
    validate_causal_frontier_plan,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    advance_causal_residency,
    replay_causal_residency,
    validate_activation_replay,
)
from .joint_score_sieve_v9 import (
    derive_vault_soft_conflict_ledger,
    validate_vault_soft_conflict_ledger,
)
from .o1c77_apple8_residual_polarity_staging_prepare import (
    FRONTIER_PLAN_BINARY_NAME,
    FRONTIER_PLAN_BINARY_SHA256,
    MANIFEST_SCHEMA as PREPARED_MANIFEST_SCHEMA,
    PreparedResidualPolarityStaging,
    STAGING_PLAN_BINARY_NAME,
    STAGING_PLAN_BINARY_SHA256,
    load_prepared_residual_polarity_staging,
)
from .residual_polarity_staging_v1 import (
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
    parse_residual_polarity_staging_plan,
    validate_o1c77_production_plan,
    validate_residual_polarity_staging_plan,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_caps,
)


ATTEMPT_ID = "O1C-0077"
CONFIG_SCHEMA = "o1-256-apple8-residual-polarity-staging-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-residual-polarity-staging-preflight-v1"
TARGET_FREE_GATE_SCHEMA = (
    "o1-256-o1c77-target-free-residual-polarity-staging-preflight-v1"
)
TARGET_FREE_GATE_CLASSIFICATION = (
    "O1C77_TARGET_FREE_RESIDUAL_POLARITY_STAGING_PREFLIGHT_PASS"
)
INVOCATION_SCHEMA = "o1-256-apple8-residual-polarity-staging-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-residual-polarity-staging-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-residual-polarity-staging-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-residual-polarity-staging-result-v1"
RECOVERY_SOURCE_SCHEMA = (
    "o1-256-apple8-residual-polarity-staging-pre-finalization-source-v1"
)
PUBLICATION_RECOVERY_SCHEMA = (
    "o1-256-apple8-residual-polarity-staging-publication-recovery-v1"
)
ROLLOVER_CHUNK_SCHEMA = "o1-256-causal-residency-rollover-chunk-v1"
RESIDENCY_BOUNDARY_SCHEMA = "o1-256-causal-residency-boundary-v1"
NATIVE_EVIDENCE_SCHEMA = "o1-256-canonical-gzip-native-evidence-v1"

CONFIG_RELATIVE = Path(
    "configs/o1c77_apple8_residual_polarity_staging_v1.json"
)
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0077_TARGET_FREE_RESIDUAL_POLARITY_STAGING_PREFLIGHT_20260720.json"
)
RESULT_RELATIVE = Path(
    "research/O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json"
)
CAPSULE_SUFFIX = "O1C-0077_apple8-residual-polarity-staging-v1"
RECOVERY_SOURCE_NAME = "pre-finalization-recovery-source.json"

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0076_APPLE8_CAUSAL_FRONTIER_RESULT_20260720.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1"
)
PARENT_RESULT_SHA256 = (
    "9459f80444b2dc196251623dfc1f59f014e6593b3b5cd7d8bbaaa5c62f0b671e"
)
PARENT_MANIFEST_SHA256 = (
    "875655a95a30a4f0df01e130a074b0b6a82b98c683575818ad5110cc6a6f1366"
)
PARENT_SOURCE_COMMIT = "f78424e92b1035a07a70350f0ad5666f2c9459e4"
PARENT_LAST_LINEAGE_ORDINAL = 16
RANK_SOURCE_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PARENT_FINAL_ACTIVE_SHA256 = (
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33"
)
INITIAL_ACTIVE_SHA256 = (
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33"
)
INITIAL_UNION_CLAUSES = 550
INITIAL_UNION_LITERALS = 1_488_224
INITIAL_OCCURRENCES = 558
INITIAL_DUPLICATE_OCCURRENCES = 8
INITIAL_CHUNK_CLAUSES = (202, 311, 0, 37, 0, 0, 0, 0, 0)
INITIAL_NEVER_RESIDENT_DEBT = 0

ACTIVE_CLAUSE_LIMIT = 256
LOCAL_EPISODES = (0,)
LINEAGE_ORDINALS = (17,)
REQUESTED_CONFLICTS_PER_EPISODE = 128
MAXIMUM_NATIVE_SOLVER_CALLS = 1
MAXIMUM_TOTAL_REQUESTED_CONFLICTS = 128
SEED = 0
THRESHOLD = 14.606178797892962
FROZEN_BASELINE_TRACE_SHA256 = (
    "f64441a20619d788ab935a870d86f8df8fa07caf4ac4fdda26cc95d10363aa70"
)
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 134_217_728
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MAXIMUM_NATIVE_EXECUTABLE_BYTES = 16_777_216
EXPECTED_NATIVE_EXECUTABLE_SHA256 = (
    "498bdfd584ddcbb1e49a14b5b916909a736f323dc1a9096e711c2343c0d1546e"
)
INHERITED_SCIENCE_INPUT_SHA256 = (
    "fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7",
    "ccfad8b31582baf0b29506387daac84e34998848851ce37e6c072666992022e1",
    "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed",
    "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911",
    "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f",
    "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91",
)

CAPACITY_REASONS = {
    "capacity_clause_count",
    "capacity_literal_count",
    "capacity_payload_bytes",
}

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
THRESHOLD_REGION_EXHAUSTED = "THRESHOLD_REGION_EXHAUSTED"
SAFE_PRUNE_GAIN = "RESIDUAL_POLARITY_STAGING_SAFE_PRUNE_GAIN"
NOVEL_CLAUSE_GAIN = "RESIDUAL_POLARITY_STAGING_NOVEL_CLAUSE_GAIN"
MECHANISM_ONLY = "RESIDUAL_POLARITY_STAGING_MECHANISM_ONLY"
NO_ACTIVATION = "RESIDUAL_POLARITY_STAGING_NO_ACTIVATION_NO_GAIN"
OPERATIONAL_TERMINAL = "RESIDUAL_POLARITY_STAGING_OPERATIONAL_TERMINAL"

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c77_apple8_residual_polarity_staging_run.py",
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency_v1": "src/o1_crypto_lab/causal_residency_v1.py",
    "preparation": (
        "src/o1_crypto_lab/o1c77_apple8_residual_polarity_staging_prepare.py"
    ),
    "threshold_no_good_vault_v1": (
        "src/o1_crypto_lab/threshold_no_good_vault_v1.py"
    ),
    "causal_frontier_v1": "src/o1_crypto_lab/causal_frontier_v1.py",
    "residual_polarity_staging_v1": (
        "src/o1_crypto_lab/residual_polarity_staging_v1.py"
    ),
    "adapter_v18": "src/o1_crypto_lab/joint_score_sieve_v18.py",
    "native_v15": "native/cadical_o1_joint_score_sieve_v15.cpp",
}


class O1C77RunError(RuntimeError):
    """A frozen residency, call, artifact, or publication invariant differs."""


class EpisodeInvoker(Protocol):
    def __call__(
        self,
        local_ordinal: int,
        lineage_ordinal: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
        /,
    ) -> object:
        """Consume one predeclared fresh native subprocess call."""


@dataclass(frozen=True)
class PreparedStream:
    directory: Path | None
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState
    frontier_plan: CausalFrontierPlan
    frontier_plan_document: Mapping[str, object]
    frontier_plan_binary: bytes
    staging_plan: ResidualPolarityStagingPlan
    staging_plan_document: Mapping[str, object]
    staging_plan_binary: bytes

    @property
    def rank_source(self) -> ThresholdNoGoodVault:
        return self.state.attic.chunks[0]


@dataclass(frozen=True)
class StreamOutcome:
    classification: str
    stop_reason: str
    episodes: tuple[Mapping[str, object], ...]
    final_state: CausalResidencyState
    native_calls: int
    requested_conflicts: int
    billed_conflicts: int | None
    globally_novel_clauses: int
    safe_threshold_prunes: int
    mechanism_activated: bool
    baseline_trace_changed: bool
    operational_failure: Mapping[str, object] | None


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) for key in value
    ):
        raise O1C77RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C77RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C77RunError(f"{field} differs")
    return value


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise O1C77RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str, *, pending: bool = False) -> str:
    if pending and value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C77RunError(f"{field} differs")
    return value


def _relative_contract(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C77RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C77RunError(f"{field} escapes the lab")
    return path.as_posix()


def _relative(root: Path, value: object, field: str) -> Path:
    path = Path(_relative_contract(value, field))
    try:
        resolved = (root / path).resolve(strict=True)
    except OSError as exc:
        raise O1C77RunError(f"{field} cannot be resolved") from exc
    if not resolved.is_relative_to(root):
        raise O1C77RunError(f"{field} escapes the lab")
    return resolved


def _regular(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C77RunError(f"{field} cannot be read") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C77RunError(f"{field} is not a regular file")
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError as exc:
        raise O1C77RunError(f"cannot hash {path}") from exc
    return digest.hexdigest()


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    _regular(path, field)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C77RunError(f"{field} JSON differs") from exc
    return _mapping(value, field)


def _atomic_create(path: Path, payload: bytes, *, immutable: bool = False) -> None:
    if not isinstance(payload, bytes) or path.exists() or path.is_symlink():
        raise O1C77RunError(f"owned artifact already exists: {path.name}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if immutable:
            path.chmod(0o444)
    except O1C77RunError:
        raise
    except OSError as exc:
        raise O1C77RunError(f"cannot publish owned artifact: {path.name}") from exc
    if path.read_bytes() != payload:
        raise O1C77RunError(f"owned artifact reread differs: {path.name}")


def _atomic_json(path: Path, value: object, *, immutable: bool = False) -> None:
    _atomic_create(path, canonical_json_bytes(value), immutable=immutable)


def _canonical_gzip(payload: bytes) -> bytes:
    if not isinstance(payload, bytes):
        raise O1C77RunError("native evidence payload differs")
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0
    ) as stream:
        stream.write(payload)
    compressed = output.getvalue()
    try:
        restored = gzip.decompress(compressed)
    except OSError as exc:
        raise O1C77RunError("native evidence compression differs") from exc
    if restored != payload:
        raise O1C77RunError("native evidence compression differs")
    return compressed


def _write_compressed_json(path: Path, value: object) -> dict[str, object]:
    payload = canonical_json_bytes(value)
    compressed = _canonical_gzip(payload)
    _atomic_create(path, compressed, immutable=True)
    return {
        "schema": NATIVE_EVIDENCE_SCHEMA,
        "path": path.name,
        "compression": "gzip-9;mtime=0;empty-filename",
        "compressed_sha256": sha256_bytes(compressed),
        "compressed_bytes": len(compressed),
        "uncompressed_sha256": sha256_bytes(payload),
        "uncompressed_bytes": len(payload),
    }


def _read_compressed_json(
    base: Path, row: object, field: str
) -> Mapping[str, object]:
    metadata = _mapping(row, field)
    if metadata.get("schema") != NATIVE_EVIDENCE_SCHEMA:
        raise O1C77RunError(f"{field} schema differs")
    name = metadata.get("path")
    if not isinstance(name, str) or Path(name).name != name:
        raise O1C77RunError(f"{field} path differs")
    path = _regular(base / name, field)
    compressed = path.read_bytes()
    if (
        len(compressed)
        != _nonnegative_int(metadata.get("compressed_bytes"), f"{field} bytes")
        or sha256_bytes(compressed)
        != _sha256(metadata.get("compressed_sha256"), f"{field} digest")
    ):
        raise O1C77RunError(f"{field} compressed artifact differs")
    try:
        payload = gzip.decompress(compressed)
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C77RunError(f"{field} payload differs") from exc
    if (
        len(payload)
        != _nonnegative_int(metadata.get("uncompressed_bytes"), f"{field} raw bytes")
        or sha256_bytes(payload)
        != _sha256(metadata.get("uncompressed_sha256"), f"{field} raw digest")
        or canonical_json_bytes(value) != payload
    ):
        raise O1C77RunError(f"{field} canonical payload differs")
    return _mapping(value, field)


def _artifact_row(path: Path, *, relative_to: Path) -> dict[str, object]:
    _regular(path, "artifact")
    return {
        "path": path.relative_to(relative_to).as_posix(),
        "sha256": _sha256_file(path),
        "serialized_bytes": path.stat().st_size,
    }


def _validate_artifact_row(root: Path, value: object, field: str) -> Path:
    row = _mapping(value, field)
    relative = row.get("path")
    if not isinstance(relative, str):
        raise O1C77RunError(f"{field} path differs")
    path_value = Path(relative)
    if path_value.is_absolute() or ".." in path_value.parts:
        raise O1C77RunError(f"{field} path escapes")
    path = _regular(root / path_value, field)
    if (
        path.stat().st_size
        != _nonnegative_int(row.get("serialized_bytes"), f"{field} bytes")
        or _sha256_file(path) != _sha256(row.get("sha256"), f"{field} digest")
    ):
        raise O1C77RunError(f"{field} artifact differs")
    return path


def _validate_regular_capsule_tree(capsule: Path) -> None:
    try:
        root_metadata = capsule.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(
            root_metadata.st_mode
        ):
            raise O1C77RunError("capsule tree root differs")
        for path in capsule.rglob("*"):
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (
                stat.S_ISREG(mode) or stat.S_ISDIR(mode)
            ):
                raise O1C77RunError("capsule tree contains a non-regular entry")
    except O1C77RunError:
        raise
    except OSError as exc:
        raise O1C77RunError("capsule tree cannot be inspected") from exc


def _parse_vault(
    payload: bytes,
    *,
    identity: object,
    observed_variables: tuple[int, ...],
) -> ThresholdNoGoodVault:
    try:
        vault = parse_threshold_no_good_vault(
            payload,
            observed_variables=observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        if vault.identity != identity:
            raise O1C77RunError("causal-residency vault identity differs")
        return vault
    except O1C77RunError:
        raise
    except ThresholdNoGoodVaultError as exc:
        raise O1C77RunError("causal-residency vault artifact differs") from exc


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C77RunError("occurrence schema differs")
    records = _sequence(document.get("records"), "occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C77RunError("occurrence ordinal differs")
        clause = clauses[union_index]
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=_nonnegative_int(
                    row.get("source_index"), "occurrence source index"
                ),
                classification=cast(str, row.get("classification")),
                source=cast(str, row.get("source")),
                witness_score_f64le_hex=cast(
                    str, row.get("witness_score_f64le_hex")
                ),
                clause=clause,
                clause_sha256=cast(str, row.get("clause_sha256")),
                witness_sha256=cast(str, row.get("witness_sha256")),
            )
        except (CausalAtticError, TypeError) as exc:
            raise O1C77RunError("occurrence record differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C77RunError("occurrence record differs")
        occurrences.append(occurrence)
    if (
        document.get("occurrence_count") != len(occurrences)
        or document.get("unique_clause_count") != len(clauses)
    ):
        raise O1C77RunError("occurrence ledger differs")
    return tuple(occurrences)


def _copy_immutable(path: Path, payload: bytes) -> dict[str, object]:
    _atomic_create(path, payload, immutable=True)
    return {
        "path": path.name,
        "sha256": sha256_bytes(payload),
        "serialized_bytes": len(payload),
    }


def _coerce_prepared(value: PreparedResidualPolarityStaging) -> PreparedStream:
    """Narrow the preparation package to the runner's immutable view."""

    try:
        directory = value.directory
        manifest = value.manifest
        manifest_bytes = value.manifest_bytes
        manifest_sha256 = value.manifest_sha256
        state = value.state
        frontier_plan = value.frontier_plan
        frontier_plan_document = value.frontier_plan_document
        frontier_plan_binary = value.frontier_plan_binary
        staging_plan = value.staging_plan
        staging_plan_document = value.staging_plan_document
        staging_plan_binary = value.staging_plan_binary
        rank_decision = value.rank_decision
    except AttributeError as exc:
        raise O1C77RunError("prepared causal-residency object differs") from exc
    if (
        directory is not None and not isinstance(directory, Path)
    ) or not isinstance(state, CausalResidencyState) or not isinstance(
        frontier_plan, CausalFrontierPlan
    ) or not isinstance(staging_plan, ResidualPolarityStagingPlan
    ):
        raise O1C77RunError("prepared staging object differs")
    try:
        validate_causal_frontier_plan(
            frontier_plan, active_vault=state.active_projection
        )
        if parse_causal_frontier_plan(
            cast(bytes, frontier_plan_binary),
            active_vault=state.active_projection,
        ) != frontier_plan:
            raise O1C77RunError("prepared causal-frontier binary differs")
        validate_residual_polarity_staging_plan(
            staging_plan,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        validate_o1c77_production_plan(staging_plan)
        if parse_residual_polarity_staging_plan(
            cast(bytes, staging_plan_binary),
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        ) != staging_plan:
            raise O1C77RunError("prepared staging binary differs")
        if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
            raise O1C77RunError("prepared plan ancestry differs")
    except (CausalFrontierError, ResidualPolarityStagingError) as exc:
        raise O1C77RunError("prepared staging object differs") from exc
    return PreparedStream(
        directory,
        dict(_mapping(manifest, "prepared manifest")),
        cast(bytes, manifest_bytes),
        _sha256(manifest_sha256, "prepared manifest digest"),
        state,
        frontier_plan,
        dict(_mapping(frontier_plan_document, "prepared frontier plan document")),
        cast(bytes, frontier_plan_binary),
        staging_plan,
        dict(_mapping(staging_plan_document, "prepared staging plan document")),
        cast(bytes, staging_plan_binary),
    )


def load_prepared_stream(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedStream:
    """Load O1C77 preparation through its attempt-specific validator."""

    try:
        prepared = load_prepared_residual_polarity_staging(
            directory, expected_manifest_sha256=expected_manifest_sha256
        )
    except Exception as exc:
        if isinstance(exc, O1C77RunError):
            raise
        raise O1C77RunError("prepared causal-frontier validation differs") from exc
    return _coerce_prepared(prepared)


def prepared_stream_from_state(
    state: CausalResidencyState,
    *,
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
    frontier_plan_document: Mapping[str, object] | None = None,
    staging_plan_document: Mapping[str, object] | None = None,
    manifest: Mapping[str, object] | None = None,
) -> PreparedStream:
    """Construct an in-memory prepared stream for target-free test fixtures."""

    if not isinstance(state, CausalResidencyState):
        raise O1C77RunError("prepared residency state differs")
    validate_activation_replay(state)
    validate_causal_frontier_plan(frontier_plan, active_vault=state.active_projection)
    if staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256:
        raise O1C77RunError("prepared plan ancestry differs")
    value: Mapping[str, object] = manifest or {
        "schema": PREPARED_MANIFEST_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "rank_source_vault_sha256": state.attic.chunks[0].sha256,
        "residency": state.describe(),
        "artifact_set": {"artifacts": {}},
    }
    payload = canonical_json_bytes(value)
    return PreparedStream(
        None,
        dict(value),
        payload,
        sha256_bytes(payload),
        state,
        frontier_plan,
        dict(frontier_plan_document or {"plan": frontier_plan.describe()}),
        frontier_plan.serialized,
        staging_plan,
        dict(staging_plan_document or {"plan": staging_plan.describe()}),
        staging_plan.serialized,
    )


def _vault_equal(left: object, right: ThresholdNoGoodVault) -> bool:
    return isinstance(left, ThresholdNoGoodVault) and left.serialized == right.serialized


def _native_failure(exc: BaseException) -> dict[str, object]:
    telemetry = getattr(exc, "failure_telemetry", None)
    return {
        "error_type": type(exc).__qualname__,
        "error_message": str(exc),
        "failure_telemetry": (
            dict(telemetry) if isinstance(telemetry, Mapping) else None
        ),
    }


def _validate_archived_v18_provenance(
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
    frontier: Mapping[str, object],
    staging: Mapping[str, object],
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
    telemetry: Mapping[str, object],
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    status: int,
    stats: Mapping[str, int],
    resources: Mapping[str, object],
    sieve: Mapping[str, object],
    key_model: bytes | None,
) -> None:
    """Cross-bind canonical native bytes and every promoted typed view."""

    try:
        _native_v18.validate_native_lifecycle(raw)
    except Exception as exc:
        raise O1C77RunError("archived native v18 lifecycle differs") from exc
    raw_stats = _mapping(raw.get("stats"), "archived native stats")
    raw_resources = _mapping(raw.get("resources"), "archived native resources")
    raw_sieve = _mapping(raw.get("sieve"), "archived native sieve")
    try:
        derived_stats = derive_vault_soft_conflict_ledger(
            raw_stats,
            requested_conflicts=REQUESTED_CONFLICTS_PER_EPISODE,
        )
    except Exception as exc:
        raise O1C77RunError("archived native conflict provenance differs") from exc
    expected_model = key_model.hex() if key_model is not None else None
    if (
        raw.get("schema") != _native_v18.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or raw.get("implementation_parent_schema")
        != _native_v18.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or raw.get("implementation_release_parent_schema")
        != _native_v18.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or raw.get("rank_source_vault_sha256") != rank_source.sha256
        or raw.get("frontier_plan_sha256") != frontier_plan.sha256
        or raw.get("frontier_source_result_sha256")
        != frontier_plan.source_result_sha256
        or raw.get("staging_plan_sha256") != staging_plan.sha256
        or raw.get("staging_source_result_sha256")
        != staging_plan.source_result_sha256
        or raw.get("reader_rank_role") != "effective-derived-order"
        or raw.get("reader") != reader
        or raw.get("frontier") != frontier
        or raw.get("staging") != staging
        or frontier.get("plan_sha256") != frontier_plan.sha256
        or staging.get("plan_sha256") != staging_plan.sha256
        or staging.get("parent_frontier_plan_sha256") != frontier_plan.sha256
        or staging.get("source_rank_payload_sha256")
        != staging_plan.source_rank_payload_sha256
        or staging.get("source_rank_order_sha256")
        != staging_plan.source_rank_order_sha256
        or staging.get("effective_rank_order_sha256")
        != staging_plan.effective_rank_order_sha256
        or raw.get("vault") != telemetry
        or reader.get("source_vault_sha256") != rank_source.sha256
        or telemetry.get("input_sha256") != active.sha256
        or telemetry.get("input_clause_aggregate_sha256")
        != active.clause_aggregate_sha256
        or raw.get("cnf_sha256") != active.identity.cnf_sha256
        or raw.get("potential_sha256") != active.identity.potential_sha256
        or raw.get("conflict_limit") != REQUESTED_CONFLICTS_PER_EPISODE
        or raw.get("seed") != SEED
        or raw.get("threshold") != active.identity.threshold
        or raw.get("status") != status
        or raw.get("key_model_hex") != expected_model
        or derived_stats != dict(stats)
        or dict(raw_resources) != dict(resources)
        or raw_sieve.get("external_clauses_emitted")
        != sieve.get("external_clauses_emitted")
        or raw_sieve.get("pending_clause_count")
        != sieve.get("pending_clause_count")
        or raw_sieve.get("grouping_sha256") != active.identity.grouping_sha256
    ):
        raise O1C77RunError("archived native v18 provenance differs")


def _validated_episode_result(
    result: object,
    *,
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
    stream_id: str,
    verify_public_model: Callable[[bytes], bool],
    require_concrete_result: bool,
) -> dict[str, object]:
    """Bind one adapter-certified v18 return to its exact residency page."""

    try:
        if require_concrete_result and not isinstance(
            result, _native_v18.JointScoreSieveV18Result
        ):
            raise O1C77RunError("native result type differs")
        raw = _mapping(getattr(result, "raw"), "native raw result")
        reader = _mapping(getattr(result, "reader"), "native reader")
        frontier = _mapping(getattr(result, "frontier"), "native frontier reader")
        staging = _mapping(getattr(result, "staging"), "native staging reader")
        result_frontier_plan = getattr(result, "frontier_plan")
        result_staging_plan = getattr(result, "staging_plan")
        telemetry = _mapping(
            getattr(result, "vault_telemetry"), "native vault telemetry"
        )
        stats = validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native conflict ledger")
        )
        resources = _mapping(getattr(result, "resources"), "native resources")
        sieve = _mapping(getattr(result, "sieve"), "native sieve")
        status = getattr(result, "status")
        key_model = getattr(result, "key_model")
        if (
            isinstance(status, bool)
            or status not in (0, 10, 20)
            or getattr(result, "conflict_limit")
            != REQUESTED_CONFLICTS_PER_EPISODE
            or getattr(result, "threshold") != rank_source.identity.threshold
            or stats["requested_conflicts"]
            != REQUESTED_CONFLICTS_PER_EPISODE
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or not _vault_equal(getattr(result, "rank_source_vault"), rank_source)
            or not _vault_equal(getattr(result, "input_vault"), active)
            or result_frontier_plan != frontier_plan
            or result_staging_plan != staging_plan
        ):
            raise O1C77RunError("native split-vault result binding differs")
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        if peak > MEMORY_LIMIT_BYTES or wall > int(TIMEOUT_SECONDS * 1_000_000):
            raise O1C77RunError("native resource boundary differs")
        pending = _nonnegative_int(
            sieve.get("pending_clause_count"), "native pending clause count"
        )
        emitted_count = _nonnegative_int(
            sieve.get("external_clauses_emitted"), "native emitted clause count"
        )
        if pending != 0:
            raise O1C77RunError("native result retained an incomplete clause")

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
            or parsed.input_clause_aggregate_sha256
            != active.clause_aggregate_sha256
            or emitted_count != len(parsed.occurrences)
        ):
            raise O1C77RunError("native emitted ledger input binding differs")

        eligible = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible, Sequence) or isinstance(
            eligible, (str, bytes, bytearray)
        ) or len(eligible) != len(parsed.occurrences):
            raise O1C77RunError("native typed emission ledger differs")
        for item, occurrence in zip(eligible, parsed.occurrences, strict=True):
            if (
                getattr(item, "index", None) != occurrence.source_index
                or getattr(item, "source", None) != occurrence.source
                or getattr(item, "classification", None)
                != occurrence.classification
                or getattr(item, "clause", None) != occurrence.clause
                or getattr(item, "clause_sha256", None)
                != occurrence.clause_sha256
                or getattr(item, "witness_sha256", None)
                != occurrence.witness_sha256
                or getattr(item, "witness_score", None)
                != occurrence.witness_score
            ):
                raise O1C77RunError("native typed emission occurrence differs")

        available = telemetry.get("next_vault_available")
        terminal_reason = telemetry.get("next_vault_terminal_reason")
        next_vault = getattr(result, "next_vault")
        if not isinstance(available, bool):
            raise O1C77RunError("native next-vault availability differs")
        if available:
            if terminal_reason is not None or not isinstance(
                next_vault, ThresholdNoGoodVault
            ):
                raise O1C77RunError("available native next vault differs")
        elif terminal_reason not in CAPACITY_REASONS or next_vault is not None:
            raise O1C77RunError("native rollover reason differs")

        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C77RunError(
                    "public candidate failed eight-block verification"
                )
        elif key_model is not None:
            raise O1C77RunError("non-SAT stream result returned a candidate")
        _validate_archived_v18_provenance(
            raw=raw,
            reader=reader,
            frontier=frontier,
            staging=staging,
            frontier_plan=frontier_plan,
            staging_plan=staging_plan,
            telemetry=telemetry,
            rank_source=rank_source,
            active=active,
            status=status,
            stats=stats,
            resources=resources,
            sieve=sieve,
            key_model=key_model,
        )
        initial_returns = _nonnegative_int(
            frontier.get("initial_once_returns"),
            "frontier initial return count",
        )
        contrast_returns = _nonnegative_int(
            frontier.get("contrast_returns"),
            "frontier contrast return count",
        )
        parent_nonzero = _nonnegative_int(
            frontier.get("parent_nonzero_returns"),
            "frontier parent nonzero count",
        )
        outer_nonzero = _nonnegative_int(
            frontier.get("outer_nonzero_returns"),
            "frontier outer nonzero count",
        )
        substitutions = initial_returns + contrast_returns
        events = _sequence(
            frontier.get("substitution_events"),
            "frontier substitution events",
        )
        first_return = frontier.get("first_frontier_return_call")
        trace_sha256 = _sha256(sieve.get("trace_sha256"), "native trace digest")
        safe_threshold_prunes = _nonnegative_int(
            sieve.get("threshold_prunes"), "native threshold prune count"
        )
        if (
            substitutions != len(events)
            or outer_nonzero - parent_nonzero != substitutions
            or (substitutions == 0) is not (first_return is None)
            or (
                first_return is not None
                and _nonnegative_int(first_return, "first frontier return call") < 1
            )
        ):
            raise O1C77RunError("frontier activation ledger differs")
        effective_returns = _nonnegative_int(
            staging.get("overlay_effective_returns"),
            "staging effective return count",
        )
        staging_contrast_returns = _nonnegative_int(
            staging.get("overlay_contrast_returns"),
            "staging contrast return count",
        )
        staged_returns = effective_returns + staging_contrast_returns
        staging_events = _sequence(
            staging.get("overlay_return_events"), "staging return events"
        )
        native_staging_activated = staging.get("mechanism_activated")
        unit_activation = staging.get("unit_activation")
        if (
            not isinstance(native_staging_activated, bool)
            or not isinstance(unit_activation, bool)
            or len(staging_events) != staged_returns
            or native_staging_activated is not (staged_returns > 0)
        ):
            raise O1C77RunError("staging activation ledger differs")
        trace_changed = trace_sha256 != FROZEN_BASELINE_TRACE_SHA256
        qualified_staging = (
            staged_returns > 0 and native_staging_activated and trace_changed
        )
        return {
            "raw": dict(raw),
            "reader": dict(reader),
            "frontier": dict(frontier),
            "staging": dict(staging),
            "telemetry": dict(telemetry),
            "telemetry_payload": telemetry_payload,
            "occurrences": parsed.occurrences,
            "stats": stats,
            "status": status,
            "key_model": key_model,
            "next_vault_available": available,
            "next_vault_terminal_reason": terminal_reason,
            "frontier_substitution_count": substitutions,
            "frontier_mechanism_activated": substitutions > 0,
            "staged_return_count": staged_returns,
            "staging_mechanism_activated": native_staging_activated,
            "staging_unit_activation": unit_activation,
            "qualified_staging_mechanism": qualified_staging,
            "trace_sha256": trace_sha256,
            "baseline_trace_sha256": FROZEN_BASELINE_TRACE_SHA256,
            "baseline_trace_changed": trace_changed,
            "safe_threshold_prunes": safe_threshold_prunes,
            "resources": {
                "peak_rss_bytes": peak,
                "wall_microseconds": wall,
                "cpu_microseconds": cpu,
            },
        }
    except O1C77RunError:
        raise
    except Exception as exc:
        raise O1C77RunError("native O1C-0077 result differs") from exc


def validate_native_executable(
    path: str | Path, *, expected_sha256: str
) -> dict[str, object]:
    """Boundedly read and freeze the exact regular executable used by calls."""

    supplied = Path(path).absolute()
    try:
        metadata = supplied.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o111 == 0
            or metadata.st_size < 1
            or metadata.st_size > MAXIMUM_NATIVE_EXECUTABLE_BYTES
        ):
            raise O1C77RunError("native executable mode differs")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(supplied, flags)
        try:
            before = os.fstat(descriptor)
            chunks: list[bytes] = []
            remaining = MAXIMUM_NATIVE_EXECUTABLE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(1 << 20, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except O1C77RunError:
        raise
    except OSError as exc:
        raise O1C77RunError("native executable cannot be read") from exc
    expected = _sha256(expected_sha256, "native executable digest")
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_mode != after.st_mode
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_size != len(payload)
        or len(payload) > MAXIMUM_NATIVE_EXECUTABLE_BYTES
        or sha256_bytes(payload) != expected
    ):
        raise O1C77RunError("native executable identity differs")
    executable = supplied.resolve(strict=True)
    return {
        "path": executable.as_posix(),
        "sha256": expected,
        "serialized_bytes": len(payload),
        "regular_file": True,
        "symlink": False,
        "executable_mode": True,
        "maximum_read_bytes": MAXIMUM_NATIVE_EXECUTABLE_BYTES,
    }


def _initial_artifacts(
    capsule: Path, prepared: PreparedStream
) -> dict[str, object]:
    """Materialize all immutable chunks and the complete initial residency."""

    initial = capsule / "initial"
    if initial.exists():
        raise O1C77RunError("initial causal-residency directory already exists")
    initial.mkdir(parents=True)
    state = prepared.state
    validate_activation_replay(state)
    chunk_rows = []
    for index, chunk in enumerate(state.attic.chunks):
        row = _copy_immutable(initial / f"chunk-{index:02d}.vault", chunk.serialized)
        chunk_rows.append({"chunk_index": index, **row})
    active_row = _copy_immutable(
        initial / "active-projection.bin", state.active_projection.serialized
    )
    occurrences_row = _copy_immutable(
        initial / "witness-occurrences.json",
        canonical_json_bytes(state.attic.occurrence_document()),
    )
    relations_row = _copy_immutable(
        initial / "subsumption-relations.json",
        canonical_json_bytes(state.attic.relation_document()),
    )
    ledger_row = _copy_immutable(
        initial / "activation-ledger.json",
        canonical_json_bytes(state.activation_ledger_document()),
    )
    prepared_row = _copy_immutable(
        initial / "prepared-manifest.json", prepared.manifest_bytes
    )
    frontier_plan_row = _copy_immutable(
        initial / FRONTIER_PLAN_BINARY_NAME, prepared.frontier_plan_binary
    )
    frontier_plan_document_row = _copy_immutable(
        initial / "frontier-plan.json",
        canonical_json_bytes(prepared.frontier_plan_document),
    )
    staging_plan_row = _copy_immutable(
        initial / STAGING_PLAN_BINARY_NAME, prepared.staging_plan_binary
    )
    staging_plan_document_row = _copy_immutable(
        initial / "staging-plan.json",
        canonical_json_bytes(prepared.staging_plan_document),
    )
    return {
        "chunks": chunk_rows,
        "active_projection": active_row,
        "occurrences": occurrences_row,
        "relations": relations_row,
        "activation_ledger": ledger_row,
        "prepared_manifest": prepared_row,
        "frontier_plan": frontier_plan_row,
        "frontier_plan_document": frontier_plan_document_row,
        "staging_plan": staging_plan_row,
        "staging_plan_document": staging_plan_document_row,
        "residency": state.describe(),
    }


def _invocation_document(
    prepared: PreparedStream,
    initial_rows: Mapping[str, object],
    bindings: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "rank_source_vault": prepared.rank_source.describe(),
        "initial_residency": prepared.state.describe(),
        "frontier_plan": prepared.frontier_plan.describe(),
        "staging_plan": prepared.staging_plan.describe(),
        "initial_artifacts": dict(initial_rows),
        "active_clause_limit": ACTIVE_CLAUSE_LIMIT,
        "local_episode_ordinals": list(LOCAL_EPISODES),
        "lineage_call_ordinals": list(LINEAGE_ORDINALS),
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
        "bindings": dict(bindings),
        "truth_key_bytes_read": False,
        "retry_authorized": False,
    }


def _failure_episode(
    *,
    episode_dir: Path,
    local_ordinal: int,
    lineage_ordinal: int,
    invocation_sha256: str,
    intent_sha256: str,
    active: ThresholdNoGoodVault,
    state: CausalResidencyState,
    exc: BaseException,
    native_result_returned: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    failure = {
        "classification": OPERATIONAL_TERMINAL,
        "local_episode_ordinal": local_ordinal,
        "lineage_call_ordinal": lineage_ordinal,
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "occurred_after_persisted_intent": True,
        "native_result_returned": native_result_returned,
        "fully_emitted_occurrences_retained": False,
        "orphan_post_native_artifacts_possible": native_result_returned,
        "native_calls_consumed": 1,
        "requested_conflicts_consumed": REQUESTED_CONFLICTS_PER_EPISODE,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
        **_native_failure(exc),
    }
    _atomic_json(episode_dir / "terminal-failure.json", failure, immutable=True)
    episode = {
        "schema": EPISODE_SCHEMA,
        "completed": False,
        "local_episode_ordinal": local_ordinal,
        "lineage_call_ordinal": lineage_ordinal,
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "input_active_vault": active.describe(),
        "residency_before": state.describe(),
        "residency_after": state.describe(),
        "native_calls_consumed": 1,
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "billed_conflicts": None,
        "retry_authorized": False,
        "terminal_failure": failure,
    }
    _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    return episode, failure


def _projection_document(state: CausalResidencyState) -> Mapping[str, object]:
    projection = state.current_projection
    describe = getattr(projection, "describe", None)
    if callable(describe):
        return _mapping(describe(), "residency projection")
    return _mapping(projection, "residency projection")


def _activation_ledger_document(
    state: CausalResidencyState,
) -> Mapping[str, object] | Sequence[object]:
    description = _mapping(state.describe(), "residency state")
    for field in ("activation_ledger", "ledger"):
        value = description.get(field)
        if isinstance(value, Mapping):
            return _mapping(value, "activation ledger")
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            return _sequence(value, "activation ledger")
    raise O1C77RunError("residency activation ledger differs")


def _executable_binding(
    bindings: Mapping[str, object], field: str
) -> Mapping[str, object] | None:
    raw = bindings.get("native_executable")
    if raw is None:
        return None
    binding = _mapping(raw, field)
    if not isinstance(binding.get("path"), str):
        raise O1C77RunError(f"{field} path differs")
    _sha256(binding.get("sha256"), f"{field} digest")
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
        raise O1C77RunError(f"native executable changed {when} call")


def execute_stream(
    *,
    capsule: Path,
    prepared: PreparedStream,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object] | None = None,
) -> StreamOutcome:
    """Consume exactly local 0 / lineage 17, without replay or retry."""

    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or not callable(invoke_episode)
        or not callable(verify_public_model)
        or not isinstance(prepared, PreparedStream)
        or prepared.state.active_projection.clause_count > ACTIVE_CLAUSE_LIMIT
        or prepared.rank_source.identity
        != prepared.state.active_projection.identity
    ):
        raise O1C77RunError("stream execution input differs")
    try:
        validate_activation_replay(prepared.state)
    except CausalResidencyError as exc:
        raise O1C77RunError("initial residency replay differs") from exc
    normalized_bindings = dict(bindings or {})
    executable_binding = _executable_binding(
        normalized_bindings, "execution native executable"
    )
    initial_rows = _initial_artifacts(capsule, prepared)
    invocation = _invocation_document(prepared, initial_rows, normalized_bindings)
    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, invocation, immutable=True)
    invocation_sha = _sha256_file(invocation_path)
    rank_path = capsule / "initial" / "chunk-00.vault"
    frontier_plan_path = capsule / "initial" / FRONTIER_PLAN_BINARY_NAME
    staging_plan_path = capsule / "initial" / STAGING_PLAN_BINARY_NAME
    if rank_path.read_bytes() != prepared.rank_source.serialized:
        raise O1C77RunError("rank-source capsule bytes differ")
    try:
        if parse_causal_frontier_plan(
            frontier_plan_path.read_bytes(),
            active_vault=prepared.state.active_projection,
        ) != prepared.frontier_plan:
            raise O1C77RunError("frontier-plan capsule bytes differ")
    except CausalFrontierError as exc:
        raise O1C77RunError("frontier-plan capsule bytes differ") from exc
    try:
        if parse_residual_polarity_staging_plan(
            staging_plan_path.read_bytes()
        ) != prepared.staging_plan:
            raise O1C77RunError("staging-plan capsule bytes differ")
    except ResidualPolarityStagingError as exc:
        raise O1C77RunError("staging-plan capsule bytes differ") from exc

    state = prepared.state
    episodes: list[Mapping[str, object]] = []
    billed_total = 0
    global_novel_total = 0
    native_calls = 0
    requested_total = 0
    safe_prune_total = 0
    mechanism_activated = False
    baseline_trace_changed = False
    science_inputs: set[str] = set(INHERITED_SCIENCE_INPUT_SHA256)

    for local_ordinal, lineage_ordinal in zip(
        LOCAL_EPISODES, LINEAGE_ORDINALS, strict=True
    ):
        episode_dir = capsule / "episodes" / f"{local_ordinal:02d}"
        episode_dir.mkdir(parents=True, exist_ok=False)
        active_before = state.active_projection
        if (
            active_before.clause_count > ACTIVE_CLAUSE_LIMIT
            or active_before.sha256 in science_inputs
        ):
            raise O1C77RunError(
                "active residency page was already recorded as a science input"
            )
        active_path = episode_dir / "active-input.bin"
        active_row = _copy_immutable(active_path, active_before.serialized)
        reread_active = _parse_vault(
            active_path.read_bytes(),
            identity=prepared.rank_source.identity,
            observed_variables=prepared.rank_source.observed_variables,
        )
        if reread_active.serialized != active_before.serialized:
            raise O1C77RunError("episode active input reread differs")
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "local_episode_ordinal": local_ordinal,
            "lineage_call_ordinal": lineage_ordinal,
            "invocation_sha256": invocation_sha,
            "rank_source_vault": prepared.rank_source.describe(),
            "active_input_vault": active_before.describe(),
            "active_input_artifact": active_row,
            "frontier_plan": prepared.frontier_plan.describe(),
            "frontier_plan_artifact": _artifact_row(
                frontier_plan_path, relative_to=capsule / "initial"
            ),
            "staging_plan": prepared.staging_plan.describe(),
            "staging_plan_artifact": _artifact_row(
                staging_plan_path, relative_to=capsule / "initial"
            ),
            "residency_before": state.describe(),
            "projection_before": dict(_projection_document(state)),
            "prior_science_input_sha256": sorted(science_inputs),
            "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "truth_key_bytes_read": False,
            "retry_authorized": False,
        }
        intent_path = episode_dir / "intent.json"
        _atomic_json(intent_path, intent, immutable=True)
        intent_sha = _sha256_file(intent_path)
        native_calls += 1
        requested_total += REQUESTED_CONFLICTS_PER_EPISODE
        try:
            _validate_call_window_executable(executable_binding, when="before")
            result = invoke_episode(
                local_ordinal,
                lineage_ordinal,
                rank_path,
                active_path,
                frontier_plan_path,
                staging_plan_path,
            )
        except BaseException as exc:
            episode, failure = _failure_episode(
                episode_dir=episode_dir,
                local_ordinal=local_ordinal,
                lineage_ordinal=lineage_ordinal,
                invocation_sha256=invocation_sha,
                intent_sha256=intent_sha,
                active=active_before,
                state=state,
                exc=exc,
                native_result_returned=False,
            )
            episodes.append(episode)
            return StreamOutcome(
                OPERATIONAL_TERMINAL,
                "native-call-or-resource-terminal",
                tuple(episodes),
                state,
                native_calls,
                requested_total,
                None,
                global_novel_total,
                safe_prune_total,
                False,
                False,
                failure,
            )

        try:
            _validate_call_window_executable(executable_binding, when="after")
            consumed_science_inputs = science_inputs | {active_before.sha256}
            stream_id = f"o1c77-episode-{local_ordinal:02d}"
            validated = _validated_episode_result(
                result,
                rank_source=prepared.rank_source,
                active=active_before,
                frontier_plan=prepared.frontier_plan,
                staging_plan=prepared.staging_plan,
                stream_id=stream_id,
                verify_public_model=verify_public_model,
                require_concrete_result=(
                    normalized_bindings.get("test_fixture")
                    != "synthetic-target-free"
                ),
            )
            mechanism_activated = cast(
                bool, validated["qualified_staging_mechanism"]
            )
            baseline_trace_changed = cast(
                bool, validated["baseline_trace_changed"]
            )
            safe_prune_total += cast(int, validated["safe_threshold_prunes"])
            occurrences = cast(
                tuple[ClauseOccurrence, ...], validated["occurrences"]
            )
            validated_telemetry = cast(
                Mapping[str, object], validated["telemetry"]
            )
            globally_known = {
                clause.serialized for clause in state.attic.union_vault.clauses
            }
            novel_clauses: list[ThresholdNoGoodClause] = []
            for occurrence in occurrences:
                key = occurrence.clause.serialized
                if key not in globally_known:
                    if occurrence.classification != "new":
                        raise O1C77RunError(
                            "globally novel clause lacks native new classification"
                        )
                    globally_known.add(key)
                    novel_clauses.append(occurrence.clause)
            rollover = ThresholdNoGoodVault(
                prepared.rank_source.identity,
                prepared.rank_source.observed_variables,
                tuple(novel_clauses),
            )
            validate_threshold_no_good_vault_caps(
                rollover, caps=O1C66_VAULT_CAPS
            )
            try:
                next_state = advance_causal_residency(
                    state,
                    chunk=rollover,
                    occurrences=occurrences,
                    next_lineage_ordinal=lineage_ordinal + 1,
                )
                validate_activation_replay(next_state)
            except (CausalAtticError, CausalResidencyError) as exc:
                raise O1C77RunError("episode residency reprojection differs") from exc
            if (
                next_state.active_projection.clause_count > ACTIVE_CLAUSE_LIMIT
                or next_state.active_projection.sha256
                in consumed_science_inputs
            ):
                raise O1C77RunError(
                    "episode residency projection repeats a science input"
                )

            # Returned evidence is written only after full semantic validation;
            # any subsequent I/O failure suppresses retention and gain claims.
            rollover_path = episode_dir / "immutable-rollover.vault"
            rollover_row = _copy_immutable(rollover_path, rollover.serialized)
            reread_rollover = _parse_vault(
                rollover_path.read_bytes(),
                identity=prepared.rank_source.identity,
                observed_variables=prepared.rank_source.observed_variables,
            )
            if reread_rollover.serialized != rollover.serialized:
                raise O1C77RunError("rollover chunk reread differs")
            native_evidence = _write_compressed_json(
                episode_dir / "native-result.json.gz", validated["raw"]
            )
            telemetry_evidence = _write_compressed_json(
                episode_dir / "vault-telemetry.json.gz", validated["telemetry"]
            )
            reader_evidence = _write_compressed_json(
                episode_dir / "decision-reader.json.gz", validated["reader"]
            )
            frontier_evidence = _write_compressed_json(
                episode_dir / "frontier-reader.json.gz",
                validated["frontier"],
            )
            staging_evidence = _write_compressed_json(
                episode_dir / "staging-reader.json.gz",
                validated["staging"],
            )
            active_output_path = episode_dir / "active-output.bin"
            active_output_row = _copy_immutable(
                active_output_path, next_state.active_projection.serialized
            )
            recovered_active = _parse_vault(
                active_output_path.read_bytes(),
                identity=prepared.rank_source.identity,
                observed_variables=prepared.rank_source.observed_variables,
            )
            if recovered_active.serialized != next_state.active_projection.serialized:
                raise O1C77RunError("episode active output reread differs")
            occurrence_delta = {
                "schema": CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
                "stream_id": stream_id,
                "occurrence_count": len(occurrences),
                "records": [
                    occurrence.describe(
                        ordinal=ordinal,
                        union_clause_index=next_state.attic.occurrence_union_indices[
                            len(state.attic.occurrences) + ordinal
                        ],
                    )
                    for ordinal, occurrence in enumerate(occurrences)
                ],
            }
            occurrence_path = episode_dir / "occurrence-delta.json"
            _atomic_json(occurrence_path, occurrence_delta, immutable=True)
            occurrence_row = _artifact_row(
                occurrence_path, relative_to=episode_dir
            )
            ledger_path = episode_dir / "residency-ledger.json"
            _atomic_json(
                ledger_path,
                _activation_ledger_document(next_state),
                immutable=True,
            )
            ledger_row = _artifact_row(ledger_path, relative_to=episode_dir)
            boundary = {
                "schema": RESIDENCY_BOUNDARY_SCHEMA,
                "local_episode_ordinal": local_ordinal,
                "lineage_call_ordinal": lineage_ordinal,
                "next_projection_lineage_ordinal": lineage_ordinal + 1,
                "residency_before": state.describe(),
                "residency_after": next_state.describe(),
                "projection_before": dict(_projection_document(state)),
                "projection_after": dict(_projection_document(next_state)),
                "globally_novel_clause_count": len(novel_clauses),
                "globally_novel_literal_count": sum(
                    clause.literal_count for clause in novel_clauses
                ),
                "fully_emitted_occurrence_count": len(occurrences),
                "fully_emitted_aggregate_sha256": validated_telemetry.get(
                    "fully_emitted_aggregate_sha256"
                ),
                "rollover_chunk": rollover_row,
                "active_output": active_output_row,
                "occurrence_delta": occurrence_row,
                "residency_ledger": ledger_row,
                "science_input_sha256": active_before.sha256,
                "science_input_was_fresh": True,
                "rollover_completed": True,
                "artifacts_reread": True,
                "target_free_reprojection_completed": True,
            }
            boundary_path = episode_dir / "residency-boundary.json"
            _atomic_json(boundary_path, boundary, immutable=True)
            status = cast(int, validated["status"])
            billed = cast(Mapping[str, int], validated["stats"])[
                "billed_conflicts"
            ]
            billed_total += billed
            global_novel_total += len(novel_clauses)
            episode = {
                "schema": EPISODE_SCHEMA,
                "completed": True,
                "local_episode_ordinal": local_ordinal,
                "lineage_call_ordinal": lineage_ordinal,
                "invocation_sha256": invocation_sha,
                "intent_sha256": intent_sha,
                "input_active_vault": active_before.describe(),
                "residency_before": state.describe(),
                "residency_after": next_state.describe(),
                "output_active_vault": next_state.active_projection.describe(),
                "native_calls_consumed": 1,
                "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
                "billed_conflicts": billed,
                "status": status,
                "native_next_vault_available": validated[
                    "next_vault_available"
                ],
                "native_next_vault_terminal_reason": validated[
                    "next_vault_terminal_reason"
                ],
                "capacity_is_rollover_not_terminal": (
                    validated["next_vault_terminal_reason"] in CAPACITY_REASONS
                ),
                "fully_emitted_occurrence_count": len(occurrences),
                "fully_emitted_aggregate_sha256": validated_telemetry.get(
                    "fully_emitted_aggregate_sha256"
                ),
                "globally_novel_clause_count": len(novel_clauses),
                "rollover_chunk_clause_count": rollover.clause_count,
                "rollover_chunk_artifact": rollover_row,
                "active_output_artifact": active_output_row,
                "occurrence_delta_artifact": occurrence_row,
                "residency_ledger_artifact": ledger_row,
                "residency_boundary_sha256": _sha256_file(boundary_path),
                "native_evidence": native_evidence,
                "vault_telemetry_evidence": telemetry_evidence,
                "reader_evidence": reader_evidence,
                "frontier_reader_evidence": frontier_evidence,
                "staging_reader_evidence": staging_evidence,
                "frontier_activation": {
                    "substitution_count": validated[
                        "frontier_substitution_count"
                    ],
                    "mechanism_activated": validated[
                        "frontier_mechanism_activated"
                    ],
                    "native_trace_sha256": validated["trace_sha256"],
                    "frozen_baseline_trace_sha256": validated[
                        "baseline_trace_sha256"
                    ],
                    "baseline_trace_changed": baseline_trace_changed,
                    "trace_change_alone_is_science_gain": False,
                    "safe_threshold_prunes": validated[
                        "safe_threshold_prunes"
                    ],
                },
                "staging_activation": {
                    "staged_return_count": validated["staged_return_count"],
                    "native_mechanism_activated": validated[
                        "staging_mechanism_activated"
                    ],
                    "qualified_mechanism_activated": mechanism_activated,
                    "native_trace_sha256": validated["trace_sha256"],
                    "frozen_baseline_trace_sha256": validated[
                        "baseline_trace_sha256"
                    ],
                    "baseline_trace_changed": baseline_trace_changed,
                    "unit_activation": validated["staging_unit_activation"],
                    "unit_activation_is_science_gain": False,
                    "trace_change_alone_is_science_gain": False,
                    "safe_threshold_prunes": validated[
                        "safe_threshold_prunes"
                    ],
                },
                "work": dict(cast(Mapping[str, object], validated["stats"])),
                "resources": dict(
                    cast(Mapping[str, object], validated["resources"])
                ),
                "public_model": {
                    "present": validated["key_model"] is not None,
                    "verified_8_of_8": status == 10,
                    "model_sha256": (
                        sha256_bytes(cast(bytes, validated["key_model"]))
                        if status == 10
                        else None
                    ),
                    "truth_key_bytes_read": False,
                },
                "science_input_sha256": active_before.sha256,
                "science_input_was_fresh": True,
                "retry_authorized": False,
                "terminal_failure": None,
            }
            _atomic_json(episode_dir / "episode.json", episode, immutable=True)
            episodes.append(episode)
            science_inputs = consumed_science_inputs
            state = next_state
            if status == 10:
                return StreamOutcome(
                    PUBLIC_EXACT_RECOVERY,
                    "public-verified-candidate",
                    tuple(episodes),
                    state,
                    native_calls,
                    requested_total,
                    billed_total,
                    global_novel_total,
                    safe_prune_total,
                    mechanism_activated,
                    baseline_trace_changed,
                    None,
                )
            if status == 20:
                return StreamOutcome(
                    THRESHOLD_REGION_EXHAUSTED,
                    "frozen-score-region-exhausted",
                    tuple(episodes),
                    state,
                    native_calls,
                    requested_total,
                    billed_total,
                    global_novel_total,
                    safe_prune_total,
                    mechanism_activated,
                    baseline_trace_changed,
                    None,
                )
        except BaseException as exc:
            episode, failure = _failure_episode(
                episode_dir=episode_dir,
                local_ordinal=local_ordinal,
                lineage_ordinal=lineage_ordinal,
                invocation_sha256=invocation_sha,
                intent_sha256=intent_sha,
                active=active_before,
                state=state,
                exc=exc,
                native_result_returned=True,
            )
            episodes.append(episode)
            return StreamOutcome(
                OPERATIONAL_TERMINAL,
                "invalid-or-unarchivable-post-native-result",
                tuple(episodes),
                state,
                native_calls,
                requested_total,
                None,
                global_novel_total,
                safe_prune_total,
                mechanism_activated,
                baseline_trace_changed,
                failure,
            )

    if native_calls != MAXIMUM_NATIVE_SOLVER_CALLS or requested_total != (
        MAXIMUM_TOTAL_REQUESTED_CONFLICTS
    ):
        raise O1C77RunError("stream bounded call ledger differs")
    if safe_prune_total:
        classification = SAFE_PRUNE_GAIN
        reason = "certified-threshold-trail-prunes-observed"
    elif global_novel_total:
        classification = NOVEL_CLAUSE_GAIN
        reason = "globally-novel-exact-clauses-retained-in-causal-attic"
    elif mechanism_activated:
        classification = MECHANISM_ONLY
        reason = "qualified-staging-activated-without-predeclared-science-gain"
    else:
        classification = NO_ACTIVATION
        reason = "no-qualified-staging-activation-or-science-gain"
    return StreamOutcome(
        classification,
        reason,
        tuple(episodes),
        state,
        native_calls,
        requested_total,
        billed_total,
        global_novel_total,
        safe_prune_total,
        mechanism_activated,
        baseline_trace_changed,
        None,
    )


def build_result(
    *,
    outcome: StreamOutcome,
    capsule_relative: str,
    source_commit: str,
    preflight: Mapping[str, object] | None = None,
    started_at: str | None = None,
    runtime: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build the terminal record with archive, rank, and residency separated."""

    if (
        not isinstance(outcome, StreamOutcome)
        or not isinstance(capsule_relative, str)
        or not capsule_relative
        or not isinstance(source_commit, str)
    ):
        raise O1C77RunError("result input differs")
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at
        or datetime.now().astimezone().isoformat(timespec="seconds"),
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "capsule": capsule_relative,
        "parent": {
            "attempt_id": "O1C-0076",
            "result_sha256": PARENT_RESULT_SHA256,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "source_commit": PARENT_SOURCE_COMMIT,
            "last_consumed_lineage_ordinal": PARENT_LAST_LINEAGE_ORDINAL,
            "retried": False,
        },
        "rank_source_vault": outcome.final_state.attic.chunks[0].describe(),
        "final_attic": outcome.final_state.attic.describe(),
        "final_residency": outcome.final_state.describe(),
        "final_active_vault": outcome.final_state.active_projection.describe(),
        "episodes": [dict(episode) for episode in outcome.episodes],
        "claim_boundary": {
            "immutable_complete_causal_attic": (
                outcome.operational_failure is None
            ),
            "target_free_residency_replayed": (
                outcome.operational_failure is None
            ),
            "active_projection_clause_limit": ACTIVE_CLAUSE_LIMIT,
            "rank_source_separate_from_active_projection": True,
            "no_science_input_sha256_reused": (
                outcome.operational_failure is None
            ),
            "capacity_event_is_rollover_after_durable_reprojection": True,
            "every_fully_emitted_occurrence_retained": (
                outcome.operational_failure is None
            ),
            "duplicate_witness_occurrences_retained": (
                outcome.operational_failure is None
            ),
            "stopped_after_single_fresh_call": (
                outcome.native_calls <= MAXIMUM_NATIVE_SOLVER_CALLS
            ),
            "qualified_staging_mechanism_activated": outcome.mechanism_activated,
            "baseline_trace_changed": outcome.baseline_trace_changed,
            "trace_change_alone_is_not_science_gain": True,
            "K_sweeps": 0,
            "rank_sweeps": 0,
            "horizon_sweeps": 0,
            "phase_calls": 0,
            "truth_key_bytes_read": False,
            "fresh_targets": 0,
            "scientific_entropy_calls": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "resources": {
            **dict(runtime or {}),
            "native_solver_calls": outcome.native_calls,
            "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
            "requested_conflicts": outcome.requested_conflicts,
            "maximum_total_requested_conflicts": (
                MAXIMUM_TOTAL_REQUESTED_CONFLICTS
            ),
            "billed_conflicts": outcome.billed_conflicts,
            "globally_novel_clauses": outcome.globally_novel_clauses,
            "safe_threshold_prunes": outcome.safe_threshold_prunes,
            "timeout_seconds_per_episode": TIMEOUT_SECONDS,
            "memory_limit_bytes_per_episode": MEMORY_LIMIT_BYTES,
            "persistent_artifact_bytes": 0,
            "publication_recovery_native_solver_calls": 0,
        },
        "operational_failure": (
            dict(outcome.operational_failure)
            if outcome.operational_failure is not None
            else None
        ),
        "publication_recovery": None,
        "preflight": dict(preflight or {}),
        "next_action": (
            "Do not retry this two-overlay operator or replay lineage 17; "
            "if no science gain occurs, evaluate only the sealed 11-row "
            "prefix-preemption successor."
        ),
    }


def write_recovery_source(capsule: Path, result: Mapping[str, object]) -> Path:
    """Seal an explicitly pre-finalization source for zero-call recovery."""

    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C77RunError("pre-finalization recovery result differs")
    result_payload = canonical_json_bytes(result)
    source = {
        "schema": RECOVERY_SOURCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "PRE_FINALIZATION",
        "result_schema": RESULT_SCHEMA,
        "result_sha256": sha256_bytes(result_payload),
        "result_serialized_bytes": len(result_payload),
        "pre_finalization_result": dict(result),
        "native_calls_authorized_during_recovery": 0,
        "public_verification_calls_authorized_during_recovery": 0,
        "truth_key_bytes_read": False,
    }
    path = capsule / RECOVERY_SOURCE_NAME
    _atomic_json(path, source, immutable=True)
    return path


# Compatibility for callers that used the older generic verb.  The bytes and
# schema remain explicitly pre-finalization and are not a second result record.
write_publication_source = write_recovery_source
PUBLICATION_SOURCE_NAME = RECOVERY_SOURCE_NAME


def _runtime_resources(
    *,
    started: float,
    cpu_started: float,
    child_started: resource.struct_rusage,
) -> dict[str, object]:
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    elapsed = max(time.perf_counter() - started, 0.0)
    cpu = max(time.process_time() - cpu_started, 0.0)
    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "elapsed_seconds": elapsed,
        "runner_cpu_seconds": cpu,
        "child_user_seconds": max(child.ru_utime - child_started.ru_utime, 0.0),
        "child_system_seconds": max(
            child.ru_stime - child_started.ru_stime, 0.0
        ),
        "runner_peak_rss_bytes": (
            peak_rss if sys.platform == "darwin" else peak_rss * 1024
        ),
    }


def _markdown(result: Mapping[str, object]) -> bytes:
    resources = _mapping(result.get("resources"), "result resources")
    return (
        "# O1C-0077 — APPLE8 residual-polarity staging\n\n"
        f"- Classification: `{result.get('classification')}`\n"
        f"- Stop reason: `{result.get('stop_reason')}`\n"
        f"- Native calls: `{resources.get('native_solver_calls')}`\n"
        f"- Requested conflicts: `{resources.get('requested_conflicts')}`\n"
        f"- Globally novel clauses: `{resources.get('globally_novel_clauses')}`\n"
        f"- Safe threshold prunes: `{resources.get('safe_threshold_prunes')}`\n"
        "- Active frontier input: one `K=256` Page 4\n"
        "- Reader inputs: one sealed frontier plan plus one sealed staging plan\n"
        "- Immutable rank source is separate from active residency\n"
        "- No active science-input identity is reused\n"
        "- Truth key bytes read: `false`\n"
    ).encode("utf-8")


def _manifest_payload(
    capsule: Path, virtual: Mapping[str, bytes]
) -> tuple[bytes, int]:
    if capsule.is_symlink() or not capsule.is_dir():
        raise O1C77RunError("capsule manifest root differs")
    payloads: dict[str, bytes] = {}
    for path in capsule.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C77RunError("capsule manifest contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256" and relative not in virtual:
                payloads[relative] = path.read_bytes()
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C77RunError("capsule manifest contains a special file")
    payloads.update(virtual)
    lines = [
        f"{sha256_bytes(payload)}  {relative}\n"
        for relative, payload in sorted(payloads.items())
    ]
    manifest = "".join(lines).encode("ascii")
    return manifest, sum(len(payload) for payload in payloads.values()) + len(
        manifest
    )


def finalize_capsule(
    capsule: Path, authoritative: Path, result: dict[str, object]
) -> None:
    """Atomically publish one authoritative result and seal its capsule."""

    if (
        authoritative.exists()
        or (capsule / "result.json").exists()
        or (capsule / "artifacts.sha256").exists()
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C77RunError("terminal O1C77 publication already exists")
    resources = cast(dict[str, object], result["resources"])
    for _ in range(16):
        result_payload = canonical_json_bytes(result)
        run_payload = _markdown(result)
        manifest, persistent = _manifest_payload(
            capsule, {"RUN.md": run_payload, "result.json": result_payload}
        )
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C77RunError("persistent artifact ledger did not converge")
    result_payload = canonical_json_bytes(result)
    run_payload = _markdown(result)
    manifest, persistent = _manifest_payload(
        capsule, {"RUN.md": run_payload, "result.json": result_payload}
    )
    if (
        resources.get("persistent_artifact_bytes") != persistent
        or persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES
    ):
        raise O1C77RunError("persistent artifact byte budget differs")
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    _atomic_create(capsule / "RUN.md", run_payload, immutable=True)
    _atomic_create(capsule / "result.json", result_payload, immutable=True)
    _atomic_create(capsule / "artifacts.sha256", manifest, immutable=True)
    _atomic_create(authoritative, result_payload, immutable=True)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        path.chmod(0o444 if path.is_file() else 0o555)
    capsule.chmod(0o555)
    if authoritative.read_bytes() != result_payload:
        raise O1C77RunError("authoritative result reread differs")


def _existing_authoritative(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    value = dict(_read_json(path, "authoritative O1C77 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C77RunError("authoritative O1C77 result differs")
    if canonical_json_bytes(value) != path.read_bytes():
        raise O1C77RunError("authoritative O1C77 result is not canonical")
    return value


def _republish_sealed_capsule(
    capsule: Path, authoritative: Path
) -> dict[str, object]:
    """Validate a sealed capsule and publish its missing authoritative copy."""

    manifest_path = _regular(
        capsule / "artifacts.sha256", "sealed capsule manifest"
    )
    result_path = _regular(capsule / "result.json", "sealed capsule result")
    expected_manifest, persistent = _manifest_payload(capsule, {})
    result = dict(_read_json(result_path, "sealed capsule result"))
    resources = _mapping(result.get("resources"), "sealed capsule resources")
    try:
        relative_capsule = capsule.relative_to(lab_root()).as_posix()
    except ValueError as exc:
        raise O1C77RunError("sealed capsule escapes lab") from exc
    if (
        manifest_path.read_bytes() != expected_manifest
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("capsule") != relative_capsule
        or resources.get("persistent_artifact_bytes") != persistent
    ):
        raise O1C77RunError("sealed O1C77 capsule differs")
    payload = result_path.read_bytes()
    if canonical_json_bytes(result) != payload:
        raise O1C77RunError("sealed O1C77 result canonical bytes differ")
    _atomic_create(authoritative, payload, immutable=True)
    return result


def _digest_or_pending(value: object, field: str) -> str:
    return _sha256(value, field, pending=True)


def _commit_or_pending(value: object, field: str) -> str:
    if value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C77RunError(f"{field} differs")
    return value


def load_config(
    path: str | Path, *, root: Path | None = None
) -> dict[str, object]:
    """Load the complete frozen O1C77 contract without writing or calling."""

    lab = (root or lab_root()).resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(lab):
        raise O1C77RunError("O1C77 config escapes the lab")
    config = dict(_read_json(config_path, "O1C77 config"))
    required_root = {
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
    if (
        set(config) != required_root
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or not isinstance(config.get("next_action"), str)
        or not config.get("next_action")
    ):
        raise O1C77RunError("frozen O1C77 config fields differ")
    parent = _mapping(config["parent"], "config parent")
    if (
        set(parent)
        != {
            "result",
            "capsule",
            "result_sha256",
            "manifest_sha256",
            "source_commit",
            "last_lineage_ordinal",
        }
        or _relative_contract(parent.get("result"), "parent result")
        != PARENT_RESULT_RELATIVE.as_posix()
        or _relative_contract(parent.get("capsule"), "parent capsule")
        != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("last_lineage_ordinal") != PARENT_LAST_LINEAGE_ORDINAL
    ):
        raise O1C77RunError("frozen O1C76 parent differs")
    preparation = _mapping(config["preparation"], "config preparation")
    if set(preparation) != {"directory", "manifest_sha256"}:
        raise O1C77RunError("prepared causal-residency config differs")
    _relative_contract(preparation.get("directory"), "preparation directory")
    _digest_or_pending(
        preparation.get("manifest_sha256"), "preparation manifest digest"
    )
    inputs = _mapping(config["inputs"], "config inputs")
    required_inputs = {
        "cnf",
        "cnf_sha256",
        "potential",
        "potential_sha256",
        "grouping",
        "grouping_sha256",
        "o1c73_config",
        "o1c73_config_sha256",
    }
    if set(inputs) != required_inputs:
        raise O1C77RunError("frozen stream inputs differ")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        _relative_contract(inputs.get(name), f"input {name}")
        _digest_or_pending(inputs.get(f"{name}_sha256"), f"input {name} digest")
    native = _mapping(config["native"], "config native")
    required_native = {
        "source",
        "executable",
        "expected_source_sha256",
        "expected_executable_sha256",
        "adapter_schema",
        "result_schema",
        "rank_source_sha256",
        "frontier_plan_sha256",
        "staging_plan_sha256",
        "source_rank_payload_sha256",
        "source_rank_order_sha256",
        "effective_rank_order_sha256",
    }
    if (
        set(native) != required_native
        or _relative_contract(native.get("source"), "native source")
        != SOURCE_PATHS["native_v15"]
        or _relative_contract(native.get("executable"), "native executable")
        != "build/o1c77/native-joint-score-sieve"
        or native.get("adapter_schema")
        != _native_v18.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema")
        != _native_v18.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("rank_source_sha256") != RANK_SOURCE_SHA256
        or native.get("frontier_plan_sha256")
        != FRONTIER_PLAN_BINARY_SHA256
        or native.get("staging_plan_sha256")
        != STAGING_PLAN_BINARY_SHA256
        or native.get("source_rank_payload_sha256")
        != "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae"
        or native.get("source_rank_order_sha256")
        != "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5"
        or native.get("effective_rank_order_sha256")
        != "6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086"
    ):
        raise O1C77RunError("native residual-polarity staging config differs")
    _digest_or_pending(native.get("expected_source_sha256"), "native source digest")
    executable_digest = _digest_or_pending(
        native.get("expected_executable_sha256"), "native executable digest"
    )
    if executable_digest not in ("PENDING", EXPECTED_NATIVE_EXECUTABLE_SHA256):
        raise O1C77RunError("frozen native executable digest differs")
    source = _mapping(config["source"], "config source")
    paths = _mapping(source.get("paths"), "config source paths")
    expected_sources = _mapping(
        source.get("expected_sha256"), "config source digests"
    )
    if (
        set(source) != {"paths", "expected_sha256", "expected_commit"}
        or dict(paths) != SOURCE_PATHS
        or set(expected_sources) != set(SOURCE_PATHS)
    ):
        raise O1C77RunError("source freeze config differs")
    _commit_or_pending(source.get("expected_commit"), "expected source commit")
    for name in SOURCE_PATHS:
        _digest_or_pending(expected_sources.get(name), f"source digest {name}")
    if native.get("expected_source_sha256") != expected_sources.get("native_v15"):
        raise O1C77RunError("native/source digest binding differs")
    gate = _mapping(
        config["target_free_preflight"], "config target-free preflight"
    )
    if (
        set(gate) != {"path", "sha256", "schema", "classification"}
        or _relative_contract(gate.get("path"), "target-free preflight path")
        != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or gate.get("schema") != TARGET_FREE_GATE_SCHEMA
        or gate.get("classification") != TARGET_FREE_GATE_CLASSIFICATION
    ):
        raise O1C77RunError("target-free preflight config differs")
    _digest_or_pending(gate.get("sha256"), "target-free preflight digest")
    budgets = _mapping(config["budgets"], "config budgets")
    expected_budgets: dict[str, object] = {
        "active_clause_limit": ACTIVE_CLAUSE_LIMIT,
        "local_episode_ordinals": list(LOCAL_EPISODES),
        "lineage_call_ordinals": list(LINEAGE_ORDINALS),
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
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
    }
    if dict(budgets) != expected_budgets:
        raise O1C77RunError("frozen O1C77 budgets differ")
    return config


def _validate_initial_contract(prepared: PreparedStream) -> None:
    state = prepared.state
    attic = state.attic
    projection = state.current_projection
    facts = {
        "rank_source": prepared.rank_source.sha256,
        "union_clauses": attic.union_vault.clause_count,
        "union_literals": attic.union_vault.literal_count,
        "occurrences": len(attic.occurrences),
        "duplicate_occurrences": attic.duplicate_occurrence_count,
        "chunk_clauses": tuple(chunk.clause_count for chunk in attic.chunks),
        "active_sha256": state.active_projection.sha256,
        "active_clauses": state.active_projection.clause_count,
        "lineage": projection.lineage_ordinal,
        "inherited_debt": len(state.never_resident_undominated_indices),
    }
    expected = {
        "rank_source": RANK_SOURCE_SHA256,
        "union_clauses": INITIAL_UNION_CLAUSES,
        "union_literals": INITIAL_UNION_LITERALS,
        "occurrences": INITIAL_OCCURRENCES,
        "duplicate_occurrences": INITIAL_DUPLICATE_OCCURRENCES,
        "chunk_clauses": INITIAL_CHUNK_CLAUSES,
        "active_sha256": INITIAL_ACTIVE_SHA256,
        "active_clauses": ACTIVE_CLAUSE_LIMIT,
        "lineage": LINEAGE_ORDINALS[0],
        "inherited_debt": INITIAL_NEVER_RESIDENT_DEBT,
    }
    if facts != expected:
        raise O1C77RunError("frozen prepared residual-polarity staging differs")
    if (
        state.used_active_sha256
        != (
            "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed",
            "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911",
            "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f",
            "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91",
            INITIAL_ACTIVE_SHA256,
        )
        or INITIAL_ACTIVE_SHA256 in INHERITED_SCIENCE_INPUT_SHA256
        or prepared.frontier_plan.active_vault_sha256 != INITIAL_ACTIVE_SHA256
        or prepared.frontier_plan.selected_active_index != 232
        or prepared.frontier_plan.selected_union_index != 526
        or prepared.frontier_plan.unassigned_literal_count != 29
        or prepared.staging_plan.active_vault_sha256 != INITIAL_ACTIVE_SHA256
        or prepared.staging_plan.parent_frontier_plan_sha256
        != prepared.frontier_plan.sha256
        or prepared.staging_plan.sha256 != STAGING_PLAN_BINARY_SHA256
        or prepared.staging_plan.source_rank_payload_sha256
        != "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae"
        or prepared.staging_plan.source_rank_order_sha256
        != "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5"
        or prepared.staging_plan.effective_rank_order_sha256
        != "6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086"
    ):
        raise O1C77RunError("prepared dual-plan staging binding differs")
    validate_activation_replay(state)
    validate_causal_frontier_plan(
        prepared.frontier_plan, active_vault=state.active_projection
    )
    validate_o1c77_production_plan(prepared.staging_plan)


def _validate_target_free_gate(
    path: Path, *, expected_sha256: str, prepared: PreparedStream
) -> Mapping[str, object]:
    payload = _regular(path, "target-free preflight").read_bytes()
    if sha256_bytes(payload) != expected_sha256:
        raise O1C77RunError("target-free preflight digest differs")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C77RunError("target-free preflight JSON differs") from exc
    row = _mapping(value, "target-free preflight")
    required_true = (
        "real_parent_preparation_fixture_passed",
        "target_free_selection_fixture_passed",
        "frontier_binary_round_trip_fixture_passed",
        "staging_binary_round_trip_fixture_passed",
        "activation_postvalidation_fixture_passed",
        "single_call_schedule_fixture_passed",
        "durable_intent_fixture_passed",
        "no_retry_fixture_passed",
        "publication_recovery_fixture_passed",
        "global_novelty_merge_fixture_passed",
        "baseline_comparison_fixture_passed",
    )
    if (
        canonical_json_bytes(value) != payload
        or row.get("schema") != TARGET_FREE_GATE_SCHEMA
        or row.get("attempt_id") != ATTEMPT_ID
        or row.get("classification") != TARGET_FREE_GATE_CLASSIFICATION
        or row.get("native_solver_calls") != 0
        or row.get("truth_key_bytes_read") is not False
        or row.get("fresh_targets") != 0
        or row.get("scientific_entropy_calls") != 0
        or row.get("fresh_reveal_calls") != 0
        or row.get("refits") != 0
        or row.get("MPS_or_GPU") is not False
        or row.get("prepared_manifest_sha256") != prepared.manifest_sha256
        or row.get("rank_source_sha256") != prepared.rank_source.sha256
        or row.get("initial_residency") != prepared.state.describe()
        or row.get("frontier_plan") != prepared.frontier_plan.describe()
        or row.get("staging_plan") != prepared.staging_plan.describe()
        or row.get("active_clause_limit") != ACTIVE_CLAUSE_LIMIT
        or row.get("local_episode_ordinals") != list(LOCAL_EPISODES)
        or row.get("lineage_call_ordinals") != list(LINEAGE_ORDINALS)
        or row.get("requested_conflicts_per_episode")
        != REQUESTED_CONFLICTS_PER_EPISODE
        or row.get("maximum_native_solver_calls")
        != MAXIMUM_NATIVE_SOLVER_CALLS
        or row.get("maximum_total_requested_conflicts")
        != MAXIMUM_TOTAL_REQUESTED_CONFLICTS
        or any(row.get(field) is not True for field in required_true)
    ):
        raise O1C77RunError("target-free preflight contract differs")
    return dict(row)


def preflight(
    config_path: str | Path,
    *,
    require_commit_binding: bool = True,
    root: Path | None = None,
) -> dict[str, object]:
    """Fail closed on every frozen input, source, gate, and resource binding."""

    lab = (root or lab_root()).resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file, root=lab)
    pending_fields: list[str] = []

    def frozen_digest(value: object, field: str) -> str:
        digest = _digest_or_pending(value, field)
        if digest == "PENDING":
            pending_fields.append(field)
        return digest

    parent = _mapping(config["parent"], "preflight parent")
    parent_result = _relative(lab, parent["result"], "parent result")
    parent_capsule = _relative(lab, parent["capsule"], "parent capsule")
    parent_manifest = _regular(
        parent_capsule / "artifacts.sha256", "parent capsule manifest"
    )
    if (
        _sha256_file(parent_result) != PARENT_RESULT_SHA256
        or _sha256_file(parent_manifest) != PARENT_MANIFEST_SHA256
    ):
        raise O1C77RunError("O1C76 parent artifact identity differs")
    preparation = _mapping(config["preparation"], "preflight preparation")
    prepared_digest = frozen_digest(
        preparation["manifest_sha256"], "prepared manifest digest"
    )
    prepared = load_prepared_stream(
        _relative(lab, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=prepared_digest,
    )
    _validate_initial_contract(prepared)
    inputs = _mapping(config["inputs"], "preflight inputs")
    observed_inputs: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        input_path = _relative(lab, inputs[name], f"input {name}")
        expected = frozen_digest(inputs[f"{name}_sha256"], f"input {name} digest")
        observed = _sha256_file(input_path)
        if observed != expected:
            raise O1C77RunError(f"frozen input {name} differs")
        observed_inputs[name] = observed
    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "preflight source paths")
    expected_sources = _mapping(
        source["expected_sha256"], "preflight source digests"
    )
    observed_sources: dict[str, str] = {}
    for name, relative in paths.items():
        source_path = _relative(lab, relative, f"source {name}")
        expected = frozen_digest(expected_sources[name], f"source digest {name}")
        observed = _sha256_file(source_path)
        if observed != expected:
            raise O1C77RunError(f"source {name} differs")
        observed_sources[name] = observed
    expected_commit = _commit_or_pending(
        source["expected_commit"], "expected source commit"
    )
    if expected_commit == "PENDING":
        pending_fields.append("expected source commit")
    native = _mapping(config["native"], "preflight native")
    frozen_digest(native["expected_source_sha256"], "native source digest")
    executable_digest = frozen_digest(
        native["expected_executable_sha256"], "native executable digest"
    )
    executable_relative = _relative_contract(
        native["executable"], "native executable"
    )
    executable = lab / executable_relative
    gate_config = _mapping(
        config["target_free_preflight"], "preflight target-free gate"
    )
    gate_digest = frozen_digest(gate_config["sha256"], "target-free gate digest")
    if pending_fields:
        raise O1C77RunError(
            "commit-bound preflight contains PENDING: " + ", ".join(pending_fields)
        )
    executable_binding = validate_native_executable(
        executable, expected_sha256=executable_digest
    )
    gate = _validate_target_free_gate(
        _relative(lab, gate_config["path"], "target-free gate"),
        expected_sha256=gate_digest,
        prepared=prepared,
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
    except (OSError, subprocess.CalledProcessError) as exc:
        raise O1C77RunError("source commit binding cannot be established") from exc
    if require_commit_binding:
        try:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", expected_commit, commit],
                cwd=lab,
                check=False,
                capture_output=True,
            )
            if ancestor.returncode != 0:
                raise O1C77RunError("source freeze is not an execution ancestor")
            for name, relative in paths.items():
                frozen_blob = subprocess.run(
                    ["git", "show", f"{expected_commit}:{relative}"],
                    cwd=lab,
                    check=True,
                    capture_output=True,
                ).stdout
                if sha256_bytes(frozen_blob) != observed_sources[name]:
                    raise O1C77RunError(
                        f"source {name} differs from its frozen commit blob"
                    )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise O1C77RunError("source commit blob binding differs") from exc
        if dirty:
            raise O1C77RunError("execution worktree is not clean")
    try:
        disk_free = shutil.disk_usage(lab).free
    except OSError as exc:
        raise O1C77RunError("disk resource preflight failed") from exc
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C77RunError("disk resource preflight differs")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "passed": True,
        "source_freeze_commit": expected_commit,
        "execution_commit": commit,
        "source_clean": not bool(dirty),
        "source_sha256": observed_sources,
        "input_sha256": observed_inputs,
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "rank_source_sha256": prepared.rank_source.sha256,
        "initial_residency": prepared.state.describe(),
        "frontier_plan": prepared.frontier_plan.describe(),
        "staging_plan": prepared.staging_plan.describe(),
        "target_free_preflight_sha256": gate_digest,
        "target_free_preflight": gate,
        "native_executable": executable_binding,
        "disk_free_bytes": disk_free,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _rebuild_initial_from_capsule(
    capsule: Path,
    rows: Mapping[str, object],
    expected_residency: Mapping[str, object],
) -> CausalResidencyState:
    initial = capsule / "initial"
    chunk_rows = _sequence(rows.get("chunks"), "recovery initial chunks")
    if not chunk_rows:
        raise O1C77RunError("recovery initial chunks differ")
    chunks: list[ThresholdNoGoodVault] = []
    for index, raw in enumerate(chunk_rows):
        row = _mapping(raw, "recovery initial chunk")
        if row.get("chunk_index") != index:
            raise O1C77RunError("recovery initial chunk ordering differs")
        path = _validate_artifact_row(
            initial, row, f"recovery initial chunk {index}"
        )
        try:
            if index == 0:
                chunk = parse_self_scoping_vault(path.read_bytes())
            else:
                rank = chunks[0]
                chunk = _parse_vault(
                    path.read_bytes(),
                    identity=rank.identity,
                    observed_variables=rank.observed_variables,
                )
        except CausalAtticError as exc:
            raise O1C77RunError("recovery initial chunk differs") from exc
        chunks.append(chunk)
    clauses: list[ThresholdNoGoodClause] = []
    known: set[bytes] = set()
    for chunk in chunks:
        for clause in chunk.clauses:
            if clause.serialized not in known:
                known.add(clause.serialized)
                clauses.append(clause)
    occurrence_path = _validate_artifact_row(
        initial, rows.get("occurrences"), "recovery initial occurrences"
    )
    occurrences = _parse_occurrence_document(
        _read_json(occurrence_path, "recovery initial occurrences"),
        clauses=tuple(clauses),
    )
    try:
        attic = reproject_causal_attic(
            tuple(chunks), occurrences, active_limit=ACTIVE_CLAUSE_LIMIT
        )
    except CausalAtticError as exc:
        raise O1C77RunError("recovery initial attic differs") from exc
    relation_path = _validate_artifact_row(
        initial, rows.get("relations"), "recovery initial relations"
    )
    if _read_json(relation_path, "recovery initial relations") != (
        attic.relation_document()
    ):
        raise O1C77RunError("recovery initial relations differ")
    active_path = _validate_artifact_row(
        initial, rows.get("active_projection"), "recovery initial active"
    )
    active = _parse_vault(
        active_path.read_bytes(),
        identity=chunks[0].identity,
        observed_variables=chunks[0].observed_variables,
    )
    ledger_path = _validate_artifact_row(
        initial, rows.get("activation_ledger"), "recovery initial ledger"
    )
    _validate_artifact_row(
        initial, rows.get("prepared_manifest"), "recovery prepared manifest"
    )
    try:
        state = replay_causal_residency(attic, expected_residency)
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C77RunError("recovery initial residency differs") from exc
    if (
        active.serialized != state.active_projection.serialized
        or _read_json(ledger_path, "recovery initial ledger")
        != state.activation_ledger_document()
        or rows.get("residency") != state.describe()
    ):
        raise O1C77RunError("recovery initial residency artifacts differ")
    return state


def _recover_completed_episode(
    *,
    capsule: Path,
    state: CausalResidencyState,
    expected: Mapping[str, object],
    invocation_sha256: str,
    science_inputs: set[str],
    frontier_plan: CausalFrontierPlan,
    staging_plan: ResidualPolarityStagingPlan,
) -> CausalResidencyState:
    local = _nonnegative_int(
        expected.get("local_episode_ordinal"), "recovery local ordinal"
    )
    lineage = _nonnegative_int(
        expected.get("lineage_call_ordinal"), "recovery lineage ordinal"
    )
    episode_dir = capsule / "episodes" / f"{local:02d}"
    journal = _read_json(episode_dir / "episode.json", "recovery episode")
    if journal != expected or journal.get("schema") != EPISODE_SCHEMA:
        raise O1C77RunError("recovery episode journal differs")
    intent_path = _regular(episode_dir / "intent.json", "recovery intent")
    intent = _read_json(intent_path, "recovery intent")
    if (
        _sha256_file(intent_path)
        != _sha256(expected.get("intent_sha256"), "recovery intent digest")
        or expected.get("invocation_sha256") != invocation_sha256
        or intent.get("invocation_sha256") != invocation_sha256
        or intent.get("schema") != INTENT_SCHEMA
        or intent.get("local_episode_ordinal") != local
        or intent.get("lineage_call_ordinal") != lineage
        or intent.get("residency_before") != state.describe()
        or intent.get("projection_before") != _projection_document(state)
        or intent.get("prior_science_input_sha256") != sorted(science_inputs)
        or intent.get("frontier_plan") != frontier_plan.describe()
        or intent.get("staging_plan") != staging_plan.describe()
    ):
        raise O1C77RunError("recovery intent binding differs")
    active_path = _validate_artifact_row(
        episode_dir, intent.get("active_input_artifact"), "recovery active input"
    )
    active = _parse_vault(
        active_path.read_bytes(),
        identity=state.attic.chunks[0].identity,
        observed_variables=state.attic.chunks[0].observed_variables,
    )
    if (
        active.serialized != state.active_projection.serialized
        or active.sha256 in science_inputs
        or expected.get("science_input_sha256") != active.sha256
        or expected.get("science_input_was_fresh") is not True
    ):
        raise O1C77RunError("recovery active input differs")
    plan_path = _validate_artifact_row(
        capsule / "initial",
        intent.get("frontier_plan_artifact"),
        "recovery frontier plan",
    )
    try:
        recovered_plan = parse_causal_frontier_plan(
            plan_path.read_bytes(), active_vault=active
        )
    except CausalFrontierError as exc:
        raise O1C77RunError("recovery frontier plan differs") from exc
    if recovered_plan != frontier_plan:
        raise O1C77RunError("recovery frontier plan differs")
    staging_path = _validate_artifact_row(
        capsule / "initial",
        intent.get("staging_plan_artifact"),
        "recovery staging plan",
    )
    try:
        recovered_staging = parse_residual_polarity_staging_plan(
            staging_path.read_bytes()
        )
    except ResidualPolarityStagingError as exc:
        raise O1C77RunError("recovery staging plan differs") from exc
    if (
        recovered_staging != staging_plan
        or recovered_staging.parent_frontier_plan_sha256 != frontier_plan.sha256
    ):
        raise O1C77RunError("recovery staging plan differs")

    telemetry = _read_compressed_json(
        episode_dir,
        expected.get("vault_telemetry_evidence"),
        "recovery vault telemetry",
    )
    telemetry_payload = canonical_json_bytes(telemetry)
    try:
        parsed = parse_vault_telemetry(
            telemetry_payload,
            stream_id=f"o1c77-episode-{local:02d}",
            expected_sha256=sha256_bytes(telemetry_payload),
        )
    except CausalAtticError as exc:
        raise O1C77RunError("recovery occurrence ledger differs") from exc
    if (
        parsed.input_identity != active.identity
        or parsed.input_vault_sha256 != active.sha256
        or parsed.input_clause_count != active.clause_count
        or parsed.input_literal_count != active.literal_count
        or parsed.input_serialized_bytes != active.serialized_bytes
        or parsed.input_clause_aggregate_sha256
        != active.clause_aggregate_sha256
    ):
        raise O1C77RunError("recovery telemetry input differs")
    native_raw = _read_compressed_json(
        episode_dir, expected.get("native_evidence"), "recovery native result"
    )
    reader = _read_compressed_json(
        episode_dir, expected.get("reader_evidence"), "recovery decision reader"
    )
    frontier = _read_compressed_json(
        episode_dir,
        expected.get("frontier_reader_evidence"),
        "recovery frontier reader",
    )
    staging = _read_compressed_json(
        episode_dir,
        expected.get("staging_reader_evidence"),
        "recovery staging reader",
    )
    status = _nonnegative_int(expected.get("status"), "recovery native status")
    if status not in (0, 10, 20):
        raise O1C77RunError("recovery native status differs")
    work = _mapping(expected.get("work"), "recovery work")
    try:
        stats = validate_vault_soft_conflict_ledger(work)
    except Exception as exc:
        raise O1C77RunError("recovery conflict ledger differs") from exc
    resources = _mapping(expected.get("resources"), "recovery resources")
    peak = _nonnegative_int(resources.get("peak_rss_bytes"), "recovery peak RSS")
    wall = _nonnegative_int(resources.get("wall_microseconds"), "recovery wall")
    _nonnegative_int(resources.get("cpu_microseconds"), "recovery CPU")
    raw_sieve = _mapping(native_raw.get("sieve"), "recovery native sieve")
    emitted_count = _nonnegative_int(
        raw_sieve.get("external_clauses_emitted"),
        "recovery native emitted count",
    )
    pending = _nonnegative_int(
        raw_sieve.get("pending_clause_count"), "recovery native pending count"
    )
    available = telemetry.get("next_vault_available")
    terminal_reason = telemetry.get("next_vault_terminal_reason")
    if (
        work.get("requested_conflicts") != REQUESTED_CONFLICTS_PER_EPISODE
        or work.get("billed_conflicts") != work.get("solve_conflicts")
        or peak > MEMORY_LIMIT_BYTES
        or wall > int(TIMEOUT_SECONDS * 1_000_000)
        or emitted_count != len(parsed.occurrences)
        or pending != 0
        or not isinstance(available, bool)
        or (
            available
            and terminal_reason is not None
        )
        or (
            not available
            and terminal_reason not in CAPACITY_REASONS
        )
        or expected.get("native_next_vault_available") is not available
        or expected.get("native_next_vault_terminal_reason") != terminal_reason
        or expected.get("capacity_is_rollover_not_terminal")
        is not (terminal_reason in CAPACITY_REASONS)
        or expected.get("native_calls_consumed") != 1
        or expected.get("requested_conflicts")
        != REQUESTED_CONFLICTS_PER_EPISODE
        or expected.get("retry_authorized") is not False
        or expected.get("terminal_failure") is not None
    ):
        raise O1C77RunError("recovery native episode ledger differs")
    raw_model = native_raw.get("key_model_hex")
    if status == 10:
        if not isinstance(raw_model, str) or len(raw_model) != 64:
            raise O1C77RunError("recovery public model encoding differs")
        try:
            key_model: bytes | None = bytes.fromhex(raw_model)
        except ValueError as exc:
            raise O1C77RunError("recovery public model encoding differs") from exc
    else:
        key_model = None
    _validate_archived_v18_provenance(
        raw=native_raw,
        reader=reader,
        frontier=frontier,
        staging=staging,
        frontier_plan=frontier_plan,
        staging_plan=staging_plan,
        telemetry=telemetry,
        rank_source=state.attic.chunks[0],
        active=active,
        status=status,
        stats=stats,
        resources=resources,
        sieve=raw_sieve,
        key_model=key_model,
    )
    initial_returns = _nonnegative_int(
        frontier.get("initial_once_returns"),
        "recovery frontier initial returns",
    )
    contrast_returns = _nonnegative_int(
        frontier.get("contrast_returns"),
        "recovery frontier contrast returns",
    )
    substitutions = initial_returns + contrast_returns
    trace_sha256 = _sha256(
        raw_sieve.get("trace_sha256"), "recovery native trace digest"
    )
    safe_threshold_prunes = _nonnegative_int(
        raw_sieve.get("threshold_prunes"),
        "recovery threshold prune count",
    )
    expected_activation = {
        "substitution_count": substitutions,
        "mechanism_activated": substitutions > 0,
        "native_trace_sha256": trace_sha256,
        "frozen_baseline_trace_sha256": FROZEN_BASELINE_TRACE_SHA256,
        "baseline_trace_changed": trace_sha256 != FROZEN_BASELINE_TRACE_SHA256,
        "trace_change_alone_is_science_gain": False,
        "safe_threshold_prunes": safe_threshold_prunes,
    }
    if expected.get("frontier_activation") != expected_activation:
        raise O1C77RunError("recovery frontier activation differs")
    effective_returns = _nonnegative_int(
        staging.get("overlay_effective_returns"),
        "recovery staging effective returns",
    )
    contrast_staged_returns = _nonnegative_int(
        staging.get("overlay_contrast_returns"),
        "recovery staging contrast returns",
    )
    staged_returns = effective_returns + contrast_staged_returns
    native_staging_activated = staging.get("mechanism_activated")
    unit_activation = staging.get("unit_activation")
    trace_changed = trace_sha256 != FROZEN_BASELINE_TRACE_SHA256
    qualified_staging = (
        staged_returns > 0
        and native_staging_activated is True
        and trace_changed
    )
    expected_staging_activation = {
        "staged_return_count": staged_returns,
        "native_mechanism_activated": native_staging_activated,
        "qualified_mechanism_activated": qualified_staging,
        "native_trace_sha256": trace_sha256,
        "frozen_baseline_trace_sha256": FROZEN_BASELINE_TRACE_SHA256,
        "baseline_trace_changed": trace_changed,
        "unit_activation": unit_activation,
        "unit_activation_is_science_gain": False,
        "trace_change_alone_is_science_gain": False,
        "safe_threshold_prunes": safe_threshold_prunes,
    }
    if (
        not isinstance(native_staging_activated, bool)
        or not isinstance(unit_activation, bool)
        or native_staging_activated is not (staged_returns > 0)
        or len(
            _sequence(
                staging.get("overlay_return_events"),
                "recovery staging events",
            )
        )
        != staged_returns
        or expected.get("staging_activation") != expected_staging_activation
    ):
        raise O1C77RunError("recovery staging activation differs")
    public_model = _mapping(expected.get("public_model"), "recovery public model")
    if (
        expected.get("fully_emitted_aggregate_sha256")
        != telemetry.get("fully_emitted_aggregate_sha256")
        or public_model.get("present") is not (key_model is not None)
        or public_model.get("verified_8_of_8") is not (status == 10)
        or public_model.get("model_sha256")
        != (sha256_bytes(key_model) if key_model is not None else None)
        or public_model.get("truth_key_bytes_read") is not False
    ):
        raise O1C77RunError("recovery native/public provenance differs")

    chunk_path = _validate_artifact_row(
        episode_dir,
        expected.get("rollover_chunk_artifact"),
        "recovery rollover chunk",
    )
    chunk = _parse_vault(
        chunk_path.read_bytes(),
        identity=state.attic.chunks[0].identity,
        observed_variables=state.attic.chunks[0].observed_variables,
    )
    globally_known = {
        clause.serialized for clause in state.attic.union_vault.clauses
    }
    expected_novel: list[ThresholdNoGoodClause] = []
    for occurrence in parsed.occurrences:
        key = occurrence.clause.serialized
        if key not in globally_known:
            if occurrence.classification != "new":
                raise O1C77RunError("recovery global novelty differs")
            globally_known.add(key)
            expected_novel.append(occurrence.clause)
    if chunk.clauses != tuple(expected_novel):
        raise O1C77RunError("recovery rollover population differs")
    try:
        next_state = advance_causal_residency(
            state,
            chunk=chunk,
            occurrences=parsed.occurrences,
            next_lineage_ordinal=lineage + 1,
        )
        validate_activation_replay(next_state)
    except CausalResidencyError as exc:
        raise O1C77RunError("recovery residency reprojection differs") from exc
    consumed_science_inputs = science_inputs | {active.sha256}
    if next_state.active_projection.sha256 in consumed_science_inputs:
        raise O1C77RunError("recovery residency repeats a science input")

    occurrence_path = _validate_artifact_row(
        episode_dir,
        expected.get("occurrence_delta_artifact"),
        "recovery occurrence delta",
    )
    occurrence_delta = _read_json(occurrence_path, "recovery occurrence delta")
    expected_records = [
        occurrence.describe(
            ordinal=ordinal,
            union_clause_index=next_state.attic.occurrence_union_indices[
                len(state.attic.occurrences) + ordinal
            ],
        )
        for ordinal, occurrence in enumerate(parsed.occurrences)
    ]
    if (
        occurrence_delta.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA
        or occurrence_delta.get("stream_id") != f"o1c77-episode-{local:02d}"
        or occurrence_delta.get("occurrence_count") != len(parsed.occurrences)
        or occurrence_delta.get("records") != expected_records
    ):
        raise O1C77RunError("recovery occurrence delta differs")
    output_path = _validate_artifact_row(
        episode_dir,
        expected.get("active_output_artifact"),
        "recovery active output",
    )
    output = _parse_vault(
        output_path.read_bytes(),
        identity=state.attic.chunks[0].identity,
        observed_variables=state.attic.chunks[0].observed_variables,
    )
    ledger_path = _validate_artifact_row(
        episode_dir,
        expected.get("residency_ledger_artifact"),
        "recovery residency ledger",
    )
    boundary_path = episode_dir / "residency-boundary.json"
    boundary = _read_json(boundary_path, "recovery residency boundary")
    if (
        output.serialized != next_state.active_projection.serialized
        or _read_json(ledger_path, "recovery residency ledger")
        != next_state.activation_ledger_document()
        or expected.get("residency_after") != next_state.describe()
        or expected.get("output_active_vault")
        != next_state.active_projection.describe()
        or boundary.get("schema") != RESIDENCY_BOUNDARY_SCHEMA
        or boundary.get("residency_before") != state.describe()
        or boundary.get("residency_after") != next_state.describe()
        or boundary.get("projection_before") != _projection_document(state)
        or boundary.get("projection_after") != _projection_document(next_state)
        or boundary.get("local_episode_ordinal") != local
        or boundary.get("lineage_call_ordinal") != lineage
        or boundary.get("next_projection_lineage_ordinal") != lineage + 1
        or boundary.get("globally_novel_clause_count") != len(expected_novel)
        or boundary.get("globally_novel_literal_count")
        != sum(clause.literal_count for clause in expected_novel)
        or boundary.get("fully_emitted_occurrence_count")
        != len(parsed.occurrences)
        or boundary.get("fully_emitted_aggregate_sha256")
        != telemetry.get("fully_emitted_aggregate_sha256")
        or boundary.get("rollover_chunk")
        != expected.get("rollover_chunk_artifact")
        or boundary.get("active_output")
        != expected.get("active_output_artifact")
        or boundary.get("occurrence_delta")
        != expected.get("occurrence_delta_artifact")
        or boundary.get("residency_ledger")
        != expected.get("residency_ledger_artifact")
        or boundary.get("rollover_completed") is not True
        or boundary.get("artifacts_reread") is not True
        or boundary.get("target_free_reprojection_completed") is not True
        or boundary.get("science_input_sha256") != active.sha256
        or boundary.get("science_input_was_fresh") is not True
        or _sha256_file(boundary_path)
        != _sha256(
            expected.get("residency_boundary_sha256"),
            "recovery residency boundary digest",
        )
        or expected.get("globally_novel_clause_count") != len(expected_novel)
        or expected.get("rollover_chunk_clause_count") != chunk.clause_count
        or expected.get("fully_emitted_occurrence_count")
        != len(parsed.occurrences)
    ):
        raise O1C77RunError("recovery residency boundary differs")
    science_inputs.add(active.sha256)
    return next_state


def _read_recovery_source(
    capsule: Path,
    recovery_source: Mapping[str, object] | str | Path | None,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    source_path = _regular(
        capsule / RECOVERY_SOURCE_NAME, "pre-finalization recovery source"
    )
    sealed = _read_json(source_path, "pre-finalization recovery source")
    if recovery_source is None:
        source = sealed
    elif isinstance(recovery_source, Mapping):
        source = dict(recovery_source)
        if canonical_json_bytes(source) != source_path.read_bytes():
            raise O1C77RunError("pre-finalization recovery source bytes differ")
    else:
        source = _read_json(Path(recovery_source), "pre-finalization recovery source")
        if canonical_json_bytes(source) != source_path.read_bytes():
            raise O1C77RunError("pre-finalization recovery source path differs")
    result = _mapping(source.get("pre_finalization_result"), "recovery result")
    result_payload = canonical_json_bytes(result)
    if (
        source != sealed
        or set(source)
        != {
            "schema",
            "attempt_id",
            "state",
            "result_schema",
            "result_sha256",
            "result_serialized_bytes",
            "pre_finalization_result",
            "native_calls_authorized_during_recovery",
            "public_verification_calls_authorized_during_recovery",
            "truth_key_bytes_read",
        }
        or source.get("schema") != RECOVERY_SOURCE_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("state") != "PRE_FINALIZATION"
        or source.get("result_schema") != RESULT_SCHEMA
        or source.get("result_sha256") != sha256_bytes(result_payload)
        or source.get("result_serialized_bytes") != len(result_payload)
        or source.get("native_calls_authorized_during_recovery") != 0
        or source.get("public_verification_calls_authorized_during_recovery") != 0
        or source.get("truth_key_bytes_read") is not False
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C77RunError("pre-finalization recovery source contract differs")
    return source, result


def recover_publication(
    capsule: Path,
    recovery_source: Mapping[str, object] | str | Path | None = None,
) -> dict[str, object]:
    """Replay sealed O1C77 sidecars without native or verification calls."""

    _validate_regular_capsule_tree(capsule)
    source_document, source = _read_recovery_source(capsule, recovery_source)
    invocation_path = _regular(capsule / "invocation.json", "recovery invocation")
    invocation = _read_json(invocation_path, "recovery invocation")
    if (
        invocation.get("schema") != INVOCATION_SCHEMA
        or invocation.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C77RunError("recovery invocation differs")
    invocation_sha = _sha256_file(invocation_path)
    bindings = _mapping(invocation.get("bindings"), "recovery bindings")
    synthetic_fixture = bindings.get("test_fixture") == "synthetic-target-free"
    if not synthetic_fixture:
        frozen_config_path = _regular(
            capsule / "config.json", "recovery frozen config"
        )
        frozen_preflight = _read_json(
            capsule / "preflight.json", "recovery frozen preflight"
        )
        native_build = _read_json(
            capsule / "native-build.json", "recovery native build"
        )
        if (
            _sha256_file(frozen_config_path) != bindings.get("config_sha256")
            or frozen_preflight != source.get("preflight")
            or frozen_preflight.get("source_freeze_commit")
            != bindings.get("source_freeze_commit")
            or frozen_preflight.get("execution_commit")
            != bindings.get("execution_commit")
            or frozen_preflight.get("source_sha256")
            != bindings.get("source_sha256")
            or frozen_preflight.get("input_sha256")
            != bindings.get("input_sha256")
            or frozen_preflight.get("native_executable")
            != bindings.get("native_executable")
            or native_build.get("executable")
            != bindings.get("native_executable")
            or native_build.get("rank_source_sha256") != RANK_SOURCE_SHA256
            or source.get("source_commit") != bindings.get("execution_commit")
            or invocation.get("initial_residency")
            != frozen_preflight.get("initial_residency")
            or _mapping(
                _mapping(
                    invocation.get("initial_artifacts"),
                    "recovery bound initial artifacts",
                ).get("prepared_manifest"),
                "recovery bound prepared manifest",
            ).get("sha256")
            != frozen_preflight.get("prepared_manifest_sha256")
            or bindings.get("prepared_manifest_sha256")
            != frozen_preflight.get("prepared_manifest_sha256")
        ):
            raise O1C77RunError("publication recovery freeze differs")
    initial_rows = _mapping(
        invocation.get("initial_artifacts"), "recovery initial artifacts"
    )
    expected_initial = _mapping(
        invocation.get("initial_residency"), "recovery initial residency"
    )
    state = _rebuild_initial_from_capsule(
        capsule, initial_rows, expected_initial
    )
    plan_path = _validate_artifact_row(
        capsule / "initial",
        initial_rows.get("frontier_plan"),
        "recovery initial frontier plan",
    )
    plan_document_path = _validate_artifact_row(
        capsule / "initial",
        initial_rows.get("frontier_plan_document"),
        "recovery initial frontier plan document",
    )
    try:
        frontier_plan = parse_causal_frontier_plan(
            plan_path.read_bytes(), active_vault=state.active_projection
        )
    except CausalFrontierError as exc:
        raise O1C77RunError("recovery initial frontier plan differs") from exc
    if (
        invocation.get("frontier_plan") != frontier_plan.describe()
        or _read_json(plan_document_path, "recovery frontier plan document").get(
            "plan"
        )
        != frontier_plan.describe()
    ):
        raise O1C77RunError("recovery initial frontier plan differs")
    staging_path = _validate_artifact_row(
        capsule / "initial",
        initial_rows.get("staging_plan"),
        "recovery initial staging plan",
    )
    staging_document_path = _validate_artifact_row(
        capsule / "initial",
        initial_rows.get("staging_plan_document"),
        "recovery initial staging plan document",
    )
    try:
        staging_plan = parse_residual_polarity_staging_plan(
            staging_path.read_bytes()
        )
        if not synthetic_fixture:
            validate_o1c77_production_plan(staging_plan)
    except ResidualPolarityStagingError as exc:
        raise O1C77RunError("recovery initial staging plan differs") from exc
    if (
        staging_plan.parent_frontier_plan_sha256 != frontier_plan.sha256
        or invocation.get("staging_plan") != staging_plan.describe()
        or _read_json(
            staging_document_path, "recovery staging plan document"
        ).get("plan")
        != staging_plan.describe()
    ):
        raise O1C77RunError("recovery initial staging plan differs")
    episodes = _sequence(source.get("episodes"), "recovery episodes")
    if len(episodes) > MAXIMUM_NATIVE_SOLVER_CALLS:
        raise O1C77RunError("recovery episode count differs")
    science_inputs: set[str] = set(INHERITED_SCIENCE_INPUT_SHA256)
    stopped = False
    for index, raw_episode in enumerate(episodes):
        episode = _mapping(raw_episode, "recovery episode")
        if (
            episode.get("local_episode_ordinal") != LOCAL_EPISODES[index]
            or episode.get("lineage_call_ordinal") != LINEAGE_ORDINALS[index]
            or stopped
        ):
            raise O1C77RunError("recovery episode schedule differs")
        if episode.get("completed") is True:
            state = _recover_completed_episode(
                capsule=capsule,
                state=state,
                expected=episode,
                invocation_sha256=invocation_sha,
                science_inputs=science_inputs,
                frontier_plan=frontier_plan,
                staging_plan=staging_plan,
            )
            stopped = episode.get("status") in (10, 20)
        elif episode.get("completed") is False:
            failed_dir = capsule / "episodes" / f"{index:02d}"
            journal = _read_json(
                failed_dir / "episode.json", "recovery failed episode"
            )
            failure = _read_json(
                failed_dir / "terminal-failure.json",
                "recovery terminal failure",
            )
            failed_intent_path = _regular(
                failed_dir / "intent.json", "recovery failed intent"
            )
            failed_intent = _read_json(
                failed_intent_path, "recovery failed intent"
            )
            active_path = _validate_artifact_row(
                failed_dir,
                failed_intent.get("active_input_artifact"),
                "recovery failed active input",
            )
            active = _parse_vault(
                active_path.read_bytes(),
                identity=state.attic.chunks[0].identity,
                observed_variables=state.attic.chunks[0].observed_variables,
            )
            if (
                episode.get("invocation_sha256") != invocation_sha
                or failed_intent.get("invocation_sha256") != invocation_sha
                or _sha256_file(failed_intent_path)
                != episode.get("intent_sha256")
                or failed_intent.get("residency_before") != state.describe()
                or failed_intent.get("projection_before")
                != _projection_document(state)
                or failed_intent.get("prior_science_input_sha256")
                != sorted(science_inputs)
                or failed_intent.get("frontier_plan")
                != frontier_plan.describe()
                or failed_intent.get("staging_plan")
                != staging_plan.describe()
                or _validate_artifact_row(
                    capsule / "initial",
                    failed_intent.get("frontier_plan_artifact"),
                    "recovery failed frontier plan",
                ).read_bytes()
                != frontier_plan.serialized
                or _validate_artifact_row(
                    capsule / "initial",
                    failed_intent.get("staging_plan_artifact"),
                    "recovery failed staging plan",
                ).read_bytes()
                != staging_plan.serialized
                or active.serialized != state.active_projection.serialized
                or active.sha256 in science_inputs
                or journal != episode
                or failure != episode.get("terminal_failure")
                or failure.get("classification") != OPERATIONAL_TERMINAL
                or failure.get("local_episode_ordinal") != LOCAL_EPISODES[index]
                or failure.get("lineage_call_ordinal") != LINEAGE_ORDINALS[index]
                or failure.get("invocation_sha256") != invocation_sha
                or failure.get("intent_sha256") != episode.get("intent_sha256")
                or failure.get("occurred_after_persisted_intent") is not True
                or not isinstance(failure.get("native_result_returned"), bool)
                or failure.get("fully_emitted_occurrences_retained") is not False
                or failure.get("native_calls_consumed") != 1
                or failure.get("requested_conflicts_consumed")
                != REQUESTED_CONFLICTS_PER_EPISODE
                or failure.get("retry_authorized") is not False
                or failure.get("truth_key_bytes_read") is not False
                or episode.get("native_calls_consumed") != 1
                or episode.get("requested_conflicts")
                != REQUESTED_CONFLICTS_PER_EPISODE
                or episode.get("billed_conflicts") is not None
                or episode.get("retry_authorized") is not False
                or episode.get("residency_after") != state.describe()
            ):
                raise O1C77RunError("recovery failed episode differs")
            stopped = True
        else:
            raise O1C77RunError("recovery episode completion differs")

    resources = _mapping(source.get("resources"), "recovery resources")
    derived_billed = 0
    derived_global_novel = 0
    derived_safe_prunes = 0
    derived_mechanism_activated = False
    derived_baseline_trace_changed = False
    derived_classification: str | None = None
    derived_stop_reason: str | None = None
    derived_failure: Mapping[str, object] | None = None
    for raw_episode in episodes:
        episode = _mapping(raw_episode, "recovery conclusion episode")
        if episode.get("completed") is False:
            derived_classification = OPERATIONAL_TERMINAL
            failure = _mapping(
                episode.get("terminal_failure"), "recovery conclusion failure"
            )
            derived_failure = failure
            derived_stop_reason = (
                "invalid-or-unarchivable-post-native-result"
                if failure.get("native_result_returned") is True
                else "native-call-or-resource-terminal"
            )
            break
        derived_billed += _nonnegative_int(
            episode.get("billed_conflicts"), "recovery billed conflicts"
        )
        derived_global_novel += _nonnegative_int(
            episode.get("globally_novel_clause_count"),
            "recovery global novelty",
        )
        activation = _mapping(
            episode.get("staging_activation"),
            "recovery conclusion staging activation",
        )
        if not isinstance(
            activation.get("qualified_mechanism_activated"), bool
        ) or not isinstance(
            activation.get("baseline_trace_changed"), bool
        ):
            raise O1C77RunError("recovery staging conclusion differs")
        derived_mechanism_activated = cast(
            bool, activation["qualified_mechanism_activated"]
        )
        derived_baseline_trace_changed = cast(
            bool, activation["baseline_trace_changed"]
        )
        derived_safe_prunes += _nonnegative_int(
            activation.get("safe_threshold_prunes"),
            "recovery conclusion safe threshold prunes",
        )
        if episode.get("status") == 10:
            derived_classification = PUBLIC_EXACT_RECOVERY
            derived_stop_reason = "public-verified-candidate"
            break
        if episode.get("status") == 20:
            derived_classification = THRESHOLD_REGION_EXHAUSTED
            derived_stop_reason = "frozen-score-region-exhausted"
            break
    if derived_classification is None:
        if len(episodes) != MAXIMUM_NATIVE_SOLVER_CALLS:
            raise O1C77RunError("recovery unterminated stream differs")
        if derived_safe_prunes:
            derived_classification = SAFE_PRUNE_GAIN
            derived_stop_reason = "certified-threshold-trail-prunes-observed"
        elif derived_global_novel:
            derived_classification = NOVEL_CLAUSE_GAIN
            derived_stop_reason = (
                "globally-novel-exact-clauses-retained-in-causal-attic"
            )
        elif derived_mechanism_activated:
            derived_classification = MECHANISM_ONLY
            derived_stop_reason = (
                "qualified-staging-activated-without-predeclared-science-gain"
            )
        else:
            derived_classification = NO_ACTIVATION
            derived_stop_reason = "no-qualified-staging-activation-or-science-gain"
    derived_billed_value: int | None = (
        None if derived_classification == OPERATIONAL_TERMINAL else derived_billed
    )
    claim_boundary = _mapping(
        source.get("claim_boundary"), "recovery claim boundary"
    )
    if (
        source.get("final_attic") != state.attic.describe()
        or source.get("final_residency") != state.describe()
        or source.get("final_active_vault")
        != state.active_projection.describe()
        or source.get("rank_source_vault") != state.attic.chunks[0].describe()
        or source.get("classification") != derived_classification
        or source.get("stop_reason") != derived_stop_reason
        or source.get("operational_failure")
        != (dict(derived_failure) if derived_failure is not None else None)
        or resources.get("native_solver_calls") != len(episodes)
        or resources.get("requested_conflicts")
        != len(episodes) * REQUESTED_CONFLICTS_PER_EPISODE
        or resources.get("billed_conflicts") != derived_billed_value
        or resources.get("globally_novel_clauses") != derived_global_novel
        or resources.get("safe_threshold_prunes") != derived_safe_prunes
        or claim_boundary.get("qualified_staging_mechanism_activated")
        is not derived_mechanism_activated
        or claim_boundary.get("baseline_trace_changed")
        is not derived_baseline_trace_changed
    ):
        raise O1C77RunError("publication recovery conclusion differs")
    recovered = dict(source)
    recovered["publication_recovery"] = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "pre_finalization_source_schema": RECOVERY_SOURCE_SCHEMA,
        "pre_finalization_source_sha256": sha256_bytes(
            canonical_json_bytes(source_document)
        ),
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_issued_during_recovery": 0,
        "public_verification_calls_issued_during_recovery": 0,
        "truth_key_bytes_read": False,
        "recovered_episode_count": len(episodes),
        "recovered_final_attic_sha256": state.attic.union_vault.sha256,
        "recovered_final_active_vault_sha256": state.active_projection.sha256,
        "recovered_activation_ledger_sha256": sha256_bytes(
            canonical_json_bytes(state.activation_ledger_document())
        ),
    }
    return recovered


def run(config_path: str | Path = CONFIG_RELATIVE) -> dict[str, object]:
    """Execute, recover, or return the frozen one-call staging attempt."""

    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    existing = _existing_authoritative(authoritative)
    if existing is not None:
        return existing
    existing_capsules = sorted(
        capsule
        for capsule in (root / "runs").glob(f"*_{CAPSULE_SUFFIX}")
        if capsule.is_dir()
    )
    if existing_capsules:
        if len(existing_capsules) != 1:
            raise O1C77RunError("multiple existing O1C77 capsules block replay")
        capsule = existing_capsules[0]
        if (capsule / "artifacts.sha256").is_file():
            return _republish_sealed_capsule(capsule, authoritative)
        if not (capsule / RECOVERY_SOURCE_NAME).is_file():
            raise O1C77RunError(
                "partial O1C77 capsule without pre-finalization recovery "
                "source blocks replay"
            )
        if any((capsule / name).exists() for name in ("RUN.md", "result.json")):
            raise O1C77RunError(
                "partially published O1C77 capsule requires manual recovery"
            )
        recovered = recover_publication(capsule)
        finalize_capsule(capsule, authoritative, recovered)
        return recovered

    config_file = Path(config_path).resolve(strict=True)
    preflight_row = preflight(
        config_file, require_commit_binding=True, root=root
    )
    config = load_config(config_file, root=root)
    preparation = _mapping(config["preparation"], "run preparation")
    prepared = load_prepared_stream(
        _relative(root, preparation["directory"], "run prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
    _validate_initial_contract(prepared)
    inputs = _mapping(config["inputs"], "run inputs")
    cnf = _relative(root, inputs["cnf"], "run CNF")
    potential = _relative(root, inputs["potential"], "run potential")
    grouping = _relative(root, inputs["grouping"], "run grouping")
    o1c73_config_path = _relative(
        root, inputs["o1c73_config"], "run O1C73 config"
    )
    o1c73_config = _o1c73.load_config(o1c73_config_path)
    baseline = _o1c73.validate_apple8_baseline(root, o1c73_config)
    public_target = _o1c73._o1c66._public_target(baseline)
    native = _mapping(config["native"], "run native")
    executable = root / _relative_contract(
        native["executable"], "run native executable"
    )
    executable_binding = validate_native_executable(
        executable,
        expected_sha256=cast(str, native["expected_executable_sha256"]),
    )
    if executable_binding != preflight_row.get("native_executable"):
        raise O1C77RunError("post-preflight native executable differs")
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
            "executable": executable_binding,
            "adapter_schema": native["adapter_schema"],
            "result_schema": native["result_schema"],
            "rank_source_sha256": native["rank_source_sha256"],
            "frontier_plan_sha256": native["frontier_plan_sha256"],
            "staging_plan_sha256": native["staging_plan_sha256"],
            "source_rank_payload_sha256": native[
                "source_rank_payload_sha256"
            ],
            "source_rank_order_sha256": native["source_rank_order_sha256"],
            "effective_rank_order_sha256": native[
                "effective_rank_order_sha256"
            ],
            "fixed_output_path_reproducibility_required": True,
        },
        immutable=True,
    )
    _atomic_create(
        capsule / "command.txt",
        (
            "nice -n 10 env PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c77_apple8_residual_polarity_staging_run run "
            f"--config {config_file.relative_to(root).as_posix()}\n"
        ).encode("utf-8"),
        immutable=True,
    )
    bindings: dict[str, object] = {
        "source_freeze_commit": preflight_row["source_freeze_commit"],
        "execution_commit": preflight_row["execution_commit"],
        "config_sha256": _sha256_file(config_file),
        "source_sha256": preflight_row["source_sha256"],
        "input_sha256": preflight_row["input_sha256"],
        "native_executable": executable_binding,
        "native_adapter_schema": native["adapter_schema"],
        "native_result_schema": native["result_schema"],
        "rank_source_sha256": RANK_SOURCE_SHA256,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "target_free_preflight_sha256": preflight_row[
            "target_free_preflight_sha256"
        ],
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "truth_key_bytes_read": False,
    }

    def invoke(
        local_ordinal: int,
        lineage_ordinal: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
    ) -> object:
        if (
            local_ordinal not in LOCAL_EPISODES
            or LINEAGE_ORDINALS[local_ordinal] != lineage_ordinal
            or _sha256_file(rank_vault) != RANK_SOURCE_SHA256
            or _sha256_file(active_vault) != INITIAL_ACTIVE_SHA256
            or _sha256_file(frontier_plan) != prepared.frontier_plan.sha256
            or _sha256_file(staging_plan) != prepared.staging_plan.sha256
        ):
            raise O1C77RunError("native residency invocation identity differs")
        observed_executable = validate_native_executable(
            executable,
            expected_sha256=cast(str, native["expected_executable_sha256"]),
        )
        if observed_executable != executable_binding:
            raise O1C77RunError("native executable changed in call window")
        result = _native_v18.run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            rank_vault_path=rank_vault,
            vault_path=active_vault,
            frontier_plan_path=frontier_plan,
            staging_plan_path=staging_plan,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            require_active_contrast=False,
            require_frontier_intervention=False,
            require_staging_activation=False,
        )
        if (
            validate_native_executable(
                executable,
                expected_sha256=cast(
                    str, native["expected_executable_sha256"]
                ),
            )
            != executable_binding
        ):
            raise O1C77RunError("native executable changed during call window")
        return result

    outcome = execute_stream(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=public_target.verify,
        bindings=bindings,
    )
    result = build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit=cast(str, preflight_row["execution_commit"]),
        preflight=preflight_row,
        started_at=started_at,
        runtime=_runtime_resources(
            started=started,
            cpu_started=cpu_started,
            child_started=child_started,
        ),
    )
    write_recovery_source(capsule, result)
    finalize_capsule(capsule, authoritative, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight, run, or recover O1C77's staging call"
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
                raise O1C77RunError("recovery capsule escapes run root")
            value = recover_publication(capsule)
            finalize_capsule(capsule, root / RESULT_RELATIVE, value)
        sys.stdout.buffer.write(canonical_json_bytes(value))
        return 0
    except O1C77RunError as exc:
        print(f"O1C77: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
