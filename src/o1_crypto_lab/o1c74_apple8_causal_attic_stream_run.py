"""O1C-0074 bounded active-vault stream over an immutable causal attic.

The runner keeps three byte identities deliberately separate:

* O1C-0073's 202-clause vault is the immutable rank source;
* the current deterministic K=256 projection is the only solver-resident vault;
* every fully emitted exact occurrence is retained in immutable attic chunks.

Each intent is durable before its one fresh subprocess call.  A native active
capacity crossing is a rollover boundary, never a scientific terminal, once
the complete emitted ledger has been validated, archived, reread, and included
in the next target-free projection.
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

from . import joint_score_sieve_v16 as _native_v16
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .joint_score_sieve_v9 import (
    derive_vault_soft_conflict_ledger,
    validate_vault_soft_conflict_ledger,
)
from .causal_attic_v1 import (
    ACTIVE_PROJECTION_SCHEMA,
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAttic,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    reproject_causal_attic,
    sha256_bytes,
)
from .o1c74_apple8_causal_attic_prepare import (
    ACTIVE_PROJECTION_NAME,
    MANIFEST_NAME as PREPARED_MANIFEST_NAME,
    MANIFEST_SCHEMA as PREPARED_MANIFEST_SCHEMA,
    NOVEL_CHUNK_NAME,
    OCCURRENCES_NAME,
    RELATIONS_NAME,
    RETAINED_CHUNK_NAME,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
    validate_threshold_no_good_vault_caps,
)


ATTEMPT_ID = "O1C-0074"
CONFIG_SCHEMA = "o1-256-apple8-causal-attic-stream-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-causal-attic-stream-preflight-v1"
TARGET_FREE_GATE_SCHEMA = (
    "o1-256-o1c74-target-free-causal-attic-stream-preflight-v1"
)
TARGET_FREE_GATE_CLASSIFICATION = (
    "O1C74_TARGET_FREE_CAUSAL_ATTIC_STREAM_PREFLIGHT_PASS"
)
INVOCATION_SCHEMA = "o1-256-apple8-causal-attic-stream-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-causal-attic-stream-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-causal-attic-stream-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-causal-attic-stream-result-v1"
PUBLICATION_RECOVERY_SCHEMA = (
    "o1-256-apple8-causal-attic-stream-publication-recovery-v1"
)
ROLLOVER_CHUNK_SCHEMA = "o1-256-causal-attic-rollover-chunk-v1"
PROJECTION_BOUNDARY_SCHEMA = "o1-256-causal-attic-projection-boundary-v1"
NATIVE_EVIDENCE_SCHEMA = "o1-256-canonical-gzip-native-evidence-v1"

CONFIG_RELATIVE = Path("configs/o1c74_apple8_causal_attic_stream_v1.json")
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0074_TARGET_FREE_CAUSAL_ATTIC_STREAM_PREFLIGHT_20260719.json"
)
RESULT_RELATIVE = Path(
    "research/O1C0074_APPLE8_CAUSAL_ATTIC_STREAM_RESULT_20260719.json"
)
CAPSULE_SUFFIX = "O1C-0074_apple8-causal-attic-stream-v1"
PUBLICATION_SOURCE_NAME = "publication_source.json"

PARENT_RESULT_RELATIVE = Path(
    "research/O1C0073_APPLE8_VAULT_RELEASE_CONTRAST_RESULT_20260719.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1"
)
PARENT_RESULT_SHA256 = (
    "43fb980b50fef20f9bc4bdcfd2ecd6e0f1f7df3bcee9297b0005bb55e4ea0cdc"
)
PARENT_MANIFEST_SHA256 = (
    "ad2791ff4ae09e9426878be4ba2f3b55eb77c85f46308c7a506d0dc96111317d"
)
PARENT_SOURCE_COMMIT = "a1a447f47b4e7bec833f1148330573fefa8e3119"
RANK_SOURCE_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
INITIAL_UNION_CLAUSES = 513
INITIAL_UNION_LITERALS = 1_397_774
INITIAL_UNION_SERIALIZED_BYTES = 5_593_339
INITIAL_ACTIVE_SHA256 = (
    "fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7"
)
INITIAL_ACTIVE_CLAUSES = 256
INITIAL_ACTIVE_LITERALS = 654_753
INITIAL_ACTIVE_SERIALIZED_BYTES = 2_620_227

ACTIVE_CLAUSE_LIMIT = 256
LOCAL_EPISODES = (0, 1, 2, 3)
LINEAGE_ORDINALS = (10, 11, 12, 13)
REQUESTED_CONFLICTS_PER_EPISODE = 128
MAXIMUM_NATIVE_SOLVER_CALLS = 4
MAXIMUM_TOTAL_REQUESTED_CONFLICTS = 512
SEED = 0
THRESHOLD = 14.606178797892962
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 134_217_728
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MAXIMUM_NATIVE_EXECUTABLE_BYTES = 16_777_216

CAPACITY_REASONS = {
    "capacity_clause_count",
    "capacity_literal_count",
    "capacity_payload_bytes",
}

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
THRESHOLD_REGION_EXHAUSTED = "THRESHOLD_REGION_EXHAUSTED"
NOVEL_CLAUSE_GAIN = "CAUSAL_ATTIC_STREAM_NOVEL_CLAUSE_GAIN"
NO_GAIN = "CAUSAL_ATTIC_STREAM_NO_GAIN"
OPERATIONAL_TERMINAL = "CAUSAL_ATTIC_STREAM_OPERATIONAL_TERMINAL"

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c74_apple8_causal_attic_stream_run.py",
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "preparation": "src/o1_crypto_lab/o1c74_apple8_causal_attic_prepare.py",
    "adapter_v16": "src/o1_crypto_lab/joint_score_sieve_v16.py",
    "native_v13": "native/cadical_o1_joint_score_sieve_v13.cpp",
}


class O1C74RunError(RuntimeError):
    """A frozen stream, artifact, call, or publication invariant differs."""


class EpisodeInvoker(Protocol):
    def __call__(
        self,
        local_ordinal: int,
        lineage_ordinal: int,
        rank_vault: Path,
        active_vault: Path,
        /,
    ) -> object:
        """Consume one predeclared fresh native subprocess call."""


@dataclass(frozen=True)
class PreparedStream:
    directory: Path | None
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalAttic

    @property
    def rank_source(self) -> ThresholdNoGoodVault:
        return self.state.chunks[0]


@dataclass(frozen=True)
class StreamOutcome:
    classification: str
    stop_reason: str
    episodes: tuple[Mapping[str, object], ...]
    final_state: CausalAttic
    native_calls: int
    requested_conflicts: int
    billed_conflicts: int | None
    globally_novel_clauses: int
    operational_failure: Mapping[str, object] | None


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) for key in value
    ):
        raise O1C74RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C74RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C74RunError(f"{field} differs")
    return value


def _positive_int(value: object, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result < 1:
        raise O1C74RunError(f"{field} differs")
    return result


def _finite_float(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise O1C74RunError(f"{field} differs")
    return float(value)


def _sha256(value: object, field: str, *, pending: bool = False) -> str:
    if pending and value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C74RunError(f"{field} differs")
    return value


def _relative(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise O1C74RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise O1C74RunError(f"{field} escapes the lab")
    resolved = (root / path).resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise O1C74RunError(f"{field} escapes the lab")
    return resolved


def _regular(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C74RunError(f"{field} cannot be read") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C74RunError(f"{field} is not a regular file")
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
    except OSError as exc:
        raise O1C74RunError(f"cannot hash {path}") from exc
    return digest.hexdigest()


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    _regular(path, field)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C74RunError(f"{field} JSON differs") from exc
    return _mapping(value, field)


def _atomic_create(path: Path, payload: bytes, *, immutable: bool = False) -> None:
    if not isinstance(payload, bytes) or path.exists() or path.is_symlink():
        raise O1C74RunError(f"owned artifact already exists: {path.name}")
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
    except O1C74RunError:
        raise
    except OSError as exc:
        raise O1C74RunError(f"cannot publish owned artifact: {path.name}") from exc
    if path.read_bytes() != payload:
        raise O1C74RunError(f"owned artifact reread differs: {path.name}")


def _atomic_json(path: Path, value: object, *, immutable: bool = False) -> None:
    _atomic_create(path, canonical_json_bytes(value), immutable=immutable)


def _canonical_gzip(payload: bytes) -> bytes:
    if not isinstance(payload, bytes):
        raise O1C74RunError("native evidence payload differs")
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0
    ) as stream:
        stream.write(payload)
    compressed = output.getvalue()
    try:
        restored = gzip.decompress(compressed)
    except OSError as exc:
        raise O1C74RunError("native evidence compression differs") from exc
    if restored != payload:
        raise O1C74RunError("native evidence compression differs")
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
        raise O1C74RunError(f"{field} schema differs")
    name = metadata.get("path")
    if not isinstance(name, str) or Path(name).name != name:
        raise O1C74RunError(f"{field} path differs")
    path = _regular(base / name, field)
    compressed = path.read_bytes()
    if (
        len(compressed)
        != _nonnegative_int(metadata.get("compressed_bytes"), f"{field} bytes")
        or sha256_bytes(compressed)
        != _sha256(metadata.get("compressed_sha256"), f"{field} digest")
    ):
        raise O1C74RunError(f"{field} compressed artifact differs")
    try:
        payload = gzip.decompress(compressed)
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C74RunError(f"{field} payload differs") from exc
    if (
        len(payload)
        != _nonnegative_int(metadata.get("uncompressed_bytes"), f"{field} raw bytes")
        or sha256_bytes(payload)
        != _sha256(metadata.get("uncompressed_sha256"), f"{field} raw digest")
        or canonical_json_bytes(value) != payload
    ):
        raise O1C74RunError(f"{field} canonical payload differs")
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
        raise O1C74RunError(f"{field} path differs")
    path_value = Path(relative)
    if path_value.is_absolute() or ".." in path_value.parts:
        raise O1C74RunError(f"{field} path escapes")
    path = _regular(root / path_value, field)
    if (
        path.stat().st_size
        != _nonnegative_int(row.get("serialized_bytes"), f"{field} bytes")
        or _sha256_file(path) != _sha256(row.get("sha256"), f"{field} digest")
    ):
        raise O1C74RunError(f"{field} artifact differs")
    return path


def _validate_regular_capsule_tree(capsule: Path) -> None:
    try:
        root_metadata = capsule.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(
            root_metadata.st_mode
        ):
            raise O1C74RunError("capsule tree root differs")
        for path in capsule.rglob("*"):
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (
                stat.S_ISREG(mode) or stat.S_ISDIR(mode)
            ):
                raise O1C74RunError("capsule tree contains a non-regular entry")
    except O1C74RunError:
        raise
    except OSError as exc:
        raise O1C74RunError("capsule tree cannot be inspected") from exc


def _parse_vault(
    payload: bytes,
    *,
    identity: object | None = None,
    observed_variables: tuple[int, ...] | None = None,
) -> ThresholdNoGoodVault:
    try:
        if identity is None or observed_variables is None:
            return parse_self_scoping_vault(payload)
        return parse_threshold_no_good_vault(
            payload,
            observed_variables=observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalAtticError, ThresholdNoGoodVaultError) as exc:
        raise O1C74RunError("causal-attic vault artifact differs") from exc


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "prepared occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C74RunError("prepared occurrence schema differs")
    records = _sequence(document.get("records"), "prepared occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "prepared occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "prepared occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C74RunError("prepared occurrence ordinal differs")
        clause = clauses[union_index]
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=_nonnegative_int(
                    row.get("source_index"), "prepared occurrence source index"
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
            raise O1C74RunError("prepared occurrence record differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C74RunError("prepared occurrence record differs")
        occurrences.append(occurrence)
    if (
        document.get("occurrence_count") != len(occurrences)
        or document.get("unique_clause_count") != len(clauses)
    ):
        raise O1C74RunError("prepared occurrence ledger differs")
    return tuple(occurrences)


def prepared_stream_from_state(
    state: CausalAttic, *, manifest: Mapping[str, object] | None = None
) -> PreparedStream:
    """Construct an in-memory prepared stream for deterministic test fixtures."""

    if not isinstance(state, CausalAttic):
        raise O1C74RunError("prepared state differs")
    value: Mapping[str, object] = manifest or {
        "schema": PREPARED_MANIFEST_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "rank_source_vault_sha256": state.chunks[0].sha256,
        "active_projection_schema": ACTIVE_PROJECTION_SCHEMA,
        "attic": state.describe(),
        "artifact_set": {"artifacts": {}},
    }
    payload = canonical_json_bytes(value)
    return PreparedStream(None, dict(value), payload, sha256_bytes(payload), state)


def load_prepared_stream(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedStream:
    """Rebuild and validate every zero-call prepared attic artifact."""

    prepared = Path(directory).resolve(strict=True)
    if not prepared.is_dir() or prepared.is_symlink():
        raise O1C74RunError("prepared causal-attic directory differs")
    manifest_path = _regular(prepared / PREPARED_MANIFEST_NAME, "prepared manifest")
    manifest_bytes = manifest_path.read_bytes()
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if sha256_bytes(manifest_bytes) != expected:
        raise O1C74RunError("prepared causal-attic manifest differs")
    try:
        decoded = json.loads(manifest_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C74RunError("prepared causal-attic manifest JSON differs") from exc
    manifest = _mapping(decoded, "prepared manifest")
    if (
        canonical_json_bytes(decoded) != manifest_bytes
        or manifest.get("schema") != PREPARED_MANIFEST_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest.get("active_projection_schema") != ACTIVE_PROJECTION_SCHEMA
    ):
        raise O1C74RunError("prepared causal-attic manifest contract differs")
    artifact_set = _mapping(manifest.get("artifact_set"), "prepared artifact set")
    rows = _mapping(artifact_set.get("artifacts"), "prepared artifacts")
    required = {
        RETAINED_CHUNK_NAME,
        NOVEL_CHUNK_NAME,
        ACTIVE_PROJECTION_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
    }
    if set(rows) != required:
        raise O1C74RunError("prepared artifact inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(required):
        row = _mapping(rows[name], f"prepared artifact {name}")
        path = _regular(prepared / name, f"prepared artifact {name}")
        payload = path.read_bytes()
        if (
            Path(name).name != name
            or row.get("sha256") != sha256_bytes(payload)
            or row.get("serialized_bytes") != len(payload)
        ):
            raise O1C74RunError(f"prepared artifact {name} differs")
        payloads[name] = payload

    rank_source = _parse_vault(payloads[RETAINED_CHUNK_NAME])
    observed = rank_source.observed_variables
    novel = _parse_vault(
        payloads[NOVEL_CHUNK_NAME],
        identity=rank_source.identity,
        observed_variables=observed,
    )
    active = _parse_vault(
        payloads[ACTIVE_PROJECTION_NAME],
        identity=rank_source.identity,
        observed_variables=observed,
    )
    try:
        occurrence_value = json.loads(payloads[OCCURRENCES_NAME])
        relation_value = json.loads(payloads[RELATIONS_NAME])
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C74RunError("prepared compact ledger differs") from exc
    union_clauses = rank_source.clauses + novel.clauses
    occurrences = _parse_occurrence_document(
        occurrence_value, clauses=union_clauses
    )
    try:
        state = reproject_causal_attic(
            (rank_source, novel), occurrences, active_limit=ACTIVE_CLAUSE_LIMIT
        )
    except CausalAtticError as exc:
        raise O1C74RunError("prepared causal-attic reconstruction differs") from exc
    if (
        state.active_projection.serialized != active.serialized
        or state.describe() != manifest.get("attic")
        or state.occurrence_document() != occurrence_value
        or state.relation_document() != relation_value
        or manifest.get("rank_source_vault_sha256") != rank_source.sha256
    ):
        raise O1C74RunError("prepared causal-attic projection differs")
    return PreparedStream(
        prepared, dict(manifest), manifest_bytes, expected, state
    )


def _copy_immutable(path: Path, payload: bytes) -> dict[str, object]:
    _atomic_create(path, payload, immutable=True)
    return {
        "path": path.name,
        "sha256": sha256_bytes(payload),
        "serialized_bytes": len(payload),
    }


def _initial_artifacts(capsule: Path, prepared: PreparedStream) -> dict[str, object]:
    """Materialize and reread the complete zero-call causal attic."""

    initial = capsule / "initial"
    if initial.exists():
        raise O1C74RunError("initial causal-attic directory already exists")
    initial.mkdir(parents=True)
    state = prepared.state
    if len(state.chunks) != 2 or state.chunks[0] != prepared.rank_source:
        raise O1C74RunError("prepared initial chunk topology differs")
    rows: dict[str, object] = {
        "rank_source": _copy_immutable(
            initial / "rank-source.vault", state.chunks[0].serialized
        ),
        "o1c73_rollover": _copy_immutable(
            initial / "o1c73-rollover.vault", state.chunks[1].serialized
        ),
        "active_projection": _copy_immutable(
            initial / "active-projection.bin", state.active_projection.serialized
        ),
        "occurrences": _copy_immutable(
            initial / "witness-occurrences.json",
            canonical_json_bytes(state.occurrence_document()),
        ),
        "relations": _copy_immutable(
            initial / "subsumption-relations.json",
            canonical_json_bytes(state.relation_document()),
        ),
        "prepared_manifest": _copy_immutable(
            initial / "prepared-manifest.json", prepared.manifest_bytes
        ),
    }
    rebuilt = _rebuild_initial_from_capsule(capsule, rows)
    if rebuilt.describe() != state.describe():
        raise O1C74RunError("materialized initial causal attic differs")
    return rows


def _rebuild_initial_from_capsule(
    capsule: Path, rows: Mapping[str, object]
) -> CausalAttic:
    initial = capsule / "initial"
    rank_path = _validate_artifact_row(initial, rows.get("rank_source"), "rank source")
    rollover_path = _validate_artifact_row(
        initial, rows.get("o1c73_rollover"), "O1C73 rollover"
    )
    active_path = _validate_artifact_row(
        initial, rows.get("active_projection"), "initial active projection"
    )
    occurrence_path = _validate_artifact_row(
        initial, rows.get("occurrences"), "initial occurrences"
    )
    _validate_artifact_row(initial, rows.get("relations"), "initial relations")
    _validate_artifact_row(
        initial, rows.get("prepared_manifest"), "prepared manifest"
    )
    rank = _parse_vault(rank_path.read_bytes())
    rollover = _parse_vault(
        rollover_path.read_bytes(),
        identity=rank.identity,
        observed_variables=rank.observed_variables,
    )
    active = _parse_vault(
        active_path.read_bytes(),
        identity=rank.identity,
        observed_variables=rank.observed_variables,
    )
    occurrences = _parse_occurrence_document(
        _read_json(occurrence_path, "initial occurrences"),
        clauses=rank.clauses + rollover.clauses,
    )
    try:
        state = reproject_causal_attic(
            (rank, rollover), occurrences, active_limit=ACTIVE_CLAUSE_LIMIT
        )
    except CausalAtticError as exc:
        raise O1C74RunError("initial causal-attic recovery differs") from exc
    if state.active_projection.serialized != active.serialized:
        raise O1C74RunError("initial active projection recovery differs")
    relation_value = _read_json(initial / "subsumption-relations.json", "relations")
    if state.relation_document() != relation_value:
        raise O1C74RunError("initial subsumption relation recovery differs")
    return state


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


def _validate_archived_v16_provenance(
    *,
    raw: Mapping[str, object],
    reader: Mapping[str, object],
    telemetry: Mapping[str, object],
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    status: int,
    stats: Mapping[str, int],
    resources: Mapping[str, object],
    sieve: Mapping[str, object],
    key_model: bytes | None,
) -> None:
    """Cross-bind the canonical native payload and every promoted typed view."""

    raw_stats = _mapping(raw.get("stats"), "archived native stats")
    raw_resources = _mapping(raw.get("resources"), "archived native resources")
    raw_sieve = _mapping(raw.get("sieve"), "archived native sieve")
    try:
        derived_stats = derive_vault_soft_conflict_ledger(
            raw_stats,
            requested_conflicts=REQUESTED_CONFLICTS_PER_EPISODE,
        )
    except Exception as exc:
        raise O1C74RunError("archived native conflict provenance differs") from exc
    expected_model = key_model.hex() if key_model is not None else None
    if (
        raw.get("schema") != _native_v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or raw.get("implementation_parent_schema")
        != _native_v16.JOINT_SCORE_SIEVE_IMPLEMENTATION_PARENT_SCHEMA
        or raw.get("implementation_release_parent_schema")
        != _native_v16.JOINT_SCORE_SIEVE_RELEASE_PARENT_SCHEMA
        or raw.get("rank_source_vault_sha256") != rank_source.sha256
        or raw.get("reader") != reader
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
        raise O1C74RunError("archived native v16 provenance differs")


def _validated_episode_result(
    result: object,
    *,
    rank_source: ThresholdNoGoodVault,
    active: ThresholdNoGoodVault,
    stream_id: str,
    verify_public_model: Callable[[bytes], bool],
    require_concrete_result: bool,
) -> dict[str, object]:
    """Bind one already adapter-certified v16 return to this stream boundary."""

    try:
        if require_concrete_result and not isinstance(
            result, _native_v16.JointScoreSieveV16Result
        ):
            raise O1C74RunError("native result type differs")
        raw = _mapping(getattr(result, "raw"), "native raw result")
        reader = _mapping(getattr(result, "reader"), "native reader")
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
            or getattr(result, "conflict_limit") != REQUESTED_CONFLICTS_PER_EPISODE
            or getattr(result, "threshold") != rank_source.identity.threshold
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS_PER_EPISODE
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or not _vault_equal(getattr(result, "rank_source_vault"), rank_source)
            or not _vault_equal(getattr(result, "input_vault"), active)
        ):
            raise O1C74RunError("native split-vault result binding differs")
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        if peak > MEMORY_LIMIT_BYTES or wall > int(TIMEOUT_SECONDS * 1_000_000):
            raise O1C74RunError("native resource boundary differs")
        pending = _nonnegative_int(
            sieve.get("pending_clause_count"), "native pending clause count"
        )
        emitted_count = _nonnegative_int(
            sieve.get("external_clauses_emitted"), "native emitted clause count"
        )
        if pending != 0:
            raise O1C74RunError("native result retained an incomplete clause")

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
            raise O1C74RunError("native emitted ledger input binding differs")

        eligible = getattr(result, "eligible_emitted_clauses")
        if not isinstance(eligible, Sequence) or isinstance(
            eligible, (str, bytes, bytearray)
        ) or len(eligible) != len(parsed.occurrences):
            raise O1C74RunError("native typed emission ledger differs")
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
                raise O1C74RunError("native typed emission occurrence differs")

        available = telemetry.get("next_vault_available")
        terminal_reason = telemetry.get("next_vault_terminal_reason")
        next_vault = getattr(result, "next_vault")
        if not isinstance(available, bool):
            raise O1C74RunError("native next-vault availability differs")
        if available:
            if terminal_reason is not None or not isinstance(
                next_vault, ThresholdNoGoodVault
            ):
                raise O1C74RunError("available native next vault differs")
        elif terminal_reason not in CAPACITY_REASONS or next_vault is not None:
            # Empty-clause termination is forbidden: an exact empty no-good is an
            # incomplete/unarchivable ledger under this bounded stream design.
            raise O1C74RunError("native rollover reason differs")

        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C74RunError("public candidate failed eight-block verification")
        elif key_model is not None:
            raise O1C74RunError("non-SAT stream result returned a candidate")
        _validate_archived_v16_provenance(
            raw=raw,
            reader=reader,
            telemetry=telemetry,
            rank_source=rank_source,
            active=active,
            status=status,
            stats=stats,
            resources=resources,
            sieve=sieve,
            key_model=key_model,
        )

        return {
            "raw": dict(raw),
            "reader": dict(reader),
            "telemetry": dict(telemetry),
            "telemetry_payload": telemetry_payload,
            "occurrences": parsed.occurrences,
            "stats": stats,
            "status": status,
            "key_model": key_model,
            "next_vault_available": available,
            "next_vault_terminal_reason": terminal_reason,
            "resources": {
                "peak_rss_bytes": peak,
                "wall_microseconds": wall,
                "cpu_microseconds": cpu,
            },
        }
    except O1C74RunError:
        raise
    except Exception as exc:
        raise O1C74RunError("native O1C-0074 result differs") from exc


def _invocation_document(
    prepared: PreparedStream,
    initial_rows: Mapping[str, object],
    bindings: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "rank_source_vault": prepared.rank_source.describe(),
        "initial_causal_attic": prepared.state.describe(),
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
    state: CausalAttic,
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
        "attic_before": state.describe(),
        "attic_after": state.describe(),
        "native_calls_consumed": 1,
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "billed_conflicts": None,
        "retry_authorized": False,
        "terminal_failure": failure,
    }
    _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    return episode, failure


def execute_stream(
    *,
    capsule: Path,
    prepared: PreparedStream,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object] | None = None,
) -> StreamOutcome:
    """Consume the frozen 0..3 / 10..13 stream once, with no call retry."""

    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or not callable(invoke_episode)
        or not callable(verify_public_model)
        or prepared.state.active_projection.clause_count > ACTIVE_CLAUSE_LIMIT
        or prepared.rank_source.identity != prepared.state.active_projection.identity
    ):
        raise O1C74RunError("stream execution input differs")
    normalized_bindings = dict(bindings or {})
    initial_rows = _initial_artifacts(capsule, prepared)
    invocation = _invocation_document(prepared, initial_rows, normalized_bindings)
    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, invocation, immutable=True)
    invocation_sha = _sha256_file(invocation_path)
    rank_path = capsule / "initial" / "rank-source.vault"
    if rank_path.read_bytes() != prepared.rank_source.serialized:
        raise O1C74RunError("rank-source capsule bytes differ")

    state = prepared.state
    episodes: list[Mapping[str, object]] = []
    billed_total = 0
    global_novel_total = 0
    native_calls = 0
    requested_total = 0

    for local_ordinal, lineage_ordinal in zip(
        LOCAL_EPISODES, LINEAGE_ORDINALS, strict=True
    ):
        episode_dir = capsule / "episodes" / f"{local_ordinal:02d}"
        episode_dir.mkdir(parents=True, exist_ok=False)
        active_before = state.active_projection
        active_path = episode_dir / "active-input.bin"
        active_row = _copy_immutable(active_path, active_before.serialized)
        reread_active = _parse_vault(
            active_path.read_bytes(),
            identity=prepared.rank_source.identity,
            observed_variables=prepared.rank_source.observed_variables,
        )
        if reread_active.serialized != active_before.serialized:
            raise O1C74RunError("episode active input reread differs")
        intent = {
            "schema": INTENT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "local_episode_ordinal": local_ordinal,
            "lineage_call_ordinal": lineage_ordinal,
            "invocation_sha256": invocation_sha,
            "rank_source_vault": prepared.rank_source.describe(),
            "active_input_vault": active_before.describe(),
            "active_input_artifact": active_row,
            "attic_before": state.describe(),
            "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "truth_key_bytes_read": False,
            "retry_authorized": False,
        }
        intent_path = episode_dir / "intent.json"
        _atomic_json(intent_path, intent, immutable=True)
        intent_sha = _sha256_file(intent_path)
        # The count is advanced immediately before the one external call.  Any
        # exception or returned-but-invalid object consumes this ordinal.
        native_calls += 1
        requested_total += REQUESTED_CONFLICTS_PER_EPISODE
        try:
            executable_binding_raw = normalized_bindings.get("native_executable")
            if executable_binding_raw is not None:
                executable_binding = _mapping(
                    executable_binding_raw, "execution native executable"
                )
                observed_executable = validate_native_executable(
                    cast(str, executable_binding.get("path")),
                    expected_sha256=cast(str, executable_binding.get("sha256")),
                )
                if observed_executable != executable_binding:
                    raise O1C74RunError(
                        "native executable changed immediately before call"
                    )
            result = invoke_episode(
                local_ordinal, lineage_ordinal, rank_path, active_path
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
                failure,
            )

        try:
            stream_id = f"o1c74-episode-{local_ordinal:02d}"
            validated = _validated_episode_result(
                result,
                rank_source=prepared.rank_source,
                active=active_before,
                stream_id=stream_id,
                verify_public_model=verify_public_model,
                require_concrete_result=(
                    normalized_bindings.get("test_fixture")
                    != "synthetic-target-free"
                ),
            )
            occurrences = cast(
                tuple[ClauseOccurrence, ...], validated["occurrences"]
            )
            validated_telemetry = cast(
                Mapping[str, object], validated["telemetry"]
            )
            globally_known = {
                clause.serialized for clause in state.union_vault.clauses
            }
            novel_clauses: list[ThresholdNoGoodClause] = []
            for occurrence in occurrences:
                key = occurrence.clause.serialized
                if key not in globally_known:
                    if occurrence.classification != "new":
                        raise O1C74RunError(
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
                next_state = reproject_causal_attic(
                    (*state.chunks, rollover),
                    (*state.occurrences, *occurrences),
                    active_limit=ACTIVE_CLAUSE_LIMIT,
                )
            except CausalAtticError as exc:
                raise O1C74RunError("episode causal reprojection differs") from exc
            if next_state.active_projection.clause_count > ACTIVE_CLAUSE_LIMIT:
                raise O1C74RunError("episode active projection exceeds K")
            # All semantic validation and reprojection completes in memory before
            # the first returned-result sidecar is created.  A later I/O error is
            # journaled operationally and makes no retention/gain claim.
            rollover_path = episode_dir / "attic-rollover.vault"
            rollover_row = _copy_immutable(rollover_path, rollover.serialized)
            reread_rollover = _parse_vault(
                rollover_path.read_bytes(),
                identity=prepared.rank_source.identity,
                observed_variables=prepared.rank_source.observed_variables,
            )
            if reread_rollover.serialized != rollover.serialized:
                raise O1C74RunError("rollover chunk reread differs")
            native_evidence = _write_compressed_json(
                episode_dir / "native-result.json.gz", validated["raw"]
            )
            telemetry_evidence = _write_compressed_json(
                episode_dir / "vault-telemetry.json.gz", validated["telemetry"]
            )
            reader_evidence = _write_compressed_json(
                episode_dir / "decision-reader.json.gz", validated["reader"]
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
                raise O1C74RunError("episode active output reread differs")
            occurrence_delta = {
                "schema": CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
                "stream_id": stream_id,
                "occurrence_count": len(occurrences),
                "records": [
                    occurrence.describe(
                        ordinal=ordinal,
                        union_clause_index=next_state.occurrence_union_indices[
                            len(state.occurrences) + ordinal
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
            boundary = {
                "schema": PROJECTION_BOUNDARY_SCHEMA,
                "local_episode_ordinal": local_ordinal,
                "lineage_call_ordinal": lineage_ordinal,
                "attic_before": state.describe(),
                "attic_after": next_state.describe(),
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
                "rollover_completed": True,
                "artifacts_reread": True,
                "reprojected_after_boundary": True,
            }
            boundary_path = episode_dir / "projection-boundary.json"
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
                "attic_before": state.describe(),
                "attic_after": next_state.describe(),
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
                "projection_boundary_sha256": _sha256_file(boundary_path),
                "native_evidence": native_evidence,
                "vault_telemetry_evidence": telemetry_evidence,
                "reader_evidence": reader_evidence,
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
                "retry_authorized": False,
                "terminal_failure": None,
            }
            _atomic_json(episode_dir / "episode.json", episode, immutable=True)
            episodes.append(episode)
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
                failure,
            )

    if native_calls != MAXIMUM_NATIVE_SOLVER_CALLS or requested_total != (
        MAXIMUM_TOTAL_REQUESTED_CONFLICTS
    ):
        raise O1C74RunError("stream bounded call ledger differs")
    classification = NOVEL_CLAUSE_GAIN if global_novel_total else NO_GAIN
    reason = (
        "globally-novel-exact-clauses-retained-in-causal-attic"
        if global_novel_total
        else "no-public-recovery-exhaustion-proof-or-global-novel-clause"
    )
    return StreamOutcome(
        classification,
        reason,
        tuple(episodes),
        state,
        native_calls,
        requested_total,
        billed_total,
        global_novel_total,
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
    """Build the publication record with attic and active identities separated."""

    if not isinstance(outcome, StreamOutcome) or not isinstance(
        capsule_relative, str
    ):
        raise O1C74RunError("result input differs")
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
            "attempt_id": "O1C-0073",
            "result_sha256": PARENT_RESULT_SHA256,
            "manifest_sha256": PARENT_MANIFEST_SHA256,
            "source_commit": PARENT_SOURCE_COMMIT,
            "last_consumed_lineage_ordinal": 9,
            "retried": False,
        },
        "rank_source_vault": outcome.final_state.chunks[0].describe(),
        "final_attic": outcome.final_state.describe(),
        "final_active_vault": outcome.final_state.active_projection.describe(),
        "episodes": [dict(episode) for episode in outcome.episodes],
        "claim_boundary": {
            "immutable_complete_causal_attic": (
                outcome.operational_failure is None
            ),
            "active_projection_clause_limit": ACTIVE_CLAUSE_LIMIT,
            "rank_source_separate_from_active_projection": True,
            "rank_source_sha256": outcome.final_state.chunks[0].sha256,
            "capacity_event_is_rollover_after_durable_reprojection": True,
            "every_fully_emitted_occurrence_retained": (
                outcome.operational_failure is None
            ),
            "duplicate_witness_occurrences_retained": (
                outcome.operational_failure is None
            ),
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
            "Do not retry O1C-0073 or replay ordinal 9; preserve the complete "
            "attic and evaluate only the frozen O1C-0074 result gate."
        ),
    }


def write_publication_source(
    capsule: Path, result: Mapping[str, object]
) -> Path:
    """Seal the terminal source record from which publication can be recovered."""

    if result.get("schema") != RESULT_SCHEMA or result.get(
        "publication_recovery"
    ) is not None:
        raise O1C74RunError("publication source result differs")
    path = capsule / PUBLICATION_SOURCE_NAME
    _atomic_json(path, dict(result), immutable=True)
    return path


def _recover_completed_episode(
    *,
    capsule: Path,
    state: CausalAttic,
    expected: Mapping[str, object],
    invocation_sha256: str,
) -> CausalAttic:
    local = _nonnegative_int(
        expected.get("local_episode_ordinal"), "recovery local ordinal"
    )
    episode_dir = capsule / "episodes" / f"{local:02d}"
    journal = _read_json(episode_dir / "episode.json", "recovery episode")
    if journal != expected or journal.get("schema") != EPISODE_SCHEMA:
        raise O1C74RunError("recovery episode journal differs")
    intent_path = _regular(episode_dir / "intent.json", "recovery intent")
    intent = _read_json(intent_path, "recovery intent")
    if (
        _sha256_file(intent_path)
        != _sha256(expected.get("intent_sha256"), "recovery intent digest")
        or expected.get("invocation_sha256") != invocation_sha256
        or intent.get("invocation_sha256") != invocation_sha256
        or intent.get("schema") != INTENT_SCHEMA
        or intent.get("local_episode_ordinal") != local
        or intent.get("lineage_call_ordinal")
        != expected.get("lineage_call_ordinal")
        or intent.get("attic_before") != state.describe()
    ):
        raise O1C74RunError("recovery intent binding differs")
    active_path = _validate_artifact_row(
        episode_dir, intent.get("active_input_artifact"), "recovery active input"
    )
    active = _parse_vault(
        active_path.read_bytes(),
        identity=state.chunks[0].identity,
        observed_variables=state.chunks[0].observed_variables,
    )
    if active.serialized != state.active_projection.serialized:
        raise O1C74RunError("recovery active input differs")

    telemetry = _read_compressed_json(
        episode_dir,
        expected.get("vault_telemetry_evidence"),
        "recovery vault telemetry",
    )
    telemetry_payload = canonical_json_bytes(telemetry)
    try:
        parsed = parse_vault_telemetry(
            telemetry_payload,
            stream_id=f"o1c74-episode-{local:02d}",
            expected_sha256=sha256_bytes(telemetry_payload),
        )
    except CausalAtticError as exc:
        raise O1C74RunError("recovery occurrence ledger differs") from exc
    if (
        parsed.input_identity != active.identity
        or parsed.input_vault_sha256 != active.sha256
        or parsed.input_clause_count != active.clause_count
        or parsed.input_literal_count != active.literal_count
        or parsed.input_serialized_bytes != active.serialized_bytes
    ):
        raise O1C74RunError("recovery telemetry input differs")
    native_raw = _read_compressed_json(
        episode_dir, expected.get("native_evidence"), "recovery native result"
    )
    reader = _read_compressed_json(
        episode_dir, expected.get("reader_evidence"), "recovery decision reader"
    )
    status = _nonnegative_int(expected.get("status"), "recovery native status")
    work = _mapping(expected.get("work"), "recovery work")
    try:
        stats = validate_vault_soft_conflict_ledger(work)
    except Exception as exc:
        raise O1C74RunError("recovery conflict ledger differs") from exc
    resources = _mapping(expected.get("resources"), "recovery resources")
    raw_model = native_raw.get("key_model_hex")
    if status == 10:
        if not isinstance(raw_model, str) or len(raw_model) != 64:
            raise O1C74RunError("recovery public model encoding differs")
        try:
            key_model: bytes | None = bytes.fromhex(raw_model)
        except ValueError as exc:
            raise O1C74RunError("recovery public model encoding differs") from exc
    else:
        key_model = None
    raw_sieve = _mapping(native_raw.get("sieve"), "recovery native sieve")
    _validate_archived_v16_provenance(
        raw=native_raw,
        reader=reader,
        telemetry=telemetry,
        rank_source=state.chunks[0],
        active=active,
        status=status,
        stats=stats,
        resources=resources,
        sieve=raw_sieve,
        key_model=key_model,
    )
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
        raise O1C74RunError("recovery native/public provenance differs")
    chunk_path = _validate_artifact_row(
        episode_dir,
        expected.get("rollover_chunk_artifact"),
        "recovery rollover chunk",
    )
    chunk = _parse_vault(
        chunk_path.read_bytes(),
        identity=state.chunks[0].identity,
        observed_variables=state.chunks[0].observed_variables,
    )
    globally_known = {clause.serialized for clause in state.union_vault.clauses}
    expected_novel: list[ThresholdNoGoodClause] = []
    for occurrence in parsed.occurrences:
        key = occurrence.clause.serialized
        if key not in globally_known:
            if occurrence.classification != "new":
                raise O1C74RunError("recovery global novelty differs")
            globally_known.add(key)
            expected_novel.append(occurrence.clause)
    if chunk.clauses != tuple(expected_novel):
        raise O1C74RunError("recovery rollover population differs")
    try:
        next_state = reproject_causal_attic(
            (*state.chunks, chunk),
            (*state.occurrences, *parsed.occurrences),
            active_limit=ACTIVE_CLAUSE_LIMIT,
        )
    except CausalAtticError as exc:
        raise O1C74RunError("recovery causal reprojection differs") from exc
    occurrence_path = _validate_artifact_row(
        episode_dir,
        expected.get("occurrence_delta_artifact"),
        "recovery occurrence delta",
    )
    occurrence_delta = _read_json(occurrence_path, "recovery occurrence delta")
    expected_records = [
        occurrence.describe(
            ordinal=ordinal,
            union_clause_index=next_state.occurrence_union_indices[
                len(state.occurrences) + ordinal
            ],
        )
        for ordinal, occurrence in enumerate(parsed.occurrences)
    ]
    if (
        occurrence_delta.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA
        or occurrence_delta.get("stream_id") != f"o1c74-episode-{local:02d}"
        or occurrence_delta.get("occurrence_count") != len(parsed.occurrences)
        or occurrence_delta.get("records") != expected_records
    ):
        raise O1C74RunError("recovery occurrence delta differs")
    output_path = _validate_artifact_row(
        episode_dir,
        expected.get("active_output_artifact"),
        "recovery active output",
    )
    output = _parse_vault(
        output_path.read_bytes(),
        identity=state.chunks[0].identity,
        observed_variables=state.chunks[0].observed_variables,
    )
    boundary = _read_json(
        episode_dir / "projection-boundary.json", "recovery projection boundary"
    )
    if (
        output.serialized != next_state.active_projection.serialized
        or expected.get("attic_after") != next_state.describe()
        or expected.get("output_active_vault")
        != next_state.active_projection.describe()
        or boundary.get("schema") != PROJECTION_BOUNDARY_SCHEMA
        or boundary.get("attic_before") != state.describe()
        or boundary.get("attic_after") != next_state.describe()
        or _sha256_file(episode_dir / "projection-boundary.json")
        != _sha256(
            expected.get("projection_boundary_sha256"),
            "recovery projection boundary digest",
        )
    ):
        raise O1C74RunError("recovery projection boundary differs")
    return next_state


def recover_publication(
    capsule: Path,
    publication_source: Mapping[str, object] | str | Path | None = None,
) -> dict[str, object]:
    """Replay sealed sidecars without issuing a native or verification call."""

    _validate_regular_capsule_tree(capsule)
    if publication_source is None:
        source = _read_json(
            capsule / PUBLICATION_SOURCE_NAME, "publication recovery source"
        )
    elif isinstance(publication_source, Mapping):
        source = dict(publication_source)
        source_path = _regular(
            capsule / PUBLICATION_SOURCE_NAME, "publication recovery source"
        )
        if canonical_json_bytes(source) != source_path.read_bytes():
            raise O1C74RunError("publication recovery source bytes differ")
    else:
        source = _read_json(Path(publication_source), "publication recovery source")
    if (
        source.get("schema") != RESULT_SCHEMA
        or source.get("attempt_id") != ATTEMPT_ID
        or source.get("publication_recovery") is not None
    ):
        raise O1C74RunError("publication recovery source contract differs")
    invocation_path = _regular(capsule / "invocation.json", "recovery invocation")
    invocation = _read_json(invocation_path, "recovery invocation")
    if invocation.get("schema") != INVOCATION_SCHEMA:
        raise O1C74RunError("recovery invocation differs")
    invocation_sha = _sha256_file(invocation_path)
    bindings = _mapping(invocation.get("bindings"), "recovery bindings")
    if bindings.get("test_fixture") != "synthetic-target-free":
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
        ):
            raise O1C74RunError("publication recovery freeze differs")
    initial_rows = _mapping(
        invocation.get("initial_artifacts"), "recovery initial artifacts"
    )
    state = _rebuild_initial_from_capsule(capsule, initial_rows)
    episodes = _sequence(source.get("episodes"), "recovery episodes")
    if len(episodes) > MAXIMUM_NATIVE_SOLVER_CALLS:
        raise O1C74RunError("recovery episode count differs")
    stopped = False
    for index, raw_episode in enumerate(episodes):
        episode = _mapping(raw_episode, "recovery episode")
        if (
            episode.get("local_episode_ordinal") != LOCAL_EPISODES[index]
            or episode.get("lineage_call_ordinal") != LINEAGE_ORDINALS[index]
            or stopped
        ):
            raise O1C74RunError("recovery episode schedule differs")
        if episode.get("completed") is True:
            state = _recover_completed_episode(
                capsule=capsule,
                state=state,
                expected=episode,
                invocation_sha256=invocation_sha,
            )
            stopped = episode.get("status") in (10, 20)
        elif episode.get("completed") is False:
            failed_dir = capsule / "episodes" / f"{index:02d}"
            journal = _read_json(
                failed_dir / "episode.json",
                "recovery failed episode",
            )
            failure_path = _regular(
                failed_dir / "terminal-failure.json",
                "recovery terminal failure",
            )
            failed_intent_path = _regular(
                failed_dir / "intent.json", "recovery failed intent"
            )
            failed_intent = _read_json(
                failed_intent_path, "recovery failed intent"
            )
            if (
                episode.get("invocation_sha256") != invocation_sha
                or failed_intent.get("invocation_sha256") != invocation_sha
                or _sha256_file(failed_intent_path)
                != episode.get("intent_sha256")
                or failed_intent.get("attic_before") != state.describe()
                or journal != episode
                or _read_json(
                failure_path, "recovery terminal failure"
                )
                != episode.get("terminal_failure")
            ):
                raise O1C74RunError("recovery failed episode differs")
            stopped = True
        else:
            raise O1C74RunError("recovery episode completion differs")
    resources = _mapping(source.get("resources"), "recovery resources")
    derived_billed = 0
    derived_global_novel = 0
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
            raise O1C74RunError("recovery unterminated stream differs")
        derived_classification = (
            NOVEL_CLAUSE_GAIN if derived_global_novel else NO_GAIN
        )
        derived_stop_reason = (
            "globally-novel-exact-clauses-retained-in-causal-attic"
            if derived_global_novel
            else "no-public-recovery-exhaustion-proof-or-global-novel-clause"
        )
    derived_billed_value: int | None = (
        None if derived_classification == OPERATIONAL_TERMINAL else derived_billed
    )
    if (
        source.get("final_attic") != state.describe()
        or source.get("final_active_vault") != state.active_projection.describe()
        or source.get("rank_source_vault") != state.chunks[0].describe()
        or source.get("classification") != derived_classification
        or source.get("stop_reason") != derived_stop_reason
        or source.get("operational_failure")
        != (dict(derived_failure) if derived_failure is not None else None)
        or resources.get("native_solver_calls") != len(episodes)
        or resources.get("requested_conflicts")
        != len(episodes) * REQUESTED_CONFLICTS_PER_EPISODE
        or resources.get("billed_conflicts") != derived_billed_value
        or resources.get("globally_novel_clauses") != derived_global_novel
    ):
        raise O1C74RunError("publication recovery conclusion differs")
    recovered = dict(source)
    recovered["publication_recovery"] = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "publication_recovered_from_completed_sidecars": True,
        "native_calls_issued_during_recovery": 0,
        "public_verification_calls_issued_during_recovery": 0,
        "truth_key_bytes_read": False,
        "recovered_episode_count": len(episodes),
        "recovered_final_attic_sha256": state.union_vault.sha256,
        "recovered_final_active_vault_sha256": state.active_projection.sha256,
    }
    return recovered


def _relative_contract(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C74RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C74RunError(f"{field} escapes the lab")
    return path.as_posix()


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
        raise O1C74RunError(f"{field} differs")
    return value


def load_config(
    path: str | Path, *, root: Path | None = None
) -> dict[str, object]:
    """Load the complete frozen O1C74 contract without writing or calling."""

    lab = (root or lab_root()).resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(lab):
        raise O1C74RunError("O1C74 config escapes the lab")
    config = dict(_read_json(config_path, "O1C74 config"))
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
        raise O1C74RunError("frozen O1C74 config fields differ")
    parent = _mapping(config["parent"], "config parent")
    if (
        set(parent)
        != {
            "result",
            "capsule",
            "result_sha256",
            "manifest_sha256",
            "source_commit",
        }
        or _relative_contract(parent.get("result"), "parent result")
        != PARENT_RESULT_RELATIVE.as_posix()
        or _relative_contract(parent.get("capsule"), "parent capsule")
        != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
    ):
        raise O1C74RunError("frozen O1C73 parent differs")
    preparation = _mapping(config["preparation"], "config preparation")
    if set(preparation) != {"directory", "manifest_sha256"}:
        raise O1C74RunError("prepared causal-attic config differs")
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
        raise O1C74RunError("frozen stream inputs differ")
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
    }
    if (
        set(native) != required_native
        or _relative_contract(native.get("source"), "native source")
        != SOURCE_PATHS["native_v13"]
        or _relative_contract(native.get("executable"), "native executable")
        != "build/o1c74/native-joint-score-sieve"
        or native.get("adapter_schema")
        != _native_v16.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema")
        != _native_v16.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("rank_source_sha256") != RANK_SOURCE_SHA256
    ):
        raise O1C74RunError("native split-vault config differs")
    _digest_or_pending(native.get("expected_source_sha256"), "native source digest")
    _digest_or_pending(
        native.get("expected_executable_sha256"), "native executable digest"
    )
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
        raise O1C74RunError("source freeze config differs")
    _commit_or_pending(source.get("expected_commit"), "expected source commit")
    for name in SOURCE_PATHS:
        _digest_or_pending(expected_sources.get(name), f"source digest {name}")
    if native.get("expected_source_sha256") != expected_sources.get("native_v13"):
        raise O1C74RunError("native/source digest binding differs")
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
        raise O1C74RunError("target-free preflight config differs")
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
    }
    if dict(budgets) != expected_budgets:
        raise O1C74RunError("frozen O1C74 budgets differ")
    return config


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
            raise O1C74RunError("native executable mode differs")
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
    except OSError as exc:
        raise O1C74RunError("native executable cannot be read") from exc
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
        raise O1C74RunError("native executable identity differs")
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


def _validate_target_free_gate(
    path: Path, *, expected_sha256: str, prepared: PreparedStream
) -> Mapping[str, object]:
    payload = _regular(path, "target-free preflight").read_bytes()
    if sha256_bytes(payload) != expected_sha256:
        raise O1C74RunError("target-free preflight digest differs")
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C74RunError("target-free preflight JSON differs") from exc
    row = _mapping(value, "target-free preflight")
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
        or row.get("initial_attic") != prepared.state.describe()
        or row.get("active_clause_limit") != ACTIVE_CLAUSE_LIMIT
        or row.get("local_episode_ordinals") != list(LOCAL_EPISODES)
        or row.get("lineage_call_ordinals") != list(LINEAGE_ORDINALS)
        or row.get("requested_conflicts_per_episode")
        != REQUESTED_CONFLICTS_PER_EPISODE
        or row.get("maximum_native_solver_calls")
        != MAXIMUM_NATIVE_SOLVER_CALLS
        or row.get("maximum_total_requested_conflicts")
        != MAXIMUM_TOTAL_REQUESTED_CONFLICTS
        or row.get("rank_active_split_fixture_passed") is not True
        or row.get("causal_attic_reconstruction_fixture_passed") is not True
        or row.get("capacity_rollover_fixture_passed") is not True
        or row.get("duplicate_occurrence_fixture_passed") is not True
        or row.get("publication_recovery_fixture_passed") is not True
        or row.get("no_retry_fixture_passed") is not True
    ):
        raise O1C74RunError("target-free preflight contract differs")
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
        raise O1C74RunError("O1C73 parent artifact identity differs")
    preparation = _mapping(config["preparation"], "preflight preparation")
    prepared_digest = frozen_digest(
        preparation["manifest_sha256"], "prepared manifest digest"
    )
    prepared = load_prepared_stream(
        _relative(lab, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=prepared_digest,
    )
    if (
        prepared.rank_source.sha256 != RANK_SOURCE_SHA256
        or prepared.state.union_vault.clause_count != INITIAL_UNION_CLAUSES
        or prepared.state.union_vault.literal_count != INITIAL_UNION_LITERALS
        or prepared.state.union_vault.serialized_bytes
        != INITIAL_UNION_SERIALIZED_BYTES
        or prepared.state.active_projection.sha256 != INITIAL_ACTIVE_SHA256
        or prepared.state.active_projection.clause_count != INITIAL_ACTIVE_CLAUSES
        or prepared.state.active_projection.literal_count != INITIAL_ACTIVE_LITERALS
        or prepared.state.active_projection.serialized_bytes
        != INITIAL_ACTIVE_SERIALIZED_BYTES
    ):
        raise O1C74RunError("frozen prepared causal attic differs")
    inputs = _mapping(config["inputs"], "preflight inputs")
    observed_inputs: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        input_path = _relative(lab, inputs[name], f"input {name}")
        expected = frozen_digest(inputs[f"{name}_sha256"], f"input {name} digest")
        observed = _sha256_file(input_path)
        if observed != expected:
            raise O1C74RunError(f"frozen input {name} differs")
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
            raise O1C74RunError(f"source {name} differs")
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
        raise O1C74RunError(
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
        raise O1C74RunError("source commit binding cannot be established") from exc
    if require_commit_binding:
        try:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", expected_commit, commit],
                cwd=lab,
                check=False,
                capture_output=True,
            )
            if ancestor.returncode != 0:
                raise O1C74RunError("source freeze is not an execution ancestor")
            for name, relative in paths.items():
                frozen_blob = subprocess.run(
                    ["git", "show", f"{expected_commit}:{relative}"],
                    cwd=lab,
                    check=True,
                    capture_output=True,
                ).stdout
                if sha256_bytes(frozen_blob) != observed_sources[name]:
                    raise O1C74RunError(
                        f"source {name} differs from its frozen commit blob"
                    )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise O1C74RunError("source commit blob binding differs") from exc
        if dirty:
            raise O1C74RunError("execution worktree is not clean")
    try:
        disk_free = shutil.disk_usage(lab).free
    except OSError as exc:
        raise O1C74RunError("disk resource preflight failed") from exc
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C74RunError("disk resource preflight differs")
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
        "initial_attic": prepared.state.describe(),
        "target_free_preflight_sha256": gate_digest,
        "target_free_preflight": gate,
        "native_executable": executable_binding,
        "disk_free_bytes": disk_free,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


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
        "# O1C-0074 — APPLE8 causal-attic stream\n\n"
        f"- Classification: `{result.get('classification')}`\n"
        f"- Stop reason: `{result.get('stop_reason')}`\n"
        f"- Native calls: `{resources.get('native_solver_calls')}`\n"
        f"- Requested conflicts: `{resources.get('requested_conflicts')}`\n"
        f"- Globally novel clauses: `{resources.get('globally_novel_clauses')}`\n"
        "- Active projection limit: `256` clauses\n"
        "- Immutable rank source is separate from the active projection\n"
        "- Truth key bytes read: `false`\n"
    ).encode("utf-8")


def _manifest_payload(
    capsule: Path, virtual: Mapping[str, bytes]
) -> tuple[bytes, int]:
    if capsule.is_symlink() or not capsule.is_dir():
        raise O1C74RunError("capsule manifest root differs")
    payloads: dict[str, bytes] = {}
    for path in capsule.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C74RunError("capsule manifest contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256" and relative not in virtual:
                payloads[relative] = path.read_bytes()
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C74RunError("capsule manifest contains a special file")
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
    """Atomically publish one terminal result and seal its complete capsule."""

    if (
        authoritative.exists()
        or (capsule / "result.json").exists()
        or (capsule / "artifacts.sha256").exists()
        or result.get("schema") != RESULT_SCHEMA
    ):
        raise O1C74RunError("terminal O1C74 publication already exists")
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
        raise O1C74RunError("persistent artifact ledger did not converge")
    result_payload = canonical_json_bytes(result)
    run_payload = _markdown(result)
    manifest, persistent = _manifest_payload(
        capsule, {"RUN.md": run_payload, "result.json": result_payload}
    )
    if (
        resources.get("persistent_artifact_bytes") != persistent
        or persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES
    ):
        raise O1C74RunError("persistent artifact byte budget differs")
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
        raise O1C74RunError("authoritative result reread differs")


def _existing_authoritative(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    value = dict(_read_json(path, "authoritative O1C74 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C74RunError("authoritative O1C74 result differs")
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
    if (
        manifest_path.read_bytes() != expected_manifest
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("capsule") != capsule.relative_to(lab_root()).as_posix()
        or resources.get("persistent_artifact_bytes") != persistent
    ):
        raise O1C74RunError("sealed O1C74 capsule differs")
    payload = result_path.read_bytes()
    if canonical_json_bytes(result) != payload:
        raise O1C74RunError("sealed O1C74 result canonical bytes differ")
    _atomic_create(authoritative, payload, immutable=True)
    return result


def run(config_path: str | Path = CONFIG_RELATIVE) -> dict[str, object]:
    """Execute or recover the one frozen four-episode O1C74 stream."""

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
            raise O1C74RunError("multiple existing O1C74 capsules block replay")
        capsule = existing_capsules[0]
        if (capsule / "artifacts.sha256").is_file():
            return _republish_sealed_capsule(capsule, authoritative)
        if not (capsule / PUBLICATION_SOURCE_NAME).is_file():
            raise O1C74RunError(
                "partial O1C74 capsule without publication source blocks replay"
            )
        if any((capsule / name).exists() for name in ("RUN.md", "result.json")):
            raise O1C74RunError(
                "partially published O1C74 capsule requires manual recovery"
            )
        recovered = recover_publication(capsule)
        finalize_capsule(capsule, authoritative, recovered)
        return recovered

    config_file = Path(config_path).resolve(strict=True)
    preflight_row = preflight(config_file, require_commit_binding=True, root=root)
    config = load_config(config_file, root=root)
    preparation = _mapping(config["preparation"], "run preparation")
    prepared = load_prepared_stream(
        _relative(root, preparation["directory"], "run prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
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
        raise O1C74RunError("post-preflight native executable differs")
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
            "fixed_output_path_reproducibility_required": True,
        },
        immutable=True,
    )
    _atomic_create(
        capsule / "command.txt",
        (
            "nice -n 10 env PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c74_apple8_causal_attic_stream_run run "
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
    ) -> object:
        if (
            local_ordinal not in LOCAL_EPISODES
            or LINEAGE_ORDINALS[local_ordinal] != lineage_ordinal
            or _sha256_file(rank_vault) != RANK_SOURCE_SHA256
        ):
            raise O1C74RunError("native stream invocation identity differs")
        observed_executable = validate_native_executable(
            executable,
            expected_sha256=cast(str, native["expected_executable_sha256"]),
        )
        if observed_executable != executable_binding:
            raise O1C74RunError("native executable changed in call window")
        result = _native_v16.run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            rank_vault_path=rank_vault,
            vault_path=active_vault,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            require_active_contrast=False,
        )
        if (
            validate_native_executable(
                executable,
                expected_sha256=cast(str, native["expected_executable_sha256"]),
            )
            != executable_binding
        ):
            raise O1C74RunError("native executable changed during call window")
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
    write_publication_source(capsule, result)
    finalize_capsule(capsule, authoritative, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight, run, or recover O1C74's causal-attic stream"
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
                raise O1C74RunError("recovery capsule escapes run root")
            value = recover_publication(capsule)
            finalize_capsule(capsule, root / RESULT_RELATIVE, value)
        sys.stdout.buffer.write(canonical_json_bytes(value))
        return 0
    except O1C74RunError as exc:
        print(f"O1C74: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
