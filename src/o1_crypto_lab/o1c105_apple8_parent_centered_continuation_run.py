"""Burn-on-intent runner for the single O1C-0105 Page-20 call.

The runner has one scientific side effect: after an immutable intent is
persisted it may invoke native v31 once, with seed zero and 128 requested
conflicts.  Failure-first priority actions are operational evidence, never a
bit belief or science gain by themselves.  Its preparation gate reads only
the published, sealed O1C-0104 composed causal-rollover bundle; it never regenerates
the expensive causal residency history.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import shlex
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence, cast

from . import joint_score_sieve_v34 as _native_v34
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .causal_attic_v1 import canonical_json_bytes, sha256_bytes
from .o1c83_apple8_causal_rollover_prepare import (
    CONTINUATION_CANDIDATE_ORDER_SHA256,
)
from . import o1c102_page19_causal_rollover_prepare as _o1c102
from . import o1c104_page20_causal_rollover_prepare as _o1c104
from .o1c82_parent_centered_seed import MISSING_VARIABLE, RECORD_BYTES
from .threshold_no_good_vault_v1 import O1C66_VAULT_CAPS, ThresholdNoGoodClause


ACTIVE_PROJECTION_NAME = _o1c104.ACTIVE_PROJECTION_NAME
ACTIVATION_LEDGER_NAME = _o1c104.ACTIVATION_LEDGER_NAME
ATTIC_CHUNK_COUNT = _o1c104.ATTIC_CHUNK_COUNT
ATTIC_OCCURRENCE_COUNT = _o1c104.ATTIC_OCCURRENCE_COUNT
ATTIC_SUBSUMPTION_RELATION_COUNT = _o1c104.ATTIC_SUBSUMPTION_RELATION_COUNT
ATTIC_UNDOMINATED_CLAUSE_COUNT = _o1c104.ATTIC_UNDOMINATED_CLAUSE_COUNT
ATTIC_UNION_CLAUSE_COUNT = _o1c104.ATTIC_UNION_CLAUSE_COUNT
COMMON_CORE_AUDIT_NAME = _o1c104.COMMON_CORE_AUDIT_NAME
COMBINED_KNOWN_INVENTORY_SHA256 = _o1c104.LOGICAL_KNOWN_INVENTORY_SHA256
DEFAULT_PARENT_CAPSULE_RELATIVE = _o1c104.DEFAULT_PARENT_CAPSULE_RELATIVE
DEFAULT_PARENT_RESULT_RELATIVE = _o1c104.DEFAULT_PARENT_RESULT_RELATIVE
DERIVED_CLOSURE_BYTES = _o1c104.NEW_DERIVED_CLOSURE_BYTES
DERIVED_CLOSURE_NAME = _o1c104.DERIVED_CLOSURE_NAME
DERIVED_CLOSURE_SHA256 = _o1c104.NEW_DERIVED_CLOSURE_SHA256
DERIVED_KNOWN_INVENTORY_SHA256 = _o1c104.NEW_DERIVED_CLOSURE_INVENTORY_SHA256
DERIVED_RECEIPT_BYTES = _o1c104.DERIVED_RECEIPT_BYTES
DERIVED_RECEIPT_NAME = _o1c104.DERIVED_RECEIPT_NAME
DERIVED_RECEIPT_SHA256 = _o1c104.DERIVED_RECEIPT_SHA256
DERIVED_OVERLAY_BYTES = _o1c104.NEW_DERIVED_OVERLAY_BYTES
DERIVED_OVERLAY_NAME = _o1c104.DERIVED_OVERLAY_NAME
DERIVED_OVERLAY_SHA256 = _o1c104.NEW_DERIVED_OVERLAY_SHA256
EMITTED_KNOWN_INVENTORY_SHA256 = _o1c104.EMITTED_KNOWN_INVENTORY_SHA256
CONTINUATION_BANK_BYTES = _o1c104.FINAL_BANK_BYTES
CONTINUATION_BANK_SHA256 = _o1c104.FINAL_BANK_SHA256
PREPARED_CONTINUATION_BANK_NAME = _o1c104.FINAL_BANK_NAME
LOGICAL_KNOWN_CLAUSE_COUNT = _o1c104.LOGICAL_KNOWN_CLAUSE_COUNT
LOGICAL_KNOWN_SHA256 = _o1c104.LOGICAL_KNOWN_SHA256
NEW_CHUNK_NAME = _o1c104.NEW_CHUNK_NAME
NEW_CHUNK_SERIALIZED_BYTES = _o1c104.NEW_CHUNK_SERIALIZED_BYTES
NEW_CHUNK_SHA256 = _o1c104.NEW_CHUNK_SHA256
OCCURRENCES_NAME = _o1c104.OCCURRENCES_NAME
OCCURRENCE_DOCUMENT_BYTES = _o1c104.OCCURRENCE_DOCUMENT_BYTES
OCCURRENCE_DOCUMENT_SHA256 = _o1c104.OCCURRENCE_DOCUMENT_SHA256
PAGE20_ACTIVE_LIMIT = _o1c104.PAGE20_ACTIVE_LIMIT
PAGE20_ACTIVATION_DOCUMENT_BYTES = _o1c104.PAGE20_ACTIVATION_DOCUMENT_BYTES
PAGE20_ACTIVATION_DOCUMENT_SHA256 = _o1c104.PAGE20_ACTIVATION_DOCUMENT_SHA256
PAGE20_CATEGORY_COUNTS: Mapping[str, int] = _native_v34.PRODUCTION_PAGE20_CATEGORY_COUNTS
PAGE20_CLAUSE_COUNT = _o1c104.PAGE20_ACTIVE_LIMIT
PAGE20_HEADROOM: Mapping[str, int] = _native_v34.PRODUCTION_PAGE20_HEADROOM
PAGE20_LITERAL_COUNT = _o1c104.PAGE20_LITERAL_COUNT
PAGE20_RESIDENCY_DOCUMENT_BYTES = _o1c104.PAGE20_RESIDENCY_DOCUMENT_BYTES
PAGE20_RESIDENCY_DOCUMENT_SHA256 = _o1c104.PAGE20_RESIDENCY_DOCUMENT_SHA256
PAGE20_SERIALIZED_BYTES = _o1c104.PAGE20_SERIALIZED_BYTES
PAGE20_SHA256 = _o1c104.PAGE20_SHA256
PURE_EMITTED_CANDIDATE_SHA256 = _native_v34.PURE_EMITTED_CANDIDATE_SHA256
EMITTED_ONLY_ACTIVE_PROJECTION_SHA256 = (
    _native_v34.EMITTED_ONLY_ACTIVE_PROJECTION_SHA256
)
PARENT_CAPSULE_MANIFEST_SHA256 = _o1c104.PARENT_CAPSULE_MANIFEST_SHA256
PARENT_RESULT_SHA256 = _o1c104.PARENT_RESULT_SHA256
PREPARATION_MANIFEST_NAME = _o1c104.PREPARATION_MANIFEST_NAME
PREPARATION_MANIFEST_BYTES = _o1c104.PREPARATION_MANIFEST_BYTES
PREPARATION_MANIFEST_SHA256 = _o1c104.PREPARATION_MANIFEST_SHA256
PREPARATION_SCHEMA = _o1c104.PREPARATION_SCHEMA
PRIORITY_RECEIPT_NAME = _o1c104.PRIORITY_RECEIPT_NAME
PRIORITY_RECEIPT_BYTES = _o1c104.PRIORITY_RECEIPT_BYTES
PRIORITY_RECEIPT_SHA256 = _o1c104.PRIORITY_RECEIPT_SHA256
RELATIONS_NAME = _o1c104.RELATIONS_NAME
RELATION_DOCUMENT_BYTES = _o1c104.RELATION_DOCUMENT_BYTES
RELATION_DOCUMENT_SHA256 = _o1c104.RELATION_DOCUMENT_SHA256
RESIDENCY_NAME = _o1c104.RESIDENCY_NAME

INHERITED_DERIVED_RECEIPT_NAME = _o1c104.INHERITED_DERIVED_RECEIPT_NAME
INHERITED_DERIVED_RECEIPT_BYTES = _o1c102.DERIVED_RECEIPT_BYTES
INHERITED_DERIVED_RECEIPT_SHA256 = _o1c102.DERIVED_RECEIPT_SHA256
INHERITED_DERIVED_CLOSURE_NAME = _o1c104.INHERITED_DERIVED_CLOSURE_NAME
INHERITED_DERIVED_CLOSURE_BYTES = _o1c102.DERIVED_CLOSURE_BYTES
INHERITED_DERIVED_CLOSURE_SHA256 = _o1c102.DERIVED_CLOSURE_SHA256
INHERITED_DERIVED_OVERLAY_NAME = _o1c104.INHERITED_DERIVED_OVERLAY_NAME
INHERITED_DERIVED_OVERLAY_BYTES = _o1c102.DERIVED_OVERLAY_BYTES
INHERITED_DERIVED_OVERLAY_SHA256 = _o1c102.DERIVED_OVERLAY_SHA256


ATTEMPT_ID = "O1C-0105"
CONFIG_SCHEMA = "o1-256-apple8-parent-centered-continuation-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-parent-centered-continuation-preflight-v1"
NATIVE_BUILD_SCHEMA = "o1-256-o1c105-native-v31-build-v2"
INVOCATION_SCHEMA = "o1-256-apple8-parent-centered-continuation-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-parent-centered-continuation-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-parent-centered-continuation-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-parent-centered-continuation-result-v1"

CONFIG_RELATIVE = Path("configs/o1c105_apple8_parent_centered_continuation_v1.json")
RESULT_RELATIVE = Path(
    "research/O1C0105_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)
CAPSULE_SUFFIX = "O1C-0105_apple8-parent-centered-continuation-v1"

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 33
SEED = 0
THRESHOLD = 14.606178797892962
REQUESTED_CONFLICTS = 128
MAXIMUM_NATIVE_CALLS = 1
TIMEOUT_SECONDS = 120.0
MEMORY_LIMIT_BYTES = 536_870_912
MINIMUM_DISK_FREE_BYTES = 1_073_741_824
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 134_217_728
BUILD_TIMEOUT_SECONDS = 120.0
PROOF_MINING_SEMANTIC = "FAILURE_FIRST_PROOF_MINING"
CERTIFIED_CROSSING_SEMANTIC = "CERTIFIED_STRICT_BOUND_CROSSING_PRUNE"

OPERATIONAL_TERMINAL = "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
SCIENCE_MODEL = "PARENT_CENTERED_CONTINUATION_CERTIFIED_MODEL_OR_KEY_GAIN"
SCIENCE_CLOSURE = "PARENT_CENTERED_CONTINUATION_CERTIFIED_CLOSURE_GAIN"
SCIENCE_PRUNE = "PARENT_CENTERED_CONTINUATION_CERTIFIED_PRUNE_GAIN"
SCIENCE_CLAUSE = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
SCIENCE_DOMAIN = "PARENT_CENTERED_CONTINUATION_ATTACKER_VALID_ENTROPY_OR_DOMAIN_GAIN"
ACTIVATION_ONLY = "PARENT_CENTERED_CONTINUATION_OPERATIONAL_ACTIVATION_ONLY"
PROBE_ONLY = "PARENT_CENTERED_CONTINUATION_EXACT_PROBE_OPERATION_ONLY"
NO_OPERATION = "PARENT_CENTERED_CONTINUATION_NO_OPERATION_NO_GAIN"

FINAL_BANK_NAME = "final-parent-centered-priority-bank.bin"
NATIVE_STDOUT_NAME = "native-stdout.json"
NATIVE_EXECUTABLE_NAME = "native-joint-score-sieve"
NATIVE_CLOSURE_DIRECTORY = "native-source"
RECEIPT_NAME = PRIORITY_RECEIPT_NAME
PUBLISHED_PREPARATION_RELATIVE = Path(
    "research/o1c104_page20_causal_rollover_seed_20260721"
)
# Filled only from the atomically published preparation bundle.  These are
# preparation identities, never compiler-output predictions.
PUBLISHED_MANIFEST_SHA256 = PREPARATION_MANIFEST_SHA256
PUBLISHED_MANIFEST_BYTES = PREPARATION_MANIFEST_BYTES
CONTINUATION_BANK_NAME = PREPARED_CONTINUATION_BANK_NAME
PRIORITY_RECEIPT_RELATIVE = PUBLISHED_PREPARATION_RELATIVE / RECEIPT_NAME
DERIVED_RECEIPT_RELATIVE = PUBLISHED_PREPARATION_RELATIVE / DERIVED_RECEIPT_NAME
DERIVED_CLOSURE_RELATIVE = PUBLISHED_PREPARATION_RELATIVE / DERIVED_CLOSURE_NAME
DERIVED_OVERLAY_RELATIVE = PUBLISHED_PREPARATION_RELATIVE / DERIVED_OVERLAY_NAME
INHERITED_DERIVED_RECEIPT_RELATIVE = (
    PUBLISHED_PREPARATION_RELATIVE / INHERITED_DERIVED_RECEIPT_NAME
)
INHERITED_DERIVED_CLOSURE_RELATIVE = (
    PUBLISHED_PREPARATION_RELATIVE / INHERITED_DERIVED_CLOSURE_NAME
)
INHERITED_DERIVED_OVERLAY_RELATIVE = (
    PUBLISHED_PREPARATION_RELATIVE / INHERITED_DERIVED_OVERLAY_NAME
)
DERIVED_NAMESPACE_SHA256_FIELDS: Mapping[str, str] = {
    "inherited_derived_resolution_receipt_sha256": (
        INHERITED_DERIVED_RECEIPT_SHA256
    ),
    "inherited_derived_resolution_closure_sha256": (
        INHERITED_DERIVED_CLOSURE_SHA256
    ),
    "inherited_derived_resolution_overlay_sha256": (
        INHERITED_DERIVED_OVERLAY_SHA256
    ),
    "new_derived_resolution_receipt_sha256": DERIVED_RECEIPT_SHA256,
    "new_derived_resolution_closure_sha256": DERIVED_CLOSURE_SHA256,
    "new_derived_resolution_overlay_sha256": DERIVED_OVERLAY_SHA256,
}

COMMON_CORE_AUDIT_BYTES = 20_115
COMMON_CORE_AUDIT_SHA256 = (
    "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c"
)

INPUT_BANK_TOTAL_COUNT = 382_714
PARENT_CENTERED_ACTION_CAPACITY = 256

NATIVE_V31_USAGE = (
    b"usage: cadical_o1_joint_score_sieve_v31 --cnf PATH "
    b"--potential PATH --grouping PATH --vault-in PATH "
    b"--priority-seed PATH --threshold FLOAT --conflict-limit N "
    b"[--seed N]\n"
)

PREPARATION_ARTIFACT_NAMES = frozenset(
    {
        ACTIVE_PROJECTION_NAME,
        ACTIVATION_LEDGER_NAME,
        COMMON_CORE_AUDIT_NAME,
        CONTINUATION_BANK_NAME,
        INHERITED_DERIVED_CLOSURE_NAME,
        INHERITED_DERIVED_OVERLAY_NAME,
        INHERITED_DERIVED_RECEIPT_NAME,
        DERIVED_CLOSURE_NAME,
        DERIVED_OVERLAY_NAME,
        DERIVED_RECEIPT_NAME,
        NEW_CHUNK_NAME,
        OCCURRENCES_NAME,
        PREPARATION_MANIFEST_NAME,
        RECEIPT_NAME,
        RELATIONS_NAME,
        RESIDENCY_NAME,
    }
)
STAGED_INITIAL_NAMES = PREPARATION_ARTIFACT_NAMES

PUBLISHED_ARTIFACT_SEALS: Mapping[str, tuple[int, str, str]] = {
    ACTIVATION_LEDGER_NAME: (
        PAGE20_ACTIVATION_DOCUMENT_BYTES,
        PAGE20_ACTIVATION_DOCUMENT_SHA256,
        "composed-activation-ledger-with-byte-exact-page19-prefix",
    ),
    COMMON_CORE_AUDIT_NAME: (
        COMMON_CORE_AUDIT_BYTES,
        COMMON_CORE_AUDIT_SHA256,
        "unchanged-historical-public-common-core-audit",
    ),
    CONTINUATION_BANK_NAME: (
        CONTINUATION_BANK_BYTES,
        CONTINUATION_BANK_SHA256,
        "sealed-evolved-live-continuation-bank-bytes",
    ),
    RECEIPT_NAME: (
        PRIORITY_RECEIPT_BYTES,
        PRIORITY_RECEIPT_SHA256,
        "canonical-o1c103-evolved-priority-state-receipt",
    ),
    OCCURRENCES_NAME: (
        OCCURRENCE_DOCUMENT_BYTES,
        OCCURRENCE_DOCUMENT_SHA256,
        "pure-native-complete-updated-occurrence-ledger",
    ),
    DERIVED_RECEIPT_NAME: (
        DERIVED_RECEIPT_BYTES,
        DERIVED_RECEIPT_SHA256,
        "exact-public-84-clause-fixed-point-resolution-proof",
    ),
    DERIVED_CLOSURE_NAME: (
        DERIVED_CLOSURE_BYTES,
        DERIVED_CLOSURE_SHA256,
        "immutable-new-84-clause-resolution-closure",
    ),
    DERIVED_OVERLAY_NAME: (
        DERIVED_OVERLAY_BYTES,
        DERIVED_OVERLAY_SHA256,
        "immutable-new-52-clause-undominated-overlay",
    ),
    INHERITED_DERIVED_RECEIPT_NAME: (
        INHERITED_DERIVED_RECEIPT_BYTES,
        INHERITED_DERIVED_RECEIPT_SHA256,
        "immutable-inherited-o1c102-resolution-proof",
    ),
    INHERITED_DERIVED_CLOSURE_NAME: (
        INHERITED_DERIVED_CLOSURE_BYTES,
        INHERITED_DERIVED_CLOSURE_SHA256,
        "immutable-inherited-five-clause-closure",
    ),
    INHERITED_DERIVED_OVERLAY_NAME: (
        INHERITED_DERIVED_OVERLAY_BYTES,
        INHERITED_DERIVED_OVERLAY_SHA256,
        "immutable-inherited-three-clause-overlay",
    ),
    NEW_CHUNK_NAME: (
        NEW_CHUNK_SERIALIZED_BYTES,
        NEW_CHUNK_SHA256,
        "immutable-unique-lineage-32-native-evidence-chunk",
    ),
    ACTIVE_PROJECTION_NAME: (
        PAGE20_SERIALIZED_BYTES,
        PAGE20_SHA256,
        "fresh-lineage-33-composed-page20-science-input",
    ),
    RESIDENCY_NAME: (
        PAGE20_RESIDENCY_DOCUMENT_BYTES,
        PAGE20_RESIDENCY_DOCUMENT_SHA256,
        "composed-three-namespace-residency-state",
    ),
    RELATIONS_NAME: (
        RELATION_DOCUMENT_BYTES,
        RELATION_DOCUMENT_SHA256,
        "pure-native-complete-updated-subsumption-closure",
    ),
}

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c105_apple8_parent_centered_continuation_run.py",
    "runner_tests": "tests/test_o1c105_apple8_parent_centered_continuation_run.py",
    "adapter_v34": "src/o1_crypto_lab/joint_score_sieve_v34.py",
    "adapter_v34_tests": "tests/test_joint_score_sieve_v34.py",
    "page20_causal_rollover_preparation": "src/o1_crypto_lab/o1c104_page20_causal_rollover_prepare.py",
    "page20_causal_rollover_preparation_tests": "tests/test_o1c104_page20_causal_rollover_prepare.py",
    "inherited_page19_causal_rollover_preparation": "src/o1_crypto_lab/o1c102_page19_causal_rollover_prepare.py",
    "inherited_page19_causal_rollover_preparation_tests": "tests/test_o1c102_page19_causal_rollover_prepare.py",
    "causal_rollover_preparation": "src/o1_crypto_lab/o1c83_apple8_causal_rollover_prepare.py",
    "parent_preparation": "src/o1_crypto_lab/o1c82_apple8_parent_centered_prepare.py",
    "seed_compiler": "src/o1_crypto_lab/o1c82_parent_centered_seed.py",
    "causal_attic": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency": "src/o1_crypto_lab/causal_residency_v1.py",
    "threshold_vault": "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
    "public_verifier": "src/o1_crypto_lab/o1c73_apple8_vault_release_contrast_run.py",
    "native_v31": "native/cadical_o1_joint_score_sieve_v31.cpp",
    "native_v31_tests": "tests/test_cadical_o1_joint_score_sieve_v31.py",
    "priority_header": "native/o1c82_parent_centered_priority.hpp",
    "native_v18": "native/cadical_o1_joint_score_sieve_v18.cpp",
    "ownership_header": "native/o1c80_decision_ownership.hpp",
    "bounded_ownership_header": "native/o1c101_bounded_decision_ownership.hpp",
    "bound_header": "native/o1c80_one_bit_bound.hpp",
    "native_v16": "native/cadical_o1_joint_score_sieve_v16.cpp",
    "native_v15": "native/cadical_o1_joint_score_sieve_v15.cpp",
    "native_v14": "native/cadical_o1_joint_score_sieve_v14.cpp",
    "native_v12": "native/cadical_o1_joint_score_sieve_v12.cpp",
    "native_v11": "native/cadical_o1_joint_score_sieve_v11.cpp",
    "native_v6": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "native_base": "native/cadical_o1_joint_score_sieve.cpp",
}
NATIVE_CLOSURE_NAMES = (
    "native_v31",
    "priority_header",
    "native_v18",
    "ownership_header",
    "bounded_ownership_header",
    "bound_header",
    "native_v16",
    "native_v15",
    "native_v14",
    "native_v12",
    "native_v11",
    "native_v6",
    "native_base",
)
NATIVE_ARCHIVE_NAMES = (
    "native-result.json",
    "adapter-memory.json",
    "priority-seed.json",
    "priority-state.json",
    "priority-actions.json",
    "decision-ownership.json",
    "base-sieve.json",
    "vault.json",
    "resources.json",
    FINAL_BANK_NAME,
)
COMPILER_FLAGS = (
    "-std=c++17",
    "-O2",
    "-DNDEBUG",
    "-Wall",
    "-Wextra",
    "-Werror",
)


class O1C105RunError(RuntimeError):
    """A frozen input, burn ledger, native result, or capsule seal differs."""


AdapterRun = Callable[..., object]


@dataclass(frozen=True)
class PublishedPreparation:
    manifest: Mapping[str, object]
    artifacts: Mapping[str, bytes]
    artifact_rows: Mapping[str, Mapping[str, object]]
    globally_known_clause_sha256: frozenset[str]


@dataclass(frozen=True)
class PreflightBundle:
    config: Mapping[str, object]
    row: Mapping[str, object]
    prepared: PublishedPreparation
    priority_receipt: bytes
    inherited_derived_receipt: bytes
    inherited_derived_closure: bytes
    inherited_derived_overlay: bytes
    new_derived_receipt: bytes
    new_derived_closure: bytes
    new_derived_overlay: bytes


@dataclass(frozen=True)
class NativeEvidence:
    raw: Mapping[str, object]
    stdout: bytes
    adapter_memory: Mapping[str, object]
    priority_seed: Mapping[str, object]
    priority_state: Mapping[str, object]
    priority_actions: Mapping[str, object]
    ownership: Mapping[str, object]
    base_sieve: Mapping[str, object]
    vault: Mapping[str, object]
    resources: Mapping[str, object]
    stats: Mapping[str, object]
    status: int
    key_model: bytes | None
    final_bank: bytes


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(k, str) for k in value):
        raise O1C105RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C105RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C105RunError(f"{field} differs")
    return value


def _positive(value: object, field: str) -> int:
    result = _nonnegative(value, field)
    if not result:
        raise O1C105RunError(f"{field} differs")
    return result


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C105RunError(f"{field} differs")
    return value


def _relative_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C105RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C105RunError(f"{field} escapes the lab")
    return path.as_posix()


def _lab_path(
    root: Path, value: object, field: str, *, directory: bool = False
) -> Path:
    relative = Path(_relative_text(value, field))
    candidate = root / relative
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C105RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected
        or not resolved.is_relative_to(root)
    ):
        raise O1C105RunError(f"{field} is not a canonical lab path")
    return resolved


def _external_path(value: object, field: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise O1C105RunError(f"{field} is not absolute")
    candidate = Path(value)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C105RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected:
        raise O1C105RunError(f"{field} is not canonical")
    return resolved


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_canonical_json(path: Path, field: str) -> Mapping[str, object]:
    payload = path.read_bytes()
    try:
        value = _mapping(json.loads(payload), field)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C105RunError(f"{field} is not JSON") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C105RunError(f"{field} is not canonical JSON")
    return value


def _atomic_create(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    if not isinstance(payload, bytes):
        raise O1C105RunError("atomic payload differs")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != payload:
            raise O1C105RunError(f"atomic write verification failed for {path.name}")
        path.chmod(mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise O1C105RunError(f"artifact already exists: {path.name}") from exc


def _atomic_json(path: Path, value: object, *, mode: int = 0o444) -> None:
    _atomic_create(path, canonical_json_bytes(value), mode=mode)


def _remove_private_stage(path: Path) -> None:
    """Make our unpublished read-only snapshot removable, then delete it."""

    if not path.exists():
        return
    for candidate in sorted(path.rglob("*"), reverse=True):
        try:
            metadata = candidate.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                candidate.chmod(0o700)
            elif stat.S_ISREG(metadata.st_mode):
                candidate.chmod(0o600)
        except OSError:
            continue
    path.chmod(0o700)
    shutil.rmtree(path)


def _artifact_row(path: Path, *, relative_to: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(relative_to).as_posix(),
        "serialized_bytes": path.stat().st_size,
        "sha256": _sha_file(path),
    }


def _pending(value: object, prefix: str = "config") -> tuple[str, ...]:
    found: list[str] = []
    if value == "PENDING":
        found.append(prefix)
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            found.extend(_pending(nested, f"{prefix}.{key}"))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            found.extend(_pending(nested, f"{prefix}[{index}]"))
    return tuple(found)


def load_config(path: str | Path, *, root: Path | None = None) -> dict[str, object]:
    """Load and structurally freeze the canonical production contract."""

    lab = (root or lab_root()).resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(lab) or config_path.is_symlink():
        raise O1C105RunError("config escapes the lab")
    config = dict(_read_canonical_json(config_path, "O1C105 config"))
    if _pending(config):
        raise O1C105RunError("config contains PENDING: " + ", ".join(_pending(config)))
    if (
        set(config)
        != {
            "schema",
            "attempt_id",
            "parent",
            "preparation",
            "inputs",
            "native",
            "source",
            "budgets",
            "next_action",
        }
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or not isinstance(config.get("next_action"), str)
        or not config["next_action"]
    ):
        raise O1C105RunError("config fields differ")

    parent = _mapping(config["parent"], "config parent")
    if (
        set(parent) != {"capsule", "capsule_manifest_sha256", "result", "result_sha256"}
        or _relative_text(parent.get("capsule"), "parent capsule")
        != DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix()
        or _relative_text(parent.get("result"), "parent result")
        != DEFAULT_PARENT_RESULT_RELATIVE.as_posix()
        or parent.get("capsule_manifest_sha256") != PARENT_CAPSULE_MANIFEST_SHA256
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
    ):
        raise O1C105RunError("frozen O1C103 parent differs")

    preparation = _mapping(config["preparation"], "config preparation")
    if (
        set(preparation)
        != {
            "published_directory",
            "manifest",
            "manifest_sha256",
            "manifest_bytes",
            "priority_state_receipt",
            "priority_state_receipt_sha256",
            "priority_state_receipt_bytes",
            "inherited_derived_resolution_receipt",
            "inherited_derived_resolution_receipt_sha256",
            "inherited_derived_resolution_receipt_bytes",
            "inherited_derived_resolution_closure",
            "inherited_derived_resolution_closure_sha256",
            "inherited_derived_resolution_closure_bytes",
            "inherited_derived_resolution_overlay",
            "inherited_derived_resolution_overlay_sha256",
            "inherited_derived_resolution_overlay_bytes",
            "new_derived_resolution_receipt",
            "new_derived_resolution_receipt_sha256",
            "new_derived_resolution_receipt_bytes",
            "new_derived_resolution_closure",
            "new_derived_resolution_closure_sha256",
            "new_derived_resolution_closure_bytes",
            "new_derived_resolution_overlay",
            "new_derived_resolution_overlay_sha256",
            "new_derived_resolution_overlay_bytes",
            "candidate_order_sha256",
        }
        or _relative_text(
            preparation.get("published_directory"), "published preparation"
        )
        != PUBLISHED_PREPARATION_RELATIVE.as_posix()
        or _relative_text(preparation.get("manifest"), "preparation manifest")
        != (PUBLISHED_PREPARATION_RELATIVE / PREPARATION_MANIFEST_NAME).as_posix()
        or preparation.get("manifest_sha256") != PUBLISHED_MANIFEST_SHA256
        or preparation.get("manifest_bytes") != PUBLISHED_MANIFEST_BYTES
        or _relative_text(
            preparation.get("priority_state_receipt"), "priority state receipt"
        )
        != PRIORITY_RECEIPT_RELATIVE.as_posix()
        or preparation.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or preparation.get("priority_state_receipt_bytes") != PRIORITY_RECEIPT_BYTES
        or _relative_text(
            preparation.get("inherited_derived_resolution_receipt"),
            "inherited derived resolution receipt",
        )
        != INHERITED_DERIVED_RECEIPT_RELATIVE.as_posix()
        or preparation.get("inherited_derived_resolution_receipt_sha256")
        != INHERITED_DERIVED_RECEIPT_SHA256
        or preparation.get("inherited_derived_resolution_receipt_bytes")
        != INHERITED_DERIVED_RECEIPT_BYTES
        or _relative_text(
            preparation.get("inherited_derived_resolution_closure"),
            "inherited derived resolution closure",
        )
        != INHERITED_DERIVED_CLOSURE_RELATIVE.as_posix()
        or preparation.get("inherited_derived_resolution_closure_sha256")
        != INHERITED_DERIVED_CLOSURE_SHA256
        or preparation.get("inherited_derived_resolution_closure_bytes")
        != INHERITED_DERIVED_CLOSURE_BYTES
        or _relative_text(
            preparation.get("inherited_derived_resolution_overlay"),
            "inherited derived resolution overlay",
        )
        != INHERITED_DERIVED_OVERLAY_RELATIVE.as_posix()
        or preparation.get("inherited_derived_resolution_overlay_sha256")
        != INHERITED_DERIVED_OVERLAY_SHA256
        or preparation.get("inherited_derived_resolution_overlay_bytes")
        != INHERITED_DERIVED_OVERLAY_BYTES
        or _relative_text(
            preparation.get("new_derived_resolution_receipt"),
            "new derived resolution receipt",
        )
        != DERIVED_RECEIPT_RELATIVE.as_posix()
        or preparation.get("new_derived_resolution_receipt_sha256")
        != DERIVED_RECEIPT_SHA256
        or preparation.get("new_derived_resolution_receipt_bytes")
        != DERIVED_RECEIPT_BYTES
        or _relative_text(
            preparation.get("new_derived_resolution_closure"),
            "new derived resolution closure",
        )
        != DERIVED_CLOSURE_RELATIVE.as_posix()
        or preparation.get("new_derived_resolution_closure_sha256")
        != DERIVED_CLOSURE_SHA256
        or preparation.get("new_derived_resolution_closure_bytes")
        != DERIVED_CLOSURE_BYTES
        or _relative_text(
            preparation.get("new_derived_resolution_overlay"),
            "new derived resolution overlay",
        )
        != DERIVED_OVERLAY_RELATIVE.as_posix()
        or preparation.get("new_derived_resolution_overlay_sha256")
        != DERIVED_OVERLAY_SHA256
        or preparation.get("new_derived_resolution_overlay_bytes")
        != DERIVED_OVERLAY_BYTES
        or preparation.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C105RunError("frozen preparation source differs")

    inputs = _mapping(config["inputs"], "config inputs")
    if set(inputs) != {
        "cnf",
        "cnf_sha256",
        "potential",
        "potential_sha256",
        "grouping",
        "grouping_sha256",
        "o1c73_config",
        "o1c73_config_sha256",
    }:
        raise O1C105RunError("input fields differ")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        _relative_text(inputs.get(name), f"input {name}")
        _sha(inputs.get(f"{name}_sha256"), f"input {name} digest")

    native = _mapping(config["native"], "config native")
    if set(native) != {
        "source",
        "source_sha256",
        "compiler",
        "compiler_flags",
        "cadical_include",
        "cadical_library",
        "cadical_library_sha256",
        "adapter_schema",
        "result_schema",
        "page20_sha256",
        "page20_bytes",
        "continuation_bank_sha256",
        "continuation_bank_bytes",
        "candidate_order_sha256",
    }:
        raise O1C105RunError("native config fields differ")
    flags = tuple(_sequence(native.get("compiler_flags"), "compiler flags"))
    if (
        _relative_text(native.get("source"), "native source")
        != SOURCE_PATHS["native_v31"]
        or native.get("source_sha256")
        != _sha(native.get("source_sha256"), "native source digest")
        or flags != COMPILER_FLAGS
        or not all(isinstance(flag, str) for flag in flags)
        or native.get("cadical_library_sha256")
        != _sha(native.get("cadical_library_sha256"), "CaDiCaL library digest")
        or native.get("adapter_schema") != _native_v34.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema") != _native_v34.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("page20_sha256") != PAGE20_SHA256
        or native.get("page20_bytes") != PAGE20_SERIALIZED_BYTES
        or native.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or native.get("continuation_bank_bytes") != CONTINUATION_BANK_BYTES
        or native.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C105RunError("frozen native contract differs")
    if (
        not isinstance(native.get("compiler"), str)
        or not Path(cast(str, native["compiler"])).is_absolute()
    ):
        raise O1C105RunError("compiler path differs")
    if (
        not isinstance(native.get("cadical_include"), str)
        or not Path(cast(str, native["cadical_include"])).is_absolute()
    ):
        raise O1C105RunError("CaDiCaL include path differs")
    if (
        not isinstance(native.get("cadical_library"), str)
        or not Path(cast(str, native["cadical_library"])).is_absolute()
    ):
        raise O1C105RunError("CaDiCaL library path differs")

    source = _mapping(config["source"], "config source")
    if set(source) != {"paths", "expected_sha256"}:
        raise O1C105RunError("source config fields differ")
    paths = _mapping(source["paths"], "source paths")
    digests = _mapping(source["expected_sha256"], "source digests")
    if dict(paths) != SOURCE_PATHS or set(digests) != set(SOURCE_PATHS):
        raise O1C105RunError("source inventory differs")
    for name in SOURCE_PATHS:
        _sha(digests.get(name), f"source {name} digest")

    budgets = _mapping(config["budgets"], "config budgets")
    expected_budgets: dict[str, object] = {
        "required_system": "Darwin",
        "required_machine": "arm64",
        "lineage_call_ordinals": [LINEAGE_CALL_ORDINAL],
        "local_episode_ordinals": [LOCAL_EPISODE_ORDINAL],
        "seed": SEED,
        "threshold": THRESHOLD,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_CALLS,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "minimum_available_memory_bytes": MEMORY_LIMIT_BYTES,
        "minimum_disk_free_bytes": MINIMUM_DISK_FREE_BYTES,
        "maximum_persistent_artifact_bytes": MAXIMUM_PERSISTENT_ARTIFACT_BYTES,
        "maximum_fresh_targets": 0,
        "maximum_fresh_reveal_calls": 0,
        "maximum_refits": 0,
        "maximum_mps_calls": 0,
        "maximum_gpu_calls": 0,
        "retry_authorized": False,
        "replay_authorized": False,
    }
    if dict(budgets) != expected_budgets:
        raise O1C105RunError("budgets differ")
    return config


def _available_memory_bytes() -> int | None:
    try:
        output = subprocess.run(
            ["vm_stat"], check=True, capture_output=True, text=True
        ).stdout
        page_size = 4096
        first = output.splitlines()[0]
        if "page size of" in first:
            page_size = int(first.split("page size of", 1)[1].split("bytes", 1)[0])
        free_pages = sum(
            int(line.rsplit(":", 1)[1].strip().rstrip("."))
            for line in output.splitlines()[1:]
            if line.startswith(("Pages free", "Pages inactive", "Pages speculative"))
        )
        return page_size * free_pages
    except (OSError, ValueError, subprocess.SubprocessError, IndexError):
        return None


def _physical_memory_bytes() -> int | None:
    try:
        return int(
            subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _sibling_solver_pids() -> tuple[int, ...]:
    try:
        output = subprocess.run(
            ["ps", "-axo", "pid=,args="], check=True, capture_output=True, text=True
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C105RunError("solver process census failed") from exc
    current = os.getpid()
    found: list[int] = []
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            pid = int(fields[0])
            argv = shlex.split(fields[1])
        except (ValueError, IndexError):
            continue
        if (
            pid != current
            and argv
            and (
                Path(argv[0]).name == NATIVE_EXECUTABLE_NAME
                or Path(argv[0]).name.startswith("cadical_o1_joint_score_sieve")
            )
        ):
            found.append(pid)
    return tuple(sorted(found))


def _default_system_probe(root: Path) -> Mapping[str, object]:
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "physical_memory_bytes": _physical_memory_bytes(),
        "available_memory_bytes": _available_memory_bytes(),
        "disk_free_bytes": shutil.disk_usage(root).free,
        "sibling_solver_pids": list(_sibling_solver_pids()),
    }


def _validate_priority_receipt(payload: bytes, bank: bytes) -> Mapping[str, object]:
    try:
        receipt = _mapping(json.loads(payload), "priority state receipt")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C105RunError("priority state receipt is not JSON") from exc
    if canonical_json_bytes(receipt) != payload:
        raise O1C105RunError("priority state receipt is not canonical JSON")
    hexadecimal = receipt.get("bank_hex")
    try:
        receipt_bank = bytes.fromhex(cast(str, hexadecimal))
    except (TypeError, ValueError) as exc:
        raise O1C105RunError("priority state receipt bank differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c103-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("bank_bytes") != CONTINUATION_BANK_BYTES
        or receipt.get("current_bank_sha256") != CONTINUATION_BANK_SHA256
        or receipt_bank != bank
    ):
        raise O1C105RunError("priority state receipt contract differs")
    return receipt


def _canonical_payload(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), field)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C105RunError(f"{field} is not JSON") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C105RunError(f"{field} is not canonical JSON")
    return value


def _validate_occurrence_ledger(payload: bytes) -> frozenset[str]:
    document = _canonical_payload(payload, "published occurrence ledger")
    records = _sequence(document.get("records"), "published occurrence records")
    if (
        document.get("schema") != "o1-score-threshold-causal-occurrences-v1"
        or document.get("occurrence_count") != ATTIC_OCCURRENCE_COUNT
        or document.get("unique_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or document.get("duplicate_occurrence_count")
        != ATTIC_OCCURRENCE_COUNT - ATTIC_UNION_CLAUSE_COUNT
        or len(records) != ATTIC_OCCURRENCE_COUNT
    ):
        raise O1C105RunError("published occurrence ledger contract differs")
    by_index: dict[int, str] = {}
    expected_fields = {
        "classification",
        "clause_sha256",
        "ordinal",
        "source",
        "source_index",
        "stream_id",
        "union_clause_index",
        "witness_score_f64le_hex",
        "witness_sha256",
    }
    for ordinal, value in enumerate(records):
        row = _mapping(value, "published occurrence record")
        union_index = _nonnegative(
            row.get("union_clause_index"), "published occurrence union index"
        )
        digest = _sha(row.get("clause_sha256"), "published occurrence clause")
        if (
            set(row) != expected_fields
            or row.get("ordinal") != ordinal
            or union_index >= ATTIC_UNION_CLAUSE_COUNT
            or (union_index in by_index and by_index[union_index] != digest)
        ):
            raise O1C105RunError("published occurrence record differs")
        by_index[union_index] = digest
    ordered = [by_index[index] for index in range(ATTIC_UNION_CLAUSE_COUNT)]
    digests = frozenset(ordered)
    if (
        set(by_index) != set(range(ATTIC_UNION_CLAUSE_COUNT))
        or len(digests) != ATTIC_UNION_CLAUSE_COUNT
        or sha256_bytes(canonical_json_bytes(ordered))
        != EMITTED_KNOWN_INVENTORY_SHA256
    ):
        raise O1C105RunError("published attic union digest inventory differs")
    return digests


def _validate_logical_known_inventory(
    artifacts: Mapping[str, bytes], emitted: frozenset[str]
) -> frozenset[str]:
    receipt = _canonical_payload(
        artifacts[DERIVED_RECEIPT_NAME], "published derived resolution receipt"
    )
    registry = _mapping(
        receipt.get("logical_known_registry"), "published logical known registry"
    )
    emitted_row = _mapping(registry.get("emitted"), "published emitted registry")
    inherited_row = _mapping(
        registry.get("inherited_derived"), "published inherited derived registry"
    )
    new_row = _mapping(registry.get("new_derived"), "published new derived registry")
    combined_row = _mapping(registry.get("combined"), "published combined registry")
    emitted_order = [
        _sha(value, "published emitted inventory digest")
        for value in _sequence(
            emitted_row.get("clause_sha256"), "published emitted inventory"
        )
    ]
    inherited_order = [
        _sha(value, "published inherited derived inventory digest")
        for value in _sequence(
            inherited_row.get("clause_sha256"),
            "published inherited derived inventory",
        )
    ]
    new_order = [
        _sha(value, "published new derived inventory digest")
        for value in _sequence(
            new_row.get("clause_sha256"), "published new derived inventory"
        )
    ]
    combined_order = [
        _sha(value, "published combined inventory digest")
        for value in _sequence(
            combined_row.get("clause_sha256"), "published combined inventory"
        )
    ]
    logical = frozenset(combined_order)
    if (
        len(emitted_order) != ATTIC_UNION_CLAUSE_COUNT
        or frozenset(emitted_order) != emitted
        or len(inherited_order) != 5
        or len(set(inherited_order)) != 5
        or len(new_order) != 84
        or len(set(new_order)) != 84
        or set(emitted_order).intersection(inherited_order)
        or set(emitted_order).intersection(new_order)
        or set(inherited_order).intersection(new_order)
        or combined_order
        != (
            emitted_order[: _o1c102.ATTIC_UNION_CLAUSE_COUNT]
            + inherited_order
            + emitted_order[_o1c102.ATTIC_UNION_CLAUSE_COUNT :]
            + new_order
        )
        or len(logical) != LOGICAL_KNOWN_CLAUSE_COUNT
        or emitted_row.get("inventory_sha256") != EMITTED_KNOWN_INVENTORY_SHA256
        or inherited_row.get("inventory_sha256")
        != _o1c104.INHERITED_DERIVED_INVENTORY_SHA256
        or new_row.get("inventory_sha256") != DERIVED_KNOWN_INVENTORY_SHA256
        or combined_row.get("inventory_sha256") != COMBINED_KNOWN_INVENTORY_SHA256
        or sha256_bytes(canonical_json_bytes(emitted_order))
        != EMITTED_KNOWN_INVENTORY_SHA256
        or sha256_bytes(canonical_json_bytes(inherited_order))
        != _o1c104.INHERITED_DERIVED_INVENTORY_SHA256
        or sha256_bytes(canonical_json_bytes(new_order))
        != DERIVED_KNOWN_INVENTORY_SHA256
        or sha256_bytes(canonical_json_bytes(combined_order))
        != COMBINED_KNOWN_INVENTORY_SHA256
        or combined_row.get("next_global_novelty_baseline_clause_count")
        != LOGICAL_KNOWN_CLAUSE_COUNT
    ):
        raise O1C105RunError("published logical known inventory differs")
    return logical


def _validate_published_documents(artifacts: Mapping[str, bytes]) -> frozenset[str]:
    activation = _canonical_payload(
        artifacts[ACTIVATION_LEDGER_NAME], "published composed activation ledger"
    )
    residency = _canonical_payload(
        artifacts[RESIDENCY_NAME], "published composed residency"
    )
    relations = _canonical_payload(artifacts[RELATIONS_NAME], "published relations")
    audit = _canonical_payload(
        artifacts[COMMON_CORE_AUDIT_NAME], "published common-core audit"
    )
    composed_entries = _sequence(
        activation.get("composed_entries"), "published composed activation entries"
    )
    final_activation = _mapping(
        composed_entries[-1] if composed_entries else None,
        "published final composed activation",
    )
    used = _sequence(
        activation.get("used_active_sha256"), "published used active identities"
    )
    projection = _mapping(
        residency.get("current_projection"), "published Page20 projection"
    )
    projection_encoding = _mapping(
        projection.get("encoding_only"), "published Page20 encoding"
    )
    logical = _mapping(
        residency.get("logical_known_registry"), "published logical registry"
    )
    emitted = _mapping(
        residency.get("emitted_causal_attic"), "published emitted attic"
    )
    emitted_union = _mapping(emitted.get("union"), "published emitted attic union")
    emitted_active = _mapping(
        emitted.get("active_projection"), "published emitted-only active projection"
    )
    emitted_active_encoding = _mapping(
        emitted_active.get("encoding_only"),
        "published emitted-only active projection encoding",
    )
    emitted_selector = _mapping(
        residency.get("emitted_selector_candidate"),
        "published pure-emitted selector candidate",
    )
    emitted_selector_encoding = _mapping(
        emitted_selector.get("encoding_only"),
        "published pure-emitted selector encoding",
    )
    residency_activation = _mapping(
        residency.get("activation_ledger"), "published residency activation ledger"
    )
    if (
        activation.get("schema") != "o1-score-threshold-composed-activation-ledger-v2"
        or activation.get("forbidden_nonactivated_candidate_sha256")
        != PURE_EMITTED_CANDIDATE_SHA256
        or len(composed_entries) != 1
        or len(used) != ATTIC_CHUNK_COUNT
        or used[-1] != PAGE20_SHA256
        or final_activation.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or final_activation.get("active_sha256") != PAGE20_SHA256
        or len(
            _sequence(
                final_activation.get("selected_inherited_derived_clauses"),
                "selected inherited derived clauses",
            )
        )
        != 3
        or len(
            _sequence(
                final_activation.get("selected_new_derived_clauses"),
                "selected new derived clauses",
            )
        )
        != 52
        or len(
            _sequence(
                final_activation.get("selected_emitted_union_indices"),
                "selected emitted clauses",
            )
        )
        != 192
        or residency.get("schema") != "o1-score-threshold-composed-residency-v2"
        or residency.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or residency.get("active_limit") != PAGE20_ACTIVE_LIMIT
        or projection.get("category_counts") != PAGE20_CATEGORY_COUNTS
        or projection_encoding.get("sha256") != PAGE20_SHA256
        or projection_encoding.get("clause_count") != PAGE20_CLAUSE_COUNT
        or projection_encoding.get("literal_count") != PAGE20_LITERAL_COUNT
        or projection_encoding.get("serialized_bytes") != PAGE20_SERIALIZED_BYTES
        or len(_sequence(emitted.get("chunks"), "published emitted chunks"))
        != ATTIC_CHUNK_COUNT
        or emitted_union.get("clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or emitted_active_encoding.get("sha256")
        != EMITTED_ONLY_ACTIVE_PROJECTION_SHA256
        or emitted_active_encoding.get("sha256") == PAGE20_SHA256
        or emitted_selector_encoding.get("sha256")
        != PURE_EMITTED_CANDIDATE_SHA256
        or emitted_selector.get("activated") is not False
        or residency_activation.get("forbidden_nonactivated_candidate_sha256")
        != PURE_EMITTED_CANDIDATE_SHA256
        or logical.get("combined_clause_count") != LOGICAL_KNOWN_CLAUSE_COUNT
        or logical.get("emitted_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or logical.get("inherited_derived_clause_count") != 5
        or logical.get("new_derived_clause_count") != 84
        or logical.get("combined_inventory_sha256")
        != COMBINED_KNOWN_INVENTORY_SHA256
        or logical.get("combined_encoding_sha256") != LOGICAL_KNOWN_SHA256
        or relations.get("schema") != "o1-score-threshold-causal-relations-v1"
        or relations.get("strict_subsumption_pair_count")
        != ATTIC_SUBSUMPTION_RELATION_COUNT
        or relations.get("undominated_clause_count") != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or audit.get("schema") != "o1-256-o1c83-common-signed-intersection-audit-v1"
    ):
        raise O1C105RunError("published composed Page20 residency contract differs")
    _validate_priority_receipt(
        artifacts[RECEIPT_NAME], artifacts[CONTINUATION_BANK_NAME]
    )
    _native_v34._validate_inherited_derived_receipt(
        artifacts[INHERITED_DERIVED_RECEIPT_NAME]
    )
    _native_v34._validate_new_derived_receipt(artifacts[DERIVED_RECEIPT_NAME])
    emitted_known = _validate_occurrence_ledger(artifacts[OCCURRENCES_NAME])
    return _validate_logical_known_inventory(artifacts, emitted_known)


def _validate_native_capacity_proof(value: object) -> Mapping[str, object]:
    """Derive and verify the exact Page-20 native-capacity proof before intent."""

    page = _mapping(value, "published Page-20 capacity source")
    expected_caps = {
        "maximum_clauses": 512,
        "maximum_literals": 1_600_000,
        "maximum_serialized_bytes": 8_388_608,
    }
    headroom = _mapping(page.get("headroom"), "published Page-20 headroom")
    input_clauses = _nonnegative(page.get("clause_count"), "Page-20 input clauses")
    additional = _nonnegative(headroom.get("clauses"), "Page-20 clause headroom")
    if (
        O1C66_VAULT_CAPS.describe() != expected_caps
        or input_clauses != PAGE20_CLAUSE_COUNT
        or additional != PAGE20_HEADROOM["clauses"]
        or dict(headroom) != PAGE20_HEADROOM
        or input_clauses + additional != expected_caps["maximum_clauses"]
        or additional < PARENT_CENTERED_ACTION_CAPACITY
    ):
        raise O1C105RunError("published Page-20 native capacity proof differs")
    proof: dict[str, object] = {
        "caps": expected_caps,
        "clause_headroom_guarantee": {
            "native_vault_maximum_clauses": expected_caps["maximum_clauses"],
            "page20_input_clauses": input_clauses,
            "maximum_additional_clauses_before_capacity_terminal": additional,
            "parent_centered_action_capacity": PARENT_CENTERED_ACTION_CAPACITY,
            "spare_clause_slots_beyond_action_capacity": (
                additional - PARENT_CENTERED_ACTION_CAPACITY
            ),
            "proved_sufficient": True,
        },
        "recorded_residual_headroom": {
            "literals": PAGE20_HEADROOM["literals"],
            "serialized_bytes": PAGE20_HEADROOM["serialized_bytes"],
        },
        "literal_future_emission_safety_claimed": False,
        "serialized_byte_future_emission_safety_claimed": False,
    }
    return proof


def _disabled_o1c96_published_manifest_validator(
    manifest: Mapping[str, object], artifacts: Mapping[str, bytes]
) -> tuple[dict[str, Mapping[str, object]], frozenset[str]]:
    """Historical O1C96 validator retained as inert provenance.
    if (
        set(manifest)
        != {
            "schema",
            "attempt_id",
            "zero_call",
            "authorization",
            "parent",
            "science_boundary",
            "transport_recovery",
            "attic",
            "page20",
            "final_priority_bank",
            "artifacts",
        }
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != "O1C-0098"
    ):
        raise O1C105RunError("published preparation manifest identity differs")
    zero_call = _mapping(manifest.get("zero_call"), "published zero-call boundary")
    authorization = _mapping(
        manifest.get("authorization"), "published authorization boundary"
    )
    parent = _mapping(manifest.get("parent"), "published preparation parent")
    science_boundary = _mapping(
        manifest.get("science_boundary"), "published science boundary"
    )
    recovery = _mapping(
        manifest.get("transport_recovery"), "published transport recovery"
    )
    attic = _mapping(manifest.get("attic"), "published preparation attic")
    page20 = _mapping(manifest.get("page20"), "published Page-16")
    _validate_native_capacity_proof(page20)
    bank = _mapping(manifest.get("final_priority_bank"), "published continuation bank")
    if dict(zero_call) != {
        "native_preflight_calls": 0,
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    } or dict(authorization) != {
        "science_call_authorized": False,
        "intent_created": False,
        "lineage29_burned": False,
        "page20_burned": False,
        "page15_retry_or_replay_authorized": False,
        "lineage28_retry_or_replay_authorized": False,
        "historical_page_retry_or_replay_authorized": False,
    }:
        raise O1C105RunError("published zero-call authorization differs")
    if (
        parent.get("attempt_id") != "O1C-0095"
        or parent.get("capsule_manifest_sha256") != PARENT_CAPSULE_MANIFEST_SHA256
        or parent.get("capsule_entry_count") != PARENT_CAPSULE_ENTRY_COUNT
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("intent_sha256") != PARENT_INTENT_SHA256
        or parent.get("terminal_failure_sha256") != DERIVED_RECEIPT_SHA256
        or parent.get("classification") != OPERATIONAL_TERMINAL
        or parent.get("page15_burned") is not True
        or parent.get("lineage28_burned") is not True
        or parent.get("native_result_returned_to_runner") is not False
        or parent.get("science_gain") is not False
        or parent.get("state_update_available") is not False
    ):
        raise O1C105RunError("published parent boundary differs")
    if (
        dict(science_boundary)
        != {
            "imported_science_attempt_id": None,
            "imported_clause_count": 0,
            "imported_priority_state_update": False,
            "o1c95_terminal_failure_imported_as_science": False,
            "o1c95_native_json_imported": False,
            "o1c95_output_artifacts_imported": [],
        }
        or recovery.get("source_lineage_ordinal") != 28
        or recovery.get("next_lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or recovery.get("fully_emitted_event_count") != 0
        or recovery.get("new_chunk_count") != 0
        or recovery.get("attic_evidence_unchanged") is not True
        or recovery.get("continuation_bank_unchanged") is not True
        or recovery.get("priority_receipt_unchanged") is not True
        or attic.get("chunk_count") != ATTIC_CHUNK_COUNT
        or attic.get("union_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or attic.get("occurrence_count") != ATTIC_OCCURRENCE_COUNT
        or attic.get("strict_subsumption_pair_count")
        != ATTIC_SUBSUMPTION_RELATION_COUNT
        or attic.get("undominated_clause_count") != ATTIC_UNDOMINATED_CLAUSE_COUNT
    ):
        raise O1C105RunError("published rollover/attic boundary differs")
    if (
        page20.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or page20.get("active_limit") != PAGE20_ACTIVE_LIMIT
        or page20.get("active_sha256") != PAGE20_SHA256
        or page20.get("clause_count") != PAGE20_CLAUSE_COUNT
        or page20.get("literal_count") != PAGE20_LITERAL_COUNT
        or page20.get("serialized_bytes") != PAGE20_SERIALIZED_BYTES
        or page20.get("category_counts") != PAGE20_CATEGORY_COUNTS
        or page20.get("headroom") != PAGE20_HEADROOM
        or page20.get("fresh_identity") is not True
    ):
        raise O1C105RunError("published Page-16 seal differs")
    if (
        bank.get("sha256") != CONTINUATION_BANK_SHA256
        or bank.get("serialized_bytes") != CONTINUATION_BANK_BYTES
        or bank.get("priority_is_key_bit_belief") is not False
        or bank.get("semantic_role")
        != "unchanged-sealed-live-continuation-bytes"
        or bank.get("validation_contract")
        != "o1c92-live-continuation-bank-with-state-receipt"
        or bank.get("eligible_coordinate_count") != 255
        or bank.get("aggregate_evolved_count") != INPUT_BANK_TOTAL_COUNT
        or bank.get("maximum_evolved_count") != 2_675
        or bank.get("minimum_nonzero_evolved_count") != 227
        or bank.get("zero_coordinate_variables") != [MISSING_VARIABLE]
        or bank.get("receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or bank.get("receipt_serialized_bytes") != PRIORITY_RECEIPT_BYTES
        or bank.get("receipt_bank_hex_byte_equal") is not True
    ):
        raise O1C105RunError("published continuation bank seal differs")
    rows_raw = _mapping(manifest.get("artifacts"), "published artifact rows")
    if set(rows_raw) != set(PUBLISHED_ARTIFACT_SEALS):
        raise O1C105RunError("published artifact row inventory differs")
    rows: dict[str, Mapping[str, object]] = {}
    for name, (size, digest, role) in PUBLISHED_ARTIFACT_SEALS.items():
        row = _mapping(rows_raw.get(name), f"published artifact row {name}")
        payload = artifacts.get(name)
        if (
            dict(row) != {"role": role, "serialized_bytes": size, "sha256": digest}
            or not isinstance(payload, bytes)
            or len(payload) != size
            or sha256_bytes(payload) != digest
        ):
            raise O1C105RunError("published artifact seal differs")
        rows[name] = row
    known = _validate_published_documents(artifacts)
    return rows, known


    """
    del manifest, artifacts
    raise O1C105RunError("historical manifest validator is disabled")


def _validate_published_manifest(
    manifest: Mapping[str, object], artifacts: Mapping[str, bytes]
) -> tuple[dict[str, Mapping[str, object]], frozenset[str]]:
    """Validate exact O1C104 bundle and all 2,692 logical identities."""

    payload = canonical_json_bytes(manifest)
    _native_v34._validate_manifest(payload)
    page20 = _mapping(manifest.get("page20"), "published Page-20")
    logical = _mapping(
        manifest.get("logical_known_registry"), "published logical known registry"
    )
    namespaces = _mapping(
        manifest.get("derived_resolution_namespaces"),
        "published derived namespaces",
    )
    inherited = _mapping(namespaces.get("inherited"), "published inherited namespace")
    new = _mapping(namespaces.get("new"), "published new namespace")
    capacity = _validate_native_capacity_proof(page20)
    if (
        manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != "O1C-0104"
        or page20.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or page20.get("active_limit") != PAGE20_ACTIVE_LIMIT
        or page20.get("active_sha256") != PAGE20_SHA256
        or page20.get("clause_count") != PAGE20_CLAUSE_COUNT
        or page20.get("literal_count") != PAGE20_LITERAL_COUNT
        or page20.get("serialized_bytes") != PAGE20_SERIALIZED_BYTES
        or page20.get("category_counts") != PAGE20_CATEGORY_COUNTS
        or page20.get("headroom") != PAGE20_HEADROOM
        or page20.get("fresh_identity") is not True
        or capacity["clause_headroom_guarantee"]
        != {
            "native_vault_maximum_clauses": 512,
            "page20_input_clauses": 247,
            "maximum_additional_clauses_before_capacity_terminal": 265,
            "parent_centered_action_capacity": 256,
            "spare_clause_slots_beyond_action_capacity": 9,
            "proved_sufficient": True,
        }
        or logical.get("emitted_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or logical.get("inherited_derived_clause_count") != 5
        or logical.get("new_derived_clause_count") != 84
        or logical.get("combined_clause_count") != LOGICAL_KNOWN_CLAUSE_COUNT
        or logical.get("combined_encoding_sha256") != LOGICAL_KNOWN_SHA256
        or logical.get("combined_inventory_sha256")
        != COMBINED_KNOWN_INVENTORY_SHA256
        or logical.get("next_global_novelty_baseline_clause_count")
        != LOGICAL_KNOWN_CLAUSE_COUNT
        or inherited.get("receipt_sha256") != INHERITED_DERIVED_RECEIPT_SHA256
        or inherited.get("closure_sha256") != INHERITED_DERIVED_CLOSURE_SHA256
        or inherited.get("overlay_sha256") != INHERITED_DERIVED_OVERLAY_SHA256
        or new.get("receipt_sha256") != DERIVED_RECEIPT_SHA256
        or new.get("closure_sha256") != DERIVED_CLOSURE_SHA256
        or new.get("overlay_sha256") != DERIVED_OVERLAY_SHA256
        or namespaces.get("combined_overlay_materialized") is not False
    ):
        raise O1C105RunError("published O1C104 Page-20 boundary differs")

    rows_raw = _mapping(manifest.get("artifacts"), "published artifact rows")
    if (
        set(rows_raw) != set(PUBLISHED_ARTIFACT_SEALS)
        or set(artifacts) != PREPARATION_ARTIFACT_NAMES
        or PREPARATION_MANIFEST_NAME not in artifacts
    ):
        raise O1C105RunError("published artifact row inventory differs")
    rows: dict[str, Mapping[str, object]] = {}
    for name, (size, digest, role) in PUBLISHED_ARTIFACT_SEALS.items():
        row = _mapping(rows_raw.get(name), f"published artifact row {name}")
        artifact = artifacts.get(name)
        if (
            dict(row) != {"role": role, "serialized_bytes": size, "sha256": digest}
            or not isinstance(artifact, bytes)
            or len(artifact) != size
            or sha256_bytes(artifact) != digest
        ):
            raise O1C105RunError("published artifact seal differs")
        rows[name] = row
    _native_v34._validate_inherited_derived_receipt(
        artifacts[INHERITED_DERIVED_RECEIPT_NAME]
    )
    _native_v34._validate_new_derived_receipt(artifacts[DERIVED_RECEIPT_NAME])
    known = _validate_published_documents(artifacts)
    return rows, known


def _load_published_preparation(
    directory: Path, manifest_path: Path
) -> PublishedPreparation:
    try:
        children = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    except OSError as exc:
        raise O1C105RunError("published preparation inventory is unreadable") from exc
    if (
        manifest_path != directory / PREPARATION_MANIFEST_NAME
        or {path.name for path in children} != PREPARATION_ARTIFACT_NAMES
    ):
        raise O1C105RunError("published preparation inventory differs")
    artifacts: dict[str, bytes] = {}
    for path in children:
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C105RunError(
                "published preparation artifact is unreadable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise O1C105RunError("published preparation artifact type differs")
        artifacts[path.name] = payload
    manifest_payload = artifacts[PREPARATION_MANIFEST_NAME]
    if (
        len(manifest_payload) != PUBLISHED_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PUBLISHED_MANIFEST_SHA256
    ):
        raise O1C105RunError("published preparation manifest seal differs")
    manifest = _canonical_payload(manifest_payload, "published preparation manifest")
    rows, known = _validate_published_manifest(manifest, artifacts)
    return PublishedPreparation(
        manifest=manifest,
        artifacts=artifacts,
        artifact_rows=rows,
        globally_known_clause_sha256=known,
    )


def _preflight_bundle(
    config_path: str | Path,
    *,
    root: Path,
    system_probe: Callable[[Path], Mapping[str, object]],
) -> PreflightBundle:
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file, root=root)
    parent = _mapping(config["parent"], "preflight parent")
    _lab_path(root, parent["capsule"], "parent capsule", directory=True)
    parent_result = _lab_path(root, parent["result"], "parent result")
    parent_manifest = _lab_path(
        root,
        (Path(cast(str, parent["capsule"])) / "artifacts.sha256").as_posix(),
        "parent capsule manifest",
    )
    if (
        _sha_file(parent_manifest) != parent["capsule_manifest_sha256"]
        or _sha_file(parent_result) != parent["result_sha256"]
    ):
        raise O1C105RunError("parent input SHA preflight differs")
    preparation = _mapping(config["preparation"], "preflight preparation")
    published_directory = _lab_path(
        root,
        preparation["published_directory"],
        "published preparation",
        directory=True,
    )
    published_manifest = _lab_path(
        root, preparation["manifest"], "published preparation manifest"
    )
    receipt_path = _lab_path(
        root, preparation["priority_state_receipt"], "priority state receipt"
    )
    inherited_receipt_path = _lab_path(
        root,
        preparation["inherited_derived_resolution_receipt"],
        "inherited derived resolution receipt",
    )
    inherited_closure_path = _lab_path(
        root,
        preparation["inherited_derived_resolution_closure"],
        "inherited derived resolution closure",
    )
    inherited_overlay_path = _lab_path(
        root,
        preparation["inherited_derived_resolution_overlay"],
        "inherited derived resolution overlay",
    )
    new_receipt_path = _lab_path(
        root,
        preparation["new_derived_resolution_receipt"],
        "new derived resolution receipt",
    )
    new_closure_path = _lab_path(
        root,
        preparation["new_derived_resolution_closure"],
        "new derived resolution closure",
    )
    new_overlay_path = _lab_path(
        root,
        preparation["new_derived_resolution_overlay"],
        "new derived resolution overlay",
    )
    if (
        published_manifest.parent != published_directory
        or published_manifest.stat().st_size != preparation["manifest_bytes"]
        or _sha_file(published_manifest) != preparation["manifest_sha256"]
        or receipt_path.stat().st_size != preparation["priority_state_receipt_bytes"]
        or _sha_file(receipt_path) != preparation["priority_state_receipt_sha256"]
        or inherited_receipt_path.stat().st_size
        != preparation["inherited_derived_resolution_receipt_bytes"]
        or _sha_file(inherited_receipt_path)
        != preparation["inherited_derived_resolution_receipt_sha256"]
        or inherited_closure_path.stat().st_size
        != preparation["inherited_derived_resolution_closure_bytes"]
        or _sha_file(inherited_closure_path)
        != preparation["inherited_derived_resolution_closure_sha256"]
        or inherited_overlay_path.stat().st_size
        != preparation["inherited_derived_resolution_overlay_bytes"]
        or _sha_file(inherited_overlay_path)
        != preparation["inherited_derived_resolution_overlay_sha256"]
        or new_receipt_path.stat().st_size
        != preparation["new_derived_resolution_receipt_bytes"]
        or _sha_file(new_receipt_path)
        != preparation["new_derived_resolution_receipt_sha256"]
        or new_closure_path.stat().st_size
        != preparation["new_derived_resolution_closure_bytes"]
        or _sha_file(new_closure_path)
        != preparation["new_derived_resolution_closure_sha256"]
        or new_overlay_path.stat().st_size
        != preparation["new_derived_resolution_overlay_bytes"]
        or _sha_file(new_overlay_path)
        != preparation["new_derived_resolution_overlay_sha256"]
    ):
        raise O1C105RunError("published preparation/receipt preflight differs")

    inputs = _mapping(config["inputs"], "preflight inputs")
    input_sha: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        candidate = _lab_path(root, inputs[name], f"input {name}")
        observed = _sha_file(candidate)
        if observed != inputs[f"{name}_sha256"]:
            raise O1C105RunError(f"input {name} SHA preflight differs")
        input_sha[name] = observed

    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "source paths")
    expected = _mapping(source["expected_sha256"], "source digests")
    source_sha: dict[str, str] = {}
    for name in SOURCE_PATHS:
        candidate = _lab_path(root, paths[name], f"source {name}")
        observed = _sha_file(candidate)
        if observed != expected[name]:
            raise O1C105RunError(f"source {name} SHA preflight differs")
        source_sha[name] = observed

    native = _mapping(config["native"], "preflight native")
    compiler = _external_path(native["compiler"], "compiler")
    include = _external_path(
        native["cadical_include"], "CaDiCaL include", directory=True
    )
    library = _external_path(native["cadical_library"], "CaDiCaL library")
    if (
        _sha_file(library) != native["cadical_library_sha256"]
        or source_sha["native_v31"] != native["source_sha256"]
    ):
        raise O1C105RunError("native toolchain/source SHA preflight differs")

    prepared = _load_published_preparation(published_directory, published_manifest)
    page20_manifest = _mapping(
        prepared.manifest.get("page20"), "published Page-20 preflight"
    )
    capacity_proof = _validate_native_capacity_proof(page20_manifest)
    prepared_rows = {
        name: {
            "serialized_bytes": len(payload),
            "sha256": sha256_bytes(payload),
        }
        for name, payload in sorted(prepared.artifacts.items())
    }
    receipt_payload = receipt_path.read_bytes()
    inherited_receipt_payload = inherited_receipt_path.read_bytes()
    inherited_closure_payload = inherited_closure_path.read_bytes()
    inherited_overlay_payload = inherited_overlay_path.read_bytes()
    new_receipt_payload = new_receipt_path.read_bytes()
    new_closure_payload = new_closure_path.read_bytes()
    new_overlay_payload = new_overlay_path.read_bytes()
    _validate_priority_receipt(
        receipt_payload, prepared.artifacts[CONTINUATION_BANK_NAME]
    )
    _native_v34._validate_inherited_derived_receipt(inherited_receipt_payload)
    _native_v34._validate_new_derived_receipt(new_receipt_payload)
    expected_derived_payloads = {
        INHERITED_DERIVED_RECEIPT_NAME: inherited_receipt_payload,
        INHERITED_DERIVED_CLOSURE_NAME: inherited_closure_payload,
        INHERITED_DERIVED_OVERLAY_NAME: inherited_overlay_payload,
        DERIVED_RECEIPT_NAME: new_receipt_payload,
        DERIVED_CLOSURE_NAME: new_closure_payload,
        DERIVED_OVERLAY_NAME: new_overlay_payload,
    }
    if any(
        payload != prepared.artifacts[name]
        for name, payload in expected_derived_payloads.items()
    ):
        raise O1C105RunError("derived namespace publication linkage differs")
    system = dict(system_probe(root))
    siblings = tuple(_sequence(system.get("sibling_solver_pids"), "sibling solvers"))
    physical = system.get("physical_memory_bytes")
    available = system.get("available_memory_bytes")
    disk = _nonnegative(system.get("disk_free_bytes"), "disk free bytes")
    if (
        system.get("system") != "Darwin"
        or system.get("machine") != "arm64"
        or siblings
        or physical is None
        or _positive(physical, "physical memory") < MEMORY_LIMIT_BYTES
        or available is None
        or _positive(available, "available memory") < MEMORY_LIMIT_BYTES
        or disk < MINIMUM_DISK_FREE_BYTES
    ):
        raise O1C105RunError("Darwin/arm64/RAM/disk/process preflight differs")
    row = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "passed": True,
        "config_sha256": _sha_file(config_file),
        "input_sha256": input_sha,
        "source_sha256": source_sha,
        "parent_result_sha256": _sha_file(parent_result),
        "parent_capsule_manifest_sha256": _sha_file(parent_manifest),
        "prepared_artifacts": prepared_rows,
        "published_preparation": {
            "path": published_directory.relative_to(root).as_posix(),
            "manifest_sha256": _sha_file(published_manifest),
            "manifest_bytes": published_manifest.stat().st_size,
            "all_artifact_seals_verified": True,
            "manifest_schema": prepared.manifest["schema"],
            "native_capacity_proof": dict(capacity_proof),
            "native_capacity_proof_verified_before_intent": True,
        },
        "page20_sha256": PAGE20_SHA256,
        "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "priority_state_receipt": {
            "serialized_bytes": len(receipt_payload),
            "sha256": _sha_file(receipt_path),
        },
        "inherited_derived_resolution_triplet": {
            "receipt": prepared_rows[INHERITED_DERIVED_RECEIPT_NAME],
            "closure": prepared_rows[INHERITED_DERIVED_CLOSURE_NAME],
            "overlay": prepared_rows[INHERITED_DERIVED_OVERLAY_NAME],
        },
        "new_derived_resolution_triplet": {
            "receipt": prepared_rows[DERIVED_RECEIPT_NAME],
            "closure": prepared_rows[DERIVED_CLOSURE_NAME],
            "overlay": prepared_rows[DERIVED_OVERLAY_NAME],
        },
        "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
        "global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        "compiler": str(compiler),
        "cadical_include": str(include),
        "cadical_library": str(library),
        "system": system,
        "native_solver_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
    }
    return PreflightBundle(
        config=config,
        row=row,
        prepared=prepared,
        priority_receipt=receipt_payload,
        inherited_derived_receipt=inherited_receipt_payload,
        inherited_derived_closure=inherited_closure_payload,
        inherited_derived_overlay=inherited_overlay_payload,
        new_derived_receipt=new_receipt_payload,
        new_derived_closure=new_closure_payload,
        new_derived_overlay=new_overlay_payload,
    )


def preflight(
    config_path: str | Path = CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    system_probe: Callable[[Path], Mapping[str, object]] = _default_system_probe,
) -> dict[str, object]:
    lab = (root or lab_root()).resolve(strict=True)
    return dict(_preflight_bundle(config_path, root=lab, system_probe=system_probe).row)


def _completed_bytes(value: object, field: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    raise O1C105RunError(f"{field} differs")


def _executable_identity(path: Path, *, relative_path: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C105RunError("native executable is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C105RunError("native executable type differs")
    size = path.stat().st_size
    if size <= 0:
        raise O1C105RunError("native executable is empty")
    return {
        "path": relative_path,
        "serialized_bytes": size,
        "sha256": _sha_file(path),
    }


def _require_executable_identity(
    path: Path, expected: Mapping[str, object], field: str
) -> None:
    expected_path = f"native/{NATIVE_EXECUTABLE_NAME}"
    if (
        set(expected) != {"path", "serialized_bytes", "sha256"}
        or expected.get("path") != expected_path
        or _positive(expected.get("serialized_bytes"), f"{field} bytes") <= 0
        or _sha(expected.get("sha256"), f"{field} digest") != expected.get("sha256")
        or _executable_identity(path, relative_path=expected_path) != dict(expected)
    ):
        raise O1C105RunError(f"{field} differs")


def _verify_staged_native_closure(
    *,
    stage: Path,
    config: Mapping[str, object],
    expected_rows: Sequence[object],
) -> list[dict[str, object]]:
    """Recompute and verify the exact read-only project closure in a capsule."""

    source = _mapping(config["source"], "staged closure source config")
    paths = _mapping(source["paths"], "staged closure source paths")
    digests = _mapping(source["expected_sha256"], "staged closure source digests")
    closure_root = stage / NATIVE_CLOSURE_DIRECTORY
    expected_files = {
        Path(_relative_text(paths[name], f"staged closure path {name}"))
        for name in NATIVE_CLOSURE_NAMES
    }
    if len(expected_files) != len(NATIVE_CLOSURE_NAMES):
        raise O1C105RunError("staged native closure basenames collide")
    expected_directories = {Path(".")}
    for relative in expected_files:
        expected_directories.update(relative.parents)
    try:
        observed_files: set[Path] = set()
        observed_directories = {Path(".")}
        for candidate in closure_root.rglob("*"):
            relative = candidate.relative_to(closure_root)
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise O1C105RunError("staged native closure contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                observed_directories.add(relative)
                if stat.S_IMODE(metadata.st_mode) != 0o555:
                    raise O1C105RunError("staged native closure directory is writable")
            elif stat.S_ISREG(metadata.st_mode):
                observed_files.add(relative)
                if stat.S_IMODE(metadata.st_mode) != 0o444:
                    raise O1C105RunError("staged native closure file is writable")
            else:
                raise O1C105RunError("staged native closure contains a special file")
    except OSError as exc:
        raise O1C105RunError("staged native closure is unreadable") from exc
    if (
        not closure_root.is_dir()
        or closure_root.is_symlink()
        or stat.S_IMODE(closure_root.stat().st_mode) != 0o555
        or observed_files != expected_files
        or observed_directories != expected_directories
    ):
        raise O1C105RunError("staged native closure inventory differs")

    rows = []
    for name in NATIVE_CLOSURE_NAMES:
        configured = _relative_text(paths[name], f"staged closure path {name}")
        path = closure_root / configured
        row = {
            "name": name,
            "configured_path": configured,
            **_artifact_row(path, relative_to=stage),
        }
        if row["sha256"] != digests.get(name):
            raise O1C105RunError(f"staged native closure {name} digest differs")
        rows.append(row)
    normalized_expected = [
        dict(_mapping(value, "expected staged closure row")) for value in expected_rows
    ]
    if rows != normalized_expected:
        raise O1C105RunError("staged native closure rows differ")
    return rows


def _stage_native_closure(
    *,
    root: Path,
    stage: Path,
    config: Mapping[str, object],
    approved_source_sha256: Mapping[str, object],
) -> list[dict[str, object]]:
    """Read each live closure member once and persist the verified snapshot."""

    source = _mapping(config["source"], "native closure source config")
    paths = _mapping(source["paths"], "native closure source paths")
    digests = _mapping(source["expected_sha256"], "native closure source digests")
    closure_root = stage / NATIVE_CLOSURE_DIRECTORY
    closure_root.mkdir(mode=0o700)
    rows: list[dict[str, object]] = []
    for name in NATIVE_CLOSURE_NAMES:
        configured = _relative_text(paths[name], f"native closure path {name}")
        expected_sha = _sha(digests.get(name), f"native closure {name} digest")
        if approved_source_sha256.get(name) != expected_sha:
            raise O1C105RunError("native closure preflight/config seal differs")
        source_path = _lab_path(root, configured, f"native closure {name}")
        payload = source_path.read_bytes()
        if sha256_bytes(payload) != expected_sha:
            raise O1C105RunError(f"native closure {name} changed after preflight")
        destination = closure_root / configured
        _atomic_create(destination, payload)
        rows.append(
            {
                "name": name,
                "configured_path": configured,
                **_artifact_row(destination, relative_to=stage),
            }
        )
    for directory in sorted(
        (path for path in closure_root.rglob("*") if path.is_dir()), reverse=True
    ):
        directory.chmod(0o555)
    closure_root.chmod(0o555)
    return _verify_staged_native_closure(
        stage=stage,
        config=config,
        expected_rows=rows,
    )


def _compile_native(
    *,
    root: Path,
    stage: Path,
    config: Mapping[str, object],
    closure_rows: Sequence[object],
    command_runner: Callable[..., object],
) -> tuple[Path, dict[str, object]]:
    native = _mapping(config["native"], "native build config")
    compiler = _external_path(native["compiler"], "compiler")
    include = _external_path(
        native["cadical_include"], "CaDiCaL include", directory=True
    )
    library = _external_path(native["cadical_library"], "CaDiCaL library")
    closure_root = stage / NATIVE_CLOSURE_DIRECTORY
    verified_closure = _verify_staged_native_closure(
        stage=stage,
        config=config,
        expected_rows=closure_rows,
    )
    source_config = _mapping(config["source"], "build source config")
    source_paths = _mapping(source_config["paths"], "build source paths")
    staged_source = _relative_text(source_paths["native_v31"], "staged v31 source")
    if (
        native["source"] != staged_source
        or _mapping(verified_closure[0], "staged v31 row").get("sha256")
        != native["source_sha256"]
        or _sha_file(library) != native["cadical_library_sha256"]
    ):
        raise O1C105RunError("native build input changed after preflight")
    output = stage / "native" / NATIVE_EXECUTABLE_NAME
    output.parent.mkdir(parents=True, exist_ok=False)
    command = [
        str(compiler),
        *COMPILER_FLAGS,
        "-I",
        "native",
        "-I",
        str(include),
        staged_source,
        str(library),
        "-o",
        str(output),
    ]
    try:
        version_result = command_runner(
            [str(compiler), "--version"],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=15,
        )
        completed = command_runner(
            command,
            cwd=closure_root,
            capture_output=True,
            check=False,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C105RunError("native v31 compilation could not run") from exc
    version_returncode = getattr(version_result, "returncode", None)
    returncode = getattr(completed, "returncode", None)
    if version_returncode != 0 or returncode != 0:
        stderr = _completed_bytes(getattr(completed, "stderr", b""), "compiler stderr")
        raise O1C105RunError(
            "native v31 compilation failed: "
            + stderr.decode("utf-8", errors="replace").strip()[:2000]
        )
    _verify_staged_native_closure(
        stage=stage,
        config=config,
        expected_rows=closure_rows,
    )
    before_smoke = _executable_identity(
        output, relative_path=f"native/{NATIVE_EXECUTABLE_NAME}"
    )
    output.chmod(0o555)
    try:
        smoke = command_runner(
            [str(output), "--help"],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C105RunError("native v31 --help smoke could not run") from exc
    smoke_stdout = _completed_bytes(getattr(smoke, "stdout", b""), "smoke stdout")
    smoke_stderr = _completed_bytes(getattr(smoke, "stderr", b""), "smoke stderr")
    after_smoke = _executable_identity(
        output, relative_path=f"native/{NATIVE_EXECUTABLE_NAME}"
    )
    if (
        getattr(smoke, "returncode", None) != 0
        or smoke_stdout != NATIVE_V31_USAGE
        or smoke_stderr
        or after_smoke != before_smoke
    ):
        raise O1C105RunError("native v31 --help smoke seal differs")
    verified_closure = _verify_staged_native_closure(
        stage=stage,
        config=config,
        expected_rows=closure_rows,
    )
    if _sha_file(library) != native["cadical_library_sha256"]:
        raise O1C105RunError("native library changed during build/smoke")
    normalized_command = [
        *command[:-1],
        f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}",
    ]
    build = {
        "schema": NATIVE_BUILD_SCHEMA,
        "source": native["source"],
        "source_sha256": native["source_sha256"],
        "staged_source": dict(_mapping(verified_closure[0], "staged v31 row")),
        "include_closure": verified_closure,
        "working_directory": f"<capsule>/{NATIVE_CLOSURE_DIRECTORY}",
        "compiler": str(compiler),
        "compiler_version_stdout_sha256": sha256_bytes(
            _completed_bytes(getattr(version_result, "stdout", b""), "compiler version")
        ),
        "compiler_flags": list(COMPILER_FLAGS),
        "command": normalized_command,
        "fixture_macro_defined": False,
        "build_invocations": 1,
        "executable": before_smoke,
        "smoke": {
            "command": [
                f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}",
                "--help",
            ],
            "returncode": 0,
            "stdout": {
                "serialized_bytes": len(smoke_stdout),
                "sha256": sha256_bytes(smoke_stdout),
            },
            "stderr": {
                "serialized_bytes": len(smoke_stderr),
                "sha256": sha256_bytes(smoke_stderr),
            },
            "executable": after_smoke,
        },
        "adapter_schema": native["adapter_schema"],
        "result_schema": native["result_schema"],
        "memory_watchdog_bytes": MEMORY_LIMIT_BYTES,
        "build_timeout_seconds": BUILD_TIMEOUT_SECONDS,
    }
    return output, build


def _validate_staged_native_build(
    *,
    capsule: Path,
    config: Mapping[str, object],
    build: Mapping[str, object],
    require_executable_identity: bool = True,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate a build document against its observed staged inputs and output."""

    expected_fields = {
        "schema",
        "source",
        "source_sha256",
        "staged_source",
        "include_closure",
        "working_directory",
        "compiler",
        "compiler_version_stdout_sha256",
        "compiler_flags",
        "command",
        "fixture_macro_defined",
        "build_invocations",
        "executable",
        "smoke",
        "adapter_schema",
        "result_schema",
        "memory_watchdog_bytes",
        "build_timeout_seconds",
    }
    native = _mapping(config["native"], "validated native build config")
    compiler = _external_path(native["compiler"], "validated build compiler")
    include = _external_path(
        native["cadical_include"],
        "validated build CaDiCaL include",
        directory=True,
    )
    library = _external_path(
        native["cadical_library"], "validated build CaDiCaL library"
    )
    closure_rows = _sequence(build.get("include_closure"), "build include closure")
    verified_closure = _verify_staged_native_closure(
        stage=capsule,
        config=config,
        expected_rows=closure_rows,
    )
    executable = dict(_mapping(build.get("executable"), "build executable"))
    smoke = dict(_mapping(build.get("smoke"), "build smoke"))
    expected_command = [
        str(compiler),
        *COMPILER_FLAGS,
        "-I",
        "native",
        "-I",
        str(include),
        native["source"],
        str(library),
        "-o",
        f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}",
    ]
    if (
        set(build) != expected_fields
        or build.get("schema") != NATIVE_BUILD_SCHEMA
        or build.get("source") != native["source"]
        or build.get("source_sha256") != native["source_sha256"]
        or build.get("staged_source") != verified_closure[0]
        or build.get("working_directory") != f"<capsule>/{NATIVE_CLOSURE_DIRECTORY}"
        or build.get("compiler") != str(compiler)
        or _sha(
            build.get("compiler_version_stdout_sha256"),
            "compiler version digest",
        )
        != build.get("compiler_version_stdout_sha256")
        or build.get("compiler_flags") != list(COMPILER_FLAGS)
        or build.get("command") != expected_command
        or build.get("fixture_macro_defined") is not False
        or build.get("build_invocations") != 1
        or build.get("adapter_schema") != native["adapter_schema"]
        or build.get("result_schema") != native["result_schema"]
        or build.get("memory_watchdog_bytes") != MEMORY_LIMIT_BYTES
        or build.get("build_timeout_seconds") != BUILD_TIMEOUT_SECONDS
        or smoke.get("command")
        != [f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}", "--help"]
        or smoke.get("returncode") != 0
        or smoke.get("stdout")
        != {
            "serialized_bytes": len(NATIVE_V31_USAGE),
            "sha256": sha256_bytes(NATIVE_V31_USAGE),
        }
        or smoke.get("stderr") != {"serialized_bytes": 0, "sha256": sha256_bytes(b"")}
        or smoke.get("executable") != executable
    ):
        raise O1C105RunError("staged native build provenance differs")
    if require_executable_identity:
        _require_executable_identity(
            capsule / "native" / NATIVE_EXECUTABLE_NAME,
            executable,
            "staged native executable",
        )
    return executable, smoke


def _stage_capsule(
    *,
    root: Path,
    config_path: Path,
    bundle: PreflightBundle,
    command_runner: Callable[..., object],
    now: Callable[[], datetime],
) -> tuple[Path, Mapping[str, object]]:
    runs = root / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    stamp = now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
    final = runs / f"{stamp}_{CAPSULE_SUFFIX}"
    stage = runs / f".{final.name}.staging-{os.getpid()}"
    if final.exists() or stage.exists():
        raise O1C105RunError("timestamped capsule already exists")
    stage.mkdir(mode=0o700)
    try:
        config_payload = config_path.read_bytes()
        if sha256_bytes(config_payload) != bundle.row.get(
            "config_sha256"
        ) or config_payload != canonical_json_bytes(bundle.config):
            raise O1C105RunError("config changed before closure snapshot")
        _atomic_create(stage / "config.json", config_payload)
        _atomic_json(stage / "preflight.json", bundle.row)
        initial = stage / "initial"
        initial.mkdir()
        for name, payload in sorted(bundle.prepared.artifacts.items()):
            _atomic_create(initial / name, payload)
        closure_rows = _stage_native_closure(
            root=root,
            stage=stage,
            config=bundle.config,
            approved_source_sha256=_mapping(
                bundle.row.get("source_sha256"), "approved closure source SHA"
            ),
        )
        _, build = _compile_native(
            root=root,
            stage=stage,
            config=bundle.config,
            closure_rows=closure_rows,
            command_runner=command_runner,
        )
        _atomic_json(stage / "native-build.json", build)
        observed_build = _read_canonical_json(
            stage / "native-build.json", "observed staged native build"
        )
        observed_executable, observed_smoke = _validate_staged_native_build(
            capsule=stage,
            config=bundle.config,
            build=observed_build,
        )
        initial_rows = {
            name: _artifact_row(initial / name, relative_to=initial)
            for name in sorted(STAGED_INITIAL_NAMES)
        }
        invocation = {
            "schema": INVOCATION_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "config_sha256": bundle.row["config_sha256"],
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "page20_sha256": PAGE20_SHA256,
            "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            **DERIVED_NAMESPACE_SHA256_FIELDS,
            "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
            "global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "threshold": THRESHOLD,
            "seed": SEED,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "maximum_native_solver_calls": MAXIMUM_NATIVE_CALLS,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "initial_artifacts": initial_rows,
            "native_build_sha256": _sha_file(stage / "native-build.json"),
            "native_executable": observed_executable,
            "native_smoke": observed_smoke,
            "retry_authorized": False,
            "replay_authorized": False,
            "target_input_present": False,
            "truth_input_present": False,
        }
        _atomic_json(stage / "invocation.json", invocation)
        _verify_staged_native_closure(
            stage=stage,
            config=bundle.config,
            expected_rows=closure_rows,
        )
        os.replace(stage, final)
        directory_fd = os.open(runs, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return final, invocation
    except BaseException:
        if stage.exists():
            _remove_private_stage(stage)
        raise


def _rehash_call_inputs(
    *,
    root: Path,
    config_path: Path,
    config: Mapping[str, object],
    preflight_row: Mapping[str, object],
    capsule: Path,
    invocation: Mapping[str, object],
    require_executable_identity: bool = True,
) -> None:
    if _sha_file(config_path) != preflight_row.get("config_sha256"):
        raise O1C105RunError("config changed before native call")
    inputs = _mapping(config["inputs"], "call inputs")
    approved = _mapping(preflight_row.get("input_sha256"), "approved input SHA")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        if (
            approved.get(name) != inputs[f"{name}_sha256"]
            or _sha_file(_lab_path(root, inputs[name], f"call input {name}"))
            != approved[name]
        ):
            raise O1C105RunError(f"input {name} changed before native call")
    source_config = _mapping(config["source"], "call source config")
    source_paths = _mapping(source_config["paths"], "call source paths")
    source_sha = _mapping(preflight_row.get("source_sha256"), "approved source SHA")
    for name in SOURCE_PATHS:
        path = _lab_path(root, source_paths[name], f"call source {name}")
        if _sha_file(path) != source_sha.get(name):
            raise O1C105RunError(f"source {name} changed before native call")
    executable = capsule / "native" / NATIVE_EXECUTABLE_NAME
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C105RunError("staged call artifact inventory differs") from exc
    if {path.name for path in children} != STAGED_INITIAL_NAMES or any(
        not path.is_file() or path.is_symlink() for path in children
    ):
        raise O1C105RunError("staged call artifact inventory differs")
    prepared_rows = _mapping(
        preflight_row.get("prepared_artifacts"), "approved prepared artifacts"
    )
    receipt_row = _mapping(
        preflight_row.get("priority_state_receipt"), "approved priority receipt"
    )
    inherited_triplet = _mapping(
        preflight_row.get("inherited_derived_resolution_triplet"),
        "approved inherited derived triplet",
    )
    new_triplet = _mapping(
        preflight_row.get("new_derived_resolution_triplet"),
        "approved new derived triplet",
    )
    if (
        prepared_rows.get(RECEIPT_NAME) != receipt_row
        or invocation.get("priority_state_receipt_sha256") != receipt_row.get("sha256")
    ):
        raise O1C105RunError("staged receipt seal differs")
    triplet_contract = (
        (
            inherited_triplet,
            "receipt",
            INHERITED_DERIVED_RECEIPT_NAME,
            "inherited_derived_resolution_receipt_sha256",
        ),
        (
            inherited_triplet,
            "closure",
            INHERITED_DERIVED_CLOSURE_NAME,
            "inherited_derived_resolution_closure_sha256",
        ),
        (
            inherited_triplet,
            "overlay",
            INHERITED_DERIVED_OVERLAY_NAME,
            "inherited_derived_resolution_overlay_sha256",
        ),
        (
            new_triplet,
            "receipt",
            DERIVED_RECEIPT_NAME,
            "new_derived_resolution_receipt_sha256",
        ),
        (
            new_triplet,
            "closure",
            DERIVED_CLOSURE_NAME,
            "new_derived_resolution_closure_sha256",
        ),
        (
            new_triplet,
            "overlay",
            DERIVED_OVERLAY_NAME,
            "new_derived_resolution_overlay_sha256",
        ),
    )
    for triplet, component, artifact_name, invocation_field in triplet_contract:
        row = _mapping(triplet.get(component), f"approved {component} row")
        if (
            prepared_rows.get(artifact_name) != row
            or invocation.get(invocation_field) != row.get("sha256")
        ):
            raise O1C105RunError("staged derived namespace seal differs")
    expected_rows = prepared_rows
    for name, value in expected_rows.items():
        row = _mapping(value, f"approved staged artifact {name}")
        path = initial / name
        if path.stat().st_size != row.get("serialized_bytes") or _sha_file(
            path
        ) != row.get("sha256"):
            raise O1C105RunError("staged call artifact seal differs")
    invocation_path = capsule / "invocation.json"
    build_path = capsule / "native-build.json"
    capsule_config_path = capsule / "config.json"
    if (
        invocation_path.read_bytes() != canonical_json_bytes(invocation)
        or capsule_config_path.read_bytes() != canonical_json_bytes(config)
        or _sha_file(capsule_config_path) != preflight_row.get("config_sha256")
        or invocation.get("config_sha256") != preflight_row.get("config_sha256")
        or _sha_file(build_path) != invocation.get("native_build_sha256")
    ):
        raise O1C105RunError("staged invocation/build seal differs")
    build = _read_canonical_json(build_path, "staged native build")
    expected = _mapping(
        invocation.get("native_executable"), "invocation native executable"
    )
    observed_executable, observed_smoke = _validate_staged_native_build(
        capsule=capsule,
        config=config,
        build=build,
        require_executable_identity=require_executable_identity,
    )
    if (
        observed_executable != expected
        or invocation.get("native_smoke") != observed_smoke
    ):
        raise O1C105RunError("staged native build/smoke seal differs")
    if require_executable_identity:
        _require_executable_identity(
            executable, expected, "native executable call seal"
        )


def _native_stdout(result: object) -> bytes:
    value = getattr(result, "native_stdout", None)
    if isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, bytes):
        payload = value
    else:
        raise O1C105RunError("adapter omitted byte-exact native stdout")
    if _sha(
        getattr(result, "native_stdout_sha256", None), "native stdout digest"
    ) != sha256_bytes(payload):
        raise O1C105RunError("native stdout digest differs")
    return payload


def _validate_result_conservation(
    priority_state: Mapping[str, object], bank: bytes
) -> None:
    """Independently conserve probes, child evaluations, and bank counts."""

    probe_trace = _mapping(priority_state.get("probe_trace"), "priority probe trace")
    probes = _nonnegative(probe_trace.get("count"), "probe count")
    counters = _mapping(priority_state.get("probe_counters"), "probe counters")
    outcome_names = (
        "NEITHER_PRUNABLE",
        "ZERO_PRUNABLE",
        "ONE_PRUNABLE",
        "BOTH_PRUNABLE",
    )
    if set(counters) != {*outcome_names, "child_bound_evaluations"}:
        raise O1C105RunError("native post-result conservation differs")
    outcomes = tuple(
        _nonnegative(counters.get(name), f"probe counter {name}")
        for name in outcome_names
    )
    child_evaluations = _nonnegative(
        counters.get("child_bound_evaluations"), "child bound evaluations"
    )
    counts = tuple(
        int.from_bytes(bank[offset : offset + 8], "little")
        for offset in range(0, len(bank), RECORD_BYTES)
    )
    zero_variables = tuple(
        variable for variable, count in enumerate(counts, start=1) if count == 0
    )
    if (
        len(counts) != 256
        or sum(outcomes) != probes
        or child_evaluations != 2 * probes
        or sum(counts) - INPUT_BANK_TOTAL_COUNT != probes
        or zero_variables != (MISSING_VARIABLE,)
    ):
        raise O1C105RunError("native post-result conservation differs")


def _adapter_memory_samples(
    value: object,
) -> tuple[dict[str, int | float], ...]:
    memory = _mapping(value, "adapter memory")
    expected_fields = {
        "memory_series_schema",
        "memory_sample_limit",
        "memory_sample_count",
        "memory_samples",
        "memory_peak_bytes",
        "memory_last_bytes",
        "memory_last_elapsed_seconds",
    }
    rows_raw = _sequence(memory.get("memory_samples"), "adapter memory samples")
    rows: list[dict[str, int | float]] = []
    for raw in rows_raw:
        row = _mapping(raw, "adapter memory sample")
        elapsed = row.get("elapsed_seconds")
        rss = row.get("rss_bytes")
        if (
            set(row) != {"elapsed_seconds", "rss_bytes"}
            or isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
            or elapsed < 0
            or isinstance(rss, bool)
            or not isinstance(rss, int)
            or rss < 0
        ):
            raise O1C105RunError("adapter memory sample differs")
        rows.append({"elapsed_seconds": float(elapsed), "rss_bytes": rss})
    peak = max((cast(int, row["rss_bytes"]) for row in rows), default=None)
    last = cast(int, rows[-1]["rss_bytes"]) if rows else None
    last_elapsed = cast(float, rows[-1]["elapsed_seconds"]) if rows else None
    if (
        set(memory) != expected_fields
        or memory.get("memory_series_schema")
        != _native_v34._v9.JOINT_SCORE_SIEVE_MEMORY_SERIES_SCHEMA
        or memory.get("memory_sample_limit")
        != _native_v34._v9.JOINT_SCORE_SIEVE_MAXIMUM_MEMORY_SAMPLES
        or memory.get("memory_sample_count") != len(rows)
        or list(rows_raw) != rows
        or rows != sorted(rows, key=lambda row: cast(float, row["elapsed_seconds"]))
        or memory.get("memory_peak_bytes") != peak
        or memory.get("memory_last_bytes") != last
        or memory.get("memory_last_elapsed_seconds") != last_elapsed
    ):
        raise O1C105RunError("adapter memory ledger differs")
    return tuple(rows)


def _validate_native_result(result: object, stdout: bytes) -> NativeEvidence:
    if not isinstance(result, _native_v34.JointScoreSieveV34Result):
        raise O1C105RunError("adapter v34 result type differs")
    raw = _mapping(result.raw, "native result")
    base_result = result.base_result
    adapter_memory = _mapping(
        getattr(base_result, "adapter_memory", None), "adapter memory"
    )
    _adapter_memory_samples(adapter_memory)
    try:
        decoded = _mapping(json.loads(stdout), "native stdout JSON")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C105RunError("native stdout JSON differs") from exc
    if (
        decoded != raw
        or raw.get("schema") != _native_v34.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    ):
        raise O1C105RunError("native stdout/result projection differs")
    priority_seed = _mapping(result.priority_seed, "priority seed telemetry")
    priority_state = _mapping(result.priority_state, "priority state")
    actions = _mapping(result.priority_actions, "priority actions")
    ownership = _mapping(result.decision_ownership, "decision ownership")
    base = _mapping(raw.get("base_sieve"), "base sieve")
    vault = _mapping(raw.get("vault"), "vault")
    resources = _mapping(result.resources, "native resources")
    stats = _mapping(result.stats, "native stats")
    bank = result.next_priority_seed
    if (
        result.conflict_limit != REQUESTED_CONFLICTS
        or result.threshold != THRESHOLD
        or raw.get("seed") != SEED
        or raw.get("active_vault_sha256") != PAGE20_SHA256
        or priority_seed.get("payload_sha256") != CONTINUATION_BANK_SHA256
        or priority_seed.get("payload_bytes") != CONTINUATION_BANK_BYTES
        or priority_seed.get("seed_source") != "sealed-live-continuation-bank"
        or priority_seed.get("live_continuation_bank_identity") is not True
        or priority_seed.get("fresh_seed_parser_used") is not False
        or not isinstance(bank, bytes)
        or len(bank) != CONTINUATION_BANK_BYTES
        or priority_state.get("bank_bytes") != CONTINUATION_BANK_BYTES
        or priority_state.get("current_bank_sha256") != sha256_bytes(bank)
        or _nonnegative(base.get("pending_clause_count"), "pending clause count") != 0
        or _nonnegative(resources.get("peak_rss_bytes"), "native peak RSS")
        > MEMORY_LIMIT_BYTES
        or _nonnegative(resources.get("wall_microseconds"), "native wall time")
        > int(TIMEOUT_SECONDS * 1_000_000)
        or result.status not in (0, 10, 20)
    ):
        raise O1C105RunError("native v31 production binding differs")
    if (
        raw.get("priority_state") != priority_state
        or raw.get("priority_actions") != actions
    ):
        raise O1C105RunError("native promoted priority projection differs")
    if raw.get("decision_ownership") != ownership:
        raise O1C105RunError("native promoted ownership projection differs")
    if result.status == 10 and not isinstance(result.key_model, bytes):
        raise O1C105RunError("SAT result omitted key model")
    if result.status != 10 and result.key_model is not None:
        raise O1C105RunError("non-SAT result returned key model")
    _validate_result_conservation(priority_state, bank)
    return NativeEvidence(
        raw=raw,
        stdout=stdout,
        adapter_memory=adapter_memory,
        priority_seed=priority_seed,
        priority_state=priority_state,
        priority_actions=actions,
        ownership=ownership,
        base_sieve=base,
        vault=vault,
        resources=resources,
        stats=stats,
        status=result.status,
        key_model=result.key_model,
        final_bank=bank,
    )


def _science_and_operation(
    evidence: NativeEvidence,
    *,
    globally_known_clause_sha256: frozenset[str] = frozenset(),
    public_model_verified: bool = False,
) -> tuple[dict[str, object], dict[str, object], str, str]:
    actions = tuple(
        _mapping(row, "priority action")
        for row in _sequence(
            evidence.priority_actions.get("actions"), "priority actions"
        )
    )
    action_count = _nonnegative(
        evidence.priority_actions.get("action_count"), "action count"
    )
    if action_count != len(actions):
        raise O1C105RunError("priority action count differs")
    failure_first = sum(row.get("semantic") == PROOF_MINING_SEMANTIC for row in actions)
    certified = sum(
        row.get("semantic") == CERTIFIED_CROSSING_SEMANTIC for row in actions
    )
    realized_certified_prunes = sum(
        row.get("semantic") == CERTIFIED_CROSSING_SEMANTIC
        and row.get("confirmed") is True
        and row.get("coincident_v6_pending") is False
        for row in actions
    )
    probe_trace = _mapping(
        evidence.priority_state.get("probe_trace"), "priority probe trace"
    )
    probes = _nonnegative(probe_trace.get("count"), "probe count")
    threshold_prunes = _nonnegative(
        evidence.base_sieve.get("threshold_prunes"), "threshold prunes"
    )
    emitted = _nonnegative(
        evidence.vault.get("fully_emitted_clause_count"), "emitted clauses"
    )
    active_new = _nonnegative(
        evidence.vault.get("emitted_new_clause_count"), "new clauses"
    )
    emitted_rows = tuple(
        _mapping(row, "emitted clause")
        for row in _sequence(
            evidence.vault.get("fully_emitted_clauses"), "emitted clause rows"
        )
    )
    terminal_empty = any(
        row.get("classification") == "terminal_empty" for row in emitted_rows
    )
    globally_novel: set[str] = set()
    for row in emitted_rows:
        if row.get("classification") != "new":
            continue
        literals = tuple(_sequence(row.get("literals"), "emitted clause literals"))
        try:
            clause = ThresholdNoGoodClause(cast(tuple[int, ...], literals))
        except (TypeError, ValueError) as exc:
            raise O1C105RunError("emitted clause serialization differs") from exc
        digest = sha256_bytes(clause.serialized)
        if digest not in globally_known_clause_sha256:
            globally_novel.add(digest)
    novel = len(globally_novel)
    if novel > active_new:
        raise O1C105RunError("global novelty exceeds active-vault novelty")
    certified_prune_gain = (
        realized_certified_prunes > 0 and threshold_prunes > 0 and emitted > 0
    )
    if evidence.status == 10 and not public_model_verified:
        raise O1C105RunError("SAT key failed exact public ChaCha verification")
    if evidence.status != 10 and public_model_verified:
        raise O1C105RunError("public model verification without SAT differs")
    model_gain = evidence.status == 10 and public_model_verified
    closure_gain = evidence.status == 20 or terminal_empty
    # Native v31 emits no entropy or domain estimate.  These fields stay
    # explicit so a later claim cannot be inferred from priority magnitude.
    entropy_gain_bits = 0.0
    domain_reduction = 0
    science_gain = bool(
        model_gain
        or closure_gain
        or certified_prune_gain
        or novel
        or entropy_gain_bits > 0.0
        or domain_reduction > 0
    )
    operation = {
        "operational_activation": action_count > 0,
        "exact_probe_operation": probes > 0,
        "probe_count": probes,
        "action_count": action_count,
        "failure_first_actions": failure_first,
        "certified_crossing_actions": certified,
        "failure_first_action_alone_is_science_gain": False,
        "nonclaim_digest_alone_is_science_gain": False,
        "priority_is_key_bit_belief": False,
    }
    science = {
        "science_gain": science_gain,
        "certified_model_or_key": model_gain,
        "certified_closure": closure_gain,
        "actual_certified_prunes": realized_certified_prunes
        if certified_prune_gain
        else 0,
        "threshold_prunes": threshold_prunes,
        "fully_emitted_clauses": emitted,
        "globally_novel_clauses": novel,
        "active_page20_new_clauses": active_new,
        "attacker_valid_entropy_gain_bits": entropy_gain_bits,
        "attacker_valid_domain_reduction": domain_reduction,
        "failure_first_action_alone_is_science_gain": False,
        "nonclaim_digest_alone_is_science_gain": False,
        "unconfirmed_crossing_alone_is_science_gain": False,
        "priority_or_differential_alone_is_science_gain": False,
    }
    if model_gain:
        return operation, science, SCIENCE_MODEL, "certified-model-or-key"
    if closure_gain:
        return operation, science, SCIENCE_CLOSURE, "certified-closure"
    if certified_prune_gain:
        return operation, science, SCIENCE_PRUNE, "actual-certified-prune"
    if novel:
        return operation, science, SCIENCE_CLAUSE, "globally-novel-clause"
    if entropy_gain_bits > 0.0 or domain_reduction > 0:
        return operation, science, SCIENCE_DOMAIN, "attacker-valid-entropy-or-domain"
    if action_count:
        return operation, science, ACTIVATION_ONLY, "priority-action-without-science"
    if probes:
        return operation, science, PROBE_ONLY, "exact-probes-without-action-or-science"
    return operation, science, NO_OPERATION, "no-operation-or-science"


def _archive_native(episode_dir: Path, evidence: NativeEvidence) -> dict[str, object]:
    components: tuple[tuple[str, object], ...] = (
        ("native-result.json", evidence.raw),
        ("adapter-memory.json", evidence.adapter_memory),
        ("priority-seed.json", evidence.priority_seed),
        ("priority-state.json", evidence.priority_state),
        ("priority-actions.json", evidence.priority_actions),
        ("decision-ownership.json", evidence.ownership),
        ("base-sieve.json", evidence.base_sieve),
        ("vault.json", evidence.vault),
        ("resources.json", evidence.resources),
    )
    rows: dict[str, object] = {}
    for name, value in components:
        path = episode_dir / name
        _atomic_json(path, value)
        rows[name] = _artifact_row(path, relative_to=episode_dir)
    bank_path = episode_dir / FINAL_BANK_NAME
    _atomic_create(bank_path, evidence.final_bank)
    rows[FINAL_BANK_NAME] = _artifact_row(bank_path, relative_to=episode_dir)
    return rows


def _failure_payload(exc: BaseException) -> dict[str, object]:
    stdout = _completed_bytes(getattr(exc, "stdout", b""), "failure stdout")
    stderr = _completed_bytes(getattr(exc, "stderr", b""), "failure stderr")
    command_raw = getattr(exc, "cmd", None)
    command = (
        [str(part) for part in command_raw]
        if isinstance(command_raw, Sequence)
        and not isinstance(command_raw, (str, bytes, bytearray))
        else None
    )
    memory_raw = getattr(exc, "memory_samples", None)
    memory_samples = (
        [dict(_mapping(row, "failure memory sample")) for row in memory_raw]
        if isinstance(memory_raw, Sequence)
        and not isinstance(memory_raw, (str, bytes, bytearray))
        else None
    )
    telemetry_raw = getattr(exc, "failure_telemetry", None)
    failure_telemetry = (
        dict(telemetry_raw) if isinstance(telemetry_raw, Mapping) else None
    )
    return {
        "exception_type": type(exc).__name__,
        "message": str(exc)[:4000],
        "native_process_evidence": {
            "returncode": getattr(exc, "returncode", None),
            "stdout_bytes": len(stdout),
            "stdout_sha256": sha256_bytes(stdout),
            "stderr_bytes": len(stderr),
            "stderr_sha256": sha256_bytes(stderr),
            "stderr_tail": stderr[-8192:].decode("utf-8", errors="replace"),
            "command": command,
            "memory_samples": memory_samples,
            "failure_telemetry": failure_telemetry,
        }
        if stdout
        or stderr
        or hasattr(exc, "returncode")
        or command is not None
        or memory_samples is not None
        or failure_telemetry is not None
        else None,
    }


def _archive_failure_stdout(
    episode_dir: Path, exc: BaseException
) -> Mapping[str, object] | None:
    """Seal completed native stdout before any terminal-failure interpretation."""

    returncode = getattr(exc, "returncode", None)
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or not hasattr(exc, "stdout")
    ):
        return None
    stdout = _completed_bytes(getattr(exc, "stdout"), "failure stdout")
    path = episode_dir / NATIVE_STDOUT_NAME
    _atomic_create(path, stdout)
    return _artifact_row(path, relative_to=episode_dir)


def _execute_once(
    *,
    root: Path,
    config_path: Path,
    capsule: Path,
    bundle: PreflightBundle,
    invocation: Mapping[str, object],
    adapter_run: AdapterRun,
    verify_public_model: Callable[[bytes], bool],
    globally_known_clause_sha256: frozenset[str],
    now: Callable[[], datetime],
) -> tuple[dict[str, object], str, str, bool, int, int | None, int | None]:
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    invocation_sha = _sha_file(capsule / "invocation.json")
    config_inputs = _mapping(bundle.config["inputs"], "invocation inputs")
    native_config = _mapping(bundle.config["native"], "invocation native")
    cnf_path = _lab_path(root, config_inputs["cnf"], "run CNF")
    potential_path = _lab_path(root, config_inputs["potential"], "run potential")
    grouping_path = _lab_path(root, config_inputs["grouping"], "run grouping")
    source_path = (
        capsule / NATIVE_CLOSURE_DIRECTORY / cast(str, native_config["source"])
    )
    executable_identity = _mapping(
        invocation.get("native_executable"), "run native executable identity"
    )
    _rehash_call_inputs(
        root=root,
        config_path=config_path,
        config=bundle.config,
        preflight_row=bundle.row,
        capsule=capsule,
        invocation=invocation,
    )
    intent = {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "created_at": now().astimezone().isoformat(timespec="microseconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "config_sha256": invocation["config_sha256"],
        "invocation_sha256": invocation_sha,
        "page20_sha256": PAGE20_SHA256,
        "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
        "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
        **DERIVED_NAMESPACE_SHA256_FIELDS,
        "native_executable": dict(executable_identity),
        "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "page20_burned": True,
        "lineage33_burned": True,
        "burn_on_persisted_intent": True,
        "retry_authorized": False,
        "replay_authorized": False,
        "page19_retry_or_replay_authorized": False,
        "page18_retry_or_replay_authorized": False,
        "page17_retry_or_replay_authorized": False,
        "page16_retry_or_replay_authorized": False,
        "page15_retry_or_replay_authorized": False,
        "page14_replay_authorized": False,
        "page13_replay_authorized": False,
        "page12_replay_authorized": False,
        "page11_replay_authorized": False,
        "page10_replay_authorized": False,
        "page9_retry_or_replay_authorized": False,
        "truth_key_bytes_read": False,
        "target_bytes_read": False,
    }
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, intent)
    intent_sha = _sha_file(intent_path)

    call_issued = False
    result_returned = False
    raw_stdout_row: Mapping[str, object] | None = None
    try:
        _rehash_call_inputs(
            root=root,
            config_path=config_path,
            config=bundle.config,
            preflight_row=bundle.row,
            capsule=capsule,
            invocation=invocation,
        )
        call_issued = True
        result = adapter_run(
            executable=capsule / "native" / NATIVE_EXECUTABLE_NAME,
            cnf_path=cnf_path,
            potential_path=potential_path,
            grouping_path=grouping_path,
            vault_path=capsule / "initial" / ACTIVE_PROJECTION_NAME,
            priority_seed_path=capsule / "initial" / CONTINUATION_BANK_NAME,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS,
            expected_source_sha256=native_config["source_sha256"],
            expected_executable_sha256=executable_identity["sha256"],
            expected_executable_bytes=executable_identity["serialized_bytes"],
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            source_path=source_path,
            rollover_manifest_path=capsule / "initial" / PREPARATION_MANIFEST_NAME,
            priority_state_receipt_path=capsule / "initial" / RECEIPT_NAME,
            inherited_derived_resolution_receipt_path=(
                capsule / "initial" / INHERITED_DERIVED_RECEIPT_NAME
            ),
            inherited_derived_resolution_closure_path=(
                capsule / "initial" / INHERITED_DERIVED_CLOSURE_NAME
            ),
            inherited_derived_resolution_overlay_path=(
                capsule / "initial" / INHERITED_DERIVED_OVERLAY_NAME
            ),
            new_derived_resolution_receipt_path=(
                capsule / "initial" / DERIVED_RECEIPT_NAME
            ),
            new_derived_resolution_closure_path=(
                capsule / "initial" / DERIVED_CLOSURE_NAME
            ),
            new_derived_resolution_overlay_path=(
                capsule / "initial" / DERIVED_OVERLAY_NAME
            ),
            sealed_page20_path=capsule / "initial" / ACTIVE_PROJECTION_NAME,
        )
        result_returned = True
        stdout = _native_stdout(result)
        stdout_path = episode_dir / NATIVE_STDOUT_NAME
        _atomic_create(stdout_path, stdout)
        raw_stdout_row = _artifact_row(stdout_path, relative_to=episode_dir)
        _rehash_call_inputs(
            root=root,
            config_path=config_path,
            config=bundle.config,
            preflight_row=bundle.row,
            capsule=capsule,
            invocation=invocation,
        )
        evidence = _validate_native_result(result, stdout)
        archived = _archive_native(episode_dir, evidence)
        public_verified = (
            bool(verify_public_model(evidence.key_model))
            if evidence.status == 10 and evidence.key_model is not None
            else False
        )
        operation, science, classification, stop = _science_and_operation(
            evidence,
            globally_known_clause_sha256=globally_known_clause_sha256,
            public_model_verified=public_verified,
        )
        actual = _nonnegative(evidence.stats.get("solve_conflicts"), "actual conflicts")
        billed = _nonnegative(
            evidence.stats.get("billed_conflicts"), "billed conflicts"
        )
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "config_sha256": invocation["config_sha256"],
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "page20_burned": True,
            "lineage33_burned": True,
            "native_call_issued": True,
            "native_result_returned": True,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "actual_conflicts": actual,
            "billed_conflicts": billed,
            "status": evidence.status,
            "native_stdout": raw_stdout_row,
            "archived_native_components": archived,
            "final_priority_bank": archived[FINAL_BANK_NAME],
            "operational": operation,
            "science": science,
            "classification": classification,
            "stop_reason": stop,
            "resources": dict(evidence.resources),
            "work": dict(evidence.stats),
            "key_model_sha256": sha256_bytes(evidence.key_model)
            if evidence.key_model is not None
            else None,
            "retry_authorized": False,
            "replay_authorized": False,
            "page19_retry_or_replay_authorized": False,
            "page18_retry_or_replay_authorized": False,
            "page17_retry_or_replay_authorized": False,
            "page16_retry_or_replay_authorized": False,
            "page15_retry_or_replay_authorized": False,
            "page14_replay_authorized": False,
            "page13_replay_authorized": False,
            "page12_replay_authorized": False,
            "page11_replay_authorized": False,
            "page10_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
            "terminal_failure": None,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return (
            episode,
            classification,
            stop,
            bool(science["science_gain"]),
            1,
            actual,
            billed,
        )
    except BaseException as exc:
        # Adapter v34 attaches the completed process record even when semantic
        # validation rejects a return-0/nonzero native payload.  Preserve those
        # irreplaceable bytes before constructing any failure interpretation.
        if raw_stdout_row is None:
            raw_stdout_row = _archive_failure_stdout(episode_dir, exc)
        returncode = getattr(exc, "returncode", None)
        post_launch = isinstance(returncode, int) and not isinstance(returncode, bool)
        calls = int(call_issued)
        failure = {
            "schema": "o1-256-apple8-parent-centered-continuation-terminal-failure-v1",
            "classification": OPERATIONAL_TERMINAL,
            "phase": "POST_CALL"
            if result_returned or post_launch
            else ("CALL" if call_issued else "PRE_CALL"),
            "occurred_after_persisted_intent": True,
            "page20_burned": True,
            "lineage33_burned": True,
            "native_call_issued": call_issued,
            "native_result_returned": result_returned,
            "native_calls_consumed": calls,
            "requested_conflicts_consumed": calls * REQUESTED_CONFLICTS,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "science_gain": False,
            "retry_authorized": False,
            "replay_authorized": False,
            "page19_retry_or_replay_authorized": False,
            "page18_retry_or_replay_authorized": False,
            "page17_retry_or_replay_authorized": False,
            "page16_retry_or_replay_authorized": False,
            "page15_retry_or_replay_authorized": False,
            "page14_replay_authorized": False,
            "page13_replay_authorized": False,
            "page12_replay_authorized": False,
            "page11_replay_authorized": False,
            "page10_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
            "native_stdout": dict(raw_stdout_row) if raw_stdout_row else None,
            **_failure_payload(exc),
        }
        _atomic_json(episode_dir / "terminal-failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "config_sha256": invocation["config_sha256"],
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "page20_burned": True,
            "lineage33_burned": True,
            "native_call_issued": call_issued,
            "native_result_returned": result_returned,
            "native_calls_consumed": calls,
            "requested_conflicts": calls * REQUESTED_CONFLICTS,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "native_stdout": dict(raw_stdout_row) if raw_stdout_row else None,
            "operational": {"operational_activation": False},
            "science": {"science_gain": False},
            "classification": OPERATIONAL_TERMINAL,
            "stop_reason": "burned-terminal-failure-no-retry",
            "retry_authorized": False,
            "replay_authorized": False,
            "page19_retry_or_replay_authorized": False,
            "page18_retry_or_replay_authorized": False,
            "page17_retry_or_replay_authorized": False,
            "page16_retry_or_replay_authorized": False,
            "page15_retry_or_replay_authorized": False,
            "page14_replay_authorized": False,
            "page13_replay_authorized": False,
            "page12_replay_authorized": False,
            "page11_replay_authorized": False,
            "page10_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
            "terminal_failure": failure,
        }
        _atomic_json(episode_dir / "episode.json", episode)
        return (
            episode,
            OPERATIONAL_TERMINAL,
            "burned-terminal-failure-no-retry",
            False,
            calls,
            None,
            None,
        )


def _manifest_bytes(capsule: Path) -> tuple[bytes, int]:
    rows: list[str] = []
    total = 0
    for path in sorted(capsule.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C105RunError("capsule contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise O1C105RunError("capsule contains a special file")
        if path.name == "artifacts.sha256" and path.parent == capsule:
            continue
        relative = path.relative_to(capsule).as_posix()
        size = path.stat().st_size
        total += size
        rows.append(f"{_sha_file(path)}  {relative}\n")
    payload = "".join(rows).encode("ascii")
    return payload, total + len(payload)


def _run_markdown(result: Mapping[str, object]) -> bytes:
    resources = _mapping(result.get("resources"), "result resources")
    lines = [
        "# O1C-0105 Page-20 parent-centered run",
        "",
        f"- Classification: `{result.get('classification')}`",
        f"- Stop reason: `{result.get('stop_reason')}`",
        f"- Native calls: `{resources.get('native_solver_calls')}` / 1",
        f"- Requested conflicts: `{resources.get('requested_conflicts')}` / 128",
        f"- Science gain: `{str(result.get('science_gain')).lower()}`",
        "- Page 20 and lineage 33 burned when `episodes/00/intent.json` was persisted.",
        "- Failure-first priority actions are operational proof-mining choices, not bit beliefs or science gain.",
        "- Retry, replay, reveal, target/truth input, refit, MPS, and GPU use were forbidden.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _publish_exact(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise O1C105RunError("authoritative result already differs")
        return
    _atomic_create(path, payload)


def _finalize_capsule(
    *, capsule: Path, authoritative: Path, result: Mapping[str, object]
) -> dict[str, object]:
    result_path = capsule / "result.json"
    run_path = capsule / "RUN.md"
    _atomic_json(result_path, result)
    _atomic_create(run_path, _run_markdown(result))
    manifest_payload, persistent_bytes = _manifest_bytes(capsule)
    if persistent_bytes > MAXIMUM_PERSISTENT_ARTIFACT_BYTES:
        raise O1C105RunError("persistent artifact budget exceeded")
    _atomic_create(capsule / "artifacts.sha256", manifest_payload)
    _publish_exact(authoritative, result_path.read_bytes())
    for path in sorted(capsule.rglob("*"), reverse=True):
        if path.is_dir():
            path.chmod(0o555)
        elif path.is_file():
            path.chmod(0o444)
    capsule.chmod(0o555)
    return dict(result)


def _existing_result(root: Path) -> dict[str, object] | None:
    authoritative = root / RESULT_RELATIVE
    if not authoritative.exists():
        return None
    value = dict(_read_canonical_json(authoritative, "authoritative O1C105 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C105RunError("authoritative O1C105 result differs")
    return value


def _existing_capsules(root: Path) -> list[Path]:
    runs = root / "runs"
    if not runs.is_dir():
        return []
    return sorted(
        path
        for path in runs.glob(f"*_{CAPSULE_SUFFIX}")
        if path.is_dir() and not path.is_symlink()
    )


def _validate_capsule_artifact_row(
    directory: Path,
    value: object,
    name: str,
    *,
    canonical_json: bool = False,
) -> Path:
    row = dict(_mapping(value, f"capsule artifact row {name}"))
    path = directory / name
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C105RunError(f"capsule artifact {name} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C105RunError(f"capsule artifact {name} type differs")
    expected = _artifact_row(path, relative_to=directory)
    if set(row) != {"path", "serialized_bytes", "sha256"} or row != expected:
        raise O1C105RunError(f"capsule artifact {name} seal differs")
    if canonical_json:
        _read_canonical_json(path, f"capsule artifact {name}")
    return path


def _validated_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C105RunError(f"{field} differs")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise O1C105RunError(f"{field} differs") from exc
    if parsed.tzinfo is None:
        raise O1C105RunError(f"{field} differs")
    return value


def _nonnegative_finite(value: object, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise O1C105RunError(f"{field} differs")
    return float(value)


def _semantic_replay_completed_native(
    *,
    root: Path,
    config: Mapping[str, object],
    prepared: PublishedPreparation,
    stdout: bytes,
    adapter_memory: Mapping[str, object],
) -> NativeEvidence:
    """Replay archived stdout through v34 using the original sealed inputs."""

    inputs = _mapping(config["inputs"], "semantic replay inputs")
    input_sha = {
        name: _sha(inputs.get(f"{name}_sha256"), f"semantic replay {name} digest")
        for name in ("cnf", "potential", "grouping")
    }
    payloads: dict[str, bytes] = {}
    for name in ("cnf", "potential", "grouping"):
        path = _lab_path(root, inputs[name], f"semantic replay {name}")
        payload = path.read_bytes()
        if sha256_bytes(payload) != input_sha[name]:
            raise O1C105RunError(f"semantic replay {name} seal differs")
        payloads[name] = payload
    page20 = prepared.artifacts[ACTIVE_PROJECTION_NAME]
    bank = prepared.artifacts[CONTINUATION_BANK_NAME]
    if (
        len(page20) != PAGE20_SERIALIZED_BYTES
        or sha256_bytes(page20) != PAGE20_SHA256
        or len(bank) != CONTINUATION_BANK_BYTES
        or sha256_bytes(bank) != CONTINUATION_BANK_SHA256
    ):
        raise O1C105RunError("semantic replay Page20/bank seal differs")
    io_v1 = _native_v34._v9._v8._v7._v1
    try:
        field = io_v1._potential(payloads["potential"])
        grouping = _native_v34._v9.validate_joint_score_sieve_grouping(
            field, payloads["grouping"]
        )
        if grouping.potential_sha256 != input_sha["potential"]:
            raise O1C105RunError("semantic replay grouping identity differs")
        input_vault = _native_v34.parse_threshold_no_good_vault(
            page20,
            observed_variables=field.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        identity = _native_v34.vault_identity_from_sources(
            cnf_sha256=input_sha["cnf"],
            potential_sha256=input_sha["potential"],
            grouping_sha256=input_sha["grouping"],
            observed_variables=field.observed_variables,
            bound_rule=_native_v34._v9.JOINT_SCORE_SIEVE_BOUND_RULE,
            threshold=THRESHOLD,
        )
        _native_v34.validate_threshold_no_good_vault_identity(
            input_vault, expected=identity
        )
        _native_v34._v9._v8._certify_input_vault(
            input_vault,
            field=field,
            grouping=grouping,
            threshold=THRESHOLD,
        )
        priority_records = _native_v34._decode_live_bank(
            bank,
            expected_sha256=CONTINUATION_BANK_SHA256,
            sealed_input=True,
        )
        memory_samples = _adapter_memory_samples(adapter_memory)
        raw = _native_v34._v21.load_native_json(stdout)
        replayed = _native_v34._parse_native_payload(
            raw,
            input_vault=input_vault,
            vault_caps=O1C66_VAULT_CAPS,
            field=field,
            grouping=grouping,
            grouping_sha256=input_sha["grouping"],
            cnf_sha256=input_sha["cnf"],
            potential_sha256=input_sha["potential"],
            threshold=THRESHOLD,
            requested_conflicts=REQUESTED_CONFLICTS,
            seed=SEED,
            priority_seed_sha256=CONTINUATION_BANK_SHA256,
            priority_seed_records=priority_records,
            production_seal=True,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            memory_samples=memory_samples,
        )
    except Exception as exc:
        raise O1C105RunError("archived native semantic replay differs") from exc
    replay_memory = _mapping(
        getattr(replayed.base_result, "adapter_memory", None),
        "semantic replay adapter memory",
    )
    if replay_memory != adapter_memory:
        raise O1C105RunError("semantic replay adapter memory differs")
    return _validate_native_result(replayed, stdout)


def _validated_capsule_result(
    root: Path,
    capsule: Path,
    *,
    public_verifier: Callable[[bytes], bool] | None = None,
) -> tuple[dict[str, object], bytes]:
    required = tuple(
        capsule / name for name in ("result.json", "RUN.md", "artifacts.sha256")
    )
    if not all(path.is_file() and not path.is_symlink() for path in required):
        if (capsule / "episodes/00/intent.json").is_file():
            raise O1C105RunError("burned incomplete capsule forbids retry or replay")
        raise O1C105RunError("incomplete pre-intent capsule blocks a fresh call")
    manifest, _ = _manifest_bytes(capsule)
    if manifest != (capsule / "artifacts.sha256").read_bytes():
        raise O1C105RunError("existing capsule manifest differs")
    episode_dir = capsule / "episodes" / "00"
    episode_path = episode_dir / "episode.json"
    episode_preview = dict(
        _read_canonical_json(episode_path, "capsule episode preview")
    )
    completed_success = episode_preview.get("completed") is True

    expected_top_level = {
        "config.json",
        "preflight.json",
        "initial",
        NATIVE_CLOSURE_DIRECTORY,
        "native",
        "native-build.json",
        "invocation.json",
        "episodes",
        "result.json",
        "RUN.md",
        "artifacts.sha256",
    }
    try:
        top_level = {path.name for path in capsule.iterdir()}
        episode_directories = {path.name for path in (capsule / "episodes").iterdir()}
        native_inventory = {path.name for path in (capsule / "native").iterdir()}
    except OSError as exc:
        raise O1C105RunError("existing capsule inventory is unreadable") from exc
    if (
        top_level != expected_top_level
        or episode_directories != {"00"}
        or native_inventory not in ({NATIVE_EXECUTABLE_NAME}, set())
        or completed_success
        and native_inventory != {NATIVE_EXECUTABLE_NAME}
    ):
        raise O1C105RunError("existing capsule inventory differs")

    config_path = root / CONFIG_RELATIVE
    config = load_config(config_path, root=root)
    capsule_config_path = capsule / "config.json"
    capsule_config = dict(_read_canonical_json(capsule_config_path, "capsule config"))
    if (
        capsule_config != config
        or capsule_config_path.read_bytes() != config_path.read_bytes()
    ):
        raise O1C105RunError("existing capsule config differs")
    config_sha = _sha_file(capsule_config_path)

    initial = capsule / "initial"
    prepared = _load_published_preparation(initial, initial / PREPARATION_MANIFEST_NAME)
    preflight_path = capsule / "preflight.json"
    preflight = dict(_read_canonical_json(preflight_path, "capsule preflight"))
    preflight_fields = {
        "schema",
        "attempt_id",
        "passed",
        "config_sha256",
        "input_sha256",
        "source_sha256",
        "parent_result_sha256",
        "parent_capsule_manifest_sha256",
        "prepared_artifacts",
        "published_preparation",
        "page20_sha256",
        "continuation_bank_sha256",
        "priority_state_receipt",
        "inherited_derived_resolution_triplet",
        "new_derived_resolution_triplet",
        "candidate_order_sha256",
        "global_novelty_baseline_clause_count",
        "compiler",
        "cadical_include",
        "cadical_library",
        "system",
        "native_solver_calls",
        "target_bytes_read",
        "truth_key_bytes_read",
        "reveal_calls",
        "refits",
        "mps_calls",
        "gpu_calls",
    }
    config_inputs = _mapping(config["inputs"], "recovery config inputs")
    config_source = _mapping(config["source"], "recovery config source")
    config_native = _mapping(config["native"], "recovery config native")
    recovery_compiler = _external_path(config_native["compiler"], "recovery compiler")
    recovery_include = _external_path(
        config_native["cadical_include"],
        "recovery CaDiCaL include",
        directory=True,
    )
    recovery_library = _external_path(
        config_native["cadical_library"], "recovery CaDiCaL library"
    )
    config_parent = _mapping(config["parent"], "recovery config parent")
    config_preparation = _mapping(config["preparation"], "recovery config preparation")
    expected_input_sha = {
        name: config_inputs[f"{name}_sha256"]
        for name in ("cnf", "potential", "grouping", "o1c73_config")
    }
    prepared_rows = {
        name: {
            "serialized_bytes": len(payload),
            "sha256": sha256_bytes(payload),
        }
        for name, payload in sorted(prepared.artifacts.items())
    }
    published = _mapping(
        preflight.get("published_preparation"), "recovery published preparation"
    )
    system = _mapping(preflight.get("system"), "recovery preflight system")
    if (
        set(preflight) != preflight_fields
        or preflight.get("schema") != PREFLIGHT_SCHEMA
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight.get("passed") is not True
        or preflight.get("config_sha256") != config_sha
        or preflight.get("input_sha256") != expected_input_sha
        or preflight.get("source_sha256")
        != _mapping(config_source["expected_sha256"], "config source SHA")
        or preflight.get("parent_result_sha256") != config_parent["result_sha256"]
        or preflight.get("parent_capsule_manifest_sha256")
        != config_parent["capsule_manifest_sha256"]
        or preflight.get("prepared_artifacts") != prepared_rows
        or set(published)
        != {
            "path",
            "manifest_sha256",
            "manifest_bytes",
            "all_artifact_seals_verified",
            "manifest_schema",
            "native_capacity_proof",
            "native_capacity_proof_verified_before_intent",
        }
        or published.get("path") != config_preparation["published_directory"]
        or published.get("manifest_sha256") != config_preparation["manifest_sha256"]
        or published.get("manifest_bytes") != config_preparation["manifest_bytes"]
        or published.get("all_artifact_seals_verified") is not True
        or published.get("manifest_schema") != PREPARATION_SCHEMA
        or published.get("native_capacity_proof")
        != _validate_native_capacity_proof(prepared.manifest["page20"])
        or published.get("native_capacity_proof_verified_before_intent") is not True
        or preflight.get("page20_sha256") != PAGE20_SHA256
        or preflight.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or preflight.get("priority_state_receipt") != prepared_rows[RECEIPT_NAME]
        or preflight.get("inherited_derived_resolution_triplet")
        != {
            "receipt": prepared_rows[INHERITED_DERIVED_RECEIPT_NAME],
            "closure": prepared_rows[INHERITED_DERIVED_CLOSURE_NAME],
            "overlay": prepared_rows[INHERITED_DERIVED_OVERLAY_NAME],
        }
        or preflight.get("new_derived_resolution_triplet")
        != {
            "receipt": prepared_rows[DERIVED_RECEIPT_NAME],
            "closure": prepared_rows[DERIVED_CLOSURE_NAME],
            "overlay": prepared_rows[DERIVED_OVERLAY_NAME],
        }
        or preflight.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
        or preflight.get("global_novelty_baseline_clause_count")
        != LOGICAL_KNOWN_CLAUSE_COUNT
        or preflight.get("compiler") != str(recovery_compiler)
        or preflight.get("cadical_include") != str(recovery_include)
        or preflight.get("cadical_library") != str(recovery_library)
        or system.get("system") != "Darwin"
        or system.get("machine") != "arm64"
        or system.get("sibling_solver_pids") != []
        or _positive(system.get("physical_memory_bytes"), "recovery physical memory")
        < MEMORY_LIMIT_BYTES
        or _positive(system.get("available_memory_bytes"), "recovery available memory")
        < MEMORY_LIMIT_BYTES
        or _nonnegative(system.get("disk_free_bytes"), "recovery disk")
        < MINIMUM_DISK_FREE_BYTES
        or preflight.get("native_solver_calls") != 0
        or preflight.get("target_bytes_read") is not False
        or preflight.get("truth_key_bytes_read") is not False
        or any(
            preflight.get(name) != 0
            for name in ("reveal_calls", "refits", "mps_calls", "gpu_calls")
        )
    ):
        raise O1C105RunError("existing capsule preflight provenance differs")

    build_path = capsule / "native-build.json"
    build = dict(_read_canonical_json(build_path, "capsule native build"))
    executable, smoke = _validate_staged_native_build(
        capsule=capsule,
        config=config,
        build=build,
        require_executable_identity=completed_success,
    )
    invocation_path = capsule / "invocation.json"
    invocation = dict(_read_canonical_json(invocation_path, "capsule invocation"))
    invocation_fields = {
        "schema",
        "attempt_id",
        "config_sha256",
        "local_episode_ordinal",
        "lineage_call_ordinal",
        "page20_sha256",
        "continuation_bank_sha256",
        "rollover_manifest_sha256",
        "priority_state_receipt_sha256",
        *DERIVED_NAMESPACE_SHA256_FIELDS,
        "candidate_order_sha256",
        "global_novelty_baseline_clause_count",
        "threshold",
        "seed",
        "requested_conflicts",
        "maximum_native_solver_calls",
        "timeout_seconds",
        "memory_limit_bytes",
        "initial_artifacts",
        "native_build_sha256",
        "native_executable",
        "native_smoke",
        "retry_authorized",
        "replay_authorized",
        "target_input_present",
        "truth_input_present",
    }
    expected_initial_rows = {
        name: _artifact_row(initial / name, relative_to=initial)
        for name in sorted(STAGED_INITIAL_NAMES)
    }
    if (
        set(invocation) != invocation_fields
        or invocation.get("schema") != INVOCATION_SCHEMA
        or invocation.get("attempt_id") != ATTEMPT_ID
        or invocation.get("config_sha256") != config_sha
        or invocation.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or invocation.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or invocation.get("page20_sha256") != PAGE20_SHA256
        or invocation.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or invocation.get("rollover_manifest_sha256") != PUBLISHED_MANIFEST_SHA256
        or invocation.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or any(
            invocation.get(name) != digest
            for name, digest in DERIVED_NAMESPACE_SHA256_FIELDS.items()
        )
        or invocation.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
        or invocation.get("global_novelty_baseline_clause_count")
        != LOGICAL_KNOWN_CLAUSE_COUNT
        or invocation.get("threshold") != THRESHOLD
        or invocation.get("seed") != SEED
        or invocation.get("requested_conflicts") != REQUESTED_CONFLICTS
        or invocation.get("maximum_native_solver_calls") != MAXIMUM_NATIVE_CALLS
        or invocation.get("timeout_seconds") != TIMEOUT_SECONDS
        or invocation.get("memory_limit_bytes") != MEMORY_LIMIT_BYTES
        or invocation.get("initial_artifacts") != expected_initial_rows
        or invocation.get("native_build_sha256") != _sha_file(build_path)
        or invocation.get("native_executable") != executable
        or invocation.get("native_smoke") != smoke
        or invocation.get("retry_authorized") is not False
        or invocation.get("replay_authorized") is not False
        or invocation.get("target_input_present") is not False
        or invocation.get("truth_input_present") is not False
    ):
        raise O1C105RunError("existing capsule invocation provenance differs")
    _rehash_call_inputs(
        root=root,
        config_path=config_path,
        config=config,
        preflight_row=preflight,
        capsule=capsule,
        invocation=invocation,
        require_executable_identity=completed_success,
    )

    intent_path = episode_dir / "intent.json"
    intent = dict(_read_canonical_json(intent_path, "capsule intent"))
    intent_fields = {
        "schema",
        "attempt_id",
        "created_at",
        "local_episode_ordinal",
        "lineage_call_ordinal",
        "config_sha256",
        "invocation_sha256",
        "page20_sha256",
        "continuation_bank_sha256",
        "rollover_manifest_sha256",
        "priority_state_receipt_sha256",
        *DERIVED_NAMESPACE_SHA256_FIELDS,
        "native_executable",
        "candidate_order_sha256",
        "requested_conflicts",
        "page20_burned",
        "lineage33_burned",
        "burn_on_persisted_intent",
        "retry_authorized",
        "replay_authorized",
        "page19_retry_or_replay_authorized",
        "page18_retry_or_replay_authorized",
        "page17_retry_or_replay_authorized",
        "page16_retry_or_replay_authorized",
        "page15_retry_or_replay_authorized",
        "page14_replay_authorized",
        "page13_replay_authorized",
        "page12_replay_authorized",
        "page11_replay_authorized",
        "page10_replay_authorized",
        "page9_retry_or_replay_authorized",
        "truth_key_bytes_read",
        "target_bytes_read",
    }
    retry_fields = (
        "retry_authorized",
        "replay_authorized",
        "page19_retry_or_replay_authorized",
        "page18_retry_or_replay_authorized",
        "page17_retry_or_replay_authorized",
        "page16_retry_or_replay_authorized",
        "page15_retry_or_replay_authorized",
        "page14_replay_authorized",
        "page13_replay_authorized",
        "page12_replay_authorized",
        "page11_replay_authorized",
        "page10_replay_authorized",
        "page9_retry_or_replay_authorized",
    )
    invocation_sha = _sha_file(invocation_path)
    if (
        set(intent) != intent_fields
        or intent.get("schema") != INTENT_SCHEMA
        or intent.get("attempt_id") != ATTEMPT_ID
        or _validated_timestamp(intent.get("created_at"), "intent timestamp")
        != intent.get("created_at")
        or intent.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or intent.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or intent.get("config_sha256") != config_sha
        or intent.get("invocation_sha256") != invocation_sha
        or intent.get("page20_sha256") != PAGE20_SHA256
        or intent.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or intent.get("rollover_manifest_sha256") != PUBLISHED_MANIFEST_SHA256
        or intent.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or any(
            intent.get(name) != digest
            for name, digest in DERIVED_NAMESPACE_SHA256_FIELDS.items()
        )
        or intent.get("native_executable") != executable
        or intent.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or intent.get("requested_conflicts") != REQUESTED_CONFLICTS
        or intent.get("page20_burned") is not True
        or intent.get("lineage33_burned") is not True
        or intent.get("burn_on_persisted_intent") is not True
        or any(intent.get(name) is not False for name in retry_fields)
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("target_bytes_read") is not False
    ):
        raise O1C105RunError("existing capsule burn intent differs")

    episode = dict(_read_canonical_json(episode_path, "capsule episode"))
    if episode != episode_preview:
        raise O1C105RunError("capsule episode changed during validation")
    episode_common_fields = {
        "schema",
        "completed",
        "local_episode_ordinal",
        "lineage_call_ordinal",
        "config_sha256",
        "invocation_sha256",
        "intent_sha256",
        "page20_burned",
        "lineage33_burned",
        "native_call_issued",
        "native_result_returned",
        "native_calls_consumed",
        "requested_conflicts",
        "actual_conflicts",
        "billed_conflicts",
        "native_stdout",
        "operational",
        "science",
        "classification",
        "stop_reason",
        *retry_fields,
        "terminal_failure",
    }
    if (
        episode.get("schema") != EPISODE_SCHEMA
        or episode.get("local_episode_ordinal") != LOCAL_EPISODE_ORDINAL
        or episode.get("lineage_call_ordinal") != LINEAGE_CALL_ORDINAL
        or episode.get("config_sha256") != config_sha
        or episode.get("invocation_sha256") != invocation_sha
        or episode.get("intent_sha256") != _sha_file(intent_path)
        or episode.get("page20_burned") is not True
        or episode.get("lineage33_burned") is not True
        or any(episode.get(name) is not False for name in retry_fields)
    ):
        raise O1C105RunError("existing capsule episode lineage differs")

    expected_episode_inventory: set[str]
    if episode.get("completed") is True:
        success_fields = episode_common_fields | {
            "status",
            "archived_native_components",
            "final_priority_bank",
            "resources",
            "work",
            "key_model_sha256",
        }
        if (
            set(episode) != success_fields
            or episode.get("native_call_issued") is not True
            or episode.get("native_result_returned") is not True
            or episode.get("native_calls_consumed") != 1
            or episode.get("requested_conflicts") != REQUESTED_CONFLICTS
            or episode.get("terminal_failure") is not None
        ):
            raise O1C105RunError("existing completed episode call contract differs")
        stdout_path = _validate_capsule_artifact_row(
            episode_dir, episode.get("native_stdout"), NATIVE_STDOUT_NAME
        )
        archived = _mapping(
            episode.get("archived_native_components"), "archived native components"
        )
        if set(archived) != set(NATIVE_ARCHIVE_NAMES):
            raise O1C105RunError("archived native component inventory differs")
        component_paths = {
            name: _validate_capsule_artifact_row(
                episode_dir,
                archived[name],
                name,
                canonical_json=name.endswith(".json"),
            )
            for name in NATIVE_ARCHIVE_NAMES
        }
        if episode.get("final_priority_bank") != archived[FINAL_BANK_NAME]:
            raise O1C105RunError("final priority bank row differs")
        expected_episode_inventory = {
            "intent.json",
            "episode.json",
            NATIVE_STDOUT_NAME,
            *NATIVE_ARCHIVE_NAMES,
        }

        stdout = stdout_path.read_bytes()
        try:
            raw = dict(_native_v34._v21.load_native_json(stdout))
        except Exception as exc:
            raise O1C105RunError("archived native stdout differs") from exc
        archived_raw = dict(
            _read_canonical_json(
                component_paths["native-result.json"], "archived native result"
            )
        )
        adapter_memory = dict(
            _read_canonical_json(
                component_paths["adapter-memory.json"], "archived adapter memory"
            )
        )
        priority_seed = dict(
            _read_canonical_json(
                component_paths["priority-seed.json"], "archived priority seed"
            )
        )
        priority_state = dict(
            _read_canonical_json(
                component_paths["priority-state.json"], "archived priority state"
            )
        )
        priority_actions = dict(
            _read_canonical_json(
                component_paths["priority-actions.json"], "archived priority actions"
            )
        )
        ownership = dict(
            _read_canonical_json(
                component_paths["decision-ownership.json"], "archived ownership"
            )
        )
        base_sieve = dict(
            _read_canonical_json(
                component_paths["base-sieve.json"], "archived base sieve"
            )
        )
        vault = dict(
            _read_canonical_json(component_paths["vault.json"], "archived vault")
        )
        native_resources = dict(
            _read_canonical_json(
                component_paths["resources.json"], "archived native resources"
            )
        )
        final_bank = component_paths[FINAL_BANK_NAME].read_bytes()
        evidence = _semantic_replay_completed_native(
            root=root,
            config=config,
            prepared=prepared,
            stdout=stdout,
            adapter_memory=adapter_memory,
        )
        work = dict(evidence.stats)
        status = evidence.status
        key_hex = raw.get("key_model_hex")
        key_model = evidence.key_model
        if status == 10:
            if (
                not isinstance(key_hex, str)
                or len(key_hex) != 64
                or key_model is None
                or key_model.hex() != key_hex
            ):
                raise O1C105RunError("archived SAT key model differs")
            if (
                len(key_model) != 32
                or episode.get("key_model_sha256") != sha256_bytes(key_model)
                or not (
                    public_verifier
                    if public_verifier is not None
                    else _public_verifier(root=root, config=config)
                )(key_model)
            ):
                raise O1C105RunError("archived SAT key model is not publicly verified")
        elif status in (0, 20):
            if key_hex is not None or episode.get("key_model_sha256") is not None:
                raise O1C105RunError("archived non-SAT key model differs")
        else:
            raise O1C105RunError("archived native status differs")
        try:
            bank_hex = bytes.fromhex(cast(str, priority_state.get("bank_hex")))
        except (TypeError, ValueError) as exc:
            raise O1C105RunError("archived final bank encoding differs") from exc
        if (
            raw != archived_raw
            or evidence.raw != raw
            or evidence.adapter_memory != adapter_memory
            or evidence.priority_seed != priority_seed
            or evidence.priority_state != priority_state
            or evidence.priority_actions != priority_actions
            or evidence.ownership != ownership
            or evidence.base_sieve != base_sieve
            or evidence.vault != vault
            or evidence.resources != native_resources
            or evidence.final_bank != final_bank
            or raw.get("schema") != _native_v34.JOINT_SCORE_SIEVE_RESULT_SCHEMA
            or raw.get("seed") != SEED
            or raw.get("threshold") != THRESHOLD
            or raw.get("conflict_limit") != REQUESTED_CONFLICTS
            or raw.get("cnf_sha256") != config_inputs["cnf_sha256"]
            or raw.get("potential_sha256") != config_inputs["potential_sha256"]
            or raw.get("active_vault_sha256") != PAGE20_SHA256
            or raw.get("priority_seed") != priority_seed
            or raw.get("priority_state") != priority_state
            or raw.get("priority_actions") != priority_actions
            or raw.get("decision_ownership") != ownership
            or raw.get("base_sieve") != base_sieve
            or raw.get("vault") != vault
            or raw.get("resources") != native_resources
            or priority_seed.get("payload_sha256") != CONTINUATION_BANK_SHA256
            or priority_seed.get("payload_bytes") != CONTINUATION_BANK_BYTES
            or len(final_bank) != CONTINUATION_BANK_BYTES
            or bank_hex != final_bank
            or priority_state.get("bank_bytes") != CONTINUATION_BANK_BYTES
            or priority_state.get("current_bank_sha256") != sha256_bytes(final_bank)
            or episode.get("status") != status
            or episode.get("resources") != native_resources
            or episode.get("work") != work
            or episode.get("actual_conflicts") != work["solve_conflicts"]
            or episode.get("billed_conflicts") != work["billed_conflicts"]
        ):
            raise O1C105RunError("archived native result cross-binding differs")
        operation, science, classification, stop = _science_and_operation(
            evidence,
            globally_known_clause_sha256=prepared.globally_known_clause_sha256,
            public_model_verified=key_model is not None,
        )
        if (
            episode.get("operational") != operation
            or episode.get("science") != science
            or episode.get("classification") != classification
            or episode.get("stop_reason") != stop
        ):
            raise O1C105RunError("completed episode science projection differs")
    elif episode.get("completed") is False:
        terminal_calls = episode.get("native_calls_consumed")
        if (
            isinstance(terminal_calls, bool)
            or not isinstance(terminal_calls, int)
            or terminal_calls not in (0, 1)
        ):
            raise O1C105RunError("terminal episode call count differs")
        if (
            set(episode) != episode_common_fields
            or episode.get("classification") != OPERATIONAL_TERMINAL
            or episode.get("stop_reason") != "burned-terminal-failure-no-retry"
            or episode.get("science") != {"science_gain": False}
            or episode.get("operational") != {"operational_activation": False}
            or episode.get("native_call_issued") is not (terminal_calls == 1)
            or episode.get("native_result_returned") is True
            and episode.get("native_call_issued") is not True
            or episode.get("requested_conflicts")
            != terminal_calls * REQUESTED_CONFLICTS
            or episode.get("actual_conflicts") is not None
            or episode.get("billed_conflicts") is not None
        ):
            raise O1C105RunError("terminal episode contract differs")
        failure_path = episode_dir / "terminal-failure.json"
        failure = dict(_read_canonical_json(failure_path, "capsule terminal failure"))
        if (
            episode.get("terminal_failure") != failure
            or failure.get("schema")
            != "o1-256-apple8-parent-centered-continuation-terminal-failure-v1"
            or failure.get("classification") != OPERATIONAL_TERMINAL
            or failure.get("occurred_after_persisted_intent") is not True
            or failure.get("page20_burned") is not True
            or failure.get("lineage33_burned") is not True
            or failure.get("native_call_issued")
            is not episode.get("native_call_issued")
            or failure.get("native_result_returned")
            is not episode.get("native_result_returned")
            or failure.get("native_calls_consumed")
            != episode.get("native_calls_consumed")
            or failure.get("requested_conflicts_consumed")
            != episode.get("requested_conflicts")
            or failure.get("actual_conflicts") is not None
            or failure.get("billed_conflicts") is not None
            or failure.get("science_gain") is not False
            or any(failure.get(name) is not False for name in retry_fields)
        ):
            raise O1C105RunError("terminal failure cross-binding differs")
        stdout_row = episode.get("native_stdout")
        if failure.get("native_stdout") != stdout_row:
            raise O1C105RunError("terminal native stdout row differs")
        if not native_inventory:
            if not (
                failure.get("phase") == "PRE_CALL"
                and failure.get("exception_type") == "O1C105RunError"
                and failure.get("message") == "native executable is unreadable"
                and failure.get("native_call_issued") is False
                and failure.get("native_result_returned") is False
                and failure.get("native_calls_consumed") == 0
                and failure.get("requested_conflicts_consumed") == 0
                and failure.get("native_stdout") is None
                and failure.get("native_process_evidence") is None
                and stdout_row is None
            ):
                raise O1C105RunError("missing terminal executable provenance differs")
        else:
            observed_executable = _executable_identity(
                capsule / "native" / NATIVE_EXECUTABLE_NAME,
                relative_path=f"native/{NATIVE_EXECUTABLE_NAME}",
            )
            if observed_executable != executable and not (
                failure.get("phase") == "PRE_CALL"
                and failure.get("native_calls_consumed") == 0
                and failure.get("message")
                in {
                    "staged native executable differs",
                    "native executable call seal differs",
                }
            ):
                raise O1C105RunError("terminal executable provenance differs")
        expected_episode_inventory = {
            "intent.json",
            "episode.json",
            "terminal-failure.json",
        }
        if stdout_row is not None:
            _validate_capsule_artifact_row(episode_dir, stdout_row, NATIVE_STDOUT_NAME)
            expected_episode_inventory.add(NATIVE_STDOUT_NAME)
    else:
        raise O1C105RunError("existing capsule episode completion differs")

    try:
        observed_episode_inventory = {path.name for path in episode_dir.iterdir()}
    except OSError as exc:
        raise O1C105RunError("episode inventory is unreadable") from exc
    if observed_episode_inventory != expected_episode_inventory:
        raise O1C105RunError("episode artifact inventory differs")

    result_path = capsule / "result.json"
    result_payload = result_path.read_bytes()
    result = dict(_read_canonical_json(result_path, "capsule result"))
    expected_capsule = capsule.relative_to(root).as_posix()
    result_fields = {
        "schema",
        "attempt_id",
        "started_at",
        "recorded_at",
        "capsule",
        "classification",
        "stop_reason",
        "operational_activation",
        "science_gain",
        "episodes",
        "claim_boundary",
        "resources",
        "preflight",
        "next_action",
    }
    episodes = _sequence(result.get("episodes"), "result episodes")
    resources = _mapping(result.get("resources"), "result resources")
    science = _mapping(episode.get("science"), "episode science")
    operational = _mapping(episode.get("operational"), "episode operational")
    claim = _mapping(result.get("claim_boundary"), "result claim boundary")
    expected_claim = {
        "failure_first_action_alone_is_science_gain": False,
        "nonclaim_digest_alone_is_science_gain": False,
        "priority_is_key_bit_belief": False,
        "science_requires": [
            "actual-certified-prune",
            "certified-closure",
            "globally-novel-clause",
            "certified-model-or-key",
            "attacker-valid-entropy-or-domain-gain",
        ],
        "config_sha256": config_sha,
        "page20_sha256": PAGE20_SHA256,
        "input_continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
        "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
        **DERIVED_NAMESPACE_SHA256_FIELDS,
        "global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        "page20_burned": True,
        "lineage33_only": True,
        "page19_retry_or_replay_authorized": False,
        "page18_retry_or_replay_authorized": False,
        "page17_retry_or_replay_authorized": False,
        "page16_retry_or_replay_authorized": False,
        "page15_retry_or_replay_authorized": False,
        "page14_replay_authorized": False,
        "page13_replay_authorized": False,
        "page12_replay_authorized": False,
        "page11_replay_authorized": False,
        "page10_replay_authorized": False,
        "page9_retry_or_replay_authorized": False,
        "retry_or_replay": False,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "fresh_reveal_calls": 0,
        "refits": 0,
        "mps_or_gpu": False,
    }
    expected_resource_fields = {
        "native_solver_calls",
        "requested_conflicts",
        "actual_conflicts",
        "billed_conflicts",
        "memory_watchdog_bytes",
        "wall_seconds",
        "cpu_seconds",
        "child_user_seconds",
        "child_system_seconds",
        "maximum_persistent_artifact_bytes",
    }
    if (
        set(result) != result_fields
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("capsule") != expected_capsule
        or _validated_timestamp(result.get("started_at"), "result start timestamp")
        != result.get("started_at")
        or _validated_timestamp(result.get("recorded_at"), "result timestamp")
        != result.get("recorded_at")
        or len(episodes) != 1
        or episodes[0] != episode
        or result.get("classification") != episode.get("classification")
        or result.get("stop_reason") != episode.get("stop_reason")
        or result.get("science_gain") is not (science.get("science_gain") is True)
        or result.get("operational_activation")
        is not (operational.get("operational_activation") is True)
        or result.get("preflight") != preflight
        or claim != expected_claim
        or set(resources) != expected_resource_fields
        or resources.get("native_solver_calls") != episode.get("native_calls_consumed")
        or resources.get("requested_conflicts") != episode.get("requested_conflicts")
        or resources.get("actual_conflicts") != episode.get("actual_conflicts")
        or resources.get("billed_conflicts") != episode.get("billed_conflicts")
        or resources.get("memory_watchdog_bytes") != MEMORY_LIMIT_BYTES
        or resources.get("maximum_persistent_artifact_bytes")
        != MAXIMUM_PERSISTENT_ARTIFACT_BYTES
        or any(
            _nonnegative_finite(resources.get(name), f"result {name}") < 0
            for name in (
                "wall_seconds",
                "cpu_seconds",
                "child_user_seconds",
                "child_system_seconds",
            )
        )
        or result.get("next_action")
        != "Never retry or replay Page 20 / lineage 33 or Pages 19 through 9; preserve the final priority bank only as a continuation seed."
        or (capsule / "RUN.md").read_bytes() != _run_markdown(result)
    ):
        raise O1C105RunError("existing capsule result differs")
    return result, result_payload


def _republish_existing_capsule(
    root: Path,
    capsule: Path,
    *,
    public_verifier: Callable[[bytes], bool] | None = None,
) -> dict[str, object]:
    result, payload = _validated_capsule_result(
        root, capsule, public_verifier=public_verifier
    )
    _publish_exact(root / RESULT_RELATIVE, payload)
    return result


def _public_verifier(
    *, root: Path, config: Mapping[str, object]
) -> Callable[[bytes], bool]:
    inputs = _mapping(config["inputs"], "public verifier inputs")
    config_path = _lab_path(root, inputs["o1c73_config"], "O1C73 verifier config")
    if _sha_file(config_path) != inputs["o1c73_config_sha256"]:
        raise O1C105RunError("public verifier config SHA differs")
    try:
        baseline_config = _o1c73.load_config(config_path)
        baseline = _o1c73.validate_apple8_baseline(root, baseline_config)
        verifier = _o1c73._o1c66._public_target(baseline).verify
    except Exception as exc:
        raise O1C105RunError("public ChaCha verifier cannot be established") from exc
    return cast(Callable[[bytes], bool], verifier)


def run(
    config_path: str | Path = CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    adapter_run: AdapterRun = _native_v34.run_joint_score_sieve,
    command_runner: Callable[..., object] = subprocess.run,
    system_probe: Callable[[Path], Mapping[str, object]] = _default_system_probe,
    public_verifier: Callable[[bytes], bool] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now().astimezone(),
) -> dict[str, object]:
    """Run the sole fresh call or return sealed evidence without replay."""

    lab = (root or lab_root()).resolve(strict=True)
    capsules = _existing_capsules(lab)
    existing = _existing_result(lab)
    if existing is not None:
        if len(capsules) != 1:
            raise O1C105RunError("authoritative O1C105 result lacks one sealed capsule")
        capsule_result, capsule_payload = _validated_capsule_result(
            lab, capsules[0], public_verifier=public_verifier
        )
        authoritative_payload = (lab / RESULT_RELATIVE).read_bytes()
        if capsule_payload != authoritative_payload or capsule_result != existing:
            raise O1C105RunError("authoritative O1C105 result differs from capsule")
        return existing
    if capsules:
        if len(capsules) != 1:
            raise O1C105RunError("multiple O1C105 capsules forbid replay")
        return _republish_existing_capsule(
            lab, capsules[0], public_verifier=public_verifier
        )

    config_file = Path(config_path).resolve(strict=True)
    bundle = _preflight_bundle(
        config_file,
        root=lab,
        system_probe=system_probe,
    )
    verified_public_model = (
        public_verifier
        if public_verifier is not None
        else _public_verifier(root=lab, config=bundle.config)
    )
    globally_known = bundle.prepared.globally_known_clause_sha256
    capsule, invocation = _stage_capsule(
        root=lab,
        config_path=config_file,
        bundle=bundle,
        command_runner=command_runner,
        now=now,
    )
    started_at = now().astimezone().isoformat(timespec="microseconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    episode, classification, stop, science_gain, calls, actual, billed = _execute_once(
        root=lab,
        config_path=config_file,
        capsule=capsule,
        bundle=bundle,
        invocation=invocation,
        adapter_run=adapter_run,
        verify_public_model=verified_public_model,
        globally_known_clause_sha256=globally_known,
        now=now,
    )
    children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": now().astimezone().isoformat(timespec="microseconds"),
        "capsule": capsule.relative_to(lab).as_posix(),
        "classification": classification,
        "stop_reason": stop,
        "operational_activation": _mapping(
            episode.get("operational"), "episode operational"
        ).get("operational_activation")
        is True,
        "science_gain": science_gain,
        "episodes": [episode],
        "claim_boundary": {
            "failure_first_action_alone_is_science_gain": False,
            "nonclaim_digest_alone_is_science_gain": False,
            "priority_is_key_bit_belief": False,
            "science_requires": [
                "actual-certified-prune",
                "certified-closure",
                "globally-novel-clause",
                "certified-model-or-key",
                "attacker-valid-entropy-or-domain-gain",
            ],
            "config_sha256": bundle.row["config_sha256"],
            "page20_sha256": PAGE20_SHA256,
            "input_continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            **DERIVED_NAMESPACE_SHA256_FIELDS,
            "global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "page20_burned": True,
            "lineage33_only": True,
            "page19_retry_or_replay_authorized": False,
            "page18_retry_or_replay_authorized": False,
            "page17_retry_or_replay_authorized": False,
            "page16_retry_or_replay_authorized": False,
            "page15_retry_or_replay_authorized": False,
            "page14_replay_authorized": False,
            "page13_replay_authorized": False,
            "page12_replay_authorized": False,
            "page11_replay_authorized": False,
            "page10_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
            "retry_or_replay": False,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "mps_or_gpu": False,
        },
        "resources": {
            "native_solver_calls": calls,
            "requested_conflicts": calls * REQUESTED_CONFLICTS,
            "actual_conflicts": actual,
            "billed_conflicts": billed,
            "memory_watchdog_bytes": MEMORY_LIMIT_BYTES,
            "wall_seconds": time.perf_counter() - started,
            "cpu_seconds": time.process_time() - cpu_started,
            "child_user_seconds": children_finished.ru_utime
            - children_started.ru_utime,
            "child_system_seconds": children_finished.ru_stime
            - children_started.ru_stime,
            "maximum_persistent_artifact_bytes": MAXIMUM_PERSISTENT_ARTIFACT_BYTES,
        },
        "preflight": dict(bundle.row),
        "next_action": "Never retry or replay Page 20 / lineage 33 or Pages 19 through 9; preserve the final priority bank only as a continuation seed.",
    }
    return _finalize_capsule(
        capsule=capsule, authoritative=lab / RESULT_RELATIVE, result=result
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or execute O1C105's one Page-20 parent-centered call"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", default=str(CONFIG_RELATIVE))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        value = (
            preflight(args.config) if args.command == "preflight" else run(args.config)
        )
        sys.stdout.buffer.write(canonical_json_bytes(value))
        return 0
    except O1C105RunError as exc:
        print(f"O1C105: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVATION_ONLY",
    "CONFIG_RELATIVE",
    "MEMORY_LIMIT_BYTES",
    "O1C105RunError",
    "OPERATIONAL_TERMINAL",
    "REQUESTED_CONFLICTS",
    "RESULT_RELATIVE",
    "THRESHOLD",
    "load_config",
    "main",
    "preflight",
    "run",
]
