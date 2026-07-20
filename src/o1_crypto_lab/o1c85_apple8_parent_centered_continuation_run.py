"""Burn-on-intent runner for the single O1C-0085 Page-10 call.

The runner has one scientific side effect: after an immutable intent is
persisted it may invoke native v21 once, with seed zero and 128 requested
conflicts.  Failure-first priority actions are operational evidence, never a
bit belief or science gain by themselves.  Its preparation gate reads only
the published, sealed O1C-0085 transport-recovery bundle; it never regenerates
the expensive causal residency history.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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

from . import joint_score_sieve_v24 as _native_v24
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .causal_attic_v1 import canonical_json_bytes, sha256_bytes
from .o1c83_apple8_causal_rollover_prepare import (
    CONTINUATION_CANDIDATE_ORDER_SHA256,
)
from .o1c85_page10_transport_recovery_prepare import (
    ACTIVE_PROJECTION_NAME,
    ACTIVATION_LEDGER_NAME,
    COMMON_CORE_AUDIT_NAME,
    CONTINUATION_BANK_BYTES,
    CONTINUATION_BANK_SHA256,
    DEFAULT_PARENT_CAPSULE_RELATIVE,
    DEFAULT_PARENT_RESULT_RELATIVE,
    FAILURE_RECEIPT_NAME,
    FINAL_BANK_NAME as PREPARED_CONTINUATION_BANK_NAME,
    OCCURRENCES_NAME,
    PAGE10_ACTIVE_LIMIT,
    PAGE10_CATEGORY_COUNTS,
    PAGE10_CLAUSE_COUNT,
    PAGE10_HEADROOM,
    PAGE10_LITERAL_COUNT,
    PAGE10_SERIALIZED_BYTES,
    PAGE10_SHA256,
    PARENT_CAPSULE_MANIFEST_SHA256,
    PARENT_FAILURE_SHA256,
    PARENT_INTENT_SHA256,
    PARENT_RESULT_SHA256,
    PREPARATION_MANIFEST_NAME,
    PREPARATION_SCHEMA,
    PRIORITY_RECEIPT_BYTES,
    PRIORITY_RECEIPT_SHA256,
    RELATIONS_NAME,
    RESIDENCY_NAME,
)
from .threshold_no_good_vault_v1 import O1C66_VAULT_CAPS, ThresholdNoGoodClause


ATTEMPT_ID = "O1C-0085"
CONFIG_SCHEMA = "o1-256-apple8-parent-centered-continuation-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-parent-centered-continuation-preflight-v1"
NATIVE_BUILD_SCHEMA = "o1-256-o1c85-native-v21-build-v1"
INVOCATION_SCHEMA = "o1-256-apple8-parent-centered-continuation-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-parent-centered-continuation-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-parent-centered-continuation-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-parent-centered-continuation-result-v1"

CONFIG_RELATIVE = Path("configs/o1c85_apple8_parent_centered_continuation_v1.json")
RESULT_RELATIVE = Path(
    "research/O1C0085_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)
CAPSULE_SUFFIX = "O1C-0085_apple8-parent-centered-continuation-v1"

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 23
SEED = 0
THRESHOLD = 14.606178797892962
REQUESTED_CONFLICTS = 128
MAXIMUM_NATIVE_CALLS = 1
TIMEOUT_SECONDS = 45.0
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
RECEIPT_NAME = "o1c82-priority-state-receipt.json"
PUBLISHED_PREPARATION_RELATIVE = Path(
    "research/o1c85_page10_transport_recovery_seed_20260720"
)
# Filled only from the atomically published preparation bundle.  These are
# preparation identities, never compiler-output predictions.
PUBLISHED_MANIFEST_SHA256 = (
    "d512f675d7076ecc650ce93052d60b8db1d1ed206d5b8d119118bdcec310c42c"
)
PUBLISHED_MANIFEST_BYTES = 4_594
CONTINUATION_BANK_NAME = PREPARED_CONTINUATION_BANK_NAME
PRIORITY_RECEIPT_RELATIVE = (
    Path("runs/20260720_143008_461948_O1C-0082_apple8-parent-centered-v1")
    / "episodes/00/priority-state.json"
)

ATTIC_CHUNK_COUNT = 13
ATTIC_UNION_CLAUSE_COUNT = 807
ATTIC_OCCURRENCE_COUNT = 815
ATTIC_SUBSUMPTION_RELATION_COUNT = 9
ATTIC_UNDOMINATED_CLAUSE_COUNT = 801
PARENT_CAPSULE_ENTRY_COUNT = 20

NATIVE_V21_USAGE = (
    b"usage: cadical_o1_joint_score_sieve_v21 --cnf PATH "
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
        FAILURE_RECEIPT_NAME,
        OCCURRENCES_NAME,
        PREPARATION_MANIFEST_NAME,
        RELATIONS_NAME,
        RESIDENCY_NAME,
    }
)
STAGED_INITIAL_NAMES = PREPARATION_ARTIFACT_NAMES | {RECEIPT_NAME}

PUBLISHED_ARTIFACT_SEALS: Mapping[str, tuple[int, str, str]] = {
    ACTIVATION_LEDGER_NAME: (
        19_089,
        "1b20f7e281638995f235844822e7853e29f0c3e2bc5f64c63325cf64c1058b2a",
        "complete-updated-replayable-activation-ledger",
    ),
    COMMON_CORE_AUDIT_NAME: (
        20_115,
        "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c",
        "unchanged-public-common-core-bound-audit",
    ),
    CONTINUATION_BANK_NAME: (
        CONTINUATION_BANK_BYTES,
        CONTINUATION_BANK_SHA256,
        "unchanged-sealed-live-continuation-bank-bytes",
    ),
    FAILURE_RECEIPT_NAME: (
        889,
        PARENT_FAILURE_SHA256,
        "canonical-o1c84-terminal-failure-receipt",
    ),
    OCCURRENCES_NAME: (
        288_536,
        "b011f4c7bbda808fc78827353fe39ddec334b067f4744bd89f1a3bc31dcacb1f",
        "unchanged-compact-witness-occurrence-ledger",
    ),
    ACTIVE_PROJECTION_NAME: (
        PAGE10_SERIALIZED_BYTES,
        PAGE10_SHA256,
        "fresh-lineage-23-page10-science-input",
    ),
    RESIDENCY_NAME: (
        36_924,
        "ca899f7094878eaad33068d30f0eaf5eaee06b6fd979042e732a8e53fe8b8bde",
        "complete-updated-causal-residency-state",
    ),
    RELATIONS_NAME: (
        6_019,
        "c599e44573e5c1be1740d1bd6fe40970cf562746e9e77ee927d7021030b58e43",
        "unchanged-strict-subsumption-closure",
    ),
}

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c85_apple8_parent_centered_continuation_run.py",
    "runner_tests": "tests/test_o1c85_apple8_parent_centered_continuation_run.py",
    "adapter_v24": "src/o1_crypto_lab/joint_score_sieve_v24.py",
    "adapter_v24_tests": "tests/test_joint_score_sieve_v24.py",
    "transport_recovery_preparation": "src/o1_crypto_lab/o1c85_page10_transport_recovery_prepare.py",
    "transport_recovery_preparation_tests": "tests/test_o1c85_page10_transport_recovery_prepare.py",
    "causal_rollover_preparation": "src/o1_crypto_lab/o1c83_apple8_causal_rollover_prepare.py",
    "parent_preparation": "src/o1_crypto_lab/o1c82_apple8_parent_centered_prepare.py",
    "seed_compiler": "src/o1_crypto_lab/o1c82_parent_centered_seed.py",
    "causal_attic": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency": "src/o1_crypto_lab/causal_residency_v1.py",
    "threshold_vault": "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
    "public_verifier": "src/o1_crypto_lab/o1c73_apple8_vault_release_contrast_run.py",
    "native_v21": "native/cadical_o1_joint_score_sieve_v21.cpp",
    "priority_header": "native/o1c82_parent_centered_priority.hpp",
    "native_v18": "native/cadical_o1_joint_score_sieve_v18.cpp",
    "ownership_header": "native/o1c80_decision_ownership.hpp",
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
    "native_v21",
    "priority_header",
    "native_v18",
    "ownership_header",
    "bound_header",
    "native_v16",
    "native_v15",
    "native_v14",
    "native_v12",
    "native_v11",
    "native_v6",
    "native_base",
)
COMPILER_FLAGS = (
    "-std=c++17",
    "-O2",
    "-DNDEBUG",
    "-Wall",
    "-Wextra",
    "-Werror",
)


class O1C85RunError(RuntimeError):
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
    receipt: bytes


@dataclass(frozen=True)
class NativeEvidence:
    raw: Mapping[str, object]
    stdout: bytes
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
        raise O1C85RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C85RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C85RunError(f"{field} differs")
    return value


def _positive(value: object, field: str) -> int:
    result = _nonnegative(value, field)
    if not result:
        raise O1C85RunError(f"{field} differs")
    return result


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C85RunError(f"{field} differs")
    return value


def _relative_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C85RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C85RunError(f"{field} escapes the lab")
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
        raise O1C85RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected
        or not resolved.is_relative_to(root)
    ):
        raise O1C85RunError(f"{field} is not a canonical lab path")
    return resolved


def _external_path(value: object, field: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise O1C85RunError(f"{field} is not absolute")
    candidate = Path(value)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C85RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected:
        raise O1C85RunError(f"{field} is not canonical")
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
        raise O1C85RunError(f"{field} is not JSON") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C85RunError(f"{field} is not canonical JSON")
    return value


def _atomic_create(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    if not isinstance(payload, bytes):
        raise O1C85RunError("atomic payload differs")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != payload:
            raise O1C85RunError(f"atomic write verification failed for {path.name}")
        path.chmod(mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise O1C85RunError(f"artifact already exists: {path.name}") from exc


def _atomic_json(path: Path, value: object, *, mode: int = 0o444) -> None:
    _atomic_create(path, canonical_json_bytes(value), mode=mode)


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
        raise O1C85RunError("config escapes the lab")
    config = dict(_read_canonical_json(config_path, "O1C85 config"))
    if _pending(config):
        raise O1C85RunError("config contains PENDING: " + ", ".join(_pending(config)))
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
        raise O1C85RunError("config fields differ")

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
        raise O1C85RunError("frozen O1C84 parent differs")

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
        or preparation.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C85RunError("frozen preparation source differs")

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
        raise O1C85RunError("input fields differ")
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
        "page10_sha256",
        "page10_bytes",
        "continuation_bank_sha256",
        "continuation_bank_bytes",
        "candidate_order_sha256",
    }:
        raise O1C85RunError("native config fields differ")
    flags = tuple(_sequence(native.get("compiler_flags"), "compiler flags"))
    if (
        _relative_text(native.get("source"), "native source")
        != SOURCE_PATHS["native_v21"]
        or native.get("source_sha256")
        != _sha(native.get("source_sha256"), "native source digest")
        or flags != COMPILER_FLAGS
        or not all(isinstance(flag, str) for flag in flags)
        or native.get("cadical_library_sha256")
        != _sha(native.get("cadical_library_sha256"), "CaDiCaL library digest")
        or native.get("adapter_schema") != _native_v24.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema") != _native_v24.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("page10_sha256") != PAGE10_SHA256
        or native.get("page10_bytes") != PAGE10_SERIALIZED_BYTES
        or native.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or native.get("continuation_bank_bytes") != CONTINUATION_BANK_BYTES
        or native.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C85RunError("frozen native contract differs")
    if (
        not isinstance(native.get("compiler"), str)
        or not Path(cast(str, native["compiler"])).is_absolute()
    ):
        raise O1C85RunError("compiler path differs")
    if (
        not isinstance(native.get("cadical_include"), str)
        or not Path(cast(str, native["cadical_include"])).is_absolute()
    ):
        raise O1C85RunError("CaDiCaL include path differs")
    if (
        not isinstance(native.get("cadical_library"), str)
        or not Path(cast(str, native["cadical_library"])).is_absolute()
    ):
        raise O1C85RunError("CaDiCaL library path differs")

    source = _mapping(config["source"], "config source")
    if set(source) != {"paths", "expected_sha256"}:
        raise O1C85RunError("source config fields differ")
    paths = _mapping(source["paths"], "source paths")
    digests = _mapping(source["expected_sha256"], "source digests")
    if dict(paths) != SOURCE_PATHS or set(digests) != set(SOURCE_PATHS):
        raise O1C85RunError("source inventory differs")
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
        raise O1C85RunError("budgets differ")
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
        raise O1C85RunError("solver process census failed") from exc
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
        raise O1C85RunError("priority state receipt is not JSON") from exc
    if canonical_json_bytes(receipt) != payload:
        raise O1C85RunError("priority state receipt is not canonical JSON")
    hexadecimal = receipt.get("bank_hex")
    try:
        receipt_bank = bytes.fromhex(cast(str, hexadecimal))
    except (TypeError, ValueError) as exc:
        raise O1C85RunError("priority state receipt bank differs") from exc
    if (
        receipt.get("schema") != "o1-256-o1c82-live-parent-centered-priority-state-v1"
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("bank_bytes") != CONTINUATION_BANK_BYTES
        or receipt.get("current_bank_sha256") != CONTINUATION_BANK_SHA256
        or receipt_bank != bank
    ):
        raise O1C85RunError("priority state receipt contract differs")
    return receipt


def _canonical_payload(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), field)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C85RunError(f"{field} is not JSON") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C85RunError(f"{field} is not canonical JSON")
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
        raise O1C85RunError("published occurrence ledger contract differs")
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
            raise O1C85RunError("published occurrence record differs")
        by_index[union_index] = digest
    digests = frozenset(by_index.values())
    if set(by_index) != set(range(ATTIC_UNION_CLAUSE_COUNT)) or len(digests) != (
        ATTIC_UNION_CLAUSE_COUNT
    ):
        raise O1C85RunError("published attic union digest inventory differs")
    return digests


def _validate_published_documents(artifacts: Mapping[str, bytes]) -> frozenset[str]:
    activation = _canonical_payload(
        artifacts[ACTIVATION_LEDGER_NAME], "published activation ledger"
    )
    activation_entries = _sequence(
        activation.get("entries"), "published activation entries"
    )
    last_activation = _mapping(
        activation_entries[-1] if activation_entries else None,
        "published final activation",
    )
    used = _sequence(
        activation.get("used_active_sha256"), "published used active identities"
    )
    residency = _canonical_payload(artifacts[RESIDENCY_NAME], "published residency")
    projection = _mapping(
        residency.get("current_projection"), "published Page-10 projection"
    )
    encoding = _mapping(projection.get("encoding_only"), "published Page-10 vault")
    attic = _mapping(residency.get("attic_evidence"), "published residency attic")
    residency_union = _mapping(attic.get("union"), "published residency attic union")
    relations = _canonical_payload(artifacts[RELATIONS_NAME], "published relations")
    audit = _canonical_payload(
        artifacts[COMMON_CORE_AUDIT_NAME], "published common-core audit"
    )
    failure = _canonical_payload(
        artifacts[FAILURE_RECEIPT_NAME], "published parent failure receipt"
    )
    if (
        activation.get("schema") != "o1-score-threshold-residency-activation-ledger-v1"
        or activation.get("entry_count") != len(activation_entries)
        or len(activation_entries) != 11
        or len(used) != 11
        or used[-1] != PAGE10_SHA256
        or last_activation.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or last_activation.get("active_sha256") != PAGE10_SHA256
        or last_activation.get("selected_clause_count") != PAGE10_CLAUSE_COUNT
        or residency.get("schema") != "o1-score-threshold-causal-residency-v1"
        or residency.get("active_limit") != PAGE10_ACTIVE_LIMIT
        or projection.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or projection.get("category_counts") != PAGE10_CATEGORY_COUNTS
        or encoding.get("sha256") != PAGE10_SHA256
        or encoding.get("clause_count") != PAGE10_CLAUSE_COUNT
        or encoding.get("literal_count") != PAGE10_LITERAL_COUNT
        or encoding.get("serialized_bytes") != PAGE10_SERIALIZED_BYTES
        or attic.get("chunk_count") != ATTIC_CHUNK_COUNT
        or residency_union.get("clause_count") != ATTIC_UNION_CLAUSE_COUNT
    ):
        raise O1C85RunError("published Page-10 residency contract differs")
    if (
        relations.get("schema") != "o1-score-threshold-causal-relations-v1"
        or relations.get("strict_subsumption_pair_count")
        != ATTIC_SUBSUMPTION_RELATION_COUNT
        or relations.get("undominated_clause_count") != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or audit.get("schema") != "o1-256-o1c83-common-signed-intersection-audit-v1"
        or failure.get("schema")
        != "o1-256-apple8-parent-centered-continuation-terminal-failure-v1"
        or failure.get("classification") != OPERATIONAL_TERMINAL
        or failure.get("phase") != "CALL"
        or failure.get("native_call_issued") is not True
        or failure.get("native_result_returned") is not False
        or failure.get("science_gain") is not False
    ):
        raise O1C85RunError("published supporting artifact contract differs")
    return _validate_occurrence_ledger(artifacts[OCCURRENCES_NAME])


def _validate_published_manifest(
    manifest: Mapping[str, object], artifacts: Mapping[str, bytes]
) -> tuple[dict[str, Mapping[str, object]], frozenset[str]]:
    if (
        set(manifest)
        != {
            "schema",
            "attempt_id",
            "zero_call",
            "authorization",
            "parent",
            "transport_recovery",
            "attic",
            "page10",
            "final_priority_bank",
            "artifacts",
        }
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C85RunError("published preparation manifest identity differs")
    zero_call = _mapping(manifest.get("zero_call"), "published zero-call boundary")
    authorization = _mapping(
        manifest.get("authorization"), "published authorization boundary"
    )
    parent = _mapping(manifest.get("parent"), "published preparation parent")
    recovery = _mapping(
        manifest.get("transport_recovery"), "published transport recovery"
    )
    attic = _mapping(manifest.get("attic"), "published preparation attic")
    page10 = _mapping(manifest.get("page10"), "published Page-10")
    bank = _mapping(manifest.get("final_priority_bank"), "published continuation bank")
    if dict(zero_call) != {
        "native_solver_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    } or dict(authorization) != {
        "science_call_authorized": False,
        "intent_created": False,
        "page10_burned": False,
        "lineage23_burned": False,
        "page9_replay_authorized": False,
        "lineage22_replay_authorized": False,
    }:
        raise O1C85RunError("published zero-call authorization differs")
    if dict(parent) != {
        "attempt_id": "O1C-0084",
        "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
        "capsule_entry_count": PARENT_CAPSULE_ENTRY_COUNT,
        "result_sha256": PARENT_RESULT_SHA256,
        "intent_sha256": PARENT_INTENT_SHA256,
        "terminal_failure_sha256": PARENT_FAILURE_SHA256,
        "classification": OPERATIONAL_TERMINAL,
        "failure_reason": "dyld-missing-LC_UUID-before-native-result",
        "page9_burned": True,
        "lineage22_burned": True,
        "native_result_returned": False,
        "actual_conflicts": None,
        "billed_conflicts": None,
        "science_gain": False,
        "state_update_available": False,
        "initial_o1c83_artifact_count": 9,
        "initial_artifacts_byte_equal_to_fresh_regeneration": True,
        "priority_receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "priority_receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
    }:
        raise O1C85RunError("published parent failure boundary differs")
    if dict(recovery) != {
        "source_lineage_ordinal": 22,
        "next_lineage_ordinal": LINEAGE_CALL_ORDINAL,
        "fully_emitted_event_count": 0,
        "new_chunk_count": 0,
        "attic_evidence_unchanged": True,
        "occurrence_ledger_unchanged": True,
        "relation_ledger_unchanged": True,
        "common_core_audit_unchanged": True,
        "continuation_bank_unchanged": True,
        "api": (
            "reproject_causal_residency(same_attic,"
            "fully_emitted_union_indices=(),next_lineage_ordinal=23,"
            "next_active_limit=254)"
        ),
    } or dict(attic) != {
        "chunk_count": ATTIC_CHUNK_COUNT,
        "union_clause_count": ATTIC_UNION_CLAUSE_COUNT,
        "occurrence_count": ATTIC_OCCURRENCE_COUNT,
        "strict_subsumption_pair_count": ATTIC_SUBSUMPTION_RELATION_COUNT,
        "undominated_clause_count": ATTIC_UNDOMINATED_CLAUSE_COUNT,
    }:
        raise O1C85RunError("published transport/attic boundary differs")
    if dict(page10) != {
        "lineage_ordinal": LINEAGE_CALL_ORDINAL,
        "active_limit": PAGE10_ACTIVE_LIMIT,
        "active_sha256": PAGE10_SHA256,
        "clause_count": PAGE10_CLAUSE_COUNT,
        "literal_count": PAGE10_LITERAL_COUNT,
        "serialized_bytes": PAGE10_SERIALIZED_BYTES,
        "category_counts": PAGE10_CATEGORY_COUNTS,
        "headroom": PAGE10_HEADROOM,
        "fresh_identity": True,
    }:
        raise O1C85RunError("published Page-10 seal differs")
    if dict(bank) != {
        "sha256": CONTINUATION_BANK_SHA256,
        "serialized_bytes": CONTINUATION_BANK_BYTES,
        "priority_is_key_bit_belief": False,
        "semantic_role": "unchanged-sealed-live-continuation-bytes",
        "validation_contract": "o1c82-live-continuation-bank-with-state-receipt",
        "encoding": "256-variable-ordered-96-byte-records-little-endian",
        "coordinate_record_count": 256,
        "eligible_coordinate_count": 255,
        "record_bytes": 96,
        "maximum_evolved_count": 575,
        "zero_coordinate_variables": [241],
        "receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        "receipt_bank_hex_byte_equal": True,
        "fresh_seed_parser_compatible": False,
        "next_action_parser_gate": (
            "require-live-continuation-parser;do-not-use-fresh-seed-parser"
        ),
    }:
        raise O1C85RunError("published continuation bank seal differs")
    rows_raw = _mapping(manifest.get("artifacts"), "published artifact rows")
    if set(rows_raw) != set(PUBLISHED_ARTIFACT_SEALS):
        raise O1C85RunError("published artifact row inventory differs")
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
            raise O1C85RunError("published artifact seal differs")
        rows[name] = row
    known = _validate_published_documents(artifacts)
    return rows, known


def _load_published_preparation(
    directory: Path, manifest_path: Path
) -> PublishedPreparation:
    try:
        children = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    except OSError as exc:
        raise O1C85RunError("published preparation inventory is unreadable") from exc
    if (
        manifest_path != directory / PREPARATION_MANIFEST_NAME
        or {path.name for path in children} != PREPARATION_ARTIFACT_NAMES
    ):
        raise O1C85RunError("published preparation inventory differs")
    artifacts: dict[str, bytes] = {}
    for path in children:
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C85RunError("published preparation artifact is unreadable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise O1C85RunError("published preparation artifact type differs")
        artifacts[path.name] = payload
    manifest_payload = artifacts[PREPARATION_MANIFEST_NAME]
    if (
        len(manifest_payload) != PUBLISHED_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PUBLISHED_MANIFEST_SHA256
    ):
        raise O1C85RunError("published preparation manifest seal differs")
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
        raise O1C85RunError("parent input SHA preflight differs")
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
    if (
        published_manifest.parent != published_directory
        or published_manifest.stat().st_size != preparation["manifest_bytes"]
        or _sha_file(published_manifest) != preparation["manifest_sha256"]
        or receipt_path.stat().st_size != preparation["priority_state_receipt_bytes"]
        or _sha_file(receipt_path) != preparation["priority_state_receipt_sha256"]
    ):
        raise O1C85RunError("published preparation/receipt preflight differs")

    inputs = _mapping(config["inputs"], "preflight inputs")
    input_sha: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        candidate = _lab_path(root, inputs[name], f"input {name}")
        observed = _sha_file(candidate)
        if observed != inputs[f"{name}_sha256"]:
            raise O1C85RunError(f"input {name} SHA preflight differs")
        input_sha[name] = observed

    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "source paths")
    expected = _mapping(source["expected_sha256"], "source digests")
    source_sha: dict[str, str] = {}
    for name in SOURCE_PATHS:
        candidate = _lab_path(root, paths[name], f"source {name}")
        observed = _sha_file(candidate)
        if observed != expected[name]:
            raise O1C85RunError(f"source {name} SHA preflight differs")
        source_sha[name] = observed

    native = _mapping(config["native"], "preflight native")
    compiler = _external_path(native["compiler"], "compiler")
    include = _external_path(
        native["cadical_include"], "CaDiCaL include", directory=True
    )
    library = _external_path(native["cadical_library"], "CaDiCaL library")
    if (
        _sha_file(library) != native["cadical_library_sha256"]
        or source_sha["native_v21"] != native["source_sha256"]
    ):
        raise O1C85RunError("native toolchain/source SHA preflight differs")

    prepared = _load_published_preparation(published_directory, published_manifest)
    prepared_rows = {
        name: {
            "serialized_bytes": len(payload),
            "sha256": sha256_bytes(payload),
        }
        for name, payload in sorted(prepared.artifacts.items())
    }
    receipt_payload = receipt_path.read_bytes()
    _validate_priority_receipt(
        receipt_payload, prepared.artifacts[CONTINUATION_BANK_NAME]
    )
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
        raise O1C85RunError("Darwin/arm64/RAM/disk/process preflight differs")
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
        },
        "page10_sha256": PAGE10_SHA256,
        "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "priority_state_receipt": {
            "serialized_bytes": len(receipt_payload),
            "sha256": _sha_file(receipt_path),
        },
        "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
        "global_novelty_baseline_clause_count": ATTIC_UNION_CLAUSE_COUNT,
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
        config=config, row=row, prepared=prepared, receipt=receipt_payload
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
    raise O1C85RunError(f"{field} differs")


def _executable_identity(path: Path, *, relative_path: str) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C85RunError("native executable is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C85RunError("native executable type differs")
    size = path.stat().st_size
    if size <= 0:
        raise O1C85RunError("native executable is empty")
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
        raise O1C85RunError(f"{field} differs")


def _compile_native(
    *,
    root: Path,
    stage: Path,
    config: Mapping[str, object],
    command_runner: Callable[..., object],
) -> tuple[Path, dict[str, object]]:
    native = _mapping(config["native"], "native build config")
    compiler = _external_path(native["compiler"], "compiler")
    include = _external_path(
        native["cadical_include"], "CaDiCaL include", directory=True
    )
    library = _external_path(native["cadical_library"], "CaDiCaL library")
    source = _lab_path(root, native["source"], "native v21 source")
    if (
        _sha_file(source) != native["source_sha256"]
        or _sha_file(library) != native["cadical_library_sha256"]
    ):
        raise O1C85RunError("native build input changed after preflight")
    output = stage / "native" / NATIVE_EXECUTABLE_NAME
    output.parent.mkdir(parents=True, exist_ok=False)
    command = [
        str(compiler),
        *COMPILER_FLAGS,
        "-I",
        "native",
        "-I",
        str(include),
        cast(str, native["source"]),
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
            cwd=root,
            capture_output=True,
            check=False,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C85RunError("native v21 compilation could not run") from exc
    version_returncode = getattr(version_result, "returncode", None)
    returncode = getattr(completed, "returncode", None)
    if version_returncode != 0 or returncode != 0:
        stderr = _completed_bytes(getattr(completed, "stderr", b""), "compiler stderr")
        raise O1C85RunError(
            "native v21 compilation failed: "
            + stderr.decode("utf-8", errors="replace").strip()[:2000]
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
        raise O1C85RunError("native v21 --help smoke could not run") from exc
    smoke_stdout = _completed_bytes(getattr(smoke, "stdout", b""), "smoke stdout")
    smoke_stderr = _completed_bytes(getattr(smoke, "stderr", b""), "smoke stderr")
    after_smoke = _executable_identity(
        output, relative_path=f"native/{NATIVE_EXECUTABLE_NAME}"
    )
    if (
        getattr(smoke, "returncode", None) != 0
        or smoke_stdout != NATIVE_V21_USAGE
        or smoke_stderr
        or after_smoke != before_smoke
    ):
        raise O1C85RunError("native v21 --help smoke seal differs")
    source_config = _mapping(config["source"], "build source config")
    source_digests = _mapping(source_config["expected_sha256"], "build source digests")
    closure = [
        {
            "name": name,
            "path": SOURCE_PATHS[name],
            "sha256": source_digests[name],
        }
        for name in NATIVE_CLOSURE_NAMES
    ]
    normalized_command = [
        *command[:-1],
        f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}",
    ]
    build = {
        "schema": NATIVE_BUILD_SCHEMA,
        "source": native["source"],
        "source_sha256": native["source_sha256"],
        "include_closure": closure,
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
        raise O1C85RunError("timestamped capsule already exists")
    stage.mkdir(mode=0o700)
    try:
        _atomic_create(stage / "config.json", config_path.read_bytes())
        _atomic_json(stage / "preflight.json", bundle.row)
        initial = stage / "initial"
        initial.mkdir()
        for name, payload in sorted(bundle.prepared.artifacts.items()):
            _atomic_create(initial / name, payload)
        _atomic_create(initial / RECEIPT_NAME, bundle.receipt)
        _, build = _compile_native(
            root=root,
            stage=stage,
            config=bundle.config,
            command_runner=command_runner,
        )
        _atomic_json(stage / "native-build.json", build)
        initial_rows = {
            name: _artifact_row(initial / name, relative_to=initial)
            for name in sorted(STAGED_INITIAL_NAMES)
        }
        invocation = {
            "schema": INVOCATION_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "page10_sha256": PAGE10_SHA256,
            "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
            "global_novelty_baseline_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "threshold": THRESHOLD,
            "seed": SEED,
            "requested_conflicts": REQUESTED_CONFLICTS,
            "maximum_native_solver_calls": MAXIMUM_NATIVE_CALLS,
            "timeout_seconds": TIMEOUT_SECONDS,
            "memory_limit_bytes": MEMORY_LIMIT_BYTES,
            "initial_artifacts": initial_rows,
            "native_build_sha256": _sha_file(stage / "native-build.json"),
            "native_executable": dict(
                _mapping(build["executable"], "observed native executable")
            ),
            "native_smoke": dict(_mapping(build["smoke"], "native smoke")),
            "retry_authorized": False,
            "replay_authorized": False,
            "target_input_present": False,
            "truth_input_present": False,
        }
        _atomic_json(stage / "invocation.json", invocation)
        os.replace(stage, final)
        directory_fd = os.open(runs, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return final, invocation
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise


def _rehash_call_inputs(
    *,
    root: Path,
    config_path: Path,
    config: Mapping[str, object],
    preflight_row: Mapping[str, object],
    capsule: Path,
    invocation: Mapping[str, object],
) -> None:
    if _sha_file(config_path) != preflight_row.get("config_sha256"):
        raise O1C85RunError("config changed before native call")
    inputs = _mapping(config["inputs"], "call inputs")
    approved = _mapping(preflight_row.get("input_sha256"), "approved input SHA")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        if (
            approved.get(name) != inputs[f"{name}_sha256"]
            or _sha_file(_lab_path(root, inputs[name], f"call input {name}"))
            != approved[name]
        ):
            raise O1C85RunError(f"input {name} changed before native call")
    source_config = _mapping(config["source"], "call source config")
    source_paths = _mapping(source_config["paths"], "call source paths")
    source_sha = _mapping(preflight_row.get("source_sha256"), "approved source SHA")
    for name in SOURCE_PATHS:
        path = _lab_path(root, source_paths[name], f"call source {name}")
        if _sha_file(path) != source_sha.get(name):
            raise O1C85RunError(f"source {name} changed before native call")
    executable = capsule / "native" / NATIVE_EXECUTABLE_NAME
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C85RunError("staged call artifact inventory differs") from exc
    if {path.name for path in children} != STAGED_INITIAL_NAMES or any(
        not path.is_file() or path.is_symlink() for path in children
    ):
        raise O1C85RunError("staged call artifact inventory differs")
    prepared_rows = _mapping(
        preflight_row.get("prepared_artifacts"), "approved prepared artifacts"
    )
    receipt_row = _mapping(
        preflight_row.get("priority_state_receipt"), "approved priority receipt"
    )
    expected_rows = {**prepared_rows, RECEIPT_NAME: receipt_row}
    for name, value in expected_rows.items():
        row = _mapping(value, f"approved staged artifact {name}")
        path = initial / name
        if path.stat().st_size != row.get("serialized_bytes") or _sha_file(
            path
        ) != row.get("sha256"):
            raise O1C85RunError("staged call artifact seal differs")
    invocation_path = capsule / "invocation.json"
    build_path = capsule / "native-build.json"
    if invocation_path.read_bytes() != canonical_json_bytes(invocation) or _sha_file(
        build_path
    ) != invocation.get("native_build_sha256"):
        raise O1C85RunError("staged invocation/build seal differs")
    build = _read_canonical_json(build_path, "staged native build")
    expected = _mapping(
        invocation.get("native_executable"), "invocation native executable"
    )
    smoke = _mapping(build.get("smoke"), "staged native smoke")
    if (
        build.get("schema") != NATIVE_BUILD_SCHEMA
        or build.get("build_invocations") != 1
        or build.get("executable") != expected
        or smoke.get("command")
        != [f"<capsule>/native/{NATIVE_EXECUTABLE_NAME}", "--help"]
        or smoke.get("returncode") != 0
        or smoke.get("stdout")
        != {
            "serialized_bytes": len(NATIVE_V21_USAGE),
            "sha256": sha256_bytes(NATIVE_V21_USAGE),
        }
        or smoke.get("stderr") != {"serialized_bytes": 0, "sha256": sha256_bytes(b"")}
        or smoke.get("executable") != expected
        or invocation.get("native_smoke") != smoke
    ):
        raise O1C85RunError("staged native build/smoke seal differs")
    _require_executable_identity(executable, expected, "native executable call seal")


def _native_stdout(result: object) -> bytes:
    value = getattr(result, "native_stdout", None)
    if isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, bytes):
        payload = value
    else:
        raise O1C85RunError("adapter omitted byte-exact native stdout")
    if _sha(
        getattr(result, "native_stdout_sha256", None), "native stdout digest"
    ) != sha256_bytes(payload):
        raise O1C85RunError("native stdout digest differs")
    return payload


def _validate_native_result(result: object, stdout: bytes) -> NativeEvidence:
    if not isinstance(result, _native_v24.JointScoreSieveV24Result):
        raise O1C85RunError("adapter v24 result type differs")
    raw = _mapping(result.raw, "native result")
    try:
        decoded = _mapping(json.loads(stdout), "native stdout JSON")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C85RunError("native stdout JSON differs") from exc
    if (
        decoded != raw
        or raw.get("schema") != _native_v24.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    ):
        raise O1C85RunError("native stdout/result projection differs")
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
        or raw.get("active_vault_sha256") != PAGE10_SHA256
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
        raise O1C85RunError("native v21 production binding differs")
    if (
        raw.get("priority_state") != priority_state
        or raw.get("priority_actions") != actions
    ):
        raise O1C85RunError("native promoted priority projection differs")
    if raw.get("decision_ownership") != ownership:
        raise O1C85RunError("native promoted ownership projection differs")
    if result.status == 10 and not isinstance(result.key_model, bytes):
        raise O1C85RunError("SAT result omitted key model")
    if result.status != 10 and result.key_model is not None:
        raise O1C85RunError("non-SAT result returned key model")
    return NativeEvidence(
        raw=raw,
        stdout=stdout,
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
        raise O1C85RunError("priority action count differs")
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
            raise O1C85RunError("emitted clause serialization differs") from exc
        digest = sha256_bytes(clause.serialized)
        if digest not in globally_known_clause_sha256:
            globally_novel.add(digest)
    novel = len(globally_novel)
    if novel > active_new:
        raise O1C85RunError("global novelty exceeds active-vault novelty")
    certified_prune_gain = (
        realized_certified_prunes > 0 and threshold_prunes > 0 and emitted > 0
    )
    if evidence.status == 10 and not public_model_verified:
        raise O1C85RunError("SAT key failed exact public ChaCha verification")
    if evidence.status != 10 and public_model_verified:
        raise O1C85RunError("public model verification without SAT differs")
    model_gain = evidence.status == 10 and public_model_verified
    closure_gain = evidence.status == 20 or terminal_empty
    # Native v21 emits no entropy or domain estimate.  These fields stay
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
        "active_page10_new_clauses": active_new,
        "attacker_valid_entropy_gain_bits": entropy_gain_bits,
        "attacker_valid_domain_reduction": domain_reduction,
        "failure_first_action_alone_is_science_gain": False,
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
        }
        if stdout or stderr or hasattr(exc, "returncode")
        else None,
    }


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
    source_path = _lab_path(root, native_config["source"], "run native source")
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
        "invocation_sha256": invocation_sha,
        "page10_sha256": PAGE10_SHA256,
        "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
        "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "native_executable": dict(executable_identity),
        "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "page10_burned": True,
        "lineage23_burned": True,
        "burn_on_persisted_intent": True,
        "retry_authorized": False,
        "replay_authorized": False,
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
            sealed_page10_path=capsule / "initial" / ACTIVE_PROJECTION_NAME,
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
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "page10_burned": True,
            "lineage23_burned": True,
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
        calls = int(call_issued)
        failure = {
            "schema": "o1-256-apple8-parent-centered-continuation-terminal-failure-v1",
            "classification": OPERATIONAL_TERMINAL,
            "phase": "POST_CALL"
            if result_returned
            else ("CALL" if call_issued else "PRE_CALL"),
            "occurred_after_persisted_intent": True,
            "page10_burned": True,
            "lineage23_burned": True,
            "native_call_issued": call_issued,
            "native_result_returned": result_returned,
            "native_calls_consumed": calls,
            "requested_conflicts_consumed": calls * REQUESTED_CONFLICTS,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "science_gain": False,
            "retry_authorized": False,
            "replay_authorized": False,
            **_failure_payload(exc),
        }
        _atomic_json(episode_dir / "terminal-failure.json", failure)
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": False,
            "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
            "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "page10_burned": True,
            "lineage23_burned": True,
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
            raise O1C85RunError("capsule contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise O1C85RunError("capsule contains a special file")
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
        "# O1C-0085 Page-10 parent-centered run",
        "",
        f"- Classification: `{result.get('classification')}`",
        f"- Stop reason: `{result.get('stop_reason')}`",
        f"- Native calls: `{resources.get('native_solver_calls')}` / 1",
        f"- Requested conflicts: `{resources.get('requested_conflicts')}` / 128",
        f"- Science gain: `{str(result.get('science_gain')).lower()}`",
        "- Page 10 and lineage 23 burned when `episodes/00/intent.json` was persisted.",
        "- Failure-first priority actions are operational proof-mining choices, not bit beliefs or science gain.",
        "- Retry, replay, reveal, target/truth input, refit, MPS, and GPU use were forbidden.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _publish_exact(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise O1C85RunError("authoritative result already differs")
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
        raise O1C85RunError("persistent artifact budget exceeded")
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
    value = dict(_read_canonical_json(authoritative, "authoritative O1C85 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C85RunError("authoritative O1C85 result differs")
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


def _validated_capsule_result(
    root: Path, capsule: Path
) -> tuple[dict[str, object], bytes]:
    required = tuple(
        capsule / name for name in ("result.json", "RUN.md", "artifacts.sha256")
    )
    if not all(path.is_file() and not path.is_symlink() for path in required):
        if (capsule / "episodes/00/intent.json").is_file():
            raise O1C85RunError("burned incomplete capsule forbids retry or replay")
        raise O1C85RunError("incomplete pre-intent capsule blocks a fresh call")
    manifest, _ = _manifest_bytes(capsule)
    if manifest != (capsule / "artifacts.sha256").read_bytes():
        raise O1C85RunError("existing capsule manifest differs")
    result_path = capsule / "result.json"
    result_payload = result_path.read_bytes()
    result = dict(_read_canonical_json(result_path, "capsule result"))
    expected_capsule = capsule.relative_to(root).as_posix()
    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("capsule") != expected_capsule
    ):
        raise O1C85RunError("existing capsule result differs")
    return result, result_payload


def _republish_existing_capsule(root: Path, capsule: Path) -> dict[str, object]:
    result, payload = _validated_capsule_result(root, capsule)
    _publish_exact(root / RESULT_RELATIVE, payload)
    return result


def _public_verifier(
    *, root: Path, config: Mapping[str, object]
) -> Callable[[bytes], bool]:
    inputs = _mapping(config["inputs"], "public verifier inputs")
    config_path = _lab_path(root, inputs["o1c73_config"], "O1C73 verifier config")
    if _sha_file(config_path) != inputs["o1c73_config_sha256"]:
        raise O1C85RunError("public verifier config SHA differs")
    try:
        baseline_config = _o1c73.load_config(config_path)
        baseline = _o1c73.validate_apple8_baseline(root, baseline_config)
        verifier = _o1c73._o1c66._public_target(baseline).verify
    except Exception as exc:
        raise O1C85RunError("public ChaCha verifier cannot be established") from exc
    return cast(Callable[[bytes], bool], verifier)


def run(
    config_path: str | Path = CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    adapter_run: AdapterRun = _native_v24.run_joint_score_sieve,
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
            raise O1C85RunError("authoritative O1C85 result lacks one sealed capsule")
        capsule_result, capsule_payload = _validated_capsule_result(lab, capsules[0])
        authoritative_payload = (lab / RESULT_RELATIVE).read_bytes()
        if capsule_payload != authoritative_payload or capsule_result != existing:
            raise O1C85RunError("authoritative O1C85 result differs from capsule")
        return existing
    if capsules:
        if len(capsules) != 1:
            raise O1C85RunError("multiple O1C85 capsules forbid replay")
        return _republish_existing_capsule(lab, capsules[0])

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
            "priority_is_key_bit_belief": False,
            "science_requires": [
                "actual-certified-prune",
                "certified-closure",
                "globally-novel-clause",
                "certified-model-or-key",
                "attacker-valid-entropy-or-domain-gain",
            ],
            "page10_sha256": PAGE10_SHA256,
            "input_continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "global_novelty_baseline_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "page10_burned": True,
            "lineage23_only": True,
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
        "next_action": "Never retry or replay Page 10 / lineage 23; preserve the final priority bank only as a continuation seed.",
    }
    return _finalize_capsule(
        capsule=capsule, authoritative=lab / RESULT_RELATIVE, result=result
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or execute O1C85's one Page-10 parent-centered call"
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
    except O1C85RunError as exc:
        print(f"O1C85: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVATION_ONLY",
    "CONFIG_RELATIVE",
    "MEMORY_LIMIT_BYTES",
    "O1C85RunError",
    "OPERATIONAL_TERMINAL",
    "REQUESTED_CONFLICTS",
    "RESULT_RELATIVE",
    "THRESHOLD",
    "load_config",
    "main",
    "preflight",
    "run",
]
