"""Burn-on-intent runner for the single O1C-0084 Page-9 call.

The runner has one scientific side effect: after an immutable intent is
persisted it may invoke native v20 once, with seed zero and 128 requested
conflicts.  Failure-first priority actions are operational evidence, never a
bit belief or science gain by themselves.
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
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v23 as _native_v23
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .causal_attic_v1 import canonical_json_bytes, sha256_bytes
from .o1c83_apple8_causal_rollover_prepare import (
    ACTIVE_PROJECTION_NAME,
    ACTIVATION_LEDGER_NAME,
    ATTIC_UNION_CLAUSE_COUNT,
    COMMON_CORE_AUDIT_NAME,
    CONTINUATION_CANDIDATE_ORDER_SHA256,
    DEFAULT_PARENT_CAPSULE_RELATIVE,
    DEFAULT_PARENT_RESULT_RELATIVE,
    FINAL_BANK_NAME as PREPARED_CONTINUATION_BANK_NAME,
    NEW_CHUNK_NAME,
    OCCURRENCES_NAME,
    PAGE9_SERIALIZED_BYTES,
    PAGE9_SHA256,
    PARENT_CAPSULE_MANIFEST_SHA256,
    PARENT_FINAL_BANK_BYTES,
    PARENT_FINAL_BANK_SHA256,
    PARENT_PRIORITY_STATE_BYTES,
    PARENT_PRIORITY_STATE_SHA256,
    PARENT_RESULT_SHA256,
    PREPARATION_MANIFEST_NAME,
    PreparedCausalRolloverArtifacts,
    RELATIONS_NAME,
    RESIDENCY_NAME,
    prepare_o1c83_causal_rollover,
)
from .threshold_no_good_vault_v1 import O1C66_VAULT_CAPS, ThresholdNoGoodClause


ATTEMPT_ID = "O1C-0084"
CONFIG_SCHEMA = "o1-256-apple8-parent-centered-continuation-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-parent-centered-continuation-preflight-v1"
NATIVE_BUILD_SCHEMA = "o1-256-o1c84-native-v20-build-v1"
INVOCATION_SCHEMA = "o1-256-apple8-parent-centered-continuation-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-parent-centered-continuation-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-parent-centered-continuation-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-parent-centered-continuation-result-v1"

CONFIG_RELATIVE = Path("configs/o1c84_apple8_parent_centered_continuation_v1.json")
RESULT_RELATIVE = Path("research/O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json")
CAPSULE_SUFFIX = "O1C-0084_apple8-parent-centered-continuation-v1"

LOCAL_EPISODE_ORDINAL = 0
LINEAGE_CALL_ORDINAL = 22
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
    "research/o1c83_causal_rollover_seed_20260720"
)
PUBLISHED_MANIFEST_SHA256 = (
    "b8a829a642159640a10cc553c6c27e5312cae4fbda8f75975688c6d14afe7dda"
)
PUBLISHED_MANIFEST_BYTES = 4_255
CONTINUATION_BANK_NAME = PREPARED_CONTINUATION_BANK_NAME
CONTINUATION_BANK_SHA256 = PARENT_FINAL_BANK_SHA256
CONTINUATION_BANK_BYTES = PARENT_FINAL_BANK_BYTES
PRIORITY_RECEIPT_RELATIVE = (
    DEFAULT_PARENT_CAPSULE_RELATIVE / "episodes/00/priority-state.json"
)

PREPARATION_ARTIFACT_NAMES = frozenset(
    {
        ACTIVE_PROJECTION_NAME,
        ACTIVATION_LEDGER_NAME,
        COMMON_CORE_AUDIT_NAME,
        CONTINUATION_BANK_NAME,
        NEW_CHUNK_NAME,
        OCCURRENCES_NAME,
        PREPARATION_MANIFEST_NAME,
        RELATIONS_NAME,
        RESIDENCY_NAME,
    }
)
STAGED_INITIAL_NAMES = PREPARATION_ARTIFACT_NAMES | {RECEIPT_NAME}

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c84_apple8_parent_centered_continuation_run.py",
    "runner_tests": "tests/test_o1c84_apple8_parent_centered_continuation_run.py",
    "adapter_v23": "src/o1_crypto_lab/joint_score_sieve_v23.py",
    "adapter_v23_tests": "tests/test_joint_score_sieve_v23.py",
    "causal_rollover_preparation": "src/o1_crypto_lab/o1c83_apple8_causal_rollover_prepare.py",
    "causal_rollover_preparation_tests": "tests/test_o1c83_apple8_causal_rollover_prepare.py",
    "parent_preparation": "src/o1_crypto_lab/o1c82_apple8_parent_centered_prepare.py",
    "parent_preparation_tests": "tests/test_o1c82_apple8_parent_centered_prepare.py",
    "seed_compiler": "src/o1_crypto_lab/o1c82_parent_centered_seed.py",
    "seed_tests": "tests/test_o1c82_parent_centered_seed.py",
    "causal_attic": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency": "src/o1_crypto_lab/causal_residency_v1.py",
    "threshold_vault": "src/o1_crypto_lab/threshold_no_good_vault_v1.py",
    "public_verifier": "src/o1_crypto_lab/o1c73_apple8_vault_release_contrast_run.py",
    "native_v20": "native/cadical_o1_joint_score_sieve_v20.cpp",
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
    "native_v20",
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
    "-Wl,-no_uuid",
)


class O1C84RunError(RuntimeError):
    """A frozen input, burn ledger, native result, or capsule seal differs."""


AdapterRun = Callable[..., object]


class PreparationRun(Protocol):
    def __call__(
        self,
        *,
        capsule_dir: str | Path,
        parent_result_path: str | Path,
    ) -> PreparedCausalRolloverArtifacts: ...


@dataclass(frozen=True)
class PreflightBundle:
    config: Mapping[str, object]
    row: Mapping[str, object]
    prepared: PreparedCausalRolloverArtifacts
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
        raise O1C84RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C84RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C84RunError(f"{field} differs")
    return value


def _positive(value: object, field: str) -> int:
    result = _nonnegative(value, field)
    if not result:
        raise O1C84RunError(f"{field} differs")
    return result


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C84RunError(f"{field} differs")
    return value


def _relative_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C84RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C84RunError(f"{field} escapes the lab")
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
        raise O1C84RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not expected
        or not resolved.is_relative_to(root)
    ):
        raise O1C84RunError(f"{field} is not a canonical lab path")
    return resolved


def _external_path(value: object, field: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise O1C84RunError(f"{field} is not absolute")
    candidate = Path(value)
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C84RunError(f"{field} cannot be resolved") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected:
        raise O1C84RunError(f"{field} is not canonical")
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
        raise O1C84RunError(f"{field} is not JSON") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C84RunError(f"{field} is not canonical JSON")
    return value


def _atomic_create(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    if not isinstance(payload, bytes):
        raise O1C84RunError("atomic payload differs")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != payload:
            raise O1C84RunError(f"atomic write verification failed for {path.name}")
        path.chmod(mode)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise O1C84RunError(f"artifact already exists: {path.name}") from exc


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
        raise O1C84RunError("config escapes the lab")
    config = dict(_read_canonical_json(config_path, "O1C84 config"))
    if _pending(config):
        raise O1C84RunError("config contains PENDING: " + ", ".join(_pending(config)))
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
        raise O1C84RunError("config fields differ")

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
        raise O1C84RunError("frozen O1C82 parent differs")

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
        or preparation.get("priority_state_receipt_sha256")
        != PARENT_PRIORITY_STATE_SHA256
        or preparation.get("priority_state_receipt_bytes")
        != PARENT_PRIORITY_STATE_BYTES
        or preparation.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C84RunError("frozen preparation source differs")

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
        raise O1C84RunError("input fields differ")
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
        "expected_executable_sha256",
        "expected_executable_bytes",
        "adapter_schema",
        "result_schema",
        "page9_sha256",
        "page9_bytes",
        "continuation_bank_sha256",
        "continuation_bank_bytes",
        "candidate_order_sha256",
    }:
        raise O1C84RunError("native config fields differ")
    flags = tuple(_sequence(native.get("compiler_flags"), "compiler flags"))
    if (
        _relative_text(native.get("source"), "native source")
        != SOURCE_PATHS["native_v20"]
        or native.get("source_sha256")
        != _sha(native.get("source_sha256"), "native source digest")
        or flags != COMPILER_FLAGS
        or not all(isinstance(flag, str) for flag in flags)
        or native.get("cadical_library_sha256")
        != _sha(native.get("cadical_library_sha256"), "CaDiCaL library digest")
        or native.get("expected_executable_sha256")
        != _sha(native.get("expected_executable_sha256"), "native executable digest")
        or _positive(native.get("expected_executable_bytes"), "native executable bytes")
        <= 0
        or native.get("adapter_schema") != _native_v23.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema") != _native_v23.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("page9_sha256") != PAGE9_SHA256
        or native.get("page9_bytes") != PAGE9_SERIALIZED_BYTES
        or native.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or native.get("continuation_bank_bytes") != CONTINUATION_BANK_BYTES
        or native.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
    ):
        raise O1C84RunError("frozen native contract differs")
    if (
        not isinstance(native.get("compiler"), str)
        or not Path(cast(str, native["compiler"])).is_absolute()
    ):
        raise O1C84RunError("compiler path differs")
    if (
        not isinstance(native.get("cadical_include"), str)
        or not Path(cast(str, native["cadical_include"])).is_absolute()
    ):
        raise O1C84RunError("CaDiCaL include path differs")
    if (
        not isinstance(native.get("cadical_library"), str)
        or not Path(cast(str, native["cadical_library"])).is_absolute()
    ):
        raise O1C84RunError("CaDiCaL library path differs")

    source = _mapping(config["source"], "config source")
    if set(source) != {"paths", "expected_sha256"}:
        raise O1C84RunError("source config fields differ")
    paths = _mapping(source["paths"], "source paths")
    digests = _mapping(source["expected_sha256"], "source digests")
    if dict(paths) != SOURCE_PATHS or set(digests) != set(SOURCE_PATHS):
        raise O1C84RunError("source inventory differs")
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
        raise O1C84RunError("budgets differ")
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
        raise O1C84RunError("solver process census failed") from exc
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
        raise O1C84RunError("priority state receipt is not JSON") from exc
    if canonical_json_bytes(receipt) != payload:
        raise O1C84RunError("priority state receipt is not canonical JSON")
    hexadecimal = receipt.get("bank_hex")
    try:
        receipt_bank = bytes.fromhex(cast(str, hexadecimal))
    except (TypeError, ValueError) as exc:
        raise O1C84RunError("priority state receipt bank differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c82-live-parent-centered-priority-state-v1"
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_sha256")
        != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("bank_bytes") != CONTINUATION_BANK_BYTES
        or receipt.get("current_bank_sha256") != CONTINUATION_BANK_SHA256
        or receipt_bank != bank
    ):
        raise O1C84RunError("priority state receipt contract differs")
    return receipt


def _validate_prepared(prepared: PreparedCausalRolloverArtifacts) -> dict[str, object]:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C84RunError("prepared Page-9 type differs")
    artifacts = dict(prepared.artifacts)
    if set(artifacts) != PREPARATION_ARTIFACT_NAMES or not all(
        isinstance(payload, bytes) for payload in artifacts.values()
    ):
        raise O1C84RunError("prepared Page-9 inventory differs")
    manifest_payload = artifacts[PREPARATION_MANIFEST_NAME]
    if (
        len(artifacts[ACTIVE_PROJECTION_NAME]) != PAGE9_SERIALIZED_BYTES
        or sha256_bytes(artifacts[ACTIVE_PROJECTION_NAME]) != PAGE9_SHA256
        or len(artifacts[CONTINUATION_BANK_NAME]) != CONTINUATION_BANK_BYTES
        or sha256_bytes(artifacts[CONTINUATION_BANK_NAME])
        != CONTINUATION_BANK_SHA256
        or len(manifest_payload) != PUBLISHED_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PUBLISHED_MANIFEST_SHA256
        or manifest_payload != canonical_json_bytes(prepared.manifest)
    ):
        raise O1C84RunError("prepared Page-9 seal differs")
    authorization = _mapping(prepared.manifest.get("authorization"), "authorization")
    page9 = _mapping(prepared.manifest.get("page9"), "prepared Page-9")
    attic = _mapping(prepared.manifest.get("attic"), "prepared attic")
    bank = _mapping(
        prepared.manifest.get("final_priority_bank"), "prepared continuation bank"
    )
    artifact_rows = _mapping(
        prepared.manifest.get("artifacts"), "prepared artifact rows"
    )
    if (
        prepared.manifest.get("schema")
        != "o1-256-o1c83-page9-causal-rollover-preparation-v1"
        or prepared.manifest.get("attempt_id") != "O1C-0083"
        or authorization.get("science_call_authorized") is not False
        or authorization.get("intent_created") is not False
        or authorization.get("page9_burned") is not False
        or authorization.get("lineage22_burned") is not False
        or page9.get("lineage_ordinal") != LINEAGE_CALL_ORDINAL
        or page9.get("active_sha256") != PAGE9_SHA256
        or page9.get("serialized_bytes") != PAGE9_SERIALIZED_BYTES
        or page9.get("fresh_identity") is not True
        or attic.get("union_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or bank.get("sha256") != CONTINUATION_BANK_SHA256
        or bank.get("serialized_bytes") != CONTINUATION_BANK_BYTES
        or bank.get("receipt_sha256") != PARENT_PRIORITY_STATE_SHA256
        or bank.get("receipt_serialized_bytes") != PARENT_PRIORITY_STATE_BYTES
        or bank.get("receipt_bank_hex_byte_equal") is not True
        or bank.get("fresh_seed_parser_compatible") is not False
        or set(artifact_rows) != PREPARATION_ARTIFACT_NAMES - {PREPARATION_MANIFEST_NAME}
    ):
        raise O1C84RunError("prepared authorization boundary differs")
    for name, payload in artifacts.items():
        if name == PREPARATION_MANIFEST_NAME:
            continue
        row = _mapping(artifact_rows[name], f"prepared artifact {name}")
        if (
            row.get("serialized_bytes") != len(payload)
            or row.get("sha256") != sha256_bytes(payload)
        ):
            raise O1C84RunError("prepared artifact manifest differs")
    try:
        union_clauses = prepared.state.attic.union_vault.clauses
        union_serialized = frozenset(clause.serialized for clause in union_clauses)
    except (AttributeError, TypeError) as exc:
        raise O1C84RunError("prepared attic union differs") from exc
    if (
        len(union_clauses) != ATTIC_UNION_CLAUSE_COUNT
        or len(union_serialized) != ATTIC_UNION_CLAUSE_COUNT
        or any(not isinstance(payload, bytes) for payload in union_serialized)
    ):
        raise O1C84RunError("prepared attic union differs")
    return {
        name: {"serialized_bytes": len(payload), "sha256": sha256_bytes(payload)}
        for name, payload in sorted(artifacts.items())
    }


def _validate_published_bundle(
    directory: Path, prepared: PreparedCausalRolloverArtifacts
) -> None:
    try:
        children = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    except OSError as exc:
        raise O1C84RunError("published preparation inventory is unreadable") from exc
    if {path.name for path in children} != PREPARATION_ARTIFACT_NAMES:
        raise O1C84RunError("published preparation inventory differs")
    for path in children:
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C84RunError("published preparation artifact is unreadable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or payload != prepared.artifacts[path.name]
        ):
            raise O1C84RunError("published preparation differs from regeneration")


def _preflight_bundle(
    config_path: str | Path,
    *,
    root: Path,
    prepare_fn: PreparationRun,
    system_probe: Callable[[Path], Mapping[str, object]],
) -> PreflightBundle:
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file, root=root)
    parent = _mapping(config["parent"], "preflight parent")
    parent_capsule = _lab_path(
        root, parent["capsule"], "parent capsule", directory=True
    )
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
        raise O1C84RunError("parent input SHA preflight differs")
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
        or receipt_path.stat().st_size
        != preparation["priority_state_receipt_bytes"]
        or _sha_file(receipt_path)
        != preparation["priority_state_receipt_sha256"]
    ):
        raise O1C84RunError("published preparation/receipt preflight differs")

    inputs = _mapping(config["inputs"], "preflight inputs")
    input_sha: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        candidate = _lab_path(root, inputs[name], f"input {name}")
        observed = _sha_file(candidate)
        if observed != inputs[f"{name}_sha256"]:
            raise O1C84RunError(f"input {name} SHA preflight differs")
        input_sha[name] = observed

    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "source paths")
    expected = _mapping(source["expected_sha256"], "source digests")
    source_sha: dict[str, str] = {}
    for name in SOURCE_PATHS:
        candidate = _lab_path(root, paths[name], f"source {name}")
        observed = _sha_file(candidate)
        if observed != expected[name]:
            raise O1C84RunError(f"source {name} SHA preflight differs")
        source_sha[name] = observed

    native = _mapping(config["native"], "preflight native")
    compiler = _external_path(native["compiler"], "compiler")
    include = _external_path(
        native["cadical_include"], "CaDiCaL include", directory=True
    )
    library = _external_path(native["cadical_library"], "CaDiCaL library")
    if (
        _sha_file(library) != native["cadical_library_sha256"]
        or source_sha["native_v20"] != native["source_sha256"]
    ):
        raise O1C84RunError("native toolchain/source SHA preflight differs")

    prepared = prepare_fn(
        capsule_dir=parent_capsule,
        parent_result_path=parent_result,
    )
    prepared_rows = _validate_prepared(prepared)
    _validate_published_bundle(published_directory, prepared)
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
        raise O1C84RunError("Darwin/arm64/RAM/disk/process preflight differs")
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
            "byte_equal_to_regeneration": True,
        },
        "page9_sha256": PAGE9_SHA256,
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
    prepare_fn: PreparationRun = prepare_o1c83_causal_rollover,
    system_probe: Callable[[Path], Mapping[str, object]] = _default_system_probe,
) -> dict[str, object]:
    lab = (root or lab_root()).resolve(strict=True)
    return dict(
        _preflight_bundle(
            config_path, root=lab, prepare_fn=prepare_fn, system_probe=system_probe
        ).row
    )


def _completed_bytes(value: object, field: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    raise O1C84RunError(f"{field} differs")


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
    source = _lab_path(root, native["source"], "native v20 source")
    if (
        _sha_file(source) != native["source_sha256"]
        or _sha_file(library) != native["cadical_library_sha256"]
    ):
        raise O1C84RunError("native build input changed after preflight")
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
        raise O1C84RunError("native v20 compilation could not run") from exc
    version_returncode = getattr(version_result, "returncode", None)
    returncode = getattr(completed, "returncode", None)
    if version_returncode != 0 or returncode != 0 or not output.is_file():
        stderr = _completed_bytes(getattr(completed, "stderr", b""), "compiler stderr")
        raise O1C84RunError(
            "native v20 compilation failed: "
            + stderr.decode("utf-8", errors="replace").strip()[:2000]
        )
    executable_sha = _sha_file(output)
    executable_bytes = output.stat().st_size
    if (
        executable_sha != native["expected_executable_sha256"]
        or executable_bytes != native["expected_executable_bytes"]
    ):
        raise O1C84RunError("compiled native v20 executable seal differs")
    output.chmod(0o555)
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
        "executable": {
            "path": f"native/{NATIVE_EXECUTABLE_NAME}",
            "serialized_bytes": executable_bytes,
            "sha256": executable_sha,
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
        raise O1C84RunError("timestamped capsule already exists")
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
            "page9_sha256": PAGE9_SHA256,
            "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PARENT_PRIORITY_STATE_SHA256,
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
) -> None:
    if _sha_file(config_path) != preflight_row.get("config_sha256"):
        raise O1C84RunError("config changed before native call")
    inputs = _mapping(config["inputs"], "call inputs")
    approved = _mapping(preflight_row.get("input_sha256"), "approved input SHA")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        if (
            approved.get(name) != inputs[f"{name}_sha256"]
            or _sha_file(_lab_path(root, inputs[name], f"call input {name}"))
            != approved[name]
        ):
            raise O1C84RunError(f"input {name} changed before native call")
    source_config = _mapping(config["source"], "call source config")
    source_paths = _mapping(source_config["paths"], "call source paths")
    source_sha = _mapping(preflight_row.get("source_sha256"), "approved source SHA")
    for name in SOURCE_PATHS:
        path = _lab_path(root, source_paths[name], f"call source {name}")
        if _sha_file(path) != source_sha.get(name):
            raise O1C84RunError(f"source {name} changed before native call")
    native = _mapping(config["native"], "call native")
    executable = capsule / "native" / NATIVE_EXECUTABLE_NAME
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C84RunError("staged call artifact inventory differs") from exc
    if (
        {path.name for path in children} != STAGED_INITIAL_NAMES
        or any(not path.is_file() or path.is_symlink() for path in children)
    ):
        raise O1C84RunError("staged call artifact inventory differs")
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
        if (
            path.stat().st_size != row.get("serialized_bytes")
            or _sha_file(path) != row.get("sha256")
        ):
            raise O1C84RunError("staged call artifact seal differs")
    if (
        executable.is_symlink()
        or not executable.is_file()
        or executable.stat().st_size != native["expected_executable_bytes"]
        or _sha_file(executable) != native["expected_executable_sha256"]
    ):
        raise O1C84RunError("native executable call seal differs")


def _native_stdout(result: object) -> bytes:
    value = getattr(result, "native_stdout", None)
    if isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, bytes):
        payload = value
    else:
        raise O1C84RunError("adapter omitted byte-exact native stdout")
    if _sha(
        getattr(result, "native_stdout_sha256", None), "native stdout digest"
    ) != sha256_bytes(payload):
        raise O1C84RunError("native stdout digest differs")
    return payload


def _validate_native_result(result: object, stdout: bytes) -> NativeEvidence:
    if not isinstance(result, _native_v23.JointScoreSieveV23Result):
        raise O1C84RunError("adapter v23 result type differs")
    raw = _mapping(result.raw, "native result")
    try:
        decoded = _mapping(json.loads(stdout), "native stdout JSON")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C84RunError("native stdout JSON differs") from exc
    if (
        decoded != raw
        or raw.get("schema") != _native_v23.JOINT_SCORE_SIEVE_RESULT_SCHEMA
    ):
        raise O1C84RunError("native stdout/result projection differs")
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
        or raw.get("active_vault_sha256") != PAGE9_SHA256
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
        raise O1C84RunError("native v20 production binding differs")
    if (
        raw.get("priority_state") != priority_state
        or raw.get("priority_actions") != actions
    ):
        raise O1C84RunError("native promoted priority projection differs")
    if raw.get("decision_ownership") != ownership:
        raise O1C84RunError("native promoted ownership projection differs")
    if result.status == 10 and not isinstance(result.key_model, bytes):
        raise O1C84RunError("SAT result omitted key model")
    if result.status != 10 and result.key_model is not None:
        raise O1C84RunError("non-SAT result returned key model")
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
    globally_known_clauses: frozenset[bytes] = frozenset(),
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
        raise O1C84RunError("priority action count differs")
    failure_first = sum(
        row.get("semantic") == PROOF_MINING_SEMANTIC for row in actions
    )
    certified = sum(
        row.get("semantic") == CERTIFIED_CROSSING_SEMANTIC
        for row in actions
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
    globally_novel: set[bytes] = set()
    for row in emitted_rows:
        if row.get("classification") != "new":
            continue
        literals = tuple(_sequence(row.get("literals"), "emitted clause literals"))
        try:
            clause = ThresholdNoGoodClause(cast(tuple[int, ...], literals))
        except (TypeError, ValueError) as exc:
            raise O1C84RunError("emitted clause serialization differs") from exc
        if clause.serialized not in globally_known_clauses:
            globally_novel.add(clause.serialized)
    novel = len(globally_novel)
    if novel > active_new:
        raise O1C84RunError("global novelty exceeds active-vault novelty")
    certified_prune_gain = (
        realized_certified_prunes > 0 and threshold_prunes > 0 and emitted > 0
    )
    if evidence.status == 10 and not public_model_verified:
        raise O1C84RunError("SAT key failed exact public ChaCha verification")
    if evidence.status != 10 and public_model_verified:
        raise O1C84RunError("public model verification without SAT differs")
    model_gain = evidence.status == 10 and public_model_verified
    closure_gain = evidence.status == 20 or terminal_empty
    # Native v20 emits no entropy or domain estimate.  These fields stay
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
        "active_page9_new_clauses": active_new,
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
    globally_known_clauses: frozenset[bytes],
    now: Callable[[], datetime],
) -> tuple[dict[str, object], str, str, bool, int, int | None, int | None]:
    episode_dir = capsule / "episodes" / "00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    invocation_sha = _sha_file(capsule / "invocation.json")
    config_inputs = _mapping(bundle.config["inputs"], "invocation inputs")
    native_config = _mapping(bundle.config["native"], "invocation native")
    cnf_path = _lab_path(root, config_inputs["cnf"], "run CNF")
    potential_path = _lab_path(
        root, config_inputs["potential"], "run potential"
    )
    grouping_path = _lab_path(root, config_inputs["grouping"], "run grouping")
    source_path = _lab_path(root, native_config["source"], "run native source")
    _rehash_call_inputs(
        root=root,
        config_path=config_path,
        config=bundle.config,
        preflight_row=bundle.row,
        capsule=capsule,
    )
    intent = {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "created_at": now().astimezone().isoformat(timespec="microseconds"),
        "local_episode_ordinal": LOCAL_EPISODE_ORDINAL,
        "lineage_call_ordinal": LINEAGE_CALL_ORDINAL,
        "invocation_sha256": invocation_sha,
        "page9_sha256": PAGE9_SHA256,
        "continuation_bank_sha256": CONTINUATION_BANK_SHA256,
        "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
        "priority_state_receipt_sha256": PARENT_PRIORITY_STATE_SHA256,
        "candidate_order_sha256": CONTINUATION_CANDIDATE_ORDER_SHA256,
        "requested_conflicts": REQUESTED_CONFLICTS,
        "page9_burned": True,
        "lineage22_burned": True,
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
            expected_executable_sha256=native_config["expected_executable_sha256"],
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
            source_path=source_path,
            rollover_manifest_path=capsule
            / "initial"
            / PREPARATION_MANIFEST_NAME,
            priority_state_receipt_path=capsule / "initial" / RECEIPT_NAME,
            sealed_page9_path=capsule / "initial" / ACTIVE_PROJECTION_NAME,
            public_fixture=False,
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
            globally_known_clauses=globally_known_clauses,
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
            "page9_burned": True,
            "lineage22_burned": True,
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
            "page9_burned": True,
            "lineage22_burned": True,
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
            "page9_burned": True,
            "lineage22_burned": True,
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
            raise O1C84RunError("capsule contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise O1C84RunError("capsule contains a special file")
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
        "# O1C-0084 Page-9 parent-centered run",
        "",
        f"- Classification: `{result.get('classification')}`",
        f"- Stop reason: `{result.get('stop_reason')}`",
        f"- Native calls: `{resources.get('native_solver_calls')}` / 1",
        f"- Requested conflicts: `{resources.get('requested_conflicts')}` / 128",
        f"- Science gain: `{str(result.get('science_gain')).lower()}`",
        "- Page 9 and lineage 22 burned when `episodes/00/intent.json` was persisted.",
        "- Failure-first priority actions are operational proof-mining choices, not bit beliefs or science gain.",
        "- Retry, replay, reveal, target/truth input, refit, MPS, and GPU use were forbidden.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _publish_exact(path: Path, payload: bytes) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise O1C84RunError("authoritative result already differs")
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
        raise O1C84RunError("persistent artifact budget exceeded")
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
    value = dict(_read_canonical_json(authoritative, "authoritative O1C84 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C84RunError("authoritative O1C84 result differs")
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
            raise O1C84RunError("burned incomplete capsule forbids retry or replay")
        raise O1C84RunError("incomplete pre-intent capsule blocks a fresh call")
    manifest, _ = _manifest_bytes(capsule)
    if manifest != (capsule / "artifacts.sha256").read_bytes():
        raise O1C84RunError("existing capsule manifest differs")
    result_path = capsule / "result.json"
    result_payload = result_path.read_bytes()
    result = dict(_read_canonical_json(result_path, "capsule result"))
    expected_capsule = capsule.relative_to(root).as_posix()
    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("capsule") != expected_capsule
    ):
        raise O1C84RunError("existing capsule result differs")
    return result, result_payload


def _republish_existing_capsule(root: Path, capsule: Path) -> dict[str, object]:
    result, payload = _validated_capsule_result(root, capsule)
    _publish_exact(root / RESULT_RELATIVE, payload)
    return result


def _globally_known_clauses(
    prepared: PreparedCausalRolloverArtifacts,
) -> frozenset[bytes]:
    try:
        clauses = prepared.state.attic.union_vault.clauses
        result = frozenset(clause.serialized for clause in clauses)
    except (AttributeError, TypeError) as exc:
        raise O1C84RunError("prepared global attic union differs") from exc
    if (
        any(not isinstance(payload, bytes) for payload in result)
        or len(result) != ATTIC_UNION_CLAUSE_COUNT
    ):
        raise O1C84RunError("prepared global attic clause differs")
    return result


def _public_verifier(
    *, root: Path, config: Mapping[str, object]
) -> Callable[[bytes], bool]:
    inputs = _mapping(config["inputs"], "public verifier inputs")
    config_path = _lab_path(root, inputs["o1c73_config"], "O1C73 verifier config")
    if _sha_file(config_path) != inputs["o1c73_config_sha256"]:
        raise O1C84RunError("public verifier config SHA differs")
    try:
        baseline_config = _o1c73.load_config(config_path)
        baseline = _o1c73.validate_apple8_baseline(root, baseline_config)
        verifier = _o1c73._o1c66._public_target(baseline).verify
    except Exception as exc:
        raise O1C84RunError("public ChaCha verifier cannot be established") from exc
    return cast(Callable[[bytes], bool], verifier)


def run(
    config_path: str | Path = CONFIG_RELATIVE,
    *,
    root: Path | None = None,
    prepare_fn: PreparationRun = prepare_o1c83_causal_rollover,
    adapter_run: AdapterRun = _native_v23.run_joint_score_sieve,
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
            raise O1C84RunError(
                "authoritative O1C84 result lacks one sealed capsule"
            )
        capsule_result, capsule_payload = _validated_capsule_result(lab, capsules[0])
        authoritative_payload = (lab / RESULT_RELATIVE).read_bytes()
        if capsule_payload != authoritative_payload or capsule_result != existing:
            raise O1C84RunError("authoritative O1C84 result differs from capsule")
        return existing
    if capsules:
        if len(capsules) != 1:
            raise O1C84RunError("multiple O1C84 capsules forbid replay")
        return _republish_existing_capsule(lab, capsules[0])

    config_file = Path(config_path).resolve(strict=True)
    bundle = _preflight_bundle(
        config_file,
        root=lab,
        prepare_fn=prepare_fn,
        system_probe=system_probe,
    )
    verified_public_model = (
        public_verifier
        if public_verifier is not None
        else _public_verifier(root=lab, config=bundle.config)
    )
    globally_known = _globally_known_clauses(bundle.prepared)
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
        globally_known_clauses=globally_known,
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
            "page9_sha256": PAGE9_SHA256,
            "input_continuation_bank_sha256": CONTINUATION_BANK_SHA256,
            "rollover_manifest_sha256": PUBLISHED_MANIFEST_SHA256,
            "priority_state_receipt_sha256": PARENT_PRIORITY_STATE_SHA256,
            "global_novelty_baseline_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "page9_burned": True,
            "lineage22_only": True,
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
        "next_action": "Never retry or replay Page 9 / lineage 22; preserve the final priority bank only as a continuation seed.",
    }
    return _finalize_capsule(
        capsule=capsule, authoritative=lab / RESULT_RELATIVE, result=result
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or execute O1C84's one Page-9 parent-centered call"
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
    except O1C84RunError as exc:
        print(f"O1C84: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVATION_ONLY",
    "CONFIG_RELATIVE",
    "MEMORY_LIMIT_BYTES",
    "O1C84RunError",
    "OPERATIONAL_TERMINAL",
    "REQUESTED_CONFLICTS",
    "RESULT_RELATIVE",
    "THRESHOLD",
    "load_config",
    "main",
    "preflight",
    "run",
]
