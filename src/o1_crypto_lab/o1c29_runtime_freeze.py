"""Fail-closed runtime and import-closure authority for O1C-0029.

The scientific application closure contains the 25 modules loaded by a fresh
import of :mod:`o1_crypto_lab.o1c29_stacked_hot_calibration_run`.  This verifier
is deliberately pinned as a separate 26th control module: it is never silently
excluded from the loaded-module inventory.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import stat
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Mapping, Sequence, cast

import numpy as np


RUNTIME_FREEZE_SCHEMA = "o1-256-o1c29-runtime-freeze-v1"
RUNTIME_RECEIPT_SCHEMA = "o1-256-o1c29-runtime-freeze-receipt-v1"
APPLICATION_PACKAGE = "o1_crypto_lab"
APPLICATION_MODULE_COUNT = 25
VERIFIER_MODULE = "o1_crypto_lab.o1c29_runtime_freeze"
_HEX = frozenset("0123456789abcdef")
_FRESH_PROBE_PREFIX = "O1C29_RUNTIME_FREEZE_RECEIPT="
_FRESH_PROBE = r"""
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(root / "src"))
contract = json.loads(sys.stdin.buffer.read().decode("ascii"))
import o1_crypto_lab.o1c29_stacked_hot_calibration_run  # noqa: E402,F401
from o1_crypto_lab.o1c29_runtime_freeze import (  # noqa: E402
    _canonical_json_bytes,
    verify_o1c29_runtime_freeze,
)

receipt = verify_o1c29_runtime_freeze(contract, root=root)
sys.stdout.buffer.write(b"O1C29_RUNTIME_FREEZE_RECEIPT=")
sys.stdout.buffer.write(_canonical_json_bytes(receipt.receipt_document()))
sys.stdout.buffer.write(b"\n")
"""


class O1C29RuntimeFreezeError(ValueError):
    """The interpreter, NumPy build, module inventory, path, or bytes differ."""


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _mapping(
    value: object,
    field: str,
    expected: set[str] | frozenset[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise O1C29RuntimeFreezeError(f"{field} must be an object")
    row = cast(Mapping[str, object], value)
    if expected is not None and set(row) != set(expected):
        raise O1C29RuntimeFreezeError(f"{field} fields differ")
    return row


def _sequence(value: object, field: str) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise O1C29RuntimeFreezeError(f"{field} must be a sequence")
    return cast(Sequence[object], value)


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise O1C29RuntimeFreezeError(f"{field} must be a nonempty string")
    return value


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise O1C29RuntimeFreezeError(f"{field} must be an integer >= {minimum}")
    return value


def _sha256(value: object, field: str) -> str:
    digest = _string(value, field)
    if len(digest) != 64 or any(character not in _HEX for character in digest):
        raise O1C29RuntimeFreezeError(f"{field} must be lowercase SHA-256")
    return digest


def _safe_relative(value: object, field: str) -> str:
    relative = _string(value, field)
    if "\x00" in relative:
        raise O1C29RuntimeFreezeError(f"{field} is not a safe relative path")
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or path.as_posix() != relative
        or path.suffix != ".py"
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise O1C29RuntimeFreezeError(f"{field} is not a safe Python source path")
    return relative


def _hash_regular_file(path: Path, field: str) -> tuple[int, str]:
    try:
        if path.is_symlink():
            raise O1C29RuntimeFreezeError(f"{field} cannot be a symlink")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except O1C29RuntimeFreezeError:
        raise
    except OSError as exc:
        raise O1C29RuntimeFreezeError(f"{field} is not readable") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise O1C29RuntimeFreezeError(f"{field} is not a regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if size != before.st_size or identity_after != identity_before:
            raise O1C29RuntimeFreezeError(f"{field} changed while hashing")
    finally:
        os.close(descriptor)
    return size, digest.hexdigest()


def _python_fingerprint() -> dict[str, object]:
    return {
        "implementation": platform.python_implementation(),
        "implementation_name": sys.implementation.name,
        "version": list(sys.version_info[:3]),
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "platform": sysconfig.get_platform(),
        "machine": platform.machine(),
        "byteorder": sys.byteorder,
    }


def _normalized_numpy_build() -> object:
    numpy_config = importlib.import_module("numpy.__config__")
    raw = getattr(numpy_config, "CONFIG", None)
    if not isinstance(raw, Mapping):
        raise O1C29RuntimeFreezeError("NumPy build configuration is unavailable")
    # The PEP-517 temporary build-environment path is non-semantic and unique to
    # the wheel build.  Every compiler, BLAS/LAPACK, machine and SIMD field stays.
    document = json.loads(json.dumps(raw, sort_keys=True, default=str))
    if not isinstance(document, dict):
        raise O1C29RuntimeFreezeError("NumPy build configuration differs")
    python_information = document.get("Python Information")
    if isinstance(python_information, dict):
        python_information.pop("path", None)
    return document


def _numpy_fingerprint() -> dict[str, object]:
    core = importlib.import_module("numpy._core._multiarray_umath")
    multiarray = importlib.import_module("numpy._core.multiarray")
    raw_path = getattr(core, "__file__", None)
    if not isinstance(raw_path, str):
        raise O1C29RuntimeFreezeError("NumPy core extension path is unavailable")
    core_path = Path(raw_path)
    core_bytes, core_sha256 = _hash_regular_file(core_path, "NumPy core extension")
    features = getattr(core, "__cpu_features__", None)
    if not isinstance(features, Mapping):
        raise O1C29RuntimeFreezeError("NumPy CPU feature inventory is unavailable")
    enabled_features = sorted(
        key
        for key, enabled in features.items()
        if isinstance(key, str) and enabled is True
    )
    c_version_reader = getattr(multiarray, "_get_ndarray_c_version", None)
    if not callable(c_version_reader):
        raise O1C29RuntimeFreezeError("NumPy ndarray C-ABI version is unavailable")
    return {
        "version": np.__version__,
        "ndarray_c_version": int(c_version_reader()),
        "core_extension_basename": core_path.name,
        "core_extension_bytes": core_bytes,
        "core_extension_sha256": core_sha256,
        "build_fingerprint_sha256": _sha256_bytes(
            _canonical_json_bytes(_normalized_numpy_build())
        ),
        "enabled_cpu_features": enabled_features,
    }


def _module_contract(
    value: object,
    *,
    root: Path,
    field: str,
) -> tuple[str, str, Path]:
    row = _mapping(value, field, {"path", "sha256"})
    relative = _safe_relative(row["path"], f"{field}.path")
    digest = _sha256(row["sha256"], f"{field}.sha256")
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise O1C29RuntimeFreezeError(f"{field}.path is unavailable") from exc
    if not resolved.is_relative_to(root) or resolved != candidate.absolute():
        raise O1C29RuntimeFreezeError(f"{field}.path escapes or aliases the lab root")
    _size, actual_digest = _hash_regular_file(resolved, f"{field}.path")
    if actual_digest != digest:
        raise O1C29RuntimeFreezeError(f"{field} source bytes differ")
    return relative, digest, resolved


def _loaded_local_modules() -> dict[str, ModuleType]:
    loaded: dict[str, ModuleType] = {}
    prefix = f"{APPLICATION_PACKAGE}."
    for name, module in sys.modules.items():
        if name != APPLICATION_PACKAGE and not name.startswith(prefix):
            continue
        if not isinstance(module, ModuleType):
            raise O1C29RuntimeFreezeError(f"loaded module {name} is invalid")
        loaded[name] = module
    return loaded


def _verify_loaded_module(
    name: str,
    module: ModuleType,
    *,
    expected_path: Path,
    expected_sha256: str,
) -> None:
    raw_file = getattr(module, "__file__", None)
    spec = getattr(module, "__spec__", None)
    raw_origin = getattr(spec, "origin", None)
    if not isinstance(raw_file, str) or not isinstance(raw_origin, str):
        raise O1C29RuntimeFreezeError(f"loaded module {name} has no source origin")
    try:
        loaded_path = Path(raw_file).resolve(strict=True)
        origin_path = Path(raw_origin).resolve(strict=True)
    except OSError as exc:
        raise O1C29RuntimeFreezeError(
            f"loaded module {name} source is unavailable"
        ) from exc
    if loaded_path != expected_path or origin_path != expected_path:
        raise O1C29RuntimeFreezeError(f"loaded module {name} path differs")
    _size, digest = _hash_regular_file(expected_path, f"loaded module {name}")
    if digest != expected_sha256:
        raise O1C29RuntimeFreezeError(f"loaded module {name} bytes differ")


@dataclass(frozen=True, slots=True)
class RuntimeFreezeReceipt:
    """Auditable receipt emitted only after every runtime invariant passes."""

    contract_sha256: str
    application_closure_sha256: str
    verifier_sha256: str
    python_fingerprint: Mapping[str, object]
    numpy_fingerprint: Mapping[str, object]
    loaded_module_names: tuple[str, ...]

    def receipt_document(self) -> dict[str, object]:
        unsigned = {
            "schema": RUNTIME_RECEIPT_SCHEMA,
            "contract_sha256": self.contract_sha256,
            "application_module_count": APPLICATION_MODULE_COUNT,
            "loaded_local_module_count": APPLICATION_MODULE_COUNT + 1,
            "application_closure_sha256": self.application_closure_sha256,
            "verifier_module": VERIFIER_MODULE,
            "verifier_sha256": self.verifier_sha256,
            "python": dict(self.python_fingerprint),
            "numpy": dict(self.numpy_fingerprint),
            "loaded_module_names": list(self.loaded_module_names),
        }
        return {
            **unsigned,
            "receipt_sha256": _sha256_bytes(_canonical_json_bytes(unsigned)),
        }


def _receipt_from_fresh_probe(
    value: object,
    *,
    contract: Mapping[str, object],
) -> RuntimeFreezeReceipt:
    row = _mapping(
        value,
        "fresh runtime receipt",
        {
            "schema",
            "contract_sha256",
            "application_module_count",
            "loaded_local_module_count",
            "application_closure_sha256",
            "verifier_module",
            "verifier_sha256",
            "python",
            "numpy",
            "loaded_module_names",
            "receipt_sha256",
        },
    )
    unsigned = dict(row)
    receipt_sha256 = _sha256(
        unsigned.pop("receipt_sha256"), "fresh runtime receipt SHA"
    )
    if _sha256_bytes(_canonical_json_bytes(unsigned)) != receipt_sha256:
        raise O1C29RuntimeFreezeError("fresh runtime receipt commitment differs")
    closure = _mapping(
        contract["application_closure"], "fresh runtime receipt application closure"
    )
    modules = _mapping(
        closure.get("modules"), "fresh runtime receipt application modules"
    )
    verifier = _mapping(contract["verifier"], "fresh runtime receipt verifier")
    verifier_module = _string(
        verifier.get("module"), "fresh runtime receipt verifier module"
    )
    expected_names = tuple(sorted((*modules, verifier_module)))
    loaded_names_raw = _sequence(
        row["loaded_module_names"], "fresh runtime receipt loaded modules"
    )
    if any(not isinstance(name, str) for name in loaded_names_raw):
        raise O1C29RuntimeFreezeError("fresh runtime receipt loaded modules differ")
    loaded_names = tuple(cast(str, name) for name in loaded_names_raw)
    if (
        row.get("schema") != RUNTIME_RECEIPT_SCHEMA
        or row.get("application_module_count") != APPLICATION_MODULE_COUNT
        or row.get("loaded_local_module_count") != APPLICATION_MODULE_COUNT + 1
        or row.get("verifier_module") != VERIFIER_MODULE
        or loaded_names != expected_names
        or row.get("contract_sha256") != _sha256_bytes(_canonical_json_bytes(contract))
        or row.get("application_closure_sha256") != closure.get("closure_sha256")
        or row.get("verifier_sha256") != verifier.get("sha256")
    ):
        raise O1C29RuntimeFreezeError("fresh runtime receipt identity differs")
    return RuntimeFreezeReceipt(
        contract_sha256=_sha256(
            row["contract_sha256"], "fresh runtime receipt contract SHA"
        ),
        application_closure_sha256=_sha256(
            row["application_closure_sha256"],
            "fresh runtime receipt application closure SHA",
        ),
        verifier_sha256=_sha256(
            row["verifier_sha256"], "fresh runtime receipt verifier SHA"
        ),
        python_fingerprint=_mapping(row["python"], "fresh runtime receipt python"),
        numpy_fingerprint=_mapping(row["numpy"], "fresh runtime receipt numpy"),
        loaded_module_names=loaded_names,
    )


def verify_o1c29_runtime_freeze_fresh(
    contract: object,
    *,
    root: str | Path,
    timeout_seconds: float = 30.0,
) -> RuntimeFreezeReceipt:
    """Run the strict verifier in a clean isolated child of ``sys.executable``.

    ``-I`` ignores ambient Python paths and user-site configuration, while
    ``-B`` prevents bytecode writes.  Only the resolved lab ``src`` directory is
    inserted by the fixed child program.  This is the stable API for a config
    loader that may itself run under pytest or another import-rich controller.
    """

    if isinstance(timeout_seconds, bool) or not isinstance(
        timeout_seconds, (int, float)
    ):
        raise O1C29RuntimeFreezeError("fresh runtime timeout must be numeric")
    timeout = float(timeout_seconds)
    if not 0.0 < timeout <= 60.0:
        raise O1C29RuntimeFreezeError("fresh runtime timeout differs")
    lab_root = Path(root).resolve(strict=True)
    top = _mapping(
        contract,
        "runtime freeze",
        {"schema", "python", "numpy", "application_closure", "verifier"},
    )
    payload = _canonical_json_bytes(top)
    try:
        completed = subprocess.run(
            (sys.executable, "-I", "-B", "-c", _FRESH_PROBE, str(lab_root)),
            cwd=lab_root,
            input=payload,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise O1C29RuntimeFreezeError("fresh runtime probe could not complete") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()
        suffix = detail[-1][:512] if detail else f"exit {completed.returncode}"
        raise O1C29RuntimeFreezeError(f"fresh runtime probe rejected: {suffix}")
    try:
        stdout = completed.stdout.decode("ascii")
    except UnicodeDecodeError as exc:
        raise O1C29RuntimeFreezeError(
            "fresh runtime probe output is not ASCII"
        ) from exc
    lines = stdout.splitlines()
    if len(lines) != 1 or not lines[0].startswith(_FRESH_PROBE_PREFIX):
        raise O1C29RuntimeFreezeError("fresh runtime probe output framing differs")
    try:
        document = json.loads(lines[0][len(_FRESH_PROBE_PREFIX) :])
    except json.JSONDecodeError as exc:
        raise O1C29RuntimeFreezeError("fresh runtime probe receipt is invalid") from exc
    receipt = _receipt_from_fresh_probe(document, contract=top)
    if receipt.receipt_document() != document:
        raise O1C29RuntimeFreezeError("fresh runtime probe receipt roundtrip differs")
    return receipt


def verify_o1c29_runtime_freeze(
    contract: object,
    *,
    root: str | Path,
) -> RuntimeFreezeReceipt:
    """Verify the real process against the frozen 25+1 runtime contract.

    This function intentionally reads :data:`sys.modules` itself.  Formal use
    belongs in the fresh O1C-0029 CLI process before reservation; callers cannot
    supply a synthetic module inventory.
    """

    lab_root = Path(root).resolve(strict=True)
    top = _mapping(
        contract,
        "runtime freeze",
        {"schema", "python", "numpy", "application_closure", "verifier"},
    )
    if top.get("schema") != RUNTIME_FREEZE_SCHEMA:
        raise O1C29RuntimeFreezeError("runtime freeze schema differs")

    expected_python = _mapping(
        top["python"],
        "runtime freeze python",
        {
            "implementation",
            "implementation_name",
            "version",
            "cache_tag",
            "soabi",
            "platform",
            "machine",
            "byteorder",
        },
    )
    version = _sequence(expected_python["version"], "runtime freeze python.version")
    if len(version) != 3 or any(
        isinstance(value, bool) or not isinstance(value, int) for value in version
    ):
        raise O1C29RuntimeFreezeError("runtime freeze python.version differs")
    actual_python = _python_fingerprint()
    if dict(expected_python) != actual_python:
        raise O1C29RuntimeFreezeError("CPython runtime fingerprint differs")

    expected_numpy = _mapping(
        top["numpy"],
        "runtime freeze numpy",
        {
            "version",
            "ndarray_c_version",
            "core_extension_basename",
            "core_extension_bytes",
            "core_extension_sha256",
            "build_fingerprint_sha256",
            "enabled_cpu_features",
        },
    )
    _string(expected_numpy["version"], "runtime freeze numpy.version")
    _integer(
        expected_numpy["ndarray_c_version"],
        "runtime freeze numpy.ndarray_c_version",
        minimum=1,
    )
    _string(
        expected_numpy["core_extension_basename"],
        "runtime freeze numpy.core_extension_basename",
    )
    _integer(
        expected_numpy["core_extension_bytes"],
        "runtime freeze numpy.core_extension_bytes",
        minimum=1,
    )
    _sha256(
        expected_numpy["core_extension_sha256"],
        "runtime freeze numpy.core_extension_sha256",
    )
    _sha256(
        expected_numpy["build_fingerprint_sha256"],
        "runtime freeze numpy.build_fingerprint_sha256",
    )
    features = _sequence(
        expected_numpy["enabled_cpu_features"],
        "runtime freeze numpy.enabled_cpu_features",
    )
    if any(not isinstance(feature, str) or not feature for feature in features):
        raise O1C29RuntimeFreezeError("runtime freeze NumPy CPU features differ")
    actual_numpy = _numpy_fingerprint()
    if dict(expected_numpy) != actual_numpy:
        raise O1C29RuntimeFreezeError("NumPy runtime/ABI/build fingerprint differs")

    closure = _mapping(
        top["application_closure"],
        "runtime freeze application closure",
        {"package", "module_count", "closure_sha256", "modules"},
    )
    if (
        closure.get("package") != APPLICATION_PACKAGE
        or closure.get("module_count") != APPLICATION_MODULE_COUNT
    ):
        raise O1C29RuntimeFreezeError("application closure identity differs")
    expected_closure_sha256 = _sha256(
        closure["closure_sha256"], "runtime freeze application closure SHA"
    )
    modules = _mapping(closure["modules"], "runtime freeze application modules")
    if len(modules) != APPLICATION_MODULE_COUNT:
        raise O1C29RuntimeFreezeError("application module inventory differs")
    if VERIFIER_MODULE in modules:
        raise O1C29RuntimeFreezeError(
            "verifier cannot be hidden in application closure"
        )
    closure_document = {
        "package": APPLICATION_PACKAGE,
        "module_count": APPLICATION_MODULE_COUNT,
        "modules": dict(modules),
    }
    if (
        _sha256_bytes(_canonical_json_bytes(closure_document))
        != expected_closure_sha256
    ):
        raise O1C29RuntimeFreezeError("application closure commitment differs")

    expected_modules: dict[str, tuple[Path, str]] = {}
    for name, value in modules.items():
        if name != APPLICATION_PACKAGE and not name.startswith(
            f"{APPLICATION_PACKAGE}."
        ):
            raise O1C29RuntimeFreezeError("application module name escapes package")
        _relative, digest, resolved = _module_contract(
            value,
            root=lab_root,
            field=f"runtime freeze module {name}",
        )
        if resolved in {path for path, _digest in expected_modules.values()}:
            raise O1C29RuntimeFreezeError("application module paths are not unique")
        expected_modules[name] = (resolved, digest)

    verifier = _mapping(
        top["verifier"],
        "runtime freeze verifier",
        {"module", "path", "sha256"},
    )
    if verifier.get("module") != VERIFIER_MODULE:
        raise O1C29RuntimeFreezeError("runtime verifier identity differs")
    _relative, verifier_sha256, verifier_path = _module_contract(
        {"path": verifier["path"], "sha256": verifier["sha256"]},
        root=lab_root,
        field="runtime freeze verifier",
    )
    expected_modules[VERIFIER_MODULE] = (verifier_path, verifier_sha256)

    loaded = _loaded_local_modules()
    if set(loaded) != set(expected_modules):
        missing = sorted(set(expected_modules) - set(loaded))
        extra = sorted(set(loaded) - set(expected_modules))
        raise O1C29RuntimeFreezeError(
            f"loaded local module inventory differs; missing={missing}, extra={extra}"
        )
    for name, (expected_path, expected_sha256) in expected_modules.items():
        _verify_loaded_module(
            name,
            loaded[name],
            expected_path=expected_path,
            expected_sha256=expected_sha256,
        )

    return RuntimeFreezeReceipt(
        contract_sha256=_sha256_bytes(_canonical_json_bytes(top)),
        application_closure_sha256=expected_closure_sha256,
        verifier_sha256=verifier_sha256,
        python_fingerprint=actual_python,
        numpy_fingerprint=actual_numpy,
        loaded_module_names=tuple(sorted(loaded)),
    )
