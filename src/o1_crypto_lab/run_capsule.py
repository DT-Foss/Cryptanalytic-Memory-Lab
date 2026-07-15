"""Immutable, recoverable run capsules for O1C research attempts.

The manager deliberately keeps all filesystem mutation below ``runs/`` and
uses directory-relative, ``O_NOFOLLOW`` file operations.  A run is assembled
under a hidden in-progress directory, then atomically renamed to its public,
timestamped name only after its manifest is complete.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import shlex
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Mapping, Sequence
from zoneinfo import ZoneInfo

from .isolation import IsolationPolicy, IsolationViolation


CAPSULE_SCHEMA = "o1c-run-capsule-v1"
_BERLIN = ZoneInfo("Europe/Berlin")
_ATTEMPT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_MANDATORY_FILES = frozenset(
    {
        "RUN.md",
        "config.json",
        "command.txt",
        "environment.json",
        "metrics.json",
        "stdout.log",
        "stderr.log",
        "artifacts.sha256",
    }
)
_STATE_FILE = ".capsule-state.json"
_MANIFEST_FILE = "artifacts.sha256"


class ClaimLevel(str, Enum):
    """Maximum evidentiary claim supported by a run."""

    SMOKE = "SMOKE"
    RETROSPECTIVE = "RETROSPECTIVE"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    FRONTIER = "FRONTIER"
    SOTA_CANDIDATE = "SOTA_CANDIDATE"
    SOTA = "SOTA"


class RunCapsuleError(RuntimeError):
    """Base error for invalid capsule lifecycle operations."""


class RunCollisionError(RunCapsuleError):
    """An attempt ID or final directory has already been reserved."""


class RunStateError(RunCapsuleError):
    """A capsule is missing, corrupt, or used after finalization."""


@dataclass(frozen=True)
class CapsuleVerification:
    schema: str
    path: Path
    manifest_sha256: str
    checked: int
    missing: tuple[str, ...]
    mismatched: tuple[str, ...]
    unexpected: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.mismatched and not self.unexpected

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "path": str(self.path),
            "manifest_sha256": self.manifest_sha256,
            "checked": self.checked,
            "missing": list(self.missing),
            "mismatched": list(self.mismatched),
            "unexpected": list(self.unexpected),
            "ok": self.ok,
        }


@dataclass(frozen=True)
class FinalizedRun:
    attempt_id: str
    path: Path
    manifest_sha256: str
    verification: CapsuleVerification


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not finite JSON: {exc}") from exc
    return (rendered + "\n").encode("utf-8")


def _write_new(parent_fd: int, name: str, value: bytes, *, mode: int = 0o600) -> None:
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
    try:
        offset = 0
        while offset < len(value):
            offset += os.write(descriptor, value[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace(parent_fd: int, name: str, value: bytes) -> None:
    temporary = f".{name}.{secrets.token_hex(12)}.tmp"
    try:
        _write_new(parent_fd, temporary, value)
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def _read_regular(parent_fd: int, name: str) -> bytes:
    try:
        descriptor = os.open(name, _file_read_flags(), dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise IsolationViolation(f"refusing symbolic-link component: {name}") from exc
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise IsolationViolation(f"capsule member is not a regular file: {name}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1 << 20):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _open_directory(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise IsolationViolation(f"refusing symbolic-link directory: {name}") from exc
        raise


def _ensure_directory(parent_fd: int, name: str, *, mode: int = 0o700) -> int:
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return _open_directory(parent_fd, name)


def _safe_artifact_parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    parts = path.parts
    if (
        not relative
        or path.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} or part.startswith(".") for part in parts)
    ):
        raise ValueError(f"unsafe artifact path: {relative!r}")
    return parts


def _collect_files(directory_fd: int, *, prefix: str = "") -> dict[str, bytes]:
    collected: dict[str, bytes] = {}
    for name in sorted(os.listdir(directory_fd)):
        if not prefix and name in {_STATE_FILE, _MANIFEST_FILE}:
            continue
        relative = f"{prefix}/{name}" if prefix else name
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise IsolationViolation(f"symbolic links are forbidden in capsules: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = _open_directory(directory_fd, name)
            try:
                collected.update(_collect_files(child_fd, prefix=relative))
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            collected[relative] = _read_regular(directory_fd, name)
        else:
            raise IsolationViolation(f"unsupported capsule member type: {relative}")
    return collected


def _make_tree_read_only(directory_fd: int, *, include_root: bool) -> None:
    for name in os.listdir(directory_fd):
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise IsolationViolation(f"symbolic links are forbidden in capsules: {name}")
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = _open_directory(directory_fd, name)
            try:
                _make_tree_read_only(child_fd, include_root=True)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            descriptor = os.open(name, _file_read_flags(), dir_fd=directory_fd)
            try:
                os.fchmod(descriptor, 0o444)
            finally:
                os.close(descriptor)
        else:
            raise IsolationViolation(f"unsupported capsule member type: {name}")
    if include_root:
        os.fchmod(directory_fd, 0o555)


def _parse_manifest(value: bytes) -> dict[str, str]:
    entries: dict[str, str] = {}
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunStateError("capsule manifest is not UTF-8") from exc
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        parts = raw.split(maxsplit=1)
        if len(parts) != 2 or not _SHA256_RE.fullmatch(parts[0]):
            raise RunStateError(f"invalid capsule manifest line {line_number}")
        relative = parts[1].lstrip("*")
        _safe_artifact_parts(relative)
        if relative == _MANIFEST_FILE or relative in entries:
            raise RunStateError(f"invalid duplicate/self manifest member: {relative}")
        entries[relative] = parts[0].lower()
    if not entries:
        raise RunStateError("capsule manifest is empty")
    return entries


def _normalize_attempt_id(value: str) -> str:
    if not _ATTEMPT_RE.fullmatch(value) or ".." in value or value.startswith("."):
        raise ValueError(
            "attempt_id must be 1-64 path-safe letters, digits, dot, underscore, or dash"
        )
    return value


def _normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug or len(slug) > 80:
        raise ValueError("slug must yield 1-80 lowercase path-safe characters")
    return slug


def _require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{name} must be non-empty text without NUL bytes")
    return value.strip()


def _validate_source_hashes(value: Mapping[str, str]) -> dict[str, str]:
    if not value:
        raise ValueError("source_hashes must contain at least one pinned source")
    normalized: dict[str, str] = {}
    for name, digest in value.items():
        label = _require_text("source hash label", name)
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid SHA-256 for source {label!r}")
        normalized[label] = digest.lower()
    return dict(sorted(normalized.items()))


def _as_command(value: str | Sequence[str]) -> str:
    if isinstance(value, str):
        return _require_text("command", value)
    arguments = list(value)
    if not arguments or any(not isinstance(item, str) or "\x00" in item for item in arguments):
        raise ValueError("command sequence must contain safe string arguments")
    return shlex.join(arguments)


class RunCapsuleManager:
    """Create, recover, finalize, and verify isolated research runs."""

    def __init__(
        self,
        lab_root: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lab_root = Path(lab_root).resolve()
        if not self.lab_root.is_dir():
            raise FileNotFoundError(self.lab_root)
        self.policy = IsolationPolicy(self.lab_root)
        self._clock = clock or (lambda: datetime.now(tz=_BERLIN))
        self._initialize_storage()

    @property
    def output_root(self) -> Path:
        return self.policy.output_root

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capsule clock must return a timezone-aware datetime")
        return value.astimezone(_BERLIN)

    def _open_runs(self) -> int:
        lab_fd = os.open(self.lab_root, _directory_flags())
        try:
            return _open_directory(lab_fd, "runs")
        finally:
            os.close(lab_fd)

    def _initialize_storage(self) -> None:
        # Invoke the shared policy first so a pre-existing runs symlink is rejected
        # with the same confinement semantics as every other lab output.
        self.policy.output_root
        lab_fd = os.open(self.lab_root, _directory_flags())
        try:
            try:
                os.mkdir("runs", mode=0o700, dir_fd=lab_fd)
            except FileExistsError:
                pass
            runs_fd = _open_directory(lab_fd, "runs")
        finally:
            os.close(lab_fd)
        try:
            for name in (".in_progress", ".attempt_ids"):
                descriptor = _ensure_directory(runs_fd, name)
                os.close(descriptor)
            try:
                lock_fd = os.open(
                    ".capsule.lock",
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=runs_fd,
                )
            except FileExistsError:
                lock_fd = os.open(
                    ".capsule.lock",
                    os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=runs_fd,
                )
            os.close(lock_fd)
        finally:
            os.close(runs_fd)

    @contextmanager
    def _locked_runs(self) -> Iterator[int]:
        runs_fd = self._open_runs()
        lock_fd = os.open(
            ".capsule.lock",
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=runs_fd,
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield runs_fd
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
            os.close(runs_fd)

    def start(
        self,
        *,
        attempt_id: str,
        slug: str,
        commit: str,
        hypothesis: str,
        prediction: str,
        controls: Sequence[str],
        budgets: Mapping[str, Any],
        source_hashes: Mapping[str, str],
        claim_level: ClaimLevel | str,
        next_action: str,
        config: Mapping[str, Any],
        command: str | Sequence[str],
        environment: Mapping[str, Any] | None = None,
    ) -> "RunCapsule":
        attempt = _normalize_attempt_id(attempt_id)
        safe_slug = _normalize_slug(slug)
        commit_value = _require_text("commit", commit)
        hypothesis_value = _require_text("hypothesis", hypothesis)
        prediction_value = _require_text("prediction", prediction)
        next_action_value = _require_text("next_action", next_action)
        control_values = tuple(_require_text("control", item) for item in controls)
        if not control_values:
            raise ValueError("controls must contain at least one explicit control")
        try:
            claim = claim_level if isinstance(claim_level, ClaimLevel) else ClaimLevel(claim_level)
        except ValueError as exc:
            raise ValueError(f"unknown claim level: {claim_level!r}") from exc
        pinned_sources = _validate_source_hashes(source_hashes)
        command_value = _as_command(command)
        started = self._now()
        timestamp = started.strftime("%Y%m%d_%H%M%S")
        final_name = f"{timestamp}_{attempt}_{safe_slug}"
        run_token = secrets.token_hex(16)
        stage_name = f"{attempt}.{run_token}.work"
        # Validate all user-supplied JSON before reserving the attempt.
        config_document = {
            "schema": "o1c-run-config-v1",
            "attempt_id": attempt,
            "commit": commit_value,
            "hypothesis": hypothesis_value,
            "prediction": prediction_value,
            "controls": list(control_values),
            "budgets": dict(budgets),
            "source_hashes": pinned_sources,
            "claim_level": claim.value,
            "next_action": next_action_value,
            "config": dict(config),
        }
        environment_document = {
            "schema": "o1c-run-environment-v1",
            "attempt_id": attempt,
            "captured": {
                "cwd": str(Path.cwd()),
                "executable": sys.executable,
                "platform": platform.platform(),
                "python": platform.python_version(),
                "timezone": "Europe/Berlin",
            },
            "provided": dict(environment or {}),
        }
        metrics_document = {
            "schema": "o1c-run-metrics-v1",
            "attempt_id": attempt,
            "status": "running",
            "claim_level": claim.value,
            "started_at": started.isoformat(),
            "ended_at": None,
            "elapsed_seconds": None,
            "next_action": next_action_value,
            "values": {},
        }
        state = {
            "schema": CAPSULE_SCHEMA,
            "status": "running",
            "attempt_id": attempt,
            "slug": safe_slug,
            "run_token": run_token,
            "stage_name": stage_name,
            "final_name": final_name,
            "started_at": started.isoformat(),
            "commit": commit_value,
            "hypothesis": hypothesis_value,
            "prediction": prediction_value,
            "controls": list(control_values),
            "budgets": dict(budgets),
            "source_hashes": pinned_sources,
            "claim_level": claim.value,
            "next_action": next_action_value,
            "command": command_value,
        }
        config_bytes = _json_bytes(config_document)
        environment_bytes = _json_bytes(environment_document)
        metrics_bytes = _json_bytes(metrics_document)
        state_bytes = _json_bytes(state)
        claim_bytes = _json_bytes(
            {
                "schema": "o1c-attempt-reservation-v1",
                "attempt_id": attempt,
                "run_token": run_token,
                "stage_name": stage_name,
                "final_name": final_name,
                "started_at": started.isoformat(),
            }
        )
        with self._locked_runs() as runs_fd:
            try:
                os.stat(final_name, dir_fd=runs_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RunCollisionError(f"final run directory already exists: {final_name}")
            attempts_fd = _open_directory(runs_fd, ".attempt_ids")
            in_progress_fd = _open_directory(runs_fd, ".in_progress")
            reservation_name = f"{attempt}.json"
            reserved = False
            staged = False
            try:
                try:
                    _write_new(attempts_fd, reservation_name, claim_bytes)
                except FileExistsError as exc:
                    raise RunCollisionError(f"attempt ID already reserved: {attempt}") from exc
                reserved = True
                os.mkdir(stage_name, mode=0o700, dir_fd=in_progress_fd)
                staged = True
                stage_fd = _open_directory(in_progress_fd, stage_name)
                try:
                    _write_new(stage_fd, _STATE_FILE, state_bytes)
                    _write_new(stage_fd, "config.json", config_bytes)
                    _write_new(stage_fd, "command.txt", (command_value + "\n").encode("utf-8"))
                    _write_new(stage_fd, "environment.json", environment_bytes)
                    _write_new(stage_fd, "metrics.json", metrics_bytes)
                    _write_new(stage_fd, "stdout.log", b"")
                    _write_new(stage_fd, "stderr.log", b"")
                    os.fsync(stage_fd)
                finally:
                    os.close(stage_fd)
                os.fsync(in_progress_fd)
                os.fsync(attempts_fd)
            except Exception:
                if staged:
                    self._remove_flat_stage(in_progress_fd, stage_name)
                if reserved:
                    try:
                        os.unlink(reservation_name, dir_fd=attempts_fd)
                    except FileNotFoundError:
                        pass
                raise
            finally:
                os.close(in_progress_fd)
                os.close(attempts_fd)
        return RunCapsule(self, state)

    create = start

    @staticmethod
    def _remove_flat_stage(in_progress_fd: int, stage_name: str) -> None:
        try:
            stage_fd = _open_directory(in_progress_fd, stage_name)
        except FileNotFoundError:
            return
        try:
            for name in os.listdir(stage_fd):
                try:
                    os.unlink(name, dir_fd=stage_fd)
                except IsADirectoryError:
                    # Start-up cleanup happens before user artifacts can exist.
                    raise RunStateError(f"unexpected directory in partial stage: {name}")
        finally:
            os.close(stage_fd)
        os.rmdir(stage_name, dir_fd=in_progress_fd)

    def recover(self, attempt_id: str) -> "RunCapsule":
        attempt = _normalize_attempt_id(attempt_id)
        with self._locked_runs() as runs_fd:
            attempts_fd = _open_directory(runs_fd, ".attempt_ids")
            in_progress_fd = _open_directory(runs_fd, ".in_progress")
            try:
                try:
                    reservation = json.loads(
                        _read_regular(attempts_fd, f"{attempt}.json").decode("utf-8")
                    )
                except FileNotFoundError as exc:
                    raise RunStateError(f"attempt has no reservation: {attempt}") from exc
                stage_name = reservation.get("stage_name")
                if not isinstance(stage_name, str) or "/" in stage_name or stage_name.startswith("."):
                    raise RunStateError(f"invalid stage reservation for {attempt}")
                try:
                    stage_fd = _open_directory(in_progress_fd, stage_name)
                except FileNotFoundError as exc:
                    raise RunStateError(f"attempt is not recoverable (likely finalized): {attempt}") from exc
                try:
                    state = json.loads(_read_regular(stage_fd, _STATE_FILE).decode("utf-8"))
                finally:
                    os.close(stage_fd)
            finally:
                os.close(in_progress_fd)
                os.close(attempts_fd)
        if (
            state.get("schema") != CAPSULE_SCHEMA
            or state.get("status") != "running"
            or state.get("attempt_id") != attempt
            or state.get("run_token") != reservation.get("run_token")
            or state.get("stage_name") != reservation.get("stage_name")
            or state.get("final_name") != reservation.get("final_name")
        ):
            raise RunStateError(f"state/reservation mismatch for {attempt}")
        return RunCapsule(self, state)

    resume = recover

    def recoverable_attempt_ids(self) -> tuple[str, ...]:
        recoverable: list[str] = []
        with self._locked_runs() as runs_fd:
            attempts_fd = _open_directory(runs_fd, ".attempt_ids")
            in_progress_fd = _open_directory(runs_fd, ".in_progress")
            try:
                for name in sorted(os.listdir(attempts_fd)):
                    if not name.endswith(".json"):
                        continue
                    try:
                        reservation = json.loads(_read_regular(attempts_fd, name).decode("utf-8"))
                        stage = reservation["stage_name"]
                        descriptor = _open_directory(in_progress_fd, stage)
                    except (KeyError, OSError, ValueError, IsolationViolation):
                        continue
                    else:
                        os.close(descriptor)
                        recoverable.append(name[:-5])
            finally:
                os.close(in_progress_fd)
                os.close(attempts_fd)
        return tuple(recoverable)

    def verify(self, path: str | Path) -> CapsuleVerification:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.output_root / candidate
        confined = self.policy.require_output_path(candidate)
        relative = confined.relative_to(self.output_root)
        if len(relative.parts) != 1 or relative.name.startswith("."):
            raise IsolationViolation("verification requires one finalized run directory")
        runs_fd = self._open_runs()
        try:
            capsule_fd = _open_directory(runs_fd, relative.name)
        finally:
            os.close(runs_fd)
        try:
            manifest_bytes = _read_regular(capsule_fd, _MANIFEST_FILE)
            expected = _parse_manifest(manifest_bytes)
            actual_bytes = _collect_files(capsule_fd)
        finally:
            os.close(capsule_fd)
        actual_hashes = {
            name: hashlib.sha256(value).hexdigest() for name, value in actual_bytes.items()
        }
        missing = sorted(set(expected) - set(actual_hashes))
        missing.extend(sorted(_MANDATORY_FILES - {_MANIFEST_FILE} - set(actual_hashes)))
        mismatched = sorted(
            name
            for name in set(expected) & set(actual_hashes)
            if expected[name] != actual_hashes[name]
        )
        unexpected = sorted(set(actual_hashes) - set(expected))
        return CapsuleVerification(
            schema="o1c-capsule-verification-v1",
            path=confined,
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            checked=len(set(expected) & set(actual_hashes)),
            missing=tuple(dict.fromkeys(missing)),
            mismatched=tuple(mismatched),
            unexpected=tuple(unexpected),
        )


class RunCapsule:
    """One active run; mutation is disabled permanently after finalization."""

    def __init__(self, manager: RunCapsuleManager, state: Mapping[str, Any]) -> None:
        self._manager = manager
        self._state = dict(state)
        self._finalized = False

    @property
    def attempt_id(self) -> str:
        return self._state["attempt_id"]

    @property
    def staging_path(self) -> Path:
        return self._manager.output_root / ".in_progress" / self._state["stage_name"]

    @property
    def final_path(self) -> Path:
        return self._manager.output_root / self._state["final_name"]

    @contextmanager
    def _open_stage(self) -> Iterator[int]:
        if self._finalized:
            raise RunStateError(f"attempt is already finalized: {self.attempt_id}")
        runs_fd = self._manager._open_runs()
        try:
            in_progress_fd = _open_directory(runs_fd, ".in_progress")
        finally:
            os.close(runs_fd)
        try:
            stage_fd = _open_directory(in_progress_fd, self._state["stage_name"])
        finally:
            os.close(in_progress_fd)
        try:
            live = json.loads(_read_regular(stage_fd, _STATE_FILE).decode("utf-8"))
            if (
                live.get("schema") != CAPSULE_SCHEMA
                or live.get("status") != "running"
                or live.get("run_token") != self._state["run_token"]
            ):
                raise RunStateError(f"live state mismatch for {self.attempt_id}")
            yield stage_fd
        finally:
            os.close(stage_fd)

    def _append(self, name: str, value: str | bytes) -> None:
        payload = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        with self._open_stage() as stage_fd:
            descriptor = os.open(
                name,
                os.O_APPEND
                | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=stage_fd,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise IsolationViolation(f"log is not a regular file: {name}")
                offset = 0
                while offset < len(payload):
                    offset += os.write(descriptor, payload[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def append_stdout(self, value: str | bytes) -> None:
        self._append("stdout.log", value)

    def append_stderr(self, value: str | bytes) -> None:
        self._append("stderr.log", value)

    def checkpoint(self, payload: Mapping[str, Any]) -> Path:
        with self._open_stage() as stage_fd:
            sequence = 1
            try:
                prior = json.loads(_read_regular(stage_fd, "checkpoint.json").decode("utf-8"))
            except FileNotFoundError:
                pass
            else:
                sequence = int(prior.get("sequence", 0)) + 1
            document = {
                "schema": "o1c-run-checkpoint-v1",
                "attempt_id": self.attempt_id,
                "updated_at": self._manager._now().isoformat(),
                "sequence": sequence,
                "payload": dict(payload),
            }
            _atomic_replace(stage_fd, "checkpoint.json", _json_bytes(document))
        return self.staging_path / "checkpoint.json"

    def write_artifact(self, relative: str, value: bytes | bytearray | memoryview) -> Path:
        parts = _safe_artifact_parts(relative)
        payload = bytes(value)
        with self._open_stage() as stage_fd:
            artifacts_fd = _ensure_directory(stage_fd, "artifacts")
            try:
                parent_fd = artifacts_fd
                opened: list[int] = []
                try:
                    for part in parts[:-1]:
                        child_fd = _ensure_directory(parent_fd, part)
                        opened.append(child_fd)
                        parent_fd = child_fd
                    _write_new(parent_fd, parts[-1], payload)
                    os.fsync(parent_fd)
                finally:
                    for descriptor in reversed(opened):
                        os.close(descriptor)
            finally:
                os.close(artifacts_fd)
        return self.staging_path / "artifacts" / Path(*parts)

    def write_text_artifact(self, relative: str, value: str) -> Path:
        return self.write_artifact(relative, value.encode("utf-8"))

    def write_json_artifact(self, relative: str, value: Any) -> Path:
        return self.write_artifact(relative, _json_bytes(value))

    def finalize(
        self,
        *,
        metrics: Mapping[str, Any],
        status: str = "completed",
        next_action: str | None = None,
    ) -> FinalizedRun:
        if self._finalized:
            raise RunStateError(f"attempt is already finalized: {self.attempt_id}")
        if status not in {"completed", "failed", "stopped"}:
            raise ValueError("status must be completed, failed, or stopped")
        final_next_action = (
            self._state["next_action"]
            if next_action is None
            else _require_text("next_action", next_action)
        )
        ended = self._manager._now()
        started = datetime.fromisoformat(self._state["started_at"])
        elapsed = max(0.0, (ended - started).total_seconds())
        metrics_document = {
            "schema": "o1c-run-metrics-v1",
            "attempt_id": self.attempt_id,
            "status": status,
            "claim_level": self._state["claim_level"],
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "elapsed_seconds": elapsed,
            "next_action": final_next_action,
            "values": dict(metrics),
        }
        metrics_bytes = _json_bytes(metrics_document)
        run_markdown = self._render_run_markdown(
            status=status,
            ended=ended,
            elapsed=elapsed,
            metrics=dict(metrics),
            next_action=final_next_action,
        ).encode("utf-8")
        with self._manager._locked_runs() as runs_fd:
            in_progress_fd = _open_directory(runs_fd, ".in_progress")
            try:
                stage_fd = _open_directory(in_progress_fd, self._state["stage_name"])
                try:
                    live = json.loads(_read_regular(stage_fd, _STATE_FILE).decode("utf-8"))
                    if live.get("run_token") != self._state["run_token"]:
                        raise RunStateError(f"live state mismatch for {self.attempt_id}")
                    try:
                        os.stat(self._state["final_name"], dir_fd=runs_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise RunCollisionError(
                            f"final run directory already exists: {self._state['final_name']}"
                        )
                    _atomic_replace(stage_fd, "metrics.json", metrics_bytes)
                    _atomic_replace(stage_fd, "RUN.md", run_markdown)
                    files = _collect_files(stage_fd)
                    absent = sorted((_MANDATORY_FILES - {_MANIFEST_FILE}) - set(files))
                    if absent:
                        raise RunStateError(
                            f"cannot finalize; mandatory files missing: {', '.join(absent)}"
                        )
                    manifest = "".join(
                        f"{hashlib.sha256(value).hexdigest()}  {name}\n"
                        for name, value in sorted(files.items())
                    ).encode("utf-8")
                    _atomic_replace(stage_fd, _MANIFEST_FILE, manifest)
                    # Hash once more after writing the manifest to detect a member
                    # swap before publication.
                    post_manifest_files = _collect_files(stage_fd)
                    if files != post_manifest_files:
                        raise RunStateError("capsule contents changed during finalization")
                    os.unlink(_STATE_FILE, dir_fd=stage_fd)
                    os.fsync(stage_fd)
                    _make_tree_read_only(stage_fd, include_root=False)
                    try:
                        os.rename(
                            self._state["stage_name"],
                            self._state["final_name"],
                            src_dir_fd=in_progress_fd,
                            dst_dir_fd=runs_fd,
                        )
                    except Exception:
                        # Keep a failed publication recoverable. Root files may be
                        # replaced atomically even though their old inodes are 0444.
                        _write_new(stage_fd, _STATE_FILE, _json_bytes(self._state))
                        raise
                    os.fchmod(stage_fd, 0o555)
                    os.fsync(in_progress_fd)
                    os.fsync(runs_fd)
                finally:
                    os.close(stage_fd)
            finally:
                os.close(in_progress_fd)
        self._finalized = True
        verification = self._manager.verify(self.final_path)
        if not verification.ok:
            raise RunStateError(
                f"published capsule failed verification: {verification.describe()}"
            )
        return FinalizedRun(
            attempt_id=self.attempt_id,
            path=self.final_path,
            manifest_sha256=verification.manifest_sha256,
            verification=verification,
        )

    finish = finalize

    def _render_run_markdown(
        self,
        *,
        status: str,
        ended: datetime,
        elapsed: float,
        metrics: Mapping[str, Any],
        next_action: str,
    ) -> str:
        controls = "\n".join(f"- {item}" for item in self._state["controls"])
        sources = "\n".join(
            f"- `{name}`: `{digest}`"
            for name, digest in self._state["source_hashes"].items()
        )
        budgets = json.dumps(self._state["budgets"], indent=2, sort_keys=True, ensure_ascii=False)
        rendered_metrics = json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False)
        return (
            f"# O1C Run {self.attempt_id}\n\n"
            f"- Schema: `{CAPSULE_SCHEMA}`\n"
            f"- Status: `{status}`\n"
            f"- Claim level: `{self._state['claim_level']}`\n"
            f"- Git commit: `{self._state['commit']}`\n"
            f"- Started (Europe/Berlin): `{self._state['started_at']}`\n"
            f"- Ended (Europe/Berlin): `{ended.isoformat()}`\n"
            f"- Elapsed seconds: `{elapsed:.6f}`\n"
            f"- Command: `{self._state['command']}`\n\n"
            "## Hypothesis\n\n"
            f"{self._state['hypothesis']}\n\n"
            "## Prediction\n\n"
            f"{self._state['prediction']}\n\n"
            "## Controls\n\n"
            f"{controls}\n\n"
            "## Budgets\n\n"
            f"```json\n{budgets}\n```\n\n"
            "## Pinned source hashes\n\n"
            f"{sources}\n\n"
            "## Metrics\n\n"
            f"```json\n{rendered_metrics}\n```\n\n"
            "## Next highest-ROI action\n\n"
            f"{next_action}\n"
        )


__all__ = [
    "CAPSULE_SCHEMA",
    "CapsuleVerification",
    "ClaimLevel",
    "FinalizedRun",
    "RunCapsule",
    "RunCapsuleError",
    "RunCapsuleManager",
    "RunCollisionError",
    "RunStateError",
]
