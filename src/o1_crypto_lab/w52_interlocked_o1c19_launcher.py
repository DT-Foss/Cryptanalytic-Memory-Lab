"""Read-only W52 interlock that launches the frozen O1C-0019 gate exactly once.

The watcher never writes to the sibling repository and never imports its Python
package.  It reads only the eight A526 progress envelopes and launcher PID files,
then requires a stable terminal state, no live launcher, adequate local resources,
an exact frozen O1C-0019 source inventory, and a clean descendant worktree before
replacing itself with the artifact-only O1C-0019 CLI.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
import traceback
from collections import Counter
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping, NoReturn, Sequence


INTERLOCK_CONFIG_SCHEMA = "o1-256-w52-interlocked-o1c0019-launcher-config-v1"
INTERLOCK_REPORT_SCHEMA = "o1-256-w52-interlocked-o1c0019-snapshot-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_PROGRESS_STATUSES = frozenset(
    {
        "running",
        "candidate_pending_confirmation",
        "candidate_confirmed",
        "peer_confirmed",
        "worker_exhausted",
    }
)


class W52InterlockError(RuntimeError):
    """The interlock config, sibling envelope, or release gate differs."""


def _mapping(
    value: object,
    field: str,
    expected: set[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise W52InterlockError(f"{field} must be an object")
    if expected is not None and set(value) != expected:
        raise W52InterlockError(f"{field} fields differ")
    return value


def _integer(
    value: object,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise W52InterlockError(f"{field} must be an integer in [{minimum},{maximum}]")
    return value


def _finite(
    value: object,
    field: str,
    minimum: float,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise W52InterlockError(f"{field} must be finite in [{minimum},{maximum}]")
    return float(value)


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise W52InterlockError(f"{field} must be a lowercase SHA-256")
    return value


def _git_oid(value: object, field: str) -> str:
    if not isinstance(value, str) or _GIT_OID.fullmatch(value) is None:
        raise W52InterlockError(f"{field} must be a lowercase 40-hex Git OID")
    return value


def _relative(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise W52InterlockError(f"{field} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise W52InterlockError(f"{field} must be a normalized relative path")
    return path


def _regular_file(path: Path, field: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise W52InterlockError(f"{field} is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise W52InterlockError(f"{field} must be a non-symlink regular file")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class W52InterlockConfig:
    config_path: Path
    lab_root: Path
    workspace_root: Path
    sibling_root: Path
    state_directory: Path
    progress_schema: str
    worker_count: int
    worker_tasks: int
    assignments_per_cell: int
    progress_pattern: str
    pid_pattern: str
    fingerprints: tuple[str, ...]
    terminal_statuses: frozenset[str]
    launcher_source_marker: str
    launcher_release_pattern: str
    observed_processes: tuple[tuple[int, tuple[str, ...]], ...]
    related_process_markers: tuple[tuple[str, ...], ...]
    poll_seconds: float
    report_every_polls: int
    stable_terminal_polls: int
    minimum_memory_free_percent: int
    maximum_load_per_cpu: float
    required_ancestor_commit: str
    run_config: Path
    run_config_sha256: str
    frozen_sources: tuple[tuple[Path, str], ...]

    @property
    def total_pair_cells(self) -> int:
        return self.worker_count * self.worker_tasks

    @property
    def lock_path(self) -> Path:
        return self.lab_root / "runs/.o1c0019-interlock.lock"

    def worker_progress_path(self, worker_index: int) -> Path:
        return self.state_directory / self.progress_pattern.format(
            worker_index=worker_index
        )

    def worker_pid_path(self, worker_index: int) -> Path:
        return self.state_directory / self.pid_pattern.format(worker_index=worker_index)

    def worker_release_marker(self, worker_index: int) -> str:
        return self.launcher_release_pattern.format(worker_index=worker_index)


@dataclass(frozen=True)
class W52WorkerSnapshot:
    worker_index: int
    status: str
    completed_pair_cells: int
    completed_assignments: int
    fingerprint_sha256: str
    progress_mtime_ns: int
    launcher_pid: int
    launcher_active: bool


@dataclass(frozen=True)
class W52Snapshot:
    workers: tuple[W52WorkerSnapshot, ...]
    terminal: bool
    terminal_commitment_sha256: str
    total_pair_cells: int
    completed_pair_cells: int
    completed_assignments: int
    active_w52_pids: tuple[int, ...]
    stop_file_present: bool

    @property
    def completion_fraction(self) -> float:
        return self.completed_pair_cells / self.total_pair_cells

    @property
    def released(self) -> bool:
        return self.terminal and not self.active_w52_pids

    @property
    def status_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(worker.status for worker in self.workers).items()))


@dataclass(frozen=True)
class LocalGateSnapshot:
    memory_free_percent: int
    load_one_minute: float
    logical_cpus: int
    worktree_clean: bool
    ancestor_present: bool
    run_config_matches: bool
    mismatched_frozen_sources: tuple[str, ...]

    @property
    def load_per_cpu(self) -> float:
        return self.load_one_minute / self.logical_cpus


@dataclass(frozen=True)
class InterlockSnapshot:
    w52: W52Snapshot
    local: LocalGateSnapshot
    ready: bool
    reasons: tuple[str, ...]

    def describe(self) -> dict[str, object]:
        return {
            "schema": INTERLOCK_REPORT_SCHEMA,
            "ready": self.ready,
            "reasons": list(self.reasons),
            "w52": {
                "terminal": self.w52.terminal,
                "released": self.w52.released,
                "status_counts": self.w52.status_counts,
                "completed_pair_cells": self.w52.completed_pair_cells,
                "total_pair_cells": self.w52.total_pair_cells,
                "completion_fraction": self.w52.completion_fraction,
                "completed_assignments": self.w52.completed_assignments,
                "active_w52_pids": list(self.w52.active_w52_pids),
                "stop_file_present": self.w52.stop_file_present,
                "terminal_commitment_sha256": (self.w52.terminal_commitment_sha256),
            },
            "local": {
                "memory_free_percent": self.local.memory_free_percent,
                "load_one_minute": self.local.load_one_minute,
                "logical_cpus": self.local.logical_cpus,
                "load_per_cpu": self.local.load_per_cpu,
                "worktree_clean": self.local.worktree_clean,
                "required_ancestor_present": self.local.ancestor_present,
                "run_config_matches": self.local.run_config_matches,
                "mismatched_frozen_sources": list(self.local.mismatched_frozen_sources),
            },
        }


def load_interlock_config(
    path: str | Path,
    *,
    lab_root: str | Path | None = None,
) -> W52InterlockConfig:
    config_path = Path(path).resolve(strict=True)
    _regular_file(config_path, "config")
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise W52InterlockError("interlock config is unreadable") from exc
    top = _mapping(
        value,
        "config",
        {"schema", "attempt_id", "sibling", "release", "run"},
    )
    if top["schema"] != INTERLOCK_CONFIG_SCHEMA or top["attempt_id"] != "O1C-0019":
        raise W52InterlockError("interlock config identity differs")

    root = (
        Path(lab_root).resolve(strict=True)
        if lab_root is not None
        else Path(__file__).resolve().parents[2]
    )
    workspace = root.parent.resolve(strict=True)
    sibling = _mapping(
        top["sibling"],
        "sibling",
        {
            "repository",
            "state_directory",
            "progress_schema",
            "worker_count",
            "worker_tasks",
            "assignments_per_cell",
            "progress_pattern",
            "pid_pattern",
            "fingerprint_sha256",
            "terminal_statuses",
            "launcher_source_marker",
            "launcher_release_pattern",
            "observed_processes",
            "related_process_markers",
        },
    )
    sibling_root = (
        workspace / _relative(sibling["repository"], "sibling.repository")
    ).resolve(strict=True)
    if sibling_root == root or not sibling_root.is_relative_to(workspace):
        raise W52InterlockError("sibling repository escapes the workspace")
    state_directory = (
        sibling_root / _relative(sibling["state_directory"], "sibling.state_directory")
    ).resolve(strict=True)
    if not state_directory.is_relative_to(sibling_root) or not state_directory.is_dir():
        raise W52InterlockError("sibling state directory differs")
    worker_count = _integer(sibling["worker_count"], "sibling.worker_count", 1, 64)
    worker_tasks = _integer(sibling["worker_tasks"], "sibling.worker_tasks", 1, 1 << 40)
    assignments_per_cell = _integer(
        sibling["assignments_per_cell"],
        "sibling.assignments_per_cell",
        1,
        1 << 40,
    )
    fingerprints_value = sibling["fingerprint_sha256"]
    if (
        not isinstance(fingerprints_value, list)
        or len(fingerprints_value) != worker_count
    ):
        raise W52InterlockError("sibling fingerprint inventory differs")
    fingerprints = tuple(
        _sha256(item, f"sibling.fingerprint_sha256[{index}]")
        for index, item in enumerate(fingerprints_value)
    )
    terminal_value = sibling["terminal_statuses"]
    if not isinstance(terminal_value, list) or not terminal_value:
        raise W52InterlockError("sibling terminal statuses differ")
    terminal_statuses = frozenset(terminal_value)
    if (
        any(not isinstance(item, str) for item in terminal_value)
        or not terminal_statuses <= _PROGRESS_STATUSES
        or "running" in terminal_statuses
        or "candidate_pending_confirmation" in terminal_statuses
    ):
        raise W52InterlockError("sibling terminal statuses differ")
    for field in (
        "progress_pattern",
        "pid_pattern",
        "launcher_release_pattern",
    ):
        pattern = sibling[field]
        if (
            not isinstance(pattern, str)
            or pattern.count("{worker_index}") != 1
            or Path(pattern.replace("{worker_index}", "0")).name
            != pattern.replace("{worker_index}", "0")
        ):
            raise W52InterlockError(f"sibling.{field} differs")
    launcher_source_marker = sibling["launcher_source_marker"]
    if not isinstance(launcher_source_marker, str) or not launcher_source_marker:
        raise W52InterlockError("sibling launcher source marker differs")
    observed_value = sibling["observed_processes"]
    if not isinstance(observed_value, list):
        raise W52InterlockError("sibling observed process inventory differs")
    observed_processes: list[tuple[int, tuple[str, ...]]] = []
    observed_pids: set[int] = set()
    for index, item in enumerate(observed_value):
        row = _mapping(
            item,
            f"sibling.observed_processes[{index}]",
            {"pid", "markers"},
        )
        pid = _integer(
            row["pid"],
            f"observed process {index} PID",
            1,
            (1 << 31) - 1,
        )
        markers_value = row["markers"]
        if (
            pid in observed_pids
            or not isinstance(markers_value, list)
            or not markers_value
            or any(
                not isinstance(marker, str) or not marker for marker in markers_value
            )
        ):
            raise W52InterlockError("sibling observed process inventory differs")
        observed_pids.add(pid)
        observed_processes.append((pid, tuple(markers_value)))
    related_value = sibling["related_process_markers"]
    if not isinstance(related_value, list):
        raise W52InterlockError("sibling related process markers differ")
    related_process_markers: list[tuple[str, ...]] = []
    for index, markers_value in enumerate(related_value):
        if (
            not isinstance(markers_value, list)
            or not markers_value
            or any(
                not isinstance(marker, str) or not marker for marker in markers_value
            )
        ):
            raise W52InterlockError(f"sibling related process markers {index} differ")
        related_process_markers.append(tuple(markers_value))

    release = _mapping(
        top["release"],
        "release",
        {
            "poll_seconds",
            "report_every_polls",
            "stable_terminal_polls",
            "minimum_memory_free_percent",
            "maximum_load_per_cpu",
        },
    )
    poll_seconds = _finite(release["poll_seconds"], "release.poll_seconds", 1.0, 3600.0)
    report_every_polls = _integer(
        release["report_every_polls"], "release.report_every_polls", 1, 100_000
    )
    stable_terminal_polls = _integer(
        release["stable_terminal_polls"],
        "release.stable_terminal_polls",
        2,
        100,
    )
    minimum_memory_free_percent = _integer(
        release["minimum_memory_free_percent"],
        "release.minimum_memory_free_percent",
        1,
        100,
    )
    maximum_load_per_cpu = _finite(
        release["maximum_load_per_cpu"],
        "release.maximum_load_per_cpu",
        0.01,
        10.0,
    )

    run = _mapping(
        top["run"],
        "run",
        {
            "required_ancestor_commit",
            "config",
            "config_sha256",
            "frozen_source_sha256",
        },
    )
    required_ancestor = _git_oid(
        run["required_ancestor_commit"], "run.required_ancestor_commit"
    )
    run_config = (root / _relative(run["config"], "run.config")).resolve(strict=True)
    if not run_config.is_relative_to(root):
        raise W52InterlockError("run config escapes the lab")
    _regular_file(run_config, "run config")
    run_config_sha256 = _sha256(run["config_sha256"], "run.config_sha256")
    frozen_value = _mapping(run["frozen_source_sha256"], "run.frozen_source_sha256")
    if not frozen_value:
        raise W52InterlockError("frozen source inventory is empty")
    frozen_sources: list[tuple[Path, str]] = []
    for relative, digest in sorted(frozen_value.items()):
        source = (root / _relative(relative, f"frozen source {relative}")).resolve(
            strict=True
        )
        if not source.is_relative_to(root):
            raise W52InterlockError("frozen source escapes the lab")
        _regular_file(source, f"frozen source {relative}")
        frozen_sources.append((source, _sha256(digest, f"frozen source {relative}")))

    return W52InterlockConfig(
        config_path=config_path,
        lab_root=root,
        workspace_root=workspace,
        sibling_root=sibling_root,
        state_directory=state_directory,
        progress_schema=str(sibling["progress_schema"]),
        worker_count=worker_count,
        worker_tasks=worker_tasks,
        assignments_per_cell=assignments_per_cell,
        progress_pattern=str(sibling["progress_pattern"]),
        pid_pattern=str(sibling["pid_pattern"]),
        fingerprints=fingerprints,
        terminal_statuses=terminal_statuses,
        launcher_source_marker=launcher_source_marker,
        launcher_release_pattern=str(sibling["launcher_release_pattern"]),
        observed_processes=tuple(observed_processes),
        related_process_markers=tuple(related_process_markers),
        poll_seconds=poll_seconds,
        report_every_polls=report_every_polls,
        stable_terminal_polls=stable_terminal_polls,
        minimum_memory_free_percent=minimum_memory_free_percent,
        maximum_load_per_cpu=maximum_load_per_cpu,
        required_ancestor_commit=required_ancestor,
        run_config=run_config,
        run_config_sha256=run_config_sha256,
        frozen_sources=tuple(frozen_sources),
    )


ProcessProbe = Callable[[int, Sequence[str]], bool]
ProcessTableProbe = Callable[[Sequence[Sequence[str]]], Sequence[int]]


def launcher_process_active(pid: int, markers: Sequence[str]) -> bool:
    """Return whether *pid* still has the expected W52 identity.

    PID files can be stale.  A live unrelated process is not W52 activity, while
    a process-table inspection failure still fails closed.
    """

    completed = subprocess.run(
        ("/bin/ps", "-fp", str(pid)),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode not in (0, 1):
        raise W52InterlockError("launcher process inspection failed")
    lines = [line for line in completed.stdout.splitlines()[1:] if line.strip()]
    if not lines:
        return False
    command = " ".join(lines)
    return all(marker in command for marker in markers)


def related_process_pids(marker_groups: Sequence[Sequence[str]]) -> tuple[int, ...]:
    """Find W52 processes even when its launcher PID files are stale.

    A long-lived production job can be restarted under new PIDs.  Exact known-PID
    probes remain useful, but only a full read-only process-table scan closes that
    restart gap.  Inspection failure raises and therefore resets the release gate.
    """

    if not marker_groups:
        return ()
    completed = subprocess.run(
        ("/bin/ps", "-axww", "-o", "pid=", "-o", "command="),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise W52InterlockError("W52 process-table inspection failed")
    found: set[int] = set()
    for line in completed.stdout.splitlines():
        match = re.match(r"\s*([0-9]+)\s+(.*)\Z", line)
        if match is None:
            continue
        pid = int(match.group(1))
        command = match.group(2)
        if any(all(marker in command for marker in group) for group in marker_groups):
            found.add(pid)
    return tuple(sorted(found))


def inspect_w52(
    config: W52InterlockConfig,
    *,
    process_probe: ProcessProbe = launcher_process_active,
    process_table_probe: ProcessTableProbe = related_process_pids,
) -> W52Snapshot:
    workers: list[W52WorkerSnapshot] = []
    for worker_index in range(config.worker_count):
        progress_path = config.worker_progress_path(worker_index)
        _regular_file(progress_path, f"worker {worker_index} progress")
        try:
            row = json.loads(progress_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise W52InterlockError(
                f"worker {worker_index} progress is unreadable"
            ) from exc
        progress = _mapping(row, f"worker {worker_index} progress")
        status = progress.get("status")
        fingerprint = progress.get("fingerprint_sha256")
        if (
            progress.get("schema") != config.progress_schema
            or progress.get("attempt_id") != "A526"
            or progress.get("worker_index") != worker_index
            or status not in _PROGRESS_STATUSES
            or fingerprint != config.fingerprints[worker_index]
            or progress.get("matched_control_candidates") != 0
        ):
            raise W52InterlockError(f"worker {worker_index} progress identity differs")
        completed_cells = _integer(
            progress.get("completed_pair_cells"),
            f"worker {worker_index} completed_pair_cells",
            0,
            config.worker_tasks,
        )
        completed_assignments = _integer(
            progress.get("completed_assignments"),
            f"worker {worker_index} completed_assignments",
            0,
            1 << 63,
        )
        if (
            progress.get("next_worker_step") != completed_cells
            or completed_assignments != completed_cells * config.assignments_per_cell
        ):
            raise W52InterlockError(f"worker {worker_index} progress geometry differs")
        if status == "worker_exhausted" and completed_cells != config.worker_tasks:
            raise W52InterlockError(
                f"worker {worker_index} exhausted before its stripe completed"
            )
        pid_path = config.worker_pid_path(worker_index)
        _regular_file(pid_path, f"worker {worker_index} launcher PID")
        try:
            pid = int(pid_path.read_text(encoding="ascii").strip())
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise W52InterlockError(
                f"worker {worker_index} launcher PID differs"
            ) from exc
        if not 1 <= pid <= (1 << 31) - 1:
            raise W52InterlockError(f"worker {worker_index} launcher PID differs")
        active = process_probe(
            pid,
            (
                config.launcher_source_marker,
                config.worker_release_marker(worker_index),
            ),
        )
        workers.append(
            W52WorkerSnapshot(
                worker_index=worker_index,
                status=str(status),
                completed_pair_cells=completed_cells,
                completed_assignments=completed_assignments,
                fingerprint_sha256=str(fingerprint),
                progress_mtime_ns=progress_path.stat().st_mtime_ns,
                launcher_pid=pid,
                launcher_active=active,
            )
        )

    observed_active = [
        pid for pid, markers in config.observed_processes if process_probe(pid, markers)
    ]
    dynamically_observed = process_table_probe(config.related_process_markers)
    if any(
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or not 1 <= pid <= (1 << 31) - 1
        for pid in dynamically_observed
    ):
        raise W52InterlockError("W52 process-table result differs")
    terminal = all(worker.status in config.terminal_statuses for worker in workers)
    stopped = any(
        worker.status in {"candidate_confirmed", "peer_confirmed"} for worker in workers
    )
    stop_path = config.state_directory / "a526_confirmed_stop_v1.json"
    stop_present = stop_path.exists()
    if stop_present:
        _regular_file(stop_path, "W52 confirmed stop")
    if stopped != stop_present and terminal:
        raise W52InterlockError("terminal W52 stop-file semantics differ")
    if stop_present:
        stop_sha256 = _file_sha256(stop_path)
        for worker in workers:
            if worker.status not in {"candidate_confirmed", "peer_confirmed"}:
                continue
            progress = json.loads(
                config.worker_progress_path(worker.worker_index).read_text(
                    encoding="utf-8"
                )
            )
            if progress.get("confirmed_stop_sha256") != stop_sha256:
                raise W52InterlockError(
                    f"worker {worker.worker_index} stop binding differs"
                )
    commitment_rows = [
        {
            "worker_index": worker.worker_index,
            "status": worker.status,
            "completed_pair_cells": worker.completed_pair_cells,
            "completed_assignments": worker.completed_assignments,
            "fingerprint_sha256": worker.fingerprint_sha256,
            "progress_mtime_ns": worker.progress_mtime_ns,
        }
        for worker in workers
    ]
    commitment = hashlib.sha256(
        json.dumps(
            commitment_rows,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()
    return W52Snapshot(
        workers=tuple(workers),
        terminal=terminal,
        terminal_commitment_sha256=commitment,
        total_pair_cells=config.total_pair_cells,
        completed_pair_cells=sum(worker.completed_pair_cells for worker in workers),
        completed_assignments=sum(worker.completed_assignments for worker in workers),
        active_w52_pids=tuple(
            sorted(
                {
                    *(
                        worker.launcher_pid
                        for worker in workers
                        if worker.launcher_active
                    ),
                    *observed_active,
                    *dynamically_observed,
                }
            )
        ),
        stop_file_present=stop_present,
    )


def memory_free_percent() -> int:
    completed = subprocess.run(
        ("/usr/bin/memory_pressure", "-Q"),
        check=True,
        capture_output=True,
        text=True,
    )
    matched = re.search(
        r"System-wide memory free percentage:\s*([0-9]{1,3})%",
        completed.stdout,
    )
    if matched is None:
        raise W52InterlockError("memory-pressure output differs")
    return _integer(int(matched.group(1)), "memory free percent", 0, 100)


def _git_gate(root: Path, ancestor: str) -> tuple[bool, bool]:
    status = subprocess.run(
        ("git", "status", "--porcelain", "--untracked-files=all"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    ancestry = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, "HEAD"),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestry.returncode not in (0, 1):
        raise W52InterlockError("git ancestry inspection failed")
    return not bool(status.stdout), ancestry.returncode == 0


def inspect_local_gates(config: W52InterlockConfig) -> LocalGateSnapshot:
    memory = memory_free_percent()
    load = float(os.getloadavg()[0])
    cpus = os.cpu_count() or 1
    clean, ancestor = _git_gate(config.lab_root, config.required_ancestor_commit)
    mismatched = tuple(
        str(path.relative_to(config.lab_root))
        for path, expected in config.frozen_sources
        if _file_sha256(path) != expected
    )
    return LocalGateSnapshot(
        memory_free_percent=memory,
        load_one_minute=load,
        logical_cpus=cpus,
        worktree_clean=clean,
        ancestor_present=ancestor,
        run_config_matches=_file_sha256(config.run_config) == config.run_config_sha256,
        mismatched_frozen_sources=mismatched,
    )


def evaluate_interlock(
    config: W52InterlockConfig,
    w52: W52Snapshot,
    local: LocalGateSnapshot,
) -> InterlockSnapshot:
    reasons: list[str] = []
    if not w52.terminal:
        reasons.append("W52_WORKERS_NONTERMINAL")
    if w52.active_w52_pids:
        reasons.append("W52_PROCESSES_ACTIVE")
    if local.memory_free_percent < config.minimum_memory_free_percent:
        reasons.append("INSUFFICIENT_FREE_MEMORY")
    if local.load_per_cpu > config.maximum_load_per_cpu:
        reasons.append("SYSTEM_LOAD_TOO_HIGH")
    if not local.worktree_clean:
        reasons.append("LAB_WORKTREE_DIRTY")
    if not local.ancestor_present:
        reasons.append("O1C0019_FREEZE_ANCESTOR_MISSING")
    if not local.run_config_matches:
        reasons.append("O1C0019_CONFIG_HASH_DIFFERS")
    if local.mismatched_frozen_sources:
        reasons.append("O1C0019_SOURCE_HASH_DIFFERS")
    return InterlockSnapshot(
        w52=w52,
        local=local,
        ready=not reasons,
        reasons=tuple(reasons),
    )


SnapshotProbe = Callable[[], InterlockSnapshot]
Emit = Callable[[Mapping[str, object]], None]


def inspect_interlock(
    config: W52InterlockConfig,
    *,
    process_probe: ProcessProbe = launcher_process_active,
    process_table_probe: ProcessTableProbe = related_process_pids,
    local_probe: Callable[
        [W52InterlockConfig], LocalGateSnapshot
    ] = inspect_local_gates,
) -> InterlockSnapshot:
    return evaluate_interlock(
        config,
        inspect_w52(
            config,
            process_probe=process_probe,
            process_table_probe=process_table_probe,
        ),
        local_probe(config),
    )


def _emit_json(value: Mapping[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, allow_nan=False), flush=True)


@contextmanager
def exclusive_launcher_lock(path: Path) -> Iterator[int]:
    descriptor = _acquire_launcher_lock(path)
    try:
        yield descriptor
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _acquire_launcher_lock(path: Path) -> int:
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise W52InterlockError("another O1C-0019 interlock is active") from exc
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        os.set_inheritable(descriptor, True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def launch_environment(config: W52InterlockConfig) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(config.lab_root / "src"),
            "PYTHONHASHSEED": "0",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
            "PYTORCH_ENABLE_MPS_FALLBACK": "0",
            "CUDA_VISIBLE_DEVICES": "",
        }
    )
    return environment


def start_power_assertion(run_pid: int) -> subprocess.Popen[bytes]:
    """Keep the later CPU gate awake without sharing its exclusive lock FD."""

    _integer(run_pid, "O1C-0019 PID", 1, (1 << 31) - 1)
    process = subprocess.Popen(
        ("/usr/bin/caffeinate", "-dimsu", "-w", str(run_pid)),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    if process.poll() is not None:
        raise W52InterlockError("O1C-0019 power assertion exited before exec")
    return process


def exec_o1c0019(config: W52InterlockConfig) -> NoReturn:
    command = (
        sys.executable,
        "-m",
        "o1_crypto_lab.full256_multiresolution_build_loo_run",
        "--config",
        str(config.run_config),
    )
    power_process = start_power_assertion(os.getpid())
    _emit_json(
        {
            "schema": INTERLOCK_REPORT_SCHEMA,
            "status": "O1C0019_POWER_ASSERTION_STARTED",
            "pid": power_process.pid,
            "watched_pid": os.getpid(),
        }
    )
    os.chdir(config.lab_root)
    os.execvpe(command[0], command, launch_environment(config))


def wait_for_release(
    config: W52InterlockConfig,
    *,
    dry_run: bool = False,
    snapshot_probe: SnapshotProbe | None = None,
    sleep: Callable[[float], None] = time.sleep,
    emit: Emit = _emit_json,
    launch: Callable[[W52InterlockConfig], object] = exec_o1c0019,
    max_polls: int | None = None,
    lock_path: Path | None = None,
    lock_descriptor: int | None = None,
) -> int:
    """Wait for a stable release and exec O1C-0019; dependency hooks aid tests."""

    if max_polls is not None:
        _integer(max_polls, "max_polls", 1, 1 << 31)
    probe = snapshot_probe or (lambda: inspect_interlock(config))
    stable = 0
    commitment: str | None = None
    previous_reasons: tuple[str, ...] | None = None
    polls = 0
    if lock_descriptor is not None:
        try:
            os.fstat(lock_descriptor)
        except OSError as exc:
            raise W52InterlockError("inherited launcher lock is invalid") from exc
        if not os.get_inheritable(lock_descriptor):
            raise W52InterlockError("inherited launcher lock is not exec-safe")
    lock_context = (
        exclusive_launcher_lock(lock_path or config.lock_path)
        if lock_descriptor is None
        else nullcontext(lock_descriptor)
    )
    with lock_context:
        while True:
            polls += 1
            try:
                snapshot = probe()
            except Exception as exc:
                stable = 0
                commitment = None
                emit(
                    {
                        "schema": INTERLOCK_REPORT_SCHEMA,
                        "poll": polls,
                        "ready": False,
                        "inspection_error": f"{type(exc).__name__}: {exc}",
                    }
                )
                snapshot = None

            if snapshot is not None:
                if snapshot.ready:
                    current = snapshot.w52.terminal_commitment_sha256
                    if current == commitment:
                        stable += 1
                    else:
                        commitment = current
                        stable = 1
                else:
                    stable = 0
                    commitment = None
                should_report = (
                    polls == 1
                    or snapshot.reasons != previous_reasons
                    or polls % config.report_every_polls == 0
                    or snapshot.ready
                )
                if should_report:
                    report = snapshot.describe()
                    report.update(
                        {
                            "poll": polls,
                            "stable_terminal_polls": stable,
                            "required_stable_terminal_polls": (
                                config.stable_terminal_polls
                            ),
                        }
                    )
                    emit(report)
                previous_reasons = snapshot.reasons

                if stable >= config.stable_terminal_polls:
                    final = probe()
                    if (
                        final.ready
                        and final.w52.terminal_commitment_sha256 == commitment
                    ):
                        emit(
                            {
                                "schema": INTERLOCK_REPORT_SCHEMA,
                                "status": (
                                    "DRY_RUN_RELEASED"
                                    if dry_run
                                    else "EXECUTING_O1C0019"
                                ),
                                "poll": polls,
                                "terminal_commitment_sha256": commitment,
                                "run_config_sha256": config.run_config_sha256,
                            }
                        )
                        if dry_run:
                            return 0
                        launch(config)
                        raise AssertionError("O1C-0019 exec unexpectedly returned")
                    stable = 0
                    commitment = None

            if max_polls is not None and polls >= max_polls:
                return 2
            sleep(config.poll_seconds)


def _daemon_log_path(config: W52InterlockConfig, value: Path | None) -> Path:
    runs = (config.lab_root / "runs").resolve(strict=True)
    path = (
        runs / ".o1c0019-w52-interlock.log"
        if value is None
        else (config.lab_root / value).resolve()
        if not value.is_absolute()
        else value.resolve()
    )
    if not path.is_relative_to(runs) or path == runs:
        raise W52InterlockError("daemon log must remain below the lab runs directory")
    if path.exists():
        _regular_file(path, "daemon log")
    return path


def _read_daemon_ack(descriptor: int, timeout_seconds: float = 15.0) -> bytes:
    readable, _, _ = select.select((descriptor,), (), (), timeout_seconds)
    if not readable:
        raise W52InterlockError("detached watcher preflight timed out")
    payload = os.read(descriptor, 4096)
    if payload != b"READY\n":
        detail = payload.decode("utf-8", errors="replace").strip()
        raise W52InterlockError(
            f"detached watcher preflight failed: {detail or 'no acknowledgement'}"
        )
    return payload


def _terminate_unacknowledged_child(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def detach_and_watch(
    config: W52InterlockConfig,
    *,
    log_path: Path | None = None,
    emit: Emit = _emit_json,
) -> int:
    """Detach one low-resource watcher; its inherited lock spans O1C-0019."""

    log = _daemon_log_path(config, log_path)
    lock_descriptor = _acquire_launcher_lock(config.lock_path)
    read_descriptor, write_descriptor = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_descriptor)
        os.close(write_descriptor)
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
        raise
    if pid:
        os.close(write_descriptor)
        try:
            _read_daemon_ack(read_descriptor)
        except BaseException:
            _terminate_unacknowledged_child(pid)
            raise
        finally:
            os.close(read_descriptor)
            # Do not LOCK_UN: the forked child shares this locked open-file entry.
            os.close(lock_descriptor)
        emit(
            {
                "schema": INTERLOCK_REPORT_SCHEMA,
                "status": "WATCHER_DETACHED",
                "pid": pid,
                "log": str(log),
                "preflight": "PASSED",
            }
        )
        return 0

    os.close(read_descriptor)
    os.setsid()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.umask(0o077)
    null_descriptor = os.open(os.devnull, os.O_RDONLY)
    log_descriptor = os.open(
        log,
        os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.dup2(null_descriptor, 0)
        os.dup2(log_descriptor, 1)
        os.dup2(log_descriptor, 2)
    finally:
        if null_descriptor > 2:
            os.close(null_descriptor)
        if log_descriptor > 2:
            os.close(log_descriptor)
    acknowledged = False
    try:
        initial = inspect_interlock(config)
        report = initial.describe()
        report["status"] = "WATCHER_PREFLIGHT_PASSED"
        _emit_json(report)
        os.write(write_descriptor, b"READY\n")
        acknowledged = True
        os.close(write_descriptor)
        result = wait_for_release(config, lock_descriptor=lock_descriptor)
    except BaseException as exc:  # The child must leave a durable diagnosis.
        if not acknowledged:
            try:
                os.write(
                    write_descriptor,
                    f"ERROR {type(exc).__name__}: {exc}\n".encode(
                        "utf-8", errors="replace"
                    ),
                )
            except OSError:
                pass
            try:
                os.close(write_descriptor)
            except OSError:
                pass
        traceback.print_exc()
        result = 1
    os._exit(result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--watch", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    if args.dry_run and not args.watch:
        parser.error("--dry-run requires --watch")
    if args.detach and (not args.watch or args.dry_run):
        parser.error("--detach requires non-dry-run --watch")
    if args.log is not None and not args.detach:
        parser.error("--log requires --detach")
    config = load_interlock_config(args.config)
    if args.check:
        try:
            snapshot = inspect_interlock(config)
        except Exception as exc:
            _emit_json(
                {
                    "schema": INTERLOCK_REPORT_SCHEMA,
                    "ready": False,
                    "inspection_error": f"{type(exc).__name__}: {exc}",
                }
            )
            return 2
        _emit_json(snapshot.describe())
        return 0 if snapshot.ready else 2
    if args.detach:
        return detach_and_watch(config, log_path=args.log)
    return wait_for_release(config, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "INTERLOCK_CONFIG_SCHEMA",
    "INTERLOCK_REPORT_SCHEMA",
    "InterlockSnapshot",
    "LocalGateSnapshot",
    "W52InterlockConfig",
    "W52InterlockError",
    "W52Snapshot",
    "W52WorkerSnapshot",
    "evaluate_interlock",
    "detach_and_watch",
    "exclusive_launcher_lock",
    "inspect_interlock",
    "inspect_local_gates",
    "inspect_w52",
    "launcher_process_active",
    "launch_environment",
    "load_interlock_config",
    "main",
    "memory_free_percent",
    "related_process_pids",
    "start_power_assertion",
    "wait_for_release",
]
