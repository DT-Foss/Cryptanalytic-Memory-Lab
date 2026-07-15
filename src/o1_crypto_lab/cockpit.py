"""Narrow, symlink-safe write access for the human research cockpit.

Runtime artifacts remain confined to ``runs/`` by :mod:`isolation`.  This module
is intentionally separate and can write only the explicitly enumerated Markdown
ledgers required by the research protocol.
"""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .isolation import IsolationViolation


class CockpitFile(str, Enum):
    STATUS = "STATUS.md"
    RESULTS_INDEX = "RESULTS_INDEX.md"
    RESEARCH_PROGRAM = "research/RESEARCH_PROGRAM.md"
    HYPOTHESES = "research/HYPOTHESES.md"
    ATTEMPT_LOG = "research/ATTEMPT_LOG.md"
    NEXT_ACTIONS = "research/NEXT_ACTIONS.md"
    DEAD_ENDS = "research/DEAD_ENDS_AND_BREADCRUMBS.md"


@dataclass(frozen=True)
class CockpitWriter:
    lab_root: Path

    @classmethod
    def package_default(cls) -> "CockpitWriter":
        return cls(Path(__file__).resolve().parents[2])

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

    def _open_parent(self, selected: CockpitFile) -> tuple[Path, int, str]:
        if not isinstance(selected, CockpitFile):
            raise IsolationViolation("cockpit writes require a CockpitFile allowlist member")
        root = self.lab_root.resolve()
        parts = Path(selected.value).parts
        descriptor = os.open(root, self._directory_flags())
        try:
            for part in parts[:-1]:
                next_descriptor = os.open(
                    part, self._directory_flags(), dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return root / selected.value, descriptor, parts[-1]
        except Exception:
            os.close(descriptor)
            raise

    def append(self, selected: CockpitFile, text: str) -> Path:
        if "\x00" in text:
            raise ValueError("cockpit text cannot contain NUL")
        destination, parent_fd, name = self._open_parent(selected)
        flags = (
            os.O_APPEND
            | os.O_CREAT
            | os.O_WRONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        return destination

    def replace(self, selected: CockpitFile, text: str) -> Path:
        if "\x00" in text:
            raise ValueError("cockpit text cannot contain NUL")
        destination, parent_fd, name = self._open_parent(selected)
        temporary_name = ""
        try:
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            for _ in range(128):
                temporary_name = f".{name}.{secrets.token_hex(12)}.tmp"
                try:
                    descriptor = os.open(
                        temporary_name, flags, 0o600, dir_fd=parent_fd
                    )
                    break
                except FileExistsError:
                    continue
            else:
                raise FileExistsError("could not allocate a cockpit temporary file")
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            # Refuse to replace a symlink even though os.replace itself would replace
            # the link rather than follow it. This makes policy failures explicit.
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and stat.S_ISLNK(existing.st_mode):
                raise IsolationViolation("cockpit destination cannot be a symbolic link")
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
            temporary_name = ""
        except Exception:
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(parent_fd)
        return destination
