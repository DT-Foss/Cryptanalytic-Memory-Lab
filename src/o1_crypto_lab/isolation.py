"""Output-path confinement for the sibling research lab."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class IsolationViolation(PermissionError):
    pass


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class IsolationPolicy:
    lab_root: Path

    @classmethod
    def package_default(cls) -> "IsolationPolicy":
        return cls(Path(__file__).resolve().parents[2])

    @property
    def output_root(self) -> Path:
        lab_root = self.lab_root.resolve()
        lexical = lab_root / "runs"
        if lexical.is_symlink():
            raise IsolationViolation("runs directory cannot be a symbolic link")
        resolved = lexical.resolve()
        if not _inside(resolved, lab_root):
            raise IsolationViolation("runs directory escapes the lab root")
        return resolved

    def require_output_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.lab_root / candidate
        resolved = candidate.resolve()
        output_root = self.output_root
        if resolved == output_root or not _inside(resolved, output_root):
            raise IsolationViolation(
                f"writes are confined to files below {output_root}; rejected {resolved}"
            )
        return resolved

    @staticmethod
    def _directory_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

    def _open_output_parent(
        self, path: str | Path, *, create_parents: bool
    ) -> tuple[Path, int, str]:
        """Open and bind the destination parent without following symlinks."""

        destination = self.require_output_path(path)
        output_root = self.output_root
        parts = destination.relative_to(output_root).parts
        if not parts:
            raise IsolationViolation("the runs directory cannot be used as a file")

        descriptor = os.open(output_root, self._directory_flags())
        try:
            for part in parts[:-1]:
                if create_parents:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                next_descriptor = os.open(
                    part, self._directory_flags(), dir_fd=descriptor
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return destination, descriptor, parts[-1]
        except Exception:
            os.close(descriptor)
            raise

    def open_output_append(self, path: str | Path) -> tuple[int, Path]:
        """Open an append-only output fd with every path component bound safely."""

        destination, parent_fd, name = self._open_output_parent(
            path, create_parents=True
        )
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
        return descriptor, destination

    def read_output_text(self, path: str | Path) -> str:
        """Read a confined output without following a swapped final symlink."""

        _, parent_fd, name = self._open_output_parent(path, create_parents=False)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            return handle.read()

    def atomic_write_json(self, path: str | Path, value: Any) -> Path:
        destination, parent_fd, name = self._open_output_parent(
            path, create_parents=True
        )
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
                    descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
                    break
                except FileExistsError:
                    continue
            else:
                raise FileExistsError("could not allocate a unique temporary output")
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
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
