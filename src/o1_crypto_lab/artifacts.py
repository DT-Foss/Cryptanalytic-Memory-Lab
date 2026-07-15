"""Read-only, SHA-256-gated access to published recovery artifacts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class ManifestError(ValueError):
    pass


def sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"manifest path escapes source root: {relative}") from exc
    return candidate


def _parse_manifest(value: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(value.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ManifestError(f"invalid manifest line {line_number}: {raw!r}")
        expected, relative = parts
        relative = relative.lstrip("*")
        if len(expected) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in expected
        ):
            raise ManifestError(f"invalid SHA-256 on line {line_number}")
        if relative in entries:
            raise ManifestError(f"duplicate manifest path: {relative}")
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ManifestError(f"unsafe manifest path: {relative}")
        entries[relative] = expected.lower()
    if not entries:
        raise ManifestError("manifest is empty")
    return entries


def load_manifest(path: str | Path) -> dict[str, str]:
    manifest_path = Path(path).resolve()
    return _parse_manifest(manifest_path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class VerificationReport:
    schema: str
    root: str
    manifest: str
    manifest_sha256: str
    checked: int
    missing: tuple[str, ...]
    mismatched: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.mismatched

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "root": self.root,
            "manifest": self.manifest,
            "manifest_sha256": self.manifest_sha256,
            "checked": self.checked,
            "missing": list(self.missing),
            "mismatched": list(self.mismatched),
            "ok": self.ok,
        }


class ReadOnlyArtifactSource:
    """A source snapshot that refuses reads until the requested byte is verified."""

    def __init__(self, root: str | Path, manifest: str | Path) -> None:
        self.root = Path(root).resolve()
        self.manifest_path = Path(manifest).resolve()
        if not self.root.is_dir():
            raise FileNotFoundError(self.root)
        manifest_bytes = self.manifest_path.read_bytes()
        self.manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        self.entries = _parse_manifest(manifest_bytes.decode("utf-8"))
        self._verified: set[str] = set()

    def _assert_manifest_unchanged(self) -> None:
        try:
            current = hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()
        except FileNotFoundError as exc:
            raise ManifestError("source manifest disappeared after pinning") from exc
        if current != self.manifest_sha256:
            raise ManifestError("source manifest changed after it was pinned")

    def verify(self, members: Iterable[str] | None = None) -> VerificationReport:
        self._assert_manifest_unchanged()
        selected = sorted(self.entries if members is None else set(members))
        unknown = [member for member in selected if member not in self.entries]
        if unknown:
            raise ManifestError(f"members absent from manifest: {', '.join(unknown)}")
        missing: list[str] = []
        mismatched: list[str] = []
        checked = 0
        for relative in selected:
            path = _safe_member(self.root, relative)
            if not path.is_file():
                missing.append(relative)
                continue
            checked += 1
            if sha256_file(path) != self.entries[relative]:
                mismatched.append(relative)
                continue
            self._verified.add(relative)
        return VerificationReport(
            schema="o1-crypto-source-verification-v1",
            root=str(self.root),
            manifest=str(self.manifest_path),
            manifest_sha256=self.manifest_sha256,
            checked=checked,
            missing=tuple(missing),
            mismatched=tuple(mismatched),
        )

    def read_bytes(self, relative: str) -> bytes:
        self._assert_manifest_unchanged()
        if relative not in self.entries:
            raise ManifestError(f"member absent from manifest: {relative}")
        path = _safe_member(self.root, relative)
        try:
            value = path.read_bytes()
        except FileNotFoundError as exc:
            raise ManifestError(f"artifact is missing: {relative}") from exc
        # Hash the exact bytes being returned. A prior bulk verification alone would
        # leave a time-of-check/time-of-use window if the source changed afterwards.
        actual = hashlib.sha256(value).hexdigest()
        if actual != self.entries[relative]:
            self._verified.discard(relative)
            raise ManifestError(f"artifact failed verification: {relative}")
        self._verified.add(relative)
        return value

    def read_json(self, relative: str):
        return json.loads(self.read_bytes(relative).decode("utf-8"))
