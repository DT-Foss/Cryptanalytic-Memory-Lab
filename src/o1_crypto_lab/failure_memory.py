"""Append-only experiment failure memory with discovery/post-test separation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from .isolation import IsolationPolicy
from .types import InformationLabel, TARGET_BLIND_FORBIDDEN


class LedgerScope(str, Enum):
    DISCOVERY = "DISCOVERY"
    POST_TEST_AUDIT = "POST_TEST_AUDIT"


@dataclass(frozen=True)
class FailureRecord:
    chain_sha256: str
    scope: LedgerScope
    reason_code: str
    detail: str
    source_snapshot_sha256: str
    labels: tuple[InformationLabel, ...] = ()
    metrics: tuple[tuple[str, float], ...] = ()

    @classmethod
    def build(
        cls,
        chain_names: Iterable[str],
        *,
        scope: LedgerScope,
        reason_code: str,
        detail: str,
        source_snapshot_sha256: str,
        labels: Iterable[InformationLabel] = (),
        metrics: dict[str, float] | None = None,
    ) -> "FailureRecord":
        names = tuple(chain_names)
        if not names or any(
            not isinstance(name, str) or not name or len(name.encode("utf-8")) > 128
            for name in names
        ):
            raise ValueError(
                "chain_names must contain non-empty strings of at most 128 bytes"
            )
        canonical = json.dumps(names, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        return cls(
            chain_sha256=hashlib.sha256(canonical).hexdigest(),
            scope=scope,
            reason_code=reason_code,
            detail=detail,
            source_snapshot_sha256=source_snapshot_sha256,
            labels=tuple(sorted(set(labels), key=lambda item: item.value)),
            metrics=tuple(sorted((metrics or {}).items())),
        )

    def validate(self) -> None:
        for name, value in (
            ("chain_sha256", self.chain_sha256),
            ("source_snapshot_sha256", self.source_snapshot_sha256),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256")
        if not isinstance(self.scope, LedgerScope):
            raise TypeError("scope must be a LedgerScope")
        if (
            not isinstance(self.reason_code, str)
            or not isinstance(self.detail, str)
            or not self.reason_code
            or not self.detail
        ):
            raise ValueError("reason_code and detail are required")
        if any(not isinstance(label, InformationLabel) for label in self.labels):
            raise TypeError("labels must contain InformationLabel values")
        if any(
            not isinstance(name, str)
            or not name
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            for name, value in self.metrics
        ):
            raise ValueError(
                "metric names are required and metric values must be finite"
            )
        if (
            self.scope is LedgerScope.DISCOVERY
            and set(self.labels) & TARGET_BLIND_FORBIDDEN
        ):
            raise ValueError(
                "post-reveal or target-secret evidence cannot enter discovery memory"
            )

    def describe(self) -> dict[str, object]:
        value = asdict(self)
        value["scope"] = self.scope.value
        value["labels"] = [label.value for label in self.labels]
        value["metrics"] = dict(self.metrics)
        return value


class FailureLedger:
    def __init__(
        self, path: str | Path, *, policy: IsolationPolicy | None = None
    ) -> None:
        self.policy = policy or IsolationPolicy.package_default()
        base = self.policy.require_output_path(path)
        suffix = base.suffix or ".jsonl"
        stem = base.name[: -len(base.suffix)] if base.suffix else base.name
        self.discovery_path = self.policy.require_output_path(
            base.with_name(f"{stem}.discovery{suffix}")
        )
        self.post_test_path = self.policy.require_output_path(
            base.with_name(f"{stem}.post-test-audit{suffix}")
        )

    def _path_for_scope(self, scope: LedgerScope) -> Path:
        configured = (
            self.discovery_path
            if scope is LedgerScope.DISCOVERY
            else self.post_test_path
        )
        return self.policy.require_output_path(configured)

    def append(self, record: FailureRecord) -> None:
        record.validate()
        destination = self._path_for_scope(record.scope)
        line = (
            json.dumps(
                record.describe(),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
        descriptor, opened_destination = self.policy.open_output_append(destination)
        if opened_destination != destination:
            os.close(descriptor)
            raise RuntimeError("failure-ledger destination changed during open")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            payload = line.encode("utf-8")
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise OSError("short write while appending failure ledger")
                written += count
            os.fsync(descriptor)
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)

    def discovery_records(self) -> list[dict[str, object]]:
        return self._records(LedgerScope.DISCOVERY)

    def post_test_records(self) -> list[dict[str, object]]:
        return self._records(LedgerScope.POST_TEST_AUDIT)

    def _records(self, expected_scope: LedgerScope) -> list[dict[str, object]]:
        path = self._path_for_scope(expected_scope)
        try:
            content = self.policy.read_output_text(path)
        except FileNotFoundError:
            return []
        records = []
        for raw in content.splitlines():
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("ledger record must be a JSON object")
            expected_fields = {
                "chain_sha256",
                "scope",
                "reason_code",
                "detail",
                "source_snapshot_sha256",
                "labels",
                "metrics",
            }
            if set(value) != expected_fields:
                raise ValueError("ledger record has an invalid field set")
            try:
                labels = tuple(InformationLabel(label) for label in value["labels"])
                metrics = tuple(dict(value["metrics"]).items())
                record = FailureRecord(
                    chain_sha256=value["chain_sha256"],
                    scope=LedgerScope(value["scope"]),
                    reason_code=value["reason_code"],
                    detail=value["detail"],
                    source_snapshot_sha256=value["source_snapshot_sha256"],
                    labels=labels,
                    metrics=metrics,
                )
                record.validate()
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("ledger contains an invalid record") from exc
            if record.scope is not expected_scope:
                raise ValueError("ledger record is stored in the wrong physical scope")
            records.append(record.describe())
        return records
