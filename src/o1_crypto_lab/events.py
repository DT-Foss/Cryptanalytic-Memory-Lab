"""Normalized evidence events shared by O1, O1-O and cryptanalytic backends."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum

from .types import InformationLabel


class EventKind(str, Enum):
    OBSERVATION = "OBSERVATION"
    HYPOTHESIS = "HYPOTHESIS"
    SUPPORT = "SUPPORT"
    CONTRADICTION = "CONTRADICTION"
    ACTION = "ACTION"
    RESULT = "RESULT"


class OutcomeDimension(str, Enum):
    GENERATION = "GENERATION"
    PROCESS = "PROCESS"
    CAPABILITY = "CAPABILITY"
    MISSION = "MISSION"


class OutcomeStatus(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EvidenceEvent:
    """One immutable, addressable observation in the combined stream."""

    session_id: str
    source_task: str
    kind: EventKind
    address: str
    dimension: OutcomeDimension
    status: OutcomeStatus
    confidence: float
    value: float
    source_artifact: str
    source_sha256: str
    labels: tuple[InformationLabel, ...] = ()

    def validate(self) -> None:
        for name, value in (
            ("session_id", self.session_id),
            ("source_task", self.source_task),
            ("address", self.address),
            ("source_artifact", self.source_artifact),
        ):
            if not value or "\x00" in value:
                raise ValueError(f"{name} is required and cannot contain NUL")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        if not math.isfinite(self.value):
            raise ValueError("value must be finite")
        if len(self.source_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in self.source_sha256
        ):
            raise ValueError("source_sha256 must be a lowercase SHA-256")

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "session_id": self.session_id,
            "source_task": self.source_task,
            "kind": self.kind.value,
            "address": self.address,
            "dimension": self.dimension.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "value": self.value,
            "source_artifact": self.source_artifact,
            "source_sha256": self.source_sha256,
            "labels": sorted(label.value for label in self.labels),
            "event_id": self.event_id,
        }

    @property
    def event_id(self) -> str:
        value = {
            "session_id": self.session_id,
            "source_task": self.source_task,
            "kind": self.kind.value,
            "address": self.address,
            "dimension": self.dimension.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "value": self.value,
            "source_artifact": self.source_artifact,
            "source_sha256": self.source_sha256,
            "labels": sorted(label.value for label in self.labels),
        }
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(canonical).hexdigest()
