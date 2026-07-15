"""Data-shape and information-flow types for cryptanalytic operator chains."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Tuple


class DataKind(str, Enum):
    """Semantic data kinds; unlike O1-O colors, these encode research meaning."""

    PUBLIC_RELATIONS = "PUBLIC_RELATIONS"
    ALIGNED_PUBLIC = "ALIGNED_PUBLIC"
    PUBLIC_FIELD = "PUBLIC_FIELD"
    CANDIDATE_TRACE = "CANDIDATE_TRACE"
    EVIDENCE_STATE = "EVIDENCE_STATE"
    SCORE = "SCORE"
    TARGET_BLIND_ORDER = "TARGET_BLIND_ORDER"
    MODEL = "MODEL"
    CONFIRMED = "CONFIRMED"


class InformationLabel(str, Enum):
    """Monotone provenance labels carried through every operator."""

    PUBLIC = "PUBLIC"
    TRAIN_LABEL = "TRAIN_LABEL"
    INTERNAL_TRAIN = "INTERNAL_TRAIN"
    CANDIDATE_ASSUMPTION = "CANDIDATE_ASSUMPTION"
    CONTROL = "CONTROL"
    TARGET_SECRET = "TARGET_SECRET"
    INTERNAL_TARGET = "INTERNAL_TARGET"
    POST_REVEAL = "POST_REVEAL"


TARGET_BLIND_FORBIDDEN: FrozenSet[InformationLabel] = frozenset(
    {
        InformationLabel.TARGET_SECRET,
        InformationLabel.INTERNAL_TARGET,
        InformationLabel.POST_REVEAL,
    }
)


@dataclass(frozen=True)
class FlowState:
    """The type and monotone information provenance at one point in a chain."""

    kind: DataKind
    labels: FrozenSet[InformationLabel] = field(default_factory=frozenset)
    history: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind is DataKind.TARGET_BLIND_ORDER and not self.target_blind:
            names = ", ".join(
                sorted(label.value for label in self.labels & TARGET_BLIND_FORBIDDEN)
            )
            raise ValueError(
                f"TARGET_BLIND_ORDER cannot contain forbidden labels: {names}"
            )

    @property
    def target_blind(self) -> bool:
        return not bool(self.labels & TARGET_BLIND_FORBIDDEN)

    def describe(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "labels": sorted(label.value for label in self.labels),
            "history": list(self.history),
            "target_blind": self.target_blind,
        }
