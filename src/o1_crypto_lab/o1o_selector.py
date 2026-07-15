"""Target-blind O1-O selector for bounded-memory deployment templates.

The selector accepts calibration fidelity and declared resource costs only.  Its
API intentionally has no deployment field, target address, outcome, progress,
or recovery metric.  Arms must cross every frozen A348 gate; among survivors,
the selector chooses the smallest serialized online state, then the least work.
It records the calibration stream in the existing bounded TargetModel and
freezes one exact future TEST proposal before returning.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .orchestrator import (
    CryptanalyticTargetModel,
    DatasetSplit,
    ExperimentProposal,
)
from .types import InformationLabel, TARGET_BLIND_FORBIDDEN


class O1OSelectionError(ValueError):
    """Raised when calibration evidence or a frozen gate is invalid."""


def _canonical_sha256(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise O1OSelectionError("selection record is not canonical finite JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1OSelectionError(f"{field_name} must be a lowercase SHA-256")
    return value


def _fraction(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1OSelectionError(f"{field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise O1OSelectionError(f"{field_name} must be finite in [0, 1]")
    return result


def _correlation(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1OSelectionError(f"{field_name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not -1.0 <= result <= 1.0:
        raise O1OSelectionError(f"{field_name} must be finite in [-1, 1]")
    return result


@dataclass(frozen=True)
class TopKFidelity:
    k: int
    fraction: float

    def __post_init__(self) -> None:
        if not isinstance(self.k, int) or isinstance(self.k, bool) or self.k < 1:
            raise O1OSelectionError("top-k fidelity k must be positive")
        object.__setattr__(self, "fraction", _fraction(self.fraction, "fraction"))

    def describe(self) -> dict[str, object]:
        return {"k": self.k, "fraction": self.fraction}


@dataclass(frozen=True)
class TopKGate:
    k: int
    minimum_fraction: float

    def __post_init__(self) -> None:
        if not isinstance(self.k, int) or isinstance(self.k, bool) or self.k < 1:
            raise O1OSelectionError("top-k gate k must be positive")
        object.__setattr__(
            self,
            "minimum_fraction",
            _fraction(self.minimum_fraction, "minimum_fraction"),
        )

    def describe(self) -> dict[str, object]:
        return {"k": self.k, "minimum_fraction": self.minimum_fraction}


@dataclass(frozen=True)
class BoundedMemoryArm:
    name: str
    family: str
    memory_plan_sha256: str
    rank_spearman: float
    rank_kendall: float
    top_k_overlap: tuple[TopKFidelity, ...]
    serialized_online_state_bytes: int
    work_units: int
    calibration_clip_count: int = 0
    labels: frozenset[InformationLabel] = field(
        default_factory=lambda: frozenset({InformationLabel.PUBLIC})
    )

    def __post_init__(self) -> None:
        for field_name, value in (("name", self.name), ("family", self.family)):
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 128
            ):
                raise O1OSelectionError(f"{field_name} is required and limited to 128 bytes")
        _sha256(self.memory_plan_sha256, "memory_plan_sha256")
        object.__setattr__(
            self,
            "rank_spearman",
            _correlation(self.rank_spearman, "rank_spearman"),
        )
        object.__setattr__(
            self,
            "rank_kendall",
            _correlation(self.rank_kendall, "rank_kendall"),
        )
        overlaps = tuple(self.top_k_overlap)
        if not overlaps or any(not isinstance(item, TopKFidelity) for item in overlaps):
            raise O1OSelectionError("top_k_overlap must contain TopKFidelity values")
        if len({item.k for item in overlaps}) != len(overlaps):
            raise O1OSelectionError("top_k_overlap contains duplicate k values")
        object.__setattr__(self, "top_k_overlap", tuple(sorted(overlaps, key=lambda x: x.k)))
        for field_name, value, minimum in (
            ("serialized_online_state_bytes", self.serialized_online_state_bytes, 1),
            ("work_units", self.work_units, 1),
            ("calibration_clip_count", self.calibration_clip_count, 0),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < minimum
            ):
                raise O1OSelectionError(f"{field_name} must be an integer >= {minimum}")
        if not isinstance(self.labels, frozenset) or any(
            not isinstance(label, InformationLabel) for label in self.labels
        ):
            raise O1OSelectionError("labels must be a frozenset of InformationLabel")
        if self.labels & TARGET_BLIND_FORBIDDEN:
            raise O1OSelectionError("O1-O calibration arm contains target-forbidden labels")

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "family": self.family,
            "memory_plan_sha256": self.memory_plan_sha256,
            "rank_spearman": self.rank_spearman,
            "rank_kendall": self.rank_kendall,
            "top_k_overlap": [item.describe() for item in self.top_k_overlap],
            "serialized_online_state_bytes": self.serialized_online_state_bytes,
            "work_units": self.work_units,
            "calibration_clip_count": self.calibration_clip_count,
            "labels": sorted(label.value for label in self.labels),
            "split": DatasetSplit.VALIDATION.value,
        }


@dataclass(frozen=True)
class SelectionThresholds:
    min_rank_spearman: float
    min_rank_kendall: float
    top_k_requirements: tuple[TopKGate, ...]
    max_serialized_online_state_bytes: int
    require_zero_calibration_clips: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "min_rank_spearman",
            _correlation(self.min_rank_spearman, "min_rank_spearman"),
        )
        object.__setattr__(
            self,
            "min_rank_kendall",
            _correlation(self.min_rank_kendall, "min_rank_kendall"),
        )
        gates = tuple(self.top_k_requirements)
        if not gates or any(not isinstance(item, TopKGate) for item in gates):
            raise O1OSelectionError("top_k_requirements must contain TopKGate values")
        if len({item.k for item in gates}) != len(gates):
            raise O1OSelectionError("top_k_requirements contains duplicate k values")
        object.__setattr__(self, "top_k_requirements", tuple(sorted(gates, key=lambda x: x.k)))
        if (
            not isinstance(self.max_serialized_online_state_bytes, int)
            or isinstance(self.max_serialized_online_state_bytes, bool)
            or self.max_serialized_online_state_bytes < 1
        ):
            raise O1OSelectionError("maximum online-state bytes must be positive")
        if not isinstance(self.require_zero_calibration_clips, bool):
            raise O1OSelectionError("require_zero_calibration_clips must be boolean")

    def describe(self) -> dict[str, object]:
        return {
            "minimum_rank_spearman": self.min_rank_spearman,
            "minimum_rank_kendall": self.min_rank_kendall,
            "top_k_requirements": [item.describe() for item in self.top_k_requirements],
            "maximum_serialized_online_state_bytes": self.max_serialized_online_state_bytes,
            "require_zero_calibration_clips": self.require_zero_calibration_clips,
        }


@dataclass(frozen=True)
class ArmGateResult:
    arm: BoundedMemoryArm
    passed: bool
    failures: tuple[str, ...]

    def describe(self) -> dict[str, object]:
        return {**self.arm.describe(), "gate_passed": self.passed, "gate_failures": list(self.failures)}


@dataclass(frozen=True)
class O1OSelectionReport:
    source_snapshot_sha256: str
    thresholds: SelectionThresholds
    evaluated: tuple[ArmGateResult, ...]
    selected_arm: BoundedMemoryArm
    frozen_test_proposal: ExperimentProposal
    target_model: Mapping[str, object]
    target_model_sha256: str

    def _payload(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-o1o-bounded-memory-selection-v1",
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "selection_information_boundary": {
                "split": DatasetSplit.VALIDATION.value,
                "accepted_inputs": [
                    "A348 target-blind rank fidelity",
                    "serialized online-state bytes",
                    "declared update work",
                    "calibration clip count",
                ],
                "deployment_field_metrics_accepted": False,
                "target_labels_accepted": False,
                "future_plan_frozen_before_deployment_read": True,
            },
            "thresholds": self.thresholds.describe(),
            "evaluated": [item.describe() for item in self.evaluated],
            "selection_rule": "all gates, then state bytes ascending, work ascending, fidelity descending, arm name ascending",
            "selected_arm": self.selected_arm.describe(),
            "frozen_test_proposal": self.frozen_test_proposal.describe(),
            "target_model": dict(self.target_model),
            "target_model_sha256": self.target_model_sha256,
            "target_labels_used": 0,
        }

    @property
    def selection_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        result = self._payload()
        result["selection_sha256"] = self.selection_sha256
        return result


class O1OSelector:
    """Evaluate A348-only arms and freeze exactly one future plan."""

    def __init__(
        self,
        *,
        source_snapshot_sha256: str,
        thresholds: SelectionThresholds,
    ) -> None:
        self.source_snapshot_sha256 = _sha256(
            source_snapshot_sha256, "source_snapshot_sha256"
        )
        if not isinstance(thresholds, SelectionThresholds):
            raise TypeError("thresholds must be SelectionThresholds")
        self.thresholds = thresholds
        self._frozen = False

    def _gate(self, arm: BoundedMemoryArm) -> ArmGateResult:
        failures: list[str] = []
        if arm.rank_spearman < self.thresholds.min_rank_spearman:
            failures.append("RANK_SPEARMAN")
        if arm.rank_kendall < self.thresholds.min_rank_kendall:
            failures.append("RANK_KENDALL")
        overlaps = {item.k: item.fraction for item in arm.top_k_overlap}
        for gate in self.thresholds.top_k_requirements:
            if overlaps.get(gate.k, -1.0) < gate.minimum_fraction:
                failures.append(f"TOP_{gate.k}_OVERLAP")
        if (
            arm.serialized_online_state_bytes
            > self.thresholds.max_serialized_online_state_bytes
        ):
            failures.append("ONLINE_STATE_BYTES")
        if self.thresholds.require_zero_calibration_clips and arm.calibration_clip_count:
            failures.append("CALIBRATION_CLIPS")
        return ArmGateResult(arm=arm, passed=not failures, failures=tuple(failures))

    def select_and_freeze(
        self, arms: Iterable[BoundedMemoryArm]
    ) -> O1OSelectionReport:
        if self._frozen:
            raise RuntimeError("O1-O selector can freeze exactly once")
        materialized = tuple(arms)
        if not materialized or any(not isinstance(arm, BoundedMemoryArm) for arm in materialized):
            raise O1OSelectionError("at least one BoundedMemoryArm is required")
        if len({arm.name for arm in materialized}) != len(materialized):
            raise O1OSelectionError("O1-O arm names must be unique")

        evaluated = tuple(self._gate(arm) for arm in materialized)
        survivors = [item.arm for item in evaluated if item.passed]
        if not survivors:
            raise O1OSelectionError("no bounded-memory arm crossed every frozen gate")
        selected = min(
            survivors,
            key=lambda arm: (
                arm.serialized_online_state_bytes,
                arm.work_units,
                -arm.rank_spearman,
                -arm.rank_kendall,
                arm.name,
            ),
        )

        model = CryptanalyticTargetModel(self.source_snapshot_sha256)
        for result in evaluated:
            arm = result.arm
            normalized_gain = (arm.rank_spearman + 1.0) / 2.0
            proposal = ExperimentProposal(
                name=arm.name,
                family=arm.family,
                expected_information_gain=normalized_gain,
                work_units=arm.work_units,
                labels=arm.labels,
                split=DatasetSplit.VALIDATION,
            )
            if result.passed:
                model.record_success(
                    proposal,
                    gain=normalized_gain,
                    surprise=max(0.0, 1.0 - arm.rank_spearman),
                )
            else:
                model.record_failure(proposal, reason_code="FROZEN_GATE_MISS")

        future = ExperimentProposal(
            name=f"future::{selected.name}",
            family=selected.family,
            expected_information_gain=(selected.rank_spearman + 1.0) / 2.0,
            work_units=selected.work_units,
            labels=selected.labels,
            split=DatasetSplit.TEST,
        )
        model.freeze_for_test(future, plan_sha256=selected.memory_plan_sha256)
        self._frozen = True
        return O1OSelectionReport(
            source_snapshot_sha256=self.source_snapshot_sha256,
            thresholds=self.thresholds,
            evaluated=evaluated,
            selected_arm=selected,
            frozen_test_proposal=future,
            target_model=model.describe(),
            target_model_sha256=model.state_sha256(),
        )


__all__ = [
    "ArmGateResult",
    "BoundedMemoryArm",
    "O1OSelectionError",
    "O1OSelectionReport",
    "O1OSelector",
    "SelectionThresholds",
    "TopKFidelity",
    "TopKGate",
]
