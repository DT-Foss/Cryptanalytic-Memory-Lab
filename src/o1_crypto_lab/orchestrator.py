"""O1-O-style target state and adaptive planning for scientific experiments."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Iterable, Mapping

from .types import InformationLabel, TARGET_BLIND_FORBIDDEN

_MAX_COUNTER = (1 << 64) - 1


class DatasetSplit(str, Enum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    POST_TEST = "POST_TEST"


class ModelLifecycle(str, Enum):
    DISCOVERY = "DISCOVERY"
    FROZEN = "FROZEN"
    TEST_CONSUMED = "TEST_CONSUMED"
    AUDIT = "AUDIT"


@dataclass(frozen=True)
class ExperimentProposal:
    name: str
    family: str
    expected_information_gain: float
    work_units: int
    labels: FrozenSet[InformationLabel] = field(default_factory=frozenset)
    split: DatasetSplit = DatasetSplit.TRAIN

    def validate(self) -> None:
        if not isinstance(self.name, str) or not isinstance(self.family, str):
            raise TypeError("proposal name and family must be strings")
        if not self.name or not self.family:
            raise ValueError("proposal name and family are required")
        if max(len(self.name.encode("utf-8")), len(self.family.encode("utf-8"))) > 128:
            raise ValueError("proposal name and family are limited to 128 UTF-8 bytes")
        if (
            isinstance(self.expected_information_gain, bool)
            or not isinstance(self.expected_information_gain, (int, float))
            or not math.isfinite(self.expected_information_gain)
            or self.expected_information_gain < 0.0
        ):
            raise ValueError("expected information gain must be non-negative")
        if not isinstance(self.work_units, int) or isinstance(self.work_units, bool):
            raise TypeError("work_units must be an integer")
        if self.work_units < 1:
            raise ValueError("work_units must be positive")
        if not isinstance(self.split, DatasetSplit):
            raise TypeError("split must be a DatasetSplit")
        if not isinstance(self.labels, frozenset) or any(
            not isinstance(label, InformationLabel) for label in self.labels
        ):
            raise TypeError("labels must be a frozenset of InformationLabel values")

    def describe(self) -> dict[str, object]:
        self.validate()
        return {
            "name": self.name,
            "family": self.family,
            "expected_information_gain": self.expected_information_gain,
            "work_units": self.work_units,
            "labels": sorted(label.value for label in self.labels),
            "split": self.split.value,
        }

    def proposal_sha256(self) -> str:
        canonical = json.dumps(
            self.describe(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass
class CryptanalyticTargetModel:
    """Cumulative target-blind state, analogous to O1-O's live TargetModel."""

    source_snapshot_sha256: str
    observations: int = 0
    best_validation_gain: float = 0.0
    stale_steps: int = 0
    family_attempts: dict[str, int] = field(default_factory=dict)
    failure_counts: dict[str, int] = field(default_factory=dict)
    blacklisted_families: set[str] = field(default_factory=set)
    last_surprise: float = 0.0
    lifecycle: ModelLifecycle = ModelLifecycle.DISCOVERY
    frozen_proposal_sha256: str | None = None
    frozen_plan_sha256: str | None = None
    test_result_sha256: str | None = None
    max_family_slots: int = 64
    max_failure_codes: int = 64
    max_identifier_bytes: int = 128

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_snapshot_sha256, str)
            or len(self.source_snapshot_sha256) != 64
            or any(
                char not in "0123456789abcdef" for char in self.source_snapshot_sha256
            )
        ):
            raise ValueError("source_snapshot_sha256 must be a lowercase SHA-256")
        for name, value in (
            ("max_family_slots", self.max_family_slots),
            ("max_failure_codes", self.max_failure_codes),
            ("max_identifier_bytes", self.max_identifier_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if len(self.family_attempts) > self.max_family_slots:
            raise ValueError("family_attempts exceeds fixed TargetModel capacity")
        if len(self.failure_counts) > self.max_failure_codes:
            raise ValueError("failure_counts exceeds fixed TargetModel capacity")
        for identifier in (
            *self.family_attempts,
            *self.failure_counts,
            *self.blacklisted_families,
        ):
            self._validate_identifier(identifier)
        if not self.blacklisted_families <= set(self.family_attempts):
            raise ValueError("blacklisted families must have an attempt counter")
        if not isinstance(self.lifecycle, ModelLifecycle):
            raise TypeError("lifecycle must be a ModelLifecycle")
        for name, value in (
            ("frozen_proposal_sha256", self.frozen_proposal_sha256),
            ("frozen_plan_sha256", self.frozen_plan_sha256),
            ("test_result_sha256", self.test_result_sha256),
        ):
            if value is not None:
                self._validate_sha256(value, name)
        frozen_values = self.frozen_proposal_sha256, self.frozen_plan_sha256
        if self.lifecycle is ModelLifecycle.DISCOVERY:
            if any(
                value is not None for value in (*frozen_values, self.test_result_sha256)
            ):
                raise ValueError(
                    "discovery lifecycle cannot contain frozen/test hashes"
                )
        elif self.lifecycle is ModelLifecycle.FROZEN:
            if (
                any(value is None for value in frozen_values)
                or self.test_result_sha256 is not None
            ):
                raise ValueError(
                    "frozen lifecycle requires proposal and plan hashes only"
                )
        elif self.lifecycle in {ModelLifecycle.TEST_CONSUMED, ModelLifecycle.AUDIT}:
            if any(
                value is None for value in (*frozen_values, self.test_result_sha256)
            ):
                raise ValueError(
                    "consumed/audit lifecycle requires all frozen/test hashes"
                )
        counts = (
            self.observations,
            self.stale_steps,
            *self.family_attempts.values(),
            *self.failure_counts.values(),
        )
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= _MAX_COUNTER
            for value in counts
        ):
            raise ValueError("TargetModel counts must be non-negative integers")
        if self.observations != sum(self.family_attempts.values()):
            raise ValueError("observations must equal the sum of family attempts")
        if self.stale_steps > self.observations:
            raise ValueError("stale_steps cannot exceed observations")
        if (
            not math.isfinite(self.best_validation_gain)
            or not math.isfinite(self.last_surprise)
            or self.best_validation_gain < 0.0
            or self.last_surprise < 0.0
        ):
            raise ValueError("TargetModel gains must be finite and non-negative")

    @staticmethod
    def _validate_sha256(value: str, name: str) -> None:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError(f"{name} must be a lowercase SHA-256")

    def _validate_identifier(self, value: str) -> None:
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > self.max_identifier_bytes
        ):
            raise ValueError(
                f"TargetModel identifiers are limited to {self.max_identifier_bytes} bytes"
            )

    def accepts_family(self, family: str) -> bool:
        self._validate_identifier(family)
        return (
            family in self.family_attempts
            or len(self.family_attempts) < self.max_family_slots
        )

    def _record_family_attempt(self, family: str) -> None:
        if not self.accepts_family(family):
            raise OverflowError("TargetModel family capacity exhausted")
        self.family_attempts[family] = self.family_attempts.get(family, 0) + 1

    def _record_failure_code(self, reason_code: str) -> None:
        self._validate_identifier(reason_code)
        if (
            reason_code not in self.failure_counts
            and len(self.failure_counts) >= self.max_failure_codes
        ):
            raise OverflowError("TargetModel failure-code capacity exhausted")
        self.failure_counts[reason_code] = self.failure_counts.get(reason_code, 0) + 1

    @staticmethod
    def _require_increment_capacity(*values: int) -> None:
        if any(value >= _MAX_COUNTER for value in values):
            raise OverflowError("TargetModel uint64 counter capacity exhausted")

    @staticmethod
    def _require_target_blind(proposal: ExperimentProposal) -> None:
        contaminated = proposal.labels & TARGET_BLIND_FORBIDDEN
        if contaminated:
            names = ", ".join(sorted(label.value for label in contaminated))
            raise ValueError(f"target-blind TargetModel rejects labels: {names}")

    def _require_discovery(self, proposal: ExperimentProposal) -> None:
        if self.lifecycle is not ModelLifecycle.DISCOVERY:
            raise RuntimeError("adaptive feedback is closed after the model is frozen")
        if proposal.split not in {DatasetSplit.TRAIN, DatasetSplit.VALIDATION}:
            raise ValueError(
                "discovery feedback accepts only TRAIN or VALIDATION splits"
            )

    def record_success(
        self, proposal: ExperimentProposal, *, gain: float, surprise: float
    ) -> None:
        proposal.validate()
        self._require_target_blind(proposal)
        self._require_discovery(proposal)
        if (
            not math.isfinite(gain)
            or not math.isfinite(surprise)
            or gain < 0.0
            or surprise < 0.0
        ):
            raise ValueError("gain and surprise must be non-negative")
        if not self.accepts_family(proposal.family):
            raise OverflowError("TargetModel family capacity exhausted")
        counters = [self.observations, self.family_attempts.get(proposal.family, 0)]
        validation_feedback = proposal.split is DatasetSplit.VALIDATION
        if validation_feedback and gain <= self.best_validation_gain:
            counters.append(self.stale_steps)
        self._require_increment_capacity(*counters)
        self.observations += 1
        self._record_family_attempt(proposal.family)
        self.last_surprise = surprise
        if validation_feedback:
            if gain > self.best_validation_gain:
                self.best_validation_gain = gain
                self.stale_steps = 0
            else:
                self.stale_steps += 1

    def record_observation(self, proposal: ExperimentProposal) -> None:
        """Ingest a typed event without treating it as success, failure or staleness."""

        proposal.validate()
        self._require_target_blind(proposal)
        self._require_discovery(proposal)
        if not self.accepts_family(proposal.family):
            raise OverflowError("TargetModel family capacity exhausted")
        self._require_increment_capacity(
            self.observations,
            self.family_attempts.get(proposal.family, 0),
        )
        self.observations += 1
        self._record_family_attempt(proposal.family)

    def record_failure(
        self,
        proposal: ExperimentProposal,
        *,
        reason_code: str,
        structural: bool = False,
    ) -> None:
        proposal.validate()
        self._require_target_blind(proposal)
        self._require_discovery(proposal)
        if not reason_code:
            raise ValueError("reason_code is required")
        self._validate_identifier(reason_code)
        if not self.accepts_family(proposal.family):
            raise OverflowError("TargetModel family capacity exhausted")
        if (
            reason_code not in self.failure_counts
            and len(self.failure_counts) >= self.max_failure_codes
        ):
            raise OverflowError("TargetModel failure-code capacity exhausted")
        counters = [
            self.observations,
            self.family_attempts.get(proposal.family, 0),
            self.failure_counts.get(reason_code, 0),
        ]
        if proposal.split is DatasetSplit.VALIDATION:
            counters.append(self.stale_steps)
        self._require_increment_capacity(*counters)
        self.observations += 1
        self._record_family_attempt(proposal.family)
        self._record_failure_code(reason_code)
        if proposal.split is DatasetSplit.VALIDATION:
            self.stale_steps += 1
        if structural:
            self.blacklisted_families.add(proposal.family)

    def freeze_for_test(self, proposal: ExperimentProposal, *, plan_sha256: str) -> str:
        if self.lifecycle is not ModelLifecycle.DISCOVERY:
            raise RuntimeError("TargetModel can be frozen exactly once")
        proposal.validate()
        self._require_target_blind(proposal)
        if proposal.split is not DatasetSplit.TEST:
            raise ValueError("frozen proposal must belong to TEST")
        self._validate_sha256(plan_sha256, "plan_sha256")
        self.frozen_proposal_sha256 = proposal.proposal_sha256()
        self.frozen_plan_sha256 = plan_sha256
        self.lifecycle = ModelLifecycle.FROZEN
        return self.state_sha256()

    def consume_test(
        self,
        proposal: ExperimentProposal,
        *,
        plan_sha256: str,
        result_sha256: str,
    ) -> None:
        proposal.validate()
        self._require_target_blind(proposal)
        if self.lifecycle is not ModelLifecycle.FROZEN:
            raise RuntimeError("test can be consumed only by a frozen TargetModel")
        if proposal.split is not DatasetSplit.TEST:
            raise ValueError("frozen TargetModel accepts exactly one TEST proposal")
        self._validate_sha256(plan_sha256, "plan_sha256")
        self._validate_sha256(result_sha256, "result_sha256")
        if proposal.proposal_sha256() != self.frozen_proposal_sha256:
            raise ValueError("test proposal differs from the frozen proposal")
        if plan_sha256 != self.frozen_plan_sha256:
            raise ValueError("test plan differs from the frozen plan")
        self.test_result_sha256 = result_sha256
        self.lifecycle = ModelLifecycle.TEST_CONSUMED

    def open_post_test_audit(self) -> None:
        if self.lifecycle is not ModelLifecycle.TEST_CONSUMED:
            raise RuntimeError("post-test audit requires a consumed test")
        self.lifecycle = ModelLifecycle.AUDIT

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-crypto-target-model-v2",
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "observations": self.observations,
            "best_validation_gain": self.best_validation_gain,
            "stale_steps": self.stale_steps,
            "family_attempts": dict(sorted(self.family_attempts.items())),
            "failure_counts": dict(sorted(self.failure_counts.items())),
            "blacklisted_families": sorted(self.blacklisted_families),
            "last_surprise": self.last_surprise,
            "lifecycle": self.lifecycle.value,
            "frozen_proposal_sha256": self.frozen_proposal_sha256,
            "frozen_plan_sha256": self.frozen_plan_sha256,
            "test_result_sha256": self.test_result_sha256,
            "max_family_slots": self.max_family_slots,
            "max_failure_codes": self.max_failure_codes,
            "max_identifier_bytes": self.max_identifier_bytes,
            "bounded_control_state": True,
            "counter_precision_bits": 64,
            "max_identifier_storage_bytes": (
                (self.max_family_slots + self.max_failure_codes)
                * self.max_identifier_bytes
            ),
        }

    @classmethod
    def from_description(
        cls, value: Mapping[str, object]
    ) -> "CryptanalyticTargetModel":
        if not isinstance(value, Mapping):
            raise TypeError("TargetModel description must be a mapping")
        if value.get("schema") != "o1-crypto-target-model-v2":
            raise ValueError("unsupported TargetModel schema")
        allowed = {
            "schema",
            "source_snapshot_sha256",
            "observations",
            "best_validation_gain",
            "stale_steps",
            "family_attempts",
            "failure_counts",
            "blacklisted_families",
            "last_surprise",
            "lifecycle",
            "frozen_proposal_sha256",
            "frozen_plan_sha256",
            "test_result_sha256",
            "max_family_slots",
            "max_failure_codes",
            "max_identifier_bytes",
            "bounded_control_state",
            "counter_precision_bits",
            "max_identifier_storage_bytes",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(f"unknown TargetModel fields: {', '.join(unknown)}")

        def strict_int(name: str, default: int) -> int:
            item = value.get(name, default)
            if not isinstance(item, int) or isinstance(item, bool):
                raise TypeError(f"TargetModel field {name} must be an integer")
            return item

        def strict_float(name: str, default: float) -> float:
            item = value.get(name, default)
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise TypeError(f"TargetModel field {name} must be numeric")
            return float(item)

        def strict_counts(name: str) -> dict[str, int]:
            item = value.get(name, {})
            if not isinstance(item, Mapping):
                raise TypeError(f"TargetModel field {name} must be a mapping")
            result: dict[str, int] = {}
            for key, count in item.items():
                if not isinstance(key, str):
                    raise TypeError(f"TargetModel {name} keys must be strings")
                if not isinstance(count, int) or isinstance(count, bool):
                    raise TypeError(f"TargetModel {name} counts must be integers")
                result[key] = count
            return result

        def optional_sha(name: str) -> str | None:
            item = value.get(name)
            if item is not None and not isinstance(item, str):
                raise TypeError(f"TargetModel field {name} must be a string or null")
            return item

        blacklisted = value.get("blacklisted_families", [])
        if not isinstance(blacklisted, list) or any(
            not isinstance(item, str) for item in blacklisted
        ):
            raise TypeError("blacklisted_families must be a list of strings")
        lifecycle_value = value.get("lifecycle", ModelLifecycle.DISCOVERY.value)
        if not isinstance(lifecycle_value, str):
            raise TypeError("lifecycle must be a string")
        source_sha = value.get("source_snapshot_sha256")
        if not isinstance(source_sha, str):
            raise TypeError("source_snapshot_sha256 must be a string")
        if value.get("bounded_control_state") is not True:
            raise ValueError("TargetModel must declare bounded_control_state=true")

        model = cls(
            source_snapshot_sha256=source_sha,
            observations=strict_int("observations", 0),
            best_validation_gain=strict_float("best_validation_gain", 0.0),
            stale_steps=strict_int("stale_steps", 0),
            family_attempts=strict_counts("family_attempts"),
            failure_counts=strict_counts("failure_counts"),
            blacklisted_families=set(blacklisted),
            last_surprise=strict_float("last_surprise", 0.0),
            lifecycle=ModelLifecycle(lifecycle_value),
            frozen_proposal_sha256=optional_sha("frozen_proposal_sha256"),
            frozen_plan_sha256=optional_sha("frozen_plan_sha256"),
            test_result_sha256=optional_sha("test_result_sha256"),
            max_family_slots=strict_int("max_family_slots", 64),
            max_failure_codes=strict_int("max_failure_codes", 64),
            max_identifier_bytes=strict_int("max_identifier_bytes", 128),
        )
        expected_storage = (
            model.max_family_slots + model.max_failure_codes
        ) * model.max_identifier_bytes
        if (
            strict_int("max_identifier_storage_bytes", expected_storage)
            != expected_storage
        ):
            raise ValueError("TargetModel storage budget is inconsistent")
        if strict_int("counter_precision_bits", 64) != 64:
            raise ValueError("TargetModel counter precision must be 64 bits")
        return model

    def state_sha256(self) -> str:
        canonical = json.dumps(
            self.describe(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


class AdaptiveResearchPlanner:
    """Select the next legal experiment from cumulative target state.

    Selection is deterministic and fully billed. Surprise increases the priority of
    untried families but cannot bypass information-flow or blacklist constraints.
    """

    def __init__(self, *, stale_limit: int = 5) -> None:
        if (
            not isinstance(stale_limit, int)
            or isinstance(stale_limit, bool)
            or stale_limit < 1
        ):
            raise ValueError("stale_limit must be positive")
        self.stale_limit = stale_limit

    def choose(
        self,
        proposals: Iterable[ExperimentProposal],
        model: CryptanalyticTargetModel,
        *,
        target_blind: bool = True,
    ) -> ExperimentProposal | None:
        if (
            model.lifecycle is ModelLifecycle.DISCOVERY
            and model.stale_steps >= self.stale_limit
        ):
            return None
        if model.lifecycle in {ModelLifecycle.TEST_CONSUMED, ModelLifecycle.AUDIT}:
            return None
        legal = []
        for proposal in proposals:
            proposal.validate()
            if proposal.family in model.blacklisted_families:
                continue
            if not model.accepts_family(proposal.family):
                continue
            if target_blind and proposal.labels & TARGET_BLIND_FORBIDDEN:
                continue
            if model.lifecycle is ModelLifecycle.DISCOVERY and proposal.split not in {
                DatasetSplit.TRAIN,
                DatasetSplit.VALIDATION,
            }:
                continue
            if (
                model.lifecycle is ModelLifecycle.FROZEN
                and proposal.split is not DatasetSplit.TEST
            ):
                continue
            if (
                model.lifecycle is ModelLifecycle.FROZEN
                and proposal.proposal_sha256() != model.frozen_proposal_sha256
            ):
                continue
            attempts = model.family_attempts.get(proposal.family, 0)
            novelty = 1.0 / (1.0 + attempts)
            surprise_bonus = model.last_surprise * novelty
            utility = (
                proposal.expected_information_gain + surprise_bonus
            ) / proposal.work_units
            tie_break = (
                proposal.name,
                proposal.family,
                proposal.split.value,
                tuple(sorted(label.value for label in proposal.labels)),
                proposal.expected_information_gain,
                proposal.work_units,
            )
            legal.append((utility, novelty, tie_break, proposal))
        if not legal:
            return None
        legal.sort(key=lambda item: (-item[0], -item[1], item[2]))
        return legal[0][3]
