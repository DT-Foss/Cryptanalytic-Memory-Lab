"""Self-calibrating, DC-complete quantized Walsh memory.

O1C-0005 deliberately omitted the constant Walsh mode because its input was
centered independently inside every low-four-bit slot.  Corrected recovery
fields are global raw reader scores: their sixteen slot means are meaningful.
This module retains those sixteen DC coefficients and derives sixteen
label-free quantizer scales from a first canonical pass over the same replayable
field.  The second pass verifies the field hash while building the bounded
integer state; no candidate row or key/value table survives finalization.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .quantized_spectral import (
    CLIP_COUNTER_BITS,
    DIRECT12_SIZE,
    FULL_COVERAGE,
    HIGH8_SIZE,
    LOW4_SLOT_COUNT,
    _pack_signed,
    _pack_unsigned,
    _quantize,
    quantizer_limit,
    safe_accumulator_bits,
)
from .walsh_memory import (
    FIELD_HASH_SCHEMA,
    ApproximationEvaluation,
    FrozenRanking,
    evaluate_approximation,
    score_field_sha256,
)


TEMPLATE_SCHEMA = "o1-adaptive-dc-walsh-template-v1"
PLAN_SCHEMA = "o1-adaptive-dc-walsh-plan-v1"
STATE_SCHEMA = "o1-adaptive-dc-walsh-state-v1"
MECHANISM_FAMILY = "o1-self-calibrating-dc-complete-quantized-walsh-vault"
MODES_PER_SLOT = HIGH8_SIZE
ACCUMULATOR_COUNT = LOW4_SLOT_COUNT * MODES_PER_SLOT
HASH_LOGICAL_STATE_BYTES = 32 + 64 + 8
CALIBRATOR_COUNTER_BYTES = 2
PASS_INTEGRITY_LOGICAL_STATE_BYTES = HASH_LOGICAL_STATE_BYTES + CALIBRATOR_COUNTER_BYTES


class AdaptiveDCSpectralError(ValueError):
    """An adaptive plan, pass, stream, or state violates its frozen contract."""


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
        raise AdaptiveDCSpectralError("value is not canonical finite ASCII JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AdaptiveDCSpectralError(f"{field} must be a lowercase SHA-256")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AdaptiveDCSpectralError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise AdaptiveDCSpectralError(f"{field} must be a finite number")
    return 0.0 if result == 0.0 else result


def _new_field_hasher() -> "hashlib._Hash":
    digest = hashlib.sha256()
    digest.update(FIELD_HASH_SCHEMA)
    digest.update(DIRECT12_SIZE.to_bytes(4, "big"))
    return digest


def _update_field_hasher(digest: "hashlib._Hash", score: float) -> None:
    digest.update(struct.pack(">d", score))


def _scale_sha256(scales: Sequence[float]) -> str:
    digest = hashlib.sha256()
    digest.update(b"o1-adaptive-dc-slot-scales-float64be-v1\x00")
    digest.update(len(scales).to_bytes(2, "big"))
    for scale in scales:
        digest.update(struct.pack(">d", scale))
    return digest.hexdigest()


@dataclass(frozen=True)
class AdaptiveDCTemplate:
    """Frozen label-free algorithm; field-derived values are absent."""

    input_bits: int
    headroom: float
    name: str = "adaptive-dc-complete-quantized-walsh"

    def __post_init__(self) -> None:
        quantizer_limit(self.input_bits)
        checked = _finite(self.headroom, "headroom")
        if checked < 1.0:
            raise AdaptiveDCSpectralError("headroom must be at least 1.0")
        if not isinstance(self.name, str) or not self.name.strip():
            raise AdaptiveDCSpectralError("template name is required")
        object.__setattr__(self, "headroom", checked)

    @property
    def quantizer_max(self) -> int:
        return quantizer_limit(self.input_bits)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": TEMPLATE_SCHEMA,
            "name": self.name,
            "mechanism_family": MECHANISM_FAMILY,
            "input_bits": self.input_bits,
            "headroom": self.headroom,
            "addressing": {
                "candidate_id": "(high8 << 4) | low4",
                "canonical_pass_order": "ascending-candidate-id-0-through-4095",
                "fixed_low4_slots": LOW4_SLOT_COUNT,
                "high8_domain_per_slot": HIGH8_SIZE,
            },
            "spectral_bank": {
                "masks_per_slot": MODES_PER_SLOT,
                "mask_interval": [0, HIGH8_SIZE - 1],
                "includes_dc": True,
                "accumulator_count": ACCUMULATOR_COUNT,
            },
            "scale_rule": {
                "name": "same-field-per-low4-absolute-peak",
                "formula": "scale[low4] = peak_abs[low4] * headroom / quantizer_max",
                "passes": 2,
                "labels_used": 0,
            },
            "integrity": {
                "field_hash": "o1-walsh-score-field-float64be-v1",
                "second_pass_must_match_first_pass": True,
                "duplicate_or_out_of_order_policy": "reject-immediately",
            },
            "claim_boundary": {
                "bounded_state": True,
                "bounded_only_with_respect_to_stream_length_for_fixed_direct12_domain": True,
                "full_rank_fixed_domain_transform": True,
                "spectral_degrees_of_freedom": ACCUMULATOR_COUNT,
                "candidate_domain_size": DIRECT12_SIZE,
                "sublinear_in_candidate_domain": False,
                "compression_claim_eligible": False,
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
                "explicit_kv_cache": False,
                "information_equivalent_to_quantized_direct_table": True,
                "no_full_sequence_attention": True,
                "replayable_source_stream_required": True,
                "serialized_logical_state_is_not_python_process_rss": True,
            },
        }

    @property
    def template_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        value = self._payload()
        value["template_sha256"] = self.template_sha256
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AdaptiveDCTemplate":
        if not isinstance(value, Mapping):
            raise AdaptiveDCSpectralError("template must be an object")
        input_bits = value.get("input_bits")
        headroom = value.get("headroom")
        name = value.get("name")
        if (
            isinstance(input_bits, bool)
            or not isinstance(input_bits, int)
            or isinstance(headroom, bool)
            or not isinstance(headroom, float)
            or not isinstance(name, str)
        ):
            raise AdaptiveDCSpectralError("template schema is invalid")
        try:
            result = cls(
                input_bits=input_bits,
                headroom=headroom,
                name=name,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AdaptiveDCSpectralError("template schema is invalid") from exc
        if result.describe() != dict(value):
            raise AdaptiveDCSpectralError("template canonical commitment differs")
        return result


@dataclass(frozen=True)
class AdaptiveDCPlan:
    """Executable plan bound to one complete, label-free score field."""

    template: AdaptiveDCTemplate
    slot_scales: tuple[float, ...]
    input_field_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.template, AdaptiveDCTemplate):
            raise TypeError("template must be an AdaptiveDCTemplate")
        scales = tuple(
            _finite(value, f"slot_scales[{index}]")
            for index, value in enumerate(self.slot_scales)
        )
        if len(scales) != LOW4_SLOT_COUNT or any(scale <= 0.0 for scale in scales):
            raise AdaptiveDCSpectralError("slot_scales must contain 16 positive values")
        object.__setattr__(self, "slot_scales", scales)
        _sha256(self.input_field_sha256, "input_field_sha256")

    @property
    def input_bits(self) -> int:
        return self.template.input_bits

    @property
    def headroom(self) -> float:
        return self.template.headroom

    @property
    def quantizer_max(self) -> int:
        return self.template.quantizer_max

    @property
    def accumulator_bits(self) -> int:
        return safe_accumulator_bits(self.input_bits)

    @property
    def serialized_accumulator_bytes(self) -> int:
        return (ACCUMULATOR_COUNT * self.accumulator_bits + 7) // 8

    @property
    def serialized_coverage_bytes(self) -> int:
        return DIRECT12_SIZE // 8

    @property
    def serialized_clip_telemetry_bytes(self) -> int:
        return (LOW4_SLOT_COUNT * 2 * CLIP_COUNTER_BITS + 7) // 8

    @property
    def serialized_online_state_bytes(self) -> int:
        return (
            self.serialized_accumulator_bytes
            + self.serialized_coverage_bytes
            + self.serialized_clip_telemetry_bytes
        )

    @property
    def serialized_static_plan_bytes(self) -> int:
        return LOW4_SLOT_COUNT * 8 + 2 * 32

    @property
    def maximum_serialized_logical_mechanism_state_bytes(self) -> int:
        return max(
            LOW4_SLOT_COUNT * 8
            + CALIBRATOR_COUNTER_BYTES
            + HASH_LOGICAL_STATE_BYTES,
            self.serialized_online_state_bytes
            + self.serialized_static_plan_bytes
            + PASS_INTEGRITY_LOGICAL_STATE_BYTES,
        )

    @property
    def scales_sha256(self) -> str:
        return _scale_sha256(self.slot_scales)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "mechanism_family": MECHANISM_FAMILY,
            "template": self.template.describe(),
            "input_field_sha256": self.input_field_sha256,
            "slot_scales": list(self.slot_scales),
            "slot_scales_sha256": self.scales_sha256,
            "online_state": {
                "integer_accumulators": ACCUMULATOR_COUNT,
                "dc_accumulators": LOW4_SLOT_COUNT,
                "non_dc_accumulators": LOW4_SLOT_COUNT * (HIGH8_SIZE - 1),
                "bits_per_accumulator": self.accumulator_bits,
                "serialized_accumulator_bytes": self.serialized_accumulator_bytes,
                "coverage_bits": DIRECT12_SIZE,
                "serialized_coverage_bytes": self.serialized_coverage_bytes,
                "serialized_clip_telemetry_bytes": self.serialized_clip_telemetry_bytes,
                "serialized_online_state_bytes": self.serialized_online_state_bytes,
                "stream_length_dependent_state": False,
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
            },
            "first_pass_state": {
                "peak_float64_values": LOW4_SLOT_COUNT,
                "serialized_peak_bytes": LOW4_SLOT_COUNT * 8,
                "canonical_address_counter_bytes": CALIBRATOR_COUNTER_BYTES,
                "logical_sha256_state_bytes": HASH_LOGICAL_STATE_BYTES,
                "logical_total_bytes": (
                    LOW4_SLOT_COUNT * 8
                    + CALIBRATOR_COUNTER_BYTES
                    + HASH_LOGICAL_STATE_BYTES
                ),
            },
            "static_plan_storage": {
                "scale_float64_values": LOW4_SLOT_COUNT,
                "serialized_scale_bytes": LOW4_SLOT_COUNT * 8,
                "bound_hash_values": 2,
                "serialized_bound_hash_bytes": 64,
                "serialized_static_plan_bytes": self.serialized_static_plan_bytes,
            },
            "second_pass_integrity_state": {
                "canonical_address_counter_bytes": CALIBRATOR_COUNTER_BYTES,
                "logical_sha256_state_bytes": HASH_LOGICAL_STATE_BYTES,
                "logical_total_bytes": PASS_INTEGRITY_LOGICAL_STATE_BYTES,
            },
            "maximum_serialized_logical_mechanism_state_bytes": (
                self.maximum_serialized_logical_mechanism_state_bytes
            ),
            "physical_runtime_memory_measured": False,
        }

    @property
    def plan_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        value = self._payload()
        value["plan_sha256"] = self.plan_sha256
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "AdaptiveDCPlan":
        if not isinstance(value, Mapping):
            raise AdaptiveDCSpectralError("plan must be an object")
        raw_scales = value.get("slot_scales")
        input_hash = value.get("input_field_sha256")
        if (
            not isinstance(raw_scales, list)
            or any(
                not isinstance(item, float)
                for item in raw_scales
            )
            or not isinstance(input_hash, str)
        ):
            raise AdaptiveDCSpectralError("plan schema is invalid")
        try:
            result = cls(
                template=AdaptiveDCTemplate.from_dict(value["template"]),  # type: ignore[arg-type]
                slot_scales=tuple(raw_scales),
                input_field_sha256=input_hash,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AdaptiveDCSpectralError("plan schema is invalid") from exc
        if result.describe() != dict(value):
            raise AdaptiveDCSpectralError("plan canonical commitment differs")
        return result


class AdaptiveDCScaleCalibrator:
    """First canonical pass: field hash plus sixteen absolute peaks."""

    def __init__(self, template: AdaptiveDCTemplate) -> None:
        if not isinstance(template, AdaptiveDCTemplate):
            raise TypeError("template must be an AdaptiveDCTemplate")
        self.template = template
        self._peaks = [0.0] * LOW4_SLOT_COUNT
        self._next_address = 0
        self._hasher = _new_field_hasher()
        self._finalized: AdaptiveDCPlan | None = None

    @property
    def observations(self) -> int:
        return self._next_address

    @property
    def logical_state_bytes(self) -> int:
        return LOW4_SLOT_COUNT * 8 + CALIBRATOR_COUNTER_BYTES + HASH_LOGICAL_STATE_BYTES

    def observe(self, candidate_id: int, score: float) -> None:
        if self._finalized is not None:
            raise AdaptiveDCSpectralError("cannot update a finalized calibrator")
        if not isinstance(candidate_id, int) or isinstance(candidate_id, bool):
            raise AdaptiveDCSpectralError("candidate_id must be an integer")
        if candidate_id != self._next_address:
            raise AdaptiveDCSpectralError(
                f"calibration pass must be canonical; expected {self._next_address}"
            )
        if not 0 <= candidate_id < DIRECT12_SIZE:
            raise AdaptiveDCSpectralError("candidate_id is outside the Direct12 domain")
        value = _finite(score, "score")
        low4 = candidate_id & 0xF
        self._peaks[low4] = max(self._peaks[low4], abs(value))
        _update_field_hasher(self._hasher, value)
        self._next_address += 1

    def observe_many(self, observations: Iterable[tuple[int, float]]) -> None:
        for candidate_id, score in observations:
            self.observe(candidate_id, score)

    def finalize(self) -> AdaptiveDCPlan:
        if self._finalized is not None:
            return self._finalized
        if self._next_address != DIRECT12_SIZE:
            raise AdaptiveDCSpectralError("calibration requires all 4096 canonical addresses")
        if any(peak <= 0.0 or not math.isfinite(peak) for peak in self._peaks):
            raise AdaptiveDCSpectralError("every low4 slot must have positive finite amplitude")
        scales = tuple(
            peak * self.template.headroom / self.template.quantizer_max
            for peak in self._peaks
        )
        self._finalized = AdaptiveDCPlan(
            template=self.template,
            slot_scales=scales,
            input_field_sha256=self._hasher.hexdigest(),
        )
        return self._finalized


def _online_state_bytes(
    plan: AdaptiveDCPlan,
    accumulators: Sequence[int],
    coverage: Sequence[int],
    negative_clips: Sequence[int],
    positive_clips: Sequence[int],
) -> bytes:
    if len(accumulators) != ACCUMULATOR_COUNT:
        raise AdaptiveDCSpectralError("state must contain exactly 4096 accumulators")
    if len(coverage) != LOW4_SLOT_COUNT or any(
        not isinstance(bits, int)
        or isinstance(bits, bool)
        or not 0 <= bits <= FULL_COVERAGE
        for bits in coverage
    ):
        raise AdaptiveDCSpectralError("coverage must contain sixteen 256-bit values")
    if len(negative_clips) != LOW4_SLOT_COUNT or len(positive_clips) != LOW4_SLOT_COUNT:
        raise AdaptiveDCSpectralError("clip telemetry must contain sixteen counters per sign")
    telemetry = tuple(
        counter
        for low4 in range(LOW4_SLOT_COUNT)
        for counter in (negative_clips[low4], positive_clips[low4])
    )
    payload = (
        _pack_signed(accumulators, plan.accumulator_bits)
        + b"".join(bits.to_bytes(32, "big") for bits in coverage)
        + _pack_unsigned(telemetry, CLIP_COUNTER_BITS)
    )
    if len(payload) != plan.serialized_online_state_bytes:
        raise AssertionError("adaptive state accounting differs from packed bytes")
    return payload


@dataclass(frozen=True)
class FrozenAdaptiveDCField:
    plan: AdaptiveDCPlan
    accumulators: tuple[int, ...]
    coverage: tuple[int, ...]
    negative_clips: tuple[int, ...]
    positive_clips: tuple[int, ...]
    input_field_hash_verified: bool

    def __post_init__(self) -> None:
        if not isinstance(self.plan, AdaptiveDCPlan):
            raise TypeError("plan must be an AdaptiveDCPlan")
        _online_state_bytes(
            self.plan,
            self.accumulators,
            self.coverage,
            self.negative_clips,
            self.positive_clips,
        )
        if any(bits != FULL_COVERAGE for bits in self.coverage):
            raise AdaptiveDCSpectralError("frozen state requires complete coverage")
        if self.input_field_hash_verified is not True:
            raise AdaptiveDCSpectralError("frozen state requires a verified second pass")

    @property
    def clip_count(self) -> int:
        return sum(self.negative_clips) + sum(self.positive_clips)

    @property
    def online_state_bytes(self) -> bytes:
        return _online_state_bytes(
            self.plan,
            self.accumulators,
            self.coverage,
            self.negative_clips,
            self.positive_clips,
        )

    @property
    def state_sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(STATE_SCHEMA.encode("ascii") + b"\x00")
        digest.update(bytes.fromhex(self.plan.plan_sha256))
        digest.update(self.online_state_bytes)
        return digest.hexdigest()

    def query(self, candidate_id: int) -> float:
        if (
            not isinstance(candidate_id, int)
            or isinstance(candidate_id, bool)
            or not 0 <= candidate_id < DIRECT12_SIZE
        ):
            raise AdaptiveDCSpectralError("candidate_id is outside the Direct12 domain")
        low4 = candidate_id & 0xF
        high8 = candidate_id >> 4
        start = low4 * MODES_PER_SLOT
        total = 0
        for mask in range(HIGH8_SIZE):
            character = -1 if (mask & high8).bit_count() & 1 else 1
            total += self.accumulators[start + mask] * character
        return self.plan.slot_scales[low4] * total / HIGH8_SIZE

    def reconstruct(self) -> tuple[float, ...]:
        result = [0.0] * DIRECT12_SIZE
        for low4 in range(LOW4_SLOT_COUNT):
            start = low4 * MODES_PER_SLOT
            values = [
                value / HIGH8_SIZE
                for value in self.accumulators[start : start + MODES_PER_SLOT]
            ]
            width = 1
            while width < HIGH8_SIZE:
                block = width * 2
                for block_start in range(0, HIGH8_SIZE, block):
                    for offset in range(width):
                        left = values[block_start + offset]
                        right = values[block_start + offset + width]
                        values[block_start + offset] = left + right
                        values[block_start + offset + width] = left - right
                width = block
            scale = self.plan.slot_scales[low4]
            for high8, value in enumerate(values):
                result[(high8 << 4) | low4] = scale * value
        return tuple(result)

    def freeze_ranking(self) -> FrozenRanking:
        return FrozenRanking.from_scores(
            self.reconstruct(),
            reference_field_sha256=self.plan.input_field_sha256,
        )

    def evaluate(
        self,
        reference_scores: Sequence[float],
        *,
        top_ks: Sequence[int] = (1, 8, 32, 128),
    ) -> ApproximationEvaluation:
        if score_field_sha256(reference_scores) != self.plan.input_field_sha256:
            raise AdaptiveDCSpectralError("reference field differs from the bound input")
        return evaluate_approximation(
            reference_scores,
            self.reconstruct(),
            top_ks=top_ks,
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": STATE_SCHEMA,
            "mechanism_family": MECHANISM_FAMILY,
            "plan_sha256": self.plan.plan_sha256,
            "state_sha256": self.state_sha256,
            "input_field_hash_verified": True,
            "observations": DIRECT12_SIZE,
            "completed_source_passes": 2,
            "coverage_complete": True,
            "clip_telemetry": {
                "negative_by_low4": list(self.negative_clips),
                "positive_by_low4": list(self.positive_clips),
                "total": self.clip_count,
            },
            "online_state": self.plan.describe()["online_state"],
            "claim_boundary": {
                "validation_ceiling_eligible": True,
                "compression_mechanism_claim_eligible": False,
                "full_rank_fixed_domain_transform": True,
                "information_equivalent_to_quantized_direct_table": True,
                "target_labels_used": 0,
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
                "retention_scope": "inside-frozen-mechanism-state-only",
            },
        }


class AdaptiveDCQuantizedVault:
    """Second canonical pass: verify the source and build all 256 slot modes."""

    def __init__(self, plan: AdaptiveDCPlan) -> None:
        if not isinstance(plan, AdaptiveDCPlan):
            raise TypeError("plan must be an AdaptiveDCPlan")
        self.plan = plan
        self._accumulators = [0] * ACCUMULATOR_COUNT
        self._coverage = [0] * LOW4_SLOT_COUNT
        self._negative_clips = [0] * LOW4_SLOT_COUNT
        self._positive_clips = [0] * LOW4_SLOT_COUNT
        self._next_address = 0
        self._hasher = _new_field_hasher()
        self._invalid = False
        self._finalized: FrozenAdaptiveDCField | None = None

    @property
    def observations(self) -> int:
        return self._next_address

    def observe(self, candidate_id: int, score: float) -> None:
        if self._finalized is not None or self._invalid:
            raise AdaptiveDCSpectralError("cannot update a finalized or invalid vault")
        if not isinstance(candidate_id, int) or isinstance(candidate_id, bool):
            self._invalid = True
            raise AdaptiveDCSpectralError("candidate_id must be an integer")
        if candidate_id != self._next_address:
            self._invalid = True
            raise AdaptiveDCSpectralError(
                f"second pass must be canonical; expected {self._next_address}"
            )
        if not 0 <= candidate_id < DIRECT12_SIZE:
            self._invalid = True
            raise AdaptiveDCSpectralError("candidate_id is outside the Direct12 domain")
        value = _finite(score, "score")
        low4 = candidate_id & 0xF
        high8 = candidate_id >> 4
        address_bit = 1 << high8
        if self._coverage[low4] & address_bit:
            self._invalid = True
            raise AdaptiveDCSpectralError("duplicate Direct12 observation")
        quantized, clip = _quantize(
            value,
            self.plan.slot_scales[low4],
            self.plan.quantizer_max,
        )
        start = low4 * MODES_PER_SLOT
        for mask in range(HIGH8_SIZE):
            character = -1 if (mask & high8).bit_count() & 1 else 1
            self._accumulators[start + mask] += quantized * character
        self._coverage[low4] |= address_bit
        if clip < 0:
            self._negative_clips[low4] += 1
        elif clip > 0:
            self._positive_clips[low4] += 1
        _update_field_hasher(self._hasher, value)
        self._next_address += 1

    def observe_many(self, observations: Iterable[tuple[int, float]]) -> None:
        for candidate_id, score in observations:
            self.observe(candidate_id, score)

    def finalize(self) -> FrozenAdaptiveDCField:
        if self._finalized is not None:
            return self._finalized
        if self._invalid:
            raise AdaptiveDCSpectralError("invalid vault cannot be finalized")
        if self._next_address != DIRECT12_SIZE or any(
            bits != FULL_COVERAGE for bits in self._coverage
        ):
            raise AdaptiveDCSpectralError("finalization requires exact 4096-cell coverage")
        if self._hasher.hexdigest() != self.plan.input_field_sha256:
            self._invalid = True
            raise AdaptiveDCSpectralError("second-pass field hash differs from calibration")
        self._finalized = FrozenAdaptiveDCField(
            plan=self.plan,
            accumulators=tuple(self._accumulators),
            coverage=tuple(self._coverage),
            negative_clips=tuple(self._negative_clips),
            positive_clips=tuple(self._positive_clips),
            input_field_hash_verified=True,
        )
        return self._finalized


@dataclass(frozen=True)
class AdaptiveDCExecution:
    template: AdaptiveDCTemplate
    plan: AdaptiveDCPlan
    frozen: FrozenAdaptiveDCField
    evaluation: ApproximationEvaluation
    order: tuple[int, ...]

    @property
    def order_uint16be(self) -> bytes:
        return b"".join(cell.to_bytes(2, "big") for cell in self.order)

    @property
    def order_uint16be_sha256(self) -> str:
        return hashlib.sha256(self.order_uint16be).hexdigest()

    def describe(self, *, include_plan: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "o1-adaptive-dc-walsh-execution-v1",
            "arm_id": self.template.name,
            "template_sha256": self.template.template_sha256,
            "plan_sha256": self.plan.plan_sha256,
            "frozen_state_sha256": self.frozen.state_sha256,
            "order_uint16be_sha256": self.order_uint16be_sha256,
            "evaluation": self.evaluation.describe(),
            "clip_count": self.frozen.clip_count,
            "serialized_online_state_bytes": self.plan.serialized_online_state_bytes,
            "serialized_static_plan_bytes": self.plan.serialized_static_plan_bytes,
            "maximum_serialized_logical_mechanism_state_bytes": (
                self.plan.maximum_serialized_logical_mechanism_state_bytes
            ),
            "physical_runtime_memory_measured": False,
            "passes": {
                "source_passes": 2,
                "field_values_read": 2 * DIRECT12_SIZE,
                "scale_updates": DIRECT12_SIZE,
                "quantizations": DIRECT12_SIZE,
                "walsh_character_evaluations": DIRECT12_SIZE * HIGH8_SIZE,
                "accumulator_updates": DIRECT12_SIZE * HIGH8_SIZE,
                "reconstruction_butterflies": LOW4_SLOT_COUNT * 8 * 128,
                "ranking_items": DIRECT12_SIZE,
            },
            "labels_used": 0,
        }
        if include_plan:
            value["plan"] = self.plan.describe()
            value["state"] = self.frozen.describe()
        return value


def execute_adaptive_dc(
    scores: Sequence[float],
    template: AdaptiveDCTemplate,
    *,
    top_ks: Sequence[int] = (1, 8, 32, 128, 512),
) -> AdaptiveDCExecution:
    """Materialized validation helper exercising the same strict two-pass API."""

    if len(scores) != DIRECT12_SIZE:
        raise AdaptiveDCSpectralError("scores must contain exactly 4096 values")
    field = tuple(_finite(value, f"scores[{index}]") for index, value in enumerate(scores))
    calibrator = AdaptiveDCScaleCalibrator(template)
    calibrator.observe_many(enumerate(field))
    plan = calibrator.finalize()
    if plan.input_field_sha256 != score_field_sha256(field):
        raise AssertionError("streaming and materialized field hashes differ")
    # The mechanism phases do not overlap.  Release the first-pass peaks and
    # hasher before allocating the second-pass accumulator bank.
    del calibrator
    vault = AdaptiveDCQuantizedVault(plan)
    vault.observe_many(enumerate(field))
    frozen = vault.finalize()
    evaluation = frozen.evaluate(field, top_ks=top_ks)
    ranking = frozen.freeze_ranking()
    return AdaptiveDCExecution(
        template=template,
        plan=plan,
        frozen=frozen,
        evaluation=evaluation,
        order=ranking.order,
    )
