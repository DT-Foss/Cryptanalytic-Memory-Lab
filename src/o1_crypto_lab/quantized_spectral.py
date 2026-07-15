"""Quantized fixed-slot Walsh memory for Direct12 score streams.

The mechanism is a deliberately literal O1-style multi-slot bit vault:

* the low four address bits select one of sixteen permanent slots;
* the high eight bits address a complete 8-bit Walsh bank without DC;
* every observation is symmetrically quantized before it reaches an integer
  accumulator; and
* the online state retains no candidate scores, rows, transcript, or key/value
  table.

The sixteen quantization scales are calibrated from a complete label-free field
and are static plan data, not recurrent state.  Exact 4096-bit coverage and
per-slot signed clip counters are included in the online-state accounting.  A
direct per-candidate quantized table exists only as :class:`DictionaryCeiling`;
its metadata makes it ineligible for a mechanism claim.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .walsh_memory import (
    ApproximationEvaluation,
    FrozenRanking,
    evaluate_approximation,
    score_field_sha256,
)


PLAN_SCHEMA = "o1-quantized-multislot-walsh-plan-v1"
STATE_SCHEMA = "o1-quantized-multislot-walsh-state-v1"
DICTIONARY_SCHEMA = "o1-quantized-dictionary-ceiling-v1"
MECHANISM_FAMILY = "o1-multislot-quantized-walsh-bit-vault"
DICTIONARY_FAMILY = "dictionary_ceiling"

LOW4_SLOT_COUNT = 16
HIGH8_BITS = 8
HIGH8_SIZE = 1 << HIGH8_BITS
DIRECT12_SIZE = LOW4_SLOT_COUNT * HIGH8_SIZE
NON_DC_MODE_COUNT = HIGH8_SIZE - 1
ACCUMULATOR_COUNT = LOW4_SLOT_COUNT * NON_DC_MODE_COUNT
FULL_COVERAGE = (1 << HIGH8_SIZE) - 1
CLIP_COUNTER_BITS = (HIGH8_SIZE + 1).bit_length()  # unsigned 0..256 -> 9 bits


class QuantizedSpectralError(ValueError):
    """Raised when a plan, quantized stream, or frozen state is invalid."""


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
        raise QuantizedSpectralError("value is not canonical finite ASCII JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise QuantizedSpectralError(f"{field} must be a lowercase SHA-256")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise QuantizedSpectralError(f"{field} must be a finite number")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise QuantizedSpectralError(f"{field} must be a finite number") from exc
    if not math.isfinite(result):
        raise QuantizedSpectralError(f"{field} must be a finite number")
    return 0.0 if result == 0.0 else result


def _score_field(scores: Sequence[float], field: str = "scores") -> tuple[float, ...]:
    try:
        if len(scores) != DIRECT12_SIZE:
            raise QuantizedSpectralError(
                f"{field} must contain exactly {DIRECT12_SIZE} Direct12 scores"
            )
    except TypeError as exc:
        raise QuantizedSpectralError(f"{field} must be a sized sequence") from exc
    return tuple(_finite(value, f"{field}[{index}]") for index, value in enumerate(scores))


def quantizer_limit(input_bits: int) -> int:
    """Return the symmetric signed magnitude limit ``2**(bits-1)-1``."""

    if (
        not isinstance(input_bits, int)
        or isinstance(input_bits, bool)
        or not 2 <= input_bits <= 8
    ):
        raise QuantizedSpectralError("input_bits must be an integer in [2, 8]")
    return (1 << (input_bits - 1)) - 1


def safe_accumulator_bits(input_bits: int) -> int:
    """Width of a signed accumulator that safely contains ``256 * Q``.

    The result is 12, 14, and 16 bits for 4-, 6-, and 8-bit inputs.  The extra
    sign bit is essential because the positive extreme must also be representable.
    """

    maximum = HIGH8_SIZE * quantizer_limit(input_bits)
    return maximum.bit_length() + 1


def _pack_signed(values: Sequence[int], width: int) -> bytes:
    if not isinstance(width, int) or width < 2:
        raise QuantizedSpectralError("signed packing width is invalid")
    lower = -(1 << (width - 1))
    upper = (1 << (width - 1)) - 1
    bit_mask = (1 << width) - 1
    packed = 0
    for index, value in enumerate(values):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not lower <= value <= upper
        ):
            raise QuantizedSpectralError(
                f"signed packed value {index} does not fit {width} bits"
            )
        packed = (packed << width) | (value & bit_mask)
    bit_count = len(values) * width
    return packed.to_bytes((bit_count + 7) // 8, "big")


def _pack_unsigned(values: Sequence[int], width: int) -> bytes:
    if not isinstance(width, int) or width < 1:
        raise QuantizedSpectralError("unsigned packing width is invalid")
    upper = (1 << width) - 1
    packed = 0
    for index, value in enumerate(values):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= upper
        ):
            raise QuantizedSpectralError(
                f"unsigned packed value {index} does not fit {width} bits"
            )
        packed = (packed << width) | value
    bit_count = len(values) * width
    return packed.to_bytes((bit_count + 7) // 8, "big")


def _scale_sha256(scales: Sequence[float]) -> str:
    digest = hashlib.sha256()
    digest.update(b"o1-quantized-slot-scales-float64be-v1\x00")
    digest.update(len(scales).to_bytes(2, "big"))
    for scale in scales:
        digest.update(struct.pack(">d", scale))
    return digest.hexdigest()


def _quantize(value: float, scale: float, limit: int) -> tuple[int, int]:
    """Round half away from zero, then symmetrically saturate.

    The second return value is -1 for a negative clip, +1 for a positive clip,
    and zero otherwise.  Values outside the quantizer range are detected before
    conversion to an arbitrarily large Python integer.
    """

    ratio = value / scale
    magnitude = abs(ratio)
    if magnitude >= limit + 0.5:
        return (-limit, -1) if ratio < 0.0 else (limit, 1)
    rounded = int(math.floor(magnitude + 0.5))
    return (-rounded if ratio < 0.0 else rounded), 0


@dataclass(frozen=True)
class QuantizedSpectralPlan:
    """Canonical transfer plan: A348 scales bound separately from deployment."""

    input_bits: int
    headroom: float
    slot_scales: tuple[float, ...]
    calibration_field_sha256: str
    deployment_field_sha256: str
    name: str = "direct12-quantized-multislot-bit-vault"

    def __post_init__(self) -> None:
        quantizer_limit(self.input_bits)
        headroom = _finite(self.headroom, "headroom")
        if headroom < 1.0:
            raise QuantizedSpectralError("headroom must be at least 1.0")
        try:
            scales = tuple(
                _finite(value, f"slot_scales[{index}]")
                for index, value in enumerate(self.slot_scales)
            )
        except TypeError as exc:
            raise QuantizedSpectralError("slot_scales must be iterable") from exc
        if len(scales) != LOW4_SLOT_COUNT or any(scale <= 0.0 for scale in scales):
            raise QuantizedSpectralError("slot_scales must contain 16 positive values")
        _sha256(self.calibration_field_sha256, "calibration_field_sha256")
        _sha256(self.deployment_field_sha256, "deployment_field_sha256")
        if not isinstance(self.name, str) or not self.name.strip():
            raise QuantizedSpectralError("plan name is required")
        object.__setattr__(self, "headroom", headroom)
        object.__setattr__(self, "slot_scales", scales)

    @classmethod
    def from_calibration(
        cls,
        calibration_scores: Sequence[float],
        deployment_scores: Sequence[float],
        *,
        input_bits: int,
        headroom: float = 1.25,
        name: str = "direct12-quantized-multislot-bit-vault",
    ) -> "QuantizedSpectralPlan":
        """Derive sixteen label-free peak scales and bind a deployment field.

        Candidate labels are intentionally absent from this API.  For each low4
        slot, ``scale = calibration_peak * headroom / Q``.  Direct12 slice-z
        fields already satisfy the no-DC, per-slot-centered input contract.
        """

        calibration = _score_field(calibration_scores, "calibration_scores")
        deployment = _score_field(deployment_scores, "deployment_scores")
        limit = quantizer_limit(input_bits)
        checked_headroom = _finite(headroom, "headroom")
        if checked_headroom < 1.0:
            raise QuantizedSpectralError("headroom must be at least 1.0")
        scales: list[float] = []
        for low4 in range(LOW4_SLOT_COUNT):
            peak = max(
                abs(calibration[(high8 << 4) | low4])
                for high8 in range(HIGH8_SIZE)
            )
            scale = peak * checked_headroom / limit
            if not math.isfinite(scale) or scale <= 0.0:
                raise QuantizedSpectralError(
                    f"calibration low4 slot {low4} has no positive finite scale"
                )
            scales.append(scale)
        return cls(
            input_bits=input_bits,
            headroom=checked_headroom,
            slot_scales=tuple(scales),
            calibration_field_sha256=score_field_sha256(calibration),
            deployment_field_sha256=score_field_sha256(deployment),
            name=name,
        )

    @property
    def quantizer_max(self) -> int:
        return quantizer_limit(self.input_bits)

    @property
    def accumulator_bits(self) -> int:
        return safe_accumulator_bits(self.input_bits)

    @property
    def accumulator_count(self) -> int:
        return ACCUMULATOR_COUNT

    @property
    def serialized_accumulator_bytes(self) -> int:
        return (self.accumulator_count * self.accumulator_bits + 7) // 8

    @property
    def serialized_coverage_bytes(self) -> int:
        return DIRECT12_SIZE // 8

    @property
    def serialized_clip_telemetry_bytes(self) -> int:
        # Negative and positive counters for each slot, each capable of 0..256.
        return (LOW4_SLOT_COUNT * 2 * CLIP_COUNTER_BITS + 7) // 8

    @property
    def serialized_online_state_bytes(self) -> int:
        return (
            self.serialized_accumulator_bytes
            + self.serialized_coverage_bytes
            + self.serialized_clip_telemetry_bytes
        )

    @property
    def serialized_static_scale_bytes(self) -> int:
        return LOW4_SLOT_COUNT * 8

    @property
    def serialized_bound_hash_bytes(self) -> int:
        return 2 * 32

    @property
    def scales_sha256(self) -> str:
        return _scale_sha256(self.slot_scales)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "name": self.name,
            "mechanism_family": MECHANISM_FAMILY,
            "addressing": {
                "domain_size": DIRECT12_SIZE,
                "candidate_id": "(high8 << 4) | low4",
                "fixed_low4_slots": LOW4_SLOT_COUNT,
                "high8_domain_per_slot": HIGH8_SIZE,
            },
            "spectral_bank": {
                "masks": "implicit integers 1..255",
                "modes_per_slot": NON_DC_MODE_COUNT,
                "includes_dc": False,
                "accumulator_count": ACCUMULATOR_COUNT,
            },
            "quantization": {
                "input_bits": self.input_bits,
                "signed_limit": self.quantizer_max,
                "rounding": "nearest-half-away-from-zero",
                "saturation": "symmetric",
                "headroom": self.headroom,
                "calibration": "per-low4 absolute peak times headroom",
            },
            "input_contract": {
                "score_field": "per-low4-centered Direct12 slice-z field",
                "calibration_role": "label-free scale-calibration field",
                "calibration_field_sha256": self.calibration_field_sha256,
                "deployment_role": "label-free hash-bound execution field",
                "deployment_field_sha256": self.deployment_field_sha256,
                "target_labels_used": 0,
            },
            "slot_scales": list(self.slot_scales),
            "slot_scales_sha256": self.scales_sha256,
            "online_state": {
                "integer_accumulators": ACCUMULATOR_COUNT,
                "accumulator_safe_bound": HIGH8_SIZE * self.quantizer_max,
                "bits_per_accumulator": self.accumulator_bits,
                "serialized_accumulator_bytes": self.serialized_accumulator_bytes,
                "coverage_bits": DIRECT12_SIZE,
                "serialized_coverage_bytes": self.serialized_coverage_bytes,
                "clip_counters": LOW4_SLOT_COUNT * 2,
                "bits_per_clip_counter": CLIP_COUNTER_BITS,
                "serialized_clip_telemetry_bytes": self.serialized_clip_telemetry_bytes,
                "serialized_online_state_bytes": self.serialized_online_state_bytes,
                "stream_length_dependent_state": False,
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
            },
            "static_plan_storage": {
                "scale_values": LOW4_SLOT_COUNT,
                "scale_dtype": "float64",
                "serialized_scale_bytes": self.serialized_static_scale_bytes,
                "bound_sha256_values": 2,
                "serialized_bound_hash_bytes": self.serialized_bound_hash_bytes,
                "counted_as_online_recurrent_state": False,
            },
            "integrity": {
                "duplicate_policy": "reject-immediately",
                "coverage_policy": "all-4096-addresses-exactly-once",
                "coverage_bitsets_are_integrity_only": True,
            },
            "claim_boundary": {
                "mechanism_claim_eligible": True,
                "dictionary_ceiling": False,
                "no_candidate_table": True,
                "no_kv_cache": True,
                "no_full_sequence_attention": True,
            },
        }

    @property
    def plan_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        result = self._payload()
        result["plan_sha256"] = self.plan_sha256
        return result

    def to_json(self) -> str:
        return json.dumps(
            self.describe(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "QuantizedSpectralPlan":
        if not isinstance(value, Mapping):
            raise QuantizedSpectralError("serialized plan must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("plan_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(
            supplied
        ):
            raise QuantizedSpectralError("serialized plan canonical SHA-256 mismatch")
        try:
            quantization = supplied["quantization"]
            contract = supplied["input_contract"]
            if not isinstance(quantization, Mapping) or not isinstance(contract, Mapping):
                raise TypeError
            plan = cls(
                input_bits=quantization["input_bits"],
                headroom=quantization["headroom"],
                slot_scales=tuple(supplied["slot_scales"]),
                calibration_field_sha256=contract["calibration_field_sha256"],
                deployment_field_sha256=contract["deployment_field_sha256"],
                name=supplied["name"],
            )
        except (KeyError, TypeError) as exc:
            raise QuantizedSpectralError("serialized plan schema is invalid") from exc
        if plan._payload() != supplied or plan.plan_sha256 != supplied_hash:
            raise QuantizedSpectralError("serialized plan contains non-canonical metadata")
        return plan


def _clip_telemetry_values(
    negative_clips: Sequence[int], positive_clips: Sequence[int]
) -> tuple[int, ...]:
    if len(negative_clips) != LOW4_SLOT_COUNT or len(positive_clips) != LOW4_SLOT_COUNT:
        raise QuantizedSpectralError("clip telemetry must contain 16 counters per sign")
    return tuple(
        counter
        for low4 in range(LOW4_SLOT_COUNT)
        for counter in (negative_clips[low4], positive_clips[low4])
    )


def _online_state_bytes(
    plan: QuantizedSpectralPlan,
    accumulators: Sequence[int],
    coverage: Sequence[int],
    negative_clips: Sequence[int],
    positive_clips: Sequence[int],
) -> bytes:
    if len(accumulators) != ACCUMULATOR_COUNT:
        raise QuantizedSpectralError("state must contain exactly 4080 accumulators")
    if len(coverage) != LOW4_SLOT_COUNT:
        raise QuantizedSpectralError("state must contain 16 coverage bitsets")
    if any(
        not isinstance(bits, int)
        or isinstance(bits, bool)
        or not 0 <= bits <= FULL_COVERAGE
        for bits in coverage
    ):
        raise QuantizedSpectralError("coverage bitsets must be unsigned 256-bit values")
    coverage_bytes = b"".join(bits.to_bytes(32, "big") for bits in coverage)
    telemetry = _clip_telemetry_values(negative_clips, positive_clips)
    payload = (
        _pack_signed(accumulators, plan.accumulator_bits)
        + coverage_bytes
        + _pack_unsigned(telemetry, CLIP_COUNTER_BITS)
    )
    if len(payload) != plan.serialized_online_state_bytes:
        raise AssertionError("online-state accounting disagrees with packed payload")
    return payload


def _state_sha256(
    plan: QuantizedSpectralPlan, online_state: bytes, *, input_hash_verified: bool
) -> str:
    digest = hashlib.sha256()
    digest.update(STATE_SCHEMA.encode("ascii") + b"\x00")
    digest.update(bytes.fromhex(plan.plan_sha256))
    digest.update(b"\x01" if input_hash_verified else b"\x00")
    digest.update(online_state)
    return digest.hexdigest()


@dataclass(frozen=True)
class FrozenQuantizedSpectralField:
    """Final integer spectral state; source candidate rows are absent."""

    plan: QuantizedSpectralPlan
    accumulators: tuple[int, ...]
    coverage: tuple[int, ...]
    negative_clips: tuple[int, ...]
    positive_clips: tuple[int, ...]
    input_field_hash_verified: bool

    def __post_init__(self) -> None:
        if not isinstance(self.plan, QuantizedSpectralPlan):
            raise TypeError("plan must be a QuantizedSpectralPlan")
        if not isinstance(self.input_field_hash_verified, bool):
            raise QuantizedSpectralError("input_field_hash_verified must be boolean")
        # Packing validates widths, telemetry, and coverage representation.
        _online_state_bytes(
            self.plan,
            self.accumulators,
            self.coverage,
            self.negative_clips,
            self.positive_clips,
        )
        if any(bits != FULL_COVERAGE for bits in self.coverage):
            raise QuantizedSpectralError("frozen state requires exact complete coverage")

    @property
    def observations(self) -> int:
        return sum(bits.bit_count() for bits in self.coverage)

    @property
    def completed_passes(self) -> int:
        return 1

    @property
    def state_scalars(self) -> int:
        return ACCUMULATOR_COUNT

    @property
    def retained_rows(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

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
        return _state_sha256(
            self.plan,
            self.online_state_bytes,
            input_hash_verified=self.input_field_hash_verified,
        )

    def query(self, candidate_id: int) -> float:
        if (
            not isinstance(candidate_id, int)
            or isinstance(candidate_id, bool)
            or not 0 <= candidate_id < DIRECT12_SIZE
        ):
            raise QuantizedSpectralError("candidate_id is outside the Direct12 domain")
        low4 = candidate_id & 0xF
        high8 = candidate_id >> 4
        start = low4 * NON_DC_MODE_COUNT
        total = 0
        for offset, mask in enumerate(range(1, HIGH8_SIZE)):
            character = -1 if (mask & high8).bit_count() & 1 else 1
            total += self.accumulators[start + offset] * character
        return self.plan.slot_scales[low4] * total / HIGH8_SIZE

    def reconstruct(self) -> tuple[float, ...]:
        """Inverse-Walsh reconstruct all slots with the absent DC fixed to zero."""

        result = [0.0] * DIRECT12_SIZE
        for low4 in range(LOW4_SLOT_COUNT):
            start = low4 * NON_DC_MODE_COUNT
            values = [0.0] + [
                value / HIGH8_SIZE
                for value in self.accumulators[start : start + NON_DC_MODE_COUNT]
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
        """Freeze a target-blind total order using the shared Walsh evaluator."""

        return FrozenRanking.from_scores(
            self.reconstruct(),
            reference_field_sha256=self.plan.deployment_field_sha256,
        )

    def evaluate(
        self,
        reference_scores: Sequence[float],
        *,
        top_ks: Sequence[int] = (1, 8, 32),
    ) -> ApproximationEvaluation:
        """Target-blind field and order fidelity; no target-label API exists."""

        reference = _score_field(reference_scores, "reference_scores")
        if score_field_sha256(reference) != self.plan.deployment_field_sha256:
            raise QuantizedSpectralError("reference field differs from deployment hash")
        return evaluate_approximation(reference, self.reconstruct(), top_ks=top_ks)

    def describe(self) -> dict[str, object]:
        return {
            "schema": STATE_SCHEMA,
            "mechanism_family": MECHANISM_FAMILY,
            "plan_sha256": self.plan.plan_sha256,
            "state_sha256": self.state_sha256,
            "input_field_hash_verified": self.input_field_hash_verified,
            "observations": self.observations,
            "coverage_complete": True,
            "completed_passes": 1,
            "state": {
                "integer_accumulators": ACCUMULATOR_COUNT,
                "bits_per_accumulator": self.plan.accumulator_bits,
                "serialized_accumulator_bytes": self.plan.serialized_accumulator_bytes,
                "coverage_bits": DIRECT12_SIZE,
                "serialized_coverage_bytes": self.plan.serialized_coverage_bytes,
                "serialized_clip_telemetry_bytes": (
                    self.plan.serialized_clip_telemetry_bytes
                ),
                "serialized_online_state_bytes": (
                    self.plan.serialized_online_state_bytes
                ),
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
            },
            "clip_telemetry": {
                "negative_by_low4": list(self.negative_clips),
                "positive_by_low4": list(self.positive_clips),
                "total": self.clip_count,
            },
            "static_calibration": {
                "calibration_field_sha256": self.plan.calibration_field_sha256,
                "deployment_field_sha256": self.plan.deployment_field_sha256,
                "slot_scales_sha256": self.plan.scales_sha256,
                "serialized_scale_bytes": self.plan.serialized_static_scale_bytes,
                "counted_as_online_recurrent_state": False,
            },
            "claim_boundary": {
                "mechanism_claim_eligible": self.input_field_hash_verified,
                "dictionary_ceiling": False,
                "deployment_field_hash_verified": self.input_field_hash_verified,
                "target_labels_used": 0,
            },
        }


class QuantizedMultiSlotBitVault:
    """Streaming 16-slot, 4080-register integer Walsh accumulator."""

    def __init__(self, plan: QuantizedSpectralPlan) -> None:
        if not isinstance(plan, QuantizedSpectralPlan):
            raise TypeError("plan must be a QuantizedSpectralPlan")
        self.plan = plan
        self._accumulators = [0] * ACCUMULATOR_COUNT
        self._coverage = [0] * LOW4_SLOT_COUNT
        self._negative_clips = [0] * LOW4_SLOT_COUNT
        self._positive_clips = [0] * LOW4_SLOT_COUNT
        self._observations = 0
        self._input_field_hash_verified = False
        self._finalized: FrozenQuantizedSpectralField | None = None

    @property
    def observations(self) -> int:
        return self._observations

    @property
    def state_scalars(self) -> int:
        return ACCUMULATOR_COUNT

    @property
    def retained_rows(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

    @property
    def online_state_bytes(self) -> bytes:
        if self._finalized is not None:
            return self._finalized.online_state_bytes
        return _online_state_bytes(
            self.plan,
            self._accumulators,
            self._coverage,
            self._negative_clips,
            self._positive_clips,
        )

    @property
    def state_sha256(self) -> str:
        if self._finalized is not None:
            return self._finalized.state_sha256
        return _state_sha256(
            self.plan,
            self.online_state_bytes,
            input_hash_verified=self._input_field_hash_verified,
        )

    def observe(self, candidate_id: int, score: float) -> None:
        if self._finalized is not None:
            raise QuantizedSpectralError("cannot update a finalized bit vault")
        if (
            not isinstance(candidate_id, int)
            or isinstance(candidate_id, bool)
            or not 0 <= candidate_id < DIRECT12_SIZE
        ):
            raise QuantizedSpectralError("candidate_id is outside the Direct12 domain")
        value = _finite(score, "score")
        low4 = candidate_id & 0xF
        high8 = candidate_id >> 4
        address_bit = 1 << high8
        if self._coverage[low4] & address_bit:
            raise QuantizedSpectralError(
                f"duplicate Direct12 candidate observation: {candidate_id}"
            )
        quantized, clip = _quantize(
            value, self.plan.slot_scales[low4], self.plan.quantizer_max
        )
        start = low4 * NON_DC_MODE_COUNT
        for offset, mask in enumerate(range(1, HIGH8_SIZE)):
            character = -1 if (mask & high8).bit_count() & 1 else 1
            self._accumulators[start + offset] += quantized * character
        self._coverage[low4] |= address_bit
        if clip < 0:
            self._negative_clips[low4] += 1
        elif clip > 0:
            self._positive_clips[low4] += 1
        self._observations += 1

    def observe_many(self, observations: Iterable[tuple[int, float]]) -> None:
        """Apply a stream transactionally using only a second O(state) snapshot."""

        if self._finalized is not None:
            raise QuantizedSpectralError("cannot update a finalized bit vault")
        snapshot = (
            self._accumulators.copy(),
            self._coverage.copy(),
            self._negative_clips.copy(),
            self._positive_clips.copy(),
            self._observations,
            self._input_field_hash_verified,
        )
        try:
            for item in observations:
                try:
                    candidate_id, score = item
                except (TypeError, ValueError) as exc:
                    raise QuantizedSpectralError(
                        "each observation must be a (candidate_id, score) pair"
                    ) from exc
                self.observe(candidate_id, score)
        except Exception:
            (
                self._accumulators,
                self._coverage,
                self._negative_clips,
                self._positive_clips,
                self._observations,
                self._input_field_hash_verified,
            ) = snapshot
            raise

    def observe_field(
        self,
        scores: Sequence[float],
        *,
        address_order: Sequence[int] | None = None,
    ) -> None:
        """Verify the deployment commitment, then stream one exact cover."""

        if self._observations:
            raise QuantizedSpectralError("observe_field requires a fresh bit vault")
        field = _score_field(scores)
        if score_field_sha256(field) != self.plan.deployment_field_sha256:
            raise QuantizedSpectralError("score field differs from deployment hash")
        if address_order is None:
            order = tuple(range(DIRECT12_SIZE))
        else:
            try:
                order = tuple(address_order)
            except TypeError as exc:
                raise QuantizedSpectralError("address_order must be iterable") from exc
            if len(order) != DIRECT12_SIZE or set(order) != set(range(DIRECT12_SIZE)):
                raise QuantizedSpectralError(
                    "address_order must be a complete Direct12 permutation"
                )
        self.observe_many((candidate_id, field[candidate_id]) for candidate_id in order)
        self._input_field_hash_verified = True

    def finalize(self) -> FrozenQuantizedSpectralField:
        if self._finalized is not None:
            return self._finalized
        if self._observations != DIRECT12_SIZE or any(
            bits != FULL_COVERAGE for bits in self._coverage
        ):
            missing = [
                HIGH8_SIZE - bits.bit_count()
                for bits in self._coverage
            ]
            raise QuantizedSpectralError(
                "finalization requires every Direct12 address exactly once; "
                f"missing_by_low4={missing}"
            )
        self._finalized = FrozenQuantizedSpectralField(
            plan=self.plan,
            accumulators=tuple(self._accumulators),
            coverage=tuple(self._coverage),
            negative_clips=tuple(self._negative_clips),
            positive_clips=tuple(self._positive_clips),
            input_field_hash_verified=self._input_field_hash_verified,
        )
        # Avoid retaining two copies of the 4080-register state after freezing.
        self._accumulators = []
        self._coverage = []
        self._negative_clips = []
        self._positive_clips = []
        return self._finalized


# Concise compatibility name for experiment runners.
QuantizedSpectralMemory = QuantizedMultiSlotBitVault


@dataclass(frozen=True)
class DictionaryCeiling:
    """Explicitly disallowed mechanism control retaining all candidate entries."""

    plan: QuantizedSpectralPlan
    quantized_candidate_entries: tuple[int, ...]
    negative_clips: tuple[int, ...]
    positive_clips: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.plan, QuantizedSpectralPlan):
            raise TypeError("plan must be a QuantizedSpectralPlan")
        if len(self.quantized_candidate_entries) != DIRECT12_SIZE:
            raise QuantizedSpectralError("dictionary ceiling requires 4096 entries")
        limit = self.plan.quantizer_max
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not -limit <= value <= limit
            for value in self.quantized_candidate_entries
        ):
            raise QuantizedSpectralError("dictionary entry exceeds quantizer range")
        _clip_telemetry_values(self.negative_clips, self.positive_clips)

    @property
    def retained_rows(self) -> int:
        return DIRECT12_SIZE

    @property
    def retained_key_value_entries(self) -> int:
        return DIRECT12_SIZE

    @property
    def serialized_candidate_table_bytes(self) -> int:
        return (DIRECT12_SIZE * self.plan.input_bits + 7) // 8

    @property
    def serialized_clip_telemetry_bytes(self) -> int:
        return self.plan.serialized_clip_telemetry_bytes

    @property
    def serialized_control_state_bytes(self) -> int:
        return (
            self.serialized_candidate_table_bytes
            + self.serialized_clip_telemetry_bytes
        )

    @property
    def state_sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(DICTIONARY_SCHEMA.encode("ascii") + b"\x00")
        digest.update(bytes.fromhex(self.plan.plan_sha256))
        digest.update(
            _pack_signed(self.quantized_candidate_entries, self.plan.input_bits)
        )
        digest.update(
            _pack_unsigned(
                _clip_telemetry_values(self.negative_clips, self.positive_clips),
                CLIP_COUNTER_BITS,
            )
        )
        return digest.hexdigest()

    def reconstruct(self) -> tuple[float, ...]:
        return tuple(
            value * self.plan.slot_scales[candidate_id & 0xF]
            for candidate_id, value in enumerate(self.quantized_candidate_entries)
        )

    def freeze_ranking(self) -> FrozenRanking:
        return FrozenRanking.from_scores(
            self.reconstruct(),
            reference_field_sha256=self.plan.deployment_field_sha256,
        )

    def evaluate(
        self,
        reference_scores: Sequence[float],
        *,
        top_ks: Sequence[int] = (1, 8, 32),
    ) -> ApproximationEvaluation:
        reference = _score_field(reference_scores, "reference_scores")
        if score_field_sha256(reference) != self.plan.deployment_field_sha256:
            raise QuantizedSpectralError("reference field differs from deployment hash")
        return evaluate_approximation(reference, self.reconstruct(), top_ks=top_ks)

    def describe(self) -> dict[str, object]:
        return {
            "schema": DICTIONARY_SCHEMA,
            "control_family": DICTIONARY_FAMILY,
            "plan_sha256": self.plan.plan_sha256,
            "state_sha256": self.state_sha256,
            "quantized_candidate_entries": DIRECT12_SIZE,
            "serialized_candidate_table_bytes": self.serialized_candidate_table_bytes,
            "serialized_clip_telemetry_bytes": self.serialized_clip_telemetry_bytes,
            "serialized_control_state_bytes": self.serialized_control_state_bytes,
            "retained_candidate_rows": DIRECT12_SIZE,
            "retained_key_value_entries": DIRECT12_SIZE,
            "mechanism_claim_eligible": False,
            "reason": "direct candidate-indexed value table",
            "target_labels_used": 0,
        }


def dictionary_ceiling(
    plan: QuantizedSpectralPlan, scores: Sequence[float]
) -> DictionaryCeiling:
    """Build the explicit direct-table ceiling from a plan-bound score field."""

    if not isinstance(plan, QuantizedSpectralPlan):
        raise TypeError("plan must be a QuantizedSpectralPlan")
    field = _score_field(scores)
    if score_field_sha256(field) != plan.deployment_field_sha256:
        raise QuantizedSpectralError("score field differs from deployment hash")
    entries: list[int] = []
    negative = [0] * LOW4_SLOT_COUNT
    positive = [0] * LOW4_SLOT_COUNT
    for candidate_id, score in enumerate(field):
        low4 = candidate_id & 0xF
        quantized, clip = _quantize(
            score, plan.slot_scales[low4], plan.quantizer_max
        )
        entries.append(quantized)
        if clip < 0:
            negative[low4] += 1
        elif clip > 0:
            positive[low4] += 1
    return DictionaryCeiling(
        plan=plan,
        quantized_candidate_entries=tuple(entries),
        negative_clips=tuple(negative),
        positive_clips=tuple(positive),
    )
