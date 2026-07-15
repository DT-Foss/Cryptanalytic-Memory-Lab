"""Sixteen-slot bounded Walsh memory for the 12-bit Direct12 address space.

Direct12 addresses are canonically written as ``(high8 << 4) | low4``.  This
module treats ``low4`` as one of sixteen independently accumulated slots and
``high8`` as the 256-address Walsh domain inside that slot.  A deployment pass
therefore keeps ``16 * K`` spectral scalars for a K-mask policy; it never keeps
candidate rows, a candidate-indexed table, a KV cache, or the stream transcript.

The three learned policies are deliberately target-label-free.  Each source
field contributes unit *non-constant* Walsh energy before fields are averaged,
so a high-amplitude field cannot dominate merely because of its scale.  The DC
character is excluded.  A separate, explicitly named 256-mask full-basis
ceiling exists only to test exact reconstruction and includes DC.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .walsh_memory import (
    FrozenRanking,
    FrozenWalshField,
    WalshMemoryError,
    WalshPlan,
    WalshScoreMemory,
    full_walsh_coefficients,
    score_field_sha256,
)


DIRECT12_BITS = 12
DIRECT12_SIZE = 1 << DIRECT12_BITS
SLOT_BITS = 4
SLOT_COUNT = 1 << SLOT_BITS
WITHIN_SLOT_BITS = DIRECT12_BITS - SLOT_BITS
SLOT_SIZE = 1 << WITHIN_SLOT_BITS

MASK_POLICY_SCHEMA = "o1-multislot-walsh-mask-policy-v1"
MULTISLOT_PLAN_SCHEMA = "o1-multislot-walsh-plan-v1"
MULTISLOT_FROZEN_FIELD_SCHEMA = "o1-multislot-walsh-frozen-field-v1"
ADDRESS_MAPPING = "direct12=(high8<<4)|low4;slot=low4;slot_address=high8"
ENERGY_NORMALIZATION = (
    "per-source non-DC Walsh squared energy normalized to one; "
    "arithmetic mean across source fields"
)
ENERGY_TIE_POLICY = "average-normalized-energy-descending-mask-ascending"

UNIVERSAL_TRAIN_FAMILY = "universal-train-average-energy-v1"
POOLED_TRAIN_CALIBRATION_FAMILY = (
    "pooled-train-plus-16-calibration-slots-average-energy-v1"
)
CALIBRATION_ONLY_FAMILY = "calibration-only-16-slots-average-energy-v1"
FULL_BASIS_FAMILY = "full-basis-256-mask-ceiling-v1"


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WalshMemoryError("value is not canonical finite JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise WalshMemoryError(f"{field} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise WalshMemoryError(f"{field} must be a lowercase SHA-256") from exc
    return value


def _finite(value: object, field: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise WalshMemoryError(f"{field} must be a finite number") from exc
    if not math.isfinite(result):
        raise WalshMemoryError(f"{field} must be a finite number")
    return 0.0 if result == 0.0 else result


def _field(scores: Sequence[float], expected: int, field: str) -> tuple[float, ...]:
    try:
        count = len(scores)
    except TypeError as exc:
        raise WalshMemoryError(f"{field} must be a sized sequence") from exc
    if count != expected:
        raise WalshMemoryError(f"{field} must contain exactly {expected} scores")
    return tuple(_finite(value, f"{field}[{index}]") for index, value in enumerate(scores))


def _canonical_masks(masks: Iterable[int], *, include_dc: bool) -> tuple[int, ...]:
    try:
        values = tuple(masks)
    except TypeError as exc:
        raise WalshMemoryError("masks must be iterable") from exc
    if not values:
        raise WalshMemoryError("at least one Walsh mask is required")
    lower = 0 if include_dc else 1
    if any(
        not isinstance(mask, int)
        or isinstance(mask, bool)
        or not lower <= mask < SLOT_SIZE
        for mask in values
    ):
        qualifier = "[0, 255]" if include_dc else "[1, 255] with DC excluded"
        raise WalshMemoryError(f"each slot mask must be an integer in {qualifier}")
    if len(set(values)) != len(values):
        raise WalshMemoryError("slot Walsh masks must be unique")
    return tuple(sorted(values, key=lambda mask: (mask.bit_count(), mask)))


def split_direct12_address(direct12_address: int) -> tuple[int, int]:
    """Return ``(low4_slot, high8_slot_address)`` for one Direct12 address."""

    if (
        not isinstance(direct12_address, int)
        or isinstance(direct12_address, bool)
        or not 0 <= direct12_address < DIRECT12_SIZE
    ):
        raise WalshMemoryError("Direct12 address must be an integer in [0, 4095]")
    return direct12_address & (SLOT_COUNT - 1), direct12_address >> SLOT_BITS


def join_direct12_address(slot: int, slot_address: int) -> int:
    """Inverse of :func:`split_direct12_address`."""

    if (
        not isinstance(slot, int)
        or isinstance(slot, bool)
        or not 0 <= slot < SLOT_COUNT
    ):
        raise WalshMemoryError("slot must be an integer in [0, 15]")
    if (
        not isinstance(slot_address, int)
        or isinstance(slot_address, bool)
        or not 0 <= slot_address < SLOT_SIZE
    ):
        raise WalshMemoryError("slot_address must be an integer in [0, 255]")
    return (slot_address << SLOT_BITS) | slot


def split_direct12_field(scores: Sequence[float]) -> tuple[tuple[float, ...], ...]:
    """Split a 4096-field into low4-major slots containing high8-major scores."""

    field = _field(scores, DIRECT12_SIZE, "Direct12 score field")
    return tuple(
        tuple(field[join_direct12_address(slot, high8)] for high8 in range(SLOT_SIZE))
        for slot in range(SLOT_COUNT)
    )


def join_direct12_slots(
    slots: Sequence[Sequence[float]],
) -> tuple[float, ...]:
    """Join exactly sixteen high8 fields using the canonical Direct12 mapping."""

    try:
        count = len(slots)
    except TypeError as exc:
        raise WalshMemoryError("slots must be a sized sequence") from exc
    if count != SLOT_COUNT:
        raise WalshMemoryError("slots must contain exactly 16 fields")
    canonical = tuple(
        _field(slot, SLOT_SIZE, f"slots[{index}]") for index, slot in enumerate(slots)
    )
    result = [0.0] * DIRECT12_SIZE
    for slot, values in enumerate(canonical):
        for high8, value in enumerate(values):
            result[join_direct12_address(slot, high8)] = value
    return tuple(result)


def _calibration_slots(
    calibration: Sequence[float] | Sequence[Sequence[float]],
) -> tuple[tuple[tuple[float, ...], ...], str]:
    """Accept a full Direct12 field or sixteen already split calibration slots."""

    try:
        count = len(calibration)
    except TypeError as exc:
        raise WalshMemoryError("calibration must be a sized sequence") from exc
    if count == DIRECT12_SIZE:
        # The explicit cast only resolves the static union; _field validates values.
        full = _field(calibration, DIRECT12_SIZE, "calibration field")  # type: ignore[arg-type]
        return split_direct12_field(full), score_field_sha256(full)
    if count == SLOT_COUNT:
        try:
            slots = tuple(
                _field(slot, SLOT_SIZE, f"calibration slots[{index}]")
                for index, slot in enumerate(calibration)  # type: ignore[assignment]
            )
        except TypeError as exc:
            raise WalshMemoryError(
                "calibration must be a 4096-field or sixteen 256-fields"
            ) from exc
        full = join_direct12_slots(slots)
        return slots, score_field_sha256(full)
    raise WalshMemoryError(
        "calibration must be a 4096-field or sixteen 256-fields"
    )


def _train_fields(fields: Iterable[Sequence[float]]) -> tuple[tuple[float, ...], ...]:
    try:
        materialized = tuple(
            _field(field, SLOT_SIZE, f"TRAIN fields[{index}]")
            for index, field in enumerate(fields)
        )
    except TypeError as exc:
        raise WalshMemoryError("TRAIN fields must be iterable 256-score fields") from exc
    if not materialized:
        raise WalshMemoryError("at least one TRAIN field is required")
    # Canonical source order makes both floating reduction and policy hashes
    # invariant to the caller's iterable order.  Duplicate fields remain duplicate
    # observations and therefore retain their explicitly supplied weight.
    return tuple(sorted(materialized, key=lambda field: (score_field_sha256(field), field)))


def _normalized_non_dc_energy(field: Sequence[float]) -> tuple[float, ...]:
    coefficients = full_walsh_coefficients(field)
    energy = math.fsum(value * value for value in coefficients[1:])
    if not math.isfinite(energy) or energy <= 0.0:
        raise WalshMemoryError(
            "each policy source field must have positive finite non-DC Walsh energy"
        )
    values = [0.0]
    values.extend((value * value) / energy for value in coefficients[1:])
    return tuple(values)


def _average_normalized_energy(
    fields: Sequence[Sequence[float]],
) -> tuple[float, ...]:
    if not fields:
        raise WalshMemoryError("at least one policy source field is required")
    normalized = tuple(_normalized_non_dc_energy(field) for field in fields)
    divisor = float(len(normalized))
    result = tuple(
        0.0
        if mask == 0
        else math.fsum(field_energy[mask] for field_energy in normalized) / divisor
        for mask in range(SLOT_SIZE)
    )
    if any(not math.isfinite(value) or value < 0.0 for value in result):
        raise WalshMemoryError("average normalized Walsh energy is invalid")
    return result


def _select_energy_masks(energies: Sequence[float], budget: int) -> tuple[int, ...]:
    if (
        not isinstance(budget, int)
        or isinstance(budget, bool)
        or not 1 <= budget < SLOT_SIZE
    ):
        raise WalshMemoryError("learned mask budget must be an integer in [1, 255]")
    ranked = sorted(range(1, SLOT_SIZE), key=lambda mask: (-energies[mask], mask))
    return _canonical_masks(ranked[:budget], include_dc=False)


@dataclass(frozen=True)
class MultiSlotWalshMaskPolicy:
    """Frozen target-blind mask policy shared by all sixteen slot memories."""

    family: str
    masks: tuple[int, ...]
    average_normalized_energy: tuple[float, ...]
    train_field_sha256s: tuple[str, ...] = ()
    calibration_slot_sha256s: tuple[str, ...] = ()
    calibration_field_sha256: str | None = None

    def __post_init__(self) -> None:
        learned_families = {
            UNIVERSAL_TRAIN_FAMILY,
            POOLED_TRAIN_CALIBRATION_FAMILY,
            CALIBRATION_ONLY_FAMILY,
        }
        if self.family not in learned_families | {FULL_BASIS_FAMILY}:
            raise WalshMemoryError("unknown multi-slot mask-policy family")
        ceiling = self.family == FULL_BASIS_FAMILY
        masks = _canonical_masks(self.masks, include_dc=ceiling)
        if ceiling and masks != tuple(sorted(range(SLOT_SIZE), key=lambda m: (m.bit_count(), m))):
            raise WalshMemoryError("full-basis ceiling must contain all 256 slot masks")
        if not ceiling and 0 in masks:
            raise WalshMemoryError("learned policies must exclude the DC mask")

        try:
            energies = tuple(
                _finite(value, f"average_normalized_energy[{index}]")
                for index, value in enumerate(self.average_normalized_energy)
            )
        except TypeError as exc:
            raise WalshMemoryError("average_normalized_energy must be iterable") from exc
        if len(energies) != SLOT_SIZE or any(value < 0.0 for value in energies):
            raise WalshMemoryError(
                "average_normalized_energy must contain 256 non-negative values"
            )
        if energies[0] != 0.0:
            raise WalshMemoryError("DC energy must be zero in a mask-policy record")

        train_hashes = tuple(
            _sha256(value, f"train_field_sha256s[{index}]")
            for index, value in enumerate(self.train_field_sha256s)
        )
        calibration_hashes = tuple(
            _sha256(value, f"calibration_slot_sha256s[{index}]")
            for index, value in enumerate(self.calibration_slot_sha256s)
        )
        calibration_field_hash = (
            None
            if self.calibration_field_sha256 is None
            else _sha256(self.calibration_field_sha256, "calibration_field_sha256")
        )

        if ceiling:
            if (
                train_hashes
                or calibration_hashes
                or calibration_field_hash is not None
                or any(energies)
            ):
                raise WalshMemoryError("full-basis ceiling cannot claim learned sources")
        else:
            expected = _select_energy_masks(energies, len(masks))
            if masks != expected:
                raise WalshMemoryError(
                    "policy masks do not match deterministic average-energy selection"
                )
            if self.family == UNIVERSAL_TRAIN_FAMILY:
                if not train_hashes or calibration_hashes or calibration_field_hash is not None:
                    raise WalshMemoryError("universal policy requires only TRAIN sources")
            elif self.family == POOLED_TRAIN_CALIBRATION_FAMILY:
                if (
                    not train_hashes
                    or len(calibration_hashes) != SLOT_COUNT
                    or calibration_field_hash is None
                ):
                    raise WalshMemoryError(
                        "pooled policy requires TRAIN sources and 16 calibration slots"
                    )
            elif self.family == CALIBRATION_ONLY_FAMILY:
                if (
                    train_hashes
                    or len(calibration_hashes) != SLOT_COUNT
                    or calibration_field_hash is None
                ):
                    raise WalshMemoryError(
                        "calibration-only policy requires exactly 16 calibration slots"
                    )

        object.__setattr__(self, "masks", masks)
        object.__setattr__(self, "average_normalized_energy", energies)
        object.__setattr__(self, "train_field_sha256s", train_hashes)
        object.__setattr__(self, "calibration_slot_sha256s", calibration_hashes)
        object.__setattr__(self, "calibration_field_sha256", calibration_field_hash)

    @property
    def budget(self) -> int:
        return len(self.masks)

    @property
    def includes_dc(self) -> bool:
        return 0 in self.masks

    @property
    def source_field_count(self) -> int:
        return len(self.train_field_sha256s) + len(self.calibration_slot_sha256s)

    @property
    def source_hash_count(self) -> int:
        return self.source_field_count + int(self.calibration_field_sha256 is not None)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": MASK_POLICY_SCHEMA,
            "family": self.family,
            "slot_address_bits": WITHIN_SLOT_BITS,
            "slot_domain_size": SLOT_SIZE,
            "budget_per_slot": self.budget,
            "masks": list(self.masks),
            "includes_dc": self.includes_dc,
            "normalization": (
                "not-applicable-full-basis-ceiling"
                if self.family == FULL_BASIS_FAMILY
                else ENERGY_NORMALIZATION
            ),
            "tie_policy": ENERGY_TIE_POLICY,
            "average_normalized_energy": list(self.average_normalized_energy),
            "sources": {
                "train_field_sha256s": list(self.train_field_sha256s),
                "calibration_slot_sha256s": list(self.calibration_slot_sha256s),
                "calibration_field_sha256": self.calibration_field_sha256,
                "source_field_count": self.source_field_count,
            },
            "target_labels_used": 0,
        }

    @property
    def policy_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        result = self._payload()
        result["policy_sha256"] = self.policy_sha256
        return result

    def to_json(self) -> str:
        return json.dumps(
            self.describe(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "MultiSlotWalshMaskPolicy":
        if not isinstance(value, Mapping):
            raise WalshMemoryError("serialized mask policy must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("policy_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(supplied):
            raise WalshMemoryError("serialized mask-policy canonical SHA-256 mismatch")
        try:
            sources = supplied["sources"]
            policy = cls(
                family=str(supplied["family"]),
                masks=tuple(int(mask) for mask in supplied["masks"]),
                average_normalized_energy=tuple(
                    float(item) for item in supplied["average_normalized_energy"]
                ),
                train_field_sha256s=tuple(sources["train_field_sha256s"]),
                calibration_slot_sha256s=tuple(
                    sources["calibration_slot_sha256s"]
                ),
                calibration_field_sha256=sources["calibration_field_sha256"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WalshMemoryError("invalid serialized multi-slot mask policy") from exc
        if policy._payload() != supplied or policy.policy_sha256 != supplied_hash:
            raise WalshMemoryError("serialized mask policy contains non-canonical metadata")
        return policy

    @classmethod
    def universal_train(
        cls, train_fields: Iterable[Sequence[float]], *, budget: int
    ) -> "MultiSlotWalshMaskPolicy":
        fields = _train_fields(train_fields)
        energies = _average_normalized_energy(fields)
        return cls(
            family=UNIVERSAL_TRAIN_FAMILY,
            masks=_select_energy_masks(energies, budget),
            average_normalized_energy=energies,
            train_field_sha256s=tuple(score_field_sha256(field) for field in fields),
        )

    @classmethod
    def pooled_train_calibration(
        cls,
        train_fields: Iterable[Sequence[float]],
        calibration: Sequence[float] | Sequence[Sequence[float]],
        *,
        budget: int,
    ) -> "MultiSlotWalshMaskPolicy":
        train = _train_fields(train_fields)
        calibration_slots, calibration_hash = _calibration_slots(calibration)
        sources = train + calibration_slots
        energies = _average_normalized_energy(sources)
        return cls(
            family=POOLED_TRAIN_CALIBRATION_FAMILY,
            masks=_select_energy_masks(energies, budget),
            average_normalized_energy=energies,
            train_field_sha256s=tuple(score_field_sha256(field) for field in train),
            calibration_slot_sha256s=tuple(
                score_field_sha256(field) for field in calibration_slots
            ),
            calibration_field_sha256=calibration_hash,
        )

    @classmethod
    def calibration_only(
        cls,
        calibration: Sequence[float] | Sequence[Sequence[float]],
        *,
        budget: int,
    ) -> "MultiSlotWalshMaskPolicy":
        calibration_slots, calibration_hash = _calibration_slots(calibration)
        energies = _average_normalized_energy(calibration_slots)
        return cls(
            family=CALIBRATION_ONLY_FAMILY,
            masks=_select_energy_masks(energies, budget),
            average_normalized_energy=energies,
            calibration_slot_sha256s=tuple(
                score_field_sha256(field) for field in calibration_slots
            ),
            calibration_field_sha256=calibration_hash,
        )

    @classmethod
    def full_basis_ceiling(cls) -> "MultiSlotWalshMaskPolicy":
        return cls(
            family=FULL_BASIS_FAMILY,
            masks=tuple(range(SLOT_SIZE)),
            average_normalized_energy=(0.0,) * SLOT_SIZE,
        )


def learn_universal_average_energy_policy(
    train_fields: Iterable[Sequence[float]], *, budget: int
) -> MultiSlotWalshMaskPolicy:
    return MultiSlotWalshMaskPolicy.universal_train(train_fields, budget=budget)


def learn_pooled_average_energy_policy(
    train_fields: Iterable[Sequence[float]],
    calibration: Sequence[float] | Sequence[Sequence[float]],
    *,
    budget: int,
) -> MultiSlotWalshMaskPolicy:
    return MultiSlotWalshMaskPolicy.pooled_train_calibration(
        train_fields, calibration, budget=budget
    )


def learn_calibration_only_average_energy_policy(
    calibration: Sequence[float] | Sequence[Sequence[float]], *, budget: int
) -> MultiSlotWalshMaskPolicy:
    return MultiSlotWalshMaskPolicy.calibration_only(calibration, budget=budget)


@dataclass(frozen=True)
class MultiSlotWalshPlan:
    """Sixteen executable slot plans bound to one deployment score field."""

    name: str
    mask_policy: MultiSlotWalshMaskPolicy
    deployment_field_sha256: str
    deployment_slot_sha256s: tuple[str, ...]
    slot_plans: tuple[WalshPlan, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise WalshMemoryError("multi-slot plan name is required")
        if not isinstance(self.mask_policy, MultiSlotWalshMaskPolicy):
            raise TypeError("mask_policy must be a MultiSlotWalshMaskPolicy")
        deployment_hash = _sha256(
            self.deployment_field_sha256, "deployment_field_sha256"
        )
        slot_hashes = tuple(
            _sha256(value, f"deployment_slot_sha256s[{index}]")
            for index, value in enumerate(self.deployment_slot_sha256s)
        )
        if len(slot_hashes) != SLOT_COUNT:
            raise WalshMemoryError("deployment must bind exactly 16 slot hashes")
        if len(self.slot_plans) != SLOT_COUNT or any(
            not isinstance(plan, WalshPlan) for plan in self.slot_plans
        ):
            raise WalshMemoryError("multi-slot plan requires exactly 16 WalshPlan objects")
        canonical_names = tuple(
            f"{self.name}/low4-slot-{slot:02d}" for slot in range(SLOT_COUNT)
        )
        for slot, plan in enumerate(self.slot_plans):
            if (
                plan.n_bits != WITHIN_SLOT_BITS
                or plan.masks != self.mask_policy.masks
                or plan.field_sha256 != slot_hashes[slot]
                or plan.name != canonical_names[slot]
                or plan.mask_family != self.mask_policy.family
                or plan.mask_source_field_sha256 != self.mask_policy.policy_sha256
            ):
                raise WalshMemoryError(
                    f"slot plan {slot} is not canonically bound to policy and deployment"
                )
        object.__setattr__(self, "deployment_field_sha256", deployment_hash)
        object.__setattr__(self, "deployment_slot_sha256s", slot_hashes)
        object.__setattr__(self, "slot_plans", tuple(self.slot_plans))

    @classmethod
    def for_deployment_field(
        cls,
        deployment_scores: Sequence[float],
        mask_policy: MultiSlotWalshMaskPolicy,
        *,
        name: str = "multislot-walsh-score-memory",
    ) -> "MultiSlotWalshPlan":
        if not isinstance(mask_policy, MultiSlotWalshMaskPolicy):
            raise TypeError("mask_policy must be a MultiSlotWalshMaskPolicy")
        full = _field(deployment_scores, DIRECT12_SIZE, "deployment score field")
        slots = split_direct12_field(full)
        slot_hashes = tuple(score_field_sha256(slot) for slot in slots)
        plans = tuple(
            WalshPlan.for_field(
                slot,
                masks=mask_policy.masks,
                name=f"{name}/low4-slot-{slot_index:02d}",
                mask_family=mask_policy.family,
                mask_source_field_sha256=mask_policy.policy_sha256,
            )
            for slot_index, slot in enumerate(slots)
        )
        return cls(
            name=name,
            mask_policy=mask_policy,
            deployment_field_sha256=score_field_sha256(full),
            deployment_slot_sha256s=slot_hashes,
            slot_plans=plans,
        )

    @property
    def masks_per_slot(self) -> int:
        return self.mask_policy.budget

    @property
    def spectral_state_scalars(self) -> int:
        return sum(plan.state_scalars for plan in self.slot_plans)

    @property
    def integrity_state_scalars(self) -> int:
        return sum(plan.integrity_state_scalars for plan in self.slot_plans)

    @property
    def online_state_scalars(self) -> int:
        return self.spectral_state_scalars + self.integrity_state_scalars

    @property
    def serialized_spectral_state_bytes(self) -> int:
        return sum(plan.serialized_state_bytes for plan in self.slot_plans)

    @property
    def serialized_integrity_state_bytes(self) -> int:
        return sum(plan.serialized_integrity_bytes for plan in self.slot_plans)

    @property
    def serialized_online_state_bytes(self) -> int:
        return sum(plan.serialized_online_state_bytes for plan in self.slot_plans)

    @property
    def logical_slot_mask_bank_bytes(self) -> int:
        return sum(plan.serialized_mask_bank_bytes for plan in self.slot_plans)

    @property
    def shared_mask_bank_bytes(self) -> int:
        return 2 * self.masks_per_slot

    @property
    def slot_bound_hash_bytes(self) -> int:
        return sum(plan.serialized_bound_hash_bytes for plan in self.slot_plans)

    @property
    def policy_source_hash_bytes(self) -> int:
        return 32 * self.mask_policy.source_hash_count

    @property
    def policy_energy_table_bytes(self) -> int:
        # The full table is committed even for the ceiling, where it is all zero.
        return 8 * SLOT_SIZE

    @property
    def serialized_static_plan_bytes_without_json_overhead(self) -> int:
        """Conservative logical storage; shared-mask deduplication is not assumed."""

        return (
            self.logical_slot_mask_bank_bytes
            + self.slot_bound_hash_bytes
            + self.policy_source_hash_bytes
            + self.policy_energy_table_bytes
            + 64  # policy and multi-slot plan commitments
        )

    @property
    def matched_single_bank_spectral_scalars(self) -> int:
        """Global 12-bit K having the same number of learned state scalars."""

        return self.spectral_state_scalars

    def _payload(self) -> dict[str, object]:
        k = self.masks_per_slot
        return {
            "schema": MULTISLOT_PLAN_SCHEMA,
            "name": self.name,
            "address_mapping": ADDRESS_MAPPING,
            "direct12_domain_size": DIRECT12_SIZE,
            "slot_count": SLOT_COUNT,
            "slot_domain_size": SLOT_SIZE,
            "deployment_field_sha256": self.deployment_field_sha256,
            "deployment_slot_sha256s": list(self.deployment_slot_sha256s),
            "mask_policy": self.mask_policy.describe(),
            "slot_plans": [plan.describe() for plan in self.slot_plans],
            "state": {
                "masks_per_slot": k,
                "spectral_scalars": self.spectral_state_scalars,
                "integrity_scalars": self.integrity_state_scalars,
                "integrity_breakdown": "16 slots x 5 address/hash-bound accounting scalars",
                "precision_bits_per_scalar": 64,
                "serialized_spectral_bytes": self.serialized_spectral_state_bytes,
                "serialized_integrity_bytes": self.serialized_integrity_state_bytes,
                "serialized_online_state_bytes": self.serialized_online_state_bytes,
                "matched_single_12bit_bank_spectral_scalars": (
                    self.matched_single_bank_spectral_scalars
                ),
                "stream_length_dependent_state": False,
                "retained_candidate_rows": 0,
                "retained_key_value_entries": 0,
            },
            "static_plan_storage": {
                "logical_slot_mask_entries": SLOT_COUNT * k,
                "logical_slot_mask_bank_bytes": self.logical_slot_mask_bank_bytes,
                "shared_mask_entries_if_deduplicated": k,
                "shared_mask_bank_bytes_if_deduplicated": self.shared_mask_bank_bytes,
                "slot_bound_hash_bytes": self.slot_bound_hash_bytes,
                "policy_source_hash_bytes": self.policy_source_hash_bytes,
                "policy_energy_table_bytes": self.policy_energy_table_bytes,
                "serialized_bytes_without_json_or_names_conservative": (
                    self.serialized_static_plan_bytes_without_json_overhead
                ),
                "counted_as_online_recurrent_state": False,
            },
            "work": {
                "update_character_evaluations_per_observation": k,
                "update_accumulations_per_observation": k,
                "full_direct12_pass_character_evaluations": DIRECT12_SIZE * k,
                "full_direct12_pass_accumulations": DIRECT12_SIZE * k,
                "query_character_evaluations": k,
                "query_accumulations": k,
                "full_reconstruction_zero_fill": DIRECT12_SIZE,
                "full_reconstruction_fwht_butterflies": (
                    SLOT_COUNT * WITHIN_SLOT_BITS * SLOT_SIZE // 2
                ),
                "ranking_items": DIRECT12_SIZE,
            },
            "target_labels_used": 0,
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
    def from_dict(cls, value: Mapping[str, object]) -> "MultiSlotWalshPlan":
        if not isinstance(value, Mapping):
            raise WalshMemoryError("serialized multi-slot plan must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("plan_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(supplied):
            raise WalshMemoryError("serialized multi-slot plan canonical SHA-256 mismatch")
        try:
            plan = cls(
                name=str(supplied["name"]),
                mask_policy=MultiSlotWalshMaskPolicy.from_dict(supplied["mask_policy"]),
                deployment_field_sha256=str(supplied["deployment_field_sha256"]),
                deployment_slot_sha256s=tuple(supplied["deployment_slot_sha256s"]),
                slot_plans=tuple(WalshPlan.from_dict(item) for item in supplied["slot_plans"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WalshMemoryError("invalid serialized multi-slot plan") from exc
        if plan._payload() != supplied or plan.plan_sha256 != supplied_hash:
            raise WalshMemoryError("serialized multi-slot plan contains non-canonical metadata")
        return plan


@dataclass(frozen=True)
class FrozenMultiSlotWalshField:
    """Finalized sixteen-slot spectral state with target-blind reconstruction."""

    plan: MultiSlotWalshPlan
    slot_fields: tuple[FrozenWalshField, ...]
    input_field_hash_verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.plan, MultiSlotWalshPlan):
            raise TypeError("plan must be a MultiSlotWalshPlan")
        if len(self.slot_fields) != SLOT_COUNT:
            raise WalshMemoryError("frozen multi-slot field requires exactly 16 slots")
        passes: set[int] = set()
        for slot, field in enumerate(self.slot_fields):
            if not isinstance(field, FrozenWalshField) or field.plan != self.plan.slot_plans[slot]:
                raise WalshMemoryError(f"frozen slot {slot} disagrees with its executable plan")
            passes.add(field.completed_passes)
        if len(passes) != 1:
            raise WalshMemoryError("all slots must contain the same number of complete passes")
        if not isinstance(self.input_field_hash_verified, bool):
            raise WalshMemoryError("input_field_hash_verified must be boolean")
        object.__setattr__(self, "slot_fields", tuple(self.slot_fields))

    @property
    def completed_passes(self) -> int:
        return self.slot_fields[0].completed_passes

    @property
    def observations(self) -> int:
        return sum(field.observations for field in self.slot_fields)

    @property
    def state_scalars(self) -> int:
        return sum(field.state_scalars for field in self.slot_fields)

    def query(self, direct12_address: int) -> float:
        slot, high8 = split_direct12_address(direct12_address)
        return self.slot_fields[slot].query(high8)

    def reconstruct_slots(self) -> tuple[tuple[float, ...], ...]:
        return tuple(field.reconstruct() for field in self.slot_fields)

    def reconstruct(self) -> tuple[float, ...]:
        return join_direct12_slots(self.reconstruct_slots())

    def freeze_ranking(self) -> FrozenRanking:
        return FrozenRanking.from_scores(
            self.reconstruct(),
            reference_field_sha256=self.plan.deployment_field_sha256,
        )

    def describe(self) -> dict[str, object]:
        ranking = self.freeze_ranking()
        return {
            "schema": MULTISLOT_FROZEN_FIELD_SCHEMA,
            "plan_sha256": self.plan.plan_sha256,
            "completed_passes": self.completed_passes,
            "observations": self.observations,
            "spectral_state_scalars": self.state_scalars,
            "reconstructed_field_sha256": ranking.score_field_sha256,
            "reference_field_sha256": self.plan.deployment_field_sha256,
            "frozen_order_sha256": ranking.order_sha256,
            "input_field_hash_verified": self.input_field_hash_verified,
            "mechanism_claim_eligible": self.input_field_hash_verified,
            "target_labels_used": 0,
        }


class MultiSlotWalshMemory:
    """Route a Direct12 score stream into sixteen fixed-width Walsh memories."""

    def __init__(self, plan: MultiSlotWalshPlan) -> None:
        if not isinstance(plan, MultiSlotWalshPlan):
            raise TypeError("plan must be a MultiSlotWalshPlan")
        self.plan = plan
        self._slots = [WalshScoreMemory(slot_plan) for slot_plan in plan.slot_plans]
        self._finalized: FrozenMultiSlotWalshField | None = None
        self._bound_field_passes = 0

    @property
    def observations(self) -> int:
        return sum(memory.observations for memory in self._slots)

    @property
    def state_scalars(self) -> int:
        return self.plan.spectral_state_scalars

    @property
    def integrity_state_scalars(self) -> int:
        return self.plan.integrity_state_scalars

    @property
    def serialized_online_state_bytes(self) -> int:
        return self.plan.serialized_online_state_bytes

    @property
    def retained_rows(self) -> int:
        return 0

    @property
    def retained_candidate_rows(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

    @property
    def bound_field_passes(self) -> int:
        """Passes supplied through the exact hash-checking ``observe_field`` API."""

        return self._bound_field_passes

    def observe(self, direct12_address: int, score: float) -> None:
        if self._finalized is not None:
            raise WalshMemoryError("cannot update a finalized multi-slot Walsh memory")
        slot, high8 = split_direct12_address(direct12_address)
        value = _finite(score, "score")
        self._slots[slot].observe(high8, value)

    def observe_field(
        self,
        scores: Sequence[float],
        *,
        address_order: Sequence[int] | None = None,
    ) -> None:
        """Stream one hash-bound complete Direct12 field in any permutation."""

        if self._finalized is not None:
            raise WalshMemoryError("cannot update a finalized multi-slot Walsh memory")
        field = _field(scores, DIRECT12_SIZE, "Direct12 score field")
        if score_field_sha256(field) != self.plan.deployment_field_sha256:
            raise WalshMemoryError("score field does not match deployment field hash")
        if address_order is None:
            order = tuple(range(DIRECT12_SIZE))
        else:
            try:
                order = tuple(address_order)
            except TypeError as exc:
                raise WalshMemoryError("address_order must be iterable") from exc
            if len(order) != DIRECT12_SIZE or set(order) != set(range(DIRECT12_SIZE)):
                raise WalshMemoryError(
                    "address_order must be a permutation of the complete Direct12 domain"
                )
        # All fallible validation is complete before persistent state changes.
        for address in order:
            self.observe(address, field[address])
        self._bound_field_passes += 1

    def finalize(self) -> FrozenMultiSlotWalshField:
        if self._finalized is not None:
            return self._finalized
        # Preflight every slot before the underlying finalizers release their mutable
        # K-wide accumulators.  This keeps a failed coverage check non-destructive.
        passes = tuple(memory._validate_complete_passes() for memory in self._slots)
        if len(set(passes)) != 1:
            raise WalshMemoryError(
                "all 16 slots require the same number of complete uniform passes"
            )
        self._finalized = FrozenMultiSlotWalshField(
            plan=self.plan,
            slot_fields=tuple(memory.finalize() for memory in self._slots),
            input_field_hash_verified=self._bound_field_passes == passes[0],
        )
        return self._finalized


__all__ = [
    "ADDRESS_MAPPING",
    "CALIBRATION_ONLY_FAMILY",
    "DIRECT12_BITS",
    "DIRECT12_SIZE",
    "ENERGY_NORMALIZATION",
    "ENERGY_TIE_POLICY",
    "FULL_BASIS_FAMILY",
    "FrozenMultiSlotWalshField",
    "MultiSlotWalshMaskPolicy",
    "MultiSlotWalshMemory",
    "MultiSlotWalshPlan",
    "POOLED_TRAIN_CALIBRATION_FAMILY",
    "SLOT_BITS",
    "SLOT_COUNT",
    "SLOT_SIZE",
    "UNIVERSAL_TRAIN_FAMILY",
    "WITHIN_SLOT_BITS",
    "join_direct12_address",
    "join_direct12_slots",
    "learn_calibration_only_average_energy_policy",
    "learn_pooled_average_energy_policy",
    "learn_universal_average_energy_policy",
    "split_direct12_address",
    "split_direct12_field",
]
