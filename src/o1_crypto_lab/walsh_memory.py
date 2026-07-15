"""Bounded Walsh-character memory for candidate score fields.

The accumulator retains one scalar for each selected Walsh mask, independent of
the number of streamed observations.  It never retains candidate rows, a key/value
table, or a stream transcript.  Limited banks are deliberately honest projections;
only the full ``2**n``-mask bank is an exact reconstruction ceiling.

The commonly discussed budgets mix two different address widths.  In particular,
12 and 78 are the non-constant degree-1 and degree-<=2 counts for ``n=12``, while
218 and 246 are the non-constant degree-<=5 and degree-<=6 counts for ``n=8``.
``fixed_budget_masks`` therefore labels incomplete degree shells as low-degree
prefixes instead of silently calling (for example) a 218-mask, 12-bit bank
"degree <= 5".
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence


PLAN_SCHEMA = "o1-walsh-score-memory-plan-v1"
RANKING_SCHEMA = "o1-walsh-frozen-ranking-v1"
EVALUATION_SCHEMA = "o1-walsh-approximation-evaluation-v1"
TARGET_EVALUATION_SCHEMA = "o1-walsh-target-rank-evaluation-v1"
FIELD_HASH_SCHEMA = b"o1-walsh-score-field-float64be-v1\x00"
TIE_POLICY = "score-descending-address-ascending"
FIXED_BUDGETS = (12, 78, 218, 246, 256, 512)
MAX_ADDRESS_BITS = 16  # uint16be is the frozen-order wire format.


class WalshMemoryError(ValueError):
    """Raised when a Walsh plan, stream, or evaluation is invalid."""


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WalshMemoryError("value is not canonical finite JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_n_bits(n_bits: int) -> int:
    if (
        not isinstance(n_bits, int)
        or isinstance(n_bits, bool)
        or not 1 <= n_bits <= MAX_ADDRESS_BITS
    ):
        raise WalshMemoryError(
            f"n_bits must be an integer in [1, {MAX_ADDRESS_BITS}]"
        )
    return n_bits


def _finite(value: float, field: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise WalshMemoryError(f"{field} must be a finite number") from exc
    if not math.isfinite(result):
        raise WalshMemoryError(f"{field} must be a finite number")
    # Make hashes and tie handling insensitive to IEEE negative zero.
    return 0.0 if result == 0.0 else result


def _field_tuple(scores: Sequence[float]) -> tuple[float, ...]:
    try:
        count = len(scores)
    except TypeError as exc:
        raise WalshMemoryError("score field must be a sized sequence") from exc
    if count < 2 or count & (count - 1):
        raise WalshMemoryError("score field length must be a power of two >= 2")
    n_bits = count.bit_length() - 1
    _validate_n_bits(n_bits)
    return tuple(_finite(value, f"scores[{index}]") for index, value in enumerate(scores))


def score_field_sha256(scores: Sequence[float]) -> str:
    """Hash a complete field as canonical length-prefixed float64be values."""

    field = _field_tuple(scores)
    digest = hashlib.sha256()
    digest.update(FIELD_HASH_SCHEMA)
    digest.update(len(field).to_bytes(4, "big"))
    for value in field:
        digest.update(struct.pack(">d", value))
    return digest.hexdigest()


def walsh_character(mask: int, address: int, *, n_bits: int | None = None) -> int:
    """Return ``(-1)**popcount(mask & address)`` with strict address checks."""

    if not isinstance(mask, int) or isinstance(mask, bool) or mask < 0:
        raise WalshMemoryError("mask must be a non-negative integer")
    if not isinstance(address, int) or isinstance(address, bool) or address < 0:
        raise WalshMemoryError("address must be a non-negative integer")
    if n_bits is not None:
        domain_size = 1 << _validate_n_bits(n_bits)
        if mask >= domain_size or address >= domain_size:
            raise WalshMemoryError("mask and address must fit n_bits")
    return _walsh_character_unchecked(mask, address)


def _walsh_character_unchecked(mask: int, address: int) -> int:
    """Validated-call hot path used by the bounded stream and query loops."""

    return -1 if (mask & address).bit_count() & 1 else 1


def degree_masks(
    n_bits: int, max_degree: int, *, include_constant: bool = False
) -> tuple[int, ...]:
    """Return every mask through a degree, ordered by degree then integer value.

    The default excludes the DC/constant mask.  Thus ``degree_masks(12, 1)`` has
    12 masks, ``degree_masks(12, 2)`` has 78, ``degree_masks(8, 5)`` has 218,
    and ``degree_masks(8, 6)`` has 246.
    """

    n_bits = _validate_n_bits(n_bits)
    if (
        not isinstance(max_degree, int)
        or isinstance(max_degree, bool)
        or not 0 <= max_degree <= n_bits
    ):
        raise WalshMemoryError("max_degree must be an integer in [0, n_bits]")
    start = 0 if include_constant else 1
    return tuple(
        sorted(
            (
                mask
                for mask in range(start, 1 << n_bits)
                if mask.bit_count() <= max_degree
            ),
            key=lambda mask: (mask.bit_count(), mask),
        )
    )


def _canonical_masks(n_bits: int, masks: Iterable[int]) -> tuple[int, ...]:
    domain_size = 1 << _validate_n_bits(n_bits)
    try:
        materialized = tuple(masks)
    except TypeError as exc:
        raise WalshMemoryError("masks must be iterable") from exc
    if not materialized:
        raise WalshMemoryError("at least one Walsh mask is required")
    for mask in materialized:
        if (
            not isinstance(mask, int)
            or isinstance(mask, bool)
            or not 0 <= mask < domain_size
        ):
            raise WalshMemoryError("each mask must be an integer in the domain")
    if len(set(materialized)) != len(materialized):
        raise WalshMemoryError("Walsh masks must be unique")
    return tuple(sorted(materialized, key=lambda mask: (mask.bit_count(), mask)))


def fixed_budget_masks(n_bits: int, budget: int) -> tuple[int, ...]:
    """Select exactly ``budget`` deterministic low-degree characters.

    A full-domain budget returns every mask including DC.  Smaller budgets omit
    DC because a constant score shift cannot affect candidate ranking, then fill
    complete degree shells followed by the integer-ordered prefix of the next
    shell.  This makes the 12-bit K=218/246/256/512 cases mathematically explicit.
    """

    n_bits = _validate_n_bits(n_bits)
    domain_size = 1 << n_bits
    if (
        not isinstance(budget, int)
        or isinstance(budget, bool)
        or not 1 <= budget <= domain_size
    ):
        raise WalshMemoryError("budget must be an integer in [1, 2**n_bits]")
    if budget == domain_size:
        return tuple(range(domain_size))
    ordered_nonconstant = sorted(
        range(1, domain_size), key=lambda mask: (mask.bit_count(), mask)
    )
    return tuple(ordered_nonconstant[:budget])


def full_walsh_coefficients(scores: Sequence[float]) -> tuple[float, ...]:
    """Return the orthogonally normalized full Walsh-Hadamard transform.

    This is an offline calibration operation over a complete target-blind score
    field, not retained streaming state.  Coefficient ``m`` is exactly the
    projection ``sum_x score[x] * character(m, x) / N`` (up to float64 rounding).
    """

    field = _field_tuple(scores)
    values = list(field)
    width = 1
    while width < len(values):
        block = width * 2
        for start in range(0, len(values), block):
            for offset in range(width):
                left = values[start + offset]
                right = values[start + offset + width]
                values[start + offset] = left + right
                values[start + offset + width] = left - right
        width = block
    normalization = float(len(values))
    coefficients = tuple(value / normalization for value in values)
    if any(not math.isfinite(value) for value in coefficients):
        raise WalshMemoryError("Walsh transform overflowed finite float64")
    return coefficients


def energy_budget_masks(
    scores: Sequence[float], budget: int, *, include_constant: bool = False
) -> tuple[int, ...]:
    """Freeze the highest-energy masks from a complete label-free score field.

    Selection uses ``abs(orthogonal_coefficient)`` descending and numeric mask
    ascending as its deterministic tie-break.  The returned set is placed in the
    canonical degree/mask order expected by :class:`WalshPlan`; no target address
    or label is accepted anywhere in this API.
    """

    coefficients = full_walsh_coefficients(scores)
    start = 0 if include_constant else 1
    available = len(coefficients) - start
    if (
        not isinstance(budget, int)
        or isinstance(budget, bool)
        or not 1 <= budget <= available
    ):
        raise WalshMemoryError(
            "energy budget exceeds the eligible Walsh-mask population"
        )
    ranked = sorted(
        range(start, len(coefficients)),
        key=lambda mask: (-abs(coefficients[mask]), mask),
    )
    return tuple(
        sorted(ranked[:budget], key=lambda mask: (mask.bit_count(), mask))
    )


def _mask_selection(n_bits: int, masks: Sequence[int]) -> dict[str, object]:
    domain_size = 1 << n_bits
    selected = set(masks)
    histogram = {
        str(degree): sum(mask.bit_count() == degree for mask in masks)
        for degree in range(n_bits + 1)
        if any(mask.bit_count() == degree for mask in masks)
    }
    complete_nonconstant = 0
    partial_degree: int | None = None
    partial_count = 0
    for degree in range(1, n_bits + 1):
        shell = {mask for mask in range(1, domain_size) if mask.bit_count() == degree}
        chosen = len(shell & selected)
        if chosen == len(shell):
            complete_nonconstant = degree
            continue
        if chosen:
            partial_degree = degree
            partial_count = chosen
        break
    is_full = selected == set(range(domain_size))
    if is_full:
        family = "full-bank-ceiling"
    elif partial_degree is None and len(masks) == sum(
        math.comb(n_bits, degree) for degree in range(1, complete_nonconstant + 1)
    ):
        family = f"degree-le-{complete_nonconstant}-no-dc"
    elif selected == set(fixed_budget_masks(n_bits, len(masks))):
        family = f"low-degree-prefix-k{len(masks)}-no-dc"
    else:
        family = "arbitrary-explicit-mask-set"
    return {
        "family": family,
        "includes_constant_mask": 0 in selected,
        "is_full_bank_ceiling": is_full,
        "degree_histogram": histogram,
        "complete_nonconstant_through_degree": complete_nonconstant,
        "partial_degree": partial_degree,
        "partial_degree_count": partial_count,
    }


@dataclass(frozen=True)
class WalshPlan:
    """Frozen, canonical description of one bounded spectral projection."""

    n_bits: int
    masks: tuple[int, ...]
    field_sha256: str
    name: str = "walsh-score-memory"
    mask_family: str = "explicit"
    mask_source_field_sha256: str | None = None

    def __post_init__(self) -> None:
        n_bits = _validate_n_bits(self.n_bits)
        canonical_masks = _canonical_masks(n_bits, self.masks)
        if not isinstance(self.field_sha256, str) or len(self.field_sha256) != 64:
            raise WalshMemoryError("field_sha256 must be a lowercase SHA-256")
        try:
            int(self.field_sha256, 16)
        except ValueError as exc:
            raise WalshMemoryError("field_sha256 must be a lowercase SHA-256") from exc
        if self.field_sha256 != self.field_sha256.lower():
            raise WalshMemoryError("field_sha256 must be a lowercase SHA-256")
        if not isinstance(self.name, str) or not self.name.strip():
            raise WalshMemoryError("plan name is required")
        if not isinstance(self.mask_family, str) or not self.mask_family.strip():
            raise WalshMemoryError("mask_family is required")
        if self.mask_source_field_sha256 is not None:
            source_hash = self.mask_source_field_sha256
            if not isinstance(source_hash, str) or len(source_hash) != 64:
                raise WalshMemoryError(
                    "mask_source_field_sha256 must be a lowercase SHA-256"
                )
            try:
                int(source_hash, 16)
            except ValueError as exc:
                raise WalshMemoryError(
                    "mask_source_field_sha256 must be a lowercase SHA-256"
                ) from exc
            if source_hash != source_hash.lower():
                raise WalshMemoryError(
                    "mask_source_field_sha256 must be a lowercase SHA-256"
                )
        object.__setattr__(self, "masks", canonical_masks)

    @property
    def domain_size(self) -> int:
        return 1 << self.n_bits

    @property
    def state_scalars(self) -> int:
        return len(self.masks)

    @property
    def state_precision_bits(self) -> int:
        return 64

    @property
    def serialized_state_bytes(self) -> int:
        return 8 * self.state_scalars

    @property
    def integrity_state_scalars(self) -> int:
        """Fixed-width counters used to reject incomplete or duplicate covers."""

        return 5

    @property
    def serialized_integrity_bytes(self) -> int:
        return 8 * self.integrity_state_scalars

    @property
    def serialized_online_state_bytes(self) -> int:
        """Complete online recurrent state, including integrity accounting."""

        return self.serialized_state_bytes + self.serialized_integrity_bytes

    @property
    def serialized_mask_bank_bytes(self) -> int:
        """Static uint16 mask-bank storage, reported separately from state."""

        return 2 * self.state_scalars

    @property
    def serialized_bound_hash_bytes(self) -> int:
        return 32 * (1 + int(self.mask_source_field_sha256 is not None))

    @property
    def is_full_bank(self) -> bool:
        return len(self.masks) == self.domain_size and set(self.masks) == set(
            range(self.domain_size)
        )

    def _payload(self) -> dict[str, object]:
        k = self.state_scalars
        n = self.domain_size
        selection = _mask_selection(self.n_bits, self.masks)
        selection["structural_family"] = selection.pop("family")
        selection["family"] = self.mask_family
        selection["source_field_sha256"] = self.mask_source_field_sha256
        return {
            "schema": PLAN_SCHEMA,
            "name": self.name,
            "n_bits": self.n_bits,
            "domain_size": n,
            "field_sha256": self.field_sha256,
            "masks": list(self.masks),
            "mask_selection": selection,
            "normalization": "sum(score*character)/observation_count",
            "state": {
                "spectral_scalars": k,
                "integrity_scalars": self.integrity_state_scalars,
                "integrity_breakdown": (
                    "observation count, address sum, address square sum, address "
                    "xor, exact hash-bound observe_field pass count"
                ),
                "precision_bits_per_scalar": self.state_precision_bits,
                "dtype": "float64",
                "serialized_spectral_bytes": self.serialized_state_bytes,
                "serialized_integrity_bytes": self.serialized_integrity_bytes,
                "serialized_online_state_bytes": self.serialized_online_state_bytes,
                "stream_length_dependent_state": False,
                "retained_rows": 0,
                "retained_key_value_entries": 0,
            },
            "static_plan_storage": {
                "mask_entries": k,
                "mask_encoding": "uint16",
                "serialized_mask_bank_bytes": self.serialized_mask_bank_bytes,
                "serialized_bound_hash_bytes": self.serialized_bound_hash_bytes,
                "counted_as_online_recurrent_state": False,
            },
            "work": {
                "update_character_evaluations_per_observation": k,
                "update_accumulations_per_observation": k,
                "query_character_evaluations": k,
                "query_accumulations": k,
                "full_reconstruction_zero_fill": n,
                "full_reconstruction_fwht_butterflies": self.n_bits * n // 2,
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
    def from_dict(cls, value: Mapping[str, object]) -> "WalshPlan":
        if not isinstance(value, Mapping):
            raise WalshMemoryError("serialized plan must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("plan_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(
            supplied
        ):
            raise WalshMemoryError("serialized plan canonical SHA-256 mismatch")
        try:
            plan = cls(
                n_bits=int(supplied["n_bits"]),
                masks=tuple(int(mask) for mask in supplied["masks"]),
                field_sha256=str(supplied["field_sha256"]),
                name=str(supplied["name"]),
                mask_family=str(supplied["mask_selection"]["family"]),
                mask_source_field_sha256=supplied["mask_selection"].get(
                    "source_field_sha256"
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise WalshMemoryError("invalid serialized Walsh plan") from exc
        if plan._payload() != supplied or plan.plan_sha256 != supplied_hash:
            raise WalshMemoryError("serialized plan contains non-canonical metadata")
        return plan

    @classmethod
    def for_field(
        cls,
        scores: Sequence[float],
        *,
        budget: int | None = None,
        masks: Iterable[int] | None = None,
        max_degree: int | None = None,
        include_constant: bool = False,
        name: str = "walsh-score-memory",
        mask_family: str | None = None,
        mask_source_field_sha256: str | None = None,
    ) -> "WalshPlan":
        """Bind a deterministic mask bank to the canonical hash of a field."""

        field = _field_tuple(scores)
        n_bits = len(field).bit_length() - 1
        choices = sum(choice is not None for choice in (budget, masks, max_degree))
        if choices > 1:
            raise WalshMemoryError(
                "choose exactly one of budget, masks, or max_degree"
            )
        if masks is not None:
            selected = _canonical_masks(n_bits, masks)
            inferred_family = "explicit"
        elif max_degree is not None:
            selected = degree_masks(
                n_bits, max_degree, include_constant=include_constant
            )
            inferred_family = _mask_selection(n_bits, selected)["family"]
        elif budget is not None:
            selected = fixed_budget_masks(n_bits, budget)
            inferred_family = _mask_selection(n_bits, selected)["family"]
        else:
            selected = tuple(range(len(field)))
            inferred_family = "full-bank-ceiling"
        if mask_source_field_sha256 is not None and masks is None:
            raise WalshMemoryError(
                "mask_source_field_sha256 is valid only with an explicit frozen mask list"
            )
        return cls(
            n_bits=n_bits,
            masks=selected,
            field_sha256=score_field_sha256(field),
            name=name,
            mask_family=mask_family or inferred_family,
            mask_source_field_sha256=mask_source_field_sha256,
        )

    @classmethod
    def full_bank(
        cls, scores: Sequence[float], *, name: str = "walsh-full-bank-ceiling"
    ) -> "WalshPlan":
        return cls.for_field(scores, name=name)


@dataclass(frozen=True)
class FrozenWalshField:
    """Finalized spectral state; queries do not need the source score field."""

    plan: WalshPlan
    coefficients: tuple[float, ...]
    completed_passes: int
    observations: int
    input_field_hash_verified: bool = False

    def __post_init__(self) -> None:
        if len(self.coefficients) != self.plan.state_scalars:
            raise WalshMemoryError("coefficient count disagrees with plan")
        if any(not math.isfinite(value) for value in self.coefficients):
            raise WalshMemoryError("coefficients must be finite")
        if self.completed_passes < 1 or self.observations != (
            self.completed_passes * self.plan.domain_size
        ):
            raise WalshMemoryError("invalid finalized stream accounting")
        if not isinstance(self.input_field_hash_verified, bool):
            raise WalshMemoryError("input_field_hash_verified must be boolean")

    @property
    def state_scalars(self) -> int:
        return self.plan.state_scalars

    def query(self, address: int) -> float:
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < self.plan.domain_size
        ):
            raise WalshMemoryError("query address is outside the plan domain")
        return sum(
            coefficient * _walsh_character_unchecked(mask, address)
            for mask, coefficient in zip(self.plan.masks, self.coefficients)
        )

    def reconstruct(self) -> tuple[float, ...]:
        # Inverse Walsh is the same butterfly as the forward transform without
        # its 1/N normalization.  Zero-filling absent masks reconstructs the
        # exact orthogonal projection in O(N log N), while individual queries
        # remain O(K).
        values = [0.0] * self.plan.domain_size
        for mask, coefficient in zip(self.plan.masks, self.coefficients):
            values[mask] = coefficient
        width = 1
        while width < len(values):
            block = width * 2
            for start in range(0, len(values), block):
                for offset in range(width):
                    left = values[start + offset]
                    right = values[start + offset + width]
                    values[start + offset] = left + right
                    values[start + offset + width] = left - right
            width = block
        return tuple(values)

    def freeze_ranking(self) -> "FrozenRanking":
        return FrozenRanking.from_scores(
            self.reconstruct(), reference_field_sha256=self.plan.field_sha256
        )


class WalshScoreMemory:
    """Streaming fixed-bank Walsh accumulator.

    Complete passes are averaged, not summed.  Replaying an identical candidate
    stream therefore leaves the reconstructed field unchanged and cannot masquerade
    as stronger independent evidence.  The observation count and three address
    moments are four constant-size integrity scalars; exact coverage is additionally
    checked by ``observe_field``.
    """

    def __init__(self, plan: WalshPlan) -> None:
        if not isinstance(plan, WalshPlan):
            raise TypeError("plan must be a WalshPlan")
        self.plan = plan
        self._sums = [0.0] * plan.state_scalars
        self._observations = 0
        self._address_sum = 0
        self._address_square_sum = 0
        self._address_xor = 0
        self._bound_field_passes = 0
        self._finalized: FrozenWalshField | None = None

    @property
    def state_scalars(self) -> int:
        return self.plan.state_scalars

    @property
    def observations(self) -> int:
        return self._observations

    @property
    def retained_rows(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

    def observe(self, address: int, score: float) -> None:
        if self._finalized is not None:
            raise WalshMemoryError("cannot update a finalized Walsh memory")
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < self.plan.domain_size
        ):
            raise WalshMemoryError("observation address is outside the plan domain")
        value = _finite(score, "score")
        for index, mask in enumerate(self.plan.masks):
            self._sums[index] += value * _walsh_character_unchecked(mask, address)
        self._observations += 1
        self._address_sum += address
        self._address_square_sum += address * address
        self._address_xor ^= address

    def observe_many(self, observations: Iterable[tuple[int, float]]) -> None:
        """Apply a batch transactionally with only O(K) rollback state."""

        if self._finalized is not None:
            raise WalshMemoryError("cannot update a finalized Walsh memory")
        snapshot = (
            self._sums.copy(),
            self._observations,
            self._address_sum,
            self._address_square_sum,
            self._address_xor,
        )
        try:
            for item in observations:
                try:
                    address, score = item
                except (TypeError, ValueError) as exc:
                    raise WalshMemoryError(
                        "each observation must be an (address, score) pair"
                    ) from exc
                self.observe(address, score)
        except Exception:
            (
                self._sums,
                self._observations,
                self._address_sum,
                self._address_square_sum,
                self._address_xor,
            ) = snapshot
            raise

    def observe_field(
        self,
        scores: Sequence[float],
        *,
        address_order: Sequence[int] | None = None,
        verify_bound_hash: bool = True,
    ) -> None:
        """Stream one complete field in any permutation with exact coverage checks."""

        field = _field_tuple(scores)
        if len(field) != self.plan.domain_size:
            raise WalshMemoryError("score field length disagrees with plan domain")
        if verify_bound_hash and score_field_sha256(field) != self.plan.field_sha256:
            raise WalshMemoryError("score field does not match the plan field hash")
        if address_order is None:
            order = tuple(range(self.plan.domain_size))
        else:
            try:
                order = tuple(address_order)
            except TypeError as exc:
                raise WalshMemoryError("address_order must be iterable") from exc
            if len(order) != self.plan.domain_size or set(order) != set(
                range(self.plan.domain_size)
            ):
                raise WalshMemoryError(
                    "address_order must be a permutation of the complete domain"
                )
        self.observe_many((address, field[address]) for address in order)
        if verify_bound_hash:
            self._bound_field_passes += 1

    def _validate_complete_passes(self) -> int:
        n = self.plan.domain_size
        if self._observations == 0 or self._observations % n:
            raise WalshMemoryError(
                "finalization requires one or more complete domain passes"
            )
        passes = self._observations // n
        expected_sum = passes * n * (n - 1) // 2
        expected_square_sum = passes * n * (n - 1) * (2 * n - 1) // 6
        # xor(0..N-1) is one only for the N=2 domain and zero for every larger
        # power-of-two domain supported here.
        expected_xor = (1 if n == 2 else 0) if passes & 1 else 0
        if (
            self._address_sum != expected_sum
            or self._address_square_sum != expected_square_sum
            or self._address_xor != expected_xor
        ):
            raise WalshMemoryError(
                "stream address moments do not match complete uniform domain passes"
            )
        return passes

    def finalize(self) -> FrozenWalshField:
        if self._finalized is not None:
            return self._finalized
        passes = self._validate_complete_passes()
        # observations == passes * N, so this is the Walsh 1/N normalization
        # followed by an arithmetic mean across repeated complete fields.
        coefficients = tuple(total / self._observations for total in self._sums)
        self._finalized = FrozenWalshField(
            plan=self.plan,
            coefficients=coefficients,
            completed_passes=passes,
            observations=self._observations,
            input_field_hash_verified=self._bound_field_passes == passes,
        )
        # Do not retain a second K-wide copy after freezing.
        self._sums = []
        return self._finalized


@dataclass(frozen=True)
class FrozenRanking:
    """Target-blind total order with an exact raw uint16be order hash."""

    order: tuple[int, ...]
    score_field_sha256: str
    reference_field_sha256: str

    def __post_init__(self) -> None:
        n = len(self.order)
        if n < 2 or n > 1 << MAX_ADDRESS_BITS or n & (n - 1):
            raise WalshMemoryError("ranking size must be a power of two in [2, 65536]")
        if set(self.order) != set(range(n)):
            raise WalshMemoryError("ranking order must be a complete permutation")
        for value in (self.score_field_sha256, self.reference_field_sha256):
            if not isinstance(value, str) or len(value) != 64:
                raise WalshMemoryError("ranking field hashes must be SHA-256 values")
            try:
                int(value, 16)
            except ValueError as exc:
                raise WalshMemoryError("ranking field hashes must be SHA-256 values") from exc

    @classmethod
    def from_scores(
        cls,
        scores: Sequence[float],
        *,
        reference_field_sha256: str | None = None,
    ) -> "FrozenRanking":
        field = _field_tuple(scores)
        field_hash = score_field_sha256(field)
        return cls(
            order=tuple(sorted(range(len(field)), key=lambda address: (-field[address], address))),
            score_field_sha256=field_hash,
            reference_field_sha256=reference_field_sha256 or field_hash,
        )

    @property
    def order_uint16be(self) -> bytes:
        return b"".join(address.to_bytes(2, "big") for address in self.order)

    @property
    def order_sha256(self) -> str:
        return hashlib.sha256(self.order_uint16be).hexdigest()

    def rank(self, address: int) -> int:
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < len(self.order)
        ):
            raise WalshMemoryError("target address is outside the ranking domain")
        return self.order.index(address) + 1

    def describe(self) -> dict[str, object]:
        return {
            "schema": RANKING_SCHEMA,
            "domain_size": len(self.order),
            "tie_policy": TIE_POLICY,
            "order_encoding": "raw-uint16be",
            "order": list(self.order),
            "order_sha256": self.order_sha256,
            "score_field_sha256": self.score_field_sha256,
            "reference_field_sha256": self.reference_field_sha256,
            "target_labels_used": 0,
        }


def _pearson(left: Sequence[float], right: Sequence[float]) -> float:
    left_mean = math.fsum(left) / len(left)
    right_mean = math.fsum(right) / len(right)
    left_centered = [value - left_mean for value in left]
    right_centered = [value - right_mean for value in right]
    left_norm = math.sqrt(math.fsum(value * value for value in left_centered))
    right_norm = math.sqrt(math.fsum(value * value for value in right_centered))
    if left_norm == 0.0 or right_norm == 0.0:
        return 1.0 if tuple(left) == tuple(right) else 0.0
    value = math.fsum(
        a * b for a, b in zip(left_centered, right_centered)
    ) / (left_norm * right_norm)
    return max(-1.0, min(1.0, value))


def _rank_positions(order: Sequence[int]) -> list[int]:
    positions = [0] * len(order)
    for position, address in enumerate(order):
        positions[address] = position
    return positions


def _spearman(left_order: Sequence[int], right_order: Sequence[int]) -> float:
    n = len(left_order)
    left = _rank_positions(left_order)
    right = _rank_positions(right_order)
    squared = sum((left[address] - right[address]) ** 2 for address in range(n))
    return 1.0 - (6.0 * squared) / (n * (n * n - 1))


def _inversion_count(values: Sequence[int]) -> int:
    work = list(values)
    temporary = [0] * len(work)

    def count(start: int, end: int) -> int:
        if end - start < 2:
            return 0
        middle = (start + end) // 2
        inversions = count(start, middle) + count(middle, end)
        left = start
        right = middle
        output = start
        while left < middle and right < end:
            if work[left] <= work[right]:
                temporary[output] = work[left]
                left += 1
            else:
                temporary[output] = work[right]
                right += 1
                inversions += middle - left
            output += 1
        while left < middle:
            temporary[output] = work[left]
            left += 1
            output += 1
        while right < end:
            temporary[output] = work[right]
            right += 1
            output += 1
        work[start:end] = temporary[start:end]
        return inversions

    return count(0, len(work))


def _kendall(left_order: Sequence[int], right_order: Sequence[int]) -> float:
    n = len(left_order)
    right_positions = _rank_positions(right_order)
    permutation = [right_positions[address] for address in left_order]
    inversions = _inversion_count(permutation)
    return 1.0 - (4.0 * inversions) / (n * (n - 1))


@dataclass(frozen=True)
class TopKOverlap:
    k: int
    intersection: int
    fraction: float

    def describe(self) -> dict[str, object]:
        return {
            "k": self.k,
            "intersection": self.intersection,
            "fraction": self.fraction,
        }


@dataclass(frozen=True)
class ApproximationEvaluation:
    reference_field_sha256: str
    approximate_field_sha256: str
    score_pearson: float
    rank_spearman: float
    rank_kendall: float
    mean_absolute_error: float
    root_mean_square_error: float
    top_k_overlap: tuple[TopKOverlap, ...]

    def describe(self) -> dict[str, object]:
        return {
            "schema": EVALUATION_SCHEMA,
            "reference_field_sha256": self.reference_field_sha256,
            "approximate_field_sha256": self.approximate_field_sha256,
            "score_pearson": self.score_pearson,
            "rank_spearman": self.rank_spearman,
            "rank_kendall": self.rank_kendall,
            "mean_absolute_error": self.mean_absolute_error,
            "root_mean_square_error": self.root_mean_square_error,
            "top_k_overlap": [item.describe() for item in self.top_k_overlap],
            "target_labels_used": 0,
        }


def evaluate_approximation(
    reference_scores: Sequence[float],
    approximate_scores: Sequence[float],
    *,
    top_ks: Sequence[int] = (1, 8, 32),
) -> ApproximationEvaluation:
    """Evaluate a target-blind approximation; this API accepts no target label."""

    reference = _field_tuple(reference_scores)
    approximate = _field_tuple(approximate_scores)
    if len(reference) != len(approximate):
        raise WalshMemoryError("reference and approximation domains must match")
    try:
        ks = tuple(sorted(set(top_ks)))
    except TypeError as exc:
        raise WalshMemoryError("top_ks must be an integer sequence") from exc
    if not ks or any(
        not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= len(reference)
        for k in ks
    ):
        raise WalshMemoryError("top_ks must contain valid positive integer cutoffs")
    reference_ranking = FrozenRanking.from_scores(reference)
    approximate_ranking = FrozenRanking.from_scores(
        approximate, reference_field_sha256=reference_ranking.score_field_sha256
    )
    errors = [left - right for left, right in zip(reference, approximate)]
    overlaps = tuple(
        TopKOverlap(
            k=k,
            intersection=len(
                set(reference_ranking.order[:k]) & set(approximate_ranking.order[:k])
            ),
            fraction=len(
                set(reference_ranking.order[:k]) & set(approximate_ranking.order[:k])
            )
            / k,
        )
        for k in ks
    )
    return ApproximationEvaluation(
        reference_field_sha256=reference_ranking.score_field_sha256,
        approximate_field_sha256=approximate_ranking.score_field_sha256,
        score_pearson=_pearson(reference, approximate),
        rank_spearman=_spearman(reference_ranking.order, approximate_ranking.order),
        rank_kendall=_kendall(reference_ranking.order, approximate_ranking.order),
        mean_absolute_error=math.fsum(abs(error) for error in errors) / len(errors),
        root_mean_square_error=math.sqrt(
            math.fsum(error * error for error in errors) / len(errors)
        ),
        top_k_overlap=overlaps,
    )


@dataclass(frozen=True)
class TargetAddressLabel:
    """Separately revealed target label, never accepted by approximation scoring."""

    address: int
    reference_field_sha256: str
    source_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.address, int) or isinstance(self.address, bool) or self.address < 0:
            raise WalshMemoryError("target address must be a non-negative integer")
        for value in (self.reference_field_sha256, self.source_sha256):
            if not isinstance(value, str) or len(value) != 64:
                raise WalshMemoryError("target provenance hashes must be SHA-256 values")
            try:
                int(value, 16)
            except ValueError as exc:
                raise WalshMemoryError("target provenance hashes must be SHA-256 values") from exc


@dataclass(frozen=True)
class TargetRankEvaluation:
    address: int
    rank: int
    domain_size: int
    order_sha256: str
    label_source_sha256: str

    def describe(self) -> dict[str, object]:
        return {
            "schema": TARGET_EVALUATION_SCHEMA,
            "address": self.address,
            "rank": self.rank,
            "domain_size": self.domain_size,
            "order_sha256": self.order_sha256,
            "label_source_sha256": self.label_source_sha256,
            "target_labels_used": 1,
        }


def evaluate_target_rank(
    ranking: FrozenRanking, label: TargetAddressLabel
) -> TargetRankEvaluation:
    """Reveal target rank only through a separately typed provenance object."""

    if not isinstance(ranking, FrozenRanking) or not isinstance(label, TargetAddressLabel):
        raise TypeError("ranking and TargetAddressLabel are required")
    if label.reference_field_sha256 != ranking.reference_field_sha256:
        raise WalshMemoryError("target label is bound to a different reference field")
    if label.address >= len(ranking.order):
        raise WalshMemoryError("target address is outside the ranking domain")
    return TargetRankEvaluation(
        address=label.address,
        rank=ranking.rank(label.address),
        domain_size=len(ranking.order),
        order_sha256=ranking.order_sha256,
        label_source_sha256=label.source_sha256,
    )


def constant_score_field(n_bits: int, value: float = 1.0) -> tuple[float, ...]:
    """Constant/DC control field."""

    n_bits = _validate_n_bits(n_bits)
    finite = _finite(value, "value")
    return (finite,) * (1 << n_bits)


def delta_score_field(
    n_bits: int,
    address: int,
    *,
    amplitude: float = 1.0,
    baseline: float = 0.0,
) -> tuple[float, ...]:
    """Single-candidate impulse control field."""

    n_bits = _validate_n_bits(n_bits)
    domain_size = 1 << n_bits
    if (
        not isinstance(address, int)
        or isinstance(address, bool)
        or not 0 <= address < domain_size
    ):
        raise WalshMemoryError("delta address is outside the domain")
    level = _finite(baseline, "baseline")
    impulse = _finite(amplitude, "amplitude")
    result = [level] * domain_size
    result[address] += impulse
    if not math.isfinite(result[address]):
        raise WalshMemoryError("delta value must remain finite")
    return tuple(result)


def candidate_id_null_field(n_bits: int, *, seed: int = 0) -> tuple[float, ...]:
    """Deterministic candidate-ID-only null with no target or trace inputs."""

    n_bits = _validate_n_bits(n_bits)
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise WalshMemoryError("seed must be an integer")
    seed_bytes = (seed & ((1 << 128) - 1)).to_bytes(16, "big")
    result = []
    for address in range(1 << n_bits):
        digest = hashlib.blake2b(
            address.to_bytes(2, "big"),
            digest_size=8,
            person=b"o1w-null",
            key=seed_bytes,
        ).digest()
        integer = int.from_bytes(digest, "big")
        result.append((integer + 0.5) / (1 << 63) - 1.0)
    return tuple(result)


# A concise alias matching the architecture vocabulary used by the research plan.
WalshSpectralMemory = WalshScoreMemory
