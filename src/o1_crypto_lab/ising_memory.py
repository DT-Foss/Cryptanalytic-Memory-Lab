"""Strict degree-one-plus-two Ising evidence memory for Direct12 cells.

The mechanism consumes one externally computed scalar evidence value for each
12-bit cell in canonical address order.  Its only learned state is either the
12 unary coefficients or the 78 unary-plus-pairwise float64 Walsh coefficients.
Masks are implicit in the fixed 12-bit Ising contract; candidate rows, evidence
values, transcripts, and key/value entries are never retained.

This is deliberately a projection, not a full-field codec.  For mask ``m``::

    coefficient[m] = sum_x evidence[x] * (-1)**popcount(m & x) / 4096

The constant mode is absent, so reconstruction discards the global mean along
with every interaction of degree three or higher.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from numbers import Real
from typing import Iterable, Mapping, Sequence

from .walsh_memory import FrozenRanking


PLAN_SCHEMA = "o1-ising-evidence-plan-v1"
STATE_SCHEMA = "o1-ising-frozen-state-v1"
MECHANISM_FAMILY = "o1-degree-1-2-walsh-ising-evidence-memory"
EVIDENCE_HASH_SCHEMA = b"o1-ising-evidence-field-float64be-v1\x00"
COEFFICIENT_HASH_SCHEMA = b"o1-ising-coefficients-float64be-v1\x00"
MASK_BANK_HASH_SCHEMA = b"o1-ising-implicit-mask-bank-uint16be-v1\x00"

N_BITS = 12
DOMAIN_SIZE = 1 << N_BITS
LINEAR_MASKS = tuple(
    mask for mask in range(1, DOMAIN_SIZE) if mask.bit_count() == 1
)
ISING_MASKS = tuple(
    sorted(
        (mask for mask in range(1, DOMAIN_SIZE) if mask.bit_count() in (1, 2)),
        key=lambda mask: (mask.bit_count(), mask),
    )
)
MASKS_BY_SUPPORT = {
    "degree1": LINEAR_MASKS,
    "degree1+2": ISING_MASKS,
}
DEGREES_BY_SUPPORT = {
    "degree1": (1,),
    "degree1+2": (1, 2),
}
COEFFICIENT_COUNT = 78
FLOAT64_BYTES = 8
SERIALIZED_ACCUMULATOR_BYTES = COEFFICIENT_COUNT * FLOAT64_BYTES
CANONICAL_COUNTER_BYTES = 2
# Match the explicit logical SHA-256 state accounting used by the other strict
# streaming mechanisms in this lab: digest, 64-byte block, and length word.
HASH_LOGICAL_STATE_BYTES = 32 + 64 + 8
PASS_INTEGRITY_BYTES = CANONICAL_COUNTER_BYTES + HASH_LOGICAL_STATE_BYTES
SERIALIZED_ONLINE_STATE_BYTES = (
    SERIALIZED_ACCUMULATOR_BYTES + PASS_INTEGRITY_BYTES
)
PLAN_BINDING_BYTES = 32
EVIDENCE_BINDING_BYTES = 32
FROZEN_BINARY_STATE_BYTES = (
    SERIALIZED_ACCUMULATOR_BYTES
    + CANONICAL_COUNTER_BYTES
    + PLAN_BINDING_BYTES
    + EVIDENCE_BINDING_BYTES
)
MATERIALIZED_RANKING_OUTPUT_PAYLOAD_BYTES = DOMAIN_SIZE * (FLOAT64_BYTES + 2)

if len(ISING_MASKS) != COEFFICIENT_COUNT:  # pragma: no cover - module invariant
    raise RuntimeError("the fixed 12-bit degree-1+2 mask bank must contain 78 masks")


class IsingMemoryError(ValueError):
    """A plan, canonical stream, or frozen Ising state is invalid."""


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IsingMemoryError("value is not canonical finite ASCII JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IsingMemoryError(f"{field} must be a lowercase SHA-256")
    return value


def _finite(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise IsingMemoryError(f"{field} must be a finite scalar")
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise IsingMemoryError(f"{field} must be a finite scalar") from exc
    if not math.isfinite(result):
        raise IsingMemoryError(f"{field} must be a finite scalar")
    return 0.0 if result == 0.0 else result


def _character(mask: int, address: int) -> int:
    return -1 if (mask & address).bit_count() & 1 else 1


def _new_evidence_hasher() -> "hashlib._Hash":
    digest = hashlib.sha256()
    digest.update(EVIDENCE_HASH_SCHEMA)
    digest.update(DOMAIN_SIZE.to_bytes(4, "big"))
    return digest


def _update_evidence_hasher(digest: "hashlib._Hash", evidence: float) -> None:
    digest.update(struct.pack(">d", evidence))


def _validate_evidence_length(evidence: Sequence[float]) -> None:
    try:
        if len(evidence) != DOMAIN_SIZE:
            raise IsingMemoryError(
                f"evidence field must contain exactly {DOMAIN_SIZE} scalars"
            )
    except TypeError as exc:
        raise IsingMemoryError("evidence field must be a sized sequence") from exc


def evidence_field_sha256(evidence: Sequence[float]) -> str:
    """Hash a complete canonical evidence field as length-bound float64be."""

    _validate_evidence_length(evidence)
    digest = _new_evidence_hasher()
    for address, raw_value in enumerate(evidence):
        value = _finite(raw_value, f"evidence[{address}]")
        _update_evidence_hasher(digest, value)
    return digest.hexdigest()


def _mask_bank_sha256(masks: Sequence[int]) -> str:
    digest = hashlib.sha256()
    digest.update(MASK_BANK_HASH_SCHEMA)
    digest.update(len(masks).to_bytes(2, "big"))
    for mask in masks:
        digest.update(mask.to_bytes(2, "big"))
    return digest.hexdigest()


MASK_BANK_SHA256 = _mask_bank_sha256(ISING_MASKS)
LINEAR_MASK_BANK_SHA256 = _mask_bank_sha256(LINEAR_MASKS)


def _coefficients_sha256(coefficients: Sequence[float]) -> str:
    digest = hashlib.sha256()
    digest.update(COEFFICIENT_HASH_SCHEMA)
    digest.update(len(coefficients).to_bytes(2, "big"))
    for coefficient in coefficients:
        digest.update(struct.pack(">d", coefficient))
    return digest.hexdigest()


@dataclass(frozen=True)
class IsingMemoryPlan:
    """Canonical fixed-mechanism plan with an optional evidence-field binding."""

    expected_evidence_sha256: str | None = None
    name: str = "direct12-degree-1-2-ising-evidence-memory"
    support_id: str = "degree1+2"

    def __post_init__(self) -> None:
        if self.expected_evidence_sha256 is not None:
            _sha256(self.expected_evidence_sha256, "expected_evidence_sha256")
        if not isinstance(self.name, str) or not self.name.strip():
            raise IsingMemoryError("plan name is required")
        if self.support_id not in MASKS_BY_SUPPORT:
            raise IsingMemoryError("support_id must be degree1 or degree1+2")

    @classmethod
    def for_evidence(
        cls,
        evidence: Sequence[float],
        *,
        name: str = "direct12-degree-1-2-ising-evidence-memory",
        support_id: str = "degree1+2",
    ) -> "IsingMemoryPlan":
        return cls(
            expected_evidence_sha256=evidence_field_sha256(evidence),
            name=name,
            support_id=support_id,
        )

    @property
    def masks(self) -> tuple[int, ...]:
        return MASKS_BY_SUPPORT[self.support_id]

    @property
    def state_scalars(self) -> int:
        return len(self.masks)

    @property
    def serialized_state_bytes(self) -> int:
        return self.state_scalars * FLOAT64_BYTES

    @property
    def serialized_integrity_bytes(self) -> int:
        return PASS_INTEGRITY_BYTES

    @property
    def serialized_online_state_bytes(self) -> int:
        return self.serialized_state_bytes + PASS_INTEGRITY_BYTES

    @property
    def serialized_bound_hash_bytes(self) -> int:
        # Bind the query contract to the plan in every case.  A field-bound
        # plan conservatively retains a second digest for expected evidence.
        return PLAN_BINDING_BYTES + (
            EVIDENCE_BINDING_BYTES
            if self.expected_evidence_sha256 is not None
            else 0
        )

    @property
    def maximum_serialized_logical_mechanism_state_bytes(self) -> int:
        return self.serialized_online_state_bytes + self.serialized_bound_hash_bytes

    def _payload(self) -> dict[str, object]:
        return {
            "schema": PLAN_SCHEMA,
            "name": self.name,
            "support_id": self.support_id,
            "mechanism_family": MECHANISM_FAMILY,
            "n_bits": N_BITS,
            "domain_size": DOMAIN_SIZE,
            "expected_evidence_sha256": self.expected_evidence_sha256,
            "projection": {
                "degrees": list(DEGREES_BY_SUPPORT[self.support_id]),
                "includes_constant_mode": False,
                "implicit_mask_count": self.state_scalars,
                "implicit_mask_order": "degree-ascending-then-mask-ascending",
                "implicit_mask_rule": (
                    "popcount(mask) == 1"
                    if self.support_id == "degree1"
                    else "1 <= popcount(mask) <= 2"
                ),
                "implicit_mask_bank_sha256": _mask_bank_sha256(self.masks),
                "normalization": "sum(evidence*character)/4096",
            },
            "online_state": {
                "float64_accumulators": self.state_scalars,
                "serialized_accumulator_bytes": self.serialized_state_bytes,
                "canonical_next_address_counter_bytes": CANONICAL_COUNTER_BYTES,
                "logical_sha256_state_bytes": HASH_LOGICAL_STATE_BYTES,
                "serialized_integrity_bytes": PASS_INTEGRITY_BYTES,
                "serialized_online_state_bytes": self.serialized_online_state_bytes,
                "stream_length_dependent_state": False,
                "retained_candidate_rows": 0,
                "retained_evidence_values": 0,
                "retained_key_value_entries": 0,
                "accounting_model": "logical-compact-recurrent-state",
            },
            "static_plan_storage": {
                "implicit_masks": True,
                "serialized_mask_bank_bytes": 0,
                "serialized_bound_hash_bytes": self.serialized_bound_hash_bytes,
            },
            "output_workspace": {
                "materialized_only_when_a_complete_ranking_is_requested": True,
                "reconstructed_float64_scores_bytes": DOMAIN_SIZE * FLOAT64_BYTES,
                "uint16_order_bytes": DOMAIN_SIZE * 2,
                "materialized_ranking_output_payload_bytes": (
                    MATERIALIZED_RANKING_OUTPUT_PAYLOAD_BYTES
                ),
                "peak_sort_or_transform_scratch_bytes_claimed": None,
                "counted_as_recurrent_mechanism_state": False,
                "retained_after_output": False,
            },
            "maximum_serialized_logical_mechanism_state_bytes": (
                self.maximum_serialized_logical_mechanism_state_bytes
            ),
            "claim_boundary": {
                "full_rank": False,
                "candidate_indexed_table": False,
                "terminal_scalar_evidence_only": True,
                "target_labels_accepted_by_api": False,
            },
        }

    @property
    def plan_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        value = self._payload()
        value["plan_sha256"] = self.plan_sha256
        return value

    def to_json(self) -> str:
        return json.dumps(
            self.describe(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "IsingMemoryPlan":
        if not isinstance(value, Mapping):
            raise IsingMemoryError("serialized plan must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("plan_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(
            supplied
        ):
            raise IsingMemoryError("serialized plan canonical SHA-256 mismatch")
        try:
            plan = cls(
                expected_evidence_sha256=supplied["expected_evidence_sha256"],
                name=supplied["name"],
                support_id=supplied["support_id"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IsingMemoryError("invalid serialized Ising plan") from exc
        if plan._payload() != supplied or plan.plan_sha256 != supplied_hash:
            raise IsingMemoryError("serialized plan contains non-canonical metadata")
        return plan


@dataclass(frozen=True)
class FrozenIsingMemory:
    """Finalized 78-coefficient state, independent of the source evidence rows."""

    plan: IsingMemoryPlan
    coefficients: tuple[float, ...]
    evidence_field_sha256: str
    observations: int = DOMAIN_SIZE

    def __post_init__(self) -> None:
        if not isinstance(self.plan, IsingMemoryPlan):
            raise TypeError("plan must be an IsingMemoryPlan")
        try:
            coefficients = tuple(
                _finite(value, f"coefficients[{index}]")
                for index, value in enumerate(self.coefficients)
            )
        except TypeError as exc:
            raise IsingMemoryError("coefficients must be iterable") from exc
        if len(coefficients) != self.plan.state_scalars:
            raise IsingMemoryError(
                "frozen state coefficient count differs from its support"
            )
        if (
            not isinstance(self.observations, int)
            or isinstance(self.observations, bool)
            or self.observations != DOMAIN_SIZE
        ):
            raise IsingMemoryError("frozen state requires exactly 4096 observations")
        evidence_hash = _sha256(
            self.evidence_field_sha256, "evidence_field_sha256"
        )
        if (
            self.plan.expected_evidence_sha256 is not None
            and evidence_hash != self.plan.expected_evidence_sha256
        ):
            raise IsingMemoryError("frozen evidence hash differs from its plan binding")
        object.__setattr__(self, "coefficients", coefficients)

    @property
    def state_scalars(self) -> int:
        return self.plan.state_scalars

    @property
    def serialized_state_bytes(self) -> int:
        return self.plan.serialized_state_bytes

    @property
    def serialized_frozen_state_bytes(self) -> int:
        return (
            self.serialized_state_bytes
            + CANONICAL_COUNTER_BYTES
            + PLAN_BINDING_BYTES
            + EVIDENCE_BINDING_BYTES
        )

    @property
    def retained_candidate_rows(self) -> int:
        return 0

    @property
    def retained_evidence_values(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

    @property
    def coefficients_float64be_sha256(self) -> str:
        return _coefficients_sha256(self.coefficients)

    def to_bytes(self) -> bytes:
        """Serialize the exact compact query state with both hash bindings."""

        payload = b"".join(struct.pack(">d", value) for value in self.coefficients)
        payload += self.observations.to_bytes(CANONICAL_COUNTER_BYTES, "big")
        payload += bytes.fromhex(self.plan.plan_sha256)
        payload += bytes.fromhex(self.evidence_field_sha256)
        if len(payload) != self.serialized_frozen_state_bytes:  # pragma: no cover
            raise AssertionError("frozen Ising binary width differs")
        return payload

    @classmethod
    def from_bytes(
        cls,
        value: bytes,
        *,
        plan: IsingMemoryPlan,
    ) -> "FrozenIsingMemory":
        """Restore a compact state against the caller's exact frozen plan."""

        if not isinstance(plan, IsingMemoryPlan):
            raise TypeError("plan must be an IsingMemoryPlan")
        expected_bytes = (
            plan.serialized_state_bytes
            + CANONICAL_COUNTER_BYTES
            + PLAN_BINDING_BYTES
            + EVIDENCE_BINDING_BYTES
        )
        if not isinstance(value, bytes) or len(value) != expected_bytes:
            raise IsingMemoryError(
                f"frozen binary state must contain {expected_bytes} bytes"
            )
        coefficient_end = plan.serialized_state_bytes
        coefficients = tuple(
            item[0]
            for item in struct.iter_unpack(">d", value[:coefficient_end])
        )
        observation_end = coefficient_end + CANONICAL_COUNTER_BYTES
        observations = int.from_bytes(value[coefficient_end:observation_end], "big")
        plan_end = observation_end + PLAN_BINDING_BYTES
        stored_plan_sha256 = value[observation_end:plan_end].hex()
        if stored_plan_sha256 != plan.plan_sha256:
            raise IsingMemoryError("frozen binary plan binding differs")
        evidence_sha256 = value[plan_end:].hex()
        return cls(
            plan=plan,
            coefficients=coefficients,
            evidence_field_sha256=evidence_sha256,
            observations=observations,
        )

    def query(self, address: int) -> float:
        if (
            not isinstance(address, int)
            or isinstance(address, bool)
            or not 0 <= address < DOMAIN_SIZE
        ):
            raise IsingMemoryError("query address is outside the 12-bit domain")
        return math.fsum(
            coefficient * _character(mask, address)
            for mask, coefficient in zip(self.plan.masks, self.coefficients)
        )

    def reconstruct(self) -> tuple[float, ...]:
        values = [0.0] * DOMAIN_SIZE
        for mask, coefficient in zip(self.plan.masks, self.coefficients):
            values[mask] = coefficient
        width = 1
        while width < DOMAIN_SIZE:
            block = width * 2
            for start in range(0, DOMAIN_SIZE, block):
                for offset in range(width):
                    left = values[start + offset]
                    right = values[start + offset + width]
                    values[start + offset] = left + right
                    values[start + offset + width] = left - right
            width = block
        return tuple(values)

    def freeze_ranking(self) -> FrozenRanking:
        return FrozenRanking.from_scores(
            self.reconstruct(),
            reference_field_sha256=self.evidence_field_sha256,
        )

    @property
    def order(self) -> tuple[int, ...]:
        return self.freeze_ranking().order

    @property
    def order_uint16be_sha256(self) -> str:
        return self.freeze_ranking().order_sha256

    def _payload(self) -> dict[str, object]:
        ranking = self.freeze_ranking()
        return {
            "schema": STATE_SCHEMA,
            "plan": self.plan.describe(),
            "evidence_field_sha256": self.evidence_field_sha256,
            "observations": self.observations,
            "coefficients": list(self.coefficients),
            "coefficients_float64be_sha256": (
                self.coefficients_float64be_sha256
            ),
            "projected_score_field_sha256": ranking.score_field_sha256,
            "order_uint16be_sha256": ranking.order_sha256,
            "state_accounting": {
                "state_scalars": self.state_scalars,
                "serialized_state_bytes": self.serialized_state_bytes,
                "serialized_frozen_state_bytes": self.serialized_frozen_state_bytes,
                "retained_candidate_rows": 0,
                "retained_evidence_values": 0,
                "retained_key_value_entries": 0,
                "binary_state_implemented": True,
            },
            "target_labels_used": 0,
        }

    @property
    def state_sha256(self) -> str:
        return _canonical_sha256(self._payload())

    def describe(self) -> dict[str, object]:
        value = self._payload()
        value["state_sha256"] = self.state_sha256
        return value

    def to_json(self) -> str:
        return json.dumps(
            self.describe(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "FrozenIsingMemory":
        if not isinstance(value, Mapping):
            raise IsingMemoryError("serialized frozen state must be an object")
        supplied = dict(value)
        supplied_hash = supplied.pop("state_sha256", None)
        if not isinstance(supplied_hash, str) or supplied_hash != _canonical_sha256(
            supplied
        ):
            raise IsingMemoryError("serialized state canonical SHA-256 mismatch")
        try:
            plan = IsingMemoryPlan.from_dict(supplied["plan"])
            coefficients = tuple(supplied["coefficients"])
            frozen = cls(
                plan=plan,
                coefficients=coefficients,
                evidence_field_sha256=supplied["evidence_field_sha256"],
                observations=supplied["observations"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise IsingMemoryError("invalid serialized frozen Ising state") from exc
        if frozen._payload() != supplied or frozen.state_sha256 != supplied_hash:
            raise IsingMemoryError(
                "serialized frozen state contains non-canonical metadata"
            )
        return frozen


class IsingEvidenceMemory:
    """One-pass canonical 4096-cell accumulator with O(12) or O(78) state."""

    def __init__(self, plan: IsingMemoryPlan | None = None) -> None:
        if plan is None:
            plan = IsingMemoryPlan()
        if not isinstance(plan, IsingMemoryPlan):
            raise TypeError("plan must be an IsingMemoryPlan")
        self.plan = plan
        self._sums = [0.0] * self.plan.state_scalars
        self._next_address = 0
        self._hasher: "hashlib._Hash | None" = _new_evidence_hasher()
        self._finalized: FrozenIsingMemory | None = None

    @property
    def observations(self) -> int:
        return self._next_address

    @property
    def next_address(self) -> int:
        return self._next_address

    @property
    def state_scalars(self) -> int:
        return self.plan.state_scalars

    @property
    def serialized_state_bytes(self) -> int:
        return self.plan.serialized_state_bytes

    @property
    def serialized_online_state_bytes(self) -> int:
        return self.plan.serialized_online_state_bytes

    @property
    def retained_candidate_rows(self) -> int:
        return 0

    @property
    def retained_evidence_values(self) -> int:
        return 0

    @property
    def retained_key_value_entries(self) -> int:
        return 0

    def observe(self, address: int, evidence: float) -> None:
        if self._finalized is not None:
            raise IsingMemoryError("cannot update a finalized Ising memory")
        if not isinstance(address, int) or isinstance(address, bool):
            raise IsingMemoryError("observation address must be an exact integer")
        if self._next_address == DOMAIN_SIZE:
            raise IsingMemoryError("canonical evidence stream is already complete")
        if address != self._next_address:
            raise IsingMemoryError(
                f"canonical evidence stream expected address {self._next_address}, "
                f"received {address}"
            )
        value = _finite(evidence, "evidence")
        # Check first, then mutate in place.  This avoids hidden duplicate
        # 78-float banks that would invalidate the recurrent-state bound.
        for total, mask in zip(self._sums, self.plan.masks):
            if not math.isfinite(total + value * _character(mask, address)):
                raise IsingMemoryError("float64 Ising accumulator overflow")
        for index, mask in enumerate(self.plan.masks):
            self._sums[index] += value * _character(mask, address)
        if self._hasher is None:  # pragma: no cover - finalized guard above
            raise AssertionError("active Ising stream lost its evidence hasher")
        _update_evidence_hasher(self._hasher, value)
        self._next_address += 1

    def observe_many(self, observations: Iterable[tuple[int, float]]) -> None:
        """Apply a forward-only batch without allocating rollback state.

        A malformed later item leaves prior valid observations committed.  The
        scientific mechanism is a stream, and its state ceiling must not hide a
        duplicate accumulator bank for convenience rollback.
        """

        if self._finalized is not None:
            raise IsingMemoryError("cannot update a finalized Ising memory")
        for item in observations:
            try:
                address, evidence = item
            except (TypeError, ValueError) as exc:
                raise IsingMemoryError(
                    "each observation must be an (address, evidence) pair"
                ) from exc
            self.observe(address, evidence)

    def observe_field(self, evidence: Sequence[float]) -> None:
        """Consume one complete field in the only permitted address order."""

        _validate_evidence_length(evidence)
        if self._next_address != 0:
            raise IsingMemoryError("observe_field requires a fresh Ising memory")
        # The caller's replayable sequence is consumed exactly once.  No
        # validation pre-pass, 4096-cell copy, or rollback coefficient bank is
        # hidden inside the mechanism; a bad later value resets to zero state.
        try:
            self.observe_many(enumerate(evidence))
        except Exception:
            # A complete-field ingest remains atomic without a rollback copy:
            # reset to the canonical zero state on rare accumulator overflow.
            self._sums = [0.0] * self.plan.state_scalars
            self._next_address = 0
            self._hasher = _new_evidence_hasher()
            raise

    def finalize(self) -> FrozenIsingMemory:
        if self._finalized is not None:
            return self._finalized
        if self._next_address != DOMAIN_SIZE:
            raise IsingMemoryError(
                "finalization requires canonical addresses 0..4095 exactly once"
            )
        if self._hasher is None:  # pragma: no cover - lifecycle invariant
            raise AssertionError("complete Ising stream lost its evidence hasher")
        evidence_hash = self._hasher.hexdigest()
        if (
            self.plan.expected_evidence_sha256 is not None
            and evidence_hash != self.plan.expected_evidence_sha256
        ):
            raise IsingMemoryError("evidence field hash differs from its plan binding")
        coefficients = tuple(total / DOMAIN_SIZE for total in self._sums)
        self._finalized = FrozenIsingMemory(
            plan=self.plan,
            coefficients=coefficients,
            evidence_field_sha256=evidence_hash,
        )
        # The frozen state is the sole coefficient owner after finalization.
        self._sums = []
        self._hasher = None
        return self._finalized
