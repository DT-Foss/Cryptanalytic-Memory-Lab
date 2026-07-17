"""Learned-mask MQAR-256 over one bounded O1 state and an exact packed vault.

The benchmark closes the gap between an ideal ``observe_haystack`` no-op and a
deployed selective memory.  Every public token has the same typed shape.  A
frozen O1 input-gate classifier alone produces the hard update mask; no route
label or truth ledger is accepted by the execution API.  Accepted tokens update
both the unchanged O1 recurrence and a canonical two-plane positional vault.

This is a synthetic retention/mechanism instrument.  It does not claim cipher
leakage or holographic compression of 256 independent bits.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping, Sequence

import numpy as np

from .memory import CountSketchBitMemory, HolographicBitMemory
from .o1_streaming_core import (
    O1FastState,
    O1StreamingCoreConfig,
    StreamingSelectiveHolographicCore,
    require_torch,
    torch,
)

SELECTIVE_MQAR_SCHEMA = "o1-256-selective-mqar-learned-mask-v1"
GATE_FREEZE_SCHEMA = "o1-256-selective-mqar-gate-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-selective-mqar-prediction-freeze-v1"
RESULT_SCHEMA = "o1-256-selective-mqar-result-v1"
_MASK64 = (1 << 64) - 1


class SelectiveMQARError(ValueError):
    """A configuration, public stream, freeze boundary, or invariant differs."""


class TruthAccessError(RuntimeError):
    """A sealed evaluation ledger was accessed before prediction freeze."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _positive_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise SelectiveMQARError(f"{field} must be an integer in [1,{maximum}]")
    return value


def _finite_float(
    value: object,
    field: str,
    *,
    minimum: float,
    maximum: float,
    minimum_inclusive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SelectiveMQARError(f"{field} must be numeric")
    scalar = float(value)
    lower_ok = scalar >= minimum if minimum_inclusive else scalar > minimum
    if not math.isfinite(scalar) or not lower_ok or scalar > maximum:
        bracket = "[" if minimum_inclusive else "("
        raise SelectiveMQARError(
            f"{field} must be finite in {bracket}{minimum},{maximum}]"
        )
    return scalar


def _seed_tuple(value: object, field: str) -> tuple[int, ...]:
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(isinstance(item, bool) or not isinstance(item, int) for item in value)
    ):
        raise SelectiveMQARError(f"{field} must be a non-empty integer sequence")
    result = tuple(int(item) for item in value)
    if len(set(result)) != len(result):
        raise SelectiveMQARError(f"{field} contains duplicate seeds")
    return result


@dataclass(frozen=True)
class SelectiveMQARConfig:
    """Fully deterministic learned-mask MQAR protocol."""

    n_bits: int
    family_count: int
    relevant_family: int
    event_dimension: int
    address_dimension: int
    model_dimension: int
    heads: int
    head_dimension: int
    holographic_slots: int
    feedforward_dimension: int
    phase_scale: float
    core_seed: int
    build_seeds: tuple[int, ...]
    calibration_seeds: tuple[int, ...]
    evaluation_seeds: tuple[int, ...]
    haystack_lengths: tuple[int, ...]
    no_binding_length: int
    chunk_tokens: int
    build_examples_per_class: int
    calibration_examples_per_class: int
    training_steps: int
    learning_rate: float
    calibration_threshold_offset: float
    shuffled_label_seed: int
    family_code_seed: int
    literal_audit_tokens: int
    maximum_core_updates: int
    countsketch_slots: int
    holographic_channels: int
    cpu_threads: int

    def __post_init__(self) -> None:
        _positive_int(self.n_bits, "n_bits", 4096)
        _positive_int(self.family_count, "family_count", 32)
        if self.family_count < 2:
            raise SelectiveMQARError("family_count must be at least two")
        if (
            isinstance(self.relevant_family, bool)
            or not isinstance(self.relevant_family, int)
            or not 0 <= self.relevant_family < self.family_count
        ):
            raise SelectiveMQARError("relevant_family is outside family_count")
        if self.event_dimension != self.family_count + 8:
            raise SelectiveMQARError(
                "event_dimension must equal family_count plus eight public fields"
            )
        if self.address_dimension < 2 or self.address_dimension % 2:
            raise SelectiveMQARError("address_dimension must be positive and even")
        O1StreamingCoreConfig(
            event_dimension=self.event_dimension,
            address_dimension=self.address_dimension,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            phase_scale=self.phase_scale,
            seed=self.core_seed,
        )
        split_sets = (
            set(self.build_seeds),
            set(self.calibration_seeds),
            set(self.evaluation_seeds),
        )
        if any(not values for values in split_sets) or any(
            left & right
            for index, left in enumerate(split_sets)
            for right in split_sets[index + 1 :]
        ):
            raise SelectiveMQARError(
                "BUILD/CAL/EVAL seeds must be non-empty and disjoint"
            )
        if (
            not self.haystack_lengths
            or tuple(sorted(set(self.haystack_lengths))) != self.haystack_lengths
            or self.haystack_lengths[0] != 0
            or any(
                isinstance(length, bool)
                or not isinstance(length, int)
                or length < 0
                or length > (1 << 24)
                or (self.n_bits + length) % 8
                for length in self.haystack_lengths
            )
        ):
            raise SelectiveMQARError(
                "haystack_lengths must be sorted unique, start at zero, and bit-pack exactly"
            )
        if self.no_binding_length < self.haystack_lengths[-1]:
            raise SelectiveMQARError(
                "no_binding_length must cover the longest haystack"
            )
        for field, maximum in (
            ("chunk_tokens", 1 << 22),
            ("build_examples_per_class", 1 << 20),
            ("calibration_examples_per_class", 1 << 20),
            ("training_steps", 100_000),
            ("literal_audit_tokens", 1 << 20),
            ("maximum_core_updates", 1 << 20),
            ("countsketch_slots", 1 << 20),
            ("holographic_channels", 1 << 20),
            ("cpu_threads", 64),
        ):
            _positive_int(getattr(self, field), field, maximum)
        if self.chunk_tokens % 8:
            raise SelectiveMQARError("chunk_tokens must be divisible by eight")
        if (
            not self.n_bits
            <= self.literal_audit_tokens
            <= (self.n_bits + self.haystack_lengths[-1])
        ):
            raise SelectiveMQARError(
                "literal_audit_tokens must contain every binding within the longest stream"
            )
        _finite_float(
            self.learning_rate,
            "learning_rate",
            minimum=0.0,
            maximum=10.0,
        )
        _finite_float(
            self.calibration_threshold_offset,
            "calibration_threshold_offset",
            minimum=-1_000_000.0,
            maximum=1_000_000.0,
            minimum_inclusive=True,
        )
        for field in (
            "core_seed",
            "shuffled_label_seed",
            "family_code_seed",
        ):
            if isinstance(getattr(self, field), bool) or not isinstance(
                getattr(self, field), int
            ):
                raise SelectiveMQARError(f"{field} must be an integer")

    @classmethod
    def from_mapping(cls, value: object) -> "SelectiveMQARConfig":
        if not isinstance(value, Mapping):
            raise SelectiveMQARError("experiment must be a mapping")
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise SelectiveMQARError("experiment fields differ")
        row = dict(value)
        for field in (
            "build_seeds",
            "calibration_seeds",
            "evaluation_seeds",
        ):
            row[field] = _seed_tuple(row[field], field)
        lengths = row["haystack_lengths"]
        if not isinstance(lengths, (list, tuple)):
            raise SelectiveMQARError("haystack_lengths must be a sequence")
        row["haystack_lengths"] = tuple(lengths)
        return cls(**row)

    @property
    def core_config(self) -> O1StreamingCoreConfig:
        return O1StreamingCoreConfig(
            event_dimension=self.event_dimension,
            address_dimension=self.address_dimension,
            model_dimension=self.model_dimension,
            heads=self.heads,
            head_dimension=self.head_dimension,
            holographic_slots=self.holographic_slots,
            feedforward_dimension=self.feedforward_dimension,
            phase_scale=self.phase_scale,
            seed=self.core_seed,
        )

    @property
    def vault_bytes(self) -> int:
        return 2 * ((self.n_bits + 7) // 8)

    @property
    def live_state_bytes(self) -> int:
        return self.core_config.fast_state_bytes() + self.vault_bytes


class PackedBitVault:
    """Canonical value+validity bitplanes with last-accepted-write semantics."""

    def __init__(self, n_bits: int) -> None:
        self.n_bits = _positive_int(n_bits, "n_bits", 1 << 20)
        self._values = 0
        self._validity = 0

    @property
    def plane_bytes(self) -> int:
        return (self.n_bits + 7) // 8

    @property
    def serialized_state_bytes(self) -> int:
        return 2 * self.plane_bytes

    def write(self, address: int, bit: int) -> None:
        if isinstance(address, bool) or not isinstance(address, int):
            raise TypeError("address must be an integer")
        if not 0 <= address < self.n_bits:
            raise IndexError(address)
        if isinstance(bit, bool) or not isinstance(bit, int) or bit not in (0, 1):
            raise ValueError("bit must be 0 or 1")
        mask = 1 << address
        self._validity |= mask
        if bit:
            self._values |= mask
        else:
            self._values &= ~mask

    def write_arrays(self, addresses: np.ndarray, bits: np.ndarray) -> None:
        address_array = np.asarray(addresses)
        bit_array = np.asarray(bits)
        if (
            address_array.ndim != 1
            or bit_array.ndim != 1
            or address_array.shape != bit_array.shape
        ):
            raise SelectiveMQARError("vault write arrays differ")
        if not address_array.size:
            return
        if bool(np.any(address_array < 0)) or bool(
            np.any(address_array >= self.n_bits)
        ):
            raise SelectiveMQARError("vault address is outside declared width")
        if bool(np.any((bit_array != 0) & (bit_array != 1))):
            raise SelectiveMQARError("vault values must be binary")
        reversed_addresses = address_array[::-1].astype(np.int64, copy=False)
        _unique, reversed_first = np.unique(reversed_addresses, return_index=True)
        last_positions = address_array.size - 1 - reversed_first
        for position in sorted(int(item) for item in last_positions):
            self.write(int(address_array[position]), int(bit_array[position]))

    def read(self, address: int) -> int:
        if isinstance(address, bool) or not isinstance(address, int):
            raise TypeError("address must be an integer")
        if not 0 <= address < self.n_bits:
            raise IndexError(address)
        mask = 1 << address
        if not self._validity & mask:
            raise KeyError(address)
        return int(bool(self._values & mask))

    def value_array(self) -> np.ndarray:
        return np.unpackbits(
            np.frombuffer(
                self._values.to_bytes(self.plane_bytes, "little"), dtype=np.uint8
            ),
            bitorder="little",
            count=self.n_bits,
        ).astype(np.uint8, copy=False)

    def validity_array(self) -> np.ndarray:
        return np.unpackbits(
            np.frombuffer(
                self._validity.to_bytes(self.plane_bytes, "little"), dtype=np.uint8
            ),
            bitorder="little",
            count=self.n_bits,
        ).astype(np.uint8, copy=False)

    def to_bytes(self) -> bytes:
        return self._values.to_bytes(
            self.plane_bytes, "little"
        ) + self._validity.to_bytes(self.plane_bytes, "little")

    @classmethod
    def from_bytes(cls, payload: bytes, *, n_bits: int) -> "PackedBitVault":
        result = cls(n_bits)
        if (
            not isinstance(payload, bytes)
            or len(payload) != result.serialized_state_bytes
        ):
            raise SelectiveMQARError("packed vault payload length differs")
        width = result.plane_bytes
        result._values = int.from_bytes(payload[:width], "little")
        result._validity = int.from_bytes(payload[width:], "little")
        high_mask = ~((1 << n_bits) - 1)
        if result._values & high_mask or result._validity & high_mask:
            raise SelectiveMQARError("packed vault contains noncanonical high bits")
        return result

    def sha256(self) -> str:
        return _sha256(self.to_bytes())


def canonical_module_bytes(module: object) -> bytes:
    """Serialize a float32 Torch module without pickle or platform metadata."""

    require_torch()
    if not hasattr(module, "state_dict"):
        raise TypeError("module must expose state_dict")
    output = bytearray(b"o1c-canonical-f32-module-v1\x00")
    state = module.state_dict()
    for name in sorted(state):
        tensor = state[name]
        if not isinstance(tensor, torch.Tensor) or tensor.dtype != torch.float32:
            raise SelectiveMQARError("canonical module contains a non-float32 tensor")
        encoded_name = name.encode("utf-8")
        array = (
            tensor.detach()
            .to(device="cpu", dtype=torch.float32)
            .contiguous()
            .numpy()
            .astype("<f4", copy=False)
        )
        payload = array.tobytes(order="C")
        output.extend(struct.pack("<I", len(encoded_name)))
        output.extend(encoded_name)
        output.extend(struct.pack("<I", array.ndim))
        for dimension in array.shape:
            output.extend(struct.pack("<Q", int(dimension)))
        output.extend(struct.pack("<Q", len(payload)))
        output.extend(payload)
    return bytes(output)


def _splitmix64(values: np.ndarray, salt: int) -> np.ndarray:
    source = np.asarray(values, dtype=np.uint64)
    with np.errstate(over="ignore"):
        mixed = source + np.uint64(salt & _MASK64) + np.uint64(0x9E3779B97F4A7C15)
        mixed = (mixed ^ (mixed >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        mixed = (mixed ^ (mixed >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        return mixed ^ (mixed >> np.uint64(31))


def _permutation(length: int, seed: int) -> np.ndarray:
    identifiers = np.arange(length, dtype=np.uint64)
    keys = _splitmix64(identifiers, seed)
    return np.lexsort((identifiers, keys)).astype(np.int64, copy=False)


def _family_codes(count: int, seed: int) -> np.ndarray:
    # Vertices of a centered regular simplex are linearly separable through zero.
    base = np.eye(count, dtype=np.float32) - np.float32(1.0 / count)
    permutation = _permutation(count, seed ^ 0xFA11C0DE)
    sign_hash = _splitmix64(np.arange(count, dtype=np.uint64), seed ^ 0x51A9)
    signs = np.where((sign_hash & np.uint64(1)) == 0, 1.0, -1.0).astype(np.float32)
    return (base[:, permutation] * signs[None, :]).astype(np.float32, copy=False)


def _address_codes(addresses: np.ndarray, *, n_bits: int, dimension: int) -> np.ndarray:
    address = np.asarray(addresses, dtype=np.float64)
    harmonic = np.arange(1, dimension // 2 + 1, dtype=np.float64)
    phase = (
        (2.0 * math.pi / float(n_bits)) * (address[:, None] + 0.5) * harmonic[None, :]
    )
    result = np.empty((address.size, dimension), dtype=np.float32)
    result[:, 0::2] = np.sin(phase).astype(np.float32)
    result[:, 1::2] = np.cos(phase).astype(np.float32)
    return result


@dataclass(frozen=True)
class PublicTokenBatch:
    """Only fields available to the deployed learned route."""

    token_ids: np.ndarray
    events: np.ndarray
    address_codes: np.ndarray
    addresses: np.ndarray
    values: np.ndarray

    def __post_init__(self) -> None:
        length = int(self.token_ids.size)
        if (
            self.token_ids.shape != (length,)
            or self.events.ndim != 2
            or self.events.shape[0] != length
            or self.address_codes.ndim != 2
            or self.address_codes.shape[0] != length
            or self.addresses.shape != (length,)
            or self.values.shape != (length,)
            or self.token_ids.dtype != np.uint64
            or self.events.dtype != np.float32
            or self.address_codes.dtype != np.float32
        ):
            raise SelectiveMQARError("public token batch fields differ")

    @property
    def length(self) -> int:
        return int(self.token_ids.size)

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                self.token_ids.astype("<u8", copy=False).tobytes(order="C"),
                self.events.astype("<f4", copy=False).tobytes(order="C"),
                self.address_codes.astype("<f4", copy=False).tobytes(order="C"),
                self.addresses.astype("<u2", copy=False).tobytes(order="C"),
                self.values.astype(np.uint8, copy=False).tobytes(order="C"),
            )
        )


def _public_stream_hashers() -> dict[str, Any]:
    return {
        name: hashlib.sha256()
        for name in ("token_ids", "events", "address_codes", "addresses", "values")
    }


def _update_public_stream_hashers(
    hashers: Mapping[str, Any], batch: PublicTokenBatch
) -> None:
    hashers["token_ids"].update(
        batch.token_ids.astype("<u8", copy=False).tobytes(order="C")
    )
    hashers["events"].update(batch.events.astype("<f4", copy=False).tobytes(order="C"))
    hashers["address_codes"].update(
        batch.address_codes.astype("<f4", copy=False).tobytes(order="C")
    )
    hashers["addresses"].update(
        batch.addresses.astype("<u2", copy=False).tobytes(order="C")
    )
    hashers["values"].update(
        batch.values.astype(np.uint8, copy=False).tobytes(order="C")
    )


def _finish_field_commitment(
    schema: str, hashers: Mapping[str, Any], *, length: int
) -> str:
    document = {
        "schema": schema,
        "length": int(length),
        "field_sha256": {
            name: hasher.hexdigest() for name, hasher in sorted(hashers.items())
        },
    }
    return _sha256(_canonical_json(document))


@dataclass(frozen=True)
class RevealedTruth:
    secret_bits: np.ndarray
    query_order: np.ndarray
    route_masks: Mapping[int, bytes]
    route_lengths: Mapping[int, int]


class SealedTruthLedger:
    """One-shot score ledger which cannot participate in public execution."""

    def __init__(
        self,
        *,
        secret_bits: np.ndarray,
        query_order: np.ndarray,
        route_masks: Mapping[int, bytes],
        route_lengths: Mapping[int, int],
    ) -> None:
        self._secret_bits = np.asarray(secret_bits, dtype=np.uint8).copy()
        self._query_order = np.asarray(query_order, dtype=np.int64).copy()
        self._route_masks = dict(route_masks)
        self._route_lengths = dict(route_lengths)
        self._reveal_count = 0

    @property
    def reveal_count(self) -> int:
        return self._reveal_count

    def reveal(self) -> RevealedTruth:
        self._reveal_count += 1
        if self._reveal_count != 1:
            raise TruthAccessError("truth ledger may be revealed exactly once")
        return RevealedTruth(
            secret_bits=self._secret_bits.copy(),
            query_order=self._query_order.copy(),
            route_masks=dict(self._route_masks),
            route_lengths=dict(self._route_lengths),
        )

    def __getitem__(self, _key: object) -> object:
        raise TruthAccessError("sealed truth ledger is not indexable")

    def __iter__(self) -> Iterator[object]:
        raise TruthAccessError("sealed truth ledger is not iterable")

    def __array__(self, *_args: object, **_kwargs: object) -> np.ndarray:
        raise TruthAccessError("sealed truth ledger is not array-convertible")


def _pack_mask(mask: np.ndarray) -> bytes:
    array = np.asarray(mask, dtype=np.bool_)
    return np.packbits(array, bitorder="little").tobytes(order="C")


class _IncrementalMaskPacker:
    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self._remainder = np.empty(0, dtype=np.bool_)
        self.length = 0

    def add(self, mask: np.ndarray) -> None:
        array = np.asarray(mask, dtype=np.bool_).reshape(-1)
        self.length += int(array.size)
        if self._remainder.size:
            array = np.concatenate((self._remainder, array))
        full = (array.size // 8) * 8
        if full:
            self._chunks.append(_pack_mask(array[:full]))
        self._remainder = array[full:].copy()

    def finish(self) -> bytes:
        if self._remainder.size:
            self._chunks.append(_pack_mask(self._remainder))
            self._remainder = np.empty(0, dtype=np.bool_)
        return b"".join(self._chunks)


class PublicEpisode:
    """A stable-supersequence public episode with no route-label accessor."""

    def __init__(self, config: SelectiveMQARConfig, seed: int) -> None:
        self.config = config
        self.seed = int(seed)
        self._codes = _family_codes(config.family_count, config.family_code_seed)
        self._binding_addresses = _permutation(config.n_bits, seed ^ 0xB1AD1A95)
        bit_hash = _splitmix64(
            np.arange(config.n_bits, dtype=np.uint64), seed ^ 0xB175EC
        )
        secret_by_address = (bit_hash & np.uint64(1)).astype(np.uint8)
        self._binding_values = secret_by_address[self._binding_addresses]
        self._secret_by_address = secret_by_address
        self._query_order = _permutation(config.n_bits, seed ^ 0x0A3E21)

        maximum = config.haystack_lengths[-1]
        binding_local = np.arange(config.n_bits, dtype=np.int64)
        distractor_local = np.arange(maximum, dtype=np.int64)
        kinds = np.concatenate(
            (
                np.ones(config.n_bits, dtype=np.bool_),
                np.zeros(maximum, dtype=np.bool_),
            )
        )
        local = np.concatenate((binding_local, distractor_local))
        raw_ids = np.concatenate(
            (
                _splitmix64(binding_local.astype(np.uint64), seed ^ 0xB10D1D),
                _splitmix64(distractor_local.astype(np.uint64), seed ^ 0xD157A6),
            )
        )
        priority = _splitmix64(raw_ids, seed ^ 0x570EA0)
        order = np.lexsort((raw_ids, priority))
        self._ordered_kind = kinds[order]
        self._ordered_local = local[order]
        self._ordered_public_id = raw_ids[order]
        self._indices: dict[int, np.ndarray] = {}
        route_masks: dict[int, bytes] = {}
        route_lengths: dict[int, int] = {}
        for length in config.haystack_lengths:
            included = self._ordered_kind | (self._ordered_local < length)
            indices = np.flatnonzero(included).astype(np.int64, copy=False)
            if indices.size != config.n_bits + length:
                raise AssertionError("stable episode projection width differs")
            self._indices[length] = indices
            truth = self._ordered_kind[indices]
            route_masks[length] = _pack_mask(truth)
            route_lengths[length] = int(truth.size)
        self._ledger = SealedTruthLedger(
            secret_bits=secret_by_address,
            query_order=self._query_order,
            route_masks=route_masks,
            route_lengths=route_lengths,
        )

    def take_ledger(self) -> SealedTruthLedger:
        return self._ledger

    def token_ids(self, haystack_length: int) -> np.ndarray:
        try:
            indices = self._indices[haystack_length]
        except KeyError as exc:
            raise SelectiveMQARError("unregistered haystack length") from exc
        return self._ordered_public_id[indices].copy()

    def query_order(self) -> np.ndarray:
        """Return the public randomized address-query order for this episode."""

        return self._query_order.copy()

    def _visible_batch(
        self,
        indices: np.ndarray,
        *,
        cue_mode: str,
    ) -> PublicTokenBatch:
        config = self.config
        kinds = self._ordered_kind[indices]
        local = self._ordered_local[indices]
        token_ids = self._ordered_public_id[indices].astype(np.uint64, copy=True)
        addresses = np.empty(indices.size, dtype=np.int64)
        values = np.empty(indices.size, dtype=np.uint8)
        families = np.empty(indices.size, dtype=np.int64)
        if bool(kinds.any()):
            binding_local = local[kinds]
            addresses[kinds] = self._binding_addresses[binding_local]
            values[kinds] = self._binding_values[binding_local]
            families[kinds] = config.relevant_family
        distractor = ~kinds
        if bool(distractor.any()):
            distractor_local = local[distractor]
            addresses[distractor] = (
                distractor_local * 197 + (self.seed & 255)
            ) % config.n_bits
            values[distractor] = ((distractor_local // config.n_bits) & 1).astype(
                np.uint8
            )
            other = np.asarray(
                [
                    family
                    for family in range(config.family_count)
                    if family != config.relevant_family
                ],
                dtype=np.int64,
            )
            families[distractor] = other[distractor_local % (config.family_count - 1)]

        events = np.zeros((indices.size, config.event_dimension), dtype=np.float32)
        if cue_mode == "identity":
            events[:, : config.family_count] = self._codes[families]
        elif cue_mode == "rotate":
            events[:, : config.family_count] = self._codes[
                (families + 1) % config.family_count
            ]
        elif cue_mode == "ablate":
            pass
        else:
            raise SelectiveMQARError(f"unknown cue mode: {cue_mode}")
        offset = config.family_count
        events[:, offset] = np.where(values == 1, 0.5, -0.5).astype(np.float32)
        events[:, offset + 1] = (addresses.astype(np.float32) + 0.5) / float(
            config.n_bits
        ) - 0.5
        for nuisance in range(6):
            hashes = _splitmix64(
                token_ids,
                self.seed ^ (0x9E37 * (nuisance + 1)) ^ 0xC0DEC0DE,
            )
            events[:, offset + 2 + nuisance] = np.where(
                (hashes & np.uint64(1)) == 0, 0.25, -0.25
            ).astype(np.float32)
        return PublicTokenBatch(
            token_ids=token_ids,
            events=events,
            address_codes=_address_codes(
                addresses,
                n_bits=config.n_bits,
                dimension=config.address_dimension,
            ),
            addresses=addresses,
            values=values,
        )

    def iter_batches(
        self,
        haystack_length: int,
        *,
        cue_mode: str = "identity",
        chunk_tokens: int | None = None,
    ) -> Iterator[PublicTokenBatch]:
        try:
            indices = self._indices[haystack_length]
        except KeyError as exc:
            raise SelectiveMQARError("unregistered haystack length") from exc
        chunk = (
            self.config.chunk_tokens
            if chunk_tokens is None
            else _positive_int(chunk_tokens, "chunk_tokens", 1 << 24)
        )
        for start in range(0, indices.size, chunk):
            yield self._visible_batch(indices[start : start + chunk], cue_mode=cue_mode)

    def collect_audit_projection(
        self,
        token_limit: int,
        *,
        cue_mode: str = "identity",
    ) -> PublicTokenBatch:
        limit = _positive_int(token_limit, "token_limit", 1 << 24)
        if (
            not self.config.n_bits
            <= limit
            <= (self.config.n_bits + self.config.haystack_lengths[-1])
        ):
            raise SelectiveMQARError(
                "audit projection must contain every binding and a legal distractor prefix"
            )
        distractors = limit - self.config.n_bits
        included = self._ordered_kind | (self._ordered_local < distractors)
        indices = np.flatnonzero(included).astype(np.int64, copy=False)
        if indices.size != limit:
            raise AssertionError("audit stable projection width differs")
        return self._visible_batch(indices, cue_mode=cue_mode)


def build_public_episode(
    config: SelectiveMQARConfig, seed: int
) -> tuple[PublicEpisode, SealedTruthLedger]:
    episode = PublicEpisode(config, seed)
    return episode, episode.take_ledger()


def _training_events(
    config: SelectiveMQARConfig,
    seeds: Sequence[int],
    examples_per_class: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    codes = _family_codes(config.family_count, config.family_code_seed)
    events: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    paired_positive: list[np.ndarray] = []
    paired_negative: list[np.ndarray] = []
    other = np.asarray(
        [
            family
            for family in range(config.family_count)
            if family != config.relevant_family
        ],
        dtype=np.int64,
    )
    for seed in seeds:
        count = 2 * examples_per_class
        label = np.concatenate(
            (
                np.ones(examples_per_class, dtype=np.float32),
                np.zeros(examples_per_class, dtype=np.float32),
            )
        )
        families = np.concatenate(
            (
                np.full(examples_per_class, config.relevant_family, dtype=np.int64),
                other[np.arange(examples_per_class) % other.size],
            )
        )
        base = np.arange(examples_per_class, dtype=np.int64)
        base_addresses = (base * 197 + (seed & 255)) % config.n_bits
        base_values = ((base // config.n_bits) & 1).astype(np.uint8)
        base_token_ids = _splitmix64(base.astype(np.uint64), seed ^ 0x7A11)
        # Positive/negative pairs expose byte-identical non-cue fields.  The gate
        # can therefore earn route margin only from the family cue learned on BUILD.
        addresses = np.concatenate((base_addresses, base_addresses))
        values = np.concatenate((base_values, base_values))
        token_ids = np.concatenate((base_token_ids, base_token_ids))
        block = np.zeros((count, config.event_dimension), dtype=np.float32)
        block[:, : config.family_count] = codes[families]
        offset = config.family_count
        block[:, offset] = np.where(values == 1, 0.5, -0.5).astype(np.float32)
        block[:, offset + 1] = (addresses.astype(np.float32) + 0.5) / float(
            config.n_bits
        ) - 0.5
        for nuisance in range(6):
            hashes = _splitmix64(token_ids, seed ^ 0xC411B ^ (0x9E37 * (nuisance + 1)))
            block[:, offset + 2 + nuisance] = np.where(
                (hashes & np.uint64(1)) == 0, 0.25, -0.25
            ).astype(np.float32)
        permutation = _permutation(count, seed ^ 0x5A17)
        events.append(block[permutation])
        labels.append(label[permutation])
        paired_positive.append(block[:examples_per_class])
        paired_negative.append(block[examples_per_class:])
    return (
        np.concatenate(events),
        np.concatenate(labels),
        np.concatenate(paired_positive),
        np.concatenate(paired_negative),
    )


@dataclass
class FrozenRouteGate:
    name: str
    core: Any
    threshold: float
    initial_state_sha256: str
    slow_state_bytes: bytes
    slow_state_sha256: str
    changed_parameters: tuple[str, ...]
    training_metrics: Mapping[str, object]
    calibration_metrics: Mapping[str, object]

    def score(self, events: np.ndarray) -> np.ndarray:
        array = np.asarray(events, dtype=np.float32)
        if array.ndim != 2 or array.shape[1] != self.core.config.event_dimension:
            raise SelectiveMQARError("gate event array differs")
        with torch.no_grad():
            tensor = torch.from_numpy(array)
            hidden = self.core.event_projection(tensor)
            logits = self.core.input_gate(hidden).mean(dim=-1)
        return logits.detach().cpu().numpy().astype(np.float32, copy=False)

    def mask(self, events: np.ndarray) -> np.ndarray:
        return self.score(events) >= np.float32(self.threshold)


def _parameter_snapshot(module: object) -> dict[str, bytes]:
    require_torch()
    return {
        name: tensor.detach()
        .to(device="cpu", dtype=torch.float32)
        .contiguous()
        .numpy()
        .astype("<f4", copy=False)
        .tobytes(order="C")
        for name, tensor in module.state_dict().items()
    }


def _calibration_metrics(
    gate: FrozenRouteGate,
    events: np.ndarray,
    labels: np.ndarray,
    *,
    scores: np.ndarray | None = None,
) -> dict[str, object]:
    scores = gate.score(events) if scores is None else np.asarray(scores)
    predicted = scores >= np.float32(gate.threshold)
    truth = labels.astype(np.bool_)
    positives = scores[truth]
    negatives = scores[~truth]
    false_negatives = int(np.count_nonzero(~predicted & truth))
    false_positives = int(np.count_nonzero(predicted & ~truth))
    return {
        "examples": int(scores.size),
        "positive_examples": int(positives.size),
        "negative_examples": int(negatives.size),
        "threshold": gate.threshold,
        "minimum_positive_score": float(positives.min()),
        "maximum_negative_score": float(negatives.max()),
        "minimum_signed_margin": float(
            min(positives.min() - gate.threshold, gate.threshold - negatives.max())
        ),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "zero_errors": false_positives == 0 and false_negatives == 0,
    }


def _global_route_certificate(
    gate: FrozenRouteGate, config: SelectiveMQARConfig
) -> dict[str, object]:
    """Certify the linear route over every legal payload/address/nuisance value."""

    with torch.no_grad():
        input_weight = gate.core.input_gate.weight.mean(dim=0).detach().cpu().numpy()
        projection = gate.core.event_projection.weight.detach().cpu().numpy()
    effective = input_weight @ projection
    cue = effective[: config.family_count]
    noncue = effective[config.family_count :]
    if noncue.shape != (8,):
        raise SelectiveMQARError("public non-cue route width differs")
    family_base = _family_codes(config.family_count, config.family_code_seed) @ cue
    nuisance_bound = float(
        0.5 * abs(noncue[0]) + 0.5 * abs(noncue[1]) + 0.25 * np.abs(noncue[2:]).sum()
    )
    positive_base = float(family_base[config.relevant_family])
    negative_base = float(np.max(np.delete(family_base, config.relevant_family)))
    positive_lower = positive_base - nuisance_bound
    negative_upper = negative_base + nuisance_bound
    return {
        "schema": "o1-selective-mqar-linear-route-certificate-v1",
        "legal_payload_absolute_bound": 0.5,
        "legal_address_absolute_bound": 0.5,
        "legal_nuisance_absolute_bound": 0.25,
        "nuisance_score_absolute_bound": nuisance_bound,
        "positive_family_base_score": positive_base,
        "maximum_negative_family_base_score": negative_base,
        "certified_positive_lower_score": positive_lower,
        "certified_negative_upper_score": negative_upper,
        "threshold": gate.threshold,
        "certified_margin": min(
            positive_lower - gate.threshold, gate.threshold - negative_upper
        ),
        "all_legal_public_tokens_separated": (
            positive_lower > gate.threshold > negative_upper
        ),
        "effective_noncue_l1": float(np.abs(noncue).sum()),
    }


def train_route_gate(
    config: SelectiveMQARConfig,
    *,
    name: str,
    shuffled_labels: bool,
    fixed_threshold: float | None = None,
) -> FrozenRouteGate:
    require_torch()
    core = StreamingSelectiveHolographicCore(config.core_config)
    with torch.no_grad():
        # A neutral O1 input gate makes the learned route the only source of
        # family preference and gives every control byte-identical initialization.
        core.input_gate.weight.zero_()
    initial_bytes = canonical_module_bytes(core)
    before = _parameter_snapshot(core)
    for parameter_name, parameter in core.named_parameters():
        parameter.requires_grad_(parameter_name == "input_gate.weight")
    build_events, build_labels, paired_positive, paired_negative = _training_events(
        config,
        config.build_seeds,
        config.build_examples_per_class,
    )
    effective_labels = build_labels.copy()
    if shuffled_labels:
        effective_labels = effective_labels[
            _permutation(effective_labels.size, config.shuffled_label_seed)
        ]
        positive_examples = build_events[effective_labels == 1.0]
        negative_examples = build_events[effective_labels == 0.0]
    else:
        positive_examples = paired_positive
        negative_examples = paired_negative
    if positive_examples.shape != negative_examples.shape:
        raise SelectiveMQARError("paired route-training classes differ")
    positive_tensor = torch.from_numpy(positive_examples)
    negative_tensor = torch.from_numpy(negative_examples)
    optimizer = torch.optim.Adam((core.input_gate.weight,), lr=config.learning_rate)
    first_loss = None
    final_loss = None
    core.train()
    for _step in range(config.training_steps):
        optimizer.zero_grad(set_to_none=True)
        positive_logits = core.input_gate(core.event_projection(positive_tensor))
        negative_logits = core.input_gate(core.event_projection(negative_tensor))
        # Paired ranking is the synthetic analogue of k_i=1 versus k_i=0:
        # byte-identical nuisance fields cancel before the route earns margin.
        pair_margin = positive_logits - negative_logits
        loss = torch.nn.functional.softplus(-pair_margin).mean()
        if not bool(torch.isfinite(loss)):
            raise SelectiveMQARError("gate training produced a non-finite loss")
        loss.backward()
        optimizer.step()
        if first_loss is None:
            first_loss = float(loss.detach())
        final_loss = float(loss.detach())
    core.eval()
    for parameter in core.parameters():
        parameter.requires_grad_(False)
    after = _parameter_snapshot(core)
    changed = tuple(sorted(name for name in before if before[name] != after[name]))
    if changed != ("input_gate.weight",):
        raise SelectiveMQARError("gate training changed a frozen parameter")
    slow_bytes = canonical_module_bytes(core)
    provisional = FrozenRouteGate(
        name=name,
        core=core,
        threshold=0.0,
        initial_state_sha256=_sha256(initial_bytes),
        slow_state_bytes=slow_bytes,
        slow_state_sha256=_sha256(slow_bytes),
        changed_parameters=changed,
        training_metrics={
            "steps": config.training_steps,
            "examples_per_step": int(build_labels.size),
            "token_exposures": int(config.training_steps * build_labels.size),
            "positive_labels": int(np.count_nonzero(effective_labels == 1.0)),
            "negative_labels": int(np.count_nonzero(effective_labels == 0.0)),
            "labels_shuffled": shuffled_labels,
            "objective": "PAIRED_LOGISTIC_ROUTE_MARGIN",
            "first_loss": first_loss,
            "final_loss": final_loss,
            "learning_rate": config.learning_rate,
        },
        calibration_metrics={},
    )
    (
        calibration_events,
        calibration_labels,
        _calibration_positive,
        _calibration_negative,
    ) = _training_events(
        config,
        config.calibration_seeds,
        config.calibration_examples_per_class,
    )
    calibration_scores = provisional.score(calibration_events)
    calibration_truth = calibration_labels.astype(np.bool_)
    if fixed_threshold is None:
        provisional.threshold = float(
            0.5
            * (
                float(calibration_scores[calibration_truth].min())
                + float(calibration_scores[~calibration_truth].max())
            )
            + config.calibration_threshold_offset
        )
    else:
        provisional.threshold = float(fixed_threshold)
    provisional.calibration_metrics = _calibration_metrics(
        provisional,
        calibration_events,
        calibration_labels,
        scores=calibration_scores,
    )
    provisional.calibration_metrics["global_public_token_certificate"] = (
        _global_route_certificate(provisional, config)
    )
    return provisional


def untrained_route_gate(
    config: SelectiveMQARConfig, *, threshold: float
) -> FrozenRouteGate:
    require_torch()
    core = StreamingSelectiveHolographicCore(config.core_config).eval()
    with torch.no_grad():
        core.input_gate.weight.zero_()
    for parameter in core.parameters():
        parameter.requires_grad_(False)
    payload = canonical_module_bytes(core)
    return FrozenRouteGate(
        name="untrained",
        core=core,
        threshold=float(threshold),
        initial_state_sha256=_sha256(payload),
        slow_state_bytes=payload,
        slow_state_sha256=_sha256(payload),
        changed_parameters=(),
        training_metrics={
            "steps": 0,
            "examples_per_step": 0,
            "token_exposures": 0,
            "labels_shuffled": False,
        },
        calibration_metrics={},
    )


def _core_update_one(
    core: object,
    state: O1FastState,
    event: np.ndarray,
    address_code: np.ndarray,
    *,
    active: bool,
) -> O1FastState:
    event_tensor = torch.from_numpy(
        np.asarray(event, dtype=np.float32).reshape(1, 1, -1)
    )
    address_tensor = torch.from_numpy(
        np.asarray(address_code, dtype=np.float32).reshape(1, 1, -1)
    )
    mask_tensor = torch.tensor([[active]], dtype=torch.bool)
    with torch.no_grad():
        _encoded, new_state = core(event_tensor, address_tensor, mask_tensor, state)
    return new_state


@dataclass(frozen=True)
class PublicExecutionRecord:
    arm: str
    seed: int
    haystack_length: int
    token_count: int
    cue_mode: str
    public_stream_sha256: str
    mask_bytes: bytes
    mask_sha256: str
    mask_encoding: str
    accepted_tokens: int
    selected_order_sha256: str
    value_plane: bytes
    validity_plane: bytes
    prediction_sha256: str
    core_replay: str
    core_updates: int
    fast_state_bytes: int
    vault_state_bytes: int
    live_state_bytes: bytes
    live_state_sha256: str
    query_state_held_exactly: bool | None
    query_order_sha256: str
    query_answers_sha256: str
    query_projection_exact: bool
    slow_state_sha256_before: str | None
    slow_state_sha256_after: str | None
    selected_pairs: tuple[tuple[int, int], ...] | None


def execute_public_episode(
    episode: PublicEpisode,
    *,
    haystack_length: int,
    arm: str,
    gate: FrozenRouteGate | None,
    cue_mode: str,
    run_core: bool,
    all_open: bool = False,
) -> PublicExecutionRecord:
    """Execute only public fields.  A truth ledger is deliberately not accepted."""

    config = episode.config
    if all_open == (gate is not None):
        raise SelectiveMQARError("execution requires exactly one gate authority")
    core = gate.core if gate is not None else None
    state = (
        core.initial_state(1)
        if run_core and core is not None
        else StreamingSelectiveHolographicCore(config.core_config).initial_state(1)
    )
    vault = PackedBitVault(config.n_bits)
    public_hashers = _public_stream_hashers()
    selected_hashers = {
        name: hashlib.sha256() for name in ("token_ids", "addresses", "values")
    }
    packer = _IncrementalMaskPacker()
    accepted = 0
    core_updates = 0
    core_complete = run_core
    selected_pairs_list: list[tuple[int, int]] = []
    slow_before = gate.slow_state_sha256 if gate is not None else None
    for batch in episode.iter_batches(
        haystack_length,
        cue_mode=cue_mode,
        chunk_tokens=config.chunk_tokens,
    ):
        _update_public_stream_hashers(public_hashers, batch)
        mask = (
            np.ones(batch.length, dtype=np.bool_)
            if all_open
            else gate.mask(batch.events)
        )
        packer.add(mask)
        selected = np.flatnonzero(mask)
        accepted += int(selected.size)
        if selected.size:
            selected_addresses = batch.addresses[selected].astype(np.int64, copy=False)
            selected_values = batch.values[selected].astype(np.uint8, copy=False)
            vault.write_arrays(selected_addresses, selected_values)
            selected_hashers["token_ids"].update(
                batch.token_ids[selected].astype("<u8", copy=False).tobytes(order="C")
            )
            selected_hashers["addresses"].update(
                selected_addresses.astype("<u2", copy=False).tobytes(order="C")
            )
            selected_hashers["values"].update(selected_values.tobytes(order="C"))
            if len(selected_pairs_list) <= config.maximum_core_updates:
                remaining = config.maximum_core_updates + 1 - len(selected_pairs_list)
                selected_pairs_list.extend(
                    (int(address), int(value))
                    for address, value in zip(
                        selected_addresses[:remaining], selected_values[:remaining]
                    )
                )
            if run_core and core is not None:
                for position in selected:
                    if core_updates >= config.maximum_core_updates:
                        core_complete = False
                        break
                    state = _core_update_one(
                        core,
                        state,
                        batch.events[position],
                        batch.address_codes[position],
                        active=True,
                    )
                    core_updates += 1
    mask_bytes = packer.finish()
    if packer.length != config.n_bits + haystack_length:
        raise AssertionError("execution token count differs")
    if accepted > config.maximum_core_updates:
        selected_pairs: tuple[tuple[int, int], ...] | None = None
    else:
        selected_pairs = tuple(selected_pairs_list)
    query_held: bool | None = None
    query_order = episode.query_order()
    if run_core and core is not None and core_complete:
        before_query = state.to_bytes(config.core_config)
        query_addresses = _address_codes(
            query_order,
            n_bits=config.n_bits,
            dimension=config.address_dimension,
        )
        query_events = np.zeros(
            (config.n_bits, config.event_dimension), dtype=np.float32
        )
        with torch.no_grad():
            _encoded, held = core(
                torch.from_numpy(query_events[None, :, :]),
                torch.from_numpy(query_addresses[None, :, :]),
                torch.zeros((1, config.n_bits), dtype=torch.bool),
                state,
            )
        query_held = held.to_bytes(config.core_config) == before_query
        state = held
    value = vault.to_bytes()[: vault.plane_bytes]
    validity = vault.to_bytes()[vault.plane_bytes :]
    value_array = vault.value_array()
    validity_array = vault.validity_array()
    query_values = value_array[query_order]
    query_validity = validity_array[query_order]
    projected_values = np.empty(config.n_bits, dtype=np.uint8)
    projected_validity = np.empty(config.n_bits, dtype=np.uint8)
    projected_values[query_order] = query_values
    projected_validity[query_order] = query_validity
    query_projection_exact = bool(
        np.array_equal(projected_values, value_array)
        and np.array_equal(projected_validity, validity_array)
    )
    query_payload = _pack_mask(query_values.astype(np.bool_)) + _pack_mask(
        query_validity.astype(np.bool_)
    )
    live = state.to_bytes(config.core_config) + vault.to_bytes()
    slow_after = (
        _sha256(canonical_module_bytes(gate.core)) if gate is not None else None
    )
    return PublicExecutionRecord(
        arm=arm,
        seed=episode.seed,
        haystack_length=haystack_length,
        token_count=config.n_bits + haystack_length,
        cue_mode=cue_mode,
        public_stream_sha256=_finish_field_commitment(
            "o1-selective-mqar-public-stream-fields-v1",
            public_hashers,
            length=packer.length,
        ),
        mask_bytes=mask_bytes,
        mask_sha256=_sha256(mask_bytes),
        mask_encoding="all-ones-derived" if all_open else "little-bitpack",
        accepted_tokens=accepted,
        selected_order_sha256=_finish_field_commitment(
            "o1-selective-mqar-selected-order-fields-v1",
            selected_hashers,
            length=accepted,
        ),
        value_plane=value,
        validity_plane=validity,
        prediction_sha256=_sha256(value + validity),
        core_replay=(
            "complete"
            if run_core and core_complete
            else "capped"
            if run_core
            else "not-requested-control"
        ),
        core_updates=core_updates,
        fast_state_bytes=config.core_config.fast_state_bytes(),
        vault_state_bytes=vault.serialized_state_bytes,
        live_state_bytes=live,
        live_state_sha256=_sha256(live),
        query_state_held_exactly=query_held,
        query_order_sha256=_sha256(
            query_order.astype("<u2", copy=False).tobytes(order="C")
        ),
        query_answers_sha256=_sha256(query_payload),
        query_projection_exact=query_projection_exact,
        slow_state_sha256_before=slow_before,
        slow_state_sha256_after=slow_after,
        selected_pairs=selected_pairs,
    )


def literal_compaction_audit(
    episode: PublicEpisode,
    gate: FrozenRouteGate,
) -> dict[str, object]:
    config = episode.config
    batch = episode.collect_audit_projection(
        min(config.literal_audit_tokens, config.n_bits + config.haystack_lengths[-1]),
    )
    predicted = gate.mask(batch.events)

    def replay(*, compact: bool) -> tuple[bytes, bytes, str]:
        state = gate.core.initial_state(1)
        vault = PackedBitVault(config.n_bits)
        accepted_digest = hashlib.sha256()
        for index in range(batch.length):
            active = bool(predicted[index])
            if compact and not active:
                continue
            state = _core_update_one(
                gate.core,
                state,
                batch.events[index],
                batch.address_codes[index],
                active=active,
            )
            if active:
                vault.write(int(batch.addresses[index]), int(batch.values[index]))
                accepted_digest.update(
                    batch.token_ids[index : index + 1]
                    .astype("<u8", copy=False)
                    .tobytes(order="C")
                )
        return (
            state.to_bytes(config.core_config),
            vault.to_bytes(),
            accepted_digest.hexdigest(),
        )

    literal = replay(compact=False)
    compacted = replay(compact=True)
    return {
        "tokens": batch.length,
        "accepted_tokens": int(np.count_nonzero(predicted)),
        "fast_state_equal": literal[0] == compacted[0],
        "vault_equal": literal[1] == compacted[1],
        "accepted_order_equal": literal[2] == compacted[2],
        "byte_exact": literal == compacted,
        "literal_live_sha256": _sha256(literal[0] + literal[1]),
        "compacted_live_sha256": _sha256(compacted[0] + compacted[1]),
    }


def _distractor_only_batches(
    config: SelectiveMQARConfig,
    *,
    seed: int,
) -> Iterator[PublicTokenBatch]:
    # Reuse the exact visible distractor law without constructing a truth ledger.
    codes = _family_codes(config.family_count, config.family_code_seed)
    other = np.asarray(
        [
            family
            for family in range(config.family_count)
            if family != config.relevant_family
        ],
        dtype=np.int64,
    )
    for start in range(0, config.no_binding_length, config.chunk_tokens):
        stop = min(start + config.chunk_tokens, config.no_binding_length)
        local = np.arange(start, stop, dtype=np.int64)
        token_ids = _splitmix64(local.astype(np.uint64), seed ^ 0xD157A6)
        addresses = (local * 197 + (seed & 255)) % config.n_bits
        values = ((local // config.n_bits) & 1).astype(np.uint8)
        families = other[local % other.size]
        events = np.zeros((local.size, config.event_dimension), dtype=np.float32)
        events[:, : config.family_count] = codes[families]
        offset = config.family_count
        events[:, offset] = np.where(values == 1, 0.5, -0.5).astype(np.float32)
        events[:, offset + 1] = (addresses.astype(np.float32) + 0.5) / float(
            config.n_bits
        ) - 0.5
        for nuisance in range(6):
            hashes = _splitmix64(
                token_ids, seed ^ (0x9E37 * (nuisance + 1)) ^ 0xC0DEC0DE
            )
            events[:, offset + 2 + nuisance] = np.where(
                (hashes & np.uint64(1)) == 0, 0.25, -0.25
            ).astype(np.float32)
        yield PublicTokenBatch(
            token_ids=token_ids,
            events=events,
            address_codes=_address_codes(
                addresses,
                n_bits=config.n_bits,
                dimension=config.address_dimension,
            ),
            addresses=addresses,
            values=values,
        )


def no_binding_control(
    config: SelectiveMQARConfig, gate: FrozenRouteGate, *, seed: int
) -> dict[str, object]:
    packer = _IncrementalMaskPacker()
    public_hashers = _public_stream_hashers()
    accepted = 0
    core_updates = 0
    core_complete = True
    state = gate.core.initial_state(1)
    vault = PackedBitVault(config.n_bits)
    initial_live = state.to_bytes(config.core_config) + vault.to_bytes()
    for batch in _distractor_only_batches(config, seed=seed):
        _update_public_stream_hashers(public_hashers, batch)
        mask = gate.mask(batch.events)
        packer.add(mask)
        selected = np.flatnonzero(mask)
        accepted += int(selected.size)
        if selected.size:
            vault.write_arrays(batch.addresses[selected], batch.values[selected])
            for position in selected:
                if core_updates >= config.maximum_core_updates:
                    core_complete = False
                    break
                state = _core_update_one(
                    gate.core,
                    state,
                    batch.events[position],
                    batch.address_codes[position],
                    active=True,
                )
                core_updates += 1
    mask_bytes = packer.finish()
    if accepted > config.maximum_core_updates:
        core_complete = False
    final_live = state.to_bytes(config.core_config) + vault.to_bytes()
    return {
        "seed": seed,
        "tokens": config.no_binding_length,
        "accepted_tokens": accepted,
        "core_updates": core_updates,
        "core_replay": "complete" if core_complete else "capped",
        "mask_bytes": mask_bytes,
        "mask_sha256": _sha256(mask_bytes),
        "public_stream_sha256": _finish_field_commitment(
            "o1-selective-mqar-public-stream-fields-v1",
            public_hashers,
            length=config.no_binding_length,
        ),
        "initial_live_state_sha256": _sha256(initial_live),
        "final_live_state_sha256": _sha256(final_live),
        "state_held_exactly": accepted == 0 and final_live == initial_live,
    }


def _storage_control_predictions(
    record: PublicExecutionRecord,
    config: SelectiveMQARConfig,
) -> dict[str, bytes] | None:
    if record.selected_pairs is None:
        return None
    sketch = CountSketchBitMemory(config.countsketch_slots, seed=record.seed)
    hologram = HolographicBitMemory(config.holographic_channels, seed=record.seed)
    for address, value in record.selected_pairs:
        sketch.write(address, value)
        hologram.write(address, value)
    sketch_bits = np.asarray(
        [sketch.read(address) for address in range(config.n_bits)], dtype=np.uint8
    )
    hologram_bits = np.asarray(
        [hologram.read(address) for address in range(config.n_bits)], dtype=np.uint8
    )
    return {
        "countsketch": np.packbits(sketch_bits, bitorder="little").tobytes(),
        "holographic": np.packbits(hologram_bits, bitorder="little").tobytes(),
    }


def _record_freeze_view(
    record: PublicExecutionRecord,
    *,
    prediction_offset: int,
    mask_offset: int | None,
    live_state_offset: int | None,
) -> dict[str, object]:
    return {
        "arm": record.arm,
        "seed": record.seed,
        "haystack_length": record.haystack_length,
        "token_count": record.token_count,
        "cue_mode": record.cue_mode,
        "public_stream_sha256": record.public_stream_sha256,
        "mask_sha256": record.mask_sha256,
        "mask_encoding": record.mask_encoding,
        "mask_bytes": len(record.mask_bytes),
        "mask_offset": mask_offset,
        "accepted_tokens": record.accepted_tokens,
        "selected_order_sha256": record.selected_order_sha256,
        "prediction_sha256": record.prediction_sha256,
        "prediction_offset": prediction_offset,
        "prediction_bytes": len(record.value_plane) + len(record.validity_plane),
        "core_replay": record.core_replay,
        "core_updates": record.core_updates,
        "fast_state_bytes": record.fast_state_bytes,
        "vault_state_bytes": record.vault_state_bytes,
        "live_state_bytes": len(record.live_state_bytes),
        "live_state_sha256": record.live_state_sha256,
        "live_state_offset": live_state_offset,
        "query_state_held_exactly": record.query_state_held_exactly,
        "query_order_sha256": record.query_order_sha256,
        "query_answers_sha256": record.query_answers_sha256,
        "query_projection_exact": record.query_projection_exact,
        "slow_state_sha256_before": record.slow_state_sha256_before,
        "slow_state_sha256_after": record.slow_state_sha256_after,
    }


def _score_record(
    record: PublicExecutionRecord,
    truth: RevealedTruth,
    *,
    n_bits: int,
) -> dict[str, object]:
    predicted_mask = (
        np.ones(record.token_count, dtype=np.bool_)
        if record.mask_encoding == "all-ones-derived"
        else np.unpackbits(
            np.frombuffer(record.mask_bytes, dtype=np.uint8),
            bitorder="little",
            count=record.token_count,
        ).astype(np.bool_, copy=False)
    )
    route = np.unpackbits(
        np.frombuffer(truth.route_masks[record.haystack_length], dtype=np.uint8),
        bitorder="little",
        count=truth.route_lengths[record.haystack_length],
    ).astype(np.bool_, copy=False)
    values = np.unpackbits(
        np.frombuffer(record.value_plane, dtype=np.uint8),
        bitorder="little",
        count=n_bits,
    ).astype(np.uint8, copy=False)
    validity = np.unpackbits(
        np.frombuffer(record.validity_plane, dtype=np.uint8),
        bitorder="little",
        count=n_bits,
    ).astype(np.uint8, copy=False)
    valid = validity.astype(np.bool_)
    correct = valid & (values == truth.secret_bits)
    true_positive = int(np.count_nonzero(predicted_mask & route))
    false_positive = int(np.count_nonzero(predicted_mask & ~route))
    false_negative = int(np.count_nonzero(~predicted_mask & route))
    true_negative = int(np.count_nonzero(~predicted_mask & ~route))
    correct_bits = int(np.count_nonzero(correct))
    valid_bits = int(np.count_nonzero(valid))
    revealed_query_sha256 = _sha256(
        truth.query_order.astype("<u2", copy=False).tobytes(order="C")
    )
    return {
        "arm": record.arm,
        "seed": record.seed,
        "haystack_length": record.haystack_length,
        "public_stream_sha256": record.public_stream_sha256,
        "mask_sha256": record.mask_sha256,
        "prediction_sha256": record.prediction_sha256,
        "correct_bits": correct_bits,
        "valid_bits": valid_bits,
        "bit_accuracy": correct_bits / n_bits,
        "exact_recall": correct_bits == n_bits and valid_bits == n_bits,
        "true_positives": true_positive,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "true_negatives": true_negative,
        "route_exact": false_positive == 0 and false_negative == 0,
        "accepted_tokens": record.accepted_tokens,
        "query_state_held_exactly": record.query_state_held_exactly,
        "query_order_matches_reveal": record.query_order_sha256
        == revealed_query_sha256,
        "query_projection_exact": record.query_projection_exact,
        "live_state_sha256": record.live_state_sha256,
        "core_replay": record.core_replay,
    }


def _post_freeze_oracle_replay(
    config: SelectiveMQARConfig,
    *,
    seed: int,
    truth: RevealedTruth,
    expected_public_sha256: Mapping[int, str],
) -> list[dict[str, object]]:
    """Execute the revealed route-mask ceiling only after predictions are frozen."""

    episode = PublicEpisode(config, seed)
    rows: list[dict[str, object]] = []
    for length in config.haystack_lengths:
        route = np.unpackbits(
            np.frombuffer(truth.route_masks[length], dtype=np.uint8),
            bitorder="little",
            count=truth.route_lengths[length],
        ).astype(np.bool_, copy=False)
        if route.size != config.n_bits + length:
            raise SelectiveMQARError("oracle route-mask width differs")
        vault = PackedBitVault(config.n_bits)
        public_hashers = _public_stream_hashers()
        cursor = 0
        accepted = 0
        for batch in episode.iter_batches(length):
            _update_public_stream_hashers(public_hashers, batch)
            batch_route = route[cursor : cursor + batch.length]
            selected = np.flatnonzero(batch_route)
            vault.write_arrays(batch.addresses[selected], batch.values[selected])
            accepted += int(selected.size)
            cursor += batch.length
        if cursor != route.size:
            raise SelectiveMQARError("oracle replay did not consume its route mask")
        public_sha256 = _finish_field_commitment(
            "o1-selective-mqar-public-stream-fields-v1",
            public_hashers,
            length=route.size,
        )
        values = vault.value_array()
        validity = vault.validity_array().astype(np.bool_)
        correct = validity & (values == truth.secret_bits)
        correct_bits = int(np.count_nonzero(correct))
        valid_bits = int(np.count_nonzero(validity))
        rows.append(
            {
                "seed": seed,
                "haystack_length": length,
                "execution_phase": "POST_PREDICTION_FREEZE_AFTER_TRUTH_REVEAL",
                "public_stream_sha256": public_sha256,
                "public_stream_matches_primary_freeze": public_sha256
                == expected_public_sha256[length],
                "accepted_tokens": accepted,
                "correct_bits": correct_bits,
                "valid_bits": valid_bits,
                "exact_recall": correct_bits == config.n_bits
                and valid_bits == config.n_bits,
                "vault_sha256": vault.sha256(),
            }
        )
    return rows


@dataclass(frozen=True)
class SelectiveMQARResult:
    report: Mapping[str, object]
    success_gate_passed: bool


def run_selective_mqar(
    config: SelectiveMQARConfig,
    *,
    on_gate_frozen: (
        Callable[[Mapping[str, bytes], Mapping[str, object]], None] | None
    ) = None,
    on_predictions_frozen: (
        Callable[[Mapping[str, bytes], Mapping[str, object]], None] | None
    ) = None,
) -> SelectiveMQARResult:
    """Train, freeze, execute, freeze predictions, reveal, and score O1C-0020."""

    require_torch()
    torch.set_num_threads(config.cpu_threads)
    try:
        torch.set_num_interop_threads(config.cpu_threads)
    except RuntimeError:
        # PyTorch permits this setting only before the first parallel operation.
        if torch.get_num_interop_threads() != config.cpu_threads:
            raise

    primary = train_route_gate(config, name="primary", shuffled_labels=False)
    shuffled = train_route_gate(
        config,
        name="shuffled_label",
        shuffled_labels=True,
        fixed_threshold=primary.threshold,
    )
    untrained = untrained_route_gate(config, threshold=primary.threshold)
    if primary.initial_state_sha256 != shuffled.initial_state_sha256:
        raise SelectiveMQARError(
            "primary and shuffled gates did not share initialization"
        )
    gate_document: dict[str, object] = {
        "schema": GATE_FREEZE_SCHEMA,
        "phase": "SLOW_STATES_FROZEN_BEFORE_EVALUATION_STREAM_GENERATION",
        "evaluation_streams_generated": 0,
        "evaluation_tokens_seen": 0,
        "evaluation_slow_updates": 0,
        "threshold": primary.threshold,
        "threshold_source": "CAL_MIDPOINT_PLUS_FROZEN_OFFSET",
        "calibration_threshold_offset": config.calibration_threshold_offset,
        "primary": {
            "initial_state_sha256": primary.initial_state_sha256,
            "slow_state_sha256": primary.slow_state_sha256,
            "slow_state_bytes": len(primary.slow_state_bytes),
            "changed_parameters": list(primary.changed_parameters),
            "training": dict(primary.training_metrics),
            "calibration": dict(primary.calibration_metrics),
        },
        "shuffled_label": {
            "initial_state_sha256": shuffled.initial_state_sha256,
            "slow_state_sha256": shuffled.slow_state_sha256,
            "slow_state_bytes": len(shuffled.slow_state_bytes),
            "changed_parameters": list(shuffled.changed_parameters),
            "training": dict(shuffled.training_metrics),
            "calibration": dict(shuffled.calibration_metrics),
        },
        "untrained": {
            "slow_state_sha256": untrained.slow_state_sha256,
            "slow_state_bytes": len(untrained.slow_state_bytes),
        },
    }
    gate_commitment = {
        "primary_gate_sha256": primary.slow_state_sha256,
        "shuffled_gate_sha256": shuffled.slow_state_sha256,
        "untrained_gate_sha256": untrained.slow_state_sha256,
        "document_without_freeze_sha256": _sha256(_canonical_json(gate_document)),
    }
    gate_document["freeze_sha256"] = _sha256(_canonical_json(gate_commitment))
    gate_artifacts = {
        "gate_freeze.json": _canonical_json(gate_document),
        "primary_gate_slow_state.bin": primary.slow_state_bytes,
        "shuffled_gate_slow_state.bin": shuffled.slow_state_bytes,
        "untrained_gate_slow_state.bin": untrained.slow_state_bytes,
    }
    if on_gate_frozen is not None:
        on_gate_frozen(gate_artifacts, gate_document)

    records: list[PublicExecutionRecord] = []
    ledgers: dict[int, SealedTruthLedger] = {}
    audit_episode: PublicEpisode | None = None
    storage_predictions: dict[tuple[int, int], dict[str, bytes] | None] = {}
    arms = (
        ("primary", primary, "identity", True, False),
        ("shuffled_label", shuffled, "identity", False, False),
        ("untrained", untrained, "identity", False, False),
        ("cue_rotated", primary, "rotate", False, False),
        ("cue_ablated", primary, "ablate", False, False),
        ("all_open", None, "identity", False, True),
    )
    for seed in config.evaluation_seeds:
        episode, ledger = build_public_episode(config, seed)
        if audit_episode is None:
            audit_episode = episode
        ledgers[seed] = ledger
        for length in config.haystack_lengths:
            for arm, gate, cue_mode, run_core, all_open in arms:
                record = execute_public_episode(
                    episode,
                    haystack_length=length,
                    arm=arm,
                    gate=gate,
                    cue_mode=cue_mode,
                    run_core=run_core,
                    all_open=all_open,
                )
                records.append(record)
                if arm == "primary":
                    storage_predictions[(seed, length)] = _storage_control_predictions(
                        record, config
                    )

    if audit_episode is None:  # pragma: no cover - config forbids empty EVAL.
        raise AssertionError("evaluation episode is absent")
    literal_audit = literal_compaction_audit(audit_episode, primary)
    del audit_episode
    del episode
    no_binding = no_binding_control(
        config,
        primary,
        seed=config.evaluation_seeds[-1] ^ 0x0B1D1A6,
    )
    if any(ledger.reveal_count != 0 for ledger in ledgers.values()):
        raise TruthAccessError("evaluation truth was accessed before prediction freeze")

    prediction_blob = bytearray()
    primary_mask_blob = bytearray()
    primary_live_blob = bytearray()
    storage_blob = bytearray()
    freeze_rows: list[dict[str, object]] = []
    for record in records:
        prediction_offset = len(prediction_blob)
        prediction_blob.extend(record.value_plane)
        prediction_blob.extend(record.validity_plane)
        mask_offset = None
        live_offset = None
        if record.arm == "primary":
            mask_offset = len(primary_mask_blob)
            primary_mask_blob.extend(record.mask_bytes)
            live_offset = len(primary_live_blob)
            primary_live_blob.extend(record.live_state_bytes)
        freeze_rows.append(
            _record_freeze_view(
                record,
                prediction_offset=prediction_offset,
                mask_offset=mask_offset,
                live_state_offset=live_offset,
            )
        )
    storage_index: list[dict[str, object]] = []
    for key in sorted(storage_predictions):
        predictions = storage_predictions[key]
        if predictions is None:
            storage_index.append(
                {"seed": key[0], "haystack_length": key[1], "available": False}
            )
            continue
        row: dict[str, object] = {
            "seed": key[0],
            "haystack_length": key[1],
            "available": True,
            "arms": {},
        }
        arm_index: dict[str, object] = {}
        for name in sorted(predictions):
            offset = len(storage_blob)
            payload = predictions[name]
            storage_blob.extend(payload)
            arm_index[name] = {
                "offset": offset,
                "bytes": len(payload),
                "sha256": _sha256(payload),
            }
        row["arms"] = arm_index
        storage_index.append(row)
    no_binding_mask = no_binding.pop("mask_bytes")
    prediction_document: dict[str, object] = {
        "schema": PREDICTION_FREEZE_SCHEMA,
        "phase": "ALL_PUBLIC_RECALLS_FROZEN_BEFORE_TRUTH_REVEAL",
        "truth_ledger_reveal_count": 0,
        "scorer_calls": 0,
        "evaluation_slow_updates": 0,
        "primary_gate_sha256": primary.slow_state_sha256,
        "shuffled_gate_sha256": shuffled.slow_state_sha256,
        "untrained_gate_sha256": untrained.slow_state_sha256,
        "records": freeze_rows,
        "storage_controls": storage_index,
        "literal_compaction_audit": literal_audit,
        "no_binding_control": no_binding,
        "binary_artifacts": {
            "recalls.bin": {
                "bytes": len(prediction_blob),
                "sha256": _sha256(bytes(prediction_blob)),
            },
            "primary_masks.bitpack": {
                "bytes": len(primary_mask_blob),
                "sha256": _sha256(bytes(primary_mask_blob)),
            },
            "primary_live_states.bin": {
                "bytes": len(primary_live_blob),
                "sha256": _sha256(bytes(primary_live_blob)),
            },
            "storage_predictions.bitpack": {
                "bytes": len(storage_blob),
                "sha256": _sha256(bytes(storage_blob)),
            },
            "no_binding_mask.bitpack": {
                "bytes": len(no_binding_mask),
                "sha256": _sha256(no_binding_mask),
            },
        },
    }
    prediction_commitment = {
        "document_without_freeze_sha256": _sha256(_canonical_json(prediction_document)),
        "artifact_sha256": {
            "recalls.bin": _sha256(bytes(prediction_blob)),
            "primary_masks.bitpack": _sha256(bytes(primary_mask_blob)),
            "primary_live_states.bin": _sha256(bytes(primary_live_blob)),
            "storage_predictions.bitpack": _sha256(bytes(storage_blob)),
            "no_binding_mask.bitpack": _sha256(no_binding_mask),
        },
    }
    prediction_document["freeze_sha256"] = _sha256(
        _canonical_json(prediction_commitment)
    )
    prediction_artifacts = {
        "prediction_freeze.json": _canonical_json(prediction_document),
        "recalls.bin": bytes(prediction_blob),
        "primary_masks.bitpack": bytes(primary_mask_blob),
        "primary_live_states.bin": bytes(primary_live_blob),
        "storage_predictions.bitpack": bytes(storage_blob),
        "no_binding_mask.bitpack": no_binding_mask,
    }
    if on_predictions_frozen is not None:
        on_predictions_frozen(prediction_artifacts, prediction_document)
    if any(ledger.reveal_count != 0 for ledger in ledgers.values()):
        raise TruthAccessError("truth was accessed inside prediction freeze")

    revealed = {seed: ledgers[seed].reveal() for seed in config.evaluation_seeds}
    scores = [
        _score_record(record, revealed[record.seed], n_bits=config.n_bits)
        for record in records
    ]
    storage_scores: list[dict[str, object]] = []
    for key in sorted(storage_predictions):
        prediction = storage_predictions[key]
        truth = revealed[key[0]].secret_bits
        if prediction is None:
            storage_scores.append(
                {"seed": key[0], "haystack_length": key[1], "available": False}
            )
            continue
        for name, payload in sorted(prediction.items()):
            bits = np.unpackbits(
                np.frombuffer(payload, dtype=np.uint8),
                bitorder="little",
                count=config.n_bits,
            )
            correct = int(np.count_nonzero(bits == truth))
            storage_scores.append(
                {
                    "seed": key[0],
                    "haystack_length": key[1],
                    "arm": name,
                    "available": True,
                    "correct_bits": correct,
                    "bit_accuracy": correct / config.n_bits,
                    "exact_recall": correct == config.n_bits,
                }
            )

    primary_scores = [row for row in scores if row["arm"] == "primary"]
    control_names = (
        "shuffled_label",
        "untrained",
        "cue_rotated",
        "cue_ablated",
        "all_open",
    )
    control_summary: dict[str, object] = {}
    for name in control_names:
        rows = [row for row in scores if row["arm"] == name]
        longest_rows = [
            row for row in rows if row["haystack_length"] == config.haystack_lengths[-1]
        ]
        control_summary[name] = {
            "cells": len(rows),
            "exact_cells": sum(bool(row["exact_recall"]) for row in rows),
            "all_exact": all(bool(row["exact_recall"]) for row in rows),
            "longest_cells": len(longest_rows),
            "longest_exact_cells": sum(
                bool(row["exact_recall"]) for row in longest_rows
            ),
            "all_longest_fail_exact": bool(longest_rows)
            and all(not bool(row["exact_recall"]) for row in longest_rows),
            "all_longest_strictly_below_primary": bool(longest_rows)
            and all(float(row["bit_accuracy"]) < 1.0 for row in longest_rows),
            "mean_bit_accuracy": float(
                np.mean([float(row["bit_accuracy"]) for row in rows])
            ),
            "total_false_positives": sum(int(row["false_positives"]) for row in rows),
            "total_false_negatives": sum(int(row["false_negatives"]) for row in rows),
        }
    storage_summary: dict[str, object] = {}
    for name in ("countsketch", "holographic"):
        rows = [
            row
            for row in storage_scores
            if row.get("available") is True and row.get("arm") == name
        ]
        storage_summary[name] = {
            "cells": len(rows),
            "exact_cells": sum(bool(row["exact_recall"]) for row in rows),
            "all_available": len(rows)
            == len(config.evaluation_seeds) * len(config.haystack_lengths),
            "all_exact": bool(rows) and all(bool(row["exact_recall"]) for row in rows),
            "longest_exact_cells": sum(
                bool(row["exact_recall"])
                for row in rows
                if row["haystack_length"] == config.haystack_lengths[-1]
            ),
            "all_longest_fail_exact": all(
                not bool(row["exact_recall"])
                for row in rows
                if row["haystack_length"] == config.haystack_lengths[-1]
            ),
            "mean_bit_accuracy": (
                float(np.mean([float(row["bit_accuracy"]) for row in rows]))
                if rows
                else None
            ),
        }
    nested_state_exact = True
    nested_prediction_exact = True
    for seed in config.evaluation_seeds:
        rows = [
            record
            for record in records
            if record.arm == "primary" and record.seed == seed
        ]
        nested_state_exact &= len({row.live_state_sha256 for row in rows}) == 1
        nested_prediction_exact &= len({row.prediction_sha256 for row in rows}) == 1
    gate_token_evaluations = (
        sum(record.token_count for record in records if record.arm != "all_open")
        + config.no_binding_length
    )
    oracle_rows: list[dict[str, object]] = []
    for seed in config.evaluation_seeds:
        expected_public = {
            record.haystack_length: record.public_stream_sha256
            for record in records
            if record.arm == "primary" and record.seed == seed
        }
        oracle_rows.extend(
            _post_freeze_oracle_replay(
                config,
                seed=seed,
                truth=revealed[seed],
                expected_public_sha256=expected_public,
            )
        )
    gates = {
        "primary_all_cells_exact_256_of_256": all(
            row["correct_bits"] == config.n_bits
            and row["valid_bits"] == config.n_bits
            and bool(row["exact_recall"])
            for row in primary_scores
        ),
        "primary_all_routes_exact": all(
            bool(row["route_exact"]) for row in primary_scores
        ),
        "primary_core_replay_complete": all(
            row["core_replay"] == "complete" for row in primary_scores
        ),
        "primary_queries_hold_state": all(
            row["query_state_held_exactly"] is True for row in primary_scores
        ),
        "primary_random_query_projection_exact": all(
            bool(row["query_projection_exact"])
            and bool(row["query_order_matches_reveal"])
            for row in primary_scores
        ),
        "primary_slow_state_unchanged": all(
            record.slow_state_sha256_before == record.slow_state_sha256_after
            for record in records
            if record.arm == "primary"
        ),
        "primary_nested_live_state_exact": nested_state_exact,
        "primary_nested_prediction_exact": nested_prediction_exact,
        "literal_compaction_byte_exact": bool(literal_audit["byte_exact"]),
        "literal_compaction_mixes_all_bindings_and_rejections": int(
            literal_audit["accepted_tokens"]
        )
        == config.n_bits
        and int(literal_audit["tokens"]) > config.n_bits,
        "calibration_zero_errors": bool(primary.calibration_metrics["zero_errors"]),
        "calibration_positive_margin": float(
            primary.calibration_metrics["minimum_signed_margin"]
        )
        > 0.0,
        "global_public_route_certificate_positive": bool(
            primary.calibration_metrics["global_public_token_certificate"][
                "all_legal_public_tokens_separated"
            ]
        )
        and float(
            primary.calibration_metrics["global_public_token_certificate"][
                "certified_margin"
            ]
        )
        > 0.0,
        "no_binding_zero_accepts": int(no_binding["accepted_tokens"]) == 0,
        "no_binding_state_held": bool(no_binding["state_held_exactly"])
        and no_binding["core_replay"] == "complete",
        "oracle_all_exact": all(
            bool(row["exact_recall"])
            and bool(row["public_stream_matches_primary_freeze"])
            and int(row["accepted_tokens"]) == config.n_bits
            for row in oracle_rows
        ),
        "registered_controls_not_all_exact": all(
            not bool(control_summary[name]["all_exact"]) for name in control_names
        ),
        "every_control_fails_every_longest_cell": all(
            bool(control_summary[name]["all_longest_fail_exact"])
            and bool(control_summary[name]["all_longest_strictly_below_primary"])
            for name in control_names
        ),
        "storage_controls_available_and_not_all_exact": all(
            bool(storage_summary[name]["all_available"])
            and not bool(storage_summary[name]["all_exact"])
            and bool(storage_summary[name]["all_longest_fail_exact"])
            for name in storage_summary
        ),
        "truth_revealed_once_after_freeze": all(
            ledger.reveal_count == 1 for ledger in ledgers.values()
        ),
        "live_state_width_exact": all(
            len(record.live_state_bytes) == config.live_state_bytes
            for record in records
            if record.arm == "primary"
        ),
    }
    success = all(bool(value) for value in gates.values())
    if success:
        classification = "EXACT_256_LEARNED_GATE_RETENTION"
    elif not gates["calibration_zero_errors"]:
        classification = "GATE_NOT_SEPARATED_ON_CALIBRATION"
    elif not gates["primary_all_routes_exact"]:
        classification = "LEARNED_GATE_OOD_ROUTE_FAILURE"
    elif not gates["primary_all_cells_exact_256_of_256"]:
        classification = "VAULT_RETENTION_FAILURE"
    else:
        classification = "MECHANISM_INVARIANT_FAILURE"

    report: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "classification": classification,
        "scientific_success_gate_passed": success,
        "claim_boundary": (
            "synthetic learned public-token routing plus exact positional Bit-Vault "
            "retention; no cipher inversion or holographic-compression claim"
        ),
        "state": {
            "o1_fast_state_bytes": config.core_config.fast_state_bytes(),
            "vault_bytes": config.vault_bytes,
            "total_live_state_bytes": config.live_state_bytes,
            "model_stream_length_dependent_state_bytes": 0,
            "model_retained_transcript_bytes": 0,
            "model_external_index_bytes": 0,
            "audit_evaluator_state_excluded_from_model_live_state": True,
            "audit_masks_retained_in_evaluator_bytes": sum(
                len(record.mask_bytes) for record in records
            )
            + len(no_binding_mask),
            "audit_masks_persisted_bytes": len(primary_mask_blob)
            + len(no_binding_mask),
            "prediction_freeze_artifact_bytes": sum(
                len(payload) for payload in prediction_artifacts.values()
            ),
            "primary_slow_state_bytes": len(primary.slow_state_bytes),
            "primary_slow_state_sha256": primary.slow_state_sha256,
            "primary_slow_parameter_count": sum(
                int(parameter.numel()) for parameter in primary.core.parameters()
            ),
            "primary_slow_raw_float32_bytes": 4
            * sum(int(parameter.numel()) for parameter in primary.core.parameters()),
            "slow_state_billed_separately": True,
        },
        "splits": {
            "build_seeds": list(config.build_seeds),
            "calibration_seeds": list(config.calibration_seeds),
            "evaluation_seeds": list(config.evaluation_seeds),
            "haystack_lengths": list(config.haystack_lengths),
            "no_binding_length": config.no_binding_length,
        },
        "gate_training": {
            "primary": {
                "training": dict(primary.training_metrics),
                "calibration": dict(primary.calibration_metrics),
            },
            "shuffled_label": {
                "training": dict(shuffled.training_metrics),
                "calibration": dict(shuffled.calibration_metrics),
            },
        },
        "primary_cells": primary_scores,
        "all_cells": scores,
        "controls": control_summary,
        "storage_controls": storage_scores,
        "storage_control_summary": storage_summary,
        "oracle_ceiling": oracle_rows,
        "literal_compaction_audit": literal_audit,
        "no_binding_control": no_binding,
        "gates": gates,
        "freeze": {
            "gate_freeze_sha256": gate_document["freeze_sha256"],
            "prediction_freeze_sha256": prediction_document["freeze_sha256"],
        },
        "work": {
            "unique_evaluation_public_tokens": len(config.evaluation_seeds)
            * (config.n_bits + config.haystack_lengths[-1]),
            "gate_token_evaluations": gate_token_evaluations
            + int(literal_audit["tokens"])
            + 2
            * len(config.calibration_seeds)
            * 2
            * config.calibration_examples_per_class,
            "primary_core_updates": sum(
                record.core_updates for record in records if record.arm == "primary"
            ),
            "literal_core_token_calls": int(literal_audit["tokens"])
            + int(literal_audit["accepted_tokens"]),
            "literal_core_updates": 2 * int(literal_audit["accepted_tokens"]),
            "no_binding_core_updates": int(no_binding["core_updates"]),
            "oracle_public_tokens_replayed_post_freeze": len(config.evaluation_seeds)
            * sum(config.n_bits + length for length in config.haystack_lengths),
            "primary_vault_writes": sum(
                record.accepted_tokens for record in records if record.arm == "primary"
            ),
            "query_tokens": len(primary_scores) * config.n_bits,
            "scientific_entropy_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "native_solver_branches": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
        },
    }
    report["result_sha256"] = _sha256(_canonical_json(report))
    return SelectiveMQARResult(report=report, success_gate_passed=success)


__all__ = [
    "GATE_FREEZE_SCHEMA",
    "PREDICTION_FREEZE_SCHEMA",
    "RESULT_SCHEMA",
    "SELECTIVE_MQAR_SCHEMA",
    "FrozenRouteGate",
    "PackedBitVault",
    "PublicEpisode",
    "PublicExecutionRecord",
    "PublicTokenBatch",
    "RevealedTruth",
    "SealedTruthLedger",
    "SelectiveMQARConfig",
    "SelectiveMQARError",
    "SelectiveMQARResult",
    "TruthAccessError",
    "build_public_episode",
    "canonical_module_bytes",
    "execute_public_episode",
    "literal_compaction_audit",
    "no_binding_control",
    "run_selective_mqar",
    "train_route_gate",
    "untrained_route_gate",
]
