"""Allocation-invariant full-256 polyphase state with a self-describing V2 ABI.

O1C-0027 used one vectorized complex64 recurrence expression.  On the local
NumPy/macOS runtime that expression can select fused or unfused arithmetic from
pointer alignment, yielding two one-ULP state variants.  V2 makes every real
float32 operation and rounding point explicit, includes that schedule in a new
basis commitment, and prefixes serialized state bytes with the basis digest.
Legacy O1C-0027 bytes therefore cannot be reinterpreted as V2 state.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping

import numpy as np

from .polyphase_sufficient_state import (
    GAINS as _LEGACY_GAINS,
    POLES as _LEGACY_POLES,
    PolyphaseSufficientStateError,
    ReplayRequiredError,
)


KEY_BITS = 256
WAVELENGTHS = (64, 96, 65)
TIMESCALES = (1, 2, 4, 8)
HORIZON_COUNT = len(WAVELENGTHS)
POLE_COUNT = len(TIMESCALES)
SLOT_SHAPE = (HORIZON_COUNT, POLE_COUNT, KEY_BITS)
SLOT_BYTES = math.prod(SLOT_SHAPE) * np.dtype("<c8").itemsize
COVERAGE_BYTES = KEY_BITS * np.dtype("<u2").itemsize
CLOCK_BYTES = np.dtype("<u8").itemsize
BASIS_PREFIX_BYTES = hashlib.sha256().digest_size
CORE_STATE_BYTES = SLOT_BYTES + COVERAGE_BYTES + CLOCK_BYTES
STATE_BYTES = BASIS_PREFIX_BYTES + CORE_STATE_BYTES
BASIS_SCHEMA = "o1-256-polyphase-sufficient-state-basis-v2"
STATE_SCHEMA = "o1-256-polyphase-sufficient-state-v2"
READOUT_SCHEMA = "o1-256-polyphase-readout-v2"
REFERENCE_SCHEMA = "o1-256-polyphase-reference-state-v2"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise PolyphaseSufficientStateError(
            "V2 basis descriptor is not canonical JSON"
        ) from exc
    return rendered.encode("ascii")


def basis_sha256_from_descriptor(value: Mapping[str, object]) -> str:
    if not isinstance(value, Mapping):
        raise PolyphaseSufficientStateError("V2 basis descriptor must be a mapping")
    return hashlib.sha256(_canonical_json_bytes(dict(value))).hexdigest()


def _build_basis() -> tuple[np.ndarray, np.ndarray, dict[str, object]]:
    poles = np.frombuffer(
        _LEGACY_POLES.astype("<c8", copy=False).tobytes(order="C"), dtype="<c8"
    ).reshape((HORIZON_COUNT, POLE_COUNT))
    gains = np.frombuffer(
        _LEGACY_GAINS.astype("<f4", copy=False).tobytes(order="C"), dtype="<f4"
    ).reshape((HORIZON_COUNT, POLE_COUNT))
    pole_bytes = poles.tobytes(order="C")
    gain_bytes = gains.tobytes(order="C")
    descriptor: dict[str, object] = {
        "schema": BASIS_SCHEMA,
        "abi_revision": 2,
        "encoder": {
            "coordinate_order": "ascending-key-bit-0-through-255",
            "group_dtype": "float32",
            "group_shape": [HORIZON_COUNT, KEY_BITS],
            "null_is_observed": True,
        },
        "kernel": {
            "mathematical_recurrence": "Z_next=a*Z+g*X",
            "production_rounding_schedule": [
                "r0=float32(ar*zr)",
                "r1=float32(ai*zi)",
                "real_product=float32(r0-r1)",
                "i0=float32(ar*zi)",
                "i1=float32(ai*zr)",
                "imaginary=float32(i0+i1)",
                "drive=float32(g*x)",
                "real=float32(real_product+drive)",
                "complex64=assemble(real,imaginary)",
            ],
            "operation_fusion": "forbidden-between-listed-rounding-points",
            "floating_error_policy": {
                "divide": "raise",
                "over": "raise",
                "invalid": "raise",
                "under": "ignore-and-round-to-float32",
                "ambient_numpy_seterr": "overridden-locally",
            },
            "timescales": list(TIMESCALES),
            "poles_c64le_sha256": hashlib.sha256(pole_bytes).hexdigest(),
            "gains_f32le_sha256": hashlib.sha256(gain_bytes).hexdigest(),
        },
        "readout": {
            "schedule": "twelve-float32-products-and-left-to-right-float32-sums",
            "temperature_storage": "positive-finite-float32-frozen-at-spec-construction",
            "temperature_division": "one-final-float32-division-per-coordinate",
            "bias": False,
        },
        "phase": {
            "rule": "positive-complex-resonator-exp(+2pi*i/wavelength)",
            "wavelengths": list(WAVELENGTHS),
            "phase_is_independent_of_coverage_counter": True,
        },
        "state": {
            "slot_shape": list(SLOT_SHAPE),
            "slot_dtype": "complex64",
            "coverage_dtype": "uint16-saturating",
            "clock_dtype": "uint64",
            "basis_prefix_bytes": BASIS_PREFIX_BYTES,
            "core_state_bytes": CORE_STATE_BYTES,
            "persistent_bytes": STATE_BYTES,
            "stream_length_dependent": False,
        },
    }
    poles.setflags(write=False)
    gains.setflags(write=False)
    return poles, gains, descriptor


_POLES, _GAINS, _BASIS_DESCRIPTOR = _build_basis()
POLES = _POLES
GAINS = _GAINS
BASIS_SHA256 = basis_sha256_from_descriptor(_BASIS_DESCRIPTOR)
_BASIS_PREFIX = bytes.fromhex(BASIS_SHA256)


def basis_descriptor() -> dict[str, object]:
    return json.loads(json.dumps(_BASIS_DESCRIPTOR, allow_nan=False))


@dataclass(frozen=True)
class PolyphaseReadoutSpec:
    """Late-bound odd V2 readout over one exact recurrence basis."""

    name: str
    basis_sha256: str
    slot_weights: np.ndarray
    temperature: float

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > 96:
            raise PolyphaseSufficientStateError("V2 readout name is required")
        if not isinstance(self.basis_sha256, str) or not _SHA256_RE.fullmatch(
            self.basis_sha256
        ):
            raise PolyphaseSufficientStateError(
                "V2 readout basis_sha256 must be lowercase SHA-256"
            )
        weights = np.asarray(self.slot_weights)
        if (
            weights.dtype != np.float32
            or weights.shape != (HORIZON_COUNT, POLE_COUNT)
            or not np.all(np.isfinite(weights))
            or not bool(np.any(weights != 0.0))
        ):
            raise PolyphaseSufficientStateError(
                "V2 readout weights must be finite nonzero float32[3,4]"
            )
        frozen = np.frombuffer(
            np.array(weights, dtype="<f4", order="C", copy=True).tobytes(order="C"),
            dtype="<f4",
        ).reshape((HORIZON_COUNT, POLE_COUNT))
        frozen.setflags(write=False)
        object.__setattr__(self, "slot_weights", frozen)
        if (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, (int, float))
            or not math.isfinite(float(self.temperature))
            or not 0.0 < float(self.temperature) <= 1_000_000.0
        ):
            raise PolyphaseSufficientStateError(
                "V2 readout temperature must be finite and positive"
            )
        with np.errstate(over="ignore", under="ignore", invalid="ignore"):
            temperature32 = np.float32(self.temperature)
        if not np.isfinite(temperature32) or temperature32 <= 0.0:
            raise PolyphaseSufficientStateError(
                "V2 readout temperature must be positive finite float32"
            )
        object.__setattr__(self, "temperature", float(temperature32))

    def describe(self) -> dict[str, object]:
        return {
            "schema": READOUT_SCHEMA,
            "name": self.name,
            "basis_sha256": self.basis_sha256,
            "slot_weights": self.slot_weights.tolist(),
            "temperature": self.temperature,
            "odd_without_bias": True,
        }


def _validated_chunk(chunk: object) -> np.ndarray:
    if not isinstance(chunk, np.ndarray) or chunk.dtype != np.float32:
        raise PolyphaseSufficientStateError(
            "each V2 stream chunk must be a float32 ndarray"
        )
    if chunk.shape == (HORIZON_COUNT, KEY_BITS):
        batch = chunk.reshape((1, HORIZON_COUNT, KEY_BITS))
    elif (
        chunk.ndim == 3
        and chunk.shape[0] > 0
        and chunk.shape[1:] == (HORIZON_COUNT, KEY_BITS)
    ):
        batch = chunk
    else:
        raise PolyphaseSufficientStateError(
            "each V2 stream chunk must have shape [3,256] or [N,3,256]"
        )
    if not np.all(np.isfinite(batch)):
        raise PolyphaseSufficientStateError("V2 stream chunk contains non-finite values")
    return batch


def _iter_groups(chunks: Iterable[np.ndarray] | np.ndarray) -> Iterator[np.ndarray]:
    source: Iterable[object]
    if isinstance(chunks, np.ndarray):
        source = (chunks,)
    else:
        try:
            source = iter(chunks)
        except TypeError as exc:
            raise PolyphaseSufficientStateError("V2 chunks must be iterable") from exc
    for chunk in source:
        for group in _validated_chunk(chunk):
            yield group


class PolyphaseSufficientState:
    """Exactly 25,128 self-describing bytes, independent of stream length."""

    __slots__ = ("_slots", "_coverage", "_clock")

    def __init__(self, slots: np.ndarray, coverage: np.ndarray, clock: int) -> None:
        if (
            not isinstance(slots, np.ndarray)
            or slots.dtype != np.complex64
            or slots.shape != SLOT_SHAPE
            or not np.all(np.isfinite(slots))
        ):
            raise PolyphaseSufficientStateError(
                "V2 slots must be finite complex64[3,4,256]"
            )
        if (
            not isinstance(coverage, np.ndarray)
            or coverage.dtype != np.uint16
            or coverage.shape != (KEY_BITS,)
        ):
            raise PolyphaseSufficientStateError("V2 coverage must be uint16[256]")
        if isinstance(clock, bool) or not isinstance(clock, int) or not 0 <= clock < 1 << 64:
            raise PolyphaseSufficientStateError("V2 clock must be uint64-compatible")
        expected = np.uint16(min(clock, int(np.iinfo(np.uint16).max)))
        if not bool(np.all(coverage == expected)):
            raise PolyphaseSufficientStateError(
                "V2 full-group coverage must equal the saturated clock"
            )
        self._slots = np.array(slots, dtype=np.complex64, order="C", copy=True)
        self._coverage = np.array(coverage, dtype=np.uint16, order="C", copy=True)
        self._clock = clock

    @classmethod
    def initial(cls) -> "PolyphaseSufficientState":
        return cls(
            np.zeros(SLOT_SHAPE, dtype=np.complex64),
            np.zeros(KEY_BITS, dtype=np.uint16),
            0,
        )

    @property
    def clock(self) -> int:
        return self._clock

    @property
    def coverage(self) -> np.ndarray:
        result = self._coverage.copy()
        result.setflags(write=False)
        return result

    @property
    def slots(self) -> np.ndarray:
        result = self._slots.copy()
        result.setflags(write=False)
        return result

    @property
    def persistent_bytes(self) -> int:
        return STATE_BYTES

    def consume(self, chunks: Iterable[np.ndarray] | np.ndarray) -> int:
        slots = self._slots.copy()
        coverage = self._coverage.copy()
        clock = self._clock
        consumed = 0
        pole_real = _POLES.real[:, :, None]
        pole_imag = _POLES.imag[:, :, None]
        gains = _GAINS[:, :, None]
        for group in _iter_groups(chunks):
            if clock == (1 << 64) - 1:
                raise PolyphaseSufficientStateError("V2 clock would overflow uint64")
            try:
                with np.errstate(
                    divide="raise",
                    over="raise",
                    invalid="raise",
                    under="ignore",
                ):
                    real_product = np.subtract(
                        np.multiply(pole_real, slots.real, dtype=np.float32),
                        np.multiply(pole_imag, slots.imag, dtype=np.float32),
                        dtype=np.float32,
                    )
                    imaginary = np.add(
                        np.multiply(pole_real, slots.imag, dtype=np.float32),
                        np.multiply(pole_imag, slots.real, dtype=np.float32),
                        dtype=np.float32,
                    )
                    driven_real = np.add(
                        real_product,
                        np.multiply(gains, group[:, None, :], dtype=np.float32),
                        dtype=np.float32,
                    )
                    updated = np.empty(SLOT_SHAPE, dtype=np.complex64)
                    updated.real = driven_real
                    updated.imag = imaginary
            except FloatingPointError as exc:
                raise PolyphaseSufficientStateError(
                    "finite V2 input overflowed the explicit complex64 recurrence"
                ) from exc
            if not np.all(np.isfinite(updated)):
                raise PolyphaseSufficientStateError(
                    "finite V2 input produced a non-finite state"
                )
            slots = updated
            coverage = np.minimum(
                coverage.astype(np.uint32) + np.uint32(1),
                np.uint32(np.iinfo(np.uint16).max),
            ).astype(np.uint16)
            clock += 1
            consumed += 1
        self._slots = np.array(slots, dtype=np.complex64, order="C", copy=True)
        self._coverage = np.array(coverage, dtype=np.uint16, order="C", copy=True)
        self._clock = clock
        return consumed

    def to_bytes(self) -> bytes:
        payload = b"".join(
            (
                _BASIS_PREFIX,
                self._slots.astype("<c8", copy=False).tobytes(order="C"),
                self._coverage.astype("<u2", copy=False).tobytes(order="C"),
                struct.pack("<Q", self._clock),
            )
        )
        if len(payload) != STATE_BYTES:  # pragma: no cover
            raise AssertionError("serialized V2 state width differs")
        return payload

    @classmethod
    def from_bytes(cls, payload: bytes) -> "PolyphaseSufficientState":
        if isinstance(payload, bytes) and len(payload) == CORE_STATE_BYTES:
            raise ReplayRequiredError(
                "legacy unprefixed state requires a cold V2 migration and replay"
            )
        if not isinstance(payload, bytes) or len(payload) != STATE_BYTES:
            raise PolyphaseSufficientStateError(
                f"serialized V2 state must contain exactly {STATE_BYTES} bytes"
            )
        if payload[:BASIS_PREFIX_BYTES] != _BASIS_PREFIX:
            raise ReplayRequiredError(
                "serialized state basis differs; cold migration and replay are required"
            )
        slot_start = BASIS_PREFIX_BYTES
        slot_end = slot_start + SLOT_BYTES
        coverage_end = slot_end + COVERAGE_BYTES
        slots = (
            np.frombuffer(payload[slot_start:slot_end], dtype="<c8")
            .reshape(SLOT_SHAPE)
            .astype(np.complex64, copy=True)
        )
        coverage = np.frombuffer(
            payload[slot_end:coverage_end], dtype="<u2"
        ).astype(np.uint16, copy=True)
        clock = int(struct.unpack("<Q", payload[coverage_end:])[0])
        return cls(slots, coverage, clock)

    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def describe(self) -> dict[str, object]:
        return {
            "schema": STATE_SCHEMA,
            "basis_sha256": BASIS_SHA256,
            "abi_revision": 2,
            "clock": self._clock,
            "coverage_min": int(self._coverage.min()),
            "coverage_max": int(self._coverage.max()),
            "core_state_bytes": CORE_STATE_BYTES,
            "basis_prefix_bytes": BASIS_PREFIX_BYTES,
            "persistent_bytes": STATE_BYTES,
            "sha256": self.sha256(),
            "stream_length_dependent": False,
        }


def _require_basis(spec: PolyphaseReadoutSpec) -> None:
    if not isinstance(spec, PolyphaseReadoutSpec):
        raise TypeError("spec must be V2 PolyphaseReadoutSpec")
    if spec.basis_sha256 != BASIS_SHA256:
        raise ReplayRequiredError(
            "readout basis differs; V2 cold migration and replay are required"
        )


def read_polyphase_state(
    state: PolyphaseSufficientState,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    if not isinstance(state, PolyphaseSufficientState):
        raise TypeError("state must be V2 PolyphaseSufficientState")
    _require_basis(spec)
    try:
        with np.errstate(
            divide="raise",
            over="raise",
            invalid="raise",
            under="ignore",
        ):
            logits = np.zeros(KEY_BITS, dtype=np.float32)
            for horizon in range(HORIZON_COUNT):
                for pole in range(POLE_COUNT):
                    logits = np.add(
                        logits,
                        np.multiply(
                            spec.slot_weights[horizon, pole],
                            state._slots[horizon, pole].real,
                            dtype=np.float32,
                        ),
                        dtype=np.float32,
                    )
            result = np.divide(
                logits,
                np.float32(spec.temperature),
                dtype=np.float32,
            )
    except FloatingPointError as exc:
        raise PolyphaseSufficientStateError(
            "finite V2 state/readout overflowed the explicit float32 schedule"
        ) from exc
    if result.shape != (KEY_BITS,) or not np.all(np.isfinite(result)):
        raise PolyphaseSufficientStateError("V2 readout produced invalid logits")
    result.setflags(write=False)
    return result


@dataclass(frozen=True)
class PolyphaseReferenceState:
    """Independent complex128 audit recurrence, never deployment state."""

    slots: np.ndarray
    envelope: np.ndarray
    coverage: np.ndarray
    clock: int

    def __post_init__(self) -> None:
        for name, value, dtype, shape in (
            ("slots", self.slots, np.complex128, SLOT_SHAPE),
            ("envelope", self.envelope, np.float64, SLOT_SHAPE),
            ("coverage", self.coverage, np.uint16, (KEY_BITS,)),
        ):
            if (
                not isinstance(value, np.ndarray)
                or value.dtype != dtype
                or value.shape != shape
                or (
                    np.issubdtype(value.dtype, np.inexact)
                    and not np.all(np.isfinite(value))
                )
            ):
                raise PolyphaseSufficientStateError(f"V2 reference {name} differs")
            frozen = np.array(value, dtype=dtype, order="C", copy=True)
            frozen.setflags(write=False)
            object.__setattr__(self, name, frozen)
        if isinstance(self.clock, bool) or not isinstance(self.clock, int) or self.clock < 0:
            raise PolyphaseSufficientStateError("V2 reference clock differs")
        expected = np.uint16(min(self.clock, int(np.iinfo(np.uint16).max)))
        if not bool(np.all(self.coverage == expected)):
            raise PolyphaseSufficientStateError(
                "V2 reference coverage differs from its clock"
            )


def direct_polyphase_state(
    chunks: Iterable[np.ndarray] | np.ndarray,
) -> PolyphaseReferenceState:
    slots = np.zeros(SLOT_SHAPE, dtype=np.complex128)
    envelope = np.zeros(SLOT_SHAPE, dtype=np.float64)
    coverage = np.zeros(KEY_BITS, dtype=np.uint16)
    clock = 0
    poles = _POLES.astype(np.complex128)[:, :, None]
    rho = np.abs(poles)
    gains = _GAINS.astype(np.float64)[:, :, None]
    for group in _iter_groups(chunks):
        values = group.astype(np.float64)[:, None, :]
        with np.errstate(
            divide="raise",
            over="raise",
            invalid="raise",
            under="ignore",
        ):
            slots = poles * slots + gains * values
            envelope = rho * envelope + np.abs(gains * values)
        coverage = np.minimum(
            coverage.astype(np.uint32) + np.uint32(1),
            np.uint32(np.iinfo(np.uint16).max),
        ).astype(np.uint16)
        clock += 1
    return PolyphaseReferenceState(slots, envelope, coverage, clock)


def read_polyphase_reference(
    state: PolyphaseReferenceState,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    if not isinstance(state, PolyphaseReferenceState):
        raise TypeError("state must be V2 PolyphaseReferenceState")
    _require_basis(spec)
    result = np.einsum(
        "hp,hpi->i",
        spec.slot_weights.astype(np.float64),
        state.slots.real,
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    if result.shape != (KEY_BITS,) or not np.all(np.isfinite(result)):
        raise PolyphaseSufficientStateError("V2 reference readout produced invalid logits")
    result.setflags(write=False)
    return result


def direct_polyphase_reference(
    chunks: Iterable[np.ndarray] | np.ndarray,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    return read_polyphase_reference(direct_polyphase_state(chunks), spec)


def reference_slot_roundoff_bound(state: PolyphaseReferenceState) -> np.ndarray:
    if not isinstance(state, PolyphaseReferenceState):
        raise TypeError("state must be V2 PolyphaseReferenceState")
    rho = np.abs(_POLES.astype(np.complex128))[:, :, None]
    memory = np.minimum(
        float(state.clock),
        1.0 / np.maximum(1.0 - rho, np.finfo(np.float64).tiny),
    )
    # V2 materializes eight float32 operations per recurrence update.
    bound = (
        48.0
        * float(np.finfo(np.float32).eps)
        * (state.envelope + 1.0)
        * memory
    )
    bound.setflags(write=False)
    return bound


def reference_readout_roundoff_bound(
    state: PolyphaseReferenceState,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    _require_basis(spec)
    slot_bound = reference_slot_roundoff_bound(state)
    projected = np.einsum(
        "hp,hpi->i",
        np.abs(spec.slot_weights.astype(np.float64)),
        slot_bound,
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    magnitude = np.einsum(
        "hp,hpi->i",
        np.abs(spec.slot_weights.astype(np.float64)),
        np.abs(state.slots.real),
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    readout_rounding = (
        12.0
        * float(np.finfo(np.float32).eps)
        * (HORIZON_COUNT * POLE_COUNT + 1)
        * (magnitude + 1.0)
    )
    result = projected + readout_rounding
    result.setflags(write=False)
    return result


if CORE_STATE_BYTES != 25_096 or STATE_BYTES != 25_128:  # pragma: no cover
    raise AssertionError("V2 polyphase state contract changed")


__all__ = [
    "BASIS_PREFIX_BYTES",
    "BASIS_SCHEMA",
    "BASIS_SHA256",
    "CLOCK_BYTES",
    "CORE_STATE_BYTES",
    "COVERAGE_BYTES",
    "GAINS",
    "HORIZON_COUNT",
    "KEY_BITS",
    "POLES",
    "POLE_COUNT",
    "PolyphaseReadoutSpec",
    "PolyphaseReferenceState",
    "PolyphaseSufficientState",
    "PolyphaseSufficientStateError",
    "READOUT_SCHEMA",
    "ReplayRequiredError",
    "SLOT_BYTES",
    "SLOT_SHAPE",
    "STATE_BYTES",
    "STATE_SCHEMA",
    "TIMESCALES",
    "WAVELENGTHS",
    "basis_descriptor",
    "basis_sha256_from_descriptor",
    "direct_polyphase_reference",
    "direct_polyphase_state",
    "read_polyphase_reference",
    "read_polyphase_state",
    "reference_readout_roundoff_bound",
    "reference_slot_roundoff_bound",
]
