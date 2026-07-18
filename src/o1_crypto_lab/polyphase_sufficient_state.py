"""Bounded full-256 polyphase sufficient state with hot-swappable readouts.

The state is a bank of stable complex resonators.  It consumes complete
``float32[3, 256]`` evidence groups exactly in stream order and retains no
transcript.  Slot weights and temperature are deliberately external: they can
be changed after ingestion without replay.  The encoder, poles, gains and phase
basis are hash-bound; changing any of them requires replay.
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


KEY_BITS = 256
WAVELENGTHS = (64, 96, 65)
TIMESCALES = (1, 2, 4, 8)
HORIZON_COUNT = len(WAVELENGTHS)
POLE_COUNT = len(TIMESCALES)
SLOT_SHAPE = (HORIZON_COUNT, POLE_COUNT, KEY_BITS)
SLOT_BYTES = math.prod(SLOT_SHAPE) * np.dtype("<c8").itemsize
COVERAGE_BYTES = KEY_BITS * np.dtype("<u2").itemsize
CLOCK_BYTES = np.dtype("<u8").itemsize
STATE_BYTES = SLOT_BYTES + COVERAGE_BYTES + CLOCK_BYTES
BASIS_SCHEMA = "o1-256-polyphase-sufficient-state-basis-v1"
STATE_SCHEMA = "o1-256-polyphase-sufficient-state-v1"
READOUT_SCHEMA = "o1-256-polyphase-readout-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_POLES_C64LE_HEX = (
    "47d17a3f7fa0c53de0c87c3f4c2dc73d28c67d3fddf4c73d2b457e3ff058c83d"
    "03ce7c3fbe8e843df71f7e3ff23f853d9ac97e3fe598853d961e7f3f75c5853d"
    "32ea7a3f92a4c23d36da7c3f5825c43da7d37d3fd8e6c43dbb507e3fe047c53d"
)
_GAINS_F32LE_HEX = (
    "419d333ef300ff3d8eaab43dcabf7f3d0c09133ee97ad03d239c933d7de3503d"
    "a13f323e810cfd3db246b33ddfc77d3d"
)


class PolyphaseSufficientStateError(ValueError):
    """A state, stream group, readout, or serialization differs."""


class ReplayRequiredError(PolyphaseSufficientStateError):
    """The requested reader is bound to a different encoder/kernel basis."""


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
        raise PolyphaseSufficientStateError("basis descriptor is not canonical JSON") from exc
    return rendered.encode("ascii")


def basis_sha256_from_descriptor(value: Mapping[str, object]) -> str:
    """Return the canonical commitment for a complete basis descriptor."""

    if not isinstance(value, Mapping):
        raise PolyphaseSufficientStateError("basis descriptor must be a mapping")
    return hashlib.sha256(_canonical_json_bytes(dict(value))).hexdigest()


def _build_basis() -> tuple[np.ndarray, np.ndarray, dict[str, object]]:
    # Literal little-endian model bytes make the recurrence independent of libm
    # implementations.  They were generated once from the documented analytic
    # pole/gain rules; the descriptor below commits their exact byte hashes.
    poles = np.frombuffer(
        bytes.fromhex(_POLES_C64LE_HEX), dtype="<c8"
    ).reshape((HORIZON_COUNT, POLE_COUNT))
    gains = np.frombuffer(
        bytes.fromhex(_GAINS_F32LE_HEX), dtype="<f4"
    ).reshape((HORIZON_COUNT, POLE_COUNT))
    if (
        not np.all(np.isfinite(poles))
        or not np.all(np.abs(poles) < 1.0)
        or not np.all(np.isfinite(gains))
        or not np.all(gains > 0.0)
    ):  # pragma: no cover
        raise AssertionError("frozen polyphase basis bytes are invalid")
    pole_bytes = poles.astype("<c8", copy=False).tobytes(order="C")
    gain_bytes = gains.astype("<f4", copy=False).tobytes(order="C")
    descriptor: dict[str, object] = {
        "schema": BASIS_SCHEMA,
        "encoder": {
            "coordinate_order": "ascending-key-bit-0-through-255",
            "group_dtype": "float32",
            "group_shape": [HORIZON_COUNT, KEY_BITS],
            "null_is_observed": True,
        },
        "kernel": {
            "recurrence": "Z_next=complex64(a*Z+g*X)",
            "gain_rule": "sqrt(1-abs(complex64(a))^2)",
            "timescales": list(TIMESCALES),
            "poles_c64le_sha256": hashlib.sha256(pole_bytes).hexdigest(),
            "gains_f32le_sha256": hashlib.sha256(gain_bytes).hexdigest(),
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
            "persistent_bytes": STATE_BYTES,
            "stream_length_dependent": False,
        },
    }
    poles.setflags(write=False)
    gains.setflags(write=False)
    return poles, gains, descriptor


_POLES, _GAINS, _BASIS_DESCRIPTOR = _build_basis()
# Public aliases remain immutable bytes-backed views.  Production functions use
# the private bindings so rebinding a public module attribute cannot alter them.
POLES = _POLES
GAINS = _GAINS
BASIS_SHA256 = basis_sha256_from_descriptor(_BASIS_DESCRIPTOR)


def basis_descriptor() -> dict[str, object]:
    """Return an independent JSON-safe copy of the frozen basis descriptor."""

    return json.loads(json.dumps(_BASIS_DESCRIPTOR, allow_nan=False))


@dataclass(frozen=True)
class PolyphaseReadoutSpec:
    """Late-bound odd readout over the frozen resonator bank."""

    name: str
    basis_sha256: str
    slot_weights: np.ndarray
    temperature: float

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name) > 96:
            raise PolyphaseSufficientStateError("readout name is required")
        if not isinstance(self.basis_sha256, str) or not _SHA256_RE.fullmatch(
            self.basis_sha256
        ):
            raise PolyphaseSufficientStateError(
                "readout basis_sha256 must be lowercase SHA-256"
            )
        weights = np.asarray(self.slot_weights)
        if (
            weights.dtype != np.float32
            or weights.shape != (HORIZON_COUNT, POLE_COUNT)
            or not np.all(np.isfinite(weights))
            or not bool(np.any(weights != 0.0))
        ):
            raise PolyphaseSufficientStateError(
                "readout slot_weights must be finite nonzero float32[3,4]"
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
                "readout temperature must be finite and positive"
            )
        object.__setattr__(self, "temperature", float(self.temperature))

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
            "each stream chunk must be a float32 ndarray"
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
            "each stream chunk must have shape [3,256] or [N,3,256]"
        )
    if not np.all(np.isfinite(batch)):
        raise PolyphaseSufficientStateError("stream chunk contains non-finite values")
    return batch


def _iter_groups(chunks: Iterable[np.ndarray] | np.ndarray) -> Iterator[np.ndarray]:
    source: Iterable[object]
    if isinstance(chunks, np.ndarray):
        source = (chunks,)
    else:
        try:
            source = iter(chunks)
        except TypeError as exc:
            raise PolyphaseSufficientStateError("chunks must be iterable") from exc
    for chunk in source:
        batch = _validated_chunk(chunk)
        for group in batch:
            yield group


class PolyphaseSufficientState:
    """Exactly 25,096 persistent bytes, independent of stream length."""

    __slots__ = ("_slots", "_coverage", "_clock")

    def __init__(self, slots: np.ndarray, coverage: np.ndarray, clock: int) -> None:
        if (
            not isinstance(slots, np.ndarray)
            or slots.dtype != np.complex64
            or slots.shape != SLOT_SHAPE
            or not np.all(np.isfinite(slots))
        ):
            raise PolyphaseSufficientStateError("slots must be finite complex64[3,4,256]")
        if (
            not isinstance(coverage, np.ndarray)
            or coverage.dtype != np.uint16
            or coverage.shape != (KEY_BITS,)
        ):
            raise PolyphaseSufficientStateError("coverage must be uint16[256]")
        if isinstance(clock, bool) or not isinstance(clock, int) or not 0 <= clock < 1 << 64:
            raise PolyphaseSufficientStateError("clock must be uint64-compatible")
        expected_coverage = np.uint16(min(clock, int(np.iinfo(np.uint16).max)))
        if not bool(np.all(coverage == expected_coverage)):
            raise PolyphaseSufficientStateError(
                "full-group coverage must equal the saturated global clock"
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
        """Consume one iterable transactionally and return its group count."""

        slots = self._slots.copy()
        coverage = self._coverage.copy()
        clock = self._clock
        consumed = 0
        poles = _POLES[:, :, None]
        gains = _GAINS[:, :, None]
        for group in _iter_groups(chunks):
            if clock == (1 << 64) - 1:
                raise PolyphaseSufficientStateError("clock would overflow uint64")
            # Explicit float32/complex64 operands keep the production recurrence
            # identical across chunk partitions in one NumPy runtime.
            try:
                with np.errstate(over="raise", invalid="raise"):
                    updated = np.asarray(
                        poles * slots + gains * group[:, None, :],
                        dtype=np.complex64,
                    )
            except FloatingPointError as exc:
                raise PolyphaseSufficientStateError(
                    "finite input overflowed the complex64 recurrence"
                ) from exc
            if not np.all(np.isfinite(updated)):
                raise PolyphaseSufficientStateError(
                    "finite input produced a non-finite complex64 state"
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
                self._slots.astype("<c8", copy=False).tobytes(order="C"),
                self._coverage.astype("<u2", copy=False).tobytes(order="C"),
                struct.pack("<Q", self._clock),
            )
        )
        if len(payload) != STATE_BYTES:  # pragma: no cover
            raise AssertionError("serialized polyphase state width differs")
        return payload

    @classmethod
    def from_bytes(cls, payload: bytes) -> "PolyphaseSufficientState":
        if not isinstance(payload, bytes) or len(payload) != STATE_BYTES:
            raise PolyphaseSufficientStateError(
                f"serialized state must contain exactly {STATE_BYTES} bytes"
            )
        slot_end = SLOT_BYTES
        coverage_end = slot_end + COVERAGE_BYTES
        slots = (
            np.frombuffer(payload[:slot_end], dtype="<c8")
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
            "clock": self._clock,
            "coverage_min": int(self._coverage.min()),
            "coverage_max": int(self._coverage.max()),
            "persistent_bytes": STATE_BYTES,
            "sha256": self.sha256(),
            "stream_length_dependent": False,
        }


def _require_basis(spec: PolyphaseReadoutSpec) -> None:
    if not isinstance(spec, PolyphaseReadoutSpec):
        raise TypeError("spec must be PolyphaseReadoutSpec")
    if spec.basis_sha256 != BASIS_SHA256:
        raise ReplayRequiredError(
            "readout basis differs; encoder/kernel/phase change requires replay"
        )


def read_polyphase_state(
    state: PolyphaseSufficientState,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    """Read 256 odd logits without mutating or replaying the state."""

    if not isinstance(state, PolyphaseSufficientState):
        raise TypeError("state must be PolyphaseSufficientState")
    _require_basis(spec)
    logits = np.einsum(
        "hp,hpi->i",
        spec.slot_weights,
        state._slots.real,
        dtype=np.float32,
        optimize=False,
    )
    result = np.asarray(logits / np.float32(spec.temperature), dtype=np.float32)
    if result.shape != (KEY_BITS,) or not np.all(np.isfinite(result)):
        raise PolyphaseSufficientStateError("readout produced invalid logits")
    result.setflags(write=False)
    return result


@dataclass(frozen=True)
class PolyphaseReferenceState:
    """Independent complex128 audit recurrence, never a deployment state."""

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
                raise PolyphaseSufficientStateError(f"reference {name} differs")
            frozen = np.array(value, dtype=dtype, order="C", copy=True)
            frozen.setflags(write=False)
            object.__setattr__(self, name, frozen)
        if isinstance(self.clock, bool) or not isinstance(self.clock, int) or self.clock < 0:
            raise PolyphaseSufficientStateError("reference clock differs")
        expected_coverage = np.uint16(
            min(self.clock, int(np.iinfo(np.uint16).max))
        )
        if not bool(np.all(self.coverage == expected_coverage)):
            raise PolyphaseSufficientStateError(
                "reference full-group coverage differs from its clock"
            )


def direct_polyphase_state(
    chunks: Iterable[np.ndarray] | np.ndarray,
) -> PolyphaseReferenceState:
    """Evaluate an independent chronological complex128 reference."""

    slots = np.zeros(SLOT_SHAPE, dtype=np.complex128)
    envelope = np.zeros(SLOT_SHAPE, dtype=np.float64)
    coverage = np.zeros(KEY_BITS, dtype=np.uint16)
    clock = 0
    poles = _POLES.astype(np.complex128)[:, :, None]
    rho = np.abs(_POLES.astype(np.complex128))[:, :, None]
    gains = _GAINS.astype(np.float64)[:, :, None]
    for group in _iter_groups(chunks):
        values = group.astype(np.float64)[:, None, :]
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
    """Read float64 logits from an independent audit state."""

    if not isinstance(state, PolyphaseReferenceState):
        raise TypeError("state must be PolyphaseReferenceState")
    _require_basis(spec)
    result = np.einsum(
        "hp,hpi->i",
        spec.slot_weights.astype(np.float64),
        state.slots.real,
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    if result.shape != (KEY_BITS,) or not np.all(np.isfinite(result)):
        raise PolyphaseSufficientStateError("reference readout produced invalid logits")
    result.setflags(write=False)
    return result


def direct_polyphase_reference(
    chunks: Iterable[np.ndarray] | np.ndarray,
    spec: PolyphaseReadoutSpec,
) -> np.ndarray:
    """Convenience wrapper for a fresh independent state and one readout."""

    return read_polyphase_reference(direct_polyphase_state(chunks), spec)


def reference_slot_roundoff_bound(state: PolyphaseReferenceState) -> np.ndarray:
    """Conservative float32 recurrence error envelope for each complex slot."""

    if not isinstance(state, PolyphaseReferenceState):
        raise TypeError("state must be PolyphaseReferenceState")
    rho = np.abs(_POLES.astype(np.complex128))[:, :, None]
    memory = np.minimum(
        float(state.clock),
        1.0 / np.maximum(1.0 - rho, np.finfo(np.float64).tiny),
    )
    bound = (
        32.0
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
    """Project the conservative slot bound through one late-bound reader."""

    _require_basis(spec)
    slot_bound = reference_slot_roundoff_bound(state)
    projected_state_bound = np.einsum(
        "hp,hpi->i",
        np.abs(spec.slot_weights.astype(np.float64)),
        slot_bound,
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    weighted_reference_magnitude = np.einsum(
        "hp,hpi->i",
        np.abs(spec.slot_weights.astype(np.float64)),
        np.abs(state.slots.real),
        dtype=np.float64,
        optimize=False,
    ) / spec.temperature
    readout_rounding = (
        8.0
        * float(np.finfo(np.float32).eps)
        * (HORIZON_COUNT * POLE_COUNT + 1)
        * (weighted_reference_magnitude + 1.0)
    )
    result = projected_state_bound + readout_rounding
    result.setflags(write=False)
    return result


if STATE_BYTES != 25_096:  # pragma: no cover
    raise AssertionError("polyphase persistent-state contract changed")


__all__ = [
    "BASIS_SCHEMA",
    "BASIS_SHA256",
    "CLOCK_BYTES",
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
