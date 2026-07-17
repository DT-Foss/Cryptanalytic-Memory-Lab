"""Stateful O1 GSSM and holographic core for typed float event streams.

This is a lab-native adaptation of the Apache-2.0 O1 mechanisms at commit
``7280924231143ac8fc666ba7e282ad4054635b6c``:

- ``reference/moebius_scan_transformer_selective.py`` supplies the bounded
  selective log-complement recurrence;
- ``src/streaming_train.py`` supplies carried state and detach-based streaming
  training;
- ``src/holographic_gssm.py`` supplies key-conditioned complex writes and
  query de-rotation.

The adaptation accepts typed cryptanalytic float events, validates every carried
state exactly, keeps query reads state-preserving, and returns a serializable
fixed-size fast state. It never imports the living O1 worktree at runtime.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any

import numpy as np

try:  # The base harness stays NumPy-only; learned O1 is an optional train extra.
    import torch
    from torch import nn
except ImportError:  # pragma: no cover - covered by the minimal runtime suite.
    torch = None  # type: ignore[assignment]
    nn = None  # type: ignore[assignment]


O1_STREAMING_SCHEMA = "o1-crypto-stateful-selective-holographic-v1"
LOG_COMPLEMENT_CLAMP = 0.999
EPSILON = 1e-6


class O1StreamingCoreError(ValueError):
    """An O1 configuration, event tensor, or carried state is invalid."""


def require_torch() -> None:
    if torch is None or nn is None:
        raise O1StreamingCoreError(
            "stateful learned O1 requires the optional 'train' dependency"
        )


def _positive_int(value: object, field: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise O1StreamingCoreError(f"{field} must be an integer in [1,{maximum}]")
    return value


def _finite_positive(value: object, field: str, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= maximum
    ):
        raise O1StreamingCoreError(f"{field} must be finite in (0,{maximum}]")
    return float(value)


@dataclass(frozen=True)
class O1StreamingCoreConfig:
    event_dimension: int
    address_dimension: int
    model_dimension: int = 64
    heads: int = 4
    head_dimension: int = 16
    holographic_slots: int = 4
    feedforward_dimension: int = 128
    phase_scale: float = math.pi
    seed: int = 170017

    def __post_init__(self) -> None:
        for field, value, maximum in (
            ("event_dimension", self.event_dimension, 4096),
            ("address_dimension", self.address_dimension, 4096),
            ("model_dimension", self.model_dimension, 4096),
            ("heads", self.heads, 64),
            ("head_dimension", self.head_dimension, 1024),
            ("holographic_slots", self.holographic_slots, 64),
            ("feedforward_dimension", self.feedforward_dimension, 16384),
        ):
            _positive_int(value, field, maximum)
        _finite_positive(self.phase_scale, "phase_scale", 8.0 * math.pi)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise O1StreamingCoreError("seed must be an integer")

    @property
    def channels(self) -> int:
        return self.heads * self.head_dimension

    def fast_state_bytes(self, batch_size: int = 1) -> int:
        batch = _positive_int(batch_size, "batch_size", 1_000_000)
        scalar_count = batch * self.channels * (1 + 2 * self.holographic_slots)
        return scalar_count * np.dtype("<f4").itemsize

    def describe(self) -> dict[str, object]:
        return {
            "schema": O1_STREAMING_SCHEMA,
            "event_dimension": self.event_dimension,
            "address_dimension": self.address_dimension,
            "model_dimension": self.model_dimension,
            "heads": self.heads,
            "head_dimension": self.head_dimension,
            "holographic_slots": self.holographic_slots,
            "feedforward_dimension": self.feedforward_dimension,
            "phase_scale": self.phase_scale,
            "seed": self.seed,
            "fast_state_float32": {
                "gssm_z": ["batch", self.heads, self.head_dimension],
                "holographic_real": [
                    "batch",
                    self.heads,
                    self.holographic_slots,
                    self.head_dimension,
                ],
                "holographic_imaginary": [
                    "batch",
                    self.heads,
                    self.holographic_slots,
                    self.head_dimension,
                ],
            },
            "fast_state_bytes_batch1": self.fast_state_bytes(),
            "stream_length_dependent_state": False,
            "source_o1_commit": "7280924231143ac8fc666ba7e282ad4054635b6c",
        }


@dataclass
class O1FastState:
    """Exact carried state for one selective+holographic layer."""

    gssm_z: Any
    holographic_real: Any
    holographic_imaginary: Any

    def validate(self, config: O1StreamingCoreConfig) -> None:
        require_torch()
        if not isinstance(config, O1StreamingCoreConfig):
            raise TypeError("config must be O1StreamingCoreConfig")
        tensors = (
            ("gssm_z", self.gssm_z),
            ("holographic_real", self.holographic_real),
            ("holographic_imaginary", self.holographic_imaginary),
        )
        if any(not isinstance(value, torch.Tensor) for _name, value in tensors):
            raise O1StreamingCoreError("fast state members must be torch tensors")
        batch = int(self.gssm_z.shape[0]) if self.gssm_z.ndim == 3 else -1
        expected = {
            "gssm_z": (batch, config.heads, config.head_dimension),
            "holographic_real": (
                batch,
                config.heads,
                config.holographic_slots,
                config.head_dimension,
            ),
            "holographic_imaginary": (
                batch,
                config.heads,
                config.holographic_slots,
                config.head_dimension,
            ),
        }
        reference = self.gssm_z
        for name, value in tensors:
            if tuple(value.shape) != expected[name]:
                raise O1StreamingCoreError(f"fast state {name} shape differs")
            if value.dtype != torch.float32:
                raise O1StreamingCoreError(f"fast state {name} must be float32")
            if value.device != reference.device:
                raise O1StreamingCoreError("fast state devices differ")
            if not bool(torch.isfinite(value).all()):
                raise O1StreamingCoreError(f"fast state {name} is not finite")
        if batch < 1:
            raise O1StreamingCoreError("fast state batch must be positive")

    @property
    def batch_size(self) -> int:
        return int(self.gssm_z.shape[0])

    def detached(self) -> "O1FastState":
        return O1FastState(
            self.gssm_z.detach(),
            self.holographic_real.detach(),
            self.holographic_imaginary.detach(),
        )

    def clone(self) -> "O1FastState":
        return O1FastState(
            self.gssm_z.clone(),
            self.holographic_real.clone(),
            self.holographic_imaginary.clone(),
        )

    def to_bytes(self, config: O1StreamingCoreConfig) -> bytes:
        self.validate(config)
        payload = b"".join(
            tensor.detach()
            .to(device="cpu", dtype=torch.float32)
            .contiguous()
            .numpy()
            .astype("<f4", copy=False)
            .tobytes(order="C")
            for tensor in (
                self.gssm_z,
                self.holographic_real,
                self.holographic_imaginary,
            )
        )
        if len(payload) != config.fast_state_bytes(self.batch_size):
            raise AssertionError("serialized fast-state width differs")
        return payload

    def sha256(self, config: O1StreamingCoreConfig) -> str:
        return hashlib.sha256(self.to_bytes(config)).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        config: O1StreamingCoreConfig,
        batch_size: int,
        device: object = "cpu",
    ) -> "O1FastState":
        require_torch()
        batch = _positive_int(batch_size, "batch_size", 1_000_000)
        if not isinstance(payload, bytes) or len(payload) != config.fast_state_bytes(
            batch
        ):
            raise O1StreamingCoreError("serialized fast-state length differs")
        values = np.frombuffer(payload, dtype="<f4")
        offset = 0

        def take(shape: tuple[int, ...]) -> Any:
            nonlocal offset
            count = math.prod(shape)
            array = values[offset : offset + count].reshape(shape).copy()
            offset += count
            return torch.from_numpy(array).to(device=device, dtype=torch.float32)

        result = cls(
            gssm_z=take((batch, config.heads, config.head_dimension)),
            holographic_real=take(
                (
                    batch,
                    config.heads,
                    config.holographic_slots,
                    config.head_dimension,
                )
            ),
            holographic_imaginary=take(
                (
                    batch,
                    config.heads,
                    config.holographic_slots,
                    config.head_dimension,
                )
            ),
        )
        if offset != values.size:  # pragma: no cover
            raise AssertionError("fast-state parser did not consume payload")
        result.validate(config)
        return result


def stateful_linear_scan(a: Any, gamma: Any, initial: Any | None) -> tuple[Any, Any]:
    """Compute ``z_t = gamma_t*z_(t-1) + a_t`` with exact carried state."""

    require_torch()
    if not isinstance(a, torch.Tensor) or not isinstance(gamma, torch.Tensor):
        raise O1StreamingCoreError("scan inputs must be torch tensors")
    if a.ndim < 3 or tuple(a.shape) != tuple(gamma.shape) or a.shape[1] < 1:
        raise O1StreamingCoreError("scan inputs require matched [B,T,...] shapes")
    if a.dtype != gamma.dtype or a.device != gamma.device:
        raise O1StreamingCoreError("scan input dtype/device differs")
    if not bool(torch.isfinite(a).all()) or not bool(torch.isfinite(gamma).all()):
        raise O1StreamingCoreError("scan inputs must be finite")
    if bool(((gamma < 0.0) | (gamma > 1.0)).any()):
        raise O1StreamingCoreError("scan gamma must be in [0,1]")
    expected_initial = tuple(a.shape[:1]) + tuple(a.shape[2:])
    if initial is None:
        state = torch.zeros_like(a[:, 0])
    else:
        if (
            not isinstance(initial, torch.Tensor)
            or tuple(initial.shape) != expected_initial
            or initial.dtype != a.dtype
            or initial.device != a.device
            or not bool(torch.isfinite(initial).all())
        ):
            raise O1StreamingCoreError("scan initial state differs")
        state = initial
    rows = []
    for index in range(a.shape[1]):
        state = gamma[:, index] * state + a[:, index]
        rows.append(state)
    return torch.stack(rows, dim=1), state


if nn is not None:

    class StreamingSelectiveHolographicCore(nn.Module):
        """Learned O1 recurrence with chunk-carried content-addressable state."""

        def __init__(self, config: O1StreamingCoreConfig) -> None:
            super().__init__()
            if not isinstance(config, O1StreamingCoreConfig):
                raise TypeError("config must be O1StreamingCoreConfig")
            self.config = config
            channels = config.channels
            self.event_projection = nn.Linear(
                config.event_dimension, config.model_dimension, bias=False
            )
            self.value_projection = nn.Linear(
                config.model_dimension, channels, bias=False
            )
            self.value_gate = nn.Linear(config.model_dimension, channels, bias=False)
            self.forget_gate = nn.Linear(config.model_dimension, channels, bias=False)
            self.input_gate = nn.Linear(config.model_dimension, channels, bias=False)
            self.write_phase = nn.Linear(config.address_dimension, channels, bias=False)
            self.read_phase = nn.Linear(config.address_dimension, channels, bias=False)
            self.slot_router = (
                nn.Linear(
                    config.address_dimension,
                    config.heads * config.holographic_slots,
                    bias=False,
                )
                if config.holographic_slots > 1
                else None
            )
            self.magnitude_output = nn.Linear(
                channels, config.model_dimension, bias=False
            )
            self.holographic_output = nn.Linear(
                2 * channels, config.model_dimension, bias=False
            )
            self.layer_norm_1 = nn.LayerNorm(config.model_dimension)
            self.feedforward = nn.Sequential(
                nn.Linear(config.model_dimension, config.feedforward_dimension),
                nn.GELU(),
                nn.Linear(config.feedforward_dimension, config.model_dimension),
            )
            self.layer_norm_2 = nn.LayerNorm(config.model_dimension)
            self._reset_parameters()

        def _reset_parameters(self) -> None:
            with torch.random.fork_rng(devices=[]):
                torch.manual_seed(self.config.seed)
                nn.init.xavier_uniform_(self.event_projection.weight, gain=0.6)
                for module in (self.forget_gate, self.input_gate):
                    nn.init.xavier_uniform_(module.weight, gain=0.1)
                for module in (
                    self.value_projection,
                    self.value_gate,
                    self.magnitude_output,
                    self.holographic_output,
                ):
                    nn.init.xavier_uniform_(module.weight, gain=0.6)
                nn.init.xavier_uniform_(self.write_phase.weight, gain=0.1)
                nn.init.xavier_uniform_(self.read_phase.weight, gain=0.1)
                if self.slot_router is not None:
                    nn.init.xavier_uniform_(self.slot_router.weight, gain=1.0)
                for module in self.feedforward:
                    if isinstance(module, nn.Linear):
                        nn.init.xavier_uniform_(module.weight, gain=0.6)
                        nn.init.zeros_(module.bias)

        def initial_state(
            self,
            batch_size: int,
            *,
            device: object | None = None,
        ) -> O1FastState:
            batch = _positive_int(batch_size, "batch_size", 1_000_000)
            target_device = (
                self.event_projection.weight.device if device is None else device
            )
            result = O1FastState(
                gssm_z=torch.zeros(
                    batch,
                    self.config.heads,
                    self.config.head_dimension,
                    dtype=torch.float32,
                    device=target_device,
                ),
                holographic_real=torch.zeros(
                    batch,
                    self.config.heads,
                    self.config.holographic_slots,
                    self.config.head_dimension,
                    dtype=torch.float32,
                    device=target_device,
                ),
                holographic_imaginary=torch.zeros(
                    batch,
                    self.config.heads,
                    self.config.holographic_slots,
                    self.config.head_dimension,
                    dtype=torch.float32,
                    device=target_device,
                ),
            )
            result.validate(self.config)
            return result

        def _validate_inputs(
            self,
            events: Any,
            addresses: Any,
            update_mask: Any,
            state: O1FastState | None,
        ) -> O1FastState:
            tensors = (events, addresses, update_mask)
            if any(not isinstance(value, torch.Tensor) for value in tensors):
                raise O1StreamingCoreError(
                    "events, addresses, and mask must be tensors"
                )
            if (
                events.ndim != 3
                or addresses.ndim != 3
                or update_mask.ndim != 2
                or events.shape[:2] != addresses.shape[:2]
                or events.shape[:2] != update_mask.shape
                or events.shape[2] != self.config.event_dimension
                or addresses.shape[2] != self.config.address_dimension
                or events.shape[1] < 1
            ):
                raise O1StreamingCoreError("stream tensor shapes differ")
            if events.dtype != torch.float32 or addresses.dtype != torch.float32:
                raise O1StreamingCoreError("events and addresses must be float32")
            if update_mask.dtype != torch.bool:
                raise O1StreamingCoreError("update_mask must be boolean")
            if (
                events.device != addresses.device
                or events.device != update_mask.device
                or events.device != self.event_projection.weight.device
            ):
                raise O1StreamingCoreError("stream tensor devices differ")
            if not bool(torch.isfinite(events).all()) or not bool(
                torch.isfinite(addresses).all()
            ):
                raise O1StreamingCoreError("stream tensors must be finite")
            carried = self.initial_state(events.shape[0]) if state is None else state
            carried.validate(self.config)
            if (
                carried.batch_size != events.shape[0]
                or carried.gssm_z.device != events.device
            ):
                raise O1StreamingCoreError("carried state batch/device differs")
            return carried

        def _slot_weights(self, addresses: Any) -> Any:
            batch, length, _dimension = addresses.shape
            if self.slot_router is None:
                return torch.ones(
                    batch,
                    length,
                    self.config.heads,
                    1,
                    dtype=addresses.dtype,
                    device=addresses.device,
                )
            logits = self.slot_router(addresses).view(
                batch,
                length,
                self.config.heads,
                self.config.holographic_slots,
            )
            soft = torch.softmax(logits, dim=-1)
            hard = torch.zeros_like(soft).scatter_(
                -1, soft.argmax(dim=-1, keepdim=True), 1.0
            )
            return hard + soft - soft.detach()

        def forward(
            self,
            events: Any,
            addresses: Any,
            update_mask: Any,
            state: O1FastState | None = None,
            *,
            return_internals: bool = False,
        ) -> tuple[Any, O1FastState] | tuple[Any, O1FastState, dict[str, Any]]:
            carried = self._validate_inputs(events, addresses, update_mask, state)
            batch, length, _dimension = events.shape
            hidden = self.event_projection(events)
            value = torch.tanh(self.value_projection(hidden))
            value_gate = torch.sigmoid(self.value_gate(hidden))
            gamma = torch.sigmoid(self.forget_gate(hidden)).view(
                batch, length, self.config.heads, self.config.head_dimension
            )
            alpha = torch.sigmoid(self.input_gate(hidden)).view(
                batch, length, self.config.heads, self.config.head_dimension
            )
            gated = (value * value_gate).view(
                batch, length, self.config.heads, self.config.head_dimension
            )
            squared = torch.clamp(gated * gated, max=LOG_COMPLEMENT_CLAMP)
            drive = alpha * torch.log(1.0 - squared + EPSILON)
            active = update_mask[:, :, None, None]
            held_gamma = torch.where(active, gamma, torch.ones_like(gamma))
            held_drive = torch.where(active, drive, torch.zeros_like(drive))
            # O1's bounded magnitude recurrence intentionally squares velocity.
            # Cryptanalytic evidence, however, has an explicit legal sign
            # (F(1)-F(0)).  Preserve that sign in the complex carrier amplitude
            # while retaining the exact log-complement GSSM magnitude above.
            signed_holographic_drive = alpha * gated
            held_holographic_drive = torch.where(
                active,
                signed_holographic_drive,
                torch.zeros_like(signed_holographic_drive),
            )
            z_sequence, z_final = stateful_linear_scan(
                held_drive, held_gamma, carried.gssm_z
            )
            magnitude = torch.sqrt(
                torch.clamp(1.0 - torch.exp(z_sequence), min=0.0) + EPSILON
            )

            write_phase = self.config.phase_scale * torch.tanh(
                self.write_phase(addresses)
            ).view(batch, length, self.config.heads, self.config.head_dimension)
            read_phase = self.config.phase_scale * torch.tanh(
                self.read_phase(addresses)
            ).view(batch, length, self.config.heads, self.config.head_dimension)
            slots = self._slot_weights(addresses)
            slot_drive = (
                held_holographic_drive[:, :, :, None, :] * slots[:, :, :, :, None]
            )
            drive_real = slot_drive * torch.cos(write_phase)[:, :, :, None, :]
            drive_imaginary = slot_drive * torch.sin(write_phase)[:, :, :, None, :]
            slot_gamma = held_gamma[:, :, :, None, :].expand(
                batch,
                length,
                self.config.heads,
                self.config.holographic_slots,
                self.config.head_dimension,
            )
            real_sequence, real_final = stateful_linear_scan(
                drive_real, slot_gamma, carried.holographic_real
            )
            imaginary_sequence, imaginary_final = stateful_linear_scan(
                drive_imaginary, slot_gamma, carried.holographic_imaginary
            )
            selected_real = (real_sequence * slots[:, :, :, :, None]).sum(dim=3)
            selected_imaginary = (imaginary_sequence * slots[:, :, :, :, None]).sum(
                dim=3
            )
            cosine = torch.cos(read_phase)
            sine = torch.sin(read_phase)
            derotated_real = selected_real * cosine + selected_imaginary * sine
            derotated_imaginary = -selected_real * sine + selected_imaginary * cosine
            holographic_read = torch.cat(
                (derotated_real, derotated_imaginary), dim=-1
            ).reshape(batch, length, 2 * self.config.channels)
            scan_output = self.magnitude_output(
                magnitude.reshape(batch, length, self.config.channels)
            ) + self.holographic_output(holographic_read)
            encoded = self.layer_norm_1(hidden + scan_output)
            encoded = self.layer_norm_2(encoded + self.feedforward(encoded))
            # A pure query is a mathematical read.  Return the original tensors
            # themselves so even IEEE signed-zero payloads remain byte-exact;
            # evaluating 1*state+0 can otherwise canonicalize -0.0 to +0.0.
            new_state = (
                carried
                if not bool(update_mask.any())
                else O1FastState(z_final, real_final, imaginary_final)
            )
            new_state.validate(self.config)
            if not return_internals:
                return encoded, new_state
            return (
                encoded,
                new_state,
                {
                    "value_gate": value_gate.view(
                        batch, length, self.config.heads, self.config.head_dimension
                    ),
                    "gamma": gamma,
                    "alpha": alpha,
                    "drive": drive,
                    "signed_holographic_drive": signed_holographic_drive,
                    "gssm_z_sequence": z_sequence,
                    "write_phase": write_phase,
                    "read_phase": read_phase,
                    "slot_weights": slots,
                    "update_mask": update_mask,
                },
            )

    class StreamingO1KeyReader(nn.Module):
        """Shared bit reader over an O1 float-event stream."""

        def __init__(self, config: O1StreamingCoreConfig) -> None:
            super().__init__()
            self.config = config
            self.core = StreamingSelectiveHolographicCore(config)
            self.bit_head = nn.Linear(config.model_dimension, 1, bias=False)
            with torch.random.fork_rng(devices=[]):
                torch.manual_seed(config.seed ^ 0xB17)
                nn.init.xavier_uniform_(self.bit_head.weight, gain=0.6)

        def forward(
            self,
            events: Any,
            addresses: Any,
            update_mask: Any,
            state: O1FastState | None = None,
            *,
            return_internals: bool = False,
        ) -> tuple[Any, O1FastState] | tuple[Any, O1FastState, dict[str, Any]]:
            if return_internals:
                encoded, new_state, internals = self.core(
                    events,
                    addresses,
                    update_mask,
                    state,
                    return_internals=True,
                )
                return self.bit_head(encoded).squeeze(-1), new_state, internals
            encoded, new_state = self.core(events, addresses, update_mask, state)
            return self.bit_head(encoded).squeeze(-1), new_state


else:  # pragma: no cover

    class StreamingSelectiveHolographicCore:  # type: ignore[no-redef]
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            require_torch()

    class StreamingO1KeyReader:  # type: ignore[no-redef]
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            require_torch()
