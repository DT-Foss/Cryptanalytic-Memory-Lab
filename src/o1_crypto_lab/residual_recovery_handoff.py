"""Exact all-256 to sibling residual-recovery handoff.

A325 and A526 search a low-coordinate residual domain.  They are valid only
when every complementary high coordinate has already been fixed correctly.
This module owns that bit codec, the mathematical entry gate, and final public
ChaCha20 verification; it does not approximate either sibling search order.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .chacha_trace import chacha20_block
from .living_inverse import KEY_BITS, PublicTargetView, bits_to_key, key_bits


class ResidualRecoveryHandoffError(ValueError):
    """A residual layout, completion, or candidate differs."""


@dataclass(frozen=True)
class ResidualLayout:
    backend: str
    residual_width: int

    def __post_init__(self) -> None:
        if self.backend not in {"A325_W46", "A526_W52"}:
            raise ResidualRecoveryHandoffError("unknown residual backend")
        expected = 46 if self.backend == "A325_W46" else 52
        if self.residual_width != expected:
            raise ResidualRecoveryHandoffError("backend residual width differs")

    @property
    def fixed_coordinates(self) -> tuple[int, ...]:
        return tuple(range(self.residual_width, KEY_BITS))

    @property
    def fixed_bit_count(self) -> int:
        return KEY_BITS - self.residual_width


A325_W46 = ResidualLayout("A325_W46", 46)
A526_W52 = ResidualLayout("A526_W52", 52)


def _binary_bits(
    values: Sequence[int] | np.ndarray, *, length: int, field: str
) -> np.ndarray:
    result = np.asarray(values)
    if result.shape != (length,) or np.any((result != 0) & (result != 1)):
        raise ResidualRecoveryHandoffError(
            f"{field} must contain exactly {length} binary values"
        )
    return result.astype(np.uint8, copy=False)


def completion_from_logits(
    logits: Sequence[float] | np.ndarray, layout: ResidualLayout
) -> tuple[int, ...]:
    """Freeze the sibling-required complement using the lab's >=0 bit rule."""

    if not isinstance(layout, ResidualLayout):
        raise TypeError("layout must be ResidualLayout")
    values = np.asarray(logits, dtype=np.float64)
    if values.shape != (KEY_BITS,) or not np.isfinite(values).all():
        raise ResidualRecoveryHandoffError("logits must be finite float64[256]")
    return tuple(int(value) for value in (values[layout.residual_width :] >= 0.0))


@dataclass(frozen=True)
class ComplementGate:
    backend: str
    correct_bits: int
    required_bits: int
    first_wrong_coordinate: int | None

    @property
    def eligible(self) -> bool:
        return self.correct_bits == self.required_bits

    def describe(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "correct_bits": self.correct_bits,
            "required_bits": self.required_bits,
            "wrong_bits": self.required_bits - self.correct_bits,
            "first_wrong_coordinate": self.first_wrong_coordinate,
            "eligible": self.eligible,
        }


def post_reveal_complement_gate(
    fixed_bits: Sequence[int] | np.ndarray,
    *,
    truth_key: bytes,
    layout: ResidualLayout,
) -> ComplementGate:
    """Diagnose a consumed completion; any wrong bit forbids residual search."""

    if not isinstance(layout, ResidualLayout):
        raise TypeError("layout must be ResidualLayout")
    fixed = _binary_bits(
        fixed_bits, length=layout.fixed_bit_count, field="fixed_bits"
    )
    truth = key_bits(truth_key)[layout.residual_width :]
    wrong = np.flatnonzero(fixed != truth)
    return ComplementGate(
        backend=layout.backend,
        correct_bits=int(layout.fixed_bit_count - len(wrong)),
        required_bits=layout.fixed_bit_count,
        first_wrong_coordinate=(
            None if not len(wrong) else int(layout.residual_width + wrong[0])
        ),
    )


@dataclass(frozen=True)
class ResidualRecoveryHandoff:
    """One target-safe fixed complement ready for an exact sibling backend."""

    layout: ResidualLayout
    public: PublicTargetView
    fixed_bits: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.layout, ResidualLayout):
            raise TypeError("layout must be ResidualLayout")
        if not isinstance(self.public, PublicTargetView):
            raise TypeError("public must be PublicTargetView")
        self.public.validate()
        _binary_bits(
            self.fixed_bits,
            length=self.layout.fixed_bit_count,
            field="fixed_bits",
        )

    @property
    def fixed_bits_sha256(self) -> str:
        packed = np.packbits(
            np.asarray(self.fixed_bits, dtype=np.uint8), bitorder="little"
        ).tobytes()
        return hashlib.sha256(packed).hexdigest()

    def candidate_key(self, residual_assignment: int) -> bytes:
        if (
            isinstance(residual_assignment, bool)
            or not isinstance(residual_assignment, int)
            or not 0 <= residual_assignment < 1 << self.layout.residual_width
        ):
            raise ResidualRecoveryHandoffError(
                "residual_assignment is outside the backend domain"
            )
        residual = tuple(
            (residual_assignment >> coordinate) & 1
            for coordinate in range(self.layout.residual_width)
        )
        return bits_to_key((*residual, *self.fixed_bits))

    def verify(self, residual_assignment: int) -> bool:
        key = self.candidate_key(residual_assignment)
        return all(
            chacha20_block(key, counter, self.public.nonce) == output
            for counter, output in zip(
                self.public.counter_schedule,
                self.public.output_blocks,
                strict=True,
            )
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-256-residual-recovery-handoff-v1",
            "backend": self.layout.backend,
            "residual_coordinates": [0, self.layout.residual_width - 1],
            "residual_width": self.layout.residual_width,
            "fixed_coordinates": [self.layout.residual_width, KEY_BITS - 1],
            "fixed_bit_count": self.layout.fixed_bit_count,
            "fixed_bits_sha256": self.fixed_bits_sha256,
            "public_view_sha256": self.public.digest(),
            "candidate_codec": "little_endian_key_coordinates_0_through_255",
        }


__all__ = [
    "A325_W46",
    "A526_W52",
    "ComplementGate",
    "ResidualLayout",
    "ResidualRecoveryHandoff",
    "ResidualRecoveryHandoffError",
    "completion_from_logits",
    "post_reveal_complement_gate",
]
