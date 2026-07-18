"""Exact O1-logit to native A526/W52 complement frontier.

The sibling A526 engine searches key coordinates 0..51 and requires coordinates
52..255 to be fixed.  This module ranks only those 204 fixed coordinates.  It
does not alter A526's layout, search order, candidate semantics, or verifier.
"""

from __future__ import annotations

import hashlib
import heapq
import math
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

import numpy as np

from .living_inverse import KEY_BITS, PublicTargetView, key_bits
from .residual_recovery_handoff import A526_W52, ResidualRecoveryHandoff


A526_RESIDUAL_WIDTH = 52
A526_FIXED_WIDTH = KEY_BITS - A526_RESIDUAL_WIDTH
A526_FIXED_COORDINATES = tuple(range(A526_RESIDUAL_WIDTH, KEY_BITS))
A526_COMPLEMENT_SCHEMA = "o1-256-a526-complement-candidate-v1"
A526_EVALUATION_SCHEMA = "o1-256-a526-complement-frontier-evaluation-v1"


class A526CompletionFrontierError(ValueError):
    """The posterior, frontier request, or A526 complement differs."""


@dataclass(frozen=True)
class A526ComplementCandidate:
    """One exact factorized-posterior assignment of A526's 204 fixed bits."""

    rank: int
    fixed_bits: tuple[int, ...]
    exact_penalty_units: int
    penalty_unit_exponent: int
    flipped_coordinates: tuple[int, ...]
    topology_code: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.rank, bool)
            or not isinstance(self.rank, int)
            or self.rank < 1
            or len(self.fixed_bits) != A526_FIXED_WIDTH
            or any(bit not in (0, 1) for bit in self.fixed_bits)
        ):
            raise A526CompletionFrontierError("A526 complement candidate differs")

    @property
    def fixed_bits_sha256(self) -> str:
        payload = np.packbits(
            np.asarray(self.fixed_bits, dtype=np.uint8), bitorder="little"
        ).tobytes()
        return hashlib.sha256(payload).hexdigest()

    def handoff(self, public: PublicTargetView) -> ResidualRecoveryHandoff:
        """Bind this complement to the unchanged native A526 layout."""

        return ResidualRecoveryHandoff(A526_W52, public, self.fixed_bits)

    def describe(self) -> dict[str, object]:
        return {
            "schema": A526_COMPLEMENT_SCHEMA,
            "rank": self.rank,
            "backend": A526_W52.backend,
            "residual_coordinates": [0, A526_RESIDUAL_WIDTH - 1],
            "fixed_coordinates": [A526_RESIDUAL_WIDTH, KEY_BITS - 1],
            "fixed_bit_count": A526_FIXED_WIDTH,
            "fixed_bits_sha256": self.fixed_bits_sha256,
            "exact_penalty_units": self.exact_penalty_units,
            "penalty_unit_exponent": self.penalty_unit_exponent,
            "flipped_coordinates": list(self.flipped_coordinates),
            "topology_code_hex": f"{self.topology_code:051x}",
        }


@dataclass(frozen=True)
class _CompletionPlan:
    logits: np.ndarray
    mode_bits: tuple[int, ...]
    topology: tuple[int, ...]
    penalty_units: tuple[int, ...]
    penalty_unit_exponent: int


def _checked_limit(limit: object) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 1 << A526_FIXED_WIDTH
    ):
        raise A526CompletionFrontierError(
            f"limit must be an integer in [1, 2^{A526_FIXED_WIDTH}]"
        )
    return limit


def _make_plan(values: Sequence[float] | np.ndarray) -> _CompletionPlan:
    try:
        logits = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise A526CompletionFrontierError(
            "logits must be finite float64[256]"
        ) from exc
    if logits.shape != (KEY_BITS,) or not bool(np.isfinite(logits).all()):
        raise A526CompletionFrontierError("logits must be finite float64[256]")
    fixed = np.ascontiguousarray(logits[A526_RESIDUAL_WIDTH:], dtype=np.float64)
    ratios = tuple(abs(float(value)).as_integer_ratio() for value in fixed)
    exponents = tuple(denominator.bit_length() - 1 for _, denominator in ratios)
    common_exponent = max(exponents, default=0)
    coordinate_units = tuple(
        numerator << (common_exponent - exponent)
        for (numerator, _), exponent in zip(ratios, exponents, strict=True)
    )
    topology_local = tuple(
        sorted(
            range(A526_FIXED_WIDTH),
            key=lambda index: (coordinate_units[index], index),
        )
    )
    fixed.setflags(write=False)
    return _CompletionPlan(
        logits=fixed,
        mode_bits=tuple(int(value >= 0.0) for value in fixed),
        topology=tuple(
            A526_RESIDUAL_WIDTH + index for index in topology_local
        ),
        penalty_units=tuple(coordinate_units[index] for index in topology_local),
        penalty_unit_exponent=common_exponent,
    )


def _mask_positions(mask: int) -> Iterator[int]:
    value = mask
    while value:
        least = value & -value
        yield least.bit_length() - 1
        value ^= least


def _iter_subset_states(
    penalty_units: tuple[int, ...], limit: int
) -> Iterator[tuple[int, int, int]]:
    """Yield rank, exact natural-logit penalty units, and topology mask."""

    heap: list[tuple[int, int, int]] = [(0, 0, -1)]
    previous: tuple[int, int] | None = None
    for rank in range(1, limit + 1):
        if not heap:
            raise AssertionError("A526 complement frontier ended early")
        exact_units, mask, last = heapq.heappop(heap)
        order = (exact_units, mask)
        if previous is not None and order < previous:
            raise AssertionError("A526 complement frontier is not ordered")
        previous = order
        yield rank, exact_units, mask

        next_position = last + 1
        if next_position >= A526_FIXED_WIDTH:
            continue
        heapq.heappush(
            heap,
            (
                exact_units + penalty_units[next_position],
                mask | (1 << next_position),
                next_position,
            ),
        )
        if last >= 0:
            heapq.heappush(
                heap,
                (
                    exact_units
                    - penalty_units[last]
                    + penalty_units[next_position],
                    (mask ^ (1 << last)) | (1 << next_position),
                    next_position,
                ),
            )


def iter_a526_complement_topk(
    logits: Sequence[float] | np.ndarray,
    *,
    limit: int,
) -> Iterator[A526ComplementCandidate]:
    """Lazily emit the exact top-K assignments of A526's fixed complement."""

    plan = _make_plan(logits)
    checked_limit = _checked_limit(limit)

    def generate() -> Iterator[A526ComplementCandidate]:
        for rank, exact_units, mask in _iter_subset_states(
            plan.penalty_units, checked_limit
        ):
            bits = list(plan.mode_bits)
            flipped = tuple(
                plan.topology[position] for position in _mask_positions(mask)
            )
            for coordinate in flipped:
                bits[coordinate - A526_RESIDUAL_WIDTH] ^= 1
            yield A526ComplementCandidate(
                rank=rank,
                fixed_bits=tuple(bits),
                exact_penalty_units=exact_units,
                penalty_unit_exponent=plan.penalty_unit_exponent,
                flipped_coordinates=flipped,
                topology_code=mask,
            )

    return generate()


def evaluate_a526_complement_topk(
    logits: Sequence[float] | np.ndarray,
    *,
    truth_key: bytes,
    limit: int,
) -> dict[str, object]:
    """Score a frozen complement frontier after reveal without running W52."""

    plan = _make_plan(logits)
    checked_limit = _checked_limit(limit)
    try:
        truth = key_bits(truth_key)[A526_RESIDUAL_WIDTH:]
    except ValueError as exc:
        raise A526CompletionFrontierError(
            "truth_key must be exactly 32 bytes"
        ) from exc

    error_mask = 0
    for position, coordinate in enumerate(plan.topology):
        local = coordinate - A526_RESIDUAL_WIDTH
        if plan.mode_bits[local] != int(truth[local]):
            error_mask |= 1 << position
    map_errors = error_mask.bit_count()
    best_errors = map_errors
    best_rank = 1
    exact_rank: int | None = None
    exact_penalty_units = sum(
        plan.penalty_units[position] for position in _mask_positions(error_mask)
    )
    for rank, _, mask in _iter_subset_states(plan.penalty_units, checked_limit):
        errors = (error_mask ^ mask).bit_count()
        if errors < best_errors:
            best_errors = errors
            best_rank = rank
        if mask == error_mask:
            exact_rank = rank
            break

    logits_payload = np.asarray(logits, dtype="<f8").tobytes(order="C")
    return {
        "schema": A526_EVALUATION_SCHEMA,
        "backend": A526_W52.backend,
        "residual_width": A526_RESIDUAL_WIDTH,
        "fixed_width": A526_FIXED_WIDTH,
        "posterior_logits_sha256": hashlib.sha256(logits_payload).hexdigest(),
        "frontier_limit": checked_limit,
        "map_correct_fixed_bits": A526_FIXED_WIDTH - map_errors,
        "map_wrong_fixed_bits": map_errors,
        "best_beam_correct_fixed_bits": A526_FIXED_WIDTH - best_errors,
        "best_beam_wrong_fixed_bits": best_errors,
        "best_beam_rank_one_based": best_rank,
        "exact_complement_in_beam": exact_rank is not None,
        "exact_complement_rank_one_based": exact_rank,
        "exact_complement_rank_lower_bound": (
            None if exact_rank is not None else checked_limit + 1
        ),
        "exact_complement_penalty_units": exact_penalty_units,
        "penalty_unit_exponent": plan.penalty_unit_exponent,
        "w52_domains_before_or_at_exact_complement": exact_rank,
        "beam_worst_case_candidate_work_log2": (
            A526_RESIDUAL_WIDTH + math.log2(checked_limit)
        ),
        "backend_launched": False,
        "truth_used_only_after_frontier_definition": True,
    }


__all__ = [
    "A526_COMPLEMENT_SCHEMA",
    "A526_EVALUATION_SCHEMA",
    "A526_FIXED_COORDINATES",
    "A526_FIXED_WIDTH",
    "A526_RESIDUAL_WIDTH",
    "A526ComplementCandidate",
    "A526CompletionFrontierError",
    "evaluate_a526_complement_topk",
    "iter_a526_complement_topk",
]
