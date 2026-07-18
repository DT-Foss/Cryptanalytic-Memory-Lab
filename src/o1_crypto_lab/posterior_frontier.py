"""Exact lazy top-K decoding for factorized full-256 key posteriors.

For a factorized Bernoulli posterior, every key is the coordinate-wise MAP key
plus a subset of bit flips.  Its log-probability differs from the MAP key by
the sum of non-negative per-bit log-odds penalties.  This module enumerates the
globally smallest subset sums without restricting flips to a preselected
uncertainty window.

Generation is truth-free.  Truth and exact public ChaCha20 verification live
in separate consumers so a frontier can be frozen before reveal.
"""

from __future__ import annotations

import hashlib
import heapq
import math
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from itertools import islice

import numpy as np

from .chacha_trace import chacha20_block_trace
from .living_inverse import (
    KEY_BITS,
    KEY_BYTES,
    PublicTargetView,
    bits_to_key,
    canonical_json_bytes,
    key_bits,
)


FRONTIER_SCHEMA = "o1-256-factorized-topk-candidate-v1"
EVALUATION_SCHEMA = "o1-256-factorized-topk-evaluation-v1"
VERIFICATION_SCHEMA = "o1-256-factorized-topk-public-verification-v1"
SMALL_WIDTH_PROOF_SCHEMA = "o1-256-factorized-topk-small-width-proof-v1"
TOPOLOGY_TIE_POLICY = (
    "ascending-flip-penalty-then-coordinate topology; equal subset sums use "
    "ascending topology bitmask"
)


class PosteriorFrontierError(ValueError):
    """A posterior, frontier request, candidate stream, or proof differs."""


@dataclass(frozen=True)
class FactorizedFrontierCandidate:
    """One globally ranked full-width factorized-posterior candidate."""

    rank: int
    key: bytes
    log2_probability: float
    flip_penalty_bits: float
    flipped_coordinates: tuple[int, ...]
    topology_code: int

    def describe(self) -> dict[str, object]:
        return {
            "schema": FRONTIER_SCHEMA,
            "rank": self.rank,
            "key_hex": self.key.hex(),
            "log2_probability": self.log2_probability,
            "flip_penalty_bits": self.flip_penalty_bits,
            "flipped_coordinates": list(self.flipped_coordinates),
            "topology_code_hex": f"{self.topology_code:064x}",
            "tie_policy": TOPOLOGY_TIE_POLICY,
        }


@dataclass(frozen=True)
class _FactorizedPlan:
    probabilities: tuple[float, ...]
    mode_bits: tuple[int, ...]
    topology: tuple[int, ...]
    penalties: tuple[float, ...]
    map_log2_probability: float


def _probabilities(
    values: Sequence[float] | np.ndarray,
    *,
    exact_width: int | None,
) -> np.ndarray:
    probabilities = np.asarray(values, dtype=np.float64)
    if probabilities.ndim != 1 or (
        exact_width is not None and probabilities.shape != (exact_width,)
    ):
        if exact_width is None:
            raise PosteriorFrontierError("posterior must be one-dimensional")
        raise PosteriorFrontierError(
            f"posterior must contain exactly {exact_width} probabilities"
        )
    if probabilities.size < 1:
        raise PosteriorFrontierError("posterior must not be empty")
    if not np.all(np.isfinite(probabilities)) or np.any(
        (probabilities <= 0.0) | (probabilities >= 1.0)
    ):
        raise PosteriorFrontierError("posterior probabilities must be finite in (0, 1)")
    return probabilities


def _candidate_limit(value: object, width: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 1 << width
    ):
        raise PosteriorFrontierError(
            f"candidate limit must be an integer in [1, 2^{width}]"
        )
    return value


def _make_plan(probabilities: np.ndarray) -> _FactorizedPlan:
    values = tuple(float(value) for value in probabilities)
    mode = tuple(int(value >= 0.5) for value in values)
    coordinate_penalties = tuple(
        abs(math.log2(value) - math.log2(1.0 - value)) for value in values
    )
    topology = tuple(
        sorted(
            range(len(values)), key=lambda index: (coordinate_penalties[index], index)
        )
    )
    penalties = tuple(coordinate_penalties[index] for index in topology)
    map_log2_probability = math.fsum(
        math.log2(max(value, 1.0 - value)) for value in values
    )
    return _FactorizedPlan(
        probabilities=values,
        mode_bits=mode,
        topology=topology,
        penalties=penalties,
        map_log2_probability=map_log2_probability,
    )


def _mask_positions(mask: int) -> Iterator[int]:
    value = mask
    while value:
        least = value & -value
        yield least.bit_length() - 1
        value ^= least


def _scaled_penalty_units(
    penalties: tuple[float, ...],
) -> tuple[tuple[int, ...], int]:
    """Represent all binary64 penalties over one exact power-of-two scale."""

    ratios = tuple(penalty.as_integer_ratio() for penalty in penalties)
    scale_exponents = tuple(denominator.bit_length() - 1 for _, denominator in ratios)
    common_exponent = max(scale_exponents, default=0)
    units = tuple(
        numerator << (common_exponent - exponent)
        for (numerator, _), exponent in zip(ratios, scale_exponents, strict=True)
    )
    return units, 1 << common_exponent


def _exhaustive_mask_penalty(mask: int, penalties: tuple[float, ...]) -> float:
    """Independently score a mask for the tractable exhaustive proof only."""

    return math.fsum(penalties[index] for index in _mask_positions(mask))


def _iter_subset_states(
    penalties: tuple[float, ...], limit: int
) -> Iterator[tuple[int, float, int]]:
    """Yield (rank, penalty, topology mask) in exact global order.

    Every non-empty subset has one parent.  If its largest topology position is
    ``j``, the parent either removes ``j`` when ``j-1`` is present or replaces
    ``j`` by ``j-1`` otherwise.  Because penalties are sorted, both forward
    children have non-decreasing cost.  The topology mask strictly increases
    along every edge, which also makes the equal-cost ordering discoverable by
    the same heap without materializing the search space.
    """

    width = len(penalties)
    penalty_units, unit_denominator = _scaled_penalty_units(penalties)
    # Exact integer units make both child updates constant-time.  The rounded
    # binary64 value remains the primary heap key, matching the public score
    # and exhaustive-proof semantics; the topology mask resolves every tie.
    heap: list[tuple[float, int, int, int]] = [(0.0, 0, -1, 0)]
    previous: tuple[float, int] | None = None
    for rank in range(1, limit + 1):
        if not heap:
            raise AssertionError("factorized subset frontier ended early")
        penalty, mask, last, exact_units = heapq.heappop(heap)
        order_key = (penalty, mask)
        if previous is not None and order_key < previous:
            raise AssertionError("factorized subset frontier is not ordered")
        previous = order_key
        yield rank, penalty, mask

        next_position = last + 1
        if next_position >= width:
            continue
        add_mask = mask | (1 << next_position)
        add_units = exact_units + penalty_units[next_position]
        heapq.heappush(
            heap,
            (
                add_units / unit_denominator,
                add_mask,
                next_position,
                add_units,
            ),
        )
        if last >= 0:
            replace_mask = (mask ^ (1 << last)) | (1 << next_position)
            replace_units = (
                exact_units - penalty_units[last] + penalty_units[next_position]
            )
            heapq.heappush(
                heap,
                (
                    replace_units / unit_denominator,
                    replace_mask,
                    next_position,
                    replace_units,
                ),
            )


def _candidate_from_state(
    plan: _FactorizedPlan,
    rank: int,
    penalty: float,
    mask: int,
) -> FactorizedFrontierCandidate:
    bits = np.asarray(plan.mode_bits, dtype=np.uint8)
    flipped = tuple(plan.topology[index] for index in _mask_positions(mask))
    if flipped:
        bits[np.asarray(flipped, dtype=np.int64)] ^= 1
    return FactorizedFrontierCandidate(
        rank=rank,
        key=bits_to_key(bits),
        log2_probability=plan.map_log2_probability - penalty,
        flip_penalty_bits=penalty,
        flipped_coordinates=flipped,
        topology_code=mask,
    )


def iter_factorized_topk(
    probabilities: Sequence[float] | np.ndarray,
    *,
    limit: int,
) -> Iterator[FactorizedFrontierCandidate]:
    """Return a truth-free lazy stream of the global factorized top-K keys.

    Runtime is ``O(K log K)`` after sorting 256 flip penalties; retained state
    is proportional to the emitted frontier, never to the ``2^256`` keyspace.
    """

    checked = _probabilities(probabilities, exact_width=KEY_BITS)
    checked_limit = _candidate_limit(limit, KEY_BITS)
    plan = _make_plan(checked)

    def generate() -> Iterator[FactorizedFrontierCandidate]:
        for rank, penalty, mask in _iter_subset_states(plan.penalties, checked_limit):
            yield _candidate_from_state(plan, rank, penalty, mask)

    return generate()


def _validate_candidate(
    candidate: object,
    *,
    expected_rank: int,
    previous_order: tuple[float, int] | None,
) -> tuple[FactorizedFrontierCandidate, tuple[float, int]]:
    if not isinstance(candidate, FactorizedFrontierCandidate):
        raise PosteriorFrontierError("frontier stream contains a foreign candidate")
    if candidate.rank != expected_rank:
        raise PosteriorFrontierError("frontier candidate ranks are not contiguous")
    if not isinstance(candidate.key, bytes) or len(candidate.key) != KEY_BYTES:
        raise PosteriorFrontierError("frontier candidate key width differs")
    if (
        not math.isfinite(candidate.flip_penalty_bits)
        or candidate.flip_penalty_bits < 0.0
        or not math.isfinite(candidate.log2_probability)
        or candidate.log2_probability > 0.0
    ):
        raise PosteriorFrontierError("frontier candidate score differs")
    if (
        isinstance(candidate.topology_code, bool)
        or not isinstance(candidate.topology_code, int)
        or not 0 <= candidate.topology_code < 1 << KEY_BITS
    ):
        raise PosteriorFrontierError("frontier topology code differs")
    if any(
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < KEY_BITS
        for value in candidate.flipped_coordinates
    ) or len(candidate.flipped_coordinates) != len(set(candidate.flipped_coordinates)):
        raise PosteriorFrontierError("frontier flipped coordinates differ")
    order = (candidate.flip_penalty_bits, candidate.topology_code)
    if previous_order is not None and order < previous_order:
        raise PosteriorFrontierError("frontier candidates are not globally ordered")
    return candidate, order


def _hamming_bytes(left: bytes, right: bytes) -> int:
    return sum(
        (left_byte ^ right_byte).bit_count()
        for left_byte, right_byte in zip(left, right, strict=True)
    )


def evaluate_factorized_frontier(
    true_key: bytes,
    candidates: Iterable[FactorizedFrontierCandidate],
) -> dict[str, object]:
    """Score an already generated frontier after reveal in one streaming pass."""

    try:
        truth = bits_to_key(key_bits(true_key))
    except ValueError as exc:
        raise PosteriorFrontierError("true key must be exactly 32 bytes") from exc
    digest = hashlib.sha256(b"o1-256-factorized-topk-candidate-stream-v1\0")
    count = 0
    true_rank: int | None = None
    best_hamming = KEY_BITS + 1
    best_hamming_rank: int | None = None
    previous_order: tuple[float, int] | None = None
    first_log2_probability: float | None = None
    final_log2_probability: float | None = None
    for expected_rank, raw in enumerate(candidates, start=1):
        candidate, previous_order = _validate_candidate(
            raw,
            expected_rank=expected_rank,
            previous_order=previous_order,
        )
        count = expected_rank
        digest.update(canonical_json_bytes(candidate.describe()))
        distance = _hamming_bytes(candidate.key, truth)
        if distance < best_hamming:
            best_hamming = distance
            best_hamming_rank = candidate.rank
        if candidate.key == truth and true_rank is None:
            true_rank = candidate.rank
        if first_log2_probability is None:
            first_log2_probability = candidate.log2_probability
        final_log2_probability = candidate.log2_probability
    if count == 0:
        raise PosteriorFrontierError("frontier candidate stream is empty")
    return {
        "schema": EVALUATION_SCHEMA,
        "candidate_count": count,
        "tie_policy": TOPOLOGY_TIE_POLICY,
        "candidate_stream_sha256": digest.hexdigest(),
        "true_key_sha256": hashlib.sha256(truth).hexdigest(),
        "exact_key_hit": true_rank is not None,
        "true_rank_one_based": true_rank,
        "best_hamming_distance": best_hamming,
        "best_hamming_rank_one_based": best_hamming_rank,
        "first_log2_probability": first_log2_probability,
        "frontier_cutoff_log2_probability": final_log2_probability,
    }


def _candidate_matches_public_target(
    candidate_key: bytes, target: PublicTargetView
) -> bool:
    return all(
        chacha20_block_trace(candidate_key, counter, target.nonce).output == expected
        for counter, expected in zip(
            target.counter_schedule, target.output_blocks, strict=True
        )
    )


def verify_frontier_against_public_target(
    target: PublicTargetView,
    candidates: Iterable[FactorizedFrontierCandidate],
    *,
    stop_on_first_match: bool = True,
    maximum_candidates: int | None = None,
) -> dict[str, object]:
    """Stream candidate keys through exact public ChaCha20 verification."""

    if not isinstance(target, PublicTargetView):
        raise PosteriorFrontierError("target must be a PublicTargetView")
    target.validate()
    if not isinstance(stop_on_first_match, bool):
        raise PosteriorFrontierError("stop_on_first_match must be boolean")
    if maximum_candidates is not None and (
        isinstance(maximum_candidates, bool)
        or not isinstance(maximum_candidates, int)
        or maximum_candidates < 1
    ):
        raise PosteriorFrontierError("maximum_candidates must be positive")

    digest = hashlib.sha256(b"o1-256-factorized-topk-verified-stream-v1\0")
    count = 0
    match_count = 0
    first_match_rank: int | None = None
    first_match_key: bytes | None = None
    previous_order: tuple[float, int] | None = None
    stopped_on_match = False
    bounded_candidates = (
        candidates
        if maximum_candidates is None
        else islice(candidates, maximum_candidates)
    )
    for expected_rank, raw in enumerate(bounded_candidates, start=1):
        candidate, previous_order = _validate_candidate(
            raw,
            expected_rank=expected_rank,
            previous_order=previous_order,
        )
        count = expected_rank
        digest.update(canonical_json_bytes(candidate.describe()))
        if _candidate_matches_public_target(candidate.key, target):
            match_count += 1
            if first_match_rank is None:
                first_match_rank = candidate.rank
                first_match_key = candidate.key
            if stop_on_first_match:
                stopped_on_match = True
                break
    if count == 0:
        raise PosteriorFrontierError("frontier candidate stream is empty")
    limit_reached = (
        maximum_candidates is not None
        and count == maximum_candidates
        and not stopped_on_match
    )
    return {
        "schema": VERIFICATION_SCHEMA,
        "target_sha256": target.digest(),
        "candidate_stream_sha256": digest.hexdigest(),
        "candidates_verified": count,
        "exact_match_found": first_match_rank is not None,
        "exact_match_count": match_count,
        "first_match_rank_one_based": first_match_rank,
        "first_match_key_hex": first_match_key.hex() if first_match_key else None,
        "stopped_on_first_match": stopped_on_match,
        "verification_limit_reached": limit_reached,
    }


def exhaustive_small_width_proof(
    probabilities: Sequence[float] | np.ndarray,
    *,
    limit: int,
) -> dict[str, object]:
    """Exhaustively certify the heap order on a tractable factorized space."""

    checked = _probabilities(probabilities, exact_width=None)
    width = int(checked.size)
    if width > 20:
        raise PosteriorFrontierError("small-width proof is limited to 20 bits")
    checked_limit = _candidate_limit(limit, width)
    plan = _make_plan(checked)
    best_first = list(_iter_subset_states(plan.penalties, checked_limit))
    exhaustive = sorted(
        (
            (
                _exhaustive_mask_penalty(mask, plan.penalties),
                mask,
            )
            for mask in range(1 << width)
        ),
        key=lambda row: (row[0], row[1]),
    )[:checked_limit]
    best_first_rows = [
        {"rank": rank, "penalty_float64_hex": penalty.hex(), "topology_code": mask}
        for rank, penalty, mask in best_first
    ]
    exhaustive_rows = [
        {
            "rank": rank,
            "penalty_float64_hex": penalty.hex(),
            "topology_code": mask,
        }
        for rank, (penalty, mask) in enumerate(exhaustive, start=1)
    ]
    match = best_first_rows == exhaustive_rows
    unsigned = {
        "schema": SMALL_WIDTH_PROOF_SCHEMA,
        "width": width,
        "candidate_count": checked_limit,
        "tie_policy": TOPOLOGY_TIE_POLICY,
        "topology": list(plan.topology),
        "best_first": best_first_rows,
        "exhaustive": exhaustive_rows,
        "orders_match": match,
    }
    return {
        **unsigned,
        "proof_sha256": hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest(),
    }


__all__ = [
    "EVALUATION_SCHEMA",
    "FRONTIER_SCHEMA",
    "FactorizedFrontierCandidate",
    "PosteriorFrontierError",
    "SMALL_WIDTH_PROOF_SCHEMA",
    "TOPOLOGY_TIE_POLICY",
    "VERIFICATION_SCHEMA",
    "evaluate_factorized_frontier",
    "exhaustive_small_width_proof",
    "iter_factorized_topk",
    "verify_frontier_against_public_target",
]
