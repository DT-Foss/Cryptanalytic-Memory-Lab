"""Truth-free global factor bounds and a bounded Full256 prefix beam."""

from __future__ import annotations

import hashlib
import heapq
import math
import struct
import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)


KEY_BITS = 256
FROZEN_PAIR_VARIABLES = 126
PAIR_COUNT = 128
COMPLETION_PAIR_COUNT = 65
MAXIMUM_KEY_VARIABLES_PER_FACTOR = 2
LOGICAL_NODE_BYTES = 48
DEFAULT_BEAM_WIDTH = 256

_NODE = struct.Struct("<32sdIHBB")


class GlobalFactorBoundError(RuntimeError):
    """A factor bound, prefix, or bounded-beam contract was violated."""


def _key_integer(key: bytes) -> int:
    if not isinstance(key, bytes) or len(key) != 32:
        raise GlobalFactorBoundError("key bytes differ")
    return int.from_bytes(key, "little")


def _key_spin(key: bytes, variable: int) -> int:
    if not 1 <= variable <= KEY_BITS:
        raise GlobalFactorBoundError("key variable differs")
    byte, bit = divmod(variable - 1, 8)
    return 1 if key[byte] & (1 << bit) else -1


def _set_key_spin(key: bytearray, variable: int, spin: int) -> None:
    if len(key) != 32 or not 1 <= variable <= KEY_BITS or spin not in (-1, 1):
        raise GlobalFactorBoundError("key update differs")
    byte, bit = divmod(variable - 1, 8)
    mask = 1 << bit
    if spin > 0:
        key[byte] |= mask
    else:
        key[byte] &= ~mask


def compile_pair_order(
    primary_ordered_variables: Iterable[int],
) -> tuple[tuple[int, int], ...]:
    """Keep the 63 frozen pairs and append all unused variables in order."""

    variables = tuple(primary_ordered_variables)
    if (
        len(variables) != FROZEN_PAIR_VARIABLES
        or len(set(variables)) != len(variables)
        or any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= KEY_BITS
            for variable in variables
        )
    ):
        raise GlobalFactorBoundError("frozen pair variables differ")
    frozen = tuple(zip(variables[::2], variables[1::2], strict=True))
    remaining = tuple(sorted(set(range(1, KEY_BITS + 1)).difference(variables)))
    completion = tuple(zip(remaining[::2], remaining[1::2], strict=True))
    pairs = frozen + completion
    flattened = tuple(variable for pair in pairs for variable in pair)
    if (
        len(frozen) != 63
        or len(remaining) != 130
        or len(completion) != COMPLETION_PAIR_COUNT
        or len(pairs) != PAIR_COUNT
        or len(set(flattened)) != KEY_BITS
        or set(flattened) != set(range(1, KEY_BITS + 1))
    ):
        raise GlobalFactorBoundError("completed pair order differs")
    return pairs


def _decode_ternary(index: int, width: int) -> tuple[int, ...]:
    digits: list[int] = []
    for _ in range(width):
        digits.append(index % 3)
        index //= 3
    if index:
        raise GlobalFactorBoundError("ternary state differs")
    return tuple(digits)


def _ternary_index(digits: Sequence[int]) -> int:
    result = 0
    scale = 1
    for digit in digits:
        if digit not in (0, 1, 2):
            raise GlobalFactorBoundError("ternary digit differs")
        result += digit * scale
        scale *= 3
    return result


@dataclass(frozen=True)
class ConditionalFactor:
    variables: tuple[int, ...]
    key_variables: tuple[int, ...]
    maxima: tuple[float, ...]

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.key_variables) <= MAXIMUM_KEY_VARIABLES_PER_FACTOR
            or len(self.maxima) != 3 ** len(self.key_variables)
            or any(not math.isfinite(value) for value in self.maxima)
        ):
            raise GlobalFactorBoundError("conditional factor differs")

    def value(self, key: bytes, assigned: frozenset[int]) -> float:
        digits = tuple(
            (2 if _key_spin(key, variable) > 0 else 1) if variable in assigned else 0
            for variable in self.key_variables
        )
        return self.maxima[_ternary_index(digits)]


def _compile_conditional_factor(
    factor: CriticalityPotentialFactor,
) -> ConditionalFactor:
    key_variables = tuple(
        variable for variable in factor.variables if variable <= KEY_BITS
    )
    if not 1 <= len(key_variables) <= MAXIMUM_KEY_VARIABLES_PER_FACTOR:
        raise GlobalFactorBoundError("factor key width differs")
    positions = {
        variable: factor.variables.index(variable) for variable in key_variables
    }
    maxima: list[float] = []
    for state in range(3 ** len(key_variables)):
        digits = _decode_ternary(state, len(key_variables))
        best = -math.inf
        for mask, energy in enumerate(factor.energies):
            consistent = True
            for variable, digit in zip(key_variables, digits, strict=True):
                if digit == 0:
                    continue
                positive = bool(mask & (1 << positions[variable]))
                if positive != (digit == 2):
                    consistent = False
                    break
            if consistent:
                best = max(best, energy)
        if not math.isfinite(best):
            raise GlobalFactorBoundError("conditional maximum is absent")
        maxima.append(best)
    return ConditionalFactor(factor.variables, key_variables, tuple(maxima))


@dataclass(frozen=True)
class ConditionalFactorBoundIndex:
    offset: float
    source_sha256: str
    factors: tuple[ConditionalFactor, ...]
    guard: float
    table_sha256: str
    serialized_sha256: str
    serialized_bytes: int

    @property
    def conditional_entries(self) -> int:
        return sum(len(factor.maxima) for factor in self.factors)

    @property
    def conditional_table_bytes(self) -> int:
        return 8 * self.conditional_entries

    @property
    def root_nominal_bound(self) -> float:
        return math.fsum((self.offset, *(factor.maxima[0] for factor in self.factors)))

    @property
    def root_bound(self) -> float:
        return self.root_nominal_bound + self.guard

    def nominal_bound(self, key: bytes, assigned_variables: Iterable[int]) -> float:
        _key_integer(key)
        assigned = frozenset(assigned_variables)
        if any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= KEY_BITS
            for variable in assigned
        ):
            raise GlobalFactorBoundError("assigned key variables differ")
        return math.fsum(
            (
                self.offset,
                *(factor.value(key, assigned) for factor in self.factors),
            )
        )

    def bound(self, key: bytes, assigned_variables: Iterable[int]) -> float:
        return self.nominal_bound(key, assigned_variables) + self.guard

    def describe(self) -> dict[str, object]:
        widths = [len(factor.key_variables) for factor in self.factors]
        return {
            "schema": "o1-256-conditional-factor-bound-index-v1",
            "source_sha256": self.source_sha256,
            "factor_count": len(self.factors),
            "unary_key_factors": widths.count(1),
            "binary_key_factors": widths.count(2),
            "maximum_key_variables_per_factor": max(widths),
            "conditional_entries": self.conditional_entries,
            "conditional_table_bytes": self.conditional_table_bytes,
            "guard": self.guard,
            "root_nominal_bound": self.root_nominal_bound,
            "root_bound": self.root_bound,
            "table_sha256": self.table_sha256,
            "serialized_sha256": self.serialized_sha256,
            "serialized_bytes": self.serialized_bytes,
        }


def _index_bytes(
    field: CriticalityPotentialField, factors: Sequence[ConditionalFactor], guard: float
) -> tuple[bytes, bytes]:
    tables = bytearray()
    metadata = bytearray()
    metadata.extend(b"O1-FACTOR-BOUND-V1\0")
    metadata.extend(struct.pack("<ddI", field.offset, guard, len(factors)))
    metadata.extend(bytes.fromhex(field.source_sha256))
    for factor in factors:
        metadata.extend(struct.pack("<B", len(factor.key_variables)))
        metadata.extend(
            struct.pack(
                "<HH",
                factor.key_variables[0],
                factor.key_variables[1] if len(factor.key_variables) == 2 else 0,
            )
        )
        metadata.extend(struct.pack("<I", len(tables) // 8))
        for value in factor.maxima:
            tables.extend(struct.pack("<d", value))
    return bytes(metadata), bytes(tables)


def compile_factor_bound_index(
    field: CriticalityPotentialField,
) -> ConditionalFactorBoundIndex:
    """Compile exact maxima for unknown/negative/positive key states."""

    if not isinstance(field, CriticalityPotentialField):
        raise GlobalFactorBoundError("potential field differs")
    factors = tuple(_compile_conditional_factor(factor) for factor in field.factors)
    absolute_envelope = math.fsum(
        (
            abs(field.offset),
            *(max(abs(value) for value in factor.maxima) for factor in factors),
        )
    )
    guard = math.nextafter(
        8192.0 * sys.float_info.epsilon * max(1.0, absolute_envelope), math.inf
    )
    metadata, tables = _index_bytes(field, factors, guard)
    serialized = metadata + tables
    return ConditionalFactorBoundIndex(
        offset=field.offset,
        source_sha256=field.source_sha256,
        factors=factors,
        guard=guard,
        table_sha256=hashlib.sha256(tables).hexdigest(),
        serialized_sha256=hashlib.sha256(serialized).hexdigest(),
        serialized_bytes=len(serialized),
    )


@dataclass(frozen=True)
class LogicalBeamNode:
    key: bytes
    nominal_bound: float
    parent_ordinal: int
    depth: int
    pair_mask: int
    flags: int = 0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key, bytes)
            or len(self.key) != 32
            or not math.isfinite(self.nominal_bound)
            or isinstance(self.parent_ordinal, bool)
            or not isinstance(self.parent_ordinal, int)
            or not 0 <= self.parent_ordinal < 1 << 32
            or isinstance(self.depth, bool)
            or not isinstance(self.depth, int)
            or not 0 <= self.depth <= PAIR_COUNT
            or self.pair_mask not in range(4)
            or isinstance(self.flags, bool)
            or not isinstance(self.flags, int)
            or not 0 <= self.flags <= 255
        ):
            raise GlobalFactorBoundError("logical beam node differs")

    @property
    def key_integer(self) -> int:
        return _key_integer(self.key)

    def to_bytes(self) -> bytes:
        payload = _NODE.pack(
            self.key,
            self.nominal_bound,
            self.parent_ordinal,
            self.depth,
            self.pair_mask,
            self.flags,
        )
        if len(payload) != LOGICAL_NODE_BYTES:
            raise GlobalFactorBoundError("logical node encoding differs")
        return payload

    @classmethod
    def from_bytes(cls, payload: bytes) -> LogicalBeamNode:
        if not isinstance(payload, bytes) or len(payload) != LOGICAL_NODE_BYTES:
            raise GlobalFactorBoundError("logical node payload differs")
        return cls(*_NODE.unpack(payload))


@dataclass(frozen=True)
class BeamStage:
    stage: int
    pair: tuple[int, int]
    parent_count: int
    generated_count: int
    retained_count: int
    retained_min_bound: float
    discarded_max_bound: float | None
    cutoff_gap: float | None
    trace_sha256: str
    retained_keys: tuple[bytes, ...]

    def describe(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "pair": list(self.pair),
            "parent_count": self.parent_count,
            "generated_count": self.generated_count,
            "retained_count": self.retained_count,
            "retained_min_bound": self.retained_min_bound,
            "discarded_max_bound": self.discarded_max_bound,
            "cutoff_gap": self.cutoff_gap,
            "trace_sha256": self.trace_sha256,
        }


@dataclass(frozen=True)
class Full256BoundCandidate:
    key: bytes
    exact_score: float
    originating_bound: float
    publicly_verified: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.key, bytes)
            or len(self.key) != 32
            or not math.isfinite(self.exact_score)
            or not math.isfinite(self.originating_bound)
            or not isinstance(self.publicly_verified, bool)
        ):
            raise GlobalFactorBoundError("Full256 candidate differs")

    def describe(self, rank: int) -> dict[str, object]:
        return {
            "rank": rank,
            "key_sha256": hashlib.sha256(self.key).hexdigest(),
            "exact_score": self.exact_score,
            "originating_bound": self.originating_bound,
            "bound_slack": self.originating_bound - self.exact_score,
            "publicly_verified": self.publicly_verified,
        }


@dataclass(frozen=True)
class Full256BoundBeamResult:
    pairs: tuple[tuple[int, int], ...]
    stages: tuple[BeamStage, ...]
    candidates: tuple[Full256BoundCandidate, ...]
    parent_expansions: int
    child_bound_evaluations: int
    forward_evaluations: int
    public_verifications: int
    beam_width: int
    logical_mutable_state_bytes: int
    telemetry_prefix_bytes: int
    final_trace_sha256: str

    @property
    def recovered_keys(self) -> tuple[bytes, ...]:
        return tuple(
            candidate.key
            for candidate in self.candidates
            if candidate.publicly_verified
        )

    @property
    def retained_masks_by_stage(self) -> tuple[tuple[int, ...], ...]:
        return tuple(
            tuple(_key_integer(key) for key in stage.retained_keys)
            for stage in self.stages
        )

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-256-global-factor-bound-beam-result-v1",
            "pair_count": len(self.pairs),
            "beam_width": self.beam_width,
            "parent_expansions": self.parent_expansions,
            "child_bound_evaluations": self.child_bound_evaluations,
            "forward_evaluations": self.forward_evaluations,
            "public_verifications": self.public_verifications,
            "logical_node_bytes": LOGICAL_NODE_BYTES,
            "logical_mutable_state_bytes": self.logical_mutable_state_bytes,
            "telemetry_prefix_bytes": self.telemetry_prefix_bytes,
            "final_trace_sha256": self.final_trace_sha256,
            "public_recoveries": len(self.recovered_keys),
            "stages": [stage.describe() for stage in self.stages],
            "candidates": [
                candidate.describe(rank)
                for rank, candidate in enumerate(self.candidates, 1)
            ],
        }


@dataclass(frozen=True)
class CertifiedBoundLeaf:
    key: bytes
    residual_mask: int
    exact_score: float
    originating_bound: float
    publicly_verified: bool

    def describe(self, rank: int) -> dict[str, object]:
        return {
            "rank": rank,
            "residual_mask": self.residual_mask,
            "key_sha256": hashlib.sha256(self.key).hexdigest(),
            "exact_score": self.exact_score,
            "originating_bound": self.originating_bound,
            "bound_slack": self.originating_bound - self.exact_score,
            "publicly_verified": self.publicly_verified,
        }


@dataclass(frozen=True)
class CertifiedBoundQueueResult:
    residual_variables: tuple[int, ...]
    leaves: tuple[CertifiedBoundLeaf, ...]
    target_leaves: int
    unscored_pops: int
    child_bound_evaluations: int
    forward_evaluations: int
    public_verifications: int
    maximum_live_nodes: int
    limit_reason: str
    elapsed_seconds: float
    trace_sha256: str

    @property
    def completed(self) -> bool:
        return len(self.leaves) == self.target_leaves

    @property
    def recovered_keys(self) -> tuple[bytes, ...]:
        return tuple(leaf.key for leaf in self.leaves if leaf.publicly_verified)

    def describe(self) -> dict[str, object]:
        return {
            "schema": "o1-256-certified-factor-bound-queue-result-v1",
            "residual_bits": len(self.residual_variables),
            "residual_variables": list(self.residual_variables),
            "target_leaves": self.target_leaves,
            "certified_leaves": len(self.leaves),
            "completed": self.completed,
            "unscored_pops": self.unscored_pops,
            "child_bound_evaluations": self.child_bound_evaluations,
            "forward_evaluations": self.forward_evaluations,
            "public_verifications": self.public_verifications,
            "maximum_live_nodes": self.maximum_live_nodes,
            "logical_queue_state_bytes": self.maximum_live_nodes * LOGICAL_NODE_BYTES,
            "limit_reason": self.limit_reason,
            "elapsed_seconds": self.elapsed_seconds,
            "trace_sha256": self.trace_sha256,
            "public_recoveries": len(self.recovered_keys),
            "leaves": [leaf.describe(rank) for rank, leaf in enumerate(self.leaves, 1)],
        }


@dataclass(frozen=True)
class _OpenBoundNode:
    key: bytes
    depth: int
    residual_mask: int
    bound: float


@dataclass(frozen=True)
class _ExactBoundNode:
    leaf: CertifiedBoundLeaf


def run_certified_bound_queue(
    index: ConditionalFactorBoundIndex,
    residual_variables: Sequence[int],
    fixed_spins: dict[int, int],
    evaluate_exact: Callable[[bytes], float],
    verify_public: Callable[[bytes], bool],
    *,
    target_leaves: int = 5,
    maximum_unscored_pops: int = 1024,
    maximum_forward_evaluations: int = 256,
    maximum_live_nodes: int = 2048,
    timeout_seconds: float = 120.0,
) -> CertifiedBoundQueueResult:
    """Certify exact top leaves under admissible partial-key bounds."""

    residual = tuple(residual_variables)
    fixed = dict(fixed_spins)
    if (
        not isinstance(index, ConditionalFactorBoundIndex)
        or not 1 <= len(residual) <= 16
        or len(set(residual)) != len(residual)
        or any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= KEY_BITS
            for variable in residual
        )
        or set(fixed) != set(range(1, KEY_BITS + 1)).difference(residual)
        or any(spin not in (-1, 1) for spin in fixed.values())
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (
                target_leaves,
                maximum_unscored_pops,
                maximum_forward_evaluations,
                maximum_live_nodes,
            )
        )
        or not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or not callable(evaluate_exact)
        or not callable(verify_public)
    ):
        raise GlobalFactorBoundError("certified bound queue inputs differ")
    root_key = bytearray(32)
    for variable, spin in fixed.items():
        _set_key_spin(root_key, variable, spin)
    root_bytes = bytes(root_key)
    root_bound = index.bound(root_bytes, fixed)
    root = _OpenBoundNode(root_bytes, 0, 0, root_bound)
    serial = 0
    heap: list[tuple[float, int, int, int, int, object]] = [
        (-root.bound, 0, 0, 0, serial, root)
    ]
    maximum_live = 1
    unscored_pops = 0
    child_bounds = 0
    forward = 0
    public = 0
    leaves: list[CertifiedBoundLeaf] = []
    trace = bytearray()
    started = time.perf_counter()
    limit_reason = "queue-exhausted"
    assigned_fixed = frozenset(fixed)
    while heap:
        if time.perf_counter() - started > timeout_seconds:
            limit_reason = "timeout"
            break
        _, kind, _, _, _, item = heapq.heappop(heap)
        if kind == 0:
            if unscored_pops >= maximum_unscored_pops:
                limit_reason = "unscored-pop-cap"
                break
            unscored_pops += 1
            if not isinstance(item, _OpenBoundNode):
                raise GlobalFactorBoundError("open bound queue item differs")
            if item.depth < len(residual):
                if len(heap) + 2 > maximum_live_nodes:
                    limit_reason = "live-node-cap"
                    break
                variable = residual[item.depth]
                assigned = assigned_fixed.union(residual[: item.depth + 1])
                for bit in (0, 1):
                    key = bytearray(item.key)
                    _set_key_spin(key, variable, 1 if bit else -1)
                    key_bytes = bytes(key)
                    mask = item.residual_mask | (bit << item.depth)
                    bound = index.bound(key_bytes, assigned)
                    child = _OpenBoundNode(key_bytes, item.depth + 1, mask, bound)
                    serial += 1
                    heapq.heappush(
                        heap,
                        (
                            -bound,
                            0,
                            -child.depth,
                            child.residual_mask,
                            serial,
                            child,
                        ),
                    )
                    child_bounds += 1
            else:
                if forward >= maximum_forward_evaluations:
                    limit_reason = "forward-evaluation-cap"
                    break
                raw_score = evaluate_exact(item.key)
                if isinstance(raw_score, bool) or not isinstance(
                    raw_score, (int, float)
                ):
                    raise GlobalFactorBoundError("certified exact score differs")
                exact_score = float(raw_score)
                if not math.isfinite(exact_score) or exact_score > item.bound:
                    raise GlobalFactorBoundError(
                        "certified exact score exceeds originating bound"
                    )
                verified = verify_public(item.key)
                if not isinstance(verified, bool):
                    raise GlobalFactorBoundError(
                        "certified public verifier result differs"
                    )
                forward += 1
                public += 1
                leaf = CertifiedBoundLeaf(
                    item.key,
                    item.residual_mask,
                    exact_score,
                    item.bound,
                    verified,
                )
                serial += 1
                heapq.heappush(
                    heap,
                    (
                        -exact_score,
                        1,
                        0,
                        leaf.residual_mask,
                        serial,
                        _ExactBoundNode(leaf),
                    ),
                )
        else:
            if not isinstance(item, _ExactBoundNode):
                raise GlobalFactorBoundError("exact bound queue item differs")
            leaves.append(item.leaf)
            trace.extend(
                struct.pack("<Hd", item.leaf.residual_mask, item.leaf.exact_score)
            )
            if len(leaves) == target_leaves:
                limit_reason = "top-k-certified"
                break
        maximum_live = max(maximum_live, len(heap))
    elapsed = time.perf_counter() - started
    if any(
        left.exact_score < right.exact_score
        or (
            left.exact_score == right.exact_score
            and left.residual_mask > right.residual_mask
        )
        for left, right in zip(leaves, leaves[1:])
    ):
        raise GlobalFactorBoundError("certified leaf order differs")
    return CertifiedBoundQueueResult(
        residual_variables=residual,
        leaves=tuple(leaves),
        target_leaves=target_leaves,
        unscored_pops=unscored_pops,
        child_bound_evaluations=child_bounds,
        forward_evaluations=forward,
        public_verifications=public,
        maximum_live_nodes=maximum_live,
        limit_reason=limit_reason,
        elapsed_seconds=elapsed,
        trace_sha256=hashlib.sha256(trace).hexdigest(),
    )


@dataclass(frozen=True)
class _StageUpdate:
    factor: ConditionalFactor
    old_assigned: frozenset[int]
    new_assigned: frozenset[int]


@dataclass(frozen=True)
class _PairProgram:
    index: ConditionalFactorBoundIndex
    pairs: tuple[tuple[int, int], ...]
    updates: tuple[tuple[_StageUpdate, ...], ...]

    def child_nominal_bound(
        self,
        parent: LogicalBeamNode,
        child_key: bytes,
        stage: int,
    ) -> float:
        if parent.depth + 1 != stage:
            raise GlobalFactorBoundError("beam stage differs")
        deltas = []
        for update in self.updates[stage - 1]:
            old = update.factor.value(parent.key, update.old_assigned)
            new = update.factor.value(child_key, update.new_assigned)
            deltas.append(new - old)
        value = math.fsum((parent.nominal_bound, *deltas))
        if not math.isfinite(value):
            raise GlobalFactorBoundError("child factor bound is not finite")
        return value


def _compile_pair_program(
    index: ConditionalFactorBoundIndex,
    pairs: Sequence[tuple[int, int]],
) -> _PairProgram:
    normalized_rows: list[tuple[int, int]] = []
    for pair in pairs:
        if len(pair) != 2:
            raise GlobalFactorBoundError("Full256 pair partition differs")
        normalized_rows.append((pair[0], pair[1]))
    normalized = tuple(normalized_rows)
    flattened = tuple(variable for pair in normalized for variable in pair)
    if (
        len(normalized) != PAIR_COUNT
        or len(flattened) != KEY_BITS
        or len(set(flattened)) != KEY_BITS
        or set(flattened) != set(range(1, KEY_BITS + 1))
    ):
        raise GlobalFactorBoundError("Full256 pair partition differs")
    variable_stage = {
        variable: stage for stage, pair in enumerate(normalized, 1) for variable in pair
    }
    updates: list[list[_StageUpdate]] = [[] for _ in normalized]
    for factor in index.factors:
        stages = sorted({variable_stage[variable] for variable in factor.key_variables})
        old_assigned: frozenset[int] = frozenset()
        for stage in stages:
            new_assigned = frozenset(
                variable
                for variable in factor.key_variables
                if variable_stage[variable] <= stage
            )
            updates[stage - 1].append(_StageUpdate(factor, old_assigned, new_assigned))
            old_assigned = new_assigned
    return _PairProgram(index, normalized, tuple(tuple(row) for row in updates))


def _node_quality(node: LogicalBeamNode, guard: float) -> tuple[float, int, int, int]:
    # Larger tuples are better.  Larger key/parent/mask values lose ties.
    return (
        node.nominal_bound + guard,
        -node.key_integer,
        -node.parent_ordinal,
        -node.pair_mask,
    )


def _ordered_nodes(
    nodes: Iterable[LogicalBeamNode], guard: float
) -> list[LogicalBeamNode]:
    return sorted(
        nodes,
        key=lambda node: (
            -(node.nominal_bound + guard),
            node.key_integer,
            node.parent_ordinal,
            node.pair_mask,
        ),
    )


def run_full256_bound_beam(
    index: ConditionalFactorBoundIndex,
    pairs: Sequence[tuple[int, int]],
    evaluate_exact: Callable[[bytes], float],
    verify_public: Callable[[bytes], bool],
    *,
    width: int = DEFAULT_BEAM_WIDTH,
) -> Full256BoundBeamResult:
    """Run one truth-free Full256 beam and exactly score its final keys."""

    if (
        not isinstance(index, ConditionalFactorBoundIndex)
        or isinstance(width, bool)
        or not isinstance(width, int)
        or width < 1
        or not callable(evaluate_exact)
        or not callable(verify_public)
    ):
        raise GlobalFactorBoundError("Full256 beam inputs differ")
    program = _compile_pair_program(index, pairs)
    root = LogicalBeamNode(
        key=bytes(32),
        nominal_bound=index.root_nominal_bound,
        parent_ordinal=0,
        depth=0,
        pair_mask=0,
    )
    current = [root]
    stages: list[BeamStage] = []
    parent_expansions = 0
    child_evaluations = 0
    telemetry_prefix_bytes = 0
    serial = 0
    for stage, pair in enumerate(program.pairs, 1):
        parent_expansions += len(current)
        heap: list[tuple[tuple[float, int, int, int], int, LogicalBeamNode]] = []
        discarded_max: float | None = None
        for parent_ordinal, parent in enumerate(current):
            for mask in range(4):
                key = bytearray(parent.key)
                _set_key_spin(key, pair[0], 1 if mask & 1 else -1)
                _set_key_spin(key, pair[1], 1 if mask & 2 else -1)
                key_bytes = bytes(key)
                node = LogicalBeamNode(
                    key=key_bytes,
                    nominal_bound=program.child_nominal_bound(parent, key_bytes, stage),
                    parent_ordinal=parent_ordinal,
                    depth=stage,
                    pair_mask=mask,
                )
                child_evaluations += 1
                serial += 1
                quality = _node_quality(node, index.guard)
                entry = (quality, serial, node)
                if len(heap) < width:
                    heapq.heappush(heap, entry)
                elif quality > heap[0][0]:
                    displaced = heapq.heapreplace(heap, entry)[2]
                    bound = displaced.nominal_bound + index.guard
                    discarded_max = (
                        bound if discarded_max is None else max(discarded_max, bound)
                    )
                else:
                    bound = node.nominal_bound + index.guard
                    discarded_max = (
                        bound if discarded_max is None else max(discarded_max, bound)
                    )
        current = _ordered_nodes((entry[2] for entry in heap), index.guard)
        if not current or len(current) != min(
            width, 4 * stages[-1].retained_count if stages else 4
        ):
            raise GlobalFactorBoundError("retained beam width differs")
        retained_min = current[-1].nominal_bound + index.guard
        cutoff = None if discarded_max is None else retained_min - discarded_max
        trace_payload = b"".join(node.to_bytes() for node in current)
        retained_keys = tuple(node.key for node in current)
        telemetry_prefix_bytes += 32 * len(retained_keys)
        stages.append(
            BeamStage(
                stage=stage,
                pair=pair,
                parent_count=parent_expansions
                - sum(row.parent_count for row in stages),
                generated_count=4
                * (parent_expansions - sum(row.parent_count for row in stages)),
                retained_count=len(current),
                retained_min_bound=retained_min,
                discarded_max_bound=discarded_max,
                cutoff_gap=cutoff,
                trace_sha256=hashlib.sha256(trace_payload).hexdigest(),
                retained_keys=retained_keys,
            )
        )

    candidates: list[Full256BoundCandidate] = []
    for node in current:
        exact = evaluate_exact(node.key)
        if isinstance(exact, bool) or not isinstance(exact, (int, float)):
            raise GlobalFactorBoundError("exact factor score differs")
        exact_score = float(exact)
        originating = node.nominal_bound + index.guard
        if not math.isfinite(exact_score) or exact_score > originating:
            raise GlobalFactorBoundError("exact score exceeds originating bound")
        verified = verify_public(node.key)
        if not isinstance(verified, bool):
            raise GlobalFactorBoundError("public verifier result differs")
        candidates.append(
            Full256BoundCandidate(node.key, exact_score, originating, verified)
        )
    candidates.sort(key=lambda row: (-row.exact_score, _key_integer(row.key)))
    result = Full256BoundBeamResult(
        pairs=program.pairs,
        stages=tuple(stages),
        candidates=tuple(candidates),
        parent_expansions=parent_expansions,
        child_bound_evaluations=child_evaluations,
        forward_evaluations=len(candidates),
        public_verifications=len(candidates),
        beam_width=width,
        logical_mutable_state_bytes=2 * width * LOGICAL_NODE_BYTES + LOGICAL_NODE_BYTES,
        telemetry_prefix_bytes=telemetry_prefix_bytes,
        final_trace_sha256=hashlib.sha256(
            b"".join(candidate.key for candidate in candidates)
        ).hexdigest(),
    )
    if width == DEFAULT_BEAM_WIDTH and (
        result.parent_expansions != 31829
        or result.child_bound_evaluations != 127316
        or result.forward_evaluations != 256
        or result.public_verifications != 256
    ):
        raise GlobalFactorBoundError("production Full256 work ledger differs")
    return result


__all__ = [
    "COMPLETION_PAIR_COUNT",
    "CertifiedBoundLeaf",
    "CertifiedBoundQueueResult",
    "ConditionalFactorBoundIndex",
    "DEFAULT_BEAM_WIDTH",
    "Full256BoundBeamResult",
    "GlobalFactorBoundError",
    "LOGICAL_NODE_BYTES",
    "LogicalBeamNode",
    "PAIR_COUNT",
    "compile_factor_bound_index",
    "compile_pair_order",
    "run_certified_bound_queue",
    "run_full256_bound_beam",
]
