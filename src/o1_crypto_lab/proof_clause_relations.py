"""Bounded signed relation field from paired target-specific proof clauses.

The extractor never sees a target key.  For each key-coordinate assumption pair
it subtracts the two derived-clause multisets and binds surviving literal phase
to the assumed key coordinate.  Clause weights use exact sixth-units, avoiding
floating-point selection drift for lengths one through three.
"""

from __future__ import annotations

import hashlib
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .cadical_sensor import ProbeRecord


KEY_BITS = 256
VARIABLE_LIMIT = 32_128
UNIT_SCALE = 6
FIELD_MAGIC = b"O1REL-H16-V1\0\0\0\0"
HEADER = struct.Struct("<16sHHHH32s")
EDGE = struct.Struct("<HHhH")


class ProofClauseRelationError(RuntimeError):
    """A probe pair, bounded field, or truth assignment differs."""


def _canonical_clause(clause: Sequence[int]) -> tuple[int, ...]:
    values = tuple(
        sorted((int(item) for item in clause), key=lambda x: (abs(x), x < 0))
    )
    if (
        not values
        or len(values) > 3
        or any(item == 0 or abs(item) > VARIABLE_LIMIT for item in values)
        or len({abs(item) for item in values}) != len(values)
    ):
        raise ProofClauseRelationError("selected proof clause differs")
    return values


def clause_contrast_units(
    *,
    key_variable: int,
    zero_clauses: Sequence[Sequence[int]],
    one_clauses: Sequence[Sequence[int]],
) -> dict[int, int]:
    """Return exact signed key↔literal scores in sixth-units."""

    if not 1 <= key_variable <= KEY_BITS:
        raise ProofClauseRelationError("key variable differs")
    counters = []
    for clauses in (zero_clauses, one_clauses):
        counters.append(Counter(_canonical_clause(clause) for clause in clauses))
    scores: defaultdict[int, int] = defaultdict(int)
    for branch_sign, difference in (
        (-1, counters[0] - counters[1]),
        (1, counters[1] - counters[0]),
    ):
        for clause, count in difference.items():
            literal_weight = UNIT_SCALE // len(clause)
            for literal in clause:
                scores[abs(literal)] += (
                    branch_sign * (1 if literal > 0 else -1) * count * literal_weight
                )
    scores.pop(key_variable, None)
    return {variable: score for variable, score in scores.items() if score}


@dataclass(frozen=True, order=True)
class ClauseRelationEdge:
    key_variable: int
    factor_variable: int
    score_units: int

    def __post_init__(self) -> None:
        if (
            not 1 <= self.key_variable <= KEY_BITS
            or not 1 <= self.factor_variable <= VARIABLE_LIMIT
            or self.factor_variable == self.key_variable
            or not -32_768 <= self.score_units <= 32_767
            or self.score_units == 0
        ):
            raise ProofClauseRelationError("relation edge differs")


@dataclass(frozen=True)
class ClauseRelationField:
    conflict_horizon: int
    selected_abs_units: int
    capacity: int
    source_sha256: str
    edges: tuple[ClauseRelationEdge, ...]
    metrics: Mapping[str, int]

    def __post_init__(self) -> None:
        if (
            not 1 <= self.conflict_horizon <= 65_535
            or not 1 <= self.selected_abs_units <= 32_767
            or not 1 <= self.capacity <= 65_535
            or len(self.edges) > self.capacity
            or len(self.source_sha256) != 64
            or tuple(sorted(self.edges)) != self.edges
            or len({(edge.key_variable, edge.factor_variable) for edge in self.edges})
            != len(self.edges)
        ):
            raise ProofClauseRelationError("bounded relation field differs")

    @property
    def serialized_bytes(self) -> int:
        return HEADER.size + EDGE.size * len(self.edges)

    def to_bytes(self) -> bytes:
        payload = bytearray(
            HEADER.pack(
                FIELD_MAGIC,
                self.conflict_horizon,
                UNIT_SCALE,
                self.selected_abs_units,
                len(self.edges),
                bytes.fromhex(self.source_sha256),
            )
        )
        for edge in self.edges:
            payload.extend(
                EDGE.pack(
                    edge.key_variable,
                    edge.factor_variable,
                    edge.score_units,
                    0,
                )
            )
        return bytes(payload)

    @property
    def state_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def factor_file_bytes(self) -> bytes:
        return "".join(
            f"{edge.key_variable} {edge.factor_variable} {edge.score_units}\n"
            for edge in self.edges
        ).encode("ascii")

    def describe(self) -> dict[str, object]:
        return {
            "conflict_horizon": self.conflict_horizon,
            "unit_scale": UNIT_SCALE,
            "selected_abs_units": self.selected_abs_units,
            "capacity": self.capacity,
            "edge_count": len(self.edges),
            "source_sha256": self.source_sha256,
            "serialized_bytes": self.serialized_bytes,
            "state_sha256": self.state_sha256,
            "factor_file_sha256": hashlib.sha256(self.factor_file_bytes()).hexdigest(),
            "metrics": dict(self.metrics),
        }


def extract_clause_relation_field(
    pairs: Iterable[tuple[ProbeRecord, ProbeRecord]],
    *,
    conflict_horizon: int,
    selected_abs_units: int = 3,
    capacity: int = 4096,
) -> ClauseRelationField:
    """Stream probe pairs into one fixed-capacity relation edge vault."""

    if (
        not 1 <= conflict_horizon <= 65_535
        or not 1 <= selected_abs_units <= 32_767
        or not 1 <= capacity <= 65_535
    ):
        raise ProofClauseRelationError("relation field plan differs")
    digest = hashlib.sha256(
        json.dumps(
            {
                "schema": "o1-proof-clause-relation-stream-v1",
                "conflict_horizon": conflict_horizon,
                "unit_scale": UNIT_SCALE,
                "selected_abs_units": selected_abs_units,
                "capacity": capacity,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    retained: list[ClauseRelationEdge] = []
    pair_count = event_count = selected_event_count = 0
    common_clause_count = symmetric_clause_count = ignored_clause_count = 0
    for expected_bit, (zero, one) in enumerate(pairs):
        if (
            zero.bit_index != expected_bit
            or one.bit_index != expected_bit
            or zero.assumed_value != 0
            or one.assumed_value != 1
            or zero.requested_conflict_horizon != conflict_horizon
            or one.requested_conflict_horizon != conflict_horizon
            or zero.status != 0
            or one.status != 0
        ):
            raise ProofClauseRelationError("paired probe stream differs")
        digest.update(bytes.fromhex(zero.deterministic_sha256))
        digest.update(bytes.fromhex(one.deterministic_sha256))
        branch_clauses: list[list[tuple[int, ...]]] = []
        branch_counters: list[Counter[tuple[int, ...]]] = []
        for record in (zero, one):
            clauses: list[tuple[int, ...]] = []
            for event in record.events:
                event_count += 1
                if event.conclusion_phase or not 1 <= len(event.clause) <= 3:
                    ignored_clause_count += 1
                    continue
                clauses.append(_canonical_clause(event.clause))
                selected_event_count += 1
            branch_clauses.append(clauses)
            branch_counters.append(Counter(clauses))
        common_clause_count += sum((branch_counters[0] & branch_counters[1]).values())
        symmetric_clause_count += sum(
            (branch_counters[0] - branch_counters[1]).values()
        ) + sum((branch_counters[1] - branch_counters[0]).values())
        scores = clause_contrast_units(
            key_variable=expected_bit + 1,
            zero_clauses=branch_clauses[0],
            one_clauses=branch_clauses[1],
        )
        retained.extend(
            ClauseRelationEdge(expected_bit + 1, variable, score)
            for variable, score in scores.items()
            if abs(score) == selected_abs_units
        )
        pair_count += 1
    if pair_count != KEY_BITS:
        raise ProofClauseRelationError("relation stream lacks all 256 pairs")
    edges = tuple(sorted(retained))
    if len(edges) > capacity:
        raise ProofClauseRelationError("relation field exceeds fixed capacity")
    metrics = {
        "pair_count": pair_count,
        "event_count": event_count,
        "selected_event_count": selected_event_count,
        "ignored_event_count": ignored_clause_count,
        "common_clause_count": common_clause_count,
        "symmetric_clause_count": symmetric_clause_count,
        "edge_count": len(edges),
        "active_key_coordinates": len({edge.key_variable for edge in edges}),
        "active_factor_variables": len({edge.factor_variable for edge in edges}),
    }
    return ClauseRelationField(
        conflict_horizon=conflict_horizon,
        selected_abs_units=selected_abs_units,
        capacity=capacity,
        source_sha256=digest.hexdigest(),
        edges=edges,
        metrics=metrics,
    )


def score_relation_field(
    field: ClauseRelationField,
    assignment: Mapping[int, int],
) -> dict[str, object]:
    """Post-freeze truth diagnostic with two coordinate-destroying controls."""

    if not field.edges:
        raise ProofClauseRelationError("cannot score an empty relation field")
    required = {
        item
        for edge in field.edges
        for item in (edge.key_variable, edge.factor_variable)
    }
    if any(assignment.get(variable) not in (-1, 1) for variable in required):
        raise ProofClauseRelationError("truth assignment lacks relation variables")
    factor_variables = sorted({edge.factor_variable for edge in field.edges})
    factor_rotation = {
        variable: factor_variables[(index + 1) % len(factor_variables)]
        for index, variable in enumerate(factor_variables)
    }

    def correct(key_variable: int, factor_variable: int, score: int) -> bool:
        predicted_same = score > 0
        actual_same = assignment[key_variable] == assignment[factor_variable]
        return predicted_same == actual_same

    primary = sum(
        correct(edge.key_variable, edge.factor_variable, edge.score_units)
        for edge in field.edges
    )
    key_rotated = sum(
        correct(
            1 + edge.key_variable % KEY_BITS,
            edge.factor_variable,
            edge.score_units,
        )
        for edge in field.edges
    )
    factor_rotated = sum(
        correct(
            edge.key_variable,
            factor_rotation[edge.factor_variable],
            edge.score_units,
        )
        for edge in field.edges
    )
    count = len(field.edges)
    return {
        "edge_count": count,
        "primary_correct": primary,
        "primary_accuracy": primary / count,
        "key_rotated_correct": key_rotated,
        "key_rotated_accuracy": key_rotated / count,
        "factor_rotated_correct": factor_rotated,
        "factor_rotated_accuracy": factor_rotated / count,
    }


def coordinate_control_field(
    field: ClauseRelationField,
    *,
    rotate: str,
) -> ClauseRelationField:
    """Destroy one endpoint identity while preserving edge count and weights."""

    if rotate == "key":
        edges = tuple(
            sorted(
                ClauseRelationEdge(
                    1 + edge.key_variable % KEY_BITS,
                    edge.factor_variable,
                    edge.score_units,
                )
                for edge in field.edges
            )
        )
    elif rotate == "factor":
        variables = sorted({edge.factor_variable for edge in field.edges})
        if len(variables) < 2:
            raise ProofClauseRelationError("factor control requires two variables")
        mapping = {
            variable: variables[(index + 1) % len(variables)]
            for index, variable in enumerate(variables)
        }
        edges = tuple(
            sorted(
                ClauseRelationEdge(
                    edge.key_variable,
                    mapping[edge.factor_variable],
                    edge.score_units,
                )
                for edge in field.edges
            )
        )
    else:
        raise ProofClauseRelationError("unknown coordinate control")
    source_sha = hashlib.sha256(
        field.to_bytes() + b"\0coordinate-control\0" + rotate.encode("ascii")
    ).hexdigest()
    metrics = dict(field.metrics)
    metrics["coordinate_control"] = 1
    return ClauseRelationField(
        conflict_horizon=field.conflict_horizon,
        selected_abs_units=field.selected_abs_units,
        capacity=field.capacity,
        source_sha256=source_sha,
        edges=edges,
        metrics=metrics,
    )


def highest_degree_key_residual(
    field: ClauseRelationField,
    *,
    residual_bits: int,
) -> tuple[int, ...]:
    """Choose a target-label-free residual by relation degree then coordinate."""

    if not 1 <= residual_bits < KEY_BITS:
        raise ProofClauseRelationError("residual width differs")
    degree = Counter(edge.key_variable for edge in field.edges)
    if len(degree) < residual_bits:
        raise ProofClauseRelationError("relation field covers too few key coordinates")
    return tuple(
        variable
        for variable, _ in sorted(degree.items(), key=lambda item: (-item[1], item[0]))[
            :residual_bits
        ]
    )


__all__ = [
    "ClauseRelationEdge",
    "ClauseRelationField",
    "ProofClauseRelationError",
    "clause_contrast_units",
    "coordinate_control_field",
    "extract_clause_relation_field",
    "highest_degree_key_residual",
    "score_relation_field",
]
