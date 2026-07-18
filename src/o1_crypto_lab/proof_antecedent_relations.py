"""Bounded signed factors from branch-exclusive proof-antecedent chains."""

from __future__ import annotations

import hashlib
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .cadical_sensor import ProbeRecord, ProofEvent
from .proof_clause_relations import (
    KEY_BITS,
    VARIABLE_LIMIT,
    ClauseRelationEdge,
)


FIELD_MAGIC = b"O1ANT-H16-V1\0\0\0\0"
HEADER = struct.Struct("<16sHHHH32s")
EDGE = struct.Struct("<HHhH")
UNIT_SCALE = 1


class ProofAntecedentRelationError(RuntimeError):
    """An original CNF, proof DAG, or bounded antecedent field differs."""


@dataclass(frozen=True)
class AntecedentRelationField:
    """Fixed-capacity signed chain-leaf occurrence field."""

    conflict_horizon: int
    minimum_abs_units: int
    capacity: int
    source_sha256: str
    edges: tuple[ClauseRelationEdge, ...]
    metrics: dict[str, int]

    def __post_init__(self) -> None:
        if (
            not 1 <= self.conflict_horizon <= 65_535
            or not 1 <= self.minimum_abs_units <= 32_767
            or not 1 <= self.capacity <= 65_535
            or len(self.edges) > self.capacity
            or len(self.source_sha256) != 64
            or tuple(sorted(self.edges)) != self.edges
            or len(
                {(edge.key_variable, edge.factor_variable) for edge in self.edges}
            )
            != len(self.edges)
        ):
            raise ProofAntecedentRelationError("bounded antecedent field differs")

    @property
    def serialized_bytes(self) -> int:
        return HEADER.size + EDGE.size * len(self.edges)

    def to_bytes(self) -> bytes:
        payload = bytearray(
            HEADER.pack(
                FIELD_MAGIC,
                self.conflict_horizon,
                UNIT_SCALE,
                self.minimum_abs_units,
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

    @classmethod
    def from_bytes(cls, payload: bytes) -> AntecedentRelationField:
        if not isinstance(payload, bytes) or len(payload) < HEADER.size:
            raise ProofAntecedentRelationError("serialized antecedent field differs")
        magic, horizon, unit_scale, minimum, edge_count, source = HEADER.unpack_from(
            payload
        )
        if (
            magic != FIELD_MAGIC
            or unit_scale != UNIT_SCALE
            or len(payload) != HEADER.size + edge_count * EDGE.size
        ):
            raise ProofAntecedentRelationError("antecedent field header differs")
        edges: list[ClauseRelationEdge] = []
        for index in range(edge_count):
            key, factor, score, reserved = EDGE.unpack_from(
                payload, HEADER.size + index * EDGE.size
            )
            if reserved:
                raise ProofAntecedentRelationError("antecedent field edge differs")
            edges.append(ClauseRelationEdge(key, factor, score))
        return cls(
            conflict_horizon=horizon,
            minimum_abs_units=minimum,
            capacity=max(1, edge_count),
            source_sha256=source.hex(),
            edges=tuple(edges),
            metrics={"edge_count": edge_count, "deserialized": 1},
        )

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
            "score_unit": "exclusive_chain_leaf_occurrence",
            "unit_scale": UNIT_SCALE,
            "minimum_abs_units": self.minimum_abs_units,
            "capacity": self.capacity,
            "edge_count": len(self.edges),
            "source_sha256": self.source_sha256,
            "serialized_bytes": self.serialized_bytes,
            "state_sha256": self.state_sha256,
            "factor_file_sha256": hashlib.sha256(
                self.factor_file_bytes()
            ).hexdigest(),
            "metrics": dict(self.metrics),
        }


def transform_antecedent_relation_field(
    field: AntecedentRelationField,
    *,
    orientation: int = 1,
    rotate: str | None = None,
) -> AntecedentRelationField:
    """Apply one frozen global orientation and optional endpoint rotation."""

    if orientation not in (-1, 1) or rotate not in (None, "key", "factor"):
        raise ProofAntecedentRelationError("antecedent field transform differs")
    key_shift = 0
    if rotate == "key":
        key_shift = next(
            (
                shift
                for shift in range(1, KEY_BITS)
                if all(
                    1 + (edge.key_variable - 1 + shift) % KEY_BITS
                    != edge.factor_variable
                    for edge in field.edges
                )
            ),
            0,
        )
        if not key_shift:
            raise ProofAntecedentRelationError("key rotation has no derangement")
    factor_shift = 0
    if rotate == "factor":
        factors = sorted({edge.factor_variable for edge in field.edges})
        if len(factors) < 2:
            raise ProofAntecedentRelationError(
                "factor control requires two variables"
            )
        factor_shift = next(
            (
                shift
                for shift in range(1, len(factors))
                if all(
                    factors[(factors.index(edge.factor_variable) + shift) % len(factors)]
                    != edge.key_variable
                    for edge in field.edges
                )
            ),
            0,
        )
        if not factor_shift:
            raise ProofAntecedentRelationError("factor rotation has no derangement")
        factor_map = {
            factor: factors[(index + factor_shift) % len(factors)]
            for index, factor in enumerate(factors)
        }
    else:
        factor_map = {}
    edges = tuple(
        sorted(
            ClauseRelationEdge(
                (
                    1 + (edge.key_variable - 1 + key_shift) % KEY_BITS
                    if rotate == "key"
                    else edge.key_variable
                ),
                (
                    factor_map[edge.factor_variable]
                    if rotate == "factor"
                    else edge.factor_variable
                ),
                orientation * edge.score_units,
            )
            for edge in field.edges
        )
    )
    transform = f"orientation={orientation};rotate={rotate or 'none'}".encode("ascii")
    metrics = dict(field.metrics)
    metrics["global_orientation"] = orientation
    metrics["coordinate_control"] = int(rotate is not None)
    metrics["coordinate_rotation"] = key_shift or factor_shift
    return AntecedentRelationField(
        conflict_horizon=field.conflict_horizon,
        minimum_abs_units=field.minimum_abs_units,
        capacity=field.capacity,
        source_sha256=hashlib.sha256(
            field.to_bytes() + b"\0antecedent-transform\0" + transform
        ).hexdigest(),
        edges=edges,
        metrics=metrics,
    )


@dataclass(frozen=True)
class OriginalClauseTable:
    variable_count: int
    clauses: tuple[tuple[int, ...], ...]
    cnf_sha256: str

    @classmethod
    def load(cls, path: str | Path) -> OriginalClauseTable:
        source = Path(path).resolve(strict=True)
        payload = source.read_bytes()
        variable_count = declared_count = -1
        clauses: list[tuple[int, ...]] = [()]
        for raw in payload.splitlines():
            line = raw.strip()
            if not line or line.startswith(b"c"):
                continue
            if line.startswith(b"p"):
                fields = line.split()
                if len(fields) != 4 or fields[:2] != [b"p", b"cnf"]:
                    raise ProofAntecedentRelationError("DIMACS header differs")
                variable_count, declared_count = map(int, fields[2:])
                continue
            values = tuple(int(item) for item in line.split())
            if (
                variable_count < 1
                or not values
                or values[-1] != 0
                or any(
                    literal == 0 or abs(literal) > variable_count
                    for literal in values[:-1]
                )
            ):
                raise ProofAntecedentRelationError("DIMACS clause differs")
            clauses.append(values[:-1])
        if declared_count != len(clauses) - 1:
            raise ProofAntecedentRelationError("DIMACS clause count differs")
        return cls(
            variable_count=variable_count,
            clauses=tuple(clauses),
            cnf_sha256=hashlib.sha256(payload).hexdigest(),
        )


@dataclass(frozen=True)
class _ChainNode:
    digest: bytes
    leaf_literals: tuple[int, ...]


def _signed_clause_bytes(clause: Sequence[int]) -> bytes:
    return b"".join(struct.pack("<i", int(literal)) for literal in clause)


def _derive_chain_node(
    event: ProofEvent,
    *,
    originals: OriginalClauseTable,
    derived: dict[int, _ChainNode],
) -> _ChainNode:
    if event.clause_id <= len(originals.clauses) - 1 or event.clause_id in derived:
        raise ProofAntecedentRelationError("derived proof ID differs")
    digest = hashlib.sha256()
    digest.update(b"O1-ANTECEDENT-CHAIN-V1\0")
    digest.update(bytes((int(event.redundant),)))
    digest.update(struct.pack("<i", event.witness))
    digest.update(struct.pack("<H", len(event.clause)))
    digest.update(_signed_clause_bytes(event.clause))
    leaves: set[int] = set()
    digest.update(struct.pack("<H", len(event.antecedents)))
    for raw_antecedent in event.antecedents:
        antecedent = abs(raw_antecedent)
        if not antecedent:
            raise ProofAntecedentRelationError("zero antecedent ID differs")
        if antecedent < len(originals.clauses):
            clause = originals.clauses[antecedent]
            parent_digest = hashlib.sha256(
                b"O1-ORIGINAL-CLAUSE-V1\0"
                + struct.pack("<Q", antecedent)
                + _signed_clause_bytes(clause)
            ).digest()
            leaves.update(clause)
        else:
            parent = derived.get(antecedent)
            if parent is None:
                raise ProofAntecedentRelationError(
                    "derived antecedent lacks an earlier node"
                )
            parent_digest = parent.digest
            leaves.update(parent.leaf_literals)
        digest.update(parent_digest)
    node = _ChainNode(
        digest.digest(), tuple(sorted(leaves, key=lambda x: (abs(x), x < 0)))
    )
    derived[event.clause_id] = node
    return node


def _branch_chain_nodes(
    record: ProbeRecord,
    *,
    originals: OriginalClauseTable,
    baseline_nodes: dict[int, _ChainNode],
) -> tuple[_ChainNode, ...]:
    if record.original_clause_count != len(originals.clauses) - 1:
        raise ProofAntecedentRelationError("probe original-clause boundary differs")
    derived = dict(baseline_nodes)
    nodes: list[_ChainNode] = []
    for event in record.events:
        if event.conclusion_phase:
            continue
        nodes.append(_derive_chain_node(event, originals=originals, derived=derived))
    return tuple(nodes)


def extract_antecedent_relation_field(
    pairs: Iterable[tuple[ProbeRecord, ProbeRecord]],
    *,
    baseline_events: Sequence[ProofEvent],
    originals: OriginalClauseTable,
    conflict_horizon: int,
    capacity: int = 8192,
) -> AntecedentRelationField:
    """Contrast full chain identity before collapsing signed original leaves."""

    if not 1 <= conflict_horizon <= 65_535 or not 1 <= capacity <= 65_535:
        raise ProofAntecedentRelationError("antecedent field plan differs")
    baseline_nodes: dict[int, _ChainNode] = {}
    for event in baseline_events:
        if event.conclusion_phase:
            continue
        _derive_chain_node(event, originals=originals, derived=baseline_nodes)
    scores: Counter[tuple[int, int]] = Counter()
    source = hashlib.sha256(
        b"O1-ANTECEDENT-RELATION-FIELD-V1\0"
        + bytes.fromhex(originals.cnf_sha256)
        + struct.pack("<HH", conflict_horizon, capacity)
    )
    pair_count = chain_count = common_count = exclusive_count = 0
    leaf_literal_count = 0
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
            raise ProofAntecedentRelationError("paired antecedent stream differs")
        source.update(bytes.fromhex(zero.deterministic_sha256))
        source.update(bytes.fromhex(one.deterministic_sha256))
        branch_nodes = [
            _branch_chain_nodes(
                record,
                originals=originals,
                baseline_nodes=baseline_nodes,
            )
            for record in (zero, one)
        ]
        counters = [Counter(node.digest for node in nodes) for nodes in branch_nodes]
        node_by_digest = {node.digest: node for nodes in branch_nodes for node in nodes}
        chain_count += sum(len(nodes) for nodes in branch_nodes)
        common_count += sum((counters[0] & counters[1]).values())
        key_variable = expected_bit + 1
        for branch_sign, difference in (
            (-1, counters[0] - counters[1]),
            (1, counters[1] - counters[0]),
        ):
            for digest, count in difference.items():
                node = node_by_digest[digest]
                exclusive_count += count
                leaf_literal_count += count * len(node.leaf_literals)
                for literal in node.leaf_literals:
                    variable = abs(literal)
                    if variable == key_variable:
                        continue
                    scores[(key_variable, variable)] += (
                        branch_sign * (1 if literal > 0 else -1) * count
                    )
        pair_count += 1
    if pair_count != KEY_BITS:
        raise ProofAntecedentRelationError("antecedent stream lacks 256 pairs")
    candidates = [
        ClauseRelationEdge(key, factor, score)
        for (key, factor), score in scores.items()
        if score and factor <= VARIABLE_LIMIT and -32_768 <= score <= 32_767
    ]
    candidates.sort(key=lambda edge: (-abs(edge.score_units), edge))
    retained = tuple(sorted(candidates[:capacity]))
    metrics = {
        "pair_count": pair_count,
        "baseline_chain_count": len(baseline_nodes),
        "branch_chain_count": chain_count,
        "common_chain_count": common_count,
        "exclusive_chain_count": exclusive_count,
        "exclusive_leaf_literal_count": leaf_literal_count,
        "uncapped_edge_count": len(candidates),
        "edge_count": len(retained),
        "capacity_truncated": int(len(candidates) > capacity),
        "active_key_coordinates": len({edge.key_variable for edge in retained}),
        "active_factor_variables": len({edge.factor_variable for edge in retained}),
    }
    if not retained:
        raise ProofAntecedentRelationError("antecedent field is empty")
    return AntecedentRelationField(
        conflict_horizon=conflict_horizon,
        minimum_abs_units=1,
        capacity=capacity,
        source_sha256=source.hexdigest(),
        edges=retained,
        metrics=metrics,
    )


__all__ = [
    "AntecedentRelationField",
    "OriginalClauseTable",
    "ProofAntecedentRelationError",
    "extract_antecedent_relation_field",
    "transform_antecedent_relation_field",
]
