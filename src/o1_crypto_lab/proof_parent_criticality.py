"""Bounded parent-role criticality factors from exclusive proof chains.

The preceding antecedent reader retained exact chain identity but collapsed every
exclusive chain into an unordered set of signed literals.  This module keeps the
ordered RUP parent role and the exact original functional clause instead.  A
candidate is scored by how critically that clause is satisfied and which literal
actually satisfies it, while public unit clauses and derived-clause satisfaction
are deliberately excluded.
"""

from __future__ import annotations

import hashlib
import struct
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np

from .cadical_sensor import ProbeRecord, ProofEvent
from .proof_antecedent_relations import OriginalClauseTable
from .proof_clause_relations import KEY_BITS, VARIABLE_LIMIT


FIELD_MAGIC = b"O1PCR-H16-V1".ljust(16, b"\0")
HEADER = struct.Struct("<16sHHHH32s")
FACTOR_PREFIX = struct.Struct("<HHQihH")
LITERAL = struct.Struct("<i")
UNIT_SCALE = 1
ROLE_LABELS = ("role0", "role1", "role2", "role3", "role4plus")
SIGNAL_LABELS = ("critical", "pivot", "polarity")
FEATURE_NAMES = tuple(
    f"{role}_{signal}" for role in ROLE_LABELS for signal in SIGNAL_LABELS
)


class ProofParentCriticalityError(RuntimeError):
    """A proof chain, bounded field, or candidate assignment differs."""


def _canonical_clause(clause: Sequence[int]) -> tuple[int, ...]:
    values = tuple(int(literal) for literal in clause)
    if (
        len(values) < 2
        or len(values) > 65_535
        or any(not literal or abs(literal) > VARIABLE_LIMIT for literal in values)
        or len({abs(literal) for literal in values}) != len(values)
    ):
        raise ProofParentCriticalityError("parent clause differs")
    return values


@dataclass(frozen=True, order=True)
class ParentCriticalityFactor:
    """One signed key-to-parent-clause factor with its exact RUP role."""

    key_variable: int
    parent_role: int
    clause_id: int
    expected_pivot: int
    score_units: int
    clause: tuple[int, ...]

    def __post_init__(self) -> None:
        clause = _canonical_clause(self.clause)
        if (
            clause != self.clause
            or not 1 <= self.key_variable <= KEY_BITS
            or not 0 <= self.parent_role <= 65_535
            or not 1 <= self.clause_id <= 0xFFFF_FFFF_FFFF_FFFF
            or self.expected_pivot not in self.clause
            or not -32_768 <= self.score_units <= 32_767
            or not self.score_units
        ):
            raise ProofParentCriticalityError("parent criticality factor differs")


@dataclass(frozen=True)
class ParentCriticalityField:
    """Fixed-capacity stream of signed original-parent criticality factors."""

    conflict_horizon: int
    minimum_abs_units: int
    capacity: int
    source_sha256: str
    factors: tuple[ParentCriticalityFactor, ...]
    metrics: Mapping[str, int]

    def __post_init__(self) -> None:
        identities = {
            (
                factor.key_variable,
                factor.parent_role,
                factor.clause_id,
                factor.expected_pivot,
                factor.clause,
            )
            for factor in self.factors
        }
        if (
            not 1 <= self.conflict_horizon <= 65_535
            or not 1 <= self.minimum_abs_units <= 32_767
            or not 1 <= self.capacity <= 65_535
            or not self.factors
            or len(self.factors) > self.capacity
            or len(self.source_sha256) != 64
            or tuple(sorted(self.factors)) != self.factors
            or len(identities) != len(self.factors)
        ):
            raise ProofParentCriticalityError("bounded parent criticality field differs")

    @property
    def serialized_bytes(self) -> int:
        return HEADER.size + sum(
            FACTOR_PREFIX.size + LITERAL.size * len(factor.clause)
            for factor in self.factors
        )

    def to_bytes(self) -> bytes:
        payload = bytearray(
            HEADER.pack(
                FIELD_MAGIC,
                self.conflict_horizon,
                UNIT_SCALE,
                self.minimum_abs_units,
                len(self.factors),
                bytes.fromhex(self.source_sha256),
            )
        )
        for factor in self.factors:
            payload.extend(
                FACTOR_PREFIX.pack(
                    factor.key_variable,
                    factor.parent_role,
                    factor.clause_id,
                    factor.expected_pivot,
                    factor.score_units,
                    len(factor.clause),
                )
            )
            for literal in factor.clause:
                payload.extend(LITERAL.pack(literal))
        return bytes(payload)

    @classmethod
    def from_bytes(cls, payload: bytes) -> ParentCriticalityField:
        if not isinstance(payload, bytes) or len(payload) < HEADER.size:
            raise ProofParentCriticalityError("serialized criticality field differs")
        magic, horizon, scale, minimum, count, source = HEADER.unpack_from(payload)
        if magic != FIELD_MAGIC or scale != UNIT_SCALE or not count:
            raise ProofParentCriticalityError("criticality field header differs")
        offset = HEADER.size
        factors: list[ParentCriticalityFactor] = []
        for _ in range(count):
            if offset + FACTOR_PREFIX.size > len(payload):
                raise ProofParentCriticalityError("criticality factor prefix differs")
            key, role, clause_id, pivot, score, length = FACTOR_PREFIX.unpack_from(
                payload, offset
            )
            offset += FACTOR_PREFIX.size
            if length < 2 or offset + LITERAL.size * length > len(payload):
                raise ProofParentCriticalityError("criticality clause length differs")
            clause = tuple(
                LITERAL.unpack_from(payload, offset + LITERAL.size * index)[0]
                for index in range(length)
            )
            offset += LITERAL.size * length
            factors.append(
                ParentCriticalityFactor(key, role, clause_id, pivot, score, clause)
            )
        if offset != len(payload):
            raise ProofParentCriticalityError("criticality field trailing bytes differ")
        return cls(
            conflict_horizon=horizon,
            minimum_abs_units=minimum,
            capacity=max(1, count),
            source_sha256=source.hex(),
            factors=tuple(factors),
            metrics={"factor_count": count, "deserialized": 1},
        )

    @property
    def state_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def factor_file_bytes(self) -> bytes:
        rows = []
        for factor in self.factors:
            clause = ",".join(str(literal) for literal in factor.clause)
            rows.append(
                f"{factor.key_variable} {factor.parent_role} {factor.clause_id} "
                f"{factor.expected_pivot} {factor.score_units} {clause}\n"
            )
        return "".join(rows).encode("ascii")

    def describe(self) -> dict[str, object]:
        return {
            "conflict_horizon": self.conflict_horizon,
            "score_unit": "exclusive_chain_direct_original_parent_occurrence",
            "unit_scale": UNIT_SCALE,
            "minimum_abs_units": self.minimum_abs_units,
            "capacity": self.capacity,
            "factor_count": len(self.factors),
            "feature_names": list(FEATURE_NAMES),
            "source_sha256": self.source_sha256,
            "serialized_bytes": self.serialized_bytes,
            "state_sha256": self.state_sha256,
            "factor_file_sha256": hashlib.sha256(
                self.factor_file_bytes()
            ).hexdigest(),
            "metrics": dict(self.metrics),
        }


@dataclass(frozen=True)
class _ParentStep:
    role: int
    clause_id: int
    clause: tuple[int, ...]
    expected_pivot: int


@dataclass(frozen=True)
class _CriticalityNode:
    digest: bytes
    clause: tuple[int, ...]
    direct_original_steps: tuple[_ParentStep, ...]
    excluded_unit_parents: int
    excluded_derived_parents: int
    excluded_conflict_parents: int


def _signed_clause_bytes(clause: Sequence[int]) -> bytes:
    return b"".join(struct.pack("<i", int(literal)) for literal in clause)


def _rup_pivots(
    terminal_clause: Sequence[int], parent_clauses: Sequence[Sequence[int]]
) -> tuple[int, ...]:
    """Replay one exact ordered RUP chain and return each propagated literal."""

    assignment: dict[int, int] = {}
    for literal in terminal_clause:
        variable = abs(literal)
        value = -1 if literal > 0 else 1
        previous = assignment.get(variable)
        if previous is not None and previous != value:
            raise ProofParentCriticalityError("terminal RUP assumptions conflict")
        assignment[variable] = value
    pivots: list[int] = []
    for role, raw_clause in enumerate(parent_clauses):
        clause = tuple(int(literal) for literal in raw_clause)
        statuses: list[bool | None] = []
        for literal in clause:
            spin = assignment.get(abs(literal))
            statuses.append(
                None if spin is None else spin == (1 if literal > 0 else -1)
            )
        if any(status is True for status in statuses):
            raise ProofParentCriticalityError("RUP parent is already satisfied")
        unresolved = [
            index for index, status in enumerate(statuses) if status is None
        ]
        if len(unresolved) == 1:
            pivot = clause[unresolved[0]]
            assignment[abs(pivot)] = 1 if pivot > 0 else -1
            pivots.append(pivot)
        elif not unresolved:
            if role != len(parent_clauses) - 1:
                raise ProofParentCriticalityError("RUP chain conflicts before its end")
            pivots.append(0)
        else:
            raise ProofParentCriticalityError("RUP parent has multiple unresolved literals")
    if not pivots or pivots[-1] != 0:
        raise ProofParentCriticalityError("RUP chain lacks terminal conflict")
    return tuple(pivots)


def _derive_criticality_node(
    event: ProofEvent,
    *,
    originals: OriginalClauseTable,
    derived: dict[int, _CriticalityNode],
) -> _CriticalityNode:
    if event.clause_id <= len(originals.clauses) - 1 or event.clause_id in derived:
        raise ProofParentCriticalityError("derived proof ID differs")
    digest = hashlib.sha256()
    digest.update(b"O1-ANTECEDENT-CHAIN-V1\0")
    digest.update(bytes((int(event.redundant),)))
    digest.update(struct.pack("<i", event.witness))
    digest.update(struct.pack("<H", len(event.clause)))
    digest.update(_signed_clause_bytes(event.clause))
    digest.update(struct.pack("<H", len(event.antecedents)))
    parents: list[tuple[int, tuple[int, ...], bytes, bool]] = []
    for raw_antecedent in event.antecedents:
        antecedent = abs(raw_antecedent)
        if not antecedent:
            raise ProofParentCriticalityError("zero antecedent ID differs")
        if antecedent < len(originals.clauses):
            clause = originals.clauses[antecedent]
            parent_digest = hashlib.sha256(
                b"O1-ORIGINAL-CLAUSE-V1\0"
                + struct.pack("<Q", antecedent)
                + _signed_clause_bytes(clause)
            ).digest()
            original = True
        else:
            parent = derived.get(antecedent)
            if parent is None:
                raise ProofParentCriticalityError(
                    "derived antecedent lacks an earlier node"
                )
            clause = parent.clause
            parent_digest = parent.digest
            original = False
        digest.update(parent_digest)
        parents.append((antecedent, clause, parent_digest, original))
    pivots = _rup_pivots(event.clause, [parent[1] for parent in parents])
    steps = tuple(
        _ParentStep(role, clause_id, tuple(clause), pivot)
        for role, ((clause_id, clause, _, original), pivot) in enumerate(
            zip(parents, pivots, strict=True)
        )
        if original and len(clause) > 1 and pivot
    )
    node = _CriticalityNode(
        digest.digest(),
        tuple(event.clause),
        steps,
        sum(
            int(bool(pivot) and len(clause) == 1)
            for (_, clause, _, _), pivot in zip(parents, pivots, strict=True)
        ),
        sum(
            int(bool(pivot) and len(clause) > 1 and not original)
            for (_, clause, _, original), pivot in zip(parents, pivots, strict=True)
        ),
        sum(int(not pivot) for pivot in pivots),
    )
    derived[event.clause_id] = node
    return node


def _branch_nodes(
    record: ProbeRecord,
    *,
    originals: OriginalClauseTable,
    baseline_nodes: dict[int, _CriticalityNode],
) -> tuple[_CriticalityNode, ...]:
    if record.original_clause_count != len(originals.clauses) - 1:
        raise ProofParentCriticalityError("probe original-clause boundary differs")
    derived = dict(baseline_nodes)
    nodes: list[_CriticalityNode] = []
    for event in record.events:
        if event.conclusion_phase:
            continue
        nodes.append(
            _derive_criticality_node(event, originals=originals, derived=derived)
        )
    return tuple(nodes)


def extract_parent_criticality_field(
    pairs: Iterable[tuple[ProbeRecord, ProbeRecord]],
    *,
    baseline_events: Sequence[ProofEvent],
    originals: OriginalClauseTable,
    conflict_horizon: int,
    capacity: int = 8192,
) -> ParentCriticalityField:
    """Contrast exact chains, then retain ordered direct original parents."""

    if not 1 <= conflict_horizon <= 65_535 or not 1 <= capacity <= 65_535:
        raise ProofParentCriticalityError("parent criticality field plan differs")
    baseline_nodes: dict[int, _CriticalityNode] = {}
    for event in baseline_events:
        if not event.conclusion_phase:
            _derive_criticality_node(
                event, originals=originals, derived=baseline_nodes
            )
    scores: Counter[tuple[int, int, int, int, tuple[int, ...]]] = Counter()
    source = hashlib.sha256(
        b"O1-PARENT-CRITICALITY-FIELD-V1\0"
        + bytes.fromhex(originals.cnf_sha256)
        + struct.pack("<HH", conflict_horizon, capacity)
    )
    pair_count = branch_count = common_count = exclusive_count = 0
    parent_observations = excluded_units = excluded_derived = excluded_conflicts = 0
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
            raise ProofParentCriticalityError("paired criticality stream differs")
        source.update(bytes.fromhex(zero.deterministic_sha256))
        source.update(bytes.fromhex(one.deterministic_sha256))
        branch_nodes = [
            _branch_nodes(
                record, originals=originals, baseline_nodes=baseline_nodes
            )
            for record in (zero, one)
        ]
        counters = [Counter(node.digest for node in nodes) for nodes in branch_nodes]
        node_by_digest = {
            node.digest: node for nodes in branch_nodes for node in nodes
        }
        branch_count += sum(len(nodes) for nodes in branch_nodes)
        common_count += sum((counters[0] & counters[1]).values())
        key_variable = expected_bit + 1
        for branch_sign, difference in (
            (-1, counters[0] - counters[1]),
            (1, counters[1] - counters[0]),
        ):
            for digest, count in difference.items():
                node = node_by_digest[digest]
                exclusive_count += count
                for step in node.direct_original_steps:
                    scores[
                        (
                            key_variable,
                            step.role,
                            step.clause_id,
                            step.expected_pivot,
                            step.clause,
                        )
                    ] += branch_sign * count
                    parent_observations += count
                # Public units, derived parents and the terminal conflict never
                # enter the original-functional-clause factor field.
                excluded_conflicts += count * node.excluded_conflict_parents
                excluded_units += count * node.excluded_unit_parents
                excluded_derived += count * node.excluded_derived_parents
        pair_count += 1
    if pair_count != KEY_BITS:
        raise ProofParentCriticalityError("criticality stream lacks 256 pairs")
    candidates = [
        ParentCriticalityFactor(key, role, clause_id, pivot, score, clause)
        for (key, role, clause_id, pivot, clause), score in scores.items()
        if score and -32_768 <= score <= 32_767
    ]
    candidates.sort(key=lambda factor: (-abs(factor.score_units), factor))
    retained = tuple(sorted(candidates[:capacity]))
    if not retained:
        raise ProofParentCriticalityError("parent criticality field is empty")
    metrics = {
        "pair_count": pair_count,
        "baseline_chain_count": len(baseline_nodes),
        "branch_chain_count": branch_count,
        "common_chain_count": common_count,
        "exclusive_chain_count": exclusive_count,
        "direct_original_parent_observations": parent_observations,
        "excluded_terminal_conflicts": excluded_conflicts,
        "excluded_unit_parents": excluded_units,
        "excluded_derived_parents": excluded_derived,
        "uncapped_factor_count": len(candidates),
        "factor_count": len(retained),
        "capacity_truncated": int(len(candidates) > capacity),
        "active_key_coordinates": len(
            {factor.key_variable for factor in retained}
        ),
        "active_original_clauses": len({factor.clause_id for factor in retained}),
        "active_clause_variables": len(
            {
                abs(literal)
                for factor in retained
                for literal in factor.clause
            }
        ),
    }
    return ParentCriticalityField(
        conflict_horizon=conflict_horizon,
        minimum_abs_units=1,
        capacity=capacity,
        source_sha256=source.hexdigest(),
        factors=retained,
        metrics=metrics,
    )


def transform_parent_criticality_field(
    field: ParentCriticalityField,
    *,
    orientation: int = 1,
    rotate: str | None = None,
) -> ParentCriticalityField:
    """Apply a global orientation or deterministic key/clause endpoint control."""

    if orientation not in (-1, 1) or rotate not in (None, "key", "clause"):
        raise ProofParentCriticalityError("criticality field transform differs")
    variable_map: dict[int, int] = {}
    if rotate == "clause":
        variables = sorted(
            {
                abs(literal)
                for factor in field.factors
                for literal in factor.clause
            }
        )
        if len(variables) < 2:
            raise ProofParentCriticalityError("clause control needs two variables")
        variable_map = {
            variable: variables[(index + 1) % len(variables)]
            for index, variable in enumerate(variables)
        }

    def map_literal(literal: int) -> int:
        variable = variable_map.get(abs(literal), abs(literal))
        return variable if literal > 0 else -variable

    factors = tuple(
        sorted(
            ParentCriticalityFactor(
                (
                    1 + factor.key_variable % KEY_BITS
                    if rotate == "key"
                    else factor.key_variable
                ),
                factor.parent_role,
                factor.clause_id,
                map_literal(factor.expected_pivot),
                orientation * factor.score_units,
                tuple(map_literal(literal) for literal in factor.clause),
            )
            for factor in field.factors
        )
    )
    transform = f"orientation={orientation};rotate={rotate or 'none'}".encode("ascii")
    metrics = dict(field.metrics)
    metrics["global_orientation"] = orientation
    metrics["coordinate_control"] = int(rotate is not None)
    metrics["coordinate_rotation"] = 1 if rotate is not None else 0
    return ParentCriticalityField(
        conflict_horizon=field.conflict_horizon,
        minimum_abs_units=field.minimum_abs_units,
        capacity=field.capacity,
        source_sha256=hashlib.sha256(
            field.to_bytes() + b"\0parent-criticality-transform\0" + transform
        ).hexdigest(),
        factors=factors,
        metrics=metrics,
    )


def parent_criticality_features(
    field: ParentCriticalityField, assignment: Mapping[int, int]
) -> np.ndarray:
    """Return the fixed 15-channel ordered criticality feature vector."""

    values = np.zeros((len(ROLE_LABELS), len(SIGNAL_LABELS)), dtype=np.float64)
    normalizers = np.zeros(len(ROLE_LABELS), dtype=np.float64)
    for factor in field.factors:
        key_spin = assignment.get(factor.key_variable)
        if key_spin not in (-1, 1):
            raise ProofParentCriticalityError("assignment lacks factor key")
        true_literals: list[int] = []
        for literal in factor.clause:
            spin = assignment.get(abs(literal))
            if spin not in (-1, 1):
                raise ProofParentCriticalityError("assignment lacks clause variable")
            if spin == (1 if literal > 0 else -1):
                true_literals.append(literal)
        role = min(factor.parent_role, len(ROLE_LABELS) - 1)
        signed = float(factor.score_units * key_spin)
        normalizers[role] += abs(factor.score_units)
        critical = len(true_literals) == 1
        values[role, 0] += signed * (1.0 if critical else -1.0)
        if critical:
            unique = true_literals[0]
            values[role, 1] += signed * (
                1.0 if unique == factor.expected_pivot else -1.0
            )
            values[role, 2] += signed * (1.0 if unique > 0 else -1.0)
    for role, normalizer in enumerate(normalizers):
        if normalizer:
            values[role] /= normalizer
    return values.reshape(-1)


def requested_parent_criticality_variables(
    fields: Iterable[ParentCriticalityField],
) -> tuple[int, ...]:
    variables: set[int] = set()
    for field in fields:
        for factor in field.factors:
            variables.add(factor.key_variable)
            variables.update(abs(literal) for literal in factor.clause)
    if not variables:
        raise ProofParentCriticalityError("criticality fields request no variables")
    return tuple(sorted(variables))


__all__ = [
    "FEATURE_NAMES",
    "ParentCriticalityFactor",
    "ParentCriticalityField",
    "ProofParentCriticalityError",
    "extract_parent_criticality_field",
    "parent_criticality_features",
    "requested_parent_criticality_variables",
    "transform_parent_criticality_field",
]
