"""Canonical residual-polarity staging plans for O1C-0077.

The plan does not replace or reorder the immutable public rank table.  It
binds that table, one already-certified active vault, the preceding public
terminal assignment, and a parent causal-frontier plan.  Exactly two rank
rows may then receive an in-memory sign overlay while every other rank field
and the row order remain unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence, cast

from .threshold_no_good_vault_v1 import ThresholdNoGoodVault
from .vault_ranked_decision_v1 import (
    VaultRankedDecision,
    VaultRankedDecisionError,
    validate_vault_ranked_decision,
)


RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA = "o1-residual-polarity-staging-plan-v1"
RESIDUAL_POLARITY_STAGING_PLAN_MAGIC = b"O1-RESIDUAL-POLARITY-STAGING-V1\0"
RESIDUAL_POLARITY_STAGING_PLAN_VERSION = 1
RESIDUAL_POLARITY_STAGING_ASSIGNMENT_ENCODING = "observed-ascending-i8-sign"
RESIDUAL_POLARITY_STAGING_SOURCE_STATE_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-grouped-state-v2"
)

RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES = 16_777_216
RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS = 1_600_000
RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS = 512
RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS = 5
RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS = 2

O1C77_SOURCE_RESULT_SHA256 = (
    "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198"
)
O1C77_SOURCE_ASSIGNMENT_SHA256 = (
    "c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2"
)
O1C77_ACTIVE_VAULT_SHA256 = (
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33"
)
O1C77_PARENT_FRONTIER_PLAN_SHA256 = (
    "83dbfbddd51bdbacb95a892cf3bc7e3c3953bc3e62b674d1f8388de7de53db30"
)
O1C77_SELECTED_ACTIVE_INDEX = 232
O1C77_SELECTED_UNION_INDEX = 526
O1C77_SELECTED_CLAUSE_SHA256 = (
    "c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322"
)
O1C77_SELECTED_CLAUSE_LITERAL_COUNT = 2438
O1C77_SOURCE_RANK_PAYLOAD_SHA256 = (
    "d3a007ebee7c515289d33be30757f769b2c1fde618fb5c6c312ea9f3509380ae"
)
O1C77_SOURCE_RANK_ORDER_SHA256 = (
    "26c0063f4eed586ef67535cccabacc07d945587a603cbb56dbb3b2225a32a2f5"
)
O1C77_EFFECTIVE_RANK_ORDER_SHA256 = (
    "6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086"
)
O1C77_INTERSECTIONS = (
    (28, 105, -105, -105),
    (131, -106, 106, 106),
    (224, 131, 131, -131),
    (226, -130, -130, 130),
    (235, -129, 129, 129),
)
O1C77_OVERLAYS = ((224, 131, -131), (226, -130, 130))

_UINT32_MAX = (1 << 32) - 1
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_CHECKSUM_BYTES = 32


class ResidualPolarityStagingError(ValueError):
    """A staging source, rank, vault, plan, or binary contract differs."""


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256(value: object, field_name: str) -> str:
    if not _is_sha256(value):
        raise ResidualPolarityStagingError(f"staging {field_name} differs")
    return cast(str, value)


def _u32(value: object, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _UINT32_MAX
    ):
        raise ResidualPolarityStagingError(f"staging {field_name} differs")
    return value


def _literal(value: object, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value in (0, _INT32_MIN)
        or not _INT32_MIN < value <= _INT32_MAX
    ):
        raise ResidualPolarityStagingError(f"staging {field_name} differs")
    return value


def _assignment_bytes(signs: tuple[int, ...]) -> bytes:
    if (
        not isinstance(signs, tuple)
        or len(signs) > RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS
        or any(
            isinstance(sign, bool)
            or not isinstance(sign, int)
            or sign not in (-1, 0, 1)
            for sign in signs
        )
    ):
        raise ResidualPolarityStagingError("staging source assignment differs")
    return bytes(255 if sign == -1 else sign for sign in signs)


def _order_bytes(literals: tuple[int, ...]) -> bytes:
    if (
        not isinstance(literals, tuple)
        or not 1 <= len(literals) <= RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS
    ):
        raise ResidualPolarityStagingError("staging rank population differs")
    seen: set[int] = set()
    payload = bytearray()
    for value in literals:
        literal = _literal(value, "rank literal")
        if abs(literal) in seen:
            raise ResidualPolarityStagingError("staging rank variable repeats")
        seen.add(abs(literal))
        payload.extend(struct.pack("<i", literal))
    return bytes(payload)


@dataclass(frozen=True, slots=True)
class ResidualPolarityIntersection:
    """One selected-clause variable intersecting the immutable rank."""

    rank_index: int
    clause_literal: int
    source_literal: int
    effective_literal: int

    def __post_init__(self) -> None:
        index = _u32(self.rank_index, "intersection rank index")
        clause = _literal(self.clause_literal, "intersection clause literal")
        source = _literal(self.source_literal, "intersection source literal")
        effective = _literal(self.effective_literal, "intersection effective literal")
        if abs(clause) != abs(source) or abs(source) != abs(effective):
            raise ResidualPolarityStagingError("staging intersection variable differs")
        if index >= RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS:
            raise ResidualPolarityStagingError(
                "staging intersection rank index differs"
            )


@dataclass(frozen=True, slots=True)
class ResidualPolarityOverlay:
    """One source-to-effective sign mutation, with rank order preserved."""

    rank_index: int
    source_literal: int
    effective_literal: int

    def __post_init__(self) -> None:
        index = _u32(self.rank_index, "overlay rank index")
        source = _literal(self.source_literal, "overlay source literal")
        effective = _literal(self.effective_literal, "overlay effective literal")
        if index >= RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS or source != -effective:
            raise ResidualPolarityStagingError("staging overlay polarity differs")


@dataclass(frozen=True)
class ResidualPolarityStagingPlan:
    """A canonical two-row polarity overlay and all of its public bindings."""

    source_result_sha256: str
    source_assignment_sha256: str
    active_vault_sha256: str
    parent_frontier_plan_sha256: str
    selected_active_index: int
    selected_union_index: int
    selected_clause_sha256: str
    selected_clause_literal_count: int
    source_rank_payload_sha256: str
    source_rank_order_sha256: str
    effective_rank_order_sha256: str
    source_assignment: tuple[int, ...] = field(repr=False)
    source_rank_literals: tuple[int, ...]
    intersections: tuple[ResidualPolarityIntersection, ...]
    overlays: tuple[ResidualPolarityOverlay, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("source result hash", self.source_result_sha256),
            ("source assignment hash", self.source_assignment_sha256),
            ("active vault hash", self.active_vault_sha256),
            ("parent frontier plan hash", self.parent_frontier_plan_sha256),
            ("selected clause hash", self.selected_clause_sha256),
            ("source rank payload hash", self.source_rank_payload_sha256),
            ("source rank order hash", self.source_rank_order_sha256),
            ("effective rank order hash", self.effective_rank_order_sha256),
        ):
            _sha256(value, name)
        _u32(self.selected_active_index, "selected active index")
        _u32(self.selected_union_index, "selected union index")
        literal_count = _u32(
            self.selected_clause_literal_count, "selected clause literal count"
        )
        if not literal_count:
            raise ResidualPolarityStagingError(
                "staging selected clause literal count differs"
            )

        assignment_payload = _assignment_bytes(self.source_assignment)
        if (
            hashlib.sha256(assignment_payload).hexdigest()
            != self.source_assignment_sha256
        ):
            raise ResidualPolarityStagingError("staging source assignment hash differs")
        source_order = _order_bytes(self.source_rank_literals)
        if hashlib.sha256(source_order).hexdigest() != self.source_rank_order_sha256:
            raise ResidualPolarityStagingError("staging source rank order hash differs")
        if (
            not isinstance(self.intersections, tuple)
            or len(self.intersections) != RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS
            or any(
                not isinstance(row, ResidualPolarityIntersection)
                for row in self.intersections
            )
            or tuple(sorted(self.intersections, key=lambda row: row.rank_index))
            != self.intersections
            or len({row.rank_index for row in self.intersections})
            != len(self.intersections)
        ):
            raise ResidualPolarityStagingError(
                "staging intersection population differs"
            )
        if (
            not isinstance(self.overlays, tuple)
            or len(self.overlays) != RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS
            or any(
                not isinstance(row, ResidualPolarityOverlay) for row in self.overlays
            )
            or tuple(sorted(self.overlays, key=lambda row: row.rank_index))
            != self.overlays
            or len({row.rank_index for row in self.overlays}) != len(self.overlays)
        ):
            raise ResidualPolarityStagingError("staging overlay population differs")

        by_intersection = {row.rank_index: row for row in self.intersections}
        effective = list(self.source_rank_literals)
        for overlay in self.overlays:
            if overlay.rank_index >= len(effective):
                raise ResidualPolarityStagingError("staging overlay rank index differs")
            intersection = by_intersection.get(overlay.rank_index)
            if (
                intersection is None
                or effective[overlay.rank_index] != overlay.source_literal
                or intersection.source_literal != overlay.source_literal
                or intersection.effective_literal != overlay.effective_literal
            ):
                raise ResidualPolarityStagingError(
                    "staging overlay intersection binding differs"
                )
            effective[overlay.rank_index] = overlay.effective_literal
        for intersection in self.intersections:
            if (
                intersection.rank_index >= len(self.source_rank_literals)
                or self.source_rank_literals[intersection.rank_index]
                != intersection.source_literal
                or effective[intersection.rank_index] != intersection.effective_literal
            ):
                raise ResidualPolarityStagingError(
                    "staging intersection rank binding differs"
                )
        effective_payload = _order_bytes(tuple(effective))
        if (
            hashlib.sha256(effective_payload).hexdigest()
            != self.effective_rank_order_sha256
        ):
            raise ResidualPolarityStagingError(
                "staging effective rank order hash differs"
            )

    @property
    def serialized(self) -> bytes:
        return serialize_residual_polarity_staging_plan(self)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()

    @property
    def serialized_bytes(self) -> int:
        return len(self.serialized)

    @property
    def source_assignment_bytes(self) -> bytes:
        return _assignment_bytes(self.source_assignment)

    @property
    def effective_rank_literals(self) -> tuple[int, ...]:
        result = list(self.source_rank_literals)
        for overlay in self.overlays:
            result[overlay.rank_index] = overlay.effective_literal
        return tuple(result)

    @property
    def source_rank_order_bytes(self) -> bytes:
        return _order_bytes(self.source_rank_literals)

    @property
    def effective_rank_order_bytes(self) -> bytes:
        return _order_bytes(self.effective_rank_literals)

    def describe(self) -> dict[str, object]:
        return {
            "schema": RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
            "sha256": self.sha256,
            "serialized_bytes": self.serialized_bytes,
            "source_result_sha256": self.source_result_sha256,
            "source_assignment_sha256": self.source_assignment_sha256,
            "active_vault_sha256": self.active_vault_sha256,
            "parent_frontier_plan_sha256": self.parent_frontier_plan_sha256,
            "selected_active_index": self.selected_active_index,
            "selected_union_index": self.selected_union_index,
            "selected_clause_sha256": self.selected_clause_sha256,
            "selected_clause_literal_count": self.selected_clause_literal_count,
            "source_rank_payload_sha256": self.source_rank_payload_sha256,
            "source_rank_order_sha256": self.source_rank_order_sha256,
            "effective_rank_order_sha256": self.effective_rank_order_sha256,
            "source_rank_literals": list(self.source_rank_literals),
            "effective_rank_literals": list(self.effective_rank_literals),
            "intersections": [
                {
                    "rank_index": row.rank_index,
                    "clause_literal": row.clause_literal,
                    "source_literal": row.source_literal,
                    "effective_literal": row.effective_literal,
                }
                for row in self.intersections
            ],
            "overlays": [
                {
                    "rank_index": row.rank_index,
                    "source_literal": row.source_literal,
                    "effective_literal": row.effective_literal,
                }
                for row in self.overlays
            ],
        }


def _source_mapping_and_hash(
    source_result: Mapping[str, object] | bytes,
    source_result_sha256: str | None,
) -> tuple[Mapping[str, object], str]:
    if isinstance(source_result, bytes):
        if len(source_result) > RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES:
            raise ResidualPolarityStagingError("staging source result is too large")
        digest = hashlib.sha256(source_result).hexdigest()
        if source_result_sha256 is not None and source_result_sha256 != digest:
            raise ResidualPolarityStagingError("staging source result hash differs")
        try:
            decoded = json.loads(source_result)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ResidualPolarityStagingError(
                "staging source result JSON differs"
            ) from exc
        if not isinstance(decoded, Mapping) or not all(
            isinstance(key, str) for key in decoded
        ):
            raise ResidualPolarityStagingError("staging source result differs")
        return cast(Mapping[str, object], decoded), digest
    if not isinstance(source_result, Mapping) or not all(
        isinstance(key, str) for key in source_result
    ):
        raise ResidualPolarityStagingError("staging source result differs")
    expected = _sha256(source_result_sha256, "source result hash")
    try:
        canonical = json.dumps(
            source_result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ResidualPolarityStagingError(
            "staging source result canonicalization differs"
        ) from exc
    if (
        len(canonical) > RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES
        or hashlib.sha256(canonical).hexdigest() != expected
    ):
        raise ResidualPolarityStagingError("staging source result hash differs")
    return source_result, expected


def _source_assignment(
    source_result: Mapping[str, object], observed_count: int
) -> tuple[tuple[int, ...], str]:
    sieve = source_result.get("sieve")
    if not isinstance(sieve, Mapping):
        raise ResidualPolarityStagingError("staging source sieve differs")
    state = sieve.get("state")
    if not isinstance(state, Mapping):
        raise ResidualPolarityStagingError("staging source state differs")
    if state.get("schema") != RESIDUAL_POLARITY_STAGING_SOURCE_STATE_SCHEMA:
        raise ResidualPolarityStagingError("staging source state schema differs")
    encoding = state.get("encoding")
    if (
        not isinstance(encoding, str)
        or encoding.split(";", 1)[0] != RESIDUAL_POLARITY_STAGING_ASSIGNMENT_ENCODING
    ):
        raise ResidualPolarityStagingError("staging source assignment encoding differs")
    assignment_hex = state.get("assignment_hex")
    if not isinstance(assignment_hex, str) or len(assignment_hex) % 2:
        raise ResidualPolarityStagingError("staging source assignment hex differs")
    try:
        payload = bytes.fromhex(assignment_hex)
    except ValueError as exc:
        raise ResidualPolarityStagingError(
            "staging source assignment hex differs"
        ) from exc
    digest = _sha256(state.get("assignment_sha256"), "source assignment hash")
    if (
        len(payload) != observed_count
        or state.get("assignment_bytes") != len(payload)
        or hashlib.sha256(payload).hexdigest() != digest
        or any(byte not in (0, 1, 255) for byte in payload)
    ):
        raise ResidualPolarityStagingError("staging source assignment differs")
    signs = tuple(-1 if byte == 255 else byte for byte in payload)
    if state.get("current_assigned_variables") != sum(sign != 0 for sign in signs):
        raise ResidualPolarityStagingError(
            "staging source assigned-variable count differs"
        )
    return signs, digest


def derive_residual_polarity_staging_plan(
    *,
    source_result: Mapping[str, object] | bytes,
    active_vault: ThresholdNoGoodVault,
    rank_decision: VaultRankedDecision,
    parent_frontier_plan_sha256: str,
    selected_active_index: int,
    selected_union_index: int,
    overlay_rank_indices: Sequence[int],
    source_result_sha256: str | None = None,
) -> ResidualPolarityStagingPlan:
    """Derive the exact five-intersection/two-overlay staging plan."""

    if not isinstance(active_vault, ThresholdNoGoodVault):
        raise ResidualPolarityStagingError("staging active vault differs")
    try:
        decision = validate_vault_ranked_decision(rank_decision)
    except VaultRankedDecisionError as exc:
        raise ResidualPolarityStagingError("staging rank decision differs") from exc
    active_index = _u32(selected_active_index, "selected active index")
    union_index = _u32(selected_union_index, "selected union index")
    if active_index >= active_vault.clause_count:
        raise ResidualPolarityStagingError("staging selected active index differs")
    if isinstance(overlay_rank_indices, (str, bytes, bytearray)):
        raise ResidualPolarityStagingError("staging overlay indices differ")
    try:
        overlay_indices = tuple(overlay_rank_indices)
    except TypeError as exc:
        raise ResidualPolarityStagingError("staging overlay indices differ") from exc
    if (
        len(overlay_indices) != RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS
        or any(
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < decision.candidate_count
            for index in overlay_indices
        )
        or tuple(sorted(overlay_indices)) != overlay_indices
        or len(set(overlay_indices)) != len(overlay_indices)
    ):
        raise ResidualPolarityStagingError("staging overlay indices differ")

    source, source_digest = _source_mapping_and_hash(
        source_result, source_result_sha256
    )
    assignment, assignment_digest = _source_assignment(
        source, len(active_vault.observed_variables)
    )
    clause = active_vault.clauses[active_index]
    assignment_by_variable = dict(
        zip(active_vault.observed_variables, assignment, strict=True)
    )
    # O1C77 stages only the prior terminal residual.  The other selected-clause
    # variables are already fixed by the source assignment and are not live
    # candidates even when they also occur in the immutable 255-key rank.
    clause_by_variable = {
        abs(literal): literal
        for literal in clause.literals
        if assignment_by_variable[abs(literal)] == 0
    }
    effective_literals = list(decision.ranked_literals)
    overlay_set = set(overlay_indices)
    intersections: list[ResidualPolarityIntersection] = []
    overlays: list[ResidualPolarityOverlay] = []
    for rank_index, source_literal in enumerate(decision.ranked_literals):
        clause_literal = clause_by_variable.get(abs(source_literal))
        if clause_literal is None:
            continue
        effective_literal = (
            -source_literal if rank_index in overlay_set else source_literal
        )
        intersections.append(
            ResidualPolarityIntersection(
                rank_index,
                clause_literal,
                source_literal,
                effective_literal,
            )
        )
        if rank_index in overlay_set:
            overlays.append(
                ResidualPolarityOverlay(rank_index, source_literal, effective_literal)
            )
            effective_literals[rank_index] = effective_literal
    if (
        len(intersections) != RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS
        or len(overlays) != RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS
    ):
        raise ResidualPolarityStagingError(
            "staging selected clause/rank intersection differs"
        )
    effective_order = _order_bytes(tuple(effective_literals))
    return ResidualPolarityStagingPlan(
        source_result_sha256=source_digest,
        source_assignment_sha256=assignment_digest,
        active_vault_sha256=active_vault.sha256,
        parent_frontier_plan_sha256=_sha256(
            parent_frontier_plan_sha256, "parent frontier plan hash"
        ),
        selected_active_index=active_index,
        selected_union_index=union_index,
        selected_clause_sha256=clause.sha256,
        selected_clause_literal_count=clause.literal_count,
        source_rank_payload_sha256=decision.rank_table_sha256,
        source_rank_order_sha256=decision.order_sha256,
        effective_rank_order_sha256=hashlib.sha256(effective_order).hexdigest(),
        source_assignment=assignment,
        source_rank_literals=decision.ranked_literals,
        intersections=tuple(intersections),
        overlays=tuple(overlays),
    )


def validate_residual_polarity_staging_plan(
    plan: ResidualPolarityStagingPlan,
    *,
    active_vault: ThresholdNoGoodVault,
    rank_decision: VaultRankedDecision,
) -> None:
    """Recompute the vault/rank/intersection/overlay bindings."""

    if not isinstance(plan, ResidualPolarityStagingPlan):
        raise ResidualPolarityStagingError("staging plan differs")
    if not isinstance(active_vault, ThresholdNoGoodVault):
        raise ResidualPolarityStagingError("staging active vault differs")
    try:
        decision = validate_vault_ranked_decision(rank_decision)
    except VaultRankedDecisionError as exc:
        raise ResidualPolarityStagingError("staging rank decision differs") from exc
    if (
        plan.active_vault_sha256 != active_vault.sha256
        or plan.selected_active_index >= active_vault.clause_count
        or len(plan.source_assignment) != len(active_vault.observed_variables)
        or plan.source_rank_payload_sha256 != decision.rank_table_sha256
        or plan.source_rank_order_sha256 != decision.order_sha256
        or plan.source_rank_literals != decision.ranked_literals
    ):
        raise ResidualPolarityStagingError("staging source binding differs")
    clause = active_vault.clauses[plan.selected_active_index]
    if (
        plan.selected_clause_sha256 != clause.sha256
        or plan.selected_clause_literal_count != clause.literal_count
    ):
        raise ResidualPolarityStagingError("staging selected clause binding differs")
    assignment_by_variable = dict(
        zip(active_vault.observed_variables, plan.source_assignment, strict=True)
    )
    expected_by_variable = {
        abs(literal): literal
        for literal in clause.literals
        if assignment_by_variable[abs(literal)] == 0
    }
    overlay_by_index = {row.rank_index: row for row in plan.overlays}
    expected: list[ResidualPolarityIntersection] = []
    for index, source_literal in enumerate(decision.ranked_literals):
        clause_literal = expected_by_variable.get(abs(source_literal))
        if clause_literal is None:
            continue
        overlay = overlay_by_index.get(index)
        effective = overlay.effective_literal if overlay else source_literal
        expected.append(
            ResidualPolarityIntersection(
                index, clause_literal, source_literal, effective
            )
        )
    if tuple(expected) != plan.intersections:
        raise ResidualPolarityStagingError(
            "staging selected clause/rank intersection differs"
        )


def validate_o1c77_production_plan(plan: ResidualPolarityStagingPlan) -> None:
    """Apply the frozen O1C-0077 production identity seal."""

    actual_intersections = tuple(
        (
            row.rank_index,
            row.clause_literal,
            row.source_literal,
            row.effective_literal,
        )
        for row in plan.intersections
    )
    actual_overlays = tuple(
        (row.rank_index, row.source_literal, row.effective_literal)
        for row in plan.overlays
    )
    if (
        plan.source_result_sha256 != O1C77_SOURCE_RESULT_SHA256
        or plan.source_assignment_sha256 != O1C77_SOURCE_ASSIGNMENT_SHA256
        or plan.active_vault_sha256 != O1C77_ACTIVE_VAULT_SHA256
        or plan.parent_frontier_plan_sha256 != O1C77_PARENT_FRONTIER_PLAN_SHA256
        or plan.selected_active_index != O1C77_SELECTED_ACTIVE_INDEX
        or plan.selected_union_index != O1C77_SELECTED_UNION_INDEX
        or plan.selected_clause_sha256 != O1C77_SELECTED_CLAUSE_SHA256
        or plan.selected_clause_literal_count != O1C77_SELECTED_CLAUSE_LITERAL_COUNT
        or plan.source_rank_payload_sha256 != O1C77_SOURCE_RANK_PAYLOAD_SHA256
        or plan.source_rank_order_sha256 != O1C77_SOURCE_RANK_ORDER_SHA256
        or plan.effective_rank_order_sha256 != O1C77_EFFECTIVE_RANK_ORDER_SHA256
        or actual_intersections != O1C77_INTERSECTIONS
        or actual_overlays != O1C77_OVERLAYS
    ):
        raise ResidualPolarityStagingError("staging O1C77 production identity differs")


def _append_u32(payload: bytearray, value: int) -> None:
    payload.extend(struct.pack("<I", _u32(value, "binary u32")))


def _append_i32(payload: bytearray, value: int) -> None:
    payload.extend(struct.pack("<i", _literal(value, "binary i32")))


def serialize_residual_polarity_staging_plan(
    plan: ResidualPolarityStagingPlan,
) -> bytes:
    """Return the sole canonical binary representation of ``plan``."""

    if not isinstance(plan, ResidualPolarityStagingPlan):
        raise ResidualPolarityStagingError("staging plan differs")
    body = bytearray(RESIDUAL_POLARITY_STAGING_PLAN_MAGIC)
    for value in (
        RESIDUAL_POLARITY_STAGING_PLAN_VERSION,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS,
        RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS,
        RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS,
    ):
        _append_u32(body, value)
    for digest in (
        plan.source_result_sha256,
        plan.source_assignment_sha256,
        plan.active_vault_sha256,
        plan.parent_frontier_plan_sha256,
        plan.selected_clause_sha256,
        plan.source_rank_payload_sha256,
        plan.source_rank_order_sha256,
        plan.effective_rank_order_sha256,
    ):
        body.extend(bytes.fromhex(digest))
    for value in (
        plan.selected_active_index,
        plan.selected_union_index,
        plan.selected_clause_literal_count,
    ):
        _append_u32(body, value)
    assignment = plan.source_assignment_bytes
    _append_u32(body, len(assignment))
    body.extend(assignment)
    _append_u32(body, len(plan.source_rank_literals))
    for literal in plan.source_rank_literals:
        _append_i32(body, literal)
    _append_u32(body, len(plan.intersections))
    for row in plan.intersections:
        _append_u32(body, row.rank_index)
        _append_i32(body, row.clause_literal)
        _append_i32(body, row.source_literal)
        _append_i32(body, row.effective_literal)
    _append_u32(body, len(plan.overlays))
    for row in plan.overlays:
        _append_u32(body, row.rank_index)
        _append_i32(body, row.source_literal)
        _append_i32(body, row.effective_literal)
    body.extend(hashlib.sha256(body).digest())
    result = bytes(body)
    if len(result) > RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES:
        raise ResidualPolarityStagingError("staging serialized plan exceeds cap")
    return result


class _Cursor:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def take(self, count: int, field_name: str) -> bytes:
        if count < 0 or self.offset + count > len(self.payload):
            raise ResidualPolarityStagingError(f"staging binary {field_name} differs")
        value = self.payload[self.offset : self.offset + count]
        self.offset += count
        return value

    def u32(self, field_name: str) -> int:
        return struct.unpack("<I", self.take(4, field_name))[0]

    def i32(self, field_name: str) -> int:
        return struct.unpack("<i", self.take(4, field_name))[0]


def parse_residual_polarity_staging_plan(
    payload: bytes,
    *,
    active_vault: ThresholdNoGoodVault | None = None,
    rank_decision: VaultRankedDecision | None = None,
) -> ResidualPolarityStagingPlan:
    """Parse, checksum, cap, and canonically reserialize a staging plan."""

    if not isinstance(payload, bytes):
        raise ResidualPolarityStagingError("staging binary payload differs")
    if (
        len(payload) <= len(RESIDUAL_POLARITY_STAGING_PLAN_MAGIC) + _CHECKSUM_BYTES
        or len(payload) > RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES
    ):
        raise ResidualPolarityStagingError("staging binary size differs")
    if (
        hashlib.sha256(payload[:-_CHECKSUM_BYTES]).digest()
        != payload[-_CHECKSUM_BYTES:]
    ):
        raise ResidualPolarityStagingError("staging binary checksum differs")
    cursor = _Cursor(payload[:-_CHECKSUM_BYTES])
    if (
        cursor.take(len(RESIDUAL_POLARITY_STAGING_PLAN_MAGIC), "magic")
        != RESIDUAL_POLARITY_STAGING_PLAN_MAGIC
    ):
        raise ResidualPolarityStagingError("staging binary magic differs")
    expected_header = (
        RESIDUAL_POLARITY_STAGING_PLAN_VERSION,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS,
        RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS,
        RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS,
        RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS,
    )
    if tuple(cursor.u32("header") for _ in expected_header) != expected_header:
        raise ResidualPolarityStagingError("staging binary version or caps differ")
    digests = tuple(cursor.take(32, "digest").hex() for _ in range(8))
    selected_active_index = cursor.u32("selected active index")
    selected_union_index = cursor.u32("selected union index")
    selected_clause_literal_count = cursor.u32("selected clause literal count")
    assignment_count = cursor.u32("assignment count")
    if assignment_count > RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS:
        raise ResidualPolarityStagingError("staging binary assignment count differs")
    assignment_payload = cursor.take(assignment_count, "assignment")
    if any(byte not in (0, 1, 255) for byte in assignment_payload):
        raise ResidualPolarityStagingError("staging binary assignment differs")
    assignment = tuple(-1 if byte == 255 else byte for byte in assignment_payload)
    rank_count = cursor.u32("rank count")
    if not 1 <= rank_count <= RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS:
        raise ResidualPolarityStagingError("staging binary rank count differs")
    rank_literals = tuple(cursor.i32("rank literal") for _ in range(rank_count))
    intersection_count = cursor.u32("intersection count")
    if intersection_count != RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS:
        raise ResidualPolarityStagingError("staging binary intersection count differs")
    intersections = tuple(
        ResidualPolarityIntersection(
            cursor.u32("intersection rank index"),
            cursor.i32("intersection clause literal"),
            cursor.i32("intersection source literal"),
            cursor.i32("intersection effective literal"),
        )
        for _ in range(intersection_count)
    )
    overlay_count = cursor.u32("overlay count")
    if overlay_count != RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS:
        raise ResidualPolarityStagingError("staging binary overlay count differs")
    overlays = tuple(
        ResidualPolarityOverlay(
            cursor.u32("overlay rank index"),
            cursor.i32("overlay source literal"),
            cursor.i32("overlay effective literal"),
        )
        for _ in range(overlay_count)
    )
    if cursor.offset != len(cursor.payload):
        raise ResidualPolarityStagingError("staging binary trailing bytes differ")
    plan = ResidualPolarityStagingPlan(
        source_result_sha256=digests[0],
        source_assignment_sha256=digests[1],
        active_vault_sha256=digests[2],
        parent_frontier_plan_sha256=digests[3],
        selected_clause_sha256=digests[4],
        source_rank_payload_sha256=digests[5],
        source_rank_order_sha256=digests[6],
        effective_rank_order_sha256=digests[7],
        selected_active_index=selected_active_index,
        selected_union_index=selected_union_index,
        selected_clause_literal_count=selected_clause_literal_count,
        source_assignment=assignment,
        source_rank_literals=rank_literals,
        intersections=intersections,
        overlays=overlays,
    )
    if serialize_residual_polarity_staging_plan(plan) != payload:
        raise ResidualPolarityStagingError("staging binary is not canonical")
    if (active_vault is None) != (rank_decision is None):
        raise ResidualPolarityStagingError("staging validation inputs differ")
    if active_vault is not None and rank_decision is not None:
        validate_residual_polarity_staging_plan(
            plan, active_vault=active_vault, rank_decision=rank_decision
        )
    return plan


def _read_regular_file(path: str | Path) -> tuple[Path, bytes]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ResidualPolarityStagingError("staging plan is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ResidualPolarityStagingError("staging plan is not a regular file")
    if metadata.st_size > RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES:
        raise ResidualPolarityStagingError("staging plan exceeds cap")
    try:
        payload = candidate.read_bytes()
    except OSError as exc:
        raise ResidualPolarityStagingError("staging plan is unreadable") from exc
    if len(payload) != metadata.st_size:
        raise ResidualPolarityStagingError("staging plan changed while reading")
    return candidate, payload


def read_residual_polarity_staging_plan(
    path: str | Path,
    *,
    active_vault: ThresholdNoGoodVault | None = None,
    rank_decision: VaultRankedDecision | None = None,
) -> ResidualPolarityStagingPlan:
    """Read one bounded regular staging-plan file."""

    _, payload = _read_regular_file(path)
    return parse_residual_polarity_staging_plan(
        payload, active_vault=active_vault, rank_decision=rank_decision
    )


def write_residual_polarity_staging_plan(
    path: str | Path, plan: ResidualPolarityStagingPlan
) -> None:
    """Atomically write one canonical staging plan without following links."""

    destination = Path(path)
    payload = serialize_residual_polarity_staging_plan(plan)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


__all__ = [
    "O1C77_ACTIVE_VAULT_SHA256",
    "O1C77_EFFECTIVE_RANK_ORDER_SHA256",
    "O1C77_INTERSECTIONS",
    "O1C77_OVERLAYS",
    "O1C77_PARENT_FRONTIER_PLAN_SHA256",
    "O1C77_SELECTED_ACTIVE_INDEX",
    "O1C77_SELECTED_CLAUSE_LITERAL_COUNT",
    "O1C77_SELECTED_CLAUSE_SHA256",
    "O1C77_SELECTED_UNION_INDEX",
    "O1C77_SOURCE_ASSIGNMENT_SHA256",
    "O1C77_SOURCE_RANK_ORDER_SHA256",
    "O1C77_SOURCE_RANK_PAYLOAD_SHA256",
    "O1C77_SOURCE_RESULT_SHA256",
    "RESIDUAL_POLARITY_STAGING_ASSIGNMENT_ENCODING",
    "RESIDUAL_POLARITY_STAGING_INTERSECTION_ROWS",
    "RESIDUAL_POLARITY_STAGING_MAXIMUM_ASSIGNMENTS",
    "RESIDUAL_POLARITY_STAGING_MAXIMUM_RANK_ROWS",
    "RESIDUAL_POLARITY_STAGING_MAXIMUM_SERIALIZED_BYTES",
    "RESIDUAL_POLARITY_STAGING_OVERLAY_ROWS",
    "RESIDUAL_POLARITY_STAGING_PLAN_MAGIC",
    "RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA",
    "RESIDUAL_POLARITY_STAGING_PLAN_VERSION",
    "ResidualPolarityIntersection",
    "ResidualPolarityOverlay",
    "ResidualPolarityStagingError",
    "ResidualPolarityStagingPlan",
    "derive_residual_polarity_staging_plan",
    "parse_residual_polarity_staging_plan",
    "read_residual_polarity_staging_plan",
    "serialize_residual_polarity_staging_plan",
    "validate_o1c77_production_plan",
    "validate_residual_polarity_staging_plan",
    "write_residual_polarity_staging_plan",
]
