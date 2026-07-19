"""Canonical target-free causal frontier plans.

A plan seals one public solver assignment against one certified active
threshold-no-good vault.  The chosen clause is the deterministic closest
currently unsatisfied clause: no literal may already be true, then the fewest
unassigned literals wins, with clause digest and active index as tie-breakers.

The binary format deliberately carries the observed-order assignment and the
complete selected-union index vector.  Native consumers can therefore verify
the selection, counts, residual clause, and decisions without parsing JSON.
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

from .threshold_no_good_vault_v1 import (
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
)


CAUSAL_FRONTIER_PLAN_SCHEMA = "o1-score-threshold-causal-frontier-plan-v1"
CAUSAL_FRONTIER_PLAN_MAGIC = b"O1-CAUSAL-FRONTIER-V1\0"
CAUSAL_FRONTIER_PLAN_VERSION = 1
CAUSAL_FRONTIER_ASSIGNMENT_ENCODING = "observed-ascending-i8-sign"
CAUSAL_FRONTIER_SOURCE_STATE_SCHEMA = (
    "o1-256-cadical-joint-score-sieve-grouped-state-v2"
)

# These limits cover the frozen vault population while keeping every parser
# allocation bounded independently of untrusted length words.
CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES = 16_777_216
CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS = 1_600_000
CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES = 512
CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS = 1_600_000

_UINT32_MAX = (1 << 32) - 1
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_CHECKSUM_BYTES = 32


class CausalFrontierError(ValueError):
    """A source assignment, active vault, plan, or binary contract differs."""


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_sha256(value: object, field_name: str) -> str:
    if not _is_sha256(value):
        raise CausalFrontierError(f"causal frontier {field_name} differs")
    return cast(str, value)


def _u32(value: object, field_name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _UINT32_MAX
    ):
        raise CausalFrontierError(f"causal frontier {field_name} differs")
    return value


def _assignment_bytes(signs: tuple[int, ...]) -> bytes:
    if (
        not isinstance(signs, tuple)
        or len(signs) > CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS
        or any(
            isinstance(sign, bool)
            or not isinstance(sign, int)
            or sign not in (-1, 0, 1)
            for sign in signs
        )
    ):
        raise CausalFrontierError("causal frontier prior assignment differs")
    return bytes(255 if sign == -1 else sign for sign in signs)


def _literal_tuple(value: object, field_name: str) -> tuple[int, ...]:
    if not isinstance(value, tuple):
        raise CausalFrontierError(f"causal frontier {field_name} differs")
    previous = 0
    for literal in value:
        if (
            isinstance(literal, bool)
            or not isinstance(literal, int)
            or literal in (0, _INT32_MIN)
            or not _INT32_MIN < literal <= _INT32_MAX
            or abs(literal) <= previous
        ):
            raise CausalFrontierError(f"causal frontier {field_name} differs")
        previous = abs(literal)
    return cast(tuple[int, ...], value)


@dataclass(frozen=True)
class CausalFrontierPlan:
    """A self-checking frontier selection and its exact intervention rows."""

    source_result_sha256: str
    source_assignment_sha256: str
    active_vault_sha256: str
    selected_union_indices: tuple[int, ...]
    selected_active_index: int
    selected_union_index: int
    selected_clause_sha256: str
    selected_clause_literal_count: int
    false_literal_count: int
    true_literal_count: int
    unassigned_literal_count: int
    prior_assignment: tuple[int, ...] = field(repr=False)
    residual_clause_literals: tuple[int, ...]
    falsifying_decision_literals: tuple[int, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.source_result_sha256, "source result hash")
        _require_sha256(self.source_assignment_sha256, "source assignment hash")
        _require_sha256(self.active_vault_sha256, "active vault hash")
        _require_sha256(self.selected_clause_sha256, "selected clause hash")
        if (
            not isinstance(self.selected_union_indices, tuple)
            or not self.selected_union_indices
            or len(self.selected_union_indices)
            > CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES
        ):
            raise CausalFrontierError("causal frontier selected union indices differ")
        for union_index in self.selected_union_indices:
            _u32(union_index, "selected union index row")
        if len(set(self.selected_union_indices)) != len(self.selected_union_indices):
            raise CausalFrontierError("causal frontier selected union indices differ")
        active_index = _u32(self.selected_active_index, "selected active index")
        union_index = _u32(self.selected_union_index, "selected union index")
        if (
            active_index >= len(self.selected_union_indices)
            or self.selected_union_indices[active_index] != union_index
        ):
            raise CausalFrontierError("causal frontier selected index mapping differs")

        literal_count = _u32(
            self.selected_clause_literal_count, "selected clause literal count"
        )
        false_count = _u32(self.false_literal_count, "false literal count")
        true_count = _u32(self.true_literal_count, "true literal count")
        unassigned_count = _u32(
            self.unassigned_literal_count, "unassigned literal count"
        )
        if (
            true_count != 0
            or false_count + true_count + unassigned_count != literal_count
            or unassigned_count > CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS
        ):
            raise CausalFrontierError("causal frontier literal counts differ")

        assignment_payload = _assignment_bytes(self.prior_assignment)
        if (
            hashlib.sha256(assignment_payload).hexdigest()
            != self.source_assignment_sha256
        ):
            raise CausalFrontierError("causal frontier source assignment hash differs")

        residual = _literal_tuple(
            self.residual_clause_literals, "residual clause literals"
        )
        decisions = _literal_tuple(
            self.falsifying_decision_literals, "falsifying decision literals"
        )
        if (
            len(residual) != unassigned_count
            or len(decisions) != unassigned_count
            or decisions != tuple(-literal for literal in residual)
        ):
            raise CausalFrontierError("causal frontier decision rows differ")

    @property
    def serialized(self) -> bytes:
        return serialize_causal_frontier_plan(self)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()

    @property
    def serialized_bytes(self) -> int:
        return len(self.serialized)

    @property
    def prior_assignment_bytes(self) -> bytes:
        return _assignment_bytes(self.prior_assignment)

    def describe(self) -> dict[str, object]:
        return {
            "schema": CAUSAL_FRONTIER_PLAN_SCHEMA,
            "sha256": self.sha256,
            "serialized_bytes": self.serialized_bytes,
            "source_result_sha256": self.source_result_sha256,
            "source_assignment_sha256": self.source_assignment_sha256,
            "active_vault_sha256": self.active_vault_sha256,
            "selected_active_index": self.selected_active_index,
            "selected_union_index": self.selected_union_index,
            "selected_clause_sha256": self.selected_clause_sha256,
            "selected_clause_literal_count": self.selected_clause_literal_count,
            "false_literal_count": self.false_literal_count,
            "true_literal_count": self.true_literal_count,
            "unassigned_literal_count": self.unassigned_literal_count,
            "residual_clause_literals": list(self.residual_clause_literals),
            "falsifying_decision_literals": list(self.falsifying_decision_literals),
        }


def _source_mapping_and_hash(
    source_result: Mapping[str, object] | bytes,
    source_result_sha256: str | None,
) -> tuple[Mapping[str, object], str]:
    if isinstance(source_result, bytes):
        if len(source_result) > CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES:
            raise CausalFrontierError("causal frontier source result is too large")
        digest = hashlib.sha256(source_result).hexdigest()
        if source_result_sha256 is not None and source_result_sha256 != digest:
            raise CausalFrontierError("causal frontier source result hash differs")
        try:
            decoded = json.loads(source_result)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CausalFrontierError(
                "causal frontier source result JSON differs"
            ) from exc
        if not isinstance(decoded, Mapping) or not all(
            isinstance(key, str) for key in decoded
        ):
            raise CausalFrontierError("causal frontier source result differs")
        return cast(Mapping[str, object], decoded), digest
    if not isinstance(source_result, Mapping) or not all(
        isinstance(key, str) for key in source_result
    ):
        raise CausalFrontierError("causal frontier source result differs")
    expected_digest = _require_sha256(source_result_sha256, "source result hash")
    try:
        canonical_payload = json.dumps(
            source_result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CausalFrontierError(
            "causal frontier source result canonicalization differs"
        ) from exc
    if (
        len(canonical_payload) > CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES
        or hashlib.sha256(canonical_payload).hexdigest() != expected_digest
    ):
        raise CausalFrontierError("causal frontier source result hash differs")
    return source_result, expected_digest


def _source_assignment(
    source_result: Mapping[str, object], observed_count: int
) -> tuple[tuple[int, ...], str]:
    sieve = source_result.get("sieve")
    if not isinstance(sieve, Mapping):
        raise CausalFrontierError("causal frontier source sieve differs")
    state = sieve.get("state")
    if not isinstance(state, Mapping):
        raise CausalFrontierError("causal frontier source state differs")
    if state.get("schema") != CAUSAL_FRONTIER_SOURCE_STATE_SCHEMA:
        raise CausalFrontierError("causal frontier source state schema differs")
    encoding = state.get("encoding")
    if (
        not isinstance(encoding, str)
        or encoding.split(";", 1)[0] != CAUSAL_FRONTIER_ASSIGNMENT_ENCODING
    ):
        raise CausalFrontierError("causal frontier source assignment encoding differs")
    assignment_hex = state.get("assignment_hex")
    if not isinstance(assignment_hex, str) or len(assignment_hex) % 2:
        raise CausalFrontierError("causal frontier source assignment hex differs")
    try:
        payload = bytes.fromhex(assignment_hex)
    except ValueError as exc:
        raise CausalFrontierError(
            "causal frontier source assignment hex differs"
        ) from exc
    assignment_sha256 = _require_sha256(
        state.get("assignment_sha256"), "source assignment hash"
    )
    if (
        len(payload) != observed_count
        or state.get("assignment_bytes") != len(payload)
        or hashlib.sha256(payload).hexdigest() != assignment_sha256
        or any(byte not in (0, 1, 255) for byte in payload)
    ):
        raise CausalFrontierError("causal frontier source assignment differs")
    signs = tuple(-1 if byte == 255 else byte for byte in payload)
    if state.get("current_assigned_variables") != sum(sign != 0 for sign in signs):
        raise CausalFrontierError(
            "causal frontier source assigned-variable count differs"
        )
    return signs, assignment_sha256


def _classify_clause(
    clause: ThresholdNoGoodClause,
    assignment: tuple[int, ...],
    observed_index: Mapping[int, int],
) -> tuple[int, int, tuple[int, ...]]:
    false_count = 0
    true_count = 0
    residual: list[int] = []
    for literal in clause.literals:
        sign = assignment[observed_index[abs(literal)]]
        if sign == 0:
            residual.append(literal)
        elif (sign == 1) == (literal > 0):
            true_count += 1
        else:
            false_count += 1
    return false_count, true_count, tuple(residual)


def derive_causal_frontier_plan(
    *,
    source_result: Mapping[str, object] | bytes,
    active_vault: ThresholdNoGoodVault,
    selected_union_indices: Sequence[int],
    source_result_sha256: str | None = None,
) -> CausalFrontierPlan:
    """Derive the unique closest unsatisfied active clause."""

    if not isinstance(active_vault, ThresholdNoGoodVault):
        raise CausalFrontierError("causal frontier active vault differs")
    if isinstance(selected_union_indices, (str, bytes, bytearray)):
        raise CausalFrontierError("causal frontier selected union indices differ")
    try:
        selected = tuple(selected_union_indices)
    except TypeError as exc:
        raise CausalFrontierError(
            "causal frontier selected union indices differ"
        ) from exc
    if len(selected) != active_vault.clause_count:
        raise CausalFrontierError("causal frontier selected union indices differ")

    source, source_digest = _source_mapping_and_hash(
        source_result, source_result_sha256
    )
    assignment, assignment_digest = _source_assignment(
        source, len(active_vault.observed_variables)
    )
    observed_index = {
        variable: index
        for index, variable in enumerate(active_vault.observed_variables)
    }
    candidates: list[
        tuple[int, str, int, int, tuple[int, ...], ThresholdNoGoodClause]
    ] = []
    for active_index, clause in enumerate(active_vault.clauses):
        false_count, true_count, residual = _classify_clause(
            clause, assignment, observed_index
        )
        if true_count == 0:
            candidates.append(
                (
                    len(residual),
                    clause.sha256,
                    active_index,
                    false_count,
                    residual,
                    clause,
                )
            )
    if not candidates:
        raise CausalFrontierError("causal frontier has no unsatisfied active clause")
    (
        unassigned_count,
        clause_sha256,
        active_index,
        false_count,
        residual,
        clause,
    ) = min(candidates, key=lambda candidate: candidate[:3])
    return CausalFrontierPlan(
        source_result_sha256=source_digest,
        source_assignment_sha256=assignment_digest,
        active_vault_sha256=active_vault.sha256,
        selected_union_indices=selected,
        selected_active_index=active_index,
        selected_union_index=selected[active_index],
        selected_clause_sha256=clause_sha256,
        selected_clause_literal_count=clause.literal_count,
        false_literal_count=false_count,
        true_literal_count=0,
        unassigned_literal_count=unassigned_count,
        prior_assignment=assignment,
        residual_clause_literals=residual,
        falsifying_decision_literals=tuple(-literal for literal in residual),
    )


def validate_causal_frontier_plan(
    plan: CausalFrontierPlan, *, active_vault: ThresholdNoGoodVault
) -> None:
    """Recompute every clause-facing field from the sealed assignment."""

    if not isinstance(plan, CausalFrontierPlan):
        raise CausalFrontierError("causal frontier plan differs")
    if not isinstance(active_vault, ThresholdNoGoodVault):
        raise CausalFrontierError("causal frontier active vault differs")
    if (
        plan.active_vault_sha256 != active_vault.sha256
        or len(plan.selected_union_indices) != active_vault.clause_count
        or len(plan.prior_assignment) != len(active_vault.observed_variables)
        or plan.selected_active_index >= active_vault.clause_count
    ):
        raise CausalFrontierError("causal frontier active vault binding differs")
    clause = active_vault.clauses[plan.selected_active_index]
    observed_index = {
        variable: index
        for index, variable in enumerate(active_vault.observed_variables)
    }
    false_count, true_count, residual = _classify_clause(
        clause, plan.prior_assignment, observed_index
    )
    if (
        plan.selected_clause_sha256 != clause.sha256
        or plan.selected_clause_literal_count != clause.literal_count
        or plan.false_literal_count != false_count
        or plan.true_literal_count != true_count
        or plan.unassigned_literal_count != len(residual)
        or plan.residual_clause_literals != residual
        or plan.falsifying_decision_literals != tuple(-literal for literal in residual)
    ):
        raise CausalFrontierError("causal frontier selected clause binding differs")

    # Re-derive the winner so a syntactically valid plan cannot point to a
    # different true-zero clause with a worse distance or tie-break.
    candidates: list[tuple[int, str, int]] = []
    for active_index, candidate_clause in enumerate(active_vault.clauses):
        _, candidate_true, candidate_residual = _classify_clause(
            candidate_clause, plan.prior_assignment, observed_index
        )
        if candidate_true == 0:
            candidates.append(
                (len(candidate_residual), candidate_clause.sha256, active_index)
            )
    if not candidates or min(candidates) != (
        plan.unassigned_literal_count,
        plan.selected_clause_sha256,
        plan.selected_active_index,
    ):
        raise CausalFrontierError("causal frontier candidate priority differs")


def _append_u32(payload: bytearray, value: int) -> None:
    payload.extend(struct.pack("<I", _u32(value, "binary u32")))


def _append_i32(payload: bytearray, value: int) -> None:
    payload.extend(struct.pack("<i", value))


def serialize_causal_frontier_plan(plan: CausalFrontierPlan) -> bytes:
    """Return the sole canonical binary representation of ``plan``."""

    if not isinstance(plan, CausalFrontierPlan):
        raise CausalFrontierError("causal frontier plan differs")
    body = bytearray(CAUSAL_FRONTIER_PLAN_MAGIC)
    for value in (
        CAUSAL_FRONTIER_PLAN_VERSION,
        CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES,
        CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS,
        CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES,
        CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS,
    ):
        _append_u32(body, value)
    for digest in (
        plan.source_result_sha256,
        plan.source_assignment_sha256,
        plan.active_vault_sha256,
    ):
        body.extend(bytes.fromhex(digest))
    _append_u32(body, len(plan.selected_union_indices))
    for union_index in plan.selected_union_indices:
        _append_u32(body, union_index)
    _append_u32(body, plan.selected_active_index)
    _append_u32(body, plan.selected_union_index)
    body.extend(bytes.fromhex(plan.selected_clause_sha256))
    for value in (
        plan.selected_clause_literal_count,
        plan.false_literal_count,
        plan.true_literal_count,
        plan.unassigned_literal_count,
    ):
        _append_u32(body, value)
    assignment_payload = plan.prior_assignment_bytes
    _append_u32(body, len(assignment_payload))
    body.extend(assignment_payload)
    _append_u32(body, len(plan.residual_clause_literals))
    for literal in plan.residual_clause_literals:
        _append_i32(body, literal)
    _append_u32(body, len(plan.falsifying_decision_literals))
    for literal in plan.falsifying_decision_literals:
        _append_i32(body, literal)
    body.extend(hashlib.sha256(body).digest())
    result = bytes(body)
    if len(result) > CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES:
        raise CausalFrontierError("causal frontier serialized plan exceeds cap")
    return result


class _Cursor:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def take(self, count: int, field_name: str) -> bytes:
        if count < 0 or self.offset + count > len(self.payload):
            raise CausalFrontierError(f"causal frontier binary {field_name} differs")
        value = self.payload[self.offset : self.offset + count]
        self.offset += count
        return value

    def u32(self, field_name: str) -> int:
        return struct.unpack("<I", self.take(4, field_name))[0]

    def i32(self, field_name: str) -> int:
        return struct.unpack("<i", self.take(4, field_name))[0]


def parse_causal_frontier_plan(
    payload: bytes, *, active_vault: ThresholdNoGoodVault | None = None
) -> CausalFrontierPlan:
    """Parse, checksum, cap, and canonically reserialize a frontier plan."""

    if not isinstance(payload, bytes):
        raise CausalFrontierError("causal frontier binary payload differs")
    if (
        len(payload) <= len(CAUSAL_FRONTIER_PLAN_MAGIC) + _CHECKSUM_BYTES
        or len(payload) > CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES
    ):
        raise CausalFrontierError("causal frontier binary size differs")
    if (
        hashlib.sha256(payload[:-_CHECKSUM_BYTES]).digest()
        != payload[-_CHECKSUM_BYTES:]
    ):
        raise CausalFrontierError("causal frontier binary checksum differs")

    cursor = _Cursor(payload[:-_CHECKSUM_BYTES])
    if (
        cursor.take(len(CAUSAL_FRONTIER_PLAN_MAGIC), "magic")
        != CAUSAL_FRONTIER_PLAN_MAGIC
    ):
        raise CausalFrontierError("causal frontier binary magic differs")
    expected_header = (
        CAUSAL_FRONTIER_PLAN_VERSION,
        CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES,
        CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS,
        CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES,
        CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS,
    )
    actual_header = tuple(cursor.u32("header") for _ in expected_header)
    if actual_header != expected_header:
        raise CausalFrontierError("causal frontier binary version or caps differ")
    source_result_sha256 = cursor.take(32, "source result hash").hex()
    source_assignment_sha256 = cursor.take(32, "source assignment hash").hex()
    active_vault_sha256 = cursor.take(32, "active vault hash").hex()

    selected_count = cursor.u32("selected index count")
    if not 1 <= selected_count <= CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES:
        raise CausalFrontierError("causal frontier binary selected index count differs")
    selected_union_indices = tuple(
        cursor.u32("selected union index") for _ in range(selected_count)
    )
    selected_active_index = cursor.u32("selected active index")
    selected_union_index = cursor.u32("selected union index")
    selected_clause_sha256 = cursor.take(32, "selected clause hash").hex()
    selected_clause_literal_count = cursor.u32("selected clause literal count")
    false_literal_count = cursor.u32("false literal count")
    true_literal_count = cursor.u32("true literal count")
    unassigned_literal_count = cursor.u32("unassigned literal count")

    assignment_count = cursor.u32("assignment count")
    if assignment_count > CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS:
        raise CausalFrontierError("causal frontier binary assignment count differs")
    assignment_payload = cursor.take(assignment_count, "assignment")
    if any(byte not in (0, 1, 255) for byte in assignment_payload):
        raise CausalFrontierError("causal frontier binary assignment differs")
    prior_assignment = tuple(-1 if byte == 255 else byte for byte in assignment_payload)

    residual_count = cursor.u32("residual count")
    if residual_count > CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS:
        raise CausalFrontierError("causal frontier binary residual count differs")
    residual = tuple(cursor.i32("residual literal") for _ in range(residual_count))
    decision_count = cursor.u32("decision count")
    if decision_count > CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS:
        raise CausalFrontierError("causal frontier binary decision count differs")
    decisions = tuple(cursor.i32("decision literal") for _ in range(decision_count))
    if cursor.offset != len(cursor.payload):
        raise CausalFrontierError("causal frontier binary trailing bytes differ")

    plan = CausalFrontierPlan(
        source_result_sha256=source_result_sha256,
        source_assignment_sha256=source_assignment_sha256,
        active_vault_sha256=active_vault_sha256,
        selected_union_indices=selected_union_indices,
        selected_active_index=selected_active_index,
        selected_union_index=selected_union_index,
        selected_clause_sha256=selected_clause_sha256,
        selected_clause_literal_count=selected_clause_literal_count,
        false_literal_count=false_literal_count,
        true_literal_count=true_literal_count,
        unassigned_literal_count=unassigned_literal_count,
        prior_assignment=prior_assignment,
        residual_clause_literals=residual,
        falsifying_decision_literals=decisions,
    )
    if serialize_causal_frontier_plan(plan) != payload:
        raise CausalFrontierError("causal frontier binary is not canonical")
    if active_vault is not None:
        validate_causal_frontier_plan(plan, active_vault=active_vault)
    return plan


def _read_regular_file(path: str | Path) -> tuple[Path, bytes]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise CausalFrontierError("causal frontier plan is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CausalFrontierError("causal frontier plan is not a regular file")
    if metadata.st_size > CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES:
        raise CausalFrontierError("causal frontier plan exceeds cap")
    try:
        payload = candidate.read_bytes()
    except OSError as exc:
        raise CausalFrontierError("causal frontier plan is unreadable") from exc
    if len(payload) != metadata.st_size:
        raise CausalFrontierError("causal frontier plan changed while reading")
    return candidate, payload


def read_causal_frontier_plan(
    path: str | Path, *, active_vault: ThresholdNoGoodVault | None = None
) -> CausalFrontierPlan:
    """Read one bounded regular plan file."""

    _, payload = _read_regular_file(path)
    return parse_causal_frontier_plan(payload, active_vault=active_vault)


def write_causal_frontier_plan(path: str | Path, plan: CausalFrontierPlan) -> None:
    """Atomically write one canonical frontier plan without following links."""

    destination = Path(path)
    payload = serialize_causal_frontier_plan(plan)
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
    "CAUSAL_FRONTIER_ASSIGNMENT_ENCODING",
    "CAUSAL_FRONTIER_MAXIMUM_ASSIGNMENTS",
    "CAUSAL_FRONTIER_MAXIMUM_RESIDUAL_LITERALS",
    "CAUSAL_FRONTIER_MAXIMUM_SELECTED_INDICES",
    "CAUSAL_FRONTIER_MAXIMUM_SERIALIZED_BYTES",
    "CAUSAL_FRONTIER_PLAN_MAGIC",
    "CAUSAL_FRONTIER_PLAN_SCHEMA",
    "CAUSAL_FRONTIER_PLAN_VERSION",
    "CausalFrontierError",
    "CausalFrontierPlan",
    "derive_causal_frontier_plan",
    "parse_causal_frontier_plan",
    "read_causal_frontier_plan",
    "serialize_causal_frontier_plan",
    "validate_causal_frontier_plan",
    "write_causal_frontier_plan",
]
