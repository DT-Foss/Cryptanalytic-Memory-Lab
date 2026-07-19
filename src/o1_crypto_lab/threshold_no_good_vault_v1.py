"""Canonical bounded archive for exact score-threshold no-goods.

The vault is deliberately solver-independent.  It binds clauses to the exact
CNF, public potential, width-6 grouping, observed-variable order, bound rule,
and binary64 threshold that certified them.  Clause order is first-emission
order; append performs exact-clause deduplication only and never subsumption,
eviction, truncation, or reordering.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping


THRESHOLD_NO_GOOD_VAULT_SCHEMA = "o1-score-threshold-no-good-vault-v1"
THRESHOLD_NO_GOOD_VAULT_MAGIC = b"O1-NOGOOD-VAULT-V1\0"
THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES = (
    len(THRESHOLD_NO_GOOD_VAULT_MAGIC) + 5 * 32 + 8 + 4
)
THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING = (
    "u32le-length;signed-i32le-dimacs-literals;strict-ascending-absolute-variable"
)
THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE = (
    "cnf-sha256,potential-sha256,grouping-sha256,observed-variables-sha256,"
    "bound-rule-sha256,threshold-f64le-exact"
)
THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE = (
    "valid-for-identical-CNF-and-score-potential-at-threshold;not-CNF-entailed"
)
THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING = (
    "u8-source(1=trail-upper-bound,2=complete-model-score);f64le-witness;"
    "canonical-clause"
)

_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1
_UINT32_MAX = (1 << 32) - 1


class ThresholdNoGoodVaultError(ValueError):
    """A vault identity, clause, encoding, or cap contract differs."""


class ThresholdNoGoodVaultOverflow(ThresholdNoGoodVaultError):
    """An atomic append would exceed one deterministic vault dimension."""

    def __init__(
        self,
        dimension: str,
        *,
        limit: int,
        current_serialized_bytes: int,
        proposed_serialized_bytes: int,
        current_clauses: int,
        proposed_clauses: int,
        current_literals: int,
        proposed_literals: int,
    ) -> None:
        current_by_dimension = {
            "serialized_bytes": current_serialized_bytes,
            "clauses": current_clauses,
            "literals": current_literals,
        }
        proposed_by_dimension = {
            "serialized_bytes": proposed_serialized_bytes,
            "clauses": proposed_clauses,
            "literals": proposed_literals,
        }
        if dimension not in current_by_dimension:
            raise ThresholdNoGoodVaultError("vault overflow dimension differs")
        self.dimension = dimension
        self.limit = limit
        self.current = current_by_dimension[dimension]
        self.proposed = proposed_by_dimension[dimension]
        self.current_serialized_bytes = current_serialized_bytes
        self.proposed_serialized_bytes = proposed_serialized_bytes
        self.current_clauses = current_clauses
        self.proposed_clauses = proposed_clauses
        self.current_literals = current_literals
        self.proposed_literals = proposed_literals
        super().__init__(
            f"threshold-no-good vault {dimension} cap exceeded "
            f"({self.current} -> {self.proposed} > {limit})"
        )

    def describe(self) -> dict[str, int | str]:
        return {
            "dimension": self.dimension,
            "limit": self.limit,
            "current": self.current,
            "proposed": self.proposed,
            "current_serialized_bytes": self.current_serialized_bytes,
            "proposed_serialized_bytes": self.proposed_serialized_bytes,
            "current_clauses": self.current_clauses,
            "proposed_clauses": self.proposed_clauses,
            "current_literals": self.current_literals,
            "proposed_literals": self.proposed_literals,
        }


def _nonnegative_cap(value: object, field_name: str, *, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ThresholdNoGoodVaultError(f"vault cap {field_name} differs")
    return value


@dataclass(frozen=True)
class VaultCaps:
    maximum_serialized_bytes: int
    maximum_clauses: int
    maximum_literals: int

    def __post_init__(self) -> None:
        _nonnegative_cap(
            self.maximum_serialized_bytes,
            "maximum_serialized_bytes",
            maximum=_UINT32_MAX,
        )
        _nonnegative_cap(self.maximum_clauses, "maximum_clauses", maximum=_UINT32_MAX)
        _nonnegative_cap(self.maximum_literals, "maximum_literals", maximum=_UINT32_MAX)

    def describe(self) -> dict[str, int]:
        return {
            "maximum_serialized_bytes": self.maximum_serialized_bytes,
            "maximum_clauses": self.maximum_clauses,
            "maximum_literals": self.maximum_literals,
        }


O1C66_VAULT_CAPS = VaultCaps(
    maximum_serialized_bytes=8_388_608,
    maximum_clauses=512,
    maximum_literals=1_600_000,
)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _threshold_bits(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


@dataclass(frozen=True)
class ThresholdNoGoodVaultIdentity:
    cnf_sha256: str
    potential_sha256: str
    grouping_sha256: str
    observed_variables_sha256: str
    bound_rule_sha256: str
    threshold: float = field(compare=False)
    threshold_f64le_bits: int = field(init=False)

    def __post_init__(self) -> None:
        if not all(
            _is_sha256(value)
            for value in (
                self.cnf_sha256,
                self.potential_sha256,
                self.grouping_sha256,
                self.observed_variables_sha256,
                self.bound_rule_sha256,
            )
        ):
            raise ThresholdNoGoodVaultError("vault identity digest differs")
        if (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, (int, float))
            or not math.isfinite(self.threshold)
        ):
            raise ThresholdNoGoodVaultError("vault identity threshold differs")
        normalized = float(self.threshold)
        object.__setattr__(self, "threshold", normalized)
        object.__setattr__(self, "threshold_f64le_bits", _threshold_bits(normalized))

    @property
    def threshold_f64le_hex(self) -> str:
        return struct.pack("<Q", self.threshold_f64le_bits).hex()

    def describe(self) -> dict[str, object]:
        return {
            "cnf_sha256": self.cnf_sha256,
            "potential_sha256": self.potential_sha256,
            "grouping_sha256": self.grouping_sha256,
            "observed_variables_sha256": self.observed_variables_sha256,
            "bound_rule_sha256": self.bound_rule_sha256,
            "threshold": self.threshold,
            "threshold_f64le_hex": self.threshold_f64le_hex,
        }


@dataclass(frozen=True, order=True)
class ThresholdNoGoodClause:
    literals: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.literals, tuple) or not self.literals:
            raise ThresholdNoGoodVaultError("vault clause is empty")
        previous = 0
        for literal in self.literals:
            if (
                isinstance(literal, bool)
                or not isinstance(literal, int)
                or literal in (0, _INT32_MIN)
                or not _INT32_MIN < literal <= _INT32_MAX
                or abs(literal) <= previous
            ):
                raise ThresholdNoGoodVaultError("vault clause literals differ")
            previous = abs(literal)
        if len(self.literals) > _UINT32_MAX:
            raise ThresholdNoGoodVaultError("vault clause length differs")

    @property
    def literal_count(self) -> int:
        return len(self.literals)

    @property
    def serialized(self) -> bytes:
        payload = bytearray(struct.pack("<I", len(self.literals)))
        for literal in self.literals:
            payload.extend(struct.pack("<i", literal))
        return bytes(payload)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.serialized).hexdigest()


def observed_variables_bytes(observed_variables: tuple[int, ...]) -> bytes:
    if (
        not isinstance(observed_variables, tuple)
        or tuple(sorted(set(observed_variables))) != observed_variables
        or any(
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= _INT32_MAX
            for variable in observed_variables
        )
    ):
        raise ThresholdNoGoodVaultError("vault observed variables differ")
    return b"".join(struct.pack("<I", variable) for variable in observed_variables)


def observed_variables_sha256(observed_variables: tuple[int, ...]) -> str:
    return hashlib.sha256(observed_variables_bytes(observed_variables)).hexdigest()


def bound_rule_sha256(bound_rule: str) -> str:
    if not isinstance(bound_rule, str) or not bound_rule:
        raise ThresholdNoGoodVaultError("vault bound rule differs")
    try:
        payload = bound_rule.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ThresholdNoGoodVaultError("vault bound rule differs") from exc
    return hashlib.sha256(payload).hexdigest()


def _serialize_components(
    identity: ThresholdNoGoodVaultIdentity,
    clauses: tuple[ThresholdNoGoodClause, ...],
) -> bytes:
    payload = bytearray(THRESHOLD_NO_GOOD_VAULT_MAGIC)
    for digest in (
        identity.cnf_sha256,
        identity.potential_sha256,
        identity.grouping_sha256,
        identity.observed_variables_sha256,
        identity.bound_rule_sha256,
    ):
        payload.extend(bytes.fromhex(digest))
    payload.extend(struct.pack("<Q", identity.threshold_f64le_bits))
    payload.extend(struct.pack("<I", len(clauses)))
    for clause in clauses:
        payload.extend(clause.serialized)
    return bytes(payload)


@dataclass(frozen=True)
class ThresholdNoGoodVault:
    identity: ThresholdNoGoodVaultIdentity
    observed_variables: tuple[int, ...]
    clauses: tuple[ThresholdNoGoodClause, ...] = ()
    serialized: bytes = field(init=False, repr=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ThresholdNoGoodVaultIdentity):
            raise ThresholdNoGoodVaultError("vault identity differs")
        observed_digest = observed_variables_sha256(self.observed_variables)
        if observed_digest != self.identity.observed_variables_sha256:
            raise ThresholdNoGoodVaultError("vault observed identity differs")
        if not isinstance(self.clauses, tuple) or any(
            not isinstance(clause, ThresholdNoGoodClause) for clause in self.clauses
        ):
            raise ThresholdNoGoodVaultError("vault clauses differ")
        if len(self.clauses) > _UINT32_MAX:
            raise ThresholdNoGoodVaultError("vault clause count differs")
        if len(set(self.clauses)) != len(self.clauses):
            raise ThresholdNoGoodVaultError("vault duplicate clause differs")
        observed = set(self.observed_variables)
        if any(
            abs(literal) not in observed
            for clause in self.clauses
            for literal in clause.literals
        ):
            raise ThresholdNoGoodVaultError("vault clause is not observed")
        serialized = _serialize_components(self.identity, self.clauses)
        object.__setattr__(self, "serialized", serialized)
        object.__setattr__(self, "sha256", hashlib.sha256(serialized).hexdigest())

    @property
    def clause_count(self) -> int:
        return len(self.clauses)

    @property
    def literal_count(self) -> int:
        return sum(clause.literal_count for clause in self.clauses)

    @property
    def serialized_bytes(self) -> int:
        return len(self.serialized)

    @property
    def clause_aggregate_sha256(self) -> str:
        return hashlib.sha256(
            b"".join(clause.serialized for clause in self.clauses)
        ).hexdigest()

    def describe(self) -> dict[str, object]:
        return {
            "schema": THRESHOLD_NO_GOOD_VAULT_SCHEMA,
            **self.identity.describe(),
            "sha256": self.sha256,
            "serialized_bytes": self.serialized_bytes,
            "clause_count": self.clause_count,
            "literal_count": self.literal_count,
            "clause_aggregate_sha256": self.clause_aggregate_sha256,
        }


@dataclass(frozen=True)
class ThresholdNoGoodVaultAppendResult:
    vault: ThresholdNoGoodVault
    appended_clauses: tuple[ThresholdNoGoodClause, ...]
    duplicate_clause_count: int
    duplicate_literal_count: int

    @property
    def appended_clause_count(self) -> int:
        return len(self.appended_clauses)

    @property
    def appended_literal_count(self) -> int:
        return sum(clause.literal_count for clause in self.appended_clauses)


def _vault_counts(
    vault: ThresholdNoGoodVault,
) -> tuple[int, int, int]:
    return vault.serialized_bytes, vault.clause_count, vault.literal_count


def _raise_first_overflow(
    *,
    caps: VaultCaps,
    current: tuple[int, int, int],
    proposed: tuple[int, int, int],
) -> None:
    dimensions = (
        ("serialized_bytes", caps.maximum_serialized_bytes, 0),
        ("clauses", caps.maximum_clauses, 1),
        ("literals", caps.maximum_literals, 2),
    )
    for dimension, limit, index in dimensions:
        if proposed[index] > limit:
            raise ThresholdNoGoodVaultOverflow(
                dimension,
                limit=limit,
                current_serialized_bytes=current[0],
                proposed_serialized_bytes=proposed[0],
                current_clauses=current[1],
                proposed_clauses=proposed[1],
                current_literals=current[2],
                proposed_literals=proposed[2],
            )


def validate_threshold_no_good_vault_caps(
    vault: ThresholdNoGoodVault, *, caps: VaultCaps
) -> ThresholdNoGoodVault:
    if not isinstance(vault, ThresholdNoGoodVault) or not isinstance(caps, VaultCaps):
        raise ThresholdNoGoodVaultError("vault cap input differs")
    counts = _vault_counts(vault)
    _raise_first_overflow(caps=caps, current=counts, proposed=counts)
    return vault


def validate_threshold_no_good_vault_identity(
    vault: ThresholdNoGoodVault, *, expected: ThresholdNoGoodVaultIdentity
) -> ThresholdNoGoodVault:
    if (
        not isinstance(vault, ThresholdNoGoodVault)
        or not isinstance(expected, ThresholdNoGoodVaultIdentity)
        or vault.identity != expected
    ):
        raise ThresholdNoGoodVaultError("vault identity contract differs")
    return vault


def empty_threshold_no_good_vault(
    *,
    identity: ThresholdNoGoodVaultIdentity,
    observed_variables: tuple[int, ...],
    caps: VaultCaps,
) -> ThresholdNoGoodVault:
    vault = ThresholdNoGoodVault(identity, observed_variables, ())
    return validate_threshold_no_good_vault_caps(vault, caps=caps)


def serialize_threshold_no_good_vault(
    vault: ThresholdNoGoodVault, *, caps: VaultCaps
) -> bytes:
    return validate_threshold_no_good_vault_caps(vault, caps=caps).serialized


def _read_u32(payload: bytes, cursor: int, field_name: str) -> tuple[int, int]:
    if cursor > len(payload) or len(payload) - cursor < 4:
        raise ThresholdNoGoodVaultError(f"vault {field_name} is truncated")
    return struct.unpack_from("<I", payload, cursor)[0], cursor + 4


def parse_threshold_no_good_vault(
    payload: bytes,
    *,
    observed_variables: tuple[int, ...],
    caps: VaultCaps,
) -> ThresholdNoGoodVault:
    if not isinstance(payload, bytes) or not isinstance(caps, VaultCaps):
        raise ThresholdNoGoodVaultError("vault payload input differs")
    empty_counts = (THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES, 0, 0)
    if len(payload) > caps.maximum_serialized_bytes:
        _raise_first_overflow(
            caps=caps,
            current=empty_counts,
            proposed=(len(payload), 0, 0),
        )
    if len(payload) < THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES:
        raise ThresholdNoGoodVaultError("vault payload is truncated")
    cursor = 0
    if payload[: len(THRESHOLD_NO_GOOD_VAULT_MAGIC)] != THRESHOLD_NO_GOOD_VAULT_MAGIC:
        raise ThresholdNoGoodVaultError("vault magic differs")
    cursor += len(THRESHOLD_NO_GOOD_VAULT_MAGIC)
    digests: list[str] = []
    for _ in range(5):
        digests.append(payload[cursor : cursor + 32].hex())
        cursor += 32
    threshold_bits = struct.unpack_from("<Q", payload, cursor)[0]
    threshold = struct.unpack("<d", struct.pack("<Q", threshold_bits))[0]
    cursor += 8
    clause_count, cursor = _read_u32(payload, cursor, "clause count")
    if clause_count > caps.maximum_clauses:
        _raise_first_overflow(
            caps=caps,
            current=empty_counts,
            proposed=(len(payload), clause_count, 0),
        )
    clauses: list[ThresholdNoGoodClause] = []
    literal_count = 0
    for _ in range(clause_count):
        length, cursor = _read_u32(payload, cursor, "clause length")
        if not length:
            raise ThresholdNoGoodVaultError("vault clause is empty")
        if cursor > len(payload) or length > (len(payload) - cursor) // 4:
            raise ThresholdNoGoodVaultError("vault clause is truncated")
        proposed_literals = literal_count + length
        if proposed_literals > caps.maximum_literals:
            _raise_first_overflow(
                caps=caps,
                current=(len(payload), len(clauses), literal_count),
                proposed=(len(payload), clause_count, proposed_literals),
            )
        literals = struct.unpack_from(f"<{length}i", payload, cursor)
        cursor += 4 * length
        clauses.append(ThresholdNoGoodClause(tuple(literals)))
        literal_count = proposed_literals
    if cursor != len(payload):
        raise ThresholdNoGoodVaultError("vault payload has trailing bytes")
    identity = ThresholdNoGoodVaultIdentity(
        cnf_sha256=digests[0],
        potential_sha256=digests[1],
        grouping_sha256=digests[2],
        observed_variables_sha256=digests[3],
        bound_rule_sha256=digests[4],
        threshold=threshold,
    )
    if identity.threshold_f64le_bits != threshold_bits:
        raise ThresholdNoGoodVaultError("vault threshold bits differ")
    vault = ThresholdNoGoodVault(identity, observed_variables, tuple(clauses))
    if vault.serialized != payload:
        raise ThresholdNoGoodVaultError("vault canonical encoding differs")
    return validate_threshold_no_good_vault_caps(vault, caps=caps)


def _normalize_clause(
    value: ThresholdNoGoodClause | tuple[int, ...],
) -> ThresholdNoGoodClause:
    if isinstance(value, ThresholdNoGoodClause):
        return value
    if isinstance(value, tuple):
        return ThresholdNoGoodClause(value)
    raise ThresholdNoGoodVaultError("vault append clause differs")


def append_new_deduplicated(
    vault: ThresholdNoGoodVault,
    clauses: Iterable[ThresholdNoGoodClause | tuple[int, ...]],
    *,
    caps: VaultCaps,
) -> ThresholdNoGoodVaultAppendResult:
    if not isinstance(vault, ThresholdNoGoodVault) or not isinstance(caps, VaultCaps):
        raise ThresholdNoGoodVaultError("vault append input differs")
    validate_threshold_no_good_vault_caps(vault, caps=caps)
    try:
        iterator = iter(clauses)
    except TypeError as exc:
        raise ThresholdNoGoodVaultError("vault append clauses differ") from exc
    seen = set(vault.clauses)
    observed = set(vault.observed_variables)
    appended: list[ThresholdNoGoodClause] = []
    duplicate_clause_count = 0
    duplicate_literal_count = 0
    current = _vault_counts(vault)
    proposed = current
    for value in iterator:
        clause = _normalize_clause(value)
        if any(abs(literal) not in observed for literal in clause.literals):
            raise ThresholdNoGoodVaultError("vault append clause is not observed")
        if clause in seen:
            duplicate_clause_count += 1
            duplicate_literal_count += clause.literal_count
            continue
        proposed = (
            proposed[0] + 4 + 4 * clause.literal_count,
            proposed[1] + 1,
            proposed[2] + clause.literal_count,
        )
        _raise_first_overflow(caps=caps, current=current, proposed=proposed)
        seen.add(clause)
        appended.append(clause)
    proposed_vault = ThresholdNoGoodVault(
        vault.identity,
        vault.observed_variables,
        vault.clauses + tuple(appended),
    )
    return ThresholdNoGoodVaultAppendResult(
        vault=proposed_vault,
        appended_clauses=tuple(appended),
        duplicate_clause_count=duplicate_clause_count,
        duplicate_literal_count=duplicate_literal_count,
    )


def read_threshold_no_good_vault(
    path: str | Path,
    *,
    observed_variables: tuple[int, ...],
    caps: VaultCaps,
) -> ThresholdNoGoodVault:
    if not isinstance(caps, VaultCaps):
        raise ThresholdNoGoodVaultError("vault cap input differs")
    try:
        with Path(path).open("rb") as handle:
            payload = handle.read(caps.maximum_serialized_bytes + 1)
    except (OSError, TypeError, ValueError) as exc:
        raise ThresholdNoGoodVaultError("vault read failed") from exc
    if len(payload) > caps.maximum_serialized_bytes:
        _raise_first_overflow(
            caps=caps,
            current=(THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES, 0, 0),
            proposed=(len(payload), 0, 0),
        )
    return parse_threshold_no_good_vault(
        payload, observed_variables=observed_variables, caps=caps
    )


def write_threshold_no_good_vault(
    path: str | Path,
    vault: ThresholdNoGoodVault,
    *,
    caps: VaultCaps,
) -> str:
    payload = serialize_threshold_no_good_vault(vault, caps=caps)
    temporary_path: Path | None = None
    try:
        destination = Path(path)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    except (OSError, TypeError, ValueError) as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
        raise ThresholdNoGoodVaultError("vault write failed") from exc
    return vault.sha256


def vault_identity_from_sources(
    *,
    cnf_sha256: str,
    potential_sha256: str,
    grouping_sha256: str,
    observed_variables: tuple[int, ...],
    bound_rule: str,
    threshold: float,
) -> ThresholdNoGoodVaultIdentity:
    return ThresholdNoGoodVaultIdentity(
        cnf_sha256=cnf_sha256,
        potential_sha256=potential_sha256,
        grouping_sha256=grouping_sha256,
        observed_variables_sha256=observed_variables_sha256(observed_variables),
        bound_rule_sha256=bound_rule_sha256(bound_rule),
        threshold=threshold,
    )


def vault_clause_from_partial_assignment(
    assignments: Mapping[int, int],
) -> ThresholdNoGoodClause:
    if not isinstance(assignments, Mapping) or not assignments:
        raise ThresholdNoGoodVaultError("vault partial assignment differs")
    literals: list[int] = []
    for variable, spin in sorted(assignments.items()):
        if (
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= _INT32_MAX
            or isinstance(spin, bool)
            or not isinstance(spin, int)
            or spin not in (-1, 1)
        ):
            raise ThresholdNoGoodVaultError("vault partial assignment differs")
        literals.append(-variable if spin > 0 else variable)
    return ThresholdNoGoodClause(tuple(literals))


def partial_assignment_from_vault_clause(
    clause: ThresholdNoGoodClause,
) -> dict[int, int]:
    if not isinstance(clause, ThresholdNoGoodClause):
        raise ThresholdNoGoodVaultError("vault clause assignment differs")
    return {abs(literal): (1 if literal < 0 else -1) for literal in clause.literals}


__all__ = [
    "O1C66_VAULT_CAPS",
    "THRESHOLD_NO_GOOD_VAULT_CLAUSE_ENCODING",
    "THRESHOLD_NO_GOOD_VAULT_HEADER_BYTES",
    "THRESHOLD_NO_GOOD_VAULT_IDENTITY_RULE",
    "THRESHOLD_NO_GOOD_VAULT_MAGIC",
    "THRESHOLD_NO_GOOD_VAULT_SCHEMA",
    "THRESHOLD_NO_GOOD_VAULT_SEMANTIC_RULE",
    "THRESHOLD_NO_GOOD_VAULT_WITNESS_ENCODING",
    "ThresholdNoGoodClause",
    "ThresholdNoGoodVault",
    "ThresholdNoGoodVaultAppendResult",
    "ThresholdNoGoodVaultError",
    "ThresholdNoGoodVaultIdentity",
    "ThresholdNoGoodVaultOverflow",
    "VaultCaps",
    "append_new_deduplicated",
    "bound_rule_sha256",
    "empty_threshold_no_good_vault",
    "observed_variables_bytes",
    "observed_variables_sha256",
    "parse_threshold_no_good_vault",
    "partial_assignment_from_vault_clause",
    "read_threshold_no_good_vault",
    "serialize_threshold_no_good_vault",
    "validate_threshold_no_good_vault_caps",
    "validate_threshold_no_good_vault_identity",
    "vault_clause_from_partial_assignment",
    "vault_identity_from_sources",
    "write_threshold_no_good_vault",
]
