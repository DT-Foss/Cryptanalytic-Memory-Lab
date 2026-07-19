"""Independent vault-suffix majority phase-field derivation for O1C70.

The reader uses only canonical clause records.  It does not interpret scores,
witnesses, targets, or candidate keys: for each key variable it counts the two
literal signs in a caller-selected clause slice and emits the majority literal.
Zero denotes an exact tie and therefore leaves CaDiCaL's global phase fallback
in control.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping


VAULT_PHASE_FIELD_SCHEMA = "o1-vault-phase-field-v1"
VAULT_PHASE_FIELD_OPERATOR = "vault-suffix-cut-literal-majority-phase"
VAULT_PHASE_FIELD_VOTE_RULE = (
    "delta=count(+v)-count(-v);+v-if-positive;-v-if-negative;0-if-tie"
)
VAULT_PHASE_FIELD_ENCODING = "256-signed-i32le-phase-literals-variable-ascending"
VAULT_PHASE_EFFECTIVE_BITPACK_ENCODING = (
    "256-bits-lsb-first-variable-ascending;1=positive-phase;ties=fallback-phase-one"
)
VAULT_PHASE_READER_SPEC_SHA256 = (
    "3dba50d3a376c2c025e2edbcc47215f19610547ad5bd6260221c82a1641df075"
)
_VAULT_PHASE_READER_SPEC_BYTES = (
    b"o1-vault-conditioned-key-phase-v1\n"
    b"input-vault-sha256="
    b"371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a\n"
    b"output-vault-sha256="
    b"cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858\n"
    b"population=output-clauses-after-exact-input-clause-prefix\n"
    b"population-clause-count=190\n"
    b"population-literal-count=564667\n"
    b"population-clause-records-sha256="
    b"cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521\n"
    b"key-variables=1..256\n"
    b"delta(v)=count(+v)-count(-v)\n"
    b"phase-literal(v)=+v if delta(v)>0;-v if delta(v)<0;0 if delta(v)=0\n"
    b"orientation=satisfy-majority-cut-literal-and-oppose-majority-excluded-"
    b"witness-spin\n"
    b"field-encoding=256-signed-i32le-phase-literals-in-variable-order;"
    b"zero-means-no-vote\n"
    b"apply=Solver::phase(phase-literal(v)) only when nonzero\n"
    b"effective-default-phase=1\n"
    b"bitpack=effective-true-at-little-endian-bit-(v-1)-of-32-bytes\n"
)

PRODUCTION_VAULT_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PRODUCTION_BASE_VAULT_SHA256 = (
    "371dd8454e46eb6c53549efa53e6412f5798b22a06e6f96c927ab74df2ba687a"
)
PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256 = (
    "cbec487e215b70a22f91b0424f05809a06c0f6cdd5c3fa259bcab0b710e74521"
)
PRODUCTION_FIELD_SHA256 = (
    "5d7fd1cfca56c1ab29f9e1490d28e16d3f5def611dad2f52c4ea4015678605fe"
)
PRODUCTION_EFFECTIVE_BITPACK_HEX = (
    "ec6d45759effd185e9a6c163d47659ea2557df6f22bb9a017361f3f6d20c3955"
)
PRODUCTION_EFFECTIVE_BITPACK_SHA256 = (
    "6381f90ee279a8075d4279ecfec5a3560e910afc12c891cb0bd86dac0ad511ec"
)
PRODUCTION_SOURCE_CLAUSE_COUNT = 202
PRODUCTION_BASE_PREFIX_CLAUSE_COUNT = 12
PRODUCTION_SUFFIX_START_CLAUSE_INDEX = 12
PRODUCTION_SUFFIX_STOP_CLAUSE_INDEX_EXCLUSIVE = 202
PRODUCTION_SUFFIX_CLAUSE_COUNT = 190
PRODUCTION_SUFFIX_LITERAL_COUNT = 564_667
PRODUCTION_KEY_VARIABLE_COUNT = 256
PRODUCTION_POSITIVE_COUNT = 139
PRODUCTION_NEGATIVE_COUNT = 116
PRODUCTION_UNPHASED_COUNT = 1
PRODUCTION_UNPHASED_VARIABLES = (241,)
PRODUCTION_APPLIED_PHASE_CALLS = 255
PRODUCTION_FALLBACK_PHASE = 1

_VAULT_MAGIC = b"O1-NOGOOD-VAULT-V1\0"
_VAULT_DIGEST_COUNT = 5
_VAULT_IDENTITY_PREFIX_BYTES = len(_VAULT_MAGIC) + 32 * _VAULT_DIGEST_COUNT + 8
_VAULT_MINIMUM_BYTES = _VAULT_IDENTITY_PREFIX_BYTES + 4
_MAXIMUM_VAULT_BYTES = 8_388_608
_MAXIMUM_VAULT_CLAUSES = 512
_MAXIMUM_VAULT_LITERALS = 1_600_000
_MAXIMUM_VARIABLE = 1_000_000
_INT32_MIN = -(1 << 31)
_INT32_MAX = (1 << 31) - 1


class VaultPhaseFieldError(ValueError):
    """The vault encoding, requested slice, or sealed phase field differs."""


@dataclass(frozen=True)
class VaultPhaseField:
    """Canonical per-variable sign counts and their phase projection."""

    source_vault_sha256: str
    source_clause_count: int
    base_prefix_clause_count: int
    base_prefix_vault_sha256: str
    suffix_start_clause_index: int
    suffix_stop_clause_index_exclusive: int
    suffix_clause_count: int
    suffix_literal_count: int
    suffix_canonical_records_sha256: str
    key_variable_count: int
    positive_occurrences: tuple[int, ...]
    negative_occurrences: tuple[int, ...]
    delta: tuple[int, ...]
    phase_literals: tuple[int, ...]
    fallback_phase: int
    field_bytes: bytes
    field_sha256: str
    positive_count: int
    negative_count: int
    unphased_count: int
    unphased_variables: tuple[int, ...]
    applied_phase_calls: int
    effective_bitpack: bytes
    effective_bitpack_sha256: str

    def describe(self) -> dict[str, object]:
        """Return the reader-facing, JSON-safe field telemetry."""

        return {
            "source_vault_sha256": self.source_vault_sha256,
            "source_clause_count": self.source_clause_count,
            "base_prefix_clause_count": self.base_prefix_clause_count,
            "base_prefix_vault_sha256": self.base_prefix_vault_sha256,
            "suffix_start_clause_index": self.suffix_start_clause_index,
            "suffix_stop_clause_index_exclusive": (
                self.suffix_stop_clause_index_exclusive
            ),
            "suffix_clause_count": self.suffix_clause_count,
            "suffix_literal_count": self.suffix_literal_count,
            "suffix_canonical_records_sha256": (self.suffix_canonical_records_sha256),
            "key_variable_count": self.key_variable_count,
            "vote_rule": VAULT_PHASE_FIELD_VOTE_RULE,
            "field_encoding": VAULT_PHASE_FIELD_ENCODING,
            "field_bytes": len(self.field_bytes),
            "field_sha256": self.field_sha256,
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
            "unphased_count": self.unphased_count,
            "unphased_variables": list(self.unphased_variables),
            "applied_phase_calls": self.applied_phase_calls,
            "fallback_phase": self.fallback_phase,
            "effective_bitpack_encoding": VAULT_PHASE_EFFECTIVE_BITPACK_ENCODING,
            "effective_bitpack_hex": self.effective_bitpack.hex(),
            "effective_bitpack_sha256": self.effective_bitpack_sha256,
        }


@dataclass(frozen=True)
class _ParsedVault:
    identity_prefix: bytes
    records: tuple[bytes, ...]
    clauses: tuple[tuple[int, ...], ...]


def _read_u32(payload: bytes, cursor: int, field: str) -> tuple[int, int]:
    if cursor < 0 or cursor + 4 > len(payload):
        raise VaultPhaseFieldError(f"vault {field} is truncated")
    return struct.unpack_from("<I", payload, cursor)[0], cursor + 4


def _parse_vault(payload: bytes) -> _ParsedVault:
    if len(payload) > _MAXIMUM_VAULT_BYTES:
        raise VaultPhaseFieldError("vault payload exceeds phase-field cap")
    if len(payload) < _VAULT_MINIMUM_BYTES or not payload.startswith(_VAULT_MAGIC):
        raise VaultPhaseFieldError("vault phase-field header differs")

    cursor = _VAULT_IDENTITY_PREFIX_BYTES
    clause_count, cursor = _read_u32(payload, cursor, "clause count")
    if clause_count > _MAXIMUM_VAULT_CLAUSES:
        raise VaultPhaseFieldError("vault clause count exceeds phase-field cap")

    clauses: list[tuple[int, ...]] = []
    records: list[bytes] = []
    seen: set[bytes] = set()
    literal_count = 0
    for _ in range(clause_count):
        record_start = cursor
        length, cursor = _read_u32(payload, cursor, "clause length")
        if length == 0:
            raise VaultPhaseFieldError("vault phase-field clause is empty")
        if length > _MAXIMUM_VAULT_LITERALS - literal_count:
            raise VaultPhaseFieldError("vault literal count exceeds phase-field cap")
        byte_count = 4 * length
        if cursor + byte_count > len(payload):
            raise VaultPhaseFieldError("vault phase-field clause is truncated")
        literals = struct.unpack_from(f"<{length}i", payload, cursor)
        cursor += byte_count
        previous_absolute = 0
        for literal in literals:
            absolute = abs(literal)
            if (
                literal in (0, _INT32_MIN)
                or absolute <= previous_absolute
                or absolute > _MAXIMUM_VARIABLE
            ):
                raise VaultPhaseFieldError(
                    "vault phase-field clause literal order differs"
                )
            previous_absolute = absolute
        record = payload[record_start:cursor]
        if record in seen:
            raise VaultPhaseFieldError("vault phase-field duplicate clause differs")
        seen.add(record)
        records.append(record)
        clauses.append(literals)
        literal_count += length
    if cursor != len(payload):
        raise VaultPhaseFieldError("vault phase-field trailing bytes differ")
    return _ParsedVault(
        identity_prefix=payload[:_VAULT_IDENTITY_PREFIX_BYTES],
        records=tuple(records),
        clauses=tuple(clauses),
    )


def derive_vault_phase_field(
    payload: bytes,
    *,
    key_variable_count: int = PRODUCTION_KEY_VARIABLE_COUNT,
    clause_start: int = 0,
    clause_stop: int | None = None,
    fallback_phase: int = PRODUCTION_FALLBACK_PHASE,
) -> VaultPhaseField:
    """Derive a generic sign-majority field from a canonical vault slice."""

    if not isinstance(payload, bytes):
        raise VaultPhaseFieldError("vault phase-field payload type differs")
    if (
        isinstance(key_variable_count, bool)
        or not isinstance(key_variable_count, int)
        or not 1 <= key_variable_count <= _INT32_MAX
        or isinstance(clause_start, bool)
        or not isinstance(clause_start, int)
        or clause_start < 0
        or (
            clause_stop is not None
            and (
                isinstance(clause_stop, bool)
                or not isinstance(clause_stop, int)
                or clause_stop < 0
            )
        )
        or isinstance(fallback_phase, bool)
        or not isinstance(fallback_phase, int)
        or fallback_phase not in (0, 1)
    ):
        raise VaultPhaseFieldError("vault phase-field derivation arguments differ")

    parsed = _parse_vault(payload)
    source_clause_count = len(parsed.clauses)
    stop = source_clause_count if clause_stop is None else clause_stop
    if clause_start > stop or stop > source_clause_count:
        raise VaultPhaseFieldError("vault phase-field clause slice differs")

    positive = [0] * key_variable_count
    negative = [0] * key_variable_count
    suffix_literal_count = 0
    for clause in parsed.clauses[clause_start:stop]:
        suffix_literal_count += len(clause)
        for literal in clause:
            variable = abs(literal)
            if variable <= key_variable_count:
                counts = positive if literal > 0 else negative
                counts[variable - 1] += 1

    deltas = tuple(left - right for left, right in zip(positive, negative))
    phase_literals = tuple(
        variable if vote > 0 else -variable if vote < 0 else 0
        for variable, vote in enumerate(deltas, start=1)
    )
    field_bytes = struct.pack(f"<{key_variable_count}i", *phase_literals)
    effective = bytearray((key_variable_count + 7) // 8)
    for variable, literal in enumerate(phase_literals, start=1):
        positive_phase = literal > 0 or (literal == 0 and fallback_phase == 1)
        if positive_phase:
            effective[(variable - 1) // 8] |= 1 << ((variable - 1) % 8)

    prefix_payload = (
        parsed.identity_prefix
        + struct.pack("<I", clause_start)
        + b"".join(parsed.records[:clause_start])
    )
    suffix_records = b"".join(parsed.records[clause_start:stop])
    unphased_variables = tuple(
        variable
        for variable, literal in enumerate(phase_literals, start=1)
        if literal == 0
    )
    positive_count = sum(literal > 0 for literal in phase_literals)
    negative_count = sum(literal < 0 for literal in phase_literals)
    return VaultPhaseField(
        source_vault_sha256=hashlib.sha256(payload).hexdigest(),
        source_clause_count=source_clause_count,
        base_prefix_clause_count=clause_start,
        base_prefix_vault_sha256=hashlib.sha256(prefix_payload).hexdigest(),
        suffix_start_clause_index=clause_start,
        suffix_stop_clause_index_exclusive=stop,
        suffix_clause_count=stop - clause_start,
        suffix_literal_count=suffix_literal_count,
        suffix_canonical_records_sha256=hashlib.sha256(suffix_records).hexdigest(),
        key_variable_count=key_variable_count,
        positive_occurrences=tuple(positive),
        negative_occurrences=tuple(negative),
        delta=deltas,
        phase_literals=phase_literals,
        fallback_phase=fallback_phase,
        field_bytes=field_bytes,
        field_sha256=hashlib.sha256(field_bytes).hexdigest(),
        positive_count=positive_count,
        negative_count=negative_count,
        unphased_count=len(unphased_variables),
        unphased_variables=unphased_variables,
        applied_phase_calls=positive_count + negative_count,
        effective_bitpack=bytes(effective),
        effective_bitpack_sha256=hashlib.sha256(effective).hexdigest(),
    )


def validate_production_vault_phase_field(payload: bytes) -> VaultPhaseField:
    """Independently reproduce and validate every sealed O1C70 field binding."""

    field = derive_vault_phase_field(
        payload,
        key_variable_count=PRODUCTION_KEY_VARIABLE_COUNT,
        clause_start=PRODUCTION_SUFFIX_START_CLAUSE_INDEX,
        clause_stop=PRODUCTION_SUFFIX_STOP_CLAUSE_INDEX_EXCLUSIVE,
        fallback_phase=PRODUCTION_FALLBACK_PHASE,
    )
    expected_scalars = (
        (field.source_vault_sha256, PRODUCTION_VAULT_SHA256),
        (field.source_clause_count, PRODUCTION_SOURCE_CLAUSE_COUNT),
        (field.base_prefix_clause_count, PRODUCTION_BASE_PREFIX_CLAUSE_COUNT),
        (field.base_prefix_vault_sha256, PRODUCTION_BASE_VAULT_SHA256),
        (
            field.suffix_start_clause_index,
            PRODUCTION_SUFFIX_START_CLAUSE_INDEX,
        ),
        (
            field.suffix_stop_clause_index_exclusive,
            PRODUCTION_SUFFIX_STOP_CLAUSE_INDEX_EXCLUSIVE,
        ),
        (field.suffix_clause_count, PRODUCTION_SUFFIX_CLAUSE_COUNT),
        (field.suffix_literal_count, PRODUCTION_SUFFIX_LITERAL_COUNT),
        (
            field.suffix_canonical_records_sha256,
            PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256,
        ),
        (field.field_sha256, PRODUCTION_FIELD_SHA256),
        (field.positive_count, PRODUCTION_POSITIVE_COUNT),
        (field.negative_count, PRODUCTION_NEGATIVE_COUNT),
        (field.unphased_count, PRODUCTION_UNPHASED_COUNT),
        (field.unphased_variables, PRODUCTION_UNPHASED_VARIABLES),
        (field.applied_phase_calls, PRODUCTION_APPLIED_PHASE_CALLS),
        (field.effective_bitpack.hex(), PRODUCTION_EFFECTIVE_BITPACK_HEX),
        (
            field.effective_bitpack_sha256,
            PRODUCTION_EFFECTIVE_BITPACK_SHA256,
        ),
    )
    if any(actual != expected for actual, expected in expected_scalars):
        raise VaultPhaseFieldError("sealed O1C70 vault phase field differs")
    return field


def vault_phase_field_reader_spec_bytes() -> bytes:
    """Return the frozen 847-byte ASCII O1C70 reader specification."""

    digest = hashlib.sha256(_VAULT_PHASE_READER_SPEC_BYTES).hexdigest()
    if len(_VAULT_PHASE_READER_SPEC_BYTES) != 847 or digest != (
        VAULT_PHASE_READER_SPEC_SHA256
    ):
        raise VaultPhaseFieldError("frozen O1C70 reader specification differs")
    return _VAULT_PHASE_READER_SPEC_BYTES


PRODUCTION_VAULT_PHASE_READER: Final[Mapping[str, object]] = MappingProxyType(
    {
        "schema": "o1-256-cadical-vault-phase-field-reader-v1",
        "operator": VAULT_PHASE_FIELD_OPERATOR,
        "cadical_configuration": "plain",
        "phase_before_override": 1,
        "phase": 1,
        "forcephase": True,
        "rephase": 0,
        "lucky": False,
        "walk": False,
        "seed": 0,
        "quiet": 1,
        "factor": 0,
        "source_vault_sha256": PRODUCTION_VAULT_SHA256,
        "source_clause_count": PRODUCTION_SOURCE_CLAUSE_COUNT,
        "base_prefix_clause_count": PRODUCTION_BASE_PREFIX_CLAUSE_COUNT,
        "base_prefix_vault_sha256": PRODUCTION_BASE_VAULT_SHA256,
        "suffix_start_clause_index": PRODUCTION_SUFFIX_START_CLAUSE_INDEX,
        "suffix_stop_clause_index_exclusive": (
            PRODUCTION_SUFFIX_STOP_CLAUSE_INDEX_EXCLUSIVE
        ),
        "suffix_clause_count": PRODUCTION_SUFFIX_CLAUSE_COUNT,
        "suffix_literal_count": PRODUCTION_SUFFIX_LITERAL_COUNT,
        "suffix_canonical_records_sha256": (PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256),
        "key_variable_count": PRODUCTION_KEY_VARIABLE_COUNT,
        "vote_rule": VAULT_PHASE_FIELD_VOTE_RULE,
        "field_encoding": VAULT_PHASE_FIELD_ENCODING,
        "field_bytes": 4 * PRODUCTION_KEY_VARIABLE_COUNT,
        "field_sha256": PRODUCTION_FIELD_SHA256,
        "positive_count": PRODUCTION_POSITIVE_COUNT,
        "negative_count": PRODUCTION_NEGATIVE_COUNT,
        "unphased_count": PRODUCTION_UNPHASED_COUNT,
        "unphased_variables": PRODUCTION_UNPHASED_VARIABLES,
        "applied_phase_calls": PRODUCTION_APPLIED_PHASE_CALLS,
        "fallback_phase": PRODUCTION_FALLBACK_PHASE,
        "effective_bitpack_encoding": VAULT_PHASE_EFFECTIVE_BITPACK_ENCODING,
        "effective_bitpack_hex": PRODUCTION_EFFECTIVE_BITPACK_HEX,
        "effective_bitpack_sha256": PRODUCTION_EFFECTIVE_BITPACK_SHA256,
        "reader_spec_sha256": VAULT_PHASE_READER_SPEC_SHA256,
    }
)


__all__ = [
    "PRODUCTION_APPLIED_PHASE_CALLS",
    "PRODUCTION_BASE_PREFIX_CLAUSE_COUNT",
    "PRODUCTION_BASE_VAULT_SHA256",
    "PRODUCTION_EFFECTIVE_BITPACK_HEX",
    "PRODUCTION_EFFECTIVE_BITPACK_SHA256",
    "PRODUCTION_FALLBACK_PHASE",
    "PRODUCTION_FIELD_SHA256",
    "PRODUCTION_KEY_VARIABLE_COUNT",
    "PRODUCTION_NEGATIVE_COUNT",
    "PRODUCTION_POSITIVE_COUNT",
    "PRODUCTION_SOURCE_CLAUSE_COUNT",
    "PRODUCTION_SUFFIX_CANONICAL_RECORDS_SHA256",
    "PRODUCTION_SUFFIX_CLAUSE_COUNT",
    "PRODUCTION_SUFFIX_LITERAL_COUNT",
    "PRODUCTION_SUFFIX_START_CLAUSE_INDEX",
    "PRODUCTION_SUFFIX_STOP_CLAUSE_INDEX_EXCLUSIVE",
    "PRODUCTION_UNPHASED_COUNT",
    "PRODUCTION_UNPHASED_VARIABLES",
    "PRODUCTION_VAULT_SHA256",
    "PRODUCTION_VAULT_PHASE_READER",
    "VAULT_PHASE_EFFECTIVE_BITPACK_ENCODING",
    "VAULT_PHASE_FIELD_ENCODING",
    "VAULT_PHASE_FIELD_OPERATOR",
    "VAULT_PHASE_FIELD_SCHEMA",
    "VAULT_PHASE_FIELD_VOTE_RULE",
    "VAULT_PHASE_READER_SPEC_SHA256",
    "VaultPhaseField",
    "VaultPhaseFieldError",
    "derive_vault_phase_field",
    "validate_production_vault_phase_field",
    "vault_phase_field_reader_spec_bytes",
]
