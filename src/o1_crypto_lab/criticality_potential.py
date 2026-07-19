"""Compile the frozen parent-criticality reader into local factor potentials."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np

from .proof_parent_criticality import (
    FEATURE_NAMES,
    ROLE_LABELS,
    ParentCriticalityField,
)


POTENTIAL_SCHEMA = "O1CRIT-POT-V1"
MAXIMUM_FACTOR_VARIABLES = 8
# This matches both native potential readers.  Parent-criticality extraction is
# still deliberately confined to the 32,128-variable one-block proof schema;
# only the compiled potential coordinate space is wider for multiblock remaps.
POTENTIAL_VARIABLE_LIMIT = 1_000_000


class CriticalityPotentialError(ValueError):
    """A frozen reader, local truth table, or assignment differs."""


@dataclass(frozen=True, order=True)
class CriticalityPotentialFactor:
    variables: tuple[int, ...]
    energies: tuple[float, ...]

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.variables) <= MAXIMUM_FACTOR_VARIABLES
            or tuple(sorted(set(self.variables))) != self.variables
            or any(
                not 1 <= variable <= POTENTIAL_VARIABLE_LIMIT
                for variable in self.variables
            )
            or len(self.energies) != 1 << len(self.variables)
            or any(not math.isfinite(energy) for energy in self.energies)
        ):
            raise CriticalityPotentialError("criticality potential factor differs")


@dataclass(frozen=True)
class CriticalityPotentialField:
    offset: float
    source_sha256: str
    factors: tuple[CriticalityPotentialFactor, ...]

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.offset)
            or len(self.source_sha256) != 64
            or not self.factors
            or tuple(sorted(self.factors)) != self.factors
            or len({factor.variables for factor in self.factors}) != len(self.factors)
        ):
            raise CriticalityPotentialError("criticality potential field differs")

    @property
    def observed_variables(self) -> tuple[int, ...]:
        return tuple(
            sorted(
                {
                    variable
                    for factor in self.factors
                    for variable in factor.variables
                }
            )
        )

    def to_bytes(self) -> bytes:
        rows = [
            f"{POTENTIAL_SCHEMA} {len(self.factors)} "
            f"{self.offset:.17g} {self.source_sha256}\n"
        ]
        for factor in self.factors:
            variables = " ".join(str(variable) for variable in factor.variables)
            energies = " ".join(f"{energy:.17g}" for energy in factor.energies)
            rows.append(f"{len(factor.variables)} {variables} {energies}\n")
        return "".join(rows).encode("ascii")

    @classmethod
    def from_bytes(cls, payload: bytes) -> CriticalityPotentialField:
        if not isinstance(payload, bytes):
            raise CriticalityPotentialError("potential payload differs")
        try:
            rows = payload.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise CriticalityPotentialError("potential payload is not ASCII") from exc
        if not rows:
            raise CriticalityPotentialError("potential payload is empty")
        header = rows[0].split()
        if len(header) != 4 or header[0] != POTENTIAL_SCHEMA:
            raise CriticalityPotentialError("potential header differs")
        try:
            count = int(header[1])
            offset = float(header[2])
        except ValueError as exc:
            raise CriticalityPotentialError("potential header encoding differs") from exc
        source = header[3]
        if count < 1 or len(rows) != count + 1:
            raise CriticalityPotentialError("potential factor count differs")
        factors: list[CriticalityPotentialFactor] = []
        for row in rows[1:]:
            fields = row.split()
            try:
                width = int(fields[0])
            except (IndexError, ValueError) as exc:
                raise CriticalityPotentialError("potential factor width differs") from exc
            expected = 1 + width + (1 << width)
            if not 1 <= width <= MAXIMUM_FACTOR_VARIABLES or len(fields) != expected:
                raise CriticalityPotentialError("potential factor row differs")
            try:
                variables = tuple(int(value) for value in fields[1 : 1 + width])
                energies = tuple(float(value) for value in fields[1 + width :])
            except ValueError as exc:
                raise CriticalityPotentialError("potential factor encoding differs") from exc
            factors.append(CriticalityPotentialFactor(variables, energies))
        return cls(offset, source, tuple(factors))

    @property
    def state_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def describe(self) -> dict[str, object]:
        widths = [len(factor.variables) for factor in self.factors]
        return {
            "schema": "o1-256-criticality-potential-field-v1",
            "offset": self.offset,
            "source_sha256": self.source_sha256,
            "state_sha256": self.state_sha256,
            "serialized_bytes": len(self.to_bytes()),
            "factor_count": len(self.factors),
            "observed_variable_count": len(self.observed_variables),
            "minimum_factor_variables": min(widths),
            "maximum_factor_variables": max(widths),
            "truth_table_entries": sum(len(factor.energies) for factor in self.factors),
        }


def _reader_arrays(
    feature_mean: Sequence[float] | np.ndarray,
    feature_std: Sequence[float] | np.ndarray,
    reader: Sequence[float] | np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    arrays = tuple(
        np.asarray(value, dtype=np.float64)
        for value in (feature_mean, feature_std, reader)
    )
    if any(
        array.shape != (len(FEATURE_NAMES),)
        or not bool(np.all(np.isfinite(array)))
        for array in arrays
    ) or bool(np.any(arrays[1] < 0.0)):
        raise CriticalityPotentialError("criticality reader arrays differ")
    return arrays


def _canonical_field(
    tables: Mapping[tuple[int, ...], np.ndarray],
    *,
    offset: float,
    source_sha256: str,
) -> CriticalityPotentialField:
    normalized_offset = float(offset)
    factors: list[CriticalityPotentialFactor] = []
    for variables, raw in sorted(tables.items()):
        energies = np.asarray(raw, dtype=np.float64)
        if energies.shape != (1 << len(variables),) or not bool(
            np.all(np.isfinite(energies))
        ):
            raise CriticalityPotentialError("compiled potential table differs")
        constant = float(energies[0])
        centered = energies - constant
        normalized_offset += constant
        if bool(np.any(centered != 0.0)):
            factors.append(
                CriticalityPotentialFactor(
                    variables, tuple(float(value) for value in centered)
                )
            )
    if not factors:
        raise CriticalityPotentialError("compiled potential field is constant")
    return CriticalityPotentialField(
        normalized_offset, source_sha256, tuple(factors)
    )


def compile_criticality_potential(
    field: ParentCriticalityField,
    *,
    feature_mean: Sequence[float] | np.ndarray,
    feature_std: Sequence[float] | np.ndarray,
    reader: Sequence[float] | np.ndarray,
) -> CriticalityPotentialField:
    """Expand one frozen standardized reader into exact local truth tables."""

    mean, std, weights = _reader_arrays(feature_mean, feature_std, reader)
    active = std > 0.0
    coefficients = np.zeros_like(weights)
    coefficients[active] = weights[active] / std[active]
    offset = -float(np.sum(weights[active] * mean[active] / std[active]))
    normalizers = np.zeros(len(ROLE_LABELS), dtype=np.float64)
    for factor in field.factors:
        role = min(factor.parent_role, len(ROLE_LABELS) - 1)
        normalizers[role] += abs(factor.score_units)
    tables: dict[tuple[int, ...], np.ndarray] = {}
    for factor in field.factors:
        role = min(factor.parent_role, len(ROLE_LABELS) - 1)
        normalizer = float(normalizers[role])
        if normalizer <= 0.0:
            raise CriticalityPotentialError("criticality role has zero normalizer")
        channel = 3 * role
        local = coefficients[channel : channel + 3]
        if not bool(np.any(local)):
            continue
        variables = tuple(
            sorted(
                {factor.key_variable, *(abs(literal) for literal in factor.clause)}
            )
        )
        if len(variables) > MAXIMUM_FACTOR_VARIABLES:
            raise CriticalityPotentialError("criticality factor table is too wide")
        positions = {variable: index for index, variable in enumerate(variables)}
        energies = np.empty(1 << len(variables), dtype=np.float64)
        for mask in range(energies.size):
            key_spin = 1 if mask & (1 << positions[factor.key_variable]) else -1
            true_literals = [
                literal
                for literal in factor.clause
                if (1 if mask & (1 << positions[abs(literal)]) else -1)
                == (1 if literal > 0 else -1)
            ]
            critical = len(true_literals) == 1
            signals = np.zeros(3, dtype=np.float64)
            signals[0] = 1.0 if critical else -1.0
            if critical:
                unique = true_literals[0]
                signals[1] = 1.0 if unique == factor.expected_pivot else -1.0
                signals[2] = 1.0 if unique > 0 else -1.0
            energies[mask] = (
                factor.score_units
                * key_spin
                * float(np.dot(local, signals))
                / normalizer
            )
        tables.setdefault(variables, np.zeros_like(energies))
        tables[variables] += energies
    source = hashlib.sha256(
        b"O1-CRITICALITY-POTENTIAL-V1\0"
        + field.to_bytes()
        + np.ascontiguousarray(mean, dtype="<f8").tobytes()
        + np.ascontiguousarray(std, dtype="<f8").tobytes()
        + np.ascontiguousarray(weights, dtype="<f8").tobytes()
    ).hexdigest()
    return _canonical_field(tables, offset=offset, source_sha256=source)


def add_unary_hints(
    field: CriticalityPotentialField,
    hints: Iterable[tuple[int, int, float]],
) -> CriticalityPotentialField:
    """Add reversible unary ceiling hints without changing any base factor."""

    tables = {
        factor.variables: np.asarray(factor.energies, dtype=np.float64).copy()
        for factor in field.factors
    }
    canonical = _canonical_hints(hints)
    for variable, spin, strength in canonical:
        table = tables.setdefault((variable,), np.zeros(2, dtype=np.float64))
        table[0] += strength if spin < 0 else -strength
        table[1] += strength if spin > 0 else -strength
    source = hashlib.sha256(
        field.to_bytes()
        + b"\0unary-criticality-hints\0"
        + _hint_bytes(canonical)
    ).hexdigest()
    return _canonical_field(tables, offset=field.offset, source_sha256=source)


def _canonical_hints(
    hints: Iterable[tuple[int, int, float]],
) -> tuple[tuple[int, int, float], ...]:
    seen: set[int] = set()
    canonical: list[tuple[int, int, float]] = []
    for variable, spin, strength in hints:
        if (
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or not 1 <= variable <= POTENTIAL_VARIABLE_LIMIT
            or spin not in (-1, 1)
            or not math.isfinite(strength)
            or strength <= 0.0
            or variable in seen
        ):
            raise CriticalityPotentialError("unary criticality hint differs")
        seen.add(variable)
        canonical.append((variable, spin, float(strength)))
    if not canonical:
        raise CriticalityPotentialError("unary criticality hints are empty")
    return tuple(sorted(canonical))


def _hint_bytes(hints: Sequence[tuple[int, int, float]]) -> bytes:
    return "".join(
        f"{variable} {spin} {strength:.17g}\n"
        for variable, spin, strength in hints
    ).encode("ascii")


def unary_hint_potential(
    hints: Iterable[tuple[int, int, float]],
) -> CriticalityPotentialField:
    """Build a canonical reversible field containing only unary ceiling hints."""

    canonical = _canonical_hints(hints)
    tables: dict[tuple[int, ...], np.ndarray] = {}
    for variable, spin, strength in canonical:
        tables[(variable,)] = np.asarray(
            (
                strength if spin < 0 else -strength,
                strength if spin > 0 else -strength,
            ),
            dtype=np.float64,
        )
    source = hashlib.sha256(
        b"O1-UNARY-CRITICALITY-POTENTIAL-V1\0" + _hint_bytes(canonical)
    ).hexdigest()
    return _canonical_field(tables, offset=0.0, source_sha256=source)


def score_potential_assignment(
    field: CriticalityPotentialField, assignment: Mapping[int, int]
) -> float:
    terms = [field.offset]
    for factor in field.factors:
        mask = 0
        for index, variable in enumerate(factor.variables):
            spin = assignment.get(variable)
            if spin not in (-1, 1):
                raise CriticalityPotentialError("potential assignment lacks variable")
            if spin > 0:
                mask |= 1 << index
        terms.append(factor.energies[mask])
    return math.fsum(terms)


__all__ = [
    "CriticalityPotentialError",
    "CriticalityPotentialFactor",
    "CriticalityPotentialField",
    "POTENTIAL_SCHEMA",
    "POTENTIAL_VARIABLE_LIMIT",
    "add_unary_hints",
    "compile_criticality_potential",
    "score_potential_assignment",
    "unary_hint_potential",
]
