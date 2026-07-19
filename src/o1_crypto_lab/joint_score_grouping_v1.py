"""Deterministic compatibility-aware grouping for public score potentials.

This module is intentionally independent of every solver and recovery path.  It
turns a :class:`CriticalityPotentialField` into bounded-width joint tables that
can be used for certified partial-assignment upper bounds.

All selection scores are integers on the exact binary64 lattice.  Table cells
and final bounds are rounded once toward positive infinity, including sums that
would overflow or underflow an ordinary intermediate binary64 addition.
"""

from __future__ import annotations

import hashlib
import math
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Mapping

from .criticality_potential import CriticalityPotentialFactor, CriticalityPotentialField


COMPATIBILITY_GROUPING_SCHEMA = "o1-public-potential-compatibility-grouping-v1"
COMPATIBILITY_GROUPING_MAGIC = b"O1-COMPAT-GREEDY-V1\0"
COMPATIBILITY_GROUPING_RULE = (
    "ascending-factor-score-aware-overlap-greedy;maximum-exact-root-gain;"
    "ties-smaller-union-width,larger-group,smaller-minimum-factor-index;"
    "groups-ascending-minimum-factor-index"
)
COMPATIBILITY_GROUPING_BOUND_RULE = (
    "exact-binary64-lattice-factor-sum;round-once-positive-infinity;"
    "partial-group-maximum;exact-binary64-lattice-root-sum;"
    "round-once-positive-infinity"
)
COMPATIBILITY_GROUPING_MEMORY_RULE = (
    "8*table_rows+8*group_count+16*variable_group_incidences;"
    "excludes-immutable-potential,container-headers,allocator-slack"
)
MAXIMUM_COMPATIBILITY_WIDTH = 20

_BINARY64_FRACTION_BITS = 52
_BINARY64_MINIMUM_EXPONENT = -1074
_BINARY64_SCALE_EXPONENT = -_BINARY64_MINIMUM_EXPONENT
_BINARY64_MAXIMUM_SCALED_INTEGER = ((1 << (_BINARY64_FRACTION_BITS + 1)) - 1) << 2045


class JointScoreGroupingError(ValueError):
    """A grouping input, exact table, or structural ledger differs."""


def _binary64_scaled_integer(value: float) -> int:
    """Return the exact integer ``value * 2**1074`` for finite binary64."""

    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    negative = bool(bits >> 63)
    exponent = (bits >> _BINARY64_FRACTION_BITS) & 0x7FF
    fraction = bits & ((1 << _BINARY64_FRACTION_BITS) - 1)
    if exponent == 0:
        magnitude = fraction
    else:
        magnitude = ((1 << _BINARY64_FRACTION_BITS) | fraction) << (exponent - 1)
    return -magnitude if negative else magnitude


def _scaled_integer_to_upward_binary64(value: int) -> float:
    """Round an exact multiple of ``2**-1074`` toward positive infinity."""

    if value > _BINARY64_MAXIMUM_SCALED_INTEGER:
        return math.inf
    if value < -_BINARY64_MAXIMUM_SCALED_INTEGER:
        return -sys.float_info.max
    if value == 0:
        return 0.0

    positive = value > 0
    magnitude = abs(value)
    shift = max(0, magnitude.bit_length() - (_BINARY64_FRACTION_BITS + 1))
    if positive:
        significand, remainder = divmod(magnitude, 1 << shift)
        if remainder:
            significand += 1
        if significand == 1 << (_BINARY64_FRACTION_BITS + 1):
            significand >>= 1
            shift += 1
    else:
        significand = magnitude >> shift

    rounded = math.ldexp(float(significand), shift - _BINARY64_SCALE_EXPONENT)
    return rounded if positive else -rounded


def outward_binary64_sum(values: Iterable[float]) -> float:
    """Return the least binary64 value not below the exact finite-input sum.

    Positive overflow returns ``+inf`` because no finite binary64 upper bound
    exists.  Negative overflow returns ``-sys.float_info.max``, the least finite
    binary64 value that is still above the exact sum.
    """

    total = 0
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise JointScoreGroupingError("outward sum input differs") from exc
    for raw in iterator:
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise JointScoreGroupingError("outward sum value differs")
        try:
            value = float(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise JointScoreGroupingError("outward sum value differs") from exc
        if not math.isfinite(value):
            raise JointScoreGroupingError("outward sum value is not finite")
        total += _binary64_scaled_integer(value)
    return _scaled_integer_to_upward_binary64(total)


@dataclass(frozen=True)
class JointScoreCompatibilityGroup:
    """One exact-factor-sum table in canonical factor and variable order."""

    factor_indices: tuple[int, ...]
    variables: tuple[int, ...]
    energies: tuple[float, ...]

    def __post_init__(self) -> None:
        if (
            not self.factor_indices
            or tuple(sorted(set(self.factor_indices))) != self.factor_indices
            or any(
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 0 <= index <= 0xFFFFFFFF
                for index in self.factor_indices
            )
            or not self.variables
            or tuple(sorted(set(self.variables))) != self.variables
            or len(self.variables) > MAXIMUM_COMPATIBILITY_WIDTH
            or any(
                isinstance(variable, bool)
                or not isinstance(variable, int)
                or not 1 <= variable <= 0xFFFFFFFF
                for variable in self.variables
            )
            or len(self.energies) != 1 << len(self.variables)
            or any(
                math.isnan(energy) or energy == -math.inf for energy in self.energies
            )
        ):
            raise JointScoreGroupingError("compatibility group differs")


def serialize_compatibility_grouping(
    *,
    potential_sha256: str,
    width_cap: int,
    factor_count: int,
    groups: tuple[JointScoreCompatibilityGroup, ...],
) -> bytes:
    """Serialize a grouping's public source identity and structural partition."""

    try:
        potential_digest = bytes.fromhex(potential_sha256)
    except (TypeError, ValueError) as exc:
        raise JointScoreGroupingError("potential digest differs") from exc
    if (
        len(potential_digest) != 32
        or potential_sha256 != potential_sha256.lower()
        or isinstance(width_cap, bool)
        or not isinstance(width_cap, int)
        or not 1 <= width_cap <= MAXIMUM_COMPATIBILITY_WIDTH
        or isinstance(factor_count, bool)
        or not isinstance(factor_count, int)
        or not 1 <= factor_count <= 0xFFFFFFFF
        or not isinstance(groups, tuple)
        or not 1 <= len(groups) <= 0xFFFFFFFF
    ):
        raise JointScoreGroupingError("compatibility grouping serialization differs")

    payload = bytearray(COMPATIBILITY_GROUPING_MAGIC)
    payload.extend(potential_digest)
    payload.extend(struct.pack("<HII", width_cap, factor_count, len(groups)))
    for group in groups:
        if not isinstance(group, JointScoreCompatibilityGroup):
            raise JointScoreGroupingError(
                "compatibility grouping serialization differs"
            )
        payload.extend(struct.pack("<I", len(group.factor_indices)))
        for factor_index in group.factor_indices:
            payload.extend(struct.pack("<I", factor_index))
        payload.extend(struct.pack("<H", len(group.variables)))
        for variable in group.variables:
            payload.extend(struct.pack("<I", variable))
    return bytes(payload)


@dataclass(frozen=True)
class JointScoreCompatibilityGrouping:
    """An immutable deterministic partition tied to one public potential."""

    potential_sha256: str
    width_cap: int
    factor_count: int
    groups: tuple[JointScoreCompatibilityGroup, ...]
    serialized: bytes
    sha256: str

    def __post_init__(self) -> None:
        members = tuple(
            factor_index
            for group in self.groups
            for factor_index in group.factor_indices
        )
        minimum_indices = tuple(group.factor_indices[0] for group in self.groups)
        expected_serialized = serialize_compatibility_grouping(
            potential_sha256=self.potential_sha256,
            width_cap=self.width_cap,
            factor_count=self.factor_count,
            groups=self.groups,
        )
        if (
            sorted(members) != list(range(self.factor_count))
            or len(members) != len(set(members))
            or minimum_indices != tuple(sorted(minimum_indices))
            or any(len(group.variables) > self.width_cap for group in self.groups)
            or self.serialized != expected_serialized
            or self.sha256 != hashlib.sha256(self.serialized).hexdigest()
        ):
            raise JointScoreGroupingError("compatibility grouping differs")

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def singleton_group_count(self) -> int:
        return sum(len(group.factor_indices) == 1 for group in self.groups)

    @property
    def pair_group_count(self) -> int:
        return sum(len(group.factor_indices) == 2 for group in self.groups)

    @property
    def higher_order_group_count(self) -> int:
        return sum(len(group.factor_indices) >= 3 for group in self.groups)

    @property
    def table_rows(self) -> int:
        return sum(len(group.energies) for group in self.groups)

    @property
    def variable_group_incidences(self) -> int:
        return sum(len(group.variables) for group in self.groups)


@dataclass(frozen=True)
class JointScoreGroupingDiagnostics:
    """Deterministic shape, memory, digest, and root-bound diagnostics."""

    schema: str
    grouping_rule: str
    bound_rule: str
    memory_rule: str
    potential_sha256: str
    grouping_sha256: str
    width_cap: int
    factor_count: int
    observed_variable_count: int
    group_count: int
    singleton_group_count: int
    pair_group_count: int
    higher_order_group_count: int
    maximum_group_size: int
    serialized_bytes: int
    table_rows: int
    variable_group_incidences: int
    raw_table_bytes: int
    estimated_indexed_bytes: int
    group_size_distribution: tuple[tuple[int, int], ...]
    group_width_distribution: tuple[tuple[int, int], ...]
    independent_root_upper_bound: float
    grouped_root_upper_bound: float

    @property
    def tightening(self) -> float | None:
        if not (
            math.isfinite(self.independent_root_upper_bound)
            and math.isfinite(self.grouped_root_upper_bound)
        ):
            return None
        return self.independent_root_upper_bound - self.grouped_root_upper_bound

    @property
    def estimated_indexed_mib(self) -> float:
        return self.estimated_indexed_bytes / float(1 << 20)

    @property
    def tightening_per_mib(self) -> float | None:
        tightening = self.tightening
        if tightening is None:
            return None
        return tightening / self.estimated_indexed_mib

    def describe(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "grouping_rule": self.grouping_rule,
            "bound_rule": self.bound_rule,
            "memory_rule": self.memory_rule,
            "potential_sha256": self.potential_sha256,
            "grouping_sha256": self.grouping_sha256,
            "width_cap": self.width_cap,
            "factor_count": self.factor_count,
            "observed_variable_count": self.observed_variable_count,
            "group_count": self.group_count,
            "singleton_group_count": self.singleton_group_count,
            "pair_group_count": self.pair_group_count,
            "higher_order_group_count": self.higher_order_group_count,
            "maximum_group_size": self.maximum_group_size,
            "serialized_bytes": self.serialized_bytes,
            "table_rows": self.table_rows,
            "variable_group_incidences": self.variable_group_incidences,
            "raw_table_bytes": self.raw_table_bytes,
            "estimated_indexed_bytes": self.estimated_indexed_bytes,
            "estimated_indexed_mib": self.estimated_indexed_mib,
            "group_size_distribution": self.group_size_distribution,
            "group_width_distribution": self.group_width_distribution,
            "independent_root_upper_bound": self.independent_root_upper_bound,
            "independent_root_upper_bound_f64le_hex": struct.pack(
                "<d", self.independent_root_upper_bound
            ).hex(),
            "grouped_root_upper_bound": self.grouped_root_upper_bound,
            "grouped_root_upper_bound_f64le_hex": struct.pack(
                "<d", self.grouped_root_upper_bound
            ).hex(),
            "tightening": self.tightening,
            "tightening_per_mib": self.tightening_per_mib,
        }


@dataclass(frozen=True)
class _CompiledGroup:
    public: JointScoreCompatibilityGroup
    exact_energies: tuple[int, ...]
    exact_maximum: int


def _projection_masks(
    union_variables: tuple[int, ...], subset_variables: tuple[int, ...]
) -> tuple[int, ...]:
    positions = {
        variable: position for position, variable in enumerate(union_variables)
    }
    rows = 1 << len(union_variables)
    result = [0] * rows
    for local, variable in enumerate(subset_variables):
        try:
            union_bit = 1 << positions[variable]
        except KeyError as exc:
            raise JointScoreGroupingError("group projection differs") from exc
        local_bit = 1 << local
        for mask in range(rows):
            if mask & union_bit:
                result[mask] |= local_bit
    return tuple(result)


def _singleton_group(
    factor_index: int,
    factor: CriticalityPotentialFactor,
    exact_energies: tuple[int, ...],
) -> _CompiledGroup:
    return _CompiledGroup(
        public=JointScoreCompatibilityGroup(
            factor_indices=(factor_index,),
            variables=factor.variables,
            energies=tuple(
                _scaled_integer_to_upward_binary64(value) for value in exact_energies
            ),
        ),
        exact_energies=exact_energies,
        exact_maximum=max(exact_energies),
    )


def _merge_group_and_factor(
    group: _CompiledGroup,
    factor_index: int,
    factor: CriticalityPotentialFactor,
    factor_exact_energies: tuple[int, ...],
) -> _CompiledGroup:
    variables = tuple(sorted(set(group.public.variables) | set(factor.variables)))
    old_projection = _projection_masks(variables, group.public.variables)
    factor_projection = _projection_masks(variables, factor.variables)
    exact_energies = tuple(
        group.exact_energies[old_mask] + factor_exact_energies[factor_mask]
        for old_mask, factor_mask in zip(old_projection, factor_projection, strict=True)
    )
    return _CompiledGroup(
        public=JointScoreCompatibilityGroup(
            factor_indices=group.public.factor_indices + (factor_index,),
            variables=variables,
            energies=tuple(
                _scaled_integer_to_upward_binary64(value) for value in exact_energies
            ),
        ),
        exact_energies=exact_energies,
        exact_maximum=max(exact_energies),
    )


def build_compatibility_grouping(
    field: CriticalityPotentialField, *, width_cap: int = 8
) -> JointScoreCompatibilityGrouping:
    """Build the deterministic maximum-exact-gain overlap partition.

    Each factor is visited once in canonical field order.  It may join an
    existing group only when the scopes overlap and their union fits the width
    cap.  Candidate gain is the exact reduction

    ``max(group) + max(factor) - max(group + factor)``.

    Ties prefer smaller union width, then a larger existing group, then the
    group with the smaller minimum factor index.
    """

    if not isinstance(field, CriticalityPotentialField):
        raise JointScoreGroupingError("compatibility potential differs")
    if (
        isinstance(width_cap, bool)
        or not isinstance(width_cap, int)
        or not 1 <= width_cap <= MAXIMUM_COMPATIBILITY_WIDTH
    ):
        raise JointScoreGroupingError("compatibility width cap differs")
    if any(len(factor.variables) > width_cap for factor in field.factors):
        raise JointScoreGroupingError("factor exceeds compatibility width cap")
    if len(field.factors) > 0xFFFFFFFF:
        raise JointScoreGroupingError("compatibility factor count differs")

    factor_exact = tuple(
        tuple(_binary64_scaled_integer(energy) for energy in factor.energies)
        for factor in field.factors
    )
    factor_maxima = tuple(max(energies) for energies in factor_exact)
    groups: list[_CompiledGroup] = []
    incident_groups: dict[int, set[int]] = {}

    for factor_index, factor in enumerate(field.factors):
        candidate_ids = sorted(
            {
                group_index
                for variable in factor.variables
                for group_index in incident_groups.get(variable, ())
            }
        )
        best_key: tuple[int, int, int, int, int] | None = None
        best_index: int | None = None
        best_group: _CompiledGroup | None = None
        for group_index in candidate_ids:
            old = groups[group_index]
            union_width = len(set(old.public.variables) | set(factor.variables))
            if union_width > width_cap:
                continue
            merged = _merge_group_and_factor(
                old, factor_index, factor, factor_exact[factor_index]
            )
            exact_gain = (
                old.exact_maximum + factor_maxima[factor_index] - merged.exact_maximum
            )
            if exact_gain < 0:
                raise JointScoreGroupingError("compatibility gain is negative")
            key = (
                exact_gain,
                -union_width,
                len(old.public.factor_indices),
                -old.public.factor_indices[0],
                -group_index,
            )
            if best_key is None or key > best_key:
                best_key = key
                best_index = group_index
                best_group = merged

        if best_index is None or best_group is None:
            group_index = len(groups)
            new_group = _singleton_group(
                factor_index, factor, factor_exact[factor_index]
            )
            groups.append(new_group)
        else:
            group_index = best_index
            new_group = best_group
            groups[group_index] = new_group
        for variable in new_group.public.variables:
            incident_groups.setdefault(variable, set()).add(group_index)

    public_groups = tuple(
        group.public
        for group in sorted(groups, key=lambda item: item.public.factor_indices[0])
    )
    potential_sha256 = field.state_sha256
    serialized = serialize_compatibility_grouping(
        potential_sha256=potential_sha256,
        width_cap=width_cap,
        factor_count=len(field.factors),
        groups=public_groups,
    )
    return JointScoreCompatibilityGrouping(
        potential_sha256=potential_sha256,
        width_cap=width_cap,
        factor_count=len(field.factors),
        groups=public_groups,
        serialized=serialized,
        sha256=hashlib.sha256(serialized).hexdigest(),
    )


def _normalize_partial_assignment(
    field: CriticalityPotentialField, assignments: Mapping[int, int]
) -> dict[int, int]:
    if not isinstance(assignments, Mapping):
        raise JointScoreGroupingError("partial assignment differs")
    observed = set(field.observed_variables)
    normalized: dict[int, int] = {}
    for variable, spin in assignments.items():
        if (
            isinstance(variable, bool)
            or not isinstance(variable, int)
            or variable not in observed
            or isinstance(spin, bool)
            or not isinstance(spin, int)
            or spin not in (-1, 1)
        ):
            raise JointScoreGroupingError("partial assignment differs")
        normalized[variable] = spin
    return normalized


def _group_maximum(
    group: JointScoreCompatibilityGroup, assignments: Mapping[int, int]
) -> float:
    best = -math.inf
    for mask, energy in enumerate(group.energies):
        if all(
            variable not in assignments
            or bool(mask & (1 << local)) == (assignments[variable] > 0)
            for local, variable in enumerate(group.variables)
        ):
            best = max(best, energy)
    if best == -math.inf:
        raise JointScoreGroupingError("compatibility group has no consistent row")
    return best


def compatibility_grouped_upper_bound(
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
    assignments: Mapping[int, int] | None = None,
) -> float:
    """Return a certified grouped bound for one public partial assignment."""

    if not isinstance(field, CriticalityPotentialField) or not isinstance(
        grouping, JointScoreCompatibilityGrouping
    ):
        raise JointScoreGroupingError("grouped bound input differs")
    if (
        grouping.factor_count != len(field.factors)
        or grouping.potential_sha256 != field.state_sha256
    ):
        raise JointScoreGroupingError("grouping potential identity differs")
    normalized = _normalize_partial_assignment(
        field, {} if assignments is None else assignments
    )
    maxima = tuple(_group_maximum(group, normalized) for group in grouping.groups)
    if any(value == math.inf for value in maxima):
        return math.inf
    return outward_binary64_sum((field.offset, *maxima))


def independent_root_upper_bound(field: CriticalityPotentialField) -> float:
    """Return the exact-outward sum of the independent factor maxima."""

    if not isinstance(field, CriticalityPotentialField):
        raise JointScoreGroupingError("independent bound potential differs")
    return outward_binary64_sum(
        (field.offset, *(max(factor.energies) for factor in field.factors))
    )


def compatibility_grouping_diagnostics(
    field: CriticalityPotentialField,
    grouping: JointScoreCompatibilityGrouping,
) -> JointScoreGroupingDiagnostics:
    """Derive deterministic bound-tightness and memory ledgers."""

    grouped_root = compatibility_grouped_upper_bound(field, grouping)
    group_sizes = Counter(len(group.factor_indices) for group in grouping.groups)
    group_widths = Counter(len(group.variables) for group in grouping.groups)
    table_rows = grouping.table_rows
    incidences = grouping.variable_group_incidences
    raw_table_bytes = 8 * table_rows
    estimated_indexed_bytes = (
        raw_table_bytes + 8 * grouping.group_count + 16 * incidences
    )
    return JointScoreGroupingDiagnostics(
        schema=COMPATIBILITY_GROUPING_SCHEMA,
        grouping_rule=COMPATIBILITY_GROUPING_RULE,
        bound_rule=COMPATIBILITY_GROUPING_BOUND_RULE,
        memory_rule=COMPATIBILITY_GROUPING_MEMORY_RULE,
        potential_sha256=grouping.potential_sha256,
        grouping_sha256=grouping.sha256,
        width_cap=grouping.width_cap,
        factor_count=grouping.factor_count,
        observed_variable_count=len(field.observed_variables),
        group_count=grouping.group_count,
        singleton_group_count=grouping.singleton_group_count,
        pair_group_count=grouping.pair_group_count,
        higher_order_group_count=grouping.higher_order_group_count,
        maximum_group_size=max(len(group.factor_indices) for group in grouping.groups),
        serialized_bytes=len(grouping.serialized),
        table_rows=table_rows,
        variable_group_incidences=incidences,
        raw_table_bytes=raw_table_bytes,
        estimated_indexed_bytes=estimated_indexed_bytes,
        group_size_distribution=tuple(sorted(group_sizes.items())),
        group_width_distribution=tuple(sorted(group_widths.items())),
        independent_root_upper_bound=independent_root_upper_bound(field),
        grouped_root_upper_bound=grouped_root,
    )


__all__ = [
    "COMPATIBILITY_GROUPING_BOUND_RULE",
    "COMPATIBILITY_GROUPING_MAGIC",
    "COMPATIBILITY_GROUPING_MEMORY_RULE",
    "COMPATIBILITY_GROUPING_RULE",
    "COMPATIBILITY_GROUPING_SCHEMA",
    "MAXIMUM_COMPATIBILITY_WIDTH",
    "JointScoreCompatibilityGroup",
    "JointScoreCompatibilityGrouping",
    "JointScoreGroupingDiagnostics",
    "JointScoreGroupingError",
    "build_compatibility_grouping",
    "compatibility_grouped_upper_bound",
    "compatibility_grouping_diagnostics",
    "independent_root_upper_bound",
    "outward_binary64_sum",
    "serialize_compatibility_grouping",
]
