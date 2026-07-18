"""Deterministic disjoint key pairs for global criticality envelopes."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass

from .criticality_potential import CriticalityPotentialField
from .proof_parent_criticality import ParentCriticalityField


class CriticalityPairGroupError(ValueError):
    """The field cannot produce a complete deterministic key-pair plan."""


@dataclass(frozen=True)
class CriticalityPairGroupPlan:
    groups: tuple[tuple[int, int], ...]
    joint_groups: int
    filler_groups: int
    eligible_variables: int

    @property
    def ordered_variables(self) -> tuple[int, ...]:
        return tuple(variable for group in self.groups for variable in group)

    @property
    def state_sha256(self) -> str:
        payload = "".join(
            f"{left} {right}\n" for left, right in self.groups
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()

    def describe(self) -> dict[str, object]:
        return {
            "group_count": len(self.groups),
            "joint_groups": self.joint_groups,
            "filler_groups": self.filler_groups,
            "eligible_variables": self.eligible_variables,
            "ordered_variables_sha256": self.state_sha256,
        }


def _support_order(field: ParentCriticalityField) -> tuple[int, ...]:
    support: dict[int, tuple[int, int]] = {}
    for factor in field.factors:
        units, count = support.get(factor.key_variable, (0, 0))
        support[factor.key_variable] = (units + abs(factor.score_units), count + 1)
    return tuple(
        sorted(
            support,
            key=lambda variable: (
                -support[variable][0],
                -support[variable][1],
                variable,
            ),
        )
    )


def _factor_pair_envelope(
    *, factor_variables: tuple[int, ...], energies: tuple[float, ...], pair: tuple[int, int]
) -> tuple[float, float, float, float]:
    try:
        positions = tuple(factor_variables.index(variable) for variable in pair)
    except ValueError as exc:
        raise CriticalityPairGroupError("pair is absent from factor") from exc
    envelope: list[float] = []
    for pair_mask in range(4):
        values = [
            energy
            for mask, energy in enumerate(energies)
            if all(
                ((mask >> positions[index]) & 1) == ((pair_mask >> index) & 1)
                for index in range(2)
            )
        ]
        if not values:
            raise CriticalityPairGroupError("pair envelope is empty")
        envelope.append(max(values))
    return tuple(envelope)  # type: ignore[return-value]


def compile_primary_pair_groups(
    field: ParentCriticalityField, potential: CriticalityPotentialField
) -> CriticalityPairGroupPlan:
    """Greedily match the strongest genuine pair interactions, then fill."""

    support_order = _support_order(field)
    eligible = set(support_order)
    if (
        not support_order
        or len(support_order) % 2
        or any(not 1 <= variable <= 256 for variable in support_order)
    ):
        raise CriticalityPairGroupError("eligible key-variable set differs")
    aggregates: dict[tuple[int, int], list[float]] = defaultdict(
        lambda: [0.0, 0.0, 0.0]
    )
    for factor in potential.factors:
        pair = tuple(variable for variable in factor.variables if variable in eligible)
        if len(pair) != 2:
            continue
        pair = tuple(sorted(pair))
        envelope = _factor_pair_envelope(
            factor_variables=factor.variables,
            energies=factor.energies,
            pair=pair,
        )
        interaction = abs(envelope[0] - envelope[1] - envelope[2] + envelope[3])
        span = max(envelope) - min(envelope)
        if not math.isfinite(interaction) or not math.isfinite(span):
            raise CriticalityPairGroupError("pair weight is non-finite")
        aggregates[pair][0] += interaction
        aggregates[pair][1] += span
        aggregates[pair][2] += 1.0

    used: set[int] = set()
    groups: list[tuple[int, int]] = []
    for pair, weight in sorted(
        aggregates.items(),
        key=lambda item: (
            -item[1][0],
            -item[1][1],
            -item[1][2],
            item[0],
        ),
    ):
        if not used.intersection(pair):
            groups.append(pair)
            used.update(pair)
    joint_groups = len(groups)
    remaining = tuple(variable for variable in support_order if variable not in used)
    groups.extend(zip(remaining[::2], remaining[1::2], strict=True))
    flattened = tuple(variable for group in groups for variable in group)
    if (
        len(groups) * 2 != len(support_order)
        or len(flattened) != len(set(flattened))
        or set(flattened) != eligible
    ):
        raise CriticalityPairGroupError("pair plan does not partition eligible keys")
    return CriticalityPairGroupPlan(
        groups=tuple(groups),
        joint_groups=joint_groups,
        filler_groups=len(groups) - joint_groups,
        eligible_variables=len(flattened),
    )


def transform_pair_groups(
    plan: CriticalityPairGroupPlan, *, rotate: str | None
) -> CriticalityPairGroupPlan:
    if rotate not in (None, "key", "clause"):
        raise CriticalityPairGroupError("pair control transform differs")
    if rotate == "key":
        groups = tuple(
            (1 + left % 256, 1 + right % 256) for left, right in plan.groups
        )
    else:
        groups = plan.groups
    transformed = CriticalityPairGroupPlan(
        groups=groups,
        joint_groups=plan.joint_groups,
        filler_groups=plan.filler_groups,
        eligible_variables=plan.eligible_variables,
    )
    if len(set(transformed.ordered_variables)) != transformed.eligible_variables:
        raise CriticalityPairGroupError("transformed pair plan is not bijective")
    return transformed


__all__ = [
    "CriticalityPairGroupError",
    "CriticalityPairGroupPlan",
    "compile_primary_pair_groups",
    "transform_pair_groups",
]
