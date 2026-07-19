from __future__ import annotations

import hashlib
import itertools
import math
import struct
import sys
from fractions import Fraction

import pytest

from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.joint_score_grouping_v1 import (
    COMPATIBILITY_GROUPING_BOUND_RULE,
    COMPATIBILITY_GROUPING_MEMORY_RULE,
    COMPATIBILITY_GROUPING_RULE,
    COMPATIBILITY_GROUPING_SCHEMA,
    JointScoreCompatibilityGrouping,
    JointScoreGroupingError,
    build_compatibility_grouping,
    compatibility_grouped_upper_bound,
    compatibility_grouping_diagnostics,
    outward_binary64_sum,
    serialize_compatibility_grouping,
)


def _field(
    factors: tuple[CriticalityPotentialFactor, ...], *, offset: float = 0.0
) -> CriticalityPotentialField:
    return CriticalityPotentialField(
        offset=offset,
        source_sha256="71" * 32,
        factors=factors,
    )


def _zero_factor(variables: tuple[int, ...]) -> CriticalityPotentialFactor:
    return CriticalityPotentialFactor(variables, (0.0,) * (1 << len(variables)))


def _exact_sum(values: tuple[float, ...]) -> Fraction:
    return sum((Fraction.from_float(value) for value in values), Fraction())


def _exact_score(
    field: CriticalityPotentialField, assignments: dict[int, int]
) -> Fraction:
    result = Fraction.from_float(field.offset)
    for factor in field.factors:
        mask = sum(
            (assignments[variable] > 0) << local
            for local, variable in enumerate(factor.variables)
        )
        result += Fraction.from_float(factor.energies[mask])
    return result


def _brute_force_field() -> CriticalityPotentialField:
    return _field(
        (
            CriticalityPotentialFactor((1,), (1.0, -0.25)),
            CriticalityPotentialFactor((1, 2), (0.0, 2.0**-53, -1.5, 0.75)),
            CriticalityPotentialFactor((1, 3), (2.0, -2.0, 0.5, -0.5)),
            CriticalityPotentialFactor((2,), (-0.75, 1.25)),
            CriticalityPotentialFactor((2, 3), (0.25, -1.0, 1.0, -0.25)),
            CriticalityPotentialFactor((9,), (0.125, -0.375)),
        ),
        offset=2.0**-54,
    )


def test_outward_sum_is_the_least_safe_binary64_for_adversarial_sums() -> None:
    cases = (
        (1.0, 2.0**-53),
        (-1.0, -(2.0**-53)),
        (1.0e308, 1.0e308, -1.0e308),
        (sys.float_info.max, -sys.float_info.max, 2.0**-1074),
        (2.0**-1074, 2.0**-1074),
        (1.0, -1.0),
    )
    for values in cases:
        exact = _exact_sum(values)
        rounded = outward_binary64_sum(values)
        assert Fraction.from_float(rounded) >= exact
        previous = math.nextafter(rounded, -math.inf)
        if previous != -math.inf:
            assert Fraction.from_float(previous) < exact

    assert outward_binary64_sum((1.0, 2.0**-53)) == math.nextafter(1.0, math.inf)
    assert outward_binary64_sum((-1.0, -(2.0**-53))) == -1.0
    assert outward_binary64_sum((sys.float_info.max,) * 2) == math.inf
    assert outward_binary64_sum((-sys.float_info.max,) * 2) == -sys.float_info.max


def test_outward_sum_rejects_non_binary64_inputs() -> None:
    for values in ((math.nan,), (math.inf,), (True,), ("1.0",)):
        with pytest.raises(JointScoreGroupingError, match="outward sum"):
            outward_binary64_sum(values)  # type: ignore[arg-type]


def test_width_cap_is_enforced_before_group_construction() -> None:
    field = _field((_zero_factor((1, 10)), _zero_factor((1, 11))))
    narrow = build_compatibility_grouping(field, width_cap=2)
    wide = build_compatibility_grouping(field, width_cap=3)
    assert tuple(group.factor_indices for group in narrow.groups) == ((0,), (1,))
    assert tuple(group.factor_indices for group in wide.groups) == ((0, 1),)
    with pytest.raises(JointScoreGroupingError, match="exceeds"):
        build_compatibility_grouping(field, width_cap=1)
    for invalid in (True, 0, 21):
        with pytest.raises(JointScoreGroupingError, match="width cap"):
            build_compatibility_grouping(field, width_cap=invalid)


def test_exact_gain_precedes_all_structural_tie_breaks() -> None:
    field = _field(
        (
            _zero_factor((1, 10)),
            CriticalityPotentialFactor((2, 5), (0.0, 1.0, 0.0, 1.0)),
            CriticalityPotentialFactor((2, 10), (1.0, 0.0, 1.0, 0.0)),
        )
    )
    grouping = build_compatibility_grouping(field, width_cap=3)
    assert tuple(group.factor_indices for group in grouping.groups) == (
        (0,),
        (1, 2),
    )


def test_ties_prefer_smaller_union_then_larger_group_then_smaller_minimum() -> None:
    smaller_union = _field(
        (
            _zero_factor((1, 10)),
            _zero_factor((2,)),
            _zero_factor((2, 10)),
        )
    )
    assert tuple(
        group.factor_indices
        for group in build_compatibility_grouping(smaller_union, width_cap=3).groups
    ) == ((0,), (1, 2))

    larger_group = _field(
        (
            _zero_factor((1, 10)),
            _zero_factor((1, 11)),
            _zero_factor((2, 5)),
            _zero_factor((2, 10, 11)),
        )
    )
    assert tuple(
        group.factor_indices
        for group in build_compatibility_grouping(larger_group, width_cap=4).groups
    ) == ((0, 1, 3), (2,))

    smaller_minimum = _field(
        (
            _zero_factor((1, 10)),
            _zero_factor((2, 5)),
            _zero_factor((2, 10)),
        )
    )
    assert tuple(
        group.factor_indices
        for group in build_compatibility_grouping(smaller_minimum, width_cap=3).groups
    ) == ((0, 2), (1,))


def test_every_group_cell_is_a_minimal_outward_exact_factor_sum() -> None:
    field = _brute_force_field()
    grouping = build_compatibility_grouping(field, width_cap=3)
    assert tuple(group.factor_indices for group in grouping.groups) == (
        (0, 1, 2, 3, 4),
        (5,),
    )
    for group in grouping.groups:
        for mask, rounded in enumerate(group.energies):
            assignments = {
                variable: 1 if mask & (1 << local) else -1
                for local, variable in enumerate(group.variables)
            }
            exact = sum(
                (
                    Fraction.from_float(
                        field.factors[factor_index].energies[
                            sum(
                                (assignments[variable] > 0) << local
                                for local, variable in enumerate(
                                    field.factors[factor_index].variables
                                )
                            )
                        ]
                    )
                    for factor_index in group.factor_indices
                ),
                Fraction(),
            )
            assert Fraction.from_float(rounded) >= exact
            previous = math.nextafter(rounded, -math.inf)
            if previous != -math.inf:
                assert Fraction.from_float(previous) < exact


def test_grouped_bound_covers_every_completion_of_every_partial_assignment() -> None:
    field = _brute_force_field()
    grouping = build_compatibility_grouping(field, width_cap=3)
    variables = field.observed_variables
    for states in itertools.product((None, -1, 1), repeat=len(variables)):
        partial = {
            variable: spin
            for variable, spin in zip(variables, states, strict=True)
            if spin is not None
        }
        upper = compatibility_grouped_upper_bound(field, grouping, partial)
        missing = tuple(variable for variable in variables if variable not in partial)
        for spins in itertools.product((-1, 1), repeat=len(missing)):
            complete = dict(partial)
            complete.update(zip(missing, spins, strict=True))
            assert Fraction.from_float(upper) >= _exact_score(field, complete)


def test_grouping_replay_hash_and_diagnostics_are_deterministic() -> None:
    field = _brute_force_field()
    first = build_compatibility_grouping(field, width_cap=3)
    replay = build_compatibility_grouping(field, width_cap=3)
    assert first == replay
    assert first.sha256 == hashlib.sha256(first.serialized).hexdigest()
    assert first.sha256 == replay.sha256
    assert first.potential_sha256 == (
        "a17bb7885b3f8c0dcafbf47798b4b488525686de4d0bdd8a753cd6b997c68eb2"
    )
    assert first.sha256 == (
        "1a7aaef8b4151a7a63e5051c7d73bab48ac1105ae04cc143f3c3aed6986aebdb"
    )
    assert len(first.serialized) == 114

    diagnostics = compatibility_grouping_diagnostics(field, first)
    description = diagnostics.describe()
    assert diagnostics.schema == COMPATIBILITY_GROUPING_SCHEMA
    assert diagnostics.grouping_rule == COMPATIBILITY_GROUPING_RULE
    assert diagnostics.bound_rule == COMPATIBILITY_GROUPING_BOUND_RULE
    assert diagnostics.memory_rule == COMPATIBILITY_GROUPING_MEMORY_RULE
    assert diagnostics.factor_count == 6
    assert diagnostics.observed_variable_count == 4
    assert diagnostics.group_count == 2
    assert diagnostics.singleton_group_count == 1
    assert diagnostics.pair_group_count == 0
    assert diagnostics.higher_order_group_count == 1
    assert diagnostics.maximum_group_size == 5
    assert diagnostics.serialized_bytes == 114
    assert diagnostics.table_rows == 10
    assert diagnostics.variable_group_incidences == 4
    assert diagnostics.raw_table_bytes == 80
    assert diagnostics.estimated_indexed_bytes == 160
    assert diagnostics.group_size_distribution == ((1, 1), (5, 1))
    assert diagnostics.group_width_distribution == ((1, 1), (3, 1))
    assert diagnostics.tightening is not None and diagnostics.tightening > 0.0
    assert description["grouping_sha256"] == first.sha256
    assert (
        description["grouped_root_upper_bound_f64le_hex"]
        == struct.pack("<d", diagnostics.grouped_root_upper_bound).hex()
    )


def test_grouping_contract_rejects_reordering_and_wrong_potential_identity() -> None:
    field = _brute_force_field()
    grouping = build_compatibility_grouping(field, width_cap=3)
    reversed_groups = tuple(reversed(grouping.groups))
    serialized = serialize_compatibility_grouping(
        potential_sha256=grouping.potential_sha256,
        width_cap=grouping.width_cap,
        factor_count=grouping.factor_count,
        groups=reversed_groups,
    )
    with pytest.raises(JointScoreGroupingError, match="grouping differs"):
        JointScoreCompatibilityGrouping(
            potential_sha256=grouping.potential_sha256,
            width_cap=grouping.width_cap,
            factor_count=grouping.factor_count,
            groups=reversed_groups,
            serialized=serialized,
            sha256=hashlib.sha256(serialized).hexdigest(),
        )

    changed = _field(field.factors, offset=math.nextafter(field.offset, math.inf))
    with pytest.raises(JointScoreGroupingError, match="identity"):
        compatibility_grouped_upper_bound(changed, grouping)
    with pytest.raises(JointScoreGroupingError, match="partial assignment"):
        compatibility_grouped_upper_bound(field, grouping, [])  # type: ignore[arg-type]
