from __future__ import annotations

import itertools

import numpy as np
import pytest

from o1_crypto_lab.criticality_potential import score_potential_assignment
from o1_crypto_lab.joint_score_sieve import joint_score_upper_bound
from o1_crypto_lab.multiblock_criticality_potential import (
    MultiblockCriticalityPotentialError,
    compile_multiblock_criticality_potential,
    score_multiblock_criticality_components,
    verify_multiblock_complete_score_equivalence,
)
from o1_crypto_lab.proof_parent_criticality import (
    FEATURE_NAMES,
    ParentCriticalityFactor,
    ParentCriticalityField,
)


def _field(block: int) -> ParentCriticalityField:
    return ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=8,
        source_sha256=f"{block + 1:02x}" * 32,
        factors=(
            ParentCriticalityFactor(
                1,
                0,
                100 + block,
                257,
                3 + block,
                (1, 257),
            ),
            ParentCriticalityFactor(
                2,
                1,
                200 + block,
                3,
                -5 - block,
                (2, 3),
            ),
        ),
        metrics={"factor_count": 2},
    )


def _inputs():
    fields = (_field(0), _field(1))
    means = (
        np.linspace(-0.25, 0.25, len(FEATURE_NAMES)),
        np.linspace(0.15, -0.15, len(FEATURE_NAMES)),
    )
    stds = (
        np.linspace(0.5, 1.5, len(FEATURE_NAMES)),
        np.linspace(1.75, 0.75, len(FEATURE_NAMES)),
    )
    reader = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    reader[:6] = (0.8, -0.4, 0.2, -1.1, 0.3, 0.7)
    return {
        "fields": fields,
        "counters": (10, 11),
        "feature_means": means,
        "feature_stds": stds,
        "reader": reader,
        "scalar_score_means": (0.35, -0.6),
        "scalar_score_stds": (1.25, 0.8),
        "block_weights": (1.5, -0.75),
    }


def test_negative_weight_merge_is_complete_score_exact_and_merges_collisions() -> None:
    inputs = _inputs()
    potential = compile_multiblock_criticality_potential(**inputs)
    scopes = [factor.variables for factor in potential.factors]
    assert scopes.count((2, 3)) == 1
    assert (1, 257) in scopes
    assert (1, 32_129) in scopes
    assert potential.observed_variables == (1, 2, 3, 257, 32_129)

    for spins in itertools.product((-1, 1), repeat=len(potential.observed_variables)):
        assignment = dict(zip(potential.observed_variables, spins, strict=True))
        component = score_multiblock_criticality_components(
            assignment=assignment, **inputs
        )
        merged = verify_multiblock_complete_score_equivalence(
            potential, assignment=assignment, **inputs
        )
        assert np.isclose(merged, component, rtol=0.0, atol=1e-12)
        assert np.isclose(
            merged,
            score_potential_assignment(potential, assignment),
            rtol=0.0,
            atol=0.0,
        )


def test_merged_partial_upper_bound_is_sound_exhaustively() -> None:
    inputs = _inputs()
    potential = compile_multiblock_criticality_potential(**inputs)
    variables = potential.observed_variables
    complete_scores = []
    for spins in itertools.product((-1, 1), repeat=len(variables)):
        assignment = dict(zip(variables, spins, strict=True))
        complete_scores.append(
            (assignment, score_potential_assignment(potential, assignment))
        )
    for partial_spins in itertools.product((-1, 0, 1), repeat=len(variables)):
        partial = {
            variable: spin
            for variable, spin in zip(variables, partial_spins, strict=True)
            if spin
        }
        consistent = [
            score
            for assignment, score in complete_scores
            if all(assignment[variable] == spin for variable, spin in partial.items())
        ]
        assert joint_score_upper_bound(potential, partial) >= max(consistent)


def test_order_calibration_counter_and_remap_are_source_bound() -> None:
    inputs = _inputs()
    baseline = compile_multiblock_criticality_potential(**inputs)

    changed_weights = {**inputs, "block_weights": (1.5, -0.5)}
    assert (
        compile_multiblock_criticality_potential(**changed_weights).source_sha256
        != baseline.source_sha256
    )

    swapped = {
        **inputs,
        "fields": tuple(reversed(inputs["fields"])),
        "feature_means": tuple(reversed(inputs["feature_means"])),
        "feature_stds": tuple(reversed(inputs["feature_stds"])),
        "scalar_score_means": tuple(reversed(inputs["scalar_score_means"])),
        "scalar_score_stds": tuple(reversed(inputs["scalar_score_stds"])),
        "block_weights": tuple(reversed(inputs["block_weights"])),
    }
    assert (
        compile_multiblock_criticality_potential(**swapped).source_sha256
        != baseline.source_sha256
    )

    changed_counter = {**inputs, "counters": (11, 12)}
    assert (
        compile_multiblock_criticality_potential(**changed_counter).source_sha256
        != baseline.source_sha256
    )


def test_eight_block_remap_reaches_actual_o1c57_coordinate_ceiling() -> None:
    field = ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=1,
        source_sha256="ab" * 32,
        factors=(ParentCriticalityFactor(1, 0, 1, 32_128, 1, (1, 32_128)),),
        metrics={"factor_count": 1},
    )
    reader = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    reader[0] = 1.0
    potential = compile_multiblock_criticality_potential(
        (field,) * 8,
        counters=tuple(range(20, 28)),
        feature_means=(np.zeros(len(FEATURE_NAMES)),) * 8,
        feature_stds=(np.ones(len(FEATURE_NAMES)),) * 8,
        reader=reader,
        scalar_score_means=(0.0,) * 8,
        scalar_score_stds=(1.0,) * 8,
    )
    assert max(potential.observed_variables) == 255_232
    assert len(potential.factors) == 8


def test_actual_o1c57_factor_scale_fits_one_canonical_potential() -> None:
    counts = (945, 945, 945, 945, 945, 945, 945, 942)
    fields = []
    for block_index, count in enumerate(counts):
        factors = []
        for index in range(count):
            key_variable = index % 256 + 1
            wire = 32_128 if index == count - 1 else 257 + index
            factors.append(
                ParentCriticalityFactor(
                    key_variable,
                    0,
                    index + 1,
                    wire,
                    1,
                    (key_variable, wire),
                )
            )
        fields.append(
            ParentCriticalityField(
                conflict_horizon=16,
                minimum_abs_units=1,
                capacity=count,
                source_sha256=f"{block_index + 32:02x}" * 32,
                factors=tuple(sorted(factors)),
                metrics={"factor_count": count},
            )
        )
    reader = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    reader[0] = 1.0
    potential = compile_multiblock_criticality_potential(
        fields,
        counters=tuple(range(100, 108)),
        feature_means=(np.zeros(len(FEATURE_NAMES)),) * 8,
        feature_stds=(np.ones(len(FEATURE_NAMES)),) * 8,
        reader=reader,
        scalar_score_means=(0.0,) * 8,
        scalar_score_stds=(1.0,) * 8,
    )
    assert len(potential.factors) == 7_557
    assert max(potential.observed_variables) == 255_232
    assert len(potential.to_bytes()) < 3 * 1024 * 1024


@pytest.mark.parametrize(
    ("replacement", "message"),
    (
        ({"counters": (10, 12)}, "contiguous"),
        ({"scalar_score_stds": (1.0, 0.0)}, "scalar_score_stds"),
        ({"scalar_score_means": (0.0,)}, "count"),
        ({"block_weights": (1.0, float("nan"))}, "block_weights"),
    ),
)
def test_invalid_multiblock_calibrations_fail_closed(
    replacement: dict[str, object], message: str
) -> None:
    inputs = {**_inputs(), **replacement}
    with pytest.raises(MultiblockCriticalityPotentialError, match=message):
        compile_multiblock_criticality_potential(**inputs)
