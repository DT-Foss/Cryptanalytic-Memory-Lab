from __future__ import annotations

from o1_crypto_lab.criticality_pair_groups import (
    compile_primary_pair_groups,
    transform_pair_groups,
)
from o1_crypto_lab.criticality_potential import (
    CriticalityPotentialFactor,
    CriticalityPotentialField,
)
from o1_crypto_lab.proof_parent_criticality import (
    ParentCriticalityFactor,
    ParentCriticalityField,
)


def test_pair_plan_prefers_joint_interaction_and_maps_key_control() -> None:
    field = ParentCriticalityField(
        conflict_horizon=16,
        minimum_abs_units=1,
        capacity=4,
        source_sha256="11" * 32,
        factors=(
            ParentCriticalityFactor(1, 1, 1, 300, 4, (1, 2, 300)),
            ParentCriticalityFactor(2, 1, 2, 301, 3, (2, 3, 301)),
            ParentCriticalityFactor(3, 1, 3, 302, 2, (3, 4, 302)),
            ParentCriticalityFactor(4, 1, 4, 303, 1, (1, 4, 303)),
        ),
        metrics={"factor_count": 4},
    )
    potential = CriticalityPotentialField(
        offset=0.0,
        source_sha256="22" * 32,
        factors=(
            CriticalityPotentialFactor(
                (1, 2, 300),
                (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 4.0),
            ),
            CriticalityPotentialFactor(
                (3, 4, 302),
                (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0),
            ),
        ),
    )
    plan = compile_primary_pair_groups(field, potential)
    assert plan.groups == ((1, 2), (3, 4))
    assert plan.joint_groups == 2
    assert plan.filler_groups == 0
    rotated = transform_pair_groups(plan, rotate="key")
    assert rotated.groups == ((2, 3), (4, 5))
    assert transform_pair_groups(plan, rotate="clause") == plan
