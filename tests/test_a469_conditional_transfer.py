from __future__ import annotations

import numpy as np

from o1_crypto_lab.a465_rank_poe_transfer import A465RankField
from o1_crypto_lab.a469_conditional_transfer import (
    A469_SELECTED_SPEC,
    a469_rank_field_from_a465,
    load_frozen_a469_model,
    quantile_bins,
)


def _permutation(seed: int) -> np.ndarray:
    return np.random.default_rng(seed).permutation(256).argsort().astype(np.int16) + 1


def _field() -> A465RankField:
    return A465RankField(
        component_h_ranks=_permutation(1),
        component_o_ranks=_permutation(2),
        a460_ranks=_permutation(3),
        a462_ranks=_permutation(4),
        a463_ranks=_permutation(5),
        final_ranks=_permutation(6),
        directional_rank_sha256="0" * 64,
    )


def test_frozen_a469_model_is_exact_selected_local_correction() -> None:
    model = load_frozen_a469_model()

    assert model.selected_spec == A469_SELECTED_SPEC
    assert model.residual_table.shape == (32,)
    assert set(model.copula_tables) == {
        "q0",
        "q1",
        "q2",
        "pair01",
        "pair02",
        "pair12",
        "triple",
        "order",
        "spread",
    }


def test_a469_preserves_every_a465_quantile_bucket() -> None:
    result = a469_rank_field_from_a465(_field())

    assert np.array_equal(
        quantile_bins(result.final_ranks, 8),
        quantile_bins(result.base_ranks, 8),
    )
    assert set(result.final_ranks.tolist()) == set(range(1, 257))
