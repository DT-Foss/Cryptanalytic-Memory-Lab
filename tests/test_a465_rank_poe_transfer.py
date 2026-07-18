from __future__ import annotations

import numpy as np

from o1_crypto_lab.a465_rank_poe_transfer import (
    A465_SELECTED_SPEC,
    first_encounter_ranks,
    load_frozen_a465_model,
    rank_product_of_experts,
)


def _permutation(seed: int) -> np.ndarray:
    return np.random.default_rng(seed).permutation(256).argsort().astype(np.int16) + 1


def _scalar_first(h: np.ndarray, o: np.ndarray, pattern: str) -> np.ndarray:
    keys = []
    for cell in range(256):
        candidates = []
        for symbol, ranks in (("H", h), ("O", o)):
            slots = [index for index, value in enumerate(pattern) if value == symbol]
            zero = int(ranks[cell]) - 1
            candidates.append(len(pattern) * (zero // len(slots)) + slots[zero % len(slots)])
        keys.append(min(candidates))
    order = sorted(range(256), key=lambda cell: (keys[cell], cell))
    result = np.empty(256, dtype=np.int16)
    result[order] = np.arange(1, 257, dtype=np.int16)
    return result


def test_frozen_a465_model_is_exact_selected_poe() -> None:
    model = load_frozen_a465_model()

    assert model.selected_spec == A465_SELECTED_SPEC
    assert {name: len(pattern) for name, pattern in model.patterns.items()} == {
        "A460": 128,
        "A462": 192,
        "A463": 130,
    }


def test_first_encounter_matches_independent_scalar_reference() -> None:
    h = _permutation(1)
    o = _permutation(2)
    pattern = load_frozen_a465_model().patterns["A463"]

    assert np.array_equal(first_encounter_ranks(h, o, pattern), _scalar_first(h, o, pattern))


def test_selected_rank_poe_matches_independent_total_order() -> None:
    experts = [_permutation(seed) for seed in (3, 4, 5)]
    score = 7 * (experts[0].astype(np.int64) + 1) ** 3
    score += (experts[1].astype(np.int64) + 1) ** 3
    score += 4 * (experts[2].astype(np.int64) + 1) ** 3
    order = sorted(
        range(256),
        key=lambda cell: (
            int(score[cell]),
            max(int(expert[cell]) for expert in experts),
            sum(int(expert[cell]) for expert in experts),
            int(experts[2][cell]),
            int(experts[1][cell]),
            int(experts[0][cell]),
            cell,
        ),
    )
    expected = np.empty(256, dtype=np.int16)
    expected[order] = np.arange(1, 257, dtype=np.int16)

    assert np.array_equal(rank_product_of_experts(*experts), expected)
