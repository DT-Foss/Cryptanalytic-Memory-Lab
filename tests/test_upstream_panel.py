import hashlib
import math
import unittest
from dataclasses import replace

import numpy as np

from o1_crypto_lab.walsh_memory import score_field_sha256
from o1_crypto_lab.upstream_panel import (
    BASE_CHANNEL_NAMES,
    DOMAIN_SIZE,
    HORIZONS,
    PANEL_VIEW_COUNT,
    RAW_CHANNEL_NAMES,
    SELECTION_ELIGIBLE_VIEW_COUNT,
    PanelViewSpec,
    UpstreamPanelError,
    UpstreamRawField,
    base_channel_values,
    bind_target,
    build_panel_specs,
    exact_label_enumeration_fwer,
    project_view,
    run_upstream_panel,
    transform_values,
)


def _character(mask: int, address: int) -> float:
    return -1.0 if (mask & address).bit_count() & 1 else 1.0


def _synthetic_field() -> UpstreamRawField:
    arrays = {}
    for horizon in HORIZONS:
        rows = []
        for address in range(DOMAIN_SIZE):
            bit0 = _character(1, address)
            bit3 = _character(8, address)
            pair = _character(1 | 8, address)
            conflicts = float(2 + ((address * 3 + horizon) % 7))
            decisions = 30.0 + 4.0 * bit0 + 2.0 * pair + horizon
            propagations = float(1000 + ((address * 29 + 11 * horizon) % 701))
            accepted = float((address * 5 + horizon) % 9)
            offered = accepted + 3.0 + float((address >> 3) % 5)
            rejected = offered - accepted
            literals = 2.0 * offered + float(address % 3)
            active_delta = 5.0 * bit3 - 2.0 * pair
            irredundant_delta = float((address % 19) - 9)
            redundant_delta = float(((address * 7) % 23) - 11)
            rows.append(
                (
                    conflicts,
                    decisions,
                    propagations,
                    accepted,
                    offered,
                    rejected,
                    literals,
                    active_delta,
                    irredundant_delta,
                    redundant_delta,
                )
            )
        arrays[horizon] = rows
    return UpstreamRawField.from_horizon_arrays(arrays)


class FieldAndTransformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.field = _synthetic_field()

    def test_field_contract_and_all_four_derived_formulas(self):
        self.assertEqual(len(RAW_CHANNEL_NAMES), 10)
        self.assertEqual(len(BASE_CHANNEL_NAMES), 14)
        row = self.field.horizon_arrays[0][0]
        conflicts = row[0]
        accepted = row[3]
        offered = row[4]
        literals = row[6]
        expected = {
            "accepted_vs_conflicts": (
                (accepted - conflicts) / (abs(accepted) + abs(conflicts))
            ),
            "accepted_per_conflict": accepted / (1.0 + conflicts),
            "offered_per_conflict": offered / (1.0 + conflicts),
            "literals_per_conflict": literals / (1.0 + conflicts),
        }
        for name, value in expected.items():
            self.assertAlmostEqual(base_channel_values(self.field, name, 1)[0], value)
        self.assertEqual(base_channel_values(self.field, "decisions", 1)[0], row[1])
        self.assertEqual(len(self.field.field_sha256), 64)

    def test_rank_transform_uses_exact_midranks_for_ties(self):
        raw = (1.0,) * 1024 + (3.0,) * 2048 + (9.0,) * 1024
        transformed = transform_values(raw, "rank")
        self.assertEqual(len(set(transformed[:1024])), 1)
        self.assertEqual(len(set(transformed[1024:3072])), 1)
        self.assertEqual(len(set(transformed[3072:])), 1)
        self.assertLess(transformed[0], transformed[1024])
        self.assertLess(transformed[1024], transformed[3072])
        self.assertAlmostEqual(math.fsum(transformed), 0.0, places=10)

    def test_projection_matches_direct_character_sum(self):
        spec = PanelViewSpec(
            "decisions", 1, "zscore", "degree1", "positive"
        )
        projected = project_view(self.field, spec)
        transformed = transform_values(
            base_channel_values(self.field, "decisions", 1), "zscore"
        )
        coefficients = {
            mask: math.fsum(
                value * _character(mask, address)
                for address, value in enumerate(transformed)
            )
            / DOMAIN_SIZE
            for mask in spec.masks
        }
        expected = tuple(
            math.fsum(
                coefficient * _character(mask, address)
                for mask, coefficient in coefficients.items()
            )
            for address in range(DOMAIN_SIZE)
        )
        self.assertTrue(np.allclose(projected, expected, rtol=0.0, atol=1e-12))

    def test_bad_shapes_counts_and_nonfinite_values_fail_closed(self):
        arrays = {horizon: [(0.0,) * 10] * DOMAIN_SIZE for horizon in HORIZONS}
        del arrays[8]
        with self.assertRaisesRegex(UpstreamPanelError, "exactly horizons"):
            UpstreamRawField.from_horizon_arrays(arrays)
        arrays[8] = [(0.0,) * 10] * DOMAIN_SIZE
        arrays[1] = [(0.0,) * 9] * DOMAIN_SIZE
        with self.assertRaisesRegex(UpstreamPanelError, "exactly 10"):
            UpstreamRawField.from_horizon_arrays(arrays)
        boolean_alias = {
            True: [(0.0,) * 10] * DOMAIN_SIZE,
            2: [(0.0,) * 10] * DOMAIN_SIZE,
            4: [(0.0,) * 10] * DOMAIN_SIZE,
            8: [(0.0,) * 10] * DOMAIN_SIZE,
        }
        with self.assertRaisesRegex(UpstreamPanelError, "exactly horizons"):
            UpstreamRawField.from_horizon_arrays(boolean_alias)

    def test_extreme_finite_zscore_stays_finite_and_centered(self):
        values = tuple(1e308 if index & 1 else -1e308 for index in range(DOMAIN_SIZE))
        transformed = transform_values(values, "zscore")
        self.assertTrue(all(math.isfinite(value) for value in transformed))
        self.assertAlmostEqual(math.fsum(transformed), 0.0, places=12)
        self.assertEqual(set(transformed), {-1.0, 1.0})


class CompletePanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.field = _synthetic_field()
        cls.blind = run_upstream_panel(cls.field)
        cls.target = 0xBAE
        cls.bound = bind_target(cls.blind, cls.target)
        cls.null = exact_label_enumeration_fwer(cls.bound)

    def test_exact_672_cardinality_and_streamability_rule(self):
        specs = build_panel_specs()
        self.assertEqual(PANEL_VIEW_COUNT, 672)
        self.assertEqual(len(specs), 672)
        self.assertEqual(len({spec.view_id for spec in specs}), 672)
        eligible = [spec for spec in specs if spec.selection_eligible]
        ineligible = [spec for spec in specs if not spec.selection_eligible]
        self.assertEqual(len(eligible), SELECTION_ELIGIBLE_VIEW_COUNT)
        self.assertEqual(SELECTION_ELIGIBLE_VIEW_COUNT, 448)
        self.assertEqual(len(ineligible), 224)
        self.assertTrue(all(spec.transform_id == "rank" for spec in ineligible))
        self.assertTrue(all(not spec.streamable for spec in ineligible))

    def test_target_blind_panel_contains_no_rank_or_selection(self):
        self.assertIsNone(self.blind.target_address)
        self.assertIsNone(self.blind.selected_primary)
        self.assertTrue(all(view.target_rank is None for view in self.blind.views))
        self.assertTrue(all(view.target_gain_bits is None for view in self.blind.views))
        with self.assertRaisesRegex(UpstreamPanelError, "target-bound"):
            exact_label_enumeration_fwer(self.blind)

    def test_orders_are_complete_tie_stable_and_hash_exact(self):
        view = next(
            item
            for item in self.blind.views
            if item.spec.view_id
            == "decisions__h1__zscore__degree1__positive"
        )
        scores = project_view(self.field, view.spec)
        expected = tuple(sorted(range(DOMAIN_SIZE), key=lambda address: (-scores[address], address)))
        self.assertEqual(view.order, expected)
        self.assertEqual(len(set(view.order)), DOMAIN_SIZE)
        self.assertEqual(
            view.order_sha256,
            hashlib.sha256(view.order_uint16be).hexdigest(),
        )
        raw = b"".join(address.to_bytes(2, "big") for address in expected)
        self.assertEqual(view.order_uint16be, raw)
        negative = next(
            item
            for item in self.blind.views
            if item.spec.view_id
            == "decisions__h1__zscore__degree1__negative"
        )
        self.assertEqual(
            negative.projected_field_sha256,
            score_field_sha256(project_view(self.field, negative.spec)),
        )

    def test_target_binding_selects_exact_deterministic_primary(self):
        self.assertEqual(self.bound.target_address, self.target)
        eligible = [
            view for view in self.bound.views if view.spec.selection_eligible
        ]
        expected = min(
            eligible,
            key=lambda view: (
                view.target_rank,
                view.spec.register_count,
                view.spec.view_id,
            ),
        )
        self.assertEqual(self.bound.selected_primary, expected)
        self.assertNotEqual(expected.spec.transform_id, "rank")
        self.assertEqual(expected.target_rank, expected.rank(self.target))
        self.assertAlmostEqual(
            expected.target_gain_bits,
            math.log2(DOMAIN_SIZE / expected.target_rank),
        )

    def test_bound_panel_recomputes_ranks_and_gain_from_frozen_orders(self):
        first = self.bound.views[0]
        forged = replace(first, target_rank=1, target_gain_bits=12.0)
        views = (forged, *self.bound.views[1:])
        with self.assertRaisesRegex(UpstreamPanelError, "rank or gain"):
            replace(self.bound, views=views)

    def test_exact_null_enumerates_every_label_and_full_selection(self):
        result = self.null
        self.assertEqual(len(result.minimum_selected_rank_by_label), DOMAIN_SIZE)
        self.assertEqual(len(result.selected_view_index_by_label), DOMAIN_SIZE)
        self.assertEqual(sum(result.selected_rank_histogram), DOMAIN_SIZE)
        self.assertEqual(len(result.eligible_view_ids), SELECTION_ELIGIBLE_VIEW_COUNT)
        self.assertEqual(
            result.minimum_selected_rank_by_label[self.target],
            self.bound.selected_primary.target_rank,
        )
        self.assertEqual(
            result.selected_view_id(self.target),
            self.bound.selected_primary.spec.view_id,
        )
        favorable = sum(
            rank <= result.observed_selected_rank
            for rank in result.minimum_selected_rank_by_label
        )
        self.assertEqual(result.favorable_label_count, favorable)
        self.assertEqual(result.exact_familywise_p, favorable / DOMAIN_SIZE)
        for label in (0, 17, 2048, 4095):
            manual = min(
                (
                    view.rank(label),
                    view.spec.register_count,
                    view.spec.view_id,
                )
                for view in self.bound.views
                if view.spec.selection_eligible
            )
            self.assertEqual(result.minimum_selected_rank_by_label[label], manual[0])
            self.assertEqual(result.selected_view_id(label), manual[2])


if __name__ == "__main__":
    unittest.main()
