import hashlib
import json
import math
import random
import unittest

from o1_crypto_lab.walsh_memory import (
    FIXED_BUDGETS,
    FrozenRanking,
    TargetAddressLabel,
    WalshMemoryError,
    WalshPlan,
    WalshScoreMemory,
    candidate_id_null_field,
    constant_score_field,
    degree_masks,
    delta_score_field,
    energy_budget_masks,
    evaluate_approximation,
    evaluate_target_rank,
    fixed_budget_masks,
    full_walsh_coefficients,
    score_field_sha256,
    walsh_character,
)


class MaskAndPlanTests(unittest.TestCase):
    def test_character_and_degree_counts_are_mathematically_exact(self):
        self.assertEqual(walsh_character(0b1010, 0b0010, n_bits=4), -1)
        self.assertEqual(walsh_character(0b1010, 0b1010, n_bits=4), 1)
        self.assertEqual(len(degree_masks(12, 1)), 12)
        self.assertEqual(len(degree_masks(12, 2)), 78)
        self.assertEqual(len(degree_masks(8, 5)), 218)
        self.assertEqual(len(degree_masks(8, 6)), 246)
        self.assertEqual(len(degree_masks(8, 6, include_constant=True)), 247)

    def test_fixed_budgets_do_not_mislabel_12_bit_partial_shells(self):
        for budget in FIXED_BUDGETS:
            masks = fixed_budget_masks(12, budget)
            self.assertEqual(len(masks), budget)
            self.assertNotIn(0, masks)
            self.assertEqual(masks, fixed_budget_masks(12, budget))
        field = tuple(float(index % 17) for index in range(1 << 12))
        plan = WalshPlan.for_field(field, budget=218)
        selection = plan.describe()["mask_selection"]
        self.assertEqual(selection["family"], "low-degree-prefix-k218-no-dc")
        self.assertEqual(selection["complete_nonconstant_through_degree"], 2)
        self.assertEqual(selection["partial_degree"], 3)
        self.assertEqual(selection["partial_degree_count"], 140)

    def test_energy_selection_is_label_free_deterministic_and_transfer_bindable(self):
        active_masks = (0b11111111, 0b11110110, 0b10101101)
        amplitudes = (5.0, -3.0, 2.0)
        calibration = tuple(
            sum(
                amplitude * walsh_character(mask, address)
                for mask, amplitude in zip(active_masks, amplitudes)
            )
            for address in range(256)
        )
        coefficients = full_walsh_coefficients(calibration)
        self.assertEqual(
            tuple(coefficients[mask] for mask in active_masks), amplitudes
        )
        selected = energy_budget_masks(calibration, 3)
        self.assertEqual(set(selected), set(active_masks))
        self.assertEqual(selected, energy_budget_masks(calibration, 3))

        # A348 supplies masks and their source hash; a distinct A349 field is the
        # field bound by the executable plan.  No target label crosses this API.
        transfer = tuple(value + (address % 11) / 100.0 for address, value in enumerate(calibration))
        calibration_hash = score_field_sha256(calibration)
        plan = WalshPlan.for_field(
            transfer,
            masks=selected,
            mask_family="energy-ranked-frozen",
            mask_source_field_sha256=calibration_hash,
        )
        described = plan.describe()
        self.assertEqual(described["field_sha256"], score_field_sha256(transfer))
        self.assertEqual(
            described["mask_selection"]["source_field_sha256"], calibration_hash
        )
        self.assertEqual(
            described["mask_selection"]["family"], "energy-ranked-frozen"
        )
        self.assertEqual(described["state"]["integrity_scalars"], 4)
        self.assertEqual(
            described["state"]["serialized_online_state_bytes"], 3 * 8 + 4 * 8
        )
        self.assertEqual(
            described["static_plan_storage"]["serialized_mask_bank_bytes"], 3 * 2
        )
        self.assertEqual(
            described["static_plan_storage"]["serialized_bound_hash_bytes"], 64
        )

    def test_energy_masks_beat_low_degree_prefix_on_sparse_spectral_field(self):
        active_masks = (0b11111111, 0b11110110, 0b10101101)
        field = tuple(
            4.0 * walsh_character(active_masks[0], address)
            - 2.0 * walsh_character(active_masks[1], address)
            + 1.0 * walsh_character(active_masks[2], address)
            for address in range(256)
        )
        energy_plan = WalshPlan.for_field(
            field,
            masks=energy_budget_masks(field, 3),
            mask_family="energy-ranked-frozen",
            mask_source_field_sha256=score_field_sha256(field),
        )
        low_degree_plan = WalshPlan.for_field(field, budget=3)
        energy = WalshScoreMemory(energy_plan)
        low_degree = WalshScoreMemory(low_degree_plan)
        energy.observe_field(field)
        low_degree.observe_field(field)
        energy_eval = evaluate_approximation(field, energy.finalize().reconstruct())
        low_degree_eval = evaluate_approximation(
            field, low_degree.finalize().reconstruct()
        )
        self.assertAlmostEqual(energy_eval.root_mean_square_error, 0.0)
        self.assertGreater(low_degree_eval.root_mean_square_error, 1.0)

    def test_full_bank_and_plan_hash_round_trip_are_deterministic(self):
        field = tuple(float((index * 13) % 19 - 7) for index in range(256))
        left = WalshPlan.full_bank(field)
        right = WalshPlan.for_field(field, masks=reversed(range(256)))
        self.assertTrue(left.is_full_bank)
        self.assertEqual(left.serialized_state_bytes, 256 * 8)
        self.assertEqual(left.serialized_integrity_bytes, 4 * 8)
        self.assertEqual(left.serialized_online_state_bytes, 256 * 8 + 4 * 8)
        self.assertEqual(left.serialized_mask_bank_bytes, 256 * 2)
        self.assertEqual(left.serialized_bound_hash_bytes, 32)
        self.assertEqual(left.masks, right.masks)
        # Names are intentionally part of the experiment plan.
        self.assertNotEqual(left.plan_sha256, right.plan_sha256)
        same = WalshPlan.full_bank(field)
        self.assertEqual(left.plan_sha256, same.plan_sha256)
        restored = WalshPlan.from_dict(json.loads(left.to_json()))
        self.assertEqual(restored, left)
        tampered = json.loads(left.to_json())
        tampered["state"]["spectral_scalars"] = 7
        with self.assertRaisesRegex(WalshMemoryError, "SHA-256 mismatch"):
            WalshPlan.from_dict(tampered)

    def test_explicit_masks_canonicalize_without_duplicates(self):
        field = tuple(float(index) for index in range(16))
        plan = WalshPlan.for_field(field, masks=[8, 1, 3, 2])
        self.assertEqual(plan.masks, (1, 2, 8, 3))
        with self.assertRaisesRegex(WalshMemoryError, "unique"):
            WalshPlan.for_field(field, masks=[1, 1])
        with self.assertRaises(WalshMemoryError):
            WalshPlan.for_field(field, masks=[16])
        with self.assertRaises(WalshMemoryError):
            WalshPlan.for_field(field, budget=2, max_degree=1)


class StreamingMemoryTests(unittest.TestCase):
    def test_full_bank_exact_reconstruction_and_normalization(self):
        field = tuple(float((index * index + 3 * index + 7) % 31) for index in range(256))
        plan = WalshPlan.full_bank(field)
        memory = WalshScoreMemory(plan)
        memory.observe_field(field)
        frozen = memory.finalize()
        reconstructed = frozen.reconstruct()
        self.assertEqual(memory.state_scalars, 256)
        self.assertEqual(memory.retained_rows, 0)
        self.assertEqual(memory.retained_key_value_entries, 0)
        self.assertEqual(frozen.completed_passes, 1)
        for expected, actual in zip(field, reconstructed):
            self.assertAlmostEqual(actual, expected, places=12)

    def test_stream_order_invariance(self):
        field = tuple(math.sin(index / 9.0) + (index % 7) / 13.0 for index in range(256))
        plan = WalshPlan.for_field(field, budget=78)
        forward = WalshScoreMemory(plan)
        reverse = WalshScoreMemory(plan)
        shuffled = WalshScoreMemory(plan)
        forward.observe_field(field)
        reverse.observe_field(field, address_order=tuple(reversed(range(256))))
        order = list(range(256))
        random.Random(71).shuffle(order)
        shuffled.observe_field(field, address_order=order)
        left = forward.finalize().reconstruct()
        for other in (reverse.finalize().reconstruct(), shuffled.finalize().reconstruct()):
            for expected, actual in zip(left, other):
                self.assertAlmostEqual(actual, expected, places=13)

    def test_duplicate_complete_stream_is_averaged_not_added(self):
        field = delta_score_field(8, 137, amplitude=9.0, baseline=-0.25)
        plan = WalshPlan.for_field(field, budget=78)
        once = WalshScoreMemory(plan)
        twice = WalshScoreMemory(plan)
        once.observe_field(field)
        twice.observe_field(field)
        twice.observe_field(field, address_order=tuple(reversed(range(256))))
        left = once.finalize()
        right = twice.finalize()
        self.assertEqual(right.completed_passes, 2)
        for expected, actual in zip(left.reconstruct(), right.reconstruct()):
            self.assertAlmostEqual(actual, expected, places=13)

    def test_constant_delta_and_candidate_id_controls(self):
        constant = constant_score_field(8, 3.5)
        no_dc = WalshPlan.for_field(constant, budget=12)
        memory = WalshScoreMemory(no_dc)
        memory.observe_field(constant)
        self.assertEqual(memory.finalize().reconstruct(), (0.0,) * 256)

        delta = delta_score_field(8, 73, amplitude=2.0)
        full = WalshScoreMemory(WalshPlan.full_bank(delta))
        full.observe_field(delta)
        self.assertEqual(full.finalize().freeze_ranking().order[0], 73)

        first = candidate_id_null_field(8, seed=5)
        second = candidate_id_null_field(8, seed=5)
        third = candidate_id_null_field(8, seed=6)
        self.assertEqual(first, second)
        self.assertNotEqual(score_field_sha256(first), score_field_sha256(third))

    def test_incomplete_duplicate_and_invalid_updates_are_rejected(self):
        field = tuple(float(index) for index in range(8))
        plan = WalshPlan.full_bank(field)
        incomplete = WalshScoreMemory(plan)
        incomplete.observe(0, field[0])
        with self.assertRaisesRegex(WalshMemoryError, "complete domain passes"):
            incomplete.finalize()

        malformed = WalshScoreMemory(plan)
        # Eight observations, but address 7 is replaced by a duplicate address 0.
        malformed.observe_many((address, field[address]) for address in range(7))
        malformed.observe(0, field[0])
        with self.assertRaisesRegex(WalshMemoryError, "address moments"):
            malformed.finalize()

        transactional = WalshScoreMemory(plan)
        with self.assertRaises(WalshMemoryError):
            transactional.observe_many([(0, 1.0), (8, 2.0)])
        self.assertEqual(transactional.observations, 0)
        with self.assertRaises(WalshMemoryError):
            transactional.observe_field(field, address_order=[0] * 8)
        with self.assertRaises(WalshMemoryError):
            transactional.observe(0, float("nan"))

        different = tuple(value + 1.0 for value in field)
        with self.assertRaisesRegex(WalshMemoryError, "field hash"):
            transactional.observe_field(different)

    def test_finalized_memory_rejects_updates(self):
        field = tuple(float(index & 1) for index in range(8))
        memory = WalshScoreMemory(WalshPlan.full_bank(field))
        memory.observe_field(field)
        first = memory.finalize()
        self.assertIs(memory.finalize(), first)
        with self.assertRaisesRegex(WalshMemoryError, "finalized"):
            memory.observe(0, 0.0)


class RankingAndEvaluationTests(unittest.TestCase):
    def test_frozen_ranking_hash_is_raw_uint16be(self):
        field = (1.0, 3.0, 3.0, -2.0)
        ranking = FrozenRanking.from_scores(field)
        self.assertEqual(ranking.order, (1, 2, 0, 3))
        raw = b"\x00\x01\x00\x02\x00\x00\x00\x03"
        self.assertEqual(ranking.order_uint16be, raw)
        self.assertEqual(ranking.order_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(ranking.describe()["target_labels_used"], 0)

    def test_approximation_metrics_are_target_blind_and_exact_at_ceiling(self):
        reference = tuple(float((index * 29) % 101) for index in range(256))
        evaluation = evaluate_approximation(reference, reference, top_ks=(32, 1, 8, 8))
        self.assertAlmostEqual(evaluation.score_pearson, 1.0)
        self.assertAlmostEqual(evaluation.rank_spearman, 1.0)
        self.assertAlmostEqual(evaluation.rank_kendall, 1.0)
        self.assertEqual(evaluation.mean_absolute_error, 0.0)
        self.assertEqual(evaluation.root_mean_square_error, 0.0)
        self.assertEqual(
            [(item.k, item.intersection, item.fraction) for item in evaluation.top_k_overlap],
            [(1, 1, 1.0), (8, 8, 1.0), (32, 32, 1.0)],
        )
        self.assertEqual(evaluation.describe()["target_labels_used"], 0)

    def test_target_rank_requires_separate_bound_label(self):
        reference = tuple(float(index) for index in range(16))
        ranking = FrozenRanking.from_scores(reference)
        label = TargetAddressLabel(
            address=15,
            reference_field_sha256=score_field_sha256(reference),
            source_sha256="a" * 64,
        )
        result = evaluate_target_rank(ranking, label)
        self.assertEqual(result.rank, 1)
        self.assertEqual(result.describe()["target_labels_used"], 1)
        wrong = TargetAddressLabel(
            address=15,
            reference_field_sha256="b" * 64,
            source_sha256="a" * 64,
        )
        with self.assertRaisesRegex(WalshMemoryError, "different reference"):
            evaluate_target_rank(ranking, wrong)

    def test_evaluation_rejects_bad_domains_and_cutoffs(self):
        with self.assertRaises(WalshMemoryError):
            evaluate_approximation((0.0, 1.0), (0.0, 1.0, 2.0, 3.0))
        with self.assertRaises(WalshMemoryError):
            evaluate_approximation((0.0, 1.0), (0.0, 1.0), top_ks=(0,))
        with self.assertRaises(WalshMemoryError):
            FrozenRanking.from_scores((0.0, float("inf")))


if __name__ == "__main__":
    unittest.main()
