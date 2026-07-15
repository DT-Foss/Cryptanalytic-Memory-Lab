import json
import math
import random
import unittest

from o1_crypto_lab.multislot_spectral import (
    CALIBRATION_ONLY_FAMILY,
    DIRECT12_SIZE,
    POOLED_TRAIN_CALIBRATION_FAMILY,
    SLOT_COUNT,
    SLOT_SIZE,
    UNIVERSAL_TRAIN_FAMILY,
    MultiSlotWalshMaskPolicy,
    MultiSlotWalshMemory,
    MultiSlotWalshPlan,
    join_direct12_address,
    join_direct12_slots,
    learn_calibration_only_average_energy_policy,
    learn_pooled_average_energy_policy,
    learn_universal_average_energy_policy,
    split_direct12_address,
    split_direct12_field,
)
from o1_crypto_lab.walsh_memory import WalshMemoryError, WalshPlan, walsh_character


def character_field(mask, amplitude=1.0, extra_mask=None, extra_amplitude=0.0):
    return tuple(
        amplitude * walsh_character(mask, address, n_bits=8)
        + (
            extra_amplitude * walsh_character(extra_mask, address, n_bits=8)
            if extra_mask is not None
            else 0.0
        )
        for address in range(SLOT_SIZE)
    )


def calibration_field(mask=17):
    return join_direct12_slots(
        tuple(
            character_field(mask, amplitude=float(slot + 1), extra_mask=91, extra_amplitude=0.01)
            for slot in range(SLOT_COUNT)
        )
    )


class Direct12MappingTests(unittest.TestCase):
    def test_address_mapping_is_bijective_and_matches_low4_high8_contract(self):
        seen = set()
        for address in range(DIRECT12_SIZE):
            slot, high8 = split_direct12_address(address)
            self.assertEqual(slot, address & 0xF)
            self.assertEqual(high8, address >> 4)
            rebuilt = join_direct12_address(slot, high8)
            self.assertEqual(rebuilt, address)
            seen.add(rebuilt)
        self.assertEqual(len(seen), DIRECT12_SIZE)
        with self.assertRaises(WalshMemoryError):
            split_direct12_address(DIRECT12_SIZE)
        with self.assertRaises(WalshMemoryError):
            join_direct12_address(16, 0)

    def test_field_split_join_round_trip_has_canonical_slot_layout(self):
        field = tuple(float(address) for address in range(DIRECT12_SIZE))
        slots = split_direct12_field(field)
        self.assertEqual(len(slots), 16)
        self.assertTrue(all(len(slot) == 256 for slot in slots))
        self.assertEqual(slots[7][193], float((193 << 4) | 7))
        self.assertEqual(join_direct12_slots(slots), field)
        with self.assertRaises(WalshMemoryError):
            join_direct12_slots(slots[:-1])


class MaskPolicyTests(unittest.TestCase):
    def test_universal_policy_is_scale_fair_order_invariant_and_deterministic(self):
        # The same spectral proportions at amplitudes 1e-6 and 1e6 must contribute
        # equally after per-field energy normalization.
        small = character_field(203, amplitude=1e-6, extra_mask=37, extra_amplitude=2e-7)
        large = character_field(203, amplitude=1e6, extra_mask=37, extra_amplitude=2e5)
        another = character_field(91, amplitude=3.0)
        left = learn_universal_average_energy_policy(
            [small, large, another], budget=3
        )
        right = learn_universal_average_energy_policy(
            [another, large, small], budget=3
        )
        self.assertEqual(left.family, UNIVERSAL_TRAIN_FAMILY)
        self.assertEqual(left.policy_sha256, right.policy_sha256)
        self.assertEqual(left.masks, right.masks)
        self.assertEqual(set(left.masks), {37, 91, 203})
        self.assertNotIn(0, left.masks)
        self.assertAlmostEqual(sum(left.average_normalized_energy), 1.0, places=12)
        restored = MultiSlotWalshMaskPolicy.from_dict(json.loads(left.to_json()))
        self.assertEqual(restored, left)

    def test_three_source_policies_have_separate_provenance_and_expected_masks(self):
        train = [character_field(200, amplitude=9.0)]
        calibration = calibration_field(mask=17)
        universal = MultiSlotWalshMaskPolicy.universal_train(train, budget=1)
        pooled = learn_pooled_average_energy_policy(train, calibration, budget=1)
        calibration_only = learn_calibration_only_average_energy_policy(
            calibration, budget=1
        )
        self.assertEqual(universal.masks, (200,))
        self.assertEqual(pooled.masks, (17,))
        self.assertEqual(calibration_only.masks, (17,))
        self.assertEqual(pooled.family, POOLED_TRAIN_CALIBRATION_FAMILY)
        self.assertEqual(calibration_only.family, CALIBRATION_ONLY_FAMILY)
        self.assertEqual(len(pooled.train_field_sha256s), 1)
        self.assertEqual(len(pooled.calibration_slot_sha256s), 16)
        self.assertEqual(len(calibration_only.calibration_slot_sha256s), 16)
        self.assertEqual(calibration_only.train_field_sha256s, ())
        self.assertEqual(pooled.describe()["target_labels_used"], 0)

    def test_ties_use_numeric_mask_and_zero_energy_is_rejected(self):
        tied = tuple(
            walsh_character(41, address, n_bits=8)
            + walsh_character(19, address, n_bits=8)
            for address in range(SLOT_SIZE)
        )
        policy = MultiSlotWalshMaskPolicy.universal_train([tied], budget=1)
        self.assertEqual(policy.masks, (19,))
        with self.assertRaisesRegex(WalshMemoryError, "positive finite non-DC"):
            MultiSlotWalshMaskPolicy.universal_train([(1.0,) * SLOT_SIZE], budget=1)
        with self.assertRaisesRegex(WalshMemoryError, r"\[1, 255\]"):
            MultiSlotWalshMaskPolicy.universal_train([tied], budget=256)


class PlanAndMemoryTests(unittest.TestCase):
    @staticmethod
    def deployment_field():
        return tuple(
            math.sin(address / 31.0)
            + math.cos(address / 67.0) * 0.3
            + ((address * 19) % 23) / 101.0
            for address in range(DIRECT12_SIZE)
        )

    def test_plan_hash_binds_policy_sources_slots_and_round_trips(self):
        deployment = self.deployment_field()
        policy = MultiSlotWalshMaskPolicy.universal_train(
            [character_field(7), character_field(89)], budget=2
        )
        left = MultiSlotWalshPlan.for_deployment_field(deployment, policy)
        right = MultiSlotWalshPlan.for_deployment_field(deployment, policy)
        self.assertEqual(left.plan_sha256, right.plan_sha256)
        self.assertEqual(len(left.slot_plans), 16)
        self.assertTrue(all(plan.masks == policy.masks for plan in left.slot_plans))
        self.assertTrue(
            all(
                plan.mask_source_field_sha256 == policy.policy_sha256
                for plan in left.slot_plans
            )
        )
        changed = list(deployment)
        changed[37] += 0.5
        changed_plan = MultiSlotWalshPlan.for_deployment_field(changed, policy)
        self.assertNotEqual(left.plan_sha256, changed_plan.plan_sha256)
        restored = MultiSlotWalshPlan.from_dict(json.loads(left.to_json()))
        self.assertEqual(restored, left)

    def test_stream_coverage_rejects_incomplete_duplicate_and_uneven_slot_passes(self):
        deployment = self.deployment_field()
        policy = MultiSlotWalshMaskPolicy.universal_train(
            [character_field(7), character_field(89)], budget=2
        )
        plan = MultiSlotWalshPlan.for_deployment_field(deployment, policy)

        incomplete = MultiSlotWalshMemory(plan)
        for address in range(DIRECT12_SIZE - 1):
            incomplete.observe(address, deployment[address])
        with self.assertRaises(WalshMemoryError):
            incomplete.finalize()

        duplicate = MultiSlotWalshMemory(plan)
        for address in range(DIRECT12_SIZE - 1):
            duplicate.observe(address, deployment[address])
        duplicate.observe(0, deployment[0])
        with self.assertRaises(WalshMemoryError):
            duplicate.finalize()

        uneven = MultiSlotWalshMemory(plan)
        uneven.observe_field(deployment)
        for high8 in range(SLOT_SIZE):
            address = join_direct12_address(0, high8)
            uneven.observe(address, deployment[address])
        with self.assertRaisesRegex(WalshMemoryError, "same number"):
            uneven.finalize()

    def test_full_basis_ceiling_is_exact_and_freezes_global_ranking(self):
        deployment = self.deployment_field()
        policy = MultiSlotWalshMaskPolicy.full_basis_ceiling()
        plan = MultiSlotWalshPlan.for_deployment_field(deployment, policy)
        memory = MultiSlotWalshMemory(plan)
        order = list(range(DIRECT12_SIZE))
        random.Random(349).shuffle(order)
        memory.observe_field(deployment, address_order=order)
        frozen = memory.finalize()
        reconstructed = frozen.reconstruct()
        self.assertEqual(frozen.completed_passes, 1)
        self.assertEqual(frozen.observations, DIRECT12_SIZE)
        for expected, actual in zip(deployment, reconstructed):
            self.assertAlmostEqual(expected, actual, places=11)
        expected_order = tuple(
            sorted(range(DIRECT12_SIZE), key=lambda address: (-deployment[address], address))
        )
        self.assertEqual(frozen.freeze_ranking().order, expected_order)
        self.assertEqual(memory.retained_candidate_rows, 0)
        self.assertEqual(memory.retained_key_value_entries, 0)

    def test_matched_spectral_state_and_16x_integrity_are_reported_honestly(self):
        deployment = self.deployment_field()
        policy = MultiSlotWalshMaskPolicy.universal_train(
            [character_field(mask) for mask in range(1, 17)], budget=16
        )
        plan = MultiSlotWalshPlan.for_deployment_field(deployment, policy)
        matched_global = WalshPlan.for_field(deployment, budget=16 * 16)
        self.assertEqual(plan.masks_per_slot, 16)
        self.assertEqual(plan.spectral_state_scalars, matched_global.state_scalars)
        self.assertEqual(plan.matched_single_bank_spectral_scalars, 256)
        self.assertEqual(plan.integrity_state_scalars, 16 * 5)
        self.assertEqual(plan.serialized_spectral_state_bytes, 256 * 8)
        self.assertEqual(plan.serialized_integrity_state_bytes, 16 * 5 * 8)
        self.assertEqual(
            plan.serialized_online_state_bytes,
            (256 + 16 * 5) * 8,
        )
        description = plan.describe()
        self.assertEqual(
            description["work"]["full_direct12_pass_character_evaluations"],
            DIRECT12_SIZE * 16,
        )
        self.assertEqual(description["state"]["retained_candidate_rows"], 0)
        self.assertEqual(description["target_labels_used"], 0)


if __name__ == "__main__":
    unittest.main()
