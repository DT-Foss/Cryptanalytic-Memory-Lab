import hashlib
import json
import math
import unittest

from o1_crypto_lab.ising_memory import (
    COEFFICIENT_COUNT,
    DOMAIN_SIZE,
    ISING_MASKS,
    LINEAR_MASKS,
    MASK_BANK_SHA256,
    FrozenIsingMemory,
    IsingEvidenceMemory,
    IsingMemoryError,
    IsingMemoryPlan,
    evidence_field_sha256,
)


def _character(mask: int, address: int) -> int:
    return -1 if (mask & address).bit_count() & 1 else 1


def _target_field(target: int) -> tuple[float, ...]:
    single_masks = tuple(1 << bit for bit in range(12))
    return tuple(
        float(
            sum(
                _character(mask, target) * _character(mask, address)
                for mask in single_masks
            )
        )
        for address in range(DOMAIN_SIZE)
    )


class IsingProjectionTests(unittest.TestCase):
    def test_exact_degree_one_two_projection_discards_dc_and_degree_three(self):
        degree_one = 1
        degree_two = 3
        another_degree_two = (1 << 4) | (1 << 9)
        degree_three = 7
        evidence = tuple(
            5.25
            + 1.5 * _character(degree_one, address)
            - 2.25 * _character(degree_two, address)
            + 0.75 * _character(another_degree_two, address)
            + 4.0 * _character(degree_three, address)
            for address in range(DOMAIN_SIZE)
        )
        expected = tuple(
            1.5 * _character(degree_one, address)
            - 2.25 * _character(degree_two, address)
            + 0.75 * _character(another_degree_two, address)
            for address in range(DOMAIN_SIZE)
        )

        memory = IsingEvidenceMemory(IsingMemoryPlan.for_evidence(evidence))
        memory.observe_field(evidence)
        frozen = memory.finalize()

        by_mask = dict(zip(ISING_MASKS, frozen.coefficients))
        self.assertEqual(by_mask[degree_one], 1.5)
        self.assertEqual(by_mask[degree_two], -2.25)
        self.assertEqual(by_mask[another_degree_two], 0.75)
        for actual, wanted in zip(frozen.reconstruct(), expected):
            self.assertAlmostEqual(actual, wanted, places=12)
        for address in (0, 1, 17, 511, 4095):
            self.assertAlmostEqual(frozen.query(address), expected[address], places=12)

    def test_frozen_target_order_is_complete_deterministic_and_target_first(self):
        target = 0xA53
        evidence = _target_field(target)
        memory = IsingEvidenceMemory(IsingMemoryPlan.for_evidence(evidence))
        memory.observe_many(enumerate(evidence))
        frozen = memory.finalize()

        self.assertEqual(frozen.order[0], target)
        self.assertEqual(len(frozen.order), DOMAIN_SIZE)
        self.assertEqual(len(set(frozen.order)), DOMAIN_SIZE)
        self.assertEqual(frozen.freeze_ranking().rank(target), 1)
        self.assertEqual(
            frozen.order_uint16be_sha256,
            frozen.freeze_ranking().order_sha256,
        )
        raw_order = b"".join(address.to_bytes(2, "big") for address in frozen.order)
        self.assertEqual(
            frozen.order_uint16be_sha256,
            hashlib.sha256(raw_order).hexdigest(),
        )
        second = IsingEvidenceMemory(IsingMemoryPlan.for_evidence(evidence))
        second.observe_field(evidence)
        self.assertEqual(second.finalize().order, frozen.order)


class IsingCanonicalStreamTests(unittest.TestCase):
    def test_duplicate_out_of_order_and_incomplete_streams_are_rejected(self):
        duplicate = IsingEvidenceMemory()
        duplicate.observe(0, 1.0)
        with self.assertRaisesRegex(IsingMemoryError, "expected address 1"):
            duplicate.observe(0, 1.0)
        self.assertEqual(duplicate.observations, 1)

        out_of_order = IsingEvidenceMemory()
        with self.assertRaisesRegex(IsingMemoryError, "expected address 0"):
            out_of_order.observe(1, 1.0)
        self.assertEqual(out_of_order.observations, 0)

        incomplete = IsingEvidenceMemory()
        incomplete.observe_many((address, 0.0) for address in range(31))
        with self.assertRaisesRegex(IsingMemoryError, "0..4095 exactly once"):
            incomplete.finalize()

    def test_nonfinite_boolean_and_forward_only_batches_are_rejected(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            memory = IsingEvidenceMemory()
            with self.assertRaisesRegex(IsingMemoryError, "finite scalar"):
                memory.observe(0, value)
            self.assertEqual(memory.observations, 0)

        boolean_address = IsingEvidenceMemory()
        with self.assertRaisesRegex(IsingMemoryError, "exact integer"):
            boolean_address.observe(False, 0.0)
        boolean_evidence = IsingEvidenceMemory()
        with self.assertRaisesRegex(IsingMemoryError, "finite scalar"):
            boolean_evidence.observe(0, True)

        forward_only = IsingEvidenceMemory()
        with self.assertRaisesRegex(IsingMemoryError, "expected address 2"):
            forward_only.observe_many(((0, 1.0), (1, 2.0), (1, 3.0)))
        self.assertEqual(forward_only.observations, 2)
        self.assertEqual(forward_only.next_address, 2)

        huge = IsingEvidenceMemory()
        with self.assertRaisesRegex(IsingMemoryError, "finite scalar"):
            huge.observe(0, 10**10000)
        self.assertEqual(huge.observations, 0)

    def test_complete_stream_cannot_be_replayed_or_updated_after_freeze(self):
        evidence = (0.0,) * DOMAIN_SIZE
        memory = IsingEvidenceMemory()
        memory.observe_field(evidence)
        with self.assertRaisesRegex(IsingMemoryError, "already complete"):
            memory.observe(DOMAIN_SIZE, 0.0)
        frozen = memory.finalize()
        self.assertIs(memory.finalize(), frozen)
        with self.assertRaisesRegex(IsingMemoryError, "finalized"):
            memory.observe(0, 0.0)


class IsingStateIntegrityTests(unittest.TestCase):
    def test_implicit_mask_bank_and_state_accounting_are_exact(self):
        plan = IsingMemoryPlan()
        described = plan.describe()
        self.assertEqual(COEFFICIENT_COUNT, 78)
        self.assertEqual(len(ISING_MASKS), 78)
        self.assertEqual(sum(mask.bit_count() == 1 for mask in ISING_MASKS), 12)
        self.assertEqual(sum(mask.bit_count() == 2 for mask in ISING_MASKS), 66)
        self.assertNotIn(0, ISING_MASKS)
        self.assertEqual(
            described["projection"]["implicit_mask_bank_sha256"],
            MASK_BANK_SHA256,
        )
        self.assertTrue(described["static_plan_storage"]["implicit_masks"])
        self.assertEqual(
            described["static_plan_storage"]["serialized_mask_bank_bytes"], 0
        )
        self.assertEqual(plan.serialized_state_bytes, 78 * 8)
        self.assertEqual(plan.serialized_integrity_bytes, 106)
        self.assertEqual(plan.serialized_online_state_bytes, 730)
        self.assertEqual(
            plan.maximum_serialized_logical_mechanism_state_bytes, 762
        )
        bound = IsingMemoryPlan(expected_evidence_sha256="0" * 64)
        self.assertEqual(plan.serialized_bound_hash_bytes, 32)
        self.assertEqual(bound.serialized_bound_hash_bytes, 64)
        self.assertEqual(
            bound.maximum_serialized_logical_mechanism_state_bytes, 794
        )
        memory = IsingEvidenceMemory(plan)
        self.assertEqual(memory.retained_candidate_rows, 0)
        self.assertEqual(memory.retained_evidence_values, 0)
        self.assertEqual(memory.retained_key_value_entries, 0)

        unary = IsingMemoryPlan(
            expected_evidence_sha256="0" * 64,
            name="direct12-unary-bit-vault",
            support_id="degree1",
        )
        self.assertEqual(unary.masks, LINEAR_MASKS)
        self.assertEqual(unary.state_scalars, 12)
        self.assertEqual(unary.serialized_state_bytes, 96)
        self.assertEqual(unary.serialized_online_state_bytes, 202)
        self.assertEqual(
            unary.maximum_serialized_logical_mechanism_state_bytes,
            266,
        )

    def test_plan_and_frozen_state_hash_round_trip_and_tamper_fail_closed(self):
        evidence = tuple(
            math.sin(address / 31.0) + (address % 13) / 17.0
            for address in range(DOMAIN_SIZE)
        )
        plan = IsingMemoryPlan.for_evidence(evidence, name="hash-bound-ising")
        restored_plan = IsingMemoryPlan.from_dict(json.loads(plan.to_json()))
        self.assertEqual(restored_plan, plan)
        plan_tamper = json.loads(plan.to_json())
        plan_tamper["online_state"]["float64_accumulators"] = 77
        with self.assertRaisesRegex(IsingMemoryError, "SHA-256 mismatch"):
            IsingMemoryPlan.from_dict(plan_tamper)

        memory = IsingEvidenceMemory(plan)
        memory.observe_field(evidence)
        frozen = memory.finalize()
        self.assertEqual(frozen.evidence_field_sha256, evidence_field_sha256(evidence))
        self.assertEqual(frozen.serialized_state_bytes, 624)
        self.assertEqual(frozen.serialized_frozen_state_bytes, 690)
        self.assertEqual(frozen.retained_candidate_rows, 0)
        restored = FrozenIsingMemory.from_dict(json.loads(frozen.to_json()))
        self.assertEqual(restored, frozen)
        self.assertEqual(restored.state_sha256, frozen.state_sha256)
        self.assertEqual(
            restored.coefficients_float64be_sha256,
            frozen.coefficients_float64be_sha256,
        )
        compact = frozen.to_bytes()
        self.assertEqual(len(compact), 690)
        self.assertEqual(
            FrozenIsingMemory.from_bytes(compact, plan=plan),
            frozen,
        )
        wrong_plan = IsingMemoryPlan.for_evidence(evidence, name="wrong-plan")
        with self.assertRaisesRegex(IsingMemoryError, "plan binding"):
            FrozenIsingMemory.from_bytes(compact, plan=wrong_plan)

        state_tamper = json.loads(frozen.to_json())
        state_tamper["coefficients"][0] += 0.5
        with self.assertRaisesRegex(IsingMemoryError, "SHA-256 mismatch"):
            FrozenIsingMemory.from_dict(state_tamper)

    def test_reference_hashes_and_tied_order_are_independent_goldens(self):
        evidence = (0.0,) * DOMAIN_SIZE
        self.assertEqual(
            MASK_BANK_SHA256,
            "b2764f11fc8265aa56c8616e6d3d45939e96fa838e92b43ba0ad73501dd4ea20",
        )
        self.assertEqual(
            evidence_field_sha256(evidence),
            "6c8a4c12f62526eb8820baf9a53263603b08fc667d617bd0fac65083ad0db07c",
        )
        memory = IsingEvidenceMemory(IsingMemoryPlan.for_evidence(evidence))
        memory.observe_field(evidence)
        frozen = memory.finalize()
        self.assertEqual(frozen.order, tuple(range(DOMAIN_SIZE)))
        self.assertEqual(
            frozen.order_uint16be_sha256,
            "a02cf28d81488fd0b2bbde4d6d5b035210669370a220eb257b016d7bf2dfe68e",
        )

    def test_unary_binary_roundtrip_and_projection_exclude_pair_modes(self):
        unary = 1 << 5
        pair = (1 << 1) | (1 << 9)
        evidence = tuple(
            3.0 * _character(unary, address)
            + 7.0 * _character(pair, address)
            for address in range(DOMAIN_SIZE)
        )
        plan = IsingMemoryPlan.for_evidence(
            evidence,
            name="unary-only",
            support_id="degree1",
        )
        memory = IsingEvidenceMemory(plan)
        memory.observe_field(evidence)
        frozen = memory.finalize()
        expected = tuple(
            3.0 * _character(unary, address)
            for address in range(DOMAIN_SIZE)
        )
        for actual, wanted in zip(frozen.reconstruct(), expected):
            self.assertAlmostEqual(actual, wanted, places=12)
        compact = frozen.to_bytes()
        self.assertEqual(len(compact), 162)
        self.assertEqual(
            FrozenIsingMemory.from_bytes(compact, plan=plan),
            frozen,
        )

    def test_bound_hash_rejects_a_different_complete_field(self):
        expected = (0.0,) * DOMAIN_SIZE
        changed = list(expected)
        changed[-1] = 1.0
        memory = IsingEvidenceMemory(IsingMemoryPlan.for_evidence(expected))
        memory.observe_field(tuple(changed))
        with self.assertRaisesRegex(IsingMemoryError, "hash differs"):
            memory.finalize()


if __name__ == "__main__":
    unittest.main()
