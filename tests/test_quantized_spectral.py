import json
import random
import unittest
from pathlib import Path

from o1_crypto_lab.quantized_spectral import (
    ACCUMULATOR_COUNT,
    DIRECT12_SIZE,
    DictionaryCeiling,
    QuantizedMultiSlotBitVault,
    QuantizedSpectralError,
    QuantizedSpectralPlan,
    dictionary_ceiling,
    quantizer_limit,
    safe_accumulator_bits,
)
from o1_crypto_lab.walsh_memory import score_field_sha256


def _paired_field(*, peak: int = 7, offset: int = 0) -> tuple[float, ...]:
    """Per-low4 zero-mean integer field with paired +/- values."""

    scores = [0.0] * DIRECT12_SIZE
    for low4 in range(16):
        for pair in range(128):
            magnitude = 1 + ((pair + low4 + offset) % peak)
            scores[((pair * 2) << 4) | low4] = float(magnitude)
            scores[((pair * 2 + 1) << 4) | low4] = float(-magnitude)
    return tuple(scores)


class QuantizedPlanTests(unittest.TestCase):
    def test_safe_widths_and_honest_packed_state_accounting(self):
        calibration = _paired_field()
        deployment = _paired_field(offset=1)
        expected = {
            4: (7, 12, 6120, 6668),
            6: (31, 14, 7140, 7688),
            8: (127, 16, 8160, 8708),
        }
        for bits, (limit, width, accumulator_bytes, total_bytes) in expected.items():
            plan = QuantizedSpectralPlan.from_calibration(
                calibration,
                deployment,
                input_bits=bits,
                headroom=1.25,
            )
            self.assertEqual(quantizer_limit(bits), limit)
            self.assertEqual(safe_accumulator_bits(bits), width)
            self.assertEqual(plan.accumulator_count, 4080)
            self.assertEqual(plan.serialized_accumulator_bytes, accumulator_bytes)
            self.assertEqual(plan.serialized_coverage_bytes, 512)
            self.assertEqual(plan.serialized_clip_telemetry_bytes, 36)
            self.assertEqual(plan.serialized_online_state_bytes, total_bytes)
            self.assertEqual(plan.serialized_static_scale_bytes, 128)
            described = plan.describe()
            self.assertEqual(
                described["online_state"]["retained_candidate_rows"], 0
            )
            self.assertFalse(
                described["static_plan_storage"][
                    "counted_as_online_recurrent_state"
                ]
            )

    def test_plan_round_trip_hashes_calibration_and_deployment_separately(self):
        calibration = _paired_field(offset=0)
        deployment = _paired_field(offset=2)
        plan = QuantizedSpectralPlan.from_calibration(
            calibration, deployment, input_bits=4, headroom=1.25
        )
        self.assertEqual(
            plan.calibration_field_sha256, score_field_sha256(calibration)
        )
        self.assertEqual(
            plan.deployment_field_sha256, score_field_sha256(deployment)
        )
        self.assertNotEqual(
            plan.calibration_field_sha256, plan.deployment_field_sha256
        )
        restored = QuantizedSpectralPlan.from_dict(json.loads(plan.to_json()))
        self.assertEqual(restored, plan)
        self.assertEqual(restored.plan_sha256, plan.plan_sha256)

        tampered = json.loads(plan.to_json())
        tampered["slot_scales"][0] *= 2.0
        with self.assertRaisesRegex(QuantizedSpectralError, "SHA-256 mismatch"):
            QuantizedSpectralPlan.from_dict(tampered)

    def test_invalid_quantizers_and_zero_calibration_are_rejected(self):
        for bits in (1, 9, True):
            with self.assertRaises(QuantizedSpectralError):
                quantizer_limit(bits)
        zeros = (0.0,) * DIRECT12_SIZE
        deployment = _paired_field()
        with self.assertRaisesRegex(QuantizedSpectralError, "no positive"):
            QuantizedSpectralPlan.from_calibration(
                zeros, deployment, input_bits=4
            )
        with self.assertRaisesRegex(QuantizedSpectralError, "at least 1.0"):
            QuantizedSpectralPlan.from_calibration(
                deployment, deployment, input_bits=4, headroom=0.99
            )


class QuantizedStreamingTests(unittest.TestCase):
    def test_full_non_dc_bank_exactly_recovers_zero_mean_quantized_slots(self):
        field = _paired_field(peak=7)
        plan = QuantizedSpectralPlan.from_calibration(
            field, field, input_bits=4, headroom=1.0
        )
        order = list(range(DIRECT12_SIZE))
        random.Random(349).shuffle(order)
        memory = QuantizedMultiSlotBitVault(plan)
        memory.observe_field(field, address_order=order)
        frozen = memory.finalize()

        self.assertEqual(frozen.state_scalars, ACCUMULATOR_COUNT)
        self.assertEqual(frozen.observations, DIRECT12_SIZE)
        self.assertEqual(frozen.retained_rows, 0)
        self.assertEqual(frozen.retained_key_value_entries, 0)
        self.assertEqual(frozen.clip_count, 0)
        self.assertTrue(frozen.input_field_hash_verified)
        self.assertEqual(len(frozen.online_state_bytes), 6668)
        self.assertEqual(len(frozen.state_sha256), 64)
        self.assertEqual(memory.online_state_bytes, frozen.online_state_bytes)
        self.assertEqual(memory.state_sha256, frozen.state_sha256)
        for expected, actual in zip(field, frozen.reconstruct()):
            self.assertAlmostEqual(actual, expected, places=12)
        for candidate_id in (0, 1, 15, 16, 2048, 4095):
            self.assertAlmostEqual(
                frozen.query(candidate_id), field[candidate_id], places=12
            )
        evaluation = frozen.evaluate(field)
        self.assertAlmostEqual(evaluation.rank_spearman, 1.0)
        self.assertEqual(evaluation.root_mean_square_error, 0.0)
        boundary = frozen.describe()["claim_boundary"]
        self.assertTrue(boundary["mechanism_claim_eligible"])
        self.assertEqual(boundary["target_labels_used"], 0)

    def test_duplicate_incomplete_and_transaction_failures_are_exact(self):
        field = _paired_field()
        plan = QuantizedSpectralPlan.from_calibration(
            field, field, input_bits=4, headroom=1.0
        )
        duplicate = QuantizedMultiSlotBitVault(plan)
        duplicate.observe(137, field[137])
        with self.assertRaisesRegex(QuantizedSpectralError, "duplicate"):
            duplicate.observe(137, field[137])
        with self.assertRaisesRegex(QuantizedSpectralError, "missing_by_low4"):
            duplicate.finalize()

        transactional = QuantizedMultiSlotBitVault(plan)
        with self.assertRaisesRegex(QuantizedSpectralError, "duplicate"):
            transactional.observe_many(
                [(0, field[0]), (1, field[1]), (0, field[0])]
            )
        self.assertEqual(transactional.observations, 0)
        self.assertEqual(
            transactional.state_sha256,
            QuantizedMultiSlotBitVault(plan).state_sha256,
        )
        with self.assertRaisesRegex(QuantizedSpectralError, "permutation"):
            transactional.observe_field(field, address_order=[0] * DIRECT12_SIZE)

    def test_state_is_order_invariant_hash_bound_and_reports_clips(self):
        calibration = _paired_field(peak=1)
        deployment = list(calibration)
        # Scale at 4 bits/headroom 1 is 1/7.  These two inputs round well outside
        # +/-7 and exercise signed per-slot telemetry.
        deployment[0] = 4.0
        deployment[16] = -4.0
        deployment = tuple(deployment)
        plan = QuantizedSpectralPlan.from_calibration(
            calibration, deployment, input_bits=4, headroom=1.0
        )
        forward = QuantizedMultiSlotBitVault(plan)
        reverse = QuantizedMultiSlotBitVault(plan)
        forward.observe_field(deployment)
        reverse.observe_field(
            deployment, address_order=tuple(reversed(range(DIRECT12_SIZE)))
        )
        left = forward.finalize()
        right = reverse.finalize()
        self.assertEqual(left.accumulators, right.accumulators)
        self.assertEqual(left.state_sha256, right.state_sha256)
        self.assertEqual(left.positive_clips[0], 1)
        self.assertEqual(left.negative_clips[0], 1)
        self.assertEqual(left.clip_count, 2)

        wrong = list(deployment)
        wrong[7] += 0.01
        with self.assertRaisesRegex(QuantizedSpectralError, "deployment hash"):
            QuantizedMultiSlotBitVault(plan).observe_field(tuple(wrong))

    def test_finalized_state_rejects_further_updates(self):
        field = _paired_field()
        plan = QuantizedSpectralPlan.from_calibration(
            field, field, input_bits=4, headroom=1.0
        )
        memory = QuantizedMultiSlotBitVault(plan)
        memory.observe_field(field)
        first = memory.finalize()
        self.assertIs(memory.finalize(), first)
        with self.assertRaisesRegex(QuantizedSpectralError, "finalized"):
            memory.observe(0, field[0])


class DictionaryCeilingTests(unittest.TestCase):
    def test_direct_quantized_table_is_explicitly_not_a_mechanism_claim(self):
        field = _paired_field()
        plan = QuantizedSpectralPlan.from_calibration(
            field, field, input_bits=4, headroom=1.0
        )
        control = dictionary_ceiling(plan, field)
        self.assertIsInstance(control, DictionaryCeiling)
        self.assertEqual(control.retained_rows, DIRECT12_SIZE)
        self.assertEqual(control.retained_key_value_entries, DIRECT12_SIZE)
        self.assertEqual(control.serialized_candidate_table_bytes, 2048)
        self.assertEqual(control.serialized_control_state_bytes, 2084)
        report = control.describe()
        self.assertEqual(report["control_family"], "dictionary_ceiling")
        self.assertFalse(report["mechanism_claim_eligible"])
        self.assertEqual(report["retained_key_value_entries"], DIRECT12_SIZE)
        self.assertAlmostEqual(control.evaluate(field).rank_spearman, 1.0)


class OptionalO1C0004RealityCheck(unittest.TestCase):
    def test_a349_transfer_matches_frozen_real_field_fidelity(self):
        root = Path(__file__).resolve().parents[1]
        runs = sorted((root / "runs").glob("*_O1C-0004_direct12-532-reproduction"))
        if not runs:
            self.skipTest("immutable O1C-0004 capsule is not present")
        artifacts = runs[-1] / "artifacts"
        try:
            calibration = tuple(
                json.loads((artifacts / "a348_score_field.json").read_text())["scores"]
            )
            deployment = tuple(
                json.loads((artifacts / "a349_score_field.json").read_text())["scores"]
            )
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self.skipTest(f"O1C-0004 score artifacts are unavailable: {exc}")

        observed = {}
        for bits in (4, 6):
            plan = QuantizedSpectralPlan.from_calibration(
                calibration,
                deployment,
                input_bits=bits,
                headroom=1.25,
            )
            memory = QuantizedMultiSlotBitVault(plan)
            memory.observe_field(deployment)
            frozen = memory.finalize()
            observed[bits] = frozen.evaluate(deployment).rank_spearman
            self.assertNotEqual(
                plan.calibration_field_sha256, plan.deployment_field_sha256
            )
            self.assertEqual(frozen.retained_key_value_entries, 0)

        self.assertAlmostEqual(observed[4], 0.9901983485302834, places=12)
        self.assertAlmostEqual(observed[6], 0.99961648791838, places=12)


if __name__ == "__main__":
    unittest.main()
