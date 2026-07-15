import json
import math
import unittest

from o1_crypto_lab.adaptive_dc_spectral import (
    ACCUMULATOR_COUNT,
    AdaptiveDCPlan,
    AdaptiveDCQuantizedVault,
    AdaptiveDCScaleCalibrator,
    AdaptiveDCSpectralError,
    AdaptiveDCTemplate,
    execute_adaptive_dc,
)


def _field() -> tuple[float, ...]:
    scores = [0.0] * 4096
    for low4 in range(16):
        dc = (low4 - 7.5) / 9.0
        for high8 in range(256):
            wave = math.sin((high8 + 1) * (low4 + 3) / 37.0)
            scores[(high8 << 4) | low4] = dc + wave
    return tuple(scores)


class AdaptiveDCPlanTests(unittest.TestCase):
    def test_state_widths_include_all_sixteen_dc_modes(self):
        field = _field()
        expected = {4: 6692, 5: 7204, 6: 7716}
        for bits, state_bytes in expected.items():
            template = AdaptiveDCTemplate(bits, 1.0, name=f"adaptive-{bits}")
            calibrator = AdaptiveDCScaleCalibrator(template)
            calibrator.observe_many(enumerate(field))
            plan = calibrator.finalize()
            self.assertEqual(ACCUMULATOR_COUNT, 4096)
            self.assertEqual(plan.serialized_online_state_bytes, state_bytes)
            self.assertEqual(plan.serialized_static_plan_bytes, 192)
            self.assertEqual(
                plan.maximum_serialized_logical_mechanism_state_bytes,
                state_bytes + 192 + 106,
            )
            self.assertEqual(plan.describe()["online_state"]["dc_accumulators"], 16)
            self.assertEqual(calibrator.logical_state_bytes, 234)
            restored = AdaptiveDCPlan.from_dict(json.loads(json.dumps(plan.describe())))
            self.assertEqual(restored, plan)
            self.assertEqual(restored.plan_sha256, plan.plan_sha256)
            boundary = plan.template.describe()["claim_boundary"]
            self.assertTrue(boundary["full_rank_fixed_domain_transform"])
            self.assertTrue(boundary["information_equivalent_to_quantized_direct_table"])
            self.assertFalse(boundary["compression_claim_eligible"])

    def test_template_and_plan_tampering_are_rejected(self):
        template = AdaptiveDCTemplate(6, 1.0)
        document = template.describe()
        document["headroom"] = 1.25
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "commitment"):
            AdaptiveDCTemplate.from_dict(document)

        calibrator = AdaptiveDCScaleCalibrator(template)
        calibrator.observe_many(enumerate(_field()))
        plan = calibrator.finalize().describe()
        plan["slot_scales"][0] *= 2.0
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "commitment"):
            AdaptiveDCPlan.from_dict(plan)

    def test_boolean_numeric_aliases_are_rejected(self):
        template = AdaptiveDCTemplate(6, 1.0).describe()
        template["headroom"] = True
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "schema"):
            AdaptiveDCTemplate.from_dict(template)

        calibrator = AdaptiveDCScaleCalibrator(AdaptiveDCTemplate(6, 1.0))
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "integer"):
            calibrator.observe(False, 0.0)

        complete = AdaptiveDCScaleCalibrator(AdaptiveDCTemplate(6, 1.0))
        complete.observe_many(enumerate(_field()))
        vault = AdaptiveDCQuantizedVault(complete.finalize())
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "integer"):
            vault.observe(False, 0.0)


class AdaptiveDCStreamingTests(unittest.TestCase):
    def test_dc_complete_bank_recovers_nonzero_slot_means(self):
        field = tuple(float((candidate & 0xF) + 1) for candidate in range(4096))
        execution = execute_adaptive_dc(
            field,
            AdaptiveDCTemplate(4, 1.0, name="constant-slot-dc"),
        )
        self.assertEqual(execution.frozen.clip_count, 0)
        self.assertEqual(execution.frozen.accumulators[0], 256 * 7)
        self.assertEqual(execution.frozen.accumulators[256], 256 * 7)
        for expected, actual in zip(field, execution.frozen.reconstruct()):
            self.assertAlmostEqual(expected, actual, places=12)
        self.assertAlmostEqual(execution.evaluation.rank_spearman, 1.0)

    def test_second_pass_hash_mismatch_poisoning_is_fail_closed(self):
        field = _field()
        calibrator = AdaptiveDCScaleCalibrator(AdaptiveDCTemplate(6, 1.0))
        calibrator.observe_many(enumerate(field))
        vault = AdaptiveDCQuantizedVault(calibrator.finalize())
        changed = list(field)
        changed[-1] += 0.25
        vault.observe_many(enumerate(changed))
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "field hash"):
            vault.finalize()
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "invalid"):
            vault.finalize()
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "invalid"):
            vault.observe(0, field[0])

    def test_both_passes_reject_noncanonical_or_incomplete_streams(self):
        field = _field()
        calibrator = AdaptiveDCScaleCalibrator(AdaptiveDCTemplate(5, 1.0))
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "expected 0"):
            calibrator.observe(1, field[1])
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "all 4096"):
            calibrator.finalize()

        complete = AdaptiveDCScaleCalibrator(AdaptiveDCTemplate(5, 1.0))
        complete.observe_many(enumerate(field))
        vault = AdaptiveDCQuantizedVault(complete.finalize())
        vault.observe(0, field[0])
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "expected 1"):
            vault.observe(0, field[0])
        with self.assertRaisesRegex(AdaptiveDCSpectralError, "invalid"):
            vault.finalize()

    def test_six_bit_execution_is_bounded_and_high_fidelity(self):
        execution = execute_adaptive_dc(
            _field(),
            AdaptiveDCTemplate(6, 1.0, name="adaptive-6bit-h1"),
        )
        self.assertLessEqual(execution.plan.serialized_online_state_bytes, 8192)
        self.assertEqual(
            execution.plan.maximum_serialized_logical_mechanism_state_bytes,
            8014,
        )
        self.assertEqual(execution.frozen.clip_count, 0)
        self.assertGreater(execution.evaluation.rank_spearman, 0.995)
        self.assertGreater(execution.evaluation.rank_kendall, 0.95)
        self.assertEqual(len(execution.order), 4096)
        self.assertEqual(len(set(execution.order)), 4096)
        report = execution.describe()
        self.assertEqual(report["passes"]["source_passes"], 2)
        self.assertEqual(report["passes"]["field_values_read"], 8192)
        self.assertEqual(report["labels_used"], 0)


if __name__ == "__main__":
    unittest.main()
