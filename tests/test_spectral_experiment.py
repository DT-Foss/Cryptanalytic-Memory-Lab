import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.spectral_experiment import (
    GlobalWalshArm,
    QuantizedArm,
    SpectralExperimentError,
    deterministic_random_masks,
    run_bounded_memory_tournament,
)


class SpectralExperimentUnitTests(unittest.TestCase):
    def test_candidate_id_random_control_is_deterministic_unique_and_dc_free(self):
        left = deterministic_random_masks(12, 218, seed=17)
        right = deterministic_random_masks(12, 218, seed=17)
        other = deterministic_random_masks(12, 218, seed=29)
        self.assertEqual(left, right)
        self.assertNotEqual(left, other)
        self.assertEqual(len(left), len(set(left)))
        self.assertNotIn(0, left)

    def test_global_full_bank_ceiling_reconstructs_and_freezes_exact_order(self):
        field = tuple(float(((index * 37) % 257) - 128) for index in range(4096))
        arm = GlobalWalshArm(
            arm_id="test-full-bank",
            family="full-bank-ceiling",
            masks=tuple(range(4096)),
            mask_source_field_sha256=None,
            o1o_eligible=False,
        )
        result = arm.execute(field, top_ks=(1, 32, 128))
        self.assertAlmostEqual(result.evaluation["rank_spearman"], 1.0)
        self.assertEqual(result.order, tuple(sorted(range(4096), key=lambda i: (-field[i], i))))
        self.assertFalse(result.o1o_eligible)

    def test_invalid_random_mask_requests_fail_closed(self):
        for budget in (0, 4096):
            with self.assertRaises(SpectralExperimentError):
                deterministic_random_masks(12, budget, seed=1)

    def test_quantized_future_template_runs_without_calibration_vector(self):
        arm = QuantizedArm(
            arm_id="frozen-4bit",
            input_bits=4,
            headroom=1.25,
            calibration_field_sha256="a" * 64,
            slot_scales=(0.25,) * 16,
            o1o_eligible=True,
        )
        restored = QuantizedArm.from_template(arm.describe_template())
        self.assertEqual(restored, arm)
        self.assertFalse(hasattr(restored, "calibration_scores"))
        deployment = tuple(float((index % 31) - 15) for index in range(4096))
        plan = restored.plan_for_deployment(deployment)
        self.assertEqual(plan.slot_scales, (0.25,) * 16)
        self.assertNotEqual(
            plan.deployment_field_sha256, plan.calibration_field_sha256
        )


@unittest.skipUnless(
    os.environ.get("O1_CRYPTO_DIRECT12_REAL") == "1",
    "set O1_CRYPTO_DIRECT12_REAL=1 for the immutable O1C-0003/0004 tournament",
)
class RealBoundedMemoryTournamentTests(unittest.TestCase):
    def test_o1o_freezes_before_a349_and_all_orders_precede_truth(self):
        root = Path(__file__).resolve().parents[1]
        callback_phases = []
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        receipt_root = Path(temporary.name)

        def canonical_sha256(value):
            return hashlib.sha256(
                json.dumps(
                    value,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            ).hexdigest()

        def selector_frozen(value):
            callback_phases.append("SELECTOR")
            self.assertFalse(value["A349_field_opened"])
            self.assertFalse(
                value["deployment_binding"]["score_content_exposed_to_selector"]
            )
            self.assertFalse(value["deployment_binding"]["score_content_parsed"])
            self.assertEqual(value["A349_labels_read"], 0)
            artifact = receipt_root / "future.json"
            artifact.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            return {
                "schema": "o1-crypto-future-template-persistence-receipt-v1",
                "persisted": True,
                "future_template_sha256": value["future_template_sha256"],
                "persisted_payload_sha256": canonical_sha256(value),
                "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }

        def orders_frozen(value, orders):
            callback_phases.append("ORDERS")
            self.assertEqual(value["complete_A349_orders"], len(orders))
            self.assertGreaterEqual(len(orders), 80)
            self.assertTrue(all(len(order) == 4096 for order in orders.values()))
            self.assertEqual(value["A348_labels_read"], 0)
            self.assertEqual(value["A349_labels_read"], 0)
            pre_reveal = receipt_root / "pre_reveal.json"
            pre_reveal.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
            order_hashes = {}
            for arm_id, order in sorted(orders.items()):
                raw = b"".join(address.to_bytes(2, "big") for address in order)
                artifact = receipt_root / f"{arm_id}.uint16be"
                artifact.write_bytes(raw)
                order_hashes[arm_id] = hashlib.sha256(raw).hexdigest()
            return {
                "schema": "o1-crypto-orders-persistence-receipt-v1",
                "persisted": True,
                "pre_reveal_sha256": value["pre_reveal_sha256"],
                "pre_reveal_artifact_sha256": hashlib.sha256(
                    pre_reveal.read_bytes()
                ).hexdigest(),
                "order_count": len(orders),
                "order_artifact_sha256_by_arm": order_hashes,
                "order_artifact_set_sha256": canonical_sha256(order_hashes),
            }

        result = run_bounded_memory_tournament(
            root / "configs/bounded_memory_tournament_v1.json",
            lab_root=root,
            on_selector_frozen=selector_frozen,
            on_orders_frozen=orders_frozen,
        )
        self.assertEqual(callback_phases, ["SELECTOR", "ORDERS"])
        self.assertTrue(result.success_gate_passed)
        metrics = result.metrics()
        self.assertEqual(
            metrics["selected_arm"]["name"],
            "quantized-bit-vault-4bit-h1.25",
        )
        self.assertEqual(metrics["selected_arm"]["labels"], ["CONTROL"])
        self.assertGreater(
            metrics["comparisons"]["quantized_4bit_h1_25_A349_rank_spearman"],
            0.98,
        )
        self.assertEqual(metrics["labels"]["A349_target_labels_read"], 0)


if __name__ == "__main__":
    unittest.main()
