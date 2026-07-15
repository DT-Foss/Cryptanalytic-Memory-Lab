import unittest

from o1_crypto_lab.benchmark import BenchmarkConfig, run_benchmark


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.config = BenchmarkConfig(
            n_bits=64,
            seeds=(1, 7, 42),
            haystack_lengths=(0, 64, 4096),
            holographic_channels=32,
            undersized_slots=16,
            evidence_relations=(1, 32, 256, 1024),
            weak_accuracy=0.55,
        )

    def test_is_deterministic_and_hashes_entire_result(self):
        first = run_benchmark(self.config)
        second = run_benchmark(self.config)
        self.assertEqual(first, second)
        self.assertEqual(len(first["result_sha256"]), 64)
        self.assertTrue(first["composition"]["gate_passed"])
        memory_row = first["memory"]["rows"][0]
        self.assertIn("state_precision_bits", memory_row)
        self.assertIn("state_dtype", memory_row)
        self.assertGreater(memory_row["serialized_state_bytes"], 0)
        evidence_row = first["evidence"]["rows"][-1]
        self.assertEqual(
            evidence_row["relation_vectors_consumed"], evidence_row["relations"]
        )
        self.assertEqual(
            evidence_row["evidence_scalars_consumed"],
            evidence_row["relations"] * self.config.n_bits,
        )

    def test_length_sweep_replays_same_memory_problem(self):
        result = run_benchmark(self.config)
        grouped = {}
        for row in result["memory"]["rows"]:
            grouped.setdefault((row["seed"], row["model"]), []).append(
                row["bit_accuracy"]
            )
            if row["model"] == "full_context_attention_ceiling":
                self.assertEqual(
                    row["state_frozen_through_haystack"],
                    row["haystack_length"] == 0,
                )
            else:
                self.assertTrue(row["state_frozen_through_haystack"])
        self.assertTrue(all(len(set(values)) == 1 for values in grouped.values()))
        direct = [
            row
            for row in result["memory"]["rows"]
            if row["model"] == "direct_bit_vault"
        ]
        self.assertTrue(all(row["exact_all_bits"] for row in direct))
        ceiling = [
            row
            for row in result["memory"]["rows"]
            if row["model"] == "full_context_attention_ceiling"
        ]
        self.assertTrue(all(row["exact_all_bits"] for row in ceiling))
        by_length = {row["haystack_length"]: row for row in ceiling if row["seed"] == 1}
        self.assertGreater(
            by_length[4096]["state_scalars"], by_length[0]["state_scalars"]
        )

    def test_independent_signal_amplifies_but_controls_do_not(self):
        result = run_benchmark(self.config)
        at_max = {
            row["mode"]: row
            for row in result["evidence"]["summary"]
            if row["relations"] == 1024
        }
        self.assertGreater(at_max["independent_weak_signal"]["mean_bit_accuracy"], 0.9)
        self.assertLess(at_max["no_signal_control"]["mean_bit_accuracy"], 0.65)
        self.assertLess(
            at_max["perfectly_correlated_error_control"]["mean_bit_accuracy"],
            0.7,
        )

    def test_config_rejects_unsorted_sweeps_and_unknown_schema(self):
        with self.assertRaises(ValueError):
            BenchmarkConfig(haystack_lengths=(2, 1)).validate()
        with self.assertRaises(ValueError):
            BenchmarkConfig(schema="future").validate()
        with self.assertRaises(TypeError):
            BenchmarkConfig(n_bits=2.5).validate()
        with self.assertRaises(TypeError):
            BenchmarkConfig(seeds=(True,)).validate()
        with self.assertRaisesRegex(ValueError, "holographic_equal_budget"):
            BenchmarkConfig(holographic_channels=127).validate()
        with self.assertRaisesRegex(ValueError, "countsketch_under_capacity"):
            BenchmarkConfig(undersized_slots=256).validate()


if __name__ == "__main__":
    unittest.main()
