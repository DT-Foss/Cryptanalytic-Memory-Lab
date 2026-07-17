from __future__ import annotations

import unittest

import numpy as np

from o1_crypto_lab.living_inverse_model import (
    ReaderTrainingConfig,
    binary_nll_bits,
    deserialize_reader,
    evaluate_posteriors,
    posterior_from_logits,
    select_shrinkage,
    torch,
    train_reader,
)


@unittest.skipIf(torch is None, "optional torch training dependency is absent")
class LivingInverseModelTests(unittest.TestCase):
    def setUp(self) -> None:
        rng = np.random.default_rng(7)
        self.features = rng.integers(0, 2, size=(192, 16)).astype(np.float32)
        pattern = np.tile(self.features[:, :8], (1, 32))[:, :256]
        self.labels = pattern.astype(np.float32)
        self.auxiliary = np.concatenate(
            (self.features[:, :8], 1.0 - self.features[:, :8]), axis=1
        ).astype(np.float32)
        self.config = ReaderTrainingConfig(
            hidden_dimension=32,
            epochs=8,
            batch_size=48,
            learning_rate=0.01,
            weight_decay=1e-5,
            auxiliary_weight=0.1,
            cpu_threads=1,
            seed=11,
        )

    def test_training_is_deterministic_and_model_round_trips(self) -> None:
        first = train_reader(
            self.features,
            self.labels,
            self.config,
            auxiliary_labels=self.auxiliary,
        )
        second = train_reader(
            self.features,
            self.labels,
            self.config,
            auxiliary_labels=self.auxiliary,
        )
        self.assertEqual(first.model_sha256, second.model_sha256)
        self.assertEqual(first.epoch_losses, second.epoch_losses)
        logits = first.predict_logits(self.features)
        frozen = first.frozen_bytes()
        restored = deserialize_reader(frozen)
        with torch.no_grad():
            restored_logits, _ = restored(torch.from_numpy(self.features))
        np.testing.assert_array_equal(
            logits, restored_logits.numpy().astype(np.float64)
        )
        self.assertLess(binary_nll_bits(logits, self.labels, 1.0), 100.0)

    def test_calibration_and_evaluation_report_signal(self) -> None:
        logits = np.where(self.labels == 1.0, 2.0, -2.0)
        shrinkage, rows = select_shrinkage(
            logits, self.labels, self.config.shrinkage_grid
        )
        self.assertGreater(shrinkage, 0.0)
        self.assertEqual(len(rows), len(self.config.shrinkage_grid))
        probabilities = posterior_from_logits(logits, shrinkage)
        report = evaluate_posteriors(probabilities, self.labels)
        self.assertLess(report["mean_key_nll_bits"], 256.0)
        self.assertEqual(report["stable_bits"], 256)

    def test_zero_shrinkage_is_exact_random_baseline(self) -> None:
        logits = np.ones((4, 256), dtype=np.float64) * 100.0
        labels = np.zeros((4, 256), dtype=np.float64)
        self.assertEqual(binary_nll_bits(logits, labels, 0.0), 256.0)
        probabilities = posterior_from_logits(logits, 0.0)
        np.testing.assert_array_equal(probabilities, np.full((4, 256), 0.5))


if __name__ == "__main__":
    unittest.main()
