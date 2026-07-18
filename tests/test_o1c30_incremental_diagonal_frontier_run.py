from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from o1_crypto_lab.o1c30_incremental_diagonal_frontier import ARM_NAMES
from o1_crypto_lab.o1c30_incremental_diagonal_frontier_run import (
    FORMAL_CONFIG_RELATIVE,
    RIDGE_L2,
    SOURCE_CORPUS_SEED,
    O1C30RunError,
    _derive_labels,
    _frontier_diagnostic,
    load_o1c30_run_config,
    load_verified_source,
    run_capsule_from_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / FORMAL_CONFIG_RELATIVE


class O1C30ConfigTests(unittest.TestCase):
    def _document(self) -> dict[str, object]:
        value = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertIsInstance(value, dict)
        return value

    def _temporary_config(self, value: dict[str, object]) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="o1c30-config-")
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_canonical_config_pins_light_full256_contract(self) -> None:
        config = load_o1c30_run_config(CONFIG, root=ROOT)

        self.assertEqual(config.ridge_l2.hex(), RIDGE_L2.hex())
        self.assertEqual(tuple(config.top["experiment"]["feature_arms"]), ARM_NAMES)
        self.assertEqual(config.source["corpus_seed"], SOURCE_CORPUS_SEED)
        self.assertEqual(len(config.builds), 4)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 0)
        self.assertEqual(config.budgets.maximum_scientific_entropy_calls, 0)
        self.assertEqual(config.budgets.maximum_sibling_reads, 0)
        self.assertEqual(config.budgets.maximum_gpu_calls, 0)

    def test_ridge_and_control_gate_are_not_tunable(self) -> None:
        document = self._document()
        experiment = document["experiment"]
        self.assertIsInstance(experiment, dict)
        experiment["ridge_l2"] = 0.01
        with self.assertRaisesRegex(O1C30RunError, "exactly 1/768"):
            load_o1c30_run_config(self._temporary_config(document), root=ROOT)

        document = self._document()
        experiment = document["experiment"]
        self.assertIsInstance(experiment, dict)
        strong = experiment["strong_gate"]
        self.assertIsInstance(strong, dict)
        strong["required_mean_control_wins"] = ["legacy_reintegrated"]
        with self.assertRaisesRegex(O1C30RunError, "strong gate"):
            load_o1c30_run_config(self._temporary_config(document), root=ROOT)

    def test_formal_runner_rejects_noncanonical_config_before_reservation(self) -> None:
        path = self._temporary_config(self._document())
        with mock.patch(
            "o1_crypto_lab.o1c30_incremental_diagonal_frontier_run."
            "RunCapsuleManager.start"
        ) as start:
            with self.assertRaisesRegex(O1C30RunError, "canonical"):
                run_capsule_from_config(path)
        start.assert_not_called()


class O1C30SourceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_o1c30_run_config(CONFIG, root=ROOT)

    def test_real_source_preflight_never_derives_a_key(self) -> None:
        with mock.patch(
            "o1_crypto_lab.o1c30_incremental_diagonal_frontier_run._derived_target",
            side_effect=AssertionError("pre-freeze key derivation"),
        ) as derive:
            source = load_verified_source(self.config)

        derive.assert_not_called()
        self.assertEqual(source.bytes_read, 8_331_098)
        self.assertEqual(len(source.builds), 4)
        self.assertEqual(
            tuple(row.pool.action_pool_sha256 for row in source.builds),
            tuple(row.fap_sha256 for row in self.config.builds),
        )

    def test_label_derivation_is_a_separate_explicit_capability(self) -> None:
        source = load_verified_source(self.config)
        calls: list[int] = []

        def deterministic(_seed: int, index: int) -> tuple[bytes, dict[str, object]]:
            calls.append(index)
            episode = source.builds[index]
            # The mismatch must fail before any label can be accepted.
            return bytes(32), dict(episode.public_view)

        with mock.patch(
            "o1_crypto_lab.o1c30_incremental_diagonal_frontier_run._derived_target",
            side_effect=deterministic,
        ):
            with self.assertRaisesRegex(O1C30RunError, "label oracle"):
                _derive_labels(source)
        self.assertEqual(calls, [0])

    def test_mutated_fap_pin_fails_without_label_derivation(self) -> None:
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        document["source"]["build"][0]["fap_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory(prefix="o1c30-source-pin-") as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            config = load_o1c30_run_config(path, root=ROOT)
            with mock.patch(
                "o1_crypto_lab.o1c30_incremental_diagonal_frontier_run._derived_target"
            ) as derive:
                with self.assertRaisesRegex(O1C30RunError, "binding|bytes"):
                    load_verified_source(config)
        derive.assert_not_called()


class O1C30FrontierDiagnosticTests(unittest.TestCase):
    def test_exact_map_key_has_rank_one_and_best_hamming_zero(self) -> None:
        labels = np.asarray([(index * 7 + 3) & 1 for index in range(256)], np.uint8)
        logits = np.where(labels == 1, 8.0, -8.0).astype(np.float64)

        result = _frontier_diagnostic(logits, labels, 64)

        self.assertEqual(result["candidates_evaluated"], 64)
        self.assertTrue(result["true_key_within_limit"])
        self.assertEqual(result["true_key_rank_if_within_limit"], 1)
        self.assertEqual(result["best_hamming_distance"], 0)
        self.assertEqual(result["best_hamming_rank"], 1)

    def test_frontier_is_deterministic(self) -> None:
        labels = np.zeros(256, np.uint8)
        logits = np.linspace(-0.5, 0.5, 256, dtype=np.float64)
        first = _frontier_diagnostic(logits, labels, 128)
        second = _frontier_diagnostic(logits, labels, 128)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
