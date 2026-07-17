from __future__ import annotations

import hashlib
import inspect
import json
import unittest
from dataclasses import replace
from unittest import mock

import numpy as np

from o1_crypto_lab.selective_mqar import (
    PackedBitVault,
    SealedTruthLedger,
    SelectiveMQARConfig,
    TruthAccessError,
    build_public_episode,
    execute_public_episode,
    literal_compaction_audit,
    no_binding_control,
    run_selective_mqar,
    torch,
    train_route_gate,
)


def _config(
    *,
    n_bits: int = 16,
    haystack_lengths: tuple[int, ...] = (0, 64, 512),
    evaluation_seeds: tuple[int, ...] = (701, 702),
) -> SelectiveMQARConfig:
    return SelectiveMQARConfig(
        n_bits=n_bits,
        family_count=8,
        relevant_family=3,
        event_dimension=16,
        address_dimension=8,
        model_dimension=16,
        heads=2,
        head_dimension=4,
        holographic_slots=4,
        feedforward_dimension=24,
        phase_scale=float(np.pi),
        core_seed=200020,
        build_seeds=(101, 102, 103, 104),
        calibration_seeds=(201, 202),
        evaluation_seeds=evaluation_seeds,
        haystack_lengths=haystack_lengths,
        no_binding_length=haystack_lengths[-1],
        chunk_tokens=64,
        build_examples_per_class=64,
        calibration_examples_per_class=64,
        training_steps=64,
        learning_rate=0.05,
        calibration_threshold_offset=0.0,
        shuffled_label_seed=300020,
        family_code_seed=400020,
        literal_audit_tokens=min(max(128, 2 * n_bits), n_bits + haystack_lengths[-1]),
        maximum_core_updates=max(64, 2 * n_bits),
        countsketch_slots=max(4, n_bits // 4),
        holographic_channels=max(4, n_bits // 4),
        cpu_threads=1,
    )


class PackedBitVaultTests(unittest.TestCase):
    def test_real_canonical_64_byte_state_and_boundary_bits(self) -> None:
        vault = PackedBitVault(256)
        self.assertEqual(vault.to_bytes(), bytes(64))
        for address, value in ((0, 1), (7, 1), (8, 0), (255, 1)):
            vault.write(address, value)

        payload = vault.to_bytes()
        self.assertEqual(len(payload), 64)
        self.assertEqual(payload[0], 0x81)
        self.assertEqual(payload[1], 0x00)
        self.assertEqual(payload[31], 0x80)
        self.assertEqual(payload[32], 0x81)
        self.assertEqual(payload[33], 0x01)
        self.assertEqual(payload[63], 0x80)
        self.assertEqual(vault.sha256(), hashlib.sha256(payload).hexdigest())

        restored = PackedBitVault.from_bytes(payload, n_bits=256)
        self.assertEqual(restored.to_bytes(), payload)
        restored.write(7, 0)
        changed = restored.to_bytes()
        self.assertEqual(changed[0], 0x01)
        self.assertEqual(changed[32], 0x81)

    def test_false_positive_overwrites_and_missing_value_stays_invalid(self) -> None:
        vault = PackedBitVault(4)
        vault.write(0, 1)  # true binding
        vault.write(0, 0)  # accepted distractor: an honest false positive
        vault.write(2, 1)
        vault.write(3, 0)

        self.assertEqual(vault.read(0), 0)
        with self.assertRaises(KeyError):
            vault.read(1)
        self.assertEqual(vault.validity_array().tolist(), [1, 0, 1, 1])
        truth = np.asarray([1, 0, 1, 0], dtype=np.uint8)
        valid = vault.validity_array().astype(bool)
        correct = valid & (vault.value_array() == truth)
        self.assertEqual(int(np.count_nonzero(correct)), 2)


@unittest.skipUnless(torch is not None, "optional Torch dependency is absent")
class SelectiveMQARMechanismTests(unittest.TestCase):
    def test_config_declares_exact_constant_352_byte_live_state(self) -> None:
        config = _config(n_bits=256, haystack_lengths=(0, 65536, 1048576))
        self.assertEqual(config.core_config.fast_state_bytes(), 288)
        self.assertEqual(config.vault_bytes, 64)
        self.assertEqual(config.live_state_bytes, 352)

    def test_stable_supersequence_projection_and_sealed_truth_api(self) -> None:
        config = _config()
        episode, ledger = build_public_episode(config, 701)
        short = episode.token_ids(64)
        long = episode.token_ids(512)
        short_set = set(int(value) for value in short)
        projected = np.asarray(
            [value for value in long if int(value) in short_set], dtype=np.uint64
        )
        np.testing.assert_array_equal(projected, short)
        query_order = episode.query_order()
        self.assertEqual(sorted(query_order.tolist()), list(range(config.n_bits)))
        self.assertFalse(np.array_equal(query_order, np.arange(config.n_bits)))
        self.assertEqual(ledger.reveal_count, 0)
        with self.assertRaises(TruthAccessError):
            _ = ledger[0]
        with self.assertRaises(TruthAccessError):
            iter(ledger)
        with self.assertRaises(TruthAccessError):
            np.asarray(ledger)
        signature = inspect.signature(execute_public_episode)
        self.assertNotIn("truth", signature.parameters)
        self.assertNotIn("ledger", signature.parameters)

    def test_training_changes_only_input_gate_and_calibrates_positive_margin(
        self,
    ) -> None:
        config = _config()
        first = train_route_gate(config, name="primary", shuffled_labels=False)
        second = train_route_gate(config, name="primary", shuffled_labels=False)
        self.assertEqual(first.changed_parameters, ("input_gate.weight",))
        self.assertTrue(first.calibration_metrics["zero_errors"])
        self.assertGreater(first.calibration_metrics["minimum_signed_margin"], 0.0)
        certificate = first.calibration_metrics["global_public_token_certificate"]
        self.assertTrue(certificate["all_legal_public_tokens_separated"])
        self.assertGreater(certificate["certified_margin"], 0.0)
        self.assertEqual(first.slow_state_sha256, second.slow_state_sha256)
        episode, _ledger = build_public_episode(config, 701)
        batch = next(episode.iter_batches(64))
        with torch.no_grad():
            expected = (
                first.core.input_gate(
                    first.core.event_projection(torch.from_numpy(batch.events))
                )
                .mean(dim=-1)
                .numpy()
            )
        np.testing.assert_array_equal(first.score(batch.events), expected)
        np.testing.assert_array_equal(
            first.mask(batch.events), expected >= first.threshold
        )

    def test_literal_and_compacted_replay_are_byte_exact(self) -> None:
        config = _config()
        gate = train_route_gate(config, name="primary", shuffled_labels=False)
        episode, _ledger = build_public_episode(config, 701)
        audit = literal_compaction_audit(episode, gate)
        self.assertTrue(audit["fast_state_equal"])
        self.assertTrue(audit["vault_equal"])
        self.assertTrue(audit["accepted_order_equal"])
        self.assertTrue(audit["byte_exact"])

    def test_stream_and_selected_commitments_ignore_chunk_boundaries(self) -> None:
        config = _config()
        gate = train_route_gate(config, name="primary", shuffled_labels=False)
        first_episode, _first_ledger = build_public_episode(config, 701)
        second_config = replace(config, chunk_tokens=128)
        second_episode, _second_ledger = build_public_episode(second_config, 701)
        first = execute_public_episode(
            first_episode,
            haystack_length=512,
            arm="primary",
            gate=gate,
            cue_mode="identity",
            run_core=True,
        )
        second = execute_public_episode(
            second_episode,
            haystack_length=512,
            arm="primary",
            gate=gate,
            cue_mode="identity",
            run_core=True,
        )
        self.assertEqual(first.public_stream_sha256, second.public_stream_sha256)
        self.assertEqual(first.selected_order_sha256, second.selected_order_sha256)
        self.assertEqual(first.mask_bytes, second.mask_bytes)
        self.assertEqual(first.live_state_bytes, second.live_state_bytes)

    def test_no_binding_false_positive_changes_state_honestly(self) -> None:
        config = _config(haystack_lengths=(0, 64), evaluation_seeds=(701,))
        gate = train_route_gate(config, name="primary", shuffled_labels=False)
        gate.threshold = -1.0e9
        control = no_binding_control(config, gate, seed=9991)
        self.assertEqual(control["accepted_tokens"], 64)
        self.assertFalse(control["state_held_exactly"])
        self.assertNotEqual(
            control["initial_live_state_sha256"],
            control["final_live_state_sha256"],
        )
        self.assertEqual(control["core_replay"], "complete")

    def test_end_to_end_freezes_before_reveal_and_controls_fail(self) -> None:
        config = _config()
        phases: list[str] = []

        def gate_callback(artifacts, document) -> None:
            phases.append(str(document["phase"]))
            self.assertEqual(document["evaluation_tokens_seen"], 0)
            self.assertEqual(document["evaluation_streams_generated"], 0)
            self.assertIn("primary_gate_slow_state.bin", artifacts)

        def prediction_callback(artifacts, document) -> None:
            phases.append(str(document["phase"]))
            self.assertEqual(document["truth_ledger_reveal_count"], 0)
            self.assertEqual(document["scorer_calls"], 0)
            self.assertIn("primary_masks.bitpack", artifacts)
            rendered = json.dumps(document, sort_keys=True)
            for forbidden in (
                '"correct_bits"',
                '"false_positives"',
                '"false_negatives"',
                '"exact_recall"',
            ):
                self.assertNotIn(forbidden, rendered)

        result = run_selective_mqar(
            config,
            on_gate_frozen=gate_callback,
            on_predictions_frozen=prediction_callback,
        )
        self.assertEqual(
            phases,
            [
                "SLOW_STATES_FROZEN_BEFORE_EVALUATION_STREAM_GENERATION",
                "ALL_PUBLIC_RECALLS_FROZEN_BEFORE_TRUTH_REVEAL",
            ],
        )
        self.assertTrue(result.success_gate_passed)
        self.assertEqual(
            result.report["classification"], "EXACT_256_LEARNED_GATE_RETENTION"
        )
        self.assertTrue(all(result.report["gates"].values()))
        for control in result.report["controls"].values():
            self.assertFalse(control["all_exact"])
        primary_rows = result.report["primary_cells"]
        self.assertTrue(all(row["route_exact"] for row in primary_rows))
        self.assertTrue(all(row["exact_recall"] for row in primary_rows))
        self.assertTrue(all(row["query_state_held_exactly"] for row in primary_rows))
        expected_gate_work = (
            5
            * len(config.evaluation_seeds)
            * sum(config.n_bits + length for length in config.haystack_lengths)
            + config.no_binding_length
            + config.literal_audit_tokens
            + 2
            * len(config.calibration_seeds)
            * 2
            * config.calibration_examples_per_class
        )
        self.assertEqual(
            result.report["work"]["gate_token_evaluations"], expected_gate_work
        )

        identity_hashes: dict[tuple[int, int], set[str]] = {}
        for row in result.report["all_cells"]:
            if row["arm"] in {"primary", "shuffled_label", "untrained"}:
                key = (row["seed"], row["haystack_length"])
                identity_hashes.setdefault(key, set()).add(
                    str(row["public_stream_sha256"])
                )
        self.assertEqual(len(identity_hashes), 6)
        self.assertTrue(all(len(values) == 1 for values in identity_hashes.values()))

    def test_callback_failure_prevents_every_truth_reveal(self) -> None:
        config = _config(haystack_lengths=(0, 64), evaluation_seeds=(701,))
        calls = 0
        original = SealedTruthLedger.reveal

        def counted(self):
            nonlocal calls
            calls += 1
            return original(self)

        def fail_freeze(_artifacts, _document) -> None:
            raise RuntimeError("intentional freeze sink failure")

        with mock.patch.object(SealedTruthLedger, "reveal", counted):
            with self.assertRaisesRegex(RuntimeError, "intentional"):
                run_selective_mqar(
                    config,
                    on_predictions_frozen=fail_freeze,
                )
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
