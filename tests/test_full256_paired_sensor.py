from __future__ import annotations

import math
import unittest
from dataclasses import replace
from pathlib import Path

import numpy as np

from o1_crypto_lab.cadical_sensor import ProofEvent, SolverSnapshot
from o1_crypto_lab.full256_paired_sensor import (
    CONFIG_SCHEMA,
    _bits_to_key,
    _labels_from_key,
    _midrank_quantiles,
    _nll_bits,
    _proof_event_commitment_payload,
    _stream_decoy_rank,
    load_full256_paired_sensor_config,
)
from o1_crypto_lab.living_inverse import canonical_sha256


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/full256_paired_causal_sensor_v1.json"


def _event_commitment(event: ProofEvent) -> str:
    return canonical_sha256([_proof_event_commitment_payload(event)])


class Full256PairedSensorConfigTests(unittest.TestCase):
    def test_canonical_config_binds_full256_source_and_17408_byte_state(self) -> None:
        raw, config = load_full256_paired_sensor_config(CONFIG)

        self.assertEqual(raw["schema"], CONFIG_SCHEMA)
        self.assertEqual(raw["attempt_id"], "O1C-0012")
        self.assertEqual(config.probe.first_bit, 0)
        self.assertEqual(config.probe.last_bit, 255)
        self.assertEqual(config.probe.conflict_horizon, 96)
        self.assertEqual(config.state_plan.horizons, (64, 96, 65))
        self.assertEqual(config.state_plan.horizon_weights, (7.0, 1.0, 4.0))
        self.assertEqual(config.state_plan.serialized_state_bytes, 17_408)
        self.assertEqual(config.maximum_state_bytes, 18_000)
        self.assertEqual(config.budgets.maximum_native_solver_branches, 514)
        self.assertEqual(config.budgets.maximum_resident_memory_mib, 384.0)
        self.assertEqual(config.budgets.maximum_mps_calls, 0)
        self.assertEqual(config.budgets.maximum_gpu_calls, 0)

        self.assertEqual(
            config.source.capsule,
            "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1",
        )
        self.assertEqual(
            config.source.manifest_sha256,
            "b7a07e6461805946897adbfb90da9e9f55ff1074e9aa1343f602eecb0645b7b4",
        )
        self.assertEqual(
            config.source.public_instance,
            "artifacts/cnf/public_attacker_instance.cnf",
        )
        self.assertEqual(
            config.source.public_instance_sha256,
            "dde6a2791726e148c99064ec71f746fb8803e5d0f6b1996dd8b238c9c9b0a2a0",
        )
        self.assertEqual(
            config.source.semantic_map,
            "artifacts/cnf/full256_chacha20.map.json",
        )
        self.assertEqual(
            config.source.semantic_map_sha256,
            "7f7438a6277086787ff2cf9b6d7468367b4edd82a65b9cfc4f9249f7ecda3318",
        )
        self.assertEqual(config.source.expected_variable_count, 32_128)
        self.assertEqual(config.source.expected_clause_count, 188_010)
        self.assertEqual(
            config.native.cadical_header_sha256,
            "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c",
        )
        self.assertEqual(
            config.native.cadical_library_sha256,
            "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f",
        )


class Full256PairedSensorMathTests(unittest.TestCase):
    def test_midrank_quantiles_are_tie_aware_shape_stable_and_deterministic(
        self,
    ) -> None:
        values = np.array([[4.0, 1.0, 1.0], [3.0, 4.0, 2.0]])
        expected = np.array(
            [
                [5.0 / 6.0, 1.0 / 6.0, 1.0 / 6.0],
                [7.0 / 12.0, 5.0 / 6.0, 5.0 / 12.0],
            ]
        )

        first = _midrank_quantiles(values)
        second = _midrank_quantiles(values.copy())

        self.assertEqual(first.shape, values.shape)
        np.testing.assert_array_equal(first, second)
        np.testing.assert_allclose(first, expected, rtol=0.0, atol=0.0)
        self.assertEqual(first[0, 1], first[0, 2])
        self.assertEqual(first[0, 0], first[1, 1])

    def test_little_endian_bit_packing_round_trip_and_nll(self) -> None:
        key = bytes(range(32))
        labels = _labels_from_key(key)

        self.assertEqual(labels.shape, (256,))
        self.assertEqual(labels[:8].tolist(), [0] * 8)
        self.assertEqual(labels[8:16].tolist(), [1, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(_bits_to_key(labels), key)
        self.assertEqual(_nll_bits(np.full(256, 0.5), labels), 256.0)

        probabilities = np.where(labels == 1, 0.75, 0.25)
        self.assertAlmostEqual(
            _nll_bits(probabilities, labels),
            -256.0 * math.log2(0.75),
            places=12,
        )

    def test_decoy_rank_stream_is_seed_deterministic_across_chunks(self) -> None:
        key = bytes(range(32))
        labels = _labels_from_key(key)
        probabilities = np.linspace(0.1, 0.9, 256, dtype=np.float64)

        first = _stream_decoy_rank(
            probabilities,
            labels,
            decoy_count=5_003,
            seed=0xC0FFEE,
        )
        replay = _stream_decoy_rank(
            probabilities.copy(),
            labels.copy(),
            decoy_count=5_003,
            seed=0xC0FFEE,
        )
        other_seed = _stream_decoy_rank(
            probabilities,
            labels,
            decoy_count=5_003,
            seed=0xC0FFEF,
        )

        self.assertEqual(first, replay)
        self.assertEqual(first["decoy_count"], 5_003)
        self.assertTrue(math.isfinite(first["true_log2_probability"]))
        self.assertGreaterEqual(first["strictly_better_decoys"], 0)
        self.assertLessEqual(first["strictly_better_decoys"], 5_003)
        self.assertGreaterEqual(first["equal_score_decoys"], 0)
        self.assertLessEqual(first["equal_score_decoys"], 5_003)
        self.assertEqual(
            first["rank_one_based"], first["strictly_better_decoys"] + 1
        )
        self.assertNotEqual(
            first["score_stream_float64le_sha256"],
            other_seed["score_stream_float64le_sha256"],
        )


class ProofEventCommitmentTests(unittest.TestCase):
    def test_commitment_covers_every_proof_event_field(self) -> None:
        event = ProofEvent(
            clause_id=188_011,
            redundant=True,
            witness=-7,
            conclusion_phase=False,
            snapshot=SolverSnapshot(
                conflicts=64,
                decisions=101,
                propagations=1_003,
                ticks=10_007,
            ),
            clause=(1, -2, 3),
            antecedents=(17, 23, 42),
        )
        payload = _proof_event_commitment_payload(event)
        baseline = _event_commitment(event)

        self.assertEqual(
            set(payload),
            {
                "id",
                "redundant",
                "witness",
                "conclusion_phase",
                "snapshot",
                "clause",
                "antecedents",
            },
        )
        mutations = {
            "clause_id": replace(event, clause_id=event.clause_id + 1),
            "redundant": replace(event, redundant=not event.redundant),
            "witness": replace(event, witness=event.witness + 1),
            "conclusion_phase": replace(
                event, conclusion_phase=not event.conclusion_phase
            ),
            "snapshot.conflicts": replace(
                event,
                snapshot=replace(
                    event.snapshot, conflicts=event.snapshot.conflicts + 1
                ),
            ),
            "snapshot.decisions": replace(
                event,
                snapshot=replace(
                    event.snapshot, decisions=event.snapshot.decisions + 1
                ),
            ),
            "snapshot.propagations": replace(
                event,
                snapshot=replace(
                    event.snapshot,
                    propagations=event.snapshot.propagations + 1,
                ),
            ),
            "snapshot.ticks": replace(
                event,
                snapshot=replace(event.snapshot, ticks=event.snapshot.ticks + 1),
            ),
            "clause": replace(event, clause=event.clause + (5,)),
            "antecedents": replace(
                event, antecedents=event.antecedents + (99,)
            ),
        }

        for field, mutated in mutations.items():
            with self.subTest(field=field):
                self.assertNotEqual(_event_commitment(mutated), baseline)


if __name__ == "__main__":
    unittest.main()
