from __future__ import annotations

import hashlib
import inspect
import json
import struct
import unittest
from pathlib import Path
from typing import Any, cast

from apple_view_6_stream_transfer import (
    ADDITIONS_PER_BLOCK,
    APPLE_VIEW_6_DIR,
    BASE_CARRY_DEPTH,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    STATE_BYTES,
    STATE_COUNTER_MAX,
    CompiledNetwork,
    ExperimentConfig,
    ProofParticipationMemory,
    PublicTarget,
    _scientific_payload,
    chacha20_block,
    compile_network,
    generate_case,
    run_experiment,
    run_order,
    validated_output_path,
)


class AppleView6StreamTransferTests(unittest.TestCase):
    config: ExperimentConfig
    target: PublicTarget
    truth: bytes
    probe: bytes
    network: CompiledNetwork
    small_result: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = ExperimentConfig(
            build_targets=1, eval_targets=1, probes_per_target=1
        )
        case = generate_case(cls.config, "build", 0)
        cls.target = case.target
        cls.truth = case.truth_key
        cls.probe = case.probes[0]
        cls.network = compile_network(case.target)
        cls.small_result = cast(dict[str, Any], run_experiment(cls.config))

    def test_rfc_8439_full_round_block_vector(self) -> None:
        self.assertEqual(chacha20_block(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_build_and_eval_fixtures_are_deterministic_and_disjoint(self) -> None:
        build = generate_case(self.config, "build", 0)
        evaluation = generate_case(self.config, "eval", 0)
        self.assertEqual(build, generate_case(self.config, "build", 0))
        all_keys = {
            build.truth_key,
            *build.probes,
            evaluation.truth_key,
            *evaluation.probes,
        }
        self.assertEqual(len(all_keys), 4)
        self.assertNotEqual(build.target.block, evaluation.target.block)
        with self.assertRaises(ValueError):
            generate_case(self.config, "invalid", 0)

    def test_compile_is_public_only_and_has_336_named_switches(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(compile_network).parameters), ("target", "meter")
        )
        self.assertEqual(len(self.network.switches), ADDITIONS_PER_BLOCK)
        self.assertEqual(
            self.network.base_majority_constraints,
            ADDITIONS_PER_BLOCK * BASE_CARRY_DEPTH,
        )
        self.assertEqual(self.network.base_constraint_count, 31_072)
        self.assertEqual(len(self.network.constraints), 31_408)

    def test_memory_is_exactly_bounded_and_addressed(self) -> None:
        memory = ProofParticipationMemory()
        self.assertEqual(len(memory.state), STATE_BYTES)
        self.assertEqual(STATE_BYTES, 1_346)
        memory.update_proof_batch((3, 1))
        memory.update_proof_batch((1, 2))
        self.assertEqual(memory.clock, 2)
        self.assertEqual(memory.cell(1), (2, 2))
        self.assertEqual(memory.cell(2), (1, 2))
        self.assertEqual(memory.cell(3), (1, 1))
        self.assertEqual(memory.frozen_order()[:3], (1, 2, 3))
        self.assertEqual(len(memory.state), STATE_BYTES)

    def test_memory_saturates_without_growing(self) -> None:
        memory = ProofParticipationMemory()
        struct.pack_into("<H", memory.state, 0, STATE_COUNTER_MAX)
        struct.pack_into("<HH", memory.state, 2, STATE_COUNTER_MAX, 9)
        memory.update_proof_batch((0,))
        self.assertEqual(memory.clock, STATE_COUNTER_MAX)
        self.assertEqual(memory.cell(0), (STATE_COUNTER_MAX, STATE_COUNTER_MAX))
        self.assertEqual(len(memory.state), STATE_BYTES)
        with self.assertRaises(ValueError):
            memory.update_proof_batch((1, 1))

    def test_exact_proof_slice_replays_on_wrong_probe(self) -> None:
        row = run_order(
            self.network,
            self.target,
            self.probe,
            tuple(range(ADDITIONS_PER_BLOCK)),
        )
        self.assertEqual(row["status"], "CONFLICT")
        self.assertEqual(row["proof_slice_replay_status"], "CONFLICT")
        self.assertLessEqual(
            cast(int, row["proof_slice_switch_count"]),
            cast(int, row["first_conflict_switch_count"]),
        )

    def test_small_run_has_hard_build_freeze_eval_separation(self) -> None:
        result = self.small_result
        self.assertEqual(result["build_phase"]["proof_batches"], 3)
        self.assertGreater(
            result["build_phase"]["stream_length_exact_identity_events"], 0
        )
        self.assertTrue(
            result["attacker_boundary"]["eval_targets_generated_after_state_freeze"]
        )
        self.assertEqual(
            result["attacker_boundary"][
                "heldout_proof_feedback_before_or_during_scored_pass"
            ],
            0,
        )
        self.assertEqual(result["attacker_boundary"]["heldout_state_updates"], 0)
        self.assertTrue(result["evaluation_phase"]["state_unchanged"])
        self.assertEqual(
            result["evaluation_phase"]["frozen_state_sha256_before"],
            result["evaluation_phase"]["frozen_state_sha256_after"],
        )

    def test_small_run_scores_learned_first_and_all_certificates_replay(self) -> None:
        target = self.small_result["evaluation_phase"]["targets"][0]
        self.assertTrue(target["learned_first_for_every_probe"])
        self.assertEqual(
            target["scored_sequence"][0],
            "learned_proof_frequency_recency:probe-0",
        )
        self.assertEqual(len(target["runs"]), 6)
        for rows in target["runs"].values():
            self.assertEqual(rows[0]["status"], "CONFLICT")
            self.assertEqual(rows[0]["proof_slice_replay_status"], "CONFLICT")
        self.assertTrue(self.small_result["summary"]["heldout_truth_controls_retained"])

    def test_scientific_payload_excludes_dynamic_fields(self) -> None:
        payload = _scientific_payload(self.small_result)
        self.assertNotIn("timeline", payload)
        self.assertNotIn("resources", payload)
        rendered = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
        self.assertEqual(hashlib.sha256(rendered).digest_size, 32)

    def test_output_is_confined_to_owned_folder(self) -> None:
        allowed = APPLE_VIEW_6_DIR / "apple_view_6_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_6_DIR.parent / "apple_view_6_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(Path("apple_view_6_result.md"))


if __name__ == "__main__":
    unittest.main()
