from __future__ import annotations

import hashlib
import inspect
import json
import struct
import unittest
from pathlib import Path
from typing import Any, cast

from apple_view_7_proof_edge_transfer import (
    ADDITIONS_PER_BLOCK,
    APPLE6_FROZEN_UNARY_ORDER,
    APPLE6_FROZEN_UNARY_ORDER_SHA256,
    APPLE_VIEW_7_DIR,
    BASE_CARRY_DEPTH,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    STATE_BATCH_CLOCK_MAX,
    STATE_BYTES,
    STATE_COUNTER_MAX,
    CompiledNetwork,
    ExperimentConfig,
    ProofEdgeMemory,
    PublicTarget,
    _order_sha256,
    _scientific_payload,
    chacha20_block,
    compile_network,
    generate_case,
    run_experiment,
    run_order,
    validated_output_path,
)


class AppleView7ProofEdgeTransferTests(unittest.TestCase):
    config: ExperimentConfig
    target: PublicTarget
    truth: bytes
    probe: bytes
    network: CompiledNetwork
    small_result: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        # This non-default seed cannot reveal the sealed reference EVAL fixtures.
        cls.config = ExperimentConfig(
            seed="apple-view-7-unit-test-v1-20260719",
            build_targets=1,
            eval_targets=1,
            probes_per_target=1,
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

    def test_edge_memory_is_exactly_bounded_addressed_and_path_readable(self) -> None:
        memory = ProofEdgeMemory()
        self.assertEqual(len(memory.state), STATE_BYTES)
        self.assertEqual(STATE_BYTES, 113_570)
        memory.update_proof_batch(((3, 1),), (3,), (1,))
        memory.update_proof_batch(((3, 1), (2, 1)), (2,), (1,))
        self.assertEqual(memory.clock, 2)
        self.assertEqual(memory.edge_count(3, 1), 2)
        self.assertEqual(memory.edge_count(2, 1), 1)
        self.assertEqual(memory.root_count(2), 1)
        self.assertEqual(memory.root_count(3), 1)
        self.assertEqual(memory.terminal_count(1), 2)
        self.assertEqual(memory.frozen_order()[:3], (3, 1, 2))
        self.assertEqual(len(memory.state), STATE_BYTES)

    def test_edge_memory_saturates_without_growing(self) -> None:
        memory = ProofEdgeMemory()
        struct.pack_into("<H", memory.state, 0, STATE_BATCH_CLOCK_MAX)
        memory.state[memory._edge_offset(4, 5)] = STATE_COUNTER_MAX
        event = memory.update_proof_batch(((4, 5),), (), (5,))
        self.assertEqual(memory.clock, STATE_BATCH_CLOCK_MAX)
        self.assertEqual(memory.edge_count(4, 5), STATE_COUNTER_MAX)
        self.assertEqual(event["already_saturated_cells"], 1)
        self.assertEqual(len(memory.state), STATE_BYTES)
        with self.assertRaises(ValueError):
            memory.update_proof_batch(((4, 4),), (), ())

    def test_exact_proof_dag_edges_and_slice_replay_on_wrong_probe(self) -> None:
        row = run_order(
            self.network,
            self.target,
            self.probe,
            tuple(range(ADDITIONS_PER_BLOCK)),
        )
        self.assertEqual(row["status"], "CONFLICT")
        self.assertEqual(row["proof_slice_replay_status"], "CONFLICT")
        proof_ids = set(row["proof_slice_switch_ids"])
        edges = row["proof_predecessor_edge_events"]
        self.assertGreater(len(edges), 0)
        self.assertEqual(row["proof_predecessor_edge_event_count"], len(edges))
        self.assertTrue(all(left != right for left, right in edges))
        self.assertTrue(all(left in proof_ids and right in proof_ids for left, right in edges))
        self.assertTrue(
            all(value in proof_ids for value in row["proof_root_switch_events"])
        )
        self.assertTrue(
            all(value in proof_ids for value in row["proof_terminal_switch_events"])
        )
        self.assertEqual(len(row["proof_terminal_switch_events"]), 1)
        self.assertLessEqual(
            cast(int, row["proof_slice_switch_count"]),
            cast(int, row["first_conflict_switch_count"]),
        )

    def test_embedded_apple6_comparator_order_is_exact(self) -> None:
        self.assertEqual(
            tuple(sorted(APPLE6_FROZEN_UNARY_ORDER)),
            tuple(range(ADDITIONS_PER_BLOCK)),
        )
        self.assertEqual(
            _order_sha256(APPLE6_FROZEN_UNARY_ORDER),
            APPLE6_FROZEN_UNARY_ORDER_SHA256,
        )

    def test_small_run_has_hard_build_freeze_eval_separation(self) -> None:
        result = self.small_result
        self.assertEqual(result["build_phase"]["proof_batches"], 3)
        self.assertGreater(
            result["build_phase"]["stream_length_exact_predecessor_edge_events"],
            0,
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

    def test_small_run_scores_edge_reader_first_and_replays_every_proof(self) -> None:
        target = self.small_result["evaluation_phase"]["targets"][0]
        self.assertTrue(target["learned_first_for_every_probe"])
        self.assertEqual(
            target["scored_sequence"][0],
            "learned_proof_edge_predecessor:probe-0",
        )
        self.assertEqual(len(target["runs"]), 7)
        for rows in target["runs"].values():
            self.assertEqual(rows[0]["status"], "CONFLICT")
            self.assertEqual(rows[0]["proof_slice_replay_status"], "CONFLICT")
        self.assertTrue(self.small_result["summary"]["heldout_truth_controls_retained"])
        self.assertFalse(
            self.small_result["summary"]["certificate_gain_can_pass_gate"]
        )

    def test_scientific_payload_excludes_dynamic_fields(self) -> None:
        payload = _scientific_payload(self.small_result)
        self.assertNotIn("timeline", payload)
        self.assertNotIn("resources", payload)
        rendered = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
        self.assertEqual(hashlib.sha256(rendered).digest_size, 32)

    def test_output_is_confined_to_owned_folder(self) -> None:
        allowed = APPLE_VIEW_7_DIR / "apple_view_7_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_7_DIR.parent / "apple_view_7_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(Path("apple_view_7_result.md"))


if __name__ == "__main__":
    unittest.main()
