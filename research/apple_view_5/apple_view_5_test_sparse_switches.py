from __future__ import annotations

import inspect
import hashlib
import json
import struct
import unittest
from pathlib import Path
from typing import Any, cast

from apple_view_5_sparse_switches import (
    ADDITIONS_PER_BLOCK,
    APPLE_VIEW_5_DIR,
    BASE_CARRY_DEPTH,
    CompiledNetwork,
    MATERIAL_SWITCH_LIMIT,
    RFC_BLOCK,
    RFC_KEY,
    RFC_NONCE,
    ExperimentConfig,
    IncrementalPropagator,
    PublicTarget,
    build_orders,
    chacha20_block,
    compile_network,
    generate_probe_keys,
    generate_target,
    public_gain_greedy_order,
    run_experiment,
    run_order,
    validated_output_path,
)


class AppleView5SparseSwitchTests(unittest.TestCase):
    config: ExperimentConfig
    target: PublicTarget
    truth: bytes
    probe: bytes
    network: CompiledNetwork

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = ExperimentConfig(probes=1)
        cls.target, cls.truth = generate_target(cls.config)
        cls.probe = generate_probe_keys(cls.config)[0]
        cls.network = compile_network(cls.target)

    def test_rfc_8439_full_round_block_vector(self) -> None:
        self.assertEqual(chacha20_block(RFC_KEY, 1, RFC_NONCE), RFC_BLOCK)

    def test_target_and_probes_repeat_apple_view_4_fixture(self) -> None:
        self.assertEqual(generate_target(self.config), (self.target, self.truth))
        self.assertEqual(
            generate_probe_keys(self.config), generate_probe_keys(self.config)
        )
        self.assertNotEqual(self.probe, self.truth)
        public_hash = hashlib.sha256(
            struct.pack("<I", self.target.counter)
            + self.target.nonce
            + self.target.block
        ).hexdigest()
        self.assertEqual(
            public_hash,
            "fa12050df20cc4c4d2f33a1b1d88e52f6194ee72bc01b928d00ca4d0d161c527",
        )

    def test_compile_is_public_only_and_has_exact_switch_partition(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(compile_network).parameters), ("target", "meter")
        )
        network = self.network
        self.assertEqual(len(network.switches), ADDITIONS_PER_BLOCK)
        self.assertEqual(
            network.base_majority_constraints,
            ADDITIONS_PER_BLOCK * BASE_CARRY_DEPTH,
        )
        self.assertEqual(network.base_constraint_count, 31_072)
        self.assertEqual(len(network.constraints), 31_408)
        self.assertEqual(len(network.key_variables), 256)
        self.assertEqual(len(network.output_variables), 512)
        for index, switch in enumerate(network.switches):
            self.assertEqual(switch.switch_id, index)
            self.assertEqual(switch.addition_index, index)
            self.assertEqual(
                switch.constraint_id, network.base_constraint_count + index
            )
            constraint = network.constraints[switch.constraint_id]
            self.assertEqual(constraint.kind, "majority")
            self.assertEqual(
                constraint.variables,
                (switch.left_bit30, switch.right_bit30, switch.carry30, switch.carry31),
            )

    def test_dormant_constraints_are_not_used_before_activation(self) -> None:
        state = IncrementalPropagator(self.network, self.target, self.probe)
        self.assertEqual(state.propagate(), "UNKNOWN")
        self.assertFalse(any(state.active[self.network.base_constraint_count :]))
        self.assertEqual(state.enabled_switch_ids, [])

    def test_all_orders_are_deterministic_permutations_and_greedy_is_public(
        self,
    ) -> None:
        orders, ledger = build_orders(self.network, self.target, self.config.seed)
        again, again_ledger = build_orders(self.network, self.target, self.config.seed)
        self.assertEqual(orders, again)
        self.assertEqual(ledger, again_ledger)
        self.assertEqual(
            set(orders),
            {
                "early_to_final",
                "final_to_early",
                "deterministic_public_random",
                "online_public_gain_greedy",
            },
        )
        for order in orders.values():
            self.assertEqual(tuple(sorted(order)), tuple(range(ADDITIONS_PER_BLOCK)))
        self.assertFalse(ledger["uses_probe_key"])
        self.assertFalse(ledger["uses_truth_key"])
        self.assertEqual(
            tuple(inspect.signature(public_gain_greedy_order).parameters),
            ("network", "target", "meter"),
        )

    def test_full_switch_set_retains_truth_and_rejects_wrong_probe(self) -> None:
        order = tuple(range(ADDITIONS_PER_BLOCK))
        truth_row = run_order(self.network, self.target, self.truth, order)
        probe_row = run_order(self.network, self.target, self.probe, order)
        self.assertEqual(truth_row["status"], "CONSISTENT_COMPLETE")
        self.assertEqual(truth_row["enabled_switches"], ADDITIONS_PER_BLOCK)
        self.assertEqual(probe_row["status"], "CONFLICT")
        self.assertIsNotNone(probe_row["first_conflict_switch_count"])
        self.assertLessEqual(
            cast(int, probe_row["first_conflict_switch_count"]),
            ADDITIONS_PER_BLOCK,
        )
        self.assertEqual(
            len(probe_row["certificate_switch_ids"]),
            probe_row["first_conflict_switch_count"],
        )
        self.assertEqual(probe_row["proof_slice_replay_status"], "CONFLICT")
        self.assertLessEqual(
            cast(int, probe_row["proof_slice_switch_count"]),
            cast(int, probe_row["first_conflict_switch_count"]),
        )

    def test_order_rejects_at_first_prefix_and_prior_prefix_survives(self) -> None:
        order = tuple(range(ADDITIONS_PER_BLOCK))
        row = run_order(self.network, self.target, self.probe, order)
        first = cast(int, row["first_conflict_switch_count"])
        before = IncrementalPropagator(self.network, self.target, self.probe)
        self.assertEqual(before.propagate(), "UNKNOWN")
        for switch_id in order[: first - 1]:
            self.assertNotEqual(before.activate_switch(switch_id), "CONFLICT")
        self.assertEqual(before.activate_switch(order[first - 1]), "CONFLICT")

    def test_reason_dag_removes_irrelevant_prefix_switches_and_replays(self) -> None:
        orders, _ = build_orders(self.network, self.target, self.config.seed)
        row = run_order(
            self.network,
            self.target,
            self.probe,
            orders["online_public_gain_greedy"],
        )
        self.assertEqual(row["proof_slice_replay_status"], "CONFLICT")
        self.assertLess(
            cast(int, row["proof_slice_switch_count"]),
            cast(int, row["first_conflict_switch_count"]),
        )

    def test_small_experiment_is_json_safe_and_truth_is_post_experiment_control(
        self,
    ) -> None:
        result = cast(dict[str, Any], run_experiment(ExperimentConfig(probes=1)))
        self.assertFalse(result["attacker_boundary"]["unbounded_cdcl_used"])
        self.assertFalse(
            result["attacker_boundary"]["branching_or_search_decisions_used"]
        )
        self.assertEqual(
            result["attacker_boundary"]["truth_key_role"],
            "post-experiment consistency control only",
        )
        self.assertTrue(result["summary"]["truth_controls_retained"])
        self.assertTrue(result["summary"]["success_gate_passed"])
        self.assertLessEqual(
            cast(int, result["summary"]["minimum_proof_slice_switch_count"]),
            MATERIAL_SWITCH_LIMIT,
        )
        self.assertEqual(result["summary"]["exact_full_key_recoveries"], 0)
        self.assertTrue(result["resources"]["budget_passed"])
        json.dumps(result, allow_nan=False)

    def test_output_is_confined_to_owned_folder(self) -> None:
        allowed = APPLE_VIEW_5_DIR / "apple_view_5_test_result.json"
        self.assertEqual(validated_output_path(allowed), allowed)
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_5_DIR.parent / "apple_view_5_escape.json")
        with self.assertRaises(ValueError):
            validated_output_path(APPLE_VIEW_5_DIR / "result.json")
        with self.assertRaises(ValueError):
            validated_output_path(Path("apple_view_5_result.md"))


if __name__ == "__main__":
    unittest.main()
