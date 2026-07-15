import unittest

from o1_crypto_lab.benchmark import composition_report
from o1_crypto_lab.composer import (
    ChainComposer,
    FlowViolation,
    Operator,
    OperatorRegistry,
    default_registry,
)
from o1_crypto_lab.types import DataKind, FlowState, InformationLabel


class ComposerTests(unittest.TestCase):
    def setUp(self):
        self.registry = default_registry()
        self.composer = ChainComposer(self.registry)
        self.public = FlowState(
            DataKind.PUBLIC_RELATIONS,
            frozenset({InformationLabel.PUBLIC}),
        )

    def test_finds_complete_scientific_chain(self):
        chains = self.composer.find_chains(
            self.public, DataKind.CONFIRMED, max_depth=10, require_target_blind=False
        )
        self.assertEqual(len(chains), 1)
        self.assertEqual(
            chains[0].names,
            (
                "align_public_blocks",
                "build_control_corrected_field",
                "project_solver_trajectory",
                "o1_stream_accumulate",
                "calibrate_against_matched_null",
                "freeze_target_blind_order",
                "execute_frozen_order",
                "exact_cipher_confirm",
            ),
        )
        self.assertIn(InformationLabel.POST_REVEAL, chains[0].final_state.labels)

    def test_monotone_provenance_blocks_post_reveal_laundering(self):
        operator = next(
            item for item in self.registry if item.name == "post_reveal_rank"
        )
        revealed = FlowState(
            DataKind.CONFIRMED,
            frozenset(
                {
                    InformationLabel.PUBLIC,
                    InformationLabel.TARGET_SECRET,
                    InformationLabel.POST_REVEAL,
                }
            ),
        )
        with self.assertRaises(FlowViolation):
            operator.apply(revealed)
        self.assertEqual(
            self.composer.find_chains(
                revealed,
                DataKind.TARGET_BLIND_ORDER,
                max_depth=2,
                require_target_blind=True,
            ),
            [],
        )
        with self.assertRaises(ValueError):
            FlowState(
                DataKind.TARGET_BLIND_ORDER,
                frozenset({InformationLabel.TARGET_SECRET}),
            )

    def test_composer_optimizes_work_not_path_depth(self):
        registry = OperatorRegistry(
            [
                Operator(
                    "direct", DataKind.PUBLIC_RELATIONS, DataKind.SCORE, work_units=100
                ),
                Operator("step_one", DataKind.PUBLIC_RELATIONS, DataKind.PUBLIC_FIELD),
                Operator("step_two", DataKind.PUBLIC_FIELD, DataKind.SCORE),
            ]
        )
        chains = ChainComposer(registry).find_chains(
            FlowState(DataKind.PUBLIC_RELATIONS), DataKind.SCORE, max_depth=2, limit=1
        )
        self.assertEqual(chains[0].names, ("step_one", "step_two"))
        self.assertEqual(chains[0].work_units, 2)

    def test_registry_rejects_duplicate_and_negative_work(self):
        operator = Operator("one", DataKind.SCORE, DataKind.MODEL)
        registry = OperatorRegistry([operator])
        with self.assertRaises(ValueError):
            registry.register(operator)
        with self.assertRaises(ValueError):
            registry.register(
                Operator("bad", DataKind.SCORE, DataKind.MODEL, work_units=-1)
            )
        with self.assertRaises(ValueError):
            registry.register(
                Operator("nan", DataKind.SCORE, DataKind.MODEL, work_units=float("nan"))
            )

    def test_composition_gate(self):
        report = composition_report()
        self.assertTrue(report["gate_passed"])
        self.assertEqual(report["post_reveal_to_target_blind_order_count"], 0)
        self.assertIn("cannot emit TARGET_BLIND_ORDER", report["post_reveal_rejection"])


if __name__ == "__main__":
    unittest.main()
