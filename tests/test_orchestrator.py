import unittest

from o1_crypto_lab.orchestrator import (
    AdaptiveResearchPlanner,
    CryptanalyticTargetModel,
    DatasetSplit,
    ExperimentProposal,
    ModelLifecycle,
)
from o1_crypto_lab.types import InformationLabel


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.model = CryptanalyticTargetModel("b" * 64)
        self.planner = AdaptiveResearchPlanner(stale_limit=3)

    def test_selects_information_gain_per_work_and_learns(self):
        expensive = ExperimentProposal("expensive", "carry", 4.0, 10)
        efficient = ExperimentProposal(
            "efficient", "solver", 1.0, 1, split=DatasetSplit.VALIDATION
        )
        self.assertEqual(
            self.planner.choose([expensive, efficient], self.model), efficient
        )
        self.model.record_success(efficient, gain=0.25, surprise=0.5)
        self.assertEqual(self.model.best_validation_gain, 0.25)
        self.assertEqual(self.model.family_attempts, {"solver": 1})
        self.assertEqual(len(self.model.state_sha256()), 64)

    def test_training_feedback_cannot_update_validation_state(self):
        training = ExperimentProposal(
            "training", "carry", 1.0, 1, split=DatasetSplit.TRAIN
        )
        self.model.record_success(training, gain=0.9, surprise=0.4)
        self.model.record_failure(training, reason_code="TRAIN_ONLY")
        self.assertEqual(self.model.best_validation_gain, 0.0)
        self.assertEqual(self.model.stale_steps, 0)

        validation = ExperimentProposal(
            "validation", "carry", 1.0, 1, split=DatasetSplit.VALIDATION
        )
        self.model.record_success(validation, gain=0.2, surprise=0.1)
        self.assertEqual(self.model.best_validation_gain, 0.2)
        self.model.record_failure(validation, reason_code="NO_VALIDATION_GAIN")
        self.assertEqual(self.model.stale_steps, 1)

    def test_structural_failure_blacklists_family(self):
        proposal = ExperimentProposal("bad", "invalid-flow", 1.0, 1)
        self.model.record_failure(proposal, reason_code="TYPE", structural=True)
        self.assertIsNone(self.planner.choose([proposal], self.model))
        self.assertIn("invalid-flow", self.model.blacklisted_families)

    def test_target_labels_are_filtered_and_cannot_be_ingested(self):
        contaminated = ExperimentProposal(
            "leaked",
            "rank",
            100.0,
            1,
            frozenset({InformationLabel.POST_REVEAL}),
        )
        clean = ExperimentProposal("clean", "public", 0.1, 10)
        self.assertEqual(self.planner.choose([contaminated, clean], self.model), clean)
        with self.assertRaises(ValueError):
            self.model.record_success(contaminated, gain=1.0, surprise=1.0)

    def test_round_trip_and_stale_stop(self):
        proposal = ExperimentProposal("try", "carry", 1.0, 1)
        self.model.record_failure(proposal, reason_code="NO_GAIN")
        restored = CryptanalyticTargetModel.from_description(self.model.describe())
        self.assertEqual(restored.describe(), self.model.describe())
        self.assertEqual(restored.state_sha256(), self.model.state_sha256())
        restored.stale_steps = 3
        self.assertIsNone(self.planner.choose([proposal], restored))

    def test_freeze_binds_exact_test_proposal_and_plan_once(self):
        test = ExperimentProposal(
            "held-out", "public", 0.1, 10, split=DatasetSplit.TEST
        )
        substituted = ExperimentProposal(
            "different", "public", 0.1, 10, split=DatasetSplit.TEST
        )
        plan = "c" * 64
        self.model.freeze_for_test(test, plan_sha256=plan)
        self.assertEqual(self.model.lifecycle, ModelLifecycle.FROZEN)
        self.assertEqual(self.planner.choose([substituted, test], self.model), test)
        with self.assertRaises(ValueError):
            self.model.consume_test(
                substituted, plan_sha256=plan, result_sha256="d" * 64
            )
        with self.assertRaises(ValueError):
            self.model.consume_test(test, plan_sha256="e" * 64, result_sha256="d" * 64)
        self.model.consume_test(test, plan_sha256=plan, result_sha256="d" * 64)
        self.assertEqual(self.model.lifecycle, ModelLifecycle.TEST_CONSUMED)
        self.assertIsNone(self.planner.choose([test], self.model))
        with self.assertRaises(RuntimeError):
            self.model.consume_test(test, plan_sha256=plan, result_sha256="d" * 64)
        self.model.open_post_test_audit()
        self.assertEqual(self.model.lifecycle, ModelLifecycle.AUDIT)

    def test_target_model_has_fixed_family_capacity(self):
        model = CryptanalyticTargetModel("f" * 64, max_family_slots=1)
        model.record_observation(ExperimentProposal("one", "family-a", 0.0, 1))
        before = model.describe()
        with self.assertRaises(OverflowError):
            model.record_success(
                ExperimentProposal("two", "family-b", 0.0, 1),
                gain=0.0,
                surprise=0.0,
            )
        self.assertEqual(model.describe(), before)

    def test_deserialization_rejects_lossy_or_unbounded_state(self):
        self.model.record_observation(ExperimentProposal("one", "family", 0.0, 1))
        description = self.model.describe()
        description["observations"] = 1.9
        with self.assertRaises(TypeError):
            CryptanalyticTargetModel.from_description(description)
        description = self.model.describe()
        description["bounded_control_state"] = False
        with self.assertRaises(ValueError):
            CryptanalyticTargetModel.from_description(description)

    def test_rejects_invalid_snapshot(self):
        with self.assertRaises(ValueError):
            CryptanalyticTargetModel("not-a-sha")
        with self.assertRaises(ValueError):
            ExperimentProposal("nan", "bad", float("nan"), 1).validate()


if __name__ == "__main__":
    unittest.main()
