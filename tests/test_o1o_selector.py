import unittest

from o1_crypto_lab.o1o_selector import (
    BoundedMemoryArm,
    O1OSelectionError,
    O1OSelector,
    SelectionThresholds,
    TopKFidelity,
    TopKGate,
)
from o1_crypto_lab.types import InformationLabel


class O1OSelectorTests(unittest.TestCase):
    def thresholds(self):
        return SelectionThresholds(
            min_rank_spearman=0.99,
            min_rank_kendall=0.91,
            top_k_requirements=(TopKGate(32, 0.7), TopKGate(128, 0.75)),
            max_serialized_online_state_bytes=8192,
        )

    def arm(self, name, *, state=7000, spearman=0.995, kendall=0.94, clips=0):
        return BoundedMemoryArm(
            name=name,
            family="bit-vault",
            memory_plan_sha256=(name[0] if name[0] in "abcdef" else "a") * 64,
            rank_spearman=spearman,
            rank_kendall=kendall,
            top_k_overlap=(TopKFidelity(32, 0.75), TopKFidelity(128, 0.8)),
            serialized_online_state_bytes=state,
            work_units=100,
            calibration_clip_count=clips,
        )

    def test_selects_smallest_state_after_all_gates_and_freezes_model(self):
        selector = O1OSelector(source_snapshot_sha256="b" * 64, thresholds=self.thresholds())
        report = selector.select_and_freeze(
            (self.arm("large", state=7800), self.arm("compact", state=6600))
        )
        self.assertEqual(report.selected_arm.name, "compact")
        value = report.describe()
        self.assertEqual(value["target_model"]["lifecycle"], "FROZEN")
        self.assertEqual(value["target_labels_used"], 0)
        self.assertEqual(len(value["selection_sha256"]), 64)
        with self.assertRaises(RuntimeError):
            selector.select_and_freeze((self.arm("again"),))

    def test_gate_rejects_bad_fidelity_state_and_clips(self):
        selector = O1OSelector(source_snapshot_sha256="b" * 64, thresholds=self.thresholds())
        with self.assertRaises(O1OSelectionError):
            selector.select_and_freeze(
                (
                    self.arm("bad-fidelity", spearman=0.8),
                    self.arm("too-large", state=9000),
                    self.arm("clipped", clips=1),
                )
            )

    def test_target_labels_are_structurally_rejected(self):
        with self.assertRaises(O1OSelectionError):
            BoundedMemoryArm(
                name="leak",
                family="bad",
                memory_plan_sha256="c" * 64,
                rank_spearman=1.0,
                rank_kendall=1.0,
                top_k_overlap=(TopKFidelity(32, 1.0),),
                serialized_online_state_bytes=1,
                work_units=1,
                labels=frozenset({InformationLabel.POST_REVEAL}),
            )


if __name__ == "__main__":
    unittest.main()
