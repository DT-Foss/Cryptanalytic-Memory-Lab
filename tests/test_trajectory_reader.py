import json
import math
import unittest

from o1_crypto_lab.stage3 import (
    FEATURE_NAMES,
    DatasetSplit,
    EpisodeSpec,
    RevealedCellLabel,
    SolverCellFeatures,
    Stage3Dataset,
    Stage3Episode,
    TargetBlindBaseline,
)
from o1_crypto_lab.trajectory_reader import (
    FrozenReaderPlan,
    RankedEpisode,
    ReaderError,
    ReaderLifecycle,
    RetrospectiveReader,
    baseline_rankings,
    evaluate_rankings,
    normalize_episode,
)
from o1_crypto_lab.types import InformationLabel


def _episode(
    target_id: str,
    split: DatasetSplit,
    *,
    correct_cell: int,
    decoy_cell: int | None = None,
    train_pattern: bool = False,
) -> Stage3Episode:
    cells = []
    for cell_index in range(256):
        values = [0.0] * len(FEATURE_NAMES)
        # TRAIN teaches that features zero and one are both positively oriented.
        if train_pattern and cell_index == correct_cell:
            values[0] = 10.0
            values[1] = 10.0
        # Validation/holdout make feature one uniquely useful; feature zero has a
        # low-index decoy.  This lets the test observe validation-based selection.
        if not train_pattern:
            if cell_index == correct_cell:
                values[1] = 10.0
            if cell_index == decoy_cell:
                values[0] = 10.0
        # A deterministic nuisance field prevents an all-constant fixture without
        # encoding the target cell.
        values[2] = float((cell_index * 17 + len(target_id)) % 31)
        cells.append(
            SolverCellFeatures(
                cell_index=cell_index,
                prefix8=f"{cell_index:08b}",
                values=tuple(values),
            )
        )
    baseline_scores = tuple(float(cell) for cell in range(256))
    spec = EpisodeSpec(
        family="fixture",
        target_id=target_id,
        unknown_key_bits=24,
        split=split,
        measurement_member=f"data/{target_id}.measurement.json.zst",
        order_member=f"data/{target_id}.order.json",
    )
    return Stage3Episode(
        spec=spec,
        schema="fixture-measurement-v1",
        attempt_id="fixture",
        cells=tuple(cells),
        baseline=TargetBlindBaseline(
            name="published_target_blind_score",
            score_field=baseline_scores,
            complete_order=tuple(reversed(range(256))),
            selected_feature_indices=(0, 1),
            score_field_sha256="d" * 64,
        ),
        measurement_compressed_sha256="a" * 64,
        measurement_raw_sha256="b" * 64,
        measurement_raw_bytes=100,
        order_sha256="c" * 64,
        protocol_sha256="1" * 64,
        public_challenge_sha256="2" * 64,
        cnf_sha256="3" * 64,
        zstd_binary="/fixture/zstd",
        zstd_version="fixture",
    )


def _label(
    episode: Stage3Episode,
    correct_cell: int,
    *,
    information_label: InformationLabel | None = None,
) -> RevealedCellLabel:
    if information_label is None:
        information_label = (
            InformationLabel.TRAIN_LABEL
            if episode.spec.split in {DatasetSplit.TRAIN, DatasetSplit.VALIDATION}
            else InformationLabel.POST_REVEAL
        )
    return RevealedCellLabel(
        family=episode.spec.family,
        target_id=episode.spec.target_id,
        split=episode.spec.split,
        correct_cell=correct_cell,
        source_member="fixture/result.json",
        source_sha256="e" * 64,
        information_label=information_label,
    )


class TrajectoryReaderTests(unittest.TestCase):
    def setUp(self):
        self.train_a = _episode(
            "train_a", DatasetSplit.TRAIN, correct_cell=13, train_pattern=True
        )
        self.train_b = _episode(
            "train_b", DatasetSplit.TRAIN, correct_cell=231, train_pattern=True
        )
        self.validation_a = _episode(
            "validation_a",
            DatasetSplit.VALIDATION,
            correct_cell=210,
            decoy_cell=3,
        )
        self.validation_b = _episode(
            "validation_b",
            DatasetSplit.VALIDATION,
            correct_cell=200,
            decoy_cell=2,
        )
        self.holdout = _episode(
            "holdout",
            DatasetSplit.RETROSPECTIVE_HOLDOUT,
            correct_cell=180,
            decoy_cell=1,
        )
        self.dataset = Stage3Dataset(
            name="reader-fixture",
            episodes=(
                self.train_a,
                self.train_b,
                self.validation_a,
                self.validation_b,
                self.holdout,
            ),
        )
        self.train_labels = (
            _label(self.train_a, 13),
            _label(self.train_b, 231),
        )
        self.validation_labels = (
            _label(self.validation_a, 210),
            _label(self.validation_b, 200),
        )
        self.holdout_labels = (_label(self.holdout, 180),)

    def test_within_episode_normalization_is_deterministic_and_tie_safe(self):
        first = normalize_episode(self.train_a)
        second = normalize_episode(self.train_a)
        self.assertEqual(first, second)
        self.assertEqual(first.robust[13][0], 1.0)
        self.assertEqual(first.robust[12][0], 0.0)
        self.assertEqual(first.ranks[13][0], 1.0)
        self.assertAlmostEqual(first.ranks[12][0], -1.0 / 255.0)
        self.assertTrue(
            all(math.isfinite(value) for row in first.robust for value in row)
        )

    def test_lifecycle_scores_features_blind_then_freezes_on_validation_only(self):
        reader = RetrospectiveReader(self.dataset)
        candidate_names = reader.fit(self.train_labels)
        self.assertEqual(reader.state, ReaderLifecycle.TRAIN_FITTED)
        self.assertIn("contrast.robust.signed_mean", candidate_names)
        self.assertIn("contrast.robust.fisher", candidate_names)
        self.assertIn("prototype.robust.l1", candidate_names)
        self.assertIn("prototype.robust.l2", candidate_names)
        self.assertIn("prototype.robust.linf", candidate_names)
        self.assertIn("feature.rank.001.+1", candidate_names)

        # Neither scoring call accepts or needs labels, including the holdout.
        validation_blind = reader.score_candidates(DatasetSplit.VALIDATION)
        holdout_blind = reader.score_candidates(DatasetSplit.RETROSPECTIVE_HOLDOUT)
        self.assertEqual(len(validation_blind), len(candidate_names))
        self.assertEqual(len(validation_blind[0].rankings), 2)
        self.assertEqual(len(holdout_blind[0].rankings), 1)
        self.assertTrue(all(len(item.rankings[0].order) == 256 for item in holdout_blind))

        with self.assertRaisesRegex(ReaderError, "sealed until.*frozen"):
            reader.evaluate(self.holdout_labels)

        plan = reader.freeze(self.validation_labels)
        self.assertEqual(reader.state, ReaderLifecycle.FROZEN)
        self.assertEqual(plan.selected_operator.name, "feature.rank.001.+1")
        self.assertEqual(len(plan.candidate_validation), len(candidate_names))
        serialized = plan.describe()
        self.assertEqual(serialized["plan_sha256"], plan.plan_sha256)
        self.assertNotIn("correct_cell", json.dumps(serialized))
        self.assertFalse(
            serialized["information_boundary"]["holdout_labels_used"]
        )

        restored = FrozenReaderPlan.from_dict(json.loads(plan.to_json()))
        self.assertEqual(restored, plan)
        self.assertEqual(restored.plan_sha256, plan.plan_sha256)

        evaluation = reader.evaluate(self.holdout_labels)
        self.assertEqual(evaluation.rows[0].rank, 1)
        self.assertEqual(evaluation.mean_log2_rank_gain, 8.0)
        self.assertEqual(evaluation.top_k_rate(1), 1.0)
        self.assertEqual(evaluation.mean_reciprocal_rank, 1.0)

    def test_fit_rejects_non_train_labels_and_refits(self):
        reader = RetrospectiveReader(self.dataset)
        with self.assertRaisesRegex(ReaderError, "TRAIN.*VALIDATION"):
            reader.fit(self.validation_labels)
        reader.fit(self.train_labels)
        with self.assertRaisesRegex(ReaderError, "exactly once"):
            reader.fit(self.train_labels)

    def test_holdout_requires_post_reveal_provenance_after_freeze(self):
        reader = RetrospectiveReader(self.dataset)
        reader.fit(self.train_labels)
        reader.freeze(self.validation_labels)
        mislabeled = (
            _label(
                self.holdout,
                180,
                information_label=InformationLabel.TRAIN_LABEL,
            ),
        )
        with self.assertRaisesRegex(ReaderError, "POST_REVEAL"):
            reader.evaluate(mislabeled)

    def test_equal_work_baselines_are_complete_and_deterministic(self):
        first = baseline_rankings(self.holdout)
        second = baseline_rankings(self.holdout)
        self.assertEqual(first, second)
        self.assertEqual(
            tuple(item.reader_name for item in first),
            (
                "baseline.numeric_ascending",
                "baseline.public_hash",
                "baseline.published_target_blind_score",
            ),
        )
        self.assertTrue(all(item.scored_cells == 256 for item in first))
        self.assertTrue(all(item.target_blind for item in first))
        self.assertEqual(first[0].order, tuple(range(256)))
        self.assertEqual(first[2].order, tuple(reversed(range(256))))

    def test_evaluation_reports_rank_gain_top_k_and_mrr(self):
        first_order = tuple(range(256))
        second_order = (0, 1, 2, 4, 3, *range(5, 256))
        rankings = (
            RankedEpisode(
                family="fixture",
                target_id="a",
                split=DatasetSplit.RETROSPECTIVE_HOLDOUT,
                reader_name="reader",
                order=first_order,
                scores=tuple(-float(cell) for cell in range(256)),
            ),
            RankedEpisode(
                family="fixture",
                target_id="b",
                split=DatasetSplit.RETROSPECTIVE_HOLDOUT,
                reader_name="reader",
                order=second_order,
                scores=tuple(-float(cell) for cell in range(256)),
            ),
        )
        labels = (
            RevealedCellLabel(
                family="fixture",
                target_id="a",
                split=DatasetSplit.RETROSPECTIVE_HOLDOUT,
                correct_cell=0,
                source_member="result.json",
                source_sha256="f" * 64,
                information_label=InformationLabel.POST_REVEAL,
            ),
            RevealedCellLabel(
                family="fixture",
                target_id="b",
                split=DatasetSplit.RETROSPECTIVE_HOLDOUT,
                correct_cell=4,
                source_member="result.json",
                source_sha256="f" * 64,
                information_label=InformationLabel.POST_REVEAL,
            ),
        )
        evaluation = evaluate_rankings(rankings, labels, top_ks=(1, 4))
        self.assertEqual(tuple(row.rank for row in evaluation.rows), (1, 4))
        self.assertEqual(evaluation.mean_log2_rank_gain, 7.0)
        self.assertEqual(evaluation.median_log2_rank_gain, 7.0)
        self.assertEqual(evaluation.top_k_rate(1), 0.5)
        self.assertEqual(evaluation.top_k_rate(4), 1.0)
        self.assertEqual(evaluation.mean_reciprocal_rank, 0.625)

    def test_serialized_plan_hash_detects_tampering(self):
        reader = RetrospectiveReader(self.dataset)
        reader.fit(self.train_labels)
        value = reader.freeze(self.validation_labels).describe()
        value["validation_targets"][0] = "fixture/tampered"
        with self.assertRaisesRegex(ReaderError, "hash mismatch"):
            FrozenReaderPlan.from_dict(value)


if __name__ == "__main__":
    unittest.main()
