import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.label_broker import broker
from o1_crypto_lab.reader_experiment import _exact_familywise_selection_null
from o1_crypto_lab.stage3 import DatasetSplit
from o1_crypto_lab.trajectory_reader import (
    CandidateBlindRankings,
    RankedEpisode,
)


def ranking(name: str, target: str, order: tuple[int, ...]) -> RankedEpisode:
    scores = [0.0] * 256
    for position, cell in enumerate(order):
        scores[cell] = float(256 - position)
    return RankedEpisode(
        family="A296",
        target_id=target,
        split=DatasetSplit.VALIDATION,
        reader_name=name,
        order=order,
        scores=tuple(scores),
    )


class ReaderPipelineTests(unittest.TestCase):
    def test_exact_null_enumerates_complete_two_label_selection(self):
        ascending = tuple(range(256))
        descending = tuple(reversed(range(256)))
        candidates = (
            CandidateBlindRankings(
                operator_name="ascending",
                rankings=(
                    ranking("ascending", "w24_t02", ascending),
                    ranking("ascending", "w28_t02", ascending),
                ),
            ),
            CandidateBlindRankings(
                operator_name="descending",
                rankings=(
                    ranking("descending", "w24_t02", descending),
                    ranking("descending", "w28_t02", descending),
                ),
            ),
        )
        report = _exact_familywise_selection_null(candidates, observed_mean_gain=8.0)
        self.assertEqual(report["label_pairs_enumerated"], 65536)
        self.assertEqual(report["candidate_operators"], 2)
        self.assertGreater(report["familywise_p_ge_observed"], 0.0)
        self.assertLess(report["familywise_p_ge_observed"], 0.001)

    def test_broker_emits_only_explicitly_requested_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            member = (
                "chronology/arx-carry-leak/research/results/v1/"
                "chacha20_round20_causal_search_gain_panel_a296_v1.json"
            )
            path = root / member
            path.parent.mkdir(parents=True)
            result = {
                "targets": [
                    {
                        "target_id": "w24_t00",
                        "discovery": {
                            "fine_prefix12": 0xAB3,
                            "candidate": (0xAB << 16) | 7,
                        },
                    },
                    {
                        "target_id": "w24_t01",
                        "discovery": {
                            "fine_prefix12": 0xCD4,
                            "candidate": (0xCD << 16) | 9,
                        },
                    },
                ]
            }
            path.write_text(json.dumps(result), encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{digest}  {member}\n", encoding="utf-8")
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            response = broker(
                source_root=root,
                manifest=manifest,
                expected_manifest_sha256=manifest_sha,
                result_member=member,
                target_ids=["w24_t00"],
                purpose="unit-test TRAIN label",
            )
            self.assertEqual(len(response["labels"]), 1)
            self.assertEqual(response["labels"][0]["target_id"], "w24_t00")
            self.assertEqual(response["labels"][0]["correct_cell"], 0xAB)
            self.assertFalse(
                response["information_boundary"]["aggregate_result_bytes_returned"]
            )


if __name__ == "__main__":
    unittest.main()
