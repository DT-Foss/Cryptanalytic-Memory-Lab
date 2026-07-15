import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.artifacts import ReadOnlyArtifactSource
from o1_crypto_lab.stage3 import (
    FEATURE_NAMES,
    BoundedZstdDecoder,
    DatasetSplit,
    EpisodeSpec,
    PostRevealLabelRegistry,
    Stage3Error,
    Stage3TrajectoryAdapter,
)
from o1_crypto_lab.types import InformationLabel


@unittest.skipUnless(shutil.which("zstd"), "zstd is required")
class Stage3AdapterTests(unittest.TestCase):
    def _fixture(self, root: Path, *, with_model_bits: bool = False):
        cells = []
        stages = []
        for cell_index in range(256):
            assumptions = [cell_index + 1]
            cells.append(
                {
                    "cell_index": cell_index,
                    "prefix8": f"{cell_index:08b}",
                    "assumptions": assumptions,
                    "fresh_solver_instance": True,
                    "final_status": "unknown",
                    "stages_run": 4,
                    "terminal_stage_index": None,
                    "metric_names": ["conflicts", "decisions", "search_propagations"],
                    "metrics_delta": [10, 20 + cell_index, 30],
                    "active_variables_delta": -1,
                    "irredundant_clauses_delta": -2,
                    "redundant_clauses_delta": 3,
                    "learned_clause_accepted_total": 4,
                    "learned_clause_offered_total": 5,
                    "learned_clause_rejected_large_total": 1,
                }
            )
            for stage_index, horizon in enumerate((1, 2, 4, 8)):
                stages.append(
                    {
                        "cell_index": cell_index,
                        "prefix8": f"{cell_index:08b}",
                        "assumptions": assumptions,
                        "stage_index": stage_index,
                        "horizon": horizon,
                        "status": "unknown",
                        "terminal": False,
                        "watchdog_fired": False,
                        "returncode": 0,
                        "model_bits_bit0_through_bit19": [1] if with_model_bits and cell_index == 7 else [],
                        "metric_names": ["conflicts", "decisions", "search_propagations"],
                        "metrics_stage_delta": [horizon, horizon + 1, horizon + 2],
                        "active_variables_delta": -1,
                        "irredundant_clauses_delta": -2,
                        "redundant_clauses_delta": 3,
                        "learned_clause_accepted_stage": 1,
                        "learned_clause_offered_stage": 2,
                        "learned_clause_rejected_large_stage": 1,
                        "learned_clause_lengths_stage": [2, 3],
                        "learned_literal_count_stage": 5,
                    }
                )
        measurement = {
            "schema": "fixture-measurement-v1",
            "attempt_id": "A296",
            "target_id": "w24_t00",
            "unknown_key_bits": 24,
            "target_label_available_to_measurement": False,
            "label_used_for_feature_construction_or_scoring": False,
            "complete_candidate_cover": True,
            "run": {
                "all_watchdogs_clear": True,
                "base_snapshot_identical_verified": True,
                "fresh_solver_per_candidate_verified": True,
                "bounded_variable_addition_enabled": False,
                "conflict_horizons": [1, 2, 4, 8],
                "cnf_sha256": "c" * 64,
                "cells": cells,
                "stages": stages,
            },
        }
        raw = (json.dumps(measurement, sort_keys=True) + "\n").encode()
        compressed = subprocess.run(
            [shutil.which("zstd"), "-q", "-c"],
            input=raw,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        measurement_member = "data/w24_t00.measurement.json.zst"
        order_member = "data/w24_t00.order.json"
        measurement_path = root / measurement_member
        measurement_path.parent.mkdir(parents=True)
        measurement_path.write_bytes(compressed)
        score_field = [float(index) for index in range(256)]
        order = {
            "schema": "fixture-order-v1",
            "target_id": "w24_t00",
            "unknown_key_bits": 24,
            "target_labels_used": 0,
            "model_refits": 0,
            "model_free_UNKNOWN_stages": 1024,
            "protocol_sha256": "a" * 64,
            "public_challenge_sha256": "b" * 64,
            "measurement": {
                "path": measurement_member,
                "compressed_bytes": len(compressed),
                "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
                "raw_bytes": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            },
            "score_field": score_field,
            "score_field_sha256": "d" * 64,
            "complete_coarse_order": list(reversed(range(256))),
            "selected_feature_indices": [1, 2],
        }
        order_bytes = (json.dumps(order, sort_keys=True) + "\n").encode()
        (root / order_member).write_bytes(order_bytes)
        result_member = "data/result.json"
        result = {
            "targets": [
                {
                    "target_id": "w24_t00",
                    "discovery": {
                        "fine_prefix12": 0xAB3,
                        "candidate": (0xAB << 16) | 7,
                    },
                }
            ]
        }
        result_bytes = (json.dumps(result, sort_keys=True) + "\n").encode()
        (root / result_member).write_bytes(result_bytes)
        manifest = root / "manifest.sha256"
        members = (measurement_member, order_member, result_member)
        manifest.write_text(
            "".join(
                f"{hashlib.sha256((root / member).read_bytes()).hexdigest()}  {member}\n"
                for member in members
            ),
            encoding="utf-8",
        )
        spec = EpisodeSpec(
            family="A296",
            target_id="w24_t00",
            unknown_key_bits=24,
            split=DatasetSplit.TRAIN,
            measurement_member=measurement_member,
            order_member=order_member,
        )
        return ReadOnlyArtifactSource(root, manifest), spec, result_member, len(raw)

    def test_ingests_target_blind_episode_with_bound_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, spec, _, raw_bytes = self._fixture(Path(temporary))
            episode = Stage3TrajectoryAdapter(source).load(spec)
            described = episode.describe()
            self.assertEqual(len(episode.cells), 256)
            self.assertEqual(len(episode.cells[0].values), len(FEATURE_NAMES))
            self.assertEqual(described["source"]["measurement_raw_bytes"], raw_bytes)
            self.assertFalse(described["information_boundary"]["post_reveal_result_read"])
            self.assertNotIn("label", json.dumps(described).lower().replace("target_label_available_to_adapter", ""))
            self.assertEqual(episode.cells[7].cell_index, 7)

    def test_rejects_model_bits_and_decode_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, spec, _, raw_bytes = self._fixture(
                Path(temporary), with_model_bits=True
            )
            with self.assertRaisesRegex(Stage3Error, "model bits"):
                Stage3TrajectoryAdapter(source).load(spec)
            compressed = source.read_bytes(spec.measurement_member)
            with self.assertRaisesRegex(Stage3Error, "byte cap"):
                BoundedZstdDecoder().decode(
                    compressed, max_output_bytes=raw_bytes - 1
                )

    def test_post_reveal_labels_require_separate_reader_and_deny_test(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, spec, result_member, _ = self._fixture(Path(temporary))
            registry = PostRevealLabelRegistry(source, [spec])
            labels = registry.read_panel_result(
                result_member, purpose="fit retrospective training reader"
            )
            self.assertEqual(labels[0].correct_cell, 0xAB)
            self.assertEqual(labels[0].information_label, InformationLabel.TRAIN_LABEL)
            self.assertEqual(len(registry.access_log), 1)
            sealed = EpisodeSpec(
                family=spec.family,
                target_id=spec.target_id,
                unknown_key_bits=spec.unknown_key_bits,
                split=DatasetSplit.TEST,
                measurement_member=spec.measurement_member,
                order_member=spec.order_member,
            )
            with self.assertRaisesRegex(Stage3Error, "refusing to reveal TEST"):
                PostRevealLabelRegistry(source, [sealed]).read_panel_result(
                    result_member, purpose="forbidden"
                )

    def test_adapter_denies_progress_members_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, spec, _, _ = self._fixture(Path(temporary))
            denied = EpisodeSpec(
                family=spec.family,
                target_id=spec.target_id,
                unknown_key_bits=spec.unknown_key_bits,
                split=spec.split,
                measurement_member="data/a350_progress.measurement.json.zst",
                order_member=spec.order_member,
            )
            with self.assertRaisesRegex(Stage3Error, "denied"):
                Stage3TrajectoryAdapter(source).load(denied)


if __name__ == "__main__":
    unittest.main()
