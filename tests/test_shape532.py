import hashlib
import json
import math
import shutil
import subprocess
import unittest
from pathlib import Path

from o1_crypto_lab.shape532 import (
    BASE_FEATURE_NAMES,
    BASE_FEATURE_NAMES_SHA256,
    FEATURE_NAMES,
    FEATURE_NAMES_SHA256,
    RAW_CHANNELS,
    Shape532Error,
    candidate_cover_zscores,
    descending_midrank,
    descending_midranks,
    direct12_order,
    direct12_order_uint16be_sha256,
    expand_cube_orbits,
    grouped_scores,
    normalized_cube_laplacian,
    pair_score,
    score_direct12_frozen_pair,
    standardized_contributions,
    trajectory_base133,
    trajectory_shape532,
    within_slice_population_zscores,
)


REPOSITORY = Path(__file__).parents[1]
SNAPSHOT = (
    REPOSITORY
    / "runs/20260715_123734_O1C-0003_direct12-source-snapshot/artifacts/source_snapshot"
)


def _raw_cells():
    cells = []
    for candidate in range(256):
        cell = {}
        for horizon in (1, 2, 4, 8):
            row = {
                channel: float((index + 1) * horizon)
                for index, channel in enumerate(RAW_CHANNELS)
            }
            row["conflicts"] = float(horizon)
            row["decisions"] = float(2 * horizon)
            row["search_propagations"] = float(6 * horizon)
            row["learned_clause_accepted_stage"] = float(3 * horizon)
            row["learned_literal_count_stage"] = float(12 * horizon)
            cell[horizon] = row
        cells.append(cell)
    return cells


class Shape532EquationTests(unittest.TestCase):
    def test_canonical_names_geometry_and_hashes(self):
        self.assertEqual(len(BASE_FEATURE_NAMES), 133)
        self.assertEqual(len(FEATURE_NAMES), 532)
        self.assertEqual(
            BASE_FEATURE_NAMES_SHA256,
            "89a4ddc5696a3312ca5d41d38c8f9b4facc9e750bcb85124b8de3b88b85dd93b",
        )
        self.assertEqual(
            FEATURE_NAMES_SHA256,
            "83154bc39a17121debca0884f776fe09be890eab323428a668387fcf806c3012",
        )
        self.assertEqual(
            FEATURE_NAMES[:4],
            tuple(f"{BASE_FEATURE_NAMES[0]}__{name}" for name in (
                "raw_z",
                "xor_laplacian",
                "xor_gradient_l2",
                "xor_gradient_maxabs",
            )),
        )

    def test_temporal_profile_differences_and_signed_ratios(self):
        base = trajectory_base133(_raw_cells())
        self.assertEqual(len(base), 256)
        self.assertEqual(len(base[0]), 133)
        expected_profile = (1 / 15, 2 / 15, 4 / 15, 8 / 15)
        expected_first = (1 / 15, 2 / 15, 4 / 15)
        expected_second = (1 / 15, 2 / 15)
        for actual, expected in zip(base[0][:4], expected_profile):
            self.assertAlmostEqual(actual, expected, places=15)
        for actual, expected in zip(base[0][4:7], expected_first):
            self.assertAlmostEqual(actual, expected, places=15)
        for actual, expected in zip(base[0][7:9], expected_second):
            self.assertAlmostEqual(actual, expected, places=15)
        # The four ratio blocks start after 13 channels * 9 temporal values.
        for value in base[0][117:121]:
            self.assertAlmostEqual(value, 1 / 3, places=15)
        for value in base[0][121:125]:
            self.assertAlmostEqual(value, 1 / 2, places=15)
        for value in base[0][125:129]:
            self.assertAlmostEqual(value, 1 / 2, places=15)
        for value in base[0][129:133]:
            self.assertAlmostEqual(value, 3 / 5, places=15)

    def test_candidate_zscore_threshold_and_cube_equations(self):
        base = [[0.0] * 133 for _ in range(256)]
        for candidate in range(256):
            base[candidate][0] = float(candidate)
            base[candidate][1] = 1.0 + (1e-13 if candidate == 0 else 0.0)
        standardized = candidate_cover_zscores(base)
        matrix = expand_cube_orbits(base)
        scale = math.sqrt((256**2 - 1) / 12)
        self.assertAlmostEqual(standardized[0][0], -127.5 / scale, places=14)
        self.assertTrue(all(row[1] == 0.0 for row in standardized))
        self.assertAlmostEqual(matrix[0][0], -127.5 / scale, places=14)
        self.assertAlmostEqual(matrix[0][1], -31.875 / scale, places=14)
        self.assertAlmostEqual(
            matrix[0][2], math.sqrt(21845 / 8) / scale, places=14
        )
        self.assertAlmostEqual(matrix[0][3], 128 / scale, places=14)
        self.assertEqual(matrix[0][4:8], (0.0, 0.0, 0.0, 0.0))

    def test_xor_translation_permutes_every_orbit_feature(self):
        base = [[0.0] * 133 for _ in range(256)]
        for candidate in range(256):
            base[candidate][0] = float((candidate * 73) % 257)
            base[candidate][7] = float(candidate.bit_count())
        original = expand_cube_orbits(base)
        mask = 0xA5
        permuted = expand_cube_orbits([base[candidate ^ mask] for candidate in range(256)])
        for candidate in range(256):
            for actual, expected in zip(permuted[candidate], original[candidate ^ mask]):
                self.assertAlmostEqual(actual, expected, places=14)

    def test_strict_input_schema_and_constant_full_transform(self):
        cells = _raw_cells()
        cells[3][2] = dict(cells[3][2])
        cells[3][2]["extra"] = 1.0
        with self.assertRaisesRegex(Shape532Error, "exactly the 13"):
            trajectory_shape532(cells)
        matrix = trajectory_shape532(_raw_cells())
        self.assertEqual(len(matrix), 256)
        self.assertEqual(len(matrix[0]), 532)
        self.assertTrue(all(value == 0.0 for row in matrix for value in row))


class FrozenPairPrimitiveTests(unittest.TestCase):
    def test_standardized_explicit_group_contributions(self):
        contributions = standardized_contributions(
            ((1.0, 2.0, 3.0), (3.0, 4.0, 5.0)),
            means=(1.0, 1.0, 1.0),
            scales=(2.0, 1.0, 4.0),
            coefficients=(2.0, -1.0, 4.0),
        )
        self.assertEqual(contributions, ((0.0, -1.0, 2.0), (2.0, -3.0, 4.0)))
        grouped = grouped_scores(contributions, {"outer": (0, 2), "middle": (1,)})
        self.assertEqual(grouped, {"outer": (2.0, 6.0), "middle": (-1.0, -3.0)})

    def test_cube_laplacian_midranks_and_pair_score(self):
        increasing = tuple(float(value) for value in range(256))
        decreasing = tuple(reversed(increasing))
        laplacian = normalized_cube_laplacian(increasing)
        self.assertEqual(laplacian[0], -31.875)
        ranks = descending_midranks(increasing)
        self.assertEqual(ranks[255], 1.0)
        self.assertEqual(ranks[0], 256.0)
        self.assertEqual(descending_midrank((1.0,) * 256, 37), 128.5)
        self.assertEqual(pair_score(increasing, decreasing), (-257.0,) * 256)

    def test_slice_population_zscore_direct_order_and_uint16_hash(self):
        scores = tuple(float(cell >> 4) for cell in range(4096))
        normalized = within_slice_population_zscores(scores)
        scale = math.sqrt((256**2 - 1) / 12)
        for low4 in range(16):
            self.assertAlmostEqual(normalized[low4], -127.5 / scale, places=14)
            self.assertAlmostEqual(normalized[(255 << 4) | low4], 127.5 / scale, places=14)
        order = direct12_order(normalized)
        expected = tuple((high8 << 4) | low4 for high8 in reversed(range(256)) for low4 in range(16))
        self.assertEqual(order, expected)
        self.assertEqual(
            direct12_order_uint16be_sha256(order),
            "156c83bec89deadb33c9946243b592c05c99ecd3836db6da6745872a4c7fc54c",
        )

    def test_deterministic_synthetic_a349_order_interface(self):
        def matrices():
            for low4 in range(16):
                yield tuple(
                    (
                        float((high8 * 73 + low4 * 17) % 257),
                        float((high8 * 151 + low4 * 29) % 263),
                    )
                    for high8 in range(256)
                )

        first = score_direct12_frozen_pair(
            matrices(),
            means=(0.0, 0.0),
            scales=(1.0, 1.0),
            coefficients=(1.0, 1.0),
            pair_group_indices=((0,), (1,)),
        )
        second = score_direct12_frozen_pair(
            matrices(),
            means=(0.0, 0.0),
            scales=(1.0, 1.0),
            coefficients=(1.0, 1.0),
            pair_group_indices=((0,), (1,)),
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.order), 4096)
        self.assertEqual(set(first.order), set(range(4096)))
        self.assertEqual(
            first.order_uint16be_sha256,
            "ba8733e91e13e9eec6f7fdd8c5cd3efce169c6b311d8b0af9a20cb9a479fc948",
        )


class FrozenSnapshotIntegrationTests(unittest.TestCase):
    def _measurement_cells(self, measurement):
        stage_rows = {
            (int(row["cell_index"]), int(row["horizon"])): row
            for row in measurement["run"]["stages"]
        }
        cells = []
        for candidate in range(256):
            cell = {}
            for horizon in (1, 2, 4, 8):
                row = stage_rows[(candidate, horizon)]
                self.assertEqual(
                    row["metric_names"],
                    ["conflicts", "decisions", "search_propagations"],
                )
                lengths = tuple(float(value) for value in row["learned_clause_lengths_stage"])
                if lengths:
                    mean = math.fsum(lengths) / len(lengths)
                    std = math.sqrt(
                        math.fsum((value - mean) ** 2 for value in lengths) / len(lengths)
                    )
                    maximum = max(lengths)
                else:
                    mean = std = maximum = 0.0
                cell[horizon] = {
                    "conflicts": row["metrics_stage_delta"][0],
                    "decisions": row["metrics_stage_delta"][1],
                    "search_propagations": row["metrics_stage_delta"][2],
                    "active_variables_delta": row["active_variables_delta"],
                    "irredundant_clauses_delta": row["irredundant_clauses_delta"],
                    "redundant_clauses_delta": row["redundant_clauses_delta"],
                    "learned_clause_accepted_stage": row["learned_clause_accepted_stage"],
                    "learned_clause_offered_stage": row["learned_clause_offered_stage"],
                    "learned_clause_rejected_large_stage": row[
                        "learned_clause_rejected_large_stage"
                    ],
                    "learned_literal_count_stage": row["learned_literal_count_stage"],
                    "learned_clause_length_mean": mean,
                    "learned_clause_length_std": std,
                    "learned_clause_length_max": maximum,
                }
            cells.append(cell)
        return cells

    def test_o1c0003_reproduces_frozen_a349_order_without_source_imports(self):
        zstd = shutil.which("zstd")
        if zstd is None or not SNAPSHOT.is_dir():
            self.skipTest("immutable O1C-0003 snapshot or zstd is unavailable")

        research = SNAPSHOT / "research"
        preflight_path = (
            research
            / "provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
        )
        group_path = research / "configs/chacha20_round20_signed_channel_ablation_v1.json"
        selection_path = (
            research
            / "configs/chacha20_round20_w46_direct12_prospective_a345_validation_a349_selection_v1.json"
        )
        order_path = (
            research
            / "results/v1/chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
        )
        model = json.loads(preflight_path.read_bytes())["frozen_model"]["model"]
        model_hash = hashlib.sha256(
            json.dumps(
                model, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(model_hash, "b096c08616a81712da881862b65f0c95388e4db3cf6b8e462bf7c2a072cb0da4")
        self.assertEqual(tuple(model["feature_names"]), FEATURE_NAMES)

        groups = {
            row["name"]: tuple(row["feature_indices"])
            for row in json.loads(group_path.read_bytes())["frozen_model"][
                "signed_semantic_groups"
            ]
        }
        selected_views = json.loads(selection_path.read_bytes())[
            "selected_view_algorithm"
        ]["selected_known_key_views"]
        suffix = "::normalized_8cube_graph_laplacian"
        selected_groups = tuple(groups[view.removesuffix(suffix)] for view in selected_views)
        measurement_root = (
            research
            / "results/v1/chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1"
        )

        def matrices():
            for low4 in range(16):
                compressed = measurement_root / f"slice_{low4:02x}.json.zst"
                process = subprocess.run(
                    [zstd, "-q", "-d", "-c", str(compressed)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                measurement = json.loads(process.stdout)
                self.assertEqual(measurement["low4"], low4)
                yield trajectory_shape532(self._measurement_cells(measurement))

        reproduced = score_direct12_frozen_pair(
            matrices(),
            means=model["means"],
            scales=model["scales"],
            coefficients=model["coefficients"],
            pair_group_indices=selected_groups,
        )
        frozen_order = json.loads(order_path.read_bytes())
        self.assertEqual(tuple(frozen_order["selected_order"]), reproduced.order)
        reproduced_score_hash = hashlib.sha256(
            json.dumps(
                list(reproduced.slice_zscores),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(reproduced_score_hash, frozen_order["score_field_sha256"])
        self.assertEqual(
            reproduced_score_hash,
            "075dd9a51afadbeba7c1012ab37aab9314e1c47589d01139291d567ecfa0a529",
        )
        self.assertEqual(
            reproduced.order_uint16be_sha256,
            frozen_order["selected_order_uint16be_sha256"],
        )
        self.assertEqual(
            reproduced.order_uint16be_sha256,
            "441c6af3d9a2a32e1a61f0d50804a1ecbf2363517a7b570c408a09a15fd1bbaa",
        )

        a348_root = (
            research
            / "results/v1/chacha20_round20_w46_direct12_sliced_reader_a348_v1"
        )

        def a348_matrices():
            for low4 in range(16):
                compressed = a348_root / f"slice_{low4:02x}.json.zst"
                process = subprocess.run(
                    [zstd, "-q", "-d", "-c", str(compressed)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                measurement = json.loads(process.stdout)
                self.assertEqual(measurement["low4"], low4)
                yield trajectory_shape532(self._measurement_cells(measurement))

        reproduced_a348 = score_direct12_frozen_pair(
            a348_matrices(),
            means=model["means"],
            scales=model["scales"],
            coefficients=model["coefficients"],
            pair_group_indices=selected_groups,
        )
        frozen_a348 = json.loads(
            (
                research
                / "results/v1/chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
            ).read_bytes()
        )
        raw_name = "A342_selected_pair_global_raw"
        normalized_name = "A342_selected_pair_slice_z"

        def canonical_score_hash(values):
            return hashlib.sha256(
                json.dumps(
                    list(values),
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()

        raw_score_hash = canonical_score_hash(reproduced_a348.raw_pair_scores)
        normalized_score_hash = canonical_score_hash(reproduced_a348.slice_zscores)
        self.assertEqual(raw_score_hash, frozen_a348["score_field_sha256"][raw_name])
        self.assertEqual(
            raw_score_hash,
            "7aca086229e8a72fa4acfc8af11942ea9e728b4e3a0b7a3682fd9e5dc04726ce",
        )
        self.assertEqual(
            normalized_score_hash,
            frozen_a348["score_field_sha256"][normalized_name],
        )
        self.assertEqual(
            normalized_score_hash,
            "81e489f95d93f3b950aad152bcab0abab193d63d099f74f9f08aa00797b32b5f",
        )
        raw_order = direct12_order(reproduced_a348.raw_pair_scores)
        self.assertEqual(tuple(frozen_a348["orders"][raw_name]), raw_order)
        raw_order_hash = direct12_order_uint16be_sha256(raw_order)
        self.assertEqual(raw_order_hash, frozen_a348["rank_panel"][raw_name]["order_uint16be_sha256"])
        self.assertEqual(
            raw_order_hash,
            "94d7d510f90da9d041807d43a18d469c800e22d5e3c4e2106522ff2b715dd035",
        )
        self.assertEqual(
            tuple(frozen_a348["orders"][normalized_name]), reproduced_a348.order
        )
        self.assertEqual(
            reproduced_a348.order_uint16be_sha256,
            frozen_a348["rank_panel"][normalized_name]["order_uint16be_sha256"],
        )
        self.assertEqual(
            reproduced_a348.order_uint16be_sha256,
            "922810f3695208a5b5ddeb612a588050cef59596450c5cd63aef48d2687db563",
        )


if __name__ == "__main__":
    unittest.main()
