from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.corrected_direct12 import (
    HIGH8_COORDINATES,
    LOW4_COORDINATES,
    SYNTHETIC_SOURCE_INDICES,
    CorrectedDirect12Error,
    PinnedSourceSnapshot,
    _corrected_mapping,
    _fixed_units,
    _validate_ledger,
    run_corrected_codec_bridge,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/corrected_codec_bridge_v1.json"


class CorrectedCodecFixtureTests(unittest.TestCase):
    def test_word0_bits_20_through_31_are_the_only_synthetic_coordinates(self):
        source = tuple(range(1, 47))
        self.assertEqual(LOW4_COORDINATES, (23, 22, 21, 20))
        self.assertEqual(HIGH8_COORDINATES, (31, 30, 29, 28, 27, 26, 25, 24))
        self.assertEqual(SYNTHETIC_SOURCE_INDICES, (*range(12), *range(24, 32)))
        self.assertEqual(
            _corrected_mapping(source),
            (*range(1, 13), *range(25, 33)),
        )
        self.assertEqual(_fixed_units(source, 0), (-24, -23, -22, -21))
        self.assertEqual(_fixed_units(source, 15), (24, 23, 22, 21))
        self.assertEqual(_fixed_units(source, 10), (24, -23, 22, -21))

    def test_active_or_outcome_source_names_are_rejected_before_any_read(self):
        cases = (
            "research/results/a345_progress.json",
            "research/results/a349_order_prospective_recovery_a350.json",
            "research/results/a350_outcome.json",
            "research/results/a358_progress.json",
            "research/results/fresh_w46_factor2_replication_a345_v1.json",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for member in cases:
                with self.subTest(member=member):
                    with self.assertRaises(CorrectedDirect12Error):
                        PinnedSourceSnapshot(
                            root,
                            ({
                                "path": member,
                                "role": "deployment",
                                "sha256": "0" * 64,
                                "bytes": 1,
                            },),
                            writer=None,
                        )

    def test_source_bytes_are_fail_closed_against_size_and_digest_pins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            member = root / "fixture.json"
            member.write_bytes(b"{}")
            snapshot = PinnedSourceSnapshot(
                root,
                ({
                    "path": "fixture.json",
                    "role": "mechanism",
                    "sha256": "0" * 64,
                    "bytes": 2,
                },),
                writer=None,
            )
            with self.assertRaisesRegex(CorrectedDirect12Error, "differs from its pin"):
                snapshot.read("fixture.json")

    def test_boolean_low4_alias_is_rejected(self):
        rows = [
            {
                "low4": low4,
                "resumed": False,
                "compressed_sha256": "1" * 64,
                "raw_sha256": "2" * 64,
                "compressed_bytes": 1,
                "raw_bytes": 1,
            }
            for low4 in range(16)
        ]
        rows[0]["low4"] = False
        with self.assertRaisesRegex(CorrectedDirect12Error, "integer"):
            _validate_ledger(rows, "A355")

    def test_noncanonical_config_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "corrected_codec_bridge_v1.json"
            copied.write_bytes(CONFIG.read_bytes())
            with self.assertRaisesRegex(CorrectedDirect12Error, "canonical lab config"):
                run_corrected_codec_bridge(copied, lab_root=ROOT)

    def test_frozen_config_identity_and_budget(self):
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(config["attempt_id"], "O1C-0006")
        self.assertEqual(config["claim_level"], "VALIDATION")
        self.assertEqual(config["budgets"]["maximum_online_state_bytes"], 8192)
        self.assertEqual(
            config["budgets"][
                "maximum_serialized_logical_mechanism_state_bytes"
            ],
            8192,
        )
        self.assertEqual(config["budgets"]["maximum_target_labels_for_bridge_selection"], 0)
        self.assertEqual(
            config["negative_control_gates"][
                "maximum_literal_o1c5_absolute_spearman"
            ],
            0.10,
        )
        self.assertEqual(len(config["source"]["members"]), 29)
        self.assertEqual(
            config["tournament"]["selection_rule"]["lexicographic_objective"][-1],
            "minimize_arm_id_ascii",
        )


@unittest.skipUnless(
    os.environ.get("O1_CRYPTO_CORRECTED_REAL") == "1",
    "set O1_CRYPTO_CORRECTED_REAL=1 to replay the two immutable corrected fields",
)
class CorrectedCodecRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preflight_artifacts = {}

        def collect_artifact(name, payload):
            if name in cls.preflight_artifacts:
                raise AssertionError(f"duplicate preflight artifact: {name}")
            cls.preflight_artifacts[name] = bytes(payload)

        cls.result = run_corrected_codec_bridge(
            CONFIG,
            lab_root=ROOT,
            artifact_writer=collect_artifact,
        )

    def test_exact_fields_orders_and_source_snapshot(self):
        fields = {field.attempt_id: field for field in self.result.fields}
        self.assertEqual(
            fields["A355"].historical_field_sha256,
            "de420a7e276bf945c821f56b4799e4c58e9c9a8e299bb9a8f329f63032a81c38",
        )
        self.assertEqual(
            fields["A355"].order_uint16be_sha256,
            "516e32fdf7b65761f2f7f4503eb6f48ce2e0c59354aed156bcac3a02f99c433a",
        )
        self.assertEqual(
            fields["A356"].historical_field_sha256,
            "ac29c51ba0e653762d60012af48a5b9fb83f2fbab73e028689f009c118aa12d1",
        )
        self.assertEqual(
            fields["A356"].order_uint16be_sha256,
            "436082dcc2a3b3f1be1ff5459c11b40de84aa57ef0bc160cc8fa57af17ae692f",
        )
        self.assertEqual(self.result.source_snapshot["member_count"], 61)
        self.assertEqual(
            self.result.source_snapshot["total_member_count_with_local_anchors"], 64
        )
        self.assertEqual(self.result.source_snapshot["capsule_snapshot_copies"], 64)
        self.assertEqual(
            sum(name.startswith("source_snapshot/") for name in self.preflight_artifacts),
            64,
        )
        self.assertEqual(self.result.source_snapshot["sibling_repository_writes"], 0)

    def test_selected_arm_and_every_success_gate(self):
        selection = self.result.report["selection"]
        self.assertEqual(selection["selected_arm"], "adaptive-dc-6bit-h1")
        metrics = selection["selected_metrics"]
        self.assertEqual(metrics["serialized_online_state_bytes"], 7716)
        self.assertEqual(
            metrics["maximum_serialized_logical_mechanism_state_bytes"], 8014
        )
        self.assertEqual(metrics["clip_count_both_fields"], 0)
        self.assertGreaterEqual(metrics["minimum_rank_spearman"], 0.9992)
        self.assertEqual(metrics["minimum_top8_overlap"], 1.0)
        self.assertEqual(metrics["minimum_top32_overlap"], 0.96875)
        gates = self.result.report["success_gates"]
        self.assertTrue(all(isinstance(value, bool) for value in gates.values()))
        self.assertTrue(all(gates.values()))
        self.assertTrue(self.result.success_gate_passed)
        self.assertFalse(selection["fresh_primary_mechanism_eligible"])
        boundary = self.result.report["claim_boundary"]
        self.assertTrue(boundary["information_equivalent_to_quantized_direct_table"])
        self.assertEqual(
            boundary["matched_direct_table_maximum_serialized_logical_bytes"],
            3918,
        )
        self.assertTrue(
            boundary["selected_spectral_ceiling_is_larger_than_direct_table"]
        )
        self.assertFalse(
            boundary["selected_spectral_ceiling_is_smaller_than_direct_table"]
        )
        self.assertFalse(boundary["sota_claim"])

    def test_historical_commitment_chain_is_recomputed(self):
        chain = self.result.report["historical_commitment_chain"]
        self.assertTrue(chain["all_internal_commitments_recomputed"])
        self.assertEqual(
            chain["A356_measurement_commitment_sha256"],
            "95ea76d80b65c121d8f92b62cde4aa49ede73a7c284dccc2cd9f1de7c4c4d535",
        )
        self.assertEqual(
            chain["A356_order_commitment_sha256"],
            "a41394ef15ba83d6ff9f1cefafc361ae8747ba4eeca2b5c0f13460e7d43b5ce5",
        )

    def test_corrected_variables_and_units_match_both_historical_mappings(self):
        descriptors = {field.attempt_id: field for field in self.result.fields}
        self.assertEqual(
            descriptors["A355"].synthetic_mapping_sha256,
            "861bc54e63a692ea5a97e4423965d43a0a452d7de01eb68b04f6021148f67a64",
        )
        self.assertEqual(
            descriptors["A356"].synthetic_mapping_sha256,
            "b94c8f3ba1bbc5779cef0e7312625b23ddf8e57b7364211c39fd0856fe2c2f13",
        )


if __name__ == "__main__":
    unittest.main()
