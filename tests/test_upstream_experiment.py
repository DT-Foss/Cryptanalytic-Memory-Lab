from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.shape532 import direct12_order
from o1_crypto_lab.upstream_experiment import (
    CONFIG_SCHEMA,
    DatasetSpec,
    PinnedO1C6Source,
    UpstreamExperimentError,
    build_panel_inventory,
    execution_evidence,
    freeze_selected_memory,
    run_upstream_ising_retrospective,
)
from o1_crypto_lab.upstream_panel import (
    DOMAIN_SIZE,
    HORIZONS,
    PanelViewSpec,
    UpstreamRawField,
    project_view,
    run_upstream_panel,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/upstream_ising_retrospective_v1.json"


def _character(mask: int, address: int) -> float:
    return -1.0 if (mask & address).bit_count() & 1 else 1.0


def _synthetic_field() -> UpstreamRawField:
    arrays = {}
    for horizon in HORIZONS:
        rows = []
        for address in range(DOMAIN_SIZE):
            unary = _character(1 << 4, address)
            pair = _character((1 << 2) | (1 << 9), address)
            conflicts = float(1 + (address % 11))
            decisions = 20.0 + 3.0 * unary + horizon
            propagations = 1000.0 + 120.0 * unary + 30.0 * pair + horizon
            accepted = float((address + horizon) % 7)
            offered = accepted + 1.0 + float((address >> 3) % 4)
            rejected = offered - accepted
            literals = 2.0 * offered + float(address % 5)
            rows.append(
                (
                    conflicts,
                    decisions,
                    propagations,
                    accepted,
                    offered,
                    rejected,
                    literals,
                    -float(address % 13),
                    -float(address % 17),
                    float(address % 19),
                )
            )
        arrays[horizon] = rows
    return UpstreamRawField.from_horizon_arrays(arrays)


class UpstreamConfigAndMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.field = _synthetic_field()
        cls.panel = run_upstream_panel(cls.field)

    def test_config_is_retrospective_target_free_and_under_direct_table_ceiling(self):
        config = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(config["schema"], CONFIG_SCHEMA)
        self.assertEqual(config["attempt_id"], "O1C-0007")
        self.assertNotIn("confirmed_prefix12", CONFIG.read_text(encoding="utf-8"))
        self.assertNotIn("A356_result", CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(config["budgets"]["maximum_new_solver_calls"], 0)
        self.assertEqual(config["budgets"]["maximum_A356_target_labels"], 0)
        self.assertLess(
            config["expected"]["selected_maximum_state_bytes"],
            config["budgets"]["direct_quantized_table_ceiling_bytes"],
        )
        a355 = DatasetSpec.from_config(
            config["source"]["A355"], expected_attempt_id="A355"
        )
        self.assertEqual(a355.fixed_units(0), (-79, -75, -71, -67))
        self.assertEqual(a355.fixed_units(15), (79, 75, 71, 67))
        self.assertTrue(a355.member(0).endswith("slice_00.json.zst"))

    def test_complete_panel_inventory_is_offset_exact_and_target_blind(self):
        inventory, blob = build_panel_inventory(self.panel)
        self.assertEqual(inventory["orders"], 672)
        self.assertEqual(inventory["streamable_orders_before_tie_gate"], 448)
        self.assertGreater(inventory["selection_eligible_orders"], 0)
        self.assertLessEqual(inventory["selection_eligible_orders"], 448)
        self.assertEqual(len(blob), 672 * 4096 * 2)
        self.assertEqual(
            hashlib.sha256(blob).hexdigest(), inventory["order_blob_sha256"]
        )
        self.assertFalse(inventory["target_address_present"])
        self.assertFalse(inventory["target_ranks_present"])
        for index, row in enumerate(inventory["views"]):
            self.assertEqual(row["offset_bytes"], index * 8192)
            self.assertEqual(row["length_bytes"], 8192)
            payload = blob[row["offset_bytes"] : row["offset_bytes"] + 8192]
            self.assertEqual(hashlib.sha256(payload).hexdigest(), row["order_sha256"])

    def test_zscore_elision_is_order_exact_and_unary_state_is_266_bytes(self):
        spec = PanelViewSpec(
            "search_propagations",
            1,
            "signed-log1p",
            "degree1",
            "negative",
        )
        evidence = execution_evidence(self.field, spec)
        self.assertTrue(all(math.isfinite(value) for value in evidence))
        memory = freeze_selected_memory(self.field, spec)
        panel_order = direct12_order(project_view(self.field, spec))
        self.assertEqual(memory.order, panel_order)
        self.assertEqual(memory.plan.state_scalars, 12)
        self.assertEqual(
            memory.plan.maximum_serialized_logical_mechanism_state_bytes,
            266,
        )
        self.assertEqual(len(memory.to_bytes()), 162)
        self.assertEqual(memory.retained_candidate_rows, 0)
        self.assertEqual(
            memory.plan.expected_evidence_sha256,
            memory.evidence_field_sha256,
        )

    def test_rank_transform_cannot_become_an_executable_memory(self):
        spec = PanelViewSpec(
            "conflicts", 1, "rank", "degree1+2", "negative"
        )
        with self.assertRaisesRegex(UpstreamExperimentError, "streamable"):
            execution_evidence(self.field, spec)


class PinnedSourceTests(unittest.TestCase):
    def test_exact_allowlist_rejects_unknown_and_repeated_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capsule = root / "runs" / "fixture"
            capsule.mkdir(parents=True)
            member = "artifacts/safe.bin"
            path = capsule / member
            path.parent.mkdir(parents=True)
            path.write_bytes(b"safe")
            manifest = capsule / "artifacts.sha256"
            manifest.write_text(
                f"{hashlib.sha256(b'safe').hexdigest()}  {member}\n",
                encoding="utf-8",
            )
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            for file in (path, manifest):
                file.chmod(0o444)
            path.parent.chmod(0o555)
            capsule.chmod(0o555)
            try:
                source = PinnedO1C6Source(
                    lab_root=root,
                    capsule_relative="runs/fixture",
                    expected_manifest_sha256=manifest_sha,
                    allowed_members=(member,),
                    writer=None,
                )
                self.assertEqual(source.read(member, phase="TEST"), b"safe")
                with self.assertRaisesRegex(UpstreamExperimentError, "repeated"):
                    source.read(member, phase="TEST")
                with self.assertRaisesRegex(UpstreamExperimentError, "outside allowlist"):
                    source.read("artifacts/other.bin", phase="TEST")
            finally:
                capsule.chmod(0o755)
                path.parent.chmod(0o755)
                for file in (path, manifest):
                    file.chmod(0o644)


@unittest.skipUnless(
    os.environ.get("O1_CRYPTO_UPSTREAM_REAL") == "1",
    "set O1_CRYPTO_UPSTREAM_REAL=1 for the immutable O1C-0006 replay",
)
class RealUpstreamExperimentTests(unittest.TestCase):
    def test_exact_real_panel_null_state_and_target_blind_a356_order(self):
        def panel_receipt(inventory, blob):
            return {
                "schema": "o1-crypto-o1c0007-panel-persistence-receipt-v1",
                "persisted": True,
                "inventory_sha256": inventory["inventory_sha256"],
                "order_blob_sha256": hashlib.sha256(blob).hexdigest(),
                "orders": inventory["orders"],
                "target_labels_read": 0,
            }

        def selection_receipt(template, state, order):
            return {
                "schema": "o1-crypto-o1c0007-selection-persistence-receipt-v1",
                "persisted": True,
                "future_template_sha256": template["future_template_sha256"],
                "A355_state_sha256": hashlib.sha256(state).hexdigest(),
                "A355_order_sha256": hashlib.sha256(order).hexdigest(),
                "A356_source_members_opened": 0,
            }

        def deployment_receipt(document, state, order):
            return {
                "schema": "o1-crypto-o1c0007-deployment-persistence-receipt-v1",
                "persisted": True,
                "execution_sha256": document["execution_sha256"],
                "A356_state_sha256": hashlib.sha256(state).hexdigest(),
                "A356_order_sha256": hashlib.sha256(order).hexdigest(),
                "A356_target_labels_read": 0,
            }

        result = run_upstream_ising_retrospective(
            CONFIG,
            lab_root=ROOT,
            artifact_writer=None,
            on_panel_frozen=panel_receipt,
            on_selection_frozen=selection_receipt,
            on_deployment_frozen=deployment_receipt,
        )
        metrics = result.metrics()
        self.assertTrue(result.success_gate_passed)
        self.assertEqual(metrics["A355_rank"], 73)
        self.assertEqual(metrics["state_registers"], 12)
        self.assertEqual(
            metrics["maximum_serialized_logical_mechanism_state_bytes"], 266
        )
        self.assertEqual(metrics["exact_familywise_p"], 0.593505859375)
        self.assertEqual(metrics["A356_target_labels_read"], 0)
        self.assertFalse(metrics["statistical_sota_claimed"])


if __name__ == "__main__":
    unittest.main()
