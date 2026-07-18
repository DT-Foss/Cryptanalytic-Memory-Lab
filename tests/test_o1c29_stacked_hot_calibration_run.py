from __future__ import annotations

import dataclasses
import hashlib
import os
import runpy
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.living_inverse import canonical_json_bytes
from o1_crypto_lab.o1c22_postresult_composer import UPSTREAM_ATTEMPT_ID
from o1_crypto_lab.o1c22_postresult_composer_run import (
    EXPECTED_UPSTREAM_ARTIFACTS,
    UPSTREAM_ARTIFACT_INDEX_SCHEMA,
)
from o1_crypto_lab.o1c29_real_protocol import (
    adapt_verified_o1c22_packet_corpus,
    bind_manager_authority_commitment,
)
from o1_crypto_lab.o1c29_stacked_hot_calibration_run import (
    ATTEMPT_ID,
    TOP_K_LIMIT,
    _acquire_execution_lease,
    execute_frozen_o1c29_protocol,
    inspect_o1c22_label_commitment_and_accounting,
    load_o1c29_stacked_hot_calibration_run_config,
    preflight_o1c29_stacked_hot_calibration,
    read_committed_o1c22_label_artifacts,
)
from o1_crypto_lab.polyphase_sufficient_state_v2 import STATE_BYTES
from o1_crypto_lab.run_capsule import RunCapsuleManager


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/o1c29_stacked_hot_calibration_v1.json"


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _real_fixture():
    namespace = runpy.run_path(str(ROOT / "tests/test_o1c29_real_protocol.py"))
    return namespace["_fixture"]()


def _packet_fixture(capsule: Path):
    namespace = runpy.run_path(str(ROOT / "tests/test_o1c29_packet_corpus.py"))
    return namespace["_write_fixture"](capsule)


def _index_payload(labels: bytes) -> bytes:
    entries: dict[str, dict[str, object]] = {
        "labels.bitpack": {
            "sha256": _sha(labels),
            "bytes": len(labels),
            "phase": "POST_FREEZE_SCORED_RESULT",
        }
    }
    while len(entries) < EXPECTED_UPSTREAM_ARTIFACTS:
        ordinal = len(entries)
        entries[f"synthetic/dummy-{ordinal:03d}.bin"] = {
            "sha256": hashlib.sha256(str(ordinal).encode("ascii")).hexdigest(),
            "bytes": 0,
            "phase": "SYNTHETIC",
        }
    return canonical_json_bytes(
        {
            "schema": UPSTREAM_ARTIFACT_INDEX_SCHEMA,
            "attempt_id": UPSTREAM_ATTEMPT_ID,
            "o1c19_manifest_sha256": "1" * 64,
            "o1c19_artifact_index_sha256": "2" * 64,
            "artifacts": entries,
            "indexed_artifact_count": len(entries),
            "indexed_artifact_bytes": len(labels),
        }
    )


@dataclasses.dataclass(frozen=True)
class _FakeFoldScore:
    outer_fold: str
    true_key_rank: int | None

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "synthetic-fold-score-v1",
            "outer_fold": self.outer_fold,
            "true_key_rank": self.true_key_rank,
        }


@dataclasses.dataclass(frozen=True)
class _FakeArmScore:
    arm: str
    operator_id: str
    folds: tuple[_FakeFoldScore, ...]
    total_compression_bits: float = 1.0
    mean_compression_bits: float = 0.25
    positive_fold_count: int = 4
    bit_accuracy: float = 0.51
    byte_top1_count: int = 1
    byte_top4_count: int = 2
    byte_top16_count: int = 3
    block16_top1_count: int = 0
    block16_top4_count: int = 1
    block16_top16_count: int = 2

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "synthetic-arm-score-v1",
            "arm": self.arm,
            "operator_id": self.operator_id,
            "folds": [row.receipt_document() for row in self.folds],
        }


@dataclasses.dataclass(frozen=True)
class _FakeScore:
    arms: tuple[_FakeArmScore, ...]
    receipt_sha256: str = "f" * 64

    def receipt_document(self) -> dict[str, object]:
        return {
            "schema": "synthetic-two-arm-score-v1",
            "arm_order": [row.arm for row in self.arms],
            "top_k_limit": TOP_K_LIMIT,
            "label_dependent_arm_selection": False,
        }


class _PendingManager:
    def __init__(self) -> None:
        self.finalized_calls: list[str] = []
        self.start_calls = 0

    def recoverable_attempt_ids(self) -> tuple[str, ...]:
        return ()

    def finalized_attempt(self, attempt_id: str):
        self.finalized_calls.append(attempt_id)
        return None

    def start(self, **_kwargs):
        self.start_calls += 1
        raise AssertionError("preflight reserved an attempt")


class O1C29StackedHotCalibrationRunTests(unittest.TestCase):
    def test_frozen_config_loads_exact_sources(self) -> None:
        config = load_o1c29_stacked_hot_calibration_run_config(CONFIG, root=ROOT)
        self.assertEqual(config.top["attempt_id"], ATTEMPT_ID)
        self.assertEqual(config.top["claim_level"], "RETROSPECTIVE")
        self.assertEqual(config.budgets.required_state_count, 16)
        self.assertEqual(config.budgets.required_state_bytes, STATE_BYTES)
        self.assertEqual(config.budgets.required_label_artifact_opens, 2)
        self.assertEqual(config.budgets.required_trusted_manager_verification_count, 1)
        self.assertEqual(config.budgets.required_trusted_manager_label_payload_reads, 1)

    def test_pending_preflight_never_reserves(self) -> None:
        manager = _PendingManager()
        preflight = preflight_o1c29_stacked_hot_calibration(
            CONFIG,
            root=ROOT,
            manager=manager,  # type: ignore[arg-type]
        )
        self.assertFalse(preflight.ready)
        self.assertEqual(preflight.report["status"], "prerequisite-pending")
        self.assertFalse(preflight.report["o1c29_reserved_by_this_preflight"])
        # The O1C-0022 lookup occurs only in the forked trusted verifier, so
        # the parent process observes only its own-attempt lookup.
        self.assertEqual(manager.finalized_calls, [ATTEMPT_ID])
        self.assertEqual(manager.start_calls, 0)

    def test_execution_lease_excludes_second_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            first = _acquire_execution_lease(manager)
            self.assertIsNotNone(first)
            try:
                self.assertIsNone(_acquire_execution_lease(manager))
            finally:
                os.close(first)  # type: ignore[arg-type]
            second = _acquire_execution_lease(manager)
            self.assertIsNotNone(second)
            os.close(second)  # type: ignore[arg-type]

    def test_label_index_authority_is_label_free_until_gated_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _packet_fixture(Path(temporary) / "capsule")
            dummy = next(
                name
                for name in fixture.entries
                if name.startswith("synthetic-authority/")
            )
            del fixture.entries[dummy]
            labels = bytes(range(128))
            fixture.entries["labels.bitpack"] = {
                "sha256": _sha(labels),
                "bytes": len(labels),
                "phase": "POST_FREEZE_SCORED_RESULT",
            }
            fixture.write_index()
            (fixture.capsule / "config.json").write_bytes(b"{}")
            metrics = {
                "values": {
                    "persistent_artifact_bytes": sum(
                        int(row["bytes"]) for row in fixture.entries.values()
                    )
                    + len(
                        (fixture.artifacts_root / "artifact_index.json").read_bytes()
                    ),
                    "budget_checks": {"persistent_artifacts": True},
                }
            }
            (fixture.capsule / "metrics.json").write_bytes(
                canonical_json_bytes(metrics)
            )
            index_payload = (
                fixture.artifacts_root / "artifact_index.json"
            ).read_bytes()
            commitment, accounting = inspect_o1c22_label_commitment_and_accounting(
                fixture.source.finalized,
                expected_artifact_index_sha256=_sha(index_payload),
                upstream_maximum_persistent_bytes=1 << 30,
            )
            # The indexed payload did not exist during inspection: successful
            # inspection therefore proves the pre-state surface was index-only.
            label_path = fixture.artifacts_root / "labels.bitpack"
            self.assertFalse(label_path.exists())
            self.assertGreater(accounting.authority_original_pass_bytes, 0)
            self.assertGreater(accounting.authority_projection_pass_bytes, 0)
            self.assertEqual(accounting.label_open_count, 2)
            label_path.write_bytes(labels)
            opened_index, opened_labels = read_committed_o1c22_label_artifacts(
                commitment
            )
            self.assertEqual(opened_index, index_payload)
            self.assertEqual(opened_labels, labels)
            label_path.write_bytes(labels[:-1] + b"x")
            with self.assertRaisesRegex(ValueError, "labels.bitpack differs"):
                read_committed_o1c22_label_artifacts(commitment)

    def test_synthetic_complete_lifecycle_persists_before_each_label_open(self) -> None:
        corpus, _labels, labels_payload, index_payload = _real_fixture()
        inputs = adapt_verified_o1c22_packet_corpus(corpus)
        manager_authority = bind_manager_authority_commitment(inputs, corpus)
        events: list[tuple[str, str]] = []
        payloads: dict[str, bytes] = {}

        def persist(relative: str, payload: bytes, _phase: str) -> None:
            self.assertNotIn(relative, payloads)
            payloads[relative] = payload
            events.append(("persist", relative))

        def read_labels(phase: str) -> tuple[bytes, bytes]:
            events.append(("labels", phase))
            return bytes(index_payload), bytes(labels_payload)

        def scorer(result, capability, *, top_k_limit):
            events.append(("score", str(top_k_limit)))
            self.assertEqual(top_k_limit, TOP_K_LIMIT)
            self.assertEqual(
                capability.prediction_result_receipt_sha256,
                result.receipt_sha256,
            )
            folds = tuple(
                _FakeFoldScore(fold, 1 if index == 0 else None)
                for index, fold in enumerate(result.global_freeze.fold_ids)
            )
            return _FakeScore(
                arms=(
                    _FakeArmScore("primary", "horizon_nonnegative_simplex_v1", folds),
                    _FakeArmScore(
                        "secondary", "magnitude_confidence_calibration_v1", folds
                    ),
                )
            )

        selector_sha = "ab" * 32
        execution = execute_frozen_o1c29_protocol(
            inputs,
            manager_authority=manager_authority,
            persist=persist,
            read_label_artifacts=read_labels,
            actual_o1c23_selector_sha256=selector_sha,
            scorer=scorer,
        )
        calibration_open = events.index(("labels", "CALIBRATION"))
        scoring_open = events.index(("labels", "SCORING"))
        scoring_call = events.index(("score", str(TOP_K_LIMIT)))
        state_bins = [name for name in payloads if name.endswith("/state.bin")]
        state_receipts = [name for name in payloads if name.endswith("/freeze.json")]
        self.assertEqual(len(state_bins), 16)
        self.assertEqual(len(state_receipts), 16)
        self.assertTrue(all(len(payloads[name]) == STATE_BYTES for name in state_bins))
        self.assertLess(
            events.index(("persist", "states/global_freeze.json")),
            calibration_open,
        )
        fit_receipts = [name for name in payloads if name.endswith("/fit.json")]
        logits = [name for name in payloads if name.endswith("_logits.f32le")]
        self.assertEqual(len(fit_receipts), 4)
        self.assertEqual(len(logits), 8)
        for relative in (*fit_receipts, *logits, "predictions/frozen_result.json"):
            self.assertLess(events.index(("persist", relative)), scoring_open)
        self.assertLess(scoring_open, scoring_call)
        self.assertEqual(
            [event for event in events if event[0] == "labels"],
            [("labels", "CALIBRATION"), ("labels", "SCORING")],
        )
        self.assertEqual(execution.work["state_stream_consumes"], 16)
        self.assertEqual(execution.work["lineage_verification_consumes"], 4)
        self.assertEqual(execution.work["hot_switch_replays"], 0)
        self.assertEqual(execution.work["sibling_reads"], 0)
        self.assertEqual(execution.result.actual_o1c23_selector_sha256, selector_sha)
        for prediction in execution.result.predictions:
            self.assertFalse(
                prediction.receipt_document()[
                    "actual_o1c23_selector_used_for_scientific_selection"
                ]
            )
        self.assertIn("scores/primary/arm_score.json", payloads)
        self.assertIn("scores/secondary/arm_score.json", payloads)


if __name__ == "__main__":
    unittest.main()
