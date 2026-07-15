import json
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.failure_memory import FailureLedger, FailureRecord, LedgerScope
from o1_crypto_lab.isolation import IsolationPolicy
from o1_crypto_lab.types import InformationLabel


class FailureMemoryTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = "a" * 64

    def test_discovery_and_post_test_ledgers_are_separated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            ledger = FailureLedger("runs/failures.jsonl", policy=IsolationPolicy(root))
            discovery = FailureRecord.build(
                ["align", "score"],
                scope=LedgerScope.DISCOVERY,
                reason_code="NO_GAIN",
                detail="held-out gain was zero",
                source_snapshot_sha256=self.snapshot,
                labels=[InformationLabel.PUBLIC],
                metrics={"gain": 0.0},
            )
            post_test = FailureRecord.build(
                ["revealed", "rank"],
                scope=LedgerScope.POST_TEST_AUDIT,
                reason_code="AUDIT_ONLY",
                detail="diagnosis after target reveal",
                source_snapshot_sha256=self.snapshot,
                labels=[InformationLabel.POST_REVEAL],
            )
            ledger.append(discovery)
            ledger.append(post_test)
            records = ledger.discovery_records()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["reason_code"], "NO_GAIN")
            audits = ledger.post_test_records()
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0]["reason_code"], "AUDIT_ONLY")
            self.assertNotEqual(ledger.discovery_path, ledger.post_test_path)
            self.assertEqual(
                {path.name for path in root.joinpath("runs").iterdir()},
                {"failures.discovery.jsonl", "failures.post-test-audit.jsonl"},
            )

    def test_contaminated_discovery_record_is_rejected(self):
        record = FailureRecord.build(
            ["bad"],
            scope=LedgerScope.DISCOVERY,
            reason_code="LEAK",
            detail="post reveal",
            source_snapshot_sha256=self.snapshot,
            labels=[InformationLabel.TARGET_SECRET],
        )
        with self.assertRaises(ValueError):
            record.validate()
        non_finite = FailureRecord.build(
            ["bad-metric"],
            scope=LedgerScope.DISCOVERY,
            reason_code="METRIC",
            detail="invalid",
            source_snapshot_sha256=self.snapshot,
            metrics={"gain": float("nan")},
        )
        with self.assertRaises(ValueError):
            non_finite.validate()

    def test_chain_hash_encoding_is_unambiguous(self):
        joined = FailureRecord.build(
            ["a\x00b"],
            scope=LedgerScope.DISCOVERY,
            reason_code="ONE",
            detail="one name",
            source_snapshot_sha256=self.snapshot,
        )
        split = FailureRecord.build(
            ["a", "b"],
            scope=LedgerScope.DISCOVERY,
            reason_code="TWO",
            detail="two names",
            source_snapshot_sha256=self.snapshot,
        )
        self.assertNotEqual(joined.chain_sha256, split.chain_sha256)
        with self.assertRaises(ValueError):
            FailureRecord.build(
                [],
                scope=LedgerScope.DISCOVERY,
                reason_code="EMPTY",
                detail="no chain",
                source_snapshot_sha256=self.snapshot,
            )

    def test_ledger_file_symlink_cannot_escape_lab(self):
        with (
            tempfile.TemporaryDirectory() as lab,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(lab)
            (root / "runs").mkdir()
            ledger = FailureLedger("runs/failures.jsonl", policy=IsolationPolicy(root))
            outside_file = Path(outside) / "captured.jsonl"
            outside_file.write_text("unchanged\n", encoding="utf-8")
            ledger.discovery_path.symlink_to(outside_file)
            record = FailureRecord.build(
                ["safe"],
                scope=LedgerScope.DISCOVERY,
                reason_code="NO_GAIN",
                detail="must stay confined",
                source_snapshot_sha256=self.snapshot,
            )
            with self.assertRaises(PermissionError):
                ledger.append(record)
            self.assertEqual(outside_file.read_text(encoding="utf-8"), "unchanged\n")

    def test_discovery_reader_revalidates_persisted_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            ledger = FailureLedger("runs/failures.jsonl", policy=IsolationPolicy(root))
            record = FailureRecord.build(
                ["chain"],
                scope=LedgerScope.DISCOVERY,
                reason_code="NO_GAIN",
                detail="valid before tamper",
                source_snapshot_sha256=self.snapshot,
            ).describe()
            record["chain_sha256"] = "invalid"
            record["reason_code"] = ""
            ledger.discovery_path.write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "invalid record"):
                ledger.discovery_records()

    def test_scope_mismatch_in_physical_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "runs").mkdir()
            ledger = FailureLedger("runs/failures.jsonl", policy=IsolationPolicy(root))
            record = FailureRecord.build(
                ["audit"],
                scope=LedgerScope.POST_TEST_AUDIT,
                reason_code="AUDIT_ONLY",
                detail="valid audit record in the wrong file",
                source_snapshot_sha256=self.snapshot,
            ).describe()
            ledger.discovery_path.write_text(
                json.dumps(record) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "wrong physical scope"):
                ledger.discovery_records()


if __name__ == "__main__":
    unittest.main()
