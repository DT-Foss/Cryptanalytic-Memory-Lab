import json
import tempfile
import unittest
from pathlib import Path

from o1_crypto_lab.events import OutcomeStatus
from o1_crypto_lab.replay import O1OSessionReplay, ReplayError


class ReplayTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        (root / "session.json").write_text(
            json.dumps({"session_id": "fixture-session", "ai_calls": 0}),
            encoding="utf-8",
        )
        (root / "engagement_report.json").write_text(
            json.dumps(
                {
                    "services_discovered": [{"service": "fixture"}],
                    "tools_generated": 2,
                    "tools_succeeded": 1,
                    "adaptive_retries": 1,
                    "retry_successes": 0,
                    "chained_tools": 1,
                }
            ),
            encoding="utf-8",
        )
        first = root / "001_first"
        first.mkdir()
        (first / "meta.json").write_text(
            json.dumps({"task_id": "001", "compiles": True, "verified": True}),
            encoding="utf-8",
        )
        (first / "execution_result.json").write_text(
            json.dumps(
                {
                    "status": "success",
                    "exit_code": 0,
                    "stdout": "SENSITIVE RAW PAYLOAD",
                    "stderr": "",
                }
            ),
            encoding="utf-8",
        )
        # A file that would fail loudly if imported. Replay must never touch it.
        (first / "generated.py").write_text(
            "raise RuntimeError('must never execute')\n", encoding="utf-8"
        )
        second = root / "002_second"
        second.mkdir()
        (second / "meta.json").write_text(
            json.dumps({"task_id": "002", "compiles": True, "verified": False}),
            encoding="utf-8",
        )
        (second / "execution_result.json").write_text(
            json.dumps(
                {
                    "status": "execution_failed",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "x",
                }
            ),
            encoding="utf-8",
        )

    def test_replay_is_deterministic_redacted_and_semantically_separated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            first = O1OSessionReplay(root).replay()
            second = O1OSessionReplay(root).replay()
            self.assertEqual(first, second)
            self.assertEqual(
                first.source_snapshot_sha256, second.source_snapshot_sha256
            )
            self.assertEqual(len(first.tasks), 2)
            self.assertEqual(len(first.events), 12)
            self.assertEqual(first.tasks[0].process, OutcomeStatus.POSITIVE)
            self.assertEqual(first.tasks[1].process, OutcomeStatus.NEGATIVE)
            self.assertEqual(first.tasks[0].capability, OutcomeStatus.UNKNOWN)
            self.assertEqual(first.tasks[0].mission, OutcomeStatus.UNKNOWN)
            described = json.dumps(first.describe(include_events=True))
            self.assertNotIn("SENSITIVE RAW PAYLOAD", described)
            self.assertNotIn("RuntimeError", described)
            self.assertTrue(
                first.describe()["semantic_contract"][
                    "process_success_is_not_capability_success"
                ]
            )
            self.assertEqual(len({event.event_id for event in first.events}), 12)
            self.assertEqual(first.adaptive_trace.adaptive_retries, 1)
            target_model = first.build_target_model()
            self.assertEqual(target_model.observations, 12)
            self.assertEqual(target_model.stale_steps, 0)
            self.assertEqual(
                first.describe()["target_model_ingest"]["observations"], 12
            )

    def test_rejects_task_id_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._fixture(root)
            (root / "001_first" / "meta.json").write_text(
                json.dumps({"task_id": "999", "compiles": True}), encoding="utf-8"
            )
            with self.assertRaises(ReplayError):
                O1OSessionReplay(root).replay()

    def test_rejects_non_integer_exit_codes(self):
        for value in (False, 0.0):
            with self.subTest(value=value), self.assertRaises(ReplayError):
                O1OSessionReplay._process_status(
                    {"exit_code": value, "status": "success"}
                )

    def test_rejects_ambiguous_non_string_output_payloads(self):
        for value in (None, 7, {"message": "x"}):
            with self.subTest(value=value), self.assertRaises(ReplayError):
                O1OSessionReplay._output_bytes({"stdout": value}, field="stdout")


if __name__ == "__main__":
    unittest.main()
