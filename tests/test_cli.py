from __future__ import annotations

import argparse
import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from o1_crypto_lab import cli


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/corrected_codec_bridge_v1.json"


class _RecordingRun:
    def __init__(self, events):
        self.events = events

    def checkpoint(self, payload):
        self.events.append(("checkpoint", payload["phase"]))

    def append_stdout(self, value):
        self.events.append(("stdout", value))

    def append_stderr(self, value):
        self.events.append(("stderr", value))

    def write_artifact(self, relative, payload):
        self.events.append(("artifact", relative))
        return ROOT / "runs/fake-o1c-0006/artifacts" / relative

    def finalize(self, *, metrics, status="completed", next_action=None):
        self.events.append(("finalize", status, metrics["schema"]))
        return SimpleNamespace(
            attempt_id="O1C-0006",
            path=ROOT / "runs/fake-o1c-0006",
            manifest_sha256="0" * 64,
            verification=SimpleNamespace(ok=True),
        )


class CorrectedBridgeCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_outcome_bearing_bridge_failure(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def recoverable_attempt_ids(self):
                return ()

            def start(self, **kwargs):
                events.append(("start", kwargs["attempt_id"]))
                return run

        def fail_bridge(*args, **kwargs):
            events.append(("bridge", "raised"))
            raise RuntimeError("synthetic bridge failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="a" * 40),
            patch.object(cli, "run_corrected_codec_bridge", side_effect=fail_bridge),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._corrected_codec_bridge(argparse.Namespace(config=CONFIG))

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("bridge"))
        self.assertIn(
            ("finalize", "failed", "o1-crypto-corrected-codec-bridge-failure-v1"),
            events,
        )

    def test_recoverable_hard_interruption_is_stopped_without_replay(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def recoverable_attempt_ids(self):
                return ("O1C-0006",)

            def recover(self, attempt_id):
                events.append(("recover", attempt_id))
                return run

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "run_corrected_codec_bridge") as bridge,
            patch("sys.stdout", new=io.StringIO()),
        ):
            code = cli._corrected_codec_bridge(argparse.Namespace(config=CONFIG))

        self.assertEqual(code, 2)
        bridge.assert_not_called()
        self.assertIn(
            (
                "finalize",
                "stopped",
                "o1-crypto-corrected-codec-bridge-interrupted-v1",
            ),
            events,
        )


if __name__ == "__main__":
    unittest.main()
