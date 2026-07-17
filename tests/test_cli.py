from __future__ import annotations

import argparse
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from o1_crypto_lab import cli


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/corrected_codec_bridge_v1.json"
UPSTREAM_CONFIG = ROOT / "configs/upstream_ising_retrospective_v1.json"
LIVING_READER_CONFIG = ROOT / "configs/living_inverse_reader_v1.json"
SIGNED_REPLICATION_CONFIG = ROOT / "configs/signed_direct_replication_v1.json"
O1C0009_MANIFEST = "f31d7672921dc0c2ec684cf8c5247a3ff2386fbea316c2eab98072cd22fb29d2"


class _RecordingRun:
    def __init__(self, events):
        self.events = events
        self.publication_prepared = False

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
    def test_complete_order_artifact_rejects_duplicate_or_out_of_domain_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "order.uint16be"
            path.write_bytes(b"".join(cell.to_bytes(2, "big") for cell in range(4096)))
            cli._verify_complete_direct12_order_artifact(path)

            duplicate = list(range(4096))
            duplicate[-1] = 0
            path.write_bytes(
                b"".join(cell.to_bytes(2, "big") for cell in duplicate)
            )
            with self.assertRaisesRegex(RuntimeError, "exact permutation"):
                cli._verify_complete_direct12_order_artifact(path)

            out_of_domain = list(range(4096))
            out_of_domain[-1] = 4096
            path.write_bytes(
                b"".join(cell.to_bytes(2, "big") for cell in out_of_domain)
            )
            with self.assertRaisesRegex(RuntimeError, "exact permutation"):
                cli._verify_complete_direct12_order_artifact(path)

    def test_complete_order_inventory_accepts_self_resolving_24_order_graph(self):
        rows = []
        groups = (
            ("exact-historical-reference", 2),
            ("negative-or-invalid-contract-control", 4),
            ("adaptive-dc-candidate", 18),
        )
        metadata = {
            "exact-historical-reference": {
                "score_field_member": "artifacts/score.json",
                "score_field_artifact_sha256": "1" * 64,
            },
            "negative-or-invalid-contract-control": {
                "control_metadata_member": "artifacts/controls.json",
                "control_metadata_artifact_sha256": "2" * 64,
            },
            "adaptive-dc-candidate": {
                "execution_member": "artifacts/execution.json",
                "execution_artifact_sha256": "3" * 64,
                "online_state_member": "artifacts/state.bin",
                "online_state_artifact_sha256": "4" * 64,
            },
        }
        sequence = 0
        for kind, count in groups:
            for _ in range(count):
                rows.append(
                    {
                        "kind": kind,
                        "member": f"artifacts/orders/{sequence}.uint16be",
                        "cells": 4096,
                        "bytes": 8192,
                        "complete_permutation": True,
                        **metadata[kind],
                    }
                )
                sequence += 1

        self.assertEqual(
            cli._validate_o1c0006_order_inventory(rows),
            {
                "exact-historical-reference": 2,
                "negative-or-invalid-contract-control": 4,
                "adaptive-dc-candidate": 18,
            },
        )

    def test_attempt_is_reserved_before_outcome_bearing_bridge_failure(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def recoverable_attempt_ids(self):
                return ()

            def finalized_attempt(self, attempt_id):
                return None

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


class UpstreamIsingCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_upstream_panel_failure(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def recoverable_attempt_ids(self):
                return ()

            def finalized_attempt(self, attempt_id):
                return None

            def start(self, **kwargs):
                events.append(("start", kwargs["attempt_id"]))
                return run

        def fail_upstream(*args, **kwargs):
            events.append(("upstream", "raised"))
            raise RuntimeError("synthetic upstream failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="b" * 40),
            patch.object(
                cli,
                "run_upstream_ising_retrospective",
                side_effect=fail_upstream,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._upstream_ising_freeze(
                argparse.Namespace(config=UPSTREAM_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("upstream"))
        self.assertIn(
            ("finalize", "failed", "o1-crypto-o1c0007-failure-v1"),
            events,
        )


class LivingInverseReaderCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_reader_failure(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def finalized_attempt(self, attempt_id):
                return None

            def recoverable_attempt_ids(self):
                return ()

            def start(self, **kwargs):
                events.append(("start", kwargs["attempt_id"]))
                return run

        def fail_reader(*args, **kwargs):
            events.append(("reader", "raised"))
            raise RuntimeError("synthetic reader failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="c" * 40),
            patch.object(
                cli,
                "run_living_inverse_reader_experiment",
                side_effect=fail_reader,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._living_inverse_reader(
                argparse.Namespace(config=LIVING_READER_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("reader"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-living-inverse-reader-failure-v1",
            ),
            events,
        )


class SignedDirectReplicationCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_replication_failure(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def verify(self, path):
                return SimpleNamespace(
                    ok=True,
                    manifest_sha256=O1C0009_MANIFEST,
                    checked=25,
                )

            def finalized_attempt(self, attempt_id):
                return None

            def recoverable_attempt_ids(self):
                return ()

            def start(self, **kwargs):
                events.append(("start", kwargs["attempt_id"]))
                return run

        def fail_replication(*args, **kwargs):
            events.append(("replication", "raised"))
            raise RuntimeError("synthetic signed replication failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="d" * 40),
            patch.object(
                cli,
                "run_signed_direct_replication",
                side_effect=fail_replication,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._signed_direct_replication(
                argparse.Namespace(config=SIGNED_REPLICATION_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("replication"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-signed-direct-replication-failure-v1",
            ),
            events,
        )

    def test_interrupted_replication_is_stopped_without_replay(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def verify(self, path):
                return SimpleNamespace(
                    ok=True,
                    manifest_sha256=O1C0009_MANIFEST,
                    checked=25,
                )

            def finalized_attempt(self, attempt_id):
                return None

            def recoverable_attempt_ids(self):
                return ("O1C-0010",)

            def recover(self, attempt_id):
                events.append(("recover", attempt_id))
                return run

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "run_signed_direct_replication") as experiment,
            patch("sys.stdout", new=io.StringIO()),
        ):
            code = cli._signed_direct_replication(
                argparse.Namespace(config=SIGNED_REPLICATION_CONFIG)
            )

        self.assertEqual(code, 2)
        experiment.assert_not_called()
        self.assertIn(("recover", "O1C-0010"), events)
        self.assertIn(
            (
                "finalize",
                "stopped",
                "o1-256-signed-direct-replication-interrupted-v1",
            ),
            events,
        )

    def test_interrupted_reader_is_stopped_without_replay(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def finalized_attempt(self, attempt_id):
                return None

            def recoverable_attempt_ids(self):
                return ("O1C-0009",)

            def recover(self, attempt_id):
                events.append(("recover", attempt_id))
                return run

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(
                cli, "run_living_inverse_reader_experiment"
            ) as reader,
            patch("sys.stdout", new=io.StringIO()),
        ):
            code = cli._living_inverse_reader(
                argparse.Namespace(config=LIVING_READER_CONFIG)
            )

        self.assertEqual(code, 2)
        reader.assert_not_called()
        self.assertIn(("recover", "O1C-0009"), events)
        self.assertIn(
            (
                "finalize",
                "stopped",
                "o1-256-living-inverse-reader-interrupted-v1",
            ),
            events,
        )


class RecoveryCLILifecycleTests(unittest.TestCase):
    def test_recoverable_upstream_interruption_stops_without_replay(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def recoverable_attempt_ids(self):
                return ("O1C-0007",)

            def finalized_attempt(self, attempt_id):
                return None

            def recover(self, attempt_id):
                events.append(("recover", attempt_id))
                return run

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "run_upstream_ising_retrospective") as experiment,
            patch("sys.stdout", new=io.StringIO()),
        ):
            code = cli._upstream_ising_freeze(
                argparse.Namespace(config=UPSTREAM_CONFIG)
            )

        self.assertEqual(code, 2)
        experiment.assert_not_called()
        self.assertIn(
            ("finalize", "stopped", "o1-crypto-o1c0007-interrupted-v1"),
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
