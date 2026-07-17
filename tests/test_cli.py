from __future__ import annotations

import argparse
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from o1_crypto_lab import cli


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "configs/corrected_codec_bridge_v1.json"
UPSTREAM_CONFIG = ROOT / "configs/upstream_ising_retrospective_v1.json"
LIVING_READER_CONFIG = ROOT / "configs/living_inverse_reader_v1.json"
SIGNED_REPLICATION_CONFIG = ROOT / "configs/signed_direct_replication_v1.json"
FULL256_CNF_CONFIG = ROOT / "configs/full256_cnf_foundation_v1.json"
FULL256_PAIRED_SENSOR_CONFIG = (
    ROOT / "configs/full256_paired_causal_sensor_v1.json"
)
FULL256_MULTIKEY_CONFIG = ROOT / "configs/full256_multikey_causal_calibration_v1.json"
FULL256_FROZEN_READER_CONFIG = (
    ROOT / "configs/full256_frozen_reader_replication_v1.json"
)
FULL256_POLYPHASE_CONFIG = ROOT / "configs/full256_polyphase_replication_v1.json"
FULL256_POLYPHASE_CONFIG_V2 = ROOT / "configs/full256_polyphase_replication_v2.json"
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


class Full256CNFFoundationCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_cnf_compilation_failure(self):
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

        def fail_foundation(*args, **kwargs):
            events.append(("cnf_foundation", "raised"))
            raise RuntimeError("synthetic CNF foundation failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="e" * 40),
            patch.object(
                cli,
                "run_full256_cnf_foundation",
                side_effect=fail_foundation,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._full256_cnf_foundation(
                argparse.Namespace(config=FULL256_CNF_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("cnf_foundation"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-full-cnf-foundation-failure-v1",
            ),
            events,
        )


class Full256PairedSensorCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_paired_sensor_failure(self):
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

        def fail_sensor(*args, **kwargs):
            events.append(("paired_sensor", "raised"))
            raise RuntimeError("synthetic paired sensor failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="f" * 40),
            patch.object(
                cli,
                "run_full256_paired_sensor",
                side_effect=fail_sensor,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._full256_paired_sensor(
                argparse.Namespace(config=FULL256_PAIRED_SENSOR_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("paired_sensor"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-paired-causal-sensor-failure-v1",
            ),
            events,
        )

    def test_parser_exposes_canonical_paired_sensor_command(self):
        args = cli.build_parser().parse_args(["full256-paired-sensor"])
        self.assertEqual(args.config, FULL256_PAIRED_SENSOR_CONFIG)
        self.assertIs(args.handler, cli._full256_paired_sensor)


class Full256MultiKeyCalibrationCLILifecycleTests(unittest.TestCase):
    def test_attempt_is_reserved_before_multikey_calibration_failure(self):
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

        def fail_calibration(*args, **kwargs):
            events.append(("multikey_calibration", "raised"))
            raise RuntimeError("synthetic multi-key calibration failure")

        with (
            patch.object(cli, "RunCapsuleManager", Manager),
            patch.object(cli, "_clean_git_commit", return_value="1" * 40),
            patch.object(
                cli,
                "run_full256_multikey_calibration",
                side_effect=fail_calibration,
            ),
            patch("sys.stderr", new=io.StringIO()),
        ):
            code = cli._full256_multikey_calibration(
                argparse.Namespace(config=FULL256_MULTIKEY_CONFIG)
            )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("multikey_calibration"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-multikey-causal-calibration-failure-v1",
            ),
            events,
        )

    def test_freezes_are_persisted_before_entropy_and_reveal(self):
        events = []
        with tempfile.TemporaryDirectory() as temporary:

            class PersistentRecordingRun(_RecordingRun):
                def write_artifact(self, relative, payload):
                    events.append(("artifact", relative))
                    path = Path(temporary) / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                    return path

            run = PersistentRecordingRun(events)

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

            def fail_after_freezes(*args, **kwargs):
                reader_document = {
                    "phase": "READER_FROZEN_BEFORE_SEALED_TARGET_ENTROPY",
                    "fresh_target_entropy_calls": 0,
                    "reader_freeze_sha256": "2" * 64,
                    "selected_arm": "u3",
                    "selected_logit_scale": 0.25,
                    "artifacts": {},
                }
                kwargs["on_reader_frozen"](
                    {
                        "reader_freeze.json": json.dumps(
                            reader_document, sort_keys=True
                        ).encode("utf-8")
                    },
                    reader_document,
                )
                events.append(("entropy", "first-sealed-target"))
                prediction_document = {
                    "phase": "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL",
                    "reader_freeze_sha256": "2" * 64,
                    "prediction_set_sha256": "3" * 64,
                    "sealed_targets": [
                        {"target_id": "sealed-0"},
                        {"target_id": "sealed-1"},
                    ],
                    "artifacts": {},
                }
                kwargs["on_predictions_frozen"](
                    {
                        "prediction_set_freeze.json": json.dumps(
                            prediction_document, sort_keys=True
                        ).encode("utf-8")
                    },
                    prediction_document,
                )
                events.append(("reveal", "first-sealed-target"))
                raise RuntimeError("stop after lifecycle probe")

            with (
                patch.object(cli, "RunCapsuleManager", Manager),
                patch.object(cli, "_clean_git_commit", return_value="2" * 40),
                patch.object(
                    cli,
                    "run_full256_multikey_calibration",
                    side_effect=fail_after_freezes,
                ),
                patch("sys.stderr", new=io.StringIO()),
            ):
                code = cli._full256_multikey_calibration(
                    argparse.Namespace(config=FULL256_MULTIKEY_CONFIG)
                )

        self.assertEqual(code, 1)
        reader_checkpoint = events.index(
            (
                "checkpoint",
                "READER_ARTIFACT_SET_PERSISTED_BEFORE_FRESH_ENTROPY",
            )
        )
        prediction_checkpoint = events.index(
            (
                "checkpoint",
                "ALL_PREDICTION_ARTIFACTS_PERSISTED_BEFORE_ANY_REVEAL",
            )
        )
        self.assertLess(
            reader_checkpoint, events.index(("entropy", "first-sealed-target"))
        )
        self.assertLess(
            prediction_checkpoint,
            events.index(("reveal", "first-sealed-target")),
        )

    def test_parser_exposes_canonical_multikey_command(self):
        args = cli.build_parser().parse_args(["full256-multikey-calibration"])
        self.assertEqual(args.config, FULL256_MULTIKEY_CONFIG)
        self.assertIs(args.handler, cli._full256_multikey_calibration)


class Full256FrozenReaderReplicationCLITests(unittest.TestCase):
    def test_runner_is_delegated_only_after_capsule_reservation(self):
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

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "configs/full256_frozen_reader_replication_v1.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("{}\n", encoding="utf-8")
            native_header = root / "native-dependency/cadical.hpp"
            native_library = root / "native-dependency/libcadical.a"
            native_header.parent.mkdir(parents=True)
            native_header.write_bytes(b"header")
            native_library.write_bytes(b"library")
            (root / "native").mkdir()
            (root / "native/cadical_pair_sensor.cpp").write_text(
                "// test\n", encoding="utf-8"
            )
            (root / "native/cadical_tracer_3_0_0.hpp").write_text(
                "// test\n", encoding="utf-8"
            )
            (root / "src/o1_crypto_lab").mkdir(parents=True)
            participating = (
                "chacha_trace.py",
                "living_inverse.py",
                "cadical_sensor.py",
                "causal_bitfield.py",
                "causal_orientation_reader.py",
                "full256_broker.py",
                "full256_cnf.py",
                "full256_paired_sensor.py",
                "full256_probe_core.py",
                "full256_multikey_calibration.py",
                "full256_frozen_reader_replication.py",
                "signed_direct_replication.py",
                "living_inverse_reader_experiment.py",
                "living_inverse_ridge.py",
                "living_inverse_corpus.py",
                "run_capsule.py",
                "cli.py",
            )
            for name in participating:
                (root / "src/o1_crypto_lab" / name).write_text(
                    "# test\n", encoding="utf-8"
                )
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "runs").mkdir()

            def digest(path):
                import hashlib

                return hashlib.sha256(path.read_bytes()).hexdigest()

            replication_config = SimpleNamespace(
                native=SimpleNamespace(
                    include_directory=str(native_header.parent),
                    static_library=str(native_library),
                    cadical_header_sha256=digest(native_header),
                    cadical_library_sha256=digest(native_library),
                ),
                corpus=SimpleNamespace(sealed_targets=8),
                controls=SimpleNamespace(transforms=()),
                probe=SimpleNamespace(sentinel_reruns_per_sweep=0),
                state_plan=SimpleNamespace(serialized_state_bytes=58_368),
                budgets=SimpleNamespace(
                    maximum_persistent_artifact_bytes=1_000_000,
                ),
                maximum_live_target_state_bytes=58_368,
            )
            top_level = {
                "attempt_id": "O1C-0014",
                "slug": "test-frozen-reader",
                "hypothesis": "test",
                "prediction": "test",
                "controls": [],
                "budgets": {},
                "source": {},
                "claim_level": "TEST",
                "next_action": "preserve",
            }
            fake_module = ModuleType("o1_crypto_lab.full256_frozen_reader_replication")

            def load_config(path):
                events.append(("load", path))
                return top_level, replication_config

            def fail_replication(*args, **kwargs):
                events.append(("replication", "raised"))
                raise RuntimeError("synthetic frozen-reader failure")

            fake_module.load_full256_frozen_reader_replication_config = load_config
            fake_module.run_full256_frozen_reader_replication = fail_replication
            with (
                patch.dict(
                    sys.modules,
                    {"o1_crypto_lab.full256_frozen_reader_replication": (fake_module)},
                ),
                patch.object(cli, "_lab_root", return_value=root),
                patch.object(cli, "RunCapsuleManager", Manager),
                patch.object(cli, "_clean_git_commit", return_value="1" * 40),
                patch("sys.stderr", new=io.StringIO()),
            ):
                code = cli._full256_frozen_reader_replication(
                    argparse.Namespace(config=config_path)
                )

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("load"), names.index("start"))
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("replication"))
        self.assertIn(
            (
                "finalize",
                "failed",
                "o1-256-frozen-reader-replication-failure-v1",
            ),
            events,
        )

    def test_parser_exposes_canonical_frozen_reader_command(self):
        args = cli.build_parser().parse_args(["full256-frozen-reader-replication"])
        self.assertEqual(args.config, FULL256_FROZEN_READER_CONFIG)
        self.assertIs(args.handler, cli._full256_frozen_reader_replication)

    def test_help_names_frozen_reader_replication(self):
        help_text = cli.build_parser().format_help()
        self.assertIn("full256-frozen-reader-replication", help_text)
        self.assertIn("replicate the frozen causal reader", help_text)
        self.assertIn("full-256 targets", help_text)


class Full256PolyphaseReplicationCLITests(unittest.TestCase):
    def test_freezes_are_persisted_after_reservation_and_before_entropy_or_reveal(
        self,
    ):
        events = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            class RecordingRun(_RecordingRun):
                def write_artifact(self, relative, payload):
                    events.append(("artifact", relative))
                    path = root / "fake-capsule/artifacts" / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                    return path

                def finalize(self, *, metrics, status="completed", next_action=None):
                    events.append(
                        (
                            "finalize_metrics",
                            metrics.get("sealed_target_reveals"),
                            metrics.get("cpu_seconds"),
                            metrics.get("wall_seconds"),
                            metrics.get("peak_rss_mib"),
                            metrics.get("outcome_failed"),
                            metrics.get("budget_checks", {}).get(
                                "persistent_artifacts"
                            ),
                            metrics.get("persisted_reveal_count"),
                            metrics.get("post_reveal_artifacts_persisted"),
                        )
                    )
                    return super().finalize(
                        metrics=metrics, status=status, next_action=next_action
                    )

            run = RecordingRun(events)

            class Manager:
                def __init__(self, lab_root):
                    self.root = lab_root

                def finalized_attempt(self, attempt_id):
                    return None

                def recoverable_attempt_ids(self):
                    return ()

                def start(self, **kwargs):
                    events.append(("start", kwargs["attempt_id"]))
                    return run

            config_path = root / "configs/full256_polyphase_replication_v1.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("{}\n", encoding="utf-8")
            native_header = root / "native-dependency/cadical.hpp"
            native_library = root / "native-dependency/libcadical.a"
            native_header.parent.mkdir(parents=True)
            native_header.write_bytes(b"header")
            native_library.write_bytes(b"library")
            (root / "native").mkdir()
            (root / "native/cadical_pair_sensor.cpp").write_text(
                "// test\n", encoding="utf-8"
            )
            (root / "native/cadical_tracer_3_0_0.hpp").write_text(
                "// test\n", encoding="utf-8"
            )
            (root / "src/o1_crypto_lab").mkdir(parents=True)
            participating = (
                "chacha_trace.py",
                "living_inverse.py",
                "cadical_sensor.py",
                "causal_bitfield.py",
                "causal_orientation_reader.py",
                "full256_broker.py",
                "full256_cnf.py",
                "full256_paired_sensor.py",
                "full256_probe_core.py",
                "full256_multikey_calibration.py",
                "full256_frozen_reader_replication.py",
                "full256_polyphase_replication.py",
                "signed_direct_replication.py",
                "living_inverse_reader_experiment.py",
                "living_inverse_ridge.py",
                "living_inverse_corpus.py",
                "run_capsule.py",
                "cli.py",
            )
            for name in participating:
                (root / "src/o1_crypto_lab" / name).write_text(
                    "# test\n", encoding="utf-8"
                )
            (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
            (root / "runs").mkdir()

            def digest(path):
                import hashlib

                return hashlib.sha256(path.read_bytes()).hexdigest()

            replication_config = SimpleNamespace(
                native=SimpleNamespace(
                    include_directory=str(native_header.parent),
                    static_library=str(native_library),
                    cadical_header_sha256=digest(native_header),
                    cadical_library_sha256=digest(native_library),
                ),
                corpus=SimpleNamespace(sealed_targets=32),
                controls=SimpleNamespace(
                    transforms=(
                        "output_bit_flip",
                        "wrong_nonce",
                        "output_byte_rotate",
                    )
                ),
                probe=SimpleNamespace(sentinel_reruns_per_sweep=0),
                state_plan=SimpleNamespace(serialized_state_bytes=17_408),
                reader=SimpleNamespace(ensemble_weights=(0.5, 0.5)),
                budgets=SimpleNamespace(
                    maximum_cpu_seconds=1600,
                    maximum_wall_seconds=1400,
                    maximum_resident_memory_mib=384,
                    maximum_persistent_artifact_bytes=5_000,
                    maximum_native_solver_branches=17_920,
                    maximum_fresh_random_targets=32,
                    maximum_sibling_reads=0,
                    maximum_sibling_writes=0,
                    maximum_mps_calls=0,
                    maximum_gpu_calls=0,
                ),
                maximum_state_bytes=18_000,
                maximum_live_target_state_bytes=67_584,
            )
            top_level = {
                "attempt_id": "O1C-0015",
                "slug": "test-polyphase",
                "hypothesis": "test",
                "prediction": "test",
                "controls": [],
                "budgets": {},
                "source": {},
                "design_lineage": {},
                "claim_level": "VALIDATION",
                "next_action": "preserve",
            }
            fake_module = ModuleType("o1_crypto_lab.full256_polyphase_replication")

            def load_config(path):
                events.append(("load", path))
                return top_level, replication_config

            def return_failed_gate_after_reveal(*args, **kwargs):
                events.append(("polyphase", "entered"))
                events.append(("attempt_id", kwargs["attempt_id"]))
                protocol = {
                    "phase": "FROZEN_PROTOCOL_VERIFIED_BEFORE_FRESH_TARGET_ENTROPY",
                    "fresh_target_entropy_calls": 0,
                    "protocol_freeze_sha256": "1" * 64,
                    "reader_freeze_sha256": "2" * 64,
                }
                protocol_payload = json.dumps(protocol).encode()
                kwargs["on_protocol_frozen"](
                    {"protocol_freeze.json": protocol_payload}, protocol
                )
                events.append(("entropy", "first-sealed-target"))
                predictions = {
                    "phase": "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL",
                    "protocol_freeze_sha256": "1" * 64,
                    "prediction_set_sha256": "3" * 64,
                    "sealed_targets": [f"target-{index:04d}" for index in range(32)],
                }
                predictions_payload = json.dumps(predictions).encode()
                kwargs["on_predictions_frozen"](
                    {"prediction_set_freeze.json": predictions_payload}, predictions
                )
                events.append(("reveal", "first-sealed-target"))
                final_payload = b'{"complete":true}' + b" " * 8_192 + b"\n"
                final_artifacts = {
                    "full256_polyphase_replication.json": final_payload,
                    **{
                        f"sealed/target-{index:04d}/reveal.json": b"{}"
                        for index in range(32)
                    },
                }
                persistent_bytes = (
                    len(protocol_payload)
                    + len(predictions_payload)
                    + sum(len(payload) for payload in final_artifacts.values())
                )
                module_metrics = {
                    "schema": "o1-256-polyphase-replication-metrics-v1",
                    "success_gate_passed": False,
                    "sealed_compression_bits_per_key": 0.125,
                    "sealed_correct_bits": 4_112,
                    "sealed_total_bits": 8_192,
                    "sealed_exact_keys": 0,
                    "positive_target_count": 18,
                    "replication_classification": "DIRECTIONAL",
                    "architecture_promotion_classification": "DO_NOT_PROMOTE",
                    "architecture_promotion_passed": False,
                    "ensemble_minus_h96_conditional_z_score": 0.25,
                    "conditional_null_z_score": 1.0,
                    "paired_conditional_null_z_score": 1.0,
                    "minimum_million_decoy_rank": 10,
                    "live_target_state_bytes": 67_584,
                    "native_solver_branches": 17_920,
                    "cpu_seconds": 10.0,
                    "wall_seconds": 10.0,
                    "peak_rss_bytes": 64 * 1024 * 1024,
                    "persistent_artifact_bytes": persistent_bytes,
                    "fresh_random_targets": 32,
                    "sibling_reads": 0,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
                return SimpleNamespace(
                    success_gate_passed=False,
                    final_artifacts=final_artifacts,
                    report={
                        "result_sha256": "4" * 64,
                        "resources": {
                            "native_cpu_seconds": 9.0,
                            "process_child_cpu_seconds": 9.0,
                        },
                        "sealed_evaluation": {
                            "h96_component": {"compression_bits_per_key": 0.0625}
                        },
                    },
                    metrics=lambda: module_metrics,
                )

            fake_module.load_full256_polyphase_replication_config = load_config
            fake_module.run_full256_polyphase_replication = (
                return_failed_gate_after_reveal
            )
            with (
                patch.dict(
                    sys.modules,
                    {"o1_crypto_lab.full256_polyphase_replication": fake_module},
                ),
                patch.object(cli, "_lab_root", return_value=root),
                patch.object(cli, "RunCapsuleManager", Manager),
                patch.object(cli, "_clean_git_commit", return_value="2" * 40),
                patch("sys.stderr", new=io.StringIO()),
            ):
                code = cli._full256_polyphase_replication(
                    argparse.Namespace(config=config_path)
                )

            normal_events = list(events)
            events = []
            run = RecordingRun(events)
            clean_checks = 0

            def fail_clean_check_after_result(_root):
                nonlocal clean_checks
                clean_checks += 1
                events.append(("clean-check", clean_checks))
                if clean_checks == 3:
                    raise RuntimeError("synthetic post-reveal source drift")
                return "2" * 40

            with (
                patch.dict(
                    sys.modules,
                    {"o1_crypto_lab.full256_polyphase_replication": fake_module},
                ),
                patch.object(cli, "_lab_root", return_value=root),
                patch.object(cli, "RunCapsuleManager", Manager),
                patch.object(
                    cli,
                    "_clean_git_commit",
                    side_effect=fail_clean_check_after_result,
                ),
                patch("sys.stderr", new=io.StringIO()),
            ):
                failure_code = cli._full256_polyphase_replication(
                    argparse.Namespace(config=config_path)
                )
            failure_events = list(events)
            events = normal_events

        names = [event[0] for event in events]
        self.assertEqual(code, 1)
        self.assertLess(names.index("load"), names.index("start"))
        self.assertLess(names.index("start"), names.index("checkpoint"))
        self.assertLess(names.index("checkpoint"), names.index("polyphase"))
        self.assertIn(("attempt_id", "O1C-0015"), events)
        protocol_checkpoint = events.index(
            ("checkpoint", "POLYPHASE_PROTOCOL_PERSISTED_BEFORE_FRESH_ENTROPY")
        )
        prediction_checkpoint = events.index(
            (
                "checkpoint",
                "ALL_POLYPHASE_PREDICTIONS_PERSISTED_BEFORE_ANY_REVEAL",
            )
        )
        self.assertLess(
            protocol_checkpoint, events.index(("entropy", "first-sealed-target"))
        )
        self.assertLess(
            prediction_checkpoint, events.index(("reveal", "first-sealed-target"))
        )
        final_artifact = events.index(
            ("artifact", "full256_polyphase_replication.json")
        )
        reveal_checkpoint = events.index(
            ("checkpoint", "POLYPHASE_TARGETS_REVEALED_ONCE_AND_RESULT_PERSISTED")
        )
        finalize_event = events.index(
            ("finalize", "failed", "o1-256-polyphase-replication-metrics-v1")
        )
        self.assertLess(events.index(("reveal", "first-sealed-target")), final_artifact)
        self.assertLess(final_artifact, reveal_checkpoint)
        self.assertLess(reveal_checkpoint, finalize_event)
        self.assertIn(
            ("finalize", "failed", "o1-256-polyphase-replication-metrics-v1"),
            events,
        )
        finalized_metrics = next(
            event for event in events if event[0] == "finalize_metrics"
        )
        self.assertEqual(finalized_metrics[1:4], (32, 10.0, 10.0))
        self.assertGreaterEqual(finalized_metrics[4], 64.0)
        self.assertIs(finalized_metrics[5], True)
        self.assertIs(finalized_metrics[6], False)
        self.assertEqual(failure_code, 1)
        failure_report = failure_events.index(
            ("artifact", "full256_polyphase_replication.json")
        )
        failure_source_check = failure_events.index(("clean-check", 3))
        failure_finalize = failure_events.index(
            ("finalize", "failed", "o1-256-polyphase-replication-failure-v1")
        )
        self.assertLess(failure_report, failure_source_check)
        self.assertLess(failure_source_check, failure_finalize)
        failure_metrics = next(
            event for event in failure_events if event[0] == "finalize_metrics"
        )
        self.assertEqual(failure_metrics[7:], (32, True))

    def test_recoverable_polyphase_interruption_stops_without_replay(self):
        events = []
        run = _RecordingRun(events)

        class Manager:
            def __init__(self, root):
                self.root = root

            def finalized_attempt(self, attempt_id):
                return None

            def recoverable_attempt_ids(self):
                return ("O1C-0015",)

            def recover(self, attempt_id):
                events.append(("recover", attempt_id))
                return run

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "configs/full256_polyphase_replication_v1.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("{}\n", encoding="utf-8")
            native_header = root / "native-dependency/cadical.hpp"
            native_library = root / "native-dependency/libcadical.a"
            native_header.parent.mkdir(parents=True)
            native_header.write_bytes(b"header")
            native_library.write_bytes(b"library")
            (root / "runs").mkdir()
            top_level = {"attempt_id": "O1C-0015"}
            replication_config = SimpleNamespace(
                native=SimpleNamespace(
                    include_directory=str(native_header.parent),
                    static_library=str(native_library),
                )
            )
            fake_module = ModuleType("o1_crypto_lab.full256_polyphase_replication")

            def load_config(path):
                events.append(("load", path))
                return top_level, replication_config

            def forbidden_replication(*args, **kwargs):
                events.append(("polyphase", "forbidden-replay"))
                raise AssertionError("recoverable O1C-0015 must not replay")

            fake_module.load_full256_polyphase_replication_config = load_config
            fake_module.run_full256_polyphase_replication = forbidden_replication
            with (
                patch.dict(
                    sys.modules,
                    {"o1_crypto_lab.full256_polyphase_replication": fake_module},
                ),
                patch.object(cli, "_lab_root", return_value=root),
                patch.object(cli, "RunCapsuleManager", Manager),
                patch("sys.stdout", new=io.StringIO()),
            ):
                code = cli._full256_polyphase_replication(
                    argparse.Namespace(config=config_path)
                )

        self.assertEqual(code, 2)
        self.assertIn(("recover", "O1C-0015"), events)
        self.assertNotIn(("polyphase", "forbidden-replay"), events)
        self.assertIn(
            ("finalize", "stopped", "o1-256-polyphase-replication-interrupted-v1"),
            events,
        )

    def test_parser_exposes_canonical_polyphase_command(self):
        args = cli.build_parser().parse_args(["full256-polyphase-replication"])
        self.assertEqual(args.config, FULL256_POLYPHASE_CONFIG)
        self.assertIs(args.handler, cli._full256_polyphase_replication)
        self.assertEqual(args.polyphase_attempt_id, "O1C-0015")
        self.assertEqual(
            args.polyphase_canonical_config,
            "full256_polyphase_replication_v1.json",
        )
        self.assertEqual(
            args.polyphase_command_name,
            "full256-polyphase-replication",
        )

    def test_parser_exposes_budget_corrected_polyphase_command(self):
        args = cli.build_parser().parse_args(["full256-polyphase-replication-v2"])
        self.assertEqual(args.config, FULL256_POLYPHASE_CONFIG_V2)
        self.assertIs(args.handler, cli._full256_polyphase_replication)
        self.assertEqual(args.polyphase_attempt_id, "O1C-0016")
        self.assertEqual(
            args.polyphase_canonical_config,
            "full256_polyphase_replication_v2.json",
        )
        self.assertEqual(
            args.polyphase_command_name,
            "full256-polyphase-replication-v2",
        )

    def test_budget_corrected_cli_rejects_cross_attempt_config_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "configs/full256_polyphase_replication_v2.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("{}\n", encoding="utf-8")
            fake_module = ModuleType("o1_crypto_lab.full256_polyphase_replication")
            fake_module.load_full256_polyphase_replication_config = lambda _path: (
                {"attempt_id": "O1C-0015"},
                SimpleNamespace(),
            )
            fake_module.run_full256_polyphase_replication = lambda *_a, **_k: None
            with (
                patch.dict(
                    sys.modules,
                    {"o1_crypto_lab.full256_polyphase_replication": fake_module},
                ),
                patch.object(cli, "_lab_root", return_value=root),
                self.assertRaisesRegex(RuntimeError, "attempt identity differs"),
            ):
                cli._full256_polyphase_replication(
                    argparse.Namespace(
                        config=config_path,
                        polyphase_canonical_config=(
                            "full256_polyphase_replication_v2.json"
                        ),
                        polyphase_attempt_id="O1C-0016",
                        polyphase_command_name="full256-polyphase-replication-v2",
                    )
                )

    def test_help_names_polyphase_replication(self):
        help_text = cli.build_parser().format_help()
        self.assertIn("full256-polyphase-replication", help_text)
        self.assertIn("full256-polyphase-replication-v2", help_text)
        self.assertIn("frozen h96+h65 polyphase reader", help_text)
        self.assertIn("32", help_text)
        self.assertIn("full-256 targets", help_text)


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
