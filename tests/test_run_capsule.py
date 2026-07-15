import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from o1_crypto_lab.isolation import IsolationViolation
from o1_crypto_lab.run_capsule import (
    ClaimLevel,
    RunCapsuleManager,
    RunCollisionError,
    RunStateError,
)


BERLIN = ZoneInfo("Europe/Berlin")
SOURCE_DIGEST = hashlib.sha256(b"pinned source").hexdigest()


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self._values = list(values)
        self._last = values[-1]

    def __call__(self) -> datetime:
        if self._values:
            self._last = self._values.pop(0)
        return self._last


def start_run(
    manager: RunCapsuleManager,
    *,
    attempt_id: str = "O1C-0001",
    slug: str = "Memory Probe",
):
    return manager.start(
        attempt_id=attempt_id,
        slug=slug,
        commit="5bb39913bec2712ce1348bc5b9667b6d5798326b",
        hypothesis="Bound evidence survives the haystack.",
        prediction="Exact recall remains above the frozen control.",
        controls=("target labels remain sealed", "random-score baseline"),
        budgets={"wall_seconds": 30, "candidate_runs": 256},
        source_hashes={"fixture.bin": SOURCE_DIGEST},
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action="Run the frozen holdout after the validity gate.",
        config={"seed": 7, "state_size": 528},
        command=("python", "-m", "o1_crypto_lab", "quick"),
        environment={"backend": "cpu"},
    )


class RunCapsuleTests(unittest.TestCase):
    def test_finalizes_complete_immutable_and_hash_correct_capsule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = datetime(2026, 7, 15, 12, 0, 0, tzinfo=BERLIN)
            checkpointed = datetime(2026, 7, 15, 12, 0, 1, tzinfo=BERLIN)
            ended = datetime(2026, 7, 15, 12, 0, 3, 500000, tzinfo=BERLIN)
            manager = RunCapsuleManager(
                root, clock=SequenceClock(started, checkpointed, ended)
            )
            run = start_run(manager)
            self.assertTrue(run.staging_path.is_dir())
            run.append_stdout("training started\n")
            run.append_stderr("bounded warning\n")
            checkpoint = run.checkpoint({"completed_cells": 128})
            self.assertTrue(checkpoint.is_file())
            run.write_json_artifact("dataset/summary.json", {"records": 8})

            result = run.finalize(
                metrics={"exact_recall": 1.0, "seeds": 5},
                next_action="Advance to a fresh prospective panel.",
            )

            expected_name = "20260715_120000_O1C-0001_memory-probe"
            self.assertEqual(result.path.name, expected_name)
            self.assertFalse(run.staging_path.exists())
            self.assertTrue(result.verification.ok)
            self.assertTrue(
                manager.verify(Path("runs") / expected_name).ok
            )
            self.assertEqual(result.manifest_sha256, result.verification.manifest_sha256)
            mandatory = {
                "RUN.md",
                "config.json",
                "command.txt",
                "environment.json",
                "metrics.json",
                "stdout.log",
                "stderr.log",
                "artifacts.sha256",
            }
            self.assertTrue(mandatory <= {path.name for path in result.path.iterdir()})
            self.assertTrue((result.path / "checkpoint.json").is_file())
            saved_config = json.loads((result.path / "config.json").read_text())
            self.assertEqual(saved_config["schema"], "o1c-run-config-v1")
            self.assertEqual(saved_config["claim_level"], "RETROSPECTIVE")
            self.assertEqual(saved_config["source_hashes"], {"fixture.bin": SOURCE_DIGEST})
            self.assertEqual(saved_config["budgets"]["candidate_runs"], 256)
            self.assertEqual(
                json.loads((result.path / "environment.json").read_text())["schema"],
                "o1c-run-environment-v1",
            )
            metrics = json.loads((result.path / "metrics.json").read_text())
            self.assertEqual(metrics["schema"], "o1c-run-metrics-v1")
            self.assertEqual(metrics["claim_level"], "RETROSPECTIVE")
            self.assertEqual(metrics["started_at"], "2026-07-15T12:00:00+02:00")
            self.assertEqual(metrics["ended_at"], "2026-07-15T12:00:03.500000+02:00")
            self.assertEqual(metrics["elapsed_seconds"], 3.5)
            self.assertEqual(
                metrics["next_action"], "Advance to a fresh prospective panel."
            )
            self.assertEqual(
                json.loads((result.path / "checkpoint.json").read_text())["sequence"],
                1,
            )
            run_text = (result.path / "RUN.md").read_text(encoding="utf-8")
            self.assertIn("Claim level: `RETROSPECTIVE`", run_text)
            self.assertIn(SOURCE_DIGEST, run_text)
            self.assertIn("Advance to a fresh prospective panel.", run_text)

            entries = {}
            for line in (result.path / "artifacts.sha256").read_text().splitlines():
                digest, relative = line.split(maxsplit=1)
                entries[relative] = digest
            self.assertNotIn("artifacts.sha256", entries)
            self.assertIn("artifacts/dataset/summary.json", entries)
            self.assertIn(".capsule-state.json", entries)
            self.assertEqual(
                entries["stdout.log"],
                hashlib.sha256((result.path / "stdout.log").read_bytes()).hexdigest(),
            )
            self.assertEqual(
                entries["artifacts/dataset/summary.json"],
                hashlib.sha256(
                    (result.path / "artifacts/dataset/summary.json").read_bytes()
                ).hexdigest(),
            )
            self.assertFalse(stat.S_IMODE(result.path.stat().st_mode) & 0o222)
            for member in result.path.rglob("*"):
                self.assertFalse(stat.S_IMODE(member.stat().st_mode) & 0o222)
            with self.assertRaises(RunStateError):
                run.append_stdout("too late")
            with self.assertRaises(RunStateError):
                run.finalize(metrics={})

    def test_duplicate_attempt_and_final_name_collisions_never_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            instant = datetime(2026, 7, 15, 12, 1, tzinfo=BERLIN)
            manager = RunCapsuleManager(root, clock=SequenceClock(instant))
            original = start_run(manager)
            with self.assertRaisesRegex(RunCollisionError, "attempt ID"):
                start_run(manager, slug="different")
            self.assertTrue(original.staging_path.is_dir())

            collision = root / "runs/20260715_120100_O1C-0002_reserved-name"
            collision.mkdir()
            marker = collision / "keep.txt"
            marker.write_text("untouched", encoding="utf-8")
            with self.assertRaisesRegex(RunCollisionError, "already exists"):
                start_run(manager, attempt_id="O1C-0002", slug="reserved name")
            self.assertEqual(marker.read_text(encoding="utf-8"), "untouched")
            self.assertFalse((root / "runs/.attempt_ids/O1C-0002.json").exists())

    def test_symlinked_internal_directory_and_artifact_parent_are_rejected(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(temporary)
            (root / "runs").mkdir()
            (root / "runs/.in_progress").symlink_to(
                Path(outside), target_is_directory=True
            )
            with self.assertRaises(IsolationViolation):
                RunCapsuleManager(root)
            self.assertEqual(list(Path(outside).iterdir()), [])

        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = start_run(manager)
            (run.staging_path / "artifacts").symlink_to(
                Path(outside), target_is_directory=True
            )
            with self.assertRaises(IsolationViolation):
                run.write_text_artifact("escape.txt", "captured")
            self.assertFalse((Path(outside) / "escape.txt").exists())

    def test_checkpoint_can_be_recovered_and_finalized_by_new_manager(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = datetime(2026, 7, 15, 13, 0, 0, tzinfo=BERLIN)
            first_checkpoint = datetime(2026, 7, 15, 13, 0, 1, tzinfo=BERLIN)
            manager = RunCapsuleManager(
                root, clock=SequenceClock(started, first_checkpoint)
            )
            run = start_run(manager, attempt_id="O1C-RECOVERY")
            run.checkpoint({"step": 1})
            self.assertEqual(manager.recoverable_attempt_ids(), ("O1C-RECOVERY",))

            second_checkpoint = datetime(2026, 7, 15, 13, 0, 2, tzinfo=BERLIN)
            ended = datetime(2026, 7, 15, 13, 0, 4, tzinfo=BERLIN)
            resumed_manager = RunCapsuleManager(
                root, clock=SequenceClock(second_checkpoint, ended)
            )
            resumed = resumed_manager.recover("O1C-RECOVERY")
            resumed.checkpoint({"step": 2})
            resumed.append_stdout("resumed\n")
            result = resumed.finish(metrics={"recovered": True}, status="completed")
            checkpoint = json.loads((result.path / "checkpoint.json").read_text())
            self.assertEqual(checkpoint["sequence"], 2)
            self.assertEqual(checkpoint["payload"], {"step": 2})
            self.assertEqual(resumed_manager.recoverable_attempt_ids(), ())
            published = resumed_manager.finalized_attempt("O1C-RECOVERY")
            self.assertIsNotNone(published)
            self.assertEqual(published.manifest_sha256, result.manifest_sha256)
            with self.assertRaisesRegex(RunStateError, "not recoverable"):
                resumed_manager.recover("O1C-RECOVERY")

    def test_legacy_in_progress_stage_remains_recoverable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            attempt = "O1C-LEGACY-STAGE"
            run = start_run(manager, attempt_id=attempt)
            direct_stage = run.staging_path
            reservation_path = root / "runs/.attempt_ids" / f"{attempt}.json"
            reservation = json.loads(reservation_path.read_text())
            state_path = direct_stage / ".capsule-state.json"
            state = json.loads(state_path.read_text())
            legacy_name = f"{attempt}.{state['run_token']}.work"
            reservation["stage_name"] = legacy_name
            reservation.pop("stage_parent")
            state["stage_name"] = legacy_name
            state.pop("stage_parent")
            state_path.write_text(json.dumps(state), encoding="utf-8")
            reservation_path.write_text(
                json.dumps(reservation),
                encoding="utf-8",
            )
            legacy_stage = root / "runs/.in_progress" / legacy_name
            direct_stage.rename(legacy_stage)

            resumed_manager = RunCapsuleManager(root)
            self.assertIn(attempt, resumed_manager.recoverable_attempt_ids())
            result = resumed_manager.recover(attempt).finalize(
                metrics={"legacy_stage_recovered": True},
                status="completed",
            )
            self.assertTrue(result.verification.ok)
            self.assertEqual(stat.S_IMODE(result.path.stat().st_mode), 0o555)

    def test_prepared_publication_survives_rename_interruption_without_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = datetime(2026, 7, 15, 13, 30, 0, tzinfo=BERLIN)
            ended = datetime(2026, 7, 15, 13, 30, 2, tzinfo=BERLIN)
            manager = RunCapsuleManager(root, clock=SequenceClock(started, ended))
            run = start_run(manager, attempt_id="O1C-PUBLISH-RECOVERY")
            run.write_text_artifact("evidence.txt", "frozen")

            with patch(
                "o1_crypto_lab.run_capsule.os.rename",
                side_effect=OSError("fault after prepared state"),
            ):
                with self.assertRaisesRegex(OSError, "fault after prepared"):
                    run.finalize(metrics={"original": True}, status="completed")

            prepared = json.loads(
                (run.staging_path / ".capsule-state.json").read_text()
            )
            self.assertEqual(prepared["publication_phase"], "prepared")
            self.assertEqual(prepared["status"], "completed")
            run.staging_path.chmod(0o700)
            orphan = run.staging_path / (
                ".metrics.json." + ("a" * 24) + ".tmp"
            )
            orphan.write_bytes(b"interrupted temporary payload")
            resumed_manager = RunCapsuleManager(root)
            self.assertEqual(
                resumed_manager.recoverable_attempt_ids(),
                ("O1C-PUBLISH-RECOVERY",),
            )
            resumed = resumed_manager.recover("O1C-PUBLISH-RECOVERY")
            self.assertTrue(resumed.publication_prepared)
            result = resumed.finalize(
                metrics={"must_not_replace": True},
                status="stopped",
            )
            metrics = json.loads((result.path / "metrics.json").read_text())
            self.assertEqual(metrics["status"], "completed")
            self.assertEqual(metrics["values"], {"original": True})
            self.assertFalse((result.path / orphan.name).exists())
            self.assertTrue(result.verification.ok)
            self.assertEqual(resumed_manager.recoverable_attempt_ids(), ())
            self.assertEqual(
                resumed_manager.finalized_attempt("O1C-PUBLISH-RECOVERY").path,
                result.path,
            )

    def test_prepared_publication_rejects_changed_bound_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = start_run(manager, attempt_id="O1C-PUBLISH-TAMPER")
            with patch(
                "o1_crypto_lab.run_capsule.os.rename",
                side_effect=OSError("publication interrupted"),
            ):
                with self.assertRaises(OSError):
                    run.finalize(metrics={"bound": "original"})

            metrics_path = run.staging_path / "metrics.json"
            metrics_path.chmod(0o644)
            metrics_path.write_text("{}\n", encoding="utf-8")
            recovered = RunCapsuleManager(root).recover("O1C-PUBLISH-TAMPER")
            with self.assertRaisesRegex(
                RunStateError,
                "content commitment differs",
            ):
                recovered.finalize(metrics={"ignored": True}, status="stopped")

    def test_post_rename_interruption_is_sealed_and_discovered_without_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            run = start_run(manager, attempt_id="O1C-POST-RENAME")
            real_rename = os.rename

            def rename_then_interrupt(*args, **kwargs):
                real_rename(*args, **kwargs)
                raise OSError("interrupted after atomic rename")

            with patch(
                "o1_crypto_lab.run_capsule.os.rename",
                side_effect=rename_then_interrupt,
            ):
                with self.assertRaisesRegex(OSError, "after atomic rename"):
                    run.finalize(metrics={"original": True})

            self.assertFalse(run.staging_path.exists())
            self.assertTrue(run.final_path.is_dir())
            self.assertEqual(stat.S_IMODE(run.final_path.stat().st_mode), 0o555)
            published = RunCapsuleManager(root).finalized_attempt(
                "O1C-POST-RENAME"
            )
            self.assertIsNotNone(published)
            self.assertTrue(published.verification.ok)
            self.assertEqual(stat.S_IMODE(published.path.stat().st_mode), 0o555)
            metrics = json.loads((published.path / "metrics.json").read_text())
            self.assertEqual(metrics["values"], {"original": True})

    def test_finalized_attempt_accepts_verified_legacy_capsule_without_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            attempt = "O1C-LEGACY"
            final_name = "20260715_140000_O1C-LEGACY_legacy"
            capsule = root / "runs" / final_name
            capsule.mkdir()
            files = {
                "RUN.md": b"# legacy\n",
                "config.json": b'{"schema":"o1c-run-config-v1"}\n',
                "command.txt": b"true\n",
                "environment.json": b"{}\n",
                "metrics.json": b'{"status":"completed"}\n',
                "stdout.log": b"",
                "stderr.log": b"",
            }
            for name, payload in files.items():
                (capsule / name).write_bytes(payload)
            manifest = "".join(
                f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
                for name, payload in sorted(files.items())
            )
            (capsule / "artifacts.sha256").write_text(
                manifest,
                encoding="utf-8",
            )
            reservation = {
                "schema": "o1c-attempt-reservation-v1",
                "attempt_id": attempt,
                "run_token": "legacy-token",
                "stage_name": "legacy-stage",
                "final_name": final_name,
                "started_at": "2026-07-15T14:00:00+02:00",
            }
            (root / "runs/.attempt_ids" / f"{attempt}.json").write_text(
                json.dumps(reservation),
                encoding="utf-8",
            )
            published = manager.finalized_attempt(attempt)
            self.assertIsNotNone(published)
            self.assertEqual(published.path, capsule.resolve())
            self.assertTrue(published.verification.ok)

    def test_verifier_detects_tampering_and_missing_mandatory_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = datetime(2026, 7, 15, 14, 0, 0, tzinfo=BERLIN)
            ended = datetime(2026, 7, 15, 14, 0, 1, tzinfo=BERLIN)
            manager = RunCapsuleManager(root, clock=SequenceClock(started, ended))
            result = start_run(manager, attempt_id="O1C-TAMPER").finalize(
                metrics={"ok": True}
            )
            os.chmod(result.path, 0o755)
            stdout = result.path / "stdout.log"
            os.chmod(stdout, 0o644)
            stdout.write_text("tampered", encoding="utf-8")
            missing = result.path / "stderr.log"
            os.chmod(missing, 0o644)
            missing.unlink()
            verification = manager.verify(result.path)
            self.assertFalse(verification.ok)
            self.assertEqual(verification.mismatched, ("stdout.log",))
            self.assertEqual(verification.missing, ("stderr.log",))

    def test_rejects_unsafe_or_nonfinite_metadata_before_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manager = RunCapsuleManager(root)
            with self.assertRaises(ValueError):
                start_run(manager, attempt_id="../escape")
            with self.assertRaises(ValueError):
                manager.start(
                    attempt_id="O1C-NAN",
                    slug="nan",
                    commit="commit",
                    hypothesis="hypothesis",
                    prediction="prediction",
                    controls=("control",),
                    budgets={"seconds": float("nan")},
                    source_hashes={"source": SOURCE_DIGEST},
                    claim_level=ClaimLevel.SMOKE,
                    next_action="stop",
                    config={},
                    command="true",
                )
            self.assertFalse((root / "runs/.attempt_ids/O1C-NAN.json").exists())


if __name__ == "__main__":
    unittest.main()
