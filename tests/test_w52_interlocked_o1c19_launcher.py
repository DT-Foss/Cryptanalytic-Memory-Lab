import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from o1_crypto_lab.w52_interlocked_o1c19_launcher import (
    INTERLOCK_CONFIG_SCHEMA,
    InterlockSnapshot,
    LocalGateSnapshot,
    W52InterlockError,
    detach_and_watch,
    evaluate_interlock,
    exec_o1c0019,
    exclusive_launcher_lock,
    inspect_w52,
    load_interlock_config,
    wait_for_release,
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class InterlockFixture:
    def __init__(self, root: Path) -> None:
        self.workspace = root
        self.lab = root / "lab"
        self.sibling = root / "sibling"
        self.state = self.sibling / "state"
        (self.lab / "configs").mkdir(parents=True)
        (self.lab / "src").mkdir()
        self.state.mkdir(parents=True)
        self.run_config = self.lab / "configs/run.json"
        self.run_config.write_text("{}\n", encoding="utf-8")
        self.source = self.lab / "src/frozen.py"
        self.source.write_text("VALUE = 1\n", encoding="utf-8")
        self.fingerprints = tuple(
            hashlib.sha256(f"worker-{i}".encode()).hexdigest() for i in range(2)
        )
        self.config_path = self.lab / "configs/interlock.json"
        self.write_config()
        for worker in range(2):
            (self.state / f"launcher_{worker}.pid").write_text(
                f"{10_000 + worker}\n", encoding="ascii"
            )
            self.write_progress(worker, "running", worker + 1)

    def write_config(self, **release_overrides: object) -> None:
        release = {
            "maximum_load_per_cpu": 0.75,
            "minimum_memory_free_percent": 25,
            "poll_seconds": 1.0,
            "report_every_polls": 2,
            "stable_terminal_polls": 3,
            **release_overrides,
        }
        value = {
            "attempt_id": "O1C-0019",
            "release": release,
            "run": {
                "config": "configs/run.json",
                "config_sha256": sha256_file(self.run_config),
                "frozen_source_sha256": {"src/frozen.py": sha256_file(self.source)},
                "required_ancestor_commit": "a" * 40,
            },
            "schema": INTERLOCK_CONFIG_SCHEMA,
            "sibling": {
                "assignments_per_cell": 16,
                "fingerprint_sha256": list(self.fingerprints),
                "launcher_release_pattern": "release_{worker_index}.json",
                "launcher_source_marker": "launcher.py",
                "observed_processes": [],
                "pid_pattern": "launcher_{worker_index}.pid",
                "progress_pattern": "progress_{worker_index}.json",
                "progress_schema": "progress-v1",
                "related_process_markers": [],
                "repository": "sibling",
                "state_directory": "state",
                "terminal_statuses": [
                    "candidate_confirmed",
                    "peer_confirmed",
                    "worker_exhausted",
                ],
                "worker_count": 2,
                "worker_tasks": 10,
            },
        }
        self.config_path.write_text(
            json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
        )

    def write_progress(
        self,
        worker: int,
        status: str,
        cells: int,
        **extra: object,
    ) -> None:
        value = {
            "schema": "progress-v1",
            "worker_index": worker,
            "status": status,
            "fingerprint_sha256": self.fingerprints[worker],
            "completed_pair_cells": cells,
            "completed_assignments": cells * 16,
            "next_worker_step": cells,
            "attempt_id": "A526",
            "matched_control_candidates": 0,
            "factual_candidates": 0,
            **extra,
        }
        (self.state / f"progress_{worker}.json").write_text(
            json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
        )

    @staticmethod
    def local(
        *, memory: int = 50, load: float = 1.0, clean: bool = True
    ) -> LocalGateSnapshot:
        return LocalGateSnapshot(
            memory_free_percent=memory,
            load_one_minute=load,
            logical_cpus=8,
            worktree_clean=clean,
            ancestor_present=True,
            run_config_matches=True,
            mismatched_frozen_sources=(),
        )


class W52InterlockedLauncherTests(unittest.TestCase):
    def test_running_w52_is_read_only_and_blocks_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            before = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in sorted(fixture.state.iterdir())
            }
            w52 = inspect_w52(config, process_probe=lambda _pid, _markers: True)
            snapshot = evaluate_interlock(config, w52, fixture.local())
            after = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in sorted(fixture.state.iterdir())
            }
            self.assertFalse(snapshot.ready)
            self.assertEqual(w52.completed_pair_cells, 3)
            self.assertEqual(w52.active_w52_pids, (10_000, 10_001))
            self.assertIn("W52_WORKERS_NONTERMINAL", snapshot.reasons)
            self.assertIn("W52_PROCESSES_ACTIVE", snapshot.reasons)
            self.assertEqual(before, after)

    def test_terminal_workers_still_wait_for_launchers_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            for worker in range(2):
                fixture.write_progress(worker, "worker_exhausted", 10)
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(config, process_probe=lambda _pid, _markers: True)
            snapshot = evaluate_interlock(
                config,
                w52,
                fixture.local(memory=10, load=16.0, clean=False),
            )
            self.assertTrue(w52.terminal)
            self.assertFalse(snapshot.ready)
            self.assertEqual(
                snapshot.reasons,
                (
                    "W52_PROCESSES_ACTIVE",
                    "INSUFFICIENT_FREE_MEMORY",
                    "SYSTEM_LOAD_TOO_HIGH",
                    "LAB_WORKTREE_DIRTY",
                ),
            )

    def test_process_missing_from_stale_pid_files_still_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            value = json.loads(fixture.config_path.read_text(encoding="utf-8"))
            value["sibling"]["observed_processes"] = [
                {"pid": 22_222, "markers": ["native-a526"]}
            ]
            fixture.config_path.write_text(json.dumps(value), encoding="utf-8")
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(
                config,
                process_probe=lambda pid, _markers: pid == 22_222,
            )
            self.assertEqual(w52.active_w52_pids, (22_222,))

    def test_dynamic_scan_catches_restarted_process_absent_from_pid_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            value = json.loads(fixture.config_path.read_text(encoding="utf-8"))
            value["sibling"]["related_process_markers"] = [["native-a526"]]
            fixture.config_path.write_text(json.dumps(value), encoding="utf-8")
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(
                config,
                process_probe=lambda _pid, _markers: False,
                process_table_probe=lambda groups: (
                    (33_333,) if groups == (("native-a526",),) else ()
                ),
            )
            self.assertEqual(w52.active_w52_pids, (33_333,))

    def test_mixed_terminal_stop_is_bound_without_reading_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            stop = fixture.state / "a526_confirmed_stop_v1.json"
            stop.write_text('{"opaque":"stop"}\n', encoding="utf-8")
            stop_sha256 = sha256_file(stop)
            fixture.write_progress(
                0,
                "candidate_confirmed",
                4,
                confirmed_stop_sha256=stop_sha256,
            )
            fixture.write_progress(1, "worker_exhausted", 10)
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(config, process_probe=lambda _pid, _markers: False)
            snapshot = evaluate_interlock(config, w52, fixture.local())
            self.assertTrue(w52.terminal)
            self.assertTrue(w52.stop_file_present)
            self.assertTrue(snapshot.ready)

    def test_stable_release_dry_run_never_calls_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            for worker in range(2):
                fixture.write_progress(worker, "worker_exhausted", 10)
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(config, process_probe=lambda _pid, _markers: False)
            ready = evaluate_interlock(config, w52, fixture.local())
            self.assertTrue(ready.ready)
            sleeps: list[float] = []
            reports: list[dict[str, object]] = []
            launches: list[object] = []
            result = wait_for_release(
                config,
                dry_run=True,
                snapshot_probe=lambda: ready,
                sleep=sleeps.append,
                emit=lambda row: reports.append(dict(row)),
                launch=lambda value: launches.append(value),
                max_polls=4,
                lock_path=Path(temporary) / "watcher.lock",
            )
            self.assertEqual(result, 0)
            self.assertEqual(sleeps, [1.0, 1.0])
            self.assertEqual(launches, [])
            self.assertEqual(reports[-1]["status"], "DRY_RUN_RELEASED")

    def test_final_reinspection_prevents_release_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            for worker in range(2):
                fixture.write_progress(worker, "worker_exhausted", 10)
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            w52 = inspect_w52(config, process_probe=lambda _pid, _markers: False)
            ready = evaluate_interlock(config, w52, fixture.local())
            blocked = InterlockSnapshot(
                w52=w52,
                local=fixture.local(memory=1),
                ready=False,
                reasons=("INSUFFICIENT_FREE_MEMORY",),
            )
            sequence = iter([ready, ready, ready, blocked, ready, ready, ready, ready])
            sleeps: list[float] = []
            result = wait_for_release(
                config,
                dry_run=True,
                snapshot_probe=lambda: next(sequence),
                sleep=sleeps.append,
                emit=lambda _row: None,
                max_polls=7,
                lock_path=Path(temporary) / "race.lock",
            )
            self.assertEqual(result, 0)
            self.assertEqual(len(sleeps), 5)

    def test_wrong_fingerprint_and_early_exhaustion_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            fixture.fingerprints = ("f" * 64, fixture.fingerprints[1])
            fixture.write_progress(0, "running", 1)
            with self.assertRaisesRegex(W52InterlockError, "identity differs"):
                inspect_w52(config, process_probe=lambda _pid, _markers: False)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            fixture.write_progress(0, "worker_exhausted", 9)
            with self.assertRaisesRegex(W52InterlockError, "exhausted before"):
                inspect_w52(config, process_probe=lambda _pid, _markers: False)

    def test_duplicate_watchers_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "exclusive.lock"
            with exclusive_launcher_lock(lock) as descriptor:
                self.assertTrue(os.get_inheritable(descriptor))
                with self.assertRaisesRegex(W52InterlockError, "another"):
                    with exclusive_launcher_lock(lock):
                        self.fail("duplicate lock unexpectedly acquired")

    def test_config_rejects_escape_and_frozen_hash_is_observable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            value = json.loads(fixture.config_path.read_text(encoding="utf-8"))
            value["sibling"]["repository"] = "../outside"
            fixture.config_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(W52InterlockError, "normalized relative"):
                load_interlock_config(fixture.config_path, lab_root=fixture.lab)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            self.assertEqual(config.run_config_sha256, sha256_file(fixture.run_config))
            self.assertEqual(config.frozen_sources[0][1], sha256_file(fixture.source))

    def test_exec_uses_exact_cpu_only_command_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            with (
                patch("o1_crypto_lab.w52_interlocked_o1c19_launcher.os.chdir") as chdir,
                patch(
                    "o1_crypto_lab.w52_interlocked_o1c19_launcher.os.execvpe"
                ) as execvpe,
            ):
                exec_o1c0019(config)
            chdir.assert_called_once_with(config.lab_root)
            executable, command, environment = execvpe.call_args.args
            self.assertEqual(executable, command[0])
            self.assertEqual(
                tuple(command[1:]),
                (
                    "-m",
                    "o1_crypto_lab.full256_multiresolution_build_loo_run",
                    "--config",
                    str(config.run_config),
                ),
            )
            self.assertEqual(environment["PYTHONPATH"], str(config.lab_root / "src"))
            self.assertEqual(environment["OMP_NUM_THREADS"], "1")
            self.assertEqual(environment["PYTORCH_ENABLE_MPS_FALLBACK"], "0")
            self.assertEqual(environment["CUDA_VISIBLE_DEVICES"], "")

    def test_detach_parent_reports_child_and_restricts_log_to_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = InterlockFixture(Path(temporary))
            (fixture.lab / "runs").mkdir()
            config = load_interlock_config(fixture.config_path, lab_root=fixture.lab)
            reports: list[dict[str, object]] = []
            with patch(
                "o1_crypto_lab.w52_interlocked_o1c19_launcher.os.fork",
                return_value=12_345,
            ):
                result = detach_and_watch(
                    config,
                    emit=lambda row: reports.append(dict(row)),
                )
            self.assertEqual(result, 0)
            self.assertEqual(reports[0]["status"], "WATCHER_DETACHED")
            self.assertEqual(reports[0]["pid"], 12_345)
            self.assertTrue(
                str(reports[0]["log"]).startswith(str((fixture.lab / "runs").resolve()))
            )
            with self.assertRaisesRegex(W52InterlockError, "runs directory"):
                detach_and_watch(
                    config,
                    log_path=fixture.workspace / "outside.log",
                    emit=lambda _row: None,
                )


if __name__ == "__main__":
    unittest.main()
