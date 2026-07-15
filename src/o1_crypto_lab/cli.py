"""Command-line interface for the isolated research harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from .artifacts import ReadOnlyArtifactSource
from .benchmark import BenchmarkConfig, composition_report, run_benchmark
from .isolation import IsolationPolicy
from .replay import O1OSessionReplay
from .reader_experiment import run_reader_experiment
from .run_capsule import ClaimLevel, RunCapsuleManager
from .stage3_ingest import run_stage3_ingest


def _lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError("could not capture the lab Git commit")
    return result.stdout.strip()


def _benchmark(args: argparse.Namespace) -> int:
    config = BenchmarkConfig.load(args.config)
    result = run_benchmark(config)
    destination = IsolationPolicy.package_default().atomic_write_json(
        args.output, result
    )
    memory_long = [
        row
        for row in result["memory"]["summary"]
        if row["haystack_length"] == max(config.haystack_lengths)
    ]
    evidence_long = [
        row
        for row in result["evidence"]["summary"]
        if row["relations"] == max(config.evidence_relations)
    ]
    print(f"wrote {destination}")
    print(
        json.dumps(
            {"memory_longest": memory_long, "evidence_longest": evidence_long}, indent=2
        )
    )
    return 0


def _compose(_args: argparse.Namespace) -> int:
    report = composition_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["gate_passed"] else 1


def _verify_source(args: argparse.Namespace) -> int:
    source = ReadOnlyArtifactSource(args.root, args.manifest)
    report = source.verify().describe()
    if args.output is not None:
        destination = IsolationPolicy.package_default().atomic_write_json(
            args.output, report
        )
        print(f"wrote {destination}")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def _boundary(_args: argparse.Namespace) -> int:
    statements = {
        "bounded_state": "State is constant in stream length, not necessarily in key width.",
        "no_dictionary_claim": "The direct vault is a declared positional register bank, not holographic recall.",
        "no_crypto_claim": "Synthetic weak evidence is an oracle instrument until a public full-round gate passes.",
        "index_accounting": "External index size is reported separately and disabled in the first benchmark.",
        "work_accounting": "All cipher, solver, candidate and operator-search work must be billed.",
        "blindness": "TARGET_SECRET, INTERNAL_TARGET and POST_REVEAL can never flow into TARGET_BLIND_ORDER.",
    }
    print(json.dumps(statements, indent=2, sort_keys=True))
    return 0


def _replay(args: argparse.Namespace) -> int:
    report = O1OSessionReplay(args.session).replay()
    value = report.describe(include_events=args.include_events)
    if args.output is not None:
        destination = IsolationPolicy.package_default().atomic_write_json(
            args.output, value
        )
        print(f"wrote {destination}")
    print(
        json.dumps(
            {
                "session_id": value["session_id"],
                "source_snapshot_sha256": value["source_snapshot_sha256"],
                "task_count": value["task_count"],
                "event_count": value["event_count"],
                "outcome_counts": value["outcome_counts"],
                "adaptive_trace": value["adaptive_trace"],
                "target_model_ingest": value["target_model_ingest"],
                "semantic_contract": value["semantic_contract"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _stage3_ingest(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    source = config["source"]
    source_root = (root / source["repository"]).resolve()
    manifest_path = (source_root / source["manifest"]).resolve()
    source_hashes = {
        "ingest_config": _sha256(config_path),
        "fullround_manifest": _sha256(manifest_path),
        "stage3_adapter": _sha256(root / "src/o1_crypto_lab/stage3.py"),
        "stage3_ingest_pipeline": _sha256(
            root / "src/o1_crypto_lab/stage3_ingest.py"
        ),
    }
    manager = RunCapsuleManager(root)
    command = (
        "o1-crypto-lab",
        "stage3-ingest",
        "--config",
        str(config_path),
    )
    run = manager.start(
        attempt_id=config["attempt_id"],
        slug=config["slug"],
        commit=_git_commit(root),
        hypothesis=config["hypothesis"],
        prediction=config["prediction"],
        controls=tuple(config["controls"]),
        budgets=config["budgets"],
        source_hashes=source_hashes,
        claim_level=ClaimLevel(config["claim_level"]),
        next_action=config["next_action"],
        config=config,
        command=command,
        environment={
            "source_root": str(source_root),
            "expected_source_commit": source["expected_commit"],
            "expected_manifest_sha256": source["expected_manifest_sha256"],
        },
    )
    try:
        run.append_stdout("Stage-3 ingestion started; post-reveal readers disabled.\n")
        run.checkpoint({"phase": "SOURCE_PINNED", "labels_read": 0})
        result = run_stage3_ingest(config_path, lab_root=root)
        run.checkpoint(
            {
                "phase": "DATASET_NORMALIZED",
                "dataset_sha256": result.dataset.dataset_sha256,
                "labels_read": 0,
            }
        )
        run.write_json_artifact("stage3_dataset.json", result.dataset.describe())
        run.write_json_artifact(
            "source_pin.json",
            {
                "schema": "o1-crypto-stage3-source-pin-v1",
                "source_commit": result.source_commit,
                "manifest_sha256": result.manifest_sha256,
                "selected_members_verified": result.selected_members_verified,
                "config_sha256": result.config_sha256,
            },
        )
        metrics = result.metrics()
        run.append_stdout(
            json.dumps(
                {
                    "dataset_sha256": metrics["dataset_sha256"],
                    "episodes": metrics["episodes"],
                    "cells": metrics["cells"],
                    "stages": metrics["stages"],
                    "target_labels_read": 0,
                },
                sort_keys=True,
            )
            + "\n"
        )
        finalized = run.finalize(metrics=metrics)
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-crypto-stage3-ingest-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "target_labels_read": 0,
            },
            status="failed",
            next_action="Fix the recorded ingestion invariant before any label access.",
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 1
    print(json.dumps({
        "attempt_id": finalized.attempt_id,
        "path": str(finalized.path),
        "manifest_sha256": finalized.manifest_sha256,
        "verified": finalized.verification.ok,
    }, indent=2, sort_keys=True))
    return 0


def _verify_run(args: argparse.Namespace) -> int:
    report = RunCapsuleManager(_lab_root()).verify(args.path).describe()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def _stage3_reader(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    source = config["source"]
    source_root = (root / source["repository"]).resolve()
    manifest_path = source_root / source["manifest"]
    ingest_config_path = root / config["ingest_config"]
    ingest_capsule_path = root / config["ingest_capsule"]["path"]
    manager = RunCapsuleManager(root)
    ingest_verification = manager.verify(ingest_capsule_path)
    if (
        not ingest_verification.ok
        or ingest_verification.manifest_sha256
        != config["ingest_capsule"]["manifest_sha256"]
    ):
        raise RuntimeError("the O1C-0001 ingestion capsule failed its pinned gate")
    module_paths = {
        "stage3_adapter": root / "src/o1_crypto_lab/stage3.py",
        "stage3_ingest_pipeline": root / "src/o1_crypto_lab/stage3_ingest.py",
        "trajectory_reader": root / "src/o1_crypto_lab/trajectory_reader.py",
        "reader_experiment": root / "src/o1_crypto_lab/reader_experiment.py",
        "label_broker": root / "src/o1_crypto_lab/label_broker.py",
    }
    source_hashes = {
        "reader_config": _sha256(config_path),
        "ingest_config": _sha256(ingest_config_path),
        "fullround_manifest": _sha256(manifest_path),
        "o1c_0001_capsule_manifest": _sha256(
            ingest_capsule_path / "artifacts.sha256"
        ),
        **{name: _sha256(path) for name, path in module_paths.items()},
    }
    command = (
        "o1-crypto-lab",
        "stage3-reader",
        "--config",
        str(config_path),
    )
    run = manager.start(
        attempt_id=config["attempt_id"],
        slug=config["slug"],
        commit=_git_commit(root),
        hypothesis=config["hypothesis"],
        prediction=config["prediction"],
        controls=tuple(config["controls"]),
        budgets=config["budgets"],
        source_hashes=source_hashes,
        claim_level=ClaimLevel(config["claim_level"]),
        next_action=config["next_action"],
        config=config,
        command=command,
        environment={
            "source_root": str(source_root),
            "source_commit": source["expected_commit"],
            "o1c_0001_capsule": str(ingest_capsule_path),
            "label_broker_process_boundary": True,
        },
    )

    def on_frozen(plan, pre_reveal) -> None:
        run.write_json_artifact("frozen_reader_plan.json", plan.describe())
        run.write_json_artifact("pre_reveal_orders.json", pre_reveal)
        run.checkpoint(
            {
                "phase": "PLAN_AND_HOLDOUT_ORDERS_FROZEN",
                "plan_sha256": plan.plan_sha256,
                "pre_reveal_sha256": pre_reveal["pre_reveal_sha256"],
                "holdout_labels_read": 0,
            }
        )
        run.append_stdout(
            f"Frozen plan {plan.plan_sha256}; holdout labels read: 0.\n"
        )

    try:
        run.append_stdout("Reader tournament started with child-process label broker.\n")
        run.checkpoint({"phase": "DATASET_REPINNING", "holdout_labels_read": 0})
        result = run_reader_experiment(
            config_path,
            lab_root=root,
            on_frozen=on_frozen,
        )
        run.write_json_artifact("reader_experiment.json", result.report)
        metrics = result.metrics()
        run.append_stdout(
            json.dumps(
                {
                    "plan_sha256": metrics["plan_sha256"],
                    "selected_operator": metrics["selected_operator"],
                    "success_gate_passed": metrics["success_gate_passed"],
                    "retrospective_mean_gain": metrics[
                        "retrospective_holdout"
                    ]["mean_log2_rank_gain"],
                    "transfer_mean_gain": metrics["transfer_holdout"][
                        "mean_log2_rank_gain"
                    ],
                },
                sort_keys=True,
            )
            + "\n"
        )
        finalized = run.finalize(metrics=metrics)
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-crypto-stage3-reader-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
            status="failed",
            next_action="Fix the recorded lifecycle or data invariant, then use a new attempt ID.",
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "attempt_id": finalized.attempt_id,
                "path": str(finalized.path),
                "manifest_sha256": finalized.manifest_sha256,
                "verified": finalized.verification.ok,
                "success_gate_passed": result.success_gate_passed,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = _lab_root()
    parser = argparse.ArgumentParser(
        prog="o1-crypto-lab",
        description="Isolated O1/O1-O cryptanalytic evidence-stream laboratory",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    benchmark = subparsers.add_parser(
        "benchmark", help="run the synthetic benchmark ladder"
    )
    benchmark.add_argument("--config", type=Path, default=root / "configs/quick.json")
    benchmark.add_argument("--output", type=Path, default=root / "runs/quick.json")
    benchmark.set_defaults(handler=_benchmark)

    compose = subparsers.add_parser(
        "compose", help="show legal and rejected operator chains"
    )
    compose.set_defaults(handler=_compose)

    verify = subparsers.add_parser(
        "verify-source",
        help="verify a read-only artifact snapshot against its manifest",
    )
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    verify.set_defaults(handler=_verify_source)

    boundary = subparsers.add_parser(
        "boundary", help="print the scientific claim boundary"
    )
    boundary.set_defaults(handler=_boundary)

    replay = subparsers.add_parser(
        "replay-o1o",
        help="normalize a stored O1-O run without executing generated code",
    )
    replay.add_argument("--session", type=Path, required=True)
    replay.add_argument("--output", type=Path)
    replay.add_argument("--include-events", action="store_true")
    replay.set_defaults(handler=_replay)

    ingest = subparsers.add_parser(
        "stage3-ingest",
        help="ingest the pinned A296/A297 solver corpus into an immutable capsule",
    )
    ingest.add_argument(
        "--config",
        type=Path,
        default=root / "configs/stage3_a296_a297_ingest_v1.json",
    )
    ingest.set_defaults(handler=_stage3_ingest)

    verify_run = subparsers.add_parser(
        "verify-run", help="verify a finalized immutable O1C run capsule"
    )
    verify_run.add_argument("path", type=Path)
    verify_run.set_defaults(handler=_verify_run)

    reader = subparsers.add_parser(
        "stage3-reader",
        help="fit, freeze and audit the retrospective Stage-3 reader tournament",
    )
    reader.add_argument(
        "--config",
        type=Path,
        default=root / "configs/stage3_reader_retrospective_v1.json",
    )
    reader.set_defaults(handler=_stage3_reader)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
