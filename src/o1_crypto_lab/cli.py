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
from .direct12_reproduction import run_direct12_reproduction
from .spectral_experiment import run_bounded_memory_tournament
from .isolation import IsolationPolicy
from .replay import O1OSessionReplay
from .reader_experiment import run_reader_experiment
from .run_capsule import ClaimLevel, RunCapsuleManager
from .stage3_ingest import run_stage3_ingest


def _lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_value_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


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


def _direct12_snapshot(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    source_config = config["source"]
    source_root = (root / source_config["repository"]).resolve()
    ledger_path = root / source_config["ledger"]
    if _sha256(ledger_path) != source_config["expected_ledger_sha256"]:
        raise RuntimeError("Direct12 source ledger hash changed")
    source = ReadOnlyArtifactSource(source_root, ledger_path)
    if source.manifest_sha256 != source_config["expected_ledger_sha256"]:
        raise RuntimeError("Direct12 source ledger pin changed during construction")
    source_commit = _git_commit(source_root)
    if source_commit != source_config["expected_head"]:
        raise RuntimeError("Direct12 source HEAD changed")
    dirty_result = subprocess.run(
        ["git", "-C", str(source_root), "status", "--porcelain"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    if dirty_result.returncode != 0:
        raise RuntimeError("could not record Direct12 source worktree state")
    dirty_rows = tuple(row for row in dirty_result.stdout.splitlines() if row)
    if bool(dirty_rows) is not bool(source_config["expected_dirty"]):
        raise RuntimeError("Direct12 source dirty-state expectation changed")
    denied = tuple(value.lower() for value in config["denied_member_fragments"])
    contaminated = sorted(
        member
        for member in source.entries
        if any(fragment in member.lower() for fragment in denied)
    )
    if contaminated:
        raise RuntimeError("Direct12 ledger contains denied result/progress members")
    report = source.verify()
    if not report.ok or report.checked != source_config["expected_members"]:
        raise RuntimeError("Direct12 source ledger verification failed")
    total_bytes = sum((source_root / member).stat().st_size for member in source.entries)
    if total_bytes != source_config["expected_bytes"]:
        raise RuntimeError("Direct12 source byte budget changed")

    manager = RunCapsuleManager(root)
    run = manager.start(
        attempt_id=config["attempt_id"],
        slug=config["slug"],
        commit=_git_commit(root),
        hypothesis=config["hypothesis"],
        prediction=config["prediction"],
        controls=tuple(config["controls"]),
        budgets=config["budgets"],
        source_hashes={
            "snapshot_config": _sha256(config_path),
            "direct12_source_ledger": _sha256(ledger_path),
            "direct12_boundary": _sha256(
                root / "provenance/DIRECT12_SOURCE_BOUNDARY.md"
            ),
        },
        claim_level=ClaimLevel(config["claim_level"]),
        next_action=config["next_action"],
        config=config,
        command=(
            "o1-crypto-lab",
            "direct12-snapshot",
            "--config",
            str(config_path),
        ),
        environment={
            "source_root": str(source_root),
            "source_head": source_commit,
            "source_worktree_dirty": bool(dirty_rows),
            "source_status_rows": len(dirty_rows),
            "fullround_manifest_provenance_claimed": False,
        },
    )
    try:
        run.append_stdout(
            f"Verified {report.checked} dirty-source ledger members; copying immutable snapshot.\n"
        )
        run.checkpoint(
            {
                "phase": "SOURCE_LEDGER_VERIFIED",
                "members": report.checked,
                "bytes": total_bytes,
                "denied_members_read": 0,
            }
        )
        for index, member in enumerate(sorted(source.entries), start=1):
            run.write_artifact(
                "source_snapshot/" + member,
                source.read_bytes(member),
            )
            if index % 16 == 0:
                run.checkpoint(
                    {
                        "phase": "COPYING_SOURCE_SNAPSHOT",
                        "members_copied": index,
                        "members_total": len(source.entries),
                        "denied_members_read": 0,
                    }
                )
        snapshot = {
            "schema": "o1-crypto-direct12-source-snapshot-v1",
            "source_head": source_commit,
            "source_worktree_dirty": bool(dirty_rows),
            "fullround_manifest_provenance_claimed": False,
            "source_ledger_sha256": source.manifest_sha256,
            "members": len(source.entries),
            "bytes": total_bytes,
            "entries": source.entries,
            "denied_members_read": 0,
        }
        run.write_json_artifact("source_snapshot.json", snapshot)
        metrics = {
            **snapshot,
            "selected_source_members_verified": report.checked,
            "gpu_seconds": 0,
            "external_solver_calls": 0,
        }
        finalized = run.finalize(metrics=metrics)
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-crypto-direct12-source-snapshot-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "denied_members_read": 0,
            },
            status="failed",
            next_action="Fix the source pin mismatch without modifying the sibling tree.",
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
                "members": len(source.entries),
                "bytes": total_bytes,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _direct12_reproduce(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    snapshot = config["snapshot"]
    capsule_path = (root / snapshot["capsule"]).resolve()
    source_hashes = {
        "reproduction_config": _sha256(config_path),
        "o1c_0003_capsule_manifest": _sha256(capsule_path / "artifacts.sha256"),
        "direct12_source_ledger": _sha256(root / snapshot["source_ledger"]),
        "direct12_adapter": _sha256(root / "src/o1_crypto_lab/direct12.py"),
        "shape532": _sha256(root / "src/o1_crypto_lab/shape532.py"),
        "direct12_reproduction": _sha256(
            root / "src/o1_crypto_lab/direct12_reproduction.py"
        ),
    }
    manager = RunCapsuleManager(root)
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
        command=(
            "o1-crypto-lab",
            "direct12-reproduce",
            "--config",
            str(config_path),
        ),
        environment={
            "source_capsule": str(capsule_path),
            "source_capsule_manifest_sha256": snapshot[
                "capsule_manifest_sha256"
            ],
            "mutable_sibling_access": False,
            "A349_truth_api_available": False,
        },
    )

    def on_frozen(pre_reveal: dict[str, object]) -> None:
        run.write_json_artifact("pre_reveal_orders.json", pre_reveal)
        run.checkpoint(
            {
                "phase": "A348_A349_ORDERS_FROZEN",
                "pre_reveal_sha256": pre_reveal["pre_reveal_sha256"],
                "A272_labels_read": 0,
                "A348_labels_read": 0,
                "A349_labels_read": 0,
            }
        )
        run.append_stdout(
            "A348 and A349 complete orders persisted before calibration truth; "
            "A349 truth API absent.\n"
        )

    try:
        run.append_stdout(
            "Independent 133-to-532 Direct12 reproduction started from O1C-0003.\n"
        )
        run.checkpoint(
            {
                "phase": "SOURCE_CAPSULE_REVERIFYING",
                "A348_labels_read": 0,
                "A349_labels_read": 0,
            }
        )
        result = run_direct12_reproduction(
            config_path,
            lab_root=root,
            on_frozen=on_frozen,
        )
        run.write_json_artifact("direct12_reproduction.json", result.report)
        run.write_json_artifact(
            "a348_score_field.json",
            {
                "schema": "o1-crypto-frozen-score-field-v1",
                "attempt_id": "A348",
                "scores": list(result.a348_scores),
                "order": list(result.a348_order),
                "target_label_present": False,
            },
        )
        run.write_json_artifact(
            "a349_score_field.json",
            {
                "schema": "o1-crypto-frozen-score-field-v1",
                "attempt_id": "A349",
                "scores": list(result.a349_scores),
                "order": list(result.a349_order),
                "target_label_present": False,
            },
        )
        run.write_artifact(
            "a348_order.uint16be",
            b"".join(value.to_bytes(2, "big") for value in result.a348_order),
        )
        run.write_artifact(
            "a349_order.uint16be",
            b"".join(value.to_bytes(2, "big") for value in result.a349_order),
        )
        metrics = result.metrics()
        run.append_stdout(
            json.dumps(
                {
                    "success_gate_passed": result.success_gate_passed,
                    "dataset_sha256": metrics["dataset_sha256"],
                    "a348_rank": metrics["a348"]["slice_z_rank_one_based"],
                    "a349_order_sha256": metrics["a349"][
                        "slice_z_order_uint16be_sha256"
                    ],
                    "A349_labels_read": metrics["labels"]["A349_labels_read"],
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
                "schema": "o1-crypto-direct12-reproduction-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "A349_labels_read": 0,
            },
            status="failed",
            next_action=(
                "Fix the exact reproduction invariant under a new attempt ID; "
                "do not inspect A349 progress or outcome."
            ),
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
                "a349_labels_read": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _bounded_memory_tournament(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    sources = config["sources"]
    o1c3_path = (root / sources["o1c_0003_capsule"]).resolve()
    o1c4_path = (root / sources["o1c_0004_capsule"]).resolve()
    module_names = (
        "artifacts.py",
        "cli.py",
        "direct12.py",
        "isolation.py",
        "orchestrator.py",
        "run_capsule.py",
        "shape532.py",
        "stage3.py",
        "types.py",
        "walsh_memory.py",
        "multislot_spectral.py",
        "quantized_spectral.py",
        "o1o_selector.py",
        "spectral_experiment.py",
    )
    source_hashes = {
        "tournament_config": _sha256(config_path),
        "o1c_0003_capsule_manifest": _sha256(o1c3_path / "artifacts.sha256"),
        "o1c_0004_capsule_manifest": _sha256(o1c4_path / "artifacts.sha256"),
        **{
            f"module_{name.removesuffix('.py')}": _sha256(
                root / "src/o1_crypto_lab" / name
            )
            for name in module_names
        },
    }
    manager = RunCapsuleManager(root)
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
        command=(
            "o1-crypto-lab",
            "bounded-memory-tournament",
            "--config",
            str(config_path),
        ),
        environment={
            "source_O1C_0003": str(o1c3_path),
            "source_O1C_0004": str(o1c4_path),
            "mutable_sibling_access": False,
            "A349_target_or_progress_access": False,
            "A349_target_blind_field_is_fresh_architecture_test": False,
        },
    )

    def on_selector_frozen(value: dict[str, object]) -> dict[str, object]:
        artifact = run.write_json_artifact("o1o_frozen_future_plan.json", value)
        run.checkpoint(
            {
                "phase": "O1O_FUTURE_PLAN_PERSISTED_BEFORE_A349_FIELD",
                "selection_sha256": value["selection_sha256"],
                "future_template_sha256": value["future_template_sha256"],
                "A348_labels_read": 0,
                "A349_field_opened": False,
                "A349_labels_read": 0,
            }
        )
        run.append_stdout(
            "O1-O future memory template persisted before the A349 score field was opened.\n"
        )
        return {
            "schema": "o1-crypto-future-template-persistence-receipt-v1",
            "persisted": True,
            "future_template_sha256": value["future_template_sha256"],
            "persisted_payload_sha256": _canonical_value_sha256(value),
            "artifact_sha256": _sha256(artifact),
        }

    def on_orders_frozen(
        value: dict[str, object], orders: dict[str, tuple[int, ...]]
    ) -> dict[str, object]:
        order_payloads: dict[str, bytes] = {}
        for arm_id in sorted(orders):
            if not arm_id or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
                for character in arm_id
            ):
                raise ValueError(f"unsafe tournament arm ID: {arm_id!r}")
            order = orders[arm_id]
            if len(order) != 4096 or set(order) != set(range(4096)):
                raise ValueError(f"incomplete tournament order: {arm_id}")
            order_payloads[arm_id] = b"".join(
                address.to_bytes(2, "big") for address in order
            )
        order_hashes: dict[str, str] = {}
        for arm_id, payload in order_payloads.items():
            artifact = run.write_artifact(
                f"frozen_orders/{arm_id}.uint16be",
                payload,
            )
            order_hashes[arm_id] = _sha256(artifact)
        # This completeness document is written only after every order artifact
        # exists and has been hashed back from the staging capsule.
        pre_reveal_artifact = run.write_json_artifact(
            "pre_reveal_tournament.json", value
        )
        run.checkpoint(
            {
                "phase": "ALL_A349_ORDERS_PERSISTED_BEFORE_A348_TRUTH",
                "orders": len(orders),
                "pre_reveal_sha256": value["pre_reveal_sha256"],
                "A348_labels_read": 0,
                "A349_labels_read": 0,
            }
        )
        run.append_stdout(
            f"Persisted {len(orders)} complete A349 target-blind orders before A348 truth.\n"
        )
        return {
            "schema": "o1-crypto-orders-persistence-receipt-v1",
            "persisted": True,
            "pre_reveal_sha256": value["pre_reveal_sha256"],
            "pre_reveal_artifact_sha256": _sha256(pre_reveal_artifact),
            "order_count": len(orders),
            "order_artifact_sha256_by_arm": order_hashes,
            "order_artifact_set_sha256": _canonical_value_sha256(order_hashes),
        }

    try:
        run.append_stdout(
            "O1C-0005 bounded-memory tournament started from immutable O1C-0003/0004.\n"
        )
        run.checkpoint(
            {
                "phase": "SOURCE_CAPSULES_REVERIFYING",
                "A348_labels_read": 0,
                "A349_field_opened": False,
                "A349_labels_read": 0,
            }
        )
        result = run_bounded_memory_tournament(
            config_path,
            lab_root=root,
            on_selector_frozen=on_selector_frozen,
            on_orders_frozen=on_orders_frozen,
        )
        run.write_json_artifact("bounded_memory_tournament.json", result.report)
        run.write_json_artifact("tournament_metrics.json", result.metrics())
        run.write_json_artifact(
            "selected_memory_template.json", result.selected_future_template
        )
        selected_id = result.metrics()["selected_arm"]["name"]
        selected_calibration = next(
            item for item in result.calibration_executions if item.arm_id == selected_id
        )
        selected_deployment = next(
            item for item in result.deployment_executions if item.arm_id == selected_id
        )
        run.write_json_artifact(
            "selected_a348_executable_plan.json", selected_calibration.plan
        )
        run.write_json_artifact(
            "selected_a349_executable_plan.json", selected_deployment.plan
        )
        run.write_json_artifact(
            "arm_summary.json",
            {
                "schema": "o1-crypto-bounded-memory-arm-summary-v1",
                "calibration": [
                    item.describe(include_plan=False)
                    for item in result.calibration_executions
                ],
                "deployment": [
                    item.describe(include_plan=False)
                    for item in result.deployment_executions
                ],
                "A349_target_labels_read": 0,
            },
        )
        metrics = result.metrics()
        run.append_stdout(
            json.dumps(
                {
                    "success_gate_passed": result.success_gate_passed,
                    "selected_arm": selected_id,
                    "selected_online_state_bytes": metrics["selected_arm"][
                        "serialized_online_state_bytes"
                    ],
                    "A349_rank_spearman": metrics["comparisons"][
                        "quantized_4bit_h1_25_A349_rank_spearman"
                    ],
                    "A349_labels_read": 0,
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
                "schema": "o1-crypto-bounded-memory-tournament-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "A349_target_labels_read": 0,
            },
            status="failed",
            next_action=(
                "Fix the recorded lifecycle or mechanism invariant under a new "
                "attempt ID without opening A349 target, outcome, or progress."
            ),
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
                "selected_arm": result.metrics()["selected_arm"]["name"],
                "A349_target_labels_read": 0,
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

    snapshot = subparsers.add_parser(
        "direct12-snapshot",
        help="copy the pinned dirty-source Direct12 dependency set into an immutable capsule",
    )
    snapshot.add_argument(
        "--config",
        type=Path,
        default=root / "configs/direct12_source_snapshot_v1.json",
    )
    snapshot.set_defaults(handler=_direct12_snapshot)

    reproduce = subparsers.add_parser(
        "direct12-reproduce",
        help="independently reproduce the frozen Direct12 532-feature reader",
    )
    reproduce.add_argument(
        "--config",
        type=Path,
        default=root / "configs/direct12_reproduction_v1.json",
    )
    reproduce.set_defaults(handler=_direct12_reproduce)

    tournament = subparsers.add_parser(
        "bounded-memory-tournament",
        help="freeze O1-O on A348, then transfer bounded memories to target-blind A349",
    )
    tournament.add_argument(
        "--config",
        type=Path,
        default=root / "configs/bounded_memory_tournament_v1.json",
    )
    tournament.set_defaults(handler=_bounded_memory_tournament)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
