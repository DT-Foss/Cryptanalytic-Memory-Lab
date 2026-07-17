"""Command-line interface for the isolated research harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path

from .artifacts import ReadOnlyArtifactSource
from .benchmark import BenchmarkConfig, composition_report, run_benchmark
from .corrected_direct12 import run_corrected_codec_bridge
from .direct12_reproduction import run_direct12_reproduction
from .full256_broker import (
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
)
from .full256_cnf_foundation import (
    load_full256_cnf_foundation_config,
    run_full256_cnf_foundation,
)
from .full256_multikey_calibration import (
    load_full256_multikey_calibration_config,
    run_full256_multikey_calibration,
)
from .online_self_discovery import (
    PREDICTION_ARMS,
    load_online_self_discovery_config,
    run_online_self_discovery,
)
from .full256_paired_sensor import (
    load_full256_paired_sensor_config,
    run_full256_paired_sensor,
)
from .spectral_experiment import run_bounded_memory_tournament
from .isolation import IsolationPolicy
from .living_inverse_foundation import (
    load_foundation_config,
    run_living_inverse_foundation,
)
from .living_inverse_reader_experiment import (
    DevelopmentReveal,
    SealedDevelopmentPanel,
    load_living_inverse_reader_config,
    run_living_inverse_reader_experiment,
)
from .replay import O1OSessionReplay
from .reader_experiment import run_reader_experiment
from .run_capsule import ClaimLevel, RunCapsuleManager
from .signed_direct_replication import (
    load_signed_direct_replication_config,
    run_signed_direct_replication,
)
from .stage3_ingest import run_stage3_ingest
from .upstream_experiment import run_upstream_ising_retrospective


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


def _verify_complete_direct12_order_artifact(path: Path) -> None:
    payload = path.read_bytes()
    if len(payload) != 4096 * 2:
        raise RuntimeError("Direct12 order artifact must contain 4096 uint16be cells")
    order = tuple(
        int.from_bytes(payload[offset : offset + 2], "big")
        for offset in range(0, len(payload), 2)
    )
    if len(set(order)) != 4096 or min(order) != 0 or max(order) != 4095:
        raise RuntimeError(
            "Direct12 order artifact must be an exact permutation of cells 0 through 4095"
        )


def _validate_o1c0006_order_inventory(
    order_index: list[dict[str, object]],
) -> dict[str, int]:
    expected = {
        "exact-historical-reference": 2,
        "negative-or-invalid-contract-control": 4,
        "adaptive-dc-candidate": 18,
    }
    category_counts = {
        kind: sum(row.get("kind") == kind for row in order_index) for kind in expected
    }
    members = [str(row.get("member")) for row in order_index]
    metadata_keys = {
        "exact-historical-reference": (
            "score_field_member",
            "score_field_artifact_sha256",
        ),
        "negative-or-invalid-contract-control": (
            "control_metadata_member",
            "control_metadata_artifact_sha256",
        ),
        "adaptive-dc-candidate": (
            "execution_member",
            "execution_artifact_sha256",
            "online_state_member",
            "online_state_artifact_sha256",
        ),
    }
    if (
        len(order_index) != 24
        or category_counts != expected
        or len(set(members)) != len(members)
        or any(
            row.get("cells") != 4096
            or row.get("bytes") != 8192
            or row.get("complete_permutation") is not True
            for row in order_index
        )
        or any(
            any(not row.get(key) for key in metadata_keys[str(row.get("kind"))])
            for row in order_index
        )
    ):
        raise RuntimeError("complete O1C-0006 order inventory differs")
    return category_counts


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


def _clean_git_commit(root: Path) -> str:
    commit = _git_commit(root)
    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=15,
    )
    if status.returncode != 0:
        raise RuntimeError("could not verify the lab Git worktree")
    if status.stdout.strip():
        raise RuntimeError("outcome-bearing runs require a clean committed lab worktree")
    return commit


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


def _corrected_codec_bridge(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("corrected bridge config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (root / "configs/corrected_codec_bridge_v1.json").resolve(
        strict=True
    )
    if config_path != expected_config:
        raise RuntimeError("corrected bridge requires its canonical lab config")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    anchors = config["anchors"]
    o1c3_path = (root / anchors["o1c_0003_capsule"]).resolve()
    o1c5_path = (root / anchors["o1c_0005_capsule"]).resolve()
    module_paths = tuple(sorted((root / "src/o1_crypto_lab").glob("*.py")))

    def current_source_hashes() -> dict[str, str]:
        return {
            "corrected_bridge_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "o1c_0003_capsule_manifest": _sha256(
                o1c3_path / "artifacts.sha256"
            ),
            "o1c_0005_capsule_manifest": _sha256(
                o1c5_path / "artifacts.sha256"
            ),
            **{f"module_{path.stem}": _sha256(path) for path in module_paths},
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(config["attempt_id"])
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-crypto-corrected-codec-bridge-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "fresh_challenge_generated": False,
                "target_labels_used_for_selection": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Treat O1C-0006 as consumed by a hard interruption and advance the "
                "same frozen protocol under O1C-0007; do not overwrite or silently "
                "resume partial artifacts."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    # Reserve the attempt before the first outcome-bearing computation.  This
    # prevents a failed gate, exception, or hard interruption from being silently
    # retried under the same attempt ID (optional stopping).
    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before corrected bridge reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before corrected bridge reservation")
    run = manager.start(
        attempt_id=config["attempt_id"],
        slug=config["slug"],
        commit=commit,
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
            "corrected-codec-bridge",
            "--config",
            str(config_path),
        ),
        environment={
            "sibling_repository": str((root / config["source"]["repository"]).resolve()),
            "sibling_repository_access": "READ_ONLY_PINNED_MEMBERS",
            "active_sibling_progress_or_outcome_reads": 0,
            "sibling_writes": 0,
            "fresh_challenge_generated": False,
            "development_fields": ["A355", "A356"],
            "scientific_replay_executions": 1,
            "outcome_bearing_replay_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_ADVANCE_ATTEMPT_ID",
        },
    )

    try:
        run.checkpoint(
            {
                "phase": "PINNED_SOURCE_REPLAY_STARTING",
                "A355_A356_target_labels_used_for_bridge_selection": 0,
                "active_sibling_progress_or_outcome_reads": 0,
                "sibling_writes": 0,
                "fresh_challenge_generated": False,
            }
        )
        run.append_stdout(
            "O1C-0006 exact corrected-codec replay and bounded adaptive-DC tournament started.\n"
        )
        result = run_corrected_codec_bridge(
            config_path,
            lab_root=root,
            artifact_writer=run.write_artifact,
        )
        if not result.success_gate_passed:
            raise RuntimeError("corrected bridge failed at least one frozen success gate")
        if _clean_git_commit(root) != commit:
            raise RuntimeError("lab Git commit changed during corrected bridge execution")
        if current_source_hashes() != source_hashes:
            raise RuntimeError("lab source hashes changed during corrected bridge execution")
        run.write_json_artifact("corrected_codec_bridge.json", result.report)
        run.write_json_artifact("bridge_metrics.json", result.metrics())
        run.write_json_artifact(
            "frozen_reference_ceiling_template.json", result.future_template
        )
        control_document: dict[str, object] = {
            "schema": "o1-crypto-o1c0006-fixed-negative-controls-v1",
            "controls": result.fixed_controls,
        }
        control_document["document_sha256"] = _canonical_value_sha256(
            control_document
        )
        control_document_path = run.write_json_artifact(
            "fixed_negative_controls.json", control_document
        )
        control_document_sha256 = _sha256(control_document_path)

        order_index: list[dict[str, object]] = []
        for field in result.fields:
            field_id = field.attempt_id.lower()
            score_field_path = run.write_json_artifact(
                f"score_fields/{field_id}.json",
                field.describe(include_scores=True),
            )
            reference_path = run.write_artifact(
                f"orders/reference/{field_id}.uint16be",
                b"".join(cell.to_bytes(2, "big") for cell in field.order),
            )
            _verify_complete_direct12_order_artifact(reference_path)
            order_index.append(
                {
                    "kind": "exact-historical-reference",
                    "field": field.attempt_id,
                    "arm_id": "legacy-A340-selected8-global-raw",
                    "member": f"artifacts/orders/reference/{field_id}.uint16be",
                    "sha256": _sha256(reference_path),
                    "cells": len(field.order),
                    "bytes": reference_path.stat().st_size,
                    "complete_permutation": True,
                    "score_field_member": f"artifacts/score_fields/{field_id}.json",
                    "score_field_artifact_sha256": _sha256(score_field_path),
                }
            )

        control_report_keys = {
            "frozen-o1c5-raw-identity": "frozen_o1c5_raw_identity",
            "global-z-atan-invalid-contract": "global_z_atan_control",
        }
        for field_id, controls in sorted(result.fixed_control_orders.items()):
            for control_id, order in sorted(controls.items()):
                if any(
                    character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
                    for character in control_id
                ):
                    raise ValueError(f"unsafe control ID: {control_id!r}")
                payload = b"".join(cell.to_bytes(2, "big") for cell in order)
                path = run.write_artifact(
                    f"orders/controls/{control_id}/{field_id.lower()}.uint16be",
                    payload,
                )
                expected_hash = result.fixed_controls[field_id][
                    control_report_keys[control_id]
                ]["order_uint16be_sha256"]
                if _sha256(path) != expected_hash:
                    raise ValueError("persisted fixed-control order differs")
                _verify_complete_direct12_order_artifact(path)
                order_index.append(
                    {
                        "kind": "negative-or-invalid-contract-control",
                        "field": field_id,
                        "arm_id": control_id,
                        "member": (
                            f"artifacts/orders/controls/{control_id}/"
                            f"{field_id.lower()}.uint16be"
                        ),
                        "sha256": expected_hash,
                        "cells": len(order),
                        "bytes": path.stat().st_size,
                        "complete_permutation": True,
                        "control_metadata_member": (
                            "artifacts/fixed_negative_controls.json"
                        ),
                        "control_metadata_artifact_sha256": (
                            control_document_sha256
                        ),
                    }
                )

        for arm_id, by_field in sorted(result.adaptive_executions.items()):
            if not arm_id or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
                for character in arm_id
            ):
                raise ValueError(f"unsafe adaptive arm ID: {arm_id!r}")
            for field_id, execution in sorted(by_field.items()):
                field_name = field_id.lower()
                execution_path = run.write_json_artifact(
                    f"adaptive/{arm_id}/{field_name}_execution.json",
                    execution.describe(include_plan=True),
                )
                state_path = run.write_artifact(
                    f"adaptive/{arm_id}/{field_name}_online_state.bin",
                    execution.frozen.online_state_bytes,
                )
                order_path = run.write_artifact(
                    f"orders/adaptive/{arm_id}/{field_name}.uint16be",
                    execution.order_uint16be,
                )
                if _sha256(order_path) != execution.order_uint16be_sha256:
                    raise ValueError("persisted adaptive order differs")
                _verify_complete_direct12_order_artifact(order_path)
                order_index.append(
                    {
                        "kind": "adaptive-dc-candidate",
                        "field": field_id,
                        "arm_id": arm_id,
                        "member": (
                            f"artifacts/orders/adaptive/{arm_id}/"
                            f"{field_name}.uint16be"
                        ),
                        "sha256": execution.order_uint16be_sha256,
                        "cells": len(execution.order),
                        "bytes": order_path.stat().st_size,
                        "complete_permutation": True,
                        "plan_sha256": execution.plan.plan_sha256,
                        "state_sha256": execution.frozen.state_sha256,
                        "execution_member": (
                            f"artifacts/adaptive/{arm_id}/"
                            f"{field_name}_execution.json"
                        ),
                        "execution_artifact_sha256": _sha256(execution_path),
                        "online_state_member": (
                            f"artifacts/adaptive/{arm_id}/"
                            f"{field_name}_online_state.bin"
                        ),
                        "online_state_artifact_sha256": _sha256(state_path),
                        "online_state_bytes": execution.plan.serialized_online_state_bytes,
                    }
                )

        category_counts = _validate_o1c0006_order_inventory(order_index)
        order_index_document = {
            "schema": "o1-crypto-o1c0006-complete-order-index-v1",
            "orders": order_index,
            "order_count": len(order_index),
            "category_counts": category_counts,
            "all_orders_are_complete_4096_cell_permutations": all(
                row["complete_permutation"] is True for row in order_index
            ),
            "target_labels_used_for_adaptive_bridge_selection": 0,
            "upstream_calibration_provenance_is_recorded_in_bridge_report": True,
        }
        order_index_document["order_set_sha256"] = _canonical_value_sha256(
            order_index_document
        )
        run.write_json_artifact("complete_order_index.json", order_index_document)
        run.checkpoint(
            {
                "phase": "DEVELOPMENT_ORDERS_AND_REFERENCE_CEILING_PERSISTED",
                "orders": len(order_index),
                "order_set_sha256": order_index_document["order_set_sha256"],
                "selected_arm": result.report["selection"]["selected_arm"],
                "future_template_sha256": result.future_template[
                    "future_template_sha256"
                ],
                "fresh_challenge_generated": False,
                "target_labels_used_for_selection": 0,
            }
        )
        metrics = result.metrics()
        metrics["complete_development_orders_persisted"] = len(order_index)
        metrics["complete_order_set_sha256"] = order_index_document[
            "order_set_sha256"
        ]
        run.append_stdout(
            json.dumps(
                {
                    "success_gate_passed": result.success_gate_passed,
                    "selected_arm": result.report["selection"]["selected_arm"],
                    "selected_online_state_bytes": result.report["costs"][
                        "selected_online_state_bytes"
                    ],
                    "minimum_rank_spearman": result.report["selection"][
                        "selected_metrics"
                    ]["minimum_rank_spearman"],
                    "complete_orders_persisted": len(order_index),
                    "fresh_challenge_generated": False,
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
                "schema": "o1-crypto-corrected-codec-bridge-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "fresh_challenge_generated": False,
                "target_labels_used_for_selection": 0,
                "sibling_writes": 0,
            },
            status="failed",
            next_action=(
                "Fix the lifecycle or reproduction invariant under a new attempt ID; "
                "do not generate or inspect a fresh challenge."
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
                "selected_arm": result.report["selection"]["selected_arm"],
                "complete_orders_persisted": len(order_index),
                "fresh_challenge_generated": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _upstream_ising_freeze(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("upstream Ising config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/upstream_ising_retrospective_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError("upstream Ising freeze requires its canonical lab config")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    source_capsule = (root / config["source"]["capsule"]).resolve()
    module_paths = tuple(sorted((root / "src/o1_crypto_lab").glob("*.py")))

    def current_source_hashes() -> dict[str, str]:
        return {
            "upstream_ising_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "o1c_0006_capsule_manifest": _sha256(
                source_capsule / "artifacts.sha256"
            ),
            **{f"module_{path.stem}": _sha256(path) for path in module_paths},
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(config["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-crypto-o1c0007-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "fresh_challenge_generated": False,
                "A356_target_labels_read": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Treat O1C-0007 as consumed by a hard interruption and advance "
                "the identical frozen protocol under O1C-0008; never replay the "
                "partial calibration under the same attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0007 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0007 reservation")
    run = manager.start(
        attempt_id=config["attempt_id"],
        slug=config["slug"],
        commit=commit,
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
            "upstream-ising-freeze",
            "--config",
            str(config_path),
        ),
        environment={
            "source_capsule": str(source_capsule),
            "source_access": "IMMUTABLE_O1C0006_EXACT_ALLOWLIST",
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "A355_truth_reads": 1,
            "A356_target_or_outcome_reads": 0,
            "fresh_challenge_generated": False,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_ADVANCE_ATTEMPT_ID",
        },
    )

    def on_panel_frozen(
        inventory: dict[str, object] | object,
        order_blob: bytes,
    ) -> dict[str, object]:
        if not isinstance(inventory, dict):
            raise RuntimeError("panel inventory must be an object")
        inventory_path = run.write_json_artifact(
            "panel/a355_target_blind_inventory.json", inventory
        )
        order_path = run.write_artifact(
            "panel/a355_target_blind_orders.uint16be", order_blob
        )
        if (
            _sha256(order_path) != inventory["order_blob_sha256"]
            or order_path.stat().st_size != inventory["order_blob_bytes"]
            or _canonical_value_sha256(
                {
                    key: value
                    for key, value in inventory.items()
                    if key != "inventory_sha256"
                }
            )
            != inventory["inventory_sha256"]
        ):
            raise RuntimeError("persisted target-blind panel inventory differs")
        run.checkpoint(
            {
                "phase": "A355_672_ORDERS_PERSISTED_BEFORE_CALIBRATION_TRUTH",
                "orders": inventory["orders"],
                "eligible_orders": inventory["selection_eligible_orders"],
                "inventory_sha256": inventory["inventory_sha256"],
                "order_blob_sha256": inventory["order_blob_sha256"],
                "A355_target_labels_read": 0,
                "A356_source_members_opened": 0,
            }
        )
        run.append_stdout(
            "Persisted all 672 complete A355 target-blind orders before calibration truth.\n"
        )
        return {
            "schema": "o1-crypto-o1c0007-panel-persistence-receipt-v1",
            "persisted": True,
            "inventory_sha256": inventory["inventory_sha256"],
            "inventory_artifact_sha256": _sha256(inventory_path),
            "order_blob_sha256": inventory["order_blob_sha256"],
            "orders": inventory["orders"],
            "target_labels_read": 0,
        }

    def on_selection_frozen(
        template: dict[str, object] | object,
        state_bytes: bytes,
        order_bytes: bytes,
    ) -> dict[str, object]:
        if not isinstance(template, dict):
            raise RuntimeError("future template must be an object")
        template_path = run.write_json_artifact(
            "selection/frozen_future_template.json", template
        )
        state_path = run.write_artifact(
            "selection/a355_compact_memory.bin", state_bytes
        )
        order_path = run.write_artifact(
            "selection/a355_selected_order.uint16be", order_bytes
        )
        _verify_complete_direct12_order_artifact(order_path)
        if _sha256(order_path) != template["calibration"]["order_sha256"]:
            raise RuntimeError("persisted A355 selected order differs")
        run.checkpoint(
            {
                "phase": "SELECTED_MEMORY_PERSISTED_BEFORE_A356_SOURCE_OPEN",
                "future_template_sha256": template["future_template_sha256"],
                "A355_state_sha256": _sha256(state_path),
                "A355_order_sha256": _sha256(order_path),
                "A356_source_members_opened": 0,
                "A356_target_labels_read": 0,
            }
        )
        run.append_stdout(
            "Frozen the selected compact evidence memory before opening A356 metadata or shards.\n"
        )
        return {
            "schema": "o1-crypto-o1c0007-selection-persistence-receipt-v1",
            "persisted": True,
            "future_template_sha256": template["future_template_sha256"],
            "future_template_artifact_sha256": _sha256(template_path),
            "A355_state_sha256": _sha256(state_path),
            "A355_order_sha256": _sha256(order_path),
            "A356_source_members_opened": 0,
        }

    def on_deployment_frozen(
        document: dict[str, object] | object,
        state_bytes: bytes,
        order_bytes: bytes,
    ) -> dict[str, object]:
        if not isinstance(document, dict):
            raise RuntimeError("deployment execution must be an object")
        document_path = run.write_json_artifact(
            "deployment/a356_target_blind_execution.json", document
        )
        state_path = run.write_artifact(
            "deployment/a356_compact_memory.bin", state_bytes
        )
        order_path = run.write_artifact(
            "deployment/a356_target_blind_order.uint16be", order_bytes
        )
        _verify_complete_direct12_order_artifact(order_path)
        if _sha256(order_path) != document["order_sha256"]:
            raise RuntimeError("persisted A356 order differs")
        run.checkpoint(
            {
                "phase": "A356_TARGET_BLIND_ORDER_PERSISTED",
                "execution_sha256": document["execution_sha256"],
                "A356_state_sha256": _sha256(state_path),
                "A356_order_sha256": _sha256(order_path),
                "A356_target_labels_read": 0,
                "fresh_challenge_generated": False,
            }
        )
        return {
            "schema": "o1-crypto-o1c0007-deployment-persistence-receipt-v1",
            "persisted": True,
            "execution_sha256": document["execution_sha256"],
            "execution_artifact_sha256": _sha256(document_path),
            "A356_state_sha256": _sha256(state_path),
            "A356_order_sha256": _sha256(order_path),
            "A356_target_labels_read": 0,
        }

    try:
        run.checkpoint(
            {
                "phase": "IMMUTABLE_O1C0006_SOURCE_PINNED",
                "A355_target_labels_read": 0,
                "A356_source_members_opened": 0,
                "A356_target_labels_read": 0,
                "sibling_writes": 0,
            }
        )
        run.append_stdout(
            "O1C-0007 upstream solver-evidence panel and compact bit-vault freeze started.\n"
        )
        result = run_upstream_ising_retrospective(
            config_path,
            lab_root=root,
            artifact_writer=run.write_artifact,
            on_panel_frozen=on_panel_frozen,
            on_selection_frozen=on_selection_frozen,
            on_deployment_frozen=on_deployment_frozen,
        )
        if not result.success_gate_passed:
            raise RuntimeError("O1C-0007 failed at least one frozen success gate")
        if _clean_git_commit(root) != commit:
            raise RuntimeError("lab Git commit changed during O1C-0007 execution")
        if current_source_hashes() != source_hashes:
            raise RuntimeError("lab source hashes changed during O1C-0007 execution")
        run.write_json_artifact("upstream_ising_retrospective.json", result.report)
        run.write_json_artifact("o1c0007_metrics.json", result.metrics())
        run.write_json_artifact("source_receipts.json", result.source_snapshot)
        run.write_json_artifact(
            "calibration/a355_target_bound_panel.json",
            result.calibration_panel.describe(),
        )
        run.write_json_artifact(
            "calibration/a355_exact_label_null.json",
            result.exact_null.describe(include_label_vectors=True),
        )
        run.write_json_artifact(
            "selection/a355_selected_memory.json",
            result.a355_memory.describe(),
        )
        metrics = result.metrics()
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(metrics=metrics)
    except Exception as exc:
        if run.publication_prepared:
            # Final metrics and content were already commitment-bound. Finish
            # or discover that exact publication without relabeling it.
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-crypto-o1c0007-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "fresh_challenge_generated": False,
                "A356_target_labels_read": 0,
                "sibling_writes": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Fix the recorded lifecycle or reproduction invariant under a "
                "new attempt ID; never replay O1C-0007 or inspect an A356 outcome."
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
                "selected_view": result.metrics()["selected_view_id"],
                "A355_rank": result.metrics()["A355_rank"],
                "maximum_state_bytes": result.metrics()[
                    "maximum_serialized_logical_mechanism_state_bytes"
                ],
                "exact_familywise_p": result.metrics()["exact_familywise_p"],
                "A356_order_sha256": result.metrics()["A356_order_sha256"],
                "fresh_challenge_generated": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _living_inverse_foundation(args: argparse.Namespace) -> int:
    root = _lab_root()
    config_path = args.config.resolve()
    top_level, foundation = load_foundation_config(config_path)
    source_hashes = {
        "config": _sha256(config_path),
        "chacha_trace": _sha256(root / "src/o1_crypto_lab/chacha_trace.py"),
        "living_inverse": _sha256(root / "src/o1_crypto_lab/living_inverse.py"),
        "full256_broker": _sha256(root / "src/o1_crypto_lab/full256_broker.py"),
        "foundation_runner": _sha256(
            root / "src/o1_crypto_lab/living_inverse_foundation.py"
        ),
    }
    manager = RunCapsuleManager(root)
    command = (
        "o1-crypto-lab",
        "living-inverse-foundation",
        "--config",
        str(config_path),
    )
    run = manager.start(
        attempt_id=str(top_level["attempt_id"]),
        slug=str(top_level["slug"]),
        commit=_clean_git_commit(root),
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=command,
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "sibling_repository_access": "none",
            "accelerator": "none",
        },
    )
    try:
        run.append_stdout(
            "O1C-0008 full-256 Living Inverse foundation started; "
            "no fresh target and no sibling access.\n"
        )
        run.checkpoint(
            {
                "phase": "ATTACKER_CONTRACT_FROZEN",
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
            }
        )
        result = run_living_inverse_foundation(foundation)
        run.write_json_artifact("living_inverse_foundation.json", result.report)
        run.write_json_artifact(
            "attacker_contract.json", result.report["attacker_contract"]
        )
        run.write_json_artifact(
            "metric_harness.json", result.report["metric_harness"]
        )
        run.checkpoint(
            {
                "phase": "FOUNDATION_MEASURED",
                "result_sha256": result.report["result_sha256"],
                "success_gate_passed": result.success_gate_passed,
                "deployment_contrasts": result.report["corpus"][
                    "deployment_contrasts"
                ],
                "fresh_target_revealed": False,
            }
        )
        run.append_stdout(
            json.dumps(result.metrics(), sort_keys=True, allow_nan=False) + "\n"
        )
        finalized = run.finalize(metrics=result.metrics())
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-living-inverse-foundation-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "fresh_target_revealed": False,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                "Fix the recorded full-256 foundation invariant under a new "
                "attempt ID; do not weaken the attacker contract."
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
                "unknown_target_key_bits": 256,
                "deployment_contrasts": result.report["corpus"][
                    "deployment_contrasts"
                ],
                "random_baseline_key_nll_bits": result.report["metric_harness"][
                    "random_baseline"
                ]["key_nll_bits"],
                "fresh_target_revealed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result.success_gate_passed else 1


def _peak_rss_mib() -> float:
    value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    divisor = 1024.0 * 1024.0 if sys.platform == "darwin" else 1024.0
    return value / divisor


def _living_inverse_reader(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("Living Inverse reader config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/living_inverse_reader_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError("Living Inverse reader requires its canonical lab config")
    top_level, reader_config = load_living_inverse_reader_config(config_path)
    participating = (
        "chacha_trace.py",
        "living_inverse.py",
        "living_inverse_corpus.py",
        "living_inverse_ridge.py",
        "living_inverse_reader_experiment.py",
        "full256_broker.py",
        "run_capsule.py",
        "cli.py",
    )

    def current_source_hashes() -> dict[str, str]:
        return {
            "reader_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            **{
                f"module_{Path(name).stem}": _sha256(
                    root / "src/o1_crypto_lab" / name
                )
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-living-inverse-reader-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "sibling_writes": 0,
                "fresh_target_state": "unknown-after-hard-interruption",
            },
            status="stopped",
            next_action=(
                "Treat O1C-0009 as consumed and advance the frozen full-256 "
                "protocol to O1C-0010; never replay a partial DEV opening."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0009 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0009 reservation")
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "living-inverse-reader",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "accelerator": "none",
            "mps_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "fresh_target_generated_at_reservation": False,
            "planned_sealed_development_targets": reader_config.development_targets,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_ADVANCE_ATTEMPT_ID",
        },
    )
    cpu_started = time.process_time()

    def persist_calibration(
        document: dict[str, object], model_blobs: dict[str, bytes] | object
    ) -> dict[str, object]:
        if not isinstance(model_blobs, Mapping):
            raise RuntimeError("frozen model inventory differs")
        selection_path = run.write_json_artifact(
            "calibration/frozen_selection.json", document
        )
        model_rows = {}
        for arm, blob in sorted(model_blobs.items()):
            if not isinstance(arm, str) or not isinstance(blob, bytes):
                raise RuntimeError("frozen model row differs")
            path = run.write_artifact(f"calibration/models/{arm}.o1hrr", blob)
            digest = _sha256(path)
            if digest != document["models"][arm]["sha256"]:
                raise RuntimeError("persisted frozen reader differs")
            model_rows[arm] = {
                "artifact": f"artifacts/calibration/models/{arm}.o1hrr",
                "sha256": digest,
                "bytes": path.stat().st_size,
            }
        receipt = {
            "schema": "o1-256-calibration-freeze-receipt-v1",
            "persisted": True,
            "selection_artifact_sha256": _sha256(selection_path),
            "selection_sha256": _canonical_value_sha256(document),
            "models": model_rows,
            "development_targets_created": 0,
            "development_labels_read": 0,
        }
        run.write_json_artifact("calibration/freeze_receipt.json", receipt)
        run.checkpoint(
            {
                "phase": "MODELS_SELECTION_AND_POLICY_FROZEN_BEFORE_DEV",
                "primary_arm": document["primary_arm"],
                "selection_sha256": receipt["selection_sha256"],
                "development_targets_created": 0,
                "development_labels_read": 0,
                "sibling_writes": 0,
            }
        )
        run.append_stdout(
            "Persisted models, scales, proposal policy and primary arm before DEV creation.\n"
        )
        return receipt

    sealed_brokers: list[Full256TargetBroker] = []
    sealed_publications: list[dict[str, object]] = []
    frozen_prediction_path: Path | None = None

    def open_sealed_development() -> SealedDevelopmentPanel:
        if sealed_brokers or sealed_publications:
            raise RuntimeError("sealed Development panel may be opened only once")
        for index in range(reader_config.development_targets):
            broker = Full256TargetBroker(
                block_count=1,
                entropy_source_id="os.urandom:o1c-0009",
                target_id=f"o1c-0009-dev-{index:04d}",
            )
            publication = broker.publish()
            sealed_brokers.append(broker)
            sealed_publications.append(publication)
        publication_path = run.write_json_artifact(
            "development/sealed_publications.json",
            {
                "schema": "o1-256-sealed-development-panel-v1",
                "targets": len(sealed_publications),
                "publications": sealed_publications,
                "keys_in_artifact": False,
                "target_traces_in_artifact": False,
            },
        )
        run.checkpoint(
            {
                "phase": "SEALED_DEV_PUBLICATIONS_OPENED_AFTER_CALIBRATION_FREEZE",
                "development_targets": len(sealed_publications),
                "publication_artifact_sha256": _sha256(publication_path),
                "development_labels_read": 0,
                "predictions_frozen": False,
                "sibling_writes": 0,
            }
        )
        return SealedDevelopmentPanel(
            target_ids=tuple(
                str(publication["target_id"])
                for publication in sealed_publications
            ),
            public_targets=tuple(
                public_view_from_publication(publication)
                for publication in sealed_publications
            ),
            publications=tuple(sealed_publications),
        )

    def freeze_predictions_and_reveal(
        prediction_blob: bytes,
        prediction_index: dict[str, object],
    ) -> DevelopmentReveal:
        nonlocal frozen_prediction_path
        if (
            len(sealed_brokers) != reader_config.development_targets
            or len(sealed_publications) != reader_config.development_targets
            or frozen_prediction_path is not None
        ):
            raise RuntimeError("sealed Development lifecycle differs before freeze")
        frozen_prediction_path = run.write_artifact(
            "development/frozen_predictions.float64le", prediction_blob
        )
        if (
            _sha256(frozen_prediction_path) != prediction_index["sha256"]
            or frozen_prediction_path.stat().st_size != prediction_index["bytes"]
        ):
            raise RuntimeError("persisted frozen Development predictions differ")
        unsigned_index = {
            key: value
            for key, value in prediction_index.items()
            if key != "index_sha256"
        }
        if _canonical_value_sha256(unsigned_index) != prediction_index["index_sha256"]:
            raise RuntimeError("frozen Development prediction index differs")
        index_path = run.write_json_artifact(
            "development/frozen_predictions.index.json", prediction_index
        )
        run.checkpoint(
            {
                "phase": "ALL_DEV_PREDICTIONS_PERSISTED_BEFORE_REVEAL",
                "frozen_prediction_sha256": prediction_index["sha256"],
                "frozen_prediction_index_sha256": prediction_index[
                    "index_sha256"
                ],
                "prediction_index_artifact_sha256": _sha256(index_path),
                "development_labels_read": 0,
                "sibling_writes": 0,
            }
        )
        reveals = []
        keys = []
        for broker, publication in zip(
            sealed_brokers, sealed_publications, strict=True
        ):
            receipt = make_freeze_receipt(
                publication,
                frozen_artifact_sha256=str(prediction_index["sha256"]),
            )
            reveal = broker.reveal(receipt)
            reveals.append(reveal)
            keys.append(bytes.fromhex(reveal["commitment_preimage"]["key_hex"]))
        reveals_path = run.write_json_artifact(
            "development/sealed_reveals.json",
            {
                "schema": "o1-256-sealed-development-reveals-v1",
                "predictions_frozen_before_reveal": True,
                "reveals": reveals,
            },
        )
        receipt = {
            "schema": "o1-256-development-panel-reveal-receipt-v1",
            "predictions_frozen_before_reveal": True,
            "frozen_prediction_sha256": prediction_index["sha256"],
            "frozen_prediction_index_sha256": prediction_index["index_sha256"],
            "reveal_count": len(reveals),
            "reveal_root": _canonical_value_sha256(
                [reveal["reveal_sha256"] for reveal in reveals]
            ),
            "reveal_artifact_sha256": _sha256(reveals_path),
        }
        run.write_json_artifact(
            "development/reveal_receipt.json", receipt
        )
        run.checkpoint(
            {
                "phase": "SEALED_DEV_REVEALED_AFTER_PREDICTION_FREEZE",
                "development_labels_read": len(keys),
                "reveal_root": receipt["reveal_root"],
                "sibling_writes": 0,
            }
        )
        return DevelopmentReveal(keys=tuple(keys), receipt=receipt)

    try:
        run.checkpoint(
            {
                "phase": "FULL256_PROTOCOL_RESERVED",
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "development_targets_created": 0,
                "development_labels_read": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0009 full-256 output-only Living Inverse reader started on CPU.\n"
        )
        result = run_living_inverse_reader_experiment(
            reader_config,
            open_sealed_development=open_sealed_development,
            freeze_predictions_and_reveal=freeze_predictions_and_reveal,
            on_calibration_frozen=persist_calibration,
            require_calibration_persistence=True,
        )
        if not result.execution_success_gate_passed:
            raise RuntimeError("O1C-0009 execution integrity gate failed")
        cpu_seconds = time.process_time() - cpu_started
        peak_rss_mib = _peak_rss_mib()
        maximum_cpu = float(top_level["budgets"]["maximum_cpu_seconds"])
        maximum_rss = float(top_level["budgets"]["maximum_resident_memory_mib"])
        if cpu_seconds > maximum_cpu:
            raise RuntimeError("O1C-0009 exceeded its CPU budget")
        if peak_rss_mib > maximum_rss:
            raise RuntimeError("O1C-0009 exceeded its resident-memory budget")
        if _clean_git_commit(root) != commit:
            raise RuntimeError("lab Git commit changed during O1C-0009 execution")
        if current_source_hashes() != source_hashes:
            raise RuntimeError("lab source hashes changed during O1C-0009 execution")
        if frozen_prediction_path is None:
            raise RuntimeError("Development predictions were not persisted")
        if (
            _sha256(frozen_prediction_path) != result.posterior_index["sha256"]
            or frozen_prediction_path.stat().st_size
            != result.posterior_index["bytes"]
        ):
            raise RuntimeError("persisted DEV prediction binary differs")
        run.write_json_artifact("living_inverse_reader.json", result.report)
        run.write_json_artifact("reader_metrics.json", result.metrics())
        run.write_json_artifact("corpus/split_inventory.json", result.report["corpus"])
        run.write_json_artifact(
            "feature_plans.json", result.report["feature_plans"]
        )
        run.write_json_artifact(
            "development/controls.json",
            {
                "direct_controls": result.report["development"]["direct_controls"],
                "primary_control": result.report["development"]["primary_control"],
            },
        )
        run.checkpoint(
            {
                "phase": "DEVELOPMENT_OPENED_ONCE_AND_PERSISTED",
                "development_openings": 1,
                "development_targets": reader_config.development_targets,
                "primary_arm": result.report["calibration"]["primary_arm"],
                "scientific_signal_gate_passed": result.scientific_signal_gate_passed,
                "result_sha256": result.report["result_sha256"],
                "sibling_writes": 0,
                "mps_calls": 0,
            }
        )
        metrics = {
            **result.metrics(),
            "cpu_seconds": cpu_seconds,
            "peak_rss_mib": peak_rss_mib,
            "cpu_budget_seconds": maximum_cpu,
            "resident_memory_budget_mib": maximum_rss,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n")
        finalized = run.finalize(metrics=metrics)
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-living-inverse-reader-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "fresh_target_generated": bool(sealed_brokers),
                "fresh_target_count": len(sealed_brokers),
                "fresh_target_revealed": bool(sealed_brokers)
                and all(broker.phase == "REVEALED" for broker in sealed_brokers),
                "sibling_writes": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Fix the recorded invariant under O1C-0010 without weakening "
                "the full-256 output-only attacker contract or replaying O1C-0009."
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
                "execution_success_gate_passed": result.execution_success_gate_passed,
                "scientific_signal_gate_passed": result.scientific_signal_gate_passed,
                "primary_arm": result.report["calibration"]["primary_arm"],
                "primary_development_mean_key_nll_bits": result.metrics()[
                    "primary_development_mean_key_nll_bits"
                ],
                "primary_transferable_bits": result.metrics()[
                    "primary_transferable_bits"
                ],
                "cpu_seconds": cpu_seconds,
                "peak_rss_mib": peak_rss_mib,
                "fresh_target_generated": True,
                "fresh_target_count": reader_config.development_targets,
                "fresh_target_revealed": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _signed_direct_replication(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("signed replication config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/signed_direct_replication_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError("signed replication requires its canonical lab config")
    top_level, source, replication = load_signed_direct_replication_config(
        config_path
    )
    participating = (
        "chacha_trace.py",
        "living_inverse.py",
        "living_inverse_ridge.py",
        "living_inverse_reader_experiment.py",
        "signed_direct_replication.py",
        "full256_broker.py",
        "artifacts.py",
        "run_capsule.py",
        "cli.py",
    )

    source_capsule = (root / source.source_capsule).resolve(strict=True)
    runs_root = (root / "runs").resolve(strict=True)
    if (
        source_capsule.parent != runs_root
        or source_capsule.name.startswith(".")
        or not source_capsule.is_dir()
    ):
        raise RuntimeError("source capsule must be one finalized run directory")
    source_manifest_path = source_capsule / "artifacts.sha256"
    manager = RunCapsuleManager(root)
    source_capsule_verification = manager.verify(source_capsule)
    if (
        not source_capsule_verification.ok
        or source_capsule_verification.manifest_sha256
        != source.source_manifest_sha256
    ):
        raise RuntimeError("O1C-0009 source capsule verification differs")
    artifact_source = ReadOnlyArtifactSource(
        source_capsule, source_manifest_path
    )
    if artifact_source.manifest_sha256 != source.source_manifest_sha256:
        raise RuntimeError("O1C-0009 artifact manifest SHA-256 differs")
    required_source_members = (
        source.direct_model_artifact,
        source.shuffled_model_artifact,
        "artifacts/living_inverse_reader.json",
    )
    source_member_report = artifact_source.verify(required_source_members)
    if not source_member_report.ok:
        raise RuntimeError("O1C-0009 source member verification failed")
    direct_model_blob = artifact_source.read_bytes(source.direct_model_artifact)
    shuffled_model_blob = artifact_source.read_bytes(source.shuffled_model_artifact)
    source_reader_report = artifact_source.read_json(
        "artifacts/living_inverse_reader.json"
    )
    if (
        _canonical_value_sha256(
            {
                key: value
                for key, value in source_reader_report.items()
                if key != "result_sha256"
            }
        )
        != source.source_result_sha256
        or source_reader_report.get("result_sha256") != source.source_result_sha256
        or _sha256(source_capsule / source.direct_model_artifact)
        != source.direct_model_sha256
        or _sha256(source_capsule / source.shuffled_model_artifact)
        != source.shuffled_model_sha256
    ):
        raise RuntimeError("O1C-0009 source result or model pin differs")
    source_manifest_bytes = source_manifest_path.read_bytes()
    if (
        hashlib.sha256(source_manifest_bytes).hexdigest()
        != source.source_manifest_sha256
    ):
        raise RuntimeError("O1C-0009 source manifest changed while pinning")

    def current_source_hashes() -> dict[str, str]:
        return {
            "replication_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "source_capsule_manifest": source.source_manifest_sha256,
            "source_result": source.source_result_sha256,
            "source_direct_model": source.direct_model_sha256,
            "source_shuffled_model": source.shuffled_model_sha256,
            **{
                f"module_{Path(name).stem}": _sha256(
                    root / "src/o1_crypto_lab" / name
                )
                for name in participating
            },
        }

    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-signed-direct-replication-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "source_models_refit": False,
                "fresh_target_state": "unknown-after-hard-interruption",
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Treat O1C-0010 as consumed, preserve its partial artifacts, and "
                "advance to the full-256 public-CNF paired-assumption mechanism "
                "without replaying this random panel."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0010 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0010 reservation")
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "signed-direct-replication",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "accelerator": "none",
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "source_models_refit": False,
            "fresh_target_generated_at_reservation": False,
            "planned_sealed_development_targets": replication.development_targets,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    cpu_started = time.process_time()
    sealed_brokers: list[Full256TargetBroker] = []
    sealed_publications: list[dict[str, object]] = []
    frozen_prediction_path: Path | None = None
    protocol_receipt: dict[str, object] | None = None

    source_provenance = {
        "source_capsule_verified": True,
        "source_capsule": source.source_capsule,
        "source_manifest_sha256": source_capsule_verification.manifest_sha256,
        "source_manifest_checked_files": source_capsule_verification.checked,
        "source_result_sha256": source.source_result_sha256,
        "source_member_verification": source_member_report.describe(),
        "source_reader_report_artifact_sha256": _sha256(
            source_capsule / "artifacts/living_inverse_reader.json"
        ),
    }

    def persist_protocol(
        document: dict[str, object], model_blobs: Mapping[str, bytes]
    ) -> dict[str, object]:
        nonlocal protocol_receipt
        if sealed_brokers or sealed_publications:
            raise RuntimeError("target entropy exists before protocol persistence")
        expected_models = {
            "direct": source.direct_model_sha256,
            "shuffled_key_control": source.shuffled_model_sha256,
        }
        if set(model_blobs) != set(expected_models):
            raise RuntimeError("signed replication model inventory differs")
        pin_path = run.write_json_artifact(
            "source/o1c0009_source_pin.json", source_provenance
        )
        manifest_path = run.write_artifact(
            "source/o1c0009_artifacts.sha256", source_manifest_bytes
        )
        model_rows = {}
        for name, blob in sorted(model_blobs.items()):
            path = run.write_artifact(f"source/models/{name}.o1hrr", blob)
            digest = _sha256(path)
            if digest != expected_models[name]:
                raise RuntimeError("persisted source model differs")
            model_rows[name] = {
                "artifact": f"artifacts/source/models/{name}.o1hrr",
                "sha256": digest,
                "bytes": path.stat().st_size,
            }
        protocol_path = run.write_json_artifact(
            "protocol/frozen_signed_replication.json", document
        )
        protocol_receipt = {
            "schema": "o1-256-signed-direct-protocol-freeze-receipt-v1",
            "persisted": True,
            "protocol_sha256": _canonical_value_sha256(document),
            "protocol_artifact_sha256": _sha256(protocol_path),
            "source_pin_artifact_sha256": _sha256(pin_path),
            "source_manifest_copy_sha256": _sha256(manifest_path),
            "models": model_rows,
            "development_targets_created": 0,
            "development_labels_read": 0,
        }
        run.write_json_artifact("protocol/freeze_receipt.json", protocol_receipt)
        run.checkpoint(
            {
                "phase": "SOURCE_MODELS_SCALES_AND_GATES_FROZEN_BEFORE_TARGET_ENTROPY",
                "protocol_sha256": protocol_receipt["protocol_sha256"],
                "source_models_refit": False,
                "source_scales_refit": False,
                "development_targets_created": 0,
                "development_labels_read": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
            }
        )
        run.append_stdout(
            "Persisted exact O1C-0009 model bytes, signed scales and all gates before target entropy.\n"
        )
        return protocol_receipt

    def open_sealed_development() -> SealedDevelopmentPanel:
        if protocol_receipt is None:
            raise RuntimeError("sealed panel cannot precede protocol persistence")
        if sealed_brokers or sealed_publications:
            raise RuntimeError("sealed Development panel may be opened only once")
        for index in range(replication.development_targets):
            broker = Full256TargetBroker(
                block_count=1,
                entropy_source_id="os.urandom:o1c-0010",
                target_id=f"o1c-0010-dev-{index:04d}",
            )
            publication = broker.publish()
            sealed_brokers.append(broker)
            sealed_publications.append(publication)
        publication_document = {
            "schema": "o1-256-sealed-development-panel-v1",
            "targets": len(sealed_publications),
            "publications": sealed_publications,
            "keys_in_artifact": False,
            "target_traces_in_artifact": False,
        }
        publication_path = run.write_json_artifact(
            "development/sealed_publications.json", publication_document
        )
        run.checkpoint(
            {
                "phase": "SEALED_2048_PUBLICATIONS_OPENED_AFTER_PROTOCOL_FREEZE",
                "development_targets": len(sealed_publications),
                "publication_root": _canonical_value_sha256(sealed_publications),
                "publication_artifact_sha256": _sha256(publication_path),
                "development_labels_read": 0,
                "predictions_frozen": False,
                "sibling_writes": 0,
            }
        )
        return SealedDevelopmentPanel(
            target_ids=tuple(
                str(publication["target_id"])
                for publication in sealed_publications
            ),
            public_targets=tuple(
                public_view_from_publication(publication)
                for publication in sealed_publications
            ),
            publications=tuple(sealed_publications),
        )

    def freeze_predictions_and_reveal(
        prediction_blob: bytes,
        prediction_index: dict[str, object],
    ) -> DevelopmentReveal:
        nonlocal frozen_prediction_path
        expected_bytes = int(top_level["budgets"]["frozen_prediction_bytes"])
        if (
            protocol_receipt is None
            or len(sealed_brokers) != replication.development_targets
            or len(sealed_publications) != replication.development_targets
            or frozen_prediction_path is not None
            or len(prediction_blob) != expected_bytes
            or prediction_index.get("bytes") != expected_bytes
            or len(prediction_index.get("matrices", []))
            != int(top_level["budgets"]["prediction_matrices"])
        ):
            raise RuntimeError("sealed Development lifecycle differs before freeze")
        frozen_prediction_path = run.write_artifact(
            "development/frozen_predictions.float64le", prediction_blob
        )
        if (
            _sha256(frozen_prediction_path) != prediction_index["sha256"]
            or frozen_prediction_path.stat().st_size != expected_bytes
        ):
            raise RuntimeError("persisted frozen Development predictions differ")
        unsigned_index = {
            key: value
            for key, value in prediction_index.items()
            if key != "index_sha256"
        }
        if _canonical_value_sha256(unsigned_index) != prediction_index["index_sha256"]:
            raise RuntimeError("frozen Development prediction index differs")
        index_path = run.write_json_artifact(
            "development/frozen_predictions.index.json", prediction_index
        )
        run.checkpoint(
            {
                "phase": "ALL_2048_PREDICTION_AND_CONTROL_MATRICES_PERSISTED_BEFORE_REVEAL",
                "frozen_prediction_sha256": prediction_index["sha256"],
                "frozen_prediction_index_sha256": prediction_index[
                    "index_sha256"
                ],
                "prediction_bytes": expected_bytes,
                "prediction_index_artifact_sha256": _sha256(index_path),
                "development_labels_read": 0,
                "sibling_writes": 0,
            }
        )
        reveals = []
        keys = []
        for broker, publication in zip(
            sealed_brokers, sealed_publications, strict=True
        ):
            receipt = make_freeze_receipt(
                publication,
                frozen_artifact_sha256=str(prediction_index["sha256"]),
            )
            reveal = broker.reveal(receipt)
            reveals.append(reveal)
            keys.append(bytes.fromhex(reveal["commitment_preimage"]["key_hex"]))
        reveals_path = run.write_json_artifact(
            "development/sealed_reveals.json",
            {
                "schema": "o1-256-sealed-development-reveals-v1",
                "predictions_frozen_before_reveal": True,
                "reveals": reveals,
            },
        )
        receipt = {
            "schema": "o1-256-development-panel-reveal-receipt-v1",
            "predictions_frozen_before_reveal": True,
            "frozen_prediction_sha256": prediction_index["sha256"],
            "frozen_prediction_index_sha256": prediction_index["index_sha256"],
            "protocol_sha256": protocol_receipt["protocol_sha256"],
            "publication_root": _canonical_value_sha256(sealed_publications),
            "reveal_count": len(reveals),
            "reveal_root": _canonical_value_sha256(
                [reveal["reveal_sha256"] for reveal in reveals]
            ),
            "reveal_artifact_sha256": _sha256(reveals_path),
        }
        run.write_json_artifact("development/reveal_receipt.json", receipt)
        run.checkpoint(
            {
                "phase": "SEALED_2048_TARGETS_REVEALED_AFTER_EXACT_PREDICTION_FREEZE",
                "development_labels_read": len(keys),
                "reveal_root": receipt["reveal_root"],
                "source_models_refit": False,
                "sibling_writes": 0,
            }
        )
        return DevelopmentReveal(keys=tuple(keys), receipt=receipt)

    try:
        run.checkpoint(
            {
                "phase": "FULL256_SIGNED_REPLICATION_RESERVED",
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "source_models_refit": False,
                "source_scales_refit": False,
                "development_targets_created": 0,
                "development_labels_read": 0,
                "development_openings": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0010 prospective full-256 no-refit signed replication started on CPU.\n"
        )
        result = run_signed_direct_replication(
            replication,
            source,
            direct_model_blob=direct_model_blob,
            shuffled_model_blob=shuffled_model_blob,
            source_provenance=source_provenance,
            open_sealed_development=open_sealed_development,
            freeze_predictions_and_reveal=freeze_predictions_and_reveal,
            on_protocol_frozen=persist_protocol,
            require_protocol_persistence=True,
        )
        if not result.execution_success_gate_passed:
            raise RuntimeError("O1C-0010 execution integrity gate failed")
        maximum_cpu = float(top_level["budgets"]["maximum_cpu_seconds"])
        maximum_rss = float(
            top_level["budgets"]["maximum_resident_memory_mib"]
        )
        if _clean_git_commit(root) != commit:
            raise RuntimeError("lab Git commit changed during O1C-0010 execution")
        if current_source_hashes() != source_hashes:
            raise RuntimeError("lab source hashes changed during O1C-0010 execution")
        final_source_verification = manager.verify(source_capsule)
        if (
            not final_source_verification.ok
            or final_source_verification.manifest_sha256
            != source.source_manifest_sha256
            or artifact_source.read_bytes(source.direct_model_artifact)
            != direct_model_blob
            or artifact_source.read_bytes(source.shuffled_model_artifact)
            != shuffled_model_blob
        ):
            raise RuntimeError("source capsule changed during O1C-0010 execution")
        if (
            frozen_prediction_path is None
            or _sha256(frozen_prediction_path) != result.prediction_index["sha256"]
            or frozen_prediction_path.stat().st_size
            != result.prediction_index["bytes"]
            or len(sealed_brokers) != replication.development_targets
            or not all(broker.phase == "REVEALED" for broker in sealed_brokers)
        ):
            raise RuntimeError("persisted O1C-0010 outcome lifecycle differs")
        run.write_json_artifact("signed_direct_replication.json", result.report)
        run.write_json_artifact("replication_metrics.json", result.metrics())
        run.write_json_artifact(
            "development/control_metrics.json",
            {
                "arms": result.report["evaluation"]["arms"],
                "paired_controls": result.report["evaluation"]["paired_controls"],
                "scientific_signal_gate": result.report["scientific_signal_gate"],
            },
        )
        run.checkpoint(
            {
                "phase": "SIGNED_REPLICATION_COMPLETED_AND_PERSISTED",
                "development_openings": 1,
                "development_targets": replication.development_targets,
                "scientific_signal_gate_passed": result.scientific_signal_gate_passed,
                "result_sha256": result.report["result_sha256"],
                "source_models_refit": False,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        # Measure after every outcome-bearing artifact has been serialized.  The
        # immutable capsule publication itself is metadata/provenance overhead and
        # is reported separately to the invoking process after finalize().
        cpu_seconds = time.process_time() - cpu_started
        peak_rss_mib = _peak_rss_mib()
        if cpu_seconds > maximum_cpu:
            raise RuntimeError("O1C-0010 exceeded its CPU budget")
        if peak_rss_mib > maximum_rss:
            raise RuntimeError("O1C-0010 exceeded its resident-memory budget")
        result_metrics = result.metrics()
        execution_gate_passed = result.execution_success_gate_passed
        scientific_gate_passed = result.scientific_signal_gate_passed
        metrics = {
            **result_metrics,
            "cpu_seconds": cpu_seconds,
            "peak_rss_mib": peak_rss_mib,
            "peak_rss_measurement_scope": (
                "through-outcome-artifact-persistence-before-capsule-publication"
            ),
            "cpu_budget_seconds": maximum_cpu,
            "resident_memory_budget_mib": maximum_rss,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n")
        # Drop the 24 MiB prediction blob before the capsule performs its immutable
        # manifest pass; all hashes and result artifacts are already persisted.
        del result
        finalized = run.finalize(metrics=metrics)
        process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-signed-direct-replication-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "target_trace_fields_in_deployment": 0,
                "source_models_refit": False,
                "fresh_target_generated": bool(sealed_brokers),
                "fresh_target_count": len(sealed_brokers),
                "predictions_frozen": frozen_prediction_path is not None,
                "fresh_target_revealed": bool(sealed_brokers)
                and all(broker.phase == "REVEALED" for broker in sealed_brokers),
                "sibling_writes": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the failed O1C-0010 capsule, fix only the recorded "
                "execution invariant under a new attempt ID, and continue the "
                "full-256 public-CNF paired-assumption mechanism."
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
                "execution_success_gate_passed": execution_gate_passed,
                "scientific_signal_gate_passed": scientific_gate_passed,
                "mean_effective_compression_bits": result_metrics[
                    "mean_effective_compression_bits"
                ],
                "conditional_null_z_score": result_metrics[
                    "conditional_null_z_score"
                ],
                "direct_minus_shuffled_compression_bits": result_metrics[
                    "direct_minus_shuffled_compression_bits"
                ],
                "direct_minus_output_permutation_compression_bits": result_metrics[
                    "direct_minus_output_permutation_compression_bits"
                ],
                "cpu_seconds": cpu_seconds,
                "outcome_peak_rss_mib": peak_rss_mib,
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "fresh_target_count": replication.development_targets,
                "fresh_target_revealed": True,
            },
            indent=2,
            sort_keys=True,
        )
    )
    # A clean negative replication is a completed scientific result, not a crash.
    return 0


def _full256_cnf_foundation(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 CNF foundation config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/full256_cnf_foundation_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError("full-256 CNF foundation requires its canonical lab config")
    top_level, foundation_config = load_full256_cnf_foundation_config(config_path)
    participating = (
        "chacha_trace.py",
        "living_inverse.py",
        "full256_cnf.py",
        "full256_cnf_foundation.py",
        "run_capsule.py",
        "cli.py",
    )

    def current_source_hashes() -> dict[str, str]:
        return {
            "foundation_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            **{
                f"module_{Path(name).stem}": _sha256(
                    root / "src/o1_crypto_lab" / name
                )
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-full-cnf-foundation-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "fresh_random_targets": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Preserve the partial O1C-0011 staging capsule and advance the "
                "same frozen compiler protocol under a new attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0011 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0011 reservation")
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "full256-cnf-foundation",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "formula_role": "target-independent-public-relation",
            "accelerator": "none",
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "fresh_random_targets": 0,
            "solver_formula_calls": 3,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    cpu_started = time.process_time()
    try:
        run.checkpoint(
            {
                "phase": "FULL256_CNF_PROTOCOL_RESERVED",
                "unknown_target_key_bits": 256,
                "rounds": 20,
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "fresh_random_targets": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0011 full-256 public ChaCha20 CNF compilation and solver self-tests started on CPU.\n"
        )
        with tempfile.TemporaryDirectory(prefix="o1c0011-cnf-", dir="/tmp") as temporary:
            result = run_full256_cnf_foundation(foundation_config, temporary)
            if not result.success_gate_passed:
                raise RuntimeError("O1C-0011 mandatory full-256 CNF gate failed")
            if _clean_git_commit(root) != commit:
                raise RuntimeError("lab Git commit changed during O1C-0011")
            if current_source_hashes() != source_hashes:
                raise RuntimeError("lab source hashes changed during O1C-0011")

            persisted: dict[str, dict[str, object]] = {}
            inventory = result.report["artifact_inventory"]
            if not isinstance(inventory, dict):
                raise RuntimeError("O1C-0011 artifact inventory differs")
            for relative, source_path in sorted(result.artifact_paths.items()):
                path = run.write_artifact(relative, source_path.read_bytes())
                row = inventory.get(relative)
                if (
                    not isinstance(row, dict)
                    or _sha256(path) != row.get("sha256")
                    or path.stat().st_size != row.get("bytes")
                ):
                    raise RuntimeError("persisted O1C-0011 CNF artifact differs")
                persisted[relative] = {
                    "sha256": _sha256(path),
                    "bytes": path.stat().st_size,
                }
            if persisted != inventory:
                raise RuntimeError("persisted O1C-0011 inventory differs")
            report_path = run.write_json_artifact(
                "full256_cnf_foundation.json", result.report
            )
            run.write_json_artifact(
                "self_tests.json", result.report["self_tests"]
            )
            run.write_json_artifact(
                "attacker_contract.json", result.report["attacker_contract"]
            )
            run.write_json_artifact("formula_summary.json", result.report["formula"])
            run.checkpoint(
                {
                    "phase": "FULL256_CNF_AND_PAIRED_INSTANCES_PERSISTED",
                    "result_sha256": result.report["result_sha256"],
                    "report_artifact_sha256": _sha256(report_path),
                    "template_sha256": result.report["formula"]["dimacs_sha256"],
                    "variable_count": result.report["formula"]["variable_count"],
                    "clause_count": result.report["formula"]["clause_count"],
                    "public_key_units": 0,
                    "paired_assumption_instances": 2,
                    "solver_formula_calls": 3,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
            )

            cpu_seconds = time.process_time() - cpu_started
            peak_rss_mib = _peak_rss_mib()
            budgets = top_level["budgets"]
            if not isinstance(budgets, dict):
                raise RuntimeError("O1C-0011 budget object differs")
            if cpu_seconds > float(budgets["maximum_cpu_seconds"]):
                raise RuntimeError("O1C-0011 exceeded its CPU budget")
            if peak_rss_mib > float(budgets["maximum_resident_memory_mib"]):
                raise RuntimeError("O1C-0011 exceeded its resident-memory budget")
            if (
                int(result.report["resources"]["persistent_artifact_bytes"])
                > int(budgets["maximum_persistent_artifact_bytes"])
            ):
                raise RuntimeError("O1C-0011 exceeded its artifact-byte budget")
            metrics = {
                **result.metrics(),
                "cpu_seconds": cpu_seconds,
                "peak_rss_mib": peak_rss_mib,
                "cpu_budget_seconds": budgets["maximum_cpu_seconds"],
                "resident_memory_budget_mib": budgets[
                    "maximum_resident_memory_mib"
                ],
                "persistent_artifact_bytes": result.report["resources"][
                    "persistent_artifact_bytes"
                ],
            }
            run.append_stdout(
                json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n"
            )
            finalized = run.finalize(metrics=metrics)
            process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-full-cnf-foundation-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "fresh_random_targets": 0,
                "target_key_units": 0,
                "sibling_writes": 0,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the failed O1C-0011 capsule, fix the exact compiler or "
                "solver-integrity invariant under a new attempt ID, and do not "
                "weaken the 256-bit attacker contract."
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
                "variable_count": metrics["variable_count"],
                "template_clause_count": metrics["template_clause_count"],
                "public_instance_clause_count": metrics[
                    "public_instance_clause_count"
                ],
                "semantic_operation_count": metrics["semantic_operation_count"],
                "template_sha256": metrics["template_sha256"],
                "public_key_unit_clauses": metrics["public_key_unit_clauses"],
                "rfc_fixed_key_status": metrics["rfc_fixed_key_status"],
                "flipped_output_status": metrics["flipped_output_status"],
                "second_fixed_key_status": metrics["second_fixed_key_status"],
                "cpu_seconds": metrics["cpu_seconds"],
                "outcome_peak_rss_mib": metrics["peak_rss_mib"],
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "sibling_writes": 0,
                "fresh_random_targets": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _full256_paired_sensor(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 paired sensor config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/full256_paired_causal_sensor_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError("full-256 paired sensor requires its canonical lab config")
    top_level, sensor_config = load_full256_paired_sensor_config(config_path)
    source_capsule = (root / sensor_config.source.capsule).resolve(strict=True)
    public_cnf = (
        source_capsule / sensor_config.source.public_instance
    ).resolve(strict=True)
    semantic_map = (
        source_capsule / sensor_config.source.semantic_map
    ).resolve(strict=True)
    source_manifest = (source_capsule / "artifacts.sha256").resolve(strict=True)
    participating = (
        "chacha_trace.py",
        "living_inverse.py",
        "cadical_sensor.py",
        "causal_bitfield.py",
        "full256_paired_sensor.py",
        "run_capsule.py",
        "cli.py",
    )

    def current_source_hashes() -> dict[str, str]:
        return {
            "paired_sensor_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "native_pair_sensor": _sha256(
                root / "native/cadical_pair_sensor.cpp"
            ),
            "native_tracer_header": _sha256(
                root / "native/cadical_tracer_3_0_0.hpp"
            ),
            "source_capsule_manifest": _sha256(source_manifest),
            "source_public_cnf": _sha256(public_cnf),
            "source_semantic_map": _sha256(semantic_map),
            **{
                f"module_{Path(name).stem}": _sha256(
                    root / "src/o1_crypto_lab" / name
                )
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-paired-causal-sensor-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "fresh_random_targets": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Preserve the partial O1C-0012 staging capsule and advance the "
                "same direct full-256 paired-sensor contract under a new attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if source_hashes["source_capsule_manifest"] != (
        sensor_config.source.manifest_sha256
    ):
        raise RuntimeError("O1C-0012 source capsule manifest differs")
    if source_hashes["source_public_cnf"] != (
        sensor_config.source.public_instance_sha256
    ):
        raise RuntimeError("O1C-0012 public CNF differs")
    if source_hashes["source_semantic_map"] != (
        sensor_config.source.semantic_map_sha256
    ):
        raise RuntimeError("O1C-0012 semantic map differs")
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0012 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0012 reservation")
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "full256-paired-sensor",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "accelerator": "none",
            "native_solver": "cadical-3.0.0-single-threaded-fork-cow",
            "native_solver_branches": 514,
            "bounded_state_bytes": sensor_config.state_plan.serialized_state_bytes,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "fresh_random_targets": 0,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    parent_cpu_started = time.process_time()
    outcome_wall_started = time.monotonic()
    try:
        run.checkpoint(
            {
                "phase": "FULL256_PAIRED_SENSOR_PROTOCOL_RESERVED",
                "unknown_target_key_bits": 256,
                "rounds": 20,
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "paired_assumption_branches": 512,
                "state_bytes": sensor_config.state_plan.serialized_state_bytes,
                "fresh_random_targets": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0012 direct full-256 paired CaDiCaL proof sensor started on CPU.\n"
        )
        with tempfile.TemporaryDirectory(
            prefix="o1c0012-paired-", dir="/tmp"
        ) as temporary:
            result = run_full256_paired_sensor(
                sensor_config,
                lab_root=root,
                working_directory=temporary,
            )
            if not result.success_gate_passed:
                raise RuntimeError("O1C-0012 mandatory paired-sensor gate failed")
            if _clean_git_commit(root) != commit:
                raise RuntimeError("lab Git commit changed during O1C-0012")
            if current_source_hashes() != source_hashes:
                raise RuntimeError("lab source hashes changed during O1C-0012")

            persistent_artifact_bytes = 0
            persisted_artifacts: dict[str, dict[str, object]] = {}
            for relative, payload in sorted(result.artifacts.items()):
                path = run.write_artifact(relative, payload)
                expected_sha256 = hashlib.sha256(payload).hexdigest()
                if _sha256(path) != expected_sha256 or path.stat().st_size != len(
                    payload
                ):
                    raise RuntimeError("persisted O1C-0012 artifact differs")
                persistent_artifact_bytes += len(payload)
                persisted_artifacts[relative] = {
                    "sha256": expected_sha256,
                    "bytes": len(payload),
                }
            run.checkpoint(
                {
                    "phase": "FULL256_PAIRED_STATE_AND_DIAGNOSTIC_PERSISTED",
                    "result_sha256": result.report["result_sha256"],
                    "state_sha256": result.report["state"]["state_sha256"],
                    "state_bytes": result.report["state"][
                        "serialized_state_bytes"
                    ],
                    "paired_bits": result.report["probe_stream"][
                        "paired_bit_count"
                    ],
                    "proof_frontiers": result.report["probe_stream"][
                        "proof_frontier_count"
                    ],
                    "persisted_artifact_bytes": persistent_artifact_bytes,
                    "artifact_inventory": persisted_artifacts,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
            )

            parent_cpu_seconds = time.process_time() - parent_cpu_started
            native_cpu_seconds = float(
                result.report["resources"]["native_child_cpu_seconds"]
            )
            total_cpu_seconds = max(
                parent_cpu_seconds + native_cpu_seconds,
                float(result.report["resources"]["budgeted_cpu_seconds"]),
            )
            wall_seconds = max(
                float(result.report["resources"]["wall_seconds"]),
                time.monotonic() - outcome_wall_started,
            )
            parent_peak_rss_mib = _peak_rss_mib()
            process_group_peak_rss_mib = (
                float(
                    result.report["resources"][
                        "conservative_process_group_peak_rss_bytes"
                    ]
                )
                / (1024.0 * 1024.0)
            )
            peak_rss_mib = max(
                parent_peak_rss_mib, process_group_peak_rss_mib
            )
            branch_count = int(result.report["probe_stream"]["branch_count"])
            sentinel_branches = 2 * sensor_config.probe.deterministic_sentinel_reruns
            total_native_branches = branch_count + sentinel_branches
            budgets = top_level["budgets"]
            if not isinstance(budgets, dict):
                raise RuntimeError("O1C-0012 budget object differs")
            budget_checks = {
                "cpu": total_cpu_seconds
                <= float(budgets["maximum_cpu_seconds"]),
                "wall": wall_seconds <= float(budgets["maximum_wall_seconds"]),
                "resident_memory": peak_rss_mib
                <= float(budgets["maximum_resident_memory_mib"]),
                "persistent_artifacts": persistent_artifact_bytes
                <= int(budgets["maximum_persistent_artifact_bytes"]),
                "native_branches": total_native_branches
                <= int(budgets["maximum_native_solver_branches"]),
                "state": int(
                    result.report["state"]["serialized_state_bytes"]
                )
                <= sensor_config.maximum_state_bytes,
                "mps": result.metrics()["mps_calls"]
                <= int(budgets["maximum_mps_calls"]),
                "gpu": result.metrics()["gpu_calls"]
                <= int(budgets["maximum_gpu_calls"]),
                "sibling_reads": result.metrics()["sibling_reads"]
                <= int(budgets["maximum_sibling_reads"]),
                "sibling_writes": result.metrics()["sibling_writes"]
                <= int(budgets["maximum_sibling_writes"]),
                "fresh_targets": result.metrics()["fresh_random_targets"]
                <= int(budgets["maximum_fresh_random_targets"]),
            }
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            if failed_budgets:
                raise RuntimeError(
                    "O1C-0012 exceeded budgets: " + ", ".join(failed_budgets)
                )
            metrics = {
                **result.metrics(),
                "parent_cpu_seconds": parent_cpu_seconds,
                "cpu_seconds": total_cpu_seconds,
                "wall_seconds": wall_seconds,
                "peak_rss_mib": peak_rss_mib,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "native_solver_branches": total_native_branches,
                "budget_checks": budget_checks,
            }
            run.append_stdout(
                json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n"
            )
            finalized = run.finalize(metrics=metrics)
            process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-paired-causal-sensor-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "fresh_random_targets": 0,
                "target_key_units": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the failed O1C-0012 capsule, fix the exact native, "
                "state, or budget invariant under a new attempt ID, and keep "
                "the direct 256-bit output-only attacker contract unchanged."
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
                "paired_bit_count": metrics["paired_bit_count"],
                "proof_frontier_count": metrics["proof_frontier_count"],
                "state_bytes": metrics["state_bytes"],
                "state_sha256": metrics["state_sha256"],
                "corrected_key_nll_bits": metrics["corrected_key_nll_bits"],
                "corrected_effective_compression_bits": metrics[
                    "corrected_effective_compression_bits"
                ],
                "corrected_correct_bits": metrics["corrected_correct_bits"],
                "million_decoy_rank": metrics["million_decoy_rank"],
                "exact_key_recovered": metrics["exact_key_recovered"],
                "cpu_seconds": metrics["cpu_seconds"],
                "wall_seconds": metrics["wall_seconds"],
                "outcome_peak_rss_mib": metrics["peak_rss_mib"],
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "sibling_writes": 0,
                "fresh_random_targets": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _full256_multikey_calibration(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 multi-key config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/full256_multikey_causal_calibration_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError(
            "full-256 multi-key calibration requires its canonical lab config"
        )
    top_level, calibration_config = load_full256_multikey_calibration_config(
        config_path
    )
    runs_root = (root / "runs").resolve(strict=True)
    source_capsule = (root / calibration_config.source.capsule).resolve(strict=True)
    if (
        source_capsule.parent != runs_root
        or source_capsule.name.startswith(".")
        or not source_capsule.is_dir()
    ):
        raise RuntimeError("O1C-0013 source must be one finalized run capsule")
    source_manifest = (source_capsule / "artifacts.sha256").resolve(strict=True)
    source_template = (source_capsule / calibration_config.source.template).resolve(
        strict=True
    )
    source_semantic_map = (
        source_capsule / calibration_config.source.semantic_map
    ).resolve(strict=True)
    native_header = (
        Path(calibration_config.native.include_directory) / "cadical.hpp"
    ).resolve(strict=True)
    native_library = Path(calibration_config.native.static_library).resolve(strict=True)
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
        "run_capsule.py",
        "cli.py",
    )

    def current_source_hashes() -> dict[str, str]:
        return {
            "multikey_calibration_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "native_pair_sensor": _sha256(root / "native/cadical_pair_sensor.cpp"),
            "native_tracer_header": _sha256(root / "native/cadical_tracer_3_0_0.hpp"),
            "native_cadical_header": _sha256(native_header),
            "native_cadical_library": _sha256(native_library),
            "source_capsule_manifest": _sha256(source_manifest),
            "source_template": _sha256(source_template),
            "source_semantic_map": _sha256(source_semantic_map),
            **{
                f"module_{Path(name).stem}": _sha256(root / "src/o1_crypto_lab" / name)
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": ("o1-256-multikey-causal-calibration-interrupted-v1"),
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "fresh_target_state": "unknown-after-hard-interruption",
                "sibling_reads": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Preserve the partial O1C-0013 staging capsule, never replay its "
                "sealed targets, and advance the same full-256 output-only protocol "
                "under a new attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    expected_source_hashes = {
        "source_capsule_manifest": calibration_config.source.manifest_sha256,
        "source_template": calibration_config.source.template_sha256,
        "source_semantic_map": calibration_config.source.semantic_map_sha256,
        "native_cadical_header": (calibration_config.native.cadical_header_sha256),
        "native_cadical_library": (calibration_config.native.cadical_library_sha256),
    }
    for name, expected_sha256 in expected_source_hashes.items():
        if source_hashes[name] != expected_sha256:
            raise RuntimeError(f"O1C-0013 pinned {name} differs")
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0013 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0013 reservation")
    planned_sweeps = (
        calibration_config.corpus.build_targets
        + calibration_config.corpus.calibration_targets
        + calibration_config.corpus.sealed_targets
        + len(calibration_config.controls.transforms)
    )
    planned_native_branches = planned_sweeps * (
        512 + 2 * calibration_config.probe.sentinel_reruns_per_sweep
    )
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "full256-multikey-calibration",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "target_internal_trace_inputs": 0,
            "accelerator": "none",
            "native_solver": "cadical-3.0.0-single-threaded-fork-cow",
            "planned_native_solver_branches": planned_native_branches,
            "causal_state_bytes": (
                calibration_config.state_plan.serialized_state_bytes
            ),
            "maximum_live_target_state_bytes": (
                calibration_config.maximum_live_target_state_bytes
            ),
            "planned_build_targets": calibration_config.corpus.build_targets,
            "planned_calibration_targets": (
                calibration_config.corpus.calibration_targets
            ),
            "planned_sealed_targets": calibration_config.corpus.sealed_targets,
            "fresh_target_generated_at_reservation": False,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted_artifacts: dict[str, dict[str, object]] = {}
    persistent_artifact_bytes = 0
    reader_frozen = False
    predictions_frozen = False
    outcome_parent_cpu_started = time.process_time()
    outcome_wall_started = time.monotonic()

    def persist_group(
        artifacts: Mapping[str, bytes],
        *,
        phase: str,
    ) -> None:
        nonlocal persistent_artifact_bytes
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise RuntimeError(f"O1C-0013 {phase} artifact group differs")
        group_bytes = 0
        for relative, payload in artifacts.items():
            if (
                not isinstance(relative, str)
                or not relative
                or not isinstance(payload, bytes)
                or relative in persisted_artifacts
            ):
                raise RuntimeError(f"O1C-0013 {phase} artifact entry differs")
            group_bytes += len(payload)
        if (
            persistent_artifact_bytes + group_bytes
            > calibration_config.budgets.maximum_persistent_artifact_bytes
        ):
            raise RuntimeError("O1C-0013 would exceed its artifact-byte budget")
        for relative, payload in sorted(artifacts.items()):
            path = run.write_artifact(relative, payload)
            expected_sha256 = hashlib.sha256(payload).hexdigest()
            if _sha256(path) != expected_sha256 or path.stat().st_size != len(payload):
                raise RuntimeError(f"persisted O1C-0013 {phase} artifact differs")
            persisted_artifacts[relative] = {
                "sha256": expected_sha256,
                "bytes": len(payload),
                "phase": phase,
            }
        persistent_artifact_bytes += group_bytes

    def on_reader_frozen(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
    ) -> None:
        nonlocal reader_frozen
        expected_inventory = {
            relative: {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for relative, payload in sorted(artifacts.items())
            if relative != "reader_freeze.json"
        }
        if reader_frozen or predictions_frozen:
            raise RuntimeError("O1C-0013 reader freeze callback order differs")
        if (
            document.get("phase") != "READER_FROZEN_BEFORE_SEALED_TARGET_ENTROPY"
            or document.get("fresh_target_entropy_calls") != 0
            or document.get("artifacts") != expected_inventory
            or "reader_freeze.json" not in artifacts
            or json.loads(artifacts["reader_freeze.json"]) != dict(document)
        ):
            raise RuntimeError("O1C-0013 reader freeze document differs")
        persist_group(artifacts, phase="reader-freeze")
        reader_frozen = True
        run.checkpoint(
            {
                "phase": "READER_ARTIFACT_SET_PERSISTED_BEFORE_FRESH_ENTROPY",
                "reader_freeze_sha256": document["reader_freeze_sha256"],
                "selected_arm": document["selected_arm"],
                "selected_logit_scale": document["selected_logit_scale"],
                "fresh_target_entropy_calls": 0,
                "fresh_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def on_predictions_frozen(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
    ) -> None:
        nonlocal predictions_frozen
        expected_inventory = {
            relative: {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for relative, payload in sorted(artifacts.items())
            if relative != "prediction_set_freeze.json"
        }
        if not reader_frozen or predictions_frozen:
            raise RuntimeError("O1C-0013 prediction freeze callback order differs")
        if (
            document.get("phase") != "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            or document.get("artifacts") != expected_inventory
            or "prediction_set_freeze.json" not in artifacts
            or json.loads(artifacts["prediction_set_freeze.json"]) != dict(document)
        ):
            raise RuntimeError("O1C-0013 prediction freeze document differs")
        sealed_targets = document.get("sealed_targets")
        if (
            not isinstance(sealed_targets, list)
            or len(sealed_targets) != calibration_config.corpus.sealed_targets
        ):
            raise RuntimeError("O1C-0013 sealed prediction inventory differs")
        persist_group(artifacts, phase="prediction-freeze")
        predictions_frozen = True
        run.checkpoint(
            {
                "phase": "ALL_PREDICTION_ARTIFACTS_PERSISTED_BEFORE_ANY_REVEAL",
                "reader_freeze_sha256": document["reader_freeze_sha256"],
                "prediction_set_sha256": document["prediction_set_sha256"],
                "sealed_prediction_count": len(sealed_targets),
                "sealed_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    try:
        run.checkpoint(
            {
                "phase": "FULL256_MULTIKEY_PROTOCOL_RESERVED",
                "unknown_target_key_bits": 256,
                "rounds": 20,
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "build_targets": calibration_config.corpus.build_targets,
                "calibration_targets": (calibration_config.corpus.calibration_targets),
                "sealed_targets_created": 0,
                "sealed_targets_revealed": 0,
                "planned_native_solver_branches": planned_native_branches,
                "reader_frozen": False,
                "predictions_frozen": False,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0013 full-256 multi-key causal calibration and sealed CPU attack started.\n"
        )
        with tempfile.TemporaryDirectory(
            prefix="o1c0013-multikey-", dir="/tmp"
        ) as temporary:
            result = run_full256_multikey_calibration(
                calibration_config,
                lab_root=root,
                working_directory=temporary,
                on_reader_frozen=on_reader_frozen,
                on_predictions_frozen=on_predictions_frozen,
            )
            if not reader_frozen or not predictions_frozen:
                raise RuntimeError(
                    "O1C-0013 freeze callbacks did not complete before reveal"
                )
            if not result.success_gate_passed:
                raise RuntimeError("O1C-0013 mandatory lifecycle gate failed")
            if _clean_git_commit(root) != commit:
                raise RuntimeError("lab Git commit changed during O1C-0013")
            if current_source_hashes() != source_hashes:
                raise RuntimeError("lab source hashes changed during O1C-0013")
            if set(result.final_artifacts) & set(persisted_artifacts):
                raise RuntimeError("O1C-0013 final artifact paths overlap freezes")
            persist_group(result.final_artifacts, phase="post-reveal-evaluation")

            module_metrics = result.metrics()
            module_resources = result.report["resources"]
            outcome_parent_cpu_seconds = (
                time.process_time() - outcome_parent_cpu_started
            )
            native_cpu_seconds = max(
                float(module_resources["native_cpu_seconds"]),
                float(module_resources["process_child_cpu_seconds"]),
            )
            total_cpu_seconds = max(
                float(module_metrics["cpu_seconds"]),
                outcome_parent_cpu_seconds + native_cpu_seconds,
            )
            total_wall_seconds = max(
                float(module_metrics["wall_seconds"]),
                time.monotonic() - outcome_wall_started,
            )
            peak_rss_mib = max(
                float(module_metrics["peak_rss_bytes"]) / (1024.0 * 1024.0),
                _peak_rss_mib(),
            )
            base_metrics = {
                **module_metrics,
                "module_budgeted_cpu_seconds": module_metrics["cpu_seconds"],
                "outcome_parent_cpu_seconds": outcome_parent_cpu_seconds,
                "native_cpu_seconds": native_cpu_seconds,
                "cpu_seconds": total_cpu_seconds,
                "module_wall_seconds": module_metrics["wall_seconds"],
                "wall_seconds": total_wall_seconds,
            }
            budget_checks = {
                "cpu": float(base_metrics["cpu_seconds"])
                <= calibration_config.budgets.maximum_cpu_seconds,
                "wall": float(base_metrics["wall_seconds"])
                <= calibration_config.budgets.maximum_wall_seconds,
                "resident_memory": peak_rss_mib
                <= calibration_config.budgets.maximum_resident_memory_mib,
                "persistent_artifacts": persistent_artifact_bytes
                <= calibration_config.budgets.maximum_persistent_artifact_bytes,
                "native_branches": int(base_metrics["native_solver_branches"])
                <= calibration_config.budgets.maximum_native_solver_branches,
                "causal_state": (
                    calibration_config.state_plan.serialized_state_bytes
                    <= calibration_config.maximum_state_bytes
                ),
                "live_target_state": int(base_metrics["live_target_state_bytes"])
                <= calibration_config.maximum_live_target_state_bytes,
                "fresh_targets": int(base_metrics["fresh_random_targets"])
                <= calibration_config.budgets.maximum_fresh_random_targets,
                "sibling_reads": int(base_metrics["sibling_reads"])
                <= calibration_config.budgets.maximum_sibling_reads,
                "sibling_writes": int(base_metrics["sibling_writes"])
                <= calibration_config.budgets.maximum_sibling_writes,
                "mps": int(base_metrics["mps_calls"])
                <= calibration_config.budgets.maximum_mps_calls,
                "gpu": int(base_metrics["gpu_calls"])
                <= calibration_config.budgets.maximum_gpu_calls,
            }
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            if failed_budgets:
                raise RuntimeError(
                    "O1C-0013 exceeded budgets: " + ", ".join(failed_budgets)
                )
            metrics = {
                **base_metrics,
                "peak_rss_mib": peak_rss_mib,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "persisted_artifact_count": len(persisted_artifacts),
                "reader_freeze_persisted_before_fresh_entropy": True,
                "prediction_set_persisted_before_reveal": True,
                "budget_checks": budget_checks,
            }
            run.checkpoint(
                {
                    "phase": "SEALED_TARGETS_REVEALED_ONCE_AND_RESULT_PERSISTED",
                    "result_sha256": result.report["result_sha256"],
                    "sealed_targets_revealed": (
                        calibration_config.corpus.sealed_targets
                    ),
                    "sealed_exact_keys": metrics["sealed_exact_keys"],
                    "sealed_compression_bits_per_key": metrics[
                        "sealed_compression_bits_per_key"
                    ],
                    "persistent_artifact_bytes": persistent_artifact_bytes,
                    "budget_checks": budget_checks,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
            )
            run.append_stdout(
                json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n"
            )
            finalized = run.finalize(metrics=metrics)
            process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-multikey-causal-calibration-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "reader_freeze_persisted": reader_frozen,
                "prediction_set_persisted": predictions_frozen,
                "fresh_target_state": (
                    "possibly-generated-after-reader-freeze"
                    if reader_frozen
                    else "not-generated-before-reader-freeze"
                ),
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the failed O1C-0013 capsule, fix the exact freeze, "
                "native, reader, or budget invariant under a new attempt ID, and "
                "never replay any sealed target from this attempt."
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
                "selected_arm": metrics["selected_arm"],
                "selected_logit_scale": metrics["selected_logit_scale"],
                "calibration_compression_bits_per_key": metrics[
                    "calibration_compression_bits_per_key"
                ],
                "sealed_compression_bits_per_key": metrics[
                    "sealed_compression_bits_per_key"
                ],
                "sealed_correct_bits": metrics["sealed_correct_bits"],
                "sealed_total_bits": metrics["sealed_total_bits"],
                "sealed_exact_keys": metrics["sealed_exact_keys"],
                "minimum_million_decoy_rank": metrics["minimum_million_decoy_rank"],
                "live_target_state_bytes": metrics["live_target_state_bytes"],
                "native_solver_branches": metrics["native_solver_branches"],
                "cpu_seconds": metrics["cpu_seconds"],
                "wall_seconds": metrics["wall_seconds"],
                "outcome_peak_rss_mib": metrics["peak_rss_mib"],
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "fresh_target_count": metrics["fresh_random_targets"],
                "fresh_targets_revealed": True,
                "sibling_writes": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _full256_frozen_reader_replication(args: argparse.Namespace) -> int:
    from .full256_frozen_reader_replication import (
        load_full256_frozen_reader_replication_config,
        run_full256_frozen_reader_replication,
    )

    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 frozen-reader config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (
        root / "configs/full256_frozen_reader_replication_v1.json"
    ).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError(
            "full-256 frozen-reader replication requires its canonical lab config"
        )
    top_level, replication_config = load_full256_frozen_reader_replication_config(
        config_path
    )
    runs_root = (root / "runs").resolve(strict=True)

    def pinned_source_hashes() -> dict[str, str]:
        hashes: dict[str, str] = {}

        def collect(node: object, prefix: str) -> None:
            if not isinstance(node, Mapping):
                return
            capsule_value = node.get("capsule")
            if capsule_value is not None:
                capsule = (root / str(capsule_value)).resolve(strict=True)
                if (
                    capsule.parent != runs_root
                    or capsule.name.startswith(".")
                    or not capsule.is_dir()
                ):
                    raise RuntimeError(
                        "O1C-0014 sources must be finalized run capsules"
                    )
                manifest = (capsule / "artifacts.sha256").resolve(strict=True)
                manifest_sha256 = _sha256(manifest)
                expected_manifest = node.get("manifest_sha256")
                if (
                    expected_manifest is not None
                    and manifest_sha256 != expected_manifest
                ):
                    raise RuntimeError(f"O1C-0014 pinned {prefix}manifest differs")
                hashes[f"{prefix}manifest"] = manifest_sha256
                for key, value in sorted(node.items()):
                    expected_key = f"{key}_sha256"
                    if (
                        key == "capsule"
                        or not isinstance(value, str)
                        or expected_key not in node
                    ):
                        continue
                    path = (capsule / value).resolve(strict=True)
                    if not path.is_relative_to(capsule) or not path.is_file():
                        raise RuntimeError(
                            f"O1C-0014 pinned {prefix}{key} escapes its capsule"
                        )
                    actual = _sha256(path)
                    if actual != node[expected_key]:
                        raise RuntimeError(f"O1C-0014 pinned {prefix}{key} differs")
                    hashes[f"{prefix}{key}"] = actual
            for key, value in sorted(node.items()):
                if isinstance(value, Mapping):
                    collect(value, f"{prefix}{key}_")

        collect(top_level["source"], "source_")
        return hashes

    native_header = (
        Path(replication_config.native.include_directory) / "cadical.hpp"
    ).resolve(strict=True)
    native_library = Path(replication_config.native.static_library).resolve(strict=True)
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

    def current_source_hashes() -> dict[str, str]:
        native_header_sha256 = _sha256(native_header)
        native_library_sha256 = _sha256(native_library)
        if native_header_sha256 != replication_config.native.cadical_header_sha256:
            raise RuntimeError("O1C-0014 pinned native CaDiCaL header differs")
        if native_library_sha256 != replication_config.native.cadical_library_sha256:
            raise RuntimeError("O1C-0014 pinned native CaDiCaL library differs")
        return {
            "frozen_reader_replication_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "native_pair_sensor": _sha256(root / "native/cadical_pair_sensor.cpp"),
            "native_tracer_header": _sha256(root / "native/cadical_tracer_3_0_0.hpp"),
            "native_cadical_header": native_header_sha256,
            "native_cadical_library": native_library_sha256,
            **pinned_source_hashes(),
            **{
                f"module_{Path(name).stem}": _sha256(root / "src/o1_crypto_lab" / name)
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    attempt_id = str(top_level["attempt_id"])
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-frozen-reader-replication-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "fresh_target_state": "unknown-after-hard-interruption",
                "sibling_reads": 0,
                "sibling_writes": 0,
            },
            status="stopped",
            next_action=(
                "Preserve the partial O1C-0014 capsule, never replay its sealed "
                "targets, and advance the frozen-reader replication under a new "
                "attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0014 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0014 reservation")
    planned_sweeps = replication_config.corpus.sealed_targets + len(
        replication_config.controls.transforms
    )
    planned_native_branches = planned_sweeps * (
        512 + 2 * replication_config.probe.sentinel_reruns_per_sweep
    )
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "full256-frozen-reader-replication",
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "target_internal_trace_inputs": 0,
            "accelerator": "none",
            "native_solver": "cadical-3.0.0-single-threaded-fork-cow",
            "planned_native_solver_branches": planned_native_branches,
            "causal_state_bytes": replication_config.state_plan.serialized_state_bytes,
            "maximum_live_target_state_bytes": (
                replication_config.maximum_live_target_state_bytes
            ),
            "planned_sealed_targets": replication_config.corpus.sealed_targets,
            "reader_retrained": False,
            "fresh_target_generated_at_reservation": False,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted_artifacts: dict[str, dict[str, object]] = {}
    persistent_artifact_bytes = 0
    protocol_frozen = False
    predictions_frozen = False
    outcome_parent_cpu_started = time.process_time()
    outcome_wall_started = time.monotonic()

    def persist_group(artifacts: Mapping[str, bytes], *, phase: str) -> None:
        nonlocal persistent_artifact_bytes
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise RuntimeError(f"O1C-0014 {phase} artifact group differs")
        group_bytes = 0
        for relative, payload in artifacts.items():
            if (
                not isinstance(relative, str)
                or not relative
                or not isinstance(payload, bytes)
                or relative in persisted_artifacts
            ):
                raise RuntimeError(f"O1C-0014 {phase} artifact entry differs")
            group_bytes += len(payload)
        if (
            persistent_artifact_bytes + group_bytes
            > replication_config.budgets.maximum_persistent_artifact_bytes
        ):
            raise RuntimeError("O1C-0014 would exceed its artifact-byte budget")
        for relative, payload in sorted(artifacts.items()):
            path = run.write_artifact(relative, payload)
            expected_sha256 = hashlib.sha256(payload).hexdigest()
            if _sha256(path) != expected_sha256 or path.stat().st_size != len(payload):
                raise RuntimeError(f"persisted O1C-0014 {phase} artifact differs")
            persisted_artifacts[relative] = {
                "sha256": expected_sha256,
                "bytes": len(payload),
                "phase": phase,
            }
        persistent_artifact_bytes += group_bytes

    def document_is_persisted(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> bool:
        expected = dict(document)
        for relative, payload in artifacts.items():
            if not relative.endswith(".json"):
                continue
            try:
                if json.loads(payload) == expected:
                    return True
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        return False

    def on_protocol_frozen(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal protocol_frozen
        if protocol_frozen or predictions_frozen:
            raise RuntimeError("O1C-0014 protocol freeze callback order differs")
        if (
            document.get("phase")
            != "FROZEN_PROTOCOL_VERIFIED_BEFORE_FRESH_TARGET_ENTROPY"
            or document.get("fresh_target_entropy_calls") != 0
            or not document_is_persisted(artifacts, document)
        ):
            raise RuntimeError("O1C-0014 protocol freeze document differs")
        persist_group(artifacts, phase="protocol-freeze")
        protocol_frozen = True
        run.checkpoint(
            {
                "phase": "FROZEN_PROTOCOL_PERSISTED_BEFORE_FRESH_ENTROPY",
                "protocol_freeze_sha256": document.get("protocol_freeze_sha256"),
                "reader_freeze_sha256": document.get("reader_freeze_sha256"),
                "fresh_target_entropy_calls": 0,
                "fresh_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def on_predictions_frozen(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal predictions_frozen
        sealed_targets = document.get("sealed_targets")
        if (
            not protocol_frozen
            or predictions_frozen
            or document.get("phase") != "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            or not document_is_persisted(artifacts, document)
            or not isinstance(sealed_targets, list)
            or len(sealed_targets) != replication_config.corpus.sealed_targets
        ):
            raise RuntimeError("O1C-0014 prediction freeze document differs")
        persist_group(artifacts, phase="prediction-freeze")
        predictions_frozen = True
        run.checkpoint(
            {
                "phase": "ALL_PREDICTION_ARTIFACTS_PERSISTED_BEFORE_ANY_REVEAL",
                "protocol_freeze_sha256": document.get("protocol_freeze_sha256"),
                "prediction_set_sha256": document.get("prediction_set_sha256"),
                "sealed_prediction_count": len(sealed_targets),
                "sealed_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    try:
        run.checkpoint(
            {
                "phase": "FULL256_FROZEN_READER_REPLICATION_RESERVED",
                "unknown_target_key_bits": 256,
                "rounds": 20,
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "sealed_targets_created": 0,
                "sealed_targets_revealed": 0,
                "planned_native_solver_branches": planned_native_branches,
                "reader_retrained": False,
                "protocol_frozen": False,
                "predictions_frozen": False,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0014 frozen-reader full-256 blind replication started.\n"
        )
        with tempfile.TemporaryDirectory(
            prefix="o1c0014-frozen-reader-", dir="/tmp"
        ) as temporary:
            result = run_full256_frozen_reader_replication(
                replication_config,
                lab_root=root,
                working_directory=temporary,
                on_protocol_frozen=on_protocol_frozen,
                on_predictions_frozen=on_predictions_frozen,
            )
            if not protocol_frozen or not predictions_frozen:
                raise RuntimeError(
                    "O1C-0014 freeze callbacks did not complete before reveal"
                )
            if not result.success_gate_passed:
                raise RuntimeError("O1C-0014 mandatory lifecycle gate failed")
            if _clean_git_commit(root) != commit:
                raise RuntimeError("lab Git commit changed during O1C-0014")
            if current_source_hashes() != source_hashes:
                raise RuntimeError("lab source hashes changed during O1C-0014")
            if set(result.final_artifacts) & set(persisted_artifacts):
                raise RuntimeError("O1C-0014 final artifact paths overlap freezes")
            persist_group(result.final_artifacts, phase="post-reveal-evaluation")

            module_metrics = result.metrics()
            module_resources = result.report["resources"]
            outcome_parent_cpu_seconds = (
                time.process_time() - outcome_parent_cpu_started
            )
            native_cpu_seconds = max(
                float(module_resources["native_cpu_seconds"]),
                float(module_resources["process_child_cpu_seconds"]),
            )
            total_cpu_seconds = max(
                float(module_metrics["cpu_seconds"]),
                outcome_parent_cpu_seconds + native_cpu_seconds,
            )
            total_wall_seconds = max(
                float(module_metrics["wall_seconds"]),
                time.monotonic() - outcome_wall_started,
            )
            peak_rss_mib = max(
                float(module_metrics["peak_rss_bytes"]) / (1024.0 * 1024.0),
                _peak_rss_mib(),
            )
            base_metrics = {
                **module_metrics,
                "module_budgeted_cpu_seconds": module_metrics["cpu_seconds"],
                "outcome_parent_cpu_seconds": outcome_parent_cpu_seconds,
                "native_cpu_seconds": native_cpu_seconds,
                "cpu_seconds": total_cpu_seconds,
                "module_wall_seconds": module_metrics["wall_seconds"],
                "wall_seconds": total_wall_seconds,
            }
            budget_checks = {
                "cpu": total_cpu_seconds
                <= replication_config.budgets.maximum_cpu_seconds,
                "wall": total_wall_seconds
                <= replication_config.budgets.maximum_wall_seconds,
                "resident_memory": peak_rss_mib
                <= replication_config.budgets.maximum_resident_memory_mib,
                "persistent_artifacts": persistent_artifact_bytes
                <= replication_config.budgets.maximum_persistent_artifact_bytes,
                "native_branches": int(base_metrics["native_solver_branches"])
                <= replication_config.budgets.maximum_native_solver_branches,
                "causal_state": replication_config.state_plan.serialized_state_bytes
                <= replication_config.maximum_state_bytes,
                "live_target_state": int(base_metrics["live_target_state_bytes"])
                <= replication_config.maximum_live_target_state_bytes,
                "fresh_targets": int(base_metrics["fresh_random_targets"])
                <= replication_config.budgets.maximum_fresh_random_targets,
                "sibling_reads": int(base_metrics["sibling_reads"])
                <= replication_config.budgets.maximum_sibling_reads,
                "sibling_writes": int(base_metrics["sibling_writes"])
                <= replication_config.budgets.maximum_sibling_writes,
                "mps": int(base_metrics["mps_calls"])
                <= replication_config.budgets.maximum_mps_calls,
                "gpu": int(base_metrics["gpu_calls"])
                <= replication_config.budgets.maximum_gpu_calls,
            }
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            if failed_budgets:
                raise RuntimeError(
                    "O1C-0014 exceeded budgets: " + ", ".join(failed_budgets)
                )
            metrics = {
                **base_metrics,
                "peak_rss_mib": peak_rss_mib,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "persisted_artifact_count": len(persisted_artifacts),
                "protocol_freeze_persisted_before_fresh_entropy": True,
                "prediction_set_persisted_before_reveal": True,
                "budget_checks": budget_checks,
            }
            run.checkpoint(
                {
                    "phase": "SEALED_TARGETS_REVEALED_ONCE_AND_RESULT_PERSISTED",
                    "result_sha256": result.report["result_sha256"],
                    "sealed_targets_revealed": replication_config.corpus.sealed_targets,
                    "sealed_exact_keys": metrics.get("sealed_exact_keys"),
                    "sealed_compression_bits_per_key": metrics.get(
                        "sealed_compression_bits_per_key"
                    ),
                    "persistent_artifact_bytes": persistent_artifact_bytes,
                    "budget_checks": budget_checks,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
            )
            run.append_stdout(
                json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n"
            )
            finalized = run.finalize(metrics=metrics)
            process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-frozen-reader-replication-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "protocol_freeze_persisted": protocol_frozen,
                "prediction_set_persisted": predictions_frozen,
                "fresh_target_state": (
                    "possibly-generated-after-protocol-freeze"
                    if protocol_frozen
                    else "not-generated-before-protocol-freeze"
                ),
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the failed O1C-0014 capsule, fix the exact protocol, "
                "native, reader, or budget invariant under a new attempt ID, and "
                "never replay any sealed target from this attempt."
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
                "sealed_compression_bits_per_key": metrics.get(
                    "sealed_compression_bits_per_key"
                ),
                "sealed_correct_bits": metrics.get("sealed_correct_bits"),
                "sealed_total_bits": metrics.get("sealed_total_bits"),
                "sealed_exact_keys": metrics.get("sealed_exact_keys"),
                "positive_target_count": metrics.get("positive_target_count"),
                "minimum_million_decoy_rank": metrics.get("minimum_million_decoy_rank"),
                "live_target_state_bytes": metrics.get("live_target_state_bytes"),
                "native_solver_branches": metrics.get("native_solver_branches"),
                "cpu_seconds": metrics.get("cpu_seconds"),
                "wall_seconds": metrics.get("wall_seconds"),
                "outcome_peak_rss_mib": metrics.get("peak_rss_mib"),
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "fresh_target_count": metrics.get("fresh_random_targets"),
                "fresh_targets_revealed": True,
                "reader_retrained": False,
                "sibling_writes": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _full256_online_self_discovery(args: argparse.Namespace) -> int:
    root = _lab_root()
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 online self-discovery config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (root / "configs/full256_online_self_discovery_v1.json").resolve(
        strict=True
    )
    if config_path != expected_config:
        raise RuntimeError(
            "full-256 online self-discovery requires its canonical lab config"
        )
    top_level, experiment, budgets = load_online_self_discovery_config(config_path)
    attempt_id = str(top_level["attempt_id"])
    if attempt_id != "O1C-0017":
        raise RuntimeError("online self-discovery attempt identity differs")

    participating = (
        "cadical_sensor.py",
        "chacha_trace.py",
        "cli.py",
        "full256_action_pool.py",
        "living_inverse.py",
        "o1_streaming_core.py",
        "online_causal_controller.py",
        "online_self_discovery.py",
        "orchestrator.py",
        "run_capsule.py",
        "types.py",
    )

    def current_source_hashes() -> dict[str, str]:
        return {
            "online_self_discovery_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            **{
                f"module_{Path(name).stem}": _sha256(root / "src/o1_crypto_lab" / name)
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-online-self-discovery-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "evaluation_labels_scored": "unknown-after-hard-interruption",
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            },
            status="stopped",
            next_action=(
                "Preserve the partial O1C-0017 mechanism capsule, do not replay "
                "the consumed attempt identity, and advance the identical frozen "
                "protocol under a new attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    expected_action_observations = (
        experiment.train_targets * 256 * 2 * 3
        + experiment.evaluation_targets * 256 * 4
        + 2 * 256
    )
    zero_budget_fields = (
        "maximum_fresh_entropy_calls",
        "maximum_sibling_reads",
        "maximum_sibling_writes",
        "maximum_mps_calls",
        "maximum_gpu_calls",
    )
    if expected_action_observations != budgets.maximum_action_observations or any(
        getattr(budgets, field) != 0 for field in zero_budget_fields
    ):
        raise RuntimeError("O1C-0017 fixed execution accounting differs")

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError("lab Git commit changed before O1C-0017 reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError("lab source hashes changed before O1C-0017 reservation")

    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            "full256-online-self-discovery",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "synthetic-full-256-mechanism-gate",
            "cryptographic_inverse_claim": False,
            "controller_receives_hidden_channel_index": False,
            "planned_action_observations": expected_action_observations,
            "planned_train_targets": experiment.train_targets,
            "planned_evaluation_targets": experiment.evaluation_targets,
            "accelerator": "none",
            "fresh_entropy_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted_artifacts: dict[str, dict[str, object]] = {}
    persistent_artifact_bytes = 0
    predictions_frozen = False
    frozen_prediction_sha256 = ""
    scoring_completed = False
    result_artifacts_persisted = False
    outcome_cpu_started = time.process_time()
    outcome_wall_started = time.monotonic()

    def json_bytes(value: object) -> bytes:
        return (
            json.dumps(
                value,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")

    def persist_group(artifacts: Mapping[str, bytes], *, phase: str) -> None:
        nonlocal persistent_artifact_bytes
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise RuntimeError(f"O1C-0017 {phase} artifact group differs")
        group_bytes = 0
        for relative, payload in artifacts.items():
            if (
                not isinstance(relative, str)
                or not relative
                or not isinstance(payload, bytes)
                or relative in persisted_artifacts
            ):
                raise RuntimeError(f"O1C-0017 {phase} artifact entry differs")
            group_bytes += len(payload)
        if (
            persistent_artifact_bytes + group_bytes
            > budgets.maximum_persistent_artifact_bytes
        ):
            raise RuntimeError("O1C-0017 would exceed its artifact-byte budget")
        for relative, payload in sorted(artifacts.items()):
            path = run.write_artifact(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            if _sha256(path) != digest or path.stat().st_size != len(payload):
                raise RuntimeError(f"persisted O1C-0017 {phase} artifact differs")
            persisted_artifacts[relative] = {
                "sha256": digest,
                "bytes": len(payload),
                "phase": phase,
            }
            persistent_artifact_bytes += len(payload)

    def on_predictions_frozen(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal frozen_prediction_sha256, predictions_frozen
        if predictions_frozen or set(artifacts) != {
            "prediction_freeze.json",
            "predictions.f32le",
        }:
            raise RuntimeError("O1C-0017 prediction-freeze artifact set differs")
        try:
            persisted_document = json.loads(artifacts["prediction_freeze.json"])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("O1C-0017 prediction-freeze JSON differs") from exc
        prediction_bytes = artifacts["predictions.f32le"]
        if (
            dict(document) != persisted_document
            or document.get("phase")
            != "ALL_SYNTHETIC_PREDICTIONS_FROZEN_BEFORE_SCORING"
            or document.get("evaluation_targets") != experiment.evaluation_targets
            or document.get("labels_exposed_to_controllers") != 0
            or document.get("controller_receives_hidden_channel_index") is not False
            or document.get("fresh_entropy_calls") != 0
            or document.get("prediction_bytes") != len(prediction_bytes)
            or len(prediction_bytes)
            != len(PREDICTION_ARMS) * experiment.evaluation_targets * 256 * 4
            or document.get("prediction_sha256")
            != hashlib.sha256(prediction_bytes).hexdigest()
        ):
            raise RuntimeError("O1C-0017 prediction-freeze document differs")
        persist_group(artifacts, phase="prediction-freeze-before-scoring")
        frozen_prediction_sha256 = hashlib.sha256(prediction_bytes).hexdigest()
        predictions_frozen = True
        run.checkpoint(
            {
                "phase": "ALL_O1C0017_PREDICTIONS_PERSISTED_BEFORE_SCORING",
                "prediction_sha256": document.get("prediction_sha256"),
                "freeze_sha256": document.get("freeze_sha256"),
                "evaluation_targets": experiment.evaluation_targets,
                "evaluation_labels_scored": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    try:
        run.checkpoint(
            {
                "phase": "FULL256_ONLINE_SELF_DISCOVERY_RESERVED",
                "synthetic_key_bits": 256,
                "planned_action_observations": expected_action_observations,
                "planned_train_targets": experiment.train_targets,
                "planned_evaluation_targets": experiment.evaluation_targets,
                "predictions_frozen": False,
                "evaluation_labels_scored": 0,
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0017 full-256 synthetic online self-discovery gate started.\n"
        )
        result = run_online_self_discovery(
            experiment,
            on_predictions_frozen=on_predictions_frozen,
        )
        if not predictions_frozen:
            raise RuntimeError("O1C-0017 predictions were not persisted before scoring")
        scoring_completed = True

        commitments = result.report["artifact_commitments"]
        if (
            hashlib.sha256(result.prediction_bytes()).hexdigest()
            != frozen_prediction_sha256
            or commitments["prediction_sha256"] != frozen_prediction_sha256
            or commitments["label_sha256"]
            != hashlib.sha256(result.label_bytes()).hexdigest()
            or commitments["compression_sha256"]
            != hashlib.sha256(result.compression_bytes()).hexdigest()
            or commitments["primary_slow_state_sha256"]
            != hashlib.sha256(result.primary_slow_state).hexdigest()
            or commitments["shuffled_slow_state_sha256"]
            != hashlib.sha256(result.shuffled_slow_state).hexdigest()
            or commitments["representative_fast_state_sha256"]
            != hashlib.sha256(result.representative_fast_state).hexdigest()
        ):
            raise RuntimeError("O1C-0017 result artifact commitment differs")

        final_artifacts = {
            "online_self_discovery.json": json_bytes(result.report),
            "labels.bitpack": result.label_bytes(),
            "compressions.f64le": result.compression_bytes(),
            "primary_slow_state.bin": result.primary_slow_state,
            "shuffled_slow_state.bin": result.shuffled_slow_state,
            "representative_fast_state.bin": result.representative_fast_state,
        }
        persist_group(final_artifacts, phase="post-freeze-scored-result")
        result_artifacts_persisted = True
        artifact_index = {
            "schema": "o1-256-online-self-discovery-artifact-index-v1",
            "attempt_id": attempt_id,
            "artifacts": dict(sorted(persisted_artifacts.items())),
            "indexed_artifact_count": len(persisted_artifacts),
            "indexed_artifact_bytes": persistent_artifact_bytes,
            "artifact_index_self_entry": False,
            "artifact_index_self_exclusion_reason": (
                "the capsule manifest binds this index without a recursive hash"
            ),
        }
        persist_group(
            {"artifact_index.json": json_bytes(artifact_index)},
            phase="artifact-index",
        )

        if _clean_git_commit(root) != commit:
            raise RuntimeError("lab Git commit changed during O1C-0017")
        if current_source_hashes() != source_hashes:
            raise RuntimeError("lab source hashes changed during O1C-0017")

        resources = result.report["resources"]
        static_accounting = result.report["static_accounting"]
        actual_action_observations = int(
            static_accounting["train_action_observations"]
        ) + int(static_accounting["evaluation_action_observations"])
        total_cpu_seconds = max(
            float(resources["cpu_seconds"]),
            time.process_time() - outcome_cpu_started,
        )
        total_wall_seconds = max(
            float(resources["wall_seconds"]),
            time.monotonic() - outcome_wall_started,
        )
        peak_rss_bytes = max(
            int(resources["process_peak_rss_bytes"]),
            int(_peak_rss_mib() * 1024 * 1024),
        )
        zero_accounting = {
            "fresh_entropy": int(resources["fresh_entropy_calls"]) == 0,
            "sibling_reads": int(resources["sibling_reads"]) == 0,
            "sibling_writes": int(resources["sibling_writes"]) == 0,
            "mps": int(resources["mps_calls"]) == 0,
            "gpu": int(resources["gpu_calls"]) == 0,
            "native_solver_branches": int(resources["native_solver_branches"]) == 0,
        }
        budget_checks = {
            "cpu": total_cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": total_wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_artifact_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "action_observations": actual_action_observations
            == expected_action_observations
            and actual_action_observations <= budgets.maximum_action_observations,
            **zero_accounting,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        outcome_failed = bool(failed_budgets) or not result.success_gate_passed
        metrics = {
            "schema": "o1-256-online-self-discovery-cli-result-v1",
            "classification": result.report["classification"],
            "claim_boundary": result.report["claim_boundary"],
            "result_sha256": result.report["result_sha256"],
            "scientific_gates": result.report["gates"],
            "scientific_success_gate_passed": result.success_gate_passed,
            "arms": result.report["arms"],
            "margins": result.report["margins"],
            "cpu_seconds": total_cpu_seconds,
            "wall_seconds": total_wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_mib": peak_rss_bytes / (1024.0 * 1024.0),
            "persistent_artifact_bytes": persistent_artifact_bytes,
            "persisted_artifact_count": len(persisted_artifacts),
            "action_observations": actual_action_observations,
            "planned_action_observations": expected_action_observations,
            "predictions_persisted_before_scoring": True,
            "evaluation_labels_scored": experiment.evaluation_targets,
            "fresh_entropy_calls": int(resources["fresh_entropy_calls"]),
            "sibling_reads": int(resources["sibling_reads"]),
            "sibling_writes": int(resources["sibling_writes"]),
            "mps_calls": int(resources["mps_calls"]),
            "gpu_calls": int(resources["gpu_calls"]),
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "outcome_failed": outcome_failed,
            "failure_reasons": [
                *(f"cli_budget:{name}" for name in failed_budgets),
                *(
                    ["scientific_success_gate_failed"]
                    if not result.success_gate_passed
                    else []
                ),
            ],
        }
        run.checkpoint(
            {
                "phase": "O1C0017_SCORED_ARTIFACTS_PERSISTED",
                "result_sha256": result.report["result_sha256"],
                "scientific_success_gate_passed": result.success_gate_passed,
                "failed_budgets": failed_budgets,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "evaluation_labels_scored": experiment.evaluation_targets,
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="failed" if outcome_failed else "completed",
        )
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-online-self-discovery-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "predictions_persisted_before_scoring": predictions_frozen,
                "evaluation_scoring_completed": scoring_completed,
                "result_artifacts_persisted": result_artifacts_persisted,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "persisted_artifact_count": len(persisted_artifacts),
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve the O1C-0017 failure capsule and its frozen predictions; "
                "fix the exact lifecycle, accounting, or persistence invariant "
                "under a new attempt ID without replaying this attempt."
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
                "capsule_status": "failed" if outcome_failed else "completed",
                "scientific_success_gate_passed": result.success_gate_passed,
                "classification": result.report["classification"],
                "primary_mean_compression_bits": result.report["arms"][
                    "primary_learned"
                ]["mean_compression_bits"],
                "primary_bit_accuracy": result.report["arms"]["primary_learned"][
                    "bit_accuracy"
                ],
                "failed_budgets": failed_budgets,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "action_observations": actual_action_observations,
                "fresh_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if outcome_failed else 0


def _full256_polyphase_replication(args: argparse.Namespace) -> int:
    from .full256_polyphase_replication import (
        load_full256_polyphase_replication_config,
        run_full256_polyphase_replication,
    )

    root = _lab_root()
    canonical_config_name = getattr(
        args,
        "polyphase_canonical_config",
        "full256_polyphase_replication_v1.json",
    )
    expected_attempt_id = getattr(args, "polyphase_attempt_id", "O1C-0015")
    command_name = getattr(
        args,
        "polyphase_command_name",
        "full256-polyphase-replication",
    )
    requested_config = args.config
    if requested_config.is_symlink():
        raise RuntimeError("full-256 polyphase config cannot be a symlink")
    config_path = requested_config.resolve(strict=True)
    expected_config = (root / "configs" / canonical_config_name).resolve(strict=True)
    if config_path != expected_config:
        raise RuntimeError(
            "full-256 polyphase replication requires its canonical lab config"
        )
    top_level, replication_config = load_full256_polyphase_replication_config(
        config_path
    )
    attempt_id = str(top_level["attempt_id"])
    if attempt_id != expected_attempt_id:
        raise RuntimeError(
            "full-256 polyphase replication attempt identity differs from its "
            "canonical CLI path"
        )
    attempt_token = attempt_id.lower().replace("-", "")
    runs_root = (root / "runs").resolve(strict=True)

    def pinned_source_hashes() -> dict[str, str]:
        hashes: dict[str, str] = {}

        def collect(node: object, prefix: str) -> None:
            if not isinstance(node, Mapping):
                return
            capsule_value = node.get("capsule")
            if capsule_value is not None:
                capsule = (root / str(capsule_value)).resolve(strict=True)
                if (
                    capsule.parent != runs_root
                    or capsule.name.startswith(".")
                    or not capsule.is_dir()
                ):
                    raise RuntimeError(
                        f"{attempt_id} sources must be finalized run capsules"
                    )
                manifest = (capsule / "artifacts.sha256").resolve(strict=True)
                manifest_sha256 = _sha256(manifest)
                expected_manifest = node.get("manifest_sha256")
                if (
                    expected_manifest is not None
                    and manifest_sha256 != expected_manifest
                ):
                    raise RuntimeError(f"{attempt_id} pinned {prefix}manifest differs")
                hashes[f"{prefix}manifest"] = manifest_sha256
                for key, value in sorted(node.items()):
                    expected_key = f"{key}_sha256"
                    if (
                        key == "capsule"
                        or not isinstance(value, str)
                        or expected_key not in node
                    ):
                        continue
                    path = (capsule / value).resolve(strict=True)
                    if not path.is_relative_to(capsule) or not path.is_file():
                        raise RuntimeError(
                            f"{attempt_id} pinned {prefix}{key} escapes its capsule"
                        )
                    actual = _sha256(path)
                    if actual != node[expected_key]:
                        raise RuntimeError(f"{attempt_id} pinned {prefix}{key} differs")
                    hashes[f"{prefix}{key}"] = actual
            for key, value in sorted(node.items()):
                if isinstance(value, Mapping):
                    collect(value, f"{prefix}{key}_")

        collect(top_level["source"], "source_")
        collect(top_level["design_lineage"], "design_lineage_")
        return hashes

    native_header = (
        Path(replication_config.native.include_directory) / "cadical.hpp"
    ).resolve(strict=True)
    native_library = Path(replication_config.native.static_library).resolve(strict=True)
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

    def current_source_hashes() -> dict[str, str]:
        native_header_sha256 = _sha256(native_header)
        native_library_sha256 = _sha256(native_library)
        if native_header_sha256 != replication_config.native.cadical_header_sha256:
            raise RuntimeError(f"{attempt_id} pinned native CaDiCaL header differs")
        if native_library_sha256 != replication_config.native.cadical_library_sha256:
            raise RuntimeError(f"{attempt_id} pinned native CaDiCaL library differs")
        return {
            "polyphase_replication_config": _sha256(config_path),
            "pyproject": _sha256(root / "pyproject.toml"),
            "native_pair_sensor": _sha256(root / "native/cadical_pair_sensor.cpp"),
            "native_tracer_header": _sha256(root / "native/cadical_tracer_3_0_0.hpp"),
            "native_cadical_header": native_header_sha256,
            "native_cadical_library": native_library_sha256,
            **pinned_source_hashes(),
            **{
                f"module_{Path(name).stem}": _sha256(root / "src/o1_crypto_lab" / name)
                for name in participating
            },
        }

    manager = RunCapsuleManager(root)
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
        metrics_document = json.loads(
            (published.path / "metrics.json").read_text(encoding="utf-8")
        )
        print(
            json.dumps(
                {
                    "attempt_id": published.attempt_id,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics_document.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics_document.get("status") == "completed" else 2
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": "o1-256-polyphase-replication-interrupted-v1",
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
                "unknown_target_key_bits": 256,
                "fresh_target_state": "unknown-after-hard-interruption",
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            },
            status="stopped",
            next_action=(
                f"Preserve the partial {attempt_id} capsule, never replay its sealed "
                "targets, and advance the polyphase replication under a new "
                "attempt ID."
            ),
        )
        print(
            json.dumps(
                {
                    "attempt_id": finalized.attempt_id,
                    "path": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "verified": finalized.verification.ok,
                    "status": "stopped-after-hard-interruption",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    commit = _clean_git_commit(root)
    source_hashes = current_source_hashes()
    if _clean_git_commit(root) != commit:
        raise RuntimeError(f"lab Git commit changed before {attempt_id} reservation")
    if current_source_hashes() != source_hashes:
        raise RuntimeError(f"lab source hashes changed before {attempt_id} reservation")
    planned_sweeps = replication_config.corpus.sealed_targets + len(
        replication_config.controls.transforms
    )
    planned_native_branches = planned_sweeps * (
        512 + 2 * replication_config.probe.sentinel_reruns_per_sweep
    )
    if (
        replication_config.corpus.sealed_targets != 32
        or len(replication_config.controls.transforms) != 3
        or planned_sweeps != 35
        or planned_native_branches != 17_920
        or replication_config.budgets.maximum_native_solver_branches != 17_920
        or replication_config.budgets.maximum_fresh_random_targets != 32
        or replication_config.budgets.maximum_sibling_reads != 0
        or replication_config.budgets.maximum_sibling_writes != 0
        or replication_config.budgets.maximum_mps_calls != 0
        or replication_config.budgets.maximum_gpu_calls != 0
    ):
        raise RuntimeError(f"{attempt_id} fixed execution accounting differs")
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top_level["slug"]),
        commit=commit,
        hypothesis=str(top_level["hypothesis"]),
        prediction=str(top_level["prediction"]),
        controls=tuple(str(value) for value in top_level["controls"]),
        budgets=dict(top_level["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel(str(top_level["claim_level"])),
        next_action=str(top_level["next_action"]),
        config=top_level,
        command=(
            "o1-crypto-lab",
            command_name,
            "--config",
            str(config_path),
        ),
        environment={
            "target_contract": "all-256-bits-unknown-public-output-only",
            "target_rounds": 20,
            "target_internal_trace_inputs": 0,
            "accelerator": "none",
            "native_solver": "cadical-3.0.0-single-threaded-fork-cow",
            "planned_sweeps": planned_sweeps,
            "planned_native_solver_branches": planned_native_branches,
            "causal_state_bytes": replication_config.state_plan.serialized_state_bytes,
            "maximum_live_target_state_bytes": (
                replication_config.maximum_live_target_state_bytes
            ),
            "planned_sealed_targets": replication_config.corpus.sealed_targets,
            "planned_target_controls": len(replication_config.controls.transforms),
            "primary_h96_exact_o1c0013_bytes": True,
            "source_build_cal_reader_reconstructions": 3,
            "target_reader_refits": 0,
            "ensemble_logit_weights": list(
                replication_config.reader.ensemble_weights
            ),
            "o1c0014_design_lineage_usage": "hash-only-no-features-labels-or-fit",
            "fresh_target_generated_at_reservation": False,
            "mps_calls": 0,
            "gpu_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "outcome_bearing_execution_begins_after_attempt_reservation": True,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted_artifacts: dict[str, dict[str, object]] = {}
    persistent_artifact_bytes = 0
    protocol_frozen = False
    predictions_frozen = False
    post_reveal_persistence_started = False
    post_reveal_artifacts_persisted = False
    outcome_parent_cpu_started = time.process_time()
    outcome_wall_started = time.monotonic()

    def persist_group(
        artifacts: Mapping[str, bytes],
        *,
        phase: str,
        enforce_budget: bool = True,
    ) -> None:
        nonlocal persistent_artifact_bytes
        if not isinstance(artifacts, Mapping) or not artifacts:
            raise RuntimeError(f"{attempt_id} {phase} artifact group differs")
        group_bytes = 0
        for relative, payload in artifacts.items():
            if (
                not isinstance(relative, str)
                or not relative
                or not isinstance(payload, bytes)
                or relative in persisted_artifacts
            ):
                raise RuntimeError(f"{attempt_id} {phase} artifact entry differs")
            group_bytes += len(payload)
        if (
            enforce_budget
            and persistent_artifact_bytes + group_bytes
            > replication_config.budgets.maximum_persistent_artifact_bytes
        ):
            raise RuntimeError(f"{attempt_id} would exceed its artifact-byte budget")
        for relative, payload in sorted(artifacts.items()):
            path = run.write_artifact(relative, payload)
            expected_sha256 = hashlib.sha256(payload).hexdigest()
            if _sha256(path) != expected_sha256 or path.stat().st_size != len(payload):
                raise RuntimeError(f"persisted {attempt_id} {phase} artifact differs")
            persisted_artifacts[relative] = {
                "sha256": expected_sha256,
                "bytes": len(payload),
                "phase": phase,
            }
        persistent_artifact_bytes += group_bytes

    def document_is_persisted(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> bool:
        expected = dict(document)
        for relative, payload in artifacts.items():
            if not relative.endswith(".json"):
                continue
            try:
                if json.loads(payload) == expected:
                    return True
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        return False

    def on_protocol_frozen(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal protocol_frozen
        if protocol_frozen or predictions_frozen:
            raise RuntimeError(f"{attempt_id} protocol freeze callback order differs")
        if (
            document.get("phase")
            != "FROZEN_PROTOCOL_VERIFIED_BEFORE_FRESH_TARGET_ENTROPY"
            or document.get("fresh_target_entropy_calls") != 0
            or not document_is_persisted(artifacts, document)
        ):
            raise RuntimeError(f"{attempt_id} protocol freeze document differs")
        persist_group(artifacts, phase="protocol-freeze")
        protocol_frozen = True
        run.checkpoint(
            {
                "phase": "POLYPHASE_PROTOCOL_PERSISTED_BEFORE_FRESH_ENTROPY",
                "protocol_freeze_sha256": document.get("protocol_freeze_sha256"),
                "reader_freeze_sha256": document.get("reader_freeze_sha256"),
                "fresh_target_entropy_calls": 0,
                "fresh_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def on_predictions_frozen(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal predictions_frozen
        sealed_targets = document.get("sealed_targets")
        if (
            not protocol_frozen
            or predictions_frozen
            or document.get("phase") != "ALL_PREDICTIONS_FROZEN_BEFORE_ANY_REVEAL"
            or not document_is_persisted(artifacts, document)
            or not isinstance(sealed_targets, list)
            or len(sealed_targets) != 32
        ):
            raise RuntimeError(f"{attempt_id} prediction freeze document differs")
        persist_group(artifacts, phase="prediction-freeze")
        predictions_frozen = True
        run.checkpoint(
            {
                "phase": "ALL_POLYPHASE_PREDICTIONS_PERSISTED_BEFORE_ANY_REVEAL",
                "protocol_freeze_sha256": document.get("protocol_freeze_sha256"),
                "prediction_set_sha256": document.get("prediction_set_sha256"),
                "sealed_prediction_count": len(sealed_targets),
                "sealed_target_reveals": 0,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    try:
        run.checkpoint(
            {
                "phase": "FULL256_POLYPHASE_REPLICATION_RESERVED",
                "unknown_target_key_bits": 256,
                "rounds": 20,
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "sealed_targets_created": 0,
                "sealed_targets_revealed": 0,
                "planned_sweeps": planned_sweeps,
                "planned_native_solver_branches": planned_native_branches,
                "primary_h96_exact_o1c0013_bytes": True,
                "source_build_cal_reader_reconstructions": 3,
                "target_reader_refits": 0,
                "protocol_frozen": False,
                "predictions_frozen": False,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            f"{attempt_id} polyphase full-256 blind replication started.\n"
        )
        with tempfile.TemporaryDirectory(
            prefix=f"{attempt_token}-polyphase-", dir="/tmp"
        ) as temporary:
            result = run_full256_polyphase_replication(
                replication_config,
                lab_root=root,
                working_directory=temporary,
                on_protocol_frozen=on_protocol_frozen,
                on_predictions_frozen=on_predictions_frozen,
                attempt_id=attempt_id,
            )
            if not protocol_frozen or not predictions_frozen:
                raise RuntimeError(
                    f"{attempt_id} freeze callbacks did not complete before reveal"
                )
            # Once targets have been revealed, preserving their complete truth is
            # the first post-result action. The final budget and source gates below
            # can still mark the capsule failed without discarding those truths.
            post_reveal_persistence_started = True
            persist_group(
                result.final_artifacts,
                phase="post-reveal-evaluation",
                enforce_budget=False,
            )
            post_reveal_artifacts_persisted = True
            if _clean_git_commit(root) != commit:
                raise RuntimeError(f"lab Git commit changed during {attempt_id}")
            if current_source_hashes() != source_hashes:
                raise RuntimeError(f"lab source hashes changed during {attempt_id}")

            module_metrics = result.metrics()
            module_resources = result.report["resources"]
            if int(module_metrics["persistent_artifact_bytes"]) != (
                persistent_artifact_bytes
            ):
                raise RuntimeError(
                    f"{attempt_id} persistent artifact accounting differs"
                )
            h96_baseline_compression_bits_per_key = float(
                result.report["sealed_evaluation"]["h96_component"][
                    "compression_bits_per_key"
                ]
            )
            if (
                int(module_metrics["native_solver_branches"])
                != planned_native_branches
                or int(module_metrics["fresh_random_targets"]) != 32
                or int(module_metrics["live_target_state_bytes"])
                != replication_config.maximum_live_target_state_bytes
                or int(module_metrics["sibling_reads"]) != 0
                or int(module_metrics["sibling_writes"]) != 0
                or int(module_metrics["mps_calls"]) != 0
                or int(module_metrics["gpu_calls"]) != 0
            ):
                raise RuntimeError(f"{attempt_id} module fixed accounting differs")
            outcome_parent_cpu_seconds = (
                time.process_time() - outcome_parent_cpu_started
            )
            native_cpu_seconds = max(
                float(module_resources["native_cpu_seconds"]),
                float(module_resources["process_child_cpu_seconds"]),
            )
            total_cpu_seconds = max(
                float(module_metrics["cpu_seconds"]),
                outcome_parent_cpu_seconds + native_cpu_seconds,
            )
            total_wall_seconds = max(
                float(module_metrics["wall_seconds"]),
                time.monotonic() - outcome_wall_started,
            )
            peak_rss_mib = max(
                float(module_metrics["peak_rss_bytes"]) / (1024.0 * 1024.0),
                _peak_rss_mib(),
            )
            base_metrics = {
                **module_metrics,
                "h96_baseline_compression_bits_per_key": (
                    h96_baseline_compression_bits_per_key
                ),
                "module_budgeted_cpu_seconds": module_metrics["cpu_seconds"],
                "outcome_parent_cpu_seconds": outcome_parent_cpu_seconds,
                "native_cpu_seconds": native_cpu_seconds,
                "cpu_seconds": total_cpu_seconds,
                "module_wall_seconds": module_metrics["wall_seconds"],
                "wall_seconds": total_wall_seconds,
            }
            budget_checks = {
                "cpu": total_cpu_seconds
                <= replication_config.budgets.maximum_cpu_seconds,
                "wall": total_wall_seconds
                <= replication_config.budgets.maximum_wall_seconds,
                "resident_memory": peak_rss_mib
                <= replication_config.budgets.maximum_resident_memory_mib,
                "persistent_artifacts": persistent_artifact_bytes
                <= replication_config.budgets.maximum_persistent_artifact_bytes,
                "native_branches": int(base_metrics["native_solver_branches"])
                == planned_native_branches,
                "causal_state": replication_config.state_plan.serialized_state_bytes
                <= replication_config.maximum_state_bytes,
                "live_target_state": int(base_metrics["live_target_state_bytes"])
                == replication_config.maximum_live_target_state_bytes,
                "fresh_targets": int(base_metrics["fresh_random_targets"]) == 32,
                "sibling_reads": int(base_metrics["sibling_reads"]) == 0,
                "sibling_writes": int(base_metrics["sibling_writes"]) == 0,
                "mps": int(base_metrics["mps_calls"]) == 0,
                "gpu": int(base_metrics["gpu_calls"]) == 0,
            }
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            outcome_failed = bool(failed_budgets) or not result.success_gate_passed
            failure_reasons = [
                *(f"cli_budget:{name}" for name in failed_budgets),
                *(
                    ["module_success_gate_failed"]
                    if not result.success_gate_passed
                    else []
                ),
            ]
            metrics = {
                **base_metrics,
                "peak_rss_mib": peak_rss_mib,
                "persistent_artifact_bytes": persistent_artifact_bytes,
                "persisted_artifact_count": len(persisted_artifacts),
                "protocol_freeze_persisted_before_fresh_entropy": True,
                "prediction_set_persisted_before_reveal": True,
                "planned_sweeps": planned_sweeps,
                "planned_native_solver_branches": planned_native_branches,
                "budget_checks": budget_checks,
                "sealed_target_reveals": 32,
                "outcome_failed": outcome_failed,
                "failure_reasons": failure_reasons,
            }
            run.checkpoint(
                {
                    "phase": "POLYPHASE_TARGETS_REVEALED_ONCE_AND_RESULT_PERSISTED",
                    "result_sha256": result.report["result_sha256"],
                    "sealed_targets_revealed": 32,
                    "sealed_exact_keys": metrics.get("sealed_exact_keys"),
                    "sealed_compression_bits_per_key": metrics.get(
                        "sealed_compression_bits_per_key"
                    ),
                    "replication_classification": metrics.get(
                        "replication_classification"
                    ),
                    "architecture_promotion_classification": metrics.get(
                        "architecture_promotion_classification"
                    ),
                    "architecture_promotion_passed": metrics.get(
                        "architecture_promotion_passed"
                    ),
                    "h96_baseline_compression_bits_per_key": metrics.get(
                        "h96_baseline_compression_bits_per_key"
                    ),
                    "persistent_artifact_bytes": persistent_artifact_bytes,
                    "budget_checks": budget_checks,
                    "sibling_writes": 0,
                    "mps_calls": 0,
                    "gpu_calls": 0,
                }
            )
            run.append_stdout(
                json.dumps(metrics, sort_keys=True, allow_nan=False) + "\n"
            )
            finalized = run.finalize(
                metrics=metrics,
                status="failed" if outcome_failed else "completed",
                next_action=(
                    f"Preserve the complete {attempt_id} result and all 32 sealed "
                    "reveals; correct only the failed runtime or lifecycle invariant "
                    "under a new attempt ID and never replay these targets."
                    if outcome_failed
                    else None
                ),
            )
            process_peak_rss_mib = _peak_rss_mib()
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            print(
                json.dumps(
                    {
                        "attempt_id": finalized.attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": metrics_document.get("status"),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if metrics_document.get("status") == "completed" else 1
        pre_reveal_resource_failure = type(
            exc
        ).__name__ == "Full256PolyphaseReplicationError" and str(exc).startswith(
            "pre-reveal polyphase resource budget exceeded:"
        )
        generated_target_count: int | str = (
            32
            if predictions_frozen
            else "unknown-after-protocol-freeze"
            if protocol_frozen
            else 0
        )
        persisted_reveal_count = sum(
            relative.startswith("sealed/")
            and relative.endswith("/reveal.json")
            and metadata.get("phase") == "post-reveal-evaluation"
            for relative, metadata in persisted_artifacts.items()
        )
        persisted_post_reveal_artifact_count = sum(
            metadata.get("phase") == "post-reveal-evaluation"
            for metadata in persisted_artifacts.values()
        )
        actually_persisted_artifact_bytes = sum(
            int(metadata["bytes"]) for metadata in persisted_artifacts.values()
        )
        revealed_in_memory_count: int | str = (
            32
            if post_reveal_persistence_started
            else 0
            if not predictions_frozen or pre_reveal_resource_failure
            else "unknown-after-prediction-freeze"
        )
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": "o1-256-polyphase-replication-failure-v1",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "unknown_target_key_bits": 256,
                "protocol_freeze_persisted": protocol_frozen,
                "prediction_set_persisted": predictions_frozen,
                "generated_target_count": generated_target_count,
                "revealed_in_memory_count": revealed_in_memory_count,
                "persisted_reveal_count": persisted_reveal_count,
                "post_reveal_persistence_started": post_reveal_persistence_started,
                "post_reveal_artifacts_persisted": (
                    post_reveal_artifacts_persisted
                ),
                "persisted_post_reveal_artifact_count": (
                    persisted_post_reveal_artifact_count
                ),
                "actually_persisted_artifact_bytes": (
                    actually_persisted_artifact_bytes
                ),
                "fresh_target_state": (
                    "generated-32-predictions-frozen-zero-reveals"
                    if pre_reveal_resource_failure
                    else "generated-32-revealed-32-truth-persistence-started"
                    if post_reveal_persistence_started
                    else "possibly-generated-after-protocol-freeze"
                    if protocol_frozen
                    else "not-generated-before-protocol-freeze"
                ),
                "target_key_units": 0,
                "target_internal_trace_inputs": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
                "scientific_inverse_signal_claimed": False,
            },
            status="failed",
            next_action=(
                f"Preserve the failed {attempt_id} capsule, fix the exact protocol, "
                "source, reader, native, or budget invariant under a new attempt "
                "ID, and never replay any sealed target from this attempt."
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
                "replication_classification": metrics.get(
                    "replication_classification"
                ),
                "architecture_promotion_classification": metrics.get(
                    "architecture_promotion_classification"
                ),
                "architecture_promotion_passed": metrics.get(
                    "architecture_promotion_passed"
                ),
                "h96_baseline_compression_bits_per_key": metrics.get(
                    "h96_baseline_compression_bits_per_key"
                ),
                "ensemble_minus_h96_conditional_z_score": metrics.get(
                    "ensemble_minus_h96_conditional_z_score"
                ),
                "sealed_compression_bits_per_key": metrics.get(
                    "sealed_compression_bits_per_key"
                ),
                "sealed_correct_bits": metrics.get("sealed_correct_bits"),
                "sealed_total_bits": metrics.get("sealed_total_bits"),
                "sealed_exact_keys": metrics.get("sealed_exact_keys"),
                "positive_target_count": metrics.get("positive_target_count"),
                "conditional_null_z_score": metrics.get(
                    "conditional_null_z_score"
                ),
                "paired_conditional_null_z_score": metrics.get(
                    "paired_conditional_null_z_score"
                ),
                "minimum_million_decoy_rank": metrics.get(
                    "minimum_million_decoy_rank"
                ),
                "live_target_state_bytes": metrics.get("live_target_state_bytes"),
                "native_solver_branches": metrics.get("native_solver_branches"),
                "cpu_seconds": metrics.get("cpu_seconds"),
                "wall_seconds": metrics.get("wall_seconds"),
                "outcome_peak_rss_mib": metrics.get("peak_rss_mib"),
                "end_to_end_process_peak_rss_mib": process_peak_rss_mib,
                "fresh_target_count": metrics.get("fresh_random_targets"),
                "fresh_targets_revealed": True,
                "capsule_status": "failed" if outcome_failed else "completed",
                "failure_reasons": metrics.get("failure_reasons"),
                "primary_h96_exact_o1c0013_bytes": True,
                "source_build_cal_reader_reconstructions": 3,
                "target_reader_refits": 0,
                "sibling_writes": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if outcome_failed else 0


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

    corrected = subparsers.add_parser(
        "corrected-codec-bridge",
        help="reproduce corrected W46 fields and freeze the adaptive DC memory bridge",
    )
    corrected.add_argument(
        "--config",
        type=Path,
        default=root / "configs/corrected_codec_bridge_v1.json",
    )
    corrected.set_defaults(handler=_corrected_codec_bridge)

    upstream = subparsers.add_parser(
        "upstream-ising-freeze",
        help="freeze the exact upstream evidence panel and compact target-blind A356 order",
    )
    upstream.add_argument(
        "--config",
        type=Path,
        default=root / "configs/upstream_ising_retrospective_v1.json",
    )
    upstream.set_defaults(handler=_upstream_ising_freeze)

    living = subparsers.add_parser(
        "living-inverse-foundation",
        help="freeze the full-256 public-output attacker and teacher boundary",
    )
    living.add_argument(
        "--config",
        type=Path,
        default=root / "configs/living_inverse_foundation_v1.json",
    )
    living.set_defaults(handler=_living_inverse_foundation)

    living_reader = subparsers.add_parser(
        "living-inverse-reader",
        help="fit and open once the full-256 output-only Living Inverse readers",
    )
    living_reader.add_argument(
        "--config",
        type=Path,
        default=root / "configs/living_inverse_reader_v1.json",
    )
    living_reader.set_defaults(handler=_living_inverse_reader)
    signed_replication = subparsers.add_parser(
        "signed-direct-replication",
        help="prospectively replicate the frozen full-256 signed direct breadcrumb",
    )
    signed_replication.add_argument(
        "--config",
        type=Path,
        default=root / "configs/signed_direct_replication_v1.json",
    )
    signed_replication.set_defaults(handler=_signed_direct_replication)
    cnf_foundation = subparsers.add_parser(
        "full256-cnf-foundation",
        help="compile and solver-validate the full-256 public ChaCha20 CNF",
    )
    cnf_foundation.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_cnf_foundation_v1.json",
    )
    cnf_foundation.set_defaults(handler=_full256_cnf_foundation)
    paired_sensor = subparsers.add_parser(
        "full256-paired-sensor",
        help="stream all full-256 paired proof frontiers into a bounded O1 state",
    )
    paired_sensor.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_paired_causal_sensor_v1.json",
    )
    paired_sensor.set_defaults(handler=_full256_paired_sensor)
    multikey_calibration = subparsers.add_parser(
        "full256-multikey-calibration",
        help=("freeze a multi-key causal reader, then attack sealed full-256 targets"),
    )
    multikey_calibration.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_multikey_causal_calibration_v1.json",
    )
    multikey_calibration.set_defaults(handler=_full256_multikey_calibration)
    online_self_discovery = subparsers.add_parser(
        "full256-online-self-discovery",
        help=(
            "train O1 online on anonymous channels, then freeze full-256 "
            "synthetic predictions before scoring"
        ),
    )
    online_self_discovery.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_online_self_discovery_v1.json",
    )
    online_self_discovery.set_defaults(handler=_full256_online_self_discovery)
    frozen_reader_replication = subparsers.add_parser(
        "full256-frozen-reader-replication",
        help=("replicate the frozen causal reader on fresh sealed full-256 targets"),
    )
    frozen_reader_replication.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_frozen_reader_replication_v1.json",
    )
    frozen_reader_replication.set_defaults(handler=_full256_frozen_reader_replication)
    polyphase_replication = subparsers.add_parser(
        "full256-polyphase-replication",
        help=("replicate the frozen h96+h65 polyphase reader on 32 full-256 targets"),
    )
    polyphase_replication.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_polyphase_replication_v1.json",
    )
    polyphase_replication.set_defaults(
        handler=_full256_polyphase_replication,
        polyphase_canonical_config="full256_polyphase_replication_v1.json",
        polyphase_attempt_id="O1C-0015",
        polyphase_command_name="full256-polyphase-replication",
    )
    polyphase_replication_v2 = subparsers.add_parser(
        "full256-polyphase-replication-v2",
        help=(
            "repeat the frozen h96+h65 polyphase reader on 32 fresh full-256 "
            "targets under corrected resource ceilings"
        ),
    )
    polyphase_replication_v2.add_argument(
        "--config",
        type=Path,
        default=root / "configs/full256_polyphase_replication_v2.json",
    )
    polyphase_replication_v2.set_defaults(
        handler=_full256_polyphase_replication,
        polyphase_canonical_config="full256_polyphase_replication_v2.json",
        polyphase_attempt_id="O1C-0016",
        polyphase_command_name="full256-polyphase-replication-v2",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
