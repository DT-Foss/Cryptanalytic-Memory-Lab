"""Capsule-backed CPU runner for learned-mask MQAR-256 (O1C-0020)."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .run_capsule import ClaimLevel, RunCapsuleManager
from .selective_mqar import (
    PREDICTION_FREEZE_SCHEMA,
    RESULT_SCHEMA,
    GATE_FREEZE_SCHEMA,
    SelectiveMQARConfig,
    run_selective_mqar,
)

RUN_CONFIG_SCHEMA = "o1-256-selective-mqar-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-selective-mqar-cli-result-v1"


class SelectiveMQARRunError(ValueError):
    """A run config, lifecycle boundary, source pin, or budget differs."""


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise SelectiveMQARRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise SelectiveMQARRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True)
class SelectiveMQARRunBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_gate_token_evaluations: int
    maximum_training_token_exposures: int
    maximum_live_state_bytes: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_native_solver_branches: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "SelectiveMQARRunBudgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        for field in ("maximum_cpu_seconds", "maximum_wall_seconds"):
            scalar = row[field]
            if (
                isinstance(scalar, bool)
                or not isinstance(scalar, (int, float))
                or not 0 < float(scalar) <= 86_400
            ):
                raise SelectiveMQARRunError(f"budgets.{field} differs")
        limits = {
            "maximum_resident_memory_mib": 65_536,
            "maximum_persistent_artifact_bytes": 1_000_000_000,
            "maximum_gate_token_evaluations": 1_000_000_000,
            "maximum_training_token_exposures": 1_000_000_000,
            "maximum_live_state_bytes": 1_000_000,
            "maximum_scientific_entropy_calls": 1_000_000,
            "maximum_sibling_reads": 1_000_000,
            "maximum_sibling_writes": 1_000_000,
            "maximum_native_solver_branches": 1_000_000,
            "maximum_mps_calls": 1_000_000,
            "maximum_gpu_calls": 1_000_000,
        }
        for field, maximum in limits.items():
            _integer(row[field], f"budgets.{field}", 0, maximum)
        result = cls(
            maximum_cpu_seconds=float(row["maximum_cpu_seconds"]),
            maximum_wall_seconds=float(row["maximum_wall_seconds"]),
            **{field: int(row[field]) for field in limits},
        )
        for field in (
            "maximum_scientific_entropy_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_native_solver_branches",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        ):
            if getattr(result, field) != 0:
                raise SelectiveMQARRunError(f"O1C-0020 requires zero {field}")
        return result


def _read_document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelectiveMQARRunError("run config is unreadable") from exc
    if not isinstance(value, dict):
        raise SelectiveMQARRunError("run config must be a mapping")
    return value


def load_selective_mqar_run_config(
    path: str | Path,
) -> tuple[dict[str, object], SelectiveMQARConfig, SelectiveMQARRunBudgets]:
    config_path = Path(path)
    value = _read_document(config_path)
    expected = {
        "schema",
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "controls",
        "budgets",
        "next_action",
        "experiment",
    }
    top = dict(_mapping(value, "config", expected))
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise SelectiveMQARRunError("run config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(top[field], str) or not top[field].strip():
            raise SelectiveMQARRunError(f"config.{field} is required")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise SelectiveMQARRunError("config.controls differ")
    try:
        claim = ClaimLevel(str(top["claim_level"]))
    except ValueError as exc:
        raise SelectiveMQARRunError("claim_level differs") from exc
    if claim is not ClaimLevel.VALIDATION:
        raise SelectiveMQARRunError("O1C-0020 claim_level must be VALIDATION")
    if top["attempt_id"] != "O1C-0020":
        raise SelectiveMQARRunError("attempt_id must be exactly O1C-0020")
    if top["slug"] != "selective-mqar-256-learned-gate-v1":
        raise SelectiveMQARRunError("O1C-0020 slug differs")
    experiment = SelectiveMQARConfig.from_mapping(top["experiment"])
    budgets = SelectiveMQARRunBudgets.from_mapping(top["budgets"])
    if experiment.n_bits != 256:
        raise SelectiveMQARRunError("O1C-0020 requires exactly 256 bits")
    if experiment.haystack_lengths != (0, 1 << 16, 1 << 20):
        raise SelectiveMQARRunError("O1C-0020 haystack sweep differs")
    if experiment.live_state_bytes != budgets.maximum_live_state_bytes:
        raise SelectiveMQARRunError("live-state budget must equal the declared state")
    planned_gate_work = (
        5
        * len(experiment.evaluation_seeds)
        * sum(experiment.n_bits + length for length in experiment.haystack_lengths)
        + experiment.no_binding_length
        + experiment.literal_audit_tokens
        + 2
        * len(experiment.calibration_seeds)
        * 2
        * experiment.calibration_examples_per_class
    )
    if planned_gate_work > budgets.maximum_gate_token_evaluations:
        raise SelectiveMQARRunError("planned gate work exceeds its budget")
    training_exposures = (
        2
        * experiment.training_steps
        * len(experiment.build_seeds)
        * 2
        * experiment.build_examples_per_class
    )
    if training_exposures > budgets.maximum_training_token_exposures:
        raise SelectiveMQARRunError("planned training work exceeds its budget")
    return top, experiment, budgets


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise SelectiveMQARRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise SelectiveMQARRunError("lab commit is unavailable")
    return commit


def _source_hashes(root: Path, config_path: Path) -> dict[str, str]:
    names = (
        "isolation.py",
        "memory.py",
        "o1_streaming_core.py",
        "run_capsule.py",
        "selective_mqar.py",
        "selective_mqar_run.py",
    )
    return {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(root / "src/o1_crypto_lab" / name)
            for name in names
        },
    }


def _already_finalized(manager: RunCapsuleManager, attempt_id: str) -> int | None:
    published = manager.finalized_attempt(attempt_id)
    if published is None:
        return None
    metrics_document = json.loads(
        (published.path / "metrics.json").read_text(encoding="utf-8")
    )
    capsule_status = metrics_document.get("status")
    print(
        json.dumps(
            {
                "attempt_id": attempt_id,
                "path": str(published.path),
                "manifest_sha256": published.manifest_sha256,
                "verified": published.verification.ok,
                "status": "already-finalized-no-replay",
                "capsule_status": capsule_status,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if capsule_status == "completed" else 2


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    canonical_config = (root / "configs/selective_mqar_256_v1.json").resolve(
        strict=True
    )
    if config_path != canonical_config:
        raise SelectiveMQARRunError(
            "O1C-0020 requires the canonical tracked config path"
        )
    top, experiment, budgets = load_selective_mqar_run_config(config_path)
    attempt_id = str(top["attempt_id"])
    manager = RunCapsuleManager(root)
    finalized_status = _already_finalized(manager, attempt_id)
    if finalized_status is not None:
        return finalized_status
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            capsule_status = metrics_document.get("status")
            print(
                json.dumps(
                    {
                        "attempt_id": attempt_id,
                        "path": str(finalized.path),
                        "manifest_sha256": finalized.manifest_sha256,
                        "verified": finalized.verification.ok,
                        "status": "prepared-publication-completed-no-replay",
                        "capsule_status": capsule_status,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0 if capsule_status == "completed" else 2
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve the interrupted attempt and advance under a new O1C ID; "
                "never replay O1C-0020 evaluation seeds."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(root)
    hashes = _source_hashes(root, config_path)
    run = manager.start(
        attempt_id=attempt_id,
        slug=str(top["slug"]),
        commit=commit,
        hypothesis=str(top["hypothesis"]),
        prediction=str(top["prediction"]),
        controls=tuple(str(item) for item in top["controls"]),
        budgets=dict(top["budgets"]),
        source_hashes=hashes,
        claim_level=ClaimLevel(str(top["claim_level"])),
        next_action=str(top["next_action"]),
        config=top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.selective_mqar_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "synthetic-mqar-256-learned-public-route",
            "accelerator": "none",
            "torch_device": "cpu",
            "cpu_threads": experiment.cpu_threads,
            "scientific_entropy_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "native_solver_branches": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    gate_frozen = False
    predictions_frozen = False
    cpu_started = time.process_time()
    wall_started = time.monotonic()

    def persist_group(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
        *,
        phase: str,
    ) -> None:
        nonlocal persistent_bytes
        if not artifacts:
            raise SelectiveMQARRunError(f"{phase} artifacts are empty")
        group_bytes = sum(len(payload) for payload in artifacts.values())
        if persistent_bytes + group_bytes > budgets.maximum_persistent_artifact_bytes:
            raise SelectiveMQARRunError(f"{phase} exceeds the artifact budget")
        for relative, payload in sorted(artifacts.items()):
            if relative in persisted or not isinstance(payload, bytes):
                raise SelectiveMQARRunError(f"{phase} artifact inventory differs")
            output = run.write_artifact(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            if _sha256_file(output) != digest:
                raise SelectiveMQARRunError(f"{phase} persisted bytes differ")
            persisted[relative] = {
                "sha256": digest,
                "bytes": len(payload),
                "phase": phase,
            }
            persistent_bytes += len(payload)
        run.checkpoint(
            {
                "phase": phase,
                "freeze_sha256": document.get("freeze_sha256"),
                "persistent_artifact_bytes": persistent_bytes,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "native_solver_branches": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def gate_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal gate_frozen
        if gate_frozen or (
            document.get("schema") != GATE_FREEZE_SCHEMA
            or document.get("phase")
            != "SLOW_STATES_FROZEN_BEFORE_EVALUATION_STREAM_GENERATION"
            or document.get("evaluation_streams_generated") != 0
            or document.get("evaluation_tokens_seen") != 0
            or document.get("evaluation_slow_updates") != 0
        ):
            raise SelectiveMQARRunError("gate freeze boundary differs")
        persist_group(artifacts, document, phase="GATE_FROZEN_BEFORE_EVALUATION")
        gate_frozen = True

    def prediction_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal predictions_frozen
        if (
            predictions_frozen
            or not gate_frozen
            or (
                document.get("schema") != PREDICTION_FREEZE_SCHEMA
                or document.get("phase")
                != "ALL_PUBLIC_RECALLS_FROZEN_BEFORE_TRUTH_REVEAL"
                or document.get("truth_ledger_reveal_count") != 0
                or document.get("scorer_calls") != 0
                or document.get("evaluation_slow_updates") != 0
            )
        ):
            raise SelectiveMQARRunError("prediction freeze boundary differs")
        persist_group(
            artifacts,
            document,
            phase="PUBLIC_PREDICTIONS_FROZEN_BEFORE_REVEAL",
        )
        predictions_frozen = True

    try:
        run.checkpoint(
            {
                "phase": "O1C0020_RESERVED",
                "n_bits": experiment.n_bits,
                "haystack_lengths": list(experiment.haystack_lengths),
                "evaluation_seeds": len(experiment.evaluation_seeds),
                "gate_frozen": False,
                "predictions_frozen": False,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "native_solver_branches": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout("Learned-mask MQAR-256 started on one CPU thread.\n")
        result = run_selective_mqar(
            experiment,
            on_gate_frozen=gate_callback,
            on_predictions_frozen=prediction_callback,
        )
        if not gate_frozen or not predictions_frozen:
            raise SelectiveMQARRunError("required freeze callbacks did not execute")
        if result.report.get("schema") != RESULT_SCHEMA:
            raise SelectiveMQARRunError("scientific result schema differs")
        result_payload = (
            json.dumps(
                result.report,
                indent=2,
                sort_keys=True,
                allow_nan=False,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
        persist_group(
            {"selective_mqar.json": result_payload},
            {"freeze_sha256": result.report["result_sha256"]},
            phase="POST_FREEZE_SCORED_RESULT",
        )
        artifact_index = {
            "schema": "o1-256-selective-mqar-artifact-index-v1",
            "attempt_id": attempt_id,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
            "self_excluded_from_index": True,
        }
        persist_group(
            {
                "artifact_index.json": (
                    json.dumps(
                        artifact_index,
                        indent=2,
                        sort_keys=True,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("ascii")
            },
            {"freeze_sha256": result.report["result_sha256"]},
            phase="ARTIFACT_INDEX",
        )
        if _git_commit(root) != commit or _source_hashes(root, config_path) != hashes:
            raise SelectiveMQARRunError("source changed during execution")

        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        work = result.report["work"]
        state = result.report["state"]
        training_exposures = sum(
            int(result.report["gate_training"][name]["training"]["token_exposures"])
            for name in ("primary", "shuffled_label")
        )
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "gate_token_evaluations": int(work["gate_token_evaluations"])
            <= budgets.maximum_gate_token_evaluations,
            "training_token_exposures": training_exposures
            <= budgets.maximum_training_token_exposures,
            "live_state": int(state["total_live_state_bytes"])
            == budgets.maximum_live_state_bytes,
            "scientific_entropy": int(work["scientific_entropy_calls"]) == 0,
            "sibling_reads": int(work["sibling_reads"]) == 0,
            "sibling_writes": int(work["sibling_writes"]) == 0,
            "native_solver_branches": int(work["native_solver_branches"]) == 0,
            "mps": int(work["mps_calls"]) == 0,
            "gpu": int(work["gpu_calls"]) == 0,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operationally_complete = not failed_budgets
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": result.report["classification"],
            "scientific_success_gate_passed": result.success_gate_passed,
            "result_sha256": result.report["result_sha256"],
            "gates": result.report["gates"],
            "state": state,
            "work": work,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "training_token_exposures": training_exposures,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "operationally_complete": operationally_complete,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if operationally_complete else "failed",
        )
    except Exception as exc:
        if run.publication_prepared:
            finalized = run.finalize(metrics={})
            metrics_document = json.loads(
                (finalized.path / "metrics.json").read_text(encoding="utf-8")
            )
            capsule_status = metrics_document.get("status")
            print(f"published prepared capsule: {finalized.path}", file=sys.stderr)
            return 0 if capsule_status == "completed" else 2
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "gate_frozen": gate_frozen,
                "predictions_frozen": predictions_frozen,
                "persistent_artifact_bytes": persistent_bytes,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and fix the lifecycle under a "
                "new O1C ID without replaying this evaluation corpus."
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
                "classification": result.report["classification"],
                "scientific_success_gate_passed": result.success_gate_passed,
                "failed_budgets": failed_budgets,
                "live_state_bytes": result.report["state"]["total_live_state_bytes"],
                "maximum_haystack_length": experiment.haystack_lengths[-1],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run capsule-backed learned-mask MQAR-256"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SelectiveMQARRunBudgets",
    "SelectiveMQARRunError",
    "load_selective_mqar_run_config",
    "main",
    "run_capsule_from_config",
]
