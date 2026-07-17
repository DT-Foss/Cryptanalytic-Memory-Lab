"""Capsule-backed CLI for the artifact-only O1C-0019 BUILD LOO gate."""

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

from .full256_multiresolution_build_loo import (
    BUILD_LOO_CONFIG_SCHEMA,
    ArtifactBuildCorpus,
    Full256BuildLooConfig,
    Full256BuildLooError,
    discover_artifact_build_corpus,
    run_full256_multiresolution_build_loo,
)
from .online_multiresolution_controller import MultiResolutionControllerConfig
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-fullround-multiresolution-build-loo-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-fullround-multiresolution-build-loo-cli-result-v1"


class Full256BuildLooRunError(ValueError):
    """A CLI config, source receipt, capsule lifecycle, or budget differs."""


def _mapping(
    value: object,
    field_name: str,
    expected: set[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise Full256BuildLooRunError(f"{field_name} must be an object")
    if expected is not None and set(value) != expected:
        raise Full256BuildLooRunError(f"{field_name} fields differ")
    return value


def _integer(
    value: object,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256BuildLooRunError(
            f"{field_name} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _sha256(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise Full256BuildLooRunError(f"{field_name} must be a lowercase SHA-256")
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


@dataclass(frozen=True)
class Full256BuildLooBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_source_artifact_bytes_read: int
    expected_existing_build_pools: int
    maximum_physical_public_pools_generated: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "Full256BuildLooBudgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        for field_name in ("maximum_cpu_seconds", "maximum_wall_seconds"):
            scalar = row[field_name]
            if (
                isinstance(scalar, bool)
                or not isinstance(scalar, (int, float))
                or not 0 < float(scalar) <= 172_800
            ):
                raise Full256BuildLooRunError(f"budgets.{field_name} differs")
        maximums = {
            "maximum_resident_memory_mib": 65_536,
            "maximum_persistent_artifact_bytes": 2_000_000_000,
            "maximum_source_artifact_bytes_read": 2_000_000_000,
            "expected_existing_build_pools": 64,
            "maximum_physical_public_pools_generated": 64,
            "maximum_native_solver_branches": 1_000_000,
            "maximum_scientific_entropy_calls": 1_000_000,
            "maximum_sibling_reads": 1_000_000,
            "maximum_sibling_writes": 1_000_000,
            "maximum_mps_calls": 1_000_000,
            "maximum_gpu_calls": 1_000_000,
        }
        for field_name, maximum in maximums.items():
            _integer(
                row[field_name],
                f"budgets.{field_name}",
                0,
                maximum,
            )
        return cls(
            maximum_cpu_seconds=float(row["maximum_cpu_seconds"]),
            maximum_wall_seconds=float(row["maximum_wall_seconds"]),
            **{field_name: int(row[field_name]) for field_name in maximums},
        )


def _experiment_config(
    value: object,
    corpus: ArtifactBuildCorpus,
) -> Full256BuildLooConfig:
    fields = {
        "schema",
        "controller",
        "work_checkpoints",
        "held_out_ordinals",
        "training_actions_per_episode",
        "raw_actions_per_episode",
        "coordinate_rotation_stride",
        "train_stream",
        "train_gate",
    }
    row = _mapping(value, "experiment", fields)
    if row["schema"] != BUILD_LOO_CONFIG_SCHEMA:
        raise Full256BuildLooRunError("experiment schema differs")
    controller_fields = set(MultiResolutionControllerConfig.__dataclass_fields__) - {
        "base"
    }
    controller_row = _mapping(
        row["controller"],
        "experiment.controller",
        controller_fields,
    )
    controller = MultiResolutionControllerConfig(
        base=corpus.base_controller,
        **dict(controller_row),
    )
    return Full256BuildLooConfig(
        controller=controller,
        work_checkpoints=tuple(row["work_checkpoints"]),
        held_out_ordinals=tuple(row["held_out_ordinals"]),
        training_actions_per_episode=row["training_actions_per_episode"],
        raw_actions_per_episode=row["raw_actions_per_episode"],
        coordinate_rotation_stride=row["coordinate_rotation_stride"],
        train_stream=row["train_stream"],
        train_gate=row["train_gate"],
    )


def load_full256_build_loo_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> tuple[
    dict[str, object],
    Full256BuildLooConfig,
    ArtifactBuildCorpus,
    Full256BuildLooBudgets,
]:
    config_path = Path(path).resolve(strict=True)
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256BuildLooRunError("run config is unreadable") from exc
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
        "source",
        "experiment",
    }
    top = dict(_mapping(value, "config", expected))
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise Full256BuildLooRunError("run config schema differs")
    for field_name in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(top[field_name], str) or not top[field_name].strip():
            raise Full256BuildLooRunError(f"config.{field_name} is required")
    try:
        ClaimLevel(str(top["claim_level"]))
    except ValueError as exc:
        raise Full256BuildLooRunError("config.claim_level differs") from exc
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise Full256BuildLooRunError("config.controls differ")

    lab_root = (
        Path(root).resolve(strict=True)
        if root is not None
        else Path(__file__).resolve().parents[2]
    )
    source = _mapping(
        top["source"],
        "source",
        {
            "capsule",
            "expected_manifest_sha256",
            "expected_artifact_index_sha256",
        },
    )
    capsule_relative = source["capsule"]
    if not isinstance(capsule_relative, str) or not capsule_relative:
        raise Full256BuildLooRunError("source.capsule is required")
    source_path = (lab_root / capsule_relative).resolve(strict=True)
    runs_root = (lab_root / "runs").resolve(strict=True)
    if not source_path.is_relative_to(runs_root):
        raise Full256BuildLooRunError("source capsule escapes finalized runs")
    expected_manifest = _sha256(
        source["expected_manifest_sha256"],
        "source.expected_manifest_sha256",
    )
    expected_index = _sha256(
        source["expected_artifact_index_sha256"],
        "source.expected_artifact_index_sha256",
    )
    try:
        corpus = discover_artifact_build_corpus(
            source_path,
            lab_root=lab_root,
            verify_capsule=True,
            expected_manifest_sha256=expected_manifest,
            expected_artifact_index_sha256=expected_index,
        )
    except Full256BuildLooError as exc:
        raise Full256BuildLooRunError(str(exc)) from exc
    experiment = _experiment_config(top["experiment"], corpus)
    budgets = Full256BuildLooBudgets.from_mapping(top["budgets"])
    if budgets.expected_existing_build_pools != len(corpus.episodes):
        raise Full256BuildLooRunError(
            "existing BUILD-pool budget must equal the source inventory"
        )
    if (
        budgets.maximum_source_artifact_bytes_read < corpus.bytes_read
        or budgets.maximum_physical_public_pools_generated != 0
        or budgets.maximum_native_solver_branches != 0
        or budgets.maximum_scientific_entropy_calls != 0
        or budgets.maximum_sibling_reads != 0
        or budgets.maximum_sibling_writes != 0
        or budgets.maximum_mps_calls != 0
        or budgets.maximum_gpu_calls != 0
    ):
        raise Full256BuildLooRunError("artifact-only CPU isolation budgets differ")
    return top, experiment, corpus, budgets


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise Full256BuildLooRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise Full256BuildLooRunError("lab commit is unavailable")
    return commit


def _source_hashes(
    root: Path,
    config_path: Path,
    corpus: ArtifactBuildCorpus,
) -> dict[str, str]:
    names = (
        "full256_action_pool.py",
        "full256_multiresolution_build_loo.py",
        "full256_multiresolution_build_loo_run.py",
        "full256_proof_pool.py",
        "living_inverse.py",
        "o1_streaming_core.py",
        "online_causal_controller.py",
        "online_multiresolution_controller.py",
        "run_capsule.py",
        "stationarity_critic.py",
    )
    return {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        "source_capsule_manifest": corpus.capsule_manifest_sha256,
        "source_artifact_index": corpus.artifact_index_sha256,
        "source_result": corpus.source_result_sha256,
        "source_config": corpus.source_config_sha256,
        "source_artifact_corpus": corpus.sha256,
        **{
            f"module_{Path(name).stem}": _sha256_file(root / "src/o1_crypto_lab" / name)
            for name in names
        },
        **{
            f"source_pool_{episode.ordinal:04d}": episode.action_pool_sha256
            for episode in corpus.episodes
        },
    }


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    top, experiment, corpus, budgets = load_full256_build_loo_run_config(
        config_path,
        root=root,
    )
    attempt_id = str(top["attempt_id"])
    manager = RunCapsuleManager(root)
    published = manager.finalized_attempt(attempt_id)
    if published is not None:
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
    if attempt_id in manager.recoverable_attempt_ids():
        interrupted = manager.recover(attempt_id)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            print(f"publication completed: {finalized.path}")
            return 0
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "hard_interruption_recovered": True,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve this interrupted retrospective fold set and advance "
                "under a new attempt identity without replaying it."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(root)
    hashes = _source_hashes(root, config_path, corpus)
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
            "o1_crypto_lab.full256_multiresolution_build_loo_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "retrospective-build-loo-fullround-256",
            "source_attempt_id": corpus.source_attempt_id,
            "source_capsule_manifest_sha256": corpus.capsule_manifest_sha256,
            "source_artifact_index_sha256": corpus.artifact_index_sha256,
            "existing_build_pools": len(corpus.episodes),
            "physical_public_pools_generated": 0,
            "native_solver_branches": 0,
            "accelerator": "none",
            "scientific_entropy_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    frozen_prediction_folds: set[int] = set()
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
            raise Full256BuildLooRunError(f"{phase} artifacts are empty")
        group_bytes = sum(len(payload) for payload in artifacts.values())
        if persistent_bytes + group_bytes > budgets.maximum_persistent_artifact_bytes:
            raise Full256BuildLooRunError(f"{phase} exceeds the artifact-byte budget")
        for relative, payload in sorted(artifacts.items()):
            if relative in persisted or not isinstance(payload, bytes):
                raise Full256BuildLooRunError(f"{phase} artifact inventory differs")
            output = run.write_artifact(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            if _sha256_file(output) != digest:
                raise Full256BuildLooRunError(f"{phase} persisted bytes differ")
            persisted[relative] = {
                "sha256": digest,
                "bytes": len(payload),
                "phase": phase,
            }
            persistent_bytes += len(payload)
        run.checkpoint(
            {
                "phase": phase,
                "fold_index": document.get("fold_index"),
                "freeze_sha256": document.get("freeze_sha256"),
                "persistent_artifact_bytes": persistent_bytes,
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def learning_callback(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
    ) -> None:
        if (
            document.get("phase")
            != "FINAL_READER_AND_ATOMIC_CRITIC_FROZEN_BEFORE_HELD_OUT_POLICY"
            or document.get("held_out_labels_materialized") != 0
            or document.get("held_out_reader_updates") != 0
            or document.get("held_out_critic_updates") != 0
        ):
            raise Full256BuildLooRunError("learning freeze boundary differs")
        persist_group(
            artifacts,
            document,
            phase=f"LEARNING_FROZEN_FOLD_{document['fold_index']}",
        )

    def prediction_callback(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
    ) -> None:
        fold_index = int(document["fold_index"])
        if (
            fold_index in frozen_prediction_folds
            or document.get("phase")
            != "ALL_HELD_OUT_TRAJECTORIES_FROZEN_BEFORE_LABEL_ACCESS"
            or document.get("held_out_labels_materialized") != 0
            or document.get("held_out_reader_updates") != 0
            or document.get("held_out_critic_updates") != 0
        ):
            raise Full256BuildLooRunError("prediction freeze boundary differs")
        persist_group(
            artifacts,
            document,
            phase=f"PREDICTION_FROZEN_FOLD_{fold_index}",
        )
        frozen_prediction_folds.add(fold_index)

    try:
        run.checkpoint(
            {
                "phase": "O1C0019_ARTIFACT_BUILD_LOO_RESERVED",
                "folds": len(experiment.held_out_ordinals),
                "source_build_pools": len(corpus.episodes),
                "source_artifact_bytes_read": corpus.bytes_read,
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout("O1C-0019 artifact-only BUILD LOO started on CPU.\n")
        result = run_full256_multiresolution_build_loo(
            experiment,
            corpus,
            on_learning_frozen=learning_callback,
            on_prediction_frozen=prediction_callback,
        )
        if len(frozen_prediction_folds) != len(experiment.held_out_ordinals):
            raise Full256BuildLooRunError(
                "not every fold was persisted before held-out scoring"
            )

        commitments = result.report["artifact_commitments"]
        global_payloads = {
            "predictions_sha256": result.predictions.astype("<f4", copy=False).tobytes(
                order="C"
            ),
            "action_orders_sha256": result.action_orders.astype(
                "<u2", copy=False
            ).tobytes(order="C"),
            "slot_orders_sha256": result.slot_orders.astype(
                "<u2", copy=False
            ).tobytes(order="C"),
            "checkpoint_action_counts_sha256": (
                result.checkpoint_action_counts.astype("<u2", copy=False).tobytes(
                    order="C"
                )
            ),
            "checkpoint_slot_counts_sha256": (
                result.checkpoint_slot_counts.astype("<u2", copy=False).tobytes(
                    order="C"
                )
            ),
            "checkpoint_work_sha256": result.checkpoint_work.astype(
                "<u4", copy=False
            ).tobytes(order="C"),
            "terminal_codes_sha256": result.terminal_codes.tobytes(order="C"),
            "static_scores_sha256": result.static_scores.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "static_counts_sha256": result.static_counts.astype(
                "<u4", copy=False
            ).tobytes(order="C"),
        }
        if any(
            commitments.get(name) != hashlib.sha256(payload).hexdigest()
            for name, payload in global_payloads.items()
        ):
            raise Full256BuildLooRunError("global result artifact commitment differs")
        final_artifacts = {
            **result.scored_artifacts(),
            "predictions.f32le": global_payloads["predictions_sha256"],
            "action_orders.u16le": global_payloads["action_orders_sha256"],
            "slot_orders.u16le": global_payloads["slot_orders_sha256"],
            "checkpoint_action_counts.u16le": global_payloads[
                "checkpoint_action_counts_sha256"
            ],
            "checkpoint_slot_counts.u16le": global_payloads[
                "checkpoint_slot_counts_sha256"
            ],
            "checkpoint_work.u32le": global_payloads["checkpoint_work_sha256"],
            "terminal_codes.u8": global_payloads["terminal_codes_sha256"],
            "static_scores.f64le": global_payloads["static_scores_sha256"],
            "static_counts.u32le": global_payloads["static_counts_sha256"],
        }
        persist_group(
            final_artifacts,
            {"freeze_sha256": result.result_sha256},
            phase="POST_FREEZE_SCORED_RESULT",
        )
        artifact_index = {
            "schema": ("o1-256-fullround-multiresolution-build-loo-artifact-index-v1"),
            "attempt_id": attempt_id,
            "source_capsule_manifest_sha256": corpus.capsule_manifest_sha256,
            "source_artifact_index_sha256": corpus.artifact_index_sha256,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
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
            {"freeze_sha256": result.result_sha256},
            phase="ARTIFACT_INDEX",
        )
        if (
            _git_commit(root) != commit
            or _source_hashes(root, config_path, corpus) != hashes
        ):
            raise Full256BuildLooRunError("source changed during execution")

        resources = result.report["resources"]
        cpu_seconds = max(
            float(resources["cpu_seconds"]),
            time.process_time() - cpu_started,
        )
        wall_seconds = max(
            float(resources["wall_seconds"]),
            time.monotonic() - wall_started,
        )
        peak_rss_bytes = max(
            int(resources["process_peak_rss_bytes"]),
            _process_peak_rss_bytes(),
        )
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "source_artifact_bytes_read": int(resources["source_artifact_bytes_read"])
            <= budgets.maximum_source_artifact_bytes_read,
            "existing_build_pools": int(resources["existing_build_pools_loaded"])
            == budgets.expected_existing_build_pools,
            "physical_public_pools_generated": int(
                resources["physical_public_pools_generated"]
            )
            == 0,
            "native_solver_branches": int(resources["native_solver_branches"]) == 0,
            "scientific_entropy": int(resources["scientific_entropy_calls"]) == 0,
            "sibling_reads": int(resources["sibling_reads"]) == 0,
            "sibling_writes": int(resources["sibling_writes"]) == 0,
            "mps": int(resources["mps_calls"]) == 0,
            "gpu": int(resources["gpu_calls"]) == 0,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operational_failure = result.report["classification"] == ("OPERATIONAL_FAILURE")
        operationally_complete = not failed_budgets and not operational_failure
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": result.report["classification"],
            "scientific_success_gate_passed": result.report["gates"][
                "success_gate_passed"
            ],
            "result_sha256": result.result_sha256,
            "margins": result.report["margins"],
            "gates": result.report["gates"],
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "source_artifact_bytes_read": resources["source_artifact_bytes_read"],
            "physical_public_pools_generated": 0,
            "native_solver_branches": 0,
            "budget_checks": budget_checks,
            "failed_budgets": failed_budgets,
            "operational_failure": operational_failure,
            "operationally_complete": operationally_complete,
        }
        run.append_stdout(json.dumps(metrics, sort_keys=True) + "\n")
        finalized = run.finalize(
            metrics=metrics,
            status="completed" if operationally_complete else "failed",
        )
    except Exception as exc:
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "prediction_folds_frozen": sorted(frozen_prediction_folds),
                "persistent_artifact_bytes": persistent_bytes,
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and repair the exact "
                "artifact-only lifecycle under a new attempt identity."
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
                "scientific_success_gate_passed": result.report["gates"][
                    "success_gate_passed"
                ],
                "failed_budgets": failed_budgets,
                "operational_failure": operational_failure,
                "raw_reader_mean_compression_bits": result.report["raw_reader_arms"][
                    "learned_reader_exhaustive"
                ]["mean_compression_bits"],
                "learned_mean_iauc_bits": result.report["arms"]["learned_stationary"][
                    "mean_iauc_bits"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run O1C-0019 artifact-only full-256 BUILD leave-one-out"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "Full256BuildLooBudgets",
    "Full256BuildLooRunError",
    "load_full256_build_loo_run_config",
    "main",
    "run_capsule_from_config",
]
