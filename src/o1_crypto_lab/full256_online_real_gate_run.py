"""Capsule-backed command runner for the O1C full-round online real gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from .causal_bitfield import CausalBitfieldPlan
from .full256_online_real_gate import (
    Full256OnlineRealGateConfig,
    run_full256_online_real_gate,
)
from .full256_paired_sensor import NativeDependencyConfig
from .full256_proof_pool import (
    Full256ProofPoolBuilder,
    Full256ProofPoolConfig,
    Full256ProofPoolSource,
)
from .online_causal_controller import OnlineCausalControllerConfig
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-fullround-online-real-gate-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-fullround-online-real-gate-cli-result-v1"


class Full256OnlineRealGateRunError(ValueError):
    """A run config, capsule lifecycle, or budget differs."""


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise Full256OnlineRealGateRunError(f"{field} fields differ")
    return value


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # macOS reports bytes; Linux reports KiB.
    return value if value > 16 * 1024 * 1024 else value * 1024


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise Full256OnlineRealGateRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


@dataclass(frozen=True)
class Full256OnlineRealGateBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_physical_public_pools: int
    maximum_native_solver_branches: int
    maximum_scientific_entropy_calls: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "Full256OnlineRealGateBudgets":
        fields = {
            "maximum_cpu_seconds",
            "maximum_wall_seconds",
            "maximum_resident_memory_mib",
            "maximum_persistent_artifact_bytes",
            "maximum_physical_public_pools",
            "maximum_native_solver_branches",
            "maximum_scientific_entropy_calls",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        }
        row = _mapping(value, "budgets", fields)
        for field in ("maximum_cpu_seconds", "maximum_wall_seconds"):
            scalar = row[field]
            if (
                isinstance(scalar, bool)
                or not isinstance(scalar, (int, float))
                or not 0 < float(scalar) <= 86_400
            ):
                raise Full256OnlineRealGateRunError(f"budgets.{field} differs")
        integer_limits = {
            "maximum_resident_memory_mib": 65_536,
            "maximum_persistent_artifact_bytes": 1_000_000_000,
            "maximum_physical_public_pools": 128,
            "maximum_native_solver_branches": 1_000_000,
            "maximum_scientific_entropy_calls": 1_000_000,
            "maximum_sibling_reads": 1_000_000,
            "maximum_sibling_writes": 1_000_000,
            "maximum_mps_calls": 1_000_000,
            "maximum_gpu_calls": 1_000_000,
        }
        for field, maximum in integer_limits.items():
            _integer(row[field], f"budgets.{field}", 0, maximum)
        return cls(
            maximum_cpu_seconds=float(row["maximum_cpu_seconds"]),
            maximum_wall_seconds=float(row["maximum_wall_seconds"]),
            **{field: int(row[field]) for field in integer_limits},
        )


def _proof_pool_config(value: object) -> Full256ProofPoolConfig:
    row = _mapping(
        value,
        "proof_pool",
        {
            "source",
            "native",
            "state_plan",
            "probe_seed",
            "timeout_seconds",
            "maximum_state_bytes",
        },
    )
    source_row = _mapping(
        row["source"],
        "proof_pool.source",
        {
            "capsule",
            "manifest_sha256",
            "template",
            "template_sha256",
            "semantic_map",
            "semantic_map_sha256",
            "expected_variable_count",
            "expected_template_clause_count",
            "expected_public_clause_count",
        },
    )
    source = Full256ProofPoolSource(**source_row)
    native = NativeDependencyConfig.from_mapping(row["native"])
    plan_row = _mapping(
        row["state_plan"],
        "proof_pool.state_plan",
        {
            "horizons",
            "horizon_weights",
            "unary_clip",
            "interaction_clip",
            "holographic_clip",
            "readout_temperature",
            "phase_seed",
        },
    )
    plan = CausalBitfieldPlan(
        horizons=tuple(plan_row["horizons"]),
        horizon_weights=tuple(plan_row["horizon_weights"]),
        unary_clip=float(plan_row["unary_clip"]),
        interaction_clip=float(plan_row["interaction_clip"]),
        holographic_clip=float(plan_row["holographic_clip"]),
        readout_temperature=float(plan_row["readout_temperature"]),
        phase_seed=int(plan_row["phase_seed"]),
    )
    return Full256ProofPoolConfig(
        source=source,
        native=native,
        state_plan=plan,
        probe_seed=int(row["probe_seed"]),
        timeout_seconds=float(row["timeout_seconds"]),
        maximum_state_bytes=int(row["maximum_state_bytes"]),
    )


def _experiment_config(value: object) -> Full256OnlineRealGateConfig:
    row = _mapping(
        value,
        "experiment",
        {
            "controller",
            "corpus_seed",
            "build_targets",
            "evaluation_targets",
            "build_index_start",
            "evaluation_index_start",
            "evaluation_split",
            "work_checkpoints",
            "coordinate_rotation",
            "maximum_checkpoint_slack",
            "minimum_raw_mean_compression_bits",
            "minimum_raw_control_margin_bits",
            "minimum_raw_positive_targets",
            "minimum_picker_iauc_margin_bits",
            "minimum_picker_win_targets",
        },
    )
    controller_row = dict(
        _mapping(
            row["controller"],
            "experiment.controller",
            set(OnlineCausalControllerConfig.__dataclass_fields__),
        )
    )
    controller_row["horizons"] = tuple(controller_row["horizons"])
    controller = OnlineCausalControllerConfig(**controller_row)
    values = dict(row)
    values.pop("controller")
    values["work_checkpoints"] = tuple(values["work_checkpoints"])
    return Full256OnlineRealGateConfig(controller=controller, **values)


def load_full256_online_real_gate_run_config(
    path: str | Path,
) -> tuple[
    dict[str, object],
    Full256OnlineRealGateConfig,
    Full256ProofPoolConfig,
    Full256OnlineRealGateBudgets,
]:
    config_path = Path(path)
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Full256OnlineRealGateRunError("run config is unreadable") from exc
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
        "proof_pool",
        "experiment",
    }
    top = dict(_mapping(value, "config", expected))
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise Full256OnlineRealGateRunError("run config schema differs")
    for field in (
        "attempt_id",
        "slug",
        "claim_level",
        "hypothesis",
        "prediction",
        "next_action",
    ):
        if not isinstance(top[field], str) or not top[field].strip():
            raise Full256OnlineRealGateRunError(f"config.{field} is required")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise Full256OnlineRealGateRunError("config.controls differ")
    gate = _experiment_config(top["experiment"])
    proof = _proof_pool_config(top["proof_pool"])
    budgets = Full256OnlineRealGateBudgets.from_mapping(top["budgets"])
    if proof.state_plan.horizons != gate.controller.horizons:
        raise Full256OnlineRealGateRunError(
            "proof-pool and controller horizons differ"
        )
    planned_pools = gate.build_targets + gate.evaluation_targets
    if planned_pools != budgets.maximum_physical_public_pools:
        raise Full256OnlineRealGateRunError(
            "physical pool budget must equal the fixed corpus size"
        )
    for field in (
        "maximum_scientific_entropy_calls",
        "maximum_sibling_reads",
        "maximum_sibling_writes",
        "maximum_mps_calls",
        "maximum_gpu_calls",
    ):
        if getattr(budgets, field) != 0:
            raise Full256OnlineRealGateRunError(
                f"O1C real gate requires zero {field}"
            )
    return top, gate, proof, budgets


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise Full256OnlineRealGateRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise Full256OnlineRealGateRunError("lab commit is unavailable")
    return commit


def _source_hashes(root: Path, config_path: Path) -> dict[str, str]:
    names = (
        "cadical_sensor.py",
        "causal_bitfield.py",
        "chacha_trace.py",
        "full256_action_pool.py",
        "full256_cnf.py",
        "full256_online_real_gate.py",
        "full256_online_real_gate_run.py",
        "full256_paired_sensor.py",
        "full256_probe_core.py",
        "full256_proof_pool.py",
        "living_inverse.py",
        "online_causal_controller.py",
        "o1_streaming_core.py",
        "run_capsule.py",
    )
    result = {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(
                root / "src/o1_crypto_lab" / name
            )
            for name in names
        },
    }
    for relative in (
        "native/cadical_pair_sensor.cpp",
        "native/cadical_tracer_3_0_0.hpp",
    ):
        result[f"native_{Path(relative).stem}"] = _sha256_file(root / relative)
    return result


def run_capsule_from_config(path: str | Path) -> int:
    root = Path(__file__).resolve().parents[2]
    config_path = Path(path).resolve(strict=True)
    top, gate, proof, budgets = load_full256_online_real_gate_run_config(
        config_path
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
                "Preserve this interrupted deterministic corpus and advance under "
                "a new attempt identity without replaying its evaluation split."
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
            "o1_crypto_lab.full256_online_real_gate_run",
            "--config",
            str(config_path),
        ),
        environment={
            "experiment_boundary": "fullround-chacha20-all-256-bits-unknown",
            "evaluation_split": gate.evaluation_split,
            "physical_public_pools": (
                gate.build_targets + gate.evaluation_targets
            ),
            "accelerator": "none",
            "scientific_entropy_calls": 0,
            "operational_path_entropy_excluded": True,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    predictions_frozen = False
    cpu_started = time.process_time()
    wall_started = time.monotonic()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    child_cpu_started = children_started.ru_utime + children_started.ru_stime

    def persist_group(
        artifacts: Mapping[str, bytes],
        document: Mapping[str, object],
        *,
        phase: str,
    ) -> None:
        nonlocal persistent_bytes
        if not artifacts:
            raise Full256OnlineRealGateRunError(f"{phase} artifacts are empty")
        group_bytes = sum(len(payload) for payload in artifacts.values())
        if (
            persistent_bytes + group_bytes
            > budgets.maximum_persistent_artifact_bytes
        ):
            raise Full256OnlineRealGateRunError(
                f"{phase} exceeds the artifact-byte budget"
            )
        for relative, payload in sorted(artifacts.items()):
            if relative in persisted or not isinstance(payload, bytes):
                raise Full256OnlineRealGateRunError(
                    f"{phase} artifact inventory differs"
                )
            output = run.write_artifact(relative, payload)
            digest = hashlib.sha256(payload).hexdigest()
            if _sha256_file(output) != digest:
                raise Full256OnlineRealGateRunError(
                    f"{phase} persisted bytes differ"
                )
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
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )

    def pool_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        if (
            document.get("phase")
            != "PUBLIC_PROOF_POOL_FROZEN_BEFORE_LABEL_ACCESS"
            or document.get("labels_materialized") != 0
            or document.get("target_key_inputs_to_probe") != 0
        ):
            raise Full256OnlineRealGateRunError("pool freeze boundary differs")
        persist_group(
            artifacts,
            document,
            phase=f"POOL_FROZEN_{document['target_id']}",
        )

    def learning_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        if (
            document.get("phase")
            != "BUILD_LEARNING_FROZEN_BEFORE_EVALUATION_TARGET_GENERATION"
            or document.get("evaluation_targets_generated") != 0
        ):
            raise Full256OnlineRealGateRunError("learning freeze boundary differs")
        persist_group(artifacts, document, phase="BUILD_LEARNING_FROZEN")

    def build_prediction_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        if (
            document.get("phase")
            != "BUILD_TRAJECTORY_FROZEN_BEFORE_LABEL_ACCESS"
            or document.get("labels_materialized") != 0
            or document.get("reader_updates_after_current_reveal") != 0
            or document.get("critic_updates_after_current_reveal") != 0
        ):
            raise Full256OnlineRealGateRunError(
                "BUILD prequential freeze boundary differs"
            )
        persist_group(
            artifacts,
            document,
            phase=f"BUILD_PREQUENTIAL_{document['target_id']}",
        )

    def prediction_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        nonlocal predictions_frozen
        if predictions_frozen or (
            document.get("phase")
            != "ALL_EVALUATION_TRAJECTORIES_FROZEN_BEFORE_LABEL_SCORING"
            or document.get("evaluation_labels_materialized") != 0
            or document.get("evaluation_slow_updates") != 0
        ):
            raise Full256OnlineRealGateRunError("prediction freeze boundary differs")
        persist_group(artifacts, document, phase="EVALUATION_PREDICTIONS_FROZEN")
        predictions_frozen = True

    try:
        run.checkpoint(
            {
                "phase": "O1C_FULLROUND_ONLINE_REAL_GATE_RESERVED",
                "build_targets": gate.build_targets,
                "evaluation_targets": gate.evaluation_targets,
                "evaluation_split": gate.evaluation_split,
                "predictions_frozen": False,
                "evaluation_labels_materialized": 0,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "Full-round online O1 reader/picker gate started on CPU.\n"
        )
        with tempfile.TemporaryDirectory(prefix="o1c0018-real-gate-") as workspace:
            builder = Full256ProofPoolBuilder(
                root=root,
                config=proof,
                workspace=workspace,
            )
            result = run_full256_online_real_gate(
                gate,
                builder=builder,
                on_pool_frozen=pool_callback,
                on_build_prediction_frozen=build_prediction_callback,
                on_learning_frozen=learning_callback,
                on_predictions_frozen=prediction_callback,
            )
            builder.verify_sources_unchanged()
        if not predictions_frozen:
            raise Full256OnlineRealGateRunError(
                "evaluation predictions were not persisted before scoring"
            )

        labels_bytes = np.packbits(
            result.labels,
            axis=1,
            bitorder="little",
        ).tobytes(order="C")
        commitments = result.report["artifact_commitments"]
        scored_payloads = {
            "labels_sha256": labels_bytes,
            "raw_compressions_sha256": result.raw_compressions.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "policy_compressions_sha256": result.policy_compressions.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "iauc_sha256": result.iauc.astype("<f8", copy=False).tobytes(
                order="C"
            ),
            "primary_slow_state_sha256": result.primary_slow_state,
            "shifted_slow_state_sha256": result.shifted_slow_state,
            "static_reward_mean_sha256": result.static_reward_mean.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "build_reward_deltas_sha256": result.build_reward_deltas.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
        }
        if any(
            commitments.get(name) != hashlib.sha256(payload).hexdigest()
            for name, payload in scored_payloads.items()
        ):
            raise Full256OnlineRealGateRunError(
                "scored result artifact commitment differs"
            )
        final_artifacts = {
            "full256_online_real_gate.json": (
                json.dumps(
                    result.report,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("ascii"),
            "labels.bitpack": labels_bytes,
            "raw_compressions.f64le": result.raw_compressions.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "policy_compressions.f64le": result.policy_compressions.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "iauc.f64le": result.iauc.astype("<f8", copy=False).tobytes(
                order="C"
            ),
        }
        persist_group(
            final_artifacts,
            {"freeze_sha256": result.report["result_sha256"]},
            phase="POST_FREEZE_SCORED_RESULT",
        )
        artifact_index = {
            "schema": "o1-256-fullround-online-real-gate-artifact-index-v1",
            "attempt_id": attempt_id,
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
            {"freeze_sha256": result.report["result_sha256"]},
            phase="ARTIFACT_INDEX",
        )
        if _git_commit(root) != commit or _source_hashes(root, config_path) != hashes:
            raise Full256OnlineRealGateRunError("source changed during execution")

        parent_cpu_seconds = max(
            float(result.report["resources"]["cpu_seconds"]),
            time.process_time() - cpu_started,
        )
        children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
        child_cpu_seconds = max(
            children_finished.ru_utime
            + children_finished.ru_stime
            - child_cpu_started,
            0.0,
        )
        cpu_seconds = parent_cpu_seconds + child_cpu_seconds
        wall_seconds = max(
            float(result.report["resources"]["wall_seconds"]),
            time.monotonic() - wall_started,
        )
        pool_peak_rss_bytes = max(
            (
                int(
                    row["resources"].get(
                        "conservative_process_group_peak_rss_bytes",
                        row["resources"].get("peak_rss_bytes", 0),
                    )
                )
                for row in result.report["resources"]["pools"]
            ),
            default=0,
        )
        peak_rss_bytes = max(
            int(result.report["resources"]["process_peak_rss_bytes"]),
            pool_peak_rss_bytes,
            _process_peak_rss_bytes(),
        )
        if any(
            "total_native_solver_branches" not in row["resources"]
            for row in result.report["resources"]["pools"]
        ):
            raise Full256OnlineRealGateRunError(
                "native solver branch accounting is absent"
            )
        native_branches = sum(
            int(row["resources"]["total_native_solver_branches"])
            for row in result.report["resources"]["pools"]
        )
        physical_pools = int(
            result.report["resources"]["physical_public_pools_generated"]
        )
        expected_native_branches = physical_pools * 2 * 256
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= budgets.maximum_persistent_artifact_bytes,
            "physical_public_pools": physical_pools
            == budgets.maximum_physical_public_pools,
            "native_solver_branches": native_branches
            == expected_native_branches
            and native_branches <= budgets.maximum_native_solver_branches,
            "scientific_entropy": True,
            "sibling_reads": True,
            "sibling_writes": True,
            "mps": True,
            "gpu": True,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operational_failure = (
            result.report["classification"] == "OPERATIONAL_FAILURE"
        )
        operationally_complete = not failed_budgets and not operational_failure
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": result.report["classification"],
            "scientific_success_gate_passed": result.success_gate_passed,
            "result_sha256": result.report["result_sha256"],
            "raw_arms": result.report["raw_arms"],
            "policy_arms": result.report["policy_arms"],
            "margins": result.report["margins"],
            "gates": result.report["gates"],
            "cpu_seconds": cpu_seconds,
            "parent_cpu_seconds": parent_cpu_seconds,
            "child_cpu_seconds": child_cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "physical_public_pools": physical_pools,
            "native_solver_branches": native_branches,
            "expected_native_solver_branches": expected_native_branches,
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
                "predictions_frozen": predictions_frozen,
                "persistent_artifact_bytes": persistent_bytes,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and fix the exact lifecycle "
                "under a new attempt identity without replaying this corpus."
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
                "operational_failure": operational_failure,
                "primary_raw_mean_compression_bits": result.report["raw_arms"][
                    "learned_reader_full_field"
                ]["mean_compression_bits"],
                "true_picker_mean_iauc_bits": result.report["policy_arms"][
                    "learned_true_reward"
                ]["mean_iauc_bits"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the capsule-backed full-round online O1 real gate"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "Full256OnlineRealGateBudgets",
    "Full256OnlineRealGateRunError",
    "load_full256_online_real_gate_run_config",
    "main",
    "run_capsule_from_config",
]
