"""Frozen retrospective reader tournament over the normalized Stage-3 corpus."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean, median
from typing import Callable, Mapping, Sequence

from .stage3 import (
    FEATURE_NAMES,
    DatasetSplit,
    RevealedCellLabel,
    Stage3Error,
)
from .stage3_ingest import run_stage3_ingest
from .trajectory_reader import (
    CandidateBlindRankings,
    FrozenReaderPlan,
    RankedEpisode,
    RankingEvaluation,
    RetrospectiveReader,
    baseline_rankings,
    evaluate_rankings,
)
from .types import InformationLabel


class ReaderExperimentError(ValueError):
    pass


FreezeCallback = Callable[[FrozenReaderPlan, Mapping[str, object]], None]


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def _load_config(path: Path) -> tuple[dict[str, object], str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReaderExperimentError("reader config is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != "o1-crypto-stage3-reader-config-v1":
        raise ReaderExperimentError("unsupported reader config schema")
    return value, hashlib.sha256(raw).hexdigest()


def _broker_labels(
    *,
    source_root: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
    result_member: str,
    target_ids: Sequence[str],
    purpose: str,
    timeout_seconds: int = 30,
) -> tuple[tuple[RevealedCellLabel, ...], dict[str, object]]:
    command = [
        sys.executable,
        "-m",
        "o1_crypto_lab.label_broker",
        "--source-root",
        str(source_root),
        "--manifest",
        str(manifest_path),
        "--expected-manifest-sha256",
        expected_manifest_sha256,
        "--result-member",
        result_member,
        "--purpose",
        purpose,
    ]
    for target_id in target_ids:
        command.extend(("--target-id", target_id))
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip()
        raise ReaderExperimentError(f"label broker failed: {message}")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ReaderExperimentError("label broker returned invalid JSON") from exc
    if not isinstance(response, dict) or response.get("schema") != "o1-crypto-label-broker-response-v1":
        raise ReaderExperimentError("label broker returned an unsupported response")
    raw_labels = response.get("labels")
    if not isinstance(raw_labels, list):
        raise ReaderExperimentError("label broker response lacks labels")
    labels: list[RevealedCellLabel] = []
    for raw in raw_labels:
        if not isinstance(raw, dict):
            raise ReaderExperimentError("label broker emitted a non-object label")
        try:
            labels.append(
                RevealedCellLabel(
                    family=str(raw["family"]),
                    target_id=str(raw["target_id"]),
                    split=DatasetSplit(str(raw["split"])),
                    correct_cell=int(raw["correct_cell"]),
                    source_member=str(raw["source_member"]),
                    source_sha256=str(raw["source_sha256"]),
                    information_label=InformationLabel(str(raw["information_label"])),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ReaderExperimentError("label broker emitted an invalid label") from exc
    if {label.target_id for label in labels} != set(target_ids):
        raise ReaderExperimentError("label broker did not return the exact target allowlist")
    receipt = {
        "schema": "o1-crypto-parent-label-broker-receipt-v1",
        "purpose": purpose,
        "requested_targets": list(target_ids),
        "response_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "broker_access_log": response.get("access_log"),
        "information_boundary": response.get("information_boundary"),
    }
    return tuple(labels), receipt


def _rankings_document(rankings: Sequence[RankedEpisode]) -> list[dict[str, object]]:
    return [ranking.describe() for ranking in rankings]


def _baseline_evaluations(
    episodes,
    labels: Sequence[RevealedCellLabel],
) -> dict[str, RankingEvaluation]:
    grouped: dict[str, list[RankedEpisode]] = {}
    for episode in episodes:
        for ranking in baseline_rankings(episode):
            grouped.setdefault(ranking.reader_name, []).append(ranking)
    return {
        name: evaluate_rankings(rankings, labels)
        for name, rankings in sorted(grouped.items())
    }


def _exact_familywise_selection_null(
    blind_candidates: Sequence[CandidateBlindRankings],
    observed_mean_gain: float,
) -> dict[str, object]:
    """Exact two-target null including the full 119-reader selection step."""

    if not blind_candidates:
        raise ReaderExperimentError("selection null requires candidate rankings")
    if any(len(candidate.rankings) != 2 for candidate in blind_candidates):
        raise ReaderExperimentError("exact selection null is defined for two validation targets")
    gain_by_rank = [0.0] + [math.log2(256.0 / rank) for rank in range(1, 257)]
    gain_tables: list[tuple[tuple[float, ...], tuple[float, ...]]] = []
    for candidate in blind_candidates:
        tables: list[tuple[float, ...]] = []
        for ranking in candidate.rankings:
            ranks = [0] * 256
            for position, cell in enumerate(ranking.order, start=1):
                ranks[cell] = position
            tables.append(tuple(gain_by_rank[rank] for rank in ranks))
        gain_tables.append((tables[0], tables[1]))
    maxima: list[float] = []
    exceedances = 0
    tolerance = 1e-12
    for first_cell in range(256):
        first_values = tuple(table[0][first_cell] for table in gain_tables)
        for second_cell in range(256):
            best = max(
                (first_values[index] + gain_tables[index][1][second_cell]) / 2.0
                for index in range(len(gain_tables))
            )
            maxima.append(best)
            if best + tolerance >= observed_mean_gain:
                exceedances += 1
    maxima.sort()

    def quantile(probability: float) -> float:
        index = round(probability * (len(maxima) - 1))
        return maxima[index]

    return {
        "schema": "o1-crypto-exact-familywise-selection-null-v1",
        "null": "two independent uniformly random correct cells over 0..255",
        "candidate_operators": len(blind_candidates),
        "label_pairs_enumerated": len(maxima),
        "observed_selected_mean_log2_rank_gain": observed_mean_gain,
        "familywise_p_ge_observed": exceedances / len(maxima),
        "null_best_mean_gain": fmean(maxima),
        "null_best_median_gain": float(median(maxima)),
        "null_best_quantiles": {
            "q50": quantile(0.50),
            "q90": quantile(0.90),
            "q95": quantile(0.95),
            "q99": quantile(0.99),
        },
    }


@dataclass(frozen=True)
class ReaderExperimentResult:
    plan: FrozenReaderPlan
    report: dict[str, object]
    config_sha256: str
    success_gate_passed: bool

    def metrics(self) -> dict[str, object]:
        evaluations = self.report["evaluations"]
        selected = {
            split: values["selected"]["summary"]
            for split, values in evaluations.items()
        }
        return {
            "schema": "o1-crypto-stage3-reader-metrics-v1",
            "plan_sha256": self.plan.plan_sha256,
            "selected_operator": self.plan.selected_operator.name,
            "selected_feature": (
                FEATURE_NAMES[self.plan.selected_operator.feature_index]
                if self.plan.selected_operator.kind == "feature"
                else None
            ),
            "candidate_operators": len(self.plan.candidate_validation),
            "validation": selected[DatasetSplit.VALIDATION.value],
            "retrospective_holdout": selected[
                DatasetSplit.RETROSPECTIVE_HOLDOUT.value
            ],
            "transfer_holdout": selected[DatasetSplit.TRANSFER_HOLDOUT.value],
            "familywise_validation_selection_null": self.report[
                "familywise_validation_selection_null"
            ],
            "success_gate_passed": self.success_gate_passed,
            "gpu_seconds": 0,
            "external_solver_calls": 0,
            "holdout_labels_read_before_freeze": 0,
        }


def run_reader_experiment(
    config_path: str | Path,
    *,
    lab_root: str | Path | None = None,
    on_frozen: FreezeCallback,
) -> ReaderExperimentResult:
    config_path = Path(config_path).resolve()
    config, config_sha256 = _load_config(config_path)
    root = (
        Path(lab_root).resolve()
        if lab_root is not None
        else Path(__file__).resolve().parents[2]
    )
    ingest_config = root / str(config.get("ingest_config"))
    ingest = run_stage3_ingest(ingest_config, lab_root=root)
    dataset = ingest.dataset
    if dataset.dataset_sha256 != config.get("expected_dataset_sha256"):
        raise ReaderExperimentError("reader dataset hash changed")
    source_config = config.get("source")
    phases = config.get("label_phases")
    if not isinstance(source_config, Mapping) or not isinstance(phases, Mapping):
        raise ReaderExperimentError("reader config source/label_phases must be objects")
    source_root = (root / str(source_config["repository"])).resolve()
    manifest_path = source_root / str(source_config["manifest"])
    expected_manifest = str(source_config["expected_manifest_sha256"])

    receipts: list[dict[str, object]] = []

    def phase_labels(split: DatasetSplit, purpose: str):
        raw = phases.get(split.value)
        if not isinstance(raw, Mapping):
            raise ReaderExperimentError(f"missing label phase {split.value}")
        target_ids = raw.get("target_ids")
        if not isinstance(target_ids, list) or not all(
            isinstance(value, str) for value in target_ids
        ):
            raise ReaderExperimentError(f"invalid target IDs for {split.value}")
        labels, receipt = _broker_labels(
            source_root=source_root,
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest,
            result_member=str(raw.get("result_member")),
            target_ids=target_ids,
            purpose=purpose,
        )
        receipts.append(receipt)
        return labels

    reader = RetrospectiveReader(dataset)
    train_labels = phase_labels(
        DatasetSplit.TRAIN, "fit the declared retrospective TRAIN readers"
    )
    candidate_names = reader.fit(train_labels)
    expected_candidates = config.get("budgets", {}).get("candidate_operators")  # type: ignore[union-attr]
    if len(candidate_names) != expected_candidates:
        raise ReaderExperimentError("candidate count changed from the frozen budget")

    # Score validation before allowing the broker to reveal validation labels.
    blind_validation = reader.score_candidates(DatasetSplit.VALIDATION)
    blind_validation_sha = _canonical_sha256(
        [
            {
                "operator_name": candidate.operator_name,
                "orders": [list(ranking.order) for ranking in candidate.rankings],
            }
            for candidate in blind_validation
        ]
    )
    validation_labels = phase_labels(
        DatasetSplit.VALIDATION,
        "select one TRAIN-fitted reader on the declared VALIDATION split",
    )
    plan = reader.freeze(validation_labels)
    selected_validation = reader.evaluate(validation_labels)

    # Every holdout order, plus all equal-work controls, is materialized before a
    # holdout label broker is called. The callback must persist/hash this boundary.
    pre_reveal: dict[str, object] = {
        "schema": "o1-crypto-stage3-pre-reveal-freeze-v1",
        "plan_sha256": plan.plan_sha256,
        "blind_validation_orders_sha256": blind_validation_sha,
        "holdout": {},
        "holdout_labels_read": 0,
    }
    selected_rankings: dict[DatasetSplit, tuple[RankedEpisode, ...]] = {}
    baseline_rankings_by_split: dict[
        DatasetSplit, dict[str, tuple[RankedEpisode, ...]]
    ] = {}
    for split in (
        DatasetSplit.RETROSPECTIVE_HOLDOUT,
        DatasetSplit.TRANSFER_HOLDOUT,
    ):
        selected_rankings[split] = reader.rank_split(split)
        episodes = tuple(
            episode for episode in dataset.episodes if episode.spec.split is split
        )
        grouped: dict[str, list[RankedEpisode]] = {}
        for episode in episodes:
            for ranking in baseline_rankings(episode):
                grouped.setdefault(ranking.reader_name, []).append(ranking)
        baseline_rankings_by_split[split] = {
            name: tuple(rankings) for name, rankings in sorted(grouped.items())
        }
        pre_reveal["holdout"][split.value] = {  # type: ignore[index]
            "selected": _rankings_document(selected_rankings[split]),
            "controls": {
                name: _rankings_document(rankings)
                for name, rankings in baseline_rankings_by_split[split].items()
            },
        }
    pre_reveal["pre_reveal_sha256"] = _canonical_sha256(pre_reveal)
    on_frozen(plan, pre_reveal)

    retrospective_labels = phase_labels(
        DatasetSplit.RETROSPECTIVE_HOLDOUT,
        "evaluate the already frozen A296 retrospective holdout orders",
    )
    transfer_labels = phase_labels(
        DatasetSplit.TRANSFER_HOLDOUT,
        "evaluate the already frozen A297 W32 transfer orders",
    )
    labels_by_split = {
        DatasetSplit.RETROSPECTIVE_HOLDOUT: retrospective_labels,
        DatasetSplit.TRANSFER_HOLDOUT: transfer_labels,
    }
    evaluations: dict[str, object] = {
        DatasetSplit.VALIDATION.value: {
            "selected": selected_validation.describe(),
        }
    }
    success = True
    for split, labels in labels_by_split.items():
        selected_evaluation = reader.evaluate(labels)
        controls = {
            name: evaluate_rankings(rankings, labels)
            for name, rankings in baseline_rankings_by_split[split].items()
        }
        evaluations[split.value] = {
            "selected": selected_evaluation.describe(),
            "controls": {
                name: evaluation.describe()
                for name, evaluation in controls.items()
            },
        }
        selected_gain = selected_evaluation.mean_log2_rank_gain
        success = success and selected_gain > 0.0 and all(
            selected_gain > evaluation.mean_log2_rank_gain
            for evaluation in controls.values()
        )

    selected_validation_metric = next(
        metric
        for metric in plan.candidate_validation
        if metric.operator_name == plan.selected_operator.name
    )
    familywise_null = _exact_familywise_selection_null(
        blind_validation,
        selected_validation_metric.mean_log2_rank_gain,
    )
    report = {
        "schema": "o1-crypto-stage3-reader-experiment-v1",
        "config_sha256": config_sha256,
        "dataset_sha256": dataset.dataset_sha256,
        "plan": plan.describe(),
        "pre_reveal_freeze": pre_reveal,
        "evaluations": evaluations,
        "familywise_validation_selection_null": familywise_null,
        "label_broker_receipts": receipts,
        "work_accounting": {
            "candidate_operators": len(candidate_names),
            "dataset_episodes": len(dataset.episodes),
            "dataset_cells": sum(len(episode.cells) for episode in dataset.episodes),
            "gpu_seconds": 0,
            "external_solver_calls": 0,
            "familywise_null_label_pairs": familywise_null[
                "label_pairs_enumerated"
            ],
        },
        "success_gate_passed": success,
        "mechanistic_breadcrumb": {
            "selected_operator": plan.selected_operator.name,
            "selected_feature": (
                FEATURE_NAMES[plan.selected_operator.feature_index]
                if plan.selected_operator.kind == "feature"
                else None
            ),
            "interpretation": (
                "A validation-selected trajectory component is informative but not "
                "a stable cross-target winner unless both holdout gates pass."
            ),
        },
    }
    return ReaderExperimentResult(
        plan=plan,
        report=report,
        config_sha256=config_sha256,
        success_gate_passed=success,
    )


__all__ = [
    "ReaderExperimentError",
    "ReaderExperimentResult",
    "run_reader_experiment",
]
