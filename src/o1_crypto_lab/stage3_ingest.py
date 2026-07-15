"""Configured, reproducible Stage-3 dataset ingestion pipeline."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .artifacts import ReadOnlyArtifactSource
from .stage3 import (
    DatasetSplit,
    Stage3Dataset,
    Stage3Error,
    Stage3TrajectoryAdapter,
    a296_a297_specs,
)


@dataclass(frozen=True)
class Stage3IngestResult:
    dataset: Stage3Dataset
    config_sha256: str
    source_commit: str
    manifest_sha256: str
    selected_members_verified: int

    def metrics(self) -> dict[str, object]:
        counts = self.dataset.describe()["counts"]
        return {
            "schema": "o1-crypto-stage3-ingest-metrics-v1",
            "dataset_sha256": self.dataset.dataset_sha256,
            "feature_schema_sha256": self.dataset.describe()[
                "feature_schema_sha256"
            ],
            "episodes": counts["episodes"],
            "cells": counts["cells"],
            "stages": counts["stages"],
            "by_split": counts["by_split"],
            "feature_count": len(self.dataset.episodes[0].cells[0].values),
            "selected_members_verified": self.selected_members_verified,
            "source_commit": self.source_commit,
            "manifest_sha256": self.manifest_sha256,
            "config_sha256": self.config_sha256,
            "target_labels_read": 0,
            "post_reveal_members_read": 0,
            "gpu_seconds": 0,
            "external_solver_calls": 0,
        }


def _read_config(path: Path) -> tuple[dict[str, object], str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Stage3Error("ingest config is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise Stage3Error("ingest config must be a JSON object")
    if value.get("schema") != "o1-crypto-stage3-ingest-config-v1":
        raise Stage3Error("unsupported ingest config schema")
    return value, hashlib.sha256(raw).hexdigest()


def _source_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise Stage3Error("could not pin the source repository commit")
    commit = result.stdout.strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise Stage3Error("source repository returned an invalid commit")
    return commit


def _expected_split_ledger(specs) -> dict[str, list[str]]:
    return {
        split.value: [
            f"{spec.family}/{spec.target_id}"
            for spec in specs
            if spec.split is split
        ]
        for split in DatasetSplit
        if split is not DatasetSplit.SEALED_DEPLOYMENT
    }


def run_stage3_ingest(
    config_path: str | Path,
    *,
    lab_root: str | Path | None = None,
) -> Stage3IngestResult:
    config_path = Path(config_path).resolve()
    config, config_sha256 = _read_config(config_path)
    selected_lab_root = (
        Path(lab_root).resolve()
        if lab_root is not None
        else Path(__file__).resolve().parents[2]
    )
    source_config = config.get("source")
    if not isinstance(source_config, Mapping):
        raise Stage3Error("config.source must be an object")
    repository = source_config.get("repository")
    manifest_member = source_config.get("manifest")
    if not isinstance(repository, str) or not isinstance(manifest_member, str):
        raise Stage3Error("config source repository/manifest must be strings")
    source_root = (selected_lab_root / repository).resolve()
    expected_commit = source_config.get("expected_commit")
    actual_commit = _source_commit(source_root)
    if actual_commit != expected_commit:
        raise Stage3Error(
            f"source commit changed: expected {expected_commit}, found {actual_commit}"
        )
    manifest_path = (source_root / manifest_member).resolve()
    source = ReadOnlyArtifactSource(source_root, manifest_path)
    if source.manifest_sha256 != source_config.get("expected_manifest_sha256"):
        raise Stage3Error("source manifest hash changed")

    specs = a296_a297_specs()
    configured_ledger = config.get("split_ledger")
    expected_ledger = _expected_split_ledger(specs)
    if configured_ledger != expected_ledger:
        raise Stage3Error("config split ledger disagrees with the adapter ledger")
    members = tuple(
        member
        for spec in specs
        for member in (spec.measurement_member, spec.order_member)
    )
    verification = source.verify(members)
    if not verification.ok or verification.checked != len(members):
        raise Stage3Error("selected source members failed manifest verification")
    budgets = config.get("budgets")
    if not isinstance(budgets, Mapping):
        raise Stage3Error("config.budgets must be an object")
    max_raw_bytes = budgets.get("max_raw_bytes_per_episode")
    if not isinstance(max_raw_bytes, int) or isinstance(max_raw_bytes, bool):
        raise Stage3Error("max_raw_bytes_per_episode must be an integer")
    denied = config.get("denied_member_fragments")
    if not isinstance(denied, list) or not all(isinstance(value, str) for value in denied):
        raise Stage3Error("denied_member_fragments must be a string list")
    dataset = Stage3TrajectoryAdapter(
        source,
        max_raw_bytes=max_raw_bytes,
        denied_member_fragments=denied,
    ).load_dataset(str(config.get("dataset_name")), specs)
    counts = dataset.describe()["counts"]
    for field, observed in (
        ("expected_episodes", counts["episodes"]),
        ("expected_cells", counts["cells"]),
        ("expected_stages", counts["stages"]),
    ):
        if budgets.get(field) != observed:
            raise Stage3Error(
                f"{field} disagrees with ingested dataset: {budgets.get(field)} != {observed}"
            )
    return Stage3IngestResult(
        dataset=dataset,
        config_sha256=config_sha256,
        source_commit=actual_commit,
        manifest_sha256=source.manifest_sha256,
        selected_members_verified=verification.checked,
    )
