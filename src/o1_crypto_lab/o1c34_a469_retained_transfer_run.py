"""Apply frozen A469 to O1C-0033's label-free retained A465 fields."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import subprocess
import time
from pathlib import Path
from typing import Sequence

import numpy as np

from .a448_proof_byte_transfer import default_sibling_root
from .a469_conditional_transfer import (
    A467_SOURCE_RELATIVE,
    A469_RESULT_RELATIVE,
    A469_SOURCE_RELATIVE,
    A469_SELECTED_SPEC,
    a465_field_from_description,
    a469_rank_field_from_a465,
    load_frozen_a469_model,
)
from .living_inverse import canonical_sha256
from .o1c33_a465_retained_transfer_run import TARGETS, _revealed_target_bytes
from .run_capsule import ClaimLevel, RunCapsuleManager


ATTEMPT_ID = "O1C-0034"
BYTE_INDEX = 3
PASS_MAX_RANK = 128
SOURCE_CAPSULE = Path(
    "runs/20260718_180604_O1C-0033_a465-retained-two-target-full256-transfer-v1"
)
SOURCE_MANIFEST_SHA256 = (
    "7c11e863f2c05e254249f5dd67117fcfad603675d0355657ba9d28b8b6f87b08"
)
SOURCE_FREEZE_SHA256 = (
    "711aff0787185a80071ec85194bc5b9a78c8ba897fdaf375ce478fc4d8c3e95f"
)


class O1C34RunError(RuntimeError):
    """The frozen O1C-0033 fields or A469 source differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit(root: Path) -> str:
    result = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if len(commit) != 40:
        raise O1C34RunError("git commit identity differs")
    return commit


def _load_source_freeze(root: Path) -> tuple[dict[str, object], Path]:
    capsule = (root / SOURCE_CAPSULE).resolve(strict=True)
    verification = RunCapsuleManager(root).verify(capsule)
    if (
        not verification.ok
        or verification.manifest_sha256 != SOURCE_MANIFEST_SHA256
    ):
        raise O1C34RunError("O1C-0033 capsule differs")
    path = (capsule / "artifacts/prediction_freeze.json").resolve(strict=True)
    value = json.loads(path.read_text(encoding="ascii"))
    if (
        value.get("phase") != "BOTH_RANK_FIELDS_FROZEN_BEFORE_LABEL_RECONSTRUCTION"
        or value.get("freeze_sha256") != SOURCE_FREEZE_SHA256
        or value.get("target_key_inputs") != 0
        or value.get("new_solver_stages") != 0
        or not isinstance(value.get("predictions"), dict)
    ):
        raise O1C34RunError("O1C-0033 prediction freeze differs")
    return value, path


def run() -> int:
    root = lab_root().resolve(strict=True)
    sibling = default_sibling_root().resolve(strict=True)
    source, source_path = _load_source_freeze(root)
    model = load_frozen_a469_model(sibling)
    source_hashes = {
        "a469_transfer": _sha256_file(root / "src/o1_crypto_lab/a469_conditional_transfer.py"),
        "o1c34_runner": _sha256_file(root / "src/o1_crypto_lab/o1c34_a469_retained_transfer_run.py"),
        "o1c33_prediction_freeze": _sha256_file(source_path),
        "sibling_A467_source": _sha256_file((sibling / A467_SOURCE_RELATIVE).resolve(strict=True)),
        "sibling_A469_source": _sha256_file((sibling / A469_SOURCE_RELATIVE).resolve(strict=True)),
        "sibling_A469_result": _sha256_file((sibling / A469_RESULT_RELATIVE).resolve(strict=True)),
    }
    if source_hashes["sibling_A469_result"] != model.result_sha256:
        raise O1C34RunError("A469 result anchor differs")
    capsule = RunCapsuleManager(root).start(
        attempt_id=ATTEMPT_ID,
        slug="a469-retained-two-target-full256-transfer-v1",
        commit=_git_commit(root),
        hypothesis=(
            "A469's unchanged sparse bucket-local correction improves A465's "
            "two retained all256 byte-3 rankings without crossing any A465 bucket."
        ),
        prediction=(
            f"Both consumed targets rank <= {PASS_MAX_RANK}/256; only then may "
            "the exact A469 reader earn one fresh blind target."
        ),
        controls=(
            "input is O1C-0033's verified label-free two-target A465 prediction freeze",
            "A469 copula tables, residual table, selected gate and tie policy are hash-frozen",
            "both A469 fields are persisted before either target byte is reconstructed",
            "A469 may reorder only within eight fixed A465 rank buckets",
            "zero new solver stages, fits, targets, coefficients, bytes or operators",
        ),
        budgets={
            "target_count": 2,
            "target_role": "CONSUMED",
            "new_solver_stages": 0,
            "new_target_count": 0,
            "maximum_wall_seconds": 10.0,
            "maximum_resident_memory_mib": 512,
            "MPS_or_GPU": False,
        },
        source_hashes=source_hashes,
        claim_level=ClaimLevel.TEST,
        next_action=(
            "If both ranks <=128, run unchanged once on a fresh blind target; "
            "otherwise close A469 all256 transfer without a resweep."
        ),
        config={
            "source_capsule": str(SOURCE_CAPSULE),
            "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
            "source_prediction_freeze_sha256": SOURCE_FREEZE_SHA256,
            "byte_index": BYTE_INDEX,
            "selected_spec": A469_SELECTED_SPEC,
            "target_labels_in_prediction": 0,
            "new_solver_stages": 0,
            "sibling_access": "strictly_read_only",
            "pass_max_rank": PASS_MAX_RANK,
        },
        command="PYTHONPATH=src python -m o1_crypto_lab.o1c34_a469_retained_transfer_run",
        environment={
            "cpu_count": os.cpu_count(),
            "load_average_at_start": list(os.getloadavg()),
            "self_maxrss_at_start": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "W52_live_process_observed": False,
        },
    )
    started = time.perf_counter()
    try:
        upstream = source["predictions"]
        if not isinstance(upstream, dict):
            raise O1C34RunError("O1C-0033 predictions differ")
        predictions = {}
        fields = {}
        for target in TARGETS:
            description = upstream.get(target.target_id)
            if not isinstance(description, dict):
                raise O1C34RunError(f"A465 field missing: {target.target_id}")
            field = a469_rank_field_from_a465(
                a465_field_from_description(description), model=model
            )
            fields[target.target_id] = field
            predictions[target.target_id] = {
                "target_id": target.target_id,
                "role": "CONSUMED",
                "public_view_sha256": target.public_view_sha256,
                **field.describe(),
            }
        freeze_without_hash = {
            "schema": "o1-256-a469-retained-prediction-freeze-v1",
            "phase": "BOTH_A469_FIELDS_FROZEN_BEFORE_LABEL_RECONSTRUCTION",
            "target_count": 2,
            "target_key_inputs": 0,
            "new_solver_stages": 0,
            "predictions": predictions,
        }
        freeze = {
            **freeze_without_hash,
            "freeze_sha256": canonical_sha256(freeze_without_hash),
        }
        capsule.write_json_artifact("prediction_freeze.json", freeze)

        truths = _revealed_target_bytes()
        rows = []
        ranks: list[int] = []
        passed_flags: list[bool] = []
        for target in TARGETS:
            field = fields[target.target_id]
            truth = truths[target.target_id]
            rank = int(field.final_ranks[truth])
            passed_target = rank <= PASS_MAX_RANK
            ranks.append(rank)
            passed_flags.append(passed_target)
            rows.append(
                {
                    "target_id": target.target_id,
                    "target_byte_hex": f"{truth:02x}",
                    "A465_rank": int(field.base_ranks[truth]),
                    "interaction_rank": int(field.interaction_ranks[truth]),
                    "A469_rank": rank,
                    "truth_correction_gate": bool(field.correction_gate[truth]),
                    "truth_correction_score": int(field.correction_score[truth]),
                    "active_correction_cells": int(np.count_nonzero(field.correction_gate)),
                    "changed_rank_cells": int(np.count_nonzero(field.final_ranks != field.base_ranks)),
                    "passed_median_gate": passed_target,
                }
            )
        passed = all(passed_flags)
        uniform_mean_log_rank = sum(math.log2(value) for value in range(1, 257)) / 256
        elapsed = time.perf_counter() - started
        result = {
            "schema": "o1-256-a469-retained-transfer-result-v1",
            "decision": "PASS_TO_FRESH" if passed else "CLOSED_NOT_REPLICATED",
            "prediction_freeze_sha256": freeze["freeze_sha256"],
            "label_revealed_after_prediction_freeze": True,
            "targets": rows,
            "aggregate": {
                "ranks": ranks,
                "both_passed_median_gate": passed,
                "mean_rank": sum(ranks) / len(ranks),
                "geometric_mean_rank": math.sqrt(ranks[0] * ranks[1]),
                "descriptive_ranking_bit_delta": (
                    uniform_mean_log_rank
                    - sum(math.log2(rank) for rank in ranks) / len(ranks)
                ),
            },
            "elapsed_seconds": elapsed,
        }
        capsule.write_json_artifact("result.json", result)
        next_action = (
            "Execute this exact A469 reader on one new blinded full256 target."
            if passed
            else "Close A469 all256 byte transfer; do not resweep and move to the next exact all-unknown sibling channel."
        )
        finalized = capsule.finalize(
            metrics={
                "target_count": 2,
                "new_solver_stages": 0,
                "new_targets": 0,
                "ranks": ranks,
                "both_passed_median_gate": passed,
                "elapsed_seconds": elapsed,
                "self_maxrss_after": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            },
            next_action=next_action,
        )
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "capsule": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "ranks": ranks,
                    "passed": passed,
                },
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:
        capsule.append_stderr(f"{type(exc).__name__}: {exc}\n")
        capsule.finalize(
            status="failed",
            metrics={"error_type": type(exc).__name__, "error": str(exc)},
            next_action="Preserve the failed capsule and repair under a new attempt ID.",
        )
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply exact A469 to two retained all256 A465 fields"
    )
    parser.parse_args(argv)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ATTEMPT_ID", "BYTE_INDEX", "O1C34RunError", "main", "run"]
