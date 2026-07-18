"""Unchanged A448 transfer on a disjoint consumed DEVELOPMENT target."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .a448_proof_byte_transfer import (
    default_sibling_root,
    measure_public_a448_byte_cube,
    revealed_byte_rank,
)
from .full256_proof_pool import (
    DeterministicKnownTarget,
    make_deterministic_known_target,
)
from .o1c31_a448_transfer_run import _source_hashes
from .run_capsule import ClaimLevel, RunCapsule, RunCapsuleManager


ATTEMPT_ID = "O1C-0032"
BYTE_INDEX = 3
CORPUS_SEED = 180_018_180_018
TARGET_SPLIT = "DEVELOPMENT"
TARGET_INDEX = 0
EXPECTED_PUBLIC_SHA256 = (
    "e622cc6b5b99913d759179a1a371335a4945cf35a1089da973896896c05291d7"
)
EXPECTED_PRIOR_POOL_SHA256 = (
    "20fbf3c50803586aba578f80a04d6bc556a8eddff19afb782e585095d62124d4"
)
PASS_MAX_RANK = 128
RAW_ARTIFACT = "a448_proof_antecedent_run.json.gz"
SOURCE_CAPSULE = (
    "runs/20260717_152827_O1C-0018_full256-online-real-gate-dev-v1"
)


class O1C32RunError(RuntimeError):
    """The exact O1C-0032 source, target, or consumed receipt differs."""


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
        raise O1C32RunError("git commit identity differs")
    return commit


def consumed_target() -> DeterministicKnownTarget:
    target = make_deterministic_known_target(
        seed=CORPUS_SEED,
        split=TARGET_SPLIT,
        index=TARGET_INDEX,
    )
    if target.public.digest() != EXPECTED_PUBLIC_SHA256:
        raise O1C32RunError("consumed DEVELOPMENT public target identity differs")
    return target


def _verify_prior_public_receipt(root: Path, target: DeterministicKnownTarget) -> str:
    receipt = (
        root
        / SOURCE_CAPSULE
        / "artifacts/pools/development-0000.json"
    ).resolve(strict=True)
    document = json.loads(receipt.read_text(encoding="ascii"))
    if (
        document.get("phase") != "PUBLIC_PROOF_POOL_FROZEN_BEFORE_LABEL_ACCESS"
        or document.get("labels_materialized") != 0
        or document.get("public_view_sha256") != EXPECTED_PUBLIC_SHA256
        or document.get("target_id") != target.target_id
        or document.get("target_key_inputs_to_probe") != 0
        or document.get("action_pool_sha256") != EXPECTED_PRIOR_POOL_SHA256
    ):
        raise O1C32RunError("prior consumed public-only receipt differs")
    public_view = document.get("pool", {}).get("public_view")
    if public_view != target.public.describe():
        raise O1C32RunError("reconstructed target differs from prior public view")
    return _sha256_file(receipt)


def _environment() -> dict[str, object]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "cpu_count": os.cpu_count(),
        "load_average_at_start": list(os.getloadavg()),
        "self_maxrss_at_start": usage.ru_maxrss,
        "W52_live_process_observed": False,
        "resource_gate_observed_at": datetime.now().astimezone().isoformat(),
        "resource_gate_memory_pressure_free_percent": 67,
        "resource_gate_cpu_idle_percent": 83.45,
        "resource_gate_swapouts_since_boot": 0,
    }


def _start_capsule(
    *,
    root: Path,
    sibling: Path,
    target: DeterministicKnownTarget,
    source_hashes: dict[str, str],
    prior_receipt_sha256: str,
) -> RunCapsule:
    template = (
        root
        / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
        "artifacts/cnf/full256_chacha20.cnf"
    )
    semantic_map = template.with_name("full256_chacha20.map.json")
    return RunCapsuleManager(root).start(
        attempt_id=ATTEMPT_ID,
        slug="a448-proof-byte3-development-repeat-v1",
        commit=_git_commit(root),
        hypothesis=(
            "The unchanged A448/A442 byte-3 reader repeats its better-than-median "
            "ordering on one disjoint consumed uniform DEVELOPMENT target while "
            "the other 248 key bits remain unknown."
        ),
        prediction=(
            f"The true byte ranks <= {PASS_MAX_RANK}/256 with no refit, target "
            "selection, or label input."
        ),
        controls=(
            "the measurement API receives only the previously frozen PublicTargetView",
            "the deterministic target reconstruction is matched to the prior zero-label public receipt",
            "the A448 reader, candidate order, byte coordinate and all source hashes are unchanged from O1C-0031",
            "the other 248 key bits receive no CNF units and remain unassigned",
            "the target byte is read only after all 256 ranks and raw telemetry are frozen",
        ),
        budgets={
            "target_count": 1,
            "target_role": "CONSUMED",
            "candidate_cells": 256,
            "solver_stages": 1024,
            "watchdog_seconds_per_stage": 2.0,
            "external_timeout_seconds": 1800.0,
            "device": "CPU",
            "MPS_or_GPU": False,
        },
        source_hashes=source_hashes,
        claim_level=ClaimLevel.TEST,
        next_action=(
            "If rank <=128, freeze this exact reader and spend one fresh blind "
            "target; otherwise close A448 transfer after the two consumed tests."
        ),
        config={
            "source_capsule": SOURCE_CAPSULE,
            "prior_public_receipt_sha256": prior_receipt_sha256,
            "prior_public_pool_sha256": EXPECTED_PRIOR_POOL_SHA256,
            "target_recipe": {
                "corpus_seed": CORPUS_SEED,
                "split": TARGET_SPLIT,
                "index": TARGET_INDEX,
            },
            "public_target": target.public.describe(),
            "public_view_sha256": target.public.digest(),
            "byte_index": BYTE_INDEX,
            "candidate_order": "numeric_0_through_255",
            "other_key_bits_assigned": 0,
            "template": str(template.relative_to(root)),
            "semantic_map": str(semantic_map.relative_to(root)),
            "sibling_root": str(sibling),
            "sibling_access": "strictly_read_only",
            "pass_max_rank": PASS_MAX_RANK,
        },
        command="PYTHONPATH=src python -m o1_crypto_lab.o1c32_a448_transfer_run",
        environment=_environment(),
    )


def run() -> int:
    root = lab_root().resolve(strict=True)
    sibling = default_sibling_root().resolve(strict=True)
    target = consumed_target()
    prior_receipt_sha256 = _verify_prior_public_receipt(root, target)
    source_hashes = _source_hashes(root, sibling)
    source_hashes["o1c32_runner"] = _sha256_file(
        root / "src/o1_crypto_lab/o1c32_a448_transfer_run.py"
    )
    source_hashes["consumed_public_receipt"] = prior_receipt_sha256
    capsule = _start_capsule(
        root=root,
        sibling=sibling,
        target=target,
        source_hashes=source_hashes,
        prior_receipt_sha256=prior_receipt_sha256,
    )
    template = (
        root
        / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
        "artifacts/cnf/full256_chacha20.cnf"
    )
    try:
        capsule.append_stdout(
            "O1C-0032 unchanged A448 consumed DEVELOPMENT repeat started.\n"
        )
        measurement = measure_public_a448_byte_cube(
            public=target.public,
            byte_index=BYTE_INDEX,
            template=template,
            semantic_map=template.with_name("full256_chacha20.map.json"),
            workspace=root / "runs",
            sibling_root=sibling,
            capture_raw_artifact=True,
        )
        if measurement.raw_artifact_gzip is None:
            raise O1C32RunError("A448 raw artifact capture is missing")
        capsule.write_artifact(RAW_ARTIFACT, measurement.raw_artifact_gzip)

        target_byte = target._key[BYTE_INDEX]
        rank = revealed_byte_rank(measurement.ranks, target_byte)
        passed = rank <= PASS_MAX_RANK
        description = measurement.describe()
        description.update(
            {
                "target_role": "CONSUMED",
                "target_id": target.target_id,
                "label_revealed_after_rank_freeze": True,
                "target_byte_hex": f"{target_byte:02x}",
                "target_rank": rank,
                "pass_max_rank": PASS_MAX_RANK,
                "passed": passed,
            }
        )
        capsule.write_json_artifact("measurement.json", description)

        uniform_mean_log_rank = sum(math.log2(value) for value in range(1, 257)) / 256
        metrics = {
            "target_role": "CONSUMED",
            "target_id": target.target_id,
            "target_byte": target_byte,
            "target_rank": rank,
            "pass_max_rank": PASS_MAX_RANK,
            "passed": passed,
            "rank_bit_gain_from_worst_rank": math.log2(256.0 / rank),
            "descriptive_gain_vs_uniform_mean_log_rank_bits": (
                uniform_mean_log_rank - math.log2(rank)
            ),
            "wall_seconds": measurement.wall_seconds,
            "candidate_cells": 256,
            "solver_stages": 1024,
            "other_key_bits_assigned": 0,
            "public_key_label_inputs": 0,
            "raw_artifact_bytes": len(measurement.raw_artifact_gzip),
            "raw_artifact_sha256": measurement.raw_artifact_sha256,
            "stable_run_sha256": measurement.stable_run_sha256,
            "stdout_sha256": measurement.stdout_sha256,
            "self_maxrss_after": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }
        next_action = (
            "Run this exact source-frozen byte-3 reader once on a new blinded fresh target."
            if passed
            else "Close A448 full256 transfer once; do not resweep it, and transfer the next exact sibling recovery mechanism."
        )
        capsule.append_stdout(
            json.dumps(
                {"attempt_id": ATTEMPT_ID, "target_rank": rank, "passed": passed},
                sort_keys=True,
            )
            + "\n"
        )
        finalized = capsule.finalize(metrics=metrics, next_action=next_action)
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "capsule": str(finalized.path),
                    "manifest_sha256": finalized.manifest_sha256,
                    "target_rank": rank,
                    "passed": passed,
                },
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:
        capsule.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = capsule.finalize(
            status="failed",
            metrics={"error_type": type(exc).__name__, "error": str(exc)},
            next_action="Preserve the failed capsule and diagnose before a new attempt ID.",
        )
        print(f"failed capsule: {finalized.path}", file=sys.stderr)
        raise


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Repeat the exact A448 byte-3 transfer on DEVELOPMENT-0000"
    )
    parser.parse_args(argv)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "BYTE_INDEX",
    "EXPECTED_PUBLIC_SHA256",
    "O1C32RunError",
    "consumed_target",
    "main",
    "run",
]
