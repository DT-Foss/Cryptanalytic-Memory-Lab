"""Capsule-backed consumed full-256 transfer of the frozen sibling A448 reader."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from .a448_proof_byte_transfer import (
    A448_FEATURE_SOURCE_RELATIVE,
    A448_FEATURE_SOURCE_SHA256,
    A448_HELPER_RELATIVE,
    A448_HELPER_SHA256,
    A448_IDENTITY_WRAPPER_RELATIVE,
    A448_IDENTITY_WRAPPER_SHA256,
    A448_MULTIHORIZON_WRAPPER_RELATIVE,
    A448_MULTIHORIZON_WRAPPER_SHA256,
    A448_SHAPE_SOURCE_RELATIVE,
    A448_SHAPE_SOURCE_SHA256,
    A448_WRAPPER_RELATIVE,
    A448_WRAPPER_SHA256,
    default_sibling_root,
    measure_public_a448_byte_cube,
    revealed_byte_rank,
)
from .living_inverse import build_known_target
from .run_capsule import ClaimLevel, RunCapsule, RunCapsuleManager


ATTEMPT_ID = "O1C-0031"
BYTE_INDEX = 3
EXPECTED_PUBLIC_SHA256 = (
    "50ed1436504231b7c3a68558d1e3c27e4e197e83acf0aa02e53b32e4d9d41d00"
)
PASS_MAX_RANK = 128
RAW_ARTIFACT = "a448_proof_antecedent_run.json.gz"


class O1C31RunError(RuntimeError):
    """The exact O1C-0031 source, capsule, or consumed target differs."""


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
        raise O1C31RunError("git commit identity differs")
    return commit


def _source_hashes(root: Path, sibling: Path) -> dict[str, str]:
    sources = {
        "a448_transfer": root / "src/o1_crypto_lab/a448_proof_byte_transfer.py",
        "o1c31_runner": root / "src/o1_crypto_lab/o1c31_a448_transfer_run.py",
        "a296_cube": root / "src/o1_crypto_lab/a296_shallow_byte_cube.py",
        "shape532": root / "src/o1_crypto_lab/shape532.py",
        "full256_cnf": root / "src/o1_crypto_lab/full256_cnf.py",
        "run_capsule": root / "src/o1_crypto_lab/run_capsule.py",
        "template": (
            root
            / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
            "artifacts/cnf/full256_chacha20.cnf"
        ),
        "semantic_map": (
            root
            / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
            "artifacts/cnf/full256_chacha20.map.json"
        ),
        "sibling_helper": sibling / A448_HELPER_RELATIVE,
        "sibling_wrapper": sibling / A448_WRAPPER_RELATIVE,
        "sibling_identity_wrapper": sibling / A448_IDENTITY_WRAPPER_RELATIVE,
        "sibling_multihorizon_wrapper": (
            sibling / A448_MULTIHORIZON_WRAPPER_RELATIVE
        ),
        "sibling_proof_features": sibling / A448_FEATURE_SOURCE_RELATIVE,
        "sibling_shape532": sibling / A448_SHAPE_SOURCE_RELATIVE,
    }
    result = {name: _sha256_file(path.resolve(strict=True)) for name, path in sources.items()}
    expected = {
        "sibling_helper": A448_HELPER_SHA256,
        "sibling_wrapper": A448_WRAPPER_SHA256,
        "sibling_identity_wrapper": A448_IDENTITY_WRAPPER_SHA256,
        "sibling_multihorizon_wrapper": A448_MULTIHORIZON_WRAPPER_SHA256,
        "sibling_proof_features": A448_FEATURE_SOURCE_SHA256,
        "sibling_shape532": A448_SHAPE_SOURCE_SHA256,
    }
    if any(result[name] != digest for name, digest in expected.items()):
        raise O1C31RunError("one or more exact sibling source anchors differ")
    return result


def _environment() -> dict[str, object]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "cpu_count": os.cpu_count(),
        "load_average_at_start": list(os.getloadavg()),
        "self_maxrss_at_start": usage.ru_maxrss,
        "W52_live_process_observed": False,
        "resource_gate_observed_at": "2026-07-18T17:29:57+02:00",
        "resource_gate_memory_pressure_free_percent": 75,
        "resource_gate_cpu_idle_percent": 88.26,
    }


def _start_capsule(
    *,
    root: Path,
    sibling: Path,
    public: object,
    source_hashes: dict[str, str],
) -> RunCapsule:
    template = (
        root
        / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
        "artifacts/cnf/full256_chacha20.cnf"
    )
    semantic_map = template.with_name("full256_chacha20.map.json")
    return RunCapsuleManager(root).start(
        attempt_id=ATTEMPT_ID,
        slug="a448-proof-byte3-full256-transfer-v1",
        commit=_git_commit(root),
        hypothesis=(
            "A448's unchanged proof-antecedent top4 plus exact A442 Borda tie "
            "backbone retains better-than-median byte ordering when all other "
            "248 key bits are unknown."
        ),
        prediction=(
            "On the consumed RFC8439 full-round public target, key byte 3 ranks "
            f"at or above the median (rank <= {PASS_MAX_RANK}/256)."
        ),
        controls=(
            "measurement API receives PublicTargetView only; key and target byte are revealed after rank freeze",
            "other 248 key bits have no CNF units and remain unassigned",
            "A375/A442/A447 models, helper, wrapper and feature source are hash-frozen with zero refits",
            "numeric 0..255 order and H1/H2/H4/H8 cover every candidate before reveal",
            "single-pass raw backbone was matched exactly against stored A447/A359 source telemetry",
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
            "If rank <=128, repeat unchanged on one disjoint consumed DEVELOPMENT "
            "target before spending a fresh target; otherwise close A448 once."
        ),
        config={
            "public_target": public.describe(),  # type: ignore[attr-defined]
            "public_view_sha256": public.digest(),  # type: ignore[attr-defined]
            "byte_index": BYTE_INDEX,
            "candidate_order": "numeric_0_through_255",
            "other_key_bits_assigned": 0,
            "template": str(template.relative_to(root)),
            "semantic_map": str(semantic_map.relative_to(root)),
            "sibling_root": str(sibling),
            "sibling_access": "strictly_read_only",
            "pass_max_rank": PASS_MAX_RANK,
        },
        command=(
            "PYTHONPATH=src python -m o1_crypto_lab.o1c31_a448_transfer_run"
        ),
        environment=_environment(),
    )


def run() -> int:
    root = lab_root().resolve(strict=True)
    sibling = default_sibling_root().resolve(strict=True)
    source_hashes = _source_hashes(root, sibling)
    known = build_known_target(
        bytes(range(32)),
        counter=1,
        nonce=bytes.fromhex("000000090000004a00000000"),
    )
    if known.public.digest() != EXPECTED_PUBLIC_SHA256:
        raise O1C31RunError("RFC8439 public target identity differs")
    capsule = _start_capsule(
        root=root,
        sibling=sibling,
        public=known.public,
        source_hashes=source_hashes,
    )
    template = (
        root
        / "runs/20260717_054138_O1C-0011_full256-public-cnf-foundation-v1/"
        "artifacts/cnf/full256_chacha20.cnf"
    )
    try:
        capsule.append_stdout(
            "O1C-0031 exact one-pass A448 consumed full256 transfer started.\n"
        )
        measurement = measure_public_a448_byte_cube(
            public=known.public,
            byte_index=BYTE_INDEX,
            template=template,
            semantic_map=template.with_name("full256_chacha20.map.json"),
            workspace=root / "runs",
            sibling_root=sibling,
            capture_raw_artifact=True,
        )
        if measurement.raw_artifact_gzip is None:
            raise O1C31RunError("A448 raw artifact capture is missing")
        capsule.write_artifact(RAW_ARTIFACT, measurement.raw_artifact_gzip)
        target_byte = known.teacher.target_key[BYTE_INDEX]
        rank = revealed_byte_rank(measurement.ranks, target_byte)
        passed = rank <= PASS_MAX_RANK
        description = measurement.describe()
        description.update(
            {
                "target_role": "CONSUMED",
                "label_revealed_after_rank_freeze": True,
                "target_byte_hex": f"{target_byte:02x}",
                "target_rank": rank,
                "pass_max_rank": PASS_MAX_RANK,
                "passed": passed,
            }
        )
        capsule.write_json_artifact("measurement.json", description)
        capsule.write_json_artifact(
            "single_pass_equivalence.json",
            {
                "schema": "o1-256-a448-single-pass-equivalence-v1",
                "source_pair": "A447_target_00_vs_A359_target_00",
                "raw_shape532_max_difference": 0.0,
                "primitive_rank_difference_count": 0,
                "A375_reader_rank_difference_count": 0,
                "A442_borda_rank_difference_count": 0,
                "stored_truth_cell": 19,
                "stored_and_reconstructed_borda_rank": 11,
                "one_pass_exact": True,
            },
        )
        bit_gain_from_worst = math.log2(256.0 / rank)
        uniform_mean_log_rank = sum(math.log2(value) for value in range(1, 257)) / 256
        descriptive_gain = uniform_mean_log_rank - math.log2(rank)
        metrics = {
            "target_role": "CONSUMED",
            "target_byte": target_byte,
            "target_rank": rank,
            "pass_max_rank": PASS_MAX_RANK,
            "passed": passed,
            "rank_bit_gain_from_worst_rank": bit_gain_from_worst,
            "descriptive_gain_vs_uniform_mean_log_rank_bits": descriptive_gain,
            "wall_seconds": measurement.wall_seconds,
            "candidate_cells": 256,
            "solver_stages": 1024,
            "other_key_bits_assigned": 0,
            "public_key_label_inputs": 0,
            "raw_artifact_bytes": len(measurement.raw_artifact_gzip),
            "raw_artifact_sha256": measurement.raw_artifact_sha256,
            "stable_run_sha256": measurement.stable_run_sha256,
            "stdout_sha256": measurement.stdout_sha256,
            "candidate_order_uint8_sha256": description[
                "candidate_order_uint8_sha256"
            ],
            "self_maxrss_after": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }
        next_action = (
            "Repeat the unchanged A448 reader on exactly one disjoint consumed "
            "DEVELOPMENT target; use a fresh target only if the consumed repeat "
            "also ranks <=128."
            if passed
            else "Close A448 once as non-transferring and move to the next exact all256 sibling mechanism."
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
        description="Run the exact consumed O1C-0031 A448 full256 transfer"
    )
    parser.parse_args(argv)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ATTEMPT_ID", "BYTE_INDEX", "O1C31RunError", "main", "run"]
