"""Capsule-backed exact A465 transfer over two retained public A448 streams."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import resource
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .a465_rank_poe_transfer import (
    A447_SOURCE_RELATIVE,
    A448_SOURCE_RELATIVE,
    A458_SOURCE_RELATIVE,
    A460_RESULT_RELATIVE,
    A462_RESULT_RELATIVE,
    A463_RESULT_RELATIVE,
    A463_SOURCE_RELATIVE,
    A465_RESULT_RELATIVE,
    A465_SOURCE_RELATIVE,
    A465_SELECTED_SPEC,
    a465_rank_field_from_run,
    load_frozen_a465_model,
    read_retained_a448_run,
)
from .a448_proof_byte_transfer import default_sibling_root
from .full256_proof_pool import make_deterministic_known_target
from .living_inverse import build_known_target, canonical_sha256
from .run_capsule import ClaimLevel, RunCapsuleManager


ATTEMPT_ID = "O1C-0033"
BYTE_INDEX = 3
PASS_MAX_RANK = 128


@dataclass(frozen=True)
class RetainedTarget:
    target_id: str
    capsule_relative: Path
    manifest_sha256: str
    raw_sha256: str
    public_view_sha256: str


TARGETS = (
    RetainedTarget(
        target_id="RFC8439",
        capsule_relative=Path(
            "runs/20260718_174416_O1C-0031_a448-proof-byte3-full256-transfer-v1"
        ),
        manifest_sha256="b89b3ea4452b74a4da38a73764d34278e918008fdf59f14983a18b48aceca919",
        raw_sha256="8098c6438a0e2264242733a554b0956ee2e49701bb84979b947bd16d201860bf",
        public_view_sha256="50ed1436504231b7c3a68558d1e3c27e4e197e83acf0aa02e53b32e4d9d41d00",
    ),
    RetainedTarget(
        target_id="development-0000",
        capsule_relative=Path(
            "runs/20260718_175112_O1C-0032_a448-proof-byte3-development-repeat-v1"
        ),
        manifest_sha256="93b25facb9099e10d1c13bfc44a542cab1b04607d19eb48ebb0dd919a7ef1892",
        raw_sha256="40cf3a8f258e4d9d12ea20497dca5bc7bfb5edc7d740bf28765ce07322bb85a6",
        public_view_sha256="e622cc6b5b99913d759179a1a371335a4945cf35a1089da973896896c05291d7",
    ),
)
RAW_NAME = "artifacts/a448_proof_antecedent_run.json.gz"


class O1C33RunError(RuntimeError):
    """The exact retained input, A465 model, or score boundary differs."""


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
        raise O1C33RunError("git commit identity differs")
    return commit


def _verified_inputs(root: Path) -> tuple[dict[str, Path], dict[str, str]]:
    manager = RunCapsuleManager(root)
    paths: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for target in TARGETS:
        capsule = (root / target.capsule_relative).resolve(strict=True)
        verification = manager.verify(capsule)
        if (
            not verification.ok
            or verification.manifest_sha256 != target.manifest_sha256
        ):
            raise O1C33RunError(f"upstream capsule differs: {target.target_id}")
        raw = (capsule / RAW_NAME).resolve(strict=True)
        digest = _sha256_file(raw)
        if digest != target.raw_sha256:
            raise O1C33RunError(f"retained raw stream differs: {target.target_id}")
        measurement = json.loads(
            (capsule / "artifacts/measurement.json").read_text(encoding="ascii")
        )
        if (
            measurement.get("public_view_sha256") != target.public_view_sha256
            or measurement.get("target_key_inputs") != 0
            or measurement.get("other_key_bits_assigned") != 0
            or measurement.get("raw_artifact_sha256") != target.raw_sha256
        ):
            raise O1C33RunError(f"upstream public receipt differs: {target.target_id}")
        paths[target.target_id] = raw
        hashes[f"retained_{target.target_id}_raw"] = digest
        hashes[f"retained_{target.target_id}_manifest"] = target.manifest_sha256
    return paths, hashes


def _source_hashes(root: Path, sibling: Path) -> dict[str, str]:
    model = load_frozen_a465_model(sibling)
    sources = {
        "a448_transfer": root / "src/o1_crypto_lab/a448_proof_byte_transfer.py",
        "a465_transfer": root / "src/o1_crypto_lab/a465_rank_poe_transfer.py",
        "o1c33_runner": root / "src/o1_crypto_lab/o1c33_a465_retained_transfer_run.py",
        "run_capsule": root / "src/o1_crypto_lab/run_capsule.py",
        "sibling_A447_source": sibling / A447_SOURCE_RELATIVE,
        "sibling_A448_source": sibling / A448_SOURCE_RELATIVE,
        "sibling_A458_source": sibling / A458_SOURCE_RELATIVE,
        "sibling_A463_source": sibling / A463_SOURCE_RELATIVE,
        "sibling_A465_source": sibling / A465_SOURCE_RELATIVE,
        "sibling_A460_result": sibling / A460_RESULT_RELATIVE,
        "sibling_A462_result": sibling / A462_RESULT_RELATIVE,
        "sibling_A463_result": sibling / A463_RESULT_RELATIVE,
        "sibling_A465_result": sibling / A465_RESULT_RELATIVE,
    }
    result = {name: _sha256_file(path.resolve(strict=True)) for name, path in sources.items()}
    if result["sibling_A465_result"] != model.result_sha256:
        raise O1C33RunError("A465 frozen result differs")
    return result


def _revealed_target_bytes() -> dict[str, int]:
    rfc = build_known_target(
        bytes(range(32)),
        counter=1,
        nonce=bytes.fromhex("000000090000004a00000000"),
    )
    development = make_deterministic_known_target(
        seed=180_018_180_018,
        split="DEVELOPMENT",
        index=0,
    )
    if (
        rfc.public.digest() != TARGETS[0].public_view_sha256
        or development.public.digest() != TARGETS[1].public_view_sha256
    ):
        raise O1C33RunError("post-freeze target reconstruction differs")
    return {
        "RFC8439": rfc.teacher.target_key[BYTE_INDEX],
        "development-0000": development._key[BYTE_INDEX],
    }


def run() -> int:
    root = lab_root().resolve(strict=True)
    sibling = default_sibling_root().resolve(strict=True)
    input_paths, input_hashes = _verified_inputs(root)
    source_hashes = _source_hashes(root, sibling)
    source_hashes.update(input_hashes)
    capsule = RunCapsuleManager(root).start(
        attempt_id=ATTEMPT_ID,
        slug="a465-retained-two-target-full256-transfer-v1",
        commit=_git_commit(root),
        hypothesis=(
            "A465's unchanged A460/A462/A463 rank-space Product-of-Experts "
            "improves or preserves byte-3 ordering on both retained all256 A448 streams."
        ),
        prediction=(
            f"Both consumed targets rank <= {PASS_MAX_RANK}/256; only then may "
            "the exact A465 reader earn one fresh blind target."
        ),
        controls=(
            "all A465 weights, waves, feature order and ties are loaded from hash-frozen sibling results",
            "only retained target-key-free A448 raw streams enter prediction",
            "both complete rank fields are persisted before either target byte is reconstructed",
            "no new solver stage, fit, target, coefficient, byte or operator selection is used",
            "all other 248 key bits were unassigned in the retained public CNF measurements",
        ),
        budgets={
            "target_count": 2,
            "target_role": "CONSUMED",
            "new_solver_stages": 0,
            "new_target_count": 0,
            "maximum_wall_seconds": 30.0,
            "maximum_resident_memory_mib": 512,
            "MPS_or_GPU": False,
        },
        source_hashes=source_hashes,
        claim_level=ClaimLevel.TEST,
        next_action=(
            "If both ranks <=128, run unchanged once on a fresh blind target; "
            "otherwise close A465 all256 byte transfer without a resweep."
        ),
        config={
            "byte_index": BYTE_INDEX,
            "selected_spec": A465_SELECTED_SPEC,
            "targets": [
                {
                    "target_id": target.target_id,
                    "role": "CONSUMED",
                    "public_view_sha256": target.public_view_sha256,
                    "source_capsule": str(target.capsule_relative),
                    "source_manifest_sha256": target.manifest_sha256,
                    "raw_artifact_sha256": target.raw_sha256,
                }
                for target in TARGETS
            ],
            "target_labels_in_prediction": 0,
            "other_key_bits_assigned": 0,
            "sibling_access": "strictly_read_only",
            "pass_max_rank": PASS_MAX_RANK,
        },
        command="PYTHONPATH=src python -m o1_crypto_lab.o1c33_a465_retained_transfer_run",
        environment={
            "cpu_count": os.cpu_count(),
            "load_average_at_start": list(os.getloadavg()),
            "self_maxrss_at_start": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "W52_live_process_observed": False,
        },
    )
    started = time.perf_counter()
    try:
        predictions: dict[str, dict[str, object]] = {}
        fields = {}
        for target in TARGETS:
            field = a465_rank_field_from_run(
                read_retained_a448_run(input_paths[target.target_id])
            )
            fields[target.target_id] = field
            predictions[target.target_id] = {
                "target_id": target.target_id,
                "role": "CONSUMED",
                "public_view_sha256": target.public_view_sha256,
                **field.describe(),
            }
        freeze_without_hash = {
            "schema": "o1-256-a465-retained-prediction-freeze-v1",
            "phase": "BOTH_RANK_FIELDS_FROZEN_BEFORE_LABEL_RECONSTRUCTION",
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
                    "component_h_rank": int(field.component_h_ranks[truth]),
                    "component_o_rank": int(field.component_o_ranks[truth]),
                    "A460_rank": int(field.a460_ranks[truth]),
                    "A462_rank": int(field.a462_ranks[truth]),
                    "A463_rank": int(field.a463_ranks[truth]),
                    "A465_rank": rank,
                    "passed_median_gate": passed_target,
                }
            )
        passed = all(passed_flags)
        uniform_mean_log_rank = sum(math.log2(value) for value in range(1, 257)) / 256
        elapsed = time.perf_counter() - started
        result = {
            "schema": "o1-256-a465-retained-transfer-result-v1",
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
            "Execute this exact A465 reader on one new blinded full256 target."
            if passed
            else "Close A465 all256 byte transfer; do not resweep and inspect the exact A469 input contract next."
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
        description="Apply exact A465 to two retained all256 A448 streams"
    )
    parser.parse_args(argv)
    return run()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ATTEMPT_ID", "BYTE_INDEX", "O1C33RunError", "TARGETS", "main", "run"]
