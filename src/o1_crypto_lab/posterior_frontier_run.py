"""Capsule-backed O1C-0024 exact factorized posterior frontier.

The outcome-bearing decoder is deliberately split at the burned reveal boundary:
public O1C-0016 probabilities are converted to an immutable candidate frontier
first; only after that frontier is persisted is the already-burned reveal opened
for retrospective rank and Hamming diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import stat
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import numpy as np

from .full256_broker import (
    public_view_from_publication,
    verify_publication,
    verify_reveal,
)
from .living_inverse import (
    KEY_BITS,
    build_known_target,
    key_bits,
    make_output_flip_control,
    make_wrong_nonce_control,
    uncertainty_beam_metrics,
)
from .posterior_frontier import (
    TOPOLOGY_TIE_POLICY,
    FactorizedFrontierCandidate,
    evaluate_factorized_frontier,
    exhaustive_small_width_proof,
    iter_factorized_topk,
    verify_frontier_against_public_target,
)
from .run_capsule import ClaimLevel, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-posterior-frontier-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-posterior-frontier-cli-result-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-posterior-frontier-prediction-freeze-v1"
RESULT_SCHEMA = "o1-256-posterior-frontier-result-v1"
WORK_SCHEMA = "o1-256-posterior-frontier-work-ledger-v1"
SOURCE_INDEX_SCHEMA = "o1-256-posterior-frontier-source-index-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-posterior-frontier-artifact-index-v1"

PHASE_FRONTIER_FROZEN = "GLOBAL_TOPK_FROZEN_BEFORE_BURNED_REVEAL_READ"
PHASE_REVEAL_READ_STARTED = "BURNED_REVEAL_PAYLOAD_READ_STARTED"
PHASE_REVEAL_READ_COMPLETED = "BURNED_REVEAL_PAYLOAD_READ_COMPLETED"
PHASE_EVALUATION_READ_STARTED = "BURNED_EVALUATION_PAYLOAD_READ_STARTED"
PHASE_EVALUATION_READ_COMPLETED = "BURNED_EVALUATION_PAYLOAD_READ_COMPLETED"

ATTEMPT_ID = "O1C-0024"
FORMAL_SLUG = "exact-factorized-posterior-frontier-v1"
FORMAL_CONFIG = "posterior_frontier_v1.json"
SUCCESS_NULL = "EXACT_GLOBAL_FRONTIER_VALIDATED_BURNED_NULL"
SUCCESS_RETROSPECTIVE_HIT = "EXACT_GLOBAL_FRONTIER_RETROSPECTIVE_BURNED_HIT"
FAILURE = "GLOBAL_FRONTIER_VALIDATION_FAILED"
OPERATIONAL_BUDGET_FAILURE = "OPERATIONAL_BUDGET_FAILURE"
_SHA256 = frozenset("0123456789abcdef")
_MAX_SELECTED_SOURCE_MEMBER_BYTES = 64 * 1024 * 1024


class PosteriorFrontierRunError(ValueError):
    """The formal config, source boundary, result, or resource gate differs."""


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as exc:
        raise PosteriorFrontierRunError("value is not canonical finite JSON") from exc
    return (rendered + "\n").encode("ascii")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _sha(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256 for character in value)
    ):
        raise PosteriorFrontierRunError(f"{field} must be a lowercase SHA-256")
    return value


def _mapping(value: object, field: str, expected: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise PosteriorFrontierRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PosteriorFrontierRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _finite(value: object, field: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise PosteriorFrontierRunError(
            f"{field} must be finite in [{minimum},{maximum}]"
        )
    return float(value)


def _read_json(path: Path, field: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PosteriorFrontierRunError(f"{field} is unreadable") from exc
    if not isinstance(value, dict):
        raise PosteriorFrontierRunError(f"{field} must be a JSON object")
    return value


def _safe_relative_parts(relative: str, field: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    parts = path.parts
    if (
        not relative
        or path.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise PosteriorFrontierRunError(f"{field} path is unsafe")
    return parts


def _read_regular_beneath(directory: Path, relative: str, field: str) -> bytes:
    """Read one regular member through a no-follow directory-fd walk."""

    parts = _safe_relative_parts(relative, field)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    root_fd: int | None = None
    opened_directories: list[int] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(directory, directory_flags)
        parent_fd = root_fd
        for part in parts[:-1]:
            child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            opened_directories.append(child_fd)
            parent_fd = child_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=parent_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise PosteriorFrontierRunError(f"{field} is not a regular file")
        if metadata.st_size > _MAX_SELECTED_SOURCE_MEMBER_BYTES:
            raise PosteriorFrontierRunError(f"{field} exceeds the source read limit")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(file_fd, 1 << 20):
            total += len(chunk)
            if total > _MAX_SELECTED_SOURCE_MEMBER_BYTES:
                raise PosteriorFrontierRunError(
                    f"{field} exceeds the source read limit"
                )
            chunks.append(chunk)
        return b"".join(chunks)
    except (OSError, UnicodeError) as exc:
        raise PosteriorFrontierRunError(f"{field} is unreadable without links") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(opened_directories):
            os.close(descriptor)
        if root_fd is not None:
            os.close(root_fd)


def _parse_manifest(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PosteriorFrontierRunError("burned manifest is not UTF-8") from exc
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        fields = raw.split(maxsplit=1)
        if len(fields) != 2:
            raise PosteriorFrontierRunError(
                f"burned manifest line {line_number} differs"
            )
        digest, relative = fields
        relative = relative.lstrip("*")
        _sha(digest, f"burned manifest line {line_number}")
        _safe_relative_parts(relative, f"burned manifest line {line_number}")
        if relative == "artifacts.sha256" or relative in entries:
            raise PosteriorFrontierRunError(
                f"burned manifest line {line_number} is duplicate or self-referential"
            )
        entries[relative] = digest
    if not entries:
        raise PosteriorFrontierRunError("burned manifest is empty")
    return entries


def _checkpoint_read_accounting(payload: object | None) -> dict[str, Any]:
    """Derive conservative source-read counts from one durable checkpoint payload."""

    if payload is None:
        return {
            "checkpoint_phase": "NO_CHECKPOINT",
            "source_reveal_payload_reads": 0,
            "source_evaluation_payload_reads": 0,
            "read_accounting_known": True,
        }
    if not isinstance(payload, Mapping):
        return {
            "checkpoint_phase": "UNKNOWN",
            "source_reveal_payload_reads": None,
            "source_evaluation_payload_reads": None,
            "read_accounting_known": False,
        }
    phase = payload.get("phase")
    counts = {
        PHASE_FRONTIER_FROZEN: (0, 0),
        PHASE_REVEAL_READ_STARTED: (1, 0),
        PHASE_REVEAL_READ_COMPLETED: (1, 0),
        PHASE_EVALUATION_READ_STARTED: (1, 1),
        PHASE_EVALUATION_READ_COMPLETED: (1, 1),
    }
    if not isinstance(phase, str) or phase not in counts:
        return {
            "checkpoint_phase": str(phase) if phase is not None else "UNKNOWN",
            "source_reveal_payload_reads": None,
            "source_evaluation_payload_reads": None,
            "read_accounting_known": False,
        }
    reveal_reads, evaluation_reads = counts[phase]
    return {
        "checkpoint_phase": phase,
        "source_reveal_payload_reads": reveal_reads,
        "source_evaluation_payload_reads": evaluation_reads,
        "read_accounting_known": True,
    }


def _recoverable_read_accounting(run: Any) -> dict[str, Any]:
    checkpoint_path = run.staging_path / "checkpoint.json"
    try:
        metadata = os.stat(checkpoint_path, follow_symlinks=False)
    except FileNotFoundError:
        return _checkpoint_read_accounting(None)
    except OSError:
        return _checkpoint_read_accounting({"phase": "UNKNOWN"})
    if not stat.S_ISREG(metadata.st_mode):
        return _checkpoint_read_accounting({"phase": "UNKNOWN"})
    try:
        document = json.loads(
            _read_regular_beneath(
                run.staging_path, "checkpoint.json", "recoverable checkpoint"
            ).decode("utf-8")
        )
    except (PosteriorFrontierRunError, UnicodeDecodeError, json.JSONDecodeError):
        return _checkpoint_read_accounting({"phase": "UNKNOWN"})
    if (
        not isinstance(document, Mapping)
        or document.get("schema") != "o1c-run-checkpoint-v1"
        or document.get("attempt_id") != ATTEMPT_ID
    ):
        return _checkpoint_read_accounting({"phase": "UNKNOWN"})
    return _checkpoint_read_accounting(document.get("payload"))


@dataclass(frozen=True)
class FrontierBudgets:
    maximum_cpu_seconds: float
    maximum_wall_seconds: float
    maximum_resident_memory_mib: int
    maximum_persistent_artifact_bytes: int
    maximum_frontier_candidates: int
    maximum_proof_candidate_evaluations: int
    maximum_legacy_cube_assignments: int
    maximum_burned_public_verifications: int
    maximum_synthetic_public_verifications: int
    maximum_source_manifest_reads: int
    maximum_source_payload_reads: int
    maximum_source_reveal_payload_reads: int
    maximum_source_evaluation_payload_reads: int
    maximum_other_outcome_payload_reads: int
    maximum_full_source_capsule_scans: int
    maximum_scientific_entropy_calls: int
    maximum_burned_reveal_reads: int
    maximum_native_solver_branches: int
    maximum_sibling_reads: int
    maximum_sibling_writes: int
    maximum_mps_calls: int
    maximum_gpu_calls: int

    @classmethod
    def from_mapping(cls, value: object) -> "FrontierBudgets":
        fields = set(cls.__dataclass_fields__)
        row = _mapping(value, "budgets", fields)
        cpu = _finite(row["maximum_cpu_seconds"], "maximum_cpu_seconds", 0.001, 3600.0)
        wall = _finite(
            row["maximum_wall_seconds"], "maximum_wall_seconds", 0.001, 3600.0
        )
        integer_limits = {
            "maximum_resident_memory_mib": 65536,
            "maximum_persistent_artifact_bytes": 1_000_000_000,
            "maximum_frontier_candidates": 1 << 24,
            "maximum_proof_candidate_evaluations": 1 << 24,
            "maximum_legacy_cube_assignments": 1 << 24,
            "maximum_burned_public_verifications": 1 << 24,
            "maximum_synthetic_public_verifications": 1 << 20,
            "maximum_source_manifest_reads": 1_000_000,
            "maximum_source_payload_reads": 1_000_000,
            "maximum_source_reveal_payload_reads": 1_000_000,
            "maximum_source_evaluation_payload_reads": 1_000_000,
            "maximum_other_outcome_payload_reads": 1_000_000,
            "maximum_full_source_capsule_scans": 1_000_000,
            "maximum_scientific_entropy_calls": 1_000_000,
            "maximum_burned_reveal_reads": 1_000_000,
            "maximum_native_solver_branches": 1_000_000,
            "maximum_sibling_reads": 1_000_000,
            "maximum_sibling_writes": 1_000_000,
            "maximum_mps_calls": 1_000_000,
            "maximum_gpu_calls": 1_000_000,
        }
        parsed = {
            field: _integer(row[field], field, 0, maximum)
            for field, maximum in integer_limits.items()
        }
        result = cls(maximum_cpu_seconds=cpu, maximum_wall_seconds=wall, **parsed)
        for field in (
            "maximum_scientific_entropy_calls",
            "maximum_other_outcome_payload_reads",
            "maximum_full_source_capsule_scans",
            "maximum_native_solver_branches",
            "maximum_sibling_reads",
            "maximum_sibling_writes",
            "maximum_mps_calls",
            "maximum_gpu_calls",
        ):
            if getattr(result, field) != 0:
                raise PosteriorFrontierRunError(f"O1C-0024 requires zero {field}")
        if result.maximum_burned_reveal_reads != 1:
            raise PosteriorFrontierRunError(
                "O1C-0024 requires exactly one burned reveal read"
            )
        exact_read_budgets = {
            "maximum_source_manifest_reads": 1,
            "maximum_source_payload_reads": 5,
            "maximum_source_reveal_payload_reads": 1,
            "maximum_source_evaluation_payload_reads": 1,
        }
        for field, expected in exact_read_budgets.items():
            if getattr(result, field) != expected:
                raise PosteriorFrontierRunError(f"O1C-0024 requires {field}={expected}")
        return result


def load_posterior_frontier_run_config(
    path: str | Path,
) -> tuple[dict[str, Any], FrontierBudgets]:
    top = _read_json(Path(path), "run config")
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
    _mapping(top, "config", expected)
    if top["schema"] != RUN_CONFIG_SCHEMA:
        raise PosteriorFrontierRunError("run config schema differs")
    if top["attempt_id"] != ATTEMPT_ID or top["slug"] != FORMAL_SLUG:
        raise PosteriorFrontierRunError("O1C-0024 identity differs")
    if top["claim_level"] != ClaimLevel.RETROSPECTIVE.value:
        raise PosteriorFrontierRunError("O1C-0024 must remain RETROSPECTIVE")
    for field in ("hypothesis", "prediction", "next_action"):
        if not isinstance(top[field], str) or not str(top[field]).strip():
            raise PosteriorFrontierRunError(f"config.{field} is required")
    controls = top["controls"]
    if (
        not isinstance(controls, list)
        or len(controls) < 7
        or any(not isinstance(item, str) or not item.strip() for item in controls)
    ):
        raise PosteriorFrontierRunError("config.controls differ")
    budgets = FrontierBudgets.from_mapping(top["budgets"])

    experiment = _mapping(
        top["experiment"],
        "experiment",
        {"exhaustive_active_widths", "synthetic", "burned"},
    )
    widths = experiment["exhaustive_active_widths"]
    if (
        not isinstance(widths, list)
        or widths != [3, 6, 10]
        or any(type(value) is not int for value in widths)
    ):
        raise PosteriorFrontierRunError("exhaustive widths differ")
    synthetic = _mapping(
        experiment["synthetic"],
        "synthetic",
        {
            "key_byte_affine_multiplier",
            "key_byte_affine_offset",
            "counter",
            "nonce_hex",
            "flip_coordinates",
            "flip_penalties_bits",
            "truth_flip_coordinate",
            "other_coordinate_penalty_bits",
            "top_k",
            "legacy_uncertain_bits",
            "expected_truth_rank",
        },
    )
    for field in (
        "key_byte_affine_multiplier",
        "key_byte_affine_offset",
        "counter",
        "truth_flip_coordinate",
        "top_k",
        "legacy_uncertain_bits",
        "expected_truth_rank",
    ):
        _integer(synthetic[field], f"synthetic.{field}", 0, (1 << 32) - 1)
    if synthetic["flip_coordinates"] != [0, 1, 2]:
        raise PosteriorFrontierRunError("synthetic flip coordinates differ")
    penalties = synthetic["flip_penalties_bits"]
    if not isinstance(penalties, list) or len(penalties) != 3:
        raise PosteriorFrontierRunError("synthetic flip penalties differ")
    parsed_penalties = [
        _finite(value, "synthetic.flip_penalty", 0.0, 1024.0) for value in penalties
    ]
    if parsed_penalties != sorted(parsed_penalties) or len(set(parsed_penalties)) != 3:
        raise PosteriorFrontierRunError("synthetic penalties must be strictly ordered")
    _finite(
        synthetic["other_coordinate_penalty_bits"],
        "synthetic.other_coordinate_penalty_bits",
        parsed_penalties[-1],
        52.0,
    )
    nonce_hex = synthetic["nonce_hex"]
    if not isinstance(nonce_hex, str):
        raise PosteriorFrontierRunError("synthetic nonce must be hexadecimal")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise PosteriorFrontierRunError("synthetic nonce is invalid") from exc
    if len(nonce) != 12:
        raise PosteriorFrontierRunError("synthetic nonce must be 12 bytes")
    if (
        synthetic["truth_flip_coordinate"] != 2
        or synthetic["top_k"] != 8
        or synthetic["legacy_uncertain_bits"] != 2
        or synthetic["expected_truth_rank"] != 4
    ):
        raise PosteriorFrontierRunError("synthetic discriminator contract differs")
    expected_proof_evaluations = 2 * sum(1 << int(width) for width in widths)
    expected_legacy_assignments = (1 << int(synthetic["legacy_uncertain_bits"])) + (
        1 << 16
    )
    if budgets.maximum_proof_candidate_evaluations != expected_proof_evaluations:
        raise PosteriorFrontierRunError("proof candidate budget differs")
    if budgets.maximum_legacy_cube_assignments != expected_legacy_assignments:
        raise PosteriorFrontierRunError("legacy cube budget differs")

    burned = _mapping(
        experiment["burned"],
        "burned",
        {
            "capsule",
            "capsule_manifest_sha256",
            "target_id",
            "top_k",
            "public_verification_limit",
            "inputs",
        },
    )
    if (
        burned["capsule"]
        != "runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2"
        or burned["target_id"] != "o1c0016-replication-0000"
    ):
        raise PosteriorFrontierRunError("burned source identity differs")
    _sha(burned["capsule_manifest_sha256"], "burned manifest")
    top_k = _integer(burned["top_k"], "burned.top_k", 1, 1 << 24)
    verify_limit = _integer(
        burned["public_verification_limit"],
        "burned.public_verification_limit",
        1,
        top_k,
    )
    inputs = _mapping(
        burned["inputs"],
        "burned.inputs",
        {
            "publication.json",
            "probabilities.f64le",
            "prediction_freeze.json",
            "reveal.json",
            "evaluation.json",
        },
    )
    for name, digest in inputs.items():
        _sha(digest, f"burned.inputs.{name}")
    if top_k + int(synthetic["top_k"]) > budgets.maximum_frontier_candidates:
        raise PosteriorFrontierRunError("frontier candidate budget is too small")
    if verify_limit > budgets.maximum_burned_public_verifications:
        raise PosteriorFrontierRunError("burned verification budget is too small")
    return top, budgets


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain", "--untracked-files=all"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise PosteriorFrontierRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise PosteriorFrontierRunError("lab commit is unavailable")
    return commit


def _source_hashes(
    root: Path, config_path: Path, config: Mapping[str, Any]
) -> dict[str, str]:
    experiment = config["experiment"]
    if not isinstance(experiment, Mapping) or not isinstance(
        experiment.get("burned"), Mapping
    ):
        raise PosteriorFrontierRunError("source hash config differs")
    burned = experiment["burned"]
    inputs = burned["inputs"]
    if not isinstance(inputs, Mapping):
        raise PosteriorFrontierRunError("source hash inputs differ")
    modules = (
        "chacha_trace.py",
        "full256_broker.py",
        "living_inverse.py",
        "posterior_frontier.py",
        "posterior_frontier_run.py",
        "run_capsule.py",
    )
    hashes = {
        "config": _sha256_file(config_path),
        "pyproject": _sha256_file(root / "pyproject.toml"),
        **{
            f"module_{Path(name).stem}": _sha256_file(root / "src/o1_crypto_lab" / name)
            for name in modules
        },
        "burned_capsule_manifest_expected": str(burned["capsule_manifest_sha256"]),
    }
    for name, digest in sorted(inputs.items()):
        hashes[f"burned_{name.replace('.', '_')}_expected"] = str(digest)
    return hashes


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


def _probability_from_mode(mode_bit: int, penalty_bits: float) -> float:
    mode_probability = 1.0 / (1.0 + 2.0 ** (-penalty_bits))
    return mode_probability if mode_bit else 1.0 - mode_probability


def _candidate_payloads(
    candidates: Sequence[FactorizedFrontierCandidate],
) -> tuple[bytes, bytes, dict[str, Any]]:
    if not candidates:
        raise PosteriorFrontierRunError("candidate frontier is empty")
    key_payload = b"".join(candidate.key for candidate in candidates)
    score_payload = struct.pack(
        f"<{len(candidates)}d",
        *(candidate.log2_probability for candidate in candidates),
    )
    if len(key_payload) != len(candidates) * 32:
        raise AssertionError("candidate key payload width differs")
    index = {
        "schema": "o1-256-factorized-topk-artifact-index-v1",
        "candidate_count": len(candidates),
        "candidate_key_bytes": 32,
        "keys_encoding": "rank-major raw 32-byte keys",
        "scores_encoding": "rank-major float64 little-endian log2 probabilities",
        "keys_sha256": _sha256(key_payload),
        "scores_sha256": _sha256(score_payload),
        "first_log2_probability": candidates[0].log2_probability,
        "cutoff_log2_probability": candidates[-1].log2_probability,
        "tie_policy": TOPOLOGY_TIE_POLICY,
        "truth_used_for_generation": False,
    }
    return key_payload, score_payload, index


def _proof_suite(widths: Sequence[int]) -> tuple[list[dict[str, Any]], bool]:
    proofs: list[dict[str, Any]] = []
    for width in widths:
        penalties = np.asarray(
            [0.071 + 0.037 * ((index * 7 + 3) % (width + 1)) for index in range(width)],
            dtype=np.float64,
        )
        mode = np.asarray([(index * 5 + 1) & 1 for index in range(width)])
        probabilities = np.asarray(
            [
                _probability_from_mode(int(bit), float(penalty))
                for bit, penalty in zip(mode, penalties, strict=True)
            ],
            dtype=np.float64,
        )
        proof = exhaustive_small_width_proof(probabilities, limit=1 << width)
        proofs.append(proof)
    return proofs, all(bool(proof["orders_match"]) for proof in proofs)


def _synthetic_experiment(spec: Mapping[str, Any]) -> dict[str, Any]:
    multiplier = int(spec["key_byte_affine_multiplier"])
    offset = int(spec["key_byte_affine_offset"])
    true_key = bytes((multiplier * index + offset) & 0xFF for index in range(32))
    known = build_known_target(
        true_key,
        counter=int(spec["counter"]),
        nonce=bytes.fromhex(str(spec["nonce_hex"])),
    )
    truth = key_bits(true_key)
    mode = truth.copy()
    truth_flip_coordinate = int(spec["truth_flip_coordinate"])
    mode[truth_flip_coordinate] ^= 1
    penalties = np.full(
        KEY_BITS, float(spec["other_coordinate_penalty_bits"]), dtype=np.float64
    )
    for coordinate, penalty in zip(
        spec["flip_coordinates"], spec["flip_penalties_bits"], strict=True
    ):
        penalties[int(coordinate)] = float(penalty)
    probabilities = np.asarray(
        [
            _probability_from_mode(int(bit), float(penalty))
            for bit, penalty in zip(mode, penalties, strict=True)
        ],
        dtype=np.float64,
    )
    top_k = int(spec["top_k"])
    candidates = tuple(iter_factorized_topk(probabilities, limit=top_k))
    key_payload, score_payload, frontier_index = _candidate_payloads(candidates)
    evaluation = evaluate_factorized_frontier(true_key, candidates)
    factual = verify_frontier_against_public_target(known.public, candidates)
    wrong_nonce = verify_frontier_against_public_target(
        make_wrong_nonce_control(known.public, 0),
        candidates,
        stop_on_first_match=False,
    )
    output_flip = verify_frontier_against_public_target(
        make_output_flip_control(known.public, 0),
        candidates,
        stop_on_first_match=False,
    )
    legacy = uncertainty_beam_metrics(
        true_key,
        probabilities,
        uncertain_bits=int(spec["legacy_uncertain_bits"]),
        beam_size=1 << int(spec["legacy_uncertain_bits"]),
    )
    expected_rank = int(spec["expected_truth_rank"])
    gates = {
        "global_truth_rank_exact": evaluation["true_rank_one_based"] == expected_rank,
        "full_round_public_verifier_hits_same_rank": factual[
            "first_match_rank_one_based"
        ]
        == expected_rank,
        "legacy_restricted_cube_excludes_truth": not bool(legacy["exact_key_in_beam"]),
        "wrong_nonce_has_zero_matches": not bool(wrong_nonce["exact_match_found"]),
        "output_flip_has_zero_matches": not bool(output_flip["exact_match_found"]),
        "candidate_generation_truth_free": True,
    }
    return {
        "schema": "o1-256-posterior-frontier-synthetic-discriminator-v1",
        "public_target": known.public.describe(),
        "true_key_sha256": _sha256(true_key),
        "posterior_sha256": _sha256(probabilities.astype("<f8").tobytes()),
        "probabilities": probabilities,
        "candidates": candidates,
        "candidate_keys": key_payload,
        "candidate_scores": score_payload,
        "frontier_index": frontier_index,
        "evaluation": evaluation,
        "factual_verification": factual,
        "wrong_nonce_verification": wrong_nonce,
        "output_flip_verification": output_flip,
        "legacy_restricted_cube": legacy,
        "gates": gates,
        "all_gates_pass": all(gates.values()),
        "public_verification_count": _integer(
            factual["candidates_verified"],
            "synthetic.factual.candidates_verified",
            1,
            top_k,
        )
        + _integer(
            wrong_nonce["candidates_verified"],
            "synthetic.wrong_nonce.candidates_verified",
            1,
            top_k,
        )
        + _integer(
            output_flip["candidates_verified"],
            "synthetic.output_flip.candidates_verified",
            1,
            top_k,
        ),
    }


def _burned_source_paths(
    root: Path, burned: Mapping[str, Any]
) -> tuple[Path, dict[str, str], dict[str, Any]]:
    capsule = (root / str(burned["capsule"])).resolve(strict=True)
    expected_capsule = (
        root / "runs/20260717_115325_O1C-0016_full256-polyphase-blind-replication-v2"
    ).resolve(strict=True)
    if capsule != expected_capsule:
        raise PosteriorFrontierRunError("burned capsule path differs")
    manifest_payload = _read_regular_beneath(
        capsule, "artifacts.sha256", "burned capsule manifest"
    )
    manifest_sha256 = _sha256(manifest_payload)
    if manifest_sha256 != burned["capsule_manifest_sha256"]:
        raise PosteriorFrontierRunError("burned capsule manifest SHA-256 differs")
    manifest = _parse_manifest(manifest_payload)
    target_root = f"artifacts/sealed/{burned['target_id']}"
    paths = {name: f"{target_root}/{name}" for name in burned["inputs"]}
    selected: dict[str, str] = {}
    for name, relative in paths.items():
        expected = str(burned["inputs"][name])
        if manifest.get(relative) != expected:
            raise PosteriorFrontierRunError(
                f"burned manifest commitment differs for {name}"
            )
        selected[relative] = expected
    source_manifest_index = {
        "schema": "o1-256-selected-source-manifest-index-v1",
        "manifest_sha256": manifest_sha256,
        "committed_member_count": len(manifest),
        "selected_member_count": len(selected),
        "selected_members": dict(sorted(selected.items())),
        "manifest_payload_reads": 1,
        "full_capsule_scans": 0,
    }
    return capsule, paths, source_manifest_index


def _read_verified(
    capsule: Path,
    relative: str,
    expected_sha256: str,
    field: str,
) -> bytes:
    payload = _read_regular_beneath(capsule, relative, field)
    if _sha256(payload) != expected_sha256:
        raise PosteriorFrontierRunError(f"{field} SHA-256 differs")
    return payload


def _burned_pre_reveal(root: Path, burned: Mapping[str, Any]) -> dict[str, Any]:
    capsule, paths, source_manifest_index = _burned_source_paths(root, burned)
    inputs = burned["inputs"]
    if not isinstance(inputs, Mapping):
        raise PosteriorFrontierRunError("burned input map differs")
    publication_payload = _read_verified(
        capsule,
        paths["publication.json"],
        str(inputs["publication.json"]),
        "publication",
    )
    probabilities_payload = _read_verified(
        capsule,
        paths["probabilities.f64le"],
        str(inputs["probabilities.f64le"]),
        "probabilities",
    )
    freeze_payload = _read_verified(
        capsule,
        paths["prediction_freeze.json"],
        str(inputs["prediction_freeze.json"]),
        "prediction freeze",
    )
    publication = json.loads(publication_payload.decode("utf-8"))
    checked_publication = verify_publication(publication)
    if checked_publication["target_id"] != burned["target_id"]:
        raise PosteriorFrontierRunError("burned publication target differs")
    public = public_view_from_publication(publication)
    probabilities = np.frombuffer(probabilities_payload, dtype="<f8").copy()
    if (
        probabilities.shape != (KEY_BITS,)
        or not np.isfinite(probabilities).all()
        or bool(((probabilities <= 0.0) | (probabilities >= 1.0)).any())
    ):
        raise PosteriorFrontierRunError("burned posterior differs")
    freeze = json.loads(freeze_payload.decode("utf-8"))
    if (
        not isinstance(freeze, dict)
        or freeze.get("phase") != "SEALED_PREDICTION_FROZEN_BEFORE_REVEAL"
        or freeze.get("target_id") != burned["target_id"]
        or freeze.get("probabilities_float64le_sha256")
        != str(inputs["probabilities.f64le"])
        or freeze.get("publication_sha256") != checked_publication["publication_sha256"]
    ):
        raise PosteriorFrontierRunError("burned prediction freeze differs")
    candidates = tuple(iter_factorized_topk(probabilities, limit=int(burned["top_k"])))
    key_payload, score_payload, frontier_index = _candidate_payloads(candidates)
    frontier_index_payload = _canonical_json(frontier_index)
    source_manifest_index_payload = _canonical_json(source_manifest_index)
    return {
        "capsule": capsule,
        "paths": paths,
        "public": public,
        "publication": checked_publication,
        "publication_payload": publication_payload,
        "probabilities": probabilities,
        "probabilities_payload": probabilities_payload,
        "source_prediction_freeze_sha256": _sha256(freeze_payload),
        "candidates": candidates,
        "candidate_keys": key_payload,
        "candidate_scores": score_payload,
        "frontier_index": frontier_index,
        "frontier_index_payload": frontier_index_payload,
        "source_manifest_index": source_manifest_index,
        "source_manifest_index_payload": source_manifest_index_payload,
        "source_manifest_reads": 1,
        "source_payload_reads": 3,
        "source_reveal_payload_reads": 0,
        "source_evaluation_payload_reads": 0,
        "other_outcome_payload_reads": 0,
        "full_source_capsule_scans": 0,
        "semantic_reveal_reads": 0,
    }


def _prediction_freeze_document(
    burned: Mapping[str, Any], pre: Mapping[str, Any]
) -> dict[str, Any]:
    commitments = {
        "burned/publication.json": {
            "bytes": len(pre["publication_payload"]),
            "sha256": _sha256(pre["publication_payload"]),
        },
        "burned/posterior.f64le": {
            "bytes": len(pre["probabilities_payload"]),
            "sha256": _sha256(pre["probabilities_payload"]),
        },
        "burned/candidates.bin": {
            "bytes": len(pre["candidate_keys"]),
            "sha256": _sha256(pre["candidate_keys"]),
        },
        "burned/scores.f64le": {
            "bytes": len(pre["candidate_scores"]),
            "sha256": _sha256(pre["candidate_scores"]),
        },
        "burned/frontier_index.json": {
            "bytes": len(pre["frontier_index_payload"]),
            "sha256": _sha256(pre["frontier_index_payload"]),
        },
        "burned/source_manifest_index.json": {
            "bytes": len(pre["source_manifest_index_payload"]),
            "sha256": _sha256(pre["source_manifest_index_payload"]),
        },
    }
    unsigned = {
        "schema": PREDICTION_FREEZE_SCHEMA,
        "phase": PHASE_FRONTIER_FROZEN,
        "target_id": burned["target_id"],
        "source_capsule": burned["capsule"],
        "source_manifest_sha256": burned["capsule_manifest_sha256"],
        "source_prediction_freeze_sha256": pre["source_prediction_freeze_sha256"],
        "candidate_count": len(pre["candidates"]),
        "tie_policy": TOPOLOGY_TIE_POLICY,
        "semantic_reveal_reads_before_freeze": pre["semantic_reveal_reads"],
        "truth_used_for_generation": False,
        "artifact_commitments": commitments,
    }
    return {**unsigned, "freeze_sha256": _sha256(_canonical_json(unsigned))}


def _burned_post_reveal(
    burned: Mapping[str, Any],
    pre: Mapping[str, Any],
    *,
    on_reveal_read_started: Callable[[], None] | None = None,
    on_reveal_read_completed: Callable[[], None] | None = None,
    on_evaluation_read_started: Callable[[], None] | None = None,
    on_evaluation_read_completed: Callable[[], None] | None = None,
) -> dict[str, Any]:
    inputs = burned["inputs"]
    paths = pre["paths"]
    if not isinstance(inputs, Mapping) or not isinstance(paths, Mapping):
        raise PosteriorFrontierRunError("burned post-reveal inputs differ")
    capsule = pre["capsule"]
    if not isinstance(capsule, Path):
        raise PosteriorFrontierRunError("burned capsule identity differs")
    if on_reveal_read_started is not None:
        on_reveal_read_started()
    reveal_payload = _read_verified(
        capsule,
        str(paths["reveal.json"]),
        str(inputs["reveal.json"]),
        "burned reveal",
    )
    reveal = verify_reveal(json.loads(reveal_payload.decode("utf-8")))
    if reveal.get("publication") != pre.get("publication"):
        raise PosteriorFrontierRunError(
            "burned reveal publication differs from the frozen public input"
        )
    key_hex = reveal["commitment_preimage"]["key_hex"]
    if not isinstance(key_hex, str):
        raise PosteriorFrontierRunError("burned reveal key differs")
    true_key = bytes.fromhex(key_hex)
    if on_reveal_read_completed is not None:
        on_reveal_read_completed()
    candidates = pre["candidates"]
    if not isinstance(candidates, tuple):
        raise PosteriorFrontierRunError("burned candidate freeze differs")
    evaluation = evaluate_factorized_frontier(true_key, candidates)
    public_verification = verify_frontier_against_public_target(
        pre["public"],
        candidates,
        stop_on_first_match=True,
        maximum_candidates=int(burned["public_verification_limit"]),
    )
    legacy = uncertainty_beam_metrics(
        true_key,
        pre["probabilities"],
        uncertain_bits=16,
        beam_size=65536,
    )
    if on_evaluation_read_started is not None:
        on_evaluation_read_started()
    source_evaluation_payload = _read_verified(
        capsule,
        str(paths["evaluation.json"]),
        str(inputs["evaluation.json"]),
        "burned evaluation",
    )
    source_evaluation = json.loads(source_evaluation_payload.decode("utf-8"))
    if (
        not isinstance(source_evaluation, dict)
        or source_evaluation.get("target_id") != burned["target_id"]
        or source_evaluation.get("reveal_sha256") != reveal.get("reveal_sha256")
    ):
        raise PosteriorFrontierRunError("burned evaluation identity differs")
    truth = key_bits(true_key)
    probabilities = np.asarray(pre["probabilities"], dtype=np.float64)
    mode = (probabilities >= 0.5).astype(np.uint8)
    selected = np.where(truth == 1, probabilities, 1.0 - probabilities)
    correct_bits = int(np.count_nonzero(mode == truth))
    compression = float(KEY_BITS + np.log2(selected).sum())
    source_primary = source_evaluation.get("primary")
    if (
        not isinstance(source_primary, Mapping)
        or source_primary.get("correct_bits") != correct_bits
        or not math.isclose(
            float(source_primary.get("compression_bits_per_key", math.nan)),
            compression,
            rel_tol=0.0,
            abs_tol=1e-12,
        )
    ):
        raise PosteriorFrontierRunError("burned source metric recomputation differs")
    if on_evaluation_read_completed is not None:
        on_evaluation_read_completed()
    source_manifest_index = pre.get("source_manifest_index")
    if not isinstance(source_manifest_index, Mapping):
        raise PosteriorFrontierRunError("burned source manifest index differs")
    return {
        "schema": "o1-256-posterior-frontier-burned-diagnostic-v1",
        "target_id": burned["target_id"],
        "source_capsule_manifest_sha256": source_manifest_index["manifest_sha256"],
        "source_manifest_members_committed": source_manifest_index[
            "committed_member_count"
        ],
        "source_selected_members_verified": source_manifest_index[
            "selected_member_count"
        ],
        "source_manifest_reads": 1,
        "source_payload_reads": 5,
        "source_reveal_payload_reads": 1,
        "source_evaluation_payload_reads": 1,
        "other_outcome_payload_reads": 0,
        "full_source_capsule_scans": 0,
        "semantic_reveal_reads": 1,
        "true_key_sha256": _sha256(true_key),
        "source_reveal_sha256": _sha256(reveal_payload),
        "source_evaluation_sha256": _sha256(source_evaluation_payload),
        "recomputed_correct_bits": correct_bits,
        "recomputed_compression_bits": compression,
        "global_frontier": evaluation,
        "public_verification_prefix": public_verification,
        "legacy_restricted_cube": legacy,
        "diagnostic_only": True,
        "reader_fit_or_selection": False,
        "fresh_target_or_entropy": False,
    }


def _artifact_index(payloads: Mapping[str, bytes]) -> dict[str, Any]:
    return {
        "schema": ARTIFACT_INDEX_SCHEMA,
        "artifact_count_excluding_this_index": len(payloads),
        "this_index_is_self_excluded": True,
        "artifacts": {
            name: {"bytes": len(payload), "sha256": _sha256(payload)}
            for name, payload in sorted(payloads.items())
        },
    }


def _final_classification(
    *,
    science_pass: bool,
    burned_hit: bool,
    failed_budgets: Sequence[str],
) -> str:
    if failed_budgets:
        return OPERATIONAL_BUDGET_FAILURE
    if not science_pass:
        return FAILURE
    return SUCCESS_RETROSPECTIVE_HIT if burned_hit else SUCCESS_NULL


def _write_artifact(
    run: Any, payloads: dict[str, bytes], name: str, payload: bytes
) -> None:
    if name in payloads:
        raise PosteriorFrontierRunError(f"duplicate artifact path: {name}")
    run.write_artifact(name, payload)
    payloads[name] = payload


def _already_finalized(manager: RunCapsuleManager) -> int | None:
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is None:
        return None
    metrics = _read_json(published.path / "metrics.json", "published metrics")
    capsule_status = metrics.get("status")
    print(
        json.dumps(
            {
                "attempt_id": ATTEMPT_ID,
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
    canonical_config = (root / "configs" / FORMAL_CONFIG).resolve(strict=True)
    if config_path != canonical_config:
        raise PosteriorFrontierRunError(
            "O1C-0024 requires the canonical tracked config path"
        )
    top, budgets = load_posterior_frontier_run_config(config_path)
    manager = RunCapsuleManager(root)
    finalized_status = _already_finalized(manager)
    if finalized_status is not None:
        return finalized_status
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
        if interrupted.publication_prepared:
            finalized = interrupted.finalize(metrics={})
            recovered_metrics = _read_json(finalized.path / "metrics.json", "metrics")
            return 0 if recovered_metrics.get("status") == "completed" else 2
        recovered_reads = _recoverable_read_accounting(interrupted)
        finalized = interrupted.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "classification": "INTERRUPTED_NO_REPLAY",
                "read_accounting": recovered_reads,
                "full_source_capsule_scans": 0,
                "scientific_result_claimed": False,
            },
            status="stopped",
            next_action=(
                "Preserve the interrupted deterministic decoder attempt and repair "
                "its lifecycle under a new O1C identity without relabeling it."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(root)
    source_hashes = _source_hashes(root, config_path, top)
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=FORMAL_SLUG,
        commit=commit,
        hypothesis=str(top["hypothesis"]),
        prediction=str(top["prediction"]),
        controls=tuple(str(item) for item in top["controls"]),
        budgets=dict(top["budgets"]),
        source_hashes=source_hashes,
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action=str(top["next_action"]),
        config=top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.posterior_frontier_run",
            "--config",
            str(config_path),
        ),
        environment={
            "cpu_only": True,
            "fresh_target_count": 0,
            "scientific_entropy_calls": 0,
            "source_capsule_is_read_only": True,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "machine": platform.machine(),
            "numpy_version": np.__version__,
        },
    )
    payloads: dict[str, bytes] = {}
    start_cpu = time.process_time()
    start_wall = time.perf_counter()
    reveal_reads = 0
    evaluation_reads = 0
    reveal_read_completed = False
    evaluation_read_completed = False
    prediction_frozen = False
    try:
        experiment = top["experiment"]
        if not isinstance(experiment, Mapping):
            raise PosteriorFrontierRunError("experiment config differs")
        widths = experiment["exhaustive_active_widths"]
        synthetic_spec = experiment["synthetic"]
        burned_spec = experiment["burned"]
        if (
            not isinstance(widths, Sequence)
            or not isinstance(synthetic_spec, Mapping)
            or not isinstance(burned_spec, Mapping)
        ):
            raise PosteriorFrontierRunError("experiment sections differ")

        proofs, proof_gate = _proof_suite(tuple(int(value) for value in widths))
        for proof in proofs:
            _write_artifact(
                run,
                payloads,
                f"proof/exhaustive_width_{proof['width']}.json",
                _canonical_json(proof),
            )

        synthetic = _synthetic_experiment(synthetic_spec)
        synthetic_probabilities = np.asarray(
            synthetic.pop("probabilities"), dtype="<f8"
        ).tobytes()
        synthetic.pop("candidates")
        synthetic_keys = synthetic.pop("candidate_keys")
        synthetic_scores = synthetic.pop("candidate_scores")
        _write_artifact(
            run, payloads, "synthetic/posterior.f64le", synthetic_probabilities
        )
        _write_artifact(run, payloads, "synthetic/candidates.bin", synthetic_keys)
        _write_artifact(run, payloads, "synthetic/scores.f64le", synthetic_scores)
        _write_artifact(
            run, payloads, "synthetic/result.json", _canonical_json(synthetic)
        )

        burned_pre = _burned_pre_reveal(root, burned_spec)
        _write_artifact(
            run,
            payloads,
            "burned/publication.json",
            burned_pre["publication_payload"],
        )
        _write_artifact(
            run,
            payloads,
            "burned/posterior.f64le",
            burned_pre["probabilities_payload"],
        )
        _write_artifact(
            run,
            payloads,
            "burned/candidates.bin",
            burned_pre["candidate_keys"],
        )
        _write_artifact(
            run,
            payloads,
            "burned/scores.f64le",
            burned_pre["candidate_scores"],
        )
        _write_artifact(
            run,
            payloads,
            "burned/frontier_index.json",
            burned_pre["frontier_index_payload"],
        )
        _write_artifact(
            run,
            payloads,
            "burned/source_manifest_index.json",
            burned_pre["source_manifest_index_payload"],
        )
        freeze = _prediction_freeze_document(burned_spec, burned_pre)
        _write_artifact(
            run,
            payloads,
            "burned/prediction_freeze.json",
            _canonical_json(freeze),
        )
        run.checkpoint(
            {
                "phase": PHASE_FRONTIER_FROZEN,
                "prediction_freeze_sha256": freeze["freeze_sha256"],
                "candidate_count": freeze["candidate_count"],
                "source_reveal_payload_reads": reveal_reads,
                "source_evaluation_payload_reads": evaluation_reads,
            }
        )
        prediction_frozen = True

        def checkpoint_read_phase(
            phase: str,
            *,
            durable_reveal_reads: int,
            durable_evaluation_reads: int,
        ) -> None:
            run.checkpoint(
                {
                    "phase": phase,
                    "prediction_freeze_sha256": freeze["freeze_sha256"],
                    "candidate_count": freeze["candidate_count"],
                    "source_reveal_payload_reads": durable_reveal_reads,
                    "source_evaluation_payload_reads": durable_evaluation_reads,
                }
            )

        def account_reveal_read_started() -> None:
            nonlocal reveal_reads
            if reveal_reads != 0:
                raise PosteriorFrontierRunError(
                    "burned semantic reveal read budget exceeded"
                )
            checkpoint_read_phase(
                PHASE_REVEAL_READ_STARTED,
                durable_reveal_reads=1,
                durable_evaluation_reads=0,
            )
            reveal_reads = 1

        def account_reveal_read_completed() -> None:
            nonlocal reveal_read_completed
            if reveal_reads != 1:
                raise PosteriorFrontierRunError("burned reveal completion differs")
            checkpoint_read_phase(
                PHASE_REVEAL_READ_COMPLETED,
                durable_reveal_reads=1,
                durable_evaluation_reads=0,
            )
            reveal_read_completed = True

        def account_evaluation_read_started() -> None:
            nonlocal evaluation_reads
            if evaluation_reads != 0 or not reveal_read_completed:
                raise PosteriorFrontierRunError(
                    "burned evaluation read lifecycle differs"
                )
            checkpoint_read_phase(
                PHASE_EVALUATION_READ_STARTED,
                durable_reveal_reads=1,
                durable_evaluation_reads=1,
            )
            evaluation_reads = 1

        def account_evaluation_read_completed() -> None:
            nonlocal evaluation_read_completed
            if evaluation_reads != 1:
                raise PosteriorFrontierRunError("burned evaluation completion differs")
            checkpoint_read_phase(
                PHASE_EVALUATION_READ_COMPLETED,
                durable_reveal_reads=1,
                durable_evaluation_reads=1,
            )
            evaluation_read_completed = True

        burned = _burned_post_reveal(
            burned_spec,
            burned_pre,
            on_reveal_read_started=account_reveal_read_started,
            on_reveal_read_completed=account_reveal_read_completed,
            on_evaluation_read_started=account_evaluation_read_started,
            on_evaluation_read_completed=account_evaluation_read_completed,
        )
        if (
            reveal_reads != int(burned["source_reveal_payload_reads"])
            or evaluation_reads != int(burned["source_evaluation_payload_reads"])
            or not reveal_read_completed
            or not evaluation_read_completed
        ):
            raise PosteriorFrontierRunError("burned source read accounting differs")
        _write_artifact(run, payloads, "burned/result.json", _canonical_json(burned))
        source_index: dict[str, Any] = {
            "schema": SOURCE_INDEX_SCHEMA,
            "source_hashes": source_hashes,
            "burned_capsule": burned_spec["capsule"],
            "burned_target_id": burned_spec["target_id"],
            "burned_manifest_members_committed": burned[
                "source_manifest_members_committed"
            ],
            "burned_selected_members_verified": burned[
                "source_selected_members_verified"
            ],
            "burned_source_manifest_reads": burned["source_manifest_reads"],
            "burned_source_payload_reads": burned["source_payload_reads"],
            "burned_reveal_payload_reads": reveal_reads,
            "burned_evaluation_payload_reads": evaluation_reads,
            "burned_other_outcome_payload_reads": burned["other_outcome_payload_reads"],
            "burned_full_capsule_scans": burned["full_source_capsule_scans"],
            "burned_reveal_read_after_prediction_freeze": prediction_frozen,
            "burned_reveal_read_completed": reveal_read_completed,
            "burned_evaluation_read_completed": evaluation_read_completed,
            "fresh_target_or_entropy": False,
        }
        _write_artifact(
            run, payloads, "source_index.json", _canonical_json(source_index)
        )

        synthetic_verifications = int(synthetic["public_verification_count"])
        burned_verifications = int(
            burned["public_verification_prefix"]["candidates_verified"]
        )
        work: dict[str, Any] = {
            "schema": WORK_SCHEMA,
            "global_frontier_candidates": int(synthetic_spec["top_k"])
            + int(burned_spec["top_k"]),
            "synthetic_frontier_candidates": int(synthetic_spec["top_k"]),
            "burned_frontier_candidates": int(burned_spec["top_k"]),
            "proof_best_first_candidates": sum(1 << int(width) for width in widths),
            "proof_exhaustive_candidates": sum(1 << int(width) for width in widths),
            "proof_candidate_evaluations": 2 * sum(1 << int(width) for width in widths),
            "synthetic_legacy_cube_assignments": 1
            << int(synthetic_spec["legacy_uncertain_bits"]),
            "burned_legacy_cube_assignments": 1 << 16,
            "legacy_cube_assignments": (1 << 16)
            + (1 << int(synthetic_spec["legacy_uncertain_bits"])),
            "synthetic_public_verifications": synthetic_verifications,
            "burned_public_verifications": burned_verifications,
            "source_manifest_reads": burned["source_manifest_reads"],
            "source_payload_reads": burned["source_payload_reads"],
            "source_reveal_payload_reads": reveal_reads,
            "source_evaluation_payload_reads": evaluation_reads,
            "other_outcome_payload_reads": burned["other_outcome_payload_reads"],
            "full_source_capsule_scans": burned["full_source_capsule_scans"],
            "scientific_entropy_calls": 0,
            "burned_semantic_reveal_reads": reveal_reads,
            "native_solver_branches": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "frontier_memory_scales_with_stream_length": False,
            "frontier_memory_scales_with_explicit_candidate_budget": True,
        }
        _write_artifact(run, payloads, "work_ledger.json", _canonical_json(work))

        burned_hit = bool(burned["global_frontier"]["exact_key_hit"])
        zero_external_work = all(
            int(work[field]) == 0
            for field in (
                "scientific_entropy_calls",
                "native_solver_branches",
                "sibling_reads",
                "sibling_writes",
                "mps_calls",
                "gpu_calls",
            )
        )
        science_gates = {
            "exhaustive_orders_match": proof_gate,
            "synthetic_discriminator_passes": bool(synthetic["all_gates_pass"]),
            "burned_candidates_frozen_before_reveal": prediction_frozen
            and reveal_reads == 1
            and reveal_read_completed,
            "selected_source_manifest_and_members_verify": burned[
                "source_capsule_manifest_sha256"
            ]
            == burned_spec["capsule_manifest_sha256"]
            and int(burned["source_selected_members_verified"])
            == len(burned_spec["inputs"]),
            "outcome_reads_are_exact_and_post_freeze": reveal_reads == 1
            and evaluation_reads == 1
            and reveal_read_completed
            and evaluation_read_completed,
            "full_source_capsule_was_not_scanned": int(
                burned["full_source_capsule_scans"]
            )
            == 0,
            "zero_fresh_entropy_solver_sibling_or_accelerator_work": zero_external_work,
        }
        science_pass = all(science_gates.values())
        cpu_seconds = time.process_time() - start_cpu
        wall_seconds = time.perf_counter() - start_wall
        peak_rss_bytes = _process_peak_rss_bytes()
        budget_checks = {
            "cpu": cpu_seconds <= budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= budgets.maximum_resident_memory_mib * 1024 * 1024,
            "frontier_candidates": work["global_frontier_candidates"]
            <= budgets.maximum_frontier_candidates,
            "proof_candidate_evaluations": work["proof_candidate_evaluations"]
            <= budgets.maximum_proof_candidate_evaluations,
            "legacy_cube_assignments": work["legacy_cube_assignments"]
            <= budgets.maximum_legacy_cube_assignments,
            "burned_public_verifications": burned_verifications
            <= budgets.maximum_burned_public_verifications,
            "synthetic_public_verifications": synthetic_verifications
            <= budgets.maximum_synthetic_public_verifications,
            "source_manifest_reads": work["source_manifest_reads"]
            == budgets.maximum_source_manifest_reads,
            "source_payload_reads": work["source_payload_reads"]
            == budgets.maximum_source_payload_reads,
            "source_reveal_payload_reads": work["source_reveal_payload_reads"]
            == budgets.maximum_source_reveal_payload_reads,
            "source_evaluation_payload_reads": work["source_evaluation_payload_reads"]
            == budgets.maximum_source_evaluation_payload_reads,
            "other_outcome_payload_reads": work["other_outcome_payload_reads"]
            == budgets.maximum_other_outcome_payload_reads,
            "full_source_capsule_scans": work["full_source_capsule_scans"]
            == budgets.maximum_full_source_capsule_scans,
            "scientific_entropy": work["scientific_entropy_calls"] == 0,
            "burned_reveal_reads": reveal_reads == budgets.maximum_burned_reveal_reads,
            "native_solver_branches": work["native_solver_branches"] == 0,
            "sibling_reads": work["sibling_reads"] == 0,
            "sibling_writes": work["sibling_writes"] == 0,
            "mps": work["mps_calls"] == 0,
            "gpu": work["gpu_calls"] == 0,
        }

        def make_result_document(
            final_classification: str,
            failed: Sequence[str],
        ) -> dict[str, Any]:
            operational_budget_passed = not failed
            scientific_result_claimed = final_classification in {
                SUCCESS_NULL,
                SUCCESS_RETROSPECTIVE_HIT,
            }
            unsigned: dict[str, Any] = {
                "schema": RESULT_SCHEMA,
                "classification": final_classification,
                "scientific_result_claimed": scientific_result_claimed,
                "science_gates_passed": science_pass,
                "mechanism_validation_passed": science_pass
                and operational_budget_passed,
                "operational_budget_passed": operational_budget_passed,
                "failed_budgets": list(failed),
                "cryptanalytic_signal_claimed": False,
                "terminal_c_achieved": False,
                "synthetic_full_round_recovery_only": True,
                "burned_diagnostic_only": True,
                "science_gates": science_gates,
                "proof_widths": list(widths),
                "decoder_runtime_inputs": [
                    "posterior_probabilities",
                    "candidate_limit",
                ],
                "synthetic": {
                    "true_rank_one_based": synthetic["evaluation"][
                        "true_rank_one_based"
                    ],
                    "legacy_exact_key_in_beam": synthetic["legacy_restricted_cube"][
                        "exact_key_in_beam"
                    ],
                    "public_verification_rank_one_based": synthetic[
                        "factual_verification"
                    ]["first_match_rank_one_based"],
                    "wrong_nonce_match": synthetic["wrong_nonce_verification"][
                        "exact_match_found"
                    ],
                    "output_flip_match": synthetic["output_flip_verification"][
                        "exact_match_found"
                    ],
                },
                "burned": {
                    "candidate_count": burned["global_frontier"]["candidate_count"],
                    "exact_key_hit": burned_hit,
                    "true_rank_one_based": burned["global_frontier"][
                        "true_rank_one_based"
                    ],
                    "best_hamming_distance_at_configured_k": burned["global_frontier"][
                        "best_hamming_distance"
                    ],
                    "map_correct_bits": burned["recomputed_correct_bits"],
                    "compression_bits": burned["recomputed_compression_bits"],
                    "public_prefix_verified": burned_verifications,
                    "public_prefix_match": burned["public_verification_prefix"][
                        "exact_match_found"
                    ],
                    "legacy_exact_key_in_beam": burned["legacy_restricted_cube"][
                        "exact_key_in_beam"
                    ],
                },
            }
            return {
                **unsigned,
                "result_sha256": _sha256(_canonical_json(unsigned)),
            }

        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        classification = _final_classification(
            science_pass=science_pass,
            burned_hit=burned_hit,
            failed_budgets=failed_budgets,
        )
        result = make_result_document(classification, failed_budgets)
        result_payload = _canonical_json(result)
        projected_payloads = {
            **payloads,
            "posterior_frontier_result.json": result_payload,
        }
        index_payload = _canonical_json(_artifact_index(projected_payloads))
        persistent_bytes = (
            sum(len(payload) for payload in payloads.values())
            + len(result_payload)
            + len(index_payload)
        )
        budget_checks["persistent_artifacts"] = (
            persistent_bytes <= budgets.maximum_persistent_artifact_bytes
        )
        if not budget_checks["persistent_artifacts"]:
            failed_budgets = sorted(
                name for name, passed in budget_checks.items() if not passed
            )
            classification = _final_classification(
                science_pass=science_pass,
                burned_hit=burned_hit,
                failed_budgets=failed_budgets,
            )
            result = make_result_document(classification, failed_budgets)
            result_payload = _canonical_json(result)
            projected_payloads = {
                **payloads,
                "posterior_frontier_result.json": result_payload,
            }
            index_payload = _canonical_json(_artifact_index(projected_payloads))
            persistent_bytes = (
                sum(len(payload) for payload in payloads.values())
                + len(result_payload)
                + len(index_payload)
            )
        _write_artifact(
            run,
            payloads,
            "posterior_frontier_result.json",
            result_payload,
        )
        _write_artifact(run, payloads, "artifact_index.json", index_payload)

        operationally_complete = science_pass and not failed_budgets
        metrics: dict[str, Any] = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": classification,
            "scientific_result_claimed": classification
            in {SUCCESS_NULL, SUCCESS_RETROSPECTIVE_HIT},
            "science_gates_passed": science_pass,
            "mechanism_validation_passed": operationally_complete,
            "cryptanalytic_signal_claimed": False,
            "terminal_c_achieved": False,
            "result_sha256": result["result_sha256"],
            "science_gates": science_gates,
            "work": work,
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_mib": peak_rss_bytes / (1024 * 1024),
            "persistent_artifact_bytes": persistent_bytes,
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
            prepared_metrics = _read_json(finalized.path / "metrics.json", "metrics")
            return 0 if prepared_metrics.get("status") == "completed" else 2
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "classification": "OPERATIONAL_FAILURE",
                "error_type": type(exc).__name__,
                "error": str(exc),
                "prediction_frozen": prediction_frozen,
                "burned_semantic_reveal_reads": reveal_reads,
                "source_reveal_payload_reads": reveal_reads,
                "source_evaluation_payload_reads": evaluation_reads,
                "reveal_read_completed": reveal_read_completed,
                "evaluation_read_completed": evaluation_read_completed,
                "full_source_capsule_scans": 0,
                "persistent_artifact_bytes": sum(
                    len(payload) for payload in payloads.values()
                ),
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and repair the exact decoder "
                "under a new O1C identity without relabeling a partial result."
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
                "classification": classification,
                "science_gates_passed": science_pass,
                "mechanism_validation_passed": operationally_complete,
                "burned_exact_key_hit": burned_hit,
                "burned_best_hamming_distance": burned["global_frontier"][
                    "best_hamming_distance"
                ],
                "failed_budgets": failed_budgets,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run O1C-0024 exact factorized full-256 posterior frontier"
    )
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "ATTEMPT_ID",
    "FAILURE",
    "FORMAL_CONFIG",
    "FORMAL_SLUG",
    "FrontierBudgets",
    "PREDICTION_FREEZE_SCHEMA",
    "OPERATIONAL_BUDGET_FAILURE",
    "PHASE_EVALUATION_READ_COMPLETED",
    "PHASE_EVALUATION_READ_STARTED",
    "PHASE_FRONTIER_FROZEN",
    "PHASE_REVEAL_READ_COMPLETED",
    "PHASE_REVEAL_READ_STARTED",
    "PosteriorFrontierRunError",
    "RESULT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "SOURCE_INDEX_SCHEMA",
    "SUCCESS_NULL",
    "SUCCESS_RETROSPECTIVE_HIT",
    "WORK_SCHEMA",
    "load_posterior_frontier_run_config",
    "main",
    "run_capsule_from_config",
]
