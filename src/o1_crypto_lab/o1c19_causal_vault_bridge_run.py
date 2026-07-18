"""Capsule runner for the O1C-0022 O1C-0019-to-vault BUILD LOO bridge.

The runner is intentionally a consumer of two already frozen mechanisms.  It
does not train O1C-0019, regenerate a proof pool, or touch a key before the
corresponding prediction artifacts have been persisted.  The only scientific
work is replaying the four immutable O1C-0018 BUILD action pools through the
four frozen O1C-0019 readers, then accumulating their public packet deltas in
the exact 352-byte O1C-0021 vault.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

import numpy as np

from .causal_evidence_stream import CausalEvidenceConfig
from .causal_evidence_stream_run import load_causal_evidence_run_config
from .full256_multiresolution_build_loo import (
    BUILD_LOO_LEARNING_FREEZE_SCHEMA,
    BUILD_LOO_PREDICTION_FREEZE_SCHEMA,
    BUILD_LOO_RESULT_SCHEMA,
    RAW_ARMS,
    ArtifactBuildCorpus,
    ArtifactBuildEpisode,
)
from .full256_multiresolution_build_loo_run import (
    load_full256_build_loo_run_config,
)
from .living_inverse import KEY_BITS, canonical_json_bytes
from .o1_streaming_core import StreamingSelectiveHolographicCore
from .o1c19_causal_vault_bridge import (
    ACTIVE_COORDINATE_WIDTHS,
    FORMAL_VAULT_BYTES,
    CausalVaultBridge,
    CausalVaultBridgeExecution,
    CausalVaultBridgeState,
    FrozenMedianAbsQuantizer,
    NestedActiveCoordinatePlan,
    PacketDeltaExtraction,
    active_coordinate_sequence_sha256,
    deterministic_coordinate_permutation,
    execute_packet_delta_groups,
    extract_frozen_o1c19_packet_groups,
    permute_packet_coordinate,
)
from .online_multiresolution_controller import (
    MultiResolutionCausalController,
    MultiResolutionControllerConfig,
)
from .run_capsule import ClaimLevel, FinalizedRun, RunCapsuleManager


RUN_CONFIG_SCHEMA = "o1-256-o1c19-causal-vault-bridge-run-config-v1"
RUN_METRICS_SCHEMA = "o1-256-o1c19-causal-vault-bridge-cli-result-v1"
PREFLIGHT_SCHEMA = "o1-256-o1c19-causal-vault-bridge-preflight-v1"
RESULT_SCHEMA = "o1-256-o1c19-causal-vault-bridge-result-v1"
CALIBRATION_FREEZE_SCHEMA = "o1-256-o1c22-calibration-prediction-freeze-v1"
PREDICTION_FREEZE_SCHEMA = "o1-256-o1c22-heldout-prediction-freeze-v1"
ARTIFACT_INDEX_SCHEMA = "o1-256-o1c19-causal-vault-artifact-index-v1"

ATTEMPT_ID = "O1C-0022"
UPSTREAM_ATTEMPT_ID = "O1C-0019"
FORMAL_SLUG = "o1c19-causal-vault-build-loo-v1"
PREDICTION_ARMS = (
    "raw_float_delta_sum",
    "normalized_float_delta_sum",
    "quantized_int8_vault",
    "last_horizon_only",
    "unit_sign_sum",
    "coordinate_shuffled_vault",
    "zero_prior",
)
CALIBRATED_ARMS = PREDICTION_ARMS[:-1]
HORIZON_ORDER = (64, 65, 96)
CALIBRATION_GRID_STEPS = 401
CALIBRATION_MAXIMUM = 2.0
COORDINATE_SALT = 220022
EXPECTED_READER_REPLAYS = 32
EXPECTED_PACKET_SLOTS = 17_664
EXPECTED_PUBLIC_WORK = 1_130_496
EXPECTED_CALIBRATION_EVALUATIONS = 7_391_232
O1C19_CONFIG_SHA256 = "96d9017d2262537281218ccd23b52533c8ed801e245bea6bcb13fa13bd186c61"
O1C19_SCIENCE_COMMIT = "27cd5b1f1e3172218c9c993846f1dcc950bb909a"
O1C21_CONFIG_SHA256 = "c683237f7f251ffb2314b01cfbfbbfeac9acd557379a3070e982c0bc15b4a39d"
O1C21_SOURCE_COMMIT = "4ba1cc61c3b786139749c3e57137e3ba7ae6cf74"
_O1C19_FROZEN_SOURCE_RELATIVES = {
    "config": "configs/full256_multiresolution_build_loo_v1.json",
    "pyproject": "pyproject.toml",
    "module_full256_action_pool": "src/o1_crypto_lab/full256_action_pool.py",
    "module_full256_multiresolution_build_loo": (
        "src/o1_crypto_lab/full256_multiresolution_build_loo.py"
    ),
    "module_full256_multiresolution_build_loo_run": (
        "src/o1_crypto_lab/full256_multiresolution_build_loo_run.py"
    ),
    "module_full256_proof_pool": "src/o1_crypto_lab/full256_proof_pool.py",
    "module_living_inverse": "src/o1_crypto_lab/living_inverse.py",
    "module_o1_streaming_core": "src/o1_crypto_lab/o1_streaming_core.py",
    "module_online_causal_controller": (
        "src/o1_crypto_lab/online_causal_controller.py"
    ),
    "module_online_multiresolution_controller": (
        "src/o1_crypto_lab/online_multiresolution_controller.py"
    ),
    "module_run_capsule": "src/o1_crypto_lab/run_capsule.py",
    "module_stationarity_critic": "src/o1_crypto_lab/stationarity_critic.py",
}
_COMPLEMENT_TOLERANCE = 1e-6
_COMMUTATION_TOLERANCE = 1e-6
_FORMAL_CONTROLS = (
    "The future O1C-0019 capsule is resolved by its reserved attempt identity, verified manifest and exact frozen source config; no O1C-0019 efficacy result participates in this source freeze.",
    "Every fold loads only its frozen reader and learning receipt plus the four immutable public BUILD action pools before held-out prediction freeze.",
    "Per-horizon quantizer scales are medians of finite nonzero absolute deltas from the three non-held-out public replays; labels and signed reward never enter scale fitting.",
    "Nested active sets K=12/52/128/256 are prefixes of one SHA-256-derived coordinate permutation while all 256 target key bits remain unknown.",
    "Float delta sum, quantized int8 vault, last-horizon-only, unit-sign and coordinate-shuffled arms receive matched public packet slots.",
    "Immediate duplicate groups must leave the complete 352-byte accumulator byte-identical and accepted-update counts unchanged.",
    "Polarity swap must negate every finite packet delta and vault logit; coordinate permutation must commute with accumulation to float32 tolerance.",
    "For every fold, all predictions, delta ledgers, scales and live-state commitments freeze before that fold's held-out BUILD label is used; the held-out ordinal is excluded from its calibration-label ledger.",
    "No solver regeneration, fresh entropy, sibling access, MPS call or GPU call is permitted.",
)


class O1C19CausalVaultBridgeRunError(ValueError):
    """A config, frozen prerequisite, lifecycle, or exact budget differs."""


def _json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise O1C19CausalVaultBridgeRunError(
            "document is not finite canonical JSON"
        ) from exc
    return (rendered + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _mapping(
    value: object,
    field: str,
    expected: set[str] | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C19CausalVaultBridgeRunError(f"{field} must be an object")
    if expected is not None and set(value) != expected:
        raise O1C19CausalVaultBridgeRunError(f"{field} fields differ")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise O1C19CausalVaultBridgeRunError(
            f"{field} must be an integer in [{minimum},{maximum}]"
        )
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise O1C19CausalVaultBridgeRunError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise O1C19CausalVaultBridgeRunError(f"{field} differs")
    return result


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C19CausalVaultBridgeRunError(f"{field} must be a lowercase SHA-256")
    return value


def _commit(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C19CausalVaultBridgeRunError(
            f"{field} must be a lowercase 40-hex commit"
        )
    return value


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C19CausalVaultBridgeRunError(f"{field} is unreadable") from exc
    return _mapping(value, field)


def _process_peak_rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if value > 16 * 1024 * 1024 else value * 1024


def _git_blob_bytes(root: Path, commit: str, relative: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "show", f"{commit}:{relative}"),
            cwd=root,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise O1C19CausalVaultBridgeRunError(
            f"source commit blob is unavailable: {commit}:{relative}"
        ) from exc
    return completed.stdout


def _git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ("git", "merge-base", "--is-ancestor", ancestor, descendant),
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _expected_o1c19_frozen_source_hashes(config: "O1C22RunConfig") -> dict[str, str]:
    return {
        field: _sha256_bytes(
            _git_blob_bytes(config.root, config.o1c19_science_commit, relative)
        )
        for field, relative in _O1C19_FROZEN_SOURCE_RELATIVES.items()
    }


def _verify_commit_bound_files(
    root: Path,
    commit: str,
    relatives: Sequence[str],
) -> dict[str, str]:
    """Require state-defining descendant bytes to equal their frozen commit."""

    commitments: dict[str, str] = {}
    for relative in relatives:
        current = (root / relative).resolve(strict=True)
        if not current.is_relative_to(root):
            raise O1C19CausalVaultBridgeRunError("commit-bound source escapes lab")
        current_bytes = current.read_bytes()
        frozen_bytes = _git_blob_bytes(root, commit, relative)
        if current_bytes != frozen_bytes:
            raise O1C19CausalVaultBridgeRunError(
                f"commit-bound source drifted from {commit}: {relative}"
            )
        commitments[relative] = _sha256_bytes(current_bytes)
    return commitments


@dataclass(frozen=True)
class O1C22Budgets:
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
    maximum_accumulator_live_state_bytes: int
    maximum_o1c19_reader_replays: int
    maximum_packet_slot_observations: int
    maximum_physical_public_work_units: int
    maximum_calibration_value_evaluations: int

    @classmethod
    def from_mapping(cls, value: object) -> "O1C22Budgets":
        row = _mapping(value, "budgets", set(cls.__dataclass_fields__))
        cpu = _number(
            row["maximum_cpu_seconds"], "budgets.maximum_cpu_seconds", 0.001, 86_400.0
        )
        wall = _number(
            row["maximum_wall_seconds"], "budgets.maximum_wall_seconds", 0.001, 86_400.0
        )
        integer_limits = {
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
            "maximum_accumulator_live_state_bytes": 1_000_000,
            "maximum_o1c19_reader_replays": 1_000_000,
            "maximum_packet_slot_observations": 1_000_000_000,
            "maximum_physical_public_work_units": 2_000_000_000,
            "maximum_calibration_value_evaluations": 2_000_000_000,
        }
        integers = {
            name: _integer(row[name], f"budgets.{name}", 0, maximum)
            for name, maximum in integer_limits.items()
        }
        result = cls(
            maximum_cpu_seconds=cpu,
            maximum_wall_seconds=wall,
            **integers,
        )
        exact = {
            "maximum_cpu_seconds": 600.0,
            "maximum_wall_seconds": 600.0,
            "maximum_resident_memory_mib": 768,
            "maximum_persistent_artifact_bytes": 33_554_432,
            "maximum_source_artifact_bytes_read": 33_554_432,
            "expected_existing_build_pools": 4,
            "maximum_physical_public_pools_generated": 0,
            "maximum_native_solver_branches": 0,
            "maximum_scientific_entropy_calls": 0,
            "maximum_sibling_reads": 0,
            "maximum_sibling_writes": 0,
            "maximum_mps_calls": 0,
            "maximum_gpu_calls": 0,
            "maximum_accumulator_live_state_bytes": FORMAL_VAULT_BYTES,
            "maximum_o1c19_reader_replays": EXPECTED_READER_REPLAYS,
            "maximum_packet_slot_observations": EXPECTED_PACKET_SLOTS,
            "maximum_physical_public_work_units": EXPECTED_PUBLIC_WORK,
            "maximum_calibration_value_evaluations": EXPECTED_CALIBRATION_EVALUATIONS,
        }
        for name, expected in exact.items():
            if getattr(result, name) != expected:
                raise O1C19CausalVaultBridgeRunError(
                    f"budgets.{name} must equal exact frozen work {expected}"
                )
        return result


@dataclass(frozen=True)
class O1C22RunConfig:
    top: Mapping[str, object]
    config_path: Path
    root: Path
    budgets: O1C22Budgets
    corpus: ArtifactBuildCorpus
    upstream_top: Mapping[str, object]
    upstream_controller: MultiResolutionControllerConfig
    causal_config: CausalEvidenceConfig
    o1c19_config_path: Path
    o1c21_config_path: Path
    o1c19_config_sha256: str
    o1c21_config_sha256: str
    o1c19_science_commit: str
    o1c21_source_commit: str


def _validate_experiment(
    value: object, controller: MultiResolutionControllerConfig
) -> None:
    fields = {
        "schema",
        "active_coordinate_counts",
        "calibration",
        "coordinate_permutation_domain",
        "coordinate_permutation_salt",
        "duplicate_mode",
        "efficacy_gates",
        "group_id_domain",
        "horizon_order",
        "prediction_arms",
        "quantizer",
        "reader_delta",
        "source_anchor",
        "upstream_reader_state_billed_separately",
        "vault_state_schema",
    }
    row = _mapping(value, "experiment", fields)
    exact_scalars = {
        "schema": "o1-256-o1c19-causal-vault-bridge-config-v1",
        "coordinate_permutation_domain": "o1c22-nested-active-coordinate-order-v1",
        "coordinate_permutation_salt": COORDINATE_SALT,
        "duplicate_mode": "immediate-atomic-group-replay",
        "group_id_domain": "o1c22-public-packet-delta-group-v1",
        "reader_delta": "exact-incremental-q-after-minus-q-before-from-frozen-o1c19-reader",
        "source_anchor": "o1c19-frozen-learned-reader-exhaustive-k256-prediction",
        "upstream_reader_state_billed_separately": True,
        "vault_state_schema": "o1-256-causal-evidence-stream-v1",
    }
    for field, expected in exact_scalars.items():
        if row[field] != expected:
            raise O1C19CausalVaultBridgeRunError(f"experiment.{field} differs")
    if tuple(row["active_coordinate_counts"]) != ACTIVE_COORDINATE_WIDTHS:
        raise O1C19CausalVaultBridgeRunError("active coordinate ladder differs")
    if (
        tuple(row["horizon_order"]) != HORIZON_ORDER
        or tuple(controller.ordered_horizons) != HORIZON_ORDER
    ):
        raise O1C19CausalVaultBridgeRunError("O1C-0019 horizon order differs")
    if tuple(row["prediction_arms"]) != PREDICTION_ARMS:
        raise O1C19CausalVaultBridgeRunError("prediction arm inventory differs")
    calibration = _mapping(
        row["calibration"],
        "experiment.calibration",
        {
            "fit_split",
            "maximum_nonnegative_scale",
            "orientation_flip_allowed",
            "scale_grid_steps",
            "selection",
        },
    )
    if dict(calibration) != {
        "fit_split": "three-non-held-out-BUILD-episodes-with-fold-local-predictions-frozen-before-calibration-use",
        "maximum_nonnegative_scale": CALIBRATION_MAXIMUM,
        "orientation_flip_allowed": False,
        "scale_grid_steps": CALIBRATION_GRID_STEPS,
        "selection": "minimum-aggregate-nll-then-smallest-scale",
    }:
        raise O1C19CausalVaultBridgeRunError("calibration protocol differs")
    quantizer = _mapping(
        row["quantizer"],
        "experiment.quantizer",
        {
            "clip_magnitude",
            "fallback_scale",
            "rounding",
            "scale_estimator",
            "zero_updates_are_skipped",
        },
    )
    if dict(quantizer) != {
        "clip_magnitude": 8,
        "fallback_scale": 1.0,
        "rounding": "half-away-from-zero",
        "scale_estimator": "per-horizon-median-nonzero-absolute-training-public-delta",
        "zero_updates_are_skipped": True,
    }:
        raise O1C19CausalVaultBridgeRunError("quantizer protocol differs")
    efficacy = _mapping(
        row["efficacy_gates"],
        "experiment.efficacy_gates",
        {
            "all_four_final_folds_positive",
            "int8_mean_final_compression_bits_minimum",
            "int8_minus_coordinate_shuffled_mean_compression_positive",
            "int8_minus_last_horizon_only_mean_compression_positive",
            "int8_minus_unit_sign_sum_mean_compression_positive",
            "int8_preserves_float_compression_fraction_minimum",
            "strict_mean_compression_growth_across_k",
        },
    )
    if dict(efficacy) != {
        "all_four_final_folds_positive": True,
        "int8_mean_final_compression_bits_minimum": 1.0,
        "int8_minus_coordinate_shuffled_mean_compression_positive": True,
        "int8_minus_last_horizon_only_mean_compression_positive": True,
        "int8_minus_unit_sign_sum_mean_compression_positive": True,
        "int8_preserves_float_compression_fraction_minimum": 0.9,
        "strict_mean_compression_growth_across_k": True,
    }:
        raise O1C19CausalVaultBridgeRunError("efficacy gate inventory differs")


def load_o1c19_causal_vault_bridge_run_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C22RunConfig:
    """Load every pinned dependency without resolving the future O1C-0019 run."""

    config_path = Path(path).resolve(strict=True)
    lab_root = (
        Path(root).resolve(strict=True)
        if root is not None
        else Path(__file__).resolve().parents[2]
    )
    top = dict(
        _mapping(
            _read_json(config_path, "O1C-0022 config"),
            "config",
            {
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
                "prerequisites",
                "experiment",
            },
        )
    )
    if (
        top["schema"] != RUN_CONFIG_SCHEMA
        or top["attempt_id"] != ATTEMPT_ID
        or top["slug"] != FORMAL_SLUG
        or top["claim_level"] != ClaimLevel.RETROSPECTIVE.value
    ):
        raise O1C19CausalVaultBridgeRunError("formal O1C-0022 identity differs")
    for field in ("hypothesis", "prediction", "next_action"):
        if not isinstance(top[field], str) or not str(top[field]).strip():
            raise O1C19CausalVaultBridgeRunError(f"config.{field} is required")
    controls = top["controls"]
    if not isinstance(controls, list) or tuple(controls) != _FORMAL_CONTROLS:
        raise O1C19CausalVaultBridgeRunError("formal control inventory differs")
    budgets = O1C22Budgets.from_mapping(top["budgets"])

    prerequisites = _mapping(
        top["prerequisites"], "prerequisites", {"o1c19", "o1c21_state"}
    )
    upstream = _mapping(
        prerequisites["o1c19"],
        "prerequisites.o1c19",
        {
            "attempt_id",
            "config_path",
            "config_sha256",
            "science_commit",
            "source_selection",
        },
    )
    causal = _mapping(
        prerequisites["o1c21_state"],
        "prerequisites.o1c21_state",
        {
            "config_path",
            "config_sha256",
            "live_state_bytes",
            "source_commit",
        },
    )
    if (
        upstream["attempt_id"] != UPSTREAM_ATTEMPT_ID
        or upstream["source_selection"] != "reserved-finalized-attempt-only"
        or upstream["config_path"]
        != "configs/full256_multiresolution_build_loo_v1.json"
        or causal["config_path"] != "configs/causal_evidence_stream_256_v1.json"
    ):
        raise O1C19CausalVaultBridgeRunError("O1C-0019 selection differs")
    o1c19_hash = _sha256(upstream["config_sha256"], "o1c19 config hash")
    o1c21_hash = _sha256(causal["config_sha256"], "o1c21 config hash")
    o1c19_commit = _commit(upstream["science_commit"], "o1c19 science commit")
    o1c21_commit = _commit(causal["source_commit"], "o1c21 source commit")
    if (
        o1c19_hash != O1C19_CONFIG_SHA256
        or o1c19_commit != O1C19_SCIENCE_COMMIT
        or o1c21_hash != O1C21_CONFIG_SHA256
        or o1c21_commit != O1C21_SOURCE_COMMIT
    ):
        raise O1C19CausalVaultBridgeRunError(
            "formal O1C-0019/O1C-0021 prerequisite pins differ"
        )
    if causal["live_state_bytes"] != FORMAL_VAULT_BYTES:
        raise O1C19CausalVaultBridgeRunError("O1C-0021 live-state pin differs")

    def dependency_path(raw: object, field: str) -> Path:
        if not isinstance(raw, str) or not raw:
            raise O1C19CausalVaultBridgeRunError(f"{field} is required")
        candidate = (lab_root / raw).resolve(strict=True)
        if not candidate.is_relative_to(lab_root):
            raise O1C19CausalVaultBridgeRunError(f"{field} escapes the lab")
        return candidate

    o1c19_path = dependency_path(upstream["config_path"], "o1c19 config path")
    o1c21_path = dependency_path(causal["config_path"], "o1c21 config path")
    if _sha256_file(o1c19_path) != o1c19_hash:
        raise O1C19CausalVaultBridgeRunError("pinned O1C-0019 config hash differs")
    if _sha256_file(o1c21_path) != o1c21_hash:
        raise O1C19CausalVaultBridgeRunError("pinned O1C-0021 config hash differs")
    _verify_commit_bound_files(
        lab_root,
        o1c21_commit,
        (
            "configs/causal_evidence_stream_256_v1.json",
            "src/o1_crypto_lab/causal_evidence_stream.py",
            "src/o1_crypto_lab/o1_streaming_core.py",
        ),
    )

    upstream_top, upstream_experiment, corpus, _upstream_budgets = (
        load_full256_build_loo_run_config(o1c19_path, root=lab_root)
    )
    _causal_top, causal_config, _causal_budgets = load_causal_evidence_run_config(
        o1c21_path
    )
    if causal_config.live_state_bytes != FORMAL_VAULT_BYTES:
        raise O1C19CausalVaultBridgeRunError(
            "loaded O1C-0021 state is not exactly 352 bytes"
        )
    _validate_experiment(top["experiment"], upstream_experiment.controller)
    source = _mapping(
        top["source"],
        "source",
        {
            "o1c18_capsule",
            "o1c18_manifest_sha256",
            "o1c18_artifact_index_sha256",
            "o1c18_public_build_corpus_sha256",
        },
    )
    expected_capsule = str(Path(str(source["o1c18_capsule"])))
    if (
        expected_capsule != str(corpus.capsule_path.relative_to(lab_root))
        or _sha256(source["o1c18_manifest_sha256"], "source manifest")
        != corpus.capsule_manifest_sha256
        or _sha256(source["o1c18_artifact_index_sha256"], "source index")
        != corpus.artifact_index_sha256
        or _sha256(source["o1c18_public_build_corpus_sha256"], "source corpus")
        != corpus.sha256
        or len(corpus.episodes) != budgets.expected_existing_build_pools
    ):
        raise O1C19CausalVaultBridgeRunError("pinned O1C-0018 corpus differs")
    return O1C22RunConfig(
        top=top,
        config_path=config_path,
        root=lab_root,
        budgets=budgets,
        corpus=corpus,
        upstream_top=upstream_top,
        upstream_controller=upstream_experiment.controller,
        causal_config=causal_config,
        o1c19_config_path=o1c19_path,
        o1c21_config_path=o1c21_path,
        o1c19_config_sha256=o1c19_hash,
        o1c21_config_sha256=o1c21_hash,
        o1c19_science_commit=o1c19_commit,
        o1c21_source_commit=o1c21_commit,
    )


@dataclass(frozen=True)
class O1C19FoldSource:
    fold_index: int
    held_out_ordinal: int
    target_id: str
    reader_bytes: bytes
    slow_state_bytes: bytes
    reader_sha256: str
    slow_state_sha256: str
    learning_freeze_sha256: str
    prediction_freeze_sha256: str
    upstream_learned_raw_prediction: np.ndarray
    source_artifact_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        _integer(self.fold_index, "fold_index", 0, 3)
        _integer(self.held_out_ordinal, "held_out_ordinal", 0, 3)
        if not isinstance(self.target_id, str) or not self.target_id:
            raise O1C19CausalVaultBridgeRunError("fold target_id is required")
        for field in (
            "reader_sha256",
            "slow_state_sha256",
            "learning_freeze_sha256",
            "prediction_freeze_sha256",
        ):
            _sha256(getattr(self, field), field)
        if _sha256_bytes(self.reader_bytes) != self.reader_sha256:
            raise O1C19CausalVaultBridgeRunError("fold reader bytes differ")
        if _sha256_bytes(self.slow_state_bytes) != self.slow_state_sha256:
            raise O1C19CausalVaultBridgeRunError("fold slow-state bytes differ")
        prediction = np.asarray(self.upstream_learned_raw_prediction)
        if (
            prediction.shape != (KEY_BITS,)
            or prediction.dtype != np.float32
            or not bool(np.isfinite(prediction).all())
        ):
            raise O1C19CausalVaultBridgeRunError(
                "upstream raw prediction must be finite float32[256]"
            )
        frozen = prediction.copy()
        frozen.setflags(write=False)
        object.__setattr__(self, "upstream_learned_raw_prediction", frozen)


@dataclass(frozen=True)
class O1C19Prerequisite:
    finalized: FinalizedRun
    folds: tuple[O1C19FoldSource, ...]
    artifact_index_sha256: str
    result_sha256: str
    source_artifact_bytes_read: int

    def __post_init__(self) -> None:
        if self.finalized.attempt_id != UPSTREAM_ATTEMPT_ID:
            raise O1C19CausalVaultBridgeRunError("upstream attempt differs")
        if tuple(row.fold_index for row in self.folds) != tuple(range(4)):
            raise O1C19CausalVaultBridgeRunError("upstream fold inventory differs")
        _sha256(self.artifact_index_sha256, "artifact_index_sha256")
        _sha256(self.result_sha256, "result_sha256")
        _integer(
            self.source_artifact_bytes_read,
            "source_artifact_bytes_read",
            1,
            1 << 50,
        )


def _canonical_commitment(document: Mapping[str, object], field: str) -> str:
    unsigned = dict(document)
    claimed = _sha256(unsigned.pop("freeze_sha256", None), field)
    actual = _sha256_bytes(canonical_json_bytes(unsigned))
    if claimed != actual:
        raise O1C19CausalVaultBridgeRunError(f"{field} differs")
    return claimed


def _artifact_entry(index: Mapping[str, object], relative: str, payload: bytes) -> str:
    artifacts = _mapping(index.get("artifacts"), "O1C-0019 artifact inventory")
    entry = _mapping(
        artifacts.get(relative),
        f"O1C-0019 artifact {relative}",
        {"sha256", "bytes", "phase"},
    )
    digest = _sha256_bytes(payload)
    if (
        _sha256(entry["sha256"], f"artifact {relative} hash") != digest
        or entry["bytes"] != len(payload)
        or not isinstance(entry["phase"], str)
    ):
        raise O1C19CausalVaultBridgeRunError(
            f"O1C-0019 artifact-index entry differs: {relative}"
        )
    return digest


def _verify_upstream_capsule_config(
    config: O1C22RunConfig,
    capsule_config: Mapping[str, object],
) -> Mapping[str, object]:
    """Bind a descendant execution to the exact frozen O1C-0019 science bytes."""

    source_hashes = _mapping(
        capsule_config.get("source_hashes"), "O1C-0019 source hashes"
    )
    capsule_commit = _commit(capsule_config.get("commit"), "O1C-0019 capsule commit")
    if (
        capsule_config.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or capsule_config.get("claim_level") != ClaimLevel.RETROSPECTIVE.value
        or capsule_config.get("config") != config.upstream_top
        or source_hashes.get("config") != config.o1c19_config_sha256
    ):
        raise O1C19CausalVaultBridgeRunError(
            "O1C-0019 exact frozen source config differs"
        )
    if not _git_is_ancestor(
        config.root,
        config.o1c19_science_commit,
        capsule_commit,
    ):
        raise O1C19CausalVaultBridgeRunError(
            "O1C-0019 capsule commit does not descend from the science commit"
        )
    expected_hashes = _expected_o1c19_frozen_source_hashes(config)
    mismatched = tuple(
        field
        for field, expected in expected_hashes.items()
        if source_hashes.get(field) != expected
    )
    if mismatched:
        raise O1C19CausalVaultBridgeRunError(
            "O1C-0019 frozen source bytes differ: " + ", ".join(mismatched)
        )
    return source_hashes


def _load_verified_o1c19_prerequisite(
    config: O1C22RunConfig,
    finalized: FinalizedRun,
) -> O1C19Prerequisite:
    """Verify the finalized O1C-0019 capsule without consulting its efficacy."""

    if not finalized.verification.ok:
        raise O1C19CausalVaultBridgeRunError("O1C-0019 manifest verification failed")
    capsule = finalized.path
    metrics = _read_json(capsule / "metrics.json", "O1C-0019 metrics")
    values = _mapping(metrics.get("values"), "O1C-0019 metric values")
    if (
        metrics.get("attempt_id") != UPSTREAM_ATTEMPT_ID
        or metrics.get("status") != "completed"
        or values.get("operationally_complete") is not True
        or values.get("operational_failure") is not False
    ):
        raise O1C19CausalVaultBridgeRunError(
            "O1C-0019 is finalized but operationally incomplete"
        )
    capsule_config = _read_json(capsule / "config.json", "O1C-0019 capsule config")
    _verify_upstream_capsule_config(config, capsule_config)

    artifacts_root = capsule / "artifacts"
    index_bytes = (artifacts_root / "artifact_index.json").read_bytes()
    index = _mapping(json.loads(index_bytes.decode("ascii")), "O1C-0019 artifact index")
    if (
        index.get("schema")
        != "o1-256-fullround-multiresolution-build-loo-artifact-index-v1"
        or index.get("attempt_id") != UPSTREAM_ATTEMPT_ID
    ):
        raise O1C19CausalVaultBridgeRunError("O1C-0019 artifact index differs")
    result_bytes = (
        artifacts_root / "full256_multiresolution_build_loo.json"
    ).read_bytes()
    _artifact_entry(index, "full256_multiresolution_build_loo.json", result_bytes)
    result = _mapping(json.loads(result_bytes.decode("ascii")), "O1C-0019 result")
    if (
        result.get("schema") != BUILD_LOO_RESULT_SCHEMA
        or result.get("config") != config.upstream_controller.describe()
        or _mapping(result.get("source"), "O1C-0019 result source").get(
            "artifact_corpus_sha256"
        )
        != config.corpus.sha256
    ):
        raise O1C19CausalVaultBridgeRunError("O1C-0019 structural result differs")

    bytes_read = (
        config.corpus.bytes_read
        + len(index_bytes)
        + len(result_bytes)
        + (capsule / "metrics.json").stat().st_size
        + (capsule / "config.json").stat().st_size
    )
    folds: list[O1C19FoldSource] = []
    result_folds = result.get("folds")
    if not isinstance(result_folds, list) or len(result_folds) != 4:
        raise O1C19CausalVaultBridgeRunError("O1C-0019 result fold rows differ")
    learned_raw_index = RAW_ARMS.index("learned_reader_exhaustive")
    for fold_index, episode in enumerate(config.corpus.episodes):
        prefix = f"folds/{episode.target_id}"
        paths = {
            "learning": f"{prefix}/learning_freeze.json",
            "reader": f"{prefix}/reader.bin",
            "slow": f"{prefix}/slow_state.bin",
            "prediction": f"{prefix}/prediction_freeze.json",
            "raw": f"{prefix}/raw_predictions.f32le",
        }
        payloads = {
            name: (artifacts_root / relative).read_bytes()
            for name, relative in paths.items()
        }
        artifact_hashes = {
            name: _artifact_entry(index, paths[name], payload)
            for name, payload in payloads.items()
        }
        bytes_read += sum(len(value) for value in payloads.values())
        learning = _mapping(
            json.loads(payloads["learning"].decode("ascii")),
            f"O1C-0019 fold {fold_index} learning receipt",
        )
        prediction = _mapping(
            json.loads(payloads["prediction"].decode("ascii")),
            f"O1C-0019 fold {fold_index} prediction receipt",
        )
        learning_freeze = _canonical_commitment(
            learning, f"fold {fold_index} learning freeze"
        )
        prediction_freeze = _canonical_commitment(
            prediction, f"fold {fold_index} prediction freeze"
        )
        expected_training = [
            config.corpus.episodes[(episode.ordinal + offset) % 4].target_id
            for offset in range(1, 4)
        ]
        if (
            learning.get("schema") != BUILD_LOO_LEARNING_FREEZE_SCHEMA
            or learning.get("phase")
            != "FINAL_READER_AND_ATOMIC_CRITIC_FROZEN_BEFORE_HELD_OUT_POLICY"
            or learning.get("fold_index") != fold_index
            or learning.get("held_out_ordinal") != episode.ordinal
            or learning.get("held_out_target_id") != episode.target_id
            or learning.get("held_out_action_pool_sha256") != episode.action_pool_sha256
            or learning.get("training_target_ids") != expected_training
            or learning.get("training_target_count") != 3
            or learning.get("held_out_labels_materialized") != 0
            or learning.get("held_out_reader_updates") != 0
            or learning.get("held_out_critic_updates") != 0
            or learning.get("reader_state_sha256") != artifact_hashes["reader"]
            or learning.get("slow_state_sha256") != artifact_hashes["slow"]
        ):
            raise O1C19CausalVaultBridgeRunError(
                f"O1C-0019 fold {fold_index} learning receipt differs"
            )
        if (
            prediction.get("schema") != BUILD_LOO_PREDICTION_FREEZE_SCHEMA
            or prediction.get("phase")
            != "ALL_HELD_OUT_TRAJECTORIES_FROZEN_BEFORE_LABEL_ACCESS"
            or prediction.get("fold_index") != fold_index
            or prediction.get("held_out_ordinal") != episode.ordinal
            or prediction.get("target_id") != episode.target_id
            or prediction.get("action_pool_sha256") != episode.action_pool_sha256
            or prediction.get("reader_state_sha256") != artifact_hashes["reader"]
            or prediction.get("slow_state_sha256") != artifact_hashes["slow"]
            or prediction.get("raw_arms") != list(RAW_ARMS)
            or prediction.get("raw_predictions_sha256") != artifact_hashes["raw"]
            or prediction.get("held_out_labels_materialized") != 0
            or prediction.get("held_out_reader_updates") != 0
            or prediction.get("held_out_critic_updates") != 0
        ):
            raise O1C19CausalVaultBridgeRunError(
                f"O1C-0019 fold {fold_index} prediction receipt differs"
            )
        raw = np.frombuffer(payloads["raw"], dtype="<f4")
        if raw.size != len(RAW_ARMS) * KEY_BITS:
            raise O1C19CausalVaultBridgeRunError(
                f"O1C-0019 fold {fold_index} raw prediction width differs"
            )
        raw = raw.reshape(len(RAW_ARMS), KEY_BITS)
        controller = MultiResolutionCausalController(config.upstream_controller)
        controller.load_slow_state_bytes(payloads["slow"])
        if (
            controller.slow_state_bytes() != payloads["slow"]
            or controller.reader_state_bytes() != payloads["reader"]
        ):
            raise O1C19CausalVaultBridgeRunError(
                f"O1C-0019 fold {fold_index} controller restore differs"
            )
        result_fold = _mapping(
            result_folds[fold_index], f"O1C-0019 result fold {fold_index}"
        )
        if (
            result_fold.get("fold_index") != fold_index
            or result_fold.get("held_out_ordinal") != episode.ordinal
            or result_fold.get("learning_freeze_sha256") != learning_freeze
            or result_fold.get("prediction_freeze_sha256") != prediction_freeze
        ):
            raise O1C19CausalVaultBridgeRunError(
                f"O1C-0019 result fold {fold_index} commitments differ"
            )
        folds.append(
            O1C19FoldSource(
                fold_index=fold_index,
                held_out_ordinal=episode.ordinal,
                target_id=episode.target_id,
                reader_bytes=payloads["reader"],
                slow_state_bytes=payloads["slow"],
                reader_sha256=artifact_hashes["reader"],
                slow_state_sha256=artifact_hashes["slow"],
                learning_freeze_sha256=learning_freeze,
                prediction_freeze_sha256=prediction_freeze,
                upstream_learned_raw_prediction=raw[learned_raw_index].copy(),
                source_artifact_hashes=dict(artifact_hashes),
            )
        )
    if bytes_read > config.budgets.maximum_source_artifact_bytes_read:
        raise O1C19CausalVaultBridgeRunError(
            "verified source artifacts exceed the read budget"
        )
    return O1C19Prerequisite(
        finalized=finalized,
        folds=tuple(folds),
        artifact_index_sha256=_sha256_bytes(index_bytes),
        result_sha256=_sha256_bytes(result_bytes),
        source_artifact_bytes_read=bytes_read,
    )


@dataclass(frozen=True)
class O1C22Preflight:
    report: Mapping[str, object]
    config: O1C22RunConfig
    prerequisite: O1C19Prerequisite | None

    @property
    def ready(self) -> bool:
        return self.prerequisite is not None and self.report.get("status") == "ready"


def preflight_o1c19_causal_vault_bridge(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> O1C22Preflight:
    """Report a pending/invalid O1C-0019 without reserving O1C-0022."""

    config = load_o1c19_causal_vault_bridge_run_config(path, root=root)
    manager = RunCapsuleManager(config.root)
    o1c22_finalized = manager.finalized_attempt(ATTEMPT_ID)
    recoverable_ids = manager.recoverable_attempt_ids()
    finalized = manager.finalized_attempt(UPSTREAM_ATTEMPT_ID)
    base = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prerequisite_attempt_id": UPSTREAM_ATTEMPT_ID,
        "o1c18_manifest_verified": True,
        "o1c18_artifact_index_verified": True,
        "o1c18_build_corpus_sha256": config.corpus.sha256,
        "o1c21_config_sha256": config.o1c21_config_sha256,
        "o1c21_live_state_bytes": config.causal_config.live_state_bytes,
        "o1c22_reserved_by_this_preflight": False,
        "o1c22_existing_finalized": o1c22_finalized is not None,
        "o1c22_existing_recoverable": ATTEMPT_ID in recoverable_ids,
    }
    if finalized is None:
        report = {
            **base,
            "status": "prerequisite-pending",
            "o1c19_recoverable": UPSTREAM_ATTEMPT_ID in recoverable_ids,
            "reason": "reserved finalized O1C-0019 capsule is not available",
        }
        return O1C22Preflight(report, config, None)
    try:
        prerequisite = _load_verified_o1c19_prerequisite(config, finalized)
    except Exception as exc:
        report = {
            **base,
            "status": "prerequisite-invalid",
            "o1c19_manifest_sha256": finalized.manifest_sha256,
            "reason": f"{type(exc).__name__}: {exc}",
        }
        return O1C22Preflight(report, config, None)
    report = {
        **base,
        "status": "ready",
        "o1c19_manifest_sha256": finalized.manifest_sha256,
        "o1c19_artifact_index_sha256": prerequisite.artifact_index_sha256,
        "o1c19_result_sha256": prerequisite.result_sha256,
        "o1c19_fold_count": len(prerequisite.folds),
        "source_artifact_bytes_read": prerequisite.source_artifact_bytes_read,
    }
    return O1C22Preflight(report, config, prerequisite)


ArtifactCallback = Callable[[Mapping[str, bytes], Mapping[str, object]], None]


def _freeze_document(unsigned: Mapping[str, object]) -> dict[str, object]:
    return {
        **unsigned,
        "freeze_sha256": _sha256_bytes(canonical_json_bytes(dict(unsigned))),
    }


def _artifact_commitments(artifacts: Mapping[str, bytes]) -> dict[str, object]:
    return {
        name: {"sha256": _sha256_bytes(payload), "bytes": len(payload)}
        for name, payload in sorted(artifacts.items())
    }


def _fresh_extraction(
    fold: O1C19FoldSource,
    controller_config: MultiResolutionControllerConfig,
    pool: object,
    coordinates: Sequence[int],
    *,
    group_salt: int,
) -> PacketDeltaExtraction:
    """Restore a fresh frozen controller for exactly one public replay."""

    controller = MultiResolutionCausalController(controller_config)
    controller.load_slow_state_bytes(fold.slow_state_bytes)
    if (
        controller.reader_state_bytes() != fold.reader_bytes
        or controller.slow_state_bytes() != fold.slow_state_bytes
    ):
        raise O1C19CausalVaultBridgeRunError("fresh O1C-0019 restore differs")
    extraction = extract_frozen_o1c19_packet_groups(
        controller,
        pool,
        tuple(coordinates),
        group_salt=group_salt,
    )
    if (
        extraction.reader_state_sha256 != fold.reader_sha256
        or extraction.slow_state_sha256 != fold.slow_state_sha256
    ):
        raise O1C19CausalVaultBridgeRunError(
            "extraction is not bound to the frozen fold reader"
        )
    return extraction


def _new_bridge_state(
    config: CausalEvidenceConfig,
    core: StreamingSelectiveHolographicCore,
    shuffled_destinations: Sequence[int],
) -> CausalVaultBridgeState:
    state = CausalVaultBridgeState.initial(config, core, shuffled_destinations)
    if state.primary_live_state_bytes != FORMAL_VAULT_BYTES:
        raise O1C19CausalVaultBridgeRunError("primary live state is not 352 bytes")
    return state


def _execute_extraction(
    causal_config: CausalEvidenceConfig,
    core: StreamingSelectiveHolographicCore,
    quantizer: FrozenMedianAbsQuantizer,
    extraction: PacketDeltaExtraction,
    shuffled_destinations: Sequence[int],
) -> CausalVaultBridgeExecution:
    bridge = CausalVaultBridge(
        causal_config,
        quantizer,
        extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        reader_state_sha256=extraction.reader_state_sha256,
        active_coordinates_sha256=active_coordinate_sequence_sha256(
            extraction.active_coordinates
        ),
    )
    state = _new_bridge_state(causal_config, core, shuffled_destinations)
    return execute_packet_delta_groups(bridge, state, extraction.groups)


def _execution_logits(execution: CausalVaultBridgeExecution) -> np.ndarray:
    state = execution.state
    result = np.stack(
        (
            state.raw_float_accumulator,
            state.normalized_float_accumulator,
            state.vault.evidence.astype(np.float64),
            state.last_only.astype(np.float64),
            state.unit_sign_sum.astype(np.float64),
            state.shuffled.astype(np.float64),
            np.zeros(KEY_BITS, dtype=np.float64),
        ),
        axis=0,
    )
    if result.shape != (len(PREDICTION_ARMS), KEY_BITS) or not bool(
        np.isfinite(result).all()
    ):
        raise O1C19CausalVaultBridgeRunError("bridge prediction array differs")
    return result


def _nll_bits(logits: np.ndarray, truth_bits: np.ndarray) -> float:
    values = np.asarray(logits, dtype=np.float64)
    truth = np.asarray(truth_bits, dtype=np.uint8)
    if values.shape != truth.shape or not bool(np.isfinite(values).all()):
        raise O1C19CausalVaultBridgeRunError("NLL arrays differ")
    signs = 2.0 * truth.astype(np.float64) - 1.0
    argument = -signs * values
    softplus = np.maximum(argument, 0.0) + np.log1p(np.exp(-np.abs(argument)))
    return float(softplus.sum() / math.log(2.0))


def fit_nonnegative_calibration_scale(
    raw_logits: np.ndarray,
    truth_bits: np.ndarray,
    *,
    maximum: float = CALIBRATION_MAXIMUM,
    steps: int = CALIBRATION_GRID_STEPS,
) -> tuple[float, float, int]:
    """Fit the frozen nonnegative grid; ties select the smaller scale."""

    raw = np.asarray(raw_logits, dtype=np.float64)
    truth = np.asarray(truth_bits, dtype=np.uint8)
    if (
        raw.shape != truth.shape
        or raw.ndim != 2
        or not bool(np.isfinite(raw).all())
        or isinstance(steps, bool)
        or not isinstance(steps, int)
        or steps < 2
        or not math.isfinite(float(maximum))
        or maximum <= 0.0
    ):
        raise O1C19CausalVaultBridgeRunError("calibration arrays/grid differ")
    candidates = np.linspace(0.0, float(maximum), steps, dtype=np.float64)
    best_scale = 0.0
    best_nll = math.inf
    for candidate in candidates:
        nll = _nll_bits(raw * candidate, truth)
        if nll < best_nll - 1e-12:
            best_nll = nll
            best_scale = float(candidate)
    return best_scale, best_nll, int(candidates.size * raw.size)


def _verify_duplicate_probe(
    config: CausalEvidenceConfig,
    core: StreamingSelectiveHolographicCore,
    quantizer: FrozenMedianAbsQuantizer,
    extraction: PacketDeltaExtraction,
) -> bool:
    bridge = CausalVaultBridge(
        config,
        quantizer,
        extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        reader_state_sha256=extraction.reader_state_sha256,
        active_coordinates_sha256=active_coordinate_sequence_sha256(
            extraction.active_coordinates
        ),
    )
    state = _new_bridge_state(config, core, tuple(range(KEY_BITS)))
    first = bridge.apply_group(state, extraction.groups[0])
    primary = state.primary_bytes(config)
    controls = state.control_bytes()
    second = bridge.apply_group(state, extraction.groups[0])
    return bool(
        first.accepted
        and not second.accepted
        and second.accepted_work_units == 0
        and state.primary_bytes(config) == primary
        and state.control_bytes() == controls
        and second.primary_state_sha256_before == second.primary_state_sha256_after
        and second.control_state_sha256_before == second.control_state_sha256_after
    )


def _verify_coordinate_commutation(
    config: CausalEvidenceConfig,
    core: StreamingSelectiveHolographicCore,
    quantizer: FrozenMedianAbsQuantizer,
    extraction: PacketDeltaExtraction,
    permutation: Sequence[int],
) -> tuple[bool, float]:
    identity = tuple(range(KEY_BITS))
    base = _execute_extraction(config, core, quantizer, extraction, identity)
    permuted_groups = tuple(
        permute_packet_coordinate(group, permutation) for group in extraction.groups
    )
    if not permuted_groups:
        raise O1C19CausalVaultBridgeRunError("permuted packet ledger is empty")
    bridge = CausalVaultBridge(
        config,
        quantizer,
        extraction.source_stream_sha256,
        action_pool_sha256=extraction.action_pool_sha256,
        reader_state_sha256=extraction.reader_state_sha256,
        active_coordinates_sha256=permuted_groups[0].active_coordinates_sha256,
    )
    permuted = execute_packet_delta_groups(
        bridge,
        _new_bridge_state(config, core, identity),
        permuted_groups,
    )
    mapping = tuple(permutation)
    residuals: list[float] = []
    base_logits = _execution_logits(base)
    permuted_logits = _execution_logits(permuted)
    for coordinate in range(KEY_BITS):
        residuals.extend(
            np.abs(
                base_logits[:-2, coordinate] - permuted_logits[:-2, mapping[coordinate]]
            ).tolist()
        )
    maximum = max(residuals, default=0.0)
    return maximum <= _COMMUTATION_TOLERANCE, maximum


def _verify_actual_polarity_swap(
    base_extraction: PacketDeltaExtraction,
    swapped_extraction: PacketDeltaExtraction,
    base_execution: CausalVaultBridgeExecution,
    swapped_execution: CausalVaultBridgeExecution,
) -> tuple[bool, float, float]:
    finite_failure = float(np.finfo(np.float64).max)
    if tuple(group.coordinate for group in base_extraction.groups) != tuple(
        group.coordinate for group in swapped_extraction.groups
    ):
        return False, finite_failure, finite_failure
    delta_residual = 0.0
    for base, swapped in zip(base_extraction.groups, swapped_extraction.groups):
        if base.horizons != swapped.horizons:
            return False, finite_failure, finite_failure
        delta_residual = max(
            delta_residual,
            max(
                (
                    abs(left + right)
                    for left, right in zip(
                        base.incremental_deltas, swapped.incremental_deltas
                    )
                ),
                default=0.0,
            ),
        )
    base_logits = _execution_logits(base_execution)
    swapped_logits = _execution_logits(swapped_execution)
    # zero_prior is trivially antisymmetric; every other arm, including the
    # independently routed shuffled control, must negate.
    logit_residual = float(np.max(np.abs(base_logits[:-1] + swapped_logits[:-1])))
    return (
        delta_residual <= _COMPLEMENT_TOLERANCE
        and logit_residual <= _COMPLEMENT_TOLERANCE,
        delta_residual,
        logit_residual,
    )


@dataclass(frozen=True)
class O1C22ScienceResult:
    report: Mapping[str, object]
    artifacts: Mapping[str, bytes]
    reader_replays: int
    packet_slots: int
    public_work_units: int
    calibration_value_evaluations: int

    @property
    def result_sha256(self) -> str:
        return _sha256(self.report.get("result_sha256"), "result_sha256")


def _score_report(
    raw_predictions: np.ndarray,
    calibrated_predictions: np.ndarray,
    labels: np.ndarray,
    active_plans: Sequence[NestedActiveCoordinatePlan],
    calibration_scales: np.ndarray,
    upstream_anchor: np.ndarray,
    integrity_gates: Mapping[str, bool],
) -> tuple[dict[str, object], np.ndarray, np.ndarray]:
    fold_count = labels.shape[0]
    widths = ACTIVE_COORDINATE_WIDTHS
    expected_prediction_shape = (
        fold_count,
        len(widths),
        len(PREDICTION_ARMS),
        KEY_BITS,
    )
    if (
        labels.shape != (4, KEY_BITS)
        or labels.dtype != np.uint8
        or raw_predictions.shape != expected_prediction_shape
        or calibrated_predictions.shape != expected_prediction_shape
        or calibration_scales.shape != (fold_count, len(PREDICTION_ARMS))
        or upstream_anchor.shape != (fold_count, KEY_BITS)
        or len(active_plans) != fold_count
        or not bool(np.isfinite(raw_predictions).all())
        or not bool(np.isfinite(calibrated_predictions).all())
        or not bool(np.isfinite(calibration_scales).all())
        or not bool(np.isfinite(upstream_anchor).all())
        or bool((calibration_scales < 0.0).any())
        or bool((calibration_scales > CALIBRATION_MAXIMUM).any())
    ):
        raise O1C19CausalVaultBridgeRunError("score input inventory differs")
    expected_calibrated = raw_predictions * calibration_scales[:, None, :, None]
    if not np.array_equal(calibrated_predictions, expected_calibrated):
        raise O1C19CausalVaultBridgeRunError(
            "calibrated predictions differ from frozen raw logits and scales"
        )
    nll = np.empty((fold_count, len(widths), len(PREDICTION_ARMS)), dtype=np.float64)
    compression = np.empty_like(nll)
    active_nll = np.empty_like(nll)
    for fold_index in range(fold_count):
        for width_index, width in enumerate(widths):
            active = np.asarray(
                active_plans[fold_index].active_coordinates(width), dtype=np.int64
            )
            for arm_index in range(len(PREDICTION_ARMS)):
                logits = calibrated_predictions[fold_index, width_index, arm_index]
                value = _nll_bits(logits, labels[fold_index])
                nll[fold_index, width_index, arm_index] = value
                compression[fold_index, width_index, arm_index] = KEY_BITS - value
                active_nll[fold_index, width_index, arm_index] = _nll_bits(
                    logits[active], labels[fold_index, active]
                )
    arm_index = {name: index for index, name in enumerate(PREDICTION_ARMS)}
    summaries: dict[str, object] = {}
    for name, index in arm_index.items():
        rows = []
        for width_index, width in enumerate(widths):
            values = compression[:, width_index, index]
            rows.append(
                {
                    "active_coordinates": width,
                    "mean_nll_bits": float(nll[:, width_index, index].mean()),
                    "mean_active_nll_bits": float(
                        active_nll[:, width_index, index].mean()
                    ),
                    "mean_compression_bits": float(values.mean()),
                    "minimum_compression_bits": float(values.min()),
                    "maximum_compression_bits": float(values.max()),
                    "positive_folds": int(np.sum(values > 0.0)),
                }
            )
        summaries[name] = {"widths": rows}

    raw_final = float(compression[:, -1, arm_index["raw_float_delta_sum"]].mean())
    normalized_final = float(
        compression[:, -1, arm_index["normalized_float_delta_sum"]].mean()
    )
    int8_values = compression[:, :, arm_index["quantized_int8_vault"]]
    int8_final = float(int8_values[:, -1].mean())
    shuffled_final = float(
        compression[:, -1, arm_index["coordinate_shuffled_vault"]].mean()
    )
    last_final = float(compression[:, -1, arm_index["last_horizon_only"]].mean())
    unit_final = float(compression[:, -1, arm_index["unit_sign_sum"]].mean())
    preservation = int8_final / normalized_final if normalized_final > 0.0 else 0.0
    mean_curve = int8_values.mean(axis=0)
    efficacy = {
        "all_four_final_folds_positive": bool(np.all(int8_values[:, -1] > 0.0)),
        "int8_mean_final_compression_bits_minimum": int8_final >= 1.0,
        "int8_minus_coordinate_shuffled_mean_compression_positive": (
            int8_final - shuffled_final > 0.0
        ),
        "int8_minus_last_horizon_only_mean_compression_positive": (
            int8_final - last_final > 0.0
        ),
        "int8_minus_unit_sign_sum_mean_compression_positive": (
            int8_final - unit_final > 0.0
        ),
        "int8_preserves_float_compression_fraction_minimum": (preservation >= 0.9),
        "strict_mean_compression_growth_across_k": all(
            float(right) > float(left)
            for left, right in zip(mean_curve[:-1], mean_curve[1:])
        ),
    }
    gates = {**dict(integrity_gates), **efficacy}
    failed = sorted(name for name, passed in gates.items() if not passed)
    integrity_passed = all(integrity_gates.values())
    smaller_signal = bool(
        np.max(
            compression[
                :,
                :-1,
                [
                    arm_index["normalized_float_delta_sum"],
                    arm_index["quantized_int8_vault"],
                ],
            ]
        )
        > 0.0
    )
    if not integrity_passed:
        classification = "INTEGRITY_OR_LIFECYCLE_FAILURE"
    elif smaller_signal and int8_final <= 0.0:
        classification = "CROSS_COORDINATE_DILUTION"
    elif raw_final <= 0.0 and normalized_final <= 0.0:
        classification = "NO_REAL_PACKET_SIGNAL"
    elif raw_final > 0.0 and normalized_final <= 0.0:
        classification = "SCALE_WEIGHTING_FAILURE"
    elif normalized_final > 0.0 and (int8_final <= 0.0 or preservation < 0.9):
        classification = "QUANTIZATION_OR_SATURATION_FAILURE"
    elif not all(efficacy.values()):
        classification = "CONTROL_SPECIFICITY_FAILURE"
    else:
        classification = "REAL_CAUSAL_VAULT_BUILD_LOO_PASS"

    anchor_nll = np.asarray(
        [
            _nll_bits(upstream_anchor[index], labels[index])
            for index in range(fold_count)
        ],
        dtype=np.float64,
    )
    anchor_compression = KEY_BITS - anchor_nll
    report = {
        "schema": RESULT_SCHEMA,
        "classification": classification,
        "claim_boundary": {
            "retrospective_build_leave_one_out": True,
            "disjoint_evaluation_claimed": False,
            "fullround_chacha20_public_artifact_replay": True,
            "unknown_key_bits_at_heldout_probe": KEY_BITS,
            "native_solver_speedup_claimed": False,
            "exact_key_recovery_claimed": False,
        },
        "active_coordinate_counts": list(widths),
        "prediction_arms": list(PREDICTION_ARMS),
        "calibration_scales": calibration_scales.tolist(),
        "arms": summaries,
        "source_anchor": {
            "arm": "o1c19_learned_reader_exhaustive_k256",
            "mean_nll_bits": float(anchor_nll.mean()),
            "mean_compression_bits": float(anchor_compression.mean()),
            "minimum_compression_bits": float(anchor_compression.min()),
            "positive_folds": int(np.sum(anchor_compression > 0.0)),
            "joins_o1c22_calibration_or_gates": False,
        },
        "margins": {
            "raw_float_mean_final_compression_bits": raw_final,
            "normalized_float_mean_final_compression_bits": normalized_final,
            "int8_mean_final_compression_bits": int8_final,
            "coordinate_shuffled_mean_final_compression_bits": shuffled_final,
            "last_horizon_only_mean_final_compression_bits": last_final,
            "unit_sign_sum_mean_final_compression_bits": unit_final,
            "int8_minus_coordinate_shuffled_mean_final_compression_bits": (
                int8_final - shuffled_final
            ),
            "int8_minus_last_horizon_only_mean_final_compression_bits": (
                int8_final - last_final
            ),
            "int8_minus_unit_sign_sum_mean_final_compression_bits": (
                int8_final - unit_final
            ),
            "int8_preserves_normalized_float_fraction": preservation,
            "int8_mean_compression_curve_bits": mean_curve.tolist(),
        },
        "gates": {**gates, "integrity_gate_passed": integrity_passed},
        "failed_gates": failed,
        "calibration_orientation_flip_allowed": False,
        "calibration_scale_grid": {
            "minimum": 0.0,
            "maximum": CALIBRATION_MAXIMUM,
            "steps": CALIBRATION_GRID_STEPS,
        },
    }
    return report, nll, compression


def _prefix_artifacts(prefix: str, artifacts: Mapping[str, bytes]) -> dict[str, bytes]:
    return {f"{prefix}/{name}": payload for name, payload in artifacts.items()}


def run_o1c19_causal_vault_bridge_science(
    config: O1C22RunConfig,
    prerequisite: O1C19Prerequisite,
    *,
    on_calibration_predictions_frozen: ArtifactCallback,
    on_heldout_predictions_frozen: ArtifactCallback,
) -> O1C22ScienceResult:
    """Execute all four retrospective folds with explicit oracle boundaries."""

    if not isinstance(config, O1C22RunConfig):
        raise TypeError("config must be O1C22RunConfig")
    if not isinstance(prerequisite, O1C19Prerequisite):
        raise TypeError("prerequisite must be O1C19Prerequisite")
    if not callable(on_calibration_predictions_frozen) or not callable(
        on_heldout_predictions_frozen
    ):
        raise O1C19CausalVaultBridgeRunError(
            "both pre-oracle persistence callbacks are required"
        )
    causal_config = config.causal_config
    core = StreamingSelectiveHolographicCore(causal_config.core_config)
    fold_count = len(prerequisite.folds)
    width_count = len(ACTIVE_COORDINATE_WIDTHS)
    raw_predictions = np.zeros(
        (fold_count, width_count, len(PREDICTION_ARMS), KEY_BITS),
        dtype=np.float64,
    )
    calibrated_predictions = np.zeros_like(raw_predictions)
    labels = np.empty((fold_count, KEY_BITS), dtype=np.uint8)
    calibration_scales = np.zeros((fold_count, len(PREDICTION_ARMS)), dtype=np.float64)
    upstream_anchor = np.stack(
        [row.upstream_learned_raw_prediction for row in prerequisite.folds]
    ).astype(np.float64, copy=False)
    active_plans: list[NestedActiveCoordinatePlan] = []
    reader_replays = 0
    packet_slots = 0
    public_work = 0
    calibration_evaluations = 0
    scored_artifacts: dict[str, bytes] = {}
    lifecycle_calibration_folds: set[int] = set()
    lifecycle_prediction_folds: set[int] = set()
    opened_label_ordinals: set[int] = set()
    fold_local_label_exclusion_passes: list[bool] = []
    duplicate_passes: list[bool] = []
    swap_passes: list[bool] = []
    swap_delta_residuals: list[float] = []
    swap_logit_residuals: list[float] = []
    commutation_passes: list[bool] = []
    commutation_residuals: list[float] = []
    exact_state_passes: list[bool] = []
    finite_passes: list[bool] = []

    for fold_index, fold in enumerate(prerequisite.folds):
        held_out = config.corpus.episodes[fold.held_out_ordinal]
        training = tuple(
            config.corpus.episodes[(fold.held_out_ordinal + offset) % fold_count]
            for offset in range(1, fold_count)
        )
        training_ordinals = [episode.ordinal for episode in training]
        fold_local_exclusion = held_out.ordinal not in training_ordinals
        if not fold_local_exclusion:
            raise O1C19CausalVaultBridgeRunError(
                f"fold {fold_index} held-out label entered its calibration ledger"
            )
        fold_local_label_exclusion_passes.append(fold_local_exclusion)
        fold_prefix = f"folds/{fold.target_id}"
        calibration_artifacts: dict[str, bytes] = {}
        training_extractions: list[
            tuple[ArtifactBuildEpisode, PacketDeltaExtraction]
        ] = []
        quantizer_groups = []
        for episode in training:
            plan = NestedActiveCoordinatePlan(
                episode.pool.source_stream_sha256, COORDINATE_SALT
            )
            extraction = _fresh_extraction(
                fold,
                config.upstream_controller,
                episode.pool,
                plan.active_coordinates(KEY_BITS),
                group_salt=COORDINATE_SALT,
            )
            reader_replays += 1
            packet_slots += extraction.observed_slots
            public_work += extraction.physical_work_units
            training_extractions.append((episode, extraction))
            quantizer_groups.extend(extraction.groups)
            calibration_artifacts[
                f"{fold_prefix}/calibration/source-{episode.target_id}/active_coordinates.json"
            ] = plan.to_bytes()
            calibration_artifacts[
                f"{fold_prefix}/calibration/source-{episode.target_id}/packet_deltas.json"
            ] = extraction.to_bytes()
        quantizer = FrozenMedianAbsQuantizer.fit_public_replays(
            tuple(quantizer_groups), horizons=HORIZON_ORDER
        )
        calibration_artifacts[f"{fold_prefix}/calibration/quantizer.json"] = (
            quantizer.to_bytes()
        )

        training_predictions = np.empty(
            (len(training), len(PREDICTION_ARMS), KEY_BITS), dtype=np.float64
        )
        for training_index, (episode, extraction) in enumerate(training_extractions):
            shuffled = deterministic_coordinate_permutation(
                episode.pool.source_stream_sha256,
                COORDINATE_SALT,
                shuffled_destination=True,
            )
            execution = _execute_extraction(
                causal_config, core, quantizer, extraction, shuffled
            )
            training_predictions[training_index] = _execution_logits(execution)
            calibration_artifacts.update(
                _prefix_artifacts(
                    f"{fold_prefix}/calibration/source-{episode.target_id}/execution",
                    execution.artifacts(causal_config),
                )
            )
            exact_state_passes.append(
                len(execution.state.primary_bytes(causal_config)) == FORMAL_VAULT_BYTES
            )
        calibration_artifacts[f"{fold_prefix}/calibration/raw_predictions.f64le"] = (
            training_predictions.astype("<f8", copy=False).tobytes(order="C")
        )
        calibration_unsigned = {
            "schema": CALIBRATION_FREEZE_SCHEMA,
            "phase": "THIS_FOLD_TRAINING_PUBLIC_DELTAS_STATES_AND_PREDICTIONS_FROZEN_BEFORE_THIS_FOLD_CALIBRATION_LABEL_USE",
            "fold_index": fold_index,
            "held_out_ordinal": held_out.ordinal,
            "held_out_target_id": held_out.target_id,
            "training_ordinals": [row.ordinal for row in training],
            "training_target_ids": [row.target_id for row in training],
            "reader_state_sha256": fold.reader_sha256,
            "slow_state_sha256": fold.slow_state_sha256,
            "quantizer_sha256": quantizer.sha256,
            "labels_used_by_this_fold_before_calibration_freeze": [],
            "held_out_label_used_for_this_fold": False,
            "previously_opened_build_label_ordinals": sorted(opened_label_ordinals),
            "build_labels_may_have_been_opened_in_other_folds": bool(
                opened_label_ordinals
            ),
            "reader_updates": 0,
            "solver_calls": 0,
            "artifacts": _artifact_commitments(calibration_artifacts),
        }
        calibration_document = _freeze_document(calibration_unsigned)
        calibration_artifacts[f"{fold_prefix}/calibration/prediction_freeze.json"] = (
            _json_bytes(calibration_document)
        )
        on_calibration_predictions_frozen(calibration_artifacts, calibration_document)
        lifecycle_calibration_folds.add(fold_index)

        training_labels = np.stack(
            [episode.labels_after_prediction_freeze() for episode in training]
        ).astype(np.uint8, copy=False)
        opened_label_ordinals.update(training_ordinals)
        for arm_index, arm in enumerate(CALIBRATED_ARMS):
            scale, _calibration_nll, evaluations = fit_nonnegative_calibration_scale(
                training_predictions[:, arm_index, :], training_labels
            )
            if scale < 0.0:
                raise O1C19CausalVaultBridgeRunError(
                    f"calibration sign flip occurred for {arm}"
                )
            calibration_scales[fold_index, arm_index] = scale
            calibration_evaluations += evaluations
        calibration_scales[fold_index, -1] = 0.0

        heldout_plan = NestedActiveCoordinatePlan(
            held_out.pool.source_stream_sha256, COORDINATE_SALT
        )
        active_plans.append(heldout_plan)
        shuffled = deterministic_coordinate_permutation(
            held_out.pool.source_stream_sha256,
            COORDINATE_SALT,
            shuffled_destination=True,
        )
        prediction_artifacts: dict[str, bytes] = {
            f"{fold_prefix}/heldout/active_coordinates.json": heldout_plan.to_bytes(),
            f"{fold_prefix}/heldout/quantizer.json": quantizer.to_bytes(),
            f"{fold_prefix}/heldout/calibration_scales.f64le": calibration_scales[
                fold_index
            ]
            .astype("<f8", copy=False)
            .tobytes(order="C"),
            f"{fold_prefix}/heldout/upstream_o1c19_learned_reader_exhaustive.f32le": fold.upstream_learned_raw_prediction.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
        }
        executions: dict[int, CausalVaultBridgeExecution] = {}
        extractions: dict[int, PacketDeltaExtraction] = {}
        for width_index, width in enumerate(ACTIVE_COORDINATE_WIDTHS):
            extraction = _fresh_extraction(
                fold,
                config.upstream_controller,
                held_out.pool,
                heldout_plan.active_coordinates(width),
                group_salt=COORDINATE_SALT,
            )
            reader_replays += 1
            packet_slots += extraction.observed_slots
            public_work += extraction.physical_work_units
            execution = _execute_extraction(
                causal_config, core, quantizer, extraction, shuffled
            )
            extractions[width] = extraction
            executions[width] = execution
            raw_predictions[fold_index, width_index] = _execution_logits(execution)
            calibrated_predictions[fold_index, width_index] = (
                raw_predictions[fold_index, width_index]
                * calibration_scales[fold_index, :, None]
            )
            width_prefix = f"{fold_prefix}/heldout/k{width:03d}"
            prediction_artifacts[f"{width_prefix}/packet_deltas.json"] = (
                extraction.to_bytes()
            )
            prediction_artifacts.update(
                _prefix_artifacts(
                    f"{width_prefix}/execution", execution.artifacts(causal_config)
                )
            )
            exact_state_passes.append(
                len(execution.state.primary_bytes(causal_config)) == FORMAL_VAULT_BYTES
            )
            finite_passes.append(
                bool(np.isfinite(raw_predictions[fold_index, width_index]).all())
                and bool(
                    np.isfinite(calibrated_predictions[fold_index, width_index]).all()
                )
            )

        k256_extraction = extractions[KEY_BITS]
        k256_execution = executions[KEY_BITS]
        swapped_extraction = _fresh_extraction(
            fold,
            config.upstream_controller,
            held_out.pool.polarity_swapped(),
            heldout_plan.active_coordinates(KEY_BITS),
            group_salt=COORDINATE_SALT,
        )
        reader_replays += 1
        packet_slots += swapped_extraction.observed_slots
        public_work += swapped_extraction.physical_work_units
        swapped_execution = _execute_extraction(
            causal_config, core, quantizer, swapped_extraction, shuffled
        )
        exact_state_passes.append(
            len(swapped_execution.state.primary_bytes(causal_config))
            == FORMAL_VAULT_BYTES
        )
        prediction_artifacts[
            f"{fold_prefix}/heldout/polarity_swap/packet_deltas.json"
        ] = swapped_extraction.to_bytes()
        prediction_artifacts.update(
            _prefix_artifacts(
                f"{fold_prefix}/heldout/polarity_swap/execution",
                swapped_execution.artifacts(causal_config),
            )
        )
        swap_ok, delta_residual, logit_residual = _verify_actual_polarity_swap(
            k256_extraction,
            swapped_extraction,
            k256_execution,
            swapped_execution,
        )
        swap_passes.append(swap_ok)
        swap_delta_residuals.append(delta_residual)
        swap_logit_residuals.append(logit_residual)
        duplicate_passes.append(
            _verify_duplicate_probe(causal_config, core, quantizer, k256_extraction)
        )
        commutation_permutation = deterministic_coordinate_permutation(
            held_out.pool.source_stream_sha256,
            COORDINATE_SALT ^ 0xC011A7E,
            shuffled_destination=True,
        )
        commute_ok, commute_residual = _verify_coordinate_commutation(
            causal_config,
            core,
            quantizer,
            k256_extraction,
            commutation_permutation,
        )
        commutation_passes.append(commute_ok)
        commutation_residuals.append(commute_residual)
        control_document = {
            "schema": "o1-256-o1c22-pre-oracle-control-result-v1",
            "fold_index": fold_index,
            "actual_polarity_swapped_pool_extracted": True,
            "polarity_delta_maximum_absolute_residual": delta_residual,
            "polarity_logit_maximum_absolute_residual": logit_residual,
            "polarity_antisymmetry_passed": swap_ok,
            "duplicate_full_state_byte_invariant": duplicate_passes[-1],
            "coordinate_commutation_maximum_absolute_residual": commute_residual,
            "coordinate_commutation_passed": commute_ok,
            "held_out_label_used_for_this_fold": False,
            "build_labels_may_have_been_opened_in_other_folds": bool(
                opened_label_ordinals
            ),
        }
        prediction_artifacts[f"{fold_prefix}/heldout/pre_oracle_controls.json"] = (
            _json_bytes(control_document)
        )
        prediction_artifacts[f"{fold_prefix}/heldout/raw_predictions.f64le"] = (
            raw_predictions[fold_index].astype("<f8", copy=False).tobytes(order="C")
        )
        prediction_artifacts[f"{fold_prefix}/heldout/calibrated_predictions.f64le"] = (
            calibrated_predictions[fold_index]
            .astype("<f8", copy=False)
            .tobytes(order="C")
        )
        prediction_unsigned = {
            "schema": PREDICTION_FREEZE_SCHEMA,
            "phase": "ALL_HELDOUT_DELTAS_SCALES_STATES_CONTROLS_AND_PREDICTIONS_FROZEN_BEFORE_LABEL_ORACLE",
            "fold_index": fold_index,
            "held_out_ordinal": held_out.ordinal,
            "held_out_target_id": held_out.target_id,
            "held_out_action_pool_sha256": held_out.action_pool_sha256,
            "reader_state_sha256": fold.reader_sha256,
            "slow_state_sha256": fold.slow_state_sha256,
            "upstream_prediction_freeze_sha256": fold.prediction_freeze_sha256,
            "quantizer_sha256": quantizer.sha256,
            "calibration_scales": calibration_scales[fold_index].tolist(),
            "active_coordinate_plan_sha256": heldout_plan.sha256,
            "active_coordinate_counts": list(ACTIVE_COORDINATE_WIDTHS),
            "prediction_arms": list(PREDICTION_ARMS),
            "calibration_label_ordinals_used_for_this_fold": training_ordinals,
            "held_out_label_used_for_this_fold": False,
            "previously_opened_build_label_ordinals": sorted(opened_label_ordinals),
            "held_out_label_may_have_been_opened_in_other_fold": (
                held_out.ordinal in opened_label_ordinals
            ),
            "held_out_reader_updates": 0,
            "solver_calls": 0,
            "scientific_entropy_calls": 0,
            "artifacts": _artifact_commitments(prediction_artifacts),
        }
        prediction_document = _freeze_document(prediction_unsigned)
        prediction_artifacts[f"{fold_prefix}/heldout/prediction_freeze.json"] = (
            _json_bytes(prediction_document)
        )
        on_heldout_predictions_frozen(prediction_artifacts, prediction_document)
        lifecycle_prediction_folds.add(fold_index)
        labels[fold_index] = held_out.labels_after_prediction_freeze()
        opened_label_ordinals.add(held_out.ordinal)

    exact_resources = {
        "reader_replays_exact": reader_replays == EXPECTED_READER_REPLAYS,
        "packet_slot_observations_exact": packet_slots == EXPECTED_PACKET_SLOTS,
        "physical_public_work_units_exact": public_work == EXPECTED_PUBLIC_WORK,
        "calibration_value_evaluations_exact": (
            calibration_evaluations == EXPECTED_CALIBRATION_EVALUATIONS
        ),
    }
    integrity_gates = {
        "all_fold_calibration_predictions_frozen_before_that_folds_calibration_label_use": (
            lifecycle_calibration_folds == set(range(fold_count))
        ),
        "all_fold_heldout_predictions_frozen_before_that_folds_heldout_label_use": (
            lifecycle_prediction_folds == set(range(fold_count))
        ),
        "every_fold_excludes_its_heldout_label_from_calibration": all(
            fold_local_label_exclusion_passes
        ),
        "all_primary_live_states_exactly_352_bytes": all(exact_state_passes),
        "all_predictions_finite": all(finite_passes),
        "all_duplicate_groups_full_state_byte_invariant": all(duplicate_passes),
        "actual_polarity_swapped_pool_delta_and_logit_antisymmetry": all(swap_passes),
        "coordinate_permutation_commutes_with_accumulation": all(commutation_passes),
        "calibration_scales_nonnegative_without_orientation_flip": bool(
            np.all(calibration_scales >= 0.0)
            and np.all(calibration_scales <= CALIBRATION_MAXIMUM)
        ),
        "matched_public_packet_work_for_all_derived_arms": True,
        "zero_solver_entropy_sibling_mps_gpu_work": True,
        **exact_resources,
    }
    scored, nll, compression = _score_report(
        raw_predictions,
        calibrated_predictions,
        labels,
        active_plans,
        calibration_scales,
        upstream_anchor,
        integrity_gates,
    )
    scored["integrity_diagnostics"] = {
        "polarity_delta_maximum_absolute_residual": max(swap_delta_residuals),
        "polarity_logit_maximum_absolute_residual": max(swap_logit_residuals),
        "coordinate_commutation_maximum_absolute_residual": max(commutation_residuals),
    }
    scored["resources"] = {
        "existing_build_pools_loaded": len(config.corpus.episodes),
        "o1c19_reader_replays": reader_replays,
        "packet_slot_observations": packet_slots,
        "physical_public_work_units": public_work,
        "calibration_value_evaluations": calibration_evaluations,
        "physical_public_pools_generated": 0,
        "native_solver_branches": 0,
        "scientific_entropy_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "mps_calls": 0,
        "gpu_calls": 0,
        "maximum_accumulator_live_state_bytes": FORMAL_VAULT_BYTES,
        "upstream_reader_state_billed_separately": True,
        "source_artifact_bytes_read": prerequisite.source_artifact_bytes_read,
    }
    scored["source"] = {
        "o1c18_artifact_corpus_sha256": config.corpus.sha256,
        "o1c19_manifest_sha256": prerequisite.finalized.manifest_sha256,
        "o1c19_artifact_index_sha256": prerequisite.artifact_index_sha256,
        "o1c19_result_sha256": prerequisite.result_sha256,
        "o1c21_config_sha256": config.o1c21_config_sha256,
    }
    scientific_unsigned = dict(scored)
    result_sha256 = _sha256_bytes(canonical_json_bytes(scientific_unsigned))
    report = {**scored, "result_sha256": result_sha256}
    scored_artifacts.update(
        {
            "o1c19_causal_vault_bridge.json": _json_bytes(report),
            "labels.bitpack": np.packbits(labels, axis=1, bitorder="little").tobytes(
                order="C"
            ),
            "raw_predictions.f64le": raw_predictions.astype("<f8", copy=False).tobytes(
                order="C"
            ),
            "calibrated_predictions.f64le": calibrated_predictions.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "calibration_scales.f64le": calibration_scales.astype(
                "<f8", copy=False
            ).tobytes(order="C"),
            "nll_bits.f64le": nll.astype("<f8", copy=False).tobytes(order="C"),
            "compression_bits.f64le": compression.astype("<f8", copy=False).tobytes(
                order="C"
            ),
            "upstream_o1c19_anchor.f32le": upstream_anchor.astype(
                "<f4", copy=False
            ).tobytes(order="C"),
        }
    )
    return O1C22ScienceResult(
        report=report,
        artifacts=scored_artifacts,
        reader_replays=reader_replays,
        packet_slots=packet_slots,
        public_work_units=public_work,
        calibration_value_evaluations=calibration_evaluations,
    )


def _git_commit(root: Path) -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if status.stdout:
        raise O1C19CausalVaultBridgeRunError("lab worktree must be clean")
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not commit:
        raise O1C19CausalVaultBridgeRunError("lab commit is unavailable")
    return commit


def _source_hashes(
    config: O1C22RunConfig,
    prerequisite: O1C19Prerequisite,
) -> dict[str, str]:
    modules = (
        "causal_evidence_stream.py",
        "causal_evidence_stream_run.py",
        "full256_action_pool.py",
        "full256_multiresolution_build_loo.py",
        "full256_multiresolution_build_loo_run.py",
        "living_inverse.py",
        "o1_streaming_core.py",
        "o1c19_causal_vault_bridge.py",
        "o1c19_causal_vault_bridge_run.py",
        "online_causal_controller.py",
        "online_multiresolution_controller.py",
        "run_capsule.py",
    )
    result = {
        "config": _sha256_file(config.config_path),
        "pyproject": _sha256_file(config.root / "pyproject.toml"),
        "o1c18_capsule_manifest": config.corpus.capsule_manifest_sha256,
        "o1c18_artifact_index": config.corpus.artifact_index_sha256,
        "o1c18_artifact_corpus": config.corpus.sha256,
        "o1c19_source_config": config.o1c19_config_sha256,
        "o1c19_capsule_manifest": prerequisite.finalized.manifest_sha256,
        "o1c19_artifact_index": prerequisite.artifact_index_sha256,
        "o1c19_result": prerequisite.result_sha256,
        "o1c21_source_config": config.o1c21_config_sha256,
        **{
            f"module_{Path(name).stem}": _sha256_file(
                config.root / "src/o1_crypto_lab" / name
            )
            for name in modules
        },
    }
    for fold in prerequisite.folds:
        prefix = f"o1c19_fold_{fold.fold_index:02d}"
        result[f"{prefix}_reader"] = fold.reader_sha256
        result[f"{prefix}_slow_state"] = fold.slow_state_sha256
        result[f"{prefix}_learning_freeze"] = fold.learning_freeze_sha256
        result[f"{prefix}_prediction_freeze"] = fold.prediction_freeze_sha256
    return result


def run_capsule_from_config(
    path: str | Path,
    *,
    root: str | Path | None = None,
) -> int:
    """Run O1C-0022, refusing to reserve it until O1C-0019 is valid."""

    config = load_o1c19_causal_vault_bridge_run_config(path, root=root)
    manager = RunCapsuleManager(config.root)
    published = manager.finalized_attempt(ATTEMPT_ID)
    if published is not None:
        metrics = _read_json(published.path / "metrics.json", "O1C-0022 metrics")
        print(
            json.dumps(
                {
                    "attempt_id": ATTEMPT_ID,
                    "path": str(published.path),
                    "manifest_sha256": published.manifest_sha256,
                    "verified": published.verification.ok,
                    "status": "already-finalized-no-replay",
                    "capsule_status": metrics.get("status"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if metrics.get("status") == "completed" else 2

    preflight = preflight_o1c19_causal_vault_bridge(
        config.config_path, root=config.root
    )
    if not preflight.ready or preflight.prerequisite is None:
        print(json.dumps(preflight.report, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    prerequisite = preflight.prerequisite
    if ATTEMPT_ID in manager.recoverable_attempt_ids():
        interrupted = manager.recover(ATTEMPT_ID)
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
                "Preserve this interrupted retrospective adapter run and use "
                "a new attempt identity after diagnosing its last checkpoint."
            ),
        )
        print(f"stopped capsule: {finalized.path}", file=sys.stderr)
        return 2

    commit = _git_commit(config.root)
    hashes = _source_hashes(config, prerequisite)
    run = manager.start(
        attempt_id=ATTEMPT_ID,
        slug=FORMAL_SLUG,
        commit=commit,
        hypothesis=str(config.top["hypothesis"]),
        prediction=str(config.top["prediction"]),
        controls=tuple(str(item) for item in config.top["controls"]),
        budgets=dict(config.top["budgets"]),
        source_hashes=hashes,
        claim_level=ClaimLevel.RETROSPECTIVE,
        next_action=str(config.top["next_action"]),
        config=config.top,
        command=(
            sys.executable,
            "-m",
            "o1_crypto_lab.o1c19_causal_vault_bridge_run",
            "--config",
            str(config.config_path),
        ),
        environment={
            "experiment_boundary": "retrospective-o1c19-build-loo-causal-vault",
            "o1c19_science_commit": config.o1c19_science_commit,
            "o1c21_source_commit": config.o1c21_source_commit,
            "o1c19_capsule": str(prerequisite.finalized.path),
            "o1c19_capsule_manifest_sha256": (prerequisite.finalized.manifest_sha256),
            "existing_build_pools": len(config.corpus.episodes),
            "physical_public_pools_generated": 0,
            "native_solver_branches": 0,
            "scientific_entropy_calls": 0,
            "sibling_repository_reads": 0,
            "sibling_repository_writes": 0,
            "mps_calls": 0,
            "gpu_calls": 0,
            "accelerator": "none",
            "hard_interruption_policy": "FINALIZE_STOPPED_AND_NEVER_REPLAY",
        },
    )
    persisted: dict[str, dict[str, object]] = {}
    persistent_bytes = 0
    calibration_folds: set[int] = set()
    prediction_folds: set[int] = set()
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
            raise O1C19CausalVaultBridgeRunError(f"{phase} artifacts are empty")
        group_bytes = sum(len(payload) for payload in artifacts.values())
        if (
            persistent_bytes + group_bytes
            > config.budgets.maximum_persistent_artifact_bytes
        ):
            raise O1C19CausalVaultBridgeRunError(
                f"{phase} exceeds the persistent-artifact budget"
            )
        for relative, payload in sorted(artifacts.items()):
            if relative in persisted or not isinstance(payload, bytes) or not relative:
                raise O1C19CausalVaultBridgeRunError(
                    f"{phase} artifact inventory differs"
                )
            output = run.write_artifact(relative, payload)
            digest = _sha256_bytes(payload)
            if _sha256_file(output) != digest:
                raise O1C19CausalVaultBridgeRunError(
                    f"{phase} persisted artifact differs"
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

    def calibration_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        fold_index = _integer(document.get("fold_index"), "fold_index", 0, 3)
        if (
            fold_index in calibration_folds
            or document.get("schema") != CALIBRATION_FREEZE_SCHEMA
            or document.get("labels_used_by_this_fold_before_calibration_freeze") != []
            or document.get("held_out_label_used_for_this_fold") is not False
        ):
            raise O1C19CausalVaultBridgeRunError(
                "calibration prediction-freeze boundary differs"
            )
        persist_group(
            artifacts,
            document,
            phase=f"CALIBRATION_PREDICTIONS_FROZEN_FOLD_{fold_index}",
        )
        calibration_folds.add(fold_index)

    def prediction_callback(
        artifacts: Mapping[str, bytes], document: Mapping[str, object]
    ) -> None:
        fold_index = _integer(document.get("fold_index"), "fold_index", 0, 3)
        if (
            fold_index in prediction_folds
            or fold_index not in calibration_folds
            or document.get("schema") != PREDICTION_FREEZE_SCHEMA
            or document.get("held_out_label_used_for_this_fold") is not False
            or document.get("held_out_ordinal")
            in document.get("calibration_label_ordinals_used_for_this_fold", ())
            or document.get("held_out_reader_updates") != 0
        ):
            raise O1C19CausalVaultBridgeRunError(
                "held-out prediction-freeze boundary differs"
            )
        persist_group(
            artifacts,
            document,
            phase=f"HELDOUT_PREDICTIONS_FROZEN_FOLD_{fold_index}",
        )
        prediction_folds.add(fold_index)

    try:
        run.checkpoint(
            {
                "phase": "O1C0022_RESERVED_AFTER_VALID_O1C0019_PREFLIGHT",
                "o1c19_manifest_sha256": prerequisite.finalized.manifest_sha256,
                "folds": len(prerequisite.folds),
                "source_artifact_bytes_read": (prerequisite.source_artifact_bytes_read),
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_entropy_calls": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "mps_calls": 0,
                "gpu_calls": 0,
            }
        )
        run.append_stdout(
            "O1C-0022 frozen O1C-0019 public packet bridge started on CPU.\n"
        )
        result = run_o1c19_causal_vault_bridge_science(
            config,
            prerequisite,
            on_calibration_predictions_frozen=calibration_callback,
            on_heldout_predictions_frozen=prediction_callback,
        )
        if calibration_folds != set(range(4)) or prediction_folds != set(range(4)):
            raise O1C19CausalVaultBridgeRunError(
                "not every fold crossed both persisted oracle boundaries"
            )
        persist_group(
            result.artifacts,
            {"freeze_sha256": result.result_sha256},
            phase="POST_FREEZE_SCORED_RESULT",
        )
        artifact_index = {
            "schema": ARTIFACT_INDEX_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "o1c19_manifest_sha256": prerequisite.finalized.manifest_sha256,
            "o1c19_artifact_index_sha256": prerequisite.artifact_index_sha256,
            "artifacts": dict(sorted(persisted.items())),
            "indexed_artifact_count": len(persisted),
            "indexed_artifact_bytes": persistent_bytes,
        }
        persist_group(
            {"artifact_index.json": _json_bytes(artifact_index)},
            {"freeze_sha256": result.result_sha256},
            phase="ARTIFACT_INDEX",
        )
        if (
            _git_commit(config.root) != commit
            or _source_hashes(config, prerequisite) != hashes
        ):
            raise O1C19CausalVaultBridgeRunError("source changed during execution")

        cpu_seconds = time.process_time() - cpu_started
        wall_seconds = time.monotonic() - wall_started
        peak_rss_bytes = _process_peak_rss_bytes()
        budget_checks = {
            "cpu": cpu_seconds <= config.budgets.maximum_cpu_seconds,
            "wall": wall_seconds <= config.budgets.maximum_wall_seconds,
            "resident_memory": peak_rss_bytes
            <= config.budgets.maximum_resident_memory_mib * 1024 * 1024,
            "persistent_artifacts": persistent_bytes
            <= config.budgets.maximum_persistent_artifact_bytes,
            "source_artifact_bytes_read": prerequisite.source_artifact_bytes_read
            <= config.budgets.maximum_source_artifact_bytes_read,
            "existing_build_pools": len(config.corpus.episodes)
            == config.budgets.expected_existing_build_pools,
            "reader_replays": result.reader_replays
            == config.budgets.maximum_o1c19_reader_replays,
            "packet_slots": result.packet_slots
            == config.budgets.maximum_packet_slot_observations,
            "public_work": result.public_work_units
            == config.budgets.maximum_physical_public_work_units,
            "calibration_value_evaluations": result.calibration_value_evaluations
            == config.budgets.maximum_calibration_value_evaluations,
            "physical_public_pools_generated": (
                config.budgets.maximum_physical_public_pools_generated == 0
            ),
            "native_solver_branches": (
                config.budgets.maximum_native_solver_branches == 0
            ),
            "scientific_entropy": (
                config.budgets.maximum_scientific_entropy_calls == 0
            ),
            "sibling_reads": config.budgets.maximum_sibling_reads == 0,
            "sibling_writes": config.budgets.maximum_sibling_writes == 0,
            "mps": config.budgets.maximum_mps_calls == 0,
            "gpu": config.budgets.maximum_gpu_calls == 0,
            "live_state": config.budgets.maximum_accumulator_live_state_bytes
            == FORMAL_VAULT_BYTES,
        }
        failed_budgets = sorted(
            name for name, passed in budget_checks.items() if not passed
        )
        operationally_complete = not failed_budgets
        metrics = {
            "schema": RUN_METRICS_SCHEMA,
            "classification": result.report["classification"],
            "scientific_success_gate_passed": result.report["classification"]
            == "REAL_CAUSAL_VAULT_BUILD_LOO_PASS",
            "result_sha256": result.result_sha256,
            "margins": result.report["margins"],
            "gates": result.report["gates"],
            "failed_gates": result.report["failed_gates"],
            "cpu_seconds": cpu_seconds,
            "wall_seconds": wall_seconds,
            "peak_rss_bytes": peak_rss_bytes,
            "persistent_artifact_bytes": persistent_bytes,
            "source_artifact_bytes_read": prerequisite.source_artifact_bytes_read,
            "reader_replays": result.reader_replays,
            "packet_slots": result.packet_slots,
            "physical_public_work_units": result.public_work_units,
            "calibration_value_evaluations": (result.calibration_value_evaluations),
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
        run.append_stderr(f"{type(exc).__name__}: {exc}\n")
        finalized = run.finalize(
            metrics={
                "schema": RUN_METRICS_SCHEMA,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "calibration_folds_frozen": sorted(calibration_folds),
                "prediction_folds_frozen": sorted(prediction_folds),
                "persistent_artifact_bytes": persistent_bytes,
                "physical_public_pools_generated": 0,
                "native_solver_branches": 0,
                "scientific_result_claimed": False,
            },
            status="failed",
            next_action=(
                "Preserve this operational failure and repair the exact "
                "pre-oracle bridge lifecycle under a new attempt identity."
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
                "scientific_success_gate_passed": result.report["classification"]
                == "REAL_CAUSAL_VAULT_BUILD_LOO_PASS",
                "failed_budgets": failed_budgets,
                "int8_mean_final_compression_bits": result.report["margins"][
                    "int8_mean_final_compression_bits"
                ],
                "o1c19_anchor_mean_compression_bits": result.report["source_anchor"][
                    "mean_compression_bits"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if operationally_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run or preflight O1C-0022 frozen O1C-0019 causal-vault LOO"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="verify pinned dependencies without reserving O1C-0022",
    )
    args = parser.parse_args(argv)
    if args.preflight:
        preflight = preflight_o1c19_causal_vault_bridge(args.config)
        print(json.dumps(preflight.report, indent=2, sort_keys=True))
        return 0 if preflight.ready else 2
    return run_capsule_from_config(args.config)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ARTIFACT_INDEX_SCHEMA",
    "CALIBRATION_FREEZE_SCHEMA",
    "PREDICTION_ARMS",
    "PREDICTION_FREEZE_SCHEMA",
    "PREFLIGHT_SCHEMA",
    "RESULT_SCHEMA",
    "RUN_CONFIG_SCHEMA",
    "RUN_METRICS_SCHEMA",
    "O1C19CausalVaultBridgeRunError",
    "O1C19FoldSource",
    "O1C19Prerequisite",
    "O1C22Budgets",
    "O1C22Preflight",
    "O1C22RunConfig",
    "O1C22ScienceResult",
    "fit_nonnegative_calibration_scale",
    "load_o1c19_causal_vault_bridge_run_config",
    "main",
    "preflight_o1c19_causal_vault_bridge",
    "run_capsule_from_config",
    "run_o1c19_causal_vault_bridge_science",
]
