"""O1C-0058 sealed multiblock finite-difference bit-vault test."""

from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Protocol, Sequence, cast

import numpy as np

from .cadical_sensor import build_native_sensor, sha256_file
from .chacha_trace import chacha20_blocks
from .full256_broker import (
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from .living_inverse import PublicTargetView
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c41_antecedent_chain_rank_run import _peak_rss_bytes
from .o1c43_parent_criticality_rank_run import (
    _extract_field,
    _score_runtime,
    _standardize_vector,
)
from .o1c57_multiblock_parent_criticality_rank_run import (
    _shared_decoy_panel,
    _slice_public_blocks,
    _standardize_scalar_decoys,
)
from .proof_parent_criticality import (
    FEATURE_NAMES,
    ParentCriticalityField,
    parent_criticality_features,
)
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0058"
CONFIG_SCHEMA = "o1-256-multiblock-bit-vault-gradient-config-v1"
RESULT_SCHEMA = "o1-256-multiblock-bit-vault-gradient-result-v1"
FREEZE_SCHEMA = "o1-256-multiblock-bit-vault-gradient-freeze-v1"
RESULT_RELATIVE = Path(
    "research/O1C0058_MULTIBLOCK_BIT_VAULT_GRADIENT_RESULT_20260719.json"
)
O1C43_MANIFEST = Path(
    "runs/20260718_233458_O1C-0043_parent-criticality-rank-v1/artifacts.sha256"
)
ARMS = ("primary", "key_rotated", "clause_rotated")
PREFIXES = (1, 2, 4, 8)
CONFIDENCE_DEPTHS = (1, 2, 4, 8, 16, 32, 64, 128, 256)
BLOCK_COUNT = 8
KEY_BITS = 256
DECOY_COUNT = 4096
GRADIENT_PANEL_SIZE = KEY_BITS + 1
PRIMARY_LIVE_STATE_BYTES = KEY_BITS * 8
ALL_ARMS_LIVE_STATE_BYTES = len(ARMS) * PRIMARY_LIVE_STATE_BYTES
READER_SHA256 = "c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30"
PIPELINE = (
    "o1c43-decoy-calibrated-score->attended-base-one-bit-finite-difference"
    "->256-float-prefix-vault->sign-synthesis"
)
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)
COMMIT_BOUND_SOURCE_NAMES = (
    "sensor_source",
    "tracer_header",
    "parent_criticality_source",
    "o1c43_runner",
    "o1c57_runner",
    "broker_source",
    "runner",
    "o1c43_result",
)


class O1C58RunError(RuntimeError):
    """The frozen bit-vault mechanism, blind lifecycle, or ledger differs."""


class _ForwardPlan(Protocol):
    def evaluate(self, *, key: bytes, counter: int, nonce: bytes) -> dict[int, int]: ...


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _key_bit(key: bytes, bit_index: int) -> int:
    if (
        not isinstance(key, bytes)
        or len(key) != 32
        or isinstance(bit_index, bool)
        or not isinstance(bit_index, int)
        or not 0 <= bit_index < KEY_BITS
    ):
        raise O1C58RunError("key-bit convention differs")
    return (key[bit_index // 8] >> (bit_index % 8)) & 1


def _xor_key_bit(key: bytes, bit_index: int) -> bytes:
    _key_bit(key, bit_index)
    mutated = bytearray(key)
    mutated[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(mutated)


def _gradient_panel(base_key: bytes) -> tuple[bytes, ...]:
    if not isinstance(base_key, bytes) or len(base_key) != 32:
        raise O1C58RunError("gradient base key differs")
    panel = (base_key, *(_xor_key_bit(base_key, index) for index in range(KEY_BITS)))
    if (
        len(panel) != GRADIENT_PANEL_SIZE
        or len(set(panel)) != GRADIENT_PANEL_SIZE
        or any(
            sum((left ^ right).bit_count() for left, right in zip(base_key, key)) != 1
            for key in panel[1:]
        )
    ):
        raise O1C58RunError("one-bit gradient panel differs")
    return panel


def _attended_base_index(primary_block_z: np.ndarray) -> tuple[int, np.ndarray]:
    matrix = np.asarray(primary_block_z, dtype=np.float64)
    if matrix.shape != (BLOCK_COUNT, DECOY_COUNT) or not np.all(np.isfinite(matrix)):
        raise O1C58RunError("attended base score matrix differs")
    aggregate = np.zeros(DECOY_COUNT, dtype=np.float64)
    for block_index in range(BLOCK_COUNT):
        aggregate = np.add(aggregate, matrix[block_index], dtype=np.float64)
    maximum = float(np.max(aggregate))
    matches = np.flatnonzero(aggregate == maximum)
    if matches.size < 1:
        raise O1C58RunError("attended base maximum differs")
    index = int(matches[0])
    if not 0 <= index < DECOY_COUNT:
        raise O1C58RunError("attended base index differs")
    return index, np.ascontiguousarray(aggregate, dtype=np.float64)


def _apply_scalar_calibration(
    scores: Sequence[float] | np.ndarray, *, mean: float, std: float
) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if (
        values.ndim != 1
        or values.size < 1
        or not np.all(np.isfinite(values))
        or not math.isfinite(mean)
        or not math.isfinite(std)
        or std <= 0.0
    ):
        raise O1C58RunError("frozen scalar calibration differs")
    result = np.asarray((values - mean) / std, dtype=np.float64)
    if not np.all(np.isfinite(result)):
        raise O1C58RunError("gradient scalar-z vector is non-finite")
    return result


def _score_keys_with_runtime(
    *,
    runtime: Mapping[str, object],
    public: PublicTargetView,
    keys: Sequence[bytes],
    reader: np.ndarray,
) -> dict[str, np.ndarray]:
    public.validate()
    key_tuple = tuple(keys)
    if (
        public.block_count != 1
        or not key_tuple
        or any(not isinstance(key, bytes) or len(key) != 32 for key in key_tuple)
        or reader.shape != (len(FEATURE_NAMES),)
        or not np.all(np.isfinite(reader))
    ):
        raise O1C58RunError("gradient scoring input differs")
    plan = cast(_ForwardPlan, runtime.get("plan"))
    fields = cast(Mapping[str, ParentCriticalityField], runtime.get("fields"))
    means = cast(Mapping[str, np.ndarray], runtime.get("means"))
    stds = cast(Mapping[str, np.ndarray], runtime.get("stds"))
    if set(fields) != set(ARMS) or set(means) != set(ARMS) or set(stds) != set(ARMS):
        raise O1C58RunError("gradient runtime arms differ")
    scores = {arm: np.empty(len(key_tuple), dtype=np.float64) for arm in ARMS}
    for row, key in enumerate(key_tuple):
        assignment = plan.evaluate(
            key=key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        for arm in ARMS:
            features = parent_criticality_features(fields[arm], assignment)
            standardized = _standardize_vector(features, means[arm], stds[arm])
            scores[arm][row] = float(np.dot(standardized, reader))
    if any(
        values.shape != (len(key_tuple),) or not np.all(np.isfinite(values))
        for values in scores.values()
    ):
        raise O1C58RunError("gradient reader scores differ")
    return scores


def _delta_from_panel_z(panel_z: Sequence[float] | np.ndarray) -> np.ndarray:
    values = np.asarray(panel_z, dtype=np.float64)
    if values.shape != (GRADIENT_PANEL_SIZE,) or not np.all(np.isfinite(values)):
        raise O1C58RunError("gradient scalar-z panel differs")
    delta = np.asarray(values[1:] - values[0], dtype=np.float64)
    if delta.shape != (KEY_BITS,) or not np.all(np.isfinite(delta)):
        raise O1C58RunError("gradient delta vector differs")
    return delta


def _vault_prefixes(
    block_deltas: np.ndarray, prefixes: Sequence[int] = PREFIXES
) -> dict[int, np.ndarray]:
    matrix = np.asarray(block_deltas, dtype=np.float64)
    requested = tuple(prefixes)
    if (
        matrix.shape != (BLOCK_COUNT, KEY_BITS)
        or not np.all(np.isfinite(matrix))
        or requested != PREFIXES
    ):
        raise O1C58RunError("bit-vault block matrix differs")
    live = np.zeros(KEY_BITS, dtype=np.float64)
    snapshots: dict[int, np.ndarray] = {}
    for block_index in range(BLOCK_COUNT):
        live += matrix[block_index]
        prefix = block_index + 1
        if prefix in requested:
            snapshots[prefix] = np.ascontiguousarray(live, dtype=np.float64).copy()
    if tuple(snapshots) != requested or live.nbytes != PRIMARY_LIVE_STATE_BYTES:
        raise O1C58RunError("bounded bit-vault prefix state differs")
    return snapshots


def _confidence_order(evidence: Sequence[float] | np.ndarray) -> tuple[int, ...]:
    values = np.asarray(evidence, dtype=np.float64)
    if values.shape != (KEY_BITS,) or not np.all(np.isfinite(values)):
        raise O1C58RunError("confidence evidence differs")
    order = tuple(
        sorted(range(KEY_BITS), key=lambda index: (-abs(values[index]), index))
    )
    if len(order) != KEY_BITS or set(order) != set(range(KEY_BITS)):
        raise O1C58RunError("confidence order differs")
    return order


def _synthesize_key(base_key: bytes, evidence: Sequence[float] | np.ndarray) -> bytes:
    if not isinstance(base_key, bytes) or len(base_key) != 32:
        raise O1C58RunError("synthesis base key differs")
    values = np.asarray(evidence, dtype=np.float64)
    if values.shape != (KEY_BITS,) or not np.all(np.isfinite(values)):
        raise O1C58RunError("synthesis evidence differs")
    candidate = bytearray(base_key)
    for bit_index in range(KEY_BITS):
        if values[bit_index] > 0.0:
            candidate[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(candidate)


def _public_verify_key(candidate: bytes, public: PublicTargetView) -> dict[str, object]:
    public.validate()
    if (
        not isinstance(candidate, bytes)
        or len(candidate) != 32
        or public.block_count != BLOCK_COUNT
    ):
        raise O1C58RunError("public candidate verification input differs")
    outputs = chacha20_blocks(
        candidate, public.counter_schedule[0], public.nonce, BLOCK_COUNT
    )
    matches = tuple(left == right for left, right in zip(outputs, public.output_blocks))
    return {
        "candidate_output_sha256": hashlib.sha256(b"".join(outputs)).hexdigest(),
        "block_matches": list(matches),
        "matched_blocks": sum(matches),
        "exact_all_blocks": all(matches),
    }


def _truth_metrics(
    *,
    base_key: bytes,
    candidate: bytes,
    truth_key: bytes,
    evidence: Sequence[float] | np.ndarray,
    confidence_order: Sequence[int],
) -> dict[str, object]:
    values = np.asarray(evidence, dtype=np.float64)
    order = tuple(confidence_order)
    if (
        any(
            not isinstance(key, bytes) or len(key) != 32
            for key in (base_key, candidate, truth_key)
        )
        or values.shape != (KEY_BITS,)
        or not np.all(np.isfinite(values))
        or len(order) != KEY_BITS
        or set(order) != set(range(KEY_BITS))
        or _synthesize_key(base_key, values) != candidate
    ):
        raise O1C58RunError("post-reveal bit metric input differs")
    correct = tuple(
        _key_bit(candidate, index) == _key_bit(truth_key, index)
        for index in range(KEY_BITS)
    )
    desired_flip = tuple(
        _key_bit(base_key, index) != _key_bit(truth_key, index)
        for index in range(KEY_BITS)
    )
    predicted_flip = tuple(values[index] > 0.0 for index in range(KEY_BITS))
    if (
        tuple(left == right for left, right in zip(desired_flip, predicted_flip))
        != correct
    ):
        raise O1C58RunError("directional bit identity differs")
    depth_rows: list[dict[str, object]] = []
    for depth in CONFIDENCE_DEPTHS:
        count = sum(correct[index] for index in order[:depth])
        depth_rows.append(
            {
                "depth": depth,
                "correct": count,
                "accuracy": count / depth,
                "all_correct": count == depth,
            }
        )
    longest = 0
    for bit_index in order:
        if not correct[bit_index]:
            break
        longest += 1
    correct_bits = sum(correct)
    return {
        "correct_bits": correct_bits,
        "hamming_distance": KEY_BITS - correct_bits,
        "directional_accuracy": correct_bits / KEY_BITS,
        "candidate_equals_truth": candidate == truth_key,
        "predicted_flip_bits": sum(predicted_flip),
        "positive_evidence_cells": int(np.count_nonzero(values > 0.0)),
        "negative_evidence_cells": int(np.count_nonzero(values < 0.0)),
        "zero_evidence_cells": int(np.count_nonzero(values == 0.0)),
        "confidence_depths": depth_rows,
        "longest_fully_correct_confidence_prefix": longest,
        "residual_width_after_correct_confidence_prefix": KEY_BITS - longest,
    }


def _base_truth_metrics(base_key: bytes, truth_key: bytes) -> dict[str, object]:
    if any(
        not isinstance(key, bytes) or len(key) != 32 for key in (base_key, truth_key)
    ):
        raise O1C58RunError("base truth metric input differs")
    correct = sum(
        _key_bit(base_key, index) == _key_bit(truth_key, index)
        for index in range(KEY_BITS)
    )
    return {
        "correct_bits": correct,
        "hamming_distance": KEY_BITS - correct,
        "candidate_equals_truth": base_key == truth_key,
    }


def _confidence_depth_row(
    metrics: Mapping[str, object], depth: int
) -> Mapping[str, object]:
    rows = metrics.get("confidence_depths")
    if not isinstance(rows, list):
        raise O1C58RunError("confidence depth metrics differ")
    for row in rows:
        if isinstance(row, dict) and row.get("depth") == depth:
            return row
    raise O1C58RunError("confidence guidance depth is absent")


def _metric_integer(metrics: Mapping[str, object], name: str) -> int:
    value = metrics.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C58RunError("bit-vault classification metric differs")
    return value


def _classify_vault(
    *,
    base_metrics: Mapping[str, object],
    metric_lookup: Mapping[tuple[str, int], Mapping[str, object]],
    verification_lookup: Mapping[tuple[str, int], Mapping[str, object]],
    base_verification: Mapping[str, object],
    guidance_depth: int,
    minimum_correct_bits: int,
    minimum_base_improvement: int,
) -> tuple[str, dict[str, object]]:
    expected = {(arm, prefix) for arm in ARMS for prefix in PREFIXES}
    if (
        set(metric_lookup) != expected
        or set(verification_lookup) != expected
        or guidance_depth != 8
        or minimum_correct_bits != 144
        or minimum_base_improvement != 8
    ):
        raise O1C58RunError("bit-vault classification input differs")
    primary = metric_lookup[("primary", 8)]
    key_control = metric_lookup[("key_rotated", 8)]
    clause_control = metric_lookup[("clause_rotated", 8)]
    base_correct = _metric_integer(base_metrics, "correct_bits")
    primary_correct = _metric_integer(primary, "correct_bits")
    key_correct = _metric_integer(key_control, "correct_bits")
    clause_correct = _metric_integer(clause_control, "correct_bits")
    primary_longest = _metric_integer(
        primary, "longest_fully_correct_confidence_prefix"
    )
    key_longest = _metric_integer(
        key_control, "longest_fully_correct_confidence_prefix"
    )
    clause_longest = _metric_integer(
        clause_control, "longest_fully_correct_confidence_prefix"
    )
    if any(
        not 0 <= value <= KEY_BITS
        for value in (
            base_correct,
            primary_correct,
            key_correct,
            clause_correct,
            primary_longest,
            key_longest,
            clause_longest,
        )
    ):
        raise O1C58RunError("bit-vault classification range differs")
    depth_row = _confidence_depth_row(primary, guidance_depth)
    top_guidance_all_correct = (
        depth_row.get("correct") == guidance_depth
        and depth_row.get("all_correct") is True
    )
    strict_confidence_margin = primary_longest > max(key_longest, clause_longest)
    guidance_gate = top_guidance_all_correct and strict_confidence_margin
    correct_threshold = primary_correct >= minimum_correct_bits
    base_improvement = primary_correct - base_correct >= minimum_base_improvement
    strict_correct_margin = primary_correct > max(key_correct, clause_correct)
    secondary_gate = correct_threshold and base_improvement and strict_correct_margin

    exact_rows = [
        (arm, prefix)
        for arm in ARMS
        for prefix in PREFIXES
        if verification_lookup[(arm, prefix)].get("exact_all_blocks") is True
        and metric_lookup[(arm, prefix)].get("candidate_equals_truth") is True
    ]
    base_exact = (
        base_verification.get("exact_all_blocks") is True
        and base_metrics.get("candidate_equals_truth") is True
    )
    exact_recovery = base_exact or bool(exact_rows)
    if exact_recovery:
        classification = "MULTIBLOCK_BIT_VAULT_EXACT_FULL256_RECOVERY"
    elif guidance_gate or secondary_gate:
        classification = "MULTIBLOCK_BIT_VAULT_PARTIAL_DIRECTIONAL_RECOVERY"
    else:
        classification = "MULTIBLOCK_BIT_VAULT_NO_DIRECTIONAL_TRANSFER"
    return classification, {
        "exact_recovery": exact_recovery,
        "base_exact_recovery": base_exact,
        "exact_synthesized_candidates": [
            {"arm": arm, "prefix": prefix} for arm, prefix in exact_rows
        ],
        "primary_prefix8_top8_all_correct": top_guidance_all_correct,
        "primary_prefix8_longest_correct_confidence_prefix": primary_longest,
        "key_rotated_prefix8_longest_correct_confidence_prefix": key_longest,
        "clause_rotated_prefix8_longest_correct_confidence_prefix": clause_longest,
        "strict_longest_correct_confidence_prefix_control_margin": strict_confidence_margin,
        "primary_partial_guidance_gate": guidance_gate,
        "primary_prefix8_correct_bits": primary_correct,
        "base_correct_bits": base_correct,
        "primary_prefix8_correct_bit_improvement_over_base": primary_correct
        - base_correct,
        "primary_prefix8_minimum_144_correct_bits": correct_threshold,
        "primary_prefix8_minimum_8_bit_base_improvement": base_improvement,
        "primary_prefix8_strict_correct_bit_control_margin": strict_correct_margin,
        "secondary_strong_bit_advantage_gate": secondary_gate,
        "partial_recovery_gate": guidance_gate or secondary_gate,
    }


def _validate_freeze_rows(
    block_rows: Sequence[Mapping[str, object]],
    prefix_rows: Sequence[Mapping[str, object]],
) -> None:
    expected_blocks = {(index, arm) for index in range(BLOCK_COUNT) for arm in ARMS}
    expected_prefixes = {(prefix, arm) for prefix in PREFIXES for arm in ARMS}
    block_fields = {
        "block_index",
        "counter",
        "arm",
        "pipeline",
        "field_sha256",
        "field_description",
        "feature_mean",
        "feature_std",
        "decoy_raw_score_sha256",
        "scalar_decoy_mean",
        "scalar_decoy_std_ddof1",
        "decoy_scalar_z_sha256",
        "calibration_keys_sha256",
        "gradient_raw_score_sha256",
        "gradient_scalar_z_sha256",
        "delta_sha256",
        "gradient_keys_sha256",
    }
    prefix_fields = {
        "prefix",
        "selection_scope",
        "arm",
        "pipeline",
        "vault_sha256",
        "live_state_bytes",
        "confidence_order_sha256",
        "synthesized_key_sha256",
        "gradient_keys_sha256",
        "public_verification",
    }
    if (
        len(block_rows) != BLOCK_COUNT * len(ARMS)
        or len(prefix_rows) != len(PREFIXES) * len(ARMS)
        or {(row.get("block_index"), row.get("arm")) for row in block_rows}
        != expected_blocks
        or {(row.get("prefix"), row.get("arm")) for row in prefix_rows}
        != expected_prefixes
        or any(set(row) != block_fields for row in block_rows)
        or any(set(row) != prefix_fields for row in prefix_rows)
        or any(row.get("pipeline") != PIPELINE for row in (*block_rows, *prefix_rows))
        or any(
            row.get("live_state_bytes") != PRIMARY_LIVE_STATE_BYTES
            for row in prefix_rows
        )
    ):
        raise O1C58RunError("pre-reveal bit-vault freeze rows differ")
    if len({str(row["calibration_keys_sha256"]) for row in block_rows}) != 1:
        raise O1C58RunError("calibration panel differs across block rows")
    if (
        len({str(row["gradient_keys_sha256"]) for row in (*block_rows, *prefix_rows)})
        != 1
    ):
        raise O1C58RunError("gradient panel differs across frozen rows")
    for row in prefix_rows:
        expected_scope = (
            "primary-all-eight-block-attack"
            if row["prefix"] == 8
            else "post-selection-evidence-ablation"
        )
        verification = row["public_verification"]
        if (
            row["selection_scope"] != expected_scope
            or not isinstance(verification, dict)
            or set(verification)
            != {
                "candidate_output_sha256",
                "block_matches",
                "matched_blocks",
                "exact_all_blocks",
            }
            or not isinstance(verification["block_matches"], list)
            or len(verification["block_matches"]) != BLOCK_COUNT
        ):
            raise O1C58RunError("pre-reveal public verification row differs")


def _commit_bound_bytes(root: Path, commit: str, path: Path, field: str) -> None:
    try:
        relative = path.resolve(strict=True).relative_to(root).as_posix()
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative}"],
            cwd=root,
            check=True,
            capture_output=True,
        )
        payload = path.read_bytes()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise O1C58RunError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C58RunError(f"{field} differs from source commit")


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C58RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    field = _mapping(config.get("field"), "field")
    reader = _mapping(config.get("reader"), "reader")
    calibration = _mapping(config.get("calibration_panel"), "calibration_panel")
    gradient = _mapping(config.get("gradient_panel"), "gradient_panel")
    vault = _mapping(config.get("vault"), "vault")
    controls = _mapping(config.get("controls"), "controls")
    verification = _mapping(config.get("verification"), "verification")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "multiblock-bit-vault-gradient-v1"
        or config.get("claim_level") != "TEST"
        or target.get("count") != 1
        or target.get("target_id") != "o1c-0058-bit-vault-fresh-0000"
        or target.get("entropy_source_id") != "os.urandom:o1c-0058"
        or target.get("block_count") != BLOCK_COUNT
        or target.get("counter_schedule") != "eight-contiguous-without-wrap"
        or target.get("rounds") != 20
        or target.get("feed_forward") is not True
        or target.get("unknown_key_bits") != KEY_BITS
        or target.get("publication_before_probe") is not True
        or target.get("reveal_after_complete_vault_freeze") is not True
        or target.get("direct_all_block_verification") is not True
        or field.get("conflict_horizon") != 16
        or field.get("seed") != 0
        or field.get("capacity") != 8192
        or field.get("direct_original_only") is not True
        or field.get("exclude_unit_parents") is not True
        or field.get("score_unit")
        != "exclusive-chain-direct-original-parent-occurrence"
        or field.get("one_field_per_public_block") is not True
        or field.get("sensor_builds") != 1
        or reader.get("source_attempt") != "O1C-0043"
        or reader.get("feature_names") != list(FEATURE_NAMES)
        or reader.get("weights_sha256") != READER_SHA256
        or reader.get("feature_standardization")
        != "unchanged-o1c43-per-block-per-arm-decoy-mean-and-sample-std"
        or reader.get("scalar_standardization")
        != "per-block-per-arm-decoy-reader-score-mean-and-sample-std-ddof1"
        or reader.get("gradient_transform") != "frozen-decoy-calibration-only"
        or any(
            reader.get(name) is not True
            for name in (
                "no_refit",
                "no_reweight",
                "no_sign_selection",
                "no_block_subset_selection",
            )
        )
        or calibration.get("count") != DECOY_COUNT
        or calibration.get("domain") != "O1C58-multiblock-bit-vault-calibration-v1"
        or calibration.get("generator")
        != "sha256(sha256(domain || NUL || full-eight-block-public-view-digest) || uint64le(index))"
        or calibration.get("shared_byte_identical_across_blocks_and_arms") is not True
        or calibration.get("duplicate_policy") != "reject"
        or gradient.get("count") != GRADIENT_PANEL_SIZE
        or gradient.get("base_selection")
        != "argmax-unweighted-eight-block-primary-decoy-scalar-z-with-smallest-index-tiebreak"
        or gradient.get("same_primary_attended_base_for_all_arms") is not True
        or gradient.get("layout")
        != "index-0-base-then-index-(i+1)-equals-base-xor-key-bit-i"
        or gradient.get("bit_convention")
        != "bit-i-is-key-byte-floor(i/8)-mask-(1<<(i-mod-8))-for-i-in-0..255"
        or gradient.get("shared_byte_identical_across_blocks_and_arms") is not True
        or gradient.get("truth_key_used_in_generation") is not False
        or gradient.get("truth_collision_policy")
        != "allowed-and-counted-as-publicly-verified-exact-success"
        or vault.get("cells") != KEY_BITS
        or vault.get("delta") != "decoy-scalar-z(one-bit-neighbor)-decoy-scalar-z(base)"
        or vault.get("prefixes") != list(PREFIXES)
        or vault.get("update") != "unweighted-float64-sum-across-public-blocks"
        or vault.get("synthesis")
        != "flip-base-bit-i-iff-cumulative-delta-i-is-strictly-positive; ties-retain-base"
        or vault.get("confidence_order")
        != "descending-absolute-cumulative-evidence-with-ascending-bit-index-tiebreak"
        or vault.get("confidence_depths") != list(CONFIDENCE_DEPTHS)
        or vault.get("primary_live_state_bytes") != PRIMARY_LIVE_STATE_BYTES
        or vault.get("all_three_live_state_bytes") != ALL_ARMS_LIVE_STATE_BYTES
        or vault.get("prefix_snapshots_are_artifacts_not_live_state") is not True
        or vault.get("prefix_interpretation")
        != "prefix-8-is-the-primary-all-public-block-attack; prefixes-1-2-4-are-post-all-block-base-selection-evidence-ablations-not-future-blind-online-attacks"
        or vault.get("learned_weights") is not False
        or vault.get("block_selection") is not False
        or controls.get("arms") != list(ARMS)
        or controls.get("identical_calibration_gradient_vault_and_synthesis_path")
        is not True
        or controls.get("rotation")
        != "one-step cyclic derangement of key coordinates or every active clause variable"
        or verification.get("when")
        != "before-reveal-after-complete-vault-and-key-freeze"
        or verification.get("candidate_count") != 13
        or verification.get("selected_base_verified_once") is not True
        or verification.get("synthesized_candidates_verified") != 12
        or verification.get("blocks_per_candidate") != BLOCK_COUNT
        or verification.get("method") != "direct-public-chacha20-output-equality"
        or verification.get("reader_rescoring_of_synthesized_candidates") is not False
        or success.get("confidence_guidance_depth") != 8
        or success.get("require_all_primary_prefix8_guidance_bits_correct") is not True
        or success.get(
            "require_primary_longest_correct_prefix_strictly_above_both_controls"
        )
        is not True
        or success.get("secondary_minimum_primary_prefix8_correct_bits") != 144
        or success.get("secondary_minimum_improvement_over_base_correct_bits") != 8
        or success.get("secondary_require_strict_correct_bit_margin_over_both_controls")
        is not True
        or success.get("exact_public_verification_is_strongest_gate") is not True
        or budgets.get("maximum_wall_seconds") != 180
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 4096
        or budgets.get("maximum_candidate_forward_evaluations") != 34824
        or budgets.get("maximum_decoy_calibration_forward_evaluations") != 32768
        or budgets.get("maximum_gradient_forward_evaluations") != 2056
        or budgets.get("maximum_synthesized_candidates") != 12
        or budgets.get("maximum_pre_reveal_verified_candidates") != 13
        or budgets.get("maximum_direct_chacha_block_evaluations") != 112
        or budgets.get("maximum_decoy_keys") != DECOY_COUNT
        or budgets.get("maximum_gradient_keys") != GRADIENT_PANEL_SIZE
        or budgets.get("maximum_primary_live_state_bytes") != PRIMARY_LIVE_STATE_BYTES
        or budgets.get("maximum_all_arms_live_state_bytes") != ALL_ARMS_LIVE_STATE_BYTES
        or budgets.get("maximum_fresh_targets") != 1
        or budgets.get("maximum_scientific_entropy_calls") != 1
        or budgets.get("maximum_sensor_builds") != 1
        or budgets.get("maximum_reveal_calls") != 1
        or budgets.get("maximum_solver_calls") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 4194304
    ):
        raise O1C58RunError("frozen O1C-0058 config differs")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "o1c57_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    )
    for name in source_names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        expected_hash = expected.get(name)
        if not isinstance(expected_hash, str) or sha256_file(resolved) != expected_hash:
            raise O1C58RunError(f"source hash differs for {name}")
    manifest = (root / O1C43_MANIFEST).resolve(strict=True)
    if sha256_file(manifest) != expected.get("o1c43_manifest"):
        raise O1C58RunError("O1C-0043 manifest hash differs")
    return config


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Base / primary prefix-8 correct bits: `{metrics['base_correct_bits']}` / "
        f"`{metrics['primary_prefix8_correct_bits']}`\n"
        f"- Primary prefix-8 longest correct confidence prefix: "
        f"`{metrics['primary_prefix8_longest_correct_confidence_prefix']}`\n"
        f"- Exact recovery: `{metrics['exact_recovery']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n"
        f"- Live efficacy/control vault bytes: `{resources['all_arms_live_state_bytes']}`\n\n"
        "The attended base, all finite differences, 256-cell vault snapshots, "
        "confidence orders, synthesized keys, and public output checks were frozen "
        "before the one-shot reveal. Prefixes 1/2/4 are post-selection evidence "
        "ablations; prefix 8 is the primary all-public-block attack.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    if (root / RESULT_RELATIVE).exists():
        raise O1C58RunError("authoritative O1C-0058 output already exists")
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    target_config = _mapping(config["target"], "target")
    field_config = _mapping(config["field"], "field")
    reader_config = _mapping(config["reader"], "reader")
    calibration_config = _mapping(config["calibration_panel"], "calibration_panel")
    success = _mapping(config["success"], "success")
    budgets = _mapping(config["budgets"], "budgets")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "o1c57_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    )
    source_paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in source_names
    }
    source_paths["o1c43_manifest"] = (root / O1C43_MANIFEST).resolve(strict=True)
    source_commit = _git_commit(root)
    commit_bound_paths = {
        "config": config_file,
        **{name: source_paths[name] for name in COMMIT_BOUND_SOURCE_NAMES},
    }
    for name, path in commit_bound_paths.items():
        _commit_bound_bytes(root, source_commit, path, name)

    o1c43 = _read_json(source_paths["o1c43_result"])
    o1c43_metrics = _mapping(o1c43.get("metrics"), "O1C-0043 metrics")
    o1c43_reader = _mapping(o1c43.get("reader"), "O1C-0043 reader")
    if (
        o1c43.get("classification") != "CONSUMED_PARENT_CRITICALITY_RANK_SIGNAL"
        or o1c43_metrics.get("development_gate_pass") is not True
        or o1c43_metrics.get("consumed_repeat_pass") is not True
        or o1c43_reader.get("feature_names") != list(FEATURE_NAMES)
        or o1c43_reader.get("weights_sha256") != reader_config["weights_sha256"]
    ):
        raise O1C58RunError("O1C-0043 prerequisite differs")
    reader = np.asarray(o1c43_reader.get("weights_l2"), dtype=np.float64)
    if (
        reader.shape != (len(FEATURE_NAMES),)
        or not np.all(np.isfinite(reader))
        or array_sha256(reader, "<f8") != READER_SHA256
    ):
        raise O1C58RunError("frozen O1C-0043 reader differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    entropy_calls = 0
    reveal_calls = 0

    def scientific_entropy(count: int) -> bytes:
        nonlocal entropy_calls
        entropy_calls += 1
        if entropy_calls != 1:
            raise O1C58RunError("scientific entropy source called more than once")
        return os.urandom(count)

    broker = Full256TargetBroker(
        block_count=BLOCK_COUNT,
        entropy_source=scientific_entropy,
        entropy_source_id=str(target_config["entropy_source_id"]),
        target_id=str(target_config["target_id"]),
    )
    publication = broker.publish()
    publication_bytes = _canonical_bytes(publication)
    public = public_view_from_publication(publication)
    blocks = _slice_public_blocks(public)
    if entropy_calls != 1 or broker.phase != "PUBLISHED":
        raise O1C58RunError("sealed multiblock publication phase differs")
    calibration_keys = _shared_decoy_panel(
        public,
        domain=str(calibration_config["domain"]),
        count=int(calibration_config["count"]),
    )
    calibration_key_bytes = b"".join(calibration_keys)
    calibration_keys_sha256 = hashlib.sha256(calibration_key_bytes).hexdigest()

    field_bytes: dict[str, bytes] = {}
    decoy_raw_bytes: dict[str, bytes] = {}
    decoy_z_bytes: dict[str, bytes] = {}
    gradient_raw_bytes: dict[str, bytes] = {}
    gradient_z_bytes: dict[str, bytes] = {}
    delta_bytes: dict[str, bytes] = {}
    vault_bytes: dict[str, bytes] = {}
    confidence_bytes: dict[str, bytes] = {}
    synthesized_key_bytes: dict[str, bytes] = {}
    selection_bytes: dict[str, bytes] = {}
    block_rows: list[dict[str, object]] = []
    prefix_rows: list[dict[str, object]] = []
    runtimes: list[dict[str, object]] = []
    natural_fields: list[ParentCriticalityField] = []
    instance_sha256: list[str] = []
    decoy_scores = {
        arm: np.empty((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64) for arm in ARMS
    }
    decoy_z = {
        arm: np.empty((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64) for arm in ARMS
    }
    scalar_calibration: dict[tuple[int, str], tuple[float, float]] = {}
    gradient_scores = {
        arm: np.empty((BLOCK_COUNT, GRADIENT_PANEL_SIZE), dtype=np.float64)
        for arm in ARMS
    }
    gradient_z = {
        arm: np.empty((BLOCK_COUNT, GRADIENT_PANEL_SIZE), dtype=np.float64)
        for arm in ARMS
    }
    block_deltas = {
        arm: np.empty((BLOCK_COUNT, KEY_BITS), dtype=np.float64) for arm in ARMS
    }

    with tempfile.TemporaryDirectory(prefix="o1c58-") as temporary:
        workspace = Path(temporary)
        sensor_build = build_native_sensor(
            source=source_paths["sensor_source"],
            tracer_header=source_paths["tracer_header"],
            cadical_include="/opt/homebrew/opt/cadical/include",
            cadical_library="/opt/homebrew/opt/cadical/lib/libcadical.a",
            output=workspace / "cadical-pair-sensor",
            expected_cadical_header_sha256=CADICAL_HEADER_SHA256,
            expected_cadical_library_sha256=CADICAL_LIBRARY_SHA256,
        )
        # Phase one: build all public fields and frozen decoy calibrations.
        for block_index, block_public in enumerate(blocks):
            natural, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=source_paths["template"],
                semantic_map=source_paths["semantic_map"],
                public=block_public,
                workspace=workspace,
                target_id=f"{target_config['target_id']}-block-{block_index:02d}",
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            runtime = _score_runtime(
                natural=natural,
                public=block_public,
                semantic_map=source_paths["semantic_map"],
                keys=calibration_keys,
                reader=reader,
            )
            runtimes.append(runtime)
            natural_fields.append(natural)
            instance_sha256.append(instance_sha)
            field_name = f"fields/block-{block_index:02d}.bin"
            field_bytes[field_name] = natural.to_bytes()
            scores = cast(Mapping[str, np.ndarray], runtime["scores"])
            if set(scores) != set(ARMS):
                raise O1C58RunError("decoy calibration arms differ")
            for arm in ARMS:
                raw = np.asarray(scores[arm], dtype=np.float64)
                if raw.shape != (DECOY_COUNT,) or not np.all(np.isfinite(raw)):
                    raise O1C58RunError("decoy reader score vector differs")
                z_values, scalar_mean, scalar_std = _standardize_scalar_decoys(raw)
                decoy_scores[arm][block_index] = raw
                decoy_z[arm][block_index] = z_values
                scalar_calibration[(block_index, arm)] = (scalar_mean, scalar_std)
                raw_name = f"scores/decoy-raw/block-{block_index:02d}-{arm}.f64le"
                z_name = f"scores/decoy-z/block-{block_index:02d}-{arm}.f64le"
                decoy_raw_bytes[raw_name] = np.ascontiguousarray(
                    raw, dtype="<f8"
                ).tobytes()
                decoy_z_bytes[z_name] = np.ascontiguousarray(
                    z_values, dtype="<f8"
                ).tobytes()

        base_index, primary_aggregate = _attended_base_index(decoy_z["primary"])
        base_key = calibration_keys[base_index]
        base_key_sha256 = hashlib.sha256(base_key).hexdigest()
        selection_payload = np.ascontiguousarray(
            primary_aggregate, dtype="<f8"
        ).tobytes()
        selection_bytes["selection/primary-eight-block-decoy-sum.f64le"] = (
            selection_payload
        )
        selection_bytes["selection/attended-base-key.bin"] = base_key
        base_verification = _public_verify_key(base_key, public)
        gradient_keys = _gradient_panel(base_key)
        gradient_key_bytes = b"".join(gradient_keys)
        gradient_keys_sha256 = hashlib.sha256(gradient_key_bytes).hexdigest()

        # Phase two: apply the frozen calibrations to one shared 257-key panel.
        for block_index, (runtime, block_public) in enumerate(zip(runtimes, blocks)):
            panel_scores = _score_keys_with_runtime(
                runtime=runtime,
                public=block_public,
                keys=gradient_keys,
                reader=reader,
            )
            fields = cast(Mapping[str, ParentCriticalityField], runtime["fields"])
            means = cast(Mapping[str, np.ndarray], runtime["means"])
            stds = cast(Mapping[str, np.ndarray], runtime["stds"])
            for arm in ARMS:
                raw = np.asarray(panel_scores[arm], dtype=np.float64)
                scalar_mean, scalar_std = scalar_calibration[(block_index, arm)]
                z_values = _apply_scalar_calibration(
                    raw, mean=scalar_mean, std=scalar_std
                )
                delta = _delta_from_panel_z(z_values)
                gradient_scores[arm][block_index] = raw
                gradient_z[arm][block_index] = z_values
                block_deltas[arm][block_index] = delta
                gradient_raw_name = (
                    f"scores/gradient-raw/block-{block_index:02d}-{arm}.f64le"
                )
                gradient_z_name = (
                    f"scores/gradient-z/block-{block_index:02d}-{arm}.f64le"
                )
                delta_name = f"deltas/block-{block_index:02d}-{arm}.f64le"
                gradient_raw_bytes[gradient_raw_name] = np.ascontiguousarray(
                    raw, dtype="<f8"
                ).tobytes()
                gradient_z_bytes[gradient_z_name] = np.ascontiguousarray(
                    z_values, dtype="<f8"
                ).tobytes()
                delta_bytes[delta_name] = np.ascontiguousarray(
                    delta, dtype="<f8"
                ).tobytes()
                decoy_raw_name = f"scores/decoy-raw/block-{block_index:02d}-{arm}.f64le"
                decoy_z_name = f"scores/decoy-z/block-{block_index:02d}-{arm}.f64le"
                block_rows.append(
                    {
                        "block_index": block_index,
                        "counter": block_public.counter_schedule[0],
                        "arm": arm,
                        "pipeline": PIPELINE,
                        "field_sha256": hashlib.sha256(
                            fields[arm].to_bytes()
                        ).hexdigest(),
                        "field_description": fields[arm].describe(),
                        "feature_mean": means[arm].tolist(),
                        "feature_std": stds[arm].tolist(),
                        "decoy_raw_score_sha256": hashlib.sha256(
                            decoy_raw_bytes[decoy_raw_name]
                        ).hexdigest(),
                        "scalar_decoy_mean": scalar_mean,
                        "scalar_decoy_std_ddof1": scalar_std,
                        "decoy_scalar_z_sha256": hashlib.sha256(
                            decoy_z_bytes[decoy_z_name]
                        ).hexdigest(),
                        "calibration_keys_sha256": calibration_keys_sha256,
                        "gradient_raw_score_sha256": hashlib.sha256(
                            gradient_raw_bytes[gradient_raw_name]
                        ).hexdigest(),
                        "gradient_scalar_z_sha256": hashlib.sha256(
                            gradient_z_bytes[gradient_z_name]
                        ).hexdigest(),
                        "delta_sha256": hashlib.sha256(
                            delta_bytes[delta_name]
                        ).hexdigest(),
                        "gradient_keys_sha256": gradient_keys_sha256,
                    }
                )

        vault_lookup: dict[tuple[str, int], np.ndarray] = {}
        confidence_lookup: dict[tuple[str, int], tuple[int, ...]] = {}
        candidate_lookup: dict[tuple[str, int], bytes] = {}
        verification_lookup: dict[tuple[str, int], dict[str, object]] = {}
        for arm in ARMS:
            snapshots = _vault_prefixes(block_deltas[arm])
            for prefix in PREFIXES:
                vault = snapshots[prefix]
                order = _confidence_order(vault)
                candidate = _synthesize_key(base_key, vault)
                verification = _public_verify_key(candidate, public)
                vault_lookup[(arm, prefix)] = vault
                confidence_lookup[(arm, prefix)] = order
                candidate_lookup[(arm, prefix)] = candidate
                verification_lookup[(arm, prefix)] = verification
                vault_name = f"vaults/prefix-{prefix:02d}-{arm}.f64le"
                confidence_name = f"confidence/prefix-{prefix:02d}-{arm}.u16le"
                candidate_name = f"synthesized/prefix-{prefix:02d}-{arm}.key"
                vault_bytes[vault_name] = np.ascontiguousarray(
                    vault, dtype="<f8"
                ).tobytes()
                confidence_bytes[confidence_name] = np.asarray(
                    order, dtype="<u2"
                ).tobytes()
                synthesized_key_bytes[candidate_name] = candidate
                prefix_rows.append(
                    {
                        "prefix": prefix,
                        "selection_scope": (
                            "primary-all-eight-block-attack"
                            if prefix == 8
                            else "post-selection-evidence-ablation"
                        ),
                        "arm": arm,
                        "pipeline": PIPELINE,
                        "vault_sha256": hashlib.sha256(
                            vault_bytes[vault_name]
                        ).hexdigest(),
                        "live_state_bytes": vault.nbytes,
                        "confidence_order_sha256": hashlib.sha256(
                            confidence_bytes[confidence_name]
                        ).hexdigest(),
                        "synthesized_key_sha256": hashlib.sha256(candidate).hexdigest(),
                        "gradient_keys_sha256": gradient_keys_sha256,
                        "public_verification": verification,
                    }
                )

        _validate_freeze_rows(block_rows, prefix_rows)
        all_arms_prefix8_payload = b"".join(
            vault_bytes[f"vaults/prefix-08-{arm}.f64le"] for arm in ARMS
        )
        if len(all_arms_prefix8_payload) != ALL_ARMS_LIVE_STATE_BYTES:
            raise O1C58RunError("all-arm live vault state differs")
        pre_reveal_payloads = {
            **field_bytes,
            **decoy_raw_bytes,
            **decoy_z_bytes,
            **gradient_raw_bytes,
            **gradient_z_bytes,
            **delta_bytes,
            **vault_bytes,
            **confidence_bytes,
            **synthesized_key_bytes,
            **selection_bytes,
        }
        pre_reveal_artifacts = {
            "publication.json": hashlib.sha256(publication_bytes).hexdigest(),
            "calibration_keys.bin": calibration_keys_sha256,
            "gradient_keys.bin": gradient_keys_sha256,
            **{
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in pre_reveal_payloads.items()
            },
        }
        score_freeze = {
            "schema": FREEZE_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "target_id": target_config["target_id"],
            "publication_sha256": publication["publication_sha256"],
            "full_public_view_sha256": public.digest(),
            "block_count": BLOCK_COUNT,
            "target_key_reads": 0,
            "reveal_calls": 0,
            "reader_weights_sha256": array_sha256(reader, "<f8"),
            "calibration_panel": config["calibration_panel"],
            "calibration_keys_sha256": calibration_keys_sha256,
            "attended_base_selection": {
                "rule": "argmax-unweighted-eight-block-primary-decoy-scalar-z-with-smallest-index-tiebreak",
                "selected_index": base_index,
                "selected_score": float(primary_aggregate[base_index]),
                "aggregate_scores_sha256": hashlib.sha256(
                    selection_payload
                ).hexdigest(),
                "base_key_sha256": base_key_sha256,
                "same_base_for_all_arms": True,
                "public_verification": base_verification,
            },
            "gradient_panel": config["gradient_panel"],
            "gradient_keys_sha256": gradient_keys_sha256,
            "natural_fields": [field.describe() for field in natural_fields],
            "natural_field_sha256": [
                hashlib.sha256(field.to_bytes()).hexdigest() for field in natural_fields
            ],
            "instance_sha256": instance_sha256,
            "block_rows": block_rows,
            "prefix_rows": prefix_rows,
            "bounded_state": {
                "dtype": "float64",
                "cells_per_arm": KEY_BITS,
                "primary_live_state_bytes": PRIMARY_LIVE_STATE_BYTES,
                "all_arms_live_state_bytes": ALL_ARMS_LIVE_STATE_BYTES,
                "all_arms_prefix8_state_sha256": hashlib.sha256(
                    all_arms_prefix8_payload
                ).hexdigest(),
                "prefix_snapshots_are_artifacts_not_live_state": True,
            },
            "pre_reveal_verified_candidates": 13,
            "pre_reveal_direct_chacha_blocks": 13 * BLOCK_COUNT,
            "pre_reveal_artifact_sha256": pre_reveal_artifacts,
        }
        score_freeze_bytes = _canonical_bytes(score_freeze)
        score_freeze_sha256 = hashlib.sha256(score_freeze_bytes).hexdigest()
        receipt = make_freeze_receipt(
            publication, frozen_artifact_sha256=score_freeze_sha256
        )
        receipt_bytes = _canonical_bytes(receipt)
        reveal_calls += 1
        reveal = broker.reveal(receipt)
        verified_reveal = verify_reveal(reveal)
        reveal_bytes = _canonical_bytes(verified_reveal)
        if reveal_calls != 1 or broker.phase != "REVEALED":
            raise O1C58RunError("sealed multiblock reveal phase differs")
        preimage = _mapping(
            verified_reveal.get("commitment_preimage"), "commitment_preimage"
        )
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C58RunError("revealed multiblock key encoding differs") from exc
        if len(truth_key) != 32:
            raise O1C58RunError("revealed multiblock key length differs")
        reproduced = chacha20_blocks(
            truth_key, public.counter_schedule[0], public.nonce, BLOCK_COUNT
        )
        if reproduced != public.output_blocks:
            raise O1C58RunError("revealed key fails direct all-eight output check")

        base_metrics = {
            **_base_truth_metrics(base_key, truth_key),
            "candidate_equals_truth": base_key == truth_key,
        }
        truth_rows: list[dict[str, object]] = []
        metric_lookup: dict[tuple[str, int], Mapping[str, object]] = {}
        for arm in ARMS:
            for prefix in PREFIXES:
                metrics = _truth_metrics(
                    base_key=base_key,
                    candidate=candidate_lookup[(arm, prefix)],
                    truth_key=truth_key,
                    evidence=vault_lookup[(arm, prefix)],
                    confidence_order=confidence_lookup[(arm, prefix)],
                )
                metric_lookup[(arm, prefix)] = metrics
                truth_rows.append(
                    {
                        "arm": arm,
                        "prefix": prefix,
                        "selection_scope": (
                            "primary-all-eight-block-attack"
                            if prefix == 8
                            else "post-selection-evidence-ablation"
                        ),
                        "metrics": metrics,
                        "public_verification": verification_lookup[(arm, prefix)],
                    }
                )
        classification, gates = _classify_vault(
            base_metrics=base_metrics,
            metric_lookup=metric_lookup,
            verification_lookup=verification_lookup,
            base_verification=base_verification,
            guidance_depth=int(success["confidence_guidance_depth"]),
            minimum_correct_bits=int(
                success["secondary_minimum_primary_prefix8_correct_bits"]
            ),
            minimum_base_improvement=int(
                success["secondary_minimum_improvement_over_base_correct_bits"]
            ),
        )

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    native_branches = BLOCK_COUNT * 512
    decoy_forward_evaluations = BLOCK_COUNT * DECOY_COUNT
    gradient_forward_evaluations = BLOCK_COUNT * GRADIENT_PANEL_SIZE
    candidate_forward_evaluations = (
        decoy_forward_evaluations + gradient_forward_evaluations
    )
    synthesized_candidates = len(ARMS) * len(PREFIXES)
    pre_reveal_verified_candidates = synthesized_candidates + 1
    direct_chacha_block_evaluations = (
        pre_reveal_verified_candidates * BLOCK_COUNT + BLOCK_COUNT
    )
    if (
        native_branches != int(budgets["maximum_native_probe_branches"])
        or candidate_forward_evaluations
        != int(budgets["maximum_candidate_forward_evaluations"])
        or decoy_forward_evaluations
        != int(budgets["maximum_decoy_calibration_forward_evaluations"])
        or gradient_forward_evaluations
        != int(budgets["maximum_gradient_forward_evaluations"])
        or synthesized_candidates != int(budgets["maximum_synthesized_candidates"])
        or pre_reveal_verified_candidates
        != int(budgets["maximum_pre_reveal_verified_candidates"])
        or direct_chacha_block_evaluations
        != int(budgets["maximum_direct_chacha_block_evaluations"])
        or len(calibration_keys) != int(budgets["maximum_decoy_keys"])
        or len(gradient_keys) != int(budgets["maximum_gradient_keys"])
        or PRIMARY_LIVE_STATE_BYTES != int(budgets["maximum_primary_live_state_bytes"])
        or ALL_ARMS_LIVE_STATE_BYTES
        != int(budgets["maximum_all_arms_live_state_bytes"])
        or entropy_calls != int(budgets["maximum_scientific_entropy_calls"])
        or reveal_calls != int(budgets["maximum_reveal_calls"])
        or elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C58RunError("O1C-0058 resource ledger exceeds frozen budget")

    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": classification,
        "claim_boundary": {
            "fresh_targets": 1,
            "scientific_entropy_calls": entropy_calls,
            "public_blocks": BLOCK_COUNT,
            "same_key_and_nonce_across_blocks": True,
            "contiguous_counter_schedule": True,
            "reader_loaded_without_refit_reweight_or_sign_selection": True,
            "attended_base_selected_only_from_primary_public_decoy_scores": True,
            "same_primary_conditioned_base_used_for_all_controls": True,
            "control_base_selection_is_not_arm_symmetric": True,
            "truth_key_not_used_in_gradient_generation": True,
            "all_vault_state_keys_and_public_verifications_frozen_before_reveal": True,
            "prefix8_is_primary_all_public_block_attack": True,
            "prefixes1_2_4_are_post_selection_evidence_ablations": True,
            "revealed_key_directly_reproduces_all_eight_outputs": True,
            "exact_key_recovery": gates["exact_recovery"],
        },
        "publication_sha256": publication["publication_sha256"],
        "public_view_sha256": public.digest(),
        "score_freeze_sha256": score_freeze_sha256,
        "freeze_receipt_sha256": receipt["receipt_sha256"],
        "reveal_sha256": verified_reveal["reveal_sha256"],
        "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
        "reader": {
            "feature_names": list(FEATURE_NAMES),
            "weights_l2": reader.tolist(),
            "weights_sha256": array_sha256(reader, "<f8"),
            "source_attempt": "O1C-0043",
        },
        "instance_sha256": instance_sha256,
        "natural_fields": [field.describe() for field in natural_fields],
        "calibration_keys_sha256": calibration_keys_sha256,
        "gradient_keys_sha256": gradient_keys_sha256,
        "attended_base": {
            "selected_decoy_index": base_index,
            "selected_primary_eight_block_score": float(primary_aggregate[base_index]),
            "base_key_sha256": base_key_sha256,
            "public_verification": base_verification,
            "post_reveal_metrics": base_metrics,
        },
        "pre_reveal_block_rows": block_rows,
        "pre_reveal_prefix_rows": prefix_rows,
        "post_reveal_truth_rows": truth_rows,
        "bounded_state": score_freeze["bounded_state"],
        "metrics": {
            **gates,
            "base_correct_bits": base_metrics["correct_bits"],
            "base_hamming_distance": base_metrics["hamming_distance"],
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "parent_cpu_seconds": time.process_time() - cpu_started,
            "child_cpu_seconds": (
                child_end.ru_utime
                + child_end.ru_stime
                - children_started.ru_utime
                - children_started.ru_stime
            ),
            "peak_rss_bytes": peak_rss,
            "native_probe_branches": native_branches,
            "candidate_forward_evaluations": candidate_forward_evaluations,
            "decoy_calibration_forward_evaluations": decoy_forward_evaluations,
            "gradient_forward_evaluations": gradient_forward_evaluations,
            "synthesized_candidates": synthesized_candidates,
            "pre_reveal_verified_candidates": pre_reveal_verified_candidates,
            "direct_chacha_block_evaluations": direct_chacha_block_evaluations,
            "decoy_keys": len(calibration_keys),
            "gradient_keys": len(gradient_keys),
            "primary_live_state_bytes": PRIMARY_LIVE_STATE_BYTES,
            "all_arms_live_state_bytes": ALL_ARMS_LIVE_STATE_BYTES,
            "prefix_snapshots_counted_as_live_state": False,
            "fresh_targets": 1,
            "scientific_entropy_calls": entropy_calls,
            "sensor_builds": 1,
            "reveal_calls": reveal_calls,
            "solver_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "native_build": sensor_build.describe(),
        "source_sha256": {
            name: sha256_file(path) for name, path in source_paths.items()
        },
        "next_action": config["next_action"],
    }

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / (
        f"{stamp}_{ATTEMPT_ID}_multiblock-bit-vault-gradient-v1"
    )
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C58RunError("O1C-0058 capsule already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c58_multiblock_bit_vault_gradient_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "calibration_keys.bin": calibration_key_bytes,
        "gradient_keys.bin": gradient_key_bytes,
        "command.txt": command_bytes,
        "config.json": config_file.read_bytes(),
        "freeze_receipt.json": receipt_bytes,
        "publication.json": publication_bytes,
        "reveal.json": reveal_bytes,
        "score_freeze.json": score_freeze_bytes,
        **pre_reveal_payloads,
    }
    for relative, payload in members.items():
        destination = capsule / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    result_resources = cast(dict[str, object], result["resources"])
    for _ in range(8):
        result_bytes = _atomic_json(capsule / "result.json", result)
        members["result.json"] = result_bytes
        manifest = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(members.items())
        ).encode("ascii")
        persistent_bytes = sum(len(payload) for payload in members.values()) + len(
            manifest
        )
        if result_resources["persistent_artifact_bytes"] == persistent_bytes:
            break
        result_resources["persistent_artifact_bytes"] = persistent_bytes
    else:
        raise O1C58RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C58RunError("persistent artifact budget differs")
    (capsule / "artifacts.sha256").write_bytes(manifest)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        if path.is_file():
            path.chmod(0o444)
        elif path.is_dir():
            path.chmod(0o555)
    capsule.chmod(0o555)
    _atomic_json(root / RESULT_RELATIVE, result)
    return result


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    result = run(arguments.config)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ALL_ARMS_LIVE_STATE_BYTES",
    "ARMS",
    "ATTEMPT_ID",
    "BLOCK_COUNT",
    "COMMIT_BOUND_SOURCE_NAMES",
    "CONFIDENCE_DEPTHS",
    "DECOY_COUNT",
    "GRADIENT_PANEL_SIZE",
    "KEY_BITS",
    "O1C58RunError",
    "PIPELINE",
    "PREFIXES",
    "PRIMARY_LIVE_STATE_BYTES",
    "_apply_scalar_calibration",
    "_attended_base_index",
    "_base_truth_metrics",
    "_classify_vault",
    "_confidence_order",
    "_delta_from_panel_z",
    "_gradient_panel",
    "_key_bit",
    "_public_verify_key",
    "_score_keys_with_runtime",
    "_synthesize_key",
    "_truth_metrics",
    "_validate_freeze_rows",
    "_vault_prefixes",
    "_xor_key_bit",
    "load_config",
    "main",
    "run",
]
