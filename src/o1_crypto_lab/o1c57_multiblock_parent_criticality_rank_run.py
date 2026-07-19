"""O1C-0057 sealed eight-block parent-criticality rank compounding test."""

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
from .o1c41_antecedent_chain_rank_run import _candidate_keys, _peak_rss_bytes
from .o1c43_parent_criticality_rank_run import (
    _extract_field,
    _score_runtime,
    _standardize_vector,
)
from .proof_parent_criticality import (
    FEATURE_NAMES,
    ParentCriticalityField,
    parent_criticality_features,
)
from .relation_candidate_rank import array_sha256, exact_candidate_rank


ATTEMPT_ID = "O1C-0057"
CONFIG_SCHEMA = "o1-256-multiblock-parent-criticality-rank-config-v1"
RESULT_SCHEMA = "o1-256-multiblock-parent-criticality-rank-result-v1"
FREEZE_SCHEMA = "o1-256-multiblock-parent-criticality-score-freeze-v1"
RESULT_RELATIVE = Path(
    "research/O1C0057_MULTIBLOCK_PARENT_CRITICALITY_RANK_RESULT_20260719.json"
)
O1C43_MANIFEST = Path(
    "runs/20260718_233458_O1C-0043_parent-criticality-rank-v1/artifacts.sha256"
)
ARMS = ("primary", "key_rotated", "clause_rotated")
PREFIXES = (1, 2, 4, 8)
BLOCK_COUNT = 8
DECOY_COUNT = 4096
PANEL_SIZE = DECOY_COUNT + 1
READER_SHA256 = "c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30"
PIPELINE = "o1c43-score-runtime->decoy-scalar-z->signed-prefix-sum"
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
    "broker_source",
    "runner",
    "o1c43_result",
)


class O1C57RunError(RuntimeError):
    """The frozen multiblock mechanism, lifecycle, or work ledger differs."""


class _ForwardPlan(Protocol):
    def evaluate(self, *, key: bytes, counter: int, nonce: bytes) -> dict[int, int]: ...


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _slice_public_view(public: PublicTargetView, block_index: int) -> PublicTargetView:
    """Return one exact validated block from the frozen eight-block public view."""

    public.validate()
    if (
        public.block_count != BLOCK_COUNT
        or isinstance(block_index, bool)
        or not isinstance(block_index, int)
        or not 0 <= block_index < BLOCK_COUNT
    ):
        raise O1C57RunError("eight-block public slice differs")
    sliced = PublicTargetView(
        counter_schedule=(public.counter_schedule[block_index],),
        nonce=public.nonce,
        output_blocks=(public.output_blocks[block_index],),
        rounds=public.rounds,
    )
    sliced.validate()
    if (
        sliced.nonce != public.nonce
        or sliced.counter_schedule[0] != public.counter_schedule[0] + block_index
        or sliced.output_blocks[0] != public.output_blocks[block_index]
    ):
        raise O1C57RunError("public block slice identity differs")
    return sliced


def _slice_public_blocks(public: PublicTargetView) -> tuple[PublicTargetView, ...]:
    slices = tuple(_slice_public_view(public, index) for index in range(BLOCK_COUNT))
    if (
        len(slices) != BLOCK_COUNT
        or tuple(item.counter_schedule[0] for item in slices)
        != public.counter_schedule
        or tuple(item.output_blocks[0] for item in slices) != public.output_blocks
        or any(item.nonce != public.nonce for item in slices)
    ):
        raise O1C57RunError("eight-block public slicing differs")
    return slices


def _shared_decoy_panel(
    public: PublicTargetView, *, domain: str, count: int
) -> tuple[bytes, ...]:
    public.validate()
    if (
        public.block_count != BLOCK_COUNT
        or not isinstance(domain, str)
        or not domain
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count != DECOY_COUNT
    ):
        raise O1C57RunError("shared multiblock candidate panel differs")
    keys = tuple(_candidate_keys(domain, public.digest(), count))
    if len(keys) != count or len(set(keys)) != count:
        raise O1C57RunError("shared multiblock panel is not unique")
    return keys


def _assert_no_truth_collision(truth_key: bytes, decoy_keys: Sequence[bytes]) -> None:
    if (
        not isinstance(truth_key, bytes)
        or len(truth_key) != 32
        or len(decoy_keys) != DECOY_COUNT
        or any(not isinstance(key, bytes) or len(key) != 32 for key in decoy_keys)
        or len(set(decoy_keys)) != len(decoy_keys)
    ):
        raise O1C57RunError("truth collision panel contract differs")
    if truth_key in set(decoy_keys):
        raise O1C57RunError("revealed truth collides with frozen decoy panel")


def _standardize_scalar_decoys(
    scores: Sequence[float] | np.ndarray,
) -> tuple[np.ndarray, float, float]:
    """Standardize reader scores using decoys only and sample variance."""

    values = np.asarray(scores, dtype=np.float64)
    if values.ndim != 1 or values.size < 2 or not np.all(np.isfinite(values)):
        raise O1C57RunError("decoy scalar score vector differs")
    mean = float(np.mean(values, dtype=np.float64))
    std = float(np.std(values, ddof=1, dtype=np.float64))
    if not math.isfinite(mean) or not math.isfinite(std) or std <= 0.0:
        raise O1C57RunError("decoy scalar score variance is zero")
    standardized = np.asarray((values - mean) / std, dtype=np.float64)
    if (
        not np.all(np.isfinite(standardized))
        or not np.isclose(np.mean(standardized), 0.0, atol=1e-12)
        or not np.isclose(np.std(standardized, ddof=1), 1.0, atol=1e-12)
    ):
        raise O1C57RunError("decoy scalar standardization differs")
    return standardized, mean, std


def _standardize_scalar_truth(score: float, *, mean: float, std: float) -> float:
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(float(score))
        or not math.isfinite(mean)
        or not math.isfinite(std)
        or std <= 0.0
    ):
        raise O1C57RunError("frozen truth scalar calibration differs")
    result = (float(score) - mean) / std
    if not math.isfinite(result):
        raise O1C57RunError("truth scalar z score is non-finite")
    return result


def _prefix_sums(
    block_scores: np.ndarray, prefixes: Sequence[int] = PREFIXES
) -> dict[int, np.ndarray]:
    matrix = np.asarray(block_scores, dtype=np.float64)
    requested = tuple(prefixes)
    if (
        matrix.ndim != 2
        or matrix.shape[0] != BLOCK_COUNT
        or matrix.shape[1] < 1
        or not np.all(np.isfinite(matrix))
        or requested != PREFIXES
    ):
        raise O1C57RunError("multiblock prefix score matrix differs")
    running = np.zeros(matrix.shape[1], dtype=np.float64)
    result: dict[int, np.ndarray] = {}
    for block_index in range(BLOCK_COUNT):
        running = np.add(running, matrix[block_index], dtype=np.float64)
        prefix = block_index + 1
        if prefix in requested:
            result[prefix] = np.ascontiguousarray(running, dtype=np.float64).copy()
    if tuple(result) != requested:
        raise O1C57RunError("signed prefix aggregation differs")
    return result


def _decoy_correlations(block_scores: np.ndarray) -> tuple[np.ndarray, dict[str, float]]:
    matrix = np.asarray(block_scores, dtype=np.float64)
    if (
        matrix.shape != (BLOCK_COUNT, DECOY_COUNT)
        or not np.all(np.isfinite(matrix))
    ):
        raise O1C57RunError("decoy cross-block score matrix differs")
    correlation = np.asarray(np.corrcoef(matrix), dtype=np.float64)
    if correlation.shape != (BLOCK_COUNT, BLOCK_COUNT) or not np.all(
        np.isfinite(correlation)
    ):
        raise O1C57RunError("decoy cross-block correlation differs")
    off_diagonal = correlation[~np.eye(BLOCK_COUNT, dtype=bool)]
    return correlation, {
        "minimum": float(np.min(off_diagonal)),
        "maximum": float(np.max(off_diagonal)),
        "mean": float(np.mean(off_diagonal, dtype=np.float64)),
    }


def _validate_freeze_rows(
    block_rows: Sequence[Mapping[str, object]],
    prefix_rows: Sequence[Mapping[str, object]],
) -> None:
    expected_blocks = {(index, arm) for index in range(BLOCK_COUNT) for arm in ARMS}
    expected_prefixes = {(prefix, arm) for prefix in PREFIXES for arm in ARMS}
    observed_blocks = {
        (row.get("block_index"), row.get("arm")) for row in block_rows
    }
    observed_prefixes = {(row.get("prefix"), row.get("arm")) for row in prefix_rows}
    block_fields = {
        "block_index",
        "counter",
        "arm",
        "pipeline",
        "field_sha256",
        "field_description",
        "feature_mean",
        "feature_std",
        "raw_score_sha256",
        "scalar_decoy_mean",
        "scalar_decoy_std_ddof1",
        "scalar_z_sha256",
        "candidate_keys_sha256",
    }
    prefix_fields = {
        "prefix",
        "arm",
        "pipeline",
        "aggregate_score_sha256",
        "candidate_keys_sha256",
    }
    if (
        len(block_rows) != BLOCK_COUNT * len(ARMS)
        or len(prefix_rows) != len(PREFIXES) * len(ARMS)
        or observed_blocks != expected_blocks
        or observed_prefixes != expected_prefixes
        or any(set(row) != block_fields for row in block_rows)
        or any(set(row) != prefix_fields for row in prefix_rows)
        or any(row.get("pipeline") != PIPELINE for row in (*block_rows, *prefix_rows))
    ):
        raise O1C57RunError("pre-reveal block or prefix freeze rows differ")
    candidate_hashes = {
        str(row["candidate_keys_sha256"]) for row in (*block_rows, *prefix_rows)
    }
    if len(candidate_hashes) != 1:
        raise O1C57RunError("candidate panel differs across frozen rows")


def _classify_prefix_ranks(
    ranks: Mapping[tuple[str, int], int], *, maximum_prefix8_rank: int
) -> tuple[str, dict[str, bool]]:
    try:
        p1 = int(ranks[("primary", 1)])
        p8 = int(ranks[("primary", 8)])
        key_p8 = int(ranks[("key_rotated", 8)])
        clause_p8 = int(ranks[("clause_rotated", 8)])
    except (KeyError, TypeError, ValueError) as exc:
        raise O1C57RunError("multiblock classification ranks differ") from exc
    if (
        isinstance(maximum_prefix8_rank, bool)
        or not isinstance(maximum_prefix8_rank, int)
        or maximum_prefix8_rank < 1
        or any(not 1 <= value <= PANEL_SIZE for value in (p1, p8, key_p8, clause_p8))
    ):
        raise O1C57RunError("multiblock classification threshold differs")
    threshold = p8 <= maximum_prefix8_rank
    improvement = p8 < p1
    controls = p8 < key_p8 and p8 < clause_p8
    if threshold and improvement and controls:
        classification = "MULTIBLOCK_PARENT_CRITICALITY_COMPOUNDING_TRANSFER"
    elif improvement:
        classification = (
            "MULTIBLOCK_PARENT_CRITICALITY_RANK_IMPROVEMENT_WITHOUT_FULL_GATE"
        )
    else:
        classification = "MULTIBLOCK_PARENT_CRITICALITY_NO_COMPOUNDING"
    return classification, {
        "prefix8_threshold": threshold,
        "strict_improvement_over_prefix1": improvement,
        "strict_prefix8_control_margin": controls,
        "prediction_pass": threshold and improvement and controls,
    }


def _rank_summary(rank: Mapping[str, object]) -> dict[str, object]:
    return {
        name: rank[name]
        for name in (
            "truth_score",
            "rank",
            "rank_min",
            "rank_max",
            "rank_fraction",
            "strictly_better_decoys",
            "tied_decoys",
            "decoy_mean",
            "decoy_std",
            "truth_z",
            "decoy_min",
            "decoy_max",
        )
    }


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
        raise O1C57RunError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C57RunError(f"{field} differs from source commit")


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C57RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    field = _mapping(config.get("field"), "field")
    reader = _mapping(config.get("reader"), "reader")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    aggregation = _mapping(config.get("aggregation"), "aggregation")
    controls = _mapping(config.get("controls"), "controls")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "multiblock-parent-criticality-rank-v1"
        or config.get("claim_level") != "TEST"
        or target.get("count") != 1
        or target.get("target_id") != "o1c-0057-multiblock-fresh-0000"
        or target.get("entropy_source_id") != "os.urandom:o1c-0057"
        or target.get("block_count") != BLOCK_COUNT
        or target.get("counter_schedule") != "eight-contiguous-without-wrap"
        or target.get("rounds") != 20
        or target.get("feed_forward") is not True
        or target.get("unknown_key_bits") != 256
        or target.get("publication_before_probe") is not True
        or target.get("reveal_after_complete_score_freeze") is not True
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
        or reader.get("no_refit") is not True
        or reader.get("no_reweight") is not True
        or reader.get("no_sign_selection") is not True
        or reader.get("no_block_subset_selection") is not True
        or reader.get("scalar_standardization")
        != "per-block-per-arm-decoy-reader-score-mean-and-sample-std-ddof1"
        or reader.get("truth_transform") != "frozen-decoy-calibration-only"
        or panel.get("count") != DECOY_COUNT
        or panel.get("domain") != "O1C57-multiblock-parent-criticality-decoy-v1"
        or panel.get("generator")
        != "sha256(sha256(domain || NUL || full-eight-block-public-view-digest) || uint64le(index))"
        or panel.get("shared_byte_identical_across_blocks_and_arms") is not True
        or panel.get("duplicate_policy") != "reject"
        or panel.get("truth_collision_policy") != "fatal-without-regeneration"
        or aggregation.get("prefixes") != list(PREFIXES)
        or aggregation.get("rule")
        != "unweighted-signed-sum-of-decoy-scalar-z-scores"
        or aggregation.get("block_signs") != [1] * BLOCK_COUNT
        or aggregation.get("learned_weights") is not False
        or aggregation.get("block_selection") is not False
        or controls.get("arms") != list(ARMS)
        or controls.get("identical_score_and_aggregation_path") is not True
        or controls.get("rotation")
        != "one-step cyclic derangement of key coordinates or every active clause variable"
        or success.get("maximum_primary_prefix8_rank") != 16
        or success.get("require_strict_improvement_over_primary_prefix1") is not True
        or success.get("require_strict_margin_over_both_prefix8_rotations") is not True
        or success.get("exact_recovery_claimed") is not False
        or budgets.get("maximum_wall_seconds") != 180
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 4096
        or budgets.get("maximum_candidate_forward_evaluations") != 32776
        or budgets.get("maximum_decoy_keys") != DECOY_COUNT
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
        raise O1C57RunError("frozen O1C-0057 config differs")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "broker_source",
        "runner",
        "o1c43_result",
    )
    for name in source_names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if sha256_file(resolved) != expected.get(name):
            raise O1C57RunError(f"source hash differs for {name}")
    manifest = (root / O1C43_MANIFEST).resolve(strict=True)
    if sha256_file(manifest) != expected.get("o1c43_manifest"):
        raise O1C57RunError("O1C-0043 manifest hash differs")
    return config


def _truth_block_scores(
    *,
    runtime: Mapping[str, object],
    public: PublicTargetView,
    truth_key: bytes,
    reader: np.ndarray,
) -> dict[str, dict[str, object]]:
    """Evaluate one truth trace once and reuse it identically for all arms."""

    plan = cast(_ForwardPlan, runtime["plan"])
    fields = cast(Mapping[str, ParentCriticalityField], runtime["fields"])
    means = cast(Mapping[str, np.ndarray], runtime["means"])
    stds = cast(Mapping[str, np.ndarray], runtime["stds"])
    if set(fields) != set(ARMS) or set(means) != set(ARMS) or set(stds) != set(ARMS):
        raise O1C57RunError("truth block runtime arms differ")
    assignment = plan.evaluate(
        key=truth_key,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
    )
    result: dict[str, dict[str, object]] = {}
    for arm in ARMS:
        features = parent_criticality_features(fields[arm], assignment)
        standardized = _standardize_vector(features, means[arm], stds[arm])
        raw_score = float(np.dot(standardized, reader))
        if not math.isfinite(raw_score):
            raise O1C57RunError("truth block reader score is non-finite")
        result[arm] = {
            "raw_score": raw_score,
            "features": features.tolist(),
            "feature_standardized": standardized.tolist(),
        }
    return result


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Primary prefix-1/prefix-8 rank: `{metrics['primary_prefix1_rank']}` / "
        f"`{metrics['primary_prefix8_rank']}`\n"
        f"- Prefix-8 controls: `{metrics['key_rotated_prefix8_rank']}` / "
        f"`{metrics['clause_rotated_prefix8_rank']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The byte-identical decoy panel, eight fields, all block calibrations, "
        "and all prefix score matrices were frozen before the one-shot reveal. "
        "No exact recovery is claimed.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    if (root / RESULT_RELATIVE).exists():
        raise O1C57RunError("authoritative O1C-0057 output already exists")
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    target_config = _mapping(config["target"], "target")
    field_config = _mapping(config["field"], "field")
    reader_config = _mapping(config["reader"], "reader")
    panel_config = _mapping(config["candidate_panel"], "candidate_panel")
    success = _mapping(config["success"], "success")
    budgets = _mapping(config["budgets"], "budgets")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
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
        raise O1C57RunError("O1C-0043 prerequisite differs")
    reader = np.asarray(o1c43_reader.get("weights_l2"), dtype=np.float64)
    if (
        reader.shape != (len(FEATURE_NAMES),)
        or not np.all(np.isfinite(reader))
        or array_sha256(reader, "<f8") != READER_SHA256
    ):
        raise O1C57RunError("frozen O1C-0043 reader differs")

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
            raise O1C57RunError("scientific entropy source called more than once")
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
        raise O1C57RunError("sealed multiblock publication phase differs")
    decoy_keys = _shared_decoy_panel(
        public,
        domain=str(panel_config["domain"]),
        count=int(panel_config["count"]),
    )
    candidate_key_bytes = b"".join(decoy_keys)
    candidate_keys_sha256 = hashlib.sha256(candidate_key_bytes).hexdigest()

    field_bytes: dict[str, bytes] = {}
    raw_score_bytes: dict[str, bytes] = {}
    scalar_z_bytes: dict[str, bytes] = {}
    prefix_score_bytes: dict[str, bytes] = {}
    correlation_bytes: dict[str, bytes] = {}
    block_rows: list[dict[str, object]] = []
    prefix_rows: list[dict[str, object]] = []
    runtimes: list[dict[str, object]] = []
    natural_fields: list[ParentCriticalityField] = []
    instance_sha256: list[str] = []
    raw_scores = {
        arm: np.empty((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64) for arm in ARMS
    }
    scalar_z = {
        arm: np.empty((BLOCK_COUNT, DECOY_COUNT), dtype=np.float64) for arm in ARMS
    }
    scalar_calibration: dict[tuple[int, str], tuple[float, float]] = {}

    with tempfile.TemporaryDirectory(prefix="o1c57-") as temporary:
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
                keys=decoy_keys,
                reader=reader,
            )
            runtimes.append(runtime)
            natural_fields.append(natural)
            instance_sha256.append(instance_sha)
            field_payload = natural.to_bytes()
            field_name = f"fields/block-{block_index:02d}.bin"
            field_bytes[field_name] = field_payload
            fields = cast(Mapping[str, ParentCriticalityField], runtime["fields"])
            means = cast(Mapping[str, np.ndarray], runtime["means"])
            stds = cast(Mapping[str, np.ndarray], runtime["stds"])
            scores = cast(Mapping[str, np.ndarray], runtime["scores"])
            if set(fields) != set(ARMS) or set(scores) != set(ARMS):
                raise O1C57RunError("per-block control arm path differs")
            for arm in ARMS:
                raw = np.asarray(scores[arm], dtype=np.float64)
                if raw.shape != (DECOY_COUNT,) or not np.all(np.isfinite(raw)):
                    raise O1C57RunError("per-block raw score vector differs")
                z_values, scalar_mean, scalar_std = _standardize_scalar_decoys(raw)
                raw_scores[arm][block_index] = raw
                scalar_z[arm][block_index] = z_values
                scalar_calibration[(block_index, arm)] = (scalar_mean, scalar_std)
                raw_name = f"scores/raw/block-{block_index:02d}-{arm}.f64le"
                z_name = f"scores/scalar-z/block-{block_index:02d}-{arm}.f64le"
                raw_payload = np.ascontiguousarray(raw, dtype="<f8").tobytes()
                z_payload = np.ascontiguousarray(z_values, dtype="<f8").tobytes()
                raw_score_bytes[raw_name] = raw_payload
                scalar_z_bytes[z_name] = z_payload
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
                        "raw_score_sha256": hashlib.sha256(raw_payload).hexdigest(),
                        "scalar_decoy_mean": scalar_mean,
                        "scalar_decoy_std_ddof1": scalar_std,
                        "scalar_z_sha256": hashlib.sha256(z_payload).hexdigest(),
                        "candidate_keys_sha256": candidate_keys_sha256,
                    }
                )

        aggregate_decoys: dict[tuple[str, int], np.ndarray] = {}
        correlation_rows: dict[str, dict[str, object]] = {}
        for arm in ARMS:
            prefixes = _prefix_sums(scalar_z[arm])
            for prefix in PREFIXES:
                aggregate = prefixes[prefix]
                aggregate_decoys[(arm, prefix)] = aggregate
                name = f"scores/prefix-{prefix:02d}-{arm}.f64le"
                payload = np.ascontiguousarray(aggregate, dtype="<f8").tobytes()
                prefix_score_bytes[name] = payload
                prefix_rows.append(
                    {
                        "prefix": prefix,
                        "arm": arm,
                        "pipeline": PIPELINE,
                        "aggregate_score_sha256": hashlib.sha256(payload).hexdigest(),
                        "candidate_keys_sha256": candidate_keys_sha256,
                    }
                )
            correlation, summary = _decoy_correlations(scalar_z[arm])
            correlation_name = f"correlations/{arm}.f64le"
            correlation_payload = np.ascontiguousarray(
                correlation, dtype="<f8"
            ).tobytes()
            correlation_bytes[correlation_name] = correlation_payload
            correlation_rows[arm] = {
                **summary,
                "matrix_sha256": hashlib.sha256(correlation_payload).hexdigest(),
            }

        _validate_freeze_rows(block_rows, prefix_rows)
        pre_reveal_artifacts = {
            "publication.json": hashlib.sha256(publication_bytes).hexdigest(),
            "candidate_keys.bin": candidate_keys_sha256,
            **{
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in {
                    **field_bytes,
                    **raw_score_bytes,
                    **scalar_z_bytes,
                    **prefix_score_bytes,
                    **correlation_bytes,
                }.items()
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
            "candidate_panel": config["candidate_panel"],
            "candidate_keys_sha256": candidate_keys_sha256,
            "natural_fields": [field.describe() for field in natural_fields],
            "natural_field_sha256": [
                hashlib.sha256(field.to_bytes()).hexdigest()
                for field in natural_fields
            ],
            "instance_sha256": instance_sha256,
            "block_rows": block_rows,
            "prefix_rows": prefix_rows,
            "decoy_cross_block_correlation": correlation_rows,
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
            raise O1C57RunError("sealed multiblock reveal phase differs")
        preimage = _mapping(
            verified_reveal.get("commitment_preimage"), "commitment_preimage"
        )
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C57RunError("revealed multiblock key encoding differs") from exc
        if len(truth_key) != 32:
            raise O1C57RunError("revealed multiblock key length differs")
        _assert_no_truth_collision(truth_key, decoy_keys)
        reproduced = chacha20_blocks(
            truth_key,
            public.counter_schedule[0],
            public.nonce,
            BLOCK_COUNT,
        )
        if reproduced != public.output_blocks:
            raise O1C57RunError("revealed key fails direct all-eight output check")

        truth_block_rows: list[dict[str, object]] = []
        truth_scalar_z = {
            arm: np.empty(BLOCK_COUNT, dtype=np.float64) for arm in ARMS
        }
        for block_index, (runtime, block_public) in enumerate(zip(runtimes, blocks)):
            truth_scores = _truth_block_scores(
                runtime=runtime,
                public=block_public,
                truth_key=truth_key,
                reader=reader,
            )
            for arm in ARMS:
                scalar_mean, scalar_std = scalar_calibration[(block_index, arm)]
                raw_truth = float(cast(float, truth_scores[arm]["raw_score"]))
                z_truth = _standardize_scalar_truth(
                    raw_truth, mean=scalar_mean, std=scalar_std
                )
                truth_scalar_z[arm][block_index] = z_truth
                rank = exact_candidate_rank(
                    truth_score=z_truth,
                    decoy_scores=scalar_z[arm][block_index],
                    truth_key=truth_key,
                    decoy_keys=decoy_keys,
                )
                truth_block_rows.append(
                    {
                        "block_index": block_index,
                        "counter": block_public.counter_schedule[0],
                        "arm": arm,
                        "pipeline": PIPELINE,
                        "raw_truth_score": raw_truth,
                        "truth_scalar_z": z_truth,
                        "rank": _rank_summary(rank),
                        "features": truth_scores[arm]["features"],
                        "feature_standardized": truth_scores[arm][
                            "feature_standardized"
                        ],
                    }
                )

        truth_prefix_rows: list[dict[str, object]] = []
        rank_lookup: dict[tuple[str, int], int] = {}
        gain_lookup: dict[tuple[str, int], float] = {}
        for arm in ARMS:
            truth_cumulative = np.cumsum(truth_scalar_z[arm], dtype=np.float64)
            for prefix in PREFIXES:
                truth_score = float(truth_cumulative[prefix - 1])
                rank = exact_candidate_rank(
                    truth_score=truth_score,
                    decoy_scores=aggregate_decoys[(arm, prefix)],
                    truth_key=truth_key,
                    decoy_keys=decoy_keys,
                )
                integer_rank = int(rank["rank"])
                gain_bits = math.log2(PANEL_SIZE / integer_rank)
                rank_lookup[(arm, prefix)] = integer_rank
                gain_lookup[(arm, prefix)] = gain_bits
                truth_prefix_rows.append(
                    {
                        "prefix": prefix,
                        "arm": arm,
                        "pipeline": PIPELINE,
                        "signed_sum_truth_z": truth_score,
                        "aggregate_truth_z_against_decoys": float(rank["truth_z"]),
                        "gain_bits": gain_bits,
                        "incremental_gain_bits_vs_prefix1": 0.0,
                        "rank": _rank_summary(rank),
                    }
                )
        for row in truth_prefix_rows:
            arm = str(row["arm"])
            prefix = int(cast(int, row["prefix"]))
            row["incremental_gain_bits_vs_prefix1"] = (
                gain_lookup[(arm, prefix)] - gain_lookup[(arm, 1)]
            )

        classification, gates = _classify_prefix_ranks(
            rank_lookup,
            maximum_prefix8_rank=int(success["maximum_primary_prefix8_rank"]),
        )

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    native_branches = BLOCK_COUNT * 512
    candidate_evaluations = BLOCK_COUNT * DECOY_COUNT + BLOCK_COUNT
    if (
        native_branches != int(budgets["maximum_native_probe_branches"])
        or candidate_evaluations
        != int(budgets["maximum_candidate_forward_evaluations"])
        or len(decoy_keys) != int(budgets["maximum_decoy_keys"])
        or entropy_calls != int(budgets["maximum_scientific_entropy_calls"])
        or reveal_calls != int(budgets["maximum_reveal_calls"])
        or elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C57RunError("O1C-0057 resource ledger exceeds frozen budget")

    prefix_metric_rows: list[dict[str, object]] = []
    for prefix in PREFIXES:
        primary_rank = rank_lookup[("primary", prefix)]
        key_rank = rank_lookup[("key_rotated", prefix)]
        clause_rank = rank_lookup[("clause_rotated", prefix)]
        prefix_metric_rows.append(
            {
                "prefix": prefix,
                "primary_rank": primary_rank,
                "key_rotated_rank": key_rank,
                "clause_rotated_rank": clause_rank,
                "key_minus_primary_rank_margin": key_rank - primary_rank,
                "clause_minus_primary_rank_margin": clause_rank - primary_rank,
                "primary_gain_bits": gain_lookup[("primary", prefix)],
                "primary_minus_key_gain_bits": gain_lookup[("primary", prefix)]
                - gain_lookup[("key_rotated", prefix)],
                "primary_minus_clause_gain_bits": gain_lookup[("primary", prefix)]
                - gain_lookup[("clause_rotated", prefix)],
            }
        )

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
            "shared_decoy_panel_derived_from_full_public_digest": True,
            "all_score_state_frozen_before_reveal": True,
            "truth_uses_frozen_decoy_calibration_only": True,
            "revealed_key_directly_reproduces_all_eight_outputs": True,
            "exact_key_recovery": False,
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
        "candidate_keys_sha256": candidate_keys_sha256,
        "pre_reveal_block_rows": block_rows,
        "pre_reveal_prefix_rows": prefix_rows,
        "truth_block_rows": truth_block_rows,
        "truth_prefix_rows": truth_prefix_rows,
        "decoy_cross_block_correlation": score_freeze[
            "decoy_cross_block_correlation"
        ],
        "metrics": {
            "primary_prefix1_rank": rank_lookup[("primary", 1)],
            "primary_prefix8_rank": rank_lookup[("primary", 8)],
            "key_rotated_prefix8_rank": rank_lookup[("key_rotated", 8)],
            "clause_rotated_prefix8_rank": rank_lookup[("clause_rotated", 8)],
            "prefix_rows": prefix_metric_rows,
            **gates,
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
            "candidate_forward_evaluations": candidate_evaluations,
            "decoy_keys": len(decoy_keys),
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
    capsule_relative = (
        Path("runs") / f"{stamp}_{ATTEMPT_ID}_multiblock-parent-criticality-rank-v1"
    )
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C57RunError("O1C-0057 capsule already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c57_multiblock_parent_criticality_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "candidate_keys.bin": candidate_key_bytes,
        "command.txt": command_bytes,
        "config.json": config_file.read_bytes(),
        "freeze_receipt.json": receipt_bytes,
        "publication.json": publication_bytes,
        "reveal.json": reveal_bytes,
        "score_freeze.json": score_freeze_bytes,
        **field_bytes,
        **raw_score_bytes,
        **scalar_z_bytes,
        **prefix_score_bytes,
        **correlation_bytes,
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
        raise O1C57RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C57RunError("persistent artifact budget differs")
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
    "ATTEMPT_ID",
    "O1C57RunError",
    "_assert_no_truth_collision",
    "_classify_prefix_ranks",
    "_prefix_sums",
    "_shared_decoy_panel",
    "_slice_public_blocks",
    "_slice_public_view",
    "_standardize_scalar_decoys",
    "_standardize_scalar_truth",
    "_truth_block_scores",
    "_validate_freeze_rows",
    "load_config",
    "main",
    "run",
]
