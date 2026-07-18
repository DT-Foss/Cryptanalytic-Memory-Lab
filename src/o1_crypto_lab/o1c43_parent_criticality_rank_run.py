"""O1C-0043 consumed-panel parent-role criticality rank diagnostic."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from .cadical_sensor import (
    build_native_sensor,
    iter_native_probe_records,
    paired_records,
    sha256_file,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import write_full256_instance
from .full256_forward_assignment import compile_full256_forward_read_plan
from .full256_proof_pool import make_deterministic_known_target
from .living_inverse import PublicTargetView, bits_to_key
from .o1_relational_search import model_matches_public
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _public_view,
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c41_antecedent_chain_rank_run import (
    _candidate_keys,
    _geometric,
    _peak_rss_bytes,
)
from .proof_antecedent_relations import OriginalClauseTable
from .proof_parent_criticality import (
    FEATURE_NAMES,
    ParentCriticalityField,
    extract_parent_criticality_field,
    parent_criticality_features,
    requested_parent_criticality_variables,
    transform_parent_criticality_field,
)
from .relation_candidate_rank import array_sha256, exact_candidate_rank


ATTEMPT_ID = "O1C-0043"
CONFIG_SCHEMA = "o1-256-parent-criticality-rank-config-v1"
RESULT_SCHEMA = "o1-256-parent-criticality-rank-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0043_PARENT_CRITICALITY_RANK_RESULT_20260718.json"
)
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)


class O1C43RunError(RuntimeError):
    """The frozen O1C-0043 mechanism, label boundary, or ledger differs."""


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _standardize_panel(
    features: np.ndarray,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    matrix = np.asarray(features, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[0] < 2 or matrix.shape[1] != len(
        FEATURE_NAMES
    ) or not np.all(np.isfinite(matrix)):
        raise O1C43RunError("criticality feature panel differs")
    mean = np.mean(matrix, axis=0, dtype=np.float64)
    std = np.std(matrix, axis=0, ddof=1, dtype=np.float64)
    active = std > 0.0
    standardized = np.zeros_like(matrix)
    standardized[:, active] = (matrix[:, active] - mean[active]) / std[active]
    return standardized, mean, std


def _standardize_vector(
    vector: np.ndarray, mean: np.ndarray, std: np.ndarray
) -> np.ndarray:
    values = np.asarray(vector, dtype=np.float64)
    if (
        values.shape != (len(FEATURE_NAMES),)
        or mean.shape != values.shape
        or std.shape != values.shape
        or not np.all(np.isfinite(values))
    ):
        raise O1C43RunError("criticality truth feature differs")
    result = np.zeros_like(values)
    active = std > 0.0
    result[active] = (values[active] - mean[active]) / std[active]
    return result


def _fit_reader(build_truth_z: Sequence[np.ndarray]) -> tuple[np.ndarray, np.ndarray]:
    matrix = np.asarray(build_truth_z, dtype=np.float64)
    if (
        matrix.shape != (4, len(FEATURE_NAMES))
        or not np.all(np.isfinite(matrix))
    ):
        raise O1C43RunError("BUILD truth feature state differs")
    raw = np.mean(matrix, axis=0, dtype=np.float64)
    norm = float(np.linalg.norm(raw))
    if not math.isfinite(norm) or norm <= 0.0:
        raise O1C43RunError("BUILD criticality reader has zero norm")
    return raw, raw / norm


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


def _classify_development(
    geometric: Mapping[str, float],
    primary_fractions: Sequence[float],
    *,
    maximum_geometric: float,
    maximum_each: float,
) -> tuple[bool, bool]:
    prediction = bool(
        len(primary_fractions) == 2
        and all(fraction <= maximum_each for fraction in primary_fractions)
        and geometric["primary"] <= maximum_geometric
    )
    controls = geometric["primary"] < min(
        geometric["key_rotated"], geometric["clause_rotated"]
    )
    return prediction, controls


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C43RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    corpus = _mapping(config.get("corpus"), "corpus")
    field = _mapping(config.get("field"), "field")
    reader = _mapping(config.get("reader"), "reader")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    controls = _mapping(config.get("controls"), "controls")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "parent-criticality-rank-v1"
        or config.get("claim_level") != "CONSUMED_DIAGNOSTIC"
        or corpus.get("seed") != 180018180018
        or corpus.get("build_indices") != [0, 1, 2, 3]
        or corpus.get("development_indices") != [0, 1]
        or corpus.get("consumed_repeat_target_id") != "o1c-0042-fresh-0000"
        or corpus.get("fresh_targets") != 0
        or not isinstance(corpus.get("build_sidecars"), list)
        or len(corpus["build_sidecars"]) != 4
        or not isinstance(corpus.get("development_sidecars"), list)
        or len(corpus["development_sidecars"]) != 2
        or field.get("conflict_horizon") != 16
        or field.get("seed") != 0
        or field.get("capacity") != 8192
        or field.get("direct_original_only") is not True
        or field.get("exclude_unit_parents") is not True
        or reader.get("feature_names") != list(FEATURE_NAMES)
        or reader.get("fit_rule")
        != "l2-normalized-mean-of-four-build-truth-per-target-decoy-z"
        or reader.get("free_parameters") != len(FEATURE_NAMES)
        or panel.get("count_per_target") != 4096
        or panel.get("domain") != "O1C43-parent-criticality-decoy-v1"
        or panel.get("duplicate_policy") != "reject"
        or controls.get("arms")
        != ["primary", "key_rotated", "clause_rotated"]
        or success.get("maximum_each_development_rank_fraction") != 0.5
        or success.get("maximum_development_geometric_rank_fraction") != 0.25
        or success.get("maximum_consumed_repeat_rank_fraction") != 0.25
        or success.get("require_strict_control_margin") is not True
        or budgets.get("maximum_wall_seconds") != 180
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 3584
        or budgets.get("maximum_candidate_forward_evaluations") != 28679
        or budgets.get("maximum_decoy_keys") != 28672
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 4194304
    ):
        raise O1C43RunError("frozen O1C-0043 config differs")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "runner",
        "o1c18_config",
        "o1c18_result",
        "development_labels",
        "o1c42_publication",
        "o1c42_reveal",
        "o1c42_result",
    )
    for name in source_names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        expected_hash = expected.get(name)
        if not isinstance(expected_hash, str) or sha256_file(resolved) != expected_hash:
            raise O1C43RunError(f"source hash differs for {name}")
    for name in (*corpus["build_sidecars"], *corpus["development_sidecars"]):
        _relative_path(root, name, "corpus.sidecar")
    return config


def _extract_sidecar_public(sidecar_path: Path, target_id: str) -> PublicTargetView:
    sidecar = _read_json(sidecar_path)
    pool = _mapping(sidecar.get("pool"), "pool")
    public = _public_view(pool.get("public_view"))
    if (
        sidecar.get("target_id") != target_id
        or sidecar.get("public_view_sha256") != public.digest()
        or sidecar.get("labels_materialized") != 0
        or sidecar.get("target_key_inputs_to_probe") != 0
    ):
        raise O1C43RunError("public sidecar boundary differs")
    return public


def _extract_field(
    *,
    sensor: Path,
    template: Path,
    semantic_map: Path,
    public: PublicTargetView,
    workspace: Path,
    target_id: str,
    horizon: int,
    seed: int,
    capacity: int,
) -> tuple[ParentCriticalityField, str]:
    cnf = workspace / f"{target_id}.cnf"
    instance = write_full256_instance(
        template,
        semantic_map,
        cnf,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
        output=public.output_blocks[0],
    )
    if instance.key_unit_clause_count != 0 or instance.public_unit_clause_count != 640:
        raise O1C43RunError("public criticality CNF differs")
    originals = OriginalClauseTable.load(cnf)
    stream = iter_native_probe_records(
        executable=sensor,
        cnf_path=cnf,
        first_bit=0,
        last_bit=255,
        conflict_limit=horizon,
        seed=seed,
        timeout_seconds=120.0,
    )
    header, pairs = paired_records(iter(stream))
    if header.variables != 32_128 or header.original_clause_count != 188_010:
        raise O1C43RunError("native parent-criticality header differs")
    field = extract_parent_criticality_field(
        pairs,
        baseline_events=header.baseline_events,
        originals=originals,
        conflict_horizon=horizon,
        capacity=capacity,
    )
    return field, instance.instance_sha256


def _feature_panels(
    *,
    fields: Mapping[str, ParentCriticalityField],
    public: PublicTargetView,
    semantic_map: Path,
    keys: Sequence[bytes],
) -> tuple[object, dict[str, np.ndarray]]:
    plan = compile_full256_forward_read_plan(
        semantic_map, requested_parent_criticality_variables(fields.values())
    )
    panels = {
        name: np.empty((len(keys), len(FEATURE_NAMES)), dtype=np.float64)
        for name in fields
    }
    for index, key in enumerate(keys):
        assignment = plan.evaluate(
            key=key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        for name, field in fields.items():
            panels[name][index] = parent_criticality_features(field, assignment)
    return plan, panels


def _truth_rank(
    *,
    field: ParentCriticalityField,
    plan: object,
    mean: np.ndarray,
    std: np.ndarray,
    reader: np.ndarray,
    decoy_scores: np.ndarray,
    decoy_keys: Sequence[bytes],
    truth_key: bytes,
    public: PublicTargetView,
) -> tuple[dict[str, object], np.ndarray, np.ndarray]:
    assignment = plan.evaluate(
        key=truth_key,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
    )
    features = parent_criticality_features(field, assignment)
    standardized = _standardize_vector(features, mean, std)
    truth_score = float(np.dot(standardized, reader))
    rank = exact_candidate_rank(
        truth_score=truth_score,
        decoy_scores=decoy_scores,
        truth_key=truth_key,
        decoy_keys=decoy_keys,
    )
    return _rank_summary(rank), features, standardized


def _score_runtime(
    *,
    natural: ParentCriticalityField,
    public: PublicTargetView,
    semantic_map: Path,
    keys: Sequence[bytes],
    reader: np.ndarray,
) -> dict[str, object]:
    fields = {
        "primary": natural,
        "key_rotated": transform_parent_criticality_field(
            natural, rotate="key"
        ),
        "clause_rotated": transform_parent_criticality_field(
            natural, rotate="clause"
        ),
    }
    plan, raw_panels = _feature_panels(
        fields=fields, public=public, semantic_map=semantic_map, keys=keys
    )
    means: dict[str, np.ndarray] = {}
    stds: dict[str, np.ndarray] = {}
    scores: dict[str, np.ndarray] = {}
    for name, panel in raw_panels.items():
        standardized, mean, std = _standardize_panel(panel)
        means[name] = mean
        stds[name] = std
        scores[name] = np.asarray(standardized @ reader, dtype=np.float64)
    return {
        "fields": fields,
        "plan": plan,
        "means": means,
        "stds": stds,
        "scores": scores,
    }


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- DEVELOPMENT primary ranks: "
        f"`{metrics['development_primary_ranks']}`\n"
        f"- DEVELOPMENT geometric primary/control: "
        f"`{metrics['development_primary_geometric_rank_fraction']}` / "
        f"`{metrics['development_best_control_geometric_rank_fraction']}`\n"
        f"- Consumed O1C-0042 repeat rank: "
        f"`{metrics['consumed_repeat_primary_rank']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The 15-channel reader is fitted only from four consumed BUILD truths. "
        "DEVELOPMENT and the conditional O1C-0042 repeat use frozen weights.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    corpus = _mapping(config["corpus"], "corpus")
    field_config = _mapping(config["field"], "field")
    panel_config = _mapping(config["candidate_panel"], "candidate_panel")
    success = _mapping(config["success"], "success")
    budgets = _mapping(config["budgets"], "budgets")

    source_paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in (
            "template",
            "semantic_map",
            "sensor_source",
            "tracer_header",
            "parent_criticality_source",
            "runner",
            "o1c18_config",
            "o1c18_result",
            "development_labels",
            "o1c42_publication",
            "o1c42_reveal",
            "o1c42_result",
        )
    }
    template = source_paths["template"]
    semantic_map = source_paths["semantic_map"]
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    native_branches = candidate_evaluations = decoy_count = 0
    field_artifacts: dict[str, bytes] = {}
    score_artifacts: dict[str, bytes] = {}

    with tempfile.TemporaryDirectory(prefix="o1c43-") as temporary:
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

        build_runtime: list[dict[str, object]] = []
        for index, sidecar_raw in zip(
            corpus["build_indices"], corpus["build_sidecars"], strict=True
        ):
            target = make_deterministic_known_target(
                seed=int(corpus["seed"]), split="BUILD", index=int(index)
            )
            sidecar = _relative_path(root, sidecar_raw, "BUILD sidecar")
            source_paths[f"sidecar_{target.target_id}"] = sidecar
            public = _extract_sidecar_public(sidecar, target.target_id)
            if public.digest() != target.public.digest():
                raise O1C43RunError("reconstructed BUILD public target differs")
            natural, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=template,
                semantic_map=semantic_map,
                public=public,
                workspace=workspace,
                target_id=target.target_id,
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            native_branches += 512
            keys = _candidate_keys(
                str(panel_config["domain"]),
                public.digest(),
                int(panel_config["count_per_target"]),
            )
            plan, raw = _feature_panels(
                fields={"natural": natural},
                public=public,
                semantic_map=semantic_map,
                keys=keys,
            )
            standardized, mean, std = _standardize_panel(raw["natural"])
            assignment = plan.evaluate(
                key=target._key,
                counter=public.counter_schedule[0],
                nonce=public.nonce,
            )
            truth_features = parent_criticality_features(natural, assignment)
            truth_z = _standardize_vector(truth_features, mean, std)
            candidate_evaluations += len(keys) + 1
            decoy_count += len(keys)
            field_artifacts[f"fields/{target.target_id}.bin"] = natural.to_bytes()
            build_runtime.append(
                {
                    "target_id": target.target_id,
                    "public": public,
                    "truth_key": target._key,
                    "truth_key_sha256": target.key_sha256,
                    "instance_sha256": instance_sha,
                    "field": natural,
                    "keys": keys,
                    "standardized": standardized,
                    "truth_features": truth_features,
                    "truth_z": truth_z,
                    "feature_mean": mean,
                    "feature_std": std,
                }
            )

        raw_reader, reader = _fit_reader(
            [np.asarray(row["truth_z"]) for row in build_runtime]
        )
        build_rows: list[dict[str, object]] = []
        for row in build_runtime:
            standardized = np.asarray(row["standardized"])
            scores = np.asarray(standardized @ reader, dtype=np.float64)
            truth_score = float(np.dot(np.asarray(row["truth_z"]), reader))
            rank = _rank_summary(
                exact_candidate_rank(
                    truth_score=truth_score,
                    decoy_scores=scores,
                    truth_key=row["truth_key"],
                    decoy_keys=row["keys"],
                )
            )
            build_rows.append(
                {
                    "target_id": row["target_id"],
                    "public_view_sha256": row["public"].digest(),
                    "truth_key_sha256": row["truth_key_sha256"],
                    "instance_sha256": row["instance_sha256"],
                    "field": row["field"].describe(),
                    "candidate_keys_sha256": hashlib.sha256(
                        b"".join(row["keys"])
                    ).hexdigest(),
                    "feature_mean": np.asarray(row["feature_mean"]).tolist(),
                    "feature_std": np.asarray(row["feature_std"]).tolist(),
                    "truth_features": np.asarray(row["truth_features"]).tolist(),
                    "truth_standardized": np.asarray(row["truth_z"]).tolist(),
                    "decoy_score_sha256": array_sha256(scores, "<f8"),
                    "rank": rank,
                }
            )
        build_freeze = {
            "schema": "o1-256-parent-criticality-build-reader-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "feature_names": list(FEATURE_NAMES),
            "fit_rule": config["reader"]["fit_rule"],
            "raw_mean_truth_z": raw_reader.tolist(),
            "reader_l2": reader.tolist(),
            "reader_sha256": array_sha256(reader, "<f8"),
            "build_targets": build_rows,
        }
        build_freeze_bytes = _canonical_bytes(build_freeze)
        build_freeze_sha256 = hashlib.sha256(build_freeze_bytes).hexdigest()

        development_runtime: list[dict[str, object]] = []
        for label_index, (index, sidecar_raw) in enumerate(
            zip(
                corpus["development_indices"],
                corpus["development_sidecars"],
                strict=True,
            )
        ):
            target_id = f"development-{int(index):04d}"
            sidecar = _relative_path(root, sidecar_raw, "DEVELOPMENT sidecar")
            source_paths[f"sidecar_{target_id}"] = sidecar
            public = _extract_sidecar_public(sidecar, target_id)
            natural, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=template,
                semantic_map=semantic_map,
                public=public,
                workspace=workspace,
                target_id=target_id,
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            native_branches += 512
            keys = _candidate_keys(
                str(panel_config["domain"]),
                public.digest(),
                int(panel_config["count_per_target"]),
            )
            runtime = _score_runtime(
                natural=natural,
                public=public,
                semantic_map=semantic_map,
                keys=keys,
                reader=reader,
            )
            candidate_evaluations += len(keys)
            decoy_count += len(keys)
            field_artifacts[f"fields/{target_id}.bin"] = natural.to_bytes()
            for name, scores in runtime["scores"].items():
                score_artifacts[f"scores/{target_id}/{name}.f64le"] = (
                    np.ascontiguousarray(scores, dtype="<f8").tobytes(order="C")
                )
            prelabel = {
                "target_id": target_id,
                "public_view_sha256": public.digest(),
                "instance_sha256": instance_sha,
                "natural_field": natural.describe(),
                "candidate_keys_sha256": hashlib.sha256(b"".join(keys)).hexdigest(),
                "arms": {
                    name: {
                        "field": runtime["fields"][name].describe(),
                        "feature_mean": runtime["means"][name].tolist(),
                        "feature_std": runtime["stds"][name].tolist(),
                        "score_sha256": array_sha256(
                            runtime["scores"][name], "<f8"
                        ),
                    }
                    for name in config["controls"]["arms"]
                },
            }
            development_runtime.append(
                {
                    "target_id": target_id,
                    "label_index": label_index,
                    "public": public,
                    "instance_sha256": instance_sha,
                    "natural": natural,
                    "keys": keys,
                    "runtime": runtime,
                    "prelabel": prelabel,
                }
            )

        development_freeze = {
            "schema": "o1-256-parent-criticality-development-score-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "build_reader_freeze_sha256": build_freeze_sha256,
            "development_label_semantic_reads_before_freeze": 0,
            "reader_sha256": array_sha256(reader, "<f8"),
            "candidate_panel": config["candidate_panel"],
            "targets": [row["prelabel"] for row in development_runtime],
        }
        development_freeze_bytes = _canonical_bytes(development_freeze)
        development_freeze_sha256 = hashlib.sha256(
            development_freeze_bytes
        ).hexdigest()

        labels_payload = source_paths["development_labels"].read_bytes()
        labels = np.unpackbits(
            np.frombuffer(labels_payload, dtype=np.uint8), bitorder="little"
        )
        if labels.shape != (512,):
            raise O1C43RunError("DEVELOPMENT labels differ")
        labels = labels.reshape(2, 256)
        development_rows: list[dict[str, object]] = []
        for row in development_runtime:
            public = row["public"]
            truth_key = bits_to_key(labels[int(row["label_index"])])
            if not model_matches_public(truth_key, public):
                raise O1C43RunError("DEVELOPMENT truth does not verify")
            runtime = row["runtime"]
            ranks: dict[str, dict[str, object]] = {}
            truth_features: dict[str, list[float]] = {}
            truth_standardized: dict[str, list[float]] = {}
            for name in config["controls"]["arms"]:
                rank, features, standardized = _truth_rank(
                    field=runtime["fields"][name],
                    plan=runtime["plan"],
                    mean=runtime["means"][name],
                    std=runtime["stds"][name],
                    reader=reader,
                    decoy_scores=runtime["scores"][name],
                    decoy_keys=row["keys"],
                    truth_key=truth_key,
                    public=public,
                )
                ranks[name] = rank
                truth_features[name] = features.tolist()
                truth_standardized[name] = standardized.tolist()
            candidate_evaluations += 1
            development_rows.append(
                {
                    "target_id": row["target_id"],
                    "public_view_sha256": public.digest(),
                    "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                    "instance_sha256": row["instance_sha256"],
                    "truth_features": truth_features,
                    "truth_standardized": truth_standardized,
                    "rank": ranks,
                }
            )

        development_geometric = {
            name: _geometric(
                [float(row["rank"][name]["rank_fraction"]) for row in development_rows]
            )
            for name in config["controls"]["arms"]
        }
        primary_fractions = [
            float(row["rank"]["primary"]["rank_fraction"])
            for row in development_rows
        ]
        development_prediction, development_control = _classify_development(
            development_geometric,
            primary_fractions,
            maximum_geometric=float(
                success["maximum_development_geometric_rank_fraction"]
            ),
            maximum_each=float(success["maximum_each_development_rank_fraction"]),
        )
        development_pass = development_prediction and development_control

        repeat_freeze_bytes: bytes | None = None
        repeat_freeze_sha256: str | None = None
        repeat_row: dict[str, object] | None = None
        repeat_pass = False
        if development_pass:
            publication = _read_json(source_paths["o1c42_publication"])
            public = public_view_from_publication(publication)
            if publication.get("target_id") != corpus["consumed_repeat_target_id"]:
                raise O1C43RunError("consumed repeat publication differs")
            natural, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=template,
                semantic_map=semantic_map,
                public=public,
                workspace=workspace,
                target_id=str(corpus["consumed_repeat_target_id"]),
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            native_branches += 512
            keys = _candidate_keys(
                str(panel_config["domain"]),
                public.digest(),
                int(panel_config["count_per_target"]),
            )
            runtime = _score_runtime(
                natural=natural,
                public=public,
                semantic_map=semantic_map,
                keys=keys,
                reader=reader,
            )
            candidate_evaluations += len(keys)
            decoy_count += len(keys)
            field_artifacts[
                f"fields/{corpus['consumed_repeat_target_id']}.bin"
            ] = natural.to_bytes()
            for name, scores in runtime["scores"].items():
                score_artifacts[
                    f"scores/{corpus['consumed_repeat_target_id']}/{name}.f64le"
                ] = np.ascontiguousarray(scores, dtype="<f8").tobytes(order="C")
            repeat_freeze = {
                "schema": "o1-256-parent-criticality-consumed-repeat-freeze-v1",
                "attempt_id": ATTEMPT_ID,
                "target_id": corpus["consumed_repeat_target_id"],
                "development_score_freeze_sha256": development_freeze_sha256,
                "development_gate_pass": True,
                "consumed_reveal_semantic_reads_before_freeze": 0,
                "reader_sha256": array_sha256(reader, "<f8"),
                "public_view_sha256": public.digest(),
                "instance_sha256": instance_sha,
                "natural_field": natural.describe(),
                "candidate_keys_sha256": hashlib.sha256(b"".join(keys)).hexdigest(),
                "arms": {
                    name: {
                        "field": runtime["fields"][name].describe(),
                        "feature_mean": runtime["means"][name].tolist(),
                        "feature_std": runtime["stds"][name].tolist(),
                        "score_sha256": array_sha256(
                            runtime["scores"][name], "<f8"
                        ),
                    }
                    for name in config["controls"]["arms"]
                },
            }
            repeat_freeze_bytes = _canonical_bytes(repeat_freeze)
            repeat_freeze_sha256 = hashlib.sha256(repeat_freeze_bytes).hexdigest()
            reveal = verify_reveal(_read_json(source_paths["o1c42_reveal"]))
            preimage = _mapping(
                reveal.get("commitment_preimage"), "commitment_preimage"
            )
            try:
                truth_key = bytes.fromhex(str(preimage["key_hex"]))
            except ValueError as exc:
                raise O1C43RunError("consumed repeat key encoding differs") from exc
            if not model_matches_public(truth_key, public):
                raise O1C43RunError("consumed repeat key does not verify")
            ranks = {}
            truth_features = {}
            truth_standardized = {}
            for name in config["controls"]["arms"]:
                rank, features, standardized = _truth_rank(
                    field=runtime["fields"][name],
                    plan=runtime["plan"],
                    mean=runtime["means"][name],
                    std=runtime["stds"][name],
                    reader=reader,
                    decoy_scores=runtime["scores"][name],
                    decoy_keys=keys,
                    truth_key=truth_key,
                    public=public,
                )
                ranks[name] = rank
                truth_features[name] = features.tolist()
                truth_standardized[name] = standardized.tolist()
            candidate_evaluations += 1
            repeat_row = {
                "target_id": corpus["consumed_repeat_target_id"],
                "public_view_sha256": public.digest(),
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                "instance_sha256": instance_sha,
                "truth_features": truth_features,
                "truth_standardized": truth_standardized,
                "rank": ranks,
            }
            primary_repeat = float(ranks["primary"]["rank_fraction"])
            repeat_pass = bool(
                primary_repeat
                <= float(success["maximum_consumed_repeat_rank_fraction"])
                and primary_repeat
                < min(
                    float(ranks["key_rotated"]["rank_fraction"]),
                    float(ranks["clause_rotated"]["rank_fraction"]),
                )
            )

    if development_pass and repeat_pass:
        classification = "CONSUMED_PARENT_CRITICALITY_RANK_SIGNAL"
    elif development_pass:
        classification = "CONSUMED_PARENT_CRITICALITY_NOT_REPEATED"
    else:
        classification = "PARENT_CRITICALITY_RANK_NOT_CONCENTRATED"

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
        or native_branches > int(budgets["maximum_native_probe_branches"])
        or candidate_evaluations
        > int(budgets["maximum_candidate_forward_evaluations"])
        or decoy_count > int(budgets["maximum_decoy_keys"])
    ):
        raise O1C43RunError("O1C-0043 resource ledger exceeds budget")

    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "classification": classification,
        "claim_boundary": {
            "retrospective_build_targets": 4,
            "consumed_development_targets": 2,
            "conditional_consumed_repeat_targets": int(repeat_row is not None),
            "fresh_targets": 0,
            "all_256_key_bits_unknown_to_each_public_probe": True,
            "development_scores_frozen_before_label_read": True,
            "consumed_repeat_scores_frozen_before_reveal_parse": bool(
                repeat_row is not None
            ),
            "candidate_scores_attacker_computable": True,
            "original_functional_clauses_only": True,
            "public_unit_parents_excluded": True,
            "exact_key_recovery": False,
            "prospective_transfer_claim": False,
        },
        "build_reader_freeze_sha256": build_freeze_sha256,
        "development_score_freeze_sha256": development_freeze_sha256,
        "consumed_repeat_freeze_sha256": repeat_freeze_sha256,
        "reader": {
            "feature_names": list(FEATURE_NAMES),
            "raw_mean_truth_z": raw_reader.tolist(),
            "weights_l2": reader.tolist(),
            "weights_sha256": array_sha256(reader, "<f8"),
        },
        "build_targets": build_rows,
        "development_targets": development_rows,
        "consumed_repeat_target": repeat_row,
        "metrics": {
            "development_primary_ranks": [
                int(row["rank"]["primary"]["rank"])
                for row in development_rows
            ],
            "development_primary_rank_fractions": primary_fractions,
            "development_primary_geometric_rank_fraction": development_geometric[
                "primary"
            ],
            "development_key_rotated_geometric_rank_fraction": development_geometric[
                "key_rotated"
            ],
            "development_clause_rotated_geometric_rank_fraction": development_geometric[
                "clause_rotated"
            ],
            "development_best_control_geometric_rank_fraction": min(
                development_geometric["key_rotated"],
                development_geometric["clause_rotated"],
            ),
            "development_prediction_pass": development_prediction,
            "development_control_margin": development_control,
            "development_gate_pass": development_pass,
            "consumed_repeat_ran": repeat_row is not None,
            "consumed_repeat_primary_rank": (
                int(repeat_row["rank"]["primary"]["rank"])
                if repeat_row is not None
                else None
            ),
            "consumed_repeat_primary_rank_fraction": (
                float(repeat_row["rank"]["primary"]["rank_fraction"])
                if repeat_row is not None
                else None
            ),
            "consumed_repeat_pass": repeat_pass,
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
            "decoy_keys": decoy_count,
            "fresh_targets": 0,
            "solver_search_calls": 0,
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
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_parent-criticality-rank-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C43RunError("O1C-0043 capsule already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c43_parent_criticality_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "build_reader_freeze.json": build_freeze_bytes,
        "command.txt": command_bytes,
        "config.json": config_file.read_bytes(),
        "development_score_freeze.json": development_freeze_bytes,
        **field_artifacts,
        **score_artifacts,
    }
    if repeat_freeze_bytes is not None:
        members["consumed_repeat_score_freeze.json"] = repeat_freeze_bytes
    for relative, payload in members.items():
        destination = capsule / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
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
        if result["resources"]["persistent_artifact_bytes"] == persistent_bytes:
            break
        result["resources"]["persistent_artifact_bytes"] = persistent_bytes
    else:
        raise O1C43RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C43RunError("persistent artifact budget differs")
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
    "O1C43RunError",
    "_classify_development",
    "_fit_reader",
    "_standardize_panel",
    "load_config",
    "main",
    "run",
]
