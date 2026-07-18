"""O1C-0041 retrospective antecedent-chain complete-candidate rank run."""

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
from .proof_antecedent_relations import (
    AntecedentRelationField,
    OriginalClauseTable,
    extract_antecedent_relation_field,
    transform_antecedent_relation_field,
)
from .relation_candidate_rank import (
    array_sha256,
    exact_candidate_rank,
    raw_relation_weights,
    relation_match_vector,
    weighted_relation_scores,
)


ATTEMPT_ID = "O1C-0041"
CONFIG_SCHEMA = "o1-256-antecedent-chain-rank-config-v1"
RESULT_SCHEMA = "o1-256-antecedent-chain-rank-result-v1"
RESULT_RELATIVE = Path("research/O1C0041_ANTECEDENT_CHAIN_RANK_RESULT_20260718.json")
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)


class O1C41RunError(RuntimeError):
    """The frozen O1C-0041 source, selection, or work ledger differs."""


def _peak_rss_bytes() -> int:
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    if own <= 16 * 1024 * 1024:
        own *= 1024
    if children <= 16 * 1024 * 1024:
        children *= 1024
    return max(own, children)


def _geometric(values: Sequence[float]) -> float:
    if not values or any(not 0.0 < value <= 1.0 for value in values):
        raise O1C41RunError("rank-product inputs differ")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _candidate_keys(domain: str, public_digest: str, count: int) -> list[bytes]:
    seed = hashlib.sha256(
        domain.encode("ascii") + b"\0" + bytes.fromhex(public_digest)
    ).digest()
    keys = [
        hashlib.sha256(seed + index.to_bytes(8, "little")).digest()
        for index in range(count)
    ]
    if len(set(keys)) != count:
        raise O1C41RunError("candidate generator produced duplicates")
    return keys


def _select_orientations(
    build_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    signs = [int(row["natural_center_sign"]) for row in build_rows]
    if len(signs) != 4 or any(sign not in (-1, 1) for sign in signs):
        raise O1C41RunError("BUILD centered signs differ")
    strict = signs[0] if all(sign == signs[0] for sign in signs) else 0
    natural = _geometric(
        [float(_mapping(row["natural"], "natural")["rank_fraction"]) for row in build_rows]
    )
    reversed_rank = _geometric(
        [
            float(_mapping(row["reversed"], "reversed")["rank_fraction"])
            for row in build_rows
        ]
    )
    pooled = 1 if natural < reversed_rank else (-1 if reversed_rank < natural else 0)
    return {
        "strict_center_signs": signs,
        "strict_selection": strict,
        "natural_geometric_rank_fraction": natural,
        "reversed_geometric_rank_fraction": reversed_rank,
        "pooled_rank_product_selection": pooled,
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C41RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    corpus = _mapping(config.get("corpus"), "corpus")
    field = _mapping(config.get("field"), "field")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    orientation = _mapping(config.get("orientation"), "orientation")
    controls = _mapping(config.get("controls"), "controls")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "antecedent-chain-rank-v1"
        or config.get("claim_level") != "RETROSPECTIVE_DIAGNOSTIC"
        or corpus.get("seed") != 180018180018
        or corpus.get("build_split") != "BUILD"
        or corpus.get("build_indices") != [0, 1, 2, 3]
        or corpus.get("development_split") != "DEVELOPMENT"
        or corpus.get("development_indices") != [0, 1]
        or corpus.get("fresh_targets") != 0
        or not isinstance(corpus.get("build_sidecars"), list)
        or len(corpus["build_sidecars"]) != 4
        or not isinstance(corpus.get("development_sidecars"), list)
        or len(corpus["development_sidecars"]) != 2
        or field.get("conflict_horizon") != 16
        or field.get("seed") != 0
        or field.get("capacity") != 8192
        or field.get("unit_scale") != 1
        or panel.get("count_per_target") != 4096
        or panel.get("domain") != "O1C41-antecedent-chain-decoy-v1"
        or panel.get("duplicate_policy") != "reject"
        or orientation.get("strict_expected_selection") != 0
        or orientation.get("pooled_expected_selection") != -1
        or orientation.get("development_uses_only_pooled_build_selection") is not True
        or orientation.get("no_development_sign_selection") is not True
        or orientation.get("no_other_weight_or_calibration_arm") is not True
        or controls.get("arms") != ["primary", "key_rotated", "factor_rotated"]
        or success.get("maximum_each_development_rank_fraction") != 0.25
        or success.get("maximum_development_geometric_rank_fraction") != 0.10
        or budgets.get("maximum_wall_seconds") != 60
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 3072
        or budgets.get("maximum_candidate_forward_evaluations") != 24582
        or budgets.get("maximum_decoy_keys") != 24576
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 2097152
    ):
        raise O1C41RunError("frozen O1C-0041 config differs")
    source_names = (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "o1c18_config",
        "o1c18_result",
        "development_labels",
    )
    for name in source_names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        expected_hash = expected.get(name)
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise O1C41RunError("source hash freeze differs")
        # DEVELOPMENT labels stay byte-unread until the score freeze in run().
        if name != "development_labels" and sha256_file(resolved) != expected_hash:
            raise O1C41RunError(f"source hash differs for {name}")
    for name in (*corpus["build_sidecars"], *corpus["development_sidecars"]):
        _relative_path(root, name, "corpus.sidecar")
    return config


def _extract_field(
    *,
    sensor: Path,
    template: Path,
    semantic_map: Path,
    sidecar_path: Path,
    target_id: str,
    workspace: Path,
    horizon: int,
    seed: int,
    capacity: int,
) -> tuple[PublicTargetView, AntecedentRelationField, str]:
    sidecar = _read_json(sidecar_path)
    pool = _mapping(sidecar.get("pool"), "pool")
    public = _public_view(pool.get("public_view"))
    if (
        sidecar.get("target_id") != target_id
        or sidecar.get("public_view_sha256") != public.digest()
        or sidecar.get("labels_materialized") != 0
        or sidecar.get("target_key_inputs_to_probe") != 0
    ):
        raise O1C41RunError("public target boundary differs")
    cnf = workspace / f"{target_id}.cnf"
    instance = write_full256_instance(
        template,
        semantic_map,
        cnf,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
        output=public.output_blocks[0],
    )
    source_instance = _mapping(pool.get("instance"), "pool.instance")
    if (
        instance.instance_sha256 != source_instance.get("instance_sha256")
        or instance.key_unit_clause_count != 0
    ):
        raise O1C41RunError("public CNF instance differs")
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
        raise O1C41RunError("native probe header differs")
    field = extract_antecedent_relation_field(
        pairs,
        baseline_events=header.baseline_events,
        originals=originals,
        conflict_horizon=horizon,
        capacity=capacity,
    )
    return public, field, instance.instance_sha256


def _score_panel(
    *,
    fields: Mapping[str, AntecedentRelationField],
    public: PublicTargetView,
    semantic_map: Path,
    keys: Sequence[bytes],
) -> tuple[object, dict[str, np.ndarray], dict[str, np.ndarray]]:
    requested = sorted(
        {
            variable
            for field in fields.values()
            for edge in field.edges
            for variable in (edge.key_variable, edge.factor_variable)
        }
    )
    plan = compile_full256_forward_read_plan(semantic_map, requested)
    weights = {name: raw_relation_weights(field) for name, field in fields.items()}
    scores = {
        name: np.empty(len(keys), dtype=np.float64) for name in fields
    }
    for index, key in enumerate(keys):
        assignment = plan.evaluate(
            key=key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        for name, field in fields.items():
            scores[name][index] = weighted_relation_scores(
                relation_match_vector(field, assignment), weights[name]
            )
    return plan, scores, weights


def _truth_rank(
    *,
    field: AntecedentRelationField,
    plan: object,
    weights: np.ndarray,
    scores: np.ndarray,
    keys: Sequence[bytes],
    truth_key: bytes,
    public: PublicTargetView,
) -> dict[str, object]:
    assignment = plan.evaluate(
        key=truth_key,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
    )
    matches = relation_match_vector(field, assignment)
    truth_score = float(weighted_relation_scores(matches, weights))
    return {
        **exact_candidate_rank(
            truth_score=truth_score,
            decoy_scores=scores,
            truth_key=truth_key,
            decoy_keys=keys,
        ),
        "truth_correct_edges": int(np.count_nonzero(matches > 0)),
        "edge_count": len(field.edges),
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
            "truth_correct_edges",
            "edge_count",
        )
    }


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Strict BUILD selection: `{metrics['strict_build_selection']}`\n"
        f"- Pooled BUILD orientation: `{metrics['pooled_build_orientation']}`\n"
        f"- DEVELOPMENT primary ranks: `{metrics['development_primary_ranks']}`\n"
        f"- DEVELOPMENT geometric rank fraction: "
        f"`{metrics['development_primary_geometric_rank_fraction']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "This is a retrospective diagnostic on consumed targets. The pooled "
        "BUILD rule is eligible for exactly one unchanged fresh replication.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected_hashes = _mapping(source["expected_sha256"], "expected_sha256")
    corpus = _mapping(config["corpus"], "corpus")
    field_config = _mapping(config["field"], "field")
    panel = _mapping(config["candidate_panel"], "candidate_panel")
    orientation_config = _mapping(config["orientation"], "orientation")
    success = _mapping(config["success"], "success")
    budgets = _mapping(config["budgets"], "budgets")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    template = _relative_path(root, source["template"], "template")
    semantic_map = _relative_path(root, source["semantic_map"], "semantic_map")
    sensor_source = _relative_path(root, source["sensor_source"], "sensor_source")
    tracer_header = _relative_path(root, source["tracer_header"], "tracer_header")
    o1c18_config_path = _relative_path(root, source["o1c18_config"], "o1c18_config")
    o1c18_result_path = _relative_path(root, source["o1c18_result"], "o1c18_result")
    labels_path = _relative_path(
        root, source["development_labels"], "development_labels"
    )
    o1c18_config = _read_json(o1c18_config_path)
    o1c18_result = _read_json(o1c18_result_path)
    experiment = _mapping(o1c18_config.get("experiment"), "o1c18.experiment")
    if (
        experiment.get("corpus_seed") != corpus["seed"]
        or o1c18_result.get("classification") != "NO_RAW_SIGNAL_PICKER_UNINTERPRETABLE"
    ):
        raise O1C41RunError("O1C-0018 source boundary differs")
    build_source = o1c18_result.get("build")
    if not isinstance(build_source, list) or len(build_source) != 4:
        raise O1C41RunError("O1C-0018 BUILD inventory differs")
    build_hashes: dict[str, str] = {}
    for raw_row in build_source:
        build_row = _mapping(raw_row, "build row")
        build_target = _mapping(build_row.get("target"), "build target")
        build_hashes[str(build_target["target_id"])] = str(
            build_target["key_sha256"]
        )

    source_paths: dict[str, Path] = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "antecedent_field": root / "src/o1_crypto_lab/proof_antecedent_relations.py",
        "forward_evaluator": root / "src/o1_crypto_lab/full256_forward_assignment.py",
        "rank_module": root / "src/o1_crypto_lab/relation_candidate_rank.py",
        "template": template,
        "semantic_map": semantic_map,
        "sensor_source": sensor_source,
        "tracer_header": tracer_header,
        "o1c18_config": o1c18_config_path,
        "o1c18_result": o1c18_result_path,
    }
    native_probe_branches = candidate_evaluations = decoy_key_count = 0
    field_artifacts: dict[str, bytes] = {}

    with tempfile.TemporaryDirectory(prefix="o1c41-") as temporary:
        workspace = Path(temporary)
        sensor_build = build_native_sensor(
            source=sensor_source,
            tracer_header=tracer_header,
            cadical_include="/opt/homebrew/opt/cadical/include",
            cadical_library="/opt/homebrew/opt/cadical/lib/libcadical.a",
            output=workspace / "cadical-pair-sensor",
            expected_cadical_header_sha256=CADICAL_HEADER_SHA256,
            expected_cadical_library_sha256=CADICAL_LIBRARY_SHA256,
        )

        build_rows: list[dict[str, object]] = []
        for ordinal, (index, sidecar_raw) in enumerate(
            zip(
                corpus["build_indices"],
                corpus["build_sidecars"],
                strict=True,
            )
        ):
            target = make_deterministic_known_target(
                seed=int(corpus["seed"]), split="BUILD", index=int(index)
            )
            sidecar = _relative_path(root, sidecar_raw, "BUILD sidecar")
            source_paths[f"sidecar_{target.target_id}"] = sidecar
            public, natural_field, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=template,
                semantic_map=semantic_map,
                sidecar_path=sidecar,
                target_id=target.target_id,
                workspace=workspace,
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            native_probe_branches += 512
            if (
                target.public.digest() != public.digest()
                or target.key_sha256 != build_hashes.get(target.target_id)
            ):
                raise O1C41RunError("reconstructed BUILD target differs")
            arms = {
                "natural": transform_antecedent_relation_field(
                    natural_field, orientation=1
                ),
                "reversed": transform_antecedent_relation_field(
                    natural_field, orientation=-1
                ),
            }
            keys = _candidate_keys(
                str(panel["domain"]), public.digest(), int(panel["count_per_target"])
            )
            decoy_key_count += len(keys)
            plan, scores, weights = _score_panel(
                fields=arms, public=public, semantic_map=semantic_map, keys=keys
            )
            candidate_evaluations += len(keys) + 1
            natural_rank = _truth_rank(
                field=arms["natural"],
                plan=plan,
                weights=weights["natural"],
                scores=scores["natural"],
                keys=keys,
                truth_key=target._key,
                public=public,
            )
            reversed_rank = _truth_rank(
                field=arms["reversed"],
                plan=plan,
                weights=weights["reversed"],
                scores=scores["reversed"],
                keys=keys,
                truth_key=target._key,
                public=public,
            )
            centered = float(natural_rank["truth_score"]) - float(
                natural_rank["decoy_mean"]
            )
            if centered == 0.0:
                raise O1C41RunError("BUILD truth score equals decoy mean")
            field_bytes = natural_field.to_bytes()
            field_artifacts[f"fields/{target.target_id}.bin"] = field_bytes
            build_rows.append(
                {
                    "ordinal": ordinal,
                    "target_id": target.target_id,
                    "public_view_sha256": public.digest(),
                    "truth_key_sha256": target.key_sha256,
                    "instance_sha256": instance_sha,
                    "field": natural_field.describe(),
                    "candidate_keys_sha256": hashlib.sha256(b"".join(keys)).hexdigest(),
                    "natural_score_sha256": array_sha256(scores["natural"], "<f8"),
                    "reversed_score_sha256": array_sha256(scores["reversed"], "<f8"),
                    "natural_center_sign": 1 if centered > 0.0 else -1,
                    "natural": _rank_summary(natural_rank),
                    "reversed": _rank_summary(reversed_rank),
                }
            )

        orientation = _select_orientations(build_rows)
        if (
            orientation["strict_selection"]
            != orientation_config["strict_expected_selection"]
            or orientation["pooled_rank_product_selection"]
            != orientation_config["pooled_expected_selection"]
        ):
            raise O1C41RunError("BUILD orientation selection differs")
        pooled_orientation = int(orientation["pooled_rank_product_selection"])
        if pooled_orientation not in (-1, 1):
            raise O1C41RunError("pooled BUILD orientation did not select")
        build_freeze = {
            "schema": "o1-256-antecedent-chain-build-selection-v1",
            "attempt_id": ATTEMPT_ID,
            "claim_level": "RETROSPECTIVE_DIAGNOSTIC",
            "selection_rules": config["orientation"],
            "build_targets": build_rows,
            "selection": orientation,
        }
        build_freeze_bytes = (
            json.dumps(build_freeze, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
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
            public, natural_field, instance_sha = _extract_field(
                sensor=sensor_build.executable,
                template=template,
                semantic_map=semantic_map,
                sidecar_path=sidecar,
                target_id=target_id,
                workspace=workspace,
                horizon=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                capacity=int(field_config["capacity"]),
            )
            native_probe_branches += 512
            arms = {
                "primary": transform_antecedent_relation_field(
                    natural_field, orientation=pooled_orientation
                ),
                "key_rotated": transform_antecedent_relation_field(
                    natural_field, orientation=pooled_orientation, rotate="key"
                ),
                "factor_rotated": transform_antecedent_relation_field(
                    natural_field, orientation=pooled_orientation, rotate="factor"
                ),
            }
            keys = _candidate_keys(
                str(panel["domain"]), public.digest(), int(panel["count_per_target"])
            )
            decoy_key_count += len(keys)
            plan, scores, weights = _score_panel(
                fields=arms, public=public, semantic_map=semantic_map, keys=keys
            )
            candidate_evaluations += len(keys)
            field_bytes = natural_field.to_bytes()
            field_artifacts[f"fields/{target_id}.bin"] = field_bytes
            development_runtime.append(
                {
                    "target_id": target_id,
                    "label_index": label_index,
                    "public": public,
                    "instance_sha256": instance_sha,
                    "natural_field": natural_field,
                    "arms": arms,
                    "keys": keys,
                    "plan": plan,
                    "scores": scores,
                    "weights": weights,
                    "prelabel": {
                        "target_id": target_id,
                        "public_view_sha256": public.digest(),
                        "instance_sha256": instance_sha,
                        "natural_field": natural_field.describe(),
                        "selected_orientation": pooled_orientation,
                        "candidate_key_count": len(keys),
                        "candidate_keys_sha256": hashlib.sha256(
                            b"".join(keys)
                        ).hexdigest(),
                        "arms": {
                            name: {
                                "field": arm.describe(),
                                "score_sha256": array_sha256(scores[name], "<f8"),
                            }
                            for name, arm in arms.items()
                        },
                    },
                }
            )

        score_freeze = {
            "schema": "o1-256-antecedent-chain-development-score-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "development_label_reads_before_freeze": 0,
            "build_selection_sha256": build_freeze_sha256,
            "selected_orientation": pooled_orientation,
            "candidate_panel": config["candidate_panel"],
            "targets": [row["prelabel"] for row in development_runtime],
        }
        score_freeze_bytes = (
            json.dumps(score_freeze, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        score_freeze_sha256 = hashlib.sha256(score_freeze_bytes).hexdigest()

        labels_payload = labels_path.read_bytes()
        if (
            hashlib.sha256(labels_payload).hexdigest()
            != expected_hashes["development_labels"]
        ):
            raise O1C41RunError("DEVELOPMENT label hash differs")
        labels = np.unpackbits(
            np.frombuffer(labels_payload, dtype=np.uint8), bitorder="little"
        )
        if labels.shape != (512,):
            raise O1C41RunError("DEVELOPMENT label shape differs")
        labels = labels.reshape(2, 256)
        source_paths["development_labels"] = labels_path
        development_rows: list[dict[str, object]] = []
        for row in development_runtime:
            public = row["public"]
            if not isinstance(public, PublicTargetView):
                raise O1C41RunError("runtime public target differs")
            truth_key = bits_to_key(labels[int(row["label_index"])])
            if not model_matches_public(truth_key, public):
                raise O1C41RunError("revealed DEVELOPMENT key differs")
            candidate_evaluations += 1
            arms = row["arms"]
            scores = row["scores"]
            weights = row["weights"]
            if (
                not isinstance(arms, Mapping)
                or not isinstance(scores, Mapping)
                or not isinstance(weights, Mapping)
            ):
                raise O1C41RunError("runtime score state differs")
            ranked = {
                str(name): _rank_summary(
                    _truth_rank(
                        field=arm,
                        plan=row["plan"],
                        weights=weights[name],
                        scores=scores[name],
                        keys=row["keys"],
                        truth_key=truth_key,
                        public=public,
                    )
                )
                for name, arm in arms.items()
            }
            development_rows.append(
                {
                    "target_id": row["target_id"],
                    "public_view_sha256": public.digest(),
                    "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                    "instance_sha256": row["instance_sha256"],
                    "natural_field": row["natural_field"].describe(),
                    "selected_orientation": pooled_orientation,
                    "rank": ranked,
                }
            )

    development_geometric = {
        arm: _geometric(
            [
                float(_mapping(row["rank"], "rank")[arm]["rank_fraction"])
                for row in development_rows
            ]
        )
        for arm in ("primary", "key_rotated", "factor_rotated")
    }
    primary_fractions = [
        float(_mapping(row["rank"], "rank")["primary"]["rank_fraction"])
        for row in development_rows
    ]
    prediction_pass = bool(
        len(primary_fractions) == 2
        and all(
            fraction <= float(success["maximum_each_development_rank_fraction"])
            for fraction in primary_fractions
        )
        and development_geometric["primary"]
        <= float(success["maximum_development_geometric_rank_fraction"])
    )
    control_margin = bool(
        development_geometric["primary"]
        < min(
            development_geometric["key_rotated"],
            development_geometric["factor_rotated"],
        )
    )
    if prediction_pass and control_margin:
        classification = "RETROSPECTIVE_CHAIN_RANK_SIGNAL_WITH_CONTROL_MARGIN"
    elif prediction_pass:
        classification = "RETROSPECTIVE_CHAIN_RANK_SIGNAL"
    else:
        classification = "ANTECEDENT_CHAIN_RANK_NOT_CONCENTRATED"

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    if (
        native_probe_branches > int(budgets["maximum_native_probe_branches"])
        or candidate_evaluations
        > int(budgets["maximum_candidate_forward_evaluations"])
        or decoy_key_count > int(budgets["maximum_decoy_keys"])
        or elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C41RunError("O1C-0041 resource ledger exceeds budget")

    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "classification": classification,
        "claim_boundary": {
            "retrospective_consumed_targets": 6,
            "fresh_targets": 0,
            "strict_unanimity_rule_selected_nothing": True,
            "pooled_orientation_uses_build_truth_only": True,
            "development_orientation_frozen_before_label_read": True,
            "all_256_key_bits_unknown_to_each_public_probe": True,
            "candidate_scores_are_attacker_computable": True,
            "prospective_transfer_claim": False,
        },
        "build_selection_freeze_sha256": build_freeze_sha256,
        "development_score_freeze_sha256": score_freeze_sha256,
        "build_targets": build_rows,
        "build_selection": orientation,
        "development_targets": development_rows,
        "metrics": {
            "strict_build_selection": orientation["strict_selection"],
            "pooled_build_orientation": pooled_orientation,
            "build_natural_geometric_rank_fraction": orientation[
                "natural_geometric_rank_fraction"
            ],
            "build_reversed_geometric_rank_fraction": orientation[
                "reversed_geometric_rank_fraction"
            ],
            "development_primary_ranks": [
                int(_mapping(row["rank"], "rank")["primary"]["rank"])
                for row in development_rows
            ],
            "development_primary_rank_fractions": primary_fractions,
            "development_primary_geometric_rank_fraction": development_geometric[
                "primary"
            ],
            "development_key_rotated_geometric_rank_fraction": development_geometric[
                "key_rotated"
            ],
            "development_factor_rotated_geometric_rank_fraction": development_geometric[
                "factor_rotated"
            ],
            "prediction_pass": prediction_pass,
            "coordinate_control_margin": control_margin,
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
            "native_probe_branches": native_probe_branches,
            "candidate_forward_evaluations": candidate_evaluations,
            "decoy_keys": decoy_key_count,
            "fresh_targets": 0,
            "solver_search_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "native_build": sensor_build.describe(),
        "source_sha256": {name: sha256_file(path) for name, path in source_paths.items()},
        "next_action": config["next_action"],
    }

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_antecedent-chain-rank-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C41RunError("O1C-0041 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    config_bytes = config_file.read_bytes()
    run_bytes = _markdown(result).encode("utf-8")
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c41_antecedent_chain_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": run_bytes,
        "build_selection_freeze.json": build_freeze_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        "development_score_freeze.json": score_freeze_bytes,
        **field_artifacts,
    }
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
        raise O1C41RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C41RunError("persistent artifact budget differs")
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
    "O1C41RunError",
    "_candidate_keys",
    "_select_orientations",
    "load_config",
    "main",
    "run",
]
