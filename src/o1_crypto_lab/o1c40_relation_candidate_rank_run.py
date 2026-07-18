"""O1C-0040 complete-candidate rank diagnostic for O1C-0039 relations."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

import numpy as np

from .cadical_sensor import sha256_file
from .full256_forward_assignment import compile_full256_forward_read_plan
from .living_inverse import PublicTargetView, bits_to_key
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _public_view,
    _read_json,
    _relative_path,
    lab_root,
)
from .proof_clause_relations import ClauseRelationField, coordinate_control_field
from .relation_candidate_rank import (
    array_sha256,
    exact_candidate_rank,
    integer_score_histogram,
    raw_relation_weights,
    relation_match_vector,
    surprise_log_odds_weights,
    weighted_relation_scores,
)


ATTEMPT_ID = "O1C-0040"
CONFIG_SCHEMA = "o1-256-relation-candidate-rank-config-v1"
RESULT_SCHEMA = "o1-256-relation-candidate-rank-result-v1"
RESULT_RELATIVE = Path("research/O1C0040_RELATION_CANDIDATE_RANK_RESULT_20260718.json")


class O1C40RunError(RuntimeError):
    """The frozen O1C-0040 plan, source, or work ledger differs."""


def _peak_rss_bytes() -> int:
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if own <= 16 * 1024 * 1024:
        own *= 1024
    return own


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C40RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    scorers = _mapping(config.get("scorers"), "scorers")
    budgets = _mapping(config.get("budgets"), "budgets")
    targets = config.get("targets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "relation-candidate-rank-v1"
        or config.get("claim_level") != "POST_REVEAL_DIAGNOSTIC"
        or not isinstance(targets, list)
        or len(targets) != 2
        or [dict(_mapping(row, "target")).get("target_id") for row in targets]
        != ["development-0000", "development-0001"]
        or [dict(_mapping(row, "target")).get("label_index") for row in targets]
        != [0, 1]
        or panel.get("count_per_target") != 4096
        or panel.get("domain") != "O1C40-decoy-v1"
        or panel.get("duplicate_policy") != "reject"
        or panel.get("truth_collision_policy") != "report_without_replacement"
        or scorers.get("arms") != ["primary", "key_rotated", "factor_rotated"]
        or scorers.get("methods") != ["raw_abs_units", "surprise_log_odds_v1"]
        or scorers.get("build_reliability_correct") != 595
        or scorers.get("build_reliability_total") != 1045
        or scorers.get("surprise_prior") != 0.5
        or scorers.get("success_rank_fraction") != 0.25
        or scorers.get("no_other_score_or_calibration_arm") is not True
        or budgets.get("maximum_wall_seconds") != 30
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_candidate_forward_evaluations") != 8194
        or budgets.get("maximum_decoy_keys") != 8192
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_solver_calls") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 1048576
    ):
        raise O1C40RunError("frozen O1C-0040 config differs")
    for name in ("semantic_map", "labels", "o1c39_result"):
        _relative_path(root, source.get(name), f"source.{name}")
    for raw in targets:
        target = _mapping(raw, "target")
        _relative_path(root, target.get("sidecar"), "target.sidecar")
        field_path = _relative_path(root, target.get("field"), "target.field")
        if sha256_file(field_path) != target.get("field_sha256"):
            raise O1C40RunError("frozen relation field hash differs")
    return config


def _candidate_keys(domain: str, public_digest: str, count: int) -> list[bytes]:
    seed = hashlib.sha256(
        domain.encode("ascii") + b"\0" + bytes.fromhex(public_digest)
    ).digest()
    keys = [
        hashlib.sha256(seed + index.to_bytes(8, "little")).digest()
        for index in range(count)
    ]
    if len(set(keys)) != count:
        raise O1C40RunError("candidate generator produced duplicates")
    return keys


def _geometric(values: list[float]) -> float:
    if not values or any(not 0.0 < value <= 1.0 for value in values):
        raise O1C40RunError("rank fraction differs")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Raw primary geometric rank fraction: "
        f"`{metrics['raw_primary_geometric_rank_fraction']}`\n"
        f"- Surprise primary geometric rank fraction: "
        f"`{metrics['surprise_primary_geometric_rank_fraction']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "This is a post-reveal diagnostic over consumed DEVELOPMENT targets. "
        "Every decoy score is attacker-computable; no recovery claim follows.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    panel = _mapping(config["candidate_panel"], "candidate_panel")
    scorer_config = _mapping(config["scorers"], "scorers")
    budgets = _mapping(config["budgets"], "budgets")
    target_configs = config["targets"]
    if not isinstance(target_configs, list):
        raise O1C40RunError("target inventory differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    semantic_map = _relative_path(root, source["semantic_map"], "semantic_map")
    labels_path = _relative_path(root, source["labels"], "labels")
    o1c39_result_path = _relative_path(root, source["o1c39_result"], "o1c39_result")
    o1c39 = _read_json(o1c39_result_path)
    if o1c39.get("classification") != "RELATION_TRANSFER_ONLY":
        raise O1C40RunError("O1C-0039 prerequisite differs")

    source_paths: dict[str, Path] = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "forward_evaluator": root / "src/o1_crypto_lab/full256_forward_assignment.py",
        "rank_module": root / "src/o1_crypto_lab/relation_candidate_rank.py",
        "relation_module": root / "src/o1_crypto_lab/proof_clause_relations.py",
        "semantic_map": semantic_map,
        "labels": labels_path,
        "o1c39_result": o1c39_result_path,
    }
    runtime: list[dict[str, object]] = []
    candidate_evaluations = decoy_key_count = 0

    # All candidate keys, forward assignments, decoy matrices, weights and score
    # vectors are computed and committed before the consumed truth keys are read.
    for raw_target in target_configs:
        target = _mapping(raw_target, "target")
        target_id = str(target["target_id"])
        sidecar_path = _relative_path(root, target["sidecar"], "sidecar")
        field_path = _relative_path(root, target["field"], "field")
        source_paths[f"sidecar_{target_id}"] = sidecar_path
        source_paths[f"field_{target_id}"] = field_path
        sidecar = _read_json(sidecar_path)
        pool = _mapping(sidecar.get("pool"), "pool")
        public = _public_view(pool.get("public_view"))
        field = ClauseRelationField.from_bytes(field_path.read_bytes())
        if (
            len(field.edges) != int(target["expected_edge_count"])
            or field.state_sha256 != target["field_sha256"]
        ):
            raise O1C40RunError("relation field identity differs")
        arms = {
            "primary": field,
            "key_rotated": coordinate_control_field(field, rotate="key"),
            "factor_rotated": coordinate_control_field(field, rotate="factor"),
        }
        requested = sorted(
            {
                variable
                for arm in arms.values()
                for edge in arm.edges
                for variable in (edge.key_variable, edge.factor_variable)
            }
        )
        plan = compile_full256_forward_read_plan(semantic_map, requested)
        keys = _candidate_keys(
            str(panel["domain"]), public.digest(), int(panel["count_per_target"])
        )
        decoy_key_count += len(keys)
        matrices = {
            name: np.empty((len(keys), len(arm.edges)), dtype=np.int8)
            for name, arm in arms.items()
        }
        for index, key in enumerate(keys):
            assignment = plan.evaluate(
                key=key,
                counter=public.counter_schedule[0],
                nonce=public.nonce,
            )
            candidate_evaluations += 1
            for name, arm in arms.items():
                matrices[name][index] = relation_match_vector(arm, assignment)
        score_data: dict[str, dict[str, object]] = {}
        for name, arm in arms.items():
            raw_weights = raw_relation_weights(arm)
            surprise_weights = surprise_log_odds_weights(
                matrices[name],
                build_correct=int(scorer_config["build_reliability_correct"]),
                build_total=int(scorer_config["build_reliability_total"]),
                prior=float(scorer_config["surprise_prior"]),
            )
            raw_scores = weighted_relation_scores(matrices[name], raw_weights)
            surprise_scores = weighted_relation_scores(matrices[name], surprise_weights)
            score_data[name] = {
                "matrix": matrices[name],
                "raw_weights": raw_weights,
                "surprise_weights": surprise_weights,
                "raw_scores": raw_scores,
                "surprise_scores": surprise_scores,
            }
        key_bytes = b"".join(keys)
        runtime.append(
            {
                "target_id": target_id,
                "label_index": int(target["label_index"]),
                "expected_truth_correct": int(target["expected_truth_correct"]),
                "public": public,
                "field": field,
                "arms": arms,
                "plan": plan,
                "keys": keys,
                "score_data": score_data,
                "prelabel": {
                    "target_id": target_id,
                    "public_view_sha256": public.digest(),
                    "field_state_sha256": field.state_sha256,
                    "candidate_key_count": len(keys),
                    "candidate_keys_sha256": hashlib.sha256(key_bytes).hexdigest(),
                    "arms": {
                        name: {
                            "match_matrix_sha256": array_sha256(data["matrix"], "|i1"),
                            "raw_score_sha256": array_sha256(data["raw_scores"], "<f8"),
                            "surprise_score_sha256": array_sha256(
                                data["surprise_scores"], "<f8"
                            ),
                            "surprise_weight_sha256": array_sha256(
                                data["surprise_weights"], "<f8"
                            ),
                        }
                        for name, data in score_data.items()
                    },
                },
            }
        )

    score_freeze = {
        "schema": "o1-256-relation-candidate-score-freeze-v1",
        "attempt_id": ATTEMPT_ID,
        "label_reads_before_freeze": 0,
        "candidate_generator": panel,
        "scorers": scorer_config,
        "targets": [row["prelabel"] for row in runtime],
    }
    freeze_bytes = (
        json.dumps(score_freeze, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    freeze_sha256 = hashlib.sha256(freeze_bytes).hexdigest()

    labels_raw = labels_path.read_bytes()
    labels = np.unpackbits(np.frombuffer(labels_raw, dtype=np.uint8), bitorder="little")
    if labels.shape != (512,):
        raise O1C40RunError("consumed label artifact shape differs")
    labels = labels.reshape(2, 256)
    targets: list[dict[str, object]] = []
    truth_collisions = 0
    for row in runtime:
        public = row["public"]
        plan = row["plan"]
        if not isinstance(public, PublicTargetView):
            raise O1C40RunError("runtime public target differs")
        truth_key = bits_to_key(labels[int(row["label_index"])])
        keys = row["keys"]
        if not isinstance(keys, list):
            raise O1C40RunError("runtime candidate keys differ")
        truth_collisions += sum(key == truth_key for key in keys)
        truth_assignment = plan.evaluate(
            key=truth_key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        candidate_evaluations += 1
        scored_arms: dict[str, object] = {}
        arms = row["arms"]
        score_data = row["score_data"]
        if not isinstance(arms, Mapping) or not isinstance(score_data, Mapping):
            raise O1C40RunError("runtime score arms differ")
        for name, arm in arms.items():
            if not isinstance(arm, ClauseRelationField):
                raise O1C40RunError("runtime relation arm differs")
            data = _mapping(score_data[name], "score data")
            truth_matches = relation_match_vector(arm, truth_assignment)
            raw_truth = float(
                weighted_relation_scores(truth_matches, data["raw_weights"])
            )
            surprise_truth = float(
                weighted_relation_scores(truth_matches, data["surprise_weights"])
            )
            if name == "primary":
                correct = int(np.count_nonzero(truth_matches > 0))
                if correct != int(row["expected_truth_correct"]):
                    raise O1C40RunError("truth relation score differs from O1C-0039")
            scored_arms[str(name)] = {
                "edge_count": len(arm.edges),
                "truth_correct_edges": int(np.count_nonzero(truth_matches > 0)),
                "raw_abs_units": {
                    **exact_candidate_rank(
                        truth_score=raw_truth,
                        decoy_scores=data["raw_scores"],
                        truth_key=truth_key,
                        decoy_keys=keys,
                    ),
                    "decoy_histogram": integer_score_histogram(data["raw_scores"]),
                },
                "surprise_log_odds_v1": {
                    **exact_candidate_rank(
                        truth_score=surprise_truth,
                        decoy_scores=data["surprise_scores"],
                        truth_key=truth_key,
                        decoy_keys=keys,
                    ),
                    "mean_abs_weight": float(np.mean(np.abs(data["surprise_weights"]))),
                },
            }
        targets.append(
            {
                "target_id": row["target_id"],
                "public_view_sha256": public.digest(),
                "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                "candidate_truth_collisions": sum(key == truth_key for key in keys),
                "arms": scored_arms,
            }
        )

    geometric: dict[str, dict[str, float]] = {}
    for method in scorer_config["methods"]:
        geometric[str(method)] = {
            str(arm): _geometric(
                [
                    float(
                        _mapping(_mapping(target["arms"], "target arms")[arm], "arm")[
                            method
                        ]["rank_fraction"]
                    )
                    for target in targets
                ]
            )
            for arm in scorer_config["arms"]
        }
    threshold = float(scorer_config["success_rank_fraction"])
    method_pass: dict[str, bool] = {}
    for method in scorer_config["methods"]:
        values = geometric[str(method)]
        every_target = all(
            float(
                _mapping(_mapping(target["arms"], "target arms")["primary"], "arm")[
                    method
                ]["rank_fraction"]
            )
            <= threshold
            for target in targets
        )
        method_pass[str(method)] = bool(
            every_target
            and values["primary"] < min(values["key_rotated"], values["factor_rotated"])
        )
    rank_transfer = any(method_pass.values())
    classification = (
        "COMPLETE_CANDIDATE_RANK_TRANSFER"
        if rank_transfer
        else "CLAUSE_RELATION_CANDIDATE_OBJECTIVE_NULL"
    )

    elapsed = time.perf_counter() - started
    peak_rss = _peak_rss_bytes()
    if (
        candidate_evaluations > int(budgets["maximum_candidate_forward_evaluations"])
        or decoy_key_count > int(budgets["maximum_decoy_keys"])
        or elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C40RunError("O1C-0040 work or resource ledger exceeds budget")
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "classification": classification,
        "claim_boundary": {
            "post_reveal_consumed_diagnostic": True,
            "all_decoy_scores_attacker_computable": True,
            "target_labels_read_after_score_freeze": True,
            "fresh_targets": 0,
            "recovered_key_bits_claimed": 0,
        },
        "score_freeze_sha256": freeze_sha256,
        "targets": targets,
        "metrics": {
            "candidate_rank_transfer": rank_transfer,
            "method_pass": method_pass,
            "raw_primary_geometric_rank_fraction": geometric["raw_abs_units"][
                "primary"
            ],
            "raw_key_rotated_geometric_rank_fraction": geometric["raw_abs_units"][
                "key_rotated"
            ],
            "raw_factor_rotated_geometric_rank_fraction": geometric["raw_abs_units"][
                "factor_rotated"
            ],
            "surprise_primary_geometric_rank_fraction": geometric[
                "surprise_log_odds_v1"
            ]["primary"],
            "surprise_key_rotated_geometric_rank_fraction": geometric[
                "surprise_log_odds_v1"
            ]["key_rotated"],
            "surprise_factor_rotated_geometric_rank_fraction": geometric[
                "surprise_log_odds_v1"
            ]["factor_rotated"],
            "truth_collisions_in_decoys": truth_collisions,
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "cpu_seconds": time.process_time() - cpu_started,
            "peak_rss_bytes": peak_rss,
            "candidate_forward_evaluations": candidate_evaluations,
            "decoy_keys": decoy_key_count,
            "solver_calls": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
            "persistent_artifact_bytes": 0,
        },
        "source_sha256": {
            name: sha256_file(path) for name, path in source_paths.items()
        },
        "next_action": config["next_action"],
    }

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_relation-candidate-rank-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C40RunError("O1C-0040 capsule path exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    config_bytes = config_file.read_bytes()
    run_bytes = _markdown(result).encode("utf-8")
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c40_relation_candidate_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    (capsule / "config.json").write_bytes(config_bytes)
    (capsule / "score_freeze.json").write_bytes(freeze_bytes)
    (capsule / "RUN.md").write_bytes(run_bytes)
    (capsule / "command.txt").write_bytes(command_bytes)
    members: dict[str, bytes] = {
        "RUN.md": run_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        "score_freeze.json": freeze_bytes,
    }
    for _ in range(8):
        result_bytes = _atomic_json(capsule / "result.json", result)
        members["result.json"] = result_bytes
        manifest = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(members.items())
        ).encode("ascii")
        persistent = sum(len(payload) for payload in members.values()) + len(manifest)
        if result["resources"]["persistent_artifact_bytes"] == persistent:
            break
        result["resources"]["persistent_artifact_bytes"] = persistent
    else:
        raise O1C40RunError("persistent byte ledger did not converge")
    if persistent > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C40RunError("persistent artifact budget differs")
    (capsule / "artifacts.sha256").write_bytes(manifest)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        path.chmod(0o444 if path.is_file() else 0o555)
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


__all__ = ["ATTEMPT_ID", "O1C40RunError", "load_config", "main", "run"]
