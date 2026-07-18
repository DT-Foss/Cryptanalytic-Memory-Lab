"""O1C-0038 corrected exact residual-width completion ceiling."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

import numpy as np

from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import bits_to_key
from .o1_relational_search import (
    build_native_guided_search,
    model_hamming_distance,
    model_matches_public,
    repair_radius_scores,
    run_guided_search,
    sha256_file,
    write_hint_scores,
)
from .o1c37_relational_guided_search_run import (
    PREDICTION_ARMS,
    _atomic_json,
    _git_commit,
    _mapping,
    _peak_rss_bytes,
    _public_view,
    _read_json,
    _relative_path,
    lab_root,
)


ATTEMPT_ID = "O1C-0038"
CONFIG_SCHEMA = "o1-256-exact-residual-completion-config-v1"
RESULT_SCHEMA = "o1-256-exact-residual-completion-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0038_EXACT_RESIDUAL_COMPLETION_RESULT_20260718.json"
)


class O1C38RunError(RuntimeError):
    """The frozen O1C-0038 ceiling contract or result differs."""


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C38RunError("config escapes the lab")
    config = _read_json(config_path)
    target = _mapping(config.get("target"), "target")
    relation = _mapping(config.get("exact_relation"), "exact_relation")
    sweep = _mapping(config.get("sweep"), "sweep")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "exact-residual-completion-v1"
        or config.get("claim_level") != "POST_REVEAL_CEILING"
        or target.get("target_id") != "build-0000"
        or target.get("width_index") != 3
        or target.get("o1_arm_index") != 2
        or sweep.get("base_conflict_limit") != 512
        or sweep.get("residual_bits_at_base") != [0, 1, 2, 4, 8, 9, 16]
        or sweep.get("residual_nine_extra_conflict_limits") != [2048, 8192, 32768]
        or sweep.get("expected_recovered_at_base") != [0, 1, 2, 4, 8]
        or sweep.get("expected_unresolved_at_base") != [9, 16]
        or budgets.get("maximum_wall_seconds") != 120
        or budgets.get("maximum_native_solver_calls") != 10
        or budgets.get("maximum_conflicts") != 46592
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
    ):
        raise O1C38RunError("frozen O1C-0038 config differs")
    _relative_path(root, config.get("source_o1c37_result"), "source_o1c37_result")
    for field in (
        "source_pool_sidecar",
        "source_result",
        "labels",
        "fold_predictions",
        "fold_prediction_freeze",
    ):
        _relative_path(root, target.get(field), f"target.{field}")
    for field in ("template", "semantic_map", "native_source"):
        _relative_path(root, relation.get(field), f"exact_relation.{field}")
    return config


def _confidence_order(scores: np.ndarray) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not bool(np.isfinite(values).all()):
        raise O1C38RunError("confidence field differs")
    return np.lexsort((np.arange(256), -np.abs(values)))


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Status: `completed`\n"
        f"- Started: `{result['started_at']}`\n"
        f"- Ended: `{result['recorded_at']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Exact residual frontier at 512 conflicts: "
        f"`{metrics['maximum_recovered_residual_bits_at_512']}` bits\n"
        f"- Residual 9 recovered by 32,768 conflicts: "
        f"`{metrics['residual_nine_recovered_by_32768']}`\n"
        f"- Decision: `{result['decision']}`\n\n"
        "This is a post-reveal mechanism ceiling. Every supplied prefix bit is "
        "oracle-correct; no attacker-valid key bits are claimed.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    target_config = _mapping(config["target"], "target")
    relation = _mapping(config["exact_relation"], "exact_relation")
    sweep = _mapping(config["sweep"], "sweep")
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()

    prior_path = _relative_path(
        root, config["source_o1c37_result"], "source_o1c37_result"
    )
    prior = _read_json(prior_path)
    prior_metrics = _mapping(prior.get("metrics"), "O1C-0037 metrics")
    if (
        prior.get("attempt_id") != "O1C-0037"
        or prior.get("decision") != "CLOSE_KEY_ONLY_FIRST_ENCOUNTER_CDCL_GUIDANCE"
        or prior_metrics.get("oracle_exact_guidance_recovered") is not True
        or prior_metrics.get("one_error_recovered_by_32768_conflicts") is not False
    ):
        raise O1C38RunError("O1C-0037 source result differs")

    pool_path = _relative_path(
        root, target_config["source_pool_sidecar"], "source_pool_sidecar"
    )
    source_result_path = _relative_path(
        root, target_config["source_result"], "source_result"
    )
    labels_path = _relative_path(root, target_config["labels"], "labels")
    predictions_path = _relative_path(
        root, target_config["fold_predictions"], "fold_predictions"
    )
    freeze_path = _relative_path(
        root, target_config["fold_prediction_freeze"], "fold_prediction_freeze"
    )
    template = _relative_path(root, relation["template"], "template")
    semantic_map = _relative_path(root, relation["semantic_map"], "semantic_map")
    native_source = _relative_path(root, relation["native_source"], "native_source")

    sidecar = _read_json(pool_path)
    pool = _mapping(sidecar.get("pool"), "pool")
    public = _public_view(pool.get("public_view"))
    if (
        sidecar.get("target_id") != "build-0000"
        or sidecar.get("public_view_sha256") != public.digest()
        or sidecar.get("labels_materialized") != 0
        or sidecar.get("target_key_inputs_to_probe") != 0
    ):
        raise O1C38RunError("public target boundary differs")

    labels = np.unpackbits(
        np.frombuffer(labels_path.read_bytes(), dtype=np.uint8), bitorder="little"
    )
    if labels.shape != (4 * 256,):
        raise O1C38RunError("label artifact shape differs")
    truth_bits = labels.reshape(4, 256)[0]
    truth_key = bits_to_key(truth_bits)
    source_result = _read_json(source_result_path)
    build_rows = source_result.get("build")
    if not isinstance(build_rows, list) or len(build_rows) != 4:
        raise O1C38RunError("source BUILD result differs")
    target_row = _mapping(
        _mapping(build_rows[0], "build[0]").get("target"), "build[0].target"
    )
    if (
        target_row.get("target_id") != "build-0000"
        or target_row.get("public_view_sha256") != public.digest()
        or target_row.get("key_sha256") != hashlib.sha256(truth_key).hexdigest()
    ):
        raise O1C38RunError("post-reveal key does not match public target")

    freeze = _read_json(freeze_path)
    if (
        freeze.get("held_out_target_id") != "build-0000"
        or freeze.get("held_out_label_used_for_this_fold") is not False
        or freeze.get("active_coordinate_counts") != [12, 52, 128, 256]
        or freeze.get("prediction_arms") != list(PREDICTION_ARMS)
    ):
        raise O1C38RunError("prediction freeze differs")
    predictions = np.fromfile(predictions_path, dtype="<f8")
    if predictions.size != 4 * len(PREDICTION_ARMS) * 256:
        raise O1C38RunError("prediction tensor shape differs")
    o1_scores = predictions.reshape(4, len(PREDICTION_ARMS), 256)[3, 2]
    exact_scores = repair_radius_scores(o1_scores, truth_bits, wrong_count=0)
    order = _confidence_order(exact_scores)
    signs = exact_scores >= 0.0
    if not bool(np.array_equal(signs, truth_bits)):
        raise O1C38RunError("oracle prefix contains an incorrect sign")

    source_paths = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "adapter": root / "src/o1_crypto_lab/o1_relational_search.py",
        "o1c37_runtime": root
        / "src/o1_crypto_lab/o1c37_relational_guided_search_run.py",
        "native": native_source,
        "prior_result": prior_path,
        "template": template,
        "semantic_map": semantic_map,
        "pool_sidecar": pool_path,
        "source_result": source_result_path,
        "labels": labels_path,
        "predictions": predictions_path,
        "prediction_freeze": freeze_path,
    }
    source_hashes = {name: sha256_file(path) for name, path in source_paths.items()}

    rows: list[dict[str, object]] = []
    requested_conflicts = 0
    with tempfile.TemporaryDirectory(prefix="o1c38-") as temporary:
        workspace = Path(temporary)
        executable = workspace / "cadical-o1-guided-search"
        build = build_native_guided_search(source=native_source, output=executable)
        cnf = workspace / "build-0000.cnf"
        instance = write_full256_instance(
            template,
            semantic_map,
            cnf,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
        )
        verification = verify_full256_instance(cnf, template, semantic_map, instance)
        source_instance = _mapping(pool.get("instance"), "pool.instance")
        if (
            instance.instance_sha256 != source_instance.get("instance_sha256")
            or instance.key_unit_clause_count != 0
            or verification.get("ok") is not True
        ):
            raise O1C38RunError("exact public CNF differs")
        hints = workspace / "oracle-exact.hints"
        hint_sha = write_hint_scores(hints, exact_scores)

        def execute(residual_bits: int, conflict_limit: int) -> None:
            nonlocal requested_conflicts
            guided_bits = 256 - residual_bits
            selected_correct = int(
                np.count_nonzero(
                    signs[order[:guided_bits]] == truth_bits[order[:guided_bits]]
                )
            )
            if selected_correct != guided_bits:
                raise O1C38RunError("exact prefix selection contains a wrong bit")
            search = run_guided_search(
                executable=executable,
                cnf_path=cnf,
                mode="guided",
                conflict_limit=conflict_limit,
                guided_bits=guided_bits,
                seed=0,
                hint_path=hints,
                timeout_seconds=60.0,
            )
            requested_conflicts += conflict_limit
            verified = bool(
                search.key_model is not None
                and model_matches_public(search.key_model, public)
            )
            rows.append(
                {
                    "name": f"oracle_exact_residual_{residual_bits:03d}_c{conflict_limit:05d}",
                    "privileged_post_reveal_ceiling": True,
                    "guided_bits": guided_bits,
                    "guided_correct_bits": selected_correct,
                    "residual_bits": residual_bits,
                    "conflict_limit": conflict_limit,
                    "hint_sha256": hint_sha,
                    "status": search.status_name,
                    "model_publicly_verified": verified,
                    "model_truth_hamming": (
                        None
                        if search.key_model is None
                        else model_hamming_distance(search.key_model, truth_key)
                    ),
                    "stats": dict(search.stats),
                    "guided": dict(search.guided),
                    "resources": dict(search.resources),
                }
            )

        base_limit = int(sweep["base_conflict_limit"])
        for residual in sweep["residual_bits_at_base"]:
            execute(int(residual), base_limit)
        for conflict_limit in sweep["residual_nine_extra_conflict_limits"]:
            execute(9, int(conflict_limit))

    if len(rows) != int(budgets["maximum_native_solver_calls"]):
        raise O1C38RunError("native solver-call count differs")
    if requested_conflicts != int(budgets["maximum_conflicts"]):
        raise O1C38RunError("conflict ledger differs")
    base_rows = {
        int(row["residual_bits"]): row
        for row in rows
        if int(row["conflict_limit"]) == int(sweep["base_conflict_limit"])
    }
    recovered_at_base = sorted(
        residual
        for residual, row in base_rows.items()
        if bool(row["model_publicly_verified"])
    )
    unresolved_at_base = sorted(
        residual
        for residual, row in base_rows.items()
        if not bool(row["model_publicly_verified"])
    )
    residual_nine_rows = [row for row in rows if int(row["residual_bits"]) == 9]
    residual_nine_recovered = any(
        bool(row["model_publicly_verified"]) for row in residual_nine_rows
    )
    expected_recovered = list(sweep["expected_recovered_at_base"])
    expected_unresolved = list(sweep["expected_unresolved_at_base"])
    elapsed = time.perf_counter() - started
    peak_rss = _peak_rss_bytes()
    if (
        recovered_at_base != expected_recovered
        or unresolved_at_base != expected_unresolved
        or residual_nine_recovered
        or elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C38RunError("formal O1C-0038 outcome or resource gate differs")

    residual_eight = base_rows[8]
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "claim_level": "POST_REVEAL_CEILING",
        "target_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "unknown_key_bits_at_real_deployment": 256,
            "public_input": "counter_nonce_one_output_block_only",
            "target_key_used_to_construct_prefix": True,
            "attacker_valid_recovery_claim": False,
            "fresh_targets": 0,
        },
        "architecture": {
            "prefix_order": "frozen_O1C-0022_K256_absolute_confidence_descending",
            "prefix_signs": "post_reveal_exact_truth_ceiling",
            "exact_relation": "O1C-0011_full256_public_ChaCha20_CNF",
            "coupling": "reversible_first_encounter_key_decisions",
            "hard_key_units_added": 0,
            "native_build": build.describe(),
            "public_instance": instance.describe(),
        },
        "arms": rows,
        "metrics": {
            "recovered_residual_bits_at_512": recovered_at_base,
            "unresolved_residual_bits_at_512": unresolved_at_base,
            "maximum_recovered_residual_bits_at_512": max(recovered_at_base),
            "residual_eight_conflicts": _mapping(
                residual_eight["stats"], "residual8.stats"
            )["conflicts"],
            "residual_eight_wall_microseconds": _mapping(
                residual_eight["resources"], "residual8.resources"
            )["wall_microseconds"],
            "residual_nine_recovered_by_32768": residual_nine_recovered,
            "all_supplied_prefix_bits_correct": True,
            "attacker_valid_exact_recoveries": 0,
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "python_cpu_seconds": time.process_time() - cpu_started,
            "native_solver_calls": len(rows),
            "requested_conflicts": requested_conflicts,
            "native_wall_seconds_sum": sum(
                int(_mapping(row["resources"], "arm.resources")["wall_microseconds"])
                for row in rows
            )
            / 1_000_000.0,
            "native_cpu_seconds_sum": sum(
                int(_mapping(row["resources"], "arm.resources")["cpu_microseconds"])
                for row in rows
            )
            / 1_000_000.0,
            "peak_rss_bytes": peak_rss,
            "MPS_or_GPU": False,
            "sibling_reads": 0,
            "sibling_writes": 0,
        },
        "source_sha256": source_hashes,
        "decision": "EXACT_RELATION_CLOSES_O1_ORDERED_RESIDUAL_8_ON_CONSUMED_TARGET",
        "next_action": config["next_action"],
    }

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = (
        Path("runs") / f"{stamp}_{ATTEMPT_ID}_exact-residual-completion-v1"
    )
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C38RunError("capsule path already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    result_bytes = _atomic_json(capsule / "result.json", result)
    config_bytes = config_file.read_bytes()
    (capsule / "config.json").write_bytes(config_bytes)
    run_bytes = _markdown(result).encode("utf-8")
    (capsule / "RUN.md").write_bytes(run_bytes)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c38_exact_residual_completion_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    (capsule / "command.txt").write_bytes(command_bytes)
    members = {
        "RUN.md": run_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        "result.json": result_bytes,
    }
    manifest = "".join(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
        for name, payload in sorted(members.items())
    ).encode("ascii")
    (capsule / "artifacts.sha256").write_bytes(manifest)
    for path in capsule.iterdir():
        path.chmod(0o444)
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


__all__ = ["ATTEMPT_ID", "O1C38RunError", "load_config", "main", "run"]
