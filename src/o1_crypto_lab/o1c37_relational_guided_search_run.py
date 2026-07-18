"""O1C-0037 exact full-256 CDCL guidance and repair-radius experiment."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

import numpy as np

from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import PublicTargetView, bits_to_key
from .o1_relational_search import (
    build_native_guided_search,
    model_hamming_distance,
    model_matches_public,
    repair_radius_scores,
    run_guided_search,
    sha256_file,
    write_hint_scores,
)


ATTEMPT_ID = "O1C-0037"
CONFIG_SCHEMA = "o1-256-relational-guided-search-config-v1"
RESULT_SCHEMA = "o1-256-relational-guided-search-result-v1"
RESULT_RELATIVE = Path("research/O1C0037_RELATIONAL_GUIDED_SEARCH_RESULT_20260718.json")
PREDICTION_ARMS = (
    "raw_float_delta_sum",
    "normalized_float_delta_sum",
    "quantized_int8_vault",
    "last_horizon_only",
    "unit_sign_sum",
    "coordinate_shuffled_vault",
    "zero_prior",
)


class O1C37RunError(RuntimeError):
    """The frozen O1C-0037 contract, input, or exact result differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C37RunError(f"{field} must be an object")
    return value


def _read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise O1C37RunError(f"invalid JSON: {path}") from exc
    return dict(_mapping(value, str(path)))


def _relative_path(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise O1C37RunError(f"{field} must be a relative path")
    candidate = (root / value).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise O1C37RunError(f"{field} escapes the lab")
    return candidate


def load_config(path: str | Path) -> dict[str, object]:
    config_path = Path(path).resolve(strict=True)
    root = lab_root().resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C37RunError("config escapes the lab")
    config = _read_json(config_path)
    target = _mapping(config.get("target"), "target")
    relation = _mapping(config.get("exact_relation"), "exact_relation")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "relational-guided-search-v1"
        or config.get("claim_level") != "TEST"
        or target.get("index") != 0
        or target.get("target_id") != "build-0000"
        or target.get("width_index") != 3
        or target.get("width") != 256
        or target.get("o1_arm") != PREDICTION_ARMS[2]
        or target.get("o1_arm_index") != 2
        or target.get("shuffled_arm") != PREDICTION_ARMS[5]
        or target.get("shuffled_arm_index") != 5
        or relation.get("base_conflict_limit") != 512
        or relation.get("o1_guided_widths") != [52, 128, 256]
        or relation.get("one_error_conflict_limits") != [512, 2048, 8192, 32768]
        or budgets.get("maximum_native_solver_calls") != 12
        or budgets.get("maximum_conflicts") != 47616
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
    ):
        raise O1C37RunError("frozen O1C-0037 config differs")
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


def _public_view(value: object) -> PublicTargetView:
    row = _mapping(value, "public_view")
    counters = row.get("counter_schedule")
    outputs = row.get("output_blocks_hex")
    if not isinstance(counters, list) or not isinstance(outputs, list):
        raise O1C37RunError("public view sequences differ")
    try:
        public = PublicTargetView(
            counter_schedule=tuple(int(item) for item in counters),
            nonce=bytes.fromhex(str(row.get("nonce_hex"))),
            output_blocks=tuple(bytes.fromhex(str(item)) for item in outputs),
        )
    except (TypeError, ValueError) as exc:
        raise O1C37RunError("public view encoding differs") from exc
    public.validate()
    if public.block_count != 1 or public.describe() != dict(row):
        raise O1C37RunError("public view semantics differ")
    return public


def _atomic_json(path: Path, value: object) -> bytes:
    payload = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
        + "\n"
    ).encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return payload


def _git_commit(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    value = completed.stdout.strip()
    if len(value) != 40:
        raise O1C37RunError("git commit differs")
    return value


def _peak_rss_bytes() -> int:
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    if own <= 16 * 1024 * 1024:
        own *= 1024
    if children <= 16 * 1024 * 1024:
        children *= 1024
    return max(own, children)


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "result.metrics")
    resources = _mapping(result["resources"], "result.resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Status: `completed`\n"
        f"- Started: `{result['started_at']}`\n"
        f"- Ended: `{result['recorded_at']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Target: standard ChaCha20-R20, all 256 bits unknown at deployment\n"
        f"- Real O1 exact recovery: `{metrics['attacker_valid_exact_recoveries']}`\n"
        f"- Oracle exact guidance: `{metrics['oracle_exact_guidance_recovered']}`\n"
        f"- One-error repair through 32,768 conflicts: "
        f"`{metrics['one_error_recovered_by_32768_conflicts']}`\n"
        f"- Decision: `{result['decision']}`\n\n"
        "The exact truth-prior ceiling recovers and independently verifies the "
        "complete key. The frozen O1 and shuffled fields do not improve exact "
        "search, and one wrong key-only first-encounter hint is not repaired.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    target_config = _mapping(config["target"], "target")
    relation = _mapping(config["exact_relation"], "exact_relation")
    budgets = _mapping(config["budgets"], "budgets")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()

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
    prediction_freeze_path = _relative_path(
        root, target_config["fold_prediction_freeze"], "fold_prediction_freeze"
    )
    template = _relative_path(root, relation["template"], "template")
    semantic_map = _relative_path(root, relation["semantic_map"], "semantic_map")
    native_source = _relative_path(root, relation["native_source"], "native_source")

    sidecar = _read_json(pool_path)
    pool = _mapping(sidecar.get("pool"), "pool sidecar.pool")
    public = _public_view(pool.get("public_view"))
    if (
        sidecar.get("target_id") != "build-0000"
        or sidecar.get("public_view_sha256") != public.digest()
        or sidecar.get("labels_materialized") != 0
        or sidecar.get("target_key_inputs_to_probe") != 0
    ):
        raise O1C37RunError("source public boundary differs")

    labels_raw = labels_path.read_bytes()
    labels = np.unpackbits(
        np.frombuffer(labels_raw, dtype=np.uint8), bitorder="little"
    )
    if labels.shape != (4 * 256,):
        raise O1C37RunError("O1C-0022 label artifact shape differs")
    truth_bits = labels.reshape(4, 256)[0]
    truth_key = bits_to_key(truth_bits)
    source_result = _read_json(source_result_path)
    build_rows = source_result.get("build")
    if not isinstance(build_rows, list) or len(build_rows) != 4:
        raise O1C37RunError("source BUILD result differs")
    target_description = _mapping(build_rows[0], "source build[0]").get("target")
    target_row = _mapping(target_description, "source build[0].target")
    if (
        target_row.get("target_id") != "build-0000"
        or target_row.get("public_view_sha256") != public.digest()
        or target_row.get("key_sha256") != hashlib.sha256(truth_key).hexdigest()
    ):
        raise O1C37RunError("post-freeze truth does not match public target")

    prediction_freeze = _read_json(prediction_freeze_path)
    if (
        prediction_freeze.get("held_out_target_id") != "build-0000"
        or prediction_freeze.get("held_out_label_used_for_this_fold") is not False
        or prediction_freeze.get("active_coordinate_counts") != [12, 52, 128, 256]
        or prediction_freeze.get("prediction_arms") != list(PREDICTION_ARMS)
    ):
        raise O1C37RunError("frozen prediction boundary differs")
    predictions = np.fromfile(predictions_path, dtype="<f8")
    if predictions.size != 4 * len(PREDICTION_ARMS) * 256:
        raise O1C37RunError("frozen prediction tensor shape differs")
    predictions = predictions.reshape(4, len(PREDICTION_ARMS), 256)
    o1_scores = predictions[3, 2]
    shuffled_scores = predictions[3, 5]
    if not bool(np.isfinite(o1_scores).all() and np.isfinite(shuffled_scores).all()):
        raise O1C37RunError("frozen score field is non-finite")

    source_paths = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "adapter": root / "src/o1_crypto_lab/o1_relational_search.py",
        "native": native_source,
        "template": template,
        "semantic_map": semantic_map,
        "pool_sidecar": pool_path,
        "source_result": source_result_path,
        "labels": labels_path,
        "predictions": predictions_path,
        "prediction_freeze": prediction_freeze_path,
    }
    source_hashes = {name: sha256_file(path) for name, path in source_paths.items()}

    rows: list[dict[str, object]] = []
    total_requested_conflicts = 0
    with tempfile.TemporaryDirectory(prefix="o1c37-") as temporary:
        workspace = Path(temporary)
        executable = workspace / "cadical-o1-guided-search"
        build = build_native_guided_search(source=native_source, output=executable)
        cnf = workspace / "build-0000.cnf"
        instance_report = write_full256_instance(
            template,
            semantic_map,
            cnf,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
        )
        verification = verify_full256_instance(
            cnf, template, semantic_map, instance_report
        )
        source_instance = _mapping(pool.get("instance"), "pool.instance")
        if (
            instance_report.instance_sha256 != source_instance.get("instance_sha256")
            or instance_report.key_unit_clause_count != 0
            or verification.get("ok") is not True
        ):
            raise O1C37RunError("reinstantiated exact public CNF differs")

        def execute(
            name: str,
            mode: str,
            scores: np.ndarray | None,
            guided_bits: int,
            conflict_limit: int,
            *,
            privileged: bool,
        ) -> None:
            nonlocal total_requested_conflicts
            hint_path: Path | None = None
            hint_sha: str | None = None
            map_correct: int | None = None
            guided_correct: int | None = None
            if scores is not None:
                hint_path = workspace / f"{name}.hints"
                hint_sha = write_hint_scores(hint_path, scores)
                ordered = np.lexsort(
                    (np.arange(256), -np.abs(np.asarray(scores)))
                )
                signs = np.asarray(scores) >= 0.0
                map_correct = int(np.count_nonzero(signs == truth_bits))
                guided_correct = int(
                    np.count_nonzero(signs[ordered[:guided_bits]] == truth_bits[ordered[:guided_bits]])
                )
            result = run_guided_search(
                executable=executable,
                cnf_path=cnf,
                mode=mode,  # type: ignore[arg-type]
                conflict_limit=conflict_limit,
                guided_bits=guided_bits,
                seed=0,
                hint_path=hint_path,
                timeout_seconds=60.0,
            )
            total_requested_conflicts += conflict_limit
            verified_model = bool(
                result.key_model is not None
                and model_matches_public(result.key_model, public)
            )
            rows.append(
                {
                    "name": name,
                    "mode": mode,
                    "privileged_post_reveal_ceiling": privileged,
                    "guided_bits": guided_bits,
                    "hint_sha256": hint_sha,
                    "map_correct_bits_post_reveal": map_correct,
                    "guided_correct_bits_post_reveal": guided_correct,
                    "status": result.status_name,
                    "status_code": result.status,
                    "model_publicly_verified": verified_model,
                    "model_truth_hamming": (
                        None
                        if result.key_model is None
                        else model_hamming_distance(result.key_model, truth_key)
                    ),
                    "stats": dict(result.stats),
                    "guided": dict(result.guided),
                    "resources": dict(result.resources),
                }
            )

        base_limit = int(relation["base_conflict_limit"])
        execute("internal", "internal", None, 0, base_limit, privileged=False)
        execute("o1_phase_k256", "phase", o1_scores, 256, base_limit, privileged=False)
        for width in relation["o1_guided_widths"]:
            execute(
                f"o1_guided_k{int(width):03d}",
                "guided",
                o1_scores,
                int(width),
                base_limit,
                privileged=False,
            )
        execute(
            "shuffled_guided_k256",
            "guided",
            shuffled_scores,
            256,
            base_limit,
            privileged=False,
        )
        oracle_exact = repair_radius_scores(o1_scores, truth_bits, wrong_count=0)
        execute(
            "oracle_exact_guided_k256",
            "guided",
            oracle_exact,
            256,
            base_limit,
            privileged=True,
        )
        oracle_one_error = repair_radius_scores(
            o1_scores, truth_bits, wrong_count=1
        )
        for limit in relation["one_error_conflict_limits"]:
            execute(
                f"oracle_one_error_guided_k256_c{int(limit):05d}",
                "guided",
                oracle_one_error,
                256,
                int(limit),
                privileged=True,
            )
        execute(
            "oracle_one_residual_guided_k255",
            "guided",
            oracle_one_error,
            255,
            base_limit,
            privileged=True,
        )

    if len(rows) != int(budgets["maximum_native_solver_calls"]):
        raise O1C37RunError("native solver-call count differs")
    if total_requested_conflicts != int(budgets["maximum_conflicts"]):
        raise O1C37RunError("requested conflict ledger differs")
    by_name = {str(row["name"]): row for row in rows}
    attacker_valid = [row for row in rows if not row["privileged_post_reveal_ceiling"]]
    attacker_recoveries = sum(bool(row["model_publicly_verified"]) for row in attacker_valid)
    oracle_exact_recovered = bool(
        by_name["oracle_exact_guided_k256"]["model_publicly_verified"]
    )
    one_error_recovered = any(
        bool(row["model_publicly_verified"])
        for row in rows
        if str(row["name"]).startswith("oracle_one_error_guided_k256")
    )
    internal = _mapping(by_name["internal"]["resources"], "internal.resources")
    o1_k256 = _mapping(by_name["o1_guided_k256"]["resources"], "o1.resources")
    shuffled_k256 = _mapping(
        by_name["shuffled_guided_k256"]["resources"], "shuffled.resources"
    )
    elapsed = time.perf_counter() - started
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "target_contract": {
            "cipher": "ChaCha20",
            "rounds": 20,
            "unknown_key_bits_at_deployment": 256,
            "public_input": "counter_nonce_one_output_block_only",
            "target_key_entered_attacker_valid_arms": False,
            "privileged_truth_used_only_in_explicit_post_reveal_ceiling_arms": True,
            "fresh_targets": 0,
        },
        "architecture": {
            "soft_prior": "frozen_O1C-0022_K256_quantized_int8_vault",
            "exact_relation": "O1C-0011_full256_public_ChaCha20_CNF",
            "coupling": "reversible_confidence_ordered_first_encounter_key_decisions",
            "hard_key_units_added": 0,
            "native_build": build.describe(),
            "public_instance": instance_report.describe(),
        },
        "arms": rows,
        "metrics": {
            "attacker_valid_exact_recoveries": attacker_recoveries,
            "attacker_valid_arm_count": len(attacker_valid),
            "oracle_exact_guidance_recovered": oracle_exact_recovered,
            "oracle_exact_guidance_conflicts": _mapping(
                by_name["oracle_exact_guided_k256"]["stats"], "oracle.stats"
            )["conflicts"],
            "one_error_recovered_by_32768_conflicts": one_error_recovered,
            "measured_key_only_repair_radius_bits": 0 if not one_error_recovered else 1,
            "o1_map_correct_bits": by_name["o1_guided_k256"][
                "map_correct_bits_post_reveal"
            ],
            "o1_guided_k052_correct_bits": by_name["o1_guided_k052"][
                "guided_correct_bits_post_reveal"
            ],
            "o1_guided_k128_correct_bits": by_name["o1_guided_k128"][
                "guided_correct_bits_post_reveal"
            ],
            "o1_guided_k256_correct_bits": by_name["o1_guided_k256"][
                "guided_correct_bits_post_reveal"
            ],
            "matched_512_wall_ratio_o1_k256_over_internal": int(
                o1_k256["wall_microseconds"]
            )
            / int(internal["wall_microseconds"]),
            "matched_512_wall_ratio_o1_over_shuffled": int(
                o1_k256["wall_microseconds"]
            )
            / int(shuffled_k256["wall_microseconds"]),
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "python_cpu_seconds": time.process_time() - cpu_started,
            "native_solver_calls": len(rows),
            "requested_conflicts": total_requested_conflicts,
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
            "peak_rss_bytes": _peak_rss_bytes(),
            "MPS_or_GPU": False,
            "sibling_reads": 0,
            "sibling_writes": 0,
        },
        "source_sha256": source_hashes,
        "decision": "CLOSE_KEY_ONLY_FIRST_ENCOUNTER_CDCL_GUIDANCE",
        "next_action": (
            "Keep the exact adapter as a ceiling instrument. Move O1 guidance from "
            "key phases to target-specific relation/proof factors or a specialized "
            "residual compiler; do not scale conflict limits on this field."
        ),
    }
    if (
        not oracle_exact_recovered
        or attacker_recoveries != 0
        or one_error_recovered
        or elapsed > float(budgets["maximum_wall_seconds"])
        or _peak_rss_bytes() > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C37RunError("formal O1C-0037 outcome or resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_relational-guided-search-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C37RunError("O1C-0037 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    result_bytes = _atomic_json(capsule / "result.json", result)
    config_bytes = config_file.read_bytes()
    (capsule / "config.json").write_bytes(config_bytes)
    run_bytes = _markdown(result).encode("utf-8")
    (capsule / "RUN.md").write_bytes(run_bytes)
    command_bytes = (
        f"PYTHONPATH=src python3 -m o1_crypto_lab.o1c37_relational_guided_search_run "
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


__all__ = ["ATTEMPT_ID", "O1C37RunError", "load_config", "main", "run"]
