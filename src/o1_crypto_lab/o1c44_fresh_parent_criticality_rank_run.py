"""O1C-0044 one-shot fresh parent-criticality joint-rank replication."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

import numpy as np

from .cadical_sensor import build_native_sensor, sha256_file
from .full256_broker import (
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from .o1_relational_search import model_matches_public
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
    _truth_rank,
)
from .proof_parent_criticality import FEATURE_NAMES
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0044"
CONFIG_SCHEMA = "o1-256-fresh-parent-criticality-rank-config-v1"
RESULT_SCHEMA = "o1-256-fresh-parent-criticality-rank-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0044_FRESH_PARENT_CRITICALITY_RANK_RESULT_20260718.json"
)
O1C43_MANIFEST = Path(
    "runs/20260718_233458_O1C-0043_parent-criticality-rank-v1/artifacts.sha256"
)
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)


class O1C44RunError(RuntimeError):
    """The frozen fresh target, parent reader, or score lifecycle differs."""


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _classify_ranks(
    ranks: Mapping[str, Mapping[str, object]], *, maximum_fraction: float
) -> tuple[str, bool, bool]:
    primary = float(ranks["primary"]["rank_fraction"])
    threshold = primary <= maximum_fraction
    controls = primary < min(
        float(ranks["key_rotated"]["rank_fraction"]),
        float(ranks["clause_rotated"]["rank_fraction"]),
    )
    if threshold and controls:
        return "FRESH_PARENT_CRITICALITY_RANK_TRANSFER", threshold, controls
    if threshold:
        return (
            "FRESH_PARENT_CRITICALITY_RANK_WITHOUT_CONTROL_MARGIN",
            threshold,
            controls,
        )
    return "FRESH_PARENT_CRITICALITY_RANK_NOT_REPLICATED", threshold, controls


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C44RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    field = _mapping(config.get("field"), "field")
    reader = _mapping(config.get("reader"), "reader")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    controls = _mapping(config.get("controls"), "controls")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "fresh-parent-criticality-rank-v1"
        or config.get("claim_level") != "TEST"
        or target.get("count") != 1
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("entropy_source_id") != "os.urandom:o1c-0044"
        or target.get("block_count") != 1
        or target.get("rounds") != 20
        or target.get("feed_forward") is not True
        or target.get("unknown_key_bits") != 256
        or field.get("conflict_horizon") != 16
        or field.get("seed") != 0
        or field.get("capacity") != 8192
        or field.get("direct_original_only") is not True
        or field.get("exclude_unit_parents") is not True
        or reader.get("feature_names") != list(FEATURE_NAMES)
        or reader.get("weights_sha256")
        != "c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30"
        or reader.get("source_attempt") != "O1C-0043"
        or reader.get("no_refit") is not True
        or panel.get("count") != 4096
        or panel.get("domain") != "O1C43-parent-criticality-decoy-v1"
        or panel.get("duplicate_policy") != "reject"
        or controls.get("arms")
        != ["primary", "key_rotated", "clause_rotated"]
        or success.get("maximum_primary_rank_fraction") != 0.25
        or success.get("require_strict_margin_over_both_rotations") is not True
        or budgets.get("maximum_wall_seconds") != 30
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 512
        or budgets.get("maximum_candidate_forward_evaluations") != 4097
        or budgets.get("maximum_decoy_keys") != 4096
        or budgets.get("maximum_fresh_targets") != 1
        or budgets.get("maximum_scientific_entropy_calls") != 1
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 2097152
    ):
        raise O1C44RunError("frozen O1C-0044 config differs")
    for name in (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "parent_criticality_source",
        "o1c43_runner",
        "runner",
        "o1c43_result",
    ):
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if sha256_file(resolved) != expected.get(name):
            raise O1C44RunError(f"source hash differs for {name}")
    manifest = (root / O1C43_MANIFEST).resolve(strict=True)
    if sha256_file(manifest) != expected.get("o1c43_manifest"):
        raise O1C44RunError("O1C-0043 manifest hash differs")
    return config


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Fresh primary rank: `{metrics['primary_rank']}/4097`\n"
        f"- Primary rank fraction: `{metrics['primary_rank_fraction']}`\n"
        f"- Key/clause control ranks: `{metrics['key_rotated_rank']}` / "
        f"`{metrics['clause_rotated_rank']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The O1C-0043 reader is loaded byte-for-byte and never refitted. The "
        "fresh key opens only after all three score vectors are frozen.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    target_config = _mapping(config["target"], "target")
    field_config = _mapping(config["field"], "field")
    reader_config = _mapping(config["reader"], "reader")
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
            "o1c43_runner",
            "runner",
            "o1c43_result",
        )
    }
    o1c43_manifest = (root / O1C43_MANIFEST).resolve(strict=True)
    source_paths["o1c43_manifest"] = o1c43_manifest
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
        raise O1C44RunError("O1C-0043 prerequisite differs")
    reader = np.asarray(o1c43_reader.get("weights_l2"), dtype=np.float64)
    if (
        reader.shape != (len(FEATURE_NAMES),)
        or not np.all(np.isfinite(reader))
        or array_sha256(reader, "<f8") != reader_config["weights_sha256"]
    ):
        raise O1C44RunError("frozen O1C-0043 reader differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    entropy_calls = 0

    def scientific_entropy(count: int) -> bytes:
        nonlocal entropy_calls
        entropy_calls += 1
        if entropy_calls != 1:
            raise O1C44RunError("fresh entropy source called more than once")
        return os.urandom(count)

    broker = Full256TargetBroker(
        block_count=int(target_config["block_count"]),
        entropy_source=scientific_entropy,
        entropy_source_id=str(target_config["entropy_source_id"]),
        target_id=str(target_config["target_id"]),
    )
    publication = broker.publish()
    publication_bytes = _canonical_bytes(publication)
    public = public_view_from_publication(publication)
    if entropy_calls != 1 or broker.phase != "PUBLISHED":
        raise O1C44RunError("fresh publication phase differs")

    with tempfile.TemporaryDirectory(prefix="o1c44-") as temporary:
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
        natural, instance_sha = _extract_field(
            sensor=sensor_build.executable,
            template=source_paths["template"],
            semantic_map=source_paths["semantic_map"],
            public=public,
            workspace=workspace,
            target_id=str(target_config["target_id"]),
            horizon=int(field_config["conflict_horizon"]),
            seed=int(field_config["seed"]),
            capacity=int(field_config["capacity"]),
        )
        keys = _candidate_keys(
            str(panel_config["domain"]), public.digest(), int(panel_config["count"])
        )
        runtime = _score_runtime(
            natural=natural,
            public=public,
            semantic_map=source_paths["semantic_map"],
            keys=keys,
            reader=reader,
        )
        candidate_key_bytes = b"".join(keys)
        score_bytes = {
            name: np.ascontiguousarray(scores, dtype="<f8").tobytes(order="C")
            for name, scores in runtime["scores"].items()
        }
        pre_reveal_index = {
            "publication.json": hashlib.sha256(publication_bytes).hexdigest(),
            "field.bin": hashlib.sha256(natural.to_bytes()).hexdigest(),
            "candidate_keys.bin": hashlib.sha256(candidate_key_bytes).hexdigest(),
            **{
                f"scores/{name}.f64le": hashlib.sha256(payload).hexdigest()
                for name, payload in score_bytes.items()
            },
        }
        score_freeze = {
            "schema": "o1-256-fresh-parent-criticality-score-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "target_id": target_config["target_id"],
            "publication_sha256": publication["publication_sha256"],
            "public_view_sha256": public.digest(),
            "target_key_reads": 0,
            "o1c43_manifest_sha256": sha256_file(o1c43_manifest),
            "o1c43_result_sha256": sha256_file(source_paths["o1c43_result"]),
            "reader_weights_sha256": array_sha256(reader, "<f8"),
            "natural_field": natural.describe(),
            "candidate_panel": config["candidate_panel"],
            "candidate_keys_sha256": hashlib.sha256(candidate_key_bytes).hexdigest(),
            "arms": {
                name: {
                    "field": runtime["fields"][name].describe(),
                    "feature_mean": runtime["means"][name].tolist(),
                    "feature_std": runtime["stds"][name].tolist(),
                    "score_sha256": array_sha256(runtime["scores"][name], "<f8"),
                }
                for name in config["controls"]["arms"]
            },
            "pre_reveal_artifact_sha256": pre_reveal_index,
        }
        score_freeze_bytes = _canonical_bytes(score_freeze)
        score_freeze_sha256 = hashlib.sha256(score_freeze_bytes).hexdigest()
        receipt = make_freeze_receipt(
            publication, frozen_artifact_sha256=score_freeze_sha256
        )
        receipt_bytes = _canonical_bytes(receipt)
        reveal = broker.reveal(receipt)
        verified_reveal = verify_reveal(reveal)
        reveal_bytes = _canonical_bytes(verified_reveal)
        if broker.phase != "REVEALED":
            raise O1C44RunError("fresh reveal phase differs")
        preimage = _mapping(
            verified_reveal.get("commitment_preimage"), "commitment_preimage"
        )
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C44RunError("fresh key encoding differs") from exc
        if len(truth_key) != 32 or not model_matches_public(truth_key, public):
            raise O1C44RunError("fresh key does not verify public relation")
        ranked: dict[str, dict[str, object]] = {}
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
                decoy_keys=keys,
                truth_key=truth_key,
                public=public,
            )
            ranked[name] = rank
            truth_features[name] = features.tolist()
            truth_standardized[name] = standardized.tolist()
        classification, threshold_pass, control_margin = _classify_ranks(
            ranked,
            maximum_fraction=float(success["maximum_primary_rank_fraction"]),
        )

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    candidate_evaluations = len(keys) + 1
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
        or 512 > int(budgets["maximum_native_probe_branches"])
        or candidate_evaluations
        > int(budgets["maximum_candidate_forward_evaluations"])
        or len(keys) > int(budgets["maximum_decoy_keys"])
        or entropy_calls > int(budgets["maximum_scientific_entropy_calls"])
    ):
        raise O1C44RunError("O1C-0044 resource ledger exceeds budget")

    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "classification": classification,
        "claim_boundary": {
            "fresh_targets": 1,
            "scientific_entropy_calls": entropy_calls,
            "target_key_bits_unknown_during_probe_and_scoring": 256,
            "reader_loaded_without_refit": True,
            "reader_weights_sha256": array_sha256(reader, "<f8"),
            "score_freeze_precedes_reveal": True,
            "candidate_scores_attacker_computable": True,
            "original_functional_clauses_only": True,
            "public_unit_parents_excluded": True,
            "revealed_key_independently_reproduces_public_output": True,
            "exact_key_recovery": False,
        },
        "publication_sha256": publication["publication_sha256"],
        "public_view_sha256": public.digest(),
        "score_freeze_sha256": score_freeze_sha256,
        "freeze_receipt_sha256": receipt["receipt_sha256"],
        "reveal_sha256": verified_reveal["reveal_sha256"],
        "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
        "instance_sha256": instance_sha,
        "reader": {
            "feature_names": list(FEATURE_NAMES),
            "weights_l2": reader.tolist(),
            "weights_sha256": array_sha256(reader, "<f8"),
            "o1c43_manifest_sha256": sha256_file(o1c43_manifest),
            "o1c43_result_sha256": sha256_file(source_paths["o1c43_result"]),
        },
        "natural_field": natural.describe(),
        "truth_features": truth_features,
        "truth_standardized": truth_standardized,
        "rank": ranked,
        "metrics": {
            "primary_rank": int(ranked["primary"]["rank"]),
            "primary_rank_fraction": float(ranked["primary"]["rank_fraction"]),
            "key_rotated_rank": int(ranked["key_rotated"]["rank"]),
            "key_rotated_rank_fraction": float(
                ranked["key_rotated"]["rank_fraction"]
            ),
            "clause_rotated_rank": int(ranked["clause_rotated"]["rank"]),
            "clause_rotated_rank_fraction": float(
                ranked["clause_rotated"]["rank_fraction"]
            ),
            "best_quarter_pass": threshold_pass,
            "coordinate_control_margin": control_margin,
            "prediction_pass": threshold_pass and control_margin,
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
            "native_probe_branches": 512,
            "candidate_forward_evaluations": candidate_evaluations,
            "decoy_keys": len(keys),
            "fresh_targets": 1,
            "scientific_entropy_calls": entropy_calls,
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
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_fresh-parent-criticality-rank-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C44RunError("O1C-0044 capsule already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c44_fresh_parent_criticality_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "candidate_keys.bin": candidate_key_bytes,
        "command.txt": command_bytes,
        "config.json": config_file.read_bytes(),
        "field.bin": natural.to_bytes(),
        "freeze_receipt.json": receipt_bytes,
        "publication.json": publication_bytes,
        "reveal.json": reveal_bytes,
        "score_freeze.json": score_freeze_bytes,
        **{f"scores/{name}.f64le": payload for name, payload in score_bytes.items()},
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
        raise O1C44RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C44RunError("persistent artifact budget differs")
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
    "O1C44RunError",
    "_classify_ranks",
    "load_config",
    "main",
    "run",
]
