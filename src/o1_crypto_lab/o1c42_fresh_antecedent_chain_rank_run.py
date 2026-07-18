"""O1C-0042 one-shot fresh Full-256 antecedent-chain rank replication."""

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

from .cadical_sensor import (
    build_native_sensor,
    iter_native_probe_records,
    paired_records,
    sha256_file,
)
from .full256_broker import (
    Full256TargetBroker,
    make_freeze_receipt,
    public_view_from_publication,
    verify_reveal,
)
from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import PublicTargetView
from .o1_relational_search import model_matches_public
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c41_antecedent_chain_rank_run import (
    _candidate_keys,
    _peak_rss_bytes,
    _rank_summary,
    _score_panel,
    _truth_rank,
)
from .proof_antecedent_relations import (
    OriginalClauseTable,
    extract_antecedent_relation_field,
    transform_antecedent_relation_field,
)
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0042"
CONFIG_SCHEMA = "o1-256-fresh-antecedent-chain-rank-config-v1"
RESULT_SCHEMA = "o1-256-fresh-antecedent-chain-rank-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0042_FRESH_ANTECEDENT_CHAIN_RANK_RESULT_20260718.json"
)
O1C41_MANIFEST = Path(
    "runs/20260718_225550_O1C-0041_antecedent-chain-rank-v1/artifacts.sha256"
)
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)


class O1C42RunError(RuntimeError):
    """The frozen fresh-target protocol, score, or work ledger differs."""


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
        float(ranks["factor_rotated"]["rank_fraction"]),
    )
    if threshold and controls:
        return "FRESH_CHAIN_RANK_TRANSFER", threshold, controls
    if threshold:
        return "FRESH_CHAIN_RANK_WITHOUT_CONTROL_MARGIN", threshold, controls
    return "FRESH_CHAIN_RANK_NOT_REPLICATED", threshold, controls


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C42RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    field = _mapping(config.get("field"), "field")
    panel = _mapping(config.get("candidate_panel"), "candidate_panel")
    controls = _mapping(config.get("controls"), "controls")
    success = _mapping(config.get("success"), "success")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "fresh-antecedent-chain-rank-v1"
        or config.get("claim_level") != "TEST"
        or target.get("count") != 1
        or target.get("target_id") != "o1c-0042-fresh-0000"
        or target.get("entropy_source_id") != "os.urandom:o1c-0042"
        or target.get("block_count") != 1
        or target.get("rounds") != 20
        or target.get("feed_forward") is not True
        or target.get("unknown_key_bits") != 256
        or field.get("conflict_horizon") != 16
        or field.get("seed") != 0
        or field.get("capacity") != 8192
        or field.get("unit_scale") != 1
        or field.get("global_orientation") != -1
        or panel.get("count") != 4096
        or panel.get("domain") != "O1C41-antecedent-chain-decoy-v1"
        or panel.get("duplicate_policy") != "reject"
        or controls.get("arms") != ["primary", "key_rotated", "factor_rotated"]
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
        or budgets.get("maximum_persistent_artifact_bytes") != 1048576
    ):
        raise O1C42RunError("frozen O1C-0042 config differs")
    for name in (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "o1c41_result",
    ):
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if sha256_file(resolved) != expected.get(name):
            raise O1C42RunError(f"source hash differs for {name}")
    manifest = (root / O1C41_MANIFEST).resolve(strict=True)
    if sha256_file(manifest) != expected.get("o1c41_manifest"):
        raise O1C42RunError("O1C-0041 manifest hash differs")
    return config


def _extract_field(
    *,
    sensor: Path,
    template: Path,
    semantic_map: Path,
    public: PublicTargetView,
    workspace: Path,
    horizon: int,
    seed: int,
    capacity: int,
):
    cnf = workspace / "fresh-public.cnf"
    instance = write_full256_instance(
        template,
        semantic_map,
        cnf,
        counter=public.counter_schedule[0],
        nonce=public.nonce,
        output=public.output_blocks[0],
    )
    verification = verify_full256_instance(cnf, template, semantic_map, instance)
    if (
        verification.get("ok") is not True
        or instance.key_unit_clause_count != 0
        or instance.public_unit_clause_count != 640
    ):
        raise O1C42RunError("fresh public CNF differs")
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
        raise O1C42RunError("fresh native probe header differs")
    field = extract_antecedent_relation_field(
        pairs,
        baseline_events=header.baseline_events,
        originals=originals,
        conflict_horizon=horizon,
        capacity=capacity,
    )
    return field, instance, verification


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Fresh primary rank: `{metrics['primary_rank']}/4097`\n"
        f"- Primary rank fraction: `{metrics['primary_rank_fraction']}`\n"
        f"- Key/factor control ranks: `{metrics['key_rotated_rank']}` / "
        f"`{metrics['factor_rotated_rank']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The target key was generated once by the sealed broker and opened only "
        "after the complete candidate-score freeze receipt.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    target_config = _mapping(config["target"], "target")
    field_config = _mapping(config["field"], "field")
    panel = _mapping(config["candidate_panel"], "candidate_panel")
    success = _mapping(config["success"], "success")
    budgets = _mapping(config["budgets"], "budgets")
    template = _relative_path(root, source["template"], "template")
    semantic_map = _relative_path(root, source["semantic_map"], "semantic_map")
    sensor_source = _relative_path(root, source["sensor_source"], "sensor_source")
    tracer_header = _relative_path(root, source["tracer_header"], "tracer_header")
    o1c41_result_path = _relative_path(root, source["o1c41_result"], "o1c41_result")
    o1c41_manifest = (root / O1C41_MANIFEST).resolve(strict=True)
    o1c41 = _read_json(o1c41_result_path)
    o1c41_metrics = _mapping(o1c41.get("metrics"), "O1C-0041 metrics")
    if (
        o1c41.get("classification")
        != "RETROSPECTIVE_CHAIN_RANK_SIGNAL_WITH_CONTROL_MARGIN"
        or o1c41_metrics.get("pooled_build_orientation")
        != field_config["global_orientation"]
        or o1c41_metrics.get("coordinate_control_margin") is not True
    ):
        raise O1C42RunError("O1C-0041 prerequisite differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    entropy_calls = 0

    def scientific_entropy(count: int) -> bytes:
        nonlocal entropy_calls
        entropy_calls += 1
        if entropy_calls != 1:
            raise O1C42RunError("fresh entropy source called more than once")
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
        raise O1C42RunError("fresh broker publication phase differs")

    source_paths: dict[str, Path] = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "o1c41_runner": root
        / "src/o1_crypto_lab/o1c41_antecedent_chain_rank_run.py",
        "antecedent_field": root / "src/o1_crypto_lab/proof_antecedent_relations.py",
        "forward_evaluator": root / "src/o1_crypto_lab/full256_forward_assignment.py",
        "rank_module": root / "src/o1_crypto_lab/relation_candidate_rank.py",
        "broker": root / "src/o1_crypto_lab/full256_broker.py",
        "template": template,
        "semantic_map": semantic_map,
        "sensor_source": sensor_source,
        "tracer_header": tracer_header,
        "o1c41_result": o1c41_result_path,
        "o1c41_manifest": o1c41_manifest,
    }

    with tempfile.TemporaryDirectory(prefix="o1c42-") as temporary:
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
        natural_field, instance, instance_verification = _extract_field(
            sensor=sensor_build.executable,
            template=template,
            semantic_map=semantic_map,
            public=public,
            workspace=workspace,
            horizon=int(field_config["conflict_horizon"]),
            seed=int(field_config["seed"]),
            capacity=int(field_config["capacity"]),
        )
        orientation = int(field_config["global_orientation"])
        arms = {
            "primary": transform_antecedent_relation_field(
                natural_field, orientation=orientation
            ),
            "key_rotated": transform_antecedent_relation_field(
                natural_field, orientation=orientation, rotate="key"
            ),
            "factor_rotated": transform_antecedent_relation_field(
                natural_field, orientation=orientation, rotate="factor"
            ),
        }
        keys = _candidate_keys(str(panel["domain"]), public.digest(), int(panel["count"]))
        plan, scores, weights = _score_panel(
            fields=arms, public=public, semantic_map=semantic_map, keys=keys
        )
        candidate_key_bytes = b"".join(keys)
        score_bytes = {
            name: np.ascontiguousarray(values, dtype="<f8").tobytes(order="C")
            for name, values in scores.items()
        }
        pre_reveal_index = {
            "publication.json": hashlib.sha256(publication_bytes).hexdigest(),
            "field.bin": hashlib.sha256(arms["primary"].to_bytes()).hexdigest(),
            "candidate_keys.bin": hashlib.sha256(candidate_key_bytes).hexdigest(),
            **{
                f"scores/{name}.f64le": hashlib.sha256(payload).hexdigest()
                for name, payload in score_bytes.items()
            },
        }
        score_freeze = {
            "schema": "o1-256-fresh-antecedent-chain-score-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "target_id": target_config["target_id"],
            "publication_sha256": publication["publication_sha256"],
            "public_view_sha256": public.digest(),
            "target_key_reads": 0,
            "selected_orientation": orientation,
            "natural_field": natural_field.describe(),
            "arms": {
                name: {
                    "field": arm.describe(),
                    "score_sha256": array_sha256(scores[name], "<f8"),
                }
                for name, arm in arms.items()
            },
            "candidate_panel": config["candidate_panel"],
            "candidate_keys_sha256": hashlib.sha256(candidate_key_bytes).hexdigest(),
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
            raise O1C42RunError("fresh broker reveal phase differs")
        preimage = _mapping(
            verified_reveal.get("commitment_preimage"), "commitment_preimage"
        )
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C42RunError("revealed key encoding differs") from exc
        if len(truth_key) != 32 or not model_matches_public(truth_key, public):
            raise O1C42RunError("revealed key does not verify public target")
        ranked = {
            name: _rank_summary(
                _truth_rank(
                    field=arm,
                    plan=plan,
                    weights=weights[name],
                    scores=scores[name],
                    keys=keys,
                    truth_key=truth_key,
                    public=public,
                )
            )
            for name, arm in arms.items()
        }
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
        or entropy_calls != int(budgets["maximum_scientific_entropy_calls"])
    ):
        raise O1C42RunError("O1C-0042 resource ledger exceeds budget")

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
            "global_orientation_frozen_from_o1c41": orientation,
            "score_freeze_precedes_reveal": True,
            "candidate_scores_attacker_computable": True,
            "revealed_key_independently_reproduces_public_output": True,
            "exact_key_recovery": False,
        },
        "publication_sha256": publication["publication_sha256"],
        "score_freeze_sha256": score_freeze_sha256,
        "freeze_receipt_sha256": receipt["receipt_sha256"],
        "reveal_sha256": verified_reveal["reveal_sha256"],
        "public_view_sha256": public.digest(),
        "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
        "instance": instance.describe(),
        "instance_verification": instance_verification,
        "natural_field": natural_field.describe(),
        "rank": ranked,
        "metrics": {
            "primary_rank": int(ranked["primary"]["rank"]),
            "primary_rank_fraction": float(ranked["primary"]["rank_fraction"]),
            "key_rotated_rank": int(ranked["key_rotated"]["rank"]),
            "key_rotated_rank_fraction": float(
                ranked["key_rotated"]["rank_fraction"]
            ),
            "factor_rotated_rank": int(ranked["factor_rotated"]["rank"]),
            "factor_rotated_rank_fraction": float(
                ranked["factor_rotated"]["rank_fraction"]
            ),
            "best_quarter_pass": threshold_pass,
            "coordinate_control_margin": control_margin,
            "prediction_pass": threshold_pass and control_margin,
            "truth_collision_count": sum(key == truth_key for key in keys),
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
        "source_sha256": {name: sha256_file(path) for name, path in source_paths.items()},
        "next_action": config["next_action"],
    }

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_fresh-antecedent-chain-rank-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C42RunError("O1C-0042 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    config_bytes = config_file.read_bytes()
    run_bytes = _markdown(result).encode("utf-8")
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c42_fresh_antecedent_chain_rank_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    members: dict[str, bytes] = {
        "RUN.md": run_bytes,
        "candidate_keys.bin": candidate_key_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        "field.bin": arms["primary"].to_bytes(),
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
        raise O1C42RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C42RunError("persistent artifact budget differs")
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
    "O1C42RunError",
    "_classify_ranks",
    "load_config",
    "main",
    "run",
]
