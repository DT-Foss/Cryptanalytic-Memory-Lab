"""O1C-0047 complete-state criticality rank on a nested residual cube."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

import numpy as np

from .cadical_sensor import sha256_file
from .criticality_potential import (
    CriticalityPotentialField,
    score_potential_assignment,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_forward_assignment import compile_full256_forward_read_plan
from .living_inverse import key_bits
from .o1_relational_search import model_matches_public
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c45_criticality_live_search_run import (
    _highest_support_key_order,
    _pretty_json_bytes,
)
from .proof_parent_criticality import (
    ParentCriticalityField,
    requested_parent_criticality_variables,
    transform_parent_criticality_field,
)
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0047"
CONFIG_SCHEMA = "o1-256-global-criticality-residual-beam-config-v1"
RESULT_SCHEMA = "o1-256-global-criticality-residual-beam-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0047_GLOBAL_CRITICALITY_RESIDUAL_BEAM_RESULT_20260719.json"
)
ARMS = ("primary", "key_rotated", "clause_rotated")


class O1C47RunError(RuntimeError):
    """The frozen global score, residual cube, or exact rank differs."""


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _candidate_key(
    truth_key: bytes, variables: tuple[int, ...], mask: int
) -> bytes:
    candidate = bytearray(truth_key)
    for index, variable in enumerate(variables):
        byte_index, bit_index = divmod(variable - 1, 8)
        bit_mask = 1 << bit_index
        if mask & (1 << index):
            candidate[byte_index] |= bit_mask
        else:
            candidate[byte_index] &= ~bit_mask
    return bytes(candidate)


def _nested_masks(
    *, truth_mask: int, width: int, maximum_width: int
) -> np.ndarray:
    if not 0 < width <= maximum_width <= 20:
        raise O1C47RunError("nested residual width differs")
    masks = np.arange(1 << maximum_width, dtype=np.uint32)
    if width == maximum_width:
        return masks
    high_mask = ((1 << maximum_width) - 1) ^ ((1 << width) - 1)
    return masks[(masks & high_mask) == (truth_mask & high_mask)]


def _rank_row(
    *, scores: np.ndarray, masks: np.ndarray, truth_mask: int
) -> dict[str, object]:
    if (
        scores.ndim != 1
        or masks.ndim != 1
        or not len(masks)
        or truth_mask not in set(int(value) for value in masks)
    ):
        raise O1C47RunError("residual rank inputs differ")
    values = scores[masks]
    truth_score = float(scores[truth_mask])
    order = np.lexsort((masks, -values))
    ordered_masks = masks[order]
    positions = np.flatnonzero(ordered_masks == truth_mask)
    if positions.shape != (1,):
        raise O1C47RunError("truth mask rank differs")
    deterministic_rank = int(positions[0]) + 1
    strict_rank = 1 + int(np.count_nonzero(values > truth_score))
    count = len(masks)
    return {
        "candidate_count": count,
        "truth_score": truth_score,
        "strict_rank": strict_rank,
        "deterministic_rank": deterministic_rank,
        "rank_fraction": deterministic_rank / count,
        "effective_enumeration_bits": math.log2(deterministic_rank),
        "search_compression_bits": math.log2(count / deterministic_rank),
        "top1": deterministic_rank <= 1,
        "top16": deterministic_rank <= 16,
        "top256": deterministic_rank <= 256,
    }


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C47RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    beam = _mapping(config.get("beam"), "beam")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "global-criticality-residual-beam-v1"
        or config.get("claim_level") != "POST_REVEAL_CEILING"
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("rounds") != 20
        or target.get("full_key_bits") != 256
        or target.get("truth_fixed_complement_bits") != 240
        or target.get("fresh_targets") != 0
        or beam.get("arms") != list(ARMS)
        or beam.get("widths") != [8, 12, 16]
        or beam.get("maximum_width") != 16
        or beam.get("candidate_count") != 65536
        or beam.get("retained_beam") != 256
        or beam.get("selector")
        != "descending-sum-abs-parent-score-units-then-count-then-coordinate"
        or beam.get("candidate_tie_break") != "ascending-binary-mask"
        or beam.get("primary_width16_gate_rank") != 256
        or budgets.get("maximum_wall_seconds") != 150
        or budgets.get("maximum_peak_rss_bytes") != 268435456
        or budgets.get("maximum_forward_evaluations") != 65536
        or budgets.get("maximum_public_verifications") != 769
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 4194304
    ):
        raise O1C47RunError("frozen O1C-0047 config differs")
    names = (
        "semantic_map",
        "publication",
        "reveal",
        "field",
        "o1c44_result",
        "primary_potential",
        "key_rotated_potential",
        "clause_rotated_potential",
        "potential_source",
        "forward_plan_source",
        "runner",
    )
    for name in names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if not isinstance(expected.get(name), str) or len(expected[name]) != 64:
            raise O1C47RunError(f"source hash contract differs for {name}")
        if sha256_file(resolved) != expected[name]:
            raise O1C47RunError(f"source hash differs for {name}")
    return config


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    width16 = _mapping(metrics["width16"], "width16")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Width-16 primary rank: `{_mapping(width16['primary'], 'primary')['deterministic_rank']}/65536`\n"
        f"- Width-16 control ranks: `key={_mapping(width16['key_rotated'], 'key')['deterministic_rank']}, clause={_mapping(width16['clause_rotated'], 'clause')['deterministic_rank']}`\n"
        f"- Primary top-256 exact verification: `{metrics['primary_top256_contains_verified_key']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "This is a post-reveal completion ceiling: 240 truth-key bits define the "
        "nested cube. Every candidate is nevertheless a complete 256-bit key and "
        "is scored by the unchanged public criticality field.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    beam_config = _mapping(config["beam"], "beam")
    budgets = _mapping(config["budgets"], "budgets")
    paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in source
        if name != "expected_sha256"
    }
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    source_commit = _git_commit(root)

    public = public_view_from_publication(_read_json(paths["publication"]))
    reveal = verify_reveal(_read_json(paths["reveal"]))
    preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
    try:
        truth_key = bytes.fromhex(str(preimage["key_hex"]))
    except ValueError as exc:
        raise O1C47RunError("revealed key encoding differs") from exc
    if len(truth_key) != 32 or not model_matches_public(truth_key, public):
        raise O1C47RunError("revealed key does not verify public target")

    natural = ParentCriticalityField.from_bytes(paths["field"].read_bytes())
    fields = {
        "primary": natural,
        "key_rotated": transform_parent_criticality_field(natural, rotate="key"),
        "clause_rotated": transform_parent_criticality_field(natural, rotate="clause"),
    }
    potentials = {
        name: CriticalityPotentialField.from_bytes(
            paths[f"{name}_potential"].read_bytes()
        )
        for name in ARMS
    }
    plan = compile_full256_forward_read_plan(
        paths["semantic_map"], requested_parent_criticality_variables(fields.values())
    )
    maximum_width = int(beam_config["maximum_width"])
    variables = _highest_support_key_order(natural)[:maximum_width]
    if len(variables) != maximum_width or len(set(variables)) != maximum_width:
        raise O1C47RunError("residual coordinate selection differs")
    truth_bit_values = tuple(int(bit) for bit in key_bits(truth_key))
    truth_mask = sum(
        truth_bit_values[variable - 1] << index
        for index, variable in enumerate(variables)
    )
    if _candidate_key(truth_key, variables, truth_mask) != truth_key:
        raise O1C47RunError("residual candidate codec differs")

    candidate_count = int(beam_config["candidate_count"])
    scores = {
        name: np.empty(candidate_count, dtype=np.float64) for name in ARMS
    }
    for mask in range(candidate_count):
        candidate = _candidate_key(truth_key, variables, mask)
        assignment = plan.evaluate(
            key=candidate,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        for name in ARMS:
            scores[name][mask] = score_potential_assignment(
                potentials[name], assignment
            )

    o1c44_result = _read_json(paths["o1c44_result"])
    o1c44_ranks = _mapping(o1c44_result.get("rank"), "O1C-0044 rank")
    truth_score_checks: dict[str, object] = {}
    for name in ARMS:
        expected = float(_mapping(o1c44_ranks.get(name), name)["truth_score"])
        actual = float(scores[name][truth_mask])
        error = abs(actual - expected)
        truth_score_checks[name] = {
            "expected": expected,
            "actual": actual,
            "absolute_error": error,
        }
        if error > 1e-12:
            raise O1C47RunError(f"global truth score differs for {name}")

    width_metrics: dict[str, object] = {}
    for width_value in beam_config["widths"]:
        width = int(width_value)
        masks = _nested_masks(
            truth_mask=truth_mask, width=width, maximum_width=maximum_width
        )
        if len(masks) != 1 << width:
            raise O1C47RunError("nested candidate count differs")
        width_metrics[str(width)] = {
            name: _rank_row(scores=scores[name], masks=masks, truth_mask=truth_mask)
            for name in ARMS
        }

    retained = int(beam_config["retained_beam"])
    top_beam: dict[str, object] = {}
    public_verifications = 1
    for name in ARMS:
        masks = np.arange(candidate_count, dtype=np.uint32)
        order = np.lexsort((masks, -scores[name]))[:retained]
        matches: list[dict[str, object]] = []
        top_hashes: list[str] = []
        for rank, mask_value in enumerate(order, start=1):
            candidate = _candidate_key(truth_key, variables, int(mask_value))
            top_hashes.append(hashlib.sha256(candidate).hexdigest())
            if model_matches_public(candidate, public):
                matches.append(
                    {
                        "rank": rank,
                        "candidate_mask": int(mask_value),
                        "key_sha256": hashlib.sha256(candidate).hexdigest(),
                    }
                )
            public_verifications += 1
        top_beam[name] = {
            "retained": retained,
            "ordered_key_sha256": top_hashes,
            "ordered_key_sha256_list_sha256": hashlib.sha256(
                ("\n".join(top_hashes) + "\n").encode("ascii")
            ).hexdigest(),
            "public_matches": matches,
        }
    if public_verifications != int(budgets["maximum_public_verifications"]):
        raise O1C47RunError("public verification ledger differs")

    width16 = _mapping(width_metrics[str(maximum_width)], "width16")
    primary16 = _mapping(width16["primary"], "primary16")
    primary_rank = int(primary16["deterministic_rank"])
    control_ranks = [
        int(_mapping(width16[name], name)["deterministic_rank"])
        for name in ARMS[1:]
    ]
    primary_margin = primary_rank < min(control_ranks)
    primary_top256 = primary_rank <= int(beam_config["primary_width16_gate_rank"])
    primary_matches = _mapping(top_beam["primary"], "primary beam")[
        "public_matches"
    ]
    verified_top256 = bool(
        isinstance(primary_matches, list)
        and len(primary_matches) == 1
        and _mapping(primary_matches[0], "primary match")["rank"] == primary_rank
    )
    controls_contain_key = any(
        bool(_mapping(top_beam[name], name)["public_matches"]) for name in ARMS[1:]
    )
    if primary_top256 and primary_margin and verified_top256 and not controls_contain_key:
        classification = "POST_REVEAL_GLOBAL_CRITICALITY_COMPRESSES_RESIDUAL16"
    elif primary_margin:
        classification = "POST_REVEAL_GLOBAL_CRITICALITY_RANK_MARGIN"
    else:
        classification = "POST_REVEAL_GLOBAL_CRITICALITY_NO_RANK_MARGIN"

    elapsed = time.perf_counter() - started
    peak_rss = _peak_rss_bytes()
    score_artifacts = {
        f"scores/{name}.f64le": np.asarray(scores[name], dtype="<f8").tobytes()
        for name in ARMS
    }
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": classification,
        "claim_boundary": {
            "post_reveal_ceiling": True,
            "truth_fixed_complement_bits": 240,
            "residual_bits": maximum_width,
            "every_candidate_is_complete_256_bit_key": True,
            "candidate_score_uses_public_forward_execution": True,
            "attacker_valid_full256_recovery": False,
            "reader_refit": False,
            "fresh_targets": 0,
        },
        "target": {
            "target_id": "o1c-0044-fresh-0000",
            "public_view_sha256": public.digest(),
            "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
            "truth_publicly_verified": True,
        },
        "architecture": {
            "score_mode": "complete-forward-assignment-global-potential",
            "residual_selector": beam_config["selector"],
            "residual_variables": list(variables),
            "truth_mask_sha256": hashlib.sha256(
                truth_mask.to_bytes(2, "little")
            ).hexdigest(),
            "candidate_tie_break": beam_config["candidate_tie_break"],
            "potential_sha256": {
                name: sha256_file(paths[f"{name}_potential"]) for name in ARMS
            },
            "truth_score_checks": truth_score_checks,
        },
        "rank": width_metrics,
        "top256_beam": top_beam,
        "metrics": {
            "width16": width_metrics[str(maximum_width)],
            "primary_width16_rank": primary_rank,
            "primary_width16_control_margin": primary_margin,
            "primary_top256_contains_verified_key": verified_top256,
            "rotated_top256_contains_verified_key": controls_contain_key,
            "primary_width16_search_compression_bits": primary16[
                "search_compression_bits"
            ],
            "primary_width16_effective_enumeration_bits": primary16[
                "effective_enumeration_bits"
            ],
        },
        "resources": {
            "elapsed_seconds": elapsed,
            "cpu_seconds": time.process_time() - cpu_started,
            "peak_rss_bytes": peak_rss,
            "forward_evaluations": candidate_count,
            "potential_score_evaluations": candidate_count * len(ARMS),
            "public_verifications": public_verifications,
            "persistent_artifact_bytes": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "score_sha256": {
            name: array_sha256(scores[name], "<f8") for name in ARMS
        },
        "source_sha256": {name: sha256_file(path) for name, path in paths.items()},
        "next_action": config["next_action"],
    }
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
        or candidate_count != int(budgets["maximum_forward_evaluations"])
    ):
        raise O1C47RunError("O1C-0047 resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_global-criticality-residual-beam-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C47RunError("O1C-0047 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    fixed_members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "command.txt": (
            "PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c47_global_criticality_residual_beam_run "
            f"--config {config_file}\n"
        ).encode("utf-8"),
        "config.json": config_file.read_bytes(),
        **score_artifacts,
    }
    members: dict[str, bytes] = {}
    manifest = b""
    for _ in range(4):
        result_bytes = _pretty_json_bytes(result)
        members = {**fixed_members, "result.json": result_bytes}
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
        raise O1C47RunError("persistent artifact byte ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C47RunError("O1C-0047 persistent artifact budget differs")
    capsule.mkdir(parents=True)
    frozen_result_bytes = _atomic_json(capsule / "result.json", result)
    if frozen_result_bytes != members["result.json"]:
        raise O1C47RunError("canonical result bytes changed after ledger freeze")
    for relative, payload in members.items():
        destination = capsule / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if relative != "result.json":
            destination.write_bytes(payload)
    (capsule / "artifacts.sha256").write_bytes(manifest)
    for artifact in sorted(capsule.rglob("*"), reverse=True):
        artifact.chmod(0o555 if artifact.is_dir() else 0o444)
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
    "O1C47RunError",
    "_candidate_key",
    "_nested_masks",
    "_rank_row",
    "load_config",
    "main",
    "run",
]
