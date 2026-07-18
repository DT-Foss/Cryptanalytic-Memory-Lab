"""O1C-0045 frozen parent-criticality reader to exact live-search pilot."""

from __future__ import annotations

import hashlib
import json
import math
import resource
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

from .cadical_sensor import sha256_file
from .criticality_factor_search import (
    CriticalitySearchResult,
    build_native_criticality_search,
    run_criticality_search,
    write_criticality_potential,
)
from .criticality_potential import (
    CriticalityPotentialField,
    compile_criticality_potential,
    score_potential_assignment,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import verify_full256_instance, write_full256_instance
from .full256_forward_assignment import compile_full256_forward_read_plan
from .living_inverse import PublicTargetView, key_bits
from .o1_relational_search import (
    GuidedSearchResult,
    build_native_guided_search,
    model_hamming_distance,
    model_matches_public,
    run_guided_search,
)
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _read_json,
    _relative_path,
    lab_root,
)
from .proof_parent_criticality import (
    ParentCriticalityField,
    requested_parent_criticality_variables,
    transform_parent_criticality_field,
)
from .relation_candidate_rank import array_sha256


ATTEMPT_ID = "O1C-0045"
CONFIG_SCHEMA = "o1-256-criticality-live-search-config-v1"
RESULT_SCHEMA = "o1-256-criticality-live-search-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0045_CRITICALITY_LIVE_SEARCH_RESULT_20260718.json"
)
ARMS = ("internal", "primary", "key_rotated", "clause_rotated")
POTENTIAL_ARMS = ARMS[1:]


class O1C45RunError(RuntimeError):
    """The frozen reader, exact compilation, or matched search differs."""


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C45RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    compilation = _mapping(config.get("compilation"), "compilation")
    search = _mapping(config.get("search"), "search")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "criticality-live-search-v1"
        or config.get("claim_level") != "CONSUMED_SEARCH_DIAGNOSTIC"
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("rounds") != 20
        or target.get("unknown_key_bits") != 256
        or target.get("fresh_targets") != 0
        or compilation.get("reader_weights_sha256")
        != "c4149a4695b13efac42268162f8381956c9616f24f25741abbce8d46be6f4d30"
        or compilation.get("candidate_count") != 4096
        or compilation.get("arms") != list(POTENTIAL_ARMS)
        or compilation.get("maximum_abs_score_error") != 1e-12
        or search.get("arms") != list(ARMS)
        or search.get("conflict_limit") != 512
        or search.get("residual_widths") != [8, 9]
        or search.get("residual_selector")
        != "descending-sum-abs-parent-score-units-then-count-then-coordinate"
        or search.get("prefix_mode") != "post-reveal-correct-key-unit-conditions"
        or search.get("seed") != 0
        or budgets.get("maximum_wall_seconds") != 90
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_candidate_forward_evaluations") != 4097
        or budgets.get("maximum_native_solver_calls") != 12
        or budgets.get("maximum_requested_conflicts") != 6144
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 2097152
    ):
        raise O1C45RunError("frozen O1C-0045 config differs")
    paths = (
        "template",
        "semantic_map",
        "o1c43_result",
        "publication",
        "field",
        "candidate_keys",
        "score_freeze",
        "primary_scores",
        "key_rotated_scores",
        "clause_rotated_scores",
        "o1c44_result",
        "reveal",
        "potential_source",
        "search_adapter",
        "potential_native_source",
        "internal_native_source",
        "runner",
    )
    for name in paths:
        _relative_path(root, source.get(name), f"source.{name}")
        if not isinstance(expected.get(name), str) or len(expected[name]) != 64:
            raise O1C45RunError(f"source hash contract differs for {name}")
    # Reveal and the O1C-0044 scored result are deliberately not opened here.
    for name in paths:
        if name in {"reveal", "o1c44_result"}:
            continue
        resolved = _relative_path(root, source[name], f"source.{name}")
        if sha256_file(resolved) != expected[name]:
            raise O1C45RunError(f"source hash differs for {name}")
    return config


def _integer_group(value: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(count) for name, count in value.items()}


def _public_search_row(
    name: str,
    result: GuidedSearchResult | CriticalitySearchResult,
    public: PublicTargetView,
) -> tuple[dict[str, object], bytes | None]:
    model = result.key_model
    verified = bool(model is not None and model_matches_public(model, public))
    row: dict[str, object] = {
        "name": name,
        "status": result.status_name,
        "conflict_limit": result.conflict_limit,
        "model_publicly_verified": verified,
        "model_sha256": None if model is None else hashlib.sha256(model).hexdigest(),
        "stats": _integer_group(result.stats),
        "resources": _integer_group(result.resources),
    }
    if isinstance(result, CriticalitySearchResult):
        row["potential"] = dict(result.potential)
    return row, model


def _highest_support_key_order(field: ParentCriticalityField) -> tuple[int, ...]:
    support: dict[int, tuple[int, int]] = {}
    for factor in field.factors:
        units, count = support.get(factor.key_variable, (0, 0))
        support[factor.key_variable] = (units + abs(factor.score_units), count + 1)
    return tuple(
        sorted(
            support,
            key=lambda variable: (
                -support[variable][0],
                -support[variable][1],
                variable,
            ),
        )
    )


def _write_prefix_cnf(
    source: Path,
    destination: Path,
    fixed_spins: Mapping[int, int],
) -> dict[str, object]:
    if (
        not fixed_spins
        or len(fixed_spins) != len(set(fixed_spins))
        or any(variable not in range(1, 257) for variable in fixed_spins)
        or any(spin not in (-1, 1) for spin in fixed_spins.values())
    ):
        raise O1C45RunError("oracle prefix assignment differs")
    lines = source.read_bytes().splitlines(keepends=True)
    header_indices = [
        index for index, row in enumerate(lines) if row.startswith(b"p cnf ")
    ]
    if len(header_indices) != 1:
        raise O1C45RunError("public CNF header differs")
    header_index = header_indices[0]
    fields = lines[header_index].split()
    if len(fields) != 4:
        raise O1C45RunError("public CNF header fields differ")
    try:
        variables = int(fields[2])
        clauses = int(fields[3])
    except ValueError as exc:
        raise O1C45RunError("public CNF header encoding differs") from exc
    if variables != 32_128 or clauses < 188_010:
        raise O1C45RunError("public CNF dimensions differ")
    lines[header_index] = f"p cnf {variables} {clauses + len(fixed_spins)}\n".encode(
        "ascii"
    )
    units = b"".join(
        f"{variable if fixed_spins[variable] > 0 else -variable} 0\n".encode(
            "ascii"
        )
        for variable in sorted(fixed_spins)
    )
    payload = b"".join(lines)
    if payload and not payload.endswith(b"\n"):
        payload += b"\n"
    payload += units
    destination.write_bytes(payload)
    return {
        "fixed_key_bits": len(fixed_spins),
        "residual_key_bits": 256 - len(fixed_spins),
        "clause_count": clauses + len(fixed_spins),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _score_equivalence(
    *,
    public: PublicTargetView,
    semantic_map: Path,
    fields: Mapping[str, ParentCriticalityField],
    potentials: Mapping[str, CriticalityPotentialField],
    candidate_keys: Sequence[bytes],
    expected_scores: Mapping[str, np.ndarray],
) -> tuple[dict[str, object], dict[str, np.ndarray], object]:
    plan = compile_full256_forward_read_plan(
        semantic_map, requested_parent_criticality_variables(fields.values())
    )
    actual = {
        name: np.empty(len(candidate_keys), dtype=np.float64)
        for name in POTENTIAL_ARMS
    }
    for index, key in enumerate(candidate_keys):
        assignment = plan.evaluate(
            key=key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        for name in POTENTIAL_ARMS:
            actual[name][index] = score_potential_assignment(
                potentials[name], assignment
            )
    arms: dict[str, object] = {}
    for name in POTENTIAL_ARMS:
        delta = np.abs(actual[name] - expected_scores[name])
        arms[name] = {
            "candidate_count": len(candidate_keys),
            "maximum_abs_error": float(np.max(delta)),
            "mean_abs_error": float(np.mean(delta)),
            "within_1e_12": bool(np.all(delta <= 1e-12)),
            "expected_score_sha256": array_sha256(expected_scores[name], "<f8"),
            "compiled_score_sha256": array_sha256(actual[name], "<f8"),
            "potential": potentials[name].describe(),
        }
    return {
        "schema": "o1-256-criticality-potential-equivalence-v1",
        "arms": arms,
        "all_within_1e_12": all(
            bool(_mapping(arms[name], name)["within_1e_12"])
            for name in POTENTIAL_ARMS
        ),
    }, actual, plan


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Full-256 primary recovery: `{metrics['primary_full256_recovery']}`\n"
        f"- Residual frontier by arm: `{metrics['maximum_recovered_residual_bits_by_arm']}`\n"
        f"- Primary matched-work gain: `{metrics['primary_matched_work_gain']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The O1C-0044 reader is algebraically compiled without refitting. Full-256 "
        "search precedes reveal; residual 8/9 rows are explicit post-reveal ceilings.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected_hashes = _mapping(source["expected_sha256"], "expected_sha256")
    compilation = _mapping(config["compilation"], "compilation")
    search_config = _mapping(config["search"], "search")
    budgets = _mapping(config["budgets"], "budgets")
    paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in source
        if name != "expected_sha256"
    }
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    source_commit = _git_commit(root)

    publication = _read_json(paths["publication"])
    public = public_view_from_publication(publication)
    score_freeze = _read_json(paths["score_freeze"])
    reader_result = _read_json(paths["o1c43_result"])
    reader_row = _mapping(reader_result.get("reader"), "O1C-0043 reader")
    reader = np.asarray(reader_row.get("weights_l2"), dtype=np.float64)
    if (
        reader_result.get("attempt_id") != "O1C-0043"
        or reader.shape != (15,)
        or array_sha256(reader, "<f8")
        != compilation["reader_weights_sha256"]
        or score_freeze.get("target_id") != "o1c-0044-fresh-0000"
        or score_freeze.get("public_view_sha256") != public.digest()
        or score_freeze.get("target_key_reads") != 0
    ):
        raise O1C45RunError("frozen reader or target publication differs")

    natural = ParentCriticalityField.from_bytes(paths["field"].read_bytes())
    fields = {
        "primary": natural,
        "key_rotated": transform_parent_criticality_field(natural, rotate="key"),
        "clause_rotated": transform_parent_criticality_field(
            natural, rotate="clause"
        ),
    }
    freeze_arms = _mapping(score_freeze.get("arms"), "score_freeze.arms")
    potentials: dict[str, CriticalityPotentialField] = {}
    for name in POTENTIAL_ARMS:
        arm = _mapping(freeze_arms.get(name), f"score_freeze.arms.{name}")
        described = _mapping(arm.get("field"), f"{name}.field")
        if fields[name].state_sha256 != described.get("state_sha256"):
            raise O1C45RunError(f"frozen transformed field differs for {name}")
        potentials[name] = compile_criticality_potential(
            fields[name],
            feature_mean=arm.get("feature_mean"),
            feature_std=arm.get("feature_std"),
            reader=reader,
        )

    candidate_payload = paths["candidate_keys"].read_bytes()
    if len(candidate_payload) != 4096 * 32:
        raise O1C45RunError("candidate key panel differs")
    candidate_keys = tuple(
        candidate_payload[offset : offset + 32]
        for offset in range(0, len(candidate_payload), 32)
    )
    expected_scores = {
        name: np.fromfile(paths[f"{name}_scores"], dtype="<f8")
        for name in POTENTIAL_ARMS
    }
    if any(scores.shape != (4096,) for scores in expected_scores.values()):
        raise O1C45RunError("frozen candidate score vector differs")
    equivalence, actual_scores, forward_plan = _score_equivalence(
        public=public,
        semantic_map=paths["semantic_map"],
        fields=fields,
        potentials=potentials,
        candidate_keys=candidate_keys,
        expected_scores=expected_scores,
    )
    if equivalence["all_within_1e_12"] is not True:
        raise O1C45RunError("criticality potential is not the frozen reader")

    key_order = _highest_support_key_order(natural)
    if len(key_order) < max(search_config["residual_widths"]):
        raise O1C45RunError("criticality field has too few active key variables")
    residual_variables = {
        str(width): list(key_order[: int(width)])
        for width in search_config["residual_widths"]
    }

    full_rows: list[dict[str, object]] = []
    full_models: dict[str, bytes | None] = {}
    residual_rows: list[dict[str, object]] = []
    solver_calls = 0
    requested_conflicts = 0
    potential_artifacts = {
        f"potentials/{name}.pot": potentials[name].to_bytes()
        for name in POTENTIAL_ARMS
    }
    with tempfile.TemporaryDirectory(prefix="o1c45-") as temporary:
        workspace = Path(temporary)
        potential_executable = workspace / "cadical-o1-criticality-search"
        internal_executable = workspace / "cadical-o1-guided-search"
        potential_build = build_native_criticality_search(
            source=paths["potential_native_source"], output=potential_executable
        )
        internal_build = build_native_guided_search(
            source=paths["internal_native_source"], output=internal_executable
        )
        cnf = workspace / "o1c44-public.cnf"
        instance = write_full256_instance(
            paths["template"],
            paths["semantic_map"],
            cnf,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
        )
        verification = verify_full256_instance(
            cnf, paths["template"], paths["semantic_map"], instance
        )
        if (
            instance.key_unit_clause_count != 0
            or verification.get("ok") is not True
        ):
            raise O1C45RunError("reinstantiated public Full-256 CNF differs")
        potential_paths: dict[str, Path] = {}
        for name in POTENTIAL_ARMS:
            destination = workspace / f"{name}.pot"
            payload_sha = write_criticality_potential(destination, potentials[name])
            if payload_sha != hashlib.sha256(potential_artifacts[f"potentials/{name}.pot"]).hexdigest():
                raise O1C45RunError(f"serialized potential differs for {name}")
            potential_paths[name] = destination

        conflict_limit = int(search_config["conflict_limit"])
        seed = int(search_config["seed"])
        internal = run_guided_search(
            executable=internal_executable,
            cnf_path=cnf,
            mode="internal",
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=60.0,
        )
        row, model = _public_search_row("internal", internal, public)
        full_rows.append(row)
        full_models["internal"] = model
        solver_calls += 1
        requested_conflicts += conflict_limit
        for name in POTENTIAL_ARMS:
            search = run_criticality_search(
                executable=potential_executable,
                cnf_path=cnf,
                potential_path=potential_paths[name],
                conflict_limit=conflict_limit,
                seed=seed,
                timeout_seconds=60.0,
            )
            row, model = _public_search_row(name, search, public)
            full_rows.append(row)
            full_models[name] = model
            solver_calls += 1
            requested_conflicts += conflict_limit

        attacker_freeze = {
            "schema": "o1-256-criticality-live-search-attacker-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "source_commit": source_commit,
            "target_id": "o1c-0044-fresh-0000",
            "public_view_sha256": public.digest(),
            "target_key_reads": 0,
            "reveal_file_reads": 0,
            "reader_weights_sha256": compilation["reader_weights_sha256"],
            "score_equivalence": equivalence,
            "potential_sha256": {
                name: hashlib.sha256(potential_artifacts[f"potentials/{name}.pot"]).hexdigest()
                for name in POTENTIAL_ARMS
            },
            "residual_key_order": list(key_order),
            "residual_variables": residual_variables,
            "full256_search": full_rows,
        }
        attacker_freeze_bytes = _canonical_bytes(attacker_freeze)
        attacker_freeze_sha256 = hashlib.sha256(attacker_freeze_bytes).hexdigest()

        if sha256_file(paths["reveal"]) != expected_hashes["reveal"] or sha256_file(
            paths["o1c44_result"]
        ) != expected_hashes["o1c44_result"]:
            raise O1C45RunError("post-freeze reveal source hash differs")
        reveal = verify_reveal(_read_json(paths["reveal"]))
        o1c44_result = _read_json(paths["o1c44_result"])
        preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C45RunError("revealed O1C-0044 key encoding differs") from exc
        if (
            len(truth_key) != 32
            or not model_matches_public(truth_key, public)
            or o1c44_result.get("classification")
            != "FRESH_PARENT_CRITICALITY_RANK_TRANSFER"
            or o1c44_result.get("public_view_sha256") != public.digest()
            or o1c44_result.get("instance_sha256") != instance.instance_sha256
        ):
            raise O1C45RunError("consumed O1C-0044 truth boundary differs")

        truth_assignment = forward_plan.evaluate(
            key=truth_key,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
        )
        truth_equivalence: dict[str, object] = {}
        ranks = _mapping(o1c44_result.get("rank"), "O1C-0044 rank")
        for name in POTENTIAL_ARMS:
            actual_truth = score_potential_assignment(
                potentials[name], truth_assignment
            )
            rank_row = _mapping(ranks.get(name), f"rank.{name}")
            expected_truth = float(rank_row["truth_score"])
            rank = 1 + int(np.count_nonzero(actual_scores[name] > actual_truth))
            error = abs(actual_truth - expected_truth)
            truth_equivalence[name] = {
                "actual_truth_score": actual_truth,
                "expected_truth_score": expected_truth,
                "absolute_error": error,
                "compiled_rank": rank,
                "expected_rank": int(rank_row["rank"]),
            }
            if error > float(compilation["maximum_abs_score_error"]) or rank != int(
                rank_row["rank"]
            ):
                raise O1C45RunError(f"truth score compilation differs for {name}")

        truth_spins = {
            index + 1: (1 if bit else -1)
            for index, bit in enumerate(key_bits(truth_key))
        }
        for width in search_config["residual_widths"]:
            width = int(width)
            residual = set(residual_variables[str(width)])
            fixed = {
                variable: spin
                for variable, spin in truth_spins.items()
                if variable not in residual
            }
            residual_cnf = workspace / f"o1c44-residual-{width}.cnf"
            prefix = _write_prefix_cnf(cnf, residual_cnf, fixed)
            internal = run_guided_search(
                executable=internal_executable,
                cnf_path=residual_cnf,
                mode="internal",
                conflict_limit=conflict_limit,
                seed=seed,
                timeout_seconds=60.0,
            )
            row, model = _public_search_row("internal", internal, public)
            row.update(
                {
                    "residual_bits": width,
                    "residual_variables": sorted(residual),
                    "privileged_post_reveal_prefix": True,
                    "prefix": prefix,
                    "model_truth_hamming": (
                        None
                        if model is None
                        else model_hamming_distance(model, truth_key)
                    ),
                }
            )
            residual_rows.append(row)
            solver_calls += 1
            requested_conflicts += conflict_limit
            for name in POTENTIAL_ARMS:
                search = run_criticality_search(
                    executable=potential_executable,
                    cnf_path=residual_cnf,
                    potential_path=potential_paths[name],
                    conflict_limit=conflict_limit,
                    seed=seed,
                    timeout_seconds=60.0,
                )
                row, model = _public_search_row(name, search, public)
                row.update(
                    {
                        "residual_bits": width,
                        "residual_variables": sorted(residual),
                        "privileged_post_reveal_prefix": True,
                        "prefix": prefix,
                        "model_truth_hamming": (
                            None
                            if model is None
                            else model_hamming_distance(model, truth_key)
                        ),
                    }
                )
                residual_rows.append(row)
                solver_calls += 1
                requested_conflicts += conflict_limit

    for row in full_rows:
        model = full_models[str(row["name"])]
        row["model_truth_hamming"] = (
            None if model is None else model_hamming_distance(model, truth_key)
        )
    if (
        solver_calls != int(budgets["maximum_native_solver_calls"])
        or requested_conflicts != int(budgets["maximum_requested_conflicts"])
    ):
        raise O1C45RunError("matched search work ledger differs")

    maximum_by_arm: dict[str, int] = {}
    for name in ARMS:
        maximum_by_arm[name] = max(
            (
                int(row["residual_bits"])
                for row in residual_rows
                if row["name"] == name and row["model_publicly_verified"] is True
            ),
            default=0,
        )
    primary_frontier_gain = maximum_by_arm["primary"] > max(
        maximum_by_arm[name] for name in ARMS if name != "primary"
    )
    shared_widths = [
        int(width)
        for width in search_config["residual_widths"]
        if all(
            any(
                row["name"] == name
                and int(row["residual_bits"]) == int(width)
                and row["model_publicly_verified"] is True
                for row in residual_rows
            )
            for name in ARMS
        )
    ]
    shared_work_width = max(shared_widths, default=0)
    conflict_by_arm_at_shared: dict[str, int] = {}
    if shared_work_width:
        conflict_by_arm_at_shared = {
            name: int(
                next(
                    _mapping(row["stats"], "row.stats")["conflicts"]
                    for row in residual_rows
                    if row["name"] == name
                    and int(row["residual_bits"]) == shared_work_width
                )
            )
            for name in ARMS
        }
    primary_conflict_gain = bool(
        conflict_by_arm_at_shared
        and conflict_by_arm_at_shared["primary"]
        < min(
            conflict_by_arm_at_shared[name]
            for name in ARMS
            if name != "primary"
        )
    )
    primary_full256 = bool(
        next(row for row in full_rows if row["name"] == "primary")[
            "model_publicly_verified"
        ]
    )
    matched_work_gain = bool(
        primary_full256 or primary_frontier_gain or primary_conflict_gain
    )
    if primary_full256:
        classification = "ATTACKER_VALID_FULL256_CRITICALITY_RECOVERY"
    elif primary_frontier_gain:
        classification = "CRITICALITY_EXPANDS_EXACT_RESIDUAL_FRONTIER"
    elif primary_conflict_gain:
        classification = "CRITICALITY_REDUCES_EXACT_RESIDUAL_CONFLICTS"
    elif maximum_by_arm["primary"]:
        classification = "CRITICALITY_MATCHES_EXACT_RESIDUAL_FRONTIER"
    else:
        classification = "CRITICALITY_LIVE_SEARCH_NO_EXACT_GAIN"

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    source_hashes = {
        name: sha256_file(path) for name, path in paths.items()
    }
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": classification,
        "claim_boundary": {
            "reader_refit": False,
            "potential_is_exact_algebraic_reader_compilation": True,
            "full256_search_precedes_reveal": True,
            "full256_unknown_key_bits": 256,
            "full256_search_attacker_valid": True,
            "residual_search_is_post_reveal_ceiling": True,
            "residual_prefix_uses_truth_key": True,
            "fresh_targets": 0,
        },
        "attacker_freeze_sha256": attacker_freeze_sha256,
        "score_equivalence": {
            **equivalence,
            "truth": truth_equivalence,
        },
        "architecture": {
            "reader_weights_sha256": compilation["reader_weights_sha256"],
            "conditional_decision_rule": "sum-local-uniform-marginal-energy-difference",
            "reversible_after_backtrack": True,
            "hard_factor_clauses_added": 0,
            "residual_selector": search_config["residual_selector"],
            "potential_build": potential_build.describe(),
            "internal_build": internal_build.describe(),
            "public_instance": instance.describe(),
        },
        "full256_search": full_rows,
        "residual_search": residual_rows,
        "metrics": {
            "primary_full256_recovery": primary_full256,
            "attacker_valid_full256_recoveries_all_arms": sum(
                int(bool(row["model_publicly_verified"])) for row in full_rows
            ),
            "maximum_recovered_residual_bits_by_arm": maximum_by_arm,
            "primary_residual_frontier_gain": primary_frontier_gain,
            "shared_recovered_work_width": shared_work_width,
            "conflicts_by_arm_at_shared_width": conflict_by_arm_at_shared,
            "primary_residual_conflict_gain": primary_conflict_gain,
            "primary_matched_work_gain": matched_work_gain,
            "compiled_primary_rank": int(
                _mapping(truth_equivalence["primary"], "truth.primary")[
                    "compiled_rank"
                ]
            ),
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
            "candidate_forward_evaluations": 4097,
            "native_solver_calls": solver_calls,
            "requested_conflicts": requested_conflicts,
            "persistent_artifact_bytes": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "source_sha256": source_hashes,
        "next_action": config["next_action"],
    }
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C45RunError("O1C-0045 resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_criticality-live-search-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C45RunError("O1C-0045 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    config_bytes = config_file.read_bytes()
    run_bytes = _markdown(result).encode("utf-8")
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c45_criticality_live_search_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    fixed_members: dict[str, bytes] = {
        "RUN.md": run_bytes,
        "attacker_freeze.json": attacker_freeze_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        **potential_artifacts,
    }
    members: dict[str, bytes] = {}
    manifest = b""
    for _ in range(4):
        result_bytes = _canonical_bytes(result)
        members = {**fixed_members, "result.json": result_bytes}
        manifest = "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in sorted(members.items())
        ).encode("ascii")
        persistent_bytes = sum(len(payload) for payload in members.values()) + len(
            manifest
        )
        if (
            result["resources"]["persistent_artifact_bytes"]
            == persistent_bytes
        ):
            break
        result["resources"]["persistent_artifact_bytes"] = persistent_bytes
    else:
        raise O1C45RunError("persistent artifact byte ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C45RunError("O1C-0045 persistent artifact budget differs")
    capsule.mkdir(parents=True)
    frozen_result_bytes = _atomic_json(capsule / "result.json", result)
    if frozen_result_bytes != members["result.json"]:
        raise O1C45RunError("canonical result bytes changed after ledger freeze")
    for relative, payload in members.items():
        destination = capsule / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if relative != "result.json":
            destination.write_bytes(payload)
    (capsule / "artifacts.sha256").write_bytes(manifest)
    for path in sorted(capsule.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
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


__all__ = ["ATTEMPT_ID", "O1C45RunError", "load_config", "main", "run"]
