"""O1C-0039 held-out proof-clause relation and exact-search experiment."""

from __future__ import annotations

import hashlib
import json
import resource
import subprocess
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
from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import PublicTargetView, bits_to_key
from .o1_factor_search import (
    build_native_factor_search,
    run_factor_search,
    write_factor_field,
)
from .o1_relational_search import (
    build_native_guided_search,
    model_matches_public,
    run_guided_search,
)
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _mapping,
    _public_view,
    _read_json,
    _relative_path,
    lab_root,
)
from .proof_clause_relations import (
    ClauseRelationField,
    coordinate_control_field,
    extract_clause_relation_field,
    highest_degree_key_residual,
    score_relation_field,
)


ATTEMPT_ID = "O1C-0039"
CONFIG_SCHEMA = "o1-256-proof-clause-relation-transfer-config-v1"
RESULT_SCHEMA = "o1-256-proof-clause-relation-transfer-result-v1"
RESULT_RELATIVE = Path("research/O1C0039_PROOF_CLAUSE_RELATION_RESULT_20260718.json")
CADICAL_HEADER_SHA256 = (
    "b7111690c61935b9c096d3701be59b3c3d26c555eab8e070f19eb2a97dc5d38c"
)
CADICAL_LIBRARY_SHA256 = (
    "44cae3728485b4fd5736ce7cb986021236652daeda9cca227a2c4ac17d3a8a7f"
)


class O1C39RunError(RuntimeError):
    """The frozen O1C-0039 contract, lifecycle, or result differs."""


def _peak_rss_bytes() -> int:
    own = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    children = int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    if own <= 16 * 1024 * 1024:
        own *= 1024
    if children <= 16 * 1024 * 1024:
        children *= 1024
    return max(own, children)


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C39RunError("config escapes the lab")
    config = _read_json(config_path)
    selection = _mapping(config.get("selection_freeze"), "selection_freeze")
    relation = _mapping(config.get("exact_relation"), "exact_relation")
    field = _mapping(config.get("field"), "field")
    search = _mapping(config.get("search"), "search")
    budgets = _mapping(config.get("budgets"), "budgets")
    targets = config.get("targets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "proof-clause-relation-transfer-v1"
        or config.get("claim_level") != "TEST"
        or selection.get("source_targets")
        != ["build-0000", "build-0001", "build-0002", "build-0003"]
        or selection.get("source_pooled_correct") != 595
        or selection.get("source_pooled_edges") != 1045
        or selection.get("selected_conflict_horizon") != 16
        or selection.get("unit_scale") != 6
        or selection.get("selected_abs_units") != 3
        or selection.get("no_other_horizon_or_weight_arm") is not True
        or not isinstance(targets, list)
        or len(targets) != 2
        or [dict(_mapping(row, "target")).get("target_id") for row in targets]
        != ["development-0000", "development-0001"]
        or [dict(_mapping(row, "target")).get("label_index") for row in targets]
        != [0, 1]
        or field.get("conflict_horizon") != 16
        or field.get("selected_abs_units") != 3
        or field.get("capacity") != 4096
        or field.get("seed") != 0
        or search.get("conflict_limit") != 512
        or search.get("residual_bits") != 9
        or search.get("residual_selector")
        != "highest_relation_degree_then_key_coordinate"
        or search.get("oracle_anchor_variable") != 257
        or search.get("oracle_anchor_max_magnitude") != 4096
        or search.get("seed") != 0
        or budgets.get("maximum_wall_seconds") != 120
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_probe_branches") != 1024
        or budgets.get("maximum_exact_solver_calls") != 18
        or budgets.get("maximum_factor_search_calls") != 14
        or budgets.get("maximum_internal_search_calls") != 2
        or budgets.get("maximum_truth_model_calls") != 2
        or budgets.get("maximum_requested_conflicts") != 8192
        or budgets.get("maximum_persistent_artifact_bytes") != 1048576
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
    ):
        raise O1C39RunError("frozen O1C-0039 config differs")
    _relative_path(root, config.get("source_result"), "source_result")
    _relative_path(root, config.get("labels"), "labels")
    for row in targets:
        target = _mapping(row, "target")
        _relative_path(root, target.get("sidecar"), "target.sidecar")
    for name in (
        "template",
        "semantic_map",
        "sensor_source",
        "tracer_header",
        "factor_search_source",
        "internal_search_source",
    ):
        _relative_path(root, relation.get(name), f"exact_relation.{name}")
    cli = relation.get("cadical_cli")
    if not isinstance(cli, str) or Path(cli).resolve(strict=True) != Path(
        "/opt/homebrew/bin/cadical"
    ).resolve(strict=True):
        raise O1C39RunError("CaDiCaL CLI path differs")
    return config


def _integer_group(value: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(count) for name, count in value.items()}


def _search_row(name: str, result, public: PublicTargetView) -> dict[str, object]:
    verified = bool(
        result.key_model is not None and model_matches_public(result.key_model, public)
    )
    return {
        "name": name,
        "status": result.status_name,
        "model_publicly_verified": verified,
        "model_sha256": (
            None
            if result.key_model is None
            else hashlib.sha256(result.key_model).hexdigest()
        ),
        "stats": _integer_group(result.stats),
        "factor": _integer_group(result.factor),
        "resources": _integer_group(result.resources),
    }


def _internal_row(result, public: PublicTargetView) -> dict[str, object]:
    verified = bool(
        result.key_model is not None and model_matches_public(result.key_model, public)
    )
    return {
        "name": "internal",
        "status": result.status_name,
        "model_publicly_verified": verified,
        "model_sha256": (
            None
            if result.key_model is None
            else hashlib.sha256(result.key_model).hexdigest()
        ),
        "stats": _integer_group(result.stats),
        "resources": _integer_group(result.resources),
    }


def _write_factor_rows(path: Path, rows: list[tuple[int, int, int]]) -> str:
    combined: dict[tuple[int, int], int] = {}
    for left, right, weight in rows:
        if (
            not 1 <= left <= 256
            or not 1 <= right <= 32_128
            or left == right
            or not -32_768 <= weight <= 32_767
            or weight == 0
        ):
            raise O1C39RunError("combined factor rows differ")
        pair = (left, right)
        combined[pair] = combined.get(pair, 0) + weight
    ordered = sorted(
        (left, right, weight) for (left, right), weight in combined.items() if weight
    )
    if not ordered or any(not -32_768 <= weight <= 32_767 for _, _, weight in ordered):
        raise O1C39RunError("combined factor rows differ")
    payload = "".join(
        f"{left} {right} {weight}\n" for left, right, weight in ordered
    ).encode("ascii")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _truth_model(
    *,
    cli: Path,
    fixed_cnf: Path,
    solution_path: Path,
    truth_key: bytes,
) -> dict[int, int]:
    version = subprocess.run(
        [str(cli), "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if version != "3.0.0":
        raise O1C39RunError("CaDiCaL CLI version differs")
    completed = subprocess.run(
        [str(cli), "--plain", "-q", "-w", str(solution_path), str(fixed_cnf)],
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    if completed.returncode != 10:
        raise O1C39RunError("fixed-key truth model did not solve SAT")
    literals: list[int] = []
    for line in solution_path.read_text(encoding="ascii").splitlines():
        if line.startswith("v "):
            literals.extend(int(item) for item in line.split()[1:] if item != "0")
    assignment = {abs(literal): 1 if literal > 0 else -1 for literal in literals}
    if set(assignment) != set(range(1, 32_129)):
        raise O1C39RunError("truth model variable coverage differs")
    model_key = bytes(
        sum((1 << bit) if assignment[8 * byte + bit + 1] > 0 else 0 for bit in range(8))
        for byte in range(32)
    )
    if model_key != truth_key:
        raise O1C39RunError("truth model key differs")
    return assignment


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Status: `completed`\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Pooled primary relation accuracy: "
        f"`{metrics['pooled_primary_relation_accuracy']}`\n"
        f"- DEVELOPMENT targets above 50%: "
        f"`{metrics['targets_primary_above_chance']}/2`\n"
        f"- Exact residual-9 primary recoveries: "
        f"`{metrics['residual9_primary_exact_recoveries']}/2`\n"
        f"- Attacker-valid full256 recoveries: "
        f"`{metrics['attacker_valid_full256_exact_recoveries']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n\n"
        "Relation fields and full256 search arms freeze before labels. Residual-9 "
        "arms are explicit post-reveal mechanism ceilings.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    relation = _mapping(config["exact_relation"], "exact_relation")
    field_config = _mapping(config["field"], "field")
    search = _mapping(config["search"], "search")
    budgets = _mapping(config["budgets"], "budgets")
    targets_config = config["targets"]
    if not isinstance(targets_config, list):
        raise O1C39RunError("target list differs")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)

    template = _relative_path(root, relation["template"], "template")
    semantic_map = _relative_path(root, relation["semantic_map"], "semantic_map")
    sensor_source = _relative_path(root, relation["sensor_source"], "sensor_source")
    tracer_header = _relative_path(root, relation["tracer_header"], "tracer_header")
    factor_source = _relative_path(
        root, relation["factor_search_source"], "factor_search_source"
    )
    internal_source = _relative_path(
        root, relation["internal_search_source"], "internal_search_source"
    )
    source_result_path = _relative_path(root, config["source_result"], "source_result")
    labels_path = _relative_path(root, config["labels"], "labels")
    cadical_cli = Path(str(relation["cadical_cli"])).resolve(strict=True)

    source_result = _read_json(source_result_path)
    pools = source_result.get("pools")
    if not isinstance(pools, list):
        raise O1C39RunError("source pool inventory differs")
    source_pool_ids = [
        str(_mapping(row, "source pool").get("target_id")) for row in pools
    ]
    if source_pool_ids[-2:] != ["development-0000", "development-0001"]:
        raise O1C39RunError("source DEVELOPMENT inventory differs")

    source_paths: dict[str, Path] = {
        "config": config_file,
        "runner": Path(__file__).resolve(),
        "field_module": root / "src/o1_crypto_lab/proof_clause_relations.py",
        "factor_adapter": root / "src/o1_crypto_lab/o1_factor_search.py",
        "sensor_adapter": root / "src/o1_crypto_lab/cadical_sensor.py",
        "sensor_source": sensor_source,
        "tracer_header": tracer_header,
        "factor_search_source": factor_source,
        "internal_search_source": internal_source,
        "template": template,
        "semantic_map": semantic_map,
        "source_result": source_result_path,
        "labels": labels_path,
        "cadical_cli": cadical_cli,
    }

    target_runtime: list[dict[str, object]] = []
    factor_search_calls = internal_search_calls = truth_model_calls = 0
    requested_conflicts = native_probe_branches = 0
    with tempfile.TemporaryDirectory(prefix="o1c39-") as temporary:
        workspace = Path(temporary)
        sensor_executable = workspace / "cadical-pair-sensor"
        factor_executable = workspace / "cadical-factor-search"
        internal_executable = workspace / "cadical-internal-search"
        sensor_build = build_native_sensor(
            source=sensor_source,
            tracer_header=tracer_header,
            cadical_include="/opt/homebrew/opt/cadical/include",
            cadical_library="/opt/homebrew/opt/cadical/lib/libcadical.a",
            output=sensor_executable,
            expected_cadical_header_sha256=CADICAL_HEADER_SHA256,
            expected_cadical_library_sha256=CADICAL_LIBRARY_SHA256,
        )
        factor_build = build_native_factor_search(
            source=factor_source, output=factor_executable
        )
        internal_build = build_native_guided_search(
            source=internal_source, output=internal_executable
        )

        # Attacker-valid phase: fields, controls, residual coordinates and all
        # full256 search outputs freeze before the label file is opened.
        for target_raw in targets_config:
            target_config = _mapping(target_raw, "target")
            target_id = str(target_config["target_id"])
            sidecar_path = _relative_path(
                root, target_config["sidecar"], f"{target_id}.sidecar"
            )
            source_paths[f"sidecar_{target_id}"] = sidecar_path
            sidecar = _read_json(sidecar_path)
            pool = _mapping(sidecar.get("pool"), f"{target_id}.pool")
            public = _public_view(pool.get("public_view"))
            if (
                sidecar.get("target_id") != target_id
                or sidecar.get("public_view_sha256") != public.digest()
                or sidecar.get("labels_materialized") != 0
                or sidecar.get("target_key_inputs_to_probe") != 0
            ):
                raise O1C39RunError("public DEVELOPMENT boundary differs")
            cnf = workspace / f"{target_id}.cnf"
            instance = write_full256_instance(
                template,
                semantic_map,
                cnf,
                counter=public.counter_schedule[0],
                nonce=public.nonce,
                output=public.output_blocks[0],
            )
            verification = verify_full256_instance(
                cnf, template, semantic_map, instance
            )
            source_instance = _mapping(pool.get("instance"), "pool.instance")
            if (
                instance.instance_sha256 != source_instance.get("instance_sha256")
                or instance.key_unit_clause_count != 0
                or verification.get("ok") is not True
            ):
                raise O1C39RunError("reinstantiated public target differs")
            stream = iter_native_probe_records(
                executable=sensor_executable,
                cnf_path=cnf,
                first_bit=0,
                last_bit=255,
                conflict_limit=int(field_config["conflict_horizon"]),
                seed=int(field_config["seed"]),
                timeout_seconds=120.0,
            )
            header, pairs = paired_records(iter(stream))
            if header.variables != 32_128 or header.original_clause_count != 188_010:
                raise O1C39RunError("native probe header differs")
            field = extract_clause_relation_field(
                pairs,
                conflict_horizon=int(field_config["conflict_horizon"]),
                selected_abs_units=int(field_config["selected_abs_units"]),
                capacity=int(field_config["capacity"]),
            )
            native_probe_branches += 512
            usable = (
                bool(field.edges)
                and len({edge.key_variable for edge in field.edges})
                >= int(search["residual_bits"])
                and len({edge.factor_variable for edge in field.edges}) >= 2
            )
            controls: dict[str, ClauseRelationField] = {}
            residual: tuple[int, ...] = ()
            full_rows: list[dict[str, object]] = []
            internal = run_guided_search(
                executable=internal_executable,
                cnf_path=cnf,
                mode="internal",
                conflict_limit=int(search["conflict_limit"]),
                seed=int(search["seed"]),
                timeout_seconds=60.0,
            )
            internal_search_calls += 1
            requested_conflicts += int(search["conflict_limit"])
            full_rows.append(_internal_row(internal, public))
            if usable:
                controls = {
                    "primary": field,
                    "key_rotated": coordinate_control_field(field, rotate="key"),
                    "factor_rotated": coordinate_control_field(field, rotate="factor"),
                }
                residual = highest_degree_key_residual(
                    field, residual_bits=int(search["residual_bits"])
                )
                for name, arm_field in controls.items():
                    factor_path = workspace / f"{target_id}-{name}.factors"
                    write_factor_field(factor_path, arm_field)
                    factor_result = run_factor_search(
                        executable=factor_executable,
                        cnf_path=cnf,
                        factors_path=factor_path,
                        conflict_limit=int(search["conflict_limit"]),
                        seed=int(search["seed"]),
                        timeout_seconds=60.0,
                    )
                    factor_search_calls += 1
                    requested_conflicts += int(search["conflict_limit"])
                    full_rows.append(_search_row(name, factor_result, public))
            field_path = workspace / f"{target_id}.field.bin"
            field_path.write_bytes(field.to_bytes())
            target_runtime.append(
                {
                    "target_id": target_id,
                    "label_index": int(target_config["label_index"]),
                    "public": public,
                    "cnf": cnf,
                    "instance": instance,
                    "field": field,
                    "controls": controls,
                    "field_bytes": field.to_bytes(),
                    "field_usable": usable,
                    "residual_variables": residual,
                    "full256_search": full_rows,
                }
            )

        attacker_freeze = {
            "schema": "o1-256-proof-clause-relation-attacker-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "target_key_reads": 0,
            "label_file_reads": 0,
            "targets": [
                {
                    "target_id": row["target_id"],
                    "public_view_sha256": row["public"].digest(),
                    "field": row["field"].describe(),
                    "field_usable": row["field_usable"],
                    "residual_variables": list(row["residual_variables"]),
                    "full256_search": row["full256_search"],
                }
                for row in target_runtime
            ],
        }
        freeze_bytes = (
            json.dumps(attacker_freeze, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        freeze_sha256 = hashlib.sha256(freeze_bytes).hexdigest()
        (workspace / "attacker_freeze.json").write_bytes(freeze_bytes)

        # Reveal phase begins only after both target fields and full256 search
        # outputs have immutable byte commitments in the attacker freeze.
        labels_raw = labels_path.read_bytes()
        labels = np.unpackbits(
            np.frombuffer(labels_raw, dtype=np.uint8), bitorder="little"
        )
        if labels.shape != (2 * 256,):
            raise O1C39RunError("DEVELOPMENT label artifact shape differs")
        labels = labels.reshape(2, 256)
        scored_targets: list[dict[str, object]] = []
        for row in target_runtime:
            target_id = str(row["target_id"])
            label_index = int(row["label_index"])
            truth_bits = labels[label_index]
            truth_key = bits_to_key(truth_bits)
            public = row["public"]
            if not isinstance(public, PublicTargetView) or not model_matches_public(
                truth_key, public
            ):
                raise O1C39RunError("revealed key does not match public target")
            fixed_cnf = workspace / f"{target_id}.fixed.cnf"
            write_full256_instance(
                template,
                semantic_map,
                fixed_cnf,
                counter=public.counter_schedule[0],
                nonce=public.nonce,
                output=public.output_blocks[0],
                key_for_self_test=truth_key,
            )
            assignment = _truth_model(
                cli=cadical_cli,
                fixed_cnf=fixed_cnf,
                solution_path=workspace / f"{target_id}.solution",
                truth_key=truth_key,
            )
            truth_model_calls += 1
            field = row["field"]
            if not isinstance(field, ClauseRelationField):
                raise O1C39RunError("runtime relation field differs")
            relation_score = (
                score_relation_field(field, assignment) if field.edges else None
            )
            residual_rows: list[dict[str, object]] = []
            if bool(row["field_usable"]):
                residual = set(row["residual_variables"])
                prefix = [
                    variable for variable in range(1, 257) if variable not in residual
                ]
                if len(prefix) != 247:
                    raise O1C39RunError("oracle residual prefix width differs")
                anchor_variable = int(search["oracle_anchor_variable"])
                public_spin = assignment[anchor_variable]
                anchors = [
                    (
                        variable,
                        anchor_variable,
                        (int(search["oracle_anchor_max_magnitude"]) - rank)
                        * assignment[variable]
                        * public_spin,
                    )
                    for rank, variable in enumerate(prefix)
                ]
                arm_rows: dict[str, list[tuple[int, int, int]]] = {"hint_only": anchors}
                controls = row["controls"]
                if not isinstance(controls, Mapping):
                    raise O1C39RunError("runtime controls differ")
                for name, arm_field in controls.items():
                    if not isinstance(arm_field, ClauseRelationField):
                        raise O1C39RunError("runtime control field differs")
                    arm_rows[str(name)] = anchors + [
                        (
                            edge.key_variable,
                            edge.factor_variable,
                            edge.score_units,
                        )
                        for edge in arm_field.edges
                    ]
                for name, factors in arm_rows.items():
                    factors_path = workspace / f"{target_id}-residual-{name}.factors"
                    factor_sha = _write_factor_rows(factors_path, factors)
                    search_result = run_factor_search(
                        executable=factor_executable,
                        cnf_path=row["cnf"],
                        factors_path=factors_path,
                        conflict_limit=int(search["conflict_limit"]),
                        seed=int(search["seed"]),
                        timeout_seconds=60.0,
                    )
                    factor_search_calls += 1
                    requested_conflicts += int(search["conflict_limit"])
                    result_row = _search_row(name, search_result, public)
                    result_row["factor_file_sha256"] = factor_sha
                    result_row["privileged_post_reveal_oracle_prefix"] = True
                    result_row["oracle_correct_prefix_bits"] = 247
                    result_row["residual_bits"] = 9
                    residual_rows.append(result_row)
            scored_targets.append(
                {
                    "target_id": target_id,
                    "public_view_sha256": public.digest(),
                    "truth_key_sha256": hashlib.sha256(truth_key).hexdigest(),
                    "field": field.describe(),
                    "relation_score": relation_score,
                    "residual_variables": list(row["residual_variables"]),
                    "full256_search": row["full256_search"],
                    "residual9_search": residual_rows,
                }
            )

        field_artifacts = {
            f"fields/{row['target_id']}.bin": row["field_bytes"]
            for row in target_runtime
        }

    exact_solver_calls = factor_search_calls + internal_search_calls + truth_model_calls
    if (
        native_probe_branches > int(budgets["maximum_native_probe_branches"])
        or exact_solver_calls > int(budgets["maximum_exact_solver_calls"])
        or factor_search_calls > int(budgets["maximum_factor_search_calls"])
        or internal_search_calls > int(budgets["maximum_internal_search_calls"])
        or truth_model_calls > int(budgets["maximum_truth_model_calls"])
        or requested_conflicts > int(budgets["maximum_requested_conflicts"])
    ):
        raise O1C39RunError("O1C-0039 work ledger exceeds budget")

    score_rows = [
        _mapping(row["relation_score"], "relation_score")
        for row in scored_targets
        if row["relation_score"] is not None
    ]
    total_edges = sum(int(row["edge_count"]) for row in score_rows)
    pooled_primary_correct = sum(int(row["primary_correct"]) for row in score_rows)
    pooled_key_correct = sum(int(row["key_rotated_correct"]) for row in score_rows)
    pooled_factor_correct = sum(
        int(row["factor_rotated_correct"]) for row in score_rows
    )
    pooled_primary = pooled_primary_correct / total_edges if total_edges else 0.0
    pooled_key = pooled_key_correct / total_edges if total_edges else 0.0
    pooled_factor = pooled_factor_correct / total_edges if total_edges else 0.0
    each_above = sum(float(row["primary_accuracy"]) > 0.5 for row in score_rows)
    relation_transfer = bool(
        len(score_rows) == 2
        and each_above == 2
        and pooled_primary > max(0.5, pooled_key, pooled_factor)
    )
    residual_primary_hits = residual_hint_hits = residual_control_hits = 0
    attacker_hits = 0
    for target in scored_targets:
        for arm in target["full256_search"]:
            if bool(_mapping(arm, "full arm")["model_publicly_verified"]):
                attacker_hits += 1
        for arm in target["residual9_search"]:
            arm_row = _mapping(arm, "residual arm")
            if not bool(arm_row["model_publicly_verified"]):
                continue
            if arm_row["name"] == "primary":
                residual_primary_hits += 1
            elif arm_row["name"] == "hint_only":
                residual_hint_hits += 1
            else:
                residual_control_hits += 1
    completion_lift = bool(
        residual_primary_hits > residual_hint_hits
        and residual_primary_hits > residual_control_hits
    )
    if relation_transfer and completion_lift:
        classification = "RELATION_TRANSFER_AND_EXACT_COMPLETION_LIFT"
    elif relation_transfer:
        classification = "RELATION_TRANSFER_ONLY"
    elif completion_lift:
        classification = "EXACT_COMPLETION_LIFT_WITHOUT_RELATION_TRANSFER"
    else:
        classification = "H16_HALF_UNIT_RELATION_NOT_TRANSFERRED"

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    source_hashes = {name: sha256_file(path) for name, path in source_paths.items()}
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": _git_commit(root),
        "classification": classification,
        "claim_boundary": {
            "relation_fields_and_full256_search_are_attacker_valid": True,
            "target_key_bits_unknown_during_field_extraction": 256,
            "target_labels_opened_after_attacker_freeze": True,
            "residual9_search_uses_explicit_post_reveal_oracle_prefix": True,
            "fresh_targets": 0,
        },
        "selection_freeze": config["selection_freeze"],
        "attacker_freeze_sha256": freeze_sha256,
        "targets": scored_targets,
        "metrics": {
            "pooled_relation_edges": total_edges,
            "pooled_primary_relation_correct": pooled_primary_correct,
            "pooled_primary_relation_accuracy": pooled_primary,
            "pooled_key_rotated_accuracy": pooled_key,
            "pooled_factor_rotated_accuracy": pooled_factor,
            "targets_primary_above_chance": each_above,
            "relation_transfer": relation_transfer,
            "residual9_primary_exact_recoveries": residual_primary_hits,
            "residual9_hint_only_exact_recoveries": residual_hint_hits,
            "residual9_rotation_control_exact_recoveries": residual_control_hits,
            "exact_completion_lift": completion_lift,
            "attacker_valid_full256_exact_recoveries": attacker_hits,
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
            "factor_search_calls": factor_search_calls,
            "internal_search_calls": internal_search_calls,
            "truth_model_calls": truth_model_calls,
            "exact_solver_calls": exact_solver_calls,
            "requested_conflicts": requested_conflicts,
            "persistent_artifact_bytes": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "native_builds": {
            "sensor": sensor_build.describe(),
            "factor": factor_build.describe(),
            "internal": internal_build.describe(),
        },
        "source_sha256": source_hashes,
        "next_action": config["next_action"],
    }
    if elapsed > float(budgets["maximum_wall_seconds"]) or peak_rss > int(
        budgets["maximum_peak_rss_bytes"]
    ):
        raise O1C39RunError("O1C-0039 resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_proof-clause-relation-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C39RunError("O1C-0039 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    capsule.mkdir(parents=True)
    config_bytes = config_file.read_bytes()
    (capsule / "config.json").write_bytes(config_bytes)
    (capsule / "attacker_freeze.json").write_bytes(freeze_bytes)
    for relative, payload in field_artifacts.items():
        destination = capsule / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    run_bytes = _markdown(result).encode("utf-8")
    (capsule / "RUN.md").write_bytes(run_bytes)
    command_bytes = (
        "PYTHONPATH=src python3 -m "
        "o1_crypto_lab.o1c39_proof_clause_relation_transfer_run "
        f"--config {config_file}\n"
    ).encode("utf-8")
    (capsule / "command.txt").write_bytes(command_bytes)
    members: dict[str, bytes] = {
        "RUN.md": run_bytes,
        "attacker_freeze.json": freeze_bytes,
        "command.txt": command_bytes,
        "config.json": config_bytes,
        **field_artifacts,
    }
    # The result contains its own artifact-byte ledger. Iterate that tiny
    # self-reference to a fixed point before sealing the immutable capsule.
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
        raise O1C39RunError("persistent artifact ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C39RunError("persistent artifact budget differs")
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


__all__ = ["ATTEMPT_ID", "O1C39RunError", "load_config", "main", "run"]
