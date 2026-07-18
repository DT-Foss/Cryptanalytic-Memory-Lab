"""O1C-0046 key-coordinate-only use of the frozen criticality potential."""

from __future__ import annotations

import hashlib
import json
import resource
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping

from .cadical_sensor import sha256_file
from .criticality_factor_search import (
    CriticalitySearchResult,
    build_native_criticality_search,
    run_criticality_search,
    write_decision_variables,
)
from .criticality_potential import CriticalityPotentialField
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import verify_full256_instance, write_full256_instance
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
from .o1c45_criticality_live_search_run import (
    _canonical_bytes,
    _highest_support_key_order,
    _pretty_json_bytes,
    _public_search_row,
    _write_prefix_cnf,
)
from .proof_parent_criticality import (
    ParentCriticalityField,
    transform_parent_criticality_field,
)


ATTEMPT_ID = "O1C-0046"
CONFIG_SCHEMA = "o1-256-key-only-criticality-search-config-v1"
RESULT_SCHEMA = "o1-256-key-only-criticality-search-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0046_KEY_ONLY_CRITICALITY_SEARCH_RESULT_20260719.json"
)
ARMS = ("internal", "primary", "key_rotated", "clause_rotated")
POTENTIAL_ARMS = ARMS[1:]


class O1C46RunError(RuntimeError):
    """The frozen potential, explicit decision scope, or matched work differs."""


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C46RunError("config escapes lab")
    config = _read_json(config_path)
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "expected_sha256")
    target = _mapping(config.get("target"), "target")
    search = _mapping(config.get("search"), "search")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "key-only-criticality-search-v1"
        or config.get("claim_level") != "CONSUMED_SEARCH_DIAGNOSTIC"
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("rounds") != 20
        or target.get("unknown_key_bits") != 256
        or target.get("fresh_targets") != 0
        or search.get("arms") != list(ARMS)
        or search.get("conflict_limit") != 512
        or search.get("residual_widths") != [8, 9]
        or search.get("decision_scope")
        != "transformed-field-key-variables-only"
        or search.get("residual_selector")
        != "descending-sum-abs-parent-score-units-then-count-then-coordinate"
        or search.get("prefix_mode")
        != "post-reveal-correct-key-unit-conditions"
        or search.get("seed") != 0
        or budgets.get("maximum_wall_seconds") != 90
        or budgets.get("maximum_peak_rss_bytes") != 536870912
        or budgets.get("maximum_native_solver_calls") != 12
        or budgets.get("maximum_requested_conflicts") != 6144
        or budgets.get("maximum_fresh_targets") != 0
        or budgets.get("maximum_sibling_reads") != 0
        or budgets.get("maximum_sibling_writes") != 0
        or budgets.get("maximum_mps_calls") != 0
        or budgets.get("maximum_gpu_calls") != 0
        or budgets.get("maximum_persistent_artifact_bytes") != 1048576
    ):
        raise O1C46RunError("frozen O1C-0046 config differs")
    names = (
        "template",
        "semantic_map",
        "publication",
        "field",
        "reveal",
        "o1c45_result",
        "primary_potential",
        "key_rotated_potential",
        "clause_rotated_potential",
        "search_adapter",
        "potential_native_source",
        "internal_native_source",
        "runner",
    )
    for name in names:
        resolved = _relative_path(root, source.get(name), f"source.{name}")
        if not isinstance(expected.get(name), str) or len(expected[name]) != 64:
            raise O1C46RunError(f"source hash contract differs for {name}")
        if name not in {"reveal", "o1c45_result"} and sha256_file(resolved) != expected[name]:
            raise O1C46RunError(f"source hash differs for {name}")
    return config


def _run_public_search(
    *,
    name: str,
    public: PublicTargetView,
    cnf: Path,
    conflict_limit: int,
    seed: int,
    internal_executable: Path,
    potential_executable: Path,
    potential_paths: Mapping[str, Path],
    decision_paths: Mapping[str, Path],
) -> tuple[dict[str, object], bytes | None]:
    result: GuidedSearchResult | CriticalitySearchResult
    if name == "internal":
        result = run_guided_search(
            executable=internal_executable,
            cnf_path=cnf,
            mode="internal",
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=60.0,
        )
    else:
        result = run_criticality_search(
            executable=potential_executable,
            cnf_path=cnf,
            potential_path=potential_paths[name],
            decision_variables_path=decision_paths[name],
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=60.0,
        )
    return _public_search_row(name, result, public)


def _maximum_recovered_width(
    rows: list[dict[str, object]], name: str
) -> int:
    return max(
        (
            int(row["residual_bits"])
            for row in rows
            if row["name"] == name and row["model_publicly_verified"] is True
        ),
        default=0,
    )


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
        "All factor variables remain observed, while the external rule may decide "
        "only the frozen field's designated key coordinates. Full-256 rows precede "
        "reveal; residual rows are explicit post-reveal ceilings.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected_hashes = _mapping(source["expected_sha256"], "expected_sha256")
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
        for name in POTENTIAL_ARMS
    }
    decision_variables = {
        name: tuple(sorted({factor.key_variable for factor in fields[name].factors}))
        for name in POTENTIAL_ARMS
    }
    for name in POTENTIAL_ARMS:
        observed = {
            variable
            for factor in potentials[name].factors
            for variable in factor.variables
        }
        if (
            not decision_variables[name]
            or not set(decision_variables[name]).issubset(observed)
            or any(variable not in range(1, 257) for variable in decision_variables[name])
        ):
            raise O1C46RunError(f"explicit decision scope differs for {name}")

    key_order = _highest_support_key_order(natural)
    residual_variables = {
        str(width): list(key_order[: int(width)])
        for width in search_config["residual_widths"]
    }
    if any(len(values) != int(width) for width, values in residual_variables.items()):
        raise O1C46RunError("residual variable order differs")

    full_rows: list[dict[str, object]] = []
    full_models: dict[str, bytes | None] = {}
    residual_rows: list[dict[str, object]] = []
    solver_calls = 0
    requested_conflicts = 0
    decision_artifacts: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="o1c46-") as temporary:
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
        if instance.key_unit_clause_count != 0 or verification.get("ok") is not True:
            raise O1C46RunError("reinstantiated public Full-256 CNF differs")

        potential_paths = {name: paths[f"{name}_potential"] for name in POTENTIAL_ARMS}
        decision_paths: dict[str, Path] = {}
        decision_hashes: dict[str, str] = {}
        for name in POTENTIAL_ARMS:
            destination = workspace / f"{name}.decision-vars"
            decision_hashes[name] = write_decision_variables(
                destination, decision_variables[name]
            )
            decision_artifacts[f"decision_variables/{name}.txt"] = destination.read_bytes()
            decision_paths[name] = destination

        conflict_limit = int(search_config["conflict_limit"])
        seed = int(search_config["seed"])
        for name in ARMS:
            row, model = _run_public_search(
                name=name,
                public=public,
                cnf=cnf,
                conflict_limit=conflict_limit,
                seed=seed,
                internal_executable=internal_executable,
                potential_executable=potential_executable,
                potential_paths=potential_paths,
                decision_paths=decision_paths,
            )
            if name != "internal":
                potential_row = _mapping(row.get("potential"), f"{name}.potential")
                if (
                    potential_row.get("decision_scope") != "explicit"
                    or potential_row.get("eligible_decision_variables")
                    != len(decision_variables[name])
                ):
                    raise O1C46RunError(f"native explicit scope differs for {name}")
            full_rows.append(row)
            full_models[name] = model
            solver_calls += 1
            requested_conflicts += conflict_limit

        attacker_freeze = {
            "schema": "o1-256-key-only-criticality-attacker-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "source_commit": source_commit,
            "target_id": "o1c-0044-fresh-0000",
            "public_view_sha256": public.digest(),
            "target_key_reads": 0,
            "reveal_file_reads": 0,
            "decision_scope": search_config["decision_scope"],
            "potential_sha256": {
                name: sha256_file(potential_paths[name]) for name in POTENTIAL_ARMS
            },
            "decision_variables": {
                name: list(decision_variables[name]) for name in POTENTIAL_ARMS
            },
            "decision_variables_sha256": decision_hashes,
            "residual_key_order": list(key_order),
            "residual_variables": residual_variables,
            "full256_search": full_rows,
        }
        attacker_freeze_bytes = _canonical_bytes(attacker_freeze)
        attacker_freeze_sha256 = hashlib.sha256(attacker_freeze_bytes).hexdigest()

        if (
            sha256_file(paths["reveal"]) != expected_hashes["reveal"]
            or sha256_file(paths["o1c45_result"]) != expected_hashes["o1c45_result"]
        ):
            raise O1C46RunError("post-freeze consumed source hash differs")
        reveal = verify_reveal(_read_json(paths["reveal"]))
        o1c45_result = _read_json(paths["o1c45_result"])
        preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except ValueError as exc:
            raise O1C46RunError("revealed O1C-0044 key encoding differs") from exc
        old_architecture = _mapping(o1c45_result.get("architecture"), "O1C-0045 architecture")
        old_metrics = _mapping(o1c45_result.get("metrics"), "O1C-0045 metrics")
        if (
            len(truth_key) != 32
            or not model_matches_public(truth_key, public)
            or o1c45_result.get("attempt_id") != "O1C-0045"
            or o1c45_result.get("classification")
            != "CRITICALITY_POTENTIAL_FAMILY_EXPANDS_RESIDUAL_FRONTIER_WITHOUT_PRIMARY_MARGIN"
            or _mapping(old_architecture.get("public_instance"), "public_instance").get(
                "instance_sha256"
            )
            != instance.instance_sha256
        ):
            raise O1C46RunError("consumed O1C-0045 boundary differs")

        truth_spins = {
            index + 1: (1 if bit else -1)
            for index, bit in enumerate(key_bits(truth_key))
        }
        for width_value in search_config["residual_widths"]:
            width = int(width_value)
            residual = set(residual_variables[str(width)])
            fixed = {
                variable: spin
                for variable, spin in truth_spins.items()
                if variable not in residual
            }
            residual_cnf = workspace / f"o1c44-residual-{width}.cnf"
            prefix = _write_prefix_cnf(cnf, residual_cnf, fixed)
            for name in ARMS:
                row, model = _run_public_search(
                    name=name,
                    public=public,
                    cnf=residual_cnf,
                    conflict_limit=conflict_limit,
                    seed=seed,
                    internal_executable=internal_executable,
                    potential_executable=potential_executable,
                    potential_paths=potential_paths,
                    decision_paths=decision_paths,
                )
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
                if name != "internal":
                    row["eligible_unfixed_decision_variables"] = sum(
                        variable in residual for variable in decision_variables[name]
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
        raise O1C46RunError("matched search work ledger differs")

    maximum_by_arm = {
        name: _maximum_recovered_width(residual_rows, name) for name in ARMS
    }
    primary_frontier_gain = maximum_by_arm["primary"] > max(
        maximum_by_arm[name] for name in ARMS if name != "primary"
    )
    primary_frontier_gain_vs_internal = (
        maximum_by_arm["primary"] > maximum_by_arm["internal"]
    )
    family_frontier_gain = max(
        maximum_by_arm[name] for name in POTENTIAL_ARMS
    ) > maximum_by_arm["internal"]
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
    shared_width = max(shared_widths, default=0)
    conflicts_by_arm: dict[str, int] = {}
    if shared_width:
        conflicts_by_arm = {
            name: int(
                _mapping(
                    next(
                        row["stats"]
                        for row in residual_rows
                        if row["name"] == name
                        and int(row["residual_bits"]) == shared_width
                    ),
                    f"{name}.stats",
                )["conflicts"]
            )
            for name in ARMS
        }
    primary_conflict_gain = bool(
        conflicts_by_arm
        and conflicts_by_arm["primary"]
        < min(conflicts_by_arm[name] for name in ARMS if name != "primary")
    )
    primary_full256 = bool(
        next(row for row in full_rows if row["name"] == "primary")[
            "model_publicly_verified"
        ]
    )
    primary_matched_work_gain = bool(
        primary_full256 or primary_frontier_gain or primary_conflict_gain
    )
    if primary_full256:
        classification = "ATTACKER_VALID_FULL256_KEY_ONLY_CRITICALITY_RECOVERY"
    elif primary_frontier_gain:
        classification = "KEY_ONLY_CRITICALITY_EXPANDS_PRIMARY_RESIDUAL_FRONTIER"
    elif primary_conflict_gain:
        classification = "KEY_ONLY_CRITICALITY_REDUCES_PRIMARY_RESIDUAL_CONFLICTS"
    elif family_frontier_gain and primary_frontier_gain_vs_internal:
        classification = "KEY_ONLY_POTENTIAL_FAMILY_GAIN_WITHOUT_PRIMARY_MARGIN"
    elif maximum_by_arm["primary"]:
        classification = "KEY_ONLY_CRITICALITY_MATCHES_EXACT_RESIDUAL_FRONTIER"
    else:
        classification = "KEY_ONLY_CRITICALITY_NO_EXACT_GAIN"

    elapsed = time.perf_counter() - started
    child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_rss = _peak_rss_bytes()
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": classification,
        "claim_boundary": {
            "reader_refit": False,
            "potentials_reused_byte_for_byte_from_o1c45": True,
            "full256_search_precedes_reveal": True,
            "full256_unknown_key_bits": 256,
            "full256_search_attacker_valid": True,
            "residual_search_is_post_reveal_ceiling": True,
            "residual_prefix_uses_truth_key": True,
            "fresh_targets": 0,
        },
        "attacker_freeze_sha256": attacker_freeze_sha256,
        "architecture": {
            "decision_scope": search_config["decision_scope"],
            "all_factor_variables_observed": True,
            "native_internal_variables_externally_decided": False,
            "conditional_decision_rule": "sum-local-uniform-marginal-energy-difference",
            "reversible_after_backtrack": True,
            "hard_factor_clauses_added": 0,
            "decision_variable_count_by_arm": {
                name: len(decision_variables[name]) for name in POTENTIAL_ARMS
            },
            "decision_variables_sha256": decision_hashes,
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
            "primary_residual_frontier_gain_vs_internal": primary_frontier_gain_vs_internal,
            "potential_family_residual_frontier_gain": family_frontier_gain,
            "shared_recovered_work_width": shared_width,
            "conflicts_by_arm_at_shared_width": conflicts_by_arm,
            "primary_residual_conflict_gain": primary_conflict_gain,
            "primary_matched_work_gain": primary_matched_work_gain,
            "o1c45_all_variable_maximum_recovered_residual_bits_by_arm": old_metrics.get(
                "maximum_recovered_residual_bits_by_arm"
            ),
            "o1c45_all_variable_conflicts_by_arm_at_shared_width": old_metrics.get(
                "conflicts_by_arm_at_shared_width"
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
            "native_solver_calls": solver_calls,
            "requested_conflicts": requested_conflicts,
            "persistent_artifact_bytes": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "source_sha256": {name: sha256_file(path) for name, path in paths.items()},
        "next_action": config["next_action"],
    }
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C46RunError("O1C-0046 resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_key-only-criticality-search-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C46RunError("O1C-0046 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    fixed_members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "attacker_freeze.json": attacker_freeze_bytes,
        "command.txt": (
            "PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c46_key_only_criticality_search_run "
            f"--config {config_file}\n"
        ).encode("utf-8"),
        "config.json": config_file.read_bytes(),
        **decision_artifacts,
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
        raise O1C46RunError("persistent artifact byte ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C46RunError("O1C-0046 persistent artifact budget differs")
    capsule.mkdir(parents=True)
    frozen_result_bytes = _atomic_json(capsule / "result.json", result)
    if frozen_result_bytes != members["result.json"]:
        raise O1C46RunError("canonical result bytes changed after ledger freeze")
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


__all__ = ["ATTEMPT_ID", "O1C46RunError", "load_config", "main", "run"]
