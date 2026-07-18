"""O1C-0048 pre-reveal pair-envelope search on the frozen O1C-0044 target."""

from __future__ import annotations

import hashlib
import json
import resource
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .cadical_sensor import sha256_file
from .criticality_pair_groups import (
    CriticalityPairGroupPlan,
    compile_primary_pair_groups,
    transform_pair_groups,
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
    _read_json,
    _relative_path,
    lab_root,
)
from .o1c45_criticality_live_search_run import (
    _canonical_bytes,
    _highest_support_key_order,
    _pretty_json_bytes,
    _write_prefix_cnf,
)
from .pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    PairEnvelopeSearchResult,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
    write_pair_envelope_decision_variables,
)
from .proof_parent_criticality import (
    ParentCriticalityField,
    transform_parent_criticality_field,
)


ATTEMPT_ID = "O1C-0048"
CONFIG_SCHEMA = "o1-256-pair-envelope-search-config-v1"
RESULT_SCHEMA = "o1-256-pair-envelope-search-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0048_PAIR_ENVELOPE_SEARCH_RESULT_20260719.json"
)
ARMS = ("internal", "primary", "key_rotated", "clause_rotated")
PAIR_ARMS = ARMS[1:]
PROTECTED_SOURCES = ("reveal", "o1c46_result", "o1c47_result")
SOURCE_NAMES = (
    "template",
    "semantic_map",
    "publication",
    "field",
    "reveal",
    "o1c46_result",
    "o1c47_result",
    "primary_potential",
    "key_rotated_potential",
    "clause_rotated_potential",
    "pair_group_source",
    "search_adapter",
    "pair_native_source",
    "internal_native_source",
    "runner",
)

_TOP_LEVEL_FIELDS = {
    "schema",
    "attempt_id",
    "slug",
    "claim_level",
    "hypothesis",
    "prediction",
    "source",
    "target",
    "pair_plan",
    "search",
    "budgets",
    "next_action",
}
_TARGET_CONTRACT = {
    "target_id": "o1c-0044-fresh-0000",
    "rounds": 20,
    "unknown_key_bits": 256,
    "fresh_targets": 0,
}
_PAIR_PLAN_CONTRACT = {
    "compiler": "natural-field-plus-primary-potential-compiled-once",
    "primary_compile_count": 1,
    "group_width": 2,
    "expected_joint_groups": 41,
    "expected_filler_groups": 22,
    "expected_group_count": 63,
    "expected_eligible_variables": 126,
    "expected_primary_ordered_variables_sha256": (
        "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
    ),
    "control_transforms": {
        "primary": None,
        "key_rotated": "v->1+v%256",
        "clause_rotated": "unchanged-primary-plan",
    },
}
_SEARCH_CONTRACT = {
    "arms": list(ARMS),
    "conflict_limit": 512,
    "residual_widths": [8, 9],
    "residual_selector": (
        "descending-sum-abs-parent-score-units-then-count-then-coordinate"
    ),
    "prefix_mode": "post-reveal-correct-key-unit-conditions",
    "full256_mode": "pre-reveal-public-cnf-zero-key-and-assumption-units",
    "gate_order": [
        "strict-primary-full256",
        "strict-primary-residual-width",
        "strict-primary-conflicts-at-largest-all-arm-recovered-width",
    ],
    "seed": 0,
    "scored_call_timeout_seconds": 120,
}
_BUDGET_CONTRACT = {
    "maximum_wall_seconds": 150,
    "maximum_peak_rss_bytes": 536870912,
    "maximum_native_solver_calls": 12,
    "maximum_requested_conflicts": 6144,
    "maximum_fresh_targets": 0,
    "maximum_sibling_reads": 0,
    "maximum_sibling_writes": 0,
    "maximum_mps_calls": 0,
    "maximum_gpu_calls": 0,
    "maximum_persistent_artifact_bytes": 2097152,
}


class O1C48RunError(RuntimeError):
    """The frozen pair plan, read boundary, or matched-work gate differs."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C48RunError(f"{field} must be an object")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _validate_config_contract(config: Mapping[str, object]) -> None:
    """Validate the complete frozen ledger without opening any source path."""

    if set(config) != _TOP_LEVEL_FIELDS:
        raise O1C48RunError("frozen O1C-0048 top-level config fields differ")
    source = _mapping(config.get("source"), "source")
    expected = _mapping(source.get("expected_sha256"), "source.expected_sha256")
    target = _mapping(config.get("target"), "target")
    pair_plan = _mapping(config.get("pair_plan"), "pair_plan")
    search = _mapping(config.get("search"), "search")
    budgets = _mapping(config.get("budgets"), "budgets")
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("slug") != "pair-envelope-search-v1"
        or config.get("claim_level") != "CONSUMED_SEARCH_DIAGNOSTIC"
        or not isinstance(config.get("hypothesis"), str)
        or not config.get("hypothesis")
        or not isinstance(config.get("prediction"), str)
        or not config.get("prediction")
        or not isinstance(config.get("next_action"), str)
        or not config.get("next_action")
        or dict(target) != _TARGET_CONTRACT
        or dict(pair_plan) != _PAIR_PLAN_CONTRACT
        or dict(search) != _SEARCH_CONTRACT
        or dict(budgets) != _BUDGET_CONTRACT
        or set(source) != {*SOURCE_NAMES, "expected_sha256"}
        or set(expected) != set(SOURCE_NAMES)
    ):
        raise O1C48RunError("frozen O1C-0048 config ledger differs")
    for name in SOURCE_NAMES:
        if not isinstance(source.get(name), str) or not source[name]:
            raise O1C48RunError(f"source path contract differs for {name}")
        if not _is_sha256(expected.get(name)):
            raise O1C48RunError(f"source hash contract differs for {name}")
    requested_calls = len(ARMS) * (1 + len(_SEARCH_CONTRACT["residual_widths"]))
    requested_conflicts = requested_calls * int(_SEARCH_CONTRACT["conflict_limit"])
    if (
        requested_calls != int(_BUDGET_CONTRACT["maximum_native_solver_calls"])
        or requested_conflicts
        != int(_BUDGET_CONTRACT["maximum_requested_conflicts"])
    ):
        raise O1C48RunError("frozen O1C-0048 matched-work ledger is inconsistent")


def load_config(path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(root):
        raise O1C48RunError("config escapes lab")
    config = _read_json(config_path)
    _validate_config_contract(config)
    source = _mapping(config["source"], "source")
    expected = _mapping(source["expected_sha256"], "source.expected_sha256")
    for name in SOURCE_NAMES:
        resolved = _relative_path(root, source[name], f"source.{name}")
        # These bytes are sealed behind the attacker-freeze gate in ``run``.
        if name not in PROTECTED_SOURCES and sha256_file(resolved) != expected[name]:
            raise O1C48RunError(f"source hash differs for {name}")
    return config


class _PostFreezeSourceGate:
    """Permit protected reveal/result reads only after a freeze hash exists."""

    def __init__(
        self,
        paths: Mapping[str, Path],
        expected_sha256: Mapping[str, object],
    ) -> None:
        if set(paths) != set(PROTECTED_SOURCES):
            raise O1C48RunError("protected source path set differs")
        self._paths = {name: Path(paths[name]) for name in PROTECTED_SOURCES}
        self._expected = {
            name: expected_sha256.get(name) for name in PROTECTED_SOURCES
        }
        if any(not _is_sha256(value) for value in self._expected.values()):
            raise O1C48RunError("protected source hash contract differs")
        self._reads = {name: 0 for name in PROTECTED_SOURCES}
        self._freeze_sha256: str | None = None

    def pre_freeze_read_counts(self) -> dict[str, int]:
        if self._freeze_sha256 is not None:
            raise O1C48RunError("pre-freeze source snapshot requested after freeze")
        if any(self._reads.values()):
            raise O1C48RunError("protected source was read before attacker freeze")
        return dict(self._reads)

    def seal(self, attacker_freeze_sha256: str) -> None:
        if self._freeze_sha256 is not None or not _is_sha256(attacker_freeze_sha256):
            raise O1C48RunError("attacker-freeze source gate seal differs")
        if any(self._reads.values()):
            raise O1C48RunError("protected source was read before attacker freeze")
        self._freeze_sha256 = attacker_freeze_sha256

    def read_verified_json(self, name: str) -> dict[str, object]:
        if self._freeze_sha256 is None:
            raise O1C48RunError("protected source read attempted before attacker freeze")
        if name not in self._paths or self._reads[name] != 0:
            raise O1C48RunError(f"protected source read ledger differs for {name}")
        self._reads[name] += 1
        try:
            payload = self._paths[name].read_bytes()
            value = json.loads(payload.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise O1C48RunError(f"protected source JSON differs for {name}") from exc
        if hashlib.sha256(payload).hexdigest() != self._expected[name]:
            raise O1C48RunError(f"post-freeze source hash differs for {name}")
        return dict(_mapping(value, name))

    def post_freeze_read_counts(self) -> dict[str, int]:
        if self._freeze_sha256 is None:
            raise O1C48RunError("post-freeze source snapshot requested before freeze")
        return dict(self._reads)


def _variable_list_sha256(variables: Sequence[int]) -> str:
    payload = "".join(f"{variable}\n" for variable in variables).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _compile_pair_plans(
    natural: ParentCriticalityField,
    potentials: Mapping[str, CriticalityPotentialField],
) -> tuple[
    dict[str, ParentCriticalityField],
    dict[str, CriticalityPairGroupPlan],
    dict[str, dict[str, object]],
]:
    """Compile the primary once, transform it twice, and prove all partitions."""

    if set(potentials) != set(PAIR_ARMS):
        raise O1C48RunError("pair potential arm set differs")
    fields = {
        "primary": natural,
        "key_rotated": transform_parent_criticality_field(natural, rotate="key"),
        "clause_rotated": transform_parent_criticality_field(
            natural, rotate="clause"
        ),
    }
    primary = compile_primary_pair_groups(natural, potentials["primary"])
    plans = {
        "primary": primary,
        "key_rotated": transform_pair_groups(primary, rotate="key"),
        "clause_rotated": transform_pair_groups(primary, rotate="clause"),
    }
    validation: dict[str, dict[str, object]] = {}
    for name in PAIR_ARMS:
        plan = plans[name]
        ordered = plan.ordered_variables
        field_keys = tuple(
            sorted({factor.key_variable for factor in fields[name].factors})
        )
        observed = tuple(sorted(potentials[name].observed_variables))
        if (
            not ordered
            or len(ordered) != 2 * len(plan.groups)
            or len(ordered) != len(set(ordered))
            or set(ordered) != set(field_keys)
            or not set(ordered).issubset(observed)
            or any(len(group) != 2 for group in plan.groups)
        ):
            raise O1C48RunError(f"ordered pair partition differs for {name}")
        validation[name] = {
            "partitions_transformed_field_keys_exactly": True,
            "all_pair_variables_observed_by_potential": True,
            "transformed_field_key_count": len(field_keys),
            "transformed_field_keys_sha256": _variable_list_sha256(field_keys),
            "observed_potential_variable_count": len(observed),
            "observed_potential_variables_sha256": _variable_list_sha256(observed),
        }
    return fields, plans, validation


def _integer_group(values: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(value) for name, value in values.items()}


def _public_search_row(
    name: str,
    result: GuidedSearchResult | PairEnvelopeSearchResult,
    public: PublicTargetView,
) -> tuple[dict[str, object], bytes | None]:
    model = result.key_model
    verified = bool(model is not None and model_matches_public(model, public))
    if result.status_name == "SAT" and not verified:
        raise O1C48RunError(f"SAT key failed public verification for {name}")
    row: dict[str, object] = {
        "name": name,
        "status": result.status_name,
        "conflict_limit": result.conflict_limit,
        "model_publicly_verified": verified,
        "model_sha256": None if model is None else hashlib.sha256(model).hexdigest(),
        "stats": _integer_group(result.stats),
        "resources": _integer_group(result.resources),
    }
    if isinstance(result, PairEnvelopeSearchResult):
        row["pair_envelope"] = dict(result.pair_envelope)
    return row, model


def _run_public_search(
    *,
    name: str,
    public: PublicTargetView,
    cnf: Path,
    conflict_limit: int,
    seed: int,
    timeout_seconds: float,
    internal_executable: Path,
    pair_executable: Path,
    potential_paths: Mapping[str, Path],
    decision_paths: Mapping[str, Path],
) -> tuple[dict[str, object], bytes | None]:
    result: GuidedSearchResult | PairEnvelopeSearchResult
    if name == "internal":
        result = run_guided_search(
            executable=internal_executable,
            cnf_path=cnf,
            mode="internal",
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
        )
    else:
        result = run_pair_envelope_search(
            executable=pair_executable,
            cnf_path=cnf,
            potential_path=potential_paths[name],
            decision_variables_path=decision_paths[name],
            conflict_limit=conflict_limit,
            seed=seed,
            timeout_seconds=timeout_seconds,
        )
    return _public_search_row(name, result, public)


def _maximum_recovered_width(rows: Sequence[Mapping[str, object]], name: str) -> int:
    return max(
        (
            int(row["residual_bits"])
            for row in rows
            if row.get("name") == name
            and row.get("model_publicly_verified") is True
        ),
        default=0,
    )


def _evaluate_gate(
    full_rows: Sequence[Mapping[str, object]],
    residual_rows: Sequence[Mapping[str, object]],
    widths: Sequence[int],
) -> dict[str, object]:
    """Apply the frozen strict-primary gate in lexicographic order."""

    exact = {
        name: bool(
            next(row for row in full_rows if row.get("name") == name).get(
                "model_publicly_verified"
            )
        )
        for name in ARMS
    }
    maximum_by_arm = {
        name: _maximum_recovered_width(residual_rows, name) for name in ARMS
    }
    control_exact = any(exact[name] for name in ARMS if name != "primary")
    strict_full256 = exact["primary"] and not control_exact
    strict_frontier = bool(
        not exact["primary"]
        and not control_exact
        and maximum_by_arm["primary"]
        > max(maximum_by_arm[name] for name in ARMS if name != "primary")
    )
    shared_widths = [
        int(width)
        for width in widths
        if all(
            any(
                row.get("name") == name
                and int(row.get("residual_bits", -1)) == int(width)
                and row.get("model_publicly_verified") is True
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
                        if row.get("name") == name
                        and int(row.get("residual_bits", -1)) == shared_width
                    ),
                    f"{name}.stats",
                )["conflicts"]
            )
            for name in ARMS
        }
    strict_conflicts = bool(
        not exact["primary"]
        and not control_exact
        and not strict_frontier
        and conflicts_by_arm
        and conflicts_by_arm["primary"]
        < min(conflicts_by_arm[name] for name in ARMS if name != "primary")
    )
    if exact["primary"]:
        selected_tier = "strict-primary-full256"
        passed = strict_full256
    elif control_exact:
        selected_tier = "control-full256-blocks-lower-tiers"
        passed = False
    elif strict_frontier:
        selected_tier = "strict-primary-residual-width"
        passed = True
    else:
        selected_tier = (
            "strict-primary-conflicts-at-largest-all-arm-recovered-width"
        )
        passed = strict_conflicts
    return {
        "gate_order": list(_SEARCH_CONTRACT["gate_order"]),
        "selected_tier": selected_tier,
        "passed": passed,
        "primary_strictly_beats_internal_and_both_rotations": passed,
        "full256_recovery_by_arm": exact,
        "primary_full256_recovery": exact["primary"],
        "primary_strict_full256_gain": strict_full256,
        "maximum_recovered_residual_bits_by_arm": maximum_by_arm,
        "primary_strict_residual_frontier_gain": strict_frontier,
        "largest_width_recovered_by_every_arm": shared_width,
        "conflicts_by_arm_at_largest_all_arm_recovered_width": conflicts_by_arm,
        "primary_strict_residual_conflict_gain": strict_conflicts,
        "wall_time_can_satisfy_gate": False,
        "control_or_telemetry_only_can_satisfy_gate": False,
    }


def _classification(gate: Mapping[str, object]) -> str:
    if gate.get("primary_strict_full256_gain") is True:
        return "ATTACKER_VALID_PAIR_ENVELOPE_STRICT_PRIMARY_FULL256_RECOVERY"
    if gate.get("primary_strict_residual_frontier_gain") is True:
        return "PAIR_ENVELOPE_STRICT_PRIMARY_RESIDUAL_FRONTIER_GAIN"
    if gate.get("primary_strict_residual_conflict_gain") is True:
        return "PAIR_ENVELOPE_STRICT_PRIMARY_RESIDUAL_CONFLICT_GAIN"
    exact = _mapping(gate.get("full256_recovery_by_arm"), "full256 recovery")
    if exact.get("primary") is True:
        return "PAIR_ENVELOPE_FULL256_WITHOUT_STRICT_PRIMARY_MARGIN"
    if any(exact.get(name) is True for name in ARMS if name != "primary"):
        return "PAIR_ENVELOPE_CONTROL_FULL256_RECOVERY"
    return "PAIR_ENVELOPE_NO_STRICT_PRIMARY_GAIN"


def _markdown(result: Mapping[str, object]) -> str:
    metrics = _mapping(result["metrics"], "metrics")
    resources = _mapping(result["resources"], "resources")
    return (
        f"# O1C Run {ATTEMPT_ID}\n\n"
        f"- Classification: `{result['classification']}`\n"
        f"- Strict primary gate: `{metrics['passed']}`\n"
        f"- Selected tier: `{metrics['selected_tier']}`\n"
        f"- Full-256 recovery by arm: `{metrics['full256_recovery_by_arm']}`\n"
        f"- Residual frontier by arm: "
        f"`{metrics['maximum_recovered_residual_bits_by_arm']}`\n"
        f"- Elapsed seconds: `{resources['elapsed_seconds']}`\n"
        f"- Peak RSS bytes: `{resources['peak_rss_bytes']}`\n\n"
        "The four Full-256 calls and ordered pair plans were frozen before any "
        "reveal or consumed-result read. Residual calls are explicit post-reveal "
        "ceilings, and only a strict primary advantage can pass.\n"
    )


def run(config_path: str | Path) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path).resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "source")
    expected_hashes = _mapping(
        source["expected_sha256"], "source.expected_sha256"
    )
    search_config = _mapping(config["search"], "search")
    plan_config = _mapping(config["pair_plan"], "pair_plan")
    budgets = _mapping(config["budgets"], "budgets")
    paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in SOURCE_NAMES
    }
    late_sources = _PostFreezeSourceGate(
        {name: paths[name] for name in PROTECTED_SOURCES}, expected_hashes
    )
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    source_commit = _git_commit(root)

    publication = _read_json(paths["publication"])
    public = public_view_from_publication(publication)
    if (
        publication.get("schema") != "o1-256-sealed-publication-v1"
        or publication.get("target_id") != _TARGET_CONTRACT["target_id"]
        or publication.get("public_view_sha256") != public.digest()
    ):
        raise O1C48RunError("consumed public target identity differs")
    natural = ParentCriticalityField.from_bytes(paths["field"].read_bytes())
    potentials = {
        name: CriticalityPotentialField.from_bytes(
            paths[f"{name}_potential"].read_bytes()
        )
        for name in PAIR_ARMS
    }
    fields, plans, plan_validation = _compile_pair_plans(natural, potentials)
    primary_description = plans["primary"].describe()
    if (
        primary_description["joint_groups"]
        != plan_config["expected_joint_groups"]
        or primary_description["filler_groups"]
        != plan_config["expected_filler_groups"]
        or primary_description["group_count"]
        != plan_config["expected_group_count"]
        or primary_description["eligible_variables"]
        != plan_config["expected_eligible_variables"]
        or primary_description["ordered_variables_sha256"]
        != plan_config["expected_primary_ordered_variables_sha256"]
    ):
        raise O1C48RunError("frozen primary ordered pair plan differs")

    key_order = _highest_support_key_order(natural)
    residual_variables = {
        str(width): list(key_order[: int(width)])
        for width in search_config["residual_widths"]
    }
    if any(
        len(values) != int(width)
        for width, values in residual_variables.items()
    ):
        raise O1C48RunError("residual variable order differs")

    full_rows: list[dict[str, object]] = []
    full_models: dict[str, bytes | None] = {}
    residual_rows: list[dict[str, object]] = []
    solver_calls = 0
    requested_conflicts = 0
    pair_artifacts: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="o1c48-") as temporary:
        workspace = Path(temporary)
        pair_executable = workspace / "cadical-o1-pair-envelope-search"
        internal_executable = workspace / "cadical-o1-guided-search"
        pair_build = build_native_pair_envelope_search(
            source=paths["pair_native_source"], output=pair_executable
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
            verification.get("ok") is not True
            or instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.assumptions
            or instance.key_fixed_for_self_test
        ):
            raise O1C48RunError("public Full-256 zero-unit instance differs")

        potential_paths = {
            name: paths[f"{name}_potential"] for name in PAIR_ARMS
        }
        decision_paths: dict[str, Path] = {}
        decision_hashes: dict[str, str] = {}
        pair_plan_records: dict[str, dict[str, object]] = {}
        for name in PAIR_ARMS:
            destination = workspace / f"{name}.ordered-pair-variables"
            decision_hashes[name] = write_pair_envelope_decision_variables(
                destination, plans[name].ordered_variables
            )
            relative = f"ordered_pair_variables/{name}.txt"
            pair_artifacts[relative] = destination.read_bytes()
            decision_paths[name] = destination
            pair_plan_records[name] = {
                **plans[name].describe(),
                **plan_validation[name],
                "groups": [list(group) for group in plans[name].groups],
                "ordered_pair_file": relative,
                "ordered_pair_file_format": (
                    "one-variable-per-line; consecutive lines form ordered pairs"
                ),
                "ordered_pair_file_sha256": decision_hashes[name],
            }

        conflict_limit = int(search_config["conflict_limit"])
        seed = int(search_config["seed"])
        timeout_seconds = float(search_config["scored_call_timeout_seconds"])
        for name in ARMS:
            row, model = _run_public_search(
                name=name,
                public=public,
                cnf=cnf,
                conflict_limit=conflict_limit,
                seed=seed,
                timeout_seconds=timeout_seconds,
                internal_executable=internal_executable,
                pair_executable=pair_executable,
                potential_paths=potential_paths,
                decision_paths=decision_paths,
            )
            if name != "internal":
                envelope = _mapping(row.get("pair_envelope"), f"{name}.envelope")
                if (
                    envelope.get("decision_rule") != PAIR_ENVELOPE_DECISION_RULE
                    or envelope.get("decision_scope")
                    != PAIR_ENVELOPE_DECISION_SCOPE
                    or envelope.get("group_width") != 2
                    or envelope.get("pair_count") != len(plans[name].groups)
                    or envelope.get("eligible_decision_variables")
                    != len(plans[name].ordered_variables)
                    or envelope.get("decision_variables_sha256")
                    != decision_hashes[name]
                ):
                    raise O1C48RunError(f"native ordered pair contract differs for {name}")
            full_rows.append(row)
            full_models[name] = model
            solver_calls += 1
            requested_conflicts += conflict_limit

        protected_counts = late_sources.pre_freeze_read_counts()
        attacker_freeze = {
            "schema": "o1-256-pair-envelope-attacker-freeze-v1",
            "attempt_id": ATTEMPT_ID,
            "source_commit": source_commit,
            "target_id": _TARGET_CONTRACT["target_id"],
            "public_view_sha256": public.digest(),
            "target_key_reads": 0,
            "reveal_file_reads": protected_counts["reveal"],
            "o1c46_result_reads": protected_counts["o1c46_result"],
            "o1c47_result_reads": protected_counts["o1c47_result"],
            "protected_source_reads_before_freeze": protected_counts,
            "pair_plan_compilation": {
                "primary_compile_count": 1,
                "primary_inputs": ["natural_field", "primary_potential"],
                "controls_derived_from_primary_plan": True,
                "key_transform": "v->1+v%256",
                "clause_transform": "unchanged-primary-plan",
            },
            "pair_plans": pair_plan_records,
            "potential_sha256": {
                name: sha256_file(potential_paths[name]) for name in PAIR_ARMS
            },
            "residual_key_order": list(key_order),
            "residual_variables": residual_variables,
            "public_instance": instance.describe(),
            "full256_search": full_rows,
        }
        attacker_freeze_bytes = _canonical_bytes(attacker_freeze)
        attacker_freeze_sha256 = hashlib.sha256(attacker_freeze_bytes).hexdigest()
        late_sources.seal(attacker_freeze_sha256)

        reveal_document = late_sources.read_verified_json("reveal")
        o1c46_result = late_sources.read_verified_json("o1c46_result")
        o1c47_result = late_sources.read_verified_json("o1c47_result")
        reveal = verify_reveal(reveal_document)
        preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except (KeyError, ValueError) as exc:
            raise O1C48RunError("revealed O1C-0044 key encoding differs") from exc
        truth_sha256 = hashlib.sha256(truth_key).hexdigest()
        old46_architecture = _mapping(
            o1c46_result.get("architecture"), "O1C-0046 architecture"
        )
        old46_instance = _mapping(
            old46_architecture.get("public_instance"), "O1C-0046 public instance"
        )
        old46_metrics = _mapping(o1c46_result.get("metrics"), "O1C-0046 metrics")
        old47_target = _mapping(o1c47_result.get("target"), "O1C-0047 target")
        old47_metrics = _mapping(o1c47_result.get("metrics"), "O1C-0047 metrics")
        width16 = _mapping(old47_metrics.get("width16"), "O1C-0047 width16")
        width16_primary = _mapping(width16.get("primary"), "O1C-0047 primary")
        if (
            len(truth_key) != 32
            or preimage.get("target_id") != _TARGET_CONTRACT["target_id"]
            or preimage.get("public_view_sha256") != public.digest()
            or not model_matches_public(truth_key, public)
            or o1c46_result.get("schema")
            != "o1-256-key-only-criticality-search-result-v1"
            or o1c46_result.get("attempt_id") != "O1C-0046"
            or o1c46_result.get("classification")
            != "KEY_ONLY_POTENTIAL_FAMILY_GAIN_WITHOUT_PRIMARY_MARGIN"
            or old46_instance != instance.describe()
            or old46_metrics.get("primary_matched_work_gain") is not False
            or o1c47_result.get("schema")
            != "o1-256-global-criticality-residual-beam-result-v1"
            or o1c47_result.get("attempt_id") != "O1C-0047"
            or o1c47_result.get("classification")
            != "POST_REVEAL_GLOBAL_CRITICALITY_COMPRESSES_RESIDUAL16"
            or old47_target.get("target_id") != _TARGET_CONTRACT["target_id"]
            or old47_target.get("public_view_sha256") != public.digest()
            or old47_target.get("truth_key_sha256") != truth_sha256
            or old47_target.get("truth_publicly_verified") is not True
            or old47_metrics.get("primary_width16_rank") != 50
            or old47_metrics.get("primary_width16_control_margin") is not True
            or old47_metrics.get("primary_top256_contains_verified_key") is not True
            or old47_metrics.get("rotated_top256_contains_verified_key") is not False
            or width16_primary.get("deterministic_rank") != 50
            or width16_primary.get("strict_rank") != 50
            or width16_primary.get("top256") is not True
        ):
            raise O1C48RunError("consumed O1C-0046/O1C-0047 boundary differs")

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
                    timeout_seconds=timeout_seconds,
                    internal_executable=internal_executable,
                    pair_executable=pair_executable,
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
                        variable in residual
                        for variable in plans[name].ordered_variables
                    )
                    row["fully_unfixed_pairs"] = sum(
                        left in residual and right in residual
                        for left, right in plans[name].groups
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
        or late_sources.post_freeze_read_counts()
        != {name: 1 for name in PROTECTED_SOURCES}
    ):
        raise O1C48RunError("matched search or protected-read ledger differs")

    gate = _evaluate_gate(
        full_rows,
        residual_rows,
        [int(width) for width in search_config["residual_widths"]],
    )
    classification = _classification(gate)
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
            "primary_pair_plan_compiled_once": True,
            "controls_transform_same_primary_pair_plan": True,
            "full256_search_precedes_reveal_and_consumed_results": True,
            "full256_unknown_key_bits": 256,
            "full256_search_attacker_valid": True,
            "residual_search_is_post_reveal_ceiling": True,
            "residual_prefix_uses_truth_key": True,
            "strict_primary_gate_required": True,
            "wall_time_is_not_a_success_gate": True,
            "fresh_targets": 0,
        },
        "attacker_freeze_sha256": attacker_freeze_sha256,
        "target": {
            "target_id": _TARGET_CONTRACT["target_id"],
            "public_view_sha256": public.digest(),
            "truth_key_sha256": truth_sha256,
            "truth_publicly_verified": True,
        },
        "architecture": {
            "decision_rule": PAIR_ENVELOPE_DECISION_RULE,
            "decision_scope": PAIR_ENVELOPE_DECISION_SCOPE,
            "group_width": 2,
            "primary_pair_plan": primary_description,
            "pair_plan_validation": plan_validation,
            "ordered_pair_file_sha256": decision_hashes,
            "residual_selector": search_config["residual_selector"],
            "pair_build": pair_build.describe(),
            "internal_build": internal_build.describe(),
            "public_instance": instance.describe(),
            "consumed_boundaries": {
                "o1c46_classification": o1c46_result["classification"],
                "o1c47_classification": o1c47_result["classification"],
                "o1c47_primary_width16_rank": 50,
            },
        },
        "full256_search": full_rows,
        "residual_search": residual_rows,
        "metrics": gate,
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
            "scored_call_timeout_seconds": timeout_seconds,
            "persistent_artifact_bytes": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "source_sha256": {
            name: str(expected_hashes[name]) for name in SOURCE_NAMES
        },
        "next_action": config["next_action"],
    }
    if (
        elapsed > float(budgets["maximum_wall_seconds"])
        or peak_rss > int(budgets["maximum_peak_rss_bytes"])
    ):
        raise O1C48RunError("O1C-0048 resource gate differs")

    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{ATTEMPT_ID}_pair-envelope-search-v1"
    capsule = root / capsule_relative
    if capsule.exists():
        raise O1C48RunError("O1C-0048 capsule path already exists")
    result["capsule"] = str(capsule_relative)
    fixed_members: dict[str, bytes] = {
        "RUN.md": _markdown(result).encode("utf-8"),
        "attacker_freeze.json": attacker_freeze_bytes,
        "command.txt": (
            "PYTHONPATH=src python3 -m "
            "o1_crypto_lab.o1c48_pair_envelope_search_run "
            f"--config {config_file}\n"
        ).encode("utf-8"),
        "config.json": config_file.read_bytes(),
        **pair_artifacts,
    }
    members: dict[str, bytes] = {}
    manifest = b""
    persistent_bytes = 0
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
        raise O1C48RunError("persistent artifact byte ledger did not converge")
    if persistent_bytes > int(budgets["maximum_persistent_artifact_bytes"]):
        raise O1C48RunError("O1C-0048 persistent artifact budget differs")
    capsule.mkdir(parents=True)
    frozen_result_bytes = _atomic_json(capsule / "result.json", result)
    if frozen_result_bytes != members["result.json"]:
        raise O1C48RunError("canonical result bytes changed after ledger freeze")
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
    "O1C48RunError",
    "_PostFreezeSourceGate",
    "_compile_pair_plans",
    "_evaluate_gate",
    "_validate_config_contract",
    "load_config",
    "main",
    "run",
]
