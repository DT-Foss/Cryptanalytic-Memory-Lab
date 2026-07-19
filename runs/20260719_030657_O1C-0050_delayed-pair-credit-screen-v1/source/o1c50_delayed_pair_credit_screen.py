"""One-call effect screen for trail-resident delayed pair credit."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .criticality_pair_groups import compile_primary_pair_groups
from .criticality_potential import CriticalityPotentialField
from .delayed_pair_credit_search import (
    build_native_delayed_pair_credit_search,
    run_delayed_pair_credit_search,
    write_delayed_pair_credit_decision_variables,
)
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import key_bits
from .o1_relational_search import model_hamming_distance, model_matches_public
from .o1c37_relational_guided_search_run import (
    _atomic_json,
    _git_commit,
    _relative_path,
    lab_root,
)
from .o1c45_criticality_live_search_run import (
    _highest_support_key_order,
    _write_prefix_cnf,
)
from .o1c48_pair_envelope_search_run import load_config
from .proof_parent_criticality import ParentCriticalityField


ATTEMPT_ID = "O1C-0050"
RESULT_SCHEMA = "o1-256-delayed-pair-credit-screen-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0050_DELAYED_PAIR_CREDIT_SCREEN_RESULT_20260719.json"
)
DEFAULT_CONFIG = Path("configs/o1c48_pair_envelope_search_v1.json")
DELAYED_SOURCE = Path("native/cadical_o1_delayed_pair_search.cpp")
DELAYED_ADAPTER = Path("src/o1_crypto_lab/delayed_pair_credit_search.py")
RUNNER_SOURCE = Path("src/o1_crypto_lab/o1c50_delayed_pair_credit_screen.py")
O1C49_RESULT = Path("research/O1C0049_ONLINE_PAIR_CREDIT_SCREEN_RESULT_20260719.json")
O1C49_RESULT_SHA256 = "01643f5949020d08b914919e3a465c5c05644ca6422cb44bf23edd5be17795a4"
RESIDUAL_WIDTH = 10
CONFLICT_LIMIT = 512
STATIC_CONFLICTS = 310
SEED = 0
TIMEOUT_SECONDS = 120.0
MAXIMUM_WALL_SECONDS = 130.0
MAXIMUM_PEAK_RSS_BYTES = 512 * 1024 * 1024


class O1C50ScreenError(RuntimeError):
    """The fixed one-call delayed-credit boundary was violated."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C50ScreenError(f"{field} differs")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C50ScreenError(f"{field} differs")
    return value


def _integer_group(values: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(value) for name, value in values.items()}


def _json_object(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise O1C50ScreenError(f"{field} JSON differs") from exc
    if not isinstance(value, dict):
        raise O1C50ScreenError(f"{field} JSON root differs")
    return value


def _hashed_json(path: Path, expected_sha256: str, field: str) -> dict[str, object]:
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise O1C50ScreenError(f"{field} hash differs")
    return _json_object(payload, field)


def _commit_bound_bytes(
    root: Path, commit: str, path: Path, payload: bytes, field: str
) -> None:
    try:
        relative = path.relative_to(root).as_posix()
        completed = subprocess.run(
            ["git", "show", f"{commit}:{relative}"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise O1C50ScreenError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C50ScreenError(f"{field} differs from source commit")


def evaluate_gate(
    *,
    status: str,
    publicly_verified: bool,
    truth_exact: bool,
    matches_truth_prefix: bool,
    conflicts: int,
    static_conflicts: int = STATIC_CONFLICTS,
) -> dict[str, object]:
    """Pass only an exact W10 recovery using fewer conflicts than static."""

    exact = bool(
        status == "SAT" and publicly_verified and truth_exact and matches_truth_prefix
    )
    passed = exact and conflicts < static_conflicts
    if not exact:
        tier = "no-exact-w10-recovery"
    elif passed:
        tier = "strict-w10-conflict-gain"
    elif conflicts == static_conflicts:
        tier = "equal-w10-conflicts"
    else:
        tier = "worse-w10-conflicts"
    return {
        "passed": passed,
        "selected_tier": tier,
        "delayed_exact_w10": exact,
        "delayed_conflicts": conflicts,
        "static_exact_w10": True,
        "static_conflicts": static_conflicts,
        "strict_conflict_delta": static_conflicts - conflicts if exact else None,
        "telemetry_cannot_satisfy_gate": True,
        "wall_time_cannot_satisfy_gate": True,
    }


def _classification(gate: Mapping[str, object]) -> str:
    if gate.get("passed") is True:
        return "DELAYED_PAIR_CREDIT_STRICT_W10_GAIN"
    return "DELAYED_PAIR_CREDIT_NO_STRICT_W10_GAIN"


def run(
    config_path: str | Path = DEFAULT_CONFIG,
    output_path: str | Path = RESULT_RELATIVE,
) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path)
    if not config_file.is_absolute():
        config_file = root / config_file
    config_file = config_file.resolve(strict=True)
    config = load_config(config_file)
    source = _mapping(config["source"], "config.source")
    expected = _mapping(source["expected_sha256"], "config.expected")
    required = (
        "template",
        "semantic_map",
        "publication",
        "field",
        "reveal",
        "primary_potential",
    )
    paths = {
        name: _relative_path(root, source[name], f"source.{name}") for name in required
    }
    source_bytes = {name: paths[name].read_bytes() for name in required}
    for name, payload in source_bytes.items():
        if hashlib.sha256(payload).hexdigest() != expected[name]:
            raise O1C50ScreenError(f"frozen O1C-0048 source differs: {name}")

    implementation_paths = {
        "delayed_source": (root / DELAYED_SOURCE).resolve(strict=True),
        "delayed_adapter": (root / DELAYED_ADAPTER).resolve(strict=True),
        "runner": (root / RUNNER_SOURCE).resolve(strict=True),
    }
    implementation_bytes = {
        name: path.read_bytes() for name, path in implementation_paths.items()
    }
    source_commit = _git_commit(root)
    for name, payload in implementation_bytes.items():
        _commit_bound_bytes(
            root, source_commit, implementation_paths[name], payload, name
        )

    publication = _json_object(source_bytes["publication"], "publication")
    public = public_view_from_publication(publication)
    field = ParentCriticalityField.from_bytes(source_bytes["field"])
    potential = CriticalityPotentialField.from_bytes(source_bytes["primary_potential"])
    plan = compile_primary_pair_groups(field, potential)
    expected_plan = {
        "group_count": 63,
        "joint_groups": 41,
        "filler_groups": 22,
        "eligible_variables": 126,
        "ordered_variables_sha256": (
            "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
        ),
    }
    if plan.describe() != expected_plan:
        raise O1C50ScreenError("frozen pair plan differs")

    baseline = _hashed_json(
        (root / O1C49_RESULT).resolve(strict=True),
        O1C49_RESULT_SHA256,
        "O1C-0049 result",
    )
    if (
        baseline.get("attempt_id") != "O1C-0049"
        or baseline.get("classification")
        != "ONLINE_PAIR_CREDIT_NO_ABSOLUTE_PRIMARY_GAIN"
        or _mapping(baseline.get("attacker_freeze"), "O1C-0049 freeze").get(
            "public_view_sha256"
        )
        != public.digest()
    ):
        raise O1C50ScreenError("O1C-0049 baseline identity differs")
    raw_static_rows = baseline.get("static_residual_baseline")
    if not isinstance(raw_static_rows, list):
        raise O1C50ScreenError("static residual baseline differs")
    candidates = [
        row
        for row in raw_static_rows
        if isinstance(row, Mapping)
        and row.get("name") == "static_primary"
        and row.get("residual_bits") == RESIDUAL_WIDTH
    ]
    if len(candidates) != 1:
        raise O1C50ScreenError("static W10 baseline differs")
    static_row = dict(candidates[0])
    if (
        static_row.get("status") != "SAT"
        or static_row.get("model_publicly_verified") is not True
        or static_row.get("model_truth_exact") is not True
        or static_row.get("model_matches_truth_fixed_prefix") is not True
        or _integer(static_row.get("conflict_limit"), "static conflict limit")
        != CONFLICT_LIMIT
        or _integer(
            _mapping(static_row.get("stats"), "static stats").get("conflicts"),
            "static conflicts",
        )
        != STATIC_CONFLICTS
    ):
        raise O1C50ScreenError("static W10 exact boundary differs")

    reveal = verify_reveal(_json_object(source_bytes["reveal"], "reveal"))
    preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
    try:
        truth_key = bytes.fromhex(str(preimage["key_hex"]))
    except (KeyError, ValueError) as exc:
        raise O1C50ScreenError("revealed key differs") from exc
    if len(truth_key) != 32 or not model_matches_public(truth_key, public):
        raise O1C50ScreenError("revealed key fails public verification")
    truth_spins = {
        index + 1: (1 if bit else -1) for index, bit in enumerate(key_bits(truth_key))
    }
    key_order = _highest_support_key_order(field)
    residual = set(key_order[:RESIDUAL_WIDTH])
    fixed = {
        variable: spin
        for variable, spin in truth_spins.items()
        if variable not in residual
    }
    if static_row.get("residual_variables") != sorted(residual):
        raise O1C50ScreenError("static W10 residual coordinates differ")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c50-") as temporary:
        workspace = Path(temporary)
        executable = workspace / "cadical-o1-delayed-pair-credit"
        build = build_native_delayed_pair_credit_search(
            source=implementation_paths["delayed_source"], output=executable
        )
        public_cnf = workspace / "public.cnf"
        instance = write_full256_instance(
            paths["template"],
            paths["semantic_map"],
            public_cnf,
            counter=public.counter_schedule[0],
            nonce=public.nonce,
            output=public.output_blocks[0],
        )
        verification = verify_full256_instance(
            public_cnf, paths["template"], paths["semantic_map"], instance
        )
        if (
            verification.get("ok") is not True
            or instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.assumptions
            or instance.key_fixed_for_self_test
        ):
            raise O1C50ScreenError("public Full256 instance differs")
        residual_cnf = workspace / "residual-10.cnf"
        prefix = _write_prefix_cnf(public_cnf, residual_cnf, fixed)
        if static_row.get("prefix") != prefix:
            raise O1C50ScreenError("static W10 prefix differs")
        decisions = workspace / "primary.ordered-pair-variables"
        decision_sha256 = write_delayed_pair_credit_decision_variables(
            decisions, plan.ordered_variables
        )
        static_pair = _mapping(static_row.get("pair_envelope"), "static pair")
        if static_pair.get("decision_variables_sha256") != decision_sha256:
            raise O1C50ScreenError("static pair decision file differs")

        delayed_result = run_delayed_pair_credit_search(
            executable=executable,
            cnf_path=residual_cnf,
            potential_path=paths["primary_potential"],
            decision_variables_path=decisions,
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
        )
        model = delayed_result.key_model
        publicly_verified = bool(
            model is not None and model_matches_public(model, public)
        )
        if delayed_result.status_name == "SAT" and not publicly_verified:
            raise O1C50ScreenError("delayed SAT model failed public verification")
        hamming = None if model is None else model_hamming_distance(model, truth_key)
        if model is None:
            matches_prefix = False
        else:
            bits = key_bits(model)
            matches_prefix = all(
                (1 if bits[variable - 1] else -1) == spin
                for variable, spin in fixed.items()
            )
            if not matches_prefix:
                raise O1C50ScreenError("delayed model violates truth prefix")
        truth_exact = bool(model is not None and hamming == 0)
        conflicts = _integer(delayed_result.stats["conflicts"], "delayed conflicts")
        gate = evaluate_gate(
            status=delayed_result.status_name,
            publicly_verified=publicly_verified,
            truth_exact=truth_exact,
            matches_truth_prefix=matches_prefix,
            conflicts=conflicts,
        )
        row: dict[str, object] = {
            "name": "delayed_primary",
            "status": delayed_result.status_name,
            "conflict_limit": delayed_result.conflict_limit,
            "residual_bits": RESIDUAL_WIDTH,
            "residual_variables": sorted(residual),
            "privileged_post_reveal_prefix": True,
            "prefix": prefix,
            "model_publicly_verified": publicly_verified,
            "model_sha256": (
                None if model is None else hashlib.sha256(model).hexdigest()
            ),
            "model_truth_hamming": hamming,
            "model_truth_exact": truth_exact,
            "model_matches_truth_fixed_prefix": matches_prefix,
            "stats": _integer_group(delayed_result.stats),
            "delayed": dict(delayed_result.delayed),
            "resources": _integer_group(delayed_result.resources),
        }
        children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
        elapsed = time.perf_counter() - started
        peak_rss = _integer(
            delayed_result.resources["peak_rss_bytes"], "delayed peak RSS"
        )
        resources = {
            "elapsed_seconds": elapsed,
            "parent_cpu_seconds": time.process_time() - cpu_started,
            "child_cpu_seconds": (
                children_finished.ru_utime
                + children_finished.ru_stime
                - children_started.ru_utime
                - children_started.ru_stime
            ),
            "peak_rss_bytes": peak_rss,
            "native_solver_calls": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        }
        if elapsed > MAXIMUM_WALL_SECONDS or peak_rss > MAXIMUM_PEAK_RSS_BYTES:
            raise O1C50ScreenError("screen resource boundary exceeded")
        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "started_at": started_at,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "classification": _classification(gate),
            "claim_level": "POST_REVEAL_MECHANISM_SCREEN",
            "hypothesis": (
                "trail-resident delayed eligibility lets later backtracks assign "
                "useful credit to the O1 pair decisions they actually undo"
            ),
            "boundary": {
                "consumed_target": True,
                "truth_fixed_key_bits": 246,
                "unknown_residual_bits": RESIDUAL_WIDTH,
                "full_round_relation": True,
                "single_native_call": True,
                "telemetry_or_wall_cannot_pass": True,
                "fresh_target_authorized_only_after_effect": True,
            },
            "architecture": {
                "pair_plan": plan.describe(),
                "decision_variables_sha256": decision_sha256,
                "delayed_native_build": build.describe(),
                "delayed_source_sha256": hashlib.sha256(
                    implementation_bytes["delayed_source"]
                ).hexdigest(),
                "delayed_adapter_sha256": hashlib.sha256(
                    implementation_bytes["delayed_adapter"]
                ).hexdigest(),
                "runner_sha256": hashlib.sha256(
                    implementation_bytes["runner"]
                ).hexdigest(),
                "public_instance": instance.describe(),
            },
            "delayed_w10": row,
            "static_w10_baseline": static_row,
            "gate": gate,
            "resources": resources,
            "next_action": (
                "run W11 then matched delayed rotations and Full256"
                if gate["passed"]
                else "close delayed credit on the frozen disjoint pair groups"
            ),
        }

    for name, before in source_bytes.items():
        if paths[name].read_bytes() != before:
            raise O1C50ScreenError(f"source changed during screen: {name}")
    for name, before in implementation_bytes.items():
        if implementation_paths[name].read_bytes() != before:
            raise O1C50ScreenError(f"implementation changed during screen: {name}")
    output = Path(output_path)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    if output != (root / RESULT_RELATIVE).resolve():
        raise O1C50ScreenError("result path differs")
    if output.exists():
        raise O1C50ScreenError("authoritative result already exists")
    _atomic_json(output, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--output", default=str(RESULT_RELATIVE))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = run(args.config, args.output)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "O1C50ScreenError",
    "RESULT_SCHEMA",
    "evaluate_gate",
    "run",
]
