"""Effect-first consumed screen for bounded online pair-group credit."""

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
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import verify_full256_instance, write_full256_instance
from .living_inverse import PublicTargetView, key_bits
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
from .online_pair_credit_search import (
    OnlinePairCreditSearchResult,
    build_native_online_pair_credit_search,
    run_online_pair_credit_search,
    write_online_pair_credit_decision_variables,
)
from .pair_envelope_search import (
    PairEnvelopeSearchResult,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
)
from .proof_parent_criticality import ParentCriticalityField


ATTEMPT_ID = "O1C-0049"
RESULT_SCHEMA = "o1-256-online-pair-credit-screen-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0049_ONLINE_PAIR_CREDIT_SCREEN_RESULT_20260719.json"
)
DEFAULT_CONFIG = Path("configs/o1c48_pair_envelope_search_v1.json")
ONLINE_SOURCE = Path("native/cadical_o1_online_pair_search.cpp")
ONLINE_ADAPTER = Path("src/o1_crypto_lab/online_pair_credit_search.py")
RUNNER_SOURCE = Path("src/o1_crypto_lab/o1c49_online_pair_credit_screen.py")
O1C48_RESULT = Path("research/O1C0048_PAIR_ENVELOPE_SEARCH_RESULT_20260719.json")
O1C48_RESULT_SHA256 = "eb5ffc29dbadb0f3722204425309d16b6befe82ea5aabc1075226f856d599663"
RESIDUAL_WIDTHS = (8, 9, 10)
CONFLICT_LIMIT = 512
SEED = 0
TIMEOUT_SECONDS = 120.0
MAXIMUM_WALL_SECONDS = 150.0
MAXIMUM_PEAK_RSS_BYTES = 512 * 1024 * 1024


class O1C49ScreenError(RuntimeError):
    """The fixed consumed screen boundary was violated."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C49ScreenError(f"{field} differs")
    return value


def _integer_group(values: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(value) for name, value in values.items()}


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C49ScreenError(f"{field} differs")
    return value


def _rows(value: object, field: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        raise O1C49ScreenError(f"{field} differs")
    return [dict(row) for row in value]


def _json_bytes(path: Path, expected_sha256: str, field: str) -> bytes:
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise O1C49ScreenError(f"{field} hash differs")
    return payload


def _json_object(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise O1C49ScreenError(f"{field} JSON differs") from exc
    if not isinstance(value, dict):
        raise O1C49ScreenError(f"{field} JSON root differs")
    return value


def _canonical_json_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


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
        raise O1C49ScreenError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C49ScreenError(f"{field} differs from source commit")


def _search_row(
    *,
    name: str,
    result: OnlinePairCreditSearchResult | PairEnvelopeSearchResult,
    public: PublicTargetView,
) -> tuple[dict[str, object], bytes | None]:
    model = result.key_model
    verified = bool(model is not None and model_matches_public(model, public))
    if result.status_name == "SAT" and not verified:
        raise O1C49ScreenError(f"SAT model failed public verification for {name}")
    row: dict[str, object] = {
        "name": name,
        "status": result.status_name,
        "conflict_limit": result.conflict_limit,
        "model_publicly_verified": verified,
        "model_sha256": None if model is None else hashlib.sha256(model).hexdigest(),
        "stats": _integer_group(result.stats),
        "resources": _integer_group(result.resources),
    }
    if isinstance(result, OnlinePairCreditSearchResult):
        row["online"] = dict(result.online)
    else:
        row["pair_envelope"] = dict(result.pair_envelope)
    return row, model


def _exact_residual(row: Mapping[str, object]) -> bool:
    return bool(
        row.get("model_publicly_verified") is True
        and row.get("model_truth_exact") is True
        and row.get("model_matches_truth_fixed_prefix") is True
    )


def _frontier(rows: Sequence[Mapping[str, object]]) -> tuple[int, int | None]:
    exact = [row for row in rows if _exact_residual(row)]
    if not exact:
        return 0, None
    width = max(_integer(row["residual_bits"], "row.residual_bits") for row in exact)
    conflicts = min(
        _integer(_mapping(row["stats"], "row.stats")["conflicts"], "row.conflicts")
        for row in exact
        if _integer(row["residual_bits"], "row.residual_bits") == width
    )
    return width, conflicts


def evaluate_absolute_gate(
    *,
    online_full_exact: bool,
    static_full_exact: bool,
    online_rows: Sequence[Mapping[str, object]],
    static_rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Compare online primary only against its frozen static primary baseline."""

    online_width, online_conflicts = _frontier(online_rows)
    static_width, static_conflicts = _frontier(static_rows)
    if online_full_exact and not static_full_exact:
        passed = True
        tier = "strict-full256"
    elif static_full_exact:
        passed = False
        tier = "static-full256-blocks-lower-tiers"
    elif online_width > static_width:
        passed = True
        tier = "strict-residual-frontier"
    elif online_width < static_width:
        passed = False
        tier = "residual-frontier-regression"
    elif (
        online_width > 0
        and online_conflicts is not None
        and static_conflicts is not None
    ):
        passed = online_conflicts < static_conflicts
        tier = "strict-conflict-gain" if passed else "no-strict-conflict-gain"
    else:
        passed = False
        tier = "no-exact-frontier"
    return {
        "passed": passed,
        "selected_tier": tier,
        "online_full256_exact": online_full_exact,
        "static_full256_exact": static_full_exact,
        "online_maximum_exact_residual_width": online_width,
        "static_maximum_exact_residual_width": static_width,
        "online_conflicts_at_own_frontier": online_conflicts,
        "static_conflicts_at_own_frontier": static_conflicts,
        "requires_rotation_controls_before_promotion": passed,
        "wall_time_cannot_satisfy_gate": True,
        "telemetry_cannot_satisfy_gate": True,
    }


def _annotate_residual(
    *,
    row: dict[str, object],
    model: bytes | None,
    width: int,
    residual: set[int],
    fixed: Mapping[int, int],
    prefix: Mapping[str, object],
    truth_key: bytes,
) -> None:
    hamming = None if model is None else model_hamming_distance(model, truth_key)
    if model is None:
        honors_prefix = False
    else:
        bits = key_bits(model)
        honors_prefix = all(
            (1 if bits[variable - 1] else -1) == spin
            for variable, spin in fixed.items()
        )
        if not honors_prefix:
            raise O1C49ScreenError("residual SAT model violates fixed truth prefix")
    row.update(
        {
            "residual_bits": width,
            "residual_variables": sorted(residual),
            "privileged_post_reveal_prefix": True,
            "prefix": dict(prefix),
            "model_truth_hamming": hamming,
            "model_truth_exact": bool(model is not None and hamming == 0),
            "model_matches_truth_fixed_prefix": honors_prefix,
        }
    )


def _classification(gate: Mapping[str, object]) -> str:
    if gate.get("passed") is True:
        return "ONLINE_PAIR_PRIMARY_ABSOLUTE_GAIN_NEEDS_CONTROLS"
    return "ONLINE_PAIR_CREDIT_NO_ABSOLUTE_PRIMARY_GAIN"


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
    expected = _mapping(source["expected_sha256"], "config.source.expected_sha256")
    required_names = (
        "template",
        "semantic_map",
        "publication",
        "field",
        "reveal",
        "primary_potential",
        "pair_native_source",
    )
    paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in required_names
    }
    pre_reveal_names = tuple(name for name in required_names if name != "reveal")
    pre_reveal_bytes = {name: paths[name].read_bytes() for name in pre_reveal_names}
    for name in pre_reveal_names:
        if hashlib.sha256(pre_reveal_bytes[name]).hexdigest() != expected[name]:
            raise O1C49ScreenError(f"frozen O1C-0048 source differs: {name}")
    online_paths = {
        "online_source": (root / ONLINE_SOURCE).resolve(strict=True),
        "online_adapter": (root / ONLINE_ADAPTER).resolve(strict=True),
        "runner": (root / RUNNER_SOURCE).resolve(strict=True),
    }
    online_bytes = {name: path.read_bytes() for name, path in online_paths.items()}
    publication = _json_object(pre_reveal_bytes["publication"], "publication")
    public = public_view_from_publication(publication)
    field = ParentCriticalityField.from_bytes(pre_reveal_bytes["field"])
    potential = CriticalityPotentialField.from_bytes(
        pre_reveal_bytes["primary_potential"]
    )
    plan = compile_primary_pair_groups(field, potential)
    if plan.describe() != {
        "group_count": 63,
        "joint_groups": 41,
        "filler_groups": 22,
        "eligible_variables": 126,
        "ordered_variables_sha256": (
            "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
        ),
    }:
        raise O1C49ScreenError("frozen pair plan differs")

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    parent_cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    source_commit = _git_commit(root)
    for name, payload in online_bytes.items():
        _commit_bound_bytes(
            root,
            source_commit,
            online_paths[name],
            payload,
            name,
        )
    native_solver_calls = 0
    requested_conflicts = 0
    online_full_row: dict[str, object]
    online_full_model: bytes | None
    online_rows: list[dict[str, object]] = []
    static_rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="o1c49-") as temporary:
        workspace = Path(temporary)
        online_executable = workspace / "cadical-o1-online-pair-credit"
        static_executable = workspace / "cadical-o1-static-pair-envelope"
        online_build = build_native_online_pair_credit_search(
            source=online_paths["online_source"], output=online_executable
        )
        static_build = build_native_pair_envelope_search(
            source=paths["pair_native_source"], output=static_executable
        )
        cnf = workspace / "public.cnf"
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
            raise O1C49ScreenError("public Full256 instance differs")
        decisions = workspace / "primary.ordered-pair-variables"
        decision_sha256 = write_online_pair_credit_decision_variables(
            decisions, plan.ordered_variables
        )
        online_full_result = run_online_pair_credit_search(
            executable=online_executable,
            cnf_path=cnf,
            potential_path=paths["primary_potential"],
            decision_variables_path=decisions,
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
        )
        native_solver_calls += 1
        requested_conflicts += CONFLICT_LIMIT
        online_full_row, online_full_model = _search_row(
            name="online_primary", result=online_full_result, public=public
        )
        attacker_freeze = {
            "schema": "o1-256-online-pair-credit-screen-attacker-freeze-v1",
            "target_id": publication.get("target_id"),
            "public_view_sha256": public.digest(),
            "full256_unknown_key_bits": 256,
            "target_key_reads": 0,
            "reveal_reads": 0,
            "o1c48_result_reads": 0,
            "online_full256_search": online_full_row,
            "pair_plan": plan.describe(),
            "decision_variables_sha256": decision_sha256,
            "public_instance": instance.describe(),
        }
        attacker_freeze_bytes = _canonical_json_bytes(attacker_freeze)
        attacker_freeze_sha256 = hashlib.sha256(attacker_freeze_bytes).hexdigest()
        attacker_freeze = _json_object(attacker_freeze_bytes, "attacker freeze")

        reveal_payload = _json_bytes(paths["reveal"], str(expected["reveal"]), "reveal")
        reveal = verify_reveal(_json_object(reveal_payload, "reveal"))
        preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
        try:
            truth_key = bytes.fromhex(str(preimage["key_hex"]))
        except (KeyError, ValueError) as exc:
            raise O1C49ScreenError("revealed key differs") from exc
        if len(truth_key) != 32 or not model_matches_public(truth_key, public):
            raise O1C49ScreenError("revealed key fails public verification")
        o1c48_path = (root / O1C48_RESULT).resolve(strict=True)
        o1c48 = _json_object(
            _json_bytes(o1c48_path, O1C48_RESULT_SHA256, "O1C-0048 result"),
            "O1C-0048 result",
        )
        if (
            o1c48.get("attempt_id") != "O1C-0048"
            or o1c48.get("classification") != "PAIR_ENVELOPE_NO_STRICT_PRIMARY_GAIN"
            or _mapping(o1c48.get("target"), "O1C-0048 target").get(
                "public_view_sha256"
            )
            != public.digest()
        ):
            raise O1C49ScreenError("O1C-0048 baseline identity differs")
        static_full_candidates = [
            row
            for row in _rows(o1c48.get("full256_search"), "O1C-0048 full rows")
            if row.get("name") == "primary"
        ]
        if len(static_full_candidates) != 1:
            raise O1C49ScreenError("O1C-0048 static Full256 baseline differs")
        static_full_row = static_full_candidates[0]
        static_rows.extend(
            row
            for row in _rows(o1c48.get("residual_search"), "O1C-0048 residual rows")
            if row.get("name") == "primary" and row.get("residual_bits") in (8, 9)
        )
        if (
            len(static_rows) != 2
            or {
                _integer(row.get("residual_bits"), "static residual width")
                for row in static_rows
            }
            != {8, 9}
            or not all(
                _exact_residual(row)
                and row.get("status") == "SAT"
                and _integer(row.get("conflict_limit"), "static conflict limit")
                == CONFLICT_LIMIT
                for row in static_rows
            )
        ):
            raise O1C49ScreenError("O1C-0048 static residual baseline differs")
        online_full_row["model_truth_hamming"] = (
            None
            if online_full_model is None
            else model_hamming_distance(online_full_model, truth_key)
        )
        online_full_row["model_truth_exact"] = bool(
            online_full_model is not None and online_full_model == truth_key
        )
        static_full_exact = bool(
            static_full_row.get("status") == "SAT"
            and static_full_row.get("model_publicly_verified") is True
            and static_full_row.get("model_truth_hamming") == 0
        )
        truth_spins = {
            index + 1: (1 if bit else -1)
            for index, bit in enumerate(key_bits(truth_key))
        }
        key_order = _highest_support_key_order(field)
        for width in RESIDUAL_WIDTHS:
            residual = set(key_order[:width])
            fixed = {
                variable: spin
                for variable, spin in truth_spins.items()
                if variable not in residual
            }
            residual_cnf = workspace / f"residual-{width}.cnf"
            prefix = _write_prefix_cnf(cnf, residual_cnf, fixed)
            online_result = run_online_pair_credit_search(
                executable=online_executable,
                cnf_path=residual_cnf,
                potential_path=paths["primary_potential"],
                decision_variables_path=decisions,
                conflict_limit=CONFLICT_LIMIT,
                seed=SEED,
                timeout_seconds=TIMEOUT_SECONDS,
            )
            native_solver_calls += 1
            requested_conflicts += CONFLICT_LIMIT
            online_row, online_model = _search_row(
                name="online_primary", result=online_result, public=public
            )
            _annotate_residual(
                row=online_row,
                model=online_model,
                width=width,
                residual=residual,
                fixed=fixed,
                prefix=prefix,
                truth_key=truth_key,
            )
            online_rows.append(online_row)
            if width in (8, 9):
                borrowed = next(
                    row
                    for row in static_rows
                    if _integer(row.get("residual_bits"), "static residual width")
                    == width
                )
                if (
                    borrowed.get("residual_variables") != sorted(residual)
                    or borrowed.get("prefix") != prefix
                ):
                    raise O1C49ScreenError(
                        "O1C-0048 static residual boundary is not matched"
                    )
            if width == 10:
                static_result = run_pair_envelope_search(
                    executable=static_executable,
                    cnf_path=residual_cnf,
                    potential_path=paths["primary_potential"],
                    decision_variables_path=decisions,
                    conflict_limit=CONFLICT_LIMIT,
                    seed=SEED,
                    timeout_seconds=TIMEOUT_SECONDS,
                )
                native_solver_calls += 1
                requested_conflicts += CONFLICT_LIMIT
                static_row, static_model = _search_row(
                    name="static_primary", result=static_result, public=public
                )
                _annotate_residual(
                    row=static_row,
                    model=static_model,
                    width=width,
                    residual=residual,
                    fixed=fixed,
                    prefix=prefix,
                    truth_key=truth_key,
                )
                static_rows.append(static_row)

        if native_solver_calls != 5 or requested_conflicts != 5 * CONFLICT_LIMIT:
            raise O1C49ScreenError("native solver-call ledger differs")
        if (
            hashlib.sha256(_canonical_json_bytes(attacker_freeze)).hexdigest()
            != attacker_freeze_sha256
        ):
            raise O1C49ScreenError("attacker freeze mutated after reveal")

        gate = evaluate_absolute_gate(
            online_full_exact=bool(online_full_row["model_truth_exact"]),
            static_full_exact=static_full_exact,
            online_rows=online_rows,
            static_rows=static_rows,
        )
        children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
        resources = {
            "elapsed_seconds": time.perf_counter() - started,
            "parent_cpu_seconds": time.process_time() - parent_cpu_started,
            "child_cpu_seconds": (
                children_finished.ru_utime
                + children_finished.ru_stime
                - children_started.ru_utime
                - children_started.ru_stime
            ),
            "peak_rss_bytes": max(
                [
                    _integer(
                        _mapping(row["resources"], "online.resources")[
                            "peak_rss_bytes"
                        ],
                        "online.peak_rss_bytes",
                    )
                    for row in online_rows
                ]
                + [
                    _integer(
                        _mapping(online_full_row["resources"], "online_full.resources")[
                            "peak_rss_bytes"
                        ],
                        "online_full.peak_rss_bytes",
                    )
                ]
                + [
                    _integer(
                        _mapping(row["resources"], "static.resources")[
                            "peak_rss_bytes"
                        ],
                        "static.peak_rss_bytes",
                    )
                    for row in static_rows
                    if row.get("residual_bits") == 10
                ]
            ),
            "native_solver_calls": native_solver_calls,
            "requested_conflicts": requested_conflicts,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        }
        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "started_at": started_at,
            "classification": _classification(gate),
            "claim_level": "CONSUMED_EFFECT_SCREEN",
            "source_commit": source_commit,
            "hypothesis": (
                "bounded target-time credit from public solver outcomes reduces "
                "absolute exact work relative to the frozen static pair scheduler"
            ),
            "attacker_freeze_sha256": attacker_freeze_sha256,
            "attacker_freeze": attacker_freeze,
            "boundary": {
                "full256_search_precedes_reveal": True,
                "full256_attacker_valid": True,
                "residual_rows_post_reveal": True,
                "consumed_target": True,
                "rotation_controls_deferred_until_primary_effect": True,
                "wall_or_telemetry_not_a_pass": True,
            },
            "architecture": {
                "pair_plan": plan.describe(),
                "online_native_build": online_build.describe(),
                "static_native_build": static_build.describe(),
                "online_source_sha256": hashlib.sha256(
                    online_bytes["online_source"]
                ).hexdigest(),
                "online_adapter_sha256": hashlib.sha256(
                    online_bytes["online_adapter"]
                ).hexdigest(),
                "runner_sha256": hashlib.sha256(online_bytes["runner"]).hexdigest(),
                "public_instance": instance.describe(),
                "residual_key_order": list(key_order),
            },
            "online_full256": online_full_row,
            "online_residual": online_rows,
            "static_full256_baseline": static_full_row,
            "static_residual_baseline": static_rows,
            "gate": gate,
            "resources": resources,
            "next_action": (
                "run matched online key/clause rotations before promotion"
                if gate["passed"]
                else "close this exact bounded credit update and retain O1C-0048"
            ),
        }
        if (
            resources["elapsed_seconds"] > MAXIMUM_WALL_SECONDS
            or resources["peak_rss_bytes"] > MAXIMUM_PEAK_RSS_BYTES
        ):
            raise O1C49ScreenError("screen resource boundary exceeded")

    for name, before in pre_reveal_bytes.items():
        if paths[name].read_bytes() != before:
            raise O1C49ScreenError(f"source changed during screen: {name}")
    for name, before in online_bytes.items():
        if online_paths[name].read_bytes() != before:
            raise O1C49ScreenError(f"online source changed during screen: {name}")
    output = Path(output_path)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    if output != (root / RESULT_RELATIVE).resolve():
        raise O1C49ScreenError("result path differs")
    if output.exists():
        raise O1C49ScreenError("authoritative result already exists")
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
    "O1C49ScreenError",
    "RESULT_SCHEMA",
    "evaluate_absolute_gate",
    "run",
]
