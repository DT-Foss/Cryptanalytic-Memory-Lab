"""Prospective W11 screen for bounded per-pattern pair credit."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .criticality_potential import CriticalityPotentialField
from .pattern_credit_search import (
    PATTERN_CREDIT_ACTION_STATE_BYTES,
    PATTERN_CREDIT_DECISION_RULE,
    PATTERN_CREDIT_OWNER_STATE_BYTES,
    PATTERN_CREDIT_STATE_BYTES,
    PatternCreditSearchResult,
    build_native_pattern_credit_search,
    run_pattern_credit_search,
    write_pattern_credit_decision_variables,
)
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
from .o1c48_pair_envelope_search_run import _compile_pair_plans, load_config
from .pair_envelope_search import (
    PAIR_ENVELOPE_DECISION_RULE,
    PAIR_ENVELOPE_DECISION_SCOPE,
    PairEnvelopeSearchResult,
    build_native_pair_envelope_search,
    run_pair_envelope_search,
)
from .proof_parent_criticality import ParentCriticalityField


ATTEMPT_ID = "O1C-0052"
RESULT_SCHEMA = "o1-256-pattern-credit-screen-result-v1"
RESULT_RELATIVE = Path("research/O1C0052_PATTERN_CREDIT_SCREEN_RESULT_20260719.json")
DEFAULT_CONFIG = Path("configs/o1c48_pair_envelope_search_v1.json")
PATTERN_SOURCE = Path("native/cadical_o1_pattern_credit_search.cpp")
PATTERN_ADAPTER = Path("src/o1_crypto_lab/pattern_credit_search.py")
RUNNER_SOURCE = Path("src/o1_crypto_lab/o1c52_pattern_credit_screen.py")
O1C48_RESULT = Path("research/O1C0048_PAIR_ENVELOPE_SEARCH_RESULT_20260719.json")
O1C48_RESULT_SHA256 = "eb5ffc29dbadb0f3722204425309d16b6befe82ea5aabc1075226f856d599663"
O1C49_RESULT = Path("research/O1C0049_ONLINE_PAIR_CREDIT_SCREEN_RESULT_20260719.json")
O1C49_RESULT_SHA256 = "01643f5949020d08b914919e3a465c5c05644ca6422cb44bf23edd5be17795a4"
O1C50_RESULT = Path("research/O1C0050_DELAYED_PAIR_CREDIT_SCREEN_RESULT_20260719.json")
O1C50_RESULT_SHA256 = "2f23214b98c4483344660b016c86f03a2a4285733d10b19b5acd8a6fc8767888"
O1C51_RESULT = Path(
    "research/O1C0051_DELAYED_PAIR_CREDIT_PROMOTION_RESULT_20260719.json"
)
O1C51_RESULT_SHA256 = "aa8fec70d1f97d7a127791699c5340db28168389beeeab32c70d2b1b3121c058"
PAIR_ARMS = ("primary", "key_rotated", "clause_rotated")
ROTATION_ARMS = PAIR_ARMS[1:]
W11_ARMS = (
    "pattern_primary",
    "static_primary",
    "pattern_key_rotated",
    "pattern_clause_rotated",
)
RESIDUAL_WIDTH = 11
CONFLICT_LIMIT = 512
SEED = 0
TIMEOUT_SECONDS = 120.0
MAXIMUM_EARLY_CLOSE_WALL_SECONDS = 130.0
MAXIMUM_PROMOTED_WALL_SECONDS = 900.0
MAXIMUM_PEAK_RSS_BYTES = 512 * 1024 * 1024

_SOURCE_NAMES = (
    "template",
    "semantic_map",
    "publication",
    "field",
    "reveal",
    "primary_potential",
    "key_rotated_potential",
    "clause_rotated_potential",
    "pair_group_source",
    "search_adapter",
    "pair_native_source",
)
_EXPECTED_PRIMARY_PLAN = {
    "group_count": 63,
    "joint_groups": 41,
    "filler_groups": 22,
    "eligible_variables": 126,
    "ordered_variables_sha256": (
        "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
    ),
}
_EXPECTED_W11_RESIDUAL_VARIABLES = [
    9,
    59,
    60,
    143,
    144,
    173,
    174,
    175,
    176,
    177,
    184,
]
_EXPECTED_W11_PREFIX = {
    "clause_count": 188255,
    "fixed_key_bits": 245,
    "residual_key_bits": 11,
    "sha256": "2a6a52f8b599dfd5381d933fc380f502339dd12fe924f142f2860114a22a29bd",
}
_CALL_PLAN = (
    ("qualification", "pattern", "primary", "post-reveal-w11"),
    ("matched-w11", "static", "primary", "post-reveal-w11"),
    ("matched-w11", "pattern", "key_rotated", "post-reveal-w11"),
    ("matched-w11", "pattern", "clause_rotated", "post-reveal-w11"),
    ("full256-promotion", "pattern", "primary", "full256"),
    ("full256-promotion", "pattern", "key_rotated", "full256"),
    ("full256-promotion", "pattern", "clause_rotated", "full256"),
)


class O1C52ScreenError(RuntimeError):
    """The frozen pattern-credit screen boundary was violated."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C52ScreenError(f"{field} differs")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C52ScreenError(f"{field} differs")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise O1C52ScreenError(f"{field} differs")
    return value


def _integer_group(values: Mapping[str, int]) -> dict[str, int]:
    return {str(name): int(value) for name, value in values.items()}


def _rows(value: object, field: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        raise O1C52ScreenError(f"{field} differs")
    return [dict(row) for row in value]


def _json_object(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C52ScreenError(f"{field} JSON differs") from exc
    if not isinstance(value, dict):
        raise O1C52ScreenError(f"{field} JSON root differs")
    return value


def _hashed_json(path: Path, expected_sha256: str, field: str) -> dict[str, object]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C52ScreenError(f"{field} read failed") from exc
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise O1C52ScreenError(f"{field} hash differs")
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
        raise O1C52ScreenError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C52ScreenError(f"{field} differs from source commit")


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _call_descriptor(ordinal: int) -> dict[str, object]:
    stage, mechanism, arm, search_space = _CALL_PLAN[ordinal - 1]
    return {
        "ordinal": ordinal,
        "stage": stage,
        "mechanism": mechanism,
        "arm": arm,
        "search_space": search_space,
        "residual_bits": RESIDUAL_WIDTH if search_space == "post-reveal-w11" else 256,
        "conflict_limit": CONFLICT_LIMIT,
        "seed": SEED,
        "timeout_seconds": TIMEOUT_SECONDS,
        "authorization": (
            "unconditional-first-call"
            if ordinal == 1
            else "exact-pattern-primary-w11-only"
        ),
    }


def call_ledger(pattern_primary_w11_exact: bool) -> dict[str, object]:
    """Return the complete deterministic call ledger for either gate branch."""

    exact = _boolean(pattern_primary_w11_exact, "pattern_primary_w11_exact")
    plan = [_call_descriptor(ordinal) for ordinal in range(1, len(_CALL_PLAN) + 1)]
    executed_count = len(plan) if exact else 1
    executed = plan[:executed_count]
    skipped = plan[executed_count:]
    return {
        "policy": (
            "call-1-pattern-primary-w11;calls-2-through-7-only-after-exact-call-1"
        ),
        "planned_calls": plan,
        "executed_calls": executed,
        "skipped_calls": skipped,
        "executed_call_ordinals": [row["ordinal"] for row in executed],
        "skipped_call_ordinals": [row["ordinal"] for row in skipped],
        "native_solver_calls": executed_count,
        "requested_conflicts": executed_count * CONFLICT_LIMIT,
        "maximum_native_solver_calls": len(plan),
        "maximum_requested_conflicts": len(plan) * CONFLICT_LIMIT,
        "parameter_tuning_calls": 0,
        "cap_tuning_calls": 0,
        "group_tuning_calls": 0,
    }


def evaluate_gate(
    *,
    status: str,
    publicly_verified: bool,
    truth_exact: bool,
    matches_truth_prefix: bool,
) -> dict[str, object]:
    """Authorize follow-ups only from an exact pattern-primary W11 result."""

    if not isinstance(status, str):
        raise O1C52ScreenError("pattern primary W11 status differs")
    public = _boolean(publicly_verified, "publicly_verified")
    exact_truth = _boolean(truth_exact, "truth_exact")
    prefix = _boolean(matches_truth_prefix, "matches_truth_prefix")
    exact = bool(status == "SAT" and public and exact_truth and prefix)
    ledger = call_ledger(exact)
    return {
        "passed": exact,
        "selected_tier": (
            "exact-pattern-primary-w11" if exact else "no-exact-pattern-primary-w11"
        ),
        "pattern_primary_w11_exact": exact,
        "status": status,
        "model_publicly_verified": public,
        "model_truth_exact": exact_truth,
        "model_matches_truth_fixed_prefix": prefix,
        "followup_calls_authorized": exact,
        "expected_native_solver_calls": ledger["native_solver_calls"],
        "expected_requested_conflicts": ledger["requested_conflicts"],
        "exact_key_and_public_verification_required": True,
        "telemetry_cannot_satisfy_gate": True,
        "wall_time_cannot_satisfy_gate": True,
    }


def _exact_mapping(
    value: Mapping[str, bool], names: Sequence[str], field: str
) -> dict[str, bool]:
    if set(value) != set(names):
        raise O1C52ScreenError(f"{field} arm set differs")
    return {name: _boolean(value[name], f"{field}.{name}") for name in names}


def _conflict_mapping(
    value: Mapping[str, int], names: Sequence[str], field: str
) -> dict[str, int]:
    if set(value) != set(names):
        raise O1C52ScreenError(f"{field} arm set differs")
    normalized = {name: _integer(value[name], f"{field}.{name}") for name in names}
    if any(conflicts < 0 for conflicts in normalized.values()):
        raise O1C52ScreenError(f"{field} differs")
    return normalized


def evaluate_promotion(
    *,
    w11_exact_by_arm: Mapping[str, bool],
    w11_conflicts_by_arm: Mapping[str, int],
    pattern_full256_exact_by_arm: Mapping[str, bool],
    static_full256_exact_by_arm: Mapping[str, bool],
) -> dict[str, object]:
    """Summarize matched evidence without changing the W11 authorization gate."""

    w11_exact = _exact_mapping(w11_exact_by_arm, W11_ARMS, "W11 exact")
    w11_conflicts = _conflict_mapping(w11_conflicts_by_arm, W11_ARMS, "W11 conflicts")
    pattern_full = _exact_mapping(
        pattern_full256_exact_by_arm, PAIR_ARMS, "pattern Full256 exact"
    )
    static_full = _exact_mapping(
        static_full256_exact_by_arm, PAIR_ARMS, "static Full256 exact"
    )
    if not w11_exact["pattern_primary"]:
        raise O1C52ScreenError(
            "promotion evidence exists without exact pattern-primary W11"
        )
    primary_conflicts = w11_conflicts["pattern_primary"]
    comparator_names = W11_ARMS[1:]
    primary_specific_w11 = all(
        not w11_exact[name] or primary_conflicts < w11_conflicts[name]
        for name in comparator_names
    )
    any_pattern_full = any(pattern_full.values())
    strict_primary_full = bool(
        pattern_full["primary"]
        and not any(pattern_full[name] for name in ROTATION_ARMS)
        and not any(static_full.values())
    )
    if strict_primary_full:
        selected_tier = "strict-pattern-primary-full256"
    elif pattern_full["primary"]:
        selected_tier = "pattern-primary-full256-without-strict-margin"
    elif any(pattern_full[name] for name in ROTATION_ARMS):
        selected_tier = "pattern-control-full256"
    elif primary_specific_w11:
        selected_tier = "primary-specific-w11"
    else:
        selected_tier = "exact-w11-without-primary-specificity"
    return {
        "selected_tier": selected_tier,
        "w11_exact_by_arm": w11_exact,
        "w11_conflicts_by_arm": w11_conflicts,
        "primary_specific_w11": primary_specific_w11,
        "pattern_full256_exact_by_arm": pattern_full,
        "static_full256_exact_by_arm": static_full,
        "strict_primary_full256_recovery": strict_primary_full,
        "any_pattern_full256_recovery": any_pattern_full,
        "does_not_change_w11_authorization_gate": True,
    }


def _classification(
    gate: Mapping[str, object], promotion: Mapping[str, object] | None
) -> str:
    if gate.get("passed") is not True:
        return "PATTERN_ACTION_CREDIT_NO_EXACT_W11_CLOSE"
    if promotion is None:
        raise O1C52ScreenError("promotion summary is absent after W11 pass")
    if promotion.get("strict_primary_full256_recovery") is True:
        return (
            "PUBLIC_INPUT_CONSUMED_PATTERN_ACTION_CREDIT_PRIMARY_STRICT_"
            "FULL256_RECOVERY"
        )
    pattern_full = _mapping(
        promotion.get("pattern_full256_exact_by_arm"), "pattern Full256 promotion"
    )
    if pattern_full.get("primary") is True:
        return "PATTERN_ACTION_CREDIT_PRIMARY_FULL256_WITHOUT_STRICT_MARGIN"
    if any(pattern_full.get(name) is True for name in ROTATION_ARMS):
        return "PATTERN_ACTION_CREDIT_CONTROL_FULL256_RECOVERY"
    if promotion.get("primary_specific_w11") is True:
        return "PATTERN_ACTION_CREDIT_PRIMARY_SPECIFIC_W11_EXPANSION"
    return "PATTERN_ACTION_CREDIT_EXACT_W11_WITHOUT_PRIMARY_SPECIFICITY"


def _model_honors_fixed_spins(model: bytes, fixed_spins: Mapping[int, int]) -> bool:
    if len(model) != 32:
        raise O1C52ScreenError("search model width differs")
    bits = key_bits(model)
    return all(
        (1 if bits[variable - 1] else -1) == spin
        for variable, spin in fixed_spins.items()
    )


def _search_row(
    *,
    name: str,
    mechanism: str,
    arm: str,
    result: PatternCreditSearchResult | PairEnvelopeSearchResult,
    public: PublicTargetView,
    truth_key: bytes,
    residual: set[int] | None = None,
    fixed: Mapping[int, int] | None = None,
    prefix: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if result.conflict_limit != CONFLICT_LIMIT:
        raise O1C52ScreenError(f"conflict cap differs for {name}")
    model = result.key_model
    publicly_verified = bool(model is not None and model_matches_public(model, public))
    if result.status_name == "SAT" and not publicly_verified:
        raise O1C52ScreenError(f"SAT model failed public verification for {name}")
    hamming = None if model is None else model_hamming_distance(model, truth_key)
    truth_exact = bool(
        result.status_name == "SAT"
        and publicly_verified
        and model is not None
        and hamming == 0
    )
    row: dict[str, object] = {
        "name": name,
        "mechanism": mechanism,
        "arm": arm,
        "status": result.status_name,
        "conflict_limit": result.conflict_limit,
        "model_publicly_verified": publicly_verified,
        "model_sha256": None if model is None else hashlib.sha256(model).hexdigest(),
        "model_truth_hamming": hamming,
        "model_truth_exact": truth_exact,
        "stats": _integer_group(result.stats),
        "resources": _integer_group(result.resources),
    }
    if isinstance(result, PatternCreditSearchResult):
        row["pattern"] = dict(result.pattern)
    else:
        row["pair_envelope"] = dict(result.pair_envelope)
    if residual is not None:
        if fixed is None or prefix is None:
            raise O1C52ScreenError(f"residual annotation differs for {name}")
        honors_prefix = bool(
            model is not None and _model_honors_fixed_spins(model, fixed)
        )
        if model is not None and not honors_prefix:
            raise O1C52ScreenError(f"model violates truth prefix for {name}")
        row.update(
            {
                "residual_bits": RESIDUAL_WIDTH,
                "residual_variables": sorted(residual),
                "privileged_post_reveal_prefix": True,
                "prefix": dict(prefix),
                "model_matches_truth_fixed_prefix": honors_prefix,
            }
        )
    return row


def _row_exact(row: Mapping[str, object], *, residual: bool) -> bool:
    exact = bool(
        row.get("status") == "SAT"
        and row.get("model_publicly_verified") is True
        and row.get("model_truth_exact") is True
    )
    if residual:
        exact = exact and row.get("model_matches_truth_fixed_prefix") is True
    return exact


def _validate_pattern_contract(
    row: Mapping[str, object],
    *,
    decision_sha256: str,
    pair_count: int,
) -> None:
    pattern = _mapping(row.get("pattern"), "pattern row")
    state = _mapping(pattern.get("state"), "pattern state")
    if (
        pattern.get("decision_rule") != PATTERN_CREDIT_DECISION_RULE
        or pattern.get("decision_scope") != PAIR_ENVELOPE_DECISION_SCOPE
        or pattern.get("decision_variables_sha256") != decision_sha256
        or _integer(pattern.get("pair_count"), "pattern pair count") != pair_count
        or _integer(pattern.get("group_width"), "pattern group width") != 2
        or _integer(state.get("bounded_state_bytes"), "pattern bounded state bytes")
        != PATTERN_CREDIT_STATE_BYTES
        or _integer(
            state.get("bounded_action_state_bytes"),
            "pattern bounded action state bytes",
        )
        != PATTERN_CREDIT_ACTION_STATE_BYTES
        or _integer(
            state.get("bounded_owner_state_bytes"),
            "pattern bounded owner state bytes",
        )
        != PATTERN_CREDIT_OWNER_STATE_BYTES
    ):
        raise O1C52ScreenError("frozen pattern native contract differs")


def _validate_static_contract(
    row: Mapping[str, object],
    *,
    decision_sha256: str,
    pair_count: int,
) -> None:
    envelope = _mapping(row.get("pair_envelope"), "static pair envelope")
    if (
        envelope.get("decision_rule") != PAIR_ENVELOPE_DECISION_RULE
        or envelope.get("decision_scope") != PAIR_ENVELOPE_DECISION_SCOPE
        or envelope.get("decision_variables_sha256") != decision_sha256
        or _integer(envelope.get("pair_count"), "static pair count") != pair_count
        or _integer(envelope.get("group_width"), "static group width") != 2
    ):
        raise O1C52ScreenError("frozen static native contract differs")


def _frozen_static_full256_rows(
    *,
    o1c48: Mapping[str, object],
    o1c49: Mapping[str, object],
    public_view_sha256: str,
) -> tuple[list[dict[str, object]], dict[str, bool]]:
    if (
        o1c48.get("schema") != "o1-256-pair-envelope-search-result-v1"
        or o1c48.get("attempt_id") != "O1C-0048"
        or o1c48.get("classification") != "PAIR_ENVELOPE_NO_STRICT_PRIMARY_GAIN"
        or _mapping(o1c48.get("target"), "O1C-0048 target").get("public_view_sha256")
        != public_view_sha256
        or o1c49.get("schema") != "o1-256-online-pair-credit-screen-result-v1"
        or o1c49.get("attempt_id") != "O1C-0049"
        or o1c49.get("classification") != "ONLINE_PAIR_CREDIT_NO_ABSOLUTE_PRIMARY_GAIN"
        or _mapping(o1c49.get("attacker_freeze"), "O1C-0049 freeze").get(
            "public_view_sha256"
        )
        != public_view_sha256
    ):
        raise O1C52ScreenError("frozen static Full256 identity differs")
    candidates = [
        row
        for row in _rows(o1c48.get("full256_search"), "O1C-0048 Full256 rows")
        if row.get("name") in PAIR_ARMS
    ]
    if len(candidates) != len(PAIR_ARMS) or [
        str(row.get("name")) for row in candidates
    ] != list(PAIR_ARMS):
        raise O1C52ScreenError("frozen static Full256 arm order differs")
    primary = next(row for row in candidates if row.get("name") == "primary")
    if o1c49.get("static_full256_baseline") != primary:
        raise O1C52ScreenError("O1C-0048/O1C-0049 static primary differs")
    exact_by_arm: dict[str, bool] = {}
    for row in candidates:
        name = str(row["name"])
        if (
            _integer(row.get("conflict_limit"), f"static {name} cap") != CONFLICT_LIMIT
            or row.get("status") != "UNKNOWN"
            or row.get("model_publicly_verified") is not False
            or row.get("model_truth_hamming") is not None
        ):
            raise O1C52ScreenError(f"frozen static Full256 row differs for {name}")
        exact_by_arm[name] = False
    return candidates, exact_by_arm


def _next_action(
    gate: Mapping[str, object], promotion: Mapping[str, object] | None
) -> str:
    if gate.get("passed") is not True:
        return (
            "close pattern action credit on the frozen disjoint pair groups after "
            "one W11 call"
        )
    if promotion is None:
        raise O1C52ScreenError("promotion summary is absent after W11 pass")
    if promotion.get("strict_primary_full256_recovery") is True:
        return (
            "report the consumed public-input strict-primary pattern action-credit "
            "Full256 recovery"
        )
    if promotion.get("any_pattern_full256_recovery") is True:
        return (
            "retain the consumed public-input pattern action-credit Full256 result "
            "with its control classification"
        )
    return (
        "retain the pattern action-credit W11 expansion and close this scheduler "
        "at its measured ceiling"
    )


def run(
    config_path: str | Path = DEFAULT_CONFIG,
    output_path: str | Path = RESULT_RELATIVE,
) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    config_file = Path(config_path)
    if not config_file.is_absolute():
        config_file = root / config_file
    config_file = config_file.resolve(strict=True)
    config_bytes = config_file.read_bytes()
    config = load_config(config_file)
    source = _mapping(config["source"], "config.source")
    expected = _mapping(source["expected_sha256"], "config.expected")
    paths = {
        name: _relative_path(root, source[name], f"source.{name}")
        for name in _SOURCE_NAMES
    }
    source_bytes = {name: paths[name].read_bytes() for name in _SOURCE_NAMES}
    for name, payload in source_bytes.items():
        if hashlib.sha256(payload).hexdigest() != expected.get(name):
            raise O1C52ScreenError(f"frozen O1C-0048 source differs: {name}")

    output = Path(output_path)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    if output != (root / RESULT_RELATIVE).resolve():
        raise O1C52ScreenError("result path differs")
    if output.exists():
        raise O1C52ScreenError("authoritative result already exists")

    implementation_paths = {
        "pattern_source": (root / PATTERN_SOURCE).resolve(strict=True),
        "pattern_adapter": (root / PATTERN_ADAPTER).resolve(strict=True),
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
    if (
        publication.get("schema") != "o1-256-sealed-publication-v1"
        or publication.get("target_id") != "o1c-0044-fresh-0000"
        or publication.get("public_view_sha256") != public.digest()
    ):
        raise O1C52ScreenError("consumed public target differs")
    reveal = verify_reveal(_json_object(source_bytes["reveal"], "reveal"))
    preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
    try:
        truth_key = bytes.fromhex(str(preimage["key_hex"]))
    except (KeyError, ValueError) as exc:
        raise O1C52ScreenError("revealed key differs") from exc
    truth_sha256 = hashlib.sha256(truth_key).hexdigest()
    if (
        len(truth_key) != 32
        or preimage.get("target_id") != publication.get("target_id")
        or preimage.get("public_view_sha256") != public.digest()
        or not model_matches_public(truth_key, public)
    ):
        raise O1C52ScreenError("revealed key fails target/public verification")

    field = ParentCriticalityField.from_bytes(source_bytes["field"])
    potentials = {
        name: CriticalityPotentialField.from_bytes(source_bytes[f"{name}_potential"])
        for name in PAIR_ARMS
    }
    _, plans, plan_validation = _compile_pair_plans(field, potentials)
    if plans["primary"].describe() != _EXPECTED_PRIMARY_PLAN:
        raise O1C52ScreenError("frozen primary pair plan differs")

    o1c48_path = root / O1C48_RESULT
    o1c49_path = root / O1C49_RESULT
    o1c50_path = (root / O1C50_RESULT).resolve(strict=True)
    o1c51_path = (root / O1C51_RESULT).resolve(strict=True)
    baseline_bytes = {
        "o1c50": o1c50_path.read_bytes(),
        "o1c51": o1c51_path.read_bytes(),
    }
    o1c50 = _hashed_json(o1c50_path, O1C50_RESULT_SHA256, "O1C-0050 result")
    o1c51 = _hashed_json(o1c51_path, O1C51_RESULT_SHA256, "O1C-0051 result")
    old50_architecture = _mapping(o1c50.get("architecture"), "O1C-0050 architecture")
    old50_gate = _mapping(o1c50.get("gate"), "O1C-0050 gate")
    old50_w10 = _mapping(o1c50.get("delayed_w10"), "O1C-0050 W10")
    if (
        o1c50.get("schema") != "o1-256-delayed-pair-credit-screen-result-v1"
        or o1c50.get("attempt_id") != "O1C-0050"
        or o1c50.get("classification") != "DELAYED_PAIR_CREDIT_STRICT_W10_GAIN"
        or old50_gate.get("passed") is not True
        or old50_gate.get("delayed_exact_w10") is not True
        or _integer(old50_gate.get("delayed_conflicts"), "O1C-0050 conflicts") != 302
        or _integer(old50_w10.get("conflict_limit"), "O1C-0050 cap") != CONFLICT_LIMIT
        or old50_w10.get("model_truth_exact") is not True
        or old50_w10.get("model_publicly_verified") is not True
        or old50_w10.get("model_matches_truth_fixed_prefix") is not True
        or old50_architecture.get("pair_plan") != plans["primary"].describe()
        or _mapping(o1c50.get("static_w10_baseline"), "O1C-0050 static W10").get(
            "model_sha256"
        )
        != truth_sha256
    ):
        raise O1C52ScreenError("frozen O1C-0050 mechanism boundary differs")

    old51_architecture = _mapping(o1c51.get("architecture"), "O1C-0051 architecture")
    old51_gate = _mapping(o1c51.get("gate"), "O1C-0051 gate")
    old51_w11_search = _mapping(o1c51.get("w11_search"), "O1C-0051 W11 search")
    old51_w11 = _mapping(
        old51_w11_search.get("delayed_primary"), "O1C-0051 delayed primary"
    )
    old51_ledger = _mapping(o1c51.get("call_ledger"), "O1C-0051 call ledger")
    old51_target = _mapping(o1c51.get("target"), "O1C-0051 target")
    if (
        o1c51.get("schema") != "o1-256-delayed-pair-credit-promotion-result-v1"
        or o1c51.get("attempt_id") != "O1C-0051"
        or o1c51.get("source_commit") != "652d2c62be236cb421ecac86a6d09a6f65156dd3"
        or o1c51.get("classification") != "DELAYED_PAIR_CREDIT_NO_EXACT_W11_CLOSE"
        or old51_target.get("public_view_sha256") != public.digest()
        or old51_target.get("truth_key_sha256") != truth_sha256
        or old51_target.get("truth_publicly_verified") is not True
        or old51_architecture.get("primary_pair_plan") != plans["primary"].describe()
        or old51_architecture.get("delayed_source_sha256")
        != old50_architecture.get("delayed_source_sha256")
        or old51_architecture.get("delayed_adapter_sha256")
        != old50_architecture.get("delayed_adapter_sha256")
        or old51_architecture.get("public_instance")
        != old50_architecture.get("public_instance")
        or old51_architecture.get("w11_residual_variables")
        != _EXPECTED_W11_RESIDUAL_VARIABLES
        or old51_gate.get("passed") is not False
        or old51_gate.get("selected_tier") != "no-exact-delayed-primary-w11"
        or old51_gate.get("followup_calls_authorized") is not False
        or old51_w11.get("status") != "UNKNOWN"
        or _integer(old51_w11.get("conflict_limit"), "O1C-0051 cap") != CONFLICT_LIMIT
        or old51_w11.get("residual_variables") != _EXPECTED_W11_RESIDUAL_VARIABLES
        or old51_w11.get("prefix") != _EXPECTED_W11_PREFIX
        or old51_w11.get("model_publicly_verified") is not False
        or old51_w11.get("model_truth_exact") is not False
        or old51_w11.get("model_matches_truth_fixed_prefix") is not False
        or _mapping(old51_w11.get("stats"), "O1C-0051 stats")
        != {"conflicts": 512, "decisions": 513, "propagations": 11983327}
        or old51_w11_search.get("static_primary") is not None
        or old51_w11_search.get("delayed_rotations") != []
        or o1c51.get("delayed_full256") != []
        or o1c51.get("static_full256_baseline") != []
        or o1c51.get("promotion") is not None
        or _integer(old51_ledger.get("native_solver_calls"), "O1C-0051 calls") != 1
        or _integer(
            old51_ledger.get("requested_conflicts"), "O1C-0051 requested conflicts"
        )
        != CONFLICT_LIMIT
        or _mapping(o1c51.get("baseline_sha256"), "O1C-0051 baselines").get("O1C-0050")
        != O1C50_RESULT_SHA256
    ):
        raise O1C52ScreenError("frozen O1C-0051 screen boundary differs")

    truth_spins = {
        index + 1: (1 if bit else -1) for index, bit in enumerate(key_bits(truth_key))
    }
    key_order = _highest_support_key_order(field)
    old50_residual = old50_w10.get("residual_variables")
    if old50_residual != sorted(key_order[:10]):
        raise O1C52ScreenError("frozen O1C-0050 residual order differs")
    residual = set(key_order[:RESIDUAL_WIDTH])
    if (
        len(residual) != RESIDUAL_WIDTH
        or sorted(residual) != _EXPECTED_W11_RESIDUAL_VARIABLES
    ):
        raise O1C52ScreenError("W11 residual coordinates differ")
    fixed = {
        variable: spin
        for variable, spin in truth_spins.items()
        if variable not in residual
    }

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    executed_calls: list[dict[str, object]] = []
    w11_static_primary: dict[str, object] | None = None
    pattern_w11_rotations: list[dict[str, object]] = []
    pattern_full256_rows: list[dict[str, object]] = []
    static_full256_rows: list[dict[str, object]] = []
    static_full_exact: dict[str, bool] = {}
    static_full256_provenance: dict[str, list[str]] = {}
    baseline_hashes = {
        "O1C-0050": O1C50_RESULT_SHA256,
        "O1C-0051": O1C51_RESULT_SHA256,
    }
    all_executed_rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="o1c52-") as temporary:
        workspace = Path(temporary)
        pattern_executable = workspace / "cadical-o1-pattern-credit"
        static_executable = workspace / "cadical-o1-static-pair-envelope"
        pattern_build = build_native_pattern_credit_search(
            source=implementation_paths["pattern_source"],
            output=pattern_executable,
        )
        static_build = None
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
            or old50_architecture.get("public_instance") != instance.describe()
            or old51_architecture.get("public_instance") != instance.describe()
        ):
            raise O1C52ScreenError("public Full256 instance differs")
        residual_cnf = workspace / "residual-11.cnf"
        prefix = _write_prefix_cnf(public_cnf, residual_cnf, fixed)
        if prefix != _EXPECTED_W11_PREFIX:
            raise O1C52ScreenError("frozen W11 prefix differs")

        potential_paths = {name: paths[f"{name}_potential"] for name in PAIR_ARMS}
        decision_paths: dict[str, Path] = {}
        decision_hashes: dict[str, str] = {}
        for name in PAIR_ARMS:
            destination = workspace / f"{name}.ordered-pair-variables"
            decision_hashes[name] = write_pattern_credit_decision_variables(
                destination, plans[name].ordered_variables
            )
            decision_paths[name] = destination

        def run_pattern(
            arm: str,
            cnf: Path,
            *,
            residual_call: bool,
            name: str,
        ) -> dict[str, object]:
            result = run_pattern_credit_search(
                executable=pattern_executable,
                cnf_path=cnf,
                potential_path=potential_paths[arm],
                decision_variables_path=decision_paths[arm],
                conflict_limit=CONFLICT_LIMIT,
                seed=SEED,
                timeout_seconds=TIMEOUT_SECONDS,
            )
            row = _search_row(
                name=name,
                mechanism="pattern",
                arm=arm,
                result=result,
                public=public,
                truth_key=truth_key,
                residual=residual if residual_call else None,
                fixed=fixed if residual_call else None,
                prefix=prefix if residual_call else None,
            )
            _validate_pattern_contract(
                row,
                decision_sha256=decision_hashes[arm],
                pair_count=len(plans[arm].groups),
            )
            all_executed_rows.append(row)
            return row

        pattern_primary_w11 = run_pattern(
            "primary",
            residual_cnf,
            residual_call=True,
            name="pattern_primary_w11",
        )
        executed_calls.append(_call_descriptor(1))
        gate = evaluate_gate(
            status=str(pattern_primary_w11["status"]),
            publicly_verified=pattern_primary_w11["model_publicly_verified"] is True,
            truth_exact=pattern_primary_w11["model_truth_exact"] is True,
            matches_truth_prefix=pattern_primary_w11["model_matches_truth_fixed_prefix"]
            is True,
        )
        primary_w11_exact = gate["passed"] is True

        if primary_w11_exact:
            resolved_o1c48 = o1c48_path.resolve(strict=True)
            resolved_o1c49 = o1c49_path.resolve(strict=True)
            baseline_bytes["o1c48"] = resolved_o1c48.read_bytes()
            baseline_bytes["o1c49"] = resolved_o1c49.read_bytes()
            o1c48 = _hashed_json(resolved_o1c48, O1C48_RESULT_SHA256, "O1C-0048 result")
            o1c49 = _hashed_json(resolved_o1c49, O1C49_RESULT_SHA256, "O1C-0049 result")
            static_full256_rows, static_full_exact = _frozen_static_full256_rows(
                o1c48=o1c48,
                o1c49=o1c49,
                public_view_sha256=public.digest(),
            )
            static_full256_provenance = {
                "primary": ["O1C-0048", "O1C-0049"],
                "key_rotated": ["O1C-0048"],
                "clause_rotated": ["O1C-0048"],
            }
            baseline_hashes.update(
                {
                    "O1C-0048": O1C48_RESULT_SHA256,
                    "O1C-0049": O1C49_RESULT_SHA256,
                }
            )
            static_build = build_native_pair_envelope_search(
                source=paths["pair_native_source"], output=static_executable
            )
            static_result = run_pair_envelope_search(
                executable=static_executable,
                cnf_path=residual_cnf,
                potential_path=potential_paths["primary"],
                decision_variables_path=decision_paths["primary"],
                conflict_limit=CONFLICT_LIMIT,
                seed=SEED,
                timeout_seconds=TIMEOUT_SECONDS,
            )
            w11_static_primary = _search_row(
                name="static_primary_w11",
                mechanism="static",
                arm="primary",
                result=static_result,
                public=public,
                truth_key=truth_key,
                residual=residual,
                fixed=fixed,
                prefix=prefix,
            )
            _validate_static_contract(
                w11_static_primary,
                decision_sha256=decision_hashes["primary"],
                pair_count=len(plans["primary"].groups),
            )
            all_executed_rows.append(w11_static_primary)
            executed_calls.append(_call_descriptor(2))

            for ordinal, arm in enumerate(ROTATION_ARMS, start=3):
                row = run_pattern(
                    arm,
                    residual_cnf,
                    residual_call=True,
                    name=f"pattern_{arm}_w11",
                )
                pattern_w11_rotations.append(row)
                executed_calls.append(_call_descriptor(ordinal))

            for ordinal, arm in enumerate(PAIR_ARMS, start=5):
                row = run_pattern(
                    arm,
                    public_cnf,
                    residual_call=False,
                    name=f"pattern_{arm}_full256",
                )
                pattern_full256_rows.append(row)
                executed_calls.append(_call_descriptor(ordinal))

        expected_ledger = call_ledger(primary_w11_exact)
        if executed_calls != expected_ledger["executed_calls"]:
            raise O1C52ScreenError("native solver call order differs")

        promotion: dict[str, object] | None = None
        if primary_w11_exact:
            if w11_static_primary is None:
                raise O1C52ScreenError("matched static W11 row is absent")
            w11_rotation_by_arm = {
                str(row["arm"]): row for row in pattern_w11_rotations
            }
            full_by_arm = {str(row["arm"]): row for row in pattern_full256_rows}
            if set(w11_rotation_by_arm) != set(ROTATION_ARMS) or set(
                full_by_arm
            ) != set(PAIR_ARMS):
                raise O1C52ScreenError("promotion result arm set differs")
            w11_by_name = {
                "pattern_primary": pattern_primary_w11,
                "static_primary": w11_static_primary,
                "pattern_key_rotated": w11_rotation_by_arm["key_rotated"],
                "pattern_clause_rotated": w11_rotation_by_arm["clause_rotated"],
            }
            promotion = evaluate_promotion(
                w11_exact_by_arm={
                    name: _row_exact(row, residual=True)
                    for name, row in w11_by_name.items()
                },
                w11_conflicts_by_arm={
                    name: _integer(
                        _mapping(row["stats"], f"{name}.stats").get("conflicts"),
                        f"{name}.conflicts",
                    )
                    for name, row in w11_by_name.items()
                },
                pattern_full256_exact_by_arm={
                    name: _row_exact(full_by_arm[name], residual=False)
                    for name in PAIR_ARMS
                },
                static_full256_exact_by_arm=static_full_exact,
            )

        children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
        elapsed = time.perf_counter() - started
        peak_rss = max(
            [_peak_rss_bytes()]
            + [
                _integer(
                    _mapping(row["resources"], "search resources").get(
                        "peak_rss_bytes"
                    ),
                    "search peak RSS",
                )
                for row in all_executed_rows
            ]
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
            "native_solver_calls": expected_ledger["native_solver_calls"],
            "requested_conflicts": expected_ledger["requested_conflicts"],
            "maximum_native_solver_calls": expected_ledger[
                "maximum_native_solver_calls"
            ],
            "maximum_requested_conflicts": expected_ledger[
                "maximum_requested_conflicts"
            ],
            "scored_call_timeout_seconds": TIMEOUT_SECONDS,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        }
        maximum_wall = (
            MAXIMUM_PROMOTED_WALL_SECONDS
            if primary_w11_exact
            else MAXIMUM_EARLY_CLOSE_WALL_SECONDS
        )
        if elapsed > maximum_wall or peak_rss > MAXIMUM_PEAK_RSS_BYTES:
            raise O1C52ScreenError("promotion resource boundary exceeded")

        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "attempt_id": ATTEMPT_ID,
            "started_at": started_at,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "source_commit": source_commit,
            "classification": _classification(gate, promotion),
            "claim_level": "CONSUMED_POST_REVEAL_PATTERN_ACTION_CREDIT_SCREEN",
            "hypothesis": (
                "bounded per-pattern action credit separates the four action and "
                "polarity cells that remained aliased by O1C-0051, expanding exact "
                "completion at W11 under the same 512-conflict cap"
            ),
            "boundary": {
                "consumed_target": True,
                "post_reveal_qualification": True,
                "qualification_unknown_residual_bits": RESIDUAL_WIDTH,
                "truth_fixed_key_bits": 256 - RESIDUAL_WIDTH,
                "first_native_call_is_pattern_primary_w11": True,
                "followups_require_exact_pattern_primary_w11": True,
                "followups_execute_without_intervening_tuning": True,
                "full256_solver_inputs_are_public_only": True,
                "full256_calls_are_consumed_promotion_not_fresh_evidence": True,
                "frozen_o1c50_and_o1c51_boundaries": True,
                "four_action_cells_per_pair_group": True,
                "same_conflict_cap_for_every_call": True,
                "parameter_tuning": 0,
                "cap_tuning": 0,
                "group_tuning": 0,
                "fresh_targets": 0,
                "sibling_reads": 0,
                "sibling_writes": 0,
                "MPS_or_GPU": False,
                "telemetry_or_wall_cannot_pass": True,
            },
            "target": {
                "target_id": publication.get("target_id"),
                "public_view_sha256": public.digest(),
                "truth_key_sha256": truth_sha256,
                "truth_publicly_verified": True,
            },
            "architecture": {
                "primary_pair_plan": plans["primary"].describe(),
                "pair_plans": {name: plans[name].describe() for name in PAIR_ARMS},
                "pair_plan_validation": plan_validation,
                "ordered_pair_file_sha256": decision_hashes,
                "pattern_native_build": pattern_build.describe(),
                "static_native_build": (
                    None if static_build is None else static_build.describe()
                ),
                "pattern_source_sha256": hashlib.sha256(
                    implementation_bytes["pattern_source"]
                ).hexdigest(),
                "pattern_adapter_sha256": hashlib.sha256(
                    implementation_bytes["pattern_adapter"]
                ).hexdigest(),
                "runner_sha256": hashlib.sha256(
                    implementation_bytes["runner"]
                ).hexdigest(),
                "public_instance": instance.describe(),
                "residual_key_order": list(key_order),
                "w11_residual_variables": sorted(residual),
            },
            "w11_search": {
                "pattern_primary": pattern_primary_w11,
                "static_primary": w11_static_primary,
                "pattern_rotations": pattern_w11_rotations,
            },
            "pattern_full256": pattern_full256_rows,
            "static_full256_baseline": static_full256_rows,
            "static_full256_baseline_provenance": static_full256_provenance,
            "gate": gate,
            "promotion": promotion,
            "call_ledger": expected_ledger,
            "resources": resources,
            "source_sha256": {
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in source_bytes.items()
            },
            "baseline_sha256": baseline_hashes,
            "next_action": _next_action(gate, promotion),
        }

    if config_file.read_bytes() != config_bytes:
        raise O1C52ScreenError("config changed during promotion")
    for name, before in source_bytes.items():
        if paths[name].read_bytes() != before:
            raise O1C52ScreenError(f"source changed during promotion: {name}")
    for name, before in implementation_bytes.items():
        if implementation_paths[name].read_bytes() != before:
            raise O1C52ScreenError(f"implementation changed during promotion: {name}")
    baseline_paths = {
        "o1c48": o1c48_path,
        "o1c49": o1c49_path,
        "o1c50": o1c50_path,
        "o1c51": o1c51_path,
    }
    for name, before in baseline_bytes.items():
        path = baseline_paths[name]
        if path.read_bytes() != before:
            raise O1C52ScreenError(f"frozen baseline changed during promotion: {name}")
    if output.exists():
        raise O1C52ScreenError("authoritative result appeared during promotion")
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
    "O1C52ScreenError",
    "RESULT_SCHEMA",
    "call_ledger",
    "evaluate_gate",
    "evaluate_promotion",
    "run",
]
