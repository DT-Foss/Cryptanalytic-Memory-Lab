"""One-call W11 screen for exact clause-role owner credit."""

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

from .criticality_pair_groups import compile_primary_pair_groups
from .criticality_potential import CriticalityPotentialField
from .full256_broker import public_view_from_publication, verify_reveal
from .full256_cnf import verify_full256_instance, write_full256_instance
from .clause_role_credit_search import (
    CLAUSE_ROLE_CREDIT_ACTION_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_CALLBACK_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_DECISION_RULE,
    CLAUSE_ROLE_CREDIT_OWNER_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_STATE_BYTES,
    CLAUSE_ROLE_CREDIT_UPDATE_FORMULA,
    ClauseRoleCreditSearchResult,
    build_native_clause_role_credit_search,
    run_clause_role_credit_search,
    write_clause_role_credit_decision_variables,
)
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
from .pair_envelope_search import PAIR_ENVELOPE_DECISION_SCOPE
from .proof_parent_criticality import ParentCriticalityField


ATTEMPT_ID = "O1C-0056"
RESULT_SCHEMA = "o1-256-clause-role-credit-screen-result-v1"
RESULT_RELATIVE = Path(
    "research/O1C0056_CLAUSE_ROLE_CREDIT_SCREEN_RESULT_20260719.json"
)
DEFAULT_CONFIG = Path("configs/o1c48_pair_envelope_search_v1.json")
NATIVE_SOURCE = Path("native/cadical_o1_clause_role_credit_search.cpp")
ADAPTER_SOURCE = Path("src/o1_crypto_lab/clause_role_credit_search.py")
RUNNER_SOURCE = Path("src/o1_crypto_lab/o1c56_clause_role_credit_screen.py")
O1C55_RESULT = Path(
    "research/O1C0055_LEARNED_CLAUSE_CREDIT_SCREEN_RESULT_20260719.json"
)
O1C55_RESULT_SHA256 = "569b9770a690357b64dcfc44bce79b1a7eedb1f9688e5c03ad6f185b50adc9b8"
CLAUSE_ROLE_CORE_COMMIT = "fc25a80"
O1C55_DECISION_RULE = "signed_learned_clause_owner_pattern_credit"

RESIDUAL_WIDTH = 11
CONFLICT_LIMIT = 512
SEED = 0
TIMEOUT_SECONDS = 120.0
MAXIMUM_WALL_SECONDS = 130.0
MAXIMUM_PEAK_RSS_BYTES = 512 * 1024 * 1024
MAXIMUM_NATIVE_SOLVER_CALLS = 1
MAXIMUM_REQUESTED_CONFLICTS = 512

EXPECTED_PUBLIC_VIEW_SHA256 = (
    "3f7841b5080200307564c9cb1956db6a48b2129afd21e85c3e76806735f464a0"
)
EXPECTED_TRUTH_KEY_SHA256 = (
    "722380bf59f57c52b258aebbd423cb8b188ea89bcdb85df114828a9c7fd37246"
)
EXPECTED_REVEAL_SHA256 = (
    "7caf9b1f83465138be80b28677207bf4a5e274b809ec65d55845168d21da0707"
)
EXPECTED_PRIMARY_POTENTIAL_SHA256 = (
    "307a0aeac84ee5efa4e6900f2105727bedbaa3a32b941102960a0257554cdf1e"
)
EXPECTED_W11_RESIDUAL_VARIABLES = (
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
)
EXPECTED_W11_PREFIX = {
    "clause_count": 188255,
    "fixed_key_bits": 245,
    "residual_key_bits": 11,
    "sha256": "2a6a52f8b599dfd5381d933fc380f502339dd12fe924f142f2860114a22a29bd",
}
EXPECTED_PRIMARY_PLAN = {
    "group_count": 63,
    "joint_groups": 41,
    "filler_groups": 22,
    "eligible_variables": 126,
    "ordered_variables_sha256": (
        "51d13c06c6640efc6b0439efa7a85900d30aea79698d18ae58202a33d03fdbd1"
    ),
}

EXACT_RECOVERY_CLASSIFICATION = "CLAUSE_ROLE_CREDIT_EXACT_W11_CLOSE"
MEMBERSHIP_NO_CLOSE_CLASSIFICATION = (
    "CLAUSE_ROLE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE"
)
NO_MEMBERSHIP_CLASSIFICATION = "CLAUSE_ROLE_CREDIT_NO_MEMBERSHIP_NO_EXACT_W11_CLOSE"

_SOURCE_NAMES = (
    "template",
    "semantic_map",
    "publication",
    "field",
    "reveal",
    "primary_potential",
    "pair_group_source",
)


class O1C56ScreenError(RuntimeError):
    """The frozen clause-role-credit screen boundary was violated."""


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise O1C56ScreenError(f"{field} differs")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise O1C56ScreenError(f"{field} differs")
    return value


def _json_object(payload: bytes, field: str) -> dict[str, object]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C56ScreenError(f"{field} JSON differs") from exc
    if not isinstance(value, dict):
        raise O1C56ScreenError(f"{field} JSON root differs")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return value == value.lower()


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
        raise O1C56ScreenError(f"{field} is not bound to source commit") from exc
    if completed.stdout != payload:
        raise O1C56ScreenError(f"{field} differs from source commit")


def _peak_rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _authoritative_output(root: Path, output_path: str | Path) -> Path:
    output = Path(output_path)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    if output != (root / RESULT_RELATIVE).resolve() or output.exists():
        raise O1C56ScreenError("result path differs or authoritative result exists")
    return output


def call_ledger() -> dict[str, object]:
    call = {
        "ordinal": 1,
        "stage": "qualification",
        "mechanism": "deepest-exact-learned-clause-owner-role-credit",
        "arm": "primary",
        "search_space": "post-reveal-w11",
        "residual_bits": RESIDUAL_WIDTH,
        "truth_fixed_bits": 256 - RESIDUAL_WIDTH,
        "conflict_limit": CONFLICT_LIMIT,
        "seed": SEED,
        "timeout_seconds": TIMEOUT_SECONDS,
        "authorization": "unconditional-only-call",
    }
    return {
        "policy": "exactly-one-primary-w11-call-no-promotion",
        "planned_calls": [call],
        "executed_calls": [call],
        "skipped_calls": [],
        "native_solver_calls": 1,
        "requested_conflicts": CONFLICT_LIMIT,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_requested_conflicts": MAXIMUM_REQUESTED_CONFLICTS,
        "parameter_tuning_calls": 0,
        "cap_tuning_calls": 0,
        "group_tuning_calls": 0,
        "rotation_calls": 0,
        "sweep_calls": 0,
        "full256_calls": 0,
        "fresh_target_calls": 0,
        "sibling_reads": 0,
        "sibling_writes": 0,
        "MPS_or_GPU": False,
    }


def classify_result(*, exact_recovery: bool, penalty_updates: int) -> str:
    if not isinstance(exact_recovery, bool):
        raise O1C56ScreenError("exact recovery classification input differs")
    penalties = _integer(penalty_updates, "penalty updates")
    if penalties < 0:
        raise O1C56ScreenError("penalty updates differ")
    if exact_recovery:
        return EXACT_RECOVERY_CLASSIFICATION
    if penalties:
        return MEMBERSHIP_NO_CLOSE_CLASSIFICATION
    return NO_MEMBERSHIP_CLASSIFICATION


def _model_honors_fixed_spins(model: bytes, fixed: Mapping[int, int]) -> bool:
    if len(model) != 32:
        raise O1C56ScreenError("search model width differs")
    bits = key_bits(model)
    return all(
        (1 if bits[variable - 1] else -1) == spin for variable, spin in fixed.items()
    )


def _search_row(
    result: ClauseRoleCreditSearchResult,
    *,
    public: PublicTargetView,
    truth_key: bytes,
    residual: set[int],
    fixed: Mapping[int, int],
    prefix: Mapping[str, object],
) -> dict[str, object]:
    if result.conflict_limit != CONFLICT_LIMIT:
        raise O1C56ScreenError("clause-role conflict cap differs")
    model = result.key_model
    publicly_verified = bool(model is not None and model_matches_public(model, public))
    honors_prefix = bool(model is not None and _model_honors_fixed_spins(model, fixed))
    if result.status_name == "SAT" and (
        model is None or not publicly_verified or not honors_prefix
    ):
        raise O1C56ScreenError("SAT model failed W11 public/prefix verification")
    hamming = None if model is None else model_hamming_distance(model, truth_key)
    exact = bool(
        result.status_name == "SAT"
        and publicly_verified
        and honors_prefix
        and hamming == 0
    )
    return {
        "name": "clause_role_credit_primary_w11",
        "mechanism": "deepest-exact-learned-clause-owner-role-credit",
        "arm": "primary",
        "status": result.status_name,
        "conflict_limit": result.conflict_limit,
        "residual_bits": RESIDUAL_WIDTH,
        "residual_variables": sorted(residual),
        "truth_fixed_bits": 256 - RESIDUAL_WIDTH,
        "privileged_post_reveal_prefix": True,
        "prefix": dict(prefix),
        "model_publicly_verified": publicly_verified,
        "model_matches_truth_fixed_prefix": honors_prefix,
        "model_sha256": None if model is None else hashlib.sha256(model).hexdigest(),
        "model_truth_hamming": hamming,
        "model_truth_exact": exact,
        "stats": {name: int(value) for name, value in result.stats.items()},
        "resources": {name: int(value) for name, value in result.resources.items()},
        "learned_clause": dict(result.learned_clause),
    }


def _validate_o1c55_boundary(
    result: Mapping[str, object],
    *,
    public_view_sha256: str,
    truth_key_sha256: str,
) -> dict[str, object]:
    """Validate the authoritative all-member arm as exact matched work."""

    target = _mapping(result.get("target"), "O1C55 target")
    ledger = _mapping(result.get("call_ledger"), "O1C55 call ledger")
    search = _mapping(result.get("w11_search"), "O1C55 W11 search")
    stats = _mapping(search.get("stats"), "O1C55 W11 stats")
    learned = _mapping(search.get("learned_clause"), "O1C55 learned clause")
    credit = _mapping(
        learned.get("learned_clause_credit"), "O1C55 learned-clause credit"
    )
    selection = _mapping(learned.get("selection"), "O1C55 selection")
    state = _mapping(learned.get("state"), "O1C55 state")
    architecture = _mapping(result.get("architecture"), "O1C55 architecture")
    prefix = _mapping(search.get("prefix"), "O1C55 W11 prefix")
    executed = ledger.get("executed_calls")
    planned = ledger.get("planned_calls")
    if (
        not isinstance(executed, list)
        or len(executed) != 1
        or not isinstance(planned, list)
        or planned != executed
    ):
        raise O1C56ScreenError("frozen O1C55 matched-work boundary differs")
    call = _mapping(executed[0], "O1C55 executed call")
    conflicts = _integer(stats.get("conflicts"), "O1C55 conflicts")
    decisions = _integer(stats.get("decisions"), "O1C55 decisions")
    propagations = _integer(stats.get("propagations"), "O1C55 propagations")
    callbacks = _integer(credit.get("clause_callbacks"), "O1C55 callbacks")
    membership = _integer(
        credit.get("clauses_with_membership"), "O1C55 membership clauses"
    )
    matched = _integer(
        credit.get("matched_owner_members"), "O1C55 matched owner members"
    )
    selected_action_cells = _integer(
        credit.get("penalty_updates"), "O1C55 selected action cells"
    )
    distinct_action_cells = _integer(
        credit.get("distinct_action_cells"), "O1C55 distinct action cells"
    )
    penalty_units = _integer(credit.get("penalty_units"), "O1C55 penalty units")
    reorderings = _integer(
        selection.get("credit_reordered_actions"), "O1C55 action reorderings"
    )
    state_sha256 = state.get("sha256")
    if (
        result.get("schema") != "o1-256-learned-clause-credit-screen-result-v1"
        or result.get("attempt_id") != "O1C-0055"
        or result.get("classification")
        != "LEARNED_CLAUSE_CREDIT_MEMBERSHIP_NO_EXACT_W11_CLOSE"
        or target.get("target_id") != "o1c-0044-fresh-0000"
        or target.get("public_view_sha256") != public_view_sha256
        or target.get("truth_key_sha256") != truth_key_sha256
        or target.get("truth_publicly_verified_by_reveal") is not True
        or ledger.get("native_solver_calls") != 1
        or ledger.get("requested_conflicts") != CONFLICT_LIMIT
        or ledger.get("actual_conflicts") != CONFLICT_LIMIT
        or ledger.get("maximum_native_solver_calls") != 1
        or ledger.get("maximum_requested_conflicts") != CONFLICT_LIMIT
        or ledger.get("full_cap_consumed_or_exact_early_hit") is not True
        or any(
            ledger.get(name) != 0
            for name in (
                "parameter_tuning_calls",
                "cap_tuning_calls",
                "group_tuning_calls",
                "rotation_calls",
                "full256_calls",
            )
        )
        or call.get("ordinal") != 1
        or call.get("stage") != "qualification"
        or call.get("mechanism") != "exact-learned-clause-owner-credit"
        or call.get("arm") != "primary"
        or call.get("search_space") != "post-reveal-w11"
        or call.get("residual_bits") != RESIDUAL_WIDTH
        or call.get("truth_fixed_bits") != 256 - RESIDUAL_WIDTH
        or call.get("conflict_limit") != CONFLICT_LIMIT
        or call.get("seed") != SEED
        or call.get("timeout_seconds") != TIMEOUT_SECONDS
        or search.get("name") != "learned_clause_credit_primary_w11"
        or search.get("status") != "UNKNOWN"
        or search.get("conflict_limit") != CONFLICT_LIMIT
        or search.get("residual_bits") != RESIDUAL_WIDTH
        or search.get("residual_variables") != list(EXPECTED_W11_RESIDUAL_VARIABLES)
        or search.get("truth_fixed_bits") != 256 - RESIDUAL_WIDTH
        or dict(prefix) != EXPECTED_W11_PREFIX
        or search.get("model_truth_exact") is not False
        or conflicts != CONFLICT_LIMIT
        or decisions < 0
        or propagations < 0
        or architecture.get("w11_residual_variables")
        != list(EXPECTED_W11_RESIDUAL_VARIABLES)
        or learned.get("decision_rule") != O1C55_DECISION_RULE
        or state.get("bounded_state_bytes") != CLAUSE_ROLE_CREDIT_STATE_BYTES
        or not _is_sha256(state_sha256)
        or callbacks
        != _integer(credit.get("empty_clauses"), "O1C55 empty clauses")
        + _integer(credit.get("unit_clauses"), "O1C55 unit clauses")
        + _integer(credit.get("large_clauses"), "O1C55 large clauses")
        or callbacks
        != membership
        + _integer(credit.get("unmatched_clauses"), "O1C55 unmatched clauses")
        or membership <= 0
        or matched < selected_action_cells
        or distinct_action_cells != selected_action_cells
        or penalty_units != 32 * selected_action_cells
        or credit.get("callback_open") != 0
        or credit.get("callback_bitmap_nonzero_members") != 0
        or credit.get("same_sign_owner_literal_violations") != 0
        or reorderings < 0
    ):
        raise O1C56ScreenError("frozen O1C55 matched-work boundary differs")
    return {
        "classification": result["classification"],
        "mechanism": "all-distinct-matched-owner-action-cell-credit",
        "status": "UNKNOWN",
        "native_solver_calls": 1,
        "requested_conflicts": CONFLICT_LIMIT,
        "conflicts": CONFLICT_LIMIT,
        "decisions": decisions,
        "propagations": propagations,
        "credit_reordered_actions": reorderings,
        "matched_owner_members": matched,
        "selected_matched_members": matched,
        "selected_credit_updates": selected_action_cells,
        "discarded_matched_members": 0,
        "multi_member_clauses": None,
        "deepest_level_ties": None,
        "role_selection_telemetry_available": False,
        "state_sha256": state_sha256,
    }


def _validate_native_contract(
    row: Mapping[str, object], *, decision_sha256: str
) -> None:
    learned = _mapping(row.get("learned_clause"), "learned clause")
    state = _mapping(learned.get("state"), "learned clause state")
    telemetry = _mapping(
        learned.get("clause_role_credit"), "learned clause telemetry"
    )
    callbacks = _integer(
        telemetry.get("clause_callbacks"), "clause-role clause callbacks"
    )
    membership = _integer(
        telemetry.get("clauses_with_membership"),
        "clause-role membership clauses",
    )
    unmatched = _integer(
        telemetry.get("unmatched_clauses"), "clause-role unmatched clauses"
    )
    selected = _integer(
        telemetry.get("selected_deepest_members"),
        "clause-role selected deepest members",
    )
    penalties = _integer(
        telemetry.get("penalty_updates"), "clause-role penalty updates"
    )
    distinct_cells = _integer(
        telemetry.get("distinct_action_cells"),
        "clause-role distinct action cells",
    )
    matched = _integer(
        telemetry.get("matched_owner_members"),
        "clause-role matched owner members",
    )
    discarded = _integer(
        telemetry.get("discarded_matched_members"),
        "clause-role discarded matched members",
    )
    selected_current = _integer(
        telemetry.get("selected_at_current_level"),
        "clause-role current-level selections",
    )
    selected_below = _integer(
        telemetry.get("selected_below_current_level"),
        "clause-role below-current selections",
    )
    multi = _integer(
        telemetry.get("multi_member_clauses"), "clause-role multi-member clauses"
    )
    ties = _integer(
        telemetry.get("deepest_level_ties"), "clause-role deepest-level ties"
    )
    penalty_units = _integer(
        telemetry.get("penalty_units"), "clause-role penalty units"
    )
    if (
        learned.get("decision_rule") != CLAUSE_ROLE_CREDIT_DECISION_RULE
        or learned.get("update_formula") != CLAUSE_ROLE_CREDIT_UPDATE_FORMULA
        or learned.get("decision_scope") != PAIR_ENVELOPE_DECISION_SCOPE
        or learned.get("decision_variables_sha256") != decision_sha256
        or learned.get("pair_count") != 63
        or learned.get("group_width") != 2
        or learned.get("external_implications") != 0
        or learned.get("hard_clauses_added") != 0
        or state.get("bounded_action_state_bytes")
        != CLAUSE_ROLE_CREDIT_ACTION_STATE_BYTES
        or state.get("bounded_owner_state_bytes")
        != CLAUSE_ROLE_CREDIT_OWNER_STATE_BYTES
        or state.get("bounded_callback_state_bytes")
        != CLAUSE_ROLE_CREDIT_CALLBACK_STATE_BYTES
        or state.get("bounded_state_bytes") != CLAUSE_ROLE_CREDIT_STATE_BYTES
        or telemetry.get("callback_open") != 0
        or telemetry.get("callback_bitmap_nonzero_members") != 0
        or telemetry.get("same_sign_owner_literal_violations") != 0
        or min(
            callbacks,
            membership,
            unmatched,
            selected,
            penalties,
            distinct_cells,
            matched,
            discarded,
            selected_current,
            selected_below,
            multi,
            ties,
            penalty_units,
        )
        < 0
        or callbacks != membership + unmatched
        or selected != membership
        or selected != penalties
        or distinct_cells != selected
        or discarded + selected != matched
        or selected_current + selected_below != selected
        or multi > membership
        or multi > discarded
        or ties > multi
        or penalty_units != 32 * penalties
    ):
        raise O1C56ScreenError("clause-role native contract differs")


def _mechanism_comparison(
    baseline: Mapping[str, object],
    row: Mapping[str, object],
    *,
    classification: str,
) -> dict[str, object]:
    """Expose matched-work all-member versus one-role telemetry."""

    if classification not in {
        EXACT_RECOVERY_CLASSIFICATION,
        MEMBERSHIP_NO_CLOSE_CLASSIFICATION,
        NO_MEMBERSHIP_CLASSIFICATION,
    }:
        raise O1C56ScreenError("O1C56 comparison classification differs")
    stats = _mapping(row.get("stats"), "O1C56 comparison stats")
    learned = _mapping(row.get("learned_clause"), "O1C56 comparison clause")
    telemetry = _mapping(
        learned.get("clause_role_credit"), "O1C56 comparison telemetry"
    )
    selection = _mapping(learned.get("selection"), "O1C56 comparison selection")
    state = _mapping(learned.get("state"), "O1C56 comparison state")
    candidate = {
        "classification": classification,
        "mechanism": "one-deepest-live-owner-per-matched-learned-clause",
        "status": row.get("status"),
        "native_solver_calls": 1,
        "requested_conflicts": CONFLICT_LIMIT,
        "conflicts": _integer(stats.get("conflicts"), "O1C56 conflicts"),
        "decisions": _integer(stats.get("decisions"), "O1C56 decisions"),
        "propagations": _integer(
            stats.get("propagations"), "O1C56 propagations"
        ),
        "credit_reordered_actions": _integer(
            selection.get("credit_reordered_actions"),
            "O1C56 action reorderings",
        ),
        "matched_owner_members": _integer(
            telemetry.get("matched_owner_members"),
            "O1C56 matched owner members",
        ),
        "selected_matched_members": _integer(
            telemetry.get("selected_deepest_members"),
            "O1C56 selected matched members",
        ),
        "selected_credit_updates": _integer(
            telemetry.get("selected_deepest_members"),
            "O1C56 selected deepest members",
        ),
        "discarded_matched_members": _integer(
            telemetry.get("discarded_matched_members"),
            "O1C56 discarded matched members",
        ),
        "multi_member_clauses": _integer(
            telemetry.get("multi_member_clauses"),
            "O1C56 multi-member clauses",
        ),
        "deepest_level_ties": _integer(
            telemetry.get("deepest_level_ties"),
            "O1C56 deepest-level ties",
        ),
        "role_selection_telemetry_available": True,
        "state_sha256": state.get("sha256"),
    }
    if not _is_sha256(candidate["state_sha256"]):
        raise O1C56ScreenError("O1C56 comparison state hash differs")
    numeric_deltas = {
        name: _integer(candidate[name], f"O1C56 {name}")
        - _integer(baseline.get(name), f"O1C55 {name}")
        for name in (
            "decisions",
            "propagations",
            "credit_reordered_actions",
            "matched_owner_members",
            "selected_matched_members",
            "selected_credit_updates",
        )
    }
    return {
        "matched_work": {
            "same_consumed_target": True,
            "same_post_reveal_w11_prefix": True,
            "same_truth_fixed_bits": 245,
            "same_residual_bits": RESIDUAL_WIDTH,
            "same_conflict_cap": CONFLICT_LIMIT,
            "same_seed": SEED,
            "one_native_call_per_arm": True,
        },
        "arms": {
            "O1C-0055_all_member": dict(baseline),
            "O1C-0056_one_role": candidate,
        },
        "delta_O1C56_minus_O1C55": numeric_deltas,
        "state_hash_changed": candidate["state_sha256"]
        != baseline.get("state_sha256"),
    }


def _validate_executed_work(row: Mapping[str, object]) -> int:
    """Require the full cap for a negative, while allowing an earlier exact hit."""

    stats = _mapping(row.get("stats"), "executed search stats")
    conflicts = _integer(stats.get("conflicts"), "executed search conflicts")
    if not 0 <= conflicts <= CONFLICT_LIMIT:
        raise O1C56ScreenError("executed search conflict boundary differs")
    exact = row.get("model_truth_exact") is True
    status = row.get("status")
    if exact:
        if (
            status != "SAT"
            or row.get("model_publicly_verified") is not True
            or row.get("model_matches_truth_fixed_prefix") is not True
        ):
            raise O1C56ScreenError("exact public recovery status differs")
    elif status != "UNKNOWN" or conflicts != CONFLICT_LIMIT:
        raise O1C56ScreenError(
            "negative search did not consume the frozen conflict budget"
        )
    return conflicts


def run(
    config_path: str | Path = DEFAULT_CONFIG,
    output_path: str | Path = RESULT_RELATIVE,
) -> dict[str, object]:
    root = lab_root().resolve(strict=True)
    output = _authoritative_output(root, output_path)
    config_file = Path(config_path)
    if not config_file.is_absolute():
        config_file = root / config_file
    config_file = config_file.resolve(strict=True)
    config_bytes = config_file.read_bytes()
    config = load_config(config_file)
    source = _mapping(config.get("source"), "config.source")
    expected = _mapping(source.get("expected_sha256"), "config.expected")
    paths = {
        name: _relative_path(root, source.get(name), f"source.{name}")
        for name in _SOURCE_NAMES
    }
    source_bytes = {name: path.read_bytes() for name, path in paths.items()}
    for name, payload in source_bytes.items():
        if _sha256(payload) != expected.get(name):
            raise O1C56ScreenError(f"frozen O1C48 source differs: {name}")
    if (
        expected.get("reveal") != EXPECTED_REVEAL_SHA256
        or expected.get("primary_potential") != EXPECTED_PRIMARY_POTENTIAL_SHA256
    ):
        raise O1C56ScreenError("frozen reveal/potential hash differs")

    implementation_paths = {
        "native": (root / NATIVE_SOURCE).resolve(strict=True),
        "adapter": (root / ADAPTER_SOURCE).resolve(strict=True),
        "runner": (root / RUNNER_SOURCE).resolve(strict=True),
    }
    implementation_bytes = {
        name: path.read_bytes() for name, path in implementation_paths.items()
    }
    source_commit = _git_commit(root)
    _commit_bound_bytes(root, source_commit, config_file, config_bytes, "config")
    for name, payload in implementation_bytes.items():
        _commit_bound_bytes(
            root, source_commit, implementation_paths[name], payload, name
        )
    for name in ("native", "adapter"):
        _commit_bound_bytes(
            root,
            CLAUSE_ROLE_CORE_COMMIT,
            implementation_paths[name],
            implementation_bytes[name],
            f"{name} clause-role core",
        )

    publication = _json_object(source_bytes["publication"], "publication")
    public = public_view_from_publication(publication)
    if (
        publication.get("target_id") != "o1c-0044-fresh-0000"
        or public.digest() != EXPECTED_PUBLIC_VIEW_SHA256
    ):
        raise O1C56ScreenError("frozen public target differs")
    reveal = verify_reveal(_json_object(source_bytes["reveal"], "reveal"))
    preimage = _mapping(reveal.get("commitment_preimage"), "reveal.preimage")
    try:
        truth_key = bytes.fromhex(str(preimage.get("key_hex")))
    except ValueError as exc:
        raise O1C56ScreenError("revealed key encoding differs") from exc
    truth_sha256 = hashlib.sha256(truth_key).hexdigest()
    if (
        len(truth_key) != 32
        or truth_sha256 != EXPECTED_TRUTH_KEY_SHA256
        or preimage.get("public_view_sha256") != public.digest()
    ):
        raise O1C56ScreenError("revealed key differs from frozen public target")

    field = ParentCriticalityField.from_bytes(source_bytes["field"])
    potential = CriticalityPotentialField.from_bytes(source_bytes["primary_potential"])
    primary_plan = compile_primary_pair_groups(field, potential)
    if primary_plan.describe() != EXPECTED_PRIMARY_PLAN:
        raise O1C56ScreenError("frozen primary pair plan differs")
    ordered_variables = primary_plan.ordered_variables
    field_key_variables = tuple(
        sorted({factor.key_variable for factor in field.factors})
    )
    if (
        len(ordered_variables) != len(set(ordered_variables))
        or set(ordered_variables) != set(field_key_variables)
        or not set(ordered_variables).issubset(potential.observed_variables)
    ):
        raise O1C56ScreenError("frozen primary pair partition differs")
    plan_validation = {
        "partitions_field_keys_exactly": True,
        "all_pair_variables_observed_by_potential": True,
        "field_key_count": len(field_key_variables),
        "observed_potential_variable_count": len(potential.observed_variables),
    }
    truth_spins = {
        index + 1: (1 if bit else -1) for index, bit in enumerate(key_bits(truth_key))
    }
    key_order = _highest_support_key_order(field)
    residual = set(key_order[:RESIDUAL_WIDTH])
    if tuple(sorted(residual)) != EXPECTED_W11_RESIDUAL_VARIABLES:
        raise O1C56ScreenError("frozen W11 residual coordinates differ")
    fixed = {
        variable: spin
        for variable, spin in truth_spins.items()
        if variable not in residual
    }

    baseline_path = (root / O1C55_RESULT).resolve(strict=True)
    baseline_bytes = baseline_path.read_bytes()
    if _sha256(baseline_bytes) != O1C55_RESULT_SHA256:
        raise O1C56ScreenError("O1C55 baseline hash differs")
    baseline = _json_object(baseline_bytes, "O1C55 baseline")
    baseline_boundary = _validate_o1c55_boundary(
        baseline,
        public_view_sha256=public.digest(),
        truth_key_sha256=truth_sha256,
    )

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    parent_cpu_started = time.process_time()
    children_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    with tempfile.TemporaryDirectory(prefix="o1c56-") as temporary:
        workspace = Path(temporary)
        executable = workspace / "cadical-o1-clause-role-credit"
        native_build = build_native_clause_role_credit_search(
            source=implementation_paths["native"], output=executable
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
        old_instance = _mapping(
            _mapping(baseline.get("architecture"), "O1C55 architecture").get(
                "public_instance"
            ),
            "O1C55 public instance",
        )
        if (
            verification.get("ok") is not True
            or instance.key_unit_clause_count != 0
            or instance.assumption_unit_clause_count != 0
            or instance.assumptions
            or instance.key_fixed_for_self_test
            or instance.describe() != old_instance
        ):
            raise O1C56ScreenError("public Full256 instance differs")
        residual_cnf = workspace / "residual-11.cnf"
        prefix = _write_prefix_cnf(public_cnf, residual_cnf, fixed)
        if prefix != EXPECTED_W11_PREFIX:
            raise O1C56ScreenError("frozen W11 prefix differs")
        decisions_path = workspace / "primary.ordered-pair-variables"
        decision_sha256 = write_clause_role_credit_decision_variables(
            decisions_path, primary_plan.ordered_variables
        )
        search_result = run_clause_role_credit_search(
            executable=executable,
            cnf_path=residual_cnf,
            potential_path=paths["primary_potential"],
            decision_variables_path=decisions_path,
            conflict_limit=CONFLICT_LIMIT,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
        )
        search = _search_row(
            search_result,
            public=public,
            truth_key=truth_key,
            residual=residual,
            fixed=fixed,
            prefix=prefix,
        )
        _validate_native_contract(search, decision_sha256=decision_sha256)
        actual_conflicts = _validate_executed_work(search)

    children_finished = resource.getrusage(resource.RUSAGE_CHILDREN)
    elapsed = time.perf_counter() - started
    parent_cpu = time.process_time() - parent_cpu_started
    child_cpu = (
        children_finished.ru_utime
        + children_finished.ru_stime
        - children_started.ru_utime
        - children_started.ru_stime
    )
    search_resources = _mapping(search["resources"], "search resources")
    peak_rss = max(
        _peak_rss_bytes(),
        _integer(search_resources.get("peak_rss_bytes"), "search peak RSS"),
    )
    if elapsed > MAXIMUM_WALL_SECONDS or peak_rss > MAXIMUM_PEAK_RSS_BYTES:
        raise O1C56ScreenError("one-call resource boundary exceeded")
    learned = _mapping(search["learned_clause"], "learned clause")
    credit = _mapping(learned.get("clause_role_credit"), "credit telemetry")
    penalty_updates = _integer(credit.get("penalty_updates"), "penalty updates")
    exact_recovery = search["model_truth_exact"] is True
    classification = classify_result(
        exact_recovery=exact_recovery, penalty_updates=penalty_updates
    )
    comparison = _mechanism_comparison(
        baseline_boundary,
        search,
        classification=classification,
    )
    ledger = call_ledger()
    ledger["actual_conflicts"] = actual_conflicts
    ledger["full_cap_consumed_or_exact_early_hit"] = True
    result: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at,
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "classification": classification,
        "claim_level": "CONSUMED_POST_REVEAL_EXACT_CLAUSE_ROLE_CREDIT_SCREEN",
        "hypothesis": (
            "one deepest live owner per exact learned clause concentrates causal "
            "negative credit enough to close W11 under the frozen 512-conflict "
            "budget"
        ),
        "boundary": {
            "consumed_target": True,
            "post_reveal_w11_only": True,
            "truth_fixed_key_bits": 245,
            "unknown_key_bits": 11,
            "exactly_one_native_solver_call": True,
            "learned_clause_membership_is_exact": True,
            "credit_only_matches_negative_live_decision_owner_literal": True,
            "exactly_one_deepest_owner_selected_per_membership_clause": True,
            "deepest_tie_break": "group-index-asc-then-member-asc",
            "followup_calls": 0,
            "full256_calls": 0,
            "rotations": 0,
            "sweeps": 0,
            "parameter_tuning": 0,
            "cap_tuning": 0,
            "group_tuning": 0,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "target": {
            "target_id": publication.get("target_id"),
            "public_view_sha256": public.digest(),
            "truth_key_sha256": truth_sha256,
            "truth_publicly_verified_by_reveal": True,
        },
        "architecture": {
            "primary_pair_plan": primary_plan.describe(),
            "pair_plan_validation": plan_validation,
            "ordered_pair_file_sha256": decision_sha256,
            "native_build": native_build.describe(),
            "native_source_sha256": _sha256(implementation_bytes["native"]),
            "adapter_sha256": _sha256(implementation_bytes["adapter"]),
            "runner_sha256": _sha256(implementation_bytes["runner"]),
            "clause_role_core_commit": CLAUSE_ROLE_CORE_COMMIT,
            "public_instance": instance.describe(),
            "residual_key_order": list(key_order),
            "w11_residual_variables": sorted(residual),
            "bounded_state_bytes": CLAUSE_ROLE_CREDIT_STATE_BYTES,
            "action_state_bytes": CLAUSE_ROLE_CREDIT_ACTION_STATE_BYTES,
            "owner_state_bytes": CLAUSE_ROLE_CREDIT_OWNER_STATE_BYTES,
            "callback_state_bytes": CLAUSE_ROLE_CREDIT_CALLBACK_STATE_BYTES,
        },
        "w11_search": search,
        "gate": {
            "passed": exact_recovery,
            "status": search["status"],
            "model_publicly_verified": search["model_publicly_verified"],
            "model_truth_exact": exact_recovery,
            "model_matches_truth_fixed_prefix": search[
                "model_matches_truth_fixed_prefix"
            ],
            "telemetry_cannot_satisfy_exact_recovery_gate": True,
            "no_followup_authorization": True,
        },
        "causal_breadcrumb": {
            "clause_callbacks": credit.get("clause_callbacks"),
            "clauses_with_membership": credit.get("clauses_with_membership"),
            "matched_owner_members": credit.get("matched_owner_members"),
            "distinct_action_cells": credit.get("distinct_action_cells"),
            "penalty_updates": penalty_updates,
            "penalty_units": credit.get("penalty_units"),
            "selected_deepest_members": credit.get("selected_deepest_members"),
            "selected_at_current_level": credit.get("selected_at_current_level"),
            "selected_below_current_level": credit.get(
                "selected_below_current_level"
            ),
            "discarded_matched_members": credit.get("discarded_matched_members"),
            "multi_member_clauses": credit.get("multi_member_clauses"),
            "deepest_level_ties": credit.get("deepest_level_ties"),
            "action_reorderings": _mapping(learned.get("selection"), "selection").get(
                "credit_reordered_actions"
            ),
            "state_sha256": _mapping(learned.get("state"), "state").get("sha256"),
        },
        "mechanism_comparison": comparison,
        "call_ledger": ledger,
        "resources": {
            "elapsed_seconds": elapsed,
            "parent_cpu_seconds": parent_cpu,
            "child_cpu_seconds": child_cpu,
            "peak_rss_bytes": peak_rss,
            "maximum_wall_seconds": MAXIMUM_WALL_SECONDS,
            "maximum_peak_rss_bytes": MAXIMUM_PEAK_RSS_BYTES,
            "native_solver_calls": 1,
            "requested_conflicts": CONFLICT_LIMIT,
            "actual_conflicts": actual_conflicts,
            "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
            "maximum_requested_conflicts": MAXIMUM_REQUESTED_CONFLICTS,
            "fresh_targets": 0,
            "sibling_reads": 0,
            "sibling_writes": 0,
            "MPS_or_GPU": False,
        },
        "baseline": {"O1C-0055": baseline_boundary},
        "baseline_sha256": {"O1C-0055": O1C55_RESULT_SHA256},
        "source_sha256": {
            "config": _sha256(config_bytes),
            **{name: _sha256(payload) for name, payload in source_bytes.items()},
            **{
                name: _sha256(payload) for name, payload in implementation_bytes.items()
            },
            "o1c55_result": O1C55_RESULT_SHA256,
        },
        "next_action": (
            "freeze exact W11 recovery and design a fresh-target Full256 promotion"
            if exact_recovery
            else (
                "retain one-role exact learned-clause credit as a causal stream "
                "breadcrumb; close this frozen screen without tuning"
                if penalty_updates
                else "close exact owner membership at this boundary and move to an "
                "earlier exact proof-event hook"
            )
        ),
    }

    if config_file.read_bytes() != config_bytes:
        raise O1C56ScreenError("config changed during one-call screen")
    for name, before in source_bytes.items():
        if paths[name].read_bytes() != before:
            raise O1C56ScreenError(f"source changed during one-call screen: {name}")
    for name, before in implementation_bytes.items():
        if implementation_paths[name].read_bytes() != before:
            raise O1C56ScreenError(
                f"implementation changed during one-call screen: {name}"
            )
    if baseline_path.read_bytes() != baseline_bytes:
        raise O1C56ScreenError("O1C55 baseline changed during one-call screen")
    if output.exists():
        raise O1C56ScreenError("authoritative result appeared during one-call screen")
    if ledger["native_solver_calls"] != 1 or ledger["full256_calls"] != 0:
        raise O1C56ScreenError("final call ledger differs")
    _atomic_json(output, result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--output", default=str(RESULT_RELATIVE))
    arguments = parser.parse_args(argv)
    result = run(arguments.config, arguments.output)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ATTEMPT_ID",
    "O1C56ScreenError",
    "RESULT_SCHEMA",
    "call_ledger",
    "classify_result",
    "run",
]
