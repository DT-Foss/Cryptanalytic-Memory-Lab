"""Straight, burn-on-intent O1C-0079 decision-ownership runner.

The runner consumes exactly the prepared Page-6/local-0/lineage-19 input.  It
has no loop, retry, sweep, reveal, truth, refit, MPS, or GPU surface.  Its three
conclusions are deliberately independent:

* ``operational_ownership_success`` describes the central token owner;
* ``qualified_prefix_activation`` describes the frozen 11-row prefix gate;
* ``science_gain`` describes only attacker-valid cryptanalytic evidence.

Filesystem publication, canonical compression, executable inspection, and
resource accounting are science-neutral mechanics imported from O1C-0078.
The O1C-0078 execution state machine is not reused.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence, cast

from . import joint_score_sieve_v20 as _native_v20
from . import o1c73_apple8_vault_release_contrast_run as _o1c73
from .causal_attic_v1 import (
    canonical_json_bytes,
    parse_vault_telemetry,
    sha256_bytes,
)
from .causal_residency_v1 import CausalResidencyError, validate_activation_replay
from .joint_score_sieve_v9 import validate_vault_soft_conflict_ledger
from .o1c78_apple8_rescue_prefix_preemption_run import (
    O1C78RunError as _O1C78TechnicalError,
    _artifact_row as _o1c78_artifact_row,
    _atomic_create as _o1c78_atomic_create,
    _atomic_json as _o1c78_atomic_json,
    _manifest_payload as _o1c78_manifest_payload,
    _native_failure as _o1c78_native_failure,
    _read_compressed_json as _o1c78_read_compressed_json,
    _runtime_resources as _o1c78_runtime_resources,
    _sha256_file as _o1c78_sha256_file,
    _validate_artifact_row as _o1c78_validate_artifact_row,
    _validate_regular_capsule_tree as _o1c78_validate_regular_capsule_tree,
    _write_compressed_json as _o1c78_write_compressed_json,
    validate_native_executable as _o1c78_validate_native_executable,
)
from .o1c79_apple8_decision_ownership_prepare import (
    ACTIVATION_LEDGER_NAME,
    ACTIVE_PROJECTION_NAME,
    CHUNK_NAMES,
    EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256,
    EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256,
    EXPECTED_PREPARED_MANIFEST_SHA256,
    EXPECTED_SCIENCE_INPUT_SHA256,
    EXPECTED_STAGING_PLAN_DOCUMENT_SHA256,
    FRONTIER_PLAN_BINARY_NAME,
    FRONTIER_PLAN_BINARY_BYTES,
    FRONTIER_PLAN_BINARY_SHA256,
    FRONTIER_PLAN_NAME,
    MANIFEST_NAME as PREPARED_MANIFEST_NAME,
    OCCURRENCES_NAME,
    PAGE5_SHA256,
    PAGE6_CLAUSE_COUNT,
    PAGE6_LITERAL_COUNT,
    PAGE6_SERIALIZED_BYTES,
    PAGE6_SHA256,
    PREFIX_PLAN_BINARY_BYTES,
    PREFIX_PLAN_BINARY_NAME,
    PREFIX_PLAN_BINARY_SHA256,
    PREFIX_PLAN_NAME,
    PreparedDecisionOwnership,
    RELATIONS_NAME,
    RESIDENCY_NAME,
    SCIENCE_INPUT_SHA256_HISTORY,
    SCIENCE_HISTORY_NAME,
    SCIENCE_INPUT_NAME,
    STAGING_PLAN_BINARY_BYTES,
    STAGING_PLAN_BINARY_NAME,
    STAGING_PLAN_BINARY_SHA256,
    STAGING_PLAN_NAME,
    TERMINAL_RECEIPT_NAME,
    load_prepared_decision_ownership,
)
from .rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
)
from .threshold_no_good_vault_v1 import O1C66_VAULT_CAPS, ThresholdNoGoodVault


ATTEMPT_ID = "O1C-0079"
CONFIG_SCHEMA = "o1-256-apple8-decision-ownership-config-v1"
PREFLIGHT_SCHEMA = "o1-256-apple8-decision-ownership-preflight-v1"
TARGET_FREE_GATE_SCHEMA = "o1-256-o1c79-target-free-decision-ownership-preflight-v1"
TARGET_FREE_GATE_CLASSIFICATION = "O1C79_TARGET_FREE_DECISION_OWNERSHIP_PREFLIGHT_PASS"
INVOCATION_SCHEMA = "o1-256-apple8-decision-ownership-invocation-v1"
INTENT_SCHEMA = "o1-256-apple8-decision-ownership-intent-v1"
EPISODE_SCHEMA = "o1-256-apple8-decision-ownership-episode-v1"
RESULT_SCHEMA = "o1-256-apple8-decision-ownership-result-v1"
RECOVERY_SOURCE_SCHEMA = "o1-256-apple8-decision-ownership-pre-finalization-source-v1"
PUBLICATION_RECOVERY_SCHEMA = "o1-256-apple8-decision-ownership-publication-recovery-v1"
RECOVERED_PUBLICATION_SOURCE_SCHEMA = (
    "o1-256-apple8-decision-ownership-recovered-finalization-source-v1"
)
NATIVE_SOURCE_CLOSURE_SCHEMA = "o1-256-native-source-include-closure-v1"

CONFIG_RELATIVE = Path("configs/o1c79_apple8_decision_ownership_v1.json")
TARGET_FREE_PREFLIGHT_RELATIVE = Path(
    "research/O1C0079_TARGET_FREE_DECISION_OWNERSHIP_PREFLIGHT_20260720.json"
)
RESULT_RELATIVE = Path(
    "research/O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json"
)
CAPSULE_SUFFIX = "O1C-0079_apple8-decision-ownership-v1"
RECOVERY_SOURCE_NAME = "pre-finalization-recovery-source.json"
PUBLICATION_RECOVERY_NAME = "publication-recovery.json"

PREPARATION_DIRECTORY_RELATIVE = Path("research/o1c79_decision_ownership_seed_20260720")
PARENT_RESULT_RELATIVE = Path(
    "research/O1C0078_APPLE8_RESCUE_PREFIX_PREEMPTION_RESULT_20260720.json"
)
PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_065505_O1C-0078_apple8-rescue-prefix-preemption-v1"
)
PARENT_RESULT_SHA256 = (
    "f72821443ed7e7dd80698a39288ff31f9c8f52a120bb745e713e3b23b1822fed"
)
PARENT_MANIFEST_SHA256 = (
    "5d358863162a64f27d215fc4b91258c73194d2458f89d9dd7495bb1e05e50a69"
)
PARENT_SOURCE_COMMIT = "2840824b2aa482f30dfbd39060c200994fc09957"
PARENT_LAST_LINEAGE_ORDINAL = 18
PARENT_CLASSIFICATION = "RESCUE_PREFIX_PREEMPTION_OPERATIONAL_TERMINAL"

RANK_SOURCE_SHA256 = "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
OLD_FRONTIER_PLAN_SHA256 = (
    "8a263e555b4b5a69d3c9a937cac3e7702a1f8e3de27db4feffc2d21563a24da1"
)
OLD_STAGING_PLAN_SHA256 = (
    "ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023"
)

ACTIVE_CLAUSE_LIMIT = 256
LOCAL_EPISODES = (0,)
LINEAGE_ORDINALS = (19,)
REQUESTED_CONFLICTS_PER_EPISODE = 128
MAXIMUM_NATIVE_SOLVER_CALLS = 1
MAXIMUM_TOTAL_REQUESTED_CONFLICTS = 128
SEED = 0
THRESHOLD = 14.606178797892962
TIMEOUT_SECONDS = 45.0
MEMORY_LIMIT_BYTES = 536_870_912
MAXIMUM_PERSISTENT_ARTIFACT_BYTES = 134_217_728
MINIMUM_DISK_FREE_BYTES = 1_073_741_824

PUBLIC_EXACT_RECOVERY = "PUBLIC_EXACT_RECOVERY"
THRESHOLD_REGION_EXHAUSTED = "THRESHOLD_REGION_EXHAUSTED"
SAFE_PRUNE_GAIN = "DECISION_OWNERSHIP_SAFE_PRUNE_GAIN"
NOVEL_CLAUSE_GAIN = "DECISION_OWNERSHIP_NOVEL_CLAUSE_GAIN"
MECHANISM_ONLY = "DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY"
OWNERSHIP_ONLY = "DECISION_OWNERSHIP_OPERATIONAL_ONLY"
NO_ACTIVATION = "DECISION_OWNERSHIP_NO_ACTIVATION_NO_GAIN"
OPERATIONAL_TERMINAL = "DECISION_OWNERSHIP_OPERATIONAL_TERMINAL"

SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c79_apple8_decision_ownership_run.py",
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency_v1": "src/o1_crypto_lab/causal_residency_v1.py",
    "preparation": ("src/o1_crypto_lab/o1c79_apple8_decision_ownership_prepare.py"),
    "threshold_no_good_vault_v1": ("src/o1_crypto_lab/threshold_no_good_vault_v1.py"),
    "causal_frontier_v1": "src/o1_crypto_lab/causal_frontier_v1.py",
    "residual_polarity_staging_v1": (
        "src/o1_crypto_lab/residual_polarity_staging_v1.py"
    ),
    "rescue_prefix_preemption_v1": ("src/o1_crypto_lab/rescue_prefix_preemption_v1.py"),
    "decision_ownership_v1": "src/o1_crypto_lab/decision_ownership_v1.py",
    "decision_ownership_fixture_tests": ("tests/test_o1c79_decision_ownership_v1.py"),
    "adapter_v20_fixture_tests": "tests/test_joint_score_sieve_v20.py",
    "preparation_fixture_tests": (
        "tests/test_o1c79_apple8_decision_ownership_prepare.py"
    ),
    "runner_fixture_tests": ("tests/test_o1c79_apple8_decision_ownership_run.py"),
    "adapter_v20": "src/o1_crypto_lab/joint_score_sieve_v20.py",
    "native_v17": "native/cadical_o1_joint_score_sieve_v17.cpp",
    "decision_ownership_header": "native/o1c79_decision_ownership.hpp",
    "native_v16": "native/cadical_o1_joint_score_sieve_v16.cpp",
    "native_v15": "native/cadical_o1_joint_score_sieve_v15.cpp",
    "native_v14": "native/cadical_o1_joint_score_sieve_v14.cpp",
    "native_v12": "native/cadical_o1_joint_score_sieve_v12.cpp",
    "native_v11": "native/cadical_o1_joint_score_sieve_v11.cpp",
    "native_v6": "native/cadical_o1_joint_score_sieve_v6.cpp",
    "native_base": "native/cadical_o1_joint_score_sieve.cpp",
}

NATIVE_INCLUDE_CLOSURE = (
    "native_v17",
    "decision_ownership_header",
    "native_v16",
    "native_v15",
    "native_v14",
    "native_v12",
    "native_v11",
    "native_v6",
    "native_base",
)
SOURCE_FREEZE_GUARD_PATHS = ("src/o1_crypto_lab", "native")

_BANNED_NATIVE_TEXT = (
    b"returned-ever",
    b"returned_ever",
    b"backtrack-release guided assignment sign differs",
)


class O1C79RunError(RuntimeError):
    """A frozen input, call ledger, conclusion, or publication differs."""


class EpisodeInvoker(Protocol):
    def __call__(
        self,
        local_ordinal: int,
        lineage_ordinal: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
        prefix_plan: Path,
        /,
    ) -> object:
        """Consume the sole predeclared native subprocess call."""


@dataclass(frozen=True)
class DecisionOwnershipOutcome:
    classification: str
    stop_reason: str
    episodes: tuple[Mapping[str, object], ...]
    native_calls: int
    requested_conflicts: int
    actual_conflicts: int | None
    billed_conflicts: int | None
    operational_ownership_success: bool
    qualified_prefix_activation: bool
    science_gain: bool
    globally_novel_clauses: int
    safe_threshold_prunes: int
    operational_failure: Mapping[str, object] | None


# Narrow compatibility names for callers familiar with the predecessor runner.
EpisodeOutcome = DecisionOwnershipOutcome
StreamOutcome = DecisionOwnershipOutcome


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C79RunError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C79RunError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C79RunError(f"{field} differs")
    return value


def _sha256(value: object, field: str, *, pending: bool = False) -> str:
    if pending and value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C79RunError(f"{field} differs")
    return value


def _relative_contract(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise O1C79RunError(f"{field} differs")
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise O1C79RunError(f"{field} escapes the lab")
    return path.as_posix()


def _relative(root: Path, value: object, field: str) -> Path:
    path = Path(_relative_contract(value, field))
    try:
        resolved = (root / path).resolve(strict=True)
    except OSError as exc:
        raise O1C79RunError(f"{field} cannot be resolved") from exc
    if not resolved.is_relative_to(root):
        raise O1C79RunError(f"{field} escapes the lab")
    return resolved


def _regular(path: Path, field: str) -> Path:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise O1C79RunError(f"{field} cannot be read") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise O1C79RunError(f"{field} is not a regular file")
    return path


def _translate_technical(function: Callable[[], object]) -> object:
    try:
        return function()
    except _O1C78TechnicalError as exc:
        raise O1C79RunError(str(exc)) from exc


def _atomic_create(path: Path, payload: bytes, *, immutable: bool = False) -> None:
    _translate_technical(
        lambda: _o1c78_atomic_create(path, payload, immutable=immutable)
    )


def _atomic_json(path: Path, value: object, *, immutable: bool = False) -> None:
    _translate_technical(lambda: _o1c78_atomic_json(path, value, immutable=immutable))


def _sha256_file(path: Path) -> str:
    return cast(str, _translate_technical(lambda: _o1c78_sha256_file(path)))


def _artifact_row(path: Path, *, relative_to: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        _translate_technical(
            lambda: _o1c78_artifact_row(path, relative_to=relative_to)
        ),
    )


def _validate_artifact_row(root: Path, value: object, field: str) -> Path:
    return cast(
        Path,
        _translate_technical(lambda: _o1c78_validate_artifact_row(root, value, field)),
    )


def _write_evidence(path: Path, value: object) -> dict[str, object]:
    return cast(
        dict[str, object],
        _translate_technical(lambda: _o1c78_write_compressed_json(path, value)),
    )


def _read_evidence(base: Path, row: object, field: str) -> Mapping[str, object]:
    return cast(
        Mapping[str, object],
        _translate_technical(lambda: _o1c78_read_compressed_json(base, row, field)),
    )


def _validate_capsule_tree(capsule: Path) -> None:
    _translate_technical(lambda: _o1c78_validate_regular_capsule_tree(capsule))


def validate_native_executable(
    path: str | Path, *, expected_sha256: str
) -> dict[str, object]:
    return cast(
        dict[str, object],
        _translate_technical(
            lambda: _o1c78_validate_native_executable(
                path, expected_sha256=expected_sha256
            )
        ),
    )


def _copy_immutable(path: Path, payload: bytes) -> dict[str, object]:
    _atomic_create(path, payload, immutable=True)
    return _artifact_row(path, relative_to=path.parent)


def _prepared_rank_source(
    prepared: PreparedDecisionOwnership,
) -> ThresholdNoGoodVault:
    try:
        rank = prepared.state.attic.chunks[0]
    except (AttributeError, IndexError) as exc:
        raise O1C79RunError("prepared rank source differs") from exc
    if not isinstance(rank, ThresholdNoGoodVault):
        raise O1C79RunError("prepared rank source differs")
    return rank


def _reject_consumed_identity(value: str, field: str) -> None:
    if value in {PAGE5_SHA256, OLD_FRONTIER_PLAN_SHA256, OLD_STAGING_PLAN_SHA256}:
        raise O1C79RunError(f"{field} reuses consumed O1C-0078 bytes")


def _validate_science_input_history(value: Mapping[str, object]) -> None:
    """Prove Page 6 is next but absent from the eight consumed inputs."""

    entries = tuple(
        _sha256(item, "science-input history entry")
        for item in _sequence(
            value.get("science_input_sha256"), "science-input history"
        )
    )
    if (
        entries != SCIENCE_INPUT_SHA256_HISTORY
        or len(entries) != 8
        or len(set(entries)) != len(entries)
        or entries[-1] != PAGE5_SHA256
        or PAGE6_SHA256 in entries
        or value.get("science_input_count") != len(entries)
        or value.get("o1c78_consumed_sha256") != PAGE5_SHA256
        or value.get("o1c78_consumed_lineage_ordinal") != 18
        or value.get("next_active_sha256") != PAGE6_SHA256
        or value.get("next_lineage_ordinal") != 19
        or value.get("next_active_absent_from_history") is not True
        or value.get("all_history_entries_unique") is not True
        or value.get("page5_replay_authorized") is not False
        or value.get("retry_authorized") is not False
    ):
        raise O1C79RunError("prepared science-input history differs")


def _validate_prepared_contract(
    prepared: PreparedDecisionOwnership, *, require_frozen: bool = True
) -> None:
    if not isinstance(prepared, PreparedDecisionOwnership):
        raise O1C79RunError("prepared decision-ownership input differs")
    state = prepared.state
    active = state.active_projection
    rank = _prepared_rank_source(prepared)
    for value, field in (
        (active.sha256, "active Page"),
        (prepared.frontier_plan.sha256, "frontier plan"),
        (prepared.staging_plan.sha256, "staging plan"),
    ):
        _reject_consumed_identity(value, field)
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C79RunError("prepared residency replay differs") from exc
    projection = state.current_projection
    if (
        active.clause_count > ACTIVE_CLAUSE_LIMIT
        or rank.identity != active.identity
        or projection.lineage_ordinal != LINEAGE_ORDINALS[0]
        or tuple(prepared.prefix_plan.prefix_literals) != O1C78_PREFIX_LITERALS
        or prepared.prefix_plan.serialized_bytes != PREFIX_PLAN_BINARY_BYTES
        or prepared.prefix_plan.sha256 != PREFIX_PLAN_BINARY_SHA256
        or sha256_bytes(prepared.prefix_plan_binary) != PREFIX_PLAN_BINARY_SHA256
    ):
        raise O1C79RunError("prepared Page-6 plan composition differs")
    if not require_frozen:
        return
    document_digests = (
        sha256_bytes(canonical_json_bytes(prepared.frontier_plan_document)),
        sha256_bytes(canonical_json_bytes(prepared.staging_plan_document)),
        sha256_bytes(canonical_json_bytes(prepared.prefix_plan_document)),
    )
    _validate_science_input_history(prepared.science_input_history)
    if (
        prepared.manifest_sha256 != EXPECTED_PREPARED_MANIFEST_SHA256
        or sha256_bytes(prepared.manifest_bytes) != EXPECTED_PREPARED_MANIFEST_SHA256
        or active.sha256 != PAGE6_SHA256
        or active.clause_count != PAGE6_CLAUSE_COUNT
        or active.literal_count != PAGE6_LITERAL_COUNT
        or active.serialized_bytes != PAGE6_SERIALIZED_BYTES
        or rank.sha256 != RANK_SOURCE_SHA256
        or prepared.frontier_plan.sha256 != FRONTIER_PLAN_BINARY_SHA256
        or len(prepared.frontier_plan_binary) != FRONTIER_PLAN_BINARY_BYTES
        or sha256_bytes(prepared.frontier_plan_binary) != FRONTIER_PLAN_BINARY_SHA256
        or prepared.staging_plan.sha256 != STAGING_PLAN_BINARY_SHA256
        or len(prepared.staging_plan_binary) != STAGING_PLAN_BINARY_BYTES
        or sha256_bytes(prepared.staging_plan_binary) != STAGING_PLAN_BINARY_SHA256
        or document_digests
        != (
            EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256,
            EXPECTED_STAGING_PLAN_DOCUMENT_SHA256,
            EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256,
        )
        or sha256_bytes(canonical_json_bytes(prepared.science_input))
        != EXPECTED_SCIENCE_INPUT_SHA256
    ):
        raise O1C79RunError("frozen prepared Page-6 identities differ")


def _ownership_activation(
    *,
    ownership: Mapping[str, object],
    central: Mapping[str, object],
    raw: Mapping[str, object],
) -> dict[str, object]:
    proposals = _nonnegative_int(ownership.get("proposals"), "ownership proposals")
    bound = _nonnegative_int(
        ownership.get("level_bound_interventions"), "ownership level-bound count"
    )
    releases = _nonnegative_int(ownership.get("releases"), "ownership releases")
    live = _nonnegative_int(ownership.get("live_tokens"), "ownership live tokens")
    omitted = _nonnegative_int(
        ownership.get("omitted_event_count"), "ownership omitted events"
    )
    events = _sequence(ownership.get("events"), "ownership events")
    proposal_tokens: list[int] = []
    bound_tokens: set[int] = set()
    terminal_tokens: set[int] = set()
    for raw_event in events:
        event = _mapping(raw_event, "ownership event")
        kind = event.get("kind")
        token = _nonnegative_int(event.get("token"), "ownership event token")
        if kind == "PROPOSED":
            proposal_tokens.append(token)
        elif kind == "LEVEL_BOUND":
            bound_tokens.add(token)
        elif kind in {"RELEASED", "LEVEL_BOUND_UNOBSERVED_RELEASE"}:
            terminal_tokens.add(token)
    serialized_raw = canonical_json_bytes(raw)
    old_runtime_absent = not any(text in serialized_raw for text in _BANNED_NATIVE_TEXT)
    complete_proposal_binding = (
        proposal_tokens == list(range(1, proposals + 1))
        and len(bound_tokens) == bound
        and proposals == bound
    )
    complete_owner_accounting = releases + live == bound
    central_unique_origin = (
        central.get("nonzero_returns") == proposals
        and len(_sequence(central.get("return_events"), "central return events"))
        == proposals
    )
    success = (
        bound > 0
        and omitted == 0
        and complete_proposal_binding
        and complete_owner_accounting
        and central_unique_origin
        and old_runtime_absent
    )
    return {
        "operational_ownership_success": success,
        "proposal_count": proposals,
        "level_bound_intervention_count": bound,
        "release_count": releases,
        "live_token_count": live,
        "all_proposals_immediately_level_bound": complete_proposal_binding,
        "every_level_bound_owner_accounted": complete_owner_accounting,
        "every_nonzero_return_has_unique_origin_instance": central_unique_origin,
        "telemetry_complete_without_omission": omitted == 0,
        "old_returned_ever_runtime_absent": old_runtime_absent,
        "foreign_and_opposite_assignments_cannot_release_stale_tokens": True,
        "proposal_count_alone_is_activation": False,
    }


def _qualified_prefix_activation(
    *,
    ownership: Mapping[str, object],
    central: Mapping[str, object],
    trace_sha256: str,
    operational_success: bool,
) -> dict[str, object]:
    prefix = _mapping(central.get("prefix"), "central prefix")
    origins = _mapping(ownership.get("origin_counts"), "ownership origin counts")
    prefix_origin = _mapping(origins.get("PREFIX"), "ownership prefix origin")
    rows = _nonnegative_int(prefix.get("rows"), "prefix rows")
    cursor = _nonnegative_int(prefix.get("cursor"), "prefix cursor")
    rescue_skips = _nonnegative_int(
        prefix.get("skipped_preassigned_rescue"), "prefix rescue skips"
    )
    bound = _nonnegative_int(prefix_origin.get("level_bound"), "bound prefix")
    releases = _nonnegative_int(prefix_origin.get("releases"), "released prefix")
    events = [
        _mapping(event, "central return event")
        for event in _sequence(central.get("return_events"), "central return events")
    ]
    first_non_prefix = next(
        (
            index
            for index, event in enumerate(events)
            if event.get("origin") != "PREFIX"
        ),
        len(events),
    )
    prefix_before_non_prefix = all(
        event.get("origin") == "PREFIX" for event in events[:first_non_prefix]
    ) and not any(
        event.get("origin") == "PREFIX" for event in events[first_non_prefix:]
    )
    trace_changed = trace_sha256 != O1C78_BASELINE_TRACE_SHA256
    qualified = (
        operational_success
        and rows == len(O1C78_PREFIX_LITERALS)
        and cursor == rows
        and rescue_skips == 0
        and bound > 0
        and releases == bound
        and prefix_before_non_prefix
        and trace_changed
    )
    return {
        "qualified_prefix_activation": qualified,
        "rows": rows,
        "rows_consumed": cursor,
        "all_rows_consumed_before_first_non_prefix_decision": (
            cursor == rows and prefix_before_non_prefix
        ),
        "skipped_preassigned_rescue": rescue_skips,
        "bound_prefix_tokens": bound,
        "released_prefix_tokens": releases,
        "every_bound_prefix_token_retired": bound > 0 and releases == bound,
        "frozen_o1c77_trace_sha256": O1C78_BASELINE_TRACE_SHA256,
        "native_trace_sha256": trace_sha256,
        "trace_distinct_from_o1c77": trace_changed,
        "proposal_count_alone_is_activation": False,
        "assignment_confirmation_required": False,
    }


def _science_gain_evidence(
    *,
    status: int,
    public_model_verified: bool,
    safe_threshold_prunes: int,
    globally_novel_clauses: int,
) -> dict[str, object]:
    formal_exhaustion = status == 20
    gain = (
        public_model_verified
        or formal_exhaustion
        or safe_threshold_prunes > 0
        or globally_novel_clauses > 0
    )
    return {
        "science_gain": gain,
        "public_complete_model_verified": public_model_verified,
        "formal_threshold_region_exhaustion": formal_exhaustion,
        "safe_local_threshold_prunes": safe_threshold_prunes,
        "globally_novel_exact_threshold_no_goods": globally_novel_clauses,
        "certified_frontier_contraction": False,
        "other_predeclared_sub256_improvement": False,
        "trace_change_is_science_gain": False,
        "ownership_accounting_is_science_gain": False,
        "decision_count_change_is_science_gain": False,
        "minimum_ub_above_threshold_is_science_gain": False,
    }


def _validated_episode_result(
    result: object,
    *,
    prepared: PreparedDecisionOwnership,
    active: ThresholdNoGoodVault,
    stream_id: str,
    verify_public_model: Callable[[bytes], bool],
    require_concrete_result: bool,
) -> dict[str, object]:
    """Independently bind one adapter-v20 return to frozen Page 6."""

    try:
        if require_concrete_result and not isinstance(
            result, _native_v20.JointScoreSieveV20Result
        ):
            raise O1C79RunError("native v20 result type differs")
        raw = _mapping(getattr(result, "raw"), "native raw result")
        central = _mapping(getattr(result, "central_reader"), "central reader")
        ownership = _mapping(
            getattr(result, "decision_ownership"), "decision ownership"
        )
        telemetry = _mapping(
            getattr(result, "vault_telemetry"), "native vault telemetry"
        )
        stats = validate_vault_soft_conflict_ledger(
            _mapping(getattr(result, "stats"), "native conflict ledger")
        )
        resources = _mapping(getattr(result, "resources"), "native resources")
        sieve = _mapping(getattr(result, "sieve"), "native sieve")
        status = getattr(result, "status")
        key_model = getattr(result, "key_model")
        rank = _prepared_rank_source(prepared)
        if (
            isinstance(status, bool)
            or status not in (0, 10, 20)
            or getattr(result, "conflict_limit") != REQUESTED_CONFLICTS_PER_EPISODE
            or getattr(result, "threshold") != THRESHOLD
            or stats["requested_conflicts"] != REQUESTED_CONFLICTS_PER_EPISODE
            or stats["billed_conflicts"] != stats["solve_conflicts"]
            or getattr(result, "rank_source_vault") != rank
            or getattr(result, "input_vault") != active
            or getattr(result, "frontier_plan") != prepared.frontier_plan
            or getattr(result, "staging_plan") != prepared.staging_plan
            or getattr(result, "prefix_preemption_plan") != prepared.prefix_plan
            or raw.get("central_reader") != central
            or raw.get("decision_ownership") != ownership
            or raw.get("vault") != telemetry
        ):
            raise O1C79RunError("native v20 Page-6 binding differs")
        _native_v20.validate_native_lifecycle(raw)
        peak = _nonnegative_int(resources.get("peak_rss_bytes"), "native peak RSS")
        wall = _nonnegative_int(resources.get("wall_microseconds"), "native wall")
        cpu = _nonnegative_int(resources.get("cpu_microseconds"), "native CPU")
        if peak > MEMORY_LIMIT_BYTES or wall > int(TIMEOUT_SECONDS * 1_000_000):
            raise O1C79RunError("native resource boundary differs")
        trace_sha256 = _sha256(sieve.get("trace_sha256"), "native trace digest")
        safe_prunes = _nonnegative_int(
            sieve.get("threshold_prunes"), "native safe threshold prunes"
        )
        if _nonnegative_int(
            sieve.get("pending_clause_count"), "native pending clause count"
        ):
            raise O1C79RunError("native result retained an incomplete clause")
        telemetry_payload = canonical_json_bytes(telemetry)
        parsed = parse_vault_telemetry(
            telemetry_payload,
            stream_id=stream_id,
            expected_sha256=sha256_bytes(telemetry_payload),
        )
        if (
            parsed.input_identity != active.identity
            or parsed.input_vault_sha256 != active.sha256
            or parsed.input_clause_count != active.clause_count
            or parsed.input_literal_count != active.literal_count
            or parsed.input_serialized_bytes != active.serialized_bytes
            or parsed.input_clause_aggregate_sha256 != active.clause_aggregate_sha256
        ):
            raise O1C79RunError("native emission ledger input differs")
        globally_known = {
            clause.serialized for clause in prepared.state.attic.union_vault.clauses
        }
        globally_novel: list[str] = []
        for occurrence in parsed.occurrences:
            serialized = occurrence.clause.serialized
            if serialized not in globally_known:
                if occurrence.classification != "new":
                    raise O1C79RunError(
                        "globally novel no-good lacks native new classification"
                    )
                globally_known.add(serialized)
                globally_novel.append(occurrence.clause_sha256)
        if status == 10:
            if not isinstance(key_model, bytes) or not verify_public_model(key_model):
                raise O1C79RunError(
                    "public candidate failed exact eight-block verification"
                )
            public_verified = True
        else:
            if key_model is not None:
                raise O1C79RunError("non-SAT result returned a candidate")
            public_verified = False
        operational = _ownership_activation(
            ownership=ownership, central=central, raw=raw
        )
        prefix = _qualified_prefix_activation(
            ownership=ownership,
            central=central,
            trace_sha256=trace_sha256,
            operational_success=cast(
                bool, operational["operational_ownership_success"]
            ),
        )
        science = _science_gain_evidence(
            status=cast(int, status),
            public_model_verified=public_verified,
            safe_threshold_prunes=safe_prunes,
            globally_novel_clauses=len(globally_novel),
        )
        return {
            "raw": dict(raw),
            "central_reader": dict(central),
            "decision_ownership": dict(ownership),
            "telemetry": dict(telemetry),
            "occurrences": parsed.occurrences,
            "stats": stats,
            "resources": {
                "peak_rss_bytes": peak,
                "wall_microseconds": wall,
                "cpu_microseconds": cpu,
            },
            "status": status,
            "key_model": key_model,
            "trace_sha256": trace_sha256,
            "safe_threshold_prunes": safe_prunes,
            "globally_novel_clause_sha256": globally_novel,
            "operational_ownership": operational,
            "prefix_activation": prefix,
            "science": science,
        }
    except O1C79RunError:
        raise
    except Exception as exc:
        raise O1C79RunError("native O1C-0079 result differs") from exc


def _initial_artifacts(
    capsule: Path, prepared: PreparedDecisionOwnership
) -> dict[str, object]:
    initial = capsule / "initial"
    if initial.exists() or initial.is_symlink():
        raise O1C79RunError("initial decision-ownership directory already exists")
    initial.mkdir(parents=True)
    state = prepared.state
    chunk_rows: list[dict[str, object]] = []
    for index, chunk in enumerate(state.attic.chunks):
        name = f"chunk-{index:02d}.vault"
        row = _copy_immutable(initial / name, chunk.serialized)
        chunk_rows.append({"chunk_index": index, **row})
    rows: dict[str, object] = {
        "chunks": chunk_rows,
        "active_projection": _copy_immutable(
            initial / ACTIVE_PROJECTION_NAME, state.active_projection.serialized
        ),
        "occurrences": _copy_immutable(
            initial / OCCURRENCES_NAME,
            canonical_json_bytes(state.attic.occurrence_document()),
        ),
        "relations": _copy_immutable(
            initial / RELATIONS_NAME,
            canonical_json_bytes(state.attic.relation_document()),
        ),
        "activation_ledger": _copy_immutable(
            initial / ACTIVATION_LEDGER_NAME,
            canonical_json_bytes(state.activation_ledger_document()),
        ),
        "residency": _copy_immutable(
            initial / RESIDENCY_NAME, canonical_json_bytes(state.describe())
        ),
        "prepared_manifest": _copy_immutable(
            initial / PREPARED_MANIFEST_NAME, prepared.manifest_bytes
        ),
        "terminal_receipt": _copy_immutable(
            initial / TERMINAL_RECEIPT_NAME,
            canonical_json_bytes(prepared.terminal_receipt),
        ),
        "science_input_history": _copy_immutable(
            initial / SCIENCE_HISTORY_NAME,
            canonical_json_bytes(prepared.science_input_history),
        ),
        "science_input": _copy_immutable(
            initial / SCIENCE_INPUT_NAME,
            canonical_json_bytes(prepared.science_input),
        ),
        "frontier_plan": _copy_immutable(
            initial / FRONTIER_PLAN_BINARY_NAME, prepared.frontier_plan_binary
        ),
        "frontier_plan_document": _copy_immutable(
            initial / FRONTIER_PLAN_NAME,
            canonical_json_bytes(prepared.frontier_plan_document),
        ),
        "staging_plan": _copy_immutable(
            initial / STAGING_PLAN_BINARY_NAME, prepared.staging_plan_binary
        ),
        "staging_plan_document": _copy_immutable(
            initial / STAGING_PLAN_NAME,
            canonical_json_bytes(prepared.staging_plan_document),
        ),
        "prefix_plan": _copy_immutable(
            initial / PREFIX_PLAN_BINARY_NAME, prepared.prefix_plan_binary
        ),
        "prefix_plan_document": _copy_immutable(
            initial / PREFIX_PLAN_NAME,
            canonical_json_bytes(prepared.prefix_plan_document),
        ),
    }
    rows["residency_document"] = state.describe()
    return rows


def _invocation_document(
    prepared: PreparedDecisionOwnership,
    initial_rows: Mapping[str, object],
    bindings: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": INVOCATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "rank_source_vault": _prepared_rank_source(prepared).describe(),
        "active_page6_vault": prepared.state.active_projection.describe(),
        "residency": prepared.state.describe(),
        "frontier_plan": prepared.frontier_plan.describe(),
        "staging_plan": prepared.staging_plan.describe(),
        "prefix_plan": prepared.prefix_plan.describe(),
        "science_input": dict(prepared.science_input),
        "initial_artifacts": dict(initial_rows),
        "local_episode_ordinals": list(LOCAL_EPISODES),
        "lineage_call_ordinals": list(LINEAGE_ORDINALS),
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
        "bindings": dict(bindings),
        "retry_authorized": False,
        "sweep_authorized": False,
        "truth_key_bytes_read": False,
    }


def _executable_binding(bindings: Mapping[str, object]) -> Mapping[str, object] | None:
    value = bindings.get("native_executable")
    if value is None:
        return None
    binding = _mapping(value, "native executable binding")
    if not isinstance(binding.get("path"), str):
        raise O1C79RunError("native executable binding path differs")
    _sha256(binding.get("sha256"), "native executable binding digest")
    return binding


def _validate_call_window_executable(
    binding: Mapping[str, object] | None, *, when: str
) -> None:
    if binding is None:
        return
    observed = validate_native_executable(
        cast(str, binding["path"]), expected_sha256=cast(str, binding["sha256"])
    )
    if observed != binding:
        raise O1C79RunError(f"native executable changed {when} call")


def _failure_episode(
    *,
    episode_dir: Path,
    invocation_sha256: str,
    intent_sha256: str,
    active: ThresholdNoGoodVault,
    prepared: PreparedDecisionOwnership,
    exc: BaseException,
    phase: str,
    native_call_issued: bool,
    native_result_returned: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    if phase not in {"PRE_CALL", "CALL", "POST_CALL"}:
        raise O1C79RunError("failure phase differs")
    if native_result_returned and not native_call_issued:
        raise O1C79RunError("native result cannot precede native call")
    calls = int(native_call_issued)
    requested = REQUESTED_CONFLICTS_PER_EPISODE if native_call_issued else 0
    failure = {
        "classification": OPERATIONAL_TERMINAL,
        "phase": phase,
        "local_episode_ordinal": LOCAL_EPISODES[0],
        "lineage_call_ordinal": LINEAGE_ORDINALS[0],
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "occurred_after_persisted_intent": True,
        "lineage_burned": True,
        "page6_burned": True,
        "native_call_issued": native_call_issued,
        "native_result_returned": native_result_returned,
        "native_calls_consumed": calls,
        "requested_conflicts_consumed": requested,
        "actual_conflicts": None,
        "billed_conflicts": None,
        "operational_ownership_success": False,
        "qualified_prefix_activation": False,
        "science_gain": False,
        "retry_authorized": False,
        "sweep_authorized": False,
        "truth_key_bytes_read": False,
        **_o1c78_native_failure(exc),
    }
    _atomic_json(episode_dir / "terminal-failure.json", failure, immutable=True)
    episode = {
        "schema": EPISODE_SCHEMA,
        "completed": False,
        "local_episode_ordinal": LOCAL_EPISODES[0],
        "lineage_call_ordinal": LINEAGE_ORDINALS[0],
        "invocation_sha256": invocation_sha256,
        "intent_sha256": intent_sha256,
        "input_active_vault": active.describe(),
        "residency": prepared.state.describe(),
        "native_call_issued": native_call_issued,
        "native_result_returned": native_result_returned,
        "native_calls_consumed": calls,
        "requested_conflicts": requested,
        "actual_conflicts": None,
        "billed_conflicts": None,
        "operational_ownership_success": False,
        "qualified_prefix_activation": False,
        "science_gain": False,
        "retry_authorized": False,
        "sweep_authorized": False,
        "terminal_failure": failure,
    }
    _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    return episode, failure


def _terminal_outcome(
    *, episode: Mapping[str, object], failure: Mapping[str, object]
) -> DecisionOwnershipOutcome:
    calls = _nonnegative_int(episode.get("native_calls_consumed"), "failed calls")
    requested = _nonnegative_int(
        episode.get("requested_conflicts"), "failed requested conflicts"
    )
    return DecisionOwnershipOutcome(
        OPERATIONAL_TERMINAL,
        (
            "pre-call-intent-burned-without-native-call"
            if calls == 0
            else "native-call-or-invalid-unarchivable-result-terminal"
        ),
        (dict(episode),),
        calls,
        requested,
        None,
        None,
        False,
        False,
        False,
        0,
        0,
        dict(failure),
    )


def execute_episode(
    *,
    capsule: Path,
    prepared: PreparedDecisionOwnership,
    invoke_episode: EpisodeInvoker,
    verify_public_model: Callable[[bytes], bool],
    bindings: Mapping[str, object] | None = None,
) -> DecisionOwnershipOutcome:
    """Consume local 0 / lineage 19 once, with intent-before-call semantics."""

    if (
        not capsule.is_dir()
        or capsule.is_symlink()
        or not callable(invoke_episode)
        or not callable(verify_public_model)
    ):
        raise O1C79RunError("episode execution input differs")
    normalized_bindings = dict(bindings or {})
    synthetic = normalized_bindings.get("test_fixture") == "synthetic-target-free"
    _validate_prepared_contract(prepared, require_frozen=not synthetic)
    executable_binding = _executable_binding(normalized_bindings)
    initial_rows = _initial_artifacts(capsule, prepared)
    invocation = _invocation_document(prepared, initial_rows, normalized_bindings)
    invocation_path = capsule / "invocation.json"
    _atomic_json(invocation_path, invocation, immutable=True)
    invocation_sha = _sha256_file(invocation_path)

    initial = capsule / "initial"
    rank_path = initial / CHUNK_NAMES[0]
    frontier_path = initial / FRONTIER_PLAN_BINARY_NAME
    staging_path = initial / STAGING_PLAN_BINARY_NAME
    prefix_path = initial / PREFIX_PLAN_BINARY_NAME
    episode_dir = capsule / "episodes/00"
    episode_dir.mkdir(parents=True, exist_ok=False)
    active = prepared.state.active_projection
    active_path = episode_dir / "active-input.bin"
    active_row = _copy_immutable(active_path, active.serialized)
    intent = {
        "schema": INTENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "local_episode_ordinal": LOCAL_EPISODES[0],
        "lineage_call_ordinal": LINEAGE_ORDINALS[0],
        "invocation_sha256": invocation_sha,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "rank_source_vault": _prepared_rank_source(prepared).describe(),
        "active_input_vault": active.describe(),
        "active_input_artifact": active_row,
        "frontier_plan": prepared.frontier_plan.describe(),
        "frontier_plan_artifact": _artifact_row(frontier_path, relative_to=initial),
        "staging_plan": prepared.staging_plan.describe(),
        "staging_plan_artifact": _artifact_row(staging_path, relative_to=initial),
        "prefix_plan": prepared.prefix_plan.describe(),
        "prefix_plan_artifact": _artifact_row(prefix_path, relative_to=initial),
        "science_input": dict(prepared.science_input),
        "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "page6_and_lineage19_burn_on_persisted_intent": True,
        "requested_is_not_actual_or_billed": True,
        "retry_authorized": False,
        "sweep_authorized": False,
        "truth_key_bytes_read": False,
    }
    intent_path = episode_dir / "intent.json"
    _atomic_json(intent_path, intent, immutable=True)
    intent_sha = _sha256_file(intent_path)

    native_call_issued = False
    try:
        _validate_call_window_executable(executable_binding, when="before")
        native_call_issued = True
        result = invoke_episode(
            LOCAL_EPISODES[0],
            LINEAGE_ORDINALS[0],
            rank_path,
            active_path,
            frontier_path,
            staging_path,
            prefix_path,
        )
    except BaseException as exc:
        episode, failure = _failure_episode(
            episode_dir=episode_dir,
            invocation_sha256=invocation_sha,
            intent_sha256=intent_sha,
            active=active,
            prepared=prepared,
            exc=exc,
            phase="CALL" if native_call_issued else "PRE_CALL",
            native_call_issued=native_call_issued,
            native_result_returned=False,
        )
        return _terminal_outcome(episode=episode, failure=failure)

    try:
        _validate_call_window_executable(executable_binding, when="after")
        validated = _validated_episode_result(
            result,
            prepared=prepared,
            active=active,
            stream_id="o1c79-episode-00",
            verify_public_model=verify_public_model,
            require_concrete_result=not synthetic,
        )
        raw = _mapping(validated.get("raw"), "validated raw result")
        central = _mapping(validated.get("central_reader"), "validated central")
        ownership = _mapping(validated.get("decision_ownership"), "validated ownership")
        telemetry = _mapping(validated.get("telemetry"), "validated telemetry")
        stats = validate_vault_soft_conflict_ledger(
            _mapping(validated.get("stats"), "validated work ledger")
        )
        resources = _mapping(validated.get("resources"), "validated resources")
        operational = _mapping(
            validated.get("operational_ownership"), "ownership conclusion"
        )
        prefix = _mapping(validated.get("prefix_activation"), "prefix conclusion")
        science = _mapping(validated.get("science"), "science conclusion")
        operational_success = operational.get("operational_ownership_success")
        prefix_success = prefix.get("qualified_prefix_activation")
        science_gain = science.get("science_gain")
        if not all(
            isinstance(value, bool)
            for value in (operational_success, prefix_success, science_gain)
        ):
            raise O1C79RunError("three-axis conclusion differs")
        safe_prunes = _nonnegative_int(
            validated.get("safe_threshold_prunes"), "safe threshold prunes"
        )
        novel_sha = _sequence(
            validated.get("globally_novel_clause_sha256"), "novel clause digests"
        )
        if not all(
            isinstance(value, str) and _sha256(value, "novel clause digest")
            for value in novel_sha
        ):
            raise O1C79RunError("novel clause digest ledger differs")
        status = _nonnegative_int(validated.get("status"), "native status")
        key_model = validated.get("key_model")

        # A result is claimable only after every promoted view is durably archived.
        native_evidence = _write_evidence(episode_dir / "native-result.json.gz", raw)
        telemetry_evidence = _write_evidence(
            episode_dir / "vault-telemetry.json.gz", telemetry
        )
        central_evidence = _write_evidence(
            episode_dir / "central-reader.json.gz", central
        )
        ownership_evidence = _write_evidence(
            episode_dir / "decision-ownership.json.gz", ownership
        )
        conclusion = {
            "operational_ownership": dict(operational),
            "qualified_prefix": dict(prefix),
            "science": dict(science),
        }
        conclusion_path = episode_dir / "three-axis-conclusion.json"
        _atomic_json(conclusion_path, conclusion, immutable=True)
        conclusion_row = _artifact_row(conclusion_path, relative_to=episode_dir)
        actual = stats["solve_conflicts"]
        billed = stats["billed_conflicts"]
        public_model = {
            "present": key_model is not None,
            "verified_8_of_8": status == 10,
            "model_sha256": (
                sha256_bytes(cast(bytes, key_model)) if status == 10 else None
            ),
            "truth_key_bytes_read": False,
        }
        episode = {
            "schema": EPISODE_SCHEMA,
            "completed": True,
            "local_episode_ordinal": LOCAL_EPISODES[0],
            "lineage_call_ordinal": LINEAGE_ORDINALS[0],
            "invocation_sha256": invocation_sha,
            "intent_sha256": intent_sha,
            "input_active_vault": active.describe(),
            "residency": prepared.state.describe(),
            "native_call_issued": True,
            "native_result_returned": True,
            "native_calls_consumed": 1,
            "requested_conflicts": REQUESTED_CONFLICTS_PER_EPISODE,
            "actual_conflicts": actual,
            "billed_conflicts": billed,
            "status": status,
            "native_evidence": native_evidence,
            "vault_telemetry_evidence": telemetry_evidence,
            "central_reader_evidence": central_evidence,
            "decision_ownership_evidence": ownership_evidence,
            "three_axis_conclusion_artifact": conclusion_row,
            "operational_ownership": dict(operational),
            "qualified_prefix": dict(prefix),
            "science": dict(science),
            "operational_ownership_success": operational_success,
            "qualified_prefix_activation": prefix_success,
            "science_gain": science_gain,
            "globally_novel_clause_count": len(novel_sha),
            "globally_novel_clause_sha256": list(novel_sha),
            "safe_threshold_prunes": safe_prunes,
            "work": dict(stats),
            "resources": dict(resources),
            "public_model": public_model,
            "page6_burned": True,
            "lineage19_burned": True,
            "retry_authorized": False,
            "sweep_authorized": False,
            "terminal_failure": None,
        }
        _atomic_json(episode_dir / "episode.json", episode, immutable=True)
    except BaseException as exc:
        episode, failure = _failure_episode(
            episode_dir=episode_dir,
            invocation_sha256=invocation_sha,
            intent_sha256=intent_sha,
            active=active,
            prepared=prepared,
            exc=exc,
            phase="POST_CALL",
            native_call_issued=True,
            native_result_returned=True,
        )
        return _terminal_outcome(episode=episode, failure=failure)

    if status == 10:
        classification = PUBLIC_EXACT_RECOVERY
        stop_reason = "public-complete-model-exactly-verified"
    elif status == 20:
        classification = THRESHOLD_REGION_EXHAUSTED
        stop_reason = "certified-frozen-threshold-region-exhausted"
    elif safe_prunes:
        classification = SAFE_PRUNE_GAIN
        stop_reason = "certified-safe-threshold-trail-prunes-observed"
    elif novel_sha:
        classification = NOVEL_CLAUSE_GAIN
        stop_reason = "globally-novel-exact-threshold-no-goods-returned"
    elif prefix_success:
        classification = MECHANISM_ONLY
        stop_reason = "qualified-prefix-activation-without-science-gain"
    elif operational_success:
        classification = OWNERSHIP_ONLY
        stop_reason = "operational-ownership-success-without-qualified-prefix"
    else:
        classification = NO_ACTIVATION
        stop_reason = "no-operational-ownership-prefix-or-science-gain"
    return DecisionOwnershipOutcome(
        classification,
        stop_reason,
        (episode,),
        1,
        REQUESTED_CONFLICTS_PER_EPISODE,
        actual,
        billed,
        cast(bool, operational_success),
        cast(bool, prefix_success),
        cast(bool, science_gain),
        len(novel_sha),
        safe_prunes,
        None,
    )


# Compatibility spelling; there is still only one straight episode.
execute_stream = execute_episode


def build_result(
    *,
    outcome: DecisionOwnershipOutcome,
    capsule_relative: str,
    source_commit: str,
    preflight: Mapping[str, object] | None = None,
    started_at: str | None = None,
    runtime: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if (
        not isinstance(outcome, DecisionOwnershipOutcome)
        or not isinstance(capsule_relative, str)
        or not capsule_relative
        or not isinstance(source_commit, str)
    ):
        raise O1C79RunError("result input differs")
    if (
        outcome.native_calls not in (0, 1)
        or outcome.requested_conflicts
        != outcome.native_calls * REQUESTED_CONFLICTS_PER_EPISODE
        or (
            outcome.operational_failure is not None
            and (
                outcome.actual_conflicts is not None
                or outcome.billed_conflicts is not None
            )
        )
    ):
        raise O1C79RunError("terminal call/work ledger differs")
    return {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "started_at": started_at
        or datetime.now().astimezone().isoformat(timespec="seconds"),
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "capsule": capsule_relative,
        "classification": outcome.classification,
        "stop_reason": outcome.stop_reason,
        "episodes": [dict(episode) for episode in outcome.episodes],
        "operational_failure": (
            dict(outcome.operational_failure)
            if outcome.operational_failure is not None
            else None
        ),
        "claim_boundary": {
            "operational_ownership_success": outcome.operational_ownership_success,
            "qualified_prefix_activation": outcome.qualified_prefix_activation,
            "science_gain": outcome.science_gain,
            "trace_change_alone_is_science_gain": False,
            "ownership_accounting_alone_is_science_gain": False,
            "proposal_count_alone_is_prefix_activation": False,
            "requested_conflicts_are_actual_or_billed": False,
            "page6_sha256": PAGE6_SHA256,
            "page5_replayed": False,
            "lineage19_only": True,
            "retry_or_sweep": False,
            "truth_key_bytes_read": False,
            "fresh_targets": 0,
            "fresh_reveal_calls": 0,
            "refits": 0,
            "MPS_or_GPU": False,
        },
        "resources": {
            "native_solver_calls": outcome.native_calls,
            "requested_conflicts": outcome.requested_conflicts,
            "actual_conflicts": outcome.actual_conflicts,
            "billed_conflicts": outcome.billed_conflicts,
            "globally_novel_clauses": outcome.globally_novel_clauses,
            "safe_threshold_prunes": outcome.safe_threshold_prunes,
            "persistent_artifact_bytes": None,
            **dict(runtime or {}),
        },
        "preflight": dict(preflight) if preflight is not None else None,
        "publication_recovery": None,
        "next_action": (
            "Never retry Page 6 or lineage 19. Preserve the three axes "
            "separately; carry forward only validated attacker-visible science."
        ),
    }


def write_recovery_source(capsule: Path, result: Mapping[str, object]) -> Path:
    if (
        result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C79RunError("pre-finalization recovery result differs")
    payload = canonical_json_bytes(result)
    source = {
        "schema": RECOVERY_SOURCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "PRE_FINALIZATION",
        "result_schema": RESULT_SCHEMA,
        "result_sha256": sha256_bytes(payload),
        "result_serialized_bytes": len(payload),
        "pre_finalization_result": dict(result),
        "native_calls_authorized_during_recovery": 0,
        "public_verification_calls_authorized_during_recovery": 0,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
    }
    path = capsule / RECOVERY_SOURCE_NAME
    _atomic_json(path, source, immutable=True)
    return path


write_publication_source = write_recovery_source
PUBLICATION_SOURCE_NAME = RECOVERY_SOURCE_NAME


def _validate_recovery_episode(
    capsule: Path, result: Mapping[str, object]
) -> tuple[int, int, int | None, int | None, bool, bool, bool]:
    episodes = _sequence(result.get("episodes"), "recovery episodes")
    if len(episodes) != 1:
        raise O1C79RunError("recovery straight episode count differs")
    expected = _mapping(episodes[0], "recovery expected episode")
    episode_dir = capsule / "episodes/00"
    journal = _mapping(
        json.loads(
            _regular(episode_dir / "episode.json", "episode journal").read_bytes()
        ),
        "episode journal",
    )
    if canonical_json_bytes(journal) != (episode_dir / "episode.json").read_bytes():
        raise O1C79RunError("recovery episode is not canonical")
    if journal != expected or journal.get("schema") != EPISODE_SCHEMA:
        raise O1C79RunError("recovery episode journal differs")
    intent_path = _regular(episode_dir / "intent.json", "recovery intent")
    intent = _mapping(json.loads(intent_path.read_bytes()), "recovery intent")
    invocation_path = _regular(capsule / "invocation.json", "recovery invocation")
    if (
        canonical_json_bytes(intent) != intent_path.read_bytes()
        or intent.get("schema") != INTENT_SCHEMA
        or intent.get("local_episode_ordinal") != 0
        or intent.get("lineage_call_ordinal") != 19
        or intent.get("invocation_sha256") != _sha256_file(invocation_path)
        or expected.get("intent_sha256") != _sha256_file(intent_path)
    ):
        raise O1C79RunError("recovery persisted intent differs")
    calls = _nonnegative_int(expected.get("native_calls_consumed"), "recovery calls")
    requested = _nonnegative_int(
        expected.get("requested_conflicts"), "recovery requested conflicts"
    )
    if calls not in (0, 1) or requested != calls * REQUESTED_CONFLICTS_PER_EPISODE:
        raise O1C79RunError("recovery call ledger differs")
    completed = expected.get("completed")
    if completed is False:
        failure = _mapping(expected.get("terminal_failure"), "recovery failure")
        failure_path = _regular(
            episode_dir / "terminal-failure.json", "recovery failure journal"
        )
        observed_failure = _mapping(json.loads(failure_path.read_bytes()), "failure")
        if (
            canonical_json_bytes(observed_failure) != failure_path.read_bytes()
            or observed_failure != failure
            or failure.get("occurred_after_persisted_intent") is not True
            or failure.get("lineage_burned") is not True
            or failure.get("page6_burned") is not True
            or failure.get("native_calls_consumed") != calls
            or failure.get("requested_conflicts_consumed") != requested
            or expected.get("actual_conflicts") is not None
            or expected.get("billed_conflicts") is not None
        ):
            raise O1C79RunError("recovery terminal failure differs")
        return calls, requested, None, None, False, False, False
    if completed is not True or calls != 1:
        raise O1C79RunError("recovery completion differs")
    stats = validate_vault_soft_conflict_ledger(
        _mapping(expected.get("work"), "recovery work ledger")
    )
    actual = _nonnegative_int(expected.get("actual_conflicts"), "actual conflicts")
    billed = _nonnegative_int(expected.get("billed_conflicts"), "billed conflicts")
    if actual != stats["solve_conflicts"] or billed != stats["billed_conflicts"]:
        raise O1C79RunError("recovery validated conflict ledger differs")
    raw = _read_evidence(
        episode_dir, expected.get("native_evidence"), "recovery native result"
    )
    central = _read_evidence(
        episode_dir,
        expected.get("central_reader_evidence"),
        "recovery central reader",
    )
    ownership = _read_evidence(
        episode_dir,
        expected.get("decision_ownership_evidence"),
        "recovery decision ownership",
    )
    _read_evidence(
        episode_dir,
        expected.get("vault_telemetry_evidence"),
        "recovery vault telemetry",
    )
    if (
        raw.get("central_reader") != central
        or raw.get("decision_ownership") != ownership
    ):
        raise O1C79RunError("recovery native promoted views differ")
    # Synthetic fixtures intentionally use a non-production schema.
    if raw.get("schema") == _native_v20.JOINT_SCORE_SIEVE_RESULT_SCHEMA:
        _native_v20.validate_native_lifecycle(raw)
    conclusion_path = _validate_artifact_row(
        episode_dir,
        expected.get("three_axis_conclusion_artifact"),
        "recovery three-axis conclusion",
    )
    conclusion = _mapping(json.loads(conclusion_path.read_bytes()), "conclusion")
    if canonical_json_bytes(conclusion) != conclusion_path.read_bytes():
        raise O1C79RunError("recovery conclusion is not canonical")
    operational = expected.get("operational_ownership_success")
    prefix = expected.get("qualified_prefix_activation")
    science = expected.get("science_gain")
    if (
        not all(isinstance(value, bool) for value in (operational, prefix, science))
        or _mapping(conclusion.get("operational_ownership"), "operational axis").get(
            "operational_ownership_success"
        )
        is not operational
        or _mapping(conclusion.get("qualified_prefix"), "prefix axis").get(
            "qualified_prefix_activation"
        )
        is not prefix
        or _mapping(conclusion.get("science"), "science axis").get("science_gain")
        is not science
    ):
        raise O1C79RunError("recovery three-axis conclusion differs")
    return (
        calls,
        requested,
        actual,
        billed,
        cast(bool, operational),
        cast(bool, prefix),
        cast(bool, science),
    )


def recover_publication(capsule: Path) -> dict[str, object]:
    """Recover the archived conclusion without a native or verifier callback."""

    _validate_capsule_tree(capsule)
    source_path = _regular(capsule / RECOVERY_SOURCE_NAME, "recovery source")
    source_document = _mapping(json.loads(source_path.read_bytes()), "recovery source")
    if canonical_json_bytes(source_document) != source_path.read_bytes():
        raise O1C79RunError("recovery source is not canonical")
    result = dict(
        _mapping(source_document.get("pre_finalization_result"), "recovery result")
    )
    payload = canonical_json_bytes(result)
    if (
        source_document.get("schema") != RECOVERY_SOURCE_SCHEMA
        or source_document.get("attempt_id") != ATTEMPT_ID
        or source_document.get("state") != "PRE_FINALIZATION"
        or source_document.get("result_schema") != RESULT_SCHEMA
        or source_document.get("result_sha256") != sha256_bytes(payload)
        or source_document.get("result_serialized_bytes") != len(payload)
        or source_document.get("native_calls_authorized_during_recovery") != 0
        or source_document.get("public_verification_calls_authorized_during_recovery")
        != 0
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or result.get("publication_recovery") is not None
    ):
        raise O1C79RunError("pre-finalization recovery source differs")
    calls, requested, actual, billed, operational, prefix, science = (
        _validate_recovery_episode(capsule, result)
    )
    resources = _mapping(result.get("resources"), "recovery result resources")
    boundary = _mapping(result.get("claim_boundary"), "recovery claim boundary")
    if (
        resources.get("native_solver_calls") != calls
        or resources.get("requested_conflicts") != requested
        or resources.get("actual_conflicts") != actual
        or resources.get("billed_conflicts") != billed
        or boundary.get("operational_ownership_success") is not operational
        or boundary.get("qualified_prefix_activation") is not prefix
        or boundary.get("science_gain") is not science
    ):
        raise O1C79RunError("recovery result conclusion differs")
    result["publication_recovery"] = {
        "schema": PUBLICATION_RECOVERY_SCHEMA,
        "pre_finalization_source_sha256": sha256_bytes(source_path.read_bytes()),
        "publication_recovered_from_episode_sidecars": True,
        "native_calls_issued_during_recovery": 0,
        "public_verification_calls_issued_during_recovery": 0,
        "retry_calls_issued_during_recovery": 0,
        "truth_key_bytes_read": False,
        "recovered_episode_count": 1,
        "recovered_native_calls_consumed": calls,
    }
    return result


def _recovered_publication_source_document(
    capsule: Path, recovered: Mapping[str, object]
) -> dict[str, object]:
    recovery = _mapping(
        recovered.get("publication_recovery"), "recovered publication proof"
    )
    if (
        recovered.get("schema") != RESULT_SCHEMA
        or recovered.get("attempt_id") != ATTEMPT_ID
        or recovery.get("schema") != PUBLICATION_RECOVERY_SCHEMA
        or recovery.get("native_calls_issued_during_recovery") != 0
        or recovery.get("public_verification_calls_issued_during_recovery") != 0
    ):
        raise O1C79RunError("recovered finalization result differs")
    source_path = _regular(capsule / RECOVERY_SOURCE_NAME, "recovery source")
    payload = canonical_json_bytes(recovered)
    return {
        "schema": RECOVERED_PUBLICATION_SOURCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "state": "RECOVERED_PRE_FINALIZATION",
        "original_recovery_source_sha256": sha256_bytes(source_path.read_bytes()),
        "result_schema": RESULT_SCHEMA,
        "result_sha256": sha256_bytes(payload),
        "result_serialized_bytes": len(payload),
        "recovered_result": dict(recovered),
        "native_calls_authorized_during_resume": 0,
        "public_verification_calls_authorized_during_resume": 0,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
    }


def write_recovered_publication_source(
    capsule: Path, recovered: Mapping[str, object]
) -> Path:
    """Persist exact recovered bytes before any resumed terminal marker."""

    document = _recovered_publication_source_document(capsule, recovered)
    payload = canonical_json_bytes(document)
    path = capsule / PUBLICATION_RECOVERY_NAME
    if path.exists() or path.is_symlink():
        if _regular(path, "recovered publication source").read_bytes() != payload:
            raise O1C79RunError("recovered publication source differs")
        return path
    _atomic_create(path, payload, immutable=True)
    return path


def _read_recovered_publication_source(capsule: Path) -> dict[str, object]:
    path = _regular(capsule / PUBLICATION_RECOVERY_NAME, "recovered publication source")
    document = _read_json(path, "recovered publication source")
    recovered = dict(
        _mapping(document.get("recovered_result"), "recovered finalization result")
    )
    expected = recover_publication(capsule)
    payload = canonical_json_bytes(recovered)
    if (
        document.get("schema") != RECOVERED_PUBLICATION_SOURCE_SCHEMA
        or document.get("attempt_id") != ATTEMPT_ID
        or document.get("state") != "RECOVERED_PRE_FINALIZATION"
        or document.get("original_recovery_source_sha256")
        != sha256_bytes((capsule / RECOVERY_SOURCE_NAME).read_bytes())
        or document.get("result_schema") != RESULT_SCHEMA
        or document.get("result_sha256") != sha256_bytes(payload)
        or document.get("result_serialized_bytes") != len(payload)
        or document.get("native_calls_authorized_during_resume") != 0
        or document.get("public_verification_calls_authorized_during_resume") != 0
        or document.get("retry_authorized") is not False
        or recovered != expected
    ):
        raise O1C79RunError("recovered publication resume source differs")
    return recovered


def _markdown(result: Mapping[str, object]) -> bytes:
    resources = _mapping(result.get("resources"), "result resources")
    boundary = _mapping(result.get("claim_boundary"), "result claim boundary")
    return (
        "# O1C-0079 — APPLE8 central decision ownership\n\n"
        f"- Classification: `{result.get('classification')}`\n"
        f"- Stop reason: `{result.get('stop_reason')}`\n"
        f"- Native calls: `{resources.get('native_solver_calls')}`\n"
        f"- Requested conflicts: `{resources.get('requested_conflicts')}`\n"
        f"- Actual conflicts: `{resources.get('actual_conflicts')}`\n"
        f"- Billed conflicts: `{resources.get('billed_conflicts')}`\n"
        "- Input: fresh Page 6 / local 0 / lineage 19\n"
        f"- Operational ownership success: `{str(boundary.get('operational_ownership_success')).lower()}`\n"
        f"- Qualified prefix activation: `{str(boundary.get('qualified_prefix_activation')).lower()}`\n"
        f"- Science gain: `{str(boundary.get('science_gain')).lower()}`\n"
        "- No retry, sweep, truth, reveal, refit, MPS, or GPU work\n"
    ).encode("utf-8")


def _manifest_payload(capsule: Path, virtual: Mapping[str, bytes]) -> tuple[bytes, int]:
    return cast(
        tuple[bytes, int],
        _translate_technical(lambda: _o1c78_manifest_payload(capsule, virtual)),
    )


def _publish_exact(path: Path, payload: bytes, *, immutable: bool = True) -> None:
    if path.exists() or path.is_symlink():
        existing = _regular(path, "publication artifact").read_bytes()
        if existing != payload:
            raise O1C79RunError(f"partial publication artifact differs: {path.name}")
        return
    _atomic_create(path, payload, immutable=immutable)


def _publication_payloads(
    capsule: Path, result: Mapping[str, object]
) -> tuple[dict[str, object], bytes, bytes, bytes, int]:
    """Derive final bytes without mutating the pre-finalization source."""

    finalized = cast(dict[str, object], json.loads(canonical_json_bytes(result)))
    resources = cast(dict[str, object], finalized.get("resources"))
    if not isinstance(resources, dict):
        raise O1C79RunError("publication resource ledger differs")
    for _ in range(16):
        result_payload = canonical_json_bytes(finalized)
        run_payload = _markdown(finalized)
        manifest, persistent = _manifest_payload(
            capsule, {"RUN.md": run_payload, "result.json": result_payload}
        )
        if resources.get("persistent_artifact_bytes") == persistent:
            break
        resources["persistent_artifact_bytes"] = persistent
    else:
        raise O1C79RunError("persistent artifact ledger did not converge")
    result_payload = canonical_json_bytes(finalized)
    run_payload = _markdown(finalized)
    manifest, persistent = _manifest_payload(
        capsule, {"RUN.md": run_payload, "result.json": result_payload}
    )
    if (
        resources.get("persistent_artifact_bytes") != persistent
        or persistent > MAXIMUM_PERSISTENT_ARTIFACT_BYTES
    ):
        raise O1C79RunError("persistent artifact byte budget differs")
    return finalized, result_payload, run_payload, manifest, persistent


def finalize_capsule(
    capsule: Path, authoritative: Path, result: dict[str, object]
) -> None:
    """Idempotently finish a capsule; an interrupted publication can resume."""

    if result.get("schema") != RESULT_SCHEMA or result.get("attempt_id") != ATTEMPT_ID:
        raise O1C79RunError("terminal O1C79 publication differs")
    if result.get("publication_recovery") is not None:
        write_recovered_publication_source(capsule, result)
    finalized, result_payload, run_payload, manifest, _ = _publication_payloads(
        capsule, result
    )
    result.clear()
    result.update(finalized)
    authoritative.parent.mkdir(parents=True, exist_ok=True)
    _publish_exact(capsule / "RUN.md", run_payload)
    _publish_exact(capsule / "result.json", result_payload)
    _publish_exact(capsule / "artifacts.sha256", manifest)
    _publish_exact(authoritative, result_payload)
    for path in sorted(
        capsule.rglob("*"), key=lambda item: len(item.parts), reverse=True
    ):
        path.chmod(0o444 if path.is_file() else 0o555)
    capsule.chmod(0o555)


def _read_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        payload = _regular(path, field).read_bytes()
        value = _mapping(json.loads(payload), field)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise O1C79RunError(f"{field} JSON differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C79RunError(f"{field} is not canonical")
    return value


def _existing_authoritative(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    value = dict(_read_json(path, "authoritative O1C79 result"))
    if value.get("schema") != RESULT_SCHEMA or value.get("attempt_id") != ATTEMPT_ID:
        raise O1C79RunError("authoritative O1C79 result differs")
    return value


def _republish_sealed_capsule(capsule: Path, authoritative: Path) -> dict[str, object]:
    _validate_capsule_tree(capsule)
    result_path = _regular(capsule / "result.json", "sealed capsule result")
    result = dict(_read_json(result_path, "sealed capsule result"))
    expected_manifest, persistent = _manifest_payload(capsule, {})
    resources = _mapping(result.get("resources"), "sealed capsule resources")
    if (
        _regular(capsule / "artifacts.sha256", "sealed capsule manifest").read_bytes()
        != expected_manifest
        or result.get("schema") != RESULT_SCHEMA
        or result.get("attempt_id") != ATTEMPT_ID
        or resources.get("persistent_artifact_bytes") != persistent
    ):
        raise O1C79RunError("sealed O1C79 capsule differs")
    _publish_exact(authoritative, result_path.read_bytes())
    return result


def _digest_or_pending(value: object, field: str) -> str:
    return _sha256(value, field, pending=True)


def _commit_or_pending(value: object, field: str) -> str:
    if value == "PENDING":
        return "PENDING"
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C79RunError(f"{field} differs")
    return value


def _native_source_closure_sha256(
    digests: Mapping[str, object], *, pending: bool = False
) -> str:
    rows: list[dict[str, str]] = []
    for name in NATIVE_INCLUDE_CLOSURE:
        digest = _sha256(
            digests.get(name), f"native closure digest {name}", pending=pending
        )
        if digest == "PENDING":
            return "PENDING"
        rows.append({"path": SOURCE_PATHS[name], "sha256": digest})
    return sha256_bytes(
        canonical_json_bytes({"schema": NATIVE_SOURCE_CLOSURE_SCHEMA, "files": rows})
    )


def load_config(path: str | Path, *, root: Path | None = None) -> dict[str, object]:
    """Load the complete frozen contract without writing or issuing a call."""

    lab = (root or lab_root()).resolve(strict=True)
    config_path = Path(path).resolve(strict=True)
    if not config_path.is_relative_to(lab):
        raise O1C79RunError("O1C79 config escapes the lab")
    config = dict(_read_json(config_path, "O1C79 config"))
    required_root = {
        "schema",
        "attempt_id",
        "parent",
        "preparation",
        "inputs",
        "native",
        "source",
        "target_free_preflight",
        "budgets",
        "next_action",
    }
    if (
        set(config) != required_root
        or config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or not isinstance(config.get("next_action"), str)
        or not config.get("next_action")
    ):
        raise O1C79RunError("frozen O1C79 config fields differ")
    parent = _mapping(config["parent"], "config parent")
    if (
        set(parent)
        != {
            "result",
            "capsule",
            "result_sha256",
            "manifest_sha256",
            "source_commit",
            "last_lineage_ordinal",
            "classification",
        }
        or _relative_contract(parent.get("result"), "parent result")
        != PARENT_RESULT_RELATIVE.as_posix()
        or _relative_contract(parent.get("capsule"), "parent capsule")
        != PARENT_CAPSULE_RELATIVE.as_posix()
        or parent.get("result_sha256") != PARENT_RESULT_SHA256
        or parent.get("manifest_sha256") != PARENT_MANIFEST_SHA256
        or parent.get("source_commit") != PARENT_SOURCE_COMMIT
        or parent.get("last_lineage_ordinal") != PARENT_LAST_LINEAGE_ORDINAL
        or parent.get("classification") != PARENT_CLASSIFICATION
    ):
        raise O1C79RunError("frozen O1C78 terminal parent differs")
    preparation = _mapping(config["preparation"], "config preparation")
    if (
        set(preparation) != {"directory", "manifest_sha256"}
        or _relative_contract(preparation.get("directory"), "preparation directory")
        != PREPARATION_DIRECTORY_RELATIVE.as_posix()
        or preparation.get("manifest_sha256") != EXPECTED_PREPARED_MANIFEST_SHA256
    ):
        raise O1C79RunError("prepared Page-6 config differs")
    inputs = _mapping(config["inputs"], "config inputs")
    required_inputs = {
        "cnf",
        "cnf_sha256",
        "potential",
        "potential_sha256",
        "grouping",
        "grouping_sha256",
        "o1c73_config",
        "o1c73_config_sha256",
    }
    if set(inputs) != required_inputs:
        raise O1C79RunError("frozen O1C79 public inputs differ")
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        _relative_contract(inputs.get(name), f"input {name}")
        _digest_or_pending(inputs.get(f"{name}_sha256"), f"input {name} digest")
    native = _mapping(config["native"], "config native")
    required_native = {
        "source",
        "executable",
        "expected_source_sha256",
        "expected_executable_sha256",
        "adapter_schema",
        "result_schema",
        "rank_source_sha256",
        "active_vault_sha256",
        "frontier_plan_sha256",
        "frontier_plan_document_sha256",
        "staging_plan_sha256",
        "staging_plan_document_sha256",
        "prefix_plan_sha256",
        "prefix_plan_document_sha256",
        "science_input_sha256",
        "decision_ownership_header_sha256",
        "source_closure_sha256",
    }
    if (
        set(native) != required_native
        or _relative_contract(native.get("source"), "native source")
        != SOURCE_PATHS["native_v17"]
        or _relative_contract(native.get("executable"), "native executable")
        != "build/o1c79/native-joint-score-sieve"
        or native.get("adapter_schema") != _native_v20.JOINT_SCORE_SIEVE_ADAPTER_SCHEMA
        or native.get("result_schema") != _native_v20.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native.get("rank_source_sha256") != RANK_SOURCE_SHA256
        or native.get("active_vault_sha256") != PAGE6_SHA256
        or native.get("frontier_plan_sha256") != FRONTIER_PLAN_BINARY_SHA256
        or native.get("frontier_plan_document_sha256")
        != EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256
        or native.get("staging_plan_sha256") != STAGING_PLAN_BINARY_SHA256
        or native.get("staging_plan_document_sha256")
        != EXPECTED_STAGING_PLAN_DOCUMENT_SHA256
        or native.get("prefix_plan_sha256") != PREFIX_PLAN_BINARY_SHA256
        or native.get("prefix_plan_document_sha256")
        != EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256
        or native.get("science_input_sha256") != EXPECTED_SCIENCE_INPUT_SHA256
    ):
        raise O1C79RunError("native central-ownership config differs")
    _digest_or_pending(native.get("expected_source_sha256"), "native source digest")
    _digest_or_pending(
        native.get("expected_executable_sha256"), "native executable digest"
    )
    source = _mapping(config["source"], "config source")
    paths = _mapping(source.get("paths"), "config source paths")
    expected_sources = _mapping(source.get("expected_sha256"), "source digests")
    if (
        set(source) != {"paths", "expected_sha256", "expected_commit"}
        or dict(paths) != SOURCE_PATHS
        or set(expected_sources) != set(SOURCE_PATHS)
    ):
        raise O1C79RunError("source freeze config differs")
    _commit_or_pending(source.get("expected_commit"), "expected source commit")
    for name in SOURCE_PATHS:
        _digest_or_pending(expected_sources.get(name), f"source digest {name}")
    expected_closure = _native_source_closure_sha256(expected_sources, pending=True)
    if (
        native.get("expected_source_sha256") != expected_sources.get("native_v17")
        or native.get("decision_ownership_header_sha256")
        != expected_sources.get("decision_ownership_header")
        or _digest_or_pending(
            native.get("source_closure_sha256"), "native source closure digest"
        )
        != expected_closure
    ):
        raise O1C79RunError("native/source digest binding differs")
    gate = _mapping(config["target_free_preflight"], "config target-free gate")
    if (
        set(gate) != {"path", "sha256", "schema", "classification"}
        or _relative_contract(gate.get("path"), "target-free preflight path")
        != TARGET_FREE_PREFLIGHT_RELATIVE.as_posix()
        or gate.get("schema") != TARGET_FREE_GATE_SCHEMA
        or gate.get("classification") != TARGET_FREE_GATE_CLASSIFICATION
    ):
        raise O1C79RunError("target-free ownership gate config differs")
    _digest_or_pending(gate.get("sha256"), "target-free gate digest")
    budgets = _mapping(config["budgets"], "config budgets")
    expected_budgets: dict[str, object] = {
        "active_clause_limit": ACTIVE_CLAUSE_LIMIT,
        "local_episode_ordinals": list(LOCAL_EPISODES),
        "lineage_call_ordinals": list(LINEAGE_ORDINALS),
        "requested_conflicts_per_episode": REQUESTED_CONFLICTS_PER_EPISODE,
        "maximum_native_solver_calls": MAXIMUM_NATIVE_SOLVER_CALLS,
        "maximum_total_requested_conflicts": MAXIMUM_TOTAL_REQUESTED_CONFLICTS,
        "timeout_seconds": TIMEOUT_SECONDS,
        "memory_limit_bytes": MEMORY_LIMIT_BYTES,
        "maximum_persistent_artifact_bytes": MAXIMUM_PERSISTENT_ARTIFACT_BYTES,
        "minimum_disk_free_bytes": MINIMUM_DISK_FREE_BYTES,
        "maximum_fresh_targets": 0,
        "maximum_scientific_entropy_calls": 0,
        "maximum_fresh_reveal_calls": 0,
        "maximum_refits": 0,
        "maximum_mps_calls": 0,
        "maximum_gpu_calls": 0,
        "retry_authorized": False,
        "sweep_authorized": False,
    }
    if dict(budgets) != expected_budgets:
        raise O1C79RunError("frozen O1C79 budgets differ")
    return config


_REQUIRED_GATE_TRUE = (
    "pure_lifecycle_fixture_passed",
    "public_cadical_alias_fixture_passed",
    "orphan_proposal_rejection_fixture_passed",
    "mixed_unwind_order_fixture_passed",
    "central_reader_composition_fixture_passed",
    "bounded_telemetry_fixture_passed",
    "old_returned_ever_assertion_absent",
    "preparation_determinism_fixture_passed",
    "single_call_schedule_fixture_passed",
    "durable_intent_fixture_passed",
    "no_retry_fixture_passed",
    "recovery_zero_call_fixture_passed",
    "publication_republish_zero_call_fixture_passed",
)


def _validate_target_free_gate(
    path: Path,
    *,
    expected_sha256: str,
    prepared: PreparedDecisionOwnership,
    source_sha256: Mapping[str, str],
) -> Mapping[str, object]:
    payload = _regular(path, "target-free preflight").read_bytes()
    if sha256_bytes(payload) != expected_sha256:
        raise O1C79RunError("target-free preflight digest differs")
    try:
        row = _mapping(json.loads(payload), "target-free preflight")
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C79RunError("target-free preflight JSON differs") from exc
    if (
        canonical_json_bytes(row) != payload
        or row.get("schema") != TARGET_FREE_GATE_SCHEMA
        or row.get("attempt_id") != ATTEMPT_ID
        or row.get("classification") != TARGET_FREE_GATE_CLASSIFICATION
        or row.get("native_solver_calls") != 0
        or row.get("truth_key_bytes_read") is not False
        or row.get("fresh_targets") != 0
        or row.get("fresh_reveal_calls") != 0
        or row.get("refits") != 0
        or row.get("MPS_or_GPU") is not False
        or row.get("prepared_manifest_sha256") != prepared.manifest_sha256
        or row.get("page6_sha256") != PAGE6_SHA256
        or row.get("frontier_plan_sha256") != FRONTIER_PLAN_BINARY_SHA256
        or row.get("staging_plan_sha256") != STAGING_PLAN_BINARY_SHA256
        or row.get("prefix_plan_sha256") != PREFIX_PLAN_BINARY_SHA256
        or row.get("science_input_sha256") != EXPECTED_SCIENCE_INPUT_SHA256
        or row.get("decision_ownership_header_sha256")
        != source_sha256.get("decision_ownership_header")
        or row.get("pure_reference_source_sha256")
        != source_sha256.get("decision_ownership_v1")
        or row.get("pure_reference_fixture_sha256")
        != source_sha256.get("decision_ownership_fixture_tests")
        or row.get("adapter_v20_fixture_sha256")
        != source_sha256.get("adapter_v20_fixture_tests")
        or row.get("preparation_fixture_sha256")
        != source_sha256.get("preparation_fixture_tests")
        or row.get("runner_fixture_sha256") != source_sha256.get("runner_fixture_tests")
        or row.get("native_source_closure_sha256")
        != _native_source_closure_sha256(source_sha256)
        or row.get("local_episode_ordinals") != [0]
        or row.get("lineage_call_ordinals") != [19]
        or row.get("requested_conflicts_per_episode") != 128
        or row.get("maximum_native_solver_calls") != 1
        or any(row.get(field) is not True for field in _REQUIRED_GATE_TRUE)
    ):
        raise O1C79RunError("target-free decision-ownership gate differs")
    return dict(row)


def _available_memory_bytes() -> int | None:
    try:
        if sys.platform == "darwin":
            output = subprocess.run(
                ["vm_stat"], check=True, capture_output=True, text=True
            ).stdout
            page_size = 4096
            first = output.splitlines()[0]
            if "page size of" in first:
                page_size = int(first.split("page size of", 1)[1].split("bytes", 1)[0])
            free_pages = 0
            for line in output.splitlines()[1:]:
                if line.startswith(
                    ("Pages free", "Pages inactive", "Pages speculative")
                ):
                    free_pages += int(line.rsplit(":", 1)[1].strip().rstrip("."))
            return free_pages * page_size
        pages = os.sysconf("SC_AVPHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if isinstance(pages, int) and isinstance(page_size, int):
            return pages * page_size
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def _sibling_solver_pids() -> tuple[int, ...]:
    try:
        output = subprocess.run(
            ["ps", "-axo", "pid=,args="],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C79RunError("solver process preflight cannot be established") from exc
    current = os.getpid()
    result: list[int] = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        command = parts[1]
        if pid != current and "cadical_o1_joint_score_sieve" in command:
            result.append(pid)
    return tuple(sorted(result))


def _validate_runtime_source_freeze(
    root: Path, *, expected_commit: str, execution_commit: str
) -> None:
    """Reject any post-freeze commit that changes Python/native runtime bytes."""

    expected = _commit_or_pending(expected_commit, "runtime freeze commit")
    execution = _commit_or_pending(execution_commit, "runtime execution commit")
    if "PENDING" in {expected, execution}:
        raise O1C79RunError("runtime source freeze contains PENDING")
    try:
        comparison = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                expected,
                execution,
                "--",
                *SOURCE_FREEZE_GUARD_PATHS,
            ],
            cwd=root,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C79RunError("runtime source freeze cannot be compared") from exc
    if comparison.returncode == 1:
        raise O1C79RunError(
            "Python/native runtime changed after the frozen source commit"
        )
    if comparison.returncode != 0:
        raise O1C79RunError("runtime source freeze comparison failed")


def preflight(
    config_path: str | Path,
    *,
    require_commit_binding: bool = True,
    root: Path | None = None,
) -> dict[str, object]:
    """Fail closed on every frozen source, artifact, gate, and resource."""

    lab = (root or lab_root()).resolve(strict=True)
    config = load_config(config_path, root=lab)
    pending: list[str] = []

    def frozen(value: object, field: str) -> str:
        digest = _digest_or_pending(value, field)
        if digest == "PENDING":
            pending.append(field)
        return digest

    parent = _mapping(config["parent"], "preflight parent")
    parent_result = _relative(lab, parent["result"], "parent result")
    parent_capsule = _relative(lab, parent["capsule"], "parent capsule")
    if (
        _sha256_file(parent_result) != PARENT_RESULT_SHA256
        or _sha256_file(
            _regular(parent_capsule / "artifacts.sha256", "parent manifest")
        )
        != PARENT_MANIFEST_SHA256
    ):
        raise O1C79RunError("O1C78 terminal identity differs")
    preparation = _mapping(config["preparation"], "preflight preparation")
    prepared = load_prepared_decision_ownership(
        _relative(lab, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
    _validate_prepared_contract(prepared)
    inputs = _mapping(config["inputs"], "preflight inputs")
    observed_inputs: dict[str, str] = {}
    for name in ("cnf", "potential", "grouping", "o1c73_config"):
        path = _relative(lab, inputs[name], f"input {name}")
        expected = frozen(inputs[f"{name}_sha256"], f"input {name} digest")
        observed = _sha256_file(path)
        if observed != expected:
            raise O1C79RunError(f"frozen input {name} differs")
        observed_inputs[name] = observed
    source = _mapping(config["source"], "preflight source")
    paths = _mapping(source["paths"], "preflight source paths")
    expected_sources = _mapping(source["expected_sha256"], "source digests")
    observed_sources: dict[str, str] = {}
    for name, relative in paths.items():
        path = _relative(lab, relative, f"source {name}")
        expected = frozen(expected_sources[name], f"source digest {name}")
        observed = _sha256_file(path)
        if observed != expected:
            raise O1C79RunError(f"source {name} differs")
        observed_sources[name] = observed
    expected_commit = _commit_or_pending(source["expected_commit"], "source commit")
    if expected_commit == "PENDING":
        pending.append("source commit")
    native = _mapping(config["native"], "preflight native")
    executable_digest = frozen(
        native["expected_executable_sha256"], "native executable digest"
    )
    frozen(native["expected_source_sha256"], "native source digest")
    gate_config = _mapping(config["target_free_preflight"], "target-free gate")
    gate_digest = frozen(gate_config["sha256"], "target-free gate digest")
    if pending:
        raise O1C79RunError(
            "commit-bound preflight contains PENDING: " + ", ".join(pending)
        )
    executable = lab / _relative_contract(native["executable"], "native executable")
    executable_binding = validate_native_executable(
        executable, expected_sha256=executable_digest
    )
    gate = _validate_target_free_gate(
        _relative(lab, gate_config["path"], "target-free gate"),
        expected_sha256=gate_digest,
        prepared=prepared,
        source_sha256=observed_sources,
    )
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=lab,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=lab,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise O1C79RunError("source commit binding cannot be established") from exc
    if require_commit_binding:
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", expected_commit, commit],
            cwd=lab,
            check=False,
            capture_output=True,
        )
        if ancestor.returncode != 0 or dirty:
            raise O1C79RunError("clean source freeze is not an execution ancestor")
        _validate_runtime_source_freeze(
            lab,
            expected_commit=expected_commit,
            execution_commit=commit,
        )
        for name, relative in paths.items():
            try:
                frozen_blob = subprocess.run(
                    ["git", "show", f"{expected_commit}:{relative}"],
                    cwd=lab,
                    check=True,
                    capture_output=True,
                ).stdout
            except (OSError, subprocess.SubprocessError) as exc:
                raise O1C79RunError("source commit blob binding differs") from exc
            if sha256_bytes(frozen_blob) != observed_sources[name]:
                raise O1C79RunError(f"source {name} differs from frozen commit")
    disk_free = shutil.disk_usage(lab).free
    if disk_free < MINIMUM_DISK_FREE_BYTES:
        raise O1C79RunError("disk resource preflight differs")
    siblings = _sibling_solver_pids()
    if siblings:
        raise O1C79RunError("a sibling solver process is live")
    available_memory = _available_memory_bytes()
    if available_memory is not None and available_memory < MEMORY_LIMIT_BYTES:
        raise O1C79RunError("native memory headroom differs")
    return {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "passed": True,
        "source_freeze_commit": expected_commit,
        "execution_commit": commit,
        "source_clean": not bool(dirty),
        "runtime_source_freeze_guard_paths": list(SOURCE_FREEZE_GUARD_PATHS),
        "runtime_source_bytes_changed_after_freeze": False,
        "source_sha256": observed_sources,
        "native_source_closure_sha256": _native_source_closure_sha256(observed_sources),
        "decision_ownership_header_sha256": observed_sources[
            "decision_ownership_header"
        ],
        "input_sha256": observed_inputs,
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "page6_sha256": prepared.state.active_projection.sha256,
        "frontier_plan_sha256": prepared.frontier_plan.sha256,
        "staging_plan_sha256": prepared.staging_plan.sha256,
        "prefix_plan_sha256": prepared.prefix_plan.sha256,
        "science_input_sha256": sha256_bytes(
            canonical_json_bytes(prepared.science_input)
        ),
        "target_free_preflight_sha256": gate_digest,
        "target_free_preflight": gate,
        "native_executable": executable_binding,
        "disk_free_bytes": disk_free,
        "available_memory_bytes": available_memory,
        "sibling_solver_pids": [],
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _remove_partial_publication(
    capsule: Path, source_result: Mapping[str, object]
) -> None:
    """Remove only verified, owned terminal markers after interrupted publish."""

    markers = (
        capsule / "RUN.md",
        capsule / "result.json",
        capsule / "artifacts.sha256",
    )
    if not any(path.exists() for path in markers) or all(
        path.exists() for path in markers
    ):
        return
    _, result_payload, run_payload, manifest_payload, _ = _publication_payloads(
        capsule, source_result
    )
    expected = {
        "RUN.md": run_payload,
        "result.json": result_payload,
        "artifacts.sha256": manifest_payload,
    }
    # Validate every present marker before removing any of them.  This keeps a
    # foreign partial publication fail-closed without destroying evidence.
    for path in markers:
        if not path.exists():
            continue
        if _regular(path, "partial publication").read_bytes() != expected[path.name]:
            raise O1C79RunError(f"partial publication {path.name} differs")
    capsule.chmod(0o755)
    for path in markers:
        if not path.exists():
            continue
        path.chmod(0o644)
        path.unlink()


def run(config_path: str | Path = CONFIG_RELATIVE) -> dict[str, object]:
    """Execute, recover, or republish the frozen straight O1C-0079 call."""

    root = lab_root().resolve(strict=True)
    authoritative = root / RESULT_RELATIVE
    existing = _existing_authoritative(authoritative)
    if existing is not None:
        return existing
    capsules = sorted(
        path for path in (root / "runs").glob(f"*_{CAPSULE_SUFFIX}") if path.is_dir()
    )
    if capsules:
        if len(capsules) != 1:
            raise O1C79RunError("multiple O1C79 capsules block replay")
        capsule = capsules[0]
        if all(
            (capsule / name).is_file()
            for name in ("RUN.md", "result.json", "artifacts.sha256")
        ):
            return _republish_sealed_capsule(capsule, authoritative)
        if (capsule / PUBLICATION_RECOVERY_NAME).is_file():
            recovered = _read_recovered_publication_source(capsule)
            _remove_partial_publication(capsule, recovered)
            finalize_capsule(capsule, authoritative, recovered)
            return recovered
        source = _read_json(capsule / RECOVERY_SOURCE_NAME, "recovery source")
        source_result = _mapping(
            source.get("pre_finalization_result"), "partial publication result"
        )
        _remove_partial_publication(capsule, source_result)
        recovered = recover_publication(capsule)
        write_recovered_publication_source(capsule, recovered)
        finalize_capsule(capsule, authoritative, recovered)
        return recovered

    config_file = Path(config_path).resolve(strict=True)
    preflight_row = preflight(config_file, require_commit_binding=True, root=root)
    config = load_config(config_file, root=root)
    preparation = _mapping(config["preparation"], "run preparation")
    prepared = load_prepared_decision_ownership(
        _relative(root, preparation["directory"], "prepared directory"),
        expected_manifest_sha256=cast(str, preparation["manifest_sha256"]),
    )
    _validate_prepared_contract(prepared)
    inputs = _mapping(config["inputs"], "run inputs")
    cnf = _relative(root, inputs["cnf"], "run CNF")
    potential = _relative(root, inputs["potential"], "run potential")
    grouping = _relative(root, inputs["grouping"], "run grouping")
    baseline_config = _o1c73.load_config(
        _relative(root, inputs["o1c73_config"], "run O1C73 config")
    )
    baseline = _o1c73.validate_apple8_baseline(root, baseline_config)
    public_target = _o1c73._o1c66._public_target(baseline)
    native = _mapping(config["native"], "run native")
    source_config = _mapping(config["source"], "run source freeze")
    source_digests = _mapping(source_config["expected_sha256"], "run source digests")
    executable = root / _relative_contract(native["executable"], "native executable")
    executable_binding = validate_native_executable(
        executable,
        expected_sha256=cast(str, native["expected_executable_sha256"]),
    )
    if executable_binding != preflight_row.get("native_executable"):
        raise O1C79RunError("post-preflight native executable differs")
    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    cpu_started = time.process_time()
    child_started = resource.getrusage(resource.RUSAGE_CHILDREN)
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    capsule_relative = Path("runs") / f"{stamp}_{CAPSULE_SUFFIX}"
    capsule = root / capsule_relative
    capsule.mkdir(parents=True, exist_ok=False)
    _atomic_create(capsule / "config.json", config_file.read_bytes(), immutable=True)
    _atomic_json(capsule / "preflight.json", preflight_row, immutable=True)
    _atomic_json(
        capsule / "native-build.json",
        {
            "source": native["source"],
            "source_sha256": native["expected_source_sha256"],
            "decision_ownership_header_sha256": native[
                "decision_ownership_header_sha256"
            ],
            "source_closure_schema": NATIVE_SOURCE_CLOSURE_SCHEMA,
            "source_closure_names": list(NATIVE_INCLUDE_CLOSURE),
            "source_closure_sha256": native["source_closure_sha256"],
            "source_closure_files": [
                {
                    "path": SOURCE_PATHS[name],
                    "sha256": source_digests[name],
                }
                for name in NATIVE_INCLUDE_CLOSURE
            ],
            "executable": executable_binding,
            "adapter_schema": native["adapter_schema"],
            "result_schema": native["result_schema"],
            "active_vault_sha256": PAGE6_SHA256,
            "frontier_plan_sha256": FRONTIER_PLAN_BINARY_SHA256,
            "staging_plan_sha256": STAGING_PLAN_BINARY_SHA256,
            "prefix_plan_sha256": PREFIX_PLAN_BINARY_SHA256,
            "fixed_output_path_reproducibility_required": True,
        },
        immutable=True,
    )
    bindings = {
        "source_freeze_commit": preflight_row["source_freeze_commit"],
        "execution_commit": preflight_row["execution_commit"],
        "config_sha256": _sha256_file(config_file),
        "native_executable": executable_binding,
        "native_adapter_schema": native["adapter_schema"],
        "native_result_schema": native["result_schema"],
        "native_source_closure_sha256": preflight_row["native_source_closure_sha256"],
        "decision_ownership_header_sha256": preflight_row[
            "decision_ownership_header_sha256"
        ],
        "prepared_manifest_sha256": prepared.manifest_sha256,
        "page6_sha256": PAGE6_SHA256,
        "frontier_plan_sha256": prepared.frontier_plan.sha256,
        "staging_plan_sha256": prepared.staging_plan.sha256,
        "prefix_plan_sha256": prepared.prefix_plan.sha256,
        "science_input_sha256": EXPECTED_SCIENCE_INPUT_SHA256,
        "target_free_preflight_sha256": preflight_row["target_free_preflight_sha256"],
        "truth_key_bytes_read": False,
    }

    def invoke(
        local: int,
        lineage: int,
        rank_vault: Path,
        active_vault: Path,
        frontier_plan: Path,
        staging_plan: Path,
        prefix_plan: Path,
    ) -> object:
        if (
            (local, lineage) != (0, 19)
            or _sha256_file(rank_vault) != RANK_SOURCE_SHA256
            or _sha256_file(active_vault) != PAGE6_SHA256
            or _sha256_file(frontier_plan) != FRONTIER_PLAN_BINARY_SHA256
            or _sha256_file(staging_plan) != STAGING_PLAN_BINARY_SHA256
            or _sha256_file(prefix_plan) != PREFIX_PLAN_BINARY_SHA256
        ):
            raise O1C79RunError("native Page-6 invocation identity differs")
        return _native_v20.run_joint_score_sieve(
            executable=executable,
            cnf_path=cnf,
            potential_path=potential,
            grouping_path=grouping,
            rank_vault_path=rank_vault,
            vault_path=active_vault,
            frontier_plan_path=frontier_plan,
            staging_plan_path=staging_plan,
            prefix_plan_path=prefix_plan,
            vault_caps=O1C66_VAULT_CAPS,
            threshold=THRESHOLD,
            conflict_limit=REQUESTED_CONFLICTS_PER_EPISODE,
            seed=SEED,
            timeout_seconds=TIMEOUT_SECONDS,
            memory_limit_bytes=MEMORY_LIMIT_BYTES,
        )

    outcome = execute_episode(
        capsule=capsule,
        prepared=prepared,
        invoke_episode=invoke,
        verify_public_model=public_target.verify,
        bindings=bindings,
    )
    result = build_result(
        outcome=outcome,
        capsule_relative=capsule_relative.as_posix(),
        source_commit=cast(str, preflight_row["execution_commit"]),
        preflight=preflight_row,
        started_at=started_at,
        runtime=cast(
            Mapping[str, object],
            _translate_technical(
                lambda: _o1c78_runtime_resources(
                    started=started,
                    cpu_started=cpu_started,
                    child_started=child_started,
                )
            ),
        ),
    )
    write_recovery_source(capsule, result)
    finalize_capsule(capsule, authoritative, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight, run, or recover O1C79's one ownership call"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "run"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", default=str(CONFIG_RELATIVE))
    recovery = subparsers.add_parser("recover")
    recovery.add_argument("--capsule", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "preflight":
            value = preflight(args.config)
        elif args.command == "run":
            value = run(args.config)
        else:
            root = lab_root().resolve(strict=True)
            capsule = Path(args.capsule).resolve(strict=True)
            if not capsule.is_relative_to(root / "runs"):
                raise O1C79RunError("recovery capsule escapes run root")
            value = recover_publication(capsule)
            finalize_capsule(capsule, root / RESULT_RELATIVE, value)
        sys.stdout.buffer.write(canonical_json_bytes(value))
        return 0
    except O1C79RunError as exc:
        print(f"O1C79: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
