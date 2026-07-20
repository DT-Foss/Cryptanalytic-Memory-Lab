"""Zero-call O1C-0096 Page-16 transport-recovery preparation.

O1C-0095 persisted intent and therefore burned Page 15 / lineage 28.  The
native process returned JSON with status zero, but adapter v29 rejected the
``priority_seed`` field contract before returning a native result to the
runner.  There is consequently no O1C-0095 scientific evidence or live state
update to import.

This module validates that exact sealed terminal boundary, regenerates the
last certified O1C-0093 Page-15 state, and reprojects its immutable 18-chunk
attic to a fresh 251-clause Page 16 / lineage 29.  It has no native, solver,
target, truth-key, model, or reveal interface.  Publication is a separate
atomic operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c85_page10_transport_recovery_prepare as _publisher
from . import o1c93_page15_causal_rollover_prepare as _o1c93
from .causal_attic_v1 import CausalAtticError, canonical_json_bytes, sha256_bytes
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    replay_causal_residency,
    reproject_causal_residency,
    validate_activation_replay,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0096"
PARENT_ATTEMPT_ID = "O1C-0095"
PREPARATION_SCHEMA = "o1-256-o1c96-page16-transport-recovery-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_220052_433697_O1C-0095_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0095_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "10c2b0f2f2745bb2a101c116d1ecf9af5c090cf627bf334d96f01e46998d26a6"
)
PARENT_CAPSULE_MANIFEST_BYTES = 1_883
PARENT_CAPSULE_ENTRY_COUNT = 20
PARENT_RESULT_SHA256 = (
    "7838ce882a696ce932b36fa11af190aaff0ee0a7673e12bbfdac1b272b2e8c93"
)
PARENT_RESULT_BYTES = 10_003
PARENT_EPISODE_SHA256 = (
    "5ad97694c28ae94e2ebfa7ef1f07f8d57e6d8801b351990c63b4679132a0e45f"
)
PARENT_EPISODE_BYTES = 1_835
PARENT_INTENT_SHA256 = (
    "089d65e7270f579c78d5d4ac15d1987cc18d82566ed233039d9e2030b3cb0bad"
)
PARENT_INTENT_BYTES = 1_320
PARENT_FAILURE_SHA256 = (
    "88c95c6aabf1c3877c9d026fb0d03bf037fb5efd38ddb3ebbc2826dfe1efe5a6"
)
PARENT_FAILURE_BYTES = 831
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
PARENT_STOP_REASON = "burned-terminal-failure-no-retry"
PARENT_REQUESTED_CONFLICTS = 128

O1C93_PREPARATION_MANIFEST_SHA256 = _o1c93.PREPARATION_MANIFEST_SHA256
O1C93_PREPARATION_MANIFEST_BYTES = _o1c93.PREPARATION_MANIFEST_BYTES
O1C93_INITIAL_ARTIFACT_COUNT = 10

CONTINUATION_BANK_SHA256 = _o1c93.FINAL_BANK_SHA256
CONTINUATION_BANK_BYTES = _o1c93.FINAL_BANK_BYTES
PRIORITY_RECEIPT_SHA256 = _o1c93.PRIORITY_RECEIPT_SHA256
PRIORITY_RECEIPT_BYTES = _o1c93.PRIORITY_RECEIPT_BYTES

ATTIC_CHUNK_COUNT = _o1c93.ATTIC_CHUNK_COUNT
ATTIC_UNION_SHA256 = _o1c93.ATTIC_UNION_SHA256
ATTIC_UNION_CLAUSE_COUNT = _o1c93.ATTIC_UNION_CLAUSE_COUNT
ATTIC_UNION_LITERAL_COUNT = _o1c93.ATTIC_UNION_LITERAL_COUNT
ATTIC_UNION_SERIALIZED_BYTES = _o1c93.ATTIC_UNION_SERIALIZED_BYTES
ATTIC_OCCURRENCE_COUNT = _o1c93.ATTIC_OCCURRENCE_COUNT
ATTIC_DUPLICATE_OCCURRENCE_COUNT = _o1c93.ATTIC_DUPLICATE_OCCURRENCE_COUNT
ATTIC_SUBSUMPTION_RELATION_COUNT = _o1c93.ATTIC_SUBSUMPTION_RELATION_COUNT
ATTIC_UNDOMINATED_CLAUSE_COUNT = _o1c93.ATTIC_UNDOMINATED_CLAUSE_COUNT

PAGE16_SHA256 = "fb3b56690ec4f50d699c2598dd4fa752376d1609d1e242ee8aa987694cdc48f5"
PAGE16_CLAUSE_COUNT = 251
PAGE16_LITERAL_COUNT = 707_566
PAGE16_SERIALIZED_BYTES = 2_831_459
PAGE16_ACTIVE_LIMIT = 251
PAGE16_LINEAGE_ORDINAL = 29
PAGE16_CATEGORY_COUNTS = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 167,
    "hot_event": 0,
    "recycled": 32,
}
PAGE16_HEADROOM = {
    "clauses": 261,
    "literals": 892_434,
    "serialized_bytes": 5_557_149,
}
PAGE16_RESIDENCY_DOCUMENT_SHA256 = (
    "6fb238a9b3f46f60dbdd0bcd0012bd1b99b5d900fc6970bd6e53499b8d59428d"
)
PAGE16_RESIDENCY_DOCUMENT_BYTES = 55_433
PAGE16_ACTIVATION_DOCUMENT_SHA256 = (
    "0b63a784761b38e22eba589f09df9abe1cd2ba9e12eab7d36210cc8ace77c437"
)
PAGE16_ACTIVATION_DOCUMENT_BYTES = 33_135
PAGE16_ACTIVATION_COUNT = 17
PAGE16_SELECTED_INDICES_SHA256 = (
    "27f64155956dea34b73a26808aca324b60550908a43a2ebd9cc23ef889c77166"
)
PAGE16_SELECTION_ORDER_SHA256 = (
    "3337fc6f229c2bbbd503d5c1ab880eaf4c7e20dccaf5bcfa36c4a9808e557b42"
)

ACTIVE_PROJECTION_NAME = "page-16-active.bin"
RESIDENCY_NAME = _o1c93.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c93.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c93.OCCURRENCES_NAME
RELATIONS_NAME = _o1c93.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c93.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c93.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = _o1c93.PRIORITY_RECEIPT_NAME
FAILURE_RECEIPT_NAME = "o1c95-terminal-failure-receipt.json"
PREPARATION_MANIFEST_NAME = "transport-recovery-preparation-manifest.json"

PREPARATION_MANIFEST_SHA256 = (
    "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
)
PREPARATION_MANIFEST_BYTES = 6_414

PreparedCausalRolloverArtifacts = _o1c93.PreparedCausalRolloverArtifacts


class O1C96PreparationError(RuntimeError):
    """An O1C-0095 seal or deterministic Page-16 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C96PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C96PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C96PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C96PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C96PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C96PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C96PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C96PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C96PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        parts = Path(relative).parts
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in parts
            or relative in entries
        ):
            raise O1C96PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C96PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C96PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C96PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C96PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C96PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C96PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/terminal-failure.json": PARENT_FAILURE_SHA256,
        f"initial/{_o1c93.PREPARATION_MANIFEST_NAME}": (
            O1C93_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c93.ACTIVE_PROJECTION_NAME}": _o1c93.PAGE15_SHA256,
        f"initial/{FINAL_BANK_NAME}": CONTINUATION_BANK_SHA256,
        f"initial/{PRIORITY_RECEIPT_NAME}": PRIORITY_RECEIPT_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C96PreparationError("parent capsule required seal differs")
    forbidden = {
        "episodes/00/native-result.json",
        "episodes/00/native-stdout.json",
        "episodes/00/priority-state.json",
        "episodes/00/final-parent-centered-priority-bank.bin",
        "episodes/00/vault.json",
    }
    if forbidden.intersection(entries):
        raise O1C96PreparationError("parent capsule unexpectedly updated state")
    return entries


def _validate_parent_result(
    capsule: Path, result_path: Path
) -> tuple[Mapping[str, object], bytes]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
        failure_payload = (capsule / "episodes/00/terminal-failure.json").read_bytes()
    except OSError as exc:
        raise O1C96PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
        or len(failure_payload) != PARENT_FAILURE_BYTES
        or sha256_bytes(failure_payload) != PARENT_FAILURE_SHA256
    ):
        raise O1C96PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    failure = _canonical_document(failure_payload, "parent terminal failure")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C96PreparationError("parent terminal contract differs")
    episode = _mapping(episodes[0], "parent result episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    resources = _mapping(result.get("resources"), "parent resources")
    science = _mapping(episode.get("science"), "parent science")
    operational = _mapping(episode.get("operational"), "parent operational state")
    nested_failure = _mapping(
        episode.get("terminal_failure"), "parent nested terminal failure"
    )
    replay_fields = (
        "page10_replay_authorized",
        "page11_replay_authorized",
        "page12_replay_authorized",
        "page13_replay_authorized",
        "page14_replay_authorized",
        "page9_retry_or_replay_authorized",
    )
    if (
        episode_document != episode
        or nested_failure != failure
        or result.get("schema")
        != "o1-256-apple8-parent-centered-continuation-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("stop_reason") != PARENT_STOP_REASON
        or result.get("science_gain") is not False
        or result.get("operational_activation") is not False
        or claim.get("page15_burned") is not True
        or claim.get("lineage28_only") is not True
        or claim.get("retry_or_replay") is not False
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("page15_sha256") != _o1c93.PAGE15_SHA256
        or claim.get("input_continuation_bank_sha256")
        != CONTINUATION_BANK_SHA256
        or claim.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or claim.get("rollover_manifest_sha256")
        != O1C93_PREPARATION_MANIFEST_SHA256
        or claim.get("global_novelty_baseline_clause_count")
        != ATTIC_UNION_CLAUSE_COUNT
        or any(claim.get(field) is not False for field in replay_fields)
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("completed") is not False
        or episode.get("lineage_call_ordinal") != 28
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page15_burned") is not True
        or episode.get("lineage28_burned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or any(episode.get(field) is not False for field in replay_fields)
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not False
        or episode.get("native_stdout") is not None
        or episode.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("actual_conflicts") is not None
        or episode.get("billed_conflicts") is not None
        or science != {"science_gain": False}
        or operational != {"operational_activation": False}
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or resources.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or resources.get("native_solver_calls") != 1
        or resources.get("actual_conflicts") is not None
        or resources.get("billed_conflicts") is not None
        or failure.get("schema")
        != "o1-256-apple8-parent-centered-continuation-terminal-failure-v1"
        or failure.get("classification") != PARENT_CLASSIFICATION
        or failure.get("exception_type") != "JointScoreSieveExecutionError"
        or failure.get("message")
        != "joint-score-sieve-v29 priority seed fields differs"
        or failure.get("phase") != "CALL"
        or failure.get("occurred_after_persisted_intent") is not True
        or failure.get("native_call_issued") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("native_result_returned") is not False
        or failure.get("native_process_evidence") is not None
        or failure.get("requested_conflicts_consumed")
        != PARENT_REQUESTED_CONFLICTS
        or failure.get("actual_conflicts") is not None
        or failure.get("billed_conflicts") is not None
        or failure.get("science_gain") is not False
        or failure.get("page15_burned") is not True
        or failure.get("lineage28_burned") is not True
        or failure.get("retry_authorized") is not False
        or failure.get("replay_authorized") is not False
        or any(failure.get(field) is not False for field in replay_fields)
    ):
        raise O1C96PreparationError("parent terminal contract differs")

    if (
        intent.get("schema")
        != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("lineage_call_ordinal") != 28
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page15_burned") is not True
        or intent.get("lineage28_burned") is not True
        or intent.get("page15_sha256") != _o1c93.PAGE15_SHA256
        or intent.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or intent.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or intent.get("rollover_manifest_sha256")
        != O1C93_PREPARATION_MANIFEST_SHA256
        or intent.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or any(intent.get(field) is not False for field in replay_fields)
        or intent.get("target_bytes_read") is not False
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("invocation_sha256") != episode.get("invocation_sha256")
    ):
        raise O1C96PreparationError("parent persisted intent contract differs")
    return result, failure_payload


def _regenerate_o1c93_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        prior = _o1c93.prepare_o1c93_page15_causal_rollover()
    except (
        OSError,
        RuntimeError,
        CausalAtticError,
        CausalResidencyError,
    ) as exc:
        raise O1C96PreparationError("O1C-0093 regeneration differs") from exc
    initial = capsule / "initial"
    expected_names = set(prior.artifacts)
    if (
        len(expected_names) != O1C93_INITIAL_ARTIFACT_COUNT
        or expected_names
        != {
            _o1c93.NEW_CHUNK_NAME,
            _o1c93.ACTIVE_PROJECTION_NAME,
            _o1c93.RESIDENCY_NAME,
            _o1c93.ACTIVATION_LEDGER_NAME,
            _o1c93.OCCURRENCES_NAME,
            _o1c93.RELATIONS_NAME,
            _o1c93.COMMON_CORE_AUDIT_NAME,
            _o1c93.FINAL_BANK_NAME,
            _o1c93.PRIORITY_RECEIPT_NAME,
            _o1c93.PREPARATION_MANIFEST_NAME,
        }
    ):
        raise O1C96PreparationError("O1C-0093 regenerated inventory differs")
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C96PreparationError("parent initial inventory is unreadable") from exc
    if {path.name for path in initial_children} != expected_names:
        raise O1C96PreparationError("parent initial inventory differs")
    for name, expected in prior.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C96PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C96PreparationError("parent initial artifact differs")
    if (
        len(prior.artifacts[_o1c93.PREPARATION_MANIFEST_NAME])
        != O1C93_PREPARATION_MANIFEST_BYTES
        or sha256_bytes(prior.artifacts[_o1c93.PREPARATION_MANIFEST_NAME])
        != O1C93_PREPARATION_MANIFEST_SHA256
        or len(prior.artifacts[FINAL_BANK_NAME]) != CONTINUATION_BANK_BYTES
        or sha256_bytes(prior.artifacts[FINAL_BANK_NAME])
        != CONTINUATION_BANK_SHA256
        or len(prior.artifacts[PRIORITY_RECEIPT_NAME]) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(prior.artifacts[PRIORITY_RECEIPT_NAME])
        != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C96PreparationError("unchanged certified continuation state differs")
    return prior


def _reproject_page16(
    previous: PreparedCausalRolloverArtifacts,
) -> CausalResidencyState:
    prior = previous.state
    prior_attic = prior.attic
    try:
        state = reproject_causal_residency(
            prior_attic,
            previous_state=prior,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=PAGE16_LINEAGE_ORDINAL,
            next_active_limit=PAGE16_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C96PreparationError("Page-16 transport recovery differs") from exc
    page = state.active_projection
    residency_payload = canonical_json_bytes(state.describe())
    activation_payload = canonical_json_bytes(state.activation_ledger_document())
    selected_payload = canonical_json_bytes(
        list(state.current_projection.selected_union_indices)
    )
    order_payload = canonical_json_bytes(list(state.current_projection.selection_order))
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - page.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - page.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - page.serialized_bytes,
    }
    same_evidence = (
        state.attic.chunks == prior_attic.chunks
        and state.attic.union_vault == prior_attic.union_vault
        and state.attic.occurrences == prior_attic.occurrences
        and state.attic.chunk_clause_union_indices
        == prior_attic.chunk_clause_union_indices
        and state.attic.occurrence_union_indices == prior_attic.occurrence_union_indices
        and state.attic.relations == prior_attic.relations
        and state.attic.undominated_indices == prior_attic.undominated_indices
    )
    if (
        roundtrip != page
        or replayed != state
        or not same_evidence
        or state.current_projection.lineage_ordinal != PAGE16_LINEAGE_ORDINAL
        or state.active_limit != PAGE16_ACTIVE_LIMIT
        or state.attic.active_limit != PAGE16_ACTIVE_LIMIT
        or page.sha256 != PAGE16_SHA256
        or page.clause_count != PAGE16_CLAUSE_COUNT
        or page.literal_count != PAGE16_LITERAL_COUNT
        or page.serialized_bytes != PAGE16_SERIALIZED_BYTES
        or state.current_projection.category_counts != PAGE16_CATEGORY_COUNTS
        or headroom != PAGE16_HEADROOM
        or len(residency_payload) != PAGE16_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE16_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE16_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE16_ACTIVATION_DOCUMENT_SHA256
        or sha256_bytes(selected_payload) != PAGE16_SELECTED_INDICES_SHA256
        or sha256_bytes(order_payload) != PAGE16_SELECTION_ORDER_SHA256
        or state.activation_ledger[:-1] != prior.activation_ledger
        or state.used_active_sha256[:-1] != prior.used_active_sha256
        or len(state.activation_ledger) != PAGE16_ACTIVATION_COUNT
        or len(state.activation_ledger) != len(prior.activation_ledger) + 1
        or page.sha256 in prior.used_active_sha256
        or len(prior.never_resident_undominated_indices) != 167
        or set(state.current_projection.new_debt_indices)
        != set(prior.never_resident_undominated_indices)
        or state.never_resident_undominated_indices
        or len(state.current_projection.recycled_indices) != 32
        or len(state.attic.chunks) != ATTIC_CHUNK_COUNT
        or state.attic.union_vault.sha256 != ATTIC_UNION_SHA256
        or state.attic.union_vault.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or state.attic.union_vault.literal_count != ATTIC_UNION_LITERAL_COUNT
        or state.attic.union_vault.serialized_bytes
        != ATTIC_UNION_SERIALIZED_BYTES
        or len(state.attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or state.attic.duplicate_occurrence_count
        != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or len(state.attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(state.attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
    ):
        raise O1C96PreparationError("Page-16 transport recovery contract differs")
    return state


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c96_page16_transport_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate burned O1C-0095 and return a fresh Page-16 bundle in memory."""

    root = lab_root()
    capsule_value = (
        (root / DEFAULT_PARENT_CAPSULE_RELATIVE).resolve()
        if capsule_dir is None
        else capsule_dir
    )
    result_value = (
        (root / DEFAULT_PARENT_RESULT_RELATIVE).resolve()
        if parent_result_path is None
        else parent_result_path
    )
    capsule = _canonical_path(capsule_value, "parent capsule", directory=True)
    result_path = _canonical_path(result_value, "parent result", directory=False)
    entries = _validate_capsule_inventory(capsule)
    _parent_result, failure_payload = _validate_parent_result(capsule, result_path)
    previous = _regenerate_o1c93_and_validate_initial(capsule)
    state = _reproject_page16(previous)

    occurrence_payload = previous.artifacts[OCCURRENCES_NAME]
    relation_payload = previous.artifacts[RELATIONS_NAME]
    audit_payload = previous.artifacts[COMMON_CORE_AUDIT_NAME]
    bank = previous.artifacts[FINAL_BANK_NAME]
    priority_receipt = previous.artifacts[PRIORITY_RECEIPT_NAME]
    continuation = _mapping(
        previous.manifest.get("final_priority_bank"),
        "O1C-0093 continuation bank",
    )
    if (
        occurrence_payload != canonical_json_bytes(state.attic.occurrence_document())
        or relation_payload != canonical_json_bytes(state.attic.relation_document())
        or audit_payload
        != (capsule / "initial" / COMMON_CORE_AUDIT_NAME).read_bytes()
        or bank != (capsule / "initial" / FINAL_BANK_NAME).read_bytes()
        or priority_receipt
        != (capsule / "initial" / PRIORITY_RECEIPT_NAME).read_bytes()
        or continuation.get("sha256") != CONTINUATION_BANK_SHA256
        or continuation.get("receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or continuation.get("receipt_bank_hex_byte_equal") is not True
    ):
        raise O1C96PreparationError("unchanged transport artifact differs")

    artifacts: dict[str, bytes] = {
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        OCCURRENCES_NAME: occurrence_payload,
        RELATIONS_NAME: relation_payload,
        COMMON_CORE_AUDIT_NAME: audit_payload,
        FINAL_BANK_NAME: bank,
        PRIORITY_RECEIPT_NAME: priority_receipt,
        FAILURE_RECEIPT_NAME: failure_payload,
    }
    roles = {
        ACTIVE_PROJECTION_NAME: "fresh-lineage-29-page16-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "unchanged-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "unchanged-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "unchanged-sealed-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "unchanged-canonical-o1c92-priority-state-receipt",
        FAILURE_RECEIPT_NAME: "canonical-o1c95-terminal-failure-receipt",
    }
    manifest: dict[str, object] = {
        "schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "native_preflight_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
        },
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page16_burned": False,
            "lineage29_burned": False,
            "page15_retry_or_replay_authorized": False,
            "lineage28_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        },
        "parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_manifest_serialized_bytes": PARENT_CAPSULE_MANIFEST_BYTES,
            "capsule_entry_count": len(entries),
            "result_sha256": PARENT_RESULT_SHA256,
            "result_serialized_bytes": PARENT_RESULT_BYTES,
            "episode_sha256": PARENT_EPISODE_SHA256,
            "intent_sha256": PARENT_INTENT_SHA256,
            "terminal_failure_sha256": PARENT_FAILURE_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "failure_reason": "adapter-v29-priority-seed-fields-mismatch",
            "native_process_returncode_zero_before_adapter_validation": True,
            "native_json_discarded_before_runner_result": True,
            "page15_burned": True,
            "lineage28_burned": True,
            "native_result_returned_to_runner": False,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "science_gain": False,
            "state_update_available": False,
            "initial_o1c93_artifact_count": O1C93_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_regeneration": True,
            "priority_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "priority_receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        },
        "science_boundary": {
            "imported_science_attempt_id": None,
            "imported_clause_count": 0,
            "imported_priority_state_update": False,
            "o1c95_terminal_failure_imported_as_science": False,
            "o1c95_native_json_imported": False,
            "o1c95_output_artifacts_imported": [],
        },
        "transport_recovery": {
            "source_lineage_ordinal": 28,
            "next_lineage_ordinal": PAGE16_LINEAGE_ORDINAL,
            "fully_emitted_event_count": 0,
            "new_chunk_count": 0,
            "attic_evidence_unchanged": True,
            "occurrence_ledger_unchanged": True,
            "relation_ledger_unchanged": True,
            "common_core_audit_unchanged": True,
            "continuation_bank_unchanged": True,
            "priority_receipt_unchanged": True,
            "api": (
                "reproject_causal_residency(same_attic,"
                "fully_emitted_union_indices=(),next_lineage_ordinal=29,"
                "next_active_limit=251)"
            ),
        },
        "attic": {
            "chunk_count": len(state.attic.chunks),
            "union_sha256": state.attic.union_vault.sha256,
            "union_clause_count": state.attic.union_vault.clause_count,
            "union_literal_count": state.attic.union_vault.literal_count,
            "union_serialized_bytes": state.attic.union_vault.serialized_bytes,
            "occurrence_count": len(state.attic.occurrences),
            "duplicate_occurrence_count": state.attic.duplicate_occurrence_count,
            "strict_subsumption_pair_count": len(state.attic.relations),
            "undominated_clause_count": len(state.attic.undominated_indices),
            "byte_and_relation_equal_to_o1c93": True,
        },
        "page16": {
            "lineage_ordinal": PAGE16_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "selected_union_indices_sha256": PAGE16_SELECTED_INDICES_SHA256,
            "selection_order_sha256": PAGE16_SELECTION_ORDER_SHA256,
            "headroom": PAGE16_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
            "activation_ledger_prior_entry_count": len(
                previous.state.activation_ledger
            ),
            "activation_ledger_next_entry_count": len(state.activation_ledger),
            "activation_entries_added": 1,
            "debt_completion": {
                "prior_never_resident_undominated_clause_count": len(
                    previous.state.never_resident_undominated_indices
                ),
                "admitted_as_new_debt_clause_count": len(
                    state.current_projection.new_debt_indices
                ),
                "remaining_never_resident_undominated_clause_count": len(
                    state.never_resident_undominated_indices
                ),
                "recycled_clause_count": len(
                    state.current_projection.recycled_indices
                ),
                "all_prior_debt_admitted": True,
            },
        },
        "final_priority_bank": {
            **dict(continuation),
            "sha256": CONTINUATION_BANK_SHA256,
            "serialized_bytes": CONTINUATION_BANK_BYTES,
            "receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
            "priority_is_key_bit_belief": False,
            "semantic_role": "unchanged-sealed-live-continuation-bytes",
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    if (
        _canonical_document(manifest_payload, "transport recovery manifest")
        != manifest
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
    ):
        raise O1C96PreparationError(
            "transport recovery manifest differs: "
            f"bytes={len(manifest_payload)}, sha256={sha256_bytes(manifest_payload)}"
        )
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c96_page16_transport_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c96_page16_transport_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C96PreparationError("prepared Page-16 bundle differs")
    expected_names = {
        ACTIVE_PROJECTION_NAME,
        RESIDENCY_NAME,
        ACTIVATION_LEDGER_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        COMMON_CORE_AUDIT_NAME,
        FINAL_BANK_NAME,
        PRIORITY_RECEIPT_NAME,
        FAILURE_RECEIPT_NAME,
        PREPARATION_MANIFEST_NAME,
    }
    manifest = _mapping(prepared.manifest, "prepared Page-16 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-16 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        ACTIVE_PROJECTION_NAME: (PAGE16_SERIALIZED_BYTES, PAGE16_SHA256),
        RESIDENCY_NAME: (
            PAGE16_RESIDENCY_DOCUMENT_BYTES,
            PAGE16_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE16_ACTIVATION_DOCUMENT_BYTES,
            PAGE16_ACTIVATION_DOCUMENT_SHA256,
        ),
        OCCURRENCES_NAME: (
            _o1c93.OCCURRENCE_DOCUMENT_BYTES,
            _o1c93.OCCURRENCE_DOCUMENT_SHA256,
        ),
        RELATIONS_NAME: (
            _o1c93.RELATION_DOCUMENT_BYTES,
            _o1c93.RELATION_DOCUMENT_SHA256,
        ),
        COMMON_CORE_AUDIT_NAME: (
            _o1c93.COMMON_CORE_AUDIT_BYTES,
            _o1c93.COMMON_CORE_AUDIT_SHA256,
        ),
        FINAL_BANK_NAME: (CONTINUATION_BANK_BYTES, CONTINUATION_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
        FAILURE_RECEIPT_NAME: (PARENT_FAILURE_BYTES, PARENT_FAILURE_SHA256),
    }
    if (
        set(prepared.artifacts) != expected_names
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest_payload != canonical_json_bytes(manifest)
        or not isinstance(manifest_payload, bytes)
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
        or set(rows) != expected_names - {PREPARATION_MANIFEST_NAME}
        or prepared.state.active_projection.sha256 != PAGE16_SHA256
        or prepared.artifacts.get(ACTIVE_PROJECTION_NAME)
        != prepared.state.active_projection.serialized
        or prepared.artifacts.get(RESIDENCY_NAME)
        != canonical_json_bytes(prepared.state.describe())
        or prepared.artifacts.get(ACTIVATION_LEDGER_NAME)
        != canonical_json_bytes(prepared.state.activation_ledger_document())
        or prepared.artifacts.get(OCCURRENCES_NAME)
        != canonical_json_bytes(prepared.state.attic.occurrence_document())
        or prepared.artifacts.get(RELATIONS_NAME)
        != canonical_json_bytes(prepared.state.attic.relation_document())
    ):
        raise O1C96PreparationError("prepared Page-16 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C96PreparationError("prepared Page-16 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-16 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C96PreparationError("prepared Page-16 artifact seal differs")


def write_prepared_o1c96_page16_transport_recovery(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-16 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(
            prepared, output_dir
        )
    except _publisher.O1C85PreparationError as exc:
        raise O1C96PreparationError("Page-16 publication failed") from exc


def prepare_and_write_o1c96_page16_transport_recovery(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-16 bundle."""

    prepared = prepare_o1c96_page16_transport_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c96_page16_transport_recovery(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0096's zero-call Page-16 recovery"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--capsule", default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix()
        )
        child.add_argument(
            "--parent-result",
            default=(root / DEFAULT_PARENT_RESULT_RELATIVE).as_posix(),
        )
        if command == "prepare":
            child.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prepared = prepare_o1c96_page16_transport_recovery(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c96_page16_transport_recovery(
                prepared, args.output_dir
            )
    except (
        O1C96PreparationError,
        CausalAtticError,
        CausalResidencyError,
    ) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(prepared.manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "ATTEMPT_ID",
    "COMMON_CORE_AUDIT_NAME",
    "CONTINUATION_BANK_BYTES",
    "CONTINUATION_BANK_SHA256",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FAILURE_RECEIPT_NAME",
    "FINAL_BANK_NAME",
    "O1C96PreparationError",
    "OCCURRENCES_NAME",
    "PAGE16_ACTIVE_LIMIT",
    "PAGE16_CATEGORY_COUNTS",
    "PAGE16_CLAUSE_COUNT",
    "PAGE16_HEADROOM",
    "PAGE16_LITERAL_COUNT",
    "PAGE16_SERIALIZED_BYTES",
    "PAGE16_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
    "PARENT_FAILURE_SHA256",
    "PARENT_INTENT_SHA256",
    "PARENT_RESULT_SHA256",
    "PREPARATION_MANIFEST_BYTES",
    "PREPARATION_MANIFEST_NAME",
    "PREPARATION_MANIFEST_SHA256",
    "PREPARATION_SCHEMA",
    "PRIORITY_RECEIPT_BYTES",
    "PRIORITY_RECEIPT_NAME",
    "PRIORITY_RECEIPT_SHA256",
    "PreparedCausalRolloverArtifacts",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "main",
    "preflight_o1c96_page16_transport_recovery",
    "prepare_and_write_o1c96_page16_transport_recovery",
    "prepare_o1c96_page16_transport_recovery",
    "write_prepared_o1c96_page16_transport_recovery",
]
