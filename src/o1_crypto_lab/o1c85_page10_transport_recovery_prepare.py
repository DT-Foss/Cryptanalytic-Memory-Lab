"""Zero-call O1C-0085 Page-10 transport-recovery preparation.

O1C-0084 burned Page 9 and lineage 22 after persisting intent, but dyld
rejected the native image before it returned a result.  Consequently there is
no new scientific evidence or live priority state to merge.  This module
validates that exact failure boundary, regenerates the O1C-0083 Page-9 state,
and projects the same immutable attic to a fresh 254-clause Page 10.

The module has no native, solver, target, truth-key, model, or reveal
interface.  Preparation is in-memory; publication delegates to O1C-0083's
type-compatible atomic directory writer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c83_apple8_causal_rollover_prepare as _o1c83
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


ATTEMPT_ID = "O1C-0085"
PARENT_ATTEMPT_ID = "O1C-0084"
PREPARATION_SCHEMA = "o1-256-o1c85-page10-transport-recovery-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_162606_777761_O1C-0084_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0084_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "811ad89955b383c4ac1303fc3f510c4169278e19cec73d465adf7a76e65cc2bf"
)
PARENT_CAPSULE_MANIFEST_BYTES = 1_883
PARENT_CAPSULE_ENTRY_COUNT = 20
PARENT_RESULT_SHA256 = (
    "4ae1238203ef10c03a1dd325242ccb59bd0f8f67c0b93fa5debd95259c7f7b96"
)
PARENT_RESULT_BYTES = 8_738
PARENT_INTENT_SHA256 = (
    "89483dda835275adba37a3cbb9099c12590cf26f439913eb4d91bbd6c912d20c"
)
PARENT_INTENT_BYTES = 946
PARENT_EPISODE_SHA256 = (
    "ed9814800d68d35586c82b728fdf8d493a67ee0f3c72fed3ff929e8d92868210"
)
PARENT_EPISODE_BYTES = 1_686
PARENT_FAILURE_SHA256 = (
    "d4136e4c7008a6c51d6bb340b67dbf29fe92b3bb9c581f0363f584e5060ca610"
)
PARENT_FAILURE_BYTES = 889
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
PARENT_STOP_REASON = "burned-terminal-failure-no-retry"

O1C83_PREPARATION_MANIFEST_SHA256 = (
    "b8a829a642159640a10cc553c6c27e5312cae4fbda8f75975688c6d14afe7dda"
)
O1C83_INITIAL_ARTIFACT_COUNT = 9
PRIORITY_RECEIPT_NAME = "o1c82-priority-state-receipt.json"
PRIORITY_RECEIPT_SHA256 = _o1c83.PARENT_PRIORITY_STATE_SHA256
PRIORITY_RECEIPT_BYTES = _o1c83.PARENT_PRIORITY_STATE_BYTES
CONTINUATION_BANK_SHA256 = _o1c83.PARENT_FINAL_BANK_SHA256
CONTINUATION_BANK_BYTES = _o1c83.PARENT_FINAL_BANK_BYTES

PAGE10_SHA256 = "bf1fd3e3938bc4125e672ee94ee599e5f21881b4fc87e2bc81e8fc57fc4d3556"
PAGE10_CLAUSE_COUNT = 254
PAGE10_LITERAL_COUNT = 718_295
PAGE10_SERIALIZED_BYTES = 2_874_387
PAGE10_ACTIVE_LIMIT = 254
PAGE10_LINEAGE_ORDINAL = 23
PAGE10_CATEGORY_COUNTS = {
    "structural_root": 4,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 47,
    "hot_event": 0,
    "recycled": 160,
}
PAGE10_HEADROOM = {
    "clauses": 258,
    "literals": 881_705,
    "serialized_bytes": 5_514_221,
}

ACTIVE_PROJECTION_NAME = "page-10-active.bin"
RESIDENCY_NAME = _o1c83.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c83.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c83.OCCURRENCES_NAME
RELATIONS_NAME = _o1c83.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c83.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c83.FINAL_BANK_NAME
FAILURE_RECEIPT_NAME = "o1c84-terminal-failure-receipt.json"
PREPARATION_MANIFEST_NAME = "transport-recovery-preparation-manifest.json"

PreparedCausalRolloverArtifacts = _o1c83.PreparedCausalRolloverArtifacts


class O1C85PreparationError(RuntimeError):
    """An O1C-0084 seal or deterministic Page-10 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C85PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C85PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C85PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C85PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C85PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C85PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C85PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C85PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C85PreparationError("parent capsule manifest row differs")
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
            raise O1C85PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C85PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C85PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C85PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C85PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C85PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C85PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/terminal-failure.json": PARENT_FAILURE_SHA256,
        f"initial/{_o1c83.PREPARATION_MANIFEST_NAME}": (
            O1C83_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c83.ACTIVE_PROJECTION_NAME}": _o1c83.PAGE9_SHA256,
        f"initial/{_o1c83.FINAL_BANK_NAME}": CONTINUATION_BANK_SHA256,
        f"initial/{PRIORITY_RECEIPT_NAME}": PRIORITY_RECEIPT_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C85PreparationError("parent capsule required seal differs")
    forbidden = {
        "episodes/00/native-result.json",
        "episodes/00/native-stdout.json",
        "episodes/00/priority-state.json",
        "episodes/00/final-parent-centered-priority-bank.bin",
        "episodes/00/vault.json",
    }
    if forbidden.intersection(entries):
        raise O1C85PreparationError("parent capsule unexpectedly updated state")
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
        raise O1C85PreparationError("parent result boundary is unreadable") from exc
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
        raise O1C85PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    failure = _canonical_document(failure_payload, "parent terminal failure")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C85PreparationError("parent terminal contract differs")
    episode = _mapping(episodes[0], "parent result episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    resources = _mapping(result.get("resources"), "parent resources")
    science = _mapping(episode.get("science"), "parent science")
    operational = _mapping(episode.get("operational"), "parent operational state")
    nested_failure = _mapping(
        episode.get("terminal_failure"), "parent nested terminal failure"
    )
    message = failure.get("message")
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
        or claim.get("page9_burned") is not True
        or claim.get("lineage22_only") is not True
        or claim.get("retry_or_replay") is not False
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("page9_sha256") != _o1c83.PAGE9_SHA256
        or claim.get("input_continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or claim.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("completed") is not False
        or episode.get("lineage_call_ordinal") != 22
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page9_burned") is not True
        or episode.get("lineage22_burned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not False
        or episode.get("native_stdout") is not None
        or episode.get("actual_conflicts") is not None
        or episode.get("billed_conflicts") is not None
        or science != {"science_gain": False}
        or operational != {"operational_activation": False}
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or resources.get("actual_conflicts") is not None
        or resources.get("billed_conflicts") is not None
        or failure.get("schema")
        != "o1-256-apple8-parent-centered-continuation-terminal-failure-v1"
        or failure.get("classification") != PARENT_CLASSIFICATION
        or failure.get("exception_type") != "JointScoreSieveExecutionError"
        or failure.get("phase") != "CALL"
        or failure.get("occurred_after_persisted_intent") is not True
        or failure.get("native_call_issued") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("native_result_returned") is not False
        or failure.get("native_process_evidence") is not None
        or failure.get("actual_conflicts") is not None
        or failure.get("billed_conflicts") is not None
        or failure.get("science_gain") is not False
        or failure.get("page9_burned") is not True
        or failure.get("lineage22_burned") is not True
        or failure.get("retry_authorized") is not False
        or failure.get("replay_authorized") is not False
        or not isinstance(message, str)
        or message.count("missing LC_UUID load command") != 2
    ):
        raise O1C85PreparationError("parent terminal contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("lineage_call_ordinal") != 22
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page9_burned") is not True
        or intent.get("lineage22_burned") is not True
        or intent.get("page9_sha256") != _o1c83.PAGE9_SHA256
        or intent.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or intent.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or intent.get("target_bytes_read") is not False
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("invocation_sha256") != episode.get("invocation_sha256")
    ):
        raise O1C85PreparationError("parent persisted intent contract differs")
    return result, failure_payload


def _regenerate_o1c83_and_validate_initial(
    capsule: Path,
) -> tuple[PreparedCausalRolloverArtifacts, bytes, Mapping[str, object]]:
    try:
        prior = _o1c83.prepare_o1c83_causal_rollover()
    except (
        OSError,
        RuntimeError,
        CausalAtticError,
        CausalResidencyError,
    ) as exc:
        raise O1C85PreparationError("O1C-0083 regeneration differs") from exc
    initial = capsule / "initial"
    expected_names = set(prior.artifacts)
    if len(expected_names) != O1C83_INITIAL_ARTIFACT_COUNT or expected_names != {
        _o1c83.NEW_CHUNK_NAME,
        _o1c83.ACTIVE_PROJECTION_NAME,
        _o1c83.RESIDENCY_NAME,
        _o1c83.ACTIVATION_LEDGER_NAME,
        _o1c83.OCCURRENCES_NAME,
        _o1c83.RELATIONS_NAME,
        _o1c83.COMMON_CORE_AUDIT_NAME,
        _o1c83.FINAL_BANK_NAME,
        _o1c83.PREPARATION_MANIFEST_NAME,
    }:
        raise O1C85PreparationError("O1C-0083 regenerated inventory differs")
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C85PreparationError("parent initial inventory is unreadable") from exc
    if {path.name for path in initial_children} != expected_names | {
        PRIORITY_RECEIPT_NAME
    }:
        raise O1C85PreparationError("parent initial inventory differs")
    for name, expected in prior.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C85PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C85PreparationError("parent initial artifact differs")

    bank = prior.artifacts[_o1c83.FINAL_BANK_NAME]
    receipt_path = initial / PRIORITY_RECEIPT_NAME
    source_receipt_path = (
        lab_root()
        / _o1c83.DEFAULT_PARENT_CAPSULE_RELATIVE
        / "episodes/00/priority-state.json"
    )
    try:
        receipt = receipt_path.read_bytes()
        source_receipt = source_receipt_path.read_bytes()
    except OSError as exc:
        raise O1C85PreparationError("priority state receipt is unreadable") from exc
    if (
        len(bank) != CONTINUATION_BANK_BYTES
        or sha256_bytes(bank) != CONTINUATION_BANK_SHA256
        or len(receipt) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt) != PRIORITY_RECEIPT_SHA256
        or receipt != source_receipt
    ):
        raise O1C85PreparationError("unchanged continuation state differs")
    try:
        continuation = _o1c83._validate_live_continuation_bank(
            source_receipt_path.parents[2], bank
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise O1C85PreparationError("continuation bank receipt differs") from exc
    return prior, receipt, continuation


def _reproject_page10(
    previous: PreparedCausalRolloverArtifacts,
) -> CausalResidencyState:
    prior = previous.state
    prior_attic = prior.attic
    try:
        state = reproject_causal_residency(
            prior_attic,
            previous_state=prior,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=PAGE10_LINEAGE_ORDINAL,
            next_active_limit=PAGE10_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C85PreparationError("Page-10 transport recovery differs") from exc
    page = state.active_projection
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
        or state.current_projection.lineage_ordinal != PAGE10_LINEAGE_ORDINAL
        or state.active_limit != PAGE10_ACTIVE_LIMIT
        or state.attic.active_limit != PAGE10_ACTIVE_LIMIT
        or page.sha256 != PAGE10_SHA256
        or page.clause_count != PAGE10_CLAUSE_COUNT
        or page.literal_count != PAGE10_LITERAL_COUNT
        or page.serialized_bytes != PAGE10_SERIALIZED_BYTES
        or state.current_projection.category_counts != PAGE10_CATEGORY_COUNTS
        or headroom != PAGE10_HEADROOM
        or state.activation_ledger[:-1] != prior.activation_ledger
        or state.used_active_sha256[:-1] != prior.used_active_sha256
        or len(state.activation_ledger) != len(prior.activation_ledger) + 1
        or page.sha256 in prior.used_active_sha256
        or len(prior.never_resident_undominated_indices) != 47
        or state.never_resident_undominated_indices
    ):
        raise O1C85PreparationError("Page-10 transport recovery contract differs")
    return state


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c85_page10_transport_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate burned O1C-0084 and return a fresh Page-10 bundle in memory."""

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
    previous, priority_receipt, continuation = _regenerate_o1c83_and_validate_initial(
        capsule
    )
    state = _reproject_page10(previous)

    occurrence_payload = previous.artifacts[_o1c83.OCCURRENCES_NAME]
    relation_payload = previous.artifacts[_o1c83.RELATIONS_NAME]
    audit_payload = previous.artifacts[_o1c83.COMMON_CORE_AUDIT_NAME]
    bank = previous.artifacts[_o1c83.FINAL_BANK_NAME]
    if (
        occurrence_payload != canonical_json_bytes(state.attic.occurrence_document())
        or relation_payload != canonical_json_bytes(state.attic.relation_document())
        or audit_payload
        != (capsule / "initial" / _o1c83.COMMON_CORE_AUDIT_NAME).read_bytes()
        or bank != (capsule / "initial" / _o1c83.FINAL_BANK_NAME).read_bytes()
    ):
        raise O1C85PreparationError("unchanged transport artifact differs")

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
        FAILURE_RECEIPT_NAME: failure_payload,
    }
    roles = {
        ACTIVE_PROJECTION_NAME: "fresh-lineage-23-page10-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "unchanged-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "unchanged-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-public-common-core-bound-audit",
        FINAL_BANK_NAME: "unchanged-sealed-live-continuation-bank-bytes",
        FAILURE_RECEIPT_NAME: "canonical-o1c84-terminal-failure-receipt",
    }
    manifest: dict[str, object] = {
        "schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
        },
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page10_burned": False,
            "lineage23_burned": False,
            "page9_replay_authorized": False,
            "lineage22_replay_authorized": False,
        },
        "parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_entry_count": len(entries),
            "result_sha256": PARENT_RESULT_SHA256,
            "intent_sha256": PARENT_INTENT_SHA256,
            "terminal_failure_sha256": PARENT_FAILURE_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "failure_reason": "dyld-missing-LC_UUID-before-native-result",
            "page9_burned": True,
            "lineage22_burned": True,
            "native_result_returned": False,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "science_gain": False,
            "state_update_available": False,
            "initial_o1c83_artifact_count": O1C83_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_regeneration": True,
            "priority_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "priority_receipt_serialized_bytes": len(priority_receipt),
        },
        "transport_recovery": {
            "source_lineage_ordinal": 22,
            "next_lineage_ordinal": PAGE10_LINEAGE_ORDINAL,
            "fully_emitted_event_count": 0,
            "new_chunk_count": 0,
            "attic_evidence_unchanged": True,
            "occurrence_ledger_unchanged": True,
            "relation_ledger_unchanged": True,
            "common_core_audit_unchanged": True,
            "continuation_bank_unchanged": True,
            "api": (
                "reproject_causal_residency(same_attic,"
                "fully_emitted_union_indices=(),next_lineage_ordinal=23,"
                "next_active_limit=254)"
            ),
        },
        "attic": {
            "chunk_count": len(state.attic.chunks),
            "union_clause_count": state.attic.union_vault.clause_count,
            "occurrence_count": len(state.attic.occurrences),
            "strict_subsumption_pair_count": len(state.attic.relations),
            "undominated_clause_count": len(state.attic.undominated_indices),
        },
        "page10": {
            "lineage_ordinal": PAGE10_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE10_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
        },
        "final_priority_bank": {
            "sha256": CONTINUATION_BANK_SHA256,
            "serialized_bytes": CONTINUATION_BANK_BYTES,
            "priority_is_key_bit_belief": False,
            "semantic_role": "unchanged-sealed-live-continuation-bytes",
            **continuation,
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    if _canonical_document(manifest_payload, "transport recovery manifest") != manifest:
        raise O1C85PreparationError("transport recovery manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c85_page10_transport_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c85_page10_transport_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def write_prepared_o1c85_page10_transport_recovery(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-10 bundle to a fresh directory."""

    try:
        _o1c83.write_prepared_o1c83_causal_rollover(prepared, output_dir)
    except _o1c83.O1C83PreparationError as exc:
        raise O1C85PreparationError("transport recovery publication failed") from exc


def prepare_and_write_o1c85_page10_transport_recovery(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-10 bundle."""

    prepared = prepare_o1c85_page10_transport_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c85_page10_transport_recovery(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0085's zero-call Page-10 recovery"
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
        prepared = prepare_o1c85_page10_transport_recovery(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c85_page10_transport_recovery(prepared, args.output_dir)
    except (
        O1C85PreparationError,
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
    "O1C85PreparationError",
    "OCCURRENCES_NAME",
    "PAGE10_ACTIVE_LIMIT",
    "PAGE10_CATEGORY_COUNTS",
    "PAGE10_CLAUSE_COUNT",
    "PAGE10_HEADROOM",
    "PAGE10_LITERAL_COUNT",
    "PAGE10_SERIALIZED_BYTES",
    "PAGE10_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
    "PARENT_FAILURE_SHA256",
    "PARENT_INTENT_SHA256",
    "PARENT_RESULT_SHA256",
    "PREPARATION_MANIFEST_NAME",
    "PREPARATION_SCHEMA",
    "PRIORITY_RECEIPT_SHA256",
    "PreparedCausalRolloverArtifacts",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "main",
    "preflight_o1c85_page10_transport_recovery",
    "prepare_and_write_o1c85_page10_transport_recovery",
    "prepare_o1c85_page10_transport_recovery",
    "write_prepared_o1c85_page10_transport_recovery",
]
