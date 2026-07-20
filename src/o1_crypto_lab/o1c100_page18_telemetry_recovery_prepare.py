"""Zero-call O1C-0100 Page-18 telemetry-cap recovery preparation.

O1C-0099 persisted intent and therefore burned Page 17 / lineage 30.  Its
native process then exited with status one because the decision-ownership
telemetry event cap was exhausted.  No native result, clause evidence, or
priority-state update reached the runner and none is imported here.

This module validates that exact sealed POST_CALL boundary, regenerates the
certified O1C-0098 state and requires all ten capsule inputs to be byte equal,
then reprojects the unchanged 19-chunk attic onto fresh Page 18 / lineage 31.
It has no native, solver, target, truth-key, model, or reveal interface.
Publication is a separate atomic operation.
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
from . import o1c98_page17_causal_rollover_prepare as _o1c98
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


ATTEMPT_ID = "O1C-0100"
PARENT_ATTEMPT_ID = "O1C-0099"
PREPARATION_SCHEMA = "o1-256-o1c100-page18-telemetry-recovery-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_004001_986566_O1C-0099_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0099_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "93fdb7eb7ce828fd6c41a327a5ab1c7c58305e6a6be752dc0812b214b1fbbf9e"
)
PARENT_CAPSULE_MANIFEST_BYTES = 3_440
PARENT_CAPSULE_ENTRY_COUNT = 33
PARENT_RESULT_SHA256 = (
    "2f60c3dc12adea0157534cd67296a0839ac9e17303868f121b1593d36a50611b"
)
PARENT_RESULT_BYTES = 32_091
PARENT_EPISODE_SHA256 = (
    "1a3555689eddb03a7673c00d44f40f964575c3608d02ecf7db21daf159030262"
)
PARENT_EPISODE_BYTES = 23_813
PARENT_INTENT_SHA256 = (
    "7791ed49d63abf3dd80707380ba1da233856324d45aaa7046245255f612dd939"
)
PARENT_INTENT_BYTES = 1_487
PARENT_FAILURE_SHA256 = (
    "fd52665283e901bb8237923efba081ee1f20d85e1070e9d5e6b2421e9ada46b4"
)
PARENT_FAILURE_BYTES = 22_520
PARENT_INVOCATION_SHA256 = (
    "66c1f8ad609cd818bd89840bbabfb004b82d15b5fbe88e4945f115d1976b7b8e"
)
PARENT_INVOCATION_BYTES = 3_467
PARENT_NATIVE_STDOUT_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
PARENT_NATIVE_STDOUT_BYTES = 0
PARENT_NATIVE_STDERR_SHA256 = (
    "c9d1f777e9922c61d2951155b36a6b3eb2406b8a0e478ecffcf17b73aa18c3b6"
)
PARENT_NATIVE_STDERR_BYTES = 72
PARENT_NATIVE_STDERR = (
    "cadical_o1_joint_score_sieve_v28: decision ownership event cap exceeded\n"
)
PARENT_FAILURE_MESSAGE = (
    "joint-score-sieve-v31 execution failed: "
    "cadical_o1_joint_score_sieve_v28: decision ownership event cap exceeded"
)
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
PARENT_STOP_REASON = "burned-terminal-failure-no-retry"
PARENT_REQUESTED_CONFLICTS = 128
PARENT_CONFIG_SHA256 = (
    "21d8982dfe2b9683e8cd6b4c8a458aa7cbbd42a7e163aa1925b1e253f0963aac"
)

O1C98_PREPARATION_MANIFEST_SHA256 = _o1c98.PREPARATION_MANIFEST_SHA256
O1C98_PREPARATION_MANIFEST_BYTES = _o1c98.PREPARATION_MANIFEST_BYTES
O1C98_INITIAL_ARTIFACT_COUNT = 10

CONTINUATION_BANK_SHA256 = _o1c98.FINAL_BANK_SHA256
CONTINUATION_BANK_BYTES = _o1c98.FINAL_BANK_BYTES
PRIORITY_RECEIPT_SHA256 = _o1c98.PRIORITY_RECEIPT_SHA256
PRIORITY_RECEIPT_BYTES = _o1c98.PRIORITY_RECEIPT_BYTES

ATTIC_CHUNK_COUNT = _o1c98.ATTIC_CHUNK_COUNT
ATTIC_UNION_SHA256 = _o1c98.ATTIC_UNION_SHA256
ATTIC_UNION_CLAUSE_COUNT = _o1c98.ATTIC_UNION_CLAUSE_COUNT
ATTIC_UNION_LITERAL_COUNT = _o1c98.ATTIC_UNION_LITERAL_COUNT
ATTIC_UNION_SERIALIZED_BYTES = _o1c98.ATTIC_UNION_SERIALIZED_BYTES
ATTIC_OCCURRENCE_COUNT = _o1c98.ATTIC_OCCURRENCE_COUNT
ATTIC_DUPLICATE_OCCURRENCE_COUNT = _o1c98.ATTIC_DUPLICATE_OCCURRENCE_COUNT
ATTIC_SUBSUMPTION_RELATION_COUNT = _o1c98.ATTIC_SUBSUMPTION_RELATION_COUNT
ATTIC_UNDOMINATED_CLAUSE_COUNT = _o1c98.ATTIC_UNDOMINATED_CLAUSE_COUNT

PAGE18_SHA256 = "5d89bbe07c8b988b4f1ce5dc2a31b860ab59192d3efc02854e27b8f779de417c"
PAGE18_CLAUSE_COUNT = 249
PAGE18_LITERAL_COUNT = 669_910
PAGE18_SERIALIZED_BYTES = 2_680_827
PAGE18_ACTIVE_LIMIT = 249
PAGE18_LINEAGE_ORDINAL = 31
PAGE18_CATEGORY_COUNTS = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 65,
    "hot_event": 0,
    "recycled": 132,
}
PAGE18_HEADROOM = {
    "clauses": 263,
    "literals": 930_090,
    "serialized_bytes": 5_707_781,
}
PAGE18_RESIDENCY_DOCUMENT_SHA256 = (
    "90ccbe483bc88bd3f3dd3c945fe65ceddc7bd291035051a305a9d96644db39e2"
)
PAGE18_RESIDENCY_DOCUMENT_BYTES = 60_284
PAGE18_ACTIVATION_DOCUMENT_SHA256 = (
    "974c530e07a7fbed88212d299e04907177896233871ead02d6837657e5f726cd"
)
PAGE18_ACTIVATION_DOCUMENT_BYTES = 37_446
PAGE18_ACTIVATION_COUNT = 19
PAGE18_SELECTED_INDICES_SHA256 = (
    "05c007e53843c89b87c109fb1b2b52f484fe358469de91336dcdaa420c49aa4b"
)
PAGE18_SELECTION_ORDER_SHA256 = (
    "4951ae5c6a10658a71a0f74c7ae63ef0ca8c3ddf5387d260b38192b6827c08b6"
)

ACTIVE_PROJECTION_NAME = "page-18-active.bin"
RESIDENCY_NAME = _o1c98.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c98.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c98.OCCURRENCES_NAME
RELATIONS_NAME = _o1c98.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c98.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c98.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = _o1c98.PRIORITY_RECEIPT_NAME
FAILURE_RECEIPT_NAME = "o1c99-terminal-failure-receipt.json"
PREPARATION_MANIFEST_NAME = "telemetry-recovery-preparation-manifest.json"

PREPARATION_MANIFEST_SHA256 = (
    "c0050ae08738f424505a92278759702bee4fcab23139a31137e715087ae437d9"
)
PREPARATION_MANIFEST_BYTES = 6_865

PreparedCausalRolloverArtifacts = _o1c98.PreparedCausalRolloverArtifacts


class O1C100PreparationError(RuntimeError):
    """An O1C-0099 seal or deterministic Page-18 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C100PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C100PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C100PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C100PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C100PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C100PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C100PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C100PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C100PreparationError("parent capsule manifest row differs")
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
            raise O1C100PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C100PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C100PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C100PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C100PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C100PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C100PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/terminal-failure.json": PARENT_FAILURE_SHA256,
        "episodes/00/native-stdout.json": PARENT_NATIVE_STDOUT_SHA256,
        "invocation.json": PARENT_INVOCATION_SHA256,
        f"initial/{_o1c98.PREPARATION_MANIFEST_NAME}": (
            O1C98_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c98.ACTIVE_PROJECTION_NAME}": _o1c98.PAGE17_SHA256,
        f"initial/{FINAL_BANK_NAME}": CONTINUATION_BANK_SHA256,
        f"initial/{PRIORITY_RECEIPT_NAME}": PRIORITY_RECEIPT_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C100PreparationError("parent capsule required seal differs")
    forbidden = {
        "episodes/00/native-result.json",
        "episodes/00/vault.json",
        "episodes/00/priority-state.json",
        "episodes/00/final-parent-centered-priority-bank.bin",
    }
    if forbidden.intersection(entries):
        raise O1C100PreparationError("parent capsule unexpectedly updated state")
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
        invocation_payload = (capsule / "invocation.json").read_bytes()
        stdout_payload = (capsule / "episodes/00/native-stdout.json").read_bytes()
    except OSError as exc:
        raise O1C100PreparationError("parent result boundary is unreadable") from exc
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
        or len(invocation_payload) != PARENT_INVOCATION_BYTES
        or sha256_bytes(invocation_payload) != PARENT_INVOCATION_SHA256
        or len(stdout_payload) != PARENT_NATIVE_STDOUT_BYTES
        or sha256_bytes(stdout_payload) != PARENT_NATIVE_STDOUT_SHA256
    ):
        raise O1C100PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    failure = _canonical_document(failure_payload, "parent terminal failure")
    invocation = _canonical_document(invocation_payload, "parent invocation")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C100PreparationError("parent terminal contract differs")
    episode = _mapping(episodes[0], "parent result episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    resources = _mapping(result.get("resources"), "parent resources")
    science = _mapping(episode.get("science"), "parent science")
    operational = _mapping(episode.get("operational"), "parent operational state")
    nested_failure = _mapping(
        episode.get("terminal_failure"), "parent nested terminal failure"
    )
    native_stdout = _mapping(episode.get("native_stdout"), "parent native stdout")
    native_process = _mapping(
        failure.get("native_process_evidence"), "parent native process evidence"
    )
    failure_telemetry = _mapping(
        native_process.get("failure_telemetry"), "parent native failure telemetry"
    )
    replay_fields = (
        "page10_replay_authorized",
        "page11_replay_authorized",
        "page12_replay_authorized",
        "page13_replay_authorized",
        "page14_replay_authorized",
        "page15_retry_or_replay_authorized",
        "page16_retry_or_replay_authorized",
        "page9_retry_or_replay_authorized",
    )
    stderr_payload = PARENT_NATIVE_STDERR.encode("utf-8")
    if (
        episode_document != episode
        or nested_failure != failure
        or result.get("schema")
        != "o1-256-apple8-parent-centered-continuation-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("capsule") != DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("stop_reason") != PARENT_STOP_REASON
        or result.get("science_gain") is not False
        or result.get("operational_activation") is not False
        or claim.get("config_sha256") != PARENT_CONFIG_SHA256
        or claim.get("page17_burned") is not True
        or claim.get("lineage30_only") is not True
        or claim.get("retry_or_replay") is not False
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("page17_sha256") != _o1c98.PAGE17_SHA256
        or claim.get("input_continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or claim.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or claim.get("rollover_manifest_sha256") != O1C98_PREPARATION_MANIFEST_SHA256
        or claim.get("global_novelty_baseline_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or any(claim.get(field) is not False for field in replay_fields)
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("completed") is not False
        or episode.get("lineage_call_ordinal") != 30
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page17_burned") is not True
        or episode.get("lineage30_burned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or any(episode.get(field) is not False for field in replay_fields)
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not False
        or native_stdout
        != {
            "path": "native-stdout.json",
            "serialized_bytes": PARENT_NATIVE_STDOUT_BYTES,
            "sha256": PARENT_NATIVE_STDOUT_SHA256,
        }
        or episode.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("actual_conflicts") is not None
        or episode.get("billed_conflicts") is not None
        or science != {"science_gain": False}
        or operational != {"operational_activation": False}
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or episode.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or resources.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or resources.get("native_solver_calls") != 1
        or resources.get("actual_conflicts") is not None
        or resources.get("billed_conflicts") is not None
        or failure.get("schema")
        != "o1-256-apple8-parent-centered-continuation-terminal-failure-v1"
        or failure.get("classification") != PARENT_CLASSIFICATION
        or failure.get("exception_type") != "JointScoreSieveExecutionError"
        or failure.get("message") != PARENT_FAILURE_MESSAGE
        or failure.get("phase") != "POST_CALL"
        or failure.get("occurred_after_persisted_intent") is not True
        or failure.get("native_call_issued") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("native_result_returned") is not False
        or _mapping(failure.get("native_stdout"), "failure native stdout")
        != native_stdout
        or failure.get("requested_conflicts_consumed") != PARENT_REQUESTED_CONFLICTS
        or failure.get("actual_conflicts") is not None
        or failure.get("billed_conflicts") is not None
        or failure.get("science_gain") is not False
        or failure.get("page17_burned") is not True
        or failure.get("lineage30_burned") is not True
        or failure.get("retry_authorized") is not False
        or failure.get("replay_authorized") is not False
        or any(failure.get(field) is not False for field in replay_fields)
        or native_process.get("returncode") != 1
        or native_process.get("stdout_bytes") != PARENT_NATIVE_STDOUT_BYTES
        or native_process.get("stdout_sha256") != PARENT_NATIVE_STDOUT_SHA256
        or native_process.get("stderr_bytes") != PARENT_NATIVE_STDERR_BYTES
        or native_process.get("stderr_sha256") != PARENT_NATIVE_STDERR_SHA256
        or native_process.get("stderr_tail") != PARENT_NATIVE_STDERR
        or len(stderr_payload) != PARENT_NATIVE_STDERR_BYTES
        or sha256_bytes(stderr_payload) != PARENT_NATIVE_STDERR_SHA256
        or failure_telemetry.get("schema")
        != "o1-256-joint-score-sieve-execution-failure-v1"
        or failure_telemetry.get("phase") != "adapter_validation"
        or failure_telemetry.get("classification_kind") != "adapter_or_parser"
        or failure_telemetry.get("returncode") != 1
        or failure_telemetry.get("stdout") != ""
        or failure_telemetry.get("stderr") != PARENT_NATIVE_STDERR
    ):
        raise O1C100PreparationError("parent terminal contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("lineage_call_ordinal") != 30
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page17_burned") is not True
        or intent.get("lineage30_burned") is not True
        or intent.get("page17_sha256") != _o1c98.PAGE17_SHA256
        or intent.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or intent.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or intent.get("rollover_manifest_sha256") != O1C98_PREPARATION_MANIFEST_SHA256
        or intent.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or any(intent.get(field) is not False for field in replay_fields)
        or intent.get("target_bytes_read") is not False
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or intent.get("config_sha256") != PARENT_CONFIG_SHA256
    ):
        raise O1C100PreparationError("parent persisted intent contract differs")

    if (
        invocation.get("schema")
        != "o1-256-apple8-parent-centered-continuation-invocation-v1"
        or invocation.get("attempt_id") != PARENT_ATTEMPT_ID
        or invocation.get("lineage_call_ordinal") != 30
        or invocation.get("local_episode_ordinal") != 0
        or invocation.get("page17_sha256") != _o1c98.PAGE17_SHA256
        or invocation.get("continuation_bank_sha256") != CONTINUATION_BANK_SHA256
        or invocation.get("priority_state_receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or invocation.get("rollover_manifest_sha256")
        != O1C98_PREPARATION_MANIFEST_SHA256
        or invocation.get("global_novelty_baseline_clause_count")
        != ATTIC_UNION_CLAUSE_COUNT
        or invocation.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or invocation.get("maximum_native_solver_calls") != 1
        or invocation.get("retry_authorized") is not False
        or invocation.get("replay_authorized") is not False
        or invocation.get("target_input_present") is not False
        or invocation.get("truth_input_present") is not False
        or invocation.get("config_sha256") != PARENT_CONFIG_SHA256
    ):
        raise O1C100PreparationError("parent invocation contract differs")
    return result, failure_payload


def _regenerate_o1c98_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c98.prepare_o1c98_page17_causal_rollover()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C100PreparationError("O1C-0098 regeneration differs") from exc
    expected_names = {
        _o1c98.NEW_CHUNK_NAME,
        _o1c98.ACTIVE_PROJECTION_NAME,
        _o1c98.RESIDENCY_NAME,
        _o1c98.ACTIVATION_LEDGER_NAME,
        _o1c98.OCCURRENCES_NAME,
        _o1c98.RELATIONS_NAME,
        _o1c98.COMMON_CORE_AUDIT_NAME,
        _o1c98.FINAL_BANK_NAME,
        _o1c98.PRIORITY_RECEIPT_NAME,
        _o1c98.PREPARATION_MANIFEST_NAME,
    }
    if (
        len(previous.artifacts) != O1C98_INITIAL_ARTIFACT_COUNT
        or set(previous.artifacts) != expected_names
    ):
        raise O1C100PreparationError("O1C-0098 regenerated inventory differs")
    initial = capsule / "initial"
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C100PreparationError("parent initial inventory is unreadable") from exc
    if {path.name for path in initial_children} != expected_names:
        raise O1C100PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C100PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C100PreparationError("parent initial artifact differs")
    if (
        len(previous.artifacts[_o1c98.PREPARATION_MANIFEST_NAME])
        != O1C98_PREPARATION_MANIFEST_BYTES
        or sha256_bytes(previous.artifacts[_o1c98.PREPARATION_MANIFEST_NAME])
        != O1C98_PREPARATION_MANIFEST_SHA256
        or len(previous.artifacts[FINAL_BANK_NAME]) != CONTINUATION_BANK_BYTES
        or sha256_bytes(previous.artifacts[FINAL_BANK_NAME]) != CONTINUATION_BANK_SHA256
        or len(previous.artifacts[PRIORITY_RECEIPT_NAME]) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(previous.artifacts[PRIORITY_RECEIPT_NAME])
        != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C100PreparationError("unchanged certified continuation state differs")
    return previous


def _reproject_page18(
    previous: PreparedCausalRolloverArtifacts,
) -> CausalResidencyState:
    prior = previous.state
    prior_attic = prior.attic
    try:
        state = reproject_causal_residency(
            prior_attic,
            previous_state=prior,
            fully_emitted_union_indices=(),
            next_lineage_ordinal=PAGE18_LINEAGE_ORDINAL,
            next_active_limit=PAGE18_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C100PreparationError("Page-18 telemetry recovery differs") from exc
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
        or state.current_projection.lineage_ordinal != PAGE18_LINEAGE_ORDINAL
        or state.active_limit != PAGE18_ACTIVE_LIMIT
        or state.attic.active_limit != PAGE18_ACTIVE_LIMIT
        or page.sha256 != PAGE18_SHA256
        or page.clause_count != PAGE18_CLAUSE_COUNT
        or page.literal_count != PAGE18_LITERAL_COUNT
        or page.serialized_bytes != PAGE18_SERIALIZED_BYTES
        or state.current_projection.category_counts != PAGE18_CATEGORY_COUNTS
        or headroom != PAGE18_HEADROOM
        or len(residency_payload) != PAGE18_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE18_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE18_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE18_ACTIVATION_DOCUMENT_SHA256
        or sha256_bytes(selected_payload) != PAGE18_SELECTED_INDICES_SHA256
        or sha256_bytes(order_payload) != PAGE18_SELECTION_ORDER_SHA256
        or state.activation_ledger[:-1] != prior.activation_ledger
        or state.used_active_sha256[:-1] != prior.used_active_sha256
        or len(state.activation_ledger) != PAGE18_ACTIVATION_COUNT
        or len(state.activation_ledger) != len(prior.activation_ledger) + 1
        or page.sha256 in prior.used_active_sha256
        or len(prior.never_resident_undominated_indices) != 65
        or set(state.current_projection.new_debt_indices)
        != set(prior.never_resident_undominated_indices)
        or state.never_resident_undominated_indices
        or len(state.current_projection.recycled_indices) != 132
        or len(state.attic.chunks) != ATTIC_CHUNK_COUNT
        or state.attic.union_vault.sha256 != ATTIC_UNION_SHA256
        or state.attic.union_vault.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or state.attic.union_vault.literal_count != ATTIC_UNION_LITERAL_COUNT
        or state.attic.union_vault.serialized_bytes != ATTIC_UNION_SERIALIZED_BYTES
        or len(state.attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or state.attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or len(state.attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(state.attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
    ):
        raise O1C100PreparationError("Page-18 telemetry recovery contract differs")
    return state


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c100_page18_telemetry_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate burned O1C-0099 and return a fresh Page-18 bundle in memory."""

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
    previous = _regenerate_o1c98_and_validate_initial(capsule)
    state = _reproject_page18(previous)

    occurrence_payload = previous.artifacts[OCCURRENCES_NAME]
    relation_payload = previous.artifacts[RELATIONS_NAME]
    audit_payload = previous.artifacts[COMMON_CORE_AUDIT_NAME]
    bank = previous.artifacts[FINAL_BANK_NAME]
    priority_receipt = previous.artifacts[PRIORITY_RECEIPT_NAME]
    continuation = _mapping(
        previous.manifest.get("final_priority_bank"),
        "O1C-0098 continuation bank",
    )
    if (
        occurrence_payload != canonical_json_bytes(state.attic.occurrence_document())
        or relation_payload != canonical_json_bytes(state.attic.relation_document())
        or audit_payload != (capsule / "initial" / COMMON_CORE_AUDIT_NAME).read_bytes()
        or bank != (capsule / "initial" / FINAL_BANK_NAME).read_bytes()
        or priority_receipt
        != (capsule / "initial" / PRIORITY_RECEIPT_NAME).read_bytes()
        or continuation.get("sha256") != CONTINUATION_BANK_SHA256
        or continuation.get("receipt_sha256") != PRIORITY_RECEIPT_SHA256
        or continuation.get("receipt_bank_hex_byte_equal") is not True
    ):
        raise O1C100PreparationError("unchanged transport artifact differs")

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
        ACTIVE_PROJECTION_NAME: "fresh-lineage-31-page18-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "unchanged-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "unchanged-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "unchanged-sealed-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "unchanged-canonical-o1c97-priority-state-receipt",
        FAILURE_RECEIPT_NAME: "canonical-o1c99-post-call-terminal-failure-receipt",
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
            "page18_burned": False,
            "lineage31_burned": False,
            "page17_retry_or_replay_authorized": False,
            "lineage30_retry_or_replay_authorized": False,
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
            "episode_serialized_bytes": PARENT_EPISODE_BYTES,
            "intent_sha256": PARENT_INTENT_SHA256,
            "intent_serialized_bytes": PARENT_INTENT_BYTES,
            "invocation_sha256": PARENT_INVOCATION_SHA256,
            "invocation_serialized_bytes": PARENT_INVOCATION_BYTES,
            "terminal_failure_sha256": PARENT_FAILURE_SHA256,
            "terminal_failure_serialized_bytes": PARENT_FAILURE_BYTES,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "failure_reason": "native-decision-ownership-event-cap-exceeded",
            "failure_phase": "POST_CALL",
            "native_process_returncode": 1,
            "native_stdout_sha256": PARENT_NATIVE_STDOUT_SHA256,
            "native_stdout_serialized_bytes": PARENT_NATIVE_STDOUT_BYTES,
            "native_stderr_sha256": PARENT_NATIVE_STDERR_SHA256,
            "native_stderr_serialized_bytes": PARENT_NATIVE_STDERR_BYTES,
            "page17_burned": True,
            "lineage30_burned": True,
            "native_result_returned_to_runner": False,
            "actual_conflicts": None,
            "billed_conflicts": None,
            "science_gain": False,
            "state_update_available": False,
            "initial_o1c98_artifact_count": O1C98_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_regeneration": True,
            "priority_receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "priority_receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        },
        "science_boundary": {
            "imported_science_attempt_id": None,
            "imported_clause_count": 0,
            "imported_priority_state_update": False,
            "o1c99_terminal_failure_imported_as_science": False,
            "o1c99_native_stdout_imported_as_science": False,
            "o1c99_output_artifacts_imported": [],
        },
        "telemetry_recovery": {
            "source_lineage_ordinal": 30,
            "next_lineage_ordinal": PAGE18_LINEAGE_ORDINAL,
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
                "fully_emitted_union_indices=(),next_lineage_ordinal=31,"
                "next_active_limit=249)"
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
            "byte_and_relation_equal_to_o1c98": True,
        },
        "page18": {
            "lineage_ordinal": PAGE18_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "selected_union_indices_sha256": PAGE18_SELECTED_INDICES_SHA256,
            "selection_order_sha256": PAGE18_SELECTION_ORDER_SHA256,
            "headroom": PAGE18_HEADROOM,
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
                "recycled_clause_count": len(state.current_projection.recycled_indices),
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
        _canonical_document(manifest_payload, "telemetry recovery manifest") != manifest
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
    ):
        raise O1C100PreparationError(
            "telemetry recovery manifest differs: "
            f"bytes={len(manifest_payload)}, sha256={sha256_bytes(manifest_payload)}"
        )
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c100_page18_telemetry_recovery(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c100_page18_telemetry_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C100PreparationError("prepared Page-18 bundle differs")
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
    manifest = _mapping(prepared.manifest, "prepared Page-18 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-18 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        ACTIVE_PROJECTION_NAME: (PAGE18_SERIALIZED_BYTES, PAGE18_SHA256),
        RESIDENCY_NAME: (
            PAGE18_RESIDENCY_DOCUMENT_BYTES,
            PAGE18_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE18_ACTIVATION_DOCUMENT_BYTES,
            PAGE18_ACTIVATION_DOCUMENT_SHA256,
        ),
        OCCURRENCES_NAME: (
            _o1c98.OCCURRENCE_DOCUMENT_BYTES,
            _o1c98.OCCURRENCE_DOCUMENT_SHA256,
        ),
        RELATIONS_NAME: (
            _o1c98.RELATION_DOCUMENT_BYTES,
            _o1c98.RELATION_DOCUMENT_SHA256,
        ),
        COMMON_CORE_AUDIT_NAME: (
            _o1c98.COMMON_CORE_AUDIT_BYTES,
            _o1c98.COMMON_CORE_AUDIT_SHA256,
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
        or prepared.state.active_projection.sha256 != PAGE18_SHA256
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
        raise O1C100PreparationError("prepared Page-18 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C100PreparationError("prepared Page-18 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-18 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C100PreparationError("prepared Page-18 artifact seal differs")


def write_prepared_o1c100_page18_telemetry_recovery(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-18 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(prepared, output_dir)
    except _publisher.O1C85PreparationError as exc:
        raise O1C100PreparationError("Page-18 publication failed") from exc


def prepare_and_write_o1c100_page18_telemetry_recovery(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-18 bundle."""

    prepared = prepare_o1c100_page18_telemetry_recovery(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c100_page18_telemetry_recovery(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0100's zero-call Page-18 recovery"
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
        prepared = prepare_o1c100_page18_telemetry_recovery(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c100_page18_telemetry_recovery(prepared, args.output_dir)
    except (
        O1C100PreparationError,
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
    "ATTIC_CHUNK_COUNT",
    "ATTIC_DUPLICATE_OCCURRENCE_COUNT",
    "ATTIC_OCCURRENCE_COUNT",
    "ATTIC_SUBSUMPTION_RELATION_COUNT",
    "ATTIC_UNDOMINATED_CLAUSE_COUNT",
    "ATTIC_UNION_CLAUSE_COUNT",
    "ATTIC_UNION_LITERAL_COUNT",
    "ATTIC_UNION_SERIALIZED_BYTES",
    "ATTIC_UNION_SHA256",
    "ATTEMPT_ID",
    "COMMON_CORE_AUDIT_NAME",
    "CONTINUATION_BANK_BYTES",
    "CONTINUATION_BANK_SHA256",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FAILURE_RECEIPT_NAME",
    "FINAL_BANK_NAME",
    "O1C100PreparationError",
    "OCCURRENCES_NAME",
    "PAGE18_ACTIVE_LIMIT",
    "PAGE18_ACTIVATION_COUNT",
    "PAGE18_ACTIVATION_DOCUMENT_BYTES",
    "PAGE18_ACTIVATION_DOCUMENT_SHA256",
    "PAGE18_CATEGORY_COUNTS",
    "PAGE18_CLAUSE_COUNT",
    "PAGE18_HEADROOM",
    "PAGE18_LINEAGE_ORDINAL",
    "PAGE18_LITERAL_COUNT",
    "PAGE18_RESIDENCY_DOCUMENT_BYTES",
    "PAGE18_RESIDENCY_DOCUMENT_SHA256",
    "PAGE18_SELECTED_INDICES_SHA256",
    "PAGE18_SELECTION_ORDER_SHA256",
    "PAGE18_SERIALIZED_BYTES",
    "PAGE18_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
    "PARENT_FAILURE_BYTES",
    "PARENT_FAILURE_SHA256",
    "PARENT_INTENT_SHA256",
    "PARENT_INVOCATION_SHA256",
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
    "preflight_o1c100_page18_telemetry_recovery",
    "prepare_and_write_o1c100_page18_telemetry_recovery",
    "prepare_o1c100_page18_telemetry_recovery",
    "write_prepared_o1c100_page18_telemetry_recovery",
]
