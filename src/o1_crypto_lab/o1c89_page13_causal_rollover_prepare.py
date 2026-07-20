"""Zero-call O1C-0089 Page-13 causal-rollover preparation.

The only new scientific evidence consumed here is O1C-0088's sealed set of
259 fully emitted, independently globally novel threshold no-good clauses.
The clauses are appended to the immutable 1,032-clause Page-12 attic, the exact
evolved live priority bank and its state receipt are carried forward, and lineage 26 is
projected at the measured one-slot-sacrifice 253-clause residency limit.

The module has no native, solver, target, truth-key, model, or reveal
interface.  Preparation is in-memory; publication is a separate atomic
operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import struct
import sys
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c85_page10_transport_recovery_prepare as _publisher
from . import o1c87_page12_causal_rollover_prepare as _o1c87
from .causal_attic_v1 import (
    CausalAtticError,
    ParsedVaultTelemetry,
    canonical_json_bytes,
    parse_vault_telemetry,
    sha256_bytes,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    advance_causal_residency,
    replay_causal_residency,
    validate_activation_replay,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0089"
PARENT_ATTEMPT_ID = "O1C-0088"
PREPARATION_SCHEMA = "o1-256-o1c89-page13-causal-rollover-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_190040_615684_O1C-0088_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0088_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "8ae16f758ee4c5e1f489c7f9c5d40d2dc001037a9b215ca60f973432af953f84"
)
PARENT_CAPSULE_MANIFEST_BYTES = 2_768
PARENT_CAPSULE_ENTRY_COUNT = 29
PARENT_RESULT_SHA256 = (
    "f1f6807c99951eff9a274a882753e5d18867b56490de2f5dbd9646bf0cbe4ba0"
)
PARENT_RESULT_BYTES = 11_019
PARENT_EPISODE_SHA256 = (
    "0d7516919b10b977e827db431898968650c592def12c0c990f1491f8e44b3e08"
)
PARENT_EPISODE_BYTES = 3_616
PARENT_INTENT_SHA256 = (
    "78ec88934bd8a72fa4a8a4a6c65e71d0b0dcd428a80f424f87fa5c53c1a54568"
)
PARENT_INTENT_BYTES = 1_221
PARENT_VAULT_TELEMETRY_SHA256 = (
    "202d0a0059058e5d2b9d181a98c7cd8b77a6f873327928714bfa346e1e2cdadd"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_191_531
PARENT_PREPARATION_MANIFEST_SHA256 = (
    "64427e4861507e373cc02b52b9c0f2d25d62f26cf9362af681b9bc90ef4a57b6"
)
PARENT_PREPARATION_MANIFEST_BYTES = 6_910
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
PARENT_STOP_REASON = "globally-novel-clause"
PARENT_REQUESTED_CONFLICTS = 128
PARENT_ACTUAL_CONFLICTS = 55
GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = 1_032

PAGE12_SHA256 = _o1c87.PAGE12_SHA256
PAGE12_CLAUSE_COUNT = _o1c87.PAGE12_CLAUSE_COUNT
PAGE12_LITERAL_COUNT = _o1c87.PAGE12_LITERAL_COUNT
PAGE12_SERIALIZED_BYTES = _o1c87.PAGE12_SERIALIZED_BYTES
PAGE12_CLAUSE_AGGREGATE_SHA256 = (
    "5e1c1d6084d466eaeabcae19412f00298e42d10a907314a8cf3d6c1ad3b771db"
)
PARENT_INITIAL_ARTIFACT_COUNT = 10

NEW_CHUNK_SHA256 = "d02b2ca0fa8d54b11572427bdc1f450fb34fe52016ccbb197f14f0fefd2c0370"
NEW_CHUNK_CLAUSE_COUNT = 259
NEW_CHUNK_LITERAL_COUNT = 744_973
NEW_CHUNK_SERIALIZED_BYTES = 2_981_119
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "3c7b8e16ab6a08441eb80ff3705a357380cebc3697b1882791643be6934aeb38"
)

ATTIC_CHUNK_COUNT = 16
ATTIC_UNION_SHA256 = "d4ea6d6d1bf1dfa3560aa81737914624c40c2dd9dacfb7fee38badc2aabab726"
ATTIC_UNION_CLAUSE_COUNT = 1_291
ATTIC_UNION_LITERAL_COUNT = 3_590_320
ATTIC_UNION_SERIALIZED_BYTES = 14_366_635
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "f47d8263a0637e218eb569e51f525ca97dda88c112d6c9b7c2c6578b4c289de4"
)
ATTIC_OCCURRENCE_COUNT = 1_299
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 8
ATTIC_SUBSUMPTION_RELATION_COUNT = 10
ATTIC_UNDOMINATED_CLAUSE_COUNT = 1_284
OCCURRENCE_DOCUMENT_SHA256 = (
    "df24ce0f39f1af309005d02876aa1c0cff09a8b0a572ffdd12f9141e7d1c999a"
)
OCCURRENCE_DOCUMENT_BYTES = 460_695
RELATION_DOCUMENT_SHA256 = (
    "a062fc798aca7238892c685cafaf22e6dfb6c35ff7d52debbd3387ee0ae52ef1"
)
RELATION_DOCUMENT_BYTES = 8_551

PAGE13_SHA256 = "4c1b7d5a6d40fad9439d95433bcc7a60ff3e7ddc0e4542b0cf003cdf4581e546"
PAGE13_CLAUSE_COUNT = 253
PAGE13_LITERAL_COUNT = 711_355
PAGE13_SERIALIZED_BYTES = 2_846_623
PAGE13_CLAUSE_AGGREGATE_SHA256 = (
    "500eea654551ee9133eb0b80d5414d93866c27f6da258066ec24dda794994e08"
)
PAGE13_ACTIVE_LIMIT = 253
PAGE13_LINEAGE_ORDINAL = 26
PAGE13_CATEGORY_COUNTS = {
    "structural_root": 5,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 205,
    "hot_event": 0,
    "recycled": 0,
}
PAGE13_HEADROOM = {
    "clauses": 259,
    "literals": 888_645,
    "serialized_bytes": 5_541_985,
}
PAGE13_RESIDENCY_DOCUMENT_SHA256 = (
    "1159d4ea9663ef8765356f2aec2feb1a3a8de25fbec835244541271f6beb7c6a"
)
PAGE13_RESIDENCY_DOCUMENT_BYTES = 47_057
PAGE13_ACTIVATION_DOCUMENT_SHA256 = (
    "1e87257c3e7fe5aabe023328b66d3144534c8f1df0f2e29d1f7e6a095a7ebcef"
)
PAGE13_ACTIVATION_DOCUMENT_BYTES = 25_968
PAGE13_ACTIVATION_COUNT = 14
NEW_MISSING_UNION_INDICES = (
    1032,
    1036,
    1051,
    1055,
    1061,
    1069,
    1072,
    1089,
    1092,
    1093,
    1099,
    1105,
    1109,
    1111,
    1116,
    1120,
    1121,
    1123,
    1127,
    1132,
    1133,
    1136,
    1152,
    1185,
    1187,
    1190,
    1206,
    1209,
    1224,
    1230,
    1235,
    1238,
    1244,
    1247,
    1250,
    1256,
    1258,
    1260,
    1262,
    1265,
    1268,
    1270,
    1272,
    1273,
    1274,
    1276,
    1277,
    1279,
    1282,
    1284,
    1286,
    1287,
    1288,
    1290,
)
NEW_RESIDENT_UNION_INDICES = tuple(
    index
    for index in range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    if index not in frozenset(NEW_MISSING_UNION_INDICES)
)
NEW_STRICT_SUBSUMPTION_RELATION_COUNT = 0

NATIVE_VAULT_CAPS = {
    "maximum_clauses": 512,
    "maximum_literals": 1_600_000,
    "maximum_serialized_bytes": 8_388_608,
}
PARENT_CENTERED_ACTION_CAPACITY = 256

FINAL_BANK_SHA256 = "0203de9f1732b095bf30062cb8a07b018ded829ee99f18ffbca715c653c0cc6a"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "9ecec7df26d93de464bc779b19f5ccab22588b8f809c443987e62ce6265a8eb8"
)
PRIORITY_RECEIPT_BYTES = 52_009
CONTINUATION_RECORD_FORMAT = "<QddQQddQQddd"
CONTINUATION_RECORD = struct.Struct(CONTINUATION_RECORD_FORMAT)
CONTINUATION_RECORD_BYTES = 96
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

NEW_CHUNK_NAME = "lineage-26-new-chunk.vault"
ACTIVE_PROJECTION_NAME = "page-13-active.bin"
RESIDENCY_NAME = _o1c87.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c87.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c87.OCCURRENCES_NAME
RELATIONS_NAME = _o1c87.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c87.COMMON_CORE_AUDIT_NAME
COMMON_CORE_AUDIT_SHA256 = (
    "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c"
)
COMMON_CORE_AUDIT_BYTES = 20_115
FINAL_BANK_NAME = _o1c87.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = "o1c88-priority-state-receipt.json"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"
PREPARATION_MANIFEST_SHA256 = (
    "467e519df281db4fc10de9223195dfedba9fd51edc93b40883f59fd3821e29ec"
)
PREPARATION_MANIFEST_BYTES = 15_590

PreparedCausalRolloverArtifacts = _o1c87.PreparedCausalRolloverArtifacts


class O1C89PreparationError(RuntimeError):
    """An O1C-0088 seal or deterministic Page-13 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C89PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C89PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C89PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C89PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C89PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C89PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C89PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C89PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C89PreparationError("parent capsule manifest row differs")
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
            raise O1C89PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C89PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C89PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C89PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C89PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C89PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C89PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": FINAL_BANK_SHA256,
        "episodes/00/priority-state.json": PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c87.ACTIVE_PROJECTION_NAME}": PAGE12_SHA256,
        f"initial/{_o1c87.PREPARATION_MANIFEST_NAME}": (
            PARENT_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c87.OCCURRENCES_NAME}": (
            "91e706f34cbb733e3cb82199b27b16c158fcacae0e19c1b3cc80e719453ec191"
        ),
        f"initial/{_o1c87.RELATIONS_NAME}": (
            "eab1f23b76d8bc0613e3c05b364cfd3beb15b38a84c46a880029687c2466b7d9"
        ),
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C89PreparationError("parent capsule required seal differs")
    if "episodes/00/terminal-failure.json" in entries:
        raise O1C89PreparationError("parent successful episode boundary differs")
    return entries


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
    except OSError as exc:
        raise O1C89PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
    ):
        raise O1C89PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C89PreparationError("parent completed-call contract differs")
    episode = _mapping(episodes[0], "parent episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    science = _mapping(episode.get("science"), "parent science")
    final_bank = _mapping(episode.get("final_priority_bank"), "parent final bank")
    archived = _mapping(
        episode.get("archived_native_components"), "parent archived components"
    )
    archived_vault = _mapping(archived.get("vault.json"), "parent archived vault")
    archived_bank = _mapping(
        archived.get("final-parent-centered-priority-bank.bin"),
        "parent archived bank",
    )
    archived_state = _mapping(
        archived.get("priority-state.json"), "parent archived priority state"
    )
    resources = _mapping(result.get("resources"), "parent resources")
    expected_science = {
        "active_page12_new_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "actual_certified_prunes": 0,
        "attacker_valid_domain_reduction": 0,
        "attacker_valid_entropy_gain_bits": 0.0,
        "certified_closure": False,
        "certified_model_or_key": False,
        "failure_first_action_alone_is_science_gain": False,
        "fully_emitted_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "globally_novel_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "priority_or_differential_alone_is_science_gain": False,
        "science_gain": True,
        "threshold_prunes": NEW_CHUNK_CLAUSE_COUNT,
        "unconfirmed_crossing_alone_is_science_gain": False,
    }
    if (
        episode_document != episode
        or result.get("schema")
        != "o1-256-apple8-parent-centered-continuation-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("capsule") != DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("classification") != PARENT_CLASSIFICATION
        or result.get("stop_reason") != PARENT_STOP_REASON
        or result.get("science_gain") is not True
        or result.get("operational_activation") is not True
        or claim.get("global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or claim.get("page12_sha256") != PAGE12_SHA256
        or claim.get("page12_burned") is not True
        or claim.get("lineage25_only") is not True
        or claim.get("input_continuation_bank_sha256") != _o1c87.FINAL_BANK_SHA256
        or claim.get("priority_state_receipt_sha256")
        != _o1c87.PRIORITY_RECEIPT_SHA256
        or claim.get("page10_replay_authorized") is not False
        or claim.get("page11_replay_authorized") is not False
        or claim.get("page9_retry_or_replay_authorized") is not False
        or claim.get("retry_or_replay") is not False
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("fresh_reveal_calls") != 0
        or claim.get("refits") != 0
        or claim.get("rollover_manifest_sha256") != PARENT_PREPARATION_MANIFEST_SHA256
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("completed") is not True
        or episode.get("status") != 0
        or episode.get("lineage_call_ordinal") != 25
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page12_burned") is not True
        or episode.get("lineage25_burned") is not True
        or episode.get("page10_replay_authorized") is not False
        or episode.get("page11_replay_authorized") is not False
        or episode.get("page9_retry_or_replay_authorized") is not False
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or episode.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("actual_conflicts") != PARENT_ACTUAL_CONFLICTS
        or episode.get("billed_conflicts") != PARENT_ACTUAL_CONFLICTS
        or episode.get("terminal_failure") is not None
        or science != expected_science
        or final_bank
        != {
            "path": "final-parent-centered-priority-bank.bin",
            "serialized_bytes": FINAL_BANK_BYTES,
            "sha256": FINAL_BANK_SHA256,
        }
        or archived_vault
        != {
            "path": "vault.json",
            "serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "sha256": PARENT_VAULT_TELEMETRY_SHA256,
        }
        or archived_bank != final_bank
        or archived_state
        != {
            "path": "priority-state.json",
            "serialized_bytes": PRIORITY_RECEIPT_BYTES,
            "sha256": PRIORITY_RECEIPT_SHA256,
        }
        or resources.get("native_solver_calls") != 1
        or resources.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or resources.get("actual_conflicts") != PARENT_ACTUAL_CONFLICTS
        or resources.get("billed_conflicts") != PARENT_ACTUAL_CONFLICTS
    ):
        raise O1C89PreparationError("parent completed-call contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("lineage_call_ordinal") != 25
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page12_sha256") != PAGE12_SHA256
        or intent.get("page12_burned") is not True
        or intent.get("lineage25_burned") is not True
        or intent.get("continuation_bank_sha256") != _o1c87.FINAL_BANK_SHA256
        or intent.get("priority_state_receipt_sha256")
        != _o1c87.PRIORITY_RECEIPT_SHA256
        or intent.get("page10_replay_authorized") is not False
        or intent.get("page11_replay_authorized") is not False
        or intent.get("page9_retry_or_replay_authorized") is not False
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or intent.get("target_bytes_read") is not False
        or intent.get("truth_key_bytes_read") is not False
        or intent.get("rollover_manifest_sha256") != PARENT_PREPARATION_MANIFEST_SHA256
        or intent.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or intent.get("invocation_sha256") != episode.get("invocation_sha256")
    ):
        raise O1C89PreparationError("parent persisted intent contract differs")
    return result


def _regenerate_page12_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c87.prepare_o1c87_page12_causal_rollover()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C89PreparationError("O1C-0087 Page-12 regeneration differs") from exc
    expected_names = set(previous.artifacts)
    if expected_names != {
        _o1c87.ACTIVE_PROJECTION_NAME,
        _o1c87.RESIDENCY_NAME,
        _o1c87.ACTIVATION_LEDGER_NAME,
        _o1c87.OCCURRENCES_NAME,
        _o1c87.RELATIONS_NAME,
        _o1c87.COMMON_CORE_AUDIT_NAME,
        _o1c87.FINAL_BANK_NAME,
        _o1c87.PRIORITY_RECEIPT_NAME,
        _o1c87.NEW_CHUNK_NAME,
        _o1c87.PREPARATION_MANIFEST_NAME,
    }:
        raise O1C89PreparationError("O1C-0087 Page-12 inventory differs")
    initial = capsule / "initial"
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C89PreparationError("parent initial inventory is unreadable") from exc
    expected_initial_names = expected_names
    if (
        len(expected_initial_names) != PARENT_INITIAL_ARTIFACT_COUNT
        or {path.name for path in initial_children} != expected_initial_names
    ):
        raise O1C89PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C89PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C89PreparationError("parent initial artifact differs")
    state = previous.state
    if (
        state.current_projection.lineage_ordinal != 25
        or state.active_limit != _o1c87.PAGE12_ACTIVE_LIMIT
        or state.active_projection.sha256 != PAGE12_SHA256
        or state.active_projection.clause_count != PAGE12_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE12_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE12_SERIALIZED_BYTES
        or state.attic.union_vault.clause_count != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or len(state.activation_ledger) != 13
    ):
        raise O1C89PreparationError("parent Page-12 state differs")
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C89PreparationError("parent Page-12 replay differs") from exc
    return previous


def _parse_parent_telemetry(
    capsule: Path, previous: CausalResidencyState
) -> ParsedVaultTelemetry:
    path = capsule / "episodes/00/vault.json"
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C89PreparationError("parent vault telemetry is unreadable") from exc
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C89PreparationError("parent vault telemetry size differs")
    raw = _canonical_document(payload, "parent vault telemetry")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c88-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C89PreparationError("parent vault telemetry differs") from exc
    active = previous.active_projection
    aggregate = sha256_bytes(b"".join(clause.serialized for clause in active.clauses))
    occurrences = telemetry.occurrences
    known_sha256 = {clause.sha256 for clause in previous.attic.union_vault.clauses}
    occurrence_sha256 = {occurrence.clause_sha256 for occurrence in occurrences}
    expected_raw = {
        "input_sha256": PAGE12_SHA256,
        "input_clause_count": PAGE12_CLAUSE_COUNT,
        "input_literal_count": PAGE12_LITERAL_COUNT,
        "input_serialized_bytes": PAGE12_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": PAGE12_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": PAGE12_CLAUSE_COUNT,
        "validated_input_literal_count": PAGE12_LITERAL_COUNT,
        "fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "fully_emitted_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": NEW_CHUNK_CLAUSE_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": PAGE12_CLAUSE_COUNT,
        "preloaded_literal_count": PAGE12_LITERAL_COUNT,
        "next_vault_available": False,
        "next_vault_sha256": None,
        "next_clause_count": None,
        "next_literal_count": None,
        "next_serialized_bytes": None,
        "next_vault_terminal_reason": "capacity_clause_count",
        "maximum_clause_count": NATIVE_VAULT_CAPS["maximum_clauses"],
        "maximum_literal_count": NATIVE_VAULT_CAPS["maximum_literals"],
        "maximum_payload_bytes": NATIVE_VAULT_CAPS["maximum_serialized_bytes"],
        "pending_clause_exported": False,
        "terminal_empty_clause_count": 0,
    }
    if (
        any(raw.get(name) != value for name, value in expected_raw.items())
        or telemetry.input_identity != active.identity
        or telemetry.input_vault_sha256 != PAGE12_SHA256
        or telemetry.input_clause_count != PAGE12_CLAUSE_COUNT
        or telemetry.input_literal_count != PAGE12_LITERAL_COUNT
        or telemetry.input_serialized_bytes != PAGE12_SERIALIZED_BYTES
        or telemetry.input_clause_aggregate_sha256 != PAGE12_CLAUSE_AGGREGATE_SHA256
        or aggregate != PAGE12_CLAUSE_AGGREGATE_SHA256
        or len(occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or telemetry.new_occurrences != occurrences
        or any(occurrence.classification != "new" for occurrence in occurrences)
        or any(occurrence.source != "trail_upper_bound" for occurrence in occurrences)
        or len(occurrence_sha256) != NEW_CHUNK_CLAUSE_COUNT
        or occurrence_sha256 & known_sha256
        or len({occurrence.clause.serialized for occurrence in occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C89PreparationError("Page-12 telemetry novelty binding differs")
    return telemetry


def _new_chunk(
    previous: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            tuple(occurrence.clause for occurrence in telemetry.occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C89PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.describe().get("clause_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
    ):
        raise O1C89PreparationError("new immutable chunk seal differs")
    return chunk


def _advance_page13(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=PAGE13_LINEAGE_ORDINAL,
            next_active_limit=PAGE13_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        page_roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C89PreparationError("Page-13 causal rollover differs") from exc
    attic = state.attic
    page = state.active_projection
    occurrence_payload = canonical_json_bytes(attic.occurrence_document())
    relation_payload = canonical_json_bytes(attic.relation_document())
    residency_payload = canonical_json_bytes(state.describe())
    activation_payload = canonical_json_bytes(state.activation_ledger_document())
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - page.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - page.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - page.serialized_bytes,
    }
    union = attic.union_vault
    new_indices = tuple(
        range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    )
    selected = frozenset(state.current_projection.selected_union_indices)
    resident_new_indices = tuple(index for index in new_indices if index in selected)
    missing_new_indices = tuple(index for index in new_indices if index not in selected)
    new_relations = tuple(
        relation
        for relation in attic.relations
        if relation not in previous.attic.relations
    )
    if (
        page_roundtrip != page
        or replayed != state
        or state.current_projection.lineage_ordinal != PAGE13_LINEAGE_ORDINAL
        or state.active_limit != PAGE13_ACTIVE_LIMIT
        or attic.active_limit != PAGE13_ACTIVE_LIMIT
        or page.sha256 != PAGE13_SHA256
        or page.clause_count != PAGE13_CLAUSE_COUNT
        or page.literal_count != PAGE13_LITERAL_COUNT
        or page.serialized_bytes != PAGE13_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE13_CLAUSE_AGGREGATE_SHA256
        or state.current_projection.category_counts != PAGE13_CATEGORY_COUNTS
        or headroom != PAGE13_HEADROOM
        # This proves the current projection is inside every cap and the 259
        # clause slots cover all 259 emitted records.  Literal/byte residuals
        # are accounting only, not a future-emission safety guarantee.
        or O1C66_VAULT_CAPS.describe() != NATIVE_VAULT_CAPS
        or page.clause_count + headroom["clauses"] != O1C66_VAULT_CAPS.maximum_clauses
        or headroom["clauses"] != NEW_CHUNK_CLAUSE_COUNT
        or PAGE12_CLAUSE_COUNT + NEW_CHUNK_CLAUSE_COUNT
        != O1C66_VAULT_CAPS.maximum_clauses + 1
        or _o1c87.PAGE12_ACTIVE_LIMIT - state.active_limit != 1
        or state.current_projection.structural_root_indices
        != previous.current_projection.structural_root_indices
        or state.current_projection.pinned_core_indices
        != previous.current_projection.pinned_core_indices
        or len(attic.chunks) != ATTIC_CHUNK_COUNT
        or attic.chunks[:-1] != previous.attic.chunks
        or attic.chunks[-1] != chunk
        or attic.chunk_clause_union_indices[-1] != new_indices
        or union.clauses[: previous.attic.union_vault.clause_count]
        != previous.attic.union_vault.clauses
        or union.sha256 != ATTIC_UNION_SHA256
        or union.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or union.literal_count != ATTIC_UNION_LITERAL_COUNT
        or union.serialized_bytes != ATTIC_UNION_SERIALIZED_BYTES
        or union.describe().get("clause_aggregate_sha256")
        != ATTIC_UNION_CLAUSE_AGGREGATE_SHA256
        or attic.occurrences[: len(previous.attic.occurrences)]
        != previous.attic.occurrences
        or attic.occurrences[-NEW_CHUNK_CLAUSE_COUNT:] != telemetry.occurrences
        or attic.occurrence_union_indices[-NEW_CHUNK_CLAUSE_COUNT:] != new_indices
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or not set(previous.attic.relations).issubset(attic.relations)
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(new_relations) != NEW_STRICT_SUBSUMPTION_RELATION_COUNT
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or len(occurrence_payload) != OCCURRENCE_DOCUMENT_BYTES
        or sha256_bytes(occurrence_payload) != OCCURRENCE_DOCUMENT_SHA256
        or len(relation_payload) != RELATION_DOCUMENT_BYTES
        or sha256_bytes(relation_payload) != RELATION_DOCUMENT_SHA256
        or len(residency_payload) != PAGE13_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE13_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE13_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE13_ACTIVATION_DOCUMENT_SHA256
        or len(state.activation_ledger) != PAGE13_ACTIVATION_COUNT
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or page.sha256 in previous.used_active_sha256
        or resident_new_indices != NEW_RESIDENT_UNION_INDICES
        or missing_new_indices != NEW_MISSING_UNION_INDICES
        or state.never_resident_undominated_indices != NEW_MISSING_UNION_INDICES
    ):
        raise O1C89PreparationError("Page-13 rollover contract differs")
    return state


def _validate_evolved_continuation_bank(
    capsule: Path, bank: bytes
) -> tuple[bytes, dict[str, object]]:
    receipt_path = capsule / "episodes/00/priority-state.json"
    try:
        receipt_payload = receipt_path.read_bytes()
    except OSError as exc:
        raise O1C89PreparationError("priority-state receipt is unreadable") from exc
    if (
        len(bank) != FINAL_BANK_BYTES
        or sha256_bytes(bank) != FINAL_BANK_SHA256
        or len(receipt_payload) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt_payload) != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C89PreparationError("evolved continuation state differs")
    receipt = _canonical_document(receipt_payload, "evolved priority-state receipt")
    operator = _mapping(receipt.get("operator"), "evolved priority operator")
    operator_accounting = _mapping(
        operator.get("state_accounting"), "evolved priority operator accounting"
    )
    accounting = _mapping(
        receipt.get("state_accounting"), "evolved priority state accounting"
    )
    probe_counters = _mapping(
        receipt.get("probe_counters"), "evolved priority probe counters"
    )
    probe_trace = _mapping(receipt.get("probe_trace"), "evolved priority probe trace")
    hexadecimal = receipt.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C89PreparationError("evolved continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C89PreparationError("evolved continuation bank hex differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c87-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or receipt.get("bank_bytes") != FINAL_BANK_BYTES
        or receipt.get("current_bank_sha256") != FINAL_BANK_SHA256
        or receipt_bank != bank
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_rule")
        != "observed-key-variables-ascending;currently-unassigned-and-no-live-token"
        or receipt.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("one_shot_rule")
        != "coordinate-consumed-on-first-return;release-does-not-rearm"
        or receipt.get("consumed_coordinate_count") != 255
        or receipt.get("assignment_literals_observed") != 35_094
        or receipt.get("parent_scans") != 570
        or receipt.get("callback_calls") != 570
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 315
        or receipt.get("last_parent_candidate_count") != 1
        or operator.get("schema")
        != "o1-256-o1c82-parent-centered-priority-telemetry-v1"
        or operator.get("action_semantics") != "current-lower-upper-bound-proof-mining"
        or operator.get("belief_orientation_authorized") is not False
        or operator.get("proof_mining_action_only") is not True
        or operator.get("coordinate_capacity") != PARENT_CENTERED_ACTION_CAPACITY
        or operator.get("eligible_coordinate_count") != 255
        or operator.get("minimum_eligible_count") != 37
        or operator.get("current_parent_candidate_count") != 1
        or operator_accounting
        != {
            "packed_bytes_per_coordinate": 96,
            "coordinate_state_bytes": 24_576,
            "parent_scratch_bytes": 4_096,
            "live_packed_state_bytes": 28_672,
        }
        or accounting
        != {
            "priority_bank_bytes": 24_576,
            "parent_scratch_bytes": 4_096,
            "priority_live_state_bytes": 28_672,
            "consumed_mask_bytes": 256,
            "action_capacity": 256,
            "action_record_bytes": 176,
            "action_state_bytes": 45_056,
            "growing_parent_history_bytes": 0,
        }
        or probe_counters
        != {
            "BOTH_PRUNABLE": 90,
            "NEITHER_PRUNABLE": 33_302,
            "ONE_PRUNABLE": 18,
            "ZERO_PRUNABLE": 3,
            "child_bound_evaluations": 66_826,
        }
        or probe_trace
        != {
            "bytes": 1_904_541,
            "count": 33_413,
            "encoding": (
                "u64le-call;u64le-probe;u32le-candidate-index;"
                "u32le-parent-level;i32le-variable;f64le-U0;f64le-U1;"
                "f64le-tau;u8-selection;i32le-certified-literal"
            ),
            "record_bytes": 57,
            "sha256": (
                "f855eaaf484325aec4c14f7f0698d088008cda5e77114fc442f53bbaba6aa439"
            ),
        }
    ):
        raise O1C89PreparationError("evolved continuation bank receipt differs")

    records: list[tuple[object, ...]] = []
    for variable in range(1, 257):
        offset = (variable - 1) * CONTINUATION_RECORD_BYTES
        values = CONTINUATION_RECORD.unpack_from(bank, offset)
        count = cast(int, values[0])
        raw_positive = cast(int, values[3])
        raw_zero = cast(int, values[4])
        centered_positive = cast(int, values[7])
        centered_zero = cast(int, values[8])
        floats = tuple(
            cast(float, value) for value in (*values[1:3], *values[5:7], *values[9:12])
        )
        if (
            any(not math.isfinite(value) for value in floats)
            or cast(float, values[2]) < 0.0
            or cast(float, values[6]) < 0.0
            or raw_positive + raw_zero > count
            or centered_positive + centered_zero > count
            or cast(float, values[10]) < abs(cast(float, values[9]))
            or cast(float, values[11]) < cast(float, values[10])
        ):
            raise O1C89PreparationError("evolved continuation bank record differs")
        records.append(values)
    counts = tuple(cast(int, record[0]) for record in records)
    nonzero_counts = tuple(count for count in counts if count)
    if (
        bank[240 * CONTINUATION_RECORD_BYTES : 241 * CONTINUATION_RECORD_BYTES]
        != bytes(CONTINUATION_RECORD_BYTES)
        or tuple(index + 1 for index, count in enumerate(counts) if not count) != (241,)
        or len(nonzero_counts) != 255
        or min(nonzero_counts) != 200
        or max(nonzero_counts) != 1_752
        or tuple(index + 1 for index, count in enumerate(counts) if count == 1_752)
        != (21,)
        or sum(counts) != 215_781
        or sum(count >= 37 for count in counts) != 255
    ):
        raise O1C89PreparationError("evolved continuation bank population differs")
    continuation = {
        "validation_contract": "o1c87-live-continuation-bank-with-state-receipt",
        "receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        "receipt_artifact": PRIORITY_RECEIPT_NAME,
        "encoding": receipt["bank_encoding"],
        "coordinate_record_count": len(records),
        "record_bytes": CONTINUATION_RECORD_BYTES,
        "eligible_coordinate_count": 255,
        "zero_coordinate_variables": [241],
        "minimum_nonzero_evolved_count": min(nonzero_counts),
        "maximum_evolved_count": max(nonzero_counts),
        "maximum_evolved_count_variables": [21],
        "aggregate_evolved_count": sum(counts),
        "receipt_bank_hex_byte_equal": True,
        "fresh_seed_parser_compatible": False,
        "next_action_parser_gate": (
            "require-live-continuation-parser;do-not-use-fresh-seed-parser"
        ),
    }
    return receipt_payload, continuation


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c89_page13_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate O1C-0088 and return the exact Page-13 bundle in memory."""

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
    _validate_parent_result(capsule, result_path)
    previous = _regenerate_page12_and_validate_initial(capsule)
    telemetry = _parse_parent_telemetry(capsule, previous.state)
    chunk = _new_chunk(previous.state, telemetry)
    state = _advance_page13(previous.state, chunk, telemetry)

    bank_path = capsule / "episodes/00/final-parent-centered-priority-bank.bin"
    try:
        bank = bank_path.read_bytes()
    except OSError as exc:
        raise O1C89PreparationError(
            "evolved final priority bank is unreadable"
        ) from exc
    priority_receipt, continuation = _validate_evolved_continuation_bank(capsule, bank)
    audit_payload = previous.artifacts[_o1c87.COMMON_CORE_AUDIT_NAME]
    if (
        len(audit_payload) != COMMON_CORE_AUDIT_BYTES
        or sha256_bytes(audit_payload) != COMMON_CORE_AUDIT_SHA256
        or audit_payload
        != (capsule / "initial" / _o1c87.COMMON_CORE_AUDIT_NAME).read_bytes()
    ):
        raise O1C89PreparationError("historical common-core audit differs")

    artifacts: dict[str, bytes] = {
        NEW_CHUNK_NAME: chunk.serialized,
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        OCCURRENCES_NAME: canonical_json_bytes(state.attic.occurrence_document()),
        RELATIONS_NAME: canonical_json_bytes(state.attic.relation_document()),
        COMMON_CORE_AUDIT_NAME: audit_payload,
        FINAL_BANK_NAME: bank,
        PRIORITY_RECEIPT_NAME: priority_receipt,
    }
    roles = {
        NEW_CHUNK_NAME: "immutable-all-new-lineage-25-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-26-page13-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "complete-updated-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-updated-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "canonical-o1c88-evolved-priority-state-receipt",
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
            "page13_burned": False,
            "lineage26_burned": False,
            "page12_replay_authorized": False,
            "lineage25_replay_authorized": False,
            "page9_retry_or_replay_authorized": False,
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
            "preparation_manifest_sha256": PARENT_PREPARATION_MANIFEST_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "source_lineage_ordinal": 25,
            "source_active_sha256": PAGE12_SHA256,
            "page12_burned": True,
            "lineage25_burned": True,
            "retry_or_replay_authorized": False,
            "global_novelty_baseline_clause_count": (
                GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
            ),
            "initial_artifact_count": PARENT_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_page12_regeneration": True,
            "activation_ledger_prefix_preserved": True,
        },
        "science_boundary": {
            "imported_science_attempt_id": PARENT_ATTEMPT_ID,
            "imported_science_kind": "fully-emitted-globally-novel-clauses",
            "imported_fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "imported_globally_novel_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "imported_literal_count": NEW_CHUNK_LITERAL_COUNT,
            "all_sources": ["trail_upper_bound"],
            "all_classifications": ["new"],
            "page9_retry_imported": False,
            "o1c84_terminal_failure_imported_as_science": False,
            "priority_magnitude_imported_as_science": False,
        },
        "rollover": {
            "stream_id": telemetry.stream_id,
            "telemetry_sha256": telemetry.artifact_sha256,
            "telemetry_serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "source_active_sha256": PAGE12_SHA256,
            "chunk_sha256": chunk.sha256,
            "clause_count": chunk.clause_count,
            "literal_count": chunk.literal_count,
            "serialized_bytes": chunk.serialized_bytes,
            "all_occurrences_new": True,
            "all_occurrences_unique": True,
            "all_occurrences_globally_novel_against_1032_clause_attic": True,
            "source_counts": {"trail_upper_bound": NEW_CHUNK_CLAUSE_COUNT},
            "classification_counts": {"new": NEW_CHUNK_CLAUSE_COUNT},
            "api": (
                "advance_causal_residency(next_lineage_ordinal=26,"
                "next_active_limit=253)"
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
            "prior_1032_clause_union_is_exact_prefix": True,
            "prior_relation_set_preserved_exactly": True,
            "new_strict_subsumption_pair_count": (
                NEW_STRICT_SUBSUMPTION_RELATION_COUNT
            ),
            "new_strict_subsumption_relations": [],
        },
        "page13": {
            "lineage_ordinal": PAGE13_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE13_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
            "one_slot_residency_sacrifice": {
                "source_input_clause_count": PAGE12_CLAUSE_COUNT,
                "fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "unsacrificed_terminal_clause_count": (
                    PAGE12_CLAUSE_COUNT + NEW_CHUNK_CLAUSE_COUNT
                ),
                "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                    "maximum_clauses"
                ],
                "terminal_overflow_clause_count": 1,
                "prior_active_limit": _o1c87.PAGE12_ACTIVE_LIMIT,
                "next_active_limit": PAGE13_ACTIVE_LIMIT,
                "residency_slots_sacrificed": 1,
                "measured_clause_headroom": PAGE13_HEADROOM["clauses"],
                "structural_root_count_preserved": 5,
                "pinned_core_count_preserved": 43,
            },
            "new_clause_residency": {
                "new_union_index_start": GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT,
                "new_union_index_stop_exclusive": ATTIC_UNION_CLAUSE_COUNT,
                "attic_retained_clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "resident_clause_count": len(NEW_RESIDENT_UNION_INDICES),
                "resident_union_indices": list(NEW_RESIDENT_UNION_INDICES),
                "missing_clause_count": len(NEW_MISSING_UNION_INDICES),
                "missing_union_indices": list(NEW_MISSING_UNION_INDICES),
                "missing_clauses": [
                    {
                        "source_index": index
                        - GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT,
                        "union_index": index,
                        "clause_sha256": state.attic.union_vault.clauses[index].sha256,
                    }
                    for index in NEW_MISSING_UNION_INDICES
                ],
            },
            "native_capacity_proof": {
                "caps": NATIVE_VAULT_CAPS,
                "clause_headroom_guarantee": {
                    "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                        "maximum_clauses"
                    ],
                    "page13_input_clauses": PAGE13_CLAUSE_COUNT,
                    "maximum_additional_clauses_before_capacity_terminal": (
                        PAGE13_HEADROOM["clauses"]
                    ),
                    "parent_centered_action_capacity": (
                        PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "spare_clause_slots_beyond_action_capacity": (
                        PAGE13_HEADROOM["clauses"] - PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "proved_sufficient": True,
                },
                "recorded_residual_headroom": {
                    "literals": PAGE13_HEADROOM["literals"],
                    "serialized_bytes": PAGE13_HEADROOM["serialized_bytes"],
                },
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "carried_context": {
            "common_core_audit_artifact": COMMON_CORE_AUDIT_NAME,
            "common_core_audit_sha256": COMMON_CORE_AUDIT_SHA256,
            "common_core_audit_serialized_bytes": COMMON_CORE_AUDIT_BYTES,
            "common_core_audit_unchanged": True,
            "historical_failure_receipt_carried_forward": False,
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
            "priority_is_key_bit_belief": False,
            "semantic_role": "sealed-evolved-live-continuation-bytes",
            **continuation,
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }
    manifest_payload = canonical_json_bytes(manifest)
    if (
        _canonical_document(manifest_payload, "causal rollover manifest") != manifest
        or len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
    ):
        raise O1C89PreparationError("causal rollover manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c89_page13_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c89_page13_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C89PreparationError("prepared Page-13 bundle differs")
    expected_names = {
        NEW_CHUNK_NAME,
        ACTIVE_PROJECTION_NAME,
        RESIDENCY_NAME,
        ACTIVATION_LEDGER_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        COMMON_CORE_AUDIT_NAME,
        FINAL_BANK_NAME,
        PRIORITY_RECEIPT_NAME,
        PREPARATION_MANIFEST_NAME,
    }
    manifest = _mapping(prepared.manifest, "prepared Page-13 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-13 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE13_SERIALIZED_BYTES, PAGE13_SHA256),
        RESIDENCY_NAME: (
            PAGE13_RESIDENCY_DOCUMENT_BYTES,
            PAGE13_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE13_ACTIVATION_DOCUMENT_BYTES,
            PAGE13_ACTIVATION_DOCUMENT_SHA256,
        ),
        OCCURRENCES_NAME: (OCCURRENCE_DOCUMENT_BYTES, OCCURRENCE_DOCUMENT_SHA256),
        RELATIONS_NAME: (RELATION_DOCUMENT_BYTES, RELATION_DOCUMENT_SHA256),
        COMMON_CORE_AUDIT_NAME: (COMMON_CORE_AUDIT_BYTES, COMMON_CORE_AUDIT_SHA256),
        FINAL_BANK_NAME: (FINAL_BANK_BYTES, FINAL_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
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
        or prepared.state.active_projection.sha256 != PAGE13_SHA256
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
        raise O1C89PreparationError("prepared Page-13 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C89PreparationError("prepared Page-13 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-13 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C89PreparationError("prepared Page-13 artifact seal differs")


def write_prepared_o1c89_page13_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-13 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(
            prepared, output_dir
        )
    except _publisher.O1C85PreparationError as exc:
        raise O1C89PreparationError("Page-13 publication failed") from exc


def prepare_and_write_o1c89_page13_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-13 bundle."""

    prepared = prepare_o1c89_page13_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c89_page13_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0089's zero-call Page-13 rollover"
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
        prepared = prepare_o1c89_page13_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c89_page13_causal_rollover(prepared, args.output_dir)
    except (
        O1C89PreparationError,
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
    "ATTIC_CHUNK_COUNT",
    "ATTIC_OCCURRENCE_COUNT",
    "ATTIC_SUBSUMPTION_RELATION_COUNT",
    "ATTIC_UNDOMINATED_CLAUSE_COUNT",
    "ATTIC_UNION_CLAUSE_COUNT",
    "ATTIC_UNION_LITERAL_COUNT",
    "ATTIC_UNION_SERIALIZED_BYTES",
    "ATTIC_UNION_SHA256",
    "COMMON_CORE_AUDIT_NAME",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FINAL_BANK_BYTES",
    "FINAL_BANK_NAME",
    "FINAL_BANK_SHA256",
    "NEW_CHUNK_CLAUSE_COUNT",
    "NEW_CHUNK_LITERAL_COUNT",
    "NEW_CHUNK_NAME",
    "NEW_CHUNK_SERIALIZED_BYTES",
    "NEW_CHUNK_SHA256",
    "O1C89PreparationError",
    "OCCURRENCES_NAME",
    "PAGE13_ACTIVE_LIMIT",
    "PAGE13_CATEGORY_COUNTS",
    "PAGE13_CLAUSE_COUNT",
    "PAGE13_HEADROOM",
    "PAGE13_LITERAL_COUNT",
    "PAGE13_SERIALIZED_BYTES",
    "PAGE13_SHA256",
    "PARENT_CAPSULE_MANIFEST_SHA256",
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
    "preflight_o1c89_page13_causal_rollover",
    "prepare_and_write_o1c89_page13_causal_rollover",
    "prepare_o1c89_page13_causal_rollover",
    "write_prepared_o1c89_page13_causal_rollover",
]
