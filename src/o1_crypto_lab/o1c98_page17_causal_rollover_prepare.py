"""Zero-call O1C-0098 Page-17 causal-rollover preparation.

The only new scientific evidence consumed here is O1C-0097's sealed stream of
263 fully emitted threshold no-good occurrences.  Exactly 262 are globally
novel; one is a current-stream duplicate of an earlier emission.  The unique
clauses form a new immutable chunk while all occurrences remain in the ledger.
The exact evolved priority bank and receipt are carried forward, and lineage
30 is projected at a 249-clause limit so another 263-clause burst fits by
clause count exactly.

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
from . import o1c96_page16_transport_recovery_prepare as _o1c96
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


ATTEMPT_ID = "O1C-0098"
PARENT_ATTEMPT_ID = "O1C-0097"
PREPARATION_SCHEMA = "o1-256-o1c98-page17-causal-rollover-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_224639_665221_O1C-0097_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0097_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "b7d8712b2ade9e5b75ff0d2f76c11907fbcafb3f01cf6e260e82303c08ff0f42"
)
PARENT_CAPSULE_MANIFEST_BYTES = 2_780
PARENT_CAPSULE_ENTRY_COUNT = 29
PARENT_RESULT_SHA256 = (
    "19b47ac6512c073d8f2b646d864d81cedfa8f1c2b2a9999f974c119779ae79e3"
)
PARENT_RESULT_BYTES = 11_922
PARENT_EPISODE_SHA256 = (
    "12068c5a7171cd7d4b4d5bfa9821af70b26e9dbf574c6bccf7f3dd81b2c34029"
)
PARENT_EPISODE_BYTES = 3_758
PARENT_INTENT_SHA256 = (
    "956c3f5f0dfa56b7b2cab9f89da962038ceb116d6d59c672ea9ff41c56738888"
)
PARENT_INTENT_BYTES = 1_362
PARENT_VAULT_TELEMETRY_SHA256 = (
    "76998719a2b99415ab702e1b72d95bb2b88be0ea01afae098669326ab7a718c8"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_201_682
PARENT_PREPARATION_MANIFEST_SHA256 = (
    "68d42b0f4cfaaf8a5b03f4b61515a8032860623dd5517fc87dac87b087a1c7b7"
)
PARENT_PREPARATION_MANIFEST_BYTES = 6_414
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
PARENT_STOP_REASON = "globally-novel-clause"
PARENT_REQUESTED_CONFLICTS = 128
PARENT_ACTUAL_CONFLICTS = 21
GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = 1_812

PAGE16_SHA256 = _o1c96.PAGE16_SHA256
PAGE16_CLAUSE_COUNT = _o1c96.PAGE16_CLAUSE_COUNT
PAGE16_LITERAL_COUNT = _o1c96.PAGE16_LITERAL_COUNT
PAGE16_SERIALIZED_BYTES = _o1c96.PAGE16_SERIALIZED_BYTES
PAGE16_CLAUSE_AGGREGATE_SHA256 = (
    "53a0bdf2f0bc134e195b9edb4b3e97b6f98ca97da92cde6902551a9064c95666"
)
PARENT_INITIAL_ARTIFACT_COUNT = 10

NEW_CHUNK_SHA256 = "c5e9c357eb80c9a32e17c3cc19a1fa6ab2db11e50e5e0d2140fbe46865fee185"
NEW_CHUNK_CLAUSE_COUNT = 262
NEW_CHUNK_LITERAL_COUNT = 745_152
NEW_CHUNK_SERIALIZED_BYTES = 2_981_847
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "b30391bf7f1166176794d665b4d2aa8ffb52a1e8766444a42a3076c92de5c863"
)

FULLY_EMITTED_OCCURRENCE_COUNT = 263
FULLY_EMITTED_LITERAL_COUNT = 748_011
FULLY_EMITTED_AGGREGATE_SHA256 = (
    "da10972004b9e8145a8f07c071ca4a2da9df795018b0b4898aa49c0be5d1a98b"
)
CURRENT_DUPLICATE_EMISSION_INDEX = 7
CURRENT_DUPLICATE_SOURCE_INDEX = 6
CURRENT_DUPLICATE_CLAUSE_SHA256 = (
    "d479f1335c455aa61873154205c94b1a98cb050a0851fc8df65a5ed536baee2f"
)
CURRENT_DUPLICATE_LITERAL_COUNT = 2_859
CURRENT_DUPLICATE_WITNESS_SCORE = 13.293490727958314

ATTIC_CHUNK_COUNT = 19
ATTIC_UNION_SHA256 = "fbe18682bae134784684e4676dbb1fce1b78d4da27182fb67679a7317b3e9646"
ATTIC_UNION_CLAUSE_COUNT = 2_074
ATTIC_UNION_LITERAL_COUNT = 5_835_680
ATTIC_UNION_SERIALIZED_BYTES = 23_351_207
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "66b62de128dc28326bdd78db1067c913592a355ebfa41ad590200c7520f832c9"
)
ATTIC_OCCURRENCE_COUNT = 2_083
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 9
ATTIC_SUBSUMPTION_RELATION_COUNT = 14
ATTIC_UNDOMINATED_CLAUSE_COUNT = 2_063
OCCURRENCE_DOCUMENT_SHA256 = (
    "78a88fc2987767a56749ebf113b8acef440aa34b3c1f3fbdcc920e11759eb744"
)
OCCURRENCE_DOCUMENT_BYTES = 740_267
RELATION_DOCUMENT_SHA256 = (
    "c9b04416788b62496a7f189e3c252653a9c8ec683a50b592e9c6b887daa8608d"
)
RELATION_DOCUMENT_BYTES = 13_682

PAGE17_SHA256 = "0c25ce470df0945fb05914bab107ecea05531166575ec88ebf7d15bb9a22fbfd"
PAGE17_CLAUSE_COUNT = 249
PAGE17_LITERAL_COUNT = 693_183
PAGE17_SERIALIZED_BYTES = 2_773_919
PAGE17_CLAUSE_AGGREGATE_SHA256 = (
    "02e1c7a8ff2415b0cf85e8803869c2fd89ab6093efcd2d001edb5ddd84f9886b"
)
PAGE17_ACTIVE_LIMIT = 249
PAGE17_LINEAGE_ORDINAL = 30
PAGE17_CATEGORY_COUNTS = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 197,
    "hot_event": 0,
    "recycled": 0,
}
PAGE17_HEADROOM = {
    "clauses": 263,
    "literals": 906_817,
    "serialized_bytes": 5_614_689,
}
PAGE17_RESIDENCY_DOCUMENT_SHA256 = (
    "330d4b8c466977a0cf27fad96c24af233e82f6ac56ce3af8c83cb9895a7bc6fe"
)
PAGE17_RESIDENCY_DOCUMENT_BYTES = 59_608
PAGE17_ACTIVATION_DOCUMENT_SHA256 = (
    "5db5a1a4efde2067b2e89d6e7ca9487c2ae2e5f75013a74b4b128f91caccdfd4"
)
PAGE17_ACTIVATION_DOCUMENT_BYTES = 36_128
PAGE17_ACTIVATION_COUNT = 18
NEW_MISSING_UNION_INDICES = (
    1816, 1820, 1823, 1828, 1833, 1836, 1837, 1841, 1845, 1848,
    1850, 1852, 1854, 1855, 1856, 1857, 1862, 1870, 1872, 1874,
    1875, 1881, 1882, 1883, 1892, 1896, 1897, 1901, 1902, 1905,
    1906, 1908, 1910, 1912, 1913, 1916, 1917, 1919, 1924, 1925,
    1926, 1927, 1929, 1930, 1933, 1934, 1937, 1939, 1941, 1942,
    1946, 1947, 1951, 1954, 1955, 1957, 1958, 1960, 1964, 1965,
    1966, 1970, 1974, 1975, 1976,
)
NEW_RESIDENT_UNION_INDICES = tuple(
    index
    for index in range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    if index not in frozenset(NEW_MISSING_UNION_INDICES)
)
NEW_STRICT_SUBSUMPTION_RELATIONS: tuple[tuple[int, int], ...] = ()
NEW_STRICT_SUBSUMPTION_RELATION_COUNT = len(NEW_STRICT_SUBSUMPTION_RELATIONS)
NEW_STRUCTURAL_ROOT_UNION_INDICES: tuple[int, ...] = ()
NEW_DOMINATED_MISSING_UNION_INDICES: tuple[int, ...] = ()
NEW_UNDOMINATED_MISSING_UNION_INDICES = tuple(
    index
    for index in NEW_MISSING_UNION_INDICES
    if index not in frozenset(NEW_DOMINATED_MISSING_UNION_INDICES)
)
HISTORICAL_NEWLY_RESIDENT_UNION_INDICES: tuple[int, ...] = ()
HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES: tuple[int, ...] = ()
NEVER_RESIDENT_UNDOMINATED_INDICES = (
    HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
    + NEW_UNDOMINATED_MISSING_UNION_INDICES
)

NATIVE_VAULT_CAPS = {
    "maximum_clauses": 512,
    "maximum_literals": 1_600_000,
    "maximum_serialized_bytes": 8_388_608,
}
PARENT_CENTERED_ACTION_CAPACITY = 256

FINAL_BANK_SHA256 = "8100bccf7e463c11b41d97a07017202c5e7ffc37763a76d38114c3044f9fa2fc"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "050551fc658de62b54b7856996fba0418194c3c2f2608e04a8e9ccc2f51fedad"
)
PRIORITY_RECEIPT_BYTES = 52_011
CONTINUATION_RECORD_FORMAT = "<QddQQddQQddd"
CONTINUATION_RECORD = struct.Struct(CONTINUATION_RECORD_FORMAT)
CONTINUATION_RECORD_BYTES = 96
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

NEW_CHUNK_NAME = "lineage-30-new-chunk.vault"
ACTIVE_PROJECTION_NAME = "page-17-active.bin"
RESIDENCY_NAME = _o1c96.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c96.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c96.OCCURRENCES_NAME
RELATIONS_NAME = _o1c96.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c96.COMMON_CORE_AUDIT_NAME
COMMON_CORE_AUDIT_SHA256 = (
    "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c"
)
COMMON_CORE_AUDIT_BYTES = 20_115
FINAL_BANK_NAME = _o1c96.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = "o1c97-priority-state-receipt.json"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"
PREPARATION_MANIFEST_SHA256 = (
    "ba7ad5d9417542d62725ab588dea4a85bc7eff8847f5276bf79a847f44c5470d"
)
PREPARATION_MANIFEST_BYTES = 18_785

PreparedCausalRolloverArtifacts = _o1c96.PreparedCausalRolloverArtifacts


class O1C98PreparationError(RuntimeError):
    """An O1C-0097 seal or deterministic Page-17 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C98PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C98PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C98PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C98PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C98PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C98PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C98PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C98PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C98PreparationError("parent capsule manifest row differs")
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
            raise O1C98PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C98PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C98PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C98PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C98PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C98PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C98PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": FINAL_BANK_SHA256,
        "episodes/00/priority-state.json": PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c96.ACTIVE_PROJECTION_NAME}": PAGE16_SHA256,
        f"initial/{_o1c96.PREPARATION_MANIFEST_NAME}": (
            PARENT_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c96.OCCURRENCES_NAME}": (
            "f101a1799f2840e5a219dc3f932ec2318a5eab0000f7a565874fc2018dd5ef98"
        ),
        f"initial/{_o1c96.RELATIONS_NAME}": (
            "e2fb3072ede6a08a4d018fda320970757e71b9c48dc1547314a6a7f7c71e47c8"
        ),
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C98PreparationError("parent capsule required seal differs")
    if "episodes/00/terminal-failure.json" in entries:
        raise O1C98PreparationError("parent successful episode boundary differs")
    return entries


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
    except OSError as exc:
        raise O1C98PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
    ):
        raise O1C98PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C98PreparationError("parent completed-call contract differs")
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
        "active_page16_new_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "actual_certified_prunes": 0,
        "attacker_valid_domain_reduction": 0,
        "attacker_valid_entropy_gain_bits": 0.0,
        "certified_closure": False,
        "certified_model_or_key": False,
        "failure_first_action_alone_is_science_gain": False,
        "fully_emitted_clauses": FULLY_EMITTED_OCCURRENCE_COUNT,
        "globally_novel_clauses": NEW_CHUNK_CLAUSE_COUNT,
        "priority_or_differential_alone_is_science_gain": False,
        "science_gain": True,
        "threshold_prunes": FULLY_EMITTED_OCCURRENCE_COUNT,
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
        or claim.get("page16_sha256") != PAGE16_SHA256
        or claim.get("page16_burned") is not True
        or claim.get("lineage29_only") is not True
        or claim.get("input_continuation_bank_sha256")
        != _o1c96.CONTINUATION_BANK_SHA256
        or claim.get("priority_state_receipt_sha256")
        != _o1c96.PRIORITY_RECEIPT_SHA256
        or claim.get("page10_replay_authorized") is not False
        or claim.get("page11_replay_authorized") is not False
        or claim.get("page12_replay_authorized") is not False
        or claim.get("page13_replay_authorized") is not False
        or claim.get("page14_replay_authorized") is not False
        or claim.get("page15_retry_or_replay_authorized") is not False
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
        or episode.get("lineage_call_ordinal") != 29
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page16_burned") is not True
        or episode.get("lineage29_burned") is not True
        or episode.get("page10_replay_authorized") is not False
        or episode.get("page11_replay_authorized") is not False
        or episode.get("page12_replay_authorized") is not False
        or episode.get("page13_replay_authorized") is not False
        or episode.get("page14_replay_authorized") is not False
        or episode.get("page15_retry_or_replay_authorized") is not False
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
        raise O1C98PreparationError("parent completed-call contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("lineage_call_ordinal") != 29
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page16_sha256") != PAGE16_SHA256
        or intent.get("page16_burned") is not True
        or intent.get("lineage29_burned") is not True
        or intent.get("continuation_bank_sha256")
        != _o1c96.CONTINUATION_BANK_SHA256
        or intent.get("priority_state_receipt_sha256")
        != _o1c96.PRIORITY_RECEIPT_SHA256
        or intent.get("page10_replay_authorized") is not False
        or intent.get("page11_replay_authorized") is not False
        or intent.get("page12_replay_authorized") is not False
        or intent.get("page13_replay_authorized") is not False
        or intent.get("page14_replay_authorized") is not False
        or intent.get("page15_retry_or_replay_authorized") is not False
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
        raise O1C98PreparationError("parent persisted intent contract differs")
    return result


def _regenerate_page16_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c96.prepare_o1c96_page16_transport_recovery()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C98PreparationError("O1C-0096 Page-16 regeneration differs") from exc
    expected_names = set(previous.artifacts)
    if expected_names != {
        _o1c96.ACTIVE_PROJECTION_NAME,
        _o1c96.RESIDENCY_NAME,
        _o1c96.ACTIVATION_LEDGER_NAME,
        _o1c96.OCCURRENCES_NAME,
        _o1c96.RELATIONS_NAME,
        _o1c96.COMMON_CORE_AUDIT_NAME,
        _o1c96.FINAL_BANK_NAME,
        _o1c96.PRIORITY_RECEIPT_NAME,
        _o1c96.FAILURE_RECEIPT_NAME,
        _o1c96.PREPARATION_MANIFEST_NAME,
    }:
        raise O1C98PreparationError("O1C-0096 Page-16 inventory differs")
    initial = capsule / "initial"
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C98PreparationError("parent initial inventory is unreadable") from exc
    expected_initial_names = expected_names
    if (
        len(expected_initial_names) != PARENT_INITIAL_ARTIFACT_COUNT
        or {path.name for path in initial_children} != expected_initial_names
    ):
        raise O1C98PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C98PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C98PreparationError("parent initial artifact differs")
    state = previous.state
    if (
        state.current_projection.lineage_ordinal != 29
        or state.active_limit != _o1c96.PAGE16_ACTIVE_LIMIT
        or state.active_projection.sha256 != PAGE16_SHA256
        or state.active_projection.clause_count != PAGE16_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE16_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE16_SERIALIZED_BYTES
        or state.attic.union_vault.clause_count != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or len(state.activation_ledger) != 17
    ):
        raise O1C98PreparationError("parent Page-16 state differs")
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C98PreparationError("parent Page-16 replay differs") from exc
    return previous


def _parse_parent_telemetry(
    capsule: Path, previous: CausalResidencyState
) -> ParsedVaultTelemetry:
    path = capsule / "episodes/00/vault.json"
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C98PreparationError("parent vault telemetry is unreadable") from exc
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C98PreparationError("parent vault telemetry size differs")
    raw = _canonical_document(payload, "parent vault telemetry")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c97-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C98PreparationError("parent vault telemetry differs") from exc
    active = previous.active_projection
    aggregate = sha256_bytes(b"".join(clause.serialized for clause in active.clauses))
    occurrences = telemetry.occurrences
    known_sha256 = {clause.sha256 for clause in previous.attic.union_vault.clauses}
    occurrence_sha256 = {occurrence.clause_sha256 for occurrence in occurrences}
    expected_raw = {
        "input_sha256": PAGE16_SHA256,
        "input_clause_count": PAGE16_CLAUSE_COUNT,
        "input_literal_count": PAGE16_LITERAL_COUNT,
        "input_serialized_bytes": PAGE16_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": PAGE16_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": PAGE16_CLAUSE_COUNT,
        "validated_input_literal_count": PAGE16_LITERAL_COUNT,
        "fully_emitted_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
        "fully_emitted_literal_count": FULLY_EMITTED_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": FULLY_EMITTED_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 1,
        "emitted_current_duplicate_literal_count": CURRENT_DUPLICATE_LITERAL_COUNT,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": PAGE16_CLAUSE_COUNT,
        "preloaded_literal_count": PAGE16_LITERAL_COUNT,
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
        or telemetry.input_vault_sha256 != PAGE16_SHA256
        or telemetry.input_clause_count != PAGE16_CLAUSE_COUNT
        or telemetry.input_literal_count != PAGE16_LITERAL_COUNT
        or telemetry.input_serialized_bytes != PAGE16_SERIALIZED_BYTES
        or telemetry.input_clause_aggregate_sha256 != PAGE16_CLAUSE_AGGREGATE_SHA256
        or aggregate != PAGE16_CLAUSE_AGGREGATE_SHA256
        or len(occurrences) != FULLY_EMITTED_OCCURRENCE_COUNT
        or len(telemetry.new_occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or tuple(
            occurrence.source_index
            for occurrence in occurrences
            if occurrence.classification == "current_duplicate"
        )
        != (CURRENT_DUPLICATE_EMISSION_INDEX,)
        or occurrences[CURRENT_DUPLICATE_SOURCE_INDEX].classification != "new"
        or occurrences[CURRENT_DUPLICATE_SOURCE_INDEX].source_index
        != CURRENT_DUPLICATE_SOURCE_INDEX
        or occurrences[CURRENT_DUPLICATE_EMISSION_INDEX].clause
        != occurrences[CURRENT_DUPLICATE_SOURCE_INDEX].clause
        or occurrences[CURRENT_DUPLICATE_EMISSION_INDEX].clause_sha256
        != CURRENT_DUPLICATE_CLAUSE_SHA256
        or occurrences[CURRENT_DUPLICATE_EMISSION_INDEX].clause.literal_count
        != CURRENT_DUPLICATE_LITERAL_COUNT
        or occurrences[CURRENT_DUPLICATE_EMISSION_INDEX].witness_score
        != CURRENT_DUPLICATE_WITNESS_SCORE
        or occurrences[CURRENT_DUPLICATE_EMISSION_INDEX].witness_sha256
        != occurrences[CURRENT_DUPLICATE_SOURCE_INDEX].witness_sha256
        or any(
            occurrence.classification not in {"new", "current_duplicate"}
            for occurrence in occurrences
        )
        or any(occurrence.source != "trail_upper_bound" for occurrence in occurrences)
        or len(occurrence_sha256) != NEW_CHUNK_CLAUSE_COUNT
        or occurrence_sha256 & known_sha256
        or len({occurrence.clause.serialized for occurrence in occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C98PreparationError("Page-16 telemetry novelty binding differs")
    return telemetry


def _new_chunk(
    previous: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            tuple(occurrence.clause for occurrence in telemetry.new_occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C98PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.describe().get("clause_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
    ):
        raise O1C98PreparationError("new immutable chunk seal differs")
    return chunk


def _advance_page17(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=PAGE17_LINEAGE_ORDINAL,
            next_active_limit=PAGE17_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        page_roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C98PreparationError("Page-17 causal rollover differs") from exc
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
        relation for relation in attic.relations if relation not in previous.attic.relations
    )
    new_relation_pairs = tuple(
        (relation.subsumer_index, relation.subsumed_index)
        for relation in new_relations
    )
    new_structural_roots = tuple(
        index
        for index in state.current_projection.structural_root_indices
        if index not in previous.current_projection.structural_root_indices
    )
    dominated = frozenset(relation.subsumed_index for relation in attic.relations)
    dominated_missing_new_indices = tuple(
        index for index in missing_new_indices if index in dominated
    )
    undominated_missing_new_indices = tuple(
        index for index in missing_new_indices if index not in dominated
    )
    historical_never_resident = previous.never_resident_undominated_indices
    historical_newly_resident = tuple(
        index for index in historical_never_resident if index in selected
    )
    historical_still_never_resident = tuple(
        index for index in historical_never_resident if index not in selected
    )
    union_index_by_sha256 = {
        clause.sha256: index for index, clause in enumerate(union.clauses)
    }
    expected_occurrence_union_indices = tuple(
        union_index_by_sha256[occurrence.clause_sha256]
        for occurrence in telemetry.occurrences
    )
    if (
        page_roundtrip != page
        or replayed != state
        or state.current_projection.lineage_ordinal != PAGE17_LINEAGE_ORDINAL
        or state.active_limit != PAGE17_ACTIVE_LIMIT
        or attic.active_limit != PAGE17_ACTIVE_LIMIT
        or page.sha256 != PAGE17_SHA256
        or page.clause_count != PAGE17_CLAUSE_COUNT
        or page.literal_count != PAGE17_LITERAL_COUNT
        or page.serialized_bytes != PAGE17_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE17_CLAUSE_AGGREGATE_SHA256
        or state.current_projection.category_counts != PAGE17_CATEGORY_COUNTS
        or headroom != PAGE17_HEADROOM
        # Clause count alone proves a future equal 263-occurrence burst fits
        # exactly. Literal and byte residuals remain accounting only.
        or O1C66_VAULT_CAPS.describe() != NATIVE_VAULT_CAPS
        or page.clause_count + headroom["clauses"] != O1C66_VAULT_CAPS.maximum_clauses
        or headroom["clauses"] != FULLY_EMITTED_OCCURRENCE_COUNT
        or page.clause_count + FULLY_EMITTED_OCCURRENCE_COUNT
        != O1C66_VAULT_CAPS.maximum_clauses
        or _o1c96.PAGE16_ACTIVE_LIMIT - state.active_limit != 2
        or state.current_projection.structural_root_indices
        != previous.current_projection.structural_root_indices
        or new_structural_roots
        or state.current_projection.pinned_core_indices
        != previous.current_projection.pinned_core_indices
        or state.current_projection.inherited_debt_indices
        or state.current_projection.hot_event_indices
        or state.current_projection.recycled_indices
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
        or attic.occurrences[-FULLY_EMITTED_OCCURRENCE_COUNT:]
        != telemetry.occurrences
        or attic.occurrence_union_indices[-FULLY_EMITTED_OCCURRENCE_COUNT:]
        != expected_occurrence_union_indices
        or expected_occurrence_union_indices[CURRENT_DUPLICATE_EMISSION_INDEX]
        != expected_occurrence_union_indices[CURRENT_DUPLICATE_SOURCE_INDEX]
        or len(set(expected_occurrence_union_indices)) != NEW_CHUNK_CLAUSE_COUNT
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or attic.relations != previous.attic.relations
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or new_relations
        or new_relation_pairs
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or len(occurrence_payload) != OCCURRENCE_DOCUMENT_BYTES
        or sha256_bytes(occurrence_payload) != OCCURRENCE_DOCUMENT_SHA256
        or len(relation_payload) != RELATION_DOCUMENT_BYTES
        or sha256_bytes(relation_payload) != RELATION_DOCUMENT_SHA256
        or len(residency_payload) != PAGE17_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE17_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE17_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE17_ACTIVATION_DOCUMENT_SHA256
        or len(state.activation_ledger) != PAGE17_ACTIVATION_COUNT
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or page.sha256 in previous.used_active_sha256
        or resident_new_indices != NEW_RESIDENT_UNION_INDICES
        or missing_new_indices != NEW_MISSING_UNION_INDICES
        or dominated_missing_new_indices != NEW_DOMINATED_MISSING_UNION_INDICES
        or undominated_missing_new_indices
        != NEW_UNDOMINATED_MISSING_UNION_INDICES
        or set(state.current_projection.new_debt_indices)
        != set(resident_new_indices)
        or dominated_missing_new_indices
        or undominated_missing_new_indices != missing_new_indices
        or historical_never_resident
        or historical_newly_resident
        or historical_still_never_resident
        or state.never_resident_undominated_indices != missing_new_indices
        or union.clauses[1_960].sha256
        != "93b78aba548d831615283bb517a6a10e1cf6a296b0cdd2802b085fcb7ec8d805"
        or 1_960 not in missing_new_indices
    ):
        raise O1C98PreparationError("Page-17 rollover contract differs")
    return state


def _validate_evolved_continuation_bank(
    capsule: Path, bank: bytes
) -> tuple[bytes, dict[str, object]]:
    receipt_path = capsule / "episodes/00/priority-state.json"
    try:
        receipt_payload = receipt_path.read_bytes()
    except OSError as exc:
        raise O1C98PreparationError("priority-state receipt is unreadable") from exc
    if (
        len(bank) != FINAL_BANK_BYTES
        or sha256_bytes(bank) != FINAL_BANK_SHA256
        or len(receipt_payload) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt_payload) != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C98PreparationError("evolved continuation state differs")
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
        raise O1C98PreparationError("evolved continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C98PreparationError("evolved continuation bank hex differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c97-live-parent-centered-continuation-priority-state-v1"
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
        or receipt.get("assignment_literals_observed") != 46_426
        or receipt.get("parent_scans") != 533
        or receipt.get("callback_calls") != 533
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 278
        or receipt.get("last_parent_candidate_count") != 2
        or operator.get("schema")
        != "o1-256-o1c82-parent-centered-priority-telemetry-v1"
        or operator.get("action_semantics") != "current-lower-upper-bound-proof-mining"
        or operator.get("belief_orientation_authorized") is not False
        or operator.get("proof_mining_action_only") is not True
        or operator.get("coordinate_capacity") != PARENT_CENTERED_ACTION_CAPACITY
        or operator.get("eligible_coordinate_count") != 255
        or operator.get("minimum_eligible_count") != 37
        or operator.get("current_parent_candidate_count") != 2
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
            "BOTH_PRUNABLE": 6,
            "NEITHER_PRUNABLE": 33_224,
            "ONE_PRUNABLE": 3,
            "ZERO_PRUNABLE": 10,
            "child_bound_evaluations": 66_486,
        }
        or probe_trace
        != {
            "bytes": 1_894_851,
            "count": 33_243,
            "encoding": (
                "u64le-call;u64le-probe;u32le-candidate-index;"
                "u32le-parent-level;i32le-variable;f64le-U0;f64le-U1;"
                "f64le-tau;u8-selection;i32le-certified-literal"
            ),
            "record_bytes": 57,
            "sha256": (
                "44ed2fd741e0beeaf56a6058ffb026d92780464717a332d0a797df681eb321bc"
            ),
        }
    ):
        raise O1C98PreparationError("evolved continuation bank receipt differs")

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
            raise O1C98PreparationError("evolved continuation bank record differs")
        records.append(values)
    counts = tuple(cast(int, record[0]) for record in records)
    nonzero_counts = tuple(count for count in counts if count)
    if (
        bank[240 * CONTINUATION_RECORD_BYTES : 241 * CONTINUATION_RECORD_BYTES]
        != bytes(CONTINUATION_RECORD_BYTES)
        or tuple(index + 1 for index, count in enumerate(counts) if not count) != (241,)
        or len(nonzero_counts) != 255
        or min(nonzero_counts) != 230
        or max(nonzero_counts) != 2_921
        or tuple(index + 1 for index, count in enumerate(counts) if count == 2_921)
        != (15,)
        or sum(counts) != 316_312
        or sum(count >= 37 for count in counts) != 255
    ):
        raise O1C98PreparationError("evolved continuation bank population differs")
    continuation = {
        "validation_contract": "o1c97-live-continuation-bank-with-state-receipt",
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
        "maximum_evolved_count_variables": [15],
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


def prepare_o1c98_page17_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate O1C-0097 and return the exact Page-17 bundle in memory."""

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
    previous = _regenerate_page16_and_validate_initial(capsule)
    telemetry = _parse_parent_telemetry(capsule, previous.state)
    chunk = _new_chunk(previous.state, telemetry)
    state = _advance_page17(previous.state, chunk, telemetry)

    bank_path = capsule / "episodes/00/final-parent-centered-priority-bank.bin"
    try:
        bank = bank_path.read_bytes()
    except OSError as exc:
        raise O1C98PreparationError(
            "evolved final priority bank is unreadable"
        ) from exc
    priority_receipt, continuation = _validate_evolved_continuation_bank(capsule, bank)
    audit_payload = previous.artifacts[_o1c96.COMMON_CORE_AUDIT_NAME]
    try:
        parent_audit_payload = (
            capsule / "initial" / _o1c96.COMMON_CORE_AUDIT_NAME
        ).read_bytes()
    except OSError as exc:
        raise O1C98PreparationError(
            "historical common-core audit is unreadable"
        ) from exc
    if (
        len(audit_payload) != COMMON_CORE_AUDIT_BYTES
        or sha256_bytes(audit_payload) != COMMON_CORE_AUDIT_SHA256
        or audit_payload != parent_audit_payload
    ):
        raise O1C98PreparationError("historical common-core audit differs")

    new_indices = tuple(
        range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    )
    selected = frozenset(state.current_projection.selected_union_indices)
    resident_new_indices = tuple(index for index in new_indices if index in selected)
    missing_new_indices = tuple(index for index in new_indices if index not in selected)
    dominated = frozenset(
        relation.subsumed_index for relation in state.attic.relations
    )
    dominated_missing_new_indices = tuple(
        index for index in missing_new_indices if index in dominated
    )
    undominated_missing_new_indices = tuple(
        index for index in missing_new_indices if index not in dominated
    )

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
        NEW_CHUNK_NAME: "immutable-unique-lineage-29-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-30-page17-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "complete-updated-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-updated-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "canonical-o1c97-evolved-priority-state-receipt",
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
            "page17_burned": False,
            "lineage30_burned": False,
            "page16_replay_authorized": False,
            "lineage29_replay_authorized": False,
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
            "preparation_manifest_sha256": PARENT_PREPARATION_MANIFEST_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "source_lineage_ordinal": 29,
            "source_active_sha256": PAGE16_SHA256,
            "page16_burned": True,
            "lineage29_burned": True,
            "retry_or_replay_authorized": False,
            "global_novelty_baseline_clause_count": (
                GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
            ),
            "initial_artifact_count": PARENT_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_page16_regeneration": True,
            "activation_ledger_prefix_preserved": True,
        },
        "science_boundary": {
            "imported_science_attempt_id": PARENT_ATTEMPT_ID,
            "imported_science_kind": (
                "fully-emitted-occurrences-with-globally-novel-unique-clauses"
            ),
            "imported_fully_emitted_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
            "imported_fully_emitted_literal_count": FULLY_EMITTED_LITERAL_COUNT,
            "imported_globally_novel_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "imported_globally_novel_literal_count": NEW_CHUNK_LITERAL_COUNT,
            "imported_current_duplicate_clause_count": 1,
            "imported_current_duplicate_literal_count": (
                CURRENT_DUPLICATE_LITERAL_COUNT
            ),
            "all_sources": ["trail_upper_bound"],
            "all_classifications": ["current_duplicate", "new"],
            "historical_failed_or_retry_evidence_imported": False,
            "priority_state_magnitude_alone_imported_as_science": False,
        },
        "rollover": {
            "stream_id": telemetry.stream_id,
            "telemetry_sha256": telemetry.artifact_sha256,
            "telemetry_serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "source_active_sha256": PAGE16_SHA256,
            "chunk_sha256": chunk.sha256,
            "clause_count": chunk.clause_count,
            "literal_count": chunk.literal_count,
            "serialized_bytes": chunk.serialized_bytes,
            "all_occurrences_new": False,
            "all_occurrences_unique": False,
            "all_distinct_clauses_globally_novel_against_1812_clause_attic": True,
            "fully_emitted_occurrence_count": FULLY_EMITTED_OCCURRENCE_COUNT,
            "source_counts": {
                "trail_upper_bound": FULLY_EMITTED_OCCURRENCE_COUNT
            },
            "classification_counts": {
                "current_duplicate": 1,
                "new": NEW_CHUNK_CLAUSE_COUNT,
            },
            "current_duplicate": {
                "emission_index": CURRENT_DUPLICATE_EMISSION_INDEX,
                "duplicate_source_emission_index": (
                    CURRENT_DUPLICATE_SOURCE_INDEX
                ),
                "clause_sha256": CURRENT_DUPLICATE_CLAUSE_SHA256,
                "literal_count": CURRENT_DUPLICATE_LITERAL_COUNT,
                "witness_score": CURRENT_DUPLICATE_WITNESS_SCORE,
                "witness_sha256": telemetry.occurrences[
                    CURRENT_DUPLICATE_EMISSION_INDEX
                ].witness_sha256,
            },
            "api": (
                "advance_causal_residency(next_lineage_ordinal=30,"
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
            "prior_1812_clause_union_is_exact_prefix": True,
            "prior_relation_set_preserved_exactly": True,
            "new_strict_subsumption_pair_count": (
                NEW_STRICT_SUBSUMPTION_RELATION_COUNT
            ),
            "new_strict_subsumption_relations": [
                relation.describe(state.attic.union_vault.clauses)
                for relation in state.attic.relations
                if relation not in previous.state.attic.relations
            ],
        },
        "page17": {
            "lineage_ordinal": PAGE17_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE17_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
            "two_slot_residency_sacrifice": {
                "source_input_clause_count": PAGE16_CLAUSE_COUNT,
                "fully_emitted_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
                "unsacrificed_terminal_clause_count": (
                    PAGE16_CLAUSE_COUNT + FULLY_EMITTED_OCCURRENCE_COUNT
                ),
                "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                    "maximum_clauses"
                ],
                "terminal_overflow_clause_count": 2,
                "prior_active_limit": _o1c96.PAGE16_ACTIVE_LIMIT,
                "next_active_limit": PAGE17_ACTIVE_LIMIT,
                "residency_slots_sacrificed": 2,
                "measured_clause_headroom": PAGE17_HEADROOM["clauses"],
                "prior_structural_root_count": len(
                    previous.state.current_projection.structural_root_indices
                ),
                "new_structural_root_count": 0,
                "next_structural_root_count": len(
                    state.current_projection.structural_root_indices
                ),
                "pinned_core_count_preserved": len(
                    state.current_projection.pinned_core_indices
                ),
            },
            "new_clause_residency": {
                "new_union_index_start": GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT,
                "new_union_index_stop_exclusive": ATTIC_UNION_CLAUSE_COUNT,
                "attic_retained_clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "resident_clause_count": len(resident_new_indices),
                "resident_union_indices": list(resident_new_indices),
                "missing_clause_count": len(missing_new_indices),
                "missing_union_indices": list(missing_new_indices),
                "dominated_missing_clause_count": len(
                    dominated_missing_new_indices
                ),
                "dominated_missing_union_indices": list(
                    dominated_missing_new_indices
                ),
                "undominated_missing_clause_count": len(
                    undominated_missing_new_indices
                ),
                "undominated_missing_union_indices": list(
                    undominated_missing_new_indices
                ),
                "missing_clauses": [
                    {
                        "source_index": index
                        - GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT,
                        "union_index": index,
                        "clause_sha256": state.attic.union_vault.clauses[index].sha256,
                    }
                    for index in missing_new_indices
                ],
            },
            "historical_never_resident_undominated": {
                "prior_clause_count": 0,
                "newly_resident_clause_count": 0,
                "newly_resident_union_indices": [],
                "remaining_clause_count": 0,
                "remaining_union_indices": [],
            },
            "never_resident_undominated": {
                "clause_count": len(state.never_resident_undominated_indices),
                "historical_clause_count": 0,
                "new_undominated_missing_clause_count": len(
                    undominated_missing_new_indices
                ),
                "union_indices": list(state.never_resident_undominated_indices),
            },
            "native_capacity_proof": {
                "caps": NATIVE_VAULT_CAPS,
                "clause_headroom_guarantee": {
                    "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                        "maximum_clauses"
                    ],
                    "page17_input_clauses": PAGE17_CLAUSE_COUNT,
                    "maximum_additional_clauses_before_capacity_terminal": (
                        PAGE17_HEADROOM["clauses"]
                    ),
                    "parent_centered_action_capacity": (
                        PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "spare_clause_slots_beyond_action_capacity": (
                        PAGE17_HEADROOM["clauses"] - PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "equal_parent_burst_clause_count": (
                        FULLY_EMITTED_OCCURRENCE_COUNT
                    ),
                    "equal_parent_burst_fits_exactly": True,
                    "proved_sufficient": True,
                },
                "recorded_residual_headroom": {
                    "literals": PAGE17_HEADROOM["literals"],
                    "serialized_bytes": PAGE17_HEADROOM["serialized_bytes"],
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
        raise O1C98PreparationError(
            "causal rollover manifest differs: "
            f"bytes={len(manifest_payload)}, sha256={sha256_bytes(manifest_payload)}"
        )
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c98_page17_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c98_page17_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C98PreparationError("prepared Page-17 bundle differs")
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
    manifest = _mapping(prepared.manifest, "prepared Page-17 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-17 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE17_SERIALIZED_BYTES, PAGE17_SHA256),
        RESIDENCY_NAME: (
            PAGE17_RESIDENCY_DOCUMENT_BYTES,
            PAGE17_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE17_ACTIVATION_DOCUMENT_BYTES,
            PAGE17_ACTIVATION_DOCUMENT_SHA256,
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
        or prepared.state.active_projection.sha256 != PAGE17_SHA256
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
        raise O1C98PreparationError("prepared Page-17 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C98PreparationError("prepared Page-17 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-17 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C98PreparationError("prepared Page-17 artifact seal differs")


def write_prepared_o1c98_page17_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-17 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(
            prepared, output_dir
        )
    except _publisher.O1C85PreparationError as exc:
        raise O1C98PreparationError("Page-17 publication failed") from exc


def prepare_and_write_o1c98_page17_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-17 bundle."""

    prepared = prepare_o1c98_page17_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c98_page17_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0098's zero-call Page-17 rollover"
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
        prepared = prepare_o1c98_page17_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c98_page17_causal_rollover(prepared, args.output_dir)
    except (
        O1C98PreparationError,
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
    "NEW_DOMINATED_MISSING_UNION_INDICES",
    "NEW_MISSING_UNION_INDICES",
    "NEW_RESIDENT_UNION_INDICES",
    "NEW_STRICT_SUBSUMPTION_RELATIONS",
    "NEW_UNDOMINATED_MISSING_UNION_INDICES",
    "NEVER_RESIDENT_UNDOMINATED_INDICES",
    "HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES",
    "HISTORICAL_NEWLY_RESIDENT_UNION_INDICES",
    "O1C98PreparationError",
    "OCCURRENCES_NAME",
    "PAGE17_ACTIVE_LIMIT",
    "PAGE17_CATEGORY_COUNTS",
    "PAGE17_CLAUSE_COUNT",
    "PAGE17_HEADROOM",
    "PAGE17_LITERAL_COUNT",
    "PAGE17_SERIALIZED_BYTES",
    "PAGE17_SHA256",
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
    "preflight_o1c98_page17_causal_rollover",
    "prepare_and_write_o1c98_page17_causal_rollover",
    "prepare_o1c98_page17_causal_rollover",
    "write_prepared_o1c98_page17_causal_rollover",
]
