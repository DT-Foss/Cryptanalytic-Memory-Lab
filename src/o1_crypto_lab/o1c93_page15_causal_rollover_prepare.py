"""Zero-call O1C-0093 Page-15 causal-rollover preparation.

The only new scientific evidence consumed here is O1C-0092's sealed set of
261 fully emitted, independently globally novel threshold no-good clauses.
The clauses are appended to the immutable 1,551-clause Page-14 attic, the exact
evolved live priority bank and its state receipt are carried forward, and lineage 28 is
projected at the measured one-slot-sacrifice 251-clause residency limit.

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
from . import o1c91_page14_causal_rollover_prepare as _o1c91
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


ATTEMPT_ID = "O1C-0093"
PARENT_ATTEMPT_ID = "O1C-0092"
PREPARATION_SCHEMA = "o1-256-o1c93-page15-causal-rollover-preparation-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_205659_306771_O1C-0092_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0092_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260720.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "b91e23706c1a019c30f4de016f4f78e8da3494416e9a5fc69043b5c2fb890eae"
)
PARENT_CAPSULE_MANIFEST_BYTES = 2_768
PARENT_CAPSULE_ENTRY_COUNT = 29
PARENT_RESULT_SHA256 = (
    "04c4d7673898dd35d9c613ed0f1676dd8f3a60f01b04167b02660b93adfcc16c"
)
PARENT_RESULT_BYTES = 11_768
PARENT_EPISODE_SHA256 = (
    "03cc0e2f1f3a846a30c77443bd4d1d42471926e9530a51e1c8e8ab01562efa35"
)
PARENT_EPISODE_BYTES = 3_682
PARENT_INTENT_SHA256 = (
    "a2c3f9704755d47bf7cd8158b42cedce423a24e10b5a901f2e43e0f3864fc66e"
)
PARENT_INTENT_BYTES = 1_287
PARENT_VAULT_TELEMETRY_SHA256 = (
    "8cb5123d0867923a778ef08d64f73b71f51f8c41003b913da183f21e91dbd61b"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_265_088
PARENT_PREPARATION_MANIFEST_SHA256 = (
    "e46ca7373bc3a94efc30dcd309728005e3bee8b93983dc2c396f45bd487dd458"
)
PARENT_PREPARATION_MANIFEST_BYTES = 20_129
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
PARENT_STOP_REASON = "globally-novel-clause"
PARENT_REQUESTED_CONFLICTS = 128
PARENT_ACTUAL_CONFLICTS = 10
GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = 1_551

PAGE14_SHA256 = _o1c91.PAGE14_SHA256
PAGE14_CLAUSE_COUNT = _o1c91.PAGE14_CLAUSE_COUNT
PAGE14_LITERAL_COUNT = _o1c91.PAGE14_LITERAL_COUNT
PAGE14_SERIALIZED_BYTES = _o1c91.PAGE14_SERIALIZED_BYTES
PAGE14_CLAUSE_AGGREGATE_SHA256 = (
    "a3acfa37ba4d7865124e2f84ac500996f4d6ec8993a58666a43870ab02a66455"
)
PARENT_INITIAL_ARTIFACT_COUNT = 10

NEW_CHUNK_SHA256 = "5a548f933ab4624aab8c70b3a169e2d47ab284bac55ac853764e725b357f8838"
NEW_CHUNK_CLAUSE_COUNT = 261
NEW_CHUNK_LITERAL_COUNT = 756_414
NEW_CHUNK_SERIALIZED_BYTES = 3_026_891
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "dad3883312e769efb4a650557a8cd0fdf0e53e0ca6ecbc840fb335c76730fce0"
)

ATTIC_CHUNK_COUNT = 18
ATTIC_UNION_SHA256 = "d8b9d1d8adadacfede38e9bb278240fcb463c9d0d91b48bca45db0c8a740ae9b"
ATTIC_UNION_CLAUSE_COUNT = 1_812
ATTIC_UNION_LITERAL_COUNT = 5_090_528
ATTIC_UNION_SERIALIZED_BYTES = 20_369_551
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "6c89cab91db5f5fe7360e2107202cbc1fa5aace84680e35b877c5ba302843e37"
)
ATTIC_OCCURRENCE_COUNT = 1_820
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 8
ATTIC_SUBSUMPTION_RELATION_COUNT = 14
ATTIC_UNDOMINATED_CLAUSE_COUNT = 1_801
OCCURRENCE_DOCUMENT_SHA256 = (
    "f101a1799f2840e5a219dc3f932ec2318a5eab0000f7a565874fc2018dd5ef98"
)
OCCURRENCE_DOCUMENT_BYTES = 646_472
RELATION_DOCUMENT_SHA256 = (
    "e2fb3072ede6a08a4d018fda320970757e71b9c48dc1547314a6a7f7c71e47c8"
)
RELATION_DOCUMENT_BYTES = 12_372

PAGE15_SHA256 = "71f4b544fd74c7979386bf607d82902dc03c4fe1485404fe8fb7111e970ecfe2"
PAGE15_CLAUSE_COUNT = 251
PAGE15_LITERAL_COUNT = 710_463
PAGE15_SERIALIZED_BYTES = 2_843_047
PAGE15_CLAUSE_AGGREGATE_SHA256 = (
    "67af511a84193c8880c628da5c2cfe1e5d3e2e8a56985de908b9afd7669f442b"
)
PAGE15_ACTIVE_LIMIT = 251
PAGE15_LINEAGE_ORDINAL = 28
PAGE15_CATEGORY_COUNTS = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 199,
    "hot_event": 0,
    "recycled": 0,
}
PAGE15_HEADROOM = {
    "clauses": 261,
    "literals": 889_537,
    "serialized_bytes": 5_545_561,
}
PAGE15_RESIDENCY_DOCUMENT_SHA256 = (
    "66fe9694b1f421021104915c489800fadfc65bb4ac69be5d59d56af39c8ebad7"
)
PAGE15_RESIDENCY_DOCUMENT_BYTES = 55_166
PAGE15_ACTIVATION_DOCUMENT_SHA256 = (
    "69e3e5c25abf185db261178227ef2fab13afdaec2caf5763e2449b346c58b026"
)
PAGE15_ACTIVATION_DOCUMENT_BYTES = 31_938
PAGE15_ACTIVATION_COUNT = 16
NEW_MISSING_UNION_INDICES = (
    1552, 1553, 1556, 1557, 1560, 1561, 1564, 1566, 1570, 1576,
    1577, 1583, 1584, 1589, 1590, 1591, 1592, 1593, 1598, 1599,
    1601, 1602, 1605, 1606, 1608, 1610, 1613, 1614, 1615, 1616,
    1620, 1621, 1622, 1631, 1638, 1643, 1645, 1646, 1648, 1649,
    1651, 1657, 1658, 1659, 1662, 1665, 1667, 1674, 1675, 1681,
    1683, 1684, 1685, 1686, 1688, 1690, 1691, 1693, 1695, 1697,
    1698, 1699, 1700, 1704, 1705, 1709, 1710, 1711, 1712, 1714,
    1717, 1720, 1728, 1729, 1731, 1733, 1735, 1737, 1740, 1741,
    1746, 1749, 1752, 1758, 1760, 1761, 1762, 1764, 1772, 1774,
    1780, 1782, 1783, 1784, 1791, 1794, 1800, 1801, 1807, 1808,
    1810,
)
NEW_RESIDENT_UNION_INDICES = tuple(
    index
    for index in range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    if index not in frozenset(NEW_MISSING_UNION_INDICES)
)
NEW_STRICT_SUBSUMPTION_RELATIONS = ((1554, 1553),)
NEW_STRICT_SUBSUMPTION_RELATION_COUNT = len(NEW_STRICT_SUBSUMPTION_RELATIONS)
NEW_STRUCTURAL_ROOT_UNION_INDICES = tuple(
    subsumer for subsumer, _ in NEW_STRICT_SUBSUMPTION_RELATIONS
)
NEW_DOMINATED_MISSING_UNION_INDICES = tuple(
    subsumed for _, subsumed in NEW_STRICT_SUBSUMPTION_RELATIONS
)
NEW_UNDOMINATED_MISSING_UNION_INDICES = tuple(
    index
    for index in NEW_MISSING_UNION_INDICES
    if index not in frozenset(NEW_DOMINATED_MISSING_UNION_INDICES)
)
HISTORICAL_NEWLY_RESIDENT_UNION_INDICES = (
    1036, 1051, 1069, 1092, 1093, 1099, 1109, 1116, 1120, 1123,
    1132, 1133, 1152, 1185, 1187, 1206, 1230, 1238, 1244, 1247,
    1250, 1256, 1258, 1260, 1262, 1265, 1268, 1270, 1272, 1273,
    1274, 1276, 1277, 1279, 1282, 1284, 1286, 1287, 1288, 1290,
)
HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES = tuple(
    index
    for index in _o1c91.NEVER_RESIDENT_UNDOMINATED_INDICES
    if index not in frozenset(HISTORICAL_NEWLY_RESIDENT_UNION_INDICES)
)
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

FINAL_BANK_SHA256 = "97a325c91b9a853a094fcc8b7fd9fafdafe6b5ec4022952e1a86af068c834fca"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "1c69bb329819ff873758e72ccfd69649310e5dd089c68665c34d0a287821c1e6"
)
PRIORITY_RECEIPT_BYTES = 52_014
CONTINUATION_RECORD_FORMAT = "<QddQQddQQddd"
CONTINUATION_RECORD = struct.Struct(CONTINUATION_RECORD_FORMAT)
CONTINUATION_RECORD_BYTES = 96
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

NEW_CHUNK_NAME = "lineage-28-new-chunk.vault"
ACTIVE_PROJECTION_NAME = "page-15-active.bin"
RESIDENCY_NAME = _o1c91.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c91.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c91.OCCURRENCES_NAME
RELATIONS_NAME = _o1c91.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c91.COMMON_CORE_AUDIT_NAME
COMMON_CORE_AUDIT_SHA256 = (
    "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c"
)
COMMON_CORE_AUDIT_BYTES = 20_115
FINAL_BANK_NAME = _o1c91.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = "o1c92-priority-state-receipt.json"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"
PREPARATION_MANIFEST_SHA256 = (
    "187f09309b2d866549441d713f29bfed696c140f5c5a99536001c889f5836a24"
)
PREPARATION_MANIFEST_BYTES = 24_136

PreparedCausalRolloverArtifacts = _o1c91.PreparedCausalRolloverArtifacts


class O1C93PreparationError(RuntimeError):
    """An O1C-0092 seal or deterministic Page-15 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C93PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C93PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C93PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C93PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C93PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C93PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C93PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C93PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C93PreparationError("parent capsule manifest row differs")
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
            raise O1C93PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C93PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C93PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C93PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        candidate_metadata = candidate.lstat()
        if stat.S_ISLNK(candidate_metadata.st_mode):
            raise O1C93PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(candidate_metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(candidate_metadata.st_mode):
            raise O1C93PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C93PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": FINAL_BANK_SHA256,
        "episodes/00/priority-state.json": PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c91.ACTIVE_PROJECTION_NAME}": PAGE14_SHA256,
        f"initial/{_o1c91.PREPARATION_MANIFEST_NAME}": (
            PARENT_PREPARATION_MANIFEST_SHA256
        ),
        f"initial/{_o1c91.OCCURRENCES_NAME}": (
            "a0769b0b64242ec54cb8571d42a853a5c47a19ac51c4eb59be296a681402f8c6"
        ),
        f"initial/{_o1c91.RELATIONS_NAME}": (
            "bf27c8e86c80be816940a85f875df5356334dfc83a824d5b7b3de40937601af1"
        ),
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C93PreparationError("parent capsule required seal differs")
    if "episodes/00/terminal-failure.json" in entries:
        raise O1C93PreparationError("parent successful episode boundary differs")
    return entries


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
    except OSError as exc:
        raise O1C93PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
    ):
        raise O1C93PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(episodes) != 1:
        raise O1C93PreparationError("parent completed-call contract differs")
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
        "active_page14_new_clauses": NEW_CHUNK_CLAUSE_COUNT,
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
        or claim.get("page14_sha256") != PAGE14_SHA256
        or claim.get("page14_burned") is not True
        or claim.get("lineage27_only") is not True
        or claim.get("input_continuation_bank_sha256") != _o1c91.FINAL_BANK_SHA256
        or claim.get("priority_state_receipt_sha256")
        != _o1c91.PRIORITY_RECEIPT_SHA256
        or claim.get("page10_replay_authorized") is not False
        or claim.get("page11_replay_authorized") is not False
        or claim.get("page12_replay_authorized") is not False
        or claim.get("page13_replay_authorized") is not False
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
        or episode.get("lineage_call_ordinal") != 27
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page14_burned") is not True
        or episode.get("lineage27_burned") is not True
        or episode.get("page10_replay_authorized") is not False
        or episode.get("page11_replay_authorized") is not False
        or episode.get("page12_replay_authorized") is not False
        or episode.get("page13_replay_authorized") is not False
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
        raise O1C93PreparationError("parent completed-call contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("lineage_call_ordinal") != 27
        or intent.get("local_episode_ordinal") != 0
        or intent.get("page14_sha256") != PAGE14_SHA256
        or intent.get("page14_burned") is not True
        or intent.get("lineage27_burned") is not True
        or intent.get("continuation_bank_sha256") != _o1c91.FINAL_BANK_SHA256
        or intent.get("priority_state_receipt_sha256")
        != _o1c91.PRIORITY_RECEIPT_SHA256
        or intent.get("page10_replay_authorized") is not False
        or intent.get("page11_replay_authorized") is not False
        or intent.get("page12_replay_authorized") is not False
        or intent.get("page13_replay_authorized") is not False
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
        raise O1C93PreparationError("parent persisted intent contract differs")
    return result


def _regenerate_page14_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c91.prepare_o1c91_page14_causal_rollover()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C93PreparationError("O1C-0091 Page-14 regeneration differs") from exc
    expected_names = set(previous.artifacts)
    if expected_names != {
        _o1c91.ACTIVE_PROJECTION_NAME,
        _o1c91.RESIDENCY_NAME,
        _o1c91.ACTIVATION_LEDGER_NAME,
        _o1c91.OCCURRENCES_NAME,
        _o1c91.RELATIONS_NAME,
        _o1c91.COMMON_CORE_AUDIT_NAME,
        _o1c91.FINAL_BANK_NAME,
        _o1c91.PRIORITY_RECEIPT_NAME,
        _o1c91.NEW_CHUNK_NAME,
        _o1c91.PREPARATION_MANIFEST_NAME,
    }:
        raise O1C93PreparationError("O1C-0091 Page-14 inventory differs")
    initial = capsule / "initial"
    try:
        initial_children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C93PreparationError("parent initial inventory is unreadable") from exc
    expected_initial_names = expected_names
    if (
        len(expected_initial_names) != PARENT_INITIAL_ARTIFACT_COUNT
        or {path.name for path in initial_children} != expected_initial_names
    ):
        raise O1C93PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C93PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C93PreparationError("parent initial artifact differs")
    state = previous.state
    if (
        state.current_projection.lineage_ordinal != 27
        or state.active_limit != _o1c91.PAGE14_ACTIVE_LIMIT
        or state.active_projection.sha256 != PAGE14_SHA256
        or state.active_projection.clause_count != PAGE14_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE14_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE14_SERIALIZED_BYTES
        or state.attic.union_vault.clause_count != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or len(state.activation_ledger) != 15
    ):
        raise O1C93PreparationError("parent Page-14 state differs")
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C93PreparationError("parent Page-14 replay differs") from exc
    return previous


def _parse_parent_telemetry(
    capsule: Path, previous: CausalResidencyState
) -> ParsedVaultTelemetry:
    path = capsule / "episodes/00/vault.json"
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C93PreparationError("parent vault telemetry is unreadable") from exc
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C93PreparationError("parent vault telemetry size differs")
    raw = _canonical_document(payload, "parent vault telemetry")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c92-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C93PreparationError("parent vault telemetry differs") from exc
    active = previous.active_projection
    aggregate = sha256_bytes(b"".join(clause.serialized for clause in active.clauses))
    occurrences = telemetry.occurrences
    known_sha256 = {clause.sha256 for clause in previous.attic.union_vault.clauses}
    occurrence_sha256 = {occurrence.clause_sha256 for occurrence in occurrences}
    expected_raw = {
        "input_sha256": PAGE14_SHA256,
        "input_clause_count": PAGE14_CLAUSE_COUNT,
        "input_literal_count": PAGE14_LITERAL_COUNT,
        "input_serialized_bytes": PAGE14_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": PAGE14_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": PAGE14_CLAUSE_COUNT,
        "validated_input_literal_count": PAGE14_LITERAL_COUNT,
        "fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "fully_emitted_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": NEW_CHUNK_CLAUSE_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": PAGE14_CLAUSE_COUNT,
        "preloaded_literal_count": PAGE14_LITERAL_COUNT,
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
        or telemetry.input_vault_sha256 != PAGE14_SHA256
        or telemetry.input_clause_count != PAGE14_CLAUSE_COUNT
        or telemetry.input_literal_count != PAGE14_LITERAL_COUNT
        or telemetry.input_serialized_bytes != PAGE14_SERIALIZED_BYTES
        or telemetry.input_clause_aggregate_sha256 != PAGE14_CLAUSE_AGGREGATE_SHA256
        or aggregate != PAGE14_CLAUSE_AGGREGATE_SHA256
        or len(occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or telemetry.new_occurrences != occurrences
        or any(occurrence.classification != "new" for occurrence in occurrences)
        or any(occurrence.source != "trail_upper_bound" for occurrence in occurrences)
        or len(occurrence_sha256) != NEW_CHUNK_CLAUSE_COUNT
        or occurrence_sha256 & known_sha256
        or len({occurrence.clause.serialized for occurrence in occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C93PreparationError("Page-14 telemetry novelty binding differs")
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
        raise O1C93PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.describe().get("clause_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
    ):
        raise O1C93PreparationError("new immutable chunk seal differs")
    return chunk


def _advance_page15(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=PAGE15_LINEAGE_ORDINAL,
            next_active_limit=PAGE15_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        page_roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C93PreparationError("Page-15 causal rollover differs") from exc
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
    new_relation_pairs = tuple(
        (relation.subsumer_index, relation.subsumed_index)
        for relation in new_relations
    )
    new_structural_roots = tuple(
        index
        for index in state.current_projection.structural_root_indices
        if index not in previous.current_projection.structural_root_indices
    )
    dominated = frozenset(
        relation.subsumed_index for relation in attic.relations
    )
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
    if (
        page_roundtrip != page
        or replayed != state
        or state.current_projection.lineage_ordinal != PAGE15_LINEAGE_ORDINAL
        or state.active_limit != PAGE15_ACTIVE_LIMIT
        or attic.active_limit != PAGE15_ACTIVE_LIMIT
        or page.sha256 != PAGE15_SHA256
        or page.clause_count != PAGE15_CLAUSE_COUNT
        or page.literal_count != PAGE15_LITERAL_COUNT
        or page.serialized_bytes != PAGE15_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE15_CLAUSE_AGGREGATE_SHA256
        or state.current_projection.category_counts != PAGE15_CATEGORY_COUNTS
        or headroom != PAGE15_HEADROOM
        # This proves the current projection is inside every cap and the 261
        # clause slots cover all 261 emitted records.  Literal/byte residuals
        # are accounting only, not a future-emission safety guarantee.
        or O1C66_VAULT_CAPS.describe() != NATIVE_VAULT_CAPS
        or page.clause_count + headroom["clauses"] != O1C66_VAULT_CAPS.maximum_clauses
        or headroom["clauses"] != NEW_CHUNK_CLAUSE_COUNT
        or PAGE14_CLAUSE_COUNT + NEW_CHUNK_CLAUSE_COUNT
        != O1C66_VAULT_CAPS.maximum_clauses + 1
        or _o1c91.PAGE14_ACTIVE_LIMIT - state.active_limit != 1
        or not set(previous.current_projection.structural_root_indices).issubset(
            state.current_projection.structural_root_indices
        )
        or new_structural_roots != NEW_STRUCTURAL_ROOT_UNION_INDICES
        or tuple(subsumer for subsumer, _ in new_relation_pairs)
        != new_structural_roots
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
        or new_relation_pairs != NEW_STRICT_SUBSUMPTION_RELATIONS
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or len(occurrence_payload) != OCCURRENCE_DOCUMENT_BYTES
        or sha256_bytes(occurrence_payload) != OCCURRENCE_DOCUMENT_SHA256
        or len(relation_payload) != RELATION_DOCUMENT_BYTES
        or sha256_bytes(relation_payload) != RELATION_DOCUMENT_SHA256
        or len(residency_payload) != PAGE15_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE15_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE15_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE15_ACTIVATION_DOCUMENT_SHA256
        or len(state.activation_ledger) != PAGE15_ACTIVATION_COUNT
        or state.activation_ledger[:-1] != previous.activation_ledger
        or state.used_active_sha256[:-1] != previous.used_active_sha256
        or page.sha256 in previous.used_active_sha256
        or resident_new_indices != NEW_RESIDENT_UNION_INDICES
        or missing_new_indices != NEW_MISSING_UNION_INDICES
        or dominated_missing_new_indices != NEW_DOMINATED_MISSING_UNION_INDICES
        or undominated_missing_new_indices
        != NEW_UNDOMINATED_MISSING_UNION_INDICES
        or historical_never_resident
        != _o1c91.NEVER_RESIDENT_UNDOMINATED_INDICES
        or historical_newly_resident
        != HISTORICAL_NEWLY_RESIDENT_UNION_INDICES
        or historical_still_never_resident
        != HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
        or set(historical_still_never_resident)
        & set(NEW_UNDOMINATED_MISSING_UNION_INDICES)
        or state.never_resident_undominated_indices
        != NEVER_RESIDENT_UNDOMINATED_INDICES
    ):
        raise O1C93PreparationError("Page-15 rollover contract differs")
    return state


def _validate_evolved_continuation_bank(
    capsule: Path, bank: bytes
) -> tuple[bytes, dict[str, object]]:
    receipt_path = capsule / "episodes/00/priority-state.json"
    try:
        receipt_payload = receipt_path.read_bytes()
    except OSError as exc:
        raise O1C93PreparationError("priority-state receipt is unreadable") from exc
    if (
        len(bank) != FINAL_BANK_BYTES
        or sha256_bytes(bank) != FINAL_BANK_SHA256
        or len(receipt_payload) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt_payload) != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C93PreparationError("evolved continuation state differs")
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
        raise O1C93PreparationError("evolved continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C93PreparationError("evolved continuation bank hex differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c92-live-parent-centered-continuation-priority-state-v1"
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
        or receipt.get("assignment_literals_observed") != 58_054
        or receipt.get("parent_scans") != 521
        or receipt.get("callback_calls") != 521
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 266
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
            "BOTH_PRUNABLE": 2,
            "NEITHER_PRUNABLE": 33_394,
            "ONE_PRUNABLE": 1,
            "ZERO_PRUNABLE": 1,
            "child_bound_evaluations": 66_796,
        }
        or probe_trace
        != {
            "bytes": 1_903_686,
            "count": 33_398,
            "encoding": (
                "u64le-call;u64le-probe;u32le-candidate-index;"
                "u32le-parent-level;i32le-variable;f64le-U0;f64le-U1;"
                "f64le-tau;u8-selection;i32le-certified-literal"
            ),
            "record_bytes": 57,
            "sha256": (
                "47689ebee922bca37548727fefe9227ab69178850e0acb9a1fa913960a51d6c9"
            ),
        }
    ):
        raise O1C93PreparationError("evolved continuation bank receipt differs")

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
            raise O1C93PreparationError("evolved continuation bank record differs")
        records.append(values)
    counts = tuple(cast(int, record[0]) for record in records)
    nonzero_counts = tuple(count for count in counts if count)
    if (
        bank[240 * CONTINUATION_RECORD_BYTES : 241 * CONTINUATION_RECORD_BYTES]
        != bytes(CONTINUATION_RECORD_BYTES)
        or tuple(index + 1 for index, count in enumerate(counts) if not count) != (241,)
        or len(nonzero_counts) != 255
        or min(nonzero_counts) != 227
        or max(nonzero_counts) != 2_675
        or tuple(index + 1 for index, count in enumerate(counts) if count == 2_675)
        != (15,)
        or sum(counts) != 283_069
        or sum(count >= 37 for count in counts) != 255
    ):
        raise O1C93PreparationError("evolved continuation bank population differs")
    continuation = {
        "validation_contract": "o1c92-live-continuation-bank-with-state-receipt",
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


def prepare_o1c93_page15_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Validate O1C-0092 and return the exact Page-15 bundle in memory."""

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
    previous = _regenerate_page14_and_validate_initial(capsule)
    telemetry = _parse_parent_telemetry(capsule, previous.state)
    chunk = _new_chunk(previous.state, telemetry)
    state = _advance_page15(previous.state, chunk, telemetry)

    bank_path = capsule / "episodes/00/final-parent-centered-priority-bank.bin"
    try:
        bank = bank_path.read_bytes()
    except OSError as exc:
        raise O1C93PreparationError(
            "evolved final priority bank is unreadable"
        ) from exc
    priority_receipt, continuation = _validate_evolved_continuation_bank(capsule, bank)
    audit_payload = previous.artifacts[_o1c91.COMMON_CORE_AUDIT_NAME]
    if (
        len(audit_payload) != COMMON_CORE_AUDIT_BYTES
        or sha256_bytes(audit_payload) != COMMON_CORE_AUDIT_SHA256
        or audit_payload
        != (capsule / "initial" / _o1c91.COMMON_CORE_AUDIT_NAME).read_bytes()
    ):
        raise O1C93PreparationError("historical common-core audit differs")

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
        NEW_CHUNK_NAME: "immutable-all-new-lineage-27-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-28-page15-science-input",
        RESIDENCY_NAME: "complete-updated-causal-residency-state",
        ACTIVATION_LEDGER_NAME: "complete-updated-replayable-activation-ledger",
        OCCURRENCES_NAME: "complete-updated-compact-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-updated-strict-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "canonical-o1c92-evolved-priority-state-receipt",
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
            "page15_burned": False,
            "lineage28_burned": False,
            "page14_replay_authorized": False,
            "lineage27_replay_authorized": False,
            "page13_replay_authorized": False,
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
            "source_lineage_ordinal": 27,
            "source_active_sha256": PAGE14_SHA256,
            "page14_burned": True,
            "lineage27_burned": True,
            "retry_or_replay_authorized": False,
            "global_novelty_baseline_clause_count": (
                GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
            ),
            "initial_artifact_count": PARENT_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_page14_regeneration": True,
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
            "source_active_sha256": PAGE14_SHA256,
            "chunk_sha256": chunk.sha256,
            "clause_count": chunk.clause_count,
            "literal_count": chunk.literal_count,
            "serialized_bytes": chunk.serialized_bytes,
            "all_occurrences_new": True,
            "all_occurrences_unique": True,
            "all_occurrences_globally_novel_against_1551_clause_attic": True,
            "source_counts": {"trail_upper_bound": NEW_CHUNK_CLAUSE_COUNT},
            "classification_counts": {"new": NEW_CHUNK_CLAUSE_COUNT},
            "api": (
                "advance_causal_residency(next_lineage_ordinal=28,"
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
            "prior_1551_clause_union_is_exact_prefix": True,
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
        "page15": {
            "lineage_ordinal": PAGE15_LINEAGE_ORDINAL,
            "active_limit": state.active_limit,
            "active_sha256": state.active_projection.sha256,
            "clause_count": state.active_projection.clause_count,
            "literal_count": state.active_projection.literal_count,
            "serialized_bytes": state.active_projection.serialized_bytes,
            "category_counts": state.current_projection.category_counts,
            "headroom": PAGE15_HEADROOM,
            "fresh_identity": state.active_projection.sha256
            not in previous.state.used_active_sha256,
            "one_slot_residency_sacrifice": {
                "source_input_clause_count": PAGE14_CLAUSE_COUNT,
                "fully_emitted_clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "unsacrificed_terminal_clause_count": (
                    PAGE14_CLAUSE_COUNT + NEW_CHUNK_CLAUSE_COUNT
                ),
                "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                    "maximum_clauses"
                ],
                "terminal_overflow_clause_count": 1,
                "prior_active_limit": _o1c91.PAGE14_ACTIVE_LIMIT,
                "next_active_limit": PAGE15_ACTIVE_LIMIT,
                "residency_slots_sacrificed": 1,
                "measured_clause_headroom": PAGE15_HEADROOM["clauses"],
                "prior_structural_root_count": len(
                    previous.state.current_projection.structural_root_indices
                ),
                "new_structural_root_count": len(
                    NEW_STRUCTURAL_ROOT_UNION_INDICES
                ),
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
                "resident_clause_count": len(NEW_RESIDENT_UNION_INDICES),
                "resident_union_indices": list(NEW_RESIDENT_UNION_INDICES),
                "missing_clause_count": len(NEW_MISSING_UNION_INDICES),
                "missing_union_indices": list(NEW_MISSING_UNION_INDICES),
                "dominated_missing_clause_count": len(
                    NEW_DOMINATED_MISSING_UNION_INDICES
                ),
                "dominated_missing_union_indices": list(
                    NEW_DOMINATED_MISSING_UNION_INDICES
                ),
                "undominated_missing_clause_count": len(
                    NEW_UNDOMINATED_MISSING_UNION_INDICES
                ),
                "undominated_missing_union_indices": list(
                    NEW_UNDOMINATED_MISSING_UNION_INDICES
                ),
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
            "historical_never_resident_undominated": {
                "prior_clause_count": len(
                    _o1c91.NEVER_RESIDENT_UNDOMINATED_INDICES
                ),
                "newly_resident_clause_count": len(
                    HISTORICAL_NEWLY_RESIDENT_UNION_INDICES
                ),
                "newly_resident_union_indices": list(
                    HISTORICAL_NEWLY_RESIDENT_UNION_INDICES
                ),
                "remaining_clause_count": len(
                    HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
                ),
                "remaining_union_indices": list(
                    HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
                ),
            },
            "never_resident_undominated": {
                "clause_count": len(NEVER_RESIDENT_UNDOMINATED_INDICES),
                "historical_clause_count": len(
                    HISTORICAL_NEVER_RESIDENT_UNDOMINATED_INDICES
                ),
                "new_undominated_missing_clause_count": len(
                    NEW_UNDOMINATED_MISSING_UNION_INDICES
                ),
                "union_indices": list(NEVER_RESIDENT_UNDOMINATED_INDICES),
            },
            "native_capacity_proof": {
                "caps": NATIVE_VAULT_CAPS,
                "clause_headroom_guarantee": {
                    "native_vault_maximum_clauses": NATIVE_VAULT_CAPS[
                        "maximum_clauses"
                    ],
                    "page15_input_clauses": PAGE15_CLAUSE_COUNT,
                    "maximum_additional_clauses_before_capacity_terminal": (
                        PAGE15_HEADROOM["clauses"]
                    ),
                    "parent_centered_action_capacity": (
                        PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "spare_clause_slots_beyond_action_capacity": (
                        PAGE15_HEADROOM["clauses"] - PARENT_CENTERED_ACTION_CAPACITY
                    ),
                    "proved_sufficient": True,
                },
                "recorded_residual_headroom": {
                    "literals": PAGE15_HEADROOM["literals"],
                    "serialized_bytes": PAGE15_HEADROOM["serialized_bytes"],
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
        raise O1C93PreparationError(
            "causal rollover manifest differs: "
            f"bytes={len(manifest_payload)}, sha256={sha256_bytes(manifest_payload)}"
        )
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c93_page15_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Run the complete zero-call validation without publishing a directory."""

    return prepare_o1c93_page15_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C93PreparationError("prepared Page-15 bundle differs")
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
    manifest = _mapping(prepared.manifest, "prepared Page-15 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-15 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE15_SERIALIZED_BYTES, PAGE15_SHA256),
        RESIDENCY_NAME: (
            PAGE15_RESIDENCY_DOCUMENT_BYTES,
            PAGE15_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE15_ACTIVATION_DOCUMENT_BYTES,
            PAGE15_ACTIVATION_DOCUMENT_SHA256,
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
        or prepared.state.active_projection.sha256 != PAGE15_SHA256
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
        raise O1C93PreparationError("prepared Page-15 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C93PreparationError("prepared Page-15 exact artifact seal differs")
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-15 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C93PreparationError("prepared Page-15 artifact seal differs")


def write_prepared_o1c93_page15_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    """Atomically publish a validated Page-15 bundle to a fresh directory."""

    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(
            prepared, output_dir
        )
    except _publisher.O1C85PreparationError as exc:
        raise O1C93PreparationError("Page-15 publication failed") from exc


def prepare_and_write_o1c93_page15_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    """Prepare, validate, and atomically publish the Page-15 bundle."""

    prepared = prepare_o1c93_page15_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c93_page15_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0093's zero-call Page-15 rollover"
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
        prepared = prepare_o1c93_page15_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c93_page15_causal_rollover(prepared, args.output_dir)
    except (
        O1C93PreparationError,
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
    "O1C93PreparationError",
    "OCCURRENCES_NAME",
    "PAGE15_ACTIVE_LIMIT",
    "PAGE15_CATEGORY_COUNTS",
    "PAGE15_CLAUSE_COUNT",
    "PAGE15_HEADROOM",
    "PAGE15_LITERAL_COUNT",
    "PAGE15_SERIALIZED_BYTES",
    "PAGE15_SHA256",
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
    "preflight_o1c93_page15_causal_rollover",
    "prepare_and_write_o1c93_page15_causal_rollover",
    "prepare_o1c93_page15_causal_rollover",
    "write_prepared_o1c93_page15_causal_rollover",
]
