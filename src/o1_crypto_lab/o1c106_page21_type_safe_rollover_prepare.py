"""Prepare O1C-0106's zero-call, type-safe Page-21 rollover.

O1C-0105 burned Page 20 / lineage 33 before the v34 adapter discovered that
eleven O1C-0104 resolution-overlay clauses do not satisfy the native v8 input
theorem.  This module never replays that call.  It seals the terminal capsule,
revalidates the canonical O1C-0104 bundle, independently runs the real v8
grouped-bound theorem over every Page-21 clause, and only then makes a fresh
lineage-34 page publishable.

The immutable 2,692-clause logical registry and both resolution namespaces are
preserved byte for byte.  The eleven theorem failures are removed from ACTIVE
only; they remain in their proof sidecars and historical activation record.
"""

from __future__ import annotations

import argparse
import json
import math
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import joint_score_sieve_v8 as _v8
from . import o1c102_page19_causal_rollover_prepare as _o1c102
from . import o1c104_page20_causal_rollover_prepare as _o1c104
from . import o1c85_page10_transport_recovery_prepare as _publisher
from .causal_attic_v1 import CausalAttic, canonical_json_bytes, sha256_bytes
from .causal_residency_v1 import ResidencyProjection
from .criticality_potential import CriticalityPotentialField
from .joint_score_grouping_v1 import JointScoreCompatibilityGrouping
from .o1_relational_search import O1RelationalSearchError
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
    partial_assignment_from_vault_clause,
    validate_threshold_no_good_vault_identity,
    vault_identity_from_sources,
)


ATTEMPT_ID = "O1C-0106"
PARENT_ATTEMPT_ID = "O1C-0105"
PREPARATION_SCHEMA = "o1-256-o1c106-page21-type-safe-rollover-preparation-v1"
CERTIFICATION_AUDIT_SCHEMA = "o1-256-o1c106-page21-v8-certification-audit-v1"
COMPOSED_RESIDENCY_SCHEMA = "o1-score-threshold-composed-residency-v3"
COMPOSED_ACTIVATION_SCHEMA = "o1-score-threshold-composed-activation-ledger-v3"

DEFAULT_O1C104_BUNDLE_RELATIVE = Path(
    "research/o1c104_page20_causal_rollover_seed_20260721"
)
DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_060959_396348_O1C-0105_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0105_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)
CNF_RELATIVE = Path(
    "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1/"
    "artifacts/cnf/full256-eight-block-apple-view-0008.cnf"
)
POTENTIAL_RELATIVE = Path(
    "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_crossblock-consequence-sieve-v1/"
    "artifacts/potential/primary-eight-block.potential"
)
GROUPING_RELATIVE = Path(
    "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1/"
    "apple8-width6.grouping"
)

O1C104_MANIFEST_SHA256 = (
    "2e784eea7ef8fb85913e45246935fa26206626bebf52f0dcb5fc8b9672ba59c5"
)
O1C104_MANIFEST_BYTES = 9_830
O1C104_BUNDLE_FILE_COUNT = 16
PARENT_CAPSULE_MANIFEST_SHA256 = (
    "5185f293b51a1185cca1d06f18f6c4ca85172bd1245bb08867df293a995f8d97"
)
PARENT_CAPSULE_MANIFEST_BYTES = 4_174
PARENT_CAPSULE_ENTRY_COUNT = 39
PARENT_RESULT_SHA256 = (
    "f4e4e2ef4fcec6817b3fa6cf445448cae9aa693460c14cd2a8f7a7a3a295d66b"
)
PARENT_RESULT_BYTES = 14_767
PARENT_INTENT_SHA256 = (
    "013ad6009c770b1370a935584ccd0f85acbc737b4895ab3ee09c6e6d58a558f9"
)
PARENT_INTENT_BYTES = 2_273
PARENT_TERMINAL_FAILURE_SHA256 = (
    "716e1683ee55ed66c401bd26bf7b3d777ad3d36803d03ac58a4fa93b3f88d45d"
)
PARENT_TERMINAL_FAILURE_BYTES = 2_384
PARENT_EPISODE_SHA256 = (
    "c459733274a6e4660783d448f472e7035fac923e2a0f035b47cb27ac397de537"
)
PARENT_INVOCATION_SHA256 = (
    "839ae1319b51d0066a3a53401e12dae2643651270b283f86f0f50fbbced648a6"
)

CNF_SHA256 = "e1fc0ac93724004291c960ea06e5584c598853b9ea8370552be09f29e73e2432"
POTENTIAL_SHA256 = "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
GROUPING_SHA256 = "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
V8_SOURCE_SHA256 = "d98662ff1ddef33c199738c44852d3903507b6bb98b86c257b8b9022f2dab03d"
THRESHOLD = 14.606178797892962
THRESHOLD_F64LE_HEX = "2ef540115d362d40"

PAGE20_LINEAGE_ORDINAL = 33
PAGE20_SHA256 = "537f63c5284e15e451739f7369fbe6ee8dddbc5dfdb15b26988269a1e40e5519"
PAGE20_BYTES = 2_762_455
PAGE20_PURE_EMITTED_SHA256 = (
    "1b46e9d8653c0ce7c7366a37ae927df1e301e1b2d7ecffaa056d84d86375bc7a"
)
PAGE21_LINEAGE_ORDINAL = 34
PAGE21_ACTIVE_LIMIT = 247
PAGE21_EMITTED_COUNT = 203
PAGE21_INHERITED_DERIVED_COUNT = 3
PAGE21_NEW_DERIVED_COUNT = 41
PAGE21_SHA256 = "36091952f38fbe5b73e20311083c7e1bfc30271cfcd6dba2f46f73f051f65fa8"
PAGE21_LITERAL_COUNT = 690_330
PAGE21_SERIALIZED_BYTES = 2_762_499
PAGE21_CLAUSE_AGGREGATE_SHA256 = (
    "72740ed87b246f17a24de10529d86f37aa6878f467d92bbcfdae197f001b1bab"
)
PAGE21_MAXIMUM_CERTIFIED_UPPER_BOUND = 14.605986705470585
CERTIFICATION_AUDIT_SHA256 = (
    "cec84918ddaba8d0c8d8b6513a8a681c1108a088089ba2534d27d7b37e2f1125"
)
CERTIFICATION_AUDIT_BYTES = 144_771

LOGICAL_KNOWN_CLAUSE_COUNT = 2_692
LOGICAL_KNOWN_LITERAL_COUNT = 7_611_885
LOGICAL_KNOWN_SERIALIZED_BYTES = 30_458_499
LOGICAL_KNOWN_SHA256 = (
    "ed53e022239f84f3bc9bbb2a822170405e362ba1a0a98a1d887e9c38d79f0220"
)
LOGICAL_KNOWN_INVENTORY_SHA256 = (
    "9b61b7e9dc9c299c311f46a6f3dce683798b589fb1994b96987fc69768a6379f"
)
EMITTED_CLAUSE_COUNT = 2_603
INHERITED_DERIVED_CLAUSE_COUNT = 5
NEW_DERIVED_CLAUSE_COUNT = 84

FINAL_BANK_SHA256 = "c0db45c1aa8889d5ed5c01c974f405c7da5c8c2d869597c53652f65512ee58d7"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "f025fffa2f5471bfe3bd9315c90fce711724161b63e8c6a1b033cf7eb95a057a"
)
INHERITED_RECEIPT_SHA256 = (
    "3eade7d3e6e195b4b5aeac098969d85a93fae34ac1246f6868ddd6f7afdb345c"
)
INHERITED_CLOSURE_SHA256 = (
    "74cc718bd1140c6295ea3d4bd9cb295e5a1f94669c7935204ea5176355640050"
)
INHERITED_OVERLAY_SHA256 = (
    "291cab4b923268393d56e3c3b16d33c34bc933c0d2d13d5baf9e0dcfe5bfe0e9"
)
NEW_RECEIPT_SHA256 = "0c0fa6119d729dc33dda48039b802b39a0f1aade05cf2e818ff5a596903ab19a"
NEW_CLOSURE_SHA256 = "f351b4d6c5226efbdf63ffb1093b48260a6f2e80fb363334dba615a8ed27abe8"
NEW_OVERLAY_SHA256 = "44175f53721783710a15bf8fcc69567ab2107469fabb777e62df166f6a047a10"

FAILED_NEW_OVERLAY_INDICES = (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14)
PASSING_NEW_OVERLAY_INDICES = (
    0,
    2,
    12,
    13,
    *range(15, 52),
)
REPLACEMENT_EMITTED_UNION_INDICES = (
    2_387,
    2_395,
    2_461,
    2_349,
    2_459,
    2_429,
    2_379,
    2_355,
    2_437,
    2_451,
    2_445,
)
REPLACEMENT_EMITTED_INDICES_SHA256 = (
    "76fb8a6e30e3c1241d79975a8f6d1e8691c65c326802fc27e490dc7d5b142c8e"
)

NEW_CHUNK_NAME = _o1c104.NEW_CHUNK_NAME
ACTIVE_PROJECTION_NAME = "page-21-active.bin"
ACTIVE_PROJECTION_ROLE = "fresh-lineage-34-v8-certified-composed-page21-science-input"
RESIDENCY_NAME = _o1c104.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c104.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c104.OCCURRENCES_NAME
RELATIONS_NAME = _o1c104.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c104.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c104.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = _o1c104.PRIORITY_RECEIPT_NAME
INHERITED_DERIVED_RECEIPT_NAME = _o1c104.INHERITED_DERIVED_RECEIPT_NAME
INHERITED_DERIVED_CLOSURE_NAME = _o1c104.INHERITED_DERIVED_CLOSURE_NAME
INHERITED_DERIVED_OVERLAY_NAME = _o1c104.INHERITED_DERIVED_OVERLAY_NAME
DERIVED_RECEIPT_NAME = _o1c104.DERIVED_RECEIPT_NAME
DERIVED_CLOSURE_NAME = _o1c104.DERIVED_CLOSURE_NAME
DERIVED_OVERLAY_NAME = _o1c104.DERIVED_OVERLAY_NAME
CERTIFICATION_AUDIT_NAME = "page-21-v8-certification-audit.json"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"

PreparedCausalRolloverArtifacts = _o1c104.PreparedCausalRolloverArtifacts


class O1C106PreparationError(RuntimeError):
    """A Page-20 burn seal, v8 theorem, or Page-21 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C106PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C106PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C106PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C106PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or resolved != path:
        raise O1C106PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C106PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C106PreparationError(f"{label} is not canonical JSON")
    return value


def _f64_hex(value: float) -> str:
    return struct.pack("<d", value).hex()


def _canonical_index_list_sha256(indices: Sequence[int]) -> str:
    payload = json.dumps(
        list(indices), sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")
    return sha256_bytes(payload)


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _artifact_roles() -> Mapping[str, str]:
    return {
        NEW_CHUNK_NAME: "immutable-unique-lineage-32-native-evidence-chunk",
        ACTIVE_PROJECTION_NAME: ACTIVE_PROJECTION_ROLE,
        RESIDENCY_NAME: "type-safe-three-namespace-lineage34-residency-state",
        ACTIVATION_LEDGER_NAME: "composed-activation-ledger-with-burned-page20-prefix",
        OCCURRENCES_NAME: "unchanged-pure-native-complete-occurrence-ledger",
        RELATIONS_NAME: "unchanged-pure-native-complete-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "unchanged-sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "unchanged-canonical-o1c103-priority-state-receipt",
        INHERITED_DERIVED_RECEIPT_NAME: (
            "immutable-inherited-o1c102-resolution-proof"
        ),
        INHERITED_DERIVED_CLOSURE_NAME: "immutable-inherited-five-clause-closure",
        INHERITED_DERIVED_OVERLAY_NAME: "immutable-inherited-three-clause-overlay",
        DERIVED_RECEIPT_NAME: (
            "immutable-o1c104-84-clause-fixed-point-resolution-proof"
        ),
        DERIVED_CLOSURE_NAME: "immutable-o1c104-84-clause-resolution-closure",
        DERIVED_OVERLAY_NAME: "immutable-o1c104-52-clause-logical-overlay-sidecar",
        CERTIFICATION_AUDIT_NAME: (
            "real-offline-v8-per-clause-page21-certification-audit"
        ),
    }


def _parse_checksum_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C106PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C106PreparationError("parent capsule manifest row differs")
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
            raise O1C106PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    return entries


def _validate_capsule_inventory(capsule: Path) -> Mapping[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C106PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C106PreparationError("parent capsule manifest differs")
    entries = _parse_checksum_manifest(payload)
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C106PreparationError("parent capsule manifest inventory differs")
    observed: set[str] = set()
    try:
        for path in capsule.rglob("*"):
            relative = path.relative_to(capsule).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise O1C106PreparationError("parent capsule contains a symlink")
            if stat.S_ISREG(metadata.st_mode):
                observed.add(relative)
    except OSError as exc:
        raise O1C106PreparationError("parent capsule inventory is unreadable") from exc
    if observed != set(entries) | {"artifacts.sha256"}:
        raise O1C106PreparationError("parent capsule inventory differs")
    for relative, digest in entries.items():
        path = capsule / relative
        try:
            metadata = path.lstat()
            item = path.read_bytes()
        except OSError as exc:
            raise O1C106PreparationError("parent capsule artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or sha256_bytes(item) != digest
        ):
            raise O1C106PreparationError("parent capsule artifact differs")
    return entries


def _validate_parent_terminal(capsule: Path, result_path: Path) -> Mapping[str, object]:
    entries = _validate_capsule_inventory(capsule)
    try:
        result_payload = result_path.read_bytes()
        capsule_result_payload = (capsule / "result.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
        failure_payload = (capsule / "episodes/00/terminal-failure.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
    except OSError as exc:
        raise O1C106PreparationError(
            "parent terminal artifacts are unreadable"
        ) from exc
    if (
        len(result_payload) != PARENT_RESULT_BYTES
        or sha256_bytes(result_payload) != PARENT_RESULT_SHA256
        or result_payload != capsule_result_payload
        or entries.get("result.json") != PARENT_RESULT_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
        or entries.get("episodes/00/intent.json") != PARENT_INTENT_SHA256
        or len(failure_payload) != PARENT_TERMINAL_FAILURE_BYTES
        or sha256_bytes(failure_payload) != PARENT_TERMINAL_FAILURE_SHA256
        or entries.get("episodes/00/terminal-failure.json")
        != PARENT_TERMINAL_FAILURE_SHA256
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or entries.get("episodes/00/episode.json") != PARENT_EPISODE_SHA256
        or entries.get("invocation.json") != PARENT_INVOCATION_SHA256
    ):
        raise O1C106PreparationError("parent terminal seals differ")
    result = _canonical_document(result_payload, "parent result")
    intent = _canonical_document(intent_payload, "parent intent")
    failure = _canonical_document(failure_payload, "parent terminal failure")
    episode = _canonical_document(episode_payload, "parent episode")
    result_episodes = _sequence(result.get("episodes"), "parent result episodes")
    if len(result_episodes) != 1:
        raise O1C106PreparationError("parent result episode differs")
    result_episode = _mapping(result_episodes[0], "parent result episode")
    result_failure = _mapping(
        result_episode.get("terminal_failure"), "parent result terminal failure"
    )
    if (
        result.get("schema") != "o1-256-apple8-parent-centered-continuation-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("classification")
        != "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL"
        or result.get("stop_reason") != "burned-terminal-failure-no-retry"
        or result.get("science_gain") is not False
        or result.get("operational_activation") is not False
        or result_episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or result_episode.get("lineage_call_ordinal") != PAGE20_LINEAGE_ORDINAL
        or result_episode.get("lineage33_burned") is not True
        or result_episode.get("native_call_issued") is not True
        or result_episode.get("native_calls_consumed") != 1
        or result_episode.get("native_result_returned") is not False
        or result_episode.get("retry_authorized") is not False
        or result_episode.get("replay_authorized") is not False
        or result_failure.get("message")
        != "joint-score-sieve-v34 adapter failed: joint-score-sieve-v8 grouped no-good certification differs"
        or result_failure.get("occurred_after_persisted_intent") is not True
        or result_failure.get("science_gain") is not False
        or intent.get("schema")
        != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("page20_sha256") != PAGE20_SHA256
        or intent.get("page20_burned") is not True
        or intent.get("lineage33_burned") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or failure.get("lineage33_burned") is not True
        or failure.get("page20_burned") is not True
        or failure.get("native_calls_consumed") != 1
        or failure.get("native_result_returned") is not False
        or failure.get("retry_authorized") is not False
        or failure.get("replay_authorized") is not False
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or episode.get("terminal_failure") != failure
    ):
        raise O1C106PreparationError("parent terminal boundary differs")
    return result


def _validate_o1c104_bundle(
    bundle: Path,
) -> tuple[PreparedCausalRolloverArtifacts, Mapping[str, bytes]]:
    manifest_path = bundle / _o1c104.PREPARATION_MANIFEST_NAME
    try:
        children = tuple(bundle.iterdir())
        manifest_payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C106PreparationError("O1C-0104 bundle is unreadable") from exc
    if (
        len(children) != O1C104_BUNDLE_FILE_COUNT
        or any(path.is_symlink() or not path.is_file() for path in children)
        or len(manifest_payload) != O1C104_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != O1C104_MANIFEST_SHA256
    ):
        raise O1C106PreparationError("O1C-0104 bundle inventory differs")
    manifest = _canonical_document(manifest_payload, "O1C-0104 manifest")
    rows = _mapping(manifest.get("artifacts"), "O1C-0104 artifact rows")
    expected_names = set(rows) | {_o1c104.PREPARATION_MANIFEST_NAME}
    if (
        manifest.get("schema") != _o1c104.PREPARATION_SCHEMA
        or manifest.get("attempt_id") != _o1c104.ATTEMPT_ID
        or {path.name for path in children} != expected_names
        or len(rows) != O1C104_BUNDLE_FILE_COUNT - 1
    ):
        raise O1C106PreparationError("O1C-0104 manifest differs")
    observed: dict[str, bytes] = {}
    for name in expected_names:
        path = bundle / name
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C106PreparationError("O1C-0104 artifact differs") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise O1C106PreparationError("O1C-0104 artifact type differs")
        observed[name] = payload
        if name != _o1c104.PREPARATION_MANIFEST_NAME:
            row = _mapping(rows.get(name), f"O1C-0104 artifact row {name}")
            role = row.get("role")
            if not isinstance(role, str) or row != _artifact_row(payload, role):
                raise O1C106PreparationError("O1C-0104 artifact row differs")
    page20 = _mapping(manifest.get("page20"), "O1C-0104 Page20")
    registry = _mapping(
        manifest.get("logical_known_registry"), "O1C-0104 logical registry"
    )
    if (
        page20.get("lineage_ordinal") != PAGE20_LINEAGE_ORDINAL
        or page20.get("active_sha256") != PAGE20_SHA256
        or page20.get("serialized_bytes") != PAGE20_BYTES
        or page20.get("pure_emitted_candidate_sha256") != PAGE20_PURE_EMITTED_SHA256
        or page20.get("pure_emitted_candidate_activated") is not False
        or registry.get("combined_clause_count") != LOGICAL_KNOWN_CLAUSE_COUNT
        or registry.get("combined_encoding_sha256") != LOGICAL_KNOWN_SHA256
        or registry.get("combined_inventory_sha256") != LOGICAL_KNOWN_INVENTORY_SHA256
        or registry.get("combined_literal_count") != LOGICAL_KNOWN_LITERAL_COUNT
        or registry.get("combined_serialized_bytes") != LOGICAL_KNOWN_SERIALIZED_BYTES
    ):
        raise O1C106PreparationError("O1C-0104 Page20 registry differs")

    # Reconstruct only the emitted selector state needed by Page 21.  The
    # expensive O1C-0104 resolution search is already sealed in the canonical
    # receipt/closure/overlay artifacts and is validated below; re-deriving it
    # would add minutes without changing a byte of this rollover.
    root = lab_root()
    parent_capsule = _canonical_path(
        root / _o1c104.DEFAULT_PARENT_CAPSULE_RELATIVE,
        "O1C-0104 parent capsule",
        directory=True,
    )
    parent_result = _canonical_path(
        root / _o1c104.DEFAULT_PARENT_RESULT_RELATIVE,
        "O1C-0104 parent result",
        directory=False,
    )
    try:
        _o1c104._validate_capsule_inventory(parent_capsule)
        _o1c104._validate_parent_result(parent_capsule, parent_result)
        previous = _o1c104._regenerate_o1c102_and_validate_initial(parent_capsule)
        telemetry = _o1c104._parse_parent_telemetry(parent_capsule, previous)
        chunk = _o1c104._new_chunk(previous.state, telemetry)
        base = _o1c104._advance_base_page20(previous, chunk, telemetry)
        bank, priority_receipt, _continuation = (
            _o1c104._validate_evolved_continuation_bank(parent_capsule)
        )
        page = parse_threshold_no_good_vault(
            observed[_o1c104.ACTIVE_PROJECTION_NAME],
            observed_variables=base.attic.union_vault.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except Exception as exc:
        raise O1C106PreparationError(
            "O1C-0104 emitted state reconstruction differs"
        ) from exc
    residency = _canonical_document(observed[RESIDENCY_NAME], "O1C-0104 residency")
    current = _mapping(residency.get("current_projection"), "O1C-0104 projection")
    category_counts_raw = _mapping(
        current.get("category_counts"), "O1C-0104 projection categories"
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in category_counts_raw.values()
    ):
        raise O1C106PreparationError("O1C-0104 projection categories differ")

    def integer_indices(field: str) -> tuple[int, ...]:
        values = tuple(_sequence(current.get(field), f"O1C-0104 {field}"))
        if any(
            isinstance(value, bool) or not isinstance(value, int) for value in values
        ):
            raise O1C106PreparationError(f"O1C-0104 {field} differs")
        return cast(tuple[int, ...], values)

    never_resident_values = tuple(
        _sequence(
            residency.get("never_resident_undominated_logical_indices"),
            "O1C-0104 never-resident indices",
        )
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in never_resident_values
    ):
        raise O1C106PreparationError("O1C-0104 never-resident indices differ")
    composed = _o1c104._ComposedPage20(
        page=page,
        residency_payload=observed[RESIDENCY_NAME],
        activation_payload=observed[ACTIVATION_LEDGER_NAME],
        selected_emitted_indices=integer_indices("selected_emitted_union_indices"),
        priority_selected_emitted_indices=integer_indices(
            "priority_selected_emitted_union_indices"
        ),
        displaced_emitted_indices=integer_indices("displaced_emitted_union_indices"),
        never_resident_undominated_indices=cast(tuple[int, ...], never_resident_values),
        category_counts=cast(Mapping[str, int], category_counts_raw),
    )
    try:
        state = _o1c104._authoritative_composed_state(base, composed)
    except Exception as exc:
        raise O1C106PreparationError("O1C-0104 composed state differs") from exc
    if (
        chunk.serialized != observed[NEW_CHUNK_NAME]
        or page.sha256 != PAGE20_SHA256
        or canonical_json_bytes(base.attic.occurrence_document())
        != observed[OCCURRENCES_NAME]
        or canonical_json_bytes(base.attic.relation_document())
        != observed[RELATIONS_NAME]
        or bank != observed[FINAL_BANK_NAME]
        or priority_receipt != observed[PRIORITY_RECEIPT_NAME]
    ):
        raise O1C106PreparationError("O1C-0104 reconstructed bytes differ")
    reconstructed = PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=observed,
        manifest=manifest,
    )
    return reconstructed, observed


def _validate_capsule_initial_equals_bundle(
    capsule: Path, bundle_artifacts: Mapping[str, bytes]
) -> None:
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C106PreparationError("parent initial bundle is unreadable") from exc
    if {path.name for path in children} != set(bundle_artifacts):
        raise O1C106PreparationError("parent initial bundle inventory differs")
    for name, expected in bundle_artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C106PreparationError("parent initial bundle differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or payload != expected
        ):
            raise O1C106PreparationError("parent initial bundle differs")


@dataclass(frozen=True)
class ComposedPage21Projection:
    lineage_ordinal: int
    vault: ThresholdNoGoodVault
    pure_emitted_candidate: ResidencyProjection
    selected_emitted_union_indices: tuple[int, ...]
    priority_selected_emitted_union_indices: tuple[int, ...]
    replacement_emitted_union_indices: tuple[int, ...]
    selected_inherited_derived_clauses: tuple[Mapping[str, object], ...]
    selected_new_derived_clauses: tuple[Mapping[str, object], ...]
    displaced_emitted_union_indices: tuple[int, ...]
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        encoding = _mapping(self.document.get("encoding_only"), "Page-21 encoding")
        if (
            self.lineage_ordinal != PAGE21_LINEAGE_ORDINAL
            or self.vault.sha256 != PAGE21_SHA256
            or self.vault.clause_count != PAGE21_ACTIVE_LIMIT
            or self.vault.literal_count != PAGE21_LITERAL_COUNT
            or self.vault.serialized_bytes != PAGE21_SERIALIZED_BYTES
            or self.pure_emitted_candidate.vault.sha256 != PAGE20_PURE_EMITTED_SHA256
            or len(self.selected_emitted_union_indices) != PAGE21_EMITTED_COUNT
            or tuple(sorted(self.selected_emitted_union_indices))
            != self.selected_emitted_union_indices
            or len(self.priority_selected_emitted_union_indices) != PAGE21_EMITTED_COUNT
            or set(self.priority_selected_emitted_union_indices)
            != set(self.selected_emitted_union_indices)
            or self.replacement_emitted_union_indices
            != REPLACEMENT_EMITTED_UNION_INDICES
            or len(self.selected_inherited_derived_clauses)
            != PAGE21_INHERITED_DERIVED_COUNT
            or len(self.selected_new_derived_clauses) != PAGE21_NEW_DERIVED_COUNT
            or len(self.displaced_emitted_union_indices) != 44
            or sum(self.category_counts.values()) != PAGE21_ACTIVE_LIMIT
            or encoding != self.vault.describe()
            or self.document.get("selected_emitted_union_indices")
            != list(self.selected_emitted_union_indices)
            or self.document.get("priority_selected_emitted_union_indices")
            != list(self.priority_selected_emitted_union_indices)
            or self.document.get("replacement_emitted_union_indices")
            != list(self.replacement_emitted_union_indices)
            or self.document.get("selected_inherited_derived_clauses")
            != list(self.selected_inherited_derived_clauses)
            or self.document.get("selected_new_derived_clauses")
            != list(self.selected_new_derived_clauses)
            or self.document.get("excluded_new_derived_closure_indices")
            != list(FAILED_NEW_OVERLAY_INDICES)
            or self.document.get("displaced_emitted_union_indices")
            != list(self.displaced_emitted_union_indices)
            or self.document.get("category_counts") != dict(self.category_counts)
            or self.document.get("category_priority_order")
            != list(self.category_priority_order)
            or self.document.get("replacement_emitted_union_indices_sha256")
            != REPLACEMENT_EMITTED_INDICES_SHA256
            or self.document.get("maximum_clause_count") != PAGE21_ACTIVE_LIMIT
            or self.document.get("serialization_rule")
            != "emitted-union-index-ascending;inherited-overlay-order;passing-new-overlay-closure-index-ascending"
        ):
            raise O1C106PreparationError("authoritative Page-21 projection differs")

    @property
    def selected_union_indices(self) -> tuple[int, ...]:
        return self.selected_emitted_union_indices

    @property
    def selection_order(self) -> tuple[int, ...]:
        return self.priority_selected_emitted_union_indices

    def describe(self) -> Mapping[str, object]:
        return self.document


@dataclass(frozen=True)
class ComposedPage21State:
    attic: CausalAttic
    current_projection: ComposedPage21Projection
    residency_payload: bytes
    activation_payload: bytes

    @property
    def active_limit(self) -> int:
        return PAGE21_ACTIVE_LIMIT

    @property
    def active_projection(self) -> ThresholdNoGoodVault:
        return self.current_projection.vault

    @property
    def used_active_sha256(self) -> tuple[str, ...]:
        activation = _canonical_document(self.activation_payload, "Page-21 activation")
        return tuple(
            cast(
                Sequence[str],
                _sequence(activation.get("used_active_sha256"), "Page-21 used inputs"),
            )
        )

    def describe(self) -> Mapping[str, object]:
        return _canonical_document(self.residency_payload, "Page-21 residency")

    def activation_ledger_document(self) -> Mapping[str, object]:
        return _canonical_document(self.activation_payload, "Page-21 activation")


@dataclass(frozen=True)
class _TheoremContext:
    field: CriticalityPotentialField
    grouping: JointScoreCompatibilityGrouping
    source_seals: Mapping[str, Mapping[str, object]]


@dataclass(frozen=True)
class _Composition:
    page: ThresholdNoGoodVault
    selected_emitted: tuple[int, ...]
    priority_selected_emitted: tuple[int, ...]
    displaced_emitted: tuple[int, ...]
    replacement_emitted: tuple[int, ...]
    inherited_rows: tuple[Mapping[str, object], ...]
    new_rows: tuple[Mapping[str, object], ...]
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    residency_payload: bytes
    activation_payload: bytes
    certification_payload: bytes


def _sealed_public_inputs(root: Path) -> _TheoremContext:
    paths = {
        "cnf": root / CNF_RELATIVE,
        "potential": root / POTENTIAL_RELATIVE,
        "grouping": root / GROUPING_RELATIVE,
        "v8_source": Path(_v8.__file__).resolve(strict=True),
    }
    expected = {
        "cnf": CNF_SHA256,
        "potential": POTENTIAL_SHA256,
        "grouping": GROUPING_SHA256,
        "v8_source": V8_SOURCE_SHA256,
    }
    payloads: dict[str, bytes] = {}
    seals: dict[str, Mapping[str, object]] = {}
    for name, path in paths.items():
        path = _canonical_path(path, f"public {name}", directory=False)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C106PreparationError(f"public {name} is unreadable") from exc
        digest = sha256_bytes(payload)
        if digest != expected[name]:
            raise O1C106PreparationError(f"public {name} seal differs")
        payloads[name] = payload
        seals[name] = {"serialized_bytes": len(payload), "sha256": digest}
    io_v1 = _v8._v7._v1
    try:
        field = io_v1._potential(payloads["potential"])
        grouping = _v8.validate_joint_score_sieve_grouping(field, payloads["grouping"])
    except Exception as exc:
        raise O1C106PreparationError("public v8 theorem inputs differ") from exc
    if grouping.potential_sha256 != POTENTIAL_SHA256:
        raise O1C106PreparationError("public grouping identity differs")
    return _TheoremContext(field=field, grouping=grouping, source_seals=seals)


def _certify_clause(
    clause: ThresholdNoGoodClause,
    *,
    context: _TheoremContext,
    namespace: str,
    active: bool,
    union_index: int | None = None,
    closure_index: int | None = None,
    logical_index: int | None = None,
) -> tuple[dict[str, object], bool]:
    field = context.field
    grouping = context.grouping
    assignments = partial_assignment_from_vault_clause(clause)
    complete = len(assignments) == len(field.observed_variables)
    metric_kind: str
    if complete:
        metric = _v8.joint_score_complete(field, assignments)
        metric_kind = "original_factor_exact_score"
    else:
        metric = _v8.joint_score_upper_bound(field, assignments, grouping=grouping)
        metric_kind = "grouped_upper_bound"
    if not math.isfinite(metric):
        raise O1C106PreparationError("v8 certification metric is non-finite")
    error: str | None = None
    certification: str | None = None
    try:
        certified_assignment, certification = _v8._certify_no_good(
            clause,
            field=field,
            grouping=grouping,
            threshold=THRESHOLD,
            source=None,
            witness_score=None,
        )
        passed = True
        if certified_assignment != tuple(sorted(assignments.items())):
            raise O1C106PreparationError("v8 certification assignment differs")
    except O1RelationalSearchError as exc:
        passed = False
        error = str(exc)
    row: dict[str, object] = {
        "namespace": namespace,
        "active": active,
        "union_index": union_index,
        "closure_index": closure_index,
        "logical_index": logical_index,
        "clause_sha256": clause.sha256,
        "literal_count": clause.literal_count,
        "excluded_assignment_count": len(assignments),
        "complete_assignment": complete,
        "metric_kind": metric_kind,
        "metric": metric,
        "metric_f64le_hex": _f64_hex(metric),
        "threshold": THRESHOLD,
        "threshold_f64le_hex": THRESHOLD_F64LE_HEX,
        "strictly_below_threshold": metric < THRESHOLD,
        "certification": certification,
        "passed": passed,
        "failure": error,
    }
    return row, passed


def _relation_data(
    receipt_payload: bytes,
) -> tuple[tuple[tuple[int, int], ...], tuple[int, ...]]:
    receipt = _canonical_document(receipt_payload, "O1C-0104 resolution receipt")
    registry = _mapping(receipt.get("logical_known_registry"), "logical registry")
    combined = _mapping(registry.get("combined"), "combined logical registry")
    relation_audit = _mapping(receipt.get("logical_relation_audit"), "relation audit")
    combined_encoding = _mapping(
        combined.get("encoding_only"), "combined logical registry encoding"
    )
    segment_order = _sequence(registry.get("registry_segment_order"), "registry order")
    relation_rows = _sequence(relation_audit.get("full_relations"), "full relations")
    relations: list[tuple[int, int]] = []
    for value in relation_rows:
        row = _mapping(value, "full relation")
        left = row.get("subsumer_logical_index")
        right = row.get("subsumed_logical_index")
        if (
            isinstance(left, bool)
            or not isinstance(left, int)
            or isinstance(right, bool)
            or not isinstance(right, int)
        ):
            raise O1C106PreparationError("full relation differs")
        relations.append((left, right))
    subsumed = {right for _left, right in relations}
    undominated = tuple(
        index for index in range(LOGICAL_KNOWN_CLAUSE_COUNT) if index not in subsumed
    )
    if (
        receipt.get("schema") != _o1c104.DERIVED_RECEIPT_SCHEMA
        or tuple(segment_order)
        != (
            "historical-emitted-causal-attic",
            "inherited-o1c102-derived-resolution",
            "new-o1c103-native-emission",
            "new-o1c104-derived-resolution",
        )
        or combined.get("clause_count") != LOGICAL_KNOWN_CLAUSE_COUNT
        or combined_encoding.get("sha256") != LOGICAL_KNOWN_SHA256
        or combined.get("inventory_sha256") != LOGICAL_KNOWN_INVENTORY_SHA256
        or len(relations) != 119
        or len(undominated) != 2_579
    ):
        raise O1C106PreparationError("logical registry order differs")
    return tuple(relations), undominated


def _logical_to_emitted_index(logical_index: int) -> int | None:
    if 0 <= logical_index < 2_338:
        return logical_index
    if 2_343 <= logical_index < 2_608:
        return logical_index - INHERITED_DERIVED_CLAUSE_COUNT
    return None


def _compose_page21(
    previous: PreparedCausalRolloverArtifacts,
    bundle_artifacts: Mapping[str, bytes],
    context: _TheoremContext,
) -> _Composition:
    state = previous.state
    if not isinstance(state, _o1c104.ComposedPage20State):
        raise O1C106PreparationError("O1C-0104 composed state differs")
    attic = state.attic
    emitted_union = attic.union_vault
    parent_residency_payload = bundle_artifacts[RESIDENCY_NAME]
    parent_residency = _canonical_document(parent_residency_payload, "parent residency")
    parent_activation_payload = bundle_artifacts[ACTIVATION_LEDGER_NAME]
    parent_activation = _canonical_document(
        parent_activation_payload, "parent activation"
    )
    parent_projection = _mapping(
        parent_residency.get("current_projection"), "parent projection"
    )
    parent_selected = tuple(
        cast(
            Sequence[int],
            _sequence(
                parent_projection.get("selected_emitted_union_indices"),
                "parent selected emitted",
            ),
        )
    )
    parent_displaced = tuple(
        cast(
            Sequence[int],
            _sequence(
                parent_projection.get("displaced_emitted_union_indices"),
                "parent displaced emitted",
            ),
        )
    )
    pure = state.current_projection.base_selector_projection
    # O1C-0104 persists displacement in lowest-priority-first order.  Page 21
    # reclaims exactly the highest-priority eleven slots made available by the
    # eleven type failures, hence the reversed prefix below.
    replacements = tuple(reversed(parent_displaced))[: len(FAILED_NEW_OVERLAY_INDICES)]
    if (
        replacements != REPLACEMENT_EMITTED_UNION_INDICES
        or _canonical_index_list_sha256(replacements)
        != REPLACEMENT_EMITTED_INDICES_SHA256
    ):
        raise O1C106PreparationError("replacement emitted selector differs")
    selected_emitted = tuple(sorted((*parent_selected, *replacements)))
    priority_selected = tuple(
        index for index in pure.selection_order if index in set(selected_emitted)
    )
    displaced = tuple(
        index for index in pure.selection_order if index not in set(selected_emitted)
    )
    if (
        len(parent_selected) != 192
        or len(parent_displaced) != 55
        or set(parent_selected) | set(parent_displaced)
        != set(pure.selected_union_indices)
        or len(selected_emitted) != PAGE21_EMITTED_COUNT
        or len(set(selected_emitted)) != PAGE21_EMITTED_COUNT
        or len(priority_selected) != PAGE21_EMITTED_COUNT
        or len(displaced) != 44
        or set(selected_emitted) | set(displaced) != set(pure.selected_union_indices)
    ):
        raise O1C106PreparationError("Page-21 emitted selector differs")

    inherited_closure = parse_threshold_no_good_vault(
        bundle_artifacts[INHERITED_DERIVED_CLOSURE_NAME],
        observed_variables=emitted_union.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    inherited_overlay = parse_threshold_no_good_vault(
        bundle_artifacts[INHERITED_DERIVED_OVERLAY_NAME],
        observed_variables=emitted_union.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    new_closure = parse_threshold_no_good_vault(
        bundle_artifacts[DERIVED_CLOSURE_NAME],
        observed_variables=emitted_union.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    new_overlay = parse_threshold_no_good_vault(
        bundle_artifacts[DERIVED_OVERLAY_NAME],
        observed_variables=emitted_union.observed_variables,
        caps=O1C66_VAULT_CAPS,
    )
    if (
        inherited_closure.sha256 != INHERITED_CLOSURE_SHA256
        or inherited_overlay.sha256 != INHERITED_OVERLAY_SHA256
        or inherited_overlay.clauses
        != tuple(
            inherited_closure.clauses[index] for index in _o1c102.DERIVED_OVERLAY_ORDER
        )
        or new_closure.sha256 != NEW_CLOSURE_SHA256
        or new_overlay.sha256 != NEW_OVERLAY_SHA256
        or new_overlay.clauses != new_closure.clauses[:52]
    ):
        raise O1C106PreparationError("derived namespace differs")

    expected_identity = vault_identity_from_sources(
        cnf_sha256=CNF_SHA256,
        potential_sha256=POTENTIAL_SHA256,
        grouping_sha256=GROUPING_SHA256,
        observed_variables=context.field.observed_variables,
        bound_rule=_v8.JOINT_SCORE_SIEVE_BOUND_RULE,
        threshold=THRESHOLD,
    )
    try:
        validate_threshold_no_good_vault_identity(
            emitted_union, expected=expected_identity
        )
        validate_threshold_no_good_vault_identity(
            inherited_overlay, expected=expected_identity
        )
        validate_threshold_no_good_vault_identity(
            new_overlay, expected=expected_identity
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C106PreparationError("v8 certification identity differs") from exc

    emitted_audit: dict[int, Mapping[str, object]] = {}
    for index in selected_emitted:
        row, passed = _certify_clause(
            emitted_union.clauses[index],
            context=context,
            namespace="emitted-causal-attic",
            active=True,
            union_index=index,
            logical_index=_o1c104._emitted_union_to_logical_index(index),
        )
        if not passed:
            raise O1C106PreparationError("active emitted v8 certification failed")
        emitted_audit[index] = row

    inherited_rows: list[Mapping[str, object]] = []
    inherited_audit: dict[int, Mapping[str, object]] = {}
    for overlay_index, closure_index in enumerate(_o1c102.DERIVED_OVERLAY_ORDER):
        clause = inherited_overlay.clauses[overlay_index]
        row, passed = _certify_clause(
            clause,
            context=context,
            namespace="inherited-o1c102-derived-resolution",
            active=True,
            closure_index=closure_index,
            logical_index=2_338 + closure_index,
        )
        if not passed:
            raise O1C106PreparationError("active inherited v8 certification failed")
        inherited_audit[closure_index] = row
        inherited_rows.append(
            {
                "namespace": "inherited-o1c102-derived-resolution",
                "closure_index": closure_index,
                "logical_index": 2_338 + closure_index,
                "clause_sha256": clause.sha256,
                "literal_count": clause.literal_count,
            }
        )

    observed_passing: list[int] = []
    observed_failing: list[int] = []
    new_audit: dict[int, Mapping[str, object]] = {}
    for closure_index, clause in enumerate(new_overlay.clauses):
        expected_active = closure_index in PASSING_NEW_OVERLAY_INDICES
        row, passed = _certify_clause(
            clause,
            context=context,
            namespace="new-o1c104-derived-resolution",
            active=expected_active,
            closure_index=closure_index,
            logical_index=2_608 + closure_index,
        )
        new_audit[closure_index] = row
        (observed_passing if passed else observed_failing).append(closure_index)
    if (
        tuple(observed_passing) != PASSING_NEW_OVERLAY_INDICES
        or tuple(observed_failing) != FAILED_NEW_OVERLAY_INDICES
        or any(
            new_audit[index].get("failure")
            != "joint-score-sieve-v8 grouped no-good certification differs"
            for index in FAILED_NEW_OVERLAY_INDICES
        )
    ):
        raise O1C106PreparationError("new overlay v8 classification differs")

    new_rows = tuple(
        {
            "namespace": "new-o1c104-derived-resolution",
            "closure_index": index,
            "logical_index": 2_608 + index,
            "clause_sha256": new_overlay.clauses[index].sha256,
            "literal_count": new_overlay.clauses[index].literal_count,
        }
        for index in PASSING_NEW_OVERLAY_INDICES
    )
    try:
        page = ThresholdNoGoodVault(
            emitted_union.identity,
            emitted_union.observed_variables,
            (
                *(emitted_union.clauses[index] for index in selected_emitted),
                *inherited_overlay.clauses,
                *(new_overlay.clauses[index] for index in PASSING_NEW_OVERLAY_INDICES),
            ),
        )
        roundtrip = parse_threshold_no_good_vault(
            page.serialized,
            observed_variables=page.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        validate_threshold_no_good_vault_identity(page, expected=expected_identity)
    except ThresholdNoGoodVaultError as exc:
        raise O1C106PreparationError("composed active Page-21 differs") from exc
    if (
        roundtrip != page
        or page.sha256 != PAGE21_SHA256
        or page.clause_count != PAGE21_ACTIVE_LIMIT
        or page.literal_count != PAGE21_LITERAL_COUNT
        or page.serialized_bytes != PAGE21_SERIALIZED_BYTES
        or page.clause_aggregate_sha256 != PAGE21_CLAUSE_AGGREGATE_SHA256
        or page.sha256 in {PAGE20_SHA256, PAGE20_PURE_EMITTED_SHA256}
    ):
        raise O1C106PreparationError("Page-21 frozen encoding differs")

    active_rows = tuple(
        (
            *(emitted_audit[index] for index in selected_emitted),
            *(inherited_audit[index] for index in _o1c102.DERIVED_OVERLAY_ORDER),
            *(new_audit[index] for index in PASSING_NEW_OVERLAY_INDICES),
        )
    )
    excluded_rows = tuple(new_audit[index] for index in FAILED_NEW_OVERLAY_INDICES)
    metrics = tuple(row.get("metric") for row in active_rows)
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in metrics
    ):
        raise O1C106PreparationError("Page-21 aggregate metric differs")
    maximum_upper = max(cast(float, value) for value in metrics)
    if (
        len(active_rows) != PAGE21_ACTIVE_LIMIT
        or any(row.get("passed") is not True for row in active_rows)
        or any(row.get("active") is not True for row in active_rows)
        or len(excluded_rows) != len(FAILED_NEW_OVERLAY_INDICES)
        or any(row.get("passed") is not False for row in excluded_rows)
        or any(row.get("active") is not False for row in excluded_rows)
        or _f64_hex(maximum_upper) != _f64_hex(PAGE21_MAXIMUM_CERTIFIED_UPPER_BOUND)
        or not maximum_upper < THRESHOLD
    ):
        raise O1C106PreparationError("Page-21 aggregate certification differs")
    certification: dict[str, object] = {
        "schema": CERTIFICATION_AUDIT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "execution": {
            "offline_only": True,
            "native_solver_calls": 0,
            "native_preflight_calls": 0,
            "science_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
        },
        "theorem": {
            "implementation": "joint_score_sieve_v8._certify_no_good",
            "rule": _v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE,
            "bound_rule": _v8.JOINT_SCORE_SIEVE_BOUND_RULE,
            "threshold": THRESHOLD,
            "threshold_f64le_hex": THRESHOLD_F64LE_HEX,
            "source_and_input_seals": context.source_seals,
        },
        "page21": {
            "lineage_ordinal": PAGE21_LINEAGE_ORDINAL,
            "sha256": page.sha256,
            "clause_count": page.clause_count,
            "literal_count": page.literal_count,
            "serialized_bytes": page.serialized_bytes,
            "all_active_clauses_certified": True,
            "active_pass_count": len(active_rows),
            "active_fail_count": 0,
            "maximum_active_upper_bound": maximum_upper,
            "maximum_active_upper_bound_f64le_hex": _f64_hex(maximum_upper),
            "maximum_strictly_below_threshold": maximum_upper < THRESHOLD,
        },
        "categories": {
            "emitted": {
                "active": PAGE21_EMITTED_COUNT,
                "pass": PAGE21_EMITTED_COUNT,
                "fail": 0,
            },
            "inherited_derived": {
                "active": PAGE21_INHERITED_DERIVED_COUNT,
                "pass": PAGE21_INHERITED_DERIVED_COUNT,
                "fail": 0,
            },
            "new_derived": {
                "candidate": 52,
                "active": PAGE21_NEW_DERIVED_COUNT,
                "pass": PAGE21_NEW_DERIVED_COUNT,
                "excluded_fail": len(FAILED_NEW_OVERLAY_INDICES),
                "passing_closure_indices": list(PASSING_NEW_OVERLAY_INDICES),
                "excluded_failing_closure_indices": list(FAILED_NEW_OVERLAY_INDICES),
            },
        },
        "active_rows_in_serialization_order": list(active_rows),
        "excluded_new_overlay_failure_rows": list(excluded_rows),
        "publication_gate": "all-247-active-v8-certifications-finished-before-publication",
        "passed": True,
    }
    certification_payload = canonical_json_bytes(certification)

    relations, undominated = _relation_data(bundle_artifacts[DERIVED_RECEIPT_NAME])
    selected_derived_logical = {
        *(2_338 + index for index in _o1c102.DERIVED_OVERLAY_ORDER),
        *(2_608 + index for index in PASSING_NEW_OVERLAY_INDICES),
    }
    dominated_native = {
        emitted_index
        for left, right in relations
        if left in selected_derived_logical
        and (emitted_index := _logical_to_emitted_index(right)) is not None
    }
    if len(dominated_native) != 46 or any(
        not 0 <= index < EMITTED_CLAUSE_COUNT for index in dominated_native
    ):
        raise O1C106PreparationError("logical relation mapping differs")

    selected_set = set(selected_emitted)
    categories = {
        "structural_root": tuple(
            index for index in pure.structural_root_indices if index in selected_set
        ),
        "pinned_core": tuple(
            index for index in pure.pinned_core_indices if index in selected_set
        ),
        "inherited_debt": tuple(
            index for index in pure.inherited_debt_indices if index in selected_set
        ),
        "new_debt": tuple(
            index for index in pure.new_debt_indices if index in selected_set
        ),
        "hot_event": tuple(
            index for index in pure.hot_event_indices if index in selected_set
        ),
        "recycled": tuple(
            index for index in pure.recycled_indices if index in selected_set
        ),
    }
    category_counts: dict[str, int] = {
        "emitted_structural_root": len(categories["structural_root"]),
        "inherited_derived_structural_root": PAGE21_INHERITED_DERIVED_COUNT,
        "new_derived_structural_root": PAGE21_NEW_DERIVED_COUNT,
        "emitted_pinned_core": len(categories["pinned_core"]),
        "emitted_inherited_debt": len(categories["inherited_debt"]),
        "emitted_new_debt": len(categories["new_debt"]),
        "emitted_hot_event": len(categories["hot_event"]),
        "emitted_recycled": len(categories["recycled"]),
    }
    category_order: list[Mapping[str, object]] = [
        {"namespace": "emitted-causal-attic", "union_index": index}
        for index in categories["structural_root"]
    ]
    category_order.extend(inherited_rows)
    category_order.extend(new_rows)
    for category in (
        "pinned_core",
        "inherited_debt",
        "new_debt",
        "hot_event",
        "recycled",
    ):
        category_order.extend(
            {
                "namespace": "emitted-causal-attic",
                "category": category,
                "union_index": index,
            }
            for index in categories[category]
        )
    if (
        len(category_order) != PAGE21_ACTIVE_LIMIT
        or sum(category_counts.values()) != PAGE21_ACTIVE_LIMIT
    ):
        raise O1C106PreparationError("Page-21 category order differs")

    prior_used = tuple(
        cast(
            Sequence[str],
            _sequence(
                parent_activation.get("used_active_sha256"), "parent used inputs"
            ),
        )
    )
    if (
        not prior_used
        or prior_used[-1] != PAGE20_SHA256
        or PAGE20_PURE_EMITTED_SHA256 in prior_used
        or page.sha256 in prior_used
    ):
        raise O1C106PreparationError("parent activation identities differ")
    current_entry: dict[str, object] = {
        "lineage_ordinal": PAGE21_LINEAGE_ORDINAL,
        "role": "v8-certified-composed-causal-page-with-two-resolution-namespaces",
        "active_sha256": page.sha256,
        "selected_emitted_union_indices": list(selected_emitted),
        "replacement_emitted_union_indices": list(replacements),
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_new_derived_clauses": list(new_rows),
        "certification_audit_artifact": CERTIFICATION_AUDIT_NAME,
        "certification_audit_sha256": sha256_bytes(certification_payload),
    }
    activation_document: dict[str, object] = {
        "schema": COMPOSED_ACTIVATION_SCHEMA,
        "parent_composed_prefix": {
            "schema": parent_activation.get("schema"),
            "serialized_bytes": len(parent_activation_payload),
            "sha256": sha256_bytes(parent_activation_payload),
            "document": parent_activation,
            "byte_exact_and_unmodified": True,
        },
        "burned_parent": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "lineage_ordinal": PAGE20_LINEAGE_ORDINAL,
            "active_sha256": PAGE20_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "intent_sha256": PARENT_INTENT_SHA256,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "retry_or_replay_authorized": False,
        },
        "composed_entries": [current_entry],
        "used_active_sha256": [*prior_used, page.sha256],
        "forbidden_nonactivated_candidate_sha256": PAGE20_PURE_EMITTED_SHA256,
        "pure_emitted_candidate_activated": False,
    }
    activation_payload = canonical_json_bytes(activation_document)

    prior_counts = tuple(
        cast(
            Sequence[int],
            _sequence(
                parent_residency.get("activation_counts"), "parent emitted counts"
            ),
        )
    )
    prior_lineages = tuple(
        cast(
            Sequence[int | None],
            _sequence(
                parent_residency.get("last_active_lineages"), "parent emitted lineages"
            ),
        )
    )
    old_counts = tuple(
        cast(
            Sequence[int],
            _sequence(
                parent_residency.get("inherited_derived_activation_counts"),
                "parent inherited counts",
            ),
        )
    )
    old_lineages = tuple(
        cast(
            Sequence[int | None],
            _sequence(
                parent_residency.get("inherited_derived_last_active_lineages"),
                "parent inherited lineages",
            ),
        )
    )
    new_counts = tuple(
        cast(
            Sequence[int],
            _sequence(
                parent_residency.get("new_derived_activation_counts"),
                "parent new counts",
            ),
        )
    )
    new_lineages = tuple(
        cast(
            Sequence[int | None],
            _sequence(
                parent_residency.get("new_derived_last_active_lineages"),
                "parent new lineages",
            ),
        )
    )
    if (
        len(prior_counts) != EMITTED_CLAUSE_COUNT
        or len(prior_lineages) != EMITTED_CLAUSE_COUNT
        or len(old_counts) != INHERITED_DERIVED_CLAUSE_COUNT
        or len(old_lineages) != INHERITED_DERIVED_CLAUSE_COUNT
        or len(new_counts) != NEW_DERIVED_CLAUSE_COUNT
        or len(new_lineages) != NEW_DERIVED_CLAUSE_COUNT
    ):
        raise O1C106PreparationError("parent activation namespace differs")
    activation_counts = tuple(
        count + (1 if index in selected_set else 0)
        for index, count in enumerate(prior_counts)
    )
    last_active_lineages = tuple(
        PAGE21_LINEAGE_ORDINAL if index in selected_set else lineage
        for index, lineage in enumerate(prior_lineages)
    )
    old_selected = set(_o1c102.DERIVED_OVERLAY_ORDER)
    inherited_counts = tuple(
        count + (1 if index in old_selected else 0)
        for index, count in enumerate(old_counts)
    )
    inherited_lineages = tuple(
        PAGE21_LINEAGE_ORDINAL if index in old_selected else lineage
        for index, lineage in enumerate(old_lineages)
    )
    new_selected = set(PASSING_NEW_OVERLAY_INDICES)
    updated_new_counts = tuple(
        count + (1 if index in new_selected else 0)
        for index, count in enumerate(new_counts)
    )
    updated_new_lineages = tuple(
        PAGE21_LINEAGE_ORDINAL if index in new_selected else lineage
        for index, lineage in enumerate(new_lineages)
    )
    selected_logical = {
        *(_o1c104._emitted_union_to_logical_index(index) for index in selected_emitted),
        *selected_derived_logical,
    }

    def never_activated(logical_index: int) -> bool:
        if logical_index < 2_338:
            return activation_counts[logical_index] == 0
        if logical_index < 2_343:
            return inherited_counts[logical_index - 2_338] == 0
        if logical_index < 2_608:
            return (
                activation_counts[logical_index - INHERITED_DERIVED_CLAUSE_COUNT] == 0
            )
        return updated_new_counts[logical_index - 2_608] == 0

    never_resident = tuple(
        index
        for index in undominated
        if index not in selected_logical and never_activated(index)
    )
    current_projection: dict[str, object] = {
        "encoding_only": page.describe(),
        "maximum_clause_count": PAGE21_ACTIVE_LIMIT,
        "category_counts": category_counts,
        "category_priority_order": category_order,
        "serialization_rule": "emitted-union-index-ascending;inherited-overlay-order;passing-new-overlay-closure-index-ascending",
        "selected_emitted_union_indices": list(selected_emitted),
        "priority_selected_emitted_union_indices": list(priority_selected),
        "replacement_emitted_union_indices": list(replacements),
        "replacement_emitted_union_indices_sha256": REPLACEMENT_EMITTED_INDICES_SHA256,
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_new_derived_clauses": list(new_rows),
        "excluded_new_derived_closure_indices": list(FAILED_NEW_OVERLAY_INDICES),
        "displaced_emitted_union_indices": list(displaced),
    }
    residency_document: dict[str, object] = {
        "schema": COMPOSED_RESIDENCY_SCHEMA,
        "active_limit": PAGE21_ACTIVE_LIMIT,
        "lineage_ordinal": PAGE21_LINEAGE_ORDINAL,
        "namespace_contract": {
            "emitted": "causal-attic-v1-with-native-ClauseOccurrence",
            "inherited_derived": "immutable-o1c102-resolution-sidecar-without-ClauseOccurrence",
            "new_derived": "immutable-o1c104-resolution-sidecar-without-ClauseOccurrence",
            "derived_enters_emitted_attic": False,
            "derived_occurrence_rows": 0,
            "selector": "parent-selector-priority-with-v8-certified-type-safe-overlay",
            "logical_registry_reordered": False,
        },
        "parent_composed_residency": {
            "serialized_bytes": len(parent_residency_payload),
            "sha256": sha256_bytes(parent_residency_payload),
            "document": parent_residency,
            "byte_exact_and_unmodified": True,
        },
        "emitted_causal_attic": attic.describe(),
        "emitted_selector_candidate": {
            "encoding_only": pure.describe(),
            "activated": False,
            "reason": "type-safe-derived-overlay-finalized-and-certified-before-lineage34-activation",
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "historical-emitted-causal-attic",
                "inherited-o1c102-derived-resolution",
                "new-o1c103-native-emission",
                "new-o1c104-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "historical-emitted-causal-attic",
                    "start": 0,
                    "stop_exclusive": 2_338,
                    "clause_count": 2_338,
                },
                {
                    "namespace": "inherited-o1c102-derived-resolution",
                    "start": 2_338,
                    "stop_exclusive": 2_343,
                    "clause_count": 5,
                },
                {
                    "namespace": "new-o1c103-native-emission",
                    "start": 2_343,
                    "stop_exclusive": 2_608,
                    "clause_count": 265,
                },
                {
                    "namespace": "new-o1c104-derived-resolution",
                    "start": 2_608,
                    "stop_exclusive": 2_692,
                    "clause_count": 84,
                },
            ],
            "emitted_clause_count": EMITTED_CLAUSE_COUNT,
            "inherited_derived_clause_count": INHERITED_DERIVED_CLAUSE_COUNT,
            "new_derived_clause_count": NEW_DERIVED_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_encoding_sha256": LOGICAL_KNOWN_SHA256,
            "combined_literal_count": LOGICAL_KNOWN_LITERAL_COUNT,
            "combined_serialized_bytes": LOGICAL_KNOWN_SERIALIZED_BYTES,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "strict_subsumption_pair_count": len(relations),
            "selected_derived_strictly_dominated_native_count": len(dominated_native),
            "undominated_clause_count": len(undominated),
            "relation_artifact": DERIVED_RECEIPT_NAME,
            "byte_exact_sidecars_preserved": True,
        },
        "current_projection": current_projection,
        "activation_counts": list(activation_counts),
        "last_active_lineages": list(last_active_lineages),
        "inherited_derived_activation_counts": list(inherited_counts),
        "inherited_derived_last_active_lineages": list(inherited_lineages),
        "new_derived_activation_counts": list(updated_new_counts),
        "new_derived_last_active_lineages": list(updated_new_lineages),
        "never_resident_undominated_logical_indices": list(never_resident),
        "certification_audit": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": sha256_bytes(certification_payload),
            "all_active_clauses_certified": True,
            "active_pass_count": PAGE21_ACTIVE_LIMIT,
            "active_fail_count": 0,
        },
        "activation_ledger": activation_document,
    }
    residency_payload = canonical_json_bytes(residency_document)
    return _Composition(
        page=page,
        selected_emitted=selected_emitted,
        priority_selected_emitted=priority_selected,
        displaced_emitted=displaced,
        replacement_emitted=replacements,
        inherited_rows=tuple(inherited_rows),
        new_rows=new_rows,
        category_counts=category_counts,
        category_priority_order=tuple(category_order),
        residency_payload=residency_payload,
        activation_payload=activation_payload,
        certification_payload=certification_payload,
    )


def _authoritative_state(
    previous: PreparedCausalRolloverArtifacts, composition: _Composition
) -> ComposedPage21State:
    residency = _canonical_document(composition.residency_payload, "Page-21 residency")
    current = _mapping(residency.get("current_projection"), "Page-21 projection")
    projection = ComposedPage21Projection(
        lineage_ordinal=PAGE21_LINEAGE_ORDINAL,
        vault=composition.page,
        pure_emitted_candidate=previous.state.current_projection.base_selector_projection,
        selected_emitted_union_indices=composition.selected_emitted,
        priority_selected_emitted_union_indices=composition.priority_selected_emitted,
        replacement_emitted_union_indices=composition.replacement_emitted,
        selected_inherited_derived_clauses=composition.inherited_rows,
        selected_new_derived_clauses=composition.new_rows,
        displaced_emitted_union_indices=composition.displaced_emitted,
        category_counts=composition.category_counts,
        category_priority_order=composition.category_priority_order,
        document=current,
    )
    state = ComposedPage21State(
        attic=previous.state.attic,
        current_projection=projection,
        residency_payload=composition.residency_payload,
        activation_payload=composition.activation_payload,
    )
    if (
        state.describe() != residency
        or state.active_projection.sha256 != PAGE21_SHA256
        or state.used_active_sha256[-1] != PAGE21_SHA256
        or PAGE20_SHA256 not in state.used_active_sha256
        or PAGE20_PURE_EMITTED_SHA256 in state.used_active_sha256
    ):
        raise O1C106PreparationError("authoritative Page-21 state differs")
    return state


def prepare_o1c106_page21_type_safe_rollover(
    *,
    o1c104_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    root = lab_root()
    bundle = _canonical_path(
        root / DEFAULT_O1C104_BUNDLE_RELATIVE
        if o1c104_bundle_dir is None
        else o1c104_bundle_dir,
        "O1C-0104 bundle",
        directory=True,
    )
    capsule = _canonical_path(
        root / DEFAULT_PARENT_CAPSULE_RELATIVE if capsule_dir is None else capsule_dir,
        "parent capsule",
        directory=True,
    )
    result_path = _canonical_path(
        root / DEFAULT_PARENT_RESULT_RELATIVE
        if parent_result_path is None
        else parent_result_path,
        "parent result",
        directory=False,
    )
    _validate_parent_terminal(capsule, result_path)
    previous, bundle_artifacts = _validate_o1c104_bundle(bundle)
    _validate_capsule_initial_equals_bundle(capsule, bundle_artifacts)
    context = _sealed_public_inputs(root)
    composition = _compose_page21(previous, bundle_artifacts, context)
    state = _authoritative_state(previous, composition)

    copied_names = {
        NEW_CHUNK_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        COMMON_CORE_AUDIT_NAME,
        FINAL_BANK_NAME,
        PRIORITY_RECEIPT_NAME,
        INHERITED_DERIVED_RECEIPT_NAME,
        INHERITED_DERIVED_CLOSURE_NAME,
        INHERITED_DERIVED_OVERLAY_NAME,
        DERIVED_RECEIPT_NAME,
        DERIVED_CLOSURE_NAME,
        DERIVED_OVERLAY_NAME,
    }
    artifacts: dict[str, bytes] = {
        name: bundle_artifacts[name] for name in copied_names
    }
    artifacts.update(
        {
            ACTIVE_PROJECTION_NAME: composition.page.serialized,
            RESIDENCY_NAME: composition.residency_payload,
            ACTIVATION_LEDGER_NAME: composition.activation_payload,
            CERTIFICATION_AUDIT_NAME: composition.certification_payload,
        }
    )
    roles = _artifact_roles()
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - composition.page.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - composition.page.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - composition.page.serialized_bytes,
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
            "page21_burned": False,
            "lineage34_burned": False,
            "page20_retry_or_replay_authorized": False,
            "lineage33_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        },
        "parent_terminal": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_manifest_serialized_bytes": PARENT_CAPSULE_MANIFEST_BYTES,
            "capsule_entry_count": PARENT_CAPSULE_ENTRY_COUNT,
            "result_sha256": PARENT_RESULT_SHA256,
            "result_serialized_bytes": PARENT_RESULT_BYTES,
            "intent_sha256": PARENT_INTENT_SHA256,
            "terminal_failure_sha256": PARENT_TERMINAL_FAILURE_SHA256,
            "classification": "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL",
            "stop_reason": "burned-terminal-failure-no-retry",
            "page20_sha256": PAGE20_SHA256,
            "page20_burned": True,
            "lineage33_burned": True,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": False,
            "retry_or_replay_authorized": False,
            "science_gain": False,
        },
        "canonical_o1c104": {
            "bundle_manifest_sha256": O1C104_MANIFEST_SHA256,
            "bundle_manifest_serialized_bytes": O1C104_MANIFEST_BYTES,
            "bundle_file_count": O1C104_BUNDLE_FILE_COUNT,
            "capsule_initial_byte_equal": True,
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "historical-emitted-causal-attic",
                "inherited-o1c102-derived-resolution",
                "new-o1c103-native-emission",
                "new-o1c104-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "historical-emitted-causal-attic",
                    "start": 0,
                    "stop_exclusive": 2_338,
                    "clause_count": 2_338,
                },
                {
                    "namespace": "inherited-o1c102-derived-resolution",
                    "start": 2_338,
                    "stop_exclusive": 2_343,
                    "clause_count": 5,
                },
                {
                    "namespace": "new-o1c103-native-emission",
                    "start": 2_343,
                    "stop_exclusive": 2_608,
                    "clause_count": 265,
                },
                {
                    "namespace": "new-o1c104-derived-resolution",
                    "start": 2_608,
                    "stop_exclusive": 2_692,
                    "clause_count": 84,
                },
            ],
            "emitted_clause_count": EMITTED_CLAUSE_COUNT,
            "inherited_derived_clause_count": INHERITED_DERIVED_CLAUSE_COUNT,
            "new_derived_clause_count": NEW_DERIVED_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_encoding_sha256": LOGICAL_KNOWN_SHA256,
            "combined_literal_count": LOGICAL_KNOWN_LITERAL_COUNT,
            "combined_serialized_bytes": LOGICAL_KNOWN_SERIALIZED_BYTES,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "byte_exact_receipt_closure_overlay_sidecars_preserved": True,
            "failing_clauses_retained_in_logical_sidecars": True,
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        },
        "derived_resolution_namespaces": {
            "inherited": {
                "receipt_sha256": INHERITED_RECEIPT_SHA256,
                "closure_sha256": INHERITED_CLOSURE_SHA256,
                "closure_clause_count": INHERITED_DERIVED_CLAUSE_COUNT,
                "overlay_sha256": INHERITED_OVERLAY_SHA256,
                "overlay_clause_count": PAGE21_INHERITED_DERIVED_COUNT,
                "resident_clause_count": PAGE21_INHERITED_DERIVED_COUNT,
            },
            "new": {
                "receipt_sha256": NEW_RECEIPT_SHA256,
                "closure_sha256": NEW_CLOSURE_SHA256,
                "closure_clause_count": NEW_DERIVED_CLAUSE_COUNT,
                "overlay_sha256": NEW_OVERLAY_SHA256,
                "overlay_clause_count": 52,
                "resident_clause_count": PAGE21_NEW_DERIVED_COUNT,
                "resident_closure_indices": list(PASSING_NEW_OVERLAY_INDICES),
                "active_only_excluded_closure_indices": list(
                    FAILED_NEW_OVERLAY_INDICES
                ),
            },
            "combined_overlay_materialized": False,
            "causal_attic_occurrence_rows_added": 0,
        },
        "certification": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": sha256_bytes(composition.certification_payload),
            "serialized_bytes": len(composition.certification_payload),
            "real_v8_theorem": True,
            "all_active_clauses_certified_before_publication": True,
            "active_pass_count": PAGE21_ACTIVE_LIMIT,
            "active_fail_count": 0,
            "maximum_active_upper_bound": PAGE21_MAXIMUM_CERTIFIED_UPPER_BOUND,
            "threshold": THRESHOLD,
            "strictly_below_threshold": True,
        },
        "page21": {
            "lineage_ordinal": PAGE21_LINEAGE_ORDINAL,
            "active_limit": PAGE21_ACTIVE_LIMIT,
            "active_sha256": composition.page.sha256,
            "clause_aggregate_sha256": composition.page.clause_aggregate_sha256,
            "clause_count": composition.page.clause_count,
            "literal_count": composition.page.literal_count,
            "serialized_bytes": composition.page.serialized_bytes,
            "category_counts": dict(composition.category_counts),
            "headroom": headroom,
            "selected_emitted_clause_count": PAGE21_EMITTED_COUNT,
            "selected_inherited_derived_clause_count": PAGE21_INHERITED_DERIVED_COUNT,
            "selected_new_derived_clause_count": PAGE21_NEW_DERIVED_COUNT,
            "replacement_emitted_union_indices": list(composition.replacement_emitted),
            "replacement_emitted_union_indices_sha256": REPLACEMENT_EMITTED_INDICES_SHA256,
            "displaced_emitted_union_indices": list(composition.displaced_emitted),
            "forbidden_pure_emitted_candidate_sha256": PAGE20_PURE_EMITTED_SHA256,
            "pure_emitted_candidate_activated": False,
            "fresh_identity": composition.page.sha256
            not in {PAGE20_SHA256, PAGE20_PURE_EMITTED_SHA256},
            "native_capacity_proof": {
                "maximum_clause_count": O1C66_VAULT_CAPS.maximum_clauses,
                "page21_input_clauses": composition.page.clause_count,
                "maximum_additional_unique_clauses_before_capacity_terminal": headroom[
                    "clauses"
                ],
                "required_clause_headroom": 265,
                "proved_sufficient": headroom["clauses"] == 265,
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
            "receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "receipt_artifact": PRIORITY_RECEIPT_NAME,
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
        _canonical_document(manifest_payload, "Page-21 manifest") != manifest
        or len(artifacts) != 16
        or headroom["clauses"] != 265
    ):
        raise O1C106PreparationError("Page-21 preparation manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=cast(_o1c104.ComposedPage20State, state),
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c106_page21_type_safe_rollover(
    *,
    o1c104_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    return prepare_o1c106_page21_type_safe_rollover(
        o1c104_bundle_dir=o1c104_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _expected_manifest_sections(
    state: ComposedPage21State,
    active: ThresholdNoGoodVault,
) -> Mapping[str, object]:
    projection = state.current_projection
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - active.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - active.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - active.serialized_bytes,
    }
    return {
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
            "page21_burned": False,
            "lineage34_burned": False,
            "page20_retry_or_replay_authorized": False,
            "lineage33_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        },
        "parent_terminal": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_manifest_serialized_bytes": PARENT_CAPSULE_MANIFEST_BYTES,
            "capsule_entry_count": PARENT_CAPSULE_ENTRY_COUNT,
            "result_sha256": PARENT_RESULT_SHA256,
            "result_serialized_bytes": PARENT_RESULT_BYTES,
            "intent_sha256": PARENT_INTENT_SHA256,
            "terminal_failure_sha256": PARENT_TERMINAL_FAILURE_SHA256,
            "classification": "PARENT_CENTERED_CONTINUATION_OPERATIONAL_TERMINAL",
            "stop_reason": "burned-terminal-failure-no-retry",
            "page20_sha256": PAGE20_SHA256,
            "page20_burned": True,
            "lineage33_burned": True,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": False,
            "retry_or_replay_authorized": False,
            "science_gain": False,
        },
        "canonical_o1c104": {
            "bundle_manifest_sha256": O1C104_MANIFEST_SHA256,
            "bundle_manifest_serialized_bytes": O1C104_MANIFEST_BYTES,
            "bundle_file_count": O1C104_BUNDLE_FILE_COUNT,
            "capsule_initial_byte_equal": True,
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "historical-emitted-causal-attic",
                "inherited-o1c102-derived-resolution",
                "new-o1c103-native-emission",
                "new-o1c104-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "historical-emitted-causal-attic",
                    "start": 0,
                    "stop_exclusive": 2_338,
                    "clause_count": 2_338,
                },
                {
                    "namespace": "inherited-o1c102-derived-resolution",
                    "start": 2_338,
                    "stop_exclusive": 2_343,
                    "clause_count": 5,
                },
                {
                    "namespace": "new-o1c103-native-emission",
                    "start": 2_343,
                    "stop_exclusive": 2_608,
                    "clause_count": 265,
                },
                {
                    "namespace": "new-o1c104-derived-resolution",
                    "start": 2_608,
                    "stop_exclusive": 2_692,
                    "clause_count": 84,
                },
            ],
            "emitted_clause_count": EMITTED_CLAUSE_COUNT,
            "inherited_derived_clause_count": INHERITED_DERIVED_CLAUSE_COUNT,
            "new_derived_clause_count": NEW_DERIVED_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_encoding_sha256": LOGICAL_KNOWN_SHA256,
            "combined_literal_count": LOGICAL_KNOWN_LITERAL_COUNT,
            "combined_serialized_bytes": LOGICAL_KNOWN_SERIALIZED_BYTES,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "byte_exact_receipt_closure_overlay_sidecars_preserved": True,
            "failing_clauses_retained_in_logical_sidecars": True,
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        },
        "derived_resolution_namespaces": {
            "inherited": {
                "receipt_sha256": INHERITED_RECEIPT_SHA256,
                "closure_sha256": INHERITED_CLOSURE_SHA256,
                "closure_clause_count": INHERITED_DERIVED_CLAUSE_COUNT,
                "overlay_sha256": INHERITED_OVERLAY_SHA256,
                "overlay_clause_count": PAGE21_INHERITED_DERIVED_COUNT,
                "resident_clause_count": PAGE21_INHERITED_DERIVED_COUNT,
            },
            "new": {
                "receipt_sha256": NEW_RECEIPT_SHA256,
                "closure_sha256": NEW_CLOSURE_SHA256,
                "closure_clause_count": NEW_DERIVED_CLAUSE_COUNT,
                "overlay_sha256": NEW_OVERLAY_SHA256,
                "overlay_clause_count": 52,
                "resident_clause_count": PAGE21_NEW_DERIVED_COUNT,
                "resident_closure_indices": list(PASSING_NEW_OVERLAY_INDICES),
                "active_only_excluded_closure_indices": list(
                    FAILED_NEW_OVERLAY_INDICES
                ),
            },
            "combined_overlay_materialized": False,
            "causal_attic_occurrence_rows_added": 0,
        },
        "certification": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": CERTIFICATION_AUDIT_SHA256,
            "serialized_bytes": CERTIFICATION_AUDIT_BYTES,
            "real_v8_theorem": True,
            "all_active_clauses_certified_before_publication": True,
            "active_pass_count": PAGE21_ACTIVE_LIMIT,
            "active_fail_count": 0,
            "maximum_active_upper_bound": PAGE21_MAXIMUM_CERTIFIED_UPPER_BOUND,
            "threshold": THRESHOLD,
            "strictly_below_threshold": True,
        },
        "page21": {
            "lineage_ordinal": PAGE21_LINEAGE_ORDINAL,
            "active_limit": PAGE21_ACTIVE_LIMIT,
            "active_sha256": active.sha256,
            "clause_aggregate_sha256": active.clause_aggregate_sha256,
            "clause_count": active.clause_count,
            "literal_count": active.literal_count,
            "serialized_bytes": active.serialized_bytes,
            "category_counts": dict(projection.category_counts),
            "headroom": headroom,
            "selected_emitted_clause_count": PAGE21_EMITTED_COUNT,
            "selected_inherited_derived_clause_count": (
                PAGE21_INHERITED_DERIVED_COUNT
            ),
            "selected_new_derived_clause_count": PAGE21_NEW_DERIVED_COUNT,
            "replacement_emitted_union_indices": list(
                projection.replacement_emitted_union_indices
            ),
            "replacement_emitted_union_indices_sha256": (
                REPLACEMENT_EMITTED_INDICES_SHA256
            ),
            "displaced_emitted_union_indices": list(
                projection.displaced_emitted_union_indices
            ),
            "forbidden_pure_emitted_candidate_sha256": (
                PAGE20_PURE_EMITTED_SHA256
            ),
            "pure_emitted_candidate_activated": False,
            "fresh_identity": True,
            "native_capacity_proof": {
                "maximum_clause_count": O1C66_VAULT_CAPS.maximum_clauses,
                "page21_input_clauses": active.clause_count,
                "maximum_additional_unique_clauses_before_capacity_terminal": (
                    headroom["clauses"]
                ),
                "required_clause_headroom": 265,
                "proved_sufficient": headroom["clauses"] == 265,
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
            "receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "receipt_artifact": PRIORITY_RECEIPT_NAME,
            "priority_is_key_bit_belief": False,
            "semantic_role": "unchanged-sealed-live-continuation-bytes",
        },
    }


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts) or not isinstance(
        prepared.state, ComposedPage21State
    ):
        raise O1C106PreparationError("prepared Page-21 publication bundle differs")
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
        INHERITED_DERIVED_RECEIPT_NAME,
        INHERITED_DERIVED_CLOSURE_NAME,
        INHERITED_DERIVED_OVERLAY_NAME,
        DERIVED_RECEIPT_NAME,
        DERIVED_CLOSURE_NAME,
        DERIVED_OVERLAY_NAME,
        CERTIFICATION_AUDIT_NAME,
        PREPARATION_MANIFEST_NAME,
    }
    manifest = _mapping(prepared.manifest, "prepared Page-21 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-21 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    active_payload = prepared.artifacts.get(ACTIVE_PROJECTION_NAME)
    audit_payload = prepared.artifacts.get(CERTIFICATION_AUDIT_NAME)
    if (
        set(prepared.artifacts) != expected_names
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or not isinstance(manifest_payload, bytes)
        or manifest_payload != canonical_json_bytes(manifest)
        or set(rows) != expected_names - {PREPARATION_MANIFEST_NAME}
        or not isinstance(active_payload, bytes)
        or not isinstance(audit_payload, bytes)
    ):
        raise O1C106PreparationError("prepared Page-21 publication bundle differs")
    audit = _canonical_document(audit_payload, "prepared Page-21 certification audit")
    try:
        active = parse_threshold_no_good_vault(
            active_payload,
            observed_variables=prepared.state.attic.union_vault.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C106PreparationError(
            "prepared Page-21 active projection differs"
        ) from exc
    if (
        active != prepared.state.active_projection
        or active.sha256 != PAGE21_SHA256
        or active.clause_count != PAGE21_ACTIVE_LIMIT
        or active.literal_count != PAGE21_LITERAL_COUNT
        or active.serialized_bytes != PAGE21_SERIALIZED_BYTES
        or active.clause_aggregate_sha256 != PAGE21_CLAUSE_AGGREGATE_SHA256
        or prepared.artifacts.get(RESIDENCY_NAME) != prepared.state.residency_payload
        or prepared.artifacts.get(ACTIVATION_LEDGER_NAME)
        != prepared.state.activation_payload
        or prepared.state.describe().get("current_projection")
        != prepared.state.current_projection.document
        or audit.get("schema") != CERTIFICATION_AUDIT_SCHEMA
        or audit.get("passed") is not True
        or _mapping(audit.get("page21"), "audit page").get("active_pass_count")
        != PAGE21_ACTIVE_LIMIT
        or sha256_bytes(audit_payload) != CERTIFICATION_AUDIT_SHA256
        or len(audit_payload) != CERTIFICATION_AUDIT_BYTES
        or PAGE20_PURE_EMITTED_SHA256 in prepared.state.used_active_sha256
    ):
        raise O1C106PreparationError("prepared Page-21 publication state differs")

    expected_sections = _expected_manifest_sections(prepared.state, active)
    expected_manifest_keys = {
        "schema",
        "attempt_id",
        "artifacts",
        *expected_sections,
    }
    if set(manifest) != expected_manifest_keys or any(
        manifest.get(name) != expected for name, expected in expected_sections.items()
    ):
        raise O1C106PreparationError("prepared Page-21 manifest contract differs")

    proof_artifact_sha256 = {
        INHERITED_DERIVED_RECEIPT_NAME: INHERITED_RECEIPT_SHA256,
        INHERITED_DERIVED_CLOSURE_NAME: INHERITED_CLOSURE_SHA256,
        INHERITED_DERIVED_OVERLAY_NAME: INHERITED_OVERLAY_SHA256,
        DERIVED_RECEIPT_NAME: NEW_RECEIPT_SHA256,
        DERIVED_CLOSURE_NAME: NEW_CLOSURE_SHA256,
        DERIVED_OVERLAY_NAME: NEW_OVERLAY_SHA256,
        FINAL_BANK_NAME: FINAL_BANK_SHA256,
        PRIORITY_RECEIPT_NAME: PRIORITY_RECEIPT_SHA256,
    }
    if any(
        sha256_bytes(prepared.artifacts[name]) != expected
        for name, expected in proof_artifact_sha256.items()
    ):
        raise O1C106PreparationError("prepared Page-21 immutable sidecar differs")

    roles = _artifact_roles()
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-21 artifact row {name}")
        payload = prepared.artifacts[name]
        if row != _artifact_row(payload, roles[name]):
            raise O1C106PreparationError("prepared Page-21 artifact row differs")


def write_prepared_o1c106_page21_type_safe_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(prepared, output_dir)
    except _publisher.O1C85PreparationError as exc:
        raise O1C106PreparationError("Page-21 publication failed") from exc


def prepare_and_write_o1c106_page21_type_safe_rollover(
    *,
    output_dir: str | Path,
    o1c104_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    prepared = prepare_o1c106_page21_type_safe_rollover(
        o1c104_bundle_dir=o1c104_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c106_page21_type_safe_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0106's zero-call type-safe Page-21 rollover"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--o1c104-bundle",
            default=(root / DEFAULT_O1C104_BUNDLE_RELATIVE).as_posix(),
        )
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
        prepared = prepare_o1c106_page21_type_safe_rollover(
            o1c104_bundle_dir=args.o1c104_bundle,
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c106_page21_type_safe_rollover(prepared, args.output_dir)
    except O1C106PreparationError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(prepared.manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVE_PROJECTION_ROLE",
    "ACTIVATION_LEDGER_NAME",
    "ATTEMPT_ID",
    "CERTIFICATION_AUDIT_NAME",
    "ComposedPage21Projection",
    "ComposedPage21State",
    "DEFAULT_O1C104_BUNDLE_RELATIVE",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FAILED_NEW_OVERLAY_INDICES",
    "O1C106PreparationError",
    "PAGE21_SHA256",
    "PASSING_NEW_OVERLAY_INDICES",
    "PREPARATION_MANIFEST_NAME",
    "REPLACEMENT_EMITTED_UNION_INDICES",
    "main",
    "preflight_o1c106_page21_type_safe_rollover",
    "prepare_and_write_o1c106_page21_type_safe_rollover",
    "prepare_o1c106_page21_type_safe_rollover",
    "write_prepared_o1c106_page21_type_safe_rollover",
]
