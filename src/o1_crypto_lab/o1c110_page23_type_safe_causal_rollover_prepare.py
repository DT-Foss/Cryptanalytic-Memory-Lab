"""Prepare O1C-0110's zero-call type-safe causal Page-23 rollover.

The sealed O1C-0109 lineage-35 call emitted 267 globally novel clauses.  This
module consumes only that immutable capsule/result and the published O1C-0108
Page-22 bundle.  It appends the native occurrences to the emitted causal attic,
computes exact propositional resolution to a genuine fixed point without a
preselected pivot or generation count, certifies every new proof clause with
the real v8 input theorem, and holds a bounded Page-23 bundle in memory.

No native solver, native preflight, science call, target, truth, or reveal path
is reachable from this module.  It intentionally has no publication function.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import shutil
import stat
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c104_page20_causal_rollover_prepare as _o1c104
from . import o1c106_page21_type_safe_rollover_prepare as _o1c106
from . import o1c108_page22_type_safe_causal_rollover_prepare as _o1c108
from . import o1c109_apple8_parent_centered_continuation_run as _o1c109
from .causal_attic_v1 import (
    CausalAttic,
    CausalAtticError,
    ClauseOccurrence,
    ParsedVaultTelemetry,
    SubsumptionRelation,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    reproject_causal_attic,
    sha256_bytes,
    strict_subsumption_relations,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    ResidencyProjection,
    _priority_projection,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0110"
PARENT_ATTEMPT_ID = "O1C-0109"
PREPARATION_SCHEMA = "o1-256-o1c110-page23-type-safe-causal-rollover-preparation-v1"
DERIVED_RECEIPT_SCHEMA = "o1-256-o1c110-derived-resolution-fixed-point-receipt-v1"
CERTIFICATION_AUDIT_SCHEMA = "o1-256-o1c110-page23-v8-certification-audit-v1"
COMPOSED_RESIDENCY_SCHEMA = "o1-score-threshold-composed-residency-v5"
COMPOSED_ACTIVATION_SCHEMA = "o1-score-threshold-composed-activation-ledger-v5"

DEFAULT_O1C108_BUNDLE_RELATIVE = Path(
    "research/o1c108_page22_type_safe_causal_rollover_seed_20260721"
)
DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_103413_313078_O1C-0109_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0109_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)

O1C108_MANIFEST_SHA256 = _o1c109.PUBLISHED_MANIFEST_SHA256
O1C108_MANIFEST_BYTES = _o1c109.PUBLISHED_MANIFEST_BYTES
O1C108_BUNDLE_FILE_COUNT = len(_o1c109.PREPARATION_ARTIFACT_NAMES)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "050a073b24fb2866b87e8353c1c8357c6598fa2eb9cf54119ee2991d7a99f2d0"
)
PARENT_CAPSULE_MANIFEST_BYTES = 5_726
PARENT_CAPSULE_ENTRY_COUNT = 54
PARENT_RESULT_SHA256 = (
    "22ec1c6a2f67c0ec89c85347865c4fc248c43ad2dacc8955fd76a72940a52c28"
)
PARENT_RESULT_BYTES = 17_638
PARENT_INTENT_SHA256 = (
    "6f42318aae4c6a4f7342ba5100e7d3ed3c6c36e416ed61614ff3d7024eca2536"
)
PARENT_INTENT_BYTES = 2_708
PARENT_EPISODE_SHA256 = (
    "47b4e4cf96278864dbe6f76d2ba4779cca7b0029703b1936ae5b5d8210f2425a"
)
PARENT_EPISODE_BYTES = 4_834
PARENT_INVOCATION_SHA256 = (
    "a7b23f879c4ee7eb7cc19f0c406456caea85a1e249644441a840f026cd4131ca"
)
PARENT_INVOCATION_BYTES = 6_482
PARENT_VAULT_TELEMETRY_SHA256 = (
    "9994058a39003697fae7322c7e50d7e7888f63322489cb328de301ac7e7b7705"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_203_145
PARENT_NATIVE_RESULT_SHA256 = (
    "a31c5130994414f99bce30e1e72989a31f7d3d9e02dd3891760d60cb5c9bb435"
)
PARENT_NATIVE_RESULT_BYTES = 5_727_468
PARENT_PRIORITY_RECEIPT_SHA256 = (
    "82d848eae4b00cd7c79ed9f10c2193a6b54e9a23507027fd82a14c87318193a5"
)
PARENT_PRIORITY_RECEIPT_BYTES = 52_137

PARENT_LINEAGE_ORDINAL = 35
PAGE23_LINEAGE_ORDINAL = 36
PAGE23_ACTIVE_LIMIT = 245
PAGE23_EMITTED_COUNT = 4
PAGE23_INHERITED_DERIVED_COUNT = 3
PAGE23_O1C104_DERIVED_COUNT = 41
PAGE23_O1C108_DERIVED_COUNT = 149
PAGE23_O1C110_DERIVED_COUNT = 48

NEW_NATIVE_OCCURRENCE_COUNT = 267
NEW_CHUNK_CLAUSE_COUNT = 267
NEW_CHUNK_LITERAL_COUNT = 749_811
NEW_CHUNK_SERIALIZED_BYTES = 3_000_503
NEW_CHUNK_SHA256 = "be34cd95215e5ebff1e0a08aa45b6bdd2abf116479c39c871447f626093bac87"
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "228da2ac7fc7f66e36dec68de31925860ceaec1525ec27cf8f8a701d49847603"
)
NEW_CHUNK_INVENTORY_SHA256 = (
    "29ad476be015cbd787460377e1431db0bbd933e58115e9f33237c9c190430dac"
)

DERIVED_CLOSURE_CLAUSE_COUNT = 48
DERIVED_CLOSURE_LITERAL_COUNT = 135_888
DERIVED_CLOSURE_BYTES = 543_935
DERIVED_CLOSURE_SHA256 = (
    "8b2a437b14693ac35309791781eeecc1fc84eb73af22a7120c0de32ac128a150"
)
DERIVED_CLOSURE_AGGREGATE_SHA256 = (
    "84c77b316936f014ffc7440c381accac63cbee0685d60ca890f24ba1dc95a085"
)
DERIVED_CLOSURE_INVENTORY_SHA256 = (
    "d447851e6d4695824c7e6fe536f14d6f8229a937974a53fb2f15573e2bf3de8c"
)
PASSING_NEW_DERIVED_INDICES = tuple(range(DERIVED_CLOSURE_CLAUSE_COUNT))
FAILED_NEW_DERIVED_INDICES: tuple[int, ...] = ()
PAGE23_MAXIMUM_CERTIFIED_UPPER_BOUND = 14.561642594796334

G1_PAIR_COUNT = 35_511
G1_ZERO_COMPLEMENT_PAIR_COUNT = 0
G1_MULTI_COMPLEMENT_PAIR_COUNT = 35_463
G1_SINGLE_PIVOT_PAIR_COUNT = 48
G2_PAIR_COUNT = 13_944
G2_ZERO_COMPLEMENT_PAIR_COUNT = 96
G2_MULTI_COMPLEMENT_PAIR_COUNT = 13_848
G2_SINGLE_PIVOT_PAIR_COUNT = 0

PRIOR_LOGICAL_CLAUSE_COUNT = 3_111
INTERMEDIATE_LOGICAL_CLAUSE_COUNT = 3_378
LOGICAL_KNOWN_CLAUSE_COUNT = 3_426
LOGICAL_KNOWN_LITERAL_COUNT = 9_687_641
LOGICAL_KNOWN_SERIALIZED_BYTES = 38_764_459
LOGICAL_KNOWN_SHA256 = (
    "1a7ac7a4c8b5289d30e185d7eabe9c2829412f4742c3fbdcc0149e8f5b1197db"
)
LOGICAL_KNOWN_AGGREGATE_SHA256 = (
    "265dd870cc7c076947b4a13bc9a380b54c2542cf8a99b947bedcfab859d2bdeb"
)
LOGICAL_KNOWN_INVENTORY_SHA256 = (
    "8efb74a693e52256a0fb5707d445d0e4eaa3ab1a47f8dd009b84dd9530dcaa27"
)
LOGICAL_SUBSUMPTION_RELATION_COUNT = 333
LOGICAL_UNDOMINATED_CLAUSE_COUNT = 3_099

ATTIC_CHUNK_COUNT = 23
ATTIC_UNION_CLAUSE_COUNT = 3_136
ATTIC_OCCURRENCE_COUNT = 3_146
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 10
ATTIC_UNION_LITERAL_COUNT = 8_860_435
ATTIC_UNION_SERIALIZED_BYTES = 35_454_475
ATTIC_UNION_SHA256 = "5a54c41fd317833b2315f763851afd6e148b389a44acebc18d3b794c6d0dac04"
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "a7a5ecaf759a293b779caecb34d006b0f8671381f0ffc3607734bc1bb0368244"
)
ATTIC_SUBSUMPTION_RELATION_COUNT = 14
ATTIC_UNDOMINATED_CLAUSE_COUNT = 3_125

PAGE23_PURE_EMITTED_SHA256 = (
    "c5fa2f2164a1d7dbf09b904ea917b063efa57e8450b476ac575cf411678fd6c3"
)
PAGE23_PURE_EMITTED_LITERAL_COUNT = 670_095
PAGE23_PURE_EMITTED_SERIALIZED_BYTES = 2_681_551
PAGE23_PURE_EMITTED_AGGREGATE_SHA256 = (
    "a9b8f1452b67446094699c70158fde06ceaaad437eb3d40084c522120730528c"
)

SELECTED_EMITTED_UNION_INDICES = (9, 123, 144, 551)
SELECTED_EMITTED_INDICES_SHA256 = (
    "5eed519f1d9040440a2c28a56a7153c8432a65c0b6318f2e0250f3337765574d"
)
PAGE23_SHA256 = "023c1565af9e0c056d64361d0f5dacfb26a3546f01b044357b7b86536880f613"
PAGE23_CLAUSE_AGGREGATE_SHA256 = (
    "10656147ceb77888f0353e2f80090008b58dfe30554fc2b161d595ecbbb8f0ec"
)
PAGE23_LITERAL_COUNT = 699_680
PAGE23_SERIALIZED_BYTES = 2_799_891

RESIDENCY_SHA256 = "575016fde7641f464ce2ea529c50349b95e1c42eeb1fbccfb1935ef716d7e901"
RESIDENCY_BYTES = 1_039_171
ACTIVATION_SHA256 = "5327d5cc7f22e7ffd368ecb367885651cc3957d0122def9373dd588b917dabde"
ACTIVATION_BYTES = 155_886
OCCURRENCE_SHA256 = "b06f4cfd6011aa140f6c8dc9cb56602e360039f9fae2a7809c5a21a52904be11"
OCCURRENCE_BYTES = 1_120_396
RELATION_SHA256 = "696a1f88c61810f4be26cdf59a88d0c0f4f43e0b238cd60dea5250a480af65eb"
RELATION_BYTES = 18_992
DERIVED_RECEIPT_SHA256 = (
    "1a864e7ab59ae664a87bd6f1571055bcc0f4842111dd37e944892a3484fe12a1"
)
DERIVED_RECEIPT_BYTES = 310_689
CERTIFICATION_AUDIT_SHA256 = (
    "e5f7135650a0874a81405de696d23632f3ff20ad2cef0e646ec4a3d39e64a48c"
)
CERTIFICATION_AUDIT_BYTES = 166_357
PREPARATION_MANIFEST_SHA256 = (
    "f1b9bd7f3040d03b969d5d62cb5d15c34764ce211b528f53a524ff41e3b72e56"
)
PREPARATION_MANIFEST_BYTES = 11_711

FINAL_BANK_SHA256 = "efffdc2021d3c62bd92e4557a8515f1728bd3350582010b0b4a90a0d2fc65951"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = PARENT_PRIORITY_RECEIPT_SHA256
PRIORITY_RECEIPT_BYTES = PARENT_PRIORITY_RECEIPT_BYTES

NEW_CHUNK_NAME = "lineage-35-native-emissions.vault"
ACTIVE_PROJECTION_NAME = "page-23-active.bin"
ACTIVE_PROJECTION_ROLE = "fresh-lineage-36-type-safe-composed-page23-science-input"
RESIDENCY_NAME = _o1c108.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c108.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c108.OCCURRENCES_NAME
RELATIONS_NAME = _o1c108.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c108.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c108.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = _o1c108.PRIORITY_RECEIPT_NAME
INHERITED_DERIVED_RECEIPT_NAME = _o1c108.INHERITED_DERIVED_RECEIPT_NAME
INHERITED_DERIVED_CLOSURE_NAME = _o1c108.INHERITED_DERIVED_CLOSURE_NAME
INHERITED_DERIVED_OVERLAY_NAME = _o1c108.INHERITED_DERIVED_OVERLAY_NAME
O1C104_DERIVED_RECEIPT_NAME = _o1c108.O1C104_DERIVED_RECEIPT_NAME
O1C104_DERIVED_CLOSURE_NAME = _o1c108.O1C104_DERIVED_CLOSURE_NAME
O1C104_DERIVED_OVERLAY_NAME = _o1c108.O1C104_DERIVED_OVERLAY_NAME
O1C108_DERIVED_RECEIPT_NAME = _o1c108.DERIVED_RECEIPT_NAME
O1C108_DERIVED_CLOSURE_NAME = _o1c108.DERIVED_CLOSURE_NAME
O1C108_DERIVED_OVERLAY_NAME = _o1c108.DERIVED_OVERLAY_NAME
DERIVED_RECEIPT_NAME = "o1c110-derived-resolution-fixed-point-receipt.json"
DERIVED_CLOSURE_NAME = "o1c110-derived-resolution-closure.vault"
DERIVED_OVERLAY_NAME = "o1c110-derived-resolution-overlay.vault"
CERTIFICATION_AUDIT_NAME = "page-23-v8-certification-audit.json"
PREPARATION_MANIFEST_NAME = _o1c108.PREPARATION_MANIFEST_NAME


class O1C110PreparationError(RuntimeError):
    """A sealed parent, fixed-point proof, theorem, or Page-23 seal differs."""


class O1C110PublicationCommittedError(O1C110PreparationError):
    """Publication committed atomically, but its parent fsync did not finish."""

    def __init__(self, target: Path, cause: OSError) -> None:
        self.target = target
        super().__init__(
            f"Page-23 publication committed at {target}, but parent fsync failed: {cause}"
        )


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C110PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C110PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _integer_tuple(value: object, label: str) -> tuple[int, ...]:
    items = tuple(_sequence(value, label))
    if any(isinstance(item, bool) or not isinstance(item, int) for item in items):
        raise O1C110PreparationError(f"{label} differs")
    return cast(tuple[int, ...], items)


def _optional_integer_tuple(value: object, label: str) -> tuple[int | None, ...]:
    items = tuple(_sequence(value, label))
    if any(
        item is not None and (isinstance(item, bool) or not isinstance(item, int))
        for item in items
    ):
        raise O1C110PreparationError(f"{label} differs")
    return cast(tuple[int | None, ...], items)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C110PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C110PreparationError(f"{label} is unreadable") from exc
    regular = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not regular or resolved != path:
        raise O1C110PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C110PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C110PreparationError(f"{label} is not canonical JSON")
    return value


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _inventory(clauses: Sequence[ThresholdNoGoodClause]) -> tuple[list[str], str]:
    values = [clause.sha256 for clause in clauses]
    if len(values) != len(set(values)):
        raise O1C110PreparationError("logical clause inventory contains a duplicate")
    return values, sha256_bytes(canonical_json_bytes(values))


def _index_list_sha256(indices: Sequence[int]) -> str:
    return sha256_bytes(canonical_json_bytes(list(indices)))


def _parse_checksum_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C110PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C110PreparationError("parent capsule manifest row differs")
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
            raise O1C110PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    return entries


def _validate_capsule_inventory(capsule: Path) -> Mapping[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C110PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C110PreparationError("parent capsule manifest differs")
    entries = _parse_checksum_manifest(payload)
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C110PreparationError("parent capsule manifest inventory differs")
    observed: set[str] = set()
    try:
        for path in capsule.rglob("*"):
            relative = path.relative_to(capsule).as_posix()
            item_metadata = path.lstat()
            if stat.S_ISLNK(item_metadata.st_mode):
                raise O1C110PreparationError("parent capsule contains a symlink")
            if stat.S_ISREG(item_metadata.st_mode):
                observed.add(relative)
            elif not stat.S_ISDIR(item_metadata.st_mode):
                raise O1C110PreparationError("parent capsule contains a special file")
    except OSError as exc:
        raise O1C110PreparationError("parent capsule inventory is unreadable") from exc
    if observed != set(entries) | {"artifacts.sha256"}:
        raise O1C110PreparationError("parent capsule inventory differs")
    for relative, digest in entries.items():
        try:
            path = capsule / relative
            item_metadata = path.lstat()
            item = path.read_bytes()
        except OSError as exc:
            raise O1C110PreparationError("parent capsule artifact differs") from exc
        if (
            stat.S_ISLNK(item_metadata.st_mode)
            or not stat.S_ISREG(item_metadata.st_mode)
            or sha256_bytes(item) != digest
        ):
            raise O1C110PreparationError("parent capsule artifact differs")
    return entries


def _zero_call() -> dict[str, object]:
    return {
        "native_solver_calls": 0,
        "native_preflight_calls": 0,
        "science_calls": 0,
        "target_bytes_read": False,
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }


def _validate_parent_success(
    capsule: Path, result_path: Path
) -> tuple[Mapping[str, object], ParsedVaultTelemetry, bytes, bytes]:
    entries = _validate_capsule_inventory(capsule)
    episode_dir = capsule / "episodes/00"
    paths = {
        "result": capsule / "result.json",
        "intent": episode_dir / "intent.json",
        "episode": episode_dir / "episode.json",
        "invocation": capsule / "invocation.json",
        "vault": episode_dir / "vault.json",
        "native_result": episode_dir / "native-result.json",
        "bank": episode_dir / FINAL_BANK_NAME,
        "receipt": episode_dir / "priority-state.json",
    }
    try:
        payloads = {name: path.read_bytes() for name, path in paths.items()}
        external_result = result_path.read_bytes()
    except OSError as exc:
        raise O1C110PreparationError("parent success artifacts are unreadable") from exc
    expected = {
        "result": (PARENT_RESULT_BYTES, PARENT_RESULT_SHA256, "result.json"),
        "intent": (
            PARENT_INTENT_BYTES,
            PARENT_INTENT_SHA256,
            "episodes/00/intent.json",
        ),
        "episode": (
            PARENT_EPISODE_BYTES,
            PARENT_EPISODE_SHA256,
            "episodes/00/episode.json",
        ),
        "invocation": (
            PARENT_INVOCATION_BYTES,
            PARENT_INVOCATION_SHA256,
            "invocation.json",
        ),
        "vault": (
            PARENT_VAULT_TELEMETRY_BYTES,
            PARENT_VAULT_TELEMETRY_SHA256,
            "episodes/00/vault.json",
        ),
        "native_result": (
            PARENT_NATIVE_RESULT_BYTES,
            PARENT_NATIVE_RESULT_SHA256,
            "episodes/00/native-result.json",
        ),
        "bank": (FINAL_BANK_BYTES, FINAL_BANK_SHA256, f"episodes/00/{FINAL_BANK_NAME}"),
        "receipt": (
            PRIORITY_RECEIPT_BYTES,
            PRIORITY_RECEIPT_SHA256,
            "episodes/00/priority-state.json",
        ),
    }
    for name, (size, digest, relative) in expected.items():
        payload = payloads[name]
        if (
            len(payload) != size
            or sha256_bytes(payload) != digest
            or entries.get(relative) != digest
        ):
            raise O1C110PreparationError("parent success seals differ")
    if external_result != payloads["result"]:
        raise O1C110PreparationError("parent authoritative result differs")

    result = _canonical_document(payloads["result"], "parent result")
    intent = _canonical_document(payloads["intent"], "parent intent")
    episode = _canonical_document(payloads["episode"], "parent episode")
    invocation = _canonical_document(payloads["invocation"], "parent invocation")
    native_result = _canonical_document(
        payloads["native_result"], "parent native result"
    )
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    science = _mapping(episode.get("science"), "parent episode science")
    operation = _mapping(episode.get("operational"), "parent episode operation")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    replay_fields = (
        "page21_retry_or_replay_authorized",
        "page20_retry_or_replay_authorized",
        "page19_retry_or_replay_authorized",
        "page18_retry_or_replay_authorized",
        "page17_retry_or_replay_authorized",
        "page16_retry_or_replay_authorized",
        "page15_retry_or_replay_authorized",
        "page14_replay_authorized",
        "page13_replay_authorized",
        "page12_replay_authorized",
        "page11_replay_authorized",
        "page10_replay_authorized",
        "page9_retry_or_replay_authorized",
    )
    if (
        result.get("schema") != _o1c109.RESULT_SCHEMA
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("capsule") != DEFAULT_PARENT_CAPSULE_RELATIVE.as_posix()
        or result.get("classification") != _o1c109.SCIENCE_CLAUSE
        or result.get("stop_reason") != "globally-novel-clause"
        or result.get("science_gain") is not True
        or result.get("operational_activation") is not True
        or len(episodes) != 1
        or _mapping(episodes[0], "parent result episode") != episode
        or claim.get("global_novelty_baseline_clause_count")
        != PRIOR_LOGICAL_CLAUSE_COUNT
        or claim.get("page22_sha256") != _o1c108.PAGE22_SHA256
        or claim.get("page22_burned") is not True
        or claim.get("lineage35_only") is not True
        or claim.get("input_continuation_bank_sha256") != _o1c108.FINAL_BANK_SHA256
        or claim.get("rollover_manifest_sha256") != O1C108_MANIFEST_SHA256
        or claim.get("retry_or_replay") is not False
        or any(claim.get(name) is not False for name in replay_fields)
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("fresh_reveal_calls") != 0
        or claim.get("refits") != 0
        or episode.get("schema") != _o1c109.EPISODE_SCHEMA
        or episode.get("completed") is not True
        or episode.get("status") != 0
        or episode.get("lineage_call_ordinal") != PARENT_LINEAGE_ORDINAL
        or episode.get("page22_burned") is not True
        or episode.get("lineage35_burned") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not True
        or episode.get("requested_conflicts") != 128
        or episode.get("actual_conflicts") != 34
        or episode.get("billed_conflicts") != 34
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or any(episode.get(name) is not False for name in replay_fields)
        or episode.get("terminal_failure") is not None
        or science.get("science_gain") is not True
        or science.get("fully_emitted_clauses") != NEW_NATIVE_OCCURRENCE_COUNT
        or science.get("globally_novel_clauses") != NEW_CHUNK_CLAUSE_COUNT
        or operation.get("operational_activation") is not True
        or intent.get("schema") != _o1c109.INTENT_SCHEMA
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("page22_sha256") != _o1c108.PAGE22_SHA256
        or intent.get("page22_burned") is not True
        or intent.get("lineage35_burned") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or invocation.get("schema") != _o1c109.INVOCATION_SCHEMA
        or invocation.get("attempt_id") != PARENT_ATTEMPT_ID
        or invocation.get("lineage_call_ordinal") != PARENT_LINEAGE_ORDINAL
        or invocation.get("page22_sha256") != _o1c108.PAGE22_SHA256
        or invocation.get("global_novelty_baseline_clause_count")
        != PRIOR_LOGICAL_CLAUSE_COUNT
        or invocation.get("target_input_present") is not False
        or invocation.get("truth_input_present") is not False
        or native_result.get("schema")
        != _o1c109._native_v36.JOINT_SCORE_SIEVE_RESULT_SCHEMA
        or native_result.get("status") != 0
        or native_result.get("active_vault_sha256") != _o1c108.PAGE22_SHA256
    ):
        raise O1C110PreparationError("parent successful call boundary differs")

    receipt = _canonical_document(payloads["receipt"], "parent priority receipt")
    hexadecimal = receipt.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C110PreparationError("parent priority bank encoding differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C110PreparationError("parent priority bank encoding differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c109-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or receipt.get("bank_bytes") != FINAL_BANK_BYTES
        or receipt.get("current_bank_sha256") != FINAL_BANK_SHA256
        or receipt_bank != payloads["bank"]
        or receipt.get("candidate_population") != 255
        or receipt.get("consumed_coordinate_count") != 255
        or receipt.get("assignment_literals_observed") != 49_537
        or receipt.get("parent_scans") != 552
        or receipt.get("callback_calls") != 552
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 297
        or receipt.get("last_parent_candidate_count") != 2
    ):
        raise O1C110PreparationError("parent priority state differs")

    try:
        telemetry = parse_vault_telemetry(
            payloads["vault"],
            stream_id="o1c109-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C110PreparationError("parent native telemetry differs") from exc
    raw_vault = _canonical_document(payloads["vault"], "parent native telemetry")
    if (
        raw_vault.get("input_sha256") != _o1c108.PAGE22_SHA256
        or raw_vault.get("input_clause_count") != _o1c108.PAGE22_ACTIVE_LIMIT
        or raw_vault.get("input_literal_count") != _o1c108.PAGE22_LITERAL_COUNT
        or raw_vault.get("input_serialized_bytes") != _o1c108.PAGE22_SERIALIZED_BYTES
        or raw_vault.get("input_clause_aggregate_sha256")
        != _o1c108.PAGE22_CLAUSE_AGGREGATE_SHA256
        or raw_vault.get("validated_input_clause_count") != _o1c108.PAGE22_ACTIVE_LIMIT
        or raw_vault.get("fully_emitted_clause_count") != NEW_NATIVE_OCCURRENCE_COUNT
        or raw_vault.get("fully_emitted_literal_count") != NEW_CHUNK_LITERAL_COUNT
        or raw_vault.get("fully_emitted_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
        or raw_vault.get("emitted_new_clause_count") != NEW_CHUNK_CLAUSE_COUNT
        or raw_vault.get("emitted_new_literal_count") != NEW_CHUNK_LITERAL_COUNT
        or raw_vault.get("emitted_current_duplicate_clause_count") != 0
        or raw_vault.get("emitted_input_duplicate_clause_count") != 0
        or raw_vault.get("next_vault_available") is not False
        or raw_vault.get("next_vault_terminal_reason") != "capacity_clause_count"
        or len(telemetry.occurrences) != NEW_NATIVE_OCCURRENCE_COUNT
        or len(telemetry.new_occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or any(
            row.classification != "new" or row.source != "trail_upper_bound"
            for row in telemetry.occurrences
        )
        or len({row.clause.serialized for row in telemetry.occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
        or native_result.get("vault") != raw_vault
    ):
        raise O1C110PreparationError("parent native novelty ledger differs")
    return result, telemetry, payloads["bank"], payloads["receipt"]


def _validate_o1c108_bundle(
    bundle: Path,
) -> tuple[_o1c109.PublishedPreparation, Mapping[str, object], Mapping[str, object]]:
    try:
        published = _o1c109._load_published_preparation(
            bundle, bundle / PREPARATION_MANIFEST_NAME
        )
    except _o1c109.O1C109RunError as exc:
        raise O1C110PreparationError("sealed O1C-0108 bundle differs") from exc
    manifest_payload = published.artifacts[PREPARATION_MANIFEST_NAME]
    if (
        len(manifest_payload) != O1C108_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != O1C108_MANIFEST_SHA256
        or len(published.artifacts) != O1C108_BUNDLE_FILE_COUNT
        or len(published.globally_known_clause_sha256) != PRIOR_LOGICAL_CLAUSE_COUNT
    ):
        raise O1C110PreparationError("sealed O1C-0108 manifest differs")
    residency = _canonical_document(
        published.artifacts[RESIDENCY_NAME], "sealed O1C-0108 residency"
    )
    activation = _canonical_document(
        published.artifacts[ACTIVATION_LEDGER_NAME],
        "sealed O1C-0108 activation ledger",
    )
    return published, residency, activation


def _validate_capsule_initial_equals_bundle(
    capsule: Path, bundle_artifacts: Mapping[str, bytes]
) -> None:
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C110PreparationError("parent initial bundle is unreadable") from exc
    if {path.name for path in children} != set(bundle_artifacts):
        raise O1C110PreparationError("parent initial bundle inventory differs")
    for name, expected in bundle_artifacts.items():
        try:
            path = initial / name
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C110PreparationError("parent initial bundle differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or payload != expected
        ):
            raise O1C110PreparationError("parent initial bundle differs")


def _load_parent_attic(
    root: Path,
    published: _o1c109.PublishedPreparation,
    residency: Mapping[str, object],
) -> tuple[CausalAttic, tuple[int, ...], tuple[int, ...]]:
    """Rehydrate the sealed 22-chunk attic without replaying old derivations."""

    emitted = _mapping(residency.get("emitted_causal_attic"), "parent emitted attic")
    chunk_rows = tuple(_sequence(emitted.get("chunks"), "parent attic chunks"))
    if len(chunk_rows) != 22 or len(_o1c108.CHUNK_SOURCE_RELATIVES) != 21:
        raise O1C110PreparationError("parent transitive chunk inventory differs")

    chunks: list[ThresholdNoGoodVault] = []
    observed: tuple[int, ...] | None = None
    for index, row_value in enumerate(chunk_rows):
        try:
            payload = (
                _canonical_path(
                    root / _o1c108.CHUNK_SOURCE_RELATIVES[index],
                    f"parent attic chunk {index}",
                    directory=False,
                ).read_bytes()
                if index < 21
                else published.artifacts[_o1c108.NEW_CHUNK_NAME]
            )
            chunk = (
                parse_self_scoping_vault(payload, caps=O1C66_VAULT_CAPS)
                if observed is None
                else parse_threshold_no_good_vault(
                    payload, observed_variables=observed, caps=O1C66_VAULT_CAPS
                )
            )
        except (OSError, KeyError, CausalAtticError, ThresholdNoGoodVaultError) as exc:
            raise O1C110PreparationError(
                "parent transitive attic chunk differs"
            ) from exc
        if observed is None:
            observed = chunk.observed_variables
        row = _mapping(row_value, f"parent attic chunk row {index}")
        indices = _integer_tuple(row.get("union_clause_indices"), "chunk indices")
        expected = {
            "chunk_index": index,
            **chunk.describe(),
            "union_clause_indices": list(indices),
        }
        if dict(row) != expected:
            raise O1C110PreparationError("parent transitive attic chunk seal differs")
        chunks.append(chunk)
    if observed is None:
        raise O1C110PreparationError("parent attic scope differs")

    union_clauses: list[ThresholdNoGoodClause] = []
    clause_indices: dict[bytes, int] = {}
    chunk_indices: list[tuple[int, ...]] = []
    for chunk in chunks:
        local: list[int] = []
        for clause in chunk.clauses:
            index = clause_indices.get(clause.serialized)
            if index is None:
                index = len(union_clauses)
                clause_indices[clause.serialized] = index
                union_clauses.append(clause)
            local.append(index)
        chunk_indices.append(tuple(local))
    try:
        union = ThresholdNoGoodVault(chunks[0].identity, observed, tuple(union_clauses))
    except ThresholdNoGoodVaultError as exc:
        raise O1C110PreparationError("parent attic union differs") from exc
    if union.describe() != dict(_mapping(emitted.get("union"), "parent attic union")):
        raise O1C110PreparationError("parent attic union seal differs")

    occurrence_payload = published.artifacts[OCCURRENCES_NAME]
    occurrence_document = _canonical_document(occurrence_payload, "parent occurrences")
    occurrence_rows = tuple(
        _sequence(occurrence_document.get("records"), "parent occurrence rows")
    )
    occurrences: list[ClauseOccurrence] = []
    occurrence_indices: list[int] = []
    for ordinal, value in enumerate(occurrence_rows):
        row = _mapping(value, f"parent occurrence {ordinal}")
        union_index = row.get("union_clause_index")
        if (
            isinstance(union_index, bool)
            or not isinstance(union_index, int)
            or not 0 <= union_index < union.clause_count
        ):
            raise O1C110PreparationError("parent occurrence index differs")
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=cast(int, row.get("source_index")),
                classification=cast(str, row.get("classification")),
                source=cast(str, row.get("source")),
                witness_score_f64le_hex=cast(str, row.get("witness_score_f64le_hex")),
                clause=union.clauses[union_index],
                clause_sha256=cast(str, row.get("clause_sha256")),
                witness_sha256=cast(str, row.get("witness_sha256")),
            )
        except (CausalAtticError, IndexError) as exc:
            raise O1C110PreparationError("parent occurrence differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C110PreparationError("parent occurrence row differs")
        occurrences.append(occurrence)
        occurrence_indices.append(union_index)

    relation_payload = published.artifacts[RELATIONS_NAME]
    relation_document = _canonical_document(relation_payload, "parent relations")
    relation_rows = tuple(
        _sequence(relation_document.get("relations"), "parent relation rows")
    )
    relations: list[SubsumptionRelation] = []
    for ordinal, value in enumerate(relation_rows):
        row = _mapping(value, f"parent relation {ordinal}")
        left, right = row.get("subsumer_index"), row.get("subsumed_index")
        if (
            isinstance(left, bool)
            or not isinstance(left, int)
            or isinstance(right, bool)
            or not isinstance(right, int)
            or not 0 <= left < union.clause_count
            or not 0 <= right < union.clause_count
        ):
            raise O1C110PreparationError("parent relation index differs")
        relation = SubsumptionRelation(left, right)
        if relation.describe(union.clauses) != dict(row):
            raise O1C110PreparationError("parent relation row differs")
        relations.append(relation)
    if tuple(relations) != tuple(sorted(set(relations))):
        raise O1C110PreparationError("parent relation ordering differs")

    active = _mapping(emitted.get("active_projection"), "parent attic projection")
    selected = _integer_tuple(active.get("selected_union_indices"), "parent selected")
    selection_order = _integer_tuple(active.get("selection_order"), "parent order")
    try:
        active_vault = ThresholdNoGoodVault(
            union.identity,
            observed,
            tuple(union.clauses[index] for index in selected),
        )
    except (ThresholdNoGoodVaultError, IndexError) as exc:
        raise O1C110PreparationError("parent active projection differs") from exc
    encoding = _mapping(active.get("encoding_only"), "parent active encoding")
    undominated = _integer_tuple(
        relation_document.get("undominated_indices"), "parent undominated indices"
    )
    attic = CausalAttic(
        chunks=tuple(chunks),
        union_vault=union,
        active_projection=active_vault,
        occurrences=tuple(occurrences),
        chunk_clause_union_indices=tuple(chunk_indices),
        occurrence_union_indices=tuple(occurrence_indices),
        relations=tuple(relations),
        undominated_indices=undominated,
        selection_order=selection_order,
        selected_union_indices=selected,
        unique_coverage_count=cast(int, active.get("unique_coverage_count")),
        occurrence_coverage_count=cast(int, active.get("occurrence_coverage_count")),
        active_limit=cast(int, active.get("maximum_clause_count")),
    )
    if (
        attic.describe() != dict(emitted)
        or active_vault.describe() != dict(encoding)
        or canonical_json_bytes(attic.occurrence_document()) != occurrence_payload
        or canonical_json_bytes(attic.relation_document()) != relation_payload
        or attic.union_vault.clause_count != _o1c108.ATTIC_UNION_CLAUSE_COUNT
        or len(attic.occurrences) != _o1c108.ATTIC_OCCURRENCE_COUNT
    ):
        raise O1C110PreparationError("parent causal attic artifacts differ")

    o1c102_residency = _mapping(
        _mapping(
            _mapping(
                _mapping(
                    residency.get("parent_composed_residency"),
                    "O1C-0108 parent residency",
                ).get("document"),
                "O1C-0106 residency",
            ).get("parent_composed_residency"),
            "O1C-0106 parent residency",
        ).get("document"),
        "O1C-0104 residency",
    )
    o1c102_document = _mapping(
        _mapping(
            o1c102_residency.get("parent_composed_residency"),
            "O1C-0104 parent residency",
        ).get("document"),
        "O1C-0102 residency",
    )
    parent_causal = _mapping(
        o1c102_document.get("parent_causal_residency"), "O1C-0102 causal residency"
    )
    pinned = _integer_tuple(parent_causal.get("pinned_core_indices"), "pinned core")
    inherited_debt = _integer_tuple(
        parent_causal.get("inherited_debt_indices"), "inherited debt"
    )
    if len(pinned) != 46 or len(inherited_debt) != 289:
        raise O1C110PreparationError("parent selector roots differ")
    return attic, pinned, inherited_debt


def _prior_logical_clauses(
    attic: CausalAttic, artifacts: Mapping[str, bytes]
) -> tuple[ThresholdNoGoodClause, ...]:
    observed = attic.union_vault.observed_variables
    try:
        inherited = parse_threshold_no_good_vault(
            artifacts[INHERITED_DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        o1c104 = parse_threshold_no_good_vault(
            artifacts[O1C104_DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        o1c108 = parse_threshold_no_good_vault(
            artifacts[O1C108_DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
    except (KeyError, ThresholdNoGoodVaultError) as exc:
        raise O1C110PreparationError("inherited derived sidecar differs") from exc
    emitted = attic.union_vault.clauses
    prior = (
        *emitted[:2_338],
        *inherited.clauses,
        *emitted[2_338:2_603],
        *o1c104.clauses,
        *emitted[2_603 : _o1c108.ATTIC_UNION_CLAUSE_COUNT],
        *o1c108.clauses,
    )
    receipt = _canonical_document(
        artifacts[O1C108_DERIVED_RECEIPT_NAME], "O1C-0108 resolution receipt"
    )
    combined = _mapping(
        _mapping(receipt.get("logical_known_registry"), "parent registry").get(
            "combined"
        ),
        "parent combined registry",
    )
    inventory = tuple(
        cast(
            Sequence[str],
            _sequence(combined.get("clause_sha256"), "parent logical inventory"),
        )
    )
    if (
        len(prior) != PRIOR_LOGICAL_CLAUSE_COUNT
        or tuple(clause.sha256 for clause in prior) != inventory
        or combined.get("inventory_sha256") != _o1c108.LOGICAL_KNOWN_INVENTORY_SHA256
        or _mapping(combined.get("encoding_only"), "parent logical encoding").get(
            "sha256"
        )
        != _o1c108.LOGICAL_KNOWN_SHA256
        or combined.get("clause_count") != PRIOR_LOGICAL_CLAUSE_COUNT
    ):
        raise O1C110PreparationError("parent chronological logical registry differs")
    return tuple(prior)


def _new_chunk(
    parent_attic: CausalAttic,
    telemetry: ParsedVaultTelemetry,
    globally_known_sha256: frozenset[str],
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            parent_attic.union_vault.observed_variables,
            tuple(row.clause for row in telemetry.new_occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C110PreparationError("new immutable native chunk differs") from exc
    _values, inventory_sha = _inventory(chunk.clauses)
    if (
        roundtrip != chunk
        or telemetry.input_identity != parent_attic.union_vault.identity
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.clause_aggregate_sha256 != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
        or globally_known_sha256.intersection(clause.sha256 for clause in chunk.clauses)
        or inventory_sha != NEW_CHUNK_INVENTORY_SHA256
    ):
        raise O1C110PreparationError("new immutable native chunk seal differs")
    return chunk


def _advance_attic(
    parent_attic: CausalAttic,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> tuple[CausalAttic, tuple[int, ...]]:
    try:
        attic = reproject_causal_attic(
            (*parent_attic.chunks, chunk),
            (*parent_attic.occurrences, *telemetry.occurrences),
            active_limit=PAGE23_ACTIVE_LIMIT,
        )
    except CausalAtticError as exc:
        raise O1C110PreparationError("Page-23 causal attic append differs") from exc
    event_indices = attic.occurrence_union_indices[-NEW_NATIVE_OCCURRENCE_COUNT:]
    if (
        attic.chunks[:-1] != parent_attic.chunks
        or attic.chunks[-1] != chunk
        or attic.occurrences[:-NEW_NATIVE_OCCURRENCE_COUNT] != parent_attic.occurrences
        or attic.union_vault.clauses[: parent_attic.union_vault.clause_count]
        != parent_attic.union_vault.clauses
        or len(attic.chunks) != ATTIC_CHUNK_COUNT
        or attic.union_vault.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or attic.union_vault.literal_count != ATTIC_UNION_LITERAL_COUNT
        or attic.union_vault.serialized_bytes != ATTIC_UNION_SERIALIZED_BYTES
        or attic.union_vault.sha256 != ATTIC_UNION_SHA256
        or attic.union_vault.clause_aggregate_sha256
        != ATTIC_UNION_CLAUSE_AGGREGATE_SHA256
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or event_indices
        != tuple(range(_o1c108.ATTIC_UNION_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT))
    ):
        raise O1C110PreparationError("Page-23 causal attic census differs")
    return attic, event_indices


@dataclass(frozen=True)
class _ResolutionArtifacts:
    closure: ThresholdNoGoodVault
    overlay: ThresholdNoGoodVault
    receipt_payload: bytes
    logical: ThresholdNoGoodVault
    full_relations: tuple[tuple[int, int], ...]
    logical_undominated_indices: tuple[int, ...]
    generation_audit: tuple[Mapping[str, object], ...]


def _derive_resolution_closure(
    attic: CausalAttic,
    chunk: ThresholdNoGoodVault,
    artifacts: Mapping[str, bytes],
) -> _ResolutionArtifacts:
    prior = _prior_logical_clauses(attic, artifacts)
    seed_refs = tuple(
        _o1c104._ClauseRef(
            kind="o1c109-native-emission",
            clause=clause,
            logical_index=PRIOR_LOGICAL_CLAUSE_COUNT + index,
            source_index=index,
            unique_index=index,
        )
        for index, clause in enumerate(chunk.clauses)
    )
    encoded = {id(ref.clause): _o1c104._encode_clause(ref.clause) for ref in seed_refs}
    known = {clause.serialized for clause in (*prior, *chunk.clauses)}
    previous: tuple[_o1c104._ClauseRef, ...] = ()
    frontier = seed_refs
    nodes: list[_o1c104._ProofNode] = []
    audits: list[Mapping[str, object]] = []
    generation = 1
    while frontier:
        counts = Counter({"zero": 0, "multi": 0, "single": 0})
        candidates: dict[
            bytes,
            tuple[ThresholdNoGoodClause, _o1c104._ClauseRef, _o1c104._ClauseRef, int],
        ] = {}

        def scan(left: _o1c104._ClauseRef, right: _o1c104._ClauseRef) -> None:
            kind, pivot, resolvent = _o1c104._pair_resolution(left, right, encoded)
            counts[kind] += 1
            if kind != "single":
                return
            if pivot is None or resolvent is None:
                raise O1C110PreparationError("resolution single-pivot edge differs")
            if resolvent.serialized not in known:
                candidates.setdefault(
                    resolvent.serialized, (resolvent, left, right, pivot)
                )

        for left in frontier:
            for right in previous:
                scan(left, right)
        for left_index, left in enumerate(frontier):
            for right in frontier[left_index + 1 :]:
                scan(left, right)
        ordered = sorted(
            candidates.values(), key=lambda row: (row[0].literal_count, row[0].sha256)
        )
        generation_nodes = tuple(
            _o1c104._ProofNode(
                generation=generation,
                node=f"G{generation}-{index:03d}",
                clause=clause,
                left=left,
                right=right,
                pivot=pivot,
            )
            for index, (clause, left, right, pivot) in enumerate(ordered)
        )
        pivot_variables = sorted({node.pivot for node in generation_nodes})
        audits.append(
            {
                "generation": generation,
                "frontier_clause_count": len(frontier),
                "prior_clause_count": len(previous),
                "frontier_to_prior_pair_count": len(frontier) * len(previous),
                "frontier_internal_pair_count": len(frontier)
                * (len(frontier) - 1)
                // 2,
                "pair_count": sum(counts.values()),
                "zero": counts["zero"],
                "multi": counts["multi"],
                "single": counts["single"],
                "unique_novel": len(generation_nodes),
                "pivot_variables": pivot_variables,
                "fixed_point_reached": not generation_nodes,
            }
        )
        if not generation_nodes:
            break
        new_refs = tuple(
            _o1c104._ClauseRef(
                kind="o1c110-derived-resolution",
                clause=node.clause,
                node=node.node,
            )
            for node in generation_nodes
        )
        nodes.extend(generation_nodes)
        known.update(node.clause.serialized for node in generation_nodes)
        encoded.update(
            {id(ref.clause): _o1c104._encode_clause(ref.clause) for ref in new_refs}
        )
        previous = (*previous, *frontier)
        frontier = new_refs
        generation += 1
    expected_audits = (
        {
            "generation": 1,
            "frontier_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "prior_clause_count": 0,
            "frontier_to_prior_pair_count": 0,
            "frontier_internal_pair_count": G1_PAIR_COUNT,
            "pair_count": G1_PAIR_COUNT,
            "zero": G1_ZERO_COMPLEMENT_PAIR_COUNT,
            "multi": G1_MULTI_COMPLEMENT_PAIR_COUNT,
            "single": G1_SINGLE_PIVOT_PAIR_COUNT,
            "unique_novel": DERIVED_CLOSURE_CLAUSE_COUNT,
            "pivot_variables": [194],
            "fixed_point_reached": False,
        },
        {
            "generation": 2,
            "frontier_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "prior_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "frontier_to_prior_pair_count": DERIVED_CLOSURE_CLAUSE_COUNT
            * NEW_CHUNK_CLAUSE_COUNT,
            "frontier_internal_pair_count": DERIVED_CLOSURE_CLAUSE_COUNT
            * (DERIVED_CLOSURE_CLAUSE_COUNT - 1)
            // 2,
            "pair_count": G2_PAIR_COUNT,
            "zero": G2_ZERO_COMPLEMENT_PAIR_COUNT,
            "multi": G2_MULTI_COMPLEMENT_PAIR_COUNT,
            "single": G2_SINGLE_PIVOT_PAIR_COUNT,
            "unique_novel": 0,
            "pivot_variables": [],
            "fixed_point_reached": True,
        },
    )
    if tuple(audits) != expected_audits:
        raise O1C110PreparationError("derived resolution fixed point differs")
    try:
        closure = ThresholdNoGoodVault(
            chunk.identity,
            chunk.observed_variables,
            tuple(node.clause for node in nodes),
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C110PreparationError("derived closure encoding differs") from exc
    _closure_inventory, closure_inventory_sha = _inventory(closure.clauses)
    if (
        closure.sha256 != DERIVED_CLOSURE_SHA256
        or closure.clause_count != DERIVED_CLOSURE_CLAUSE_COUNT
        or closure.literal_count != DERIVED_CLOSURE_LITERAL_COUNT
        or closure.serialized_bytes != DERIVED_CLOSURE_BYTES
        or closure.clause_aggregate_sha256 != DERIVED_CLOSURE_AGGREGATE_SHA256
        or closure_inventory_sha != DERIVED_CLOSURE_INVENTORY_SHA256
    ):
        raise O1C110PreparationError("derived closure seal differs")

    intermediate = (*prior, *chunk.clauses)
    logical_clauses = (*intermediate, *closure.clauses)
    _prior_inventory, prior_inventory_sha = _inventory(prior)
    _intermediate_inventory, intermediate_inventory_sha = _inventory(intermediate)
    _logical_inventory, logical_inventory_sha = _inventory(logical_clauses)
    try:
        logical = ThresholdNoGoodVault(
            chunk.identity, chunk.observed_variables, logical_clauses
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C110PreparationError("logical registry encoding differs") from exc
    if (
        prior_inventory_sha != _o1c108.LOGICAL_KNOWN_INVENTORY_SHA256
        or len(intermediate) != INTERMEDIATE_LOGICAL_CLAUSE_COUNT
        or logical.clause_count != LOGICAL_KNOWN_CLAUSE_COUNT
        or logical.literal_count != LOGICAL_KNOWN_LITERAL_COUNT
        or logical.serialized_bytes != LOGICAL_KNOWN_SERIALIZED_BYTES
        or logical.sha256 != LOGICAL_KNOWN_SHA256
        or logical.clause_aggregate_sha256 != LOGICAL_KNOWN_AGGREGATE_SHA256
        or logical_inventory_sha != LOGICAL_KNOWN_INVENTORY_SHA256
    ):
        raise O1C110PreparationError("chronological logical registry differs")

    edge_inventory: list[dict[str, object]] = []
    proof_edges: list[dict[str, object]] = []
    for index, node in enumerate(nodes):
        if (
            _o1c104._resolve_exact(
                node.left.clause, node.right.clause, pivot=node.pivot
            )
            != node.clause
        ):
            raise O1C110PreparationError("derived proof edge replay differs")
        edge = {
            "index": index,
            "node": node.node,
            "generation": node.generation,
            "pivot_variable": node.pivot,
            "left_clause_sha256": node.left.clause.sha256,
            "right_clause_sha256": node.right.clause.sha256,
            "resolvent_sha256": node.clause.sha256,
            "literal_count": node.clause.literal_count,
        }
        edge_inventory.append(edge)
        proof_edges.append(
            {
                **edge,
                "left_parent": node.left.describe(),
                "right_parent": node.right.describe(),
                "byte_exact_replay": True,
            }
        )
    edge_inventory_sha = sha256_bytes(canonical_json_bytes(edge_inventory))

    relations = strict_subsumption_relations(logical.clauses)
    full_relations = tuple(
        (relation.subsumer_index, relation.subsumed_index) for relation in relations
    )
    subsumed = {right for _left, right in full_relations}
    undominated = tuple(
        index for index in range(logical.clause_count) if index not in subsumed
    )
    if (
        len(full_relations) != LOGICAL_SUBSUMPTION_RELATION_COUNT
        or len(undominated) != LOGICAL_UNDOMINATED_CLAUSE_COUNT
    ):
        raise O1C110PreparationError("logical relation census differs")
    receipt = {
        "schema": DERIVED_RECEIPT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_boundary": {
            "derivation_kind": "exact-propositional-resolution-fixed-point",
            "public_only": True,
            **_zero_call(),
            "derived_clauses_are_native_occurrences": False,
            "derived_clauses_enter_causal_attic": False,
            "pivot_or_generation_preselected": False,
            "certified_logical_consequence": True,
        },
        "source": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "source_active_sha256": _o1c108.PAGE22_SHA256,
            "vault_telemetry_sha256": PARENT_VAULT_TELEMETRY_SHA256,
            "native_chunk_sha256": NEW_CHUNK_SHA256,
            "native_unique_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        },
        "resolution_rule": {
            "scope": "within-o1c109-native-emission-cohort-and-generated-frontiers",
            "pivot_rule": "discover-exactly-one-opposite-signed-pivot-per-pair",
            "required_pivot_variable": None,
            "required_generation_count": None,
            "nonpivot_complements_allowed": False,
            "resolvent_rule": "union-of-parent-literals-minus-both-pivot-literals",
            "literal_order": "strict-ascending-absolute-variable",
            "tautological_resolvents_allowed": False,
            "closure_order": "generation-ascending;literal-count-ascending;clause-sha256-ascending",
        },
        "edge_inventory_sha256": edge_inventory_sha,
        "edge_inventory": edge_inventory,
        "edges": proof_edges,
        "fixed_point_audit": {"generations": list(audits), "fixed_point_reached": True},
        "closure": {
            **closure.describe(),
            "artifact": DERIVED_CLOSURE_NAME,
            "inventory_sha256": closure_inventory_sha,
            "generation_clause_counts": [DERIVED_CLOSURE_CLAUSE_COUNT],
        },
        "proof_overlay": {
            **closure.describe(),
            "artifact": DERIVED_OVERLAY_NAME,
            "inventory_sha256": closure_inventory_sha,
            "closure_indices": list(range(DERIVED_CLOSURE_CLAUSE_COUNT)),
            "all_clauses_preserved": True,
            "causal_attic_occurrence_count_added": 0,
        },
        "logical_relation_audit": {
            "full_relation_count": len(full_relations),
            "full_relations": [
                {"subsumer_logical_index": left, "subsumed_logical_index": right}
                for left, right in full_relations
            ],
            "logical_undominated_clause_count": len(undominated),
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "o1c108-logical-known-registry-byte-order",
                "new-o1c109-native-emission",
                "new-o1c110-derived-resolution",
            ],
            "prior_prefix": {
                "clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
                "inventory_sha256": prior_inventory_sha,
            },
            "new_native": {
                "start": PRIOR_LOGICAL_CLAUSE_COUNT,
                "stop_exclusive": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                "clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "inventory_sha256": _inventory(chunk.clauses)[1],
            },
            "new_derived": {
                "start": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                "stop_exclusive": LOGICAL_KNOWN_CLAUSE_COUNT,
                "clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                "inventory_sha256": closure_inventory_sha,
            },
            "intermediate_inventory_sha256": intermediate_inventory_sha,
            "combined": {
                "clause_count": logical.clause_count,
                "clause_sha256": [clause.sha256 for clause in logical.clauses],
                "inventory_sha256": logical_inventory_sha,
                "ordering": "byte-exact-o1c108-logical-prefix;new-native-first-emission-order;new-derived-proof-order",
                "encoding_only": logical.describe(),
                "next_global_novelty_baseline_clause_count": logical.clause_count,
            },
        },
    }
    return _ResolutionArtifacts(
        closure=closure,
        overlay=closure,
        receipt_payload=canonical_json_bytes(receipt),
        logical=logical,
        full_relations=full_relations,
        logical_undominated_indices=undominated,
        generation_audit=tuple(audits),
    )


@dataclass(frozen=True)
class ComposedPage23Projection:
    lineage_ordinal: int
    vault: ThresholdNoGoodVault
    pure_emitted_candidate: ResidencyProjection
    selected_emitted_union_indices: tuple[int, ...]
    priority_selected_emitted_union_indices: tuple[int, ...]
    selected_inherited_derived_clauses: tuple[Mapping[str, object], ...]
    selected_o1c104_derived_clauses: tuple[Mapping[str, object], ...]
    selected_o1c108_derived_clauses: tuple[Mapping[str, object], ...]
    selected_o1c110_derived_clauses: tuple[Mapping[str, object], ...]
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    document: Mapping[str, object]

    @property
    def selected_union_indices(self) -> tuple[int, ...]:
        return self.selected_emitted_union_indices

    @property
    def selection_order(self) -> tuple[int, ...]:
        return self.priority_selected_emitted_union_indices

    def describe(self) -> Mapping[str, object]:
        return self.document


@dataclass(frozen=True)
class ComposedPage23State:
    attic: CausalAttic
    current_projection: ComposedPage23Projection
    residency_payload: bytes
    activation_payload: bytes

    @property
    def active_limit(self) -> int:
        return PAGE23_ACTIVE_LIMIT

    @property
    def active_projection(self) -> ThresholdNoGoodVault:
        return self.current_projection.vault

    @property
    def used_active_sha256(self) -> tuple[str, ...]:
        document = _canonical_document(self.activation_payload, "Page-23 activation")
        return tuple(
            cast(
                Sequence[str],
                _sequence(document.get("used_active_sha256"), "Page-23 used inputs"),
            )
        )

    def describe(self) -> Mapping[str, object]:
        return _canonical_document(self.residency_payload, "Page-23 residency")

    def activation_ledger_document(self) -> Mapping[str, object]:
        return _canonical_document(self.activation_payload, "Page-23 activation")


@dataclass(frozen=True)
class PreparedCausalRolloverArtifacts:
    """Complete zero-call Page-23 preparation held only in memory."""

    state: ComposedPage23State
    artifacts: Mapping[str, bytes]
    manifest: Mapping[str, object]


@dataclass(frozen=True)
class _Composition:
    page: ThresholdNoGoodVault
    pure_emitted: ResidencyProjection
    selected_emitted: tuple[int, ...]
    priority_selected_emitted: tuple[int, ...]
    inherited_rows: tuple[Mapping[str, object], ...]
    o1c104_rows: tuple[Mapping[str, object], ...]
    o1c108_rows: tuple[Mapping[str, object], ...]
    o1c110_rows: tuple[Mapping[str, object], ...]
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    residency_payload: bytes
    activation_payload: bytes
    certification_payload: bytes


def _emitted_to_logical_index(union_index: int) -> int:
    if not 0 <= union_index < ATTIC_UNION_CLAUSE_COUNT:
        raise O1C110PreparationError("emitted union index differs")
    if union_index < 2_338:
        return union_index
    if union_index < 2_603:
        return union_index + 5
    if union_index < _o1c108.ATTIC_UNION_CLAUSE_COUNT:
        return union_index + 89
    return PRIOR_LOGICAL_CLAUSE_COUNT + union_index - _o1c108.ATTIC_UNION_CLAUSE_COUNT


def _validated_parent_derived_rows(
    parent_residency: Mapping[str, object],
    *,
    observed_variables: tuple[int, ...],
    artifacts: Mapping[str, bytes],
) -> tuple[
    tuple[Mapping[str, object], ...],
    tuple[Mapping[str, object], ...],
    tuple[Mapping[str, object], ...],
    ThresholdNoGoodVault,
    ThresholdNoGoodVault,
    ThresholdNoGoodVault,
]:
    current = _mapping(parent_residency.get("current_projection"), "parent projection")
    groups = (
        (
            "selected_inherited_derived_clauses",
            INHERITED_DERIVED_CLOSURE_NAME,
            "inherited-o1c102-derived-resolution",
            PAGE23_INHERITED_DERIVED_COUNT,
            2_338,
        ),
        (
            "selected_o1c104_derived_clauses",
            O1C104_DERIVED_CLOSURE_NAME,
            "new-o1c104-derived-resolution",
            PAGE23_O1C104_DERIVED_COUNT,
            2_608,
        ),
        (
            "selected_o1c108_derived_clauses",
            O1C108_DERIVED_CLOSURE_NAME,
            "new-o1c108-derived-resolution",
            PAGE23_O1C108_DERIVED_COUNT,
            2_958,
        ),
    )
    rows_out: list[tuple[Mapping[str, object], ...]] = []
    vaults: list[ThresholdNoGoodVault] = []
    for field, artifact, namespace, expected_count, logical_start in groups:
        try:
            vault = parse_threshold_no_good_vault(
                artifacts[artifact],
                observed_variables=observed_variables,
                caps=O1C66_VAULT_CAPS,
            )
        except (KeyError, ThresholdNoGoodVaultError) as exc:
            raise O1C110PreparationError("parent derived namespace differs") from exc
        values = tuple(_sequence(current.get(field), f"parent {field}"))
        rows: list[Mapping[str, object]] = []
        for value in values:
            row = _mapping(value, f"parent {field} row")
            index = row.get("closure_index")
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 0 <= index < vault.clause_count
            ):
                raise O1C110PreparationError("parent derived closure index differs")
            clause = vault.clauses[index]
            expected = {
                "namespace": namespace,
                "closure_index": index,
                "logical_index": logical_start + index,
                "clause_sha256": clause.sha256,
                "literal_count": clause.literal_count,
            }
            if dict(row) != expected:
                raise O1C110PreparationError("parent derived row differs")
            rows.append(row)
        if len(rows) != expected_count:
            raise O1C110PreparationError("parent derived resident count differs")
        rows_out.append(tuple(rows))
        vaults.append(vault)
    return (
        rows_out[0],
        rows_out[1],
        rows_out[2],
        vaults[0],
        vaults[1],
        vaults[2],
    )


def _legacy_certification_index(
    artifacts: Mapping[str, bytes],
) -> dict[tuple[str, int], Mapping[str, object]]:
    audit = _canonical_document(
        artifacts[_o1c108.CERTIFICATION_AUDIT_NAME], "parent certification audit"
    )
    rows = tuple(
        _sequence(
            audit.get("active_rows_in_serialization_order"),
            "parent certification rows",
        )
    )
    indexed: dict[tuple[str, int], Mapping[str, object]] = {}
    for value in rows:
        row = _mapping(value, "parent certification row")
        namespace, closure_index = row.get("namespace"), row.get("closure_index")
        if (
            isinstance(namespace, str)
            and isinstance(closure_index, int)
            and not isinstance(closure_index, bool)
        ):
            indexed[(namespace, closure_index)] = row
    if (
        audit.get("schema") != _o1c108.CERTIFICATION_AUDIT_SCHEMA
        or audit.get("passed") is not True
        or len(rows) != _o1c108.PAGE22_ACTIVE_LIMIT
        or any(
            _mapping(row, "parent certification row").get("passed") is not True
            for row in rows
        )
    ):
        raise O1C110PreparationError("parent certification prefix differs")
    return indexed


def _compose_page23(
    *,
    root: Path,
    attic: CausalAttic,
    event_indices: tuple[int, ...],
    pinned: tuple[int, ...],
    inherited_debt: tuple[int, ...],
    published: _o1c109.PublishedPreparation,
    parent_residency: Mapping[str, object],
    parent_activation: Mapping[str, object],
    resolution: _ResolutionArtifacts,
) -> _Composition:
    parent_counts = _integer_tuple(
        parent_residency.get("activation_counts"), "parent emitted counts"
    )
    parent_lineages = _optional_integer_tuple(
        parent_residency.get("last_active_lineages"), "parent emitted lineages"
    )
    prior_used = tuple(
        cast(
            Sequence[str],
            _sequence(
                parent_activation.get("used_active_sha256"), "parent used inputs"
            ),
        )
    )
    if (
        len(parent_counts) != _o1c108.ATTIC_UNION_CLAUSE_COUNT
        or len(parent_lineages) != _o1c108.ATTIC_UNION_CLAUSE_COUNT
        or not prior_used
        or prior_used[-1] != _o1c108.PAGE22_SHA256
        or len(set(prior_used)) != len(prior_used)
    ):
        raise O1C110PreparationError("parent residency counters differ")
    counts_before = parent_counts + (0,) * NEW_CHUNK_CLAUSE_COUNT
    lineages_before = parent_lineages + (None,) * NEW_CHUNK_CLAUSE_COUNT
    try:
        pure = _priority_projection(
            attic,
            lineage_ordinal=PAGE23_LINEAGE_ORDINAL,
            active_limit=PAGE23_ACTIVE_LIMIT,
            pinned_core_indices=pinned,
            inherited_debt_indices=inherited_debt,
            activation_counts=counts_before,
            last_active_lineages=lineages_before,
            fully_emitted_union_indices=event_indices,
            used_active_sha256=prior_used,
        )
    except CausalResidencyError as exc:
        raise O1C110PreparationError("Page-23 emitted selector differs") from exc
    priority_selected = pure.selection_order[:PAGE23_EMITTED_COUNT]
    selected_emitted = tuple(sorted(priority_selected))
    if (
        pure.lineage_ordinal != PAGE23_LINEAGE_ORDINAL
        or pure.vault.clause_count != PAGE23_ACTIVE_LIMIT
        or pure.vault.sha256 != PAGE23_PURE_EMITTED_SHA256
        or pure.vault.literal_count != PAGE23_PURE_EMITTED_LITERAL_COUNT
        or pure.vault.serialized_bytes != PAGE23_PURE_EMITTED_SERIALIZED_BYTES
        or pure.vault.clause_aggregate_sha256 != PAGE23_PURE_EMITTED_AGGREGATE_SHA256
        or len(priority_selected) != PAGE23_EMITTED_COUNT
        or len(set(priority_selected)) != PAGE23_EMITTED_COUNT
        or selected_emitted != SELECTED_EMITTED_UNION_INDICES
        or _index_list_sha256(selected_emitted) != SELECTED_EMITTED_INDICES_SHA256
    ):
        raise O1C110PreparationError("Page-23 emitted selector prefix differs")

    (
        inherited_rows,
        o1c104_rows,
        o1c108_rows,
        inherited_closure,
        o1c104_closure,
        o1c108_closure,
    ) = _validated_parent_derived_rows(
        parent_residency,
        observed_variables=attic.union_vault.observed_variables,
        artifacts=published.artifacts,
    )
    o1c110_rows = tuple(
        {
            "namespace": "new-o1c110-derived-resolution",
            "closure_index": index,
            "logical_index": INTERMEDIATE_LOGICAL_CLAUSE_COUNT + index,
            "clause_sha256": clause.sha256,
            "literal_count": clause.literal_count,
        }
        for index, clause in enumerate(resolution.closure.clauses)
    )

    def clauses_for(
        rows: Sequence[Mapping[str, object]], vault: ThresholdNoGoodVault
    ) -> tuple[ThresholdNoGoodClause, ...]:
        return tuple(vault.clauses[cast(int, row["closure_index"])] for row in rows)

    try:
        page = ThresholdNoGoodVault(
            attic.union_vault.identity,
            attic.union_vault.observed_variables,
            (
                *(attic.union_vault.clauses[index] for index in selected_emitted),
                *clauses_for(inherited_rows, inherited_closure),
                *clauses_for(o1c104_rows, o1c104_closure),
                *clauses_for(o1c108_rows, o1c108_closure),
                *resolution.closure.clauses,
            ),
        )
        roundtrip = parse_threshold_no_good_vault(
            page.serialized,
            observed_variables=page.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (ThresholdNoGoodVaultError, IndexError) as exc:
        raise O1C110PreparationError("composed active Page-23 differs") from exc
    if (
        roundtrip != page
        or page.clause_count != PAGE23_ACTIVE_LIMIT
        or page.sha256 != PAGE23_SHA256
        or page.clause_aggregate_sha256 != PAGE23_CLAUSE_AGGREGATE_SHA256
        or page.literal_count != PAGE23_LITERAL_COUNT
        or page.serialized_bytes != PAGE23_SERIALIZED_BYTES
        or page.sha256 in set(prior_used) | {pure.vault.sha256}
    ):
        raise O1C110PreparationError("Page-23 encoding differs")

    try:
        context = _o1c106._sealed_public_inputs(root)
    except _o1c106.O1C106PreparationError as exc:
        raise O1C110PreparationError("v8 public theorem inputs differ") from exc
    emitted_audit: list[Mapping[str, object]] = []
    for index in selected_emitted:
        try:
            row, passed = _o1c106._certify_clause(
                attic.union_vault.clauses[index],
                context=context,
                namespace="emitted-causal-attic",
                active=True,
                union_index=index,
                logical_index=_emitted_to_logical_index(index),
            )
        except _o1c106.O1C106PreparationError as exc:
            raise O1C110PreparationError(
                "active emitted certification differs"
            ) from exc
        if not passed:
            raise O1C110PreparationError("active emitted certification failed")
        emitted_audit.append(row)

    legacy_index = _legacy_certification_index(published.artifacts)
    legacy_rows: list[Mapping[str, object]] = []
    for row in (*inherited_rows, *o1c104_rows, *o1c108_rows):
        key = (cast(str, row["namespace"]), cast(int, row["closure_index"]))
        audit_row = legacy_index.get(key)
        if (
            audit_row is None
            or audit_row.get("clause_sha256") != row["clause_sha256"]
            or audit_row.get("passed") is not True
            or audit_row.get("active") is not True
        ):
            raise O1C110PreparationError("legacy derived certification differs")
        legacy_rows.append(audit_row)

    new_audit: list[Mapping[str, object]] = []
    metrics: list[float] = []
    for index, clause in enumerate(resolution.closure.clauses):
        try:
            row, passed = _o1c106._certify_clause(
                clause,
                context=context,
                namespace="new-o1c110-derived-resolution",
                active=True,
                closure_index=index,
                logical_index=INTERMEDIATE_LOGICAL_CLAUSE_COUNT + index,
            )
        except _o1c106.O1C106PreparationError as exc:
            raise O1C110PreparationError("new derived certification differs") from exc
        metric = row.get("metric")
        if (
            not passed
            or isinstance(metric, bool)
            or not isinstance(metric, (int, float))
        ):
            raise O1C110PreparationError("new derived certification failed")
        new_audit.append(row)
        metrics.append(float(metric))
    maximum_new = max(metrics)
    if _o1c106._f64_hex(maximum_new) != _o1c106._f64_hex(
        PAGE23_MAXIMUM_CERTIFIED_UPPER_BOUND
    ):
        raise O1C110PreparationError("new derived certification bound differs")

    active_rows = (*emitted_audit, *legacy_rows, *new_audit)
    active_metrics = tuple(row.get("metric") for row in active_rows)
    if (
        len(active_rows) != PAGE23_ACTIVE_LIMIT
        or any(row.get("passed") is not True for row in active_rows)
        or any(
            isinstance(metric, bool) or not isinstance(metric, (int, float))
            for metric in active_metrics
        )
    ):
        raise O1C110PreparationError("Page-23 aggregate certification differs")
    maximum_active = max(cast(float, metric) for metric in active_metrics)
    if not maximum_active < _o1c106.THRESHOLD:
        raise O1C110PreparationError("Page-23 certification threshold differs")
    certification = {
        "schema": CERTIFICATION_AUDIT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "execution": {"offline_only": True, **_zero_call()},
        "theorem": {
            "implementation": "joint_score_sieve_v8._certify_no_good",
            "rule": _o1c106._v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE,
            "bound_rule": _o1c106._v8.JOINT_SCORE_SIEVE_BOUND_RULE,
            "threshold": _o1c106.THRESHOLD,
            "threshold_f64le_hex": _o1c106.THRESHOLD_F64LE_HEX,
            "source_and_input_seals": context.source_seals,
        },
        "inherited_certification": {
            "artifact": _o1c108.CERTIFICATION_AUDIT_NAME,
            "sha256": _o1c108.CERTIFICATION_AUDIT_SHA256,
            "byte_exact_and_unmodified": True,
            "active_legacy_derived_pass_count": len(legacy_rows),
        },
        "new_o1c110_resolution_candidates": {
            "candidate_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "certified_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "pass_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "fail_count": 0,
            "passing_closure_indices": list(PASSING_NEW_DERIVED_INDICES),
            "failing_closure_indices": [],
            "maximum_passing_upper_bound": maximum_new,
            "maximum_passing_upper_bound_f64le_hex": _o1c106._f64_hex(maximum_new),
            "rows_in_closure_order": new_audit,
        },
        "page23": {
            "lineage_ordinal": PAGE23_LINEAGE_ORDINAL,
            **page.describe(),
            "active_pass_count": len(active_rows),
            "active_fail_count": 0,
            "maximum_active_upper_bound": maximum_active,
            "maximum_active_upper_bound_f64le_hex": _o1c106._f64_hex(maximum_active),
            "maximum_strictly_below_threshold": True,
        },
        "categories": {
            "emitted": {
                "active": PAGE23_EMITTED_COUNT,
                "pass": PAGE23_EMITTED_COUNT,
                "fail": 0,
            },
            "legacy_derived": {
                "active": len(legacy_rows),
                "pass": len(legacy_rows),
                "fail": 0,
            },
            "new_derived": {
                "candidate": DERIVED_CLOSURE_CLAUSE_COUNT,
                "active": DERIVED_CLOSURE_CLAUSE_COUNT,
                "pass": DERIVED_CLOSURE_CLAUSE_COUNT,
                "fail": 0,
            },
        },
        "active_rows_in_serialization_order": list(active_rows),
        "publication_gate": "all-48-new-derived-and-all-245-active-v8-certifications-finished-in-memory",
        "passed": True,
    }
    certification_payload = canonical_json_bytes(certification)

    selected_set = set(selected_emitted)
    emitted_categories = {
        name: tuple(index for index in values if index in selected_set)
        for name, values in {
            "structural_root": pure.structural_root_indices,
            "pinned_core": pure.pinned_core_indices,
            "inherited_debt": pure.inherited_debt_indices,
            "new_debt": pure.new_debt_indices,
            "hot_event": pure.hot_event_indices,
            "recycled": pure.recycled_indices,
        }.items()
    }
    category_counts = {
        "emitted_structural_root": len(emitted_categories["structural_root"]),
        "inherited_o1c102_derived_structural_root": len(inherited_rows),
        "o1c104_derived_structural_root": len(o1c104_rows),
        "o1c108_derived_structural_root": len(o1c108_rows),
        "o1c110_derived_structural_root": len(o1c110_rows),
        "emitted_pinned_core": len(emitted_categories["pinned_core"]),
        "emitted_inherited_debt": len(emitted_categories["inherited_debt"]),
        "emitted_new_debt": len(emitted_categories["new_debt"]),
        "emitted_hot_event": len(emitted_categories["hot_event"]),
        "emitted_recycled": len(emitted_categories["recycled"]),
    }
    category_order: list[Mapping[str, object]] = [
        {
            "namespace": "emitted-causal-attic",
            "category": "structural_root",
            "union_index": index,
        }
        for index in emitted_categories["structural_root"]
    ]
    category_order.extend(inherited_rows)
    category_order.extend(o1c104_rows)
    category_order.extend(o1c108_rows)
    category_order.extend(o1c110_rows)
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
            for index in emitted_categories[category]
        )
    if (
        len(category_order) != PAGE23_ACTIVE_LIMIT
        or sum(category_counts.values()) != PAGE23_ACTIVE_LIMIT
    ):
        raise O1C110PreparationError("Page-23 category composition differs")

    activation_counts = tuple(
        count + (1 if index in selected_set else 0)
        for index, count in enumerate(counts_before)
    )
    last_active_lineages = tuple(
        PAGE23_LINEAGE_ORDINAL if index in selected_set else lineage
        for index, lineage in enumerate(lineages_before)
    )

    def advance_derived(
        count_field: str, lineage_field: str, rows: Sequence[Mapping[str, object]]
    ) -> tuple[tuple[int, ...], tuple[int | None, ...]]:
        counts = _integer_tuple(parent_residency.get(count_field), count_field)
        lineages = _optional_integer_tuple(
            parent_residency.get(lineage_field), lineage_field
        )
        selected_indices = {cast(int, row["closure_index"]) for row in rows}
        if len(counts) != len(lineages) or any(
            index >= len(counts) for index in selected_indices
        ):
            raise O1C110PreparationError("parent derived activation state differs")
        return (
            tuple(
                count + (1 if index in selected_indices else 0)
                for index, count in enumerate(counts)
            ),
            tuple(
                PAGE23_LINEAGE_ORDINAL if index in selected_indices else lineage
                for index, lineage in enumerate(lineages)
            ),
        )

    inherited_counts, inherited_lineages = advance_derived(
        "inherited_derived_activation_counts",
        "inherited_derived_last_active_lineages",
        inherited_rows,
    )
    o1c104_counts, o1c104_lineages = advance_derived(
        "o1c104_derived_activation_counts",
        "o1c104_derived_last_active_lineages",
        o1c104_rows,
    )
    o1c108_counts, o1c108_lineages = advance_derived(
        "o1c108_derived_activation_counts",
        "o1c108_derived_last_active_lineages",
        o1c108_rows,
    )
    o1c110_counts = (1,) * DERIVED_CLOSURE_CLAUSE_COUNT
    o1c110_lineages = (PAGE23_LINEAGE_ORDINAL,) * DERIVED_CLOSURE_CLAUSE_COUNT

    current_projection: dict[str, object] = {
        "encoding_only": page.describe(),
        "maximum_clause_count": PAGE23_ACTIVE_LIMIT,
        "category_counts": category_counts,
        "category_priority_order": category_order,
        "serialization_rule": "emitted-union-index-ascending;o1c102-row-order;o1c104-row-order;o1c108-row-order;o1c110-closure-index-ascending",
        "selector_confirmation": "exact-prefix-of-causally-advanced-pure-emitted-selection-order",
        "selected_emitted_union_indices": list(selected_emitted),
        "priority_selected_emitted_union_indices": list(priority_selected),
        "selected_emitted_union_indices_sha256": _index_list_sha256(selected_emitted),
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_o1c104_derived_clauses": list(o1c104_rows),
        "selected_o1c108_derived_clauses": list(o1c108_rows),
        "selected_o1c110_derived_clauses": list(o1c110_rows),
        "excluded_o1c110_derived_closure_indices": [],
    }
    current_entry = {
        "lineage_ordinal": PAGE23_LINEAGE_ORDINAL,
        "role": "type-safe-composed-causal-page-with-four-resolution-namespaces",
        "active_sha256": page.sha256,
        "selected_emitted_union_indices": list(selected_emitted),
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_o1c104_derived_clauses": list(o1c104_rows),
        "selected_o1c108_derived_clauses": list(o1c108_rows),
        "selected_o1c110_derived_clauses": list(o1c110_rows),
        "certification_audit_artifact": CERTIFICATION_AUDIT_NAME,
        "certification_audit_sha256": sha256_bytes(certification_payload),
    }
    parent_activation_payload = published.artifacts[ACTIVATION_LEDGER_NAME]
    activation_document = {
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
            "lineage_ordinal": PARENT_LINEAGE_ORDINAL,
            "active_sha256": _o1c108.PAGE22_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "intent_sha256": PARENT_INTENT_SHA256,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "retry_or_replay_authorized": False,
        },
        "composed_entries": [current_entry],
        "used_active_sha256": [*prior_used, page.sha256],
        "forbidden_nonactivated_candidate_sha256": pure.vault.sha256,
        "pure_emitted_candidate_activated": False,
    }
    activation_payload = canonical_json_bytes(activation_document)
    parent_residency_payload = published.artifacts[RESIDENCY_NAME]
    residency_document = {
        "schema": COMPOSED_RESIDENCY_SCHEMA,
        "active_limit": PAGE23_ACTIVE_LIMIT,
        "lineage_ordinal": PAGE23_LINEAGE_ORDINAL,
        "namespace_contract": {
            "emitted": "causal-attic-v1-with-native-ClauseOccurrence",
            "inherited_o1c102_derived": "immutable-o1c102-resolution-sidecar-without-ClauseOccurrence",
            "inherited_o1c104_derived": "immutable-o1c104-resolution-sidecar-without-ClauseOccurrence",
            "inherited_o1c108_derived": "immutable-o1c108-resolution-sidecar-without-ClauseOccurrence",
            "new_o1c110_derived": "immutable-o1c110-resolution-sidecar-without-ClauseOccurrence",
            "derived_enters_emitted_attic": False,
            "derived_occurrence_rows": 0,
            "selector": "causally-advanced-pure-emitted-priority-prefix-after-type-safe-derived-residency",
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
            "reason": "241-certified-derived-clauses-finalized-before-selecting-exact-4-clause-prefix",
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "o1c108-logical-known-registry-byte-order",
                "new-o1c109-native-emission",
                "new-o1c110-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "o1c108-logical-known-registry-byte-order",
                    "start": 0,
                    "stop_exclusive": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c109-native-emission",
                    "start": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "clause_count": NEW_CHUNK_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c110-derived-resolution",
                    "start": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": LOGICAL_KNOWN_CLAUSE_COUNT,
                    "clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                },
            ],
            "emitted_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "inherited_o1c102_derived_clause_count": 5,
            "inherited_o1c104_derived_clause_count": 84,
            "inherited_o1c108_derived_clause_count": 153,
            "new_o1c110_derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_encoding_sha256": resolution.logical.sha256,
            "combined_clause_aggregate_sha256": resolution.logical.clause_aggregate_sha256,
            "combined_literal_count": resolution.logical.literal_count,
            "combined_serialized_bytes": resolution.logical.serialized_bytes,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "strict_subsumption_pair_count": len(resolution.full_relations),
            "undominated_clause_count": len(resolution.logical_undominated_indices),
            "relation_artifact": DERIVED_RECEIPT_NAME,
            "byte_exact_inherited_sidecars_preserved": True,
            "all_48_new_proof_clauses_preserved": True,
        },
        "current_projection": current_projection,
        "activation_counts": list(activation_counts),
        "last_active_lineages": list(last_active_lineages),
        "inherited_derived_activation_counts": list(inherited_counts),
        "inherited_derived_last_active_lineages": list(inherited_lineages),
        "o1c104_derived_activation_counts": list(o1c104_counts),
        "o1c104_derived_last_active_lineages": list(o1c104_lineages),
        "o1c108_derived_activation_counts": list(o1c108_counts),
        "o1c108_derived_last_active_lineages": list(o1c108_lineages),
        "o1c110_derived_activation_counts": list(o1c110_counts),
        "o1c110_derived_last_active_lineages": list(o1c110_lineages),
        "certification_audit": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": sha256_bytes(certification_payload),
            "all_48_new_derived_clauses_certified": True,
            "new_derived_pass_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "new_derived_fail_count": 0,
            "all_active_clauses_certified": True,
            "active_pass_count": PAGE23_ACTIVE_LIMIT,
            "active_fail_count": 0,
        },
        "activation_ledger": activation_document,
    }
    return _Composition(
        page=page,
        pure_emitted=pure,
        selected_emitted=selected_emitted,
        priority_selected_emitted=priority_selected,
        inherited_rows=inherited_rows,
        o1c104_rows=o1c104_rows,
        o1c108_rows=o1c108_rows,
        o1c110_rows=o1c110_rows,
        category_counts=category_counts,
        category_priority_order=tuple(category_order),
        residency_payload=canonical_json_bytes(residency_document),
        activation_payload=activation_payload,
        certification_payload=certification_payload,
    )


def _authoritative_state(
    attic: CausalAttic, composition: _Composition
) -> ComposedPage23State:
    residency = _canonical_document(composition.residency_payload, "Page-23 residency")
    current = _mapping(residency.get("current_projection"), "Page-23 projection")
    projection = ComposedPage23Projection(
        lineage_ordinal=PAGE23_LINEAGE_ORDINAL,
        vault=composition.page,
        pure_emitted_candidate=composition.pure_emitted,
        selected_emitted_union_indices=composition.selected_emitted,
        priority_selected_emitted_union_indices=composition.priority_selected_emitted,
        selected_inherited_derived_clauses=composition.inherited_rows,
        selected_o1c104_derived_clauses=composition.o1c104_rows,
        selected_o1c108_derived_clauses=composition.o1c108_rows,
        selected_o1c110_derived_clauses=composition.o1c110_rows,
        category_counts=composition.category_counts,
        category_priority_order=composition.category_priority_order,
        document=current,
    )
    state = ComposedPage23State(
        attic=attic,
        current_projection=projection,
        residency_payload=composition.residency_payload,
        activation_payload=composition.activation_payload,
    )
    if (
        state.describe() != residency
        or state.active_projection.clause_count != PAGE23_ACTIVE_LIMIT
        or state.used_active_sha256[-1] != state.active_projection.sha256
        or _o1c108.PAGE22_SHA256 not in state.used_active_sha256
        or composition.pure_emitted.vault.sha256 in state.used_active_sha256
        or current.get("selected_emitted_union_indices")
        != list(composition.selected_emitted)
        or current.get("priority_selected_emitted_union_indices")
        != list(composition.priority_selected_emitted)
        or current.get("selected_o1c110_derived_clauses")
        != list(composition.o1c110_rows)
        or sum(composition.category_counts.values()) != PAGE23_ACTIVE_LIMIT
    ):
        raise O1C110PreparationError("authoritative Page-23 state differs")
    return state


def _artifact_roles() -> Mapping[str, str]:
    return {
        NEW_CHUNK_NAME: "immutable-unique-lineage-35-native-evidence-chunk",
        ACTIVE_PROJECTION_NAME: ACTIVE_PROJECTION_ROLE,
        RESIDENCY_NAME: "type-safe-five-namespace-lineage36-residency-state",
        ACTIVATION_LEDGER_NAME: "composed-activation-ledger-with-burned-page22-prefix",
        OCCURRENCES_NAME: "append-only-pure-native-complete-occurrence-ledger",
        RELATIONS_NAME: "complete-pure-native-signed-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-o1c109-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "sealed-o1c109-priority-state-receipt",
        INHERITED_DERIVED_RECEIPT_NAME: "immutable-inherited-o1c102-resolution-proof",
        INHERITED_DERIVED_CLOSURE_NAME: "immutable-inherited-o1c102-five-clause-closure",
        INHERITED_DERIVED_OVERLAY_NAME: "immutable-inherited-o1c102-three-clause-overlay",
        O1C104_DERIVED_RECEIPT_NAME: "immutable-inherited-o1c104-resolution-proof",
        O1C104_DERIVED_CLOSURE_NAME: "immutable-inherited-o1c104-84-clause-closure",
        O1C104_DERIVED_OVERLAY_NAME: "immutable-inherited-o1c104-52-clause-overlay",
        O1C108_DERIVED_RECEIPT_NAME: "immutable-inherited-o1c108-resolution-proof",
        O1C108_DERIVED_CLOSURE_NAME: "immutable-inherited-o1c108-153-clause-closure",
        O1C108_DERIVED_OVERLAY_NAME: "immutable-inherited-o1c108-153-clause-overlay",
        DERIVED_RECEIPT_NAME: "exact-public-o1c110-48-clause-fixed-point-resolution-proof",
        DERIVED_CLOSURE_NAME: "immutable-o1c110-48-clause-resolution-closure",
        DERIVED_OVERLAY_NAME: "immutable-o1c110-all-48-clause-proof-overlay",
        CERTIFICATION_AUDIT_NAME: "real-offline-v8-all-48-candidate-and-page23-certification-audit",
    }


def _build_manifest(
    *,
    state: ComposedPage23State,
    resolution: _ResolutionArtifacts,
    composition: _Composition,
    artifacts: Mapping[str, bytes],
) -> Mapping[str, object]:
    active = state.active_projection
    headroom = {
        "clauses": O1C66_VAULT_CAPS.maximum_clauses - active.clause_count,
        "literals": O1C66_VAULT_CAPS.maximum_literals - active.literal_count,
        "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
        - active.serialized_bytes,
    }
    roles = _artifact_roles()
    return {
        "schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": _zero_call(),
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page23_burned": False,
            "lineage36_burned": False,
            "page22_retry_or_replay_authorized": False,
            "lineage35_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        },
        "parent_success": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "capsule_manifest_serialized_bytes": PARENT_CAPSULE_MANIFEST_BYTES,
            "capsule_entry_count": PARENT_CAPSULE_ENTRY_COUNT,
            "result_sha256": PARENT_RESULT_SHA256,
            "result_serialized_bytes": PARENT_RESULT_BYTES,
            "intent_sha256": PARENT_INTENT_SHA256,
            "episode_sha256": PARENT_EPISODE_SHA256,
            "invocation_sha256": PARENT_INVOCATION_SHA256,
            "vault_telemetry_sha256": PARENT_VAULT_TELEMETRY_SHA256,
            "native_result_sha256": PARENT_NATIVE_RESULT_SHA256,
            "classification": _o1c109.SCIENCE_CLAUSE,
            "stop_reason": "globally-novel-clause",
            "page22_sha256": _o1c108.PAGE22_SHA256,
            "page22_burned": True,
            "lineage35_burned": True,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "globally_novel_native_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "retry_or_replay_authorized": False,
            "science_gain": True,
        },
        "canonical_o1c108": {
            "bundle_manifest_sha256": O1C108_MANIFEST_SHA256,
            "bundle_manifest_serialized_bytes": O1C108_MANIFEST_BYTES,
            "bundle_file_count": O1C108_BUNDLE_FILE_COUNT,
            "capsule_initial_byte_equal": True,
            "page22_certification_audit_sha256": _o1c108.CERTIFICATION_AUDIT_SHA256,
        },
        "causal_attic": {
            "chunk_count": ATTIC_CHUNK_COUNT,
            "union_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "occurrence_count": ATTIC_OCCURRENCE_COUNT,
            "duplicate_occurrence_count": ATTIC_DUPLICATE_OCCURRENCE_COUNT,
            "new_chunk_sha256": NEW_CHUNK_SHA256,
            "new_chunk_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "new_chunk_inventory_sha256": NEW_CHUNK_INVENTORY_SHA256,
            "union_sha256": state.attic.union_vault.sha256,
            "union_clause_aggregate_sha256": state.attic.union_vault.clause_aggregate_sha256,
            "union_literal_count": state.attic.union_vault.literal_count,
            "union_serialized_bytes": state.attic.union_vault.serialized_bytes,
            "strict_subsumption_pair_count": len(state.attic.relations),
            "undominated_clause_count": len(state.attic.undominated_indices),
            "occurrence_ledger_sha256": sha256_bytes(artifacts[OCCURRENCES_NAME]),
            "relation_ledger_sha256": sha256_bytes(artifacts[RELATIONS_NAME]),
            "append_only_parent_prefix": True,
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "o1c108-logical-known-registry-byte-order",
                "new-o1c109-native-emission",
                "new-o1c110-derived-resolution",
            ],
            "prior_prefix_clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
            "new_native_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "new_derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": resolution.logical.clause_count,
            "combined_encoding_sha256": resolution.logical.sha256,
            "combined_clause_aggregate_sha256": resolution.logical.clause_aggregate_sha256,
            "combined_literal_count": resolution.logical.literal_count,
            "combined_serialized_bytes": resolution.logical.serialized_bytes,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "strict_subsumption_pair_count": len(resolution.full_relations),
            "undominated_clause_count": len(resolution.logical_undominated_indices),
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "byte_exact_o1c108_prefix": True,
        },
        "derived_resolution": {
            "receipt_sha256": sha256_bytes(resolution.receipt_payload),
            "receipt_serialized_bytes": len(resolution.receipt_payload),
            "closure_sha256": resolution.closure.sha256,
            "closure_clause_count": resolution.closure.clause_count,
            "closure_inventory_sha256": DERIVED_CLOSURE_INVENTORY_SHA256,
            "overlay_sha256": resolution.overlay.sha256,
            "fixed_point_generation_audit": list(resolution.generation_audit),
            "pivot_or_generation_preselected": False,
            "all_clauses_preserved_in_proof_sidecars": True,
            "causal_attic_occurrence_rows_added": 0,
        },
        "certification": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": sha256_bytes(composition.certification_payload),
            "serialized_bytes": len(composition.certification_payload),
            "real_v8_theorem": True,
            "new_candidate_certified_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "new_candidate_pass_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "new_candidate_fail_count": 0,
            "all_active_clauses_certified": True,
            "active_pass_count": PAGE23_ACTIVE_LIMIT,
            "active_fail_count": 0,
            "maximum_new_passing_upper_bound": PAGE23_MAXIMUM_CERTIFIED_UPPER_BOUND,
            "threshold": _o1c106.THRESHOLD,
            "strictly_below_threshold": True,
        },
        "page23": {
            "lineage_ordinal": PAGE23_LINEAGE_ORDINAL,
            "active_limit": PAGE23_ACTIVE_LIMIT,
            "active_sha256": active.sha256,
            "clause_aggregate_sha256": active.clause_aggregate_sha256,
            "clause_count": active.clause_count,
            "literal_count": active.literal_count,
            "serialized_bytes": active.serialized_bytes,
            "category_counts": dict(composition.category_counts),
            "headroom": headroom,
            "selected_emitted_clause_count": PAGE23_EMITTED_COUNT,
            "selected_inherited_o1c102_derived_clause_count": PAGE23_INHERITED_DERIVED_COUNT,
            "selected_inherited_o1c104_derived_clause_count": PAGE23_O1C104_DERIVED_COUNT,
            "selected_inherited_o1c108_derived_clause_count": PAGE23_O1C108_DERIVED_COUNT,
            "selected_new_o1c110_derived_clause_count": PAGE23_O1C110_DERIVED_COUNT,
            "selected_emitted_union_indices": list(composition.selected_emitted),
            "selected_emitted_union_indices_sha256": _index_list_sha256(
                composition.selected_emitted
            ),
            "pure_emitted_candidate_sha256": composition.pure_emitted.vault.sha256,
            "pure_emitted_candidate_activated": False,
            "selector_confirmation": "exact-prefix-of-causally-advanced-pure-emitted-selection-order",
            "fresh_identity": active.sha256
            not in set(state.used_active_sha256[:-1])
            | {composition.pure_emitted.vault.sha256},
            "native_capacity_proof": {
                "maximum_clause_count": O1C66_VAULT_CAPS.maximum_clauses,
                "page23_input_clauses": active.clause_count,
                "maximum_additional_unique_clauses_before_capacity_terminal": headroom[
                    "clauses"
                ],
                "required_clause_headroom": NEW_CHUNK_CLAUSE_COUNT,
                "proved_sufficient": headroom["clauses"] == NEW_CHUNK_CLAUSE_COUNT,
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
            "receipt_sha256": PRIORITY_RECEIPT_SHA256,
            "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
            "receipt_artifact": PRIORITY_RECEIPT_NAME,
            "receipt_bank_hex_byte_equal": True,
            "priority_is_key_bit_belief": False,
            "semantic_role": "sealed-o1c109-live-continuation-bytes",
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }


def _fixed_artifact_seals() -> Mapping[str, tuple[int, str]]:
    return {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE23_SERIALIZED_BYTES, PAGE23_SHA256),
        RESIDENCY_NAME: (RESIDENCY_BYTES, RESIDENCY_SHA256),
        ACTIVATION_LEDGER_NAME: (ACTIVATION_BYTES, ACTIVATION_SHA256),
        OCCURRENCES_NAME: (OCCURRENCE_BYTES, OCCURRENCE_SHA256),
        RELATIONS_NAME: (RELATION_BYTES, RELATION_SHA256),
        FINAL_BANK_NAME: (FINAL_BANK_BYTES, FINAL_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
        DERIVED_RECEIPT_NAME: (DERIVED_RECEIPT_BYTES, DERIVED_RECEIPT_SHA256),
        DERIVED_CLOSURE_NAME: (DERIVED_CLOSURE_BYTES, DERIVED_CLOSURE_SHA256),
        DERIVED_OVERLAY_NAME: (DERIVED_CLOSURE_BYTES, DERIVED_CLOSURE_SHA256),
        CERTIFICATION_AUDIT_NAME: (
            CERTIFICATION_AUDIT_BYTES,
            CERTIFICATION_AUDIT_SHA256,
        ),
        PREPARATION_MANIFEST_NAME: (
            PREPARATION_MANIFEST_BYTES,
            PREPARATION_MANIFEST_SHA256,
        ),
    }


def _validate_prepared_bundle(prepared: PreparedCausalRolloverArtifacts) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C110PreparationError("prepared bundle type differs")
    expected_names = {*_artifact_roles(), PREPARATION_MANIFEST_NAME}
    if set(prepared.artifacts) != expected_names or len(prepared.artifacts) != 23:
        raise O1C110PreparationError("prepared artifact inventory differs")
    for name, (size, digest) in _fixed_artifact_seals().items():
        payload = prepared.artifacts.get(name)
        if (
            not isinstance(payload, bytes)
            or len(payload) != size
            or sha256_bytes(payload) != digest
        ):
            raise O1C110PreparationError(f"prepared {name} seal differs")

    manifest_payload = prepared.artifacts[PREPARATION_MANIFEST_NAME]
    manifest = _canonical_document(manifest_payload, "prepared manifest")
    expected_rows = {
        name: _artifact_row(payload, _artifact_roles()[name])
        for name, payload in sorted(prepared.artifacts.items())
        if name != PREPARATION_MANIFEST_NAME
    }
    if (
        manifest != prepared.manifest
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest.get("zero_call") != _zero_call()
        or manifest.get("artifacts") != expected_rows
    ):
        raise O1C110PreparationError("prepared manifest contract differs")

    observed = prepared.state.attic.union_vault.observed_variables
    try:
        chunk = parse_threshold_no_good_vault(
            prepared.artifacts[NEW_CHUNK_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        page = parse_threshold_no_good_vault(
            prepared.artifacts[ACTIVE_PROJECTION_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        closure = parse_threshold_no_good_vault(
            prepared.artifacts[DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        overlay = parse_threshold_no_good_vault(
            prepared.artifacts[DERIVED_OVERLAY_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C110PreparationError("prepared vault encoding differs") from exc
    receipt = _canonical_document(
        prepared.artifacts[DERIVED_RECEIPT_NAME], "prepared proof receipt"
    )
    certification = _canonical_document(
        prepared.artifacts[CERTIFICATION_AUDIT_NAME], "prepared certification"
    )
    priority = _canonical_document(
        prepared.artifacts[PRIORITY_RECEIPT_NAME], "prepared priority receipt"
    )
    bank_hex = priority.get("bank_hex")
    try:
        receipt_bank = bytes.fromhex(cast(str, bank_hex))
    except (TypeError, ValueError) as exc:
        raise O1C110PreparationError("prepared priority bank encoding differs") from exc
    if (
        chunk.sha256 != NEW_CHUNK_SHA256
        or page != prepared.state.active_projection
        or closure != overlay
        or closure.sha256 != DERIVED_CLOSURE_SHA256
        or prepared.artifacts[RESIDENCY_NAME] != prepared.state.residency_payload
        or prepared.artifacts[ACTIVATION_LEDGER_NAME]
        != prepared.state.activation_payload
        or prepared.artifacts[OCCURRENCES_NAME]
        != canonical_json_bytes(prepared.state.attic.occurrence_document())
        or prepared.artifacts[RELATIONS_NAME]
        != canonical_json_bytes(prepared.state.attic.relation_document())
        or receipt.get("schema") != DERIVED_RECEIPT_SCHEMA
        or _mapping(receipt.get("claim_boundary"), "proof claim").get(
            "pivot_or_generation_preselected"
        )
        is not False
        or _mapping(receipt.get("fixed_point_audit"), "fixed point audit").get(
            "fixed_point_reached"
        )
        is not True
        or certification.get("schema") != CERTIFICATION_AUDIT_SCHEMA
        or certification.get("passed") is not True
        or _mapping(certification.get("page23"), "certified Page-23").get(
            "active_pass_count"
        )
        != PAGE23_ACTIVE_LIMIT
        or receipt_bank != prepared.artifacts[FINAL_BANK_NAME]
    ):
        raise O1C110PreparationError("prepared semantic bundle differs")


def _atomic_rename_noreplace(source: Path, target: Path) -> None:
    """Atomically install one directory and refuse every existing target.

    Darwin exposes ``renamex_np(RENAME_EXCL)`` and modern Linux exposes
    ``renameat2(RENAME_NOREPLACE)``.  A platform without either primitive is
    rejected: falling back to check-then-rename would reintroduce a no-clobber
    race exactly at the irreversible publication boundary.
    """

    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = getattr(libc, "renamex_np", None)
    if renamex_np is not None:
        renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source_bytes, target_bytes, 0x00000004)
    else:
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise O1C110PreparationError(
                "atomic no-clobber directory publication is unavailable"
            )
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, source_bytes, -100, target_bytes, 0x00000001)
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        raise FileExistsError(error, os.strerror(error), target)
    raise OSError(error, os.strerror(error), target)


def _canonical_output_target(output_dir: str | Path) -> Path:
    output = Path(output_dir)
    if output.name in ("", ".", ".."):
        raise O1C110PreparationError("Page-23 output name differs")
    if not output.is_absolute():
        output = Path.cwd() / output
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        metadata = output.parent.lstat()
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise O1C110PreparationError("Page-23 output parent differs") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or parent != output.parent.absolute()
    ):
        raise O1C110PreparationError("Page-23 output parent is not canonical")
    target = parent / output.name
    try:
        target.lstat()
    except FileNotFoundError:
        return target
    except OSError as exc:
        raise O1C110PreparationError("Page-23 output differs") from exc
    raise O1C110PreparationError("Page-23 output already exists")


def _validate_materialized_directory(
    prepared: PreparedCausalRolloverArtifacts, directory: Path
) -> None:
    try:
        metadata = directory.lstat()
        children = tuple(directory.iterdir())
    except OSError as exc:
        raise O1C110PreparationError("materialized Page-23 directory differs") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise O1C110PreparationError("materialized Page-23 directory differs")
    if {path.name for path in children} != set(prepared.artifacts):
        raise O1C110PreparationError("materialized Page-23 inventory differs")
    for path in children:
        try:
            item_metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C110PreparationError(
                "materialized Page-23 artifact differs"
            ) from exc
        if (
            stat.S_ISLNK(item_metadata.st_mode)
            or not stat.S_ISREG(item_metadata.st_mode)
            or payload != prepared.artifacts[path.name]
        ):
            raise O1C110PreparationError("materialized Page-23 artifact differs")


def write_prepared_o1c110_page23_type_safe_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> Path:
    """Publish a validated Page-23 bundle atomically and without clobbering."""

    _validate_prepared_bundle(prepared)
    target = _canonical_output_target(output_dir)
    parent = target.parent
    try:
        stage = Path(
            tempfile.mkdtemp(prefix=f".{target.name}.", suffix=".tmp", dir=parent)
        )
    except OSError as exc:
        raise O1C110PreparationError("Page-23 publication stage failed") from exc
    committed = False
    try:
        for name, payload in sorted(prepared.artifacts.items()):
            if Path(name).name != name:
                raise O1C110PreparationError("Page-23 artifact name differs")
            path = stage / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.fchmod(handle.fileno(), 0o444)
            except OSError as exc:
                raise O1C110PreparationError("Page-23 artifact write failed") from exc
        _validate_materialized_directory(prepared, stage)
        stage_fd = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        try:
            _atomic_rename_noreplace(stage, target)
        except FileExistsError as exc:
            raise O1C110PreparationError("Page-23 output already exists") from exc
        except O1C110PreparationError:
            raise
        except OSError as exc:
            raise O1C110PreparationError("Page-23 atomic publication failed") from exc
        committed = True
        _validate_materialized_directory(prepared, target)
        try:
            parent_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            raise O1C110PublicationCommittedError(target, exc) from exc
        return target
    finally:
        if not committed and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def prepare_and_write_o1c110_page23_type_safe_causal_rollover(
    *,
    output_dir: str | Path,
    o1c108_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    prepared = prepare_o1c110_page23_type_safe_causal_rollover(
        o1c108_bundle_dir=o1c108_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c110_page23_type_safe_causal_rollover(prepared, output_dir)
    return prepared


def prepare_o1c110_page23_type_safe_causal_rollover(
    *,
    o1c108_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    root = lab_root()
    bundle = _canonical_path(
        root / DEFAULT_O1C108_BUNDLE_RELATIVE
        if o1c108_bundle_dir is None
        else o1c108_bundle_dir,
        "O1C-0108 bundle",
        directory=True,
    )
    capsule = _canonical_path(
        root / DEFAULT_PARENT_CAPSULE_RELATIVE if capsule_dir is None else capsule_dir,
        "O1C-0109 capsule",
        directory=True,
    )
    result_path = _canonical_path(
        root / DEFAULT_PARENT_RESULT_RELATIVE
        if parent_result_path is None
        else parent_result_path,
        "O1C-0109 result",
        directory=False,
    )
    published, parent_residency, parent_activation = _validate_o1c108_bundle(bundle)
    _result, telemetry, bank, priority_receipt = _validate_parent_success(
        capsule, result_path
    )
    _validate_capsule_initial_equals_bundle(capsule, published.artifacts)
    parent_attic, pinned, inherited_debt = _load_parent_attic(
        root, published, parent_residency
    )
    chunk = _new_chunk(parent_attic, telemetry, published.globally_known_clause_sha256)
    attic, event_indices = _advance_attic(parent_attic, chunk, telemetry)
    resolution = _derive_resolution_closure(attic, chunk, published.artifacts)
    composition = _compose_page23(
        root=root,
        attic=attic,
        event_indices=event_indices,
        pinned=pinned,
        inherited_debt=inherited_debt,
        published=published,
        parent_residency=parent_residency,
        parent_activation=parent_activation,
        resolution=resolution,
    )
    state = _authoritative_state(attic, composition)

    copied_names = {
        COMMON_CORE_AUDIT_NAME,
        INHERITED_DERIVED_RECEIPT_NAME,
        INHERITED_DERIVED_CLOSURE_NAME,
        INHERITED_DERIVED_OVERLAY_NAME,
        O1C104_DERIVED_RECEIPT_NAME,
        O1C104_DERIVED_CLOSURE_NAME,
        O1C104_DERIVED_OVERLAY_NAME,
        O1C108_DERIVED_RECEIPT_NAME,
        O1C108_DERIVED_CLOSURE_NAME,
        O1C108_DERIVED_OVERLAY_NAME,
    }
    artifacts: dict[str, bytes] = {
        name: published.artifacts[name] for name in copied_names
    }
    artifacts.update(
        {
            NEW_CHUNK_NAME: chunk.serialized,
            ACTIVE_PROJECTION_NAME: composition.page.serialized,
            RESIDENCY_NAME: composition.residency_payload,
            ACTIVATION_LEDGER_NAME: composition.activation_payload,
            OCCURRENCES_NAME: canonical_json_bytes(attic.occurrence_document()),
            RELATIONS_NAME: canonical_json_bytes(attic.relation_document()),
            FINAL_BANK_NAME: bank,
            PRIORITY_RECEIPT_NAME: priority_receipt,
            DERIVED_RECEIPT_NAME: resolution.receipt_payload,
            DERIVED_CLOSURE_NAME: resolution.closure.serialized,
            DERIVED_OVERLAY_NAME: resolution.overlay.serialized,
            CERTIFICATION_AUDIT_NAME: composition.certification_payload,
        }
    )
    manifest = _build_manifest(
        state=state,
        resolution=resolution,
        composition=composition,
        artifacts=artifacts,
    )
    manifest_payload = canonical_json_bytes(manifest)
    if (
        _canonical_document(manifest_payload, "Page-23 manifest") != manifest
        or len(artifacts) != 22
        or set(artifacts) != set(_artifact_roles())
        or _mapping(manifest.get("page23"), "manifest Page-23").get("headroom")
        != {
            "clauses": NEW_CHUNK_CLAUSE_COUNT,
            "literals": O1C66_VAULT_CAPS.maximum_literals
            - composition.page.literal_count,
            "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
            - composition.page.serialized_bytes,
        }
    ):
        raise O1C110PreparationError("Page-23 preparation manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    if len(artifacts) != 23:
        raise O1C110PreparationError("Page-23 artifact inventory differs")
    prepared = PreparedCausalRolloverArtifacts(
        state=state, artifacts=artifacts, manifest=manifest
    )
    _validate_prepared_bundle(prepared)
    return prepared


def preflight_o1c110_page23_type_safe_causal_rollover(
    *,
    o1c108_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    return prepare_o1c110_page23_type_safe_causal_rollover(
        o1c108_bundle_dir=o1c108_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or atomically publish O1C-0110's zero-call Page-23 rollover."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--o1c108-bundle-dir",
            type=Path,
            default=root / DEFAULT_O1C108_BUNDLE_RELATIVE,
        )
        child.add_argument(
            "--capsule-dir",
            type=Path,
            default=root / DEFAULT_PARENT_CAPSULE_RELATIVE,
        )
        child.add_argument(
            "--parent-result",
            type=Path,
            default=root / DEFAULT_PARENT_RESULT_RELATIVE,
        )
        if command == "prepare":
            child.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prepared = prepare_o1c110_page23_type_safe_causal_rollover(
            o1c108_bundle_dir=args.o1c108_bundle_dir,
            capsule_dir=args.capsule_dir,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c110_page23_type_safe_causal_rollover(
                prepared, args.output_dir
            )
    except O1C110PreparationError as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(prepared.manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
