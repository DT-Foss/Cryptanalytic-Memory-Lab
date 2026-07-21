"""Prepare O1C-0108's zero-call type-safe causal Page-22 rollover.

The successful O1C-0107 lineage-34 call emitted 266 globally novel native
clauses.  This module consumes only its sealed capsule/result and the sealed
O1C-0106 Page-21 bundle.  It never launches, preflights, or imports a native
solver.  The native clauses are appended to the causal attic, their complete
one-generation exact-resolution fixed point is retained as a proof sidecar,
and every one of the 153 resolvents is independently checked by the real v8
input theorem before the fresh Page-22 projection can be published.

Four resolvents fail that input theorem.  They remain in the immutable proof
closure and logical registry, but can never enter ACTIVE.  Page 22 is composed
from the 193 certified derived clauses and the 53 highest-priority clauses of
the causally advanced pure-emitted selector.  Its 246-clause limit leaves the
exact 266-clause native capacity required by the next call.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c102_page19_causal_rollover_prepare as _o1c102
from . import o1c104_page20_causal_rollover_prepare as _o1c104
from . import o1c106_page21_type_safe_rollover_prepare as _o1c106
from . import o1c107_apple8_parent_centered_continuation_run as _o1c107
from .causal_attic_v1 import (
    CausalAttic,
    CausalAtticError,
    ClauseOccurrence,
    ParsedVaultTelemetry,
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


ATTEMPT_ID = "O1C-0108"
PARENT_ATTEMPT_ID = "O1C-0107"
PREPARATION_SCHEMA = "o1-256-o1c108-page22-type-safe-causal-rollover-preparation-v1"
DERIVED_RECEIPT_SCHEMA = "o1-256-o1c108-derived-resolution-closure-receipt-v1"
CERTIFICATION_AUDIT_SCHEMA = "o1-256-o1c108-page22-v8-certification-audit-v1"
COMPOSED_RESIDENCY_SCHEMA = "o1-score-threshold-composed-residency-v4"
COMPOSED_ACTIVATION_SCHEMA = "o1-score-threshold-composed-activation-ledger-v4"

DEFAULT_O1C106_BUNDLE_RELATIVE = Path(
    "research/o1c106_page21_type_safe_rollover_seed_20260721"
)
DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_082548_917617_O1C-0107_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0107_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)

# The O1C106 bundle intentionally stores one copy of the newest chunk and a
# complete digest-only description of its transitive attic.  These canonical,
# published chunk paths materialize that description without regenerating the
# historical preparation chain.  Every byte is checked against the chunk row
# embedded in the sealed O1C106 residency before it is used.
CHUNK_SOURCE_RELATIVES = (
    Path("research/o1c74_causal_attic_seed_20260719/retained-source.vault"),
    Path("research/o1c74_causal_attic_seed_20260719/novel-rollover.vault"),
    Path("research/o1c75_causal_residency_seed_20260719/chunk-02.vault"),
    Path("research/o1c75_causal_residency_seed_20260719/chunk-03.vault"),
    *(
        Path("research/o1c75_causal_residency_seed_20260719/chunk-02.vault")
        for _ in range(8)
    ),
    Path("research/o1c83_causal_rollover_seed_20260720/lineage-22-new-chunk.vault"),
    Path(
        "research/o1c86_page11_causal_rollover_seed_20260720/lineage-24-new-chunk.vault"
    ),
    Path(
        "research/o1c87_page12_causal_rollover_seed_20260720/lineage-25-new-chunk.vault"
    ),
    Path(
        "research/o1c89_page13_causal_rollover_seed_20260720/lineage-26-new-chunk.vault"
    ),
    Path(
        "research/o1c91_page14_causal_rollover_seed_20260720/lineage-27-new-chunk.vault"
    ),
    Path(
        "research/o1c93_page15_causal_rollover_seed_20260720/lineage-28-new-chunk.vault"
    ),
    Path(
        "research/o1c98_page17_causal_rollover_seed_20260720/lineage-30-new-chunk.vault"
    ),
    Path(
        "research/o1c102_page19_causal_rollover_seed_20260721/lineage-31-native-emissions.vault"
    ),
    Path(
        "research/o1c104_page20_causal_rollover_seed_20260721/lineage-32-native-emissions.vault"
    ),
)

O1C106_MANIFEST_SHA256 = _o1c107.PUBLISHED_MANIFEST_SHA256
O1C106_MANIFEST_BYTES = _o1c107.PUBLISHED_MANIFEST_BYTES
O1C106_BUNDLE_FILE_COUNT = len(_o1c107.PREPARATION_ARTIFACT_NAMES)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "ffafafaac6c90d4d2092546629f0a2bee1f3067765cf6998aca30654a6118732"
)
PARENT_CAPSULE_MANIFEST_BYTES = 5_267
PARENT_CAPSULE_ENTRY_COUNT = 50
PARENT_RESULT_SHA256 = (
    "3d16db8abfa22531d1d18407c28b2c6e435b197d03e7297f2c837c6b50b48202"
)
PARENT_RESULT_BYTES = 15_838
PARENT_INTENT_SHA256 = (
    "28b4eee8204f250277c99a8d4824e9d7af57e252f36fa3aa6913a7a94cd0d6d5"
)
PARENT_INTENT_BYTES = 2_315
PARENT_EPISODE_SHA256 = (
    "3bb40dca757ab4f2b5a756f0ec5e39da2eea2969e1a935d09468b9b214c11984"
)
PARENT_EPISODE_BYTES = 4_292
PARENT_INVOCATION_SHA256 = (
    "e41843d5be10ed8cc884c8ad56519807e290b00d8e6bd529a0635af7b91c29ea"
)
PARENT_INVOCATION_BYTES = 5_527
PARENT_VAULT_TELEMETRY_SHA256 = (
    "0f2c33ec151f01429df35892cef4251f8322f3e3997c70c708daa46cd8dcf615"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_209_153
PARENT_NATIVE_RESULT_SHA256 = (
    "c7741ac20621f45f7ab101dc38b320474078e82871da8e00092e17bd5d37d406"
)
PARENT_NATIVE_RESULT_BYTES = 5_685_830

PARENT_LINEAGE_ORDINAL = 34
PAGE22_LINEAGE_ORDINAL = 35
PAGE22_ACTIVE_LIMIT = 246
PAGE22_EMITTED_COUNT = 53
PAGE22_INHERITED_DERIVED_COUNT = 3
PAGE22_O1C104_DERIVED_COUNT = 41
PAGE22_O1C108_DERIVED_COUNT = 149

NEW_NATIVE_OCCURRENCE_COUNT = 266
NEW_CHUNK_CLAUSE_COUNT = 266
NEW_CHUNK_LITERAL_COUNT = 752_466
NEW_CHUNK_SERIALIZED_BYTES = 3_011_119
NEW_CHUNK_SHA256 = "cbadc55596763f56e68e58810a47617f9e7aa5106f3ed297664f3ddebef61e2c"
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = (
    "a69109b64ac9ca79ba247ba93a82b1ffeb6dc7b5114593172f5946980fed1d25"
)
NEW_CHUNK_INVENTORY_SHA256 = (
    "53dc0b3c84ba04fec6d03a630e9cb8728a59992a7ff2aa65fe03dbe027b92b1a"
)

ATTIC_CHUNK_COUNT = 22
ATTIC_UNION_CLAUSE_COUNT = 2_869
ATTIC_OCCURRENCE_COUNT = 2_879
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 10
ATTIC_UNION_LITERAL_COUNT = 8_110_624
ATTIC_UNION_SERIALIZED_BYTES = 32_454_163
ATTIC_UNION_SHA256 = "e010b4f23efb2a672be18a151b0950d312fbe232156142e5a6f68d93eb3bc7d5"
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "1dd7bb5f088c33db945fa3358cec35d8b8105385a10b4944bbd9e9210a92a276"
)
ATTIC_SUBSUMPTION_RELATION_COUNT = 14
ATTIC_UNDOMINATED_CLAUSE_COUNT = 2_858

DERIVED_CLOSURE_CLAUSE_COUNT = 153
DERIVED_CLOSURE_LITERAL_COUNT = 437_591
DERIVED_CLOSURE_BYTES = 1_751_167
DERIVED_CLOSURE_SHA256 = (
    "6c77595387df7a84121056fa1c09036ddae91c58ad05c6b769245cf23ee6f935"
)
DERIVED_CLOSURE_AGGREGATE_SHA256 = (
    "0b46239512a5d87ca89ec5a9fc0bfde2e0100e4677ec2cbd81f2d4aa8cde2c45"
)
DERIVED_CLOSURE_INVENTORY_SHA256 = (
    "9d162fe9718664cfd5d2b4d016c6b390ec086bd8987d37c22a76518355965d62"
)
DERIVED_EDGE_INVENTORY_SHA256 = (
    "23500f3b5a7a30c8e1b08d3bdc00135a4e6cd75d1a64ab3e61fe3101f460ea79"
)
FAILED_NEW_DERIVED_INDICES = (1, 2, 32, 55)
PASSING_NEW_DERIVED_INDICES = tuple(
    index
    for index in range(DERIVED_CLOSURE_CLAUSE_COUNT)
    if index not in set(FAILED_NEW_DERIVED_INDICES)
)
PAGE22_MAXIMUM_CERTIFIED_UPPER_BOUND = 14.50523425946539

G1_PAIR_COUNT = 35_245
G1_ZERO_COMPLEMENT_PAIR_COUNT = 0
G1_MULTI_COMPLEMENT_PAIR_COUNT = 35_092
G1_SINGLE_PIVOT_PAIR_COUNT = 153
G2_FRONTIER_PAIR_COUNT = 52_326
G2_ZERO_COMPLEMENT_PAIR_COUNT = 306
G2_MULTI_COMPLEMENT_PAIR_COUNT = 52_020
G2_SINGLE_PIVOT_PAIR_COUNT = 0

PRIOR_LOGICAL_CLAUSE_COUNT = 2_692
INTERMEDIATE_LOGICAL_CLAUSE_COUNT = 2_958
LOGICAL_KNOWN_CLAUSE_COUNT = 3_111
LOGICAL_KNOWN_LITERAL_COUNT = 8_801_942
LOGICAL_KNOWN_SERIALIZED_BYTES = 35_220_403
INTERMEDIATE_LOGICAL_INVENTORY_SHA256 = (
    "4154b7725b3f541bf34097fc841311a1339e15ad73bb88a4cadeb5ad58a78ae7"
)
LOGICAL_KNOWN_INVENTORY_SHA256 = (
    "88a28c05da2f685ccc8a24193b05771c7ee02c7ba5fe1d8e987ef3662301576d"
)
LOGICAL_KNOWN_SHA256 = (
    "20cd02d895ef7024a827b2bf128111e1f0b8afb1db1d11f16f3ad6baa577de57"
)
LOGICAL_KNOWN_AGGREGATE_SHA256 = (
    "45f7ac33a37eab1699c94064de94e19a7a976c5ad855587a8430700fa6beb2cc"
)
LOGICAL_SUBSUMPTION_RELATION_COUNT = 285
LOGICAL_UNDOMINATED_CLAUSE_COUNT = 2_832

FINAL_BANK_SHA256 = "62360d82b191b2e323c7205d950651ac1ad592cc9365892bf5c58d932b64087f"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "a3578ea3fb591b9227ca11034ac34aba8c170f47a65e05e092d108106f33129e"
)
PRIORITY_RECEIPT_BYTES = 51_961

NEW_CHUNK_NAME = "lineage-34-native-emissions.vault"
ACTIVE_PROJECTION_NAME = "page-22-active.bin"
ACTIVE_PROJECTION_ROLE = "fresh-lineage-35-type-safe-composed-page22-science-input"
RESIDENCY_NAME = _o1c106.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c106.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c106.OCCURRENCES_NAME
RELATIONS_NAME = _o1c106.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c106.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c106.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = _o1c106.PRIORITY_RECEIPT_NAME
INHERITED_DERIVED_RECEIPT_NAME = _o1c106.INHERITED_DERIVED_RECEIPT_NAME
INHERITED_DERIVED_CLOSURE_NAME = _o1c106.INHERITED_DERIVED_CLOSURE_NAME
INHERITED_DERIVED_OVERLAY_NAME = _o1c106.INHERITED_DERIVED_OVERLAY_NAME
O1C104_DERIVED_RECEIPT_NAME = _o1c106.DERIVED_RECEIPT_NAME
O1C104_DERIVED_CLOSURE_NAME = _o1c106.DERIVED_CLOSURE_NAME
O1C104_DERIVED_OVERLAY_NAME = _o1c106.DERIVED_OVERLAY_NAME
DERIVED_RECEIPT_NAME = "o1c108-derived-resolution-closure-receipt.json"
DERIVED_CLOSURE_NAME = "o1c108-derived-resolution-closure.vault"
DERIVED_OVERLAY_NAME = "o1c108-derived-resolution-overlay.vault"
CERTIFICATION_AUDIT_NAME = "page-22-v8-certification-audit.json"
PREPARATION_MANIFEST_NAME = _o1c106.PREPARATION_MANIFEST_NAME

PAGE22_SHA256 = "183878040210ffb542b199148c7151bd2656b6019755a978142f3fbf87ac162f"
PAGE22_CLAUSE_AGGREGATE_SHA256 = (
    "683e3f5510843679edb0e5d8dc450c3abb6b366fc49291557a0d68aaff774fd7"
)
PAGE22_LITERAL_COUNT = 688_833
PAGE22_SERIALIZED_BYTES = 2_756_507
PAGE22_PURE_EMITTED_SHA256 = (
    "97623323579d56de5034caf107627c939a991be0e00e6aee192d60a0bcf56f88"
)
PAGE22_PURE_EMITTED_LITERAL_COUNT = 674_160
PAGE22_PURE_EMITTED_SERIALIZED_BYTES = 2_697_815
SELECTED_EMITTED_UNION_INDICES = (
    9,
    123,
    144,
    202,
    203,
    204,
    205,
    206,
    207,
    513,
    514,
    515,
    516,
    517,
    518,
    519,
    520,
    521,
    522,
    523,
    524,
    525,
    526,
    527,
    528,
    529,
    530,
    531,
    532,
    533,
    534,
    535,
    536,
    537,
    538,
    539,
    540,
    541,
    542,
    543,
    544,
    545,
    546,
    547,
    548,
    549,
    551,
    812,
    1_296,
    1_298,
    1_328,
    1_554,
    2_711,
)
SELECTED_EMITTED_INDICES_SHA256 = (
    "4288c99f66b918e5f30e8cde3fc246accc477691611288e984f5b764502af0ae"
)
DERIVED_RECEIPT_SHA256 = (
    "98c353c24b097dd3b6bec974d91a55d8bf789248d571e37554fe8ce2216d9fe8"
)
DERIVED_RECEIPT_BYTES = 361_008
CERTIFICATION_AUDIT_SHA256 = (
    "69c39844a95a6e5e163f445c351c221fbc19b2348a140c8a659785f5081a6c88"
)
CERTIFICATION_AUDIT_BYTES = 227_369
RESIDENCY_SHA256 = "6ef563a6f42939bab76b9a711a39d87f5cec64ef1ca7c761a1f977af732fe17e"
RESIDENCY_BYTES = 723_643
ACTIVATION_SHA256 = "c83c9f0b20c78853df1a214fed2e557daf54c36451ec3d26e7f2e3cf5ed1dcb2"
ACTIVATION_BYTES = 106_972
OCCURRENCE_SHA256 = "efcdd199db530288bc4675f3403969607bbfe08cfd424680254a0e744802926c"
OCCURRENCE_BYTES = 1_024_920
RELATION_SHA256 = "7f61b7065eb6f29398a23a9d8a7dd09be98b09470e951aebf404bfeef2a0328b"
RELATION_BYTES = 17_657
PREPARATION_MANIFEST_SHA256 = (
    "f16d505fc8f5007d6a1ace11c991323d74802eaa6d005c1eaaa3fe71daa72b04"
)
PREPARATION_MANIFEST_BYTES = 12_468


class O1C108PreparationError(RuntimeError):
    """A sealed parent, proof, theorem, selector, or publication seal differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C108PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C108PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C108PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C108PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or resolved != path:
        raise O1C108PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C108PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C108PreparationError(f"{label} is not canonical JSON")
    return value


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _index_list_sha256(indices: Sequence[int]) -> str:
    return sha256_bytes(canonical_json_bytes(list(indices)))


def _inventory(clauses: Sequence[ThresholdNoGoodClause]) -> tuple[list[str], str]:
    values = [clause.sha256 for clause in clauses]
    if len(values) != len(set(values)):
        raise O1C108PreparationError("logical clause inventory contains a duplicate")
    return values, sha256_bytes(canonical_json_bytes(values))


def _parse_checksum_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C108PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C108PreparationError("parent capsule manifest row differs")
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
            raise O1C108PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    return entries


def _validate_capsule_inventory(capsule: Path) -> Mapping[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C108PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C108PreparationError("parent capsule manifest differs")
    entries = _parse_checksum_manifest(payload)
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C108PreparationError("parent capsule manifest inventory differs")
    observed: set[str] = set()
    try:
        for path in capsule.rglob("*"):
            relative = path.relative_to(capsule).as_posix()
            item_metadata = path.lstat()
            if stat.S_ISLNK(item_metadata.st_mode):
                raise O1C108PreparationError("parent capsule contains a symlink")
            if stat.S_ISREG(item_metadata.st_mode):
                observed.add(relative)
            elif not stat.S_ISDIR(item_metadata.st_mode):
                raise O1C108PreparationError("parent capsule contains a special file")
    except OSError as exc:
        raise O1C108PreparationError("parent capsule inventory is unreadable") from exc
    if observed != set(entries) | {"artifacts.sha256"}:
        raise O1C108PreparationError("parent capsule inventory differs")
    for relative, digest in entries.items():
        path = capsule / relative
        try:
            item_metadata = path.lstat()
            item = path.read_bytes()
        except OSError as exc:
            raise O1C108PreparationError("parent capsule artifact differs") from exc
        if (
            stat.S_ISLNK(item_metadata.st_mode)
            or not stat.S_ISREG(item_metadata.st_mode)
            or sha256_bytes(item) != digest
        ):
            raise O1C108PreparationError("parent capsule artifact differs")
    return entries


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
        raise O1C108PreparationError("parent success artifacts are unreadable") from exc
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
            raise O1C108PreparationError("parent success seals differ")
    if external_result != payloads["result"]:
        raise O1C108PreparationError("parent authoritative result differs")

    result = _canonical_document(payloads["result"], "parent result")
    intent = _canonical_document(payloads["intent"], "parent intent")
    episode = _canonical_document(payloads["episode"], "parent episode")
    episodes = _sequence(result.get("episodes"), "parent result episodes")
    science = _mapping(episode.get("science"), "parent episode science")
    operation = _mapping(episode.get("operational"), "parent episode operation")
    if (
        result.get("schema") != _o1c107.RESULT_SCHEMA
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("classification") != _o1c107.SCIENCE_CLAUSE
        or result.get("stop_reason") != "globally-novel-clause"
        or result.get("science_gain") is not True
        or result.get("operational_activation") is not True
        or len(episodes) != 1
        or _mapping(episodes[0], "parent result episode") != episode
        or episode.get("schema") != _o1c107.EPISODE_SCHEMA
        or episode.get("completed") is not True
        or episode.get("lineage_call_ordinal") != PARENT_LINEAGE_ORDINAL
        or episode.get("page21_burned") is not True
        or episode.get("lineage34_burned") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not True
        or episode.get("requested_conflicts") != 128
        or episode.get("actual_conflicts") != 57
        or episode.get("billed_conflicts") != 57
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or episode.get("terminal_failure") is not None
        or science.get("science_gain") is not True
        or science.get("fully_emitted_clauses") != NEW_NATIVE_OCCURRENCE_COUNT
        or science.get("globally_novel_clauses") != NEW_CHUNK_CLAUSE_COUNT
        or operation.get("operational_activation") is not True
        or intent.get("schema") != _o1c107.INTENT_SCHEMA
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("page21_sha256") != _o1c106.PAGE21_SHA256
        or intent.get("page21_burned") is not True
        or intent.get("lineage34_burned") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
    ):
        raise O1C108PreparationError("parent successful call boundary differs")

    receipt = _canonical_document(payloads["receipt"], "parent priority receipt")
    hexadecimal = receipt.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C108PreparationError("parent priority bank encoding differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C108PreparationError("parent priority bank encoding differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c107-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or receipt.get("bank_bytes") != FINAL_BANK_BYTES
        or receipt.get("current_bank_sha256") != FINAL_BANK_SHA256
        or receipt_bank != payloads["bank"]
        or receipt.get("candidate_population") != 255
        or receipt.get("consumed_coordinate_count") != 255
        or receipt.get("assignment_literals_observed") != 59_895
        or receipt.get("parent_scans") != 570
        or receipt.get("callback_calls") != 570
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 315
        or receipt.get("last_parent_candidate_count") != 2
    ):
        raise O1C108PreparationError("parent priority state differs")
    try:
        telemetry = parse_vault_telemetry(
            payloads["vault"],
            stream_id="o1c107-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C108PreparationError("parent native telemetry differs") from exc
    raw_vault = _canonical_document(payloads["vault"], "parent native telemetry")
    expected_vault = {
        "input_sha256": _o1c106.PAGE21_SHA256,
        "input_clause_count": _o1c106.PAGE21_ACTIVE_LIMIT,
        "input_literal_count": _o1c106.PAGE21_LITERAL_COUNT,
        "input_serialized_bytes": _o1c106.PAGE21_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": _o1c106.PAGE21_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": _o1c106.PAGE21_ACTIVE_LIMIT,
        "validated_input_literal_count": _o1c106.PAGE21_LITERAL_COUNT,
        "fully_emitted_clause_count": NEW_NATIVE_OCCURRENCE_COUNT,
        "fully_emitted_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": NEW_CHUNK_CLAUSE_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": _o1c106.PAGE21_ACTIVE_LIMIT,
        "preloaded_literal_count": _o1c106.PAGE21_LITERAL_COUNT,
        "next_vault_available": False,
        "next_vault_sha256": None,
        "next_clause_count": None,
        "next_literal_count": None,
        "next_serialized_bytes": None,
        "next_vault_terminal_reason": "capacity_clause_count",
        "maximum_clause_count": 512,
        "maximum_literal_count": 1_600_000,
        "maximum_payload_bytes": 8_388_608,
        "pending_clause_exported": False,
        "terminal_empty_clause_count": 0,
    }
    if (
        any(raw_vault.get(name) != value for name, value in expected_vault.items())
        or len(telemetry.occurrences) != NEW_NATIVE_OCCURRENCE_COUNT
        or len(telemetry.new_occurrences) != NEW_CHUNK_CLAUSE_COUNT
        or any(
            row.classification != "new" or row.source != "trail_upper_bound"
            for row in telemetry.occurrences
        )
        or len({row.clause.serialized for row in telemetry.occurrences})
        != NEW_CHUNK_CLAUSE_COUNT
    ):
        raise O1C108PreparationError("parent native novelty ledger differs")
    return result, telemetry, payloads["bank"], payloads["receipt"]


def _validate_o1c106_bundle(
    bundle: Path,
) -> tuple[_o1c107.PublishedPreparation, Mapping[str, object], Mapping[str, object]]:
    try:
        published = _o1c107._load_published_preparation(
            bundle, bundle / _o1c106.PREPARATION_MANIFEST_NAME
        )
    except _o1c107.O1C107RunError as exc:
        raise O1C108PreparationError("sealed O1C-0106 bundle differs") from exc
    manifest_payload = published.artifacts[_o1c106.PREPARATION_MANIFEST_NAME]
    if (
        len(manifest_payload) != O1C106_MANIFEST_BYTES
        or sha256_bytes(manifest_payload) != O1C106_MANIFEST_SHA256
        or len(published.artifacts) != O1C106_BUNDLE_FILE_COUNT
    ):
        raise O1C108PreparationError("sealed O1C-0106 manifest differs")
    residency = _canonical_document(
        published.artifacts[RESIDENCY_NAME], "sealed O1C-0106 residency"
    )
    activation = _canonical_document(
        published.artifacts[ACTIVATION_LEDGER_NAME],
        "sealed O1C-0106 activation ledger",
    )
    return published, residency, activation


def _validate_capsule_initial_equals_bundle(
    capsule: Path, bundle_artifacts: Mapping[str, bytes]
) -> None:
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C108PreparationError("parent initial bundle is unreadable") from exc
    if {path.name for path in children} != set(bundle_artifacts):
        raise O1C108PreparationError("parent initial bundle inventory differs")
    for name, expected in bundle_artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError as exc:
            raise O1C108PreparationError("parent initial bundle differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or payload != expected
        ):
            raise O1C108PreparationError("parent initial bundle differs")


def _integer_tuple(value: object, label: str) -> tuple[int, ...]:
    items = tuple(_sequence(value, label))
    if any(isinstance(item, bool) or not isinstance(item, int) for item in items):
        raise O1C108PreparationError(f"{label} differs")
    return cast(tuple[int, ...], items)


def _optional_integer_tuple(value: object, label: str) -> tuple[int | None, ...]:
    items = tuple(_sequence(value, label))
    if any(
        item is not None and (isinstance(item, bool) or not isinstance(item, int))
        for item in items
    ):
        raise O1C108PreparationError(f"{label} differs")
    return cast(tuple[int | None, ...], items)


def _load_parent_attic(
    root: Path,
    published: _o1c107.PublishedPreparation,
    residency: Mapping[str, object],
) -> tuple[CausalAttic, tuple[int, ...], tuple[int, ...]]:
    emitted_description = _mapping(
        residency.get("emitted_causal_attic"), "O1C-0106 emitted attic"
    )
    chunk_rows = tuple(
        _sequence(emitted_description.get("chunks"), "O1C-0106 attic chunks")
    )
    if len(CHUNK_SOURCE_RELATIVES) != 21 or len(chunk_rows) != 21:
        raise O1C108PreparationError("O1C-0106 transitive chunk inventory differs")
    chunks: list[ThresholdNoGoodVault] = []
    observed_variables: tuple[int, ...] | None = None
    for index, (relative, row_value) in enumerate(
        zip(CHUNK_SOURCE_RELATIVES, chunk_rows, strict=True)
    ):
        path = _canonical_path(root / relative, f"attic chunk {index}", directory=False)
        try:
            payload = path.read_bytes()
            chunk = (
                parse_self_scoping_vault(payload, caps=O1C66_VAULT_CAPS)
                if observed_variables is None
                else parse_threshold_no_good_vault(
                    payload,
                    observed_variables=observed_variables,
                    caps=O1C66_VAULT_CAPS,
                )
            )
        except (OSError, CausalAtticError, ThresholdNoGoodVaultError) as exc:
            raise O1C108PreparationError("transitive attic chunk differs") from exc
        if observed_variables is None:
            observed_variables = chunk.observed_variables
        row = _mapping(row_value, f"O1C-0106 attic chunk row {index}")
        expected = {"chunk_index": index, **chunk.describe()}
        if any(row.get(name) != value for name, value in expected.items()):
            raise O1C108PreparationError("transitive attic chunk seal differs")
        chunks.append(chunk)
    if observed_variables is None:
        raise O1C108PreparationError("transitive attic scope differs")

    union_clauses: list[ThresholdNoGoodClause] = []
    clause_by_bytes: dict[bytes, int] = {}
    for chunk in chunks:
        for clause in chunk.clauses:
            if clause.serialized not in clause_by_bytes:
                clause_by_bytes[clause.serialized] = len(union_clauses)
                union_clauses.append(clause)
    try:
        union = ThresholdNoGoodVault(
            chunks[0].identity, observed_variables, tuple(union_clauses)
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("parent attic union differs") from exc
    union_description = _mapping(
        emitted_description.get("union"), "O1C-0106 emitted attic union"
    )
    if union.describe() != dict(union_description):
        raise O1C108PreparationError("parent attic union seal differs")

    occurrence_payload = published.artifacts[OCCURRENCES_NAME]
    occurrence_document = _canonical_document(
        occurrence_payload, "O1C-0106 occurrence ledger"
    )
    rows = tuple(_sequence(occurrence_document.get("records"), "O1C-0106 occurrences"))
    occurrences: list[ClauseOccurrence] = []
    for ordinal, row_value in enumerate(rows):
        row = _mapping(row_value, f"O1C-0106 occurrence {ordinal}")
        union_index = row.get("union_clause_index")
        if (
            isinstance(union_index, bool)
            or not isinstance(union_index, int)
            or not 0 <= union_index < union.clause_count
        ):
            raise O1C108PreparationError("O1C-0106 occurrence index differs")
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
            raise O1C108PreparationError("O1C-0106 occurrence differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C108PreparationError("O1C-0106 occurrence row differs")
        occurrences.append(occurrence)
    try:
        attic = reproject_causal_attic(
            tuple(chunks), tuple(occurrences), active_limit=_o1c106.PAGE21_ACTIVE_LIMIT
        )
    except CausalAtticError as exc:
        raise O1C108PreparationError("parent causal attic replay differs") from exc
    relation_payload = canonical_json_bytes(attic.relation_document())
    if (
        attic.describe() != dict(emitted_description)
        or canonical_json_bytes(attic.occurrence_document()) != occurrence_payload
        or relation_payload != published.artifacts[RELATIONS_NAME]
        or attic.union_vault.clause_count != _o1c104.ATTIC_UNION_CLAUSE_COUNT
        or len(attic.occurrences) != _o1c104.ATTIC_OCCURRENCE_COUNT
    ):
        raise O1C108PreparationError("parent causal attic artifacts differ")

    o1c102_residency = _mapping(
        _mapping(
            _mapping(
                residency.get("parent_composed_residency"),
                "O1C-0106 parent residency",
            ).get("document"),
            "O1C-0104 residency",
        ).get("parent_composed_residency"),
        "O1C-0104 parent residency",
    )
    o1c102_document = _mapping(o1c102_residency.get("document"), "O1C-0102 residency")
    parent_causal = _mapping(
        o1c102_document.get("parent_causal_residency"),
        "O1C-0102 parent causal residency",
    )
    pinned = _integer_tuple(parent_causal.get("pinned_core_indices"), "pinned core")
    inherited_debt = _integer_tuple(
        parent_causal.get("inherited_debt_indices"), "inherited debt"
    )
    if len(pinned) != 46 or len(inherited_debt) != 289:
        raise O1C108PreparationError("parent causal selector roots differ")
    return attic, pinned, inherited_debt


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
        raise O1C108PreparationError("new immutable native chunk differs") from exc
    _values, inventory_sha = _inventory(chunk.clauses)
    if (
        roundtrip != chunk
        or telemetry.input_identity != parent_attic.union_vault.identity
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.clause_aggregate_sha256 != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
        or inventory_sha != NEW_CHUNK_INVENTORY_SHA256
        or globally_known_sha256.intersection(clause.sha256 for clause in chunk.clauses)
    ):
        raise O1C108PreparationError("new immutable native chunk seal differs")
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
            active_limit=PAGE22_ACTIVE_LIMIT,
        )
    except CausalAtticError as exc:
        raise O1C108PreparationError("Page-22 causal attic append differs") from exc
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
        or len(set(event_indices)) != NEW_CHUNK_CLAUSE_COUNT
        or event_indices
        != tuple(
            range(
                _o1c104.ATTIC_UNION_CLAUSE_COUNT,
                ATTIC_UNION_CLAUSE_COUNT,
            )
        )
    ):
        raise O1C108PreparationError("Page-22 causal attic census differs")
    return attic, event_indices


@dataclass(frozen=True)
class _ResolutionArtifacts:
    closure: ThresholdNoGoodVault
    overlay: ThresholdNoGoodVault
    receipt_payload: bytes
    logical: ThresholdNoGoodVault
    full_relations: tuple[tuple[int, int], ...]
    logical_undominated_indices: tuple[int, ...]


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
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("inherited derived sidecar differs") from exc
    emitted = attic.union_vault.clauses[: _o1c104.ATTIC_UNION_CLAUSE_COUNT]
    prior = (
        *emitted[:2_338],
        *inherited.clauses,
        *emitted[2_338:],
        *o1c104.clauses,
    )
    receipt = _canonical_document(
        artifacts[O1C104_DERIVED_RECEIPT_NAME], "O1C-0104 resolution receipt"
    )
    registry = _mapping(receipt.get("logical_known_registry"), "prior registry")
    combined = _mapping(registry.get("combined"), "prior combined registry")
    inventory = tuple(
        cast(
            Sequence[str],
            _sequence(combined.get("clause_sha256"), "prior clause inventory"),
        )
    )
    if (
        len(prior) != PRIOR_LOGICAL_CLAUSE_COUNT
        or tuple(clause.sha256 for clause in prior) != inventory
        or combined.get("inventory_sha256") != _o1c106.LOGICAL_KNOWN_INVENTORY_SHA256
        or combined.get("clause_count") != PRIOR_LOGICAL_CLAUSE_COUNT
    ):
        raise O1C108PreparationError("prior chronological logical registry differs")
    return tuple(prior)


def _derive_resolution_closure(
    attic: CausalAttic,
    chunk: ThresholdNoGoodVault,
    artifacts: Mapping[str, bytes],
) -> _ResolutionArtifacts:
    native_refs = tuple(
        _o1c104._ClauseRef(
            kind="o1c107-native-emission",
            clause=clause,
            logical_index=PRIOR_LOGICAL_CLAUSE_COUNT + index,
            source_index=index,
            unique_index=index,
        )
        for index, clause in enumerate(chunk.clauses)
    )
    encoded = {
        id(ref.clause): _o1c104._encode_clause(ref.clause) for ref in native_refs
    }
    known = {clause.serialized for clause in _prior_logical_clauses(attic, artifacts)}
    known.update(clause.serialized for clause in chunk.clauses)
    candidates: dict[
        bytes,
        tuple[ThresholdNoGoodClause, _o1c104._ClauseRef, _o1c104._ClauseRef, int],
    ] = {}
    g1_counts = {"zero": 0, "multi": 0, "single": 0}
    for left_index, left in enumerate(native_refs):
        for right in native_refs[left_index + 1 :]:
            kind, pivot, resolvent = _o1c104._pair_resolution(left, right, encoded)
            g1_counts[kind] += 1
            if kind == "single":
                if pivot is None or resolvent is None or pivot != 32:
                    raise O1C108PreparationError("generation-1 pivot differs")
                if resolvent.serialized in known:
                    raise O1C108PreparationError("generation-1 resolvent is not novel")
                candidates.setdefault(
                    resolvent.serialized, (resolvent, left, right, pivot)
                )
    ordered = sorted(
        candidates.values(), key=lambda row: (row[0].literal_count, row[0].sha256)
    )
    nodes = tuple(
        _o1c104._ProofNode(
            generation=1,
            node=f"G1-{index:03d}",
            clause=clause,
            left=left,
            right=right,
            pivot=pivot,
        )
        for index, (clause, left, right, pivot) in enumerate(ordered)
    )
    derived_refs = tuple(
        _o1c104._ClauseRef(
            kind="o1c108-derived-resolution", clause=node.clause, node=node.node
        )
        for node in nodes
    )
    encoded.update(
        {id(ref.clause): _o1c104._encode_clause(ref.clause) for ref in derived_refs}
    )
    known_after_g1 = known | {node.clause.serialized for node in nodes}
    g2_counts = {"zero": 0, "multi": 0, "single": 0}
    g2_novel: set[bytes] = set()

    def scan_g2(left: _o1c104._ClauseRef, right: _o1c104._ClauseRef) -> None:
        kind, _pivot, resolvent = _o1c104._pair_resolution(left, right, encoded)
        g2_counts[kind] += 1
        if (
            kind == "single"
            and resolvent is not None
            and resolvent.serialized not in known_after_g1
        ):
            g2_novel.add(resolvent.serialized)

    for left in derived_refs:
        for right in native_refs:
            scan_g2(left, right)
    for left_index, left in enumerate(derived_refs):
        for right in derived_refs[left_index + 1 :]:
            scan_g2(left, right)
    if (
        g1_counts
        != {
            "zero": G1_ZERO_COMPLEMENT_PAIR_COUNT,
            "multi": G1_MULTI_COMPLEMENT_PAIR_COUNT,
            "single": G1_SINGLE_PIVOT_PAIR_COUNT,
        }
        or sum(g1_counts.values()) != G1_PAIR_COUNT
        or len(nodes) != DERIVED_CLOSURE_CLAUSE_COUNT
        or g2_counts
        != {
            "zero": G2_ZERO_COMPLEMENT_PAIR_COUNT,
            "multi": G2_MULTI_COMPLEMENT_PAIR_COUNT,
            "single": G2_SINGLE_PIVOT_PAIR_COUNT,
        }
        or sum(g2_counts.values()) != G2_FRONTIER_PAIR_COUNT
        or g2_novel
    ):
        raise O1C108PreparationError("derived resolution fixed point differs")
    try:
        closure = ThresholdNoGoodVault(
            chunk.identity,
            chunk.observed_variables,
            tuple(node.clause for node in nodes),
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("derived closure encoding differs") from exc
    overlay = closure
    _closure_inventory, closure_inventory_sha = _inventory(closure.clauses)
    if (
        closure.sha256 != DERIVED_CLOSURE_SHA256
        or closure.clause_count != DERIVED_CLOSURE_CLAUSE_COUNT
        or closure.literal_count != DERIVED_CLOSURE_LITERAL_COUNT
        or closure.serialized_bytes != DERIVED_CLOSURE_BYTES
        or closure.clause_aggregate_sha256 != DERIVED_CLOSURE_AGGREGATE_SHA256
        or closure_inventory_sha != DERIVED_CLOSURE_INVENTORY_SHA256
    ):
        raise O1C108PreparationError("derived closure seal differs")

    prior = _prior_logical_clauses(attic, artifacts)
    intermediate = (*prior, *chunk.clauses)
    _intermediate_inventory, intermediate_inventory_sha = _inventory(intermediate)
    logical_clauses = (*intermediate, *closure.clauses)
    _logical_inventory, logical_inventory_sha = _inventory(logical_clauses)
    try:
        logical = ThresholdNoGoodVault(
            chunk.identity, chunk.observed_variables, logical_clauses
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("logical registry encoding differs") from exc
    if (
        len(intermediate) != INTERMEDIATE_LOGICAL_CLAUSE_COUNT
        or intermediate_inventory_sha != INTERMEDIATE_LOGICAL_INVENTORY_SHA256
        or logical.clause_count != LOGICAL_KNOWN_CLAUSE_COUNT
        or logical.literal_count != LOGICAL_KNOWN_LITERAL_COUNT
        or logical.serialized_bytes != LOGICAL_KNOWN_SERIALIZED_BYTES
        or logical_inventory_sha != LOGICAL_KNOWN_INVENTORY_SHA256
        or logical.sha256 != LOGICAL_KNOWN_SHA256
        or logical.clause_aggregate_sha256 != LOGICAL_KNOWN_AGGREGATE_SHA256
    ):
        raise O1C108PreparationError("chronological logical registry seal differs")

    edge_inventory: list[dict[str, object]] = []
    proof_edges: list[dict[str, object]] = []
    for index, node in enumerate(nodes):
        recomputed = _o1c104._resolve_exact(
            node.left.clause, node.right.clause, pivot=node.pivot
        )
        if recomputed != node.clause:
            raise O1C108PreparationError("derived proof edge replay differs")
        if node.left.source_index is None or node.right.source_index is None:
            raise O1C108PreparationError("derived proof parent differs")
        edge_row = {
            "index": index,
            "left_source_index": node.left.source_index,
            "right_source_index": node.right.source_index,
            "pivot_variable": node.pivot,
            "resolvent_sha256": node.clause.sha256,
            "literal_count": node.clause.literal_count,
        }
        edge_inventory.append(edge_row)
        proof_edges.append(
            {
                "node": node.node,
                "generation": 1,
                "left_parent": node.left.describe(),
                "right_parent": node.right.describe(),
                **edge_row,
                "byte_exact_replay": True,
            }
        )
    edge_inventory_sha = sha256_bytes(canonical_json_bytes(edge_inventory))
    if edge_inventory_sha != DERIVED_EDGE_INVENTORY_SHA256:
        raise O1C108PreparationError("derived edge inventory seal differs")

    relations = strict_subsumption_relations(logical.clauses)
    full_relations = tuple(
        (relation.subsumer_index, relation.subsumed_index) for relation in relations
    )
    subsumed = {right for _left, right in full_relations}
    undominated = tuple(
        index for index in range(LOGICAL_KNOWN_CLAUSE_COUNT) if index not in subsumed
    )
    if (
        len(full_relations) != LOGICAL_SUBSUMPTION_RELATION_COUNT
        or len(undominated) != LOGICAL_UNDOMINATED_CLAUSE_COUNT
    ):
        raise O1C108PreparationError("logical relation census differs")
    receipt: dict[str, object] = {
        "schema": DERIVED_RECEIPT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_boundary": {
            "derivation_kind": "exact-propositional-resolution-fixed-point",
            "public_only": True,
            "native_solver_calls": 0,
            "native_preflight_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
            "derived_clauses_are_native_occurrences": False,
            "derived_clauses_enter_causal_attic": False,
            "observed": False,
            "emitted": False,
            "certified_logical_consequence": True,
        },
        "source": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "source_active_sha256": _o1c106.PAGE21_SHA256,
            "vault_telemetry_sha256": PARENT_VAULT_TELEMETRY_SHA256,
            "native_chunk_sha256": NEW_CHUNK_SHA256,
            "native_unique_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        },
        "resolution_rule": {
            "scope": "within-o1c107-native-emission-cohort",
            "pivot_rule": "exactly-one-opposite-signed-pivot-variable",
            "required_generation_1_pivot_variable": 32,
            "nonpivot_complements_allowed": False,
            "resolvent_rule": "union-of-parent-literals-minus-both-pivot-literals",
            "literal_order": "strict-ascending-absolute-variable",
            "tautological_resolvents_allowed": False,
            "closure_order": "generation-ascending;literal-count-ascending;clause-sha256-ascending",
        },
        "edge_inventory_sha256": edge_inventory_sha,
        "edge_inventory": edge_inventory,
        "edges": proof_edges,
        "fixed_point_audit": {
            "generation_1": {
                "pair_count": G1_PAIR_COUNT,
                **g1_counts,
                "unique_novel": len(nodes),
                "pivot_variables": [32],
            },
            "generation_2": {
                "native_to_generation_1_pair_count": len(native_refs)
                * len(derived_refs),
                "generation_1_internal_pair_count": len(derived_refs)
                * (len(derived_refs) - 1)
                // 2,
                "pair_count": G2_FRONTIER_PAIR_COUNT,
                **g2_counts,
                "unique_novel": 0,
                "fixed_point_reached": True,
            },
        },
        "closure": {
            **closure.describe(),
            "artifact": DERIVED_CLOSURE_NAME,
            "inventory_sha256": closure_inventory_sha,
            "generation_1_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "generation_2_clause_count": 0,
        },
        "proof_overlay": {
            **overlay.describe(),
            "artifact": DERIVED_OVERLAY_NAME,
            "inventory_sha256": closure_inventory_sha,
            "closure_indices": list(range(DERIVED_CLOSURE_CLAUSE_COUNT)),
            "all_153_clauses_preserved": True,
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
                "o1c106-logical-known-registry-byte-order",
                "new-o1c107-native-emission",
                "new-o1c108-derived-resolution",
            ],
            "prior_prefix": {
                "clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
                "inventory_sha256": _o1c106.LOGICAL_KNOWN_INVENTORY_SHA256,
            },
            "new_native": {
                "start": PRIOR_LOGICAL_CLAUSE_COUNT,
                "stop_exclusive": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                "clause_count": NEW_CHUNK_CLAUSE_COUNT,
                "inventory_sha256": NEW_CHUNK_INVENTORY_SHA256,
            },
            "new_derived": {
                "start": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                "stop_exclusive": LOGICAL_KNOWN_CLAUSE_COUNT,
                "clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                "inventory_sha256": DERIVED_CLOSURE_INVENTORY_SHA256,
            },
            "combined": {
                "clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
                "clause_sha256": [clause.sha256 for clause in logical.clauses],
                "inventory_sha256": logical_inventory_sha,
                "ordering": "byte-exact-o1c106-logical-prefix;new-native-first-emission-order;new-derived-proof-order",
                "encoding_only": logical.describe(),
                "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            },
        },
    }
    return _ResolutionArtifacts(
        closure=closure,
        overlay=overlay,
        receipt_payload=canonical_json_bytes(receipt),
        logical=logical,
        full_relations=full_relations,
        logical_undominated_indices=undominated,
    )


@dataclass(frozen=True)
class ComposedPage22Projection:
    lineage_ordinal: int
    vault: ThresholdNoGoodVault
    pure_emitted_candidate: ResidencyProjection
    selected_emitted_union_indices: tuple[int, ...]
    priority_selected_emitted_union_indices: tuple[int, ...]
    selected_inherited_derived_clauses: tuple[Mapping[str, object], ...]
    selected_o1c104_derived_clauses: tuple[Mapping[str, object], ...]
    selected_o1c108_derived_clauses: tuple[Mapping[str, object], ...]
    excluded_o1c108_derived_indices: tuple[int, ...]
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    document: Mapping[str, object]

    def __post_init__(self) -> None:
        encoding = _mapping(self.document.get("encoding_only"), "Page-22 encoding")
        if (
            self.lineage_ordinal != PAGE22_LINEAGE_ORDINAL
            or self.vault.clause_count != PAGE22_ACTIVE_LIMIT
            or (PAGE22_SHA256 and self.vault.sha256 != PAGE22_SHA256)
            or len(self.selected_emitted_union_indices) != PAGE22_EMITTED_COUNT
            or tuple(sorted(self.selected_emitted_union_indices))
            != self.selected_emitted_union_indices
            or len(self.priority_selected_emitted_union_indices) != PAGE22_EMITTED_COUNT
            or set(self.priority_selected_emitted_union_indices)
            != set(self.selected_emitted_union_indices)
            or self.priority_selected_emitted_union_indices
            != self.pure_emitted_candidate.selection_order[:PAGE22_EMITTED_COUNT]
            or len(self.selected_inherited_derived_clauses)
            != PAGE22_INHERITED_DERIVED_COUNT
            or len(self.selected_o1c104_derived_clauses) != PAGE22_O1C104_DERIVED_COUNT
            or len(self.selected_o1c108_derived_clauses) != PAGE22_O1C108_DERIVED_COUNT
            or self.excluded_o1c108_derived_indices != FAILED_NEW_DERIVED_INDICES
            or sum(self.category_counts.values()) != PAGE22_ACTIVE_LIMIT
            or encoding != self.vault.describe()
            or self.document.get("selected_emitted_union_indices")
            != list(self.selected_emitted_union_indices)
            or self.document.get("priority_selected_emitted_union_indices")
            != list(self.priority_selected_emitted_union_indices)
            or self.document.get("selected_inherited_derived_clauses")
            != list(self.selected_inherited_derived_clauses)
            or self.document.get("selected_o1c104_derived_clauses")
            != list(self.selected_o1c104_derived_clauses)
            or self.document.get("selected_o1c108_derived_clauses")
            != list(self.selected_o1c108_derived_clauses)
            or self.document.get("excluded_o1c108_derived_closure_indices")
            != list(self.excluded_o1c108_derived_indices)
            or self.document.get("category_counts") != dict(self.category_counts)
            or self.document.get("category_priority_order")
            != list(self.category_priority_order)
            or self.document.get("maximum_clause_count") != PAGE22_ACTIVE_LIMIT
            or self.document.get("selected_emitted_union_indices_sha256")
            != _index_list_sha256(self.selected_emitted_union_indices)
            or self.document.get("selector_confirmation")
            != "exact-prefix-of-causally-advanced-pure-emitted-selection-order"
        ):
            raise O1C108PreparationError("authoritative Page-22 projection differs")

    @property
    def selected_union_indices(self) -> tuple[int, ...]:
        return self.selected_emitted_union_indices

    @property
    def selection_order(self) -> tuple[int, ...]:
        return self.priority_selected_emitted_union_indices

    def describe(self) -> Mapping[str, object]:
        return self.document


@dataclass(frozen=True)
class ComposedPage22State:
    attic: CausalAttic
    current_projection: ComposedPage22Projection
    residency_payload: bytes
    activation_payload: bytes

    @property
    def active_limit(self) -> int:
        return PAGE22_ACTIVE_LIMIT

    @property
    def active_projection(self) -> ThresholdNoGoodVault:
        return self.current_projection.vault

    @property
    def used_active_sha256(self) -> tuple[str, ...]:
        activation = _canonical_document(self.activation_payload, "Page-22 activation")
        return tuple(
            cast(
                Sequence[str],
                _sequence(activation.get("used_active_sha256"), "Page-22 used inputs"),
            )
        )

    def describe(self) -> Mapping[str, object]:
        return _canonical_document(self.residency_payload, "Page-22 residency")

    def activation_ledger_document(self) -> Mapping[str, object]:
        return _canonical_document(self.activation_payload, "Page-22 activation")


@dataclass(frozen=True)
class PreparedCausalRolloverArtifacts:
    """Complete Page-22 publication held only in memory until validated."""

    state: ComposedPage22State
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
    category_counts: Mapping[str, int]
    category_priority_order: tuple[Mapping[str, object], ...]
    residency_payload: bytes
    activation_payload: bytes
    certification_payload: bytes


def _derived_row(
    *,
    namespace: str,
    closure_index: int,
    logical_index: int,
    clause: ThresholdNoGoodClause,
) -> dict[str, object]:
    return {
        "namespace": namespace,
        "closure_index": closure_index,
        "logical_index": logical_index,
        "clause_sha256": clause.sha256,
        "literal_count": clause.literal_count,
    }


def _legacy_certification_rows(
    artifacts: Mapping[str, bytes],
) -> tuple[dict[tuple[str, int], Mapping[str, object]], Mapping[str, object]]:
    audit = _canonical_document(
        artifacts[_o1c106.CERTIFICATION_AUDIT_NAME],
        "O1C-0106 certification audit",
    )
    rows = tuple(
        _sequence(
            audit.get("active_rows_in_serialization_order"),
            "O1C-0106 active certification rows",
        )
    )
    indexed: dict[tuple[str, int], Mapping[str, object]] = {}
    for value in rows:
        row = _mapping(value, "O1C-0106 certification row")
        namespace = row.get("namespace")
        closure_index = row.get("closure_index")
        if (
            isinstance(namespace, str)
            and isinstance(closure_index, int)
            and not isinstance(closure_index, bool)
        ):
            indexed[(namespace, closure_index)] = row
    if (
        audit.get("schema") != _o1c106.CERTIFICATION_AUDIT_SCHEMA
        or audit.get("passed") is not True
        or len(rows) != _o1c106.PAGE21_ACTIVE_LIMIT
        or any(
            _mapping(row, "legacy certification row").get("passed") is not True
            for row in rows
        )
    ):
        raise O1C108PreparationError("O1C-0106 certification prefix differs")
    return indexed, audit


def _compose_page22(
    *,
    root: Path,
    attic: CausalAttic,
    event_indices: tuple[int, ...],
    pinned: tuple[int, ...],
    inherited_debt: tuple[int, ...],
    published: _o1c107.PublishedPreparation,
    parent_residency: Mapping[str, object],
    parent_activation: Mapping[str, object],
    resolution: _ResolutionArtifacts,
) -> _Composition:
    parent_counts = _integer_tuple(
        parent_residency.get("activation_counts"), "parent emitted activation counts"
    )
    parent_lineages = _optional_integer_tuple(
        parent_residency.get("last_active_lineages"),
        "parent emitted last-active lineages",
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
        len(parent_counts) != _o1c104.ATTIC_UNION_CLAUSE_COUNT
        or len(parent_lineages) != _o1c104.ATTIC_UNION_CLAUSE_COUNT
        or not prior_used
        or prior_used[-1] != _o1c106.PAGE21_SHA256
        or len(set(prior_used)) != len(prior_used)
    ):
        raise O1C108PreparationError("parent causal residency counters differ")
    counts_before = parent_counts + (0,) * NEW_CHUNK_CLAUSE_COUNT
    lineages_before = parent_lineages + (None,) * NEW_CHUNK_CLAUSE_COUNT
    try:
        pure = _priority_projection(
            attic,
            lineage_ordinal=PAGE22_LINEAGE_ORDINAL,
            active_limit=PAGE22_ACTIVE_LIMIT,
            pinned_core_indices=pinned,
            inherited_debt_indices=inherited_debt,
            activation_counts=counts_before,
            last_active_lineages=lineages_before,
            fully_emitted_union_indices=event_indices,
            used_active_sha256=prior_used,
        )
    except CausalResidencyError as exc:
        raise O1C108PreparationError("Page-22 pure-emitted selector differs") from exc
    priority_selected = pure.selection_order[:PAGE22_EMITTED_COUNT]
    selected_emitted = tuple(sorted(priority_selected))
    if (
        pure.lineage_ordinal != PAGE22_LINEAGE_ORDINAL
        or pure.vault.clause_count != PAGE22_ACTIVE_LIMIT
        or pure.vault.sha256 != PAGE22_PURE_EMITTED_SHA256
        or pure.vault.literal_count != PAGE22_PURE_EMITTED_LITERAL_COUNT
        or pure.vault.serialized_bytes != PAGE22_PURE_EMITTED_SERIALIZED_BYTES
        or len(priority_selected) != PAGE22_EMITTED_COUNT
        or len(set(priority_selected)) != PAGE22_EMITTED_COUNT
        or selected_emitted != SELECTED_EMITTED_UNION_INDICES
        or _index_list_sha256(selected_emitted) != SELECTED_EMITTED_INDICES_SHA256
    ):
        raise O1C108PreparationError("Page-22 emitted selector prefix differs")

    observed = attic.union_vault.observed_variables
    try:
        inherited_closure = parse_threshold_no_good_vault(
            published.artifacts[INHERITED_DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        inherited_overlay = parse_threshold_no_good_vault(
            published.artifacts[INHERITED_DERIVED_OVERLAY_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        o1c104_closure = parse_threshold_no_good_vault(
            published.artifacts[O1C104_DERIVED_CLOSURE_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
        o1c104_overlay = parse_threshold_no_good_vault(
            published.artifacts[O1C104_DERIVED_OVERLAY_NAME],
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("preserved derived namespace differs") from exc
    if (
        inherited_overlay.clauses
        != tuple(
            inherited_closure.clauses[index] for index in _o1c102.DERIVED_OVERLAY_ORDER
        )
        or o1c104_overlay.clauses != o1c104_closure.clauses[:52]
    ):
        raise O1C108PreparationError("preserved derived overlay differs")

    inherited_rows = tuple(
        _derived_row(
            namespace="inherited-o1c102-derived-resolution",
            closure_index=index,
            logical_index=2_338 + index,
            clause=inherited_closure.clauses[index],
        )
        for index in _o1c102.DERIVED_OVERLAY_ORDER
    )
    o1c104_rows = tuple(
        _derived_row(
            namespace="new-o1c104-derived-resolution",
            closure_index=index,
            logical_index=2_608 + index,
            clause=o1c104_closure.clauses[index],
        )
        for index in _o1c106.PASSING_NEW_OVERLAY_INDICES
    )
    o1c108_rows = tuple(
        _derived_row(
            namespace="new-o1c108-derived-resolution",
            closure_index=index,
            logical_index=INTERMEDIATE_LOGICAL_CLAUSE_COUNT + index,
            clause=resolution.closure.clauses[index],
        )
        for index in PASSING_NEW_DERIVED_INDICES
    )

    try:
        page = ThresholdNoGoodVault(
            attic.union_vault.identity,
            observed,
            (
                *(attic.union_vault.clauses[index] for index in selected_emitted),
                *inherited_overlay.clauses,
                *(
                    o1c104_closure.clauses[index]
                    for index in _o1c106.PASSING_NEW_OVERLAY_INDICES
                ),
                *(
                    resolution.closure.clauses[index]
                    for index in PASSING_NEW_DERIVED_INDICES
                ),
            ),
        )
        roundtrip = parse_threshold_no_good_vault(
            page.serialized,
            observed_variables=observed,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("composed active Page-22 differs") from exc
    if (
        roundtrip != page
        or page.clause_count != PAGE22_ACTIVE_LIMIT
        or page.sha256 != PAGE22_SHA256
        or page.clause_aggregate_sha256 != PAGE22_CLAUSE_AGGREGATE_SHA256
        or page.literal_count != PAGE22_LITERAL_COUNT
        or page.serialized_bytes != PAGE22_SERIALIZED_BYTES
        or page.sha256 in set(prior_used) | {pure.vault.sha256}
    ):
        raise O1C108PreparationError("Page-22 frozen encoding differs")

    try:
        context = _o1c106._sealed_public_inputs(root)
    except _o1c106.O1C106PreparationError as exc:
        raise O1C108PreparationError("v8 public theorem inputs differ") from exc
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
            raise O1C108PreparationError(
                "active emitted v8 certification differs"
            ) from exc
        if not passed:
            raise O1C108PreparationError("active emitted v8 certification failed")
        emitted_audit.append(row)

    legacy_index, legacy_audit = _legacy_certification_rows(published.artifacts)
    legacy_rows: list[Mapping[str, object]] = []
    for row in (*inherited_rows, *o1c104_rows):
        key = (cast(str, row["namespace"]), cast(int, row["closure_index"]))
        audit_row = legacy_index.get(key)
        if (
            audit_row is None
            or audit_row.get("clause_sha256") != row["clause_sha256"]
            or audit_row.get("passed") is not True
            or audit_row.get("active") is not True
        ):
            raise O1C108PreparationError("legacy derived certification differs")
        legacy_rows.append(audit_row)

    new_audit: dict[int, Mapping[str, object]] = {}
    observed_passing: list[int] = []
    observed_failing: list[int] = []
    for index, clause in enumerate(resolution.closure.clauses):
        expected_active = index in PASSING_NEW_DERIVED_INDICES
        try:
            row, passed = _o1c106._certify_clause(
                clause,
                context=context,
                namespace="new-o1c108-derived-resolution",
                active=expected_active,
                closure_index=index,
                logical_index=INTERMEDIATE_LOGICAL_CLAUSE_COUNT + index,
            )
        except _o1c106.O1C106PreparationError as exc:
            raise O1C108PreparationError(
                "new derived v8 certification differs"
            ) from exc
        new_audit[index] = row
        (observed_passing if passed else observed_failing).append(index)
    passing_metrics = tuple(
        new_audit[index].get("metric") for index in observed_passing
    )
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in passing_metrics
    ):
        raise O1C108PreparationError("new derived certification metric differs")
    maximum_new = max(cast(float, value) for value in passing_metrics)
    if (
        tuple(observed_passing) != PASSING_NEW_DERIVED_INDICES
        or tuple(observed_failing) != FAILED_NEW_DERIVED_INDICES
        or any(
            new_audit[index].get("failure")
            != "joint-score-sieve-v8 grouped no-good certification differs"
            for index in FAILED_NEW_DERIVED_INDICES
        )
        or _o1c106._f64_hex(maximum_new)
        != _o1c106._f64_hex(PAGE22_MAXIMUM_CERTIFIED_UPPER_BOUND)
    ):
        raise O1C108PreparationError("new derived v8 classification differs")

    active_rows = (
        *emitted_audit,
        *legacy_rows,
        *(new_audit[index] for index in PASSING_NEW_DERIVED_INDICES),
    )
    active_metrics = tuple(row.get("metric") for row in active_rows)
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        for value in active_metrics
    ):
        raise O1C108PreparationError("Page-22 certification metric differs")
    maximum_active = max(cast(float, value) for value in active_metrics)
    if (
        len(active_rows) != PAGE22_ACTIVE_LIMIT
        or any(row.get("passed") is not True for row in active_rows)
        or not maximum_active < _o1c106.THRESHOLD
    ):
        raise O1C108PreparationError("Page-22 aggregate certification differs")
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
            "rule": _o1c106._v8.JOINT_SCORE_SIEVE_VAULT_INPUT_CERTIFICATION_RULE,
            "bound_rule": _o1c106._v8.JOINT_SCORE_SIEVE_BOUND_RULE,
            "threshold": _o1c106.THRESHOLD,
            "threshold_f64le_hex": _o1c106.THRESHOLD_F64LE_HEX,
            "source_and_input_seals": context.source_seals,
        },
        "inherited_certification": {
            "artifact": _o1c106.CERTIFICATION_AUDIT_NAME,
            "sha256": _o1c106.CERTIFICATION_AUDIT_SHA256,
            "byte_exact_and_unmodified": True,
            "active_legacy_derived_pass_count": len(legacy_rows),
        },
        "new_o1c108_resolution_candidates": {
            "candidate_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "certified_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "pass_count": PAGE22_O1C108_DERIVED_COUNT,
            "fail_count": len(FAILED_NEW_DERIVED_INDICES),
            "passing_closure_indices": list(PASSING_NEW_DERIVED_INDICES),
            "failing_closure_indices": list(FAILED_NEW_DERIVED_INDICES),
            "maximum_passing_upper_bound": maximum_new,
            "maximum_passing_upper_bound_f64le_hex": _o1c106._f64_hex(maximum_new),
            "rows_in_closure_order": [new_audit[index] for index in range(153)],
        },
        "page22": {
            "lineage_ordinal": PAGE22_LINEAGE_ORDINAL,
            "sha256": page.sha256,
            "clause_count": page.clause_count,
            "literal_count": page.literal_count,
            "serialized_bytes": page.serialized_bytes,
            "active_pass_count": len(active_rows),
            "active_fail_count": 0,
            "maximum_active_upper_bound": maximum_active,
            "maximum_active_upper_bound_f64le_hex": _o1c106._f64_hex(maximum_active),
            "maximum_strictly_below_threshold": maximum_active < _o1c106.THRESHOLD,
        },
        "categories": {
            "emitted": {
                "active": PAGE22_EMITTED_COUNT,
                "pass": PAGE22_EMITTED_COUNT,
                "fail": 0,
            },
            "legacy_derived": {
                "active": len(legacy_rows),
                "pass": len(legacy_rows),
                "fail": 0,
            },
            "new_derived": {
                "candidate": DERIVED_CLOSURE_CLAUSE_COUNT,
                "active": PAGE22_O1C108_DERIVED_COUNT,
                "pass": PAGE22_O1C108_DERIVED_COUNT,
                "excluded_fail": len(FAILED_NEW_DERIVED_INDICES),
            },
        },
        "active_rows_in_serialization_order": list(active_rows),
        "excluded_new_derived_failure_rows": [
            new_audit[index] for index in FAILED_NEW_DERIVED_INDICES
        ],
        "publication_gate": "all-153-new-derived-v8-certifications-and-all-246-active-certifications-finished-before-publication",
        "passed": True,
    }
    certification_payload = canonical_json_bytes(certification)

    selected_set = set(selected_emitted)
    emitted_categories = {
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
    category_counts = {
        "emitted_structural_root": len(emitted_categories["structural_root"]),
        "inherited_o1c102_derived_structural_root": len(inherited_rows),
        "o1c104_derived_structural_root": len(o1c104_rows),
        "o1c108_derived_structural_root": len(o1c108_rows),
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
        len(category_order) != PAGE22_ACTIVE_LIMIT
        or sum(category_counts.values()) != PAGE22_ACTIVE_LIMIT
    ):
        raise O1C108PreparationError("Page-22 category composition differs")

    selected_derived_logical = {
        *(2_338 + index for index in _o1c102.DERIVED_OVERLAY_ORDER),
        *(2_608 + index for index in _o1c106.PASSING_NEW_OVERLAY_INDICES),
        *(
            INTERMEDIATE_LOGICAL_CLAUSE_COUNT + index
            for index in PASSING_NEW_DERIVED_INDICES
        ),
    }
    selected_logical = {
        *(_emitted_to_logical_index(index) for index in selected_emitted),
        *selected_derived_logical,
    }
    activation_counts = tuple(
        count + (1 if index in selected_set else 0)
        for index, count in enumerate(counts_before)
    )
    last_active_lineages = tuple(
        PAGE22_LINEAGE_ORDINAL if index in selected_set else lineage
        for index, lineage in enumerate(lineages_before)
    )
    inherited_counts = _integer_tuple(
        parent_residency.get("inherited_derived_activation_counts"),
        "parent O1C-0102 derived counts",
    )
    inherited_lineages = _optional_integer_tuple(
        parent_residency.get("inherited_derived_last_active_lineages"),
        "parent O1C-0102 derived lineages",
    )
    o1c104_counts = _integer_tuple(
        parent_residency.get("new_derived_activation_counts"),
        "parent O1C-0104 derived counts",
    )
    o1c104_lineages = _optional_integer_tuple(
        parent_residency.get("new_derived_last_active_lineages"),
        "parent O1C-0104 derived lineages",
    )
    inherited_selected = set(_o1c102.DERIVED_OVERLAY_ORDER)
    o1c104_selected = set(_o1c106.PASSING_NEW_OVERLAY_INDICES)
    updated_inherited_counts = tuple(
        count + (1 if index in inherited_selected else 0)
        for index, count in enumerate(inherited_counts)
    )
    updated_inherited_lineages = tuple(
        PAGE22_LINEAGE_ORDINAL if index in inherited_selected else lineage
        for index, lineage in enumerate(inherited_lineages)
    )
    updated_o1c104_counts = tuple(
        count + (1 if index in o1c104_selected else 0)
        for index, count in enumerate(o1c104_counts)
    )
    updated_o1c104_lineages = tuple(
        PAGE22_LINEAGE_ORDINAL if index in o1c104_selected else lineage
        for index, lineage in enumerate(o1c104_lineages)
    )
    o1c108_counts = tuple(
        1 if index in set(PASSING_NEW_DERIVED_INDICES) else 0
        for index in range(DERIVED_CLOSURE_CLAUSE_COUNT)
    )
    o1c108_lineages: tuple[int | None, ...] = tuple(
        PAGE22_LINEAGE_ORDINAL if count else None for count in o1c108_counts
    )
    if (
        len(inherited_counts) != 5
        or len(inherited_lineages) != 5
        or len(o1c104_counts) != 84
        or len(o1c104_lineages) != 84
    ):
        raise O1C108PreparationError("parent derived activation namespace differs")

    def never_activated(logical_index: int) -> bool:
        if logical_index < 2_338:
            return activation_counts[logical_index] == 0
        if logical_index < 2_343:
            return updated_inherited_counts[logical_index - 2_338] == 0
        if logical_index < 2_608:
            return activation_counts[logical_index - 5] == 0
        if logical_index < PRIOR_LOGICAL_CLAUSE_COUNT:
            return updated_o1c104_counts[logical_index - 2_608] == 0
        if logical_index < INTERMEDIATE_LOGICAL_CLAUSE_COUNT:
            return (
                activation_counts[
                    _o1c104.ATTIC_UNION_CLAUSE_COUNT
                    + logical_index
                    - PRIOR_LOGICAL_CLAUSE_COUNT
                ]
                == 0
            )
        return o1c108_counts[logical_index - INTERMEDIATE_LOGICAL_CLAUSE_COUNT] == 0

    never_resident = tuple(
        index
        for index in resolution.logical_undominated_indices
        if index not in selected_logical and never_activated(index)
    )
    current_projection: dict[str, object] = {
        "encoding_only": page.describe(),
        "maximum_clause_count": PAGE22_ACTIVE_LIMIT,
        "category_counts": category_counts,
        "category_priority_order": category_order,
        "serialization_rule": "emitted-union-index-ascending;o1c102-overlay-order;o1c104-passing-closure-index-ascending;o1c108-passing-closure-index-ascending",
        "selector_confirmation": "exact-prefix-of-causally-advanced-pure-emitted-selection-order",
        "selected_emitted_union_indices": list(selected_emitted),
        "priority_selected_emitted_union_indices": list(priority_selected),
        "selected_emitted_union_indices_sha256": _index_list_sha256(selected_emitted),
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_o1c104_derived_clauses": list(o1c104_rows),
        "selected_o1c108_derived_clauses": list(o1c108_rows),
        "excluded_o1c108_derived_closure_indices": list(FAILED_NEW_DERIVED_INDICES),
    }
    current_entry = {
        "lineage_ordinal": PAGE22_LINEAGE_ORDINAL,
        "role": "type-safe-composed-causal-page-with-three-resolution-namespaces",
        "active_sha256": page.sha256,
        "selected_emitted_union_indices": list(selected_emitted),
        "selected_inherited_derived_clauses": list(inherited_rows),
        "selected_o1c104_derived_clauses": list(o1c104_rows),
        "selected_o1c108_derived_clauses": list(o1c108_rows),
        "certification_audit_artifact": CERTIFICATION_AUDIT_NAME,
        "certification_audit_sha256": sha256_bytes(certification_payload),
    }
    parent_activation_payload = published.artifacts[ACTIVATION_LEDGER_NAME]
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
            "lineage_ordinal": PARENT_LINEAGE_ORDINAL,
            "active_sha256": _o1c106.PAGE21_SHA256,
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
    residency_document: dict[str, object] = {
        "schema": COMPOSED_RESIDENCY_SCHEMA,
        "active_limit": PAGE22_ACTIVE_LIMIT,
        "lineage_ordinal": PAGE22_LINEAGE_ORDINAL,
        "namespace_contract": {
            "emitted": "causal-attic-v1-with-native-ClauseOccurrence",
            "inherited_o1c102_derived": "immutable-o1c102-resolution-sidecar-without-ClauseOccurrence",
            "inherited_o1c104_derived": "immutable-o1c104-resolution-sidecar-without-ClauseOccurrence",
            "new_o1c108_derived": "immutable-o1c108-resolution-sidecar-without-ClauseOccurrence",
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
            "reason": "193-certified-derived-clauses-finalized-before-selecting-exact-53-clause-prefix",
        },
        "logical_known_registry": {
            "registry_segment_order": [
                "o1c106-logical-known-registry-byte-order",
                "new-o1c107-native-emission",
                "new-o1c108-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "o1c106-logical-known-registry-byte-order",
                    "start": 0,
                    "stop_exclusive": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c107-native-emission",
                    "start": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "clause_count": NEW_CHUNK_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c108-derived-resolution",
                    "start": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": LOGICAL_KNOWN_CLAUSE_COUNT,
                    "clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                },
            ],
            "emitted_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "inherited_o1c102_derived_clause_count": 5,
            "inherited_o1c104_derived_clause_count": 84,
            "new_o1c108_derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_encoding_sha256": resolution.logical.sha256,
            "combined_literal_count": resolution.logical.literal_count,
            "combined_serialized_bytes": resolution.logical.serialized_bytes,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "strict_subsumption_pair_count": len(resolution.full_relations),
            "undominated_clause_count": len(resolution.logical_undominated_indices),
            "relation_artifact": DERIVED_RECEIPT_NAME,
            "byte_exact_inherited_sidecars_preserved": True,
            "all_153_new_proof_clauses_preserved": True,
        },
        "current_projection": current_projection,
        "activation_counts": list(activation_counts),
        "last_active_lineages": list(last_active_lineages),
        "inherited_derived_activation_counts": list(updated_inherited_counts),
        "inherited_derived_last_active_lineages": list(updated_inherited_lineages),
        "o1c104_derived_activation_counts": list(updated_o1c104_counts),
        "o1c104_derived_last_active_lineages": list(updated_o1c104_lineages),
        "o1c108_derived_activation_counts": list(o1c108_counts),
        "o1c108_derived_last_active_lineages": list(o1c108_lineages),
        "never_resident_undominated_logical_indices": list(never_resident),
        "certification_audit": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": sha256_bytes(certification_payload),
            "all_153_new_derived_clauses_certified": True,
            "new_derived_pass_count": PAGE22_O1C108_DERIVED_COUNT,
            "new_derived_fail_count": len(FAILED_NEW_DERIVED_INDICES),
            "all_active_clauses_certified": True,
            "active_pass_count": PAGE22_ACTIVE_LIMIT,
            "active_fail_count": 0,
        },
        "activation_ledger": activation_document,
    }
    residency_payload = canonical_json_bytes(residency_document)
    return _Composition(
        page=page,
        pure_emitted=pure,
        selected_emitted=selected_emitted,
        priority_selected_emitted=priority_selected,
        inherited_rows=inherited_rows,
        o1c104_rows=o1c104_rows,
        o1c108_rows=o1c108_rows,
        category_counts=category_counts,
        category_priority_order=tuple(category_order),
        residency_payload=residency_payload,
        activation_payload=activation_payload,
        certification_payload=certification_payload,
    )


def _emitted_to_logical_index(union_index: int) -> int:
    if not 0 <= union_index < ATTIC_UNION_CLAUSE_COUNT:
        raise O1C108PreparationError("emitted union index differs")
    if union_index < 2_338:
        return union_index
    if union_index < _o1c104.ATTIC_UNION_CLAUSE_COUNT:
        return union_index + 5
    return PRIOR_LOGICAL_CLAUSE_COUNT + union_index - _o1c104.ATTIC_UNION_CLAUSE_COUNT


def _authoritative_state(
    attic: CausalAttic, composition: _Composition
) -> ComposedPage22State:
    residency = _canonical_document(composition.residency_payload, "Page-22 residency")
    current = _mapping(residency.get("current_projection"), "Page-22 projection")
    projection = ComposedPage22Projection(
        lineage_ordinal=PAGE22_LINEAGE_ORDINAL,
        vault=composition.page,
        pure_emitted_candidate=composition.pure_emitted,
        selected_emitted_union_indices=composition.selected_emitted,
        priority_selected_emitted_union_indices=composition.priority_selected_emitted,
        selected_inherited_derived_clauses=composition.inherited_rows,
        selected_o1c104_derived_clauses=composition.o1c104_rows,
        selected_o1c108_derived_clauses=composition.o1c108_rows,
        excluded_o1c108_derived_indices=FAILED_NEW_DERIVED_INDICES,
        category_counts=composition.category_counts,
        category_priority_order=composition.category_priority_order,
        document=current,
    )
    state = ComposedPage22State(
        attic=attic,
        current_projection=projection,
        residency_payload=composition.residency_payload,
        activation_payload=composition.activation_payload,
    )
    if (
        state.describe() != residency
        or state.active_projection.clause_count != PAGE22_ACTIVE_LIMIT
        or state.used_active_sha256[-1] != state.active_projection.sha256
        or _o1c106.PAGE21_SHA256 not in state.used_active_sha256
        or composition.pure_emitted.vault.sha256 in state.used_active_sha256
    ):
        raise O1C108PreparationError("authoritative Page-22 state differs")
    return state


def _artifact_roles() -> Mapping[str, str]:
    return {
        NEW_CHUNK_NAME: "immutable-unique-lineage-34-native-evidence-chunk",
        ACTIVE_PROJECTION_NAME: ACTIVE_PROJECTION_ROLE,
        RESIDENCY_NAME: "type-safe-four-namespace-lineage35-residency-state",
        ACTIVATION_LEDGER_NAME: "composed-activation-ledger-with-burned-page21-prefix",
        OCCURRENCES_NAME: "append-only-pure-native-complete-occurrence-ledger",
        RELATIONS_NAME: "complete-pure-native-signed-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-o1c107-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "sealed-o1c107-priority-state-receipt",
        INHERITED_DERIVED_RECEIPT_NAME: "immutable-inherited-o1c102-resolution-proof",
        INHERITED_DERIVED_CLOSURE_NAME: "immutable-inherited-o1c102-five-clause-closure",
        INHERITED_DERIVED_OVERLAY_NAME: "immutable-inherited-o1c102-three-clause-overlay",
        O1C104_DERIVED_RECEIPT_NAME: "immutable-inherited-o1c104-84-clause-fixed-point-proof",
        O1C104_DERIVED_CLOSURE_NAME: "immutable-inherited-o1c104-84-clause-closure",
        O1C104_DERIVED_OVERLAY_NAME: "immutable-inherited-o1c104-52-clause-overlay",
        DERIVED_RECEIPT_NAME: "exact-public-o1c108-153-clause-fixed-point-resolution-proof",
        DERIVED_CLOSURE_NAME: "immutable-o1c108-153-clause-resolution-closure",
        DERIVED_OVERLAY_NAME: "immutable-o1c108-all-153-clause-proof-overlay",
        CERTIFICATION_AUDIT_NAME: "real-offline-v8-all-153-candidate-and-page22-certification-audit",
    }


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


def _build_manifest(
    *,
    state: ComposedPage22State,
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
    receipt_sha = sha256_bytes(resolution.receipt_payload)
    certification_sha = sha256_bytes(composition.certification_payload)
    roles = _artifact_roles()
    return {
        "schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": _zero_call(),
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page22_burned": False,
            "lineage35_burned": False,
            "page21_retry_or_replay_authorized": False,
            "lineage34_retry_or_replay_authorized": False,
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
            "classification": _o1c107.SCIENCE_CLAUSE,
            "stop_reason": "globally-novel-clause",
            "page21_sha256": _o1c106.PAGE21_SHA256,
            "page21_burned": True,
            "lineage34_burned": True,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "globally_novel_native_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "retry_or_replay_authorized": False,
            "science_gain": True,
        },
        "canonical_o1c106": {
            "bundle_manifest_sha256": O1C106_MANIFEST_SHA256,
            "bundle_manifest_serialized_bytes": O1C106_MANIFEST_BYTES,
            "bundle_file_count": O1C106_BUNDLE_FILE_COUNT,
            "capsule_initial_byte_equal": True,
            "page21_certification_audit_sha256": _o1c106.CERTIFICATION_AUDIT_SHA256,
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
                "o1c106-logical-known-registry-byte-order",
                "new-o1c107-native-emission",
                "new-o1c108-derived-resolution",
            ],
            "registry_segments": [
                {
                    "namespace": "o1c106-logical-known-registry-byte-order",
                    "start": 0,
                    "stop_exclusive": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "clause_count": PRIOR_LOGICAL_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c107-native-emission",
                    "start": PRIOR_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "clause_count": NEW_CHUNK_CLAUSE_COUNT,
                },
                {
                    "namespace": "new-o1c108-derived-resolution",
                    "start": INTERMEDIATE_LOGICAL_CLAUSE_COUNT,
                    "stop_exclusive": LOGICAL_KNOWN_CLAUSE_COUNT,
                    "clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                },
            ],
            "emitted_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "inherited_derived_clause_count": 89,
            "new_derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": resolution.logical.clause_count,
            "combined_encoding_sha256": resolution.logical.sha256,
            "combined_clause_aggregate_sha256": resolution.logical.clause_aggregate_sha256,
            "combined_literal_count": resolution.logical.literal_count,
            "combined_serialized_bytes": resolution.logical.serialized_bytes,
            "combined_inventory_sha256": LOGICAL_KNOWN_INVENTORY_SHA256,
            "strict_subsumption_pair_count": len(resolution.full_relations),
            "undominated_clause_count": len(resolution.logical_undominated_indices),
            "byte_exact_inherited_receipt_closure_overlay_sidecars_preserved": True,
            "all_153_new_proof_clauses_retained": True,
            "failing_clauses_retained_in_logical_sidecars": True,
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        },
        "derived_resolution_namespaces": {
            "inherited_o1c102": {
                "receipt_sha256": _o1c106.INHERITED_RECEIPT_SHA256,
                "closure_sha256": _o1c106.INHERITED_CLOSURE_SHA256,
                "closure_clause_count": 5,
                "overlay_sha256": _o1c106.INHERITED_OVERLAY_SHA256,
                "resident_clause_count": PAGE22_INHERITED_DERIVED_COUNT,
            },
            "inherited_o1c104": {
                "receipt_sha256": _o1c106.NEW_RECEIPT_SHA256,
                "closure_sha256": _o1c106.NEW_CLOSURE_SHA256,
                "closure_clause_count": 84,
                "overlay_sha256": _o1c106.NEW_OVERLAY_SHA256,
                "resident_clause_count": PAGE22_O1C104_DERIVED_COUNT,
                "resident_closure_indices": list(_o1c106.PASSING_NEW_OVERLAY_INDICES),
            },
            "new_o1c108": {
                "receipt_sha256": receipt_sha,
                "receipt_serialized_bytes": len(resolution.receipt_payload),
                "closure_sha256": DERIVED_CLOSURE_SHA256,
                "closure_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                "overlay_sha256": DERIVED_CLOSURE_SHA256,
                "overlay_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
                "resident_clause_count": PAGE22_O1C108_DERIVED_COUNT,
                "resident_closure_indices": list(PASSING_NEW_DERIVED_INDICES),
                "active_only_excluded_closure_indices": list(
                    FAILED_NEW_DERIVED_INDICES
                ),
                "all_clauses_preserved_in_proof_sidecars": True,
            },
            "combined_overlay_materialized": False,
            "causal_attic_occurrence_rows_added_by_derived": 0,
        },
        "certification": {
            "artifact": CERTIFICATION_AUDIT_NAME,
            "sha256": certification_sha,
            "serialized_bytes": len(composition.certification_payload),
            "real_v8_theorem": True,
            "new_candidate_certified_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "new_candidate_pass_count": PAGE22_O1C108_DERIVED_COUNT,
            "new_candidate_fail_count": len(FAILED_NEW_DERIVED_INDICES),
            "new_candidate_failing_indices": list(FAILED_NEW_DERIVED_INDICES),
            "all_active_clauses_certified_before_publication": True,
            "active_pass_count": PAGE22_ACTIVE_LIMIT,
            "active_fail_count": 0,
            "maximum_new_passing_upper_bound": PAGE22_MAXIMUM_CERTIFIED_UPPER_BOUND,
            "threshold": _o1c106.THRESHOLD,
            "strictly_below_threshold": True,
        },
        "page22": {
            "lineage_ordinal": PAGE22_LINEAGE_ORDINAL,
            "active_limit": PAGE22_ACTIVE_LIMIT,
            "active_sha256": active.sha256,
            "clause_aggregate_sha256": active.clause_aggregate_sha256,
            "clause_count": active.clause_count,
            "literal_count": active.literal_count,
            "serialized_bytes": active.serialized_bytes,
            "category_counts": dict(composition.category_counts),
            "headroom": headroom,
            "selected_emitted_clause_count": PAGE22_EMITTED_COUNT,
            "selected_inherited_o1c102_derived_clause_count": PAGE22_INHERITED_DERIVED_COUNT,
            "selected_inherited_o1c104_derived_clause_count": PAGE22_O1C104_DERIVED_COUNT,
            "selected_new_o1c108_derived_clause_count": PAGE22_O1C108_DERIVED_COUNT,
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
                "page22_input_clauses": active.clause_count,
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
            "semantic_role": "sealed-o1c107-live-continuation-bytes",
        },
        "artifacts": {
            name: _artifact_row(payload, roles[name])
            for name, payload in sorted(artifacts.items())
        },
    }


def prepare_o1c108_page22_type_safe_causal_rollover(
    *,
    o1c106_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    root = lab_root()
    bundle = _canonical_path(
        root / DEFAULT_O1C106_BUNDLE_RELATIVE
        if o1c106_bundle_dir is None
        else o1c106_bundle_dir,
        "O1C-0106 bundle",
        directory=True,
    )
    capsule = _canonical_path(
        root / DEFAULT_PARENT_CAPSULE_RELATIVE if capsule_dir is None else capsule_dir,
        "O1C-0107 capsule",
        directory=True,
    )
    result_path = _canonical_path(
        root / DEFAULT_PARENT_RESULT_RELATIVE
        if parent_result_path is None
        else parent_result_path,
        "O1C-0107 result",
        directory=False,
    )
    published, parent_residency, parent_activation = _validate_o1c106_bundle(bundle)
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
    composition = _compose_page22(
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
        _canonical_document(manifest_payload, "Page-22 manifest") != manifest
        or len(artifacts) != 19
        or _mapping(manifest.get("page22"), "manifest Page-22").get("headroom")
        != {
            "clauses": 266,
            "literals": O1C66_VAULT_CAPS.maximum_literals
            - composition.page.literal_count,
            "serialized_bytes": O1C66_VAULT_CAPS.maximum_serialized_bytes
            - composition.page.serialized_bytes,
        }
    ):
        raise O1C108PreparationError("Page-22 preparation manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=state,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c108_page22_type_safe_causal_rollover(
    *,
    o1c106_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    return prepare_o1c108_page22_type_safe_causal_rollover(
        o1c106_bundle_dir=o1c106_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _fixed_artifact_seals() -> Mapping[str, tuple[int, str]]:
    return {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE22_SERIALIZED_BYTES, PAGE22_SHA256),
        RESIDENCY_NAME: (RESIDENCY_BYTES, RESIDENCY_SHA256),
        ACTIVATION_LEDGER_NAME: (ACTIVATION_BYTES, ACTIVATION_SHA256),
        OCCURRENCES_NAME: (OCCURRENCE_BYTES, OCCURRENCE_SHA256),
        RELATIONS_NAME: (RELATION_BYTES, RELATION_SHA256),
        COMMON_CORE_AUDIT_NAME: (
            _o1c107.COMMON_CORE_AUDIT_BYTES,
            _o1c107.COMMON_CORE_AUDIT_SHA256,
        ),
        FINAL_BANK_NAME: (FINAL_BANK_BYTES, FINAL_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
        INHERITED_DERIVED_RECEIPT_NAME: (
            _o1c107.INHERITED_DERIVED_RECEIPT_BYTES,
            _o1c106.INHERITED_RECEIPT_SHA256,
        ),
        INHERITED_DERIVED_CLOSURE_NAME: (
            _o1c107.INHERITED_DERIVED_CLOSURE_BYTES,
            _o1c106.INHERITED_CLOSURE_SHA256,
        ),
        INHERITED_DERIVED_OVERLAY_NAME: (
            _o1c107.INHERITED_DERIVED_OVERLAY_BYTES,
            _o1c106.INHERITED_OVERLAY_SHA256,
        ),
        O1C104_DERIVED_RECEIPT_NAME: (
            _o1c107.DERIVED_RECEIPT_BYTES,
            _o1c106.NEW_RECEIPT_SHA256,
        ),
        O1C104_DERIVED_CLOSURE_NAME: (
            _o1c107.DERIVED_CLOSURE_BYTES,
            _o1c106.NEW_CLOSURE_SHA256,
        ),
        O1C104_DERIVED_OVERLAY_NAME: (
            _o1c107.DERIVED_OVERLAY_BYTES,
            _o1c106.NEW_OVERLAY_SHA256,
        ),
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


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts) or not isinstance(
        prepared.state, ComposedPage22State
    ):
        raise O1C108PreparationError("prepared Page-22 publication bundle differs")
    fixed = _fixed_artifact_seals()
    if set(prepared.artifacts) != set(fixed):
        raise O1C108PreparationError("prepared Page-22 artifact inventory differs")
    for name, (size, digest) in fixed.items():
        payload = prepared.artifacts.get(name)
        if (
            not isinstance(payload, bytes)
            or len(payload) != size
            or sha256_bytes(payload) != digest
        ):
            raise O1C108PreparationError(f"prepared Page-22 artifact {name} differs")

    manifest_payload = prepared.artifacts[PREPARATION_MANIFEST_NAME]
    manifest = _canonical_document(manifest_payload, "prepared Page-22 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-22 artifact rows")
    roles = _artifact_roles()
    if (
        manifest != prepared.manifest
        or manifest_payload != canonical_json_bytes(prepared.manifest)
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or set(rows) != set(fixed) - {PREPARATION_MANIFEST_NAME}
        or set(manifest)
        != {
            "schema",
            "attempt_id",
            "zero_call",
            "authorization",
            "parent_success",
            "canonical_o1c106",
            "causal_attic",
            "logical_known_registry",
            "derived_resolution_namespaces",
            "certification",
            "page22",
            "final_priority_bank",
            "artifacts",
        }
    ):
        raise O1C108PreparationError("prepared Page-22 manifest differs")
    for name, role in roles.items():
        if rows.get(name) != _artifact_row(prepared.artifacts[name], role):
            raise O1C108PreparationError("prepared Page-22 artifact row differs")

    zero_call = _mapping(manifest.get("zero_call"), "manifest zero-call boundary")
    authorization = _mapping(manifest.get("authorization"), "manifest authorization")
    parent = _mapping(manifest.get("parent_success"), "manifest parent")
    canonical_parent = _mapping(
        manifest.get("canonical_o1c106"), "manifest canonical parent bundle"
    )
    attic_row = _mapping(manifest.get("causal_attic"), "manifest causal attic")
    registry = _mapping(
        manifest.get("logical_known_registry"), "manifest logical registry"
    )
    namespaces = _mapping(
        manifest.get("derived_resolution_namespaces"),
        "manifest derived namespaces",
    )
    new_namespace = _mapping(
        namespaces.get("new_o1c108"), "manifest new derived namespace"
    )
    certification = _mapping(manifest.get("certification"), "manifest certification")
    page22 = _mapping(manifest.get("page22"), "manifest Page-22")
    capacity = _mapping(
        page22.get("native_capacity_proof"), "manifest Page-22 capacity"
    )
    bank = _mapping(manifest.get("final_priority_bank"), "manifest final bank")
    if (
        zero_call != _zero_call()
        or authorization
        != {
            "science_call_authorized": False,
            "intent_created": False,
            "page22_burned": False,
            "lineage35_burned": False,
            "page21_retry_or_replay_authorized": False,
            "lineage34_retry_or_replay_authorized": False,
            "historical_page_retry_or_replay_authorized": False,
        }
        or parent
        != {
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
            "classification": _o1c107.SCIENCE_CLAUSE,
            "stop_reason": "globally-novel-clause",
            "page21_sha256": _o1c106.PAGE21_SHA256,
            "page21_burned": True,
            "lineage34_burned": True,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "globally_novel_native_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "retry_or_replay_authorized": False,
            "science_gain": True,
        }
        or canonical_parent
        != {
            "bundle_manifest_sha256": O1C106_MANIFEST_SHA256,
            "bundle_manifest_serialized_bytes": O1C106_MANIFEST_BYTES,
            "bundle_file_count": O1C106_BUNDLE_FILE_COUNT,
            "capsule_initial_byte_equal": True,
            "page21_certification_audit_sha256": _o1c106.CERTIFICATION_AUDIT_SHA256,
        }
        or attic_row.get("chunk_count") != ATTIC_CHUNK_COUNT
        or attic_row.get("union_clause_count") != ATTIC_UNION_CLAUSE_COUNT
        or attic_row.get("occurrence_count") != ATTIC_OCCURRENCE_COUNT
        or attic_row.get("duplicate_occurrence_count")
        != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or attic_row.get("union_sha256") != ATTIC_UNION_SHA256
        or attic_row.get("strict_subsumption_pair_count")
        != ATTIC_SUBSUMPTION_RELATION_COUNT
        or registry.get("combined_clause_count") != LOGICAL_KNOWN_CLAUSE_COUNT
        or registry.get("combined_encoding_sha256") != LOGICAL_KNOWN_SHA256
        or registry.get("combined_clause_aggregate_sha256")
        != LOGICAL_KNOWN_AGGREGATE_SHA256
        or registry.get("combined_inventory_sha256") != LOGICAL_KNOWN_INVENTORY_SHA256
        or registry.get("combined_literal_count") != LOGICAL_KNOWN_LITERAL_COUNT
        or registry.get("combined_serialized_bytes") != LOGICAL_KNOWN_SERIALIZED_BYTES
        or registry.get("strict_subsumption_pair_count")
        != LOGICAL_SUBSUMPTION_RELATION_COUNT
        or registry.get("all_153_new_proof_clauses_retained") is not True
        or namespaces.get("combined_overlay_materialized") is not False
        or new_namespace.get("receipt_sha256") != DERIVED_RECEIPT_SHA256
        or new_namespace.get("closure_sha256") != DERIVED_CLOSURE_SHA256
        or new_namespace.get("overlay_sha256") != DERIVED_CLOSURE_SHA256
        or new_namespace.get("closure_clause_count") != DERIVED_CLOSURE_CLAUSE_COUNT
        or tuple(
            _integer_tuple(
                new_namespace.get("active_only_excluded_closure_indices"),
                "manifest excluded derived indices",
            )
        )
        != FAILED_NEW_DERIVED_INDICES
        or certification.get("sha256") != CERTIFICATION_AUDIT_SHA256
        or certification.get("new_candidate_certified_count")
        != DERIVED_CLOSURE_CLAUSE_COUNT
        or certification.get("new_candidate_pass_count") != PAGE22_O1C108_DERIVED_COUNT
        or certification.get("new_candidate_fail_count")
        != len(FAILED_NEW_DERIVED_INDICES)
        or certification.get("active_pass_count") != PAGE22_ACTIVE_LIMIT
        or certification.get("active_fail_count") != 0
        or page22.get("lineage_ordinal") != PAGE22_LINEAGE_ORDINAL
        or page22.get("active_limit") != PAGE22_ACTIVE_LIMIT
        or page22.get("active_sha256") != PAGE22_SHA256
        or page22.get("clause_aggregate_sha256") != PAGE22_CLAUSE_AGGREGATE_SHA256
        or page22.get("clause_count") != PAGE22_ACTIVE_LIMIT
        or page22.get("literal_count") != PAGE22_LITERAL_COUNT
        or page22.get("serialized_bytes") != PAGE22_SERIALIZED_BYTES
        or page22.get("selected_emitted_clause_count") != PAGE22_EMITTED_COUNT
        or page22.get("selected_inherited_o1c102_derived_clause_count")
        != PAGE22_INHERITED_DERIVED_COUNT
        or page22.get("selected_inherited_o1c104_derived_clause_count")
        != PAGE22_O1C104_DERIVED_COUNT
        or page22.get("selected_new_o1c108_derived_clause_count")
        != PAGE22_O1C108_DERIVED_COUNT
        or tuple(
            _integer_tuple(
                page22.get("selected_emitted_union_indices"),
                "manifest selected emitted indices",
            )
        )
        != SELECTED_EMITTED_UNION_INDICES
        or page22.get("selected_emitted_union_indices_sha256")
        != SELECTED_EMITTED_INDICES_SHA256
        or page22.get("pure_emitted_candidate_sha256") != PAGE22_PURE_EMITTED_SHA256
        or page22.get("pure_emitted_candidate_activated") is not False
        or capacity
        != {
            "maximum_clause_count": O1C66_VAULT_CAPS.maximum_clauses,
            "page22_input_clauses": PAGE22_ACTIVE_LIMIT,
            "maximum_additional_unique_clauses_before_capacity_terminal": 266,
            "required_clause_headroom": 266,
            "proved_sufficient": True,
            "literal_future_emission_safety_claimed": False,
            "serialized_byte_future_emission_safety_claimed": False,
        }
        or bank.get("sha256") != FINAL_BANK_SHA256
        or bank.get("receipt_sha256") != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C108PreparationError("prepared Page-22 manifest contract differs")

    state = cast(ComposedPage22State, prepared.state)
    try:
        active = parse_threshold_no_good_vault(
            prepared.artifacts[ACTIVE_PROJECTION_NAME],
            observed_variables=state.attic.union_vault.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        closure = parse_threshold_no_good_vault(
            prepared.artifacts[DERIVED_CLOSURE_NAME],
            observed_variables=state.attic.union_vault.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        overlay = parse_threshold_no_good_vault(
            prepared.artifacts[DERIVED_OVERLAY_NAME],
            observed_variables=state.attic.union_vault.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C108PreparationError("prepared Page-22 vault differs") from exc
    audit = _canonical_document(
        prepared.artifacts[CERTIFICATION_AUDIT_NAME],
        "prepared Page-22 certification audit",
    )
    candidates = _mapping(
        audit.get("new_o1c108_resolution_candidates"),
        "prepared Page-22 candidate audit",
    )
    receipt = _canonical_document(
        prepared.artifacts[DERIVED_RECEIPT_NAME],
        "prepared Page-22 derived receipt",
    )
    fixed_point = _mapping(receipt.get("fixed_point_audit"), "fixed-point audit")
    generation_1 = _mapping(fixed_point.get("generation_1"), "generation-1 audit")
    generation_2 = _mapping(fixed_point.get("generation_2"), "generation-2 audit")
    failing = tuple(closure.clauses[index] for index in FAILED_NEW_DERIVED_INDICES)
    active_serialized = {clause.serialized for clause in active.clauses}
    if (
        active != state.active_projection
        or active.sha256 != PAGE22_SHA256
        or closure != overlay
        or closure.sha256 != DERIVED_CLOSURE_SHA256
        or closure.clause_count != DERIVED_CLOSURE_CLAUSE_COUNT
        or any(clause.serialized in active_serialized for clause in failing)
        or any(
            closure.clauses[index].serialized not in active_serialized
            for index in PASSING_NEW_DERIVED_INDICES
        )
        or prepared.artifacts[RESIDENCY_NAME] != state.residency_payload
        or prepared.artifacts[ACTIVATION_LEDGER_NAME] != state.activation_payload
        or canonical_json_bytes(state.attic.occurrence_document())
        != prepared.artifacts[OCCURRENCES_NAME]
        or canonical_json_bytes(state.attic.relation_document())
        != prepared.artifacts[RELATIONS_NAME]
        or state.current_projection.selected_emitted_union_indices
        != SELECTED_EMITTED_UNION_INDICES
        or state.current_projection.priority_selected_emitted_union_indices
        != state.current_projection.pure_emitted_candidate.selection_order[
            :PAGE22_EMITTED_COUNT
        ]
        or state.current_projection.excluded_o1c108_derived_indices
        != FAILED_NEW_DERIVED_INDICES
        or state.current_projection.pure_emitted_candidate.vault.sha256
        != PAGE22_PURE_EMITTED_SHA256
        or state.current_projection.pure_emitted_candidate.vault.sha256
        in state.used_active_sha256
        or audit.get("schema") != CERTIFICATION_AUDIT_SCHEMA
        or audit.get("passed") is not True
        or candidates.get("certified_count") != DERIVED_CLOSURE_CLAUSE_COUNT
        or tuple(
            _integer_tuple(
                candidates.get("failing_closure_indices"),
                "audit failing derived indices",
            )
        )
        != FAILED_NEW_DERIVED_INDICES
        or generation_1.get("pair_count") != G1_PAIR_COUNT
        or generation_1.get("unique_novel") != DERIVED_CLOSURE_CLAUSE_COUNT
        or generation_1.get("pivot_variables") != [32]
        or generation_2.get("pair_count") != G2_FRONTIER_PAIR_COUNT
        or generation_2.get("unique_novel") != 0
        or generation_2.get("fixed_point_reached") is not True
        or receipt.get("edge_inventory_sha256") != DERIVED_EDGE_INVENTORY_SHA256
    ):
        raise O1C108PreparationError("prepared Page-22 publication state differs")


def write_prepared_o1c108_page22_type_safe_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts, output_dir: str | Path
) -> None:
    _validate_prepared_bundle_for_publication(prepared)
    output = Path(output_dir)
    if output.name in ("", ".", ".."):
        raise O1C108PreparationError("Page-22 output name differs")
    try:
        if output.is_symlink():
            raise O1C108PreparationError("Page-22 output is a symlink")
        if output.exists():
            raise O1C108PreparationError("Page-22 output already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        parent = output.parent.resolve(strict=True)
        if output.parent.absolute() != parent:
            raise O1C108PreparationError("Page-22 output parent is a symlink")
    except O1C108PreparationError:
        raise
    except OSError as exc:
        raise O1C108PreparationError("Page-22 output parent differs") from exc
    target = parent / output.name
    try:
        stage = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.", suffix=".tmp", dir=parent)
        )
    except OSError as exc:
        raise O1C108PreparationError("Page-22 publication stage failed") from exc
    try:
        for name, payload in prepared.artifacts.items():
            if Path(name).name != name:
                raise O1C108PreparationError("Page-22 artifact name differs")
            path = stage / name
            try:
                with path.open("xb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                raise O1C108PreparationError("Page-22 artifact write failed") from exc
        stage_fd = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        if target.exists() or target.is_symlink():
            raise O1C108PreparationError("Page-22 output already exists")
        os.rename(stage, target)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def prepare_and_write_o1c108_page22_type_safe_causal_rollover(
    *,
    output_dir: str | Path,
    o1c106_bundle_dir: str | Path | None = None,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    prepared = prepare_o1c108_page22_type_safe_causal_rollover(
        o1c106_bundle_dir=o1c106_bundle_dir,
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c108_page22_type_safe_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0108's zero-call type-safe Page-22 causal rollover"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("preflight", "prepare"):
        child = subparsers.add_parser(command)
        child.add_argument(
            "--o1c106-bundle",
            default=(root / DEFAULT_O1C106_BUNDLE_RELATIVE).as_posix(),
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
        prepared = prepare_o1c108_page22_type_safe_causal_rollover(
            o1c106_bundle_dir=args.o1c106_bundle,
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c108_page22_type_safe_causal_rollover(
                prepared, args.output_dir
            )
    except O1C108PreparationError as exc:
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
    "ComposedPage22Projection",
    "ComposedPage22State",
    "DEFAULT_O1C106_BUNDLE_RELATIVE",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "DERIVED_CLOSURE_NAME",
    "DERIVED_OVERLAY_NAME",
    "DERIVED_RECEIPT_NAME",
    "FAILED_NEW_DERIVED_INDICES",
    "FINAL_BANK_NAME",
    "LOGICAL_KNOWN_CLAUSE_COUNT",
    "LOGICAL_KNOWN_INVENTORY_SHA256",
    "LOGICAL_KNOWN_SHA256",
    "NEW_CHUNK_NAME",
    "O1C108PreparationError",
    "PAGE22_SHA256",
    "PASSING_NEW_DERIVED_INDICES",
    "PREPARATION_MANIFEST_NAME",
    "PRIORITY_RECEIPT_NAME",
    "SELECTED_EMITTED_UNION_INDICES",
    "main",
    "preflight_o1c108_page22_type_safe_causal_rollover",
    "prepare_and_write_o1c108_page22_type_safe_causal_rollover",
    "prepare_o1c108_page22_type_safe_causal_rollover",
    "write_prepared_o1c108_page22_type_safe_causal_rollover",
]
