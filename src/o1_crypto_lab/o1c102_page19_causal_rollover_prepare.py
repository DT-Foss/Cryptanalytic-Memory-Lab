"""Zero-call O1C-0102 Page-19 causal rollover preparation.

The only native evidence ingested here is O1C-0101's sealed stream of 264
fully emitted threshold no-goods.  Every emission is unique and globally
novel against the 2,074-clause parent attic.  Five additional clauses are
derived by exact public resolution from five of those emissions.  Derived
clauses never masquerade as native witness occurrences: the complete closure
and its three-clause undominated antichain are immutable proof sidecars.

The module regenerates O1C-0100 byte-for-byte, validates the complete parent
capsule, advances the native causal attic to lineage 32, and prepares an
atomic publication bundle.  It has no native, solver, target, truth-key,
model, or reveal interface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from . import o1c85_page10_transport_recovery_prepare as _publisher
from . import o1c100_page18_telemetry_recovery_prepare as _o1c100
from .causal_attic_v1 import (
    CausalAtticError,
    ParsedVaultTelemetry,
    canonical_json_bytes,
    parse_vault_telemetry,
    sha256_bytes,
    strict_subsumption_relations,
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
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0102"
PARENT_ATTEMPT_ID = "O1C-0101"
PREPARATION_SCHEMA = "o1-256-o1c102-page19-causal-rollover-preparation-v1"
DERIVED_RECEIPT_SCHEMA = "o1-256-o1c102-derived-resolution-closure-receipt-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260721_014426_614942_O1C-0101_apple8-parent-centered-continuation-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0101_APPLE8_PARENT_CENTERED_CONTINUATION_RESULT_20260721.json"
)

PARENT_CAPSULE_MANIFEST_SHA256 = (
    "9d5d97db2465359ea0f7f918c3d77948540a91fd2098c2eb6ecfd90806deecfc"
)
PARENT_CAPSULE_MANIFEST_BYTES = 4_463
PARENT_CAPSULE_ENTRY_COUNT = 43
PARENT_RESULT_SHA256 = (
    "4237dd1e8a8f95688a166daee082f3b15c3be4b1271e05d89ea12ccde7f115ae"
)
PARENT_RESULT_BYTES = 12_860
PARENT_EPISODE_SHA256 = (
    "fde0c0823827bef725b3a9636485d8162b2a48b2103662654811fffb00691d02"
)
PARENT_EPISODE_BYTES = 4_166
PARENT_INTENT_SHA256 = (
    "2849e4645b69a33e6c50e53eabb0127db562b58d12dff83e09b717095a69330e"
)
PARENT_INTENT_BYTES = 1_630
PARENT_INVOCATION_SHA256 = (
    "8aee7081ab0959e111c8ed9b03eddf9494012d05827f685887c16a82a6a780df"
)
PARENT_INVOCATION_BYTES = 3_590
PARENT_VAULT_TELEMETRY_SHA256 = (
    "9c2e78a52d8131a2c6bb3e86e547a5aaf0e393f7ef4500fc408f2151f4358f85"
)
PARENT_VAULT_TELEMETRY_BYTES = 5_313_673
PARENT_CLASSIFICATION = "PARENT_CENTERED_CONTINUATION_NOVEL_CLAUSE_GAIN"
PARENT_STOP_REASON = "globally-novel-clause"
PARENT_CONFIG_SHA256 = (
    "f341b50b86f143c9350da6615ddfcd842860f203ef32fc6a5e0494bee49ff2a2"
)
PARENT_REQUESTED_CONFLICTS = 128
PARENT_ACTUAL_CONFLICTS = 36
PARENT_INITIAL_ARTIFACT_COUNT = 10

GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT = 2_074
FULLY_EMITTED_OCCURRENCE_COUNT = 264
FULLY_EMITTED_LITERAL_COUNT = 766_686
FULLY_EMITTED_AGGREGATE_SHA256 = (
    "07add4a7a99bf4a65b60bb731360de99919f635412a2c2abd80e3f64b24b5d10"
)

NEW_CHUNK_SHA256 = "ecd202118dc31dab92b388a3da5f842301e0de020aad4d7b9ef0a123fde2096c"
NEW_CHUNK_CLAUSE_COUNT = 264
NEW_CHUNK_LITERAL_COUNT = 766_686
NEW_CHUNK_SERIALIZED_BYTES = 3_067_991
NEW_CHUNK_CLAUSE_AGGREGATE_SHA256 = FULLY_EMITTED_AGGREGATE_SHA256

ATTIC_CHUNK_COUNT = 20
ATTIC_UNION_SHA256 = "e945cdd02af6c3b247a0b6876a50ee944d16b29d8390a1d20de024b9bb01d9fa"
ATTIC_UNION_CLAUSE_COUNT = 2_338
ATTIC_UNION_LITERAL_COUNT = 6_602_366
ATTIC_UNION_SERIALIZED_BYTES = 26_419_007
ATTIC_UNION_CLAUSE_AGGREGATE_SHA256 = (
    "7c2683b3704c84745a3f46063bfaadff1afcf3c9aa0ddbffb55d625b65f358f7"
)
ATTIC_OCCURRENCE_COUNT = 2_347
ATTIC_DUPLICATE_OCCURRENCE_COUNT = 9
ATTIC_SUBSUMPTION_RELATION_COUNT = 14
ATTIC_UNDOMINATED_CLAUSE_COUNT = 2_327
OCCURRENCE_DOCUMENT_SHA256 = (
    "c2d8eaf751fd226d29b73628af4cc02503f4d06676c616b26c55c9b068998eaf"
)
OCCURRENCE_DOCUMENT_BYTES = 834_669
RELATION_DOCUMENT_SHA256 = (
    "deb857ff4d76809a2fe6a1e7da27fff3ba328307f9765201e83f77185c957a8e"
)
RELATION_DOCUMENT_BYTES = 15_002

PAGE19_BASE_SHA256 = "751547f3a4a3cde1268e993f04b9aa6c3fa77f47fe4eda1cc8c3815e5f06043c"
PAGE18_CLAUSE_AGGREGATE_SHA256 = (
    "c75c85a17f732e4a19a0d7694b756ba067f5e5856f6581d5c0e94f2691e58026"
)
PAGE19_BASE_CLAUSE_COUNT = 248
PAGE19_BASE_LITERAL_COUNT = 702_347
PAGE19_BASE_SERIALIZED_BYTES = 2_810_571
PAGE19_BASE_CLAUSE_AGGREGATE_SHA256 = (
    "2176a43d5a9cdf6133a146ed3e99e70096f5f53495bc980178e81230b5b0950d"
)
PAGE19_ACTIVE_LIMIT = 248
PAGE19_LINEAGE_ORDINAL = 32
PAGE19_BASE_CATEGORY_COUNTS = {
    "structural_root": 9,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 196,
    "hot_event": 0,
    "recycled": 0,
}
PAGE19_BASE_HEADROOM = {
    "clauses": 264,
    "literals": 897_653,
    "serialized_bytes": 5_578_037,
}
PAGE19_BASE_RESIDENCY_DOCUMENT_SHA256 = (
    "1ab6d14645a2bfe00752b6e4d5b6cba2a5b1d300a5574e59cf44fceed438c9a3"
)
PAGE19_BASE_RESIDENCY_DOCUMENT_BYTES = 64_722
PAGE19_BASE_ACTIVATION_DOCUMENT_SHA256 = (
    "ab5354d87c4fda7f0e3d1c0b0171c5edc33dfa32bdf80a941df507974b40843d"
)
PAGE19_BASE_ACTIVATION_DOCUMENT_BYTES = 40_450
PAGE19_BASE_ACTIVATION_COUNT = 20
PAGE19_BASE_SELECTED_INDICES_SHA256 = (
    "6b850b472dea427c0af211c053b098f9ab2ab7db4abc3e49fc2976bf339c5b67"
)
PAGE19_BASE_SELECTION_ORDER_SHA256 = (
    "48c77a6d33f5125e0c793206d1971d0e9eb61192ef7e5395798fbd6d55a19c79"
)

PAGE19_SHA256 = "3857519d4a384333d576ec1fe11939ef2a46d82d9ce7c585bc989792c0ceb3e6"
PAGE19_CLAUSE_COUNT = 248
PAGE19_LITERAL_COUNT = 702_343
PAGE19_SERIALIZED_BYTES = 2_810_555
PAGE19_CLAUSE_AGGREGATE_SHA256 = (
    "fb8452c0e4808d171d6631adcc8587c00fdb23f1819a6c47733d5d64782b6b2a"
)
PAGE19_CATEGORY_COUNTS = {
    "structural_root": 12,
    "pinned_core": 43,
    "inherited_debt": 0,
    "new_debt": 193,
    "hot_event": 0,
    "recycled": 0,
}
PAGE19_HEADROOM = {
    "clauses": 264,
    "literals": 897_657,
    "serialized_bytes": 5_578_053,
}
DISPLACED_EMITTED_UNION_INDICES = (2_079, 2_081, 2_302)
DISPLACED_EMITTED_CLAUSE_SHA256 = (
    "11cb7f4165091c9d2700335ad2ab0a29058d57f8bf3c5318707bea021d2dea9a",
    "a60df58678737e3b3b798066ed07123adc024fda2cf867e565fd6707dc806999",
    "bef420374f5b68791b5aff0fc86fc436e3d2388ee7f4e9e5c30a32c9f3a4761c",
)
DISPLACED_EMITTED_LITERAL_COUNTS = (2_861, 2_916, 2_916)
COMPOSED_RESIDENCY_SCHEMA = "o1-score-threshold-composed-residency-v1"
COMPOSED_ACTIVATION_SCHEMA = "o1-score-threshold-composed-activation-ledger-v1"
LOGICAL_KNOWN_CLAUSE_COUNT = 2_343
LOGICAL_KNOWN_LITERAL_COUNT = 6_616_885
LOGICAL_KNOWN_SERIALIZED_BYTES = 26_477_103
LOGICAL_SUBSUMPTION_RELATION_COUNT = 21
LOGICAL_UNDOMINATED_CLAUSE_COUNT = 2_327

# Frozen after one complete deterministic construction.
LOGICAL_KNOWN_SHA256 = (
    "4a3cfe07e1e5057da39af8b36dc8099e546aa824a4a0b184f9e4b3b51ccaadf6"
)
EMITTED_KNOWN_INVENTORY_SHA256 = (
    "93eda1a1fdc53315f37b67d151af570dac6813efb1a9763053b67dd5ad35fe21"
)
DERIVED_KNOWN_INVENTORY_SHA256 = (
    "efcdec39c1adea417a77e3b2776ea077ed78aeeb4b6275b08d12b0f940960794"
)
COMBINED_KNOWN_INVENTORY_SHA256 = (
    "6e3276c49c71def1143f49ef2c2e399a89a474c8e0f2075d2608c105186f4ef2"
)
PAGE19_RESIDENCY_DOCUMENT_SHA256 = (
    "d6c00aa3ad8d40bb9a8b68153d3d83483cb7d4ff134eb6d8f0dcf6f3efebeb1a"
)
PAGE19_RESIDENCY_DOCUMENT_BYTES = 168_153
PAGE19_ACTIVATION_DOCUMENT_SHA256 = (
    "473e2299cd2f971658fdb0fe4e12a65e70cce4c88edcd4cc0e635bea10812a1f"
)
PAGE19_ACTIVATION_DOCUMENT_BYTES = 41_241

NEW_MISSING_UNION_INDICES = (
    2078,
    2085,
    2089,
    2091,
    2096,
    2097,
    2099,
    2101,
    2102,
    2103,
    2105,
    2106,
    2119,
    2123,
    2124,
    2128,
    2142,
    2147,
    2149,
    2154,
    2163,
    2165,
    2174,
    2175,
    2176,
    2178,
    2179,
    2189,
    2208,
    2209,
    2212,
    2217,
    2222,
    2229,
    2230,
    2232,
    2241,
    2243,
    2244,
    2246,
    2247,
    2249,
    2252,
    2260,
    2262,
    2263,
    2264,
    2265,
    2266,
    2271,
    2272,
    2274,
    2275,
    2279,
    2285,
    2289,
    2293,
    2296,
    2297,
    2300,
    2303,
    2305,
    2307,
    2312,
    2313,
    2322,
    2323,
    2336,
)
NEW_RESIDENT_UNION_INDICES = tuple(
    index
    for index in range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    if index not in frozenset(NEW_MISSING_UNION_INDICES)
)

SOURCE_ROWS = (
    {
        "source_index": 4,
        "clause_sha256": "fc5e264f8a70ad0c736d1c7acbdb8937d7458af037c730aa3f9bef757173539a",
        "literal_count": 2_916,
        "witness_sha256": "3f63f8dd972a9c6bdc3c0f4d0c05675524a4258eafb2ff38a81f9b141592df41",
        "witness_score_f64le_hex": "04b6e4c649e82a40",
    },
    {
        "source_index": 5,
        "clause_sha256": "11cb7f4165091c9d2700335ad2ab0a29058d57f8bf3c5318707bea021d2dea9a",
        "literal_count": 2_861,
        "witness_sha256": "c2fcc34975480f68d1c3d01c80f85be23421c341286ce379f3c28c42fdfbe559",
        "witness_score_f64le_hex": "6ab91db3cd302d40",
    },
    {
        "source_index": 6,
        "clause_sha256": "6fb28d0d7ba13b271dce9b33635fe5b0a425682cff48467908976c23d6f86d01",
        "literal_count": 2_859,
        "witness_sha256": "e3159197b461143f45aee77f54d49422d19221d6ef1725b118466bab4f485001",
        "witness_score_f64le_hex": "25c9a0c3e0342d40",
    },
    {
        "source_index": 7,
        "clause_sha256": "a60df58678737e3b3b798066ed07123adc024fda2cf867e565fd6707dc806999",
        "literal_count": 2_916,
        "witness_sha256": "48c0f69052fcfae62fef66f98be360761d7ec042a832aa1c2e575406dc67f966",
        "witness_score_f64le_hex": "c23c0a434ee42a40",
    },
    {
        "source_index": 8,
        "clause_sha256": "3a4cf346922c769ab46018004db24f8243ab6971fe932db1b9d4cbaa7b3fe5b1",
        "literal_count": 2_861,
        "witness_sha256": "2ab97437003a06b544a04b04794edad4dfef1b737baab98e77ee50542e581b84",
        "witness_score_f64le_hex": "2840432fd22c2d40",
    },
)

DERIVED_CLAUSE_SHA256 = (
    "ec0d175725601e2672e234376d948a23f35eef9b35af0febcfc92586e4909d69",
    "833f35049d66a765186c650ff9d3a0494bfce94433d4f011fd53150206343ada",
    "50dd1476f1ef0291417357c2881eb203f3d505054a927d6bce5859ea1794c9e9",
    "0b92dd541f51356044c0da449c11e1521786a282b8971a033b5b683a4c722552",
    "5e385e56f06d85cd763f3c257bffadebfbb2695f60e7e0b7be1852d8ae761c91",
)
DERIVED_CLAUSE_LITERAL_COUNTS = (2_915, 2_915, 2_860, 2_915, 2_914)
DERIVED_CLOSURE_SHA256 = (
    "74cc718bd1140c6295ea3d4bd9cb295e5a1f94669c7935204ea5176355640050"
)
DERIVED_CLOSURE_BYTES = 58_287
DERIVED_CLOSURE_CLAUSE_COUNT = 5
DERIVED_CLOSURE_LITERAL_COUNT = 14_519
DERIVED_CLOSURE_AGGREGATE_SHA256 = (
    "35e9efd97a8e782976a61521cc4d9e2a8300557d0f1c58f0331c0f4be7585f7a"
)
DERIVED_OVERLAY_ORDER = (2, 4, 3)
DERIVED_OVERLAY_SHA256 = (
    "291cab4b923268393d56e3c3b16d33c34bc933c0d2d13d5baf9e0dcfe5bfe0e9"
)
DERIVED_OVERLAY_BYTES = 34_959
DERIVED_OVERLAY_CLAUSE_COUNT = 3
DERIVED_OVERLAY_LITERAL_COUNT = 8_689
DERIVED_OVERLAY_AGGREGATE_SHA256 = (
    "e2c4f983bbb4e96a88e8b9a4923c193d694536caa6a169045350622e8bddc437"
)

FINAL_BANK_SHA256 = "a8e137b1546076f32902acbb97163ae419ad45e61c4b311a3d8c9c941ba58f01"
FINAL_BANK_BYTES = 24_576
PRIORITY_RECEIPT_SHA256 = (
    "30d25ec825241ab79fae1f704e698fe5d14b535bdb9121a3d6ce891bd3fb1f36"
)
PRIORITY_RECEIPT_BYTES = 52_013
CONTINUATION_CANDIDATE_ORDER_SHA256 = (
    "8198e3662f8ea2647c85982585b51ef46154007397bdc67533615778d8741a44"
)

NEW_CHUNK_NAME = "lineage-31-native-emissions.vault"
ACTIVE_PROJECTION_NAME = "page-19-active.bin"
RESIDENCY_NAME = _o1c100.RESIDENCY_NAME
ACTIVATION_LEDGER_NAME = _o1c100.ACTIVATION_LEDGER_NAME
OCCURRENCES_NAME = _o1c100.OCCURRENCES_NAME
RELATIONS_NAME = _o1c100.RELATIONS_NAME
COMMON_CORE_AUDIT_NAME = _o1c100.COMMON_CORE_AUDIT_NAME
FINAL_BANK_NAME = _o1c100.FINAL_BANK_NAME
PRIORITY_RECEIPT_NAME = "o1c101-priority-state-receipt.json"
DERIVED_RECEIPT_NAME = "o1c102-derived-resolution-closure-receipt.json"
DERIVED_CLOSURE_NAME = "o1c102-derived-resolution-closure.vault"
DERIVED_OVERLAY_NAME = "o1c102-derived-resolution-overlay.vault"
PREPARATION_MANIFEST_NAME = "causal-rollover-preparation-manifest.json"

# Frozen after the active-page overlay contract is constructed below.
PREPARATION_MANIFEST_SHA256 = (
    "9e3e2dd88c5688b88ff2f7673f161577f3b5cafc36bf2c060cc4388d5dfdaad0"
)
PREPARATION_MANIFEST_BYTES = 8_012
DERIVED_RECEIPT_SHA256 = (
    "3eade7d3e6e195b4b5aeac098969d85a93fae34ac1246f6868ddd6f7afdb345c"
)
DERIVED_RECEIPT_BYTES = 326_232

PreparedCausalRolloverArtifacts = _o1c100.PreparedCausalRolloverArtifacts


class O1C102PreparationError(RuntimeError):
    """An O1C-0101 seal or deterministic Page-19 invariant differs."""


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C102PreparationError(f"{label} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C102PreparationError(f"{label} differs")
    return cast(Sequence[object], value)


def _canonical_path(value: str | Path, label: str, *, directory: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise O1C102PreparationError(f"{label} path is not canonical")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise O1C102PreparationError(f"{label} is unreadable") from exc
    expected = (
        stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or not expected or path != resolved:
        raise O1C102PreparationError(f"{label} path is not canonical")
    return path


def _canonical_document(payload: bytes, label: str) -> Mapping[str, object]:
    try:
        value = _mapping(json.loads(payload), label)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C102PreparationError(f"{label} differs") from exc
    if canonical_json_bytes(value) != payload:
        raise O1C102PreparationError(f"{label} is not canonical JSON")
    return value


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C102PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C102PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C102PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C102PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    manifest_path = capsule / "artifacts.sha256"
    try:
        metadata = manifest_path.lstat()
        payload = manifest_path.read_bytes()
    except OSError as exc:
        raise O1C102PreparationError("parent capsule manifest is unreadable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or len(payload) != PARENT_CAPSULE_MANIFEST_BYTES
        or sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256
    ):
        raise O1C102PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C102PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C102PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C102PreparationError("parent capsule inventory or digest differs")
    required = {
        "result.json": PARENT_RESULT_SHA256,
        "episodes/00/episode.json": PARENT_EPISODE_SHA256,
        "episodes/00/intent.json": PARENT_INTENT_SHA256,
        "invocation.json": PARENT_INVOCATION_SHA256,
        "episodes/00/vault.json": PARENT_VAULT_TELEMETRY_SHA256,
        "episodes/00/final-parent-centered-priority-bank.bin": FINAL_BANK_SHA256,
        "episodes/00/priority-state.json": PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c100.PREPARATION_MANIFEST_NAME}": _o1c100.PREPARATION_MANIFEST_SHA256,
        f"initial/{_o1c100.ACTIVE_PROJECTION_NAME}": _o1c100.PAGE18_SHA256,
        f"initial/{_o1c100.FINAL_BANK_NAME}": _o1c100.CONTINUATION_BANK_SHA256,
        f"initial/{_o1c100.PRIORITY_RECEIPT_NAME}": _o1c100.PRIORITY_RECEIPT_SHA256,
        f"initial/{_o1c100.FAILURE_RECEIPT_NAME}": _o1c100.PARENT_FAILURE_SHA256,
    }
    if any(entries.get(name) != digest for name, digest in required.items()):
        raise O1C102PreparationError("parent capsule required seal differs")
    if "episodes/00/terminal-failure.json" in entries:
        raise O1C102PreparationError("parent successful episode boundary differs")
    return entries


def _validate_parent_result(capsule: Path, result_path: Path) -> Mapping[str, object]:
    try:
        payload = result_path.read_bytes()
        capsule_payload = (capsule / "result.json").read_bytes()
        episode_payload = (capsule / "episodes/00/episode.json").read_bytes()
        intent_payload = (capsule / "episodes/00/intent.json").read_bytes()
        invocation_payload = (capsule / "invocation.json").read_bytes()
    except OSError as exc:
        raise O1C102PreparationError("parent result boundary is unreadable") from exc
    if (
        len(payload) != PARENT_RESULT_BYTES
        or sha256_bytes(payload) != PARENT_RESULT_SHA256
        or capsule_payload != payload
        or len(episode_payload) != PARENT_EPISODE_BYTES
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or len(intent_payload) != PARENT_INTENT_BYTES
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
        or len(invocation_payload) != PARENT_INVOCATION_BYTES
        or sha256_bytes(invocation_payload) != PARENT_INVOCATION_SHA256
    ):
        raise O1C102PreparationError("parent result binding differs")

    result = _canonical_document(payload, "parent result")
    episode_document = _canonical_document(episode_payload, "parent episode")
    intent = _canonical_document(intent_payload, "parent intent")
    invocation = _canonical_document(invocation_payload, "parent invocation")
    episodes = _sequence(result.get("episodes"), "parent episodes")
    if len(episodes) != 1:
        raise O1C102PreparationError("parent completed-call contract differs")
    episode = _mapping(episodes[0], "parent episode")
    claim = _mapping(result.get("claim_boundary"), "parent claim boundary")
    science = _mapping(episode.get("science"), "parent science")
    final_bank = _mapping(episode.get("final_priority_bank"), "parent final bank")
    archived = _mapping(episode.get("archived_native_components"), "parent artifacts")
    expected_science = {
        "active_page18_new_clauses": 264,
        "actual_certified_prunes": 0,
        "attacker_valid_domain_reduction": 0,
        "attacker_valid_entropy_gain_bits": 0.0,
        "certified_closure": False,
        "certified_model_or_key": False,
        "failure_first_action_alone_is_science_gain": False,
        "fully_emitted_clauses": 264,
        "globally_novel_clauses": 264,
        "nonclaim_digest_alone_is_science_gain": False,
        "priority_or_differential_alone_is_science_gain": False,
        "science_gain": True,
        "threshold_prunes": 264,
        "unconfirmed_crossing_alone_is_science_gain": False,
    }
    replay_fields = (
        "page10_replay_authorized",
        "page11_replay_authorized",
        "page12_replay_authorized",
        "page13_replay_authorized",
        "page14_replay_authorized",
        "page15_retry_or_replay_authorized",
        "page16_retry_or_replay_authorized",
        "page17_retry_or_replay_authorized",
        "page9_retry_or_replay_authorized",
    )
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
        or claim.get("config_sha256") != PARENT_CONFIG_SHA256
        or claim.get("global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or claim.get("page18_sha256") != _o1c100.PAGE18_SHA256
        or claim.get("page18_burned") is not True
        or claim.get("lineage31_only") is not True
        or claim.get("input_continuation_bank_sha256")
        != _o1c100.CONTINUATION_BANK_SHA256
        or claim.get("priority_state_receipt_sha256") != _o1c100.PRIORITY_RECEIPT_SHA256
        or claim.get("rollover_manifest_sha256") != _o1c100.PREPARATION_MANIFEST_SHA256
        or claim.get("terminal_failure_receipt_sha256") != _o1c100.PARENT_FAILURE_SHA256
        or claim.get("retry_or_replay") is not False
        or any(claim.get(field) is not False for field in replay_fields)
        or claim.get("target_bytes_read") is not False
        or claim.get("truth_key_bytes_read") is not False
        or claim.get("fresh_reveal_calls") != 0
        or claim.get("refits") != 0
        or episode.get("schema")
        != "o1-256-apple8-parent-centered-continuation-episode-v1"
        or episode.get("classification") != PARENT_CLASSIFICATION
        or episode.get("completed") is not True
        or episode.get("status") != 0
        or episode.get("lineage_call_ordinal") != 31
        or episode.get("local_episode_ordinal") != 0
        or episode.get("page18_burned") is not True
        or episode.get("lineage31_burned") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("native_result_returned") is not True
        or episode.get("retry_authorized") is not False
        or episode.get("replay_authorized") is not False
        or any(episode.get(field) is not False for field in replay_fields)
        or episode.get("requested_conflicts") != PARENT_REQUESTED_CONFLICTS
        or episode.get("actual_conflicts") != PARENT_ACTUAL_CONFLICTS
        or episode.get("billed_conflicts") != PARENT_ACTUAL_CONFLICTS
        or episode.get("terminal_failure") is not None
        or episode.get("stop_reason") != PARENT_STOP_REASON
        or episode.get("intent_sha256") != PARENT_INTENT_SHA256
        or episode.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or science != expected_science
        or final_bank
        != {
            "path": "final-parent-centered-priority-bank.bin",
            "serialized_bytes": FINAL_BANK_BYTES,
            "sha256": FINAL_BANK_SHA256,
        }
        or _mapping(archived.get("vault.json"), "parent vault artifact")
        != {
            "path": "vault.json",
            "serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "sha256": PARENT_VAULT_TELEMETRY_SHA256,
        }
        or _mapping(archived.get("priority-state.json"), "parent state artifact")
        != {
            "path": "priority-state.json",
            "serialized_bytes": PRIORITY_RECEIPT_BYTES,
            "sha256": PRIORITY_RECEIPT_SHA256,
        }
    ):
        raise O1C102PreparationError("parent completed-call contract differs")

    if (
        intent.get("schema") != "o1-256-apple8-parent-centered-continuation-intent-v1"
        or intent.get("attempt_id") != PARENT_ATTEMPT_ID
        or intent.get("lineage_call_ordinal") != 31
        or intent.get("page18_sha256") != _o1c100.PAGE18_SHA256
        or intent.get("page18_burned") is not True
        or intent.get("lineage31_burned") is not True
        or intent.get("burn_on_persisted_intent") is not True
        or intent.get("retry_authorized") is not False
        or intent.get("replay_authorized") is not False
        or intent.get("invocation_sha256") != PARENT_INVOCATION_SHA256
        or invocation.get("schema")
        != "o1-256-apple8-parent-centered-continuation-invocation-v1"
        or invocation.get("attempt_id") != PARENT_ATTEMPT_ID
        or invocation.get("lineage_call_ordinal") != 31
        or invocation.get("page18_sha256") != _o1c100.PAGE18_SHA256
        or invocation.get("global_novelty_baseline_clause_count")
        != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or invocation.get("maximum_native_solver_calls") != 1
        or invocation.get("retry_authorized") is not False
        or invocation.get("replay_authorized") is not False
        or invocation.get("target_input_present") is not False
        or invocation.get("truth_input_present") is not False
    ):
        raise O1C102PreparationError("parent persisted boundary differs")
    return result


def _regenerate_o1c100_and_validate_initial(
    capsule: Path,
) -> PreparedCausalRolloverArtifacts:
    try:
        previous = _o1c100.prepare_o1c100_page18_telemetry_recovery()
    except (OSError, RuntimeError, CausalAtticError, CausalResidencyError) as exc:
        raise O1C102PreparationError("O1C-0100 regeneration differs") from exc
    expected_names = {
        _o1c100.ACTIVE_PROJECTION_NAME,
        _o1c100.RESIDENCY_NAME,
        _o1c100.ACTIVATION_LEDGER_NAME,
        _o1c100.OCCURRENCES_NAME,
        _o1c100.RELATIONS_NAME,
        _o1c100.COMMON_CORE_AUDIT_NAME,
        _o1c100.FINAL_BANK_NAME,
        _o1c100.PRIORITY_RECEIPT_NAME,
        _o1c100.FAILURE_RECEIPT_NAME,
        _o1c100.PREPARATION_MANIFEST_NAME,
    }
    initial = capsule / "initial"
    try:
        children = tuple(initial.iterdir())
    except OSError as exc:
        raise O1C102PreparationError("parent initial inventory is unreadable") from exc
    if (
        set(previous.artifacts) != expected_names
        or len(previous.artifacts) != PARENT_INITIAL_ARTIFACT_COUNT
        or {path.name for path in children} != expected_names
    ):
        raise O1C102PreparationError("parent initial inventory differs")
    for name, expected in previous.artifacts.items():
        path = initial / name
        try:
            metadata = path.lstat()
            observed = path.read_bytes()
        except OSError as exc:
            raise O1C102PreparationError("parent initial artifact differs") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or observed != expected
        ):
            raise O1C102PreparationError("parent initial artifact differs")
    state = previous.state
    if (
        state.current_projection.lineage_ordinal != 31
        or state.active_limit != _o1c100.PAGE18_ACTIVE_LIMIT
        or state.active_projection.sha256 != _o1c100.PAGE18_SHA256
        or state.attic.union_vault.clause_count != GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT
        or len(state.activation_ledger) != _o1c100.PAGE18_ACTIVATION_COUNT
    ):
        raise O1C102PreparationError("parent Page-18 state differs")
    try:
        validate_activation_replay(state)
    except CausalResidencyError as exc:
        raise O1C102PreparationError("parent Page-18 replay differs") from exc
    return previous


def _parse_parent_telemetry(
    capsule: Path, previous: CausalResidencyState
) -> ParsedVaultTelemetry:
    path = capsule / "episodes/00/vault.json"
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise O1C102PreparationError("parent vault telemetry is unreadable") from exc
    if len(payload) != PARENT_VAULT_TELEMETRY_BYTES:
        raise O1C102PreparationError("parent vault telemetry size differs")
    raw = _canonical_document(payload, "parent vault telemetry")
    try:
        telemetry = parse_vault_telemetry(
            payload,
            stream_id="o1c101-episode-00",
            expected_sha256=PARENT_VAULT_TELEMETRY_SHA256,
        )
    except CausalAtticError as exc:
        raise O1C102PreparationError("parent vault telemetry differs") from exc
    active = previous.active_projection
    expected_raw = {
        "input_sha256": _o1c100.PAGE18_SHA256,
        "input_clause_count": _o1c100.PAGE18_CLAUSE_COUNT,
        "input_literal_count": _o1c100.PAGE18_LITERAL_COUNT,
        "input_serialized_bytes": _o1c100.PAGE18_SERIALIZED_BYTES,
        "input_clause_aggregate_sha256": PAGE18_CLAUSE_AGGREGATE_SHA256,
        "validated_input_clause_count": _o1c100.PAGE18_CLAUSE_COUNT,
        "validated_input_literal_count": _o1c100.PAGE18_LITERAL_COUNT,
        "fully_emitted_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
        "fully_emitted_literal_count": FULLY_EMITTED_LITERAL_COUNT,
        "fully_emitted_aggregate_sha256": FULLY_EMITTED_AGGREGATE_SHA256,
        "emitted_new_clause_count": NEW_CHUNK_CLAUSE_COUNT,
        "emitted_new_literal_count": NEW_CHUNK_LITERAL_COUNT,
        "emitted_current_duplicate_clause_count": 0,
        "emitted_current_duplicate_literal_count": 0,
        "emitted_input_duplicate_clause_count": 0,
        "emitted_input_duplicate_literal_count": 0,
        "preloaded_clause_count": _o1c100.PAGE18_CLAUSE_COUNT,
        "preloaded_literal_count": _o1c100.PAGE18_LITERAL_COUNT,
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
    occurrences = telemetry.occurrences
    known = {clause.sha256 for clause in previous.attic.union_vault.clauses}
    if (
        any(raw.get(name) != value for name, value in expected_raw.items())
        or telemetry.input_identity != active.identity
        or telemetry.input_vault_sha256 != _o1c100.PAGE18_SHA256
        or len(occurrences) != FULLY_EMITTED_OCCURRENCE_COUNT
        or telemetry.new_occurrences != occurrences
        or any(row.source != "trail_upper_bound" for row in occurrences)
        or any(row.classification != "new" for row in occurrences)
        or len({row.clause.serialized for row in occurrences}) != NEW_CHUNK_CLAUSE_COUNT
        or known.intersection(row.clause_sha256 for row in occurrences)
    ):
        raise O1C102PreparationError("Page-18 telemetry novelty binding differs")
    for expected in SOURCE_ROWS:
        row = occurrences[cast(int, expected["source_index"])]
        observed = {
            "source_index": row.source_index,
            "clause_sha256": row.clause_sha256,
            "literal_count": row.clause.literal_count,
            "witness_sha256": row.witness_sha256,
            "witness_score_f64le_hex": row.witness_score_f64le_hex,
        }
        if observed != expected:
            raise O1C102PreparationError("resolution source binding differs")
    return telemetry


def _new_chunk(
    previous: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> ThresholdNoGoodVault:
    try:
        chunk = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            tuple(row.clause for row in telemetry.new_occurrences),
        )
        roundtrip = parse_threshold_no_good_vault(
            chunk.serialized,
            observed_variables=chunk.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C102PreparationError("new immutable chunk differs") from exc
    if (
        roundtrip != chunk
        or chunk.sha256 != NEW_CHUNK_SHA256
        or chunk.clause_count != NEW_CHUNK_CLAUSE_COUNT
        or chunk.literal_count != NEW_CHUNK_LITERAL_COUNT
        or chunk.serialized_bytes != NEW_CHUNK_SERIALIZED_BYTES
        or chunk.describe().get("clause_aggregate_sha256")
        != NEW_CHUNK_CLAUSE_AGGREGATE_SHA256
    ):
        raise O1C102PreparationError("new immutable chunk seal differs")
    return chunk


def _resolve_exact(
    left: ThresholdNoGoodClause,
    right: ThresholdNoGoodClause,
    *,
    pivot: int,
) -> ThresholdNoGoodClause:
    if isinstance(pivot, bool) or not isinstance(pivot, int) or pivot <= 0:
        raise O1C102PreparationError("resolution pivot differs")
    left_pivot = {literal for literal in left.literals if abs(literal) == pivot}
    right_pivot = {literal for literal in right.literals if abs(literal) == pivot}
    if (left_pivot, right_pivot) not in (({-pivot}, {pivot}), ({pivot}, {-pivot})):
        raise O1C102PreparationError("resolution complementary pivot differs")
    left_tail = {literal for literal in left.literals if abs(literal) != pivot}
    right_tail = {literal for literal in right.literals if abs(literal) != pivot}
    if any(-literal in right_tail for literal in left_tail):
        raise O1C102PreparationError("resolution has a non-pivot complement")
    try:
        return ThresholdNoGoodClause(tuple(sorted(left_tail | right_tail, key=abs)))
    except ThresholdNoGoodVaultError as exc:
        raise O1C102PreparationError("resolution canonical clause differs") from exc


def _derive_resolution_closure(
    previous: CausalResidencyState,
    telemetry: ParsedVaultTelemetry,
) -> tuple[ThresholdNoGoodVault, ThresholdNoGoodVault, bytes]:
    source = telemetry.occurrences
    r0 = _resolve_exact(source[4].clause, source[5].clause, pivot=190_577)
    r1 = _resolve_exact(source[4].clause, source[6].clause, pivot=191_229)
    r2 = _resolve_exact(source[5].clause, source[6].clause, pivot=191_229)
    r3 = _resolve_exact(source[7].clause, source[8].clause, pivot=190_577)
    r4 = _resolve_exact(r0, source[6].clause, pivot=191_229)
    alternative_r4 = _resolve_exact(r1, r2, pivot=190_577)
    clauses = (r0, r1, r2, r3, r4)
    overlay_clauses = tuple(clauses[index] for index in DERIVED_OVERLAY_ORDER)
    if (
        r4 != alternative_r4
        or tuple(clause.sha256 for clause in clauses) != DERIVED_CLAUSE_SHA256
        or tuple(clause.literal_count for clause in clauses)
        != DERIVED_CLAUSE_LITERAL_COUNTS
        or overlay_clauses
        != tuple(
            sorted(
                overlay_clauses,
                key=lambda clause: (clause.literal_count, clause.sha256),
            )
        )
    ):
        raise O1C102PreparationError("derived resolution closure differs")
    try:
        closure = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            clauses,
        )
        overlay = ThresholdNoGoodVault(
            telemetry.input_identity,
            previous.active_projection.observed_variables,
            overlay_clauses,
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C102PreparationError("derived resolution vault differs") from exc
    relations = strict_subsumption_relations(closure.clauses)
    expected_relations = ((4, 0), (4, 1))
    relation_pairs = tuple(
        (row.subsumer_index, row.subsumed_index) for row in relations
    )
    prior_and_native = (
        *previous.attic.union_vault.clauses,
        *(row.clause for row in source),
    )
    prior_native_serialized = {clause.serialized for clause in prior_and_native}
    all_serialized = [clause.serialized for clause in clauses]
    # Only pairs touching a derived node are new.  The 2,338-clause emitted
    # closure was already exhaustively sealed by CausalAttic-v1; recomputing
    # those historical pairs would add no information and dominates runtime.
    base_sets = tuple(frozenset(clause.literals) for clause in prior_and_native)
    derived_sets = tuple(frozenset(clause.literals) for clause in clauses)
    incremental_pairs: list[tuple[int, int]] = []
    incremental_pair_count = 0
    for derived_index, derived_literals in enumerate(derived_sets):
        conceptual_derived_index = ATTIC_UNION_CLAUSE_COUNT + derived_index
        for base_index, base_literals in enumerate(base_sets):
            incremental_pair_count += 1
            if derived_literals < base_literals:
                incremental_pairs.append((conceptual_derived_index, base_index))
            elif base_literals < derived_literals:
                incremental_pairs.append((base_index, conceptual_derived_index))
        for other_index in range(derived_index):
            incremental_pair_count += 1
            other_literals = derived_sets[other_index]
            conceptual_other_index = ATTIC_UNION_CLAUSE_COUNT + other_index
            if derived_literals < other_literals:
                incremental_pairs.append(
                    (conceptual_derived_index, conceptual_other_index)
                )
            elif other_literals < derived_literals:
                incremental_pairs.append(
                    (conceptual_other_index, conceptual_derived_index)
                )
    expected_incremental_pairs = (
        (2_338, 2_078),
        (2_339, 2_078),
        (2_340, 2_079),
        (2_341, 2_081),
        (2_342, 2_078),
        (2_342, 2_338),
        (2_342, 2_339),
    )
    if (
        closure.sha256 != DERIVED_CLOSURE_SHA256
        or closure.serialized_bytes != DERIVED_CLOSURE_BYTES
        or closure.clause_count != DERIVED_CLOSURE_CLAUSE_COUNT
        or closure.literal_count != DERIVED_CLOSURE_LITERAL_COUNT
        or closure.describe().get("clause_aggregate_sha256")
        != DERIVED_CLOSURE_AGGREGATE_SHA256
        or overlay.sha256 != DERIVED_OVERLAY_SHA256
        or overlay.serialized_bytes != DERIVED_OVERLAY_BYTES
        or overlay.clause_count != DERIVED_OVERLAY_CLAUSE_COUNT
        or overlay.literal_count != DERIVED_OVERLAY_LITERAL_COUNT
        or overlay.describe().get("clause_aggregate_sha256")
        != DERIVED_OVERLAY_AGGREGATE_SHA256
        or len(set(all_serialized)) != 5
        or any(payload in prior_native_serialized for payload in all_serialized)
        or relation_pairs != expected_relations
        or incremental_pair_count != 11_700
        or tuple(incremental_pairs) != expected_incremental_pairs
    ):
        raise O1C102PreparationError("derived resolution closure audit differs")

    edge_rows = [
        {
            "node": "R0",
            "generation": 1,
            "left_parent": {
                "kind": "native-emission",
                "source_index": 4,
                "sha256": source[4].clause_sha256,
            },
            "right_parent": {
                "kind": "native-emission",
                "source_index": 5,
                "sha256": source[5].clause_sha256,
            },
            "pivot_variable": 190_577,
            "left_pivot_literal": -190_577,
            "right_pivot_literal": 190_577,
            "resolvent_sha256": r0.sha256,
            "resolvent_literal_count": r0.literal_count,
        },
        {
            "node": "R1",
            "generation": 1,
            "left_parent": {
                "kind": "native-emission",
                "source_index": 4,
                "sha256": source[4].clause_sha256,
            },
            "right_parent": {
                "kind": "native-emission",
                "source_index": 6,
                "sha256": source[6].clause_sha256,
            },
            "pivot_variable": 191_229,
            "left_pivot_literal": -191_229,
            "right_pivot_literal": 191_229,
            "resolvent_sha256": r1.sha256,
            "resolvent_literal_count": r1.literal_count,
        },
        {
            "node": "R2",
            "generation": 1,
            "left_parent": {
                "kind": "native-emission",
                "source_index": 5,
                "sha256": source[5].clause_sha256,
            },
            "right_parent": {
                "kind": "native-emission",
                "source_index": 6,
                "sha256": source[6].clause_sha256,
            },
            "pivot_variable": 191_229,
            "left_pivot_literal": -191_229,
            "right_pivot_literal": 191_229,
            "resolvent_sha256": r2.sha256,
            "resolvent_literal_count": r2.literal_count,
        },
        {
            "node": "R3",
            "generation": 1,
            "left_parent": {
                "kind": "native-emission",
                "source_index": 7,
                "sha256": source[7].clause_sha256,
            },
            "right_parent": {
                "kind": "native-emission",
                "source_index": 8,
                "sha256": source[8].clause_sha256,
            },
            "pivot_variable": 190_577,
            "left_pivot_literal": -190_577,
            "right_pivot_literal": 190_577,
            "resolvent_sha256": r3.sha256,
            "resolvent_literal_count": r3.literal_count,
        },
        {
            "node": "R4",
            "generation": 2,
            "left_parent": {
                "kind": "derived-resolution",
                "node": "R0",
                "sha256": r0.sha256,
            },
            "right_parent": {
                "kind": "native-emission",
                "source_index": 6,
                "sha256": source[6].clause_sha256,
            },
            "pivot_variable": 191_229,
            "left_pivot_literal": -191_229,
            "right_pivot_literal": 191_229,
            "resolvent_sha256": r4.sha256,
            "resolvent_literal_count": r4.literal_count,
            "alternative_derivation": {
                "left_parent": {
                    "kind": "derived-resolution",
                    "node": "R1",
                    "sha256": r1.sha256,
                },
                "right_parent": {
                    "kind": "derived-resolution",
                    "node": "R2",
                    "sha256": r2.sha256,
                },
                "pivot_variable": 190_577,
                "left_pivot_literal": -190_577,
                "right_pivot_literal": 190_577,
                "byte_equal": True,
            },
        },
    ]
    receipt: dict[str, object] = {
        "schema": DERIVED_RECEIPT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "claim_boundary": {
            "derivation_kind": "exact-propositional-resolution",
            "public_only": True,
            "native_solver_calls": 0,
            "native_preflight_calls": 0,
            "target_bytes_read": False,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
            "derived_clauses_are_native_occurrences": False,
            "derived_clauses_enter_causal_attic": False,
            "derived_clauses_claim_key_recovery": False,
            "observed": False,
            "emitted": False,
            "certified_logical_consequence": True,
            "attacker_valid_domain_reduction": 0,
            "attacker_valid_entropy_gain_bits": 0.0,
            "certified_model_or_key": False,
        },
        "public_identity": telemetry.input_identity.describe(),
        "source": {
            "attempt_id": PARENT_ATTEMPT_ID,
            "capsule_manifest_sha256": PARENT_CAPSULE_MANIFEST_SHA256,
            "result_sha256": PARENT_RESULT_SHA256,
            "source_active_sha256": _o1c100.PAGE18_SHA256,
            "vault_telemetry_sha256": PARENT_VAULT_TELEMETRY_SHA256,
            "vault_telemetry_serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "native_chunk_sha256": NEW_CHUNK_SHA256,
            "native_chunk_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "native_rows": [dict(row) for row in SOURCE_ROWS],
        },
        "resolution_rule": {
            "pivot_rule": "exactly-one-opposite-signed-pivot-variable",
            "nonpivot_complements_allowed": False,
            "resolvent_rule": "union-of-parent-literals-minus-both-pivot-literals",
            "literal_order": "strict-ascending-absolute-variable",
            "tautological_resolvents_allowed": False,
        },
        "edges": edge_rows,
        "exhaustive_audit": {
            "historical_vs_native_pair_count": 547_536,
            "native_vs_native_pair_count": 34_716,
            "derived_incremental_pair_count": 11_700,
            "historical_native_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "derived_clause_count": len(clauses),
            "derived_duplicate_count": 0,
            "derived_vs_historical_native_strict_subsumption_count": 5,
            "within_derived_strict_subsumption_count": 2,
            "all_incremental_relations": [
                {
                    "subsumer_logical_index": left,
                    "subsumer_clause_sha256": (
                        (*prior_and_native, *clauses)[left].sha256
                    ),
                    "subsumer_literal_count": (
                        (*prior_and_native, *clauses)[left].literal_count
                    ),
                    "subsumed_logical_index": right,
                    "subsumed_clause_sha256": (
                        (*prior_and_native, *clauses)[right].sha256
                    ),
                    "subsumed_literal_count": (
                        (*prior_and_native, *clauses)[right].literal_count
                    ),
                }
                for left, right in incremental_pairs
            ],
            "within_derived_relations": [
                row.describe(closure.clauses) for row in relations
            ],
        },
        "closure": {
            **closure.describe(),
            "artifact": DERIVED_CLOSURE_NAME,
            "node_order": ["R0", "R1", "R2", "R3", "R4"],
        },
        "undominated_antichain_overlay": {
            **overlay.describe(),
            "artifact": DERIVED_OVERLAY_NAME,
            "node_order": ["R2", "R4", "R3"],
            "ordering_rule": "literal-count-ascending;clause-sha256-ascending",
            "excluded_dominated_nodes": ["R0", "R1"],
            "causal_attic_occurrence_count_added": 0,
        },
    }
    receipt_payload = canonical_json_bytes(receipt)
    return closure, overlay, receipt_payload


def _advance_base_page19(
    previous: CausalResidencyState,
    chunk: ThresholdNoGoodVault,
    telemetry: ParsedVaultTelemetry,
) -> CausalResidencyState:
    try:
        state = advance_causal_residency(
            previous,
            chunk=chunk,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=PAGE19_LINEAGE_ORDINAL,
            next_active_limit=PAGE19_ACTIVE_LIMIT,
        )
        validate_activation_replay(state)
        replayed = replay_causal_residency(state.attic, state.describe())
        roundtrip = parse_threshold_no_good_vault(
            state.active_projection.serialized,
            observed_variables=state.active_projection.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (CausalResidencyError, ThresholdNoGoodVaultError) as exc:
        raise O1C102PreparationError("Page-19 causal rollover differs") from exc
    attic = state.attic
    page = state.active_projection
    occurrence_payload = canonical_json_bytes(attic.occurrence_document())
    relation_payload = canonical_json_bytes(attic.relation_document())
    residency_payload = canonical_json_bytes(state.describe())
    activation_payload = canonical_json_bytes(state.activation_ledger_document())
    selected_payload = canonical_json_bytes(
        list(state.current_projection.selected_union_indices)
    )
    order_payload = canonical_json_bytes(list(state.current_projection.selection_order))
    new_indices = tuple(
        range(GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT, ATTIC_UNION_CLAUSE_COUNT)
    )
    selected = frozenset(state.current_projection.selected_union_indices)
    resident = tuple(index for index in new_indices if index in selected)
    missing = tuple(index for index in new_indices if index not in selected)
    new_relations = tuple(
        row for row in attic.relations if row not in previous.attic.relations
    )
    if (
        roundtrip != page
        or replayed != state
        or state.current_projection.lineage_ordinal != PAGE19_LINEAGE_ORDINAL
        or state.active_limit != PAGE19_ACTIVE_LIMIT
        or page.sha256 != PAGE19_BASE_SHA256
        or page.clause_count != PAGE19_BASE_CLAUSE_COUNT
        or page.literal_count != PAGE19_BASE_LITERAL_COUNT
        or page.serialized_bytes != PAGE19_BASE_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE19_BASE_CLAUSE_AGGREGATE_SHA256
        or state.current_projection.category_counts != PAGE19_BASE_CATEGORY_COUNTS
        or len(attic.chunks) != ATTIC_CHUNK_COUNT
        or attic.chunks[:-1] != previous.attic.chunks
        or attic.chunks[-1] != chunk
        or attic.chunk_clause_union_indices[-1] != new_indices
        or attic.union_vault.sha256 != ATTIC_UNION_SHA256
        or attic.union_vault.clause_count != ATTIC_UNION_CLAUSE_COUNT
        or attic.union_vault.literal_count != ATTIC_UNION_LITERAL_COUNT
        or attic.union_vault.serialized_bytes != ATTIC_UNION_SERIALIZED_BYTES
        or attic.union_vault.describe().get("clause_aggregate_sha256")
        != ATTIC_UNION_CLAUSE_AGGREGATE_SHA256
        or len(attic.occurrences) != ATTIC_OCCURRENCE_COUNT
        or attic.duplicate_occurrence_count != ATTIC_DUPLICATE_OCCURRENCE_COUNT
        or len(attic.relations) != ATTIC_SUBSUMPTION_RELATION_COUNT
        or new_relations
        or len(attic.undominated_indices) != ATTIC_UNDOMINATED_CLAUSE_COUNT
        or len(occurrence_payload) != OCCURRENCE_DOCUMENT_BYTES
        or sha256_bytes(occurrence_payload) != OCCURRENCE_DOCUMENT_SHA256
        or len(relation_payload) != RELATION_DOCUMENT_BYTES
        or sha256_bytes(relation_payload) != RELATION_DOCUMENT_SHA256
        or len(residency_payload) != PAGE19_BASE_RESIDENCY_DOCUMENT_BYTES
        or sha256_bytes(residency_payload) != PAGE19_BASE_RESIDENCY_DOCUMENT_SHA256
        or len(activation_payload) != PAGE19_BASE_ACTIVATION_DOCUMENT_BYTES
        or sha256_bytes(activation_payload) != PAGE19_BASE_ACTIVATION_DOCUMENT_SHA256
        or sha256_bytes(selected_payload) != PAGE19_BASE_SELECTED_INDICES_SHA256
        or sha256_bytes(order_payload) != PAGE19_BASE_SELECTION_ORDER_SHA256
        or len(state.activation_ledger) != PAGE19_BASE_ACTIVATION_COUNT
        or state.activation_ledger[:-1] != previous.activation_ledger
        or page.sha256 in previous.used_active_sha256
        or resident != NEW_RESIDENT_UNION_INDICES
        or missing != NEW_MISSING_UNION_INDICES
        or state.never_resident_undominated_indices != NEW_MISSING_UNION_INDICES
        or set(state.current_projection.new_debt_indices) != set(resident)
    ):
        raise O1C102PreparationError("Page-19 base rollover contract differs")
    return state


def _validate_evolved_continuation_bank(
    capsule: Path,
) -> tuple[bytes, bytes, dict[str, object]]:
    episode = capsule / "episodes/00"
    try:
        bank = (episode / "final-parent-centered-priority-bank.bin").read_bytes()
        receipt_payload = (episode / "priority-state.json").read_bytes()
    except OSError as exc:
        raise O1C102PreparationError(
            "evolved continuation state is unreadable"
        ) from exc
    if (
        len(bank) != FINAL_BANK_BYTES
        or sha256_bytes(bank) != FINAL_BANK_SHA256
        or len(receipt_payload) != PRIORITY_RECEIPT_BYTES
        or sha256_bytes(receipt_payload) != PRIORITY_RECEIPT_SHA256
    ):
        raise O1C102PreparationError("evolved continuation state differs")
    receipt = _canonical_document(receipt_payload, "evolved priority-state receipt")
    hexadecimal = receipt.get("bank_hex")
    if not isinstance(hexadecimal, str):
        raise O1C102PreparationError("evolved continuation bank hex differs")
    try:
        receipt_bank = bytes.fromhex(hexadecimal)
    except ValueError as exc:
        raise O1C102PreparationError("evolved continuation bank hex differs") from exc
    if (
        receipt.get("schema")
        != "o1-256-o1c101-live-parent-centered-continuation-priority-state-v1"
        or receipt.get("bank_encoding")
        != "256-variable-ordered-96-byte-records-little-endian"
        or receipt.get("bank_bytes") != FINAL_BANK_BYTES
        or receipt.get("current_bank_sha256") != FINAL_BANK_SHA256
        or receipt_bank != bank
        or receipt.get("candidate_population") != 255
        or receipt.get("candidate_order_sha256") != CONTINUATION_CANDIDATE_ORDER_SHA256
        or receipt.get("consumed_coordinate_count") != 255
        or receipt.get("assignment_literals_observed") != 72_077
        or receipt.get("parent_scans") != 551
        or receipt.get("callback_calls") != 551
        or receipt.get("nonzero_returns") != 255
        or receipt.get("zero_returns") != 296
        or receipt.get("last_parent_candidate_count") != 2
    ):
        raise O1C102PreparationError("evolved continuation bank receipt differs")
    continuation = {
        "validation_contract": "o1c101-live-continuation-bank-with-state-receipt",
        "receipt_sha256": PRIORITY_RECEIPT_SHA256,
        "receipt_serialized_bytes": PRIORITY_RECEIPT_BYTES,
        "receipt_artifact": PRIORITY_RECEIPT_NAME,
        "encoding": receipt["bank_encoding"],
        "coordinate_record_count": 256,
        "record_bytes": 96,
        "eligible_coordinate_count": 255,
        "receipt_bank_hex_byte_equal": True,
        "fresh_seed_parser_compatible": False,
        "priority_is_key_bit_belief": False,
    }
    return bank, receipt_payload, continuation


@dataclass(frozen=True)
class _ComposedPage19:
    page: ThresholdNoGoodVault
    residency_payload: bytes
    activation_payload: bytes
    selected_emitted_indices: tuple[int, ...]
    priority_selected_emitted_indices: tuple[int, ...]
    never_resident_undominated_indices: tuple[int, ...]
    logical_known_sha256: str
    emitted_inventory_sha256: str
    derived_inventory_sha256: str
    combined_inventory_sha256: str


def _known_inventory(
    clauses: Sequence[ThresholdNoGoodClause],
) -> tuple[list[str], str]:
    inventory = [clause.sha256 for clause in clauses]
    if len(inventory) != len(set(inventory)):
        raise O1C102PreparationError("known-clause inventory contains a duplicate")
    return inventory, sha256_bytes(canonical_json_bytes(inventory))


def _logical_relations() -> tuple[tuple[int, int], ...]:
    return (
        (2_338, 2_078),
        (2_339, 2_078),
        (2_340, 2_079),
        (2_341, 2_081),
        (2_342, 2_078),
        (2_342, 2_338),
        (2_342, 2_339),
    )


def _compose_page19(
    previous: CausalResidencyState,
    base: CausalResidencyState,
    closure: ThresholdNoGoodVault,
    overlay: ThresholdNoGoodVault,
) -> _ComposedPage19:
    emitted_union = base.attic.union_vault
    displaced = frozenset(DISPLACED_EMITTED_UNION_INDICES)
    selected_emitted = tuple(
        index
        for index in base.current_projection.selected_union_indices
        if index not in displaced
    )
    priority_selected = tuple(
        index
        for index in base.current_projection.selection_order
        if index not in displaced
    )
    displaced_clauses = tuple(
        emitted_union.clauses[index] for index in DISPLACED_EMITTED_UNION_INDICES
    )
    if (
        tuple(clause.sha256 for clause in displaced_clauses)
        != DISPLACED_EMITTED_CLAUSE_SHA256
        or tuple(clause.literal_count for clause in displaced_clauses)
        != DISPLACED_EMITTED_LITERAL_COUNTS
        or not displaced.issubset(base.current_projection.new_debt_indices)
        or len(selected_emitted) != 245
        or len(priority_selected) != 245
        or overlay.clauses
        != tuple(closure.clauses[index] for index in DERIVED_OVERLAY_ORDER)
    ):
        raise O1C102PreparationError("derived active-page displacement differs")
    try:
        page = ThresholdNoGoodVault(
            emitted_union.identity,
            emitted_union.observed_variables,
            (
                *(emitted_union.clauses[index] for index in selected_emitted),
                *overlay.clauses,
            ),
        )
        roundtrip = parse_threshold_no_good_vault(
            page.serialized,
            observed_variables=page.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        logical = ThresholdNoGoodVault(
            emitted_union.identity,
            emitted_union.observed_variables,
            (*emitted_union.clauses, *closure.clauses),
        )
    except ThresholdNoGoodVaultError as exc:
        raise O1C102PreparationError("derived active Page-19 differs") from exc

    emitted_inventory, emitted_inventory_sha256 = _known_inventory(
        emitted_union.clauses
    )
    derived_inventory, derived_inventory_sha256 = _known_inventory(closure.clauses)
    combined_inventory = [*emitted_inventory, *derived_inventory]
    combined_inventory_sha256 = sha256_bytes(canonical_json_bytes(combined_inventory))
    relation_pairs = (
        *((row.subsumer_index, row.subsumed_index) for row in base.attic.relations),
        *_logical_relations(),
    )
    subsumed = frozenset(right for _left, right in relation_pairs)
    logical_undominated = tuple(
        index for index in range(LOGICAL_KNOWN_CLAUSE_COUNT) if index not in subsumed
    )
    selected_logical = frozenset(
        (
            *selected_emitted,
            *(ATTIC_UNION_CLAUSE_COUNT + index for index in DERIVED_OVERLAY_ORDER),
        )
    )
    prior_counts = previous.activation_counts + (0,) * NEW_CHUNK_CLAUSE_COUNT
    prior_lineages = previous.last_active_lineages + (None,) * NEW_CHUNK_CLAUSE_COUNT
    activation_counts = tuple(
        count + (1 if index in selected_emitted else 0)
        for index, count in enumerate(prior_counts)
    )
    last_active_lineages = tuple(
        PAGE19_LINEAGE_ORDINAL if index in selected_emitted else lineage
        for index, lineage in enumerate(prior_lineages)
    )
    never_resident = tuple(
        index
        for index in logical_undominated
        if index not in selected_logical
        and (index >= len(prior_counts) or prior_counts[index] == 0)
    )
    derived_selection = [
        {
            "namespace": "certified-derived-resolution",
            "node": node,
            "logical_index": ATTIC_UNION_CLAUSE_COUNT + closure_index,
            "clause_sha256": closure.clauses[closure_index].sha256,
            "literal_count": closure.clauses[closure_index].literal_count,
        }
        for node, closure_index in zip(("R2", "R4", "R3"), DERIVED_OVERLAY_ORDER)
    ]
    category_order: list[dict[str, object]] = [
        {"namespace": "emitted-causal-attic", "union_index": index}
        for index in base.current_projection.structural_root_indices
    ]
    category_order.extend(derived_selection)
    category_order.extend(
        {"namespace": "emitted-causal-attic", "union_index": index}
        for index in base.current_projection.pinned_core_indices
    )
    category_order.extend(
        {"namespace": "emitted-causal-attic", "union_index": index}
        for index in base.current_projection.new_debt_indices
        if index not in displaced
    )
    parent_activation_payload = canonical_json_bytes(
        previous.activation_ledger_document()
    )
    current_entry: dict[str, object] = {
        "lineage_ordinal": PAGE19_LINEAGE_ORDINAL,
        "role": "composed-causal-page-with-certified-resolution-overlay",
        "active_sha256": page.sha256,
        "selected_emitted_union_indices": list(selected_emitted),
        "selected_derived_clauses": derived_selection,
    }
    used_active_sha256 = (*previous.used_active_sha256, page.sha256)
    activation_document: dict[str, object] = {
        "schema": COMPOSED_ACTIVATION_SCHEMA,
        "causal_v1_prefix": {
            "schema": "o1-score-threshold-residency-activation-ledger-v1",
            "serialized_bytes": len(parent_activation_payload),
            "sha256": sha256_bytes(parent_activation_payload),
            "document": previous.activation_ledger_document(),
            "entry_count": len(previous.activation_ledger),
            "byte_exact_and_unmodified": True,
        },
        "composed_entries": [current_entry],
        "used_active_sha256": list(used_active_sha256),
        "forbidden_nonactivated_candidate_sha256": PAGE19_BASE_SHA256,
        "pure_emitted_candidate_activated": False,
    }
    activation_payload = canonical_json_bytes(activation_document)
    logical_description = logical.describe()
    residency_document: dict[str, object] = {
        "schema": COMPOSED_RESIDENCY_SCHEMA,
        "active_limit": PAGE19_ACTIVE_LIMIT,
        "lineage_ordinal": PAGE19_LINEAGE_ORDINAL,
        "namespace_contract": {
            "emitted": "causal-attic-v1-with-native-ClauseOccurrence",
            "derived": "certified-resolution-sidecar-without-ClauseOccurrence",
            "derived_enters_emitted_attic": False,
            "derived_occurrence_rows": 0,
            "selector": "compose-emitted-residency-with-certified-undominated-overlay",
        },
        "parent_causal_residency": previous.describe(),
        "emitted_causal_attic": base.attic.describe(),
        "emitted_selector_candidate": {
            "encoding_only": base.active_projection.describe(),
            "activated": False,
            "reason": "three-certified-derived-structural-roots-overlay-finalized-before-activation",
        },
        "logical_known_registry": {
            "encoding_only": logical_description,
            "emitted_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": len(combined_inventory),
            "emitted_inventory_sha256": emitted_inventory_sha256,
            "derived_inventory_sha256": derived_inventory_sha256,
            "combined_inventory_sha256": combined_inventory_sha256,
            "inventory_encoding": "canonical-json-sha256-array;emitted-union-order-then-derived-closure-order",
            "strict_subsumption_pair_count": len(relation_pairs),
            "undominated_clause_count": len(logical_undominated),
            "incremental_relations": [
                {"subsumer_logical_index": left, "subsumed_logical_index": right}
                for left, right in _logical_relations()
            ],
        },
        "current_projection": {
            "encoding_only": page.describe(),
            "maximum_clause_count": PAGE19_ACTIVE_LIMIT,
            "category_counts": PAGE19_CATEGORY_COUNTS,
            "category_priority_order": category_order,
            "serialization_rule": "emitted-selected-union-index-ascending;derived-overlay-literal-count-ascending-clause-sha256-ascending",
            "selected_emitted_union_indices": list(selected_emitted),
            "priority_selected_emitted_union_indices": list(priority_selected),
            "selected_derived_clauses": derived_selection,
            "displaced_emitted_union_indices": list(DISPLACED_EMITTED_UNION_INDICES),
            "displaced_emitted_clause_sha256": list(DISPLACED_EMITTED_CLAUSE_SHA256),
        },
        "activation_counts": list(activation_counts),
        "last_active_lineages": list(last_active_lineages),
        "derived_activation_counts": [0, 0, 1, 1, 1],
        "derived_last_active_lineages": [None, None, 32, 32, 32],
        "never_resident_undominated_logical_indices": list(never_resident),
        "activation_ledger": activation_document,
    }
    residency_payload = canonical_json_bytes(residency_document)
    if (
        roundtrip != page
        or page.sha256 != PAGE19_SHA256
        or page.clause_count != PAGE19_CLAUSE_COUNT
        or page.literal_count != PAGE19_LITERAL_COUNT
        or page.serialized_bytes != PAGE19_SERIALIZED_BYTES
        or page.describe().get("clause_aggregate_sha256")
        != PAGE19_CLAUSE_AGGREGATE_SHA256
        or PAGE19_BASE_SHA256 in used_active_sha256
        or len(category_order) != PAGE19_ACTIVE_LIMIT
        or logical.sha256 != LOGICAL_KNOWN_SHA256
        and bool(LOGICAL_KNOWN_SHA256)
        or logical.clause_count != LOGICAL_KNOWN_CLAUSE_COUNT
        or logical.literal_count != LOGICAL_KNOWN_LITERAL_COUNT
        or logical.serialized_bytes != LOGICAL_KNOWN_SERIALIZED_BYTES
        or len(relation_pairs) != LOGICAL_SUBSUMPTION_RELATION_COUNT
        or len(logical_undominated) != LOGICAL_UNDOMINATED_CLAUSE_COUNT
        or len(never_resident) != 68
        or (
            EMITTED_KNOWN_INVENTORY_SHA256
            and emitted_inventory_sha256 != EMITTED_KNOWN_INVENTORY_SHA256
        )
        or (
            DERIVED_KNOWN_INVENTORY_SHA256
            and derived_inventory_sha256 != DERIVED_KNOWN_INVENTORY_SHA256
        )
        or (
            COMBINED_KNOWN_INVENTORY_SHA256
            and combined_inventory_sha256 != COMBINED_KNOWN_INVENTORY_SHA256
        )
        or (
            PAGE19_RESIDENCY_DOCUMENT_BYTES
            and len(residency_payload) != PAGE19_RESIDENCY_DOCUMENT_BYTES
        )
        or (
            PAGE19_RESIDENCY_DOCUMENT_SHA256
            and sha256_bytes(residency_payload) != PAGE19_RESIDENCY_DOCUMENT_SHA256
        )
        or (
            PAGE19_ACTIVATION_DOCUMENT_BYTES
            and len(activation_payload) != PAGE19_ACTIVATION_DOCUMENT_BYTES
        )
        or (
            PAGE19_ACTIVATION_DOCUMENT_SHA256
            and sha256_bytes(activation_payload) != PAGE19_ACTIVATION_DOCUMENT_SHA256
        )
    ):
        raise O1C102PreparationError("composed Page-19 contract differs")
    return _ComposedPage19(
        page=page,
        residency_payload=residency_payload,
        activation_payload=activation_payload,
        selected_emitted_indices=selected_emitted,
        priority_selected_emitted_indices=priority_selected,
        never_resident_undominated_indices=never_resident,
        logical_known_sha256=logical.sha256,
        emitted_inventory_sha256=emitted_inventory_sha256,
        derived_inventory_sha256=derived_inventory_sha256,
        combined_inventory_sha256=combined_inventory_sha256,
    )


def _finalize_derived_receipt(
    receipt_payload: bytes,
    *,
    base: CausalResidencyState,
    closure: ThresholdNoGoodVault,
    composed: _ComposedPage19,
) -> bytes:
    receipt = dict(_canonical_document(receipt_payload, "derived receipt draft"))
    emitted_inventory, emitted_digest = _known_inventory(base.attic.union_vault.clauses)
    derived_inventory, derived_digest = _known_inventory(closure.clauses)
    combined_inventory = [*emitted_inventory, *derived_inventory]
    combined_digest = sha256_bytes(canonical_json_bytes(combined_inventory))
    receipt["logical_known_registry"] = {
        "emitted": {
            "clause_count": len(emitted_inventory),
            "clause_sha256": emitted_inventory,
            "inventory_sha256": emitted_digest,
            "source": "causal-attic-v1-union-order",
        },
        "derived": {
            "clause_count": len(derived_inventory),
            "clause_sha256": derived_inventory,
            "inventory_sha256": derived_digest,
            "source": "certified-resolution-closure-order",
        },
        "combined": {
            "clause_count": len(combined_inventory),
            "clause_sha256": combined_inventory,
            "inventory_sha256": combined_digest,
            "ordering": "emitted-union-order-then-derived-closure-order",
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        },
    }
    receipt["page19_binding"] = {
        "active_sha256": composed.page.sha256,
        "active_clause_count": composed.page.clause_count,
        "selected_emitted_clause_count": len(composed.selected_emitted_indices),
        "selected_derived_clause_count": DERIVED_OVERLAY_CLAUSE_COUNT,
        "derived_overlay_sha256": DERIVED_OVERLAY_SHA256,
        "pure_emitted_candidate_sha256": PAGE19_BASE_SHA256,
        "pure_emitted_candidate_activated": False,
    }
    finalized = canonical_json_bytes(receipt)
    if (
        emitted_digest != composed.emitted_inventory_sha256
        or derived_digest != composed.derived_inventory_sha256
        or combined_digest != composed.combined_inventory_sha256
        or (DERIVED_RECEIPT_BYTES and len(finalized) != DERIVED_RECEIPT_BYTES)
        or (
            DERIVED_RECEIPT_SHA256 and sha256_bytes(finalized) != DERIVED_RECEIPT_SHA256
        )
    ):
        raise O1C102PreparationError("derived resolution receipt differs")
    return finalized


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def prepare_o1c102_page19_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
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
    previous = _regenerate_o1c100_and_validate_initial(capsule)
    telemetry = _parse_parent_telemetry(capsule, previous.state)
    chunk = _new_chunk(previous.state, telemetry)
    closure, overlay, receipt_draft = _derive_resolution_closure(
        previous.state, telemetry
    )
    base = _advance_base_page19(previous.state, chunk, telemetry)
    composed = _compose_page19(previous.state, base, closure, overlay)
    derived_receipt = _finalize_derived_receipt(
        receipt_draft,
        base=base,
        closure=closure,
        composed=composed,
    )
    bank, priority_receipt, continuation = _validate_evolved_continuation_bank(capsule)
    audit_payload = previous.artifacts[COMMON_CORE_AUDIT_NAME]
    if audit_payload != (capsule / "initial" / COMMON_CORE_AUDIT_NAME).read_bytes():
        raise O1C102PreparationError("historical common-core audit differs")

    artifacts: dict[str, bytes] = {
        NEW_CHUNK_NAME: chunk.serialized,
        ACTIVE_PROJECTION_NAME: composed.page.serialized,
        RESIDENCY_NAME: composed.residency_payload,
        ACTIVATION_LEDGER_NAME: composed.activation_payload,
        OCCURRENCES_NAME: canonical_json_bytes(base.attic.occurrence_document()),
        RELATIONS_NAME: canonical_json_bytes(base.attic.relation_document()),
        COMMON_CORE_AUDIT_NAME: audit_payload,
        FINAL_BANK_NAME: bank,
        PRIORITY_RECEIPT_NAME: priority_receipt,
        DERIVED_RECEIPT_NAME: derived_receipt,
        DERIVED_CLOSURE_NAME: closure.serialized,
        DERIVED_OVERLAY_NAME: overlay.serialized,
    }
    roles = {
        NEW_CHUNK_NAME: "immutable-unique-lineage-31-native-evidence-chunk",
        ACTIVE_PROJECTION_NAME: "fresh-lineage-32-composed-page19-science-input",
        RESIDENCY_NAME: "composed-two-namespace-residency-state",
        ACTIVATION_LEDGER_NAME: "composed-activation-ledger-with-byte-exact-v1-prefix",
        OCCURRENCES_NAME: "pure-native-complete-updated-occurrence-ledger",
        RELATIONS_NAME: "pure-native-complete-updated-subsumption-closure",
        COMMON_CORE_AUDIT_NAME: "unchanged-historical-public-common-core-audit",
        FINAL_BANK_NAME: "sealed-evolved-live-continuation-bank-bytes",
        PRIORITY_RECEIPT_NAME: "canonical-o1c101-evolved-priority-state-receipt",
        DERIVED_RECEIPT_NAME: "exact-public-resolution-proof-and-known-registry",
        DERIVED_CLOSURE_NAME: "immutable-five-clause-certified-resolution-closure",
        DERIVED_OVERLAY_NAME: "immutable-three-clause-undominated-resolution-overlay",
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
            "page19_burned": False,
            "lineage32_burned": False,
            "page18_retry_or_replay_authorized": False,
            "lineage31_retry_or_replay_authorized": False,
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
            "invocation_sha256": PARENT_INVOCATION_SHA256,
            "classification": PARENT_CLASSIFICATION,
            "stop_reason": PARENT_STOP_REASON,
            "source_lineage_ordinal": 31,
            "source_active_sha256": _o1c100.PAGE18_SHA256,
            "page18_burned": True,
            "lineage31_burned": True,
            "retry_or_replay_authorized": False,
            "global_novelty_baseline_clause_count": GLOBAL_NOVELTY_BASELINE_CLAUSE_COUNT,
            "initial_artifact_count": PARENT_INITIAL_ARTIFACT_COUNT,
            "initial_artifacts_byte_equal_to_fresh_o1c100_regeneration": True,
        },
        "science_boundary": {
            "imported_science_attempt_id": PARENT_ATTEMPT_ID,
            "imported_native_fully_emitted_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
            "imported_native_globally_novel_clause_count": NEW_CHUNK_CLAUSE_COUNT,
            "certified_derived_resolution_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "resident_derived_resolution_clause_count": DERIVED_OVERLAY_CLAUSE_COUNT,
            "derived_occurrence_count": 0,
            "derived_clauses_are_native_emissions": False,
            "certified_logical_consequence": True,
            "attacker_valid_domain_reduction": 0,
            "attacker_valid_entropy_gain_bits": 0.0,
            "certified_model_or_key": False,
        },
        "rollover": {
            "stream_id": telemetry.stream_id,
            "telemetry_sha256": telemetry.artifact_sha256,
            "telemetry_serialized_bytes": PARENT_VAULT_TELEMETRY_BYTES,
            "native_chunk_sha256": chunk.sha256,
            "native_clause_count": chunk.clause_count,
            "native_literal_count": chunk.literal_count,
            "all_native_occurrences_unique": True,
            "all_native_occurrences_globally_novel_against_2074_clause_attic": True,
            "api": "advance_causal_residency(next_lineage_ordinal=32,next_active_limit=248)",
        },
        "emitted_causal_attic": {
            "chunk_count": len(base.attic.chunks),
            "union_sha256": base.attic.union_vault.sha256,
            "union_clause_count": base.attic.union_vault.clause_count,
            "union_literal_count": base.attic.union_vault.literal_count,
            "union_serialized_bytes": base.attic.union_vault.serialized_bytes,
            "occurrence_count": len(base.attic.occurrences),
            "derived_occurrence_count": 0,
            "duplicate_occurrence_count": base.attic.duplicate_occurrence_count,
            "strict_subsumption_pair_count": len(base.attic.relations),
            "undominated_clause_count": len(base.attic.undominated_indices),
            "derived_sidecars_excluded": True,
        },
        "logical_known_registry": {
            "emitted_clause_count": ATTIC_UNION_CLAUSE_COUNT,
            "derived_clause_count": DERIVED_CLOSURE_CLAUSE_COUNT,
            "combined_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
            "combined_sha256": composed.logical_known_sha256,
            "combined_literal_count": LOGICAL_KNOWN_LITERAL_COUNT,
            "combined_serialized_bytes": LOGICAL_KNOWN_SERIALIZED_BYTES,
            "emitted_inventory_sha256": composed.emitted_inventory_sha256,
            "derived_inventory_sha256": composed.derived_inventory_sha256,
            "combined_inventory_sha256": composed.combined_inventory_sha256,
            "inventory_artifact": DERIVED_RECEIPT_NAME,
            "next_global_novelty_baseline_clause_count": LOGICAL_KNOWN_CLAUSE_COUNT,
        },
        "derived_resolution": {
            "receipt_sha256": sha256_bytes(derived_receipt),
            "receipt_serialized_bytes": len(derived_receipt),
            "closure_sha256": closure.sha256,
            "closure_clause_count": closure.clause_count,
            "overlay_sha256": overlay.sha256,
            "overlay_clause_count": overlay.clause_count,
            "causal_attic_occurrence_rows_added": 0,
        },
        "page19": {
            "lineage_ordinal": PAGE19_LINEAGE_ORDINAL,
            "active_limit": PAGE19_ACTIVE_LIMIT,
            "active_sha256": composed.page.sha256,
            "clause_count": composed.page.clause_count,
            "literal_count": composed.page.literal_count,
            "serialized_bytes": composed.page.serialized_bytes,
            "category_counts": PAGE19_CATEGORY_COUNTS,
            "headroom": PAGE19_HEADROOM,
            "selected_emitted_clause_count": len(composed.selected_emitted_indices),
            "selected_derived_clause_count": DERIVED_OVERLAY_CLAUSE_COUNT,
            "displaced_emitted_union_indices": list(DISPLACED_EMITTED_UNION_INDICES),
            "pure_emitted_candidate_sha256": PAGE19_BASE_SHA256,
            "pure_emitted_candidate_activated": False,
            "fresh_identity": composed.page.sha256
            not in previous.state.used_active_sha256,
            "never_resident_undominated_clause_count": len(
                composed.never_resident_undominated_indices
            ),
            "native_capacity_proof": {
                "maximum_clause_count": O1C66_VAULT_CAPS.maximum_clauses,
                "page19_input_clauses": composed.page.clause_count,
                "maximum_additional_clauses_before_capacity_terminal": PAGE19_HEADROOM[
                    "clauses"
                ],
                "equal_parent_burst_clause_count": FULLY_EMITTED_OCCURRENCE_COUNT,
                "equal_parent_burst_fits_exactly": True,
                "literal_future_emission_safety_claimed": False,
                "serialized_byte_future_emission_safety_claimed": False,
            },
        },
        "final_priority_bank": {
            "sha256": FINAL_BANK_SHA256,
            "serialized_bytes": FINAL_BANK_BYTES,
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
        or (
            PREPARATION_MANIFEST_BYTES
            and len(manifest_payload) != PREPARATION_MANIFEST_BYTES
        )
        or (
            PREPARATION_MANIFEST_SHA256
            and sha256_bytes(manifest_payload) != PREPARATION_MANIFEST_SHA256
        )
    ):
        raise O1C102PreparationError("causal rollover manifest differs")
    artifacts[PREPARATION_MANIFEST_NAME] = manifest_payload
    return PreparedCausalRolloverArtifacts(
        state=base,
        artifacts=artifacts,
        manifest=manifest,
    )


def preflight_o1c102_page19_causal_rollover(
    *,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    return prepare_o1c102_page19_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )


def _validate_prepared_bundle_for_publication(
    prepared: PreparedCausalRolloverArtifacts,
) -> None:
    if not isinstance(prepared, PreparedCausalRolloverArtifacts):
        raise O1C102PreparationError("prepared Page-19 bundle differs")
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
        DERIVED_RECEIPT_NAME,
        DERIVED_CLOSURE_NAME,
        DERIVED_OVERLAY_NAME,
        PREPARATION_MANIFEST_NAME,
    }
    manifest = _mapping(prepared.manifest, "prepared Page-19 manifest")
    rows = _mapping(manifest.get("artifacts"), "prepared Page-19 artifact rows")
    manifest_payload = prepared.artifacts.get(PREPARATION_MANIFEST_NAME)
    exact_artifact_seals = {
        NEW_CHUNK_NAME: (NEW_CHUNK_SERIALIZED_BYTES, NEW_CHUNK_SHA256),
        ACTIVE_PROJECTION_NAME: (PAGE19_SERIALIZED_BYTES, PAGE19_SHA256),
        OCCURRENCES_NAME: (OCCURRENCE_DOCUMENT_BYTES, OCCURRENCE_DOCUMENT_SHA256),
        RELATIONS_NAME: (RELATION_DOCUMENT_BYTES, RELATION_DOCUMENT_SHA256),
        COMMON_CORE_AUDIT_NAME: (
            20_115,
            "2a14bc7382f90bb038223852fd8c5fcfb2c99145338800efead72cb6c1dbb83c",
        ),
        FINAL_BANK_NAME: (FINAL_BANK_BYTES, FINAL_BANK_SHA256),
        PRIORITY_RECEIPT_NAME: (PRIORITY_RECEIPT_BYTES, PRIORITY_RECEIPT_SHA256),
        DERIVED_CLOSURE_NAME: (DERIVED_CLOSURE_BYTES, DERIVED_CLOSURE_SHA256),
        DERIVED_OVERLAY_NAME: (DERIVED_OVERLAY_BYTES, DERIVED_OVERLAY_SHA256),
    }
    conditional_seals = {
        RESIDENCY_NAME: (
            PAGE19_RESIDENCY_DOCUMENT_BYTES,
            PAGE19_RESIDENCY_DOCUMENT_SHA256,
        ),
        ACTIVATION_LEDGER_NAME: (
            PAGE19_ACTIVATION_DOCUMENT_BYTES,
            PAGE19_ACTIVATION_DOCUMENT_SHA256,
        ),
        DERIVED_RECEIPT_NAME: (DERIVED_RECEIPT_BYTES, DERIVED_RECEIPT_SHA256),
        PREPARATION_MANIFEST_NAME: (
            PREPARATION_MANIFEST_BYTES,
            PREPARATION_MANIFEST_SHA256,
        ),
    }
    if (
        set(prepared.artifacts) != expected_names
        or manifest.get("schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or not isinstance(manifest_payload, bytes)
        or manifest_payload != canonical_json_bytes(manifest)
        or set(rows) != expected_names - {PREPARATION_MANIFEST_NAME}
        or prepared.state.active_projection.sha256 != PAGE19_BASE_SHA256
        or prepared.artifacts.get(ACTIVE_PROJECTION_NAME)
        == prepared.state.active_projection.serialized
        or prepared.artifacts.get(OCCURRENCES_NAME)
        != canonical_json_bytes(prepared.state.attic.occurrence_document())
        or prepared.artifacts.get(RELATIONS_NAME)
        != canonical_json_bytes(prepared.state.attic.relation_document())
    ):
        raise O1C102PreparationError("prepared Page-19 publication bundle differs")
    for name, (expected_bytes, expected_sha256) in exact_artifact_seals.items():
        payload = prepared.artifacts[name]
        if len(payload) != expected_bytes or sha256_bytes(payload) != expected_sha256:
            raise O1C102PreparationError("prepared Page-19 exact artifact seal differs")
    for name, (expected_bytes, expected_sha256) in conditional_seals.items():
        payload = prepared.artifacts[name]
        if expected_bytes and len(payload) != expected_bytes:
            raise O1C102PreparationError(
                "prepared Page-19 frozen artifact size differs"
            )
        if expected_sha256 and sha256_bytes(payload) != expected_sha256:
            raise O1C102PreparationError(
                "prepared Page-19 frozen artifact seal differs"
            )
    for name, row_value in rows.items():
        row = _mapping(row_value, f"prepared Page-19 artifact row {name}")
        payload = prepared.artifacts[name]
        role = row.get("role")
        if not isinstance(role, str) or not role or row != _artifact_row(payload, role):
            raise O1C102PreparationError("prepared Page-19 artifact row differs")


def write_prepared_o1c102_page19_causal_rollover(
    prepared: PreparedCausalRolloverArtifacts,
    output_dir: str | Path,
) -> None:
    _validate_prepared_bundle_for_publication(prepared)
    try:
        _publisher.write_prepared_o1c85_page10_transport_recovery(prepared, output_dir)
    except _publisher.O1C85PreparationError as exc:
        raise O1C102PreparationError("Page-19 publication failed") from exc


def prepare_and_write_o1c102_page19_causal_rollover(
    *,
    output_dir: str | Path,
    capsule_dir: str | Path | None = None,
    parent_result_path: str | Path | None = None,
) -> PreparedCausalRolloverArtifacts:
    prepared = prepare_o1c102_page19_causal_rollover(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
    )
    write_prepared_o1c102_page19_causal_rollover(prepared, output_dir)
    return prepared


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Preflight or prepare O1C-0102's zero-call Page-19 rollover"
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
        prepared = prepare_o1c102_page19_causal_rollover(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
        )
        if args.command == "prepare":
            write_prepared_o1c102_page19_causal_rollover(prepared, args.output_dir)
    except (O1C102PreparationError, CausalAtticError, CausalResidencyError) as exc:
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
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "DERIVED_CLOSURE_NAME",
    "DERIVED_OVERLAY_NAME",
    "DERIVED_RECEIPT_NAME",
    "FINAL_BANK_NAME",
    "NEW_CHUNK_NAME",
    "O1C102PreparationError",
    "OCCURRENCES_NAME",
    "PREPARATION_MANIFEST_NAME",
    "PRIORITY_RECEIPT_NAME",
    "PreparedCausalRolloverArtifacts",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "main",
    "preflight_o1c102_page19_causal_rollover",
    "prepare_and_write_o1c102_page19_causal_rollover",
    "prepare_o1c102_page19_causal_rollover",
    "write_prepared_o1c102_page19_causal_rollover",
]
