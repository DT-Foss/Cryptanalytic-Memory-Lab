"""Deterministic zero-call O1C-0080 Page-7 preparation.

The only admissible predecessor is the immutable completed O1C-0079 call.
This module verifies that capsule, its archived native and promoted ownership
evidence, and the additive zero-call erratum.  It then parses the real empty
vault-emission ledger and advances causal residency with one identity-bound
empty rollover chunk.  No failed-call reprojection, solver call, target, truth
key, reveal, refit, or scientific intent is involved.
"""

from __future__ import annotations

import argparse
import gzip
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAtticError,
    ClauseOccurrence,
    ParsedVaultTelemetry,
    canonical_json_bytes,
    parse_self_scoping_vault,
    parse_vault_telemetry,
    reproject_causal_attic,
    sha256_bytes,
)
from .causal_frontier_v1 import (
    CAUSAL_FRONTIER_PLAN_SCHEMA,
    CausalFrontierError,
    CausalFrontierPlan,
    derive_causal_frontier_plan,
    parse_causal_frontier_plan,
    serialize_causal_frontier_plan,
    validate_causal_frontier_plan,
)
from .causal_residency_v1 import (
    CausalResidencyError,
    CausalResidencyState,
    advance_causal_residency,
    replay_causal_residency,
    validate_activation_replay,
)
from .o1c79_apple8_decision_ownership_prepare import (
    EXPECTED_PREPARED_MANIFEST_SHA256 as O1C79_PREPARED_MANIFEST_SHA256,
)
from .o1c79_apple8_decision_ownership_prepare import (
    O1C79PreparationError,
    PreparedDecisionOwnership,
    _o1c78_derive_rank_decision,
    _publish_directory as _o1c79_publish_directory,
    load_prepared_decision_ownership,
)
from .rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
    parse_rescue_prefix_preemption_plan,
    validate_rescue_prefix_preemption_evidence,
    validate_rescue_prefix_preemption_plan,
)
from .residual_polarity_staging_v1 import (
    RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
    derive_residual_polarity_staging_plan,
    parse_residual_polarity_staging_plan,
    serialize_residual_polarity_staging_plan,
    validate_residual_polarity_staging_plan,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)
from .vault_ranked_decision_v1 import VaultRankedDecision


ATTEMPT_ID = "O1C-0080"
PARENT_ATTEMPT_ID = "O1C-0079"
PREPARATION_SCHEMA = "o1-256-apple8-bound-crossing-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-bound-crossing-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-bound-crossing-artifact-set-v1"
PARENT_RECEIPT_SCHEMA = "o1-256-o1c79-completed-call-consumption-receipt-v1"
SCIENCE_HISTORY_SCHEMA = "o1-256-o1c80-science-input-history-v1"
SCIENCE_INPUT_SCHEMA = "o1-256-apple8-bound-crossing-science-input-v1"
FRONTIER_PLAN_DOCUMENT_SCHEMA = "o1-256-apple8-bound-crossing-frontier-plan-document-v1"
STAGING_PLAN_DOCUMENT_SCHEMA = "o1-256-apple8-bound-crossing-staging-plan-document-v1"
PREFIX_PLAN_DOCUMENT_SCHEMA = (
    "o1-256-apple8-bound-crossing-inherited-prefix-plan-document-v1"
)

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_085738_O1C-0079_apple8-decision-ownership-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0079_APPLE8_DECISION_OWNERSHIP_RESULT_20260720.json"
)
DEFAULT_PARENT_ERRATUM_RELATIVE = Path(
    "research/O1C0079_APPLE8_DECISION_OWNERSHIP_ZERO_CALL_ERRATUM_20260720.json"
)
FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE = Path(
    "runs/20260720_013632_O1C-0076_apple8-causal-frontier-v1/"
    "episodes/00/native-result.json.gz"
)
PREFIX_SOURCE_NATIVE_GZIP_RELATIVE = Path(
    "runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1/"
    "episodes/00/native-result.json.gz"
)

CHUNK_NAMES = tuple(f"chunk-{index:02d}.vault" for index in range(11))
ACTIVE_PROJECTION_NAME = "page-07-active.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
RESIDENCY_NAME = "residency.json"
PARENT_RECEIPT_NAME = "o1c79-consumption-receipt.json"
SCIENCE_HISTORY_NAME = "science-input-history.json"
SCIENCE_INPUT_NAME = "science-input.json"
FRONTIER_PLAN_NAME = "frontier-plan.json"
FRONTIER_PLAN_BINARY_NAME = "frontier-plan.bin"
STAGING_PLAN_NAME = "staging-plan.json"
STAGING_PLAN_BINARY_NAME = "staging-plan.bin"
PREFIX_PLAN_NAME = "prefix-plan.json"
PREFIX_PLAN_BINARY_NAME = "prefix-plan.bin"
MANIFEST_NAME = "bound-crossing-preparation-manifest.json"

PARENT_RESULT_SHA256 = (
    "ce68d10eed83d9a0d90518c579f4e1841cd8a6791e4cd975d0d27a64bcc6251e"
)
PARENT_CAPSULE_MANIFEST_SHA256 = (
    "f7cd0de5ba58a59de913db88ba3e9ce2ae1b486a4e922700f65dff3aa5d39475"
)
PARENT_ERRATUM_SHA256 = (
    "b5c2465a532486aaf68a6a622f2312de29ec8a52ea6cea70c9d9c36f19985fa9"
)
PARENT_INVOCATION_SHA256 = (
    "1ead7e6168d9dbd1d6675c110735d8ca2bf16738866c8e31101f56d44f03152c"
)
PARENT_INTENT_SHA256 = (
    "ebbd476cc0f9476c1e22c3d2650baa55f5b031dbcd7e5adb582217f31c7b54c0"
)
PARENT_EPISODE_SHA256 = (
    "0c84d89f41c7d7419878060cbeb64e54d35b320d1a4e44d58501bc27a5d7f840"
)
PARENT_THREE_AXIS_SHA256 = (
    "cf7b024de9caf949255d136797d5394879fe487a854e5fbfc1b82bf7e25e7504"
)
PARENT_SOURCE_COMMIT = "8b058cbfe62d93d0263a275f4081982f382a4355"
CORRECTED_VALIDATOR_COMMIT = "665ea8260ae7127baabc83af2fe208080f6f58f9"
PARENT_CAPSULE_ENTRY_COUNT = 40
PARENT_RAW_CLASSIFICATION = "DECISION_OWNERSHIP_NO_ACTIVATION_NO_GAIN"
PARENT_RAW_STOP_REASON = "no-operational-ownership-prefix-or-science-gain"
PARENT_CORRECTED_CLASSIFICATION = "DECISION_OWNERSHIP_QUALIFIED_PREFIX_MECHANISM_ONLY"
PARENT_CORRECTED_STOP_REASON = "qualified-prefix-activation-without-science-gain"

PARENT_NATIVE_GZIP_SHA256 = (
    "ec75d6c336d9dbfeb243f9992f624c8c3a71cdb0b1322bc0a713076911aa0f65"
)
PARENT_NATIVE_RAW_SHA256 = (
    "acda128d4a4ebc32376de7fce3ef40de72e20539befebe56eaea4276a43fd283"
)
PARENT_NATIVE_GZIP_BYTES = 159_220
PARENT_NATIVE_RAW_BYTES = 1_928_031
PARENT_OWNERSHIP_GZIP_SHA256 = (
    "6403d8a674a5c563eb8e30fdcaabb5745122654a234dd1cb0b2ef77f90de34e3"
)
PARENT_OWNERSHIP_RAW_SHA256 = (
    "87e6476486fa02624fab9b6b6f84c00dded60fbcefef871475201439849d4a0b"
)
PARENT_OWNERSHIP_GZIP_BYTES = 132_920
PARENT_OWNERSHIP_RAW_BYTES = 1_791_935
PARENT_TELEMETRY_GZIP_SHA256 = (
    "043b3c51531614d19826133e7c74cf5f19b73685a6e9ab7f163daf4f9534b41e"
)
PARENT_TELEMETRY_RAW_SHA256 = (
    "24b5454d713be708a9e39aca6e2062e54278de2a5d1469c21d532d082e26957a"
)
PARENT_TELEMETRY_GZIP_BYTES = 1_096
PARENT_TELEMETRY_RAW_BYTES = 2_564

FRONTIER_SOURCE_NATIVE_GZIP_SHA256 = (
    "0ca67f629bfc62f62d3705c74f3fef44aff3d5e4646048798a7006c722d02658"
)
FRONTIER_SOURCE_NATIVE_RAW_SHA256 = (
    "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198"
)
FRONTIER_SOURCE_NATIVE_RAW_BYTES = 252_812
PREFIX_SOURCE_NATIVE_GZIP_SHA256 = (
    "e13e98d14af49978a8afaeebb36d4d854f21f92ffa29efcbec323e7a20ec5a15"
)
PREFIX_SOURCE_NATIVE_RAW_SHA256 = (
    "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0"
)
PREFIX_SOURCE_NATIVE_RAW_BYTES = 361_499

PAGE6_SHA256 = "69bde6adc23e9e89f97581175ecb85dc9f1d94cddc6d162dfb2f93f9d60f3846"
PAGE7_SHA256 = "92b6e547e143cdaf2f28fe731fd356bc69806926ee569205d6def432144258ff"
PAGE7_SELECTION_ORDER_SHA256 = (
    "776819396914179fe1a0ae9b443a6c0775e32c70bf36658b6dfe7043002dc723"
)
PAGE7_CLAUSE_COUNT = 256
PAGE7_LITERAL_COUNT = 663_409
PAGE7_SERIALIZED_BYTES = 2_654_851
PAGE7_CLAUSE_AGGREGATE_SHA256 = (
    "fe2897d271f164864b9a57c9e2963bbf6150f8d491864d020ad4e667a75c3582"
)
PAGE7_STATE_DOCUMENT_SHA256 = (
    "4ff5afc6039561d38767ca39384b07d7cbd2c9e99b425a4f53c4f6e6f58ba656"
)
PAGE7_ACTIVATION_LEDGER_SHA256 = (
    "92ef452b5c7028d67a8639372a9d79052f45edcf5c5099768a0cad65d65cba8c"
)
EMPTY_ROLLOVER_SHA256 = (
    "43377d8b5c116f2e3deac2064a16bbc526ae2c31bb2999c074084b81faa4ce94"
)
EMPTY_ROLLOVER_BYTES = 191
UNCHANGED_UNION_SHA256 = (
    "e99682c4d0c1cfb53a2b51284d810e5a0a07dd7023672549b8435a920d688307"
)
UNCHANGED_UNION_CLAUSES = 550
UNCHANGED_UNION_LITERALS = 1_488_224
UNCHANGED_OCCURRENCES = 558
EXPECTED_CHUNK_CLAUSE_COUNTS = (202, 311, 0, 37, 0, 0, 0, 0, 0, 0, 0)

FRONTIER_PLAN_BINARY_SHA256 = (
    "321582ee831aca3820af944d4a4ca700bbb3eff22f26b8f532b6c16d1498be95"
)
FRONTIER_PLAN_BINARY_BYTES = 4_479
STAGING_PLAN_BINARY_SHA256 = (
    "83a73291160b6232c6fb834185476b1e6a6d6c0774c0d8ea5b0a434d6833aac0"
)
STAGING_PLAN_BINARY_BYTES = 4_477
PREFIX_PLAN_BINARY_SHA256 = (
    "b5debc5f55f7cbc1e728d00ce1d14d0c437249793f8c10e8b80e614a00ed155c"
)
PREFIX_PLAN_BINARY_BYTES = 44

SCIENCE_INPUT_SHA256_HISTORY = (
    "fb7528bf1cccf76e57dfa34dd8d5b13a9c96b331dad9ebf4443e7caa45d6f2b7",
    "ccfad8b31582baf0b29506387daac84e34998848851ce37e6c072666992022e1",
    "78696f2b662beda4b371aa547350cc66b2105bc4dcaf0b982af2d1279e3012ed",
    "82b1512a393f9d595a1207253e2b623ee8ece9bd2f5b92f8283857c3dd9b2911",
    "db3acd5e6b7eb27529fd141a99865623530258f3aa2f7db6e84f03f16ecf4f0f",
    "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91",
    "b57e3091df7eca20137f4c63e3bc125aa8978c2ff183a7396de3a2a4a79acf33",
    "07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208",
    PAGE6_SHA256,
)

# Frozen after constructing the deterministic real-capsule preparation below.
EXPECTED_PARENT_RECEIPT_SHA256 = (
    "325bac1b6728ffad16ae918d452a7124b000878bb9a41401f5992e1101c736bd"
)
EXPECTED_SCIENCE_HISTORY_SHA256 = (
    "f40cd6869ec1c471c7152c50e741106ac99d334d47370797c181aa8297edfb1c"
)
EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256 = (
    "b6408cf247f56f16bbf784a07ddd312564f7eae4cac9c340ee42fd7c356ce685"
)
EXPECTED_STAGING_PLAN_DOCUMENT_SHA256 = (
    "81f4f6dd46b624f29f904fd69681df5cfa8f1a5bd9528f34a39fbf62f29f1c90"
)
EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256 = (
    "88239344bf0d33e332d7a3a76aef4ba2101472842e9e7ec8ad1f1dd9073128c1"
)
EXPECTED_SCIENCE_INPUT_SHA256 = (
    "b3596451285786ce6a57af5cb8e2669dfeccbe0872e3c4a5bb24dc2ed859757b"
)
EXPECTED_PREPARED_MANIFEST_SHA256 = (
    "b928d96502a67b24e1671b12166b6e92aed81fbf715c91a8695b7c88ad9cbba0"
)

_CAPSULE_REQUIRED_SHA256 = {
    "result.json": PARENT_RESULT_SHA256,
    "invocation.json": PARENT_INVOCATION_SHA256,
    "episodes/00/intent.json": PARENT_INTENT_SHA256,
    "episodes/00/episode.json": PARENT_EPISODE_SHA256,
    "episodes/00/three-axis-conclusion.json": PARENT_THREE_AXIS_SHA256,
    "episodes/00/native-result.json.gz": PARENT_NATIVE_GZIP_SHA256,
    "episodes/00/decision-ownership.json.gz": PARENT_OWNERSHIP_GZIP_SHA256,
    "episodes/00/vault-telemetry.json.gz": PARENT_TELEMETRY_GZIP_SHA256,
    "initial/decision-ownership-preparation-manifest.json": (
        O1C79_PREPARED_MANIFEST_SHA256
    ),
    "initial/page-06-active.bin": PAGE6_SHA256,
    "episodes/00/active-input.bin": PAGE6_SHA256,
}


class O1C80PreparationError(RuntimeError):
    """A sealed input, zero-emission advance, or Page-7 artifact differs."""


@dataclass(frozen=True)
class _ParentEvidence:
    prepared: PreparedDecisionOwnership
    result: Mapping[str, object]
    erratum: Mapping[str, object]
    invocation: Mapping[str, object]
    episode: Mapping[str, object]
    native: Mapping[str, object]
    ownership: Mapping[str, object]
    telemetry_document: Mapping[str, object]
    telemetry: ParsedVaultTelemetry


@dataclass(frozen=True)
class _PlanBundle:
    rank_decision: VaultRankedDecision
    frontier_plan: CausalFrontierPlan
    frontier_document: Mapping[str, object]
    frontier_binary: bytes
    staging_plan: ResidualPolarityStagingPlan
    staging_document: Mapping[str, object]
    staging_binary: bytes
    prefix_plan: RescuePrefixPreemptionPlan
    prefix_document: Mapping[str, object]
    prefix_binary: bytes


@dataclass(frozen=True)
class PreparedBoundCrossing:
    """Independently reconstructed Page-7 preparation."""

    directory: Path
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState
    parent_receipt: Mapping[str, object]
    science_input_history: Mapping[str, object]
    science_input: Mapping[str, object]
    frontier_plan: CausalFrontierPlan
    staging_plan: ResidualPolarityStagingPlan
    prefix_plan: RescuePrefixPreemptionPlan


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise O1C80PreparationError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise O1C80PreparationError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C80PreparationError(f"{field} differs")
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C80PreparationError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C80PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C80PreparationError(f"{field} is not a sealed regular file")
    return path


def _sealed_directory(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C80PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise O1C80PreparationError(f"{field} is not a sealed directory")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise O1C80PreparationError(f"{field} is unreadable") from exc


def _read_json_bytes(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C80PreparationError(f"{field} JSON differs") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C80PreparationError(f"{field} is not canonical")
    return document


def _parse_capsule_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C80PreparationError("parent capsule manifest differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C80PreparationError("parent capsule manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C80PreparationError("parent capsule manifest row differs")
        entries[relative] = digest
    if len(entries) != PARENT_CAPSULE_ENTRY_COUNT:
        raise O1C80PreparationError("parent capsule manifest inventory differs")
    return entries


def _validate_capsule_inventory(capsule: Path) -> dict[str, str]:
    path = _regular_file(capsule / "artifacts.sha256", "parent capsule manifest")
    payload = path.read_bytes()
    if sha256_bytes(payload) != PARENT_CAPSULE_MANIFEST_SHA256:
        raise O1C80PreparationError("parent capsule manifest differs")
    entries = _parse_capsule_manifest(payload)
    observed: dict[str, str] = {}
    for candidate in capsule.rglob("*"):
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise O1C80PreparationError("parent capsule inventory differs") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C80PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = candidate.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = sha256_bytes(candidate.read_bytes())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C80PreparationError("parent capsule contains a special file")
    if observed != entries or any(
        entries.get(relative) != digest
        for relative, digest in _CAPSULE_REQUIRED_SHA256.items()
    ):
        raise O1C80PreparationError("parent capsule inventory or digest differs")
    return entries


def _read_canonical_gzip(
    path: Path,
    *,
    field: str,
    gzip_sha256: str,
    gzip_bytes: int,
    raw_sha256: str,
    raw_bytes: int,
) -> tuple[bytes, Mapping[str, object]]:
    compressed = _regular_file(path, field).read_bytes()
    if len(compressed) != gzip_bytes or sha256_bytes(compressed) != gzip_sha256:
        raise O1C80PreparationError(f"{field} gzip differs")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C80PreparationError(f"{field} gzip differs") from exc
    if len(raw) != raw_bytes or sha256_bytes(raw) != raw_sha256:
        raise O1C80PreparationError(f"{field} raw evidence differs")
    return raw, _read_json_bytes(raw, field)


def _evidence_row(
    *,
    path: str,
    compressed_bytes: int,
    compressed_sha256: str,
    raw_bytes: int,
    raw_sha256: str,
) -> dict[str, object]:
    return {
        "compressed_bytes": compressed_bytes,
        "compressed_sha256": compressed_sha256,
        "compression": "gzip-9;mtime=0;empty-filename",
        "path": path,
        "schema": "o1-256-canonical-gzip-native-evidence-v1",
        "uncompressed_bytes": raw_bytes,
        "uncompressed_sha256": raw_sha256,
    }


def _validate_parent_evidence(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    parent_erratum_path: str | Path,
) -> _ParentEvidence:
    capsule = _sealed_directory(Path(capsule_dir), "parent capsule")
    entries = _validate_capsule_inventory(capsule)
    result_path = _regular_file(Path(parent_result_path), "parent result root")
    result_payload = result_path.read_bytes()
    if (
        sha256_bytes(result_payload) != PARENT_RESULT_SHA256
        or result_payload != (capsule / "result.json").read_bytes()
        or entries.get("result.json") != PARENT_RESULT_SHA256
    ):
        raise O1C80PreparationError("parent result binding differs")
    result = _read_json_bytes(result_payload, "parent result")
    erratum_path = _regular_file(Path(parent_erratum_path), "parent erratum root")
    erratum_payload = erratum_path.read_bytes()
    if sha256_bytes(erratum_payload) != PARENT_ERRATUM_SHA256:
        raise O1C80PreparationError("parent zero-call erratum differs")
    erratum = _read_json_bytes(erratum_payload, "parent zero-call erratum")

    invocation_payload = _regular_file(
        capsule / "invocation.json", "parent invocation"
    ).read_bytes()
    episode_payload = _regular_file(
        capsule / "episodes/00/episode.json", "parent episode"
    ).read_bytes()
    intent_payload = _regular_file(
        capsule / "episodes/00/intent.json", "parent intent"
    ).read_bytes()
    conclusion_payload = _regular_file(
        capsule / "episodes/00/three-axis-conclusion.json",
        "parent three-axis conclusion",
    ).read_bytes()
    invocation = _read_json_bytes(invocation_payload, "parent invocation")
    episode = _read_json_bytes(episode_payload, "parent episode")
    intent = _read_json_bytes(intent_payload, "parent intent")
    conclusion = _read_json_bytes(conclusion_payload, "parent conclusion")
    if (
        sha256_bytes(invocation_payload) != PARENT_INVOCATION_SHA256
        or sha256_bytes(episode_payload) != PARENT_EPISODE_SHA256
        or sha256_bytes(intent_payload) != PARENT_INTENT_SHA256
        or sha256_bytes(conclusion_payload) != PARENT_THREE_AXIS_SHA256
    ):
        raise O1C80PreparationError("parent completed call receipt differs")

    episode_dir = capsule / "episodes/00"
    native_raw, native = _read_canonical_gzip(
        episode_dir / "native-result.json.gz",
        field="parent native evidence",
        gzip_sha256=PARENT_NATIVE_GZIP_SHA256,
        gzip_bytes=PARENT_NATIVE_GZIP_BYTES,
        raw_sha256=PARENT_NATIVE_RAW_SHA256,
        raw_bytes=PARENT_NATIVE_RAW_BYTES,
    )
    ownership_raw, ownership = _read_canonical_gzip(
        episode_dir / "decision-ownership.json.gz",
        field="parent ownership evidence",
        gzip_sha256=PARENT_OWNERSHIP_GZIP_SHA256,
        gzip_bytes=PARENT_OWNERSHIP_GZIP_BYTES,
        raw_sha256=PARENT_OWNERSHIP_RAW_SHA256,
        raw_bytes=PARENT_OWNERSHIP_RAW_BYTES,
    )
    telemetry_raw, telemetry_document = _read_canonical_gzip(
        episode_dir / "vault-telemetry.json.gz",
        field="parent vault telemetry",
        gzip_sha256=PARENT_TELEMETRY_GZIP_SHA256,
        gzip_bytes=PARENT_TELEMETRY_GZIP_BYTES,
        raw_sha256=PARENT_TELEMETRY_RAW_SHA256,
        raw_bytes=PARENT_TELEMETRY_RAW_BYTES,
    )
    try:
        telemetry = parse_vault_telemetry(
            telemetry_raw,
            stream_id="o1c79-episode-00",
            expected_sha256=PARENT_TELEMETRY_RAW_SHA256,
        )
        prepared = load_prepared_decision_ownership(
            capsule / "initial",
            expected_manifest_sha256=O1C79_PREPARED_MANIFEST_SHA256,
        )
    except (CausalAtticError, O1C79PreparationError) as exc:
        raise O1C80PreparationError("parent Page-6 replay differs") from exc

    episodes = _sequence(result.get("episodes"), "parent result episodes")
    result_episode = _mapping(episodes[0], "parent result episode") if episodes else {}
    corrected_axes = _mapping(
        _mapping(erratum.get("correction"), "parent erratum correction").get(
            "corrected_axes"
        ),
        "parent corrected axes",
    )
    next_action = _mapping(erratum.get("next_action"), "parent next action")
    state = prepared.state
    zero_fields = (
        "fully_emitted_clause_count",
        "fully_emitted_literal_count",
        "emitted_new_clause_count",
        "emitted_new_literal_count",
        "emitted_input_duplicate_clause_count",
        "emitted_input_duplicate_literal_count",
        "emitted_current_duplicate_clause_count",
        "emitted_current_duplicate_literal_count",
        "terminal_empty_clause_count",
    )
    if (
        result.get("schema") != "o1-256-apple8-decision-ownership-result-v1"
        or result.get("attempt_id") != PARENT_ATTEMPT_ID
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or result.get("classification") != PARENT_RAW_CLASSIFICATION
        or result.get("stop_reason") != PARENT_RAW_STOP_REASON
        or len(episodes) != 1
        or result_episode != episode
        or episode.get("completed") is not True
        or episode.get("native_call_issued") is not True
        or episode.get("native_calls_consumed") != 1
        or episode.get("local_episode_ordinal") != 0
        or episode.get("lineage_call_ordinal") != 19
        or episode.get("requested_conflicts") != 128
        or episode.get("actual_conflicts") != 128
        or episode.get("billed_conflicts") != 128
        or episode.get("page6_burned") is not True
        or episode.get("lineage19_burned") is not True
        or episode.get("globally_novel_clause_count") != 0
        or episode.get("globally_novel_clause_sha256") != []
        or episode.get("native_evidence")
        != _evidence_row(
            path="native-result.json.gz",
            compressed_bytes=PARENT_NATIVE_GZIP_BYTES,
            compressed_sha256=PARENT_NATIVE_GZIP_SHA256,
            raw_bytes=PARENT_NATIVE_RAW_BYTES,
            raw_sha256=PARENT_NATIVE_RAW_SHA256,
        )
        or episode.get("decision_ownership_evidence")
        != _evidence_row(
            path="decision-ownership.json.gz",
            compressed_bytes=PARENT_OWNERSHIP_GZIP_BYTES,
            compressed_sha256=PARENT_OWNERSHIP_GZIP_SHA256,
            raw_bytes=PARENT_OWNERSHIP_RAW_BYTES,
            raw_sha256=PARENT_OWNERSHIP_RAW_SHA256,
        )
        or episode.get("vault_telemetry_evidence")
        != _evidence_row(
            path="vault-telemetry.json.gz",
            compressed_bytes=PARENT_TELEMETRY_GZIP_BYTES,
            compressed_sha256=PARENT_TELEMETRY_GZIP_SHA256,
            raw_bytes=PARENT_TELEMETRY_RAW_BYTES,
            raw_sha256=PARENT_TELEMETRY_RAW_SHA256,
        )
        or invocation.get("attempt_id") != PARENT_ATTEMPT_ID
        or invocation.get("maximum_native_solver_calls") != 1
        or invocation.get("lineage_call_ordinals") != [19]
        or invocation.get("local_episode_ordinals") != [0]
        or invocation.get("retry_authorized") is not False
        or invocation.get("sweep_authorized") is not False
        or intent.get("lineage_call_ordinal") != 19
        or intent.get("local_episode_ordinal") != 0
        or native.get("schema") != "o1-256-cadical-joint-score-sieve-result-v17"
        or native.get("vault") != telemetry_document
        or native.get("decision_ownership") != ownership
        or native_raw != canonical_json_bytes(native)
        or ownership_raw != canonical_json_bytes(ownership)
        or conclusion.get("operational_ownership")
        != episode.get("operational_ownership")
        or conclusion.get("qualified_prefix") != episode.get("qualified_prefix")
        or conclusion.get("science") != episode.get("science")
        or erratum.get("schema")
        != "o1-256-apple8-decision-ownership-zero-call-erratum-v1"
        or erratum.get("attempt_id") != PARENT_ATTEMPT_ID
        or erratum.get("classification") != PARENT_CORRECTED_CLASSIFICATION
        or erratum.get("corrected_stop_reason") != PARENT_CORRECTED_STOP_REASON
        or erratum.get("corrected_validator_commit") != CORRECTED_VALIDATOR_COMMIT
        or corrected_axes
        != {
            "operational_ownership_success": True,
            "qualified_prefix_activation": True,
            "science_gain": False,
        }
        or next_action.get("attempt_id") != ATTEMPT_ID
        or next_action.get("authorized") is not False
        or next_action.get("lineage_ordinal") != 20
        or next_action.get("page7_provisional_sha256") != PAGE7_SHA256
        or next_action.get("page7_selection_order_sha256")
        != PAGE7_SELECTION_ORDER_SHA256
        or next_action.get("page7_clause_count") != PAGE7_CLAUSE_COUNT
        or next_action.get("page7_literal_count") != PAGE7_LITERAL_COUNT
        or next_action.get("page7_fully_emitted_union_indices") != []
        or invocation.get("residency") != state.describe()
        or episode.get("residency") != state.describe()
        or episode.get("input_active_vault") != state.active_projection.describe()
        or state.current_projection.lineage_ordinal != 19
        or state.active_projection.sha256 != PAGE6_SHA256
        or len(state.attic.chunks) != 10
        or len(state.attic.occurrences) != UNCHANGED_OCCURRENCES
        or telemetry.input_identity != state.active_projection.identity
        or telemetry.input_vault_sha256 != PAGE6_SHA256
        or telemetry.input_clause_count != 256
        or telemetry.input_literal_count != 723_864
        or telemetry.input_serialized_bytes != 2_896_671
        or telemetry.occurrences != ()
        or telemetry_document.get("fully_emitted_clauses") != []
        or telemetry_document.get("fully_emitted_aggregate_sha256") != sha256_bytes(b"")
        or any(telemetry_document.get(field) != 0 for field in zero_fields)
        or telemetry_document.get("next_vault_sha256") != PAGE6_SHA256
        or telemetry_document.get("next_clause_count") != 256
    ):
        raise O1C80PreparationError("sealed O1C-0079 evidence contract differs")
    return _ParentEvidence(
        prepared=prepared,
        result=result,
        erratum=erratum,
        invocation=invocation,
        episode=episode,
        native=native,
        ownership=ownership,
        telemetry_document=telemetry_document,
        telemetry=telemetry,
    )


def _validate_successor_state(
    state: CausalResidencyState,
    *,
    previous_state: CausalResidencyState | None = None,
) -> None:
    projection = state.current_projection.describe()
    if (
        state.current_projection.lineage_ordinal != 20
        or state.active_projection.sha256 != PAGE7_SHA256
        or state.active_projection.clause_count != PAGE7_CLAUSE_COUNT
        or state.active_projection.literal_count != PAGE7_LITERAL_COUNT
        or state.active_projection.serialized_bytes != PAGE7_SERIALIZED_BYTES
        or state.active_projection.clause_aggregate_sha256
        != PAGE7_CLAUSE_AGGREGATE_SHA256
        or projection.get("selection_order_sha256") != PAGE7_SELECTION_ORDER_SHA256
        or sha256_bytes(canonical_json_bytes(state.describe()))
        != PAGE7_STATE_DOCUMENT_SHA256
        or sha256_bytes(canonical_json_bytes(state.activation_ledger_document()))
        != PAGE7_ACTIVATION_LEDGER_SHA256
        or state.attic.union_vault.sha256 != UNCHANGED_UNION_SHA256
        or state.attic.union_vault.clause_count != UNCHANGED_UNION_CLAUSES
        or state.attic.union_vault.literal_count != UNCHANGED_UNION_LITERALS
        or len(state.attic.occurrences) != UNCHANGED_OCCURRENCES
        or tuple(chunk.clause_count for chunk in state.attic.chunks)
        != EXPECTED_CHUNK_CLAUSE_COUNTS
        or len(state.attic.chunks) != 11
        or state.attic.chunks[-1].sha256 != EMPTY_ROLLOVER_SHA256
        or state.attic.chunks[-1].serialized_bytes != EMPTY_ROLLOVER_BYTES
        or PAGE7_SHA256 in SCIENCE_INPUT_SHA256_HISTORY
        or PAGE6_SHA256 not in SCIENCE_INPUT_SHA256_HISTORY
    ):
        raise O1C80PreparationError("frozen Page-7 successor differs")
    if previous_state is not None and (
        state.attic.chunks != (*previous_state.attic.chunks, state.attic.chunks[-1])
        or state.attic.occurrences != previous_state.attic.occurrences
        or state.attic.relations != previous_state.attic.relations
        or state.attic.union_vault != previous_state.attic.union_vault
        or len(state.activation_ledger) != len(previous_state.activation_ledger) + 1
        or state.activation_ledger[:-1] != previous_state.activation_ledger
    ):
        raise O1C80PreparationError("Page-7 advance rewrote immutable evidence")
    validate_activation_replay(state)


def _advance_successor(
    previous_state: CausalResidencyState, telemetry: ParsedVaultTelemetry
) -> CausalResidencyState:
    if (
        previous_state.current_projection.lineage_ordinal != 19
        or previous_state.active_projection.sha256 != PAGE6_SHA256
        or telemetry.input_vault_sha256 != PAGE6_SHA256
        or telemetry.occurrences != ()
    ):
        raise O1C80PreparationError("Page-7 advance source differs")
    rollover = ThresholdNoGoodVault(
        previous_state.active_projection.identity,
        previous_state.active_projection.observed_variables,
        (),
    )
    if (
        rollover.sha256 != EMPTY_ROLLOVER_SHA256
        or rollover.clause_count != 0
        or rollover.literal_count != 0
        or rollover.serialized_bytes != EMPTY_ROLLOVER_BYTES
    ):
        raise O1C80PreparationError("identity-bound empty rollover differs")
    try:
        state = advance_causal_residency(
            previous_state,
            chunk=rollover,
            occurrences=telemetry.occurrences,
            next_lineage_ordinal=20,
        )
    except CausalResidencyError as exc:
        raise O1C80PreparationError("Page-7 causal-residency advance differs") from exc
    if state.active_projection.sha256 == PAGE6_SHA256:
        raise O1C80PreparationError("Page 6 cannot be reused")
    _validate_successor_state(state, previous_state=previous_state)
    return state


def _read_native_source(
    path: Path,
    *,
    field: str,
    expected_gzip_sha256: str,
    expected_raw_sha256: str,
    expected_raw_bytes: int,
) -> bytes:
    compressed = _regular_file(path, field).read_bytes()
    if sha256_bytes(compressed) != expected_gzip_sha256:
        raise O1C80PreparationError(f"{field} gzip differs")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C80PreparationError(f"{field} gzip differs") from exc
    if len(raw) != expected_raw_bytes or sha256_bytes(raw) != expected_raw_sha256:
        raise O1C80PreparationError(f"{field} raw result differs")
    _read_json_bytes(raw, field)
    return raw


def _frontier_plan_document(plan: CausalFrontierPlan) -> dict[str, object]:
    return {
        "schema": FRONTIER_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": CAUSAL_FRONTIER_PLAN_SCHEMA,
        "lineage_ordinal": 20,
        "plan": plan.describe(),
        "derivation": "deterministic-closest-unsatisfied-clause-on-page7",
        "source_native_gzip_sha256": FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE7_SHA256,
        "page6_plan_bytes_copied": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _staging_plan_document(
    plan: ResidualPolarityStagingPlan, *, frontier_plan: CausalFrontierPlan
) -> dict[str, object]:
    return {
        "schema": STAGING_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
        "lineage_ordinal": 20,
        "plan": plan.describe(),
        "derivation": "deterministic-page7-residual-polarity-overlay",
        "source_native_gzip_sha256": FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE7_SHA256,
        "parent_frontier_plan_sha256": frontier_plan.sha256,
        "overlay_rank_indices_zero_based": [224, 226],
        "page6_plan_bytes_copied": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _prefix_plan_document(
    plan: RescuePrefixPreemptionPlan, *, staging_plan: ResidualPolarityStagingPlan
) -> dict[str, object]:
    return {
        "schema": PREFIX_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": plan.describe().get("schema"),
        "lineage_ordinal": 20,
        "plan": plan.describe(),
        "derivation": "static-content-inherited;fresh-page7-evidence-cross-binding",
        "source_native_gzip_sha256": PREFIX_SOURCE_NATIVE_GZIP_SHA256,
        "source_result_sha256": PREFIX_SOURCE_NATIVE_RAW_SHA256,
        "active_vault_sha256": PAGE7_SHA256,
        "parent_staging_plan_sha256": staging_plan.sha256,
        "baseline_trace_sha256": O1C78_BASELINE_TRACE_SHA256,
        "static_legacy_selector_required_by_native_contract": True,
        "content_inherited_unchanged": True,
        "binary_content_identity_with_page6_allowed": True,
        "page6_plan_document_copied": False,
        "fresh_page7_cross_binding_validated": True,
        "tuned_for_page7": False,
        "refit": False,
        "new_science_claim": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _validate_plan_bundle(
    state: CausalResidencyState,
    bundle: _PlanBundle,
    *,
    prefix_source: bytes,
) -> None:
    try:
        validate_causal_frontier_plan(
            bundle.frontier_plan, active_vault=state.active_projection
        )
        validate_residual_polarity_staging_plan(
            bundle.staging_plan,
            active_vault=state.active_projection,
            rank_decision=bundle.rank_decision,
        )
        validate_rescue_prefix_preemption_plan(
            bundle.prefix_plan, active_vault=state.active_projection
        )
        validate_rescue_prefix_preemption_evidence(
            bundle.prefix_plan,
            source_result=prefix_source,
            source_result_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=bundle.staging_plan.sha256,
            baseline_trace_sha256=O1C78_BASELINE_TRACE_SHA256,
        )
        parsed_frontier = parse_causal_frontier_plan(
            bundle.frontier_binary, active_vault=state.active_projection
        )
        parsed_staging = parse_residual_polarity_staging_plan(
            bundle.staging_binary,
            active_vault=state.active_projection,
            rank_decision=bundle.rank_decision,
        )
        parsed_prefix = parse_rescue_prefix_preemption_plan(
            bundle.prefix_binary, active_vault=state.active_projection
        )
    except (
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C80PreparationError("Page-7 plan validation differs") from exc
    if (
        parsed_frontier != bundle.frontier_plan
        or parsed_staging != bundle.staging_plan
        or parsed_prefix != bundle.prefix_plan
        or bundle.frontier_plan.active_vault_sha256 != PAGE7_SHA256
        or bundle.frontier_plan.selected_active_index != 232
        or bundle.frontier_plan.selected_union_index != 526
        or bundle.frontier_plan.sha256 != FRONTIER_PLAN_BINARY_SHA256
        or len(bundle.frontier_binary) != FRONTIER_PLAN_BINARY_BYTES
        or bundle.staging_plan.active_vault_sha256 != PAGE7_SHA256
        or bundle.staging_plan.parent_frontier_plan_sha256
        != FRONTIER_PLAN_BINARY_SHA256
        or bundle.staging_plan.sha256 != STAGING_PLAN_BINARY_SHA256
        or len(bundle.staging_binary) != STAGING_PLAN_BINARY_BYTES
        or tuple(row.rank_index for row in bundle.staging_plan.overlays) != (224, 226)
        or bundle.prefix_plan.prefix_literals != O1C78_PREFIX_LITERALS
        or bundle.prefix_plan.sha256 != PREFIX_PLAN_BINARY_SHA256
        or len(bundle.prefix_binary) != PREFIX_PLAN_BINARY_BYTES
        or bundle.frontier_document != _frontier_plan_document(bundle.frontier_plan)
        or sha256_bytes(canonical_json_bytes(bundle.frontier_document))
        != EXPECTED_FRONTIER_PLAN_DOCUMENT_SHA256
        or bundle.staging_document
        != _staging_plan_document(
            bundle.staging_plan, frontier_plan=bundle.frontier_plan
        )
        or sha256_bytes(canonical_json_bytes(bundle.staging_document))
        != EXPECTED_STAGING_PLAN_DOCUMENT_SHA256
        or bundle.prefix_document
        != _prefix_plan_document(bundle.prefix_plan, staging_plan=bundle.staging_plan)
        or sha256_bytes(canonical_json_bytes(bundle.prefix_document))
        != EXPECTED_PREFIX_PLAN_DOCUMENT_SHA256
    ):
        raise O1C80PreparationError("frozen Page-7 plan bundle differs")


def _derive_plan_bundle(
    state: CausalResidencyState,
    *,
    parent: PreparedDecisionOwnership,
    frontier_source_path: Path,
    prefix_source_path: Path,
) -> _PlanBundle:
    frontier_source = _read_native_source(
        frontier_source_path,
        field="frontier/staging source",
        expected_gzip_sha256=FRONTIER_SOURCE_NATIVE_GZIP_SHA256,
        expected_raw_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
        expected_raw_bytes=FRONTIER_SOURCE_NATIVE_RAW_BYTES,
    )
    prefix_source = _read_native_source(
        prefix_source_path,
        field="inherited prefix source",
        expected_gzip_sha256=PREFIX_SOURCE_NATIVE_GZIP_SHA256,
        expected_raw_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
        expected_raw_bytes=PREFIX_SOURCE_NATIVE_RAW_BYTES,
    )
    try:
        rank_decision = _o1c78_derive_rank_decision(state)
        frontier_plan = derive_causal_frontier_plan(
            source_result=frontier_source,
            source_result_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            selected_union_indices=state.current_projection.selected_union_indices,
        )
        frontier_binary = serialize_causal_frontier_plan(frontier_plan)
        staging_plan = derive_residual_polarity_staging_plan(
            source_result=frontier_source,
            source_result_sha256=FRONTIER_SOURCE_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
            parent_frontier_plan_sha256=frontier_plan.sha256,
            selected_active_index=frontier_plan.selected_active_index,
            selected_union_index=frontier_plan.selected_union_index,
            overlay_rank_indices=(224, 226),
        )
        staging_binary = serialize_residual_polarity_staging_plan(staging_plan)
        prefix_binary = parent.prefix_plan_binary
        prefix_plan = parse_rescue_prefix_preemption_plan(
            prefix_binary, active_vault=state.active_projection
        )
    except (
        O1C79PreparationError,
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C80PreparationError("Page-7 plan derivation differs") from exc
    bundle = _PlanBundle(
        rank_decision=rank_decision,
        frontier_plan=frontier_plan,
        frontier_document=_frontier_plan_document(frontier_plan),
        frontier_binary=frontier_binary,
        staging_plan=staging_plan,
        staging_document=_staging_plan_document(
            staging_plan, frontier_plan=frontier_plan
        ),
        staging_binary=staging_binary,
        prefix_plan=prefix_plan,
        prefix_document=_prefix_plan_document(prefix_plan, staging_plan=staging_plan),
        prefix_binary=prefix_binary,
    )
    _validate_plan_bundle(state, bundle, prefix_source=prefix_source)
    return bundle


def _parent_receipt_document() -> dict[str, object]:
    return {
        "schema": PARENT_RECEIPT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "parent_attempt_id": PARENT_ATTEMPT_ID,
        "immutable_evidence_sha256": {
            "raw_result": PARENT_RESULT_SHA256,
            "capsule_manifest": PARENT_CAPSULE_MANIFEST_SHA256,
            "zero_call_erratum": PARENT_ERRATUM_SHA256,
            "native_gzip": PARENT_NATIVE_GZIP_SHA256,
            "native_raw": PARENT_NATIVE_RAW_SHA256,
            "ownership_gzip": PARENT_OWNERSHIP_GZIP_SHA256,
            "ownership_raw": PARENT_OWNERSHIP_RAW_SHA256,
            "vault_telemetry_gzip": PARENT_TELEMETRY_GZIP_SHA256,
            "vault_telemetry_raw": PARENT_TELEMETRY_RAW_SHA256,
        },
        "raw_archive": {
            "classification": PARENT_RAW_CLASSIFICATION,
            "stop_reason": PARENT_RAW_STOP_REASON,
            "operational_ownership_success": False,
            "qualified_prefix_activation": False,
            "science_gain": False,
            "bytes_modified": False,
        },
        "corrected_interpretation": {
            "classification": PARENT_CORRECTED_CLASSIFICATION,
            "stop_reason": PARENT_CORRECTED_STOP_REASON,
            "operational_ownership_success": True,
            "qualified_prefix_activation": True,
            "science_gain": False,
            "method": "additive-zero-call-erratum",
        },
        "consumption": {
            "local_episode_ordinal": 0,
            "lineage_call_ordinal": 19,
            "science_input_sha256": PAGE6_SHA256,
            "native_call_issued": True,
            "native_calls_consumed": 1,
            "native_result_returned": True,
            "requested_conflicts": 128,
            "actual_conflicts": 128,
            "billed_conflicts": 128,
            "page6_burned": True,
            "retry_authorized": False,
        },
        "emission_import": {
            "telemetry_parsed": True,
            "fully_emitted_union_indices": [],
            "fully_emitted_clause_count": 0,
            "fully_emitted_literal_count": 0,
            "new_occurrence_count": 0,
            "rollover_chunk_sha256": EMPTY_ROLLOVER_SHA256,
            "rollover_clause_count": 0,
            "rollover_occurrence_count": 0,
            "rollover_emission_count": 0,
            "advance_api": "advance_causal_residency",
            "failed_call_reprojection_used": False,
            "synthetic_evidence_created": False,
        },
        "truth_key_bytes_read": False,
        "reveal_calls": 0,
        "refits": 0,
    }


def _science_history_document() -> dict[str, object]:
    return {
        "schema": SCIENCE_HISTORY_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "history_order": "chronological-consumption-order",
        "science_input_count": len(SCIENCE_INPUT_SHA256_HISTORY),
        "science_input_sha256": list(SCIENCE_INPUT_SHA256_HISTORY),
        "o1c79_consumed_sha256": PAGE6_SHA256,
        "o1c79_consumed_lineage_ordinal": 19,
        "next_active_sha256": PAGE7_SHA256,
        "next_lineage_ordinal": 20,
        "next_active_absent_from_history": True,
        "all_history_entries_unique": True,
        "page6_replay_authorized": False,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
    }


def _science_input_document(
    *,
    bundle: _PlanBundle,
    parent_receipt_sha256: str,
    science_history_sha256: str,
) -> dict[str, object]:
    return {
        "schema": SCIENCE_INPUT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "lineage_call_ordinal": 20,
        "active_vault_sha256": PAGE7_SHA256,
        "rank_source_sha256": "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858",
        "frontier_plan_sha256": bundle.frontier_plan.sha256,
        "frontier_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.frontier_document)
        ),
        "staging_plan_sha256": bundle.staging_plan.sha256,
        "staging_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.staging_document)
        ),
        "prefix_plan_sha256": bundle.prefix_plan.sha256,
        "prefix_plan_document_sha256": sha256_bytes(
            canonical_json_bytes(bundle.prefix_document)
        ),
        "prefix_content_inherited_unchanged": True,
        "prefix_page7_cross_binding_validated": True,
        "parent_receipt_sha256": parent_receipt_sha256,
        "science_history_sha256": science_history_sha256,
        "page6_frontier_or_staging_plan_bytes_reused": False,
        "page6_science_input_reused": False,
        "science_call_authorized": False,
        "intent_created": False,
        "page_burned": False,
        "native_solver_calls": 0,
        "truth_key_bytes_read": False,
    }


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _roles() -> dict[str, str]:
    return {
        **{
            name: (
                "identity-bound-empty-o1c79-rollover-receipt"
                if name == CHUNK_NAMES[-1]
                else "unchanged-immutable-causal-attic-chunk"
            )
            for name in CHUNK_NAMES
        },
        ACTIVE_PROJECTION_NAME: "fresh-unused-page7-science-input",
        OCCURRENCES_NAME: "unchanged-complete-witness-occurrence-ledger",
        RELATIONS_NAME: "unchanged-complete-strict-subsumption-closure",
        ACTIVATION_LEDGER_NAME: "lineage20-causal-residency-ledger",
        RESIDENCY_NAME: "lineage20-complete-causal-residency-state",
        PARENT_RECEIPT_NAME: "sealed-o1c79-call-and-zero-emission-receipt",
        SCIENCE_HISTORY_NAME: "complete-nine-input-consumption-history",
        SCIENCE_INPUT_NAME: "page7-cross-bound-target-free-science-input",
        FRONTIER_PLAN_NAME: "fresh-page7-derived-frontier-plan-document",
        FRONTIER_PLAN_BINARY_NAME: "fresh-page7-native-frontier-plan",
        STAGING_PLAN_NAME: "fresh-page7-derived-staging-plan-document",
        STAGING_PLAN_BINARY_NAME: "fresh-page7-native-staging-plan",
        PREFIX_PLAN_NAME: "fresh-page7-binding-of-static-legacy-prefix",
        PREFIX_PLAN_BINARY_NAME: "inherited-static-prefix-content-not-refit",
    }


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    try:
        _o1c79_publish_directory(output_dir, files)
    except O1C79PreparationError as exc:
        raise O1C80PreparationError(str(exc)) from exc


def _build_successor(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    parent_erratum_path: str | Path,
    frontier_source_path: str | Path | None = None,
    prefix_source_path: str | Path | None = None,
) -> tuple[dict[str, object], dict[str, bytes], CausalResidencyState, _PlanBundle]:
    evidence = _validate_parent_evidence(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
        parent_erratum_path=parent_erratum_path,
    )
    state = _advance_successor(evidence.prepared.state, evidence.telemetry)
    root = lab_root()
    bundle = _derive_plan_bundle(
        state,
        parent=evidence.prepared,
        frontier_source_path=_regular_file(
            Path(frontier_source_path)
            if frontier_source_path is not None
            else root / FRONTIER_SOURCE_NATIVE_GZIP_RELATIVE,
            "frontier/staging source root",
        ).resolve(strict=True),
        prefix_source_path=_regular_file(
            Path(prefix_source_path)
            if prefix_source_path is not None
            else root / PREFIX_SOURCE_NATIVE_GZIP_RELATIVE,
            "inherited prefix source root",
        ).resolve(strict=True),
    )
    parent_receipt = _parent_receipt_document()
    parent_receipt_payload = canonical_json_bytes(parent_receipt)
    science_history = _science_history_document()
    science_history_payload = canonical_json_bytes(science_history)
    science_input = _science_input_document(
        bundle=bundle,
        parent_receipt_sha256=sha256_bytes(parent_receipt_payload),
        science_history_sha256=sha256_bytes(science_history_payload),
    )
    if (
        sha256_bytes(parent_receipt_payload) != EXPECTED_PARENT_RECEIPT_SHA256
        or sha256_bytes(science_history_payload) != EXPECTED_SCIENCE_HISTORY_SHA256
        or sha256_bytes(canonical_json_bytes(science_input))
        != EXPECTED_SCIENCE_INPUT_SHA256
    ):
        raise O1C80PreparationError("frozen Page-7 receipt/input differs")
    artifacts: dict[str, bytes] = {
        **{
            name: chunk.serialized
            for name, chunk in zip(CHUNK_NAMES, state.attic.chunks, strict=True)
        },
        ACTIVE_PROJECTION_NAME: state.active_projection.serialized,
        OCCURRENCES_NAME: canonical_json_bytes(state.attic.occurrence_document()),
        RELATIONS_NAME: canonical_json_bytes(state.attic.relation_document()),
        ACTIVATION_LEDGER_NAME: canonical_json_bytes(
            state.activation_ledger_document()
        ),
        RESIDENCY_NAME: canonical_json_bytes(state.describe()),
        PARENT_RECEIPT_NAME: parent_receipt_payload,
        SCIENCE_HISTORY_NAME: science_history_payload,
        SCIENCE_INPUT_NAME: canonical_json_bytes(science_input),
        FRONTIER_PLAN_NAME: canonical_json_bytes(bundle.frontier_document),
        FRONTIER_PLAN_BINARY_NAME: bundle.frontier_binary,
        STAGING_PLAN_NAME: canonical_json_bytes(bundle.staging_document),
        STAGING_PLAN_BINARY_NAME: bundle.staging_binary,
        PREFIX_PLAN_NAME: canonical_json_bytes(bundle.prefix_document),
        PREFIX_PLAN_BINARY_NAME: bundle.prefix_binary,
    }
    roles = _roles()
    rows = {
        name: _artifact_row(payload, roles[name])
        for name, payload in sorted(artifacts.items())
    }
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "preparation_schema": PREPARATION_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "zero_call": {
            "native_solver_calls": 0,
            "science_calls": 0,
            "public_verification_calls": 0,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
            "mps_or_gpu_calls": 0,
        },
        "authorization": {
            "science_call_authorized": False,
            "intent_created": False,
            "page7_burned": False,
            "lineage20_burned": False,
            "page6_replay_authorized": False,
        },
        "parent_receipt": parent_receipt,
        "projection_contract": {
            "source_lineage_ordinal": 19,
            "source_active_sha256": PAGE6_SHA256,
            "next_lineage_ordinal": 20,
            "next_active_sha256": PAGE7_SHA256,
            "next_selection_order_sha256": PAGE7_SELECTION_ORDER_SHA256,
            "advance_api": "advance_causal_residency",
            "empty_rollover_sha256": EMPTY_ROLLOVER_SHA256,
            "empty_rollover_clause_count": 0,
            "empty_rollover_occurrence_count": 0,
            "empty_rollover_emission_count": 0,
            "fully_emitted_union_indices": [],
            "attic_chunk_count_before": 10,
            "attic_chunk_count_after": 11,
            "occurrence_count_before": UNCHANGED_OCCURRENCES,
            "occurrence_count_after": UNCHANGED_OCCURRENCES,
            "unchanged_union_sha256": UNCHANGED_UNION_SHA256,
            "failed_call_reprojection_used": False,
            "synthetic_evidence_created": False,
            "page6_replay_authorized": False,
        },
        "science_input_history": science_history,
        "science_input": science_input,
        "frontier_plan": dict(bundle.frontier_document),
        "staging_plan": dict(bundle.staging_document),
        "prefix_plan": dict(bundle.prefix_document),
        "residency": state.describe(),
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifact_count": len(rows),
            "artifacts": rows,
        },
    }
    return manifest, artifacts, state, bundle


def prepare_o1c80_bound_crossing(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    parent_erratum_path: str | Path,
    output_dir: str | Path,
    frontier_source_path: str | Path | None = None,
    prefix_source_path: str | Path | None = None,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Atomically publish the exact zero-call Page-7 successor."""

    if enforce_release_contract is not True:
        raise O1C80PreparationError("release-contract flag must remain true")
    manifest, artifacts, _, _ = _build_successor(
        capsule_dir=capsule_dir,
        parent_result_path=parent_result_path,
        parent_erratum_path=parent_erratum_path,
        frontier_source_path=frontier_source_path,
        prefix_source_path=prefix_source_path,
    )
    payload = canonical_json_bytes(manifest)
    if sha256_bytes(payload) != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise O1C80PreparationError("frozen bound-crossing manifest identity differs")
    _publish_directory(Path(output_dir), {**artifacts, MANIFEST_NAME: payload})
    return manifest


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "prepared occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C80PreparationError("prepared occurrence schema differs")
    records = _sequence(document.get("records"), "prepared occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "prepared occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "prepared occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C80PreparationError("prepared occurrence ordinal differs")
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=_nonnegative_int(
                    row.get("source_index"), "prepared occurrence source index"
                ),
                classification=cast(str, row.get("classification")),
                source=cast(str, row.get("source")),
                witness_score_f64le_hex=cast(str, row.get("witness_score_f64le_hex")),
                clause=clauses[union_index],
                clause_sha256=cast(str, row.get("clause_sha256")),
                witness_sha256=cast(str, row.get("witness_sha256")),
            )
        except (CausalAtticError, TypeError) as exc:
            raise O1C80PreparationError("prepared occurrence record differs") from exc
        if occurrence.describe(ordinal=ordinal, union_clause_index=union_index) != dict(
            row
        ):
            raise O1C80PreparationError("prepared occurrence record differs")
        occurrences.append(occurrence)
    if document.get("occurrence_count") != len(occurrences) or document.get(
        "unique_clause_count"
    ) != len(clauses):
        raise O1C80PreparationError("prepared occurrence ledger differs")
    return tuple(occurrences)


def load_prepared_bound_crossing(
    directory: str | Path,
    *,
    expected_manifest_sha256: str,
    prefix_source_path: str | Path | None = None,
) -> PreparedBoundCrossing:
    """Reconstruct and cross-validate every published Page-7 artifact."""

    prepared = _sealed_directory(Path(directory), "prepared bound-crossing root")
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if expected != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise O1C80PreparationError("prepared manifest freeze differs")
    manifest_payload = _regular_file(
        prepared / MANIFEST_NAME, "prepared manifest"
    ).read_bytes()
    if sha256_bytes(manifest_payload) != expected:
        raise O1C80PreparationError("prepared bound-crossing manifest differs")
    manifest = _read_json_bytes(manifest_payload, "prepared manifest")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("preparation_schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C80PreparationError("prepared manifest contract differs")
    artifact_set = _mapping(manifest.get("artifact_set"), "prepared artifact set")
    rows = _mapping(artifact_set.get("artifacts"), "prepared artifacts")
    roles = _roles()
    expected_names = set(roles)
    actual = tuple(prepared.iterdir())
    if (
        set(rows) != expected_names
        or artifact_set.get("schema") != ARTIFACT_SET_SCHEMA
        or artifact_set.get("artifact_count") != len(expected_names)
        or {path.name for path in actual} != expected_names | {MANIFEST_NAME}
        or any(path.is_symlink() or not path.is_file() for path in actual)
    ):
        raise O1C80PreparationError("prepared directory inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(expected_names):
        row = _mapping(rows[name], f"prepared artifact {name}")
        payload = _regular_file(
            prepared / name, f"prepared artifact {name}"
        ).read_bytes()
        if (
            row.get("role") != roles[name]
            or row.get("sha256") != sha256_bytes(payload)
            or row.get("serialized_bytes") != len(payload)
        ):
            raise O1C80PreparationError(f"prepared artifact {name} differs")
        payloads[name] = payload

    try:
        rank = parse_self_scoping_vault(payloads[CHUNK_NAMES[0]])
        chunks = [rank]
        for name in CHUNK_NAMES[1:]:
            chunks.append(
                parse_threshold_no_good_vault(
                    payloads[name],
                    observed_variables=rank.observed_variables,
                    caps=O1C66_VAULT_CAPS,
                )
            )
        union_clauses: list[ThresholdNoGoodClause] = []
        known: set[bytes] = set()
        for chunk in chunks:
            for clause in chunk.clauses:
                if clause.serialized not in known:
                    known.add(clause.serialized)
                    union_clauses.append(clause)
        occurrence_document = _read_json_bytes(
            payloads[OCCURRENCES_NAME], "prepared occurrences"
        )
        occurrences = _parse_occurrence_document(
            occurrence_document, clauses=tuple(union_clauses)
        )
        attic = reproject_causal_attic(tuple(chunks), occurrences, active_limit=256)
        residency_document = _read_json_bytes(
            payloads[RESIDENCY_NAME], "prepared residency"
        )
        state = replay_causal_residency(attic, residency_document)
        active = parse_threshold_no_good_vault(
            payloads[ACTIVE_PROJECTION_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
        rank_decision = _o1c78_derive_rank_decision(state)
        frontier_plan = parse_causal_frontier_plan(
            payloads[FRONTIER_PLAN_BINARY_NAME], active_vault=state.active_projection
        )
        staging_plan = parse_residual_polarity_staging_plan(
            payloads[STAGING_PLAN_BINARY_NAME],
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        prefix_plan = parse_rescue_prefix_preemption_plan(
            payloads[PREFIX_PLAN_BINARY_NAME], active_vault=state.active_projection
        )
    except (
        CausalAtticError,
        CausalResidencyError,
        ThresholdNoGoodVaultError,
        O1C79PreparationError,
        CausalFrontierError,
        ResidualPolarityStagingError,
        RescuePrefixPreemptionError,
    ) as exc:
        raise O1C80PreparationError(
            "prepared bound-crossing reconstruction differs"
        ) from exc

    frontier_document = _read_json_bytes(
        payloads[FRONTIER_PLAN_NAME], "prepared frontier plan"
    )
    staging_document = _read_json_bytes(
        payloads[STAGING_PLAN_NAME], "prepared staging plan"
    )
    prefix_document = _read_json_bytes(
        payloads[PREFIX_PLAN_NAME], "prepared prefix plan"
    )
    bundle = _PlanBundle(
        rank_decision=rank_decision,
        frontier_plan=frontier_plan,
        frontier_document=frontier_document,
        frontier_binary=payloads[FRONTIER_PLAN_BINARY_NAME],
        staging_plan=staging_plan,
        staging_document=staging_document,
        staging_binary=payloads[STAGING_PLAN_BINARY_NAME],
        prefix_plan=prefix_plan,
        prefix_document=prefix_document,
        prefix_binary=payloads[PREFIX_PLAN_BINARY_NAME],
    )
    root = lab_root()
    prefix_source = _read_native_source(
        _regular_file(
            Path(prefix_source_path)
            if prefix_source_path is not None
            else root / PREFIX_SOURCE_NATIVE_GZIP_RELATIVE,
            "prepared inherited prefix source",
        ).resolve(strict=True),
        field="prepared inherited prefix source",
        expected_gzip_sha256=PREFIX_SOURCE_NATIVE_GZIP_SHA256,
        expected_raw_sha256=PREFIX_SOURCE_NATIVE_RAW_SHA256,
        expected_raw_bytes=PREFIX_SOURCE_NATIVE_RAW_BYTES,
    )
    _validate_plan_bundle(state, bundle, prefix_source=prefix_source)
    parent_receipt = _read_json_bytes(
        payloads[PARENT_RECEIPT_NAME], "prepared parent receipt"
    )
    science_history = _read_json_bytes(
        payloads[SCIENCE_HISTORY_NAME], "prepared science history"
    )
    science_input = _read_json_bytes(
        payloads[SCIENCE_INPUT_NAME], "prepared science input"
    )
    expected_science_input = _science_input_document(
        bundle=bundle,
        parent_receipt_sha256=sha256_bytes(payloads[PARENT_RECEIPT_NAME]),
        science_history_sha256=sha256_bytes(payloads[SCIENCE_HISTORY_NAME]),
    )
    projection_contract = _mapping(
        manifest.get("projection_contract"), "prepared projection contract"
    )
    if (
        state.active_projection.serialized != active.serialized
        or state.describe() != residency_document
        or state.describe() != manifest.get("residency")
        or state.attic.occurrence_document() != occurrence_document
        or canonical_json_bytes(state.attic.relation_document())
        != payloads[RELATIONS_NAME]
        or canonical_json_bytes(state.activation_ledger_document())
        != payloads[ACTIVATION_LEDGER_NAME]
        or parent_receipt != _parent_receipt_document()
        or sha256_bytes(payloads[PARENT_RECEIPT_NAME]) != EXPECTED_PARENT_RECEIPT_SHA256
        or parent_receipt != manifest.get("parent_receipt")
        or science_history != _science_history_document()
        or sha256_bytes(payloads[SCIENCE_HISTORY_NAME])
        != EXPECTED_SCIENCE_HISTORY_SHA256
        or science_history != manifest.get("science_input_history")
        or science_input != expected_science_input
        or sha256_bytes(payloads[SCIENCE_INPUT_NAME]) != EXPECTED_SCIENCE_INPUT_SHA256
        or science_input != manifest.get("science_input")
        or frontier_document != manifest.get("frontier_plan")
        or staging_document != manifest.get("staging_plan")
        or prefix_document != manifest.get("prefix_plan")
        or projection_contract
        != {
            "source_lineage_ordinal": 19,
            "source_active_sha256": PAGE6_SHA256,
            "next_lineage_ordinal": 20,
            "next_active_sha256": PAGE7_SHA256,
            "next_selection_order_sha256": PAGE7_SELECTION_ORDER_SHA256,
            "advance_api": "advance_causal_residency",
            "empty_rollover_sha256": EMPTY_ROLLOVER_SHA256,
            "empty_rollover_clause_count": 0,
            "empty_rollover_occurrence_count": 0,
            "empty_rollover_emission_count": 0,
            "fully_emitted_union_indices": [],
            "attic_chunk_count_before": 10,
            "attic_chunk_count_after": 11,
            "occurrence_count_before": UNCHANGED_OCCURRENCES,
            "occurrence_count_after": UNCHANGED_OCCURRENCES,
            "unchanged_union_sha256": UNCHANGED_UNION_SHA256,
            "failed_call_reprojection_used": False,
            "synthetic_evidence_created": False,
            "page6_replay_authorized": False,
        }
        or manifest.get("zero_call")
        != {
            "native_solver_calls": 0,
            "science_calls": 0,
            "public_verification_calls": 0,
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
            "refits": 0,
            "mps_or_gpu_calls": 0,
        }
        or manifest.get("authorization")
        != {
            "science_call_authorized": False,
            "intent_created": False,
            "page7_burned": False,
            "lineage20_burned": False,
            "page6_replay_authorized": False,
        }
    ):
        raise O1C80PreparationError("prepared Page-7 projection differs")
    _validate_successor_state(state)
    return PreparedBoundCrossing(
        directory=prepared,
        manifest=dict(manifest),
        manifest_bytes=manifest_payload,
        manifest_sha256=expected,
        state=state,
        parent_receipt=dict(parent_receipt),
        science_input_history=dict(science_history),
        science_input=dict(science_input),
        frontier_plan=frontier_plan,
        staging_plan=staging_plan,
        prefix_plan=prefix_plan,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0080's zero-call Page-7 bound-crossing seed"
    )
    parser.add_argument(
        "--capsule", default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix()
    )
    parser.add_argument(
        "--parent-result",
        default=(root / DEFAULT_PARENT_RESULT_RELATIVE).as_posix(),
    )
    parser.add_argument(
        "--parent-erratum",
        default=(root / DEFAULT_PARENT_ERRATUM_RELATIVE).as_posix(),
    )
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = prepare_o1c80_bound_crossing(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
            parent_erratum_path=args.parent_erratum,
            output_dir=args.output_dir,
        )
    except (O1C80PreparationError, CausalResidencyError) as exc:
        print(f"{ATTEMPT_ID}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ACTIVE_PROJECTION_NAME",
    "ACTIVATION_LEDGER_NAME",
    "CHUNK_NAMES",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_ERRATUM_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "EMPTY_ROLLOVER_SHA256",
    "EXPECTED_PREPARED_MANIFEST_SHA256",
    "FRONTIER_PLAN_BINARY_NAME",
    "FRONTIER_PLAN_NAME",
    "MANIFEST_NAME",
    "O1C80PreparationError",
    "OCCURRENCES_NAME",
    "PAGE7_SELECTION_ORDER_SHA256",
    "PAGE7_SHA256",
    "PARENT_RECEIPT_NAME",
    "PREFIX_PLAN_BINARY_NAME",
    "PREFIX_PLAN_NAME",
    "PreparedBoundCrossing",
    "RELATIONS_NAME",
    "RESIDENCY_NAME",
    "SCIENCE_HISTORY_NAME",
    "SCIENCE_INPUT_NAME",
    "STAGING_PLAN_BINARY_NAME",
    "STAGING_PLAN_NAME",
    "lab_root",
    "load_prepared_bound_crossing",
    "main",
    "prepare_o1c80_bound_crossing",
]
