"""Zero-call preparation of O1C-0078 rescue-prefix preemption.

The direct scientific parent is the sealed O1C-0077 capsule.  Preparation
validates and replays that capsule to fresh Page 5 without launching a native
process.  O1C-0077's terminal assignment is retained only as direct-parent
evidence: it has no unsatisfied Page-5 frontier.  The inner clause-526 control
stack is instead rebound from the already sealed O1C-0076 canonical frontier
and assignment, after which the exact eleven-row prefix is added outside it.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping, Sequence, cast

from .causal_attic_v1 import (
    CAUSAL_ATTIC_OCCURRENCE_SCHEMA,
    CausalAtticError,
    ClauseOccurrence,
    canonical_json_bytes,
    parse_self_scoping_vault,
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
    replay_causal_residency,
    validate_activation_replay,
)
from .residual_polarity_staging_v1 import (
    RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
    ResidualPolarityStagingError,
    ResidualPolarityStagingPlan,
    parse_residual_polarity_staging_plan,
    serialize_residual_polarity_staging_plan,
    validate_o1c77_production_plan,
    validate_residual_polarity_staging_plan,
)
from .rescue_prefix_preemption_v1 import (
    O1C78_BASELINE_TRACE_SHA256,
    O1C78_PREFIX_LITERALS,
    O1C78_PREFIX_ORDER_SHA256,
    RESCUE_PREFIX_PREEMPTION_PLAN_SCHEMA,
    RescuePrefixPreemptionError,
    RescuePrefixPreemptionPlan,
    derive_rescue_prefix_preemption_plan,
    parse_rescue_prefix_preemption_plan,
    rescue_prefix_order_bytes,
    serialize_rescue_prefix_preemption_plan,
    validate_o1c78_production_plan,
    validate_rescue_prefix_preemption_plan,
)
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)
from .vault_ranked_decision_v1 import (
    PRODUCTION_ORDER_BYTES,
    PRODUCTION_ORDER_SHA256,
    PRODUCTION_RANK_TABLE_BYTES,
    PRODUCTION_RANK_TABLE_SHA256,
    VaultRankedDecision,
    VaultRankedDecisionError,
    derive_production_vault_ranked_decision,
)


ATTEMPT_ID = "O1C-0078"
PREPARATION_SCHEMA = "o1-256-apple8-rescue-prefix-preemption-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-rescue-prefix-preemption-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-rescue-prefix-preemption-artifact-set-v1"
FRONTIER_PLAN_DOCUMENT_SCHEMA = "o1-256-causal-frontier-plan-document-v1"
STAGING_PLAN_DOCUMENT_SCHEMA = (
    "o1-256-residual-polarity-staging-plan-document-v1"
)
PREFIX_PLAN_DOCUMENT_SCHEMA = (
    "o1-256-rescue-prefix-preemption-plan-document-v1"
)
PARENT_PROVENANCE_SCHEMA = "o1-256-o1c77-parent-provenance-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_025550_O1C-0077_apple8-residual-polarity-staging-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0077_APPLE8_RESIDUAL_POLARITY_STAGING_RESULT_20260720.json"
)
POTENTIAL_RELATIVE = Path(
    "runs/20260719_095509_APPLE-VIEW-0008-MATCHED_"
    "crossblock-consequence-sieve-v1/artifacts/potential/"
    "primary-eight-block.potential"
)
GROUPING_RELATIVE = Path(
    "runs/20260719_215617_O1C-0073_apple8-vault-release-contrast-v1/"
    "apple8-width6.grouping"
)

CHUNK_NAMES = tuple(f"chunk-{index:02d}.vault" for index in range(10))
ACTIVE_PROJECTION_NAME = "page-05-active.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
SOURCE_ASSIGNMENT_NAME = "source-assignment.bin"
FRONTIER_PLAN_NAME = "frontier-plan.json"
FRONTIER_PLAN_BINARY_NAME = "frontier-plan.bin"
STAGING_PLAN_NAME = "staging-plan.json"
STAGING_PLAN_BINARY_NAME = "staging-plan.bin"
PREFIX_PLAN_NAME = "prefix-plan.json"
PREFIX_PLAN_BINARY_NAME = "prefix-plan.bin"
PARENT_PROVENANCE_NAME = "parent-provenance.json"
MANIFEST_NAME = "rescue-prefix-preemption-manifest.json"

PARENT_RESULT_SHA256 = (
    "8b87d7cdc39f6380a887b2e45d4879544ff88cd7c53e22f44876e46c334cf103"
)
PARENT_MANIFEST_SHA256 = (
    "6b8526c5eaa2c318d4eef1e8c4dc87e744307c95f30699a90e4444021d2dbece"
)
PARENT_SOURCE_COMMIT = "8eba8614fc9d19ef893a0e7f093737ed6b23dc68"
PARENT_RUNNER_SHA256 = (
    "edaa827f95eb37738c0138dee0acb5b40586f7f5eb5c85a4496dc833c7f354b8"
)
PARENT_NATIVE_GZIP_SHA256 = (
    "e13e98d14af49978a8afaeebb36d4d854f21f92ffa29efcbec323e7a20ec5a15"
)
PARENT_NATIVE_RAW_SHA256 = (
    "8980046510cd80417260436d73fdbe3cb24da6d233e136aff616972f92aadfd0"
)
PARENT_NATIVE_RAW_BYTES = 361_499
PARENT_TERMINAL_ASSIGNMENT_SHA256 = (
    "2d26cfd7d2cba61bd49d116a6cb64c35a8fabbacdb4244a431703ef1a562e6bc"
)
PARENT_TERMINAL_TRACE_SHA256 = O1C78_BASELINE_TRACE_SHA256

# The O1C-0076 source is intentionally retained only by the rebound inner
# control stack.  It is not the direct-parent terminal state for O1C-0078.
CONTROL_SOURCE_RESULT_SHA256 = (
    "5cee812cc99b824b43b345f20b2eed253a09090a69866de2f3c4fa074c95e198"
)
SOURCE_ASSIGNMENT_SHA256 = (
    "c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2"
)
PARENT_INITIAL_FRONTIER_PLAN_SHA256 = (
    "83dbfbddd51bdbacb95a892cf3bc7e3c3953bc3e62b674d1f8388de7de53db30"
)
PARENT_INITIAL_STAGING_PLAN_SHA256 = (
    "db99c44c1a08203f691c197172d71dad73ac12c64326d48461fac10316ee3167"
)
RANK_SOURCE_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PAGE5_SHA256 = (
    "07c73013705898e228a05b0578b0f8090a6f094c427dbd8f32d856467b08e208"
)
UNION_AGGREGATE_SHA256 = (
    "840cc5cecdfe998fe1b0b2d4b7c4dbc3ee554112fc9ec550b0720c765f9c1911"
)
SELECTED_ACTIVE_INDEX = 232
SELECTED_UNION_INDEX = 526
SELECTED_CLAUSE_SHA256 = (
    "c4a9c471f9eb45829764a841fb8c6971eecdc8b9a9e251732d65875647f25322"
)
SELECTED_FALSE_COUNT = 2_409
SELECTED_TRUE_COUNT = 0
SELECTED_UNASSIGNED_COUNT = 29
SELECTED_CLAUSE_LITERAL_COUNT = 2_438
SELECTED_WITNESS_SCORE = 14.554563483898708
RESIDUAL_I32LE_SHA256 = (
    "ed2056882fd69ed2fc6ffb502ae251e3d7876fa4131b0fa35396d73305deccd7"
)
FALSIFYING_I32LE_SHA256 = (
    "71de3130c414926ba0527d1d427b99400454a90e40152b20c68ff02c06c7fe48"
)
FRONTIER_PLAN_BINARY_SHA256 = (
    "8a263e555b4b5a69d3c9a937cac3e7702a1f8e3de27db4feffc2d21563a24da1"
)
FRONTIER_PLAN_BINARY_BYTES = 4_479
FRONTIER_PLAN_BODY_SHA256 = (
    "fabc4719451f61d6f9ac3b7c2c56b98c1272fceaa532ae7cac3b20e4fd8b1837"
)
POTENTIAL_SHA256 = (
    "8c6101b49c7050caf895bd9c496c05bcea9f43a2b27f378d7306be38b00d5390"
)
GROUPING_SHA256 = (
    "3da85bae132d829252a68f0e3fd99220ea7d1ef365042806af810ff02f75f636"
)
EFFECTIVE_RANK_ORDER_SHA256 = (
    "6ab071e611809ee898e81d0659ff0736453dd390d26c739383826c94276ad086"
)
OVERLAY_RANK_INDICES = (224, 226)
INTERSECTION_RANK_INDICES = (28, 131, 224, 226, 235)
STAGING_PLAN_BINARY_SHA256 = (
    "ecbca2bd3ab2e5196d4cae76a968c7957909ada49e4d225d28841a4c21d2e023"
)
STAGING_PLAN_BINARY_BYTES = 4_477
PREFIX_LITERALS = O1C78_PREFIX_LITERALS
PREFIX_ORDER_I32LE_SHA256 = O1C78_PREFIX_ORDER_SHA256

# The native prefix plan is the canonical signed-i32le order itself.  Source,
# active-page, staging-parent, and trace bindings live in the canonical plan
# document and manifest rather than changing these 44 native-facing bytes.
PREFIX_PLAN_BINARY_SHA256 = PREFIX_ORDER_I32LE_SHA256
PREFIX_PLAN_BINARY_BYTES = 44
EXPECTED_PREPARED_MANIFEST_SHA256 = (
    "ee1a2144b2eb30ac3f69012f4e5085de1c6f668625f85b31e73c0aa188cfd30d"
)

EXPECTED_PARENT_SOURCE_SHA256 = {
    "runner": PARENT_RUNNER_SHA256,
    "preparation": (
        "ea7d8cb0b761f9471320c3f25968f395e252307b69c3cb436d8b860f5bb0bbed"
    ),
    "causal_attic_v1": (
        "39da3833f7bba7fd012313ff176e9ebd82adc7e088bdfa8d37880fbbcf3a438f"
    ),
    "causal_residency_v1": (
        "c769f8cf06331eb3aba83b14d86e450abaff502dfef06386511194b949df1895"
    ),
    "threshold_no_good_vault_v1": (
        "622ede78c389ef9e6181e8ebf173c4cbc05197ea2c4795f352b433d2e87cbf5a"
    ),
    "causal_frontier_v1": (
        "471fd95be08b2ef1cca0762ce5517b0684913998ee2e6c42b3724274fef6a930"
    ),
    "residual_polarity_staging_v1": (
        "ee75a9d2d6fc8e17fd35e6affab202c35c082089ce58fbbd73ae8acf51bc402c"
    ),
    "adapter_v18": (
        "c812678d6311d1fd55c9708cc5118dde4ff8652a46659e83d9e183f187c3681c"
    ),
    "native_v15": (
        "fd14a4d30f1b8a8659810544d540cf567e9cb85d9c7d03a480b51080698c82d4"
    ),
}
PARENT_SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c77_apple8_residual_polarity_staging_run.py",
    "preparation": (
        "src/o1_crypto_lab/o1c77_apple8_residual_polarity_staging_prepare.py"
    ),
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency_v1": "src/o1_crypto_lab/causal_residency_v1.py",
    "threshold_no_good_vault_v1": (
        "src/o1_crypto_lab/threshold_no_good_vault_v1.py"
    ),
    "causal_frontier_v1": "src/o1_crypto_lab/causal_frontier_v1.py",
    "residual_polarity_staging_v1": (
        "src/o1_crypto_lab/residual_polarity_staging_v1.py"
    ),
    "adapter_v18": "src/o1_crypto_lab/joint_score_sieve_v18.py",
    "native_v15": "native/cadical_o1_joint_score_sieve_v15.cpp",
}


class O1C78PreparationError(RuntimeError):
    """A sealed parent, rebound plan, prefix, or artifact differs."""


@dataclass(frozen=True)
class PreparedRescuePrefixPreemption:
    directory: Path | None
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState
    source_assignment: bytes
    frontier_plan: CausalFrontierPlan
    frontier_plan_document: Mapping[str, object]
    frontier_plan_binary: bytes
    staging_plan: ResidualPolarityStagingPlan
    staging_plan_document: Mapping[str, object]
    staging_plan_binary: bytes
    prefix_plan: RescuePrefixPreemptionPlan
    prefix_plan_document: Mapping[str, object]
    prefix_plan_binary: bytes
    rank_decision: VaultRankedDecision

    @property
    def control_source_assignment(self) -> bytes:
        return self.source_assignment

    @property
    def rank_source(self) -> ThresholdNoGoodVault:
        return self.state.attic.chunks[0]

    @property
    def active_projection(self) -> ThresholdNoGoodVault:
        return self.state.active_projection


def lab_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) for key in value
    ):
        raise O1C78PreparationError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise O1C78PreparationError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C78PreparationError(f"{field} differs")
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C78PreparationError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C78PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C78PreparationError(f"{field} is not a sealed regular file")
    return path


def _sealed_directory(path: Path, field: str) -> Path:
    """Resolve one existing directory only after rejecting a root symlink."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C78PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise O1C78PreparationError(f"{field} is not a sealed directory")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise O1C78PreparationError(f"{field} is unreadable") from exc


def _read_json_bytes(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C78PreparationError(f"{field} JSON differs") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C78PreparationError(f"{field} is not canonical")
    return document


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C78PreparationError("occurrence schema differs")
    records = _sequence(document.get("records"), "occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C78PreparationError("occurrence ordinal differs")
        try:
            occurrence = ClauseOccurrence(
                stream_id=cast(str, row.get("stream_id")),
                source_index=_nonnegative_int(
                    row.get("source_index"), "occurrence source index"
                ),
                classification=cast(str, row.get("classification")),
                source=cast(str, row.get("source")),
                witness_score_f64le_hex=cast(
                    str, row.get("witness_score_f64le_hex")
                ),
                clause=clauses[union_index],
                clause_sha256=cast(str, row.get("clause_sha256")),
                witness_sha256=cast(str, row.get("witness_sha256")),
            )
        except (CausalAtticError, TypeError) as exc:
            raise O1C78PreparationError("occurrence record differs") from exc
        if occurrence.describe(
            ordinal=ordinal, union_clause_index=union_index
        ) != dict(row):
            raise O1C78PreparationError("occurrence record differs")
        occurrences.append(occurrence)
    if (
        document.get("occurrence_count") != len(occurrences)
        or document.get("unique_clause_count") != len(clauses)
    ):
        raise O1C78PreparationError("occurrence ledger differs")
    return tuple(occurrences)


def _parse_artifact_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C78PreparationError("parent manifest encoding differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C78PreparationError("parent manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C78PreparationError("parent manifest row differs")
        entries[relative] = digest
    if len(entries) != 39:
        raise O1C78PreparationError("parent manifest inventory differs")
    return entries


def _validate_parent_capsule(
    capsule: Path, parent_result_path: Path
) -> tuple[Mapping[str, object], Mapping[str, object], str, dict[str, str]]:
    manifest_path = _regular_file(capsule / "artifacts.sha256", "parent manifest")
    manifest_payload = manifest_path.read_bytes()
    if sha256_bytes(manifest_payload) != PARENT_MANIFEST_SHA256:
        raise O1C78PreparationError("parent capsule manifest differs")
    entries = _parse_artifact_manifest(manifest_payload)
    observed: dict[str, str] = {}
    for path in capsule.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise O1C78PreparationError(
                "parent capsule inventory differs"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C78PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = sha256_bytes(path.read_bytes())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C78PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C78PreparationError("parent capsule inventory or digest differs")

    result_payload = _regular_file(parent_result_path, "parent result").read_bytes()
    if (
        sha256_bytes(result_payload) != PARENT_RESULT_SHA256
        or result_payload != (capsule / "result.json").read_bytes()
        or entries.get("result.json") != PARENT_RESULT_SHA256
    ):
        raise O1C78PreparationError("parent result binding differs")
    result = _read_json_bytes(result_payload, "parent result")
    invocation_payload = _regular_file(
        capsule / "invocation.json", "parent invocation"
    ).read_bytes()
    invocation = _read_json_bytes(invocation_payload, "parent invocation")
    if (
        result.get("attempt_id") != "O1C-0077"
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or len(_sequence(result.get("episodes"), "parent episodes")) != 1
        or invocation.get("attempt_id") != "O1C-0077"
    ):
        raise O1C78PreparationError("parent result contract differs")
    return result, invocation, sha256_bytes(invocation_payload), entries


def _validate_parent_sources(invocation: Mapping[str, object]) -> None:
    bindings = _mapping(invocation.get("bindings"), "parent bindings")
    recorded = _mapping(bindings.get("source_sha256"), "parent source hashes")
    if (
        bindings.get("execution_commit") != PARENT_SOURCE_COMMIT
        or dict(recorded) != EXPECTED_PARENT_SOURCE_SHA256
    ):
        raise O1C78PreparationError("parent source binding differs")
    root = lab_root()
    for name, relative in PARENT_SOURCE_PATHS.items():
        payload = _regular_file(root / relative, f"parent source {name}").read_bytes()
        if sha256_bytes(payload) != EXPECTED_PARENT_SOURCE_SHA256[name]:
            raise O1C78PreparationError(f"parent source {name} differs")


def _read_parent_native(
    capsule: Path, entries: Mapping[str, str]
) -> tuple[Mapping[str, object], bytes, bytes]:
    relative = "episodes/00/native-result.json.gz"
    compressed = _regular_file(
        capsule / relative, "parent terminal native result"
    ).read_bytes()
    if (
        sha256_bytes(compressed) != PARENT_NATIVE_GZIP_SHA256
        or entries.get(relative) != PARENT_NATIVE_GZIP_SHA256
    ):
        raise O1C78PreparationError("parent terminal native gzip differs")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C78PreparationError("parent terminal native gzip differs") from exc
    if (
        len(raw) != PARENT_NATIVE_RAW_BYTES
        or sha256_bytes(raw) != PARENT_NATIVE_RAW_SHA256
    ):
        raise O1C78PreparationError("parent terminal native raw result differs")
    native = _read_json_bytes(raw, "parent terminal native result")
    sieve = _mapping(native.get("sieve"), "parent terminal sieve")
    state = _mapping(sieve.get("state"), "parent terminal sieve state")
    encoded = state.get("assignment_hex")
    if not isinstance(encoded, str):
        raise O1C78PreparationError("parent terminal assignment differs")
    try:
        assignment = bytes.fromhex(encoded)
    except ValueError as exc:
        raise O1C78PreparationError("parent terminal assignment differs") from exc
    if (
        len(assignment) != sieve.get("observed_variables")
        or len(assignment) != state.get("assignment_bytes")
        or set(assignment) - {0, 1, 255}
        or sha256_bytes(assignment) != PARENT_TERMINAL_ASSIGNMENT_SHA256
        or state.get("assignment_sha256") != PARENT_TERMINAL_ASSIGNMENT_SHA256
        or sieve.get("trace_sha256") != PARENT_TERMINAL_TRACE_SHA256
        or PARENT_TERMINAL_ASSIGNMENT_SHA256 == SOURCE_ASSIGNMENT_SHA256
    ):
        raise O1C78PreparationError("parent terminal assignment differs")
    return native, raw, assignment


def _derive_rank_decision(state: CausalResidencyState) -> VaultRankedDecision:
    root = lab_root()
    potential = _regular_file(
        root / POTENTIAL_RELATIVE, "production potential"
    ).read_bytes()
    grouping = _regular_file(
        root / GROUPING_RELATIVE, "production grouping"
    ).read_bytes()
    if (
        sha256_bytes(potential) != POTENTIAL_SHA256
        or sha256_bytes(grouping) != GROUPING_SHA256
    ):
        raise O1C78PreparationError("production rank inputs differ")
    try:
        decision = derive_production_vault_ranked_decision(
            state.attic.chunks[0].serialized, potential, grouping
        )
    except VaultRankedDecisionError as exc:
        raise O1C78PreparationError("production rank derivation differs") from exc
    if (
        decision.source_vault_sha256 != RANK_SOURCE_SHA256
        or decision.rank_table_sha256 != PRODUCTION_RANK_TABLE_SHA256
        or len(decision.rank_table_bytes) != PRODUCTION_RANK_TABLE_BYTES
        or decision.order_sha256 != PRODUCTION_ORDER_SHA256
        or len(decision.order_bytes) != PRODUCTION_ORDER_BYTES
    ):
        raise O1C78PreparationError("production rank release contract differs")
    return decision


def _recover_parent_state(
    capsule: Path, result: Mapping[str, object], invocation: Mapping[str, object]
) -> tuple[
    CausalResidencyState,
    CausalFrontierPlan,
    ResidualPolarityStagingPlan,
    VaultRankedDecision,
]:
    """Import O1C-0077 recovery only after capsule and source validation."""

    from . import o1c77_apple8_residual_polarity_staging_run as parent_runner

    try:
        state = parent_runner._rebuild_initial_from_capsule(
            capsule,
            _mapping(invocation.get("initial_artifacts"), "parent initial artifacts"),
            _mapping(invocation.get("initial_residency"), "parent initial residency"),
        )
        initial_frontier = parse_causal_frontier_plan(
            _regular_file(
                capsule / "initial" / "frontier-plan.bin",
                "parent initial frontier plan",
            ).read_bytes(),
            active_vault=state.active_projection,
        )
        rank_decision = _derive_rank_decision(state)
        initial_staging = parse_residual_polarity_staging_plan(
            _regular_file(
                capsule / "initial" / "staging-plan.bin",
                "parent initial staging plan",
            ).read_bytes(),
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        validate_o1c77_production_plan(initial_staging)
        if (
            initial_frontier.describe() != invocation.get("frontier_plan")
            or initial_staging.describe() != invocation.get("staging_plan")
        ):
            raise O1C78PreparationError("sealed parent initial plan differs")
        invocation_sha = sha256_bytes((capsule / "invocation.json").read_bytes())
        science_inputs: set[str] = set(parent_runner.INHERITED_SCIENCE_INPUT_SHA256)
        for raw in _sequence(result.get("episodes"), "parent episodes"):
            state = parent_runner._recover_completed_episode(
                capsule=capsule,
                state=state,
                expected=_mapping(raw, "parent episode"),
                invocation_sha256=invocation_sha,
                science_inputs=science_inputs,
                frontier_plan=initial_frontier,
                staging_plan=initial_staging,
            )
        validate_activation_replay(state)
    except Exception as exc:
        if isinstance(exc, O1C78PreparationError):
            raise
        raise O1C78PreparationError("sealed parent replay differs") from exc
    if (
        state.describe() != result.get("final_residency")
        or state.attic.describe() != result.get("final_attic")
        or state.active_projection.describe() != result.get("final_active_vault")
        or state.active_projection.sha256 != PAGE5_SHA256
        or state.attic.chunks[0].sha256 != RANK_SOURCE_SHA256
        or tuple(chunk.clause_count for chunk in state.attic.chunks)
        != (202, 311, 0, 37, 0, 0, 0, 0, 0, 0)
        or state.current_projection.lineage_ordinal != 18
    ):
        raise O1C78PreparationError("sealed parent terminal state differs")
    return state, initial_frontier, initial_staging, rank_decision


def _frontier_plan_document(
    state: CausalResidencyState, plan: CausalFrontierPlan
) -> dict[str, object]:
    residual_binary = struct.pack(
        f"<{len(plan.residual_clause_literals)}i", *plan.residual_clause_literals
    )
    falsifying_binary = struct.pack(
        f"<{len(plan.falsifying_decision_literals)}i",
        *plan.falsifying_decision_literals,
    )
    witness_scores = [
        occurrence.witness_score
        for occurrence, union_index in zip(
            state.attic.occurrences,
            state.attic.occurrence_union_indices,
            strict=True,
        )
        if union_index == plan.selected_union_index
    ]
    if not witness_scores:
        raise O1C78PreparationError("selected frontier witness differs")
    return {
        "schema": FRONTIER_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": CAUSAL_FRONTIER_PLAN_SCHEMA,
        "plan": plan.describe(),
        "selection_rule": (
            "sealed O1C-0076 clause-526 control plan; unchanged selected "
            "clause rebound to fresh O1C-0077 Page 5"
        ),
        "control_source_result_sha256": CONTROL_SOURCE_RESULT_SHA256,
        "control_source_assignment_sha256": SOURCE_ASSIGNMENT_SHA256,
        "rebound_from_frontier_plan_sha256": (
            PARENT_INITIAL_FRONTIER_PLAN_SHA256
        ),
        "o1c77_terminal_assignment_used_for_frontier_derivation": False,
        "first_witness_score": witness_scores[0],
        "residual_i32le_sha256": sha256_bytes(residual_binary),
        "falsifying_i32le_sha256": sha256_bytes(falsifying_binary),
        "truth_key_bytes_read": False,
        "native_solver_calls": 0,
        "reveal_calls": 0,
    }


def _staging_plan_document(
    plan: ResidualPolarityStagingPlan,
) -> dict[str, object]:
    return {
        "schema": STAGING_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": RESIDUAL_POLARITY_STAGING_PLAN_SCHEMA,
        "plan": plan.describe(),
        "rebound_from_staging_plan_sha256": PARENT_INITIAL_STAGING_PLAN_SHA256,
        "overlay_rank_indices_zero_based": list(OVERLAY_RANK_INDICES),
        "intersection_rank_indices_zero_based": list(INTERSECTION_RANK_INDICES),
        "overlay_applied_before_embedded_parent_readers": True,
        "immutable_rank_payload_rewritten": False,
        "o1c77_terminal_assignment_used_for_staging_derivation": False,
        "activation_postvalidated": True,
        "unit_activation_is_science_gain": False,
        "truth_key_bytes_read": False,
        "native_solver_calls": 0,
        "reveal_calls": 0,
    }


def _prefix_plan_document(plan: RescuePrefixPreemptionPlan) -> dict[str, object]:
    prefix_bytes = rescue_prefix_order_bytes(plan.prefix_literals)
    return {
        "schema": PREFIX_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": RESCUE_PREFIX_PREEMPTION_PLAN_SCHEMA,
        "plan": plan.describe(),
        "source_result_sha256": PARENT_NATIVE_RAW_SHA256,
        "source_assignment_sha256": PARENT_TERMINAL_ASSIGNMENT_SHA256,
        "active_vault_sha256": PAGE5_SHA256,
        "parent_staging_plan_sha256": STAGING_PLAN_BINARY_SHA256,
        "baseline_trace_sha256": PARENT_TERMINAL_TRACE_SHA256,
        "prefix_encoding": "signed-i32le",
        "prefix_literal_count": len(plan.prefix_literals),
        "prefix_i32le_bytes": len(prefix_bytes),
        "prefix_i32le_sha256": sha256_bytes(prefix_bytes),
        "prefix_consumed_before_first_parent_call": True,
        "adaptive_subset_authorized": False,
        "adaptive_order_authorized": False,
        "retry_authorized": False,
        "truth_key_bytes_read": False,
        "native_solver_calls": 0,
        "reveal_calls": 0,
    }


def _rebind_frontier_plan(
    state: CausalResidencyState, source: CausalFrontierPlan
) -> tuple[CausalFrontierPlan, dict[str, object], bytes]:
    """Rebind the sealed O1C-0076 control plan without re-deriving it."""

    if (
        source.sha256 != PARENT_INITIAL_FRONTIER_PLAN_SHA256
        or source.source_result_sha256 != CONTROL_SOURCE_RESULT_SHA256
        or source.source_assignment_sha256 != SOURCE_ASSIGNMENT_SHA256
        or source.selected_active_index != SELECTED_ACTIVE_INDEX
        or source.selected_union_index != SELECTED_UNION_INDEX
        or source.selected_clause_sha256 != SELECTED_CLAUSE_SHA256
    ):
        raise O1C78PreparationError("sealed control frontier differs")
    plan = replace(
        source,
        active_vault_sha256=state.active_projection.sha256,
        selected_union_indices=state.current_projection.selected_union_indices,
    )
    try:
        validate_causal_frontier_plan(plan, active_vault=state.active_projection)
        binary = serialize_causal_frontier_plan(plan)
        if parse_causal_frontier_plan(
            binary, active_vault=state.active_projection
        ) != plan:
            raise O1C78PreparationError("frontier binary round trip differs")
    except CausalFrontierError as exc:
        raise O1C78PreparationError("Page-5 frontier rebind differs") from exc
    return plan, _frontier_plan_document(state, plan), binary


def _validate_terminal_assignment_has_no_frontier(
    state: CausalResidencyState, native_result_raw: bytes
) -> None:
    """Prove the direct-parent assignment is not a Page-5 plan source."""

    try:
        derive_causal_frontier_plan(
            source_result=native_result_raw,
            source_result_sha256=PARENT_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            selected_union_indices=state.current_projection.selected_union_indices,
        )
    except CausalFrontierError as exc:
        if str(exc) != "causal frontier has no unsatisfied active clause":
            raise O1C78PreparationError(
                "terminal assignment frontier rejection differs"
            ) from exc
        return
    raise O1C78PreparationError(
        "terminal assignment unexpectedly derived a Page-5 frontier"
    )


def _rebind_staging_plan(
    *,
    state: CausalResidencyState,
    source: ResidualPolarityStagingPlan,
    frontier_plan: CausalFrontierPlan,
    rank_decision: VaultRankedDecision,
) -> tuple[ResidualPolarityStagingPlan, dict[str, object], bytes]:
    """Rebind the unchanged two-row overlay to Page 5 and its frontier."""

    if (
        source.sha256 != PARENT_INITIAL_STAGING_PLAN_SHA256
        or source.source_result_sha256 != CONTROL_SOURCE_RESULT_SHA256
        or source.source_assignment_sha256 != SOURCE_ASSIGNMENT_SHA256
        or tuple(row.rank_index for row in source.overlays)
        != OVERLAY_RANK_INDICES
    ):
        raise O1C78PreparationError("sealed control staging differs")
    plan = replace(
        source,
        active_vault_sha256=state.active_projection.sha256,
        parent_frontier_plan_sha256=frontier_plan.sha256,
    )
    try:
        validate_residual_polarity_staging_plan(
            plan,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        binary = serialize_residual_polarity_staging_plan(plan)
        if parse_residual_polarity_staging_plan(
            binary,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        ) != plan:
            raise O1C78PreparationError("staging binary round trip differs")
    except ResidualPolarityStagingError as exc:
        raise O1C78PreparationError("Page-5 staging rebind differs") from exc
    return plan, _staging_plan_document(plan), binary


def _derive_prefix_plan(
    *,
    state: CausalResidencyState,
    native_result_raw: bytes,
    staging_plan: ResidualPolarityStagingPlan,
) -> tuple[RescuePrefixPreemptionPlan, dict[str, object], bytes]:
    """Derive and round-trip the exact target-free eleven-row prefix."""

    try:
        plan = derive_rescue_prefix_preemption_plan(
            source_result=native_result_raw,
            source_result_sha256=PARENT_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=PARENT_TERMINAL_TRACE_SHA256,
            prefix_literals=PREFIX_LITERALS,
        )
        validate_rescue_prefix_preemption_plan(
            plan,
            source_result_sha256=PARENT_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=PARENT_TERMINAL_TRACE_SHA256,
            required_prefix_literals=PREFIX_LITERALS,
        )
        validate_o1c78_production_plan(plan)
        binary = serialize_rescue_prefix_preemption_plan(plan)
        parsed = parse_rescue_prefix_preemption_plan(
            binary, active_vault=state.active_projection
        )
        validate_o1c78_production_plan(parsed)
        if parsed != plan or parsed.serialized != binary:
            raise O1C78PreparationError("prefix binary round trip differs")
    except RescuePrefixPreemptionError as exc:
        raise O1C78PreparationError("rescue-prefix preemption differs") from exc
    return plan, _prefix_plan_document(plan), binary


def _validate_release_contract(
    state: CausalResidencyState,
    control_assignment: bytes,
    plan: CausalFrontierPlan,
    plan_document: Mapping[str, object],
    plan_binary: bytes,
    rank_decision: VaultRankedDecision,
    staging_plan: ResidualPolarityStagingPlan,
    staging_document: Mapping[str, object],
    staging_binary: bytes,
    prefix_plan: RescuePrefixPreemptionPlan,
    prefix_document: Mapping[str, object],
    prefix_binary: bytes,
) -> None:
    residual_binary = struct.pack(
        f"<{len(plan.residual_clause_literals)}i", *plan.residual_clause_literals
    )
    falsifying_binary = struct.pack(
        f"<{len(plan.falsifying_decision_literals)}i",
        *plan.falsifying_decision_literals,
    )
    prefix_order = rescue_prefix_order_bytes(prefix_plan.prefix_literals)
    facts = {
        "chunks": tuple(chunk.clause_count for chunk in state.attic.chunks),
        "union_clauses": state.attic.union_vault.clause_count,
        "union_literals": state.attic.union_vault.literal_count,
        "union_aggregate": state.attic.union_vault.clause_aggregate_sha256,
        "occurrences": len(state.attic.occurrences),
        "duplicates": state.attic.duplicate_occurrence_count,
        "active": state.active_projection.sha256,
        "active_count": state.active_projection.clause_count,
        "active_literals": state.active_projection.literal_count,
        "active_bytes": state.active_projection.serialized_bytes,
        "lineage": state.current_projection.lineage_ordinal,
        "debt": len(state.never_resident_undominated_indices),
        "control_assignment": sha256_bytes(control_assignment),
        "terminal_assignment_distinct": (
            PARENT_TERMINAL_ASSIGNMENT_SHA256 != sha256_bytes(control_assignment)
        ),
        "active_index": plan.selected_active_index,
        "union_index": plan.selected_union_index,
        "clause": plan.selected_clause_sha256,
        "literal_count": plan.selected_clause_literal_count,
        "false": plan.false_literal_count,
        "true": plan.true_literal_count,
        "unassigned": plan.unassigned_literal_count,
        "witness": plan_document.get("first_witness_score"),
        "residual": sha256_bytes(residual_binary),
        "falsifying": sha256_bytes(falsifying_binary),
        "frontier_round_trip": parse_causal_frontier_plan(
            plan_binary, active_vault=state.active_projection
        )
        == plan,
        "frontier_sha256": sha256_bytes(plan_binary),
        "frontier_bytes": len(plan_binary),
        "frontier_body": sha256_bytes(plan_binary[:-32]),
        "rank_table": rank_decision.rank_table_sha256,
        "rank_table_bytes": len(rank_decision.rank_table_bytes),
        "source_order": rank_decision.order_sha256,
        "source_order_bytes": len(rank_decision.order_bytes),
        "effective_order": staging_plan.effective_rank_order_sha256,
        "overlay_indices": tuple(row.rank_index for row in staging_plan.overlays),
        "intersection_indices": tuple(
            row.rank_index for row in staging_plan.intersections
        ),
        "staging_parent": staging_plan.parent_frontier_plan_sha256,
        "staging_source": staging_plan.source_result_sha256,
        "staging_assignment": staging_plan.source_assignment_sha256,
        "staging_active": staging_plan.active_vault_sha256,
        "staging_round_trip": parse_residual_polarity_staging_plan(
            staging_binary,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
        == staging_plan,
        "staging_sha256": sha256_bytes(staging_binary),
        "staging_bytes": len(staging_binary),
        "staging_document": staging_document.get("plan"),
        "prefix_literals": prefix_plan.prefix_literals,
        "prefix_order_sha256": sha256_bytes(prefix_order),
        "prefix_order_bytes": len(prefix_order),
        "prefix_sha256": sha256_bytes(prefix_binary),
        "prefix_bytes": len(prefix_binary),
        "prefix_document": prefix_document.get("plan"),
    }
    expected = {
        "chunks": (202, 311, 0, 37, 0, 0, 0, 0, 0, 0),
        "union_clauses": 550,
        "union_literals": 1_488_224,
        "union_aggregate": UNION_AGGREGATE_SHA256,
        "occurrences": 558,
        "duplicates": 8,
        "active": PAGE5_SHA256,
        "active_count": 256,
        "active_literals": 654_465,
        "active_bytes": 2_619_075,
        "lineage": 18,
        "debt": 0,
        "control_assignment": SOURCE_ASSIGNMENT_SHA256,
        "terminal_assignment_distinct": True,
        "active_index": SELECTED_ACTIVE_INDEX,
        "union_index": SELECTED_UNION_INDEX,
        "clause": SELECTED_CLAUSE_SHA256,
        "literal_count": SELECTED_CLAUSE_LITERAL_COUNT,
        "false": SELECTED_FALSE_COUNT,
        "true": SELECTED_TRUE_COUNT,
        "unassigned": SELECTED_UNASSIGNED_COUNT,
        "witness": SELECTED_WITNESS_SCORE,
        "residual": RESIDUAL_I32LE_SHA256,
        "falsifying": FALSIFYING_I32LE_SHA256,
        "frontier_round_trip": True,
        "frontier_sha256": FRONTIER_PLAN_BINARY_SHA256,
        "frontier_bytes": FRONTIER_PLAN_BINARY_BYTES,
        "frontier_body": FRONTIER_PLAN_BODY_SHA256,
        "rank_table": PRODUCTION_RANK_TABLE_SHA256,
        "rank_table_bytes": PRODUCTION_RANK_TABLE_BYTES,
        "source_order": PRODUCTION_ORDER_SHA256,
        "source_order_bytes": PRODUCTION_ORDER_BYTES,
        "effective_order": EFFECTIVE_RANK_ORDER_SHA256,
        "overlay_indices": OVERLAY_RANK_INDICES,
        "intersection_indices": INTERSECTION_RANK_INDICES,
        "staging_parent": FRONTIER_PLAN_BINARY_SHA256,
        "staging_source": CONTROL_SOURCE_RESULT_SHA256,
        "staging_assignment": SOURCE_ASSIGNMENT_SHA256,
        "staging_active": PAGE5_SHA256,
        "staging_round_trip": True,
        "staging_sha256": STAGING_PLAN_BINARY_SHA256,
        "staging_bytes": STAGING_PLAN_BINARY_BYTES,
        "staging_document": staging_plan.describe(),
        "prefix_literals": PREFIX_LITERALS,
        "prefix_order_sha256": PREFIX_ORDER_I32LE_SHA256,
        "prefix_order_bytes": PREFIX_PLAN_BINARY_BYTES,
        "prefix_sha256": PREFIX_PLAN_BINARY_SHA256,
        "prefix_bytes": PREFIX_PLAN_BINARY_BYTES,
        "prefix_document": prefix_plan.describe(),
    }
    if facts != expected:
        raise O1C78PreparationError("rescue-prefix release contract differs")


def _artifact_row(payload: bytes, role: str) -> dict[str, object]:
    return {
        "role": role,
        "serialized_bytes": len(payload),
        "sha256": sha256_bytes(payload),
    }


def _durable_write(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise O1C78PreparationError("prefix-preemption artifact write failed") from exc


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise O1C78PreparationError("prefix-preemption output already exists")
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise O1C78PreparationError(
            "prefix-preemption output parent differs"
        ) from exc
    if output_dir.name in ("", ".", ".."):
        raise O1C78PreparationError("prefix-preemption output name differs")
    destination = parent / output_dir.name
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".tmp", dir=parent)
    )
    published = False
    try:
        for name, payload in files.items():
            if Path(name).name != name:
                raise O1C78PreparationError(
                    "prefix-preemption artifact name differs"
                )
            _durable_write(stage / name, payload)
        stage_descriptor = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(stage_descriptor)
        finally:
            os.close(stage_descriptor)
        os.replace(stage, destination)
        published = True
        descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        shutil.rmtree(destination if published else stage, ignore_errors=True)
        raise O1C78PreparationError(
            "prefix-preemption artifact publication failed"
        ) from exc
    except Exception:
        shutil.rmtree(destination if published else stage, ignore_errors=True)
        raise


def _validate_frozen_manifest_payload(payload: bytes) -> None:
    if sha256_bytes(payload) != EXPECTED_PREPARED_MANIFEST_SHA256:
        raise O1C78PreparationError(
            "frozen prefix-preemption manifest identity differs"
        )


def prepare_o1c78_rescue_prefix_preemption(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    output_dir: str | Path,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Replay O1C-0077 and publish the complete zero-call Page-5 seed."""

    if enforce_release_contract is not True:
        raise O1C78PreparationError("release-contract flag must remain true")
    capsule = _sealed_directory(Path(capsule_dir), "parent capsule")
    parent_result = _regular_file(
        Path(parent_result_path), "parent result root"
    ).resolve(strict=True)
    result, invocation, invocation_sha, entries = _validate_parent_capsule(
        capsule, parent_result
    )
    _validate_parent_sources(invocation)
    native, native_raw, terminal_assignment = _read_parent_native(
        capsule, entries
    )
    state, control_frontier, control_staging, rank_decision = (
        _recover_parent_state(capsule, result, invocation)
    )
    control_assignment = control_frontier.prior_assignment_bytes
    if (
        sha256_bytes(control_assignment) != SOURCE_ASSIGNMENT_SHA256
        or control_staging.source_assignment_bytes != control_assignment
        or sha256_bytes(terminal_assignment) != PARENT_TERMINAL_ASSIGNMENT_SHA256
    ):
        raise O1C78PreparationError("control-plan source assignment differs")
    _validate_terminal_assignment_has_no_frontier(state, native_raw)
    plan, plan_document, plan_binary = _rebind_frontier_plan(
        state, control_frontier
    )
    staging_plan, staging_document, staging_binary = _rebind_staging_plan(
        state=state,
        source=control_staging,
        frontier_plan=plan,
        rank_decision=rank_decision,
    )
    prefix_plan, prefix_document, prefix_binary = _derive_prefix_plan(
        state=state,
        native_result_raw=native_raw,
        staging_plan=staging_plan,
    )
    if enforce_release_contract:
        _validate_release_contract(
            state,
            control_assignment,
            plan,
            plan_document,
            plan_binary,
            rank_decision,
            staging_plan,
            staging_document,
            staging_binary,
            prefix_plan,
            prefix_document,
            prefix_binary,
        )

    provenance = {
        "schema": PARENT_PROVENANCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "parent_attempt_id": "O1C-0077",
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_source_commit": PARENT_SOURCE_COMMIT,
        "parent_invocation_sha256": invocation_sha,
        "parent_runner_sha256": PARENT_RUNNER_SHA256,
        "parent_source_sha256": dict(EXPECTED_PARENT_SOURCE_SHA256),
        "terminal_native_gzip_sha256": PARENT_NATIVE_GZIP_SHA256,
        "terminal_native_raw_sha256": PARENT_NATIVE_RAW_SHA256,
        "terminal_native_raw_bytes": PARENT_NATIVE_RAW_BYTES,
        "terminal_native_schema": native.get("schema"),
        "terminal_trace_sha256": _mapping(
            native.get("sieve"), "terminal sieve"
        ).get("trace_sha256"),
        "terminal_source_assignment_sha256": (
            PARENT_TERMINAL_ASSIGNMENT_SHA256
        ),
        "terminal_assignment_used_for_frontier_derivation": False,
        "control_source_attempt_id": "O1C-0076",
        "control_source_result_sha256": CONTROL_SOURCE_RESULT_SHA256,
        "control_source_assignment_sha256": SOURCE_ASSIGNMENT_SHA256,
        "control_source_role": "sealed-inner-frontier-staging-provenance-only",
        "rank_source_sha256": RANK_SOURCE_SHA256,
        "fresh_page5_sha256": PAGE5_SHA256,
        "parent_last_consumed_lineage_ordinal": 17,
        "prepared_lineage_ordinal": 18,
        "truth_key_bytes_read": False,
    }
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
        SOURCE_ASSIGNMENT_NAME: control_assignment,
        FRONTIER_PLAN_NAME: canonical_json_bytes(plan_document),
        FRONTIER_PLAN_BINARY_NAME: plan_binary,
        STAGING_PLAN_NAME: canonical_json_bytes(staging_document),
        STAGING_PLAN_BINARY_NAME: staging_binary,
        PREFIX_PLAN_NAME: canonical_json_bytes(prefix_document),
        PREFIX_PLAN_BINARY_NAME: prefix_binary,
        PARENT_PROVENANCE_NAME: canonical_json_bytes(provenance),
    }
    roles = {
        **{name: "immutable-complete-causal-attic-chunk" for name in CHUNK_NAMES},
        ACTIVE_PROJECTION_NAME: "unused-fresh-page5-science-input",
        OCCURRENCES_NAME: "complete-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-strict-subsumption-closure",
        ACTIVATION_LEDGER_NAME: "complete-causal-residency-ledger",
        SOURCE_ASSIGNMENT_NAME: (
            "sealed-o1c76-inner-control-plan-assignment-only"
        ),
        FRONTIER_PLAN_NAME: "sealed-page5-control-frontier-plan",
        FRONTIER_PLAN_BINARY_NAME: "native-frontier-falsifying-literal-plan",
        STAGING_PLAN_NAME: "sealed-page5-residual-polarity-staging-plan",
        STAGING_PLAN_BINARY_NAME: "native-residual-polarity-staging-plan",
        PREFIX_PLAN_NAME: "target-free-rescue-prefix-preemption-plan",
        PREFIX_PLAN_BINARY_NAME: "native-signed-i32le-rescue-prefix-plan",
        PARENT_PROVENANCE_NAME: "sealed-parent-replay-and-control-provenance",
    }
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
            "truth_key_bytes_read": False,
            "reveal_calls": 0,
        },
        "parent": provenance,
        "residency": state.describe(),
        "frontier_plan": plan_document,
        "staging_plan": staging_document,
        "prefix_plan": prefix_document,
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifact_count": len(rows),
            "artifacts": rows,
        },
    }
    payload = canonical_json_bytes(manifest)
    _validate_frozen_manifest_payload(payload)
    _publish_directory(Path(output_dir), {**artifacts, MANIFEST_NAME: payload})
    return manifest


def load_prepared_rescue_prefix_preemption(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedRescuePrefixPreemption:
    """Validate exact inventory and reconstruct the complete Page-5 seed."""

    prepared = _sealed_directory(Path(directory), "prepared prefix-preemption root")
    manifest_path = _regular_file(prepared / MANIFEST_NAME, "prepared manifest")
    manifest_bytes = manifest_path.read_bytes()
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if sha256_bytes(manifest_bytes) != expected:
        raise O1C78PreparationError("prepared prefix-preemption manifest differs")
    manifest = _read_json_bytes(manifest_bytes, "prepared manifest")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("preparation_schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C78PreparationError("prepared manifest contract differs")
    artifact_set = _mapping(manifest.get("artifact_set"), "prepared artifact set")
    rows = _mapping(artifact_set.get("artifacts"), "prepared artifacts")
    expected_names = set(CHUNK_NAMES) | {
        ACTIVE_PROJECTION_NAME,
        OCCURRENCES_NAME,
        RELATIONS_NAME,
        ACTIVATION_LEDGER_NAME,
        SOURCE_ASSIGNMENT_NAME,
        FRONTIER_PLAN_NAME,
        FRONTIER_PLAN_BINARY_NAME,
        STAGING_PLAN_NAME,
        STAGING_PLAN_BINARY_NAME,
        PREFIX_PLAN_NAME,
        PREFIX_PLAN_BINARY_NAME,
        PARENT_PROVENANCE_NAME,
    }
    actual = tuple(prepared.iterdir())
    if (
        set(rows) != expected_names
        or artifact_set.get("artifact_count") != len(expected_names)
        or {path.name for path in actual} != expected_names | {MANIFEST_NAME}
        or any(path.is_symlink() or not path.is_file() for path in actual)
    ):
        raise O1C78PreparationError("prepared directory inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(expected_names):
        row = _mapping(rows[name], f"prepared artifact {name}")
        payload = _regular_file(
            prepared / name, f"prepared artifact {name}"
        ).read_bytes()
        if (
            row.get("sha256") != sha256_bytes(payload)
            or row.get("serialized_bytes") != len(payload)
        ):
            raise O1C78PreparationError(f"prepared artifact {name} differs")
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
        union_clauses = []
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
        attic = reproject_causal_attic(
            tuple(chunks), occurrences, active_limit=256
        )
        state = replay_causal_residency(
            attic, _mapping(manifest.get("residency"), "prepared residency")
        )
        validate_activation_replay(state)
        active = parse_threshold_no_good_vault(
            payloads[ACTIVE_PROJECTION_NAME],
            observed_variables=rank.observed_variables,
            caps=O1C66_VAULT_CAPS,
        )
    except (
        CausalAtticError,
        CausalResidencyError,
        ThresholdNoGoodVaultError,
        O1C78PreparationError,
    ) as exc:
        raise O1C78PreparationError(
            "prepared prefix-preemption reconstruction differs"
        ) from exc

    assignment = payloads[SOURCE_ASSIGNMENT_NAME]
    plan_document = _read_json_bytes(
        payloads[FRONTIER_PLAN_NAME], "prepared frontier plan"
    )
    plan_binary = payloads[FRONTIER_PLAN_BINARY_NAME]
    try:
        plan = parse_causal_frontier_plan(
            plan_binary, active_vault=state.active_projection
        )
    except CausalFrontierError as exc:
        raise O1C78PreparationError("prepared frontier binary differs") from exc
    rank_decision = _derive_rank_decision(state)
    staging_document = _read_json_bytes(
        payloads[STAGING_PLAN_NAME], "prepared staging plan"
    )
    staging_binary = payloads[STAGING_PLAN_BINARY_NAME]
    try:
        staging_plan = parse_residual_polarity_staging_plan(
            staging_binary,
            active_vault=state.active_projection,
            rank_decision=rank_decision,
        )
    except ResidualPolarityStagingError as exc:
        raise O1C78PreparationError("prepared staging binary differs") from exc
    prefix_document = _read_json_bytes(
        payloads[PREFIX_PLAN_NAME], "prepared prefix plan"
    )
    prefix_binary = payloads[PREFIX_PLAN_BINARY_NAME]
    try:
        prefix_plan = parse_rescue_prefix_preemption_plan(
            prefix_binary, active_vault=state.active_projection
        )
        validate_rescue_prefix_preemption_plan(
            prefix_plan,
            active_vault=state.active_projection,
            parent_staging_plan_sha256=staging_plan.sha256,
            baseline_trace_sha256=PARENT_TERMINAL_TRACE_SHA256,
            source_result_sha256=PARENT_NATIVE_RAW_SHA256,
            required_prefix_literals=PREFIX_LITERALS,
        )
        validate_o1c78_production_plan(prefix_plan)
    except RescuePrefixPreemptionError as exc:
        raise O1C78PreparationError("prepared prefix binary differs") from exc

    derived_document = _frontier_plan_document(state, plan)
    derived_staging_document = _staging_plan_document(staging_plan)
    derived_prefix_document = _prefix_plan_document(prefix_plan)
    provenance = _read_json_bytes(
        payloads[PARENT_PROVENANCE_NAME], "prepared parent provenance"
    )
    if (
        state.active_projection.serialized != active.serialized
        or state.attic.occurrence_document() != occurrence_document
        or canonical_json_bytes(state.attic.relation_document())
        != payloads[RELATIONS_NAME]
        or canonical_json_bytes(state.activation_ledger_document())
        != payloads[ACTIVATION_LEDGER_NAME]
        or plan.source_assignment_sha256 != sha256_bytes(assignment)
        or plan.prior_assignment_bytes != assignment
        or plan.source_result_sha256 != CONTROL_SOURCE_RESULT_SHA256
        or plan_document != derived_document
        or plan_document != manifest.get("frontier_plan")
        or staging_plan.source_assignment_bytes != assignment
        or staging_plan.parent_frontier_plan_sha256 != plan.sha256
        or staging_document != derived_staging_document
        or staging_document != manifest.get("staging_plan")
        or prefix_document != derived_prefix_document
        or prefix_document != manifest.get("prefix_plan")
        or provenance != manifest.get("parent")
        or provenance.get("terminal_source_assignment_sha256")
        != PARENT_TERMINAL_ASSIGNMENT_SHA256
        or provenance.get("control_source_assignment_sha256")
        != SOURCE_ASSIGNMENT_SHA256
    ):
        raise O1C78PreparationError("prepared prefix projection differs")
    _validate_release_contract(
        state,
        assignment,
        plan,
        plan_document,
        plan_binary,
        rank_decision,
        staging_plan,
        staging_document,
        staging_binary,
        prefix_plan,
        prefix_document,
        prefix_binary,
    )
    return PreparedRescuePrefixPreemption(
        directory=prepared,
        manifest=dict(manifest),
        manifest_bytes=manifest_bytes,
        manifest_sha256=expected,
        state=state,
        source_assignment=assignment,
        frontier_plan=plan,
        frontier_plan_document=dict(plan_document),
        frontier_plan_binary=plan_binary,
        staging_plan=staging_plan,
        staging_plan_document=dict(staging_document),
        staging_plan_binary=staging_binary,
        prefix_plan=prefix_plan,
        prefix_plan_document=dict(prefix_document),
        prefix_plan_binary=prefix_binary,
        rank_decision=rank_decision,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0078's zero-call rescue-prefix preemption"
    )
    parser.add_argument(
        "--capsule", default=(root / DEFAULT_PARENT_CAPSULE_RELATIVE).as_posix()
    )
    parser.add_argument(
        "--parent-result",
        default=(root / DEFAULT_PARENT_RESULT_RELATIVE).as_posix(),
    )
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = prepare_o1c78_rescue_prefix_preemption(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
            output_dir=args.output_dir,
        )
    except (O1C78PreparationError, CausalResidencyError) as exc:
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
    "CONTROL_SOURCE_RESULT_SHA256",
    "DEFAULT_PARENT_CAPSULE_RELATIVE",
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "EFFECTIVE_RANK_ORDER_SHA256",
    "EXPECTED_PREPARED_MANIFEST_SHA256",
    "FALSIFYING_I32LE_SHA256",
    "FRONTIER_PLAN_BINARY_NAME",
    "FRONTIER_PLAN_BINARY_SHA256",
    "FRONTIER_PLAN_NAME",
    "INTERSECTION_RANK_INDICES",
    "MANIFEST_NAME",
    "MANIFEST_SCHEMA",
    "O1C78PreparationError",
    "OVERLAY_RANK_INDICES",
    "PAGE5_SHA256",
    "PARENT_NATIVE_RAW_SHA256",
    "PARENT_PROVENANCE_NAME",
    "PARENT_TERMINAL_ASSIGNMENT_SHA256",
    "PREFIX_LITERALS",
    "PREFIX_ORDER_I32LE_SHA256",
    "PREFIX_PLAN_BINARY_BYTES",
    "PREFIX_PLAN_BINARY_NAME",
    "PREFIX_PLAN_BINARY_SHA256",
    "PREFIX_PLAN_NAME",
    "PreparedRescuePrefixPreemption",
    "RANK_SOURCE_SHA256",
    "RELATIONS_NAME",
    "SELECTED_CLAUSE_SHA256",
    "SOURCE_ASSIGNMENT_NAME",
    "SOURCE_ASSIGNMENT_SHA256",
    "STAGING_PLAN_BINARY_BYTES",
    "STAGING_PLAN_BINARY_NAME",
    "STAGING_PLAN_BINARY_SHA256",
    "STAGING_PLAN_NAME",
    "lab_root",
    "load_prepared_rescue_prefix_preemption",
    "main",
    "prepare_o1c78_rescue_prefix_preemption",
]
