"""Zero-call preparation of O1C-0076's target-free causal frontier.

The only scientific parent is the sealed O1C-0075 capsule.  This module
validates that capsule byte-for-byte, replays its complete causal-residency
state through the hash-pinned recovery implementation, and derives one bounded
frontier plan from the final public solver assignment.  It never imports a
target broker, reads truth, launches a solver, or performs a reveal.
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
from dataclasses import dataclass
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
from .threshold_no_good_vault_v1 import (
    O1C66_VAULT_CAPS,
    ThresholdNoGoodClause,
    ThresholdNoGoodVault,
    ThresholdNoGoodVaultError,
    parse_threshold_no_good_vault,
)


ATTEMPT_ID = "O1C-0076"
PREPARATION_SCHEMA = "o1-256-apple8-causal-frontier-preparation-v1"
MANIFEST_SCHEMA = "o1-256-apple8-causal-frontier-manifest-v1"
ARTIFACT_SET_SCHEMA = "o1-256-apple8-causal-frontier-artifact-set-v1"
FRONTIER_PLAN_DOCUMENT_SCHEMA = "o1-256-causal-frontier-plan-document-v1"
PARENT_PROVENANCE_SCHEMA = "o1-256-o1c75-parent-provenance-v1"

DEFAULT_PARENT_CAPSULE_RELATIVE = Path(
    "runs/20260720_002724_O1C-0075_apple8-causal-residency-stream-v1"
)
DEFAULT_PARENT_RESULT_RELATIVE = Path(
    "research/O1C0075_APPLE8_CAUSAL_RESIDENCY_STREAM_RESULT_20260720.json"
)

CHUNK_NAMES = tuple(f"chunk-{index:02d}.vault" for index in range(8))
ACTIVE_PROJECTION_NAME = "page-03-active.bin"
OCCURRENCES_NAME = "witness-occurrences.json"
RELATIONS_NAME = "subsumption-relations.json"
ACTIVATION_LEDGER_NAME = "activation-ledger.json"
SOURCE_ASSIGNMENT_NAME = "source-assignment.bin"
FRONTIER_PLAN_NAME = "frontier-plan.json"
FRONTIER_PLAN_BINARY_NAME = "frontier-plan.bin"
PARENT_PROVENANCE_NAME = "parent-provenance.json"
MANIFEST_NAME = "causal-frontier-manifest.json"

PARENT_RESULT_SHA256 = (
    "1307be5e1c140f27ec76873a212785f7dae9b5dd986ca8f953e94809e31639c9"
)
PARENT_MANIFEST_SHA256 = (
    "3a421ee236af5afe46011314d74c25b726a2e7f35e9963ae8d4a862e070327f9"
)
PARENT_SOURCE_COMMIT = "1b30cc06b3ab28d94df773cc854a7814af9fb210"
PARENT_RUNNER_SHA256 = (
    "033464f9c5e0b0d108d5058c34574b48ac67f5667fd3127e237b2b00bbb71cc3"
)
PARENT_NATIVE_GZIP_SHA256 = (
    "d377c552e60b96a01479012e2c6eee536550a8b9839f1957f17f605b0ada149e"
)
PARENT_NATIVE_RAW_SHA256 = (
    "b1f97d0735f1704dbef8e634b7df57e1c65b895b3a0da10da13a6eea72aa1ed5"
)
SOURCE_ASSIGNMENT_SHA256 = (
    "c62a8e3c41694b25c86aa8e66dfc9072cec7d23b7efd39fc4c766ef8ea2418d2"
)
RANK_SOURCE_SHA256 = (
    "cd523334672dd75c068c2dd32fe218fb7ae55644c0d56e6347271bba3a9c1858"
)
PAGE3_SHA256 = (
    "5b459ea4a10bcb8183e5aaf1e93a91e0e7e4bfc89c58b3e65efaf8d4838c8d91"
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
    "6da2702b6840a2c24a2fc09a3a49ab34d913cc55cc3135c1087880a9461860f1"
)
FRONTIER_PLAN_BINARY_BYTES = 4_479
EXPECTED_PREPARED_MANIFEST_SHA256 = (
    "e10c90ee8d2cd37516fe093c3833c7cdc59d64ac513d0a9ec17afb051bd057d6"
)

EXPECTED_PARENT_SOURCE_SHA256 = {
    "runner": PARENT_RUNNER_SHA256,
    "preparation": (
        "980c64f4627d80ddf78e43af7bcc1dca4962076ae9d498ff2d8fa82356183889"
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
    "adapter_v16": (
        "8dba3c47cc707221d417eb0ca99147c72c7fae2a3b923017019a8f6c87e86da9"
    ),
    "native_v13": (
        "bfac8629f7a346042bb4513759ece118fa8c7c5b635f2909a6133db5e22a8621"
    ),
}
PARENT_SOURCE_PATHS = {
    "runner": "src/o1_crypto_lab/o1c75_apple8_causal_residency_stream_run.py",
    "preparation": "src/o1_crypto_lab/o1c75_apple8_causal_residency_prepare.py",
    "causal_attic_v1": "src/o1_crypto_lab/causal_attic_v1.py",
    "causal_residency_v1": "src/o1_crypto_lab/causal_residency_v1.py",
    "threshold_no_good_vault_v1": (
        "src/o1_crypto_lab/threshold_no_good_vault_v1.py"
    ),
    "adapter_v16": "src/o1_crypto_lab/joint_score_sieve_v16.py",
    "native_v13": "native/cadical_o1_joint_score_sieve_v13.cpp",
}


class O1C76PreparationError(RuntimeError):
    """A sealed parent, target-free derivation, or artifact differs."""


@dataclass(frozen=True)
class PreparedFrontier:
    directory: Path | None
    manifest: Mapping[str, object]
    manifest_bytes: bytes
    manifest_sha256: str
    state: CausalResidencyState
    source_assignment: bytes
    frontier_plan: CausalFrontierPlan
    frontier_plan_document: Mapping[str, object]
    frontier_plan_binary: bytes

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
        raise O1C76PreparationError(f"{field} differs")
    return cast(Mapping[str, object], value)


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(
        value, (str, bytes, bytearray)
    ):
        raise O1C76PreparationError(f"{field} differs")
    return cast(Sequence[object], value)


def _nonnegative_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise O1C76PreparationError(f"{field} differs")
    return value


def _sha256(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise O1C76PreparationError(f"{field} differs")
    return value


def _regular_file(path: Path, field: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise O1C76PreparationError(f"{field} is unreadable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise O1C76PreparationError(f"{field} is not a sealed regular file")
    return path


def _read_json_bytes(payload: bytes, field: str) -> Mapping[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise O1C76PreparationError(f"{field} JSON differs") from exc
    document = _mapping(value, field)
    if canonical_json_bytes(document) != payload:
        raise O1C76PreparationError(f"{field} is not canonical")
    return document


def _parse_occurrence_document(
    value: object, *, clauses: tuple[ThresholdNoGoodClause, ...]
) -> tuple[ClauseOccurrence, ...]:
    document = _mapping(value, "occurrence document")
    if document.get("schema") != CAUSAL_ATTIC_OCCURRENCE_SCHEMA:
        raise O1C76PreparationError("occurrence schema differs")
    records = _sequence(document.get("records"), "occurrence records")
    occurrences: list[ClauseOccurrence] = []
    for ordinal, raw in enumerate(records):
        row = _mapping(raw, "occurrence record")
        union_index = _nonnegative_int(
            row.get("union_clause_index"), "occurrence union index"
        )
        if row.get("ordinal") != ordinal or union_index >= len(clauses):
            raise O1C76PreparationError("occurrence ordinal differs")
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
            raise O1C76PreparationError("occurrence record differs") from exc
        if occurrence.describe(
            ordinal=ordinal, union_clause_index=union_index
        ) != dict(row):
            raise O1C76PreparationError("occurrence record differs")
        occurrences.append(occurrence)
    if (
        document.get("occurrence_count") != len(occurrences)
        or document.get("unique_clause_count") != len(clauses)
    ):
        raise O1C76PreparationError("occurrence ledger differs")
    return tuple(occurrences)


def _parse_artifact_manifest(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise O1C76PreparationError("parent manifest encoding differs") from exc
    entries: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise O1C76PreparationError("parent manifest row differs")
        digest, relative = line[:64], line[66:]
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or relative in entries
        ):
            raise O1C76PreparationError("parent manifest row differs")
        entries[relative] = digest
    if len(entries) != 41:
        raise O1C76PreparationError("parent manifest inventory differs")
    return entries


def _validate_parent_capsule(
    capsule: Path, parent_result_path: Path
) -> tuple[Mapping[str, object], Mapping[str, object], str]:
    manifest_path = _regular_file(capsule / "artifacts.sha256", "parent manifest")
    manifest_payload = manifest_path.read_bytes()
    if sha256_bytes(manifest_payload) != PARENT_MANIFEST_SHA256:
        raise O1C76PreparationError("parent capsule manifest differs")
    entries = _parse_artifact_manifest(manifest_payload)
    observed: dict[str, str] = {}
    for path in capsule.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise O1C76PreparationError("parent capsule inventory differs") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise O1C76PreparationError("parent capsule contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(capsule).as_posix()
            if relative != "artifacts.sha256":
                observed[relative] = sha256_bytes(path.read_bytes())
        elif not stat.S_ISDIR(metadata.st_mode):
            raise O1C76PreparationError("parent capsule contains a special file")
    if observed != entries:
        raise O1C76PreparationError("parent capsule inventory or digest differs")

    result_payload = _regular_file(parent_result_path, "parent result").read_bytes()
    if (
        sha256_bytes(result_payload) != PARENT_RESULT_SHA256
        or result_payload != (capsule / "result.json").read_bytes()
        or entries.get("result.json") != PARENT_RESULT_SHA256
    ):
        raise O1C76PreparationError("parent result binding differs")
    result = _read_json_bytes(result_payload, "parent result")
    invocation_payload = _regular_file(
        capsule / "invocation.json", "parent invocation"
    ).read_bytes()
    invocation = _read_json_bytes(invocation_payload, "parent invocation")
    if (
        result.get("attempt_id") != "O1C-0075"
        or result.get("source_commit") != PARENT_SOURCE_COMMIT
        or len(_sequence(result.get("episodes"), "parent episodes")) != 2
    ):
        raise O1C76PreparationError("parent result contract differs")
    return result, invocation, sha256_bytes(invocation_payload)


def _validate_parent_sources(invocation: Mapping[str, object]) -> None:
    bindings = _mapping(invocation.get("bindings"), "parent bindings")
    recorded = _mapping(bindings.get("source_sha256"), "parent source hashes")
    if (
        bindings.get("execution_commit") != PARENT_SOURCE_COMMIT
        or dict(recorded) != EXPECTED_PARENT_SOURCE_SHA256
    ):
        raise O1C76PreparationError("parent source binding differs")
    root = lab_root()
    for name, relative in PARENT_SOURCE_PATHS.items():
        payload = _regular_file(root / relative, f"parent source {name}").read_bytes()
        if sha256_bytes(payload) != EXPECTED_PARENT_SOURCE_SHA256[name]:
            raise O1C76PreparationError(f"parent source {name} differs")


def _read_parent_assignment(
    capsule: Path, entries: Mapping[str, str]
) -> tuple[bytes, Mapping[str, object], bytes]:
    relative = "episodes/01/native-result.json.gz"
    path = _regular_file(capsule / relative, "parent terminal native result")
    compressed = path.read_bytes()
    if (
        sha256_bytes(compressed) != PARENT_NATIVE_GZIP_SHA256
        or entries.get(relative) != PARENT_NATIVE_GZIP_SHA256
    ):
        raise O1C76PreparationError("parent terminal native gzip differs")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise O1C76PreparationError("parent terminal native gzip differs") from exc
    if len(raw) > 1_048_576 or sha256_bytes(raw) != PARENT_NATIVE_RAW_SHA256:
        raise O1C76PreparationError("parent terminal native raw result differs")
    native = _read_json_bytes(raw, "parent terminal native result")
    sieve = _mapping(native.get("sieve"), "parent terminal sieve")
    state = _mapping(sieve.get("state"), "parent terminal sieve state")
    encoded = state.get("assignment_hex")
    if not isinstance(encoded, str):
        raise O1C76PreparationError("parent terminal assignment differs")
    try:
        assignment = bytes.fromhex(encoded)
    except ValueError as exc:
        raise O1C76PreparationError("parent terminal assignment differs") from exc
    if (
        len(assignment) != sieve.get("observed_variables")
        or len(assignment) != state.get("assignment_bytes")
        or set(assignment) - {0, 1, 255}
        or sha256_bytes(assignment) != SOURCE_ASSIGNMENT_SHA256
        or state.get("assignment_sha256") != SOURCE_ASSIGNMENT_SHA256
    ):
        raise O1C76PreparationError("parent terminal assignment differs")
    return assignment, native, raw


def _recover_parent_state(
    capsule: Path, result: Mapping[str, object], invocation: Mapping[str, object]
) -> CausalResidencyState:
    """Import private recovery only after capsule and source validation."""

    from . import o1c75_apple8_causal_residency_stream_run as parent_runner

    try:
        state = parent_runner._rebuild_initial_from_capsule(
            capsule,
            _mapping(invocation.get("initial_artifacts"), "parent initial artifacts"),
            _mapping(invocation.get("initial_residency"), "parent initial residency"),
        )
        invocation_sha = sha256_bytes((capsule / "invocation.json").read_bytes())
        science_inputs: set[str] = set(
            parent_runner.INHERITED_SCIENCE_INPUT_SHA256
        )
        for raw in _sequence(result.get("episodes"), "parent episodes"):
            state = parent_runner._recover_completed_episode(
                capsule=capsule,
                state=state,
                expected=_mapping(raw, "parent episode"),
                invocation_sha256=invocation_sha,
                science_inputs=science_inputs,
            )
        validate_activation_replay(state)
    except Exception as exc:
        raise O1C76PreparationError("sealed parent replay differs") from exc
    if (
        state.describe() != result.get("final_residency")
        or state.attic.describe() != result.get("final_attic")
        or state.active_projection.describe() != result.get("final_active_vault")
        or state.active_projection.sha256 != PAGE3_SHA256
        or state.attic.chunks[0].sha256 != RANK_SOURCE_SHA256
    ):
        raise O1C76PreparationError("sealed parent terminal state differs")
    return state


def _derive_frontier_plan(
    state: CausalResidencyState,
    native_result_raw: bytes,
) -> tuple[CausalFrontierPlan, dict[str, object], bytes]:
    """Call the generic target-free derivation and add attempt provenance."""

    try:
        plan = derive_causal_frontier_plan(
            source_result=native_result_raw,
            source_result_sha256=PARENT_NATIVE_RAW_SHA256,
            active_vault=state.active_projection,
            selected_union_indices=state.current_projection.selected_union_indices,
        )
        validate_causal_frontier_plan(plan, active_vault=state.active_projection)
        binary = serialize_causal_frontier_plan(plan)
        if parse_causal_frontier_plan(
            binary, active_vault=state.active_projection
        ) != plan:
            raise O1C76PreparationError("frontier binary round trip differs")
    except CausalFrontierError as exc:
        raise O1C76PreparationError("generic causal-frontier derivation differs") from exc
    return plan, _frontier_plan_document(state, plan), binary


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
        raise O1C76PreparationError("selected frontier witness differs")
    return {
        "schema": FRONTIER_PLAN_DOCUMENT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "generic_plan_schema": CAUSAL_FRONTIER_PLAN_SCHEMA,
        "plan": plan.describe(),
        "selection_rule": (
            "true_count=0; minimum unassigned_count; clause SHA-256; "
            "active index"
        ),
        "first_witness_score": witness_scores[0],
        "residual_i32le_sha256": sha256_bytes(residual_binary),
        "falsifying_i32le_sha256": sha256_bytes(falsifying_binary),
        "truth_key_bytes_read": False,
        "native_solver_calls": 0,
        "reveal_calls": 0,
    }


def _validate_release_contract(
    state: CausalResidencyState,
    assignment: bytes,
    plan: CausalFrontierPlan,
    plan_document: Mapping[str, object],
    plan_binary: bytes,
) -> None:
    residual_binary = struct.pack(
        f"<{len(plan.residual_clause_literals)}i", *plan.residual_clause_literals
    )
    falsifying_binary = struct.pack(
        f"<{len(plan.falsifying_decision_literals)}i",
        *plan.falsifying_decision_literals,
    )
    facts = {
        "chunks": tuple(chunk.clause_count for chunk in state.attic.chunks),
        "union_clauses": state.attic.union_vault.clause_count,
        "union_literals": state.attic.union_vault.literal_count,
        "union_aggregate": state.attic.union_vault.clause_aggregate_sha256,
        "occurrences": len(state.attic.occurrences),
        "duplicates": state.attic.duplicate_occurrence_count,
        "active": state.active_projection.sha256,
        "active_count": state.active_projection.clause_count,
        "lineage": state.current_projection.lineage_ordinal,
        "debt": len(state.never_resident_undominated_indices),
        "assignment": sha256_bytes(assignment),
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
        "binary_round_trip": parse_causal_frontier_plan(
            plan_binary, active_vault=state.active_projection
        ) == plan,
        "binary_sha256": sha256_bytes(plan_binary),
        "binary_bytes": len(plan_binary),
    }
    expected = {
        "chunks": (202, 311, 0, 37, 0, 0, 0, 0),
        "union_clauses": 550,
        "union_literals": 1_488_224,
        "union_aggregate": UNION_AGGREGATE_SHA256,
        "occurrences": 558,
        "duplicates": 8,
        "active": PAGE3_SHA256,
        "active_count": 256,
        "lineage": 16,
        "debt": 0,
        "assignment": SOURCE_ASSIGNMENT_SHA256,
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
        "binary_round_trip": True,
        "binary_sha256": FRONTIER_PLAN_BINARY_SHA256,
        "binary_bytes": FRONTIER_PLAN_BINARY_BYTES,
    }
    if facts != expected:
        raise O1C76PreparationError("frontier release contract differs")


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
        raise O1C76PreparationError("causal-frontier artifact write failed") from exc


def _publish_directory(output_dir: Path, files: Mapping[str, bytes]) -> None:
    if output_dir.exists():
        raise O1C76PreparationError("causal-frontier output already exists")
    try:
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        parent = output_dir.parent.resolve(strict=True)
    except OSError as exc:
        raise O1C76PreparationError("causal-frontier output parent differs") from exc
    if output_dir.name in ("", ".", ".."):
        raise O1C76PreparationError("causal-frontier output name differs")
    stage = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".tmp", dir=parent)
    )
    try:
        for name, payload in files.items():
            if Path(name).name != name:
                raise O1C76PreparationError("causal-frontier artifact name differs")
            _durable_write(stage / name, payload)
        os.replace(stage, output_dir)
        descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def prepare_o1c76_causal_frontier(
    *,
    capsule_dir: str | Path,
    parent_result_path: str | Path,
    output_dir: str | Path,
    enforce_release_contract: bool = True,
) -> dict[str, object]:
    """Replay O1C-0075 and atomically publish the zero-call frontier seed."""

    if not isinstance(enforce_release_contract, bool):
        raise O1C76PreparationError("release-contract flag differs")
    capsule = Path(capsule_dir).resolve(strict=True)
    parent_result = Path(parent_result_path).resolve(strict=True)
    result, invocation, invocation_sha = _validate_parent_capsule(
        capsule, parent_result
    )
    _validate_parent_sources(invocation)
    manifest_entries = _parse_artifact_manifest(
        (capsule / "artifacts.sha256").read_bytes()
    )
    assignment, native, native_raw = _read_parent_assignment(
        capsule, manifest_entries
    )
    state = _recover_parent_state(capsule, result, invocation)
    plan, plan_document, plan_binary = _derive_frontier_plan(state, native_raw)
    if enforce_release_contract:
        _validate_release_contract(
            state, assignment, plan, plan_document, plan_binary
        )

    provenance = {
        "schema": PARENT_PROVENANCE_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "parent_attempt_id": "O1C-0075",
        "parent_result_sha256": PARENT_RESULT_SHA256,
        "parent_manifest_sha256": PARENT_MANIFEST_SHA256,
        "parent_source_commit": PARENT_SOURCE_COMMIT,
        "parent_invocation_sha256": invocation_sha,
        "parent_runner_sha256": PARENT_RUNNER_SHA256,
        "parent_source_sha256": dict(EXPECTED_PARENT_SOURCE_SHA256),
        "terminal_native_gzip_sha256": PARENT_NATIVE_GZIP_SHA256,
        "terminal_native_raw_sha256": PARENT_NATIVE_RAW_SHA256,
        "terminal_native_schema": native.get("schema"),
        "terminal_trace_sha256": _mapping(
            native.get("sieve"), "terminal sieve"
        ).get("trace_sha256"),
        "source_assignment_sha256": SOURCE_ASSIGNMENT_SHA256,
        "rank_source_sha256": RANK_SOURCE_SHA256,
        "fresh_page3_sha256": PAGE3_SHA256,
        "parent_last_consumed_lineage_ordinal": 15,
        "prepared_lineage_ordinal": 16,
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
        SOURCE_ASSIGNMENT_NAME: assignment,
        FRONTIER_PLAN_NAME: canonical_json_bytes(plan_document),
        FRONTIER_PLAN_BINARY_NAME: plan_binary,
        PARENT_PROVENANCE_NAME: canonical_json_bytes(provenance),
    }
    roles = {
        **{name: "immutable-complete-causal-attic-chunk" for name in CHUNK_NAMES},
        ACTIVE_PROJECTION_NAME: "unused-fresh-page3-science-input",
        OCCURRENCES_NAME: "complete-witness-occurrence-ledger",
        RELATIONS_NAME: "complete-strict-subsumption-closure",
        ACTIVATION_LEDGER_NAME: "complete-causal-residency-ledger",
        SOURCE_ASSIGNMENT_NAME: "public-observed-ascending-terminal-assignment",
        FRONTIER_PLAN_NAME: "target-free-selected-frontier-plan",
        FRONTIER_PLAN_BINARY_NAME: "native-frontier-falsifying-literal-plan",
        PARENT_PROVENANCE_NAME: "sealed-parent-replay-provenance",
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
        "artifact_set": {
            "schema": ARTIFACT_SET_SCHEMA,
            "artifact_count": len(rows),
            "artifacts": rows,
        },
    }
    payload = canonical_json_bytes(manifest)
    _publish_directory(Path(output_dir), {**artifacts, MANIFEST_NAME: payload})
    return manifest


def load_prepared_frontier(
    directory: str | Path, *, expected_manifest_sha256: str
) -> PreparedFrontier:
    """Validate exact inventory and reconstruct the complete frontier seed."""

    prepared = Path(directory).resolve(strict=True)
    if not prepared.is_dir() or prepared.is_symlink():
        raise O1C76PreparationError("prepared causal-frontier directory differs")
    manifest_path = _regular_file(prepared / MANIFEST_NAME, "prepared manifest")
    manifest_bytes = manifest_path.read_bytes()
    expected = _sha256(expected_manifest_sha256, "prepared manifest SHA-256")
    if sha256_bytes(manifest_bytes) != expected:
        raise O1C76PreparationError("prepared causal-frontier manifest differs")
    manifest = _read_json_bytes(manifest_bytes, "prepared manifest")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("preparation_schema") != PREPARATION_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
    ):
        raise O1C76PreparationError("prepared manifest contract differs")
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
        PARENT_PROVENANCE_NAME,
    }
    actual = tuple(prepared.iterdir())
    if (
        set(rows) != expected_names
        or artifact_set.get("artifact_count") != len(expected_names)
        or {path.name for path in actual} != expected_names | {MANIFEST_NAME}
        or any(path.is_symlink() or not path.is_file() for path in actual)
    ):
        raise O1C76PreparationError("prepared directory inventory differs")
    payloads: dict[str, bytes] = {}
    for name in sorted(expected_names):
        row = _mapping(rows[name], f"prepared artifact {name}")
        payload = _regular_file(prepared / name, f"prepared artifact {name}").read_bytes()
        if (
            row.get("sha256") != sha256_bytes(payload)
            or row.get("serialized_bytes") != len(payload)
        ):
            raise O1C76PreparationError(f"prepared artifact {name} differs")
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
        O1C76PreparationError,
    ) as exc:
        raise O1C76PreparationError("prepared frontier reconstruction differs") from exc
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
        raise O1C76PreparationError("prepared frontier binary differs") from exc
    derived_document = _frontier_plan_document(state, plan)
    if (
        state.active_projection.serialized != active.serialized
        or state.attic.occurrence_document() != occurrence_document
        or canonical_json_bytes(state.attic.relation_document())
        != payloads[RELATIONS_NAME]
        or canonical_json_bytes(state.activation_ledger_document())
        != payloads[ACTIVATION_LEDGER_NAME]
        or plan.source_assignment_sha256 != sha256_bytes(assignment)
        or plan.prior_assignment_bytes != assignment
        or plan.source_result_sha256 != PARENT_NATIVE_RAW_SHA256
        or plan_document != derived_document
        or plan_document != manifest.get("frontier_plan")
        or _read_json_bytes(
            payloads[PARENT_PROVENANCE_NAME], "prepared parent provenance"
        )
        != manifest.get("parent")
    ):
        raise O1C76PreparationError("prepared frontier projection differs")
    _validate_release_contract(
        state, assignment, plan, plan_document, plan_binary
    )
    return PreparedFrontier(
        directory=prepared,
        manifest=dict(manifest),
        manifest_bytes=manifest_bytes,
        manifest_sha256=expected,
        state=state,
        source_assignment=assignment,
        frontier_plan=plan,
        frontier_plan_document=dict(plan_document),
        frontier_plan_binary=plan_binary,
    )


def _parser() -> argparse.ArgumentParser:
    root = lab_root()
    parser = argparse.ArgumentParser(
        description="Prepare O1C-0076's zero-call causal frontier"
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
        manifest = prepare_o1c76_causal_frontier(
            capsule_dir=args.capsule,
            parent_result_path=args.parent_result,
            output_dir=args.output_dir,
        )
    except (O1C76PreparationError, CausalResidencyError) as exc:
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
    "DEFAULT_PARENT_RESULT_RELATIVE",
    "FALSIFYING_I32LE_SHA256",
    "EXPECTED_PREPARED_MANIFEST_SHA256",
    "FRONTIER_PLAN_BINARY_SHA256",
    "FRONTIER_PLAN_BINARY_NAME",
    "FRONTIER_PLAN_NAME",
    "MANIFEST_NAME",
    "MANIFEST_SCHEMA",
    "O1C76PreparationError",
    "PAGE3_SHA256",
    "PARENT_PROVENANCE_NAME",
    "PreparedFrontier",
    "RANK_SOURCE_SHA256",
    "RELATIONS_NAME",
    "SELECTED_CLAUSE_SHA256",
    "SOURCE_ASSIGNMENT_NAME",
    "SOURCE_ASSIGNMENT_SHA256",
    "lab_root",
    "load_prepared_frontier",
    "main",
    "prepare_o1c76_causal_frontier",
]
